//! HeySafe 本地模型调用器（独立命令行工具）
//!
//! 给定一个模型文件 + 一个或多个 PE 文件/目录，输出每个文件的恶意概率、
//! 命中家族和最终判决。纯 Rust、无 C 依赖、加载后只读、可多线程并行——
//! 与 HeySafe 引擎内部用的是同一份特征提取器 + 同一份树推理器，结论一致。
//!
//! 用法：
//!   model-cli <模型文件> <PE文件或目录> [更多路径...] [选项]
//!
//! 模型文件可以是：
//!   · 明文 `heysafe_local_model.trees.bin`（魔数 HSTREE01）
//!   · xz 压缩的 `heysafe_local_model.trees.bin.xz`（自动识别并解压）
//!
//! 选项：
//!   --threshold <f>   恶意判定阈值（默认 0.8488；恶意概率 >= 阈值即判恶意）
//!   --jobs <n>        并行线程数（默认 = 逻辑核心数）
//!   --json            每个文件输出一行 JSON（便于脚本消费）
//!   --classes a,b,..  自定义类别名（默认按 HeySafe 10 类模型）
//!   --quiet           只打印判为恶意的文件
//!
//! 退出码：0 = 全部处理完成；2 = 参数/模型错误。

mod features;
mod tree;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tree::TreeEnsemble;

/// 默认阈值：gen3 模型 1000 轮、FPR=0.1% 档校准值（见 heysafe_local_model_meta.json）。
/// 恶意概率 = 1 - P(良性)，>= 阈值即判恶意。换模型请按各自验证集重新校准。
const DEFAULT_THRESHOLD: f32 = 0.8488;

/// HeySafe 默认 10 类模型的类别名（class 0 = 良性）。
const DEFAULT_CLASS_NAMES: &[&str] = &[
    "Benign",
    "Ransom",
    "Backdoor.RAT",
    "Stealer",
    "Loader",
    "Miner",
    "Worm",
    "Spyware",
    "HackTool",
    "Trojan.Generic",
];

/// 可扫描扩展名（目录递归时用；直接指定单个文件则无视此过滤）。
const PE_EXTS: &[&str] = &["exe", "dll", "sys", "scr", "com", "cpl", "ocx", "efi", "mui", "node"];

struct Opts {
    model: PathBuf,
    targets: Vec<PathBuf>,
    threshold: f32,
    jobs: usize,
    json: bool,
    quiet: bool,
    class_names: Vec<String>,
}

fn print_usage() {
    eprintln!(
        "HeySafe 本地模型调用器\n\
         \n\
         用法：model-cli <模型文件> <PE文件或目录> [更多路径...] [选项]\n\
         \n\
         选项：\n\
         \x20 --threshold <f>   恶意判定阈值（默认 {DEFAULT_THRESHOLD}）\n\
         \x20 --jobs <n>        并行线程数（默认 = CPU 逻辑核心数）\n\
         \x20 --json            每个文件输出一行 JSON\n\
         \x20 --classes a,b,..  自定义类别名（默认 HeySafe 10 类）\n\
         \x20 --quiet           只打印判为恶意的文件\n\
         \n\
         模型文件可为明文 .trees.bin 或 xz 压缩的 .trees.bin.xz（自动识别）。"
    );
}

fn parse_args() -> Result<Opts, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.is_empty() {
        return Err("缺少参数".to_string());
    }
    let mut positional: Vec<PathBuf> = Vec::new();
    let mut threshold = DEFAULT_THRESHOLD;
    let mut jobs = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let mut json = false;
    let mut quiet = false;
    let mut class_names: Vec<String> =
        DEFAULT_CLASS_NAMES.iter().map(|s| s.to_string()).collect();

    let mut i = 0;
    while i < raw.len() {
        let a = &raw[i];
        match a.as_str() {
            "--threshold" => {
                i += 1;
                let v = raw.get(i).ok_or("--threshold 缺少值")?;
                threshold = v.parse().map_err(|_| format!("--threshold 非法: {v}"))?;
            }
            "--jobs" => {
                i += 1;
                let v = raw.get(i).ok_or("--jobs 缺少值")?;
                jobs = v.parse::<usize>().map_err(|_| format!("--jobs 非法: {v}"))?.max(1);
            }
            "--classes" => {
                i += 1;
                let v = raw.get(i).ok_or("--classes 缺少值")?;
                class_names = v.split(',').map(|s| s.trim().to_string()).collect();
            }
            "--json" => json = true,
            "--quiet" => quiet = true,
            "-h" | "--help" => return Err("help".to_string()),
            other if other.starts_with("--") => {
                return Err(format!("未知选项: {other}"));
            }
            _ => positional.push(PathBuf::from(a)),
        }
        i += 1;
    }

    if positional.len() < 2 {
        return Err("需要：<模型文件> <至少一个PE文件或目录>".to_string());
    }
    let model = positional.remove(0);
    Ok(Opts {
        model,
        targets: positional,
        threshold,
        jobs,
        json,
        quiet,
        class_names,
    })
}

/// 读模型字节：自动识别 xz（magic FD 37 7A 58 5A 00）并解压，否则原样返回。
fn read_model_bytes(path: &Path) -> Result<Vec<u8>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("读模型失败 {}: {e}", path.display()))?;
    const XZ_MAGIC: &[u8] = &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
    if raw.starts_with(XZ_MAGIC) {
        let mut out = Vec::new();
        let mut reader = std::io::BufReader::new(&raw[..]);
        lzma_rs::xz_decompress(&mut reader, &mut out)
            .map_err(|e| format!("xz 解压失败: {e:?}"))?;
        Ok(out)
    } else {
        Ok(raw)
    }
}

/// 递归收集目标路径下的 PE 候选文件；单个文件直接收（无视扩展名）。
fn collect_targets(targets: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for t in targets {
        if t.is_file() {
            out.push(t.clone());
        } else if t.is_dir() {
            collect_dir(t, &mut out);
        } else {
            eprintln!("跳过（不存在）: {}", t.display());
        }
    }
    out
}

fn collect_dir(dir: &Path, out: &mut Vec<PathBuf>) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_dir(&p, out);
        } else if p.is_file() {
            let ext_ok = p
                .extension()
                .and_then(|x| x.to_str())
                .map(|x| PE_EXTS.contains(&x.to_ascii_lowercase().as_str()))
                .unwrap_or(false);
            if ext_ok {
                out.push(p);
            }
        }
    }
}

struct FileResult {
    path: PathBuf,
    outcome: Outcome,
}

enum Outcome {
    /// 成功推理：恶意概率、家族名、是否达阈值。
    Scored { prob: f32, family: String, malicious: bool },
    /// 非 PE / 特征提取失败 / 读文件失败。
    Skipped(String),
}

/// 对单个文件推理。用 catch_unwind 罩住特征提取——畸形 PE 触发 panic 也只降级为
/// Skipped，绝不带崩整个进程（批量扫一堆样本时尤其重要）。
fn scan_file(path: &Path, model: &TreeEnsemble, threshold: f32, class_names: &[String]) -> Outcome {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return Outcome::Skipped(format!("读取失败: {e}")),
    };
    let extracted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        features::extract(&bytes)
    }));
    let feats = match extracted {
        Ok(Some(f)) => f,
        Ok(None) => return Outcome::Skipped("非 PE / 文件过小".to_string()),
        Err(_) => return Outcome::Skipped("特征提取 panic（畸形 PE）".to_string()),
    };
    if feats.len() != features::NDIM {
        return Outcome::Skipped(format!("特征维度异常: {}", feats.len()));
    }
    let out = model.evaluate(&feats);
    let prob = out.malicious_prob;
    let malicious = prob >= threshold;
    let family = if malicious {
        best_malicious_family(&out.probabilities, class_names)
    } else {
        class_names.first().cloned().unwrap_or_else(|| "Benign".to_string())
    };
    Outcome::Scored { prob, family, malicious }
}

/// 取概率最高的非良性类名（index 0 视为良性，跳过）。
fn best_malicious_family(probs: &[f32], class_names: &[String]) -> String {
    let mut best = 1usize;
    let mut best_v = f32::NEG_INFINITY;
    for (i, &p) in probs.iter().enumerate() {
        if i == 0 {
            continue;
        }
        if p > best_v {
            best_v = p;
            best = i;
        }
    }
    class_names
        .get(best)
        .cloned()
        .unwrap_or_else(|| format!("class{best}"))
}

fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            _ => o.push(c),
        }
    }
    o
}

fn print_result(r: &FileResult, opts: &Opts) {
    match &r.outcome {
        Outcome::Scored { prob, family, malicious } => {
            if opts.quiet && !malicious {
                return;
            }
            if opts.json {
                println!(
                    "{{\"path\":\"{}\",\"malicious\":{},\"probability\":{:.6},\"family\":\"{}\",\"threshold\":{}}}",
                    json_escape(&r.path.to_string_lossy()),
                    malicious,
                    prob,
                    json_escape(family),
                    opts.threshold
                );
            } else {
                let verdict = if *malicious { "恶意" } else { "安全" };
                println!(
                    "[{verdict}] p={:.4} {:<16} {}",
                    prob,
                    family,
                    r.path.display()
                );
            }
        }
        Outcome::Skipped(reason) => {
            if opts.quiet {
                return;
            }
            if opts.json {
                println!(
                    "{{\"path\":\"{}\",\"skipped\":\"{}\"}}",
                    json_escape(&r.path.to_string_lossy()),
                    json_escape(reason)
                );
            } else {
                println!("[跳过] {:<22} {}", reason, r.path.display());
            }
        }
    }
}

fn main() {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            if e != "help" {
                eprintln!("参数错误：{e}\n");
            }
            print_usage();
            std::process::exit(2);
        }
    };

    // 加载模型（一次性）。
    let t_load = Instant::now();
    let model_bytes = match read_model_bytes(&opts.model) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let model = match TreeEnsemble::from_bytes(&model_bytes) {
        Ok(m) => Arc::new(m),
        Err(e) => {
            eprintln!("模型解析失败：{e}");
            std::process::exit(2);
        }
    };
    drop(model_bytes);
    eprintln!(
        "模型已加载：{} 棵树 / {} 类 / {} 维特征，耗时 {:?}",
        model.n_trees(),
        model.n_classes(),
        model.n_features(),
        t_load.elapsed()
    );
    if model.n_features() != features::NDIM {
        eprintln!(
            "警告：模型特征维度 {} 与本工具特征提取器 {} 不一致，结果不可信（模型与提取器不配套）。",
            model.n_features(),
            features::NDIM
        );
    }

    // 收集目标文件。
    let files = collect_targets(&opts.targets);
    if files.is_empty() {
        eprintln!("没有可扫描的文件。");
        std::process::exit(0);
    }
    eprintln!("待扫描文件数：{}，并行线程：{}", files.len(), opts.jobs);

    let t_scan = Instant::now();
    let mal = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicU64::new(0));

    // 自建线程池并行：把文件按索引取模分给 N 个线程，无需 rayon 依赖，结果各线程
    // 本地收集后合并，输出串行（避免多线程 println 交错）。
    let opts = Arc::new(opts);
    let files = Arc::new(files);
    let jobs = opts.jobs.min(files.len()).max(1);
    let mut handles = Vec::with_capacity(jobs);
    for w in 0..jobs {
        let model = model.clone();
        let opts = opts.clone();
        let files = files.clone();
        let mal = mal.clone();
        let done = done.clone();
        handles.push(std::thread::spawn(move || {
            let mut local: Vec<FileResult> = Vec::new();
            let mut idx = w;
            while idx < files.len() {
                let path = &files[idx];
                let outcome = scan_file(path, &model, opts.threshold, &opts.class_names);
                if let Outcome::Scored { malicious: true, .. } = &outcome {
                    mal.fetch_add(1, Ordering::Relaxed);
                }
                done.fetch_add(1, Ordering::Relaxed);
                local.push(FileResult { path: path.clone(), outcome });
                idx += jobs;
            }
            local
        }));
    }

    let mut all: Vec<FileResult> = Vec::new();
    for h in handles {
        if let Ok(mut v) = h.join() {
            all.append(&mut v);
        }
    }
    // 按路径排序，输出稳定。
    all.sort_by(|a, b| a.path.cmp(&b.path));
    for r in &all {
        print_result(r, &opts);
    }

    let scanned = done.load(Ordering::Relaxed);
    let mal_n = mal.load(Ordering::Relaxed);
    let elapsed = t_scan.elapsed();
    let rate = if elapsed.as_secs_f64() > 0.0 {
        scanned as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    eprintln!(
        "\n完成：扫描 {scanned} 个文件，判为恶意 {mal_n} 个，耗时 {:?}（{:.1} 文件/秒），阈值 {}",
        elapsed, rate, opts.threshold
    );
}
