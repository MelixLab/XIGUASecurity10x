//! 扫描器：文件收集（智能/全盘/自定义）、SHA-256 哈希、ML 推理、云端哈希检查。
//! 移植自 XIGUASecurity10x（antivirus-ui/src-tauri/scanner.rs 精简版）。

use crate::engine::features;
use crate::engine::tree::TreeEnsemble;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

/// 主扫描引擎 ML 阈值（与旧项目主扫描器一致：0.7）。
pub const ML_THRESHOLD: f32 = 0.7;

/// HeySafe 10 类模型类别名（class 0 = Benign）。
pub const CLASS_NAMES: [&str; 10] = [
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

/// 智能（快速）扫描扩展名。
const SMART_EXTS: [&str; 6] = ["exe", "dll", "sys", "zip", "rar", "7z"];

/// 全盘扫描扩展名。
const FULL_EXTS: [&str; 9] = ["exe", "dll", "sys", "drv", "ocx", "scr", "zip", "rar", "7z"];

/// 云哈希库 API（旧项目默认服务器）。
pub const CLOUD_DEFAULT_URL: &str = "https://cloudapi.xiguastudio.top";
pub const CLOUD_DEFAULT_KEY: &str = "scan_dcc33b100b8a485fb099a5dce4c4f486";

static MODEL: OnceLock<Option<Arc<TreeEnsemble>>> = OnceLock::new();

/// 模型文件路径：开发期在 src-tauri/engines/melix/ 下。
pub fn model_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("engines")
        .join("melix")
        .join("Melix_local_model.trees.bin.xz")
}

/// 懒加载 ML 模型（xz 解压 + HSTREE01 解析），失败返回 None（上层 fail-open）。
pub fn load_model() -> Option<Arc<TreeEnsemble>> {
    MODEL
        .get_or_init(|| {
            let raw = std::fs::read(model_path()).ok()?;
            const XZ_MAGIC: &[u8] = &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
            let bytes = if raw.starts_with(XZ_MAGIC) {
                let mut out = Vec::new();
                let mut reader = std::io::BufReader::new(&raw[..]);
                lzma_rs::xz_decompress(&mut reader, &mut out).ok()?;
                out
            } else {
                raw
            };
            TreeEnsemble::from_bytes(&bytes).ok().map(Arc::new)
        })
        .clone()
}

// ═══════════════════════════════════════════════════════════════════════════
// 文件收集
// ═══════════════════════════════════════════════════════════════════════════

fn is_wanted_ext(path: &Path, exts: &[&str]) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| exts.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

fn contains_eicar(path: &Path) -> bool {
    path.to_string_lossy().to_ascii_lowercase().contains("eicar")
}

fn should_skip(path: &Path) -> bool {
    let p = path.to_string_lossy().to_ascii_lowercase();
    p.contains("driverstore") || p.contains("windowsapps")
}

fn scan_dir_recursive(dir: &Path, exts: &[&str], out: &mut Vec<String>) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for e in rd.flatten() {
        let p = e.path();
        if should_skip(&p) {
            continue;
        }
        if p.is_dir() {
            scan_dir_recursive(&p, exts, out);
        } else if p.is_file() && (is_wanted_ext(&p, exts) || contains_eicar(&p)) {
            out.push(p.to_string_lossy().into_owned());
        }
    }
}

/// 智能（快速）扫描：System32/SysWOW64（除 DriverStore）+ drivers + Program Files/ProgramData
/// （除 WindowsApps）+ Windows/Temp + 用户 Temp。类型 exe/dll/sys/zip/rar/7z + eicar。
pub fn get_scan_files() -> Vec<String> {
    let mut out = Vec::new();
    let roots = [
        "C:/Windows/System32",
        "C:/Windows/SysWOW64",
        "C:/Windows/System32/drivers",
        "C:/Windows/SysWOW64/drivers",
        "C:/Program Files",
        "C:/Program Files (x86)",
        "C:/ProgramData",
        "C:/Windows/Temp",
    ];
    for r in roots {
        scan_dir_recursive(Path::new(r), &SMART_EXTS, &mut out);
    }
    if let Some(t) = std::env::temp_dir().to_str() {
        scan_dir_recursive(Path::new(t), &SMART_EXTS, &mut out);
    }
    out
}

/// 全盘扫描：C:/ 及所有存在盘符，排除系统冗余目录。
pub fn get_full_scan_files() -> Vec<String> {
    let mut out = Vec::new();
    let mut drives = vec![PathBuf::from("C:/")];
    for letter in b'D'..=b'Z' {
        let root = format!("{}:/", letter as char);
        if Path::new(&root).exists() {
            drives.push(PathBuf::from(root));
        }
    }
    const EXCLUDE: [&str; 9] = [
        "c:/windows/winsxs",
        "c:/windows/installer",
        "c:/windows/softwaredistribution",
        "c:/windows/prefetch",
        "c:/windows/logs",
        "c:/windows/driverstore",
        "c:/$recycle.bin",
        "c:/recovery",
        "c:/system volume information",
    ];
    let exclude = |p: &Path| {
        let s = p.to_string_lossy().to_ascii_lowercase();
        EXCLUDE.iter().any(|x| s.starts_with(x))
    };
    fn walk(dir: &Path, exts: &[&str], out: &mut Vec<String>, excl: &dyn Fn(&Path) -> bool) {
        let rd = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(_) => return,
        };
        for e in rd.flatten() {
            let p = e.path();
            if excl(&p) || should_skip(&p) {
                continue;
            }
            if p.is_dir() {
                walk(&p, exts, out, excl);
            } else if p.is_file() && (is_wanted_ext(&p, exts) || contains_eicar(&p)) {
                out.push(p.to_string_lossy().into_owned());
            }
        }
    }
    for d in drives {
        walk(&d, &FULL_EXTS, &mut out, &exclude);
    }
    out
}

/// 自定义扫描：单文件按 PE 头/脚本/压缩包识别；目录递归（深度 5）。
pub fn get_scan_files_direct(paths: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let script_exts = ["bat", "cmd"];
    let archive_exts = ["zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz"];
    for p in paths {
        let path = PathBuf::from(&p);
        if path.is_file() {
            if is_pe_or_target(&path, &script_exts, &archive_exts) {
                out.push(p);
            }
        } else if path.is_dir() {
            scan_custom_dir(&path, &script_exts, &archive_exts, &mut out, 0);
        }
    }
    out
}

fn is_pe_or_target(path: &Path, script_exts: &[&str], archive_exts: &[&str]) -> bool {
    if contains_eicar(path) {
        return true;
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    if script_exts.contains(&ext.as_str()) || archive_exts.contains(&ext.as_str()) {
        return true;
    }
    // PE 头探测（MZ）
    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        let mut buf = [0u8; 2];
        if f.read_exact(&mut buf).is_ok() {
            return buf[0] == b'M' && buf[1] == b'Z';
        }
    }
    false
}

fn scan_custom_dir(
    dir: &Path,
    script_exts: &[&str],
    archive_exts: &[&str],
    out: &mut Vec<String>,
    depth: usize,
) {
    if depth > 5 {
        return;
    }
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            scan_custom_dir(&p, script_exts, archive_exts, out, depth + 1);
        } else if p.is_file() && is_pe_or_target(&p, script_exts, archive_exts) {
            out.push(p.to_string_lossy().into_owned());
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 哈希
// ═══════════════════════════════════════════════════════════════════════════

/// 计算文件 SHA-256（小写 hex），失败返回 None。
pub fn calculate_file_hash(file_path: &str) -> Option<String> {
    let file = std::fs::File::open(file_path).ok()?;
    let mut hasher = Sha256::new();
    let mut reader = std::io::BufReader::new(file);
    let mut buffer = [0u8; 8192];
    loop {
        use std::io::Read;
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(_) => return None,
        }
    }
    Some(format!("{:x}", hasher.finalize()))
}

// ═══════════════════════════════════════════════════════════════════════════
// ML 推理
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ScanResult {
    pub file_path: String,
    pub file_hash: Option<String>,
    /// CLEAN | MALICIOUS | ERROR
    pub result: String,
    pub probability: f32,
    pub virus_family: Option<String>,
    /// 云端命中时为 true
    pub from_cloud: bool,
}

/// 单文件本地 ML 扫描。读文件 → 特征提取 → 树推理 → 阈值判定。
pub fn ml_scan_file(path: &str) -> ScanResult {
    let hash = calculate_file_hash(path);
    let model = match load_model() {
        Some(m) => m,
        None => {
            return ScanResult {
                file_path: path.to_string(),
                file_hash: hash,
                result: "ERROR".to_string(),
                probability: 0.0,
                virus_family: Some("Model not loaded".to_string()),
                from_cloud: false,
            }
        }
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => {
            return ScanResult {
                file_path: path.to_string(),
                file_hash: hash,
                result: "ERROR".to_string(),
                probability: 0.0,
                virus_family: None,
                from_cloud: false,
            }
        }
    };
    let feats = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        features::extract(&bytes)
    }))
    .ok()
    .flatten();
    let feats = match feats {
        Some(f) => f,
        None => {
            return ScanResult {
                file_path: path.to_string(),
                file_hash: hash,
                result: "CLEAN".to_string(),
                probability: 0.0,
                virus_family: None,
                from_cloud: false,
            }
        }
    };
    let out = model.evaluate(&feats);
    let prob = out.malicious_prob;
    let malicious = prob >= ML_THRESHOLD;
    let family = if malicious {
        let mut best = 1usize;
        let mut best_v = f32::NEG_INFINITY;
        for (i, &p) in out.probabilities.iter().enumerate() {
            if i == 0 {
                continue;
            }
            if p > best_v {
                best_v = p;
                best = i;
            }
        }
        Some(CLASS_NAMES.get(best).copied().unwrap_or("Unknown").to_string())
    } else {
        None
    };
    ScanResult {
        file_path: path.to_string(),
        file_hash: hash,
        result: if malicious { "MALICIOUS".to_string() } else { "CLEAN".to_string() },
        probability: prob,
        virus_family: family,
        from_cloud: false,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 云端哈希
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Clone, Deserialize)]
pub struct CloudCheckItem {
    pub result: Option<String>,
    pub family: Option<String>,
    pub name: Option<String>,
}

#[derive(Deserialize)]
pub struct CloudCheckResponse {
    pub results: Option<Vec<CloudCheckItem>>,
    pub result: Option<String>,
    pub family: Option<String>,
    pub name: Option<String>,
}

/// 批量云端哈希检查（POST /api/batch_check?key=...）。
pub async fn cloud_batch_check(
    server_url: &str,
    api_key: &str,
    hashes: &[String],
) -> Result<Vec<CloudCheckItem>, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!("{}/api/batch_check?key={}", server_url, api_key);
    let body = serde_json::json!({ "hashes": hashes });
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("cloud check failed: {}", e))?;
    let parsed: CloudCheckResponse = resp.json().await.map_err(|e| e.to_string())?;
    Ok(parsed.results.unwrap_or_default())
}

// ═══════════════════════════════════════════════════════════════════════════
// 批量扫描编排
// ═══════════════════════════════════════════════════════════════════════════

/// 批量扫描：可选云端哈希优先，未命中走本地 ML。返回 ScanResult JSON 数组。
pub fn scan_batch_files(
    file_paths: Vec<String>,
    cloud_enabled: bool,
    cloud_url: Option<String>,
    cloud_key: Option<String>,
) -> Vec<ScanResult> {
    use rayon::prelude::*;

    if file_paths.is_empty() {
        return Vec::new();
    }

    // 1) 并行算哈希
    let hashes: Vec<Option<String>> = file_paths
        .par_iter()
        .map(|p| calculate_file_hash(p))
        .collect();

    // 2) 云端批量检查
    let mut cloud_results: Vec<Option<CloudCheckItem>> = vec![None; file_paths.len()];
    if cloud_enabled {
        let url = cloud_url.unwrap_or_else(|| CLOUD_DEFAULT_URL.to_string());
        let key = cloud_key.unwrap_or_else(|| CLOUD_DEFAULT_KEY.to_string());
        let indexed: Vec<(usize, String)> = hashes
            .iter()
            .enumerate()
            .filter_map(|(i, h)| h.as_ref().map(|h| (i, h.clone())))
            .collect();
        if !indexed.is_empty() {
            let req_hashes: Vec<String> = indexed.iter().map(|(_, h)| h.clone()).collect();
            let rt = tauri::async_runtime::block_on(async {
                cloud_batch_check(&url, &key, &req_hashes).await
            });
            if let Ok(items) = rt {
                for (k, (orig_idx, _)) in indexed.iter().enumerate() {
                    cloud_results[*orig_idx] = items.get(k).cloned();
                }
            }
        }
    }

    // 3) 未命中云端（unknown/失败）→ 本地 ML
    file_paths
        .par_iter()
        .enumerate()
        .map(|(i, p)| {
            if let Some(item) = &cloud_results[i] {
                match item.result.as_deref() {
                    Some("black") => ScanResult {
                        file_path: p.clone(),
                        file_hash: hashes[i].clone(),
                        result: "MALICIOUS".to_string(),
                        probability: 0.95,
                        virus_family: item.family.clone().or_else(|| item.name.clone()).or(Some("CloudHash".to_string())),
                        from_cloud: true,
                    },
                    Some("white") => ScanResult {
                        file_path: p.clone(),
                        file_hash: hashes[i].clone(),
                        result: "CLEAN".to_string(),
                        probability: 0.0,
                        virus_family: None,
                        from_cloud: true,
                    },
                    _ => ml_scan_file(p),
                }
            } else {
                ml_scan_file(p)
            }
        })
        .collect()
}
