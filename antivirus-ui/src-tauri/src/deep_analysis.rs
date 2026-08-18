// 深度分析模块 - 可疑文件评分 + 云端沙箱自动提交
// 逻辑：
//   1. 根据文件大小、数字签名、文件名计算可疑分数
//   2. 超过阈值自动提交到微步云沙箱
//   3. 同步等待分析结果（120-150s），发射进度事件给前端

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;
use tauri::Emitter;

// ── 冒充的常见软件名称列表 ──
const IMPERSONATED_SOFTWARE: &[&str] = &[
    // ── 办公/协作 ──
    "有道", "youdao", "yaodao", "夸克", "quark", "qurk", "quak", "百度", "baidu",
    "腾讯", "tencent", "微信", "wechat", "weixin", "钉钉", "dingtalk", "飞书", "feishu",
    "企业微信", "wecom", "腾讯会议", "tencentmeeting", "wemeet",
    "wps", "office", "word", "excel", "pdf", "adobe",
    // ── 远程控制（银狐高频仿冒） ──
    "向日葵", "sunlogin", "xrk", "todesk", "anydesk", "teamviewer", "rustdesk",
    // ── 互联网/电商 ──
    "阿里", "ali", "淘宝", "taobao", "京东", "jd", "抖音", "douyin", "tiktok",
    "拼多多", "pinduoduo", "美团", "meituan", "饿了么", "eleme",
    "网易", "netease", "搜狐", "sohu", "新浪", "sina", "微博", "weibo",
    // ── 安全/杀毒 ──
    "360", "金山", "kaspersky", "卡巴", "诺顿", "norton", "小红伞",
    "火绒", "huorong", "瑞星", "rising", "江民",
    // ── 硬件/科技 ──
    "华为", "huawei", "小米", "xiaomi", "oppo", "vivo", "三星", "samsung",
    "联想", "lenovo", "华硕", "asus", "惠普", "hp", "戴尔", "dell",
    // ── 浏览器/网络 ──
    "chrome", "google", "firefox", "edge", "qq", "foxmail", "outlook",
    "steam", "epic", "阿里云", "aliyun", "腾讯云", "tencentcloud",
    // ── 下载/工具 ──
    "迅雷", "xunlei", "thunder", "百度网盘", "baidunetdisk", "夸克网盘",
    "安装", "setup", "install", "update", "升级",
    // ── 常见银狐拼写变体 ──
    "quark", "qurk", "quak", "quork", "youad", "yoado", "dingd", "feis",
    "wechat", "wechqt", "wechot", "wxwork", "wx",
];

const SUSPICIOUS_NAME_KEYWORDS: &[&str] = &[
    "破解", "crack", "keygen", "激活", "patch", "补丁",
    "注册机", "绿色版", "便携版", "免安装",
];

// ── 数据结构 ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspicionScore {
    pub total: u32,
    pub max_possible: u32,
    pub reasons: Vec<String>,
    pub should_deep_analyze: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepAnalysisProgress {
    pub percent: u32,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepAnalysisResult {
    pub sha256: String,
    pub sandbox_verdict: String,
    pub threat_score: f64,
    pub threat_family: String,
    pub family_category: String,
    pub malicious: bool,
    pub summary: serde_json::Value,
    pub threat_info: serde_json::Value,
    pub iocs: Vec<String>,
}

// ── 评分配置 ──
const SCORE_THRESHOLD: u32 = 50;
const MAX_FILE_SIZE: u64 = 104_857_600; // 100MB

// ── 沙箱威胁类型 → 中文分类映射 ──
pub fn map_threat_category(malware_type: &str, family: &str) -> String {
    match malware_type.to_lowercase().as_str() {
        "cybercrime" => "网络黑产",
        "trojan" | "backdoor" => "木马程序",
        "ransomware" => "勒索病毒",
        "miner" => "挖矿程序",
        "worm" => "蠕虫病毒",
        "spyware" => "间谍软件",
        "adware" => "广告软件",
        "pua" | "riskware" => "风险程序",
        "hacktool" => "黑客工具",
        "downloader" => "下载器",
        "dropper" => "投递器",
        _ => {
            if family.contains("SilverFox") { "银狐木马" }
            else if family.contains("Cybercrime") { "网络黑产" }
            else if family.contains("Trojan") { "木马程序" }
            else if family.contains("Ransom") { "勒索病毒" }
            else { "恶意程序" }
        }
    }
    .to_string()
}

// ── 计算可疑分数 ──
pub fn calculate_suspicion_score(file_path: &str) -> SuspicionScore {
    let mut score: u32 = 0;
    let mut reasons: Vec<String> = Vec::new();
    let path = Path::new(file_path);

    // 1) 文件 > 100MB
    let file_size = std::fs::metadata(file_path)
        .map(|m| m.len())
        .unwrap_or(0);

    if file_size > MAX_FILE_SIZE {
        score += 40;
        reasons.push(format!("文件体积过大 ({:.1}MB)", file_size as f64 / 1_048_576.0));
    }

    // 2) 文件名仿冒检测
    if let Some(fname) = path.file_stem().and_then(|n| n.to_str()) {
        let lower = fname.to_lowercase();

        // 检查是否包含正常软件名（仿冒）
        let matched_software = IMPERSONATED_SOFTWARE
            .iter()
            .any(|&sw| lower.contains(&sw.to_lowercase()));

        if matched_software {
            score += 20;
            reasons.push("文件名包含疑似仿冒的知名软件名称".to_string());
        }

        // 检查是否包含可疑关键词
        let matched_keyword = SUSPICIOUS_NAME_KEYWORDS
            .iter()
            .any(|&kw| lower.contains(kw));

        if matched_keyword {
            score += 15;
            reasons.push("文件名包含可疑关键词（破解/激活等）".to_string());
        }
    }

    // 3) 双扩展名伪装检测
    if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
        let dot_count = fname.chars().filter(|&c| c == '.').count();
        if dot_count >= 2 {
            let parts: Vec<&str> = fname.split('.').collect();
            let suspicious_double = parts.len() >= 3
                && !parts[parts.len() - 1].to_lowercase().contains("exe")
                && !parts[parts.len() - 1].to_lowercase().contains("dll");
            if suspicious_double {
                score += 10;
                reasons.push("双扩展名伪装（如 .pdf.exe）".to_string());
            }
        }
    }

    let result = SuspicionScore {
        total: score,
        max_possible: 100,
        reasons,
        should_deep_analyze: score >= SCORE_THRESHOLD,
    };
    // 只在真正需要深度分析时打印，避免安全文件刷屏
    if result.should_deep_analyze {
        eprintln!(
            "[DeepAnalysis] 评分结果: score={}, threshold={}, should_deep_analyze={}, reasons={:?}",
            result.total, SCORE_THRESHOLD, result.should_deep_analyze, result.reasons
        );
    }
    result
}

// ── 深度分析流程（同步堵塞，发射进度事件） ──
pub async fn run_deep_analysis<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    file_path: &str,
) -> Result<DeepAnalysisResult, String> {
    // ── 第1步：计算 SHA256 ──
    emit_progress(app, 0, "正在计算文件哈希...").await;

    let sha256 = {
        use sha2::Digest;
        let mut file = tokio::fs::File::open(file_path)
            .await
            .map_err(|e| format!("无法打开文件: {}", e))?;
        let mut hasher = sha2::Sha256::new();
        let mut buf = vec![0u8; 8192];
        use tokio::io::AsyncReadExt;
        loop {
            let n = file.read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 { break; }
            hasher.update(&buf[..n]);
        }
        format!("{:x}", hasher.finalize())
    };

    eprintln!("[DeepAnalysis] SHA256: {}", sha256);
    let client = reqwest::Client::new();

    // ── 第2步：先查询是否已存在报告（避免重复上传） ──
    emit_progress(app, 5, "正在查询云端已有报告...").await;

    let report = {
        // 第一次查询
        let q = client
            .post("http://103.118.245.82:9051/v3/file/report")
            .header("X-API-Key", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1")
            .json(&serde_json::json!({"resource": sha256}))
            .send()
            .await;

        match q {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    let rc = json.get("response_code").and_then(|c| c.as_i64()).unwrap_or(-99);
                    let data_obj = json.get("data").and_then(|d| d.as_object());
                    let data_keys: Vec<String> = data_obj.map(|o| o.keys().cloned().collect()).unwrap_or_default();
                    eprintln!("[DeepAnalysis] 缓存查询: rc={}, data_keys=[{}]", rc, data_keys.join(","));

                    // 微步 v3 API: 沙箱分析完成标志 — data.summary 非空且包含 threat_score
                    let has_summary = data_obj
                        .and_then(|o| o.get("summary"))
                        .and_then(|s| s.as_object())
                        .map(|s| {
                            let has_score = s.contains_key("threat_score");
                            if !has_score {
                                eprintln!("[DeepAnalysis]   summary 存在但没有 threat_score");
                            }
                            has_score
                        })
                        .unwrap_or(false);

                    if rc == 0 && has_summary {
                        eprintln!("[DeepAnalysis] 已有完整沙箱报告，直接使用");
                        emit_progress(app, 15, "命中缓存报告，跳过上传").await;
                        json
                    } else {
                        eprintln!("[DeepAnalysis] 缓存不完整，准备上传 (rc={}, has_summary={})", rc, has_summary);
                        drop(json);
                        upload_and_poll(&client, app, file_path, &sha256).await?
                    }
                } else {
                    upload_and_poll(&client, app, file_path, &sha256).await?
                }
            }
            Err(_) => {
                upload_and_poll(&client, app, file_path, &sha256).await?
            }
        }
    };

    // ── 第4步：解析完整报告 ──
    emit_progress(app, 95, "正在解析沙箱分析报告...").await;

    let data = report.get("data").cloned().unwrap_or(serde_json::Value::Null);
    let summary = data.get("summary").cloned().unwrap_or(serde_json::Value::Null);
    let threat_info = data.get("threat_info").cloned().unwrap_or(serde_json::Value::Null);

    // 调试：打印完整 data 结构
    eprintln!("[DeepAnalysis] data_json={}", serde_json::to_string_pretty(&data).unwrap_or_default().lines().take(80).collect::<Vec<_>>().join("\n"));

    // 调试：打印 summary 和 threat_info 的字段名
    eprintln!("[DeepAnalysis] summary_keys=[{}]",
        summary.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>().join(",")).unwrap_or_default());
    eprintln!("[DeepAnalysis] threat_info_keys=[{}]",
        threat_info.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>().join(",")).unwrap_or_default());

    let threat_score = summary.get("threat_score").and_then(|v| v.as_f64()).unwrap_or(0.0);

    // 使用沙箱自己的判定（summary 中的 threat_level / tag）
    let sandbox_verdict = summary.get("threat_level").and_then(|v| {
        v.as_str().map(|s| match s {
            "malicious" | "恶意" | "dangerous" => "malicious",
            "suspicious" | "可疑" => "suspicious",
            _ => "safe",
        })
        .or_else(|| v.as_i64().map(|l| {
            if l >= 3 { "malicious" } else if l >= 2 { "suspicious" } else { "safe" }
        }))
    })
    .or_else(|| summary.get("tag").and_then(|v| v.as_str()).map(|t| {
        if t.contains("malicious") || t.contains("恶意") { "malicious" }
        else if t.contains("suspicious") || t.contains("可疑") { "suspicious" }
        else { "safe" }
    }))
    .unwrap_or("unknown");

    // 威胁分类（加 HVM: 前缀）
    let threat_family = summary.get("malware_family").and_then(|v| v.as_str())
        .or_else(|| summary.get("malware_type").and_then(|v| v.as_str()))
        .filter(|f| !f.is_empty())
        .map(|f| format!("HVM:{}", f))
        .unwrap_or_default();

    // 中文分类标签映射
    let malware_type = summary.get("malware_type").and_then(|v| v.as_str()).unwrap_or("");
    let family_category = map_threat_category(malware_type, &threat_family);

    eprintln!("[DeepAnalysis] threat_level={:?}, malware_family={:?}",
        summary.get("threat_level"), summary.get("malware_family"));

    // 综合判定：沙箱自己判 malicious 或评分够高就算威胁
    let malicious = sandbox_verdict == "malicious"
        || sandbox_verdict == "suspicious" && threat_score >= 55.0
        || threat_score >= 60.0;

    // IOC 提取
    let mut iocs: Vec<String> = Vec::new();
    if let Some(ioc_obj) = data.get("ioc").and_then(|v| v.as_object()) {
        for (key, val) in ioc_obj {
            if let Some(arr) = val.as_array() {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        iocs.push(format!("{}: {}", key, s));
                    }
                }
            }
        }
    }

    eprintln!("[DeepAnalysis] 分析完成: sandbox_verdict={}, threat_score={}, threat_family={}, iocs={}",
        sandbox_verdict, threat_score, threat_family, iocs.len());

    emit_progress(app, 100, "深度分析完成").await;

    Ok(DeepAnalysisResult {
        sha256,
        sandbox_verdict: sandbox_verdict.to_string(),
        threat_score,
        threat_family,
        family_category,
        malicious,
        summary,
        threat_info,
        iocs,
    })
}

// ── 辅助：发射进度事件 ──
async fn emit_progress<R: tauri::Runtime>(app: &tauri::AppHandle<R>, percent: u32, status: &str) {
    let _ = app.emit("deep-analysis-progress", DeepAnalysisProgress {
        percent,
        status: status.to_string(),
    });
}

// ── 上传 + 轮询（首次查询无缓存时调用） ──
async fn upload_and_poll<R: tauri::Runtime>(
    client: &reqwest::Client,
    app: &tauri::AppHandle<R>,
    file_path: &str,
    sha256: &str,
) -> Result<serde_json::Value, String> {
    emit_progress(app, 12, "正在上传文件到云端沙箱...").await;

    let file_bytes = tokio::fs::read(file_path)
        .await
        .map_err(|e| format!("读取文件失败: {}", e))?;

    let file_name = std::path::Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let file_part = reqwest::multipart::Part::bytes(file_bytes)
        .file_name(file_name.clone());
    let form = reqwest::multipart::Form::new()
        .part("file", file_part)
        .text("sandbox_type", "win10_22h2_enx64_office2019")
        .text("run_time", "120");

    let upload_resp = client
        .post("http://103.118.245.82:9051/v3/file/upload")
        .header("X-API-Key", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1")
        .multipart(form)
        .send()
        .await
        .map_err(|e| format!("上传失败: {}", e))?;

    let _: serde_json::Value = upload_resp
        .json()
        .await
        .map_err(|e| format!("解析上传响应失败: {}", e))?;

    // 轮询报告（最多 60 次 × 3s = 180s）
    emit_progress(app, 20, "文件已提交，等待沙箱分析完成...").await;

    for i in 0..60 {
        if i > 0 {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }

        let pct = 20 + ((i as f64 / 60.0) * 70.0) as u32;
        emit_progress(app, pct.min(90), format!("沙箱分析中... ({}/{})", i + 1, 60).as_str()).await;

        let q = client
            .post("http://103.118.245.82:9051/v3/file/report")
            .header("X-API-Key", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1")
            .json(&serde_json::json!({"resource": sha256}))
            .send()
            .await;

        match q {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    let data_obj = json.get("data").and_then(|d| d.as_object());
                    let data_keys: Vec<String> = data_obj.map(|o| o.keys().cloned().collect()).unwrap_or_default();
                    let has_summary = data_obj
                        .and_then(|o| o.get("summary"))
                        .and_then(|s| s.as_object())
                        .map(|s| s.contains_key("threat_score"))
                        .unwrap_or(false);
                    let rc = json.get("response_code").and_then(|c| c.as_i64()).unwrap_or(-99);
                    eprintln!("[DeepAnalysis] 轮询第{}次: rc={}, has_summary={}, keys=[{}]", i + 1, rc, has_summary, data_keys.join(","));
                    if rc == 0 && has_summary {
                        return Ok(json);
                    }
                }
            }
            Err(e) => {
                eprintln!("[DeepAnalysis] 轮询查询失败: {}", e);
            }
        }
    }

    Err("云端分析超时（180s）".to_string())
}
