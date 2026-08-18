//! AVIC (自制杀软联合情报中心) 云端威胁情报模块
//!
//! 双向集成：
//! - **查询**：防护（文件防护、进程防护）拦截前查询 AVIC 信誉库，命中恶意哈希则直接拦截
//! - **上报**：防护检出恶意时自动上报 SHA256 到 AVIC 平台
//!
//! 本地缓存：查询结果缓存到 SQLite/内存，命中缓存时零延迟。
//!
//! API 文档: http://103.118.245.82:9501/api/v1/
//! 认证方式: X-API-Key 请求头

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// AVIC API 服务地址
const AVIC_BASE_URL: &str = "http://103.118.245.82:9501";

/// AVIC API Key（硬编码）
const AVIC_API_KEY: &str = "AVIC-518D05C4E45800493487D1C68B9CFCB0";

/// 缓存条目有效期（24 小时）
const CACHE_TTL: Duration = Duration::from_secs(86400);

/// 查询结果缓存：SHA256 → (是否恶意, 威胁名, 插入时间)
static CACHE: Mutex<Option<HashMap<String, CacheEntry>>> = Mutex::new(None);

struct CacheEntry {
    is_malicious: bool,
    threat_name: String,
    inserted: Instant,
}

/// 检查 AVIC 是否已配置（始终为 true，Key 已硬编码）
pub fn is_configured() -> bool {
    true
}

/// 计算文件的 SHA256 哈希
fn compute_sha256(file_path: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(file_path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];

    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return None,
        }
    }

    let result = hasher.finalize();
    Some(format!("{:x}", result))
}

/// 查询 AVIC 信誉库（带本地缓存）
///
/// 返回值：
/// - `Some((threat_name, family))`：命中恶意哈希，应立即拦截
/// - `None`：未命中或查询失败，继续其他检测
///
/// 缓存策略：
/// - 命中缓存的恶意记录：永久有效（不放过已知威胁）
/// - 命中缓存的安全记录：24 小时后过期
/// - 未命中缓存：同步查询 AVIC API（约 50-200ms）
pub fn query_hash(hash: &str) -> Option<(String, String)> {
    // 1. 先查本地缓存
    {
        let mut guard = CACHE.lock().ok()?;
        if let Some(ref mut cache) = *guard {
            if let Some(entry) = cache.get(hash) {
                let elapsed = entry.inserted.elapsed();
                // 恶意记录永久有效；安全记录 24 小时过期
                if entry.is_malicious || elapsed < CACHE_TTL {
                    if entry.is_malicious {
                        println!("[AVIC] 缓存命中（恶意）: {}... threat={}", &hash[..hash.len().min(16)], entry.threat_name);
                        return Some((entry.threat_name.clone(), String::new()));
                    }
                    // 安全记录缓存命中，不拦截
                    return None;
                }
                // 过期，移除
                cache.remove(hash);
            }
        }
    }

    // 2. 查询 AVIC API
    let url = format!("{}/api/v1/query", AVIC_BASE_URL);
    let body = serde_json::json!({ "hash": hash }).to_string();

    // 构建带超时的 agent：默认 ureq 无超时，服务器不可达时会长时间阻塞
    // 调用线程（WMI 回调/文件监控回调），导致监控线程卡死。
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(3))
        .timeout_read(Duration::from_secs(5))
        .timeout_write(Duration::from_secs(5))
        .build();

    match agent.post(&url)
        .set("X-API-Key", AVIC_API_KEY)
        .set("Content-Type", "application/json")
        .send_string(&body)
    {
        Ok(resp) => {
            match resp.into_json::<serde_json::Value>() {
                Ok(json) => {
                    let found = json.get("found").and_then(|v| v.as_bool()).unwrap_or(false);
                    let classification = json.get("classification").and_then(|v| v.as_str()).unwrap_or("");

                    if found && classification == "malicious" {
                        let threat_name = json.get("threat_name").and_then(|v| v.as_str()).unwrap_or("AVIC.Malicious").to_string();
                        let family = json.get("family").and_then(|v| v.as_str()).unwrap_or("").to_string();

                        println!(
                            "[AVIC] 信誉库命中（恶意）: {}... threat={} family={}",
                            &hash[..hash.len().min(16)], threat_name, family
                        );

                        // 写入缓存（恶意记录永久有效）
                        if let Ok(mut guard) = CACHE.lock() {
                            let cache = guard.get_or_insert_with(HashMap::new);
                            cache.insert(hash.to_string(), CacheEntry {
                                is_malicious: true,
                                threat_name: threat_name.clone(),
                                inserted: Instant::now(),
                            });
                        }

                        return Some((threat_name, family));
                    }

                    // 未命中或安全 → 缓存为安全记录
                    if let Ok(mut guard) = CACHE.lock() {
                        let cache = guard.get_or_insert_with(HashMap::new);
                        cache.insert(hash.to_string(), CacheEntry {
                            is_malicious: false,
                            threat_name: String::new(),
                            inserted: Instant::now(),
                        });
                    }

                    None
                }
                Err(e) => {
                    println!("[AVIC] 查询解析失败: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            println!("[AVIC] 查询失败: {}", e);
            None
        }
    }
}

/// 查询文件是否为 AVIC 已知恶意（先算 SHA256 再查信誉库）
///
/// 返回值：
/// - `Some((threat_name, family))`：命中恶意，应立即拦截
/// - `None`：未命中或无法查询，继续其他检测
pub fn check_file(file_path: &str) -> Option<(String, String)> {
    let hash = compute_sha256(file_path)?;
    query_hash(&hash)
}

/// 上报威胁哈希到 AVIC 平台
///
/// 仅在防护场景调用（文件防护、进程防护、沙箱拦截）。
/// 在后台线程中执行，不阻塞主流程。
pub fn submit_threat(file_path: &str, threat_name: &str, family: &str, source: &str) {
    let path_owned = file_path.to_string();
    let threat_owned = threat_name.to_string();
    let family_owned = family.to_string();
    let source_owned = source.to_string();

    std::thread::spawn(move || {
        let hash = match compute_sha256(&path_owned) {
            Some(h) => h,
            None => {
                println!("[AVIC] 无法计算哈希，跳过上报: {}", path_owned);
                return;
            }
        };

        let file_name = Path::new(&path_owned)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        let description = format!(
            "[{}] 文件名: {} | 路径: {} | 来源: {}",
            source_owned, file_name, path_owned, source_owned
        );

        let tags = format!("{}, {}, xigua-security", source_owned, family_owned);

        println!(
            "[AVIC] 上报威胁: {} hash={}... threat={} family={}",
            file_name,
            &hash[..hash.len().min(16)],
            threat_owned,
            family_owned
        );

        let body = serde_json::json!({
            "hash": hash,
            "threat_name": threat_owned,
            "family": family_owned,
            "description": description,
            "tags": tags,
        });

        let url = format!("{}/api/v1/submit", AVIC_BASE_URL);
        let body_str = body.to_string();
        // 带超时的 agent，避免服务器不可达时后台线程永久阻塞
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(3))
            .timeout_read(Duration::from_secs(5))
            .timeout_write(Duration::from_secs(5))
            .build();
        match agent.post(&url)
            .set("X-API-Key", AVIC_API_KEY)
            .set("Content-Type", "application/json")
            .send_string(&body_str)
        {
            Ok(resp) => {
                let status = resp.status();
                match resp.into_json::<serde_json::Value>() {
                    Ok(json) => {
                        let msg = json.get("message").and_then(|v| v.as_str()).unwrap_or("");
                        let classification = json.get("classification").and_then(|v| v.as_str()).unwrap_or("");
                        println!(
                            "[AVIC] 上报成功: status={} classification={} message={} ({} hash={})",
                            status, classification, msg, file_name, &hash[..hash.len().min(16)]
                        );

                        // 上报后同时更新本地缓存为恶意
                        if let Ok(mut guard) = CACHE.lock() {
                            let cache = guard.get_or_insert_with(HashMap::new);
                            cache.insert(hash, CacheEntry {
                                is_malicious: true,
                                threat_name: threat_owned.clone(),
                                inserted: Instant::now(),
                            });
                        }
                    }
                    Err(e) => {
                        println!("[AVIC] 解析响应失败: status={} err={}", status, e);
                    }
                }
            }
            Err(e) => {
                println!("[AVIC] 上报失败: {} ({})", e, file_name);
            }
        }
    });
}

/// 测试 AVIC 连接（检查 API 状态）
pub fn test_connection() -> Result<String, String> {
    let url = format!("{}/api/v1/status", AVIC_BASE_URL);

    let resp = ureq::get(&url)
        .set("X-API-Key", AVIC_API_KEY)
        .call()
        .map_err(|e| format!("请求失败: {}", e))?;

    let json: serde_json::Value = resp
        .into_json()
        .map_err(|e| format!("解析响应失败: {}", e))?;

    let online = json.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
    let db_total = json
        .get("database")
        .and_then(|d| d.get("total_hashes"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let trusted = json
        .get("api_key")
        .and_then(|k| k.get("trusted"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Ok(format!(
        "连接成功 | 状态: {} | 数据库: {} 条 | 密钥可信: {}",
        online, db_total, trusted
    ))
}
