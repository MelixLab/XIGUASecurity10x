use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;
use reqwest;
use tauri::Emitter;
use lazy_static::lazy_static;

lazy_static! {
    static ref RULES_SERVER_URL: Mutex<String> = Mutex::new("http://103.118.245.82:5001".to_string());
}

/// 设置规则库服务端地址
pub fn set_rules_server_url(url: String) {
    let mut guard = RULES_SERVER_URL.lock().unwrap();
    *guard = url.trim_end_matches('/').to_string();
    println!("[RulesUpdater] Server URL set to: {}", *guard);
}

pub fn get_rules_server_url() -> String {
    RULES_SERVER_URL.lock().unwrap().clone()
}

/// 规则库下载进度
#[derive(Debug, Clone, Serialize)]
pub struct RulesDownloadProgress {
    pub progress: u32,
    pub status: String,
}

/// 最新版本信息（与服务端 /api/rules/latest 返回格式保持一致）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatestVersionInfo {
    pub version: String,
    pub updated_at: String,
    pub description: String,
    pub files: RuleFiles,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFiles {
    pub db: RuleFileInfo,
    // 保留旧字段，兼容旧服务端
    pub whitelist: Option<RuleFileInfo>,
    pub blacklist: Option<RuleFileInfo>,
    pub virus_families: Option<RuleFileInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFileInfo {
    pub version: String,
    pub url: String,
    pub hash: String,
}

/// 本地规则库信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalRulesInfo {
    pub version: String,
    pub updated_at: String,
    pub last_check: String,
}

impl Default for LocalRulesInfo {
    fn default() -> Self {
        Self {
            version: "0.0.0".to_string(),
            updated_at: "1970-01-01 00:00:00".to_string(),
            last_check: "1970-01-01 00:00:00".to_string(),
        }
    }
}

/// 检查规则库更新 - 从自建 Python 服务端获取最新版本
pub async fn check_rules_update() -> Result<Option<LatestVersionInfo>, String> {
    let server_url = get_rules_server_url();
    let latest_url = format!("{}/api/rules/latest", server_url);
    println!("[RulesUpdater] - Checking for rules update from: {}", latest_url);

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;

    let response = client
        .get(&latest_url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch version info: {}", e))?;

    if !response.status().is_success() {
        println!("[RulesUpdater] - HTTP error: {}", response.status());
        return Err(format!("HTTP error: {}", response.status()));
    }

    let mut remote_info: LatestVersionInfo = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse version info: {}", e))?;

    println!("[RulesUpdater] - Remote version: {}", remote_info.version);

    // 服务端可能返回相对 URL，补齐为绝对 URL
    remote_info.files.db.url = make_absolute_url(&server_url, &remote_info.files.db.url);
    if let Some(ref mut f) = remote_info.files.whitelist.as_mut() {
        f.url = make_absolute_url(&server_url, &f.url);
    }
    if let Some(ref mut f) = remote_info.files.blacklist.as_mut() {
        f.url = make_absolute_url(&server_url, &f.url);
    }
    if let Some(ref mut f) = remote_info.files.virus_families.as_mut() {
        f.url = make_absolute_url(&server_url, &f.url);
    }

    // 获取本地版本
    let local_info = get_local_rules_info();
    println!("[RulesUpdater] - Local version: {}", local_info.version);

    // 比较版本号
    let is_newer = is_newer_version(&remote_info.version, &local_info.version);
    println!("[RulesUpdater] - Is newer: {}", is_newer);

    if is_newer {
        Ok(Some(remote_info))
    } else {
        Ok(None)
    }
}

/// 将相对 URL 转换为绝对 URL
fn make_absolute_url(base: &str, url: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        let path = if url.starts_with('/') { &url[1..] } else { url };
        format!("{}/{}", base, path)
    }
}

/// 下载并更新规则库（保留历史版本，带进度回调）
pub async fn download_and_update_rules_with_progress<R: tauri::Runtime>(
    info: &LatestVersionInfo,
    app_handle: &tauri::AppHandle<R>,
) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| e.to_string())?;
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_dir = format!("{}/XIGUASecurity", local_app_data);
    let history_dir = format!("{}/rules/history", config_dir);

    // 发送开始下载事件
    let _ = app_handle.emit("rules-download-progress", RulesDownloadProgress {
        progress: 0,
        status: "开始下载规则库...".to_string(),
    });

    // 创建配置目录、规则目录和历史目录
    fs::create_dir_all(&config_dir)
        .map_err(|e| format!("Failed to create config directory: {}", e))?;
    fs::create_dir_all(&history_dir)
        .map_err(|e| format!("Failed to create history directory: {}", e))?;

    // 获取当前版本（用于备份）
    let current_info = get_local_rules_info();
    let current_version = &current_info.version;

    // 如果当前版本不是默认版本，备份当前规则 DB 到历史目录
    if current_version != "0.0.0" {
        let _ = app_handle.emit("rules-download-progress", RulesDownloadProgress {
            progress: 10,
            status: "备份当前规则...".to_string(),
        });
        backup_current_rules_db(&config_dir, &history_dir, current_version)?;
    }

    let db_path = crate::rules_db::rules_db_path();
    let db_tmp_path = db_path.with_extension("db.tmp");

    // 下载新规则 DB（从 20% 到 89%）
    download_rule_file_with_progress(
        &client,
        &info.files.db.url,
        db_tmp_path.to_str().unwrap_or("rules.db.tmp"),
        app_handle,
        20,
        69,
        "规则数据库"
    ).await?;

    // 先关闭已加载的 DB，释放文件占用，否则 Windows 下无法替换
    crate::rules_db::close_rules_db();

    // 原子替换规则 DB
    let _ = app_handle.emit("rules-download-progress", RulesDownloadProgress {
        progress: 92,
        status: "替换规则数据库...".to_string(),
    });
    fs::rename(&db_tmp_path, &db_path)
        .map_err(|e| format!("Failed to replace rules DB: {}", e))?;

    // 更新本地版本信息
    let _ = app_handle.emit("rules-download-progress", RulesDownloadProgress {
        progress: 95,
        status: "保存版本信息...".to_string(),
    });
    let local_info = LocalRulesInfo {
        version: info.version.clone(),
        updated_at: info.updated_at.clone(),
        last_check: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
    };
    save_local_rules_info(&local_info)?;

    // 重新加载规则 DB
    let _ = app_handle.emit("rules-download-progress", RulesDownloadProgress {
        progress: 98,
        status: "重新加载规则...".to_string(),
    });
    crate::rules_db::reload_rules_db().map_err(|e| format!("Failed to reload rules DB: {}", e))?;

    // 发送完成事件
    let _ = app_handle.emit("rules-download-progress", RulesDownloadProgress {
        progress: 100,
        status: "规则库更新完成".to_string(),
    });

    Ok(())
}

/// 下载并更新规则库（保留历史版本，兼容旧版本无进度）
pub async fn download_and_update_rules(info: &LatestVersionInfo) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| e.to_string())?;
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_dir = format!("{}/XIGUASecurity", local_app_data);
    let history_dir = format!("{}/rules/history", config_dir);

    // 创建规则目录和历史目录
    fs::create_dir_all(&config_dir)
        .map_err(|e| format!("Failed to create config directory: {}", e))?;
    fs::create_dir_all(&history_dir)
        .map_err(|e| format!("Failed to create history directory: {}", e))?;

    // 获取当前版本（用于备份）
    let current_info = get_local_rules_info();
    let current_version = &current_info.version;

    // 如果当前版本不是默认版本，备份当前规则 DB 到历史目录
    if current_version != "0.0.0" {
        backup_current_rules_db(&config_dir, &history_dir, current_version)?;
    }

    let db_path = crate::rules_db::rules_db_path();
    let db_tmp_path = db_path.with_extension("db.tmp");

    // 下载新规则 DB
    download_rule_file(&client, &info.files.db.url, db_tmp_path.to_str().unwrap()).await?;

    // 先关闭已加载的 DB，释放文件占用，否则 Windows 下无法替换
    crate::rules_db::close_rules_db();

    // 原子替换规则 DB
    fs::rename(&db_tmp_path, &db_path)
        .map_err(|e| format!("Failed to replace rules DB: {}", e))?;

    // 更新本地版本信息
    let local_info = LocalRulesInfo {
        version: info.version.clone(),
        updated_at: info.updated_at.clone(),
        last_check: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
    };
    save_local_rules_info(&local_info)?;

    // 重新加载规则 DB
    crate::rules_db::reload_rules_db().map_err(|e| format!("Failed to reload rules DB: {}", e))?;

    Ok(())
}

/// 备份当前规则 DB 到历史目录
fn backup_current_rules_db(_config_dir: &str, history_dir: &str, version: &str) -> Result<(), String> {
    let version_dir = format!("{}/{}", history_dir, version);

    fs::create_dir_all(&version_dir)
        .map_err(|e| format!("Failed to create version history directory: {}", e))?;

    let db_path = crate::rules_db::rules_db_path();
    let db_dst = format!("{}/rules.db", version_dir);
    if db_path.exists() {
        fs::copy(&db_path, &db_dst)
            .map_err(|e| format!("Failed to backup rules DB: {}", e))?;
    }

    println!("[RulesUpdater] - Backed up DB version {} to history", version);
    Ok(())
}

/// 备份当前规则文件到历史目录（兼容旧版 JSON 规则）
fn backup_current_rules(config_dir: &str, rules_dir: &str, history_dir: &str, version: &str) -> Result<(), String> {
    let version_dir = format!("{}/{}", history_dir, version);

    // 创建版本历史目录
    fs::create_dir_all(&version_dir)
        .map_err(|e| format!("Failed to create version history directory: {}", e))?;

    // 备份白名单（配置根目录）
    let whitelist_src = format!("{}/whitelist.json", config_dir);
    let whitelist_dst = format!("{}/whitelist.json", version_dir);
    if Path::new(&whitelist_src).exists() {
        fs::copy(&whitelist_src, &whitelist_dst)
            .map_err(|e| format!("Failed to backup whitelist: {}", e))?;
    }

    // 备份黑名单（配置根目录）
    let blacklist_src = format!("{}/blacklist.json", config_dir);
    let blacklist_dst = format!("{}/blacklist.json", version_dir);
    if Path::new(&blacklist_src).exists() {
        fs::copy(&blacklist_src, &blacklist_dst)
            .map_err(|e| format!("Failed to backup blacklist: {}", e))?;
    }

    // 备份病毒家族规则（rules 子目录）
    let virus_src = format!("{}/virus_families.json", rules_dir);
    let virus_dst = format!("{}/virus_families.json", version_dir);
    if Path::new(&virus_src).exists() {
        fs::copy(&virus_src, &virus_dst)
            .map_err(|e| format!("Failed to backup virus families: {}", e))?;
    }

    println!("[RulesUpdater] - Backed up version {} to history", version);
    Ok(())
}

/// 获取历史版本列表
pub fn get_rule_history_versions() -> Vec<String> {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let history_dir = format!("{}/XIGUASecurity/rules/history", local_app_data);

    let mut versions = Vec::new();

    if let Ok(entries) = fs::read_dir(&history_dir) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        versions.push(name.to_string());
                    }
                }
            }
        }
    }

    // 按版本号排序（降序）
    versions.sort_by(|a, b| {
        let a_parts: Vec<u32> = a.split('.').filter_map(|s| s.parse().ok()).collect();
        let b_parts: Vec<u32> = b.split('.').filter_map(|s| s.parse().ok()).collect();

        for i in 0..a_parts.len().max(b_parts.len()) {
            let a_val = a_parts.get(i).copied().unwrap_or(0);
            let b_val = b_parts.get(i).copied().unwrap_or(0);

            if a_val != b_val {
                return b_val.cmp(&a_val); // 降序
            }
        }

        std::cmp::Ordering::Equal
    });

    versions
}

/// 下载单个规则文件（带进度回调）
async fn download_rule_file_with_progress<R: tauri::Runtime>(
    client: &reqwest::Client,
    url: &str,
    path: &str,
    app_handle: &tauri::AppHandle<R>,
    base_progress: u32,
    progress_range: u32,
    file_name: &str,
) -> Result<(), String> {
    println!("[RulesUpdater] - Downloading: {}", url);

    let start_time = std::time::Instant::now();
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Failed to download {}: {}", url, e))?;

    let elapsed = start_time.elapsed();
    println!("[RulesUpdater] - Response received in {:?}", elapsed);

    if !response.status().is_success() {
        return Err(format!("HTTP error for {}: {}", url, response.status()));
    }

    // 获取总大小
    let total_size = response.content_length().unwrap_or(0);
    println!("[RulesUpdater] - Total size: {} bytes", total_size);

    // 使用流式下载
    use futures_util::StreamExt;
    let mut stream = response.bytes_stream();
    let mut downloaded: u64 = 0;
    let mut file = fs::File::create(path)
        .map_err(|e| format!("Failed to create file {}: {}", path, e))?;

    let mut last_reported_progress = base_progress;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("Download chunk error: {}", e))?;
        file.write_all(&chunk)
            .map_err(|e| format!("Failed to write chunk: {}", e))?;
        downloaded += chunk.len() as u64;

        // 计算并发送进度（每1%更新一次）
        if total_size > 0 {
            let file_progress_percent = ((downloaded as f64 / total_size as f64) * 100.0) as u32;
            let overall_progress = base_progress + (file_progress_percent * progress_range / 100);

            // 确保至少每1%更新一次
            if overall_progress > last_reported_progress {
                last_reported_progress = overall_progress;
                let _ = app_handle.emit("rules-download-progress", RulesDownloadProgress {
                    progress: overall_progress.min(99),
                    status: format!("下载{}... {}%", file_name, file_progress_percent),
                });
            }
        }
    }

    file.flush().map_err(|e| format!("Failed to flush file: {}", e))?;
    drop(file);

    let total_elapsed = start_time.elapsed();
    let size_mb = downloaded as f64 / 1024.0 / 1024.0;
    println!("[RulesUpdater] - Downloaded {:.2} MB in {:?}", size_mb, total_elapsed);

    Ok(())
}

/// 下载单个规则文件（无进度回调，兼容旧版本）
async fn download_rule_file(client: &reqwest::Client, url: &str, path: &str) -> Result<(), String> {
    println!("[RulesUpdater] - Downloading: {}", url);

    let start_time = std::time::Instant::now();
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Failed to download {}: {}", url, e))?;

    let elapsed = start_time.elapsed();
    println!("[RulesUpdater] - Response received in {:?}", elapsed);

    if !response.status().is_success() {
        return Err(format!("HTTP error for {}: {}", url, response.status()));
    }

    // 获取总大小
    let total_size = response.content_length().unwrap_or(0);
    println!("[RulesUpdater] - Total size: {} bytes", total_size);

    // 使用流式下载
    use futures_util::StreamExt;
    let mut stream = response.bytes_stream();
    let mut downloaded: u64 = 0;
    let mut file = fs::File::create(path)
        .map_err(|e| format!("Failed to create file {}: {}", path, e))?;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("Download chunk error: {}", e))?;
        file.write_all(&chunk)
            .map_err(|e| format!("Failed to write chunk: {}", e))?;
        downloaded += chunk.len() as u64;
    }

    file.flush().map_err(|e| format!("Failed to flush file: {}", e))?;
    drop(file);

    let total_elapsed = start_time.elapsed();
    let size_mb = downloaded as f64 / 1024.0 / 1024.0;
    println!("[RulesUpdater] - Downloaded {:.2} MB in {:?}", size_mb, total_elapsed);

    Ok(())
}

/// 获取本地规则库信息
pub fn get_local_rules_info() -> LocalRulesInfo {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let info_path = format!("{}/XIGUASecurity/rules_info.json", local_app_data);

    if !Path::new(&info_path).exists() {
        return LocalRulesInfo::default();
    }

    match fs::read_to_string(&info_path) {
        Ok(content) => {
            serde_json::from_str(&content).unwrap_or_default()
        }
        Err(_) => LocalRulesInfo::default(),
    }
}

/// 保存本地规则库信息
fn save_local_rules_info(info: &LocalRulesInfo) -> Result<(), String> {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_dir = format!("{}/XIGUASecurity", local_app_data);

    fs::create_dir_all(&config_dir)
        .map_err(|e| format!("Failed to create config dir: {}", e))?;

    let info_path = format!("{}/rules_info.json", config_dir);
    let content = serde_json::to_string_pretty(info)
        .map_err(|e| format!("Failed to serialize rules info: {}", e))?;

    fs::write(&info_path, content)
        .map_err(|e| format!("Failed to write rules info: {}", e))?;

    Ok(())
}

/// 比较版本号，判断 remote 是否比 local 新
fn is_newer_version(remote: &str, local: &str) -> bool {
    let remote_parts: Vec<u32> = remote.split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    let local_parts: Vec<u32> = local.split('.')
        .filter_map(|s| s.parse().ok())
        .collect();

    for i in 0..remote_parts.len().max(local_parts.len()) {
        let remote_val = remote_parts.get(i).copied().unwrap_or(0);
        let local_val = local_parts.get(i).copied().unwrap_or(0);

        if remote_val > local_val {
            return true;
        } else if remote_val < local_val {
            return false;
        }
    }

    false
}

/// 获取规则库状态信息（用于前端显示）
pub fn get_rules_status() -> serde_json::Value {
    let info = get_local_rules_info();

    // 从 rules_info.json 读取文件数量和哈希数量
    let (file_count, hash_count) = get_rules_counts();

    serde_json::json!({
        "version": info.version,
        "updated_at": info.updated_at,
        "last_check": info.last_check,
        "file_count": file_count,
        "hash_count": hash_count,
    })
}

/// 获取已加载的规则文件数量和哈希数量
fn get_rules_counts() -> (usize, usize) {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let info_path = std::path::PathBuf::from(&local_app_data)
        .join("XIGUASecurity")
        .join("rules_info.json");

    if let Ok(content) = fs::read_to_string(&info_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            let file_count = json.get("file_count")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .unwrap_or(0);
            let hash_count = json.get("hash_count")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .unwrap_or(0);
            return (file_count, hash_count);
        }
    }

    (0, 0)
}

/// 检查是否应该自动检查更新（每天一次）
pub fn should_auto_check() -> bool {
    let info = get_local_rules_info();
    let last_check = match chrono::NaiveDateTime::parse_from_str(&info.last_check, "%Y-%m-%d %H:%M:%S") {
        Ok(dt) => dt,
        Err(_) => return true, // 如果解析失败，允许检查
    };

    let now = chrono::Local::now().naive_local();
    let duration = now.signed_duration_since(last_check);

    // 如果距离上次检查超过24小时，则允许检查
    duration.num_hours() >= 24
}

/// 更新最后检查时间
pub fn update_last_check_time() {
    let mut info = get_local_rules_info();
    info.last_check = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let _ = save_local_rules_info(&info);
}
