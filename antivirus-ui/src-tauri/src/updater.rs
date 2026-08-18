use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use reqwest;
use tauri::Emitter;

// 镜像站前缀 - 用于加速 GitHub 文件下载
const MIRROR_PREFIX: &str = "https://github.lmxdg.de5.net/";

const GITHUB_REPO: &str = "MelixLab/XIGUASecurity10x";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub has_update: bool,
    pub current_version: String,
    pub latest_version: String,
    pub download_url: Option<String>,
    pub release_notes: String,
    pub file_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DownloadProgress {
    pub progress: u32,
    pub status: String,
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    body: String,
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

/// 检查更新
pub async fn check_update() -> Result<UpdateInfo, String> {
    println!("[Updater] - Checking for updates...");
    println!("[Updater] - Current version: {}", CURRENT_VERSION);
    
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    
    // 获取 GitHub 最新 Release
    let url = format!("https://api.github.com/repos/{}/releases/latest", GITHUB_REPO);
    println!("[Updater] - Fetching from: {}", url);
    
    let response = client
        .get(&url)
        .header("User-Agent", "XIGUASecurity-Updater")
        .send()
        .await
        .map_err(|e| format!("Failed to fetch release: {}", e))?;
    
    println!("[Updater] - Response status: {}", response.status());
    
    if !response.status().is_success() {
        return Err(format!("GitHub API error: {}", response.status()));
    }
    
    let release: GitHubRelease = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse release: {}", e))?;
    
    println!("[Updater] - Latest release tag: {}", release.tag_name);
    
    // 解析版本号（去掉 v 前缀）
    let latest_version = release.tag_name.trim_start_matches('v').to_string();
    println!("[Updater] - Parsed latest version: {}", latest_version);
    
    let current = parse_version(CURRENT_VERSION)?;
    let latest = parse_version(&latest_version)?;
    
    println!("[Updater] - Current version parsed: {:?}", current);
    println!("[Updater] - Latest version parsed: {:?}", latest);
    
    // 比较版本
    let has_update = latest > current;
    println!("[Updater] - Has update: {}", has_update);
    
    // 查找安装包资源
    let download_url = release.assets
        .iter()
        .find(|a| a.name.ends_with("-setup.exe"))
        .map(|a| a.browser_download_url.clone());
    
    println!("[Updater] - Download URL: {:?}", download_url);
    
    Ok(UpdateInfo {
        has_update,
        current_version: CURRENT_VERSION.to_string(),
        latest_version,
        download_url,
        release_notes: release.body,
        file_hash: None,
    })
}

/// 下载并安装更新（带进度回调）
pub async fn download_and_install_with_progress<R: tauri::Runtime>(
    url: &str,
    app_handle: &tauri::AppHandle<R>,
) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| e.to_string())?;
    
    // 下载到临时目录
    let temp_dir = std::env::temp_dir();
    let installer_path = temp_dir.join("XIGUASecurity_update.exe");
    
    // 使用镜像站加速下载
    // 历史 bug：format!("{}{}", MIRROR_PREFIX, url) 把完整 GitHub URL 拼到
    // 镜像域名后（https://github.lmxdg.de5.net/https://github.com/...），
    // 若镜像站不支持该格式则下载永远失败。改为只替换 github.com 域名前缀。
    let mirror_url = if url.starts_with("https://github.com/") {
        format!("{}{}", MIRROR_PREFIX, &url["https://github.com/".len()..])
    } else {
        url.to_string()
    };
    println!("[Updater] - Downloading update from mirror: {}", mirror_url);
    
    // 发送开始下载事件
    let _ = app_handle.emit("download-progress", DownloadProgress {
        progress: 0,
        status: "开始下载...".to_string(),
    });
    
    let response = client
        .get(&mirror_url)
        .send()
        .await
        .map_err(|e| format!("Download failed: {}", e))?;
    
    if !response.status().is_success() {
        return Err(format!("Download error: {}", response.status()));
    }
    
    // 获取总大小
    let total_size = response.content_length().unwrap_or(0);
    println!("[Updater] - Total size: {} bytes", total_size);
    
    // 使用流式下载以获取进度
    let mut stream = response.bytes_stream();
    let mut downloaded: u64 = 0;
    let mut file = fs::File::create(&installer_path)
        .map_err(|e| format!("Failed to create file: {}", e))?;
    
    use futures_util::StreamExt;
    
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("Download chunk error: {}", e))?;
        file.write_all(&chunk)
            .map_err(|e| format!("Failed to write chunk: {}", e))?;
        downloaded += chunk.len() as u64;
        
        // 计算并发送进度
        if total_size > 0 {
            let progress = ((downloaded as f64 / total_size as f64) * 100.0) as u32;
            let _ = app_handle.emit("download-progress", DownloadProgress {
                progress,
                status: format!("下载中... {}%", progress),
            });
        }
    }
    
    file.flush().map_err(|e| format!("Failed to flush file: {}", e))?;
    drop(file);
    
    println!("[Updater] - Update downloaded to: {:?}", installer_path);
    
    // 发送下载完成事件
    let _ = app_handle.emit("download-progress", DownloadProgress {
        progress: 100,
        status: "下载完成，准备安装...".to_string(),
    });
    
    // 等待一小段时间让用户看到100%
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    // 发送安装中事件
    let _ = app_handle.emit("download-progress", DownloadProgress {
        progress: 100,
        status: "正在启动安装程序...".to_string(),
    });
    
    // 启动安装程序（使用 PowerShell Start-Process 请求管理员权限，静默安装）
    let installer_path_str = installer_path.to_string_lossy().to_string();
    println!("[Updater] - Starting installer with admin privileges: {}", installer_path_str);
    
    // 使用 PowerShell 的 Start-Process -Verb RunAs 来请求管理员权限
    let ps_command = format!(
        "Start-Process -FilePath '{}' -ArgumentList '/SILENT','/CLOSEAPPLICATIONS' -Verb RunAs -Wait",
        installer_path_str.replace("'", "''")
    );
    
    Command::new("powershell")
        .args(&["-Command", &ps_command])
        .spawn()
        .map_err(|e| format!("Failed to start installer: {}", e))?;
    
    println!("[Updater] - Installer started, exiting application...");
    
    // 发送退出事件
    let _ = app_handle.emit("download-progress", DownloadProgress {
        progress: 100,
        status: "安装程序已启动，应用即将退出...".to_string(),
    });
    
    // 等待一小段时间让用户看到消息
    tokio::time::sleep(Duration::from_millis(1000)).await;
    
    // 退出应用程序
    app_handle.exit(0);
    
    Ok(())
}

/// 下载并安装更新（兼容旧版本，无进度）
pub async fn download_and_install(url: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| e.to_string())?;
    
    let temp_dir = std::env::temp_dir();
    let installer_path = temp_dir.join("XIGUASecurity_update.exe");
    
    // 使用镜像站加速下载
    let mirror_url = format!("{}{}", MIRROR_PREFIX, url);
    println!("[Updater] - Downloading update from mirror: {}", mirror_url);
    
    let response = client
        .get(&mirror_url)
        .send()
        .await
        .map_err(|e| format!("Download failed: {}", e))?;
    
    if !response.status().is_success() {
        return Err(format!("Download error: {}", response.status()));
    }
    
    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read download: {}", e))?;
    
    fs::write(&installer_path, bytes)
        .map_err(|e| format!("Failed to save installer: {}", e))?;
    
    println!("[Updater] Update downloaded to: {:?}", installer_path);
    
    // 启动安装程序
    Command::new(&installer_path)
        .arg("/SILENT")
        .spawn()
        .map_err(|e| format!("Failed to start installer: {}", e))?;
    
    Ok(())
}

/// 解析版本号
fn parse_version(version: &str) -> Result<Vec<u32>, String> {
    version
        .split('.')
        .map(|s| s.parse::<u32>().map_err(|e| format!("Invalid version: {}", e)))
        .collect()
}

/// 获取当前版本
pub fn get_current_version() -> String {
    CURRENT_VERSION.to_string()
}
