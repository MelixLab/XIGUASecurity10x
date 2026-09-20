use serde::{Deserialize, Serialize};
use std::time::Duration;

/// 公告服务地址（默认空，通过环境变量 XIGUA_ANNOUNCEMENT_URL 配置）
const ANNOUNCEMENT_API_URL: &str = "";

/// 公告信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Announcement {
    pub id: String,
    pub title: String,
    pub content: String,
    #[serde(alias = "publish_date", alias = "publishDate")]
    pub publish_date: String,
    pub author: Option<String>,
}

/// 获取最新公告
pub async fn fetch_latest_announcement() -> Result<Option<Announcement>, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let api_url = std::env::var("XIGUA_ANNOUNCEMENT_URL")
        .unwrap_or_else(|_| ANNOUNCEMENT_API_URL.to_string());
    if api_url.is_empty() {
        return Ok(None);
    }

    println!("[Announcement] Fetching latest announcement from: {}", api_url);

    let response = client
        .get(api_url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch announcement: {}", e))?;

    if !response.status().is_success() {
        if response.status() == 404 {
            println!("[Announcement] No announcement found");
            return Ok(None);
        }
        return Err(format!("HTTP error: {}", response.status()));
    }

    // 先获取原始文本以便调试
    let text = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;
    println!("[Announcement] Raw response: {}", text);

    let announcement: Announcement = serde_json::from_str(&text)
        .map_err(|e| format!("Failed to parse announcement: {}", e))?;

    println!("[Announcement] Fetched announcement: {}", announcement.title);
    Ok(Some(announcement))
}
