use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use reqwest;
use serde_json;

/// 日志上传服务固定地址（内置，不暴露给用户）
const DEFAULT_SERVER_URL: &str = "http://103.118.245.82:8052";

/// 客户端日志上传器
/// 负责把主程序最近的日志/行为时间线批量上传到远端 Python 收集服务
pub struct LogUploader {
    enabled: AtomicBool,
    server_url: String,
    device_name: String,
    recent_logs: Mutex<VecDeque<serde_json::Value>>,
    client: reqwest::Client,
}

impl LogUploader {
    pub fn new() -> Result<Self, String> {
        let device_name = Self::compute_device_name();

        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| format!("创建 HTTP 客户端失败: {}", e))?;

        Ok(Self {
            enabled: AtomicBool::new(true),
            server_url: DEFAULT_SERVER_URL.to_string(),
            device_name,
            recent_logs: Mutex::new(VecDeque::new()),
            client,
        })
    }

    fn compute_device_name() -> String {
        #[cfg(target_os = "windows")]
        {
            if let Ok(name) = std::env::var("COMPUTERNAME") {
                return name;
            }
        }
        if let Ok(name) = std::env::var("HOSTNAME") {
            return name;
        }
        "unknown-device".to_string()
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn get_device_name(&self) -> String {
        self.device_name.clone()
    }

    /// 接收前端推送过来的最近日志（批量）
    pub fn push_recent_logs(&self, entries: Vec<serde_json::Value>) -> usize {
        if !self.is_enabled() || entries.is_empty() {
            return 0;
        }
        let mut queue = self.recent_logs.lock().unwrap();
        let count = entries.len();
        for entry in entries {
            queue.push_back(entry);
        }
        // 只保留最近 500 条未上传日志，避免内存无限增长
        while queue.len() > 500 {
            queue.pop_front();
        }
        count
    }

    /// 把队列中的日志批量发送给服务器
    pub async fn flush_recent_logs(&self) -> Result<usize, String> {
        if !self.is_enabled() {
            return Ok(0);
        }

        let entries: Vec<serde_json::Value> = {
            let mut queue = self.recent_logs.lock().unwrap();
            if queue.is_empty() {
                return Ok(0);
            }
            queue.drain(..).collect()
        };

        let payload = serde_json::json!({
            "device_name": self.device_name,
            "entries": entries,
        });

        let resp = self.client
            .post(format!("{}/api/logs/batch", self.server_url))
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("上传日志请求失败: {}", e))?;

        if resp.status().is_success() {
            Ok(entries.len())
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            Err(format!("日志上传失败: {} - {}", status, body))
        }
    }

    /// 发送心跳，保持设备在线状态
    pub async fn send_heartbeat(&self) -> Result<(), String> {
        if !self.is_enabled() {
            return Ok(());
        }

        let payload = serde_json::json!({
            "device_name": self.device_name,
        });

        let resp = self.client
            .post(format!("{}/api/heartbeat", self.server_url))
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("心跳请求失败: {}", e))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            Err(format!("心跳失败: {} - {}", status, body))
        }
    }
}

use std::sync::OnceLock;

static LOG_UPLOADER: OnceLock<LogUploader> = OnceLock::new();

pub fn init_log_uploader() -> Result<(), String> {
    let uploader = LogUploader::new()?;
    LOG_UPLOADER.set(uploader).map_err(|_| "日志上传器已初始化".to_string())?;
    Ok(())
}

pub fn get_log_uploader() -> Result<&'static LogUploader, String> {
    LOG_UPLOADER.get().ok_or_else(|| "日志上传器未初始化".to_string())
}
