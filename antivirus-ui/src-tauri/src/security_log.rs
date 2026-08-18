use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use chrono::{DateTime, Local, NaiveDate, NaiveDateTime};

/// 安全日志条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityLogEntry {
    pub id: String,
    pub timestamp: String,
    pub category: LogCategory,
    pub function: String,
    pub summary: String,
    pub details: Option<LogDetails>,
    pub file_path: Option<String>,
    pub threat_name: Option<String>,
    pub action: LogAction,
    pub result: LogResult,
}

/// 日志类别
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LogCategory {
    Scan,           // 扫描
    Realtime,       // 实时监控
    Behavior,       // 行为防护
    Driver,         // 驱动防护
    Update,         // 更新
    Quarantine,     // 隔离区
    System,         // 系统
    Other,          // 其他
}

impl LogCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogCategory::Scan => "扫描",
            LogCategory::Realtime => "实时监控",
            LogCategory::Behavior => "行为防护",
            LogCategory::Driver => "驱动防护",
            LogCategory::Update => "更新",
            LogCategory::Quarantine => "隔离区",
            LogCategory::System => "系统",
            LogCategory::Other => "其他",
        }
    }
}

/// 日志操作类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LogAction {
    Detected,       // 检测到威胁
    Blocked,        // 已拦截
    Cleaned,        // 已清理
    Quarantined,    // 已隔离
    Deleted,        // 已删除
    Allowed,        // 已允许
    Scanned,        // 已扫描
    Updated,        // 已更新
    Started,        // 已启动
    Stopped,        // 已停止
    Info,           // 信息
}

impl LogAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogAction::Detected => "检测到威胁",
            LogAction::Blocked => "已拦截",
            LogAction::Cleaned => "已清理",
            LogAction::Quarantined => "已隔离",
            LogAction::Deleted => "已删除",
            LogAction::Allowed => "已允许",
            LogAction::Scanned => "已扫描",
            LogAction::Updated => "已更新",
            LogAction::Started => "已启动",
            LogAction::Stopped => "已停止",
            LogAction::Info => "信息",
        }
    }
}

/// 日志结果
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LogResult {
    Success,        // 成功
    Failed,         // 失败
    Partial,        // 部分成功
    Cancelled,      // 已取消
    Pending,        // 处理中
}

impl LogResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogResult::Success => "成功",
            LogResult::Failed => "失败",
            LogResult::Partial => "部分成功",
            LogResult::Cancelled => "已取消",
            LogResult::Pending => "处理中",
        }
    }
}

/// 日志详情
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogDetails {
    pub scanned_files: Option<u64>,
    pub threats_found: Option<u64>,
    pub threats_cleaned: Option<u64>,
    pub file_size: Option<String>,
    pub virus_family: Option<String>,
    pub additional_info: Option<String>,
}

/// 安全日志管理器
pub struct SecurityLogManager {
    log_dir: PathBuf,
    current_date: Mutex<String>,
}

impl SecurityLogManager {
    /// 创建新的日志管理器
    pub fn new() -> Result<Self, String> {
        let log_dir = Self::get_log_dir()?;
        
        // 确保日志目录存在
        if !log_dir.exists() {
            fs::create_dir_all(&log_dir).map_err(|e| format!("创建日志目录失败: {}", e))?;
        }
        
        let current_date = Local::now().format("%Y-%m-%d").to_string();
        
        Ok(SecurityLogManager {
            log_dir,
            current_date: Mutex::new(current_date),
        })
    }
    
    /// 获取日志目录
    fn get_log_dir() -> Result<PathBuf, String> {
        let app_dir = dirs::data_local_dir()
            .ok_or_else(|| "无法获取本地数据目录".to_string())?;
        Ok(app_dir.join("XIGUASecurity").join("logs"))
    }
    
    /// 获取当前日志文件路径
    fn get_current_log_file(&self) -> PathBuf {
        let date = Local::now().format("%Y-%m-%d").to_string();
        self.log_dir.join(format!("security_log_{}.jsonl", date))
    }
    
    /// 添加日志条目
    pub fn add_log(&self, entry: SecurityLogEntry) -> Result<(), String> {
        let log_file = self.get_current_log_file();
        
        let json = serde_json::to_string(&entry)
            .map_err(|e| format!("序列化日志失败: {}", e))?;
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .map_err(|e| format!("打开日志文件失败: {}", e))?;
        
        writeln!(file, "{}", json).map_err(|e| format!("写入日志失败: {}", e))?;
        
        Ok(())
    }
    
    /// 获取日志列表（支持筛选和分页）
    pub fn get_logs(
        &self,
        start_date: Option<String>,
        end_date: Option<String>,
        category: Option<LogCategory>,
        keyword: Option<String>,
        page: usize,
        page_size: usize,
    ) -> Result<(Vec<SecurityLogEntry>, usize), String> {
        let mut all_logs = Vec::new();
        
        // 获取日期范围内的所有日志文件
        let log_files = self.get_log_files_in_range(start_date.as_deref(), end_date.as_deref())?;
        
        for log_file in log_files {
            let file = File::open(&log_file)
                .map_err(|e| format!("打开日志文件失败: {}", e))?;
            
            let reader = BufReader::new(file);
            
            for line in reader.lines() {
                let line = line.map_err(|e| format!("读取日志行失败: {}", e))?;
                if line.trim().is_empty() {
                    continue;
                }
                
                if let Ok(entry) = serde_json::from_str::<SecurityLogEntry>(&line) {
                    // 类别筛选
                    if let Some(ref cat) = category {
                        if entry.category != *cat {
                            continue;
                        }
                    }
                    
                    // 关键词筛选
                    if let Some(ref kw) = keyword {
                        let kw_lower = kw.to_lowercase();
                        let match_kw = entry.summary.to_lowercase().contains(&kw_lower)
                            || entry.function.to_lowercase().contains(&kw_lower)
                            || entry.file_path.as_ref().map(|p| p.to_lowercase().contains(&kw_lower)).unwrap_or(false)
                            || entry.threat_name.as_ref().map(|t| t.to_lowercase().contains(&kw_lower)).unwrap_or(false);
                        
                        if !match_kw {
                            continue;
                        }
                    }
                    
                    all_logs.push(entry);
                }
            }
        }
        
        // 按时间倒序排序
        all_logs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        let total = all_logs.len();
        
        // 分页
        let start = page * page_size;
        let end = (start + page_size).min(total);
        let paginated_logs = if start < total {
            all_logs[start..end].to_vec()
        } else {
            Vec::new()
        };
        
        Ok((paginated_logs, total))
    }
    
    /// 获取日期范围内的日志文件列表
    fn get_log_files_in_range(
        &self,
        start_date: Option<&str>,
        end_date: Option<&str>,
    ) -> Result<Vec<PathBuf>, String> {
        let mut files = Vec::new();
        
        let entries = fs::read_dir(&self.log_dir)
            .map_err(|e| format!("读取日志目录失败: {}", e))?;
        
        for entry in entries {
            let entry = entry.map_err(|e| format!("读取目录项失败: {}", e))?;
            let path = entry.path();
            
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                if filename.starts_with("security_log_") && filename.ends_with(".jsonl") {
                    // 提取日期
                    if let Some(date_str) = filename.strip_prefix("security_log_")
                        .and_then(|s| s.strip_suffix(".jsonl")) {
                        
                        // 日期范围筛选
                        let in_range = match (start_date, end_date) {
                            (Some(start), Some(end)) => date_str >= start && date_str <= end,
                            (Some(start), None) => date_str >= start,
                            (None, Some(end)) => date_str <= end,
                            (None, None) => true,
                        };
                        
                        if in_range {
                            files.push(path);
                        }
                    }
                }
            }
        }
        
        // 按日期排序
        files.sort();
        
        Ok(files)
    }
    
    /// 获取日志统计信息
    pub fn get_log_stats(&self, days: i64) -> Result<LogStats, String> {
        let end_date = Local::now();
        let start_date = end_date - chrono::Duration::days(days);
        
        let (logs, _) = self.get_logs(
            Some(start_date.format("%Y-%m-%d").to_string()),
            Some(end_date.format("%Y-%m-%d").to_string()),
            None,
            None,
            0,
            10000,
        )?;
        
        let mut category_counts: HashMap<String, u64> = HashMap::new();
        let mut action_counts: HashMap<String, u64> = HashMap::new();
        let mut threats_found: u64 = 0;
        let mut threats_blocked: u64 = 0;
        let mut threats_cleaned: u64 = 0;
        
        for log in &logs {
            *category_counts.entry(log.category.as_str().to_string()).or_insert(0) += 1;
            *action_counts.entry(log.action.as_str().to_string()).or_insert(0) += 1;
            
            if let Some(ref details) = log.details {
                if let Some(count) = details.threats_found {
                    threats_found += count;
                }
                if let Some(count) = details.threats_cleaned {
                    threats_cleaned += count;
                }
            }
            
            if log.action == LogAction::Blocked || log.action == LogAction::Quarantined {
                threats_blocked += 1;
            }
        }
        
        Ok(LogStats {
            total_logs: logs.len() as u64,
            category_counts,
            action_counts,
            threats_found,
            threats_blocked,
            threats_cleaned,
        })
    }
    
    /// 清除指定日期范围的日志
    pub fn clear_logs(
        &self,
        start_date: Option<String>,
        end_date: Option<String>,
    ) -> Result<u64, String> {
        let log_files = self.get_log_files_in_range(start_date.as_deref(), end_date.as_deref())?;
        let mut deleted_count = 0u64;
        
        for log_file in log_files {
            fs::remove_file(&log_file).map_err(|e| format!("删除日志文件失败: {}", e))?;
            deleted_count += 1;
        }
        
        Ok(deleted_count)
    }
    
    /// 导出日志到文件
    pub fn export_logs(
        &self,
        start_date: Option<String>,
        end_date: Option<String>,
        category: Option<LogCategory>,
        keyword: Option<String>,
        export_path: &str,
    ) -> Result<u64, String> {
        let (logs, total) = self.get_logs(start_date, end_date, category, keyword, 0, 100000)?;
        
        let json = serde_json::to_string_pretty(&logs)
            .map_err(|e| format!("序列化日志失败: {}", e))?;
        
        fs::write(export_path, json).map_err(|e| format!("写入导出文件失败: {}", e))?;
        
        Ok(total as u64)
    }
}

/// 日志统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogStats {
    pub total_logs: u64,
    pub category_counts: HashMap<String, u64>,
    pub action_counts: HashMap<String, u64>,
    pub threats_found: u64,
    pub threats_blocked: u64,
    pub threats_cleaned: u64,
}

/// 全局日志管理器实例
use std::sync::OnceLock;

static LOG_MANAGER: OnceLock<SecurityLogManager> = OnceLock::new();

pub fn init_log_manager() -> Result<(), String> {
    let manager = SecurityLogManager::new()?;
    LOG_MANAGER.set(manager).map_err(|_| "日志管理器已初始化".to_string())?;
    Ok(())
}

pub fn get_log_manager() -> Result<&'static SecurityLogManager, String> {
    LOG_MANAGER.get().ok_or_else(|| "日志管理器未初始化".to_string())
}

/// 便捷函数：添加日志
pub fn add_security_log(
    category: LogCategory,
    function: &str,
    summary: &str,
    file_path: Option<String>,
    threat_name: Option<String>,
    action: LogAction,
    result: LogResult,
    details: Option<LogDetails>,
) -> Result<(), String> {
    let manager = get_log_manager()?;
    
    let entry = SecurityLogEntry {
        id: format!("{}", chrono::Local::now().timestamp_millis()),
        timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        category,
        function: function.to_string(),
        summary: summary.to_string(),
        details,
        file_path,
        threat_name,
        action,
        result,
    };
    
    manager.add_log(entry)
}

/// 便捷函数：记录扫描日志
pub fn log_scan_completed(
    scanned_files: u64,
    threats_found: u64,
    threats_cleaned: u64,
) -> Result<(), String> {
    let summary = if threats_found > 0 {
        format!("扫描完成，发现 {} 个威胁，已清理 {} 个", threats_found, threats_cleaned)
    } else {
        "扫描完成，未发现威胁".to_string()
    };
    
    add_security_log(
        LogCategory::Scan,
        "全盘扫描",
        &summary,
        None,
        None,
        LogAction::Scanned,
        LogResult::Success,
        Some(LogDetails {
            scanned_files: Some(scanned_files),
            threats_found: Some(threats_found),
            threats_cleaned: Some(threats_cleaned),
            file_size: None,
            virus_family: None,
            additional_info: None,
        }),
    )
}

/// 便捷函数：记录威胁检测日志
pub fn log_threat_detected(
    file_path: &str,
    threat_name: &str,
    action: LogAction,
) -> Result<(), String> {
    let summary = format!("检测到威胁: {}", threat_name);
    
    add_security_log(
        LogCategory::Realtime,
        "实时监控",
        &summary,
        Some(file_path.to_string()),
        Some(threat_name.to_string()),
        action,
        LogResult::Success,
        None,
    )
}

/// 便捷函数：记录驱动防护日志
pub fn log_driver_protection(
    file_path: &str,
    protection_type: &str,
    blocked: bool,
) -> Result<(), String> {
    let (action, result) = if blocked {
        (LogAction::Blocked, LogResult::Success)
    } else {
        (LogAction::Detected, LogResult::Success)
    };
    
    let summary = if blocked {
        format!("已拦截{}: {}", protection_type, file_path)
    } else {
        format!("检测到{}: {}", protection_type, file_path)
    };
    
    add_security_log(
        LogCategory::Driver,
        "驱动防护",
        &summary,
        Some(file_path.to_string()),
        None,
        action,
        result,
        None,
    )
}

/// 便捷函数：记录隔离区操作日志
pub fn log_quarantine_action(
    file_path: &str,
    threat_name: &str,
    action: LogAction,
    success: bool,
) -> Result<(), String> {
    let result = if success { LogResult::Success } else { LogResult::Failed };
    
    let action_str = match action {
        LogAction::Quarantined => "隔离",
        LogAction::Deleted => "删除",
        LogAction::Cleaned => "恢复",
        _ => "操作",
    };
    
    let summary = format!("{}{}文件: {}", if success { "" } else { "尝试" }, action_str, file_path);
    
    add_security_log(
        LogCategory::Quarantine,
        "隔离区管理",
        &summary,
        Some(file_path.to_string()),
        Some(threat_name.to_string()),
        action,
        result,
        None,
    )
}
