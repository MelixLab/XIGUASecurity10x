//! 程序诊断日志模块
//!
//! 将程序运行的所有关键状态写入统一日志文件，便于诊断各种问题。
//!
//! ## 特性
//! - 分级日志：INFO / WARN / ERROR
//! - 按天轮转：`diagnostic_YYYY-MM-DD.log`
//! - 线程安全：Mutex 串行写入，多线程并发安全
//! - 自动清理：只保留最近 `LOG_RETENTION_DAYS` 天的日志文件
//! - 初始化时记录系统环境快照（OS 版本、CPU、内存），便于诊断环境相关问题
//!
//! ## 日志位置
//! `%LOCALAPPDATA%\XIGUASecurity\logs\diagnostic_YYYY-MM-DD.log`
//! 打包版与开发版使用同一位置，方便收集日志排查问题。

use chrono::Local;
use once_cell::sync::Lazy;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex as StdMutex;

/// 日志保留天数（自动清理更早的日志文件）
const LOG_RETENTION_DAYS: i64 = 14;

/// 日志级别
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

impl LogLevel {
    fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }
}

/// 获取日志目录：%LOCALAPPDATA%\XIGUASecurity\logs
pub fn log_dir() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(base).join("XIGUASecurity").join("logs")
}

/// 当前日期的日志文件路径
fn today_log_path() -> PathBuf {
    let date = Local::now().format("%Y-%m-%d").to_string();
    log_dir().join(format!("diagnostic_{}.log", date))
}

/// 确保日志目录存在
fn ensure_log_dir() -> bool {
    let dir = log_dir();
    if dir.exists() {
        return true;
    }
    fs::create_dir_all(&dir).is_ok()
}

/// 追加一行日志到文件（线程安全，串行写入）
fn append_line(level: LogLevel, msg: &str) {
    // 防止递归：日志写入失败时不再触发日志
    if let Ok(mut guard) = LOG_MUTEX.lock() {
        if !ensure_log_dir() {
            return;
        }
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        let tid = std::thread::current().id();
        let line = format!("[{}] [{}] [t{:?}] {}\n", timestamp, level.as_str(), tid, msg);
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(today_log_path())
        {
            let _ = file.write_all(line.as_bytes());
        }
        // 写入完成后释放锁，再尝试清理（避免持锁做 IO）
        drop(guard);
    }
    // 日志清理频率低，每次写入后顺带检查（快速失败，不做阻塞）
    maybe_cleanup_old_logs();
}

/// 互斥锁：串行化日志写入，避免多线程交错
static LOG_MUTEX: Lazy<StdMutex<()>> = Lazy::new(|| StdMutex::new(()));

/// 记录 INFO 级别日志
pub fn info(msg: &str) {
    append_line(LogLevel::Info, msg);
}

/// 记录 WARN 级别日志
pub fn warn(msg: &str) {
    append_line(LogLevel::Warn, msg);
}

/// 记录 ERROR 级别日志
pub fn error(msg: &str) {
    append_line(LogLevel::Error, msg);
}

/// 格式化 + 记录 INFO 级别日志
pub fn info_fmt(args: std::fmt::Arguments<'_>) {
    append_line(LogLevel::Info, &args.to_string());
}

/// 格式化 + 记录 WARN 级别日志
pub fn warn_fmt(args: std::fmt::Arguments<'_>) {
    append_line(LogLevel::Warn, &args.to_string());
}

/// 格式化 + 记录 ERROR 级别日志
pub fn error_fmt(args: std::fmt::Arguments<'_>) {
    append_line(LogLevel::Error, &args.to_string());
}

/// 宏：`diag_info!("tag", "message {}", val)`
#[macro_export]
macro_rules! diag_info {
    ($($arg:tt)*) => {
        $crate::diagnostic_log::info_fmt(format_args!($($arg)*))
    };
}

/// 宏：`diag_warn!("tag", "message {}", val)`
#[macro_export]
macro_rules! diag_warn {
    ($($arg:tt)*) => {
        $crate::diagnostic_log::warn_fmt(format_args!($($arg)*))
    };
}

/// 宏：`diag_error!("tag", "message {}", val)`
#[macro_export]
macro_rules! diag_error {
    ($($arg:tt)*) => {
        $crate::diagnostic_log::error_fmt(format_args!($($arg)*))
    };
}

/// 清理超过保留天数的旧日志文件
fn maybe_cleanup_old_logs() {
    // 每天最多清理一次，避免每次写入都扫目录
    static LAST_CLEANUP: Lazy<StdMutex<String>> = Lazy::new(|| StdMutex::new(String::new()));
    let today = Local::now().date_naive().format("%Y-%m-%d").to_string();
    {
        let mut last = LAST_CLEANUP.lock().unwrap();
        if *last == today {
            return;
        }
        *last = today;
    }

    let dir = log_dir();
    let Ok(entries) = fs::read_dir(&dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        // 只处理 diagnostic_YYYY-MM-DD.log 格式
        if !name.starts_with("diagnostic_") || !name.ends_with(".log") {
            continue;
        }
        let date_str = &name["diagnostic_".len()..name.len() - ".log".len()];
        if let Ok(dt) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
            let days_old = (Local::now().date_naive() - dt).num_days();
            if days_old > LOG_RETENTION_DAYS {
                let _ = fs::remove_file(&path);
            }
        }
    }
}

/// 初始化诊断日志：创建目录 + 记录系统环境快照
pub fn init() {
    let _ = log_dir();
    if !ensure_log_dir() {
        return;
    }

    info("==========================================");
    info("XIGUASecurity 诊断日志初始化");
    info("==========================================");

    // 系统环境快照
    info(&format!("程序路径: {}", std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "unknown".to_string())));
    info(&format!("当前工作目录: {}", std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_else(|_| "unknown".to_string())));
    info(&format!("OS: {}", std::env::consts::OS));
    info(&format!("架构: {}", std::env::consts::ARCH));

    // Windows 版本信息（后台线程获取，避免阻塞主线程）
    #[cfg(windows)]
    {
        std::thread::spawn(|| {
            use std::os::windows::process::CommandExt;
            use std::process::Command;
            if let Ok(output) = Command::new("powershell.exe")
                .args([
                    "-NoProfile",
                    "-Command",
                    "(Get-CimInstance Win32_OperatingSystem).Caption + ' Build ' + (Get-CimInstance Win32_OperatingSystem).BuildNumber + ' | ' + (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
                ])
                .creation_flags(0x08000000)
                .output()
            {
                let sysinfo = String::from_utf8_lossy(&output.stdout).trim().to_string();
                info(&format!("系统信息: {}", sysinfo));
            }
        });
    }

    // 日志文件位置
    info(&format!("日志目录: {}", log_dir().display()));

    // 命令行动态
    let args: Vec<String> = std::env::args().collect();
    info(&format!("命令行参数: {:?}", args));
}

/// 获取日志目录下的所有诊断日志文件（按名称排序，新→旧）
pub fn list_log_files() -> Vec<PathBuf> {
    let dir = log_dir();
    let Ok(entries) = fs::read_dir(&dir) else { return Vec::new() };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("diagnostic_") && n.ends_with(".log"))
                .unwrap_or(false)
        })
        .collect();
    files.sort_by_key(|p| std::cmp::Reverse(p.clone()));
    files
}

/// 读取日志内容（默认最近 5000 行，从文件末尾读取）
pub fn read_logs(limit: usize) -> String {
    let files = list_log_files();
    if files.is_empty() {
        return "暂无诊断日志".to_string();
    }
    let mut result = String::new();
    let mut remaining = limit.max(100);
    // 从最新文件开始读，按需向前补充
    for path in files {
        if remaining == 0 {
            break;
        }
        let Ok(content) = fs::read_to_string(&path) else { continue };
        let lines: Vec<&str> = content.lines().collect();
        let start = lines.len().saturating_sub(remaining.min(5000));
        let slice = lines[start..].join("\n");
        if !result.is_empty() {
            result.push('\n');
        }
        result.push_str(&slice);
        remaining = remaining.saturating_sub(lines.len());
        // 只在第一个（最新）文件截断
        break;
    }
    result
}

/// 清空全部诊断日志文件
pub fn clear_logs() -> usize {
    let files = list_log_files();
    let mut removed = 0;
    for path in files {
        if fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    info(&format!("已清空诊断日志，删除 {} 个文件", removed));
    removed
}
