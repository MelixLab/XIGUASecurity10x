//! 系统级功能：WinINet 系统代理设置/还原、父进程看门狗、关闭事件。
//!
//! 安全设计（核心约束：任何情况下都不能让用户"没法上网"）：
//! 1. 启用代理前先把原设置备份到 JSON 文件；
//! 2. 只有当前 ProxyServer 等于本程序标记（127.0.0.1:端口）时才允许还原，
//!    绝不覆盖用户后来手动配置的其他代理；
//! 3. 还原逻辑幂等：正常退出、父进程死亡、异常退出都会调用；
//! 4. 主程序侧也会做同样的还原，双保险。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use winreg::enums::{KEY_READ, KEY_WRITE};
use winreg::RegKey;

/// WinINet 代理设置注册表路径
const INTERNET_SETTINGS_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// 还原时用系统托盘广播 WinINet 设置变更，让浏览器立即生效
const INTERNET_OPTION_SETTINGS_CHANGED: i32 = 39;
const INTERNET_OPTION_REFRESH: i32 = 37;

/// 备份文件内容
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyBackup {
    pub proxy_enable: u32,
    pub proxy_server: String,
    pub proxy_override: String,
    pub auto_config_url: Option<String>,
}

fn internet_settings_key() -> Result<RegKey, String> {
    let hkcu = RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    hkcu.open_subkey_with_flags(INTERNET_SETTINGS_PATH, KEY_READ | KEY_WRITE)
        .map_err(|e| format!("打开注册表 Internet Settings 失败: {}", e))
}

/// 读取当前系统代理值（不存在时返回默认）
fn read_current_proxy() -> (u32, String) {
    let Ok(key) = internet_settings_key() else {
        return (0, String::new());
    };
    let enable = key.get_value::<u32, _>("ProxyEnable").unwrap_or(0);
    let server = key.get_value::<String, _>("ProxyServer").unwrap_or_default();
    (enable, server)
}

/// 读取原设置并写入备份文件（幂等：已存在则跳过，防止覆盖第一次的备份）
pub fn backup_proxy(backup_path: &Path) -> Result<ProxyBackup, String> {
    if backup_path.exists() {
        // 已备份过，直接读取返回（例如重复启动本进程）
        if let Ok(s) = std::fs::read_to_string(backup_path) {
            if let Ok(b) = serde_json::from_str::<ProxyBackup>(&s) {
                return Ok(b);
            }
        }
    }
    let key = internet_settings_key()?;
    let backup = ProxyBackup {
        proxy_enable: key.get_value::<u32, _>("ProxyEnable").unwrap_or(0),
        proxy_server: key.get_value::<String, _>("ProxyServer").unwrap_or_default(),
        proxy_override: key.get_value::<String, _>("ProxyOverride").unwrap_or_default(),
        auto_config_url: key.get_value::<String, _>("AutoConfigURL").ok(),
    };
    let json = serde_json::to_string_pretty(&backup)
        .map_err(|e| format!("序列化备份失败: {}", e))?;
    if let Some(parent) = backup_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(backup_path, json).map_err(|e| format!("写入备份文件失败: {}", e))?;
    println!("[NetProxy] WinINet proxy backup saved: {:?}", backup_path);
    Ok(backup)
}

/// 设置系统代理为本进程（先备份）
pub fn set_proxy(port: u16, backup_path: &Path) -> Result<(), String> {
    let _ = backup_proxy(backup_path)?;
    let key = internet_settings_key()?;
    let proxy_server = format!("127.0.0.1:{}", port);
    key.set_value("ProxyEnable", &1u32)
        .map_err(|e| format!("设置 ProxyEnable 失败: {}", e))?;
    key.set_value("ProxyServer", &proxy_server)
        .map_err(|e| format!("设置 ProxyServer 失败: {}", e))?;
    // <local> 表示本地地址直连，不走代理（避免本地服务被代理影响）
    key.set_value("ProxyOverride", &"<local>")
        .map_err(|e| format!("设置 ProxyOverride 失败: {}", e))?;
    broadcast_proxy_change();
    println!("[NetProxy] System proxy set to {}", proxy_server);
    Ok(())
}

/// 广播 WinINet 设置变更（通知浏览器/系统立即刷新代理配置）
fn broadcast_proxy_change() {
    unsafe {
        let wininet = windows::Win32::System::LibraryLoader::LoadLibraryW(windows::core::w!("wininet.dll"));
        if let Ok(h) = wininet {
            type FnInternetSetOptionW = unsafe extern "system" fn(*mut core::ffi::c_void, i32, *mut core::ffi::c_void, u32) -> i32;
            if let Some(proc) = windows::Win32::System::LibraryLoader::GetProcAddress(h, windows::core::s!("InternetSetOptionW")) {
                let f: FnInternetSetOptionW = std::mem::transmute(proc);
                let _ = f(std::ptr::null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null_mut(), 0);
                let _ = f(std::ptr::null_mut(), INTERNET_OPTION_REFRESH, std::ptr::null_mut(), 0);
            }
            let _ = windows::Win32::Foundation::FreeLibrary(h);
        }
    }
}

/// 还原系统代理。安全前提：只有当当前 ProxyServer 等于本程序的标记时才动手，
/// 否则说明用户已改过代理（或根本没启用过），直接不动，避免破坏用户配置。
///
/// 第三方代理软件（如 Steam++ 加速器）可能并发改写注册表，因此执行后校验一次，
/// 若仍残留本程序标记则重试（最多 3 次），保证"程序退出后不留任何代理残留"。
pub fn restore_proxy(port: u16, backup_path: &Path) -> bool {
    let marker = format!("127.0.0.1:{}", port);
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        let (_, current_server) = read_current_proxy();
        if current_server != marker {
            println!(
                "[NetProxy] Skip restore: current ProxyServer '{}' != marker '{}'",
                current_server, marker
            );
            return false;
        }
        apply_restore(port, backup_path);
        let (_, server_after) = read_current_proxy();
        if server_after != marker {
            println!("[NetProxy] Proxy restored (attempt {})", attempt + 1);
            return true;
        }
        println!("[NetProxy] Restore incomplete (marker still present), retrying...");
    }
    eprintln!("[NetProxy] Restore failed after 3 attempts (proxy may be disturbed by 3rd-party software)");
    false
}

/// 执行还原写入：有备份 → 恢复原值；无备份 → 关闭代理。幂等。
fn apply_restore(port: u16, backup_path: &Path) {
    let Ok(key) = internet_settings_key() else {
        return;
    };

    let backup = std::fs::read_to_string(backup_path)
        .ok()
        .and_then(|s| serde_json::from_str::<ProxyBackup>(&s).ok());

    match backup {
        Some(b) => {
            let _ = key.set_value("ProxyEnable", &b.proxy_enable);
            if b.proxy_server.is_empty() {
                let _ = key.delete_value("ProxyServer");
            } else {
                let _ = key.set_value("ProxyServer", &b.proxy_server);
            }
            if b.proxy_override.is_empty() {
                let _ = key.delete_value("ProxyOverride");
            } else {
                let _ = key.set_value("ProxyOverride", &b.proxy_override);
            }
            match b.auto_config_url {
                Some(url) if !url.is_empty() => {
                    let _ = key.set_value("AutoConfigURL", &url);
                }
                _ => {
                    let _ = key.delete_value("AutoConfigURL");
                }
            }
            println!("[NetProxy] Proxy restored from backup: enable={}", b.proxy_enable);
        }
        None => {
            let _ = key.set_value("ProxyEnable", &0u32);
            let _ = key.delete_value("ProxyServer");
            let _ = key.delete_value("ProxyOverride");
            println!("[NetProxy] No backup found, proxy disabled directly");
        }
    }

    broadcast_proxy_change();
    let _ = std::fs::remove_file(backup_path);
    let _ = port; // 标记一致性由调用方校验
}

// ==================== 父进程看门狗 ====================

/// 看门狗：每 1 秒检查父进程是否存活，若父进程已退出则触发关闭事件，
/// 由主流程统一走"还原代理再退出"的安全路径。
/// shutdown_event 以 isize 传入（HANDLE 不满足 Send，跨线程前先转成裸整数）。
pub fn spawn_parent_watchdog(parent_pid: u32, shutdown_event_raw: isize) {
    if parent_pid == 0 {
        return;
    }
    std::thread::spawn(move || {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::System::Threading::{GetExitCodeProcess, OpenProcess, SetEvent, PROCESS_QUERY_LIMITED_INFORMATION};
        const STILL_ACTIVE: u32 = 259;

        let shutdown_event = HANDLE(shutdown_event_raw as *mut core::ffi::c_void);
        unsafe {
            let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, parent_pid) else {
                println!("[NetProxy] Parent process {} not accessible, treating as dead", parent_pid);
                let _ = SetEvent(shutdown_event);
                return;
            };
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                let mut code: u32 = 0;
                if GetExitCodeProcess(handle, &mut code).is_err() || code != STILL_ACTIVE {
                    println!("[NetProxy] Parent process {} exited (code={}), triggering shutdown", parent_pid, code);
                    let _ = SetEvent(shutdown_event);
                    let _ = CloseHandle(handle);
                    return;
                }
            }
        }
    });
}

// ==================== 关闭事件 ====================

/// 创建/打开关闭事件（自动复位，全局命名，主程序用同名事件发信号）
pub fn create_shutdown_event() -> windows::Win32::Foundation::HANDLE {
    use windows::Win32::System::Threading::CreateEventW;
    // w! 宏生成静态宽字符串，生命周期为整个程序，PCWSTR 不会悬垂
    let name = windows::core::w!("XIGUA_NETPROXY_SHUTDOWN_EVENT");
    unsafe { CreateEventW(None, false, false, name).unwrap_or_default() }
}

/// 打开关闭事件并置位（主程序调用，通知代理进程优雅退出；本进程内自测/调试用）
#[allow(dead_code)]
pub fn signal_shutdown() -> bool {
    use windows::Win32::System::Threading::{OpenEventW, SetEvent, EVENT_MODIFY_STATE};
    let name = windows::core::w!("XIGUA_NETPROXY_SHUTDOWN_EVENT");
    unsafe {
        let Ok(handle) = OpenEventW(EVENT_MODIFY_STATE, false, name) else {
            return false;
        };
        let ok = SetEvent(handle).is_ok();
        let _ = windows::Win32::Foundation::CloseHandle(handle);
        ok
    }
}

/// 等待关闭事件，最多等待 timeout_ms 毫秒；返回 true 表示收到关闭信号
pub fn wait_shutdown_event(timeout_ms: u32) -> bool {
    use windows::Win32::Foundation::WAIT_EVENT;
    use windows::Win32::System::Threading::{OpenEventW, WaitForSingleObject, SYNCHRONIZATION_ACCESS_RIGHTS};
    let name = windows::core::w!("XIGUA_NETPROXY_SHUTDOWN_EVENT");
    unsafe {
        // SYNCHRONIZE = 0x00100000
        let Ok(handle) = OpenEventW(SYNCHRONIZATION_ACCESS_RIGHTS(0x0010_0000), false, name) else {
            return false;
        };
        let r = WaitForSingleObject(handle, timeout_ms);
        let _ = windows::Win32::Foundation::CloseHandle(handle);
        r == WAIT_EVENT(0) // WAIT_OBJECT_0 = 收到信号
    }
}

/// 数据目录（与主程序一致）：%LOCALAPPDATA%\XIGUASecurity
pub fn data_dir() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(base).join("XIGUASecurity")
}

/// 备份文件路径
pub fn default_backup_path() -> PathBuf {
    data_dir().join("netproxy_backup.json")
}

/// 事件记录文件路径
pub fn default_events_path() -> PathBuf {
    data_dir().join("network_events.jsonl")
}
