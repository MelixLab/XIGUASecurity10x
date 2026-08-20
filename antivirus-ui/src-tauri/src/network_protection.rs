//! 网络防护模块（主程序侧）
//!
//! 架构：主程序不直接实现代理，而是启动独立进程 netproxy.exe（纯用户态本地代理），
//! 由 netproxy 负责设置/还原 Windows 系统代理（WinINet）并拦截恶意域名。
//!
//! 安全设计（核心：任何情况下都不能让用户"没法上网"）：
//! 1. netproxy 内置父进程看门狗：主程序退出/崩溃 → 自动还原系统代理；
//! 2. 主程序监控 netproxy：其异常退出 → 立即还原系统代理并通知用户；
//! 3. 主程序启动时做崩溃恢复：检测到上次残留的本程序代理 → 还原；
//! 4. 还原仅当当前 ProxyServer 等于本程序标记时才执行，绝不覆盖用户后来
//!    手动配置的其他代理（如 VPN/Steam++）。
//!
//! 模块仅随 Windows 目标编译（依赖注册表/进程 API）。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};

/// 代理端口（与 netproxy 内置默认端口一致）
pub const NETPROXY_PORT: u16 = 37887;
const PROXY_MARKER: &str = "127.0.0.1:37887";
const SHUTDOWN_EVENT_NAME: &str = "XIGUA_NETPROXY_SHUTDOWN_EVENT";

/// 等待子进程就绪超时
const READY_TIMEOUT: Duration = Duration::from_secs(10);
/// 优雅关闭等待超时
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
/// 事件轮询间隔
const EVENT_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// 弹窗去重窗口（同域名）
const ALERT_DEDUP: Duration = Duration::from_secs(5);

/// 网络防护拦截事件（与 netproxy 写入 JSONL 的字段一致）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBlockEvent {
    pub ts: String,
    pub domain: String,
    pub category: String,
    pub process: String,
    pub pid: u32,
    pub kind: String,
    /// 动态评估命中原因（netproxy 动态拦截时携带）
    #[serde(default)]
    pub reason: Option<String>,
}

/// 网络防护状态
#[derive(Debug, Clone, Serialize)]
pub struct NetworkProtectionState {
    pub enabled: bool,
    pub port: u16,
    pub rules_count: usize,
    pub blocked_total: u64,
    pub child_alive: bool,
    pub last_error: Option<String>,
}

struct NetProtectionInner {
    enabled: bool,
    child: Option<Child>,
    /// 事件文件已消费的字节偏移
    event_offset: u64,
    /// 弹窗去重（域名 → 时间）
    alert_dedup: HashMap<String, Instant>,
    rules_count: usize,
    last_error: Option<String>,
}

impl NetProtectionInner {
    fn new() -> Self {
        Self {
            enabled: false,
            child: None,
            event_offset: 0,
            alert_dedup: HashMap::new(),
            rules_count: 0,
            last_error: None,
        }
    }
}

static NET_PROTECTION: OnceLock<StdMutex<NetProtectionInner>> = OnceLock::new();
fn net_protection() -> &'static StdMutex<NetProtectionInner> {
    NET_PROTECTION.get_or_init(|| StdMutex::new(NetProtectionInner::new()))
}

/// 是否正在主动停止（区分"我们停的"与"它自己崩的"）
static STOPPING: AtomicBool = AtomicBool::new(false);

// ==================== 路径与状态持久化 ====================

fn data_dir() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(base).join("XIGUASecurity")
}

fn state_file_path() -> PathBuf {
    data_dir().join("network_protection_state.json")
}

fn backup_file_path() -> PathBuf {
    data_dir().join("netproxy_backup.json")
}

fn events_file_path() -> PathBuf {
    data_dir().join("network_events.jsonl")
}

/// 持久化开关状态（下次启动时恢复）
fn write_state_file(enabled: bool) {
    let path = state_file_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, serde_json::json!({ "enabled": enabled }).to_string());
}

fn read_state_file() -> bool {
    std::fs::read_to_string(state_file_path())
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("enabled").and_then(|e| e.as_bool()))
        .unwrap_or(false)
}

// ==================== 查找 netproxy.exe ====================

fn find_netproxy_exe() -> Option<PathBuf> {
    let exe_path = std::env::current_exe().ok()?;
    let exe_dir = exe_path.parent()?;

    // 1. 打包/安装路径：主程序同级 Driver/ 目录（与 XIGUASecurityAgent.exe 同级）
    let driver_dir = exe_dir.join("Driver").join("netproxy.exe");
    if driver_dir.exists() {
        return Some(driver_dir);
    }

    // 2. 主程序同级目录
    let direct = exe_dir.join("netproxy.exe");
    if direct.exists() {
        return Some(direct);
    }

    // 3. 开发路径：向上遍历 6 层查找 netproxy/target/{release,debug}/netproxy.exe
    let mut current = exe_dir.to_path_buf();
    for _ in 0..6 {
        if let Some(parent) = current.parent() {
            for profile in ["release", "debug"] {
                let candidate = parent
                    .join("netproxy")
                    .join("target")
                    .join(profile)
                    .join("netproxy.exe");
                if candidate.exists() {
                    return Some(candidate);
                }
            }
            current = parent.to_path_buf();
        } else {
            break;
        }
    }
    None
}

// ==================== 系统代理还原（主程序侧，双保险） ====================

#[derive(Debug, Deserialize)]
struct ProxyBackup {
    proxy_enable: u32,
    proxy_server: String,
    proxy_override: String,
    auto_config_url: Option<String>,
}

fn internet_settings_key() -> Result<winreg::RegKey, String> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    let hkcu = winreg::RegKey::predef(HKEY_CURRENT_USER);
    hkcu.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        KEY_READ | KEY_WRITE,
    )
    .map_err(|e| format!("打开注册表 Internet Settings 失败: {}", e))
}

/// 广播 WinINet 设置变更（动态加载 wininet.dll，避免引入新特性）
fn broadcast_proxy_change() {
    unsafe {
        if let Ok(wininet) =
            windows::Win32::System::LibraryLoader::LoadLibraryW(windows::core::w!("wininet.dll"))
        {
            type FnInternetSetOptionW = unsafe extern "system" fn(
                *mut core::ffi::c_void,
                i32,
                *mut core::ffi::c_void,
                u32,
            ) -> i32;
            if let Some(proc) = windows::Win32::System::LibraryLoader::GetProcAddress(
                wininet,
                windows::core::s!("InternetSetOptionW"),
            ) {
                let f: FnInternetSetOptionW = std::mem::transmute(proc);
                let _ = f(std::ptr::null_mut(), 39, std::ptr::null_mut(), 0); // SETTINGS_CHANGED
                let _ = f(std::ptr::null_mut(), 37, std::ptr::null_mut(), 0); // REFRESH
            }
            let _ = windows::Win32::Foundation::FreeLibrary(wininet);
        }
    }
}

/// 还原系统代理（仅当当前 ProxyServer 等于本程序标记时）。
/// 第三方代理软件（如 Steam++）可能并发改写注册表，故执行后校验并重试（最多 3 次）。
pub fn restore_proxy_safe() -> bool {
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(300));
        }
        let Ok(key) = internet_settings_key() else {
            return false;
        };
        let current: String = key.get_value("ProxyServer").unwrap_or_default();
        if current != PROXY_MARKER {
            // 当前代理不是本程序设置的（用户/第三方改过）→ 不动，避免覆盖
            return false;
        }
        apply_restore_safe(&key);
        let after: String = key.get_value("ProxyServer").unwrap_or_default();
        if after != PROXY_MARKER {
            return true;
        }
        println!("[NetworkProtection] Restore incomplete, retrying (attempt {})", attempt + 1);
    }
    eprintln!("[NetworkProtection] Restore failed after 3 attempts");
    false
}

/// 执行还原写入（幂等）：有备份恢复原值，无备份关闭代理
fn apply_restore_safe(key: &winreg::RegKey) {
    let backup_path = backup_file_path();
    let backup = std::fs::read_to_string(&backup_path)
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
        }
        None => {
            let _ = key.set_value("ProxyEnable", &0u32);
            let _ = key.delete_value("ProxyServer");
            let _ = key.delete_value("ProxyOverride");
        }
    }
    broadcast_proxy_change();
    let _ = std::fs::remove_file(backup_path);
}

/// 向 netproxy 发送优雅关闭信号
fn signal_shutdown() -> bool {
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

// ==================== 启动 / 停止 ====================

/// 启动 netproxy 子进程并等待就绪（同步阻塞，调用方应放入 spawn_blocking）
fn start_sync(app: &AppHandle) -> Result<usize, String> {
    let mut state = net_protection().lock().unwrap();
    if state.enabled {
        return Ok(state.rules_count);
    }

    // 启动前先做一次崩溃恢复：若上次残留本程序代理，先还原（旧进程可能已死）
    if restore_proxy_safe() {
        crate::log_to_file("[NetworkProtection] Startup: cleaned up stale proxy from previous session");
    }

    let exe = find_netproxy_exe().ok_or_else(|| "netproxy.exe not found".to_string())?;
    let backup = backup_file_path();
    let events = events_file_path();

    let mut cmd = Command::new(&exe);
    cmd.arg("--port")
        .arg(NETPROXY_PORT.to_string())
        .arg("--parent-pid")
        .arg(std::process::id().to_string())
        .arg("--backup")
        .arg(backup.to_string_lossy().to_string())
        .arg("--events")
        .arg(events.to_string_lossy().to_string())
        // 网页域名白名单文件：与主程序 whitelist.rs 共用 %LOCALAPPDATA%\XIGUASecurity\user_whitelist.json，
        // netproxy 按文件修改时间热重载，主程序增删域名后无需重启。
        .arg("--whitelist")
        .arg(data_dir().join("user_whitelist.json").to_string_lossy().to_string());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.stdout(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("启动 netproxy 失败: {}", e))?;

    // 读取 stdout 直到 READY / ERROR（同时持续消费管道，避免子进程写爆/EPIPE）
    let stdout = child.stdout.take().ok_or_else(|| "无法读取 netproxy 输出".to_string())?;
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            if let Ok(l) = line {
                let is_marker = l.starts_with("READY") || l.starts_with("ERROR");
                let _ = tx.send(l);
                if is_marker {
                    // 继续读到 EOF：保持管道被消费
                }
            }
        }
    });

    // 等待就绪标记
    let deadline = Instant::now() + READY_TIMEOUT;
    let ready_result: Result<usize, String> = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break Err("netproxy 启动超时（10 秒内未就绪）".to_string());
        }
        match rx.recv_timeout(remaining) {
            Ok(line) if line.starts_with("READY") => {
                // READY port=37887 rules=37
                let rules = line
                    .split_whitespace()
                    .find_map(|t| t.strip_prefix("rules="))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                break Ok(rules);
            }
            Ok(line) if line.starts_with("ERROR") => {
                break Err(format!("netproxy 启动失败: {}", line));
            }
            Ok(_) => continue,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                break Err("netproxy 启动超时（10 秒内未就绪）".to_string());
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break Err("netproxy 进程提前退出".to_string());
            }
        }
    };

    let rules_count = match ready_result {
        Ok(r) => r,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            restore_proxy_safe();
            state.last_error = Some(e.clone());
            return Err(e);
        }
    };

    state.enabled = true;
    state.child = Some(child);
    state.rules_count = rules_count;
    state.last_error = None;
    // ★关键：从事件文件末尾开始消费。events 文件累积了历史上所有拦截记录，
    // 若偏移从 0 开始，启用瞬间会把全部历史事件重放为通知/日志（用户感知"一启动就狂弹通知"）。
    if let Ok(meta) = std::fs::metadata(&events) {
        state.event_offset = meta.len();
    }
    drop(state);

    write_state_file(true);
    crate::log_to_file(&format!(
        "[NetworkProtection] Enabled, netproxy running (port={}, rules={})",
        NETPROXY_PORT, rules_count
    ));

    // 启动监控线程
    start_monitor(app.clone());
    Ok(rules_count)
}

/// 停止网络防护（同步阻塞）
fn stop_sync() -> bool {
    STOPPING.store(true, Ordering::SeqCst);
    let mut state = net_protection().lock().unwrap();
    state.enabled = false;

    let mut exited = true;
    if let Some(mut child) = state.child.take() {
        exited = false;
        if signal_shutdown() {
            for _ in 0..(STOP_TIMEOUT.as_millis() / 100) {
                if let Ok(Some(_)) = child.try_wait() {
                    exited = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        if !exited {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    // 还原系统代理（主程序侧兜底；子进程自身也会还原，幂等）
    let restored = restore_proxy_safe();
    drop(state);

    write_state_file(false);
    STOPPING.store(false, Ordering::SeqCst);
    crate::log_to_file(&format!(
        "[NetworkProtection] Disabled (child_exited={}, proxy_restored={})",
        exited, restored
    ));
    restored
}

// ==================== 监控线程 ====================

fn start_monitor(app: AppHandle) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(EVENT_POLL_INTERVAL);

            // 1. 检查子进程是否意外退出
            let child_exited = {
                let mut state = net_protection().lock().unwrap();
                if !state.enabled {
                    continue;
                }
                match &mut state.child {
                    Some(child) => child.try_wait().ok().flatten().is_some(),
                    None => true,
                }
            };

            if child_exited && !STOPPING.load(Ordering::SeqCst) {
                crate::log_to_file("[NetworkProtection] netproxy exited unexpectedly, restoring system proxy");
                restore_proxy_safe();
                {
                    let mut state = net_protection().lock().unwrap();
                    state.enabled = false;
                    state.child = None;
                }
                write_state_file(false);
                // 通知用户
                let _ = crate::notification::show_security_notification_simple(
                    &app,
                    crate::notification::NotificationType::Info,
                    "XIGUASecurity 网络防护",
                    "网络防护进程异常退出，系统代理已自动还原，不影响上网。",
                );
                let _ = app.emit("network-protection-state", serde_json::json!({
                    "enabled": false, "reason": "child_exited"
                }));
                continue;
            }

            // 2. 消费事件文件
            let new_events = {
                let mut state = net_protection().lock().unwrap();
                if !state.enabled {
                    continue;
                }
                let (offset, events) = read_new_events(events_file_path(), state.event_offset);
                state.event_offset = offset;
                events
            };

            for ev in new_events {
                // 安全日志（时间线）
                let _ = crate::security_log::add_security_log(
                    crate::security_log::LogCategory::Realtime,
                    "网络防护",
                    &format!("已阻止访问恶意域名: {}", ev.domain),
                    None,
                    Some(ev.category.clone()),
                    crate::security_log::LogAction::Blocked,
                    crate::security_log::LogResult::Success,
                    Some(crate::security_log::LogDetails {
                        scanned_files: None,
                        threats_found: None,
                        threats_cleaned: None,
                        file_size: None,
                        virus_family: Some(ev.category.clone()),
                        additional_info: Some(format!("进程: {}", ev.process)),
                    }),
                );

                // 前端事件
                let payload = serde_json::json!({
                    "domain": ev.domain,
                    "category": ev.category,
                    "process": ev.process,
                    "pid": ev.pid,
                    "ts": ev.ts,
                    "reason": ev.reason,
                });
                let _ = app.emit("network-protection-event", payload);

                // 系统 Toast 通知（同域名 5 秒去重，与弹窗去重复用同一缓存）
                let show = {
                    let mut state = net_protection().lock().unwrap();
                    state.alert_dedup.retain(|_, t| t.elapsed() < ALERT_DEDUP * 2);
                    if let Some(last) = state.alert_dedup.get(&ev.domain) {
                        last.elapsed() >= ALERT_DEDUP
                    } else {
                        true
                    }
                };
                if show {
                    net_protection().lock().unwrap().alert_dedup.insert(ev.domain.clone(), Instant::now());
                    show_block_notification(&app, &ev);
                }
            }

            // 3. 事件文件被轮转（重建）时偏移自动重置（read_new_events 内处理）
        }
    });
}

/// 读取事件文件新增内容。返回 (新偏移, 新增事件)。
/// 若文件变小（轮转/清空），偏移重置为 0。
fn read_new_events(path: PathBuf, offset: u64) -> (u64, Vec<NetworkBlockEvent>) {
    let Ok(meta) = std::fs::metadata(&path) else {
        return (offset, Vec::new());
    };
    let len = meta.len();
    if len < offset {
        return (0, read_tail(&path, 0));
    }
    if len == offset {
        return (offset, Vec::new());
    }
    // 只读新增部分
    let events = read_tail(&path, offset);
    (len, events)
}

fn read_tail(path: &PathBuf, from: u64) -> Vec<NetworkBlockEvent> {
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    use std::io::{Read, Seek, SeekFrom};
    let mut file = file;
    let _ = file.seek(SeekFrom::Start(from));
    let mut content = String::new();
    let _ = file.read_to_string(&mut content);
    content
        .lines()
        .filter_map(|l| serde_json::from_str::<NetworkBlockEvent>(l).ok())
        .collect()
}

// ==================== 拦截通知（系统 Toast，替代独立弹窗） ====================

/// 风险类别中文名
fn category_label(category: &str) -> &'static str {
    match category {
        "phishing" => "钓鱼网站",
        "malware" => "恶意软件",
        "scam" => "诈骗网站",
        "adware" => "广告软件",
        "tracker" => "跟踪器",
        "squatting" => "仿冒域名",
        _ => "恶意站点",
    }
}

/// 全局通知节流（毫秒）：同一时刻连续命中多个域名时，最多每 2 秒弹一条，
/// 避免用户被通知轰炸
const NOTIFY_INTERVAL_MS: u64 = 2000;
static LAST_NOTIFY_TS: AtomicU64 = AtomicU64::new(0);

/// 通过程序现有通知系统（Windows 原生 Toast）提示拦截事件
fn show_block_notification(app: &AppHandle, ev: &NetworkBlockEvent) {
    // 全局节流
    let now = chrono::Local::now().timestamp_millis() as u64;
    let last = LAST_NOTIFY_TS.load(Ordering::Relaxed);
    if now.saturating_sub(last) < NOTIFY_INTERVAL_MS {
        return;
    }
    LAST_NOTIFY_TS.store(now, Ordering::Relaxed);

    let title = "XIGUASecurity 网络防护已阻止危险连接";
    let mut body = format!(
        "域名: {}\n类别: {}\n进程: {}",
        ev.domain,
        category_label(&ev.category),
        ev.process
    );
    if let Some(reason) = &ev.reason {
        body.push_str(&format!("\n原因: {}", reason));
    }

    let _ = crate::notification::show_security_notification(
        app,
        crate::notification::NotificationOptions::new(
            crate::notification::NotificationType::Block,
            title,
            body,
        ),
    );
    println!(
        "[NetworkProtection] Block notification sent: {} ({})",
        ev.domain, ev.category
    );
}

// ==================== 启动时恢复 ====================

/// 主程序启动时调用：
/// 1. 上次启用过网络防护 → 自动恢复启用；
/// 2. 未启用但有残留代理（上次崩溃遗留）→ 还原。
pub fn init_on_startup(app: AppHandle) {
    std::thread::spawn(move || {
        // 崩溃恢复：检查是否有本程序的残留代理（有备份文件但状态为关闭）
        if !read_state_file() && backup_file_path().exists() {
            if restore_proxy_safe() {
                crate::log_to_file("[NetworkProtection] Startup recovery: restored stale system proxy from crashed session");
            }
        }
        // 上次启用 → 自动恢复
        if read_state_file() {
            crate::log_to_file("[NetworkProtection] Auto-restoring network protection from last session");
            match start_sync(&app) {
                Ok(rules) => {
                    crate::log_to_file(&format!(
                        "[NetworkProtection] Auto-restored (rules={})",
                        rules
                    ));
                }
                Err(e) => {
                    crate::log_to_file(&format!("[NetworkProtection] Auto-restore failed: {}", e));
                }
            }
        }
    });
}

// ==================== Tauri 命令 ====================

/// 启用/禁用网络防护
#[tauri::command]
pub async fn set_network_protection_enabled(
    enabled: bool,
    app: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    println!("[NetworkProtection] set_network_protection_enabled({})", enabled);
    if enabled {
        let app_for_start = app.clone();
        let rules = tokio::task::spawn_blocking(move || start_sync(&app_for_start))
            .await
            .map_err(|e| format!("启用网络防护任务失败: {}", e))??;
        let state = get_state_value();
        crate::log_to_file(&format!(
            "[NetworkProtection] Enabled via UI (rules={})",
            rules
        ));
        let _ = app.emit("network-protection-state", serde_json::json!({
            "enabled": true
        }));
        Ok(state)
    } else {
        let restored = tokio::task::spawn_blocking(stop_sync)
            .await
            .unwrap_or(false);
        crate::log_to_file(&format!(
            "[NetworkProtection] Disabled via UI (proxy_restored={})",
            restored
        ));
        let _ = app.emit("network-protection-state", serde_json::json!({
            "enabled": false
        }));
        Ok(get_state_value())
    }
}

/// 获取网络防护状态
#[tauri::command]
pub fn get_network_protection_state() -> serde_json::Value {
    get_state_value()
}

fn get_state_value() -> serde_json::Value {
    let mut state = net_protection().lock().unwrap();
    let child_alive = match &mut state.child {
        Some(child) => child.try_wait().ok().flatten().is_none(),
        None => false,
    };
    // 统计拦截总数：事件文件行数
    let blocked_total = std::fs::read_to_string(events_file_path())
        .map(|s| s.lines().count() as u64)
        .unwrap_or(0);
    serde_json::json!({
        "enabled": state.enabled,
        "port": NETPROXY_PORT,
        "rules_count": state.rules_count,
        "blocked_total": blocked_total,
        "child_alive": child_alive,
        "last_error": state.last_error,
    })
}

/// 获取最近拦截事件
#[tauri::command]
pub fn get_network_protection_events(limit: usize) -> Vec<NetworkBlockEvent> {
    let limit = limit.clamp(1, 500);
    std::fs::read_to_string(events_file_path())
        .map(|s| {
            s.lines()
                .rev()
                .filter_map(|l| serde_json::from_str::<NetworkBlockEvent>(l).ok())
                .take(limit)
                .collect()
        })
        .unwrap_or_default()
}

/// 测试命令：模拟一次拦截（用于验证通知/日志链路）
#[tauri::command]
pub fn trigger_network_block_test(domain: String, app: tauri::AppHandle) -> Result<(), String> {
    println!("[NetworkProtection] Test block for domain: {}", domain);
    let ev = NetworkBlockEvent {
        ts: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        domain: domain.clone(),
        category: "phishing".to_string(),
        process: "test".to_string(),
        pid: 0,
        kind: "test".to_string(),
        reason: Some("测试触发".to_string()),
    };
    let _ = crate::security_log::add_security_log(
        crate::security_log::LogCategory::Realtime,
        "网络防护",
        &format!("[测试] 已阻止访问恶意域名: {}", domain),
        None,
        Some("phishing".to_string()),
        crate::security_log::LogAction::Blocked,
        crate::security_log::LogResult::Success,
        None,
    );
    let _ = app.emit(
        "network-protection-event",
        serde_json::json!({
            "domain": domain,
            "category": "phishing",
            "process": "test",
            "pid": 0,
            "ts": ev.ts,
        }),
    );
    show_block_notification(&app, &ev);
    Ok(())
}

/// 退出前停止（供 cleanup_before_exit 调用，需快速返回）
pub fn stop_on_exit() {
    // 放到独立线程，避免阻塞退出流程；子进程自身也有父进程看门狗兜底
    std::thread::spawn(|| {
        let _ = stop_sync();
    });
}
