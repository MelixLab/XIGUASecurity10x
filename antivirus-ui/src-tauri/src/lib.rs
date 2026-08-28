use tauri::{Manager, Window, State, Emitter, RunEvent, Listener, tray::{TrayIconBuilder, TrayIconEvent}, menu::{Menu, MenuItem, PredefinedMenuItem, MenuEvent}, window::{ProgressBarState, ProgressBarStatus}};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{SHOW_WINDOW_CMD, GetForegroundWindow};
use windows::Win32::Graphics::Gdi::{GetMonitorInfoW, MonitorFromWindow, MONITORINFO, MONITOR_DEFAULTTONEAREST, GetDC, ReleaseDC};
use windows::core::PCWSTR;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex as StdMutex;
use std::sync::OnceLock;
use std::sync::mpsc;
use std::collections::{HashMap, VecDeque};
use std::fs::File;

/// 文件防护弹窗互斥锁，防止并发创建同名窗口导致透明残留
static FILE_PROTECTION_ALERT_MUTEX: OnceLock<StdMutex<()>> = OnceLock::new();

/// 最近一次文件防护弹窗数据缓存：
/// 前端页面加载后通过 get_pending_file_protection_data 主动拉取，
/// 解决新建窗口时 emit 事件在 listener 注册前丢失导致的空内容问题。
static PENDING_FILE_PROTECTION_DATA: OnceLock<StdMutex<Option<serde_json::Value>>> = OnceLock::new();

fn pending_file_protection_data() -> &'static StdMutex<Option<serde_json::Value>> {
    PENDING_FILE_PROTECTION_DATA.get_or_init(|| StdMutex::new(None))
}

/// 沙箱进度窗口代际计数器：每次显示窗口时递增，
/// 关闭定时器唤醒后检查代际是否匹配，不匹配则跳过隐藏（防止旧定时器关闭新窗口）
static SANDBOX_PROGRESS_GEN: AtomicU64 = AtomicU64::new(0);

/// 沙箱分析互斥锁：防止并发 handle_sandbox_analysis 调用。
/// 
/// 历史 bug：set_analyzing(false) 在分析末尾（verdict/cleanup 之前）就被清除，
/// 导致用户可以在第一个分析还在收尾时触发第二个分析。两个 handle_sandbox_analysis
/// 并发运行时，第一个分析的 close_sandbox_progress_window 会捕获到第二个分析的
/// 新代际值，8 秒后误关第二个分析的进度窗口。
/// 
/// 修复：用 Mutex 序列化所有 handle_sandbox_analysis 调用，第二个调用等待第一个完成。
static SANDBOX_ANALYSIS_LOCK: OnceLock<StdMutex<()>> = OnceLock::new();

/// 并发进程拦截扫描计数器，限制最大同时扫描数防止线程泛滥
static CONCURRENT_SCANS: AtomicU32 = AtomicU32::new(0);

// 自动沙盒分析模块
mod sandbox_analysis;

// Sandboxie Monitor API（内核驱动级 trace 读取）
mod sbie_api;

// 程序诊断日志模块（所有状态写入统一日志文件）
mod diagnostic_log;

// 文件防护模块
mod file_protection;

// 网络防护模块（纯用户态系统代理拦截，独立 netproxy 子进程）
#[cfg(not(feature = "ms_store"))]
mod network_protection;

// R3 勒索软件防护模块
mod ransomware_protection;
mod popup_interceptor;

// 脚本防护模块（监控 PowerShell/CMD 危险命令）
mod script_protection;

// Windows 原生 Toast 通知模块
mod notification;

// 通用文件日志（打包版无终端输出，写文件便于排查）
// 统一入口：同时输出到控制台（开发版）和诊断日志文件（%LOCALAPPDATA%\XIGUASecurity\logs\）
fn log_to_file(msg: &str) {
    // 诊断日志（分级，按天轮转，自动清理旧日志）
    diagnostic_log::info(msg);
    // 控制台输出（开发版可见，打包版无终端）
    println!("{}", msg);
}

// 全局变量：是否允许关闭窗口（由程序内部控制）
static ALLOW_CLOSE: AtomicBool = AtomicBool::new(false);

// 全局变量：是否以后台/托盘模式启动（不显示主窗口）
static SILENT_STARTUP: AtomicBool = AtomicBool::new(false);

// 全局变量：当前显示语言（用于独立弹窗本地化）
static CURRENT_LANGUAGE: StdMutex<String> = StdMutex::new(String::new());

lazy_static::lazy_static! {
    // 全局锁定的文件句柄存储（保持文件被占用）
    static ref LOCKED_FILES: Arc<StdMutex<Vec<File>>> = Arc::new(StdMutex::new(Vec::new()));
}

// ==================== 拦截请求队列（多请求串行化） ====================

#[derive(Clone)]
struct InterceptItem {
    intercept_type: String,
    process_name: String,
    file_path: String,
    resp_pipe: String,
    threat_info: String,
    /// 用户超时未决策时的默认动作：true=拦截（AVIC 云端已知威胁默认不放行），
    /// false=放行（普通扫描威胁维持原默认）
    default_block: bool,
}

lazy_static::lazy_static! {
    static ref INTERCEPT_QUEUE: StdMutex<VecDeque<InterceptItem>> = StdMutex::new(VecDeque::new());
    /// 响应管道 → (进程名, 威胁名)，用于 send_intercept_decision 发射事件
    static ref INTERCEPT_INFO_MAP: StdMutex<std::collections::HashMap<String, (String, String)>> = StdMutex::new(std::collections::HashMap::new());
}

/// 是否有拦截窗口正在显示
static INTERCEPT_BUSY: AtomicBool = AtomicBool::new(false);

/// 拦截窗口显示流程互斥锁（防止多个通知处理线程并发调用 show_next_intercept，
/// 导致 check-then-set 竞态、窗口操作竞争）
static INTERCEPT_SHOW_LOCK: OnceLock<StdMutex<()>> = OnceLock::new();

/// 决策等待者表（同步模型核心）：
/// 弹窗线程（=消息循环线程）显示窗口后注册一个 channel，然后阻塞等待；
/// 前端按钮点击 → send_av_driver_decision 命令（Tauri 线程池）通过此表
/// 找到等待者并发送决策 → 弹窗线程唤醒后直接写决策回管道、关闭窗口。
/// key = resp_pipe (= notification_id 字符串)
static AV_DECISION_WAITERS: OnceLock<StdMutex<HashMap<String, mpsc::Sender<av_driver_client::AvDecision>>>> = OnceLock::new();

/// 拦截窗口 busy 的开始时间戳（用于 watchdog 超时重置）
static INTERCEPT_BUSY_SINCE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// 标记预创建的拦截窗口已被 show_next_intercept 认领，预创建线程不应再 hide() 它
static INTERCEPT_WINDOW_CLAIMED: AtomicBool = AtomicBool::new(false);

/// 安全桌面确认等待者表：
/// 关闭防护/退出等高危操作先显示安全确认窗口，等待用户按住确认后才继续执行。
/// key = session_id（每次确认生成唯一 ID）
static SECURE_CONFIRM_WAITERS: OnceLock<StdMutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>>> = OnceLock::new();

/// 获取安全确认等待者表（懒初始化）
fn secure_confirm_waiters() -> &'static StdMutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>> {
    SECURE_CONFIRM_WAITERS.get_or_init(|| StdMutex::new(HashMap::new()))
}

/// 用户态"始终允许/始终拦截"规则表（仅内存，应用重启后清空）。
/// 不写入驱动（驱动 DenyList 常驻内存无法卸载，会导致跨重启持续生效），
/// 由 R3 在每次拦截通知到达时先行检查。
/// 元组: (通知类型, 路径, 决策 "allow" | "block")
static INTERCEPT_ALWAYS_RULES: OnceLock<StdMutex<Vec<(String, String, String)>>> = OnceLock::new();

/// 添加一条用户态 always 规则（同类型同路径覆盖旧规则）
fn add_always_rule(rule_type: &str, path: &str, decision: &str) {
    let rules = INTERCEPT_ALWAYS_RULES.get_or_init(|| StdMutex::new(Vec::new()));
    let mut guard = rules.lock().unwrap();
    guard.retain(|(t, p, _)| !(t == rule_type && p == path));
    guard.push((rule_type.to_string(), path.to_string(), decision.to_string()));
    println!("[AlwaysRule] Added: type={} path={} decision={} (total={})", rule_type, path, decision, guard.len());
}

/// 查询用户态 always 规则：命中返回 Some(决策)，未命中返回 None。
/// 路径匹配：精确匹配或前缀包含匹配（路径统一转小写）。
fn check_always_rule(rule_type: &str, path: &str) -> Option<String> {
    let rules = INTERCEPT_ALWAYS_RULES.get_or_init(|| StdMutex::new(Vec::new()));
    let guard = rules.lock().unwrap();
    if guard.is_empty() {
        return None;
    }
    let path_lower = path.to_lowercase();
    for (t, p, d) in guard.iter() {
        if t != rule_type {
            continue;
        }
        if p.eq_ignore_ascii_case(path) || path_lower.contains(&p.to_lowercase()) {
            return Some(d.clone());
        }
    }
    None
}

/// 通知模式开关：开启后驱动/基础防护拦截不再弹窗，仅通过系统 Toast 通知提示
static NOTIFICATION_MODE_ENABLED: AtomicBool = AtomicBool::new(false);

// 允许关闭窗口（内部调用）
fn allow_window_close() {
    ALLOW_CLOSE.store(true, Ordering::SeqCst);
}

use std::sync::{Arc, Mutex};
use std::process::Command;
use std::os::windows::process::CommandExt;

// 检查拦截工具进程是否存在
#[cfg(windows)]
#[cfg(not(feature = "ms_store"))]
fn is_interceptor_running() -> bool {
    // 优先检查 av_driver_client 是否已连接
    if av_driver_client::is_av_driver_connected() {
        return true;
    }

    // 回退：检查 XIGUASecurityAgent.exe 进程是否存在
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS, PROCESSENTRY32W};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    
    unsafe {
        // 创建进程快照
        let snapshot: HANDLE = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return false,
        };
        
        // 初始化 PROCESSENTRY32W 结构
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        
        // 获取第一个进程
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                // 将 szExeFile (u16数组) 转换为字符串
                let exe_file: Vec<u16> = entry.szExeFile.iter()
                    .take_while(|&&c| c != 0)
                    .copied()
                    .collect();
                
                if let Ok(name) = String::from_utf16(&exe_file) {
                    if name.eq_ignore_ascii_case("XIGUASecurityAgent.exe") {
                        let _: windows::core::Result<()> = CloseHandle(snapshot);
                        return true;
                    }
                }
                
                // 获取下一个进程
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        
        let _: windows::core::Result<()> = CloseHandle(snapshot);
        false
    }
}

#[cfg(not(windows))]
#[cfg(not(feature = "ms_store"))]
fn is_interceptor_running() -> bool {
    false
}
mod ember_features;
mod tree;
mod scanner;
use scanner::{scan_file_direct, scan_batch_direct, scan_batch_direct_with_hashes, get_scan_files_direct, CleaningResult};

mod updater;
use updater::{check_update, download_and_install_with_progress, get_current_version};



mod archive_scanner;
use archive_scanner::scan_archive_command;

mod context_menu;
use context_menu::{register_context_menu_command, unregister_context_menu_command, is_context_menu_registered_command};

mod signature_verifier;

mod whitelist;
use whitelist::reload_whitelist;

mod blacklist;
use blacklist::{get_blacklist_manager, reload_blacklist, BlacklistData};

mod rules_updater;
mod rules_db;
use rules_updater::{check_rules_update, download_and_update_rules_with_progress, get_rules_status, should_auto_check, update_last_check_time};

mod announcement;
use announcement::{fetch_latest_announcement, Announcement};

mod quarantine;
use quarantine::{QuarantineManager, quarantine_threat_file, restore_quarantined_file, delete_quarantined_file, get_quarantined_files, get_quarantine_stats};

// 活动内存威胁处置模块（清除被占用文件：开机时清除 / 不重启而清除）
mod active_threat;

// AVIC 云端威胁情报上报模块
mod avic_client;

mod security_log;
use security_log::{LogCategory, LogStats, init_log_manager, get_log_manager};

mod log_uploader;
use log_uploader::{init_log_uploader, get_log_uploader};

mod wsc_registrar;
use wsc_registrar::{register_wd_replacement, unregister_wd_replacement};

// MS Store 构建标志
#[cfg(feature = "ms_store")]
const IS_MS_STORE: bool = true;
#[cfg(not(feature = "ms_store"))]
const IS_MS_STORE: bool = false;

mod etw_monitor;
use etw_monitor::get_etw_monitor;

mod deep_analysis;
// use deep_analysis::DeepAnalysisResult; // 通过模块路径直接调用

mod process_watcher;
use process_watcher::ProcessWatcher;

// EDR 核心模块 - 基于MITRE ATT&CK的行为检测
mod amsi_protection;
mod behavior_engine;
mod defense_evasion;
mod credential_access;
mod process_injection;

mod system_repair;

// 新 KMDF 驱动管道客户端模块
#[cfg(not(feature = "ms_store"))]
mod av_driver_client;
#[cfg(not(feature = "ms_store"))]
mod avmodel_client;
// Melix 端点防护（HIPS）桥接 — 经 AVGuard（管理员）中转，主程序非管理员无法直连 Melix.Control
#[cfg(not(feature = "ms_store"))]
mod melix_ui_client;
// 内存活动威胁扫描模块（快速扫描开局阶段）
#[cfg(not(feature = "ms_store"))]
mod memory_scan;
use system_repair::{scan_system_issues, fix_system_issues};

/// 从 EDR 报告中提取 IOA 标记，并映射为标准化病毒家族名称
fn infer_edr_family(report: &EdrReportData) -> String {
    // 1. 优先使用报告中明确标注的 IOA 家族
    if let Some((name, score)) = report.ioa_families.first() {
        if *score > 0 {
            let family = map_ioa_family_name(name);
            println!("[EDR Family] IOA matched: {} (score={}) -> {}", name, score, family);
            return family;
        }
    }

    // 2. 从完整时间线文本中提取高置信特征
    let timeline_text = report
        .timeline
        .iter()
        .map(|e| e.detail.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let full_text = format!(
        "{} {} {} {}",
        report.process_name.to_lowercase(),
        report.process_path.to_lowercase(),
        report.command_line.to_lowercase(),
        timeline_text.to_lowercase()
    );

    // 3. 已知样本/工具的特征签名
    if full_text.contains("silverfox")
        || full_text.contains("whiteloader.exe")
        || (full_text.contains("libcef.dll") && full_text.contains("temp\\sftest"))
    {
        return "Trojan.Win32.SilverFox".to_string();
    }

    if full_text.contains("steamcommunity") && full_text.contains("drivers\\etc\\hosts") {
        return "Tool.HackTool.SteamCommunity302".to_string();
    }

    if full_text.contains("xiguasecurity")
        && (full_text.contains("taskkill.exe") || full_text.contains("sc stop") || full_text.contains("reg delete"))
    {
        return "Trojan.PSW.KillAV".to_string();
    }

    // 4. 行为模式推断
    let has_ppid_spoof = timeline_text.contains("PPIDSpoofing") || timeline_text.contains("父进程欺骗");
    let has_drop = timeline_text.contains("SuspiciousFileDrop") || timeline_text.contains("可疑文件落盘");
    let has_drop_combo = timeline_text.contains("SuspiciousFileDropCombo") || timeline_text.contains("可疑文件落盘组合");
    let has_sideload = timeline_text.contains("Sideload") || timeline_text.contains("可疑映像加载");
    let has_hosts_tamper = timeline_text.contains("CriticalFileTamper") || timeline_text.contains("drivers\\etc\\hosts");
    let has_inject = timeline_text.contains("远程线程") || timeline_text.contains("RemoteThread") || timeline_text.contains("注入");
    let has_rwx = timeline_text.contains("Memory RWX") || timeline_text.contains("RWX");
    let has_cmd = timeline_text.contains("SuspiciousCmd") || timeline_text.contains("可疑命令");
    let has_reg = timeline_text.contains("RegWrite") || timeline_text.contains("注册表写入");

    if has_drop_combo && has_ppid_spoof {
        return "Trojan.Win32.SilverFoxLoader".to_string();
    }
    if has_drop && has_sideload {
        return "Trojan.Win32.DllSideloader".to_string();
    }
    if has_ppid_spoof && has_drop {
        return "Trojan.Win32.ProcessHollowing".to_string();
    }
    if has_hosts_tamper {
        return "Tool.HackTool.HostsModifier".to_string();
    }
    if has_inject && has_rwx {
        return "Trojan.Win32.ReflectiveInjector".to_string();
    }
    if has_inject {
        return "Trojan.Win32.ProcessInjector".to_string();
    }
    if has_drop {
        return "Trojan.Win32.Dropper".to_string();
    }
    if has_sideload {
        return "Trojan.Win32.Sideloader".to_string();
    }
    if has_cmd && (full_text.contains("powershell.exe") || full_text.contains("cmd.exe")) {
        return "Trojan.BAT.Agent".to_string();
    }
    if has_reg {
        return "Trojan.Win32.RegistryModifier".to_string();
    }

    // 5. 回退：使用基于进程名的粗略分类
    if report.process_name.to_lowercase().contains("powershell") || report.command_line.to_lowercase().contains("powershell") {
        return "Trojan.PSW.PowerShell".to_string();
    }
    if report.process_name.to_lowercase().contains("python") || report.command_line.to_lowercase().contains("python") {
        return "Trojan.Python.Generic".to_string();
    }
    if report.process_name.to_lowercase().contains("cmd") {
        return "Trojan.BAT.Agent".to_string();
    }

    println!("[EDR Family] Fallback to generic for process: {}", report.process_name);
    "Trojan.Win32.SuspiciousBehavior".to_string()
}

/// IOA 家族名称映射表：把驱动侧给出的原始标识转换为标准命名
fn map_ioa_family_name(raw: &str) -> String {
    match raw.to_lowercase().as_str() {
        "silverfox" => "Trojan.Win32.SilverFox".to_string(),
        "amadey" => "Trojan.Win32.Amadey".to_string(),
        "redline" => "Trojan.Win32.RedLineStealer".to_string(),
        "agenttesla" => "Trojan.Win32.AgentTesla".to_string(),
        "formbook" => "Trojan.Win32.Formbook".to_string(),
        "lokibot" => "Trojan.Win32.LokiBot".to_string(),
        "remcos" => "Trojan.Win32.Remcos".to_string(),
        "nanocore" => "Trojan.Win32.NanoCore".to_string(),
        "asyncrat" => "Trojan.Win32.AsyncRAT".to_string(),
        "quasarrat" => "Trojan.Win32.QuasarRAT".to_string(),
        "warzone" => "Trojan.Win32.WarzoneRAT".to_string(),
        "cobaltstrike" => "Trojan.Win32.CobaltStrike".to_string(),
        "meterpreter" => "Trojan.Win32.Meterpreter".to_string(),
        "sliver" => "Trojan.Win32.Sliver".to_string(),
        "bruteratel" => "Trojan.Win32.BruteRatel".to_string(),
        "phantomcore" => "Trojan.Win32.PhantomCore".to_string(),
        "mimikatz" => "HackTool.Win32.Mimikatz".to_string(),
        "rubeus" => "HackTool.Win32.Rubeus".to_string(),
        "sharpview" => "HackTool.Win32.SharpView".to_string(),
        "seatbelt" => "HackTool.Win32.Seatbelt".to_string(),
        "procdump" => "HackTool.Win32.ProcDump".to_string(),
        _ => format!("Trojan.Win32.{}", capitalize_family(raw)),
    }
}

fn capitalize_family(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => s.to_string(),
    }
}

/// 把 \Device\HarddiskVolumeX\... 这类 NT 设备路径转换为 C:\... 等 DOS 盘符路径
#[cfg(windows)]
fn convert_device_path_to_dos_path(path: &str) -> String {
    if !path.starts_with("\\Device\\") {
        return path.to_string();
    }

    unsafe {
        use windows::Win32::Storage::FileSystem::{GetLogicalDriveStringsW, QueryDosDeviceW};
        use windows::core::PCWSTR;

        let mut buf = [0u16; 512];
        let len = GetLogicalDriveStringsW(Some(&mut buf));
        if len == 0 {
            return path.to_string();
        }

        let drive_strings = String::from_utf16_lossy(&buf[..len as usize]);
        let drives: Vec<&str> = drive_strings.split('\0').filter(|s| !s.is_empty()).collect();

        for drive in drives {
            // drive 形如 "C:\"
            let letter = drive.trim_end_matches('\\');
            let letter_wide: Vec<u16> = letter.encode_utf16().chain(Some(0)).collect();
            let mut device_buf = [0u16; 260];
            let device_len = QueryDosDeviceW(PCWSTR(letter_wide.as_ptr()), Some(&mut device_buf));
            if device_len == 0 {
                continue;
            }
            let device = String::from_utf16_lossy(&device_buf[..device_len as usize]);
            let device = device.trim_end_matches('\0');
            let prefix = format!("{}\\", device);
            if path.starts_with(&prefix) {
                let rest = &path[prefix.len()..];
                return format!("{}\\{}", letter, rest);
            }
        }
    }

    path.to_string()
}

#[cfg(not(windows))]
fn convert_device_path_to_dos_path(path: &str) -> String {
    path.to_string()
}

// 驱动防护状态管理
#[cfg(not(feature = "ms_store"))]
pub struct DriverProtectionState {
    pub enabled: Arc<Mutex<bool>>,
    pub intercepted_logs: Arc<Mutex<Vec<String>>>,
    pub process_check_count: Arc<Mutex<u64>>,
}

#[cfg(not(feature = "ms_store"))]
impl DriverProtectionState {
    pub fn new() -> Self {
        Self {
            enabled: Arc::new(Mutex::new(false)),
            intercepted_logs: Arc::new(Mutex::new(Vec::new())),
            process_check_count: Arc::new(Mutex::new(0)),
        }
    }
}

// 扫描设置状态管理
pub struct ScanSettingsState {
    pub infector_detection_enabled: Arc<Mutex<bool>>,
    pub virus_family_analysis_enabled: Arc<Mutex<bool>>,
}

impl ScanSettingsState {
    pub fn new() -> Self {
        Self {
            infector_detection_enabled: Arc::new(Mutex::new(true)),
            virus_family_analysis_enabled: Arc::new(Mutex::new(true)),
        }
    }
}

/// 向响应管道写入决策结果
fn write_to_resp_pipe(pipe_name: &str, decision: &str) {
    use windows::Win32::Storage::FileSystem::CreateFileA;
    use windows::Win32::Storage::FileSystem::{FILE_FLAG_OVERLAPPED, OPEN_EXISTING};
    use windows::Win32::System::Pipes::WaitNamedPipeA;
    
    let pipe_name_c = std::ffi::CString::new(pipe_name).unwrap();
    
    // 等待管道可用
    unsafe { WaitNamedPipeA(windows::core::PCSTR(pipe_name_c.as_ptr() as *const u8), 10000); }
    
    // 连接到响应管道
    let handle = unsafe {
        CreateFileA(
            windows::core::PCSTR(pipe_name_c.as_ptr() as *const u8),
            windows::Win32::Storage::FileSystem::FILE_GENERIC_WRITE.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            None,
        )
    };
    
    match handle {
        Ok(h) => {
            let decision_c = std::ffi::CString::new(decision).unwrap();
            let data = decision_c.as_bytes();
            let mut bytes_written: u32 = 0;
            let result = unsafe {
                windows::Win32::Storage::FileSystem::WriteFile(
                    h,
                    Some(data),
                    Some(&mut bytes_written),
                    None,
                )
            };
            if result.is_ok() {
                println!("[RespPipe] Wrote '{}' to {}", decision, pipe_name);
            } else {
                eprintln!("[RespPipe] Failed to write to {}", pipe_name);
            }
            unsafe { let _ = windows::Win32::Foundation::CloseHandle(h); }
        }
        Err(e) => {
            eprintln!("[RespPipe] Failed to connect to {}: {:?}", pipe_name, e);
        }
    }
}

// ==================== 进程拦截扫描与窗口展示（参考 SimpleLauncher.c） ====================

/// 在预创建的拦截窗口中显示信息（或排队等待）
#[cfg(not(feature = "ms_store"))]
fn show_intercept_window_internal(
    app_handle: &tauri::AppHandle,
    intercept_type: &str,
    process_name: &str,
    file_path: &str,
    resp_pipe: &str,
    threat_info: &str,
    default_block: bool,
) {
    // 先入队
    {
        let mut queue = INTERCEPT_QUEUE.lock().unwrap();
        queue.push_back(InterceptItem {
            intercept_type: intercept_type.to_string(),
            process_name: process_name.to_string(),
            file_path: file_path.to_string(),
            resp_pipe: resp_pipe.to_string(),
            threat_info: threat_info.to_string(),
            default_block,
        });
    }
    // ★历史 bug：旧代码直接同步调用 show_next_intercept(app_handle)，
    // 但 show_next_intercept 内部有 recv_timeout(30s) 和 INTERCEPT_SHOW_LOCK 锁竞争。
    // 驱动通知线程（ThreadId(77) 等）被同步阻塞后，新驱动通知无法处理，
    // 后续所有拦截请求全被跳过，程序卡死（防护关不掉、扫描点不了）。
    // ★修复：spawn 独立线程异步执行，不阻塞驱动通知线程。
    let app_cloned = app_handle.clone();
    std::thread::spawn(move || {
        show_next_intercept(&app_cloned);
    });
}

/// 使用 Win32 API 强制将窗口显示到前台，绕过 Windows 前台锁限制。
///
/// 当从后台线程调用 Tauri 的 `show()` + `set_focus()` 时，Windows 前台锁
/// 会静默阻止窗口出现在屏幕上（`show()` 返回 Ok 但用户看不到窗口）。
/// 此函数通过 `AttachThreadInput` 将当前线程的输入队列附加到前台线程，
/// 使 `SetForegroundWindow` 调用获得前台权限，从而强制窗口可见。
///
/// 使用动态加载（GetProcAddress）而非直接链接，避免 Tauri 依赖的 windows crate
/// 与本项目 Cargo.toml 中的 windows crate 版本冲突导致的类型不匹配。
#[cfg(windows)]
fn force_window_visible(win: &tauri::WebviewWindow) {    // 提取原始 HWND 指针，绕过 windows crate 版本冲突
    let hwnd_raw = match win.hwnd() {
        Ok(h) => h.0 as *mut std::ffi::c_void,
        Err(e) => {
            eprintln!("[ForceVisible] Failed to get HWND: {}", e);
            return;
        }
    };

    unsafe {
        // 加载 user32.dll
        let user32 = match windows::Win32::System::LibraryLoader::LoadLibraryW(windows::core::w!("user32.dll")) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[ForceVisible] Failed to load user32.dll: {}", e);
                return;
            }
        };

        // 辅助：获取函数指针
        type FnGetForegroundWindow = unsafe extern "system" fn() -> *mut std::ffi::c_void;
        type FnGetWindowThreadProcessId = unsafe extern "system" fn(*mut std::ffi::c_void, *mut u32) -> u32;
        type FnGetCurrentThreadId = unsafe extern "system" fn() -> u32;
        type FnAttachThreadInput = unsafe extern "system" fn(u32, u32, i32) -> i32;
        type FnShowWindow = unsafe extern "system" fn(*mut std::ffi::c_void, i32) -> i32;
        type FnSetWindowPos = unsafe extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, i32, i32, i32, i32, u32) -> i32;
        type FnGetDpiForWindow = unsafe extern "system" fn(*mut std::ffi::c_void) -> u32;
        type FnSetForegroundWindow = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;

        let get_foreground: FnGetForegroundWindow = {
            let proc = windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("GetForegroundWindow"));
            match proc {
                Some(p) => std::mem::transmute(p),
                None => { eprintln!("[ForceVisible] GetForegroundWindow not found"); return; }
            }
        };
        let get_thread_pid: FnGetWindowThreadProcessId = {
            let proc = windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("GetWindowThreadProcessId"));
            match proc {
                Some(p) => std::mem::transmute(p),
                None => { eprintln!("[ForceVisible] GetWindowThreadProcessId not found"); return; }
            }
        };
        let get_current_tid: FnGetCurrentThreadId = {
            let proc = windows::Win32::System::LibraryLoader::GetProcAddress(windows::Win32::System::LibraryLoader::LoadLibraryW(windows::core::w!("kernel32.dll")).unwrap(), windows::core::s!("GetCurrentThreadId"));
            match proc {
                Some(p) => std::mem::transmute(p),
                None => { eprintln!("[ForceVisible] GetCurrentThreadId not found"); return; }
            }
        };
        let attach_thread: FnAttachThreadInput = {
            let proc = windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("AttachThreadInput"));
            match proc {
                Some(p) => std::mem::transmute(p),
                None => { eprintln!("[ForceVisible] AttachThreadInput not found"); return; }
            }
        };
        let show_win: FnShowWindow = {
            let proc = windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("ShowWindow"));
            match proc {
                Some(p) => std::mem::transmute(p),
                None => { eprintln!("[ForceVisible] ShowWindow not found"); return; }
            }
        };
        let bring_to_top: FnSetWindowPos = {
            let proc = windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("SetWindowPos"));
            match proc {
                Some(p) => std::mem::transmute(p),
                None => { eprintln!("[ForceVisible] SetWindowPos not found"); return; }
            }
        };
        let get_dpi_for_window: FnGetDpiForWindow = {
            let proc = windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("GetDpiForWindow"));
            match proc {
                Some(p) => std::mem::transmute(p),
                None => { eprintln!("[ForceVisible] GetDpiForWindow not found"); return; }
            }
        };
        let set_foreground: FnSetForegroundWindow = {
            let proc = windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("SetForegroundWindow"));
            match proc {
                Some(p) => std::mem::transmute(p),
                None => { eprintln!("[ForceVisible] SetForegroundWindow not found"); return; }
            }
        };

        // 获取前台窗口及其线程 ID
        let foreground = get_foreground();
        let foreground_tid = if foreground as usize != 0 {
            get_thread_pid(foreground, std::ptr::null_mut())
        } else {
            0
        };
        let current_tid = get_current_tid();

        // 附加输入队列以获取前台权限
        let mut attached = false;
        if foreground_tid != 0 && foreground_tid != current_tid {
            attached = attach_thread(foreground_tid, current_tid, 1) != 0;
        }

        // 强制显示并置顶 (SW_SHOWNORMAL = 1)
        let _ = show_win(hwnd_raw, 1);

        // 定位到右下角并置顶：SetWindowPos 一次完成（跨线程安全，不依赖主线程）。
        // 关键：不要用 Tauri set_position——它 dispatch 主线程同步执行，主线程忙时
        // 阻塞，导致窗口不显示/位置错乱（历史 bug：第二个弹窗"偏上/不弹出"）。
        // 计算工作区右下角（GetMonitorInfoW），物理像素需乘 DPI 缩放。
        {
            #[repr(C)]
            struct RECT { left: i32, top: i32, right: i32, bottom: i32 }
            #[repr(C)]
            struct MONITORINFO { cb_size: u32, rc_monitor: RECT, rc_work: RECT, dw_flags: u32 }

            type FnMonitorFromWindow = unsafe extern "system" fn(*mut std::ffi::c_void, u32) -> *mut std::ffi::c_void;
            type FnGetMonitorInfoW = unsafe extern "system" fn(*mut std::ffi::c_void, *mut MONITORINFO) -> i32;

            let monitor_from_window: FnMonitorFromWindow = std::mem::transmute(
                windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("MonitorFromWindow")).unwrap()
            );
            let get_monitor_info: FnGetMonitorInfoW = std::mem::transmute(
                windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("GetMonitorInfoW")).unwrap()
            );

            let monitor = monitor_from_window(hwnd_raw, 2);
            let mut mi = MONITORINFO {
                cb_size: std::mem::size_of::<MONITORINFO>() as u32,
                rc_monitor: RECT { left: 0, top: 0, right: 0, bottom: 0 },
                rc_work: RECT { left: 0, top: 0, right: 0, bottom: 0 },
                dw_flags: 0,
            };
            if !monitor.is_null() && get_monitor_info(monitor, &mut mi) != 0 {
                let dpi = get_dpi_for_window(hwnd_raw).max(96);
                let scale = dpi as f64 / 96.0;
                // 拦截窗口 360 逻辑宽，初始高度 340（最小高度）。
                // 历史 bug：旧代码硬编码 500，每次显示窗口都重置为 500px，
                // 前端 adjustWindowHeight 通过异步 invoke 调整回来有延迟，
                // 导致窗口"底下空出一大片"后才收缩。
                // 改为 340（最小高度），前端自适应调大比调小更自然。
                let w = (360.0 * scale) as i32;
                let h = (340.0 * scale) as i32;
                let pad_r = (20.0 * scale) as i32;
                let pad_b = (10.0 * scale) as i32;
                let x = mi.rc_work.right - w - pad_r;
                let y = mi.rc_work.bottom - h - pad_b;
                // HWND_TOPMOST=-1; SWP_NOACTIVATE=0x10, SWP_SHOWWINDOW=0x40
                let _ = bring_to_top(hwnd_raw, (-1_isize) as *mut std::ffi::c_void, x, y, w, h, 0x10 | 0x40);
            } else {
                let _ = bring_to_top(hwnd_raw, (-1_isize) as *mut std::ffi::c_void, 0, 0, 0, 0, 0x10 | 0x40);
            }
        }
        let _ = set_foreground(hwnd_raw);

        // 分离输入队列
        if attached {
            let _ = attach_thread(foreground_tid, current_tid, 0);
        }

        // 注意：不再调用 win.set_always_on_top()/win.set_focus()！
        // 这些 Tauri API 在后台线程调用时会 dispatch 到主线程并同步等待，
        // 主线程繁忙时可能阻塞/死锁。纯 Win32 的 ShowWindow/SetWindowPos/
        // SetForegroundWindow 已足够完成置顶，且不依赖主线程。

        println!(
            "[ForceVisible] Window forced visible: hwnd={:#x} fg_tid={} cur_tid={} attached={}",
            hwnd_raw as usize, foreground_tid, current_tid, attached
        );
    }
}

/// 仅显示窗口并获取前台权限，不改变窗口位置/大小。
/// 用于非拦截窗口（如时间线窗口）从后台线程显示时绕过 Windows 前台锁。
#[cfg(windows)]
fn force_window_foreground(win: &tauri::WebviewWindow) {
    let hwnd_raw = match win.hwnd() {
        Ok(h) => h.0 as *mut std::ffi::c_void,
        Err(e) => {
            eprintln!("[ForceForeground] Failed to get HWND: {}", e);
            return;
        }
    };

    unsafe {
        let user32 = match windows::Win32::System::LibraryLoader::LoadLibraryW(windows::core::w!("user32.dll")) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[ForceForeground] Failed to load user32.dll: {}", e);
                return;
            }
        };

        type FnGetForegroundWindow = unsafe extern "system" fn() -> *mut std::ffi::c_void;
        type FnGetWindowThreadProcessId = unsafe extern "system" fn(*mut std::ffi::c_void, *mut u32) -> u32;
        type FnGetCurrentThreadId = unsafe extern "system" fn() -> u32;
        type FnAttachThreadInput = unsafe extern "system" fn(u32, u32, i32) -> i32;
        type FnShowWindow = unsafe extern "system" fn(*mut std::ffi::c_void, i32) -> i32;
        type FnSetForegroundWindow = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;

        let get_foreground: FnGetForegroundWindow = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("GetForegroundWindow")).unwrap()
        );
        let get_thread_pid: FnGetWindowThreadProcessId = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("GetWindowThreadProcessId")).unwrap()
        );
        let get_current_tid: FnGetCurrentThreadId = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(
                windows::Win32::System::LibraryLoader::LoadLibraryW(windows::core::w!("kernel32.dll")).unwrap(),
                windows::core::s!("GetCurrentThreadId")
            ).unwrap()
        );
        let attach_thread: FnAttachThreadInput = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("AttachThreadInput")).unwrap()
        );
        let show_win: FnShowWindow = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("ShowWindow")).unwrap()
        );
        let set_foreground: FnSetForegroundWindow = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("SetForegroundWindow")).unwrap()
        );

        let foreground = get_foreground();
        let foreground_tid = if foreground as usize != 0 {
            get_thread_pid(foreground, std::ptr::null_mut())
        } else {
            0
        };
        let current_tid = get_current_tid();

        let mut attached = false;
        if foreground_tid != 0 && foreground_tid != current_tid {
            attached = attach_thread(foreground_tid, current_tid, 1) != 0;
        }

        let _ = show_win(hwnd_raw, 1); // SW_SHOWNORMAL
        let _ = set_foreground(hwnd_raw);

        if attached {
            let _ = attach_thread(foreground_tid, current_tid, 0);
        }

        println!("[ForceForeground] Window forced foreground: hwnd={:#x}", hwnd_raw as usize);
    }
}

#[cfg(not(windows))]
fn force_window_foreground(win: &tauri::WebviewWindow) {
    let _ = win.show();
    let _ = win.set_focus();
}

#[cfg(not(windows))]
fn force_window_visible(win: &tauri::WebviewWindow) {
    let _ = win.show();
    let _ = win.set_focus();
    let _ = win.set_always_on_top(true);
}

// ==================== 安全桌面（Secure Desktop 模拟，全屏 + 真实壁纸） ====================

/// 获取当前用户桌面壁纸，返回 base64 data URL（用于安全桌面背景）。
/// 纯色壁纸或读取失败时返回 None（前端退化为渐变背景）。
/// Windows 11 Spotlight/幻灯片壁纸 SPI_GETDESKWALLPAPER 可能返回空，
/// 回退读取系统缓存的 TranscodedWallpaper（这是系统对壁纸的实际渲染缓存）。
#[cfg(windows)]
fn get_desktop_wallpaper_base64() -> Option<String> {
    use windows::Win32::System::LibraryLoader::{LoadLibraryW, GetProcAddress};
    use std::os::windows::ffi::OsStringExt;

    // SPI_GETDESKWALLPAPER = 0x0073
    const SPI_GETDESKWALLPAPER: u32 = 0x0073;

    unsafe {
        let user32 = LoadLibraryW(windows::core::w!("user32.dll")).ok()?;
        type FnSystemParametersInfoW = unsafe extern "system" fn(u32, u32, *mut u16, u32) -> i32;
        let spi: FnSystemParametersInfoW = std::mem::transmute(
            GetProcAddress(user32, windows::core::s!("SystemParametersInfoW"))?
        );

        // 候选壁纸路径：SPI 查询结果 → TranscodedWallpaper 缓存
        let mut candidates: Vec<std::path::PathBuf> = Vec::new();

        // 1. SPI 查询当前壁纸路径
        let mut buf = vec![0u16; 520];
        if spi(SPI_GETDESKWALLPAPER, 0, buf.as_mut_ptr() as *mut _, 0) != 0 {
            let len = buf.iter().position(|&c| c == 0).unwrap_or(0);
            if len > 0 {
                let path_os = std::ffi::OsString::from_wide(&buf[..len]);
                let p = std::path::PathBuf::from(path_os);
                if p.exists() {
                    candidates.push(p);
                }
            }
        }

        // 2. TranscodedWallpaper 缓存（对 Spotlight/幻灯片有效）
        if let Ok(appdata) = std::env::var("APPDATA") {
            let tw = std::path::PathBuf::from(&appdata)
                .join("Microsoft").join("Windows").join("Themes").join("TranscodedWallpaper");
            if tw.exists() {
                candidates.push(tw);
            }
        }

        for path in candidates {
            let bytes = match std::fs::read(&path) {
                Ok(b) if !b.is_empty() => b,
                _ => continue,
            };
            // TranscodedWallpaper 无扩展名，按 JPEG 处理（系统缓存实际就是 JPEG）
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
            let mime = match ext.as_str() {
                "png" => "image/png",
                "bmp" => "image/bmp",
                "gif" => "image/gif",
                "webp" => "image/webp",
                _ => "image/jpeg",
            };
            return Some(format!("data:{};base64,{}", mime, base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes)));
        }

        None
    }
}

/// 强制安全桌面窗口全屏铺满整个显示器（含任务栏区域）并置顶。
/// 使用纯 Win32 SetWindowPos，跨线程安全，不依赖 Tauri 主线程。
#[cfg(windows)]
fn force_secure_desktop_fullscreen(win: &tauri::WebviewWindow) {
    let hwnd_raw = match win.hwnd() {
        Ok(h) => h.0 as *mut std::ffi::c_void,
        Err(e) => {
            eprintln!("[SecureDesktop] Failed to get HWND: {}", e);
            return;
        }
    };

    unsafe {
        let user32 = match windows::Win32::System::LibraryLoader::LoadLibraryW(windows::core::w!("user32.dll")) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[SecureDesktop] Failed to load user32.dll: {}", e);
                return;
            }
        };

        #[repr(C)]
        struct RECT { left: i32, top: i32, right: i32, bottom: i32 }
        #[repr(C)]
        struct MONITORINFO { cb_size: u32, rc_monitor: RECT, rc_work: RECT, dw_flags: u32 }

        type FnMonitorFromWindow = unsafe extern "system" fn(*mut std::ffi::c_void, u32) -> *mut std::ffi::c_void;
        type FnGetMonitorInfoW = unsafe extern "system" fn(*mut std::ffi::c_void, *mut MONITORINFO) -> i32;
        type FnSetWindowPos = unsafe extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, i32, i32, i32, i32, u32) -> i32;
        type FnShowWindow = unsafe extern "system" fn(*mut std::ffi::c_void, i32) -> i32;
        type FnSetForegroundWindow = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;

        let monitor_from_window: FnMonitorFromWindow = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("MonitorFromWindow")).unwrap()
        );
        let get_monitor_info: FnGetMonitorInfoW = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("GetMonitorInfoW")).unwrap()
        );
        let set_window_pos: FnSetWindowPos = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("SetWindowPos")).unwrap()
        );
        let show_window: FnShowWindow = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("ShowWindow")).unwrap()
        );
        let set_foreground: FnSetForegroundWindow = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("SetForegroundWindow")).unwrap()
        );

        // MONITOR_DEFAULTTONEAREST = 2
        let monitor = monitor_from_window(hwnd_raw, 2);
        let mut mi = MONITORINFO {
            cb_size: std::mem::size_of::<MONITORINFO>() as u32,
            rc_monitor: RECT { left: 0, top: 0, right: 0, bottom: 0 },
            rc_work: RECT { left: 0, top: 0, right: 0, bottom: 0 },
            dw_flags: 0,
        };

        if !monitor.is_null() && get_monitor_info(monitor, &mut mi) != 0 {
            // 使用 rc_monitor（整个显示器，含任务栏），实现真正全屏
            let w = mi.rc_monitor.right - mi.rc_monitor.left;
            let h = mi.rc_monitor.bottom - mi.rc_monitor.top;
            // HWND_TOPMOST = -1; SWP_SHOWWINDOW = 0x40
            let _ = set_window_pos(hwnd_raw, (-1_isize) as *mut std::ffi::c_void, mi.rc_monitor.left, mi.rc_monitor.top, w, h, 0x40);
            println!("[SecureDesktop] Fullscreen set: {}x{} at ({},{})", w, h, mi.rc_monitor.left, mi.rc_monitor.top);
        } else {
            // 兜底：SystemMetrics 获取主屏尺寸
            type FnGetSystemMetrics = unsafe extern "system" fn(i32) -> i32;
            let gsm: FnGetSystemMetrics = std::mem::transmute(
                windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("GetSystemMetrics")).unwrap()
            );
            let w = gsm(0); // SM_CXSCREEN
            let h = gsm(1); // SM_CYSCREEN
            let _ = set_window_pos(hwnd_raw, (-1_isize) as *mut std::ffi::c_void, 0, 0, w, h, 0x40);
            println!("[SecureDesktop] Fullscreen fallback: {}x{}", w, h);
        }

        let _ = show_window(hwnd_raw, 1); // SW_SHOWNORMAL
        let _ = set_foreground(hwnd_raw); // 抢前台焦点（绕过前台锁）
    }
}

#[cfg(not(windows))]
fn force_secure_desktop_fullscreen(win: &tauri::WebviewWindow) {
    let _ = win.set_fullscreen(true);
    let _ = win.show();
    let _ = win.set_focus();
}

/// 使用纯 Win32 ShowWindow(SW_HIDE) 立即隐藏窗口，不经过 Tauri 主线程事件循环。
///
/// 历史卡死点：win.hide() 会 dispatch 到主线程排队执行，主线程繁忙时延迟，
/// 导致决策已送达但窗口迟迟不消失（用户感知为"点击按钮后窗口卡住"）。
/// ShowWindow 可跨线程直接操作 HWND，立即生效，主线程多忙都不受影响——
/// 这才真正对齐 AVMain 的 TaskDialog（当前线程直接操作，不依赖任何事件循环）。
#[cfg(windows)]
pub(crate) fn win32_hide_window(win: &tauri::WebviewWindow) {
    let hwnd_raw = match win.hwnd() {
        Ok(h) => h.0 as *mut std::ffi::c_void,
        Err(e) => {
            eprintln!("[Win32Hide] Failed to get HWND: {}", e);
            return;
        }
    };
    unsafe {
        let user32 = match windows::Win32::System::LibraryLoader::LoadLibraryW(windows::core::w!("user32.dll")) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[Win32Hide] Failed to load user32.dll: {}", e);
                return;
            }
        };
        type FnShowWindow = unsafe extern "system" fn(*mut std::ffi::c_void, i32) -> i32;
        let show_win: FnShowWindow = match windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("ShowWindow")) {
            Some(p) => std::mem::transmute(p),
            None => { eprintln!("[Win32Hide] ShowWindow not found"); return; }
        };
        // SW_HIDE = 0：立即隐藏，不经过主线程
        let _ = show_win(hwnd_raw, 0);
        println!("[Win32Hide] Window hidden via Win32: hwnd={:#x}", hwnd_raw as usize);
    }
}

#[cfg(not(windows))]
pub(crate) fn win32_hide_window(win: &tauri::WebviewWindow) {
    let _ = win.hide();
}

/// 隐藏拦截窗口：纯 Win32 ShowWindow(SW_HIDE) 立即隐藏（任意线程直接调用）。
/// 同时通过 run_on_main_thread 异步同步 Tauri/WebView2 内部可见状态（fire-and-forget）。
/// ★历史 bug：旧代码在 Win32 隐藏后还调用了 run_on_main_thread(win.hide())，
/// 与 show_next_intercept 中的 run_on_main_thread(win.show()) 一样，
/// 派发到主线程的回调若遇主线程阻塞则永远无法执行，导致后续 invoke 全卡死。
/// ★修复：移除 run_on_main_thread，只依赖 Win32 ShowWindow(SW_HIDE)。
/// Win32 隐藏窗口后 WebView2 渲染即被暂停，无需额外同步。
#[cfg(not(feature = "ms_store"))]
fn hide_intercept_window(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("intercept-alert") {
        win32_hide_window(&win);
    }
}

/// 在主线程（Tauri 事件循环线程）执行拦截窗口显示。
/// 所有 WebviewWindow 方法（close/eval/show/动态创建）都必须在此线程调用：
/// 后台线程调用会同步等待主线程事件循环处理，主线程繁忙时死锁——窗口弹不出来、
/// 决策发不出去、被挂起的进程永久卡住（这正是 watchdog 63 秒卡死的根因）。
#[cfg(not(feature = "ms_store"))]
fn show_intercept_window_on_main(
    app: &tauri::AppHandle,
    item: &InterceptItem,
    description: &str,
) -> Result<(), String> {
    // 此函数仅作动态创建兜底（配置窗口 intercept-alert 不存在时）。
    // 历史卡死点：hide/close 基础防护窗口会同步阻塞主线程。

    if let Some(win) = app.get_webview_window("intercept-alert") {
        println!("[InterceptQueue] show_intercept_window_on_main on thread {:?}", std::thread::current().id());
        let display_path = if !item.threat_info.is_empty() {
            format!("{}\n{}", item.file_path, item.threat_info)
        } else {
            item.file_path.clone()
        };

        let escape_js = |s: &str| -> String {
            s.replace('\\', "\\\\")
             .replace('\'', "\\'")
             .replace('\n', "\\n")
             .replace('\r', "\\r")
             .replace('\t', "\\t")
        };

        let escaped_type = escape_js(&item.intercept_type);
        let escaped_process = escape_js(&item.process_name);
        let escaped_path = escape_js(&display_path);
        let escaped_resp = escape_js(&item.resp_pipe);
        let escaped_desc = escape_js(description);

        // 生成内容填充 JS：等待 DOM 就绪后应用（WebView 未加载完成时 eval 会失败，
        // 导致倒计时不启动、INTERCEPT_BUSY 卡死），最多重试 8 秒
        let js = format!(
            r#"
            (function(){{
                var data = {{ resp:'{}', type:'{}', proc:'{}', path:'{}', desc:'{}' }};
                var tries = 0;
                function apply(){{
                    var t = document.getElementById('intercept-type');
                    if (!t) {{
                        if (tries < 80) {{ tries++; setTimeout(apply, 100); return; }}
                        console.error('[eval] DOM not ready after retries');
                        return;
                    }}
                    window.currentRespPipe = data.resp;
                    document.getElementById('intercept-type').textContent = data.type;
                    document.getElementById('intercept-process').textContent = data.proc;
                    document.getElementById('intercept-command').textContent = data.path;
                    document.getElementById('intercept-description').textContent = data.desc;
                    document.getElementById('action-btn').style.display = 'none';
                    document.getElementById('action-buttons').classList.add('visible');
                    if (typeof startCountdown === 'function') startCountdown();
                    if (typeof adjustWindowHeight === 'function') adjustWindowHeight();
                    console.log('[eval] Content updated, resp_pipe: ' + data.resp);
                }}
                apply();
            }})();
            "#,
            escaped_resp, escaped_type, escaped_process, escaped_path, escaped_desc
        );
        let eval_result = win.eval(&js);
        if let Err(e) = eval_result {
            eprintln!("[InterceptQueue] eval failed: {}", e);
            log_to_file(&format!("[InterceptQueue] eval failed: {}", e));
        }
        // 标记窗口已被认领，预创建线程不应再 hide() 它
        INTERCEPT_WINDOW_CLAIMED.store(true, Ordering::SeqCst);
        // 先调用 Tauri show()，再通过 Win32 API 强制置顶（绕过前台锁）
        let show_result = win.show();
        if let Err(e) = show_result {
            eprintln!("[InterceptQueue] show failed: {}", e);
            log_to_file(&format!("[InterceptQueue] show failed: {}", e));
        }
        // 强制窗口可见并置顶（解决后台线程 show() 不显示的问题）
        force_window_visible(&win);
        println!("[InterceptQueue] Window shown for: {}", item.process_name);
        return Ok(());
    }

    // 动态创建拦截窗口（intercept-alert 配置窗口不存在时的兜底）
    let lang = get_current_language();
    let url = format!(
        "intercept-alert.html?source=driver_protection&lang={}",
        urlencoding::encode(&lang)
    );
    let new_win = tauri::WebviewWindowBuilder::new(
        app,
        "intercept-alert",
        tauri::WebviewUrl::App(url.into())
    )
    .title("实时防护拦截")
    .inner_size(360.0, 500.0)
    .decorations(false)
    .transparent(false)
    .shadow(true)
    .always_on_top(true)
    .skip_taskbar(true)
    .resizable(false)
    .visible(true)
    .build()
    .map_err(|e| format!("Failed to create window dynamically: {}", e))?;
    println!("[InterceptQueue] Dynamically created intercept window");

    // 定位到右下角
    if let Ok(Some(monitor)) = new_win.primary_monitor() {
        let mp = monitor.position();
        let ms = monitor.size();
        let sf = monitor.scale_factor();
        let phys_w = (360.0 * sf) as i32;
        let phys_h = (500.0 * sf) as i32;
        let pad_r = (20.0 * sf) as i32;
        let pad_b = (80.0 * sf) as i32;
        let x = mp.x + ms.width as i32 - phys_w - pad_r;
        let y = mp.y + ms.height as i32 - phys_h - pad_b;
        let _ = new_win.set_position(tauri::Position::Physical(
            tauri::PhysicalPosition { x, y }
        ));
    }

    // 数据填充由调用方（show_next_intercept）emit + 后台重试线程完成。
    // 历史卡死根因：此处同步 eval() 在 WebView 未就绪时可阻塞主线程，
    // 导致整个 UI（关闭/最小化/托盘/所有按钮）无响应、只剩可拖动的窗口骨架。
    // 因此只做 build + 纯 Win32 显示，绝不在此 eval。
    INTERCEPT_WINDOW_CLAIMED.store(true, Ordering::SeqCst);
    // 纯 Win32 显示+定位+置顶（跨线程安全，不经过主线程事件循环，不阻塞）
    force_window_visible(&new_win);
    println!("[InterceptQueue] Dynamically created window shown via Win32: {}", item.process_name);
    Ok(())
}

/// 弹出队列中的下一个拦截请求，显示到窗口
fn show_next_intercept(app_handle: &tauri::AppHandle) {
    println!("[InterceptQueue] show_next_intercept on thread {:?}", std::thread::current().id());
    // 互斥锁保护整个流程：check-then-set 竞态 + 窗口操作竞争
    let _show_guard = INTERCEPT_SHOW_LOCK.get_or_init(|| StdMutex::new(())).lock().unwrap();

    if INTERCEPT_BUSY.load(Ordering::SeqCst) {
        println!("[InterceptQueue] Busy, waiting...");
        return;
    }

    let item = {
        let mut queue = INTERCEPT_QUEUE.lock().unwrap();
        queue.pop_front()
    };

    let item = match item {
        Some(i) => i,
        None => {
            println!("[InterceptQueue] Queue empty, hiding window");
            // 队列空了，隐藏窗口（纯 Win32 立即隐藏 + dispatch 同步 Tauri 状态）
            INTERCEPT_WINDOW_CLAIMED.store(false, Ordering::SeqCst);
            hide_intercept_window(app_handle);
            return;
        }
    };

    INTERCEPT_BUSY.store(true, Ordering::SeqCst);
    INTERCEPT_BUSY_SINCE.store(chrono::Local::now().timestamp(), Ordering::SeqCst);

    // ===== 显示拦截窗口：完全不依赖 Tauri 主线程事件循环 =====
    // 窗口由 tauri.conf.json 配置（label: intercept-alert，visible: false 隐藏创建）。
    // 显示用纯 Win32 ShowWindow/SetForegroundWindow（跨线程安全、立即生效），
    // 数据注入用线程安全的 emit 事件（前端已 listen intercept-data）。
    // 关键：只要 Win32 显示成功即视为"窗口已显示"——emit 失败绝不 auto-block！
    // 历史 bug：emit 失败被误判为窗口显示失败，触发 auto-block 消费 AV_DRIVER_PENDING
    // 记录，而窗口其实已弹出 → 用户点按钮时记录已空 → Notification not found → 决策发不出。
    // emit 失败由后台重试线程兜底（webview 加载完成后补发数据）。
    let mut shown_ok = false;
    if let Some(win) = app_handle.get_webview_window("intercept-alert") {
        // 注意：不在主线程调用 set_position！force_window_visible 内部已用纯 Win32
        // SetWindowPos 完成"显示 + 定位右下角 + 置顶"（跨线程直调，不依赖主线程）。
        // 纯 Win32 显示 + 置顶（不经过主线程，立即生效）
        // ★历史 bug：旧代码在此处还调用了 run_on_main_thread(win.show()) 来
        // "同步 WebView2 可见状态"，但 run_on_main_thread 将回调派发到主线程事件循环。
        // 若主线程被其他回调阻塞（如 resize 的 set_size），该回调永远无法执行，
        // 导致后续所有 invoke（close_intercept_window、扫描、开关防护等）也卡死
        // （它们同样依赖主线程处理 IPC 消息），表现为整个程序完全冻结。
        // ★修复：移除 run_on_main_thread，只依赖 Win32 ShowWindow。
        // Win32 显示窗口后 WebView2 内容即可见，无需额外同步。
        force_window_visible(&win);
        INTERCEPT_WINDOW_CLAIMED.store(true, Ordering::SeqCst);
        // 只要窗口存在且 Win32 显示成功，就视为已显示
        shown_ok = true;
        println!("[InterceptQueue] Window shown via Win32 for: {}", item.process_name);

        // 数据注入：emit 事件（线程安全）。失败不阻塞，交给重试线程补发。
        let display_path = if !item.threat_info.is_empty() {
            format!("{}\n{}", item.file_path, item.threat_info)
        } else {
            item.file_path.clone()
        };
        let payload = serde_json::json!({
            "type": item.intercept_type,
            "process": item.process_name,
            "command": display_path,
            "resp_pipe": item.resp_pipe,
            "source": "driver_protection",
        });
        if win.emit("intercept-data", payload).is_ok() {
            println!("[InterceptQueue] intercept-data emitted for: {}", item.process_name);
        } else {
            eprintln!("[InterceptQueue] emit intercept-data failed (will retry in background): {}", item.process_name);
        }

        // 后台重试线程：webview 未加载完成时 emit 会失败（listener 未注册），
        // 每 500ms 重试直到成功或等待者被消费（决策已送达），最长 30 秒。
        let retry_win = win.clone();
        let retry_resp = item.resp_pipe.clone();
        let retry_type = item.intercept_type.clone();
        let retry_proc = item.process_name.clone();
        let retry_path = display_path.clone();
        std::thread::spawn(move || {
            for attempt in 0..60 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                // 等待者已被消费（决策送达/超时）→ 停止重试
                let still_waiting = match AV_DECISION_WAITERS.get() {
                    Some(w) => w.lock().unwrap().contains_key(&retry_resp),
                    None => false,
                };
                if !still_waiting {
                    break;
                }
                let payload = serde_json::json!({
                    "type": retry_type,
                    "process": retry_proc,
                    "command": retry_path,
                    "resp_pipe": retry_resp,
                    "source": "driver_protection",
                });
                if retry_win.emit("intercept-data", payload).is_ok() {
                    println!("[InterceptQueue] intercept-data re-emitted (attempt {})", attempt + 1);
                    break;
                }
            }
        });
    } else {
        // 窗口不存在（配置窗口未创建/已销毁）：兜底 dispatch 到主线程动态创建。
        // 历史卡死根因：此处 run_on_main_or_direct 把 show_intercept_window_on_main
        // （内部同步 eval/show）dispatch 到主线程，主线程被未就绪 WebView 阻塞后，
        // 整个 UI（关闭/最小化/托盘/所有按钮）全部无响应，只剩可拖动的窗口骨架。
        // 现在：dispatch 只做 build + Win32 显示（不 eval），且本线程不阻塞等待，
        // 改为轮询 get_webview_window（纯查表，不依赖主线程）+ emit 补数据。
        eprintln!("[InterceptQueue] Window not found, dispatching dynamic creation (non-blocking)");
        let app_clone = app_handle.clone();
        let item_clone = item.clone();
        let _ = app_handle.run_on_main_thread(move || {
            let _ = show_intercept_window_on_main(&app_clone, &item_clone, "");
        });

        // 轮询等待窗口出现（最多 5 秒；get_webview_window 是纯查表，主线程被占也不影响）
        let mut win_opt = None;
        for _ in 0..50 {
            if let Some(win) = app_handle.get_webview_window("intercept-alert") {
                win_opt = Some(win);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        if let Some(win) = win_opt {
            // 纯 Win32 显示 + 置顶（跨线程安全，不经过主线程）
            force_window_visible(&win);
            // 同步 Tauri/WebView2 可见状态（fire-and-forget）
            let win_clone = win.clone();
            let _ = app_handle.run_on_main_thread(move || { let _ = win_clone.show(); });
            INTERCEPT_WINDOW_CLAIMED.store(true, Ordering::SeqCst);
            shown_ok = true;
            // 数据注入：emit 事件（线程安全）。失败交给下面的重试线程兜底。
            let display_path = if !item.threat_info.is_empty() {
                format!("{}\n{}", item.file_path, item.threat_info)
            } else {
                item.file_path.clone()
            };
            let payload = serde_json::json!({
                "type": item.intercept_type,
                "process": item.process_name,
                "command": display_path,
                "resp_pipe": item.resp_pipe,
                "source": "driver_protection",
            });
            if win.emit("intercept-data", payload).is_ok() {
                println!("[InterceptQueue] intercept-data emitted for: {}", item.process_name);
            } else {
                eprintln!("[InterceptQueue] emit intercept-data failed (will retry in background): {}", item.process_name);
            }
            // 后台重试线程：webview 未加载完成时 emit 会失败（listener 未注册），
            // 每 500ms 重试直到成功或等待者被消费（决策已送达），最长 30 秒。
            let retry_win = win.clone();
            let retry_resp = item.resp_pipe.clone();
            let retry_type = item.intercept_type.clone();
            let retry_proc = item.process_name.clone();
            let retry_path = display_path.clone();
            std::thread::spawn(move || {
                for attempt in 0..60 {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    let still_waiting = match AV_DECISION_WAITERS.get() {
                        Some(w) => w.lock().unwrap().contains_key(&retry_resp),
                        None => false,
                    };
                    if !still_waiting {
                        break;
                    }
                    let payload = serde_json::json!({
                        "type": retry_type,
                        "process": retry_proc,
                        "command": retry_path,
                        "resp_pipe": retry_resp,
                        "source": "driver_protection",
                    });
                    if retry_win.emit("intercept-data", payload).is_ok() {
                        println!("[InterceptQueue] intercept-data re-emitted (attempt {})", attempt + 1);
                        break;
                    }
                }
            });
        } else {
            eprintln!("[InterceptQueue] Window creation failed within 5s, auto-blocking: {}", item.process_name);
        }
    }

    if !shown_ok {
        eprintln!("[InterceptQueue] Failed to show intercept window, auto-blocking: {}", item.process_name);
        log_to_file(&format!("[InterceptQueue] Window show failed: {}", item.process_name));
        // 窗口显示失败 → 拦截所有排队请求并清空队列
        let drain_and_block = || -> Vec<InterceptItem> {
            let mut queue = INTERCEPT_QUEUE.lock().unwrap();
            queue.drain(..).collect()
        };
        block_intercept_item(&item.resp_pipe);
        for pending in drain_and_block() {
            block_intercept_item(&pending.resp_pipe);
        }
        INTERCEPT_BUSY.store(false, Ordering::SeqCst);
        INTERCEPT_BUSY_SINCE.store(0, Ordering::SeqCst);
        INTERCEPT_WINDOW_CLAIMED.store(false, Ordering::SeqCst);
        return;
    }

    // ===== 同步等待用户决策（与 AVMain 的 TaskDialog 模态阻塞语义一致）=====
    // 本线程 = 消息循环线程，在此阻塞等待；前端按钮点击 →
    // send_av_driver_decision 命令（Tauri 线程池）→ 通过 AV_DECISION_WAITERS
    // 发送决策唤醒本线程 → 本线程直接写决策回管道、关闭窗口、重置状态。
    // 弹窗等待期间不读新通知，后续通知由驱动/Agent 排队，与 AVMain 一致。
    // 30 秒超时兜底默认放行（与 Agent/驱动超时对齐，防止进程永久挂起）。
    //
    // 释放 INTERCEPT_SHOW_LOCK：窗口已显示完毕、INTERCEPT_BUSY 已设置，
    // 锁不再需要（BUSY 标志足以防止并发）。提前释放锁允许基础防护 try_lock
    // 成功（发现 BUSY=true 后跳过），避免该锁被本线程阻塞 30 秒。
    drop(_show_guard);
    let resp_pipe_key = item.resp_pipe.clone();
    let (wait_tx, wait_rx) = mpsc::channel::<av_driver_client::AvDecision>();
    {
        let mut waiters = AV_DECISION_WAITERS
            .get_or_init(|| StdMutex::new(HashMap::new()))
            .lock()
            .unwrap();
        waiters.insert(resp_pipe_key.clone(), wait_tx);
    }
    println!("[InterceptQueue] Waiting for user decision: {}", item.process_name);

    // ★AVIC 已知威胁（default_block）用 25 秒超时而非 30 秒：
    // Agent 侧决策等待超时是 30 秒（默认放行）。若本端超时后再发默认 DENY，
    // Agent 可能已超时放行，导致"超时却放行了恶意程序"。
    // 25 秒保证默认决策在 Agent 超时前送达。
    let wait_secs = if item.default_block { 25 } else { 30 };
    let decision = match wait_rx.recv_timeout(std::time::Duration::from_secs(wait_secs)) {
        Ok(d) => d,
        Err(_) => {
            println!("[InterceptQueue] Decision timeout, defaulting to {}: {}", if item.default_block { "block" } else { "allow" }, item.process_name);
            log_to_file(&format!("[InterceptQueue] Decision timeout, default {}: {}", if item.default_block { "block" } else { "allow" }, item.process_name));
            build_default_decision(&resp_pipe_key)
        }
    };

    // 清理等待者注册
    if let Some(waiters) = AV_DECISION_WAITERS.get() {
        waiters.lock().unwrap().remove(&resp_pipe_key);
    }

    // 异步发送决策到驱动（不阻塞 show_next_intercept 线程）
    // ★历史 bug：旧代码同步调用 send_av_decision。若驱动管道堵塞（如驱动未响应、
    // 通知已被 AVIC 前置 DENY 消费导致管道写入卡住），该线程被阻塞，无法关闭
    // 窗口/重置 INTERCEPT_BUSY，导致后续所有拦截窗口无法弹出、程序卡死。
    // ★修复：spawn 独立线程异步发送，本线程立即关闭窗口+重置状态，确保
    // 后续拦截能正常进行。即使异步发送失败（如驱动已处理完通知），也不影响
    // 窗口关闭和状态重置（幂等操作）。
    std::thread::spawn(move || {
        if let Err(e) = av_driver_client::send_av_decision(decision) {
            eprintln!("[InterceptQueue] Failed to send decision (async): {}", e);
            log_to_file(&format!("[InterceptQueue] Failed to send decision (async): {}", e));
        }
    });

    // 隐藏拦截窗口、重置状态，准备处理下一条通知。
    // 纯 Win32 立即隐藏（任意线程直调，主线程多忙都生效），再 dispatch 同步 Tauri 状态
    hide_intercept_window(app_handle);
    INTERCEPT_BUSY.store(false, Ordering::SeqCst);
    INTERCEPT_BUSY_SINCE.store(0, Ordering::SeqCst);
    INTERCEPT_WINDOW_CLAIMED.store(false, Ordering::SeqCst);
    println!("[InterceptQueue] Decision sent, window hidden. Ready for next notification.");

    // 关键：主动拉取队列中的下一个拦截请求！
    // 历史 bug：show_next_intercept 只在入队时调用一次，busy 时直接 return，
    // 之后无人再拉取队列 → 队列里的请求必须等超时/其他事件才被处理，
    // 表现为"等到超时之后才弹出下一次的拦截"。
    {
        let queue_empty = INTERCEPT_QUEUE.lock().unwrap().is_empty();
        if !queue_empty {
            println!("[InterceptQueue] Queue has pending items, processing next...");
            // _show_guard 已在 recv_timeout 前释放（见上方的 drop），无需再次 drop
            show_next_intercept(app_handle);
            return;
        }
    }
}

/// 决策超时兜底：根据待决通知信息生成默认放行决策
/// （前端 30 秒未决策时调用；若 AV_DRIVER_PENDING 已被前端命令消费，
/// 则退化为按 notification_id 构造默认放行，确保进程不会被永久挂起）
#[cfg(not(feature = "ms_store"))]
fn build_default_decision(pending_key: &str) -> av_driver_client::AvDecision {
    use av_driver_client::*;

    let info = {
        let mut pending = AV_DRIVER_PENDING.lock().unwrap();
        pending.remove(pending_key)
    };

    match info {
        Some(info) => {
            // AVIC 云端已知威胁（default_block=true）超时默认拦截，其余默认放行
            let default_dec = if info.default_block { AV_DECISION_DENY_ONCE } else { AV_DECISION_ALLOW_ONCE };
            match info.notification_type.as_str() {
                "process" => AvDecision::Process {
                    notification_id: info.notification_id,
                    decision: default_dec,
                    image_path: info.image_path,
                },
                "registry" => AvDecision::Registry {
                    notification_id: info.notification_id,
                    decision: AV_DECISION_ALLOW_ONCE,
                    key_path: info.image_path,
                },
                "injection" => AvDecision::Injection {
                    notification_id: info.notification_id,
                    decision: AV_DECISION_ALLOW_ONCE,
                },
                "ransom" => AvDecision::Ransom {
                    notification_id: info.notification_id,
                    decision: XGS_DECISION_STAY_BLOCK,
                },
                "endpoint" => AvDecision::EndPoint {
                    notification_id: info.notification_id,
                    decision: XGS_EP_DECISION_ALLOW,
                },
                "injectguard" => AvDecision::InjectGuard {
                    sequence_id: info.notification_id as u32,
                    decision: IG_DECISION_ALLOW,
                },
                _ => AvDecision::Process {
                    notification_id: info.notification_id,
                    decision: default_dec,
                    image_path: info.image_path,
                },
            }
        }
        None => {
            // 查不到（极端情况）：按 pending_key 解析 notification_id，默认放行
            let notification_id = pending_key.parse::<u64>().unwrap_or(0);
            AvDecision::Process {
                notification_id,
                decision: AV_DECISION_ALLOW_ONCE,
                image_path: String::new(),
            }
        }
    }
}

/// 拦截一个排队项：新驱动通知走 send_av_decision，旧版走 write_to_resp_pipe
#[cfg(not(feature = "ms_store"))]
fn block_intercept_item(resp_pipe: &str) {
    if resp_pipe.is_empty() { return; }

    // 检查是否是新驱动通知 (notification_id 存在于 AV_DRIVER_PENDING)
    let pending_info = {
        let mut pending = AV_DRIVER_PENDING.lock().unwrap();
        pending.remove(resp_pipe)
    };
    if let Some(info) = pending_info {
        // 新驱动：通过 send_av_decision 发送拦截决策
        let decision = match info.notification_type.as_str() {
            "process" => av_driver_client::AvDecision::Process {
                notification_id: info.notification_id,
                decision: av_driver_client::AV_DECISION_DENY_ONCE,
                image_path: info.image_path,
            },
            "registry" => av_driver_client::AvDecision::Registry {
                notification_id: info.notification_id,
                decision: av_driver_client::AV_DECISION_DENY_ONCE,
                key_path: info.image_path,
            },
            "injection" => av_driver_client::AvDecision::Injection {
                notification_id: info.notification_id,
                decision: av_driver_client::AV_DECISION_DENY_ONCE,
            },
            "ransom" => av_driver_client::AvDecision::Ransom {
                notification_id: info.notification_id,
                decision: av_driver_client::XGS_DECISION_STAY_BLOCK,
            },
            "endpoint" => av_driver_client::AvDecision::EndPoint {
                notification_id: info.notification_id,
                decision: av_driver_client::XGS_EP_DECISION_KILL,
            },
            "injectguard" => av_driver_client::AvDecision::InjectGuard {
                sequence_id: info.notification_id as u32,
                decision: av_driver_client::IG_DECISION_BLOCK,
            },
            _ => {
                eprintln!("[InterceptQueue] Unknown notification type: {}", info.notification_type);
                return;
            }
        };
        let _ = av_driver_client::send_av_decision(decision);
        return;
    }

    // 旧版 SimpleLauncher：写入响应管道
    write_to_resp_pipe(resp_pipe, "block");
}

#[cfg(not(feature = "ms_store"))]
fn extract_process_name(message: &str) -> Option<String> {
    println!("[ExtractProcess] Parsing message: {}", message);
    
    // 格式1: (进程: regedit.exe) - 实际日志格式
    // 使用 char_indices 来正确处理 Unicode 字符
    if let Some(start) = message.find("(进程:") {
        // 找到 "(进程:" 后面的位置（考虑 Unicode 字符边界）
        let prefix = "(进程:";
        let search_start = start + prefix.len();
        if search_start < message.len() {
            // 跳过冒号后的空格
            let rest = &message[search_start..];
            let rest = if rest.starts_with(' ') {
                &rest[1..]
            } else {
                rest
            };
            println!("[ExtractProcess] Found '(进程:' at {}, rest: {}", start, rest);
            if let Some(end) = rest.find(")") {
                let process_name = rest[..end].trim().to_string();
                println!("[ExtractProcess] Extracted process name: {}", process_name);
                return Some(process_name);
            }
        }
    }
    
    // 格式2: 进程: xxx.exe
    if let Some(start) = message.find("进程:") {
        let prefix = "进程:";
        let search_start = start + prefix.len();
        if search_start < message.len() {
            let rest = &message[search_start..];
            // 如果下一个字符是空格，跳过它
            let rest = if rest.starts_with(' ') {
                &rest[1..]
            } else {
                rest
            };
            println!("[ExtractProcess] Found '进程:' at {}, rest: {}", start, rest);
            if let Some(end) = rest.find(" ") {
                let process_name = rest[..end].trim().to_string();
                println!("[ExtractProcess] Extracted process name: {}", process_name);
                return Some(process_name);
            }
        }
    }
    
    // 尝试其他格式
    if let Some(start) = message.find("Process:") {
        let prefix = "Process:";
        let search_start = start + prefix.len();
        if search_start < message.len() {
            let rest = &message[search_start..];
            if let Some(end) = rest.find(" ") {
                let process_name = rest[..end].trim().to_string();
                println!("[ExtractProcess] Extracted process name from 'Process:': {}", process_name);
                return Some(process_name);
            }
        }
    }
    
    // 格式: Blocked: xxx.exe (PID: ...) — SimpleLauncher.c 驱动拦截消息
    if let Some(bs) = message.find("Blocked: ") {
        let after = &message[bs + 9..]; // skip "Blocked: "
        if let Some(pid_pos) = after.find(" (PID:") {
            let name = after[..pid_pos].trim();
            if !name.is_empty() {
                println!("[ExtractProcess] Extracted from 'Blocked:': {}", name);
                return Some(name.to_string());
            }
        }
    }

    // 格式3: 已阻止恶意行为: \??\C:\WINDOWS\system32\taskkill.exe (类型: ...)
    // 从路径中提取进程名
    if message.contains("已阻止恶意行为:") || message.contains("拦截恶意行为:") {
        // 查找 .exe 路径
        if let Some(exe_pos) = message.find(".exe") {
            // 向前查找路径开始（\ 或 :\）
            let before_exe = &message[..exe_pos];
            if let Some(last_slash) = before_exe.rfind("\\") {
                // 确保索引有效
                let start_idx = last_slash + 1;
                let end_idx = exe_pos + 4; // +4 包含 ".exe"
                if start_idx <= exe_pos && end_idx <= message.len() {
                    let process_name = &message[start_idx..end_idx];
                    let process_name = process_name.trim().to_string();
                    if !process_name.is_empty() {
                        println!("[ExtractProcess] Extracted process name from path: {}", process_name);
                        return Some(process_name);
                    }
                }
            }
        }
    }
    
    println!("[ExtractProcess] Could not extract process name from message");
    None
}

// ==================== 新 KMDF 驱动通知处理 ====================

/// 当前待处理的驱动通知信息（供 send_av_driver_decision 查找）
#[cfg(not(feature = "ms_store"))]
struct AvDriverPendingInfo {
    /// 通知类型: "process", "registry", "injection", "ransom", "endpoint"
    notification_type: String,
    /// 通知 ID
    notification_id: u64,
    /// 镜像路径（进程/注册表决策需要）
    image_path: String,
    /// 进程名（用于日志/通知）
    process_name: String,
    /// 用户超时未决策时的默认动作：true=拦截（AVIC 云端已知威胁）
    default_block: bool,
}

#[cfg(not(feature = "ms_store"))]
lazy_static::lazy_static! {
    static ref AV_DRIVER_PENDING: StdMutex<std::collections::HashMap<String, AvDriverPendingInfo>> =
        StdMutex::new(std::collections::HashMap::new());
}

/// 获取待分析的文件路径（由用户在设置中指定）
fn get_pending_analysis_file() -> Option<String> {
    sandbox_analysis::get_pending_file()
}

/// 沙盒分析完整流程
/// 1. 右下角弹窗"正在分析"
/// 2. 在沙盒中运行文件
/// 3. 收集行为数据并通过 IOA 规则分析
/// 4. 安全→关闭沙盒重启程序；恶意→终止
pub fn handle_sandbox_analysis(app_handle: &tauri::AppHandle, original_file: &str) {
    use sandbox_analysis::*;

    // ★互斥锁：序列化所有沙盒分析调用，防止并发分析导致进度窗口竞态★
    // 如果上一个分析还在收尾（verdict/progress/cleanup），此调用会等待其完成。
    let _analysis_lock = SANDBOX_ANALYSIS_LOCK
        .get_or_init(|| StdMutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    // ★全局冷却期检查（入口级最终防线）★
    // 分析完成后重新启动的原程序（含子进程）可能立即触发相同路径的再次分析，
    // 造成"分析→重启→再分析"死循环。冷却期内相同路径直接跳过，不再弹窗口。
    if sandbox_analysis::should_skip_due_to_cooldown(original_file) {
        println!("[SandboxAnalysis] 冷却期内跳过重复分析请求: {}", original_file);
        diag_info!("[SandboxAnalysis] 冷却期内跳过重复分析请求: {}", original_file);
        return;
    }

    println!("[SandboxAnalysis] 开始分析: {}", original_file);
    diag_info!("[SandboxAnalysis] 开始分析: {}", original_file);

    let process_name = std::path::Path::new(&original_file)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("未知程序");

    // 1. 创建右下角进度窗口（使用预创建窗口，不在后台线程创建 WebviewWindow）
    let progress_window = show_sandbox_progress_window(app_handle, process_name);
    if progress_window.is_none() {
        eprintln!("[SandboxAnalysis] ★警告：进度窗口不存在！可能被前端 close() 销毁了。分析将继续在后台进行。");
        diag_warn!("[SandboxAnalysis] ★警告：进度窗口不存在！可能被前端 close() 销毁了。分析将继续在后台进行。");
    }

    // 窗口是预创建的，页面早已加载完成，只需短暂等待 UI 线程处理 show 消息
    // 旧代码等待 800ms，实际 100ms 足够 Win32 ShowWindow 完成
    std::thread::sleep(std::time::Duration::from_millis(100));

    let _ = app_handle.emit("sandbox-progress", serde_json::json!({
        "filename": process_name,
        "step": 1,
        "status_text": "正在启动沙箱环境..."
    }));

    // 2. 准备环境
    diag_info!("[SandboxAnalysis] 正在准备沙盒环境...");
    let mut controller = SandboxController::new(original_file);
    if let Err(e) = controller.prepare_environment() {
        eprintln!("[SandboxAnalysis] 环境准备失败: {}", e);
        diag_warn!("[SandboxAnalysis] 环境准备失败: {}", e);
        let _ = app_handle.emit("sandbox-progress", serde_json::json!({
            "step": 1,
            "status_text": format!("环境准备失败: {}", e)
        }));
        close_sandbox_progress_window(app_handle, 3000);
        return;
    }
    diag_info!("[SandboxAnalysis] 沙盒环境已就绪");

    let _ = app_handle.emit("sandbox-progress", serde_json::json!({
        "filename": process_name,
        "step": 2,
        "status_text": "沙盒已就绪，正在启动目标程序..."
    }));

    // 设置分析标记，沙盒内启动的进程不会被重复拦截
    sandbox_analysis::set_analyzing(true);
    // 清空上一次的沙箱 PID 集合
    sandbox_analysis::clear_sandbox_pids();

    // 3. 启动沙盒
    diag_info!("[SandboxAnalysis] 正在启动目标程序到沙盒...");
    if let Err(e) = controller.start() {
        eprintln!("[SandboxAnalysis] 沙盒启动失败: {}", e);
        diag_warn!("[SandboxAnalysis] 沙盒启动失败: {}", e);
        sandbox_analysis::set_analyzing(false);
        sandbox_analysis::clear_sandbox_pids();
        let _ = app_handle.emit("sandbox-progress", serde_json::json!({
            "step": 2,
            "status_text": format!("沙盒启动失败: {}", e)
        }));
        close_sandbox_progress_window(app_handle, 3000);
        return;
    }

    // 记录沙箱内目标进程 PID，用于区分沙箱内/外进程
    if let Some(target_pid) = controller.target_pid() {
        sandbox_analysis::add_sandbox_pid(target_pid);
        println!("[SandboxAnalysis] 沙箱目标 PID={} 已记录", target_pid);
    }

    let _ = app_handle.emit("sandbox-progress", serde_json::json!({
        "filename": process_name,
        "step": 2,
        "status_text": "正在监控程序行为..."
    }));

    // 4. 收集行为数据（通过 Sandboxie 跟踪日志和文件系统监控）
    collect_behavior_events(&mut controller, original_file);

    let _ = app_handle.emit("sandbox-progress", serde_json::json!({
        "step": 3,
        "status_text": "正在分析行为数据..."
    }));

    // 分析完成，关闭沙盒
    // 注意：set_analyzing(false) 移到函数末尾，防止在 verdict/cleanup 期间
    // 被新的分析请求插入导致并发竞态
    let _ = controller.stop();

    // 5. 分析结果
    let (verdict, score, hits) = controller.analyze();
    let malware_family = controller.detect_malware_family();
    println!(
        "[SandboxAnalysis] 分析完成: verdict={}, score={}, hits={}, family={}",
        verdict.label(),
        score,
        hits.len(),
        malware_family.as_ref().map(|f| f.name.as_str()).unwrap_or("未识别")
    );

    // 6. 发送分析结果到进度窗口
    let (verdict_str, family_name, family_desc) = match &verdict {
        AnalysisVerdict::Benign => {
            // 加入白名单，下次不再拦截
            sandbox_analysis::add_to_whitelist(original_file);
            ("safe", None, None)
        }
        AnalysisVerdict::Malicious => {
            let hit_names: Vec<&str> = hits.iter().map(|(_, name)| name.as_str()).collect();
            let desc = match &malware_family {
                Some(family) => format!(
                    "{}\n命中规则: {}", family.description, hit_names.join(", ")
                ),
                None => format!("命中规则: {}", hit_names.join(", ")),
            };

            // AVIC 云端情报上报（沙箱分析检出恶意）
            let avic_family = malware_family.as_ref().map(|f| f.name.as_str()).unwrap_or("Sandbox.Detected");
            let avic_threat = format!("Sandbox/{}", avic_family);
            avic_client::submit_threat(original_file, &avic_threat, avic_family, "sandbox");

            ("malicious", malware_family.as_ref().map(|f| f.name.clone()), Some(desc))
        }
        AnalysisVerdict::Suspicious => {
            let desc = match &malware_family {
                Some(family) => format!("疑似 {}（评分: {}）\n{}", family.name, score, family.description),
                None => format!("评分: {}", score),
            };

            // AVIC 云端情报上报（沙箱分析检出疑似恶意）
            let avic_family = malware_family.as_ref().map(|f| f.name.as_str()).unwrap_or("Sandbox.Suspicious");
            let avic_threat = format!("Sandbox/{}", avic_family);
            avic_client::submit_threat(original_file, &avic_threat, avic_family, "sandbox");

            ("suspicious", malware_family.as_ref().map(|f| f.name.clone()), Some(desc))
        }
    };

    let _ = app_handle.emit("sandbox-result", serde_json::json!({
        "verdict": verdict_str,
        "family_name": family_name,
        "description": family_desc,
        "score": score,
    }));

    // 8. 导出行为分析报告到日志目录
    {
        let report = controller.export_report(verdict_str, score, malware_family.as_ref());
        let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
        let report_dir = format!("{}/XIGUASecurity/sandbox_reports", local_app_data);
        let _ = std::fs::create_dir_all(&report_dir);

        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let file_name = std::path::Path::new(&original_file)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");
        let safe_name: String = file_name.chars()
            .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
            .collect();
        let report_path = format!("{}/{}_{}.txt", report_dir, safe_name, timestamp);

        match std::fs::write(&report_path, &report) {
            Ok(_) => {
                println!("[SandboxAnalysis] 行为报告已导出: {}", report_path);
                diag_info!("[SandboxAnalysis] 行为报告已导出: {}", report_path);
            }
            Err(e) => {
                eprintln!("[SandboxAnalysis] 行为报告导出失败: {}", e);
                diag_warn!("[SandboxAnalysis] 行为报告导出失败: {}", e);
            }
        }
        // 同时写入诊断日志
        diag_info!("[SandboxAnalysis] === 行为报告 ===\n{}", report);
    }

    // 7. 根据结果处理
    match &verdict {
        AnalysisVerdict::Benign => {
            // ★路径级防再触发★：分析完成判定安全，标记原始文件路径，
            // 该路径下所有进程（含子进程）在 TTL 内不再触发新的沙箱分析
            sandbox_analysis::mark_recently_analyzed_path(original_file);

            // 重新运行原始文件
            match std::process::Command::new(original_file)
                .creation_flags(0x08000000)
                .spawn()
            {
                Ok(child) => {
                    println!("[SandboxAnalysis] 重新启动原始文件成功: {} (PID={})", original_file, child.id());
                    // ★防再触发★：将重新启动的进程标记为"最近放行"（TTL 10s），
                    // 防止驱动/WMI/R3 立即再次识别它而触发第二次沙箱分析。
                    // 历史 bug：重新启动的进程与白名单写入存在竞态，立即触发二次分析，
                    // 且 find_pids_by_name 把普通进程误判为沙箱目标，导致"薛定谔"状态。
                    sandbox_analysis::mark_recently_launched(child.id());
                }
                Err(e) => {
                    eprintln!("[SandboxAnalysis] 重新启动原始文件失败: {} - {}", original_file, e);
                    // 通知用户启动失败
                    let _ = app_handle.emit("sandbox-result", serde_json::json!({
                        "verdict": "launch_failed",
                        "error": e.to_string(),
                        "original_file": original_file,
                    }));
                }
            }
            close_sandbox_progress_window(app_handle, 8000);
        }
        AnalysisVerdict::Malicious | AnalysisVerdict::Suspicious => {
            close_sandbox_progress_window(app_handle, 8000);
        }
    }

    cleanup_trigger();
    sandbox_analysis::clear_pending_file();
    sandbox_analysis::clear_sandbox_pids();
    sandbox_analysis::clear_titled_hwnds();
    
    // ★最后才清除分析标记：确保整个分析流程（含 verdict、进度窗口、cleanup）完全结束后，
    // 才允许新的沙盒分析请求进入。配合 SANDBOX_ANALYSIS_LOCK 互斥锁双重保障。
    sandbox_analysis::set_analyzing(false);

    // ★记录分析结束时间，启动全局冷却期★
    // 冷却期内（3s）相同路径的再次分析请求在入口直接跳过，
    // 从根源杜绝"分析完成→重新启动→再分析"死循环。
    sandbox_analysis::mark_analysis_cooldown();
}

/// 创建沙箱分析进度窗口（右下角）
fn show_sandbox_progress_window(app: &tauri::AppHandle, process_name: &str) -> Option<tauri::WebviewWindow> {
    println!("[SandboxProgress] 开始创建进度窗口，文件: {}", process_name);

    let window = app.get_webview_window("sandbox-progress")?;
    println!("[SandboxProgress] 找到预创建窗口");

    // ★递增代际计数器，使之前所有 pending 的关闭定时器失效★
    let _gen = SANDBOX_PROGRESS_GEN.fetch_add(1, Ordering::SeqCst);
    println!("[SandboxProgress] 代际计数器: {} → {}", _gen, _gen + 1);

    // ★先用 Win32 API 显示窗口（不经过主线程，立即生效），再 eval 重置页面★
    // 顺序很重要：如果 eval 先执行且主线程繁忙，eval 会阻塞后台线程，
    // 导致 win32_show_window 迟迟不被调用，窗口弹不出来。
    // 先 show 确保窗口立即可见，eval 即使延迟也不影响窗口显示。
    println!("[SandboxProgress] 调用 win32_show_window 显示窗口");
    win32_show_window(&window, 360.0, 380.0, true);

    // 重置页面状态（窗口可能被隐藏而非销毁，上次的状态还在）
    // 放在 show 之后：即使 eval 失败或延迟，窗口已经显示
    let _ = window.eval("window.__resetSandboxProgress && window.__resetSandboxProgress();");

    println!("[SandboxProgress] 进度窗口已显示，文件: {}", process_name);
    Some(window)
}

/// 关闭沙箱分析进度窗口（隐藏而非销毁，避免页面重载）
/// 使用代际计数器防止旧定时器关闭新窗口
/// 
/// ★必须用 Win32 ShowWindow(SW_HIDE) 而非 Tauri window.hide()★
/// 原因：show 用 Win32 ShowWindow(SW_SHOWNORMAL)，如果 hide 用 Tauri hide()，
/// Tauri 内部 visible 标志会变成 false，后续 Win32 ShowWindow 让 HWND 可见后，
/// Tauri 内部逻辑可能把窗口重新隐藏 —— 表现为"第二次进度窗口弹不出来"。
/// 统一用 Win32 控制可见性，Tauri 内部始终认为 visible=true，不产生冲突。
fn close_sandbox_progress_window(app: &tauri::AppHandle, delay_ms: u64) {
    let gen = SANDBOX_PROGRESS_GEN.load(Ordering::SeqCst);
    let app_handle = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        let current_gen = SANDBOX_PROGRESS_GEN.load(Ordering::SeqCst);
        if current_gen != gen {
            println!("[SandboxProgress] 关闭定时器代际不匹配 ({} != {})，跳过隐藏", gen, current_gen);
            return;
        }
        if let Some(window) = app_handle.get_webview_window("sandbox-progress") {
            // 用 Win32 API 隐藏窗口，不用 Tauri window.hide()
            win32_hide_window(&window);
            println!("[SandboxProgress] 窗口已隐藏 (代际={})", gen);
        }
    });
}

/// 隐藏沙箱分析进度窗口（前端通过 invoke 调用，不销毁窗口）
/// ★前端不能调用 window.close()，那会销毁窗口导致第二次分析时 get_webview_window 返回 None
#[tauri::command]
fn hide_sandbox_progress_window(app_handle: tauri::AppHandle) {
    if let Some(window) = app_handle.get_webview_window("sandbox-progress") {
        win32_hide_window(&window);
        println!("[SandboxProgress] 前端请求隐藏窗口");
    }
}

/// 通过 Sandboxie Monitor API（内核驱动级 trace）收集行为事件
///
/// 使用 SbieDrv.sys 的 Monitor API 实时读取沙箱内进程的文件、注册表、网络等操作，
/// 替代旧的轮询方式（文件系统快照 diff + 网络连接轮询 + RegHive 修改检查）。
fn collect_behavior_events(controller: &mut sandbox_analysis::SandboxController, _target_file: &str) {
    use sandbox_analysis::BehaviorEvent;
    use std::time::Duration;

    let target_pid = controller.target_pid().unwrap_or(0);
    println!("[SandboxAnalysis] 开始 Monitor API 监控，目标 PID={}", target_pid);

    // 1. 收集样本进程树 PID（用于过滤 trace 条目）
    let mut sample_pids: Vec<u32> = Vec::new();
    if target_pid > 0 {
        sample_pids.push(target_pid);
        // 递归收集子进程
        fn collect_tree(root_pid: u32, pids: &mut Vec<u32>) {
            let mut to_check = vec![root_pid];
            let mut visited = std::collections::HashSet::new();
            visited.insert(root_pid);
            while let Some(pid) = to_check.pop() {
                for child_pid in get_child_processes(pid) {
                    if visited.insert(child_pid) {
                        pids.push(child_pid);
                        to_check.push(child_pid);
                    }
                }
            }
        }
        collect_tree(target_pid, &mut sample_pids);
    }
    println!("[SandboxAnalysis] 样本进程树 PIDs: {:?}", sample_pids);

    // 将所有沙箱内进程 PID 加入全局集合，供驱动通知区分沙箱内/外进程
    for &pid in &sample_pids {
        sandbox_analysis::add_sandbox_pid(pid);
    }

    // 2. 打开 Sandboxie 驱动并启用 Monitor API
    // 传入空 PID 集合以禁用 PID 过滤 — AUTOSandBox 是专用沙箱，
    // 其中所有进程都属于样本，无需按 PID 过滤。
    // 历史 bug：PID 集合在启动时固定，子进程启动后其事件被丢弃。
    let mut monitor = match sbie_api::SbieMonitor::open(Vec::new()) {
        Ok(m) => {
            println!("[SandboxAnalysis] Sandboxie Monitor API 已启用");
            crate::diag_info!("[SandboxAnalysis] Sandboxie Monitor API 已启用（内核驱动级 trace）");
            m
        }
        Err(e) => {
            println!("[SandboxAnalysis] Monitor API 启动失败: {}，回退到轮询模式", e);
            crate::diag_warn!("[SandboxAnalysis] Monitor API 启动失败: {}，回退到轮询模式", e);
            // 回退到旧的轮询方法
            collect_behavior_events_fallback(controller, _target_file);
            return;
        }
    };

    let start = std::time::Instant::now();
    // 记录已上报的子进程（补充检测）
    let mut seen_children: std::collections::HashSet<u32> = std::collections::HashSet::new();

    // 3. 监控循环（最多 60 秒）
    while start.elapsed().as_secs() < 60 {
        std::thread::sleep(Duration::from_millis(500));

        if controller.is_timed_out() {
            break;
        }

        // 3a. 从 Sandboxie Monitor API 读取 trace 条目
        let events = monitor.collect();
        for event in events {
            println!("[SandboxAnalysis] [Monitor] {:?}", event);
            controller.add_behavior_event(event);
        }

        // 3b. 补充检测：子进程树（Monitor API 可能不捕获所有进程创建事件）
        if target_pid > 0 {
            fn collect_process_tree(root_pid: u32) -> Vec<(u32, String)> {
                let mut result = Vec::new();
                let mut to_check = vec![root_pid];
                let mut visited = std::collections::HashSet::new();
                visited.insert(root_pid);

                while let Some(pid) = to_check.pop() {
                    let children = get_child_processes(pid);
                    for child_pid in children {
                        if visited.insert(child_pid) {
                            let name = get_process_name(child_pid)
                                .unwrap_or_else(|| format!("PID:{}", child_pid));
                            result.push((child_pid, name.clone()));
                            to_check.push(child_pid);
                        }
                    }
                }
                result
            }

            let all_children = collect_process_tree(target_pid);
            for (child_pid, name) in all_children {
                // 将子进程 PID 加入全局沙箱集合
                sandbox_analysis::add_sandbox_pid(child_pid);
                if seen_children.insert(child_pid) {
                    let is_suspicious = is_suspicious_process_name(&name);
                    println!("[SandboxAnalysis] 检测到子进程: {} (PID={}) suspicious={}", name, child_pid, is_suspicious);
                    controller.add_behavior_event(BehaviorEvent::ProcessCreate {
                        name,
                        is_suspicious,
                        is_elevated: false,
                    });
                }
            }

            // 子进程数量阈值检测
            let total_children = seen_children.len();
            if total_children > 2 {
                println!("[SandboxAnalysis] 子进程数量异常: {} 个", total_children);
                if total_children == 3 {
                    let parent_name = get_process_name(target_pid)
                        .unwrap_or_else(|| format!("PID:{}", target_pid));
                    controller.add_behavior_event(BehaviorEvent::ExcessiveChildProcess {
                        count: total_children as u32,
                        parent: parent_name,
                    });
                }
            }
        }

        // 3c. 检查分析引擎是否已判定为恶意（提前终止）
        let (verdict, score, _) = controller.analyze();
        if score >= 100 {
            println!("[SandboxAnalysis] 评分已达 {} (verdict={})，提前终止监控", score, verdict.label());
            break;
        }
    }

    // 4. 最后再 drain 一次，确保不遗漏
    let final_events = monitor.collect();
    for event in final_events {
        println!("[SandboxAnalysis] [Monitor-Final] {:?}", event);
        controller.add_behavior_event(event);
    }

    monitor.close();
    println!("[SandboxAnalysis] 行为事件收集完成，事件数: {}", controller.event_count());
}

/// 旧的轮询模式（回退方案）：文件系统快照 diff + 网络轮询 + RegHive 检测
fn collect_behavior_events_fallback(controller: &mut sandbox_analysis::SandboxController, _target_file: &str) {
    use sandbox_analysis::BehaviorEvent;
    use std::time::Duration;

    let box_root = get_sandboxie_box_root();
    println!("[SandboxAnalysis] [Fallback] 沙盒根目录: {:?}", box_root);

    let drive_c = box_root.as_ref().map(|r| r.join("drive").join("C"));
    let start = std::time::Instant::now();

    let base_snapshot = if let Some(ref root) = drive_c {
        if root.exists() {
            snapshot_directory(root)
        } else {
            snapshot_directory(box_root.as_ref().unwrap())
        }
    } else {
        Vec::new()
    };

    let mut seen_network: std::collections::HashSet<(String, u16)> = std::collections::HashSet::new();
    let mut seen_children: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let target_pid = controller.target_pid().unwrap_or(0);

    while start.elapsed().as_secs() < 60 {
        std::thread::sleep(Duration::from_secs(2));
        if controller.is_timed_out() { break; }

        if let Some(ref root) = drive_c {
            if root.exists() {
                let current = snapshot_directory(root);
                if !current.is_empty() {
                    analyze_file_changes(controller, &base_snapshot, &current, root);
                }
            }
        }

        if target_pid > 0 {
            let connections = get_process_network_connections(target_pid);
            for (ip, port) in connections {
                if seen_network.insert((ip.clone(), port)) {
                    controller.add_behavior_event(BehaviorEvent::NetworkConnect {
                        ip, port, is_suspicious: is_suspicious_port(port),
                    });
                }
            }
        }

        if target_pid > 0 {
            fn collect_process_tree(root_pid: u32) -> Vec<(u32, String)> {
                let mut result = Vec::new();
                let mut to_check = vec![root_pid];
                let mut visited = std::collections::HashSet::new();
                visited.insert(root_pid);
                while let Some(pid) = to_check.pop() {
                    for child_pid in get_child_processes(pid) {
                        if visited.insert(child_pid) {
                            let name = get_process_name(child_pid).unwrap_or_else(|| format!("PID:{}", child_pid));
                            result.push((child_pid, name));
                            to_check.push(child_pid);
                        }
                    }
                }
                result
            }
            let all_children = collect_process_tree(target_pid);
            for (child_pid, name) in all_children {
                if seen_children.insert(child_pid) {
                    let is_suspicious = is_suspicious_process_name(&name);
                    controller.add_behavior_event(BehaviorEvent::ProcessCreate { name, is_suspicious, is_elevated: false });
                }
            }
            if seen_children.len() > 2 && seen_children.len() == 3 {
                let parent_name = get_process_name(target_pid).unwrap_or_else(|| format!("PID:{}", target_pid));
                controller.add_behavior_event(BehaviorEvent::ExcessiveChildProcess { count: seen_children.len() as u32, parent: parent_name });
            }
        }

        if let Some(ref root) = box_root {
            let reghive = root.join("RegHive");
            if reghive.exists() {
                if let Ok(meta) = std::fs::metadata(&reghive) {
                    if let Some(mt) = meta.modified().ok() {
                        if mt.elapsed().unwrap_or(Duration::from_secs(999)).as_secs() < 5 {
                            controller.add_behavior_event(BehaviorEvent::RegModify {
                                key: "RegHive".to_string(), is_run_key: false, is_security_key: false, is_proxy_key: false,
                            });
                        }
                    }
                }
            }
        }
    }
    println!("[SandboxAnalysis] [Fallback] 行为事件收集完成，事件数: {}", controller.event_count());
}

/// 获取 Sandboxie 沙盒根目录
fn get_sandboxie_box_root() -> Option<std::path::PathBuf> {
    // 尝试通过 SbieIni.exe 查询 FileRootPath
    if let Some(sbie_ini) = sandbox_analysis::get_sbie_ini_exe() {
        let output = Command::new(&sbie_ini)
            .args(["query", "GlobalSettings", "FileRootPath"])
            .creation_flags(0x08000000)
            .output()
            .ok();

        if let Some(out) = output {
            let root = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !root.is_empty() {
                let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string());
                let expanded = root.replace("%USER%", &user);
                let box_dir = std::path::PathBuf::from(&expanded).join("AUTOSandBox");
                if box_dir.exists() {
                    return Some(box_dir);
                }
            }
        }
    }

    // 回退：尝试常见路径
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string());
    let local_app = std::env::var("LOCALAPPDATA").unwrap_or_default();

    let candidates = [
        std::path::PathBuf::from(format!(r"C:\Sandbox\{}\AUTOSandBox", user)),
        std::path::PathBuf::from(format!(r"{}\Sandbox\AUTOSandBox", local_app)),
        std::path::PathBuf::from(format!(r"C:\Sandbox\AUTOSandBox")),
    ];

    for c in &candidates {
        if c.exists() {
            return Some(c.clone());
        }
    }

    None
}

/// 获取进程的所有网络连接（TCP + UDP）
fn get_process_network_connections(pid: u32) -> Vec<(String, u16)> {
    let mut result = Vec::new();

    #[cfg(windows)]
    {
        use windows::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, GetExtendedUdpTable,
            MIB_TCPROW_OWNER_PID, MIB_UDPROW_OWNER_PID,
            TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
        };

        // TCP 连接
        unsafe {
            let mut size: u32 = 0;
            GetExtendedTcpTable(None, &mut size, false, 2, TCP_TABLE_OWNER_PID_ALL, 0);
            if size > 0 {
                let mut buf = vec![0u8; size as usize];
                let ret = GetExtendedTcpTable(
                    Some(buf.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    2,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );
                if ret == 0 {
                    let count = *(buf.as_ptr() as *const u32);
                    let table_ptr = buf.as_ptr().add(4) as *const u8;
                    let entry_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
                    for i in 0..count as usize {
                        let row_ptr = table_ptr.add(i * entry_size) as *const MIB_TCPROW_OWNER_PID;
                        let row = &*row_ptr;
                        if row.dwOwningPid == pid {
                            let port = u16::from_be(row.dwLocalPort as u16);
                            let ip = format!("{}.{}.{}.{}",
                                row.dwLocalAddr & 0xFF,
                                (row.dwLocalAddr >> 8) & 0xFF,
                                (row.dwLocalAddr >> 16) & 0xFF,
                                (row.dwLocalAddr >> 24) & 0xFF);
                            result.push((ip, port));
                        }
                    }
                }
            }
        }

        // UDP 连接
        unsafe {
            let mut size: u32 = 0;
            GetExtendedUdpTable(None, &mut size, false, 2, UDP_TABLE_OWNER_PID, 0);
            if size > 0 {
                let mut buf = vec![0u8; size as usize];
                let ret = GetExtendedUdpTable(
                    Some(buf.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    2,
                    UDP_TABLE_OWNER_PID,
                    0,
                );
                if ret == 0 {
                    let count = *(buf.as_ptr() as *const u32);
                    let table_ptr = buf.as_ptr().add(4) as *const u8;
                    let entry_size = std::mem::size_of::<MIB_UDPROW_OWNER_PID>();
                    for i in 0..count as usize {
                        let row_ptr = table_ptr.add(i * entry_size) as *const MIB_UDPROW_OWNER_PID;
                        let row = &*row_ptr;
                        if row.dwOwningPid == pid {
                            let port = u16::from_be(row.dwLocalPort as u16);
                            let ip = format!("{}.{}.{}.{}",
                                row.dwLocalAddr & 0xFF,
                                (row.dwLocalAddr >> 8) & 0xFF,
                                (row.dwLocalAddr >> 16) & 0xFF,
                                (row.dwLocalAddr >> 24) & 0xFF);
                            result.push((ip, port));
                        }
                    }
                }
            }
        }
    }

    result
}

/// 获取进程的所有子进程
fn get_child_processes(parent_pid: u32) -> Vec<u32> {
    let mut result = Vec::new();

    #[cfg(windows)]
    {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
            PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        };

        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(s) => s,
                Err(_) => return result,
            };

            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32ParentProcessID == parent_pid {
                        result.push(entry.th32ProcessID);
                    }
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(snapshot);
        }
    }

    result
}

/// 通过 PID 获取进程名
fn get_process_name(pid: u32) -> Option<String> {
    #[cfg(windows)]
    {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
            PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        };

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32ProcessID == pid {
                        let name = String::from_utf16_lossy(&entry.szExeFile);
                        let _ = windows::Win32::Foundation::CloseHandle(snapshot);
                        return Some(name.trim_end_matches('\0').to_string());
                    }
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(snapshot);
        }
    }
    None
}

/// 判断端口是否可疑
fn is_suspicious_port(port: u16) -> bool {
    matches!(port, 4444 | 4445 | 6666 | 6667 | 9999 | 1234 | 31337 | 3389 | 22 | 23 | 445 | 139)
}

/// 判断进程名是否可疑
fn is_suspicious_process_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    const SUSPICIOUS: &[&str] = &[
        "cmd", "powershell", "wscript", "cscript", "mshta", "rundll32",
        "regsvr32", "msiexec", "certutil", "bitsadmin", "schtasks",
        "netsh", "wmic", "vssadmin", "bcdedit", "shutdown",
    ];
    SUSPICIOUS.iter().any(|s| lower.contains(s))
}

/// 目录快照
fn snapshot_directory(dir: &std::path::Path) -> Vec<(String, u64)> {
    let mut files = Vec::new();
    if !dir.exists() {
        return files;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let rel = path.strip_prefix(dir).unwrap_or(&path).to_string_lossy().to_string();
            if let Ok(meta) = path.metadata() {
                files.push((rel, meta.len()));
            }
            if path.is_dir() {
                files.extend(snapshot_directory(&path).into_iter().map(|(p, s)| {
                    (format!("{}\\{}", path.file_name().unwrap_or_default().to_string_lossy(), p), s)
                }));
            }
        }
    }
    files
}

/// 分析文件变化并生成行为事件
fn analyze_file_changes(
    controller: &mut sandbox_analysis::SandboxController,
    base: &[(String, u64)],
    current: &[(String, u64)],
    _root: &std::path::Path,
) {
    use sandbox_analysis::BehaviorEvent;

    let base_map: std::collections::HashMap<&str, u64> = base.iter().map(|(p, s)| (p.as_str(), *s)).collect();
    let current_map: std::collections::HashMap<&str, u64> = current.iter().map(|(p, s)| (p.as_str(), *s)).collect();

    // 可疑释放目录（银狐木马等常见释放路径）
    // 匹配方式：路径包含以下任意片段即视为可疑目录
    let suspicious_patterns = [
        "ProgramData\\",
        "Users\\All Users\\",
        "AppData\\Roaming\\",
        "AppData\\Local\\",
        "AppData\\Local\\Temp\\",
        "Windows\\Temp\\",
        "Windows\\System32\\config\\systemprofile\\",
        "Users\\Public\\",
        "$Recycle.Bin\\",
    ];

    // 系统目录（非用户应用目录）
    let system_dirs = ["Windows\\System32", "Windows\\SysWOW64", "Program Files"];

    // 检测文件名是否为随机名称（银狐木马常见：a1b2c3d4.exe、~tmp1234.dll等）
    fn is_random_filename(path: &str) -> bool {
        let filename = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let stem = std::path::Path::new(filename)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        if stem.is_empty() {
            return false;
        }

        // 以 ~ 开头的临时文件名（如 ~tmp1234、~df39a2）
        if stem.starts_with('~') {
            return true;
        }

        // GUID式名称（如 {12345678-1234-1234-1234-123456789abc}）
        if stem.starts_with('{') && stem.ends_with('}') && stem.len() >= 36 {
            return true;
        }

        // 纯十六进制或纯数字（如 1a2b3c4d.exe、88472639.exe）
        let is_hex = stem.len() >= 6 && stem.chars().all(|c| c.is_ascii_hexdigit());

        // 哈希长度名称（MD5=32, SHA1=40, SHA256=64）
        let is_hash_len = matches!(stem.len(), 32 | 40 | 64)
            && stem.chars().all(|c| c.is_ascii_hexdigit());

        // 高随机性：字母数字混合，无明显语义（如 a1b2c3d4、x7y9z2k1）
        let alpha_count = stem.chars().filter(|c| c.is_ascii_alphabetic()).count();
        let digit_count = stem.chars().filter(|c| c.is_ascii_digit()).count();
        let is_mixed = stem.len() >= 6 && alpha_count >= 3 && digit_count >= 3;

        // 纯数字名称（如 88472639.exe）
        let is_pure_digits = stem.len() >= 6 && stem.chars().all(|c| c.is_ascii_digit());

        // 双扩展名（如 document.pdf.exe、invoice.doc.scr）
        let dot_count = stem.matches('.').count();
        let has_double_ext = dot_count >= 2;

        is_hex || is_hash_len || is_mixed || is_pure_digits || has_double_ext
    }

    // 新增文件检测
    for (path, _) in current_map.iter() {
        if !base_map.contains_key(*path) {
            let path_lower = path.to_lowercase();
            let is_executable = path_lower.ends_with(".exe")
                || path_lower.ends_with(".dll")
                || path_lower.ends_with(".scr")
                || path_lower.ends_with(".pif");
            let is_system = system_dirs.iter().any(|d| path.starts_with(d));
            let is_suspicious_dir = suspicious_patterns.iter().any(|p| path.contains(p));
            let is_random = is_random_filename(path);

            if is_executable {
                let event = if is_system {
                    // 系统目录释放可执行文件（FS-001，最高优先级）
                    println!("[SandboxAnalysis] 系统目录释放可执行文件: {}", path);
                    BehaviorEvent::FileCreate {
                        path: path.to_string(),
                        is_system_dir: true,
                        is_executable: true,
                        is_suspicious_dir: false,
                        is_random_name: is_random,
                    }
                } else if is_suspicious_dir && is_random {
                    // 可疑目录+随机名称（FS-012，银狐高置信度）
                    println!("[SandboxAnalysis] 可疑目录随机名称可执行文件: {}", path);
                    BehaviorEvent::FileCreate {
                        path: path.to_string(),
                        is_system_dir: false,
                        is_executable: true,
                        is_suspicious_dir: true,
                        is_random_name: true,
                    }
                } else if is_suspicious_dir {
                    // 可疑目录释放可执行文件（FS-010）
                    println!("[SandboxAnalysis] 可疑目录释放可执行文件: {}", path);
                    BehaviorEvent::FileCreate {
                        path: path.to_string(),
                        is_system_dir: false,
                        is_executable: true,
                        is_suspicious_dir: true,
                        is_random_name: false,
                    }
                } else if is_random {
                    // 随机名称可执行文件（FS-011）
                    println!("[SandboxAnalysis] 随机名称可执行文件: {}", path);
                    BehaviorEvent::FileCreate {
                        path: path.to_string(),
                        is_system_dir: false,
                        is_executable: true,
                        is_suspicious_dir: false,
                        is_random_name: true,
                    }
                } else {
                    continue;
                };
                controller.add_behavior_event(event);
            }
        }
    }

    // 修改文件
    for (path, size) in current_map.iter() {
        if let Some(base_size) = base_map.get(*path) {
            if size != base_size {
                let is_system = system_dirs.iter().any(|d| path.starts_with(d));
                if is_system {
                    controller.add_behavior_event(BehaviorEvent::FileModify {
                        path: path.to_string(),
                        is_system_file: true,
                    });
                }
            }
        }
    }

    // 删除文件
    let deleted: Vec<_> = base_map.keys().filter(|p| !current_map.contains_key(**p)).collect();
    if !deleted.is_empty() {
        controller.add_behavior_event(BehaviorEvent::FileBatchDelete {
            count: deleted.len() as u32,
        });
    }
}

/// 处理来自新 KMDF 驱动的通知
/// 在 Tauri 事件监听器中调用，根据通知类型执行扫描/弹窗/自动决策
#[cfg(not(feature = "ms_store"))]
fn handle_av_driver_notification(app_handle: &tauri::AppHandle, notification: &av_driver_client::AvNotification) {
    use av_driver_client::*;

    match notification {
        AvNotification::Process(n) => {
            println!("[AvDriver] Process notify: PID={} path={} reason={}", n.process_id, n.image_path, n.block_reason);
            let process_name = std::path::Path::new(&n.image_path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("未知进程")
                .to_string();

            // ★AVIC 云端信誉库查询（最高优先级，先于所有白名单）★
            // 历史 bug：沙箱白名单/路径白名单检查在 AVIC 之前且直接放行，
            // 导致 AVIC 情报中心已有恶意记录的文件，只要进过沙箱白名单
            // 或用户信任路径，就永远绕过云端检测，防护不拦截。
            // 云端已知威胁必须优先拦截：DENY 进程 + 弹窗询问用户，不进沙箱。
            if let Some((threat_name, _family)) = avic_client::check_file(&n.image_path) {
                println!("[AvDriver] AVIC 命中恶意（前置检查），拦截并询问用户: {} threat={}", n.image_path, threat_name);

                let silent = get_silent_mode_enabled();
                let notification_mode = NOTIFICATION_MODE_ENABLED.load(Ordering::SeqCst);

                if silent {
                    // 静默模式：无弹窗无通知，直接 DENY
                    let _ = send_av_decision(AvDecision::Process {
                        notification_id: n.notification_id,
                        decision: AV_DECISION_DENY_ONCE,
                        image_path: n.image_path.clone(),
                    });
                } else if notification_mode {
                    // 通知模式：直接 DENY + 系统通知（无交互弹窗）
                    let _ = send_av_decision(AvDecision::Process {
                        notification_id: n.notification_id,
                        decision: AV_DECISION_DENY_ONCE,
                        image_path: n.image_path.clone(),
                    });
                    let notify_options = notification::NotificationOptions::new(
                        notification::NotificationType::Block,
                        "AVIC 云端拦截",
                        &format!("威胁: {} (AVIC 云端信誉库)", threat_name),
                    )
                    .with_source(notification::NotificationSource::Basic)
                    .with_file(&process_name, &n.image_path);
                    let _ = notification::show_security_notification(app_handle, notify_options);
                } else {
                    // ★弹窗模式：不预先 DENY★
                    // 历史 bug：先 send_av_decision(DENY) 再弹窗询问，进程已被终止，
                    // 用户点"允许"完全无效（表现为"怎么点都拒绝"）。
                    // 现在进程保持驱动挂起状态，由用户决策决定去留；
                    // 超时未决策默认 DENY（AVIC 云端已知恶意，绝不默认放行）。
                    let pending_key = n.notification_id.to_string();
                    let threat_info = format!("威胁: {} (AVIC 云端信誉库)", threat_name);
                    {
                        let mut pending = AV_DRIVER_PENDING.lock().unwrap();
                        pending.insert(pending_key.clone(), AvDriverPendingInfo {
                            notification_type: "process".to_string(),
                            notification_id: n.notification_id,
                            image_path: n.image_path.clone(),
                            process_name: process_name.clone(),
                            default_block: true,
                        });
                    }
                    {
                        let mut info_map = INTERCEPT_INFO_MAP.lock().unwrap();
                        info_map.insert(pending_key.clone(), (process_name.clone(), threat_name.clone()));
                    }
                    show_intercept_window_internal(
                        app_handle, "进程拦截", &process_name, &n.image_path, &pending_key, &threat_info,
                        true,
                    );
                }

                // 3. 上报前端事件（即使静默模式也记录）
                let _ = app_handle.emit("driver-process-blocked", serde_json::json!({
                    "process": process_name,
                    "threat": threat_name,
                    "path": n.image_path,
                    "source": "AVIC",
                }));
                return;
            }

            // ★白名单先行校验（v2）★
            // 决策完全由主程序处理：白名单中的进程/驱动，主程序直接 ALLOW_ONCE，
            // 跳过沙箱、扫描、深度分析等一切后续防护检查。
            // 匹配维度：路径白名单（前缀匹配）+ 进程名白名单（从 image_path 提取文件名）。
            // 位置保持在 AVIC 云端信誉库之后，云端已知威胁优先拦截（历史 bug 修复）。
            if crate::whitelist::is_path_whitelisted(&n.image_path) {
                println!("[AvDriver] Whitelisted, auto-allow: {}", n.image_path);
                let _ = send_av_decision(AvDecision::Process {
                    notification_id: n.notification_id,
                    decision: AV_DECISION_ALLOW_ONCE,
                    image_path: n.image_path.clone(),
                });
                return;
            }

            // 沙盒分析进行中时，只放行沙箱内启动的进程（及其子进程）
            // 非沙箱进程仍然走正常的扫描/拦截逻辑，不会被直接放行
            if sandbox_analysis::is_analyzing() {
                let pid = n.process_id;
                let ppid = n.parent_process_id;
                // ★最近放行进程（Benign 判定后重新启动的原始文件）直接放行★
                if sandbox_analysis::is_recently_launched(pid) {
                    println!("[AvDriver] Recently launched, auto-allow: {} (PID={})", n.image_path, pid);
                    let _ = send_av_decision(AvDecision::Process {
                        notification_id: n.notification_id,
                        decision: AV_DECISION_ALLOW_ONCE,
                        image_path: n.image_path.clone(),
                    });
                    return;
                }
                // 检查进程自身、父进程是否在沙箱 PID 集合中，或路径是否在沙箱目录内
                // ★路径判断★：沙箱内真实进程（即使尚未加入 PID 集合）也必须放行，
                // 否则沙箱目标进程/子进程会被当"非沙箱进程"扫描，未签名文件被拦截。
                if sandbox_analysis::is_sandbox_pid(pid) || sandbox_analysis::is_sandbox_pid(ppid)
                    || sandbox_analysis::is_path_in_sandbox(&n.image_path)
                {
                    // 沙箱内进程，放行并记录 PID（子进程也会被记录）
                    sandbox_analysis::add_sandbox_pid(pid);
                    println!("[AvDriver] Sandbox internal process, auto-allow: {} (PID={}, PPID={})", n.image_path, pid, ppid);
                    let _ = send_av_decision(AvDecision::Process {
                        notification_id: n.notification_id,
                        decision: AV_DECISION_ALLOW_ONCE,
                        image_path: n.image_path.clone(),
                    });
                    return;
                }
                // ★同名进程兜底★：沙箱内主进程的 image path 可能是原始路径
                // （Sandboxie 对部分目录直接访问，路径不重定向，日志中
                // `\??\C:\Users\...\Downloads\Xxx.exe` 实为沙箱内进程）。
                // 若进程名与当前分析目标同名且不是"最近放行"的普通进程，
                // 视为沙箱内进程放行并记录，避免被当"非沙箱进程"拦截。
                {
                    let is_same_name = sandbox_analysis::get_pending_file()
                        .and_then(|p| std::path::Path::new(&p).file_name().map(|n| n.to_string_lossy().into_owned()))
                        .map(|target| target.eq_ignore_ascii_case(&process_name))
                        .unwrap_or(false);
                    // ★路径级防线★：最近分析完成的原始文件路径直接放行（含子进程）
                    if sandbox_analysis::is_recently_analyzed_path(&n.image_path) {
                        println!("[AvDriver] Recently analyzed path, auto-allow: {} (PID={})", n.image_path, pid);
                        let _ = send_av_decision(AvDecision::Process {
                            notification_id: n.notification_id,
                            decision: AV_DECISION_ALLOW_ONCE,
                            image_path: n.image_path.clone(),
                        });
                        return;
                    }
                    if is_same_name && !sandbox_analysis::is_recently_launched(pid) {
                        sandbox_analysis::add_sandbox_pid(pid);
                        println!("[AvDriver] Sandbox same-name process, auto-allow: {} (PID={})", n.image_path, pid);
                        let _ = send_av_decision(AvDecision::Process {
                            notification_id: n.notification_id,
                            decision: AV_DECISION_ALLOW_ONCE,
                            image_path: n.image_path.clone(),
                        });
                        return;
                    }
                }
                // 非沙箱进程：不直接放行，继续走下面的正常逻辑
                println!("[AvDriver] Sandbox analyzing but process is NOT in sandbox, normal scan: {} (PID={})", n.image_path, pid);
            }

            // 沙盒分析白名单：之前分析过且安全的文件，自动放行
            if sandbox_analysis::is_analysis_enabled()
                && sandbox_analysis::is_image_whitelisted(&n.image_path)
            {
                println!("[AvDriver] File in sandbox whitelist, auto-allow: {}", n.image_path);
                let _ = send_av_decision(AvDecision::Process {
                    notification_id: n.notification_id,
                    decision: AV_DECISION_ALLOW_ONCE,
                    image_path: n.image_path.clone(),
                });
                return;
            }

            // 沙盒分析触发检测：拦截 TEMP\XIGUASandbox\Sandbox.exe 触发自动分析
            // ★传完整路径★：is_sandbox_trigger_process 内部校验路径，
            // 防止用户自己的同名文件（如 Downloads\sandbox.exe）被误判为触发器
            if sandbox_analysis::is_analysis_enabled()
                && sandbox_analysis::is_sandbox_trigger_process(&n.image_path)
            {
                println!("[AvDriver] Sandbox trigger detected, blocking and analyzing: {}", n.image_path);
                let _ = send_av_decision(AvDecision::Process {
                    notification_id: n.notification_id,
                    decision: AV_DECISION_DENY_ONCE,
                    image_path: n.image_path.clone(),
                });
                let app = app_handle.clone();
                let raw_file = get_pending_analysis_file().unwrap_or_else(|| n.image_path.clone());
                let original_file = raw_file.strip_prefix("\\??\\").unwrap_or(&raw_file).to_string();
                std::thread::spawn(move || {
                    handle_sandbox_analysis(&app, &original_file);
                });
                return;
            }

            // ★沙箱拦截检查：在 AV 扫描之前检查文件是否需要沙箱分析★
            // 驱动通知是进程启动前的防线：如果文件未签名且在监控目录中，
            // 直接 DENY 进程启动（进程根本不会启动），然后触发沙箱分析。
            // 这样无需 taskkill/AVModel 终止——进程从未启动。
            // 历史 bug：此处缺少沙箱检查，驱动只做 AV 扫描就放行，
            // 导致未签名的恶意安装包被放行后由 R3 monitor 延迟 ~1 分钟才拦截。
            if sandbox_analysis::is_analysis_enabled()
                && sandbox_analysis::should_intercept_for_sandbox(&n.image_path, n.process_id)
            {
                // 注意：AVIC 恶意文件已由前置检查（上方 AVIC 云端信誉库查询）拦截并
                // DENY+弹窗询问，走不到这里。此处只处理"未知文件进沙箱分析"。
                println!("[AvDriver] Sandbox intercept (unsigned file in watched dir), denying: {} (PID={})",
                    n.image_path, n.process_id);

                // 拒绝进程启动 — 进程不会启动，无需后续终止
                let _ = send_av_decision(AvDecision::Process {
                    notification_id: n.notification_id,
                    decision: AV_DECISION_DENY_ONCE,
                    image_path: n.image_path.clone(),
                });

                // 异步触发沙箱分析（不阻塞驱动通知线程）
                let app = app_handle.clone();
                let path = n.image_path.strip_prefix("\\??\\").unwrap_or(&n.image_path).to_string();
                std::thread::spawn(move || {
                    sandbox_analysis::set_pending_file(&path);
                    handle_sandbox_analysis(&app, &path);
                });
                return;
            }

            // 同步扫描（与 AVMain 一致：当前线程处理完才读下一条通知）。
            // 历史 bug：spawn 独立线程扫描，导致扫描/弹窗/决策与通知接收解耦，
            // 引发"通知堆积读不到、决策无人消费、并发竞态静默放行"等问题。
            do_av_process_scan(app_handle, n);
        }

        AvNotification::Registry(n) => {
            println!("[AvDriver] Registry notify: PID={} key={}", n.process_id, n.key_path);
            let process_name = format!("PID: {}", n.process_id);
            let op_desc = match n.operation_type {
                1 => "写入值",
                2 => "删除值",
                3 => "删除键",
                4 => "创建键",
                _ => "注册表操作",
            };
            // 用户态 always 规则检查（仅内存，重启后清空）
            if let Some(rule) = check_always_rule("registry", &n.key_path) {
                let dec = if rule == "block" { AV_DECISION_DENY_ONCE } else { AV_DECISION_ALLOW_ONCE };
                println!("[AvDriver] Always-rule {} registry: {}", rule, n.key_path);
                let _ = send_av_decision(AvDecision::Registry {
                    notification_id: n.notification_id,
                    decision: dec,
                    key_path: n.key_path.clone(),
                });
                return;
            }
            let pending_key = n.notification_id.to_string();
            {
                let mut pending = AV_DRIVER_PENDING.lock().unwrap();
                pending.insert(pending_key.clone(), AvDriverPendingInfo {
                    notification_type: "registry".to_string(),
                    notification_id: n.notification_id,
                    image_path: n.key_path.clone(),
                    process_name: process_name.clone(),
                    default_block: false,
                });
            }
            show_intercept_window_internal(
                app_handle, "注册表拦截", &process_name, &n.key_path, &pending_key,
                &format!("操作: {}", op_desc),
                false,
            );
        }

        AvNotification::Injection(n) => {
            println!("[AvDriver] Injection notify: src={} tgt={}", n.source_process_id, n.target_process_id);
            let process_name = format!("PID: {} → PID: {}", n.source_process_id, n.target_process_id);
            // 用户态 always 规则检查（仅内存，重启后清空）
            if let Some(rule) = check_always_rule("injection", &n.source_image_path) {
                let dec = if rule == "block" { AV_DECISION_DENY_ONCE } else { AV_DECISION_ALLOW_ONCE };
                println!("[AvDriver] Always-rule {} injection: {}", rule, n.source_image_path);
                let _ = send_av_decision(AvDecision::Injection {
                    notification_id: n.notification_id,
                    decision: dec,
                });
                return;
            }
            let pending_key = n.notification_id.to_string();
            {
                let mut pending = AV_DRIVER_PENDING.lock().unwrap();
                pending.insert(pending_key.clone(), AvDriverPendingInfo {
                    notification_type: "injection".to_string(),
                    notification_id: n.notification_id,
                    image_path: n.source_image_path.clone(),
                    process_name: process_name.clone(),
                    default_block: false,
                });
            }
            show_intercept_window_internal(
                app_handle, "可疑行为拦截", &process_name, &n.source_image_path, &pending_key,
                &format!("目标PID: {} 线程ID: {} 起始地址: 0x{:X}", n.target_process_id, n.thread_id, n.start_address),
                false,
            );
        }

        AvNotification::Ransom(n) => {
            println!("[AvDriver] Ransom notify: {} files affected, ID={}", n.file_count, n.notification_id);
            let process_name = "勒索软件防护";
            let file_summary = if n.files.is_empty() {
                format!("共 {} 个文件受影响", n.file_count)
            } else {
                let first = &n.files[0];
                format!("共 {} 个文件受影响\n示例: {}", n.file_count, first.original_path)
            };
            let pending_key = n.notification_id.to_string();
            {
                let mut pending = AV_DRIVER_PENDING.lock().unwrap();
                pending.insert(pending_key.clone(), AvDriverPendingInfo {
                    notification_type: "ransom".to_string(),
                    notification_id: n.notification_id,
                    image_path: String::new(),
                    process_name: process_name.to_string(),
                    default_block: false,
                });
            }
            show_intercept_window_internal(
                app_handle, "勒索软件拦截", process_name, &file_summary, &pending_key,
                &format!("通知ID: {}", n.notification_id),
                false,
            );
        }

        AvNotification::EndPoint(n) => {
            println!("[AvDriver] EndPoint notify: PID={} score={} rules={}", n.process_id, n.total_score, n.rule_count);
            let process_name = std::path::Path::new(&n.image_path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("未知进程")
                .to_string();

            // 用户态 always 规则检查（仅内存，重启后清空）
            if let Some(rule) = check_always_rule("endpoint", &n.image_path) {
                let dec = if rule == "block" { XGS_EP_DECISION_KILL } else { XGS_EP_DECISION_ALLOW };
                println!("[AvDriver] Always-rule {} endpoint: {}", rule, n.image_path);
                let _ = send_av_decision(AvDecision::EndPoint {
                    notification_id: n.notification_id,
                    decision: dec,
                });
                return;
            }

            // EDR 通知需要用户决策：允许或终止
            let pending_key = n.notification_id.to_string();
            {
                let mut pending = AV_DRIVER_PENDING.lock().unwrap();
                pending.insert(pending_key.clone(), AvDriverPendingInfo {
                    notification_type: "endpoint".to_string(),
                    notification_id: n.notification_id,
                    image_path: n.image_path.clone(),
                    process_name: process_name.clone(),
                    default_block: false,
                });
            }

            // 构建规则命中描述
            let rule_desc: String = n.rules.iter()
                .map(|r| format!("{} (+{}分)", r.description, r.score))
                .collect::<Vec<_>>()
                .join("\n");

            // 弹出 EndPoint 威胁拦截窗口（使用拦截窗口，而非旧的自动终止告警）
            show_intercept_window_internal(
                app_handle, "可疑行为拦截", &process_name, &n.image_path, &pending_key,
                &format!("威胁评分: {}\n命中规则:\n{}", n.total_score, rule_desc),
                false,
            );
        }

        AvNotification::Error { code, message } => {
            println!("[AvDriver] Error from AVSystem: {} - {}", code, message);
        }

        AvNotification::InjectGuard(n) => {
            println!("[AvDriver] InjectGuard notify: src={}({}) -> tgt={}({}), type={}, seq={}",
                     n.source_pid, n.source_process_name,
                     n.target_pid, n.target_process_name,
                     n.event_type, n.sequence_id);

            let src_name = if n.source_process_name.is_empty() {
                format!("PID={}", n.source_pid)
            } else {
                n.source_process_name.clone()
            };
            let tgt_name = if n.target_process_name.is_empty() {
                format!("PID={}", n.target_pid)
            } else {
                n.target_process_name.clone()
            };

            let image_path = format!("{} -> {}", src_name, tgt_name);

            if let Some(rule) = check_always_rule("injectguard", &image_path) {
                let dec = if rule == "block" { IG_DECISION_BLOCK } else { IG_DECISION_ALLOW };
                println!("[AvDriver] Always-rule {} injectguard: {}", rule, image_path);
                let _ = send_av_decision(AvDecision::InjectGuard {
                    sequence_id: n.sequence_id,
                    decision: dec,
                });
                return;
            }

            let pending_key = n.sequence_id.to_string();
            {
                let mut pending = AV_DRIVER_PENDING.lock().unwrap();
                pending.insert(pending_key.clone(), AvDriverPendingInfo {
                    notification_type: "injectguard".to_string(),
                    notification_id: n.sequence_id as u64,
                    image_path: image_path.clone(),
                    process_name: src_name.clone(),
                    default_block: false,
                });
            }

            let chain_desc: String = n.chain_steps.iter()
                .map(|s| match *s {
                    1 => "OpenProcess".to_string(),
                    2 => "VirtualAllocEx".to_string(),
                    3 => "WriteProcessMemory".to_string(),
                    4 => "CreateRemoteThread".to_string(),
                    5 => "SectionCreate".to_string(),
                    6 => "SectionMap".to_string(),
                    7 => "SuspendThread".to_string(),
                    8 => "SetThreadContext".to_string(),
                    9 => "ResumeThread".to_string(),
                    _ => format!("Step{}", s),
                })
                .collect::<Vec<_>>()
                .join(" → ");

            show_intercept_window_internal(
                app_handle, "注入攻击拦截", &src_name, &image_path, &pending_key,
                &format!("检测到进程注入链:\n{} → {}\n注入链: {}\n目标 PID: {}\n源 PID: {}",
                         src_name, tgt_name, chain_desc, n.target_pid, n.source_pid),
                false,
            );
        }
    }
}

/// 对新驱动拦截的进程执行扫描，并根据结果自动决策或弹窗
#[cfg(not(feature = "ms_store"))]
fn do_av_process_scan(app_handle: &tauri::AppHandle, n: &av_driver_client::ProcessNotifyData) {
    use av_driver_client::*;
    use scanner::SCANNER;
    use scanner::SKIP_FAMILY_ANALYSIS;

    // 用户态 always 规则检查：命中"始终拦截/始终允许"直接决策，不弹窗、不扫描
    // （这些规则仅存在于 R3 内存中，应用重启后清空，不会写入驱动的常驻 DenyList）
    if let Some(rule) = check_always_rule("process", &n.image_path) {
        if rule == "block" {
            println!("[AvDriver] Always-rule BLOCK: {}", n.image_path);
            let _ = send_av_decision(AvDecision::Process {
                notification_id: n.notification_id,
                decision: AV_DECISION_DENY_ONCE,
                image_path: n.image_path.clone(),
            });
            let _ = app_handle.emit("driver-process-blocked", serde_json::json!({
                "process": std::path::Path::new(&n.image_path).file_name().and_then(|s| s.to_str()).unwrap_or(""),
                "threat": "AlwaysRule",
                "path": n.image_path,
            }));
        } else {
            println!("[AvDriver] Always-rule ALLOW: {}", n.image_path);
            let _ = send_av_decision(AvDecision::Process {
                notification_id: n.notification_id,
                decision: AV_DECISION_ALLOW_ONCE,
                image_path: n.image_path.clone(),
            });
        }
        return;
    }

    // ── AVIC 云端信誉库查询（最高优先级，在本地引擎扫描之前）──
    // 命中已知恶意哈希则直接拦截，跳过本地引擎扫描和并发限制（零误报、低延迟）
    if let Some((threat_name, _family)) = avic_client::check_file(&n.image_path) {
        let process_name = std::path::Path::new(&n.image_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("未知进程")
            .to_string();

        println!(
            "[AvDriver] AVIC 命中恶意，直接拦截: {} threat={}",
            process_name, threat_name
        );

        let silent = get_silent_mode_enabled();
        let notification_mode = NOTIFICATION_MODE_ENABLED.load(Ordering::SeqCst);

        if silent {
            // 静默模式：无弹窗无通知，直接 DENY
            let _ = send_av_decision(AvDecision::Process {
                notification_id: n.notification_id,
                decision: AV_DECISION_DENY_ONCE,
                image_path: n.image_path.clone(),
            });
        } else if notification_mode {
            // 通知模式：直接 DENY + 系统通知
            let _ = send_av_decision(AvDecision::Process {
                notification_id: n.notification_id,
                decision: AV_DECISION_DENY_ONCE,
                image_path: n.image_path.clone(),
            });
            let notify_options = notification::NotificationOptions::new(
                notification::NotificationType::Block,
                "AVIC 云端拦截",
                &format!("威胁: {} (AVIC 云端信誉库)", threat_name),
            )
            .with_source(notification::NotificationSource::Basic)
            .with_file(&process_name, &n.image_path);
            let _ = notification::show_security_notification(app_handle, notify_options);
        } else {
            // ★弹窗模式：不预先 DENY★（历史 bug：先 DENY 后弹窗，点"允许"无效）
            // 进程保持驱动挂起状态，由用户决策决定去留；超时默认 DENY。
            let pending_key = n.notification_id.to_string();
            let threat_info = format!("威胁: {} (AVIC 云端信誉库)", threat_name);
            {
                let mut pending = AV_DRIVER_PENDING.lock().unwrap();
                pending.insert(pending_key.clone(), AvDriverPendingInfo {
                    notification_type: "process".to_string(),
                    notification_id: n.notification_id,
                    image_path: n.image_path.clone(),
                    process_name: process_name.clone(),
                    default_block: true,
                });
            }
            {
                let mut info_map = INTERCEPT_INFO_MAP.lock().unwrap();
                info_map.insert(pending_key.clone(), (process_name.clone(), threat_name.clone()));
            }
            show_intercept_window_internal(
                app_handle, "进程拦截", &process_name, &n.image_path, &pending_key, &threat_info,
                true,
            );
        }

        let _ = app_handle.emit("driver-process-blocked", serde_json::json!({
            "process": process_name,
            "threat": threat_name,
            "path": n.image_path,
            "source": "AVIC",
        }));
        return;
    }

    // 并发扫描限制：限制同时扫描数量以控制 CPU，但绝不因队列满而静默放行。
    // 历史 bug：等待 6 秒后 auto-allow，驱动全拦截模式下并发启动多个进程时
    // 频繁触发，导致病毒进程"扫描都没扫就直接放行"。现在超时后继续扫描。
    const MAX_CONCURRENT_SCANS: u32 = 4;
    const MAX_WAIT_MS: u64 = 8000;
    const POLL_INTERVAL_MS: u64 = 200;
    let mut waited_ms: u64 = 0;
    let mut acquired_slot = false;
    loop {
        let current = CONCURRENT_SCANS.fetch_add(1, Ordering::SeqCst);
        if current < MAX_CONCURRENT_SCANS {
            acquired_slot = true;
            break;
        }
        CONCURRENT_SCANS.fetch_sub(1, Ordering::SeqCst);
        waited_ms += POLL_INTERVAL_MS;
        if waited_ms >= MAX_WAIT_MS {
            // 队列满且等待超时：继续扫描（可能短暂超限），但不放行病毒
            println!("[AvDriver] Scan queue full after {}ms, scanning anyway: {}", MAX_WAIT_MS, n.image_path);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS));
    }

    SKIP_FAMILY_ANALYSIS.store(true, std::sync::atomic::Ordering::Relaxed);

    // 使用 read() 阻塞等待读锁（写锁通常仅在模型加载时短暂持有）。
    // 不要用 try_read()：驱动全拦截模式下多个进程并发扫描时，
    // try_read 在写锁持有瞬间返回 Err，导致静默放行病毒而不扫描不弹窗。
    // 这里只等待锁，不增加扫描并发；真正的并发上限由 CONCURRENT_SCANS 控制。
    let scan_result = match SCANNER.read() {
        Ok(s) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            s.scan_file(&n.image_path, None)
        })) {
            Ok(r) => r,
            Err(_) => {
                SKIP_FAMILY_ANALYSIS.store(false, std::sync::atomic::Ordering::Relaxed);
                if acquired_slot {
                    CONCURRENT_SCANS.fetch_sub(1, Ordering::SeqCst);
                }
                let _ = send_av_decision(AvDecision::Process {
                    notification_id: n.notification_id,
                    decision: AV_DECISION_ALLOW_ONCE,
                    image_path: n.image_path.clone(),
                });
                return;
            }
        },
        Err(e) => {
            eprintln!("[AvDriver] Scanner lock poisoned: {}", e);
            SKIP_FAMILY_ANALYSIS.store(false, std::sync::atomic::Ordering::Relaxed);
            if acquired_slot {
                CONCURRENT_SCANS.fetch_sub(1, Ordering::SeqCst);
            }
            let _ = send_av_decision(AvDecision::Process {
                notification_id: n.notification_id,
                decision: AV_DECISION_ALLOW_ONCE,
                image_path: n.image_path.clone(),
            });
            return;
        }
    };

    SKIP_FAMILY_ANALYSIS.store(false, std::sync::atomic::Ordering::Relaxed);
    if acquired_slot {
        CONCURRENT_SCANS.fetch_sub(1, Ordering::SeqCst);
    }

    let is_threat = scan_result.result == "MALICIOUS";
    let is_installer = scan_result.result == "INSTALLER";
    let probability = scan_result.probability;
    let family = scan_result.virus_family.unwrap_or_default();

    let process_name = std::path::Path::new(&n.image_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("未知进程")
        .to_string();

    println!("[AvDriver] Scan: result={} prob={:.3} family={}", scan_result.result, probability, family);

    let silent = get_silent_mode_enabled();
    let pending_key = n.notification_id.to_string();

    if is_threat {
        println!("[AvDriver] THREAT: {} silent={}", family, silent);

        if silent {
            // 静默模式 → 直接拦截
            let _ = send_av_decision(AvDecision::Process {
                notification_id: n.notification_id,
                decision: AV_DECISION_DENY_ONCE,
                image_path: n.image_path.clone(),
            });
            let _ = app_handle.emit("driver-process-blocked", serde_json::json!({
                "process": process_name,
                "threat": family,
                "path": n.image_path,
            }));
        } else {
            // 弹出拦截窗口
            {
                let mut pending = AV_DRIVER_PENDING.lock().unwrap();
                pending.insert(pending_key.clone(), AvDriverPendingInfo {
                    notification_type: "process".to_string(),
                    notification_id: n.notification_id,
                    image_path: n.image_path.clone(),
                    process_name: process_name.clone(),
                    default_block: false,
                });
            }
            // 同时保存进程信息供事件发射使用
            {
                let mut info_map = INTERCEPT_INFO_MAP.lock().unwrap();
                info_map.insert(pending_key.clone(), (process_name.clone(), family.clone()));
            }

            let threat_info = format!("威胁: {} (概率: {:.1}%)", family, probability * 100.0);

            if NOTIFICATION_MODE_ENABLED.load(Ordering::SeqCst) {
                // 通知模式：直接拦截 + 系统通知
                let _ = send_av_decision(AvDecision::Process {
                    notification_id: n.notification_id,
                    decision: AV_DECISION_DENY_ONCE,
                    image_path: n.image_path.clone(),
                });
                let notify_options = notification::NotificationOptions::new(
                    notification::NotificationType::Block,
                    "驱动防护拦截",
                    &threat_info,
                )
                .with_source(notification::NotificationSource::Basic)
                .with_file(&process_name, &n.image_path);
                let _ = notification::show_security_notification(app_handle, notify_options);
            } else {
                show_intercept_window_internal(
                    app_handle, "进程拦截", &process_name, &n.image_path, &pending_key, &threat_info,
                    false,
                );
            }
        }
    } else if is_installer || probability <= 0.85 {
        // 本地模型未检出威胁 → 先放行进程，再在后台线程进行云端深度分析
        // ★卡死修复：原来此处 block_on 等待云端沙箱分析（120-180s），
        // 直接阻塞驱动通知线程（= 消息循环/主线程），导致整个 UI 卡死无响应。
        // 现在先放行进程（不阻塞通知循环），深度分析移入独立线程，
        // 检出恶意后通过事件回调终止进程并提示用户。
        let _ = send_av_decision(AvDecision::Process {
            notification_id: n.notification_id,
            decision: AV_DECISION_ALLOW_ONCE,
            image_path: n.image_path.clone(),
        });

        if get_cloud_deep_analysis_enabled() {
            let score = deep_analysis::calculate_suspicion_score(&n.image_path);
            if score.should_deep_analyze {
                println!("[AvDriver] Deep analysis triggered: score={} for {}", score.total, n.image_path);
                let _ = app_handle.emit("deep-analysis-start", serde_json::json!({
                    "filePath": n.image_path,
                    "score": score.total,
                    "reasons": score.reasons,
                }));

                // 独立线程执行深度分析（不阻塞通知/主线程）
                let app_for_analysis = app_handle.clone();
                let path_for_analysis = n.image_path.clone();
                let proc_name_clone = process_name.clone();
                let proc_pid = n.process_id;
                let notif_id = n.notification_id;
                std::thread::spawn(move || {
                    let app_clone = app_for_analysis.clone();
                    let path_clone = path_for_analysis.clone();
                    let deep_result = tauri::async_runtime::block_on(async move {
                        deep_analysis::run_deep_analysis(&app_for_analysis, &path_for_analysis).await
                    });

                    match deep_result {
                        Ok(da_result) => {
                            println!("[AvDriver] Deep analysis: verdict={} score={} family={} malicious={}",
                                da_result.sandbox_verdict, da_result.threat_score, da_result.threat_family, da_result.malicious);
                            let _ = app_clone.emit("deep-analysis-done", serde_json::json!({
                                "verdict": da_result.sandbox_verdict,
                                "threatScore": da_result.threat_score,
                                "threatFamily": da_result.threat_family,
                                "malicious": da_result.malicious,
                                "iocs": da_result.iocs,
                            }));
                            if da_result.malicious {
                                let deep_family = if !da_result.threat_family.is_empty() {
                                    da_result.threat_family.clone()
                                } else {
                                    format!("Sandbox:{}", da_result.sandbox_verdict)
                                };
                                let deep_confidence = (da_result.threat_score as f64 / 100.0).min(1.0);
                                let threat_info = format!("威胁: {} (概率: {:.1}%)", deep_family, deep_confidence * 100.0);
                                let silent = get_silent_mode_enabled();

                                // 尝试终止已放行的恶意进程（通过 AVModel 按 PID 杀）
                                if proc_pid > 0 {
                                    kill_process_via_avmodel(proc_pid);
                                }

                                if silent {
                                    let _ = app_clone.emit("driver-process-blocked", serde_json::json!({
                                        "process": proc_name_clone,
                                        "threat": deep_family,
                                        "path": path_clone,
                                        "source": "deep_analysis",
                                    }));
                                } else {
                                    {
                                        let mut pending = AV_DRIVER_PENDING.lock().unwrap();
                                        pending.insert(notif_id.to_string(), AvDriverPendingInfo {
                                            notification_type: "process".to_string(),
                                            notification_id: notif_id,
                                            image_path: path_clone.clone(),
                                            process_name: proc_name_clone.clone(),
                                            default_block: false,
                                        });
                                    }
                                    {
                                        let mut info_map = INTERCEPT_INFO_MAP.lock().unwrap();
                                        info_map.insert(notif_id.to_string(), (proc_name_clone.clone(), deep_family.clone()));
                                    }
                                    if NOTIFICATION_MODE_ENABLED.load(Ordering::SeqCst) {
                                        let notify_options = notification::NotificationOptions::new(
                                            notification::NotificationType::Block,
                                            "驱动防护拦截",
                                            &threat_info,
                                        )
                                        .with_source(notification::NotificationSource::Basic)
                                        .with_file(&proc_name_clone, &path_clone);
                                        let _ = notification::show_security_notification(&app_clone, notify_options);
                                    } else {
                                        show_intercept_window_internal(
                                            &app_clone, "进程拦截", &proc_name_clone, &path_clone,
                                            &notif_id.to_string(), &threat_info,
                                            false,
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[AvDriver] Deep analysis failed: {}", e);
                            let _ = app_clone.emit("deep-analysis-error", serde_json::json!({
                                "error": e.to_string(),
                            }));
                        }
                    }
                });
            }
        }
    } else {
        // 可疑 → 自动拦截
        println!("[AvDriver] Suspicious, auto-block: {}", process_name);
        let _ = send_av_decision(AvDecision::Process {
            notification_id: n.notification_id,
            decision: AV_DECISION_DENY_ONCE,
            image_path: n.image_path.clone(),
        });
        let _ = app_handle.emit("driver-process-blocked", serde_json::json!({
            "process": process_name,
            "threat": "Suspicious",
            "path": n.image_path,
        }));
    }
}

/// 发送新驱动拦截决策（前端调用）
/// pending_key = notification_id 的字符串形式
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn send_av_driver_decision(
    app: tauri::AppHandle,
    pending_key: String,
    decision: String,
) -> Result<(), String> {
    use av_driver_client::*;

    println!("[SendAvDriverDecision] Called: pending_key={} decision={}", pending_key, decision);

    // 从待处理表中查找通知信息
    let info = {
        let mut pending = AV_DRIVER_PENDING.lock().unwrap();
        pending.remove(&pending_key)
    };

    // 兜底：pending 不存在时（已被超时/其他路径消费，或键不匹配），
    // 绝不返回错误——按钮必须始终有效！从 pending_key 解析 notification_id
    // 构造兜底决策，让被拦截进程立即得到响应，避免永久挂起。
    let info = match info {
        Some(i) => i,
        None => {
            eprintln!("[SendAvDriverDecision] Notification not found for key: {} (fallback direct send)", pending_key);
            // 解析 notification_id（pending_key 就是其字符串形式）
            let notification_id = pending_key.parse::<u64>().unwrap_or(0);
            // 构造兜底信息：类型未知时按进程处理（decision 决定放行/拦截）
            AvDriverPendingInfo {
                notification_type: "process".to_string(),
                notification_id,
                image_path: String::new(),
                process_name: String::new(),
                default_block: false,
            }
        }
    };

    // 记录用户态 always 规则（仅内存，应用重启后清空）。
    // 关键：不把 ALLOW_ALWAYS/DENY_ALWAYS 发送给驱动！驱动 DenyList/AllowList 常驻
    // 内存无法卸载，会导致"始终"决策跨应用重启持续生效。改为只发 ONCE 决策给驱动，
    // 后续拦截由 R3 侧 check_always_rule 直接处理。
    let mut emit_blocked = false;

    let av_decision = match info.notification_type.as_str() {
        "process" => {
            let (dec, is_block) = match decision.as_str() {
                "allow" => (AV_DECISION_ALLOW_ONCE, false),
                "block" => (AV_DECISION_DENY_ONCE, true),
                "allow_always" => {
                    add_always_rule("process", &info.image_path, "allow");
                    (AV_DECISION_ALLOW_ONCE, false)
                }
                "block_always" => {
                    add_always_rule("process", &info.image_path, "block");
                    (AV_DECISION_DENY_ONCE, true)
                }
                _ => (AV_DECISION_ALLOW_ONCE, false),
            };
            // 如果是拦截，发射事件
            if is_block {
                emit_blocked = true;
            }
            AvDecision::Process {
                notification_id: info.notification_id,
                decision: dec,
                image_path: info.image_path.clone(),
            }
        }
        "registry" => {
            let (dec, _is_block) = match decision.as_str() {
                "allow" => (AV_DECISION_ALLOW_ONCE, false),
                "block" => (AV_DECISION_DENY_ONCE, true),
                "allow_always" => {
                    add_always_rule("registry", &info.image_path, "allow");
                    (AV_DECISION_ALLOW_ONCE, false)
                }
                "block_always" => {
                    add_always_rule("registry", &info.image_path, "block");
                    (AV_DECISION_DENY_ONCE, true)
                }
                _ => (AV_DECISION_ALLOW_ONCE, false),
            };
            AvDecision::Registry {
                notification_id: info.notification_id,
                decision: dec,
                key_path: info.image_path.clone(),
            }
        }
        "injection" => {
            let (dec, _is_block) = match decision.as_str() {
                "allow" => (AV_DECISION_ALLOW_ONCE, false),
                "block" => (AV_DECISION_DENY_ONCE, true),
                "allow_always" => {
                    add_always_rule("injection", &info.image_path, "allow");
                    (AV_DECISION_ALLOW_ONCE, false)
                }
                "block_always" => {
                    add_always_rule("injection", &info.image_path, "block");
                    (AV_DECISION_DENY_ONCE, true)
                }
                _ => (AV_DECISION_ALLOW_ONCE, false),
            };
            AvDecision::Injection {
                notification_id: info.notification_id,
                decision: dec,
            }
        }
        "ransom" => {
            let dec = match decision.as_str() {
                "allow" => XGS_DECISION_ALLOW,
                "block" => XGS_DECISION_STAY_BLOCK,
                "restore" => XGS_DECISION_RESTORE,
                _ => XGS_DECISION_STAY_BLOCK,
            };
            AvDecision::Ransom {
                notification_id: info.notification_id,
                decision: dec,
            }
        }
        "endpoint" => {
            let (dec, is_block) = match decision.as_str() {
                "allow" => (XGS_EP_DECISION_ALLOW, false),
                "block" => (XGS_EP_DECISION_KILL, true),
                "block_always" => {
                    add_always_rule("endpoint", &info.image_path, "block");
                    (XGS_EP_DECISION_KILL, true)
                }
                "allow_always" => {
                    add_always_rule("endpoint", &info.image_path, "allow");
                    (XGS_EP_DECISION_ALLOW, false)
                }
                _ => (XGS_EP_DECISION_ALLOW, false),
            };
            if is_block {
                emit_blocked = true;
            }
            AvDecision::EndPoint {
                notification_id: info.notification_id,
                decision: dec,
            }
        }
        "injectguard" => {
            let (dec, is_block) = match decision.as_str() {
                "allow" => (IG_DECISION_ALLOW, false),
                "block" => (IG_DECISION_BLOCK, true),
                "allow_always" => {
                    add_always_rule("injectguard", &info.image_path, "allow");
                    (IG_DECISION_ALLOW, false)
                }
                "block_always" => {
                    add_always_rule("injectguard", &info.image_path, "block");
                    (IG_DECISION_BLOCK, true)
                }
                _ => (IG_DECISION_ALLOW, false),
            };
            if is_block {
                emit_blocked = true;
            }
            AvDecision::InjectGuard {
                sequence_id: info.notification_id as u32,
                decision: dec,
            }
        }
        _ => return Err(format!("Unknown notification type: {}", info.notification_type)),
    };

    // 清理 INTERCEPT_INFO_MAP
    {
        let mut info_map = INTERCEPT_INFO_MAP.lock().unwrap();
        info_map.remove(&pending_key);
    }

    // 同步模型：唤醒等待中的弹窗线程（=消息循环线程），由它统一写决策回管道、
    // 关闭窗口、重置状态。若弹窗线程已退出等待（超时/窗口异常），则直接发送决策兜底，
    // 确保被拦截进程永远不会因无人消费决策而永久挂起。
    // 注意：决策送达必须最先完成——emit 事件（下方）会 dispatch 到主线程同步触发
    // JS listener，若主线程繁忙，emit 会阻塞本命令，但决策已在阻塞前送达，不影响拦截。
    let waiters = AV_DECISION_WAITERS.get();
    let tx_opt = match waiters {
        Some(w) => w.lock().unwrap().remove(&pending_key),
        None => None,
    };
    match tx_opt {
        Some(tx) => {
            // 弹窗线程收到决策后自行写管道、关窗口、重置状态
            let _ = tx.send(av_decision);
            println!("[SendAvDriverDecision] Decision delivered to intercept waiter");
        }
        None => {
            // 无等待者（窗口已关闭/超时/异常）：直接发送决策。
            // 注意：弹窗线程一定已退出等待（waiters 注册已被移除），此处补发决策，
            // 并幂等重置拦截状态，防止极端情况下 INTERCEPT_BUSY 残留 stuck。
            if let Err(e) = send_av_decision(av_decision) {
                eprintln!("[SendAvDriverDecision] Failed to send decision: {}", e);
                log_to_file(&format!("[SendAvDriverDecision] Failed to send decision: {}", e));
            }
            INTERCEPT_BUSY.store(false, Ordering::SeqCst);
            INTERCEPT_BUSY_SINCE.store(0, Ordering::SeqCst);
            INTERCEPT_WINDOW_CLAIMED.store(false, Ordering::SeqCst);
            hide_intercept_window(&app);
            // ★历史 bug：同 close_intercept_window，重置 BUSY 后必须主动拉取队列，
            // 否则 show_next_intercept 之前因 BUSY=true 跳过的拦截项永远无法弹出。
            let app_clone = app.clone();
            std::thread::spawn(move || {
                crate::show_next_intercept(&app_clone);
            });
            println!("[SendAvDriverDecision] No waiter, decision sent directly, state reset");
        }
    }

    // 拦截事件（放在决策送达之后：即使主线程繁忙导致 emit 阻塞，
    // 决策已发送，拦截功能不受影响）
    if emit_blocked {
        let _ = app.emit("driver-process-blocked", serde_json::json!({
            "process": info.process_name,
            "threat": "UserBlocked",
        }));
    }

    Ok(())
}

// ==================== 通用 Win32 窗口辅助函数 ====================

/// 使用纯 Win32 API 将窗口显示并定位到右下角（不经过主线程事件循环）。
///
/// 所有 Tauri 窗口方法（show/set_focus/set_position 等）在后台线程调用时，
/// 会 dispatch 到主线程同步等待——主线程繁忙时造成死锁。
/// 本函数通过 ShowWindow + SetWindowPos + SetForegroundWindow 直接操作 HWND，
/// 跨线程安全、立即生效，不依赖主线程事件循环。
///
/// 参数:
/// - win: Tauri 窗口引用
/// - logical_w / logical_h: 窗口逻辑尺寸（物理像素自动按 DPI 缩放）
/// - bottom_right: true=右下角定位, false=屏幕居中定位
#[cfg(windows)]
pub(crate) fn win32_show_window(
    win: &tauri::WebviewWindow,
    logical_w: f64,
    logical_h: f64,
    bottom_right: bool,
) {
    let hwnd_raw = match win.hwnd() {
        Ok(h) => h.0 as *mut std::ffi::c_void,
        Err(e) => {
            eprintln!("[Win32ShowWindow] Failed to get HWND: {}", e);
            return;
        }
    };

    unsafe {
        let user32 = match windows::Win32::System::LibraryLoader::LoadLibraryW(windows::core::w!("user32.dll")) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[Win32ShowWindow] Failed to load user32.dll: {}", e);
                return;
            }
        };

        type FnShowWindow = unsafe extern "system" fn(*mut std::ffi::c_void, i32) -> i32;
        type FnSetWindowPos = unsafe extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, i32, i32, i32, i32, u32) -> i32;
        type FnSetForegroundWindow = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;
        type FnGetDpiForWindow = unsafe extern "system" fn(*mut std::ffi::c_void) -> u32;

        let show_win: FnShowWindow = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("ShowWindow")).unwrap()
        );
        let bring_to_top: FnSetWindowPos = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("SetWindowPos")).unwrap()
        );
        let set_foreground: FnSetForegroundWindow = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("SetForegroundWindow")).unwrap()
        );
        let get_dpi: FnGetDpiForWindow = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("GetDpiForWindow")).unwrap()
        );

        // ShowWindow(SW_SHOWNORMAL = 1)：立即显示，不经过主线程
        let _ = show_win(hwnd_raw, 1);

        let dpi = get_dpi(hwnd_raw).max(96);
        let scale = dpi as f64 / 96.0;
        let window_w = (logical_w * scale) as i32;
        let window_h = (logical_h * scale) as i32;

        // 获取工作区计算位置
        #[repr(C)]
        struct RECT { left: i32, top: i32, right: i32, bottom: i32 }
        #[repr(C)]
        struct MONITORINFO { cb_size: u32, rc_monitor: RECT, rc_work: RECT, dw_flags: u32 }

        type FnMonitorFromWindow = unsafe extern "system" fn(*mut std::ffi::c_void, u32) -> *mut std::ffi::c_void;
        type FnGetMonitorInfoW = unsafe extern "system" fn(*mut std::ffi::c_void, *mut MONITORINFO) -> i32;

        let monitor_from_window: FnMonitorFromWindow = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("MonitorFromWindow")).unwrap()
        );
        let get_monitor_info: FnGetMonitorInfoW = std::mem::transmute(
            windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("GetMonitorInfoW")).unwrap()
        );

        let monitor = monitor_from_window(hwnd_raw, 2);
        let mut mi = MONITORINFO {
            cb_size: std::mem::size_of::<MONITORINFO>() as u32,
            rc_monitor: RECT { left: 0, top: 0, right: 0, bottom: 0 },
            rc_work: RECT { left: 0, top: 0, right: 0, bottom: 0 },
            dw_flags: 0,
        };

        let (x, y) = if !monitor.is_null() && get_monitor_info(monitor, &mut mi) != 0 {
            if bottom_right {
                let pad_r = (20.0 * scale) as i32;
                let pad_b = (10.0 * scale) as i32;
                (mi.rc_work.right - window_w - pad_r, mi.rc_work.bottom - window_h - pad_b)
            } else {
                let cx = (mi.rc_work.left + mi.rc_work.right) / 2;
                let cy = (mi.rc_work.top + mi.rc_work.bottom) / 2;
                (cx - window_w / 2, cy - window_h / 2)
            }
        } else {
            (0, 0)
        };

        // HWND_TOPMOST=-1; SWP_NOACTIVATE=0x10, SWP_SHOWWINDOW=0x40
        let _ = bring_to_top(hwnd_raw, (-1_isize) as *mut std::ffi::c_void, x, y, window_w, window_h, 0x10 | 0x40);
        let _ = set_foreground(hwnd_raw);

        println!("[Win32ShowWindow] Window shown: hwnd={:#x} dpi={} pos=({},{}) size={}x{}", hwnd_raw as usize, dpi, x, y, window_w, window_h);
    }
}

#[cfg(not(windows))]
pub(crate) fn win32_show_window(win: &tauri::WebviewWindow, _logical_w: f64, _logical_h: f64, _bottom_right: bool) {
    let _ = win.show();
    let _ = win.set_focus();
}

// ==================== 文件防护告警 ====================

#[cfg(windows)]
fn win32_show_file_protection_alert(win: &tauri::WebviewWindow) {
    win32_show_window(win, 420.0, 240.0, true);
}

/// 显示文件防护木马隔离告警窗口
///
/// ★卡死修复（拦截窗口与文件防护窗口并发冲突）★：
/// 历史 bug：文件防护窗口未预创建，每次告警都在 tokio worker 上
/// WebviewWindowBuilder::build() 动态建窗，随后 win32_show_window 内部的 hwnd()
/// 会通过 getter 通道同步阻塞等待主线程响应。当驱动/基础防护的拦截窗口正在
/// 等待用户决策、主线程繁忙时，建窗/显示出现竞态并静默失败（窗口被"忽略"，
/// 弹不出来）；并发告警又经 FILE_PROTECTION_ALERT_MUTEX（阻塞互斥锁，跨 await
/// 持有）串行阻塞多个 tokio worker，最终拖垮整个 async 命令管线 → 程序卡死。
/// ★修复：1) 窗口改为 tauri.conf.json 预创建（label: file-protection-alert，
/// 隐藏创建，webview 已加载），运行期不再动态建窗；2) 所有窗口操作（emit 重试
/// + Win32 显示）移入独立 std::thread，命令立即返回，不占用 tokio worker、
/// 不依赖主线程事件循环；3) 关闭改为纯 Win32 隐藏复用，绝不销毁窗口。
#[tauri::command]
async fn show_file_protection_alert(app_handle: tauri::AppHandle, file_path: String, virus_family: String) {
    println!("[FileProtectionAlert] File: {}, Family: {} - Showing alert window", file_path, virus_family);

    // AVIC 云端情报上报（文件防护检出恶意）— 内部已自行 spawn 线程，不阻塞
    avic_client::submit_threat(&file_path, &virus_family, &virus_family, "file_protection");

    let file_name = std::path::Path::new(&file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&file_path)
        .to_string();

    // 使用 emit 替代 eval：线程安全，不 dispatch 主线程，不会造成死锁
    let payload = serde_json::json!({
        "filePath": file_path,
        "fileName": file_name,
        "virusFamily": virus_family,
    });

    // 缓存最近一次数据，供前端页面加载后主动拉取（防止 emit 事件丢失）
    *pending_file_protection_data().lock().unwrap() = Some(payload.clone());

    // ★全部窗口操作移到独立 std::thread：命令立即返回，不阻塞 tokio worker，
    // 也不阻塞主线程。窗口为预创建窗口（tauri.conf.json），get_webview_window
    // 是纯查表，emit 线程安全，Win32 显示跨线程安全。
    std::thread::spawn(move || {
        // 互斥：防止并发告警的 emit/显示交错导致数据覆盖错乱（std 线程内短暂持有，安全）
        let _guard = FILE_PROTECTION_ALERT_MUTEX.get_or_init(|| StdMutex::new(())).lock().unwrap();

        // 复用预创建窗口（正常路径）
        let window = app_handle.get_webview_window("file-protection-alert");
        let window = match window {
            Some(w) => w,
            None => {
                // 兜底（预创建配置下不应发生）：dispatch 主线程动态创建（fire-and-forget，
                // 不阻塞本线程），轮询等待窗口出现（最多 3 秒；get_webview_window 纯查表）。
                eprintln!("[FileProtectionAlert] Window not found, dispatching dynamic creation (non-blocking)");
                let app_clone = app_handle.clone();
                let _ = app_handle.run_on_main_thread(move || {
                    let lang = get_current_language();
                    let url = format!(
                        "file-protection-alert.html?lang={}",
                        urlencoding::encode(&lang)
                    );
                    let _ = tauri::WebviewWindowBuilder::new(
                        &app_clone,
                        "file-protection-alert",
                        tauri::WebviewUrl::App(url.into()),
                    )
                    .title("文件防护")
                    .inner_size(420.0, 240.0)
                    .decorations(false)
                    .transparent(true)
                    .shadow(true)
                    .always_on_top(true)
                    .skip_taskbar(true)
                    .resizable(false)
                    .visible(false)
                    .build();
                });
                let mut found = None;
                for _ in 0..30 {
                    if let Some(w) = app_handle.get_webview_window("file-protection-alert") {
                        found = Some(w);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                match found {
                    Some(w) => w,
                    None => {
                        eprintln!("[FileProtectionAlert] Window creation failed within 3s");
                        return;
                    }
                }
            }
        };

        // emit 数据作为唯一数据通道（预创建窗口的页面在启动时已注册 listener）。
        // 重试覆盖极端情况下页面监听器晚注册的情况；失败不阻塞，pending 数据兜底。
        for attempt in 0..5 {
            if window.emit("file-protection-data", payload.clone()).is_ok() {
                if attempt > 0 {
                    println!("[FileProtectionAlert] emit retried (attempt {})", attempt + 1);
                }
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(150));
        }

        // Win32 直接显示+定位，不经过主线程事件循环（hwnd() 是预创建窗口，
        // 主线程正常时毫秒级返回；本线程是 std 线程，短暂等待不影响 async 管线）
        win32_show_file_protection_alert(&window);
        println!("[FileProtectionAlert] Alert window shown for file: {}", file_path);
    });
}

/// 获取最近一次待显示的文件防护弹窗数据（前端页面加载后的兜底拉取）
#[tauri::command]
fn get_pending_file_protection_data() -> Option<serde_json::Value> {
    pending_file_protection_data().lock().unwrap().clone()
}

/// 关闭文件防护告警窗口
#[tauri::command]
async fn close_file_protection_alert_window(app: tauri::AppHandle) -> Result<(), String> {
    println!("[FileProtectionAlert] Hiding file protection alert window (reuse, not destroy)");
    // ★卡死修复：window.destroy()/close() 会销毁 file-protection-alert 窗口，
    // 下一次告警只能走"tokio worker 动态 build + hwnd() 等待主线程"路径，
    // 主线程繁忙时创建/显示失败，窗口"弹不出来"；且 destroy 从后台线程调用
    // 存在阻塞/竞态风险。改为纯 Win32 隐藏复用（与拦截窗口 hide_intercept_window
    // 同一模式），窗口生命周期与主程序一致，下次告警直接 emit + 显示。
    if let Some(window) = app.get_webview_window("file-protection-alert") {
        win32_hide_window(&window);
        println!("[FileProtectionAlert] Window hidden successfully");
    } else {
        println!("[FileProtectionAlert] Window not found");
    }
    Ok(())
}

/// 信任文件：从隔离区恢复并关闭告警窗口
#[tauri::command]
async fn trust_file_protection_alert(file_path: String, app_handle: tauri::AppHandle) -> Result<bool, String> {
    println!("[FileProtectionAlert] Trusting file, restoring: {}", file_path);

    // 根据原始路径查找隔离记录ID，再调用恢复命令
    let id = match QuarantineManager::new() {
        Ok(manager) => match manager.find_id_by_original_path(&file_path) {
            Ok(Some(id)) => id,
            Ok(None) => {
                println!("[FileProtectionAlert] No quarantine record found for: {}", file_path);
                if let Some(window) = app_handle.get_webview_window("file-protection-alert") {
                    // 隐藏复用，不销毁窗口（避免下次告警重新建窗的竞态/阻塞）
                    win32_hide_window(&window);
                }
                return Err("未找到隔离记录".to_string());
            }
            Err(e) => {
                println!("[FileProtectionAlert] Failed to find quarantine id: {} - {}", file_path, e);
                if let Some(window) = app_handle.get_webview_window("file-protection-alert") {
                    win32_hide_window(&window);
                }
                return Err(e);
            }
        }
        Err(e) => {
            println!("[FileProtectionAlert] Failed to create quarantine manager: {}", e);
            if let Some(window) = app_handle.get_webview_window("file-protection-alert") {
                win32_hide_window(&window);
            }
            return Err(e);
        }
    };

    let result = restore_quarantined_file(id).await;

    // 关闭告警窗口（隐藏复用，不销毁）
    if let Some(window) = app_handle.get_webview_window("file-protection-alert") {
        win32_hide_window(&window);
    }

    match result {
        Ok(value) => {
            let success = value.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
            println!("[FileProtectionAlert] File restored: {} -> {}", file_path, success);
            Ok(success)
        }
        Err(e) => {
            println!("[FileProtectionAlert] Failed to restore file: {} - {}", file_path, e);
            Err(e)
        }
    }
}

/// 打开主窗口并切换到隔离区页面
#[tauri::command]
async fn open_quarantine_window(app: tauri::AppHandle) -> Result<(), String> {
    println!("[FileProtectionAlert] Opening quarantine page");
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
        let _ = window.emit("navigate-to", "quarantine");
    }
    Ok(())
}

// 处理 protocol 激活
fn handle_protocol_activation(url: &str) {
    println!("[Protocol] Handling activation: {}", url);
    
    // 解析 URL: xiguasecurity://threat/kill/process.exe 或 xiguasecurity://threat/ignore/process.exe
    let parts: Vec<&str> = url.split("/").collect();
    if parts.len() >= 5 {
        let action = parts[3]; // kill 或 ignore
        let process_name = parts[4]; // 进程名
        
        match action {
            "kill" => {
                println!("[Protocol] Kill action for process: {}", process_name);
                kill_process_with_admin(process_name);
                // 等待一会让用户看到结果
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
            "ignore" => {
                println!("[Protocol] Ignore action for process: {}", process_name);
                // 什么都不做，只是记录日志
            }
            _ => {
                println!("[Protocol] Unknown action: {}", action);
            }
        }
    } else {
        println!("[Protocol] Invalid URL format");
    }
}

// 使用管理员权限终止进程
fn kill_process_with_admin(process_name: &str) {
    let process_name = process_name.to_string();

    std::thread::spawn(move || {
        println!("[KillProcess] Attempting to kill process: {}", process_name);

        if is_elevated() {
            // 已提权：直接用 taskkill，无需 ShellExecuteW("runas") 避免 UIPI 死锁
            use std::os::windows::process::CommandExt;
            let result = std::process::Command::new("taskkill")
                .args(["/IM", &process_name, "/F", "/T"])
                .creation_flags(0x08000000)
                .output();

            match result {
                Ok(output) => {
                    if output.status.success() {
                        println!("[KillProcess] taskkill succeeded for: {}", process_name);
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        println!("[KillProcess] taskkill failed for {}: {}", process_name, stderr.trim());
                    }
                }
                Err(e) => {
                    eprintln!("[KillProcess] Failed to run taskkill: {}", e);
                }
            }
        } else {
            // 未提权：使用 ShellExecuteW("runas") 触发 UAC
            unsafe {
                use windows::Win32::UI::Shell::ShellExecuteW;
                use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK, MB_ICONERROR, MB_TOPMOST, SW_SHOWNORMAL};
                use windows::core::HSTRING;

                let ps_command = format!(
                    "Stop-Process -Name '{}' -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2",
                    process_name.replace(".exe", "").replace("'", "''")
                );

                let operation = HSTRING::from("runas");
                let file = HSTRING::from("powershell.exe");
                let parameters = HSTRING::from(format!("-NoProfile -Command \"{}\"", ps_command));

                let result = ShellExecuteW(
                    None,
                    &operation,
                    &file,
                    &parameters,
                    None,
                    SW_SHOWNORMAL
                );

                let result_code = result.0 as usize;
                if result_code > 32 {
                    println!("[KillProcess] Elevated PowerShell launched successfully for: {}", process_name);
                } else {
                    println!("[KillProcess] Failed to launch elevated PowerShell, error code: {}", result_code);
                    let title = HSTRING::from("终止失败");
                    let body = HSTRING::from(format!("无法启动管理员权限进程。\n错误代码: {}", result_code));
                    MessageBoxW(None, &body, &title, MB_OK | MB_ICONERROR | MB_TOPMOST);
                }
            }
        }
    });
}

// Tauri 命令：从威胁提示窗口终止进程
#[tauri::command]
fn get_scanner_info_command() -> Result<serde_json::Value, String> {
    use scanner::SCANNER;
    let scanner = SCANNER.read().map_err(|e| e.to_string())?;
    Ok(scanner.get_info())
}

#[tauri::command]
fn get_virus_family_rules_command() -> Result<serde_json::Value, String> {
    use scanner::virus_family::rule_engine;
    let engine = rule_engine::get_engine();
    Ok(engine.get_loaded_rules_info())
}

#[tauri::command]
fn reload_virus_family_rules_command() -> Result<(), String> {
    use scanner::virus_family::rule_engine;
    rule_engine::reload_engine()
}

#[tauri::command]
fn get_engine_rule_count() -> serde_json::Value {
    use scanner::virus_family::rule_engine;
    let engine = rule_engine::get_engine();
    serde_json::json!({
        "signatures": engine.signatures.len(),
        "behaviors": engine.behavior_categories.len(),
    })
}

#[tauri::command]
fn kill_process_from_alert(process_name: String) -> Result<(), String> {
    println!("[KillProcessFromAlert] Killing process: {}", process_name);
    
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    // 首先尝试普通权限 taskkill（无 UAC）
    let output = Command::new("taskkill")
        .args(&["/F", "/IM", &process_name])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output();
    
    if let Ok(result) = output {
        if result.status.success() {
            println!("[KillProcessFromAlert] Successfully killed process via taskkill: {}", process_name);
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&result.stderr);
        println!("[KillProcessFromAlert] taskkill failed: {}", stderr);
    }
    
    // taskkill 失败时回退到 R3 Windows API（无 UAC）
    println!("[KillProcessFromAlert] Falling back to R3 Windows API termination");
    if kill_process_by_name(&process_name) {
        println!("[KillProcessFromAlert] R3 termination succeeded: {}", process_name);
        return Ok(());
    }

    // R3 也失败时尝试 UAC 提权兜底
    println!("[KillProcessFromAlert] R3 failed, trying UAC elevation");
    if kill_process_by_name_uac(&process_name) {
        println!("[KillProcessFromAlert] UAC elevation succeeded: {}", process_name);
        return Ok(());
    }

    Err(format!("无法终止进程 {}，可能需要管理员权限", process_name))
}

// 启动拦截工具进程（直接 ShellExecuteW runas 提权启动）
#[cfg(not(feature = "ms_store"))]
fn start_interceptor_tool() -> Result<(), String> {
    // 获取项目根目录（从可执行文件路径推算）
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get exe path: {}", e))?;
    
    // 尝试找到项目根目录（包含 Driver 目录的目录）
    let mut current_dir = exe_path.parent();
    let mut interceptor_path = None;
    
    for _ in 0..5 {
        if let Some(dir) = current_dir {
            // 新驱动: 查找 Driver/XIGUASecurityAgent.exe
            let test_path = dir.join("Driver").join("XIGUASecurityAgent.exe");
            if test_path.exists() {
                interceptor_path = Some(test_path);
                break;
            }
            current_dir = dir.parent();
        } else {
            break;
        }
    }
    
    let interceptor_path = interceptor_path.ok_or("Could not find XIGUASecurityAgent.exe in Driver directory")?;
    let path_str = interceptor_path.to_str().ok_or("Invalid path encoding")?;
    let driver_dir = interceptor_path.parent().ok_or("Invalid driver directory")?;
    let driver_dir_str = driver_dir.to_str().ok_or("Invalid driver directory encoding")?;
    
    log_to_file(&format!("[DriverProtection] start_interceptor_tool: launching {:?}", interceptor_path));
    println!("[DriverProtection] Launching XIGUASecurityAgent: {:?}", interceptor_path);

    // 智能启动：已提权时用 CreateProcessW（避免 ShellExecuteW + UIPI 死锁），
    // 未提权时用 ShellExecuteW("runas") 触发 UAC
    launch_process_with_elevation(path_str, None, Some(driver_dir_str), 0)
        .map_err(|e| {
            let msg = format!("[DriverProtection] Failed to launch XIGUASecurityAgent: {}", e);
            log_to_file(&msg);
            println!("{}", msg);
            e
        })?;

    log_to_file("[DriverProtection] XIGUASecurityAgent launched successfully");
    println!("[DriverProtection] XIGUASecurityAgent launched successfully");
    Ok(())
}

// ==================== AVModel 独立防护进程 ====================

/// 查找 AVModel 可执行文件路径
/// 搜索顺序：主程序同级目录 → AVModel/ 子目录 → Driver/ 目录 → 向上遍历 5 层
#[cfg(not(feature = "ms_store"))]
fn find_avmodel_exe() -> Option<std::path::PathBuf> {
    let exe_path = std::env::current_exe().ok()?;
    let exe_dir = exe_path.parent()?;

    // 可执行文件名不含 "xiguasecurity"，避免驱动 OB 回调保护逻辑干扰
    const AVMODEL_EXE: &str = "AVGuard.exe";

    // 1. 主程序同级目录
    let direct = exe_dir.join(AVMODEL_EXE);
    if direct.exists() {
        return Some(direct);
    }

    // 2. AVModel/ 子目录
    let subdir = exe_dir.join("AVModel").join(AVMODEL_EXE);
    if subdir.exists() {
        return Some(subdir);
    }

    // 3. Driver/ 目录（与 XIGUASecurityAgent.exe 同级）
    let driver_dir = exe_dir.join("Driver").join(AVMODEL_EXE);
    if driver_dir.exists() {
        return Some(driver_dir);
    }

    // 4. 向上遍历 5 层查找 AVModel/
    let mut current_dir = exe_dir.parent();
    for _ in 0..5 {
        if let Some(dir) = current_dir {
            let avmodel_dir = dir.join("AVModel").join("target")
                .join(if cfg!(debug_assertions) { "debug" } else { "release" })
                .join(AVMODEL_EXE);
            if avmodel_dir.exists() {
                return Some(avmodel_dir);
            }
            current_dir = dir.parent();
        } else {
            break;
        }
    }

    None
}

/// 启动 AVModel 独立防护进程（管理员权限）
#[cfg(not(feature = "ms_store"))]
fn start_avmodel_process() -> Result<(), String> {
    let avmodel_path = find_avmodel_exe()
        .ok_or_else(|| "AVGuard.exe not found".to_string())?;

    let path_str = avmodel_path.to_str()
        .ok_or_else(|| "Invalid AVModel path encoding".to_string())?;

    let working_dir = avmodel_path.parent()
        .and_then(|p| p.to_str())
        .unwrap_or(".");

    log_to_file(&format!("[AVModel] Launching: {:?}", avmodel_path));
    println!("[AVModel] Launching AVModel process: {:?}", avmodel_path);

    launch_process_with_elevation(path_str, None, Some(working_dir), 0)
        .map_err(|e| {
            let msg = format!("[AVModel] Failed to launch: {}", e);
            log_to_file(&msg);
            println!("{}", msg);
            e
        })?;

    log_to_file("[AVModel] AVModel process launched successfully");
    println!("[AVModel] AVModel process launched successfully");
    Ok(())
}

/// AVModel 看门狗线程：监控 AVModel 进程，如果停止运行则自动拉起
#[cfg(not(feature = "ms_store"))]
fn start_avmodel_watchdog() {
    std::thread::spawn(move || {
        // 初始等待 5 秒，让 AVModel 有足够时间启动
        std::thread::sleep(std::time::Duration::from_secs(5));

        // 重启冷却：记录上次尝试重启的时间，避免反复弹 UAC
        let mut last_restart_attempt: Option<std::time::Instant> = None;
        // 连续失败计数：如果 ping 一直失败但已启动过重启，不再重复弹 UAC
        let mut consecutive_failures: u32 = 0;

        loop {
            let ping_ok = avmodel_client::ping();

            if ping_ok {
                consecutive_failures = 0;
                last_restart_attempt = None;
            } else {
                consecutive_failures += 1;
                println!("[AVModel] Watchdog: ping failed (consecutive: {})", consecutive_failures);
                log_to_file(&format!("[AVModel] Watchdog: ping failed (consecutive: {})", consecutive_failures));

                // 只在第一次失败时尝试重启，之后等冷却期
                let should_try_restart = if consecutive_failures == 1 {
                    true
                } else {
                    // 后续失败：检查冷却期（60 秒内不重复弹 UAC）
                    match last_restart_attempt {
                        Some(last) => last.elapsed() > std::time::Duration::from_secs(60),
                        None => true,
                    }
                };

                if should_try_restart {
                    println!("[AVModel] Watchdog: attempting to restart AVModel...");
                    log_to_file("[AVModel] Watchdog: attempting to restart AVModel...");
                    last_restart_attempt = Some(std::time::Instant::now());

                    match start_avmodel_process() {
                        Ok(()) => {
                            println!("[AVModel] Watchdog: restart launched, waiting...");
                            log_to_file("[AVModel] Watchdog: restart launched, waiting...");
                            std::thread::sleep(std::time::Duration::from_secs(5));
                        }
                        Err(e) => {
                            println!("[AVModel] Watchdog: restart failed: {}", e);
                            log_to_file(&format!("[AVModel] Watchdog: restart failed: {}", e));
                            // 启动失败（如用户拒绝 UAC），设长冷却期
                            std::thread::sleep(std::time::Duration::from_secs(30));
                        }
                    }
                }
            }

            // 每 10 秒检查一次
            std::thread::sleep(std::time::Duration::from_secs(10));
        }
    });
}

/// 通过 AVModel 终止进程（供其他模块调用）
/// 当常规终止方式失败时，调用此函数利用 AVModel 的多种终止方法
#[cfg(not(feature = "ms_store"))]
pub fn kill_process_via_avmodel(pid: u32) -> bool {
    avmodel_client::request_kill(pid)
}

/// MS Store 版本 stub — 不支持 AVModel 独立防护进程
#[cfg(feature = "ms_store")]
pub fn kill_process_via_avmodel(_pid: u32) -> bool {
    false
}

/// 通过 AVModel 按进程名终止进程（供其他模块调用）
/// 处理主进程退出后释放同名 .tmp 子进程的场景
#[cfg(not(feature = "ms_store"))]
pub fn kill_process_by_name_via_avmodel(name: &str) -> Option<avmodel_client::AvModelResponse> {
    avmodel_client::request_kill_by_name(name)
}

/// MS Store 版本 stub
#[cfg(feature = "ms_store")]
pub fn kill_process_by_name_via_avmodel(_name: &str) -> Option<avmodel_client::AvModelResponse> {
    None
}

// 通过进程名结束进程（R3，使用 Windows API，无需 UAC 弹窗）
fn kill_process_by_name(process_name: &str) -> bool {
    #[cfg(windows)]
    {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
            PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        };
        use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
        use windows::Win32::Foundation::CloseHandle;

        let target = process_name.to_lowercase();
        let target = if target.ends_with(".exe") {
            target
        } else {
            format!("{}.exe", target)
        };

        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(e) => {
                    println!("[KillProcess] CreateToolhelp32Snapshot failed: {}", e);
                    return false;
                }
            };

            let mut entry = PROCESSENTRY32W::default();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            let mut killed_any = false;
            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let exe_len = entry.szExeFile.iter().take_while(|&&c| c != 0).count();
                    let exe_name = String::from_utf16_lossy(&entry.szExeFile[..exe_len]);
                    if exe_name.to_lowercase() == target {
                        let pid = entry.th32ProcessID;
                        if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                            let result = TerminateProcess(handle, 1);
                            let _ = CloseHandle(handle);
                            if result.is_ok() {
                                println!("[KillProcess] Terminated {} (PID: {}) via Windows API", exe_name, pid);
                                killed_any = true;
                            } else {
                                println!("[KillProcess] TerminateProcess failed for {} (PID: {})", exe_name, pid);
                            }
                        } else {
                            println!("[KillProcess] OpenProcess failed for {} (PID: {})", exe_name, pid);
                        }
                    }
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
            killed_any
        }
    }

    #[cfg(not(windows))]
    {
        false
    }
}

// UAC 提权兜底：R3 终止失败时，通过 runas 启动 PowerShell 结束进程
fn kill_process_by_name_uac(process_name: &str) -> bool {
    #[cfg(windows)]
    {
        let ps_cmd = format!(
            "-Command \"& {{ $proc = Get-Process -Name '{}' -ErrorAction SilentlyContinue; if ($proc) {{ Stop-Process -Id $proc.Id -Force; Write-Host 'Process terminated' }} else {{ Write-Host 'Process not found' }} }}\"",
            process_name.trim_end_matches(".exe")
        );

        let ps_cmd_wide: Vec<u16> = ps_cmd.encode_utf16().chain(std::iter::once(0)).collect();
        let runas: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();
        let powershell: Vec<u16> = "powershell.exe".encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let result = ShellExecuteW(
                None,
                PCWSTR(runas.as_ptr()),
                PCWSTR(powershell.as_ptr()),
                PCWSTR(ps_cmd_wide.as_ptr()),
                None,
                SHOW_WINDOW_CMD(0), // SW_HIDE
            );

            if result.0 as isize > 32 {
                println!("[KillProcess] UAC PowerShell kill command executed for {}", process_name);
                true
            } else {
                println!("[KillProcess] UAC PowerShell kill failed with code: {:?}", result.0);
                false
            }
        }
    }

    #[cfg(not(windows))]
    {
        false
    }
}

// Tauri 命令：按进程名结束进程（先 R3，再 UAC 兜底）
#[tauri::command]
fn kill_process_by_name_command(process_name: String) -> Result<(), String> {
    // 先尝试 R3 Windows API
    if kill_process_by_name(&process_name) {
        return Ok(());
    }

    // R3 失败时尝试 UAC 提权
    println!("[KillProcessByNameCommand] R3 failed, trying UAC elevation");
    if kill_process_by_name_uac(&process_name) {
        return Ok(());
    }

    Err(format!("无法终止进程: {}", process_name))
}

// 停止驱动 - 直接终止 XIGUASecurityAgent.exe 进程
#[cfg(not(feature = "ms_store"))]
fn stop_interceptor_tool() -> Result<(), String> {
    println!("[DriverProtection] Stopping XIGUASecurityAgent...");
    log_to_file("[DriverProtection] stop_interceptor_tool called");

    // 直接用 taskkill 终止进程（无需 UAC，因为主程序可能已有足够权限）
    use std::process::Command;
    use std::os::windows::process::CommandExt;

    let output = Command::new("taskkill")
        .args(&["/F", "/IM", "XIGUASecurityAgent.exe"])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output();

    match output {
        Ok(result) => {
            if result.status.success() {
                log_to_file("[DriverProtection] XIGUASecurityAgent killed via taskkill");
                println!("[DriverProtection] XIGUASecurityAgent killed via taskkill");
            } else {
                // taskkill 可能因为权限不足失败，回退到 R3 API
                let stderr = String::from_utf8_lossy(&result.stderr);
                log_to_file(&format!("[DriverProtection] taskkill failed: {}", stderr.trim()));
                println!("[DriverProtection] taskkill failed: {}, trying R3 API", stderr.trim());

                if kill_process_by_name("XIGUASecurityAgent.exe") {
                    log_to_file("[DriverProtection] XIGUASecurityAgent killed via R3 API");
                    println!("[DriverProtection] XIGUASecurityAgent killed via R3 API");
                } else {
                    log_to_file("[DriverProtection] R3 kill also failed, process may have already exited");
                    println!("[DriverProtection] R3 kill failed, process may have already exited");
                }
            }
        }
        Err(e) => {
            log_to_file(&format!("[DriverProtection] Failed to execute taskkill: {}", e));
            println!("[DriverProtection] Failed to execute taskkill: {}", e);

            // 回退到 R3 API
            if kill_process_by_name("XIGUASecurityAgent.exe") {
                log_to_file("[DriverProtection] XIGUASecurityAgent killed via R3 API");
            }
        }
    }

    // 等待进程完全退出
    std::thread::sleep(std::time::Duration::from_millis(500));

    log_to_file("[DriverProtection] stop_interceptor_tool finished");
    Ok(())
}

// 同步停止驱动防护：优先优雅退出 Agent 进程，等待其退出后再兜底强杀
// 供 set_driver_protection(false) 和退出清理 (cleanup_before_exit) 共用
#[cfg(not(feature = "ms_store"))]
fn stop_driver_protection_sync() {
    log_to_file("[DriverProtection] stop_driver_protection_sync called");

    // 1. 优雅退出：通过管道发送 shutdown 请求，Agent 收到后自行退出
    //    Agent 是管理员权限进程，普通用户权限的主程序无法直接强杀，
    //    唯一可靠的方式是让 Agent 主动退出。
    let mut graceful_ok = false;
    match av_driver_client::send_shutdown_request() {
        Ok(()) => {
            log_to_file("[DriverProtection] Shutdown request sent, waiting for Agent to exit");
            println!("[DriverProtection] Shutdown request sent, waiting for Agent to exit");
            graceful_ok = true;
        }
        Err(e) => {
            log_to_file(&format!("[DriverProtection] Failed to send shutdown request: {}", e));
            println!("[DriverProtection] Failed to send shutdown request: {}", e);
        }
    }

    // 2. 停止 av_driver_client（关闭主程序侧管道，解除阻塞的 ReadFile）
    av_driver_client::stop_av_driver_client();
    log_to_file("[DriverProtection] av_driver_client stopped");

    // 3. 等待 Agent 自行退出（最多 5 秒，每 100ms 轮询一次）
    let mut exited = false;
    if graceful_ok {
        for _ in 0..50 {
            if !is_interceptor_running() {
                exited = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    // 4. 兜底：优雅退出失败或超时才强杀
    if exited {
        log_to_file("[DriverProtection] Agent exited gracefully");
        println!("[DriverProtection] Agent exited gracefully");
    } else {
        if graceful_ok {
            log_to_file("[DriverProtection] Agent did not exit within timeout, force killing");
            println!("[DriverProtection] Agent did not exit within timeout, force killing");
        }
        let result = std::panic::catch_unwind(|| {
            stop_interceptor_tool()
        });
        match result {
            Ok(Ok(_)) => {
                println!("[DriverProtection] Interceptor stopped successfully");
                log_to_file("[DriverProtection] Interceptor stopped successfully");
            }
            Ok(Err(e)) => {
                eprintln!("[DriverProtection] Failed to stop interceptor: {}", e);
                log_to_file(&format!("[DriverProtection] Failed to stop interceptor: {}", e));
            }
            Err(_) => {
                eprintln!("[DriverProtection] stop_interceptor_tool panicked");
                log_to_file("[DriverProtection] stop_interceptor_tool panicked");
            }
        }
    }
}

// 在后台线程启动驱动防护（AVModel + Agent + av_driver_client）。
// 供 set_driver_protection(true) 与"启动时强制开启驱动防护"共用，
// 避免 setup 里依赖 State 的生命周期问题。
#[cfg(not(feature = "ms_store"))]
fn start_driver_protection_background(app_handle: tauri::AppHandle) {
    log_to_file("[DriverProtection] start_driver_protection_background");
    std::thread::spawn(move || {
        // 先启动 AVModel，再启动 Agent（AVModel 必须先于 Agent，否则 OB 回调剥离其权限）
        if !avmodel_client::ping() {
            println!("[DriverProtection] Starting AVModel before Agent...");
            log_to_file("[DriverProtection] Starting AVModel before Agent...");
            match start_avmodel_process() {
                Ok(()) => {
                    for _ in 0..10 {
                        if avmodel_client::ping() {
                            println!("[DriverProtection] AVModel is ready");
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                }
                Err(e) => {
                    println!("[DriverProtection] AVModel failed to start: {}", e);
                    log_to_file(&format!("[DriverProtection] AVModel failed to start: {}", e));
                }
            }
        }

        log_to_file("[DriverProtection] spawn thread: starting interceptor");
        let result = std::panic::catch_unwind(|| {
            start_interceptor_tool()
        });
        match result {
            Ok(Ok(_)) => {
                println!("[DriverProtection] Agent started, waiting for pipe...");
                log_to_file("[DriverProtection] Agent started, waiting for pipe...");
                let mut connected = false;
                for attempt in 1..=10 {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    match av_driver_client::start_av_driver_client(app_handle.clone()) {
                        Ok(()) => {
                            println!("[DriverProtection] av_driver_client connected successfully");
                            log_to_file("[DriverProtection] av_driver_client connected successfully");
                            connected = true;
                            break;
                        }
                        Err(e) => {
                            println!("[DriverProtection] av_driver_client connect failed: {}", e);
                            log_to_file(&format!("[DriverProtection] av_driver_client connect failed: {}", e));
                        }
                    }
                }
                if connected {
                    let _ = security_log::add_security_log(
                        security_log::LogCategory::Driver,
                        "驱动防护",
                        "驱动防护已启动",
                        None, None,
                        security_log::LogAction::Started,
                        security_log::LogResult::Success, None,
                    );
                } else {
                    log_to_file("[DriverProtection] Failed to connect av_driver_client after 10 attempts");
                }
            }
            Ok(Err(e)) => {
                eprintln!("[DriverProtection] Failed to start interceptor: {}", e);
                log_to_file(&format!("[DriverProtection] Failed to start interceptor: {}", e));
            }
            Err(_) => {
                eprintln!("[DriverProtection] start_interceptor_tool panicked");
                log_to_file("[DriverProtection] start_interceptor_tool panicked");
            }
        }
    });
}

#[tauri::command]
#[cfg(not(feature = "ms_store"))]
fn set_driver_protection(enabled: bool, state: State<DriverProtectionState>, app_handle: tauri::AppHandle) -> Result<(), String> {
    log_to_file(&format!("[DriverProtection] set_driver_protection called: enabled={}", enabled));
    if let Ok(mut guard) = state.enabled.lock() {
        *guard = enabled;
        println!("[DriverProtection] Enabled: {}", enabled);
        log_to_file(&format!("[DriverProtection] state set to {}", enabled));
        
        // 在后台线程执行启动/停止操作，避免阻塞 Tauri IPC
        // ShellExecuteW(runas) 触发 UAC 弹窗，若同步执行可能导致界面卡死
        if enabled {
            let app_clone = app_handle.clone();
            start_driver_protection_background(app_clone);
        } else {
            std::thread::spawn(|| {
                log_to_file("[DriverProtection] spawn thread: stopping interceptor");

                // 优雅退出 Agent（发送 shutdown 请求并等待其退出，超时才强杀）
                stop_driver_protection_sync();

                let _ = security_log::add_security_log(
                    security_log::LogCategory::Driver,
                    "驱动防护",
                    "驱动防护已停止",
                    None, None,
                    security_log::LogAction::Stopped,
                    security_log::LogResult::Success, None,
                );
                let event = TimelineEvent {
                    id: format!("protection_stop_{}", chrono::Local::now().timestamp()),
                    timestamp: chrono::Local::now().to_rfc3339(),
                    event_type: "warning".to_string(),
                    title: "实时防护已关闭".to_string(),
                    description: "XIGUASecurity 实时防护功能已关闭".to_string(),
                    process_name: None,
                    result: Some("警告".to_string()),
                };
                add_timeline_event(event);
            });
        }
    }
    
    log_to_file("[DriverProtection] set_driver_protection returning Ok");
    Ok(())
}

#[tauri::command]
fn is_ms_store() -> bool {
    IS_MS_STORE
}

#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn get_driver_protection(state: State<'_, DriverProtectionState>) -> Result<bool, ()> {
    // 在异步线程中执行进程检查，避免阻塞UI
    let result = tokio::task::spawn_blocking(|| {
        is_interceptor_running()
    }).await.unwrap_or(false);
    
    // 更新状态
    if let Ok(mut guard) = state.enabled.lock() {
        *guard = result;
    }
    
    Ok(result)
}

#[tauri::command]
#[cfg(not(feature = "ms_store"))]
fn get_intercepted_logs(state: State<DriverProtectionState>) -> Vec<String> {
    if let Ok(guard) = state.intercepted_logs.lock() {
        let logs = guard.clone();
        // 调试：检查返回的日志是否有乱码
        for (i, log) in logs.iter().enumerate() {
            if log.chars().any(|c| c == '�' || (c as u32) > 0x9FFF) {
                println!("[GetInterceptedLogs] Log {} may be garbled: {}", i, log);
            }
        }
        logs
    } else {
        Vec::new()
    }
}

#[tauri::command]
#[cfg(not(feature = "ms_store"))]
fn clear_intercepted_logs(state: State<DriverProtectionState>) -> Result<(), String> {
    if let Ok(mut guard) = state.intercepted_logs.lock() {
        guard.clear();
        Ok(())
    } else {
        Err("Failed to lock logs".to_string())
    }
}

// 设置任务栏进度条
#[tauri::command]
async fn set_taskbar_progress(app_handle: tauri::AppHandle, progress: Option<f64>) -> Result<(), String> {
    if let Some(window) = app_handle.get_webview_window("main") {
        if let Some(p) = progress {
            // 将 0-100 的进度转换为 0-100 的 u64
            let normalized = (p as u64).clamp(0, 100);
            window.set_progress_bar(ProgressBarState {
                progress: Some(normalized),
                status: Some(ProgressBarStatus::Normal),
            }).map_err(|e| e.to_string())?;
        } else {
            // 清除进度条
            window.set_progress_bar(ProgressBarState {
                progress: None,
                status: Some(ProgressBarStatus::None),
            }).map_err(|e| e.to_string())?;
        }
        Ok(())
    } else {
        Err("Main window not found".to_string())
    }
}

// 时间线事件结构体
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct TimelineEvent {
    id: String,
    timestamp: String,
    event_type: String,
    title: String,
    description: String,
    process_name: Option<String>,
    result: Option<String>,
}

// 时间线存储文件路径
fn get_timeline_file_path() -> std::path::PathBuf {
    // 使用标准目录，不依赖 tauri::Config
    let app_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("XIGUASecurity");
    app_dir.join("timeline_events.json")
}

// 加载时间线事件
fn load_timeline_events() -> Vec<TimelineEvent> {
    let path = get_timeline_file_path();
    if path.exists() {
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                match serde_json::from_str::<Vec<TimelineEvent>>(&content) {
                    Ok(events) => {
                        println!("[Timeline] Loaded {} events from file", events.len());
                        events
                    }
                    Err(e) => {
                        println!("[Timeline] Failed to parse events: {}", e);
                        Vec::new()
                    }
                }
            }
            Err(e) => {
                println!("[Timeline] Failed to read file: {}", e);
                Vec::new()
            }
        }
    } else {
        println!("[Timeline] No existing timeline file found");
        Vec::new()
    }
}

// 保存时间线事件
fn save_timeline_events(events: &[TimelineEvent]) {
    let path = get_timeline_file_path();
    // 确保目录存在
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    
    match serde_json::to_string_pretty(events) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                println!("[Timeline] Failed to save events: {}", e);
            } else {
                println!("[Timeline] Saved {} events to file", events.len());
            }
        }
        Err(e) => {
            println!("[Timeline] Failed to serialize events: {}", e);
        }
    }
}

// 添加时间线事件（避免重复）
#[tauri::command]
fn add_timeline_event_command(event: TimelineEvent) {
    let mut events = load_timeline_events();
    
    // 检查是否已存在相同时间戳和描述的事件（避免重复）
    let is_duplicate = events.iter().any(|e| {
        e.timestamp == event.timestamp && e.description == event.description
    });
    
    if !is_duplicate {
        let title = event.title.clone();
        events.insert(0, event); // 新事件插入到开头
        
        // 限制存储的事件数量（保留最近 1000 条）
        if events.len() > 1000 {
            events.truncate(1000);
        }
        
        save_timeline_events(&events);
        println!("[Timeline] Event added: {}", title);
    } else {
        println!("[Timeline] Duplicate event skipped: {}", event.title);
    }
}

// 内部使用的添加时间线事件函数
fn add_timeline_event(event: TimelineEvent) {
    add_timeline_event_command(event);
}

#[tauri::command]
#[cfg(not(feature = "ms_store"))]
fn get_timeline_events(state: State<DriverProtectionState>) -> Vec<TimelineEvent> {
    let mut events = load_timeline_events();
    
    // 从拦截日志生成新的事件（内存中的最新日志）
    if let Ok(logs_guard) = state.intercepted_logs.lock() {
        for log in logs_guard.iter() {
            let event = parse_log_to_timeline_event(log);
            // 检查是否已存在
            if !events.iter().any(|e| e.id == event.id) {
                events.insert(0, event);
            }
        }
    }
    
    events
}

// 全局正则表达式（避免重复编译）
lazy_static::lazy_static! {
    static ref TIMESTAMP_REGEX: regex::Regex = regex::Regex::new(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]").unwrap();
}

#[cfg(not(feature = "ms_store"))]
fn parse_log_to_timeline_event(log: &str) -> TimelineEvent {
    // 解析时间戳
    let timestamp = if let Some(cap) = TIMESTAMP_REGEX.captures(log) {
        cap.get(1).map(|m| m.as_str().to_string()).unwrap_or_else(|| chrono::Local::now().to_rfc3339())
    } else {
        chrono::Local::now().to_rfc3339()
    };
    
    // 判断事件类型
    let (event_type, title, description, process_name, result) = if log.contains("[BLOCK]") || log.contains("已阻止") {
        let process = extract_process_name(log);
        (
            "block".to_string(),
            "已阻止恶意行为".to_string(),
            log.to_string(),
            process,
            Some("已阻止".to_string())
        )
    } else if log.contains("[WARNING]") || log.contains("警告") {
        let process = extract_process_name(log);
        (
            "warning".to_string(),
            "安全警告".to_string(),
            log.to_string(),
            process,
            Some("警告".to_string())
        )
    } else if log.contains("protection started") || log.contains("protection enabled") || log.contains("防护已启动") || log.contains("防护已开启") {
        (
            "system".to_string(),
            "实时防护已启动".to_string(),
            "XIGUASecurity 实时防护功能已成功启动".to_string(),
            None,
            Some("正常".to_string())
        )
    } else if log.contains("protection stopped") || log.contains("protection disabled") || log.contains("防护已停止") || log.contains("防护已关闭") {
        (
            "warning".to_string(),
            "实时防护已关闭".to_string(),
            "XIGUASecurity 实时防护功能已关闭".to_string(),
            None,
            Some("警告".to_string())
        )
    } else if log.contains("Connected to driver") || log.contains("驱动连接成功") {
        (
            "system".to_string(),
            "驱动连接成功".to_string(),
            "成功连接到 XIGUASecurity 驱动".to_string(),
            None,
            Some("正常".to_string())
        )
    } else if log.contains("application started") || log.contains("程序启动") {
        (
            "system".to_string(),
            "应用程序启动".to_string(),
            "XIGUASecurity 应用程序已启动".to_string(),
            None,
            Some("正常".to_string())
        )
    } else if log.contains("application exited") || log.contains("程序退出") || log.contains("shutdown") {
        (
            "system".to_string(),
            "应用程序退出".to_string(),
            "XIGUASecurity 应用程序已退出".to_string(),
            None,
            Some("正常".to_string())
        )
    } else if log.contains("扫描") || log.contains("Scan") {
        (
            "scan".to_string(),
            "扫描任务".to_string(),
            log.to_string(),
            None,
            Some("完成".to_string())
        )
    } else if log.contains("更新") || log.contains("Update") {
        (
            "update".to_string(),
            "病毒库更新".to_string(),
            log.to_string(),
            None,
            Some("成功".to_string())
        )
    } else {
        (
            "system".to_string(),
            "系统事件".to_string(),
            log.to_string(),
            None,
            None
        )
    };
    
    // 生成唯一 ID：基于时间戳和日志内容的哈希
    let id = if let Some(cap) = TIMESTAMP_REGEX.captures(log) {
        let ts = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        format!("log_{}_{}", ts, log.len())
    } else {
        format!("log_{}_{}", chrono::Local::now().timestamp(), log.len())
    };
    
    TimelineEvent {
        id,
        timestamp,
        event_type,
        title,
        description,
        process_name,
        result,
    }
}

// 进程信息结构体（用于进程管理器）
#[derive(serde::Serialize, Clone)]
struct SystemProcessInfo {
    name: String,
    pid: u32,
    path: String,
}

// 获取系统进程列表
#[tauri::command]
fn get_process_list() -> Vec<SystemProcessInfo> {
    use windows::Win32::System::ProcessStatus::{EnumProcesses, GetModuleBaseNameW, GetProcessImageFileNameW};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
    use windows::Win32::Foundation::CloseHandle;
    
    let mut processes = Vec::new();
    
    unsafe {
        let mut process_ids = vec![0u32; 2048];
        let mut bytes_returned = 0u32;
        
        // 枚举所有进程
        if EnumProcesses(
            process_ids.as_mut_ptr(),
            (process_ids.len() * std::mem::size_of::<u32>()) as u32,
            &mut bytes_returned,
        ).is_ok() {
            let num_processes = bytes_returned as usize / std::mem::size_of::<u32>();
            
            for i in 0..num_processes {
                let pid = process_ids[i];
                if pid == 0 {
                    continue;
                }
                
                // 打开进程
                if let Ok(handle) = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    false,
                    pid,
                ) {
                    let mut name_buffer = vec![0u16; 260];
                    let name_len = GetModuleBaseNameW(
                        handle,
                        None,
                        &mut name_buffer,
                    );
                    
                    // 获取进程路径
                    let mut path_buffer = vec![0u16; 1024];
                    let path_len = GetProcessImageFileNameW(handle, &mut path_buffer);
                    
                    let _ = CloseHandle(handle);
                    
                    if name_len > 0 {
                        let name = String::from_utf16_lossy(&name_buffer[..name_len as usize]);
                        let path = if path_len > 0 {
                            String::from_utf16_lossy(&path_buffer[..path_len as usize])
                        } else {
                            "Unknown".to_string()
                        };
                        
                        processes.push(SystemProcessInfo {
                            name,
                            pid,
                            path,
                        });
                    }
                }
            }
        }
    }
    
    // 按名称排序
    processes.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    processes
}

// 结束进程
#[tauri::command]
fn kill_process(pid: u32) -> Result<(), String> {
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    use windows::Win32::Foundation::CloseHandle;
    
    unsafe {
        if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) {
            let result = TerminateProcess(handle, 1);
            let _ = CloseHandle(handle);
            
            if result.is_ok() {
                Ok(())
            } else {
                Err("Failed to terminate process".to_string())
            }
        } else {
            Err("Failed to open process".to_string())
        }
    }
}

/// 通过驱动强制终止进程（内部逻辑，供沙箱模块等 Rust 代码调用）
/// 需要驱动防护运行中，向 SimpleLauncher 的命令管道发送 KILL_PROCESS 指令。
///
/// ★不能写成 `pub fn + #[tauri::command]`★
/// tauri 宏对 pub 函数会给生成的 `__cmd__xxx` 加 `#[macro_export]` 导出到 crate 根，
/// 随后 generate_handler! 再引用时宏命名空间重复定义 (E0255)。
/// 因此：内部逻辑放这里（普通 pub fn），Tauri command 是下方私有 wrapper。
#[cfg(not(feature = "ms_store"))]
pub fn kill_process_via_driver_internal(pid: u32) -> Result<(), String> {
    const CMD_PIPE_NAME: &str = r"\\.\pipe\XIGUASecurityCmd_";

    #[cfg(windows)]
    {
        use windows::Win32::Storage::FileSystem::CreateFileA;
        use windows::Win32::Storage::FileSystem::{OPEN_EXISTING, FILE_FLAG_OVERLAPPED};
        use windows::Win32::System::Pipes::WaitNamedPipeA;
        use windows::Win32::Foundation::CloseHandle;

        let pipe_name_c = std::ffi::CString::new(CMD_PIPE_NAME).unwrap();

        // 等待管道可用（最多 3 秒）
        unsafe {
            if WaitNamedPipeA(
                windows::core::PCSTR(pipe_name_c.as_ptr() as *const u8),
                3000,
            ).is_err() {
                return Err("驱动命令管道不可用，请确认驱动防护已启动".to_string());
            }
        }

        let handle = unsafe {
            CreateFileA(
                windows::core::PCSTR(pipe_name_c.as_ptr() as *const u8),
                windows::Win32::Storage::FileSystem::FILE_GENERIC_WRITE.0,
                windows::Win32::Storage::FileSystem::FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                None,
            )
        };

        match handle {
            Ok(h) => {
                let cmd = format!("KILL_PROCESS pid={}\n", pid);
                let cmd_bytes = cmd.as_bytes();

                // 使用 WriteFile 写入管道
                let mut written: u32 = 0;
                let write_result = unsafe {
                    windows::Win32::Storage::FileSystem::WriteFile(
                        h,
                        Some(cmd_bytes),
                        Some(&mut written),
                        None,
                    )
                };

                unsafe { let _ = CloseHandle(h); }

                if write_result.is_ok() && written > 0 {
                    println!("[DriverKill] Sent KILL_PROCESS for PID={} via driver pipe", pid);
                    Ok(())
                } else {
                    Err(format!("写入驱动命令管道失败: 写入 {} 字节", written))
                }
            }
            Err(e) => Err(format!("无法连接驱动命令管道: {:?}", e)),
        }
    }

    #[cfg(not(windows))]
    Err("仅 Windows 平台支持驱动终止进程".to_string())
}

/// 通过驱动强制终止进程（Tauri 命令，供前端调用）
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
fn kill_process_via_driver(pid: u32) -> Result<(), String> {
    kill_process_via_driver_internal(pid)
}

// 检查当前是否以管理员权限运行
#[tauri::command]
fn is_admin() -> bool {
    is_elevated()
}

// 检查是否以管理员权限运行（内部函数）
// 使用 OpenProcessToken + GetTokenInformation + TokenElevation
// IsUserAnAdmin 在 Win10/Win8 上通过 runas 提权时可能返回错误结果，
// 改用 TokenElevation 查询当前进程 token 的提权状态，更可靠。
#[cfg(windows)]
pub fn is_elevated() -> bool {
    unsafe {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};

        let mut token_handle = windows::Win32::Foundation::HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_err() {
            println!("[AdminCheck] OpenProcessToken failed");
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_len: u32 = 0;
        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_len,
        );

        let _ = CloseHandle(token_handle);

        let is_admin = result.is_ok() && elevation.TokenIsElevated != 0;
        println!("[AdminCheck] TokenElevation returned: {}", is_admin);
        is_admin
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

/// 智能进程启动：已提权时用 CreateProcessW（继承父进程权限），未提权时用 ShellExecuteW("runas")
///
/// **关键修复**：从提权进程调用 ShellExecuteW("runas") 会通过 COM 与非提权的 explorer.exe
/// 通信，UIPI 阻止高完整性→低完整性通信，导致 COM 调用挂起，STA 消息泵被冻结。
/// 已提权时改用 CreateProcessW 直接启动子进程（继承父进程的提权级别），
/// 完全绕过 Shell API 和 COM，避免 UIPI 死锁。
#[cfg(windows)]
fn launch_process_with_elevation(
    exe_path: &str,
    args: Option<&str>,
    working_dir: Option<&str>,
    show_cmd: u16,
) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    if is_elevated() {
        // 已提权：直接用 CreateProcessW 启动子进程，子进程继承父进程的提权级别
        // 完全不经过 Shell API，避免 COM/UIPI 死锁
        let mut cmd = std::process::Command::new(exe_path);
        if let Some(a) = args {
            for arg in shell_split_args(a) {
                cmd.arg(&arg);
            }
        }
        if let Some(dir) = working_dir {
            cmd.current_dir(dir);
        }
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        match cmd.spawn() {
            Ok(child) => {
                println!("[LaunchProcess] Created process (already elevated): {} PID={}", exe_path, child.id());
                Ok(())
            }
            Err(e) => {
                let msg = format!("CreateProcessW failed for '{}': {}", exe_path, e);
                eprintln!("[LaunchProcess] {}", msg);
                Err(msg)
            }
        }
    } else {
        // 未提权：使用 ShellExecuteW("runas") 触发 UAC 提权
        let exe_wide: Vec<u16> = exe_path.encode_utf16().chain(std::iter::once(0)).collect();
        let runas: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();
        let args_wide: Vec<u16> = match args {
            Some(a) => a.encode_utf16().chain(std::iter::once(0)).collect(),
            None => vec![0],
        };
        let dir_wide: Vec<u16> = match working_dir {
            Some(d) => d.encode_utf16().chain(std::iter::once(0)).collect(),
            None => vec![0],
        };

        unsafe {
            let result = ShellExecuteW(
                None,
                PCWSTR(runas.as_ptr()),
                PCWSTR(exe_wide.as_ptr()),
                PCWSTR(args_wide.as_ptr()),
                PCWSTR(dir_wide.as_ptr()),
                SHOW_WINDOW_CMD(show_cmd as i32),
            );

            if result.0 as usize <= 32 {
                let msg = format!("ShellExecuteW failed for '{}', code: {}", exe_path, result.0 as usize);
                eprintln!("[LaunchProcess] {}", msg);
                return Err(msg);
            }
            println!("[LaunchProcess] ShellExecuteW runas succeeded: {}", exe_path);
        }
        Ok(())
    }
}

/// 简单的命令行参数分割（不处理复杂引号嵌套，适用于路径和简单参数）
fn shell_split_args(args: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in args.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    result.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        result.push(current);
    }
    result
}

#[tauri::command]
fn minimize_window(window: Window) {
    let _ = window.minimize();
}

#[tauri::command]
fn maximize_window(window: Window) {
    let _ = window.maximize();
}

#[tauri::command]
fn close_window(window: Window) {
    // 先允许关闭，然后关闭窗口
    allow_window_close();
    let _ = window.close();
}

#[tauri::command]
fn start_drag(window: Window) {
    let _ = window.start_dragging();
}

#[tauri::command]
fn get_home_dir() -> Result<String, String> {
    dirs::home_dir()
        .map(|path| path.to_string_lossy().to_string())
        .ok_or_else(|| "Failed to get home directory".to_string())
}

// 检查必要文件完整性（启动时调用）
#[tauri::command]
fn check_essential_files() -> Vec<String> {
    let mut missing = Vec::new();
    
    // 获取可执行文件所在目录
    let exe_dir = match std::env::current_exe() {
        Ok(path) => path.parent().unwrap_or(&path).to_path_buf(),
        Err(_) => return vec!["无法获取程序目录".to_string()],
    };
    
    // 必要文件清单（相对 exe 目录）
    // 驱动核心文件
    let essential_paths = [
        // 安全防护驱动
        "Driver/XIGUAFileProtect.sys",
        "Driver/XIGUAEndPoint.sys",
        "Driver/XIGUASecurityAntiVirus.sys",
        "Driver/XIGUASelfProtect.sys",
        "Driver/XIGUASecurityAntiVirus.inf",
        // 辅助工具
        "Driver/XIGUASecurityAgent.exe",
        "Driver/MelixCloudScan_CLI.exe",
        // 扫描引擎（正常模式）
        "Driver/Melix/ZeroEngine.exe",
        // 扫描引擎（FLASH 模式）
        "Driver/Melix-Flash/ZeroEngine.exe",
    ];
    
    for rel_path in &essential_paths {
        let full_path = exe_dir.join(rel_path);
        if !full_path.exists() {
            missing.push(rel_path.to_string());
        }
    }
    
    missing
}

#[tauri::command]
async fn open_timeline_window(app: tauri::AppHandle) -> Result<(), String> {
    println!("[Timeline] Opening timeline window");

    // 窗口已存在则直接显示并聚焦，避免重复创建导致 label 冲突
    if let Some(existing) = app.get_webview_window("timeline") {
        println!("[Timeline] Window already exists, focusing it");
        force_window_foreground(&existing);
        return Ok(());
    }

    let window = tauri::WebviewWindowBuilder::new(
        &app,
        "timeline",
        tauri::WebviewUrl::App("timeline.html".into())
    )
    .title("防护时间线")
    .inner_size(900.0, 700.0)
    .decorations(true)
    .transparent(false)
    .shadow(true)
    .always_on_top(false)
    .skip_taskbar(false)
    .resizable(true)
    .visible(false)
    .build()
    .map_err(|e| format!("Failed to create timeline window: {}", e))?;
    
    // 设置窗口图标
    let icon = tauri::include_image!("icons/icon.png");
    let _ = window.set_icon(icon);

    // 使用 Win32 API 显示窗口并获取前台权限，绕过 Windows 前台锁
    force_window_foreground(&window);

    println!("[Timeline] Timeline window opened successfully");
    Ok(())
}

// 构建原生托盘菜单（替代 WebView 自定义窗口，避免主线程死锁）
fn build_tray_menu(app: &tauri::AppHandle) -> tauri::menu::Menu<tauri::Wry> {
    let show_main = MenuItem::with_id(app, "tray_show_main", "打开主界面", true, None::<&str>).expect("menu item");
    let quick_scan = MenuItem::with_id(app, "tray_quick_scan", "快速扫描", true, None::<&str>).expect("menu item");
    let custom_scan = MenuItem::with_id(app, "tray_custom_scan", "自定义扫描", true, None::<&str>).expect("menu item");
    let timeline = MenuItem::with_id(app, "tray_timeline", "时间线", true, None::<&str>).expect("menu item");
    let quarantine = MenuItem::with_id(app, "tray_quarantine", "隔离区", true, None::<&str>).expect("menu item");
    let settings = MenuItem::with_id(app, "tray_settings", "设置", true, None::<&str>).expect("menu item");
    let sep1 = PredefinedMenuItem::separator(app).expect("separator");
    let exit = MenuItem::with_id(app, "tray_exit", "退出", true, None::<&str>).expect("menu item");

    Menu::with_items(app, &[&show_main, &sep1, &quick_scan, &custom_scan, &timeline, &quarantine, &sep1, &settings, &exit]).expect("menu")
}

// 原生托盘菜单事件处理
fn on_tray_menu_event(app: &tauri::AppHandle, event: &MenuEvent) {
    let id = event.id().as_ref();
    println!("[Tray] Menu item clicked: {}", id);
    match id {
        "tray_show_main" => {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }
        "tray_quick_scan" => {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
                let _ = window.emit("navigate-to", "quick-scan");
            }
        }
        "tray_custom_scan" => {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
                let _ = window.emit("navigate-to", "custom-scan");
            }
        }
        "tray_timeline" => {
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let _ = open_timeline_window(app_handle).await;
            });
        }
        "tray_quarantine" => {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
                let _ = window.emit("navigate-to", "quarantine");
            }
        }
        "tray_settings" => {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
                let _ = window.emit("navigate-to", "settings");
            }
        }
        "tray_exit" => {
            // 退出前先经过安全桌面确认，防止恶意程序通过托盘直接关闭杀软
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let confirmed = show_secure_confirm_window(
                    &app_handle,
                    "退出 XIGUASecurity",
                    "您确定要退出西瓜杀毒吗？退出后所有防护将停止，您的计算机将失去保护。",
                    "tray_exit",
                ).await;
                if confirmed {
                    println!("[Tray] Exit confirmed from tray menu");
                    app_handle.exit(0);
                } else {
                    println!("[Tray] Exit cancelled from tray menu");
                }
            });
        }
        _ => {}
    }
}

// 全局变量跟踪托盘菜单窗口状态（已废弃，保留兼容）
static TRAY_MENU_OPEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn check_driver_process_running() -> Result<bool, ()> {
    // 在异步线程中执行进程检查，避免阻塞UI
    let result = tokio::task::spawn_blocking(|| {
        is_interceptor_running()
    }).await.unwrap_or(false);
    
    Ok(result)
}

// 设置窗口亚克力效果
#[cfg(windows)]
fn set_window_acrylic(hwnd: isize, alpha: u8) -> bool {
    unsafe {
        #[repr(C)]
        struct ACCENT_POLICY {
            AccentState: u32,
            AccentFlags: u32,
            GradientColor: u32,
            AnimationId: u32,
        }
        #[repr(C)]
        struct WINCOMPATTRDATA {
            Attribute: u32,
            Data: *const ACCENT_POLICY,
            DataSize: u32,
        }
        let gradient_color: u32 = ((alpha as u32) << 24) | 0xFB_F8_F8;
        let policy = ACCENT_POLICY {
            AccentState: 4,
            AccentFlags: 0x20,
            GradientColor: gradient_color,
            AnimationId: 0,
        };
        let mut data = WINCOMPATTRDATA {
            Attribute: 19,
            Data: &policy as *const _,
            DataSize: std::mem::size_of::<ACCENT_POLICY>() as u32,
        };
        type Fn = unsafe extern "system" fn(hwnd: isize, data: *mut WINCOMPATTRDATA) -> i32;
        if let Ok(user32) = windows::Win32::System::LibraryLoader::LoadLibraryW(windows::core::w!("user32.dll")) {
            if let Some(proc) = windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("SetWindowCompositionAttribute")) {
                let func: Fn = std::mem::transmute(proc);
                let result = func(hwnd, &mut data);
                println!("[Window] Acrylic set (alpha={}): result={}", alpha, result);
                return result != 0;
            }
        }
    }
    false
}

// 调节亚克力强度
#[cfg(windows)]
#[tauri::command]
async fn set_acrylic_intensity(window: tauri::Window, alpha: u8) -> Result<(), String> {
    let hwnd = window.hwnd().map_err(|e| e.to_string())?.0 as isize;
    let alpha = alpha.clamp(0, 255);
    set_window_acrylic(hwnd, alpha);
    println!("[Window] Acrylic intensity set to {}", alpha);
    Ok(())
}

// 禁用 SetWindowCompositionAttribute 模糊效果（切换材质前清理）
#[cfg(windows)]
fn disable_window_composition(hwnd: isize) -> bool {
    unsafe {
        #[repr(C)]
        struct ACCENT_POLICY {
            AccentState: u32,
            AccentFlags: u32,
            GradientColor: u32,
            AnimationId: u32,
        }
        #[repr(C)]
        struct WINCOMPATTRDATA {
            Attribute: u32,
            Data: *const ACCENT_POLICY,
            DataSize: u32,
        }
        let policy = ACCENT_POLICY {
            AccentState: 0, // ACCENT_DISABLED
            AccentFlags: 0,
            GradientColor: 0,
            AnimationId: 0,
        };
        let mut data = WINCOMPATTRDATA {
            Attribute: 19,
            Data: &policy as *const _,
            DataSize: std::mem::size_of::<ACCENT_POLICY>() as u32,
        };
        type Fn = unsafe extern "system" fn(hwnd: isize, data: *mut WINCOMPATTRDATA) -> i32;
        if let Ok(user32) = windows::Win32::System::LibraryLoader::LoadLibraryW(windows::core::w!("user32.dll")) {
            if let Some(proc) = windows::Win32::System::LibraryLoader::GetProcAddress(user32, windows::core::s!("SetWindowCompositionAttribute")) {
                let func: Fn = std::mem::transmute(proc);
                let result = func(hwnd, &mut data);
                println!("[Window] Composition disabled: result={}", result);
                return result != 0;
            }
        }
    }
    false
}

// 通过 DwmSetWindowAttribute 设置窗口背景材质（云母/亚克力/无）
#[cfg(windows)]
unsafe fn dwm_set_window_attribute(hwnd: isize, attr: u32, data: *const std::ffi::c_void, size: u32) -> i32 {
    type DwmFn = unsafe extern "system" fn(
        hwnd: *mut std::ffi::c_void,
        dwattribute: u32,
        pvattribute: *const std::ffi::c_void,
        cbattribute: u32,
    ) -> i32;
    if let Ok(dwmapi) = windows::Win32::System::LibraryLoader::LoadLibraryW(windows::core::w!("dwmapi.dll")) {
        if let Some(proc) = windows::Win32::System::LibraryLoader::GetProcAddress(dwmapi, windows::core::s!("DwmSetWindowAttribute")) {
            let func: DwmFn = std::mem::transmute(proc);
            return func(hwnd as *mut std::ffi::c_void, attr, data, size);
        }
    }
    0
}

#[cfg(windows)]
fn set_window_backdrop_internal(hwnd: isize, backdrop: &str, theme_mode: &str) -> bool {
    unsafe {
        // 切离亚克力时先清理旧的 ACCENT 模糊
        if backdrop != "acrylic" {
            disable_window_composition(hwnd);
        }

        // 亚克力继续走 SetWindowCompositionAttribute（效果更可控）
        if backdrop == "acrylic" {
            return set_window_acrylic(hwnd, 120);
        }

        // DWM 背景材质类型：1=NONE, 2=MICA(主窗口), 3=TRANSIENTWINDOW(系统亚克力), 4=TABBEDWINDOW(MicaAlt)
        let backdrop_type: u32 = match backdrop {
            "none" => 1,
            "mica" => 2,
            "micaAlt" => 4,
            _ => 1,
        };

        // 云母效果跟随当前主题：深色模式启用沉浸式深色，浅色/彩色模式关闭
        let dark_mode: i32 = if theme_mode == "dark" { 1 } else { 0 };
        dwm_set_window_attribute(
            hwnd,
            20, // DWMWA_USE_IMMERSIVE_DARK_MODE
            &dark_mode as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<i32>() as u32,
        );

        let result = dwm_set_window_attribute(
            hwnd,
            38, // DWMWA_SYSTEMBACKDROP_TYPE
            &backdrop_type as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
        );
        println!("[Window] Backdrop set to '{}', theme_mode='{}', dark_mode={}, result={}", backdrop, theme_mode, dark_mode, result);
        result != 0
    }
}

#[cfg(windows)]
#[tauri::command]
async fn set_window_backdrop(window: tauri::Window, backdrop: String, theme_mode: String) -> Result<(), String> {
    let hwnd = window.hwnd().map_err(|e| e.to_string())?.0 as isize;
    let valid = ["none", "acrylic", "mica", "micaAlt"];
    if !valid.contains(&backdrop.as_str()) {
        return Err(format!("Invalid backdrop type: {}", backdrop));
    }
    set_window_backdrop_internal(hwnd, &backdrop, &theme_mode);
    Ok(())
}

#[cfg(not(windows))]
#[tauri::command]
async fn set_window_backdrop(_window: tauri::Window, _backdrop: String, _theme_mode: String) -> Result<(), String> {
    Ok(())
}

// 检查内核隔离状态（内存完整性）
fn check_kernel_isolation_status() -> Result<bool, String> {
    // 使用 PowerShell 命令查询注册表，避免直接调用 Windows API
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            "try { $val = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -ErrorAction Stop; if ($val.Enabled -eq 1) { Write-Host '1' } else { Write-Host '0' } } catch { Write-Host '-1' }"
        ])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output();
    
    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("[KernelIsolation] PowerShell output: '{}'", stdout);
            match stdout.as_str() {
                "1" => Ok(true),   // 内核隔离已启用
                "0" => Ok(false),  // 内核隔离已禁用
                _ => {
                    println!("[KernelIsolation] Unexpected output: '{}'", stdout);
                    Err("无法读取内核隔离状态".to_string())
                }
            }
        }
        Err(e) => {
            println!("[KernelIsolation] PowerShell error: {}", e);
            Err(format!("执行PowerShell命令失败: {}", e))
        }
    }
}

// 检查驱动文件是否存在于系统目录
fn check_driver_file_exists() -> Result<bool, String> {
    let driver_paths = [
        "C:\\Windows\\System32\\drivers\\XIGUASecurityAntiVirus.sys",
        "C:\\Windows\\System32\\drivers\\XIGUAFileProtect.sys",
        "C:\\Windows\\System32\\drivers\\XIGUAEndPoint.sys",
        "C:\\Windows\\System32\\drivers\\XIGUASelfProtect.sys",
    ];
    
    for path in &driver_paths {
        if std::path::Path::new(path).exists() {
            return Ok(true);
        }
    }
    
    Ok(false)
}

// 检查 Agent 文件是否存在（当前程序目录 Driver/XIGUASecurityAgent.exe）
fn check_agent_file_exists() -> bool {
    let exe_dir = match std::env::current_exe() {
        Ok(path) => path.parent().unwrap_or(&path).to_path_buf(),
        Err(_) => return false,
    };
    // 常见位置：程序目录、程序目录/Driver、上级目录/Driver
    let candidates = [
        exe_dir.join("Driver").join("XIGUASecurityAgent.exe"),
        exe_dir.join("XIGUASecurityAgent.exe"),
    ];
    for p in &candidates {
        if p.exists() {
            return true;
        }
    }
    // 上级目录兜底
    if let Some(parent) = exe_dir.parent() {
        let up = parent.join("Driver").join("XIGUASecurityAgent.exe");
        if up.exists() {
            return true;
        }
    }
    false
}

// ==================== 驱动高级检查（sc start 提权） ====================

/// 高级检查结果
#[derive(serde::Serialize)]
struct AdvancedDriverCheckResult {
    log_path: String,
    error_code: Option<String>,
    exit_success: bool,
    message: String,
}

/// 高级检查：以管理员权限执行 `sc start AVDriver`，捕获错误码并写入日志文件。
/// 日志保存到 %LOCALAPPDATA%\XIGUASecurity\logs\driver_advanced_check.log。
/// 带超时保护：sc start 挂起时自动结束进程，避免界面无限等待。
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn advanced_driver_check() -> Result<AdvancedDriverCheckResult, String> {
    tokio::task::spawn_blocking(|| {
        // 日志目录
        let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
        let log_dir = format!("{}\\XIGUASecurity\\logs", local_app_data);
        let _ = std::fs::create_dir_all(&log_dir);
        let log_path = format!("{}\\driver_advanced_check.log", log_dir);

        // 将 PowerShell 脚本写入临时文件（避免 -Command 转义问题）
        // 日志路径直接硬编码进脚本（不用环境变量），保证 UAC 提权后的新进程也能正确写入
        let script_path = format!("{}\\driver_advanced_check.ps1", log_dir);
        let ps_script = format!(r#"
$ErrorActionPreference = 'Continue'
$logContent = @()
$logContent += "===== XIGUASecurity 驱动高级检查 ====="
$logContent += ("时间: " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$logContent += ("系统: " + $env:OS + " | Build: " + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber)
$logContent += "----------------------------------------"
try {{
    $output = sc.exe start AVDriver 2>&1
    $code = $LASTEXITCODE
    foreach ($line in $output) {{ $logContent += ("输出: " + $line) }}
    $logContent += ("sc start 退出码: " + $code)
    if ($code -eq 0) {{
        $logContent += "结果: 驱动服务启动成功"
    }} else {{
        $logContent += "结果: 驱动服务启动失败"
    }}
}} catch {{
    $logContent += ("异常: " + $_.Exception.Message)
}}
$logContent += "完成标记: DONE"
$logContent | Out-File -FilePath '{log_path}' -Encoding UTF8
"#, log_path = log_path.replace('\'', "''"));
        let _ = std::fs::write(&script_path, ps_script);

        // 已提权：直接执行；未提权：通过 runas 触发 UAC 提权执行
        if is_elevated() {
            // 当前已是管理员：直接运行，带超时 kill
            let mut child = match std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", &script_path])
                .env("OUTPUT_LOG", &log_path)
                .creation_flags(0x08000000) // CREATE_NO_WINDOW
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    let fallback = format!(
                        "===== XIGUASecurity 驱动高级检查 =====\n时间: {}\n无法启动 PowerShell: {}\n",
                        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                        e
                    );
                    let _ = std::fs::write(&log_path, fallback);
                    return Ok(AdvancedDriverCheckResult {
                        log_path,
                        error_code: None,
                        exit_success: false,
                        message: format!("无法启动 PowerShell: {}", e),
                    });
                }
            };

            // 最多等待 25 秒，超时后结束 PowerShell 进程
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(25);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => {
                        if std::time::Instant::now() >= deadline {
                            println!("[AdvancedDriverCheck] timeout, killing powershell");
                            let _ = child.kill();
                            let _ = child.wait();
                            let mut content = std::fs::read_to_string(&log_path).unwrap_or_default();
                            if !content.contains("完成标记: DONE") {
                                content.push_str("\n结果: 执行超时，已自动终止（sc start 可能无响应）\n完成标记: DONE\n");
                                let _ = std::fs::write(&log_path, content);
                            }
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                    Err(e) => {
                        println!("[AdvancedDriverCheck] try_wait error: {}", e);
                        break;
                    }
                }
            }
        } else {
            // 未提权：通过 runas 触发 UAC 提权执行，然后轮询日志文件等待完成标记
            unsafe {
                use windows::core::HSTRING;
                use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

                let operation = HSTRING::from("runas");
                let file = HSTRING::from("powershell.exe");
                let params = HSTRING::from(format!(
                    "-NoProfile -ExecutionPolicy Bypass -File \"{}\"",
                    script_path
                ));

                // 先写入"等待提权"标记，便于前端感知 UAC 弹窗阶段
                let _ = std::fs::write(
                    &log_path,
                    format!("===== XIGUASecurity 驱动高级检查 =====\n时间: {}\n状态: 等待管理员授权...\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S")),
                );

                let result = ShellExecuteW(
                    None,
                    &operation,
                    &file,
                    &params,
                    None,
                    SW_SHOWNORMAL,
                );
                let result_code = result.0 as usize;
                println!("[AdvancedDriverCheck] ShellExecuteW(runas) code: {}", result_code);

                if result_code <= 32 {
                    // UAC 启动失败（用户取消或系统拒绝）
                    let mut content = std::fs::read_to_string(&log_path).unwrap_or_default();
                    content.push_str(&format!("\n状态: 管理员授权失败（错误码 {}），请确认已同意 UAC 提示\n完成标记: DONE\n", result_code));
                    let _ = std::fs::write(&log_path, content);
                }
            }
        }

        // 等待日志文件出现完成标记（UAC 场景用户确认需要时间，最长等 60 秒）
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            if let Ok(content) = std::fs::read_to_string(&log_path) {
                if content.contains("完成标记: DONE") {
                    break;
                }
            }
            if std::time::Instant::now() >= deadline {
                if let Ok(mut content) = std::fs::read_to_string(&log_path) {
                    if !content.contains("完成标记: DONE") {
                        content.push_str("\n结果: 等待超时（60 秒），请检查是否已同意 UAC 授权\n完成标记: DONE\n");
                        let _ = std::fs::write(&log_path, content);
                    }
                }
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(300));
        }

        // 读取日志并提取 sc start 退出码
        let log_content = std::fs::read_to_string(&log_path).unwrap_or_default();
        let mut error_code: Option<String> = None;
        for line in log_content.lines() {
            if line.contains("sc start 退出码:") {
                error_code = line.split(":").nth(1).map(|s| s.trim().to_string());
                break;
            }
        }
        let timed_out = log_content.contains("超时");
        let uac_failed = log_content.contains("授权失败");

        let message = if uac_failed {
            "高级检查未执行：管理员授权失败或用户取消了 UAC 提示".to_string()
        } else if timed_out {
            "高级检查执行超时，已自动终止，请查看日志".to_string()
        } else {
            "高级检查已完成，日志已保存".to_string()
        };

        Ok(AdvancedDriverCheckResult {
            log_path,
            error_code,
            exit_success: !timed_out && !uac_failed,
            message,
        })
    }).await.map_err(|e| format!("高级检查任务失败: {}", e))?
}

/// 用系统默认程序打开指定文件/目录（ShellExecuteW，不依赖 opener 插件权限）
#[tauri::command]
fn open_file_path(path: String) -> Result<(), String> {
    #[cfg(windows)]
    {
        use windows::core::HSTRING;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        if path.trim().is_empty() {
            return Err("路径为空".to_string());
        }
        unsafe {
            let file = HSTRING::from(&path);
            let result = ShellExecuteW(
                None,
                &HSTRING::from("open"),
                &file,
                None,
                None,
                SW_SHOWNORMAL,
            );
            let code = result.0 as usize;
            if code <= 32 {
                return Err(format!("打开失败，错误码: {}", code));
            }
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Err("不支持当前平台".to_string())
    }
}

// 检查过滤器驱动注册状态（AVDriver 或 XIGUA 系列驱动）
fn check_filter_driver_registered() -> Result<bool, String> {
    // 使用 PowerShell 命令查询注册表，检查驱动是否已注册
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            "try { $val = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\AVDriver' -Name 'ImagePath' -ErrorAction Stop; if ($val.ImagePath) { Write-Host '1' } else { Write-Host '0' } } catch { Write-Host '0' }"
        ])
        .creation_flags(0x08000000)
        .output();
    
    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("[FilterDriver] Registered check output: '{}'", stdout);
            Ok(stdout == "1")
        }
        Err(e) => {
            println!("[FilterDriver] Registered check error: {}", e);
            Err(format!("检查驱动注册状态失败: {}", e))
        }
    }
}

// 检查过滤器驱动启动状态
fn check_filter_driver_started() -> Result<bool, String> {
    // 使用 PowerShell 命令查询驱动状态
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            "try { $service = Get-Service -Name 'AVDriver' -ErrorAction Stop; if ($service.Status -eq 'Running') { Write-Host '1' } else { Write-Host '0' } } catch { Write-Host '0' }"
        ])
        .creation_flags(0x08000000)
        .output();
    
    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("[FilterDriver] Started check output: '{}'", stdout);
            Ok(stdout == "1")
        }
        Err(e) => {
            println!("[FilterDriver] Started check error: {}", e);
            Err(format!("检查驱动启动状态失败: {}", e))
        }
    }
}

// 驱动防护诊断结果
#[derive(serde::Serialize)]
struct DriverDiagnosticsResult {
    kernel_isolation_enabled: bool,
    kernel_isolation_check_error: Option<String>,
    system_version_supported: bool,
    agent_file_exists: bool,
    process_running: bool,
    driver_file_exists: bool,
    driver_file_check_error: Option<String>,
    driver_registered: bool,
    driver_registered_check_error: Option<String>,
    driver_started: bool,
    driver_started_check_error: Option<String>,
}

#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn diagnose_driver_protection() -> Result<DriverDiagnosticsResult, String> {
    // 检查包含多次同步 PowerShell 调用（每次 0.2-2s），移入 spawn_blocking
    // 避免阻塞 async 运行时工作线程
    tokio::task::spawn_blocking(|| {
        // 检查内核隔离状态
        let (kernel_isolation_enabled, kernel_isolation_check_error) = match check_kernel_isolation_status() {
            Ok(enabled) => (enabled, None),
            Err(e) => (false, Some(e)),
        };
        
        // 检查系统版本：驱动不兼容 Windows 10，仅 Windows 11 及以上可加载
        let system_version_supported = is_windows_11();
        
        // 检查 Agent 文件是否存在（程序目录 Driver/XIGUASecurityAgent.exe）
        let agent_file_exists = check_agent_file_exists();
        
        // 检查进程是否运行
        let process_running = is_interceptor_running();
        
        // 检查驱动文件是否存在
        let (driver_file_exists, driver_file_check_error) = match check_driver_file_exists() {
            Ok(exists) => (exists, None),
            Err(e) => (false, Some(e)),
        };
        
        // 检查驱动是否已注册
        let (driver_registered, driver_registered_check_error) = match check_filter_driver_registered() {
            Ok(registered) => (registered, None),
            Err(e) => (false, Some(e)),
        };
        
        // 检查驱动是否已启动
        let (driver_started, driver_started_check_error) = match check_filter_driver_started() {
            Ok(started) => (started, None),
            Err(e) => (false, Some(e)),
        };
        
        Ok(DriverDiagnosticsResult {
            kernel_isolation_enabled,
            kernel_isolation_check_error,
            system_version_supported,
            agent_file_exists,
            process_running,
            driver_file_exists,
            driver_file_check_error,
            driver_registered,
            driver_registered_check_error,
            driver_started,
            driver_started_check_error,
        })
    }).await.map_err(|e| format!("诊断任务失败: {}", e))?
}

// 白名单 - 这些文件名不会被报毒
const WHITE_LIST: &[&str] = &[
    "nvAIDVC.dll",
    "Git-2.53.0.3-64-bit.exe",
];

#[tauri::command]
async fn get_scan_files() -> Result<Vec<String>, String> {
    // 目录遍历为同步阻塞操作（可能耗时数秒），移入 spawn_blocking
    // 避免阻塞 async 运行时工作线程导致其他命令排队延迟
    tokio::task::spawn_blocking(|| -> Result<Vec<String>, String> {
    let mut all_files = vec![];
    
    // 1. 扫描System32，但排除DriverStore
    let system32 = "C:/Windows/System32";
    let syswow64 = "C:/Windows/SysWOW64";
    
    for dir in [system32, syswow64] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let path_str = path.to_string_lossy().to_string();
                
                // 排除DriverStore目录
                if path_str.contains("DriverStore") {
                    continue;
                }
                
                if path.is_file() {
                    // 添加PE文件和压缩包
                    if let Some(ext) = path.extension() {
                        let ext = ext.to_string_lossy().to_lowercase();
                        if ["exe", "dll", "sys", "zip", "rar", "7z"].contains(&ext.as_str()) {
                            all_files.push(path_str);
                        }
                    }
                } else if path.is_dir() {
                    // 递归扫描子目录（排除DriverStore）
                    scan_dir_recursive(&path, &mut all_files);
                }
            }
        }
    }
    
    // 2. 扫描驱动目录
    for driver_dir in ["C:/Windows/System32/drivers", "C:/Windows/SysWOW64/drivers"] {
        scan_dir_recursive(std::path::Path::new(driver_dir), &mut all_files);
    }
    
    // 3. 扫描应用目录（排除 WindowsApps）
    for app_dir in ["C:/Program Files", "C:/ProgramData"] {
        if let Ok(entries) = std::fs::read_dir(app_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let path_name = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                // 跳过 WindowsApps 目录
                if path.is_dir() && path_name.eq_ignore_ascii_case("WindowsApps") {
                    continue;
                }
                if path.is_dir() {
                    scan_dir_recursive(&path, &mut all_files);
                }
            }
        }
    }
    
    // 4. 扫描临时目录
    scan_dir_recursive(std::path::Path::new("C:/Windows/Temp"), &mut all_files);
    scan_dir_recursive(&std::env::temp_dir(), &mut all_files);
    
    Ok(all_files)
    }).await.map_err(|e| format!("扫描任务失败: {}", e))?
}

/// 内存活动威胁扫描（快速扫描开局阶段）
///
/// 遍历系统进程表（优先 AVGuard 提权枚举，覆盖管理员进程），
/// 对每个运行中进程的镜像文件执行本地引擎扫描，
/// 命中威胁标记为「内存活动威胁」。
///
/// 返回 MemoryScanOutcome JSON: { source, total_processes, scanned, threats, errors }
/// ★不能写成 pub fn（tauri 宏对 pub 函数导出 __cmd__xxx 到 crate 根，与
/// generate_handler! 引用重复定义 E0255，见 kill_process_via_driver_internal 注释）★
#[tauri::command]
async fn scan_running_processes_command() -> Result<serde_json::Value, String> {
    scan_running_processes_impl().await
}

/// 内存活动威胁扫描实现（非 MS Store：AVGuard 提权枚举 + 本地引擎扫描）
#[cfg(not(feature = "ms_store"))]
async fn scan_running_processes_impl() -> Result<serde_json::Value, String> {
    tokio::task::spawn_blocking(|| {
        let outcome = crate::memory_scan::scan_running_processes();
        serde_json::to_value(&outcome).map_err(|e| format!("序列化失败: {}", e))
    })
    .await
    .map_err(|e| format!("内存威胁扫描任务失败: {}", e))?
}

/// 内存活动威胁扫描实现（MS Store 版本 stub — 无 AVGuard 提权进程，返回空结果）
#[cfg(feature = "ms_store")]
async fn scan_running_processes_impl() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "source": "none",
        "total_processes": 0,
        "scanned": 0,
        "threats": [],
        "errors": ["MS Store 版本不支持内存威胁扫描"],
    }))
}

// 递归扫描目录，排除DriverStore和WindowsApps
fn scan_dir_recursive(dir: &std::path::Path, files: &mut Vec<String>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let path_str = path.to_string_lossy().to_string();
            
            // 排除DriverStore目录
            if path_str.contains("DriverStore") {
                continue;
            }
            
            // 排除WindowsApps目录
            if path_str.contains("WindowsApps") {
                continue;
            }
            
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    let ext = ext.to_string_lossy().to_lowercase();
                    if ["exe", "dll", "sys", "zip", "rar", "7z"].contains(&ext.as_str()) {
                        files.push(path_str);
                        continue;
                    }
                }
                // EICAR 测试文件：文件名包含 "eicar" 即纳入扫描（不依赖扩展名）
                if path_str.to_lowercase().contains("eicar") {
                    files.push(path_str);
                }
            } else if path.is_dir() {
                scan_dir_recursive(&path, files);
            }
        }
    }
}

// 全盘扫描 - 扫描整个系统盘
#[tauri::command]
async fn get_full_scan_files() -> Result<Vec<String>, String> {
    // 全盘遍历为同步阻塞操作（可能耗时数十秒），移入 spawn_blocking
    // 避免阻塞 async 运行时工作线程
    tokio::task::spawn_blocking(|| -> Result<Vec<String>, String> {
    let mut all_files = vec![];
    
    // 全盘扫描：扫描所有可用盘符
    let c_drive = std::path::Path::new("C:/");
    if c_drive.exists() {
        scan_full_recursive(c_drive, &mut all_files);
    }
    
    // 动态检测所有可用盘符（D-Z）
    for drive_letter in 'D'..='Z' {
        let drive_path = format!("{}:\\", drive_letter);
        let path = std::path::Path::new(&drive_path);
        if path.exists() {
            scan_full_recursive(path, &mut all_files);
        }
    }
    
    Ok(all_files)
    }).await.map_err(|e| format!("全盘扫描任务失败: {}", e))?
}

// 全盘扫描递归函数
fn scan_full_recursive(dir: &std::path::Path, files: &mut Vec<String>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let path_str = path.to_string_lossy().to_string().to_lowercase();
            
            // 排除不需要扫描的目录
            let excluded_dirs = [
                "c:/windows/winsxs",
                "c:/windows/installer",
                "c:/windows/softwaredistribution",
                "c:/windows/prefetch",
                "c:/windows/logs",
                "c:/windows/driverstore",
                "c:/$recycle.bin",
                "c:/programdata",
                "c:/recovery",
                "c:/system volume information",
            ];
            
            if path.is_dir() {
                // 跳过排除的目录
                if excluded_dirs.iter().any(|d| path_str.starts_with(d)) {
                    continue;
                }
                // 递归扫描子目录
                scan_full_recursive(&path, files);
            } else if path.is_file() {
                // 扫描PE文件和压缩包
                if let Some(ext) = path.extension() {
                    let ext = ext.to_string_lossy().to_lowercase();
                    if ["exe", "dll", "sys", "drv", "ocx", "scr", "zip", "rar", "7z"].contains(&ext.as_str()) {
                        files.push(path.to_string_lossy().to_string());
                        continue;
                    }
                }
                // EICAR 测试文件：文件名包含 "eicar" 即纳入扫描（不依赖扩展名）
                if path_str.contains("eicar") {
                    files.push(path.to_string_lossy().to_string());
                }
            }
        }
    }
}

// 更新检查命令
#[tauri::command]
async fn check_update_command() -> Result<String, String> {
    match check_update().await {
        Ok(info) => serde_json::to_string(&info).map_err(|e| e.to_string()),
        Err(e) => Err(e)
    }
}

// 下载更新命令（带进度）
#[tauri::command]
async fn download_update_command(url: String, app_handle: tauri::AppHandle) -> Result<(), String> {
    download_and_install_with_progress(&url, &app_handle).await
}

// 获取当前版本命令
#[tauri::command]
fn get_version_command() -> String {
    get_current_version()
}

// 锁定威胁文件 - 通过独占打开文件来阻止其他程序访问
#[tauri::command]
async fn lock_threat_file(file_path: String) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;
        
        // 检查文件是否已经被锁定
        {
            let locked = LOCKED_FILES.lock().map_err(|e| e.to_string())?;
            for file in locked.iter() {
                // 简单检查：如果已经锁定了这个路径，就不再重复锁定
                // 实际比较需要更复杂的逻辑，这里简化处理
                let _ = file.metadata();
            }
        }
        
        // 以独占模式打开文件（不共享读、写、删除）
        // share_mode(0) 表示 FILE_SHARE_NONE - 完全独占
        let file = OpenOptions::new()
            .read(true)
            .share_mode(0) // 不共享任何权限
            .open(&file_path)
            .map_err(|e| format!("Failed to lock file: {}", e))?;
        
        // 将文件句柄保存到全局变量，保持文件被占用状态
        // 这样其他程序（包括资源管理器）都无法访问该文件
        {
            let mut locked = LOCKED_FILES.lock().map_err(|e| e.to_string())?;
            locked.push(file);
        }
        
        println!("[LockFile] File locked and occupied: {}", file_path);
    }
    
    Ok(())
}

// 发送拦截通知
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn send_intercept_notification(
    app: tauri::AppHandle,
    title: String,
    body: String,
    notification_type: Option<String>,
    source: Option<String>,
    file_name: Option<String>,
    file_path: Option<String>,
    resp_pipe: Option<String>,
) -> Result<(), String> {
    use notification::{NotificationOptions, NotificationType, NotificationSource};

    let ntype = match notification_type.as_deref() {
        Some("threat") => NotificationType::Threat,
        Some("safe") => NotificationType::Safe,
        Some("info") => NotificationType::Info,
        _ => NotificationType::Block,
    };

    let nsource = match source.as_deref() {
        Some("basic") => NotificationSource::Basic,
        Some("driver") => NotificationSource::Driver,
        _ => NotificationSource::Basic,
    };

    let mut options = NotificationOptions::new(ntype, title, body)
        .with_source(nsource);

    if let Some(name) = file_name {
        options = options.with_file(name, file_path.unwrap_or_default());
    } else if let Some(path) = file_path {
        options = options.with_file("", path);
    }

    if let Some(pipe) = resp_pipe {
        if !pipe.is_empty() {
            options = options.with_resp_pipe(pipe);
        }
    }

    notification::show_security_notification(&app, options)
}

// 显示拦截窗口
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn show_intercept_window(
    app: tauri::AppHandle,
    process_name: String,
    command_line: String,
    time: String,
    intercept_type: Option<String>,
) -> Result<(), String> {
    let intercept_type = intercept_type.unwrap_or_else(|| "驱动拦截".to_string());
    println!("[ShowInterceptWindow] Showing window for process: {} (Type: {})", process_name, intercept_type);

    // ===== 竞态条件修复：try_lock INTERCEPT_SHOW_LOCK + 设置 INTERCEPT_BUSY =====
    // 基础防护与驱动防护共享同一个 intercept-alert 窗口。
    // 原先只检查 INTERCEPT_BUSY 标志，但检查与显示之间存在 TOCTOU 竞态窗口：
    // 两条路径可能同时调用 force_window_visible，导致 AttachThreadInput 冲突、
    // 窗口状态混乱、emit 数据互相覆盖（resp_pipe 丢失）。
    // 修复：用 try_lock 原子化"检查 + 设置 BUSY"。一旦 BUSY 设置成功就释放锁，
    // 后续窗口操作不再持有锁（避免阻塞 tokio worker 或驱动防护路径）。
    {
        let _show_guard = match INTERCEPT_SHOW_LOCK.get_or_init(|| StdMutex::new(())).try_lock() {
            Ok(g) => g,
            Err(_) => {
                println!("[ShowInterceptWindow] Show lock held (driver intercept active), skipping: {}", process_name);
                return Ok(());
            }
        };
        if INTERCEPT_BUSY.load(Ordering::SeqCst) {
            println!("[ShowInterceptWindow] Driver intercept busy, skipping basic-protection window for: {}", process_name);
            return Ok(());
        }

        // ===== 基础防护模式下必须设置 INTERCEPT_BUSY =====
        // 驱动防护在 show_next_intercept 中设置 INTERCEPT_BUSY，
        // 基础防护也需要设置以防止：
        // 1. 驱动防护通知抢占窗口数据导致 currentRespPipe 混乱
        // 2. 多个基础防护同时打开窗口
        // 3. 关闭后状态残留卡住后续所有操作
        INTERCEPT_BUSY.store(true, Ordering::SeqCst);
        INTERCEPT_BUSY_SINCE.store(chrono::Local::now().timestamp(), Ordering::SeqCst);
        INTERCEPT_WINDOW_CLAIMED.store(true, Ordering::SeqCst);
        // _show_guard 在此处释放，后续窗口操作不持有锁
    }

    // ★历史 bug 安全网：基础防护模式下，INTERCEPT_BUSY 只由前端 close_intercept_window
    // 调用清除。若主线程被阻塞（如旧版 run_on_main_thread），invoke 永远无法到达，
    // INTERCEPT_BUSY 永远为 true → 所有后续拦截跳过 + 程序卡死。
    // ★修复：tokio::spawn 一个 30 秒超时兜底，到期自动重置 BUSY。
    // 无等待者注册（基础防护无需决策管道），直接重置状态。
    let app_timeout = app.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        if INTERCEPT_BUSY.load(Ordering::SeqCst) {
            eprintln!("[ShowInterceptWindow] Basic-protection timeout (30s), force resetting INTERCEPT_BUSY");
            INTERCEPT_BUSY.store(false, Ordering::SeqCst);
            INTERCEPT_BUSY_SINCE.store(0, Ordering::SeqCst);
            INTERCEPT_WINDOW_CLAIMED.store(false, Ordering::SeqCst);
            hide_intercept_window(&app_timeout);
        }
    });

    // ===== 复用预创建窗口，绝不 close() 销毁 =====
    // 历史卡死根因：close() 销毁共享 intercept-alert 窗口后，下一次驱动拦截
    // 只能走"主线程 dispatch + 同步 eval"兜底路径，WebView 未就绪时 eval 会
    // 阻塞主线程，导致整个 UI（关闭/最小化/托盘/所有按钮）无响应、只剩窗口骨架。
    // 数据填充统一用线程安全 emit（intercept-alert.html 已注册 intercept-data 监听）。
    let payload = serde_json::json!({
        "time": time,
        "type": intercept_type,
        "process": process_name,
        "command": command_line,
        "source": "basic_protection",
    });

    // 窗口已存在：emit + 纯 Win32 显示（跨线程安全，不依赖主线程）
    if let Some(win) = app.get_webview_window("intercept-alert") {
        let _ = win.emit("intercept-data", payload);
        force_window_visible(&win);
        // ★历史 bug：移除 run_on_main_thread(win.show())，见 show_next_intercept 注释
        println!("[ShowInterceptWindow] Reused existing window, emitted data");
        return Ok(());
    }

    // 窗口不存在（极少见）：dispatch 到主线程动态创建（不 eval），创建后 emit 补数据
    let app_clone = app.clone();
    let _ = app.run_on_main_thread(move || {
        let _ = show_intercept_window_on_main(&app_clone, &InterceptItem {
            intercept_type: "基础防护拦截".to_string(),
            process_name: String::new(),
            file_path: String::new(),
            resp_pipe: String::new(),
            threat_info: String::new(),
            default_block: false,
        }, "");
    });

    // 轮询等待窗口出现（最多 5 秒；get_webview_window 是纯查表，不依赖主线程）
    for _ in 0..50 {
        if let Some(win) = app.get_webview_window("intercept-alert") {
            force_window_visible(&win);
            let _ = win.emit("intercept-data", payload);
            println!("[ShowInterceptWindow] Window created, data emitted");
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // 创建失败：重置拦截状态，防止 INTERCEPT_BUSY 残留卡死后续所有操作
    INTERCEPT_BUSY.store(false, Ordering::SeqCst);
    INTERCEPT_BUSY_SINCE.store(0, Ordering::SeqCst);
    INTERCEPT_WINDOW_CLAIMED.store(false, Ordering::SeqCst);
    eprintln!("[ShowInterceptWindow] Failed to create window within 5s");
    Ok(())
}

// 关闭拦截窗口命令：改为隐藏复用，绝不销毁窗口
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn close_intercept_window(app: tauri::AppHandle) -> Result<(), String> {
    println!("[CloseInterceptWindow] Hiding intercept window (reuse, not destroy)");
    // 历史 bug：window.close() 会销毁共享 intercept-alert 窗口，下一次拦截只能
    // 走"主线程 dispatch + eval"兜底路径，存在主线程卡死风险。
    // 改为纯 Win32 隐藏复用，窗口生命周期与主程序一致。
    // 基础防护路径：释放 INTERCEPT_BUSY，防止状态残留卡死后续所有拦截操作
    INTERCEPT_BUSY.store(false, Ordering::SeqCst);
    INTERCEPT_BUSY_SINCE.store(0, Ordering::SeqCst);
    INTERCEPT_WINDOW_CLAIMED.store(false, Ordering::SeqCst);
    hide_intercept_window(&app);
    // ★历史 bug：close_intercept_window 仅重置 INTERCEPT_BUSY 但不消费队列。
    // 若 show_next_intercept 之前因 BUSY=true 提前返回，队列中的拦截项被跳过，
    // 后续所有拦截窗口无法弹出。此处主动拉取队列下一个。
    // show_next_intercept 是阻塞函数（内部有 recv_timeout 30s），
    // 不能直接在 tokio 线程上调用，必须 spawn 独立线程。
    let app_clone = app.clone();
    std::thread::spawn(move || {
        crate::show_next_intercept(&app_clone);
    });
    Ok(())
}

/// 前端调用：直接调整拦截窗口高度并重新定位
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn resize_intercept_window(app: tauri::AppHandle, height: f64) -> Result<(), String> {
    let min_h = 340.0_f64.max(height.min(680.0));
    println!("[InterceptWin] resize_intercept_window: height={}", min_h);

    // 尝试找到拦截窗口（intercept-alert 配置窗口）
    let window = app.get_webview_window("intercept-alert")
        .or_else(|| app.get_webview_window("intercept-driver-win"));
    let window = match window {
        Some(w) => w,
        None => {
            eprintln!("[InterceptWin] Window not found for resize");
            return Err("Intercept window not found".to_string());
        }
    };

    // 调整窗口高度并定位到右下角。
    // 用 Tauri 原生 set_size(Logical)/set_position(Logical)——Tauri 内部正确处理
    // 高 DPI 缩放（win32 SetWindowPos 物理像素换算在 WebView 高 DPI 下会失真，
    // 导致窗口"非常非常小"+滚动条）。
    // ===== 关键修复：用 run_on_main_thread 避免阻塞 tokio worker =====
    // set_size/set_position 是同步 Tauri 调用，在 tokio worker 上直接调用会
    // 阻塞等待主线程处理。如果主线程繁忙（如处理 run_on_main_thread 队列），
    // tokio worker 被卡住，导致所有 async 命令（自定义扫描、EDR、系统修复等）
    // 无响应。改用 run_on_main_thread（fire-and-forget）避免阻塞。
    let monitor_info = window.primary_monitor().ok().flatten();
    let win_clone = window.clone();
    let _ = app.run_on_main_thread(move || {
        let _ = win_clone.set_size(tauri::Size::Logical(tauri::LogicalSize { width: 360.0, height: min_h }));
        if let Some(monitor) = monitor_info {
            let mp = monitor.position();
            let ms = monitor.size();
            let phys_w = (360.0 * monitor.scale_factor()) as i32;
            let phys_h = (min_h * monitor.scale_factor()) as i32;
            let pad_r = (20.0 * monitor.scale_factor()) as i32;
            let pad_b = (80.0 * monitor.scale_factor()) as i32;
            let x = mp.x + ms.width as i32 - phys_w - pad_r;
            let y = mp.y + ms.height as i32 - phys_h - pad_b;
            println!("[InterceptWin] Position: x={} y={} (monitor {}x{} @{}x{})", x, y, ms.width, ms.height, mp.x, mp.y);
            let _ = win_clone.set_position(tauri::Position::Physical(tauri::PhysicalPosition { x, y }));
        }
        println!("[InterceptWin] Resized to 360x{} via main thread", min_h);
    });

    Ok(())
}

/// 前端调用：强制重置 INTERCEPT_BUSY（前端 sendDecision 失败时调用，防止卡死）
/// 同步模型下：重置标志并唤醒所有等待中的弹窗线程（默认放行），
/// 使弹窗线程立即写决策回管道、关闭窗口、进入下一轮通知处理。
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn reset_intercept_busy(app: tauri::AppHandle) -> Result<(), String> {
    println!("[ResetInterceptBusy] Force resetting INTERCEPT_BUSY");
    INTERCEPT_BUSY.store(false, Ordering::SeqCst);
    INTERCEPT_BUSY_SINCE.store(0, Ordering::SeqCst);
    INTERCEPT_WINDOW_CLAIMED.store(false, Ordering::SeqCst);

    // 唤醒所有等待者（默认放行），避免弹窗线程空等 30 秒
    if let Some(waiters) = AV_DECISION_WAITERS.get() {
        let keys: Vec<String> = waiters.lock().unwrap().keys().cloned().collect();
        for key in keys {
            let decision = build_default_decision(&key);
            let tx = waiters.lock().unwrap().remove(&key);
            if let Some(tx) = tx {
                let _ = tx.send(decision);
            }
        }
    }

    // 若拦截窗口存在则隐藏（弹窗线程可能已退出，窗口残留）。
    // 纯 Win32 立即隐藏 + dispatch 同步 Tauri 状态
    hide_intercept_window(&app);

    Ok(())
}

/// 查询当前用户态 always 规则（"始终允许/始终拦截"列表，应用重启后清空）
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
fn get_always_rules() -> Vec<serde_json::Value> {
    let rules = INTERCEPT_ALWAYS_RULES.get_or_init(|| StdMutex::new(Vec::new()));
    let guard = rules.lock().unwrap();
    guard.iter()
        .map(|(t, p, d)| serde_json::json!({ "type": t, "path": p, "decision": d }))
        .collect()
}

/// 清除所有用户态 always 规则（重启应用也会自动清空）
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
fn clear_always_rules() -> usize {
    let rules = INTERCEPT_ALWAYS_RULES.get_or_init(|| StdMutex::new(Vec::new()));
    let mut guard = rules.lock().unwrap();
    let count = guard.len();
    guard.clear();
    println!("[AlwaysRule] Cleared {} rules", count);
    count
}

/// 移除单条用户态 always 规则
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
fn remove_always_rule(rule_type: String, path: String) -> bool {
    let rules = INTERCEPT_ALWAYS_RULES.get_or_init(|| StdMutex::new(Vec::new()));
    let mut guard = rules.lock().unwrap();
    let before = guard.len();
    guard.retain(|(t, p, _)| !(t == &rule_type && p == &path));
    let removed = guard.len() != before;
    println!("[AlwaysRule] Removed: type={} path={} success={}", rule_type, path, removed);
    removed
}

// 关闭 EDR 告警窗口命令
#[tauri::command]
async fn close_edr_alert_window(app: tauri::AppHandle) -> Result<(), String> {
    println!("[CloseEDRAlert] Closing EDR alert window");
    if let Some(window) = app.get_webview_window("edr-alert") {
        window.close().map_err(|e| format!("Failed to close window: {}", e))?;
        println!("[CloseEDRAlert] Window closed successfully");
    } else {
        println!("[CloseEDRAlert] Window not found");
    }
    Ok(())
}

// 关闭 EDR 告警并触发快速扫描
#[tauri::command]
async fn close_edr_alert_and_start_scan(app: tauri::AppHandle) -> Result<(), String> {
    println!("[CloseEDRAlert] Closing EDR alert and starting quick scan");
    if let Some(window) = app.get_webview_window("edr-alert") {
        let _ = window.close();
    }
    let _ = app.emit("edr-start-quick-scan", ());
    Ok(())
}

// 显示 EDR 行为链拓扑窗口命令
#[tauri::command]
async fn show_edr_behavior_chain(app: tauri::AppHandle, process: String, _path: String,
                                   score: i32, pid: i32, parent: i32, code: String) -> Result<(), String> {
    println!("[ShowEDRChain] Opening behavior chain for process: {}, score: {}", process, score);

    // 关闭已存在的窗口
    if let Some(existing) = app.get_webview_window("edr-behavior-chain") {
        let _ = existing.close();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // 只传递关键标识参数，完整数据由前端加载后调用 get_edr_report_data 获取
    let url = format!(
        "edr-behavior-chain.html?process={}&pid={}&parent={}&code={}&score={}",
        urlencoding::encode(&process),
        pid,
        parent,
        urlencoding::encode(&code),
        score
    );

    match tauri::WebviewWindowBuilder::new(
        &app,
        "edr-behavior-chain",
        tauri::WebviewUrl::App(url.into())
    )
    .title("EDR 行为链拓扑")
    .inner_size(1000.0, 680.0)
    .decorations(true)
    .resizable(true)
    .build() {
        Ok(window) => {
            let _ = window.show();
            let _ = window.set_focus();
            println!("[ShowEDRChain] Window shown");
            Ok(())
        }
        Err(e) => {
            eprintln!("[ShowEDRChain] Failed to create window: {}", e);
            Err(format!("Failed to create window: {}", e))
        }
    }
}

// 列出 EDR 历史报告
#[tauri::command]
async fn list_edr_reports() -> Result<String, String> {
    use serde::Serialize;

    #[derive(Serialize)]
    struct ReportItem {
        file_name: String,
        report_code: String,
        process_name: String,
        pid: i32,
        total_score: i32,
        result: String,
        report_time: String,
    }

    let mut reports: Vec<ReportItem> = Vec::new();
    let candidates = collect_edr_report_candidates();

    for (path, _) in candidates {
        let fname = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // 轻量解析头部
        let mut report_code = String::new();
        let mut process_name = String::new();
        let mut pid = 0i32;
        let mut total_score = 0i32;
        let mut result = String::new();
        let mut report_time = String::new();

        for line in content.lines().take(30) {
            let trimmed = line.trim();
            if let Some(v) = parse_value_after_colon(trimmed, "Report Code") { report_code = v; report_time = parse_report_time_from_code(&report_code); }
            else if let Some(v) = parse_value_after_colon(trimmed, "报告编码") { report_code = v; report_time = parse_report_time_from_code(&report_code); }
            else if let Some(v) = parse_value_after_colon(trimmed, "Process Name") { process_name = v; }
            else if let Some(v) = parse_value_after_colon(trimmed, "进程名称") { process_name = v; }
            else if let Some(v) = parse_value_after_colon(trimmed, "PID") { if let Ok(p) = v.parse::<i32>() { pid = p; } }
            else if let Some(v) = parse_value_after_colon(trimmed, "进程PID") { if let Ok(p) = v.parse::<i32>() { pid = p; } }
            else if let Some(v) = parse_value_after_colon(trimmed, "Result") { result = v; }
            else if let Some(v) = parse_value_after_colon(trimmed, "处理结果") { result = v; }
            else if trimmed.starts_with("Total Score") || trimmed.starts_with("总评分") {
                if let Some(v) = parse_number_before_slash(trimmed) { total_score = v; }
            }
        }

        reports.push(ReportItem {
            file_name: fname,
            report_code,
            process_name,
            pid,
            total_score,
            result,
            report_time,
        });
    }

    if reports.is_empty() {
        let mut searched: Vec<String> = Vec::new();
        if let Ok(local) = std::env::var("LOCALAPPDATA") { searched.push(format!("{}\\XIGUASecurity\\EDRReports", local)); }
        if let Ok(pd) = std::env::var("PROGRAMDATA") { searched.push(format!("{}\\XIGUASecurity\\EDRReports", pd)); }
        if let Ok(cwd) = std::env::current_dir() { searched.push(cwd.to_string_lossy().to_string()); }
        if let Ok(exe) = std::env::current_exe() { if let Some(p) = exe.parent() { searched.push(p.to_string_lossy().to_string()); } }
        if let Ok(cwd) = std::env::current_dir() { if let Some(p) = cwd.parent() { searched.push(p.to_string_lossy().to_string()); } }
        return Err(format!("未找到 EDR 报告文件。已搜索以下路径: {}", searched.join("; ")));
    }

    // 按时间倒序
    reports.sort_by(|a, b| b.report_time.cmp(&a.report_time));

    match serde_json::to_string(&reports) {
        Ok(s) => Ok(s),
        Err(e) => Err(format!("Failed to serialize reports: {}", e)),
    }
}

// 获取 EDR 报告完整数据
#[tauri::command]
async fn get_edr_report_data(process: String, pid: i32, code: String) -> Result<String, String> {
    println!("[GetEDRReportData] pid={}, process={}, code={}", pid, process, code);
    let data = read_edr_report_file(pid, &process, &code);

    // Convert to serde_json
    #[derive(serde::Serialize)]
    struct TimelineEventJson {
        seq: i32,
        datetime: String,
        relative_sec: String,
        code: String,
        type_cn: String,
        type_en: String,
        detail: String,
    }

    #[derive(serde::Serialize)]
    struct ReportDataJson {
        report_code: String,
        process_name: String,
        process_path: String,
        pid: i32,
        parent_pid: i32,
        parent_path: String,
        command_line: String,
        lolbins: bool,
        result: String,
        total_score: i32,
        threshold: i32,
        file_writes: i32,
        file_deletes: i32,
        registry_mods: i32,
        inject_attempts: i32,
        suspicious_cmds: i32,
        memory_rwx: i32,
        remote_threads: i32,
        image_loads: i32,
        report_time: String,
        virus_family: String,
        ioa_families: Vec<(String, i32)>,
        timeline: Vec<TimelineEventJson>,
    }

    let family = infer_edr_family(&data);
    let json = ReportDataJson {
        report_code: data.report_code,
        process_name: data.process_name,
        process_path: data.process_path,
        pid: data.pid,
        parent_pid: data.parent_pid,
        parent_path: data.parent_path,
        command_line: data.command_line,
        lolbins: data.lolbins,
        result: data.result,
        total_score: data.total_score,
        threshold: data.threshold,
        file_writes: data.file_writes,
        file_deletes: data.file_deletes,
        registry_mods: data.registry_mods,
        inject_attempts: data.inject_attempts,
        suspicious_cmds: data.suspicious_cmds,
        memory_rwx: data.memory_rwx,
        remote_threads: data.remote_threads,
        image_loads: data.image_loads,
        report_time: data.report_time,
        virus_family: family,
        ioa_families: data.ioa_families.clone(),
        timeline: data.timeline.into_iter().map(|e| TimelineEventJson {
            seq: e.seq,
            datetime: e.datetime,
            relative_sec: e.relative_sec,
            code: e.code,
            type_cn: e.type_cn,
            type_en: e.type_en,
            detail: e.detail,
        }).collect(),
    };

    match serde_json::to_string(&json) {
        Ok(s) => Ok(s),
        Err(e) => Err(format!("Failed to serialize report data: {}", e)),
    }
}

/// EDR 报告数据结构
#[derive(Clone, Debug)]
struct EdrTimelineEvent {
    seq: i32,
    datetime: String,
    relative_sec: String,
    code: String,
    type_cn: String,
    type_en: String,
    detail: String,
}

#[derive(Clone, Debug)]
struct EdrReportData {
    report_code: String,
    process_name: String,
    process_path: String,
    pid: i32,
    parent_pid: i32,
    parent_path: String,
    command_line: String,
    lolbins: bool,
    result: String,
    total_score: i32,
    threshold: i32,
    file_writes: i32,
    file_deletes: i32,
    registry_mods: i32,
    inject_attempts: i32,
    suspicious_cmds: i32,
    memory_rwx: i32,
    remote_threads: i32,
    image_loads: i32,
    report_time: String,
    timeline: Vec<EdrTimelineEvent>,
    ioa_families: Vec<(String, i32)>,
}

impl Default for EdrReportData {
    fn default() -> Self {
        Self {
            report_code: String::new(),
            process_name: String::new(),
            process_path: String::new(),
            pid: 0,
            parent_pid: 0,
            parent_path: String::new(),
            command_line: String::new(),
            lolbins: false,
            result: String::new(),
            total_score: 0,
            threshold: 100,
            file_writes: 0,
            file_deletes: 0,
            registry_mods: 0,
            inject_attempts: 0,
            suspicious_cmds: 0,
            memory_rwx: 0,
            remote_threads: 0,
            image_loads: 0,
            report_time: String::new(),
            timeline: Vec::new(),
            ioa_families: Vec::new(),
        }
    }
}

/// 读取 EDR 报告文件，解析完整行为数据和时间线
fn read_edr_report_file(pid: i32, process_name: &str, report_code_hint: &str) -> EdrReportData {
    let mut data = EdrReportData::default();
    data.pid = pid;
    data.process_name = process_name.to_string();

    let candidates = collect_edr_report_candidates();
    if candidates.is_empty() {
        println!("[ReadEDRReport] No EDR report files found in any search path");
        return data;
    }

    let mut best_file: Option<std::path::PathBuf> = None;

    // 如果传了 report_code_hint，优先读取文件内容匹配 Report Code
    if !report_code_hint.is_empty() {
        for (path, _) in &candidates {
            if let Ok(content) = std::fs::read_to_string(path) {
                if content.contains(report_code_hint) {
                    println!("[ReadEDRReport] Matched by report code: {}", path.display());
                    best_file = Some(path.clone());
                    break;
                }
            }
        }
    }

    // 未匹配到 code，则按 pid + process_name 匹配文件名
    if best_file.is_none() {
        let new_pid_pattern = format!("PID{}_", pid);
        let old_pid_pattern = format!("_{}_", pid);
        for (path, _) in &candidates {
            let fname = path.file_name().unwrap_or_default().to_string_lossy().to_string();
            if !fname.contains(&new_pid_pattern) && !fname.contains(&old_pid_pattern) {
                continue;
            }
            if !process_name.is_empty() && !fname.to_lowercase().contains(&process_name.to_lowercase()) {
                continue;
            }
            best_file = Some(path.clone());
            println!("[ReadEDRReport] Matched by pid/process filename: {}", path.display());
            break;
        }
    }

    // 最后兜底：取最新的 EDR_*.txt
    if best_file.is_none() {
        best_file = candidates.into_iter().map(|(p, _)| p).next();
        if let Some(ref p) = best_file {
            println!("[ReadEDRReport] Fallback to latest file: {}", p.display());
        }
    }

    let file_path = match best_file {
        Some(f) => f,
        None => return data,
    };

    println!("[ReadEDRReport] Reading report file: {}", file_path.display());

    let content = match std::fs::read_to_string(&file_path) {
        Ok(c) => c,
        Err(_) => return data,
    };

    parse_edr_report_content(&content, &mut data);
    data
}

/// 收集所有可能的 EDR 报告文件路径
fn collect_edr_report_candidates() -> Vec<(std::path::PathBuf, u64)> {
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();

    // 1. LOCALAPPDATA\XIGUASecurity\EDRReports (旧版 SimpleLauncher)
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        dirs.push(std::path::PathBuf::from(format!("{}\\XIGUASecurity\\EDRReports", local)));
    }

    // 2. PROGRAMDATA\XIGUASecurity\EDRReports (新 KMDF 驱动 EDRTracker.c)
    if let Ok(pd) = std::env::var("PROGRAMDATA") {
        dirs.push(std::path::PathBuf::from(format!("{}\\XIGUASecurity\\EDRReports", pd)));
    }

    // 3. PROGRAMDATA\XIGUASecurity\Reports (新 XIGUASecurityAgent 行为链报告)
    if let Ok(pd) = std::env::var("PROGRAMDATA") {
        dirs.push(std::path::PathBuf::from(format!("{}\\XIGUASecurity\\Reports", pd)));
    }

    // 4. 自定义环境变量路径
    if let Ok(custom) = std::env::var("XIGUA_EDR_REPORT_DIR") {
        dirs.push(std::path::PathBuf::from(custom));
    }

    // 5. 当前工作目录
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd);
    }

    // 6. 程序 exe 所在目录
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            dirs.push(parent.to_path_buf());
        }
    }

    // 去重
    let mut seen = std::collections::HashSet::new();
    let mut candidates: Vec<(std::path::PathBuf, u64)> = Vec::new();
    for dir in dirs {
        if seen.contains(&dir) { continue; }
        seen.insert(dir.clone());
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                // 搜索 .txt (EDRTracker) 和 .log (XIGUASecurityAgent) 文件
                if !fname.ends_with(".txt") && !fname.ends_with(".log") {
                    continue;
                }
                // 放宽匹配：文件名以 EDR_ 开头，或者内容包含 Report Code/报告编码/报告 ID/行为链
                let is_edr_name = fname.starts_with("EDR_") || fname.to_lowercase().contains("edr");
                if !is_edr_name {
                    // 快速读取内容确认
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        let preview = content.chars().take(500).collect::<String>();
                        if !preview.contains("Report Code")
                            && !preview.contains("报告编码")
                            && !preview.contains("报告 ID")
                            && !preview.contains("行为链")
                            && !preview.contains("端点防护") {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
                if let Ok(meta) = entry.metadata() {
                    if let Ok(modified) = meta.modified() {
                        let t = modified.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                        candidates.push((entry.path(), t));
                    }
                }
            }
        }
    }

    // 按修改时间降序
    candidates.sort_by(|a, b| b.1.cmp(&a.1));
    candidates
}

fn parse_edr_report_content(content: &str, data: &mut EdrReportData) {
    let mut in_summary = false;
    let mut in_timeline = false;
    let mut in_old_detail = false;
    let mut in_behavior_analysis = false;
    let mut old_detail_lines: Vec<String> = Vec::new();
    let mut behavior_analysis_lines: Vec<String> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() {
            in_old_detail = false;
            continue;
        }

        // 区域标记（中英文）
        if trimmed.starts_with("Behavior Summary") || trimmed.starts_with("行为评分摘要") || trimmed.starts_with("---------- 行为评分摘要") {
            in_summary = true;
            in_timeline = false;
            in_old_detail = false;
            continue;
        }
        if trimmed.contains("Timeline") || trimmed.contains("行为链时间线") || trimmed.contains("Chronological") || trimmed.starts_with("[完整行为链") {
            in_summary = false;
            in_timeline = true;
            in_old_detail = false;
            continue;
        }
        if trimmed.starts_with("MITRE ATT&CK") || trimmed.starts_with("最近活动详情") || trimmed.starts_with("---------- 最近活动详情") {
            in_summary = false;
            in_timeline = false;
            in_old_detail = trimmed.contains("最近活动详情");
            in_behavior_analysis = false;
            continue;
        }
        if trimmed.contains("行为链分析") {
            in_summary = false;
            in_timeline = false;
            in_old_detail = false;
            in_behavior_analysis = true;
            continue;
        }
        // XIGUASecurityAgent 报告区域标记
        if trimmed.starts_with("[基本信息]") || trimmed.starts_with("[IOA 检测原因") || trimmed.starts_with("[处置结果]") {
            in_summary = false;
            in_timeline = false;
            in_old_detail = false;
            in_behavior_analysis = false;
            continue;
        }

        // 旧格式：最近活动详情内容
        if in_old_detail && !trimmed.starts_with("=") && !trimmed.starts_with("-") {
            old_detail_lines.push(trimmed.to_string());
            continue;
        }

        // 行为链分析内容（C 驱动格式，无时间线时作为备选）
        if in_behavior_analysis {
            if trimmed.starts_with("=") || trimmed.starts_with("报告结束") {
                in_behavior_analysis = false;
            } else {
                behavior_analysis_lines.push(trimmed.to_string());
            }
            continue;
        }

        // 基础字段解析（中英文）
        if let Some(v) = parse_value_after_colon(trimmed, "Report Code") { data.report_code = v.clone(); data.report_time = parse_report_time_from_code(&v); }
        else if let Some(v) = parse_value_after_colon(trimmed, "报告编码") { data.report_code = v.clone(); data.report_time = parse_report_time_from_code(&v); }
        else if let Some(v) = parse_value_after_colon(trimmed, "报告 ID") { data.report_code = v.clone(); }
        else if let Some(v) = parse_value_after_colon(trimmed, "Process Name") { data.process_name = v; }
        else if let Some(v) = parse_value_after_colon(trimmed, "进程名称") { data.process_name = v; }
        else if let Some(v) = parse_value_after_colon(trimmed, "PID") { if let Ok(p) = v.parse::<i32>() { data.pid = p; } }
        else if let Some(v) = parse_value_after_colon(trimmed, "进程PID") { if let Ok(p) = v.parse::<i32>() { data.pid = p; } }
        else if let Some(v) = parse_value_after_colon(trimmed, "进程 ID") { if let Ok(p) = v.parse::<i32>() { data.pid = p; } }
        else if let Some(v) = parse_value_after_colon(trimmed, "Parent PID") { if let Ok(p) = v.parse::<i32>() { data.parent_pid = p; } }
        else if let Some(v) = parse_value_after_colon(trimmed, "父进程PID") { if let Ok(p) = v.parse::<i32>() { data.parent_pid = p; } }
        else if let Some(v) = parse_value_after_colon(trimmed, "父进程 ID") { if let Ok(p) = v.parse::<i32>() { data.parent_pid = p; } }
        else if let Some(v) = parse_value_after_colon(trimmed, "Parent Path") { data.parent_path = v; }
        else if let Some(v) = parse_value_after_colon(trimmed, "父进程路径") { data.parent_path = v; }
        else if let Some(v) = parse_value_after_colon(trimmed, "Process Path") { data.process_path = v; }
        else if let Some(v) = parse_value_after_colon(trimmed, "进程路径") { data.process_path = v; }
        else if let Some(v) = parse_value_after_colon(trimmed, "镜像路径") { data.process_path = v; }
        else if let Some(v) = parse_value_after_colon(trimmed, "Command Line") { data.command_line = v; }
        else if let Some(v) = parse_value_after_colon(trimmed, "命令行") { data.command_line = v; }
        else if let Some(v) = parse_value_after_colon(trimmed, "LOLBins Abuse") { data.lolbins = v.eq_ignore_ascii_case("yes"); }
        else if let Some(v) = parse_value_after_colon(trimmed, "LOLBins滥用") { data.lolbins = v.contains("是") || v.eq_ignore_ascii_case("yes"); }
        else if let Some(v) = parse_value_after_colon(trimmed, "Result") { data.result = v; }
        else if let Some(v) = parse_value_after_colon(trimmed, "处理结果") { data.result = v; }
        else if let Some(v) = parse_value_after_colon(trimmed, "用户决策") { data.result = v; }
        else if trimmed.starts_with("Total Score") || trimmed.starts_with("总评分") || trimmed.starts_with("威胁评分") {
            if let Some(v) = parse_number_before_slash(trimmed) { data.total_score = v; }
        }
        else if trimmed.starts_with("Report generated") {
            // skip
        }
        // Behavior Summary 行（中英文）
        else if in_summary {
            if let Some(v) = parse_number_after_prefix(trimmed, "File Writes") { data.file_writes = v; }
            else if let Some(v) = parse_number_after_prefix(trimmed, "文件写入次数") { data.file_writes = v; }
            else if let Some(v) = parse_number_after_prefix(trimmed, "File Deletes") { data.file_deletes = v; }
            else if let Some(v) = parse_number_after_prefix(trimmed, "文件删除次数") { data.file_deletes = v; }
            else if let Some(v) = parse_number_after_prefix(trimmed, "Registry Mods") { data.registry_mods = v; }
            else if let Some(v) = parse_number_after_prefix(trimmed, "注册表修改次数") { data.registry_mods = v; }
            else if let Some(v) = parse_number_after_prefix(trimmed, "Inject Attempts") { data.inject_attempts = v; }
            else if let Some(v) = parse_number_after_prefix(trimmed, "注入尝试次数") { data.inject_attempts = v; }
            else if let Some(v) = parse_number_after_prefix(trimmed, "Suspicious Cmds") { data.suspicious_cmds = v; }
            else if let Some(v) = parse_number_after_prefix(trimmed, "可疑命令次数") { data.suspicious_cmds = v; }
            else if let Some(v) = parse_number_after_prefix(trimmed, "Memory RWX") { data.memory_rwx = v; }
            else if let Some(v) = parse_number_after_prefix(trimmed, "内存RWX次数") { data.memory_rwx = v; }
            else if let Some(v) = parse_number_after_prefix(trimmed, "Remote Threads") { data.remote_threads = v; }
            else if let Some(v) = parse_number_after_prefix(trimmed, "远程线程次数") { data.remote_threads = v; }
            else if let Some(v) = parse_number_after_prefix(trimmed, "Image Loads") { data.image_loads = v; }
            else if let Some(v) = parse_number_after_prefix(trimmed, "映像加载次数") { data.image_loads = v; }
        }
        // Timeline 行（新格式）
        else if in_timeline && trimmed.starts_with('[') {
            if let Some(event) = parse_timeline_line(trimmed) {
                data.timeline.push(event);
            }
        }
        // XIGUASecurityAgent 行为链表格行（以数字开头的表格行）
        else if in_timeline && trimmed.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            if let Some(event) = parse_endpoint_timeline_line(trimmed) {
                data.timeline.push(event);
            }
        }
    }

    // 旧格式没有时间线，但如果有"最近活动详情"，作为单个事件展示
    if data.timeline.is_empty() && !old_detail_lines.is_empty() {
        let detail = old_detail_lines.join(" | ");
        if !detail.is_empty() && detail != "N/A" {
            data.timeline.push(EdrTimelineEvent {
                seq: 1,
                datetime: data.report_time.clone(),
                relative_sec: "0.000s".to_string(),
                code: "-".to_string(),
                type_cn: "关键活动".to_string(),
                type_en: "KeyActivity".to_string(),
                detail,
            });
        }
    }

    // C 驱动格式：行为链分析也没有时间线，转换分析文本为事件
    if data.timeline.is_empty() && !behavior_analysis_lines.is_empty() {
        for (i, line) in behavior_analysis_lines.iter().enumerate() {
            let (level, desc) = if line.starts_with("[高危]") {
                ("高危", line[4..].trim())
            } else if line.starts_with("[中危]") {
                ("中危", line[4..].trim())
            } else if line.starts_with("[信息]") {
                ("信息", line[4..].trim())
            } else {
                ("分析", line.as_str())
            };
            data.timeline.push(EdrTimelineEvent {
                seq: (i + 1) as i32,
                datetime: data.report_time.clone(),
                relative_sec: "0.000s".to_string(),
                code: "-".to_string(),
                type_cn: format!("行为分析({})", level),
                type_en: level.to_string(),
                detail: desc.to_string(),
            });
        }
    }

    // 提取时间线中的 IOA 标记：IOA:FamilyName:+score 或 IOA:FamilyName:-score
    let mut ioa_map: std::collections::HashMap<String, i32> = std::collections::HashMap::new();
    let ioa_regex = regex::Regex::new(r"IOA:([^:\s]+):([+-]\d+)").unwrap();
    for event in &data.timeline {
        for cap in ioa_regex.captures_iter(&event.detail) {
            if let (Some(name_match), Some(score_match)) = (cap.get(1), cap.get(2)) {
                let name = name_match.as_str().trim().to_string();
                let score = score_match.as_str().parse::<i32>().unwrap_or(0);
                *ioa_map.entry(name).or_insert(0) += score;
            }
        }
    }
    let mut ioa_vec: Vec<(String, i32)> = ioa_map.into_iter().collect();
    ioa_vec.sort_by(|a, b| b.1.cmp(&a.1));
    data.ioa_families = ioa_vec;

    // 将 NT 设备路径（\Device\HarddiskVolumeX\...）映射为真实盘符路径（C:\...）
    data.process_path = convert_device_path_to_dos_path(&data.process_path);
    data.parent_path = convert_device_path_to_dos_path(&data.parent_path);
}

fn parse_value_after_colon(line: &str, key: &str) -> Option<String> {
    // 支持 key 后面有任意空格再跟冒号，例如 "Report Code     : EDR-..."
    if let Some(pos) = line.find(':') {
        let before = line[..pos].trim_end();
        if before == key {
            return Some(line[pos + 1..].trim().to_string());
        }
    }
    None
}

/// 从 Report Code 提取时间，例如 EDR-20260701-205028-46028 -> 2026-07-01 20:50:28
fn parse_report_time_from_code(code: &str) -> String {
    // 找到格式 EDR-YYYYMMDD-HHMMSS-PID
    let parts: Vec<&str> = code.split('-').collect();
    if parts.len() >= 3 {
        let date = parts[1];
        let time = parts[2];
        if date.len() == 8 && time.len() == 6 {
            return format!("{}-{}-{} {}:{}:{}",
                &date[0..4], &date[4..6], &date[6..8],
                &time[0..2], &time[2..4], &time[4..6]);
        }
    }
    String::new()
}

fn parse_number_before_slash(line: &str) -> Option<i32> {
    // Total Score : 105 / 100 (Threshold)
    if let Some(pos) = line.find('/') {
        let left = &line[..pos];
        let num_str: String = left.chars().rev().take_while(|c| c.is_ascii_digit()).collect::<String>().chars().rev().collect();
        return num_str.parse::<i32>().ok();
    }
    None
}

fn parse_number_after_prefix(line: &str, key: &str) -> Option<i32> {
    // 支持 key 后面有任意空格再跟冒号，例如 "File Writes      : 3 (+0 pts)"
    // 中英文键名均可：如 "文件写入次数: 3 (+0 分，仅记录)"
    if let Some(pos) = line.find(':') {
        let before = line[..pos].trim_end();
        if before == key {
            let after = &line[pos + 1..];
            let num_str: String = after.trim().chars().take_while(|c| c.is_ascii_digit()).collect();
            return num_str.parse::<i32>().ok();
        }
    }
    None
}

fn parse_timeline_line(line: &str) -> Option<EdrTimelineEvent> {
    // [1] 2026-07-01 20:50:10.199 (00.000s) [ T1485] 文件写入(FileWrite) | \Device\HarddiskVolume3\...
    // 跳过 [N]
    if !line.starts_with('[') { return None; }
    let closing = line.find(']')?;
    let seq_str = &line[1..closing];
    let seq = seq_str.parse::<i32>().ok()?;

    let rest = line[closing + 1..].trim_start();

    // 日期时间
    let mut dt = String::new();
    let mut rest2 = rest;
    if let Some(sp) = rest.find(' ') {
        if let Some(sp2) = rest[sp+1..].find(' ') {
            dt = rest[..sp + 1 + sp2].to_string();
            rest2 = rest[sp + 1 + sp2 + 1..].trim_start();
        }
    }
    if dt.is_empty() { return None; }

    // 相对秒数 (00.000s)
    let p_open = rest2.find('(')?;
    let p_close = rest2.find(')')?;
    let relative_sec = rest2[p_open + 1..p_close].to_string();
    let rest3 = rest2[p_close + 1..].trim_start();

    // 代码 [ T1485]
    let code_open = rest3.find('[')?;
    let code_close = rest3.find(']')?;
    let code = rest3[code_open + 1..code_close].trim().to_string();
    let rest4 = rest3[code_close + 1..].trim_start();

    // 类型 文件写入(FileWrite) | Detail
    let pipe_pos = rest4.find('|')?;
    let type_part = rest4[..pipe_pos].trim();
    let detail = rest4[pipe_pos + 1..].trim().to_string();

    // 类型中英文分离
    let (type_cn, type_en) = if let Some(paren) = type_part.find('(') {
        let close = type_part.find(')')?;
        (type_part[..paren].trim().to_string(), type_part[paren + 1..close].to_string())
    } else {
        (type_part.to_string(), String::new())
    };

    Some(EdrTimelineEvent { seq, datetime: dt, relative_sec, code, type_cn, type_en, detail })
}

/// 解析 XIGUASecurityAgent 行为链表格行
/// 格式: 序号  时间(UTC)  T-Code  行为类型  详情
/// 例如: "1  2026-08-01 12:00:00.000  T001  进程创建  detail..."
fn parse_endpoint_timeline_line(line: &str) -> Option<EdrTimelineEvent> {
    let parts: Vec<&str> = line.splitn(6, char::is_whitespace).collect();
    if parts.len() < 5 { return None; }

    // 跳过分隔线 (----)
    if parts[0].contains('-') { return None; }

    let seq = parts[0].trim().parse::<i32>().ok()?;
    let date = parts[1].trim();
    let time_part = parts[2].trim();

    // 时间格式: HH:MM:SS.mmm
    let datetime = if time_part.contains(':') {
        format!("{} {}", date, time_part)
    } else {
        // 如果第三个部分不是时间，可能是 T-Code（日期被合并了）
        format!("{}", date)
    };

    // 确定哪个部分是 T-Code，哪个是行为类型
    let (code, type_str, detail) = if time_part.contains(':') {
        // 正常格式: seq date time code type detail
        if parts.len() >= 6 {
            (parts[3].trim().to_string(), parts[4].trim().to_string(), parts[5].trim().to_string())
        } else if parts.len() == 5 {
            (parts[3].trim().to_string(), parts[4].trim().to_string(), String::new())
        } else {
            return None;
        }
    } else {
        // 退化格式: seq date code type detail
        if parts.len() >= 5 {
            (parts[2].trim().to_string(), parts[3].trim().to_string(), parts[4].trim().to_string())
        } else {
            return None;
        }
    };

    // 行为类型中英文分离（如 "进程创建(ProcessCreate)"）
    let (type_cn, type_en) = if let Some(paren) = type_str.find('(') {
        let close = type_str.find(')').unwrap_or(type_str.len());
        (type_str[..paren].trim().to_string(), type_str[paren + 1..close].to_string())
    } else {
        (type_str, String::new())
    };

    Some(EdrTimelineEvent {
        seq,
        datetime,
        relative_sec: "0.000s".to_string(),
        code,
        type_cn,
        type_en,
        detail,
    })
}

/// 应用拦截决策：写入响应管道、发射事件、清理信息表。
/// 供 send_intercept_decision 和 Toast 通知激活回调复用。
#[cfg(not(feature = "ms_store"))]
fn apply_intercept_decision(app: &tauri::AppHandle, decision: &str, resp_pipe_name: &str) {
    println!("[ApplyInterceptDecision] Decision: {}, RespPipe: {}", decision, resp_pipe_name);

    // 如果用户点了拦截，从信息表查找进程名并发射事件
    if decision == "block" && !resp_pipe_name.is_empty() {
        let (proc_name, threat_name) = {
            let info_map = INTERCEPT_INFO_MAP.lock().unwrap();
            info_map.get(resp_pipe_name).cloned().unwrap_or_else(|| ("未知进程".to_string(), "Unknown".to_string()))
        };
        let _ = app.emit("driver-process-blocked", serde_json::json!({
            "process": proc_name,
            "threat": threat_name,
        }));
        // 清理
        let mut info_map = INTERCEPT_INFO_MAP.lock().unwrap();
        info_map.remove(resp_pipe_name);
    }

    // 在新线程中写入响应管道（避免阻塞 Tauri 命令线程）
    if !resp_pipe_name.is_empty() {
        let resp = decision.to_string();
        let pipe = resp_pipe_name.to_string();
        std::thread::spawn(move || {
            write_to_resp_pipe(&pipe, &resp);
        });
    } else {
        println!("[ApplyInterceptDecision] No response pipe, decision logged only");
    }
}

// 设置通知模式开关
#[tauri::command]
fn set_notification_mode_enabled(enabled: bool) -> Result<(), String> {
    NOTIFICATION_MODE_ENABLED.store(enabled, Ordering::SeqCst);
    println!("[NotificationMode] Set to {}", enabled);
    Ok(())
}

// 关闭威胁警告窗口命令
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn close_threat_window(app: tauri::AppHandle) -> Result<(), String> {
    println!("[CloseThreatWindow] Closing threat window");
    if let Some(window) = app.get_webview_window("threat-alert") {
        window.close().map_err(|e| format!("Failed to close window: {}", e))?;
        println!("[CloseThreatWindow] Window closed successfully");
    } else {
        println!("[CloseThreatWindow] Window not found");
    }
    Ok(())
}

// 白名单管理命令
#[tauri::command]
fn get_whitelist_info() -> serde_json::Value {
    crate::rules_updater::get_rules_status()
}

#[tauri::command]
fn reload_whitelist_command() -> bool {
    reload_whitelist()
}

#[tauri::command]
fn import_whitelist_from_json(_json_content: String) -> Result<(), String> {
    Err("规则库已迁移至 SQLite，请使用规则库更新功能".to_string())
}

// 重新加载规则库 SQLite 数据库
#[tauri::command]
fn scan_and_load_rules_command() -> Result<serde_json::Value, String> {
    crate::rules_db::reload_rules_db().map_err(|e| e.to_string())?;
    let status = crate::rules_updater::get_rules_status();
    Ok(serde_json::json!({
        "success": true,
        "hash_count": status.get("hash_count").and_then(|v| v.as_u64()).unwrap_or(0),
        "version": status.get("version").and_then(|v| v.as_str()).unwrap_or("0.0.0"),
        "file_count": status.get("file_count").and_then(|v| v.as_u64()).unwrap_or(0),
    }))
}

// 黑规则库管理命令
#[tauri::command]
fn get_blacklist_info() -> serde_json::Value {
    let manager = get_blacklist_manager();
    serde_json::json!({
        "version": manager.get_version(),
        "updated_at": manager.get_updated_at(),
        "hash_count": manager.get_hash_count(),
    })
}

#[tauri::command]
fn reload_blacklist_command() -> bool {
    reload_blacklist()
}

#[tauri::command]
fn import_blacklist_from_json(json_content: String) -> Result<(), String> {
    let data: BlacklistData = serde_json::from_str(&json_content)
        .map_err(|e| format!("Invalid JSON format: {}", e))?;

    let mut manager = get_blacklist_manager();
    manager.update_data(data);
    manager.save_to_file()?;

    Ok(())
}

// 规则库更新命令
#[tauri::command]
async fn check_rules_update_command() -> Result<serde_json::Value, String> {
    update_last_check_time();
    
    match check_rules_update().await {
        Ok(Some(info)) => {
            Ok(serde_json::json!({
                "has_update": true,
                "version": info.version,
                "updated_at": info.updated_at,
                "description": info.description,
            }))
        }
        Ok(None) => {
            Ok(serde_json::json!({
                "has_update": false,
            }))
        }
        Err(e) => Err(e),
    }
}

#[tauri::command]
async fn update_rules_command(app_handle: tauri::AppHandle) -> Result<(), String> {
    let info = check_rules_update().await?
        .ok_or("No update available")?;
    
    download_and_update_rules_with_progress(&info, &app_handle).await
}

#[tauri::command]
fn get_rules_status_command() -> serde_json::Value {
    get_rules_status()
}

#[tauri::command]
fn set_rules_server_url_command(url: String) {
    crate::rules_updater::set_rules_server_url(url);
}

#[tauri::command]
fn get_rules_server_url_command() -> String {
    crate::rules_updater::get_rules_server_url()
}

#[tauri::command]
fn should_auto_check_rules() -> bool {
    should_auto_check()
}

// 获取最新公告
#[tauri::command]
async fn fetch_announcement_command() -> Result<Option<Announcement>, String> {
    fetch_latest_announcement().await
}

// 打开规则库文件夹
#[tauri::command]
fn open_rules_folder() -> Result<(), String> {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    // 使用 Windows 路径分隔符
    let rules_dir = std::path::PathBuf::from(&local_app_data)
        .join("XIGUASecurity")
        .join("rules");
    
    // 确保目录存在
    std::fs::create_dir_all(&rules_dir)
        .map_err(|e| format!("Failed to create rules directory: {}", e))?;
    
    // 转换为绝对路径字符串
    let path_str = rules_dir.to_string_lossy().to_string();
    println!("[Rules] Opening folder: {}", path_str);
    
    // 使用系统默认程序打开文件夹
    #[cfg(windows)]
    {
        use std::process::Command;
        // 使用 /select 参数确保打开的是文件夹本身而不是父目录
        let result = Command::new("explorer")
            .arg(&path_str)
            .spawn();
        
        if let Err(e) = result {
            println!("[Rules] Failed to open with explorer: {}, trying start command", e);
            // 备用方案：使用 start 命令
            Command::new("cmd")
                .args(&["/C", "start", "", &path_str])
                .spawn()
                .map_err(|e| format!("Failed to open folder: {}", e))?;
        }
    }
    
    #[cfg(not(windows))]
    {
        use std::process::Command;
        Command::new("xdg-open")
            .arg(&path_str)
            .spawn()
            .map_err(|e| format!("Failed to open folder: {}", e))?;
    }
    
    Ok(())
}

// 打开文件所在位置
#[tauri::command]
fn open_file_location(file_path: String) -> Result<(), String> {
    use std::path::PathBuf;
    // 统一转成 Windows 反斜杠格式，避免前端传正斜杠路径导致 explorer 解析失败
    let path = PathBuf::from(file_path.replace('/', "\\"));
    let file_path_normalized = path.to_string_lossy().to_string();

    #[cfg(windows)]
    {
        use std::process::Command;
        // 如果文件/目录仍存在，用 /select,<path> 高亮选中
        if path.exists() {
            // 将 /select, 和路径分开为两个参数，避免 Rust Command API 对含引号参数重复转义
            let result = Command::new("explorer")
                .arg("/select,")
                .arg(&file_path_normalized)
                .spawn();

            if result.is_ok() {
                return Ok(());
            }
            println!("[OpenLocation] Failed to open with explorer /select, trying parent folder");
        }

        // 备用：打开文件所在文件夹
        if let Some(parent) = path.parent() {
            let parent_str = parent.to_string_lossy().to_string();
            if parent.exists() {
                let _ = Command::new("explorer")
                    .arg(&parent_str)
                    .spawn();
                return Ok(());
            }
        }

        return Err(format!("Path does not exist: {}", file_path_normalized));
    }

    #[cfg(not(windows))]
    {
        use std::process::Command;
        if let Some(parent) = path.parent() {
            Command::new("xdg-open")
                .arg(parent.to_string_lossy().to_string())
                .spawn()
                .map_err(|e| format!("Failed to open folder: {}", e))?;
            Ok(())
        } else {
            Err("No parent directory".to_string())
        }
    }
}

// 云端扫描设置管理
// 云端深度分析（自动沙箱）开关
#[tauri::command]
fn get_cloud_deep_analysis_enabled() -> bool {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_path = format!("{}/XIGUASecurity/cloud_deep_analysis_enabled.txt", local_app_data);
    match std::fs::read_to_string(&config_path) {
        Ok(content) => content.trim() == "true",
        Err(_) => true, // 默认开启
    }
}

#[tauri::command]
fn set_cloud_deep_analysis_enabled(enabled: bool) -> Result<(), String> {
    let local_app_data = std::env::var("LOCALAPPDATA").map_err(|e| format!("Cannot get LOCALAPPDATA: {}", e))?;
    let config_dir = format!("{}/XIGUASecurity", local_app_data);
    std::fs::create_dir_all(&config_dir).map_err(|e| format!("Cannot create config dir: {}", e))?;
    let config_path = format!("{}/cloud_deep_analysis_enabled.txt", config_dir);
    std::fs::write(&config_path, if enabled { "true" } else { "false" })
        .map_err(|e| format!("Cannot write config: {}", e))?;
    Ok(())
}


// 扫描敏感度设置管理
#[tauri::command]
fn get_scan_sensitivity() -> String {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_path = format!("{}/XIGUASecurity/scan_sensitivity.txt", local_app_data);
    std::fs::read_to_string(&config_path)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "high".to_string())
}

#[tauri::command]
fn set_scan_sensitivity(sensitivity: String) -> Result<String, String> {
    let local_app_data = std::env::var("LOCALAPPDATA").map_err(|e| format!("Cannot get LOCALAPPDATA: {}", e))?;
    let config_dir = format!("{}/XIGUASecurity", local_app_data);
    std::fs::create_dir_all(&config_dir).map_err(|e| format!("Cannot create config dir '{}': {}", config_dir, e))?;
    let config_path = format!("{}/scan_sensitivity.txt", config_dir);
    std::fs::write(&config_path, &sensitivity).map_err(|e| format!("Cannot write config '{}': {}", config_path, e))?;
    println!("[Scanner] Sensitivity set to: {}", sensitivity);

    // 根据敏感度重新加载模型
    let exe_path = std::env::current_exe().map_err(|e| format!("Cannot get exe path: {}", e))?;
    let exe_dir = exe_path.parent().ok_or("Cannot get exe directory")?;

    let (model_path, feature_dim) = if sensitivity == "low" {
        // 低敏感度：使用 Melix-Flash 模型 (283维)
        let mut paths = vec![
            exe_dir.join("engines").join("melix-flash").join("DeepMode.onnx"),
            exe_dir.join("Melix-Flash").join("DeepMode.onnx"),
            exe_dir.join("DeepMode.onnx"),
        ];
        let mut current = Some(exe_dir);
        for _ in 0..6 {
            if let Some(dir) = current {
                paths.push(dir.join("engines").join("melix-flash").join("DeepMode.onnx"));
                paths.push(dir.join("Melix-Flash").join("DeepMode.onnx"));
                current = dir.parent();
            }
        }
        (paths.iter().find(|p| p.exists())
            .ok_or_else(|| "Low sensitivity model (Melix-Flash/DeepMode.onnx) not found".to_string())
            .map(|p| {
                println!("[Scanner] - Found low-sensitivity model at: {}", p.display());
                p.to_string_lossy().to_string()
            })?, 283)
    } else {
        // 高敏感度：使用 Melix 模型（默认路径，567维）
        let mut paths = vec![
            exe_dir.join("engines").join("melix").join("DeepMode.onnx"),
            exe_dir.join("Melix").join("DeepMode.onnx"),
            exe_dir.join("DeepMode.onnx"),
        ];
        let mut current = Some(exe_dir);
        for _ in 0..6 {
            if let Some(dir) = current {
                paths.push(dir.join("engines").join("melix").join("DeepMode.onnx"));
                paths.push(dir.join("Melix").join("DeepMode.onnx"));
                current = dir.parent();
            }
        }
        (paths.iter().find(|p| p.exists())
            .ok_or_else(|| "High sensitivity model (Melix/DeepMode.onnx) not found".to_string())
            .map(|p| {
                println!("[Scanner] - Found high-sensitivity model at: {}", p.display());
                p.to_string_lossy().to_string()
            })?, 567)
    };

    let scanner = scanner::SCANNER.read().map_err(|e| format!("{} - {}", model_path, e))?;
    scanner.reload_model(&model_path, feature_dim).map_err(|e| format!("路径: {} - 错误: {}", model_path, e))?;
    Ok(model_path)
}

/// 获取脚本防护启用状态
#[tauri::command]
fn get_script_protection_enabled() -> bool {
    script_protection::is_script_protection_enabled()
}

/// 设置脚本防护启用状态
#[tauri::command]
fn set_script_protection_enabled(enabled: bool, app: tauri::AppHandle) -> Result<(), String> {
    diag_info!("[ScriptProtection] set_script_protection_enabled: {}", enabled);
    if enabled {
        script_protection::start_script_protection(app)
    } else {
        script_protection::stop_script_protection()
    }
}

// 脚本扫描引擎设置管理
#[tauri::command]
fn get_script_scan_enabled() -> bool {
    // 从本地存储读取，默认关闭
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_path = format!("{}/XIGUASecurity/script_scan_enabled.txt", local_app_data);
    std::fs::read_to_string(&config_path)
        .map(|s| s.trim() == "true")
        .unwrap_or(false)
}

#[tauri::command]
fn set_script_scan_enabled(enabled: bool) {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_dir = format!("{}/XIGUASecurity", local_app_data);
    let _ = std::fs::create_dir_all(&config_dir);
    let config_path = format!("{}/script_scan_enabled.txt", config_dir);
    let _ = std::fs::write(&config_path, if enabled { "true" } else { "false" });
}

// 静默模式设置管理
#[tauri::command]
fn get_silent_mode_enabled() -> bool {
    // 从本地存储读取，默认关闭
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_path = format!("{}/XIGUASecurity/silent_mode_enabled.txt", local_app_data);
    std::fs::read_to_string(&config_path)
        .map(|s| s.trim() == "true")
        .unwrap_or(false)
}

#[tauri::command]
fn set_silent_mode_enabled(enabled: bool) {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_dir = format!("{}/XIGUASecurity", local_app_data);
    let _ = std::fs::create_dir_all(&config_dir);
    let config_path = format!("{}/silent_mode_enabled.txt", config_dir);
    let _ = std::fs::write(&config_path, if enabled { "true" } else { "false" });
}

// 基础防护设置管理
#[tauri::command]
fn get_basic_protection_enabled() -> bool {
    // 从本地存储读取，默认开启
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_path = format!("{}/XIGUASecurity/basic_protection_enabled.txt", local_app_data);
    std::fs::read_to_string(&config_path)
        .map(|s| s.trim() == "true")
        .unwrap_or(true) // 默认开启
}

#[tauri::command]
fn set_basic_protection_enabled(enabled: bool) {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_dir = format!("{}/XIGUASecurity", local_app_data);
    let _ = std::fs::create_dir_all(&config_dir);
    let config_path = format!("{}/basic_protection_enabled.txt", config_dir);
    let _ = std::fs::write(&config_path, if enabled { "true" } else { "false" });
}

// ==================== 自动沙盒分析 ====================

#[tauri::command]
fn get_sandbox_analysis_enabled() -> bool {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_path = format!("{}/XIGUASecurity/sandbox_analysis_enabled.txt", local_app_data);
    // 配置文件不存在时默认启用（新用户安装后默认开启沙盒分析）
    let enabled = std::fs::read_to_string(&config_path)
        .map(|s| s.trim() == "true")
        .unwrap_or(true);
    sandbox_analysis::set_analysis_enabled(enabled);
    enabled
}

#[tauri::command]
fn set_sandbox_analysis_enabled(enabled: bool, app_handle: tauri::AppHandle) {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_dir = format!("{}/XIGUASecurity", local_app_data);
    let _ = std::fs::create_dir_all(&config_dir);
    let config_path = format!("{}/sandbox_analysis_enabled.txt", config_dir);
    let _ = std::fs::write(&config_path, if enabled { "true" } else { "false" });
    sandbox_analysis::set_analysis_enabled(enabled);

    // 启用时：如果驱动未运行，启动 R3 进程监控
    // 禁用时：停止 R3 监控
    if enabled {
        if !av_driver_client::is_av_driver_connected() {
            println!("[SandboxAnalysis] Driver not connected, starting R3 process monitor");
            sandbox_analysis::start_r3_process_monitor(&app_handle);
        } else {
            println!("[SandboxAnalysis] Driver connected, R3 monitor not needed");
        }
    } else {
        sandbox_analysis::stop_r3_process_monitor();
    }
}

#[tauri::command]
fn set_sandbox_analysis_file(file_path: String) -> Result<(), String> {
    if !std::path::Path::new(&file_path).exists() {
        return Err("文件不存在".to_string());
    }
    sandbox_analysis::set_pending_file(&file_path);
    Ok(())
}

#[tauri::command]
async fn prepare_sandbox_environment(app_handle: tauri::AppHandle) -> Result<bool, String> {
    println!("[SandboxAnalysis] prepare_sandbox_environment 命令被调用");
    // 后台静默安装
    let result = tokio::task::spawn_blocking(|| {
        sandbox_analysis::ensure_sandboxie()
    }).await.map_err(|e| format!("安装任务失败: {}", e))?;

    match result {
        Ok(true) => {
            println!("[SandboxAnalysis] 环境已就绪");
            Ok(true)
        }
        Ok(false) => {
            println!("[SandboxAnalysis] 环境未就绪");
            Err("环境未就绪".to_string())
        }
        Err(e) => {
            println!("[SandboxAnalysis] 环境配置失败: {}", e);
            // 安装失败，弹出错误通知
            let _ = notification::show_security_notification_simple(
                &app_handle,
                notification::NotificationType::Block,
                "沙盒环境配置失败",
                &e,
            );
            Err(e)
        }
    }
}

#[tauri::command]
async fn trigger_sandbox_analysis(file_path: String, app_handle: tauri::AppHandle) -> Result<(), String> {
    if !std::path::Path::new(&file_path).exists() {
        return Err("文件不存在".to_string());
    }

    // 设置待分析文件
    sandbox_analysis::set_pending_file(&file_path);

    // 检查驱动是否在运行
    if av_driver_client::is_av_driver_connected() {
        // 驱动模式：复制为 Sandbox.exe 并运行，驱动拦截后触发 handle_sandbox_analysis
        println!("[SandboxAnalysis] Driver connected, using trigger mechanism");
        let trigger = tokio::task::spawn_blocking(move || {
            sandbox_analysis::prepare_trigger(&file_path)
                .and_then(|path| sandbox_analysis::run_trigger(&path))
        }).await.map_err(|e| format!("触发任务失败: {}", e))?;
        trigger
    } else {
        // R3 模式：驱动未运行，直接调用 handle_sandbox_analysis
        println!("[SandboxAnalysis] Driver not connected, using R3 direct analysis");
        let app = app_handle.clone();
        tokio::task::spawn_blocking(move || {
            handle_sandbox_analysis(&app, &file_path);
        }).await.map_err(|e| format!("分析任务失败: {}", e))?;
        Ok(())
    }
}

#[tauri::command]
fn clear_sandbox_whitelist() -> Result<String, String> {
    let count = sandbox_analysis::clear_whitelist()?;
    Ok(format!("已清除 {} 条白名单记录", count))
}

#[tauri::command]
fn get_sandbox_whitelist_count() -> usize {
    sandbox_analysis::get_whitelist_count()
}

// ==================== AVIC 云端情报 ====================

#[tauri::command]
async fn test_avic_connection() -> Result<String, String> {
    tokio::task::spawn_blocking(|| avic_client::test_connection())
        .await
        .map_err(|e| format!("任务失败: {}", e))?
}

#[tauri::command]
fn avic_is_configured() -> bool {
    avic_client::is_configured()
}

// 获取运行中的进程列表（异步版本，避免阻塞主线程）
// 使用 ToolHelp 快照枚举，获取数量不受 1024 限制；再用 PROCESS_QUERY_LIMITED_INFORMATION
// 获取完整路径，避免旧方式因权限不足而漏掉大量进程。
#[tauri::command]
async fn get_running_processes() -> Result<Vec<serde_json::Value>, String> {
    // 使用 spawn_blocking 在独立线程中执行，避免阻塞主线程
    let processes = tokio::task::spawn_blocking(|| {
        let mut processes = Vec::new();

        #[cfg(windows)]
        unsafe {
            use windows::Win32::System::Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
                PROCESSENTRY32W, TH32CS_SNAPPROCESS,
            };
            use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
            use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
            use windows::Win32::Foundation::CloseHandle;

            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if let Ok(snapshot) = snapshot {
                let mut entry: PROCESSENTRY32W = std::mem::zeroed();
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

                if Process32FirstW(snapshot, &mut entry).is_ok() {
                    loop {
                        let pid = entry.th32ProcessID;
                        let name = String::from_utf16_lossy(&entry.szExeFile)
                            .trim_end_matches('\0')
                            .to_string();

                        let mut path = String::new();
                        // ToolHelp 只能拿到进程名；尝试打开进程获取完整路径
                        if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                            let mut path_buf = [0u16; 520];
                            if GetModuleFileNameExW(handle, None, &mut path_buf) > 0 {
                                path = String::from_utf16_lossy(&path_buf)
                                    .trim_end_matches('\0')
                                    .to_string();
                            }
                            let _ = CloseHandle(handle);
                        }

                        // 获取不到完整路径的进程无法安全扫描，跳过而不是用进程名兜底，
                        // 避免“系统找不到指定的文件”这种无效报错
                        if path.is_empty() {
                            continue;
                        }

                        processes.push(serde_json::json!({
                            "pid": pid,
                            "path": path,
                            "name": name
                        }));

                        if Process32NextW(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }

                let _ = CloseHandle(snapshot);
            }
        }

        processes
    }).await.map_err(|e| format!("Failed to get processes: {}", e))?;

    Ok(processes)
}

// ==================== WMI 事件驱动的进程监控 ====================
// 替代轮询方案：订阅 Win32_ProcessStartTrace，新进程启动时即时通知

lazy_static::lazy_static! {
    static ref PROCESS_WATCHER: ProcessWatcher = ProcessWatcher::new();
}

#[tauri::command]
fn start_process_watcher(app: tauri::AppHandle) -> Result<(), String> {
    diag_info!("[ProcessWatcher] Starting WMI process watcher");
    println!("[ProcessWatcher] Starting WMI process watcher...");
    PROCESS_WATCHER.start(app);
    Ok(())
}

#[tauri::command]
fn stop_process_watcher() -> Result<(), String> {
    diag_info!("[ProcessWatcher] Stopping WMI process watcher");
    println!("[ProcessWatcher] Stopping WMI process watcher...");
    PROCESS_WATCHER.stop();
    Ok(())
}

// 轻量级获取运行中进程 PID 列表（仅返回 PID，避免 OpenProcess 开销）
// 用于前端高频轮询（500ms），比 get_running_processes 快 100x
#[tauri::command]
async fn get_running_pids() -> Result<Vec<u32>, String> {
    let pids = tokio::task::spawn_blocking(|| {
        let mut pids = Vec::new();
        #[cfg(windows)]
        unsafe {
            use windows::Win32::System::ProcessStatus::EnumProcesses;
            let mut process_ids = [0u32; 4096];
            let mut bytes_returned = 0u32;
            if EnumProcesses(
                process_ids.as_mut_ptr(),
                (process_ids.len() * std::mem::size_of::<u32>()) as u32,
                &mut bytes_returned,
            ).is_ok() {
                let num_processes = bytes_returned as usize / std::mem::size_of::<u32>();
                for i in 0..num_processes {
                    let p = process_ids[i];
                    if p != 0 {
                        pids.push(p);
                    }
                }
            }
        }
        pids
    }).await.map_err(|e| format!("Failed to get pids: {}", e))?;
    Ok(pids)
}

// 获取指定 PID 的进程详细信息（路径 + 名称）
// 只在有新进程时调用，不参与高频轮询
#[tauri::command]
async fn get_process_info(pid: u32) -> Result<Option<serde_json::Value>, String> {
    let info = tokio::task::spawn_blocking(move || {
        #[cfg(windows)]
        unsafe {
            use windows::Win32::System::Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
                PROCESSENTRY32W, TH32CS_SNAPPROCESS,
            };
            use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
            use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
            use windows::Win32::Foundation::CloseHandle;

            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if let Ok(snapshot) = snapshot {
                let mut entry: PROCESSENTRY32W = std::mem::zeroed();
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32FirstW(snapshot, &mut entry).is_ok() {
                    loop {
                        if entry.th32ProcessID == pid {
                            let name = String::from_utf16_lossy(&entry.szExeFile)
                                .trim_end_matches('\0')
                                .to_string();
                            let mut path = String::new();
                            if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                                let mut path_buf = [0u16; 520];
                                if GetModuleFileNameExW(handle, None, &mut path_buf) > 0 {
                                    path = String::from_utf16_lossy(&path_buf)
                                        .trim_end_matches('\0')
                                        .to_string();
                                }
                                let _ = CloseHandle(handle);
                            }
                            let _ = CloseHandle(snapshot);
                            if path.is_empty() {
                                return None;
                            }
                            return Some(serde_json::json!({
                                "pid": pid,
                                "path": path,
                                "name": name
                            }));
                        }
                        if Process32NextW(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snapshot);
            }
            None
        }
        #[cfg(not(windows))]
        { None }
    }).await.map_err(|e| format!("Failed to get process info: {}", e))?;
    Ok(info)
}

// 终止进程（异步版本）
#[tauri::command]
async fn terminate_process(pid: u32) -> Result<(), String> {
    // 使用 spawn_blocking 避免阻塞主线程
    tokio::task::spawn_blocking(move || {
        #[cfg(windows)]
        unsafe {
            use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
            use windows::Win32::Foundation::CloseHandle;
            
            let process_handle = OpenProcess(PROCESS_TERMINATE, false, pid);
            
            match process_handle {
                Ok(handle) => {
                    let result = TerminateProcess(handle, 1);
                    let _ = CloseHandle(handle);
                    
                    if result.is_ok() {
                        Ok(())
                    } else {
                        Err("Failed to terminate process".to_string())
                    }
                }
                Err(e) => Err(format!("Failed to open process: {}", e)),
            }
        }
        
        #[cfg(not(windows))]
        Err("Not supported on this platform".to_string())
    }).await.map_err(|e| format!("Task failed: {}", e))?
}

// ==================== PUA (潜在不需要程序) 拦截 ====================

/// PUA 进程名列表（小写，含 .exe 后缀）
const PUA_PROCESS_NAMES: &[&str] = &[
    // 2345系列
    "2345explorer.exe",
    "2345picviewer.exe",
    "2345safeguard.exe",
    "2345safe.exe",
    "2345mini.exe",
    "2345safetray.exe",
    "2345好压.exe",
    "2345王牌输入法.exe",
    "2345看图王.exe",
    "2345浏览器.exe",
    "2345安全卫士.exe",
    // 快压 / 好压
    "kuaizip.exe",
    "kuaizipupdate.exe",
    "haozip.exe",
    "haozipupdate.exe",
    // 鲁大师
    "computerz_cn.exe",
    "ludashi.exe",
    "ldsmain.exe",
    // 驱动精灵
    "drivergenius.exe",
    "djp.exe",
    "dgsetup.exe",
    // 驱动人生
    "dtlite.exe",
    "dt.exe",
    "dtagent.exe",
    "dtservice.exe",
    // 百度系列
    "baidusd.exe",
    "baiduan.exe",
    "baiduprotect.exe",
    // 金山系列
    "ksafe.exe",
    "kws.exe",
    "ksoftmgr.exe",
    // 迅雷迷你
    "minithunder.exe",
    // 其他常见捆绑软件
    "desktoppet.exe",        // 小鸟壁纸
    "xiaoniaowallpaper.exe",
    "niaobz.exe",
    "softmanager.exe",
    "drvmgr.exe",
    "ruanjianquanjia.exe",
    "paojiaolianmeng.exe",   // 跑跑车联盟
    "hao123.exe",
    "hao123install.exe",
    "duba.exe",              // 毒霸
    "kxetray.exe",
    "kxescore.exe",
    "qqpcmgr.exe",           // 腾讯电脑管家
    "qqprotect.exe",
    // 弹窗类 / 推广类
    "adwarecleaner.exe",
    "uninst.exe",            // 部分捆绑软件的卸载器伪装
];

/// 可疑文件名列表（命中后直接挂起并上传云端沙箱分析）
const SUSPICIOUS_PROCESS_NAMES: &[&str] = &[
    // 测试用文件名（可用于验证拦截功能）
    "suspicious_test.exe",
    "test_malware.exe",
    "test_suspicious.exe",
    // 已知可疑/高风险工具
    "psexesvc.exe",           // PsExec 远程执行
    "procdump.exe",           // 进程转储（常用于窃取凭据）
    "mimikatz.exe",           // 凭据提取
    "mimilib.dll",
    "nc.exe",                 // NetCat
    "ncat.exe",
    "cobalt_strike.exe",
    "beacon.exe",
    "metasploit.exe",
    "msfconsole.exe",
    "meterpreter.exe",
    "reverse_shell.exe",
    "keylogger.exe",
    "ransomware.exe",
    "cryptolocker.exe",
    "wannacry.exe",
    "locky.exe",
    // 远控/后门
    "tvnviewer.exe",          // TightVNC（常被滥用）
    "winvnc.exe",
    "ammyy.exe",              // Ammyy Admin（常被滥用）
    "anydesk.exe",            // AnyDesk（可被滥用，按需启用）
    "radmin.exe",
];

// NtSuspendProcess / NtResumeProcess from ntdll.dll
#[cfg(windows)]
extern "system" {
    fn NtSuspendProcess(handle: windows::Win32::Foundation::HANDLE) -> i32;
    fn NtResumeProcess(handle: windows::Win32::Foundation::HANDLE) -> i32;
}

/// 挂起进程
#[tauri::command]
async fn suspend_process(pid: u32) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        #[cfg(windows)]
        unsafe {
            use windows::Win32::System::Threading::OpenProcess;
            use windows::Win32::Foundation::CloseHandle;
            // PROCESS_SUSPEND_RESUME = 0x00000800
            let handle = OpenProcess(
                windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS(0x00000800),
                false,
                pid,
            ).map_err(|e| format!("Failed to open process: {}", e))?;
            let status = NtSuspendProcess(handle);
            let _ = CloseHandle(handle);
            if status >= 0 { Ok(()) } else { Err(format!("NtSuspendProcess failed: 0x{:08X}", status)) }
        }
        #[cfg(not(windows))]
        Err("Not supported on this platform".to_string())
    }).await.map_err(|e| format!("Task failed: {}", e))?
}

/// 恢复进程
#[tauri::command]
async fn resume_process(pid: u32) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        #[cfg(windows)]
        unsafe {
            use windows::Win32::System::Threading::OpenProcess;
            use windows::Win32::Foundation::CloseHandle;
            let handle = OpenProcess(
                windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS(0x00000800),
                false,
                pid,
            ).map_err(|e| format!("Failed to open process: {}", e))?;
            let status = NtResumeProcess(handle);
            let _ = CloseHandle(handle);
            if status >= 0 { Ok(()) } else { Err(format!("NtResumeProcess failed: 0x{:08X}", status)) }
        }
        #[cfg(not(windows))]
        Err("Not supported on this platform".to_string())
    }).await.map_err(|e| format!("Task failed: {}", e))?
}

/// 检查进程名是否在 PUA 名单中
#[tauri::command]
fn check_is_pua(process_name: String) -> bool {
    let lower = process_name.to_lowercase();
    PUA_PROCESS_NAMES.iter().any(|&pua| lower == pua)
}

// PUA 防护开关
#[tauri::command]
fn get_pua_protection_enabled() -> bool {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let path = format!("{}/XIGUASecurity/pua_protection_enabled.txt", local_app_data);
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_lowercase() == "true")
        .unwrap_or(false)
}

#[tauri::command]
fn set_pua_protection_enabled(enabled: bool) -> Result<(), String> {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let dir = format!("{}/XIGUASecurity", local_app_data);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = format!("{}/pua_protection_enabled.txt", local_app_data);
    std::fs::write(&path, if enabled { "true" } else { "false" }).map_err(|e| e.to_string())?;
    Ok(())
}

/// 显示 PUA 拦截窗口（带允许/拦截按钮）
#[tauri::command]
async fn show_pua_intercept_window(
    app: tauri::AppHandle,
    process_name: String,
    command_line: String,
    pid: u32,
) -> Result<(), String> {
    let time = chrono::Local::now().format("%Y/%m/%d %H:%M:%S").to_string();

    // 关闭已存在的 PUA 拦截窗口
    if let Some(existing) = app.get_webview_window("intercept-pua") {
        let _ = existing.close();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    let lang = get_current_language();
    let url = format!(
        "intercept-alert.html?source=pua_protection&time={}&process={}&command={}&type={}&pid={}&lang={}",
        urlencoding::encode(&time),
        urlencoding::encode(&process_name),
        urlencoding::encode(&command_line),
        urlencoding::encode("捆绑软件拦截(垃圾程序)"),
        pid,
        urlencoding::encode(&lang)
    );

    let window = tauri::WebviewWindowBuilder::new(
        &app,
        "intercept-pua",
        tauri::WebviewUrl::App(url.into()),
    )
    .title("PUA 拦截")
    .inner_size(360.0, 540.0)
    .decorations(false)
    .transparent(false)
    .shadow(true)
    .always_on_top(true)
    .skip_taskbar(true)
    .resizable(false)
    .visible(false)
    .build()
    .map_err(|e| format!("Failed to create PUA window: {}", e))?;

    // 定位到右下角
    #[cfg(windows)]
    {
        use tauri::Position;
        use windows::Win32::Graphics::Gdi::{GetDeviceCaps, LOGPIXELSX};
        unsafe {
            let hwnd = GetForegroundWindow();
            let hmonitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
            let mut mi = MONITORINFO::default();
            mi.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
            if GetMonitorInfoW(hmonitor, &mut mi).as_bool() {
                let hdc = GetDC(None);
                let dpi = GetDeviceCaps(hdc, LOGPIXELSX) as f32;
                let _ = ReleaseDC(None, hdc);
                let scale = dpi / 96.0;
                let w = (360.0 * scale) as i32;
                let h = (540.0 * scale) as i32;
                let m = (20.0 * scale) as i32;
                let x = mi.rcWork.right - w - m;
                let y = mi.rcWork.bottom - h - m;
                let _ = window.set_position(Position::Physical(tauri::PhysicalPosition { x, y }));
            }
        }
    }

    window.show().map_err(|e| format!("Failed to show: {}", e))?;
    window.set_focus().map_err(|e| format!("Failed to focus: {}", e))?;
    Ok(())
}

/// 处理 PUA 拦截决策
#[tauri::command]
async fn send_pua_decision(app: tauri::AppHandle, decision: String, pid: u32) -> Result<(), String> {
    if decision == "block" {
        let _ = terminate_process(pid).await;
    } else {
        let _ = resume_process(pid).await;
    }
    // 关闭 PUA 拦截窗口
    if let Some(win) = app.get_webview_window("intercept-pua") {
        let _ = win.close();
    }
    Ok(())
}

// ========== 可疑文件拦截 ==========

// 可疑文件拦截开关
#[tauri::command]
fn get_suspicious_intercept_enabled() -> bool {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let path = format!("{}/XIGUASecurity/suspicious_intercept_enabled.txt", local_app_data);
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_lowercase() == "true")
        .unwrap_or(false)
}

#[tauri::command]
fn set_suspicious_intercept_enabled(enabled: bool) -> Result<(), String> {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let dir = format!("{}/XIGUASecurity", local_app_data);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = format!("{}/XIGUASecurity/suspicious_intercept_enabled.txt", local_app_data);
    std::fs::write(&path, if enabled { "true" } else { "false" }).map_err(|e| e.to_string())?;
    Ok(())
}

// ==================== 桌面宠物（Live2D 洛天依） ====================

/// 是否已创建桌面宠物窗口
lazy_static::lazy_static! {
    static ref PET_WINDOW_CREATED: Mutex<bool> = Mutex::new(false);
}

/// 显示或隐藏桌面宠物（洛天依 Live2D，透明浮动窗口，固定在右下角）
#[tauri::command]
async fn toggle_desktop_pet(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    if enabled {
        // 如果已存在，显示
        if let Some(pet_win) = app.get_webview_window("desktop-pet") {
            let _ = pet_win.show();
            let _ = pet_win.set_focus();
            return Ok(());
        }

        eprintln!("[DesktopPet] Creating pet window...");

        // 创建桌面宠物窗口
        let window = tauri::WebviewWindowBuilder::new(
            &app,
            "desktop-pet",
            tauri::WebviewUrl::App("live2d-pet.html".into()),
        )
        .title("洛天依桌宠")
        .inner_size(280.0, 360.0)
        .decorations(false)
        .transparent(true)
        .shadow(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .resizable(false)
        .visible(true)
        .build()
        .map_err(|e| format!("创建桌宠窗口失败: {}", e))?;

        // 定位到右下角（使用屏幕尺寸计算位置）
        if let Ok(Some(monitor)) = window.primary_monitor() {
            let screen_size = monitor.size();
            let scale_factor = monitor.scale_factor();
            let x = ((screen_size.width as f64 / scale_factor) - 280.0).max(0.0) as i32;
            let y = ((screen_size.height as f64 / scale_factor) - 360.0).max(0.0) as i32;
            eprintln!("[DesktopPet] Screen: {}x{}, scale: {}, placing at: {},{}",
                screen_size.width, screen_size.height, scale_factor, x, y);
            let _ = window.set_position(tauri::PhysicalPosition::new(x, y));
        } else {
            eprintln!("[DesktopPet] No monitor found, using default position");
        }

        {
            let mut created = PET_WINDOW_CREATED.lock().unwrap();
            *created = true;
        }
        eprintln!("[DesktopPet] Pet window created successfully");
    } else {
        // 关闭宠物窗口
        if let Some(pet_win) = app.get_webview_window("desktop-pet") {
            let _ = pet_win.close();
        }
        {
            let mut created = PET_WINDOW_CREATED.lock().unwrap();
            *created = false;
        }
        eprintln!("[DesktopPet] Pet window closed");
    }
    Ok(())
}

/// 获取桌面宠物当前状态
#[tauri::command]
fn get_desktop_pet_enabled() -> bool {
    *PET_WINDOW_CREATED.lock().unwrap()
}

/// 显示可疑文件拦截窗口（Avast 风格，屏幕居中）
#[tauri::command]
async fn show_suspicious_intercept_window(
    app: tauri::AppHandle,
    file_name: String,
    file_path: String,
    pid: u32,
    confidence: f64,
) -> Result<(), String> {
    // 关闭已存在的窗口
    if let Some(existing) = app.get_webview_window("intercept-suspicious") {
        let _ = existing.close();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    let lang = get_current_language();
    let url = format!(
        "suspicious-intercept.html?name={}&path={}&pid={}&confidence={}&lang={}",
        urlencoding::encode(&file_name),
        urlencoding::encode(&file_path),
        pid,
        confidence,
        urlencoding::encode(&lang)
    );

    let window = tauri::WebviewWindowBuilder::new(
        &app,
        "intercept-suspicious",
        tauri::WebviewUrl::App(url.into()),
    )
    .title("可疑文件检测")
    .inner_size(520.0, 320.0)
    .decorations(false)
    .transparent(true)
    .shadow(true)
    .always_on_top(true)
    .skip_taskbar(true)
    .resizable(false)
    .visible(false)
    .build()
    .map_err(|e| format!("Failed to create suspicious intercept window: {}", e))?;

    // 屏幕居中定位
    #[cfg(windows)]
    {
        use tauri::Position;
        use windows::Win32::Graphics::Gdi::{GetDeviceCaps, LOGPIXELSX};
        unsafe {
            let hwnd = GetForegroundWindow();
            let hmonitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
            let mut mi = MONITORINFO::default();
            mi.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
            if GetMonitorInfoW(hmonitor, &mut mi).as_bool() {
                let hdc = GetDC(None);
                let dpi = GetDeviceCaps(hdc, LOGPIXELSX) as f32;
                let _ = ReleaseDC(None, hdc);
                let scale = dpi / 96.0;
                let w = (520.0 * scale) as i32;
                let h = (320.0 * scale) as i32;
                let cx = (mi.rcWork.left + mi.rcWork.right) / 2;
                let cy = (mi.rcWork.top + mi.rcWork.bottom) / 2;
                let x = cx - w / 2;
                let y = cy - h / 2;
                let _ = window.set_position(Position::Physical(tauri::PhysicalPosition { x, y }));
            }
        }
    }

    window.show().map_err(|e| format!("Failed to show: {}", e))?;
    window.set_focus().map_err(|e| format!("Failed to focus: {}", e))?;
    Ok(())
}

/// 处理可疑文件拦截决策
#[tauri::command]
async fn send_suspicious_decision(app: tauri::AppHandle, decision: String, pid: u32) -> Result<(), String> {
    if decision == "block" {
        let _ = terminate_process(pid).await;
    } else {
        let _ = resume_process(pid).await;
    }
    if let Some(win) = app.get_webview_window("intercept-suspicious") {
        let _ = win.close();
    }
    Ok(())
}

/// 可疑文件云端沙箱分析（由拦截窗口调用）
/// 仅对 .exe 可执行文件执行沙箱上传，忽略 DLL 及其他文件类型
#[tauri::command]
async fn suspicious_analyze_file(_app: tauri::AppHandle, file_path: String, _pid: u32) -> Result<serde_json::Value, String> {
    // 文件类型检查：仅上传 .exe 可执行文件
    let lower_path = file_path.to_lowercase();
    if !lower_path.ends_with(".exe") {
        eprintln!("[Suspicious] 跳过非可执行文件（仅沙箱分析 .exe）: {}", file_path);
        return Ok(serde_json::json!({
            "verdict": "skip",
            "reason": "仅支持 .exe 可执行文件的沙箱分析",
            "score": 0,
            "sha256": ""
        }));
    }

    // 文件大小检查：跳过超过 50MB 的文件（沙箱无法处理过大文件）
    if let Ok(metadata) = std::fs::metadata(&file_path) {
        if metadata.len() > 50 * 1024 * 1024 {
            eprintln!("[Suspicious] 跳过过大文件（超过 50MB）: {} ({} bytes)", file_path, metadata.len());
            return Ok(serde_json::json!({
                "verdict": "skip",
                "reason": "文件过大（超过 50MB），跳过沙箱分析",
                "score": 0,
                "sha256": ""
            }));
        }
    }

    // 计算文件 SHA256
    let sha256 = {
        use std::io::Read;
        use sha2::Digest;
        let mut file = std::fs::File::open(&file_path).map_err(|e| e.to_string())?;
        let mut hasher = sha2::Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 { break; }
            hasher.update(&buf[..n]);
        }
        format!("{:x}", hasher.finalize())
    };

    eprintln!("[Suspicious] 开始云端分析: {} (SHA256: {})", file_path, sha256);

    // 上传到微步沙箱
    let client = reqwest::Client::new();
    let file_bytes = std::fs::read(&file_path).map_err(|e| e.to_string())?;
    let file_part = reqwest::multipart::Part::bytes(file_bytes)
        .file_name(std::path::Path::new(&file_path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string())
        .mime_str("application/octet-stream")
            .unwrap();

    let form = reqwest::multipart::Form::new()
        .part("file", file_part)
        .text("sandbox_type", "win10_22h2_enx64_office2019")
        .text("run_time", "120");

    let upload_resp = client
        .post(format!("{}/v3/file/upload", SANDBOX_RELAY_BASE))
        .header("X-API-Key", SANDBOX_API_KEY)
        .multipart(form)
        .send()
        .await
        .map_err(|e| format!("Upload failed: {}", e))?;

    let upload_json: serde_json::Value = upload_resp.json().await.map_err(|e| e.to_string())?;
    eprintln!("[Suspicious] 上传响应: {}", serde_json::to_string(&upload_json).unwrap_or_default());

    // 轮询报告（最多等待 180 秒）
    let mut report: Option<serde_json::Value> = None;
    for i in 0..60 {
        if i > 0 {
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        }

        let report_resp = client
            .post(format!("{}/v3/file/report", SANDBOX_RELAY_BASE))
            .header("X-API-Key", SANDBOX_API_KEY)
            .json(&serde_json::json!({"resource": sha256}))
            .send()
            .await;

        match report_resp {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    let has_data = json.get("data").and_then(|d| d.as_object()).map(|o| !o.is_empty()).unwrap_or(false);
                    let rc = json.get("response_code").and_then(|c| c.as_i64()).unwrap_or(-99);
                    eprintln!("[Suspicious] 第{}次查询: rc={}, has_data={}", i+1, rc, has_data);
                    if rc == 0 && has_data {
                        report = Some(json);
                        break;
                    }
                }
            }
            Err(e) => {
                eprintln!("[Suspicious] 查询失败: {}", e);
            }
        }
    }

    let report = report.ok_or_else(|| "云端分析超时".to_string())?;

    // 解析结果
    let data = report.get("data").cloned().unwrap_or(serde_json::Value::Null);
    let summary = data.get("summary").cloned().unwrap_or(serde_json::Value::Null);
    let multiengines = data.get("multiengines").cloned().unwrap_or(serde_json::Value::Null);

    let threat_score = summary.get("threat_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let detect_rate = multiengines.get("detect_rate").and_then(|v| v.as_str()).unwrap_or("0/0");

    // 判定
    let detect_count = detect_rate.split('/').next().and_then(|s| s.parse::<i32>().ok()).unwrap_or(0);
    let verdict = if detect_count >= 5 || threat_score > 70.0 {
        "malicious"
    } else if detect_count >= 3 || threat_score > 50.0 {
        "suspicious"
    } else {
        "safe"
    };

    eprintln!("[Suspicious] 分析完成: verdict={}, threat_score={}, detect_rate={}", verdict, threat_score, detect_rate);

    Ok(serde_json::json!({
        "verdict": verdict,
        "threat_score": threat_score,
        "detect_rate": detect_rate,
        "detect_count": detect_count,
        "data": data,
    }))
}

// 基础防护文件扫描（使用本地引擎）
#[tauri::command]
async fn scan_file_basic(app: tauri::AppHandle, file_path: String, pid: Option<u32>, pua_enabled: Option<bool>) -> Result<serde_json::Value, String> {
    // 先检查是否为 PUA 捆绑软件
    if let Some(filename) = std::path::Path::new(&file_path).file_name() {
        if let Some(name) = filename.to_str() {
            let lower = name.to_lowercase();
            let is_pua = PUA_PROCESS_NAMES.iter().any(|&pua| lower == pua);
            if is_pua && pua_enabled.unwrap_or(false) {
                // 后端直接挂起进程
                if let Some(process_pid) = pid {
                    let _ = suspend_process(process_pid).await;
                }
                // 后端直接弹出拦截窗口
                let _ = show_pua_intercept_window(
                    app.clone(),
                    name.to_string(),
                    file_path.clone(),
                    pid.unwrap_or(0),
                ).await;
                return Ok(serde_json::json!({
                    "isThreat": true,
                    "threatName": "PUA:捆绑软件",
                    "confidence": 1.0,
                    "result": "PUA",
                    "processName": name
                }));
            }
        }
    }

    // 可疑文件名检测：命中名单直接挂起并弹出拦截窗口
    if let Some(filename) = std::path::Path::new(&file_path).file_name() {
        if let Some(name) = filename.to_str() {
            let lower = name.to_lowercase();
            let is_suspicious = SUSPICIOUS_PROCESS_NAMES.iter().any(|&s| lower == s);
            let intercept_enabled = get_suspicious_intercept_enabled();
            eprintln!("[Suspicious] 文件名检查: name={}, is_suspicious={}, intercept_enabled={}", name, is_suspicious, intercept_enabled);
            if is_suspicious && intercept_enabled {
                eprintln!("[Suspicious] 命中可疑名单，挂起进程 pid={:?}", pid);
                if let Some(process_pid) = pid {
                    match suspend_process(process_pid).await {
                        Ok(()) => eprintln!("[Suspicious] 进程 {} 已挂起", process_pid),
                        Err(e) => eprintln!("[Suspicious] 挂起进程失败: {}", e),
                    }
                }
                match show_suspicious_intercept_window(
                    app.clone(),
                    name.to_string(),
                    file_path.clone(),
                    pid.unwrap_or(0),
                    0.70,
                ).await {
                    Ok(()) => eprintln!("[Suspicious] 拦截窗口已弹出"),
                    Err(e) => eprintln!("[Suspicious] 弹出拦截窗口失败: {}", e),
                }
                return Ok(serde_json::json!({
                    "isThreat": false,
                    "threatName": "",
                    "confidence": 0.70,
                    "result": "SUSPICIOUS",
                    "processName": name
                }));
            }
        }
    }

    // 调用现有的扫描引擎（跳过病毒家族分析——先杀进程再异步分析）
    use scanner::SCANNER;
    use scanner::SKIP_FAMILY_ANALYSIS;

    // 引擎扫描为 CPU 密集同步操作，移入 spawn_blocking
    // 避免阻塞 async 运行时工作线程导致其他命令排队延迟
    let file_path_clone = file_path.clone();
    let scan_result = tokio::task::spawn_blocking(move || -> Result<scanner::ScanResult, String> {
        // 设置跳过标志：让 scan_file 不执行耗时的病毒家族分析
        SKIP_FAMILY_ANALYSIS.store(true, std::sync::atomic::Ordering::Relaxed);
        let result = {
            let scanner = SCANNER.read().map_err(|e| e.to_string())?;
            scanner.scan_file(&file_path_clone, None)
        };
        SKIP_FAMILY_ANALYSIS.store(false, std::sync::atomic::Ordering::Relaxed);
        Ok(result)
    }).await.map_err(|e| format!("扫描任务失败: {}", e))??;

    // 安装包/打包器引擎跳过 → 不威胁也不提交沙箱
    if scan_result.result == "INSTALLER" {
        let installer_info = scan_result.virus_family.unwrap_or_default();
        return Ok(serde_json::json!({
            "isThreat": false,
            "threatName": installer_info,
            "confidence": 0.0,
            "result": "INSTALLER",
            "processName": std::path::Path::new(&file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown"),
        }));
    }

    let is_threat = scan_result.result == "MALICIOUS";
    let probability = scan_result.probability;
    let family_raw = scan_result.virus_family;

    // 引擎检出威胁 → 立即返回结果让前端处理（前端优先使用驱动杀）
    if is_threat {
        let process_name = std::path::Path::new(&file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        // 使用快速路径的 family 名（或通用名）
        let threat_name = family_raw.unwrap_or_else(|| {
            format!("HEUR:Trojan.Win32.Generic!ml ({:.1}%)", probability * 100.0)
        });

        return Ok(serde_json::json!({
            "isThreat": true,
            "threatName": threat_name,
            "confidence": probability,
            "result": "MALICIOUS",
            "processName": process_name,
        }));
    }

    // ── 深度分析：引擎未检出但可疑分数达阈值时，自动提交沙箱 ──
    if !is_threat && probability < 0.85 && get_cloud_deep_analysis_enabled() {
        let score = deep_analysis::calculate_suspicion_score(&file_path);
        if score.should_deep_analyze {
            // 先发通知给前端（显示右上角通知 + 进度条）
            let _ = app.emit("deep-analysis-start", serde_json::json!({
                "filePath": file_path,
                "score": score.total,
                "reasons": score.reasons,
            }));
            // 同步堵塞等待沙箱结果
            match deep_analysis::run_deep_analysis(&app, &file_path).await {
                Ok(da_result) => {
                    eprintln!("[DeepAnalysis] 沙箱返回: verdict={}, score={}, family={}",
                        da_result.sandbox_verdict, da_result.threat_score, da_result.threat_family);
                    let _ = app.emit("deep-analysis-done", serde_json::json!({
                        "verdict": da_result.sandbox_verdict,
                        "threatScore": da_result.threat_score,
                        "threatFamily": da_result.threat_family,
                        "malicious": da_result.malicious,
                        "iocs": da_result.iocs,
                    }));
                    if da_result.malicious {
                        let family = if !da_result.threat_family.is_empty() {
                            da_result.threat_family.clone()
                        } else {
                            format!("Sandbox:{}", da_result.sandbox_verdict)
                        };
                        return Ok(serde_json::json!({
                            "isThreat": true,
                            "threatName": format!("{} (沙箱检测)", family),
                            "confidence": (da_result.threat_score / 100.0).min(1.0),
                            "result": "MALICIOUS",
                            "sandboxResult": da_result.sandbox_verdict,
                        }));
                    }
                }
                Err(e) => {
                    eprintln!("[DeepAnalysis] 深度分析失败: {}", e);
                    let _ = app.emit("deep-analysis-error", serde_json::json!({
                        "error": e,
                    }));
                }
            }
        }
    }

    // 可疑文件拦截：概率 > 0.85 且不是明确恶意（MALICIOUS 由前端单独处理）
    let suspicious_enabled = get_suspicious_intercept_enabled();
    if !is_threat && probability > 0.85 && suspicious_enabled {
        if let Some(filename) = std::path::Path::new(&file_path).file_name() {
            let name = filename.to_string_lossy().to_string();
            eprintln!("[Suspicious] 检测到可疑文件: {} (概率: {:.2})", name, probability);
            // 挂起进程
            if let Some(process_pid) = pid {
                let _ = suspend_process(process_pid).await;
            }
            // 弹出拦截窗口
            let _ = show_suspicious_intercept_window(
                app.clone(),
                name,
                file_path.clone(),
                pid.unwrap_or(0),
                probability as f64,
            ).await;
            return Ok(serde_json::json!({
                "isThreat": false,
                "threatName": "",
                "confidence": probability,
                "result": "SUSPICIOUS",
                "processName": std::path::Path::new(&file_path).file_name().unwrap_or_default().to_string_lossy()
            }));
        }
    }

    Ok(serde_json::json!({
        "isThreat": is_threat,
        "threatName": family_raw.unwrap_or_default(),
        "confidence": probability,
        "result": if is_threat { "MALICIOUS" } else { "CLEAN" }
    }))
}

/// 自定义扫描 + 深度分析（与引擎扫描结果保持一致，额外支持可疑文件沙箱验证）
#[tauri::command]
async fn scan_file_with_deep_analysis(app: tauri::AppHandle, file_path: String) -> Result<String, String> {
    use scanner::SCANNER;

    // 1. 引擎扫描（CPU 密集同步操作，移入 spawn_blocking 避免阻塞 async 运行时）
    let file_path_clone = file_path.clone();
    let (scan_result, scan_json) = tokio::task::spawn_blocking(move || -> Result<(scanner::ScanResult, String), String> {
        let scanner = SCANNER.read().map_err(|e| e.to_string())?;
        let result = scanner.scan_file(&file_path_clone, None);
        let json = serde_json::to_string(&result).map_err(|e| e.to_string())?;
        Ok((result, json))
    }).await.map_err(|e| format!("扫描任务失败: {}", e))??;

    // 2. 引擎未检出恶意时，判断是否需要深度分析
    let is_malicious = scan_result.result == "MALICIOUS";
    if !is_malicious && scan_result.probability < 0.85 && get_cloud_deep_analysis_enabled() {
        let score = deep_analysis::calculate_suspicion_score(&file_path);
        if score.should_deep_analyze {
            // 发事件
            let _ = app.emit("deep-analysis-start", serde_json::json!({
                "filePath": file_path,
                "score": score.total,
                "reasons": score.reasons,
            }));

            // 堵塞等待沙箱
            match deep_analysis::run_deep_analysis(&app, &file_path).await {
                Ok(da) => {
                    let _ = app.emit("deep-analysis-done", serde_json::json!({
                        "verdict": da.sandbox_verdict,
                        "threatScore": da.threat_score,
                        "threatFamily": da.threat_family,
                        "malicious": da.malicious,
                        "iocs": da.iocs,
                    }));
                    if da.malicious {
                        // 沙箱判定为恶意 → 覆盖原始扫描结果
                        let family = if !da.threat_family.is_empty() && da.threat_family != "HVM:unknown" {
                            da.threat_family.clone()
                        } else {
                            // 云端没有给出家族，使用本地引擎
                            match std::fs::read(&file_path) {
                                Ok(data) => {
                                    let local = crate::scanner::virus_family::analyze_family(
                                        &data, &file_path, true, (da.threat_score / 100.0).min(1.0) as f32
                                    );
                                    format!("HVM:{}", local.detection_name)
                                }
                                Err(_) => format!("HVM:{}", da.sandbox_verdict),
                            }
                        };
                        let enriched = serde_json::json!({
                            "file_path": file_path,
                            "result": "MALICIOUS",
                            "probability": (da.threat_score / 100.0).min(1.0),
                            "virus_family": family,
                            "family_category": da.family_category,
                            "is_trusted": false,
                            "is_infector": false,
                        });
                        return serde_json::to_string(&enriched).map_err(|e| e.to_string());
                    }
                }
                Err(e) => {
                    eprintln!("[DeepAnalysis] 自定义扫描深度分析失败: {}", e);
                    let _ = app.emit("deep-analysis-error", serde_json::json!({"error": e}));
                }
            }
        }
    }

    Ok(scan_json)
}

// ========== 路径白名单管理命令 ==========

#[tauri::command]
fn add_whitelist_path_command(path: String) -> Result<(), String> {
    crate::whitelist::add_whitelist_path(path)
}

// 通知中心"允许"按钮使用的别名（与 add_whitelist_path_command 相同逻辑）
#[tauri::command]
fn add_to_whitelist(path: String) -> Result<(), String> {
    crate::whitelist::add_whitelist_path(path)
}

#[tauri::command]
fn remove_whitelist_path_command(path: String) -> Result<(), String> {
    crate::whitelist::remove_whitelist_path(&path)
}

#[tauri::command]
fn get_whitelist_paths_command() -> Vec<String> {
    crate::whitelist::get_whitelist_paths()
}

#[tauri::command]
fn is_path_whitelisted_command(path: String) -> bool {
    crate::whitelist::is_path_whitelisted(&path)
}

// ========== 进程名白名单管理命令（同步到 EDR 驱动白名单） ==========

#[tauri::command]
fn add_whitelist_process_command(name: String) -> Result<(), String> {
    crate::whitelist::add_whitelist_process(name)
}

#[tauri::command]
fn remove_whitelist_process_command(name: String) -> Result<(), String> {
    crate::whitelist::remove_whitelist_process(&name)
}

#[tauri::command]
fn get_whitelist_processes_command() -> Vec<String> {
    crate::whitelist::get_whitelist_processes()
}

#[tauri::command]
fn is_process_whitelisted_command(name: String) -> bool {
    crate::whitelist::is_process_whitelisted(&name)
}

// ========== 网页域名白名单管理命令（netproxy 热加载生效） ==========

#[tauri::command]
fn add_whitelist_domain_command(domain: String) -> Result<(), String> {
    crate::whitelist::add_whitelist_domain(domain)
}

#[tauri::command]
fn remove_whitelist_domain_command(domain: String) -> Result<(), String> {
    crate::whitelist::remove_whitelist_domain(&domain)
}

#[tauri::command]
fn get_whitelist_domains_command() -> Vec<String> {
    crate::whitelist::get_whitelist_domains()
}

#[tauri::command]
fn is_domain_whitelisted_command(domain: String) -> bool {
    crate::whitelist::is_domain_whitelisted(&domain)
}

// ========== 路径黑名单管理命令 ==========

#[tauri::command]
fn add_blacklist_path_command(path: String) -> Result<(), String> {
    crate::blacklist::add_blacklist_path(path)
}

#[tauri::command]
fn remove_blacklist_path_command(path: String) -> Result<(), String> {
    crate::blacklist::remove_blacklist_path(&path)
}

#[tauri::command]
fn get_blacklist_paths_command() -> Vec<String> {
    crate::blacklist::get_blacklist_paths()
}

#[tauri::command]
fn is_path_blacklisted_command(path: String) -> bool {
    crate::blacklist::is_path_blacklisted(&path)
}

// 防护配置结构
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ProtectionConfig {
    #[serde(default = "default_true")]
    boot: bool,
    #[serde(default = "default_true")]
    registry: bool,
    #[serde(default = "default_false")]
    ransomware: bool, // 勒索软件防护默认关闭（误报率高）
    #[serde(default = "default_true")]
    process: bool,
    #[serde(default = "default_true")]
    memory: bool,
    #[serde(default = "default_true")]
    new_intercept_window: bool, // 新拦截窗口：通过管道与主程序通讯
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

impl Default for ProtectionConfig {
    fn default() -> Self {
        ProtectionConfig {
            boot: true,
            registry: true,
            ransomware: false, // 勒索软件防护默认关闭
            process: true,
            memory: true,
            new_intercept_window: true,
        }
    }
}

fn get_protection_config_path() -> String {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    format!("{}/XIGUASecurity/protection_config.json", local_app_data)
}

#[tauri::command]
fn get_protection_config() -> ProtectionConfig {
    let config_path = get_protection_config_path();
    std::fs::read_to_string(&config_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

#[tauri::command]
fn set_protection_config(config: ProtectionConfig, app: tauri::AppHandle) -> Result<(), String> {
    let config_path = get_protection_config_path();
    let config_dir = std::path::Path::new(&config_path).parent().ok_or("Invalid path")?;
    std::fs::create_dir_all(config_dir).map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    std::fs::write(&config_path, json).map_err(|e| e.to_string())?;
    // 同步 R3 勒索软件防护
    let manager = crate::ransomware_protection::get_ransomware_protection();
    {
        let mgr = manager.lock().unwrap();
        mgr.set_enabled(config.ransomware);
    }
    if config.ransomware {
        manager.lock().unwrap().start(app, false)?;
    } else {
        manager.lock().unwrap().stop(app)?;
    }
    Ok(())
}

// 感染型病毒清除命令
#[tauri::command]
async fn clean_infector_file(file_path: String, quarantine_dir: String) -> Result<CleaningResult, String> {
    use crate::scanner::clean_infected_file;
    
    let result = clean_infected_file(&file_path, &quarantine_dir);
    Ok(result)
}

// ==================== 垃圾清理命令 ====================

/// 扫描垃圾文件
#[tauri::command]
fn scan_junk_command(categories: Vec<String>) -> Result<serde_json::Value, String> {
    use std::path::PathBuf;
    use std::fs;

    let mut items: Vec<serde_json::Value> = Vec::new();
    let mut cat_sizes: Vec<serde_json::Value> = Vec::new();

    for cat in &categories {
        let paths = match cat.as_str() {
            "temp" => {
                let mut dirs = vec![std::env::var("TEMP").unwrap_or_else(|_| "C:\\Windows\\Temp".into())];
                dirs.push("C:\\Windows\\Temp".into());
                dirs
            }
            "prefetch" => vec!["C:\\Windows\\Prefetch".into()],
            "recycle" => vec!["C:\\$Recycle.Bin".into()],
            "browser" => {
                let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
                vec![
                    format!("{}\\Google\\Chrome\\User Data\\Default\\Cache", local),
                    format!("{}\\Google\\Chrome\\User Data\\Default\\Code Cache", local),
                    format!("{}\\Microsoft\\Edge\\User Data\\Default\\Cache", local),
                    format!("{}\\Microsoft\\Edge\\User Data\\Default\\Code Cache", local),
                ]
            }
            "logs" => vec!["C:\\Windows\\Logs".into()],
            "dumps" => vec!["C:\\Windows\\Minidump".into()],
            _ => continue,
        };

        let mut cat_total: u64 = 0;

        for dir in &paths {
            let p = PathBuf::from(dir);
            if !p.exists() { continue; }
            if let Ok(entries) = fs::read_dir(&p) {
                for entry in entries.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        if meta.is_file() {
                            let size = meta.len();
                            cat_total += size;
                            if let Some(path_str) = entry.path().to_str() {
                                // 只记录超过 1KB 的文件
                                if size > 1024 {
                                    items.push(serde_json::json!({
                                        "path": path_str,
                                        "size": size,
                                    }));
                                }
                            }
                        }
                    }
                }
            }
        }

        cat_sizes.push(serde_json::json!({
            "name": cat,
            "size": cat_total,
        }));
    }

    Ok(serde_json::json!({
        "items": items,
        "categories": cat_sizes,
    }))
}

/// 清理垃圾文件
#[tauri::command]
fn clean_junk_command(categories: Vec<String>) -> Result<serde_json::Value, String> {
    use std::path::PathBuf;
    use std::fs;

    let mut freed: u64 = 0;

    for cat in &categories {
        let paths = match cat.as_str() {
            "temp" => {
                let mut dirs = vec![std::env::var("TEMP").unwrap_or_else(|_| "C:\\Windows\\Temp".into())];
                dirs.push("C:\\Windows\\Temp".into());
                dirs
            }
            "prefetch" => vec!["C:\\Windows\\Prefetch".into()],
            "recycle" => {
                // 回收站使用 cmd.exe 清空
                let _ = std::process::Command::new("cmd")
                    .args(&["/C", "rd", "/s", "/q", "C:\\$Recycle.Bin"])
                    .spawn();
                continue;
            }
            "browser" => {
                let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
                vec![
                    format!("{}\\Google\\Chrome\\User Data\\Default\\Cache", local),
                    format!("{}\\Google\\Chrome\\User Data\\Default\\Code Cache", local),
                    format!("{}\\Microsoft\\Edge\\User Data\\Default\\Cache", local),
                    format!("{}\\Microsoft\\Edge\\User Data\\Default\\Code Cache", local),
                ]
            }
            "logs" => vec!["C:\\Windows\\Logs".into()],
            "dumps" => vec!["C:\\Windows\\Minidump".into()],
            _ => continue,
        };

        for dir in &paths {
            let p = PathBuf::from(dir);
            if !p.exists() { continue; }
            if let Ok(entries) = fs::read_dir(&p) {
                for entry in entries.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        if meta.is_file() {
                            let size = meta.len();
                            let _ = fs::remove_file(entry.path());
                            freed += size;
                        }
                    }
                }
            }
        }
    }

    // 也清理临时目录下更深层的文件
    if categories.contains(&"temp".to_string()) {
        let temp_dir = std::env::var("TEMP").unwrap_or_else(|_| "C:\\Windows\\Temp".into());
        if let Ok(entries) = fs::read_dir(&temp_dir) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if meta.is_dir() {
                        let _ = fs::remove_dir_all(entry.path());
                    } else if meta.is_file() {
                        let size = meta.len();
                        let _ = fs::remove_file(entry.path());
                        freed += size;
                    }
                }
            }
        }
    }

    Ok(serde_json::json!({
        "freed_bytes": freed,
    }))
}

// 获取驱动防护统计信息
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
fn get_driver_stats(state: State<'_, DriverProtectionState>) -> Result<serde_json::Value, String> {
    let count = *state.process_check_count.lock().map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "process_check_count": count
    }))
}

// ==================== 浏览器防护命令 ====================

/// 打开 Edge 浏览器并加载浏览器防护插件
#[tauri::command]
fn open_browser_protection() -> Result<String, String> {
    // === 1. 确定插件路径（优先 exe 同级目录，回退到源码目录）===
    // 最终用户机器上，插件在 exe 同级的 extensions/browser-protection/
    // 开发模式下，插件在项目根目录 D:\XIGUASecurity10x\extensions\browser-protection/
    let ext_path = std::env::current_exe()
        .ok()
        .as_ref()
        .and_then(|exe| exe.parent())
        .and_then(|base| {
            // 1) exe 同级
            let p = base.join("extensions").join("browser-protection");
            if p.exists() { return Some(p); }
            // 2) dev 模式：exe 在 src-tauri/target/debug/，往上 4 层到项目根
            let dev = base.join("..").join("..").join("..").join("..")
                .join("extensions").join("browser-protection");
            if dev.exists() { return Some(dev); }
            None
        })
        .unwrap_or_else(|| {
            // 最后回退：编译时嵌入的源码路径
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent().and_then(|p| p.parent())
                .map(|p| p.join("extensions").join("browser-protection"))
                .unwrap_or_else(|| std::path::PathBuf::from("extensions").join("browser-protection"))
        });

    if !ext_path.exists() {
        return Err(format!(
            "插件目录不存在: {}\n请确保程序目录下存在 extensions/browser-protection/ 文件夹",
            ext_path.display()
        ));
    }

    // 解析为绝对路径
    let ext_abs = std::fs::canonicalize(&ext_path)
        .map_err(|e| format!("无法解析插件路径: {}", e))?;
    let ext_str = ext_abs.to_string_lossy().to_string();

    // === 2. 查找 Edge 浏览器 ===
    let edge_path = find_edge_path()?;

    println!("[BrowserProtection] Edge: {}", edge_path);
    println!("[BrowserProtection] Extension: {}", ext_str);

    // === 3. 启动 Edge：打开扩展管理页面，同时 --load-extension 加载插件 ===
    #[cfg(windows)]
    {
        use std::process::Command;
        Command::new(&edge_path)
            .arg(format!("--load-extension={}", ext_str))
            .arg("edge://extensions/")
            .spawn()
            .map_err(|e| format!("启动 Edge 失败: {}", e))?;
    }

    #[cfg(not(windows))]
    {
        use std::process::Command;
        Command::new(&edge_path)
            .arg(format!("--load-extension={}", ext_str))
            .arg("edge://extensions/")
            .spawn()
            .map_err(|e| format!("启动 Edge 失败: {}", e))?;
    }

    // 返回插件绝对路径，前端显示给用户参考
    Ok(ext_str)
}

/// 查找 Edge 可执行文件路径
fn find_edge_path() -> Result<String, String> {
    let edge_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\msedge.exe",
    ];

    for p in &edge_paths {
        if std::path::Path::new(p).exists() {
            return Ok(p.to_string());
        }
    }

    // 从 PATH 查找
    #[cfg(windows)]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("where").arg("msedge").output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !path.is_empty() && std::path::Path::new(&path).exists() {
                    return Ok(path);
                }
            }
        }
        // 注册表查找
        if let Ok(output) = Command::new("reg")
            .args(&["query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe", "/ve"])
            .output()
        {
            if output.status.success() {
                let out = String::from_utf8_lossy(&output.stdout);
                for line in out.lines() {
                    let trimmed = line.trim();
                    if trimmed.contains("REG_SZ") || trimmed.contains("REG_EXPAND_SZ") {
                        if let Some(val) = trimmed.rsplit_once("  ") {
                            let path = val.1.trim().to_string();
                            if std::path::Path::new(&path).exists() {
                                return Ok(path);
                            }
                        }
                    }
                }
            }
        }
    }

    Err("未找到 Edge 浏览器，请确保已安装 Microsoft Edge".to_string())
}

// ==================== 安全日志命令 ====================

#[tauri::command]
fn get_security_logs(
    start_date: Option<String>,
    end_date: Option<String>,
    category: Option<String>,
    keyword: Option<String>,
    page: usize,
    page_size: usize,
) -> Result<serde_json::Value, String> {
    let manager = get_log_manager()?;
    
    // 转换类别字符串为枚举
    let category_enum = category.and_then(|c| match c.as_str() {
        "scan" => Some(LogCategory::Scan),
        "realtime" => Some(LogCategory::Realtime),
        "behavior" => Some(LogCategory::Behavior),
        "driver" => Some(LogCategory::Driver),
        "update" => Some(LogCategory::Update),
        "quarantine" => Some(LogCategory::Quarantine),
        "system" => Some(LogCategory::System),
        _ => None,
    });
    
    let (logs, total) = manager.get_logs(start_date, end_date, category_enum, keyword, page, page_size)?;
    
    Ok(serde_json::json!({
        "logs": logs,
        "total": total,
        "page": page,
        "page_size": page_size
    }))
}

#[tauri::command]
fn get_security_log_stats(days: i64) -> Result<LogStats, String> {
    let manager = get_log_manager()?;
    manager.get_log_stats(days)
}

#[tauri::command]
fn clear_security_logs(
    start_date: Option<String>,
    end_date: Option<String>,
) -> Result<u64, String> {
    let manager = get_log_manager()?;
    manager.clear_logs(start_date, end_date)
}

#[tauri::command]
async fn export_security_logs(
    start_date: Option<String>,
    end_date: Option<String>,
    category: Option<String>,
    keyword: Option<String>,
    export_path: String,
) -> Result<u64, String> {
    let manager = get_log_manager()?;
    
    // 转换类别字符串为枚举
    let category_enum = category.and_then(|c| match c.as_str() {
        "scan" => Some(LogCategory::Scan),
        "realtime" => Some(LogCategory::Realtime),
        "behavior" => Some(LogCategory::Behavior),
        "driver" => Some(LogCategory::Driver),
        "update" => Some(LogCategory::Update),
        "quarantine" => Some(LogCategory::Quarantine),
        "system" => Some(LogCategory::System),
        _ => None,
    });
    
    manager.export_logs(start_date, end_date, category_enum, keyword, &export_path)
}

#[tauri::command]
fn add_security_log(
    category: String,
    function: String,
    summary: String,
    file_path: Option<String>,
    threat_name: Option<String>,
    action: String,
    result: String,
    details: Option<serde_json::Value>,
) -> Result<(), String> {
    use security_log::{LogCategory, LogAction, LogResult, LogDetails};
    
    let category_enum = match category.as_str() {
        "scan" => LogCategory::Scan,
        "realtime" => LogCategory::Realtime,
        "behavior" => LogCategory::Behavior,
        "driver" => LogCategory::Driver,
        "update" => LogCategory::Update,
        "quarantine" => LogCategory::Quarantine,
        "system" => LogCategory::System,
        _ => LogCategory::Other,
    };
    
    let action_enum = match action.as_str() {
        "detected" => LogAction::Detected,
        "blocked" => LogAction::Blocked,
        "cleaned" => LogAction::Cleaned,
        "quarantined" => LogAction::Quarantined,
        "deleted" => LogAction::Deleted,
        "allowed" => LogAction::Allowed,
        "scanned" => LogAction::Scanned,
        "updated" => LogAction::Updated,
        "started" => LogAction::Started,
        "stopped" => LogAction::Stopped,
        _ => LogAction::Info,
    };
    
    let result_enum = match result.as_str() {
        "success" => LogResult::Success,
        "failed" => LogResult::Failed,
        "partial" => LogResult::Partial,
        "cancelled" => LogResult::Cancelled,
        "pending" => LogResult::Pending,
        _ => LogResult::Success,
    };
    
    let details_obj = details.and_then(|d| {
        serde_json::from_value::<LogDetails>(d).ok()
    });
    
    security_log::add_security_log(
        category_enum,
        &function,
        &summary,
        file_path,
        threat_name,
        action_enum,
        result_enum,
        details_obj,
    )
}

// 记录扫描事件到时间线
#[tauri::command]
fn add_scan_timeline_event(
    event_type: String,
    title: String,
    description: String,
    _scanned_files: Option<u32>,
    threats_found: Option<u32>,
) {
    // 先克隆 description 用于安全日志
    let description_for_log = description.clone();
    
    let event = TimelineEvent {
        id: format!("scan_{}_{}", event_type, chrono::Local::now().timestamp()),
        timestamp: chrono::Local::now().to_rfc3339(),
        event_type: "scan".to_string(),
        title,
        description,
        process_name: None,
        result: match event_type.as_str() {
            "start" => Some("进行中".to_string()),
            "completed" => Some(format!("发现 {} 个威胁", threats_found.unwrap_or(0))),
            _ => Some("完成".to_string()),
        },
    };
    add_timeline_event(event);
    
    // 同时记录到安全日志
    let _ = security_log::add_security_log(
        security_log::LogCategory::Scan,
        "扫描任务",
        &description_for_log,
        None,
        None,
        match event_type.as_str() {
            "start" => security_log::LogAction::Started,
            _ => security_log::LogAction::Scanned,
        },
        security_log::LogResult::Success,
        None,
    );
}

// 扫描设置命令 - 感染型病毒检测
#[tauri::command]
fn get_infector_detection_enabled() -> bool {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_path = format!("{}/XIGUASecurity/infector_detection_enabled.txt", local_app_data);
    std::fs::read_to_string(&config_path)
        .map(|s| s.trim() == "true")
        .unwrap_or(true) // 默认开启
}

#[tauri::command]
fn set_infector_detection_enabled(enabled: bool) {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_dir = format!("{}/XIGUASecurity", local_app_data);
    let _ = std::fs::create_dir_all(&config_dir);
    let config_path = format!("{}/infector_detection_enabled.txt", config_dir);
    let _ = std::fs::write(&config_path, if enabled { "true" } else { "false" });
}

// 扫描设置命令 - 病毒家族分析
#[tauri::command]
fn get_virus_family_analysis_enabled() -> bool {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_path = format!("{}/XIGUASecurity/virus_family_analysis_enabled.txt", local_app_data);
    std::fs::read_to_string(&config_path)
        .map(|s| s.trim() == "true")
        .unwrap_or(true) // 默认开启
}

#[tauri::command]
fn set_virus_family_analysis_enabled(enabled: bool) {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_dir = format!("{}/XIGUASecurity", local_app_data);
    let _ = std::fs::create_dir_all(&config_dir);
    let config_path = format!("{}/virus_family_analysis_enabled.txt", config_dir);
    let _ = std::fs::write(&config_path, if enabled { "true" } else { "false" });
}

/// 获取已加载的病毒家族检测规则信息
#[tauri::command]
fn get_loaded_rules_command() -> Result<serde_json::Value, String> {
    Ok(crate::scanner::virus_family::rule_engine::get_loaded_rules_info())
}

// 驱动防护配置保存/读取 - 默认开启
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
fn get_driver_protection_config_enabled() -> bool {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_path = format!("{}/XIGUASecurity/driver_protection_enabled.txt", local_app_data);
    std::fs::read_to_string(&config_path)
        .map(|s| s.trim() == "true")
        .unwrap_or(true) // 默认开启
}

#[tauri::command]
#[cfg(not(feature = "ms_store"))]
fn set_driver_protection_config_enabled(enabled: bool) {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_dir = format!("{}/XIGUASecurity", local_app_data);
    let _ = std::fs::create_dir_all(&config_dir);
    let config_path = format!("{}/driver_protection_enabled.txt", config_dir);
    let _ = std::fs::write(&config_path, if enabled { "true" } else { "false" });
}

// ==================== 增强端点防护（MelixEDR）集成 ====================
// 该模块负责接入外部专业端点防护项目 MelixEDR。启动顺序（必须严格遵守）：
//   1. 运行 install-driver.ps1（绕过执行策略 + RUNAS 管理员），安装并加载 MelixDrv.sys 驱动
//   2. 运行 Service/Melix.Service.exe（RUNAS 管理员），连接驱动并处理后端逻辑
//   3. 运行 Melix.UI.exe（普通权限），根据后台服务状态在界面显示是否已保护
// 打包时整个 Driver/ 目录（含 MelixEDR/）已由 tauri.conf.json 的 resources 复制到程序目录。

// 端点防护开关配置读写 - 默认关闭（需用户确认开启）
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
fn get_endpoint_protection_enabled() -> bool {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_path = format!("{}/XIGUASecurity/endpoint_protection_enabled.txt", local_app_data);
    std::fs::read_to_string(&config_path)
        .map(|s| s.trim() == "true")
        .unwrap_or(false) // 默认关闭
}

#[tauri::command]
#[cfg(not(feature = "ms_store"))]
fn set_endpoint_protection_enabled(enabled: bool) {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_dir = format!("{}/XIGUASecurity", local_app_data);
    let _ = std::fs::create_dir_all(&config_dir);
    let config_path = format!("{}/endpoint_protection_enabled.txt", config_dir);
    let _ = std::fs::write(&config_path, if enabled { "true" } else { "false" });
}

// 首次启动/首次出现该选项时是否已询问过用户（防止每次启动都弹窗）
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
fn get_endpoint_protection_prompted() -> bool {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_path = format!("{}/XIGUASecurity/endpoint_protection_prompted.txt", local_app_data);
    std::fs::read_to_string(&config_path)
        .map(|s| s.trim() == "true")
        .unwrap_or(false)
}

#[tauri::command]
#[cfg(not(feature = "ms_store"))]
fn set_endpoint_protection_prompted(prompted: bool) {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_dir = format!("{}/XIGUASecurity", local_app_data);
    let _ = std::fs::create_dir_all(&config_dir);
    let config_path = format!("{}/endpoint_protection_prompted.txt", config_dir);
    let _ = std::fs::write(&config_path, if prompted { "true" } else { "false" });
}

// 查找 MelixEDR 部署目录（包含 install-driver.ps1、Melix.UI.exe、Service/Melix.Service.exe）
#[cfg(not(feature = "ms_store"))]
fn find_melix_edr_dir() -> Option<std::path::PathBuf> {
    let exe_path = std::env::current_exe().ok()?;
    let exe_dir = exe_path.parent()?;

    // 从可执行文件目录向上遍历 5 层，查找 Driver/MelixEDR 目录
    let mut current_dir = Some(exe_dir.to_path_buf());
    for _ in 0..6 {
        if let Some(dir) = current_dir {
            // 1. 主程序同级 Driver/MelixEDR
            let test = dir.join("Driver").join("MelixEDR");
            if test.join("install-driver.ps1").exists() && test.join("Melix.UI.exe").exists() {
                return Some(test);
            }
            // 2. 直接是当前目录下 MelixEDR
            let direct = dir.join("MelixEDR");
            if direct.join("install-driver.ps1").exists() && direct.join("Melix.UI.exe").exists() {
                return Some(direct);
            }
            current_dir = dir.parent().map(|p| p.to_path_buf());
        } else {
            break;
        }
    }
    None
}

// 检查 Melix.Service.exe 进程是否运行（端点防护后端服务）
#[cfg(windows)]
fn is_melix_service_running() -> bool {
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS, PROCESSENTRY32W};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};

    unsafe {
        let snapshot: HANDLE = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let exe_file: Vec<u16> = entry.szExeFile.iter()
                    .take_while(|&&c| c != 0)
                    .copied()
                    .collect();

                if let Ok(name) = String::from_utf16(&exe_file) {
                    if name.eq_ignore_ascii_case("Melix.Service.exe") {
                        let _: windows::core::Result<()> = CloseHandle(snapshot);
                        return true;
                    }
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _: windows::core::Result<()> = CloseHandle(snapshot);
        false
    }
}

#[cfg(not(windows))]
fn is_melix_service_running() -> bool {
    false
}

// 获取端点防护当前状态（以后台服务进程是否运行为准）
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn get_endpoint_protection_status() -> Result<bool, ()> {
    let result = tokio::task::spawn_blocking(|| {
        is_melix_service_running()
    }).await.unwrap_or(false);
    Ok(result)
}

// 运行 install-driver.ps1：绕过执行策略并用 RUNAS 提权（主程序可能无管理员权限）
#[cfg(not(feature = "ms_store"))]
fn run_endpoint_install_script(script_path: &str, working_dir: &str) -> Result<(), String> {
    // 脚本自带提权逻辑（if (-not (Test-Admin)) { Start-Process -Verb RunAs }），
    // 若当前未提权则由脚本自身触发 UAC；此处仍需 -ExecutionPolicy Bypass 绕过执行策略。
    // 直接以 powershell 启动脚本（不额外 runas），脚本内部会自动请求管理员权限。
    let args = format!(
        "-NoProfile -ExecutionPolicy Bypass -File \"{}\"",
        script_path
    );

    // 若当前进程已提权则直接启动；否则由脚本内部触发 UAC 提权
    if is_elevated() {
        use std::os::windows::process::CommandExt;
        log_to_file(&format!("[EndpointProtection] Running install-driver.ps1 (elevated): {}", args));
        let child = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script_path])
            .current_dir(working_dir)
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .spawn()
            .map_err(|e| format!("Failed to start install-driver.ps1: {}", e))?;
        let _ = child;
        Ok(())
    } else {
        // 未提权：交给脚本内部触发 UAC（脚本首部 if(-not (Test-Admin)) 会用 -Verb RunAs 重启自身）
        let args_wide: Vec<u16> = args.encode_utf16().chain(std::iter::once(0)).collect();
        let ps: Vec<u16> = "powershell.exe".encode_utf16().chain(std::iter::once(0)).collect();
        let runas: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();
        let dir_wide: Vec<u16> = working_dir.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            let result = ShellExecuteW(
                None,
                PCWSTR(runas.as_ptr()),
                PCWSTR(ps.as_ptr()),
                PCWSTR(args_wide.as_ptr()),
                PCWSTR(dir_wide.as_ptr()),
                SHOW_WINDOW_CMD(1), // SW_SHOWNORMAL，让 UAC 提示可见
            );
            if result.0 as usize <= 32 {
                return Err(format!("ShellExecuteW failed for install-driver.ps1, code: {}", result.0 as usize));
            }
        }
        Ok(())
    }
}

// 启动端点防护（后台线程执行，避免阻塞 Tauri IPC）
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
fn start_endpoint_protection(app_handle: tauri::AppHandle) -> Result<(), String> {
    let melix_dir = find_melix_edr_dir()
        .ok_or_else(|| "未找到 MelixEDR 目录（Driver/MelixEDR），请检查安装完整性".to_string())?;
    let melix_dir_str = melix_dir.to_str().ok_or("Invalid MelixEDR path encoding")?.to_string();
    let install_script = melix_dir.join("install-driver.ps1");
    let service_exe = melix_dir.join("Service").join("Melix.Service.exe");
    let ui_exe = melix_dir.join("Melix.UI.exe");

    log_to_file(&format!("[EndpointProtection] start_endpoint_protection, dir: {}", melix_dir_str));

    if !install_script.exists() {
        return Err("未找到 install-driver.ps1 脚本".to_string());
    }
    if !service_exe.exists() {
        return Err("未找到 Service/Melix.Service.exe".to_string());
    }
    if !ui_exe.exists() {
        return Err("未找到 Melix.UI.exe".to_string());
    }

    let script_str = install_script.to_str().ok_or("Invalid script path")?.to_string();
    let service_str = service_exe.to_str().ok_or("Invalid service path")?.to_string();
    let ui_str = ui_exe.to_str().ok_or("Invalid UI path")?.to_string();
    let service_dir = service_exe.parent().and_then(|p| p.to_str()).unwrap_or(".").to_string();

    std::thread::spawn(move || {
        log_to_file("[EndpointProtection] Step 1/3: running install-driver.ps1...");
        match run_endpoint_install_script(&script_str, &melix_dir_str) {
            Ok(()) => {
                log_to_file("[EndpointProtection] install-driver.ps1 launched");
                // 等待驱动安装完成（脚本内部包含 UAC 等待），给足时间
                std::thread::sleep(std::time::Duration::from_secs(8));
            }
            Err(e) => {
                log_to_file(&format!("[EndpointProtection] install-driver.ps1 failed: {}", e));
            }
        }

        log_to_file("[EndpointProtection] Step 2/3: starting Melix.Service.exe...");
        // 以 --console 方式运行，使服务程序以独立进程运行（连接驱动并处理后端事件），
        // 用 RUNAS 提权（驱动通信需管理员权限）。
        match launch_process_with_elevation(&service_str, Some("--console"), Some(&service_dir), 0) {
            Ok(()) => {
                log_to_file("[EndpointProtection] Melix.Service.exe launched");
                // 等待服务连接驱动
                std::thread::sleep(std::time::Duration::from_secs(4));
            }
            Err(e) => {
                log_to_file(&format!("[EndpointProtection] Melix.Service.exe failed to start: {}", e));
            }
        }

        // Step 3/3: 启动 Melix.UI 后台进程（无窗口）。
        // Melix.UI 负责连接 Melix.Service 并弹拦截/规则等原生窗口；主程序通过
        // `\\.\pipe\Melix.UIControl` 管道控制它（弹规则窗口/设置窗口等）。
        // 若 UI 已在运行则跳过。
        log_to_file("[EndpointProtection] Step 3/3: ensuring Melix.UI background process is running...");
        if melix_ui_client::send_command("ping", 1500).is_err() {
            match launch_process_with_elevation(&ui_str, None, Some(&melix_dir_str), 1) {
                Ok(()) => log_to_file("[EndpointProtection] Melix.UI background process launched"),
                Err(e) => log_to_file(&format!("[EndpointProtection] failed to launch Melix.UI: {e}")),
            }
            std::thread::sleep(std::time::Duration::from_secs(3));
        }

        let _ = security_log::add_security_log(
            security_log::LogCategory::Driver,
            "端点防护",
            "增强端点防护已启动",
            None, None,
            security_log::LogAction::Started,
            security_log::LogResult::Success, None,
        );
        let event = TimelineEvent {
            id: format!("endpoint_protection_start_{}", chrono::Local::now().timestamp()),
            timestamp: chrono::Local::now().to_rfc3339(),
            event_type: "system".to_string(),
            title: "增强端点防护已启动".to_string(),
            description: "MelixEDR 专业端点防护已启动，提供更强的端点防护效果".to_string(),
            process_name: None,
            result: Some("正常".to_string()),
        };
        add_timeline_event(event);

        let _ = app_handle.emit("endpoint-protection-notification", "started");

        // 启动 Melix.UI 拦截事件监听线程：持续读取 Melix.UI 后台进程推送的拦截/询问事件，
        // 写入通知中心与事件日志，并 emit 给前端。
        let app_for_events = app_handle.clone();
        std::thread::spawn(move || {
            log_to_file("[MelixEvents] listening to Melix.UI intercept events");
            loop {
                let pipe = match melix_ui_client::connect_pipe(10000) {
                    Ok(p) => p,
                    Err(e) => {
                        log_to_file(&format!("[MelixEvents] connect Melix.UI failed: {e}"));
                        std::thread::sleep(std::time::Duration::from_secs(3));
                        continue;
                    }
                };
                let _guard = melix_ui_client::PipeGuard(pipe);
                log_to_file("[MelixEvents] connected to Melix.UI");
                loop {
                    match melix_ui_client::read_line(pipe, 60000) {
                        Ok(line) => {
                            handle_melix_ui_event(&app_for_events, &line);
                        }
                        Err(e) => {
                            log_to_file(&format!("[MelixEvents] read error: {e}, reconnecting"));
                            break;
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
        });
    });

    Ok(())
}

// 停止端点防护（后台线程执行）
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
fn stop_endpoint_protection(app_handle: tauri::AppHandle) -> Result<(), String> {
    log_to_file("[EndpointProtection] stop_endpoint_protection");
    std::thread::spawn(move || {
        // 停止后端服务与 UI（Melix.Service.exe、Melix.UI.exe）
        log_to_file("[EndpointProtection] stopping Melix.Service.exe / Melix.UI.exe");
        let _ = kill_process_by_name_uac("Melix.Service");
        std::thread::sleep(std::time::Duration::from_millis(500));
        let _ = kill_process_by_name_uac("Melix.UI");

        let _ = security_log::add_security_log(
            security_log::LogCategory::Driver,
            "端点防护",
            "增强端点防护已停止",
            None, None,
            security_log::LogAction::Stopped,
            security_log::LogResult::Success, None,
        );
        let event = TimelineEvent {
            id: format!("endpoint_protection_stop_{}", chrono::Local::now().timestamp()),
            timestamp: chrono::Local::now().to_rfc3339(),
            event_type: "system".to_string(),
            title: "增强端点防护已停止".to_string(),
            description: "MelixEDR 专业端点防护已停止".to_string(),
            process_name: None,
            result: Some("正常".to_string()),
        };
        add_timeline_event(event);

        let _ = app_handle.emit("endpoint-protection-notification", "stopped");
    });
    Ok(())
}

/// 处理 Melix.UI 后台进程推送的拦截/询问事件。
/// UI 推送格式：`{"event":"intercept","type":"prompt"/"block","payload":{SecurityEvent}}`
/// 这里写入安全日志(事件日志)并 emit 通知给前端(通知中心)。
fn handle_melix_ui_event(app: &tauri::AppHandle, line: &str) {
    let v: serde_json::Value = match serde_json::from_str(line) {
        Ok(x) => x,
        Err(_) => return,
    };
    if v.get("event").and_then(|x| x.as_str()) != Some("intercept") {
        return;
    }
    let kind = v.get("type").and_then(|x| x.as_str()).unwrap_or("block");
    let payload = v.get("payload").cloned().unwrap_or(serde_json::Value::Null);

    let actor = payload
        .get("actorPath")
        .or_else(|| payload.get("processName"))
        .and_then(|x| x.as_str())
        .unwrap_or("未知进程");
    let target = payload
        .get("target")
        .or_else(|| payload.get("targetPath"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let ev_type = payload.get("type").and_then(|x| x.as_str()).unwrap_or("");
    let risk = payload
        .get("risk")
        .and_then(|x| if x.is_string() { x.as_str() } else { x.get("description").and_then(|d| d.as_str()) })
        .unwrap_or("检测到可疑行为");

    let summary = if kind == "prompt" {
        format!("端点防护询问：{actor} 触发 {ev_type}")
    } else {
        format!("端点防护已拦截：{actor} {risk}")
    };

    // 写入安全日志(事件日志)
    let _ = security_log::add_security_log(
        security_log::LogCategory::Realtime,
        "端点防护",
        &summary,
        Some(actor.to_string()),
        Some(format!("{ev_type} · {risk}")),
        if kind == "prompt" { security_log::LogAction::Detected } else { security_log::LogAction::Blocked },
        security_log::LogResult::Success,
        Some(security_log::LogDetails {
            scanned_files: None,
            threats_found: Some(1),
            threats_cleaned: None,
            file_size: None,
            virus_family: Some(ev_type.to_string()),
            additional_info: Some(format!("目标:{}", if target.is_empty() { "—".to_string() } else { target.to_string() })),
        }),
    );

    // emit 通知给前端(通知中心)
    let _ = app.emit("melix-intercepted", serde_json::json!({
        "kind": kind,
        "actor": actor,
        "target": target,
        "type": ev_type,
        "risk": risk,
        "summary": summary,
    }));
}

// ==================== Melix HIPS 防护规则桥接层（跳过 Melix.UI） ====================
// 主程序通过 melix_ipc 命名管道客户端直接与 Melix.Service 通信，
// 实现防护规则面板、内置规则、拦截决策等功能的完整集成。

/// 检查 Melix.Service 是否运行（经 AVGuard 中转探测）。
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn melix_service_running() -> bool {
    tokio::task::spawn_blocking(avmodel_client::melix_service_running).await.map_err(|e| e.to_string()).unwrap_or(Ok(false)).unwrap_or(false)
}

/// 请求防护规则列表（经 AVGuard 只发送请求，规则通过 melix-rules 事件异步返回）。
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn melix_get_rules() -> Result<Vec<serde_json::Value>, String> {
    // 只发送请求；规则数据随后经事件管道以 melix-rules 事件推送到前端
    tokio::task::spawn_blocking(avmodel_client::melix_get_rules).await.map_err(|e| e.to_string())?
}

/// 新增一条防护规则。
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn melix_add_rule(
    actor_path: Option<String>,
    r#type: Option<String>,
    target_pattern: Option<String>,
    action: String,
    note: Option<String>,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || avmodel_client::melix_add_rule(actor_path, r#type, target_pattern, action, note))
        .await.map_err(|e| e.to_string())?
}

/// 删除指定防护规则。
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn melix_delete_rule(rule_id: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || avmodel_client::melix_delete_rule(rule_id)).await.map_err(|e| e.to_string())?
}

/// 获取当前运行时设置（总开关等）。
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn melix_get_settings() -> Result<serde_json::Value, String> {
    tokio::task::spawn_blocking(avmodel_client::melix_get_settings).await.map_err(|e| e.to_string())?
}

/// 更新运行时设置。
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn melix_update_settings(settings: serde_json::Value) -> Result<(), String> {
    tokio::task::spawn_blocking(move || avmodel_client::melix_update_settings(settings)).await.map_err(|e| e.to_string())?
}

/// 获取文件信任列表。
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn melix_get_trust_list() -> Result<Vec<serde_json::Value>, String> {
    tokio::task::spawn_blocking(avmodel_client::melix_get_trust_list).await.map_err(|e| e.to_string())?
}

/// 新增一条文件信任。
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn melix_add_trust(actor_path: String, note: Option<String>) -> Result<(), String> {
    tokio::task::spawn_blocking(move || avmodel_client::melix_add_trust(actor_path, note)).await.map_err(|e| e.to_string())?
}

/// 移除一条文件信任。
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn melix_remove_trust(rule_id: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || avmodel_client::melix_remove_trust(rule_id)).await.map_err(|e| e.to_string())?
}

/// 用户对某拦截事件做出裁决（允许/阻止/询问）。
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn melix_prompt_response(event_id: String, action: String, remember: bool) -> Result<(), String> {
    tokio::task::spawn_blocking(move || avmodel_client::melix_prompt_response(event_id, action, remember)).await.map_err(|e| e.to_string())?
}

// ==================== Melix.UI 后台进程控制 ====================
// 主程序通过命名管道 `Melix.UIControl` 命令 Melix.UI 后台进程弹出原生规则/设置/信任窗口，
// 复用其稳定连接 Melix.Service 的能力（规则查询/编辑、拦截窗口都由 UI 进程完成）。

#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn melix_ui_open_rules() -> Result<(), String> {
    melix_ui_client::send_command("show_rules", 2000).map(|_| ())
}

#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn melix_ui_open_settings() -> Result<(), String> {
    melix_ui_client::send_command("show_settings", 2000).map(|_| ())
}

#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn melix_ui_open_trust() -> Result<(), String> {
    melix_ui_client::send_command("show_trust", 2000).map(|_| ())
}

#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn melix_ui_open_chain() -> Result<(), String> {
    melix_ui_client::send_command("show_chain", 2000).map(|_| ())
}

#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn melix_ui_open_composite() -> Result<(), String> {
    melix_ui_client::send_command("show_composite", 2000).map(|_| ())
}

#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn melix_ui_open_log() -> Result<(), String> {
    melix_ui_client::send_command("show_log", 2000).map(|_| ())
}

#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn melix_ui_ping() -> Result<bool, String> {
    Ok(melix_ui_client::send_command("ping", 2000).map(|r| r.ok).unwrap_or(false))
}

/// 查询 Melix.UI 的引擎/内核/服务连接状态（跟随 WPF 端显示的真实状态）。
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
async fn melix_ui_get_status() -> Result<melix_ui_client::UiEngineStatus, String> {
    melix_ui_client::get_status(2500)
}

// ==================== Windows 版本检测与兼容性警告 ====================

/// 检测当前系统是否为 Windows 11（通过注册表获取真实 Build 号）
/// 使用注册表而非 GetVersionExW，因为后者受应用程序清单影响可能返回错误版本
#[tauri::command]
fn is_windows_11() -> bool {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;

        let key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(key_path) {
            // 读取 CurrentBuildNumber (REG_SZ)，Windows 11 的 Build >= 22000
            if let Ok(build_str) = key.get_value::<String, _>("CurrentBuildNumber") {
                if let Ok(build) = build_str.parse::<u32>() {
                    return build >= 22000;
                }
            }
            // 兜底：读取 ProductName 是否包含 "Windows 11"
            if let Ok(name) = key.get_value::<String, _>("ProductName") {
                return name.contains("Windows 11");
            }
        }
    }
    false
}

/// 获取驱动防护是否应自动启动
#[tauri::command]
#[cfg(not(feature = "ms_store"))]
fn get_driver_auto_start_decision() -> bool {
    true
}

// 白名单检查命令
#[tauri::command]
fn is_hash_whitelisted(hash: String) -> bool {
    whitelist::is_hash_whitelisted(&hash)
}

// 检测是否安装了Xdows-Security（通过检查桌面快捷方式）
#[tauri::command]
fn check_xdows_security_installed() -> bool {
    use std::path::PathBuf;
    
    // 获取桌面路径
    let desktop_path = if let Ok(userprofile) = std::env::var("USERPROFILE") {
        PathBuf::from(userprofile).join("Desktop")
    } else {
        return false;
    };
    
    // 检查公共桌面路径
    let public_desktop = PathBuf::from("C:\\Users\\Public\\Desktop");
    
    // 可能的快捷方式名称
    let shortcut_names = ["Xdows-Security.lnk", "Xdows Security.lnk", "XdowsSecurity.lnk"];
    
    // 检查用户桌面
    for name in &shortcut_names {
        if desktop_path.join(name).exists() {
            println!("[XdowsCheck] Found Xdows-Security shortcut at: {:?}", desktop_path.join(name));
            return true;
        }
    }
    
    // 检查公共桌面
    for name in &shortcut_names {
        if public_desktop.join(name).exists() {
            println!("[XdowsCheck] Found Xdows-Security shortcut at: {:?}", public_desktop.join(name));
            return true;
        }
    }
    
    println!("[XdowsCheck] Xdows-Security shortcut not found");
    false
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Margins {
    cx_left_width: i32,
    cx_right_width: i32,
    cy_top_height: i32,
    cy_bottom_height: i32,
}

// 托盘菜单命令：显示主窗口
#[tauri::command]
async fn show_main_window(app: tauri::AppHandle, page: Option<String>) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
        
        // 如果指定了页面，发送事件让前端切换
        if let Some(page_name) = page {
            let _ = window.emit("navigate-to", page_name);
        }
    }
    
    // 关闭托盘菜单窗口
    if let Some(tray_window) = app.get_webview_window("tray-menu") {
        let _ = tray_window.close();
    }
    Ok(())
}

// 启动时显示主窗口（由前端 splash 渲染完成后调用）
#[tauri::command]
async fn show_startup_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        println!("[Setup] Main window shown by frontend request");
    }
    Ok(())
}

// 前端 splash 隐藏（前端渲染完成后调用；窗口显示由 show_startup_window 控制）
// 历史遗留：前端曾在旧架构调用此命令，后端未注册，导致前端 catch 到错误。
// 保留空实现以兼容前端调用，无实际作用。
#[tauri::command]
fn hide_splash() {}

// 托盘菜单命令：关闭托盘菜单窗口
#[tauri::command]
fn close_tray_menu(app: tauri::AppHandle) {
    println!("[Tray] Close tray menu requested");
    if let Some(window) = app.get_webview_window("tray-menu") {
        let _ = window.close();
    }
    TRAY_MENU_OPEN.store(false, std::sync::atomic::Ordering::SeqCst);
}

// 托盘菜单命令：退出应用
#[tauri::command]
async fn exit_app(app: tauri::AppHandle) {
    println!("[Tray] Exit requested from tray menu");
    // 先经过安全桌面确认，确认后才真正退出
    let confirmed = show_secure_confirm_window(&app, "退出 XIGUASecurity", "您确定要退出西瓜杀毒吗？退出后所有防护将停止，您的计算机将失去保护。", "exit_app").await;
    if confirmed {
        println!("[Tray] Exit confirmed, triggering Tauri exit flow");
        // 触发 Tauri 正常退出流程，统一在 RunEvent::ExitRequested 中清理资源
        app.exit(0);
    } else {
        println!("[Tray] Exit cancelled by user");
    }
}

// ==================== 安全桌面确认机制 ====================

/// 显示安全桌面确认窗口并等待用户决策。
/// 返回 true 表示用户长按确认，false 表示取消/超时。
/// 用于关闭防护、退出程序等高危操作，防止病毒恶意程序静默关闭杀软。
async fn show_secure_confirm_window(
    app: &tauri::AppHandle,
    title: &str,
    description: &str,
    action: &str,
) -> bool {
    // 生成唯一 session id
    let session_id = format!("secure_confirm_{}", chrono::Local::now().timestamp_millis());
    let (tx, rx) = tokio::sync::oneshot::channel::<bool>();

    // 注册等待者
    {
        let mut waiters = secure_confirm_waiters().lock().unwrap();
        waiters.insert(session_id.clone(), tx);
    }

    // 获取安全确认窗口（tauri.conf.json 已配置，visible: false）
    // 如果不存在则动态创建兜底
    let window = match app.get_webview_window("secure-confirm") {
        Some(w) => w,
        None => {
            println!("[SecureConfirm] Window not found, dynamically creating...");
            let url = "secure-confirm.html";
            match tauri::WebviewWindowBuilder::new(
                app,
                "secure-confirm",
                tauri::WebviewUrl::App(url.into())
            )
            .title("XIGUASecurity 安全确认")
            .decorations(false)
            .transparent(false)
            .shadow(false)
            .always_on_top(true)
            .skip_taskbar(true)
            .resizable(false)
            .visible(true)
            .fullscreen(true)
            .build()
            {
                Ok(w) => w,
                Err(e) => {
                    println!("[SecureConfirm] Failed to create window: {}", e);
                    let _ = secure_confirm_waiters().lock().unwrap().remove(&session_id);
                    return false;
                }
            }
        }
    };

    // 注入内容：优先 emit 事件（线程安全），并附带 eval 兜底
    // 附带真实桌面壁纸（base64），前端用作背景
    let wallpaper = get_desktop_wallpaper_base64();
    let payload = serde_json::json!({
        "sessionId": session_id,
        "title": title,
        "description": description,
        "action": action,
        "wallpaper": wallpaper,
    });
    let _ = window.emit("secure-confirm-data", payload);

    // eval 兜底（窗口已存在但事件未监听成功时使用）
    let escape_js = |s: &str| -> String {
        s.replace('\\', "\\\\")
         .replace('\'', "\\'")
         .replace('\n', "\\n")
         .replace('\r', "\\r")
         .replace('\t', "\\t")
    };
    let esc_session = escape_js(&session_id);
    let esc_title = escape_js(title);
    let esc_desc = escape_js(description);
    let esc_action = escape_js(action);
    let esc_wallpaper = escape_js(wallpaper.as_deref().unwrap_or(""));

    let js = format!(
        r#"(function(){{
            var data = {{ sessionId:'{}', title:'{}', description:'{}', action:'{}', wallpaper:'{}' }};
            if (typeof window.applySecureConfirmData === 'function') {{
                window.applySecureConfirmData(data);
            }} else {{
                var tries = 0;
                function waitReady(){{
                    if (typeof window.applySecureConfirmData === 'function') {{
                        window.applySecureConfirmData(data);
                    }} else if (tries < 80) {{
                        tries++;
                        setTimeout(waitReady, 100);
                    }}
                }}
                waitReady();
            }}
        }})();"#,
        esc_session, esc_title, esc_desc, esc_action, esc_wallpaper
    );
    let _ = window.eval(&js);

    // 阻止安全确认窗口被 Alt+F4 / 系统关闭（只能通过窗口内按钮响应）
    // 使用函数级静态标记，只挂载一次
    {
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
        static CLOSE_GUARD_ATTACHED: AtomicBool = AtomicBool::new(false);
        if !CLOSE_GUARD_ATTACHED.swap(true, AtomicOrdering::SeqCst) {
            let _ = window.on_window_event(move |event| {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    println!("[SecureConfirm] Close requested blocked, keeping window for decision");
                }
            });
        }
    }

    // 强制全屏铺满整个显示器（含任务栏）+ 置顶 + 抢前台
    // 注意：绝不能调用 force_window_visible —— 它会把窗口重新定位到右下角 360x500
    // （那是拦截窗口专用的），导致安全桌面显示在小角落。
    // 顺序：先 Win32 全屏铺满再显示，避免先闪现默认尺寸小窗。
    force_secure_desktop_fullscreen(&window);
    let _ = window.show();
    println!("[SecureConfirm] Window shown (fullscreen + wallpaper) for action: {}", action);

    // 等待用户决策（最多 120 秒，超时按取消处理）
    let result = match tokio::time::timeout(std::time::Duration::from_secs(120), rx).await {
        Ok(Ok(approved)) => {
            println!("[SecureConfirm] User decision: {}", if approved { "confirmed" } else { "cancelled" });
            approved
        }
        Ok(Err(_)) => {
            println!("[SecureConfirm] Channel closed, treating as cancelled");
            false
        }
        Err(_) => {
            println!("[SecureConfirm] Timeout after 120s, treating as cancelled");
            false
        }
    };

    // 清理等待者并隐藏窗口
    let _ = secure_confirm_waiters().lock().unwrap().remove(&session_id);
    let _ = window.hide();
    result
}

/// 安全确认窗口前端回调：用户点击按钮后上报决策
#[tauri::command]
fn secure_confirm_respond(session_id: String, approved: bool) -> Result<(), String> {
    println!("[SecureConfirm] Respond called: session={} approved={}", session_id, approved);
    let waiter = {
        let mut waiters = secure_confirm_waiters().lock().unwrap();
        waiters.remove(&session_id)
    };
    if let Some(tx) = waiter {
        let _ = tx.send(approved);
    } else {
        println!("[SecureConfirm] No waiter found for session: {}", session_id);
    }
    Ok(())
}

/// 显示安全桌面确认窗口（供前端直接调用，返回用户决策）
#[tauri::command]
async fn show_secure_confirm_command(
    app: tauri::AppHandle,
    title: String,
    description: String,
    action: String,
) -> Result<bool, String> {
    Ok(show_secure_confirm_window(&app, &title, &description, &action).await)
}

// 应用退出前统一清理资源
fn cleanup_before_exit(app: &tauri::AppHandle) {
    use std::sync::Once;
    static EXIT_CLEANUP: Once = Once::new();
    EXIT_CLEANUP.call_once(|| {
        diag_info!("[Cleanup] Application exiting, stopping protection services...");
        println!("[Cleanup] Application exiting, stopping protection services...");

        // 1. 关闭拦截窗口
        if let Some(win) = app.get_webview_window("intercept-alert") {
            let _ = win.close();
        }
        // 1b. 关闭安全确认窗口
        if let Some(win) = app.get_webview_window("secure-confirm") {
            let _ = win.close();
        }

        // 2. 停止 EDR 监控
        stop_edr_monitoring();

        // 2b. 停止网络防护（还原系统代理；独立线程执行，不阻塞退出；子进程也有看门狗兜底）
        #[cfg(not(feature = "ms_store"))]
        network_protection::stop_on_exit();

        // 3. 停止 WMI 进程监控
        let _ = stop_process_watcher();

        // 4. 停止文件防护
        if let Err(e) = file_protection::get_file_protection().lock().unwrap().stop(app.clone()) {
            eprintln!("[Cleanup] Failed to stop file protection: {}", e);
            diag_warn!("[Cleanup] Failed to stop file protection: {}", e);
        }

        // 5. 停止弹窗拦截
        if let Err(e) = popup_interceptor::get_popup_interceptor().lock().unwrap().stop() {
            eprintln!("[Cleanup] Failed to stop popup interceptor: {}", e);
            diag_warn!("[Cleanup] Failed to stop popup interceptor: {}", e);
        }

        // 6. 停止勒索软件防护
        if let Err(e) = ransomware_protection::get_ransomware_protection().lock().unwrap().stop(app.clone()) {
            eprintln!("[Cleanup] Failed to stop ransomware protection: {}", e);
            diag_warn!("[Cleanup] Failed to stop ransomware protection: {}", e);
        }

        // 7. 停止驱动防护：同步发送 shutdown 请求并等待 Agent 退出（最多 5 秒），
        //    确保 Agent 进程真正退出后主程序才退出，避免防护残留
        #[cfg(not(feature = "ms_store"))]
        stop_driver_protection_sync();

        diag_info!("[Cleanup] Protection services stop requested");
        println!("[Cleanup] Protection services stop requested");
    });
}

// 托盘菜单命令：检查更新
#[tauri::command]
async fn check_update_from_tray(app: tauri::AppHandle) -> Result<(), String> {
    // 显示主窗口并触发更新检查
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
        let _ = window.emit("check-update", ());
    }
    
    // 关闭托盘菜单窗口
    if let Some(tray_window) = app.get_webview_window("tray-menu") {
        let _ = tray_window.close();
    }
    
    Ok(())
}

// Windows 计划任务启动项配置
const STARTUP_TASK_NAME: &str = "XIGUASecurity";

// 托盘/设置命令：通过计划任务添加开机自启动（带 --silent 参数，以最高权限运行）
#[tauri::command]
async fn add_to_startup_folder() -> Result<bool, String> {
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get current exe path: {}", e))?;
    let exe_path_str = exe_path.to_str()
        .ok_or("Invalid exe path")?;
    let task_run = format!("\"{}\" --silent", exe_path_str);

    let output = std::process::Command::new("schtasks.exe")
        .args(&[
            "/Create",
            "/TN", STARTUP_TASK_NAME,
            "/TR", &task_run,
            "/SC", "ONLOGON",
            "/RL", "HIGHEST",
            "/F",
        ])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .map_err(|e| format!("Failed to run schtasks: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("schtasks failed: {}", stderr));
    }

    println!("[Startup] Added scheduled task: {}", task_run);
    Ok(true)
}

// 托盘/设置命令：删除计划任务启动项
#[tauri::command]
async fn remove_from_startup_folder() -> Result<bool, String> {
    let output = std::process::Command::new("schtasks.exe")
        .args(&[
            "/Delete",
            "/TN", STARTUP_TASK_NAME,
            "/F",
        ])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .map_err(|e| format!("Failed to run schtasks: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // 如果任务不存在也视为成功
        if stderr.contains("does not exist") || stderr.contains("不存在") {
            return Ok(true);
        }
        return Err(format!("schtasks failed: {}", stderr));
    }

    println!("[Startup] Removed scheduled task");
    Ok(true)
}

// 托盘/设置命令：检查计划任务是否存在
#[tauri::command]
async fn is_in_startup_folder() -> Result<bool, String> {
    let output = std::process::Command::new("schtasks.exe")
        .args(&[
            "/Query",
            "/TN", STARTUP_TASK_NAME,
            "/FO", "LIST",
        ])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output();

    match output {
        Ok(o) => Ok(o.status.success()),
        Err(_) => Ok(false),
    }
}

// 托盘菜单命令：切换流量悬浮窗
// 功能已规划但未实现，此处仅持久化开关状态供前端读取
#[tauri::command]
fn toggle_float_window(enabled: bool) -> Result<(), String> {
    let config_path = get_float_window_config_path();
    let _ = std::fs::create_dir_all(config_path.parent().unwrap_or(std::path::Path::new(".")));
    std::fs::write(&config_path, if enabled { "true" } else { "false" })
        .map_err(|e| format!("写入悬浮窗配置失败: {}", e))?;
    println!("[Tray] Float window enabled: {}", enabled);
    Ok(())
}

// 托盘菜单命令：获取流量悬浮窗状态
#[tauri::command]
fn get_float_window_enabled() -> bool {
    std::fs::read_to_string(get_float_window_config_path())
        .map(|s| s.trim() == "true")
        .unwrap_or(false)
}

fn get_float_window_config_path() -> std::path::PathBuf {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(base).join("XIGUASecurity").join("float_window_enabled.txt")
}

// 托盘菜单命令：切换游戏模式
// 功能已规划但未实现，此处仅持久化开关状态供前端读取
#[tauri::command]
fn toggle_game_mode(enabled: bool) -> Result<(), String> {
    let config_path = get_game_mode_config_path();
    let _ = std::fs::create_dir_all(config_path.parent().unwrap_or(std::path::Path::new(".")));
    std::fs::write(&config_path, if enabled { "true" } else { "false" })
        .map_err(|e| format!("写入游戏模式配置失败: {}", e))?;
    println!("[Tray] Game mode enabled: {}", enabled);
    Ok(())
}

// 托盘菜单命令：获取游戏模式状态
#[tauri::command]
fn get_game_mode_enabled() -> bool {
    std::fs::read_to_string(get_game_mode_config_path())
        .map(|s| s.trim() == "true")
        .unwrap_or(false)
}

fn get_game_mode_config_path() -> std::path::PathBuf {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(base).join("XIGUASecurity").join("game_mode_enabled.txt")
}

/// 打开云平台（系统浏览器跳转）
#[tauri::command]
fn open_chat_window(_app: tauri::AppHandle) -> Result<(), String> {
    let url = "https://scan.xiguastudio.top";
    println!("[CloudPlatform] Opening in browser: {}", url);
    
    // 使用系统默认浏览器打开
    std::process::Command::new("cmd")
        .args(["/c", "start", "", url])
        .spawn()
        .map_err(|e| format!("Failed to open browser: {}", e))?;
    
    Ok(())
}

/// 打开赞助页面（系统浏览器跳转到开放平台）
#[tauri::command]
fn open_sponsor_url() -> Result<(), String> {
    let url = "https://cloudapi.xiguastudio.top/";
    diag_info!("[Sponsor] Opening sponsor page in browser: {}", url);
    // 使用系统默认浏览器打开
    std::process::Command::new("cmd")
        .args(["/c", "start", "", url])
        .spawn()
        .map_err(|e| {
            diag_error!("[Sponsor] Failed to open browser: {}", e);
            format!("Failed to open browser: {}", e)
        })?;
    Ok(())
}

/// 打开问题反馈问卷（系统浏览器跳转）
#[tauri::command]
fn open_survey_url() -> Result<(), String> {
    let url = "https://wj.qq.com/s2/27484810/0tt3/";
    diag_info!("[Feedback] Opening survey in browser: {}", url);
    // 使用系统默认浏览器打开
    std::process::Command::new("cmd")
        .args(["/c", "start", "", url])
        .spawn()
        .map_err(|e| {
            diag_error!("[Feedback] Failed to open browser: {}", e);
            format!("Failed to open browser: {}", e)
        })?;
    Ok(())
}

// 设置当前显示语言
#[tauri::command]
fn set_language(lang: String) {
    if let Ok(mut current) = CURRENT_LANGUAGE.lock() {
        *current = lang;
    }
}

// 获取当前显示语言，未设置时默认返回 zh-CN
#[tauri::command]
fn get_current_language() -> String {
    CURRENT_LANGUAGE
        .lock()
        .ok()
        .map(|guard| {
            let s = guard.clone();
            if s.is_empty() { "zh-CN".to_string() } else { s }
        })
        .unwrap_or_else(|| "zh-CN".to_string())
}

// 系统修复扫描
#[tauri::command]
async fn system_repair_scan() -> Result<String, String> {
    let result = scan_system_issues();
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

// 修复指定系统问题
#[tauri::command]
async fn system_repair_fix(issue_ids: Vec<String>) -> Result<String, String> {
    let result = fix_system_issues(issue_ids);
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

// 日志上传相关命令
#[tauri::command]
fn get_log_upload_device_name() -> Result<String, String> {
    get_log_uploader().map(|u| u.get_device_name())
}

#[tauri::command]
fn get_log_upload_enabled() -> Result<bool, String> {
    get_log_uploader().map(|u| u.is_enabled())
}

#[tauri::command]
fn set_log_upload_enabled(enabled: bool) -> Result<(), String> {
    get_log_uploader().map(|u| u.set_enabled(enabled))
}

#[tauri::command]
fn upload_recent_logs_command(entries: Vec<serde_json::Value>) -> Result<usize, String> {
    let uploader = get_log_uploader()?;
    Ok(uploader.push_recent_logs(entries))
}

/// 获取诊断日志目录路径（前端用于展示/导出）
#[tauri::command]
fn get_diagnostic_log_dir() -> Result<String, String> {
    Ok(diagnostic_log::log_dir().display().to_string())
}

/// 读取诊断日志内容（limit 限制行数，默认最近 5000 行）
#[tauri::command]
fn get_diagnostic_logs(limit: Option<usize>) -> Result<String, String> {
    Ok(diagnostic_log::read_logs(limit.unwrap_or(5000)))
}

/// 清空全部诊断日志文件，返回删除的文件数
#[tauri::command]
fn clear_diagnostic_logs() -> Result<usize, String> {
    Ok(diagnostic_log::clear_logs())
}

/// 打开诊断日志所在文件夹（资源管理器）
#[tauri::command]
fn open_diagnostic_log_dir() -> Result<(), String> {
    let dir = diagnostic_log::log_dir();
    if !dir.exists() {
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    }
    std::process::Command::new("explorer.exe")
        .arg(dir.as_os_str())
        .spawn()
        .map_err(|e| format!("打开日志目录失败: {}", e))?;
    Ok(())
}

/// 上传扫描检测到的威胁（含 SHA256），便于云端入库和降低误报
/// 优先使用前端传来的 sha256，若为空则尝试本地计算
#[tauri::command]
async fn upload_threats_command(threats: Vec<serde_json::Value>) -> Result<usize, String> {
    let uploader = get_log_uploader()?;
    if !uploader.is_enabled() {
        return Ok(0);
    }

    let mut entries: Vec<serde_json::Value> = Vec::with_capacity(threats.len());
    for threat in &threats {
        let file_path = threat.get("path").and_then(|v| v.as_str()).unwrap_or("");
        let threat_name = threat.get("threat_name").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let probability = threat.get("probability").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let virus_family = threat.get("virus_family").and_then(|v| v.as_str()).unwrap_or("");
        let family_category = threat.get("family_category").and_then(|v| v.as_str()).unwrap_or("");

        // 优先使用前端传过来的 sha256
        let sha256 = threat.get("sha256")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                // 前端未提供时，尝试本地计算
                if !file_path.is_empty() {
                    crate::scanner::calculate_file_hash(file_path).unwrap_or_default()
                } else {
                    String::new()
                }
            });

        let entry = serde_json::json!({
            "timestamp": chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            "category": "threat",
            "function": "扫描检测",
            "summary": format!("[{}] {}", threat_name, file_path),
            "details": {
                "file_path": file_path,
                "threat_name": threat_name,
                "virus_family": virus_family,
                "family_category": family_category,
                "probability": probability,
                "sha256": sha256,
            },
            "action": "Detected",
            "result": "success",
        });
        entries.push(entry);
    }

    if entries.is_empty() {
        return Ok(0);
    }

    Ok(uploader.push_recent_logs(entries))
}

// 历史上传状态文件路径
fn get_historical_upload_state_path() -> std::path::PathBuf {
    let app_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("XIGUASecurity");
    app_dir.join("historical_upload_state.json")
}

// 加载已上传的历史日志键
fn load_historical_upload_state() -> Vec<String> {
    let path = get_historical_upload_state_path();
    if path.exists() {
        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<Vec<String>>(&content) {
                Ok(keys) => keys,
                Err(e) => {
                    println!("[HistoricalUpload] Failed to parse state file: {}", e);
                    Vec::new()
                }
            },
            Err(e) => {
                println!("[HistoricalUpload] Failed to read state file: {}", e);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    }
}

// 保存已上传的历史日志键
fn save_historical_upload_state(keys: &[String]) {
    let path = get_historical_upload_state_path();
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            println!("[HistoricalUpload] Failed to create state dir: {}", e);
            return;
        }
    }
    match serde_json::to_string_pretty(keys) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                println!("[HistoricalUpload] Failed to write state file: {}", e);
            }
        }
        Err(e) => {
            println!("[HistoricalUpload] Failed to serialize state: {}", e);
        }
    }
}

// 读取并解析单个 EDR 报告文件
fn parse_edr_report_file(path: &std::path::Path) -> Option<EdrReportData> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut data = EdrReportData::default();
    parse_edr_report_content(&content, &mut data);
    Some(data)
}

// 上传历史时间线和 EDR 报告日志（带去重）
#[tauri::command]
fn upload_historical_logs_command() -> Result<usize, String> {
    let uploader = get_log_uploader()?;
    let mut uploaded_keys = load_historical_upload_state();
    let mut uploaded_set: std::collections::HashSet<String> = uploaded_keys.iter().cloned().collect();
    let mut new_keys: Vec<String> = Vec::new();
    let mut entries: Vec<serde_json::Value> = Vec::new();

    // 1. 时间线事件
    let timeline_events = load_timeline_events();
    for event in timeline_events {
        let key = if event.id.is_empty() {
            format!("timeline:{}:{}:{}", event.timestamp, event.event_type, event.title)
        } else {
            format!("timeline:{}", event.id)
        };
        if uploaded_set.contains(&key) {
            continue;
        }
        let entry = serde_json::json!({
            "timestamp": event.timestamp,
            "category": "timeline",
            "function": event.event_type,
            "summary": event.title,
            "details": {
                "description": event.description,
                "process_name": event.process_name.unwrap_or_default(),
                "result": event.result.unwrap_or_default(),
            },
            "action": "info",
            "result": "success",
        });
        entries.push(entry);
        uploaded_set.insert(key.clone());
        new_keys.push(key);
    }

    // 2. EDR 报告
    let candidates = collect_edr_report_candidates();
    for (path, _) in candidates {
        let data = match parse_edr_report_file(&path) {
            Some(d) => d,
            None => continue,
        };
        let key = if !data.report_code.is_empty() {
            format!("edr:{}", data.report_code)
        } else {
            format!("edr:{}:{}:{}", data.process_name, data.pid, data.report_time)
        };
        if uploaded_set.contains(&key) {
            continue;
        }
        let timestamp = if data.report_time.is_empty() {
            chrono::Local::now().to_rfc3339()
        } else {
            data.report_time.clone()
        };
        let behavior: Vec<serde_json::Value> = data.timeline.iter().map(|e| {
            serde_json::json!({
                "seq": e.seq,
                "datetime": e.datetime,
                "relative_sec": e.relative_sec,
                "code": e.code,
                "type_cn": e.type_cn,
                "type_en": e.type_en,
                "detail": e.detail,
            })
        }).collect();
        let entry = serde_json::json!({
            "timestamp": timestamp,
            "category": "edr",
            "function": "EDR拦截",
            "summary": format!("EDR 拦截: {} (PID: {})", data.process_name, data.pid),
            "details": {
                "report_code": data.report_code,
                "process_name": data.process_name,
                "process_path": data.process_path,
                "pid": data.pid,
                "parent_pid": data.parent_pid,
                "parent_path": data.parent_path,
                "command_line": data.command_line,
                "total_score": data.total_score,
                "threshold": data.threshold,
                "file_writes": data.file_writes,
                "file_deletes": data.file_deletes,
                "registry_mods": data.registry_mods,
                "inject_attempts": data.inject_attempts,
                "suspicious_cmds": data.suspicious_cmds,
                "memory_rwx": data.memory_rwx,
                "remote_threads": data.remote_threads,
                "image_loads": data.image_loads,
                "result": data.result,
                "behavior": behavior,
            },
            "action": "Blocked",
            "result": "success",
        });
        entries.push(entry);
        uploaded_set.insert(key.clone());
        new_keys.push(key);
    }

    let count = entries.len();
    if count > 0 {
        uploader.push_recent_logs(entries);
        uploaded_keys.extend(new_keys);
        save_historical_upload_state(&uploaded_keys);
    }

    println!("[HistoricalUpload] Uploaded {} historical log entries", count);
    Ok(count)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // 初始化诊断日志（在任何日志输出之前），记录系统环境快照
    diagnostic_log::init();
    diag_info!("[Startup] run() started");
    log_to_file("run() started");

    // 配置 Rayo 全局线程池，为 UI 主线程保留至少一个逻辑核心，避免扫描任务占满 CPU 导致界面卡顿
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let rayon_threads = cpu_count.saturating_sub(1).max(1);
    if let Err(e) = rayon::ThreadPoolBuilder::new()
        .num_threads(rayon_threads)
        .thread_name(|i| format!("xigua-scan-{}", i))
        .build_global()
    {
        eprintln!("[Startup] Failed to configure Rayon thread pool: {}", e);
    } else {
        println!("[Startup] Configured Rayon thread pool with {} threads (total CPUs: {})", rayon_threads, cpu_count);
    }

    // 检查命令行参数，处理 protocol 激活
    let args: Vec<String> = std::env::args().collect();
    log_to_file(&format!("[Startup] Command line args: {:?}", args));
    println!("[Startup] Command line args: {:?}", args);
    
    // 检查是否有 protocol URL 参数 (xiguasecurity://threat/kill/process.exe)
    for arg in &args {
        if arg.starts_with("xiguasecurity://") {
            println!("[Protocol] Detected protocol activation: {}", arg);
            handle_protocol_activation(arg);
            // 处理完后退出，因为这只是为了处理通知点击
            return;
        }
    }
    
    // 检查是否有右键扫描参数 (--scan <path>)
    let mut scan_path_from_context: Option<String> = None;
    for i in 0..args.len() {
        if args[i] == "--scan" && i + 1 < args.len() {
            scan_path_from_context = Some(args[i + 1].clone());
            println!("[ContextMenu] Detected scan request for: {}", args[i + 1]);
            break;
        }
    }
    
    // 检查是否以后台/托盘模式启动 (--silent / --tray)
    let silent = args.iter().any(|a| a == "--silent" || a == "--tray");
    if silent {
        SILENT_STARTUP.store(true, Ordering::Relaxed);
        println!("[Startup] Silent startup detected, main window will be hidden");
        log_to_file("[Startup] Silent startup detected, main window will be hidden");
    }
    
    // 初始化安全日志管理器
    if let Err(e) = init_log_manager() {
        eprintln!("[SecurityLog] 初始化失败: {}", e);
    } else {
        println!("[SecurityLog] 初始化成功");
        // 记录应用启动日志
        let _ = security_log::add_security_log(
            security_log::LogCategory::System,
            "系统启动",
            "XIGUASecurity 安全软件已启动",
            None,
            None,
            security_log::LogAction::Started,
            security_log::LogResult::Success,
            None,
        );
    }
    
    // 初始化日志上传器
    if let Err(e) = init_log_uploader() {
        eprintln!("[LogUploader] 初始化失败: {}", e);
    } else {
        println!("[LogUploader] 初始化成功，设备名: {}", get_log_uploader().unwrap().get_device_name());
    }
    
    // 主程序不需要管理员权限，以当前用户身份运行
    // 需要管理员权限的操作（如终止系统进程、安装驱动）会单独通过 UAC 提权
    
    #[cfg(not(feature = "ms_store"))]
    let driver_state = DriverProtectionState::new();
    let scan_settings_state = ScanSettingsState::new();
    
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, argv, cwd| {
            println!("[SingleInstance] New instance launched with args: {:?}, cwd: {:?}", argv, cwd);
            
            // 检查是否有扫描参数
            for i in 0..argv.len() {
                if argv[i] == "--scan" && i + 1 < argv.len() {
                    let scan_path = argv[i + 1].clone();
                    println!("[SingleInstance] Received scan request for: {}", scan_path);
                    
                    // 发送事件到现有实例
                    let _ = app.emit("scan-path-selected", serde_json::json!({
                        "path": scan_path,
                        "source": "context_menu"
                    }));
                    
                    // 显示并聚焦窗口
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                    break;
                }
            }
            
            // 如果没有扫描参数，只是显示窗口
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init());

    #[cfg(not(feature = "ms_store"))]
    {
        builder = builder.manage(driver_state);
    }

    let app = builder
        .manage(scan_settings_state)
        .invoke_handler(tauri::generate_handler![
            is_ms_store,
            #[cfg(not(feature = "ms_store"))]
            set_driver_protection,
            #[cfg(not(feature = "ms_store"))]
            get_driver_protection,
            #[cfg(not(feature = "ms_store"))]
            get_intercepted_logs,
            #[cfg(not(feature = "ms_store"))]
            clear_intercepted_logs,
            #[cfg(not(feature = "ms_store"))]
            kill_process_via_driver,
            #[cfg(not(feature = "ms_store"))]
            get_driver_stats,
            #[cfg(not(feature = "ms_store"))]
            diagnose_driver_protection,
            #[cfg(not(feature = "ms_store"))]
            advanced_driver_check,
            open_file_path,
            #[cfg(not(feature = "ms_store"))]
            send_intercept_notification,
            #[cfg(not(feature = "ms_store"))]
            show_intercept_window,
            #[cfg(not(feature = "ms_store"))]
            close_intercept_window,
            #[cfg(not(feature = "ms_store"))]
            resize_intercept_window,
            #[cfg(not(feature = "ms_store"))]
            reset_intercept_busy,
            get_always_rules,
            clear_always_rules,
            remove_always_rule,
            #[cfg(not(feature = "ms_store"))]
            close_threat_window,
            #[cfg(not(feature = "ms_store"))]
            get_driver_protection_config_enabled,
            #[cfg(not(feature = "ms_store"))]
            set_driver_protection_config_enabled,
            #[cfg(not(feature = "ms_store"))]
            get_endpoint_protection_enabled,
            #[cfg(not(feature = "ms_store"))]
            set_endpoint_protection_enabled,
            #[cfg(not(feature = "ms_store"))]
            get_endpoint_protection_prompted,
            #[cfg(not(feature = "ms_store"))]
            set_endpoint_protection_prompted,
            #[cfg(not(feature = "ms_store"))]
            get_endpoint_protection_status,
            #[cfg(not(feature = "ms_store"))]
            start_endpoint_protection,
            #[cfg(not(feature = "ms_store"))]
            stop_endpoint_protection,
            // Melix HIPS 规则桥接命令
            #[cfg(not(feature = "ms_store"))]
            melix_service_running,
            #[cfg(not(feature = "ms_store"))]
            melix_get_rules,
            #[cfg(not(feature = "ms_store"))]
            melix_add_rule,
            #[cfg(not(feature = "ms_store"))]
            melix_delete_rule,
            #[cfg(not(feature = "ms_store"))]
            melix_get_settings,
            #[cfg(not(feature = "ms_store"))]
            melix_update_settings,
            #[cfg(not(feature = "ms_store"))]
            melix_get_trust_list,
            #[cfg(not(feature = "ms_store"))]
            melix_add_trust,
            #[cfg(not(feature = "ms_store"))]
            melix_remove_trust,
            #[cfg(not(feature = "ms_store"))]
            melix_prompt_response,
            // Melix.UI 后台进程控制命令
            #[cfg(not(feature = "ms_store"))]
            melix_ui_open_rules,
            #[cfg(not(feature = "ms_store"))]
            melix_ui_open_settings,
            #[cfg(not(feature = "ms_store"))]
            melix_ui_open_trust,
            #[cfg(not(feature = "ms_store"))]
            melix_ui_open_chain,
            #[cfg(not(feature = "ms_store"))]
            melix_ui_open_composite,
            #[cfg(not(feature = "ms_store"))]
            melix_ui_open_log,
            #[cfg(not(feature = "ms_store"))]
            melix_ui_ping,
            #[cfg(not(feature = "ms_store"))]
            melix_ui_get_status,
            is_windows_11,
            #[cfg(not(feature = "ms_store"))]
            get_driver_auto_start_decision,
            #[cfg(not(feature = "ms_store"))]
            register_wd_replacement,
            #[cfg(not(feature = "ms_store"))]
            unregister_wd_replacement,
            is_admin,
            minimize_window,
            maximize_window,
            close_window,
            start_drag,
            get_home_dir,
            check_essential_files,
            get_scan_files,
            get_full_scan_files,
            scan_file_direct,
            scan_batch_direct,
            scan_batch_direct_with_hashes,
            get_scan_files_direct,
            scan_running_processes_command,
            set_taskbar_progress,
            get_process_list,
            kill_process,
            kill_process_by_name_command,
            #[cfg(not(feature = "ms_store"))]
            check_driver_process_running,
            check_update_command,
            download_update_command,
            get_version_command,
            lock_threat_file,
            get_cloud_deep_analysis_enabled,
            set_cloud_deep_analysis_enabled,
            get_scan_sensitivity,
            set_scan_sensitivity,
            get_silent_mode_enabled,
            set_silent_mode_enabled,
            get_protection_config,
            set_protection_config,
            get_whitelist_info,
            reload_whitelist_command,
            import_whitelist_from_json,
            get_blacklist_info,
            reload_blacklist_command,
            import_blacklist_from_json,
            scan_and_load_rules_command,
            check_rules_update_command,
            update_rules_command,
            get_rules_status_command,
            set_rules_server_url_command,
            get_rules_server_url_command,
            should_auto_check_rules,
            open_rules_folder,
            open_file_location,
            quarantine_threat_file,
            restore_quarantined_file,
            delete_quarantined_file,
            get_quarantined_files,
            get_quarantine_stats,
            active_threat::show_active_threat_alert,
            active_threat::close_active_threat_alert_window,
            active_threat::get_pending_active_threat_data,
            active_threat::show_reboot_countdown,
            active_threat::close_reboot_countdown_window,
            active_threat::schedule_boot_cleanup_command,
            active_threat::clear_without_restart_command,
            active_threat::restart_now_command,
            clean_infector_file,
            get_security_logs,
            get_security_log_stats,
            clear_security_logs,
            export_security_logs,
            add_security_log,
            get_infector_detection_enabled,
            set_infector_detection_enabled,
            get_virus_family_analysis_enabled,
            set_virus_family_analysis_enabled,
            get_script_scan_enabled,
            set_script_scan_enabled,
            is_hash_whitelisted,
            check_xdows_security_installed,
            scanner::calculate_file_hash_command,
            scanner::calculate_file_hashes_command,
            scanner::scan_script_file_command,
            scan_archive_command,
            kill_process_from_alert,
            get_scanner_info_command,
            get_virus_family_rules_command,
            reload_virus_family_rules_command,
            get_engine_rule_count,
            close_edr_alert_window,
            close_edr_alert_and_start_scan,
            show_edr_behavior_chain,
            show_file_protection_alert,
            get_pending_file_protection_data,
            close_file_protection_alert_window,
            trust_file_protection_alert,
            open_quarantine_window,
            get_edr_report_data,
            list_edr_reports,
            open_timeline_window,
            #[cfg(not(feature = "ms_store"))]
            get_timeline_events,
            add_timeline_event_command,
            add_scan_timeline_event,
            show_main_window,
            show_startup_window,
            hide_splash,
            close_tray_menu,
            exit_app,
            show_secure_confirm_command,
            secure_confirm_respond,
            check_update_from_tray,
            add_to_startup_folder,
            remove_from_startup_folder,
            is_in_startup_folder,
            toggle_float_window,
            get_float_window_enabled,
            toggle_game_mode,
            get_game_mode_enabled,
            set_edr_mode,
            get_edr_process_list,
            get_edr_process_detail,
            load_image_as_base64,
            set_acrylic_intensity,
            set_window_backdrop,
            register_context_menu_command,
            unregister_context_menu_command,
            is_context_menu_registered_command,
            fetch_announcement_command,
            get_basic_protection_enabled,
            set_basic_protection_enabled,
            get_sandbox_analysis_enabled,
            set_sandbox_analysis_enabled,
            set_sandbox_analysis_file,
            prepare_sandbox_environment,
            trigger_sandbox_analysis,
            clear_sandbox_whitelist,
            get_sandbox_whitelist_count,
            test_avic_connection,
            avic_is_configured,
            get_script_protection_enabled,
            set_script_protection_enabled,
            get_running_processes,
            get_running_pids,
            get_process_info,
            start_process_watcher,
            stop_process_watcher,
            terminate_process,
            suspend_process,
            resume_process,
            hide_sandbox_progress_window,
            check_is_pua,
            file_protection::set_file_protection_enabled,
            file_protection::get_file_protection_enabled,
            file_protection::get_file_protection_events,
            file_protection::start_file_protection,
            file_protection::stop_file_protection,
            #[cfg(not(feature = "ms_store"))]
            network_protection::set_network_protection_enabled,
            #[cfg(not(feature = "ms_store"))]
            network_protection::get_network_protection_state,
            #[cfg(not(feature = "ms_store"))]
            network_protection::get_network_protection_events,
            #[cfg(not(feature = "ms_store"))]
            network_protection::trigger_network_block_test,
            ransomware_protection::set_ransomware_protection_enabled,
            ransomware_protection::get_ransomware_protection_state,
            ransomware_protection::estimate_ransomware_backup_size,
            ransomware_protection::start_ransomware_backup,
            ransomware_protection::rollback_ransomware_files,
            ransomware_protection::rollback_ransomware_by_process,
            popup_interceptor::start_popup_interceptor,
            popup_interceptor::stop_popup_interceptor,
            popup_interceptor::get_popup_interceptor_state,
            popup_interceptor::get_popup_rules,
            popup_interceptor::add_popup_rule,
            popup_interceptor::remove_popup_rule,
            popup_interceptor::get_hidden_popups,
            popup_interceptor::restore_popup,
            popup_interceptor::remove_popup_record,
            popup_interceptor::purify_popup,
            popup_interceptor::dismiss_popup_prompt,
            get_pua_protection_enabled,
            set_pua_protection_enabled,
            show_pua_intercept_window,
            send_pua_decision,
            get_suspicious_intercept_enabled,
            set_suspicious_intercept_enabled,
            show_suspicious_intercept_window,
            send_suspicious_decision,
            suspicious_analyze_file,
            scan_file_basic,
            scan_file_with_deep_analysis,
            toggle_desktop_pet,
            get_desktop_pet_enabled,
            add_whitelist_path_command,
            add_to_whitelist,
            remove_whitelist_path_command,
            get_whitelist_paths_command,
            is_path_whitelisted_command,
            add_whitelist_process_command,
            remove_whitelist_process_command,
            get_whitelist_processes_command,
            is_process_whitelisted_command,
            add_whitelist_domain_command,
            remove_whitelist_domain_command,
            get_whitelist_domains_command,
            is_domain_whitelisted_command,
            add_blacklist_path_command,
            remove_blacklist_path_command,
            get_blacklist_paths_command,
            is_path_blacklisted_command,
            open_chat_window,
            scanner::cloud_hash_check_command,
            scanner::cloud_hash_batch_command,
            scanner::check_onnx_model_loaded,
            scanner::set_skip_local_rules,
            scan_junk_command,
            clean_junk_command,
            open_browser_protection,
            get_loaded_rules_command,
            sandbox_upload_file,
            sandbox_query_report,
            sandbox_query_multiengines,
            set_language,
            get_current_language,
            system_repair_scan,
            system_repair_fix,
            get_log_upload_device_name,
            get_log_upload_enabled,
            set_log_upload_enabled,
            upload_recent_logs_command,
            upload_threats_command,
            upload_historical_logs_command,
            get_diagnostic_log_dir,
            get_diagnostic_logs,
            clear_diagnostic_logs,
            open_diagnostic_log_dir,
            save_background_image,
            get_background_image,
            delete_background_image,
            open_sponsor_url,
            open_survey_url,
            set_notification_mode_enabled,
            #[cfg(not(feature = "ms_store"))]
            send_av_driver_decision,
        ])
        .on_menu_event(|app, event| {
            on_tray_menu_event(app, &event);
        })
        .setup(|app| {
            // 网络防护：启动时崩溃恢复 + 上次状态自动恢复
            #[cfg(not(feature = "ms_store"))]
            {
                network_protection::init_on_startup(app.handle().clone());
            }

            // AVModel 看门狗线程在后台启动，监控 AVModel 进程
            // AVModel 本身的启动在 set_driver_protection(true) 中，先于 Agent 启动
            #[cfg(not(feature = "ms_store"))]
            {
                start_avmodel_watchdog();
            }

            let window = app.get_webview_window("main").unwrap();
            let app_handle = app.handle().clone();
            
            // 如果是后台/托盘模式启动，隐藏主窗口；否则由前端渲染 splash 后调用 show_startup_window 显示
            if SILENT_STARTUP.load(Ordering::Relaxed) {
                println!("[Setup] Silent startup: hiding main window");
                let _ = window.hide();
            } else {
                println!("[Setup] Main window created hidden, waiting for frontend splash render");
            }
            
            // 设置窗口图标
            let icon = tauri::include_image!("icons/icon.png");
            let _ = window.set_icon(icon);
            
            // 创建系统托盘（使用原生菜单，避免 WebView 窗口创建导致主线程死锁）
            let tray_menu = build_tray_menu(&app.handle());
            let _tray_icon = TrayIconBuilder::with_id("main")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("XIGUASecurity")
                .menu(&tray_menu)
                .show_menu_on_left_click(false)
                .on_tray_icon_event(|tray, event| {
                    match event {
                        // 左键单击显示主窗口
                        TrayIconEvent::Click { button: tauri::tray::MouseButton::Left, .. } => {
                            if let Some(window) = tray.app_handle().get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                        // 右键单击：Tauri 自动显示原生菜单，无需手动处理
                        _ => {}
                    }
                })
                .build(app)?;
            
            // 监听窗口关闭事件，改为最小化到托盘
            let window_clone = window.clone();
            window.on_window_event(move |event| {
                match event {
                    tauri::WindowEvent::CloseRequested { api, .. } => {
                        println!("[App] Window close requested, minimizing to tray...");
                        
                        // 阻止窗口关闭，改为隐藏
                        api.prevent_close();
                        let _ = window_clone.hide();
                        
                        // 显示托盘提示
                        println!("[App] Window hidden, running in tray");
                    }
                    _ => {}
                }
            });

            // 初始化规则 SQLite DB：优先从 rules.db 加载；如果不存在则尝试从旧 JSON 迁移
            std::thread::spawn(|| {
                let db_path = crate::rules_db::rules_db_path();
                if !db_path.exists() {
                    println!("[Setup] Rules DB not found, attempting JSON migration...");
                    let _ = crate::rules_db::migrate_from_json();
                }
                if db_path.exists() {
                    let _ = crate::rules_db::reload_rules_db();
                } else {
                    println!("[Setup] No rules DB available, using empty in-memory rules");
                }
            });

            // 旧版 SimpleLauncher 命名管道服务器已弃用
            // 新架构: XIGUASecurityAgent 创建管道服务器，主程序通过 av_driver_client 作为客户端连接
            // av_driver_client 在 set_driver_protection(true) 时启动
            #[cfg(not(feature = "ms_store"))]
            {
                // 不再启动旧版管道服务器
            }

            // 拦截窗口 watchdog：防止 INTERCEPT_BUSY 卡死后所有拦截请求被跳过。
            // 同步架构下，弹窗线程在 show_next_intercept 内最多 recv_timeout(30s) 等决策，
            // 正常等待期间 INTERCEPT_BUSY 为 true 属预期。因此阈值放宽到 60 秒，
            // 只兜底"弹窗线程异常退出/决策无人消费"的极端卡死。
            {
                let app_handle_clone = app_handle.clone();
                std::thread::spawn(move || {
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(10));
                        if INTERCEPT_BUSY.load(Ordering::SeqCst) {
                            let since = INTERCEPT_BUSY_SINCE.load(Ordering::SeqCst);
                            if since > 0 {
                                let elapsed = chrono::Local::now().timestamp() - since;
                                if elapsed > 60 {
                                    eprintln!("[InterceptWatchdog] INTERCEPT_BUSY stuck for {}s, waking waiters with default decision", elapsed);
                                    log_to_file(&format!("[InterceptWatchdog] INTERCEPT_BUSY stuck for {}s, waking waiters", elapsed));
                                    // ★历史 bug：旧代码只唤醒 waiters 但不重置 INTERCEPT_BUSY，
                                    // 注释声称"弹窗线程收到后自行重置"。但若弹窗线程的 recv_timeout
                                    // 被其他问题阻塞（如主线程卡死导致决策无法送达），waiters 收不到消息，
                                    // INTERCEPT_BUSY 永远为 true，后续所有拦截请求被跳过，程序卡死。
                                    // ★修复：唤醒 waiters 后也幂等重置 BUSY 状态，确保后续拦截能正常进行。
                                    if let Some(waiters) = AV_DECISION_WAITERS.get() {
                                        let keys: Vec<String> = waiters.lock().unwrap().keys().cloned().collect();
                                        for key in keys {
                                            let decision = build_default_decision(&key);
                                            let tx = waiters.lock().unwrap().remove(&key);
                                            if let Some(tx) = tx {
                                                let _ = tx.send(decision);
                                            }
                                        }
                                    }
                                    INTERCEPT_BUSY.store(false, Ordering::SeqCst);
                                    INTERCEPT_BUSY_SINCE.store(0, Ordering::SeqCst);
                                    INTERCEPT_WINDOW_CLAIMED.store(false, Ordering::SeqCst);
                                    hide_intercept_window(&app_handle_clone);
                                    // ★历史 bug：同 close_intercept_window，重置 BUSY 后
                                    // 主动拉取队列，防止拦截项被跳过。
                                    let app_clone = app_handle_clone.clone();
                                    std::thread::spawn(move || {
                                        crate::show_next_intercept(&app_clone);
                                    });
                                }
                            }
                        }
                    }
                });
            }
            
            // 拦截窗口不再预创建！直接复用 tauri.conf.json 中配置好的 intercept-alert 窗口
            // （label: intercept-alert，visible: false 隐藏创建，webview 已加载）。
            // 历史问题：动态预创建需要 dispatch 到主线程 build()，主线程繁忙时卡死，
            // 且预创建线程与消息循环线程并发操作窗口引发状态混乱。
            // 显示/隐藏/缩放用纯 Win32 直调 + 线程安全 emit，完全不依赖主线程。

            // 监听威胁警告窗口的事件
            {
                let app_handle_clone = app_handle.clone();
                app.listen("threat-alert-kill", move |event| {
                    if let Ok(payload) = serde_json::from_str::<serde_json::Value>(event.payload()) {
                        if let Some(process_name) = payload.get("processName").and_then(|v| v.as_str()) {
                            println!("[ThreatAlert] Received kill event for process: {}", process_name);
                            kill_process_with_admin(process_name);
                            // 关闭威胁警告窗口
                            if let Some(alert_window) = app_handle_clone.get_webview_window("threat-alert") {
                                let _ = alert_window.close();
                            }
                        }
                    }
                });
            }
            
            // 监听新 KMDF 驱动通知 (av_driver_client 发出)
            #[cfg(not(feature = "ms_store"))]
            {
                let app_handle_clone = app_handle.clone();
                app.listen("av-driver-notification", move |event| {
                    if let Ok(notification) = serde_json::from_str::<av_driver_client::AvNotification>(event.payload()) {
                        println!("[Setup] Received av-driver-notification on thread {:?}", std::thread::current().id());
                        // 同步模型（与 AVMain 一致）：直接在当前线程（消息循环线程）处理。
                        // emit 同步触发本回调，本回调返回后消息循环才继续读下一条通知，
                        // 等价于 AVMain 的"弹窗阻塞 → 写决策 → 下一条"。
                        // 历史 bug：此处 spawn 独立线程处理，导致弹窗/决策与通知接收解耦，
                        // 引发"通知堆积读不到、决策无人消费"等并发问题。
                        handle_av_driver_notification(&app_handle_clone, &notification);
                    } else {
                        eprintln!("[Setup] Failed to parse av-driver-notification payload");
                    }
                });
                println!("[Setup] av-driver-notification listener registered");
            }
            
            #[cfg(windows)]
            {
                // 设置应用ID，让通知显示正确的应用名称和图标
                unsafe {
                    use windows::Win32::System::Com::CoInitialize;
                    use windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;
                    use windows::core::HSTRING;
                    
                    let _ = CoInitialize(None);
                    let _ = SetCurrentProcessExplicitAppUserModelID(&HSTRING::from("XIGUASecurity.App"));
                }
                
                // 设置窗口圆角（Fluent Design）
                unsafe {
                    let hwnd = window.hwnd().unwrap().0 as *mut std::ffi::c_void;
                    let corner_preference: u32 = 2; // DWMWCP_ROUND
                    
                    type DwmFn = unsafe extern "system" fn(
                        hwnd: *mut std::ffi::c_void,
                        dwattribute: u32,
                        pvattribute: *const std::ffi::c_void,
                        cbattribute: u32
                    ) -> i32;
                    
                    if let Ok(dwmapi) = windows::Win32::System::LibraryLoader::LoadLibraryW(windows::core::w!("dwmapi.dll")) {
                        if let Some(proc) = windows::Win32::System::LibraryLoader::GetProcAddress(dwmapi, windows::core::s!("DwmSetWindowAttribute")) {
                            let func: DwmFn = std::mem::transmute(proc);
                            let _ = func(
                                hwnd,
                                33, // DWMWA_WINDOW_CORNER_PREFERENCE
                                &corner_preference as *const _ as *const _,
                                std::mem::size_of::<u32>() as u32
                            );
                        }
                    }
                }
                
                // 设置窗口亚克力效果 (SetWindowCompositionAttribute)
                let hwnd = window.hwnd().unwrap().0 as isize;
                set_window_acrylic(hwnd, 120);
            }
            
            // 处理右键扫描请求
            if let Some(scan_path) = scan_path_from_context {
                let app_handle = app.handle().clone();
                let window = window.clone();
                tauri::async_runtime::spawn(async move {
                    // 等待窗口准备好
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    println!("[ContextMenu] Emitting scan-path-selected event with path: {}", scan_path);
                    // 发送事件到前端，触发扫描
                    let _ = app_handle.emit("scan-path-selected", serde_json::json!({
                        "path": scan_path,
                        "source": "context_menu"
                    }));
                    // 确保窗口显示
                    let _ = window.show();
                    let _ = window.set_focus();
                });
            }

            // 规则库已迁移至 SQLite（rules.db），启动时由 rules_db 模块加载，无需 JSON 扫描
            println!("[Startup] Rules DB (SQLite) initialized by rules_db module");

            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                    if let Ok(uploader) = get_log_uploader() {
                        if uploader.is_enabled() {
                            match uploader.flush_recent_logs().await {
                                Ok(count) => {
                                    if count > 0 {
                                        println!("[LogUploader] Uploaded {} recent logs", count);
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[LogUploader] Upload failed: {}", e);
                                }
                            }
                        }
                    }
                }
            });

            // 启动心跳任务：启动后立即发送一次，之后每 30 秒一次，保持设备在线
            tauri::async_runtime::spawn(async move {
                // 首次心跳延迟 5 秒，等待网络初始化
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                loop {
                    if let Ok(uploader) = get_log_uploader() {
                        if uploader.is_enabled() {
                            match uploader.send_heartbeat().await {
                                Ok(_) => {
                                    // 心跳成功，静默
                                }
                                Err(e) => {
                                    eprintln!("[LogUploader] Heartbeat failed: {}", e);
                                }
                            }
                        }
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                }
            });

            // 启动时检查：沙盒分析默认开启（新用户安装后自动启用）
            // 配置文件不存在时默认为 true，并写入配置文件持久化
            {
                let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
                let config_dir = format!("{}/XIGUASecurity", local_app_data);
                let config_path = format!("{}/sandbox_analysis_enabled.txt", config_dir);

                let sandbox_enabled = std::fs::read_to_string(&config_path)
                    .map(|s| s.trim() == "true")
                    .unwrap_or(true); // 配置文件不存在时默认启用

                if sandbox_enabled {
                    sandbox_analysis::set_analysis_enabled(true);

                    // 持久化默认配置（配置文件不存在时写入）
                    let _ = std::fs::create_dir_all(&config_dir);
                    if !std::path::Path::new(&config_path).exists() {
                        let _ = std::fs::write(&config_path, "true");
                        println!("[Setup] 沙盒分析默认启用，已写入配置文件");
                    }

                    // 后台自动检测并配置沙盒环境
                    let app_handle_clone = app.handle().clone();
                    std::thread::spawn(move || {
                        println!("[Setup] 开始自动检测沙盒环境...");
                        diag_info!("[Setup] 开始自动检测沙盒环境...");
                        match sandbox_analysis::auto_configure_sandbox() {
                            Ok(true) => {
                                println!("[Setup] 沙盒环境自动配置完成");
                                diag_info!("[Setup] 沙盒环境自动配置完成");
                            }
                            Ok(false) => {
                                println!("[Setup] 沙盒环境未就绪");
                                diag_warn!("[Setup] 沙盒环境未就绪");
                            }
                            Err(e) => {
                                println!("[Setup] 沙盒环境自动配置失败: {}", e);
                                diag_warn!("[Setup] 沙盒环境自动配置失败: {}", e);
                            }
                        }

                        // 配置完成后，如果驱动未连接，启动 R3 进程监控
                        if !av_driver_client::is_av_driver_connected() {
                            println!("[Setup] 驱动未连接，启动 R3 进程监控");
                            sandbox_analysis::start_r3_process_monitor(&app_handle_clone);
                        }
                    });
                }
            }

            // 驱动防护默认强制开启：即使上次会话用户关闭了驱动/总防护，
            // 本次启动也自动连接驱动（避免"上次关掉 → 重启失去驱动 → 功能丢失"）。
            // 用户仅可在当前会话内临时关闭（set_driver_protection(false) 只影响本次运行）。
            // 若驱动已连接则幂等跳过（不重复提权拉起）。
            #[cfg(not(feature = "ms_store"))]
            {
                if !av_driver_client::is_av_driver_connected() && !is_interceptor_running() {
                    println!("[Setup] 驱动防护默认强制开启：自动连接驱动");
                    log_to_file("[Setup] 驱动防护默认强制开启：自动连接驱动");
                    start_driver_protection_background(app.handle().clone());
                } else {
                    println!("[Setup] 驱动已连接/已在运行，跳过强制启动");
                }
            }

            diag_info!("[Setup] Tauri setup completed successfully");
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application");
    diag_info!("[Startup] Tauri build completed, entering event loop");
    println!("[Startup] Tauri build completed, entering event loop");
    app.run(|app_handle, event| {
            match event {
                RunEvent::ExitRequested { .. } => {
                    diag_info!("[App] ExitRequested, running cleanup");
                    cleanup_before_exit(&app_handle);
                    diag_info!("[App] Cleanup finished, application exiting");
                }
                RunEvent::Exit => {
                    diag_info!("[App] Application exited");
                }
                _ => {}
            }
        });
}

// ==================== EDR (Endpoint Detection and Response) 模块 ====================

// 设置 EDR 模式
#[tauri::command]
async fn set_edr_mode(enabled: bool) -> Result<(), String> {
    println!("[EDR] Setting EDR mode to: {}", enabled);
    
    let monitor_arc = get_etw_monitor();
    let mut monitor = monitor_arc.lock().map_err(|e| e.to_string())?;
    
    if enabled {
        // 启动 ETW 监控
        monitor.start();
        println!("[EDR] EDR mode enabled, ETW monitoring started");
    } else {
        // 停止 ETW 监控
        monitor.stop();
        println!("[EDR] EDR mode disabled");
    }
    
    Ok(())
}

// 获取 EDR 进程列表
#[tauri::command]
async fn get_edr_process_list() -> Result<Vec<etw_monitor::ProcessInfo>, String> {
    let monitor_arc = get_etw_monitor();
    let monitor = monitor_arc.lock().map_err(|e| e.to_string())?;
    let processes = monitor.get_process_list();
    Ok(processes)
}

// 获取 EDR 进程详情
#[tauri::command]
async fn get_edr_process_detail(pid: u32) -> Result<etw_monitor::ProcessInfo, String> {
    let monitor_arc = get_etw_monitor();
    let monitor = monitor_arc.lock().map_err(|e| e.to_string())?;
    monitor.get_process_detail(pid)
        .ok_or_else(|| "Process not found".to_string())
}

fn stop_edr_monitoring() {
    println!("[EDR] Stopping EDR monitoring...");
    if let Ok(mut monitor) = get_etw_monitor().lock() {
        monitor.stop();
    }
}

// 加载图片文件并返回 base64 数据 URL
#[tauri::command]
async fn load_image_as_base64(file_path: String) -> Result<String, String> {
    use std::fs;
    use std::path::Path;
    
    let path = Path::new(&file_path);
    if !path.exists() {
        return Err(format!("File not found: {}", file_path));
    }
    
    // 读取文件内容
    let bytes = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;
    
    // 根据扩展名判断 MIME 类型
    let ext = path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    
    let mime_type = match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "bmp" => "image/bmp",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "svg" => "image/svg+xml",
        _ => "application/octet-stream",
    };
    
    // 转换为 base64
    let base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
    let data_url = format!("data:{};base64,{}", mime_type, base64);
    
    Ok(data_url)
}

// ==================== 自定义背景图片管理 ====================

/// 背景图片存储目录：%LOCALAPPDATA%\XIGUASecurity\background
fn background_image_dir() -> std::path::PathBuf {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(base).join("XIGUASecurity").join("background")
}

/// 保存自定义背景图片：复制用户选择的图片到程序数据目录，返回保存后的路径。
/// 这样用户移动/删除原图后背景依然有效。
#[tauri::command]
fn save_background_image(file_path: String) -> Result<String, String> {
    use std::fs;

    let src = std::path::Path::new(&file_path);
    if !src.exists() {
        return Err(format!("文件不存在: {}", file_path));
    }

    // 校验扩展名（仅允许图片格式）
    let ext = src.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let allowed = ["png", "jpg", "jpeg", "gif", "bmp", "webp", "ico"];
    if !allowed.contains(&ext.as_str()) {
        return Err(format!("不支持的图片格式: {}", ext));
    }

    // 创建目录并复制文件（固定文件名 background.<ext>，保持扩展名以正确识别 MIME）
    let dir = background_image_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("创建背景目录失败: {}", e))?;

    let dest = dir.join(format!("background.{}", ext));
    // 先删除旧文件（同名不同格式的情况）
    // 只删除 background.* 系列文件，避免误删其他文件
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if let Some(name_str) = name.to_str() {
                if name_str.starts_with("background.") && name_str != dest.file_name().and_then(|n| n.to_str()).unwrap_or("") {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
    fs::copy(src, &dest).map_err(|e| format!("复制背景图片失败: {}", e))?;

    diag_info!("[Background] Saved background image: {} -> {}", file_path, dest.display());
    Ok(dest.to_string_lossy().to_string())
}

/// 获取已保存的背景图片路径（未设置返回空字符串）
#[tauri::command]
fn get_background_image() -> Result<String, String> {
    let dir = background_image_dir();
    if !dir.exists() {
        return Ok(String::new());
    }
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if let Some(name_str) = name.to_str() {
                if name_str.starts_with("background.") {
                    return Ok(entry.path().to_string_lossy().to_string());
                }
            }
        }
    }
    Ok(String::new())
}

/// 删除已保存的背景图片
#[tauri::command]
fn delete_background_image() -> Result<(), String> {
    let dir = background_image_dir();
    if !dir.exists() {
        return Ok(());
    }
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if let Some(name_str) = name.to_str() {
                if name_str.starts_with("background.") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }
    diag_info!("[Background] Deleted background image");
    Ok(())
}

// ==================== 微步云沙箱 API 中转站 模块 ====================

const SANDBOX_RELAY_BASE: &str = "http://103.118.245.82:9051";
const SANDBOX_API_KEY: &str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1";

/// 上传文件到云沙箱进行分析
#[tauri::command]
async fn sandbox_upload_file(file_path: String) -> Result<serde_json::Value, String> {
    let url = format!("{}/v3/file/upload", SANDBOX_RELAY_BASE);
    
    // 读取文件内容
    let file_bytes = tokio::fs::read(&file_path)
        .await
        .map_err(|e| format!("无法读取文件: {}", e))?;
    
    let file_name = std::path::Path::new(&file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();
    
    // 构造 multipart 表单（必须传 sandbox_type 和 run_time 才能触发沙箱行为分析）
    let file_part = reqwest::multipart::Part::bytes(file_bytes)
        .file_name(file_name.clone());
    let form = reqwest::multipart::Form::new()
        .part("file", file_part)
        .text("sandbox_type", "win10_22h2_enx64_office2019")
        .text("run_time", "120");
    
    // 发送请求
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("X-API-Key", SANDBOX_API_KEY)
        .multipart(form)
        .send()
        .await
        .map_err(|e| format!("上传请求失败: {}", e))?;
    
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("解析响应失败: {}", e))?;
    
    if status.is_success() {
        Ok(body)
    } else {
        // 即使非200也尝试返回body内容，方便前端调试
        eprintln!("[Sandbox] 上传API返回非200状态: {} - {}", status, body);
        Err(format!("上传失败 (HTTP {}): {}", status, body))
    }
}

/// 查询文件沙箱分析报告
#[tauri::command]
async fn sandbox_query_report(resource: String) -> Result<serde_json::Value, String> {
    let url = format!("{}/v3/file/report", SANDBOX_RELAY_BASE);
    
    eprintln!("[Sandbox] 查询报告 请求URL: {}", url);
    eprintln!("[Sandbox] 查询报告 请求resource: '{}'", resource);
    eprintln!("[Sandbox] 查询报告 resource长度: {}", resource.len());
    
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("X-API-Key", SANDBOX_API_KEY)
        .json(&serde_json::json!({"resource": resource}))
        .send()
        .await
        .map_err(|e| format!("查询报告请求失败: {}", e))?;
    
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("解析响应失败: {}", e))?;
    
    if status.is_success() {
        Ok(body)
    } else {
        eprintln!("[Sandbox] 报告查询API返回非200状态: {} - {}", status, body);
        Err(format!("查询报告失败 (HTTP {}): {}", status, body))
    }
}

/// 查询多引擎扫描结果
#[tauri::command]
async fn sandbox_query_multiengines(resource: String) -> Result<serde_json::Value, String> {
    let url = format!("{}/v3/file/report/multiengines", SANDBOX_RELAY_BASE);
    
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("X-API-Key", SANDBOX_API_KEY)
        .json(&serde_json::json!({"resource": resource}))
        .send()
        .await
        .map_err(|e| format!("查询多引擎结果请求失败: {}", e))?;
    
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("解析响应失败: {}", e))?;
    
    if status.is_success() {
        Ok(body)
    } else {
        Err(format!("查询多引擎结果失败 (HTTP {}): {}", status, body))
    }
}
