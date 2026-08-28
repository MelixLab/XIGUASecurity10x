//! 驱动防护模块：Agent 进程启停、状态检测、拦截窗口与驱动决策。
//! 移植自 XIGUASecurity10x（简化版：不做 AVIC 云信誉/沙箱，通知直接弹拦截窗口）。

use crate::av_driver_client::{self, AvDecision, AvNotification};
use once_cell::sync::Lazy;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager};

const AGENT_EXE: &str = "XIGUASecurityAgent.exe";

/// 被拦截项的完整信息（含驱动决策所需字段）。
#[derive(Clone)]
pub struct InterceptItem {
    pub intercept_type: String,
    pub process_name: String,
    pub file_path: String,
    pub pending_key: String,
    pub threat_info: String,
    /// process | registry | injection | ransom | endpoint | injectguard
    pub notification_type: String,
    /// 决策时需要的原始 id
    pub raw_id: u64,
    /// true = 超时默认拦截（云端已知威胁）；false = 超时默认放行（本地扫描命中）
    pub default_block: bool,
}

pub struct DriverState {
    pub intercept_busy: bool,
    pub queue: VecDeque<InterceptItem>,
    pub pending: HashMap<String, InterceptItem>,
}

pub static DRIVER_STATE: Lazy<Mutex<DriverState>> = Lazy::new(|| {
    Mutex::new(DriverState {
        intercept_busy: false,
        queue: VecDeque::new(),
        pending: HashMap::new(),
    })
});

// ═══════════════════════════════════════════════════════════════════════════
// Agent 进程管理
// ═══════════════════════════════════════════════════════════════════════════

/// 查找 Agent exe：可执行文件同级 → 向上遍历找 Driver/ 目录。
pub fn find_agent_exe() -> Option<PathBuf> {
    let mut dir = std::env::current_exe().ok()?.parent().map(Path::to_path_buf)?;
    for _ in 0..6 {
        let candidate = dir.join("Driver").join(AGENT_EXE);
        if candidate.is_file() {
            return Some(candidate);
        }
        if dir.join(AGENT_EXE).is_file() {
            return Some(dir.join(AGENT_EXE));
        }
        dir = dir.parent()?.to_path_buf();
    }
    None
}

/// Agent 进程是否在运行（Toolhelp 快照枚举）。
pub fn is_agent_running() -> bool {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::Foundation::CloseHandle;
    use std::os::windows::ffi::OsStringExt;

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_err() {
            return false;
        }
        let snapshot = snapshot.unwrap();
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = false;
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                // szExeFile 是固定 260 字符数组，需在 null 处截断再比较
                let wide = &entry.szExeFile;
                let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
                let name = std::ffi::OsString::from_wide(&wide[..len])
                    .to_string_lossy()
                    .to_string();
                if name.eq_ignore_ascii_case(AGENT_EXE) {
                    found = true;
                    break;
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
        found
    }
}

/// 当前进程是否已提权（OpenProcessToken + TokenElevation）。
pub fn is_elevated() -> bool {
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_INFORMATION_CLASS, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: windows::Win32::Foundation::HANDLE =
            windows::Win32::Foundation::HANDLE(std::ptr::null_mut());
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        let _ = windows::Win32::Foundation::CloseHandle(token);
        ok.is_ok() && elevation.TokenIsElevated != 0
    }
}

/// 启动 Agent。必须管理员权限：已提权 → CreateProcess 直接启动（子进程继承提权）；
/// 未提权 → ShellExecuteW("runas") 触发 UAC（普通权限启动的 Agent 无法工作）。
pub fn start_agent() -> Result<(), String> {
    let exe = find_agent_exe().ok_or("找不到 XIGUASecurityAgent.exe".to_string())?;
    if is_agent_running() {
        return Ok(());
    }
    let exe_str = exe.to_string_lossy().into_owned();
    let dir = exe.parent().map(|p| p.to_string_lossy().into_owned());

    if is_elevated() {
        // 已提权：CreateProcess，子进程继承提权级别
        unsafe {
            use windows::Win32::System::Threading::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
            use windows::Win32::System::Threading::CREATE_NO_WINDOW;
            use std::os::windows::ffi::OsStrExt;
            let mut si = STARTUPINFOW::default();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi = PROCESS_INFORMATION::default();
            let app_wide: Vec<u16> = std::ffi::OsStr::new(&exe_str)
                .encode_wide()
                .chain(Some(0))
                .collect();
            let dir_wide: Vec<u16> = dir
                .as_ref()
                .map(|d| std::ffi::OsStr::new(d).encode_wide().chain(Some(0)).collect())
                .unwrap_or_default();
            let app_ptr = windows::core::PCWSTR(app_wide.as_ptr());
            let dir_ptr = if dir_wide.is_empty() {
                windows::core::PCWSTR(std::ptr::null())
            } else {
                windows::core::PCWSTR(dir_wide.as_ptr())
            };
            let ok = CreateProcessW(
                app_ptr,
                windows::core::PWSTR(std::ptr::null_mut()),
                None,
                None,
                windows::Win32::Foundation::BOOL(0),
                CREATE_NO_WINDOW,
                None,
                dir_ptr,
                &si,
                &mut pi,
            );
            if ok.is_ok() {
                let _ = windows::Win32::Foundation::CloseHandle(pi.hProcess);
                let _ = windows::Win32::Foundation::CloseHandle(pi.hThread);
                return Ok(());
            }
        }
    }

    // 未提权（或 CreateProcess 失败）：ShellExecute runas 触发 UAC
    unsafe {
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
        use std::os::windows::ffi::OsStrExt;
        let verb: Vec<u16> = "runas".encode_utf16().chain(Some(0)).collect();
        let file: Vec<u16> = std::ffi::OsStr::new(&exe_str).encode_wide().chain(Some(0)).collect();
        let res = ShellExecuteW(
            None,
            windows::core::PCWSTR(verb.as_ptr()),
            windows::core::PCWSTR(file.as_ptr()),
            None,
            None,
            SW_HIDE,
        );
        if (res.0 as isize) > 32 {
            Ok(())
        } else {
            Err(format!("启动 Agent 失败（UAC 被拒绝?） code={:?}", res.0))
        }
    }
}

/// 停止 Agent：先普通权限 taskkill，失败（管理员进程拒绝访问）则提权 taskkill 兜底。
pub fn stop_agent() -> Result<(), String> {
    if !is_agent_running() {
        return Ok(());
    }

    fn run_taskkill(elevated: bool) {
        unsafe {
            use windows::Win32::System::Threading::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
            use windows::Win32::System::Threading::CREATE_NO_WINDOW;
            let mut si = STARTUPINFOW::default();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi = PROCESS_INFORMATION::default();
            let mut cmd: Vec<u16> = "taskkill /F /IM XIGUASecurityAgent.exe"
                .encode_utf16()
                .chain(Some(0))
                .collect();
            if elevated {
                // 提权执行：ShellExecute runas
                use windows::Win32::UI::Shell::ShellExecuteW;
                use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
                let verb: Vec<u16> = "runas".encode_utf16().chain(Some(0)).collect();
                let file: Vec<u16> = "taskkill.exe".encode_utf16().chain(Some(0)).collect();
                let args: Vec<u16> = "/F /IM XIGUASecurityAgent.exe".encode_utf16().chain(Some(0)).collect();
                let _ = ShellExecuteW(
                    None,
                    windows::core::PCWSTR(verb.as_ptr()),
                    windows::core::PCWSTR(file.as_ptr()),
                    windows::core::PCWSTR(args.as_ptr()),
                    None,
                    SW_HIDE,
                );
            } else {
                let ok = CreateProcessW(
                    None,
                    windows::core::PWSTR(cmd.as_mut_ptr()),
                    None,
                    None,
                    windows::Win32::Foundation::BOOL(0),
                    CREATE_NO_WINDOW,
                    None,
                    None,
                    &si,
                    &mut pi,
                );
                if ok.is_ok() {
                    let _ = windows::Win32::System::Threading::WaitForSingleObject(pi.hProcess, 3000);
                    let _ = windows::Win32::Foundation::CloseHandle(pi.hProcess);
                    let _ = windows::Win32::Foundation::CloseHandle(pi.hThread);
                }
            }
        }
    }

    // 1) 普通权限
    run_taskkill(false);
    for _ in 0..10 {
        if !is_agent_running() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // 2) 仍在运行（管理员进程）→ 提权兜底
    if is_agent_running() {
        run_taskkill(true);
        for _ in 0..15 {
            if !is_agent_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    if is_agent_running() {
        Err("无法停止 Agent（权限不足或进程拒绝退出）".to_string())
    } else {
        Ok(())
    }
}

/// 驱动防护是否启用（Agent 运行或管道已连接）。
pub fn is_driver_protection_enabled() -> bool {
    is_agent_running() || av_driver_client::is_av_driver_connected()
}

/// 设置驱动防护开关。
pub fn set_driver_protection(app: &AppHandle, enabled: bool) -> Result<(), String> {
    if enabled {
        start_agent()?;
        // 尝试连接 Agent 管道（后台线程，失败不阻塞开关状态）
        let app = app.clone();
        std::thread::spawn(move || {
            let _ = av_driver_client::start_av_driver_client(app);
        });
    } else {
        let _ = av_driver_client::send_shutdown_request();
        av_driver_client::stop_av_driver_client();
        stop_agent()?;
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// 拦截窗口
// ═══════════════════════════════════════════════════════════════════════════

fn show_win32(win: &tauri::WebviewWindow) {
    let _ = win.show();
    let _ = win.set_focus();
    let _ = win.set_always_on_top(true);
}

/// 弹出一条拦截（串行队列）。
pub fn show_intercept(app: &AppHandle, item: InterceptItem) {
    {
        let mut st = DRIVER_STATE.lock().unwrap();
        st.pending.insert(item.pending_key.clone(), item.clone());
        st.queue.push_back(item);
        if st.intercept_busy {
            return;
        }
        st.intercept_busy = true;
    }
    process_next(app);
}

fn process_next(app: &AppHandle) {
    let item = {
        let mut st = DRIVER_STATE.lock().unwrap();
        st.queue.pop_front()
    };
    let item = match item {
        Some(i) => i,
        None => {
            let mut st = DRIVER_STATE.lock().unwrap();
            st.intercept_busy = false;
            return;
        }
    };

    let payload = serde_json::json!({
        "type": item.intercept_type,
        "process": item.process_name,
        "command": format!("{}\n威胁: {}", item.file_path, item.threat_info),
        "resp_pipe": item.pending_key,
        "source": "driver_protection",
    });

    if let Some(win) = app.get_webview_window("intercept-alert") {
        let _ = win.emit("intercept-data", payload);
        show_win32(&win);
    } else {
        // 兜底：动态创建
        match tauri::WebviewWindowBuilder::new(app, "intercept-alert", tauri::WebviewUrl::App("intercept-alert.html".into()))
            .title("实时防护拦截")
            .inner_size(360.0, 500.0)
            .decorations(false)
            .transparent(true)
            .shadow(true)
            .always_on_top(true)
            .skip_taskbar(true)
            .resizable(false)
            .build()
        {
            Ok(win) => {
                let _ = win.emit("intercept-data", payload);
                show_win32(&win);
            }
            Err(e) => {
                let mut st = DRIVER_STATE.lock().unwrap();
                st.intercept_busy = false;
                eprintln!("[DriverProtection] 创建拦截窗口失败: {}", e);
            }
        }
    }
    // 决策/关闭后由 finish_intercept 继续下一条
}

/// 关闭当前拦截窗口并处理队列下一条。
pub fn finish_intercept(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("intercept-alert") {
        let _ = win.hide();
    }
    {
        let mut st = DRIVER_STATE.lock().unwrap();
        st.intercept_busy = false;
    }
    process_next(app);
}

/// 应用驱动决策并写回 Agent 管道。
pub fn apply_decision(app: &AppHandle, pending_key: &str, decision: &str) -> Result<(), String> {
    let item = {
        let mut st = DRIVER_STATE.lock().unwrap();
        st.pending.remove(pending_key)
    }
    .ok_or("Notification not found")?;

    let code = match decision {
        "allow" => av_driver_client::AV_DECISION_ALLOW_ONCE,
        "block" => av_driver_client::AV_DECISION_DENY_ONCE,
        "allow_always" => av_driver_client::AV_DECISION_ALLOW_ALWAYS,
        "block_always" => av_driver_client::AV_DECISION_DENY_ALWAYS,
        _ => return Err(format!("Invalid decision: {}", decision)),
    };

    let av_decision = match item.notification_type.as_str() {
        "process" => AvDecision::Process {
            notification_id: item.raw_id,
            decision: code,
            image_path: item.file_path,
        },
        "registry" => AvDecision::Registry {
            notification_id: item.raw_id,
            decision: code,
            key_path: item.file_path,
        },
        "injection" => AvDecision::Injection {
            notification_id: item.raw_id,
            decision: code,
        },
        "ransom" => AvDecision::Ransom {
            notification_id: item.raw_id,
            decision: code,
        },
        "endpoint" => AvDecision::EndPoint {
            notification_id: item.raw_id,
            decision: code,
        },
        "injectguard" => AvDecision::InjectGuard {
            sequence_id: item.raw_id as u32,
            decision: code,
        },
        _ => return Err("Unknown notification type".to_string()),
    };

    av_driver_client::send_av_decision(av_decision)?;
    finish_intercept(app);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// 通知处理
// ═══════════════════════════════════════════════════════════════════════════

fn file_name_of(p: &str) -> String {
    Path::new(p)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.to_string())
}

/// 处理 Agent 推送的驱动拦截通知 → 弹拦截窗口。
/// 进程通知：先用本地 ML 引擎扫描镜像 → 恶意弹窗拦截 / 安全直接放行（与旧项目一致）。
pub fn handle_notification(app: &AppHandle, n: AvNotification) {
    let item = match n {
        AvNotification::Process(p) => {
            // 驱动已挂起该进程，主程序负责判定：扫描 → 恶意弹窗 / 安全放行
            let sr = crate::scanner::ml_scan_file(&p.image_path);
            if sr.result != "MALICIOUS" {
                // 安全 → 自动放行（ALLOW_ONCE）
                let _ = av_driver_client::send_av_decision(AvDecision::Process {
                    notification_id: p.notification_id,
                    decision: av_driver_client::AV_DECISION_ALLOW_ONCE,
                    image_path: p.image_path,
                });
                return;
            }
            let family = sr.virus_family.clone().unwrap_or_else(|| "Malware".to_string());
            InterceptItem {
                intercept_type: "进程拦截".to_string(),
                process_name: file_name_of(&p.image_path),
                file_path: p.image_path,
                pending_key: p.notification_id.to_string(),
                threat_info: format!("威胁: {} (概率: {:.1}%)", family, sr.probability * 100.0),
                notification_type: "process".to_string(),
                raw_id: p.notification_id,
                default_block: false,
            }
        }
        AvNotification::Registry(r) => InterceptItem {
            intercept_type: "注册表拦截".to_string(),
            process_name: format!("PID {}", r.process_id),
            file_path: r.key_path,
            pending_key: r.notification_id.to_string(),
            threat_info: format!("操作: {}", r.operation_type),
            notification_type: "registry".to_string(),
            raw_id: r.notification_id,
            default_block: false,
        },
        AvNotification::Injection(i) => InterceptItem {
            intercept_type: "注入拦截".to_string(),
            process_name: i.source_image_path,
            file_path: format!("目标进程 PID {}", i.target_process_id),
            pending_key: i.notification_id.to_string(),
            threat_info: format!("线程 {} 地址 0x{:X}", i.thread_id, i.start_address),
            notification_type: "injection".to_string(),
            raw_id: i.notification_id,
            default_block: false,
        },
        AvNotification::Ransom(r) => {
            let first = r.files.first().map(|f| f.original_path.clone()).unwrap_or_default();
            InterceptItem {
                intercept_type: "勒索防护".to_string(),
                process_name: format!("{} 个文件", r.file_count),
                file_path: first,
                pending_key: r.notification_id.to_string(),
                threat_info: "检测到疑似勒索行为，文件已被备份保护".to_string(),
                notification_type: "ransom".to_string(),
                raw_id: r.notification_id,
                default_block: false,
            }
        }
        AvNotification::EndPoint(e) => InterceptItem {
            intercept_type: "行为拦截".to_string(),
            process_name: file_name_of(&e.image_path),
            file_path: e.image_path,
            pending_key: e.notification_id.to_string(),
            threat_info: format!("行为评分 {}", e.total_score),
            notification_type: "endpoint".to_string(),
            raw_id: e.notification_id,
            default_block: false,
        },
        AvNotification::InjectGuard(g) => InterceptItem {
            intercept_type: "注入防护".to_string(),
            process_name: g.source_process_name,
            file_path: g.target_process_name,
            pending_key: format!("ig{}", g.sequence_id),
            threat_info: format!("事件类型 {}", g.event_type),
            notification_type: "injectguard".to_string(),
            raw_id: g.sequence_id as u64,
            default_block: false,
        },
        AvNotification::Error { code, message } => {
            eprintln!("[DriverProtection] Agent 错误: {} - {}", code, message);
            return;
        }
    };
    show_intercept(app, item);
}

/// 供 lib.rs 注册：监听 av-driver-notification 事件。
#[derive(Clone, Serialize)]
pub struct DriverStatus {
    pub enabled: bool,
}
