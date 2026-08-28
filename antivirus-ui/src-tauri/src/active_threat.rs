//! 活动内存威胁处置模块（卡巴斯基风格）
//!
//! 场景：主程序尝试删除/隔离病毒源文件时返回"拒绝访问"（文件被活动进程占用）。
//! 此时弹出独立处置窗口，提供两种清除方案：
//!
//! 1. 开机时清除（schedule_boot_cleanup）
//!    - 优先使用 MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT) 将文件标记为
//!      下次重启时由 Session Manager 删除（需管理员 + SeRestorePrivilege）。
//!    - 失败则回退 PowerShell 提权写注册表
//!      HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\
//!      PendingFileRenameOperations（与 MoveFileEx 同一底层机制）。
//!    - 随后显示 60 秒重启倒计时窗口，用户可立即重启或取消。
//!
//! 2. 不重启而清除（clear_without_restart）
//!    - 使用 Windows Restart Manager 定位占用文件的全部进程；
//!    - 分级终止进程：R3 TerminateProcess → AVGuard(AVModel) → 驱动管道
//!      → UAC PowerShell Stop-Process；
//!    - 等待句柄释放后重试删除原文件。

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use once_cell::sync::Lazy;
use tauri::{AppHandle, Emitter, Manager};

/// 活动威胁处置窗口互斥（std 线程内短暂持有，防止并发告警交错）
static ACTIVE_THREAT_ALERT_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

/// 最近一次待显示的"活动内存威胁"弹窗数据（前端页面加载后的兜底拉取）
static PENDING_ACTIVE_THREAT_DATA: Lazy<Mutex<Option<serde_json::Value>>> =
    Lazy::new(|| Mutex::new(None));

// ==================== 错误识别 ====================

/// 判断错误是否属于"拒绝访问 / 文件被占用"（删除失败的核心原因）
pub fn is_access_denied_error(err: &str) -> bool {
    let lower = err.to_lowercase();
    lower.contains("access is denied")
        || lower.contains("拒绝访问")
        || lower.contains("os error 5")
        || lower.contains("sharing violation")
        || lower.contains("os error 32")
        || lower.contains("being used by another process")
        || lower.contains("另一个程序正在使用")
}

// ==================== 开机时清除 ====================

/// 将文件标记为"下次重启时删除"
///
/// 优先 in-process 调用 MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT)：
/// 该 API 专门用于删除被占用文件，由 Session Manager 在开机早期完成，
/// 此时任何进程都尚未启动，不会重新占用。要求调用进程已提权
/// （本程序以管理员运行时直接生效，不弹 UAC）。
///
/// 失败（例如 MS Store 模式未提权）则回退 PowerShell 提权（runas）
/// 直接写 PendingFileRenameOperations 注册表（同一底层机制）。
pub fn schedule_boot_cleanup(file_path: &str) -> Result<String, String> {
    // 路径必须是完整绝对路径
    let abs_path = absolute_path(file_path)?;

    // 方案一：in-process MoveFileEx（已提权时无 UAC 弹窗）
    if crate::is_elevated() && move_file_ex_delay_reboot(&abs_path) {
        println!("[ActiveThreat] 已通过 MoveFileEx 标记重启删除: {}", abs_path);
        return Ok("movefileex".to_string());
    }

    // 方案二：PowerShell 提权写 PendingFileRenameOperations 注册表
    let method = schedule_boot_cleanup_via_powershell(&abs_path)?;
    println!("[ActiveThreat] 已通过 {} 标记重启删除: {}", method, abs_path);
    Ok(method)
}

/// 获取文件的绝对路径（要求存在或可解析；被占用文件依然存在）
fn absolute_path(file_path: &str) -> Result<String, String> {
    let p = Path::new(file_path);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("无法解析绝对路径: {}", e))?
            .join(p)
    };
    // 规范化，避免 ./ 与 .. 干扰 Session Manager 的路径匹配
    Ok(abs
        .canonicalize()
        .unwrap_or(abs)
        .to_string_lossy()
        .to_string())
}

/// in-process MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT)
#[cfg(windows)]
fn move_file_ex_delay_reboot(abs_path: &str) -> bool {
    use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
    use windows::core::PCWSTR;

    let wide: Vec<u16> = abs_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe { MoveFileExW(PCWSTR(wide.as_ptr()), None, MOVEFILE_DELAY_UNTIL_REBOOT).is_ok() }
}

#[cfg(not(windows))]
fn move_file_ex_delay_reboot(_abs_path: &str) -> bool {
    false
}

/// PowerShell 提权写 PendingFileRenameOperations 注册表（MultiString）
/// 每个待删文件占两项：[\\??\C:\full\path, ""]（空串表示删除）
fn schedule_boot_cleanup_via_powershell(abs_path: &str) -> Result<String, String> {
    // PendingFileRenameOperations 约定使用 \??\ 前缀的 NT 路径
    let nt_path = format!("\\??\\{}", abs_path).replace('\'', "''");

    let ps = format!(
        "Add-Type -AssemblyName Microsoft.Win32.Registry; \
         $k=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\\CurrentControlSet\\Control\\Session Manager',$true); \
         if(-not $k){{ Write-Output 'REG_FAIL'; exit 1 }}; \
         $cur=$k.GetValue('PendingFileRenameOperations',$null); \
         $list=New-Object System.Collections.ArrayList; \
         if($cur){{ foreach($v in $cur){{ [void]$list.Add([string]$v) }} }}; \
         [void]$list.Add('{0}'); [void]$list.Add(''); \
         $k.SetValue('PendingFileRenameOperations',$list.ToArray(),[Microsoft.Win32.RegistryValueKind]::MultiString); \
         $k.Close(); Write-Output 'REG_OK'",
        nt_path
    );

    run_powershell_elevated(&ps)?;
    Ok("registry".to_string())
}

// ==================== 不重启而清除 ====================

/// 使用 Windows Restart Manager 定位占用指定文件的全部进程 PID
pub fn find_processes_holding_file(file_path: &str) -> Vec<u32> {
    #[cfg(windows)]
    {
        use windows::core::{PCWSTR, PWSTR};
        use windows::Win32::System::RestartManager::{
            RmEndSession, RmGetList, RmRegisterResources, RmStartSession,
            CCH_RM_SESSION_KEY, RM_PROCESS_INFO,
        };

        let file_path_wide: Vec<u16> = file_path.encode_utf16().chain(Some(0)).collect();

        unsafe {
            let mut session: u32 = 0;
            let mut session_key = [0u16; (CCH_RM_SESSION_KEY + 1) as usize];
            if RmStartSession(&mut session, 0, PWSTR(session_key.as_mut_ptr())).0 != 0 {
                return Vec::new();
            }

            let filenames = [PCWSTR(file_path_wide.as_ptr())];
            if RmRegisterResources(session, Some(&filenames), None, None).0 != 0 {
                let _ = RmEndSession(session);
                return Vec::new();
            }

            let mut proc_info_needed: u32 = 0;
            let mut proc_info_count: u32 = 0;
            let mut reboot_reasons: u32 = 0;

            // 第一次调用获取所需数量
            let _ = RmGetList(
                session,
                &mut proc_info_needed,
                &mut proc_info_count,
                None,
                &mut reboot_reasons,
            );

            if proc_info_needed == 0 {
                let _ = RmEndSession(session);
                return Vec::new();
            }

            let mut proc_infos: Vec<RM_PROCESS_INFO> =
                vec![std::mem::zeroed(); proc_info_needed as usize];
            proc_info_count = proc_info_needed;
            let result = RmGetList(
                session,
                &mut proc_info_needed,
                &mut proc_info_count,
                Some(proc_infos.as_mut_ptr()),
                &mut reboot_reasons,
            );

            let pids = if result.0 == 0 && proc_info_count > 0 {
                proc_infos
                    .iter()
                    .take(proc_info_count as usize)
                    .map(|info| info.Process.dwProcessId)
                    .filter(|pid| *pid != 0 && *pid != std::process::id())
                    .collect()
            } else {
                Vec::new()
            };

            let _ = RmEndSession(session);
            pids
        }
    }

    #[cfg(not(windows))]
    {
        let _ = file_path;
        Vec::new()
    }
}

/// 检查进程是否仍存活
fn process_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};
        unsafe {
            match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
                Ok(h) => {
                    let _ = CloseHandle(h);
                    true
                }
                Err(_) => false,
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        false
    }
}

/// 分级终止单个进程：R3 TerminateProcess → AVGuard(AVModel) → 驱动管道 → UAC PowerShell
fn kill_pid_escalated(pid: u32) -> bool {
    // 进程可能已退出
    if !process_alive(pid) {
        return true;
    }

    // 1. R3 TerminateProcess（无需提权）
    if crate::kill_process(pid).is_ok() {
        if wait_process_exit(pid, 3) {
            return true;
        }
    }

    // 2. AVGuard 独立防护进程（管理员 + SeDebugPrivilege）
    #[cfg(not(feature = "ms_store"))]
    if crate::kill_process_via_avmodel(pid) {
        if wait_process_exit(pid, 3) {
            return true;
        }
    }

    // 3. 内核驱动命令管道（最高权限）
    #[cfg(not(feature = "ms_store"))]
    if crate::kill_process_via_driver_internal(pid).is_ok() {
        if wait_process_exit(pid, 3) {
            return true;
        }
    }

    // 4. UAC PowerShell Stop-Process -Force（最后一搏）
    kill_pid_via_powershell_uac(pid) && wait_process_exit(pid, 5)
}

/// 等待进程退出（最多约 timeout_sec 秒）
fn wait_process_exit(pid: u32, timeout_sec: u64) -> bool {
    for _ in 0..timeout_sec.saturating_mul(5) {
        if !process_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// UAC PowerShell 按 PID 强制结束进程
fn kill_pid_via_powershell_uac(pid: u32) -> bool {
    let ps = format!(
        "Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue; if(Get-Process -Id {pid} -ErrorAction SilentlyContinue){{ 'KILL_FAIL' }} else {{ 'KILL_OK' }}",
        pid = pid
    );
    run_powershell_elevated(&ps).is_ok()
}

/// 不重启而清除：定位占用进程 → 分级终止 → 重试删除原文件
///
/// 返回被成功结束的进程 PID 列表；文件已被删除视为成功。
pub fn clear_without_restart(file_path: &str) -> Result<Vec<u32>, String> {
    let abs_path = absolute_path(file_path)?;
    let path = Path::new(&abs_path);

    // 文件已不存在 → 视为清除成功
    if !path.exists() {
        println!("[ActiveThreat] 文件已不存在，无需清除: {}", abs_path);
        return Ok(Vec::new());
    }

    // 1. 定位占用进程
    let pids = find_processes_holding_file(&abs_path);
    println!(
        "[ActiveThreat] 占用文件的进程 {} 个: {:?} (path={})",
        pids.len(),
        pids,
        abs_path
    );

    // 2. 分级终止占用进程
    let mut killed = Vec::new();
    for pid in pids {
        if kill_pid_escalated(pid) {
            killed.push(pid);
        } else {
            println!("[ActiveThreat] 无法终止进程 PID={}（可能为受保护系统进程）", pid);
        }
    }

    // 3. 等待句柄释放并重试删除（最多约 3 秒）
    for attempt in 0..15 {
        if !path.exists() {
            println!("[ActiveThreat] 原文件已消失，清除成功");
            return Ok(killed);
        }
        match std::fs::remove_file(path) {
            Ok(()) => {
                println!("[ActiveThreat] 重试删除成功（第 {} 次尝试）: {}", attempt + 1, abs_path);
                return Ok(killed);
            }
            Err(e) if is_access_denied_error(&e.to_string()) => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => return Err(format!("删除失败: {}", e)),
        }
    }

    Err("文件仍被占用，无法在不重启的情况下清除；建议使用开机时清除".to_string())
}

// ==================== 重启 ====================

/// 立即重启系统（shutdown /r /t 0，经 PowerShell 提权执行）
pub fn restart_now() -> Result<(), String> {
    run_powershell_elevated("shutdown.exe /r /t 0")
}

// ==================== PowerShell 提权辅助 ====================

/// 通过 ShellExecuteW(runas) 以管理员权限执行 PowerShell 命令（隐藏窗口）
///
/// 已提权时直接执行不弹 UAC；未提权时弹出 UAC 确认框。
/// ShellExecuteW 返回 >32 仅表示"启动成功"（fire-and-forget，不等待结果），
/// 因此本函数只保证命令被提交执行。
fn run_powershell_elevated(command: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SHOW_WINDOW_CMD;
        use windows::core::PCWSTR;

        let full_cmd = format!(
            "-NoProfile -NonInteractive -WindowStyle Hidden -Command \"{}\"",
            command
        );
        let full_wide: Vec<u16> = full_cmd.encode_utf16().chain(std::iter::once(0)).collect();
        let runas: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();
        let powershell: Vec<u16> = "powershell.exe".encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let result = ShellExecuteW(
                None,
                PCWSTR(runas.as_ptr()),
                PCWSTR(powershell.as_ptr()),
                PCWSTR(full_wide.as_ptr()),
                None,
                SHOW_WINDOW_CMD(0), // SW_HIDE
            );
            if result.0 as isize > 32 {
                println!("[ActiveThreat] PowerShell 提权命令已提交: {}", command);
                Ok(())
            } else {
                Err(format!(
                    "PowerShell 提权执行失败（用户可能取消了 UAC）, code={:?}",
                    result.0
                ))
            }
        }
    }

    #[cfg(not(windows))]
    {
        let _ = command;
        Err("仅 Windows 平台支持".to_string())
    }
}

// ==================== 弹窗窗口（active-threat-alert / reboot-countdown） ====================

/// 显示"发现活动内存威胁"处置窗口（卡巴斯基风格，右下角弹出）
#[tauri::command]
pub fn show_active_threat_alert(app: tauri::AppHandle, file_path: String, threat_name: String) {
    println!(
        "[ActiveThreat] 显示活动内存威胁处置窗口: {} (threat={})",
        file_path, threat_name
    );

    let file_name = Path::new(&file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&file_path)
        .to_string();

    let payload = serde_json::json!({
        "filePath": file_path,
        "fileName": file_name,
        "threatName": threat_name,
    });

    // 缓存最近一次数据，供前端页面加载后主动拉取（防止 emit 事件丢失）
    *PENDING_ACTIVE_THREAT_DATA.lock().unwrap() = Some(payload.clone());

    // 全部窗口操作移入独立 std::thread，避免占用 tokio worker / 阻塞主线程
    std::thread::spawn(move || {
        let _guard = ACTIVE_THREAT_ALERT_MUTEX.lock().unwrap();

        let window = match app.get_webview_window("active-threat-alert") {
            Some(w) => w,
            None => {
                eprintln!("[ActiveThreat] active-threat-alert 窗口不存在（预创建配置下不应发生）");
                return;
            }
        };

        // emit 数据作为唯一数据通道，重试覆盖页面监听器晚注册的情况
        for attempt in 0..5 {
            if window.emit("active-threat-data", payload.clone()).is_ok() {
                if attempt > 0 {
                    println!("[ActiveThreat] emit retried (attempt {})", attempt + 1);
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(150));
        }

        // 右下角弹出（与文件防护告警一致）
        crate::win32_show_window(&window, 400.0, 400.0, true);
        println!("[ActiveThreat] 处置窗口已显示: {}", file_path);
    });
}

/// 触发"活动内存威胁"处置窗口（供隔离 API 等模块内部调用）
pub fn trigger_active_threat_alert(app: AppHandle, file_path: String, threat_name: String) {
    show_active_threat_alert(app, file_path, threat_name);
}

/// 关闭（隐藏复用）活动威胁处置窗口
#[tauri::command]
pub fn close_active_threat_alert_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("active-threat-alert") {
        crate::win32_hide_window(&window);
        println!("[ActiveThreat] 处置窗口已隐藏（复用，不销毁）");
    }
    Ok(())
}

/// 获取最近一次待显示的活动威胁弹窗数据（前端兜底拉取）
#[tauri::command]
pub fn get_pending_active_threat_data() -> Option<serde_json::Value> {
    PENDING_ACTIVE_THREAT_DATA.lock().unwrap().clone()
}

/// 显示 60 秒重启倒计时窗口（居中）
#[tauri::command]
pub fn show_reboot_countdown(app: tauri::AppHandle) {
    println!("[ActiveThreat] 显示重启倒计时窗口");

    std::thread::spawn(move || {
        let _guard = ACTIVE_THREAT_ALERT_MUTEX.lock().unwrap();

        if let Some(window) = app.get_webview_window("reboot-countdown") {
            // 通知页面开始倒计时（页面已注册 listener；emit 失败则页面自行启动倒计时）
            let _ = window.emit("reboot-countdown-start", serde_json::json!({ "seconds": 60 }));
            crate::win32_show_window(&window, 360.0, 220.0, false);
            println!("[ActiveThreat] 重启倒计时窗口已显示");
        } else {
            eprintln!("[ActiveThreat] reboot-countdown 窗口不存在（预创建配置下不应发生）");
        }
    });
}

/// 关闭（隐藏复用）重启倒计时窗口
#[tauri::command]
pub fn close_reboot_countdown_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("reboot-countdown") {
        crate::win32_hide_window(&window);
        println!("[ActiveThreat] 重启倒计时窗口已隐藏");
    }
    Ok(())
}

// ==================== Tauri 命令 ====================

/// 开机时清除：标记文件下次重启删除（命令封装）
/// async：避免阻塞主线程（内部可能触发 UAC PowerShell）
#[tauri::command]
pub async fn schedule_boot_cleanup_command(file_path: String) -> Result<serde_json::Value, String> {
    let method = schedule_boot_cleanup(&file_path)?;
    Ok(serde_json::json!({
        "success": true,
        "method": method,
    }))
}

/// 不重启而清除：定位并终止占用进程后重试删除（命令封装）
/// async：内部会阻塞等待进程退出（最多数秒），必须脱离主线程
#[tauri::command]
pub async fn clear_without_restart_command(file_path: String) -> Result<serde_json::Value, String> {
    let killed_pids = clear_without_restart(&file_path)?;
    Ok(serde_json::json!({
        "success": true,
        "killed_pids": killed_pids,
    }))
}

/// 立即重启系统（命令封装）
#[tauri::command]
pub async fn restart_now_command() -> Result<(), String> {
    restart_now()
}
