//! 脚本防护模块
//!
//! 使用 WMI 轮询查询 Win32_Process 表，监控脚本解释器进程的命令行，
//! 一旦发现有危险命令执行，立即终止进程并弹出系统通知。
//! 使用 WMI 直接查询而非 wmic 子进程，性能远优于旧版。

use serde::Deserialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tauri::AppHandle;

/// 全局脚本防护控制标志
static SCRIPT_PROTECTION_RUNNING: AtomicBool = AtomicBool::new(false);
/// 防护状态
static SCRIPT_PROTECTION_ENABLED: AtomicBool = AtomicBool::new(false);

/// 脚本解释器进程名列表（用于 WQL WHERE 子句）
const SCRIPT_INTERPRETER_NAMES: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
];

/// 危险命令模式列表（小写匹配）
const DANGEROUS_PATTERNS: &[(&str, &str)] = &[
    // 常见的恶意下载执行
    ("downloadfile", "远程下载并执行代码"),
    ("invoke-webrequest", "远程下载 PowerShell"),
    ("iwr", "远程下载 PowerShell 简写"),
    ("wget", "远程下载文件"),
    ("curl", "远程下载文件"),
    ("start-bitstransfer", "BITS 后台下载"),
    ("bitsadmin /transfer", "BITS 后台下载"),
    ("certutil -urlcache", "CertUtil 远程下载"),
    ("certutil -split", "CertUtil 分块下载"),
    // 编码执行
    ("-enc", "Base64 编码执行"),
    ("-encodedcommand", "Base64 编码命令执行"),
    ("-e ", "编码参数执行"),
    ("frombase64string", "Base64 解码执行"),
    // 反弹 shell / 远程连接
    ("reverse", "反弹 Shell"),
    ("bind", "绑定 Shell"),
    ("new-object system.net.sockets.tcpclient", "TCP 反弹连接"),
    ("invoke-expression", "表达式动态执行"),
    ("iex", "Invoke-Expression 简写"),
    // 进程注入
    ("invoke-cimethod", "WMI 远程执行"),
    ("invoke-wmimethod", "WMI 远程执行"),
    ("createobject", "COM 对象创建"),
    // 权限提升
    ("bypass", "绕过执行策略"),
    ("-exec bypass", "绕过执行策略"),
    ("unrestricted", "无限制执行策略"),
    ("add-type", "动态编译执行"),
    // 敏感操作
    ("stop-process", "终止进程操作"),
    ("remove-item", "删除文件操作"),
    ("rm ", "删除文件"),
    ("del ", "删除文件"),
    ("format-volume", "格式化卷"),
    ("clear-disk", "清除磁盘"),
    // 持久化
    ("register-scheduledjob", "注册计划任务持久化"),
    ("new-service", "创建服务"),
    ("schtasks /create", "创建计划任务"),
    ("add-mp-preference", "修改 Windows Defender 配置"),
    ("set-mppreference", "修改 Windows Defender 配置"),
    // 系统配置篡改
    ("reg add", "注册表添加"),
    ("reg delete", "注册表删除"),
    ("bcdedit", "启动配置修改"),
    ("takeown", "获取文件所有权"),
    ("icacls", "修改文件权限"),
    ("attrib -r -s -h", "去除文件属性隐藏"),
];

/// WMI Win32_Process 结构
#[derive(Deserialize, Debug)]
struct Win32Process {
    ProcessId: u32,
    Name: Option<String>,
    CommandLine: Option<String>,
}

/// 获取脚本防护启用状态
pub fn is_script_protection_enabled() -> bool {
    SCRIPT_PROTECTION_ENABLED.load(Ordering::Relaxed)
}

/// 获取脚本防护运行状态
pub fn is_script_protection_running() -> bool {
    SCRIPT_PROTECTION_RUNNING.load(Ordering::Relaxed)
}

/// 启动脚本防护监控（WMI 轮询 Win32_Process 表）
#[tauri::command]
pub fn start_script_protection(app: AppHandle) -> Result<(), String> {
    if SCRIPT_PROTECTION_RUNNING.swap(true, Ordering::SeqCst) {
        return Ok(()); // 已在运行
    }
    SCRIPT_PROTECTION_ENABLED.store(true, Ordering::Relaxed);

    std::thread::spawn(move || {
        println!("[ScriptProtection] - Started");

        // 初始化 COM（每个线程只需一次）
        unsafe {
            let _ = windows::Win32::System::Com::CoInitializeEx(
                None,
                windows::Win32::System::Com::COINIT_MULTITHREADED,
            );
        }

        // 已通知过的进程缓存，避免重复通知
        let mut notified_pids: std::collections::HashSet<u32> = std::collections::HashSet::new();

        while SCRIPT_PROTECTION_RUNNING.load(Ordering::SeqCst) {
            // 每次循环创建新的 WMI 连接，避免连接过期
            match poll_script_processes(&app, &mut notified_pids) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("[ScriptProtection] - Poll error: {}", e);
                }
            }

            // 每 2 秒轮询一次
            for _ in 0..20 {
                if !SCRIPT_PROTECTION_RUNNING.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }

        println!("[ScriptProtection] - Stopped");
    });

    Ok(())
}

/// 停止脚本防护监控
#[tauri::command]
pub fn stop_script_protection() -> Result<(), String> {
    SCRIPT_PROTECTION_RUNNING.store(false, Ordering::SeqCst);
    SCRIPT_PROTECTION_ENABLED.store(false, Ordering::Relaxed);
    println!("[ScriptProtection] - Stop requested");
    Ok(())
}

/// 轮询查询 Win32_Process 表，检查脚本解释器进程的命令行
fn poll_script_processes(
    app: &AppHandle,
    notified_pids: &mut std::collections::HashSet<u32>,
) -> Result<(), String> {
    // 构建 WQL 查询条件
    let name_conditions: Vec<String> = SCRIPT_INTERPRETER_NAMES
        .iter()
        .map(|n| format!("Name = '{}'", n))
        .collect();
    let wql = format!(
        "SELECT ProcessId, Name, CommandLine FROM Win32_Process WHERE {}",
        name_conditions.join(" OR ")
    );

    // 创建 WMI 连接并执行查询
    let wmi_con = wmi::WMIConnection::new(
        wmi::COMLibrary::new().map_err(|e| format!("COM init failed: {:?}", e))?
    ).map_err(|e| format!("WMI connection failed: {:?}", e))?;

    let processes: Vec<Win32Process> = wmi_con
        .raw_query(&wql)
        .map_err(|e| format!("WMI query failed: {:?}", e))?;

    for proc in processes {
        let pid = proc.ProcessId;

        // 跳过已通知过的进程
        if notified_pids.contains(&pid) {
            continue;
        }

        // 获取命令行
        let cmdline = match proc.CommandLine {
            Some(ref c) => c.clone(),
            None => continue,
        };

        let cmdline_lower = cmdline.to_lowercase();

        // 跳过自身的进程
        if cmdline_lower.contains("xiguasecurity") {
            continue;
        }

        // 跳过没有命令行的纯交互式 shell（如直接打开的 cmd / powershell 窗口）
        // 纯交互式 shell 的 CommandLine 通常就是 exe 路径本身
        let exe_name_lower = proc.Name.as_deref().unwrap_or("").to_lowercase();
        if cmdline_lower.trim_matches('"') == exe_name_lower.trim_matches('"')
            || cmdline_lower.trim() == exe_name_lower.trim()
        {
            continue;
        }

        // 检查是否有危险模式
        if let Some(threat) = check_dangerous_patterns(&cmdline_lower) {
            println!(
                "[ScriptProtection] - THREAT: {} (PID={}) cmdline={}",
                proc.Name.as_deref().unwrap_or("unknown"), pid, cmdline
            );

            // 终止进程
            kill_process(pid);

            // 发送系统通知
            let process_name = proc.Name.as_deref().unwrap_or("unknown");
            let display_cmdline = truncate_cmdline(&cmdline, 200);
            send_native_notification(
                app,
                "恶意脚本已拦截",
                &format!("{} (PID: {})", process_name, pid),
                &display_cmdline,
                threat,
            );

            notified_pids.insert(pid);
        }
    }

    Ok(())
}

/// 检查命令行是否匹配危险模式
fn check_dangerous_patterns(cmdline_lower: &str) -> Option<&'static str> {
    for &(pattern, description) in DANGEROUS_PATTERNS {
        if cmdline_lower.contains(pattern) {
            return Some(description);
        }
    }
    None
}

/// 终止指定 PID 的进程
fn kill_process(pid: u32) {
    unsafe {
        use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
        use windows::Win32::Foundation::CloseHandle;

        if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) {
            let _ = TerminateProcess(handle, 1);
            let _ = CloseHandle(handle);
        }
    }
}

/// 截断过长的命令行，保证通知可读
fn truncate_cmdline(cmdline: &str, max_len: usize) -> String {
    let trimmed = cmdline.trim();
    if trimmed.len() <= max_len {
        trimmed.to_string()
    } else {
        format!("{}...", &trimmed[..max_len])
    }
}

/// 发送 Windows 原生系统通知
fn send_native_notification(
    app: &AppHandle,
    title: &str,
    file_name: &str,
    file_path: &str,
    threat: &str,
) {
    use crate::notification::{NotificationOptions, NotificationType, show_security_notification};

    let options = NotificationOptions::new(NotificationType::Threat, title, threat)
        .with_file(file_name, file_path)
        .with_action("查看详情", "action=open_script_protection")
        .with_action("忽略", "action=dismiss");

    if let Err(e) = show_security_notification(app, options) {
        eprintln!("[ScriptProtection] - Notification failed: {}", e);
    }
}
