//! WMI 事件驱动的进程监控模块
//!
//! 订阅 Win32_ProcessStartTrace 事件，有新进程启动时 Windows 主动通知，
//! 无需轮询，空闲时零 CPU 占用。
//!
//! **沙箱拦截优先**：每个新进程先经过 `sandbox_analysis::check_and_intercept_process`
//! 检查（白名单→排除→可执行→监控目录→签名），被拦截的进程不会发送到前端，
//! 也不会进入后续的扫描流程。沙箱检查是所有防护中最先执行的。

use serde::Deserialize;
use std::os::windows::process::CommandExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tauri::Emitter;

use crate::sandbox_analysis;

/// 隐藏窗口标志
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// WMI Win32_ProcessStartTrace 事件结构
#[derive(Deserialize, Debug)]
struct ProcessStartTrace {
    ProcessId: u32,
    ProcessName: String,
    #[allow(dead_code)]
    ParentProcessId: Option<u32>,
    #[allow(dead_code)]
    SessionId: Option<u32>,
}

/// 进程启动事件，发送到前端
#[derive(Clone, serde::Serialize)]
pub struct ProcessStartEvent {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
}

/// WMI 进程监控器
pub struct ProcessWatcher {
    running: Arc<AtomicBool>,
}

impl ProcessWatcher {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 启动 WMI 进程事件监听
    /// 在后台线程中运行，订阅 Win32_ProcessStartTrace
    pub fn start(&self, app_handle: tauri::AppHandle) {
        if self.running.load(Ordering::SeqCst) {
            return;
        }
        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();
        std::thread::spawn(move || {
            println!("[ProcessWatcher] Starting WMI process event subscription...");

            // 初始化 COM
            unsafe {
                let _ = windows::Win32::System::Com::CoInitializeEx(
                    None,
                    windows::Win32::System::Com::COINIT_MULTITHREADED,
                );
            }

            // 创建 WMI 连接
            match wmi::WMIConnection::new(wmi::COMLibrary::new().expect("COM init")) {
                Ok(wmi_con) => {
                    // 订阅 Win32_ProcessStartTrace 事件（事件驱动，零 CPU）
                    match wmi_con.notification::<ProcessStartTrace>() {
                        Ok(events) => {
                            println!("[ProcessWatcher] WMI subscription active, waiting for process events...");

                            for event_result in events {
                                if !running.load(Ordering::SeqCst) {
                                    break;
                                }

                                if let Ok(evt) = event_result {
                                    let pid = evt.ProcessId;
                                    let name = evt.ProcessName;

                                    // 获取进程完整路径
                                    let path = get_process_path(pid);

                                    // ★基础防护：AVIC 黑名单直接拦截★
                                    // 文件在 AVIC 情报中心被拉黑 → 终止进程并提示，不送沙箱。
                                    // 职责划分：AVIC 拦截归基础防护（这里）和驱动防护，
                                    // 沙箱分析对黑名单文件不采取任何操作。
                                    if let Some(ref p) = path {
                                        if let Some((threat_name, _family)) = crate::avic_client::check_file(p) {
                                            println!("[ProcessWatcher] AVIC 命中恶意，基础防护拦截: {} threat={} (PID={})", p, threat_name, pid);
                                            crate::diag_info!("[ProcessWatcher] AVIC 命中恶意，基础防护拦截: {}", p);
                                            // 终止进程
                                            #[cfg(not(feature = "ms_store"))]
                                            {
                                                crate::kill_process_via_avmodel(pid);
                                            }
                                            let _ = std::process::Command::new("taskkill")
                                                .args(["/F", "/T", "/PID", &pid.to_string()])
                                                .creation_flags(CREATE_NO_WINDOW)
                                                .output();
                                            // 提示用户
                                            let _ = app_handle.emit("avic-blocked", serde_json::json!({
                                                "path": p,
                                                "threat": threat_name,
                                                "source": "AVIC",
                                                "pid": pid,
                                            }));
                                            continue;
                                        }
                                    }

                                    // ★沙箱拦截——所有防护中沙箱相关逻辑最先执行★
                                    // 白名单检查不耗时，签名检查最耗时放最后
                                    if let Some(ref p) = path {
                                        if sandbox_analysis::check_and_intercept_process(p, pid, &app_handle) {
                                            // 已被沙箱拦截，不发送到前端，跳过后续防护
                                            continue;
                                        }
                                    }

                                    let event = ProcessStartEvent {
                                        pid,
                                        name,
                                        path,
                                    };

                                    // 发送到前端（沙箱检查已通过）
                                    let _ = app_handle.emit("process-started", &event);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[ProcessWatcher] WMI notification failed: {}", e);
                            // 回退到轮询模式
                            run_fallback_polling(running, app_handle);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[ProcessWatcher] WMI connection failed: {}", e);
                    // 回退到轮询模式
                    run_fallback_polling(running, app_handle);
                }
            }

            unsafe {
                let _ = windows::Win32::System::Com::CoUninitialize();
            }
            println!("[ProcessWatcher] Stopped");
        });
    }

    /// 停止监控
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// 回退方案：使用 EnumProcesses 快速轮询（当 WMI 不可用时）
fn run_fallback_polling(running: Arc<AtomicBool>, app_handle: tauri::AppHandle) {
    println!("[ProcessWatcher] Running fallback polling mode (500ms)");
    
    let mut known_pids: std::collections::HashSet<u32> = std::collections::HashSet::new();

    // 首次扫描填充已知 PID
    if let Ok(pids) = enum_pids() {
        known_pids.extend(pids);
    }

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(500));

        if let Ok(pids) = enum_pids() {
                    for &pid in &pids {
                        if !known_pids.contains(&pid) {
                            // 新进程
                            let name = get_process_name(pid).unwrap_or_default();
                            let path = get_process_path(pid);

                            // ★基础防护：AVIC 黑名单直接拦截★
                            if let Some(ref p) = path {
                                if let Some((threat_name, _family)) = crate::avic_client::check_file(p) {
                                    println!("[ProcessWatcher] AVIC 命中恶意，基础防护拦截(fallback): {} threat={} (PID={})", p, threat_name, pid);
                                    crate::diag_info!("[ProcessWatcher] AVIC 命中恶意，基础防护拦截(fallback): {}", p);
                                    #[cfg(not(feature = "ms_store"))]
                                    {
                                        crate::kill_process_via_avmodel(pid);
                                    }
                                    let _ = std::process::Command::new("taskkill")
                                        .args(["/F", "/T", "/PID", &pid.to_string()])
                                        .creation_flags(CREATE_NO_WINDOW)
                                        .output();
                                    let _ = app_handle.emit("avic-blocked", serde_json::json!({
                                        "path": p,
                                        "threat": threat_name,
                                        "source": "AVIC",
                                        "pid": pid,
                                    }));
                                    continue;
                                }
                            }

                            // ★沙箱拦截——所有防护中沙箱相关逻辑最先执行★
                            if let Some(ref p) = path {
                                if sandbox_analysis::check_and_intercept_process(p, pid, &app_handle) {
                                    // 已被沙箱拦截，不发送到前端
                                    continue;
                                }
                            }

                            let event = ProcessStartEvent {
                                pid,
                                name,
                                path,
                            };
                            let _ = app_handle.emit("process-started", &event);
                        }
                    }
                    known_pids = pids.into_iter().collect();
                }
    }
}

/// 使用 EnumProcesses 快速枚举 PID（轻量，不涉及 OpenProcess）
fn enum_pids() -> Result<Vec<u32>, String> {
    unsafe {
        use windows::Win32::System::ProcessStatus::EnumProcesses;
        let mut process_ids = [0u32; 4096];
        let mut bytes_returned = 0u32;
        if EnumProcesses(
            process_ids.as_mut_ptr(),
            (process_ids.len() * std::mem::size_of::<u32>()) as u32,
            &mut bytes_returned,
        )
        .is_ok()
        {
            let num = bytes_returned as usize / std::mem::size_of::<u32>();
            Ok(process_ids[..num]
                .iter()
                .filter(|&&p| p != 0)
                .copied()
                .collect())
        } else {
            Err("EnumProcesses failed".to_string())
        }
    }
}

/// 获取进程名（通过 Toolhelp32 snapshot，无需 OpenProcess）
fn get_process_name(pid: u32) -> Option<String> {
    unsafe {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
            PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        };
        use windows::Win32::Foundation::CloseHandle;

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == pid {
                    let name = String::from_utf16_lossy(&entry.szExeFile)
                        .trim_end_matches('\0')
                        .to_string();
                    let _ = CloseHandle(snapshot);
                    return Some(name);
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
        None
    }
}

/// 获取进程完整路径（需要 OpenProcess）
fn get_process_path(pid: u32) -> Option<String> {
    unsafe {
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };
        use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
        use windows::Win32::Foundation::CloseHandle;

        if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
            let mut path_buf = [0u16; 520];
            let len = GetModuleFileNameExW(handle, None, &mut path_buf);
            let _ = CloseHandle(handle);
            if len > 0 {
                let path = String::from_utf16_lossy(&path_buf[..len as usize]);
                return Some(path);
            }
        }
        None
    }
}
