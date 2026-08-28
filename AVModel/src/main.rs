//! AVGuard — 独立防护进程
//!
//! 以管理员权限运行，提供多种进程终止方式，作为驱动拦截失效时的后备防线。
//! 通过命名管道 `\\.\pipe\AVGuardPipe` 与主程序通信。
//!
//! 终止方法（逐级升级）：
//! 1. TerminateProcess — 常规 R3 API 终止
//! 2. TerminateThread — 枚举并终止所有线程（绕过进程级 hook）
//! 3. CreateRemoteThread + ExitProcess — 远程线程注入（绕过 TerminateProcess hook）
//! 4. NtTerminateProcess — 直接调用 ntdll（绕过用户态 hook / 部分 Ob 回调）
//!
//! 进程枚举（内存活动威胁扫描）：
//! `list_processes` — 纯 R3 Toolhelp32Snapshot 枚举全部进程，
//! 以提权 + SeDebugPrivilege 打开进程并 QueryFullProcessImageNameW 获取完整镜像路径，
//! 覆盖主程序（普通权限）无法查询的提权进程。主程序据此逐个扫描镜像文件。

#![cfg(windows)]

use std::io;
use std::ptr;

// Melix HIPS 命名管道客户端（管理员桥接层）
mod melix_ipc;
use melix_ipc::{IpcMessageType, VerdictAction, MelixClient};

use serde::{Deserialize, Serialize};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LUID,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW,
    SE_PRIVILEGE_ENABLED, SECURITY_ATTRIBUTES, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY,
    LUID_AND_ATTRIBUTES, TOKEN_PRIVILEGES,
    SECURITY_DESCRIPTOR, SetSecurityDescriptorDacl,
    GetTokenInformation, TokenElevation,
};
use windows::Win32::Storage::FileSystem::{
    ReadFile, WriteFile, FlushFileBuffers, FILE_FLAGS_AND_ATTRIBUTES,
};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, ConnectNamedPipe, PIPE_TYPE_MESSAGE, PIPE_READMODE_MESSAGE, PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetCurrentProcess, GetCurrentProcessId, OpenProcess,
    OpenProcessToken, OpenThread, TerminateProcess, TerminateThread,
    THREAD_TERMINATE, PROCESS_TERMINATE,
    PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_WRITE, WaitForSingleObject,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next,
    TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

const PIPE_NAME: &str = r"\\.\pipe\AVGuardPipe";
const PIPE_BUFFER_SIZE: u32 = 65536;
const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
const FILE_FLAG_OVERLAPPED: u32 = 0x40000000;

// ==================== 通信协议 ====================

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "cmd")]
enum Request {
    #[serde(rename = "ping")]
    Ping,

    #[serde(rename = "kill")]
    Kill { pid: u32 },

    #[serde(rename = "kill_batch")]
    KillBatch { pids: Vec<u32> },

    #[serde(rename = "kill_by_name")]
    KillByName { name: String },

    #[serde(rename = "list_processes")]
    ListProcesses { offset: u32, count: u32 },

    #[serde(rename = "shutdown")]
    Shutdown,

    // ===== Melix HIPS 端点防护桥接命令（管理员中转，主程序非管理员无法直连 Melix.Control） =====
    /// 查询 Melix.Service 是否运行（命名管道是否可用）
    #[serde(rename = "melix_running")]
    MelixRunning,

    /// 获取防护规则列表
    #[serde(rename = "melix_rules")]
    MelixRules,

    /// 新增防护规则
    #[serde(rename = "melix_add_rule")]
    MelixAddRule {
        actor_path: Option<String>,
        r#type: Option<String>,
        target_pattern: Option<String>,
        action: String,
        note: Option<String>,
    },

    /// 删除防护规则
    #[serde(rename = "melix_delete_rule")]
    MelixDeleteRule { rule_id: String },

    /// 获取运行时设置
    #[serde(rename = "melix_settings_get")]
    MelixSettingsGet,

    /// 更新运行时设置
    #[serde(rename = "melix_settings_set")]
    MelixSettingsSet { settings: serde_json::Value },

    /// 获取文件信任列表
    #[serde(rename = "melix_trust_list")]
    MelixTrustList,

    /// 新增文件信任
    #[serde(rename = "melix_add_trust")]
    MelixAddTrust { actor_path: String, note: Option<String> },

    /// 移除文件信任
    #[serde(rename = "melix_remove_trust")]
    MelixRemoveTrust { rule_id: String },

    /// 用户裁决回复
    #[serde(rename = "melix_prompt")]
    MelixPrompt { event_id: String, action: String, remember: bool },
}

/// 进程条目（list_processes 响应）
#[derive(Serialize, Deserialize, Debug, Clone)]
struct ProcessInfo {
    pid: u32,
    parent_pid: u32,
    name: String,
    /// 镜像完整路径（无法打开/受保护进程为 None）
    path: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Response {
    ok: bool,
    msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    killed: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    killed_pids: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    processes: Option<Vec<ProcessInfo>>,
    /// Melix 桥接响应数据（规则/设置/信任列表，由调用方解析）
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

impl Response {
    fn ok(msg: &str) -> Self {
        Self { ok: true, msg: msg.to_string(), method: None, killed: None, failed: None, killed_pids: None, total: None, offset: None, processes: None, data: None }
    }
    fn ok_with_method(msg: &str, method: &str) -> Self {
        Self { ok: true, msg: msg.to_string(), method: Some(method.to_string()), killed: None, failed: None, killed_pids: None, total: None, offset: None, processes: None, data: None }
    }
    fn ok_with_data(msg: &str, data: serde_json::Value) -> Self {
        Self { ok: true, msg: msg.to_string(), method: None, killed: None, failed: None, killed_pids: None, total: None, offset: None, processes: None, data: Some(data) }
    }
    fn err(msg: &str) -> Self {
        Self { ok: false, msg: msg.to_string(), method: None, killed: None, failed: None, killed_pids: None, total: None, offset: None, processes: None, data: None }
    }
}

// ==================== 文件日志 ====================

use std::io::Write;

fn log_file_path() -> std::path::PathBuf {
    // 日志写到 TEMP 目录
    let tmp = std::env::var_os("TEMP").unwrap_or_else(|| std::ffi::OsString::from("C:\\"));
    std::path::PathBuf::from(&tmp).join("AVGuard.log")
}

fn log_to_file(msg: &str) {
    use std::fs::OpenOptions;
    let path = log_file_path();
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let _ = writeln!(f, "[{}] {}", now, msg);
    }
    println!("{}", msg);
}

// ==================== 主函数 ====================

/// 单实例保护：枚举所有 AVGuard 进程，杀掉除当前进程外的其他实例。
/// 解决多 AVGuard 并发导致 Melix 单连接管道冲突(error 121)与同名事件管道创建失败的问题。
fn ensure_single_instance() {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::Foundation::CloseHandle;
    let my_pid = unsafe { GetCurrentProcessId() };
    unsafe {
        if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let name = String::from_utf16_lossy(&entry.szExeFile)
                        .trim_end_matches('\0')
                        .to_lowercase();
                    let stem = std::path::Path::new(&name)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_lowercase();
                    if stem == "avguard" && entry.th32ProcessID != my_pid {
                        log_to_file(&format!("[AVGuard] Single-instance: killing other AVGuard PID={}", entry.th32ProcessID));
                        let _ = kill_process_multi(entry.th32ProcessID);
                    }
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
        }
    }
}

fn main() {
    log_to_file(&format!("[AVGuard] Starting... PID={}", unsafe { GetCurrentProcessId() }));

    // 启用 SeDebugPrivilege
    match enable_debug_privilege() {
        Ok(()) => log_to_file("[AVGuard] SeDebugPrivilege enabled"),
        Err(e) => log_to_file(&format!("[AVGuard] WARNING: Failed to enable SeDebugPrivilege: {}", e)),
    }

    // 单实例保护：杀掉其他 AVGuard 实例，避免多实例竞争 Melix 单连接管道与同名事件管道
    ensure_single_instance();

    // 启动 Melix 端点防护事件监听线程（后台，持续监听 PromptRequest/BlockNotification 并推送给主程序）
    std::thread::spawn(spawn_melix_watcher);

    // 启动命名管道服务器
    run_pipe_server();
}

// ==================== Melix 单连接桥接 ====================
// 主程序（普通权限）无法直连 Melix.Control。AVGuard 作为唯一客户端建立**一条**
// 到 Melix.Service 的常驻连接（Melix.Service 管道实例数 = 1，不能并发多连接，
// 否则第二个连接 WaitNamedPipe 会超时 error 121）。
//
// 模型参考 Melix.UI 的 IpcClient：单连接 + 后台读取循环分发。
//  - worker 线程：持锁短超时读取事件(PromptRequest/BlockNotification)并推送给主程序；
//  - melix 请求(rules/settings/trust/prompt)：通过同一连接发送并同步读取响应。
// 读写共用一个 Mutex 串行化，避免管道数据交错。
const MELIX_EVENT_PIPE_NAME: &str = r"\\.\pipe\AVGuardMelixEventPipe";

use std::sync::{Mutex as StdMutex, OnceLock};

// 全局共享的 Melix.Service 连接（单连接模型，串行使用）
static MELIX_CONN: OnceLock<StdMutex<Option<MelixClient>>> = OnceLock::new();
fn melix_conn() -> &'static StdMutex<Option<MelixClient>> {
    MELIX_CONN.get_or_init(|| StdMutex::new(None))
}

/// 获取或建立 Melix.Service 连接。
fn get_melix_conn() -> Result<std::sync::MutexGuard<'static, Option<MelixClient>>, String> {
    let guard = melix_conn().lock().map_err(|e| e.to_string())?;
    Ok(guard)
}

// HANDLE 不是 Send，用包装使其可在线程间共享
struct SendH(HANDLE);
unsafe impl Send for SendH {}

// 全局事件推送管道 handle（在事件推送线程与读循环间共享）
static MELIX_EVENT_PIPE: OnceLock<StdMutex<Option<SendH>>> = OnceLock::new();
fn melix_event_pipe() -> &'static StdMutex<Option<SendH>> {
    MELIX_EVENT_PIPE.get_or_init(|| StdMutex::new(None))
}

/// 后台线程：创建事件推送管道并等待主程序连接；断开后重建。
fn spawn_event_pipe_host() {
    loop {
        let (sa, _sd) = build_null_dacl_security_attributes();
        let pipe = unsafe {
            let path: Vec<u16> = MELIX_EVENT_PIPE_NAME.encode_utf16().chain(Some(0)).collect();
            let h = CreateNamedPipeW(
                PCWSTR(path.as_ptr()),
                FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_DUPLEX),
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,
                PIPE_BUFFER_SIZE,
                PIPE_BUFFER_SIZE,
                0,
                Some(&sa),
            );
            h
        };
        if pipe == INVALID_HANDLE_VALUE {
            log_to_file("[MelixEventsHost] create event pipe failed");
            std::thread::sleep(std::time::Duration::from_secs(2));
            continue;
        }
        // 等待主程序连接（阻塞）。连接后存入全局供读循环推送。
        unsafe { let _ = ConnectNamedPipe(pipe, None); }
        log_to_file("[MelixEventsHost] event pipe connected by main program");
        *melix_event_pipe().lock().unwrap() = Some(SendH(pipe));
        // 持续等待主程序断开；断开后清空并重建
        loop {
            // 简单探测：读一字节，若返回 0/错误则主程序已断开
            let mut b = [0u8; 1];
            let mut read = 0u32;
            let hr = unsafe { ReadFile(pipe, Some(&mut b), Some(&mut read), None) };
            let closed = hr.is_err() || read == 0;
            if closed {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        unsafe { let _ = CloseHandle(pipe); }
        *melix_event_pipe().lock().unwrap() = None;
        log_to_file("[MelixEventsHost] event pipe disconnected, rebuilding");
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
}

/// 后台 worker：保持 Melix 连接，持续读取事件并推送主程序。若连接断开则重连。
/// 关键：连接后**立即进入读循环**（参考 Melix.UI：先启动读取再发 Hello），
/// 避免服务端 SendAsync(Hello) 时因对端未读而 "Pipe is broken"。
fn spawn_melix_watcher() {
    log_to_file("[MelixWatcher] Starting melix event watcher thread");
    // 先启动事件推送管道宿主（后台），再进入 Melix 读循环
    std::thread::spawn(spawn_event_pipe_host);
    loop {
        // 连接 Melix.Service（唯一连接）
        let mut client = match MelixClient::connect() {
            Ok(c) => c,
            Err(e) => {
                if e == "MELIX_SERVICE_NOT_RUNNING" {
                    std::thread::sleep(std::time::Duration::from_secs(3));
                } else {
                    log_to_file(&format!("[MelixWatcher] connect failed: {e}"));
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
                continue;
            }
        };
        // 存入全局共享连接
        *melix_conn().lock().unwrap() = Some(client);
        log_to_file("[MelixWatcher] connected to Melix.Service, listening for events");

        // 立即进入读循环（持续消费服务端 Hello/事件/响应）
        let mut broken = false;
        while !broken {
            let mut guard = match melix_conn().lock() {
                Ok(g) => g,
                Err(_) => { broken = true; break; }
            };
            if let Some(c) = guard.as_mut() {
                match c.read_line_timeout(250) {
                    Ok(msg) => {
                        // 仅记录非刷屏类型，避免日志爆炸
                        if msg.r#type != IpcMessageType::LogEntry
                            && msg.r#type != IpcMessageType::EventStream
                            && msg.r#type != IpcMessageType::Hello
                        {
                            log_to_file(&format!("[MelixWatcher] got msg type={}", msg.r#type.name()));
                        }
                        // 事件驱动：把收到的所有消息推送给主程序
                        let payload = serde_json::json!({
                            "type": msg.r#type.name(),
                            "payload": msg.payload,
                        });
                        let line = payload.to_string();
                        let mut buf = line.as_bytes().to_vec();
                        buf.push(b'\n');
                        let mut written = 0u32;
                        let pipe = melix_event_pipe().lock().ok().and_then(|p| p.as_ref().map(|h| h.0)).unwrap_or(INVALID_HANDLE_VALUE);
                        if pipe != INVALID_HANDLE_VALUE {
                            let r = unsafe { WriteFile(pipe, Some(&buf), Some(&mut written), None) };
                            if r.is_err() {
                                log_to_file("[MelixWatcher] event pipe write failed");
                            }
                        }
                    }
                    Err(e) => {
                        if e == "read timeout" || e.starts_with("parse message:") {
                            // 无事件或半包：继续
                        } else {
                            log_to_file(&format!("[MelixWatcher] read error: {e}, reconnecting"));
                            broken = true;
                        }
                    }
                }
            } else {
                broken = true;
            }
            drop(guard);
        }
        // 连接断开：清除共享连接并重连
        *melix_conn().lock().unwrap() = None;
        log_to_file("[MelixWatcher] reconnecting to Melix.Service");
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
}

// ==================== 命名管道服务器 ====================

/// 创建 NULL DACL 安全属性，允许非提权进程连接提权进程创建的管道
/// 用 Box 固定 SECURITY_DESCRIPTOR 在堆上，避免 move 后指针失效
fn build_null_dacl_security_attributes() -> (SECURITY_ATTRIBUTES, Box<SECURITY_DESCRIPTOR>) {
    let mut sd = Box::new(SECURITY_DESCRIPTOR::default());
    let sd_ptr = sd.as_mut() as *mut _;

    unsafe {
        // 初始化安全描述符 (REVISION = 1)
        let p_sd = windows::Win32::Security::PSECURITY_DESCRIPTOR(sd_ptr as *mut _);
        let _ = windows::Win32::Security::InitializeSecurityDescriptor(p_sd, 1);
        // 设置空 DACL（NULL DACL = 允许所有人访问）
        let _ = SetSecurityDescriptorDacl(p_sd, true, None, false);
    }

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd_ptr as *mut _,
        bInheritHandle: false.into(),
    };

    (sa, sd)
}

fn run_pipe_server() {
    log_to_file(&format!("[AVGuard] Pipe server starting on {}", PIPE_NAME));

    loop {
        let pipe_name_w: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

        // 使用 NULL DACL，允许非提权的主程序连接
        let (sa, _sd) = build_null_dacl_security_attributes();

        let pipe = unsafe {
            CreateNamedPipeW(
                PCWSTR(pipe_name_w.as_ptr()),
                FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED),
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                255, // PIPE_UNLIMITED_INSTANCES — 允许多个实例，避免单连接瓶颈
                PIPE_BUFFER_SIZE,
                PIPE_BUFFER_SIZE,
                0,
                Some(&sa),
            )
        };

        if pipe == INVALID_HANDLE_VALUE {
            let err = unsafe { GetLastError() };
            log_to_file(&format!("[AVGuard] CreateNamedPipeW failed: error {}", err.0));
            std::thread::sleep(std::time::Duration::from_secs(2));
            continue;
        }

        // 等待客户端连接
        let connected = unsafe { ConnectNamedPipe(pipe, None) };

        if connected.is_err() {
            let err = unsafe { GetLastError() };
            if err != windows::Win32::Foundation::ERROR_PIPE_CONNECTED {
                log_to_file(&format!("[AVGuard] ConnectNamedPipe failed: error {}", err.0));
                unsafe { let _ = CloseHandle(pipe); }
                std::thread::sleep(std::time::Duration::from_millis(500));
                continue;
            }
        }

        // 处理客户端连接
        let should_shutdown = handle_client(pipe);

        unsafe { let _ = CloseHandle(pipe); }

        if should_shutdown {
            println!("[AVModel] Received shutdown command, exiting");
            break;
        }
    }
}

/// 处理客户端连接，返回 true 表示收到 shutdown 命令
fn handle_client(pipe: HANDLE) -> bool {
    loop {
        let req = match read_message(pipe) {
            Ok(data) => data,
            Err(e) => {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    // Client disconnected — normal
                } else {
                    log_to_file(&format!("[AVGuard] Read error: {}", e));
                }
                return false;
            }
        };

        let req_str = match String::from_utf8(req) {
            Ok(s) => s,
            Err(_) => {
                let _ = send_message(pipe, &Response::err("Invalid UTF-8"));
                continue;
            }
        };

        log_to_file(&format!("[AVGuard] Received: {}", req_str));

        let request: Request = match serde_json::from_str(&req_str) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::err(&format!("Invalid JSON: {}", e));
                let _ = send_message(pipe, &resp);
                continue;
            }
        };

        let (response, shutdown) = match request {
            Request::Ping => {
                (Response::ok("pong"), false)
            }
            Request::Kill { pid } => {
                let (resp, _) = kill_process_multi(pid);
                (resp, false)
            }
            Request::KillBatch { pids } => {
                let mut killed = Vec::new();
                let mut failed = Vec::new();
                for &pid in &pids {
                    let (resp, _) = kill_process_multi(pid);
                    if resp.ok {
                        killed.push(pid);
                    } else {
                        failed.push(pid);
                    }
                }
                let resp = Response {
                    ok: true,
                    msg: format!("Killed {} of {} processes", killed.len(), pids.len()),
                    method: None,
                    killed: Some(killed),
                    failed: Some(failed),
                    killed_pids: None,
                    total: None,
                    offset: None,
                    processes: None,
                    data: None,
                };
                (resp, false)
            }
            Request::KillByName { name } => {
                let resp = kill_by_name_multi(&name);
                (resp, false)
            }
            Request::ListProcesses { offset, count } => {
                let resp = list_processes_paginated(offset, count.min(200));
                (resp, false)
            }
            Request::Shutdown => {
                (Response::ok("bye"), true)
            }
            // ===== Melix HIPS 桥接命令 =====
            Request::MelixRunning => {
                (melix_service_running(), false)
            }
            Request::MelixRules => {
                (melix_handle("rules", None), false)
            }
            Request::MelixAddRule { actor_path, r#type, target_pattern, action, note } => {
                let params = serde_json::json!({
                    "actor_path": actor_path,
                    "type": r#type,
                    "target_pattern": target_pattern,
                    "action": action,
                    "note": note,
                });
                (melix_handle("add_rule", Some(params)), false)
            }
            Request::MelixDeleteRule { rule_id } => {
                let params = serde_json::json!({ "rule_id": rule_id });
                (melix_handle("delete_rule", Some(params)), false)
            }
            Request::MelixSettingsGet => {
                (melix_handle("settings_get", None), false)
            }
            Request::MelixSettingsSet { settings } => {
                let params = serde_json::json!({ "settings": settings });
                (melix_handle("settings_set", Some(params)), false)
            }
            Request::MelixTrustList => {
                (melix_handle("trust_list", None), false)
            }
            Request::MelixAddTrust { actor_path, note } => {
                let params = serde_json::json!({ "actor_path": actor_path, "note": note });
                (melix_handle("add_trust", Some(params)), false)
            }
            Request::MelixRemoveTrust { rule_id } => {
                let params = serde_json::json!({ "rule_id": rule_id });
                (melix_handle("remove_trust", Some(params)), false)
            }
            Request::MelixPrompt { event_id, action, remember } => {
                let params = serde_json::json!({ "event_id": event_id, "action": action, "remember": remember });
                (melix_handle("prompt", Some(params)), false)
            }
        };

        if send_message(pipe, &response).is_err() {
            eprintln!("[AVModel] Failed to send response");
            return false;
        }

        if shutdown {
            return true;
        }
    }
}

// ==================== Melix HIPS 桥接（管理员中转） ====================

/// 判断 Melix.Service 是否已连接（worker 是否建立了共享连接）。
fn melix_service_running() -> Response {
    let running = match melix_conn().lock() {
        Ok(g) => g.is_some(),
        Err(_) => false,
    };
    Response::ok_with_data("melix running check", serde_json::json!({ "running": running }))
}

/// 解析裁决动作字符串。
fn parse_verdict(s: &str) -> Result<VerdictAction, Response> {
    match s.to_ascii_lowercase().as_str() {
        "allow" => Ok(VerdictAction::Allow),
        "block" => Ok(VerdictAction::Block),
        "ask" => Ok(VerdictAction::Ask),
        other => Err(Response::err(&format!("invalid verdict action: {other}"))),
    }
}

/// 将 Melix 规则转成前端友好的 JSON。
fn rule_to_json(r: &melix_ipc::DefenseRule) -> serde_json::Value {
    serde_json::json!({
        "id": r.id,
        "actorPath": r.actor_path,
        "type": r.r#type,
        "targetPattern": r.target_pattern,
        "commandLinePattern": r.command_line_pattern,
        "actorHashes": r.actor_hashes,
        "targetHashes": r.target_hashes,
        "requireUnsigned": r.require_unsigned,
        "action": r.action,
        "note": r.note,
        "createdUtc": r.created_utc,
    })
}

/// 通用 Melix 命令处理入口，返回主程序可解析的 Response。
/// 通过全局共享连接（单连接模型）执行，避免与 worker 争抢第二个连接（Melix 管道实例数=1）。
fn melix_handle(cmd: &str, params: Option<serde_json::Value>) -> Response {
    // 获取共享连接（worker 已建立的常驻连接）
    let mut guard = match melix_conn().lock() {
        Ok(g) => g,
        Err(e) => return Response::err(&format!("共享连接锁失败: {e}")),
    };
    let client = match guard.as_mut() {
        Some(c) => c,
        None => return Response::err("端点防护服务未运行（Melix.Service 未连接）"),
    };

    match cmd {
        // 参考 Melix.UI：请求只发送，响应由 worker 后台读循环推送（事件驱动），这里不读响应。
        "rules" => {
            match client.send(IpcMessageType::RulesRequest, &serde_json::json!({})) {
                Ok(()) => Response::ok("规则请求已发送"),
                Err(e) => Response::err(&format!("发送规则请求失败: {e}")),
            }
        }
        "add_rule" => {
            let p = params.unwrap_or_default();
            let action = match parse_verdict(p.get("action").and_then(|v| v.as_str()).unwrap_or("")) {
                Ok(a) => a,
                Err(r) => return r,
            };
            let payload = melix_ipc::AddRulePayload {
                actor_path: p.get("actor_path").and_then(|v| v.as_str()).map(|s| s.to_string()),
                r#type: p.get("type").and_then(|v| v.as_str()).map(|s| parse_ev_type(s)).flatten(),
                target_pattern: p.get("target_pattern").and_then(|v| v.as_str()).map(|s| s.to_string()),
                action,
                note: p.get("note").and_then(|v| v.as_str()).map(|s| s.to_string()),
            };
            match client.send(IpcMessageType::AddRule, &payload) {
                Ok(()) => Response::ok("已添加规则"),
                Err(e) => Response::err(&format!("添加规则失败: {e}")),
            }
        }
        "delete_rule" => {
            let p = params.unwrap_or_default();
            let rule_id = p.get("rule_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let payload = melix_ipc::DeleteRulePayload { rule_id };
            match client.send(IpcMessageType::DeleteRule, &payload) {
                Ok(()) => Response::ok("已删除规则"),
                Err(e) => Response::err(&format!("删除规则失败: {e}")),
            }
        }
        "settings_get" => {
            match client.send(IpcMessageType::SettingsRequest, &serde_json::json!({})) {
                Ok(()) => Response::ok("设置请求已发送"),
                Err(e) => Response::err(&format!("发送设置请求失败: {e}")),
            }
        }
        "settings_set" => {
            let p = params.unwrap_or_default();
            let settings = p.get("settings").cloned().unwrap_or(serde_json::json!({}));
            match client.send_json(IpcMessageType::SettingsUpdate, &settings.to_string()) {
                Ok(()) => Response::ok("已更新设置"),
                Err(e) => Response::err(&format!("更新设置失败: {e}")),
            }
        }
        "trust_list" => {
            match client.send(IpcMessageType::TrustListRequest, &serde_json::json!({})) {
                Ok(()) => Response::ok("信任列表请求已发送"),
                Err(e) => Response::err(&format!("发送信任列表请求失败: {e}")),
            }
        }
        "add_trust" => {
            let p = params.unwrap_or_default();
            let actor_path = p.get("actor_path").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let note = p.get("note").and_then(|v| v.as_str()).map(|s| s.to_string());
            let payload = melix_ipc::AddTrustPayload { actor_path, note };
            match client.send(IpcMessageType::AddTrust, &payload) {
                Ok(()) => Response::ok("已添加信任"),
                Err(e) => Response::err(&format!("添加信任失败: {e}")),
            }
        }
        "remove_trust" => {
            let p = params.unwrap_or_default();
            let rule_id = p.get("rule_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let payload = melix_ipc::RemoveTrustPayload { rule_id };
            match client.send(IpcMessageType::RemoveTrust, &payload) {
                Ok(()) => Response::ok("已移除信任"),
                Err(e) => Response::err(&format!("移除信任失败: {e}")),
            }
        }
        "prompt" => {
            let p = params.unwrap_or_default();
            let action = match parse_verdict(p.get("action").and_then(|v| v.as_str()).unwrap_or("")) {
                Ok(a) => a,
                Err(r) => return r,
            };
            let payload = melix_ipc::PromptResponsePayload {
                event_id: p.get("event_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                action,
                remember: p.get("remember").and_then(|v| v.as_bool()).unwrap_or(false),
            };
            match client.send(IpcMessageType::PromptResponse, &payload) {
                Ok(()) => Response::ok("已提交裁决"),
                Err(e) => Response::err(&format!("提交裁决失败: {e}")),
            }
        }
        other => Response::err(&format!("未知 melix 命令: {other}")),
    }
}

/// 解析事件类型字符串。
fn parse_ev_type(s: &str) -> Option<melix_ipc::EventType> {
    use melix_ipc::EventType;
    match s {
        "ProcessCreate" => Some(EventType::ProcessCreate),
        "ProcessTerminate" => Some(EventType::ProcessTerminate),
        "RemoteThread" => Some(EventType::RemoteThread),
        "ImageLoad" => Some(EventType::ImageLoad),
        "FileWrite" => Some(EventType::FileWrite),
        "FileDelete" => Some(EventType::FileDelete),
        "RegistryWrite" => Some(EventType::RegistryWrite),
        "NetworkConnect" => Some(EventType::NetworkConnect),
        "SelfProtect" => Some(EventType::SelfProtect),
        "MemoryAlloc" => Some(EventType::MemoryAlloc),
        "OpenProcess" => Some(EventType::OpenProcess),
        "WriteMemory" => Some(EventType::WriteMemory),
        _ => None,
    }
}

// ==================== 消息读写 ====================

/// 读取消息：4 字节 LE 长度前缀 + JSON body
fn read_message(pipe: HANDLE) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    read_exact(pipe, &mut len_buf)?;

    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > 10 * 1024 * 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid message length"));
    }

    let mut buf = vec![0u8; len];
    read_exact(pipe, &mut buf)?;
    Ok(buf)
}

fn read_exact(pipe: HANDLE, buf: &mut [u8]) -> io::Result<()> {
    let mut total = 0;
    while total < buf.len() {
        let mut bytes_read = 0u32;
        let ok = unsafe {
            ReadFile(
                pipe,
                Some(&mut buf[total..]),
                Some(&mut bytes_read),
                None,
            )
        };
        if ok.is_err() {
            let err = unsafe { GetLastError() };
            if err == windows::Win32::Foundation::ERROR_BROKEN_PIPE {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Pipe closed"));
            }
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("ReadFile failed: error {}", err.0),
            ));
        }
        if bytes_read == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "End of pipe"));
        }
        total += bytes_read as usize;
    }
    Ok(())
}

/// 发送消息：4 字节 LE 长度前缀 + JSON body
fn send_message(pipe: HANDLE, resp: &Response) -> io::Result<()> {
    let json = serde_json::to_vec(resp).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let len = json.len() as u32;
    let len_bytes = len.to_le_bytes();

    let mut total = 0;
    while total < len_bytes.len() {
        let mut written = 0u32;
        let ok = unsafe {
            WriteFile(
                pipe,
                Some(&len_bytes[total..]),
                Some(&mut written),
                None,
            )
        };
        if ok.is_err() {
            return Err(io::Error::new(io::ErrorKind::Other, "WriteFile failed"));
        }
        total += written as usize;
    }

    let mut total = 0;
    while total < json.len() {
        let mut written = 0u32;
        let ok = unsafe {
            WriteFile(
                pipe,
                Some(&json[total..]),
                Some(&mut written),
                None,
            )
        };
        if ok.is_err() {
            return Err(io::Error::new(io::ErrorKind::Other, "WriteFile failed"));
        }
        total += written as usize;
    }

    let _ = unsafe { FlushFileBuffers(pipe) };
    Ok(())
}

// ==================== 权限提升 ====================

fn enable_debug_privilege() -> Result<(), String> {
    unsafe {
        let mut token: HANDLE = HANDLE(ptr::null_mut());
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ).map_err(|e| format!("OpenProcessToken: {}", e))?;

        // ★验证是否真的提权（TOKEN_ELEVATION）★
        // 历史 bug：如果 AVGuard 未以管理员权限运行（例如 UAC 被拒绝后 watchdog
        // 以普通权限拉起，或 ShellExecuteW(runas) 静默降级），后续所有终止方法
        // 都会因完整性级别限制而失败（TerminateProcess 0x80070005 等），
        // 但日志仍显示 "SeDebugPrivilege enabled"（AdjustTokenPrivileges 不报错）。
        let mut elevation: u32 = 0;
        let mut size = 0u32;
        let elev_ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut u32 as *mut _),
            std::mem::size_of::<u32>() as u32,
            &mut size,
        );
        if elev_ok.is_err() || elevation == 0 {
            let _ = CloseHandle(token);
            let msg = format!(
                "AVGuard 未以管理员权限运行 (TokenElevation={:?}, query_err={:?})，无法终止受保护进程",
                elevation, elev_ok.as_ref().err()
            );
            log_to_file(&format!("[AVGuard] WARNING: {}", msg));
            return Err(msg);
        }
        log_to_file("[AVGuard] TokenElevation=1，确认以管理员权限运行");

        let mut luid = LUID::default();
        let name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
        LookupPrivilegeValueW(
            PCWSTR(ptr::null()),
            PCWSTR(name.as_ptr()),
            &mut luid,
        ).map_err(|e| format!("LookupPrivilegeValueW: {}", e))?;

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let result = AdjustTokenPrivileges(
            token,
            false,
            Some(&tp),
            0,
            None,
            None,
        );

        // ★检查是否部分失败（ERROR_NOT_ALL_ASSIGNED = 1300）★
        // AdjustTokenPrivileges 即使没有权限也会返回成功（部分分配），
        // 必须用 GetLastError 区分"全部成功"和"未分配"。
        let last_err = GetLastError();
        let _ = CloseHandle(token);

        result.map_err(|e| format!("AdjustTokenPrivileges: {}", e))?;

        if last_err == windows::Win32::Foundation::ERROR_NOT_ALL_ASSIGNED {
            return Err(format!("AdjustTokenPrivileges: ERROR_NOT_ALL_ASSIGNED (权限未分配，token 中没有 SeDebugPrivilege)"));
        }

        Ok(())
    }
}

// ==================== 进程终止（多方法） ====================

/// 等待进程真正死亡（最多等 5 秒，每 500ms 检查一次）
/// 返回 true 表示进程已死亡
fn wait_for_process_death(pid: u32, max_wait_ms: u64) -> bool {
    let start = std::time::Instant::now();
    let max_dur = std::time::Duration::from_millis(max_wait_ms);
    while start.elapsed() < max_dur {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if !process_exists(pid) {
            return true;
        }
    }
    false
}

/// 使用多种方法尝试终止进程，逐级升级
fn kill_process_multi(pid: u32) -> (Response, bool) {
    log_to_file(&format!("[AVGuard] Attempting to kill PID={}", pid));

    // 检查进程是否存在
    if !process_exists(pid) {
        let msg = format!("PID {} does not exist", pid);
        log_to_file(&format!("[AVGuard] {}", msg));
        return (Response::err(&msg), false);
    }
    log_to_file(&format!("[AVGuard] PID {} exists, proceeding with termination", pid));

    // 方法 1: TerminateProcess（常规，内部使用 WaitForSingleObject 等待）
    match kill_method_terminate_process(pid) {
        Ok(()) => {
            let msg = format!("PID {} killed via TerminateProcess", pid);
            log_to_file(&msg);
            return (Response::ok_with_method(&msg, "TerminateProcess"), true);
        }
        Err(e) => {
            log_to_file(&format!("[AVGuard] Method 1 (TerminateProcess) failed: {}", e));
        }
    }

    // 方法 2: TerminateThread（枚举并终止所有线程）
    match kill_method_terminate_threads(pid) {
        Ok(()) => {
            log_to_file(&format!("[AVGuard] Method 2 (TerminateThread) returned Ok, waiting for death..."));
            if wait_for_process_death(pid, 5000) {
                let msg = format!("PID {} killed via TerminateThread", pid);
                log_to_file(&msg);
                return (Response::ok_with_method(&msg, "TerminateThread"), true);
            }
            log_to_file("[AVGuard] Method 2 (TerminateThread) process still alive after 5s, trying next");
        }
        Err(e) => {
            log_to_file(&format!("[AVGuard] Method 2 (TerminateThread) failed: {}", e));
        }
    }

    // 方法 3: CreateRemoteThread + ExitProcess（远程线程注入）
    match kill_method_remote_thread(pid) {
        Ok(()) => {
            log_to_file(&format!("[AVGuard] Method 3 (RemoteThread) returned Ok, waiting for death..."));
            if wait_for_process_death(pid, 5000) {
                let msg = format!("PID {} killed via RemoteThread", pid);
                log_to_file(&msg);
                return (Response::ok_with_method(&msg, "RemoteThread"), true);
            }
            log_to_file("[AVGuard] Method 3 (RemoteThread) process still alive after 5s, trying next");
        }
        Err(e) => {
            log_to_file(&format!("[AVGuard] Method 3 (RemoteThread) failed: {}", e));
        }
    }

    // 方法 4: NtTerminateProcess（直接 ntdll 调用，内部使用 WaitForSingleObject 等待）
    match kill_method_nt_terminate(pid) {
        Ok(()) => {
            let msg = format!("PID {} killed via NtTerminateProcess", pid);
            log_to_file(&msg);
            return (Response::ok_with_method(&msg, "NtTerminateProcess"), true);
        }
        Err(e) => {
            log_to_file(&format!("[AVGuard] Method 4 (NtTerminateProcess) failed: {}", e));
        }
    }

    // 所有方法都失败
    let msg = format!("All termination methods failed for PID {}", pid);
    log_to_file(&format!("[AVGuard] {}", msg));
    (Response::err(&msg), false)
}

/// 按进程名查找并终止进程
/// 安装程序常见模式：主进程 WINAV_Setup_2.3.0.exe 释放同名 .tmp 到临时目录后退出，
/// 真实运行的进程名称为 WINAV_Setup_2.3.0.tmp。
/// 这里枚举所有进程，匹配名称（去扩展名后的 stem），杀所有匹配的进程。
fn kill_by_name_multi(target_name: &str) -> Response {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::Foundation::CloseHandle;

    // 提取目标进程名的 stem（去掉扩展名）
    let target_stem = std::path::Path::new(target_name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(target_name)
        .to_lowercase();

    log_to_file(&format!("[AVGuard] kill_by_name: target_stem={}", target_stem));

    let mut matched_pids: Vec<u32> = Vec::new();

    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(e) => {
                log_to_file(&format!("[AVGuard] kill_by_name: CreateToolhelp32Snapshot failed: {}", e));
                return Response::err(&format!("CreateToolhelp32Snapshot failed: {}", e));
            }
        };

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_err() {
            let _ = CloseHandle(snapshot);
            return Response::err("Process32FirstW failed");
        }

        loop {
            let process_name = String::from_utf16_lossy(&entry.szExeFile)
                .trim_end_matches('\0')
                .to_string();
            let process_stem = std::path::Path::new(&process_name)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();

            // ★匹配所有 stem 相同的进程（包括完全同名的进程）★
            // 历史 bug：`process_name != target_name` 把按原名运行的进程排除掉，
            // 例如 PID 终止失败后按名称兜底时，进程明明按原名活着却报
            // "No matching processes found"，导致兜底失效只能靠 taskkill。
            if process_stem == target_stem {
                matched_pids.push(entry.th32ProcessID);
                log_to_file(&format!("[AVGuard]   Matched process: {} (PID={})", process_name, entry.th32ProcessID));
            }

            if Process32NextW(snapshot, &mut entry).is_err() {
                break;
            }
        }

        let _ = CloseHandle(snapshot);
    }

    if matched_pids.is_empty() {
        log_to_file("[AVGuard] kill_by_name: no matching processes found");
        return Response::err("No matching processes found");
    }

    log_to_file(&format!("[AVGuard] kill_by_name: found {} matching processes, killing...", matched_pids.len()));

    let mut killed = Vec::new();
    let mut failed = Vec::new();
    for &pid in &matched_pids {
        let (resp, _) = kill_process_multi(pid);
        if resp.ok {
            killed.push(pid);
        } else {
            failed.push(pid);
        }
    }

    Response {
        ok: !killed.is_empty(),
        msg: format!("Killed {} of {} matching processes", killed.len(), matched_pids.len()),
        method: None,
        killed: Some(killed),
        failed: Some(failed),
        killed_pids: Some(matched_pids),
        total: None,
        offset: None,
        processes: None,
        data: None,
    }
}

// ==================== 进程列表枚举（内存活动威胁扫描） ====================

/// 进程快照缓存：分页请求之间保持同一快照（5 秒 TTL），避免翻页时进程变化导致总数不一致
static PROC_LIST_CACHE: std::sync::Mutex<Option<(std::time::Instant, Vec<ProcessInfo>)>> =
    std::sync::Mutex::new(None);

/// 枚举系统全部进程（纯 R3）：
/// Toolhelp32Snapshot 遍历进程表，OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)
/// + QueryFullProcessImageNameW 获取完整镜像路径。
/// AVGuard 以管理员 + SeDebugPrivilege 运行，可打开并查询提权进程（PPL 除外），
/// 覆盖主程序（普通权限）无法访问的进程。
fn list_processes_snapshot() -> Vec<ProcessInfo> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_NAME_WIN32,
    };

    let mut out: Vec<ProcessInfo> = Vec::new();

    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(e) => {
                log_to_file(&format!("[AVGuard] list_processes: CreateToolhelp32Snapshot failed: {}", e));
                return out;
            }
        };

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_err() {
            let _ = CloseHandle(snapshot);
            log_to_file("[AVGuard] list_processes: Process32FirstW failed");
            return out;
        }

        loop {
            let pid = entry.th32ProcessID;
            let parent_pid = entry.th32ParentProcessID;
            let name = String::from_utf16_lossy(&entry.szExeFile)
                .trim_end_matches('\0')
                .to_string();

            // 获取完整镜像路径（PID 0 = System Idle Process 无法打开）
            let mut path: Option<String> = None;
            if pid != 0 {
                if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                    let mut buf = [0u16; 1024];
                    let mut size = buf.len() as u32;
                    if QueryFullProcessImageNameW(
                        handle,
                        PROCESS_NAME_WIN32,
                        windows::core::PWSTR(buf.as_mut_ptr()),
                        &mut size,
                    ).is_ok() && size > 0 {
                        path = Some(String::from_utf16_lossy(&buf[..size as usize]));
                    }
                    let _ = CloseHandle(handle);
                }
            }

            out.push(ProcessInfo { pid, parent_pid, name, path });

            if Process32NextW(snapshot, &mut entry).is_err() {
                break;
            }
        }

        let _ = CloseHandle(snapshot);
    }

    out
}

/// 分页返回进程列表。同一连接内多次翻页共享一个快照（5 秒 TTL）。
/// 为保证消息不超过管道 64KB 缓冲，超长路径/进程名做字符边界安全截断，
/// 序列化仍超限时逐条裁剪。
fn list_processes_paginated(offset: u32, count: u32) -> Response {
    let snapshot = {
        let mut cache = PROC_LIST_CACHE.lock().unwrap();
        match cache.as_ref() {
            Some((t, v)) if t.elapsed() < std::time::Duration::from_secs(5) => v.clone(),
            _ => {
                let v = list_processes_snapshot();
                *cache = Some((std::time::Instant::now(), v.clone()));
                v
            }
        }
    };

    let total = snapshot.len() as u32;
    let start = offset as usize;
    if start >= snapshot.len() {
        return Response {
            ok: true,
            msg: format!("total={} offset={} returned=0", total, offset),
            method: None,
            killed: None,
            failed: None,
            killed_pids: None,
            total: Some(total),
            offset: Some(offset),
            processes: Some(Vec::new()),
            data: None,
        };
    }

    let mut page: Vec<ProcessInfo> = snapshot[start..]
        .iter()
        .take(count as usize)
        .cloned()
        .collect();

    // 字符边界安全截断，防止超长路径撑爆管道消息
    for p in page.iter_mut() {
        if let Some(path) = p.path.as_mut() {
            if path.chars().count() > 400 {
                *path = path.chars().take(400).collect();
            }
        }
        if p.name.chars().count() > 100 {
            p.name = p.name.chars().take(100).collect();
        }
    }

    // 序列化仍超 48KB（64KB 管道缓冲安全线）时逐条裁剪
    loop {
        let json_len = serde_json::to_vec(&page).map(|v| v.len()).unwrap_or(usize::MAX);
        if json_len <= 48000 || page.len() <= 1 {
            break;
        }
        page.pop();
    }

    Response {
        ok: true,
        msg: format!("total={} offset={} returned={}", total, offset, page.len()),
        method: None,
        killed: None,
        failed: None,
        killed_pids: None,
        total: Some(total),
        offset: Some(offset),
        processes: Some(page),
        data: None,
    }
}

/// 等待进程句柄变为有信号（即进程退出），最多等指定毫秒
/// 返回 true 表示进程已退出，false 表示超时
fn wait_for_handle(handle: HANDLE, timeout_ms: u32) -> bool {
    unsafe {
        WaitForSingleObject(handle, timeout_ms) == windows::Win32::Foundation::WAIT_OBJECT_0
    }
}

/// 检查进程是否存在
fn process_exists(pid: u32) -> bool {
    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION,
            false,
            pid,
        );
        if handle.is_err() {
            return false;
        }
        let _ = CloseHandle(handle.unwrap());
        true
    }
}

/// 方法 1: TerminateProcess — 常规 R3 API
/// 用 WaitForSingleObject 等待进程真正退出，不使用轮询
fn kill_method_terminate_process(pid: u32) -> Result<(), String> {
    unsafe {
        let handle = OpenProcess(
            PROCESS_TERMINATE,
            false,
            pid,
        ).map_err(|e| format!("OpenProcess(PROCESS_TERMINATE): {}", e))?;

        let result = TerminateProcess(handle, 1);
        if result.is_err() {
            let _ = CloseHandle(handle);
            return result.map_err(|e| format!("TerminateProcess: {}", e));
        }

        // WaitForSingleObject 等待进程退出，最多 5 秒
        log_to_file("[AVGuard]   TerminateProcess OK, waiting for handle signal...");
        let exited = wait_for_handle(handle, 5000);
        let _ = CloseHandle(handle);

        if exited {
            Ok(())
        } else {
            Err("TerminateProcess: process handle not signaled after 5s".to_string())
        }
    }
}

/// 方法 2: TerminateThread — 枚举并终止所有线程
/// 绕过进程级 hook（某些恶意软件只 hook TerminateProcess）
fn kill_method_terminate_threads(pid: u32) -> Result<(), String> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| format!("CreateToolhelp32Snapshot: {}", e))?;

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            cntUsage: 0,
            th32ThreadID: 0,
            th32OwnerProcessID: 0,
            tpBasePri: 0,
            tpDeltaPri: 0,
            dwFlags: 0,
        };

        let mut ok = Thread32First(snapshot, &mut entry);
        let mut killed_any = false;
        let mut last_error = String::new();

        while ok.is_ok() {
            if entry.th32OwnerProcessID == pid {
                match OpenThread(THREAD_TERMINATE, false, entry.th32ThreadID) {
                    Ok(thread_handle) => {
                        match TerminateThread(thread_handle, 1) {
                            Ok(()) => {
                                killed_any = true;
                                println!("[AVModel]   Thread {} terminated", entry.th32ThreadID);
                            }
                            Err(e) => {
                                last_error = format!("TerminateThread({}): {}", entry.th32ThreadID, e);
                            }
                        }
                        let _ = CloseHandle(thread_handle);
                    }
                    Err(e) => {
                        last_error = format!("OpenThread({}): {}", entry.th32ThreadID, e);
                    }
                }
            }
            ok = Thread32Next(snapshot, &mut entry);
        }

        let _ = CloseHandle(snapshot);

        if killed_any {
            Ok(())
        } else {
            Err(format!("No threads killed for PID {}. Last error: {}", pid, last_error))
        }
    }
}

/// 方法 3: CreateRemoteThread + ExitProcess
/// 在目标进程中创建远程线程执行 ExitProcess，绕过 TerminateProcess hook
fn kill_method_remote_thread(pid: u32) -> Result<(), String> {
    unsafe {
        let handle = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
            false,
            pid,
        ).map_err(|e| format!("OpenProcess(VM_WRITE|CREATE_THREAD): {}", e))?;

        // 获取 kernel32.dll 中 ExitProcess 的地址
        // kernel32.dll 在所有进程中加载地址相同（同一启动会话内）
        let kernel32 = GetModuleHandleA(windows::core::PCSTR(b"kernel32.dll\0".as_ptr()))
            .map_err(|e| format!("GetModuleHandleA(kernel32): {}", e))?;

        let exit_process_addr = GetProcAddress(kernel32, windows::core::PCSTR(b"ExitProcess\0".as_ptr()))
            .ok_or_else(|| "GetProcAddress(ExitProcess) returned null".to_string())?;

        println!("[AVModel]   ExitProcess @ 0x{:016X}", exit_process_addr as usize);

        // 创建远程线程，线程函数为 ExitProcess，参数为退出码 1
        let thread_handle = CreateRemoteThread(
            handle,
            None,
            0,
            Some(std::mem::transmute::<
                *const (),
                unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
            >(exit_process_addr as *const ())),
            Some(1 as *mut std::ffi::c_void),
            0,
            None,
        ).map_err(|e| {
            let _ = CloseHandle(handle);
            format!("CreateRemoteThread: {}", e)
        })?;

        // 等待远程线程执行
        let _ = WaitForSingleObject(thread_handle, 3000);
        let _ = CloseHandle(thread_handle);
        let _ = CloseHandle(handle);

        Ok(())
    }
}

/// 方法 4: NtTerminateProcess — 直接从 ntdll.dll 获取并调用
/// 绕过 kernel32.dll 层面的用户态 hook，以及部分 Ob 回调
fn kill_method_nt_terminate(pid: u32) -> Result<(), String> {
    unsafe {
        // 从 ntdll.dll 获取 NtTerminateProcess
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| format!("GetModuleHandleA(ntdll): {}", e))?;

        let nt_terminate_addr = GetProcAddress(ntdll, windows::core::PCSTR(b"NtTerminateProcess\0".as_ptr()))
            .ok_or_else(|| "GetProcAddress(NtTerminateProcess) returned null".to_string())?;

        println!("[AVModel]   NtTerminateProcess @ 0x{:016X}", nt_terminate_addr as usize);

        // 尝试使用 PROCESS_TERMINATE 打开
        let handle = OpenProcess(
            PROCESS_TERMINATE,
            false,
            pid,
        );

        let handle = match handle {
            Ok(h) => h,
            Err(e) => {
                return Err(format!("OpenProcess(PROCESS_TERMINATE) for NtTerminateProcess: {}", e));
            }
        };

        // 定义函数指针类型: NTSTATUS NtTerminateProcess(HANDLE, NTSTATUS)
        type NtTerminateProcessFn = unsafe extern "system" fn(HANDLE, i32) -> i32;
        let nt_terminate: NtTerminateProcessFn = std::mem::transmute(nt_terminate_addr);

        // 调用 NtTerminateProcess(handle, 0)
        // NTSTATUS: 0 = STATUS_SUCCESS, 负数 = 错误
        let status = nt_terminate(handle, 0);

        // ★STATUS_PENDING (0xC000010A) 必须视为成功★
        // 历史 bug：NtTerminateProcess 对受内核保护的进程（如刷机工具自保护驱动、
        // 火绒/360 HIPS、恶意软件反终止驱动）返回 STATUS_PENDING 而非 STATUS_SUCCESS，
        // 表示"终止请求已排队，进程正在退出"。旧代码 if status >= 0 把 0xC000010A
        // （i32 负数）误判为失败，导致所有方法"全部失败"而进程其实已被内核接受终止。
        // TerminateProcess/CreateRemoteThread 会被此类保护拦截（拒绝访问 0x80070005），
        // NtTerminateProcess 是唯一能穿透的路径，必须正确处理。
        const STATUS_SUCCESS: i32 = 0;
        const STATUS_PENDING: i32 = 0xC000010Au32 as i32; // -1073741558

        if status == STATUS_SUCCESS || status == STATUS_PENDING {
            // NtTerminateProcess 成功/已排队，用 WaitForSingleObject 等待进程退出
            log_to_file("[AVGuard]   NtTerminateProcess OK (SUCCESS or PENDING), waiting for handle signal...");
            let exited = wait_for_handle(handle, 5000);
            let _ = CloseHandle(handle);
            if exited {
                Ok(())
            } else {
                // 句柄未信号：再检查进程是否真的已消失（PENDING 场景下句柄可能不信号）
                if !process_exists(pid) {
                    log_to_file("[AVGuard]   Handle not signaled but process no longer exists, treating as success");
                    Ok(())
                } else {
                    Err("NtTerminateProcess: process handle not signaled after 5s and process still exists".to_string())
                }
            }
        } else {
            let _ = CloseHandle(handle);
            Err(format!("NtTerminateProcess returned NTSTATUS 0x{:08X}", status as u32))
        }
    }
}
