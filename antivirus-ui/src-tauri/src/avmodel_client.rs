//! AVGuard IPC 客户端 — 与 AVGuard 独立防护进程通信
//!
//! 主程序通过此模块向 AVGuard 进程发送终止请求。
//! AVGuard 以管理员权限运行，拥有 SeDebugPrivilege，可终止大部分进程。
//!
//! 通信协议：命名管道 `\\.\pipe\AVGuardPipe`
//! 消息格式：4 字节 LE 长度前缀 + JSON body

#![cfg(windows)]

use std::ptr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FlushFileBuffers,
    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::WaitNamedPipeW;

const PIPE_NAME: &str = r"\\.\pipe\AVGuardPipe";
const CONNECT_TIMEOUT_MS: u32 = 5000;
const READ_TIMEOUT_MS: u32 = 10000;

// ==================== 协议结构 ====================

#[derive(Serialize, Debug)]
struct KillRequest {
    cmd: String,
    pid: u32,
}

#[derive(Serialize, Debug)]
struct KillBatchRequest {
    cmd: String,
    pids: Vec<u32>,
}

#[derive(Serialize, Debug)]
struct KillByNameRequest {
    cmd: String,
    name: String,
}

#[derive(Serialize, Debug)]
struct PingRequest {
    cmd: String,
}

/// 进程列表分页请求（内存活动威胁扫描）
#[derive(Serialize, Debug)]
struct ListProcessesRequest {
    cmd: String,
    offset: u32,
    count: u32,
}

/// Melix HIPS 桥接请求（经 AVGuard 中转）
#[derive(Serialize, Debug)]
struct MelixBridgeRequest {
    cmd: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
}

/// AVGuard 返回的进程条目
#[derive(Deserialize, Debug, Clone)]
pub struct AvModelProcessInfo {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    /// 镜像完整路径（无法打开/受保护进程为 None）
    pub path: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AvModelResponse {
    pub ok: bool,
    pub msg: String,
    pub method: Option<String>,
    pub killed: Option<Vec<u32>>,
    pub failed: Option<Vec<u32>>,
    pub killed_pids: Option<Vec<u32>>,
    /// list_processes 响应：进程总数
    pub total: Option<u32>,
    /// list_processes 响应：本页起始偏移
    pub offset: Option<u32>,
    /// list_processes 响应：本页进程条目
    pub processes: Option<Vec<AvModelProcessInfo>>,
    /// Melix 桥接响应数据（规则/设置/信任列表等，由调用方解析）
    pub data: Option<serde_json::Value>,
}

// ==================== 公共 API ====================

/// 向 AVModel 发送终止进程请求
/// 返回 true 表示进程已被成功终止
pub fn request_kill(pid: u32) -> bool {
    let req = KillRequest { cmd: "kill".to_string(), pid };
    match send_request(&req) {
        Ok(resp) => {
            if resp.ok {
                println!("[AVModelClient] PID {} killed via AVModel (method: {:?})", pid, resp.method);
                true
            } else {
                println!("[AVModelClient] AVModel failed to kill PID {}: {}", pid, resp.msg);
                false
            }
        }
        Err(e) => {
            println!("[AVModelClient] Failed to send kill request for PID {}: {}", pid, e);
            false
        }
    }
}

/// 向 AVModel 发送批量终止进程请求
pub fn request_kill_batch(pids: &[u32]) -> Option<AvModelResponse> {
    let req = KillBatchRequest { cmd: "kill_batch".to_string(), pids: pids.to_vec() };
    match send_request(&req) {
        Ok(resp) => Some(resp),
        Err(e) => {
            println!("[AVModelClient] Failed to send kill_batch request: {}", e);
            None
        }
    }
}

/// 向 AVModel 发送按进程名终止请求
/// 安装程序常见模式：原进程退出后释放同名 .tmp 子进程
/// AVGuard 会枚举所有进程，匹配同名不同扩展名的进程并终止
pub fn request_kill_by_name(name: &str) -> Option<AvModelResponse> {
    let req = KillByNameRequest { cmd: "kill_by_name".to_string(), name: name.to_string() };
    match send_request(&req) {
        Ok(resp) => Some(resp),
        Err(e) => {
            println!("[AVModelClient] Failed to send kill_by_name request: {}", e);
            None
        }
    }
}

/// 检查 AVModel 进程是否在线
pub fn ping() -> bool {
    let req = PingRequest { cmd: "ping".to_string() };
    match send_request(&req) {
        Ok(resp) => {
            if !resp.ok {
                println!("[AVModelClient] ping: AVModel responded but ok=false, msg={}", resp.msg);
            }
            resp.ok
        }
        Err(e) => {
            println!("[AVModelClient] ping failed: {}", e);
            false
        }
    }
}

/// 请求 AVGuard 枚举全部运行进程（含提权进程的完整镜像路径）
///
/// AVGuard 以管理员 + SeDebugPrivilege 运行（纯 R3），可以打开并查询
/// 主程序（普通权限）无法访问的提权进程。返回全部进程条目，供内存威胁扫描使用。
///
/// 分页：单连接内多轮请求（每页最多 200 条），直到取完或超页数上限。
/// AVGuard 不可用 / 响应异常时返回 Err，由调用方回退到用户态枚举。
pub fn request_process_list() -> Result<Vec<AvModelProcessInfo>, String> {
    const PAGE_SIZE: u32 = 200;
    const MAX_PAGES: u32 = 20;

    let pipe = connect_pipe()?;
    let _guard = PipeGuard(pipe);

    let mut all: Vec<AvModelProcessInfo> = Vec::new();
    let mut offset: u32 = 0;
    let mut total: u32 = u32::MAX;
    let mut pages: u32 = 0;

    while offset < total && pages < MAX_PAGES {
        let req = ListProcessesRequest {
            cmd: "list_processes".to_string(),
            offset,
            count: PAGE_SIZE,
        };
        let resp = request_on_pipe(pipe, &req)?;
        if !resp.ok {
            return Err(format!("AVGuard list_processes failed: {}", resp.msg));
        }

        let page = resp.processes.unwrap_or_default();
        total = resp.total.unwrap_or(offset + page.len() as u32);
        pages += 1;

        if page.is_empty() {
            break;
        }
        let page_len = page.len() as u32;
        all.extend(page);
        offset += page_len;
    }

    println!("[AVModelClient] list_processes: collected {} processes (total={}, pages={})", all.len(), total, pages);
    Ok(all)
}

// ==================== Melix HIPS 桥接转发 ====================
// 主程序（普通权限）无法直连 Melix.Control，统一经 AVGuard（管理员）中转。

/// 通用的 Melix 命令转发：向 AVGuard 发送 melix_* 命令，返回其 data。
fn melix_request(cmd: &str, params: Option<serde_json::Value>) -> Result<serde_json::Value, String> {
    let req = MelixBridgeRequest {
        cmd: cmd.to_string(),
        params,
    };
    match send_request(&req) {
        Ok(resp) => {
            if !resp.ok {
                return Err(resp.msg);
            }
            Ok(resp.data.unwrap_or(serde_json::Value::Null))
        }
        Err(e) => Err(format!("AVGuard melix 转发失败: {e}")),
    }
}

/// 检查 Melix.Service 是否运行。
pub fn melix_service_running() -> Result<bool, String> {
    let data = melix_request("melix_running", None)?;
    Ok(data.get("running").and_then(|v| v.as_bool()).unwrap_or(false))
}

/// 获取防护规则列表（返回原始 JSON 数组元素）。
pub fn melix_get_rules() -> Result<Vec<serde_json::Value>, String> {
    let data = melix_request("melix_rules", None)?;
    Ok(data.get("rules").and_then(|v| v.as_array()).cloned().unwrap_or_default())
}

/// 新增防护规则。
pub fn melix_add_rule(
    actor_path: Option<String>, r#type: Option<String>, target_pattern: Option<String>,
    action: String, note: Option<String>,
) -> Result<(), String> {
    melix_request("melix_add_rule", Some(serde_json::json!({
        "actor_path": actor_path, "type": r#type, "target_pattern": target_pattern,
        "action": action, "note": note,
    }))).map(|_| ())
}

/// 删除防护规则。
pub fn melix_delete_rule(rule_id: String) -> Result<(), String> {
    melix_request("melix_delete_rule", Some(serde_json::json!({ "rule_id": rule_id }))).map(|_| ())
}

/// 获取运行时设置。
pub fn melix_get_settings() -> Result<serde_json::Value, String> {
    melix_request("melix_settings_get", None)
}

/// 更新运行时设置。
pub fn melix_update_settings(settings: serde_json::Value) -> Result<(), String> {
    melix_request("melix_settings_set", Some(serde_json::json!({ "settings": settings }))).map(|_| ())
}

/// 获取文件信任列表。
pub fn melix_get_trust_list() -> Result<Vec<serde_json::Value>, String> {
    let data = melix_request("melix_trust_list", None)?;
    Ok(data.get("entries").and_then(|v| v.as_array()).cloned().unwrap_or_default())
}

/// 新增文件信任。
pub fn melix_add_trust(actor_path: String, note: Option<String>) -> Result<(), String> {
    melix_request("melix_add_trust", Some(serde_json::json!({ "actor_path": actor_path, "note": note }))).map(|_| ())
}

/// 移除文件信任。
pub fn melix_remove_trust(rule_id: String) -> Result<(), String> {
    melix_request("melix_remove_trust", Some(serde_json::json!({ "rule_id": rule_id }))).map(|_| ())
}

/// 提交拦截裁决。
pub fn melix_prompt_response(event_id: String, action: String, remember: bool) -> Result<(), String> {
    melix_request("melix_prompt", Some(serde_json::json!({ "event_id": event_id, "action": action, "remember": remember }))).map(|_| ())
}

// ==================== 内部实现 ====================

/// 在已建立的管道连接上发送一次请求并读取响应（供分页复用）
fn request_on_pipe<T: Serialize>(pipe: HANDLE, req: &T) -> Result<AvModelResponse, String> {
    let json = serde_json::to_vec(req).map_err(|e| format!("Serialize: {}", e))?;
    let len = json.len() as u32;
    let len_bytes = len.to_le_bytes();

    unsafe {
        let mut written = 0u32;
        WriteFile(
            pipe,
            Some(&len_bytes),
            Some(&mut written),
            None,
        ).map_err(|e| format!("WriteFile(len): {}", e))?;

        let mut written = 0u32;
        WriteFile(
            pipe,
            Some(&json),
            Some(&mut written),
            None,
        ).map_err(|e| format!("WriteFile(body): {}", e))?;

        let _ = FlushFileBuffers(pipe);

        let resp_data = read_message(pipe)?;
        let resp: AvModelResponse = serde_json::from_slice(&resp_data)
            .map_err(|e| format!("Deserialize response: {}", e))?;

        Ok(resp)
    }
}

fn send_request<T: Serialize>(req: &T) -> Result<AvModelResponse, String> {
    // 连接到 AVModel 管道
    let pipe = connect_pipe()?;
    let _guard = PipeGuard(pipe);

    request_on_pipe(pipe, req)
}

// ==================== Melix 事件监听（拦截窗口前置） ====================
// 主程序连 AVGuard 的事件推送管道 `\\.\pipe\AVGuardMelixEventPipe`，持续读取
// Melix 主动推送的 PromptRequest / BlockNotification（行分隔 JSON，以 \n 结尾）。

const MELIX_EVENT_PIPE_NAME: &str = r"\\.\pipe\AVGuardMelixEventPipe";

/// 连接到 AVGuard 的 Melix 事件推送管道（阻塞等待）。
pub fn connect_melix_event_pipe() -> Result<HANDLE, String> {
    let pipe_name_w: Vec<u16> = MELIX_EVENT_PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let wait_ok = WaitNamedPipeW(PCWSTR(pipe_name_w.as_ptr()), 10000);
        if !wait_ok.as_bool() {
            let err = GetLastError();
            return Err(format!("WaitNamedPipe event pipe failed: error {}", err.0));
        }
        let pipe = CreateFileW(
            PCWSTR(pipe_name_w.as_ptr()),
            0x80000000u32 | 0x40000000u32,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| e.to_string())?;
        Ok(pipe)
    }
}

/// 读取一行 Melix 事件（阻塞直到收到一行或管道关闭）。返回 (type, payload_json)。
pub fn read_melix_event_line(pipe: HANDLE) -> Result<(String, String), String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(60000);
    loop {
        if std::time::Instant::now() > deadline {
            return Err("event pipe read timeout".to_string());
        }
        let mut read = 0u32;
        let hr = unsafe { ReadFile(pipe, Some(&mut byte), Some(&mut read), None) };
        if let Err(e) = hr {
            return Err(format!("ReadFile event pipe failed: {e}"));
        }
        if read == 0 {
            return Err("event pipe closed".to_string());
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&line);
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("parse event: {e}"))?;
    let ty = v.get("type").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let payload = v.get("payload").and_then(|x| x.as_str()).unwrap_or("").to_string();
    Ok((ty, payload))
}

fn connect_pipe() -> Result<HANDLE, String> {
    let pipe_name_w: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        // 等待管道可用 — WaitNamedPipeW 在 windows 0.58 返回 BOOL
        let wait_ok = WaitNamedPipeW(PCWSTR(pipe_name_w.as_ptr()), CONNECT_TIMEOUT_MS);
        if !wait_ok.as_bool() {
            let err = GetLastError();
            println!("[AVModelClient] WaitNamedPipeW failed: error {} (AVModel not running or pipe not accessible?)", err.0);
            return Err(format!("WaitNamedPipeW failed: error {} (AVModel not running?)", err.0));
        }

        // CreateFileW 在 windows 0.58 返回 Result<HANDLE, Error>
        // GENERIC_READ=0x80000000, GENERIC_WRITE=0x40000000
        let pipe = CreateFileW(
            PCWSTR(pipe_name_w.as_ptr()),
            0x80000000u32 | 0x40000000u32,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| {
            println!("[AVModelClient] CreateFileW failed: {} (error code: {})", e, e.code());
            format!("CreateFileW failed: {}", e)
        })?;

        Ok(pipe)
    }
}

fn read_message(pipe: HANDLE) -> Result<Vec<u8>, String> {
    unsafe {
        // 读取 4 字节长度前缀
        let mut len_buf = [0u8; 4];
        read_exact(pipe, &mut len_buf)?;

        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > 10 * 1024 * 1024 {
            return Err(format!("Invalid response length: {}", len));
        }

        let mut buf = vec![0u8; len];
        read_exact(pipe, &mut buf)?;
        Ok(buf)
    }
}

unsafe fn read_exact(pipe: HANDLE, buf: &mut [u8]) -> Result<(), String> {
    let mut total = 0;
    while total < buf.len() {
        let mut bytes_read = 0u32;
        let ok = ReadFile(
            pipe,
            Some(&mut buf[total..]),
            Some(&mut bytes_read),
            None,
        );

        if ok.is_err() {
            let err = GetLastError();
            return Err(format!("ReadFile failed: error {}", err.0));
        }
        if bytes_read == 0 {
            return Err("End of pipe".to_string());
        }
        total += bytes_read as usize;
    }
    Ok(())
}

/// RAII guard 确保 pipe handle 被关闭
pub struct PipeGuard(pub HANDLE);
impl Drop for PipeGuard {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.0); }
    }
}
