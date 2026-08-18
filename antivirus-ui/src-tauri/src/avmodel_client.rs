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

#[derive(Deserialize, Debug, Clone)]
pub struct AvModelResponse {
    pub ok: bool,
    pub msg: String,
    pub method: Option<String>,
    pub killed: Option<Vec<u32>>,
    pub failed: Option<Vec<u32>>,
    pub killed_pids: Option<Vec<u32>>,
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

// ==================== 内部实现 ====================

fn send_request<T: Serialize>(req: &T) -> Result<AvModelResponse, String> {
    let json = serde_json::to_vec(req).map_err(|e| format!("Serialize: {}", e))?;
    let len = json.len() as u32;
    let len_bytes = len.to_le_bytes();

    // 连接到 AVModel 管道
    let pipe = connect_pipe()?;
    let _guard = PipeGuard(pipe);

    unsafe {
        // 发送长度前缀
        let mut written = 0u32;
        WriteFile(
            pipe,
            Some(&len_bytes),
            Some(&mut written),
            None,
        ).map_err(|e| format!("WriteFile(len): {}", e))?;

        // 发送 JSON body
        let mut written = 0u32;
        WriteFile(
            pipe,
            Some(&json),
            Some(&mut written),
            None,
        ).map_err(|e| format!("WriteFile(body): {}", e))?;

        let _ = FlushFileBuffers(pipe);

        // 读取响应
        let resp_data = read_message(pipe)?;
        let resp: AvModelResponse = serde_json::from_slice(&resp_data)
            .map_err(|e| format!("Deserialize response: {}", e))?;

        Ok(resp)
    }
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
struct PipeGuard(HANDLE);
impl Drop for PipeGuard {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.0); }
    }
}
