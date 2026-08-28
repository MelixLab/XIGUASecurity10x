//! Melix.UI 后台进程控制客户端
//!
//! 主程序通过命名管道 `\\.\pipe\Melix.UIControl` 控制 Melix.UI 后台进程，
//! 让它在需要时弹出规则/设置/信任等原生窗口（复用其稳定的 IpcClient 与 Melix.Service 通讯）。
//! 协议：按行分隔 JSON，请求 `{"cmd":"show_rules",...}`，响应 `{"ok":true,...}`。

#![cfg(windows)]

use std::time::Duration;

use serde::{Deserialize, Serialize};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::WaitNamedPipeW;

pub const MELIX_UI_PIPE: &str = r"\\.\pipe\Melix.UIControl";

#[derive(Deserialize, Debug)]
pub struct UiControlResponse {
    pub ok: bool,
    pub msg: Option<String>,
}

/// Melix.UI 返回的引擎状态快照（get_status 命令）。
#[derive(Deserialize, Serialize, Debug)]
pub struct UiEngineStatus {
    pub ok: bool,
    pub msg: Option<String>,
    #[serde(default)]
    pub engine: String,
    #[serde(default)]
    pub connected: bool,
    #[serde(default)]
    pub kernel_enabled: bool,
    #[serde(default)]
    pub kernel_connected: bool,
    #[serde(default)]
    pub protection_enabled: bool,
    #[serde(default)]
    pub event_source: String,
}

/// 向 Melix.UI 查询引擎/内核/服务连接状态，返回结构化结果。
pub fn get_status(timeout_ms: u32) -> Result<UiEngineStatus, String> {
    let pipe = connect(timeout_ms)?;
    let _guard = PipeGuard(pipe);
    let mut buf = b"{\"cmd\":\"get_status\"}\n".to_vec();
    let mut written = 0u32;
    unsafe {
        WriteFile(pipe, Some(&buf), Some(&mut written), None).map_err(|e| e.to_string())?;
    }
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms as u64);
    loop {
        if std::time::Instant::now() > deadline {
            return Err("UI status timeout".to_string());
        }
        let mut read = 0u32;
        let hr = unsafe { ReadFile(pipe, Some(&mut byte), Some(&mut read), None) };
        if let Err(e) = hr {
            return Err(format!("ReadFile failed: {e}"));
        }
        if read == 0 {
            return Err("UI pipe closed".to_string());
        }
        if byte[0] == b'\n' {
            break;
        }
        out.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&out);
    serde_json::from_str(&text).map_err(|e| format!("parse UI status: {e}"))
}

/// 向 Melix.UI 后台进程发送一条命令并读取响应。若 UI 未运行返回 Err。
pub fn send_command(cmd: &str, timeout_ms: u32) -> Result<UiControlResponse, String> {
    let pipe = connect(timeout_ms)?;
    let _guard = PipeGuard(pipe);

    let line = format!(r#"{{"cmd":"{cmd}"}}"#);
    let mut buf = line.as_bytes().to_vec();
    buf.push(b'\n');
    let mut written = 0u32;
    unsafe {
        WriteFile(pipe, Some(&buf), Some(&mut written), None).map_err(|e| e.to_string())?;
    }

    // 读取一行响应
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms as u64);
    loop {
        if std::time::Instant::now() > deadline {
            return Err("UI control timeout".to_string());
        }
        let mut read = 0u32;
        let hr = unsafe { ReadFile(pipe, Some(&mut byte), Some(&mut read), None) };
        if let Err(e) = hr {
            return Err(format!("ReadFile failed: {e}"));
        }
        if read == 0 {
            return Err("UI control pipe closed".to_string());
        }
        if byte[0] == b'\n' {
            break;
        }
        out.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&out);
    serde_json::from_str(&text).map_err(|e| format!("parse UI response: {e}"))
}

/// 连接到 Melix.UI 控制管道（长连接，供监听事件使用）。
pub fn connect_pipe(timeout_ms: u32) -> Result<HANDLE, String> {
    connect(timeout_ms)
}

/// 读取一行（阻塞，供监听线程持续读取 UI 主动推送的事件/响应）。
/// 返回原始 JSON 行。管道断开/超时返回 Err。
pub fn read_line(pipe: HANDLE, timeout_ms: u64) -> Result<String, String> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if std::time::Instant::now() > deadline {
            return Err("ui listen timeout".to_string());
        }
        let mut read = 0u32;
        let hr = unsafe { ReadFile(pipe, Some(&mut byte), Some(&mut read), None) };
        if let Err(e) = hr {
            return Err(format!("ReadFile failed: {e}"));
        }
        if read == 0 {
            return Err("ui pipe closed".to_string());
        }
        if byte[0] == b'\n' {
            break;
        }
        out.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&out).to_string())
}

fn connect(timeout_ms: u32) -> Result<HANDLE, String> {
    unsafe {
        let path: Vec<u16> = MELIX_UI_PIPE.encode_utf16().chain(Some(0)).collect();
        let pipe_path = PCWSTR(path.as_ptr());

        let wait_ok = WaitNamedPipeW(pipe_path, timeout_ms).as_bool();
        if !wait_ok {
            let err = GetLastError();
            // error 2 = 管道不存在（服务未运行或管道名被隔离）；
            // error 5 = Access denied（权限不足，普通进程连管理员管道）
            return Err(format!(
                "WaitNamedPipeW({}) failed, err={} ({})",
                MELIX_UI_PIPE,
                err.0,
                match err.0 {
                    2 => "ERROR_FILE_NOT_FOUND: 管道不存在，Melix.UI 未启动或未创建控制管道",
                    5 => "ERROR_ACCESS_DENIED: 权限不足，Melix.UI 控制管道拒绝访问",
                    121 => "ERROR_SEM_TIMEOUT: 等待超时，管道忙或未就绪",
                    _ => "未知错误",
                }
            ));
        }
        let pipe = CreateFileW(
            pipe_path,
            0x80000000u32 | 0x40000000u32,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| format!("CreateFileW({}) failed: {}", MELIX_UI_PIPE, e))?;
        Ok(pipe)
    }
}

pub struct PipeGuard(pub HANDLE);
impl Drop for PipeGuard {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.0); }
    }
}

// 别名，便于调用方使用
pub type PipeGuard2 = PipeGuard;
