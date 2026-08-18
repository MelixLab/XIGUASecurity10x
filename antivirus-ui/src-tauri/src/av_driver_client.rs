//! AVDriver 命名管道客户端模块
//!
//! 对应 AVMain.cpp (主程序 Mock)，以 CLIENT 身份连接 AVSystem (XIGUASecurityAgent.exe)
//! 创建的命名管道 \\.\pipe\AVSystemPipe，完成 HMAC-SHA256 鉴权后接收驱动拦截通知，
//! 并将用户决策发回 AVSystem 转发至驱动。
//!
//! 三层架构:
//!   AVDriver (内核 KMDF)  <--IOCTL-->  AVSystem (SYSTEM 服务)  <--命名管道-->  主程序 (本模块)
//!
//! 协议参考: KMDF Driver/AVCommon/AVProtocol.h

#![cfg(not(feature = "ms_store"))]

use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use sha2::{Sha256, Digest};
use tauri::{AppHandle, Emitter, Manager};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED};
use windows::Win32::System::Pipes::WaitNamedPipeW;

// ==================== 协议常量 (对应 AVProtocol.h) ====================

/// 管道魔数 "AVDR"
const AV_PIPE_MAGIC: u32 = 0x41564452;

/// 管道全名
const AV_PIPE_FULL_NAME: &str = r"\\.\pipe\AVSystemPipe";

/// HMAC-SHA256 摘要长度
const AV_HASH_SIZE: usize = 32;

/// 随机 Challenge 长度
const AV_CHALLENGE_SIZE: usize = 32;

/// Session ID 长度
const AV_SESSION_ID_SIZE: usize = 16;

/// 共享密钥长度
const AV_SHARED_KEY_SIZE: usize = 32;

/// 最大管道消息大小 (64KB)
const AV_MAX_PIPE_MSG_SIZE: usize = 65536;

/// 进程路径最大长度 (WCHAR 数)
const AV_MAX_PROCESS_PATH_LEN: usize = 520;

/// 注册表键路径最大长度 (WCHAR 数)
const AV_MAX_REG_PATH_LEN: usize = 520;

/// 注册表值名最大长度 (WCHAR 数)
const AV_MAX_REG_VALUE_LEN: usize = 260;

/// 勒索通知最大文件数
const XGS_RANSOM_LIST_MAX: usize = 12;

/// 勒索文件路径最大长度 (WCHAR 数)
const XGS_MAX_FILE_PATH_LEN: usize = 520;

/// EndPoint 规则最大数
const XGS_EP_RULE_MAX: usize = 6;

/// EndPoint 规则描述长度 (WCHAR 数)
const XGS_EP_RULE_DESC_LEN: usize = 128;

/// 共享密钥 (开发阶段, 与 AVProtocol.h 一致)
const AV_SHARED_KEY: [u8; AV_SHARED_KEY_SIZE] = [
    0x4A, 0x6F, 0x69, 0x6E, 0x74, 0x41, 0x56, 0x54,
    0x65, 0x61, 0x6D, 0x4B, 0x65, 0x79, 0x32, 0x30,
    0x32, 0x34, 0x5F, 0x53, 0x65, 0x63, 0x75, 0x72,
    0x65, 0x41, 0x76, 0x44, 0x72, 0x69, 0x76, 0x65,
];

// ==================== 管道消息类型 (对应 AV_PIPE_MSG_TYPE) ====================

const AV_PIPE_MSG_AUTH_INIT: u32          = 0x1001;
const AV_PIPE_MSG_AUTH_CHALLENGE: u32     = 0x1002;
const AV_PIPE_MSG_AUTH_VERIFY: u32        = 0x1003;
const AV_PIPE_MSG_AUTH_RESULT: u32        = 0x1004;

const AV_PIPE_MSG_SCAN_REQUEST: u32       = 0x2001;
const AV_PIPE_MSG_SCAN_RESPONSE: u32      = 0x2002;
const AV_PIPE_MSG_GET_STATUS: u32         = 0x2003;
const AV_PIPE_MSG_STATUS_RESPONSE: u32    = 0x2004;
const AV_PIPE_MSG_HEARTBEAT: u32          = 0x2005;
const AV_PIPE_MSG_HEARTBEAT_RESPONSE: u32 = 0x2006;

const AV_PIPE_MSG_PROCESS_NOTIFY: u32     = 0x2010;
const AV_PIPE_MSG_PROCESS_DECISION: u32   = 0x2011;

const AV_PIPE_MSG_REG_NOTIFY: u32         = 0x2020;
const AV_PIPE_MSG_REG_DECISION: u32       = 0x2021;

const AV_PIPE_MSG_INJECTION_NOTIFY: u32   = 0x2030;
const AV_PIPE_MSG_INJECTION_DECISION: u32 = 0x2031;

const AV_PIPE_MSG_RANSOM_NOTIFY: u32      = 0x2040;
const AV_PIPE_MSG_RANSOM_DECISION: u32    = 0x2041;

const AV_PIPE_MSG_ENDPOINT_NOTIFY: u32    = 0x2050;
const AV_PIPE_MSG_ENDPOINT_DECISION: u32  = 0x2051;

const AV_PIPE_MSG_SHUTDOWN_REQUEST: u32   = 0x3000;
const AV_PIPE_MSG_ERROR: u32             = 0xFFFF;

// ==================== 决策类型 (对应 AV_DECISION_TYPE) ====================

pub const AV_DECISION_ALLOW_ONCE: u32   = 1;
pub const AV_DECISION_DENY_ONCE: u32    = 2;
pub const AV_DECISION_ALLOW_ALWAYS: u32 = 3;
pub const AV_DECISION_DENY_ALWAYS: u32  = 4;

/// 勒索决策码
pub const XGS_DECISION_ALLOW: u32      = 1;
pub const XGS_DECISION_STAY_BLOCK: u32 = 2;
pub const XGS_DECISION_RESTORE: u32    = 3;

/// EndPoint 决策码
pub const XGS_EP_DECISION_ALLOW: u32 = 1;
pub const XGS_EP_DECISION_KILL: u32  = 2;

// ==================== 通知数据结构 (解析后的 Rust 结构体) ====================

/// HANDLE 的线程安全包装 (windows HANDLE 不是 Send/Sync)
struct SendHandle(HANDLE);
unsafe impl Send for SendHandle {}
unsafe impl Sync for SendHandle {}

/// 进程拦截通知
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessNotifyData {
    pub notification_id: u64,
    pub process_id: u32,
    pub parent_process_id: u32,
    pub image_path: String,
    pub command_line: String,
    pub block_reason: u32,
    pub rule_description: String,
}

/// 注册表拦截通知
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RegNotifyData {
    pub notification_id: u64,
    pub process_id: u32,
    pub operation_type: u32,
    pub key_path: String,
    pub value_name: String,
}

/// 远程线程注入通知
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct InjectionNotifyData {
    pub notification_id: u64,
    pub source_process_id: u32,
    pub target_process_id: u32,
    pub thread_id: u32,
    pub start_address: u64,
    pub source_image_path: String,
}

/// 勒索文件条目
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RansomFileEntry {
    pub operation: u32,
    pub original_path: String,
    pub backup_path: String,
}

/// 勒索防护通知
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RansomNotifyData {
    pub notification_id: u64,
    pub file_count: u32,
    pub files: Vec<RansomFileEntry>,
}

/// EndPoint 规则命中
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct EpRuleHit {
    pub rule_id: u32,
    pub score: u32,
    pub description: String,
}

/// EndPoint 威胁通知 (EDR)
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct EndPointNotifyData {
    pub notification_id: u64,
    pub process_id: u32,
    pub parent_process_id: u32,
    pub total_score: u32,
    pub rule_count: u32,
    pub rules: Vec<EpRuleHit>,
    pub image_path: String,
}

/// 所有通知类型的统一枚举
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind")]
pub enum AvNotification {
    Process(ProcessNotifyData),
    Registry(RegNotifyData),
    Injection(InjectionNotifyData),
    Ransom(RansomNotifyData),
    EndPoint(EndPointNotifyData),
    Error { code: u32, message: String },
}

// ==================== 决策数据 (发送给 AVSystem) ====================

/// 用户决策，由 UI 回调产生
#[derive(Clone, Debug)]
pub enum AvDecision {
    /// 进程决策: notification_id, decision_type, image_path
    Process { notification_id: u64, decision: u32, image_path: String },
    /// 注册表决策: notification_id, decision_type, key_path
    Registry { notification_id: u64, decision: u32, key_path: String },
    /// 注入决策: notification_id, decision_type
    Injection { notification_id: u64, decision: u32 },
    /// 勒索决策: notification_id, decision_code
    Ransom { notification_id: u64, decision: u32 },
    /// EndPoint 决策: notification_id, decision_code
    EndPoint { notification_id: u64, decision: u32 },
}

// ==================== 字节读写辅助函数 ====================

fn write_u32_le(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_u64_le(buf: &mut [u8], offset: usize, val: u64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]])
}

fn read_u64_le(buf: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

/// 将宽字符串写入固定大小的缓冲区 (WCHAR[max_chars])
fn write_wide_string_fixed(buf: &mut [u8], offset: usize, max_chars: usize, s: &str) {
    let wide: Vec<u16> = s.encode_utf16().collect();
    let mut char_idx = 0;
    for i in 0..max_chars {
        let byte_pos = offset + i * 2;
        if byte_pos + 1 >= buf.len() {
            break;
        }
        let ch = if char_idx < wide.len() {
            let c = wide[char_idx];
            char_idx += 1;
            c
        } else {
            0 // null terminator + padding
        };
        buf[byte_pos] = (ch & 0xFF) as u8;
        buf[byte_pos + 1] = (ch >> 8) as u8;
    }
}

/// 从固定大小的缓冲区读取宽字符串 (WCHAR[max_chars])
fn read_wide_string_fixed(buf: &[u8], offset: usize, max_chars: usize) -> String {
    let mut wide: Vec<u16> = Vec::with_capacity(max_chars);
    for i in 0..max_chars {
        let byte_pos = offset + i * 2;
        if byte_pos + 1 >= buf.len() {
            break;
        }
        let ch = u16::from_le_bytes([buf[byte_pos], buf[byte_pos + 1]]);
        if ch == 0 {
            break;
        }
        wide.push(ch);
    }
    String::from_utf16_lossy(&wide)
}

// ==================== HMAC-SHA256 (使用 sha2 crate) ====================

/// 计算 HMAC-SHA256
///
/// HMAC(key, message) = H(opad || H(ipad || message))
/// block_size = 64 (SHA256)
fn calculate_hmac(data: &[u8], key: &[u8]) -> [u8; AV_HASH_SIZE] {
    const BLOCK_SIZE: usize = 64;

    // 步骤1: 处理密钥
    let key_processed: Vec<u8> = if key.len() > BLOCK_SIZE {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.finalize().to_vec()
    } else {
        key.to_vec()
    };

    // 填充密钥到 block_size
    let mut k_padded = [0u8; BLOCK_SIZE];
    k_padded[..key_processed.len()].copy_from_slice(&key_processed);

    // 步骤2: 计算 ipad 和 opad
    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = k_padded[i] ^ 0x36;
        opad[i] = k_padded[i] ^ 0x5c;
    }

    // 步骤3: H(ipad || message)
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    // 步骤4: H(opad || inner_hash)
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    let outer_hash = outer.finalize();

    let mut result = [0u8; AV_HASH_SIZE];
    result.copy_from_slice(&outer_hash);
    result
}

/// XOR 校验和 (与 AVProtocol.h XorChecksum 一致)
fn xor_checksum(data: &[u8]) -> u32 {
    let mut checksum: u32 = 0;
    for &b in data {
        checksum ^= b as u32;
    }
    checksum
}

// ==================== 管道消息收发 ====================

/// 管道消息头 (16 字节, packed)
struct PipeMsgHeader {
    magic: u32,
    msg_type: u32,
    data_size: u32,
    checksum: u32,
}

const HEADER_SIZE: usize = 16;

/// 解析消息头
fn parse_header(buf: &[u8]) -> Option<PipeMsgHeader> {
    if buf.len() < HEADER_SIZE {
        return None;
    }
    Some(PipeMsgHeader {
        magic: read_u32_le(buf, 0),
        msg_type: read_u32_le(buf, 4),
        data_size: read_u32_le(buf, 8),
        checksum: read_u32_le(buf, 12),
    })
}

/// 发送管道消息: 头部 + 数据
///
/// ★OVERLAPPED 实现：管道句柄已用 FILE_FLAG_OVERLAPPED 打开。
/// 与 recv_pipe_message 可在不同线程并发执行（读/写互不阻塞），
/// 这是决策写入线程与消息循环读取线程并发的前提。
fn send_pipe_message(
    pipe: HANDLE,
    msg_type: u32,
    data: &[u8],
) -> Result<(), String> {
    use windows::Win32::Storage::FileSystem::WriteFile;
    use windows::Win32::System::IO::{OVERLAPPED, GetOverlappedResult, CancelIoEx};
    use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
    use windows::Win32::Foundation::{GetLastError, ERROR_IO_PENDING, WAIT_OBJECT_0, CloseHandle, BOOL};

    let total_size = HEADER_SIZE + data.len();
    let mut buffer = vec![0u8; total_size];

    // 填充头部
    write_u32_le(&mut buffer, 0, AV_PIPE_MAGIC);
    write_u32_le(&mut buffer, 4, msg_type);
    write_u32_le(&mut buffer, 8, data.len() as u32);
    write_u32_le(&mut buffer, 12, xor_checksum(data));

    // 复制数据
    if !data.is_empty() {
        buffer[HEADER_SIZE..].copy_from_slice(data);
    }

    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    // 注意：双 windows crate 版本共存时 `bool.into()` 推断有歧义（E0283），
    // 必须显式构造 BOOL。
    let event = unsafe { CreateEventW(None, BOOL(0), BOOL(0), None) } // 自动重置事件
        .map_err(|e| format!("CreateEventW failed: {:?}", e))?;
    ov.hEvent = event;

    let mut bytes_written: u32 = 0;
    let result = unsafe {
        WriteFile(pipe, Some(&buffer), Some(&mut bytes_written), Some(&mut ov as *mut OVERLAPPED))
    };

    if result.is_err() {
        let err = unsafe { GetLastError() };
        if err == ERROR_IO_PENDING {
            // 写入挂起（管道缓冲区满等）：等待完成，15 秒兜底防止无限阻塞
            let wait = unsafe { WaitForSingleObject(event, 15000) };
            if wait == WAIT_OBJECT_0 {
                let go = unsafe { GetOverlappedResult(pipe, &ov, &mut bytes_written, BOOL(1)) };
                let _ = unsafe { CloseHandle(event) };
                go.map_err(|e| format!("GetOverlappedResult failed: {:?}", e))?;
            } else {
                let _ = unsafe { CancelIoEx(pipe, Some(&ov as *const OVERLAPPED)) };
                let _ = unsafe { CloseHandle(event) };
                return Err(format!("WriteFile pending wait failed: {:?}", wait));
            }
        } else {
            let _ = unsafe { CloseHandle(event) };
            return Err(format!("WriteFile failed: {:?}", err));
        }
    } else {
        let _ = unsafe { CloseHandle(event) };
    }

    if bytes_written as usize != total_size {
        return Err(format!("Incomplete write: {}/{}", bytes_written, total_size));
    }
    Ok(())
}

/// 接收管道消息: 返回 (消息类型, 数据部分)
///
/// ★OVERLAPPED 实现：阻塞等待数据（或连接被 CancelIoEx 中止）。
/// 消息循环线程长期挂起在此读时，决策写入线程可并发 WriteFile 不受影响。
fn recv_pipe_message(
    pipe: HANDLE,
) -> Result<(u32, Vec<u8>), String> {
    use windows::Win32::Storage::FileSystem::ReadFile;
    use windows::Win32::System::IO::{OVERLAPPED, GetOverlappedResult};
    use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};
    use windows::Win32::Foundation::{GetLastError, ERROR_IO_PENDING, WAIT_OBJECT_0, CloseHandle, BOOL};

    let mut buffer = vec![0u8; AV_MAX_PIPE_MSG_SIZE];

    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    // 双 windows crate 版本共存时 `bool.into()` 推断有歧义（E0283），显式构造 BOOL
    let event = unsafe { CreateEventW(None, BOOL(1), BOOL(0), None) } // 手动重置事件
        .map_err(|e| format!("CreateEventW failed: {:?}", e))?;
    ov.hEvent = event;

    let mut bytes_read: u32 = 0;
    let result = unsafe {
        ReadFile(pipe, Some(&mut buffer), Some(&mut bytes_read), Some(&mut ov as *mut OVERLAPPED))
    };

    if result.is_err() {
        let err = unsafe { GetLastError() };
        if err == ERROR_IO_PENDING {
            // 挂起读取：阻塞等待数据到达；stop() 会 CancelIoEx 中止本次等待
            let wait = unsafe { WaitForSingleObject(event, INFINITE) };
            if wait == WAIT_OBJECT_0 {
                let go = unsafe { GetOverlappedResult(pipe, &ov, &mut bytes_read, BOOL(1)) };
                let _ = unsafe { CloseHandle(event) };
                go.map_err(|e| format!("ReadFile failed: {:?}", e))?;
            } else {
                let _ = unsafe { CloseHandle(event) };
                return Err(format!("ReadFile wait failed: {:?}", wait));
            }
        } else {
            let _ = unsafe { CloseHandle(event) };
            return Err(format!("ReadFile failed: {:?}", err));
        }
    } else {
        let _ = unsafe { CloseHandle(event) };
    }

    if (bytes_read as usize) < HEADER_SIZE {
        return Err(format!("Message too short: {} bytes", bytes_read));
    }

    let header = parse_header(&buffer[..bytes_read as usize])
        .ok_or("Failed to parse header")?;

    if header.magic != AV_PIPE_MAGIC {
        return Err(format!("Invalid magic: 0x{:08X}", header.magic));
    }

    let data_end = HEADER_SIZE + header.data_size as usize;
    if data_end > bytes_read as usize {
        return Err(format!("Incomplete data: header claims {} bytes, got {}", 
            header.data_size, bytes_read as usize - HEADER_SIZE));
    }

    // 验证校验和
    if header.data_size > 0 {
        let data = &buffer[HEADER_SIZE..data_end];
        let calc = xor_checksum(data);
        if calc != header.checksum {
            return Err(format!("Checksum mismatch: calc 0x{:08X}, msg 0x{:08X}", calc, header.checksum));
        }
    }

    let data = if header.data_size > 0 {
        buffer[HEADER_SIZE..data_end].to_vec()
    } else {
        Vec::new()
    };

    Ok((header.msg_type, data))
}

// ==================== 通知数据解析 ====================

/// 解析进程拦截通知
fn parse_process_notify(data: &[u8]) -> ProcessNotifyData {
    // 布局: u64 NotificationId, u32 ProcessId, u32 ParentProcessId,
    //       WCHAR[520] ImagePath, WCHAR[520] CommandLine, u32 BlockReason, WCHAR[128] RuleDescription
    let mut offset = 0;
    let notification_id = read_u64_le(data, offset); offset += 8;
    let process_id = read_u32_le(data, offset); offset += 4;
    let parent_process_id = read_u32_le(data, offset); offset += 4;
    let image_path = read_wide_string_fixed(data, offset, AV_MAX_PROCESS_PATH_LEN); offset += AV_MAX_PROCESS_PATH_LEN * 2;
    let command_line = read_wide_string_fixed(data, offset, AV_MAX_PROCESS_PATH_LEN); offset += AV_MAX_PROCESS_PATH_LEN * 2;
    let block_reason = read_u32_le(data, offset); offset += 4;
    let rule_description = read_wide_string_fixed(data, offset, 128);

    ProcessNotifyData {
        notification_id,
        process_id,
        parent_process_id,
        image_path,
        command_line,
        block_reason,
        rule_description,
    }
}

/// 解析注册表拦截通知
fn parse_reg_notify(data: &[u8]) -> RegNotifyData {
    let mut offset = 0;
    let notification_id = read_u64_le(data, offset); offset += 8;
    let process_id = read_u32_le(data, offset); offset += 4;
    let operation_type = read_u32_le(data, offset); offset += 4;
    let key_path = read_wide_string_fixed(data, offset, AV_MAX_REG_PATH_LEN); offset += AV_MAX_REG_PATH_LEN * 2;
    let value_name = read_wide_string_fixed(data, offset, AV_MAX_REG_VALUE_LEN);

    RegNotifyData {
        notification_id,
        process_id,
        operation_type,
        key_path,
        value_name,
    }
}

/// 解析远程线程注入通知
fn parse_injection_notify(data: &[u8]) -> InjectionNotifyData {
    let mut offset = 0;
    let notification_id = read_u64_le(data, offset); offset += 8;
    let source_process_id = read_u32_le(data, offset); offset += 4;
    let target_process_id = read_u32_le(data, offset); offset += 4;
    let thread_id = read_u32_le(data, offset); offset += 4;
    let start_address = read_u64_le(data, offset); offset += 8;
    let source_image_path = read_wide_string_fixed(data, offset, AV_MAX_PROCESS_PATH_LEN);

    InjectionNotifyData {
        notification_id,
        source_process_id,
        target_process_id,
        thread_id,
        start_address,
        source_image_path,
    }
}

/// 解析勒索防护通知
fn parse_ransom_notify(data: &[u8]) -> RansomNotifyData {
    let mut offset = 0;
    let notification_id = read_u64_le(data, offset); offset += 8;
    let file_count = read_u32_le(data, offset); offset += 4;

    let mut files = Vec::new();
    let list_count = file_count.min(XGS_RANSOM_LIST_MAX as u32);
    for _ in 0..list_count {
        let operation = read_u32_le(data, offset); offset += 4;
        let original_path = read_wide_string_fixed(data, offset, XGS_MAX_FILE_PATH_LEN); offset += XGS_MAX_FILE_PATH_LEN * 2;
        let backup_path = read_wide_string_fixed(data, offset, XGS_MAX_FILE_PATH_LEN); offset += XGS_MAX_FILE_PATH_LEN * 2;
        files.push(RansomFileEntry { operation, original_path, backup_path });
    }

    RansomNotifyData {
        notification_id,
        file_count,
        files,
    }
}

/// 解析 EndPoint 威胁通知 (EDR)
fn parse_endpoint_notify(data: &[u8]) -> EndPointNotifyData {
    let mut offset = 0;
    let notification_id = read_u64_le(data, offset); offset += 8;
    let process_id = read_u32_le(data, offset); offset += 4;
    let parent_process_id = read_u32_le(data, offset); offset += 4;
    let total_score = read_u32_le(data, offset); offset += 4;
    let rule_count = read_u32_le(data, offset); offset += 4;

    let mut rules = Vec::new();
    let rc = rule_count.min(XGS_EP_RULE_MAX as u32);
    for _ in 0..rc {
        let rule_id = read_u32_le(data, offset); offset += 4;
        let score = read_u32_le(data, offset); offset += 4;
        let description = read_wide_string_fixed(data, offset, XGS_EP_RULE_DESC_LEN); offset += XGS_EP_RULE_DESC_LEN * 2;
        rules.push(EpRuleHit { rule_id, score, description });
    }

    let image_path = read_wide_string_fixed(data, offset, AV_MAX_PROCESS_PATH_LEN);

    EndPointNotifyData {
        notification_id,
        process_id,
        parent_process_id,
        total_score,
        rule_count,
        rules,
        image_path,
    }
}

// ==================== 决策序列化 ====================

/// 序列化进程决策
fn serialize_process_decision(notification_id: u64, decision: u32, image_path: &str) -> Vec<u8> {
    // 布局: u64 NotificationId, u32 Decision, WCHAR[520] ImagePath
    let size = 8 + 4 + AV_MAX_PROCESS_PATH_LEN * 2;
    let mut buf = vec![0u8; size];
    let mut offset = 0;
    write_u64_le(&mut buf, offset, notification_id); offset += 8;
    write_u32_le(&mut buf, offset, decision); offset += 4;
    write_wide_string_fixed(&mut buf, offset, AV_MAX_PROCESS_PATH_LEN, image_path);
    buf
}

/// 序列化注册表决策
fn serialize_reg_decision(notification_id: u64, decision: u32, key_path: &str) -> Vec<u8> {
    let size = 8 + 4 + AV_MAX_REG_PATH_LEN * 2;
    let mut buf = vec![0u8; size];
    let mut offset = 0;
    write_u64_le(&mut buf, offset, notification_id); offset += 8;
    write_u32_le(&mut buf, offset, decision); offset += 4;
    write_wide_string_fixed(&mut buf, offset, AV_MAX_REG_PATH_LEN, key_path);
    buf
}

/// 序列化注入决策
fn serialize_injection_decision(notification_id: u64, decision: u32) -> Vec<u8> {
    let size = 8 + 4;
    let mut buf = vec![0u8; size];
    write_u64_le(&mut buf, 0, notification_id);
    write_u32_le(&mut buf, 8, decision);
    buf
}

/// 序列化勒索决策
fn serialize_ransom_decision(notification_id: u64, decision: u32) -> Vec<u8> {
    let size = 8 + 4;
    let mut buf = vec![0u8; size];
    write_u64_le(&mut buf, 0, notification_id);
    write_u32_le(&mut buf, 8, decision);
    buf
}

/// 序列化 EndPoint 决策
fn serialize_endpoint_decision(notification_id: u64, decision: u32) -> Vec<u8> {
    let size = 8 + 4;
    let mut buf = vec![0u8; size];
    write_u64_le(&mut buf, 0, notification_id);
    write_u32_le(&mut buf, 8, decision);
    buf
}

// ==================== 鉴权 ====================

/// 执行 HMAC-SHA256 鉴权握手
///
/// 流程:
/// 1. 发送 AuthInit
/// 2. 接收 Challenge
/// 3. 计算 HMAC-SHA256(challenge || sequenceId, sharedKey)
/// 4. 发送 AuthVerify
/// 5. 接收 AuthResult
fn authenticate(pipe: HANDLE) -> Result<[u8; AV_SESSION_ID_SIZE], String> {
    // Step 1: 发送 AuthInit (ProtocolVersion = 1)
    let auth_init = [0x01u8, 0x00, 0x00, 0x00]; // u32 LE = 1
    send_pipe_message(pipe, AV_PIPE_MSG_AUTH_INIT, &auth_init)?;

    // Step 2: 接收 Challenge
    let (msg_type, data) = recv_pipe_message(pipe)?;
    if msg_type != AV_PIPE_MSG_AUTH_CHALLENGE {
        return Err(format!("Expected AuthChallenge(0x{:04X}), got 0x{:04X}", AV_PIPE_MSG_AUTH_CHALLENGE, msg_type));
    }
    if data.len() < 8 + AV_CHALLENGE_SIZE {
        return Err("Challenge data too short".to_string());
    }
    let sequence_id = read_u64_le(&data, 0);
    let challenge = &data[8..8 + AV_CHALLENGE_SIZE];

    // Step 3: 计算 HMAC
    // HMAC input = challenge(32) + sequenceId(8, LE)
    let mut hmac_input = Vec::with_capacity(AV_CHALLENGE_SIZE + 8);
    hmac_input.extend_from_slice(challenge);
    hmac_input.extend_from_slice(&sequence_id.to_le_bytes());
    let hmac = calculate_hmac(&hmac_input, &AV_SHARED_KEY);

    // Step 4: 发送 AuthVerify
    // 布局: u64 SequenceId, UCHAR[32] Challenge, UCHAR[32] Hmac
    let verify_size = 8 + AV_CHALLENGE_SIZE + AV_HASH_SIZE;
    let mut verify_buf = vec![0u8; verify_size];
    let mut offset = 0;
    write_u64_le(&mut verify_buf, offset, sequence_id); offset += 8;
    verify_buf[offset..offset + AV_CHALLENGE_SIZE].copy_from_slice(challenge); offset += AV_CHALLENGE_SIZE;
    verify_buf[offset..offset + AV_HASH_SIZE].copy_from_slice(&hmac);

    send_pipe_message(pipe, AV_PIPE_MSG_AUTH_VERIFY, &verify_buf)?;

    // Step 5: 接收 AuthResult
    let (msg_type, data) = recv_pipe_message(pipe)?;
    if msg_type != AV_PIPE_MSG_AUTH_RESULT {
        return Err(format!("Expected AuthResult(0x{:04X}), got 0x{:04X}", AV_PIPE_MSG_AUTH_RESULT, msg_type));
    }
    // 布局: BOOLEAN Success, UCHAR[16] SessionId, u32 ErrorCode
    if data.is_empty() {
        return Err("AuthResult data empty".to_string());
    }
    let success = data[0] != 0;
    if !success {
        let error_code = if data.len() >= 1 + AV_SESSION_ID_SIZE + 4 {
            read_u32_le(&data, 1 + AV_SESSION_ID_SIZE)
        } else {
            0
        };
        return Err(format!("Authentication failed, error code: {}", error_code));
    }

    let mut session_id = [0u8; AV_SESSION_ID_SIZE];
    if data.len() >= 1 + AV_SESSION_ID_SIZE {
        session_id.copy_from_slice(&data[1..1 + AV_SESSION_ID_SIZE]);
    }

    Ok(session_id)
}

// ==================== 管道连接 ====================

/// 连接到 AVSystem 命名管道 (客户端)
fn connect_to_pipe() -> Result<HANDLE, String> {
    let pipe_name: Vec<u16> = AV_PIPE_FULL_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // 等待管道可用 (最多 10 秒)
    let wait_result = unsafe {
        WaitNamedPipeW(
            windows::core::PCWSTR(pipe_name.as_ptr()),
            10000,
        )
    };
    if !wait_result.as_bool() {
        // 管道可能还没创建，尝试直接 CreateFile
        println!("[AvDriverClient] WaitNamedPipe failed, trying direct connect");
    }

    // 连接管道
    // ★关键：FILE_FLAG_OVERLAPPED——必须用异步 I/O 句柄！
    // 历史 bug：同步句柄下，消息循环线程阻塞在 ReadFile 时，另一线程（决策写入）
    // 对该句柄并发 WriteFile，行为未定义，决策经常发不出去，驱动超时后默认拒绝。
    // overlapped 句柄允许"一个线程挂起读 + 另一线程写"并发进行，互不干扰。
    let handle = unsafe {
        CreateFileW(
            windows::core::PCWSTR(pipe_name.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            None,
        )
    };

    let pipe = handle.map_err(|e| format!("CreateFileW connect to pipe failed: {:?}", e))?;

    // 设置管道为消息读取模式
    use windows::Win32::System::Pipes::{PIPE_READMODE_MESSAGE, SetNamedPipeHandleState};
    let pipe_mode = PIPE_READMODE_MESSAGE;
    unsafe {
        let _ = SetNamedPipeHandleState(
            pipe,
            Some(&pipe_mode),
            None,
            None,
        );
    }

    Ok(pipe)
}

// ==================== 客户端主结构 ====================

/// AVDriver 管道客户端
pub struct AvDriverClient {
    /// 管道句柄 (消息循环线程独占)
    pipe: Arc<Mutex<Option<SendHandle>>>,
    /// 会话 ID
    session_id: Arc<Mutex<[u8; AV_SESSION_ID_SIZE]>>,
    /// 停止标志
    stop_flag: Arc<AtomicBool>,
    /// 消息循环线程 (同步模型: 收通知→弹窗等决策→写决策→下一轮)
    thread: Option<std::thread::JoinHandle<()>>,
    /// 是否已连接
    connected: Arc<AtomicBool>,
}

impl AvDriverClient {
    /// 创建并启动客户端
    ///
    /// 连接到 AVSystem 管道，鉴权后进入消息循环。
    /// 通知通过 Tauri 事件 `av-driver-notification` 发送到前端，
    /// 决策通过 `send_decision()` 方法回传。
    pub fn start(app_handle: AppHandle) -> Result<Self, String> {
        println!("[AvDriverClient] Starting, connecting to {} ...", AV_PIPE_FULL_NAME);

        let pipe = connect_to_pipe()?;
        println!("[AvDriverClient] Pipe connected");

        let session_id = authenticate(pipe)?;
        println!("[AvDriverClient] Authentication successful");

        let pipe = Arc::new(Mutex::new(Some(SendHandle(pipe))));
        let session_id = Arc::new(Mutex::new(session_id));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let connected = Arc::new(AtomicBool::new(true));

        let pipe_clone = Arc::clone(&pipe);
        let stop_clone = Arc::clone(&stop_flag);
        let connected_clone = Arc::clone(&connected);

        // 消息循环线程（同步模型，完全对齐 AVMain 测试程序）：
        // ReadFile(阻塞) → 解析通知 → emit → listener 同步处理（弹窗阻塞等待用户决策）
        // → 写回决策 → 下一轮。弹窗等待期间不读新通知，与 AVMain 的
        // TaskDialogIndirect 模态阻塞语义一致。决策由弹窗线程直接写管道。
        let thread = std::thread::spawn(move || {
            message_loop(pipe_clone, app_handle, stop_clone, connected_clone);
        });

        Ok(AvDriverClient {
            pipe,
            session_id,
            stop_flag,
            thread: Some(thread),
            connected,
        })
    }

    /// 发送用户决策：直接写回管道（同步，与 AVMain 的 SendPipeMessage 一致）。
    /// 注意：仅在消息循环线程（弹窗等待决策后）调用，保证与 ReadFile 无并发。
    pub fn send_decision(&self, decision: AvDecision) -> Result<(), String> {
        let guard = self.pipe.lock().unwrap();
        match *guard {
            Some(ref sh) => send_decision_to_pipe(sh.0, &decision),
            None => Err("Client not started or pipe closed".to_string()),
        }
    }

    /// 发送优雅退出请求：Agent 收到 AV_PIPE_MSG_SHUTDOWN_REQUEST 后自行退出。
    /// 无数据负载，仅头部。必须在本端关闭管道句柄之前调用。
    pub fn send_shutdown(&self) -> Result<(), String> {
        let guard = self.pipe.lock().unwrap();
        match *guard {
            Some(ref sh) => send_pipe_message(sh.0, AV_PIPE_MSG_SHUTDOWN_REQUEST, &[]),
            None => Err("Client not started or pipe closed".to_string()),
        }
    }

    /// 是否已连接
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// 停止客户端
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        self.connected.store(false, Ordering::SeqCst);

        // 关闭管道句柄以解除阻塞的 ReadFile。
        // ★OVERLAPPED 句柄必须先 CancelIoEx 再 CloseHandle：
        // 直接 CloseHandle 不会让挂起的 overlapped 读完成，消息循环线程
        // 将永远阻塞在 WaitForSingleObject 上，join() 死锁。
        if let Ok(mut guard) = self.pipe.lock() {
            if let Some(send_handle) = guard.take() {
                unsafe {
                    let _ = windows::Win32::System::IO::CancelIoEx(send_handle.0, None);
                    let _ = CloseHandle(send_handle.0);
                }
            }
        }

        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }

        println!("[AvDriverClient] Stopped");
    }
}

impl Drop for AvDriverClient {
    fn drop(&mut self) {
        self.stop();
    }
}

// ==================== 消息循环 ====================

/// 消息循环（同步模型，与 AVMain 测试程序完全一致）：
/// ReadFile(阻塞) → 解析通知 → emit("av-driver-notification")
/// → listener 同步处理（扫描/弹窗，弹窗阻塞等待用户决策）
/// → 弹窗线程直接写决策回管道 → 返回 → 下一轮 ReadFile。
///
/// 弹窗等待期间不读新通知，后续通知由驱动/Agent 排队，与 AVMain 的
/// TaskDialogIndirect 模态阻塞语义一致。因此不存在"通知堆积读不到"、
/// "决策无人消费"等异步架构引入的问题。
fn message_loop(
    pipe: Arc<Mutex<Option<SendHandle>>>,
    app_handle: AppHandle,
    stop_flag: Arc<AtomicBool>,
    connected: Arc<AtomicBool>,
) {
    println!("[AvDriverClient] Message loop started");

    while !stop_flag.load(Ordering::SeqCst) {
        // 获取管道句柄
        let pipe_handle = {
            let guard = pipe.lock().unwrap();
            match *guard {
                Some(ref sh) => sh.0,
                None => {
                    println!("[AvDriverClient] Pipe closed, exiting loop");
                    break;
                }
            }
        };

        // 接收消息 (阻塞, 驱动/AVSystem 推送)
        let (msg_type, data) = match recv_pipe_message(pipe_handle) {
            Ok(result) => result,
            Err(e) => {
                // 连接断开
                println!("[AvDriverClient] RecvPipeMessage failed: {}, connection closed", e);
                connected.store(false, Ordering::SeqCst);
                let _ = app_handle.emit("av-driver-disconnected", serde_json::json!({"error": e}));
                break;
            }
        };

        if stop_flag.load(Ordering::SeqCst) {
            break;
        }

        // 解析通知
        let notification = match msg_type {
            AV_PIPE_MSG_PROCESS_NOTIFY => {
                let notify = parse_process_notify(&data);
                AvNotification::Process(notify)
            }
            AV_PIPE_MSG_REG_NOTIFY => {
                let notify = parse_reg_notify(&data);
                AvNotification::Registry(notify)
            }
            AV_PIPE_MSG_INJECTION_NOTIFY => {
                let notify = parse_injection_notify(&data);
                AvNotification::Injection(notify)
            }
            AV_PIPE_MSG_RANSOM_NOTIFY => {
                let notify = parse_ransom_notify(&data);
                AvNotification::Ransom(notify)
            }
            AV_PIPE_MSG_ENDPOINT_NOTIFY => {
                let notify = parse_endpoint_notify(&data);
                AvNotification::EndPoint(notify)
            }
            AV_PIPE_MSG_ERROR => {
                // 错误消息
                let code = if data.len() >= 4 { read_u32_le(&data, 0) } else { 0 };
                let message = if data.len() >= 4 {
                    read_wide_string_fixed(&data, 4, 256)
                } else {
                    String::new()
                };
                println!("[AvDriverClient] Error from AVSystem: {} - {}", code, message);
                continue;
            }
            _ => {
                println!("[AvDriverClient] Unknown message type: 0x{:04X}", msg_type);
                continue;
            }
        };

        // 发送通知到前端：emit 同步触发 listener。
        // listener 内同步执行处理（含弹窗阻塞等待用户决策），返回后才继续下一轮，
        // 与 AVMain 的"弹窗阻塞 → 写决策 → 下一条"完全一致。
        let _ = app_handle.emit("av-driver-notification", &notification);
    }

    connected.store(false, Ordering::SeqCst);
    println!("[AvDriverClient] Message loop exited");
}

/// 将决策发送到管道
fn send_decision_to_pipe(pipe: HANDLE, decision: &AvDecision) -> Result<(), String> {
    match decision {
        AvDecision::Process { notification_id, decision, image_path } => {
            let data = serialize_process_decision(*notification_id, *decision, image_path);
            send_pipe_message(pipe, AV_PIPE_MSG_PROCESS_DECISION, &data)
        }
        AvDecision::Registry { notification_id, decision, key_path } => {
            let data = serialize_reg_decision(*notification_id, *decision, key_path);
            send_pipe_message(pipe, AV_PIPE_MSG_REG_DECISION, &data)
        }
        AvDecision::Injection { notification_id, decision } => {
            let data = serialize_injection_decision(*notification_id, *decision);
            send_pipe_message(pipe, AV_PIPE_MSG_INJECTION_DECISION, &data)
        }
        AvDecision::Ransom { notification_id, decision } => {
            let data = serialize_ransom_decision(*notification_id, *decision);
            send_pipe_message(pipe, AV_PIPE_MSG_RANSOM_DECISION, &data)
        }
        AvDecision::EndPoint { notification_id, decision } => {
            let data = serialize_endpoint_decision(*notification_id, *decision);
            send_pipe_message(pipe, AV_PIPE_MSG_ENDPOINT_DECISION, &data)
        }
    }
}

// ==================== 全局单例 ====================

use once_cell::sync::Lazy;
use std::sync::Mutex as StdMutex;

static AV_DRIVER_CLIENT: Lazy<StdMutex<Option<AvDriverClient>>> = Lazy::new(|| StdMutex::new(None));

/// 启动 AVDriver 客户端
pub fn start_av_driver_client(app_handle: AppHandle) -> Result<(), String> {
    let mut guard = AV_DRIVER_CLIENT.lock().unwrap();
    if guard.is_some() {
        println!("[AvDriverClient] Already running");
        return Ok(());
    }
    let client = AvDriverClient::start(app_handle)?;
    *guard = Some(client);
    Ok(())
}

/// 停止 AVDriver 客户端
pub fn stop_av_driver_client() {
    let mut guard = AV_DRIVER_CLIENT.lock().unwrap();
    if let Some(mut client) = guard.take() {
        client.stop();
    }
}

/// 发送优雅退出请求给 Agent（AV_PIPE_MSG_SHUTDOWN_REQUEST，无数据负载）。
/// Agent 是管理员权限进程，普通用户权限的主程序无法直接终止它；
/// 通过管道发送 shutdown 请求，Agent 收到后自行清理并退出进程。
/// 必须在 stop_av_driver_client() 之前调用（关闭句柄后就发不出去了）。
pub fn send_shutdown_request() -> Result<(), String> {
    let guard = AV_DRIVER_CLIENT.lock().unwrap();
    match guard.as_ref() {
        Some(client) => client.send_shutdown(),
        None => Err("AVDriver client not running".to_string()),
    }
}

/// 发送用户决策
pub fn send_av_decision(decision: AvDecision) -> Result<(), String> {
    let guard = AV_DRIVER_CLIENT.lock().unwrap();
    match guard.as_ref() {
        Some(client) => client.send_decision(decision),
        None => Err("AVDriver client not running".to_string()),
    }
}

/// 检查客户端是否已连接
pub fn is_av_driver_connected() -> bool {
    let guard = AV_DRIVER_CLIENT.lock().unwrap();
    guard.as_ref().map(|c| c.is_connected()).unwrap_or(false)
}
