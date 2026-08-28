//! Melix 端点防护 IPC 客户端 — AVGuard（管理员）作为桥接层，替代 Melix.UI
//!
//! 主程序（普通权限）无法直接连接 Melix.Service 的命名管道 `\\.\pipe\Melix.Control`，
//! 因此由 AVGuard（管理员权限）作为中转：主程序向 AVGuardPipe 发命令，
//! AVGuard 在此实现 Melix 客户端协议，代为读写 HIPS 防护规则/设置/信任并处理拦截决策。
//!
//! 协议（见 Melix.Core/Ipc/IpcMessage.cs）：
//!   - 命名管道：`\\.\pipe\Melix.Control`
//!   - 帧格式：每条 `IpcMessage` 序列化为一行 JSON，以 `\n` 结尾
//!   - 信封：`{ "type": "<IpcMessageType>", "payload": "<JSON字符串>" }`
//!   - 序列化使用 camelCase 命名策略

#![cfg(windows)]

use std::time::Duration;

use serde::{Deserialize, Serialize};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::WaitNamedPipeW;

pub const MELIX_PIPE_NAME: &str = r"\\.\pipe\Melix.Control";
const CONNECT_TIMEOUT_MS: u32 = 5000;
const READ_TIMEOUT_MS: u32 = 10000;

// ==================== 协议枚举 ====================

/// IpcMessageType（与 Melix.Core/Ipc/IpcMessage.cs 一致）。
/// 注意：.NET System.Text.Json 默认把枚举序列化为**数字**（raw 中 `"type":2`），
/// 因此这里必须按底层数字值反序列化，不能用字符串。
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum IpcMessageType {
    PromptRequest = 0,
    PromptResponse = 1,
    LogEntry = 2,
    BlockNotification = 3,
    Hello = 4,
    RulesRequest = 5,
    RulesResponse = 6,
    DeleteRule = 7,
    AddRule = 8,
    SettingsRequest = 9,
    SettingsResponse = 10,
    SettingsUpdate = 11,
    TrustListRequest = 12,
    TrustListResponse = 13,
    AddTrust = 14,
    RemoveTrust = 15,
    EventStream = 16,
    CompositeRulesRequest = 17,
    CompositeRulesResponse = 18,
    AddCompositeRule = 19,
    DeleteCompositeRule = 20,
    ToggleCompositeRule = 21,
}

impl IpcMessageType {
    pub fn name(&self) -> &'static str {
        match self {
            IpcMessageType::PromptRequest => "PromptRequest",
            IpcMessageType::PromptResponse => "PromptResponse",
            IpcMessageType::LogEntry => "LogEntry",
            IpcMessageType::BlockNotification => "BlockNotification",
            IpcMessageType::Hello => "Hello",
            IpcMessageType::RulesRequest => "RulesRequest",
            IpcMessageType::RulesResponse => "RulesResponse",
            IpcMessageType::DeleteRule => "DeleteRule",
            IpcMessageType::AddRule => "AddRule",
            IpcMessageType::SettingsRequest => "SettingsRequest",
            IpcMessageType::SettingsResponse => "SettingsResponse",
            IpcMessageType::SettingsUpdate => "SettingsUpdate",
            IpcMessageType::TrustListRequest => "TrustListRequest",
            IpcMessageType::TrustListResponse => "TrustListResponse",
            IpcMessageType::AddTrust => "AddTrust",
            IpcMessageType::RemoveTrust => "RemoveTrust",
            IpcMessageType::EventStream => "EventStream",
            IpcMessageType::CompositeRulesRequest => "CompositeRulesRequest",
            IpcMessageType::CompositeRulesResponse => "CompositeRulesResponse",
            IpcMessageType::AddCompositeRule => "AddCompositeRule",
            IpcMessageType::DeleteCompositeRule => "DeleteCompositeRule",
            IpcMessageType::ToggleCompositeRule => "ToggleCompositeRule",
        }
    }
}

/// 事件类型（与 Melix.Core/Models/EventType.cs 一致）。
/// payload 内序列化为**字符串**（如 "ProcessCreate"），规则中也可能为数字，两者都支持。
#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum EventType {
    ProcessCreate,
    ProcessTerminate,
    RemoteThread,
    ImageLoad,
    FileWrite,
    FileDelete,
    RegistryWrite,
    NetworkConnect,
    SelfProtect,
    MemoryAlloc,
    OpenProcess,
    WriteMemory,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::ProcessCreate => "ProcessCreate",
            EventType::ProcessTerminate => "ProcessTerminate",
            EventType::RemoteThread => "RemoteThread",
            EventType::ImageLoad => "ImageLoad",
            EventType::FileWrite => "FileWrite",
            EventType::FileDelete => "FileDelete",
            EventType::RegistryWrite => "RegistryWrite",
            EventType::NetworkConnect => "NetworkConnect",
            EventType::SelfProtect => "SelfProtect",
            EventType::MemoryAlloc => "MemoryAlloc",
            EventType::OpenProcess => "OpenProcess",
            EventType::WriteMemory => "WriteMemory",
        }
    }
}

impl<'de> Deserialize<'de> for EventType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Num(u32),
            Str(String),
        }
        match Repr::deserialize(deserializer)? {
            Repr::Num(n) => match n {
                0 => Ok(EventType::ProcessCreate),
                1 => Ok(EventType::ProcessTerminate),
                2 => Ok(EventType::RemoteThread),
                3 => Ok(EventType::ImageLoad),
                4 => Ok(EventType::FileWrite),
                5 => Ok(EventType::FileDelete),
                6 => Ok(EventType::RegistryWrite),
                7 => Ok(EventType::NetworkConnect),
                8 => Ok(EventType::SelfProtect),
                9 => Ok(EventType::MemoryAlloc),
                10 => Ok(EventType::OpenProcess),
                11 => Ok(EventType::WriteMemory),
                _ => Err(serde::de::Error::custom(format!("invalid event num {n}"))),
            },
            Repr::Str(s) => match s.as_str() {
                "ProcessCreate" => Ok(EventType::ProcessCreate),
                "ProcessTerminate" => Ok(EventType::ProcessTerminate),
                "RemoteThread" => Ok(EventType::RemoteThread),
                "ImageLoad" => Ok(EventType::ImageLoad),
                "FileWrite" => Ok(EventType::FileWrite),
                "FileDelete" => Ok(EventType::FileDelete),
                "RegistryWrite" => Ok(EventType::RegistryWrite),
                "NetworkConnect" => Ok(EventType::NetworkConnect),
                "SelfProtect" => Ok(EventType::SelfProtect),
                "MemoryAlloc" => Ok(EventType::MemoryAlloc),
                "OpenProcess" => Ok(EventType::OpenProcess),
                "WriteMemory" => Ok(EventType::WriteMemory),
                _ => Err(serde::de::Error::custom(format!("invalid event {s}"))),
            },
        }
    }
}

/// 裁决动作（与 Melix.Core/Models/VerdictAction.cs 一致）。
/// 可能被序列化为数字(0/1/2)或字符串("Allow"/"Block"/"Ask")，这里两者都支持。
#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum VerdictAction {
    Allow,
    Block,
    Ask,
}

impl VerdictAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            VerdictAction::Allow => "allow",
            VerdictAction::Block => "block",
            VerdictAction::Ask => "ask",
        }
    }
}

impl<'de> Deserialize<'de> for VerdictAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Num(u32),
            Str(String),
        }
        match Repr::deserialize(deserializer)? {
            Repr::Num(n) => match n {
                0 => Ok(VerdictAction::Allow),
                1 => Ok(VerdictAction::Block),
                2 => Ok(VerdictAction::Ask),
                _ => Err(serde::de::Error::custom(format!("invalid verdict num {n}"))),
            },
            Repr::Str(s) => match s.to_ascii_lowercase().as_str() {
                "allow" => Ok(VerdictAction::Allow),
                "block" => Ok(VerdictAction::Block),
                "ask" => Ok(VerdictAction::Ask),
                _ => Err(serde::de::Error::custom(format!("invalid verdict {s}"))),
            },
        }
    }
}

// ==================== 信封 ====================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcMessage {
    #[serde(rename = "type")]
    pub r#type: IpcMessageType,
    pub payload: String,
}

impl IpcMessage {
    fn new<T: Serialize>(r#type: IpcMessageType, payload: &T) -> Self {
        IpcMessage {
            r#type,
            payload: serde_json::to_string(payload).unwrap_or_default(),
        }
    }
    fn from_json(r#type: IpcMessageType, json: &str) -> Self {
        IpcMessage {
            r#type,
            payload: json.to_string(),
        }
    }
    fn serialize(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

// ==================== 负载结构 ====================

/// 防护规则（与 Melix.Core/Models/DefenseRule.cs 一致）。
/// 服务端序列化使用 camelCase，因此字段统一为 camelCase 命名。
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DefenseRule {
    pub id: String,
    pub actor_path: Option<String>,
    #[serde(rename = "type")]
    pub r#type: Option<EventType>,
    pub target_pattern: Option<String>,
    pub command_line_pattern: Option<String>,
    pub actor_hashes: Option<Vec<String>>,
    pub target_hashes: Option<Vec<String>>,
    pub require_unsigned: Option<bool>,
    pub action: VerdictAction,
    pub note: Option<String>,
    pub created_utc: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PromptResponsePayload {
    pub event_id: String,
    pub action: VerdictAction,
    pub remember: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RulesResponsePayload {
    pub rules: Vec<DefenseRule>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeleteRulePayload {
    pub rule_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AddRulePayload {
    pub actor_path: Option<String>,
    #[serde(rename = "type")]
    pub r#type: Option<EventType>,
    pub target_pattern: Option<String>,
    pub action: VerdictAction,
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HelloPayload {
    pub process_id: u32,
    pub role: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TrustListResponsePayload {
    pub entries: Vec<DefenseRule>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AddTrustPayload {
    pub actor_path: String,
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RemoveTrustPayload {
    pub rule_id: String,
}

// ==================== 管道客户端 ====================

pub struct MelixClient {
    handle: HANDLE,
}

impl MelixClient {
    /// 连接到 Melix.Service 命名管道（阻塞，带超时）。AVGuard 以管理员权限运行，可成功连接。
    pub fn connect() -> Result<Self, String> {
        unsafe {
            let path: Vec<u16> = MELIX_PIPE_NAME.encode_utf16().chain(Some(0)).collect();
            let pipe_path = PCWSTR(path.as_ptr());

            let wait_ok = WaitNamedPipeW(pipe_path, CONNECT_TIMEOUT_MS).as_bool();
            if !wait_ok {
                let err = GetLastError();
                if err.0 == 2 {
                    return Err("MELIX_SERVICE_NOT_RUNNING".to_string());
                }
                return Err(format!("WaitNamedPipe failed: {}", err.0));
            }

            let handle = CreateFileW(
                pipe_path,
                0x80000000u32 | 0x40000000u32,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            .map_err(|e| format!("CreateFileW failed: {}", e))?;
            Ok(MelixClient { handle })
        }
    }

    /// 发送握手（Hello），角色为 ui（AVGuard 替代 Melix.UI 作为 UI 客户端）。
    pub fn hello(&mut self, process_id: u32) -> Result<(), String> {
        let payload = HelloPayload {
            process_id,
            role: "ui".to_string(),
        };
        self.send(IpcMessageType::Hello, &payload)
    }

    pub fn send<T: Serialize>(&mut self, r#type: IpcMessageType, payload: &T) -> Result<(), String> {
        let msg = IpcMessage::new(r#type, payload);
        self.send_raw(&msg.serialize())
    }

    pub fn send_json(&mut self, r#type: IpcMessageType, payload_json: &str) -> Result<(), String> {
        let msg = IpcMessage::from_json(r#type, payload_json);
        self.send_raw(&msg.serialize())
    }

    fn send_raw(&mut self, line: &str) -> Result<(), String> {
        let mut buf = line.as_bytes().to_vec();
        buf.push(b'\n');
        let mut written = 0u32;
        unsafe {
            WriteFile(self.handle, Some(&buf), Some(&mut written), None).map_err(|e| e.to_string())?;
        }
        if written != buf.len() as u32 {
            return Err(format!("short write: {} / {}", written, buf.len()));
        }
        Ok(())
    }

    pub fn request(
        &mut self,
        req_type: IpcMessageType,
        payload: &impl Serialize,
        resp_type: IpcMessageType,
    ) -> Result<IpcMessage, String> {
        self.send(req_type, payload)?;
        // 循环读取，跳过 Hello/LogEntry/EventStream 等非目标推送，直到拿到想要的响应类型。
        // 用较短超时避免在高频事件推送下长时间占锁/卡死。
        let deadline = std::time::Instant::now() + Duration::from_millis(3000);
        let mut skipped = 0u32;
        loop {
            if std::time::Instant::now() > deadline {
                return Err(format!("request response timeout after skipping {skipped} msgs"));
            }
            let msg = match self.read_line_timeout(500) {
                Ok(m) => m,
                Err(e) => return Err(format!("request read: {e}")),
            };
            if msg.r#type == resp_type {
                return Ok(msg);
            }
            skipped += 1;
            // 非目标消息(Hello/事件推送)：继续读下一条
        }
    }

    pub fn read_line(&mut self) -> Result<IpcMessage, String> {
        self.read_line_timeout(READ_TIMEOUT_MS as u64)
    }

    /// 带可配置超时(毫秒)读取一行。超时返回 Err("read timeout")。
    pub fn read_line_timeout(&mut self, timeout_ms: u64) -> Result<IpcMessage, String> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            if std::time::Instant::now() > deadline {
                return Err("read timeout".to_string());
            }
            let mut read = 0u32;
            let hr = unsafe { ReadFile(self.handle, Some(&mut byte), Some(&mut read), None) };
            if let Err(e) = hr {
                return Err(format!("ReadFile failed: {}", e));
            }
            if read == 0 {
                return Err("pipe closed".to_string());
            }
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
        }
        let text = String::from_utf8_lossy(&line);
        if text.trim().is_empty() {
            return Err("empty message".to_string());
        }
        serde_json::from_str(&text).map_err(|e| {
            // 诊断：打印完整行 + 长度 + 是否含内嵌换行，定位协议/编码问题
            let has_nl = text.contains('\n');
            format!("parse message: {e} | len={} hasNL={} raw={}", line.len(), has_nl, text)
        })
    }
}

impl Drop for MelixClient {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.handle); }
    }
}

// MelixClient 封装了 HANDLE（原始指针），但命名管道 handle 可以跨线程传递使用，
// 且我们的所有访问都通过互斥锁串行化，因此可以安全地在线程间共享。
unsafe impl Send for MelixClient {}
