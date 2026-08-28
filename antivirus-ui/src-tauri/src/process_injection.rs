//! 进程注入检测模块
//!
//! 检测各类进程注入技术，基于MITRE ATT&CK框架:
//! - T1055: 进程注入
//! - T1055.001: 经典进程注入 (CreateRemoteThread)
//! - T1055.002: 镂空进程注入 (Process Hollowing)
//! - T1055.003: 进程注入 (Process Doppelgänging)
//! - T1055.004: APC注入
//! - T1055.012: 进程镂空 (Process Hollowing)
//! - T1055.005: 线程劫持
//!
//! 检测策略:
//! 1. 命令行模式匹配 - 快速检测已知工具调用
//! 2. API调用序列跟踪 - 检测注入链（多步操作组合）
//! 3. ETW事件序列关联 - 基于Threat Intelligence ETW provider

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use once_cell::sync::Lazy;
use regex::Regex;

/// 注入技术类型
#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq)]
pub enum InjectionTechnique {
    /// 经典注入: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
    ClassicRemoteThread,
    /// 进程镂空: CreateProcess(suspended) + NtUnmapViewOfSection + VirtualAllocEx + WriteProcessMemory + SetThreadContext + ResumeThread
    ProcessHollowing,
    /// APC注入: QueueUserAPC / NtQueueApcThread
    ApcInjection,
    /// DLL注入: VirtualAllocEx + WriteProcessMemory(DLL path) + CreateRemoteThread(LoadLibrary)
    DllInjection,
    /// 线程劫持: OpenThread + SuspendThread + GetThreadContext + SetThreadContext + ResumeThread
    ThreadHijacking,
    /// RWX内存映射: NtCreateSection + MapViewOfFile(远程) + WriteProcessMemory
    SectionMapping,
    /// 进程替换: CreateProcess(suspended) + NtUnmapViewOfSection + WriteProcessMemory + ResumeThread
    ProcessReplacement,
}

impl InjectionTechnique {
    pub fn mitre_id(&self) -> &'static str {
        match self {
            InjectionTechnique::ClassicRemoteThread => "T1055.001",
            InjectionTechnique::ProcessHollowing => "T1055.012",
            InjectionTechnique::ApcInjection => "T1055.004",
            InjectionTechnique::DllInjection => "T1055",
            InjectionTechnique::ThreadHijacking => "T1055.005",
            InjectionTechnique::SectionMapping => "T1055",
            InjectionTechnique::ProcessReplacement => "T1055.012",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            InjectionTechnique::ClassicRemoteThread => "经典远程线程注入",
            InjectionTechnique::ProcessHollowing => "进程镂空",
            InjectionTechnique::ApcInjection => "APC注入",
            InjectionTechnique::DllInjection => "DLL注入",
            InjectionTechnique::ThreadHijacking => "线程劫持",
            InjectionTechnique::SectionMapping => "RWX内存段映射注入",
            InjectionTechnique::ProcessReplacement => "进程替换",
        }
    }

    pub fn severity(&self) -> u8 {
        match self {
            InjectionTechnique::ProcessHollowing => 99,
            InjectionTechnique::ProcessReplacement => 95,
            InjectionTechnique::ClassicRemoteThread => 80,
            InjectionTechnique::ThreadHijacking => 85,
            InjectionTechnique::ApcInjection => 78,
            InjectionTechnique::DllInjection => 75,
            InjectionTechnique::SectionMapping => 82,
        }
    }
}

/// API调用事件 (来自ETW或内核回调)
#[derive(Debug, Clone)]
pub struct ApiCallEvent {
    pub source_pid: u32,
    pub source_process: String,
    pub target_pid: u32,
    pub api_name: String,
    pub details: String,
    pub timestamp: Instant,
}

/// 注入检测结果
#[derive(Debug, Clone)]
pub struct InjectionDetection {
    pub technique: InjectionTechnique,
    pub source_pid: u32,
    pub source_process: String,
    pub target_pid: u32,
    pub api_chain: Vec<String>,
    pub description: String,
    pub severity: u8,
    pub should_terminate: bool,
    pub should_notify: bool,
}

/// API调用跟踪器 - 每个源进程维护一个时间窗口内的调用序列
struct ApiCallTracker {
    /// key: (source_pid, target_pid), value: API调用序列
    calls: HashMap<(u32, u32), VecDeque<ApiCallEvent>>,
}

impl ApiCallTracker {
    fn new() -> Self {
        ApiCallTracker {
            calls: HashMap::new(),
        }
    }

    fn add_call(&mut self, event: ApiCallEvent) {
        let key = (event.source_pid, event.target_pid);
        let queue = self.calls.entry(key).or_default();

        // 清理超过30秒的旧调用
        let now = Instant::now();
        while let Some(front) = queue.front() {
            if now.duration_since(front.timestamp) > Duration::from_secs(30) {
                queue.pop_front();
            } else {
                break;
            }
        }

        queue.push_back(event);
    }

    fn get_calls(&self, source_pid: u32, target_pid: u32) -> Vec<String> {
        let key = (source_pid, target_pid);
        match self.calls.get(&key) {
            Some(queue) => queue.iter().map(|e| e.api_name.clone()).collect(),
            None => Vec::new(),
        }
    }

    fn clear_process(&mut self, pid: u32) {
        self.calls.retain(|(src, tgt), _| *src != pid && *tgt != pid);
    }
}

static API_TRACKER: Lazy<Mutex<ApiCallTracker>> =
    Lazy::new(|| Mutex::new(ApiCallTracker::new()));

/// 白名单进程
static INJECTION_WHITELIST: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "svchost.exe", "csrss.exe", "lsass.exe", "wininit.exe",
        "services.exe", "smss.exe", "winlogon.exe",
        "msmpeng.exe", "securityhealthservice.exe",
        "taskmgr.exe", "procmon.exe", "procmon64.exe",
        "explorer.exe", "dwm.exe", "runtimebroker.exe",
        "system.exe",
    ])
});

fn is_whitelisted(process_name: &str) -> bool {
    let lower = process_name.to_lowercase();
    INJECTION_WHITELIST.contains(lower.as_str())
}

// =====================================================================
// 命令行模式匹配 - 检测已知注入工具
// =====================================================================

/// 检测注入工具命令行 (PowerShell Empire, Cobalt Strike, etc.)
static RE_INJECTION_PS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:Invoke-ReflectivePEInjection|Invoke-DllInjection|Invoke-AssemblyInject|Invoke-PSInject|Invoke-CimMethod|Set-RemoteThreadContext|RUNDLL32.*-inject|Out-Shellcode|Out-CompressedDll)").unwrap()
});

/// 检测Meterpreter/metinject
static RE_METERPRETER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:meterpreter|metinject|msfconsole|msfvenom.*inject|shellcode_inject)").unwrap()
});

/// 检测注入器工具
static RE_INJECTOR_TOOL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:injector\.exe|remoteexec\.exe|Inject-PE|Inject-Shellcode|ProcessHollowing\.exe|RunPE\.exe|Hollowing\.exe|dll_inject|APC_Inject|QueueUserAPC)").unwrap()
});

/// 检测CreateRemoteThread via PowerShell
static RE_REMOTE_THREAD_PS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:CreateRemoteThread|NtCreateThreadEx|RtlCreateUserThread|ZwCreateThread)").unwrap()
});

/// 命令行快速检测 - 检测已知注入工具调用
pub fn detect_injection_commandline(
    pid: u32,
    process_name: &str,
    command_line: &str,
) -> Option<InjectionDetection> {
    if is_whitelisted(process_name) {
        return None;
    }

    let (technique, _matched) = if RE_INJECTION_PS.is_match(command_line) {
        (InjectionTechnique::DllInjection, true)
    } else if RE_METERPRETER.is_match(command_line) {
        (InjectionTechnique::ClassicRemoteThread, true)
    } else if RE_INJECTOR_TOOL.is_match(command_line) {
        (InjectionTechnique::ProcessHollowing, true)
    } else if RE_REMOTE_THREAD_PS.is_match(command_line) {
        (InjectionTechnique::ClassicRemoteThread, true)
    } else {
        return None;
    };

    Some(InjectionDetection {
        technique,
        source_pid: pid,
        source_process: process_name.into(),
        target_pid: 0, // 命令行模式无法获取目标PID
        api_chain: vec![command_line.into()],
        description: format!(
            "检测到注入工具调用: {} 使用 {}",
            process_name,
            technique.name()
        ),
        severity: technique.severity(),
        should_terminate: true,
        should_notify: true,
    })
}

// =====================================================================
// API调用序列检测 - 检测注入链
// =====================================================================

/// 定义API名称别名映射
fn normalize_api_name(api: &str) -> &str {
    let lower = api.to_lowercase();
    match lower.as_str() {
        "virtualallocex" | "ntallocatevirtualmemory" => "VirtualAllocEx",
        "writeprocessmemory" | "ntwritevirtualmemory" => "WriteProcessMemory",
        "createremotethread" | "ntcreatethreadex" | "rtlcreateuserthread" => "CreateRemoteThread",
        "queueuserapc" | "ntqueueapcthread" => "QueueUserAPC",
        "ntunmapviewofsection" | "zwmunmapviewofsection" => "NtUnmapViewOfSection",
        "mapviewoffile" | "mapviewoffileex" | "ntmapviewofsection" => "MapViewOfFile",
        "ntcreatesection" | "createsection" | "zwcreatesection" => "NtCreateSection",
        "getthreadcontext" | "ntgetcontextthread" => "GetThreadContext",
        "setthreadcontext" | "ntsetcontextthread" => "SetThreadContext",
        "resumethread" | "ntresumethread" => "ResumeThread",
        "openthread" | "ntopenthread" => "OpenThread",
        "suspendthread" | "ntsuspendthread" => "SuspendThread",
        "openprocess" | "ntopenprocess" => "OpenProcess",
        "createprocess" | "ntcreateuserprocess" | "createprocessasuser" | "createprocesswithtoken" | "createprocesswithlogon" => "CreateProcess",
        _ => api,
    }
}

/// 记录API调用事件 (来自ETW Threat Intelligence provider)
pub fn on_api_call(
    source_pid: u32,
    source_process: &str,
    target_pid: u32,
    api_name: &str,
    details: &str,
) {
    if is_whitelisted(source_process) {
        return;
    }

    let event = ApiCallEvent {
        source_pid,
        source_process: source_process.into(),
        target_pid,
        api_name: normalize_api_name(api_name).into(),
        details: details.into(),
        timestamp: Instant::now(),
    };

    let mut tracker = API_TRACKER.lock().unwrap();
    tracker.add_call(event);

    // 添加后立即检测
    drop(tracker);
    check_injection_chain(source_pid, source_process, target_pid);
}

/// 检测注入链
fn check_injection_chain(
    source_pid: u32,
    source_process: &str,
    target_pid: u32,
) -> Option<InjectionDetection> {
    let tracker = API_TRACKER.lock().unwrap();
    let api_chain = tracker.get_calls(source_pid, target_pid);
    drop(tracker);

    if api_chain.is_empty() {
        return None;
    }

    let api_set: HashSet<&str> = api_chain.iter().map(|s| s.as_str()).collect();

    // 1. 进程镂空链: CreateProcess(suspended) -> NtUnmapViewOfSection -> VirtualAllocEx -> WriteProcessMemory -> SetThreadContext -> ResumeThread
    let has_create_suspended = api_set.contains("CreateProcess");
    let has_unmap = api_set.contains("NtUnmapViewOfSection");
    let has_alloc = api_set.contains("VirtualAllocEx");
    let has_write = api_set.contains("WriteProcessMemory");
    let has_set_context = api_set.contains("SetThreadContext");
    let has_resume = api_set.contains("ResumeThread");

    if has_create_suspended && has_unmap && has_write && has_set_context && has_resume {
        let mut chain = api_chain.clone();
        chain.retain(|api| matches!(
            api.as_str(),
            "CreateProcess" | "NtUnmapViewOfSection" | "VirtualAllocEx"
            | "WriteProcessMemory" | "SetThreadContext" | "ResumeThread"
        ));
        return Some(InjectionDetection {
            technique: InjectionTechnique::ProcessHollowing,
            source_pid,
            source_process: source_process.into(),
            target_pid,
            api_chain: chain,
            description: "检测到完整进程镂空链: 创建挂起进程 -> 取消映射 -> 写入 -> 修改上下文 -> 恢复执行".into(),
            severity: 99,
            should_terminate: true,
            should_notify: true,
        });
    }

    // 2. 经典远程线程注入: VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread
    if has_alloc && has_write && api_set.contains("CreateRemoteThread") {
        let mut chain = api_chain.clone();
        chain.retain(|api| matches!(
            api.as_str(),
            "VirtualAllocEx" | "WriteProcessMemory" | "CreateRemoteThread"
        ));
        return Some(InjectionDetection {
            technique: InjectionTechnique::ClassicRemoteThread,
            source_pid,
            source_process: source_process.into(),
            target_pid,
            api_chain: chain,
            description: "检测到经典远程线程注入: VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread".into(),
            severity: 80,
            should_terminate: true,
            should_notify: true,
        });
    }

    // 3. APC注入: VirtualAllocEx -> WriteProcessMemory -> QueueUserAPC
    if has_alloc && has_write && api_set.contains("QueueUserAPC") {
        let mut chain = api_chain.clone();
        chain.retain(|api| matches!(
            api.as_str(),
            "VirtualAllocEx" | "WriteProcessMemory" | "QueueUserAPC"
        ));
        return Some(InjectionDetection {
            technique: InjectionTechnique::ApcInjection,
            source_pid,
            source_process: source_process.into(),
            target_pid,
            api_chain: chain,
            description: "检测到APC注入: VirtualAllocEx -> WriteProcessMemory -> QueueUserAPC".into(),
            severity: 78,
            should_terminate: true,
            should_notify: true,
        });
    }

    // 4. 线程劫持: OpenThread -> SuspendThread -> GetThreadContext -> SetThreadContext -> ResumeThread
    if api_set.contains("OpenThread") && api_set.contains("SuspendThread")
        && api_set.contains("GetThreadContext") && api_set.contains("SetThreadContext")
        && api_set.contains("ResumeThread")
    {
        let mut chain = api_chain.clone();
        chain.retain(|api| matches!(
            api.as_str(),
            "OpenThread" | "SuspendThread" | "GetThreadContext"
            | "SetThreadContext" | "ResumeThread"
        ));
        return Some(InjectionDetection {
            technique: InjectionTechnique::ThreadHijacking,
            source_pid,
            source_process: source_process.into(),
            target_pid,
            api_chain: chain,
            description: "检测到线程劫持: 打开线程 -> 挂起 -> 获取/修改上下文 -> 恢复".into(),
            severity: 85,
            should_terminate: true,
            should_notify: true,
        });
    }

    // 5. RWX内存段映射注入: NtCreateSection -> MapViewOfFile -> WriteProcessMemory
    if api_set.contains("NtCreateSection") && api_set.contains("MapViewOfFile")
        && api_set.contains("WriteProcessMemory")
    {
        let mut chain = api_chain.clone();
        chain.retain(|api| matches!(
            api.as_str(),
            "NtCreateSection" | "MapViewOfFile" | "WriteProcessMemory"
        ));
        return Some(InjectionDetection {
            technique: InjectionTechnique::SectionMapping,
            source_pid,
            source_process: source_process.into(),
            target_pid,
            api_chain: chain,
            description: "检测到RWX内存段映射注入: NtCreateSection -> MapViewOfFile -> WriteProcessMemory".into(),
            severity: 82,
            should_terminate: true,
            should_notify: true,
        });
    }

    // 6. DLL注入: VirtualAllocEx -> WriteProcessMemory(DLL path) -> CreateRemoteThread(LoadLibrary)
    //    这个和经典注入的区别是写入的内容是DLL路径而非shellcode
    if has_alloc && has_write && api_set.contains("CreateRemoteThread") {
        let mut chain = api_chain.clone();
        chain.retain(|api| matches!(
            api.as_str(),
            "VirtualAllocEx" | "WriteProcessMemory" | "CreateRemoteThread"
        ));
        return Some(InjectionDetection {
            technique: InjectionTechnique::DllInjection,
            source_pid,
            source_process: source_process.into(),
            target_pid,
            api_chain: chain,
            description: "检测到DLL注入: VirtualAllocEx -> WriteProcessMemory(DLL路径) -> CreateRemoteThread(LoadLibrary)".into(),
            severity: 75,
            should_terminate: true,
            should_notify: true,
        });
    }

    // 7. 进程替换: CreateProcess(suspended) -> NtUnmapViewOfSection -> WriteProcessMemory -> ResumeThread (无SetThreadContext)
    if has_create_suspended && has_unmap && has_write && has_resume && !has_set_context {
        let mut chain = api_chain.clone();
        chain.retain(|api| matches!(
            api.as_str(),
            "CreateProcess" | "NtUnmapViewOfSection" | "WriteProcessMemory" | "ResumeThread"
        ));
        return Some(InjectionDetection {
            technique: InjectionTechnique::ProcessReplacement,
            source_pid,
            source_process: source_process.into(),
            target_pid,
            api_chain: chain,
            description: "检测到进程替换: 创建挂起进程 -> 取消映射 -> 写入 -> 恢复执行".into(),
            severity: 95,
            should_terminate: true,
            should_notify: true,
        });
    }

    None
}

// =====================================================================
// 可疑行为模式检测 - 基于ETW Threat Intelligence events
// =====================================================================

/// 检测可疑的内存分配模式
///
/// 当非白名单进程在另一个进程中分配RWX内存时触发
pub fn detect_suspicious_remote_allocation(
    source_pid: u32,
    source_process: &str,
    target_pid: u32,
    target_process: &str,
    protection: u32,
) -> Option<InjectionDetection> {
    if is_whitelisted(source_process) {
        return None;
    }

    // PAGE_EXECUTE_READWRITE = 0x40, PAGE_EXECUTE_WRITECOPY = 0x80
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

    if protection != PAGE_EXECUTE_READWRITE && protection != PAGE_EXECUTE_WRITECOPY {
        return None;
    }

    Some(InjectionDetection {
        technique: InjectionTechnique::ClassicRemoteThread,
        source_pid,
        source_process: source_process.into(),
        target_pid,
        api_chain: vec![format!(
            "VirtualAllocEx(target={}, protection=RWX)",
            target_process
        )],
        description: format!(
            "在远程进程 {} 中分配RWX内存: 可能是注入前兆",
            target_process
        ),
        severity: 70,
        should_terminate: false,
        should_notify: true,
    })
}

/// 检测可疑的远程内存写入
pub fn detect_suspicious_remote_write(
    source_pid: u32,
    source_process: &str,
    target_pid: u32,
    target_process: &str,
    size: usize,
) -> Option<InjectionDetection> {
    if is_whitelisted(source_process) {
        return None;
    }

    // 写入超过4KB的可执行代码到远程进程
    if size < 4096 {
        return None;
    }

    Some(InjectionDetection {
        technique: InjectionTechnique::ClassicRemoteThread,
        source_pid,
        source_process: source_process.into(),
        target_pid,
        api_chain: vec![format!(
            "WriteProcessMemory(target={}, size={})",
            target_process, size
        )],
        description: format!(
            "向远程进程 {} 写入 {} 字节数据: 可能是代码注入",
            target_process, size
        ),
        severity: 65,
        should_terminate: false,
        should_notify: true,
    })
}

// =====================================================================
// 进程退出清理
// =====================================================================

/// 清除指定进程的API调用跟踪记录
pub fn on_process_exit(pid: u32) {
    let mut tracker = API_TRACKER.lock().unwrap();
    tracker.clear_process(pid);
}

/// 重置所有跟踪记录
pub fn reset_tracking() {
    let mut tracker = API_TRACKER.lock().unwrap();
    tracker.calls.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hollowing_detection() {
        reset_tracking();

        // 模拟进程镂空链
        on_api_call(1000, "malware.exe", 2000, "CreateProcess", "suspended");
        on_api_call(1000, "malware.exe", 2000, "NtUnmapViewOfSection", "");
        on_api_call(1000, "malware.exe", 2000, "VirtualAllocEx", "RWX");
        on_api_call(1000, "malware.exe", 2000, "WriteProcessMemory", "4096 bytes");
        on_api_call(1000, "malware.exe", 2000, "SetThreadContext", "");
        on_api_call(1000, "malware.exe", 2000, "ResumeThread", "");

        let detection = check_injection_chain(1000, "malware.exe", 2000);

        assert!(detection.is_some());
        let det = detection.unwrap();
        assert_eq!(det.technique, InjectionTechnique::ProcessHollowing);
        assert_eq!(det.severity, 99);
        assert!(det.should_terminate);

        reset_tracking();
    }

    #[test]
    fn test_classic_injection_detection() {
        reset_tracking();

        on_api_call(1000, "injector.exe", 2000, "VirtualAllocEx", "RWX");
        on_api_call(1000, "injector.exe", 2000, "WriteProcessMemory", "shellcode");
        on_api_call(1000, "injector.exe", 2000, "CreateRemoteThread", "");

        let detection = check_injection_chain(1000, "injector.exe", 2000);

        assert!(detection.is_some());
        let det = detection.unwrap();
        assert_eq!(det.technique, InjectionTechnique::ClassicRemoteThread);

        reset_tracking();
    }

    #[test]
    fn test_whitelist_no_detection() {
        reset_tracking();

        on_api_call(1000, "svchost.exe", 2000, "VirtualAllocEx", "RWX");
        on_api_call(1000, "svchost.exe", 2000, "WriteProcessMemory", "data");
        on_api_call(1000, "svchost.exe", 2000, "CreateRemoteThread", "");

        let detection = check_injection_chain(1000, "svchost.exe", 2000);
        // 白名单进程的调用不会被跟踪
        assert!(detection.is_none());

        reset_tracking();
    }
}
