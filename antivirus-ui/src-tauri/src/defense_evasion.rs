//! 防御规避检测模块
//!
//! 检测攻击者试图绕过或禁用安全工具的行为，基于MITRE ATT&CK框架:
//! - T1562.001: 禁用或修改工具 (Windows Defender)
//! - T1562.002: 禁用Windows事件日志
//! - T1070.001: 清除Windows事件日志
//! - T1070.002: 清除用户历史
//! - T1490: 影子副本删除 (勒索软件加密前步骤)
//! - T1564.001: 隐藏文件属性
//! - T1027: 混淆/编码文件
//! - T1112: 修改注册表 (SafeBoot操作)

use std::collections::HashSet;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use regex::Regex;

/// 防御规避事件类型
#[derive(Debug, Clone, PartialEq)]
pub enum EvasionEvent {
    /// 影子副本删除
    ShadowCopyDeletion {
        method: String,
        command: String,
        pid: u32,
        process_name: String,
    },
 /// 清除事件日志
    ClearEventLog {
        method: String,
        command: String,
        pid: u32,
        process_name: String,
    },
    /// 禁用Windows Defender
    DisableDefender {
        method: String,
        detail: String,
        pid: u32,
        process_name: String,
    },
    /// AMSI绕过
    AmsiBypass {
        method: String,
        detail: String,
        pid: u32,
        process_name: String,
    },
    /// 安全模式/SafeBoot操纵
    SafeModeManipulation {
        method: String,
        command: String,
        pid: u32,
        process_name: String,
    },
    /// 隐藏文件属性
    FileAttributeHiding {
        command: String,
        pid: u32,
        process_name: String,
    },
    /// 编码/混淆命令
    EncodedCommand {
        encoding_type: String,
        command: String,
        pid: u32,
        process_name: String,
    },
}

impl EvasionEvent {
    pub fn severity(&self) -> u8 {
        match self {
            EvasionEvent::ShadowCopyDeletion { .. } => 98,
            EvasionEvent::ClearEventLog { .. } => 65,
            EvasionEvent::DisableDefender { .. } => 82,
            EvasionEvent::AmsiBypass { .. } => 85,
            EvasionEvent::SafeModeManipulation { .. } => 95,
            EvasionEvent::FileAttributeHiding { .. } => 35,
            EvasionEvent::EncodedCommand { .. } => 60,
        }
    }

    pub fn mitre_technique(&self) -> &'static str {
        match self {
            EvasionEvent::ShadowCopyDeletion { .. } => "T1490",
            EvasionEvent::ClearEventLog { .. } => "T1070.001",
            EvasionEvent::DisableDefender { .. } => "T1562.001",
            EvasionEvent::AmsiBypass { .. } => "T1562.001",
            EvasionEvent::SafeModeManipulation { .. } => "T1112",
            EvasionEvent::FileAttributeHiding { .. } => "T1564.001",
            EvasionEvent::EncodedCommand { .. } => "T1027",
        }
    }

    pub fn description(&self) -> String {
        match self {
            EvasionEvent::ShadowCopyDeletion { method, .. } => {
                format!("影子副本删除 ({}): 勒索软件加密前典型行为", method)
            }
            EvasionEvent::ClearEventLog { method, .. } => {
                format!("清除事件日志 ({}): 攻击者试图清除痕迹", method)
            }
            EvasionEvent::DisableDefender { method, .. } => {
                format!("禁用Windows Defender ({}): 安全工具被关闭", method)
            }
            EvasionEvent::AmsiBypass { method, .. } => {
                format!("AMSI绕过 ({}): 脚本扫描被绕过", method)
            }
            EvasionEvent::SafeModeManipulation { method, .. } => {
                format!("安全模式操纵 ({}): 可能是勒索软件SafeBoot攻击", method)
            }
            EvasionEvent::FileAttributeHiding { .. } => {
                "隐藏文件属性: 文件被设置为隐藏".into()
            }
            EvasionEvent::EncodedCommand { encoding_type, .. } => {
                format!("编码命令 ({}): 可能的混淆执行", encoding_type)
            }
        }
    }
}

/// 检测结果
#[derive(Debug, Clone)]
pub struct EvasionDetection {
    pub event: EvasionEvent,
    pub should_terminate: bool,
    pub should_notify: bool,
}

/// 白名单进程 - 这些进程执行相关操作时可能合法
static DEFENDER_WHITELIST: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "svchost.exe", "csrss.exe", "lsass.exe", "wininit.exe",
        "services.exe", "smss.exe", "winlogon.exe",
        "msmpeng.exe", "msascui.exe", "securityhealthservice.exe",
        "securityhealthsystray.exe", "tiworker.exe", "trustedinstaller.exe",
        "defenderservice.exe",
    ])
});

/// 已触发事件去重 (PID + event_type)
static TRIGGERED_EVENTS: Lazy<Mutex<HashSet<(u32, &'static str)>>> =
    Lazy::new(|| Mutex::new(HashSet::new()));

fn is_whitelisted(process_name: &str) -> bool {
    let lower = process_name.to_lowercase();
    DEFENDER_WHITELIST.contains(lower.as_str())
}

fn should_report(pid: u32, event_key: &'static str) -> bool {
    let mut set = TRIGGERED_EVENTS.lock().unwrap();
    let key = (pid, event_key);
    if set.contains(&key) {
        return false;
    }
    set.insert(key);
    true
}

// =====================================================================
// 影子副本删除检测 (T1490)
// =====================================================================

static RE_SHADOW_VSSADMIN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)vssadmin\s+(?:delete\s+shadows|delete\s+shadowstorage)").unwrap()
});

static RE_SHADOW_WMIC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)wmic\s+shadowcopy\s+(?:delete|call\s+delete)").unwrap()
});

static RE_SHADOW_WBADMIN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)wbadmin\s+(?:delete\s+(?:catalog|backup)|stop\s+job)").unwrap()
});

static RE_SHADOW_PS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:Get-WmiObject|Get-CimInstance).*ShadowCopy|Remove-WmiObject.*ShadowCopy|(?:vssadmin|vss)\s.*delete").unwrap()
});

static RE_SHADOW_DISKSHADOW: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)diskshadow.*(?:delete\s+shadows|remove\s+shadows)").unwrap()
});

/// 检测影子副本删除行为
pub fn detect_shadow_copy_deletion(
    pid: u32,
    process_name: &str,
    command_line: &str,
) -> Option<EvasionDetection> {
    if is_whitelisted(process_name) {
        return None;
    }

    let (method, matched) = if RE_SHADOW_VSSADMIN.is_match(command_line) {
        ("vssadmin", true)
    } else if RE_SHADOW_WMIC.is_match(command_line) {
        ("wmic", true)
    } else if RE_SHADOW_WBADMIN.is_match(command_line) {
        ("wbadmin", true)
    } else if RE_SHADOW_PS.is_match(command_line) {
        ("powershell", true)
    } else if RE_SHADOW_DISKSHADOW.is_match(command_line) {
        ("diskshadow", true)
    } else {
        ("", false)
    };

    if !matched {
        return None;
    }

    if !should_report(pid, "shadow_copy_deletion") {
        return None;
    }

    let event = EvasionEvent::ShadowCopyDeletion {
        method: method.into(),
        command: command_line.into(),
        pid,
        process_name: process_name.into(),
    };

    Some(EvasionDetection {
        event,
        should_terminate: true,
        should_notify: true,
    })
}

// =====================================================================
// 清除事件日志检测 (T1070.001)
// =====================================================================

static RE_CLEARLOG_WEVTUTIL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)wevtutil\s+(?:cl|clear-log)").unwrap()
});

static RE_CLEARLOG_PS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:Clear-EventLog|Limit-EventLog|Remove-EventLog|Clear-WinEvent)").unwrap()
});

static RE_CLEARLOG_AUDITPOL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)auditpol\s+/(?:clear|remove)").unwrap()
});

/// 检测清除事件日志行为
pub fn detect_log_clearing(
    pid: u32,
    process_name: &str,
    command_line: &str,
) -> Option<EvasionDetection> {
    if is_whitelisted(process_name) {
        return None;
    }

    let (method, matched) = if RE_CLEARLOG_WEVTUTIL.is_match(command_line) {
        ("wevtutil", true)
    } else if RE_CLEARLOG_PS.is_match(command_line) {
        ("powershell", true)
    } else if RE_CLEARLOG_AUDITPOL.is_match(command_line) {
        ("auditpol", true)
    } else {
        ("", false)
    };

    if !matched {
        return None;
    }

    if !should_report(pid, "clear_event_log") {
        return None;
    }

    let event = EvasionEvent::ClearEventLog {
        method: method.into(),
        command: command_line.into(),
        pid,
        process_name: process_name.into(),
    };

    Some(EvasionDetection {
        event,
        should_terminate: false,
        should_notify: true,
    })
}

// =====================================================================
// 禁用Windows Defender检测 (T1562.001)
// =====================================================================

static RE_DISABLE_DEFENDER_REG: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:Windows\s+Defender|Microsoft\s+Defender).*(?:DisableAntiSpyware|DisableBehaviorMonitor|DisableRealtimeMonitoring|DisableIOAVProtection|DisableOnAccessProtection|DisableRoutinelyTakingAction)").unwrap()
});

static RE_DISABLE_DEFENDER_PS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)Set-MpPreference\s+(?:-?DisableRealtimeMonitoring|-\s*DisableBehaviorMonitoring|-\s*DisableIOAVProtection|-\s*DisableScriptScanning|-\s*DisableRemovableDriveScanning)\s+([Tt]rue|1)").unwrap()
});

static RE_DISABLE_DEFENDER_SC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:sc\s+(?:stop|config)|net\s+stop)\s+(?:WinDefend|MsMpSvc)").unwrap()
});

static RE_DISABLE_DEFENDER_TASKKILL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)taskkill\s+(?:/f\s+)?/im\s+(?:MsMpEng\.exe|MSASCui\.exe|SecurityHealthService\.exe|MpCmdRun\.exe)").unwrap()
});

/// 检测禁用Windows Defender行为
pub fn detect_defender_disabling(
    pid: u32,
    process_name: &str,
    command_line: &str,
) -> Option<EvasionDetection> {
    if is_whitelisted(process_name) {
        return None;
    }

    let (method, detail) = if RE_DISABLE_DEFENDER_PS.is_match(command_line) {
        ("Set-MpPreference", "PowerShell禁用Defender实时监控")
    } else if RE_DISABLE_DEFENDER_SC.is_match(command_line) {
        ("sc/net", "服务停止/禁用Defender服务")
    } else if RE_DISABLE_DEFENDER_TASKKILL.is_match(command_line) {
        ("taskkill", "强杀Defender进程")
    } else if RE_DISABLE_DEFENDER_REG.is_match(command_line) {
        ("registry", "注册表禁用Defender")
    } else {
        return None;
    };

    if !should_report(pid, "disable_defender") {
        return None;
    }

    let event = EvasionEvent::DisableDefender {
        method: method.into(),
        detail: detail.into(),
        pid,
        process_name: process_name.into(),
    };

    Some(EvasionDetection {
        event,
        should_terminate: true,
        should_notify: true,
    })
}

// =====================================================================
// 安全模式/SafeBoot操纵检测 (T1112 + T1543.003)
// BlackMatter/REvil勒索软件专用技术
// =====================================================================

static RE_SAFEMODE_BCDEDIT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)bcdedit\s+/(?:set|deletevalue)\s+(?:\{.*\}\s+)?safeboot").unwrap()
});

static RE_SAFEMODE_REG: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:HKLM|HKEY_LOCAL_MACHINE)\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal|HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network").unwrap()
});

/// 检测安全模式操纵行为
pub fn detect_safemode_manipulation(
    pid: u32,
    process_name: &str,
    command_line: &str,
) -> Option<EvasionDetection> {
    if is_whitelisted(process_name) {
        return None;
    }

    let (method, matched) = if RE_SAFEMODE_BCDEDIT.is_match(command_line) {
        ("bcdedit", true)
    } else if RE_SAFEMODE_REG.is_match(command_line) {
        ("registry", true)
    } else {
        ("", false)
    };

    if !matched {
        return None;
    }

    if !should_report(pid, "safemode_manipulation") {
        return None;
    }

    let event = EvasionEvent::SafeModeManipulation {
        method: method.into(),
        command: command_line.into(),
        pid,
        process_name: process_name.into(),
    };

    Some(EvasionDetection {
        event,
        should_terminate: true,
        should_notify: true,
    })
}

// =====================================================================
// 隐藏文件属性检测 (T1564.001)
// =====================================================================

static RE_HIDDEN_ATTRIB: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)attrib\s+(?:\+\s*[hs]|-\s*[hs]).*\.[a-z0-9]+").unwrap()
});

static RE_HIDDEN_PS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:Set-ItemProperty|New-ItemProperty).*Attributes.*(?:Hidden|System)").unwrap()
});

/// 检测隐藏文件属性设置行为
pub fn detect_file_attribute_hiding(
    pid: u32,
    process_name: &str,
    command_line: &str,
) -> Option<EvasionDetection> {
    if is_whitelisted(process_name) {
        return None;
    }

    let matched = RE_HIDDEN_ATTRIB.is_match(command_line)
        || RE_HIDDEN_PS.is_match(command_line);

    if !matched {
        return None;
    }

    if !should_report(pid, "file_attribute_hiding") {
        return None;
    }

    let event = EvasionEvent::FileAttributeHiding {
        command: command_line.into(),
        pid,
        process_name: process_name.into(),
    };

    Some(EvasionDetection {
        event,
        should_terminate: false,
        should_notify: true,
    })
}

// =====================================================================
// 编码/混淆命令检测 (T1027)
// =====================================================================

static RE_ENCODED_PS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:-Enc|-EncodedCommand|-e\s+)\s+([A-Za-z0-9+/=]{20,})").unwrap()
});

static RE_ENCODED_CERTUTIL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)certutil\s+-decode|certutil\s+-decodehex").unwrap()
});

static RE_BASE64_PS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\[Convert\]::FromBase64String|FromBase64String\(").unwrap()
});

/// 检测编码/混淆命令行为
pub fn detect_encoded_command(
    pid: u32,
    process_name: &str,
    command_line: &str,
) -> Option<EvasionDetection> {
    if is_whitelisted(process_name) {
        return None;
    }

    let (encoding_type, matched) = if RE_ENCODED_PS.is_match(command_line) {
        ("PowerShell EncodedCommand", true)
    } else if RE_ENCODED_CERTUTIL.is_match(command_line) {
        ("certutil decode", true)
    } else if RE_BASE64_PS.is_match(command_line) {
        ("PowerShell Base64", true)
    } else {
        ("", false)
    };

    if !matched {
        return None;
    }

    // 不去重 - 编码命令可能多次执行
    let event = EvasionEvent::EncodedCommand {
        encoding_type: encoding_type.into(),
        command: command_line.into(),
        pid,
        process_name: process_name.into(),
    };

    Some(EvasionDetection {
        event,
        should_terminate: false,
        should_notify: true,
    })
}

// =====================================================================
// 综合检测入口
// =====================================================================

/// 对进程创建事件执行所有防御规避检测
pub fn check_process_creation(
    pid: u32,
    process_name: &str,
    command_line: &str,
) -> Vec<EvasionDetection> {
    let mut results = Vec::new();

    // 按严重性从高到低检测
    if let Some(d) = detect_shadow_copy_deletion(pid, process_name, command_line) {
        results.push(d);
    }
    if let Some(d) = detect_safemode_manipulation(pid, process_name, command_line) {
        results.push(d);
    }
    if let Some(d) = detect_defender_disabling(pid, process_name, command_line) {
        results.push(d);
    }
    if let Some(d) = detect_log_clearing(pid, process_name, command_line) {
        results.push(d);
    }
    if let Some(d) = detect_file_attribute_hiding(pid, process_name, command_line) {
        results.push(d);
    }
    if let Some(d) = detect_encoded_command(pid, process_name, command_line) {
        results.push(d);
    }

    results
}

/// 清除指定PID的去重记录（进程退出时调用）
pub fn on_process_exit(pid: u32) {
    let mut set = TRIGGERED_EVENTS.lock().unwrap();
    set.retain(|(p, _)| *p != pid);
}

/// 重置所有去重记录
pub fn reset_dedup() {
    TRIGGERED_EVENTS.lock().unwrap().clear();
}
