//! 凭据访问检测模块
//!
//! 检测攻击者试图窃取凭据的行为，基于MITRE ATT&CK框架:
//! - T1003.001: LSASS内存转储
//! - T1003.002: SAM注册表hive导出
//! - T1003.003: NTDS.dit访问
//! - T1555: 凭据存储区访问
//! - T1555.003: 凭据管理器
//! - T1555.004: Windows凭据管理器
//! - T1552.004: DPAPI主密钥导出
//! - T1110: 暴力破解

use std::collections::HashSet;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use regex::Regex;

/// 凭据访问事件类型
#[derive(Debug, Clone, PartialEq)]
pub enum CredentialEvent {
    /// LSASS内存转储 (T1003.001)
    LsassMemoryDump {
        method: String,
        command: String,
        pid: u32,
        process_name: String,
    },
    /// SAM hive导出 (T1003.002)
    SamHiveExport {
        method: String,
        command: String,
        pid: u32,
        process_name: String,
    },
    /// NTDS.dit访问 (T1003.003)
    NtdsDitAccess {
        method: String,
        command: String,
        pid: u32,
        process_name: String,
    },
    /// 凭据管理器枚举 (T1555.004)
    CredentialManagerDump {
        method: String,
        command: String,
        pid: u32,
        process_name: String,
    },
    /// DPAPI主密钥导出 (T1552.004)
    DpapiKeyExport {
        method: String,
        command: String,
        pid: u32,
        process_name: String,
    },
    /// 暴力破解工具 (T1110)
    BruteForceTool {
        tool_name: String,
        command: String,
        pid: u32,
        process_name: String,
    },
    /// LSASS句柄获取 (T1003.001 前兆)
    LsassHandleAccess {
        access_mask: u32,
        pid: u32,
        process_name: String,
    },
}

impl CredentialEvent {
    pub fn severity(&self) -> u8 {
        match self {
            CredentialEvent::LsassMemoryDump { .. } => 98,
            CredentialEvent::SamHiveExport { .. } => 88,
            CredentialEvent::NtdsDitAccess { .. } => 97,
            CredentialEvent::CredentialManagerDump { .. } => 85,
            CredentialEvent::DpapiKeyExport { .. } => 78,
            CredentialEvent::BruteForceTool { .. } => 55,
            CredentialEvent::LsassHandleAccess { .. } => 75,
        }
    }

    pub fn mitre_technique(&self) -> &'static str {
        match self {
            CredentialEvent::LsassMemoryDump { .. } => "T1003.001",
            CredentialEvent::SamHiveExport { .. } => "T1003.002",
            CredentialEvent::NtdsDitAccess { .. } => "T1003.003",
            CredentialEvent::CredentialManagerDump { .. } => "T1555.004",
            CredentialEvent::DpapiKeyExport { .. } => "T1552.004",
            CredentialEvent::BruteForceTool { .. } => "T1110",
            CredentialEvent::LsassHandleAccess { .. } => "T1003.001",
        }
    }

    pub fn description(&self) -> String {
        match self {
            CredentialEvent::LsassMemoryDump { method, .. } => {
                format!("LSASS内存转储 ({}): 凭据窃取行为", method)
            }
            CredentialEvent::SamHiveExport { method, .. } => {
                format!("SAM hive导出 ({}): 本地密码哈希窃取", method)
            }
            CredentialEvent::NtdsDitAccess { method, .. } => {
                format!("NTDS.dit访问 ({}): Active Directory凭据窃取", method)
            }
            CredentialEvent::CredentialManagerDump { method, .. } => {
                format!("凭据管理器枚举 ({}): 保存的凭据窃取", method)
            }
            CredentialEvent::DpapiKeyExport { method, .. } => {
                format!("DPAPI密钥导出 ({}): 加密数据解密密钥窃取", method)
            }
            CredentialEvent::BruteForceTool { tool_name, .. } => {
                format!("暴力破解工具 ({}): 密码猜测攻击", tool_name)
            }
            CredentialEvent::LsassHandleAccess { .. } => {
                "LSASS句柄获取: 可能是凭据窃取前兆".into()
            }
        }
    }
}

/// 检测结果
#[derive(Debug, Clone)]
pub struct CredentialDetection {
    pub event: CredentialEvent,
    pub should_terminate: bool,
    pub should_quarantine: bool,
    pub should_notify: bool,
}

/// 白名单进程
static CRED_WHITELIST: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "svchost.exe", "lsass.exe", "wininit.exe", "services.exe",
        "smss.exe", "winlogon.exe", "csrss.exe",
        "msmpeng.exe", "securityhealthservice.exe",
        "taskmgr.exe", "procmon.exe", "procmon64.exe",
        "system.exe", "idle.exe",
    ])
});

/// DPAPI白名单 - 这些进程正常使用CryptUnprotectData
static DPAPI_WHITELIST: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
        "iexplore.exe", "explorer.exe", "svchost.exe",
        "lsass.exe", "winlogon.exe",
    ])
});

static TRIGGERED_EVENTS: Lazy<Mutex<HashSet<(u32, &'static str)>>> =
    Lazy::new(|| Mutex::new(HashSet::new()));

fn is_whitelisted(process_name: &str, whitelist: &HashSet<&'static str>) -> bool {
    let lower = process_name.to_lowercase();
    whitelist.contains(lower.as_str())
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
// LSASS内存转储检测 (T1003.001)
// =====================================================================

/// 检测procdump转储LSASS
static RE_PROCDUMP_LSASS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)procdump(?:\.exe)?\s+(?:-ma\s+)?(?:-r\s+)?(?:lsass|PID\s*\d+|进程)").unwrap()
});

/// 检测comsvcs.dll MiniDump
static RE_COMSVCS_MINDUMP: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)rundll32\.exe\s+comsvcs\.dll.*MiniDump.*(?:lsass|\d+)").unwrap()
});

/// 检测SQLDumper
static RE_SQLDUMPER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)sqldumper\.exe.*(?:lsass|PID\s*\d+)").unwrap()
});

/// 检测PowerShell Get-Process lsass
static RE_PS_LSASS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:Get-Process|Out-MiniDump).*lsass|MiniDump.*lsass\.dmp").unwrap()
});

/// 检测 Mimikatz 命令
static RE_MIMIKATZ: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)mimikatz|sekurlsa::|lsadump::|kerberos::|crypto::|privilege::debug").unwrap()
});

/// 检测SharpKatz
static RE_SHARPKATZ: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)sharpkatz|Rubeus\.exe|klist|kfu|dump").unwrap()
});

/// 检测LSASS内存转储
pub fn detect_lsass_dump(
    pid: u32,
    process_name: &str,
    command_line: &str,
) -> Option<CredentialDetection> {
    if is_whitelisted(process_name, &CRED_WHITELIST) {
        return None;
    }

    let (method, matched) = if RE_COMSVCS_MINDUMP.is_match(command_line) {
        ("comsvcs.dll MiniDump", true)
    } else if RE_MIMIKATZ.is_match(command_line) {
        ("Mimikatz", true)
    } else if RE_SHARPKATZ.is_match(command_line) {
        ("SharpKatz/Rubeus", true)
    } else if RE_PROCDUMP_LSASS.is_match(command_line) {
        ("procdump", true)
    } else if RE_PS_LSASS.is_match(command_line) {
        ("PowerShell", true)
    } else if RE_SQLDUMPER.is_match(command_line) {
        ("SQLDumper", true)
    } else {
        ("", false)
    };

    if !matched {
        return None;
    }

    if !should_report(pid, "lsass_dump") {
        return None;
    }

    let event = CredentialEvent::LsassMemoryDump {
        method: method.into(),
        command: command_line.into(),
        pid,
        process_name: process_name.into(),
    };

    Some(CredentialDetection {
        event,
        should_terminate: true,
        should_quarantine: true,
        should_notify: true,
    })
}

// =====================================================================
// SAM hive导出检测 (T1003.002)
// =====================================================================

static RE_REG_SAVE_SAM: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)reg\.exe\s+save\s+(?:HKLM\\|HKEY_LOCAL_MACHINE\\)(?:SAM|SECURITY|SYSTEM)").unwrap()
});

static RE_REG_PS_BACKUP: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:Copy-Item|reg\s+save).*\\(?:SAM|SECURITY|SYSTEM)(?:\s|$)").unwrap()
});

static RE_REG_ESAMI: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)reg\s+save.*sam|reg\s+save.*security|reg\s+save.*system").unwrap()
});

/// 检测SAM hive导出
pub fn detect_sam_hive_export(
    pid: u32,
    process_name: &str,
    command_line: &str,
) -> Option<CredentialDetection> {
    if is_whitelisted(process_name, &CRED_WHITELIST) {
        return None;
    }

    let (method, matched) = if RE_REG_SAVE_SAM.is_match(command_line) {
        ("reg.exe save", true)
    } else if RE_REG_PS_BACKUP.is_match(command_line) {
        ("PowerShell", true)
    } else if RE_REG_ESAMI.is_match(command_line) {
        ("reg save", true)
    } else {
        ("", false)
    };

    if !matched {
        return None;
    }

    if !should_report(pid, "sam_hive_export") {
        return None;
    }

    let event = CredentialEvent::SamHiveExport {
        method: method.into(),
        command: command_line.into(),
        pid,
        process_name: process_name.into(),
    };

    Some(CredentialDetection {
        event,
        should_terminate: true,
        should_quarantine: true,
        should_notify: true,
    })
}

// =====================================================================
// NTDS.dit访问检测 (T1003.003)
// =====================================================================

static RE_NTDSUTIL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)ntdsutil.*(?:ifm|installFromMedia|snapshot)").unwrap()
});

static RE_VSS_NTD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)vssadmin\s+create\s+shadow|diskshadow.*shadow.*copy.*ntds|ntds\.dit").unwrap()
});

static RE_NTDSDIT_COPY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)copy.*ntds\.dit|robocopy.*ntds\.dit|xcopy.*ntds\.dit").unwrap()
});

static RE_DSAMIN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)dsamain(?:\.exe)?\s+-dbpath|esentutl.*ntds\.dit").unwrap()
});

/// 检测NTDS.dit访问
pub fn detect_ntds_access(
    pid: u32,
    process_name: &str,
    command_line: &str,
) -> Option<CredentialDetection> {
    if is_whitelisted(process_name, &CRED_WHITELIST) {
        return None;
    }

    let (method, matched) = if RE_NTDSUTIL.is_match(command_line) {
        ("ntdsutil IFM", true)
    } else if RE_VSS_NTD.is_match(command_line) {
        ("vssadmin/diskshadow", true)
    } else if RE_NTDSDIT_COPY.is_match(command_line) {
        ("file copy", true)
    } else if RE_DSAMIN.is_match(command_line) {
        ("dsamain/esentutl", true)
    } else {
        ("", false)
    };

    if !matched {
        return None;
    }

    if !should_report(pid, "ntds_access") {
        return None;
    }

    let event = CredentialEvent::NtdsDitAccess {
        method: method.into(),
        command: command_line.into(),
        pid,
        process_name: process_name.into(),
    };

    Some(CredentialDetection {
        event,
        should_terminate: true,
        should_quarantine: true,
        should_notify: true,
    })
}

// =====================================================================
// 凭据管理器枚举检测 (T1555.004)
// =====================================================================

static RE_CMDKEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)cmdkey\s+/(?:list|add|delete)").unwrap()
});

static RE_VAULTCMD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)vaultcmd\s+/(?:list|listcreds)").unwrap()
});

static RE_PS_CREDMAN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:Get-StoredCredential|Get-Credential|Start-Process.*-Credential|cmdkey|vaultcmd)").unwrap()
});

/// 检测凭据管理器枚举
pub fn detect_cred_manager_dump(
    pid: u32,
    process_name: &str,
    command_line: &str,
) -> Option<CredentialDetection> {
    if is_whitelisted(process_name, &CRED_WHITELIST) {
        return None;
    }

    let (method, matched) = if RE_CMDKEY.is_match(command_line) {
        ("cmdkey", true)
    } else if RE_VAULTCMD.is_match(command_line) {
        ("vaultcmd", true)
    } else if RE_PS_CREDMAN.is_match(command_line) {
        ("PowerShell", true)
    } else {
        ("", false)
    };

    if !matched {
        return None;
    }

    if !should_report(pid, "cred_manager_dump") {
        return None;
    }

    let event = CredentialEvent::CredentialManagerDump {
        method: method.into(),
        command: command_line.into(),
        pid,
        process_name: process_name.into(),
    };

    Some(CredentialDetection {
        event,
        should_terminate: false,
        should_quarantine: false,
        should_notify: true,
    })
}

// =====================================================================
// DPAPI密钥导出检测 (T1552.004)
// =====================================================================

static RE_DPAPI_FILE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:Protect|Local\s+State).*AppData\\Roaming\\Microsoft\\Protect|Microsoft\\Protect\\S-").unwrap()
});

static RE_DPAPI_API: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:CryptUnprotectData|CryptProtectData|DPAPI).*-MaterKey|--maste?rkeys?").unwrap()
});

static RE_PFX_EXPORT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:certutil|certmgr|powershell).*-exportPFX|Export-PfxCertificate|certutil.*-exportcert").unwrap()
});

/// 检测DPAPI密钥导出
pub fn detect_dpapi_export(
    pid: u32,
    process_name: &str,
    command_line: &str,
) -> Option<CredentialDetection> {
    if is_whitelisted(process_name, &DPAPI_WHITELIST) {
        return None;
    }

    let (method, matched) = if RE_DPAPI_FILE.is_match(command_line) {
        ("DPAPI文件访问", true)
    } else if RE_DPAPI_API.is_match(command_line) {
        ("DPAPI API调用", true)
    } else if RE_PFX_EXPORT.is_match(command_line) {
        ("PFX证书导出", true)
    } else {
        ("", false)
    };

    if !matched {
        return None;
    }

    if !should_report(pid, "dpapi_export") {
        return None;
    }

    let event = CredentialEvent::DpapiKeyExport {
        method: method.into(),
        command: command_line.into(),
        pid,
        process_name: process_name.into(),
    };

    Some(CredentialDetection {
        event,
        should_terminate: false,
        should_quarantine: false,
        should_notify: true,
    })
}

// =====================================================================
// 暴力破解工具检测 (T1110)
// =====================================================================

static RE_BRUTE_TOOLS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:hydra|medusa|ncrack|patator|hashcat|john\.exe|johntheripper|crackmapexec|CME\.exe|netexec|nxc)").unwrap()
});

static RE_NET_USE_AUTH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)net\s+(?:use|user|accounts)\s+/user:.*\\.*\s+\$?\S+\s+\S+").unwrap()
});

/// 检测暴力破解工具
pub fn detect_brute_force(
    pid: u32,
    process_name: &str,
    command_line: &str,
) -> Option<CredentialDetection> {
    let combined = format!("{} {}", process_name, command_line);

    let tool_name = if RE_BRUTE_TOOLS.is_match(&combined) {
        RE_BRUTE_TOOLS
            .captures(&combined)
            .and_then(|c| c.get(0))
            .map(|m| m.as_str().to_lowercase())
            .unwrap_or_default()
    } else if RE_NET_USE_AUTH.is_match(command_line) {
        "net use auth".into()
    } else {
        return None;
    };

    if !should_report(pid, "brute_force") {
        return None;
    }

    let event = CredentialEvent::BruteForceTool {
        tool_name,
        command: command_line.into(),
        pid,
        process_name: process_name.into(),
    };

    Some(CredentialDetection {
        event,
        should_terminate: true,
        should_quarantine: false,
        should_notify: true,
    })
}

// =====================================================================
// LSASS句柄获取检测 (T1003.001 前兆)
// =====================================================================

/// 关键访问掩码位
const PROCESS_VM_READ: u32 = 0x0010;
const PROCESS_VM_OPERATION: u32 = 0x0008;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const PROCESS_DUP_HANDLE: u32 = 0x0040;

/// 检测LSASS句柄获取（前兆行为）
///
/// 当非白名单进程尝试获取LSASS进程的VM_READ/VM_OPERATION权限时触发
pub fn detect_lsass_handle_access(
    pid: u32,
    process_name: &str,
    _target_pid: u32,
    target_name: &str,
    access_mask: u32,
) -> Option<CredentialDetection> {
    // 目标必须是LSASS
    if !target_name.eq_ignore_ascii_case("lsass.exe") {
        return None;
    }

    if is_whitelisted(process_name, &CRED_WHITELIST) {
        return None;
    }

    // 检查危险访问权限
    let has_vm_read = (access_mask & PROCESS_VM_READ) != 0;
    let has_vm_operation = (access_mask & PROCESS_VM_OPERATION) != 0;
    let has_dup_handle = (access_mask & PROCESS_DUP_HANDLE) != 0;

    if !has_vm_read && !has_vm_operation && !has_dup_handle {
        return None;
    }

    if !should_report(pid, "lsass_handle") {
        return None;
    }

    let event = CredentialEvent::LsassHandleAccess {
        access_mask,
        pid,
        process_name: process_name.into(),
    };

    Some(CredentialDetection {
        event,
        should_terminate: false,
        should_quarantine: false,
        should_notify: true,
    })
}

// =====================================================================
// 综合检测入口
// =====================================================================

/// 对进程创建事件执行所有凭据访问检测
pub fn check_process_creation(
    pid: u32,
    process_name: &str,
    command_line: &str,
) -> Vec<CredentialDetection> {
    let mut results = Vec::new();

    if let Some(d) = detect_lsass_dump(pid, process_name, command_line) {
        results.push(d);
    }
    if let Some(d) = detect_ntds_access(pid, process_name, command_line) {
        results.push(d);
    }
    if let Some(d) = detect_sam_hive_export(pid, process_name, command_line) {
        results.push(d);
    }
    if let Some(d) = detect_cred_manager_dump(pid, process_name, command_line) {
        results.push(d);
    }
    if let Some(d) = detect_dpapi_export(pid, process_name, command_line) {
        results.push(d);
    }
    if let Some(d) = detect_brute_force(pid, process_name, command_line) {
        results.push(d);
    }

    results
}

/// 清除指定PID的去重记录
pub fn on_process_exit(pid: u32) {
    let mut set = TRIGGERED_EVENTS.lock().unwrap();
    set.retain(|(p, _)| *p != pid);
}

/// 重置所有去重记录
pub fn reset_dedup() {
    TRIGGERED_EVENTS.lock().unwrap().clear();
}
