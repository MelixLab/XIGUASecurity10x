use serde::{Deserialize, Serialize};
use winreg::enums::*;
use winreg::RegKey;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SystemIssue {
    pub id: String,
    pub category: String,
    pub name: String,
    pub description: String,
    pub path: String,
    pub current_value: Option<String>,
    pub expected_value: Option<String>,
    pub severity: String,
    pub can_fix: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SystemRepairSummary {
    pub total: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub fixed: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SystemRepairResult {
    pub issues: Vec<SystemIssue>,
    pub summary: SystemRepairSummary,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FixResult {
    pub success: bool,
    pub fixed_ids: Vec<String>,
    pub failed_ids: Vec<String>,
    pub message: String,
}

/// 读取 HKLM/HKCU 下指定键的 DWORD 值，返回字符串形式
fn read_dword(hive: &str, subkey: &str, value: &str) -> Option<String> {
    let key = match hive {
        "HKLM" => RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(subkey).ok()?,
        "HKCU" => RegKey::predef(HKEY_CURRENT_USER).open_subkey(subkey).ok()?,
        "HKU" => RegKey::predef(HKEY_USERS).open_subkey(subkey).ok()?,
        _ => return None,
    };
    key.get_value::<u32, _>(value).ok().map(|v| v.to_string())
}

/// 写入 HKLM/HKCU 下指定键的 DWORD 值
fn write_dword(hive: &str, subkey: &str, value: &str, data: u32) -> bool {
    let key = match hive {
        "HKLM" => RegKey::predef(HKEY_LOCAL_MACHINE).create_subkey(subkey).ok().map(|(k, _)| k),
        "HKCU" => RegKey::predef(HKEY_CURRENT_USER).create_subkey(subkey).ok().map(|(k, _)| k),
        "HKU" => RegKey::predef(HKEY_USERS).create_subkey(subkey).ok().map(|(k, _)| k),
        _ => None,
    };
    match key {
        Some(k) => k.set_value(value, &data).is_ok(),
        None => false,
    }
}

/// 读取字符串值
fn read_string(hive: &str, subkey: &str, value: &str) -> Option<String> {
    let key = match hive {
        "HKLM" => RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(subkey).ok()?,
        "HKCU" => RegKey::predef(HKEY_CURRENT_USER).open_subkey(subkey).ok()?,
        "HKU" => RegKey::predef(HKEY_USERS).open_subkey(subkey).ok()?,
        _ => return None,
    };
    key.get_value::<String, _>(value).ok()
}

/// 检查某键值是否存在，并返回对应 SystemIssue
fn check_registry_policy(
    issues: &mut Vec<SystemIssue>,
    category: &str,
    name: &str,
    description: &str,
    hive: &str,
    subkey: &str,
    value: &str,
    expected_value: &str,
    severity: &str,
) {
    let current = read_dword(hive, subkey, value);
    if current.as_deref() == Some(expected_value) || current.is_none() {
        return;
    }
    issues.push(SystemIssue {
        id: format!("{}\\{}\\{}", hive, subkey, value),
        category: category.to_string(),
        name: name.to_string(),
        description: description.to_string(),
        path: format!("{}\\{}\\{}", hive, subkey, value),
        current_value: current,
        expected_value: Some(expected_value.to_string()),
        severity: severity.to_string(),
        can_fix: true,
    });
}

/// 检查 IFEO 映像劫持
fn check_ifeo_debugger(issues: &mut Vec<SystemIssue>) {
    let base = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = match hklm.open_subkey(base) {
        Ok(k) => k,
        Err(_) => return,
    };
    let subkeys: Vec<String> = key.enum_keys().filter_map(|k| k.ok()).collect();
    for subkey_name in subkeys {
        if subkey_name.to_lowercase().starts_with("sethc.exe")
            || subkey_name.to_lowercase().starts_with("utilman.exe")
            || subkey_name.to_lowercase().starts_with("osk.exe")
            || subkey_name.to_lowercase().starts_with("magnify.exe")
            || subkey_name.to_lowercase().starts_with("narrator.exe")
        {
            continue; // 这些在单独的后门检测中处理
        }
        let subkey_path = format!("{}\\{}", base, subkey_name);
        if let Some(debugger) = read_string("HKLM", &subkey_path, "Debugger") {
            if !debugger.trim().is_empty() {
                issues.push(SystemIssue {
                    id: format!("HKLM\\{}\\Debugger", subkey_path),
                    category: "映像劫持与进程后门".to_string(),
                    name: format!("IFEO 调试器劫持: {}", subkey_name),
                    description: "Image File Execution Options 下存在非空 Debugger 值，可能劫持程序启动".to_string(),
                    path: format!("HKLM\\{}\\Debugger", subkey_path),
                    current_value: Some(debugger),
                    expected_value: Some("(空)".to_string()),
                    severity: "High".to_string(),
                    can_fix: true,
                });
            }
        }
    }
}

/// 检查 AppInit_DLLs 注入
fn check_appinit_dlls(issues: &mut Vec<SystemIssue>) {
    let subkey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    if let Some(v) = read_string("HKLM", subkey, "AppInit_DLLs") {
        if !v.trim().is_empty() {
            issues.push(SystemIssue {
                id: "HKLM\\AppInit_DLLs".to_string(),
                category: "映像劫持与进程后门".to_string(),
                name: "AppInit_DLLs 注入".to_string(),
                description: "系统启动时加载 AppInit_DLLs，常被恶意软件用于 DLL 注入".to_string(),
                path: format!("HKLM\\{}\\AppInit_DLLs", subkey),
                current_value: Some(v),
                expected_value: Some("(空)".to_string()),
                severity: "High".to_string(),
                can_fix: true,
            });
        }
    }
    let load = read_dword("HKLM", subkey, "LoadAppInit_DLLs");
    if load.as_deref() == Some("1") {
        issues.push(SystemIssue {
            id: "HKLM\\LoadAppInit_DLLs".to_string(),
            category: "映像劫持与进程后门".to_string(),
            name: "LoadAppInit_DLLs 已启用".to_string(),
            description: "LoadAppInit_DLLs 被启用，允许 AppInit_DLLs 注入".to_string(),
            path: format!("HKLM\\{}\\LoadAppInit_DLLs", subkey),
            current_value: load,
            expected_value: Some("0".to_string()),
            severity: "Medium".to_string(),
            can_fix: true,
        });
    }
}

/// 检查 BootExecute 是否被篡改
fn check_boot_execute(issues: &mut Vec<SystemIssue>) {
    let subkey = "SYSTEM\\CurrentControlSet\\Control\\Session Manager";
    if let Some(v) = read_string("HKLM", subkey, "BootExecute") {
        // BootExecute 是 REG_MULTI_SZ，读取时可能含 \0，先转空格再统一比较
        let normalized = v.trim().to_lowercase().replace('\0', " ").replace("  ", " ").trim().to_string();
        if normalized != "autocheck autochk *" {
            issues.push(SystemIssue {
                id: "HKLM\\BootExecute".to_string(),
                category: "映像劫持与进程后门".to_string(),
                name: "BootExecute 启动项被篡改".to_string(),
                description: "Session Manager BootExecute 值异常，可能包含恶意启动命令".to_string(),
                path: format!("HKLM\\{}\\BootExecute", subkey),
                current_value: Some(v),
                expected_value: Some("autocheck autochk *".to_string()),
                severity: "High".to_string(),
                can_fix: true,
            });
        }
    }
}

/// 检查粘滞键等辅助功能后门
fn check_accessibility_backdoors(issues: &mut Vec<SystemIssue>) {
    let base = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    let targets = vec!["sethc.exe", "utilman.exe", "osk.exe", "Magnify.exe", "Narrator.exe"];
    for target in targets {
        let subkey = format!("{}\\{}", base, target);
        if let Some(debugger) = read_string("HKLM", &subkey, "Debugger") {
            if !debugger.trim().is_empty() {
                issues.push(SystemIssue {
                    id: format!("HKLM\\{}\\Debugger", subkey),
                    category: "映像劫持与进程后门".to_string(),
                    name: format!("{} 辅助功能后门", target),
                    description: format!("{} 被 IFEO Debugger 劫持，常见于按 5 次 Shift 等辅助功能触发后门", target),
                    path: format!("HKLM\\{}\\Debugger", subkey),
                    current_value: Some(debugger),
                    expected_value: Some("(空)".to_string()),
                    severity: "High".to_string(),
                    can_fix: true,
                });
            }
        }
    }
}

/// 检查 Winlogon 登录链
fn check_winlogon(issues: &mut Vec<SystemIssue>) {
    let subkey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    let shell = read_string("HKLM", subkey, "Shell");
    if shell.as_deref() != Some("explorer.exe") {
        issues.push(SystemIssue {
            id: "HKLM\\Winlogon\\Shell".to_string(),
            category: "登录与启动链劫持".to_string(),
            name: "Winlogon Shell 异常".to_string(),
            description: "登录后启动的 Shell 不是默认 explorer.exe，可能被恶意替换".to_string(),
            path: format!("HKLM\\{}\\Shell", subkey),
            current_value: shell,
            expected_value: Some("explorer.exe".to_string()),
            severity: "High".to_string(),
            can_fix: true,
        });
    }
    let userinit = read_string("HKLM", subkey, "Userinit");
    let expected = r"C:\Windows\system32\userinit.exe,";
    // 路径大小写不敏感比较（如 C:\WINDOWS 与 C:\Windows）
    if userinit.as_deref().map(|s| s.to_lowercase()).unwrap_or_default() != expected.to_lowercase() {
        issues.push(SystemIssue {
            id: "HKLM\\Winlogon\\Userinit".to_string(),
            category: "登录与启动链劫持".to_string(),
            name: "Winlogon Userinit 异常".to_string(),
            description: "Userinit 启动路径被修改，可能附加恶意程序".to_string(),
            path: format!("HKLM\\{}\\Userinit", subkey),
            current_value: userinit,
            expected_value: Some(expected.to_string()),
            severity: "High".to_string(),
            can_fix: true,
        });
    }
}

/// 检查 HKCU/HKLM Run 启动项
fn check_run_startup(issues: &mut Vec<SystemIssue>) {
    let paths = vec![
        ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        ("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        ("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices"),
        ("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices"),
        ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"),
        ("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"),
    ];
    for (hive, subkey) in paths {
        let key = match RegKey::predef(match hive {
            "HKLM" => HKEY_LOCAL_MACHINE,
            "HKCU" => HKEY_CURRENT_USER,
            _ => continue,
        }).open_subkey(subkey) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let values: Vec<(String, String)> = key.enum_values().filter_map(|v| {
            v.ok().and_then(|(name, value)| {
                match value {
                    winreg::RegValue { bytes, vtype: winreg::enums::RegType::REG_SZ | winreg::enums::RegType::REG_EXPAND_SZ, .. } => {
                        // REG_SZ/REG_EXPAND_SZ 末尾可能有 \0\0，去掉 trailing nulls
                        let s = String::from_utf8_lossy(&bytes).trim_end_matches('\0').to_string();
                        Some((name, s))
                    }
                    _ => None,
                }
            })
        }).collect();
        for (name, value) in values {
            if is_suspicious_startup(&value) {
                issues.push(SystemIssue {
                    id: format!("{}\\{}\\{}", hive, subkey, name),
                    category: "登录与启动链劫持".to_string(),
                    name: format!("可疑启动项: {}", name),
                    description: "启动项指向 Temp/AppData/脚本等可疑位置或无签名路径".to_string(),
                    path: format!("{}\\{}\\{}", hive, subkey, name),
                    current_value: Some(value),
                    expected_value: Some("(删除)".to_string()),
                    severity: "Medium".to_string(),
                    can_fix: true,
                });
            }
        }
    }
}

/// 简单启发式判断启动项是否可疑
fn is_suspicious_startup(value: &str) -> bool {
    let lower = value.to_lowercase();
    let suspicious_paths = vec![
        r"\temp\", r"\tmp\", r"\appdata\", r"\downloads\", r"\desktop\",
    ];
    let suspicious_exts = vec![".bat", ".cmd", ".vbs", ".js", ".ps1", ".wsf", ".wsh"];
    for p in suspicious_paths {
        if lower.contains(p) {
            return true;
        }
    }
    for ext in suspicious_exts {
        if lower.ends_with(ext) {
            return true;
        }
    }
    false
}

/// 检查资源管理器显示设置
fn check_explorer_display(issues: &mut Vec<SystemIssue>) {
    let subkey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced";
    // 文件扩展名被隐藏是常见病毒配合手段（双扩展名病毒），需要恢复显示。
    let hide_ext = read_dword("HKCU", subkey, "HideFileExt");
    if hide_ext.as_deref() != Some("0") {
        issues.push(SystemIssue {
            id: format!("HKCU\\{}\\HideFileExt", subkey),
            category: "资源管理器显示劫持".to_string(),
            name: "文件扩展名被隐藏".to_string(),
            description: "文件扩展名被强制隐藏，常见于双扩展名病毒配合".to_string(),
            path: format!("HKCU\\{}\\HideFileExt", subkey),
            current_value: hide_ext,
            expected_value: Some("0".to_string()),
            severity: "Low".to_string(),
            can_fix: true,
        });
    }
    // 受保护的操作系统文件未显示，可能掩盖恶意系统级文件。
    let show_super = read_dword("HKCU", subkey, "ShowSuperHidden");
    if show_super.as_deref() != Some("1") {
        issues.push(SystemIssue {
            id: format!("HKCU\\{}\\ShowSuperHidden", subkey),
            category: "资源管理器显示劫持".to_string(),
            name: "显示系统文件被禁用".to_string(),
            description: "资源管理器未显示受保护的操作系统文件".to_string(),
            path: format!("HKCU\\{}\\ShowSuperHidden", subkey),
            current_value: show_super,
            expected_value: Some("1".to_string()),
            severity: "Low".to_string(),
            can_fix: true,
        });
    }
}

/// 执行系统修复扫描
pub fn scan_system_issues() -> SystemRepairResult {
    let mut issues: Vec<SystemIssue> = Vec::new();

    // A. 系统工具禁用（策略类）
    let policy_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    check_registry_policy(&mut issues, "系统工具禁用", "任务管理器被禁用", "DisableTaskMgr 被设为 1，任务管理器无法打开", "HKCU", policy_path, "DisableTaskMgr", "0", "Medium");
    check_registry_policy(&mut issues, "系统工具禁用", "注册表编辑器被禁用", "DisableRegistryTools 被设为 1，regedit 无法打开", "HKCU", policy_path, "DisableRegistryTools", "0", "Medium");
    check_registry_policy(&mut issues, "系统工具禁用", "命令提示符被禁用", "DisableCMD 被设为 1，cmd 无法打开", "HKCU", policy_path, "DisableCMD", "0", "Medium");
    check_registry_policy(&mut issues, "系统工具禁用", "控制面板被禁用", "NoControlPanel 被设为 1，控制面板无法打开", "HKCU", policy_path, "NoControlPanel", "0", "Medium");
    check_registry_policy(&mut issues, "系统工具禁用", "文件夹选项被禁用", "NoFolderOptions 被设为 1，文件夹选项无法打开", "HKCU", policy_path, "NoFolderOptions", "0", "Low");
    check_registry_policy(&mut issues, "系统工具禁用", "运行对话框被禁用", "NoRun 被设为 1，Win+R 无法使用", "HKCU", policy_path, "NoRun", "0", "Low");
    check_registry_policy(&mut issues, "系统工具禁用", "查找功能被禁用", "NoFind 被设为 1，搜索功能被禁用", "HKCU", policy_path, "NoFind", "0", "Low");
    check_registry_policy(&mut issues, "系统工具禁用", "桌面图标被隐藏", "NoDesktop 被设为 1，桌面不显示图标", "HKCU", policy_path, "NoDesktop", "0", "Low");
    check_registry_policy(&mut issues, "系统工具禁用", "关机选项被禁用", "NoClose 被设为 1，无法通过开始菜单关机", "HKCU", policy_path, "NoClose", "0", "Medium");
    check_registry_policy(&mut issues, "系统工具禁用", "注销选项被禁用", "NoLogOff 被设为 1，无法注销", "HKCU", policy_path, "NoLogOff", "0", "Low");
    check_registry_policy(&mut issues, "系统工具禁用", "Windows 键被禁用", "NoWinKeys 被设为 1，Win 键失效", "HKCU", policy_path, "NoWinKeys", "0", "Low");
    check_registry_policy(&mut issues, "系统工具禁用", "锁定工作站被禁用", "DisableLockWorkstation 被设为 1，Win+L 无法锁定", "HKCU", policy_path, "DisableLockWorkstation", "0", "Low");
    check_registry_policy(&mut issues, "系统工具禁用", "更改密码被禁用", "DisableChangePassword 被设为 1，无法更改密码", "HKCU", policy_path, "DisableChangePassword", "0", "Low");
    check_registry_policy(&mut issues, "系统工具禁用", "快速用户切换被隐藏", "HideFastUserSwitching 被设为 1，快速用户切换被隐藏", "HKCU", policy_path, "HideFastUserSwitching", "0", "Low");
    check_registry_policy(&mut issues, "系统工具禁用", "通知中心被禁用", "DisableNotificationCenter 被设为 1，通知中心无法打开", "HKCU", policy_path, "DisableNotificationCenter", "0", "Low");

    let explorer_policy = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer";
    check_registry_policy(&mut issues, "系统工具禁用", "磁盘驱动器被隐藏", "NoDrives 非 0，可能隐藏或禁访盘符", "HKCU", explorer_policy, "NoDrives", "0", "Medium");
    check_registry_policy(&mut issues, "系统工具禁用", "MMC 控制台被禁用", "DisableMMC 被设为 1，services.msc/gpedit.msc 等无法打开", "HKCU", explorer_policy, "DisableMMC", "0", "Medium");
    check_registry_policy(&mut issues, "系统工具禁用", "Windows Script Host 被禁用", "Enabled 被设为 0，WSH 被禁用（病毒常禁用杀软脚本）", "HKLM", "SOFTWARE\\Microsoft\\Windows Script Host\\Settings", "Enabled", "1", "Medium");

    // cmd AutoRun 劫持
    if let Some(v) = read_string("HKCU", "Software\\Microsoft\\Command Processor", "AutoRun") {
        if !v.trim().is_empty() {
            issues.push(SystemIssue {
                id: "HKCU\\CommandProcessor\\AutoRun".to_string(),
                category: "系统工具禁用".to_string(),
                name: "CMD AutoRun 劫持".to_string(),
                description: "命令处理器 AutoRun 被设置，打开 cmd 即执行恶意命令".to_string(),
                path: "HKCU\\Software\\Microsoft\\Command Processor\\AutoRun".to_string(),
                current_value: Some(v),
                expected_value: Some("(空)".to_string()),
                severity: "High".to_string(),
                can_fix: true,
            });
        }
    }

    // 系统还原被禁
    check_registry_policy(&mut issues, "系统工具禁用", "系统还原被禁用", "DisableSR 被设为 1，系统还原被禁用", "HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore", "DisableSR", "0", "Medium");
    check_registry_policy(&mut issues, "系统工具禁用", "系统还原配置被禁用", "DisableConfig 被设为 1，无法配置系统还原", "HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore", "DisableConfig", "0", "Medium");

    // B. 资源管理器显示劫持
    check_explorer_display(&mut issues);

    // C. 映像劫持与进程后门
    check_ifeo_debugger(&mut issues);
    check_appinit_dlls(&mut issues);
    check_boot_execute(&mut issues);
    check_accessibility_backdoors(&mut issues);

    // D. 登录与启动链劫持
    check_winlogon(&mut issues);
    check_run_startup(&mut issues);

    // 统计
    let high = issues.iter().filter(|i| i.severity == "High").count();
    let medium = issues.iter().filter(|i| i.severity == "Medium").count();
    let low = issues.iter().filter(|i| i.severity == "Low").count();
    SystemRepairResult {
        summary: SystemRepairSummary {
            total: issues.len(),
            high,
            medium,
            low,
            fixed: 0,
        },
        issues,
    }
}

/// 修复指定 ID 的问题（基础实现：删除或重置注册表值）
pub fn fix_system_issues(issue_ids: Vec<String>) -> FixResult {
    let mut fixed = Vec::new();
    let mut failed = Vec::new();

    for id in issue_ids {
        let parts: Vec<&str> = id.split('\\').collect();
        if parts.len() < 4 {
            failed.push(id);
            continue;
        }
        let hive = parts[0];
        let subkey = parts[1..parts.len() - 1].join("\\");
        let value = parts[parts.len() - 1];

        let key = match hive {
            "HKLM" => RegKey::predef(HKEY_LOCAL_MACHINE).create_subkey(&subkey).ok().map(|(k, _)| k),
            "HKCU" => RegKey::predef(HKEY_CURRENT_USER).create_subkey(&subkey).ok().map(|(k, _)| k),
            "HKU" => RegKey::predef(HKEY_USERS).create_subkey(&subkey).ok().map(|(k, _)| k),
            _ => None,
        };

        if let Some(key) = key {
            let result = match value {
                "HideFileExt" => write_dword(hive, &subkey, value, 0),
                "ShowSuperHidden" => write_dword(hive, &subkey, value, 1),
                _ => key.delete_value(value).is_ok(),
            };
            if result {
                fixed.push(id);
            } else {
                failed.push(id);
            }
        } else {
            failed.push(id);
        }
    }

    let fixed_count = fixed.len();
    let failed_count = failed.len();
    FixResult {
        success: failed.is_empty(),
        fixed_ids: fixed,
        failed_ids: failed,
        message: format!("已修复 {} 项，失败 {} 项", fixed_count, failed_count),
    }
}
