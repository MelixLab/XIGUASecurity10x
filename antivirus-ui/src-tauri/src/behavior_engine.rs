//=============================================================================
// behavior_engine.rs - EDR 行为规则引擎
//
// 功能:
//   1. 基于 MITRE ATT&CK 的行为检测规则
//   2. 进程创建/命令行/文件路径/注册表模式匹配
//   3. 进程树关联分析 (父子进程链异常)
//   4. 威胁分级与响应建议
//
// 参考: HydraDragon Owlyshield 行为规则引擎
//=============================================================================

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::OnceLock;
use regex::Regex;

//=============================================================================
// MITRE ATT&CK 技术 ID
//=============================================================================

/// ATT&CK 技术分类
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AttackTechnique {
    T1059_001,  // PowerShell
    T1059_003,  // Windows Command Shell
    T1059_005,  // Visual Basic
    T1059_007,  // JavaScript/JScript
    T1055,       // Process Injection
    T1055_001,  // DLL Injection
    T1055_003,  // Thread Execution Hijacking
    T1055_012,  // Process Hollowing
    T1562_001,  // Disable or Modify Tools (Defender)
    T1562_002,  // Disable Windows Event Logging
    T1112,      // Modify Registry
    T1547_001,  // Registry Run Keys
    T1543_003,  // Create Service
    T1003_001,  // LSASS Memory Dump
    T1003_002,  // SAM Hive Export
    T1490,      // Shadow Copy Deletion
    T1070_001,  // Clear Event Logs
    T1027,      // Obfuscated Files
    T1564_001,  // Hidden Files
    T1055_004,  // Asynchronous Procedure Call
    T1218_004,  // InstallUtil Proxy
    T1218_009,  // RegSvcs Proxy
    T1548_002,  // UAC Bypass
    T1620,      // Reflective Code Loading
    T1041,      // Exfiltration Over C2
    T1113,      // Screen Capture
    T1056_001,  // Keylogging
    T1036,      // Masquerading
    Other(String),
}

impl AttackTechnique {
    pub fn id(&self) -> &str {
        match self {
            AttackTechnique::T1059_001 => "T1059.001",
            AttackTechnique::T1059_003 => "T1059.003",
            AttackTechnique::T1059_005 => "T1059.005",
            AttackTechnique::T1059_007 => "T1059.007",
            AttackTechnique::T1055 => "T1055",
            AttackTechnique::T1055_001 => "T1055.001",
            AttackTechnique::T1055_003 => "T1055.003",
            AttackTechnique::T1055_004 => "T1055.004",
            AttackTechnique::T1055_012 => "T1055.012",
            AttackTechnique::T1562_001 => "T1562.001",
            AttackTechnique::T1562_002 => "T1562.002",
            AttackTechnique::T1112 => "T1112",
            AttackTechnique::T1547_001 => "T1547.001",
            AttackTechnique::T1543_003 => "T1543.003",
            AttackTechnique::T1003_001 => "T1003.001",
            AttackTechnique::T1003_002 => "T1003.002",
            AttackTechnique::T1490 => "T1490",
            AttackTechnique::T1070_001 => "T1070.001",
            AttackTechnique::T1027 => "T1027",
            AttackTechnique::T1564_001 => "T1564.001",
            AttackTechnique::T1218_004 => "T1218.004",
            AttackTechnique::T1218_009 => "T1218.009",
            AttackTechnique::T1548_002 => "T1548.002",
            AttackTechnique::T1620 => "T1620",
            AttackTechnique::T1041 => "T1041",
            AttackTechnique::T1113 => "T1113",
            AttackTechnique::T1056_001 => "T1056.001",
            AttackTechnique::T1036 => "T1036",
            AttackTechnique::Other(s) => s,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            AttackTechnique::T1059_001 => "PowerShell",
            AttackTechnique::T1059_003 => "Windows Command Shell",
            AttackTechnique::T1059_005 => "Visual Basic",
            AttackTechnique::T1059_007 => "JavaScript/JScript",
            AttackTechnique::T1055 => "Process Injection",
            AttackTechnique::T1055_001 => "DLL Injection",
            AttackTechnique::T1055_003 => "Thread Execution Hijacking",
            AttackTechnique::T1055_004 => "Asynchronous Procedure Call",
            AttackTechnique::T1055_012 => "Process Hollowing",
            AttackTechnique::T1562_001 => "Disable or Modify Tools",
            AttackTechnique::T1562_002 => "Disable Windows Event Logging",
            AttackTechnique::T1112 => "Modify Registry",
            AttackTechnique::T1547_001 => "Registry Run Keys",
            AttackTechnique::T1543_003 => "Create or Modify System Process",
            AttackTechnique::T1003_001 => "LSASS Memory Dump",
            AttackTechnique::T1003_002 => "SAM Hive Export",
            AttackTechnique::T1490 => "Inhibit System Recovery",
            AttackTechnique::T1070_001 => "Clear Windows Event Logs",
            AttackTechnique::T1027 => "Obfuscated Files or Information",
            AttackTechnique::T1564_001 => "Hidden Files and Directories",
            AttackTechnique::T1218_004 => "InstallUtil Proxy Execution",
            AttackTechnique::T1218_009 => "RegSvcs Proxy Execution",
            AttackTechnique::T1548_002 => "UAC Bypass",
            AttackTechnique::T1620 => "Reflective Code Loading",
            AttackTechnique::T1041 => "Exfiltration Over C2",
            AttackTechnique::T1113 => "Screen Capture",
            AttackTechnique::T1056_001 => "Keyboard Input Capture",
            AttackTechnique::T1036 => "Masquerading",
            AttackTechnique::Other(_) => "Unknown",
        }
    }
}

//=============================================================================
// 威胁级别
//=============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatLevel {
    pub fn as_str(&self) -> &str {
        match self {
            ThreatLevel::Info => "info",
            ThreatLevel::Low => "low",
            ThreatLevel::Medium => "medium",
            ThreatLevel::High => "high",
            ThreatLevel::Critical => "critical",
        }
    }
}

//=============================================================================
// 行为规则定义
//=============================================================================

/// 匹配模式类型
#[derive(Debug, Clone)]
pub enum MatchPattern {
    /// 命令行正则匹配
    CommandLine(String),
    /// 进程名匹配 (小写)
    ProcessName(String),
    /// 文件路径模式匹配
    FilePath(String),
    /// 注册表路径模式匹配
    RegistryPath(String),
    /// 父进程名匹配
    ParentProcess(String),
    /// 任意条件组合
    Any(Vec<MatchPattern>),
    /// 全部条件组合
    All(Vec<MatchPattern>),
}

/// 检测规则
#[derive(Debug, Clone)]
pub struct DetectionRule {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub technique: AttackTechnique,
    pub severity: ThreatLevel,
    pub pattern: MatchPattern,
    /// 建议响应动作
    pub response: ResponseAction,
}

/// 响应动作
#[derive(Debug, Clone, PartialEq)]
pub enum ResponseAction {
    /// 仅记录日志
    Log,
    /// 通知用户
    Notify,
    /// 终止进程
    Terminate,
    /// 拦截并通知
    Block,
}

/// 检测结果
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub rule_id: String,
    pub rule_name: String,
    pub technique: AttackTechnique,
    pub severity: ThreatLevel,
    pub response: ResponseAction,
    pub matched_detail: String,
}

//=============================================================================
// 进程上下文 (用于规则匹配)
//=============================================================================

#[derive(Debug, Clone, Default)]
pub struct ProcessContext {
    pub pid: u32,
    pub parent_pid: u32,
    pub process_name: String,
    pub parent_name: String,
    pub command_line: String,
    pub image_path: String,
    pub creation_time: u64,
}

//=============================================================================
// 规则引擎
//=============================================================================

pub struct BehaviorEngine {
    rules: Vec<DetectionRule>,
    /// 进程树缓存: PID -> ProcessContext
    process_tree: HashMap<u32, ProcessContext>,
    /// 已触发规则去重: PID + rule_id -> 触发时间
    triggered: HashMap<String, u64>,
}

impl BehaviorEngine {
    pub fn new() -> Self {
        Self {
            rules: default_rules(),
            process_tree: HashMap::new(),
            triggered: HashMap::new(),
        }
    }

    /// 添加自定义规则
    pub fn add_rule(&mut self, rule: DetectionRule) {
        self.rules.push(rule);
    }

    /// 记录进程创建事件, 返回触发的检测规则
    pub fn on_process_created(&mut self, ctx: ProcessContext) -> Vec<DetectionResult> {
        // 缓存进程上下文
        self.process_tree.insert(ctx.pid, ctx.clone());

        // 清理过期的进程树 (超过 1000 条)
        if self.process_tree.len() > 1000 {
            let oldest = self.process_tree
                .iter()
                .filter(|(_, v)| v.creation_time > 0)
                .min_by_key(|(_, v)| v.creation_time)
                .map(|(k, _)| *k);
            if let Some(pid) = oldest {
                self.process_tree.remove(&pid);
            }
        }

        // 对该进程执行规则匹配
        self.match_rules(&ctx)
    }

    /// 记录进程退出, 清理缓存
    pub fn on_process_terminated(&mut self, pid: u32) {
        self.process_tree.remove(&pid);
        // 清理相关触发记录
        let prefix = format!("{}-", pid);
        self.triggered.retain(|k, _| !k.starts_with(&prefix));
    }

    /// 对进程上下文执行所有规则匹配
    fn match_rules(&mut self, ctx: &ProcessContext) -> Vec<DetectionResult> {
        let mut results = Vec::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for rule in &self.rules {
            // 去重: 同一进程同一规则不重复触发 (5分钟内)
            let key = format!("{}-{}", ctx.pid, rule.rule_id);
            if let Some(&t) = self.triggered.get(&key) {
                if now - t < 300 {
                    continue;
                }
            }

            if let Some(detail) = self.match_pattern(&rule.pattern, ctx) {
                self.triggered.insert(key, now);

                results.push(DetectionResult {
                    rule_id: rule.rule_id.clone(),
                    rule_name: rule.name.clone(),
                    technique: rule.technique.clone(),
                    severity: rule.severity,
                    response: rule.response.clone(),
                    matched_detail: detail,
                });
            }
        }

        results
    }

    /// 模式匹配
    fn match_pattern(&self, pattern: &MatchPattern, ctx: &ProcessContext) -> Option<String> {
        match pattern {
            MatchPattern::CommandLine(re) => {
                if let Ok(regex) = Regex::new(re) {
                    if regex.is_match(&ctx.command_line) {
                        return Some(format!(
                            "命令行匹配: {} -> {}",
                            ctx.process_name,
                            ctx.command_line.chars().take(200).collect::<String>()
                        ));
                    }
                }
                None
            }
            MatchPattern::ProcessName(name) => {
                if ctx.process_name.to_lowercase().contains(&name.to_lowercase()) {
                    return Some(format!("进程名匹配: {}", ctx.process_name));
                }
                None
            }
            MatchPattern::FilePath(pattern) => {
                if ctx.image_path.to_lowercase().contains(&pattern.to_lowercase()) {
                    return Some(format!("文件路径匹配: {}", ctx.image_path));
                }
                None
            }
            MatchPattern::RegistryPath(_) => None, // 注册表匹配在 on_registry_event 中处理
            MatchPattern::ParentProcess(name) => {
                if ctx.parent_name.to_lowercase().contains(&name.to_lowercase()) {
                    return Some(format!("父进程匹配: {} (parent: {})", ctx.process_name, ctx.parent_name));
                }
                None
            }
            MatchPattern::Any(patterns) => {
                for p in patterns {
                    if let Some(detail) = self.match_pattern(p, ctx) {
                        return Some(detail);
                    }
                }
                None
            }
            MatchPattern::All(patterns) => {
                let mut details = Vec::new();
                for p in patterns {
                    if let Some(detail) = self.match_pattern(p, ctx) {
                        details.push(detail);
                    } else {
                        return None;
                    }
                }
                Some(details.join("; "))
            }
        }
    }

    /// 注册表事件匹配 (由注册表监控回调调用)
    pub fn on_registry_event(
        &mut self,
        pid: u32,
        key_path: &str,
        value_name: &str,
        operation: &str,
    ) -> Vec<DetectionResult> {
        let ctx = match self.process_tree.get(&pid) {
            Some(c) => c.clone(),
            None => ProcessContext {
                pid,
                process_name: "unknown".into(),
                ..Default::default()
            },
        };

        let mut results = Vec::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let full_path = format!("{}\\{}", key_path, value_name);
        let full_path_lower = full_path.to_lowercase();

        for rule in &self.rules {
            let key = format!("{}-{}", pid, rule.rule_id);
            if let Some(&t) = self.triggered.get(&key) {
                if now - t < 300 {
                    continue;
                }
            }

            if let MatchPattern::RegistryPath(pattern) = &rule.pattern {
                if full_path_lower.contains(&pattern.to_lowercase()) {
                    self.triggered.insert(key, now);
                    results.push(DetectionResult {
                        rule_id: rule.rule_id.clone(),
                        rule_name: rule.name.clone(),
                        technique: rule.technique.clone(),
                        severity: rule.severity,
                        response: rule.response.clone(),
                        matched_detail: format!(
                            "注册表{}: {} -> {} ({})",
                            operation, full_path, ctx.process_name, pid
                        ),
                    });
                }
            }
        }

        results
    }

    /// 获取所有规则
    pub fn rules(&self) -> &[DetectionRule] {
        &self.rules
    }
}

//=============================================================================
// 默认检测规则 (内置, 参考 HydraDragon + MITRE ATT&CK)
//=============================================================================

fn default_rules() -> Vec<DetectionRule> {
    vec![
        // ===== 凭据访问 (T1003) =====
        DetectionRule {
            rule_id: "XG-CRED-001".into(),
            name: "LSASS 内存转储".into(),
            description: "检测通过 comsvcs.dll MiniDump 或 taskmgr 转储 LSASS 进程内存".into(),
            technique: AttackTechnique::T1003_001,
            severity: ThreatLevel::Critical,
            pattern: MatchPattern::Any(vec![
                MatchPattern::CommandLine(r"(?i)MiniDump|comsvcs\.dll.*MiniDump|lsass.*dmp|procdump.*-ma.*lsass".into()),
                MatchPattern::CommandLine(r"(?i)Get-Process lsass|ntds\.dit".into()),
            ]),
            response: ResponseAction::Terminate,
        },
        DetectionRule {
            rule_id: "XG-CRED-002".into(),
            name: "SAM 注册表 hive 导出".into(),
            description: "检测注册表 SAM hive 导出 (reg save)".into(),
            technique: AttackTechnique::T1003_002,
            severity: ThreatLevel::Critical,
            pattern: MatchPattern::CommandLine(r"(?i)reg\s+save\s+\\.*\\SAM|reg\s+save\s+\\.*\\SYSTEM|reg\s+save\s+\\.*\\SECURITY".into()),
            response: ResponseAction::Terminate,
        },
        DetectionRule {
            rule_id: "XG-CRED-003".into(),
            name: "SharpKatz/Mimikatz 命令".into(),
            description: "检测 Mimikatz 或类似凭据窃取工具的命令行特征".into(),
            technique: AttackTechnique::T1003_001,
            severity: ThreatLevel::Critical,
            pattern: MatchPattern::Any(vec![
                MatchPattern::CommandLine(r"(?i)mimikatz|sekurlsa|kerberos::|crypto::|lsadump|privilege::debug".into()),
                MatchPattern::ProcessName("mimikatz".into()),
                MatchPattern::ProcessName("sharpkatz".into()),
                MatchPattern::ProcessName("procdump".into()),
            ]),
            response: ResponseAction::Terminate,
        },

        // ===== 防御规避 (T1562) =====
        DetectionRule {
            rule_id: "XG-EVAD-001".into(),
            name: "禁用 Windows Defender".into(),
            description: "检测通过 PowerShell 或 reg 禁用 Defender 实时保护".into(),
            technique: AttackTechnique::T1562_001,
            severity: ThreatLevel::High,
            pattern: MatchPattern::Any(vec![
                MatchPattern::CommandLine(r"(?i)Set-MpPreference\s+-DisableRealtimeMonitoring\s+(?:\$true|1)".into()),
                MatchPattern::CommandLine(r"(?i)Set-MpPreference\s+-DisableBehaviorMonitoring\s+(?:\$true|1)".into()),
                MatchPattern::CommandLine(r"(?i)Add-MpPreference\s+-ExclusionPath".into()),
                MatchPattern::CommandLine(r"(?i)Uninstall-WindowsFeature\s+Windows-Defender".into()),
                MatchPattern::CommandLine(r"(?i)netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off".into()),
                MatchPattern::RegistryPath(r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection".into()),
                MatchPattern::RegistryPath(r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring".into()),
            ]),
            response: ResponseAction::Block,
        },
        DetectionRule {
            rule_id: "XG-EVAD-002".into(),
            name: "清除事件日志".into(),
            description: "检测清除 Windows 事件日志 (wevtutil cl 或 Clear-EventLog)".into(),
            technique: AttackTechnique::T1070_001,
            severity: ThreatLevel::High,
            pattern: MatchPattern::Any(vec![
                MatchPattern::CommandLine(r"(?i)wevtutil\s+cl".into()),
                MatchPattern::CommandLine(r"(?i)Clear-EventLog|Limit-EventLog|Remove-EventLog".into()),
                MatchPattern::CommandLine(r"(?i)Get-WinEvent.*ListLog.*Clear".into()),
            ]),
            response: ResponseAction::Block,
        },
        DetectionRule {
            rule_id: "XG-EVAD-003".into(),
            name: "删除卷影副本".into(),
            description: "检测通过 vssadmin/wmic/Powershell 删除卷影副本 (勒索软件前置)".into(),
            technique: AttackTechnique::T1490,
            severity: ThreatLevel::Critical,
            pattern: MatchPattern::Any(vec![
                MatchPattern::CommandLine(r"(?i)vssadmin\s+delete\s+shadows".into()),
                MatchPattern::CommandLine(r"(?i)wmic\s+shadowcopy\s+delete".into()),
                MatchPattern::CommandLine(r"(?i)Get-WmiObject.*ShadowCopy.*Delete".into()),
                MatchPattern::CommandLine(r"(?i)wbadmin\s+delete\s+catalog".into()),
                MatchPattern::CommandLine(r"(?i)bcdedit\s+/set\s+bootstatuspolicy\s+ignoreallfailures".into()),
            ]),
            response: ResponseAction::Terminate,
        },
        DetectionRule {
            rule_id: "XG-EVAD-004".into(),
            name: "Base64 编码命令".into(),
            description: "检测 PowerShell -EncodedCommand 或 base64 编码的命令行".into(),
            technique: AttackTechnique::T1027,
            severity: ThreatLevel::Medium,
            pattern: MatchPattern::Any(vec![
                MatchPattern::CommandLine(r"(?i)-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}".into()),
                MatchPattern::CommandLine(r"(?i)frombase64string|System\.Convert::FromBase64String".into()),
                MatchPattern::CommandLine(r"(?i)IEX\s*\(\s*New-Object\s+Net\.WebClient\)\.DownloadString".into()),
                MatchPattern::CommandLine(r"(?i)Invoke-Expression|IEX\s".into()),
            ]),
            response: ResponseAction::Notify,
        },
        DetectionRule {
            rule_id: "XG-EVAD-005".into(),
            name: "AMSI Bypass".into(),
            description: "检测 PowerShell 中尝试绕过 AMSI 的常见模式".into(),
            technique: AttackTechnique::T1562_001,
            severity: ThreatLevel::High,
            pattern: MatchPattern::Any(vec![
                MatchPattern::CommandLine(r"(?i)amsiInitFailed|amsiUtils|AmsiScanBuffer".into()),
                MatchPattern::CommandLine(r"(?i)\[Ref\]\.Assembly::GetType|Reflection\.Assembly".into()),
                MatchPattern::CommandLine(r"(?i)System\.Management\.Automation\.AmsiUtils".into()),
                MatchPattern::RegistryPath(r"SOFTWARE\Microsoft\Windows Script\Settings\AmsiEnable".into()),
            ]),
            response: ResponseAction::Block,
        },

        // ===== 持久化 (T1547/T1543) =====
        DetectionRule {
            rule_id: "XG-PERS-001".into(),
            name: "注册表 Run 键自启动".into(),
            description: "检测向 Run/RunOnce 注册表键写入自启动项".into(),
            technique: AttackTechnique::T1547_001,
            severity: ThreatLevel::Medium,
            pattern: MatchPattern::Any(vec![
                MatchPattern::RegistryPath(r"CurrentVersion\Run".into()),
                MatchPattern::RegistryPath(r"CurrentVersion\RunOnce".into()),
                MatchPattern::RegistryPath(r"CurrentVersion\RunServices".into()),
                MatchPattern::RegistryPath(r"CurrentVersion\RunServicesOnce".into()),
                MatchPattern::CommandLine(r"(?i)reg\s+add.*\\Run|reg\s+add.*\\RunOnce".into()),
                MatchPattern::CommandLine(r"(?i)New-ItemProperty.*-Path.*Run|Set-ItemProperty.*-Path.*Run".into()),
            ]),
            response: ResponseAction::Notify,
        },
        DetectionRule {
            rule_id: "XG-PERS-002".into(),
            name: "创建计划任务".into(),
            description: "检测通过 schtasks 或 PowerShell 创建计划任务".into(),
            technique: AttackTechnique::T1543_003,
            severity: ThreatLevel::Medium,
            pattern: MatchPattern::Any(vec![
                MatchPattern::CommandLine(r"(?i)schtasks\s+/create|schtasks\s+-create".into()),
                MatchPattern::CommandLine(r"(?i)Register-ScheduledTask|New-ScheduledTask".into()),
                MatchPattern::CommandLine(r"(?i)at\s+\d+:\d+\s+\S+\.(exe|bat|cmd|ps1|vbs)".into()),
            ]),
            response: ResponseAction::Notify,
        },
        DetectionRule {
            rule_id: "XG-PERS-003".into(),
            name: "创建系统服务".into(),
            description: "检测通过 sc/PowerShell 创建系统服务".into(),
            technique: AttackTechnique::T1543_003,
            severity: ThreatLevel::Medium,
            pattern: MatchPattern::Any(vec![
                MatchPattern::CommandLine(r"(?i)sc\s+create|sc\s+config\s+\S+\s+binPath".into()),
                MatchPattern::CommandLine(r"(?i)New-Service|Set-Service.*-StartupType\s+Auto".into()),
                MatchPattern::RegistryPath(r"SYSTEM\CurrentControlSet\Services".into()),
            ]),
            response: ResponseAction::Notify,
        },

        // ===== 进程注入 (T1055) =====
        DetectionRule {
            rule_id: "XG-INJ-001".into(),
            name: "进程注入 API 调用".into(),
            description: "检测通过 PowerShell/命令行调用进程注入相关 API".into(),
            technique: AttackTechnique::T1055,
            severity: ThreatLevel::High,
            pattern: MatchPattern::Any(vec![
                MatchPattern::CommandLine(r"(?i)VirtualAllocEx|WriteProcessMemory|CreateRemoteThread".into()),
                MatchPattern::CommandLine(r"(?i)NtCreateThreadEx|RtlCreateUserThread".into()),
                MatchPattern::CommandLine(r"(?i)QueueUserAPC|NtQueueApcThread".into()),
                MatchPattern::CommandLine(r"(?i)SetThreadContext|GetThreadContext.*ResumeThread".into()),
            ]),
            response: ResponseAction::Block,
        },
        DetectionRule {
            rule_id: "XG-INJ-002".into(),
            name: "可疑的 RunPE/进程镂空".into(),
            description: "检测通过 PowerShell 或 .NET 执行的进程镂空/RunPE 技术".into(),
            technique: AttackTechnique::T1055_012,
            severity: ThreatLevel::Critical,
            pattern: MatchPattern::Any(vec![
                MatchPattern::CommandLine(r"(?i)RunPE|ProcessHollowing|HollowProcess".into()),
                MatchPattern::CommandLine(r"(?i)NtUnmapViewOfSection|ZwUnmapViewOfSection".into()),
                MatchPattern::CommandLine(r"(?i)UpdateProcThreadMultipleApis|CreateProcess.*CREATE_SUSPENDED.*WriteProcessMemory.*ResumeThread".into()),
            ]),
            response: ResponseAction::Terminate,
        },

        // ===== 横向移动/执行 (T1218) =====
        DetectionRule {
            rule_id: "XG-LAT-001".into(),
            name: "LOLBAS 代理执行".into(),
            description: "检测通过 LOLBAS (InstallUtil, RegSvcs, MSBuild 等) 执行可疑代码".into(),
            technique: AttackTechnique::T1218_004,
            severity: ThreatLevel::Medium,
            pattern: MatchPattern::Any(vec![
                MatchPattern::CommandLine(r"(?i)InstallUtil\.exe\s+/logfile=0\s+/Uninstall.*\.dll".into()),
                MatchPattern::CommandLine(r"(?i)RegSvcs\.exe\s+.*\.dll".into()),
                MatchPattern::CommandLine(r"(?i)RegAsm\.exe\s+.*\.dll".into()),
                MatchPattern::CommandLine(r"(?i)MSBuild\.exe.*\.csproj".into()),
                MatchPattern::CommandLine(r"(?i)rundll32\.exe\s+.*\.dll.*,.*\s(u|U)ninstall|Install".into()),
            ]),
            response: ResponseAction::Notify,
        },
        DetectionRule {
            rule_id: "XG-LAT-002".into(),
            name: "UAC Bypass (Fodhelper)".into(),
            description: "检测通过 Fodhelper 或其他 UAC bypass 技术".into(),
            technique: AttackTechnique::T1548_002,
            severity: ThreatLevel::High,
            pattern: MatchPattern::Any(vec![
                MatchPattern::CommandLine(r"(?i)fodhelper\.exe|computerdefaults\.exe|dccw\.exe".into()),
                MatchPattern::RegistryPath(r"Environment\CurrentDirectory".into()),
                MatchPattern::RegistryPath(r"ms-settings\\Shell\\Open\\command".into()),
            ]),
            response: ResponseAction::Block,
        },

        // ===== 伪装 (T1036) =====
        DetectionRule {
            rule_id: "XG-MASK-001".into(),
            name: "系统文件伪装".into(),
            description: "检测进程在非系统目录运行系统进程名 (如 svchost.exe 在 Temp 目录)".into(),
            technique: AttackTechnique::T1036,
            severity: ThreatLevel::High,
            pattern: MatchPattern::All(vec![
                MatchPattern::ProcessName("svchost.exe".into()),
                MatchPattern::FilePath(r"\Temp\".into()),
            ]),
            response: ResponseAction::Block,
        },
        DetectionRule {
            rule_id: "XG-MASK-002".into(),
            name: "可疑文件名伪装".into(),
            description: "检测文件名伪装为系统组件 (如 svch0st.exe, lssass.exe)".into(),
            technique: AttackTechnique::T1036,
            severity: ThreatLevel::High,
            pattern: MatchPattern::Any(vec![
                MatchPattern::ProcessName("svch0st".into()),
                MatchPattern::ProcessName("lssass".into()),
                MatchPattern::ProcessName("scvhost".into()),
                MatchPattern::ProcessName("csrsss".into()),
                MatchPattern::ProcessName("lsasss".into()),
                MatchPattern::ProcessName("taskmgn".into()),
            ]),
            response: ResponseAction::Block,
        },

        // ===== 下载/执行 (T1105) =====
        DetectionRule {
            rule_id: "XG-DL-001".into(),
            name: "可疑文件下载".into(),
            description: "检测通过 PowerShell/curl/certutil 下载可执行文件".into(),
            technique: AttackTechnique::T1027,
            severity: ThreatLevel::Medium,
            pattern: MatchPattern::Any(vec![
                MatchPattern::CommandLine(r"(?i)Invoke-WebRequest|System\.Net\.WebClient.*DownloadFile".into()),
                MatchPattern::CommandLine(r"(?i)curl.*-o\s+\S+\.(exe|bat|cmd|ps1|vbs|js|jar)".into()),
                MatchPattern::CommandLine(r"(?i)certutil\s+-urlcache\s+http.*\.(exe|bat|dll)".into()),
                MatchPattern::CommandLine(r"(?i)bitsadmin\s+/transfer\s+.*\.(exe|dll|bat)".into()),
            ]),
            response: ResponseAction::Notify,
        },
        DetectionRule {
            rule_id: "XG-DL-002".into(),
            name: "从临时目录执行".into(),
            description: "检测从 Temp/AppData/Downloads 目录直接执行可执行文件".into(),
            technique: AttackTechnique::T1027,
            severity: ThreatLevel::Medium,
            pattern: MatchPattern::Any(vec![
                MatchPattern::FilePath(r"\Temp\".into()),
                MatchPattern::FilePath(r"\AppData\Local\Temp".into()),
                MatchPattern::FilePath(r"\AppData\Roaming".into()),
                MatchPattern::FilePath(r"\Downloads\".into()),
            ]),
            response: ResponseAction::Notify,
        },

        // ===== 屏幕捕获/键盘记录 (T1113/T1056) =====
        DetectionRule {
            rule_id: "XG-PRIV-001".into(),
            name: "屏幕捕获".into(),
            description: "检测可能的屏幕捕获行为".into(),
            technique: AttackTechnique::T1113,
            severity: ThreatLevel::Medium,
            pattern: MatchPattern::Any(vec![
                MatchPattern::CommandLine(r"(?i)CopyFromScreen|BitBlt|Screen\.CaptureScreen".into()),
                MatchPattern::ProcessName("nirsoft".into()),
            ]),
            response: ResponseAction::Notify,
        },
        DetectionRule {
            rule_id: "XG-PRIV-002".into(),
            name: "键盘记录 API 调用".into(),
            description: "检测调用 SetWindowsHookEx 安装键盘钩子".into(),
            technique: AttackTechnique::T1056_001,
            severity: ThreatLevel::Medium,
            pattern: MatchPattern::Any(vec![
                MatchPattern::CommandLine(r"(?i)SetWindowsHookEx|WH_KEYBOARD_LL|GetAsyncKeyState".into()),
                MatchPattern::ProcessName("keylogger".into()),
            ]),
            response: ResponseAction::Block,
        },
    ]
}

//=============================================================================
// 全局引擎单例
//=============================================================================

static ENGINE: OnceLock<Mutex<BehaviorEngine>> = OnceLock::new();

pub fn engine() -> &'static Mutex<BehaviorEngine> {
    ENGINE.get_or_init(|| Mutex::new(BehaviorEngine::new()))
}

/// 便捷入口: 进程创建时调用
pub fn evaluate_process(ctx: ProcessContext) -> Vec<DetectionResult> {
    let mut e = match engine().lock() {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let results = e.on_process_created(ctx);

    for r in &results {
        let level_str = match r.severity {
            ThreatLevel::Critical => "[EDR-CRITICAL]",
            ThreatLevel::High => "[EDR-HIGH]",
            ThreatLevel::Medium => "[EDR-MEDIUM]",
            ThreatLevel::Low => "[EDR-LOW]",
            ThreatLevel::Info => "[EDR-INFO]",
        };
        crate::log_to_file(&format!(
            "{} Rule {} ({}) {}: {}",
            level_str,
            r.rule_id,
            r.technique.id(),
            r.technique.name(),
            r.matched_detail
        ));
    }

    results
}

/// 便捷入口: 注册表事件时调用
pub fn evaluate_registry(
    pid: u32,
    key_path: &str,
    value_name: &str,
    operation: &str,
) -> Vec<DetectionResult> {
    let mut e = match engine().lock() {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    e.on_registry_event(pid, key_path, value_name, operation)
}

/// 便捷入口: 进程退出时清理
pub fn on_process_exit(pid: u32) {
    if let Ok(mut e) = engine().lock() {
        e.on_process_terminated(pid);
    }
}
