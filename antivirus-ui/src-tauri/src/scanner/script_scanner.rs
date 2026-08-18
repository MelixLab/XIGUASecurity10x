use std::fs;
use std::path::Path;
use std::collections::HashSet;

/// 脚本扫描结果
#[derive(Debug, Clone)]
pub struct ScriptScanResult {
    pub is_malicious: bool,
    pub virus_family: Option<String>,
    pub threat_level: f32,
    pub description: String,
}

/// 模拟执行状态
#[derive(Debug, Clone)]
struct ExecutionState {
    /// 尝试删除的文件
    deleted_files: HashSet<String>,
    /// 尝试修改的注册表项
    modified_registry: HashSet<String>,
    /// 尝试创建的计划任务
    created_tasks: HashSet<String>,
    /// 尝试启动的进程
    spawned_processes: HashSet<String>,
    /// 尝试修改的系统配置
    modified_system: HashSet<String>,
    /// 尝试下载的文件
    downloaded_files: HashSet<String>,
    /// 尝试修改的MBR/启动
    modified_boot: bool,
    /// 尝试清除日志
    cleared_logs: bool,
    /// 威胁分数
    threat_score: f32,
    /// 检测到的行为
    behaviors: Vec<String>,
}

impl ExecutionState {
    fn new() -> Self {
        ExecutionState {
            deleted_files: HashSet::new(),
            modified_registry: HashSet::new(),
            created_tasks: HashSet::new(),
            spawned_processes: HashSet::new(),
            modified_system: HashSet::new(),
            downloaded_files: HashSet::new(),
            modified_boot: false,
            cleared_logs: false,
            threat_score: 0.0,
            behaviors: Vec::new(),
        }
    }

    fn add_threat(&mut self, score: f32, behavior: &str) {
        self.threat_score += score;
        if !self.behaviors.contains(&behavior.to_string()) {
            self.behaviors.push(behavior.to_string());
        }
    }
}

/// 扫描脚本文件
pub fn scan_script_file(file_path: &str) -> Option<ScriptScanResult> {
    let path = Path::new(file_path);
    let extension = path.extension()?.to_str()?.to_lowercase();
    
    match extension.as_str() {
        "bat" | "cmd" => {
            let content = fs::read_to_string(file_path).ok()?;
            scan_bat_content(&content, file_path)
        },
        _ => None,
    }
}

/// 从内存缓冲区扫描脚本文件（用于压缩包内脚本扫描）
pub fn scan_script_buffer(content: &[u8], file_name: &str) -> Option<ScriptScanResult> {
    let path = Path::new(file_name);
    let extension = path.extension()?.to_str()?.to_lowercase();
    
    match extension.as_str() {
        "bat" | "cmd" => {
            let content_str = String::from_utf8_lossy(content);
            scan_bat_content(&content_str, file_name)
        },
        _ => None,
    }
}

/// 扫描 BAT 文件内容 - 使用解释器模拟器
fn scan_bat_content(content: &str, file_path: &str) -> Option<ScriptScanResult> {
    let content_lower = content.to_lowercase();
    
    // 使用解释器模拟器分析脚本行为
    let state = simulate_bat_execution(&content_lower);
    
    // 根据模拟执行结果判断威胁
    println!("[ScriptScan] File: {}, Threat Score: {}, Behaviors: {:?}", file_path, state.threat_score, state.behaviors);
    
    if state.threat_score >= 4.0 {
        let virus_family = analyze_bat_family_by_state(&state);
        println!("[ScriptScan] High threat detected: {} (score={})", virus_family, state.threat_score);
        Some(ScriptScanResult {
            is_malicious: true,
            virus_family: Some(virus_family),
            threat_level: (state.threat_score / 10.0).min(1.0),
            description: format!("模拟执行检测到威胁行为: {}", state.behaviors.join(", ")),
        })
    } else if state.threat_score >= 2.5 {
        let virus_family = analyze_bat_family_by_state(&state);
        println!("[ScriptScan] Medium threat detected: {} (score={})", virus_family, state.threat_score);
        Some(ScriptScanResult {
            is_malicious: true,
            virus_family: Some(virus_family),
            threat_level: (state.threat_score / 10.0).min(1.0),
            description: format!("模拟执行检测到可疑行为: {}", state.behaviors.join(", ")),
        })
    } else {
        println!("[ScriptScan] No threat detected, score too low: {}", state.threat_score);
        None
    }
}

/// BAT 解释器模拟器 - 模拟执行并分析行为
fn simulate_bat_execution(content: &str) -> ExecutionState {
    let mut state = ExecutionState::new();
    let lines: Vec<&str> = content.lines().collect();
    
    for line in lines {
        let line_lower = line.to_lowercase().trim().to_string();
        
        // 跳过空行和注释
        if line_lower.is_empty() || line_lower.starts_with("rem ") || line_lower.starts_with("::") || line_lower.starts_with("@rem ") {
            continue;
        }
        
        // 移除前导的 @
        let line_clean = if line_lower.starts_with('@') {
            line_lower[1..].trim().to_string()
        } else {
            line_lower
        };
        
        // echo 行：只检测文件写入位置，不要把 echo 内容当作实际执行命令
        if line_clean.starts_with("echo ") {
            analyze_echo_line(&line_clean, &mut state);
            continue;
        }
        
        // 分析命令
        analyze_command(&line_clean, &mut state);
    }
    
    // 组合行为加分：持久化 + 强制重启/关机 = 典型恶意玩笑/破坏脚本
    let has_startup = state.modified_registry.contains("startup");
    let has_forced_reboot = state.behaviors.iter().any(|b| b == "强制重启系统");
    let has_system_write = state.behaviors.iter().any(|b| b == "写入系统目录");
    
    if has_startup && has_forced_reboot {
        state.add_threat(2.0, "持久化自启+强制重启组合");
    }
    if has_system_write && has_forced_reboot {
        state.add_threat(1.5, "系统目录写入+强制重启组合");
    }
    
    state
}

/// 判断路径是否为系统目录
fn is_system_directory_path(cmd: &str) -> bool {
    cmd.contains("%windir%") || 
    cmd.contains("%system%") || 
    cmd.contains("system32") || 
    cmd.contains("syswow64") || 
    cmd.contains("c:\\windows")
}

/// 分析 echo 行：检测是否写入系统目录
fn analyze_echo_line(cmd: &str, state: &mut ExecutionState) {
    // 只关心写入操作
    if cmd.contains('>') {
        if is_system_directory_path(cmd) {
            state.add_threat(1.0, "写入系统目录");
        }
        if cmd.contains("\\windows") || cmd.contains("\\system") {
            state.add_threat(0.5, "写入系统关键目录");
        }
    }
}

/// 分析单条命令的行为
fn analyze_command(cmd: &str, state: &mut ExecutionState) {
    // 1. 文件删除操作 (高危)
    if cmd.contains("del ") || cmd.contains("erase ") {
        if cmd.contains("/f") || cmd.contains("/q") || cmd.contains("/s") {
            state.add_threat(0.9, "强制删除文件");
            if cmd.contains("*") || cmd.contains("?") {
                state.add_threat(0.5, "批量删除文件");
            }
            if cmd.contains("c:\\") || cmd.contains("%system%") || cmd.contains("%windir%") {
                state.add_threat(1.0, "删除系统文件");
            }
        }
    }
    
    // 2. 目录删除操作 (中危, 安装卸载程序常见)
    if cmd.contains("rd ") || cmd.contains("rmdir ") {
        if cmd.contains("/s") || cmd.contains("/q") {
            state.add_threat(0.3, "递归删除目录");
            if cmd.contains("c:\\") || cmd.contains("%system%") {
                state.add_threat(1.0, "删除系统目录");
            }
        }
    }
    
    // 3. 格式化磁盘 (极高危)
    if cmd.contains("format ") {
        state.add_threat(2.0, "格式化磁盘");
        state.modified_system.insert("disk_format".to_string());
    }
    
    // 4. 磁盘分区操作 (高危)
    if cmd.contains("diskpart") {
        state.add_threat(1.5, "磁盘分区操作");
        state.modified_system.insert("disk_partition".to_string());
    }
    
    // 5. MBR/启动修改 (极高危)
    if cmd.contains("bootsect") || cmd.contains("bcdedit") {
        state.add_threat(2.0, "修改启动配置");
        state.modified_boot = true;
    }
    
    // 6. 卷影副本删除 (勒索软件特征)
    if cmd.contains("vssadmin") && cmd.contains("delete") {
        state.add_threat(1.8, "删除卷影副本");
        state.modified_system.insert("shadow_delete".to_string());
    }
    
    // 7. 备份删除 (勒索软件特征)
    if cmd.contains("wbadmin") && (cmd.contains("delete") || cmd.contains("disable")) {
        state.add_threat(1.8, "删除系统备份");
        state.modified_system.insert("backup_delete".to_string());
    }
    
    // 8. 注册表操作
    if cmd.contains("reg ") {
        if cmd.contains("delete") {
            state.add_threat(0.3, "删除注册表项");
            state.modified_registry.insert("delete".to_string());
        }
        if cmd.contains("add") {
            if cmd.contains("run") || cmd.contains("startup") {
                state.add_threat(1.5, "添加启动项");
                state.modified_registry.insert("startup".to_string());
            } else {
                state.add_threat(0.1, "修改注册表");
            }
        }
    }
    
    // 9. 服务操作 (安装卸载常见, 仅删除服务才给中分)
    if cmd.contains("sc ") {
        if cmd.contains("delete") {
            state.add_threat(0.4, "删除系统服务");
        }
        if cmd.contains("stop") {
            state.add_threat(0.2, "停止系统服务");
        }
        if cmd.contains("config") {
            state.add_threat(0.2, "修改服务配置");
        }
    }
    
    // 10. 进程终止
    if cmd.contains("taskkill") {
        state.add_threat(0.5, "终止进程");
        if cmd.contains("/f") {
            state.add_threat(0.3, "强制终止进程");
        }
        if cmd.contains("explorer") || cmd.contains("svchost") || cmd.contains("csrss") {
            state.add_threat(1.0, "终止系统进程");
        }
    }
    
    // 11. 用户账户操作
    if cmd.contains("net user") || cmd.contains("net localgroup") {
        if cmd.contains("add") || cmd.contains("/add") {
            state.add_threat(0.8, "创建用户账户");
        }
        if cmd.contains("delete") || cmd.contains("/delete") {
            state.add_threat(0.7, "删除用户账户");
        }
        if cmd.contains("administrators") {
            state.add_threat(1.0, "修改管理员组");
        }
    }
    
    // 12. 防火墙操作 (安装卸载常见)
    if cmd.contains("netsh") && cmd.contains("firewall") {
        state.add_threat(0.4, "修改防火墙设置");
        if cmd.contains("disable") || cmd.contains("off") {
            state.add_threat(1.0, "禁用防火墙");
        }
    }
    
    // 13. 计划任务
    if cmd.contains("schtasks") || (cmd.contains("at ") && !cmd.contains("path")) {
        state.add_threat(0.3, "创建计划任务");
        state.created_tasks.insert("new_task".to_string());
    }
    
    // 14. 下载操作
    if cmd.contains("bitsadmin") || cmd.contains("certutil -urlcache") || cmd.contains("certutil -split") {
        state.add_threat(0.9, "下载文件");
        state.downloaded_files.insert("unknown".to_string());
    }
    
    // 15. PowerShell 执行
    if cmd.contains("powershell") || cmd.contains("powershell.exe") {
        state.add_threat(0.2, "执行PowerShell");
        state.spawned_processes.insert("powershell".to_string());
        
        if cmd.contains("-enc") || cmd.contains("-encodedcommand") || cmd.contains("-e ") {
            state.add_threat(1.5, "执行编码命令");
        }
        
        if cmd.contains("-ep bypass") || cmd.contains("-executionpolicy bypass") {
            state.add_threat(1.0, "绕过执行策略");
        }
    }
    
    // 16. 其他脚本执行
    if cmd.contains("mshta") || cmd.contains("cscript") || cmd.contains("wscript") {
        state.add_threat(0.7, "执行脚本");
    }
    
    // 16.1 UAC 提权绕过（Shell.Application + ShellExecute + runas）
    if cmd.contains("shell.application") && cmd.contains("shellexecute") && cmd.contains("runas") {
        state.add_threat(2.0, "UAC提权绕过");
    }
    
    // 17. DLL 操作
    if cmd.contains("regsvr32") || cmd.contains("rundll32") {
        state.add_threat(0.2, "加载DLL");
    }
    
    // 18. 文件关联修改
    if cmd.contains("assoc ") || cmd.contains("ftype ") {
        state.add_threat(0.2, "修改文件关联");
    }
    
    // 19. 权限操作
    if cmd.contains("takeown") || cmd.contains("icacls") || cmd.contains("cacls") {
        state.add_threat(0.2, "修改文件权限");
    }
    
    // 20. 隐藏文件
    if cmd.contains("attrib") && (cmd.contains("+h") || cmd.contains("+s")) {
        state.add_threat(0.3, "隐藏文件");
    }
    
    // 21. 日志清除
    if cmd.contains("wevtutil") && cmd.contains("cl") {
        state.add_threat(1.0, "清除事件日志");
        state.cleared_logs = true;
    }
    
    // 22. 关机操作
    if cmd.contains("shutdown") {
        if cmd.contains("/f") && cmd.contains("/r") {
            state.add_threat(1.5, "强制重启系统");
        } else if cmd.contains("/r") || cmd.contains("/s") {
            state.add_threat(1.0, "关机/重启系统");
        } else {
            state.add_threat(0.3, "关机/重启系统");
        }
    }
}

/// 分析 BAT 文件所属的病毒家族
pub fn analyze_bat_family(content: &str, behaviors: &[String]) -> String {
    let mut family_scores: std::collections::HashMap<&str, i32> = std::collections::HashMap::new();
    
    // 根据行为推断家族
    for behavior in behaviors {
        match behavior.as_str() {
            "文件删除操作" | "目录删除操作" => {
                *family_scores.entry("Trojan.Win32.FileDestroyer").or_insert(0) += 3;
                *family_scores.entry("Trojan.Win32.DiskWiper").or_insert(0) += 2;
            }
            "磁盘格式化" | "磁盘分区操作" | "删除卷影副本" | "删除备份" => {
                *family_scores.entry("Trojan.Win32.DiskWiper").or_insert(0) += 5;
                *family_scores.entry("Ransomware").or_insert(0) += 3;
            }
            "注册表删除" | "注册表修改" => {
                *family_scores.entry("Trojan.Win32.RegistryModifier").or_insert(0) += 3;
                *family_scores.entry("Trojan.Win32.StartupModifier").or_insert(0) += 2;
            }
            "用户账户操作" | "用户组操作" => {
                *family_scores.entry("Backdoor.Win32.AccountManipulator").or_insert(0) += 4;
                *family_scores.entry("Trojan.Win32.PrivilegeEscalator").or_insert(0) += 2;
            }
            "防火墙设置" => {
                *family_scores.entry("Backdoor.Win32.FirewallDisabler").or_insert(0) += 4;
                *family_scores.entry("Trojan.Win32.DefenseEvasion").or_insert(0) += 2;
            }
            "服务配置" | "服务停止" | "服务删除" => {
                *family_scores.entry("Trojan.Win32.ServiceManipulator").or_insert(0) += 3;
                *family_scores.entry("Rootkit").or_insert(0) += 2;
            }
            "强制终止进程" | "进程操作" => {
                *family_scores.entry("Trojan.Win32.ProcessKiller").or_insert(0) += 3;
                *family_scores.entry("Trojan.Win32.AVKill").or_insert(0) += 2;
            }
            "PowerShell执行" => {
                *family_scores.entry("Trojan.Win32.PowerShellDropper").or_insert(0) += 2;
                *family_scores.entry("Backdoor.Win32.PowerShell").or_insert(0) += 2;
            }
            "编码命令" => {
                *family_scores.entry("Trojan.Win32.Obfuscated").or_insert(0) += 5;
                *family_scores.entry("Trojan.Win32.EncodedPayload").or_insert(0) += 4;
            }
            "下载工具" => {
                *family_scores.entry("Trojan.Win32.Downloader").or_insert(0) += 4;
                *family_scores.entry("Trojan.Win32.Dropper").or_insert(0) += 3;
            }
            "HTA执行" | "脚本执行" => {
                *family_scores.entry("Trojan.Win32.ScriptRunner").or_insert(0) += 3;
                *family_scores.entry("Trojan.Win32.HTALoader").or_insert(0) += 3;
            }
            "DLL注册" | "DLL执行" => {
                *family_scores.entry("Trojan.Win32.DLLInjector").or_insert(0) += 3;
                *family_scores.entry("Trojan.Win32.DLLLoader").or_insert(0) += 2;
            }
            "计划任务" => {
                *family_scores.entry("Trojan.Win32.Persistence").or_insert(0) += 3;
                *family_scores.entry("Backdoor.Win32.ScheduledTask").or_insert(0) += 3;
            }
            "文件关联" | "文件类型" => {
                *family_scores.entry("Trojan.Win32.FileHijacker").or_insert(0) += 3;
            }
            "权限获取" | "权限修改" | "隐藏文件" | "系统文件操作" => {
                *family_scores.entry("Trojan.Win32.PrivilegeEscalator").or_insert(0) += 3;
                *family_scores.entry("Rootkit").or_insert(0) += 2;
            }
            "启动配置" => {
                *family_scores.entry("Trojan.Win32.BootModifier").or_insert(0) += 4;
                *family_scores.entry("Rootkit").or_insert(0) += 3;
            }
            "清除日志" => {
                *family_scores.entry("Trojan.Win32.LogCleaner").or_insert(0) += 4;
                *family_scores.entry("Trojan.Win32.AntiForensics").or_insert(0) += 3;
            }
            "关机操作" => {
                *family_scores.entry("Trojan.Win32.SystemDisruptor").or_insert(0) += 2;
            }
            _ => {}
        }
    }
    
    // 特殊模式检测
    if content.contains("-enc") || content.contains("-encodedcommand") {
        *family_scores.entry("Trojan.Win32.EncodedPayload").or_insert(0) += 5;
    }
    
    if content.contains("vssadmin delete") || content.contains("wbadmin delete") {
        *family_scores.entry("Ransomware").or_insert(0) += 5;
    }
    
    if content.contains("bcdedit") {
        *family_scores.entry("Trojan.Win32.BootModifier").or_insert(0) += 4;
    }
    
    // 找出得分最高的家族
    let mut max_score = 0;
    let mut best_family = "Trojan.Win32.BAT.Generic";
    
    for (family, score) in &family_scores {
        if *score > max_score {
            max_score = *score;
            best_family = *family;
        }
    }
    
    best_family.to_string()
}

/// 基于模拟执行状态分析病毒家族 - 简化命名，类似火绒风格
fn analyze_bat_family_by_state(state: &ExecutionState) -> String {
    let mut family_scores: std::collections::HashMap<&str, i32> = std::collections::HashMap::new();
    
    // 根据模拟执行的行为推断家族 - 使用简洁的命名
    for behavior in &state.behaviors {
        match behavior.as_str() {
            "格式化磁盘" | "磁盘分区操作" => {
                *family_scores.entry("Trojan/KillDisk").or_insert(0) += 5;
                *family_scores.entry("Ransomware").or_insert(0) += 3;
            }
            "修改启动配置" => {
                *family_scores.entry("Trojan/BootKit").or_insert(0) += 5;
                *family_scores.entry("Rootkit").or_insert(0) += 4;
            }
            "删除卷影副本" | "删除系统备份" => {
                *family_scores.entry("Ransomware").or_insert(0) += 5;
                *family_scores.entry("Trojan/KillFiles").or_insert(0) += 3;
            }
            "强制删除文件" | "批量删除文件" => {
                *family_scores.entry("Trojan/KillFiles").or_insert(0) += 4;
            }
            "删除系统文件" | "删除系统目录" => {
                *family_scores.entry("Trojan/SystemDestroyer").or_insert(0) += 5;
                *family_scores.entry("Trojan/KillFiles").or_insert(0) += 3;
            }
            "添加启动项" => {
                *family_scores.entry("Trojan/Startup").or_insert(0) += 4;
                *family_scores.entry("Trojan/Persistence").or_insert(0) += 3;
            }
            "删除注册表项" | "修改注册表" => {
                *family_scores.entry("Trojan/Registry").or_insert(0) += 3;
            }
            "创建用户账户" | "修改管理员组" => {
                *family_scores.entry("Backdoor/AccountHack").or_insert(0) += 5;
                *family_scores.entry("Trojan/Privilege").or_insert(0) += 3;
            }
            "禁用防火墙" => {
                *family_scores.entry("Backdoor/FirewallKill").or_insert(0) += 5;
                *family_scores.entry("Trojan/DefenseKill").or_insert(0) += 3;
            }
            "执行编码命令" | "绕过执行策略" => {
                *family_scores.entry("Trojan/Obfuscated").or_insert(0) += 5;
                *family_scores.entry("Trojan/Encoded").or_insert(0) += 4;
            }
            "下载文件" => {
                *family_scores.entry("TrojanDownloader/BAT").or_insert(0) += 4;
                *family_scores.entry("Trojan/Dropper").or_insert(0) += 3;
            }
            "终止系统进程" | "终止进程" | "强制终止进程" => {
                *family_scores.entry("Trojan/KillAV").or_insert(0) += 5;
                *family_scores.entry("Trojan/ProcessKill").or_insert(0) += 3;
            }
            "清除事件日志" => {
                *family_scores.entry("Trojan/LogWiper").or_insert(0) += 4;
                *family_scores.entry("Trojan/AntiForensics").or_insert(0) += 3;
            }
            "创建计划任务" => {
                *family_scores.entry("Trojan/Persistence").or_insert(0) += 3;
                *family_scores.entry("Backdoor/ScheduledTask").or_insert(0) += 3;
            }
            "删除系统服务" => {
                *family_scores.entry("Trojan/ServiceKill").or_insert(0) += 4;
            }
            _ => {}
        }
    }
    
    // 根据系统修改状态额外加分
    if state.modified_boot {
        *family_scores.entry("Trojan/BootKit").or_insert(0) += 5;
        *family_scores.entry("Rootkit").or_insert(0) += 3;
    }
    
    if state.cleared_logs {
        *family_scores.entry("Trojan/LogWiper").or_insert(0) += 4;
    }
    
    if !state.downloaded_files.is_empty() {
        *family_scores.entry("TrojanDownloader/BAT").or_insert(0) += 3;
    }
    
    if !state.created_tasks.is_empty() {
        *family_scores.entry("Trojan/Persistence").or_insert(0) += 3;
    }
    
    // 找出得分最高的家族
    let mut max_score = 0;
    let mut best_family = "Trojan/BAT.Agent";
    
    for (family, score) in &family_scores {
        if *score > max_score {
            max_score = *score;
            best_family = *family;
        }
    }
    
    // 如果没有明确匹配，根据威胁分数给出通用家族
    if max_score == 0 {
        if state.threat_score >= 3.0 {
            return "Trojan/BAT.High".to_string();
        } else if state.threat_score >= 1.5 {
            return "Trojan/BAT.Medium".to_string();
        } else {
            return "Trojan/BAT.Low".to_string();
        }
    }
    
    best_family.to_string()
}
