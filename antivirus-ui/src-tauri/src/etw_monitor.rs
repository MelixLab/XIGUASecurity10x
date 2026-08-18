// ETW (Event Tracing for Windows) 监控模块
// 通过启动 C# EtwCollector.exe 子进程获取内核 ETW 事件

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::thread;
use std::time::Duration;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio, Child};
use serde::{Serialize, Deserialize};
use chrono::Local;

// 进程信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub command_line: Option<String>,
    pub parent_pid: Option<u32>,
    pub parent_name: Option<String>,
    pub start_time: String,
    pub risk_level: String,
    pub risk_score: u32,
    pub threat_family: String,
    pub threat_confidence: String,
    pub event_count: u32,
    pub network_events: u32,
    pub file_events: u32,
    pub registry_events: u32,
    pub process_events: u32,
    pub suspicious_tool_count: u32,
    pub events: Vec<ProcessEvent>,
}

// 进程事件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub time: String,
    pub event_type: String,
    pub action: String,
    pub details: String,
    pub risk: String,
}

// 从 C# EtwCollector 接收的 JSON 事件
#[derive(Debug, Deserialize)]
struct EtwJsonEvent {
    #[serde(rename = "type")]
    event_type: String,
    pid: i32,
    name: String,
    details: String,
    #[serde(default)]
    time: String,
    #[serde(default)]
    ppid: i32,
    #[serde(default)]
    tid: i32,
}

// ETW 监控状态
pub struct EtwMonitor {
    enabled: Arc<Mutex<bool>>,
    processes: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
    monitor_thread: Option<thread::JoinHandle<()>>,
    collector_child: Arc<Mutex<Option<Child>>>,
}

impl EtwMonitor {
    pub fn new() -> Self {
        Self {
            enabled: Arc::new(Mutex::new(false)),
            processes: Arc::new(Mutex::new(HashMap::new())),
            monitor_thread: None,
            collector_child: Arc::new(Mutex::new(None)),
        }
    }

    pub fn start(&mut self) {
        let mut enabled = self.enabled.lock().unwrap();
        if *enabled {
            println!("[ETW] Monitor already running");
            return;
        }
        *enabled = true;
        drop(enabled);

        println!("[ETW] Starting ETW monitor...");

        let enabled_clone = Arc::clone(&self.enabled);
        let processes_clone = Arc::clone(&self.processes);
        let collector_child = Arc::clone(&self.collector_child);

        self.monitor_thread = Some(thread::spawn(move || {
            monitor_loop(enabled_clone, processes_clone, collector_child);
        }));
    }

    pub fn stop(&mut self) {
        let mut enabled = self.enabled.lock().unwrap();
        *enabled = false;
        drop(enabled);

        // 杀掉子进程
        if let Some(mut child) = self.collector_child.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
            println!("[ETW] Collector process killed");
        }

        if let Some(handle) = self.monitor_thread.take() {
            let _ = handle.join();
        }

        let mut processes = self.processes.lock().unwrap();
        processes.clear();
        println!("[ETW] Monitor stopped");
    }

    pub fn get_process_list(&self) -> Vec<ProcessInfo> {
        let processes = self.processes.lock().unwrap();
        processes.values().cloned().collect()
    }

    pub fn get_process_detail(&self, pid: u32) -> Option<ProcessInfo> {
        let processes = self.processes.lock().unwrap();
        processes.get(&pid).cloned()
    }
}

// 监控循环
fn monitor_loop(
    enabled: Arc<Mutex<bool>>,
    processes: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
    collector_child: Arc<Mutex<Option<Child>>>,
) {
    println!("[ETW] Monitor loop started");
    
    // 获取初始进程列表
    match get_system_processes() {
        Ok(system_processes) => {
            println!("[ETW] First scan found {} processes", system_processes.len());
            let mut processes_map = processes.lock().unwrap();
            for (pid, name, path) in system_processes {
                let process = create_process_info(pid, name, path);
                processes_map.insert(pid, process);
            }
            println!("[ETW] Added {} processes to monitor", processes_map.len());
        }
        Err(e) => {
            println!("[ETW] Failed to get system processes: {}", e);
        }
    }
    
    // 启动 C# ETW 采集器子进程
    #[cfg(windows)]
    {
        let processes_clone = Arc::clone(&processes);
        let enabled_clone = Arc::clone(&enabled);
        let child_holder = Arc::clone(&collector_child);
        thread::spawn(move || {
            etw_collector_thread(processes_clone, enabled_clone, child_holder);
        });
    }
    
    // 主循环：定期更新进程列表
    loop {
        if !*enabled.lock().unwrap() {
            break;
        }

        if let Ok(system_processes) = get_system_processes() {
            let mut processes_map = processes.lock().unwrap();
            
            for (pid, name, path) in system_processes {
                if !processes_map.contains_key(&pid) {
                    let process = create_process_info(pid, name, path);
                    processes_map.insert(pid, process);
                    add_process_event(&mut processes_map, pid, "process", "进程启动");
                }
            }
        }

        thread::sleep(Duration::from_secs(2));
    }
    
    println!("[ETW] Monitor loop ended");
}

// 启动 C# ETW 采集器并读取 JSON 事件
#[cfg(windows)]
fn etw_collector_thread(
    processes: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
    enabled: Arc<Mutex<bool>>,
    child_holder: Arc<Mutex<Option<Child>>>,
) {
    println!("[ETW] Launching EtwCollector.exe...");
    
    // 查找 EtwCollector.exe
    let exe_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("EtwCollector.exe")))
        .unwrap_or_else(|| std::path::PathBuf::from("EtwCollector.exe"));
    
    println!("[ETW] Collector path: {:?}", exe_path);
    
    let mut child = match Command::new(&exe_path)
        .arg("XIGUASecurity_ETW")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            println!("[ETW] ERROR: Failed to start EtwCollector.exe: {}", e);
            println!("[ETW] Falling back to process polling mode");
            fallback_process_monitor(processes, enabled);
            return;
        }
    };
    
    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let stderr = child.stderr.take().expect("Failed to capture stderr");
    
    // 保存 child 句柄以便外部 kill
    {
        let mut holder = child_holder.lock().unwrap();
        *holder = Some(child);
        drop(holder);
    }
    
    // 在单独线程读取 stderr 以打印日志
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            if let Ok(l) = line {
                if l.contains("[ETW]") {
                    eprintln!("{}", l);
                }
            }
        }
    });
    
    println!("[ETW] Collector started, reading events...");
    
    let reader = BufReader::new(stdout);
    let mut event_count = 0u64;
    
    for line in reader.lines() {
        // 检查停止信号
        if !*enabled.lock().unwrap() {
            break;
        }
        
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        
        if line.is_empty() {
            continue;
        }
        
        // 解析 JSON 事件
        let evt: EtwJsonEvent = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => continue,
        };
        
        let pid = evt.pid as u32;
        
        match evt.event_type.as_str() {
            "heartbeat" => {
            }
            "process_start" => {
                let new_path = evt.details.clone();
                let new_name = evt.name.clone();
                let mut map = processes.lock().unwrap();
                if !map.contains_key(&pid) {
                    let mut proc = create_process_info(pid, new_name.clone(), new_path);
                    proc.parent_pid = if evt.ppid > 0 { Some(evt.ppid as u32) } else { None };
                    map.insert(pid, proc);
                }
                add_process_event(&mut map, pid, "process", "进程启动");
                if evt.ppid > 0 {
                    let ppid = evt.ppid as u32;
                    let child_detail = format!("{} (PID: {})", new_name, pid);
                    add_process_event_with_detail(&mut map, ppid, "process", "启动子进程", &child_detail);
                    // 父进程风险：如果启动了系统工具，增加 suspicious_tool_count
                    if let Some(parent) = map.get_mut(&ppid) {
                        let event_risk = eval_event_risk("process", &new_name);
                        if event_risk > 0 {
                            parent.risk_score += event_risk;
                            // 如果是已知系统工具，累计 suspicious_tool_count
                            if is_suspicious_system_tool(&new_name) {
                                parent.suspicious_tool_count += 1;
                            }
                        }
                        reassess_risk(parent);
                    }
                }
                if let Some(p) = map.get_mut(&pid) {
                    reassess_risk(p);
                }
            }
            "process_stop" => {
                let mut map = processes.lock().unwrap();
                add_process_event(&mut map, pid, "process", "进程终止");
                map.remove(&pid);
            }
            "thread" => {
                let mut map = processes.lock().unwrap();
                add_process_event_with_detail(&mut map, pid, "thread", "线程活动", &evt.details);
            }
            "image" => {
                let mut map = processes.lock().unwrap();
                add_process_event_with_detail(&mut map, pid, "image", "模块加载", &evt.details);
                if let Some(p) = map.get_mut(&pid) {
                    let risk_inc = eval_event_risk("file", &evt.details);
                    if risk_inc > 0 { p.risk_score += risk_inc; }
                    reassess_risk(p);
                }
            }
            "file" => {
                let mut map = processes.lock().unwrap();
                add_process_event_with_detail(&mut map, pid, "file", "文件操作", &evt.details);
                if let Some(p) = map.get_mut(&pid) {
                    p.file_events += 1;
                    let risk_inc = eval_event_risk("file", &evt.details);
                    if risk_inc > 0 { p.risk_score += risk_inc; }
                    reassess_risk(p);
                }
            }
            "network" => {
                let mut map = processes.lock().unwrap();
                add_process_event_with_detail(&mut map, pid, "network", "网络活动", &evt.details);
                if let Some(p) = map.get_mut(&pid) {
                    p.network_events += 1;
                    let risk_inc = eval_event_risk("network", &evt.details);
                    if risk_inc > 0 { p.risk_score += risk_inc; }
                    reassess_risk(p);
                }
            }
            "registry" => {
                let mut map = processes.lock().unwrap();
                add_process_event_with_detail(&mut map, pid, "registry", "注册表操作", &evt.details);
                if let Some(p) = map.get_mut(&pid) {
                    p.registry_events += 1;
                    let risk_inc = eval_event_risk("registry", &evt.details);
                    if risk_inc > 0 { p.risk_score += risk_inc; }
                    reassess_risk(p);
                }
            }
            _ => {}
        }
        
        event_count += 1;
        if event_count % 100 == 0 {
            println!("[ETW] Received {} events so far", event_count);
        }
    }
    
    println!("[ETW] Collector thread ended ({} total events)", event_count);
}

// 没有 ETW 采集器时的降级方案：仅轮询进程
#[cfg(windows)]
fn fallback_process_monitor(
    processes: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
    enabled: Arc<Mutex<bool>>,
) {
    println!("[ETW] Running in fallback mode (process polling only)");
    loop {
        if !*enabled.lock().unwrap() {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

// 为进程添加事件
fn add_process_event(
    processes: &mut HashMap<u32, ProcessInfo>,
    pid: u32,
    event_type: &str,
    action: &str,
) {
    if let Some(process) = processes.get_mut(&pid) {
        let now = Local::now();
        let details = format!("{} {} (PID: {})", action, &process.name, pid);
        process.events.push(ProcessEvent {
            time: now.format("%H:%M:%S").to_string(),
            event_type: event_type.to_string(),
            action: action.to_string(),
            details,
            risk: "low".to_string(),
        });
        process.event_count += 1;
        match event_type {
            "process" => process.process_events += 1,
            "network" => process.network_events += 1,
            "file" => process.file_events += 1,
            "registry" => process.registry_events += 1,
            _ => {}
        }
        
        if process.events.len() > 200 {
            process.events.drain(0..(process.events.len() - 200));
        }
    }
}

// 为进程添加详细事件
fn add_process_event_with_detail(
    processes: &mut HashMap<u32, ProcessInfo>,
    pid: u32,
    event_type: &str,
    action: &str,
    details: &str,
) {
    if let Some(process) = processes.get_mut(&pid) {
        let now = Local::now();
        process.events.push(ProcessEvent {
            time: now.format("%H:%M:%S").to_string(),
            event_type: event_type.to_string(),
            action: action.to_string(),
            details: details.to_string(),
            risk: "low".to_string(),
        });
        process.event_count += 1;
        match event_type {
            "process" => process.process_events += 1,
            "network" => process.network_events += 1,
            "file" => process.file_events += 1,
            "registry" => process.registry_events += 1,
            _ => {}
        }
        
        if process.events.len() > 200 {
            process.events.drain(0..(process.events.len() - 200));
        }
    }
}

// 获取系统进程列表
#[cfg(windows)]
fn get_system_processes() -> Result<Vec<(u32, String, String)>, String> {
    use windows::Win32::System::ProcessStatus::{EnumProcesses, GetModuleBaseNameW, GetModuleFileNameExW};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
    use windows::Win32::Foundation::CloseHandle;

    let mut processes = Vec::new();
    let mut process_ids = [0u32; 1024];
    let mut bytes_returned = 0u32;

    unsafe {
        if EnumProcesses(
            process_ids.as_mut_ptr(),
            (process_ids.len() * std::mem::size_of::<u32>()) as u32,
            &mut bytes_returned,
        ).is_ok() {
            let num_processes = bytes_returned as usize / std::mem::size_of::<u32>();
            
            for i in 0..num_processes {
                let pid = process_ids[i];
                if pid == 0 {
                    continue;
                }

                if let Ok(handle) = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    false,
                    pid,
                ) {
                    let mut name_buffer = [0u16; 260];
                    let name_len = GetModuleBaseNameW(handle, None, &mut name_buffer);
                    
                    if name_len > 0 {
                        let name = String::from_utf16_lossy(&name_buffer[..name_len as usize]);
                        
                        let mut path_buffer = [0u16; 260];
                        let path_len = GetModuleFileNameExW(handle, None, &mut path_buffer);
                        let path = if path_len > 0 {
                            String::from_utf16_lossy(&path_buffer[..path_len as usize])
                        } else {
                            name.clone()
                        };
                        
                        processes.push((pid, name, path));
                    }
                    
                    let _ = CloseHandle(handle);
                }
            }
        }
    }

    Ok(processes)
}

#[cfg(not(windows))]
fn get_system_processes() -> Result<Vec<(u32, String, String)>, String> {
    Ok(Vec::new())
}

fn create_process_info(pid: u32, name: String, path: String) -> ProcessInfo {
    let now = Local::now();
    let (risk_level, risk_score) = assess_risk(&name, &path);
    
    ProcessInfo {
        pid,
        name: name.clone(),
        path: path.clone(),
        command_line: None,
        parent_pid: None,
        parent_name: None,
        start_time: now.format("%Y-%m-%d %H:%M:%S").to_string(),
        risk_level,
        risk_score,
        threat_family: String::new(),
        threat_confidence: String::new(),
        event_count: 0,
        network_events: 0,
        file_events: 0,
        registry_events: 0,
        process_events: 0,
        suspicious_tool_count: 0,
        events: Vec::new(),
    }
}

// ==================== 企业级 EDR 风险评分 ====================

// 系统侦察/管理工具列表 —— 大量调用这些工具非常可疑
fn is_suspicious_system_tool(name: &str) -> bool {
    let tools: &[&str] = &[
        "tasklist.exe", "whoami.exe", "net.exe", "net1.exe",
        "netstat.exe", "sc.exe", "wmic.exe", "ipconfig.exe",
        "schtasks.exe", "reg.exe", "regsvr32.exe", "rundll32.exe",
        "mshta.exe", "wscript.exe", "cscript.exe", "powershell.exe",
        "cmd.exe", "certutil.exe", "bitsadmin.exe", "nslookup.exe",
        "ping.exe", "tracert.exe", "arp.exe", "systeminfo.exe",
        "quser.exe", "query.exe", "findstr.exe", "vssadmin.exe",
        "wevtutil.exe", "bcdedit.exe", "icacls.exe", "takeown.exe",
        "attrib.exe", "cacls.exe", "diskpart.exe", "driverquery.exe",
        "fc.exe", "gpresult.exe", "gpupdate.exe", "logoff.exe",
        "makecab.exe", "mofcomp.exe", "nbtstat.exe", "netsh.exe",
        "pathping.exe", "psexec.exe", "qwinsta.exe", "route.exe",
        "shutdown.exe", "wusa.exe", "xcopy.exe",
    ];
    tools.contains(&name.to_lowercase().as_str())
}

// 评估单个事件的威胁程度（返回需加到父进程上的分）
fn eval_event_risk(event_type: &str, details: &str) -> u32 {
    let upper = details.to_uppercase();

    match event_type {
        "process" => {
            if is_suspicious_system_tool(details) {
                return 3;
            }
            0
        }
        "network" => {
            // 仅高危端口加分，常见端口一律不加
            if upper.contains(":4444") || upper.contains(":1337")
                || upper.contains(":3389") || upper.contains(":445")
                || upper.contains(":135") || upper.contains(":22")
                || upper.contains(":6667") || upper.contains(":5552")
                || upper.contains(":1433") || upper.contains(":1521")
                || upper.contains(":3306") || upper.contains(":6379")
                || upper.contains(":27017") || upper.contains(":11211") {
                return 3;
            }
            0
        }
        "registry" => {
            // 持久化相关键
            if upper.contains("\\RUN") || upper.contains("\\RUNONCE")
                || upper.contains("\\RUNSERVICES") || upper.contains("\\SERVICES\\")
                || upper.contains("\\WINDOWS\\CURRENTVERSION\\RUN") {
                return 5;
            }
            if upper.contains("\\WINLOGON\\") || upper.contains("\\SHELL\\")
                || upper.contains("\\BOOTEXECUTE") || upper.contains("\\APPSETUP\\") {
                return 5;
            }
            // 浏览器劫持
            if upper.contains("BROWSER HELPER OBJECTS")
                || upper.contains("\\EXPLORER\\BROWSER HELPER") {
                return 4;
            }
            // 安全软件禁用
            if upper.contains("\\WINDOWS DEFENDER") || upper.contains("DISABLEANTISPYWARE")
                || upper.contains("DISABLEANTIVIRUS") {
                return 3;
            }
            0
        }
        "file" => {
            if upper.contains("\\STARTUP\\")
                || upper.contains("\\START MENU\\PROGRAMS\\STARTUP") {
                return 5;
            }
            if (upper.contains("\\TEMP\\") || upper.contains("\\APPDATA\\LOCAL\\TEMP\\"))
                && (upper.ends_with(".EXE") || upper.ends_with(".DLL")
                    || upper.ends_with(".SYS") || upper.ends_with(".PS1")
                    || upper.ends_with(".VBS") || upper.ends_with(".BAT")
                    || upper.ends_with(".VBE") || upper.ends_with(".JS")
                    || upper.ends_with(".HTA")) {
                return 3;
            }
            0
        }
        _ => 0,
    }
}

fn assess_risk(name: &str, path: &str) -> (String, u32) {
    // 已知安全应用直接豁免
    if is_legitimate_process(name, path) {
        return ("low".to_string(), 0);
    }

    let name_lower = name.to_lowercase();
    let path_lower = path.to_lowercase();

    // 静态分析：恶意文件名模式 → 直接高风险
    let high_risk_patterns = [
        "mimikatz", "procdump", "psexec", "psexesvc",
        "suspicious", "malware", "trojan", "backdoor",
        "keylogger", "ransomware", "miner", "inject",
    ];
    for pattern in &high_risk_patterns {
        if name_lower.contains(pattern) {
            return ("high".to_string(), 20);
        }
    }

    let mut score: u32 = 0;

    // 从临时目录/下载目录运行 → 可疑
    if path_lower.contains("\\temp\\") || path_lower.contains("\\appdata\\local\\temp\\") {
        score += 5;
    }
    if path_lower.contains("\\downloads\\") || path_lower.contains("\\download\\") {
        score += 3;
    }

    // 系统进程豁免
    if is_system_process(name) {
        return ("low".to_string(), 0);
    }

    ("low".to_string(), score)
}

// 根据行为动态重新评估 —— 真正的EDR逻辑
fn reassess_risk(process: &mut ProcessInfo) {
    // 已知安全应用不参与威胁评分
    if is_legitimate_process(&process.name, &process.path) {
        process.risk_score = 0;
        process.risk_level = "low".to_string();
        process.threat_family = String::new();
        process.threat_confidence = String::new();
        return;
    }

    let path_lower = process.path.to_lowercase();

    // 基于当前累积分数 + 行为 + 环境 计算总分
    // 注意：risk_score 已被 eval_event_risk 逐次累加，不要覆盖
    let score = process.risk_score 
        + risk_behavior_bonus(process)
        + risk_environment_bonus(&path_lower);

    process.risk_score = score;
    process.risk_level = if score >= 20 {
        "high".to_string()
    } else if score >= 12 {
        "medium".to_string()
    } else {
        "low".to_string()
    };
    // 中风险以上进行威胁分类
    if process.risk_level == "high" || process.risk_level == "medium" {
        let (family, confidence) = classify_threat(process);
        process.threat_family = family;
        process.threat_confidence = confidence;
    }
}

// ==================== 威胁分类引擎 ====================
// 原则：宁可不报，不能错杀。仅在有明确恶意行为组合时分类。

fn classify_threat(process: &ProcessInfo) -> (String, String) {
    let path_lower = process.path.to_lowercase();
    let name_lower = process.name.to_lowercase();
    let tl = process.suspicious_tool_count;
    let pe = process.process_events;
    let temp = path_lower.contains("\\temp\\") || path_lower.contains("\\appdata\\local\\temp\\");
    let downloads = path_lower.contains("\\downloads\\");
    let fringe = temp || downloads;

    // ---------- Ransom (勒索软件) ----------
    // 特征：vssadmin/bcdedit 痕迹 + 大量进程
    if tl >= 2 && pe > 8 {
        return ("Ransom·勒索行为".to_string(), "高置信".to_string());
    }

    // ---------- SilverFox / 银狐木马 ----------
    // 特征：大量侦察工具 + C2 + 可疑路径
    if tl >= 4 && fringe {
        return ("银狐木马".to_string(), "高置信".to_string());
    }
    if tl >= 3 && fringe {
        return ("银狐木马·疑似".to_string(), "疑似".to_string());
    }

    // ---------- Worm (蠕虫) ----------
    // 特征：极多子进程 + 横向移动工具
    if pe > 30 && tl >= 3 {
        return ("Worm·蠕虫传播".to_string(), "已确认".to_string());
    }
    if pe > 20 && tl >= 2 {
        return ("Worm·疑似蠕虫".to_string(), "高置信".to_string());
    }

    // ---------- Miner (挖矿) ----------
    // 特征：进程名含 miner/stratum 等关键词
    if name_lower.contains("miner") || name_lower.contains("xmrig")
        || name_lower.contains("stratum") {
        return ("Miner·挖矿程序".to_string(), "已确认".to_string());
    }

    // ---------- Dropper (投放器) ----------
    if fringe && pe >= 4 && tl >= 1 {
        return ("Dropper·投放器".to_string(), "高置信".to_string());
    }
    if fringe && pe >= 2 {
        return ("Dropper·疑似投放".to_string(), "疑似".to_string());
    }

    // ---------- Backdoor (后门) ----------
    // 特征：持久化行为 + 系统工具
    if process.risk_score >= 10 && tl >= 1 && fringe {
        return ("Backdoor·后门".to_string(), "高置信".to_string());
    }

    // ---------- Trojan (通用木马) ----------
    if pe > 20 && tl >= 2 {
        return ("Trojan·远控木马".to_string(), "高置信".to_string());
    }
    if pe > 10 && tl >= 1 {
        return ("Trojan·疑似木马".to_string(), "疑似".to_string());
    }

    // ---------- Rootkit ----------
    if name_lower.contains("rootkit") || name_lower.contains("tdl") {
        return ("Rootkit".to_string(), "高置信".to_string());
    }

    // ---------- 横向移动 ----------
    if tl >= 4 && pe > 5 {
        return ("Lateral·横向移动".to_string(), "高置信".to_string());
    }

    // ---------- 系统工具滥用 ----------
    if tl >= 3 {
        return ("系统工具滥用".to_string(), "疑似".to_string());
    }

    // ---------- 无法归类 ----------
    if process.risk_level == "high" {
        return ("未知威胁".to_string(), "低置信".to_string());
    }
    ("可疑进程行为".to_string(), "低置信".to_string())
}

fn risk_behavior_bonus(process: &ProcessInfo) -> u32 {
    // 核心原则：网络/文件/注册表的数量不代表恶意，只有模式才代表恶意
    // 仅保留两项真正有效的指标：系统工具调用 + 子进程链
    let mut bonus: u32 = 0;

    // 调用了可疑系统工具 —— 正常软件不会频繁调用 whoami/tasklist/sc 等
    match process.suspicious_tool_count {
        n if n >= 5  => bonus += 10,
        n if n >= 3  => bonus += 6,
        n if n >= 1  => bonus += 2,
        _ => {}
    }

    bonus
}

fn risk_environment_bonus(path_lower: &str) -> u32 {
    let mut bonus: u32 = 0;
    if path_lower.contains("\\temp\\") || path_lower.contains("\\appdata\\local\\temp\\") {
        bonus += 5;
    }
    if path_lower.contains("\\downloads\\") {
        bonus += 3;
    }
    if !path_lower.contains("\\windows\\")
        && !path_lower.contains("\\program files")
        && !path_lower.contains("\\program files (x86)") {
        bonus += 1;
    }
    bonus
}

fn is_system_process(name: &str) -> bool {
    let system_processes = [
        "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
        "winlogon.exe", "dwm.exe", "taskhost.exe", "conhost.exe",
    ];
    
    system_processes.iter().any(|&p| name.to_lowercase() == p)
}

// 已知安全应用白名单 —— 这些应用即使行为活跃也不应标记为威胁
fn is_legitimate_application(name: &str) -> bool {
    let legit = [
        // 即时通讯
        "qq.exe", "wechat.exe", "weixin.exe", "tim.exe",
        "dingtalk.exe", "feishu.exe",
        "discord.exe", "telegram.exe", "slack.exe",
        "teams.exe", "skype.exe",
        // 浏览器
        "msedge.exe", "chrome.exe", "firefox.exe",
        "opera.exe", "brave.exe",
        // 开发工具
        "code.exe", "devenv.exe", "msbuild.exe",
        "idea64.exe", "pycharm64.exe", "rider64.exe",
        "sublime_text.exe", "notepad++.exe",
        // 办公
        "wps.exe", "wpp.exe", "et.exe",
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "notepad.exe", "mspaint.exe", "calc.exe", "snippingtool.exe",
        // 游戏
        "steam.exe", "epicgameslauncher.exe",
        // 媒体
        "spotify.exe", "vlc.exe", "obs64.exe",
        // 输入法
        "ctfmon.exe", "chsinaping.exe", "sogoupy.exe",
        // 云存储
        "onedrive.exe", "dropbox.exe",
        // 系统工具(仅用户可见的)
        "taskmgr.exe", "cmd.exe", "powershell.exe",
        "xcopy.exe", "robocopy.exe", "find.exe",
        "wdica.exe", "clipboard.exe", "sndvol.exe",
        // 远程
        "mstsc.exe", "anydesk.exe", "todesk.exe",
        "teamviewer.exe", "sunloginclient.exe",
        // 自身
        "xiguasecurity.exe", "xiguasecurity10x.exe",
    ];
    legit.contains(&name.to_lowercase().as_str())
}

fn is_legitimate_process(name: &str, path: &str) -> bool {
    let name_lower = name.to_lowercase();
    let path_lower = path.to_lowercase();

    if is_system_process(&name_lower) { return true; }
    if is_legitimate_application(&name_lower) { return true; }

    // 标记名称包含已知厂商/产品名
    if name_lower.contains("adobe") || name_lower.contains("nvidia")
        || name_lower.contains("intel") || name_lower.contains("amd")
        || name_lower.contains("dell") || name_lower.contains("hp.")
        || name_lower.contains("logitech") || name_lower.contains("razer")
        || name_lower.contains("autodesk") || name_lower.contains("tencent")
        || name_lower.contains("baidu") || name_lower.contains("360")
        || name_lower.contains("kaspersky") || name_lower.contains("eset")
        || name_lower.contains("bitdefender") || name_lower.contains("malwarebytes")
        || name_lower.contains("norton") || name_lower.contains("mcafee")
        || name_lower.contains("avast") || name_lower.contains("avg")
        || name_lower.contains("trend") || name_lower.contains("symantec")
        || name_lower.contains("citrix") || name_lower.contains("vmware")
        || name_lower.contains("oracle") || name_lower.contains("java")
        || name_lower.contains("python") || name_lower.contains("node.")
        || name_lower.contains("docker") || name_lower.contains("nginx")
    {
        return true;
    }

    // Program Files 中的程序
    if path_lower.contains("\\program files\\") || path_lower.contains("\\program files (x86)\\") {
        return true;
    }
    // AppData 中的知名应用目录
    if path_lower.contains("\\appdata\\local\\") || path_lower.contains("\\appdata\\roaming\\") {
        if path_lower.contains("\\microsoft\\") && path_lower.contains("\\teams\\") { return true; }
        if path_lower.contains("\\slack\\") || path_lower.contains("\\discord\\") { return true; }
    }

    false
}

lazy_static::lazy_static! {
    static ref ETW_MONITOR: Arc<Mutex<EtwMonitor>> = Arc::new(Mutex::new(EtwMonitor::new()));
}

pub fn get_etw_monitor() -> Arc<Mutex<EtwMonitor>> {
    Arc::clone(&ETW_MONITOR)
}

pub fn init_rand() {}
