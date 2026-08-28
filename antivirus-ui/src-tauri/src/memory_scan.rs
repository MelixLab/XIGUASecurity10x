//! 内存活动威胁扫描模块
//!
//! 快速扫描开局阶段：遍历系统进程表，对每个运行中进程的镜像文件执行本地引擎扫描。
//!
//! 权限模型：
//! - 主程序以普通权限运行，无法打开提权进程（管理员进程），拿不到它们的镜像路径；
//! - 优先通过 AVGuard.exe（独立提权 R3 进程，管理员 + SeDebugPrivilege）枚举进程表，
//!   返回全部进程（含提权进程）的完整镜像路径；
//! - AVGuard 不可用时回退到本进程用户态 Toolhelp32 快照枚举（仅覆盖可访问的进程）。
//!
//! 命中引擎威胁的进程标记为「内存活动威胁」，前端以独立分类展示。

use serde::Serialize;
use std::collections::HashSet;

use crate::avmodel_client;
use crate::scanner::{ScanResult, SCANNER};

/// 单个进程的扫描结果
#[derive(Debug, Clone, Serialize)]
pub struct ProcessScanResult {
    pub pid: u32,
    pub parent_pid: u32,
    pub process_name: String,
    pub image_path: String,
    /// CLEAN / MALICIOUS / ERROR
    pub result: String,
    pub probability: f32,
    pub virus_family: Option<String>,
    pub family_category: Option<String>,
    /// 是否为内存活动威胁（进程正在运行的镜像被判定为恶意）
    pub is_memory_threat: bool,
}

/// 内存扫描整体结果
#[derive(Debug, Clone, Serialize)]
pub struct MemoryScanOutcome {
    /// 进程列表来源: "avguard"（提权枚举）| "usermode"（用户态兜底）| "none"
    pub source: String,
    /// 进程表总数
    pub total_processes: usize,
    /// 实际扫描的镜像文件数（去重后）
    pub scanned: usize,
    /// 命中威胁数
    pub threats: Vec<ProcessScanResult>,
    /// 枚举/扫描过程中的错误（不影响整体结果）
    pub errors: Vec<String>,
}

/// 运行进程条目（统一 avguard 与用户态两种来源）
struct RunningProcess {
    pid: u32,
    parent_pid: u32,
    name: String,
    image_path: Option<String>,
}

/// 内存活动威胁分类标签（与前端展示一致）
pub const MEMORY_THREAT_CATEGORY: &str = "内存活动威胁";

/// 执行内存活动威胁扫描
pub fn scan_running_processes() -> MemoryScanOutcome {
    let mut outcome = MemoryScanOutcome {
        source: "none".to_string(),
        total_processes: 0,
        scanned: 0,
        threats: Vec::new(),
        errors: Vec::new(),
    };

    // 1. 获取进程表：优先 AVGuard 提权枚举
    let processes: Vec<RunningProcess> = match request_processes_via_avguard() {
        Ok(list) if !list.is_empty() => {
            outcome.source = "avguard".to_string();
            list
        }
        Ok(_list) => {
            // AVGuard 在线但返回空列表（罕见），回退用户态
            outcome.errors.push("AVGuard 返回空进程列表，回退用户态枚举".to_string());
            request_processes_usermode(&mut outcome)
        }
        Err(e) => {
            outcome.errors.push(format!("AVGuard 枚举失败({})，回退用户态枚举", e));
            request_processes_usermode(&mut outcome)
        }
    };

    outcome.total_processes = processes.len();

    // 2. 过滤并去重：只保留有镜像路径的 PE 文件，按路径去重（多进程共享同一镜像只扫一次）
    let own_pid = std::process::id();
    let mut seen: HashSet<String> = HashSet::new();
    let mut to_scan: Vec<(u32, u32, String, String)> = Vec::new(); // (pid, parent_pid, name, path)

    for p in processes {
        if p.pid == own_pid {
            continue; // 自身进程（主程序镜像由白名单兜底，无需扫）
        }
        let Some(path) = p.image_path.as_ref() else {
            continue; // 拿不到路径的进程（如受 PPL 保护）跳过
        };
        let lower = path.to_lowercase();
        if !is_scanable_extension(&lower) {
            continue; // 非 PE 扩展名跳过（进程镜像主要是 exe，也涵盖 dll/sys）
        }
        if seen.insert(lower) {
            to_scan.push((p.pid, p.parent_pid, p.name.clone(), path.clone()));
        }
    }

    // 3. 并行扫描镜像文件
    outcome.scanned = to_scan.len();
    if to_scan.is_empty() {
        return outcome;
    }

    let scanner_guard = match SCANNER.read() {
        Ok(g) => g,
        Err(e) => {
            outcome.errors.push(format!("扫描器锁定失败: {}", e));
            return outcome;
        }
    };

    let results: Vec<(u32, u32, String, String, ScanResult)> = to_scan
        .par_iter()
        .map(|(pid, ppid, name, path)| {
            let scan = scanner_guard.scan_file(path, None);
            (pid.clone(), ppid.clone(), name.clone(), path.clone(), scan)
        })
        .collect();
    drop(scanner_guard);

    // 4. 组装结果：只把引擎判定为恶意的进程加入 threats（干净结果仅计入 scanned 统计）
    for (pid, ppid, name, path, scan) in results {
        // ★历史 bug：此前把所有结果（含 CLEAN）都 push 进 threats，
        // 前端拿到后全部当作威胁展示，导致一扫描就全是「内存活动威胁」。
        // 现在仅 MALICIOUS 才会进入 threats。
        if scan.result != "MALICIOUS" {
            continue;
        }
        outcome.threats.push(ProcessScanResult {
            pid,
            parent_pid: ppid,
            process_name: name,
            image_path: path,
            result: scan.result,
            probability: scan.probability,
            virus_family: scan.virus_family,
            family_category: Some(MEMORY_THREAT_CATEGORY.to_string()),
            is_memory_threat: true,
        });
    }

    // 威胁按概率降序（最可疑的排最前）
    outcome
        .threats
        .sort_by(|a, b| b.probability.partial_cmp(&a.probability).unwrap_or(std::cmp::Ordering::Equal));

    outcome
}

// ==================== 进程表获取 ====================

/// 通过 AVGuard（提权 R3）枚举全部进程
fn request_processes_via_avguard() -> Result<Vec<RunningProcess>, String> {
    let list = avmodel_client::request_process_list()?;
    Ok(list
        .into_iter()
        .map(|p| RunningProcess {
            pid: p.pid,
            parent_pid: p.parent_pid,
            name: p.name,
            image_path: p.path,
        })
        .collect())
}

/// 用户态 Toolhelp32 快照枚举（AVGuard 不可用时的兜底）
/// 普通权限可遍历进程表，但只能打开同权限或更低权限的进程获取路径
#[cfg(windows)]
fn request_processes_usermode(outcome: &mut MemoryScanOutcome) -> Vec<RunningProcess> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_NAME_WIN32,
    };

    let mut list: Vec<RunningProcess> = Vec::new();

    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(e) => {
                outcome.errors.push(format!("用户态进程快照失败: {}", e));
                return list;
            }
        };

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                let name = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_end_matches('\0')
                    .to_string();

                let mut image_path: Option<String> = None;
                if pid != 0 {
                    if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                        let mut buf = [0u16; 1024];
                        let mut size = buf.len() as u32;
                        if QueryFullProcessImageNameW(
                            handle,
                            PROCESS_NAME_WIN32,
                            windows::core::PWSTR(buf.as_mut_ptr()),
                            &mut size,
                        )
                        .is_ok()
                            && size > 0
                        {
                            image_path = Some(String::from_utf16_lossy(&buf[..size as usize]));
                        }
                        let _ = windows::Win32::Foundation::CloseHandle(handle);
                    }
                }

                list.push(RunningProcess {
                    pid,
                    parent_pid: entry.th32ParentProcessID,
                    name,
                    image_path,
                });

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = windows::Win32::Foundation::CloseHandle(snapshot);
    }

    outcome.source = "usermode".to_string();
    list
}

/// 用户态枚举（非 Windows 平台兜底为空）
#[cfg(not(windows))]
fn request_processes_usermode(_outcome: &mut MemoryScanOutcome) -> Vec<RunningProcess> {
    Vec::new()
}

// ==================== 工具函数 ====================

/// 是否是可扫描的 PE 扩展名
fn is_scanable_extension(path_lower: &str) -> bool {
    const PE_EXTS: &[&str] = &["exe", "dll", "sys", "drv", "ocx", "scr"];
    let ext = std::path::Path::new(path_lower)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    PE_EXTS.contains(&ext)
}

// 使用 rayon 并行扫描
use rayon::prelude::*;
