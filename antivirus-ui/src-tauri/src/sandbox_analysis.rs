//! 自动沙盒分析模块
//!
//! 工作流程:
//! 1. WMI 事件 / R3 监控器检测桌面和下载目录中启动的可执行文件
//! 2. 使用原生 WinVerifyTrust API 验证数字签名（毫秒级，无需启动 PowerShell）
//! 3. 未签名文件 → 终止进程，在 Sandboxie 沙盒中运行
//! 4. 行为分析引擎通过 IOA 规则分析
//! 5. 安全 → 关闭沙盒，重新运行原始文件; 恶意 → 终止

use std::path::{Path, PathBuf};
use std::process::Command;
use std::os::windows::process::CommandExt;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[cfg(windows)]
use windows::Win32::Foundation::HWND;
const CREATE_NO_WINDOW: u32 = 0x08000000;
const SANDBOX_BORDER_COLOR: u32 = 0x00FF00FF; // 紫色 (BGR: FF 00 FF)
const SANDBOX_TRIGGER_NAME: &str = "Sandbox.exe";
const SANDBOX_BOX_NAME: &str = "AUTOSandBox";
const ANALYSIS_TIMEOUT_SECS: u64 = 60;
const MALICIOUS_THRESHOLD: u32 = 100;

static SANDBOX_ANALYSIS_ENABLED: AtomicBool = AtomicBool::new(false);
static SANDBOX_ANALYSIS_RUNNING: AtomicBool = AtomicBool::new(false);
static PENDING_ANALYSIS_FILE: Mutex<Option<String>> = Mutex::new(None);
static ANALYSIS_TARGET_PID: AtomicU32 = AtomicU32::new(0);
static SANDBOX_ANALYZING: AtomicBool = AtomicBool::new(false);

/// 沙盒环境（Sandboxie 安装 + SbieSvc 服务）是否已就绪。
/// ★性能关键★：Setup 启动线程的 auto_configure_sandbox() 与首次分析的 prepare_environment()
/// 共享此标志，避免并发重复执行两套完整的环境配置（scrub + 服务检查 + 14 条 SbieIni 命令），
/// 历史上两套配置并发导致几十个进程启动被驱动串行扫描，沙箱分析延迟约 1 分钟。
static SANDBOX_ENV_READY: AtomicBool = AtomicBool::new(false);

/// 环境配置互斥锁：串行化 auto_configure_sandbox 与 prepare_environment 的环境准备部分。
static SANDBOX_ENV_LOCK: once_cell::sync::Lazy<Mutex<()>> =
    once_cell::sync::Lazy::new(|| Mutex::new(()));

/// scrub_sandboxie_ui 是否已执行过（幂等操作，整个会话只执行一次）
static SANDBOXIE_SCRUBBED: AtomicBool = AtomicBool::new(false);

/// configure_sandbox_box 基础 13 项设置是否已执行（整个会话只执行一次；
/// MsiInstaller 除外，每次分析都同步以保证 MSI 分析后能恢复）
static SANDBOX_CONFIGURED_BASE: AtomicBool = AtomicBool::new(false);

/// 最近由沙箱分析"重新启动"的进程（Benign 判定后放行原始文件）。
/// ★防再触发★：分析完成后重新启动的原始文件若立即被驱动/WMI/R3 再次识别，
/// 会触发第二次分析（白名单写入与进程启动存在竞态），造成"薛定谔"状态：
/// 第二次分析把普通进程误判为沙箱目标，真实沙箱进程反被拦截。
/// TTL 内这些 PID 直接放行，不再进入沙箱拦截流程。
static RECENTLY_LAUNCHED: once_cell::sync::Lazy<Mutex<Vec<(u32, Instant)>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(Vec::new()));
const RECENTLY_LAUNCHED_TTL: Duration = Duration::from_secs(10);

/// ★路径级放行名单★（防再触发升级版）
/// 历史 bug：只标记主进程 PID，但重新启动的程序会 fork 子进程（不同 PID、
/// 不同 hash），子进程不在最近放行名单也不在白名单，导致"分析完成→再分析"死循环。
/// 这里记录最近分析完成的原始文件路径，TTL 内所有同路径进程（含子进程）直接放行。
static RECENTLY_ANALYZED_PATHS: once_cell::sync::Lazy<Mutex<Vec<(String, Instant)>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(Vec::new()));
const RECENTLY_ANALYZED_TTL: Duration = Duration::from_secs(10);

/// 标记进程为"最近放行"（沙箱分析 Benign 后重新启动的原始文件进程）
pub fn mark_recently_launched(pid: u32) {
    if pid == 0 {
        return;
    }
    RECENTLY_LAUNCHED.lock().unwrap().push((pid, Instant::now()));
    println!("[SandboxAnalysis] 标记最近放行进程 PID={}（{}s 内不再拦截）", pid, RECENTLY_LAUNCHED_TTL.as_secs());
}

/// 标记文件路径为"最近分析完成"（Benign 判定后调用）
/// 该路径下的所有进程（含子进程）在 TTL 内不再触发新的沙箱分析
pub fn mark_recently_analyzed_path(path: &str) {
    let canonical = strip_nt_path_prefix(path).to_lowercase();
    RECENTLY_ANALYZED_PATHS.lock().unwrap().push((canonical.clone(), Instant::now()));
    println!("[SandboxAnalysis] 标记最近分析完成路径: {}（{}s 内同路径进程不再拦截）", path, RECENTLY_ANALYZED_TTL.as_secs());
}

// ==================== 全局分析冷却期 ====================

/// ★全局冷却期★：最近一次沙盒分析完成的时间。
/// 用途：分析完成后重新启动原程序会 fork 子进程（不同 PID/hash/路径），
/// 子进程的启动通知可能再次触发分析。在冷却期内（4 秒），
/// **任何进程启动都不会触发新的沙盒分析**，从根源上杜绝"分析→重启→再分析"死循环。
/// 这是 handle_sandbox_analysis 入口级 + should_intercept_for_sandbox 拦截级的双重防线。
const SANDBOX_COOLDOWN: Duration = Duration::from_secs(4);

/// 最近一次完成（set_analyzing(false)）的时间
static LAST_ANALYSIS_END: Mutex<Option<Instant>> = Mutex::new(None);

/// 记录分析结束时间（在 handle_sandbox_analysis 末尾调用）
pub fn mark_analysis_cooldown() {
    *LAST_ANALYSIS_END.lock().unwrap() = Some(Instant::now());
}

/// 全局冷却期内（距上次分析结束 < COOLDOWN）→ 任何文件都跳过分析
pub fn is_in_analysis_cooldown() -> bool {
    let Some(end) = *LAST_ANALYSIS_END.lock().unwrap() else {
        return false; // 从未分析过
    };
    end.elapsed() < SANDBOX_COOLDOWN
}

/// 检查冷却期是否生效：冷却期内 → 跳过（不区分路径）
pub fn should_skip_due_to_cooldown(file_path: &str) -> bool {
    if !is_in_analysis_cooldown() {
        return false; // 冷却期已过或从未分析
    }
    let elapsed = LAST_ANALYSIS_END
        .lock()
        .unwrap()
        .map(|e| e.elapsed().as_secs_f64())
        .unwrap_or(0.0);
    println!("[SandboxAnalysis] ★全局冷却期生效★ 跳过沙盒分析: {}（距上次分析结束 {:.1}s）", file_path, elapsed);
    true
}

/// 检查路径是否在"最近分析完成"名单内（同时清理过期项）
pub fn is_recently_analyzed_path(path: &str) -> bool {
    let canonical = strip_nt_path_prefix(path).to_lowercase();
    let mut list = RECENTLY_ANALYZED_PATHS.lock().unwrap();
    let now = Instant::now();
    list.retain(|(_, t)| now.duration_since(*t) < RECENTLY_ANALYZED_TTL);
    list.iter().any(|(p, _)| *p == canonical)
}

/// 检查进程是否在"最近放行"名单内（同时清理过期项）
pub fn is_recently_launched(pid: u32) -> bool {
    let mut list = RECENTLY_LAUNCHED.lock().unwrap();
    let now = Instant::now();
    list.retain(|(_, t)| now.duration_since(*t) < RECENTLY_LAUNCHED_TTL);
    list.iter().any(|(p, _)| *p == pid)
}

/// 判断路径是否在 Sandboxie 沙箱目录内（如 C:\Sandbox\...\AUTOSandBox\...）
/// 用于区分"沙箱内进程"与"同名普通进程"。
/// 历史 bug：find_pids_by_name 只按文件名匹配，把分析后重新启动的普通进程
/// 误判为沙箱目标；驱动也把沙箱内真实进程误判为"非沙箱进程"拦截。
pub fn is_path_in_sandbox(path: &str) -> bool {
    let p = strip_nt_path_prefix(path).to_lowercase();
    p.contains("\\sandbox\\")
}

/// 当前沙箱内运行的进程 PID 集合（包括目标进程及其子进程）
/// 用于区分"沙箱内启动的进程"和"用户主动启动的进程"
/// 分析中时，只有沙箱内的进程才会被自动放行
static SANDBOX_PIDS: once_cell::sync::Lazy<Mutex<std::collections::HashSet<u32>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(std::collections::HashSet::new()));

pub fn is_analysis_enabled() -> bool {
    SANDBOX_ANALYSIS_ENABLED.load(Ordering::SeqCst)
}

pub fn set_analysis_enabled(enabled: bool) {
    SANDBOX_ANALYSIS_ENABLED.store(enabled, Ordering::SeqCst);
}

pub fn is_analysis_running() -> bool {
    SANDBOX_ANALYSIS_RUNNING.load(Ordering::SeqCst)
}

pub fn is_analyzing() -> bool {
    SANDBOX_ANALYZING.load(Ordering::SeqCst)
}

pub fn set_analyzing(analyzing: bool) {
    SANDBOX_ANALYZING.store(analyzing, Ordering::SeqCst);
}

pub fn set_pending_file(path: &str) {
    *PENDING_ANALYSIS_FILE.lock().unwrap() = Some(path.to_string());
}

pub fn get_pending_file() -> Option<String> {
    PENDING_ANALYSIS_FILE.lock().unwrap().clone()
}

pub fn clear_pending_file() {
    *PENDING_ANALYSIS_FILE.lock().unwrap() = None;
}

// ==================== 沙箱 PID 集合管理 ====================

/// 添加一个 PID 到沙箱集合
pub fn add_sandbox_pid(pid: u32) {
    if pid > 0 {
        SANDBOX_PIDS.lock().unwrap().insert(pid);
    }
}

/// 检查 PID 是否在沙箱集合中
pub fn is_sandbox_pid(pid: u32) -> bool {
    SANDBOX_PIDS.lock().unwrap().contains(&pid)
}

/// 清空沙箱 PID 集合（分析完成后调用）
pub fn clear_sandbox_pids() {
    SANDBOX_PIDS.lock().unwrap().clear();
}

/// 已修改过标题的 HWND 集合，避免边框重试时重复追加" 在西瓜杀毒沙箱中"
static TITLED_HWNDS: once_cell::sync::Lazy<Mutex<std::collections::HashSet<isize>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(std::collections::HashSet::new()));

/// 清空已标记标题的 HWND 集合（分析完成后调用，为下次分析做准备）
pub fn clear_titled_hwnds() {
    TITLED_HWNDS.lock().unwrap().clear();
}

/// 判断是否为沙箱触发器进程（prepare_trigger 复制的 TEMP\XIGUASandbox\Sandbox.exe）
/// ★必须校验完整路径★
/// 历史 bug：只按文件名匹配（eq_ignore_ascii_case "Sandbox.exe"），导致用户自己的
/// 任意名为 sandbox.exe 的文件被误判为触发器：分析完成后重新启动的原程序
/// （sandbox.exe）立即被驱动拦截触发第二次分析，形成"分析→重启→再分析"死循环。
pub fn is_sandbox_trigger_process(image_path: &str) -> bool {
    let p = strip_nt_path_prefix(image_path).to_lowercase();
    let expected = get_temp_dir().join(SANDBOX_TRIGGER_NAME);
    p == expected.to_string_lossy().to_lowercase()
}

// ==================== 环境配置 ====================

fn sbie_start_exists() -> bool {
    let candidates = [
        r"C:\Program Files\Sandboxie-Plus\Start.exe",
        r"C:\Program Files\Sandboxie\Start.exe",
        r"C:\Program Files (x86)\Sandboxie-Plus\Start.exe",
    ];
    candidates.iter().any(|p| Path::new(p).exists())
}

fn find_sandboxie_dir() -> Option<PathBuf> {
    let exe_dir = std::env::current_exe().ok()?;
    let mut current = exe_dir.parent()?;
    for _ in 0..6 {
        let candidate = current.join("SandBoxie");
        if candidate.join("Start.exe").exists() {
            return Some(candidate);
        }
        current = current.parent()?;
    }
    None
}

fn find_bundled_sbie_setup() -> Option<PathBuf> {
    // 优先从程序同级目录查找安装包（打包后 Sandboxie-Plus-*.exe 与主程序在同一目录）
    let exe_dir = std::env::current_exe().ok()?;
    let exe_parent = exe_dir.parent()?;
    if let Ok(entries) = std::fs::read_dir(exe_parent) {
        let mut setups: Vec<_> = entries
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.to_lowercase().contains("sandboxie") && n.ends_with(".exe"))
                    .unwrap_or(false)
            })
            .collect();
        setups.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
        if let Some(first) = setups.first() {
            return Some(first.path());
        }
    }

    // 回退：向上查找 SandBoxie 目录
    if let Some(sbie_dir) = find_sandboxie_dir() {
        if let Ok(entries) = std::fs::read_dir(&sbie_dir) {
            let mut setups: Vec<_> = entries
                .flatten()
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .map(|n| n.to_lowercase().contains("sandboxie") && n.ends_with(".exe"))
                        .unwrap_or(false)
                })
                .collect();
            setups.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
            if let Some(first) = setups.first() {
                return Some(first.path());
            }
        }
    }
    None
}

/// 按名称终止进程（taskkill），带硬超时：最多等 2 秒，超时强制终止 taskkill。
/// 历史 bug：同步 .status() 等待 taskkill 可能在系统繁忙时挂起数分钟，
/// 直接拖垮沙箱环境准备（scrub 曾阻塞 133 秒）。
fn kill_process_by_name(name: &str) {
    let mut child = match Command::new("taskkill")
        .args(["/IM", name, "/F"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }
}

fn strip_nt_path_prefix(path: &str) -> String {
    if let Some(stripped) = path.strip_prefix("\\??\\") {
        stripped.to_string()
    } else if let Some(stripped) = path.strip_prefix("\\Device\\") {
        stripped.to_string()
    } else {
        path.to_string()
    }
}

fn scrub_sandboxie_ui() {
    // ★幂等 + 后台异步执行★
    // 历史 bug（严重性能问题）：scrub 同步执行，内部 PowerShell 递归扫描桌面/开始菜单
    // 可挂起 130+ 秒，且 Setup 线程与分析线程并发各自执行一遍完整环境配置，
    // 导致沙箱分析延迟 1 分钟+ 才真正启动目标程序。
    // 现在：整个 scrub 放到后台线程 fire-and-forget，环境准备不再等待；
    // 内部所有子进程调用带硬超时，PowerShell 脚本去掉 -Recurse 递归扫描。
    //
    // ★重要：安装完成后必须同步等待 scrub 完成（scrub_sandboxie_ui_sync 分支），
    // 否则 Sandboxie 托盘 UI（Sandboxie.exe/SbieCtrl.exe/SandMan.exe）未被清理，
    // 会持有沙箱 IPC 锁/窗口 hook，导致 Start.exe 启动的目标程序弹不出窗口，
    // 沙盒分析显示"正在监控程序行为"但程序根本没启动。
    if SANDBOXIE_SCRUBBED.swap(true, Ordering::SeqCst) {
        println!("[SandboxAnalysis] scrub_sandboxie_ui 已执行过，跳过");
        return;
    }

    std::thread::spawn(|| {
        let scrub_start = Instant::now();
        println!("[SandboxAnalysis] scrub_sandboxie_ui 后台执行开始");
        scrub_sandboxie_ui_impl();
        println!("[SandboxAnalysis] scrub_sandboxie_ui 后台执行完成（耗时 {:.1}s）", scrub_start.elapsed().as_secs_f64());
    });
}

/// 安装完成后同步执行的 scrub（等待完整清理，防止托盘 UI 干扰沙箱启动）
/// 只处理最关键部分：杀进程 + 重命名 exe（不做慢速的快捷方式清理）
fn scrub_sandboxie_ui_sync() {
    println!("[SandboxAnalysis] scrub_sandboxie_ui_sync 开始（安装后同步清理）");

    // 1. 终止所有 Sandboxie 管理 UI / 托盘进程
    for name in &["Sandboxie.exe", "SandMan.exe", "SbieCtrl.exe"] {
        kill_process_by_name(name);
    }

    // 2. 重命名 UI 可执行文件，防止重新弹出
    let bases = [
        Path::new(r"C:\Program Files\Sandboxie-Plus"),
        Path::new(r"C:\Program Files (x86)\Sandboxie-Plus"),
        Path::new(r"C:\Program Files\Sandboxie"),
        Path::new(r"C:\Program Files (x86)\Sandboxie"),
    ];
    for base in &bases {
        for name in &["Sandboxie.exe", "SandMan.exe", "SbieCtrl.exe"] {
            let exe = base.join(name);
            let bak = base.join(format!("{}.bak", name));
            if exe.exists() && !bak.exists() {
                let _ = std::fs::rename(&exe, &bak);
            }
        }
    }

    // 3. 短暂等待进程真正退出（最多 2 秒）
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        let any_alive = ["Sandboxie.exe", "SandMan.exe", "SbieCtrl.exe"]
            .iter()
            .any(|n| process_exists(n));
        if !any_alive {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    println!("[SandboxAnalysis] scrub_sandboxie_ui_sync 完成");
}

/// 检查指定名称的进程是否存活
fn process_exists(name: &str) -> bool {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = false;
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let exe_name = String::from_utf16_lossy(&entry.szExeFile);
                if exe_name.trim_end_matches('\0').eq_ignore_ascii_case(name) {
                    found = true;
                    break;
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = windows::Win32::Foundation::CloseHandle(snapshot);
        found
    }
}

/// scrub 的实际执行体（后台线程和同步路径共用）
fn scrub_sandboxie_ui_impl() {
    // 1. 终止 Sandboxie 管理 UI（带超时，每个最多 2 秒）
    for name in &["Sandboxie.exe", "SandMan.exe", "SbieCtrl.exe"] {
        kill_process_by_name(name);
    }

    // 2. 重命名 UI 可执行文件，防止重新弹出
    let bases = [
        Path::new(r"C:\Program Files\Sandboxie-Plus"),
        Path::new(r"C:\Program Files (x86)\Sandboxie-Plus"),
        Path::new(r"C:\Program Files\Sandboxie"),
        Path::new(r"C:\Program Files (x86)\Sandboxie"),
    ];
    for base in &bases {
        for name in &["Sandboxie.exe", "SandMan.exe", "SbieCtrl.exe"] {
            let exe = base.join(name);
            let bak = base.join(format!("{}.bak", name));
            if exe.exists() && !bak.exists() {
                let _ = std::fs::rename(&exe, &bak);
            }
        }
    }

        // 3. 清理桌面/开始菜单快捷方式与注册表自启动
        //    ★不再 -Recurse 递归扫描：快捷方式就在目录第一层，
        //    递归扫描大目录（尤其 OneDrive 占位符/网络位置）可挂起数分钟★
        //    最多等待 5 秒，超时强制终止 PowerShell
        let ps_script = r#"
$ErrorActionPreference='SilentlyContinue'
foreach ($d in @(
  [Environment]::GetFolderPath('Desktop'),
  [Environment]::GetFolderPath('CommonDesktopDirectory'),
  "$env:PUBLIC\Desktop",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
)) {
  if (-not $d) { continue }
  if (-not (Test-Path -LiteralPath $d)) { continue }
  Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'Sandboxie|SandMan|SbieCtrl' } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}
foreach ($hive in @(
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)) {
  if (-not (Test-Path $hive)) { continue }
  $props = Get-ItemProperty -Path $hive -ErrorAction SilentlyContinue
  if (-not $props) { continue }
  foreach ($n in @($props.PSObject.Properties.Name)) {
    if ($n -match 'Sandboxie|SandMan|SbieCtrl') {
      Remove-ItemProperty -Path $hive -Name $n -Force -ErrorAction SilentlyContinue
    }
  }
}
"#;
        let scrub_child = Command::new("powershell")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();

        if let Ok(mut child) = scrub_child {
            // 最多等待 5 秒，超时则强制终止，避免 PowerShell 脚本卡死
            let timeout = Duration::from_secs(5);
            let start = std::time::Instant::now();
            while start.elapsed() < timeout {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                    Err(_) => break,
                }
            }
            match child.try_wait() {
                Ok(None) => { let _ = child.kill(); }
                _ => {}
            }
        }

        println!("[SandboxAnalysis] scrub_sandboxie_ui_impl 完成");
}

pub fn ensure_sandboxie() -> Result<bool, String> {
    let env_start = Instant::now();
    println!("[SandboxAnalysis] ensure_sandboxie() 开始");
    crate::diag_info!("[SandboxAnalysis] ensure_sandboxie() 开始");

    if sbie_start_exists() {
        println!("[SandboxAnalysis] Start.exe 已存在，执行 scrub_sandboxie_ui_sync（同步清理托盘 UI）");
        crate::diag_info!("[SandboxAnalysis] Start.exe 已存在，执行 scrub_sandboxie_ui_sync");
        // ★同步清理托盘 UI：托盘图标（Sandboxie.exe/SbieCtrl.exe/SandMan.exe）持有
        // 沙箱 IPC 锁，会导致 Start.exe 启动的目标程序弹不出窗口。已有安装时
        // 同样需要同步清理，不能只靠后台异步 scrub（可能未执行完就开始分析）。
        scrub_sandboxie_ui_sync();
        println!("[SandboxAnalysis] 环境已就绪（已有安装）（耗时 {:.1}s）", env_start.elapsed().as_secs_f64());
        crate::diag_info!("[SandboxAnalysis] 环境已就绪（已有安装）");
        return Ok(true);
    }

    println!("[SandboxAnalysis] Start.exe 不存在，开始查找安装包");
    crate::diag_info!("[SandboxAnalysis] Start.exe 不存在，开始查找安装包");
    let setup = find_bundled_sbie_setup()
        .ok_or_else(|| {
            let msg = "未找到 Sandboxie 安装包".to_string();
            println!("[SandboxAnalysis] {}", msg);
            crate::diag_warn!("[SandboxAnalysis] {}", msg);
            msg
        })?;

    println!("[SandboxAnalysis] 找到安装包: {:?}", setup);
    crate::diag_info!("[SandboxAnalysis] 找到安装包: {:?}", setup);

    // 检查是否已提权：已提权时直接启动安装包（CreateProcessW），
    // 避免 PowerShell -Verb RunAs 在提权进程中的 COM/UIPI 死锁
    let already_elevated = crate::is_elevated();

    let install_status = if already_elevated {
        // 已提权：直接用 std::process::Command 启动安装包（继承父进程权限）
        println!("[SandboxAnalysis] 已提权，直接启动安装包（不走 ShellExecuteW）");
        crate::diag_info!("[SandboxAnalysis] 已提权，直接启动安装包（不走 ShellExecuteW）");
        Command::new(&setup)
            .args(["/VERYSILENT", "/NORESTART", "/SUPPRESSMSGBOXES", "/NOICONS", "/TASKS="])
            .creation_flags(CREATE_NO_WINDOW)
            .status()
            .map_err(|e| {
                let msg = format!("安装启动失败: {}", e);
                println!("[SandboxAnalysis] {}", msg);
                msg
            })?
    } else {
        // 未提权：通过 PowerShell -Verb RunAs 触发 UAC
        let setup_str = setup.to_string_lossy().replace('\'', "''");
        let ps = format!(
            "$p = Start-Process -FilePath '{}' -ArgumentList '/VERYSILENT','/NORESTART','/SUPPRESSMSGBOXES','/NOICONS','/TASKS=' -PassThru -Verb RunAs; if ($p) {{ $p | Wait-Process -Timeout 60; exit $p.ExitCode }} else {{ exit 1 }}",
            setup_str
        );
        println!("[SandboxAnalysis] 未提权，通过 PowerShell -Verb RunAs 安装...");
        let output = Command::new("powershell")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| {
                let msg = format!("安装启动失败: {}", e);
                println!("[SandboxAnalysis] {}", msg);
                msg
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("[SandboxAnalysis] 安装 exit={}", output.status.code().unwrap_or(-1));
        if !stdout.is_empty() {
            println!("[SandboxAnalysis] stdout: {}", stdout);
        }
        if !stderr.is_empty() {
            println!("[SandboxAnalysis] stderr: {}", stderr);
        }
        output.status
    };

    if !install_status.success() {
        return Err(format!("安装失败 exit={}", install_status.code().unwrap_or(-1)));
    }

    std::thread::sleep(Duration::from_secs(2));
    println!("[SandboxAnalysis] 安装完成，执行 scrub_sandboxie_ui_sync（同步清理托盘 UI）");
    // ★同步执行：安装后必须彻底清理 Sandboxie 托盘 UI，
    // 否则托盘图标（Sandboxie.exe/SbieCtrl.exe/SandMan.exe）持有沙箱 IPC 锁，
    // 导致 Start.exe 启动的目标程序弹不出窗口、沙盒分析"正在监控但程序没启动"。
    scrub_sandboxie_ui_sync();

    if sbie_start_exists() {
        println!("[SandboxAnalysis] 环境已就绪（耗时 {:.1}s）", env_start.elapsed().as_secs_f64());
        Ok(true)
    } else {
        println!("[SandboxAnalysis] 安装后仍找不到 Start.exe");
        Err("安装后仍找不到 Start.exe".to_string())
    }
}

pub fn get_sbie_start_exe() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from(r"C:\Program Files\Sandboxie-Plus\Start.exe"),
        PathBuf::from(r"C:\Program Files\Sandboxie\Start.exe"),
        PathBuf::from(r"C:\Program Files (x86)\Sandboxie-Plus\Start.exe"),
    ];
    for c in &candidates {
        if c.exists() {
            return Some(c.clone());
        }
    }
    find_sandboxie_dir().map(|d| d.join("Start.exe"))
}

pub fn get_sbie_ini_exe() -> Option<PathBuf> {
    get_sbie_start_exe()
        .and_then(|p| p.parent().map(|d| d.join("SbieIni.exe")))
        .filter(|p| p.exists())
}

fn get_kmdutil_exe() -> Option<PathBuf> {
    get_sbie_start_exe()
        .and_then(|p| p.parent().map(|d| d.join("KmdUtil.exe")))
        .filter(|p| p.exists())
}

pub fn ensure_sbie_service() -> Result<(), String> {
    let kmdutil = get_kmdutil_exe().ok_or("KmdUtil.exe not found")?;
    let sbie_dir = kmdutil.parent().unwrap();
    let kmdutil_str = kmdutil.to_string_lossy().replace('\'', "''");

    // 检查服务是否已经在运行
    let check = Command::new("sc")
        .args(["query", "SbieSvc"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    if let Ok(out) = check {
        let output_str = String::from_utf8_lossy(&out.stdout);
        if output_str.contains("RUNNING") {
            println!("[SandboxAnalysis] SbieSvc 正在运行");
            crate::diag_info!("[SandboxAnalysis] SbieSvc 正在运行");
            return Ok(());
        }
    }

    println!("[SandboxAnalysis] SbieSvc 未运行，安装并启动服务");
    crate::diag_info!("[SandboxAnalysis] SbieSvc 未运行，安装并启动服务");

    let sbie_svc = sbie_dir.join("SbieSvc.exe");
    let sbie_drv = sbie_dir.join("SbieDrv.sys");
    let svc_str = sbie_svc.to_string_lossy().replace('\'', "''");
    let drv_str = sbie_drv.to_string_lossy().replace('\'', "''");

    // 检查是否已提权：已提权时直接运行 KmdUtil（CreateProcessW），
    // 避免 PowerShell -Verb RunAs 在提权进程中的 COM/UIPI 死锁
    if crate::is_elevated() {
        // 已提权：直接运行 KmdUtil 命令（继承父进程权限）
        println!("[SandboxAnalysis] 已提权，直接运行 KmdUtil");
        crate::diag_info!("[SandboxAnalysis] 已提权，直接运行 KmdUtil");

        let kmd = kmdutil.to_string_lossy().into_owned();

        // install SbieSvc
        let _ = Command::new(&kmd)
            .args(["install", "SbieSvc", &sbie_svc.to_string_lossy()])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        // install SbieDrv
        let _ = Command::new(&kmd)
            .args(["install", "SbieDrv", &sbie_drv.to_string_lossy()])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        // start SbieSvc
        let _ = Command::new(&kmd)
            .args(["start", "SbieSvc"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        crate::diag_info!("[SandboxAnalysis] KmdUtil 直接执行完成");
    } else {
        // 未提权：通过 PowerShell -Verb RunAs 触发 UAC
        println!("[SandboxAnalysis] 未提权，通过 PowerShell -Verb RunAs 执行");
        let ps = format!(
            "Start-Process -FilePath '{}' -ArgumentList 'install','SbieSvc','{}' -Verb RunAs -PassThru | Wait-Process -Timeout 30; \
             Start-Process -FilePath '{}' -ArgumentList 'install','SbieDrv','{}' -Verb RunAs -PassThru | Wait-Process -Timeout 30; \
             Start-Process -FilePath '{}' -ArgumentList 'start','SbieSvc' -Verb RunAs -PassThru | Wait-Process -Timeout 10",
            kmdutil_str, svc_str,
            kmdutil_str, drv_str,
            kmdutil_str
        );

        let output = Command::new("powershell")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("Failed to run KmdUtil via PowerShell: {}", e))?;

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("[SandboxAnalysis] KmdUtil install stdout: {}", stdout);
        if !stderr.is_empty() {
            println!("[SandboxAnalysis] KmdUtil install stderr: {}", stderr);
        }
    }

    std::thread::sleep(Duration::from_secs(1));

    // 再次验证
    let check2 = Command::new("sc")
        .args(["query", "SbieSvc"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    if let Ok(out) = check2 {
        let output_str = String::from_utf8_lossy(&out.stdout);
        if output_str.contains("RUNNING") {
            println!("[SandboxAnalysis] SbieSvc 已启动");
            return Ok(());
        }
    }

    Err("SbieSvc 服务安装/启动失败".to_string())
}

/// 配置沙盒参数
/// `is_msi`: 是否正在分析 MSI 安装程序。为 true 时临时启用 MsiInstaller 设置，
///           为 false 时主动移除该设置以恢复默认安全级别。
/// MsiInstaller=y 会降低沙箱安全性（允许 Windows Installer 服务在沙箱内运行），
/// 因此仅在分析 MSI 文件时临时启用，分析其他文件时必须移除。
pub fn configure_sandbox_box(is_msi: bool) -> Result<(), String> {
    let cfg_start = Instant::now();
    let sbie_ini = get_sbie_ini_exe().ok_or("SbieIni.exe not found")?;
    let sbie_ini_str = sbie_ini.to_string_lossy();

    let box_name = SANDBOX_BOX_NAME;

    let mut cmd_lines = String::new();

    // ★基础 13 项设置整个会话只执行一次★
    // 历史 bug：每次分析都跑 14 条 SbieIni 命令 + 独立验证进程，且与 Setup 线程的
    // auto_configure_sandbox() 并发执行（2×14 条命令、几十个进程启动被驱动串行扫描），
    // 导致沙箱分析延迟约 1 分钟才真正启动目标程序。
    let first_run = !SANDBOX_CONFIGURED_BASE.swap(true, Ordering::SeqCst);
    if first_run {
        let settings: Vec<(&str, &str)> = vec![
            ("Enabled", "y"),
            ("AutoDelete", "n"),
            ("BlockNetworkFiles", "y"),
            ("ConfigLevel", "10"),
            ("BorderColor", "#00FFFF,ttl"),
            ("FileTrace", "wcd"),
            ("KeyTrace", "wcd"),
            ("PipeTrace", "w"),
            ("IpcTrace", "w"),
            ("NetFwTrace", "*"),
            ("DnsTrace", "*"),
            ("TraceBufferPages", "2560"),
            ("FakeAdminRights", "y"),
        ];

        for (key, value) in &settings {
            cmd_lines.push_str(&format!("& '{}' set {} {} {}\n", sbie_ini_str, box_name, key, value));
        }

        // 验证 Enabled（并入同一 PowerShell，输出最后一行即为 query 结果）
        cmd_lines.push_str(&format!("& '{}' query {} Enabled\n", sbie_ini_str, box_name));
    }

    // MsiInstaller：每次分析都同步（MSI→y，非 MSI→unset），
    // 保证 MSI 分析后能恢复默认安全级别。
    if is_msi {
        cmd_lines.push_str(&format!("& '{}' set {} MsiInstaller y\n", sbie_ini_str, box_name));
    } else {
        cmd_lines.push_str(&format!("& '{}' unset {} MsiInstaller\n", sbie_ini_str, box_name));
    }

    // 单次 PowerShell 调用执行所有命令（只有基础配置首次 + MsiInstaller 两条，快）
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &cmd_lines])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    if first_run {
        let enabled = match &output {
            Ok(out) => String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .last()
                .map(|s| s.to_string()),
            Err(_) => None,
        };
        match enabled {
            Some(v) => println!("[SandboxAnalysis] Box '{}' Enabled: '{}'", SANDBOX_BOX_NAME, v),
            None => println!("[SandboxAnalysis] Box '{}' Enabled: (无法获取，PowerShell 失败)", SANDBOX_BOX_NAME),
        }
    }

    println!("[SandboxAnalysis] configure_sandbox_box(is_msi={}) 完成（耗时 {:.1}s）",
        is_msi, cfg_start.elapsed().as_secs_f64());
    Ok(())
}

/// 自动检测并配置沙盒环境（启动时调用）
/// 完整流程：安装 Sandboxie → 启动 SbieSvc 服务 → 配置 AUTOSandBox
pub fn auto_configure_sandbox() -> Result<bool, String> {
    let total_start = Instant::now();
    println!("[SandboxAnalysis] auto_configure_sandbox() 开始");
    crate::diag_info!("[SandboxAnalysis] auto_configure_sandbox() 开始");

    // ★环境互斥锁 + READY 标志：与首次分析的 prepare_environment() 共享，
    // 整个会话只完整配置一次，避免并发重复执行两套完整流程★
    let _guard = SANDBOX_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if SANDBOX_ENV_READY.load(Ordering::SeqCst) {
        println!("[SandboxAnalysis] 沙盒环境已就绪（此前已配置），跳过重复配置");
        return Ok(true);
    }

    // 1. 确保 Sandboxie 已安装
    ensure_sandboxie()?;
    crate::diag_info!("[SandboxAnalysis] Sandboxie 已安装");

    // 2. 确保 SbieSvc 服务正在运行
    ensure_sbie_service()?;
    crate::diag_info!("[SandboxAnalysis] SbieSvc 服务已运行");

    // 3. 配置 AUTOSandBox 沙盒参数（默认不启用 MSI 支持，保持最高安全性）
    configure_sandbox_box(false)?;
    crate::diag_info!("[SandboxAnalysis] AUTOSandBox 配置完成");

    SANDBOX_ENV_READY.store(true, Ordering::SeqCst);
    println!("[SandboxAnalysis] auto_configure_sandbox() 完成，沙盒环境已就绪（总耗时 {:.1}s）",
        total_start.elapsed().as_secs_f64());
    crate::diag_info!("[SandboxAnalysis] auto_configure_sandbox() 完成，沙盒环境已就绪");
    Ok(true)
}

// ==================== 行为分析引擎 ====================

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BehaviorCategory {
    FileSystem,
    Registry,
    Process,
    Network,
    System,
    Security,
    Persistence,
    CredentialAccess,
    LateralMovement,
    DefenseEvasion,
    Collection,
}

#[derive(Debug, Clone)]
pub struct IoaRule {
    pub id: String,
    pub name: String,
    pub category: BehaviorCategory,
    pub weight: u32,
    pub description: String,
}

#[derive(Debug, Clone)]
pub enum BehaviorEvent {
    // === 文件系统 ===
    FileCreate { path: String, is_system_dir: bool, is_executable: bool, is_suspicious_dir: bool, is_random_name: bool },
    FileModify { path: String, is_system_file: bool },
    FileDelete { path: String, count: u32 },
    FileBatchDelete { count: u32 },
    FileExtensionChange { count: u32 },
    /// 文件分割重组（银狐特征：将PE拆分为16进制文本再拼接）
    FileSplitAndReconstruct { temp_path: String },
    /// 释放隐藏文件（无扩展名，银狐特征）
    HiddenFileDrop { path: String },
    /// 文件内容覆写（wiper特征：用随机数据覆写文件内容）
    FileContentOverwrite { path: String },
    /// MBR/磁盘分区表修改（破坏性恶意软件特征）
    MbrModify,
    /// 磁盘擦除（wiper特征）
    DiskWipe,
    /// 批量文件加密（勒索软件特征）
    FileMassEncrypt { count: u32 },
    /// 在用户文档目录批量创建/修改文件（勒索加密前兆）
    DocumentDirMassModification { count: u32 },

    // === 注册表 ===
    RegModify { key: String, is_run_key: bool, is_security_key: bool, is_proxy_key: bool },
    RegCreate { key: String },
    /// 修改系统代理设置（银狐C2流量转发特征）
    ProxySettingModified { server: String },
    /// AppInit_DLLs 修改（持久化注入）
    AppInitDllsModify,
    /// Winlogon Shell/Userinit 修改（持久化注入）
    WinlogonModify,
    /// COM对象劫持
    ComHijack { clsid: String },
    /// Image File Execution Options 劫持
    IfeoHijack { target: String },
    /// 注册表备份删除（防御规避）
    RegistryBackupDelete,

    // === 进程 ===
    ProcessCreate { name: String, is_suspicious: bool, is_elevated: bool },
    ProcessInject { source_pid: u32, target_pid: u32 },
    ProcessHollowing,
    DllInjection { target: String },
    ThreadHijack,
    CodeInjection,
    /// 创建互斥体（银狐特征：Run2019/iryhtyruqm等）
    MutexCreate { name: String },
    /// 注入explorer.exe（银狐2025-2026新变种特征）
    ExplorerProcessInjection,
    /// DLL搜索顺序劫持（银狐DoH变种：白加黑）
    DllSearchOrderHijack { dll_name: String },
    /// sRDI反射加载（银狐新变种：DLL转shellcode内存加载）
    SRDILoading,
    /// rundll32加载可疑DLL（银狐特征：rundll32加载intel.dll）
    Rundll32Execution { dll: String, entrypoint: String },
    /// 内核驱动加载（rootkit特征）
    DriverLoad { name: String },
    /// 过量子进程创建（银狐/木马特征：创建超过2个子进程）
    ExcessiveChildProcess { count: u32, parent: String },

    // === 网络 ===
    NetworkConnect { ip: String, port: u16, is_suspicious: bool },
    NetworkDNS { domain: String, is_suspicious: bool },
    /// 加密C2通信（银狐特征：Base64+XOR加密的C2配置）
    EncryptedC2Communication { port: u16 },
    /// DNS over HTTPS隐蔽通信（银狐DoH变种特征）
    DnsOverHttps { server: String },
    /// 网络共享枚举（蠕虫横向传播特征）
    NetworkShareEnum,
    /// 横向移动尝试
    LateralMovement { target: String },
    /// 可疑端口连接（已知C2端口）
    KnownC2PortConnect { port: u16 },
    /// 大量数据外发（数据窃取特征）
    DataExfiltration { bytes: u64 },

    // === 系统 ===
    ServiceCreate { name: String },
    ServiceModify { name: String },
    ScheduledTaskCreate { name: String },
    ScreenLockAttempt,
    MouseKeyboardBlock,
    WallpaperChange { path: String },
    ShadowCopyDelete,
    BackupCatalogDelete,
    BootConfigModify,
    SafeModeDisable,
    UacDisable,
    FirewallRuleAdd,
    DefenderDisable,
    SystemRestoreDisable,
    /// 添加Defender排除项（银狐新变种特征：PowerShell添加C-F盘排除）
    DefenderExclusionAdd { path: String },
    /// 事件日志清除（防御规避）
    EventLogClear,
    /// 系统关机/重启（破坏性特征）
    SystemShutdown,

    // === 安全对抗 ===
    AntiDebug { technique: String },
    AntiVM { technique: String },
    SandboxDetect { technique: String },
    /// 安全软件环境检测（银狐特征：检测火绒/360/腾讯管家等）
    SecurityProductDetection { names: Vec<String> },
    /// 数字签名伪造（银狐特征：伪造网易等公司数字签名）
    ForgedDigitalSignature { signer: String },
    /// 阻断安全软件网络功能（银狐新变种：修改TCP表阻断云查杀）
    SecurityProductNetworkBlock,
    /// 加壳检测（银狐使用UPX/VMProtect等）
    PackingDetected { packer: String },

    // === 持久化 ===
    /// 伪装系统服务名（银狐特征：如 NetHelperSvc）
    FakeSystemService { name: String },
    /// WMI持久化
    WmiPersistence { query: String },
    /// PowerShell持久化（银狐新变种：Base64编码的PowerShell脚本）
    PowerShellPersistence { script: String },

    // === 凭据窃取 ===
    /// 键盘记录
    Keylogging,
    /// 屏幕截图
    ScreenCapture,
    /// 剪贴板监控/劫持
    ClipboardHijack,
    /// 浏览器数据窃取
    BrowserDataTheft { browser: String },
    /// LSASS内存访问（凭据窃取）
    LsassAccess,
    /// SAM数据库访问
    SamDatabaseAccess,
    /// 凭据窃取
    CredentialTheft { source: String },
    /// Token操纵（权限提升）
    TokenManipulation,
    /// 权限提升尝试
    PrivilegeEscalation,

    // === 数据收集 ===
    /// 系统信息收集
    SystemInfoCollection,
    /// 进程枚举（银狐新变种：枚举进程查找安全软件）
    ProcessEnumeration,
    /// 文件搜索（勒索软件特征：搜索要加密的文件）
    FileSearchForEncryption,
}

impl BehaviorEvent {
    fn category(&self) -> BehaviorCategory {
        match self {
            Self::FileCreate { .. } | Self::FileModify { .. } | Self::FileDelete { .. }
            | Self::FileBatchDelete { .. } | Self::FileExtensionChange { .. }
            | Self::FileSplitAndReconstruct { .. } | Self::HiddenFileDrop { .. }
            | Self::FileContentOverwrite { .. } | Self::MbrModify | Self::DiskWipe
            | Self::FileMassEncrypt { .. } | Self::DocumentDirMassModification { .. } => BehaviorCategory::FileSystem,
            Self::RegModify { .. } | Self::RegCreate { .. }
            | Self::ProxySettingModified { .. } | Self::AppInitDllsModify
            | Self::WinlogonModify | Self::ComHijack { .. } | Self::IfeoHijack { .. }
            | Self::RegistryBackupDelete => BehaviorCategory::Registry,
            Self::ProcessCreate { .. } | Self::ProcessInject { .. }
            | Self::ProcessHollowing | Self::DllInjection { .. }
            | Self::ThreadHijack | Self::CodeInjection
            | Self::MutexCreate { .. } | Self::ExplorerProcessInjection
            | Self::DllSearchOrderHijack { .. } | Self::SRDILoading
            | Self::Rundll32Execution { .. } | Self::DriverLoad { .. }
            | Self::ExcessiveChildProcess { .. } => BehaviorCategory::Process,
            Self::NetworkConnect { .. } | Self::NetworkDNS { .. }
            | Self::EncryptedC2Communication { .. } | Self::DnsOverHttps { .. }
            | Self::NetworkShareEnum | Self::LateralMovement { .. }
            | Self::KnownC2PortConnect { .. } | Self::DataExfiltration { .. } => BehaviorCategory::Network,
            Self::ServiceCreate { .. } | Self::ServiceModify { .. }
            | Self::ScheduledTaskCreate { .. } | Self::BootConfigModify
            | Self::FirewallRuleAdd | Self::UacDisable | Self::DefenderDisable
            | Self::SystemRestoreDisable | Self::SafeModeDisable
            | Self::ScreenLockAttempt | Self::MouseKeyboardBlock
            | Self::WallpaperChange { .. } | Self::ShadowCopyDelete
            | Self::BackupCatalogDelete | Self::DefenderExclusionAdd { .. }
            | Self::EventLogClear | Self::SystemShutdown => BehaviorCategory::System,
            Self::AntiDebug { .. } | Self::AntiVM { .. }
            | Self::SandboxDetect { .. }
            | Self::SecurityProductDetection { .. }
            | Self::ForgedDigitalSignature { .. }
            | Self::SecurityProductNetworkBlock | Self::PackingDetected { .. } => BehaviorCategory::Security,
            Self::FakeSystemService { .. } | Self::WmiPersistence { .. }
            | Self::PowerShellPersistence { .. } => BehaviorCategory::Persistence,
            Self::Keylogging | Self::ScreenCapture | Self::ClipboardHijack
            | Self::BrowserDataTheft { .. } | Self::LsassAccess
            | Self::SamDatabaseAccess | Self::CredentialTheft { .. }
            | Self::TokenManipulation | Self::PrivilegeEscalation => BehaviorCategory::CredentialAccess,
            Self::SystemInfoCollection | Self::ProcessEnumeration
            | Self::FileSearchForEncryption => BehaviorCategory::Collection,
        }
    }
}

/// 银狐木马已知C2域名（2025-2026变种）
const SILVERFOX_C2_DOMAINS: &[&str] = &[
    "nimlgb.icu", "aeiessle.top", "klaszaq.top", "dashz.a5.com",
    "dashz.a6.com", "huairenshangde.xyz", "fsbbb250804.com",
    "llbbb250804.com", "smignsangdsgjbn.shop",
];

/// 银狐木马已知C2 IP地址（2025-2026变种，含71+节点）
const SILVERFOX_C2_IPS: &[&str] = &[
    "45.204.200.26",
    "8.210.85.204", "8.210.196.121", "8.218.85.204", "8.218.196.121",
    "23.224.194.33", "27.50.63.10", "27.124.2.161", "27.124.2.198",
    "27.124.3.74", "27.124.43.45", "27.124.45.134", "38.45.127.82",
    "38.46.12.250", "38.46.15.2", "38.46.15.234", "38.91.112.98",
    "38.91.113.10", "38.91.114.26", "38.91.118.98", "38.181.23.70",
    "43.248.172.149", "45.194.36.11", "45.195.148.42", "45.197.63.138",
    "47.76.145.46", "47.76.206.40", "47.76.226.133", "47.239.160.115",
    "52.184.66.236", "103.71.152.14", "103.99.61.46", "103.101.177.98",
    "103.101.177.106", "103.101.177.178", "103.142.147.155", "103.193.174.48",
    "103.207.164.50", "118.107.46.23", "118.107.47.132", "120.89.71.130",
    "134.122.196.9", "137.220.137.139", "137.220.152.195",
    "137.220.205.130", "154.212.146.57", "154.23.127.35", "154.23.178.23",
    "154.23.178.82", "154.82.85.34", "154.82.92.13", "154.91.65.112",
    "154.91.83.28", "156.234.0.28", "156.247.35.2", "156.247.38.11",
    "156.247.41.56", "192.2.183.40", "198.2.235.187", "198.176.60.31",
    "202.95.8.55", "206.119.80.53", "206.119.82.12", "206.238.114.13",
    "206.238.115.106", "206.238.198.49", "206.238.220.50", "206.238.220.85",
    "206.238.221.97", "206.238.76.142", "206.238.77.181",
];

/// 银狐木马已知互斥体名称（2025-2026变种，含新变种的iryhtyruqm）
const SILVERFOX_MUTEXES: &[&str] = &[
    "Run2019", "ConnentGroup", "iryhtyruqm",
];

/// 银狐木马伪装的系统服务名
const SILVERFOX_FAKE_SERVICES: &[&str] = &[
    "NetHelperSvc", "Rslmxp nnjkwaum",
];

/// 银狐木马已知C2端口（2025-2026变种）
const SILVERFOX_C2_PORTS: &[u16] = &[
    18852, 9090, 9091, 9092, 6180, 443,
];

/// 可疑端口（常用于C2通信和远控）
const SUSPICIOUS_PORTS: &[u16] = &[
    4444, 4445, 6666, 6667, 9999, 1234, 31337, 3389, 22, 23, 445, 139,
    6180, 8888, 1337, 5900, 8080, 8443, 18852, 9090, 9091, 9092,
    5555, 9999, 4444, 1337, 31337, 6667, 12345, 12346, 54321,
];

/// 可疑子进程名（LOLBins - Living Off The Land Binaries）
const SUSPICIOUS_PROCESS_NAMES: &[&str] = &[
    "cmd", "powershell", "wscript", "cscript", "mshta", "rundll32",
    "regsvr32", "msiexec", "certutil", "bitsadmin", "schtasks",
    "netsh", "wmic", "vssadmin", "bcdedit", "shutdown",
    "reg", "net", "sc", "taskkill", "diskpart", "format",
];

/// 安全软件进程名（银狐会检测这些，用于环境感知）
const SECURITY_PRODUCT_NAMES: &[&str] = &[
    // 火绒
    "hipstray", "hipmain", "wsctrl", "usysdiag",
    // 360
    "360tray", "360safe", "zhudongfangyu", "360sd", "360leakfixer",
    // 腾讯电脑管家
    "qhsafe", "qhsrv", "qmtray", "qmsafe",
    // 金山
    "kxescore", "kxetray", "knsdtray",
    // 卡巴斯基
    "avp", "kavtray",
    // Windows Defender
    "msmpeng", "msascui", "securityhealth",
    // 迈克菲
    "mcshield", "mctray",
    // 其他
    "avguard", "avgsvc", "nortonsecurity",
];

/// 系统关键进程（注入这些进程是高危行为）
const SYSTEM_CRITICAL_PROCESSES: &[&str] = &[
    "explorer", "svchost", "lsass", "csrss", "winlogon",
    "services", "smss", "wininit", "dwm",
];

/// 勒索软件常见加密扩展名
const RANSOMWARE_EXTENSIONS: &[&str] = &[
    ".locked", ".encrypted", ".crypto", ".crypt", ".enc",
    ".ransom", ".crypted", ".locky", ".wcry", ".wannacry",
    ".cerber", ".ryuk", ".sodinokibi", ".conti", ".gandcrab",
    ".phobos", ".djvu", ".stop", ".maze", ".revil",
];

/// 已知恶意互斥体名称（跨家族）
const KNOWN_MALWARE_MUTEXES: &[&str] = &[
    // 银狐
    "Run2019", "ConnentGroup", "iryhtyruqm",
    // 通用远控
    "syncMutex", "syncStart", "DC_MUTEX", "Ozdrw",
    // 蠕虫
    "sbsbsbsb", "q1q1q1q1",
];

pub struct BehaviorAnalysisEngine {
    rules: Vec<IoaRule>,
    events: Vec<BehaviorEvent>,
    scores: HashMap<String, u32>,
    total_score: u32,
    /// 上下文增强：多个低分行为组合时额外加分
    context_bonus: u32,
}

impl BehaviorAnalysisEngine {
    pub fn new() -> Self {
        let rules = Self::default_rules();
        Self {
            rules,
            events: Vec::new(),
            scores: HashMap::new(),
            total_score: 0,
            context_bonus: 0,
        }
    }

    fn default_rules() -> Vec<IoaRule> {
        vec![
            // === 文件系统 ===
            // 低分单项，避免正常安装程序误报
            IoaRule { id: "FS-001".into(), name: "系统目录可执行文件创建".into(), category: BehaviorCategory::FileSystem, weight: 15, description: "在系统目录创建可执行文件".into() },
            IoaRule { id: "FS-002".into(), name: "系统文件修改".into(), category: BehaviorCategory::FileSystem, weight: 25, description: "修改系统关键文件".into() },
            IoaRule { id: "FS-003".into(), name: "批量文件删除(≥10)".into(), category: BehaviorCategory::FileSystem, weight: 50, description: "短时间内删除大量文件（勒索特征）".into() },
            IoaRule { id: "FS-004".into(), name: "文件扩展名篡改".into(), category: BehaviorCategory::FileSystem, weight: 40, description: "批量修改文件扩展名（勒索特征）".into() },
            IoaRule { id: "FS-005".into(), name: "文件内容覆写".into(), category: BehaviorCategory::FileSystem, weight: 55, description: "用随机数据覆写文件内容（wiper特征）".into() },
            IoaRule { id: "FS-006".into(), name: "MBR修改".into(), category: BehaviorCategory::FileSystem, weight: 80, description: "修改主引导记录（破坏性恶意软件特征）".into() },
            IoaRule { id: "FS-007".into(), name: "磁盘擦除".into(), category: BehaviorCategory::FileSystem, weight: 90, description: "擦除磁盘数据（wiper特征）".into() },
            IoaRule { id: "FS-008".into(), name: "批量文件加密".into(), category: BehaviorCategory::FileSystem, weight: 60, description: "短时间内加密大量文件（勒索特征）".into() },
            IoaRule { id: "FS-009".into(), name: "文档目录批量修改".into(), category: BehaviorCategory::FileSystem, weight: 35, description: "用户文档目录批量创建/修改文件（勒索前兆）".into() },
            // 银狐专项
            IoaRule { id: "SF-001".into(), name: "文件分割重组".into(), category: BehaviorCategory::FileSystem, weight: 45, description: "将PE文件拆分为文本片段再拼接执行（银狐免杀特征）".into() },
            IoaRule { id: "SF-002".into(), name: "释放隐藏文件".into(), category: BehaviorCategory::FileSystem, weight: 20, description: "释放无扩展名的隐藏文件（银狐特征）".into() },
            IoaRule { id: "FS-010".into(), name: "可疑目录释放可执行文件".into(), category: BehaviorCategory::FileSystem, weight: 25, description: "在AppData/ProgramData/Temp等可疑目录释放可执行文件（银狐常见行为）".into() },
            IoaRule { id: "FS-011".into(), name: "随机名称可执行文件".into(), category: BehaviorCategory::FileSystem, weight: 20, description: "释放随机命名的可执行文件（银狐/木马免杀特征）".into() },
            IoaRule { id: "FS-012".into(), name: "可疑目录随机名称可执行文件".into(), category: BehaviorCategory::FileSystem, weight: 45, description: "在可疑目录释放随机名称可执行文件（银狐高置信度特征）".into() },

            // === 注册表 ===
            IoaRule { id: "REG-001".into(), name: "自启动项修改".into(), category: BehaviorCategory::Registry, weight: 20, description: "修改Run/RunOnce等自启动键".into() },
            IoaRule { id: "REG-002".into(), name: "安全设置修改".into(), category: BehaviorCategory::Registry, weight: 30, description: "修改安全相关注册表项".into() },
            IoaRule { id: "REG-003".into(), name: "注册表键创建".into(), category: BehaviorCategory::Registry, weight: 10, description: "创建新的注册表键".into() },
            IoaRule { id: "REG-004".into(), name: "系统代理修改".into(), category: BehaviorCategory::Registry, weight: 35, description: "修改系统代理设置（银狐C2流量转发）".into() },
            IoaRule { id: "REG-005".into(), name: "AppInit_DLLs修改".into(), category: BehaviorCategory::Registry, weight: 40, description: "修改AppInit_DLLs（持久化注入）".into() },
            IoaRule { id: "REG-006".into(), name: "Winlogon修改".into(), category: BehaviorCategory::Registry, weight: 45, description: "修改Winlogon Shell/Userinit（持久化注入）".into() },
            IoaRule { id: "REG-007".into(), name: "COM对象劫持".into(), category: BehaviorCategory::Registry, weight: 35, description: "劫持COM对象CLSID（持久化）".into() },
            IoaRule { id: "REG-008".into(), name: "IFEO劫持".into(), category: BehaviorCategory::Registry, weight: 40, description: "Image File Execution Options劫持（持久化）".into() },
            IoaRule { id: "REG-009".into(), name: "注册表备份删除".into(), category: BehaviorCategory::Registry, weight: 30, description: "删除注册表备份（防御规避）".into() },

            // === 进程 ===
            IoaRule { id: "PROC-001".into(), name: "可疑子进程创建".into(), category: BehaviorCategory::Process, weight: 15, description: "创建cmd/powershell等可疑子进程".into() },
            IoaRule { id: "PROC-002".into(), name: "进程注入".into(), category: BehaviorCategory::Process, weight: 40, description: "向其他进程注入代码".into() },
            IoaRule { id: "PROC-003".into(), name: "进程镂空".into(), category: BehaviorCategory::Process, weight: 45, description: "Process Hollowing技术".into() },
            IoaRule { id: "PROC-004".into(), name: "DLL注入".into(), category: BehaviorCategory::Process, weight: 35, description: "DLL注入到其他进程".into() },
            IoaRule { id: "PROC-005".into(), name: "线程劫持".into(), category: BehaviorCategory::Process, weight: 40, description: "线程劫持技术".into() },
            IoaRule { id: "PROC-006".into(), name: "代码注入".into(), category: BehaviorCategory::Process, weight: 45, description: "代码注入技术".into() },
            IoaRule { id: "PROC-007".into(), name: "可疑互斥体创建".into(), category: BehaviorCategory::Process, weight: 30, description: "创建已知恶意互斥体（银狐Run2019/iryhtyruqm等）".into() },
            IoaRule { id: "PROC-008".into(), name: "explorer.exe注入".into(), category: BehaviorCategory::Process, weight: 50, description: "注入explorer.exe常驻进程（银狐新变种特征）".into() },
            IoaRule { id: "PROC-009".into(), name: "DLL搜索顺序劫持".into(), category: BehaviorCategory::Process, weight: 35, description: "白加黑DLL劫持（银狐DoH变种特征）".into() },
            IoaRule { id: "PROC-010".into(), name: "sRDI反射加载".into(), category: BehaviorCategory::Process, weight: 50, description: "DLL转shellcode内存反射加载（银狐新变种特征）".into() },
            IoaRule { id: "PROC-011".into(), name: "rundll32可疑执行".into(), category: BehaviorCategory::Process, weight: 25, description: "rundll32加载可疑DLL（银狐特征）".into() },
            IoaRule { id: "PROC-012".into(), name: "内核驱动加载".into(), category: BehaviorCategory::Process, weight: 55, description: "加载内核驱动（rootkit特征）".into() },
            IoaRule { id: "PROC-013".into(), name: "过量子进程创建".into(), category: BehaviorCategory::Process, weight: 35, description: "创建超过2个子进程（银狐/木马多层派生特征）".into() },

            // === 网络 ===
            IoaRule { id: "NET-001".into(), name: "可疑端口连接".into(), category: BehaviorCategory::Network, weight: 20, description: "连接已知C2端口".into() },
            IoaRule { id: "NET-002".into(), name: "可疑DNS查询".into(), category: BehaviorCategory::Network, weight: 25, description: "查询可疑域名".into() },
            IoaRule { id: "NET-003".into(), name: "银狐C2域名连接".into(), category: BehaviorCategory::Network, weight: 60, description: "连接已知银狐木马C2域名".into() },
            IoaRule { id: "NET-004".into(), name: "加密C2通信".into(), category: BehaviorCategory::Network, weight: 35, description: "检测到加密C2通信（银狐Base64+XOR特征）".into() },
            IoaRule { id: "NET-005".into(), name: "银狐C2 IP连接".into(), category: BehaviorCategory::Network, weight: 55, description: "连接已知银狐木马C2 IP地址".into() },
            IoaRule { id: "NET-006".into(), name: "DoH隐蔽通信".into(), category: BehaviorCategory::Network, weight: 40, description: "DNS over HTTPS隐蔽通信（银狐DoH变种特征）".into() },
            IoaRule { id: "NET-007".into(), name: "网络共享枚举".into(), category: BehaviorCategory::Network, weight: 25, description: "枚举网络共享（蠕虫横向传播特征）".into() },
            IoaRule { id: "NET-008".into(), name: "横向移动".into(), category: BehaviorCategory::Network, weight: 45, description: "尝试横向移动到其他主机".into() },
            IoaRule { id: "NET-009".into(), name: "数据外发".into(), category: BehaviorCategory::Network, weight: 40, description: "大量数据外发（数据窃取特征）".into() },

            // === 系统 ===
            IoaRule { id: "SYS-001".into(), name: "服务创建".into(), category: BehaviorCategory::System, weight: 20, description: "创建系统服务".into() },
            IoaRule { id: "SYS-002".into(), name: "计划任务创建".into(), category: BehaviorCategory::System, weight: 20, description: "创建计划任务".into() },
            IoaRule { id: "SYS-003".into(), name: "屏幕锁定".into(), category: BehaviorCategory::System, weight: 50, description: "尝试锁定屏幕（勒索特征）".into() },
            IoaRule { id: "SYS-004".into(), name: "输入阻断".into(), category: BehaviorCategory::System, weight: 50, description: "阻断鼠标键盘输入（勒索特征）".into() },
            IoaRule { id: "SYS-005".into(), name: "壁纸修改".into(), category: BehaviorCategory::System, weight: 35, description: "修改桌面壁纸（勒索特征）".into() },
            IoaRule { id: "SYS-006".into(), name: "卷影副本删除".into(), category: BehaviorCategory::System, weight: 50, description: "删除卷影副本（勒索特征）".into() },
            IoaRule { id: "SYS-007".into(), name: "备份目录删除".into(), category: BehaviorCategory::System, weight: 50, description: "删除备份目录（勒索特征）".into() },
            IoaRule { id: "SYS-008".into(), name: "启动配置修改".into(), category: BehaviorCategory::System, weight: 30, description: "修改启动配置".into() },
            IoaRule { id: "SYS-009".into(), name: "安全模式禁用".into(), category: BehaviorCategory::System, weight: 40, description: "禁用安全模式".into() },
            IoaRule { id: "SYS-010".into(), name: "UAC禁用".into(), category: BehaviorCategory::System, weight: 30, description: "禁用用户账户控制".into() },
            IoaRule { id: "SYS-011".into(), name: "防火墙规则添加".into(), category: BehaviorCategory::System, weight: 25, description: "添加防火墙规则".into() },
            IoaRule { id: "SYS-012".into(), name: "Defender禁用".into(), category: BehaviorCategory::System, weight: 45, description: "禁用Windows Defender".into() },
            IoaRule { id: "SYS-013".into(), name: "系统还原禁用".into(), category: BehaviorCategory::System, weight: 35, description: "禁用系统还原".into() },
            IoaRule { id: "SYS-014".into(), name: "Defender排除项添加".into(), category: BehaviorCategory::System, weight: 40, description: "添加Defender扫描排除项（银狐新变种特征）".into() },
            IoaRule { id: "SYS-015".into(), name: "事件日志清除".into(), category: BehaviorCategory::System, weight: 30, description: "清除事件日志（防御规避）".into() },
            IoaRule { id: "SYS-016".into(), name: "系统关机".into(), category: BehaviorCategory::System, weight: 45, description: "强制关机/重启（破坏性特征）".into() },

            // === 安全对抗 ===
            IoaRule { id: "SEC-001".into(), name: "反调试".into(), category: BehaviorCategory::Security, weight: 20, description: "检测调试器".into() },
            IoaRule { id: "SEC-002".into(), name: "反虚拟机".into(), category: BehaviorCategory::Security, weight: 15, description: "检测虚拟机环境".into() },
            IoaRule { id: "SEC-003".into(), name: "沙箱检测".into(), category: BehaviorCategory::Security, weight: 20, description: "检测沙箱环境".into() },
            IoaRule { id: "SEC-004".into(), name: "安全软件环境检测".into(), category: BehaviorCategory::Security, weight: 35, description: "检测火绒/360/腾讯管家等安全软件（银狐特征）".into() },
            IoaRule { id: "SEC-005".into(), name: "数字签名伪造".into(), category: BehaviorCategory::Security, weight: 40, description: "伪造知名公司数字签名（银狐特征）".into() },
            IoaRule { id: "SEC-006".into(), name: "安全软件网络阻断".into(), category: BehaviorCategory::Security, weight: 45, description: "阻断安全软件网络功能（银狐新变种特征）".into() },
            IoaRule { id: "SEC-007".into(), name: "加壳检测".into(), category: BehaviorCategory::Security, weight: 15, description: "检测到加壳（UPX/VMProtect等）".into() },

            // === 持久化 ===
            IoaRule { id: "PER-001".into(), name: "伪装系统服务".into(), category: BehaviorCategory::Persistence, weight: 35, description: "创建伪装的系统服务名（银狐NetHelperSvc等）".into() },
            IoaRule { id: "PER-002".into(), name: "WMI持久化".into(), category: BehaviorCategory::Persistence, weight: 35, description: "通过WMI事件订阅实现持久化".into() },
            IoaRule { id: "PER-003".into(), name: "PowerShell持久化".into(), category: BehaviorCategory::Persistence, weight: 30, description: "Base64编码PowerShell脚本持久化（银狐新变种特征）".into() },

            // === 凭据窃取 ===
            IoaRule { id: "CRED-001".into(), name: "键盘记录".into(), category: BehaviorCategory::CredentialAccess, weight: 45, description: "键盘记录行为（信息窃取）".into() },
            IoaRule { id: "CRED-002".into(), name: "屏幕截图".into(), category: BehaviorCategory::CredentialAccess, weight: 30, description: "截取屏幕（信息窃取）".into() },
            IoaRule { id: "CRED-003".into(), name: "剪贴板监控".into(), category: BehaviorCategory::CredentialAccess, weight: 35, description: "监控/劫持剪贴板数据".into() },
            IoaRule { id: "CRED-004".into(), name: "浏览器数据窃取".into(), category: BehaviorCategory::CredentialAccess, weight: 40, description: "窃取浏览器保存的密码/Cookie".into() },
            IoaRule { id: "CRED-005".into(), name: "LSASS访问".into(), category: BehaviorCategory::CredentialAccess, weight: 55, description: "访问LSASS内存（凭据窃取）".into() },
            IoaRule { id: "CRED-006".into(), name: "SAM数据库访问".into(), category: BehaviorCategory::CredentialAccess, weight: 50, description: "访问SAM数据库（凭据窃取）".into() },
            IoaRule { id: "CRED-007".into(), name: "凭据窃取".into(), category: BehaviorCategory::CredentialAccess, weight: 40, description: "从各类来源窃取凭据".into() },
            IoaRule { id: "CRED-008".into(), name: "Token操纵".into(), category: BehaviorCategory::CredentialAccess, weight: 45, description: "操纵访问令牌（权限提升）".into() },
            IoaRule { id: "CRED-009".into(), name: "权限提升".into(), category: BehaviorCategory::CredentialAccess, weight: 35, description: "尝试权限提升".into() },

            // === 数据收集 ===
            IoaRule { id: "COL-001".into(), name: "系统信息收集".into(), category: BehaviorCategory::Collection, weight: 15, description: "收集系统硬件/软件信息".into() },
            IoaRule { id: "COL-002".into(), name: "进程枚举".into(), category: BehaviorCategory::Collection, weight: 20, description: "枚举系统进程（银狐用于查找安全软件）".into() },
            IoaRule { id: "COL-003".into(), name: "文件搜索加密".into(), category: BehaviorCategory::Collection, weight: 30, description: "搜索用户文档（勒索软件加密前兆）".into() },
        ]
    }

    pub fn add_event(&mut self, event: BehaviorEvent) {
        let rule_id = self.match_rule(&event);
        if !rule_id.is_empty() {
            if let Some(rule) = self.rules.iter().find(|r| r.id == rule_id) {
                let score = self.scores.entry(rule.id.clone()).or_insert(0);
                *score += rule.weight;
                self.total_score += rule.weight;
            }
        }
        self.events.push(event);
        // 每次添加事件后重新计算上下文增强分
        self.recompute_context_bonus();
    }

    /// 上下文增强评分：多个行为组合时额外加分，降低单项误报率
    fn recompute_context_bonus(&self) {
        // 此方法在 add_event 中调用，但实际加分在 verdict() 中
        // 这里仅做占位，实际逻辑在 verdict 中
    }

    /// 计算上下文增强分（多行为组合才加分，单行为不加分）
    fn context_bonus_score(&self) -> u32 {
        let mut bonus = 0u32;

        let has_reg_run = self.has_rule_hit("REG-001");
        let has_suspicious_proc = self.has_rule_hit("PROC-001");
        let has_network = self.events.iter().any(|e| matches!(e.category(), BehaviorCategory::Network));
        let has_proxy = self.has_rule_hit("REG-004");
        let has_file_split = self.has_rule_hit("SF-001");
        let has_hidden_file = self.has_rule_hit("SF-002");
        let has_mutex = self.has_rule_hit("PROC-007");
        let has_fake_service = self.has_rule_hit("PER-001");
        let has_sec_detect = self.has_rule_hit("SEC-004");
        let has_forged_sig = self.has_rule_hit("SEC-005");
        let has_schtasks = self.has_rule_hit("SYS-002");
        let has_service = self.has_rule_hit("SYS-001");
        let has_c2_domain = self.has_rule_hit("NET-003");
        let has_encrypted_c2 = self.has_rule_hit("NET-004");
        let has_defender_disable = self.has_rule_hit("SYS-012");
        let has_c2_ip = self.has_rule_hit("NET-005");
        let has_doh = self.has_rule_hit("NET-006");
        let has_explorer_inject = self.has_rule_hit("PROC-008");
        let has_dll_hijack = self.has_rule_hit("PROC-009");
        let has_srdi = self.has_rule_hit("PROC-010");
        let has_defender_exclusion = self.has_rule_hit("SYS-014");
        let has_sec_net_block = self.has_rule_hit("SEC-006");
        let has_ps_persist = self.has_rule_hit("PER-003");
        let has_rundll32 = self.has_rule_hit("PROC-011");
        let has_packing = self.has_rule_hit("SEC-007");
        let has_keylog = self.has_rule_hit("CRED-001");
        let has_cred_theft = self.has_rule_hit("CRED-007");
        let has_lsass = self.has_rule_hit("CRED-005");
        let has_data_exfil = self.has_rule_hit("NET-009");
        let has_batch_delete = self.has_rule_hit("FS-003");
        let has_ext_change = self.has_rule_hit("FS-004");
        let has_mbr = self.has_rule_hit("FS-006");
        let has_disk_wipe = self.has_rule_hit("FS-007");
        let has_mass_encrypt = self.has_rule_hit("FS-008");
        let has_shadow_delete = self.has_rule_hit("SYS-006");
        let has_backup_delete = self.has_rule_hit("SYS-007");
        let has_wallpaper = self.has_rule_hit("SYS-005");
        let has_screen_lock = self.has_rule_hit("SYS-003");
        let has_input_block = self.has_rule_hit("SYS-004");
        let has_event_log_clear = self.has_rule_hit("SYS-015");
        let has_shutdown = self.has_rule_hit("SYS-016");
        let has_process_enum = self.has_rule_hit("COL-002");
        let has_file_search = self.has_rule_hit("COL-003");
        let has_share_enum = self.has_rule_hit("NET-007");
        let has_lateral = self.has_rule_hit("NET-008");

        // 新增行为检测规则
        let has_suspicious_dir_drop = self.has_rule_hit("FS-010");
        let has_random_name = self.has_rule_hit("FS-011");
        let has_suspicious_random = self.has_rule_hit("FS-012");
        let has_excessive_children = self.has_rule_hit("PROC-013");

        // ===== 银狐木马组合特征（2025-2026变种）=====

        // 银狐组合：自启动 + 可疑子进程 + 网络 → 强烈恶意
        if has_reg_run && has_suspicious_proc && has_network {
            bonus += 25;
        }
        // 银狐组合：文件分割重组 + 隐藏文件 → 免杀行为链
        if has_file_split && has_hidden_file {
            bonus += 20;
        }
        // 银狐组合：互斥体 + 伪装服务 → 银狐持久化
        if has_mutex && has_fake_service {
            bonus += 20;
        }
        // 银狐组合：安全软件检测 + 代理修改 → C2流量转发
        if has_sec_detect && has_proxy {
            bonus += 25;
        }
        // 银狐组合：数字签名伪造 + C2域名 → 银狐确认
        if has_forged_sig && has_c2_domain {
            bonus += 30;
        }
        // 银狐新变种：explorer注入 + sRDI + 安全软件网络阻断
        if has_explorer_inject && (has_srdi || has_sec_net_block) {
            bonus += 30;
        }
        // 银狐新变种：Defender排除项 + 进程枚举
        if has_defender_exclusion && has_process_enum {
            bonus += 25;
        }
        // 银狐DoH变种：DLL搜索顺序劫持 + DoH通信
        if has_dll_hijack && has_doh {
            bonus += 25;
        }
        // 银狐新变种：rundll32执行 + PowerShell持久化
        if has_rundll32 && has_ps_persist {
            bonus += 20;
        }
        // 银狐确认：C2 IP + C2域名
        if has_c2_ip && has_c2_domain {
            bonus += 20;
        }
        // 银狐新变种：加壳 + 安全软件检测
        if has_packing && has_sec_detect {
            bonus += 15;
        }

        // ===== 行为驱动检测组合（银狐/木马通用行为模式）=====

        // 可疑目录释放 + 过量子进程 → 银狐典型行为链
        if (has_suspicious_dir_drop || has_suspicious_random) && has_excessive_children {
            bonus += 30;
        }
        // 随机名称 + 过量子进程 → 木马多层派生
        if has_random_name && has_excessive_children {
            bonus += 25;
        }
        // 可疑目录释放 + 网络连接 → 木马下载/回传
        if (has_suspicious_dir_drop || has_random_name) && has_network {
            bonus += 20;
        }
        // 可疑目录+随机名称 + 自启动 → 持久化落地
        if has_suspicious_random && has_reg_run {
            bonus += 25;
        }

        // ===== 勒索软件组合特征 =====

        // 勒索组合：批量加密 + 卷影删除
        if (has_mass_encrypt || has_batch_delete || has_ext_change) && (has_shadow_delete || has_backup_delete) {
            bonus += 25;
        }
        // 勒索组合：文件搜索 + 批量加密
        if has_file_search && (has_mass_encrypt || has_ext_change) {
            bonus += 20;
        }
        // 勒索组合：壁纸修改 + 屏幕锁定/输入阻断
        if has_wallpaper && (has_screen_lock || has_input_block) {
            bonus += 20;
        }

        // ===== Wiper/破坏性木马组合 =====

        // Wiper组合：MBR修改 + 系统关机
        if has_mbr && has_shutdown {
            bonus += 30;
        }
        // Wiper组合：磁盘擦除 + 事件日志清除
        if has_disk_wipe && has_event_log_clear {
            bonus += 25;
        }

        // ===== 信息窃取组合 =====

        // 信息窃取：键盘记录 + 数据外发
        if has_keylog && has_data_exfil {
            bonus += 25;
        }
        // 信息窃取：LSASS访问 + 凭据窃取
        if has_lsass && has_cred_theft {
            bonus += 20;
        }
        // 信息窃取：屏幕截图 + 数据外发
        if has_data_exfil && self.has_rule_hit("CRED-002") {
            bonus += 15;
        }

        // ===== 蠕虫组合 =====

        // 蠕虫组合：网络共享枚举 + 横向移动
        if has_share_enum && has_lateral {
            bonus += 25;
        }

        // ===== 通用持久化组合 =====

        // 持久化组合：计划任务 + 服务 + 自启动 → 多重持久化
        if has_schtasks && has_service && has_reg_run {
            bonus += 15;
        }
        // C2通信组合：C2域名 + 加密通信
        if has_c2_domain && has_encrypted_c2 {
            bonus += 15;
        }
        // 对抗组合：安全软件检测 + Defender禁用
        if has_sec_detect && has_defender_disable {
            bonus += 20;
        }
        // 对抗组合：安全软件网络阻断 + 进程枚举
        if has_sec_net_block && has_process_enum {
            bonus += 15;
        }

        bonus
    }

    fn has_rule_hit(&self, rule_id: &str) -> bool {
        self.scores.contains_key(rule_id)
    }

    fn match_rule(&self, event: &BehaviorEvent) -> String {
        match event {
            // === 文件系统 ===
            BehaviorEvent::FileCreate { is_system_dir, is_executable, is_suspicious_dir, is_random_name, .. } => {
                if *is_system_dir && *is_executable {
                    "FS-001".into()
                } else if *is_executable && *is_suspicious_dir && *is_random_name {
                    "FS-012".into()
                } else if *is_executable && *is_suspicious_dir {
                    "FS-010".into()
                } else if *is_executable && *is_random_name {
                    "FS-011".into()
                } else {
                    String::new()
                }
            }
            BehaviorEvent::FileModify { is_system_file, .. } => {
                if *is_system_file { "FS-002".into() } else { String::new() }
            }
            BehaviorEvent::FileDelete { count, .. } => {
                if *count >= 10 { "FS-003".into() } else { String::new() }
            }
            BehaviorEvent::FileBatchDelete { count } => {
                if *count >= 10 { "FS-003".into() } else { String::new() }
            }
            BehaviorEvent::FileExtensionChange { count } => {
                if *count >= 5 { "FS-004".into() } else { String::new() }
            }
            BehaviorEvent::FileSplitAndReconstruct { .. } => "SF-001".into(),
            BehaviorEvent::HiddenFileDrop { .. } => "SF-002".into(),
            BehaviorEvent::FileContentOverwrite { .. } => "FS-005".into(),
            BehaviorEvent::MbrModify => "FS-006".into(),
            BehaviorEvent::DiskWipe => "FS-007".into(),
            BehaviorEvent::FileMassEncrypt { count } => {
                if *count >= 5 { "FS-008".into() } else { String::new() }
            }
            BehaviorEvent::DocumentDirMassModification { count } => {
                if *count >= 10 { "FS-009".into() } else { String::new() }
            }

            // === 注册表 ===
            BehaviorEvent::RegModify { is_run_key, is_security_key, is_proxy_key, .. } => {
                if *is_run_key { "REG-001".into() }
                else if *is_security_key { "REG-002".into() }
                else if *is_proxy_key { "REG-004".into() }
                else { String::new() }
            }
            BehaviorEvent::RegCreate { .. } => "REG-003".into(),
            BehaviorEvent::ProxySettingModified { .. } => "REG-004".into(),
            BehaviorEvent::AppInitDllsModify => "REG-005".into(),
            BehaviorEvent::WinlogonModify => "REG-006".into(),
            BehaviorEvent::ComHijack { .. } => "REG-007".into(),
            BehaviorEvent::IfeoHijack { .. } => "REG-008".into(),
            BehaviorEvent::RegistryBackupDelete => "REG-009".into(),

            // === 进程 ===
            BehaviorEvent::ProcessCreate { is_suspicious, .. } => {
                if *is_suspicious { "PROC-001".into() } else { String::new() }
            }
            BehaviorEvent::ProcessInject { .. } => "PROC-002".into(),
            BehaviorEvent::ProcessHollowing => "PROC-003".into(),
            BehaviorEvent::DllInjection { .. } => "PROC-004".into(),
            BehaviorEvent::ThreadHijack => "PROC-005".into(),
            BehaviorEvent::CodeInjection => "PROC-006".into(),
            BehaviorEvent::MutexCreate { name } => {
                let lower = name.to_lowercase();
                if SILVERFOX_MUTEXES.iter().any(|m| lower.contains(&m.to_lowercase())) {
                    "PROC-007".into()
                } else { String::new() }
            }
            BehaviorEvent::ExplorerProcessInjection => "PROC-008".into(),
            BehaviorEvent::DllSearchOrderHijack { .. } => "PROC-009".into(),
            BehaviorEvent::SRDILoading => "PROC-010".into(),
            BehaviorEvent::Rundll32Execution { .. } => "PROC-011".into(),
            BehaviorEvent::DriverLoad { .. } => "PROC-012".into(),
            BehaviorEvent::ExcessiveChildProcess { .. } => "PROC-013".into(),

            // === 网络 ===
            BehaviorEvent::NetworkConnect { ip, port, is_suspicious } => {
                let ip_str = ip.as_str();
                if SILVERFOX_C2_IPS.iter().any(|c2| *c2 == ip_str) {
                    "NET-005".into()
                } else if SILVERFOX_C2_PORTS.contains(port) {
                    "NET-005".into()
                } else if *is_suspicious || SUSPICIOUS_PORTS.contains(port) {
                    "NET-001".into()
                } else { String::new() }
            }
            BehaviorEvent::NetworkDNS { domain, is_suspicious } => {
                let lower = domain.to_lowercase();
                if SILVERFOX_C2_DOMAINS.iter().any(|d| lower.contains(d)) {
                    "NET-003".into()
                } else if *is_suspicious {
                    "NET-002".into()
                } else { String::new() }
            }
            BehaviorEvent::EncryptedC2Communication { .. } => "NET-004".into(),
            BehaviorEvent::DnsOverHttps { .. } => "NET-006".into(),
            BehaviorEvent::NetworkShareEnum => "NET-007".into(),
            BehaviorEvent::LateralMovement { .. } => "NET-008".into(),
            BehaviorEvent::KnownC2PortConnect { .. } => "NET-001".into(),
            BehaviorEvent::DataExfiltration { bytes } => {
                if *bytes > 1_000_000 { "NET-009".into() } else { String::new() }
            }

            // === 系统 ===
            BehaviorEvent::ServiceCreate { name } => {
                let lower = name.to_lowercase();
                if SILVERFOX_FAKE_SERVICES.iter().any(|s| lower.contains(&s.to_lowercase())) {
                    "PER-001".into()
                } else {
                    "SYS-001".into()
                }
            }
            BehaviorEvent::ServiceModify { .. } => "SYS-001".into(),
            BehaviorEvent::ScheduledTaskCreate { .. } => "SYS-002".into(),
            BehaviorEvent::ScreenLockAttempt => "SYS-003".into(),
            BehaviorEvent::MouseKeyboardBlock => "SYS-004".into(),
            BehaviorEvent::WallpaperChange { .. } => "SYS-005".into(),
            BehaviorEvent::ShadowCopyDelete => "SYS-006".into(),
            BehaviorEvent::BackupCatalogDelete => "SYS-007".into(),
            BehaviorEvent::BootConfigModify => "SYS-008".into(),
            BehaviorEvent::SafeModeDisable => "SYS-009".into(),
            BehaviorEvent::UacDisable => "SYS-010".into(),
            BehaviorEvent::FirewallRuleAdd => "SYS-011".into(),
            BehaviorEvent::DefenderDisable => "SYS-012".into(),
            BehaviorEvent::SystemRestoreDisable => "SYS-013".into(),
            BehaviorEvent::DefenderExclusionAdd { .. } => "SYS-014".into(),
            BehaviorEvent::EventLogClear => "SYS-015".into(),
            BehaviorEvent::SystemShutdown => "SYS-016".into(),

            // === 安全对抗 ===
            BehaviorEvent::AntiDebug { .. } => "SEC-001".into(),
            BehaviorEvent::AntiVM { .. } => "SEC-002".into(),
            BehaviorEvent::SandboxDetect { .. } => "SEC-003".into(),
            BehaviorEvent::SecurityProductDetection { .. } => "SEC-004".into(),
            BehaviorEvent::ForgedDigitalSignature { .. } => "SEC-005".into(),
            BehaviorEvent::SecurityProductNetworkBlock => "SEC-006".into(),
            BehaviorEvent::PackingDetected { .. } => "SEC-007".into(),

            // === 持久化 ===
            BehaviorEvent::FakeSystemService { name } => {
                let lower = name.to_lowercase();
                if SILVERFOX_FAKE_SERVICES.iter().any(|s| lower.contains(&s.to_lowercase())) {
                    "PER-001".into()
                } else { String::new() }
            }
            BehaviorEvent::WmiPersistence { .. } => "PER-002".into(),
            BehaviorEvent::PowerShellPersistence { .. } => "PER-003".into(),

            // === 凭据窃取 ===
            BehaviorEvent::Keylogging => "CRED-001".into(),
            BehaviorEvent::ScreenCapture => "CRED-002".into(),
            BehaviorEvent::ClipboardHijack => "CRED-003".into(),
            BehaviorEvent::BrowserDataTheft { .. } => "CRED-004".into(),
            BehaviorEvent::LsassAccess => "CRED-005".into(),
            BehaviorEvent::SamDatabaseAccess => "CRED-006".into(),
            BehaviorEvent::CredentialTheft { .. } => "CRED-007".into(),
            BehaviorEvent::TokenManipulation => "CRED-008".into(),
            BehaviorEvent::PrivilegeEscalation => "CRED-009".into(),

            // === 数据收集 ===
            BehaviorEvent::SystemInfoCollection => "COL-001".into(),
            BehaviorEvent::ProcessEnumeration => "COL-002".into(),
            BehaviorEvent::FileSearchForEncryption => "COL-003".into(),
        }
    }

    pub fn verdict(&self) -> AnalysisVerdict {
        let final_score = self.total_score + self.context_bonus_score();
        if final_score >= MALICIOUS_THRESHOLD {
            AnalysisVerdict::Malicious
        } else if final_score >= 50 {
            AnalysisVerdict::Suspicious
        } else {
            AnalysisVerdict::Benign
        }
    }

    pub fn total_score(&self) -> u32 {
        self.total_score + self.context_bonus_score()
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn hit_rules(&self) -> Vec<&IoaRule> {
        self.scores
            .keys()
            .filter_map(|id| self.rules.iter().find(|r| &r.id == id))
            .collect()
    }

    pub fn events_by_category(&self, cat: &BehaviorCategory) -> Vec<&BehaviorEvent> {
        self.events.iter().filter(|e| {
            &e.category() == cat
        }).collect()
    }

    /// 导出所有行为事件为可读文本，用于日志分析和规则改进
    pub fn export_behavior_report(&self, target_file: &str, verdict: &str, score: u32, family: Option<&MalwareFamily>) -> String {
        let mut report = String::new();

        report.push_str("========================================\n");
        report.push_str("XIGUASecurity 沙盒行为分析报告\n");
        report.push_str("========================================\n");
        report.push_str(&format!("分析时间: {}\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S")));
        report.push_str(&format!("目标文件: {}\n", target_file));
        report.push_str(&format!("判定结果: {}\n", verdict));
        report.push_str(&format!("威胁评分: {}\n", score));
        if let Some(f) = family {
            report.push_str(&format!("病毒家族: {} ({})\n", f.name, f.family_id));
            report.push_str(&format!("家族描述: {}\n", f.description));
        } else {
            report.push_str("病毒家族: 未识别\n");
        }
        report.push_str(&format!("行为事件数: {}\n", self.events.len()));
        report.push_str("\n");

        // 命中规则列表
        report.push_str("----------------------------------------\n");
        report.push_str("命中的 IOA 规则\n");
        report.push_str("----------------------------------------\n");
        if self.scores.is_empty() {
            report.push_str("（无规则命中）\n");
        } else {
            let mut sorted_hits: Vec<(&String, &u32)> = self.scores.iter().collect();
            sorted_hits.sort_by(|a, b| b.1.cmp(a.1));
            for (rule_id, accumulated) in &sorted_hits {
                if let Some(rule) = self.rules.iter().find(|r| &r.id == *rule_id) {
                    report.push_str(&format!(
                        "  [{}] {} (权重:{}, 累计:{}) - {}\n",
                        rule.id, rule.name, rule.weight, accumulated, rule.description
                    ));
                }
            }
        }
        report.push_str(&format!("\n基础评分: {}\n", self.total_score));
        report.push_str(&format!("上下文增强分: {}\n", self.context_bonus_score()));
        report.push_str(&format!("最终评分: {}\n\n", self.total_score + self.context_bonus_score()));

        // 按类别输出行为事件
        let categories = [
            (BehaviorCategory::FileSystem, "文件系统"),
            (BehaviorCategory::Registry, "注册表"),
            (BehaviorCategory::Process, "进程"),
            (BehaviorCategory::Network, "网络"),
            (BehaviorCategory::System, "系统"),
            (BehaviorCategory::Security, "安全对抗"),
            (BehaviorCategory::Persistence, "持久化"),
            (BehaviorCategory::CredentialAccess, "凭据窃取"),
            (BehaviorCategory::Collection, "数据收集"),
        ];

        for (cat, cat_name) in &categories {
            let cat_events: Vec<&BehaviorEvent> = self.events.iter()
                .filter(|e| &e.category() == cat)
                .collect();
            if cat_events.is_empty() {
                continue;
            }
            report.push_str("----------------------------------------\n");
            report.push_str(&format!("{} ({} 事件)\n", cat_name, cat_events.len()));
            report.push_str("----------------------------------------\n");
            for (i, event) in cat_events.iter().enumerate() {
                report.push_str(&format!("  {}. {:?}\n", i + 1, event));
            }
            report.push_str("\n");
        }

        report.push_str("========================================\n");
        report.push_str("报告结束\n");
        report.push_str("========================================\n");

        report
    }

    /// 根据行为特征识别恶意软件家族
    pub fn detect_malware_family(&self) -> Option<MalwareFamily> {
        let has_run_key = self.has_rule_hit("REG-001");
        let has_suspicious_child = self.has_rule_hit("PROC-001");
        let has_network = self.events.iter().any(|e| matches!(e.category(), BehaviorCategory::Network));
        let has_file_split = self.has_rule_hit("SF-001");
        let has_sec_detect = self.has_rule_hit("SEC-004");
        let has_proxy = self.has_rule_hit("REG-004");
        let has_mutex = self.has_rule_hit("PROC-007");
        let has_fake_service = self.has_rule_hit("PER-001");
        let has_forged_sig = self.has_rule_hit("SEC-005");
        let has_c2_domain = self.has_rule_hit("NET-003");
        let has_encrypted_c2 = self.has_rule_hit("NET-004");
        let has_hidden_file = self.has_rule_hit("SF-002");
        let has_c2_ip = self.has_rule_hit("NET-005");
        let has_doh = self.has_rule_hit("NET-006");
        let has_explorer_inject = self.has_rule_hit("PROC-008");
        let has_dll_hijack = self.has_rule_hit("PROC-009");
        let has_srdi = self.has_rule_hit("PROC-010");
        let has_rundll32 = self.has_rule_hit("PROC-011");
        let has_defender_exclusion = self.has_rule_hit("SYS-014");
        let has_sec_net_block = self.has_rule_hit("SEC-006");
        let has_ps_persist = self.has_rule_hit("PER-003");
        let has_packing = self.has_rule_hit("SEC-007");
        let has_process_enum = self.has_rule_hit("COL-002");
        let has_suspicious_dir_drop = self.has_rule_hit("FS-010");
        let has_random_name = self.has_rule_hit("FS-011");
        let has_suspicious_random = self.has_rule_hit("FS-012");
        let has_excessive_children = self.has_rule_hit("PROC-013");

        // ===== 银狐病毒（SilverFox）=====
        // 基于2025-2026最新变种分析：
        // 变种1: MSI投递，文件分割重组，安全软件检测，代理修改，互斥体Run2019，伪装服务NetHelperSvc
        // 变种2: NSIS投递，explorer注入，sRDI反射加载，Defender排除项，安全软件网络阻断，互斥体iryhtyruqm
        // 变种3: INNO Setup投递，DLL搜索顺序劫持(白加黑)，DoH隐蔽通信，键盘记录，凭据窃取

        // 银狐核心特征：文件分割重组 + 安全软件检测 + 网络通信
        if has_file_split && has_sec_detect && has_network {
            return Some(MalwareFamily {
                name: "银狐病毒".to_string(),
                family_id: "SilverFox".to_string(),
                description: "检测到文件分割重组免杀、安全软件环境检测和网络通信，符合银狐木马2025-2026变种的核心行为特征。该家族通过MSI/NSIS投递，使用多层解密+反射加载，具备80+备用C2地址".to_string(),
            });
        }
        // 银狐新变种：explorer注入 + sRDI + 安全软件网络阻断
        if has_explorer_inject && (has_srdi || has_sec_net_block) {
            return Some(MalwareFamily {
                name: "银狐病毒".to_string(),
                family_id: "SilverFox".to_string(),
                description: "检测到explorer.exe进程注入和sRDI反射加载/安全软件网络阻断，符合银狐木马2025年9月新变种特征。该变种通过NSIS投递，使用进程空洞+进程注入隐藏于explorer.exe，阻断安全软件云查杀功能".to_string(),
            });
        }
        // 银狐DoH变种：DLL搜索顺序劫持 + DoH通信
        if has_dll_hijack && has_doh {
            return Some(MalwareFamily {
                name: "银狐病毒".to_string(),
                family_id: "SilverFox".to_string(),
                description: "检测到DLL搜索顺序劫持(白加黑)和DNS over HTTPS隐蔽通信，符合银狐木马DoH变种特征。该变种通过INNO Setup投递，使用DoH隧道绕过DNS监控，具备键盘记录和凭据窃取能力".to_string(),
            });
        }
        // 银狐次级特征：互斥体 + 伪装服务 + 代理修改
        if has_mutex && has_fake_service && has_proxy {
            return Some(MalwareFamily {
                name: "银狐病毒".to_string(),
                family_id: "SilverFox".to_string(),
                description: "检测到银狐特征互斥体(Run2019/iryhtyruqm)、伪装系统服务(NetHelperSvc)和系统代理修改，符合银狐木马持久化和C2流量转发行为".to_string(),
            });
        }
        // 银狐新变种：Defender排除项 + 进程枚举
        if has_defender_exclusion && has_process_enum {
            return Some(MalwareFamily {
                name: "银狐病毒".to_string(),
                family_id: "SilverFox".to_string(),
                description: "检测到Defender扫描排除项添加和进程枚举，符合银狐木马新变种的防御规避行为。该变种通过PowerShell将磁盘添加为Defender排除项，并枚举进程查找安全软件".to_string(),
            });
        }
        // 银狐组合：自启动 + 可疑子进程 + 安全软件检测
        if has_run_key && has_suspicious_child && has_sec_detect {
            return Some(MalwareFamily {
                name: "银狐病毒".to_string(),
                family_id: "SilverFox".to_string(),
                description: "检测到自启动修改、可疑子进程创建和安全软件环境检测，符合银狐木马持久化和对抗行为".to_string(),
            });
        }
        // 银狐组合：伪造签名 + C2域名/IP
        if has_forged_sig && (has_c2_domain || has_c2_ip) {
            return Some(MalwareFamily {
                name: "银狐病毒".to_string(),
                family_id: "SilverFox".to_string(),
                description: "检测到伪造数字签名和已知银狐C2连接，确认为银狐木马".to_string(),
            });
        }
        // 银狐组合：隐藏文件释放 + 加密C2通信
        if has_hidden_file && has_encrypted_c2 {
            return Some(MalwareFamily {
                name: "银狐病毒".to_string(),
                family_id: "SilverFox".to_string(),
                description: "检测到隐藏文件释放和加密C2通信，符合银狐木马无文件加载和Base64+XOR加密通信特征".to_string(),
            });
        }
        // 银狐新变种：rundll32执行 + PowerShell持久化
        if has_rundll32 && has_ps_persist {
            return Some(MalwareFamily {
                name: "银狐病毒".to_string(),
                family_id: "SilverFox".to_string(),
                description: "检测到rundll32加载可疑DLL和PowerShell持久化，符合银狐木马新变种的执行和持久化行为".to_string(),
            });
        }
        // 银狐组合：C2 IP + C2域名
        if has_c2_ip && has_c2_domain {
            return Some(MalwareFamily {
                name: "银狐病毒".to_string(),
                family_id: "SilverFox".to_string(),
                description: "检测到同时连接银狐已知C2 IP和C2域名，确认为银狐木马通信行为".to_string(),
            });
        }
        // 银狐行为驱动检测：可疑目录随机名称 + 过量子进程 → 银狐多层派生
        if has_suspicious_random && has_excessive_children {
            return Some(MalwareFamily {
                name: "银狐病毒".to_string(),
                family_id: "SilverFox".to_string(),
                description: "检测到在可疑目录释放随机名称可执行文件并创建超过2个子进程，符合银狐木马多层派生和免杀落地行为。该家族通过在AppData/ProgramData等目录释放随机名exe，再多层派生子进程加载恶意模块".to_string(),
            });
        }
        // 银狐行为驱动检测：可疑目录释放 + 网络 → 木马下载/回传
        if (has_suspicious_dir_drop || has_random_name) && has_network && has_excessive_children {
            return Some(MalwareFamily {
                name: "银狐病毒".to_string(),
                family_id: "SilverFox".to_string(),
                description: "检测到可疑目录释放可执行文件、过量子进程创建和网络通信，符合银狐木马下载器行为链。程序在可疑目录释放文件后派生多个子进程，并建立C2网络连接".to_string(),
            });
        }
        // 通用木马：可疑目录释放 + 自启动 → 持久化落地
        if (has_suspicious_dir_drop || has_suspicious_random) && has_run_key {
            return Some(MalwareFamily {
                name: "持久化木马".to_string(),
                family_id: "GenericTrojan".to_string(),
                description: "检测到在可疑目录释放可执行文件并修改自启动项，具备持久化驻留特征。程序通过AppData/ProgramData等目录落地并设置开机自启".to_string(),
            });
        }

        // ===== Wiper/破坏性木马 =====
        let has_mbr = self.has_rule_hit("FS-006");
        let has_disk_wipe = self.has_rule_hit("FS-007");
        let has_content_overwrite = self.has_rule_hit("FS-005");
        let has_shutdown = self.has_rule_hit("SYS-016");
        let has_event_log_clear = self.has_rule_hit("SYS-015");

        if has_mbr || has_disk_wipe {
            return Some(MalwareFamily {
                name: "破坏性木马(Wiper)".to_string(),
                family_id: "Wiper".to_string(),
                description: "检测到MBR修改或磁盘擦除行为，具有破坏性恶意软件(Wiper)特征。此类木马会永久性破坏用户数据，不可恢复".to_string(),
            });
        }
        if has_content_overwrite && (has_shutdown || has_event_log_clear) {
            return Some(MalwareFamily {
                name: "破坏性木马(Wiper)".to_string(),
                family_id: "Wiper".to_string(),
                description: "检测到文件内容覆写配合系统关机或日志清除，具有wiper-ransomware特征，使用随机数据覆写文件后伪造勒索".to_string(),
            });
        }

        // ===== 勒索软件 =====
        let has_batch_delete = self.has_rule_hit("FS-003");
        let has_ext_change = self.has_rule_hit("FS-004");
        let has_mass_encrypt = self.has_rule_hit("FS-008");
        let has_shadow_delete = self.has_rule_hit("SYS-006");
        let has_backup_delete = self.has_rule_hit("SYS-007");
        let has_wallpaper = self.has_rule_hit("SYS-005");
        let has_screen_lock = self.has_rule_hit("SYS-003");
        let has_input_block = self.has_rule_hit("SYS-004");
        let has_file_search = self.has_rule_hit("COL-003");

        if (has_mass_encrypt || has_batch_delete || has_ext_change) && (has_shadow_delete || has_backup_delete) {
            return Some(MalwareFamily {
                name: "勒索软件".to_string(),
                family_id: "Ransomware".to_string(),
                description: "检测到批量文件加密/删除和卷影副本/备份删除，具有典型勒索软件行为特征".to_string(),
            });
        }
        if (has_mass_encrypt || has_batch_delete || has_ext_change) && (has_wallpaper || has_screen_lock || has_input_block) {
            return Some(MalwareFamily {
                name: "勒索软件".to_string(),
                family_id: "Ransomware".to_string(),
                description: "检测到批量文件加密/删除配合壁纸修改或屏幕锁定，具有勒索软件行为特征".to_string(),
            });
        }
        if has_file_search && (has_mass_encrypt || has_ext_change) {
            return Some(MalwareFamily {
                name: "勒索软件".to_string(),
                family_id: "Ransomware".to_string(),
                description: "检测到文件搜索和批量文件加密，符合勒索软件先扫描后加密的行为模式".to_string(),
            });
        }

        // ===== 信息窃取木马 =====
        let has_keylog = self.has_rule_hit("CRED-001");
        let has_cred_theft = self.has_rule_hit("CRED-007");
        let has_lsass = self.has_rule_hit("CRED-005");
        let has_browser_theft = self.has_rule_hit("CRED-004");
        let has_clipboard = self.has_rule_hit("CRED-003");
        let has_data_exfil = self.has_rule_hit("NET-009");
        let has_screen_capture = self.has_rule_hit("CRED-002");

        if has_keylog && has_data_exfil {
            return Some(MalwareFamily {
                name: "信息窃取木马".to_string(),
                family_id: "InfoStealer".to_string(),
                description: "检测到键盘记录和数据外发，具有信息窃取木马特征。该类木马窃取用户输入的密码、银行卡等敏感信息".to_string(),
            });
        }
        if has_lsass && has_cred_theft {
            return Some(MalwareFamily {
                name: "凭据窃取木马".to_string(),
                family_id: "CredentialStealer".to_string(),
                description: "检测到LSASS内存访问和凭据窃取行为，具有凭据窃取木马特征。该类木马从LSASS进程内存中提取用户密码哈希".to_string(),
            });
        }
        if has_browser_theft && has_data_exfil {
            return Some(MalwareFamily {
                name: "浏览器信息窃取木马".to_string(),
                family_id: "BrowserStealer".to_string(),
                description: "检测到浏览器数据窃取和数据外发，具有浏览器信息窃取木马特征。该类木马窃取浏览器保存的密码、Cookie和自动填充数据".to_string(),
            });
        }
        if has_clipboard && has_data_exfil {
            return Some(MalwareFamily {
                name: "剪贴板劫持木马".to_string(),
                family_id: "ClipboardHijacker".to_string(),
                description: "检测到剪贴板监控和数据外发，具有剪贴板劫持木马特征。该类木马监控剪贴板内容，替换钱包地址等敏感信息".to_string(),
            });
        }
        if (has_screen_capture || has_keylog) && has_network && !has_batch_delete && !has_ext_change {
            return Some(MalwareFamily {
                name: "远控木马(RAT)".to_string(),
                family_id: "RAT".to_string(),
                description: "检测到屏幕监控/键盘记录和网络通信，具有远控木马(RAT)特征。该类木马可远程控制受害者电脑，进行屏幕监控、文件窃取等操作".to_string(),
            });
        }

        // ===== 蠕虫 =====
        let has_share_enum = self.has_rule_hit("NET-007");
        let has_lateral = self.has_rule_hit("NET-008");

        if has_share_enum && has_lateral {
            return Some(MalwareFamily {
                name: "蠕虫".to_string(),
                family_id: "Worm".to_string(),
                description: "检测到网络共享枚举和横向移动，具有蠕虫特征。该类恶意软件通过网络共享和漏洞自动传播到其他主机".to_string(),
            });
        }

        // ===== 下载者木马 =====
        let has_suspicious_net = self.has_rule_hit("NET-001");
        let has_file_create_sys = self.has_rule_hit("FS-001");
        let has_suspicious_dns = self.has_rule_hit("NET-002");

        if has_suspicious_net && (has_file_create_sys || has_suspicious_dns) && !has_batch_delete && !has_ext_change {
            return Some(MalwareFamily {
                name: "下载者木马".to_string(),
                family_id: "Downloader".to_string(),
                description: "通过可疑网络连接下载并执行恶意程序，在系统目录创建可执行文件，具有下载者木马行为特征".to_string(),
            });
        }

        // ===== 后门 =====
        let has_schtasks = self.has_rule_hit("SYS-002");
        let has_service = self.has_rule_hit("SYS-001");
        let has_appinit = self.has_rule_hit("REG-005");
        let has_winlogon = self.has_rule_hit("REG-006");
        let has_wmi_persist = self.has_rule_hit("PER-002");

        if (has_appinit || has_winlogon || has_wmi_persist) && has_network {
            return Some(MalwareFamily {
                name: "后门".to_string(),
                family_id: "Backdoor".to_string(),
                description: "检测到深度持久化机制(AppInit_DLLs/Winlogon/WMI)和网络通信，具有后门特征。该类恶意软件在系统中建立隐蔽后门，供攻击者随时远程访问".to_string(),
            });
        }

        // ===== Rootkit =====
        let has_driver_load = self.has_rule_hit("PROC-012");
        let has_event_log = self.has_rule_hit("SYS-015");

        if has_driver_load && (has_event_log || has_sec_detect) {
            return Some(MalwareFamily {
                name: "Rootkit".to_string(),
                family_id: "Rootkit".to_string(),
                description: "检测到内核驱动加载和安全软件检测/日志清除，具有Rootkit特征。该类恶意软件通过内核驱动深入系统底层，隐藏自身进程和文件".to_string(),
            });
        }

        // ===== 进程注入型木马 =====
        let has_injection = self.has_rule_hit("PROC-002") || self.has_rule_hit("PROC-003")
            || self.has_rule_hit("PROC-004") || self.has_rule_hit("PROC-005")
            || self.has_rule_hit("PROC-006");

        if has_injection {
            return Some(MalwareFamily {
                name: "进程注入型木马".to_string(),
                family_id: "ProcessInjection".to_string(),
                description: "检测到进程注入、DLL注入、进程镂空或代码注入行为，具有进程注入型恶意软件特征".to_string(),
            });
        }

        // ===== 挖矿木马 =====
        if has_network && (has_schtasks || has_service) && !has_batch_delete && !has_wallpaper && !has_ext_change {
            return Some(MalwareFamily {
                name: "挖矿木马".to_string(),
                family_id: "Cryptominer".to_string(),
                description: "通过网络连接矿池，通过计划任务或服务实现持久化，具有挖矿木马行为特征".to_string(),
            });
        }

        // ===== 安全软件对抗型 =====
        let has_defender_disable = self.has_rule_hit("SYS-012");
        let has_uac_disable = self.has_rule_hit("SYS-010");
        let has_firewall = self.has_rule_hit("SYS-011");
        let has_safe_mode_disable = self.has_rule_hit("SYS-009");
        let has_system_restore_disable = self.has_rule_hit("SYS-013");

        if has_defender_disable || (has_uac_disable && (has_firewall || has_safe_mode_disable || has_system_restore_disable)) {
            return Some(MalwareFamily {
                name: "安全软件对抗型木马".to_string(),
                family_id: "AntiSecurity".to_string(),
                description: "尝试禁用安全软件、防火墙、UAC或系统还原功能，具有安全软件对抗型恶意软件特征".to_string(),
            });
        }

        // ===== 反分析型 =====
        let has_anti_debug = self.has_rule_hit("SEC-001");
        let has_anti_vm = self.has_rule_hit("SEC-002");
        let has_sandbox_detect = self.has_rule_hit("SEC-003");

        if has_anti_debug || has_anti_vm || has_sandbox_detect {
            return Some(MalwareFamily {
                name: "反分析型木马".to_string(),
                family_id: "AntiAnalysis".to_string(),
                description: "检测到反调试、反虚拟机或反沙箱行为，具有反分析型恶意软件特征".to_string(),
            });
        }

        // ===== 加壳可疑程序 =====
        if has_packing && has_network {
            return Some(MalwareFamily {
                name: "加壳可疑程序".to_string(),
                family_id: "Packed".to_string(),
                description: "检测到加壳(UPX/VMProtect等)和网络通信，具有加壳可疑程序特征。加壳常被用于规避杀毒软件检测".to_string(),
            });
        }

        None
    }
}

/// 恶意软件家族识别结果
#[derive(Debug, Clone)]
pub struct MalwareFamily {
    pub name: String,
    pub family_id: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub enum AnalysisVerdict {
    Benign,
    Suspicious,
    Malicious,
}

impl AnalysisVerdict {
    pub fn is_malicious(&self) -> bool {
        matches!(self, Self::Malicious)
    }
    pub fn is_safe(&self) -> bool {
        matches!(self, Self::Benign)
    }
    pub fn label(&self) -> &str {
        match self {
            Self::Benign => "安全",
            Self::Suspicious => "可疑",
            Self::Malicious => "恶意",
        }
    }
}

// ==================== 沙盒窗口边框渲染 ====================

/// 终止进程并等待其真正退出
/// 返回 true 表示进程已退出，false 表示终止失败
#[cfg(windows)]
fn terminate_process_with_wait(pid: u32) -> bool {
    use windows::Win32::System::Threading::{
        OpenProcess, TerminateProcess, WaitForSingleObject,
        PROCESS_TERMINATE, PROCESS_SYNCHRONIZE,
    };
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};

    let handle = unsafe {
        match OpenProcess(
            PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
            false,
            pid,
        ) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[R3Monitor] OpenProcess failed PID={}: {}", pid, e);
                return false;
            }
        }
    };

    let terminated = unsafe { TerminateProcess(handle, 1) }.is_ok();
    if !terminated {
        eprintln!("[R3Monitor] TerminateProcess failed PID={}", pid);
        let _ = unsafe { CloseHandle(handle) };
        return false;
    }

    // 等待进程真正退出（最多 3 秒）
    let result = unsafe { WaitForSingleObject(handle, 3000) };
    let _ = unsafe { CloseHandle(handle) };

    if result == WAIT_OBJECT_0 {
        println!("[R3Monitor] Process PID={} terminated and exited", pid);
        true
    } else {
        eprintln!("[R3Monitor] Process PID={} did not exit within 3s (wait result={:?})", pid, result);
        false
    }
}

#[cfg(not(windows))]
fn terminate_process_with_wait(_pid: u32) -> bool {
    false
}

/// 按进程名查找所有匹配的进程 PID
#[cfg(windows)]
fn find_pids_by_name(target_name: &str) -> Vec<u32> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use std::path::Path;

    let target_lower = target_name.to_lowercase();
    let mut result = Vec::new();

    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(s) => s,
            Err(_) => return result,
        };

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let exe_name = String::from_utf16_lossy(&entry.szExeFile);
                let exe_name = exe_name.trim_end_matches('\0');
                let file_name = Path::new(exe_name)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(exe_name);
                if file_name.to_lowercase() == target_lower {
                    // ★排除最近放行的普通进程★
                    // 历史教训：分析完成后重新启动的原始文件进程（mark_recently_launched
                    // 标记）与沙箱内进程同名，曾被误判为沙箱目标（"薛定谔"状态）。
                    // 修复方案：不能只按路径判断——沙箱内主进程的 image path 可能是
                    // 原始路径（Sandboxie 对部分目录直接访问），路径过滤会漏掉真进程
                    // 导致 `Started, PID: None` 空分析。正确做法：匹配所有同名进程，
                    // 排除"最近放行"名单中的进程（那些是分析完成后重启的普通进程），
                    // 其余即为沙箱内进程。
                    if !is_recently_launched(entry.th32ProcessID) {
                        // 路径级防线：最近分析完成的原始文件路径的进程不是沙箱目标
                        if let Some(full_path) = get_process_full_path(entry.th32ProcessID) {
                            if is_recently_analyzed_path(&full_path) {
                                // 跳过（普通进程，非沙箱目标）
                            } else {
                                // ★沙箱内进程优先★：路径含 \Sandbox\ 的进程是真正的
                                // 沙箱目标（Sandboxie 重定向的进程路径），排在最前面
                                if is_path_in_sandbox(&full_path) {
                                    result.insert(0, entry.th32ProcessID);
                                } else {
                                    result.push(entry.th32ProcessID);
                                }
                            }
                        } else {
                            result.push(entry.th32ProcessID);
                        }
                    }
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = windows::Win32::Foundation::CloseHandle(snapshot);
    }

    result
}

/// 递归收集进程树（包括 root_pid 及其所有子进程、孙进程）
/// 用于边框渲染：安装程序会派生 .tmp 子进程来创建窗口，需要给整个进程树加边框
#[cfg(windows)]
fn collect_process_tree_pids(root_pids: &[u32]) -> Vec<u32> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };

    let mut result: std::collections::HashSet<u32> = root_pids.iter().copied().collect();
    let mut to_check: Vec<u32> = root_pids.to_vec();

    unsafe {
        while let Some(parent_pid) = to_check.pop() {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32ParentProcessID == parent_pid {
                        if result.insert(entry.th32ProcessID) {
                            to_check.push(entry.th32ProcessID);
                        }
                    }
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(snapshot);
        }
    }

    result.into_iter().collect()
}

#[cfg(not(windows))]
fn collect_process_tree_pids(_root_pids: &[u32]) -> Vec<u32> {
    Vec::new()
}

#[cfg(windows)]
fn apply_sandbox_border_to_pids(pids: &[u32]) {
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowThreadProcessId, IsWindowVisible,
        SetWindowPos, HWND_TOPMOST, SWP_NOMOVE, SWP_NOSIZE, SWP_NOACTIVATE,
        SendMessageW, WM_SETTEXT, GetWindowTextW, GetWindowTextLengthW,
    };
    use windows::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMWA_BORDER_COLOR, DWMWA_CAPTION_COLOR,
        DWMWA_TEXT_COLOR,
    };

    // 已修改过标题的 HWND 集合在模块级别定义（TITLED_HWNDS）
    // 边框颜色可以重复设置（幂等），但标题追加不幂等

    // 本次 EnumWindows 的临时收集列表
    let mut found_hwnds: Vec<(isize, u32)> = Vec::new();

    unsafe extern "system" fn enum_callback(hwnd: HWND, lparam: windows::Win32::Foundation::LPARAM) -> windows::Win32::Foundation::BOOL {
        let mut window_pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, Some(&mut window_pid as *mut u32));
        if IsWindowVisible(hwnd).as_bool() && GetWindowTextLengthW(hwnd) > 0 {
            // 将结果写入 lparam 指向的 Vec
            let vec_ptr = lparam.0 as *mut Vec<(isize, u32)>;
            if !vec_ptr.is_null() {
                (*vec_ptr).push((hwnd.0 as isize, window_pid));
            }
        }
        windows::Win32::Foundation::BOOL(1)
    }

    unsafe {
        let vec_ptr = &mut found_hwnds as *mut Vec<(isize, u32)>;
        let _ = EnumWindows(Some(enum_callback), windows::Win32::Foundation::LPARAM(vec_ptr as isize));
    }

    let suffix: Vec<u16> = " 在西瓜杀毒沙箱中\0".encode_utf16().collect();
    let suffix_no_null: &[u16] = &suffix[..suffix.len() - 1];

    let mut applied_count = 0;
    for (hwnd_raw, window_pid) in &found_hwnds {
        if !pids.contains(window_pid) {
            continue;
        }

        let hwnd = HWND(*hwnd_raw as *mut _);
        unsafe {
            // 边框颜色、标题栏颜色、文字颜色：幂等，可重复设置
            let border_result = DwmSetWindowAttribute(
                hwnd,
                DWMWA_BORDER_COLOR,
                &SANDBOX_BORDER_COLOR as *const _ as *const _,
                std::mem::size_of::<u32>() as u32,
            );
            let caption_result = DwmSetWindowAttribute(
                hwnd,
                DWMWA_CAPTION_COLOR,
                &SANDBOX_BORDER_COLOR as *const _ as *const _,
                std::mem::size_of::<u32>() as u32,
            );
            let white: u32 = 0x00FFFFFF;
            let text_result = DwmSetWindowAttribute(
                hwnd,
                DWMWA_TEXT_COLOR,
                &white as *const _ as *const _,
                std::mem::size_of::<u32>() as u32,
            );
            let _ = SetWindowPos(
                hwnd,
                HWND_TOPMOST,
                0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
            );

            // 标题修改：只在第一次处理此 HWND 时执行
            // 用 static HashSet 记录已处理过的 HWND，避免重试时重复追加后缀
            let already_titled = TITLED_HWNDS.lock().unwrap().contains(hwnd_raw);
            if !already_titled {
                let len = GetWindowTextLengthW(hwnd);
                let mut original = vec![0u16; (len as usize) + 1];
                let got = GetWindowTextW(hwnd, &mut original);
                original.truncate(got as usize);
                let mut new_title = original.clone();
                // 双重保险：也检查标题是否已包含后缀
                if !new_title.ends_with(suffix_no_null) {
                    new_title.extend_from_slice(suffix_no_null);
                }
                new_title.push(0); // null terminator
                let _ = SendMessageW(
                    hwnd,
                    WM_SETTEXT,
                    windows::Win32::Foundation::WPARAM(0),
                    windows::Win32::Foundation::LPARAM(new_title.as_ptr() as isize),
                );
                // 记录此 HWND 已修改过标题
                TITLED_HWNDS.lock().unwrap().insert(*hwnd_raw);
            }

            if border_result.is_ok() && caption_result.is_ok() && text_result.is_ok() {
                applied_count += 1;
                if !already_titled {
                    println!("[SandboxAnalysis] 已为窗口 PID={} 应用紫色边框并修改标题", window_pid);
                }
            } else {
                eprintln!("[SandboxAnalysis] 边框渲染部分失败 PID={} border={:?} caption={:?} text={:?}",
                    window_pid, border_result, caption_result, text_result);
            }
        }
    }

    if applied_count == 0 && !pids.is_empty() {
        println!("[SandboxAnalysis] 未找到可应用边框的窗口（进程可能尚未创建窗口），PIDs: {:?}", pids);
    }
}

// ==================== 沙盒控制器 ====================

pub struct SandboxController {
    target_file: String,
    target_pid: Option<u32>,
    box_name: String,
    engine: BehaviorAnalysisEngine,
    start_time: Option<Instant>,
}

impl SandboxController {
    pub fn new(target_file: &str) -> Self {
        Self {
            target_file: target_file.to_string(),
            target_pid: None,
            box_name: SANDBOX_BOX_NAME.to_string(),
            engine: BehaviorAnalysisEngine::new(),
            start_time: None,
        }
    }

    pub fn prepare_environment(&self) -> Result<(), String> {
        let env_start = Instant::now();

        // ★环境互斥锁 + READY 标志：与 Setup 线程的 auto_configure_sandbox() 共享，
        // 整个会话只完整配置一次（安装 + 服务 + 基础沙箱参数），
        // 后续分析直接跳过，避免每次分析都重复数十次进程启动被驱动串行扫描★
        let _guard = SANDBOX_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        if !SANDBOX_ENV_READY.load(Ordering::SeqCst) {
            ensure_sandboxie()?;
            ensure_sbie_service()?;
        }

        // ★每次沙盒准备时结束 Sandboxie 托盘/UI 进程★
        // 历史 bug（全新虚拟机沙盒"正在监控但程序没启动"）：托盘图标
        // （Sandboxie.exe/SbieCtrl.exe/SandMan.exe）持有沙箱 IPC 锁/窗口 hook，
        // Start.exe 启动的目标程序弹不出窗口。用户实测：托盘有图标就无法分析，
        // 退出 Sandboxie 后立刻正常。简单直接：每次准备时杀掉这三个进程即可。
        for name in &["Sandboxie.exe", "SandMan.exe", "SbieCtrl.exe"] {
            kill_process_by_name(name);
        }

        // 检测目标文件是否为 MSI 安装程序
        // MSI 文件需要临时启用 MsiInstaller 设置才能在沙箱中正常运行
        // configure_sandbox_box 内部基础配置只执行一次，这里仅同步 MsiInstaller，开销极小
        // 注意：configure 放在锁内，与 Setup 线程的配置完全串行，避免并发写 Sandboxie 配置
        let is_msi = std::path::Path::new(&self.target_file)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("msi"))
            .unwrap_or(false);
        configure_sandbox_box(is_msi)?;

        SANDBOX_ENV_READY.store(true, Ordering::SeqCst);

        println!("[SandboxAnalysis] prepare_environment 完成（耗时 {:.1}s）", env_start.elapsed().as_secs_f64());
        Ok(())
    }

    pub fn start(&mut self) -> Result<u32, String> {
        let start_exe = get_sbie_start_exe().ok_or("Start.exe not found")?;

        println!("[SandboxAnalysis] Launching: {} via sandbox", self.target_file);

        let box_arg = format!("/box:{}", self.box_name);
        let target = strip_nt_path_prefix(&self.target_file);
        let target_name = std::path::Path::new(&self.target_file)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Sandbox.exe")
            .to_string();

        // ★启动验证与重试机制★
        // 历史 bug（全新系统/虚拟机）：SbieSvc 驱动尚未完全就绪时，Start.exe 会
        // 静默返回成功但目标程序根本不启动（沙箱里没有进程，只显示"正在监控程序"）。
        // 旧代码只 spawn 一次、不检查结果、不重试，导致全新系统上分析永远空转 60 秒。
        // 修复：spawn 后检查 Start.exe 退出码；找不到沙箱内进程时重试整个启动
        // （最多 3 次），每次重试前重新确认 SbieSvc 服务运行。
        let mut last_matching: Vec<u32> = Vec::new();
        let mut start_error: Option<String> = None;

        for attempt in 1..=3 {
            println!("[SandboxAnalysis] 沙箱启动尝试 #{}/3: {} via {}", attempt, target, start_exe.display());

            // 每次重试前确认服务运行（服务未就绪时重新拉起）
            if attempt > 1 {
                let _ = ensure_sbie_service();
                // ★清理 Sandboxie 托盘 UI★
                // 历史 bug：托盘图标（Sandboxie.exe/SbieCtrl.exe/SandMan.exe）持有
                // 沙箱 IPC 锁/窗口 hook，Start.exe 启动的目标程序弹不出窗口，
                // 沙盒显示"正在监控程序行为"但程序根本没启动。
                // 用户实测：托盘有图标就无法分析，退出 Sandboxie 后立刻正常。
                scrub_sandboxie_ui_sync();
                std::thread::sleep(Duration::from_millis(300));
            }

            // spawn 并等待 Start.exe 完成（它很快返回，目标程序由 SbieSvc 派生）
            let spawn_result = Command::new(&start_exe)
                .args([&box_arg, "/silent"])
                .arg(&target)
                .creation_flags(CREATE_NO_WINDOW)
                .output();

            match spawn_result {
                Ok(out) => {
                    let code = out.status.code().unwrap_or(-1);
                    if !out.status.success() {
                        println!("[SandboxAnalysis] Start.exe 返回失败 exit={} (尝试 #{})", code, attempt);
                        start_error = Some(format!("Start.exe exit={}", code));
                    } else {
                        println!("[SandboxAnalysis] Start.exe 启动成功 exit={} (尝试 #{})", code, attempt);
                    }
                }
                Err(e) => {
                    println!("[SandboxAnalysis] Start.exe 启动失败: {} (尝试 #{})", e, attempt);
                    start_error = Some(e.to_string());
                }
            }

            // 轮询查找沙箱内进程（最多 3 秒，找到就立即返回）
            #[cfg(windows)]
            {
                let mut matching_pids: Vec<u32> = Vec::new();
                for attempt_poll in 1..=15 {
                    matching_pids = find_pids_by_name(&target_name);
                    if !matching_pids.is_empty() {
                        println!("[SandboxAnalysis] 查找进程「{}」匹配 PID: {:?} (尝试 #{}, 轮询 #{})", target_name, matching_pids, attempt, attempt_poll);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }

                if !matching_pids.is_empty() {
                    last_matching = matching_pids.clone();
                    // 边框渲染可能因窗口尚未创建而失败，重试 5 次
                    // 每次重试都动态收集进程树，因为安装程序会派生 .tmp 子进程创建窗口
                    apply_sandbox_border_to_pids(&matching_pids);
                    let root_pids = matching_pids.clone();
                    std::thread::spawn(move || {
                        for attempt in 1..=5 {
                            std::thread::sleep(Duration::from_secs(2));
                            if SANDBOX_ANALYZING.load(Ordering::SeqCst) {
                                // 动态收集进程树（包括新派生的子进程）
                                let tree_pids = collect_process_tree_pids(&root_pids);
                                apply_sandbox_border_to_pids(&tree_pids);
                                println!("[SandboxAnalysis] 边框重试 #{}, PIDs: {:?}", attempt, tree_pids);
                            } else {
                                break;
                            }
                        }
                    });
                    break; // 找到进程，停止重试
                }

                println!("[SandboxAnalysis] 尝试 #{} 未找到沙箱内进程「{}」（可能 SbieSvc 未就绪）", attempt, target_name);
                std::thread::sleep(Duration::from_millis(800));
            }
        }

        if last_matching.is_empty() {
            // 所有重试都失败
            let reason = start_error.unwrap_or_else(|| "沙箱内未出现目标进程".to_string());
            let msg = format!("沙箱启动失败（3 次重试均未找到进程）: {}", reason);
            println!("[SandboxAnalysis] ★{}★", msg);
            crate::diag_warn!("[SandboxAnalysis] {}", msg);
            return Err(msg);
        }

        if let Some(&pid) = last_matching.first() {
            self.target_pid = Some(pid);
            ANALYSIS_TARGET_PID.store(pid, Ordering::SeqCst);
        }

        self.start_time = Some(Instant::now());
        SANDBOX_ANALYSIS_RUNNING.store(true, Ordering::SeqCst);

        println!("[SandboxAnalysis] Started, PID: {:?}", self.target_pid);
        Ok(self.target_pid.unwrap_or(0))
    }

    pub fn stop(&mut self) -> Result<(), String> {
        let start_exe = get_sbie_start_exe().ok_or("Start.exe not found")?;

        let box_arg = format!("/box:{}", self.box_name);
        let _ = Command::new(&start_exe)
            .args([&box_arg, "/terminate"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        SANDBOX_ANALYSIS_RUNNING.store(false, Ordering::SeqCst);
        ANALYSIS_TARGET_PID.store(0, Ordering::SeqCst);
        self.target_pid = None;

        println!("[SandboxAnalysis] Stopped");
        Ok(())
    }

    pub fn add_behavior_event(&mut self, event: BehaviorEvent) {
        self.engine.add_event(event);
    }

    pub fn analyze(&self) -> (AnalysisVerdict, u32, Vec<(String, String)>) {
        let verdict = self.engine.verdict();
        let score = self.engine.total_score();
        let hits = self.engine.hit_rules();
        let hit_names: Vec<(String, String)> = hits
            .iter()
            .map(|r| (r.id.clone(), r.name.clone()))
            .collect();
        (verdict, score, hit_names)
    }

    pub fn event_count(&self) -> usize {
        self.engine.event_count()
    }

    pub fn is_timed_out(&self) -> bool {
        if let Some(start) = &self.start_time {
            return start.elapsed().as_secs() > ANALYSIS_TIMEOUT_SECS;
        }
        false
    }

    pub fn target_file(&self) -> &str {
        &self.target_file
    }

    pub fn target_pid(&self) -> Option<u32> {
        self.target_pid
    }

    pub fn detect_malware_family(&self) -> Option<MalwareFamily> {
        self.engine.detect_malware_family()
    }

    /// 导出行为分析报告到指定目录
    pub fn export_report(&self, verdict_str: &str, score: u32, family: Option<&MalwareFamily>) -> String {
        self.engine.export_behavior_report(&self.target_file, verdict_str, score, family)
    }
}

impl Drop for SandboxController {
    fn drop(&mut self) {
        if SANDBOX_ANALYSIS_RUNNING.load(Ordering::SeqCst) {
            let _ = self.stop();
        }
    }
}

// ==================== 触发机制 ====================

fn get_temp_dir() -> PathBuf {
    let temp = std::env::var("TEMP").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(temp).join("XIGUASandbox")
}

pub fn prepare_trigger(original_file: &str) -> Result<PathBuf, String> {
    let temp_dir = get_temp_dir();
    std::fs::create_dir_all(&temp_dir).map_err(|e| format!("创建临时目录失败: {}", e))?;

    let trigger_path = temp_dir.join(SANDBOX_TRIGGER_NAME);
    std::fs::copy(original_file, &trigger_path)
        .map_err(|e| format!("复制文件失败: {}", e))?;

    println!("[SandboxAnalysis] Trigger prepared: {} -> {}", original_file, trigger_path.display());
    Ok(trigger_path)
}

pub fn run_trigger(trigger_path: &Path) -> Result<(), String> {
    Command::new(trigger_path)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("运行触发文件失败: {}", e))?;
    Ok(())
}

pub fn cleanup_trigger() {
    let trigger_path = get_temp_dir().join(SANDBOX_TRIGGER_NAME);
    if trigger_path.exists() {
        let _ = std::fs::remove_file(&trigger_path);
    }
}

// ==================== 沙盒分析白名单 ====================

fn whitelist_path() -> PathBuf {
    let local_app = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(local_app).join("XIGUASecurity").join("sandbox_whitelist.txt")
}

pub fn compute_file_sha256(path: &str) -> Option<String> {
    use std::io::Read;
    use sha2::{Sha256, Digest};

    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = file.read(&mut buffer).ok()?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

pub fn add_to_whitelist(path: &str) {
    let hash = match compute_file_sha256(path) {
        Some(h) => h,
        None => {
            println!("[SandboxAnalysis] 无法计算 SHA256，跳过白名单: {}", path);
            return;
        }
    };

    let whitelist_file = whitelist_path();
    if let Some(parent) = whitelist_file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let existing = std::fs::read_to_string(&whitelist_file).unwrap_or_default();
    if !existing.lines().any(|line| line == hash) {
        let mut content = existing;
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(&hash);
        content.push('\n');
        let _ = std::fs::write(&whitelist_file, content);
        println!("[SandboxAnalysis] 已添加到白名单: {} ({})", path, hash);
    }
}

pub fn is_image_whitelisted(image_path: &str) -> bool {
    let path = strip_nt_path_prefix(image_path);
    let hash = match compute_file_sha256(&path) {
        Some(h) => h,
        None => return false,
    };
    let whitelist_file = whitelist_path();
    let existing = match std::fs::read_to_string(&whitelist_file) {
        Ok(s) => s,
        Err(_) => return false,
    };
    existing.lines().any(|line| line == hash)
}

pub fn clear_whitelist() -> Result<usize, String> {
    let whitelist_file = whitelist_path();
    let count = std::fs::read_to_string(&whitelist_file)
        .map(|s| s.lines().filter(|l| !l.is_empty()).count())
        .unwrap_or(0);
    let _ = std::fs::write(&whitelist_file, "");
    println!("[SandboxAnalysis] 白名单已清除 ({} 条记录)", count);
    Ok(count)
}

pub fn get_whitelist_count() -> usize {
    let whitelist_file = whitelist_path();
    std::fs::read_to_string(&whitelist_file)
        .map(|s| s.lines().filter(|l| !l.is_empty()).count())
        .unwrap_or(0)
}

// ==================== 辅助函数 ====================

fn get_pid_snapshot() -> Vec<u32> {
    use windows::Win32::System::ProcessStatus::EnumProcesses;
    let mut pids = vec![0u32; 2048];
    let mut bytes = 0u32;
    unsafe {
        let _ = EnumProcesses(pids.as_mut_ptr(), (pids.len() * 4) as u32, &mut bytes);
    }
    let count = bytes as usize / 4;
    pids[..count].to_vec()
}

// ==================== 完整分析流程 ====================

pub struct AnalysisResult {
    pub verdict: AnalysisVerdict,
    pub score: u32,
    pub hit_rules: Vec<(String, String)>,
    pub event_count: usize,
    pub target_file: String,
    pub duration_secs: u64,
}

pub fn run_full_analysis(
    target_file: &str,
    event_collector: impl Fn(&mut SandboxController) -> Result<(), String>,
) -> Result<AnalysisResult, String> {
    let mut controller = SandboxController::new(target_file);

    controller.prepare_environment()?;
    controller.start()?;

    event_collector(&mut controller)?;

    let (verdict, score, hits) = controller.analyze();
    let duration = controller
        .start_time
        .map(|s| s.elapsed().as_secs())
        .unwrap_or(0);

    let result = AnalysisResult {
        verdict: verdict.clone(),
        score,
        hit_rules: hits,
        event_count: controller.event_count(),
        target_file: target_file.to_string(),
        duration_secs: duration,
    };

    match &verdict {
        AnalysisVerdict::Benign => {
            println!("[SandboxAnalysis] 文件安全，关闭沙盒并重新启动");
            controller.stop()?;
            let _ = Command::new(target_file)
                .creation_flags(CREATE_NO_WINDOW)
                .spawn();
        }
        AnalysisVerdict::Malicious => {
            println!("[SandboxAnalysis] 文件恶意，终止进程");
            controller.stop()?;
        }
        AnalysisVerdict::Suspicious => {
            println!("[SandboxAnalysis] 文件可疑，保持沙盒");
        }
    }

    cleanup_trigger();
    Ok(result)
}

// ==================== R3 进程监控（无驱动模式） ====================

static R3_MONITOR_RUNNING: AtomicBool = AtomicBool::new(false);

/// R3 进程监控是否正在运行
pub fn is_r3_monitor_running() -> bool {
    R3_MONITOR_RUNNING.load(Ordering::SeqCst)
}

/// 检查单个进程是否需要沙箱拦截（供 WMI 事件回调使用）
///
/// **检查顺序（从快到慢）**：
/// 1. 沙箱分析是否启用 + 是否正在分析中（原子读，纳秒级）
/// 2. **白名单检查**（读文件 + SHA256，微秒级，不耗时）
/// 3. 排除自身/系统进程（字符串比较，微秒级）
/// 4. 是否可执行文件（扩展名比较，纳秒级）
/// 5. 是否在监控目录下（路径前缀比较，微秒级）
/// 6. 数字签名验证（PowerShell 调用，百毫秒级，最耗时）
///
/// 返回 `true` 表示已拦截（已触发沙箱分析），调用方应跳过后续防护。
/// 返回 `false` 表示放行，调用方可以继续其他防护检查。

/// 检查进程是否仍然存活
#[cfg(windows)]
fn is_process_alive(pid: u32) -> bool {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows::Win32::Foundation::CloseHandle;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        match handle {
            Ok(h) => {
                let _ = CloseHandle(h);
                true
            }
            Err(_) => false,
        }
    }
}

/// 检查文件是否需要沙箱拦截（仅检查，不终止进程，不触发分析）
/// 供驱动通知路径在进程启动前调用：如果返回 true，驱动应直接 DENY 进程启动
/// 供 process_watcher / R3 monitor 在进程启动后调用：如果返回 true，需终止进程并触发分析
#[cfg(windows)]
pub fn should_intercept_for_sandbox(path: &str, pid: u32) -> bool {
    // 0. ★全局冷却期检查（最先执行）★
    // 分析完成后的冷却期内（4s），任何进程启动都不再触发新的沙盒分析。
    // 防止"分析→重新启动→再分析"死循环：重新启动的程序及其子进程
    // （不同 PID/hash/路径）会被全部放行。
    if is_in_analysis_cooldown() {
        println!("[R3Monitor] 全局冷却期内，跳过沙箱拦截: {} (PID={})", path, pid);
        return false;
    }

    // 0a. ★最近放行检查（Benign 判定后重新启动的进程直接放行）★
    // 防止"分析完成立即再次分析"：重新启动的原始文件进程在 TTL 内不被拦截
    if is_recently_launched(pid) {
        println!("[R3Monitor] 最近放行进程 PID={}，跳过沙箱拦截", pid);
        return false;
    }

    // 0b. ★路径级放行检查★：最近分析完成的原始文件路径，同路径进程（含子进程）直接放行
    // 历史 bug：只标记主进程 PID，子进程（不同 PID/hash）仍触发"分析→再分析"死循环
    if is_recently_analyzed_path(path) {
        println!("[R3Monitor] 最近分析完成路径，跳过沙箱拦截: {} (PID={})", path, pid);
        return false;
    }

    // 1. 沙箱分析未启用 → 不拦截
    if !SANDBOX_ANALYSIS_ENABLED.load(Ordering::SeqCst) {
        return false;
    }

    // 2. 正在分析中 → 只放行沙箱内的进程，非沙箱进程继续检查
    if SANDBOX_ANALYZING.load(Ordering::SeqCst) {
        if is_sandbox_pid(pid) {
            return false;
        }
        // 非沙箱进程：继续检查，如果也未签名则需拦截
    }

    // 3. ★AVIC 黑名单检查：命中则不采取任何操作（不拦截、不分析）★
    // AVIC 黑名单拦截由基础防护（WMI watcher）和驱动防护负责，
    // 沙箱分析对已拉黑文件不做任何事——不进沙箱、不终止、不分析。
    if crate::avic_client::check_file(path).is_some() {
        println!("[R3Monitor] AVIC 黑名单文件，沙箱不采取任何操作: {} (PID={})", path, pid);
        return false;
    }

    // 4. ★白名单检查★
    if is_image_whitelisted(path) {
        return false;
    }

    // 5. 排除自身和系统进程
    if is_self_or_excluded_process(path) {
        return false;
    }

    // 6. 检查是否是可执行文件
    if !is_executable(path) {
        return false;
    }

    // 7. 检查是否在监控目录下
    let watched_dirs = get_watched_directories();
    if !is_path_in_watched_dirs(path, &watched_dirs) {
        return false;
    }

    let normalized = normalize_path(path);
    println!("[R3Monitor] 监控目录中的可执行文件: {} (PID={})", normalized, pid);
    crate::diag_info!("[R3Monitor] 监控目录中的可执行文件: {} (PID={})", normalized, pid);

    // 8. 验证数字签名（原生 WinVerifyTrust API，毫秒级，无需启动 PowerShell）
    let has_valid_sig = verify_signature_via_powershell(path);

    if has_valid_sig {
        println!("[R3Monitor] 文件有有效签名，放行: {}", path);
        crate::diag_info!("[R3Monitor] 文件有有效签名，放行: {}", path);
        return false;
    }

    // 9. 未签名 → 需要沙箱拦截
    println!("[R3Monitor] 文件无有效签名，触发沙箱分析: {}", path);
    crate::diag_info!("[R3Monitor] 文件无有效签名，触发沙箱分析: {}", path);
    true
}

/// 终止进程：优先使用 AVModel（多种终止方法，包括 NtTerminateProcess），
/// taskkill 仅作为 AVModel 不可用时的后备
/// 如果 PID 无效（进程已退出），使用 process_name 按名称查找
#[cfg(windows)]
fn terminate_process_via_avmodel_first(pid: u32, process_name: Option<&str>) -> bool {
    // 优先使用 AVModel 独立防护进程（SeDebugPrivilege + 多种终止方法）
    println!("[R3Monitor] 调用 AVModel 终止 PID={}", pid);
    crate::diag_info!("[R3Monitor] 调用 AVModel 终止 PID={}", pid);
    if crate::kill_process_via_avmodel(pid) {
        println!("[R3Monitor] AVModel 成功终止 PID={}", pid);
        return true;
    }

    // AVModel 按 PID 失败：尝试按进程名查找（处理安装程序释放同名 .tmp 子进程的场景）
    if let Some(name) = process_name {
        let file_name = std::path::Path::new(name)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(name);
        println!("[R3Monitor] AVModel PID 失败，尝试按名称查找: {}", file_name);
        crate::diag_info!("[R3Monitor] AVModel PID 失败，尝试按名称查找: {}", file_name);

        if let Some(resp) = crate::kill_process_by_name_via_avmodel(file_name) {
            if resp.ok {
                let killed_count = resp.killed.as_ref().map(|k| k.len()).unwrap_or(0);
                println!("[R3Monitor] AVModel 按名称终止成功，杀掉了 {} 个进程", killed_count);
                crate::diag_info!("[R3Monitor] AVModel 按名称终止成功，杀掉了 {} 个进程", killed_count);
                return true;
            }
            println!("[R3Monitor] AVModel 按名称终止失败: {}", resp.msg);
        }
    }

    // AVModel 完全失败 → 驱动后备（内核态终止，不受完整性级别限制）
    // 历史 bug：安装包释放的安装子进程常以高完整性运行（requireAdministrator），
    // R3 层（AVModel/taskkill）会因 UIPI 完整性检查拒绝访问（0x80070005），
    // 只有内核驱动能无条件终止。taskkill 降为最后兜底。
    #[cfg(not(feature = "ms_store"))]
    {
        println!("[R3Monitor] AVModel 完全失败，使用驱动后备终止 PID={}", pid);
        crate::diag_info!("[R3Monitor] AVModel 完全失败，使用驱动后备终止 PID={}", pid);
        if crate::kill_process_via_driver_internal(pid).is_ok() {
            // 短暂等待后检查进程是否已退出
            std::thread::sleep(std::time::Duration::from_millis(300));
            if !is_process_alive(pid) {
                println!("[R3Monitor] 驱动后备成功终止 PID={}", pid);
                return true;
            }
            println!("[R3Monitor] 驱动后备已发送 KILL_PROCESS，但进程仍存活 PID={}", pid);
        } else {
            println!("[R3Monitor] 驱动后备不可用（驱动未运行），继续 taskkill");
        }
    }

    // taskkill 后备（最后兜底）
    println!("[R3Monitor] 使用 taskkill 后备 PID={}", pid);
    crate::diag_info!("[R3Monitor] 使用 taskkill 后备 PID={}", pid);
    let _ = std::process::Command::new("taskkill")
        .args(["/F", "/T", "/PID", &pid.to_string()])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    println!("[R3Monitor] taskkill /T /F PID={}", pid);

    // 短暂等待后检查进程是否仍存活
    std::thread::sleep(std::time::Duration::from_millis(200));
    !is_process_alive(pid)
}

#[cfg(windows)]
pub fn check_and_intercept_process(
    path: &str,
    pid: u32,
    app_handle: &tauri::AppHandle,
) -> bool {
    // ★沙箱对 AVIC 黑名单不采取任何操作★
    // AVIC 黑名单拦截由基础防护（WMI watcher）和驱动防护负责，
    // 沙箱模块不终止进程、不弹窗。这里在 should_intercept_for_sandbox
    // 内已处理（AVIC 命中 → 返回 false，不触发沙箱分析）。

    // 调用统一的检查逻辑
    if !should_intercept_for_sandbox(path, pid) {
        return false;
    }

    // 需要沙箱拦截 → 终止进程（AVModel 优先，taskkill 后备）
    terminate_process_via_avmodel_first(pid, Some(path));

    // 设置 pending file
    set_pending_file(path);

    // ★异步触发沙箱分析，不阻塞 R3 监控线程★
    // 历史 bug：直接同步调用 handle_sandbox_analysis 导致 R3 监控线程
    // 被阻塞长达 60 秒（沙箱分析超时），期间无法处理新进程事件——
    // 包括拦截窗口的显示，导致程序卡死。
    // 参考 lib.rs 中驱动通知处理器的做法，用 std::thread::spawn 异步执行。
    let app = app_handle.clone();
    let file_path = path.to_string();
    std::thread::spawn(move || {
        crate::handle_sandbox_analysis(&app, &file_path);
    });
    true // 已拦截
}

#[cfg(not(windows))]
pub fn should_intercept_for_sandbox(_path: &str, _pid: u32) -> bool {
    false
}

#[cfg(not(windows))]
pub fn check_and_intercept_process(
    _path: &str,
    _pid: u32,
    _app_handle: &tauri::AppHandle,
) -> bool {
    false
}

/// 获取需要监控的目录（桌面、下载）
#[cfg(windows)]
fn get_watched_directories() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Some(userprofile) = std::env::var_os("USERPROFILE") {
        let user_dir = PathBuf::from(&userprofile);

        // 桌面目录
        let desktop_path = user_dir.join("Desktop");
        if desktop_path.exists() {
            dirs.push(desktop_path);
        }

        // 下载目录
        let downloads_path = user_dir.join("Downloads");
        if downloads_path.exists() {
            dirs.push(downloads_path);
        }
    }

    // 全部 canonicalize，确保格式一致
    dirs.into_iter()
        .filter_map(|d| std::fs::canonicalize(&d).ok().or(Some(d)))
        .collect()
}

#[cfg(not(windows))]
fn get_watched_directories() -> Vec<PathBuf> {
    Vec::new()
}

/// 规范化文件路径（去除 \??\ 和 \\?\ 前缀，统一为普通路径）
fn normalize_path(file_path: &str) -> String {
    let path = file_path.trim_start_matches("\\??\\");
    let path = path.trim_start_matches("\\\\?\\");
    path.to_string()
}

/// 检查文件路径是否在监控目录下（支持子目录）
fn is_path_in_watched_dirs(file_path: &str, dirs: &[PathBuf]) -> bool {
    let normalized = normalize_path(file_path);
    let path = match std::fs::canonicalize(&normalized) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[R3Monitor] canonicalize 失败: {} -> {} err={}", file_path, normalized, e);
            PathBuf::from(&normalized)
        }
    };

    let path_lower = path.to_string_lossy().to_lowercase();

    for dir in dirs {
        let dir_lower = dir.to_string_lossy().to_lowercase();
        if path_lower.starts_with(&dir_lower) {
            return true;
        }
    }
    false
}

/// 检查是否是自身进程或需要排除的进程
fn is_self_or_excluded_process(file_path: &str) -> bool {
    let lower = file_path.to_lowercase();
    // 排除自身
    if lower.contains("xiguasecurity") {
        return true;
    }
    // 排除 Sandboxie 相关进程
    if lower.contains("sandboxie") || lower.contains("start.exe") {
        return true;
    }
    // 排除系统目录下的进程
    if lower.starts_with("c:\\windows\\") {
        return true;
    }
    // 排除临时目录中的触发文件
    if lower.contains("xiguasandbox") {
        return true;
    }
    false
}

/// 判断文件是否为可执行文件
fn is_executable(file_path: &str) -> bool {
    let ext = Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    matches!(ext.to_lowercase().as_str(), "exe" | "msi" | "bat" | "cmd" | "ps1" | "scr" | "com")
}

/// 使用原生 WinVerifyTrust API 验证文件数字签名（毫秒级，无需启动 PowerShell）
/// 返回 true 表示签名有效，false 表示未签名或签名无效
///
/// 性能对比：
/// - PowerShell Get-AuthenticodeSignature: 500ms-2s（需启动 powershell.exe 进程）
/// - WinVerifyTrust 原生 API: 1-10ms（直接调用 wintrust.dll）
///
/// 直接复用项目已有的 `signature_verifier` 模块，避免重复实现。
fn verify_signature_via_powershell(file_path: &str) -> bool {
    let info = crate::signature_verifier::verify_file_signature(file_path);
    let is_valid = info.status.is_trusted();
    if is_valid {
        println!("[SignatureCheck] {} -> Valid (WinVerifyTrust)", file_path);
    } else {
        println!("[SignatureCheck] {} -> {:?} (WinVerifyTrust)", file_path, info.status);
    }
    is_valid
}

/// 启动 R3 进程监控线程
/// 监控桌面和下载目录中启动的未签名可执行文件
#[cfg(windows)]
pub fn start_r3_process_monitor(app_handle: &tauri::AppHandle) {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::Foundation::CloseHandle;

    if R3_MONITOR_RUNNING.swap(true, Ordering::SeqCst) {
        println!("[R3Monitor] Already running");
        return;
    }

    let app = app_handle.clone();
    std::thread::spawn(move || {
        println!("[R3Monitor] Started, monitoring desktop/downloads for unsigned executables");

        let watched_dirs = get_watched_directories();
        for d in &watched_dirs {
            println!("[R3Monitor] 监控目录: {} (canonicalize={})", d.display(), d.to_string_lossy());
        }

        let mut seen_pids: std::collections::HashSet<u32> = std::collections::HashSet::new();

        while R3_MONITOR_RUNNING.load(Ordering::SeqCst)
            && SANDBOX_ANALYSIS_ENABLED.load(Ordering::SeqCst)
        {
            std::thread::sleep(Duration::from_millis(500));

            // 如果正在分析中，跳过检测
            if SANDBOX_ANALYZING.load(Ordering::SeqCst) {
                continue;
            }

            // ★全局冷却期★：分析完成后的冷却期内不检测任何新进程，
            // 防止"分析→重新启动→再分析"死循环
            if is_in_analysis_cooldown() {
                continue;
            }

            unsafe {
                let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                let mut entry: PROCESSENTRY32W = std::mem::zeroed();
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

                if Process32FirstW(snapshot, &mut entry).is_err() {
                    let _ = CloseHandle(snapshot);
                    continue;
                }

                loop {
                    let pid = entry.th32ProcessID;

                    // 跳过已处理的 PID
                    if !seen_pids.contains(&pid) {
                        seen_pids.insert(pid);

                        // 获取进程完整路径
                        if let Some(ref path) = get_process_full_path(pid) {
                            let normalized = normalize_path(path);
                            let is_exe = is_executable(path);
                            let is_excluded = is_self_or_excluded_process(path);
                            let in_watched = is_path_in_watched_dirs(path, &watched_dirs);

                            // 调试：打印所有新检测到的 exe 进程
                            if is_exe {
                                println!("[R3Monitor] 新进程 PID={} path={} exe={} excluded={} in_watched={}",
                                    pid, normalized, is_exe, is_excluded, in_watched);
                            }

                            // ★白名单检查（最先执行——唯一不耗时的检查）★
                            if is_image_whitelisted(path) {
                                println!("[R3Monitor] File in sandbox whitelist, auto-allow: {}", path);
                                crate::diag_info!("[R3Monitor] 文件在白名单中，放行: {}", path);
                                if Process32NextW(snapshot, &mut entry).is_err() {
                                    break;
                                }
                                continue;
                            }

                            // ★最近放行检查（Benign 判定后重新启动的进程）★
                            // 防"分析完成立即再次分析"：重新启动的原始文件进程在 TTL 内放行
                            if is_recently_launched(pid) {
                                println!("[R3Monitor] 最近放行进程 PID={}，跳过: {}", pid, path);
                                if Process32NextW(snapshot, &mut entry).is_err() {
                                    break;
                                }
                                continue;
                            }

                            // ★路径级放行检查★：最近分析完成的原始文件路径，同路径进程（含子进程）放行
                            if is_recently_analyzed_path(path) {
                                println!("[R3Monitor] 最近分析完成路径，跳过: {} (PID={})", path, pid);
                                if Process32NextW(snapshot, &mut entry).is_err() {
                                    break;
                                }
                                continue;
                            }

                            // 排除自身和系统进程
                            if is_excluded {
                                if Process32NextW(snapshot, &mut entry).is_err() {
                                    break;
                                }
                                continue;
                            }

                            // 检查是否是可执行文件
                            if !is_exe {
                                if Process32NextW(snapshot, &mut entry).is_err() {
                                    break;
                                }
                                continue;
                            }

                            // 检查是否在监控目录下
                            if !in_watched {
                                if Process32NextW(snapshot, &mut entry).is_err() {
                                    break;
                                }
                                continue;
                            }

                            println!("[R3Monitor] 监控目录中的可执行文件: {} (PID={})", normalized, pid);
                            crate::diag_info!("[R3Monitor] 监控目录中的可执行文件: {} (PID={})", normalized, pid);

                            // 验证数字签名（最耗时的检查，放最后）
                            let has_valid_sig = verify_signature_via_powershell(path);
                            if has_valid_sig {
                                println!("[R3Monitor] 文件有有效签名，放行: {}", path);
                                crate::diag_info!("[R3Monitor] 文件有有效签名，放行: {}", path);
                            } else {
                                println!("[R3Monitor] 文件无有效签名，触发沙箱分析: {}", path);
                                crate::diag_info!("[R3Monitor] 文件无有效签名，触发沙箱分析: {}", path);

                                // 终止进程：AVModel 优先（多种方法），taskkill 后备
                                terminate_process_via_avmodel_first(pid, Some(path));

                                // 设置 pending file 并异步触发分析（不阻塞 R3 监控线程）
                                set_pending_file(path);
                                let app_clone = app.clone();
                                let file_path = path.to_string();
                                std::thread::spawn(move || {
                                    crate::handle_sandbox_analysis(&app_clone, &file_path);
                                });
                                break;
                            }
                        }
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }

                let _ = CloseHandle(snapshot);
            }

            // 定期清理已退出的 PID，避免 seen_pids 无限增长
            if seen_pids.len() > 200 {
                seen_pids.clear();
            }
        }

        R3_MONITOR_RUNNING.store(false, Ordering::SeqCst);
        println!("[R3Monitor] Stopped");
    });
}

#[cfg(not(windows))]
pub fn start_r3_process_monitor(_app_handle: &tauri::AppHandle) {}

/// 停止 R3 进程监控
pub fn stop_r3_process_monitor() {
    R3_MONITOR_RUNNING.store(false, Ordering::SeqCst);
}

/// 通过 PID 获取进程完整路径
#[cfg(windows)]
fn get_process_full_path(pid: u32) -> Option<String> {
    use windows::Win32::System::Threading::OpenProcess;
    use windows::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
    use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
    use windows::Win32::Foundation::CloseHandle;

    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
            Ok(h) => h,
            Err(e) => {
                // 权限不足是正常的（系统进程），只在非系统 PID 时打印
                if pid > 100 {
                    eprintln!("[R3Monitor] OpenProcess failed PID={}: {}", pid, e);
                }
                return None;
            }
        };

        let mut path_buf = [0u16; 520];
        let len = GetModuleFileNameExW(handle, None, &mut path_buf);
        let _ = CloseHandle(handle);

        if len > 0 {
            let path = String::from_utf16_lossy(&path_buf[..len as usize])
                .trim_end_matches('\0')
                .to_string();
            let clean = path.strip_prefix("\\??\\").unwrap_or(&path).to_string();
            Some(clean)
        } else {
            eprintln!("[R3Monitor] GetModuleFileNameExW returned 0 for PID={}", pid);
            None
        }
    }
}

#[cfg(not(windows))]
fn get_process_full_path(_pid: u32) -> Option<String> {
    None
}
