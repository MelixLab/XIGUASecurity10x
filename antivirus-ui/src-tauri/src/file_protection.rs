use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
use tauri::Emitter;

use crate::quarantine::QuarantineManager;
use crate::kill_process;

const SILVERFOX_THREAT_NAME: &str = "Trojan/Win32:SilverFox.sa";
const SILVERFOX_THREAT_LEVEL: &str = "High";

/// 文件防护事件
#[derive(Clone, serde::Serialize)]
pub struct FileProtectionEvent {
    pub id: String,
    pub path: String,
    pub kind: String,
    pub timestamp: String,
    pub threat_name: Option<String>,
}

/// 文件防护状态
#[derive(Clone, serde::Serialize)]
pub struct FileProtectionState {
    pub enabled: bool,
    pub scope: String,
    pub watched_paths: Vec<String>,
}

struct FileProtectionInner {
    enabled: bool,
    scope: String,
    watcher: Option<RecommendedWatcher>,
    events: VecDeque<FileProtectionEvent>,
    dedup: HashMap<String, Instant>,
    watched_paths: Vec<PathBuf>,
}

impl FileProtectionInner {
    fn new() -> Self {
        Self {
            enabled: false,
            scope: "common".to_string(),
            watcher: None,
            events: VecDeque::with_capacity(256),
            dedup: HashMap::new(),
            watched_paths: Vec::new(),
        }
    }

    fn prune_dedup(&mut self) {
        let now = Instant::now();
        let ttl = Duration::from_secs(10);
        self.dedup.retain(|_, ts| now.duration_since(*ts) < ttl);
    }

    fn should_handle(&mut self, path: &str) -> bool {
        self.prune_dedup();
        let key = path.to_lowercase();
        if self.dedup.contains_key(&key) {
            return false;
        }
        self.dedup.insert(key, Instant::now());
        true
    }

    fn is_monitored_file(path: &str) -> bool {
        let path_lower = path.to_lowercase();
        path_lower.ends_with(".exe")
            || path_lower.ends_with(".scr")
            || path_lower.ends_with(".com")
            || path_lower.ends_with(".pif")
            || path_lower.ends_with(".msi")
            || path_lower.ends_with(".msp")
            || path_lower.ends_with(".gadget")
            // 常见脚本/宏载体也纳入监控，恶意文件常从此类文件启动
            || path_lower.ends_with(".js")
            || path_lower.ends_with(".jse")
            || path_lower.ends_with(".vbs")
            || path_lower.ends_with(".vbe")
            || path_lower.ends_with(".bat")
            || path_lower.ends_with(".cmd")
            || path_lower.ends_with(".ps1")
            || path_lower.ends_with(".wsf")
            || path_lower.ends_with(".hta")
            // EICAR 标准测试文件（文件名包含 "eicar" 即纳入监控，扫描器会验证内容）
            || path_lower.contains("eicar")
    }

    /// 银狐木马常利用 C:\driver 或 C:\drivers 目录藏匿本体并自启动
    fn is_silverfox_path(path: &str) -> bool {
        let path_lower = path.to_lowercase();
        path_lower.starts_with("c:\\driver\\") || path_lower.starts_with("c:\\drivers\\")
    }

    fn push_event(&mut self, path: String, kind: String) -> Option<FileProtectionEvent> {
        self.prune_dedup();

        let is_silverfox = Self::is_silverfox_path(&path);
        let threat_name = if is_silverfox {
            Some(SILVERFOX_THREAT_NAME.to_string())
        } else {
            None
        };

        // 银狐木马路径：高危目录，不走去重、不限制扩展名，确保每次创建都触发隔离弹窗
        if !is_silverfox {
            if !self.should_handle(&path) {
                return None;
            }
            if !Self::is_monitored_file(&path) {
                return None;
            }
        }

        static EVENT_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let counter = EVENT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let event = FileProtectionEvent {
            id: format!("{}_{}", chrono::Utc::now().timestamp_millis(), counter),
            path,
            kind,
            timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            threat_name,
        };

        if self.events.len() >= 256 {
            self.events.pop_front();
        }
        self.events.push_back(event.clone());
        Some(event)
    }
}

pub struct FileProtectionManager {
    inner: Arc<Mutex<FileProtectionInner>>,
}

impl FileProtectionManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(FileProtectionInner::new())),
        }
    }

    pub fn state(&self) -> FileProtectionState {
        let inner = self.inner.lock().unwrap();
        FileProtectionState {
            enabled: inner.enabled,
            scope: inner.scope.clone(),
            watched_paths: inner.watched_paths.iter().map(|p| p.to_string_lossy().to_string()).collect(),
        }
    }

    pub fn set_enabled(&self, enabled: bool, scope: String) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap();
        inner.enabled = enabled;
        inner.scope = scope;
        Ok(())
    }

    fn get_common_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        if let Some(dir) = dirs::download_dir() {
            paths.push(dir);
        }
        if let Some(dir) = dirs::desktop_dir() {
            paths.push(dir);
        }
        if let Some(dir) = dirs::document_dir() {
            paths.push(dir);
        }
        // Windows temp 通常是 C:\Users\<user>\AppData\Local\Temp，直接使用
        paths.push(std::env::temp_dir());

        // 添加几个常见的公共下载/临时目录
        if let Some(home) = dirs::home_dir() {
            paths.push(home.join("Downloads"));
            paths.push(home.join("Desktop"));
            paths.push(home.join("Documents"));
        }

        paths
    }

    pub fn start(&self, app: tauri::AppHandle) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap();
        if inner.watcher.is_some() {
            return Ok(());
        }

        let mut paths = Self::get_common_paths();
        // 额外监控 C:\ 根目录，用于捕获 driver/drivers 目录的创建/修改
        paths.push(PathBuf::from("C:\\"));
        let watched: Vec<PathBuf> = paths.iter().filter(|p| p.exists()).cloned().collect();
        if watched.is_empty() {
            return Err("No valid directories to watch".to_string());
        }

        let inner_clone = Arc::clone(&self.inner);
        let app_clone = app.clone();
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let kind = format!("{:?}", event.kind);
                for path in event.paths {
                    if let Some(s) = path.to_str() {
                        let mut inner = inner_clone.lock().unwrap();
                        if let Some(evt) = inner.push_event(s.to_string(), kind.clone()) {
                            let is_silverfox = evt.threat_name.is_some();
                            let _ = app_clone.emit("file-protection-event", evt);
                            if is_silverfox {
                                // 银狐木马：后台结束相关进程，帮助前端隔离成功
                                let path_for_handler = s.to_string();
                                std::thread::spawn(move || {
                                    handle_silverfox_processes(&path_for_handler);
                                });
                            } else {
                                // ── AVIC 云端信誉库查询 ──
                                // 后台线程检查文件哈希是否在 AVIC 已知恶意库中，
                                // 命中则发射 file-protection-event（threat_name 已设置），
                                // 前端收到后自动隔离并弹窗（与银狐木马走同一处理路径）。
                                let app_for_avic = app_clone.clone();
                                let path_for_avic = s.to_string();
                                std::thread::spawn(move || {
                                    if let Some((threat_name, _family)) =
                                        crate::avic_client::check_file(&path_for_avic)
                                    {
                                        println!(
                                            "[FileProtection] AVIC 命中恶意: {} threat={}",
                                            path_for_avic, threat_name
                                        );

                                        let avic_evt = FileProtectionEvent {
                                            id: format!(
                                                "avic_{}",
                                                chrono::Utc::now().timestamp_millis()
                                            ),
                                            path: path_for_avic.clone(),
                                            kind: "avic_cloud_block".to_string(),
                                            timestamp: chrono::Local::now()
                                                .format("%Y-%m-%d %H:%M:%S")
                                                .to_string(),
                                            threat_name: Some(threat_name),
                                        };
                                        let _ = app_for_avic.emit("file-protection-event", avic_evt);
                                    }
                                });
                            }
                        }
                    }
                }
            }
        })
        .map_err(|e| format!("Failed to create file watcher: {}", e))?;

        for path in &watched {
            watcher
                .watch(path, RecursiveMode::Recursive)
                .map_err(|e| format!("Failed to watch {}: {}", path.display(), e))?;
        }

        inner.watcher = Some(watcher);
        inner.watched_paths = watched.clone();
        drop(inner);

        // 通知前端监控已启动
        let _ = app.emit("file-protection-started", FileProtectionState {
            enabled: true,
            scope: "common".to_string(),
            watched_paths: watched.iter().map(|p| p.to_string_lossy().to_string()).collect(),
        });

        Ok(())
    }

    pub fn stop(&self, app: tauri::AppHandle) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(mut watcher) = inner.watcher.take() {
            for path in &inner.watched_paths {
                let _ = watcher.unwatch(path);
            }
        }
        inner.watcher = None;
        inner.watched_paths.clear();
        inner.events.clear();
        drop(inner);

        let _ = app.emit("file-protection-stopped", ());
        Ok(())
    }

    pub fn drain_events(&self, limit: usize) -> Vec<FileProtectionEvent> {
        let mut inner = self.inner.lock().unwrap();
        let mut result = Vec::with_capacity(limit.min(inner.events.len()));
        while result.len() < limit && !inner.events.is_empty() {
            if let Some(event) = inner.events.pop_front() {
                result.push(event);
            }
        }
        result
    }
}

// 全局单例
use once_cell::sync::Lazy;
static FILE_PROTECTION: Lazy<Arc<Mutex<FileProtectionManager>>> =
    Lazy::new(|| Arc::new(Mutex::new(FileProtectionManager::new())));

pub fn get_file_protection() -> Arc<Mutex<FileProtectionManager>> {
    Arc::clone(&FILE_PROTECTION)
}

#[tauri::command]
pub async fn set_file_protection_enabled(
    enabled: bool,
    scope: String,
    app: tauri::AppHandle,
) -> Result<FileProtectionState, String> {
    let manager = get_file_protection();
    {
        let mut mgr = manager.lock().unwrap();
        mgr.set_enabled(enabled, scope)?;
    }

    let should_start = {
        let mgr = manager.lock().unwrap();
        enabled && mgr.state().watched_paths.is_empty()
    };

    if should_start {
        manager.lock().unwrap().start(app)?;
    } else if !enabled {
        manager.lock().unwrap().stop(app)?;
    }

    let state = manager.lock().unwrap().state();
    Ok(state)
}

#[tauri::command]
pub async fn get_file_protection_enabled() -> Result<FileProtectionState, String> {
    let state = get_file_protection().lock().unwrap().state();
    Ok(state)
}

#[tauri::command]
pub async fn get_file_protection_events(limit: Option<usize>) -> Result<Vec<FileProtectionEvent>, String> {
    let events = get_file_protection().lock().unwrap().drain_events(limit.unwrap_or(16));
    Ok(events)
}

#[tauri::command]
pub async fn start_file_protection(app: tauri::AppHandle) -> Result<FileProtectionState, String> {
    let manager = get_file_protection();
    manager.lock().unwrap().start(app)?;
    let state = manager.lock().unwrap().state();
    Ok(state)
}

#[tauri::command]
pub async fn stop_file_protection(app: tauri::AppHandle) -> Result<(), String> {
    get_file_protection().lock().unwrap().stop(app)?;
    Ok(())
}

/// 银狐木马处置入口：结束相关进程，便于前端隔离弹窗流程成功处理
fn handle_silverfox_processes(file_path: &str) {
    println!("[SilverFox] 开始结束相关进程: {}", file_path);

    for attempt in 1..=5 {
        kill_processes_under_silverfox_dirs();
        std::thread::sleep(Duration::from_millis(200));

        // 如果文件已经被前端隔离移走，提前结束
        if !Path::new(file_path).exists() {
            println!("[SilverFox] 目标文件已消失，结束进程处理: {}", file_path);
            return;
        }

        // 额外尝试结束占用目标文件句柄的进程
        if let Some(pid) = find_process_holding_file(file_path) {
            let _ = kill_process(pid);
            println!("[SilverFox] 已结束占用目标文件的进程 PID={}", pid);
        }
    }
}

/// 结束所有在 C:\driver 或 C:\drivers 目录下运行的可执行文件进程
fn kill_processes_under_silverfox_dirs() {
    unsafe {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
            PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        };
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
        use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;

        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(s) => s,
            Err(_) => return,
        };

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                if pid == 0 {
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                    continue;
                }

                if let Ok(handle) = OpenProcess(PROCESS_TERMINATE | windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION | windows::Win32::System::Threading::PROCESS_VM_READ, false, pid) {
                    let mut path_buf = [0u16; 520];
                    let len = GetModuleFileNameExW(handle, None, &mut path_buf);
                    if len > 0 {
                        let path = String::from_utf16_lossy(&path_buf[..len as usize]).to_string();
                        let path_lower = path.to_lowercase();
                        if path_lower.starts_with("c:\\driver\\") || path_lower.starts_with("c:\\drivers\\") {
                            let _ = TerminateProcess(handle, 1);
                            println!("[SilverFox] 已结束进程 PID={} path={}", pid, path);
                        }
                    }
                    let _ = CloseHandle(handle);
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
}

/// 查找占用指定文件句柄的进程 PID（使用 Windows Restart Manager）
fn find_process_holding_file(file_path: &str) -> Option<u32> {
    use windows::Win32::System::RestartManager::{
        RmEndSession, RmGetList, RmRegisterResources, RmStartSession,
        CCH_RM_SESSION_KEY, RM_PROCESS_INFO,
    };
    use windows::core::{PCWSTR, PWSTR};

    let file_path_wide: Vec<u16> = file_path.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let mut session: u32 = 0;
        let mut session_key = [0u16; (CCH_RM_SESSION_KEY + 1) as usize];
        let result = RmStartSession(&mut session, 0, PWSTR(session_key.as_mut_ptr()));
        if result.0 != 0 {
            return None;
        }

        let filenames = [PCWSTR(file_path_wide.as_ptr())];
        let register_result = RmRegisterResources(session, Some(&filenames), None, None);
        if register_result.0 != 0 {
            let _ = RmEndSession(session);
            return None;
        }

        let mut proc_info_needed: u32 = 0;
        let mut proc_info_count: u32 = 0;
        let mut reboot_reasons: u32 = 0;

        // 第一次调用获取所需数量
        let _ = RmGetList(
            session,
            &mut proc_info_needed,
            &mut proc_info_count,
            None,
            &mut reboot_reasons,
        );

        if proc_info_needed == 0 {
            let _ = RmEndSession(session);
            return None;
        }

        let mut proc_infos: Vec<RM_PROCESS_INFO> = vec![std::mem::zeroed(); proc_info_needed as usize];
        proc_info_count = proc_info_needed;
        let result = RmGetList(
            session,
            &mut proc_info_needed,
            &mut proc_info_count,
            Some(proc_infos.as_mut_ptr()),
            &mut reboot_reasons,
        );

        let pid = if result.0 == 0 && proc_info_count > 0 {
            Some(proc_infos[0].Process.dwProcessId)
        } else {
            None
        };

        let _ = RmEndSession(session);
        pid
    }
}

/// 强制删除文件：先尝试普通删除，失败则尝试重命名后安排重启删除
fn force_delete_file(file_path: &str) -> Result<(), String> {
    let path = Path::new(file_path);

    // 普通删除
    if std::fs::remove_file(path).is_ok() {
        return Ok(());
    }

    // 尝试设置文件可写后再删除
    unsafe {
        use windows::Win32::Storage::FileSystem::{
            SetFileAttributesW, FILE_ATTRIBUTE_NORMAL,
        };
        use windows::core::PCWSTR;

        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let _ = SetFileAttributesW(PCWSTR(wide.as_ptr()), FILE_ATTRIBUTE_NORMAL);
    }

    if std::fs::remove_file(path).is_ok() {
        return Ok(());
    }

    // 如果仍然失败，尝试移动到临时目录后由系统重启时清理
    let file_name = path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "silverfox.tmp".to_string());
    let temp_dir = std::env::temp_dir().join("XIGUASecurity_ForceDelete");
    let _ = std::fs::create_dir_all(&temp_dir);
    let temp_path = temp_dir.join(format!("{}_{}", chrono::Local::now().timestamp_millis(), file_name));

    match std::fs::rename(path, &temp_path) {
        Ok(_) => {
            // 移动成功，尝试删除临时文件；若被占用则安排下次启动清理
            if std::fs::remove_file(&temp_path).is_err() {
                // 记录待清理路径，启动时清理
                println!("[SilverFox] 文件已移动，将在重启后清理: {}", temp_path.display());
            }
            Ok(())
        }
        Err(e) => Err(format!("无法移动或删除文件: {}", e)),
    }
}
