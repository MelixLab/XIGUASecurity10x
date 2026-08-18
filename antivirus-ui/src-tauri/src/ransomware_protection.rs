use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use tauri::{Emitter, Manager};

/// 文档类型后缀（重点关注勒索软件常修改的文档、图片、短视频）
const DOC_EXTENSIONS: &[&str] = &[
    // Office 文档
    ".doc", ".docx", ".docm",
    ".ppt", ".pptx", ".pptm",
    ".xls", ".xlsx", ".xlsm",
    ".pdf", ".txt",
    // 图片
    ".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp",
    // 短视频
    ".mp4", ".mov", ".avi", ".mkv", ".wmv",
];

/// 单条修改记录
#[derive(Clone, serde::Serialize)]
pub struct RansomwareEvent {
    pub id: String,
    pub path: String,
    pub process_name: String,
    pub timestamp: String,
    pub backed_up: bool,
}

/// 检测状态
#[derive(Clone, serde::Serialize)]
pub struct RansomwareDetection {
    pub detected: bool,
    pub process_name: String,
    pub event_count: usize,
    pub time_window_secs: u64,
    pub affected_files: Vec<RansomwareEvent>,
    pub timestamp: String,
}

/// 回滚结果（包含失败原因，便于前端展示）
#[derive(Clone, serde::Serialize)]
pub struct RollbackResult {
    pub path: String,
    pub success: bool,
    pub message: String,
}

/// 备份进度/估算信息
#[derive(Clone, serde::Serialize)]
pub struct BackupProgress {
    /// 已扫描文件数
    pub scanned: usize,
    /// 总文件数
    pub total: usize,
    /// 已备份文件数
    pub backed_up: usize,
    /// 总大小（字节）
    pub total_size_bytes: u64,
    /// 当前正在处理的文件（路径或描述）
    pub current_file: String,
    /// 是否只是估算阶段
    pub estimated: bool,
    /// 是否已完成
    pub completed: bool,
}

#[derive(Clone, serde::Serialize)]
pub struct RansomwareProtectionState {
    pub enabled: bool,
    pub watched_paths: Vec<String>,
    pub backup_dir: String,
    pub total_backed_up: usize,
}

struct RansomwareProtectionInner {
    enabled: bool,
    watcher: Option<RecommendedWatcher>,
    watched_paths: Vec<PathBuf>,
    backup_dir: PathBuf,
    /// 最近一段时间的修改事件，按进程名分组
    events: VecDeque<(Instant, String, PathBuf)>,
    /// 事件 ID 计数器
    event_counter: u64,
    /// 已检测到的攻击进程（冷却期，防止同一攻击反复弹窗）
    detected_processes: HashMap<String, Instant>,
    /// 达到阈值但仍在观察是否稳定的进程 -> 最后一次事件时间
    pending_detections: HashMap<String, Instant>,
    /// 每个原文件的最新几个备份版本（包含修改后的版本）
    backup_map: HashMap<String, Vec<PathBuf>>,
    /// 每个原文件的初始备份版本（首次开启时备份的“最后已知良好”版本）
    initial_backup_map: HashMap<String, PathBuf>,
    /// 检测阈值：时间窗口（秒）内超过该数量的修改即触发
    window_secs: u64,
    threshold: usize,
    /// 稳定期：连续多少秒无新事件才判定为一次完整攻击
    stabilization_secs: u64,
    /// 检测冷却期：一次检测后多少秒内不再为同一进程触发
    cooldown_secs: u64,
    /// 用于后台稳定期检测线程的停止标志
    stop_flag: Arc<AtomicBool>,
    /// 上一次稳定期检测线程句柄（用于 stop 时等待）
    detection_thread: Option<std::thread::JoinHandle<()>>,
    /// 用于发送事件通知
    app_handle: Option<tauri::AppHandle>,
    /// 初始备份是否正在进行，期间忽略事件避免竞争
    initial_backup_running: bool,
}

impl RansomwareProtectionInner {
    fn new() -> Self {
        let mut inner = Self {
            enabled: false,
            watcher: None,
            watched_paths: Vec::new(),
            backup_dir: Self::default_backup_dir(),
            events: VecDeque::new(),
            event_counter: 0,
            detected_processes: HashMap::new(),
            pending_detections: HashMap::new(),
            backup_map: HashMap::new(),
            initial_backup_map: HashMap::new(),
            window_secs: 10,
            threshold: 15,
            stabilization_secs: 2,
            cooldown_secs: 30,
            stop_flag: Arc::new(AtomicBool::new(false)),
            detection_thread: None,
            app_handle: None,
            initial_backup_running: false,
        };
        inner.load_backup_index();
        inner
    }

    fn default_backup_dir() -> PathBuf {
        let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().to_string());
        PathBuf::from(local_app_data).join("XIGUASecurity").join("RansomwareBackup")
    }

    fn backup_index_path(&self) -> PathBuf {
        self.backup_dir.join("backup_index.json")
    }

    fn load_backup_index(&mut self) {
        let path = self.backup_index_path();
        if !path.exists() {
            return;
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                if let Ok(index) = serde_json::from_str::<HashMap<String, PathBuf>>(&content) {
                    // 启动时清理已不存在原文件的旧记录，避免删除同名文件后重新创建时误报
                    let mut pruned = 0;
                    for (original_str, backup_path) in index {
                        if Path::new(&original_str).exists() {
                            self.initial_backup_map.insert(original_str, backup_path);
                        } else {
                            let _ = std::fs::remove_file(&backup_path);
                            pruned += 1;
                        }
                    }
                    if pruned > 0 {
                        self.save_backup_index();
                    }
                    println!("[RansomwareProtection] Loaded {} initial backup entries from index, pruned {}", self.initial_backup_map.len(), pruned);
                }
            }
            Err(e) => {
                println!("[RansomwareProtection] Failed to load backup index: {}", e);
            }
        }
    }

    // 从备份记录中移除指定原文件，并删除对应的备份文件
    fn remove_backup_record(&mut self, original_str: &str) {
        let mut removed_any = false;
        if let Some(backup_path) = self.initial_backup_map.remove(original_str) {
            let _ = std::fs::remove_file(&backup_path);
            removed_any = true;
        }
        if let Some(versions) = self.backup_map.remove(original_str) {
            for v in versions {
                let _ = std::fs::remove_file(&v);
            }
            removed_any = true;
        }
        if removed_any {
            self.save_backup_index();
        }
    }

    fn save_backup_index(&self) {
        let path = self.backup_index_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_string_pretty(&self.initial_backup_map) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    println!("[RansomwareProtection] Failed to save backup index: {}", e);
                }
            }
            Err(e) => {
                println!("[RansomwareProtection] Failed to serialize backup index: {}", e);
            }
        }
    }

    fn is_document(path: &Path) -> bool {
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        if ext.is_empty() {
            return false;
        }
        DOC_EXTENSIONS.iter().any(|e| e.trim_start_matches('.') == ext)
    }

    fn prune_events(&mut self) {
        let now = Instant::now();
        let window = Duration::from_secs(self.window_secs);
        while let Some((ts, _, _)) = self.events.front() {
            if now.duration_since(*ts) > window {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    fn backup_file(&mut self, original: &Path) -> Option<PathBuf> {
        if !original.exists() || !original.is_file() {
            return None;
        }
        let original_str = original.to_string_lossy().to_string();
        let relative = original_str.replace(':', "_").replace('\\', "/");
        let backup_path = self.backup_dir.join(&relative);
        let backup_dir = backup_path.parent()?;
        if let Err(e) = std::fs::create_dir_all(backup_dir) {
            println!("[RansomwareProtection] Failed to create backup dir: {}", e);
            return None;
        }
        // 保留最近 3 个修改版本
        let versioned = self.next_version_path(&backup_path);
        match std::fs::copy(original, &versioned) {
            Ok(_) => {
                println!("[RansomwareProtection] Backed up {} -> {}", original.display(), versioned.display());
                // 首次备份时同时保存为初始版本，用于后续回滚
                use std::collections::hash_map::Entry;
                let is_new_initial = matches!(self.initial_backup_map.entry(original_str.clone()), Entry::Vacant(_));
                self.initial_backup_map.entry(original_str.clone()).or_insert_with(|| versioned.clone());
                if is_new_initial {
                    self.save_backup_index();
                }
                let versions = self.backup_map.entry(original_str).or_insert_with(Vec::new);
                versions.push(versioned.clone());
                if versions.len() > 3 {
                    let _ = std::fs::remove_file(&versions[0]);
                    versions.remove(0);
                }
                Some(versioned)
            }
            Err(e) => {
                println!("[RansomwareProtection] Backup failed: {}", e);
                None
            }
        }
    }

    fn next_version_path(&self, base: &Path) -> PathBuf {
        let ts = chrono::Local::now().format("%Y%m%d_%H%M%S_%3f").to_string();
        if let Some(stem) = base.file_stem().and_then(|s| s.to_str()) {
            if let Some(ext) = base.extension().and_then(|e| e.to_str()) {
                base.with_file_name(format!("{}_{}.v.{}", stem, ts, ext))
            } else {
                base.with_file_name(format!("{}_{}", stem, ts))
            }
        } else {
            base.with_file_name(format!("backup_{}", ts))
        }
    }

    fn push_event(&mut self, path: PathBuf, process_name: String, _is_remove: bool) {
        let path_str = path.to_string_lossy().to_string();
        // 只统计已备份过的文件（现有文件）的修改/删除事件。
        // 新建文件不在备份映射中，直接忽略，避免大量创建文件时误报。
        let is_backed_up = self.initial_backup_map.contains_key(&path_str) || self.backup_map.contains_key(&path_str);
        if !is_backed_up {
            return;
        }

        self.prune_events();
        let now = Instant::now();
        self.events.push_back((now, process_name.clone(), path.clone()));

        self.event_counter += 1;

        // 检测：同一进程在短时间内修改/删除/重命名超过阈值
        let count = self.events.iter()
            .filter(|(_, proc, _)| proc == &process_name)
            .count();

        if count >= self.threshold {
            // 检查是否处于冷却期
            let in_cooldown = self.detected_processes.get(&process_name)
                .map(|t| now.duration_since(*t) < Duration::from_secs(self.cooldown_secs))
                .unwrap_or(false);
            if !in_cooldown {
                self.pending_detections.insert(process_name, now);
            }
        }
    }

    /// 检查是否有进程已达到稳定期。返回所有满足条件的检测事件。
    fn check_pending_detections(&mut self) -> Vec<RansomwareDetection> {
        let now = Instant::now();
        let mut ready = Vec::new();

        // 复制 pending 键值避免在迭代中修改
        let pending: Vec<(String, Instant)> = self.pending_detections.iter().map(|(k, v)| (k.clone(), *v)).collect();

        for (process_name, last_event) in pending {
            if now.duration_since(last_event) < Duration::from_secs(self.stabilization_secs) {
                continue; // 仍在活跃，继续等待
            }

            // 稳定期已到，汇总该进程在本次窗口内的所有事件
            let affected_events: Vec<(Instant, String, PathBuf)> = self.events
                .iter()
                .filter(|(_, proc, _)| proc == &process_name)
                .cloned()
                .collect();

            // 去重：同一文件多次修改只保留最新一次（或按路径去重）
            let mut seen_paths = HashMap::new();
            for (ts, proc, p) in affected_events.iter() {
                seen_paths.insert(p.to_string_lossy().to_string(), (*ts, proc.clone(), p.clone()));
            }
            let mut unique_events: Vec<(Instant, String, PathBuf)> = seen_paths.into_values().collect();
            // 按时间排序
            unique_events.sort_by(|a, b| a.0.cmp(&b.0));

            let count = unique_events.len();
            let affected: Vec<RansomwareEvent> = unique_events
                .into_iter()
                .map(|(_, _, p)| {
                    let p_str = p.to_string_lossy().to_string();
                    RansomwareEvent {
                        id: format!("detect_{}", self.event_counter),
                        path: p_str.clone(),
                        process_name: process_name.clone(),
                        timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                        backed_up: self.initial_backup_map.contains_key(&p_str) || self.backup_map.contains_key(&p_str),
                    }
                })
                .collect();

            ready.push(RansomwareDetection {
                detected: true,
                process_name: process_name.clone(),
                event_count: count,
                time_window_secs: self.window_secs,
                affected_files: affected,
                timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            });

            // 标记冷却期，并移除 pending 状态
            self.detected_processes.insert(process_name.clone(), now);
            self.pending_detections.remove(&process_name);
            // 清除该进程已处理的事件，避免下一次检测重复统计
            self.events.retain(|(_, proc, _)| proc != &process_name);
        }

        ready
    }
}

pub struct RansomwareProtectionManager {
    inner: Arc<Mutex<RansomwareProtectionInner>>,
}

impl RansomwareProtectionManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(RansomwareProtectionInner::new())),
        }
    }

    pub fn state(&self) -> RansomwareProtectionState {
        let inner = self.inner.lock().unwrap();
        RansomwareProtectionState {
            enabled: inner.enabled,
            watched_paths: inner.watched_paths.iter().map(|p| p.to_string_lossy().to_string()).collect(),
            backup_dir: inner.backup_dir.to_string_lossy().to_string(),
            total_backed_up: inner.backup_map.len(),
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.enabled = enabled;
    }

    fn get_user_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(d) = dirs::desktop_dir() { paths.push(d); }
        if let Some(d) = dirs::document_dir() { paths.push(d); }
        if let Some(d) = dirs::download_dir() { paths.push(d); }
        if let Some(d) = dirs::picture_dir() { paths.push(d); }
        if let Some(d) = dirs::home_dir() {
            paths.push(d.join("Desktop"));
            paths.push(d.join("Documents"));
            paths.push(d.join("Downloads"));
        }
        paths
    }

    /// 首次开启时进行全量备份，并发送进度事件。force=true 时忽略已有初始备份，强制重新备份。
    /// silent=true 时只在控制台记录日志，不向前端发送进度事件。
    fn initial_backup(&self, force: bool, silent: bool) -> usize {
        // 标记初始备份进行中，期间 watcher 忽略非删除事件，避免竞争误报
        {
            let mut inner = self.inner.lock().unwrap();
            inner.initial_backup_running = true;
        }

        let result = self.initial_backup_inner(force, silent);

        {
            let mut inner = self.inner.lock().unwrap();
            inner.initial_backup_running = false;
        }
        result
    }

    fn initial_backup_inner(&self, force: bool, silent: bool) -> usize {
        let paths = Self::get_user_paths();
        let app_handle = self.inner.lock().unwrap().app_handle.clone();

        // 第一步：收集所有需要备份的文件
        let mut files_to_backup: Vec<(PathBuf, u64)> = Vec::new();
        for dir in &paths {
            if !dir.exists() { continue; }
            let walk = walkdir::WalkDir::new(dir).max_depth(4).into_iter();
            for entry in walk.filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_file() && RansomwareProtectionInner::is_document(path) {
                    let path_str = path.to_string_lossy().to_string();
                    let inner = self.inner.lock().unwrap();
                    // 非强制模式下，已有初始备份则跳过
                    if !force && inner.initial_backup_map.contains_key(&path_str) {
                        drop(inner);
                        continue;
                    }
                    drop(inner);
                    if let Ok(meta) = std::fs::metadata(path) {
                        files_to_backup.push((path.to_path_buf(), meta.len()));
                    }
                }
            }
        }

        let total = files_to_backup.len();
        let total_size: u64 = files_to_backup.iter().map(|(_, s)| s).sum();

        // 发送估算/开始事件
        if !silent {
            if let Some(app) = &app_handle {
                let _ = app.emit("ransomware-backup-progress", BackupProgress {
                    scanned: 0,
                    total,
                    backed_up: 0,
                    total_size_bytes: total_size,
                    current_file: "准备备份".to_string(),
                    estimated: true,
                    completed: false,
                });
            }
        } else {
            println!("[RansomwareProtection] Silent initial backup started: {} files, {} bytes", total, total_size);
        }

        let mut backed_up = 0usize;
        for (path, _) in files_to_backup {
            let path_str = path.to_string_lossy().to_string();
            let mut inner = self.inner.lock().unwrap();
            // 强制模式下：先移除已有备份记录，让 backup_file 重新生成新的初始备份
            if force {
                if let Some(old) = inner.initial_backup_map.remove(&path_str) {
                    let _ = std::fs::remove_file(&old);
                }
            }
            let result = inner.backup_file(&path);
            drop(inner);
            if result.is_some() {
                backed_up += 1;
            }
            if let Some(app) = &app_handle {
                if !silent {
                    let _ = app.emit("ransomware-backup-progress", BackupProgress {
                        scanned: backed_up,
                        total,
                        backed_up,
                        total_size_bytes: total_size,
                        current_file: path_str,
                        estimated: false,
                        completed: false,
                    });
                } else if backed_up % 50 == 0 {
                    // 静默模式下每 50 个文件记录一次日志，避免日志刷屏
                    println!("[RansomwareProtection] Silent backup progress: {}/{}", backed_up, total);
                }
            }
        }

        println!("[RansomwareProtection] Initial backup completed: {}/{} files", backed_up, total);
        if !silent {
            if let Some(app) = &app_handle {
                let _ = app.emit("ransomware-backup-completed", BackupProgress {
                    scanned: total,
                    total,
                    backed_up,
                    total_size_bytes: total_size,
                    current_file: "备份完成".to_string(),
                    estimated: false,
                    completed: true,
                });
            }
        } else {
            println!("[RansomwareProtection] Silent initial backup completed: {}/{} files", backed_up, total);
        }
        backed_up
    }

    /// 估算需要备份的文件总数和总大小（未备份过的文件）
    fn estimate_backup_size(&self) -> BackupProgress {
        let paths = Self::get_user_paths();
        let mut total_files = 0usize;
        let mut total_size = 0u64;
        for dir in &paths {
            if !dir.exists() { continue; }
            let walk = walkdir::WalkDir::new(dir).max_depth(4).into_iter();
            for entry in walk.filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_file() && RansomwareProtectionInner::is_document(path) {
                    let path_str = path.to_string_lossy().to_string();
                    let inner = self.inner.lock().unwrap();
                    if inner.initial_backup_map.contains_key(&path_str) {
                        drop(inner);
                        continue;
                    }
                    drop(inner);
                    if let Ok(meta) = std::fs::metadata(path) {
                        total_files += 1;
                        total_size += meta.len();
                    }
                }
            }
        }
        BackupProgress {
            scanned: 0,
            total: total_files,
            backed_up: 0,
            total_size_bytes: total_size,
            current_file: "估算完成".to_string(),
            estimated: true,
            completed: false,
        }
    }

    pub fn start(&self, app: tauri::AppHandle, silent: bool) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap();
        if inner.watcher.is_some() {
            return Ok(());
        }

        let paths = Self::get_user_paths();
        let watched: Vec<PathBuf> = paths.iter().filter(|p| p.exists()).cloned().collect();
        if watched.is_empty() {
            return Err("No user directories to watch".to_string());
        }
        inner.watched_paths = watched.clone();
        inner.app_handle = Some(app.clone());

        let inner_clone = Arc::clone(&self.inner);
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                // 监控修改（内容/重命名都属于 Modify）、删除（勒索软件常见行为：加密/改后缀/删除原文件）
                let is_monitored_kind = matches!(event.kind, EventKind::Modify(_) | EventKind::Remove(_));
                if !is_monitored_kind {
                    return;
                }
                let is_remove = matches!(event.kind, EventKind::Remove(_));
                let mut inner = inner_clone.lock().unwrap();
                // 初始备份期间忽略事件，避免备份过程中创建的新文件被误判
                if inner.initial_backup_running && !is_remove {
                    drop(inner);
                    return;
                }
                for path in event.paths {
                    let path_str = path.to_string_lossy().to_string();

                    // 删除事件：同步清理备份记录，避免同名新文件被误判
                    if is_remove {
                        inner.remove_backup_record(&path_str);
                        continue;
                    }

                    // 修改事件发生时文件应该存在（不存在则忽略）
                    if !path.exists() {
                        continue;
                    }

                    // 删除事件发生时文件可能已不存在，无法再通过 path.is_file() 判断，
                    // 因此根据后缀或历史备份记录来决定是否纳入统计。
                    let is_doc = RansomwareProtectionInner::is_document(&path)
                        || path_str.to_lowercase().split('.').last().map(|ext| {
                            DOC_EXTENSIONS.iter().any(|e| e.trim_start_matches('.') == ext)
                        }).unwrap_or(false);
                    if !is_doc {
                        continue;
                    }
                    // notify 在 Windows 上通常无法提供可靠的进程名，统一标记为 unknown
                    let process_name = "unknown".to_string();
                    inner.push_event(path, process_name, is_remove);
                }
            }
        })
        .map_err(|e| format!("Failed to create watcher: {}", e))?;

        for path in &watched {
            watcher
                .watch(path, RecursiveMode::Recursive)
                .map_err(|e| format!("Failed to watch {}: {}", path.display(), e))?;
        }

        inner.watcher = Some(watcher);
        inner.stop_flag.store(false, Ordering::SeqCst);
        let stop_flag = Arc::clone(&inner.stop_flag);
        drop(inner);

        // 启动稳定期检测后台线程：等待事件风暴静止后，一次性汇总并通知前端
        let inner_for_detection = Arc::clone(&self.inner);
        let detection_handle = std::thread::spawn(move || {
            loop {
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }
                // 每 200ms 检查一次是否有进程已稳定
                std::thread::sleep(Duration::from_millis(200));
                let mut inner = inner_for_detection.lock().unwrap();
                let detections = inner.check_pending_detections();
                let app_handle = inner.app_handle.clone();
                drop(inner);
                if let Some(app) = app_handle {
                    for detection in detections {
                        println!(
                            "[RansomwareProtection] Stabilized detection: process={}, files={}",
                            detection.process_name, detection.event_count
                        );
                        // 勒索检测属于高优先级安全事件，必须确保主窗口可见，用户才能看到弹窗并回滚
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.unminimize();
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                        let _ = app.emit("ransomware-detected", detection);
                    }
                }
            }
        });

        {
            let mut inner = self.inner.lock().unwrap();
            inner.detection_thread = Some(detection_handle);
        }

        // 全量备份在后台线程进行
        let mgr_clone = Arc::new(self.clone());
        std::thread::spawn(move || {
            mgr_clone.initial_backup(false, silent);
        });

        Ok(())
    }

    pub fn stop(&self, _app: tauri::AppHandle) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(mut watcher) = inner.watcher.take() {
            for path in &inner.watched_paths {
                let _ = watcher.unwatch(path);
            }
        }
        inner.watcher = None;
        inner.watched_paths.clear();
        inner.events.clear();
        inner.pending_detections.clear();
        inner.app_handle = None;
        inner.stop_flag.store(true, Ordering::SeqCst);
        let handle = inner.detection_thread.take();
        drop(inner);
        // 等待后台线程退出，避免资源泄漏
        if let Some(h) = handle {
            let _ = h.join();
        }
        Ok(())
    }

    /// 回滚指定文件到初始备份版本（“最后已知良好”版本），返回详细结果
    pub fn rollback_files(&self, original_paths: Vec<String>) -> Vec<RollbackResult> {
        let inner = self.inner.lock().unwrap();
        let mut results = Vec::new();

        // 去重
        let mut unique_paths = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for p in original_paths {
            if seen.insert(p.clone()) {
                unique_paths.push(p);
            }
        }

        for original in &unique_paths {
            let original_path = PathBuf::from(original);
            let backup = inner.initial_backup_map.get(original)
                .or_else(|| inner.backup_map.get(original).and_then(|v| v.first()));
            if let Some(backup) = backup {
                if !backup.exists() {
                    println!("[RansomwareProtection] Rollback failed: backup not found for {} -> {:?}", original, backup);
                    results.push(RollbackResult {
                        path: original.clone(),
                        success: false,
                        message: "备份文件不存在".to_string(),
                    });
                    continue;
                }
                if let Some(parent) = original_path.parent() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        println!("[RansomwareProtection] Rollback failed: cannot create dir for {}: {}", original, e);
                        results.push(RollbackResult {
                            path: original.clone(),
                            success: false,
                            message: format!("无法创建目标目录: {}", e),
                        });
                        continue;
                    }
                }

                // 如果目标文件存在且只读，尝试移除只读属性
                if original_path.exists() {
                    if let Err(e) = Self::remove_readonly(&original_path) {
                        println!("[RansomwareProtection] Rollback warning: cannot clear readonly for {}: {}", original, e);
                    }
                }

                match std::fs::copy(backup, &original_path) {
                    Ok(_) => {
                        println!("[RansomwareProtection] Rolled back {} -> {}", backup.display(), original_path.display());
                        results.push(RollbackResult {
                            path: original.clone(),
                            success: true,
                            message: "回滚成功".to_string(),
                        });
                    }
                    Err(e) => {
                        println!("[RansomwareProtection] Rollback failed: copy error for {}: {}", original, e);
                        results.push(RollbackResult {
                            path: original.clone(),
                            success: false,
                            message: format!("复制失败: {}", e),
                        });
                    }
                }
            } else {
                println!("[RansomwareProtection] Rollback failed: no backup recorded for {}", original);
                results.push(RollbackResult {
                    path: original.clone(),
                    success: false,
                    message: "没有可用的备份".to_string(),
                });
            }
        }
        results
    }

    #[cfg(windows)]
    fn remove_readonly(path: &Path) -> Result<(), String> {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::fs::MetadataExt;
        use windows::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_FLAGS_AND_ATTRIBUTES};
        use windows::core::PCWSTR;
        let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
        let mut attrs = metadata.file_attributes();
        const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
        if attrs & FILE_ATTRIBUTE_READONLY != 0 {
            attrs &= !FILE_ATTRIBUTE_READONLY;
            unsafe {
                let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
                SetFileAttributesW(PCWSTR(wide.as_ptr()), FILE_FLAGS_AND_ATTRIBUTES(attrs)).map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    #[cfg(not(windows))]
    fn remove_readonly(path: &Path) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).map_err(|e| e.to_string())?.permissions();
        let mode = perms.mode();
        if mode & 0o200 == 0 {
            perms.set_mode(mode | 0o200);
            std::fs::set_permissions(path, perms).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// 回滚某个进程在检测时间窗口内修改的所有文件
    pub fn rollback_by_process(&self, process_name: String) -> Vec<RollbackResult> {
        let inner = self.inner.lock().unwrap();
        let paths: Vec<String> = inner.events
            .iter()
            .filter(|(_, proc, _)| proc == &process_name)
            .map(|(_, _, p)| p.to_string_lossy().to_string())
            .collect();
        drop(inner);
        self.rollback_files(paths)
    }

    pub fn list_backup_versions(&self, original_path: String) -> Vec<String> {
        let inner = self.inner.lock().unwrap();
        inner.backup_map.get(&original_path)
            .map(|v| v.iter().map(|p| p.to_string_lossy().to_string()).collect())
            .unwrap_or_default()
    }
}

// 为了能在 Arc 中 clone，我们手动实现 Clone（不使用 Arc::clone，因为这里要整个 manager 的 clone）
impl Clone for RansomwareProtectionManager {
    fn clone(&self) -> Self {
        Self { inner: Arc::clone(&self.inner) }
    }
}

// 全局单例
use once_cell::sync::Lazy;
static RANSOMWARE_PROTECTION: Lazy<Arc<Mutex<RansomwareProtectionManager>>> =
    Lazy::new(|| Arc::new(Mutex::new(RansomwareProtectionManager::new())));

pub fn get_ransomware_protection() -> Arc<Mutex<RansomwareProtectionManager>> {
    Arc::clone(&RANSOMWARE_PROTECTION)
}

#[tauri::command]
pub async fn set_ransomware_protection_enabled(
    enabled: bool,
    app: tauri::AppHandle,
) -> Result<RansomwareProtectionState, String> {
    let manager = get_ransomware_protection();
    {
        let mut mgr = manager.lock().unwrap();
        mgr.set_enabled(enabled);
    }
    if enabled {
        manager.lock().unwrap().start(app, true)?;
    } else {
        manager.lock().unwrap().stop(app)?;
    }
    let state = manager.lock().unwrap().state();
    Ok(state)
}

#[tauri::command]
pub async fn get_ransomware_protection_state() -> Result<RansomwareProtectionState, String> {
    Ok(get_ransomware_protection().lock().unwrap().state())
}

#[tauri::command]
pub async fn estimate_ransomware_backup_size() -> Result<BackupProgress, String> {
    Ok(get_ransomware_protection().lock().unwrap().estimate_backup_size())
}

#[tauri::command]
pub async fn start_ransomware_backup(force: bool) -> Result<RansomwareProtectionState, String> {
    let manager = get_ransomware_protection();
    let mgr = manager.lock().unwrap().clone();
    std::thread::spawn(move || {
        mgr.initial_backup(force, false);
    });
    Ok(get_ransomware_protection().lock().unwrap().state())
}

#[tauri::command]
pub async fn rollback_ransomware_files(paths: Vec<String>) -> Result<Vec<RollbackResult>, String> {
    Ok(get_ransomware_protection().lock().unwrap().rollback_files(paths))
}

#[tauri::command]
pub async fn rollback_ransomware_by_process(process_name: String) -> Result<Vec<RollbackResult>, String> {
    Ok(get_ransomware_protection().lock().unwrap().rollback_by_process(process_name))
}
