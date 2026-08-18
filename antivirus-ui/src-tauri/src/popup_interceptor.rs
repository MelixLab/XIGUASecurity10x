use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager};
use windows::Win32::Foundation::{BOOL, CloseHandle, HWND, LPARAM, RECT};
use windows::Win32::Graphics::Gdi::{
    GetDeviceCaps, GetDC, GetMonitorInfoW, MonitorFromWindow, ReleaseDC, LOGPIXELSX, MONITORINFO,
    MONITOR_DEFAULTTONEAREST,
};
use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
use windows::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowRect, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    SetWindowPos, ShowWindow, SW_HIDE, SW_SHOW, SWP_HIDEWINDOW, SWP_NOACTIVATE, SWP_NOMOVE,
    SWP_NOSIZE, SWP_SHOWWINDOW,
};

/// 被净化的弹窗记录
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct HiddenPopup {
    pub hwnd: i64,
    pub title: String,
    pub process_name: String,
    pub process_path: String,
    pub rule: String,
    pub hidden_at: String,
}

/// 弹窗拦截器状态
#[derive(Clone, serde::Serialize)]
pub struct PopupInterceptorState {
    pub enabled: bool,
    pub total_hidden: usize,
    pub rule_count: usize,
    pub scan_count: u64,
}

/// 单个提示窗口的状态
#[derive(Clone)]
struct PromptRecord {
    shown_at: Instant,
}

struct PopupInterceptorInner {
    enabled: bool,
    app_handle: Option<AppHandle>,
    stop_flag: Arc<AtomicBool>,
    monitor_thread: Option<std::thread::JoinHandle<()>>,
    /// 内置广告关键词
    default_keywords: Vec<String>,
    /// 用户自定义规则（持久化）
    custom_rules: Vec<String>,
    /// 当前已净化的弹窗
    hidden_popups: Vec<HiddenPopup>,
    /// 已提示过的窗口（避免反复弹提示）
    prompted: HashMap<i64, PromptRecord>,
    /// 已忽略的窗口（5 分钟内不再提示）
    ignored: HashMap<i64, Instant>,
    /// 当前正在显示的提示窗口所对应的目标窗口句柄
    active_prompt_target: Option<i64>,
    /// 扫描计数
    scan_count: u64,
}

impl PopupInterceptorInner {
    fn new() -> Self {
        let mut inner = Self {
            enabled: false,
            app_handle: None,
            stop_flag: Arc::new(AtomicBool::new(false)),
            monitor_thread: None,
            default_keywords: vec![
                "推广".to_string(),
                "推销".to_string(),
                "广告".to_string(),
                "立即领取".to_string(),
                "免费领取".to_string(),
                "恭喜".to_string(),
                "中奖".to_string(),
                "红包".to_string(),
                "优惠".to_string(),
                "限时".to_string(),
                "抢购".to_string(),
                "赞助".to_string(),
                "推荐".to_string(),
                "促销".to_string(),
                "特价".to_string(),
                "折扣".to_string(),
                "砍价".to_string(),
                "助力".to_string(),
                "签到".to_string(),
                "抽奖".to_string(),
                "会员".to_string(),
                "续费".to_string(),
                "升级".to_string(),
                "弹窗".to_string(),
                "资讯".to_string(),
                "热点".to_string(),
                "新闻".to_string(),
            ],
            custom_rules: Vec::new(),
            hidden_popups: Vec::new(),
            prompted: HashMap::new(),
            ignored: HashMap::new(),
            active_prompt_target: None,
            scan_count: 0,
        };
        inner.load_rules();
        inner.load_hidden_popups();
        inner
    }

    fn rules_file() -> PathBuf {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().to_string());
        PathBuf::from(local).join("XIGUASecurity").join("popup_rules.json")
    }

    fn load_rules(&mut self) {
        let path = Self::rules_file();
        if !path.exists() {
            return;
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                if let Ok(rules) = serde_json::from_str::<Vec<String>>(&content) {
                    println!("[PopupInterceptor] Loaded {} custom rules", rules.len());
                    self.custom_rules = rules;
                }
            }
            Err(e) => println!("[PopupInterceptor] Failed to load rules: {}", e),
        }
    }

    fn save_rules(&self) {
        let path = Self::rules_file();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&self.custom_rules) {
            if let Err(e) = std::fs::write(&path, json) {
                println!("[PopupInterceptor] Failed to save rules: {}", e);
            }
        }
    }

    fn hidden_popups_file() -> PathBuf {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().to_string());
        PathBuf::from(local).join("XIGUASecurity").join("hidden_popups.json")
    }

    fn load_hidden_popups(&mut self) {
        let path = Self::hidden_popups_file();
        if !path.exists() {
            return;
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                if let Ok(popups) = serde_json::from_str::<Vec<HiddenPopup>>(&content) {
                    println!("[PopupInterceptor] Loaded {} hidden popups", popups.len());
                    self.hidden_popups = popups;
                }
            }
            Err(e) => println!("[PopupInterceptor] Failed to load hidden popups: {}", e),
        }
    }

    fn save_hidden_popups(&self) {
        let path = Self::hidden_popups_file();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&self.hidden_popups) {
            if let Err(e) = std::fs::write(&path, json) {
                println!("[PopupInterceptor] Failed to save hidden popups: {}", e);
            }
        }
    }

}

pub struct PopupInterceptorManager {
    inner: Arc<Mutex<PopupInterceptorInner>>,
}

impl PopupInterceptorManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(PopupInterceptorInner::new())),
        }
    }

    pub fn state(&self) -> PopupInterceptorState {
        let inner = self.inner.lock().unwrap();
        PopupInterceptorState {
            enabled: inner.enabled,
            total_hidden: inner.hidden_popups.len(),
            rule_count: inner.custom_rules.len(),
            scan_count: inner.scan_count,
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.enabled = enabled;
    }

    pub fn start(&self, app: AppHandle) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap();
        if inner.monitor_thread.is_some() {
            return Ok(());
        }
        inner.app_handle = Some(app.clone());
        inner.stop_flag.store(false, Ordering::SeqCst);
        let stop_flag = Arc::clone(&inner.stop_flag);
        drop(inner);

        let inner_clone = Arc::clone(&self.inner);
        let handle = std::thread::spawn(move || {
            loop {
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }
                {
                    let mut inner = inner_clone.lock().unwrap();
                    if inner.enabled {
                        inner.scan_count += 1;
                        scan_and_handle(&mut inner);
                    }
                }
                std::thread::sleep(Duration::from_millis(600));
            }
        });

        {
            let mut inner = self.inner.lock().unwrap();
            inner.monitor_thread = Some(handle);
        }
        Ok(())
    }

    pub fn stop(&self) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap();
        inner.enabled = false;
        inner.app_handle = None;
        inner.stop_flag.store(true, Ordering::SeqCst);
        let handle = inner.monitor_thread.take();
        drop(inner);
        if let Some(h) = handle {
            let _ = h.join();
        }
        Ok(())
    }

    pub fn rules(&self) -> Vec<String> {
        let inner = self.inner.lock().unwrap();
        inner.custom_rules.clone()
    }

    pub fn add_rule(&self, rule: String) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap();
        let trimmed = rule.trim().to_string();
        if trimmed.is_empty() {
            return Err("Rule cannot be empty".to_string());
        }
        if !inner.custom_rules.iter().any(|r| r.to_lowercase() == trimmed.to_lowercase()) {
            inner.custom_rules.push(trimmed);
            inner.save_rules();
        }
        Ok(())
    }

    pub fn remove_rule(&self, rule: String) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap();
        inner.custom_rules.retain(|r| r.to_lowercase() != rule.to_lowercase());
        inner.save_rules();
        Ok(())
    }

    pub fn hidden_popups(&self) -> Vec<HiddenPopup> {
        let inner = self.inner.lock().unwrap();
        inner.hidden_popups.clone()
    }

    /// 从提示窗口点击“净化”：隐藏窗口并加入精确规则（按窗口标题精确匹配）
    pub fn purify(&self, hwnd: i64, title: String, _keyword: String) -> Result<bool, String> {
        let mut inner = self.inner.lock().unwrap();
        // 按窗口标题精确匹配的规则（带 title: 前缀，与关键词规则区分）
        let exact_rule = format!("title:{}", title);
        if !inner.custom_rules.iter().any(|r| r.to_lowercase() == exact_rule.to_lowercase()) {
            inner.custom_rules.push(exact_rule);
            inner.save_rules();
        }
        // 隐藏目标窗口
        let hidden = unsafe {
            let hwnd = HWND(hwnd as *mut std::ffi::c_void);
            if IsWindowVisible(hwnd).as_bool() {
                // 使用 ShowWindow SW_HIDE 或 SetWindowPos SWP_HIDEWINDOW 隐藏，不发送 WM_CLOSE
                let _ = ShowWindow(hwnd, SW_HIDE);
                let _ = SetWindowPos(
                    hwnd,
                    None,
                    0,
                    0,
                    0,
                    0,
                    SWP_HIDEWINDOW | SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE,
                );
                true
            } else {
                false
            }
        };
        if hidden {
            let (process_name, process_path) = get_process_info(hwnd);
            inner.hidden_popups.push(HiddenPopup {
                hwnd,
                title: title.clone(),
                process_name,
                process_path,
                rule: format!("title:{}", title),
                hidden_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            });
            // 标记已净化，不再提示，并关闭提示窗口
            inner.prompted.remove(&hwnd);
            inner.ignored.remove(&hwnd);
            inner.save_hidden_popups();
            if inner.active_prompt_target == Some(hwnd) {
                inner.active_prompt_target = None;
                if let Some(app) = &inner.app_handle {
                    close_prompt_window(app);
                }
            }
        }
        Ok(hidden)
    }

    /// 恢复某个被隐藏的弹窗
    pub fn restore_popup(&self, hwnd: i64) -> Result<bool, String> {
        let mut inner = self.inner.lock().unwrap();
        let restored = unsafe {
            let hwnd = HWND(hwnd as *mut std::ffi::c_void);
            let _ = ShowWindow(hwnd, SW_SHOW);
            let _ = SetWindowPos(
                hwnd,
                None,
                0,
                0,
                0,
                0,
                SWP_SHOWWINDOW | SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE,
            );
            IsWindowVisible(hwnd).as_bool()
        };
        inner.hidden_popups.retain(|p| p.hwnd != hwnd);
        inner.save_hidden_popups();
        Ok(restored)
    }

    /// 从列表中移除记录（不恢复窗口）
    pub fn remove_popup_record(&self, hwnd: i64) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap();
        inner.hidden_popups.retain(|p| p.hwnd != hwnd);
        inner.save_hidden_popups();
        Ok(())
    }

    /// 提示窗口点击“忽略”
    pub fn dismiss_prompt(&self, hwnd: i64) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap();
        inner.ignored.insert(hwnd, Instant::now());
        inner.prompted.remove(&hwnd);
        if inner.active_prompt_target == Some(hwnd) {
            inner.active_prompt_target = None;
            if let Some(app) = &inner.app_handle {
                close_prompt_window(app);
            }
        }
        Ok(())
    }
}

impl Clone for PopupInterceptorManager {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

fn get_window_pid(hwnd: i64) -> u32 {
    unsafe {
        let hwnd = HWND(hwnd as *mut std::ffi::c_void);
        let mut pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        pid
    }
}

fn get_process_info(hwnd: i64) -> (String, String) {
    unsafe {
        let hwnd = HWND(hwnd as *mut std::ffi::c_void);
        let mut pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if pid == 0 {
            return ("未知进程".to_string(), "".to_string());
        }
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        match handle {
            Ok(h) if !h.is_invalid() => {
                let mut buf = [0u16; 512];
                let len = GetModuleFileNameExW(h, None, &mut buf);
                let _ = CloseHandle(h);
                if len > 0 {
                    let path = String::from_utf16_lossy(&buf[..len as usize]);
                    let name = PathBuf::from(&path)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "未知进程".to_string());
                    return (name, path);
                }
            }
            _ => {}
        }
        ("未知进程".to_string(), "".to_string())
    }
}

fn scan_and_handle(inner: &mut PopupInterceptorInner) {
    // 清理过期的忽略记录（5 分钟）
    let now = Instant::now();
    inner.ignored.retain(|_, t| now.duration_since(*t) < Duration::from_secs(300));
    inner.prompted.retain(|_, r| now.duration_since(r.shown_at) < Duration::from_secs(300));

    let app_handle = inner.app_handle.clone();
    let custom_rules = inner.custom_rules.clone();
    let default_keywords = inner.default_keywords.clone();
    let hidden_hwnds: HashSet<i64> = inner.hidden_popups.iter().map(|p| p.hwnd).collect();

    // 收集当前所有可见窗口
    let mut windows: Vec<(i64, String, RECT)> = Vec::new();
    unsafe {
        let _ = EnumWindows(Some(enum_window_callback), LPARAM(&mut windows as *mut _ as isize));
    }

    let own_pid = unsafe { GetCurrentProcessId() };

    // 如果存在正在显示的提示窗口，先尝试跟随目标窗口；若目标已关闭/隐藏，则关闭提示窗口
    if let Some(target_hwnd) = inner.active_prompt_target {
        let target_still_visible = windows.iter().any(|(hwnd, _, _)| *hwnd == target_hwnd);
        if let Some(app) = &app_handle {
            if target_still_visible {
                let _ = move_prompt_window(app, target_hwnd);
            } else {
                close_prompt_window(app);
                inner.active_prompt_target = None;
            }
        }
    }

    for (hwnd, title, rect) in windows {
        // 跳过本进程窗口（主窗口、提示窗口等）
        if get_window_pid(hwnd) == own_pid {
            continue;
        }
        // 跳过已净化的窗口
        if hidden_hwnds.contains(&hwnd) {
            continue;
        }
        // 跳过标题为空的窗口
        if title.is_empty() {
            continue;
        }

        let lower_title = title.to_lowercase();
        let in_custom = custom_rules.iter().any(|rule| {
            let rule_lower = rule.to_lowercase();
            if let Some(exact_title) = rule_lower.strip_prefix("title:") {
                lower_title == exact_title
            } else {
                lower_title.contains(&rule_lower)
            }
        });
        let matched_default = default_keywords.iter().find(|kw| lower_title.contains(&kw.to_lowercase())).cloned();

        if in_custom {
            // 命中自定义规则，自动隐藏
            unsafe {
                let h = HWND(hwnd as *mut std::ffi::c_void);
                let _ = ShowWindow(h, SW_HIDE);
                let _ = SetWindowPos(
                    h,
                    None,
                    0,
                    0,
                    0,
                    0,
                    SWP_HIDEWINDOW | SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE,
                );
            }
            let (process_name, process_path) = get_process_info(hwnd);
            inner.hidden_popups.push(HiddenPopup {
                hwnd,
                title,
                process_name,
                process_path,
                rule: "自定义规则".to_string(),
                hidden_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            });
            continue;
        }

        if let Some(keyword) = matched_default {
            // 命中默认关键词，且未被忽略/提示过，则显示提示窗口
            if inner.ignored.contains_key(&hwnd) || inner.prompted.contains_key(&hwnd) {
                continue;
            }
            if let Some(app) = &app_handle {
                show_prompt_window(app, hwnd, &title, &keyword, rect);
                inner.prompted.insert(hwnd, PromptRecord {
                    shown_at: now,
                });
                inner.active_prompt_target = Some(hwnd);
            }
        }
    }
}

extern "system" fn enum_window_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    unsafe {
        let windows = lparam.0 as *mut Vec<(i64, String, RECT)>;
        if IsWindowVisible(hwnd).as_bool() {
            let mut buf = [0u16; 512];
            let len = GetWindowTextW(hwnd, &mut buf);
            if len > 0 {
                let title = String::from_utf16_lossy(&buf[..len as usize]);
                let mut rect = RECT::default();
                if GetWindowRect(hwnd, &mut rect).is_ok() {
                    (*windows).push((hwnd.0 as i64, title, rect));
                }
            }
        }
    }
    BOOL(1)
}

fn get_window_rect(hwnd: i64) -> Option<RECT> {
    unsafe {
        let hwnd = HWND(hwnd as *mut std::ffi::c_void);
        let mut rect = RECT::default();
        if GetWindowRect(hwnd, &mut rect).is_ok() {
            Some(rect)
        } else {
            None
        }
    }
}

fn calculate_prompt_position(hwnd: i64, rect: RECT) -> (i32, i32) {
    let logical_width = 320.0;
    let logical_height = 120.0;
    let margin = 8.0;
    let title_bar_height = 40.0; // 标题栏高度，用于最大化时定位

    // 获取目标窗口的 DPI 缩放
    let scale = unsafe {
        let hdc = GetDC(None);
        let dpi = GetDeviceCaps(hdc, LOGPIXELSX) as f64;
        let _ = ReleaseDC(None, hdc);
        if dpi > 0.0 {
            dpi / 96.0
        } else {
            1.0
        }
    };

    let physical_width = (logical_width * scale) as i32;
    let physical_height = (logical_height * scale) as i32;
    let physical_margin = (margin * scale) as i32;
    let physical_title_bar = (title_bar_height * scale) as i32;

    // 获取目标窗口所在显示器的工作区
    let monitor_info = unsafe {
        let target_hwnd = HWND(hwnd as *mut std::ffi::c_void);
        let hmonitor = MonitorFromWindow(target_hwnd, MONITOR_DEFAULTTONEAREST);
        let mut mi = MONITORINFO::default();
        mi.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
        if GetMonitorInfoW(hmonitor, &mut mi).as_bool() {
            Some(mi)
        } else {
            None
        }
    };

    // 默认放在目标窗口标题栏上方偏右
    let mut x = rect.right - physical_width - physical_margin;
    let mut y = rect.top - physical_height - physical_margin;

    if let Some(mi) = monitor_info {
        // 如果上方空间不足（窗口最大化或靠近屏幕顶部），放到标题栏下方
        if y < mi.rcWork.top + physical_margin {
            y = rect.top + physical_title_bar + physical_margin;
        }
        // 横向边界保护：确保不超出显示器工作区
        let work_right = mi.rcWork.right - physical_margin;
        let work_left = mi.rcWork.left + physical_margin;
        if x + physical_width > work_right {
            x = work_right - physical_width;
        }
        if x < work_left {
            x = work_left;
        }
        // 纵向边界保护：确保不超出显示器工作区底部
        let work_bottom = mi.rcWork.bottom - physical_margin;
        if y + physical_height > work_bottom {
            y = work_bottom - physical_height;
        }
    }

    (x.max(0), y.max(0))
}

fn move_prompt_window(app: &AppHandle, hwnd: i64) -> bool {
    if let Some(window) = app.get_webview_window("popup-prompt") {
        if let Some(rect) = get_window_rect(hwnd) {
            let (x, y) = calculate_prompt_position(hwnd, rect);
            let _ = window.set_position(tauri::Position::Physical(tauri::PhysicalPosition::new(x, y)));
            return true;
        }
    }
    false
}

fn close_prompt_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("popup-prompt") {
        let _ = window.close();
    }
}

fn show_prompt_window(app: &AppHandle, hwnd: i64, title: &str, keyword: &str, rect: RECT) {
    // 关闭已有的提示窗口（避免多个提示堆叠）
    close_prompt_window(app);

    let encoded_title = urlencoding::encode(title);
    let encoded_keyword = urlencoding::encode(keyword);
    let url = format!(
        "popup-prompt.html?hwnd={}&title={}&keyword={}",
        hwnd, encoded_title, encoded_keyword
    );

    let (x, y) = calculate_prompt_position(hwnd, rect);

    let window = tauri::WebviewWindowBuilder::new(
        app,
        "popup-prompt",
        tauri::WebviewUrl::App(url.into()),
    )
    .title("弹窗提示")
    .inner_size(320.0, 120.0)
    .decorations(false)
    .transparent(false)
    .shadow(true)
    .always_on_top(true)
    .skip_taskbar(true)
    .resizable(false)
    .visible(false)
    .build();

    match window {
        Ok(w) => {
            let _ = w.set_position(tauri::Position::Physical(tauri::PhysicalPosition::new(x, y)));
            let _ = w.show();
            let _ = w.set_focus();
        }
        Err(e) => println!("[PopupInterceptor] Failed to create prompt window: {}", e),
    }
}

// 全局单例
use once_cell::sync::Lazy;
static POPUP_INTERCEPTOR: Lazy<Arc<Mutex<PopupInterceptorManager>>> =
    Lazy::new(|| Arc::new(Mutex::new(PopupInterceptorManager::new())));

pub fn get_popup_interceptor() -> Arc<Mutex<PopupInterceptorManager>> {
    Arc::clone(&POPUP_INTERCEPTOR)
}

#[tauri::command]
pub async fn start_popup_interceptor(app: tauri::AppHandle) -> Result<PopupInterceptorState, String> {
    let manager = get_popup_interceptor();
    {
        let mgr = manager.lock().unwrap();
        mgr.set_enabled(true);
    }
    manager.lock().unwrap().start(app)?;
    let state = manager.lock().unwrap().state();
    Ok(state)
}

#[tauri::command]
pub async fn stop_popup_interceptor() -> Result<PopupInterceptorState, String> {
    let manager = get_popup_interceptor();
    manager.lock().unwrap().stop()?;
    let state = manager.lock().unwrap().state();
    Ok(state)
}

#[tauri::command]
pub async fn get_popup_interceptor_state() -> Result<PopupInterceptorState, String> {
    Ok(get_popup_interceptor().lock().unwrap().state())
}

#[tauri::command]
pub async fn get_popup_rules() -> Result<Vec<String>, String> {
    Ok(get_popup_interceptor().lock().unwrap().rules())
}

#[tauri::command]
pub async fn add_popup_rule(rule: String) -> Result<(), String> {
    get_popup_interceptor().lock().unwrap().add_rule(rule)
}

#[tauri::command]
pub async fn remove_popup_rule(rule: String) -> Result<(), String> {
    get_popup_interceptor().lock().unwrap().remove_rule(rule)
}

#[tauri::command]
pub async fn get_hidden_popups() -> Result<Vec<HiddenPopup>, String> {
    Ok(get_popup_interceptor().lock().unwrap().hidden_popups())
}

#[tauri::command]
pub async fn restore_popup(hwnd: i64) -> Result<bool, String> {
    get_popup_interceptor().lock().unwrap().restore_popup(hwnd)
}

#[tauri::command]
pub async fn remove_popup_record(hwnd: i64) -> Result<(), String> {
    get_popup_interceptor().lock().unwrap().remove_popup_record(hwnd)
}

#[tauri::command]
pub async fn purify_popup(hwnd: i64, title: String, keyword: String) -> Result<bool, String> {
    get_popup_interceptor().lock().unwrap().purify(hwnd, title, keyword)
}

#[tauri::command]
pub async fn dismiss_popup_prompt(hwnd: i64) -> Result<(), String> {
    get_popup_interceptor().lock().unwrap().dismiss_prompt(hwnd)
}

