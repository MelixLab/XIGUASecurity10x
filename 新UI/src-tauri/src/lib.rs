mod av_driver_client;
mod driver_protection;
mod engine;
mod scanner;

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            cmd_get_scan_files,
            cmd_get_full_scan_files,
            cmd_get_scan_files_direct,
            cmd_scan_batch,
            cmd_calculate_file_hash,
            get_driver_protection,
            set_driver_protection,
            check_driver_process_running,
            send_av_driver_decision,
            close_intercept_window,
            resize_intercept_window,
            set_window_backdrop
        ])
        .setup(|app| {
            // 监听驱动 Agent 推送的拦截通知
            use tauri::{Emitter, Listener};
            let app_handle = app.handle().clone();
            app_handle.clone().listen("av-driver-notification", move |event| {
                let n: Option<av_driver_client::AvNotification> =
                    serde_json::from_str(event.payload()).ok();
                if let Some(n) = n {
                    driver_protection::handle_notification(&app_handle, n);
                }
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running XIGUASecurity");
}

// ═══════════════════════════════════════════════════════════════════════════
// 扫描引擎命令
// ═══════════════════════════════════════════════════════════════════════════

/// 智能（快速）扫描：返回待扫描文件列表。
#[tauri::command]
async fn cmd_get_scan_files() -> Result<Vec<String>, String> {
    tauri::async_runtime::spawn_blocking(scanner::get_scan_files)
        .await
        .map_err(|e| e.to_string())
}

/// 全盘扫描：返回待扫描文件列表。
#[tauri::command]
async fn cmd_get_full_scan_files() -> Result<Vec<String>, String> {
    tauri::async_runtime::spawn_blocking(scanner::get_full_scan_files)
        .await
        .map_err(|e| e.to_string())
}

/// 自定义扫描：返回指定路径下的待扫描文件列表。
#[tauri::command]
async fn cmd_get_scan_files_direct(paths: Vec<String>) -> Result<Vec<String>, String> {
    tauri::async_runtime::spawn_blocking(move || scanner::get_scan_files_direct(paths))
        .await
        .map_err(|e| e.to_string())
}

/// 批量扫描（ML + 云端哈希）。返回 ScanResult 的 JSON 数组字符串。
#[tauri::command]
async fn cmd_scan_batch(
    file_paths: Vec<String>,
    cloud_enabled: bool,
    cloud_url: Option<String>,
    cloud_key: Option<String>,
) -> Result<String, String> {
    let res = tauri::async_runtime::spawn_blocking(move || {
        scanner::scan_batch_files(file_paths, cloud_enabled, cloud_url, cloud_key)
    })
    .await
    .map_err(|e| e.to_string())?;
    serde_json::to_string(&res).map_err(|e| e.to_string())
}

/// 计算单个文件 SHA-256。
#[tauri::command]
fn cmd_calculate_file_hash(file_path: String) -> Result<Option<String>, String> {
    Ok(scanner::calculate_file_hash(&file_path))
}

// ═══════════════════════════════════════════════════════════════════════════
// 驱动防护命令
// ═══════════════════════════════════════════════════════════════════════════

/// 查询驱动防护当前状态（Agent 是否运行）。
#[tauri::command]
fn get_driver_protection() -> Result<bool, String> {
    Ok(driver_protection::is_driver_protection_enabled())
}

/// 设置驱动防护开关（手动开启/关闭）。
#[tauri::command]
async fn set_driver_protection(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || driver_protection::set_driver_protection(&app, enabled))
        .await
        .map_err(|e| e.to_string())?
}

/// 检查 Agent 进程是否在运行。
#[tauri::command]
fn check_driver_process_running() -> Result<bool, String> {
    Ok(driver_protection::is_agent_running())
}

/// 驱动拦截窗口用户决策（allow/block/allow_always/block_always）。
#[tauri::command]
async fn send_av_driver_decision(
    app: tauri::AppHandle,
    pending_key: String,
    decision: String,
) -> Result<(), String> {
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        driver_protection::apply_decision(&app, &pending_key, &decision)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 关闭/隐藏拦截窗口。
#[tauri::command]
async fn close_intercept_window(app: tauri::AppHandle) -> Result<(), String> {
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        driver_protection::finish_intercept(&app);
    })
    .await
    .map_err(|e| e.to_string())
}

/// 调整拦截窗口高度（自适应内容）。
#[tauri::command]
async fn resize_intercept_window(app: tauri::AppHandle, height: f64) -> Result<(), String> {
    if let Some(win) = app.get_webview_window("intercept-alert") {
        let h = height.clamp(340.0, 680.0);
        let _ = win.set_size(tauri::LogicalSize::new(360.0, h));
    }
    Ok(())
}

/// 设置窗口背景材质（简化：仅占位，兼容拦截窗口调用）。
#[tauri::command]
fn set_window_backdrop(_app: tauri::AppHandle, _backdrop: Option<String>, _theme_mode: Option<String>) -> Result<(), String> {
    Ok(())
}
