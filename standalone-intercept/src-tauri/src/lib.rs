// =============================================================================
// Standalone Suspicious File Intercept Program
// Only does suspicious file interception - background process monitoring,
// ONNX model scanning, cloud sandbox analysis, and intercept UI.
// =============================================================================

use tauri::{Manager, RunEvent};
use windows::Win32::Graphics::Gdi::{GetMonitorInfoW, MonitorFromWindow, MONITORINFO, MONITOR_DEFAULTTONEAREST, GetDeviceCaps, LOGPIXELSX, GetDC, ReleaseDC};
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

mod scanner;
use scanner::SCANNER;

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

// ==================== Constants ====================

const SANDBOX_RELAY_BASE: &str = "http://103.118.245.82:9051";
const SANDBOX_API_KEY: &str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1";

/// Suspicious process name list (suspended immediately and uploaded to cloud sandbox)
const SUSPICIOUS_PROCESS_NAMES: &[&str] = &[
    // Test filenames
    "suspicious_test.exe",
    "test_malware.exe",
    "test_suspicious.exe",
    // Known suspicious/high-risk tools
    "psexesvc.exe",           // PsExec remote execution
    "procdump.exe",           // Process dump (credential theft)
    "mimikatz.exe",           // Credential extraction
    "mimilib.dll",
    "nc.exe",                 // NetCat
    "ncat.exe",
    "cobalt_strike.exe",
    "beacon.exe",
    "metasploit.exe",
    "msfconsole.exe",
    "meterpreter.exe",
    "reverse_shell.exe",
    "keylogger.exe",
    "ransomware.exe",
    "cryptolocker.exe",
    "wannacry.exe",
    "locky.exe",
    // Remote access / backdoor
    "tvnviewer.exe",          // TightVNC (often abused)
    "winvnc.exe",
    "ammyy.exe",              // Ammyy Admin (often abused)
    "anydesk.exe",            // AnyDesk (can be abused)
    "radmin.exe",
];

// ==================== Global State ====================

lazy_static::lazy_static! {
    /// PIDs that have already been scanned in the monitor loop.
    static ref MONITORED_PIDS: Mutex<HashSet<u32>> = Mutex::new(HashSet::new());
}

/// Stop flag for the background process monitor.
static MONITOR_STOP: AtomicBool = AtomicBool::new(false);

// ==================== NtSuspendProcess / NtResumeProcess ====================

#[cfg(windows)]
extern "system" {
    fn NtSuspendProcess(handle: windows::Win32::Foundation::HANDLE) -> i32;
    fn NtResumeProcess(handle: windows::Win32::Foundation::HANDLE) -> i32;
}

// ==================== Public entry point ====================

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            // Keep the main window hidden — this is a background monitor
            if let Some(main_win) = app.get_webview_window("main") {
                let _ = main_win.hide();
            }

            // Auto-start the background process monitor
            // Ensure the enabled flag file exists (default: true for standalone)
            {
                let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
                let dir = format!("{}/XIGUASecurity", local_app_data);
                let _ = std::fs::create_dir_all(&dir);
                let path = format!("{}/suspicious_intercept_enabled.txt", dir);
                if !std::path::Path::new(&path).exists() {
                    let _ = std::fs::write(&path, "true");
                }
            }
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                process_monitor_loop(app_handle).await;
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_running_processes,
            terminate_process,
            suspend_process,
            resume_process,
            scan_file_basic,
            show_suspicious_intercept_window,
            send_suspicious_decision,
            suspicious_analyze_file,
            get_suspicious_intercept_enabled,
            set_suspicious_intercept_enabled,
            start_process_monitor,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_app_handle, event| {
            match event {
                RunEvent::ExitRequested { .. } => {
                    println!("[App] Exit requested, stopping monitor...");
                    MONITOR_STOP.store(true, Ordering::SeqCst);
                }
                _ => {}
            }
        });
}

// ==================== Background Process Monitor ====================

/// Core monitor loop — enumerates processes every 500ms, checks each new
/// process against SUSPICIOUS_PROCESS_NAMES and the ONNX model.
async fn process_monitor_loop(app: tauri::AppHandle) {
    println!("[Monitor] Starting background process monitor");
    let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        if MONITOR_STOP.load(Ordering::SeqCst) {
            println!("[Monitor] Stop flag set, exiting monitor loop");
            break;
        }

        // Skip if intercept is disabled
        if !get_suspicious_intercept_enabled() {
            continue;
        }

        // Get current running processes
        let processes = match get_running_processes_internal().await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[Monitor] Failed to enumerate processes: {}", e);
                continue;
            }
        };

        // Build a set of currently alive PIDs
        let mut alive_pids = HashSet::new();

        for proc in &processes {
            let pid = match proc.get("pid").and_then(|v| v.as_u64()) {
                Some(p) => p as u32,
                None => continue,
            };
            alive_pids.insert(pid);

            // Skip already-processed PIDs
            {
                let monitored = MONITORED_PIDS.lock().unwrap();
                if monitored.contains(&pid) {
                    continue;
                }
            }

            // Mark as processed immediately
            {
                let mut monitored = MONITORED_PIDS.lock().unwrap();
                monitored.insert(pid);
            }

            let name = proc.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let path = proc.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();

            if name.is_empty() || path.is_empty() {
                continue;
            }

            let lower_name = name.to_lowercase();

            // --- Check 1: Suspicious filename match ---
            let filename_match = SUSPICIOUS_PROCESS_NAMES.iter().any(|&s| lower_name == s);
            if filename_match {
                println!("[Monitor] Suspicious filename detected: {} (pid={})", name, pid);

                // Suspend the process
                match suspend_process_internal(pid) {
                    Ok(()) => println!("[Monitor] Process {} suspended (filename match)", pid),
                    Err(e) => eprintln!("[Monitor] Failed to suspend {}: {}", pid, e),
                }

                // Show intercept window
                let app_clone = app.clone();
                let fname = name.clone();
                let fpath = path.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = show_suspicious_intercept_window_internal(
                        app_clone, fname, fpath, pid, 0.70,
                    ).await {
                        eprintln!("[Monitor] Failed to show intercept window: {}", e);
                    }
                });
                continue;
            }

            // --- Check 2: ONNX model probability scan ---
            let app_clone = app.clone();
            let fname = name.clone();
            let fpath = path.clone();
            tauri::async_runtime::spawn(async move {
                let is_suspicious = {
                    let scanner = match SCANNER.read() {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("[Monitor] Scanner lock poisoned: {}", e);
                            return;
                        }
                    };
                    let result = scanner.scan_file(&fpath, None);
                    !matches!(result.result.as_str(), "MALICIOUS") && result.probability > 0.70
                };

                if is_suspicious {
                    println!("[Monitor] Suspicious by ONNX scan: {} (pid={})", fname, pid);

                    match suspend_process_internal(pid) {
                        Ok(()) => println!("[Monitor] Process {} suspended (ONNX match)", pid),
                        Err(e) => eprintln!("[Monitor] Failed to suspend {}: {}", pid, e),
                    }

                    if let Err(e) = show_suspicious_intercept_window_internal(
                        app_clone, fname, fpath, pid, 0.70,
                    ).await {
                        eprintln!("[Monitor] Failed to show intercept window: {}", e);
                    }
                }
            });
        }

        // Periodic cleanup: remove PIDs that are no longer alive
        {
            let mut monitored = MONITORED_PIDS.lock().unwrap();
            let before = monitored.len();
            monitored.retain(|pid| alive_pids.contains(pid));
            let removed = before - monitored.len();
            if removed > 0 {
                println!("[Monitor] Cleaned {} stale PIDs from tracking set", removed);
            }
        }
    }
}

/// Helper: enumerate processes and return as Vec<serde_json::Value>.
async fn get_running_processes_internal() -> Result<Vec<serde_json::Value>, String> {
    tokio::task::spawn_blocking(|| {
        let mut processes = Vec::new();

        #[cfg(windows)]
        unsafe {
            use windows::Win32::System::ProcessStatus::{EnumProcesses, GetModuleBaseNameW, GetModuleFileNameExW};
            use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
            use windows::Win32::Foundation::CloseHandle;

            let mut process_ids = [0u32; 1024];
            let mut bytes_returned = 0u32;

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

                    let process_handle = OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                        false,
                        pid,
                    );

                    if let Ok(handle) = process_handle {
                        let mut path_buffer = [0u16; 512];

                        if GetModuleFileNameExW(
                            handle,
                            None,
                            &mut path_buffer,
                        ) > 0 {
                            let path = String::from_utf16_lossy(&path_buffer)
                                .trim_end_matches('\0')
                                .to_string();

                            let mut name_buffer = [0u16; 256];
                            let name_len = GetModuleBaseNameW(
                                handle,
                                None,
                                &mut name_buffer,
                            );

                            let name = if name_len > 0 {
                                String::from_utf16_lossy(&name_buffer[..name_len as usize])
                                    .to_string()
                            } else {
                                path.split('\\').last().unwrap_or("unknown").to_string()
                            };

                            processes.push(serde_json::json!({
                                "pid": pid,
                                "path": path,
                                "name": name
                            }));
                        }

                        let _ = CloseHandle(handle);
                    }
                }
            }
        }

        processes
    }).await.map_err(|e| format!("Failed to get processes: {}", e))
}

/// Helper: suspend a process by PID.
fn suspend_process_internal(pid: u32) -> Result<(), String> {
    #[cfg(windows)]
    unsafe {
        use windows::Win32::System::Threading::OpenProcess;
        use windows::Win32::Foundation::CloseHandle;
        // PROCESS_SUSPEND_RESUME = 0x00000800
        let handle = OpenProcess(
            windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS(0x00000800),
            false,
            pid,
        ).map_err(|e| format!("Failed to open process: {}", e))?;
        let status = NtSuspendProcess(handle);
        let _ = CloseHandle(handle);
        if status >= 0 { Ok(()) } else { Err(format!("NtSuspendProcess failed: 0x{:08X}", status)) }
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        Err("Not supported on this platform".to_string())
    }
}

/// Helper: resume a process by PID.
fn resume_process_internal(pid: u32) -> Result<(), String> {
    #[cfg(windows)]
    unsafe {
        use windows::Win32::System::Threading::OpenProcess;
        use windows::Win32::Foundation::CloseHandle;
        let handle = OpenProcess(
            windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS(0x00000800),
            false,
            pid,
        ).map_err(|e| format!("Failed to open process: {}", e))?;
        let status = NtResumeProcess(handle);
        let _ = CloseHandle(handle);
        if status >= 0 { Ok(()) } else { Err(format!("NtResumeProcess failed: 0x{:08X}", status)) }
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        Err("Not supported on this platform".to_string())
    }
}

/// Helper: create and show the intercept window centered on screen.
async fn show_suspicious_intercept_window_internal(
    app: tauri::AppHandle,
    file_name: String,
    file_path: String,
    pid: u32,
    confidence: f64,
) -> Result<(), String> {
    // Close existing intercept window
    if let Some(existing) = app.get_webview_window("intercept-suspicious") {
        let _ = existing.close();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    let url = format!(
        "suspicious-intercept.html?name={}&path={}&pid={}&confidence={}",
        urlencoding::encode(&file_name),
        urlencoding::encode(&file_path),
        pid,
        confidence,
    );

    let window = tauri::WebviewWindowBuilder::new(
        &app,
        "intercept-suspicious",
        tauri::WebviewUrl::App(url.into()),
    )
    .inner_size(520.0, 320.0)
    .decorations(false)
    .transparent(false)
    .shadow(true)
    .always_on_top(true)
    .skip_taskbar(true)
    .resizable(false)
    .visible(false)
    .build()
    .map_err(|e| format!("Failed to create intercept window: {}", e))?;

    // Center on screen (DPI-aware)
    #[cfg(windows)]
    {
        use tauri::Position;
        unsafe {
            let hwnd = GetForegroundWindow();
            let hmonitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
            let mut mi = MONITORINFO::default();
            mi.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
            if GetMonitorInfoW(hmonitor, &mut mi).as_bool() {
                let hdc = GetDC(None);
                let dpi = GetDeviceCaps(hdc, LOGPIXELSX) as f32;
                let _ = ReleaseDC(None, hdc);
                let scale = dpi / 96.0;
                let w = (520.0 * scale) as i32;
                let h = (320.0 * scale) as i32;
                let cx = (mi.rcWork.left + mi.rcWork.right) / 2;
                let cy = (mi.rcWork.top + mi.rcWork.bottom) / 2;
                let x = cx - w / 2;
                let y = cy - h / 2;
                let _ = window.set_position(Position::Physical(tauri::PhysicalPosition { x, y }));
            }
        }
    }

    window.show().map_err(|e| format!("Failed to show window: {}", e))?;
    window.set_focus().map_err(|e| format!("Failed to focus window: {}", e))?;
    Ok(())
}

// ==================== Tauri Commands ====================

/// Start the background process monitor (idempotent — does nothing if already running).
#[tauri::command]
async fn start_process_monitor(app: tauri::AppHandle) -> Result<(), String> {
    MONITOR_STOP.store(false, Ordering::SeqCst);
    tauri::async_runtime::spawn(async move {
        process_monitor_loop(app).await;
    });
    Ok(())
}

/// Enumerate running Windows processes.
#[tauri::command]
async fn get_running_processes() -> Result<Vec<serde_json::Value>, String> {
    get_running_processes_internal().await
}

/// Terminate a process by PID.
#[tauri::command]
async fn terminate_process(pid: u32) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        #[cfg(windows)]
        unsafe {
            use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
            use windows::Win32::Foundation::CloseHandle;

            let process_handle = OpenProcess(PROCESS_TERMINATE, false, pid);

            match process_handle {
                Ok(handle) => {
                    let result = TerminateProcess(handle, 1);
                    let _ = CloseHandle(handle);

                    if result.is_ok() {
                        Ok(())
                    } else {
                        Err("Failed to terminate process".to_string())
                    }
                }
                Err(e) => Err(format!("Failed to open process: {}", e)),
            }
        }

        #[cfg(not(windows))]
        {
            let _ = pid;
            Err("Not supported on this platform".to_string())
        }
    }).await.map_err(|e| format!("Task failed: {}", e))?
}

/// Suspend a process by PID using NtSuspendProcess.
#[tauri::command]
async fn suspend_process(pid: u32) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        suspend_process_internal(pid)
    }).await.map_err(|e| format!("Task failed: {}", e))?
}

/// Resume a process by PID using NtResumeProcess.
#[tauri::command]
async fn resume_process(pid: u32) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        resume_process_internal(pid)
    }).await.map_err(|e| format!("Task failed: {}", e))?
}

/// Read the suspicious intercept enabled setting from %LOCALAPPDATA%/XIGUASecurity/.
#[tauri::command]
fn get_suspicious_intercept_enabled() -> bool {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let path = format!("{}/XIGUASecurity/suspicious_intercept_enabled.txt", local_app_data);
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_lowercase() == "true")
        .unwrap_or(true)
}

/// Write the suspicious intercept enabled setting to %LOCALAPPDATA%/XIGUASecurity/.
#[tauri::command]
fn set_suspicious_intercept_enabled(enabled: bool) -> Result<(), String> {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let dir = format!("{}/XIGUASecurity", local_app_data);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = format!("{}/XIGUASecurity/suspicious_intercept_enabled.txt", local_app_data);
    std::fs::write(&path, if enabled { "true" } else { "false" }).map_err(|e| e.to_string())?;
    Ok(())
}

/// Create and display the suspicious file intercept window (Avast-style, centered on screen).
#[tauri::command]
async fn show_suspicious_intercept_window(
    app: tauri::AppHandle,
    file_name: String,
    file_path: String,
    pid: u32,
    confidence: f64,
) -> Result<(), String> {
    show_suspicious_intercept_window_internal(app, file_name, file_path, pid, confidence).await
}

/// Handle the user's decision from the intercept window (block=terminate, allow=resume).
#[tauri::command]
async fn send_suspicious_decision(app: tauri::AppHandle, decision: String, pid: u32) -> Result<(), String> {
    if decision == "block" {
        let _ = terminate_process(pid).await;
    } else {
        let _ = resume_process(pid).await;
    }
    if let Some(win) = app.get_webview_window("intercept-suspicious") {
        let _ = win.close();
    }
    Ok(())
}

/// Upload a file to the cloud sandbox for analysis, poll for the report, and return the verdict.
#[tauri::command]
async fn suspicious_analyze_file(_app: tauri::AppHandle, file_path: String, pid: u32) -> Result<serde_json::Value, String> {
    // Compute file SHA256
    let sha256 = {
        use std::io::Read;
        use sha2::Digest;
        let mut file = std::fs::File::open(&file_path).map_err(|e| e.to_string())?;
        let mut hasher = sha2::Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 { break; }
            hasher.update(&buf[..n]);
        }
        format!("{:x}", hasher.finalize())
    };

    eprintln!("[Suspicious] Starting cloud analysis: {} (SHA256: {})", file_path, sha256);

    // Upload to sandbox
    let client = reqwest::Client::new();
    let file_bytes = std::fs::read(&file_path).map_err(|e| e.to_string())?;
    let file_part = reqwest::multipart::Part::bytes(file_bytes)
        .file_name(std::path::Path::new(&file_path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string())
        .mime_str("application/octet-stream")
            .unwrap();

    let form = reqwest::multipart::Form::new()
        .part("file", file_part)
        .text("sandbox_type", "win10_22h2_enx64_office2019")
        .text("run_time", "120");

    let upload_resp = client
        .post(format!("{}/v3/file/upload", SANDBOX_RELAY_BASE))
        .header("X-API-Key", SANDBOX_API_KEY)
        .multipart(form)
        .send()
        .await
        .map_err(|e| format!("Upload failed: {}", e))?;

    let upload_json: serde_json::Value = upload_resp.json().await.map_err(|e| e.to_string())?;
    eprintln!("[Suspicious] Upload response: {}", serde_json::to_string(&upload_json).unwrap_or_default());

    // Poll for report (up to 180 seconds)
    let mut report: Option<serde_json::Value> = None;
    for i in 0..60 {
        if i > 0 {
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        }

        let report_resp = client
            .post(format!("{}/v3/file/report", SANDBOX_RELAY_BASE))
            .header("X-API-Key", SANDBOX_API_KEY)
            .json(&serde_json::json!({"resource": sha256}))
            .send()
            .await;

        match report_resp {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    let has_data = json.get("data").and_then(|d| d.as_object()).map(|o| !o.is_empty()).unwrap_or(false);
                    let rc = json.get("response_code").and_then(|c| c.as_i64()).unwrap_or(-99);
                    eprintln!("[Suspicious] Poll #{}: rc={}, has_data={}", i + 1, rc, has_data);
                    if rc == 0 && has_data {
                        report = Some(json);
                        break;
                    }
                }
            }
            Err(e) => {
                eprintln!("[Suspicious] Poll failed: {}", e);
            }
        }
    }

    let report = report.ok_or_else(|| "Cloud analysis timeout".to_string())?;

    // Parse result
    let data = report.get("data").cloned().unwrap_or(serde_json::Value::Null);
    let summary = data.get("summary").cloned().unwrap_or(serde_json::Value::Null);
    let multiengines = data.get("multiengines").cloned().unwrap_or(serde_json::Value::Null);

    let threat_score = summary.get("threat_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let detect_rate = multiengines.get("detect_rate").and_then(|v| v.as_str()).unwrap_or("0/0");

    // Verdict
    let detect_count = detect_rate.split('/').next().and_then(|s| s.parse::<i32>().ok()).unwrap_or(0);
    let verdict = if detect_count >= 5 || threat_score > 70.0 {
        "malicious"
    } else if detect_count >= 3 || threat_score > 50.0 {
        "suspicious"
    } else {
        "safe"
    };

    eprintln!("[Suspicious] Analysis complete: verdict={}, threat_score={}, detect_rate={}", verdict, threat_score, detect_rate);

    let _ = pid; // available for future use (e.g. auto-terminate on malicious)

    Ok(serde_json::json!({
        "verdict": verdict,
        "threat_score": threat_score,
        "detect_rate": detect_rate,
        "detect_count": detect_count,
        "data": data,
    }))
}

/// Simplified file scan: suspicious filename check + ONNX model scan.
/// If suspicious (filename match OR probability > 0.70), suspend process + show intercept window.
#[tauri::command]
async fn scan_file_basic(app: tauri::AppHandle, file_path: String, pid: Option<u32>, _pua_enabled: Option<bool>) -> Result<serde_json::Value, String> {
    // --- Check 1: Suspicious filename match ---
    if let Some(filename) = std::path::Path::new(&file_path).file_name() {
        if let Some(name) = filename.to_str() {
            let lower = name.to_lowercase();
            let is_suspicious = SUSPICIOUS_PROCESS_NAMES.iter().any(|&s| lower == s);
            let intercept_enabled = get_suspicious_intercept_enabled();
            eprintln!("[Suspicious] Filename check: name={}, is_suspicious={}, intercept_enabled={}", name, is_suspicious, intercept_enabled);
            if is_suspicious && intercept_enabled {
                eprintln!("[Suspicious] Matched suspicious list, suspending pid={:?}", pid);
                if let Some(process_pid) = pid {
                    match suspend_process(process_pid).await {
                        Ok(()) => eprintln!("[Suspicious] Process {} suspended", process_pid),
                        Err(e) => eprintln!("[Suspicious] Failed to suspend process: {}", e),
                    }
                }
                match show_suspicious_intercept_window(
                    app.clone(),
                    name.to_string(),
                    file_path.clone(),
                    pid.unwrap_or(0),
                    0.70,
                ).await {
                    Ok(()) => eprintln!("[Suspicious] Intercept window shown"),
                    Err(e) => eprintln!("[Suspicious] Failed to show intercept window: {}", e),
                }
                return Ok(serde_json::json!({
                    "isThreat": false,
                    "threatName": "",
                    "confidence": 0.70,
                    "result": "SUSPICIOUS",
                    "processName": name
                }));
            }
        }
    }

    // --- Check 2: ONNX model scan ---
    let (is_threat, threat_name, probability) = {
        let scanner = SCANNER.read().map_err(|e| e.to_string())?;
        let result = scanner.scan_file(&file_path, None);
        let is_threat = result.result == "MALICIOUS";
        let threat_name = if is_threat {
            result.virus_family.clone().unwrap_or_else(|| "Trojan.Win32.General".to_string())
        } else {
            String::new()
        };
        (is_threat, threat_name, result.probability)
    };

    // If probability > 0.70 and not already flagged as MALICIOUS, treat as suspicious
    let suspicious_enabled = get_suspicious_intercept_enabled();
    if !is_threat && probability > 0.70 && suspicious_enabled {
        if let Some(filename) = std::path::Path::new(&file_path).file_name() {
            let name = filename.to_string_lossy().to_string();
            eprintln!("[Suspicious] Suspicious file detected: {} (probability: {:.2})", name, probability);
            // Suspend process
            if let Some(process_pid) = pid {
                let _ = suspend_process(process_pid).await;
            }
            // Show intercept window
            let _ = show_suspicious_intercept_window(
                app.clone(),
                name,
                file_path.clone(),
                pid.unwrap_or(0),
                probability as f64,
            ).await;
            return Ok(serde_json::json!({
                "isThreat": false,
                "threatName": "",
                "confidence": probability,
                "result": "SUSPICIOUS",
                "processName": std::path::Path::new(&file_path).file_name().unwrap_or_default().to_string_lossy()
            }));
        }
    }

    Ok(serde_json::json!({
        "isThreat": is_threat,
        "threatName": threat_name,
        "confidence": probability,
        "result": if is_threat { "MALICIOUS" } else { "CLEAN" }
    }))
}
