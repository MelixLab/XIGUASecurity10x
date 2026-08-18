use std::process::Command;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

const CREATE_NO_WINDOW: u32 = 0x08000000;

pub struct WscRegistrar {
    app_handle: AppHandle,
}

impl WscRegistrar {
    pub fn new(app_handle: AppHandle) -> Self {
        Self { app_handle }
    }

    fn get_defendnot_loader_path(&self) -> PathBuf {
        // 首先尝试从资源目录查找
        if let Ok(resource_dir) = self.app_handle.path().resource_dir() {
            let path = resource_dir.join("defendnot-loader.exe");
            if path.exists() {
                return path;
            }
        }
        
        // 然后尝试从应用程序目录查找
        if let Ok(app_dir) = self.app_handle.path().app_local_data_dir() {
            let path = app_dir.parent().unwrap_or(&app_dir).join("defendnot-loader.exe");
            if path.exists() {
                return path;
            }
        }
        
        // 最后尝试当前工作目录
        PathBuf::from("defendnot-loader.exe")
    }

    fn get_defendnot_dll_path(&self) -> PathBuf {
        // 首先尝试从资源目录查找
        if let Ok(resource_dir) = self.app_handle.path().resource_dir() {
            let path = resource_dir.join("defendnot.dll");
            if path.exists() {
                return path;
            }
        }
        
        // 然后尝试从应用程序目录查找
        if let Ok(app_dir) = self.app_handle.path().app_local_data_dir() {
            let path = app_dir.parent().unwrap_or(&app_dir).join("defendnot.dll");
            if path.exists() {
                return path;
            }
        }
        
        // 最后尝试当前工作目录
        PathBuf::from("defendnot.dll")
    }

    pub fn register_as_antivirus(&self, app_name: &str) -> Result<(), String> {
        let loader_path = self.get_defendnot_loader_path();
        let dll_path = self.get_defendnot_dll_path();
        
        if !loader_path.exists() {
            return Err(format!("defendnot-loader.exe not found at: {:?}", loader_path));
        }
        
        if !dll_path.exists() {
            return Err(format!("defendnot.dll not found at: {:?}", dll_path));
        }

        println!("[WSC] Using defendnot-loader: {:?}", loader_path);
        println!("[WSC] Using defendnot.dll: {:?}", dll_path);
        println!("[WSC] Registering as: {}", app_name);

        // 调用 defendnot-loader 进行注册（自动申请管理员权限）
        let output = Command::new("powershell.exe")
            .args(&[
                "-Command",
                &format!(
                    "Start-Process -FilePath '{}' -ArgumentList '--name','{}','--silent' -Verb RunAs -Wait",
                    loader_path.to_string_lossy().replace("'", "''"),
                    app_name.replace("'", "''")
                )
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("Failed to execute defendnot-loader: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        println!("[WSC] stdout: {}", stdout);
        println!("[WSC] stderr: {}", stderr);

        if output.status.success() {
            println!("[WSC] Successfully registered as antivirus");
            Ok(())
        } else {
            Err(format!("defendnot-loader failed with exit code: {}\nstderr: {}", 
                output.status.code().unwrap_or(-1), stderr))
        }
    }

    pub fn unregister(&self) -> Result<(), String> {
        let loader_path = self.get_defendnot_loader_path();
        
        if !loader_path.exists() {
            return Err(format!("defendnot-loader.exe not found at: {:?}", loader_path));
        }

        println!("[WSC] Unregistering from WSC...");

        // 调用 defendnot-loader 进行注销（自动申请管理员权限）
        let output = Command::new("powershell.exe")
            .args(&[
                "-Command",
                &format!(
                    "Start-Process -FilePath '{}' -ArgumentList '--disable','--silent' -Verb RunAs -Wait",
                    loader_path.to_string_lossy().replace("'", "''")
                )
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("Failed to execute defendnot-loader: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        println!("[WSC] stdout: {}", stdout);
        println!("[WSC] stderr: {}", stderr);

        if output.status.success() {
            println!("[WSC] Successfully unregistered");
            Ok(())
        } else {
            Err(format!("defendnot-loader failed with exit code: {}\nstderr: {}", 
                output.status.code().unwrap_or(-1), stderr))
        }
    }
}

#[tauri::command]
pub async fn register_wd_replacement(app_handle: AppHandle, app_name: String) -> Result<bool, String> {
    // Command::output() 会触发 UAC 弹窗并 -Wait 等待用户确认（可能数十秒），
    // 属于阻塞 IO，移入 spawn_blocking 避免占用 async 运行时工作线程
    tokio::task::spawn_blocking(move || {
        let registrar = WscRegistrar::new(app_handle);
        match registrar.register_as_antivirus(&app_name) {
            Ok(_) => Ok(true),
            Err(e) => {
                eprintln!("[WSC] Registration failed: {}", e);
                Err(e)
            }
        }
    }).await.map_err(|e| format!("注册任务失败: {}", e))?
}

#[tauri::command]
pub async fn unregister_wd_replacement(app_handle: AppHandle) -> Result<bool, String> {
    // 同上：Command::output() 会触发 UAC 弹窗并等待，移入 spawn_blocking
    tokio::task::spawn_blocking(move || {
        let registrar = WscRegistrar::new(app_handle);
        match registrar.unregister() {
            Ok(_) => Ok(true),
            Err(e) => {
                eprintln!("[WSC] Unregistration failed: {}", e);
                Err(e)
            }
        }
    }).await.map_err(|e| format!("注销任务失败: {}", e))?
}
