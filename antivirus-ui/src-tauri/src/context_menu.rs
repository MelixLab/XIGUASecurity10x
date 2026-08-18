use std::process::Command;
use std::os::windows::process::CommandExt;
use windows::Win32::System::Registry::{HKEY_CURRENT_USER, RegCreateKeyExW, RegSetValueExW, RegDeleteKeyW, RegCloseKey, RegOpenKeyExW, HKEY, KEY_WRITE, KEY_READ, REG_SZ, REG_OPEN_CREATE_OPTIONS};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::core::PCWSTR;

const APP_NAME: &str = "XIGUASecurity";
const MENU_TEXT: &str = "使用XIGUASecurity扫描";

// 隐藏窗口标志
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// 将字符串转换为宽字符串（以null结尾）
fn to_wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 注册右键菜单（写入当前用户，不需要管理员权限）
pub fn register_context_menu() -> Result<(), String> {
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get exe path: {}", e))?
        .to_string_lossy()
        .to_string();

    // 注册到 HKEY_CURRENT_USER\Software\Classes，不需要管理员权限
    register_user_context_menu("*", &exe_path)?;
    register_user_context_menu("Directory", &exe_path)?;
    register_user_context_menu("Drive", &exe_path)?;

    Ok(())
}

/// 注册单个用户级右键菜单
fn register_user_context_menu(key: &str, exe_path: &str) -> Result<(), String> {
    let key_path = format!("Software\\Classes\\{}\\shell\\{}", key, APP_NAME);
    // 使用 %L 获取长路径，避免短路径/Unicode/空格问题；exe 路径和目标路径都加引号
    let command = format!("\"{}\" --scan \"%L\"", exe_path);

    unsafe {
        // 创建主键
        let mut hkey: HKEY = std::mem::zeroed();
        let key_wide = to_wide_string(&key_path);
        let result = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(key_wide.as_ptr()),
            0,
            None,
            REG_OPEN_CREATE_OPTIONS(0),
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        );

        if result != ERROR_SUCCESS {
            return Err(format!("Failed to create registry key: {:?}", result));
        }

        // 设置显示文本
        let text_wide = to_wide_string(MENU_TEXT);
        let _ = RegSetValueExW(
            hkey,
            None,
            0,
            REG_SZ,
            Some(std::slice::from_raw_parts(
                text_wide.as_ptr() as *const u8,
                text_wide.len() * 2 - 2,
            )),
        );

        // 设置图标
        let icon_wide = to_wide_string(exe_path);
        let icon_name = to_wide_string("Icon");
        let _ = RegSetValueExW(
            hkey,
            PCWSTR(icon_name.as_ptr()),
            0,
            REG_SZ,
            Some(std::slice::from_raw_parts(
                icon_wide.as_ptr() as *const u8,
                icon_wide.len() * 2 - 2,
            )),
        );

        let _ = RegCloseKey(hkey);

        // 创建 command 子键
        let command_key_path = format!("Software\\Classes\\{}\\shell\\{}\\command", key, APP_NAME);
        let mut hkey_command: HKEY = std::mem::zeroed();
        let command_key_wide = to_wide_string(&command_key_path);
        let result = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(command_key_wide.as_ptr()),
            0,
            None,
            REG_OPEN_CREATE_OPTIONS(0),
            KEY_WRITE,
            None,
            &mut hkey_command,
            None,
        );

        if result != ERROR_SUCCESS {
            return Err(format!("Failed to create command registry key: {:?}", result));
        }

        // 设置命令值
        let command_wide = to_wide_string(&command);
        let _ = RegSetValueExW(
            hkey_command,
            None,
            0,
            REG_SZ,
            Some(std::slice::from_raw_parts(
                command_wide.as_ptr() as *const u8,
                command_wide.len() * 2 - 2,
            )),
        );

        let _ = RegCloseKey(hkey_command);
    }

    Ok(())
}

/// 注销右键菜单（当前用户级别）
pub fn unregister_context_menu() -> Result<(), String> {
    delete_user_context_menu("*")?;
    delete_user_context_menu("Directory")?;
    delete_user_context_menu("Drive")?;

    Ok(())
}

/// 删除单个用户级右键菜单
fn delete_user_context_menu(key: &str) -> Result<(), String> {
    let key_path = format!("Software\\Classes\\{}\\shell\\{}", key, APP_NAME);

    unsafe {
        // 先删除 command 子键
        let command_key_path = format!("{}\\command", key_path);
        let command_key_wide = to_wide_string(&command_key_path);
        let _ = RegDeleteKeyW(HKEY_CURRENT_USER, PCWSTR(command_key_wide.as_ptr()));

        // 删除主键
        let key_wide = to_wide_string(&key_path);
        let result = RegDeleteKeyW(HKEY_CURRENT_USER, PCWSTR(key_wide.as_ptr()));

        if result != ERROR_SUCCESS && result.0 != 2 {
            return Err(format!("Failed to delete registry key: {:?}", result));
        }
    }

    Ok(())
}

/// 检查右键菜单是否已注册
pub fn is_context_menu_registered() -> bool {
    unsafe {
        let key_path = format!("Software\\Classes\\*\\shell\\{}", APP_NAME);
        let key_wide = to_wide_string(&key_path);
        
        let mut hkey: HKEY = std::mem::zeroed();
        let result = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(key_wide.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        );

        if result == ERROR_SUCCESS {
            let _ = RegCloseKey(hkey);
            true
        } else {
            false
        }
    }
}

/// Tauri 命令：注册右键菜单
#[tauri::command]
pub async fn register_context_menu_command() -> Result<bool, String> {
    match register_context_menu() {
        Ok(_) => Ok(true),
        Err(e) => Err(e),
    }
}

/// Tauri 命令：注销右键菜单
#[tauri::command]
pub async fn unregister_context_menu_command() -> Result<bool, String> {
    match unregister_context_menu() {
        Ok(_) => Ok(true),
        Err(e) => Err(e),
    }
}

/// Tauri 命令：检查右键菜单状态
#[tauri::command]
pub async fn is_context_menu_registered_command() -> Result<bool, String> {
    Ok(is_context_menu_registered())
}
