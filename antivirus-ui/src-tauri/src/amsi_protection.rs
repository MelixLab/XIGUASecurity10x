//! AMSI (Anti-Malware Scan Interface) 集成模块
//!
//! 功能:
//!   1. 动态加载 amsi.dll, 通过 AmsiScanBuffer 扫描脚本/命令内容
//!   2. 检测 AMSI bypass (内存补丁/注册表禁用)
//!   3. 为 script_protection 和 behavior_engine 提供 AMSI 扫描能力

use std::ffi::c_void;
use std::sync::OnceLock;
use windows::Win32::System::LibraryLoader::{LoadLibraryW, GetProcAddress};
use windows::core::{PCWSTR, PCSTR};
use windows::Win32::Foundation::HMODULE;

type AmsiInitializeSessionFn = unsafe extern "system" fn(
    app_name: PCWSTR,
    session: *mut u64,
) -> i32;

type AmsiScanBufferFn = unsafe extern "system" fn(
    session: u64,
    buffer: *const c_void,
    length: usize,
    content_name: PCWSTR,
    result: *mut u32,
) -> i32;

type AmsiCloseSessionFn = unsafe extern "system" fn(
    session: u64,
);

#[derive(Debug, Clone, PartialEq)]
pub enum AmsiResult {
    Clean,
    Blocked,
    DetectedByAV,
    NotYetScanned,
    Error(String),
}

impl AmsiResult {
    pub fn is_malicious(&self) -> bool {
        matches!(self, AmsiResult::Blocked | AmsiResult::DetectedByAV)
    }
}

const AMSI_RESULT_CLEAN: u32 = 0;
const AMSI_RESULT_NOT_DETECTED: u32 = 1;
const AMSI_RESULT_BLOCKED_BY_ADMIN: u32 = 2;
const AMSI_RESULT_DETECTED: u32 = 32768;

/// AMSI API 句柄 (存储裸指针避免 Send/Sync 问题)
struct AmsiApi {
    module: isize,
    initialize_session: AmsiInitializeSessionFn,
    scan_buffer: AmsiScanBufferFn,
    close_session: AmsiCloseSessionFn,
    session: u64,
}

unsafe impl Send for AmsiApi {}
unsafe impl Sync for AmsiApi {}

static AMSI_API: OnceLock<Option<AmsiApi>> = OnceLock::new();

pub fn init() -> bool {
    get_or_init_amsi().is_some()
}

fn get_or_init_amsi() -> Option<&'static AmsiApi> {
    AMSI_API.get_or_init(|| unsafe {
        let module = LoadLibraryW(PCWSTR(
            encode_wide("amsi.dll").as_ptr(),
        ));

        let module = match module {
            Ok(h) => h,
            Err(_) => {
                crate::log_to_file("[AMSI] Failed to load amsi.dll");
                return None;
            }
        };

        let module_raw = module.0 as isize;

        let init_fn = GetProcAddress(module, PCSTR(b"AmsiInitializeSession\0".as_ptr()));
        let scan_fn = GetProcAddress(module, PCSTR(b"AmsiScanBuffer\0".as_ptr()));
        let close_fn = GetProcAddress(module, PCSTR(b"AmsiCloseSession\0".as_ptr()));

        let (init_fn, scan_fn, close_fn) = match (init_fn, scan_fn, close_fn) {
            (Some(i), Some(s), Some(c)) => (i, s, c),
            _ => {
                crate::log_to_file("[AMSI] Failed to get function addresses");
                return None;
            }
        };

        let initialize_session: AmsiInitializeSessionFn = std::mem::transmute(init_fn);
        let scan_buffer: AmsiScanBufferFn = std::mem::transmute(scan_fn);
        let close_session: AmsiCloseSessionFn = std::mem::transmute(close_fn);

        let app_name = encode_wide("XIGUASecurity");
        let mut session: u64 = 0;
        let status = initialize_session(PCWSTR(app_name.as_ptr()), &mut session);

        if status != 0 {
            crate::log_to_file(&format!("[AMSI] AmsiInitializeSession failed: 0x{:08X}", status as u32));
            return None;
        }

        crate::log_to_file(&format!("[AMSI] Session initialized (id={})", session));

        Some(AmsiApi {
            module: module_raw,
            initialize_session,
            scan_buffer,
            close_session,
            session,
        })
    })
    .as_ref()
}

pub fn scan_string(content: &str, content_name: &str) -> AmsiResult {
    scan_bytes(content.as_bytes(), content_name)
}

pub fn scan_bytes(content: &[u8], content_name: &str) -> AmsiResult {
    let api = match get_or_init_amsi() {
        Some(api) => api,
        None => return AmsiResult::Error("AMSI not available".into()),
    };

    let content_name_wide = encode_wide(content_name);
    let mut result: u32 = 0;

    let status = unsafe {
        (api.scan_buffer)(
            api.session,
            content.as_ptr() as *const c_void,
            content.len(),
            PCWSTR(content_name_wide.as_ptr()),
            &mut result,
        )
    };

    if status != 0 {
        return AmsiResult::Error(format!("AmsiScanBuffer failed: 0x{:08X}", status as u32));
    }

    match result {
        AMSI_RESULT_CLEAN => AmsiResult::Clean,
        AMSI_RESULT_NOT_DETECTED => AmsiResult::NotYetScanned,
        AMSI_RESULT_BLOCKED_BY_ADMIN => AmsiResult::Blocked,
        v if v >= AMSI_RESULT_DETECTED => AmsiResult::DetectedByAV,
        _ => AmsiResult::NotYetScanned,
    }
}

//=============================================================================
// AMSI Bypass 检测
//=============================================================================

pub fn check_amsi_bypass() -> bool {
    if check_amsi_function_patched() {
        crate::log_to_file("[AMSI] WARNING: AmsiScanBuffer appears to be patched!");
        return true;
    }

    if check_amsi_registry_disabled() {
        crate::log_to_file("[AMSI] WARNING: AMSI is disabled via registry!");
        return true;
    }

    false
}

fn check_amsi_function_patched() -> bool {
    let api = match get_or_init_amsi() {
        Some(api) => api,
        None => return false,
    };

    unsafe {
        let module = HMODULE(api.module as *mut c_void);
        let fn_addr = GetProcAddress(module, PCSTR(b"AmsiScanBuffer\0".as_ptr()));
        let fn_addr = match fn_addr {
            Some(f) => f,
            None => return false,
        };

        let ptr = fn_addr as *const u8;

        let mut bytes = [0u8; 16];
        std::ptr::copy_nonoverlapping(ptr, bytes.as_mut_ptr(), 16);

        // ret (0xC3) - 函数直接返回
        if bytes[0] == 0xC3 {
            return true;
        }

        // mov eax, imm32; ret - 返回固定值
        if bytes[0] == 0xB8 && bytes[5] == 0xC3 {
            return true;
        }

        // 全 NOP 填充
        if bytes.iter().take(8).all(|&b| b == 0x90) {
            return true;
        }
    }

    false
}

fn check_amsi_registry_disabled() -> bool {
    use windows::Win32::System::Registry::{
        RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER,
        KEY_READ,
    };

    unsafe {
        let subkey = encode_wide("SOFTWARE\\Microsoft\\Windows Script\\Settings");
        let value = encode_wide("AmsiEnable");

        for hive in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
            let mut hkey: HKEY = std::mem::zeroed();
            let status = RegOpenKeyExW(
                hive,
                PCWSTR(subkey.as_ptr()),
                0,
                KEY_READ,
                &mut hkey,
            );

            if status.is_ok() {
                let mut data: u32 = 0;
                let mut data_len: u32 = std::mem::size_of::<u32>() as u32;
                let status = RegQueryValueExW(
                    hkey,
                    PCWSTR(value.as_ptr()),
                    None,
                    None,
                    Some(&mut data as *mut _ as *mut u8),
                    Some(&mut data_len),
                );

                if status.is_ok() && data == 0 {
                    return true;
                }
            }
        }
    }

    false
}

fn encode_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 扫描脚本命令并返回威胁级别
pub fn scan_script_command(
    process_name: &str,
    command_line: &str,
) -> (AmsiResult, Option<String>) {
    if check_amsi_bypass() {
        return (
            AmsiResult::Error("AMSI bypass detected".into()),
            Some("AMSI已被禁用或补丁，脚本内容无法通过AMSI扫描".into()),
        );
    }

    let content_name = format!("{}-script", process_name);
    let result = scan_string(command_line, &content_name);

    let message = match &result {
        AmsiResult::Blocked => Some(format!("AMSI拦截: {} 执行的脚本被判定为恶意", process_name)),
        AmsiResult::DetectedByAV => Some(format!("AMSI检测: {} 执行的脚本被判定为恶意", process_name)),
        AmsiResult::Clean => None,
        AmsiResult::NotYetScanned => None,
        AmsiResult::Error(e) => Some(format!("AMSI扫描失败: {}", e)),
    };

    (result, message)
}

pub fn periodic_integrity_check() -> bool {
    let bypassed = check_amsi_bypass();
    if bypassed {
        crate::log_to_file("[AMSI] INTEGRITY CHECK FAILED: AMSI bypass detected!");
    }
    !bypassed
}
