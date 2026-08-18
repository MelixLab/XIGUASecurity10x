use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::{HWND, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WINTRUST_ACTION_GENERIC_VERIFY_V2,
    WINTRUST_DATA, WINTRUST_DATA_UICHOICE, WINTRUST_DATA_REVOCATION_CHECKS,
    WINTRUST_DATA_STATE_ACTION, WINTRUST_DATA_PROVIDER_FLAGS, WINTRUST_DATA_UICONTEXT,
    WINTRUST_FILE_INFO,
    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_LIFETIME_SIGNING_FLAG,
};
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows::core::{PCWSTR, PWSTR, GUID};

/// 签名验证结果
#[derive(Debug, Clone, PartialEq)]
pub enum SignatureStatus {
    Valid,           // 签名有效且可信
    Invalid,         // 签名无效
    NotSigned,       // 未签名
    Expired,         // 签名过期
    Revoked,         // 证书被吊销
    Unknown,         // 未知状态
}

impl SignatureStatus {
    pub fn is_trusted(&self) -> bool {
        matches!(self, SignatureStatus::Valid)
    }
}

/// 签名信息
#[derive(Debug, Clone)]
pub struct SignatureInfo {
    pub status: SignatureStatus,
    pub signer_name: Option<String>,
    pub timestamp: Option<String>,
    pub certificate_thumbprint: Option<String>,
}

/// 使用 WinVerifyTrust API 验证文件签名
pub fn verify_file_signature(file_path: &str) -> SignatureInfo {
    let wide_path: Vec<u16> = OsStr::new(file_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        // 设置 WinTrust 文件信息
        let file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide_path.as_ptr()),
            hFile: INVALID_HANDLE_VALUE,
            pgKnownSubject: std::ptr::null_mut(),
        };

        // 设置 GUID
        let action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // 设置 WinTrust 数据
        let mut trust_data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            pPolicyCallbackData: std::ptr::null_mut(),
            pSIPClientData: std::ptr::null_mut(),
            dwUIChoice: WTD_UI_NONE,
            // ★启用证书链吊销检查★：检查整个证书链（包括终端实体证书和中间CA证书）的吊销状态
            // 旧代码用 WTD_REVOKE_NONE 完全不检查吊销，被吊销的证书仍能通过验证
            fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: std::mem::zeroed(),
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: HANDLE(std::ptr::null_mut()),
            pwszURLReference: PWSTR(std::ptr::null_mut()),
            // ★启用吊销检查和有效期检查★：
            // WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT: 检查除根证书外的整个证书链的吊销状态
            //   （根证书通常不在 CRL 中，检查根证书会导致不必要的网络请求和超时）
            // WTD_LIFETIME_SIGNING_FLAG: 检查签名有效期，过期的签名不通过验证
            //   （如果没有此标志，WinVerifyTrust 不检查时间戳和有效期）
            dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(
                WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT.0 | WTD_LIFETIME_SIGNING_FLAG.0
            ),
            dwUIContext: WINTRUST_DATA_UICONTEXT(0),
            pSignatureSettings: std::ptr::null_mut(),
        };

        // 设置文件信息指针
        let file_info_ptr = &file_info as *const _ as *mut _;
        trust_data.Anonymous.pFile = file_info_ptr;

        // 调用 WinVerifyTrust
        let hwnd = HWND(std::ptr::null_mut());
        let result = WinVerifyTrust(
            hwnd,
            &action_guid as *const _ as *mut _,
            &mut trust_data as *mut _ as *mut _,
        );

        // 关闭验证状态
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(
            hwnd,
            &action_guid as *const _ as *mut _,
            &mut trust_data as *mut _ as *mut _,
        );

        // 解析结果 (HRESULT 是 i32 类型，错误码是负数)
        let status = match result {
            0 => SignatureStatus::Valid,  // ERROR_SUCCESS
            -2146762496 => SignatureStatus::Expired,  // TRUST_E_EXPIRED (0x800B0100)
            -2146762495 => SignatureStatus::Revoked,  // TRUST_E_REVOKED (0x800B0101)
            -2146762487 => SignatureStatus::Invalid,  // CERT_E_UNTRUSTEDROOT (0x800B0109) — 不可信的根证书
            -2146762486 => SignatureStatus::Invalid,  // CERT_E_CHAINING (0x800B010A) — 证书链不完整
            -2146762488 => SignatureStatus::Invalid,  // CERT_E_MALFORMED (0x800B0108) — 证书格式错误
            -2146762480 => SignatureStatus::Invalid,  // CERT_E_WRONG_USAGE (0x800B0110) — 证书用途错误
            -2146869239 => SignatureStatus::Invalid,  // TRUST_E_BAD_DIGEST (0x80096009) — 签名不匹配（文件被篡改）
            -2146869232 => SignatureStatus::Invalid,  // TRUST_E_CERT_SIGNATURE (0x80096010)
            -2146885358 => SignatureStatus::Invalid,  // CRYPT_E_REVOCATION_OFFLINE (0x80092012) — 吊销检查服务器不可达，保守视为无效
            -2146885629 => SignatureStatus::NotSigned, // CRYPT_E_FILE_ERROR (0x80092003)
            -2146762751 => SignatureStatus::NotSigned, // TRUST_E_PROVIDER_UNKNOWN (0x800B0001)
            -2146869231 => SignatureStatus::Invalid,  // TRUST_E_SUBJECT_NOT_TRUSTED (0x80096011)
            -2146869244 => SignatureStatus::Invalid,  // TRUST_E_SUBJECT_FORM_UNKNOWN (0x80096004)
            _ => {
                println!("[SignatureVerifier] Unknown error code: {} (0x{:08X})", result, result as u32);
                // 未知错误码：保守视为无效，不放行
                SignatureStatus::Invalid
            }
        };

        // 获取签名者信息
        let signer_name = get_signer_name(file_path);

        SignatureInfo {
            status,
            signer_name,
            timestamp: None,
            certificate_thumbprint: None,
        }
    }
}

/// 快速检查文件是否有有效签名（用于扫描时快速判断）
pub fn has_valid_signature(file_path: &str) -> bool {
    let info = verify_file_signature(file_path);
    info.status.is_trusted()
}

/// 获取签名者名称
fn get_signer_name(file_path: &str) -> Option<String> {
    let wide_path: Vec<u16> = OsStr::new(file_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        // 获取版本信息大小
        let size = GetFileVersionInfoSizeW(
            PCWSTR(wide_path.as_ptr()),
            None,
        );

        if size == 0 {
            return None;
        }

        // 分配缓冲区
        let mut buffer: Vec<u8> = vec![0; size as usize];

        // 获取版本信息
        if GetFileVersionInfoW(
            PCWSTR(wide_path.as_ptr()),
            0,
            size,
            buffer.as_mut_ptr() as *mut _,
        ).is_err() {
            return None;
        }

        // 查询签名者信息
        let sub_block: Vec<u16> = OsStr::new("\\StringFileInfo\\040904B0\\CompanyName")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut value_ptr: *mut u8 = std::ptr::null_mut();
        let mut value_len: u32 = 0;

        if VerQueryValueW(
            buffer.as_ptr() as *const _,
            PCWSTR(sub_block.as_ptr()),
            &mut value_ptr as *mut _ as *mut *mut _,
            &mut value_len,
        ).as_bool() && value_len > 0 && !value_ptr.is_null() {
            let company_name = std::slice::from_raw_parts(
                value_ptr as *const u16,
                value_len as usize / 2,
            );
            return String::from_utf16(company_name).ok();
        }

        None
    }
}

/// 检查文件是否有嵌入式签名
pub fn has_embedded_signature(file_path: &str) -> bool {
    has_valid_signature(file_path)
}

/// 检查文件是否有目录签名（Catalog签名）
pub fn has_catalog_signature(file_path: &str) -> bool {
    // 目录签名验证需要更复杂的实现
    // 这里简化处理，直接返回嵌入式签名结果
    has_embedded_signature(file_path)
}

/// 综合签名验证 - 检查所有类型的签名
pub fn verify_all_signatures(file_path: &str) -> SignatureInfo {
    // 首先检查嵌入式签名
    let embedded = verify_file_signature(file_path);
    
    if embedded.status.is_trusted() {
        return embedded;
    }

    // 如果嵌入式签名无效，检查目录签名
    // 注意：完整的目录签名验证需要实现更复杂的逻辑
    // 这里返回嵌入式签名的结果
    embedded
}

/// 获取签名的详细描述
pub fn get_signature_description(status: &SignatureStatus) -> &'static str {
    match status {
        SignatureStatus::Valid => "文件具有有效的数字签名",
        SignatureStatus::Invalid => "文件签名无效或已损坏",
        SignatureStatus::NotSigned => "文件没有数字签名",
        SignatureStatus::Expired => "文件签名证书已过期",
        SignatureStatus::Revoked => "文件签名证书已被吊销",
        SignatureStatus::Unknown => "无法验证文件签名",
    }
}
