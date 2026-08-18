use std::io::{Read, Cursor};
use std::path::Path;
use serde::{Deserialize, Serialize};

/// 压缩包内文件扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveFileResult {
    /// 压缩包路径
    pub archive_path: String,
    /// 压缩包内文件路径
    pub inner_path: String,
    /// 文件大小
    pub size: u64,
    /// 扫描结果
    pub scan_result: Option<crate::scanner::ScanResult>,
    /// 是否加密
    pub is_encrypted: bool,
    /// 错误信息
    pub error: Option<String>,
}

/// 压缩包扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveScanResult {
    /// 压缩包路径
    pub archive_path: String,
    /// 压缩包类型
    pub archive_type: String,
    /// 内文件扫描结果列表
    pub files: Vec<ArchiveFileResult>,
    /// 是否有密码保护
    pub has_password: bool,
    /// 错误信息
    pub error: Option<String>,
}

/// 检查文件是否为压缩包或安装包
pub fn is_archive_file(file_path: &str) -> Option<&'static str> {
    let path = Path::new(file_path);
    let ext = path.extension()?.to_str()?.to_lowercase();
    
    match ext.as_str() {
        "zip" => Some("zip"),
        "rar" => Some("rar"),
        "7z" => Some("7z"),
        "tar" => Some("tar"),
        "gz" | "tgz" => Some("gzip"),
        "bz2" => Some("bzip2"),
        "xz" => Some("xz"),
        "msi" => Some("installer"),         // MSI 安装包
        "exe" => {
            // 先检查是否为安装包/打包器（NSIS/Inno/InstallShield 等）
            if detect_installer_type(file_path).is_some() {
                Some("installer")
            } else if is_self_extracting_exe(file_path) {
                // 再检查是否为自解压程序（嵌入式 ZIP/7z/RAR）
                Some("sfx")
            } else {
                None
            }
        }
        _ => None,
    }
}

// ==================== 安装包/打包器检测 ====================

/// 已知安装包/打包器类型
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InstallerType {
    /// Nullsoft Scriptable Install System
    NSIS,
    /// Inno Setup
    InnoSetup,
    /// InstallShield
    InstallShield,
    /// WISE Installer
    WISE,
    /// Setup Factory (Indigo Rose)
    SetupFactory,
    /// Microsoft Windows Installer (.msi)
    Msi,
}

impl InstallerType {
    /// 返回类型标识符（用于 archive_type 字段）
    pub fn as_str(&self) -> &'static str {
        match self {
            InstallerType::NSIS => "nsis",
            InstallerType::InnoSetup => "inno",
            InstallerType::InstallShield => "installshield",
            InstallerType::WISE => "wise",
            InstallerType::SetupFactory => "setup_factory",
            InstallerType::Msi => "msi",
        }
    }

    /// 返回可读的名称
    pub fn display_name(&self) -> &'static str {
        match self {
            InstallerType::NSIS => "NSIS 安装包",
            InstallerType::InnoSetup => "Inno Setup 安装包",
            InstallerType::InstallShield => "InstallShield 安装包",
            InstallerType::WISE => "WISE 安装包",
            InstallerType::SetupFactory => "Setup Factory 安装包",
            InstallerType::Msi => "MSI 安装包",
        }
    }
}

// NSIS 签名特征（在 PE 覆盖区 / .rdata 段中查找）
// 来源: https://nsis.sourceforge.io/Can_I_decompile_an_existing_installer%3F
const NSIS_SIGNATURES: &[&[u8]] = &[
    b"\xED\xBE\xAD\xDE\x4E\x75\x6C\x6C\x53\x6F\x66\x74\x49\x6E\x73\x74", // v1.1e: NullsoftInst
    b"\xEF\xBE\xAD\xDE\x4E\x75\x6C\x6C\x53\x6F\x66\x74\x49\x6E\x73\x74", // v1.30+: NullsoftInst
    b"\xEF\xBE\xAD\xDE\x4E\x75\x6C\x6C\x73\x6F\x66\x74\x49\x6E\x73\x74", // v1.60b2+: nullsoftInst
];

// Inno Setup 签名（字符串资源中）
const INNO_SIGNATURES: &[&[u8]] = &[
    b"Inno Setup",
    b"jrsoftware",
];

// InstallShield 签名
const INSTALLSHIELD_SIGNATURES: &[&[u8]] = &[
    b"InstallShield",
    b"Install Shield",
    b"ISSetup",
];

// WISE Installer 签名
const WISE_SIGNATURES: &[&[u8]] = &[
    b"WISE",
    b"WISE_INSTALLER",
];

// Setup Factory (Indigo Rose) 签名
const SETUP_FACTORY_SIGNATURES: &[&[u8]] = &[
    b"Setup Factory",
    b"Indigo Rose",
    b"SETUPFACTORY",
];

// MSI 文件头（OLE2 Compound Document）
const MSI_HEADER: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// 检测安装包／打包器类型
/// 支持：NSIS, Inno Setup, InstallShield, WISE, Setup Factory, MSI
pub fn detect_installer_type(file_path: &str) -> Option<InstallerType> {
    let path = std::path::Path::new(file_path);
    let ext = path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase());

    // MSI 文件：扩展名 + OLE2 文件头检测
    if ext.as_deref() == Some("msi") {
        if let Ok(data) = std::fs::read(file_path) {
            if data.len() >= 8 && &data[..8] == MSI_HEADER {
                return Some(InstallerType::Msi);
            }
        }
        return None; // 不是合法的 MSI
    }

    // 以下检测仅针对 .exe 文件
    if ext.as_deref() != Some("exe") {
        return None;
    }

    let data = match std::fs::read(file_path) {
        Ok(d) => d,
        Err(_) => return None,
    };

    if data.len() < 1024 {
        return None;
    }

    // 安装包签名通常位于文件前 1MB 范围内（PE 头 + 段表 + .rdata）
    let search_end = std::cmp::min(data.len(), 1024 * 1024);
    let search_data = &data[..search_end];

    // 检查 NSIS 签名（精准匹配）
    for sig in NSIS_SIGNATURES {
        if search_data.windows(sig.len()).any(|w| w == *sig) {
            return Some(InstallerType::NSIS);
        }
    }

    // 检查 Inno Setup 签名
    for sig in INNO_SIGNATURES {
        if search_data.windows(sig.len()).any(|w| w == *sig) {
            return Some(InstallerType::InnoSetup);
        }
    }

    // 检查 InstallShield 签名
    for sig in INSTALLSHIELD_SIGNATURES {
        if search_data.windows(sig.len()).any(|w| w == *sig) {
            return Some(InstallerType::InstallShield);
        }
    }

    // 检查 WISE 签名
    for sig in WISE_SIGNATURES {
        if search_data.windows(sig.len()).any(|w| w == *sig) {
            return Some(InstallerType::WISE);
        }
    }

    // 检查 Setup Factory 签名
    for sig in SETUP_FACTORY_SIGNATURES {
        if search_data.windows(sig.len()).any(|w| w == *sig) {
            return Some(InstallerType::SetupFactory);
        }
    }

    None
}

/// 查找 7z.exe（优先应用内置，其次系统安装路径）
fn find_7z_exe() -> Option<std::path::PathBuf> {
    // 1. 从可执行文件同目录查找 Driver\7z.exe
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(dir) = exe_path.parent() {
            let bundled = dir.join("Driver").join("7z.exe");
            if bundled.exists() {
                return Some(bundled);
            }
            // 也可能直接放在 exe 同目录
            let beside = dir.join("7z.exe");
            if beside.exists() {
                return Some(beside);
            }
        }
    }

    // 2. 检查系统安装路径
    for p in [
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
    ] {
        if std::path::Path::new(p).exists() {
            return Some(std::path::PathBuf::from(p));
        }
    }

    None
}

/// 使用 7z 解压安装包到临时目录（支持 NSIS、Inno、MSI CAB、InstallShield 等）
fn try_extract_with_7z(installer_path: &str) -> Option<std::path::PathBuf> {
    let seven_zip = find_7z_exe()?;
    let temp_dir = std::env::temp_dir().join(format!("xigua_7z_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let temp_str = temp_dir.to_str()?;

    let output = std::process::Command::new(&seven_zip)
        .args(["x", installer_path, &format!("-o{}", temp_str), "-y"])
        .output()
        .ok()?;

    if output.status.success() {
        Some(temp_dir)
    } else {
        let _ = std::fs::remove_dir_all(&temp_dir);
        None
    }
}

/// 尝试用 msiexec /a 管理安装提取 MSI（Windows 内置，无需额外工具）
fn try_extract_msi(msi_path: &str) -> Option<std::path::PathBuf> {
    let temp_dir = std::env::temp_dir().join(format!("xigua_msi_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let temp_str = temp_dir.to_str()?;

    // msiexec /a "file.msi" /qn TARGETDIR="C:\temp" 完全静默管理安装
    let output = std::process::Command::new("msiexec")
        .args(["/a", msi_path, "/qn", &format!("TARGETDIR=\"{}\"", temp_str)])
        .output()
        .ok()?;

    if output.status.success() {
        Some(temp_dir)
    } else {
        let _ = std::fs::remove_dir_all(&temp_dir);
        None
    }
}

/// 扫描安装包：跳过引擎→尝试解包→扫描内部文件
fn scan_installer_in_memory(
    installer_path: &str,
    scanner: &crate::scanner::Scanner,
) -> ArchiveScanResult {
    let installer_type = detect_installer_type(installer_path)
        .unwrap_or(InstallerType::Msi);
    let archive_type_str = installer_type.as_str().to_string();

    // 收集解压目录中的文件并扫描
    let mut scan_extracted = |extract_dir: std::path::PathBuf| -> Vec<ArchiveFileResult> {
        let mut results = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&extract_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let path_str = path.to_string_lossy().to_string();
                    if is_executable_by_extension(&path_str) {
                        if let Ok(data) = std::fs::read(&path) {
                            let inner_result = scan_memory_buffer(&data, &path_str, scanner);
                            results.push(ArchiveFileResult {
                                archive_path: installer_path.to_string(),
                                inner_path: path_str,
                                size: data.len() as u64,
                                scan_result: Some(inner_result),
                                is_encrypted: false,
                                error: None,
                            });
                        }
                    }
                }
            }
        }
        let _ = std::fs::remove_dir_all(&extract_dir);
        results
    };

    // 尝试收集解压出的文件列表
    let mut files: Vec<ArchiveFileResult> = Vec::new();

    // 1. 优先用 7z 解包（NSIS、Inno、InstallShield 等均支持）
    if installer_type != InstallerType::Msi {
        if let Some(extract_dir) = try_extract_with_7z(installer_path) {
            files = scan_extracted(extract_dir);
        }
    }

    // 2. MSI 安装包 → 用 msiexec /a 解包
    if files.is_empty() && installer_type == InstallerType::Msi {
        if let Some(extract_dir) = try_extract_msi(installer_path) {
            files = scan_extracted(extract_dir);
        }
    }

    // 2. 尝试嵌入式 ZIP 检测（NSIS/Inno 等安装包可能嵌入 ZIP 压缩数据）
    if files.is_empty() {
        if let Ok(data) = std::fs::read(installer_path) {
            // 检查 EXE 是否以 ZIP 头开头（纯 ZIP SFX 格式）
            if data.len() > 4 && &data[..4] == b"PK\x03\x04" {
                let mut result = scan_zip_in_memory(installer_path, scanner);
                result.archive_type = archive_type_str;
                return result;
            }
            // 在文件末尾搜索 ZIP 中央目录结尾签名（常见嵌入式 ZIP）
            if data.len() > 22 {
                let end_sig = b"PK\x05\x06";
                if data[data.len()-22..].windows(4).any(|w| w == end_sig) {
                    // 有嵌入式 ZIP 尾巴，尝试提取
                    let mut result = scan_zip_in_memory(installer_path, scanner);
                    result.archive_type = archive_type_str;
                    return result;
                }
            }
        }
    }

    // 3. 返回结果（可能无内部文件——解包能力有限，但引擎已跳过）
    let has_files = !files.is_empty();
    ArchiveScanResult {
        archive_path: installer_path.to_string(),
        archive_type: archive_type_str,
        files,
        has_password: false,
        error: if has_files { None } else { Some("Installer extraction not available, engine skipped".to_string()) },
    }
}

/// 检查是否为自解压安装程序
fn is_self_extracting_exe(file_path: &str) -> bool {
    // 读取文件头部检查是否为自解压程序
    if let Ok(data) = std::fs::read(file_path) {
        // 检查 ZIP 签名 (PK)
        if data.len() > 4 && &data[0..4] == b"PK\x03\x04" {
            return true;
        }
        // 检查 7z 签名
        if data.len() > 6 && &data[0..6] == b"7z\xBC\xAF\x27\x1C" {
            return true;
        }
        // 检查 RAR 签名
        if data.len() > 7 && (&data[0..7] == b"Rar!\x1a\x07\x00" || &data[0..7] == b"Rar!\x1a\x07\x01") {
            return true;
        }
    }
    false
}

/// 检查是否为 PE 文件（通过文件头判断）
fn is_pe_file(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    // 检查 MZ 头 (0x4D 0x5A) 或 "MZ"
    if data[0] == b'M' && data[1] == b'Z' {
        return true;
    }
    false
}

/// 检查文件扩展名是否为可执行文件或脚本
fn is_executable_by_extension(file_path: &str) -> bool {
    let path = Path::new(file_path);
    if let Some(ext) = path.extension() {
        let ext = ext.to_str().unwrap_or("").to_lowercase();
        // PE 文件扩展名
        if ["exe", "dll", "sys", "drv", "ocx", "scr", "com"].contains(&ext.as_str()) {
            return true;
        }
        // 脚本文件扩展名
        if is_script_file(file_path) {
            return true;
        }
    }
    false
}

/// 检查是否为脚本文件
fn is_script_file(file_path: &str) -> bool {
    let path = Path::new(file_path);
    if let Some(ext) = path.extension() {
        let ext = ext.to_str().unwrap_or("").to_lowercase();
        return ["bat", "cmd", "ps1", "vbs", "js", "wsf", "wsh"].contains(&ext.as_str());
    }
    false
}

/// 使用脚本扫描引擎扫描内存中的脚本文件
fn scan_script_in_memory(buffer: &[u8], file_name: &str) -> crate::scanner::ScanResult {
    use crate::scanner::scan_script_buffer;
    
    match scan_script_buffer(buffer, file_name) {
        Some(script_result) => crate::scanner::ScanResult {
            file_path: file_name.to_string(),
            file_hash: None,
            result: if script_result.is_malicious { "MALICIOUS".to_string() } else { "CLEAN".to_string() },
            probability: script_result.threat_level,
            signature_status: Some("Script scan".to_string()),
            is_trusted: false,
            error: None,
            virus_family: script_result.virus_family,
            family_category: None,
            is_infector: false,
        },
        None => crate::scanner::ScanResult {
            file_path: file_name.to_string(),
            file_hash: None,
            result: "CLEAN".to_string(),
            probability: 0.0,
            signature_status: Some("Script scan".to_string()),
            is_trusted: false,
            error: None,
            virus_family: None,
            family_category: None,
            is_infector: false,
        },
    }
}

/// 扫描压缩包（内存中解压）
pub fn scan_archive_in_memory(
    archive_path: &str,
    scanner: &crate::scanner::Scanner,
) -> ArchiveScanResult {
    let archive_type = match is_archive_file(archive_path) {
        Some(t) => t,
        None => {
            return ArchiveScanResult {
                archive_path: archive_path.to_string(),
                archive_type: "unknown".to_string(),
                files: vec![],
                has_password: false,
                error: Some("Not a supported archive file".to_string()),
            };
        }
    };

    match archive_type {
        "zip" | "sfx" => scan_zip_in_memory(archive_path, scanner),
        "7z" => scan_7z_in_memory(archive_path, scanner),
        "installer" => scan_installer_in_memory(archive_path, scanner),
        _ => ArchiveScanResult {
            archive_path: archive_path.to_string(),
            archive_type: archive_type.to_string(),
            files: vec![],
            has_password: false,
            error: Some("Archive type not yet supported for memory scanning".to_string()),
        },
    }
}

/// 常用密码列表
const COMMON_PASSWORDS: &[&str] = &[
    "infected",
    "123456",
    "12345678",
    "password",
    "1234",
    "12345",
    "123456789",
    "qwerty",
    "abc123",
    "password1",
    "111111",
    "000000",
    "666666",
    "888888",
    "999999",
    "virus",
    "malware",
    "sample",
    "test",
];

/// 在内存中扫描 ZIP 文件
fn scan_zip_in_memory(
    archive_path: &str,
    scanner: &crate::scanner::Scanner,
) -> ArchiveScanResult {
    let file_data = match std::fs::read(archive_path) {
        Ok(data) => data,
        Err(e) => {
            return ArchiveScanResult {
                archive_path: archive_path.to_string(),
                archive_type: "zip".to_string(),
                files: vec![],
                has_password: false,
                error: Some(format!("Failed to read archive: {}", e)),
            };
        }
    };

    // 首先检查是否需要密码，在一个独立的作用域中
    let (needs_password, password_found) = {
        let cursor = Cursor::new(&file_data);
        let mut test_archive = match zip::ZipArchive::new(cursor) {
            Ok(archive) => archive,
            Err(_) => {
                return ArchiveScanResult {
                    archive_path: archive_path.to_string(),
                    archive_type: "zip".to_string(),
                    files: vec![],
                    has_password: false,
                    error: Some("Failed to open ZIP archive".to_string()),
                };
            }
        };

        // 尝试无密码打开第一个文件
        let first_file_result = test_archive.by_index(0);
        let is_encrypted = first_file_result.is_err() && 
            first_file_result.as_ref().err().map(|e| e.to_string().contains("password") || e.to_string().contains("encrypted")).unwrap_or(false);

        let mut found_password: Option<String> = None;
        if is_encrypted {
            // 尝试常用密码
            for password in COMMON_PASSWORDS {
                let cursor = Cursor::new(&file_data);
                if let Ok(mut pw_archive) = zip::ZipArchive::new(cursor) {
                    if pw_archive.by_index_decrypt(0, password.as_bytes()).is_ok() {
                        found_password = Some(password.to_string());
                        break;
                    }
                }
            }
        }

        (is_encrypted, found_password)
    };

    // 重新打开压缩包进行扫描
    let cursor = Cursor::new(&file_data);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(archive) => archive,
        Err(e) => {
            return ArchiveScanResult {
                archive_path: archive_path.to_string(),
                archive_type: "zip".to_string(),
                files: vec![],
                has_password: needs_password,
                error: Some(format!("Failed to open ZIP archive: {}", e)),
            };
        }
    };

    let mut results = Vec::new();

    // 遍历压缩包内的文件
    for i in 0..archive.len() {
        let file_result = if let Some(ref pwd) = password_found {
            archive.by_index_decrypt(i, pwd.as_bytes())
        } else {
            archive.by_index(i).map_err(|e| e.into())
        };

        let mut file = match file_result {
            Ok(file) => file,
            Err(e) => {
                // 可能是加密的且密码不对
                if e.to_string().contains("password") || e.to_string().contains("encrypted") {
                    continue;
                }
                continue;
            }
        };

        let inner_path = file.name().to_string();
        let size = file.size();

        // 跳过目录和过大的文件（超过 100MB）
        if file.is_dir() || size > 100 * 1024 * 1024 {
            continue;
        }

        // 读取文件内容到内存
        let mut buffer = Vec::with_capacity(size as usize);
        if let Err(e) = file.read_to_end(&mut buffer) {
            results.push(ArchiveFileResult {
                archive_path: archive_path.to_string(),
                inner_path: inner_path.clone(),
                size,
                scan_result: None,
                is_encrypted: password_found.is_some(),
                error: Some(format!("Failed to read file content: {}", e)),
            });
            continue;
        }

        // 只扫描 PE 文件或可执行脚本（通过文件头或扩展名判断）
        if !is_pe_file(&buffer) && !is_executable_by_extension(&inner_path) {
            // 不是可执行文件，跳过扫描但记录文件信息
            results.push(ArchiveFileResult {
                archive_path: archive_path.to_string(),
                inner_path: inner_path.clone(),
                size,
                scan_result: Some(crate::scanner::ScanResult {
                    file_path: inner_path.clone(),
                    file_hash: None,
                    result: "SKIPPED".to_string(),
                    probability: 0.0,
                    signature_status: Some("Not an executable file".to_string()),
                    is_trusted: false,
                    error: None,
                    virus_family: None,
                    family_category: None,
                    is_infector: false,
                }),
                is_encrypted: password_found.is_some(),
                error: None,
            });
            continue;
        }

        // 判断是否为脚本文件，使用脚本扫描引擎
        let scan_result = if is_script_file(&inner_path) {
            scan_script_in_memory(&buffer, &inner_path)
        } else {
            // PE 文件使用普通 AI 引擎扫描
            scan_memory_buffer(&buffer, &inner_path, scanner)
        };

        results.push(ArchiveFileResult {
            archive_path: archive_path.to_string(),
            inner_path,
            size,
            scan_result: Some(scan_result),
            is_encrypted: password_found.is_some(),
            error: None,
        });
    }

    ArchiveScanResult {
        archive_path: archive_path.to_string(),
        archive_type: "zip".to_string(),
        files: results,
        has_password: needs_password,
        error: if needs_password && password_found.is_none() {
            Some("Archive is password protected and could not be decrypted with common passwords".to_string())
        } else {
            None
        },
    }
}

/// 在内存中扫描 7z 文件
fn scan_7z_in_memory(
    _archive_path: &str,
    _scanner: &crate::scanner::Scanner,
) -> ArchiveScanResult {
    // 7z 扫描实现 - 暂时未完全实现
    // 由于 sevenz-rust 库的 API 限制，7z 扫描功能需要更多工作
    ArchiveScanResult {
        archive_path: _archive_path.to_string(),
        archive_type: "7z".to_string(),
        files: vec![],
        has_password: false,
        error: Some("7z memory scanning not yet fully implemented".to_string()),
    }
}

/// 在内存中扫描缓冲区
fn scan_memory_buffer(
    buffer: &[u8],
    file_name: &str,
    scanner: &crate::scanner::Scanner,
) -> crate::scanner::ScanResult {
    // 创建一个临时标识，表示这是内存中的文件
    // 历史 bug：原实现 format!("{} -> {}", file_name, file_name) 两个参数
    // 都传了同一文件名，显示 "virus.exe -> virus.exe"（本意是
    // "压缩包路径 -> 内文件路径"）。此函数没有压缩包路径上下文，
    // 直接使用内层文件名作为虚拟路径。
    let virtual_path = file_name.to_string();
    
    // 使用扫描器的内存扫描方法
    scanner.scan_memory_buffer(buffer, &virtual_path)
}

/// Tauri 命令：扫描压缩包
#[tauri::command]
pub async fn scan_archive_command(
    archive_path: String,
) -> Result<String, String> {
    use crate::scanner::SCANNER;
    
    let scanner = SCANNER.read().map_err(|e| e.to_string())?;
    let result = scan_archive_in_memory(&archive_path, &scanner);
    
    serde_json::to_string(&result).map_err(|e| e.to_string())
}
