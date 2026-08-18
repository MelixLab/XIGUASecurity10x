use std::sync::atomic::{AtomicU64, Ordering};

// 批量扫描计时器（原子计数，用于分析并行度）
static EXTRACT_TIME_NS: AtomicU64 = AtomicU64::new(0);
static ONNX_TIME_NS: AtomicU64 = AtomicU64::new(0);

// 字节属性查找表：bit0=可打印, bit1=控制字符, bit2=高位, bit3=零字节
const fn build_byte_attr() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        let b = i as u8;
        if b >= 32 && b <= 126 { table[i] |= 1; }
        if b < 32 || b == 127 { table[i] |= 2; }
        if b >= 0x80 { table[i] |= 4; }
        if b == 0 { table[i] |= 8; }
        i += 1;
    }
    table
}
const BYTE_ATTR: [u8; 256] = build_byte_attr();

use std::path::Path;
use std::sync::{Arc, RwLock, Mutex};
use serde::{Deserialize, Serialize};
use std::fs;
use std::time::{Duration, Instant};
use std::thread;
use std::cell::RefCell;
use walkdir::WalkDir;
use rayon::prelude::*;
use sha2::{Sha256, Digest};
use once_cell::sync::Lazy;

use crate::tree::TreeEnsemble;

/// 带超时的文件读取（防止文件被锁导致 scan_file 无限阻塞）
///
/// 实现说明：直接同步读取（Windows 上 std::fs::read 遇到文件被独占锁定时
/// 会立即返回错误，不会无限阻塞）。无需再 spawn 读取线程——旧实现 spawn
/// 线程 + recv_timeout 在超时后无法回收仍阻塞的读线程，会导致线程泄漏。
fn read_file_with_timeout(file_path: &str, timeout: std::time::Duration) -> Result<Vec<u8>, String> {
    let _ = timeout; // 保留参数签名兼容调用方；同步读取本身即有系统级失败保护
    std::fs::read(file_path).map_err(|e| format!("Failed to read file: {}", e))
}

// 全局HTTP客户端（复用连接池）
static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .pool_max_idle_per_host(50)
        .pool_idle_timeout(Duration::from_secs(30))
        .build()
        .expect("Failed to create HTTP client")
});

// 病毒家族判断引擎（纯静态分析，不依赖外部YARA规则）
pub mod virus_family;
use virus_family::analyze_family;

// 检查病毒家族分析是否启用
fn is_virus_family_analysis_enabled() -> bool {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_path = format!("{}/XIGUASecurity/virus_family_analysis_enabled.txt", local_app_data);
    std::fs::read_to_string(&config_path)
        .map(|s| s.trim() == "true")
        .unwrap_or(true) // 默认开启
}

// 感染型病毒检测引擎
mod infector_detector;
pub use infector_detector::{detect_infector, get_infector_description};

// 感染型病毒清除引擎
mod infector_cleaner;
pub use infector_cleaner::{clean_infected_file, get_cleaning_report, CleaningResult};

// 脚本扫描引擎
mod script_scanner;
pub use script_scanner::{scan_script_file, scan_script_buffer, analyze_bat_family};

// 白名单/黑规则库模块
use crate::whitelist::{is_hash_whitelisted, is_name_whitelisted, is_path_whitelisted};
use crate::blacklist::{is_hash_blacklisted, is_path_blacklisted};
// 哈希白名单 - 这些文件哈希不会被报毒
// 使用lazy_static在运行时初始化，避免重复计算
lazy_static::lazy_static! {
    static ref HASH_WHITE_LIST: std::collections::HashSet<String> = {
        let mut set = std::collections::HashSet::new();
        // Windows系统文件 (SysWOW64 OLE组件)
        set.insert("126A00E34A6516C0D382A221071AB4084031C2A89CCB6144CAB960CE1F86EE2C".to_string());
        // Sandboxie LowLevel.dll (AMD64)
        set.insert("88F1A0C55F2D3E38FFFA30856D3D0666A842BC6A41599DE18BF91BE5C8368E63".to_string());
        // Sandboxie LowLevel.dll (ARM64)
        set.insert("85777439AEE3EA9A69AC6A928FEC43E9AE8FD0355FFF3A684BC4F4029228B7BA".to_string());
        // d3dcsx_42.dll (System32)
        set.insert("8852C218583DC11113705BD89DABD51B0F77DB6B393EAF9A9A751652B7CDEF24".to_string());
        // d3dcsx_42.dll (SysWOW64)
        set.insert("E462EB3D41DB54988CE3BE46CED60B0073F8D939A9946CDA67FB1DF3C8AFE0A1".to_string());
        // Git installer
        set.insert("BC88381E192BD5B17A131755D837828D8A570DA1EAD89CFCDE0D45AE38133C0B".to_string());
        set
    };

    // 内置病毒哈希黑名单 - 已知恶意文件哈希（优先级低于外部黑规则库）
    static ref HASH_BLACK_LIST: std::collections::HashMap<String, String> = {
        let mut map = std::collections::HashMap::new();
        // pyas_killer.exe - AVKill 工具 (前10MB哈希)
        map.insert("96A296D224F285C67BEE93C30F8A309157F0DAA35DC5B87E410B78630A09CFC7".to_string(), "AVKill".to_string());
        // EICAR 标准反病毒测试文件
        map.insert("275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F".to_string(), "EICAR".to_string());
        map
    };

    // 文件名白名单 - 只在检测到威胁时检查
    static ref FILENAME_WHITE_LIST: std::collections::HashSet<String> = {
        let mut set = std::collections::HashSet::new();
        // 更新程序
        set.insert("XIGUASecurity_update.exe".to_string());
        set.insert("XIGUASecurity10x_setup.exe".to_string());
        set.insert("XIGUASecurity10x.exe".to_string());
        // 西瓜杀毒组件
        set.insert("MelixCloudScan_CLI.exe".to_string());
        // Git 安装程序（匹配 Git-*.exe 模式）
        set.insert("Git-2.53.0.3-64-bit.exe".to_string());
        set.insert("Git-2.51.1-64-bit.exe".to_string());
        set
    };
}

// 验证文件数字签名 - 使用Windows API检测签名（包括目录签名）
// 先检测嵌入式签名，如果没有再检测目录签名
#[cfg(windows)]
pub fn verify_file_signature(file_path: &str) -> (bool, Option<String>) {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Security::Cryptography::{
        CryptQueryObject, CERT_QUERY_OBJECT_FILE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY, HCERTSTORE, CERT_CONTEXT
    };

    // 将路径转换为宽字符
    let wide_path: Vec<u16> = std::path::Path::new(file_path)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        // 首先检查嵌入式签名（更快）
        let mut cert_store: HCERTSTORE = std::mem::zeroed();
        let mut msg_context = std::ptr::null_mut();
        let mut cert_context_raw: *mut std::ffi::c_void = std::ptr::null_mut();

        let result = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide_path.as_ptr() as *const _,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut cert_store),
            Some(&mut msg_context),
            Some(&mut cert_context_raw),
        );

        if result.is_ok() && !cert_context_raw.is_null() {
            // 有嵌入式签名
            use windows::Win32::Security::Cryptography::CertFreeCertificateContext;
            let cert_context = cert_context_raw as *const CERT_CONTEXT;
            let _ = CertFreeCertificateContext(Some(cert_context));
            if !cert_store.is_invalid() {
                use windows::Win32::Security::Cryptography::CertCloseStore;
                let _ = CertCloseStore(cert_store, 0);
            }
            return (true, Some("Embedded Signed".to_string()));
        }

        // 无嵌入式签名 → 无目录签名快速路径（目录签名查询开销大且收益低）。
        // 历史 bug：此处曾 std::fs::read 整个文件到内存只为检查 PE 头安全目录，
        // 导致大文件在 quick_check 阶段被整读一遍（16MB 以上文件内存峰值极高），
        // 且检查结果从未被使用（永远返回 (false, None)）。现已移除全量读取。
        (false, None)
    }
}

// 非Windows平台返回无签名
#[cfg(not(windows))]
pub fn verify_file_signature(_file_path: &str) -> (bool, Option<String>) {
    (false, None)
}

// 扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub file_path: String,
    pub file_hash: Option<String>, // SHA256哈希值
    pub result: String, // "CLEAN", "MALICIOUS", "ERROR", "TIMEOUT"
    pub probability: f32,
    pub signature_status: Option<String>,
    pub is_trusted: bool,
    pub error: Option<String>,
    pub virus_family: Option<String>, // 病毒家族类型
    pub family_category: Option<String>, // 病毒家族中文分类标签（如"木马病毒"、"勒索病毒"等）
    pub is_infector: bool, // 是否为感染型病毒
}

// 扫描器状态
pub struct Scanner {
    /// TreeEnsemble 模型（纯 Rust 推理，替代 ONNX Runtime）
    pub tree_model: Arc<RwLock<Option<TreeEnsemble>>>,
    threshold: f32,
    system_paths: Vec<String>,
    model_path: Option<String>,
    // 缓存已扫描文件的结果
    result_cache: Arc<Mutex<std::collections::HashMap<String, ScanResult>>>,
    // 缓存已提取的特征向量（key: 文件路径, value: (mtime, size, features)）
    feature_cache: Arc<Mutex<std::collections::HashMap<String, (u64, u64, Vec<f32>)>>>,
    // 模型特征维度
    pub feature_dim: std::sync::atomic::AtomicUsize,
    // 模型版本计数器
    model_generation: std::sync::atomic::AtomicU64,
}

impl Scanner {
    // 文件读取与特征提取常量
    const FEATURE_STREAMING_LIMIT: usize = 16 * 1024 * 1024; // 16MB 以下小文件完整读取
    const FAMILY_DATA_LIMIT: usize = 4 * 1024 * 1024;        // 家族分析最多读取前 4MB

    pub fn new() -> Self {
        let mut scanner = Self {
            tree_model: Arc::new(RwLock::new(None)),
            threshold: 0.7,
            system_paths: vec![],
            model_path: None,
            result_cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
            feature_cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
            feature_dim: std::sync::atomic::AtomicUsize::new(crate::ember_features::NDIM),
            model_generation: std::sync::atomic::AtomicU64::new(1),
        };

        // 尝试加载 TreeEnsemble 模型
        match scanner.load_model() {
            Ok(_) => println!("[Scanner] - TreeEnsemble model loaded successfully"),
            Err(e) => eprintln!("[Scanner] - Failed to load TreeEnsemble model: {}", e),
        }

        scanner
    }

    fn load_model(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let exe_path = std::env::current_exe()
            .map_err(|e| format!("Failed to get exe path: {}", e))?;
        let exe_dir = exe_path.parent()
            .ok_or("Failed to get exe directory")?;

        let model_paths = vec![
            exe_dir.join("engines").join("melix").join("Melix_local_model.trees.bin.xz"),
            exe_dir.join("Melix_local_model.trees.bin.xz"),
        ];

        for path_buf in &model_paths {
            if path_buf.exists() {
                let path_str = path_buf.to_string_lossy();
                println!("[Scanner] - Loading TreeEnsemble model from: {}", path_str);

                let raw = fs::read(&path_buf)?;
                let model_bytes = Self::maybe_decompress_xz(&raw)?;
                let model = TreeEnsemble::from_bytes(&model_bytes)?;

                println!("[Scanner] - TreeEnsemble loaded: {} trees, {} classes, {} features",
                    model.n_trees(), model.n_classes(), model.n_features());

                self.feature_dim.store(model.n_features(), std::sync::atomic::Ordering::Relaxed);
                *self.tree_model.write().unwrap() = Some(model);
                self.model_path = Some(path_str.to_string());
                return Ok(());
            }
        }

        eprintln!("[Scanner] - ERROR: Could not find Melix_local_model.trees.bin.xz");
        for path in &model_paths {
            eprintln!("  - {}", path.display());
        }
        Err("Melix_local_model.trees.bin.xz not found".into())
    }

    /// 自动解压 xz 数据（如果 magic 匹配），否则原样返回。
    fn maybe_decompress_xz(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        const XZ_MAGIC: &[u8] = &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
        if data.starts_with(XZ_MAGIC) {
            let mut out = Vec::new();
            let mut reader = std::io::BufReader::new(data);
            lzma_rs::xz_decompress(&mut reader, &mut out)
                .map_err(|e| format!("xz decompress failed: {:?}", e))?;
            Ok(out)
        } else {
            Ok(data.to_vec())
        }
    }

    /// 运行时重新加载模型（用于切换敏感度模式）
    pub fn reload_model(&self, model_path: &str, _feature_dim: usize) -> Result<(), String> {
        let path = std::path::Path::new(model_path);
        println!("[Scanner] - reload_model path: {}", path.display());

        let data = std::fs::read(path).map_err(|e| format!("读取模型文件失败: {} - {}", model_path, e))?;
        println!("[Scanner] - Read {} bytes from model file", data.len());

        let model_bytes = Self::maybe_decompress_xz(&data).map_err(|e| e.to_string())?;
        let model = TreeEnsemble::from_bytes(&model_bytes)?;

        println!("[Scanner] - TreeEnsemble reloaded: {} trees, {} classes, {} features",
            model.n_trees(), model.n_classes(), model.n_features());

        self.feature_dim.store(model.n_features(), std::sync::atomic::Ordering::Relaxed);
        *self.tree_model.write().map_err(|e| e.to_string())? = Some(model);
        // 递增版本号
        self.model_generation.fetch_add(1, std::sync::atomic::Ordering::Release);
        // 清空缓存
        self.result_cache.lock().unwrap().clear();
        self.feature_cache.lock().unwrap().clear();
        println!("[Scanner] - Model reloaded from: {}, feature_dim: {}", model_path, self.feature_dim.load(std::sync::atomic::Ordering::Relaxed));
        Ok(())
    }

    /// 获取扫描器状态信息
    pub fn get_info(&self) -> serde_json::Value {
        let model_loaded = self.tree_model.read().unwrap().is_some();
        serde_json::json!({
            "model_loaded": model_loaded,
            "model_path": self.model_path,
            "threshold": self.threshold,
        })
    }

    // EMBER V3 2568维特征提取（委托给 ember_features 模块）
    pub fn extract_features(&self, file_path: &str) -> Result<Vec<f32>, String> {
        if let Some(features) = self.get_cached_features(file_path) {
            return Ok(features);
        }
        let data = fs::read(file_path).map_err(|e| format!("Failed to read file: {}", e))?;
        let features = crate::ember_features::extract(&data).ok_or_else(|| "Not a valid PE file".to_string())?;
        if features.len() != crate::ember_features::NDIM {
            return Err(format!("EMBER feature dim mismatch: expected {}, got {}", crate::ember_features::NDIM, features.len()));
        }
        self.put_cached_features(file_path, features.clone());
        Ok(features)
    }

    // 从缓存读取特征（按路径+mtime+size校验）
    fn get_cached_features(&self, file_path: &str) -> Option<Vec<f32>> {
        let metadata = fs::metadata(file_path).ok()?;
        let mtime = metadata
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        let size = metadata.len();
        let cache = self.feature_cache.lock().unwrap();
        cache.get(file_path).and_then(|(t, s, f)| {
            if *t == mtime && *s == size {
                Some(f.clone())
            } else {
                None
            }
        })
    }

    // 将特征写入缓存
    fn put_cached_features(&self, file_path: &str, features: Vec<f32>) {
        if let Ok(metadata) = fs::metadata(file_path) {
            let mtime = metadata
                .modified()
                .map(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs())
                .unwrap_or(0);
            let size = metadata.len();
            let mut cache = self.feature_cache.lock().unwrap();
            if cache.len() > 2000 {
                cache.clear();
            }
            cache.insert(file_path.to_string(), (mtime, size, features));
        }
    }

    // 运行 TreeEnsemble 模型推理（替代 ONNX Runtime，概率始终在 0~1 之间）
    fn run_tree_inference(&self, features: &[f32]) -> Result<f32, String> {
        let guard = self.tree_model.read().map_err(|e| e.to_string())?;
        let model = guard.as_ref().ok_or_else(|| "TreeEnsemble model not loaded".to_string())?;
        Ok(model.evaluate(features).malicious_prob)
    }

    // 快速预检查 - 不运行模型，只做基本检查
    // precomputed_hash: 前端已计算好的哈希，若提供可提前做名单命中
    fn quick_check(&self, file_path: &str, precomputed_hash: Option<&str>) -> Option<ScanResult> {
        // 检查文件是否存在
        if !Path::new(file_path).exists() {
            return Some(ScanResult {
                file_path: file_path.to_string(),
                file_hash: precomputed_hash.map(|s| s.to_uppercase()),
                result: "ERROR".to_string(),
                probability: 0.0,
                signature_status: None,
                is_trusted: false,
                error: Some("File not found".to_string()),
                virus_family: None,
                family_category: None,
                is_infector: false,
            });
        }

        // 检查缓存
        {
            let cache = self.result_cache.lock().unwrap();
            if let Some(result) = cache.get(file_path) {
                return Some(result.clone());
            }
        }

        // EICAR 标准反病毒测试文件检测
        // EICAR 字符串位于文件开头 68 字节内，所有杀毒软件均应检测
        // 注意：Notepad 保存的 UTF-8 文件可能带有 BOM 头（EF BB BF），需要跳过
        const EICAR_SIGNATURE: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];
        if let Ok(mut file) = std::fs::File::open(file_path) {
            use std::io::Read;
            // 先读前 71 字节（68 签名 + 3 BOM），以便跳过 BOM 后仍能检查完整签名
            let mut buf = [0u8; 71];
            let n = file.read(&mut buf).unwrap_or(0);
            // 确定有效起始位置：跳过 BOM 头
            let start = if n >= 3 && &buf[..3] == UTF8_BOM { 3 } else { 0 };
            let remaining = n - start;
            if remaining >= 68 {
                let content = &buf[start..start + 68];
                if content == EICAR_SIGNATURE {
                    return Some(ScanResult {
                        file_path: file_path.to_string(),
                        file_hash: None,
                        result: "MALICIOUS".to_string(),
                        probability: 1.0,
                        signature_status: Some("EICAR test file".to_string()),
                        is_trusted: false,
                        error: None,
                        virus_family: Some("TEST/AVEngTestFile!EICAR (100.0%)".to_string()),
                        family_category: Some("测试文件".to_string()),
                        is_infector: false,
                    });
                }
            }
        }

        // 检查数字签名（比哈希计算快）
        // 注意：即使文件有签名，也需要进行感染型病毒检测
        // 因为感染型病毒可能劫持了有签名的文件
        let (has_signature, signer_name) = verify_file_signature(file_path);
        
        // 先进行感染型病毒检测（不受签名影响）
        let infector_result = detect_infector(file_path);
        if infector_result.is_infected {
            // 感染型病毒检测优先级最高
            return Some(ScanResult {
                file_path: file_path.to_string(),
                file_hash: precomputed_hash.map(|s| s.to_uppercase()),
                result: "MALICIOUS".to_string(),
                probability: infector_result.confidence,
                signature_status: signer_name.or(Some("Signed".to_string())),
                is_trusted: false, // 被感染的文件即使有签名也不可信
                error: None,
                virus_family: Some(format!("HEUR:Infector.{}!ml (置信度: {:.0}%)", 
                    if infector_result.details.entry_point_anomaly { "EP_Hijack" } else { "Section_Anomaly" },
                    infector_result.confidence * 100.0)),
                family_category: Some("感染型病毒".to_string()),
                is_infector: true,
            });
        }

        // 如果前端已传哈希，优先做黑白名单命中（黑名单优先于签名）
        if !SKIP_LOCAL_RULES.load(std::sync::atomic::Ordering::Relaxed) {
            if let Some(pre_hash) = precomputed_hash {
                if let Some(result) = Self::hash_lookup_result(file_path, pre_hash) {
                    return Some(result);
                }
            }

            // 检查黑规则库：路径黑名单
            if is_path_blacklisted(file_path) {
                return Some(ScanResult {
                    file_path: file_path.to_string(),
                    file_hash: None,
                    result: "MALICIOUS".to_string(),
                    probability: 1.0,
                    signature_status: Some("Path Blacklisted".to_string()),
                    is_trusted: false,
                    error: None,
                    virus_family: Some("HEUR:Blacklisted.Path!ml (100.0%)".to_string()),
                    family_category: Some("黑客工具".to_string()),
                    is_infector: false,
                });
            }

            // 检查黑规则库：文件名黑名单（移到完整读取后，优先使用哈希家族）
            // 文件名白名单仍可提前跳过
            if let Some(filename) = Path::new(file_path).file_name() {
                if let Some(name) = filename.to_str() {
                    // 检查白规则库：文件名白名单
                    if FILENAME_WHITE_LIST.contains(name) || is_name_whitelisted(name) {
                        return Some(ScanResult {
                            file_path: file_path.to_string(),
                            file_hash: None,
                            result: "CLEAN".to_string(),
                            probability: 0.0,
                            signature_status: Some("Filename Whitelisted".to_string()),
                            is_trusted: true,
                            error: None,
                            virus_family: None,
                            family_category: None,
                            is_infector: false,
                        });
                    }
                }
            }

            // 检查白规则库：路径白名单（用户配置的免扫描路径）
            if is_path_whitelisted(file_path) {
                return Some(ScanResult {
                    file_path: file_path.to_string(),
                    file_hash: None,
                    result: "CLEAN".to_string(),
                    probability: 0.0,
                    signature_status: Some("Path Whitelisted".to_string()),
                    is_trusted: true,
                    error: None,
                    virus_family: None,
                    family_category: None,
                    is_infector: false,
                });
            }

            // 经过黑白名单检查后，再看签名
            if has_signature {
                return Some(ScanResult {
                    file_path: file_path.to_string(),
                    file_hash: None,
                    result: "CLEAN".to_string(),
                    probability: 0.0,
                    signature_status: signer_name.or(Some("Signed".to_string())),
                    is_trusted: true,
                    error: None,
                    virus_family: None,
                    family_category: None,
                    is_infector: false,
                });
            }
        }

        // 安装包/打包器检测：跳过引擎扫描（易误报），转由 archive_scanner 解包分析
        if let Some(installer_type) = crate::archive_scanner::detect_installer_type(file_path) {
            return Some(ScanResult {
                file_path: file_path.to_string(),
                file_hash: None,
                result: "INSTALLER".to_string(),
                probability: 0.0,
                signature_status: Some(format!("Installer: {}", installer_type.as_str())),
                is_trusted: false,
                error: None,
                virus_family: Some(format!("INSTALLER/{}", installer_type.display_name())),
                family_category: Some("安装包".to_string()),
                is_infector: false,
            });
        }

        None // 需要完整扫描
    }

    /// 根据哈希查询黑白名单，命中则返回扫描结果，否则返回 None
    fn hash_lookup_result(file_path: &str, hash: &str) -> Option<ScanResult> {
        let hash_upper = hash.to_uppercase();
        // 先查黑名单
        let black_family = is_hash_blacklisted(&hash_upper)
            .or_else(|| HASH_BLACK_LIST.get(&hash_upper).cloned());
        if let Some(family) = black_family {
            return Some(ScanResult {
                file_path: file_path.to_string(),
                file_hash: Some(hash_upper),
                result: "MALICIOUS".to_string(),
                probability: 1.0,
                signature_status: Some(format!("Hash Blacklisted: {}", family)),
                is_trusted: false,
                error: None,
                virus_family: Some(family),
                family_category: None,
                is_infector: false,
            });
        }
        // 再查白名单
        if HASH_WHITE_LIST.contains(&hash_upper) || is_hash_whitelisted(&hash_upper) {
            return Some(ScanResult {
                file_path: file_path.to_string(),
                file_hash: Some(hash_upper),
                result: "CLEAN".to_string(),
                probability: 0.0,
                signature_status: Some("Hash Whitelisted".to_string()),
                is_trusted: true,
                error: None,
                virus_family: None,
                family_category: None,
                is_infector: false,
            });
        }
        None
    }

    // 扫描单个文件
    // precomputed_hash: 前端已计算好的哈希，传入可避免重复计算
    pub fn scan_file(&self, file_path: &str, precomputed_hash: Option<&str>) -> ScanResult {
        let start = Instant::now();
        let timeout = Duration::from_secs(60);

        // 快速预检查
        if let Some(result) = self.quick_check(file_path, precomputed_hash) {
            return result;
        }

        let is_system_path = self.system_paths.iter().any(|p| file_path.starts_with(p));
        let effective_threshold = self.threshold;

        // 根据文件大小选择读取策略：小文件一次性读入内存；大文件流式提取特征/哈希，仅加载前50MB给家族分析
        const FEATURE_STREAMING_LIMIT: usize = Scanner::FEATURE_STREAMING_LIMIT;
        const FAMILY_DATA_LIMIT: usize = Scanner::FAMILY_DATA_LIMIT;

        // 如果前端已经传了哈希，直接用它做名单命中，避免任何读取
        if !SKIP_LOCAL_RULES.load(std::sync::atomic::Ordering::Relaxed) {
            if let Some(pre_hash) = precomputed_hash {
                if let Some(result) = Self::hash_lookup_result(file_path, pre_hash) {
                    return result;
                }
            }
        }

        let metadata = match std::fs::metadata(file_path) {
            Ok(m) => m,
            Err(e) => return ScanResult {
                file_path: file_path.to_string(),
                file_hash: None,
                result: "ERROR".to_string(),
                probability: 0.0,
                signature_status: None,
                is_trusted: false,
                error: Some(format!("Failed to stat file: {}", e)),
                virus_family: None,
                family_category: None,
                is_infector: false,
            }
        };
        let file_size = metadata.len() as usize;

        let (file_data, features, computed_hash) = if file_size <= FEATURE_STREAMING_LIMIT {
            // 小文件：一次读取完整文件，先算哈希查名单，命中则直接跳过特征提取和 ONNX
            let read_start = Instant::now();
            let data = match read_file_with_timeout(file_path, std::time::Duration::from_secs(15)) {
                Ok(d) => d,
                Err(e) => return ScanResult {
                    file_path: file_path.to_string(),
                    file_hash: None,
                    result: "ERROR".to_string(),
                    probability: 0.0,
                    signature_status: None,
                    is_trusted: false,
                    error: Some(e),
                    virus_family: None,
                    family_category: None,
                    is_infector: false,
                }
            };
            let read_len = data.len();

            let mut hasher = Sha256::new();
            hasher.update(&data);
            let small_hash = format!("{:x}", hasher.finalize());

            if !SKIP_LOCAL_RULES.load(std::sync::atomic::Ordering::Relaxed) {
                if let Some(result) = Self::hash_lookup_result(file_path, &small_hash) {
                    return result;
                }
            }

            let extract_start = Instant::now();
            let features = match self.get_cached_features(file_path) {
                Some(f) => f,
                None => match self.extract_features_from_bytes(&data, file_size) {
                    Ok(f) => {
                        self.put_cached_features(file_path, f.clone());
                        f
                    }
                    Err(e) => {
                        EXTRACT_TIME_NS.fetch_add(extract_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
                        return ScanResult {
                            file_path: file_path.to_string(),
                            file_hash: Some(small_hash),
                            result: "ERROR".to_string(),
                            probability: 0.0,
                            signature_status: None,
                            is_trusted: false,
                            error: Some(e),
                            virus_family: None,
                            family_category: None,
                            is_infector: false,
                        };
                    }
                }
            };
            EXTRACT_TIME_NS.fetch_add(extract_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
            (data, features, Some(small_hash))
        } else {
            // 大文件：读取前 64MB 用于特征提取和家族分析
            let extract_start = Instant::now();
            let (features, file_data, computed_hash) = match self.get_cached_features(file_path) {
                Some(cached) => {
                    // 有缓存特征，只需读取文件数据用于家族分析
                    let d = match read_file_with_timeout(file_path, std::time::Duration::from_secs(30)) {
                        Ok(d) => d,
                        Err(e) => return ScanResult {
                            file_path: file_path.to_string(),
                            file_hash: None,
                            result: "ERROR".to_string(),
                            probability: 0.0,
                            signature_status: None,
                            is_trusted: false,
                            error: Some(e),
                            virus_family: None,
                            family_category: None,
                            is_infector: false,
                        }
                    };
                    // 先对完整文件计算哈希（用于名单查询和 AVIC 云端查询）
                    use sha2::Digest;
                    let mut hasher = Sha256::new();
                    hasher.update(&d);
                    let h = format!("{:x}", hasher.finalize());
                    // 家族分析只取前 FAMILY_DATA_LIMIT 字节
                    let mut family_d = d;
                    family_d.truncate(FAMILY_DATA_LIMIT);
                    (cached, family_d, Some(h))
                }
                None => {
                    // 读取完整文件用于特征提取
                    let mut data = match read_file_with_timeout(file_path, std::time::Duration::from_secs(30)) {
                        Ok(d) => d,
                        Err(e) => {
                            EXTRACT_TIME_NS.fetch_add(extract_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
                            return ScanResult {
                                file_path: file_path.to_string(),
                                file_hash: None,
                                result: "ERROR".to_string(),
                                probability: 0.0,
                                signature_status: None,
                                is_trusted: false,
                                error: Some(e),
                                virus_family: None,
                                family_category: None,
                                is_infector: false,
                            };
                        }
                    };
                    let read_len = data.len();
                    use sha2::Digest;
                    let mut hasher = Sha256::new();
                    hasher.update(&data);
                    let hash = format!("{:x}", hasher.finalize());

                    let features = match crate::ember_features::extract(&data) {
                        Some(f) => f,
                        None => {
                            EXTRACT_TIME_NS.fetch_add(extract_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
                            return ScanResult {
                                file_path: file_path.to_string(),
                                file_hash: Some(hash),
                                result: "ERROR".to_string(),
                                probability: 0.0,
                                signature_status: None,
                                is_trusted: false,
                                error: Some("Not a valid PE file".to_string()),
                                virus_family: None,
                                family_category: None,
                                is_infector: false,
                            };
                        }
                    };
                    self.put_cached_features(file_path, features.clone());
                    let family_data = if read_len > FAMILY_DATA_LIMIT {
                        data.truncate(FAMILY_DATA_LIMIT);
                        data
                    } else {
                        data
                    };
                    (features, family_data, Some(hash))
                }
            };
            EXTRACT_TIME_NS.fetch_add(extract_start.elapsed().as_nanos() as u64, Ordering::Relaxed);

            let precomputed_from_stream = computed_hash.clone();
            // 大文件算完 hash 查名单
            if !SKIP_LOCAL_RULES.load(std::sync::atomic::Ordering::Relaxed) {
                if let Some(ref h) = precomputed_from_stream {
                    if let Some(result) = Self::hash_lookup_result(file_path, h) {
                        return result;
                    }
                }
            }

            (file_data, features, computed_hash)
        };

        // 组装 file_hash（哈希已在前面阶段算出）
        let file_hash = computed_hash.clone();

        // 检查超时
        if start.elapsed() > timeout {
            return ScanResult {
                file_path: file_path.to_string(),
                file_hash: file_hash.clone(),
                result: "TIMEOUT".to_string(),
                probability: 0.0,
                signature_status: None,
                is_trusted: false,
                error: Some("Feature extraction timeout".to_string()),
                virus_family: None,
                family_category: None,
                is_infector: false,
            };
        }

        // ONNX 推理
        let onnx_start = Instant::now();
        let (probability, is_malicious) = match self.run_tree_inference(&features) {
            Ok(prob) => (prob, prob >= effective_threshold),
            Err(e) => {
                ONNX_TIME_NS.fetch_add(onnx_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
                return ScanResult {
                    file_path: file_path.to_string(),
                    file_hash: file_hash.clone(),
                    result: "ERROR".to_string(),
                    probability: 0.0,
                    signature_status: None,
                    is_trusted: false,
                    error: Some(format!("ONNX inference error: {}", e)),
                    virus_family: None,
                    family_category: None,
                    is_infector: false,
                };
            }
        };
        ONNX_TIME_NS.fetch_add(onnx_start.elapsed().as_nanos() as u64, Ordering::Relaxed);

        // 签名验证已禁用以提升扫描速度
        let signature_status = Some("Signature check disabled".to_string());
        let is_trusted = is_system_path;

        // 病毒家族分析：使用已读取的 file_data，避免第三次读取
        let (virus_family, family_category) = if is_malicious && !is_trusted {
            if SKIP_FAMILY_ANALYSIS.load(std::sync::atomic::Ordering::Relaxed) {
                let generic = format!("HEUR:Trojan.Win32.Generic!ml ({:.1}%)", probability * 100.0);
                (Some(generic), Some("木马病毒".to_string()))
            } else {
            let mut category: Option<String> = None;
            let mut detail: Option<String> = None;

            if is_virus_family_analysis_enabled() {
                // 家族分析不需要完整 50MB，截断到前 4MB 以降低 CPU/内存开销
                const FAMILY_ANALYSIS_LIMIT: usize = 4 * 1024 * 1024;
                let family_data = &file_data[..file_data.len().min(FAMILY_ANALYSIS_LIMIT)];
                let family_result = analyze_family(family_data, file_path, is_malicious, probability);
                category = Some(family_result.primary_family.category_label().to_string());
                let detection_name = &family_result.detection_name;
                let raw = if family_result.is_packed && !detection_name.starts_with("Packed/") {
                    let packer_name = family_result.packer_name.as_deref().unwrap_or("Unknown");
                    format!("{}+{} ({:.1}%)", detection_name, packer_name, probability * 100.0)
                } else {
                    format!("{} ({:.1}%)", detection_name, probability * 100.0)
                };
                detail = Some(raw);
            }

            if detail.is_none() {
                detail = Some(format!("HEUR:Trojan.Win32.Generic!ml ({:.1}%)", probability * 100.0));
                category = Some("木马病毒".to_string());
            }

            let final_detail = detail.map(|d| {
                if d.starts_with("HEUR:") {
                    d
                } else if d.starts_with("ADV:") {
                    format!("HEUR:{}", &d[4..])
                } else {
                    format!("HEUR:{}", d)
                }
            });
            (final_detail, category)
            }
        } else {
            (None, None)
        };

        // 注意：感染型病毒检测已在 quick_check 中完成
        // 这里不需要重复检测，因为能执行到这里说明：
        // 1. 文件没有签名（有签名的在quick_check中已返回）
        // 2. 文件没有感染型病毒（有感染型病毒的也在quick_check中已返回）

        // 如果签名可信但模型检测为恶意，降低威胁等级
        let final_result = if is_malicious && is_trusted {
            "CLEAN".to_string()  // 有有效签名的文件视为安全
        } else if is_malicious {
            "MALICIOUS".to_string()
        } else {
            "CLEAN".to_string()
        };

        let result = ScanResult {
            file_path: file_path.to_string(),
            file_hash: file_hash.clone(),
            result: final_result,
            probability: if is_trusted { 0.0 } else { probability },
            signature_status,
            is_trusted,
            error: None,
            virus_family,
            family_category,
            is_infector: false, // 能执行到这里说明没有感染型病毒
        };

        // 缓存结果
        {
            let mut cache = self.result_cache.lock().unwrap();
            if cache.len() > 10000 {
                cache.clear();
            }
            cache.insert(file_path.to_string(), result.clone());
        }

        result
    }

    // 批量扫描 - 使用Rayon并行处理，优化并行度
    pub fn scan_batch(&self, file_paths: Vec<String>) -> Vec<ScanResult> {
        self.scan_batch_with_hashes(file_paths, None)
    }

    // 批量扫描 - 使用预计算哈希，避免重复读取文件
    pub fn scan_batch_with_hashes(&self, file_paths: Vec<String>, precomputed_hashes: Option<Vec<Option<String>>>) -> Vec<ScanResult> {
        let total = file_paths.len();
        println!("[SCAN_BATCH] Starting batch scan of {} files", total);
        let start = Instant::now();

        // 重置批量计时器
        EXTRACT_TIME_NS.store(0, Ordering::Relaxed);
        ONNX_TIME_NS.store(0, Ordering::Relaxed);

        let hashes = precomputed_hashes.unwrap_or_default();
        let use_hashes = hashes.len() == total;
        
        // 使用Rayon并行处理，增大每个任务处理的文件数以减少调度开销
        let results: Vec<ScanResult> = file_paths.par_iter()
            .enumerate()
            .with_max_len(4)  // 每个任务处理4个文件，降低调度开销
            .map(|(i, path)| {
                let hash_ref = if use_hashes {
                    hashes[i].as_deref()
                } else {
                    None
                };
                let result = self.scan_file(path, hash_ref);
                result
            })
            .collect();
        
        let elapsed = start.elapsed();
        let threats = results.iter().filter(|r| r.result == "MALICIOUS").count();
        let avg_ms = if total > 0 {
            elapsed.as_millis() as f64 / total as f64
        } else {
            0.0
        };
        let cpu_cores = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let extract_ms = EXTRACT_TIME_NS.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let onnx_ms = ONNX_TIME_NS.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let parallelism_extract = if extract_ms > 0.0 { extract_ms / elapsed.as_millis() as f64 } else { 0.0 };
        let parallelism_onnx = if onnx_ms > 0.0 { onnx_ms / elapsed.as_millis() as f64 } else { 0.0 };
        println!("[SCAN_BATCH] Completed {} files in {:?} (avg {:.2}ms/file, {} CPU cores), found {} threats", total, elapsed, avg_ms, cpu_cores, threats);
        println!("[SCAN_BATCH] Breakdown: extract={:.1}ms total, onnx={:.1}ms total; parallelism: extract={:.1}x, onnx={:.1}x", extract_ms, onnx_ms, parallelism_extract, parallelism_onnx);
        
        results
    }

    // 检查路径是否位于排除目录中（用于快速扫描跳过系统目录）
    fn is_in_excluded_dirs(path: &str, excluded_dirs: &[String]) -> bool {
        let path_lower = path.to_lowercase();
        excluded_dirs.iter().any(|excluded| {
            let excluded_lower = excluded.to_lowercase();
            path_lower.starts_with(&excluded_lower)
        })
    }

    // 检查文件路径是否为PE文件（通过读取文件MZ头）
    fn is_pe_file_by_path(path: &str) -> bool {
        use std::io::Read;
        
        if let Ok(mut file) = fs::File::open(path) {
            let mut header = [0u8; 2];
            if file.read_exact(&mut header).is_ok() {
                // 检查MZ头 (0x4D 0x5A) 或 "MZ"
                return header[0] == b'M' && header[1] == b'Z';
            }
        }
        false
    }

    // 获取扫描文件列表
    // filter_extensions: true=只扫描PE扩展名, false=扫描PE文件+脚本文件+压缩包
    pub fn get_scan_files(&self, paths: Vec<String>, filter_extensions: bool) -> Vec<String> {
        let mut files = vec![];
        
        // 脚本文件扩展名（自定义扫描时包含）
        let script_extensions = ["bat", "cmd"];
        // 压缩包扩展名
        let archive_extensions = ["zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz"];
        // 快速扫描默认排除的系统/Windows应用目录
        let excluded_dirs: Vec<String> = if filter_extensions {
            vec![
                "C:\\Program Files\\WindowsApps".to_string(),
                "C:\\Program Files (x86)\\WindowsApps".to_string(),
            ]
        } else {
            vec![]
        };

        for path in paths {
            let path_obj = std::path::Path::new(&path);

            if path_obj.is_file() {
                // 快速扫描时排除 WindowsApps 路径下的文件
                if filter_extensions && Self::is_in_excluded_dirs(&path, &excluded_dirs) {
                    continue;
                }
                let ext = path_obj.extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                    
                if filter_extensions {
                    // 普通扫描：只扫描PE扩展名 + 压缩包
                    if ["exe", "dll", "sys", "drv", "ocx", "scr"].contains(&ext.as_str()) 
                        || archive_extensions.contains(&ext.as_str()) {
                        files.push(path);
                    }
                } else {
                    // 自定义扫描：PE文件 + 脚本文件 + 压缩包
                    if Self::is_pe_file_by_path(&path) 
                        || script_extensions.contains(&ext.as_str())
                        || archive_extensions.contains(&ext.as_str())
                        || path.to_lowercase().contains("eicar") {
                        files.push(path);
                    }
                }
            } else if path_obj.is_dir() {
                for entry in WalkDir::new(&path)
                    .max_depth(5)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    if entry.file_type().is_file() {
                        if let Some(path_str) = entry.path().to_str() {
                            // 快速扫描时排除 WindowsApps 路径下的文件
                            if filter_extensions && Self::is_in_excluded_dirs(path_str, &excluded_dirs) {
                                continue;
                            }
                            let ext = entry.path().extension()
                                .and_then(|e| e.to_str())
                                .unwrap_or("")
                                .to_lowercase();

                            if filter_extensions {
                                // 普通扫描：只扫描PE扩展名 + 压缩包
                                if ["exe", "dll", "sys", "drv", "ocx", "scr"].contains(&ext.as_str())
                                    || archive_extensions.contains(&ext.as_str()) {
                                    files.push(path_str.to_string());
                                }
                                // 普通扫描也兜底 EICAR
                                if path_str.to_lowercase().contains("eicar") {
                                    files.push(path_str.to_string());
                                }
                            } else {
                                // 自定义扫描：PE文件 + 脚本文件 + 压缩包
                                if Self::is_pe_file_by_path(path_str) 
                                    || script_extensions.contains(&ext.as_str())
                                    || archive_extensions.contains(&ext.as_str())
                                    || path_str.to_lowercase().contains("eicar") {
                                    files.push(path_str.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        files
    }

    // 从内存缓冲区扫描文件内容（用于压缩包扫描）
    pub fn scan_memory_buffer(&self, buffer: &[u8], virtual_path: &str) -> ScanResult {
        const MIN_FILE_SIZE: usize = 16;

        let file_size = buffer.len();

        // 处理极小文件
        if file_size < MIN_FILE_SIZE {
            return ScanResult {
                file_path: virtual_path.to_string(),
                file_hash: None,
                result: "CLEAN".to_string(),
                probability: 0.0,
                signature_status: Some("File too small".to_string()),
                is_trusted: false,
                error: None,
                virus_family: None,
                family_category: None,
                is_infector: false,
            };
        }

        // 提取特征（使用完整缓冲区，不截断）
        let features = match self.extract_features_from_bytes(buffer, file_size) {
            Ok(f) => f,
            Err(e) => {
                return ScanResult {
                    file_path: virtual_path.to_string(),
                    file_hash: None,
                    result: "ERROR".to_string(),
                    probability: 0.0,
                    signature_status: None,
                    is_trusted: false,
                    error: Some(e),
                    virus_family: None,
                    family_category: None,
                    is_infector: false,
                };
            }
        };

        // 运行ONNX模型推理
        let probability = match self.run_tree_inference(&features) {
            Ok(prob) => {
                println!("[SCAN_MEM] {} | probability={:.6} | threshold={} | result={}", virtual_path, prob, self.threshold, if prob >= self.threshold { "MALICIOUS" } else { "CLEAN" });
                prob
            }
            Err(e) => {
                return ScanResult {
                    file_path: virtual_path.to_string(),
                    file_hash: None,
                    result: "ERROR".to_string(),
                    probability: 0.0,
                    signature_status: None,
                    is_trusted: false,
                    error: Some(format!("ONNX inference error: {}", e)),
                    virus_family: None,
                    family_category: None,
                    is_infector: false,
                };
            }
        };

        // 使用动态阈值判断
        let is_malicious = probability >= self.threshold;

        // 如果是恶意软件，使用病毒家族引擎分析
        let virus_family = if is_malicious && is_virus_family_analysis_enabled() {
            // 对于内存扫描，使用启发式分析
            Some(format!("HEUR:Suspicious (Memory Scan) ({:.1}%)", probability * 100.0))
        } else {
            None
        };
        let family_category = virus_family.as_ref().map(|_| "可疑程序".to_string());

        let final_result = if is_malicious {
            "MALICIOUS".to_string()
        } else {
            "CLEAN".to_string()
        };

        ScanResult {
            file_path: virtual_path.to_string(),
            file_hash: None, // 内存扫描不计算哈希
            result: final_result,
            probability,
            signature_status: Some("Memory scan".to_string()),
            is_trusted: false,
            error: None,
            virus_family,
            family_category,
            is_infector: false,
        }
    }

    // 从字节数组提取 EMBER V3 2568维特征（委托给 ember_features 模块）
    fn extract_features_from_bytes(&self, _bytes: &[u8], _original_size: usize) -> Result<Vec<f32>, String> {
        crate::ember_features::extract(_bytes).ok_or_else(|| "Not a valid PE file".to_string())
    }
}

// 全局扫描器实例
lazy_static::lazy_static! {
    pub static ref SCANNER: Arc<RwLock<Scanner>> = Arc::new(RwLock::new(Scanner::new()));
}

// 实时防护跳过病毒家族分析的标志（先杀进程再异步分析）
pub static SKIP_FAMILY_ANALYSIS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// 禁用本地规则库（跳过黑白名单/哈希校验，直接走引擎扫描）
pub static SKIP_LOCAL_RULES: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// Tauri命令
#[tauri::command]
pub async fn scan_file_direct(file_path: String, file_hash: Option<String>) -> Result<String, String> {
    let result = tokio::task::spawn_blocking(move || -> Result<ScanResult, String> {
        let scanner = SCANNER.read().map_err(|e| e.to_string())?;
        let hash_ref = file_hash.as_deref();
        Ok(scanner.scan_file(&file_path, hash_ref))
    }).await.map_err(|e| format!("Scan task failed: {}", e))??;
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn scan_batch_direct(file_paths: Vec<String>) -> Result<String, String> {
    let result = tokio::task::spawn_blocking(move || -> Result<Vec<ScanResult>, String> {
        let scanner = SCANNER.read().map_err(|e| e.to_string())?;
        Ok(scanner.scan_batch(file_paths))
    }).await.map_err(|e| format!("Scan task failed: {}", e))??;
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn scan_batch_direct_with_hashes(file_paths: Vec<String>, hashes: Vec<Option<String>>) -> Result<String, String> {
    let result = tokio::task::spawn_blocking(move || -> Result<Vec<ScanResult>, String> {
        let scanner = SCANNER.read().map_err(|e| e.to_string())?;
        Ok(scanner.scan_batch_with_hashes(file_paths, Some(hashes)))
    }).await.map_err(|e| format!("Scan task failed: {}", e))??;
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_scan_files_direct(paths: Vec<String>) -> Result<Vec<String>, String> {
    let scanner = SCANNER.read().map_err(|e| e.to_string())?;
    // 自定义扫描：不过滤扩展名，扫描所有文件
    Ok(scanner.get_scan_files(paths, false))
}

#[tauri::command]
pub async fn get_scan_files_filtered(paths: Vec<String>) -> Result<Vec<String>, String> {
    let scanner = SCANNER.read().map_err(|e| e.to_string())?;
    // 快速/全盘扫描：只扫描PE扩展名
    Ok(scanner.get_scan_files(paths, true))
}

/// 检查 TreeEnsemble 模型是否已加载
#[tauri::command]
pub async fn check_onnx_model_loaded() -> Result<bool, String> {
    let scanner = SCANNER.read().map_err(|e| e.to_string())?;
    let loaded = scanner.tree_model.read().map_err(|e| e.to_string())?.is_some();
    Ok(loaded)
}

/// 获取/设置「禁用本地规则库」状态（传递 None 仅查询，Some(true/false) 设置）
#[tauri::command]
pub async fn set_skip_local_rules(enabled: Option<bool>) -> Result<bool, String> {
    if let Some(val) = enabled {
        SKIP_LOCAL_RULES.store(val, std::sync::atomic::Ordering::Relaxed);
        println!("[Scanner] - SKIP_LOCAL_RULES set to {}", val);
    }
    Ok(SKIP_LOCAL_RULES.load(std::sync::atomic::Ordering::Relaxed))
}

/// 计算文件SHA256哈希（流式读取，支持大文件）
pub(crate) fn calculate_file_hash(file_path: &str) -> Result<String, String> {
    use std::io::Read;
    
    let file = match fs::File::open(file_path) {
        Ok(f) => f,
        Err(e) => return Err(format!("Failed to open file: {}", e)),
    };
    
    let mut hasher = Sha256::new();
    let mut reader = std::io::BufReader::new(file);
    let mut buffer = [0u8; 8192]; // 8KB 缓冲区
    
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break, // 文件读取完毕
            Ok(n) => {
                hasher.update(&buffer[..n]);
            }
            Err(e) => return Err(format!("Failed to read file: {}", e)),
        }
    }
    
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

/// 计算文件SHA256哈希（供前端调用）- 异步版本，避免阻塞UI
#[tauri::command]
pub async fn calculate_file_hash_command(file_path: String) -> Result<String, String> {
    // 在独立线程中执行哈希计算，避免阻塞主线程
    let path = file_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        calculate_file_hash(&path)
    }).await;
    
    match result {
        Ok(Ok(hash)) => Ok(hash),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("Hash calculation task failed".to_string()),
    }
}

/// 批量计算文件SHA256哈希（减少IPC往返和线程调度开销，使用Rayon并行计算）
#[tauri::command]
pub async fn calculate_file_hashes_command(file_paths: Vec<String>) -> Result<Vec<Option<String>>, String> {
    let result = tokio::task::spawn_blocking(move || {
        // 使用Rayon并行计算整批文件哈希，充分利用多核和磁盘并发I/O
        file_paths.par_iter()
            .map(|path| {
                match calculate_file_hash(path) {
                    Ok(hash) => Some(hash),
                    Err(e) => {
                        eprintln!("[HashBatch] Failed for {}: {}", path, e);
                        None
                    }
                }
            })
            .collect::<Vec<Option<String>>>()
    }).await;
    
    match result {
        Ok(hashes) => Ok(hashes),
        Err(_) => Err("Hash batch calculation task failed".to_string()),
    }
}

/// 扫描脚本文件（供前端调用）
#[tauri::command]
pub async fn scan_script_file_command(file_path: String) -> Result<serde_json::Value, String> {
    use crate::scanner::script_scanner::scan_script_file;
    
    tokio::task::spawn_blocking(move || {
        match scan_script_file(&file_path) {
            Some(result) => {
                Ok(serde_json::json!({
                    "is_malicious": result.is_malicious,
                    "virus_family": result.virus_family,
                    "threat_level": result.threat_level,
                    "description": result.description
                }))
            }
            None => Ok(serde_json::json!({
                "is_malicious": false,
                "virus_family": null,
                "threat_level": 0.0,
                "description": ""
            }))
        }
    }).await.map_err(|e| e.to_string())?
}

/// 云端哈希检查请求参数
#[derive(Debug, Serialize, Deserialize)]
pub struct CloudHashCheckRequest {
    pub hash: String,
}

/// 云端哈希检查响应（匹配云端API格式）
#[derive(Debug, Serialize, Deserialize)]
pub struct CloudHashCheckResponse {
    pub code: Option<i32>,
    pub result: String,
    #[serde(rename = "family")]
    pub family: Option<String>,
    #[serde(rename = "message")]
    pub message: Option<String>,
    pub hash: Option<String>,
    pub hash_type: Option<String>,
}

/// 云端哈希批量检查请求参数
#[derive(Debug, Serialize, Deserialize)]
pub struct CloudHashBatchRequest {
    pub hashes: Vec<String>,
}

/// 云端哈希批量检查单条结果
#[derive(Debug, Serialize, Deserialize)]
pub struct CloudHashBatchItem {
    pub hash: String,
    pub result: String,
    pub message: Option<String>,
    pub family: Option<String>,
}

/// 云端哈希批量检查响应
#[derive(Debug, Serialize, Deserialize)]
pub struct CloudHashBatchResponse {
    pub code: Option<i32>,
    pub results: Vec<CloudHashBatchItem>,
}

/// 云端哈希检查命令（代理前端请求，解决CSP限制）
#[tauri::command]
pub async fn cloud_hash_check_command(
    server_url: String,
    api_key: String,
    request: CloudHashCheckRequest,
) -> Result<CloudHashCheckResponse, String> {
    let url = format!("{}/api/check?key={}", server_url, api_key);
    
    let response = HTTP_CLIENT
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;
    
    let status = response.status();
    let text = response.text().await.map_err(|e| format!("Failed to read response: {}", e))?;
    
    if !status.is_success() {
        return Err(format!("HTTP error {}: {}", status, text));
    }
    
    let result: CloudHashCheckResponse = serde_json::from_str(&text)
        .map_err(|e| format!("Failed to parse response: {} | raw: {}", e, text))?;
    
    Ok(result)
}

/// 云端哈希批量检查命令（代理前端请求，解决CSP限制）
#[tauri::command]
pub async fn cloud_hash_batch_command(
    server_url: String,
    api_key: String,
    request: CloudHashBatchRequest,
) -> Result<CloudHashBatchResponse, String> {
    let url = format!("{}/api/batch_check?key={}", server_url, api_key);
    
    let response = HTTP_CLIENT
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;
    
    let status = response.status();
    let text = response.text().await.map_err(|e| format!("Failed to read response: {}", e))?;
    
    if !status.is_success() {
        return Err(format!("HTTP error {}: {}", status, text));
    }
    
    let result: CloudHashBatchResponse = serde_json::from_str(&text)
        .map_err(|e| format!("Failed to parse response: {} | raw: {}", e, text))?;
    
    Ok(result)
}
