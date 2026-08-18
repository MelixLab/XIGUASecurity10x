use std::path::Path;
use std::sync::{Arc, RwLock, Mutex};
use serde::{Deserialize, Serialize};
use std::fs;
use std::time::{Duration, Instant};
use std::cell::RefCell;
use sha2::{Sha256, Digest};

// ONNX Runtime imports
use ort::session::Session;
use ort::value::Value;
use ndarray::Array2;

// Stub whitelist functions (no external whitelist module)
fn is_hash_whitelisted(_hash: &str) -> bool { false }
fn is_name_whitelisted(_name: &str) -> bool { false }
fn is_path_whitelisted(_path: &str) -> bool { false }

// 哈希白名单 - 这些文件哈希不会被报毒
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

    // 病毒哈希黑名单 - 已知恶意文件哈希
    static ref HASH_BLACK_LIST: std::collections::HashMap<String, String> = {
        let mut map = std::collections::HashMap::new();
        // pyas_killer.exe - AVKill 工具 (前10MB哈希)
        map.insert("96A296D224F285C67BEE93C30F8A309157F0DAA35DC5B87E410B78630A09CFC7".to_string(), "AVKill".to_string());
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
        set.insert("InstallFilter.exe".to_string());
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

        // 没有嵌入式签名，检查是否有目录签名
        // 通过检查文件是否有安全目录条目来快速判断
        // 使用ImageGetCertificateData或类似方法

        // 简单方法：检查文件是否有目录签名的特征
        // 读取文件PE头检查安全目录引用
        if let Ok(data) = std::fs::read(file_path) {
            if data.len() > 64 {
                // 检查PE头中的安全目录表
                let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
                if pe_offset > 0 && pe_offset + 24 < data.len() {
                    // 检查数据目录表中的安全目录项（第4个条目，索引3）
                    let security_dir_offset = pe_offset + 24 + 3 * 8; // 3 * sizeof(IMAGE_DATA_DIRECTORY)
                    if security_dir_offset + 8 <= data.len() {
                        let _virtual_address = u32::from_le_bytes([
                            data[security_dir_offset],
                            data[security_dir_offset + 1],
                            data[security_dir_offset + 2],
                            data[security_dir_offset + 3],
                        ]);
                        // 如果虚拟地址为0，说明没有嵌入式签名，但可能有目录签名
                        // 目录签名存储在Windows目录签名数据库中，不在文件本身
                        // 这种情况下我们需要信任Windows的系统文件

                        // 检查是否是系统文件路径
                        let _lower_path = file_path.to_lowercase();
                        // Windows目录不再自动信任，需要实际签名验证
                    }
                }
            }
        }

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
    session: Arc<RwLock<Option<Session>>>,
    // 模型数据，用于 thread_local Session 创建
    model_data: Arc<RwLock<Option<Vec<u8>>>>,
    threshold: f32,
    system_paths: Vec<String>,
    model_path: Option<String>,
    // 缓存已扫描文件的结果
    result_cache: Arc<Mutex<std::collections::HashMap<String, ScanResult>>>,
    // 当前模型的特征维度（低敏感度=283，高敏感度=567）
    pub feature_dim: std::sync::atomic::AtomicUsize,
}

#[allow(dead_code)]
impl Scanner {
    pub fn new() -> Self {
        let mut scanner = Self {
            session: Arc::new(RwLock::new(None)),
            model_data: Arc::new(RwLock::new(None)),
            threshold: 0.92,
            system_paths: vec![],
            model_path: None,
            result_cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
            feature_dim: std::sync::atomic::AtomicUsize::new(567),
        };

        // 尝试加载ONNX模型
        match scanner.load_model() {
            Ok(_) => println!("[Scanner] - ONNX model loaded successfully"),
            Err(e) => eprintln!("[Scanner] - Failed to load ONNX model: {}", e),
        }

        scanner
    }

    fn load_model(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // 获取可执行文件所在目录
        let exe_path = std::env::current_exe()
            .map_err(|e| format!("Failed to get exe path: {}", e))?;
        let exe_dir = exe_path.parent()
            .ok_or("Failed to get exe directory")?;

        // 尝试多个相对路径查找模型（包括开发模式和发布模式）
        let model_paths = vec![
            // 发布模式路径 - 与exe同目录
            exe_dir.join("engines").join("melix").join("DeepMode.onnx"),
            exe_dir.join("DeepMode.onnx"),
            // 开发模式路径（从target/debug或target/release向上找到项目根目录）
            exe_dir.parent().unwrap_or(exe_dir).parent().unwrap_or(exe_dir).join("engines").join("melix").join("DeepMode.onnx"),
            exe_dir.parent().unwrap_or(exe_dir).join("engines").join("melix").join("DeepMode.onnx"),
        ];

        for path_buf in &model_paths {
            if path_buf.exists() {
                let path_str = path_buf.to_string_lossy();
                println!("[Scanner] - Loading ONNX model from: {}", path_str);

                // 读取模型文件
                let model_data = fs::read(&path_buf)?;

                // 创建主 Session
                let session = Session::builder()?
                    .with_intra_threads(1)?
                    .commit_from_memory(&model_data)?;

                *self.session.write().unwrap() = Some(session);
                
                // 保存模型数据用于 thread_local Session 创建
                *self.model_data.write().unwrap() = Some(model_data);
                
                self.model_path = Some(path_str.to_string());
                println!("[Scanner] - ONNX model loaded successfully (thread_local mode)");
                return Ok(());
            }
        }

        // 打印所有尝试过的路径，方便调试
        eprintln!("[Scanner] - ERROR: Could not find DeepMode.onnx in any of these locations:");
        for path in &model_paths {
            eprintln!("  - {}", path.display());
        }
        Err("DeepMode.onnx not found. Please ensure the model file exists in Driver/Melix/ directory".into())
    }

    /// 运行时重新加载模型（用于切换敏感度模式）
    pub fn reload_model(&self, model_path: &str, feature_dim: usize) -> Result<(), String> {
        let path = std::path::Path::new(model_path);
        println!("[Scanner] - reload_model path: {}", path.display());

        // 检查文件元数据
        match std::fs::metadata(path) {
            Ok(meta) => {
                println!("[Scanner] - File size: {}, is_file: {}", meta.len(), meta.is_file());
                if !meta.is_file() {
                    return Err(format!("Path is not a file: {}", model_path));
                }
            }
            Err(e) => return Err(format!("Cannot access model file metadata: {} - {}", model_path, e)),
        }

        let mut file = std::fs::File::open(path)
            .map_err(|e| format!("Failed to open model file: {} - {}", model_path, e))?;
        let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
        println!("[Scanner] - Opened file, size: {}", file_len);

        let mut model_data = Vec::with_capacity(file_len as usize + 1);
        use std::io::Read;
        file.read_to_end(&mut model_data)
            .map_err(|e| format!("Failed to read model file content: {}", e))?;
        println!("[Scanner] - Read {} bytes from model file", model_data.len());
        let session = Session::builder()
            .map_err(|e| format!("Failed to create session builder: {}", e))?
            .with_intra_threads(1)
            .map_err(|e| format!("Failed to set intra threads: {}", e))?
            .commit_from_memory(&model_data)
            .map_err(|e| format!("Failed to commit model from memory: {}", e))?;

        *self.session.write().map_err(|e| e.to_string())? = Some(session);
        // 清空结果缓存，确保切换模型后旧缓存不生效
        {
            let mut cache = self.result_cache.lock().unwrap();
            let old_len = cache.len();
            cache.clear();
            println!("[Scanner] - Cleared result cache ({} entries) after model reload", old_len);
        }
        self.feature_dim.store(feature_dim, std::sync::atomic::Ordering::Relaxed);
        println!("[Scanner] - Model reloaded from: {}, feature_dim: {}", model_path, self.feature_dim.load(std::sync::atomic::Ordering::Relaxed));
        Ok(())
    }

    /// 获取扫描器状态信息
    pub fn get_info(&self) -> serde_json::Value {
        let model_loaded = self.session.read().unwrap().is_some();
        serde_json::json!({
            "model_loaded": model_loaded,
            "model_path": self.model_path,
            "threshold": self.threshold,
        })
    }

    // 提取文件特征（依据当前模型维度，低敏感度=283维，高敏感度=567维）
    // 0-282: 原始特征（字节频率、熵、统计特征）
    // 283-538: 字节二元组哈希频率 (256维) （仅567维模型）
    // 539-546: 字节分布统计 (8维) （仅567维模型）
    // 547-554: 区域熵 (8维) （仅567维模型）
    // 555-566: 结构特征 (12维) （仅567维模型）
    pub fn extract_features(&self, file_path: &str) -> Result<Vec<f32>, String> {
        let feature_dim = self.feature_dim.load(std::sync::atomic::Ordering::Relaxed);
        const MAX_FILE_SIZE: usize = 2 * 1024 * 1024; // 2MB (足够提取特征)
        const MIN_FILE_SIZE: usize = 16;

        let metadata = fs::metadata(file_path).map_err(|e| e.to_string())?;
        let file_size = metadata.len() as usize;

        // 处理极小文件
        if file_size < MIN_FILE_SIZE {
            return Ok(self.create_default_features(file_size));
        }

        // 读取文件（限制大小）
        let bytes = if file_size > MAX_FILE_SIZE {
            let mut buf = vec![0u8; MAX_FILE_SIZE];
            let mut file = fs::File::open(file_path).map_err(|e| e.to_string())?;
            use std::io::Read;
            let _ = file.read_exact(&mut buf);
            buf
        } else {
            fs::read(file_path).map_err(|e| e.to_string())?
        };

        let total_bytes = bytes.len();
        let total_bytes_f = total_bytes as f64;

        // 统计各种字节类型 - 单次遍历
        let mut byte_counts = [0i64; 256];
        let mut printable_count = 0;
        let mut control_count = 0;
        let mut whitespace_count = 0;
        let mut letter_count = 0;
        let mut digit_count = 0;
        let mut max_zero_run = 0;
        let mut current_zero_run = 0;
        let mut high_byte_count = 0;

        // 新增跟踪变量
        let mut bigram_counts = [0i64; 256];
        let mut non_zero_run_sum: i64 = 0;
        let mut non_zero_run_count = 0;
        let mut max_non_zero_run = 0;
        let mut current_non_zero_run = 0;
        let mut first_1024_nulls = 0;
        let mut after_1024_nulls = 0;
        let mut first_1024_count = 0;
        let mut after_1024_count = 0;
        let mut ff_count = 0;
        let mut high_unicode_count = 0;
        let mut non_zero_control_count = 0;
        let mut pair_repetitions = 0;
        let mut total_pairs = 0;
        let mut prev_byte: u8 = 0;
        let mut auto_sum_x: f64 = 0.0;
        let mut auto_sum_y: f64 = 0.0;
        let mut auto_sum_xy: f64 = 0.0;
        let mut auto_sum_x2: f64 = 0.0;
        let mut auto_sum_y2: f64 = 0.0;

        for (i, &b) in bytes.iter().enumerate() {
            byte_counts[b as usize] += 1;

            // 原有统计
            if b >= 0x80 {
                high_byte_count += 1;
            }

            if b == 0 {
                current_zero_run += 1;
                max_zero_run = max_zero_run.max(current_zero_run);
            } else {
                current_zero_run = 0;
            }

            if b >= 32 && b <= 126 {
                printable_count += 1;
                if b.is_ascii_alphabetic() {
                    letter_count += 1;
                } else if b.is_ascii_digit() {
                    digit_count += 1;
                }
            } else if b < 32 || b == 127 {
                control_count += 1;
            }
            if b == 9 || b == 10 || b == 13 || b == 32 {
                whitespace_count += 1;
            }

            // 二元组与自相关
            if i > 0 {
                let hash = ((prev_byte as usize) * 31 + b as usize) & 0xFF;
                bigram_counts[hash] += 1;
                if b == prev_byte { pair_repetitions += 1; }
                total_pairs += 1;
                let x = prev_byte as f64;
                let y = b as f64;
                auto_sum_x += x; auto_sum_y += y;
                auto_sum_xy += x * y;
                auto_sum_x2 += x * x;
                auto_sum_y2 += y * y;
            }

            // 非零连续段
            if b != 0 {
                current_non_zero_run += 1;
                max_non_zero_run = max_non_zero_run.max(current_non_zero_run);
            } else {
                if current_non_zero_run > 0 {
                    non_zero_run_sum += current_non_zero_run as i64;
                    non_zero_run_count += 1;
                }
                current_non_zero_run = 0;
            }

            // 按位置统计null
            if i < 1024 {
                first_1024_count += 1;
                if b == 0 { first_1024_nulls += 1; }
            } else {
                after_1024_count += 1;
                if b == 0 { after_1024_nulls += 1; }
            }

            // 特殊字节
            if b == 0xFF { ff_count += 1; }
            if b >= 0xC0 { high_unicode_count += 1; }
            if b > 0 && b < 32 { non_zero_control_count += 1; }

            prev_byte = b;
        }
        if current_non_zero_run > 0 {
            non_zero_run_sum += current_non_zero_run as i64;
            non_zero_run_count += 1;
        }

        let mut features = vec![0.0f32; feature_dim];


        // ========== 原有特征 (0-282) ==========

        // 1. 字节频率 (256维)
        for i in 0..256 {
            features[i] = (byte_counts[i] as f64 / total_bytes_f) as f32;
        }
        // 2. 熵值 (1维)
        features[256] = self.calculate_entropy(&byte_counts, total_bytes_f);
        // 3. 块级熵值 (16维)
        self.calculate_block_entropies_fast(&bytes, &mut features);
        // 4-11. 其他特征
        features[273] = (printable_count as f64 / total_bytes_f) as f32;
        features[274] = (control_count as f64 / total_bytes_f) as f32;
        features[275] = (whitespace_count as f64 / total_bytes_f) as f32;
        features[276] = (letter_count as f64 / total_bytes_f) as f32;
        features[277] = (digit_count as f64 / total_bytes_f) as f32;
        features[278] = (high_byte_count as f64 / total_bytes_f) as f32;
        features[279] = max_zero_run as f32;
        features[280] = (byte_counts[0] as f64 / total_bytes_f) as f32;
        features[281] = if self.is_pe_file(&bytes) { 1.0f32 } else { 0.0f32 };
        features[282] = ((file_size + 1) as f64).log10() as f32;

        // ========== 新增特征 (283-566) — 仅567维模型使用 ==========
        if feature_dim > 283 {

        // 14. 字节二元组哈希频率 (256维)
        let total_pairs_f = total_pairs.max(1) as f64;
        for i in 0..256 {
            features[283 + i] = (bigram_counts[i] as f64 / total_pairs_f) as f32;
        }

        // 15. 字节分布统计 (8维: 539-546)
        let mean_freq = total_bytes_f / 256.0;
        let mut variance = 0.0f64;
        for i in 0..256 {
            let diff = byte_counts[i] as f64 - mean_freq;
            variance += diff * diff;
        }
        variance /= 256.0;
        let std_dev = variance.sqrt();
        features[539] = (std_dev / (mean_freq + 1e-10)) as f32; // 变异系数

        if std_dev > 1e-10 {
            let mut skewness = 0.0f64;
            let mut kurtosis = 0.0f64;
            for i in 0..256 {
                let z = (byte_counts[i] as f64 - mean_freq) / std_dev;
                skewness += z * z * z;
                kurtosis += z * z * z * z;
            }
            features[540] = (skewness / 256.0) as f32;           // 偏度
            features[541] = (kurtosis / 256.0 - 3.0) as f32;     // 超额峰度
        }

        // Top-N 字节比例 (使用 select 避免完整排序)
        let mut sorted_counts: Vec<i64> = byte_counts.to_vec();
        sorted_counts.select_nth_unstable_by(9, |a, b| b.cmp(a));
        sorted_counts[..10].sort_unstable_by(|a, b| b.cmp(a));
        features[542] = (sorted_counts[0] as f64 / total_bytes_f) as f32;
        features[543] = (sorted_counts[..5].iter().sum::<i64>() as f64 / total_bytes_f) as f32;
        features[544] = (sorted_counts[..10].iter().sum::<i64>() as f64 / total_bytes_f) as f32;

        // 唯一字节种类数
        let unique_bytes = byte_counts.iter().filter(|&&c| c > 0).count();
        features[545] = unique_bytes as f32 / 256.0;

        // Gini系数 (排序后 O(n log n) 公式)
        let mut gini_sorted: Vec<i64> = byte_counts.to_vec();
        gini_sorted.sort_unstable();
        let mut weighted_sum = 0.0f64;
        let total_count: f64 = gini_sorted.iter().sum::<i64>() as f64;
        for (i, &val) in gini_sorted.iter().enumerate() {
            weighted_sum += (i as f64 + 1.0) * val as f64;
        }
        features[546] = if total_count > 0.0 {
            ((2.0 * weighted_sum - (256.0 + 1.0) * total_count) / (256.0 * total_count) + 1.0) as f32
        } else { 0.0 };

        // 16. 区域熵 (8维: 547-554)
        let region_size = (total_bytes / 8).max(1);
        for r in 0..8 {
            let start = r * region_size;
            let end = if r == 7 { total_bytes } else { (start + region_size).min(total_bytes) };
            let len = end - start;
            if len > 0 {
                let mut region_counts = [0i64; 256];
                for idx in start..end {
                    region_counts[bytes[idx] as usize] += 1;
                }
                features[547 + r] = self.calculate_entropy(&region_counts, len as f64);
            }
        }

        // 17. 结构特征 (12维: 555-566)
        // 非零连续段平均长度 (归一化)
        features[555] = if non_zero_run_count > 0 {
            (non_zero_run_sum as f64 / non_zero_run_count as f64 / total_bytes_f) as f32
        } else { 0.0 };
        // 非零连续段最大长度 (归一化)
        features[556] = (max_non_zero_run as f64 / total_bytes_f) as f32;
        // 前1024字节null比例
        features[557] = if first_1024_count > 0 { first_1024_nulls as f32 / first_1024_count as f32 } else { 0.0 };
        // 1024字节后null比例
        features[558] = if after_1024_count > 0 { after_1024_nulls as f32 / after_1024_count as f32 } else { 0.0 };
        // 前后半熵差
        let half_point = total_bytes / 2;
        if half_point > 0 {
            let mut fh_counts = [0i64; 256];
            let mut sh_counts = [0i64; 256];
            for i in 0..half_point { fh_counts[bytes[i] as usize] += 1; }
            for i in half_point..total_bytes { sh_counts[bytes[i] as usize] += 1; }
            features[559] = (self.calculate_entropy(&fh_counts, half_point as f64)
                - self.calculate_entropy(&sh_counts, (total_bytes - half_point) as f64)).abs();
        }
        // 块熵标准差
        let block_entropy_mean: f32 = features[257..273].iter().sum::<f32>() / 16.0;
        let block_entropy_var: f32 = features[257..273].iter()
            .map(|&v| (v - block_entropy_mean).powi(2))
            .sum::<f32>() / 16.0;
        features[560] = block_entropy_var.sqrt();
        // 字节自相关系数 (lag-1)
        let n = (total_bytes - 1) as f64;
        if n > 0.0 {
            let corr_num = n * auto_sum_xy - auto_sum_x * auto_sum_y;
            let corr_den = ((n * auto_sum_x2 - auto_sum_x * auto_sum_x) * (n * auto_sum_y2 - auto_sum_y * auto_sum_y)).sqrt();
            features[561] = if corr_den > 1e-10 { (corr_num / corr_den) as f32 } else { 0.0 };
        }
        // 0xFF字节比例
        features[562] = (ff_count as f64 / total_bytes_f) as f32;
        // 高Unicode字节比例 (>=0xC0)
        features[563] = (high_unicode_count as f64 / total_bytes_f) as f32;
        // 非零控制字符比例
        features[564] = (non_zero_control_count as f64 / total_bytes_f) as f32;
        // 相邻字节重复比例
        features[565] = if total_pairs > 0 { pair_repetitions as f32 / total_pairs as f32 } else { 0.0 };
        // 唯一二元组种类比例
        let unique_bigrams = bigram_counts.iter().filter(|&&c| c > 0).count();
        features[566] = unique_bigrams as f32 / 256.0;

        }

        Ok(features)
    }

    fn create_default_features(&self, file_size: usize) -> Vec<f32> {
        let mut features = vec![0.0f32; self.feature_dim.load(std::sync::atomic::Ordering::Relaxed)];
        features[282] = ((file_size + 1) as f64).log10() as f32;
        features
    }

    fn calculate_entropy(&self, byte_counts: &[i64; 256], total_bytes: f64) -> f32 {
        let mut entropy = 0.0f64;
        for i in 0..256 {
            if byte_counts[i] > 0 {
                let p = byte_counts[i] as f64 / total_bytes;
                entropy -= p * p.log2();
            }
        }
        entropy as f32
    }

    // 简化的块级熵值计算
    fn calculate_block_entropies_fast(&self, bytes: &[u8], features: &mut [f32]) {
        const BLOCK_SIZE: usize = 256;
        let num_blocks = (bytes.len() / BLOCK_SIZE).min(16);

        if num_blocks == 0 {
            // 文件太小，使用整体熵值
            let mut byte_counts = [0i64; 256];
            for &b in bytes {
                byte_counts[b as usize] += 1;
            }
            let entropy = self.calculate_entropy(&byte_counts, bytes.len() as f64);
            for i in 0..16 {
                features[257 + i] = entropy;
            }
            return;
        }

        for i in 0..num_blocks {
            let start = i * BLOCK_SIZE;
            let length = BLOCK_SIZE.min(bytes.len() - start);

            let mut block_counts = [0i64; 256];
            for j in 0..length {
                block_counts[bytes[start + j] as usize] += 1;
            }

            features[257 + i] = self.calculate_entropy(&block_counts, length as f64);
        }

        // 如果块数不足16，用最后一个块的熵值填充
        if num_blocks < 16 {
            let last_entropy = features[257 + num_blocks - 1];
            for i in num_blocks..16 {
                features[257 + i] = last_entropy;
            }
        }
    }

    fn is_pe_file(&self, data: &[u8]) -> bool {
        if data.len() < 64 {
            return false;
        }

        // Check MZ header
        if data[0] != b'M' || data[1] != b'Z' {
            return false;
        }

        // Get PE header offset
        let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
        if pe_offset + 4 > data.len() {
            return false;
        }

        // Check PE signature
        data[pe_offset] == b'P' && data[pe_offset + 1] == b'E'
    }

    // 运行ONNX模型推理 - 使用 thread_local Session 实现无锁并行
    fn run_onnx_inference(&self, features: &[f32]) -> Result<f32, String> {
        thread_local! {
            static LOCAL_SESSION: RefCell<Option<Session>> = RefCell::new(None);
        }

        let dim = self.feature_dim.load(std::sync::atomic::Ordering::Relaxed);
        // 创建输入张量 [1, dim]
        let input_array = Array2::from_shape_vec((1, dim), features.to_vec())
            .map_err(|e| format!("Failed to create input array: {}", e))?;
        let input_value = Value::from_array(input_array)
            .map_err(|e| format!("Failed to create input value: {}", e))?;
        let label_array = ndarray::Array2::<bool>::from_elem((1, 1), false);
        let label_value = Value::from_array(label_array)
            .map_err(|e| format!("Failed to create label value: {}", e))?;
        let inputs: Vec<(&str, ort::session::SessionInputValue)> = vec![
            ("Features", input_value.into()),
            ("Label", label_value.into())
        ];

        LOCAL_SESSION.with(|cell| {
            // 确保当前线程有 Session
            {
                let mut borrow = cell.borrow_mut();
                if borrow.is_none() {
                    // 从共享的 model_data 创建当前线程的 Session
                    let model_data_guard = self.model_data.read()
                        .map_err(|e| format!("Failed to read model data: {}", e))?;
                    let data = model_data_guard.as_ref()
                        .ok_or("Model data not loaded")?;
                    let s = Session::builder()
                        .map_err(|e| format!("Session builder failed: {}", e))?
                        .with_intra_threads(1)
                        .map_err(|e| format!("Set threads failed: {}", e))?
                        .commit_from_memory(data)
                        .map_err(|e| format!("Commit session failed: {}", e))?;
                    *borrow = Some(s);
                }
            }

            // 执行推理
            let mut borrow = cell.borrow_mut();
            let session = borrow.as_mut().unwrap();
            let outputs = session.run(inputs)
                .map_err(|e| format!("ONNX inference failed: {}", e))?;
            Self::extract_probability(&outputs)
        })
    }

    // 从 ONNX 输出中提取概率
    fn extract_probability(outputs: &ort::session::SessionOutputs) -> Result<f32, String> {
        // 尝试获取 Probability.output
        for (name, output_value) in outputs.iter() {
            if name == "Probability.output" {
                let (_, data) = output_value.try_extract_tensor::<f32>()
                    .map_err(|e| format!("Failed to extract tensor: {}", e))?;
                return Ok(data[0]);
            }
        }

        // 如果没有 Probability.output，尝试 Score.output 并应用 sigmoid
        for (name, output_value) in outputs.iter() {
            if name == "Score.output" {
                let (_, data) = output_value.try_extract_tensor::<f32>()
                    .map_err(|e| format!("Failed to extract tensor: {}", e))?;
                // 应用 sigmoid 函数: 1 / (1 + exp(-score))
                return Ok(1.0f32 / (1.0f32 + (-data[0]).exp()));
            }
        }

        // 回退到第一个输出
        let (_, output_value) = outputs.iter().next()
            .ok_or("No output from model")?;
        let (_, data) = output_value.try_extract_tensor::<f32>()
            .map_err(|e| format!("Failed to extract tensor: {}", e))?;
        Ok(data[0])
    }

    // 快速预检查 - 不运行模型，只做基本检查
    // 简化版：移除了感染型病毒检测
    fn quick_check(&self, file_path: &str) -> Option<ScanResult> {
        // 检查文件是否存在
        if !Path::new(file_path).exists() {
            return Some(ScanResult {
                file_path: file_path.to_string(),
                file_hash: None,
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

        // 检查数字签名（比哈希计算快）
        let (has_signature, signer_name) = verify_file_signature(file_path);
        
        // 如果有签名，则视为安全
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

        // 检查路径白名单（stub：始终返回false）
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

        None // 需要完整扫描
    }

    // 扫描单个文件（简化版：移除了病毒家族分析）
    // precomputed_hash: 前端已计算好的哈希，传入可避免重复计算
    pub fn scan_file(&self, file_path: &str, precomputed_hash: Option<&str>) -> ScanResult {
        let start = Instant::now();
        let timeout = Duration::from_secs(10);

        // 快速预检查
        if let Some(result) = self.quick_check(file_path) {
            return result;
        }

        let is_system_path = self.system_paths.iter().any(|p| file_path.starts_with(p));
        
        let effective_threshold = self.threshold;

        // 提取特征
        let features = match self.extract_features(file_path) {
            Ok(f) => f,
            Err(e) => {
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

        // 检查超时
        if start.elapsed() > timeout {
            return ScanResult {
                file_path: file_path.to_string(),
                file_hash: None,
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

        // 运行ONNX模型推理
        let probability = match self.run_onnx_inference(&features) {
            Ok(prob) => prob,
            Err(e) => {
                return ScanResult {
                    file_path: file_path.to_string(),
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
        let is_malicious = probability >= effective_threshold;

        // 计算文件哈希（用于黑名单和白名单检查）
        // 如果前端已提供预计算哈希，直接使用，避免重复读取文件
        let file_hash = precomputed_hash
            .map(|h| Some(h.to_string()))
            .unwrap_or_else(|| calculate_file_hash(file_path).ok());

        // 先检查病毒哈希黑名单（优先于模型检测）
        if let Some(ref hash) = file_hash {
            if let Some(family) = HASH_BLACK_LIST.get(hash) {
                return ScanResult {
                    file_path: file_path.to_string(),
                    file_hash: file_hash.clone(),
                    result: "MALICIOUS".to_string(),
                    probability: 1.0,
                    signature_status: Some(format!("Hash Blacklisted: {}", family)),
                    is_trusted: false,
                    error: None,
                    virus_family: Some(format!("HEUR:HackTool.{}!ml (100.0%)", family)),
                    family_category: Some("黑客工具".to_string()),
                    is_infector: false,
                };
            }
        }

        // 如果检测到威胁，先检查白名单（避免误报）
        if is_malicious {
            // 先检查文件名白名单（更快）- 包括内置和外部白名单
            if let Some(filename) = Path::new(file_path).file_name() {
                if let Some(name) = filename.to_str() {
                    if FILENAME_WHITE_LIST.contains(name) || is_name_whitelisted(name) {
                        return ScanResult {
                            file_path: file_path.to_string(),
                            file_hash: file_hash.clone(),
                            result: "CLEAN".to_string(),
                            probability: 0.0,
                            signature_status: Some("Filename Whitelisted".to_string()),
                            is_trusted: true,
                            error: None,
                            virus_family: None,
                            family_category: None,
                            is_infector: false,
                        };
                    }
                }
            }
            
            // 再检查哈希白名单（使用已计算的哈希）- 包括内置和外部白名单
            if let Some(ref hash) = file_hash {
                if HASH_WHITE_LIST.contains(hash) || is_hash_whitelisted(hash) {
                    return ScanResult {
                        file_path: file_path.to_string(),
                        file_hash: file_hash.clone(),
                        result: "CLEAN".to_string(),
                        probability: 0.0,
                        signature_status: Some("Hash Whitelisted".to_string()),
                        is_trusted: true,
                        error: None,
                        virus_family: None,
                        family_category: None,
                        is_infector: false,
                    };
                }
            }
        }

        // 如果是恶意软件，检查数字签名
        let signature_status = Some("Signature check disabled".to_string());
        let is_trusted = is_system_path;

        // 简化版：不进行病毒家族分析
        let virus_family = None;
        let family_category = None;

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
            is_infector: false,
        };

        // 缓存结果
        {
            let mut cache = self.result_cache.lock().unwrap();
            if cache.len() > 5000 {
                cache.clear();
            }
            cache.insert(file_path.to_string(), result.clone());
        }

        result
    }
}

// 全局扫描器实例 - 使用RwLock，scan_file内部ONNX推理只需要读锁（ort 2.0 Session::run仅需&self），允许多线程并行推理
lazy_static::lazy_static! {
    pub static ref SCANNER: Arc<RwLock<Scanner>> = Arc::new(RwLock::new(Scanner::new()));
}

/// 计算文件SHA256哈希（流式读取，支持大文件）
pub fn calculate_file_hash(file_path: &str) -> Result<String, String> {
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
