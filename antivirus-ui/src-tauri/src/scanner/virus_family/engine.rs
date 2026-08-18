/// 病毒家族分析引擎 v3.0 - 完全按照 family_classifier_v3.py 实现
/// 行为分类 + 特征签名库 + 字符串行为提取

use super::rule_engine;
use super::types::*;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use once_cell::sync::Lazy;

// ============================================================
// 特征签名库（从外部JSON规则文件加载）
// ============================================================

// ============================================================
// 主入口
// ============================================================

pub fn analyze_family(data: &[u8], file_path: &str, is_malicious: bool, probability: f32) -> FamilyAnalysisResult {

    // 银狐木马（SilverFox）专用启发式检测
    // 特征：PE 文件、体积较小、文件名完全随机、位于用户可写或隐蔽目录
    if let Some(details) = detect_silverfox(data, file_path, is_malicious, probability) {
        return FamilyAnalysisResult {
            primary_family: VirusFamily::SilverFox,
            detection_name: "Trojan/SilverFox.sa".to_string(),
            primary_score: 95.0,
            is_packed: detect_packer(data).is_some(),
            packer_name: detect_packer(data),
            hit_details: details,
        };
    }

    // 规则引擎为空（无外部规则文件加载）则跳过所有家族检测
    let engine = rule_engine::get_engine();
    if engine.signatures.is_empty() {
        return FamilyAnalysisResult {
            primary_family: VirusFamily::Generic,
            detection_name: format!("HEUR:Trojan/Agent.{}", generate_variant_id(file_path, data)),
            primary_score: probability * 100.0,
            is_packed: false,
            packer_name: None,
            hit_details: vec!["规则引擎为空，跳过家族检测".to_string()],
        };
    }

    // 预检函数由规则引擎控制——仅在规则文件包含对应家族时才运行
    if rule_engine::get_engine().has_signature_for_family("AVKill") {
        if let Some(details) = detect_avkill(data) {
            let variant_id = generate_variant_id(file_path, data);
            return FamilyAnalysisResult {
                primary_family: VirusFamily::AVKill,
                detection_name: format!("Trojan/AVKill.{}", variant_id),
                primary_score: 95.0,
                is_packed: false,
                packer_name: None,
                hit_details: details,
            };
        }
    }
    if rule_engine::get_engine().has_signature_for_family("PyInstallerRansom") {
        if let Some(details) = detect_pyinstaller(data) {
            let variant_id = generate_variant_id(file_path, data);
            return FamilyAnalysisResult {
                primary_family: VirusFamily::PyInstallerRansom,
                detection_name: format!("PUA:Win32/PyInstaller.Ransom.{}", variant_id),
                primary_score: 95.0,
                is_packed: false,
                packer_name: None,
                hit_details: details,
            };
        }
    }

    let imports = extract_imports(data);
    let strings = extract_strings(data);
    let packer = detect_packer(data);
    let compiler = detect_compiler(data, &strings);
    

    let mut behaviors = extract_behaviors(&imports);
    let str_behaviors = extract_behaviors_from_strings(&strings);
    for (cat, funcs) in str_behaviors {
        behaviors.entry(cat).or_insert_with(Vec::new).extend(funcs);
    }
    let behavior_counts: HashMap<&str, usize> = behaviors.iter()
        .map(|(k, v)| (k.as_str(), v.len()))
        .collect();
    
    // 执行分类 - 返回 (family, base_name, score, details)
    let (family, base_name, score, details) = classify(&behavior_counts, &strings, packer.as_deref(), compiler.as_deref());
    
  
    let variant_id = generate_variant_id(file_path, data);
    let detection_name = format!("{}.{}", base_name, variant_id);
    
    FamilyAnalysisResult {
        primary_family: family,
        detection_name,
        primary_score: if score > 0.0 { score } else { probability * 100.0 },
        is_packed: packer.is_some(),
        packer_name: packer,
        hit_details: details,
    }
}

// ============================================================
// 字符串提取
// ============================================================

fn extract_strings(data: &[u8]) -> HashSet<String> {
    let mut strings = HashSet::new();
    let mut current = Vec::with_capacity(64);
    const MAX_STRINGS: usize = 20000;
    const MAX_INPUT: usize = 512 * 1024;

    for &byte in data.iter().take(MAX_INPUT) {
        if strings.len() >= MAX_STRINGS { break; }

        if byte.is_ascii_graphic() || byte == b' ' || byte == b'\n' || byte == b'\r' {
            if current.len() < 256 {
                current.push(byte);
            }
        } else {
            if current.len() >= 4 {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    let s = s.trim();
                    if !s.is_empty() && !s.chars().all(|c| c == ' ' || c == '.' || c == '-' || c == '_' || c == '/' || c == '\\') {
                        strings.insert(s.to_string());
                    }
                }
            }
            current.clear();
        }
    }
    if strings.len() < MAX_STRINGS && current.len() >= 4 {
        if let Ok(s) = String::from_utf8(current) {
            let s = s.trim();
            if !s.is_empty() {
                strings.insert(s.to_string());
            }
        }
    }

    strings
}

// ============================================================
// 行为特征提取（从导入表）
// ============================================================

fn extract_behaviors(imports: &[String]) -> HashMap<String, Vec<String>> {
    let engine = rule_engine::get_engine();
    let mut behaviors: HashMap<String, Vec<String>> = HashMap::new();

    for category in &engine.behavior_categories {
        let mut matched = HashSet::new();
        for imp in imports {
            let imp_lower = imp.to_lowercase();
            for pat in &category.high {
                if imp_lower.contains(&pat.to_lowercase()) {
                    matched.insert(imp.clone());
                    break;
                }
            }
            if matched.contains(imp) { continue; }
            for pat in &category.medium {
                if imp_lower.contains(&pat.to_lowercase()) {
                    matched.insert(imp.clone());
                    break;
                }
            }
        }
        if !matched.is_empty() {
            behaviors.insert(category.name.clone(), matched.into_iter().collect());
        }
    }

    behaviors
}

// ============================================================
// 行为特征提取
// ============================================================

fn extract_behaviors_from_strings(strings: &HashSet<String>) -> HashMap<String, Vec<String>> {
    let engine = rule_engine::get_engine();
    let mut behaviors: HashMap<String, Vec<String>> = HashMap::new();

    for category in &engine.behavior_categories {
        let mut matched = Vec::new();
        for pat in &category.high {
            let pat_lower = pat.to_lowercase();
            if strings.iter().any(|s| s.to_lowercase().contains(&pat_lower)) {
                matched.push(pat.clone());
            }
        }
        for pat in &category.medium {
            if matched.contains(pat) { continue; }
            let pat_lower = pat.to_lowercase();
            if strings.iter().any(|s| s.to_lowercase().contains(&pat_lower)) {
                matched.push(pat.clone());
            }
        }
        if !matched.is_empty() {
            behaviors.insert(category.name.clone(), matched);
        }
    }

    behaviors
}

// ============================================================
// 检测编程语言/编译器
// ============================================================

fn detect_compiler(data: &[u8], strings: &HashSet<String>) -> Option<String> {
    // 编译器特征通常位于文件前部，限制扫描范围降低开销
    let scan_limit = (2 * 1024 * 1024).min(data.len());
    let head = &data[..scan_limit];
    if head.windows(11).any(|w| w == b".NETFramework" || w == b"mscorlib") {
        return Some(".NET".to_string());
    }
    if strings.iter().any(|s| s.contains("www.eyuyan.com") || s.contains("易语言")) {
        return Some("易语言".to_string());
    }
    if head.windows(7).any(|w| w == b"#AutoIt") || head.windows(4).any(|w| w == b"AU3!") {
        return Some("AutoIt".to_string());
    }
    if strings.iter().any(|s| s.contains("nsis.sf.net") || s.contains("NSIS")) {
        return Some("NSIS".to_string());
    }
    if head.windows(7).any(|w| w == b"Borland") || head.windows(6).any(|w| w == b"Delphi") {
        return Some("Delphi".to_string());
    }
    None
}

// ============================================================
// 分类主逻辑（与Python脚本完全一致）
// ============================================================

fn classify(
    behavior_counts: &HashMap<&str, usize>,
    strings: &HashSet<String>,
    packer: Option<&str>,
    compiler: Option<&str>,
) -> (VirusFamily, String, f32, Vec<String>) {
    
    let engine = rule_engine::get_engine();
    
    // 签名匹配
    let (family, name, score, details) = engine.match_signatures(behavior_counts, strings, packer, compiler);
    
    // 阈值 >= 0.35（与Python脚本一致）
    if score >= 35.0 {
        return (family, name, score, details);
    }
    
    // 默认返回Generic
    (VirusFamily::Generic, "HEUR:Trojan/Agent".to_string(), score, details)
}

// ============================================================
// 变种ID生成
// ============================================================

// 变种ID中使用的预编译正则（避免每次调用重新编译）
static VERSION_RE: Lazy<regex::Regex> = Lazy::new(|| regex::Regex::new(r"(\d+\.\d+)").unwrap());
static ARCH_RE: Lazy<regex::Regex> = Lazy::new(|| regex::Regex::new(r"x(86|64)").unwrap());
static PRO_RE: Lazy<regex::Regex> = Lazy::new(|| regex::Regex::new(r"pro").unwrap());
static BETA_RE: Lazy<regex::Regex> = Lazy::new(|| regex::Regex::new(r"beta[\d\.]*").unwrap());
static V_RE: Lazy<regex::Regex> = Lazy::new(|| regex::Regex::new(r"v(\d+)").unwrap());

fn generate_variant_id(file_path: &str, data: &[u8]) -> String {
    let filename = std::path::Path::new(file_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();

    // 使用预编译正则（避免每次调用重新编译）
    let patterns: [&Lazy<regex::Regex>; 5] = [&VERSION_RE, &ARCH_RE, &PRO_RE, &BETA_RE, &V_RE];
    let mut variant_parts: Vec<String> = Vec::new();
    for re in &patterns {
        if let Some(cap) = re.captures(&filename) {
            variant_parts.push(cap.get(0).map(|m| m.as_str().to_string()).unwrap_or_default());
        }
    }

    // 计算数据哈希（仅取前4KB，避免对大文件做全量哈希）
    let data_hash = {
        let sample = if data.len() > 4096 { &data[..4096] } else { data };
        let mut hasher = DefaultHasher::new();
        sample.hash(&mut hasher);
        let hash = hasher.finish();
        format!("{:02x}", (hash & 0xFF) as u8)
    };

   
    if variant_parts.is_empty() {
        data_hash
    } else {
        // 取第一个版本特征的首字母 
        let first_char = variant_parts[0].chars().next().unwrap_or('a');
        let variant_id = format!("{}{}", first_char, &data_hash[0..1]);
        variant_id
    }
}

fn extract_imports(data: &[u8]) -> Vec<String> {
    let mut imports = Vec::new();
    
    if data.len() < 64 || data[0] != 0x4D || data[1] != 0x5A {
        return imports;
    }
    
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if pe_offset + 24 > data.len() || data[pe_offset] != 0x50 || data[pe_offset + 1] != 0x45 {
        return imports;
    }
    
    let coff_off = pe_offset + 4;
    let opt_hdr_size = u16::from_le_bytes([data[coff_off + 16], data[coff_off + 17]]) as usize;
    let opt_hdr_off = coff_off + 20;
    let is_64bit = data[opt_hdr_off] == 0x0B && data[opt_hdr_off + 1] == 0x02;
    
    let import_dir_offset = if is_64bit { 112 } else { 104 };
    if opt_hdr_off + import_dir_offset + 8 > data.len() { return imports; }
    
    let import_rva = u32::from_le_bytes([
        data[opt_hdr_off + import_dir_offset],
        data[opt_hdr_off + import_dir_offset + 1],
        data[opt_hdr_off + import_dir_offset + 2],
        data[opt_hdr_off + import_dir_offset + 3],
    ]);
    if import_rva == 0 { return imports; }
    
    let num_sections = u16::from_le_bytes([data[coff_off + 2], data[coff_off + 3]]);
    let sec_table_off = opt_hdr_off + opt_hdr_size;
    
    for i in 0..num_sections.min(40) {
        let sec_off = sec_table_off + (i as usize * 40);
        if sec_off + 40 > data.len() { break; }
        
        let virt_addr = u32::from_le_bytes([
            data[sec_off + 12], data[sec_off + 13], data[sec_off + 14], data[sec_off + 15],
        ]);
        let raw_ptr = u32::from_le_bytes([
            data[sec_off + 20], data[sec_off + 21], data[sec_off + 22], data[sec_off + 23],
        ]);
        let raw_size = u32::from_le_bytes([
            data[sec_off + 16], data[sec_off + 17], data[sec_off + 18], data[sec_off + 19],
        ]);
        
        if import_rva >= virt_addr && import_rva < virt_addr + raw_size {
            let import_off = (import_rva - virt_addr + raw_ptr) as usize;
            parse_import_descriptors(data, import_off, &mut imports);
            break;
        }
    }
    
    imports
}

fn parse_import_descriptors(data: &[u8], import_off: usize, imports: &mut Vec<String>) {
    let entry_size = 20;
    let mut offset = import_off;
    
    while offset + entry_size <= data.len() {
        if data[offset..offset+20].iter().all(|&b| b == 0) { break; }
        
        let name_rva = u32::from_le_bytes([
            data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15],
        ]);
        let ilt_rva = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]);
        
        if name_rva != 0 {
            if let Some(name_offset) = rva_to_offset(data, name_rva) {
                let dll_name = read_ascii_string(data, name_offset);
                if !dll_name.is_empty() {
                    imports.push(dll_name);
                    
                    if ilt_rva != 0 {
                        if let Some(ilt_offset) = rva_to_offset(data, ilt_rva) {
                            parse_ilt(data, ilt_offset, imports);
                        }
                    }
                }
            }
        }
        offset += entry_size;
    }
}

fn parse_ilt(data: &[u8], mut offset: usize, imports: &mut Vec<String>) {
    let is_64bit = data.len() > 64 && {
        let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
        let opt_hdr_off = pe_offset + 24;
        data[opt_hdr_off] == 0x0B && data[opt_hdr_off + 1] == 0x02
    };
    
    loop {
        if is_64bit {
            if offset + 8 > data.len() { break; }
            let entry = u64::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3],
                data[offset+4], data[offset+5], data[offset+6], data[offset+7],
            ]);
            if entry == 0 { break; }
            if (entry & 0x8000000000000000) == 0 {
                let name_rva = (entry & 0x7FFFFFFFFFFFFFFF) as u32;
                if let Some(name_offset) = rva_to_offset(data, name_rva) {
                    let api_name = read_ascii_string(data, name_offset + 2);
                    if !api_name.is_empty() { imports.push(api_name); }
                }
            }
            offset += 8;
        } else {
            if offset + 4 > data.len() { break; }
            let entry = u32::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3],
            ]);
            if entry == 0 { break; }
            if (entry & 0x80000000) == 0 {
                let name_rva = entry & 0x7FFFFFFF;
                if let Some(name_offset) = rva_to_offset(data, name_rva) {
                    let api_name = read_ascii_string(data, name_offset + 2);
                    if !api_name.is_empty() { imports.push(api_name); }
                }
            }
            offset += 4;
        }
    }
}

fn rva_to_offset(data: &[u8], rva: u32) -> Option<usize> {
    if data.len() < 64 { return None; }
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if pe_offset + 24 > data.len() { return None; }
    
    let coff_off = pe_offset + 4;
    let num_sections = u16::from_le_bytes([data[coff_off + 2], data[coff_off + 3]]);
    let opt_hdr_size = u16::from_le_bytes([data[coff_off + 16], data[coff_off + 17]]) as usize;
    let opt_hdr_off = coff_off + 20;
    let sec_table_off = opt_hdr_off + opt_hdr_size;
    
    for i in 0..num_sections.min(40) {
        let sec_off = sec_table_off + (i as usize * 40);
        if sec_off + 40 > data.len() { break; }
        
        let virt_addr = u32::from_le_bytes([
            data[sec_off + 12], data[sec_off + 13], data[sec_off + 14], data[sec_off + 15],
        ]);
        let raw_ptr = u32::from_le_bytes([
            data[sec_off + 20], data[sec_off + 21], data[sec_off + 22], data[sec_off + 23],
        ]);
        let raw_size = u32::from_le_bytes([
            data[sec_off + 16], data[sec_off + 17], data[sec_off + 18], data[sec_off + 19],
        ]);
        
        if rva >= virt_addr && rva < virt_addr + raw_size {
            return Some((rva - virt_addr + raw_ptr) as usize);
        }
    }
    None
}

fn read_ascii_string(data: &[u8], offset: usize) -> String {
    if offset >= data.len() { return String::new(); }
    let mut result = String::new();
    for i in offset..data.len().min(offset + 256) {
        let c = data[i];
        if c == 0 { break; }
        if c.is_ascii_graphic() || c == b' ' { result.push(c as char); } else { break; }
    }
    result
}

// ============================================================
// 银狐木马（SilverFox）启发式检测
// 特征：
//   1. PE 可执行文件
//   2. 文件体积较小（<= 50 MB）
//   3. 文件名为 6~16 位完全随机字符（字母+数字混合）
//   4. 位于用户可写/隐蔽目录（ProgramData、AppData、Temp、Program Files (x86) 等）
// ============================================================

fn detect_silverfox(data: &[u8], file_path: &str, is_malicious: bool, probability: f32) -> Option<Vec<String>> {
    // 仅对已被模型判定为恶意或概率较高的样本触发，降低误报
    if !is_malicious && probability < 0.80 {
        return None;
    }

    if data.len() < 64 {
        return None;
    }
    if data[0] != 0x4D || data[1] != 0x5A {
        return None;
    }

    const SIZE_THRESHOLD: usize = 50 * 1024 * 1024; // 50 MB
    if data.len() > SIZE_THRESHOLD {
        return None;
    }

    // ──── 已知合法软件路径白名单 ────
    // 这些目录下的文件不会被误判为银狐木马
    let lower_path = file_path.to_lowercase();
    let trusted_paths = [
        "leigod",           // 雷神加速器
        "seewo",            // 希沃（seewo）教育软件
        "mozilla",          // Firefox/NSS 库
        "mozilla firefox",
        "nss",              // Network Security Services (NSS) 库
    ];
    if trusted_paths.iter().any(|&p| lower_path.contains(p)) {
        return None;
    }

    let file_name = std::path::Path::new(file_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    if !is_random_name(file_name) {
        return None;
    }

    if !is_silverfox_path(file_path) {
        return None;
    }

    let mut details = vec![
        format!("银狐木马随机文件名特征: {}", file_name),
        format!("文件体积小: {} bytes", data.len()),
        format!("可疑存放路径: {}", file_path),
    ];

    if let Some(packer) = detect_packer(data) {
        details.push(format!("检测到加壳: {}", packer));
    }

    Some(details)
}

/// 判断文件名是否为完全随机的字符组合
fn is_random_name(name: &str) -> bool {
    let base = name.rsplit_once('.')
        .map(|(b, _)| b)
        .unwrap_or(name);

    if base.len() < 6 || base.len() > 16 {
        return false;
    }

    if !base.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }

    let letters = base.chars().filter(|c| c.is_ascii_alphabetic()).count();
    let digits = base.chars().filter(|c| c.is_ascii_digit()).count();
    if letters < 2 || digits < 1 {
        return false;
    }

    // 排除常见安装/工具类文件名
    let lower = base.to_lowercase();
    let common_words = [
        "setup", "install", "update", "uninstall", "launcher", "helper",
        "crash", "log", "report", "service", "driver", "tool", "util",
        "client", "server", "agent", "host", "manager", "console",
        "explorer", "notepad", "calc", "msedge", "chrome", "firefox",
        // 常见系统/第三方库命名模式（名称+版本号后缀，不是随机名）
        "freebl",        // Mozilla NSS freebl 加密库 (freebl3.dll)
        "nss",           // Mozilla Network Security Services (nss3.dll)
        "ssl",           // SSL/TLS 库 (ssl3.dll)
        "smime",         // S/MIME 库 (smime3.dll)
        "sqlite",        // SQLite 数据库库 (sqlite3.dll)
        "softokn",       // Mozilla PKCS#11 软令牌 (softokn3.dll)
    ];
    if common_words.iter().any(|&w| lower.contains(w)) {
        return false;
    }

    // 使用香农熵 + 字符重复度判断随机性
    // 银狐随机名较短，可能有重复字符，所以阈值不能设太高
    if name_entropy(base) < 2.2 {
        return false;
    }

    // 避免极端重复（如 aaaaaa12 这种不应视为随机）
    let mut freq = std::collections::HashMap::new();
    for c in base.chars() {
        *freq.entry(c.to_ascii_lowercase()).or_insert(0usize) += 1;
    }
    let max_count = freq.values().copied().max().unwrap_or(0);
    let len = base.len();
    max_count <= (len as f32 * 0.45) as usize
}

fn name_entropy(s: &str) -> f32 {
    use std::collections::HashMap;
    let mut freq = HashMap::new();
    for c in s.chars() {
        *freq.entry(c.to_ascii_lowercase()).or_insert(0usize) += 1;
    }
    let len = s.len() as f32;
    if len == 0.0 {
        return 0.0;
    }
    let mut entropy = 0.0f32;
    for &count in freq.values() {
        let p = count as f32 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// 判断路径是否为银狐常见藏身目录
fn is_silverfox_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    let suspicious = [
        "\\programdata\\",
        "\\appdata\\local\\",
        "\\appdata\\roaming\\",
        "\\temp\\",
        "\\windows\\temp\\",
        "\\program files (x86)\\",
        "\\program files\\",
    ];
    suspicious.iter().any(|&p| lower.contains(p))
}

// ============================================================
// AV Kill 检测 - 杀毒软件禁用/终止工具
// ============================================================

fn detect_avkill(data: &[u8]) -> Option<Vec<String>> {
    if data.len() < 64 { return None; }
    let mut details = Vec::new();

    // 特征 1: AV Kill 工具专有字符串（大小写不敏感，不用拷贝全量数据）
    let tool_strings = [
        "defendnot",
        "defender-disabler",
        "no-defender",
        "wsc_proxy",
        "windows security center",
    ];
    for &s in &tool_strings {
        if data.windows(s.len()).any(|w| w.eq_ignore_ascii_case(s.as_bytes())) {
            details.push(format!("AV Kill 工具特征: {}", s));
        }
    }

    // 特征 2: 被终止的 AV 进程名（ASCII + UTF-16 宽字符串）
    let target_processes = [
        "msmpeng.exe",
        "mssense.exe",
        "senseir.exe",
        "nissrv.exe",
        "securityhealthservice.exe",
        "mpcmdrun.exe",
        "savservice.exe",
        "mbamservice.exe",
        "ekrn.exe",
        "avp.exe",
    ];

    for &name in &target_processes {
        if data.windows(name.len()).any(|w| w.eq_ignore_ascii_case(name.as_bytes())) {
            details.push(format!("AV 进程目标: {}", name));
            continue;
        }
        let wide: Vec<u8> = name.bytes().flat_map(|b| [b, 0]).collect();
        if data.windows(wide.len()).any(|w| w.eq_ignore_ascii_case(&wide)) {
            details.push(format!("AV 进程目标(宽): {}", name));
        }
    }

    if details.is_empty() { return None; }
    Some(details)
}

// ============================================================
// PyInstaller 检测
// ============================================================

fn detect_pyinstaller(data: &[u8]) -> Option<Vec<String>> {
    if data.len() < 64 { return None; }
    
    let mut details = Vec::new();
    
    // 1. 检查 PE 节表中是否有 .pyz 节
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if pe_offset + 24 <= data.len() && data[pe_offset] == 0x50 && data[pe_offset + 1] == 0x45 {
        let coff_off = pe_offset + 4;
        let num_sections = u16::from_le_bytes([data[coff_off + 2], data[coff_off + 3]]);
        let opt_hdr_size = u16::from_le_bytes([data[coff_off + 16], data[coff_off + 17]]) as usize;
        let opt_hdr_off = coff_off + 20;
        let sec_table_off = opt_hdr_off + opt_hdr_size;
        
        for i in 0..num_sections.min(10) {
            let sec_off = sec_table_off + (i as usize * 40);
            if sec_off + 8 > data.len() { break; }
            let name = String::from_utf8_lossy(&data[sec_off..sec_off + 8]);
            let name_trimmed = name.trim_end_matches('\0');
            if name_trimmed == ".pyz" {
                details.push(format!("PyInstaller 节表: {}", name_trimmed));
            }
        }
    }
    
    // 2. 检查 PyInstaller 特征字符串（大小写不敏感，在原数据上比较）
    let pyinstaller_strings = [
        ("pyinstaller", "PyInstaller 特征字符串"),
        ("[pyi-", "PyInstaller 启动器日志格式"),
        ("meipass", "PyInstaller 临时目录特征"),
        ("_meipass2_", "PyInstaller 环境变量特征"),
        ("pyz-00.pyz", "PyInstaller 压缩归档资源"),
        ("absolute path to", "PyInstaller 错误信息特征"),
    ];
    
    for (s, desc) in &pyinstaller_strings {
        if data.windows(s.len()).any(|w| w.eq_ignore_ascii_case(s.as_bytes())) {
            details.push(desc.to_string());
        }
    }
    
    // 3. 检查 Python DLL 导入
    if data.windows(b"python3".len()).any(|w| w.eq_ignore_ascii_case(b"python3"))
        || data.windows(b"python39".len()).any(|w| w.eq_ignore_ascii_case(b"python39"))
        || data.windows(b"python310".len()).any(|w| w.eq_ignore_ascii_case(b"python310"))
        || data.windows(b"python311".len()).any(|w| w.eq_ignore_ascii_case(b"python311"))
        || data.windows(b"python312".len()).any(|w| w.eq_ignore_ascii_case(b"python312"))
        || data.windows(b"python313".len()).any(|w| w.eq_ignore_ascii_case(b"python313"))
    {
        if !details.iter().any(|d| d.contains("Python")) {
            details.push("Python DLL 导入引用".to_string());
        }
    }
    
    if details.is_empty() { return None; }
    Some(details)
}

// ============================================================
// 壳检测
// ============================================================

fn detect_packer(data: &[u8]) -> Option<String> {
    if data.len() < 64 { return None; }
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if pe_offset + 24 > data.len() { return None; }
    
    let coff_off = pe_offset + 4;
    let num_sections = u16::from_le_bytes([data[coff_off + 2], data[coff_off + 3]]);
    let opt_hdr_size = u16::from_le_bytes([data[coff_off + 16], data[coff_off + 17]]) as usize;
    let opt_hdr_off = coff_off + 20;
    let sec_table_off = opt_hdr_off + opt_hdr_size;
    
    for i in 0..num_sections.min(10) {
        let sec_off = sec_table_off + (i as usize * 40);
        if sec_off + 8 > data.len() { break; }
        let name = String::from_utf8_lossy(&data[sec_off..sec_off + 8]);
        if name.contains("UPX") { return Some("UPX".to_string()); }
        if name.contains("themida") || name.contains("PEC2") || name.contains(".themida") { return Some("Themida".to_string()); }
        if name.contains(".vmp") || name.contains("VMP") { return Some("VMProtect".to_string()); }
        if name.contains(".aspack") { return Some("ASPack".to_string()); }
        if name.contains(".mpress") { return Some("MPRESS".to_string()); }
    }
    None
}
