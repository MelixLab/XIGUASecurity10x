use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

/// 感染型病毒检测结果
#[derive(Debug, Clone)]
pub struct InfectorDetectionResult {
    pub is_infected: bool,
    pub confidence: f32,
    pub indicators: Vec<String>,
    pub details: InfectorDetails,
}

#[derive(Debug, Clone)]
pub struct InfectorDetails {
    pub entropy: f32,
    pub suspicious_sections: Vec<String>,
    pub entry_point_anomaly: bool,
    pub section_mismatch: bool,
    pub high_entropy_sections: Vec<String>,
    pub packer_info: Option<String>,
    pub appendage_detected: bool,
}

impl InfectorDetectionResult {
    pub fn clean() -> Self {
        Self {
            is_infected: false,
            confidence: 0.0,
            indicators: Vec::new(),
            details: InfectorDetails {
                entropy: 0.0,
                suspicious_sections: Vec::new(),
                entry_point_anomaly: false,
                section_mismatch: false,
                high_entropy_sections: Vec::new(),
                packer_info: None,
                appendage_detected: false,
            },
        }
    }
}

/// 感染型病毒检测引擎 - 带缓存
pub struct InfectorEngine {
    cache: Arc<Mutex<HashMap<String, InfectorDetectionResult>>>,
}

impl InfectorEngine {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 检测感染型病毒（带缓存）
    pub fn detect(&self, file_path: &str) -> InfectorDetectionResult {
        // 检查缓存
        {
            let cache = self.cache.lock().unwrap();
            if let Some(result) = cache.get(file_path) {
                return result.clone();
            }
        }

        let result = detect_infector_internal(file_path);

        // 缓存结果
        {
            let mut cache = self.cache.lock().unwrap();
            if cache.len() > 5000 {
                cache.clear();
            }
            cache.insert(file_path.to_string(), result.clone());
        }

        result
    }
}

/// 全局感染型病毒检测引擎实例
lazy_static::lazy_static! {
    pub static ref INFECTOR_ENGINE: InfectorEngine = InfectorEngine::new();
}

/// 检测感染型病毒（公开接口，带缓存）
pub fn detect_infector(file_path: &str) -> InfectorDetectionResult {
    INFECTOR_ENGINE.detect(file_path)
}

/// 检测感染型病毒（内部实现）
///
/// 主流 AV 对感染型病毒的判定通常是：结构异常 + 加壳识别 + 行为/信誉交叉验证。
/// 本引擎目前以静态结构启发式为主，核心思路：
/// 1. 识别常见加壳器，避免把正常加壳软件误判为感染型病毒；
/// 2. 检测 PE 末尾是否被追加病毒节区；
/// 3. 入口点是否被重定向到可疑节区；
/// 4. 多指标加权，且排除加壳器后再进行严格判定。
fn detect_infector_internal(file_path: &str) -> InfectorDetectionResult {
    let path = Path::new(file_path);

    // 只分析PE文件
    if !is_pe_file(path) {
        return InfectorDetectionResult::clean();
    }

    // 排除驱动和DLL文件 - 感染型病毒通常不会感染这些文件
    if let Some(ext) = path.extension() {
        let ext = ext.to_string_lossy().to_lowercase();
        if matches!(ext.as_str(), "sys" | "dll" | "drv") {
            return InfectorDetectionResult::clean();
        }
    }

    // 获取实际文件大小，用于判断末尾是否有追加数据
    let actual_file_size = fs::metadata(file_path)
        .map(|m| m.len() as usize)
        .unwrap_or(0);

    // 快速检查：只读取文件头部（最多64KB），而不是整个文件
    const MAX_HEADER_SIZE: usize = 64 * 1024;
    let data = match fs::read(file_path) {
        Ok(d) => {
            if d.len() > MAX_HEADER_SIZE {
                d[..MAX_HEADER_SIZE].to_vec()
            } else {
                d
            }
        }
        Err(_) => return InfectorDetectionResult::clean(),
    };

    analyze_pe_infector(&data, actual_file_size)
}

/// 检查是否是PE文件
fn is_pe_file(path: &Path) -> bool {
    if let Some(ext) = path.extension() {
        let ext = ext.to_string_lossy().to_lowercase();
        matches!(ext.as_str(), "exe" | "dll" | "sys" | "drv" | "ocx" | "scr")
    } else {
        false
    }
}

/// 常见加壳器/保护器节区名（用于识别正常加壳，降低误报）
const KNOWN_PACKER_SECTIONS: &[(&str, &str)] = &[
    ("UPX0", "UPX"),
    ("UPX1", "UPX"),
    ("UPX2", "UPX"),
    (".upx", "UPX"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    ("PEC2", "PECompact"),
    ("PECompact2", "PECompact"),
    (".MPRESS1", "MPRESS"),
    (".MPRESS2", "MPRESS"),
    (".mpress", "MPRESS"),
    (".themida", "Themida"),
    (".winlice", "WinLicense"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".vmp2", "VMProtect"),
    (".enigma1", "Enigma"),
    (".enigma2", "Enigma"),
    (".petite", "Petite"),
    (".nsp0", "NsPack"),
    (".nsp1", "NsPack"),
    (".RLPack", "RLPack"),
    (".yoda", "Yoda"),
    (".yP", "Yoda"),
    (".bs0", "Bambis"),
    (".bs1", "Bambis"),
    (".far", "FSG"),
    (".ccg", "CCG"),
    ("PAC", "PANDORA"),
    ("petite", "Petite"),
    (".交响", "其它压缩壳"),
];

/// 判断节区名是否属于已知加壳器
fn detect_packer(section_names: &[String]) -> Option<String> {
    let mut matched = Vec::new();
    for name in section_names {
        for (pattern, packer) in KNOWN_PACKER_SECTIONS {
            if name.eq_ignore_ascii_case(pattern) {
                matched.push(*packer);
            }
        }
    }
    matched.sort();
    matched.dedup();
    if matched.is_empty() {
        None
    } else {
        Some(matched.join(","))
    }
}

/// 判断节区名是否为标准代码节区
fn is_standard_code_section(name: &str, characteristics: u32) -> bool {
    let name = name.trim();
    name == ".text"
        || name.starts_with(".text")
        || name.starts_with("CODE")
        || name == "init"
        || name == "INIT"
        || (characteristics & 0x00000020) != 0
}

/// 判断节区名是否可疑（空、随机或明显不是正常节区名）
fn is_suspicious_section_name(name: &str) -> bool {
    let name = name.trim();
    if name.is_empty() {
        return true;
    }
    // 常见正常节区名
    let normal_sections = [
        ".text", ".data", ".rdata", ".bss", ".rsrc", ".reloc",
        ".pdata", ".xdata", ".debug", ".crt", ".tls", ".edata",
        ".idata", ".didat", ".sdata", ".sxdata", ".gfids", ".gljmp",
        "CODE", "DATA", "BSS", "TLS", "INIT", ".itext", ".adata",
        ".vmp", ".vmp0", ".vmp1", ".upx", "UPX0", "UPX1", ".aspack",
    ];
    if normal_sections.iter().any(|s| name.eq_ignore_ascii_case(s)) {
        return false;
    }
    // 节区名长度非标准（正常 1-8 字符）
    if name.len() > 8 {
        return true;
    }
    // 节区名包含随机字符（常见感染型病毒会生成随机节区名）
    let has_weird_char = name.bytes().any(|b| {
        !b.is_ascii_alphanumeric() && b != b'.' && b != b'_' && b != b'!'
    });
    if has_weird_char {
        return true;
    }
    // 纯随机字母数字组合，且不是 .text 等已知节区
    let is_random = name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.')
        && !name.starts_with(".")
        && name.len() >= 4;
    if is_random {
        return true;
    }
    false
}

/// 分析PE文件是否被感染
///
/// 核心检测逻辑（参考主流 AV 结构启发式）：
/// 1. 识别加壳器，加壳文件大幅降低可疑分；
/// 2. 检测入口点是否被重定向到末尾新增的可执行节区；
/// 3. 检测文件末尾是否存在追加数据（appendage）；
/// 4. 检测入口点节区是否同时具备 RWE + 高熵；
/// 5. 多指标加权，必须满足多个强指标才判定为感染。
fn analyze_pe_infector(data: &[u8], actual_file_size: usize) -> InfectorDetectionResult {
    let mut result = InfectorDetectionResult::clean();
    let mut indicators = Vec::new();
    let mut score = 0.0f32;

    // 解析PE头
    if data.len() < 64 {
        return result;
    }

    // 检查MZ头
    if data[0] != 0x4D || data[1] != 0x5A {
        return result;
    }

    // 获取PE头偏移
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if pe_offset + 24 >= data.len() {
        return result;
    }

    // 检查PE签名
    if data[pe_offset] != 0x50 || data[pe_offset + 1] != 0x45 {
        return result;
    }

    // 获取COFF头信息
    let coff_header_offset = pe_offset + 4;
    let num_sections = u16::from_le_bytes([
        data[coff_header_offset + 2],
        data[coff_header_offset + 3],
    ]);

    // 节区数量检查 - 感染型病毒通常会增加节区数量
    if num_sections < 2 || num_sections > 32 {
        return result;
    }

    let optional_header_size = u16::from_le_bytes([
        data[coff_header_offset + 16],
        data[coff_header_offset + 17],
    ]);

    // 获取可选头偏移和入口点
    let optional_header_offset = coff_header_offset + 20;
    let entry_point = u32::from_le_bytes([
        data[optional_header_offset + 16],
        data[optional_header_offset + 17],
        data[optional_header_offset + 18],
        data[optional_header_offset + 19],
    ]);

    // 节表偏移
    let section_table_offset = optional_header_offset + optional_header_size as usize;

    // 收集所有节区信息
    let mut sections = Vec::new();
    for i in 0..num_sections {
        let section_offset = section_table_offset + (i as usize * 40);
        if section_offset + 40 > data.len() {
            break;
        }

        // 节区名称（8字节）
        let name_bytes = &data[section_offset..section_offset + 8];
        let name = String::from_utf8_lossy(name_bytes)
            .trim_end_matches('\0')
            .to_string();

        // 虚拟大小
        let virtual_size = u32::from_le_bytes([
            data[section_offset + 8],
            data[section_offset + 9],
            data[section_offset + 10],
            data[section_offset + 11],
        ]);

        // 虚拟地址
        let virtual_address = u32::from_le_bytes([
            data[section_offset + 12],
            data[section_offset + 13],
            data[section_offset + 14],
            data[section_offset + 15],
        ]);

        // 原始大小
        let raw_size = u32::from_le_bytes([
            data[section_offset + 16],
            data[section_offset + 17],
            data[section_offset + 18],
            data[section_offset + 19],
        ]);

        // 原始地址
        let raw_address = u32::from_le_bytes([
            data[section_offset + 20],
            data[section_offset + 21],
            data[section_offset + 22],
            data[section_offset + 23],
        ]);

        // 特征
        let characteristics = u32::from_le_bytes([
            data[section_offset + 36],
            data[section_offset + 37],
            data[section_offset + 38],
            data[section_offset + 39],
        ]);

        sections.push(SectionInfo {
            name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_address,
            characteristics,
        });
    }

    if sections.is_empty() {
        return result;
    }

    // 检测是否加壳
    let section_names: Vec<String> = sections.iter().map(|s| s.name.clone()).collect();
    let packer_info = detect_packer(&section_names);
    result.details.packer_info = packer_info.clone();
    let is_packed = packer_info.is_some();
    if let Some(packer) = &packer_info {
        indicators.push(format!("检测到加壳器: {}", packer));
    }

    // 获取最后一个节区
    let last_section = sections.last().unwrap();

    // 判断入口点所在的节区
    let mut entry_point_section: Option<&SectionInfo> = None;
    for section in &sections {
        let sec_start = section.virtual_address;
        let sec_end = section.virtual_address + section.virtual_size;
        if entry_point >= sec_start && entry_point < sec_end {
            entry_point_section = Some(section);
            break;
        }
    }

    let ep_in_last_section = entry_point_section
        .map(|ep| ep.virtual_address == last_section.virtual_address)
        .unwrap_or(false);

    // 指标1：入口点不在标准代码节区
    if let Some(ep_section) = entry_point_section {
        let standard = is_standard_code_section(&ep_section.name, ep_section.characteristics);
        if !standard {
            indicators.push(format!("入口点指向非标准节区 '{}'", ep_section.name));
            result.details.entry_point_anomaly = true;
            score += 15.0; // 保守加分
        }

        // 指标2：入口点所在节区可执行且高熵（>7.9）
        let executable = (ep_section.characteristics & 0x20000000) != 0;
        if executable && ep_section.raw_size > 0 {
            let check_size = (ep_section.raw_size as usize)
                .min(4096)
                .min(data.len().saturating_sub(ep_section.raw_address as usize));
            if check_size > 0 && ep_section.raw_address as usize + check_size <= data.len() {
                let section_data = &data[ep_section.raw_address as usize..
                                          ep_section.raw_address as usize + check_size];
                let entropy = calculate_entropy_fast(section_data);

                if entropy > 7.9 {
                    indicators.push(format!(
                        "入口点节区 '{}' 可执行且熵值较高: {:.2}",
                        ep_section.name, entropy
                    ));
                    result.details.high_entropy_sections.push(format!("{} ({:.2})", ep_section.name, entropy));
                    score += 15.0;
                }
            }
        }

        // 指标3：入口点节区具有 RWE 权限（读写执行）
        let rwe = (ep_section.characteristics & 0xE0000000) == 0xE0000000;
        if rwe {
            indicators.push(format!("入口点节区 '{}' 具有读写执行权限", ep_section.name));
            score += 20.0;
        }

        // 指标4：入口点节区名可疑（空/随机）
        if is_suspicious_section_name(&ep_section.name) {
            indicators.push(format!("入口点节区 '{}' 名称为可疑随机名", ep_section.name));
            score += 20.0;
        }
    }

    // 指标5：入口点在最后节区（强指标）
    if ep_in_last_section {
        indicators.push("入口点指向最后一个节区".to_string());
        score += 25.0;

        // 指标6：入口点正好在最后节区开头（典型感染型病毒 stub）
        if let Some(ep_section) = entry_point_section {
            if entry_point == ep_section.virtual_address ||
               (entry_point - ep_section.virtual_address) < 0x100 {
                indicators.push("入口点位于最后节区起始位置（病毒 stub 常见）".to_string());
                score += 20.0;
            }
        }
    }

    // 指标7：文件末尾存在追加数据（appendage）
    // 感染型病毒追加新代码后，最后一个节区的 raw_address + raw_size 通常小于文件实际大小
    let last_section_end = (last_section.raw_address + last_section.raw_size) as usize;
    if actual_file_size > 0 && actual_file_size > last_section_end {
        let appendage_size = actual_file_size - last_section_end;
        if appendage_size > 0x100 {
            indicators.push(format!(
                "文件末尾存在追加数据: {} 字节",
                appendage_size
            ));
            result.details.appendage_detected = true;
            score += 25.0;
        }
    } else if actual_file_size > 0 && last_section_end > actual_file_size {
        // 节区大小超过文件大小，说明节表被篡改
        indicators.push("最后节区大小超过文件大小（节表异常）".to_string());
        result.details.section_mismatch = true;
        score += 20.0;
    }

    // 指标8：多个节区具有 RWE 权限（异常）
    let rwe_count = sections.iter()
        .filter(|s| (s.characteristics & 0xE0000000) == 0xE0000000)
        .count();
    if rwe_count >= 2 {
        indicators.push(format!("存在 {} 个读写执行（RWE）节区", rwe_count));
        score += 10.0;
    }

    // 指标9：最后节区可执行且大小异常（虚拟大小远大于原始大小）
    if last_section.raw_size > 0 && last_section.virtual_size > 0
        && (last_section.virtual_size as f32 / last_section.raw_size as f32) > 5.0
        && (last_section.characteristics & 0x20000000) != 0 {
        indicators.push(format!(
            "最后节区 '{}' 虚拟/原始大小比例异常: {:.1}",
            last_section.name,
            last_section.virtual_size as f32 / last_section.raw_size as f32
        ));
        score += 15.0;
    }

    // 文件整体熵值
    let file_entropy = calculate_entropy_fast(data);
    result.details.entropy = file_entropy;

    // 加壳器削弱：识别到加壳器时，大幅降低分数，避免误报
    if is_packed {
        let penalty = 25.0f32;
        score = (score - penalty).max(0.0);
        indicators.push(format!("加壳器削弱: -{}", penalty));
    }

    // 综合判定
    // 判定策略1：多个强指标（分数 >= 65，至少 3 个指标）
    let strong_threshold = 65.0;
    let has_multiple_indicators = indicators.iter()
        .filter(|i| !i.starts_with("检测到加壳器") && !i.starts_with("加壳器削弱"))
        .count() >= 3;

    // 判定策略2：强组合（入口点在最后节区 + 末尾追加数据 + 高熵/RWE）
    let has_infection_combo = ep_in_last_section
        && result.details.appendage_detected
        && score >= 60.0;

    // 判定策略3：极高置信度（分数 >= 80，至少 2 个强指标）
    let has_very_high_score = score >= 80.0 && indicators.len() >= 2;

    let is_infected = (score >= strong_threshold && has_multiple_indicators)
        || has_infection_combo
        || has_very_high_score;

    result.is_infected = is_infected;
    result.confidence = (score / 100.0f32).min(1.0f32);
    result.indicators = indicators;

    result
}

/// 节区信息
struct SectionInfo {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_address: u32,
    characteristics: u32,
}

/// 快速计算数据熵值（Shannon熵）- 使用采样
/// 返回值范围 0-8，越高表示越随机（可能是加密或压缩）
fn calculate_entropy_fast(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    // 采样：最多检查8192字节，步进为2（每隔一个字节采样）
    const SAMPLE_SIZE: usize = 8192;
    const STEP: usize = 2;

    let mut frequency = [0u64; 256];
    let mut sample_count = 0;

    for i in (0..data.len().min(SAMPLE_SIZE * STEP)).step_by(STEP) {
        frequency[data[i] as usize] += 1;
        sample_count += 1;
    }

    if sample_count == 0 {
        return 0.0;
    }

    let len = sample_count as f64;
    let mut entropy = 0.0;

    for &count in &frequency {
        if count > 0 {
            let probability = count as f64 / len;
            entropy -= probability * probability.log2();
        }
    }

    entropy as f32
}

/// 获取感染型病毒检测描述
pub fn get_infector_description(result: &InfectorDetectionResult) -> String {
    if !result.is_infected {
        return "未发现感染型病毒特征".to_string();
    }

    let mut description = format!(
        "检测到感染型病毒特征（置信度: {:.0}%）\n",
        result.confidence * 100.0
    );

    description.push_str("发现以下可疑指标:\n");
    for indicator in &result.indicators {
        description.push_str(&format!("  - {}\n", indicator));
    }

    description
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        // 重复数据熵值应该很低
        let repeated = vec![0x41u8; 1000];
        assert!(calculate_entropy_fast(&repeated) < 1.0);

        // 随机数据熵值应该很高
        let random: Vec<u8> = (0..1000).map(|i| (i * 7 + 13) as u8).collect();
        assert!(calculate_entropy_fast(&random) > 7.0);
    }

    #[test]
    fn test_packer_detection() {
        let names = vec!["UPX0".to_string(), "UPX1".to_string()];
        assert!(detect_packer(&names).is_some());

        let names = vec![".text".to_string(), ".data".to_string()];
        assert!(detect_packer(&names).is_none());
    }

    #[test]
    fn test_suspicious_section_name() {
        assert!(!is_suspicious_section_name(".text"));
        assert!(!is_suspicious_section_name("CODE"));
        assert!(is_suspicious_section_name(""));
        assert!(is_suspicious_section_name("abcd"));
    }
}
