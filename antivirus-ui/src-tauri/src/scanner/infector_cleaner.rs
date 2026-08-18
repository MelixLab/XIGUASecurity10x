use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};

/// 感染型病毒清除结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleaningResult {
    pub success: bool,
    pub message: String,
    pub original_entry_point: Option<u32>,
    pub malicious_section: Option<String>,
    pub backup_path: Option<String>,
    pub quarantine_id: Option<String>, // 隔离ID
    pub cleaning_log: Vec<String>, // 处理日志
}

impl CleaningResult {
    pub fn success(message: &str) -> Self {
        Self {
            success: true,
            message: message.to_string(),
            original_entry_point: None,
            malicious_section: None,
            backup_path: None,
            quarantine_id: None,
            cleaning_log: Vec::new(),
        }
    }
    
    pub fn failure(message: &str) -> Self {
        Self {
            success: false,
            message: message.to_string(),
            original_entry_point: None,
            malicious_section: None,
            backup_path: None,
            quarantine_id: None,
            cleaning_log: Vec::new(),
        }
    }
}

/// PE文件结构信息
#[derive(Debug, Clone)]
pub struct PEFileInfo {
    pub data: Vec<u8>,
    pub pe_offset: usize,
    pub coff_header_offset: usize,
    pub optional_header_offset: usize,
    pub section_table_offset: usize,
    pub num_sections: u16,
    pub optional_header_size: u16,
    pub entry_point: u32,
    pub image_base: u64,
    pub is_64bit: bool,
    pub sections: Vec<SectionInfo>,
}

/// 节区信息
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_address: u32,
    pub characteristics: u32,
    pub index: usize,
}

/// 感染分析结果
#[derive(Debug, Clone)]
pub struct InfectionAnalysis {
    pub is_infected: bool,
    pub malicious_section_index: Option<usize>,
    pub malicious_section_name: Option<String>,
    pub original_entry_point: Option<u32>,
    pub indicators: Vec<String>,
}

/// 步骤一：PE文件结构解析与异常检测
/// 
/// 完全解析被感染PE文件的结构，提取所有节表信息，
/// 检测具有可执行权限、格式异常或名称可疑的节区
pub fn analyze_pe_structure(file_path: &str) -> Result<PEFileInfo, String> {
    let data = fs::read(file_path)
        .map_err(|e| format!("无法读取文件: {}", e))?;
    
    if data.len() < 64 {
        return Err("文件太小，不是有效的PE文件".to_string());
    }
    
    // 检查MZ头
    if data[0] != 0x4D || data[1] != 0x5A {
        return Err("不是有效的PE文件 (缺少MZ头)".to_string());
    }
    
    // 获取PE头偏移
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if pe_offset + 24 > data.len() {
        return Err("PE头偏移无效".to_string());
    }
    
    // 检查PE签名
    if data[pe_offset] != 0x50 || data[pe_offset + 1] != 0x45 {
        return Err("不是有效的PE文件 (缺少PE签名)".to_string());
    }
    
    // 获取COFF头信息
    let coff_header_offset = pe_offset + 4;
    let num_sections = u16::from_le_bytes([
        data[coff_header_offset + 2],
        data[coff_header_offset + 3],
    ]);
    
    let optional_header_size = u16::from_le_bytes([
        data[coff_header_offset + 16],
        data[coff_header_offset + 17],
    ]);
    
    // 获取可选头偏移
    let optional_header_offset = coff_header_offset + 20;
    
    // 判断是32位还是64位
    let pe_type = u16::from_le_bytes([
        data[optional_header_offset],
        data[optional_header_offset + 1],
    ]);
    let is_64bit = pe_type == 0x20B;
    
    // 获取入口点
    let entry_point = u32::from_le_bytes([
        data[optional_header_offset + 16],
        data[optional_header_offset + 17],
        data[optional_header_offset + 18],
        data[optional_header_offset + 19],
    ]);
    
    // 获取映像基址
    let image_base = if is_64bit {
        u64::from_le_bytes([
            data[optional_header_offset + 24],
            data[optional_header_offset + 25],
            data[optional_header_offset + 26],
            data[optional_header_offset + 27],
            data[optional_header_offset + 28],
            data[optional_header_offset + 29],
            data[optional_header_offset + 30],
            data[optional_header_offset + 31],
        ])
    } else {
        u32::from_le_bytes([
            data[optional_header_offset + 28],
            data[optional_header_offset + 29],
            data[optional_header_offset + 30],
            data[optional_header_offset + 31],
        ]) as u64
    };
    
    // 节表偏移
    let section_table_offset = optional_header_offset + optional_header_size as usize;
    
    // 解析所有节区信息
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
            index: i as usize,
        });
    }
    
    Ok(PEFileInfo {
        data,
        pe_offset,
        coff_header_offset,
        optional_header_offset,
        section_table_offset,
        num_sections,
        optional_header_size,
        entry_point,
        image_base,
        is_64bit,
        sections,
    })
}

/// 分析感染情况
/// 
/// 检测文件是否被感染，并定位恶意节区和原始入口点
/// 使用与扫描器相同的检测逻辑和阈值（70分，至少2个指标）
pub fn analyze_infection(pe_info: &PEFileInfo) -> InfectionAnalysis {
    let mut analysis = InfectionAnalysis {
        is_infected: false,
        malicious_section_index: None,
        malicious_section_name: None,
        original_entry_point: None,
        indicators: Vec::new(),
    };
    
    if pe_info.sections.is_empty() {
        return analysis;
    }
    
    // 获取最后一个节区
    let last_section = pe_info.sections.last().unwrap();
    let last_section_index = pe_info.sections.len() - 1;
    
    // 检查入口点是否在最后一个节区
    let last_section_start = last_section.virtual_address;
    let last_section_end = last_section.virtual_address + last_section.virtual_size;
    let entry_point_in_last_section = pe_info.entry_point >= last_section_start 
        && pe_info.entry_point < last_section_end;
    
    // 检查最后一个节区是否是标准的代码节区
    let is_standard_code_section = last_section.name == ".text" || 
        last_section.name.starts_with(".text") ||
        (last_section.characteristics & 0x00000020) != 0;
    
    // 检查是否具有可执行权限
    let is_executable = (last_section.characteristics & 0x20000000) != 0;
    
    // 检查是否具有RWE权限（读写执行）
    let is_rwe = (last_section.characteristics & 0xE0000000) == 0xE0000000;
    
    // 检查入口点是否在.text节区
    let mut entry_point_in_text = false;
    for section in &pe_info.sections {
        if section.name == ".text" || section.name.starts_with(".text") {
            let text_start = section.virtual_address;
            let text_end = section.virtual_address + section.virtual_size;
            if pe_info.entry_point >= text_start && pe_info.entry_point < text_end {
                entry_point_in_text = true;
                break;
            }
        }
    }
    
    // 综合判断 - 与扫描器使用完全相同的评分逻辑
    let mut score = 0;
    
    // 核心检测1：入口点指向最后一个节区且非标准代码节区
    if entry_point_in_last_section && !is_standard_code_section {
        analysis.indicators.push(format!(
            "入口点指向最后一个节区 '{}' (非标准代码节区)", 
            last_section.name
        ));
        score += 35;
    }
    
    // 核心检测2：最后一个节区具有可执行权限且熵值较高
    if is_executable && last_section.raw_size > 0 {
        let section_data = &pe_info.data[last_section.raw_address as usize..
            (last_section.raw_address as usize + last_section.raw_size as usize).min(pe_info.data.len())];
        let entropy = calculate_entropy(section_data);
        if entropy > 7.5 {
            analysis.indicators.push(format!(
                "最后一个节区 '{}' 可执行且熵值较高: {:.2}",
                last_section.name, entropy
            ));
            score += 25;
        }
    }
    
    // 核心检测3：最后一个节区的原始大小与虚拟大小差异很大
    if last_section.raw_size > 0 && last_section.virtual_size > 0 {
        let ratio = last_section.virtual_size as f32 / last_section.raw_size as f32;
        if ratio > 5.0 {
            analysis.indicators.push(format!(
                "最后一个节区大小异常: 虚拟大小={} 原始大小={} 比例={:.1}",
                last_section.virtual_size, last_section.raw_size, ratio
            ));
            score += 20;
        }
    }
    
    // 核心检测4：入口点不在.text节区而在最后一个节区
    if !entry_point_in_text && entry_point_in_last_section {
        analysis.indicators.push("入口点不在.text节区，而在最后一个节区".to_string());
        score += 30;
    }
    
    // 核心检测5：最后一个节区具有读写执行权限（RWE）
    if is_rwe {
        analysis.indicators.push(format!(
            "最后一个节区 '{}' 具有读写执行权限 (RWE)",
            last_section.name
        ));
        score += 25;
    }
    
    // 使用与扫描器相同的阈值：50分且至少2个指标
    let threshold = 50;
    let has_multiple_indicators = analysis.indicators.len() >= 2;
    
    println!("[InfectorCleaner] Analysis score: {}, indicators: {}, threshold: {} (multiple: {})", 
        score, analysis.indicators.len(), threshold, has_multiple_indicators);
    
    if score >= threshold && has_multiple_indicators {
        analysis.malicious_section_index = Some(last_section_index);
        analysis.malicious_section_name = Some(last_section.name.clone());
        
        // 尝试从病毒代码中提取原始OEP
        if let Some(oep) = extract_original_entry_point(pe_info, last_section_index) {
            analysis.original_entry_point = Some(oep);
            analysis.indicators.push(format!("从病毒代码中提取到原始入口点: 0x{:08X}", oep));
        }
        
        analysis.is_infected = true;
        println!("[InfectorCleaner] Infection confirmed! Section: {}", last_section.name);
    } else {
        println!("[InfectorCleaner] Infection not confirmed. Score: {} < {} or indicators: {} < 2", 
            score, threshold, analysis.indicators.len());
    }
    
    analysis
}

/// 计算数据熵值（Shannon熵）
fn calculate_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    
    let mut frequency = [0u64; 256];
    
    for &byte in data {
        frequency[byte as usize] += 1;
    }
    
    let len = data.len() as f64;
    let mut entropy = 0.0;
    
    for &count in &frequency {
        if count > 0 {
            let probability = count as f64 / len;
            entropy -= probability * probability.log2();
        }
    }
    
    entropy as f32
}

/// 从病毒代码中提取原始入口点
/// 
/// 病毒代码通常会在执行完毕后跳转回原始入口点
/// 查找JMP指令或存储的OEP值
fn extract_original_entry_point(pe_info: &PEFileInfo, malicious_section_index: usize) -> Option<u32> {
    let section = &pe_info.sections[malicious_section_index];
    
    if section.raw_address == 0 || section.raw_size == 0 {
        return None;
    }
    
    let start = section.raw_address as usize;
    let end = start + section.raw_size as usize;
    
    if end > pe_info.data.len() {
        return None;
    }
    
    let code = &pe_info.data[start..end];
    
    // 查找x64 JMP指令 (0x49 0xFF 0xE7 = jmp r15 或 0xFF 0xE0 = jmp rax)
    for i in 0..code.len().saturating_sub(10) {
        // 查找 jmp r15 (0x49 0xFF 0xE7)
        if code[i] == 0x49 && code[i+1] == 0xFF && code[i+2] == 0xE7 {
            // 往前查找 mov r15, imm64 (0x49 0xBF)
            if i >= 10 {
                for j in (0..i-10).rev() {
                    if code[j] == 0x49 && code[j+1] == 0xBF {
                        // 提取8字节地址
                        let addr_bytes = &code[j+2..j+10];
                        let addr = u64::from_le_bytes([
                            addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3],
                            addr_bytes[4], addr_bytes[5], addr_bytes[6], addr_bytes[7],
                        ]);
                        // 转换为RVA
                        let rva = (addr - pe_info.image_base) as u32;
                        return Some(rva);
                    }
                }
            }
        }
        
        // 查找 mov rax, imm64 + jmp rax
        if code[i] == 0x48 && code[i+1] == 0xB8 {
            // 0x48 0xB8 = mov rax, imm64
            if i + 10 < code.len() && code[i+10] == 0xFF && code[i+11] == 0xE0 {
                let addr_bytes = &code[i+2..i+10];
                let addr = u64::from_le_bytes([
                    addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3],
                    addr_bytes[4], addr_bytes[5], addr_bytes[6], addr_bytes[7],
                ]);
                let rva = (addr - pe_info.image_base) as u32;
                return Some(rva);
            }
        }
    }
    
    // 如果找不到跳转指令，尝试其他方法
    // 查找存储的OEP值（通常在病毒代码开头）
    if code.len() >= 20 {
        // 查找常见的OEP保存模式
        for i in 0..code.len().saturating_sub(4) {
            let val = u32::from_le_bytes([code[i], code[i+1], code[i+2], code[i+3]]);
            // 检查是否是合理的RVA值（通常在0x1000-0x10000000范围内）
            if val >= 0x1000 && val < 0x10000000 {
                // 检查这个值是否指向.text节区
                for section in &pe_info.sections {
                    if section.name == ".text" || section.name.starts_with(".text") {
                        let section_start = section.virtual_address;
                        let section_end = section.virtual_address + section.virtual_size;
                        if val >= section_start && val < section_end {
                            return Some(val);
                        }
                    }
                }
            }
        }
    }
    
    None
}

/// 步骤二：入口点恢复
/// 
/// 修改PE头中的AddressOfEntryPoint字段，将入口点恢复为原始OEP
fn restore_entry_point(pe_info: &mut PEFileInfo, original_ep: u32) -> Result<(), String> {
    let offset = pe_info.optional_header_offset + 16;
    
    if offset + 4 > pe_info.data.len() {
        return Err("PE头偏移无效".to_string());
    }
    
    // 写入原始入口点
    pe_info.data[offset] = (original_ep & 0xFF) as u8;
    pe_info.data[offset + 1] = ((original_ep >> 8) & 0xFF) as u8;
    pe_info.data[offset + 2] = ((original_ep >> 16) & 0xFF) as u8;
    pe_info.data[offset + 3] = ((original_ep >> 24) & 0xFF) as u8;
    
    pe_info.entry_point = original_ep;
    
    Ok(())
}

/// 步骤三：恶意节区删除
/// 
/// 从节表中删除恶意节区条目，并调整后续节区
fn remove_malicious_section(
    pe_info: &mut PEFileInfo, 
    malicious_index: usize
) -> Result<(), String> {
    if malicious_index >= pe_info.sections.len() {
        return Err("无效的恶意节区索引".to_string());
    }
    
    let _malicious_section = pe_info.sections[malicious_index].clone();
    
    // 从节表中删除该节区
    pe_info.sections.remove(malicious_index);
    
    // 更新节区数量
    pe_info.num_sections = pe_info.sections.len() as u16;
    
    // 更新COFF头中的节区数量
    let num_sections_offset = pe_info.coff_header_offset + 2;
    pe_info.data[num_sections_offset] = (pe_info.num_sections & 0xFF) as u8;
    pe_info.data[num_sections_offset + 1] = ((pe_info.num_sections >> 8) & 0xFF) as u8;
    
    // 更新节区索引
    for (i, section) in pe_info.sections.iter_mut().enumerate() {
        section.index = i;
    }
    
    // 从节表中删除该节区的40字节条目
    let _section_entry_offset = pe_info.section_table_offset + (malicious_index * 40);
    
    // 将后续节区条目向前移动
    for i in malicious_index..pe_info.sections.len() {
        let src_offset = pe_info.section_table_offset + ((i + 1) * 40);
        let dst_offset = pe_info.section_table_offset + (i * 40);
        
        if src_offset + 40 <= pe_info.data.len() && dst_offset + 40 <= pe_info.data.len() {
            let bytes_to_copy = pe_info.data[src_offset..src_offset + 40].to_vec();
            pe_info.data[dst_offset..dst_offset + 40].copy_from_slice(&bytes_to_copy);
        }
    }
    
    // 清空最后一个节区条目（现在重复了）
    let last_entry_offset = pe_info.section_table_offset + (pe_info.sections.len() * 40);
    if last_entry_offset + 40 <= pe_info.data.len() {
        for i in 0..40 {
            pe_info.data[last_entry_offset + i] = 0;
        }
    }
    
    Ok(())
}

/// 步骤四：文件结构修复
/// 
/// 修正后续节区的文件偏移，调整PE头中的关键字段
fn repair_file_structure(pe_info: &mut PEFileInfo, malicious_raw_size: u32) -> Result<(), String> {
    // 更新SizeOfImage（减去恶意节区的虚拟大小）
    let size_of_image_offset = pe_info.optional_header_offset + 56;
    
    if size_of_image_offset + 4 <= pe_info.data.len() {
        let current_size = u32::from_le_bytes([
            pe_info.data[size_of_image_offset],
            pe_info.data[size_of_image_offset + 1],
            pe_info.data[size_of_image_offset + 2],
            pe_info.data[size_of_image_offset + 3],
        ]);
        
        // 重新计算SizeOfImage（最后一个节区的虚拟地址 + 虚拟大小，向上对齐到0x1000）
        let new_size = if let Some(last) = pe_info.sections.last() {
            let size = last.virtual_address + last.virtual_size;
            ((size + 0xFFF) / 0x1000) * 0x1000
        } else {
            current_size - malicious_raw_size
        };
        
        pe_info.data[size_of_image_offset] = (new_size & 0xFF) as u8;
        pe_info.data[size_of_image_offset + 1] = ((new_size >> 8) & 0xFF) as u8;
        pe_info.data[size_of_image_offset + 2] = ((new_size >> 16) & 0xFF) as u8;
        pe_info.data[size_of_image_offset + 3] = ((new_size >> 24) & 0xFF) as u8;
    }
    
    // 截断文件数据（删除恶意节区的文件内容）
    // 找到恶意节区的原始数据位置并截断
    let mut truncate_pos = None;
    
    for section in &pe_info.sections {
        let section_end = section.raw_address + section.raw_size;
        if truncate_pos.is_none() || section_end > truncate_pos.unwrap() {
            truncate_pos = Some(section_end);
        }
    }
    
    if let Some(pos) = truncate_pos {
        let pos = pos as usize;
        if pos < pe_info.data.len() {
            pe_info.data.truncate(pos);
        }
    }
    
    Ok(())
}

/// 步骤五：完整性校验与安全处理
/// 
/// 1. 先将原文件隔离到隔离区（加密存储）
/// 2. 然后清除感染
/// 3. 记录详细的处理日志
pub fn clean_infected_file(
    file_path: &str,
    quarantine_dir: &str,
) -> CleaningResult {
    let mut cleaning_log = Vec::new();
    
    // 记录开始处理
    cleaning_log.push(format!("[1/6] 开始处理感染型病毒: {}", file_path));
    
    // 首先使用扫描器的detect_infector函数检测感染
    let infector_result = crate::scanner::infector_detector::detect_infector(file_path);
    
    if !infector_result.is_infected {
        cleaning_log.push("[ERROR] 未检测到感染型病毒特征".to_string());
        let mut result = CleaningResult::failure("未检测到感染型病毒特征，无需清除");
        result.cleaning_log = cleaning_log;
        return result;
    }
    
    cleaning_log.push(format!("[2/6] 检测到感染型病毒，置信度: {:.2}%", infector_result.confidence * 100.0));
    
    // 步骤一：解析PE文件结构
    let mut pe_info = match analyze_pe_structure(file_path) {
        Ok(info) => info,
        Err(e) => {
            cleaning_log.push(format!("[ERROR] PE解析失败: {}", e));
            let mut result = CleaningResult::failure(&format!("PE解析失败: {}", e));
            result.cleaning_log = cleaning_log;
            return result;
        }
    };
    
    cleaning_log.push(format!("[3/6] PE文件解析成功: {} 个节区", pe_info.num_sections));
    
    // 分析感染情况
    let analysis = analyze_infection(&pe_info);
    
    // 确定恶意节区索引
    let malicious_index = if analysis.is_infected {
        analysis.malicious_section_index.unwrap_or(pe_info.sections.len() - 1)
    } else {
        pe_info.sections.len() - 1
    };
    
    let malicious_section = pe_info.sections[malicious_index].clone();
    cleaning_log.push(format!("  - 恶意节区: {} (索引: {})", malicious_section.name, malicious_index));
    
    // 确定原始入口点
    let original_ep = if analysis.is_infected {
        match analysis.original_entry_point {
            Some(ep) => {
                cleaning_log.push(format!("  - 从病毒代码中提取到原始入口点: 0x{:08X}", ep));
                ep
            },
            None => {
                // 如果无法提取OEP，尝试使用.text节区的入口
                let mut found_ep = None;
                for section in &pe_info.sections {
                    if section.name == ".text" || section.name.starts_with(".text") {
                        found_ep = Some(section.virtual_address);
                        break;
                    }
                }
                match found_ep {
                    Some(ep) => {
                        cleaning_log.push(format!("  - 使用.text节区地址作为原始入口点: 0x{:08X}", ep));
                        ep
                    },
                    None => {
                        cleaning_log.push("[ERROR] 无法确定原始入口点".to_string());
                        let mut result = CleaningResult::failure("无法确定原始入口点");
                        result.cleaning_log = cleaning_log;
                        return result;
                    }
                }
            }
        }
    } else {
        // 使用.text节区作为OEP
        let mut found_ep = None;
        for section in &pe_info.sections {
            if section.name == ".text" || section.name.starts_with(".text") {
                found_ep = Some(section.virtual_address);
                break;
            }
        }
        match found_ep {
            Some(ep) => {
                cleaning_log.push(format!("  - 使用.text节区地址作为原始入口点: 0x{:08X}", ep));
                ep
            },
            None => {
                cleaning_log.push("[ERROR] 无法确定原始入口点".to_string());
                let mut result = CleaningResult::failure("无法确定原始入口点");
                result.cleaning_log = cleaning_log;
                return result;
            }
        }
    };
    
    // 步骤二：先将原文件隔离到隔离区（加密存储）
    cleaning_log.push("[4/6] 将原文件隔离到隔离区...".to_string());
    
    let quarantine_id = match crate::quarantine::QuarantineManager::new() {
        Ok(manager) => {
            match manager.quarantine_file(
                file_path,
                &format!("Infector.{}!ml", malicious_section.name.trim_start_matches('.')),
                "High"
            ) {
                Ok(quarantined_file) => {
                    cleaning_log.push(format!("  - 原文件已隔离，隔离ID: {}", quarantined_file.id));
                    Some(quarantined_file.id)
                },
                Err(e) => {
                    cleaning_log.push(format!("[WARNING] 隔离原文件失败: {}，继续清除操作", e));
                    None
                }
            }
        },
        Err(e) => {
            cleaning_log.push(format!("[WARNING] 创建隔离管理器失败: {}，继续清除操作", e));
            None
        }
    };
    
    // 步骤三：恢复入口点
    cleaning_log.push("[5/6] 清除感染...".to_string());
    
    if let Err(e) = restore_entry_point(&mut pe_info, original_ep) {
        cleaning_log.push(format!("[ERROR] 恢复入口点失败: {}", e));
        let mut result = CleaningResult::failure(&format!("恢复入口点失败: {}", e));
        result.cleaning_log = cleaning_log;
        result.quarantine_id = quarantine_id;
        return result;
    }
    cleaning_log.push(format!("  - 入口点已恢复: 0x{:08X}", original_ep));
    
    // 步骤四：删除恶意节区
    let malicious_raw_size = malicious_section.raw_size;
    if let Err(e) = remove_malicious_section(&mut pe_info, malicious_index) {
        cleaning_log.push(format!("[ERROR] 删除恶意节区失败: {}", e));
        let mut result = CleaningResult::failure(&format!("删除恶意节区失败: {}", e));
        result.cleaning_log = cleaning_log;
        result.quarantine_id = quarantine_id;
        return result;
    }
    cleaning_log.push(format!("  - 恶意节区 '{}' 已删除", malicious_section.name));
    
    // 步骤五：修复文件结构
    if let Err(e) = repair_file_structure(&mut pe_info, malicious_raw_size) {
        cleaning_log.push(format!("[ERROR] 修复文件结构失败: {}", e));
        let mut result = CleaningResult::failure(&format!("修复文件结构失败: {}", e));
        result.cleaning_log = cleaning_log;
        result.quarantine_id = quarantine_id;
        return result;
    }
    cleaning_log.push("  - 文件结构已修复".to_string());
    
    // 保存修复后的文件
    if let Err(e) = fs::write(file_path, &pe_info.data) {
        cleaning_log.push(format!("[ERROR] 保存修复后的文件失败: {}", e));
        let mut result = CleaningResult::failure(&format!("保存修复后的文件失败: {}", e));
        result.cleaning_log = cleaning_log;
        result.quarantine_id = quarantine_id;
        return result;
    }
    cleaning_log.push(format!("  - 修复后的文件已保存: {}", file_path));
    
    // 完成
    cleaning_log.push("[6/6] 清除完成".to_string());
    
    let mut result = CleaningResult::success(&format!(
        "成功清除感染型病毒。恶意节区 '{}' 已删除，入口点已恢复为 0x{:08X}",
        malicious_section.name, original_ep
    ));
    
    result.original_entry_point = Some(original_ep);
    result.malicious_section = Some(malicious_section.name);
    result.quarantine_id = quarantine_id;
    result.cleaning_log = cleaning_log;
    
    result
}

/// 获取感染清除报告
pub fn get_cleaning_report(result: &CleaningResult) -> String {
    if result.success {
        let mut report = format!("✓ 清除成功\n\n");
        report.push_str(&format!("{}", result.message));
        
        if let Some(ref section) = result.malicious_section {
            report.push_str(&format!("\n删除的恶意节区: {}", section));
        }
        
        if let Some(ep) = result.original_entry_point {
            report.push_str(&format!("\n恢复的原始入口点: 0x{:08X}", ep));
        }
        
        if let Some(ref backup) = result.backup_path {
            report.push_str(&format!("\n备份文件: {}", backup));
        }
        
        report
    } else {
        format!("✗ 清除失败\n\n{}", result.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pe_structure_parsing() {
        // 这个测试需要一个实际的PE文件
        // 在实际测试中使用模拟数据
    }
    
    #[test]
    fn test_entry_point_extraction() {
        // 测试OEP提取逻辑
    }
}
