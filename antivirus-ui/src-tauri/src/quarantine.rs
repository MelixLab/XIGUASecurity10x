use std::fs;
use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};

use crate::security_log::{self, LogCategory, LogAction, LogResult};

/// 隔离文件信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedFile {
    pub id: String,
    pub original_path: String,
    pub file_name: String,
    pub quarantine_date: String,
    pub file_size: u64,
    pub threat_name: String,
    pub threat_level: String,
}

/// 隔离区管理器
pub struct QuarantineManager {
    quarantine_dir: PathBuf,
}

impl QuarantineManager {
    /// 创建隔离区管理器
    pub fn new() -> Result<Self, String> {
        let local_app_data = std::env::var("LOCALAPPDATA")
            .map_err(|_| "无法获取LOCALAPPDATA目录".to_string())?;
        
        let quarantine_dir = PathBuf::from(&local_app_data)
            .join("XIGUASecurity")
            .join("Quarantine");
        
        // 创建隔离区目录
        if !quarantine_dir.exists() {
            fs::create_dir_all(&quarantine_dir)
                .map_err(|e| format!("创建隔离区目录失败: {}", e))?;
        }
        
        Ok(Self { quarantine_dir })
    }
    
    /// 隔离文件
    /// 将威胁文件移动到隔离区，并保存元数据
    pub fn quarantine_file(
        &self,
        file_path: &str,
        threat_name: &str,
        threat_level: &str,
    ) -> Result<QuarantinedFile, String> {
        let source_path = Path::new(file_path);
        
        if !source_path.exists() {
            return Err("文件不存在".to_string());
        }
        
        // 生成唯一ID
        let id = format!("{}_{}", 
            chrono::Local::now().timestamp_millis(),
            generate_random_string(8)
        );
        
        // 获取文件信息
        let file_name = source_path
            .file_name()
            .ok_or("无效的文件名")?
            .to_string_lossy()
            .to_string();
        
        let file_size = fs::metadata(source_path)
            .map_err(|e| format!("获取文件元数据失败: {}", e))?
            .len();
        
        // 创建隔离文件路径
        let quarantine_file_path = self.quarantine_dir.join(format!("{}.quarantine", id));
        let metadata_path = self.quarantine_dir.join(format!("{}.json", id));
        
        // 读取原始文件内容并加密（简单XOR加密）
        let file_content = fs::read(source_path)
            .map_err(|e| format!("读取文件失败: {}", e))?;
        
        let encrypted_content = xor_encrypt(&file_content, &id);
        
        // 保存加密后的文件
        fs::write(&quarantine_file_path, encrypted_content)
            .map_err(|e| format!("写入隔离文件失败: {}", e))?;
        
        // 创建隔离文件信息
        let quarantined_file = QuarantinedFile {
            id: id.clone(),
            original_path: file_path.to_string(),
            file_name: file_name.clone(),
            quarantine_date: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            file_size,
            threat_name: threat_name.to_string(),
            threat_level: threat_level.to_string(),
        };
        
        // 保存元数据
        let metadata = serde_json::to_string_pretty(&quarantined_file)
            .map_err(|e| format!("序列化元数据失败: {}", e))?;
        
        fs::write(&metadata_path, metadata)
            .map_err(|e| format!("写入元数据失败: {}", e))?;
        
        // 删除原始文件
        fs::remove_file(source_path)
            .map_err(|e| format!("删除原始文件失败: {}", e))?;
        
        println!("[Quarantine] 文件已隔离: {} -> {}", file_path, id);
        
        // 记录安全日志
        let _ = security_log::add_security_log(
            LogCategory::Quarantine,
            "隔离区管理",
            &format!("已将威胁文件隔离: {}", file_name),
            Some(file_path.to_string()),
            Some(threat_name.to_string()),
            LogAction::Quarantined,
            LogResult::Success,
            None,
        );
        
        Ok(quarantined_file)
    }
    
    /// 恢复文件
    /// 从隔离区恢复文件到原始位置
    pub fn restore_file(&self, id: &str) -> Result<String, String> {
        let quarantine_file_path = self.quarantine_dir.join(format!("{}.quarantine", id));
        let metadata_path = self.quarantine_dir.join(format!("{}.json", id));
        
        if !quarantine_file_path.exists() || !metadata_path.exists() {
            return Err("隔离文件不存在".to_string());
        }
        
        // 读取元数据
        let metadata: QuarantinedFile = serde_json::from_str(
            &fs::read_to_string(&metadata_path)
                .map_err(|e| format!("读取元数据失败: {}", e))?
        ).map_err(|e| format!("解析元数据失败: {}", e))?;
        
        // 读取加密文件并解密
        let encrypted_content = fs::read(&quarantine_file_path)
            .map_err(|e| format!("读取隔离文件失败: {}", e))?;
        
        let decrypted_content = xor_encrypt(&encrypted_content, id);
        
        // 检查原始目录是否存在
        let original_path = Path::new(&metadata.original_path);
        if let Some(parent) = original_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("创建原始目录失败: {}", e))?;
            }
        }
        
        // 恢复文件
        fs::write(&metadata.original_path, decrypted_content)
            .map_err(|e| format!("恢复文件失败: {}", e))?;
        
        // 删除隔离区文件
        fs::remove_file(&quarantine_file_path)
            .map_err(|e| format!("删除隔离文件失败: {}", e))?;
        
        fs::remove_file(&metadata_path)
            .map_err(|e| format!("删除元数据失败: {}", e))?;
        
        println!("[Quarantine] 文件已恢复: {} -> {}", id, metadata.original_path);
        
        // 记录安全日志
        let _ = security_log::add_security_log(
            LogCategory::Quarantine,
            "隔离区管理",
            &format!("已从隔离区恢复文件: {}", metadata.file_name),
            Some(metadata.original_path.clone()),
            Some(metadata.threat_name.clone()),
            LogAction::Cleaned,
            LogResult::Success,
            None,
        );
        
        Ok(metadata.original_path)
    }
    
    /// 根据原始路径查找隔离记录ID
    pub fn find_id_by_original_path(&self, file_path: &str) -> Result<Option<String>, String> {
        let files = self.list_quarantined_files()?;
        Ok(files.into_iter().find(|f| f.original_path == file_path).map(|f| f.id))
    }
    
    /// 删除隔离文件
    /// 永久删除隔离区的文件
    pub fn delete_file(&self, id: &str) -> Result<(), String> {
        let quarantine_file_path = self.quarantine_dir.join(format!("{}.quarantine", id));
        let metadata_path = self.quarantine_dir.join(format!("{}.json", id));
        
        // 先读取元数据用于日志记录
        let metadata: Option<QuarantinedFile> = if metadata_path.exists() {
            fs::read_to_string(&metadata_path)
                .ok()
                .and_then(|content| serde_json::from_str(&content).ok())
        } else {
            None
        };
        
        if quarantine_file_path.exists() {
            fs::remove_file(&quarantine_file_path)
                .map_err(|e| format!("删除隔离文件失败: {}", e))?;
        }
        
        if metadata_path.exists() {
            fs::remove_file(&metadata_path)
                .map_err(|e| format!("删除元数据失败: {}", e))?;
        }
        
        println!("[Quarantine] 文件已永久删除: {}", id);
        
        // 记录安全日志
        let _ = security_log::add_security_log(
            LogCategory::Quarantine,
            "隔离区管理",
            &format!("已永久删除隔离文件: {}", 
                metadata.as_ref().map(|m| m.file_name.clone()).unwrap_or_else(|| id.to_string())),
            metadata.as_ref().map(|m| m.original_path.clone()),
            metadata.as_ref().map(|m| m.threat_name.clone()),
            LogAction::Deleted,
            LogResult::Success,
            None,
        );
        
        Ok(())
    }
    
    /// 获取所有隔离文件列表
    pub fn list_quarantined_files(&self) -> Result<Vec<QuarantinedFile>, String> {
        let mut files = Vec::new();
        
        let entries = fs::read_dir(&self.quarantine_dir)
            .map_err(|e| format!("读取隔离区目录失败: {}", e))?;
        
        for entry in entries {
            let entry = entry.map_err(|e| format!("读取目录项失败: {}", e))?;
            let path = entry.path();
            
            // 只处理.json元数据文件
            if path.extension().map_or(false, |ext| ext == "json") {
                match fs::read_to_string(&path) {
                    Ok(content) => {
                        if let Ok(file_info) = serde_json::from_str::<QuarantinedFile>(&content) {
                            files.push(file_info);
                        }
                    }
                    Err(e) => {
                        eprintln!("[Quarantine] 读取元数据文件失败: {} - {}", path.display(), e);
                    }
                }
            }
        }
        
        // 按隔离日期排序（最新的在前）
        files.sort_by(|a, b| b.quarantine_date.cmp(&a.quarantine_date));
        
        Ok(files)
    }
    
    /// 获取隔离区统计信息
    pub fn get_stats(&self) -> Result<(usize, u64), String> {
        let files = self.list_quarantined_files()?;
        let count = files.len();
        let total_size: u64 = files.iter().map(|f| f.file_size).sum();
        
        Ok((count, total_size))
    }
}

/// 简单的XOR加密/解密
fn xor_encrypt(data: &[u8], key: &str) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key_bytes[i % key_bytes.len()])
        .collect()
}

/// 生成随机字符串
fn generate_random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut result = String::with_capacity(length);
    
    // 使用当前时间作为随机种子
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    
    let mut seed = timestamp;
    
    for _ in 0..length {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        let idx = (seed % CHARSET.len() as u128) as usize;
        result.push(CHARSET[idx] as char);
    }
    
    result
}

/// 处理威胁文件（隔离）
///
/// ★活动内存威胁接入★：若清除失败的原因是"拒绝访问"（病毒正在运行、文件被占用），
/// 不再简单返回错误，而是：
/// 1. 自动弹出卡巴斯基风格"发现活动内存威胁"处置窗口（开机时清除 / 不重启而清除）；
/// 2. 返回结构化结果 {success:false, reason:"access_denied"}，前端据此分支处理，
///    不再误报"已隔离"，也不再重复弹标准隔离告警。
#[tauri::command]
pub async fn quarantine_threat_file(
    file_path: String,
    threat_name: String,
    threat_level: String,
    app: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    let manager = QuarantineManager::new()?;
    
    match manager.quarantine_file(&file_path, &threat_name, &threat_level) {
        Ok(quarantined) => Ok(serde_json::json!({
            "success": true,
            "id": quarantined.id,
            "original_path": quarantined.original_path,
            "file_name": quarantined.file_name,
            "quarantine_date": quarantined.quarantine_date,
            "file_size": quarantined.file_size,
            "threat_name": quarantined.threat_name,
            "threat_level": quarantined.threat_level,
        })),
        Err(e) if crate::active_threat::is_access_denied_error(&e) => {
            eprintln!(
                "[Quarantine] 清除失败（文件被活动进程占用）: {} - {}",
                file_path, e
            );

            // 自动弹出"发现活动内存威胁"处置窗口（右下角，卡巴斯基风格）
            crate::active_threat::trigger_active_threat_alert(
                app,
                file_path.clone(),
                threat_name.clone(),
            );

            Ok(serde_json::json!({
                "success": false,
                "reason": "access_denied",
                "error": e,
                "file_path": file_path,
                "threat_name": threat_name,
            }))
        }
        Err(e) => Err(e),
    }
}

/// 从隔离区恢复文件
#[tauri::command]
pub async fn restore_quarantined_file(id: String) -> Result<serde_json::Value, String> {
    let manager = QuarantineManager::new()?;
    
    let restored_path = manager.restore_file(&id)?;
    
    Ok(serde_json::json!({
        "success": true,
        "restored_path": restored_path,
    }))
}

/// 永久删除隔离文件
#[tauri::command]
pub async fn delete_quarantined_file(id: String) -> Result<serde_json::Value, String> {
    let manager = QuarantineManager::new()?;
    
    manager.delete_file(&id)?;
    
    Ok(serde_json::json!({
        "success": true,
    }))
}

/// 获取隔离区文件列表
#[tauri::command]
pub async fn get_quarantined_files() -> Result<serde_json::Value, String> {
    let manager = QuarantineManager::new()?;
    
    let files = manager.list_quarantined_files()?;
    let (count, total_size) = manager.get_stats()?;
    
    Ok(serde_json::json!({
        "success": true,
        "files": files,
        "count": count,
        "total_size": total_size,
    }))
}

/// 获取隔离区统计信息
#[tauri::command]
pub async fn get_quarantine_stats() -> Result<serde_json::Value, String> {
    let manager = QuarantineManager::new()?;
    
    let (count, total_size) = manager.get_stats()?;
    
    Ok(serde_json::json!({
        "success": true,
        "count": count,
        "total_size": total_size,
    }))
}

/// 将扫描检测到的多个文件批量加入隔离区（扫描完成后的"处理"按钮使用）
#[tauri::command]
pub async fn quarantine_scan_files(paths: Vec<String>) -> Result<serde_json::Value, String> {
    let manager = QuarantineManager::new()?;
    let mut quarantined = 0u32;
    let mut failed = 0u32;
    for p in &paths {
        match manager.quarantine_file(p, "扫描检测到的威胁", "high") {
            Ok(_) => quarantined += 1,
            Err(e) => {
                eprintln!("[Quarantine] 隔离失败 {}: {}", p, e);
                failed += 1;
            }
        }
    }
    Ok(serde_json::json!({
        "success": true,
        "quarantined": quarantined,
        "failed": failed,
    }))
}
