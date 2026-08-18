use std::collections::HashSet;
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};
use lazy_static::lazy_static;
use std::sync::Mutex;

/// 白名单数据结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistData {
    pub version: String,
    pub updated_at: String,
    pub description: String,
    pub file_hashes: Vec<String>,
    pub file_names: Vec<String>,
    pub file_paths: Vec<String>,
}

impl Default for WhitelistData {
    fn default() -> Self {
        Self {
            version: "1.0.0".to_string(),
            updated_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            description: "XIGUASecurity Hash Whitelist".to_string(),
            file_hashes: Vec::new(),
            file_names: Vec::new(),
            file_paths: Vec::new(),
        }
    }
}

/// 白名单管理器
pub struct WhitelistManager {
    data: WhitelistData,
    hash_set: HashSet<String>,
    name_set: HashSet<String>,
    path_set: HashSet<String>,
}

impl WhitelistManager {
    pub fn new() -> Self {
        let mut manager = Self {
            data: WhitelistData::default(),
            hash_set: HashSet::new(),
            name_set: HashSet::new(),
            path_set: HashSet::new(),
        };
        // 先尝试从用户数据目录加载已有白名单
        manager.load_from_file();
        // 再尝试从 Driver 文件夹加载内置规则（确保扫描前规则已就绪）
        manager.load_builtin_from_driver();
        manager
    }

    /// 从 Driver 文件夹加载内置规则（在初始化时同步调用）
    fn load_builtin_from_driver(&mut self) -> bool {
        let exe_path = match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => return false,
        };
        
        // 从 exe 路径开始向上搜索最多 5 层找 Driver 文件夹
        let mut current_dir = exe_path.parent();
        let driver_dir = loop {
            match current_dir {
                Some(dir) => {
                    let test = dir.join("Driver");
                    if test.exists() && test.is_dir() {
                        break Some(test);
                    }
                    current_dir = dir.parent();
                }
                None => break None,
            }
        };
        
        let driver_dir = match driver_dir {
            Some(d) => d,
            None => return false,
        };
        
        let mut loaded = false;
        if let Ok(entries) = fs::read_dir(&driver_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map_or(false, |e| e == "json") {
                    if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                        if name.starts_with("whitelist_v") {
                            if let Ok(content) = fs::read_to_string(&path) {
                                if let Ok(data) = serde_json::from_str::<WhitelistData>(&content) {
                                    for hash in &data.file_hashes {
                                        self.add_hash(hash.clone());
                                    }
                                    for name in &data.file_names {
                                        self.add_name(name.clone());
                                    }
                                    loaded = true;
                                    // 更新版本信息（用找到的最新版本）
                                    let parts: Vec<&str> = name.split('_').collect();
                                    if parts.len() >= 3 {
                                        let ver = parts[1].trim_start_matches('v');
                                        if is_newer_version(ver, &self.data.version) {
                                            self.data.version = ver.to_string();
                                            self.data.updated_at = data.updated_at.clone();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        if loaded {
            // 保存到用户数据目录，确保后续扫描也能加载
            let _ = self.save_to_file();
            // 同步更新 rules_info.json
            if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
                let rules_dir = std::path::PathBuf::from(&local_app_data).join("XIGUASecurity");
                if let Ok(info_path) = std::fs::create_dir_all(&rules_dir) {
                    let _ = info_path; // suppress unused warning
                }
                let info_path = rules_dir.join("rules_info.json");
                let info = serde_json::json!({
                    "version": self.data.version,
                    "updated_at": self.data.updated_at,
                    "last_check": chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    "file_count": 1,
                    "hash_count": self.hash_set.len(),
                });
                if let Ok(content) = serde_json::to_string_pretty(&info) {
                    let _ = std::fs::write(&info_path, content);
                }
            }
        }
        
        loaded
    }

    /// 从文件加载白名单
    pub fn load_from_file(&mut self) -> bool {
        let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
        let whitelist_path = format!("{}/XIGUASecurity/whitelist.json", local_app_data);
        
        if !Path::new(&whitelist_path).exists() {
            println!("[Whitelist] - No whitelist file found at: {}", whitelist_path);
            return false;
        }

        match fs::read_to_string(&whitelist_path) {
            Ok(content) => {
                match serde_json::from_str::<WhitelistData>(&content) {
                    Ok(data) => {
                        self.data = data.clone();
                        self.hash_set = data.file_hashes.iter().map(|s| s.to_uppercase()).collect();
                        self.name_set = data.file_names.iter().map(|s| s.to_lowercase()).collect();
                        println!("[Whitelist] - Loaded {} hashes and {} filenames", 
                            self.hash_set.len(), self.name_set.len());
                        let _ = self.sync_edr_whitelist();
                        true
                    }
                    Err(e) => {
                        println!("[Whitelist] - Failed to parse whitelist: {}", e);
                        false
                    }
                }
            }
            Err(e) => {
                println!("[Whitelist] - Failed to read whitelist file: {}", e);
                false
            }
        }
    }

    /// 保存白名单到文件
    pub fn save_to_file(&self) -> Result<(), String> {
        let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
        let config_dir = format!("{}/XIGUASecurity", local_app_data);
        
        fs::create_dir_all(&config_dir)
            .map_err(|e| format!("Failed to create config dir: {}", e))?;
        
        let whitelist_path = format!("{}/whitelist.json", config_dir);
        let content = serde_json::to_string_pretty(&self.data)
            .map_err(|e| format!("Failed to serialize whitelist: {}", e))?;
        
        fs::write(&whitelist_path, content)
            .map_err(|e| format!("Failed to write whitelist file: {}", e))?;
        
        // 同步到驱动 EDR 白名单
        let _ = self.sync_edr_whitelist();
        
        Ok(())
    }

    /// 同步白名单文件名到驱动 EDR 白名单文件
    /// 文件路径: C:\ProgramData\XIGUASecurity\EDRWhitelist.txt
    /// 格式: 每行一个进程名（如 cmd.exe）
    fn sync_edr_whitelist(&self) -> Result<(), String> {
        let program_data = std::env::var("PROGRAMDATA")
            .unwrap_or_else(|_| "C:/ProgramData".to_string());
        let edr_dir = std::path::PathBuf::from(&program_data).join("XIGUASecurity");
        
        std::fs::create_dir_all(&edr_dir)
            .map_err(|e| format!("Failed to create EDR whitelist dir: {}", e))?;
        
        let edr_path = edr_dir.join("EDRWhitelist.txt");
        
        // 只写入用户添加的进程名，不内置系统进程（避免恶意进程改名绕过）
        let names: Vec<String> = self.data.file_names.iter()
            .map(|n| n.trim().to_lowercase())
            .filter(|n| !n.is_empty())
            .collect();
        
        let content = names.join("\r\n");
        std::fs::write(&edr_path, content)
            .map_err(|e| format!("Failed to write EDR whitelist file: {}", e))?;
        
        println!("[Whitelist] - Synced {} entries to EDR whitelist: {}",
            names.len(), edr_path.display());
        
        Ok(())
    }

    /// 检查哈希是否在白名单中
    pub fn contains_hash(&self, hash: &str) -> bool {
        self.hash_set.contains(&hash.to_uppercase())
    }

    /// 检查文件名是否在白名单中
    pub fn contains_name(&self, name: &str) -> bool {
        self.name_set.contains(&name.to_lowercase())
    }

    /// 添加哈希到白名单
    pub fn add_hash(&mut self, hash: String) {
        let hash_upper = hash.to_uppercase();
        if !self.hash_set.contains(&hash_upper) {
            self.hash_set.insert(hash_upper.clone());
            self.data.file_hashes.push(hash_upper);
        }
    }

    /// 添加文件名到白名单
    pub fn add_name(&mut self, name: String) {
        let name_lower = name.to_lowercase();
        if !self.name_set.contains(&name_lower) {
            self.name_set.insert(name_lower.clone());
            self.data.file_names.push(name_lower);
        }
    }

    /// 从白名单移除文件名
    pub fn remove_name(&mut self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        if self.name_set.remove(&name_lower) {
            self.data.file_names.retain(|n| n.to_lowercase() != name_lower);
            true
        } else {
            false
        }
    }

    /// 获取所有白名单文件名（进程名）
    pub fn get_names(&self) -> Vec<String> {
        self.data.file_names.clone()
    }

    /// 获取版本
    pub fn get_version(&self) -> String {
        self.data.version.clone()
    }

    /// 获取更新日期
    pub fn get_updated_at(&self) -> String {
        self.data.updated_at.clone()
    }

    /// 获取哈希数量
    pub fn get_hash_count(&self) -> usize {
        self.hash_set.len()
    }

    /// 获取白名单数据
    pub fn get_data(&self) -> &WhitelistData {
        &self.data
    }

    /// 更新白名单数据
    pub fn update_data(&mut self, data: WhitelistData) {
        self.data = data.clone();
        self.hash_set = data.file_hashes.iter().map(|s| s.to_uppercase()).collect();
        self.name_set = data.file_names.iter().map(|s| s.to_lowercase()).collect();
        self.path_set = data.file_paths.iter().map(|s| s.to_lowercase()).collect();
    }

    // ========== 路径白名单 ==========

    /// 检查路径是否在白名单中（前缀匹配）
    pub fn contains_path(&self, path: &str) -> bool {
        let lower = path.to_lowercase().replace('/', "\\");
        self.path_set.iter().any(|p| lower.starts_with(p.as_str()) || lower == p.as_str())
    }

    /// 添加路径到白名单
    pub fn add_path(&mut self, path: String) {
        let normalised = path.to_lowercase().replace('/', "\\").trim_end_matches('\\').to_string();
        if !self.path_set.contains(&normalised) {
            self.path_set.insert(normalised.clone());
            self.data.file_paths.push(normalised);
        }
    }

    /// 从白名单移除路径
    pub fn remove_path(&mut self, path: &str) -> bool {
        let normalised = path.to_lowercase().replace('/', "\\").trim_end_matches('\\').to_string();
        if self.path_set.remove(&normalised) {
            self.data.file_paths.retain(|p| p.to_lowercase() != normalised);
            true
        } else {
            false
        }
    }

    /// 获取所有白名单路径
    pub fn get_paths(&self) -> Vec<String> {
        self.data.file_paths.clone()
    }
}

// 全局白名单管理器实例
lazy_static! {
    static ref WHITELIST_MANAGER: Mutex<WhitelistManager> = Mutex::new(WhitelistManager::new());
}

/// 获取全局白名单管理器
pub fn get_whitelist_manager() -> std::sync::MutexGuard<'static, WhitelistManager> {
    WHITELIST_MANAGER.lock().unwrap()
}

/// 重新加载白名单
pub fn reload_whitelist() -> bool {
    get_whitelist_manager().load_from_file()
}

/// 检查哈希是否在白名单中
pub fn is_hash_whitelisted(hash: &str) -> bool {
    match crate::rules_db::lookup_hash(hash) {
        crate::rules_db::HashLookupResult::Whitelisted => true,
        crate::rules_db::HashLookupResult::Blacklisted { .. } => false,
        crate::rules_db::HashLookupResult::NotFound => get_whitelist_manager().contains_hash(hash),
    }
}

/// 检查文件名是否在白名单中
pub fn is_name_whitelisted(name: &str) -> bool {
    match crate::rules_db::lookup_file_name(name) {
        Some(list_type) if list_type == "whitelist" => true,
        Some(_) => false,
        None => get_whitelist_manager().contains_name(name),
    }
}

// ========== 路径白名单（用户管理） ==========

/// 检查路径是否在白名单中
pub fn is_path_whitelisted(path: &str) -> bool {
    match crate::rules_db::lookup_file_path(path) {
        Some(list_type) if list_type == "whitelist" => true,
        Some(_) => false,
        None => get_whitelist_manager().contains_path(path),
    }
}

/// 添加路径到白名单（持久化保存）
pub fn add_whitelist_path(path: String) -> Result<(), String> {
    let mut mgr = get_whitelist_manager();
    mgr.add_path(path);
    mgr.save_to_file()
}

/// 从白名单移除路径（持久化保存）
pub fn remove_whitelist_path(path: &str) -> Result<(), String> {
    let mut mgr = get_whitelist_manager();
    mgr.remove_path(path);
    mgr.save_to_file()
}

/// 获取所有白名单路径
pub fn get_whitelist_paths() -> Vec<String> {
    get_whitelist_manager().get_paths()
}

// ========== 进程名白名单（用户管理，同步到 EDR 驱动白名单） ==========

/// 检查进程名是否在白名单中
pub fn is_process_whitelisted(name: &str) -> bool {
    get_whitelist_manager().contains_name(name)
}

/// 添加进程名到白名单（持久化保存并同步到 EDRWhitelist.txt）
pub fn add_whitelist_process(name: String) -> Result<(), String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("进程名不能为空".to_string());
    }
    if !trimmed.contains('.') {
        return Err("进程名必须包含文件后缀，例如 cmd.exe、taskmgr.exe".to_string());
    }
    let mut mgr = get_whitelist_manager();
    mgr.add_name(trimmed.to_string());
    mgr.save_to_file()
}

/// 从白名单移除进程名（持久化保存并同步到 EDRWhitelist.txt）
pub fn remove_whitelist_process(name: &str) -> Result<(), String> {
    let mut mgr = get_whitelist_manager();
    mgr.remove_name(name);
    mgr.save_to_file()
}

/// 获取所有白名单进程名
pub fn get_whitelist_processes() -> Vec<String> {
    get_whitelist_manager().get_names()
}

/// 扫描规则文件夹并加载所有规则文件
/// 规则文件命名格式: whitelist_v1.0.0_2025-01-15.json
/// 返回: (总哈希数, 最新版本号, 加载的文件数量)
pub fn scan_and_load_rules() -> Result<(usize, String, usize), String> {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let rules_dir = format!("{}/XIGUASecurity/rules", local_app_data);
    
    if !Path::new(&rules_dir).exists() {
        return Ok((0, "0.0.0".to_string(), 0));
    }
    
    let mut total_hashes = 0;
    let mut latest_version = "0.0.0".to_string();
    let mut loaded_files = 0;
    let mut all_files: Vec<(String, String)> = Vec::new(); // (文件路径, 版本号)
    
    // 第一步：扫描规则文件夹中的所有 JSON 文件
    if let Ok(entries) = fs::read_dir(&rules_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "json" {
                    if let Some(filename) = path.file_stem().and_then(|s| s.to_str()) {
                        // 解析文件名格式: whitelist_v1.0.0_2025-01-15
                        if filename.starts_with("whitelist_v") {
                            let parts: Vec<&str> = filename.split('_').collect();
                            if parts.len() >= 3 {
                                let version = parts[1].trim_start_matches('v');
                                let file_path = path.to_string_lossy().to_string();
                                all_files.push((file_path, version.to_string()));
                                
                                // 跟踪最新版本号
                                if is_newer_version(version, &latest_version) {
                                    latest_version = version.to_string();
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // 第二步：加载所有规则文件
    let mut manager = get_whitelist_manager();
    let mut latest_updated_at = String::new();
    
    for (file_path, version) in &all_files {
        match fs::read_to_string(&file_path) {
            Ok(content) => {
                match serde_json::from_str::<WhitelistData>(&content) {
                    Ok(data) => {
                        // 合并新规则到现有规则
                        for hash in &data.file_hashes {
                            manager.add_hash(hash.clone());
                        }
                        for name in &data.file_names {
                            manager.add_name(name.clone());
                        }
                        
                        // 如果这是最新版本，记录更新时间
                        if version == &latest_version {
                            latest_updated_at = data.updated_at.clone();
                        }
                        
                        loaded_files += 1;
                        println!("[Whitelist] - Loaded rules from {} (v{}): {} hashes", 
                            file_path, version, data.file_hashes.len());
                    }
                    Err(e) => {
                        println!("[Whitelist] - Failed to parse {}: {}", file_path, e);
                    }
                }
            }
            Err(e) => {
                println!("[Whitelist] - Failed to read {}: {}", file_path, e);
            }
        }
    }
    
    // 第三步：保存合并后的规则
    if loaded_files > 0 {
        manager.data.version = latest_version.clone();
        manager.data.updated_at = latest_updated_at.clone();
        manager.save_to_file()?;
        
        total_hashes = manager.get_hash_count();
        println!("[Whitelist] - Total loaded {} files, {} hashes, latest version {}", 
            loaded_files, total_hashes, latest_version);
        
        // 更新规则库信息文件
        update_rules_info(&latest_version, &latest_updated_at, loaded_files, total_hashes)?;
    }
    
    Ok((total_hashes, latest_version, loaded_files))
}

/// 从程序所在目录的 Driver 文件夹复制内置规则文件到用户数据目录
/// 安装包自带的规则文件放在此目录，安装后自动复制到 %LOCALAPPDATA%/XIGUASecurity/rules/
/// 然后由 scan_and_load_rules() 统一加载
/// 返回: 复制的文件数量
pub fn copy_rules_from_driver_folder() -> usize {
    let local_app_data = match std::env::var("LOCALAPPDATA") {
        Ok(val) => val,
        Err(_) => {
            println!("[Whitelist] - Cannot get LOCALAPPDATA");
            return 0;
        }
    };
    let target_dir = std::path::PathBuf::from(&local_app_data)
        .join("XIGUASecurity")
        .join("rules");
    
    // 从 exe 路径开始向上搜索最多 5 层父目录来找 Driver 文件夹
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return 0,
    };
    
    let mut current_dir = exe_path.parent();
    let mut driver_dir = None;
    
    for _ in 0..5 {
        if let Some(dir) = current_dir {
            let test_path = dir.join("Driver");
            if test_path.exists() && test_path.is_dir() {
                driver_dir = Some(test_path);
                break;
            }
            current_dir = dir.parent();
        } else {
            break;
        }
    }
    
    let driver_dir = match driver_dir {
        Some(dir) => dir,
        None => {
            println!("[Whitelist] - Driver directory not found (searched 5 levels from exe)");
            return 0;
        }
    };
    
    // 确保目标目录存在
    if let Err(e) = fs::create_dir_all(&target_dir) {
        println!("[Whitelist] - Failed to create rules directory: {}", e);
        return 0;
    }
    
    // 收集 Driver 目录下的 whitelist_v*.json 文件
    let mut copied_count = 0;
    
    if let Ok(entries) = fs::read_dir(&driver_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "json") {
                let filename = match path.file_name().and_then(|s| s.to_str()) {
                    Some(name) => name.to_string(),
                    None => continue,
                };
                // 只复制 whitelist_v 开头的规则文件
                if filename.starts_with("whitelist_v") {
                    let dest = target_dir.join(&filename);
                    // 如果目标已存在且相同版本则跳过（比较文件名即可，因为版本在文件名中）
                    if dest.exists() {
                        println!("[Whitelist] - Rule file already exists, skipping: {}", filename);
                        continue;
                    }
                    match fs::copy(&path, &dest) {
                        Ok(_) => {
                            copied_count += 1;
                            println!("[Whitelist] - Copied built-in rule: {} -> {:?}", filename, dest);
                        }
                        Err(e) => {
                            println!("[Whitelist] - Failed to copy {}: {}", filename, e);
                        }
                    }
                }
            }
        }
    }
    
    if copied_count > 0 {
        println!("[Whitelist] - Copied {} built-in rule files from Driver to rules directory", copied_count);
    } else {
        println!("[Whitelist] - No new rule files to copy from Driver");
    }
    
    copied_count
}

/// 更新规则库信息文件
fn update_rules_info(version: &str, updated_at: &str, file_count: usize, hash_count: usize) -> Result<(), String> {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_dir = std::path::PathBuf::from(&local_app_data).join("XIGUASecurity");
    
    std::fs::create_dir_all(&config_dir)
        .map_err(|e| format!("Failed to create config dir: {}", e))?;
    
    let info_path = config_dir.join("rules_info.json");
    
    let info = serde_json::json!({
        "version": version,
        "updated_at": updated_at,
        "last_check": chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        "file_count": file_count,
        "hash_count": hash_count,
    });
    
    let content = serde_json::to_string_pretty(&info)
        .map_err(|e| format!("Failed to serialize rules info: {}", e))?;
    
    std::fs::write(&info_path, content)
        .map_err(|e| format!("Failed to write rules info: {}", e))?;
    
    println!("[Whitelist] - Updated rules info: version={}, updated_at={}, files={}, hashes={}", version, updated_at, file_count, hash_count);
    Ok(())
}

/// 比较版本号
fn is_newer_version(new: &str, current: &str) -> bool {
    let new_parts: Vec<u32> = new.split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    let current_parts: Vec<u32> = current.split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    
    for i in 0..new_parts.len().max(current_parts.len()) {
        let new_val = new_parts.get(i).copied().unwrap_or(0);
        let current_val = current_parts.get(i).copied().unwrap_or(0);
        
        if new_val > current_val {
            return true;
        } else if new_val < current_val {
            return false;
        }
    }
    
    false
}
