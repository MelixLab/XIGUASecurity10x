use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};
use lazy_static::lazy_static;
use std::sync::Mutex;

/// 黑规则库数据结构（与白名单结构一致，便于共用服务端和管理页面）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistData {
    pub version: String,
    pub updated_at: String,
    pub description: String,
    pub file_hashes: Vec<String>,
    pub file_names: Vec<String>,
    pub file_paths: Vec<String>,
}

impl Default for BlacklistData {
    fn default() -> Self {
        Self {
            version: "1.0.0".to_string(),
            updated_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            description: "XIGUASecurity Hash Blacklist".to_string(),
            file_hashes: Vec::new(),
            file_names: Vec::new(),
            file_paths: Vec::new(),
        }
    }
}

/// 黑规则库管理器
pub struct BlacklistManager {
    data: BlacklistData,
    hash_map: HashMap<String, String>, // hash -> family/描述
    name_set: HashSet<String>,
    path_set: HashSet<String>,
}

impl BlacklistManager {
    pub fn new() -> Self {
        let mut manager = Self {
            data: BlacklistData::default(),
            hash_map: HashMap::new(),
            name_set: HashSet::new(),
            path_set: HashSet::new(),
        };
        manager.load_from_file();
        manager
    }

    /// 从用户数据目录加载黑规则库
    pub fn load_from_file(&mut self) -> bool {
        let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "".to_string());
        if local_app_data.is_empty() {
            return false;
        }
        let blacklist_path = format!("{}/XIGUASecurity/blacklist.json", local_app_data);

        if !Path::new(&blacklist_path).exists() {
            println!("[Blacklist] - No blacklist file found at: {}", blacklist_path);
            return false;
        }

        match fs::read_to_string(&blacklist_path) {
            Ok(content) => {
                match serde_json::from_str::<BlacklistData>(&content) {
                    Ok(data) => {
                        self.update_data(data);
                        println!("[Blacklist] - Loaded {} hashes and {} filenames",
                            self.hash_map.len(), self.name_set.len());
                        true
                    }
                    Err(e) => {
                        println!("[Blacklist] - Failed to parse blacklist: {}", e);
                        false
                    }
                }
            }
            Err(e) => {
                println!("[Blacklist] - Failed to read blacklist file: {}", e);
                false
            }
        }
    }

    /// 保存黑规则库到文件
    pub fn save_to_file(&self) -> Result<(), String> {
        let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
        let config_dir = format!("{}/XIGUASecurity", local_app_data);

        fs::create_dir_all(&config_dir)
            .map_err(|e| format!("Failed to create config dir: {}", e))?;

        let blacklist_path = format!("{}/blacklist.json", config_dir);
        let content = serde_json::to_string_pretty(&self.data)
            .map_err(|e| format!("Failed to serialize blacklist: {}", e))?;

        fs::write(&blacklist_path, content)
            .map_err(|e| format!("Failed to write blacklist file: {}", e))?;

        Ok(())
    }

    /// 覆盖更新黑规则库数据
    pub fn update_data(&mut self, data: BlacklistData) {
        self.data = data.clone();
        // 哈希黑名单支持附带 family/描述，格式 "<hash>[:<family>]"
        self.hash_map = data.file_hashes.iter()
            .map(|s| {
                let upper = s.to_uppercase();
                if let Some((hash, family)) = upper.split_once(':') {
                    (hash.to_string(), family.trim().to_string())
                } else {
                    (upper.clone(), "Blacklisted".to_string())
                }
            })
            .collect();
        self.name_set = data.file_names.iter().map(|s| s.to_lowercase()).collect();
        self.path_set = data.file_paths.iter().map(|s| s.to_lowercase()).collect();
    }

    /// 检查哈希是否在黑名单中，返回 family/描述
    pub fn contains_hash(&self, hash: &str) -> Option<String> {
        self.hash_map.get(&hash.to_uppercase()).cloned()
    }

    /// 检查文件名是否在黑名单中
    pub fn contains_name(&self, name: &str) -> bool {
        self.name_set.contains(&name.to_lowercase())
    }

    /// 检查路径是否在黑名单中（前缀匹配）
    pub fn contains_path(&self, path: &str) -> bool {
        let lower = path.to_lowercase().replace('/', "\\");
        self.path_set.iter().any(|p| lower.starts_with(p.as_str()) || lower == p.as_str())
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
        self.hash_map.len()
    }

    /// 添加哈希到黑名单（支持 "hash[:family]" 格式）
    pub fn add_hash(&mut self, hash: String) {
        let upper = hash.to_uppercase();
        if let Some((h, family)) = upper.split_once(':') {
            let h = h.to_string();
            if !self.hash_map.contains_key(&h) {
                self.hash_map.insert(h.clone(), family.trim().to_string());
                self.data.file_hashes.push(format!("{}:{}", h, family.trim()));
            }
        } else {
            if !self.hash_map.contains_key(&upper) {
                self.hash_map.insert(upper.clone(), "Blacklisted".to_string());
                self.data.file_hashes.push(upper);
            }
        }
    }

    /// 添加文件名到黑名单
    pub fn add_name(&mut self, name: String) {
        let lower = name.to_lowercase();
        if !self.name_set.contains(&lower) {
            self.name_set.insert(lower.clone());
            self.data.file_names.push(lower);
        }
    }

    /// 添加路径到黑名单（前缀匹配）
    pub fn add_path(&mut self, path: String) {
        let normalised = path.to_lowercase().replace('/', "\\").trim_end_matches('\\').to_string();
        if !self.path_set.contains(&normalised) {
            self.path_set.insert(normalised.clone());
            self.data.file_paths.push(normalised);
        }
    }

    /// 从黑名单移除路径
    pub fn remove_path(&mut self, path: &str) -> bool {
        let normalised = path.to_lowercase().replace('/', "\\").trim_end_matches('\\').to_string();
        if self.path_set.remove(&normalised) {
            self.data.file_paths.retain(|p| p.to_lowercase() != normalised);
            true
        } else {
            false
        }
    }

    /// 获取所有黑名单路径
    pub fn get_paths(&self) -> Vec<String> {
        self.data.file_paths.clone()
    }

    /// 获取黑名单数据
    pub fn get_data(&self) -> &BlacklistData {
        &self.data
    }
}

// 全局黑规则库管理器实例
lazy_static! {
    static ref BLACKLIST_MANAGER: Mutex<BlacklistManager> = Mutex::new(BlacklistManager::new());
}

/// 获取全局黑规则库管理器
pub fn get_blacklist_manager() -> std::sync::MutexGuard<'static, BlacklistManager> {
    BLACKLIST_MANAGER.lock().unwrap()
}

/// 重新加载黑规则库
pub fn reload_blacklist() -> bool {
    get_blacklist_manager().load_from_file()
}

/// 检查哈希是否在黑名单中
pub fn is_hash_blacklisted(hash: &str) -> Option<String> {
    match crate::rules_db::lookup_hash(hash) {
        crate::rules_db::HashLookupResult::Blacklisted { family, .. } => Some(family),
        _ => get_blacklist_manager().contains_hash(hash),
    }
}

/// 检查文件名是否在黑名单中
pub fn is_name_blacklisted(name: &str) -> bool {
    match crate::rules_db::lookup_file_name(name) {
        Some(list_type) if list_type == "blacklist" => true,
        _ => get_blacklist_manager().contains_name(name),
    }
}

/// 检查路径是否在黑名单中
pub fn is_path_blacklisted(path: &str) -> bool {
    match crate::rules_db::lookup_file_path(path) {
        Some(list_type) if list_type == "blacklist" => true,
        _ => get_blacklist_manager().contains_path(path),
    }
}

// ========== 路径黑名单（用户管理） ==========

/// 添加路径到黑名单（持久化保存）
pub fn add_blacklist_path(path: String) -> Result<(), String> {
    let mut mgr = get_blacklist_manager();
    mgr.add_path(path);
    mgr.save_to_file()
}

/// 从黑名单移除路径（持久化保存）
pub fn remove_blacklist_path(path: &str) -> Result<(), String> {
    let mut mgr = get_blacklist_manager();
    mgr.remove_path(path);
    mgr.save_to_file()
}

/// 获取所有黑名单路径
pub fn get_blacklist_paths() -> Vec<String> {
    get_blacklist_manager().get_paths()
}
