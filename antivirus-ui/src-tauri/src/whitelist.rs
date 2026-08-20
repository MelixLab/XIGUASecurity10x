//! 用户白名单模块（v2）
//!
//! 防护架构重构后，规则库已迁移至 SQLite（rules_db.rs），
//! 驱动侧不再读取任何白名单文件。本模块仅管理用户级白名单：
//!
//! 1. 进程白名单（进程名 + 完整路径）：驱动发来进程通知时，
//!    主程序在决策链中先校验白名单，命中 → 直接放行。
//! 2. 网页白名单（域名）：netproxy 在拦截前先查域名白名单，
//!    命中 → 直接放行。netproxy 通过 --whitelist 参数读取
//!    user_whitelist.json，并支持按文件修改时间热重载。
//!
//! 数据文件：%LOCALAPPDATA%\XIGUASecurity\user_whitelist.json
//! v1 旧 whitelist.json 的 file_paths 在首次加载时自动迁入用户白名单。

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};
use lazy_static::lazy_static;
use std::sync::Mutex;

/// 用户白名单数据结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistData {
    pub version: String,
    pub updated_at: String,
    pub description: String,
    /// 进程名白名单（如 notepad.exe，匹配任意路径下同名进程）
    #[serde(default)]
    pub processes: Vec<String>,
    /// 路径白名单（如 C:\Tools\xxx.exe，前缀匹配）
    #[serde(default)]
    pub paths: Vec<String>,
    /// 网页域名白名单（如 example.com，匹配域名及其子域）
    #[serde(default)]
    pub domains: Vec<String>,
    /// v1 旧字段：路径白名单（加载时并入 paths，用于迁移）
    #[serde(default)]
    pub file_paths: Vec<String>,
}

impl Default for WhitelistData {
    fn default() -> Self {
        Self {
            version: "2.0.0".to_string(),
            updated_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            description: "XIGUASecurity Whitelist (v2)".to_string(),
            processes: Vec::new(),
            paths: Vec::new(),
            domains: Vec::new(),
            file_paths: Vec::new(),
        }
    }
}

/// 白名单管理器（仅用户白名单；规则库由 rules_db.rs / SQLite 管理）
pub struct WhitelistManager {
    /// 用户白名单数据（processes/paths/domains，持久化到 user_whitelist.json）
    data: WhitelistData,
    /// 进程名白名单集合（小写）
    process_set: HashSet<String>,
    /// 路径白名单集合（小写，归一化 `\`）
    path_set: HashSet<String>,
    /// 域名白名单集合（小写）
    domain_set: HashSet<String>,
}

impl WhitelistManager {
    pub fn new() -> Self {
        let mut manager = Self {
            data: WhitelistData::default(),
            process_set: HashSet::new(),
            path_set: HashSet::new(),
            domain_set: HashSet::new(),
        };
        manager.load_from_file();
        manager
    }

    /// 从文件加载用户白名单（user_whitelist.json）
    /// 若文件不存在且存在 v1 旧 whitelist.json，则迁移其 file_paths 后首次保存
    pub fn load_from_file(&mut self) -> bool {
        let whitelist_path = user_whitelist_path();

        if !Path::new(&whitelist_path).exists() {
            // v1 → v2 迁移：旧 whitelist.json 的用户路径白名单（file_paths）迁入新文件
            let old_path = legacy_whitelist_path();
            if Path::new(&old_path).exists() {
                if let Ok(content) = fs::read_to_string(&old_path) {
                    // 旧 whitelist.json 可能包含规则库字段，用通用 Value 解析只取 file_paths
                    if let Ok(old) = serde_json::from_str::<serde_json::Value>(&content) {
                        let mut migrated = false;
                        if let Some(paths) = old.get("file_paths").and_then(|v| v.as_array()) {
                            for p in paths {
                                if let Some(s) = p.as_str() {
                                    if !s.trim().is_empty() {
                                        self.data.paths.push(s.trim().to_string());
                                        migrated = true;
                                    }
                                }
                            }
                        }
                        if migrated {
                            self.rebuild_sets();
                            let _ = self.save_to_file();
                            println!("[Whitelist] Migrated {} paths from v1 whitelist.json", self.data.paths.len());
                        }
                    }
                }
            }
            println!("[Whitelist] No user whitelist file found at: {}", whitelist_path);
            return false;
        }

        match fs::read_to_string(&whitelist_path) {
            Ok(content) => {
                match serde_json::from_str::<WhitelistData>(&content) {
                    Ok(data) => {
                        self.data = data;
                        self.rebuild_sets();
                        println!(
                            "[Whitelist] Loaded: {} processes, {} paths, {} domains",
                            self.process_set.len(),
                            self.path_set.len(),
                            self.domain_set.len()
                        );
                        true
                    }
                    Err(e) => {
                        println!("[Whitelist] Failed to parse user whitelist: {}", e);
                        false
                    }
                }
            }
            Err(e) => {
                println!("[Whitelist] Failed to read user whitelist file: {}", e);
                false
            }
        }
    }

    /// 根据 data 重建内存集合
    fn rebuild_sets(&mut self) {
        self.process_set = self.data.processes.iter().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect();
        self.path_set = self.data.paths.iter().map(|s| normalize_path(s)).filter(|s| !s.is_empty()).collect();
        self.domain_set = self.data.domains.iter().map(|s| normalize_domain(s)).filter(|s| !s.is_empty()).collect();
    }

    /// 保存用户白名单到文件（user_whitelist.json，仅含进程/路径/域名）
    pub fn save_to_file(&self) -> Result<(), String> {
        let config_dir = config_dir();
        fs::create_dir_all(&config_dir)
            .map_err(|e| format!("Failed to create config dir: {}", e))?;

        let mut user = WhitelistData::default();
        user.processes = self.data.processes.clone();
        user.paths = self.data.paths.clone();
        user.domains = self.data.domains.clone();
        user.updated_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let content = serde_json::to_string_pretty(&user)
            .map_err(|e| format!("Failed to serialize user whitelist: {}", e))?;
        fs::write(user_whitelist_path(), content)
            .map_err(|e| format!("Failed to write user whitelist file: {}", e))?;
        Ok(())
    }

    // ========== 进程名白名单 ==========

    /// 检查进程名是否在白名单中（精确匹配，忽略大小写）
    pub fn contains_process(&self, name: &str) -> bool {
        let lower = name.trim().to_lowercase();
        !lower.is_empty() && self.process_set.contains(&lower)
    }

    /// 添加进程名到白名单
    pub fn add_process(&mut self, name: String) {
        let lower = name.trim().to_lowercase();
        if !lower.is_empty() && !self.process_set.contains(&lower) {
            self.process_set.insert(lower.clone());
            self.data.processes.push(lower);
        }
    }

    /// 从白名单移除进程名
    pub fn remove_process(&mut self, name: &str) -> bool {
        let lower = name.trim().to_lowercase();
        if self.process_set.remove(&lower) {
            self.data.processes.retain(|n| n.trim().to_lowercase() != lower);
            true
        } else {
            false
        }
    }

    /// 获取所有白名单进程名
    pub fn get_processes(&self) -> Vec<String> {
        self.data.processes.clone()
    }

    // ========== 路径白名单 ==========

    /// 检查路径是否在白名单中（前缀匹配，忽略大小写）
    pub fn contains_path(&self, path: &str) -> bool {
        let lower = normalize_path(path);
        if lower.is_empty() {
            return false;
        }
        self.path_set.iter().any(|p| lower.starts_with(p.as_str()) || lower == p.as_str())
    }

    /// 添加路径到白名单
    pub fn add_path(&mut self, path: String) {
        let normalised = normalize_path(&path);
        if !normalised.is_empty() && !self.path_set.contains(&normalised) {
            self.path_set.insert(normalised.clone());
            self.data.paths.push(normalised);
        }
    }

    /// 从白名单移除路径
    pub fn remove_path(&mut self, path: &str) -> bool {
        let normalised = normalize_path(path);
        if self.path_set.remove(&normalised) {
            self.data.paths.retain(|p| normalize_path(p) != normalised);
            true
        } else {
            false
        }
    }

    /// 获取所有白名单路径
    pub fn get_paths(&self) -> Vec<String> {
        self.data.paths.clone()
    }

    // ========== 网页域名白名单 ==========

    /// 检查域名是否在白名单中（精确匹配或子域匹配，如 example.com 命中 www.example.com）
    pub fn contains_domain(&self, host: &str) -> bool {
        let host = normalize_domain(host);
        if host.is_empty() {
            return false;
        }
        self.domain_set
            .iter()
            .any(|d| host == d.as_str() || host.ends_with(&format!(".{}", d)))
    }

    /// 添加域名到白名单
    pub fn add_domain(&mut self, domain: String) {
        let normalised = normalize_domain(&domain);
        if !normalised.is_empty() && !self.domain_set.contains(&normalised) {
            self.domain_set.insert(normalised.clone());
            self.data.domains.push(normalised);
        }
    }

    /// 从白名单移除域名
    pub fn remove_domain(&mut self, domain: &str) -> bool {
        let normalised = normalize_domain(domain);
        if self.domain_set.remove(&normalised) {
            self.data.domains.retain(|d| normalize_domain(d) != normalised);
            true
        } else {
            false
        }
    }

    /// 获取所有白名单域名
    pub fn get_domains(&self) -> Vec<String> {
        self.data.domains.clone()
    }
}

// 全局白名单管理器实例
lazy_static! {
    static ref WHITELIST_MANAGER: Mutex<WhitelistManager> = Mutex::new(WhitelistManager::new());
}

/// 配置目录：%LOCALAPPDATA%\XIGUASecurity
fn config_dir() -> String {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    format!("{}/XIGUASecurity", local_app_data)
}

/// 用户白名单文件：进程/路径/网页域名
fn user_whitelist_path() -> String {
    format!("{}/user_whitelist.json", config_dir())
}

/// v1 旧规则库文件路径（仅用于迁移读取）
fn legacy_whitelist_path() -> String {
    format!("{}/whitelist.json", config_dir())
}

/// 获取全局白名单管理器
pub fn get_whitelist_manager() -> std::sync::MutexGuard<'static, WhitelistManager> {
    WHITELIST_MANAGER.lock().unwrap()
}

/// 重新加载白名单
pub fn reload_whitelist() -> bool {
    get_whitelist_manager().load_from_file()
}

/// 归一化路径：统一分隔符为 `\`、小写、去尾部 `\`
fn normalize_path(path: &str) -> String {
    path.trim()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

/// 归一化域名：小写、去尾部 `.`、去协议与路径部分
fn normalize_domain(domain: &str) -> String {
    let mut d = domain.trim().to_lowercase();
    for scheme in ["https://", "http://"] {
        if let Some(rest) = d.strip_prefix(scheme) {
            d = rest.to_string();
            break;
        }
    }
    d = d.split(['/', '?', '#']).next().unwrap_or(&d).to_string();
    d = d.trim_end_matches('.').to_string();
    d
}

// ========== 检查函数（决策链与扫描器共用） ==========

/// 检查哈希是否在白名单中（规则库 SQLite 查询）
pub fn is_hash_whitelisted(hash: &str) -> bool {
    match crate::rules_db::lookup_hash(hash) {
        crate::rules_db::HashLookupResult::Whitelisted => true,
        crate::rules_db::HashLookupResult::Blacklisted { .. } => false,
        crate::rules_db::HashLookupResult::NotFound => false,
    }
}

/// 检查文件名是否在白名单中（规则库 SQLite 查询）
pub fn is_name_whitelisted(name: &str) -> bool {
    match crate::rules_db::lookup_file_name(name) {
        Some(list_type) if list_type == "whitelist" => true,
        _ => false,
    }
}

/// 检查路径是否在白名单中：
/// 1. 规则库 SQLite 查询；2. 路径白名单前缀匹配；3. 文件名匹配进程名白名单。
/// 进程防护决策链"先行校验白名单"即调用此函数。
pub fn is_path_whitelisted(path: &str) -> bool {
    match crate::rules_db::lookup_file_path(path) {
        Some(list_type) if list_type == "whitelist" => return true,
        _ => {}
    }
    let mgr = get_whitelist_manager();
    if mgr.contains_path(path) {
        return true;
    }
    let file_name = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    mgr.contains_process(file_name)
}

/// 检查进程名是否在白名单中
pub fn is_process_whitelisted(name: &str) -> bool {
    get_whitelist_manager().contains_process(name)
}

/// 检查域名是否在网页白名单中（netproxy 与主程序共用语义）
pub fn is_domain_whitelisted(host: &str) -> bool {
    get_whitelist_manager().contains_domain(host)
}

// ========== 路径白名单（用户管理，持久化） ==========

/// 添加路径到白名单（持久化保存）
pub fn add_whitelist_path(path: String) -> Result<(), String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("路径不能为空".to_string());
    }
    let mut mgr = get_whitelist_manager();
    mgr.add_path(trimmed.to_string());
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

// ========== 进程名白名单（用户管理，持久化） ==========

/// 添加进程名到白名单（持久化保存）
pub fn add_whitelist_process(name: String) -> Result<(), String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("进程名不能为空".to_string());
    }
    if !trimmed.contains('.') {
        return Err("进程名必须包含文件后缀，例如 cmd.exe、taskmgr.exe".to_string());
    }
    let mut mgr = get_whitelist_manager();
    mgr.add_process(trimmed.to_string());
    mgr.save_to_file()
}

/// 从白名单移除进程名（持久化保存）
pub fn remove_whitelist_process(name: &str) -> Result<(), String> {
    let mut mgr = get_whitelist_manager();
    mgr.remove_process(name);
    mgr.save_to_file()
}

/// 获取所有白名单进程名
pub fn get_whitelist_processes() -> Vec<String> {
    get_whitelist_manager().get_processes()
}

// ========== 网页域名白名单（用户管理，持久化，netproxy 热加载） ==========

/// 添加域名到白名单（持久化保存；netproxy 检测到文件变更后自动热加载）
pub fn add_whitelist_domain(domain: String) -> Result<(), String> {
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return Err("域名不能为空".to_string());
    }
    if trimmed.contains('/') && !trimmed.starts_with("http") {
        return Err("请输入域名，例如 example.com，不要包含路径".to_string());
    }
    let mut mgr = get_whitelist_manager();
    mgr.add_domain(trimmed.to_string());
    mgr.save_to_file()
}

/// 从白名单移除域名（持久化保存）
pub fn remove_whitelist_domain(domain: &str) -> Result<(), String> {
    let mut mgr = get_whitelist_manager();
    mgr.remove_domain(domain);
    mgr.save_to_file()
}

/// 获取所有白名单域名
pub fn get_whitelist_domains() -> Vec<String> {
    get_whitelist_manager().get_domains()
}
