use rusqlite::{Connection, OptionalExtension, Result as SqliteResult};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// 规则 DB 路径：%LOCALAPPDATA%\XIGUASecurity\rules.db
pub fn rules_db_path() -> PathBuf {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(local_app_data).join("XIGUASecurity").join("rules.db")
}

/// 查询结果：哈希在白名单/黑名单中的命中信息
#[derive(Debug, Clone)]
pub enum HashLookupResult {
    NotFound,
    Whitelisted,
    Blacklisted { family: String, description: String },
}

/// 规则数据库管理器
pub struct RulesDb {
    conn: Connection,
}

impl RulesDb {
    /// 打开指定路径的规则 DB
    pub fn open<P: AsRef<Path>>(path: P) -> SqliteResult<Self> {
        let conn = Connection::open(path)?;
        Ok(Self { conn })
    }

    /// 打开默认路径的规则 DB
    pub fn open_default() -> SqliteResult<Self> {
        let path = rules_db_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        Self::open(path)
    }

    /// 返回 DB 版本元数据
    pub fn version(&self) -> SqliteResult<String> {
        let mut stmt = self.conn.prepare("SELECT value FROM meta WHERE key = 'version'")?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            return Ok(row.get(0)?);
        }
        Ok("0.0.0".to_string())
    }

    /// 查询哈希：先查白名单，再查黑名单
    pub fn lookup_hash(&self, hash: &str) -> SqliteResult<HashLookupResult> {
        let hash_upper = hash.to_uppercase();

        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM whitelist WHERE hash = ?1",
            [&hash_upper],
            |row| row.get(0),
        )?;
        if count > 0 {
            return Ok(HashLookupResult::Whitelisted);
        }

        let row = self.conn.query_row(
            "SELECT family, description FROM blacklist WHERE hash = ?1",
            [&hash_upper],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        ).optional()?;

        if let Some((family, description)) = row {
            return Ok(HashLookupResult::Blacklisted { family, description });
        }

        Ok(HashLookupResult::NotFound)
    }

    /// 按文件名查询是否在白名单/黑名单
    pub fn lookup_file_name(&self, name: &str) -> SqliteResult<Option<String>> {
        let name_lower = name.to_lowercase();
        let row = self.conn.query_row(
            "SELECT list_type FROM file_names WHERE name = ?1",
            [&name_lower],
            |row| row.get::<_, String>(0),
        ).optional()?;
        Ok(row)
    }

    /// 按文件路径查询是否在白名单/黑名单
    pub fn lookup_file_path(&self, path: &str) -> SqliteResult<Option<String>> {
        let path_lower = path.to_lowercase();
        let row = self.conn.query_row(
            "SELECT list_type FROM file_paths WHERE path = ?1",
            [&path_lower],
            |row| row.get::<_, String>(0),
        ).optional()?;
        Ok(row)
    }

    /// 获取病毒家族数据（JSON 字符串）
    pub fn virus_family(&self, family: &str) -> SqliteResult<Option<String>> {
        self.conn.query_row(
            "SELECT data FROM virus_families WHERE family = ?1",
            [family],
            |row| row.get::<_, String>(0),
        ).optional()
    }

    /// 所有病毒家族名称
    pub fn virus_family_names(&self) -> SqliteResult<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT family FROM virus_families")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<SqliteResult<Vec<_>>>()
    }
}

/// 全局规则 DB 句柄（延迟加载）
lazy_static::lazy_static! {
    static ref RULES_DB: Mutex<Option<RulesDb>> = Mutex::new(None);
}

/// 初始化/重新加载全局规则 DB
pub fn reload_rules_db() -> Result<(), String> {
    let path = rules_db_path();
    if !path.exists() {
        return Err(format!("Rules DB not found at {}", path.display()));
    }
    let db = RulesDb::open(&path).map_err(|e| format!("Failed to open rules DB: {}", e))?;
    let mut guard = RULES_DB.lock().unwrap();
    *guard = Some(db);
    println!("[RulesDb] Reloaded rules DB from {}", path.display());
    Ok(())
}

/// 关闭全局规则 DB（更新前需要先释放文件占用）
pub fn close_rules_db() {
    let mut guard = RULES_DB.lock().unwrap();
    if guard.is_some() {
        *guard = None;
        println!("[RulesDb] Closed rules DB");
    }
}

/// 获取全局规则 DB（如果未加载则尝试加载）
pub fn get_rules_db() -> Option<std::sync::MutexGuard<'static, Option<RulesDb>>> {
    {
        let guard = RULES_DB.lock().unwrap();
        if guard.is_some() {
            return Some(guard);
        }
    }
    // 未加载，尝试从默认路径加载
    if rules_db_path().exists() {
        if let Err(e) = reload_rules_db() {
            println!("[RulesDb] Auto-reload failed: {}", e);
        }
    }
    Some(RULES_DB.lock().unwrap())
}

/// 便捷查询：按哈希查询
pub fn lookup_hash(hash: &str) -> HashLookupResult {
    if let Some(guard) = get_rules_db() {
        if let Some(db) = guard.as_ref() {
            return db.lookup_hash(hash).unwrap_or(HashLookupResult::NotFound);
        }
    }
    HashLookupResult::NotFound
}

/// 便捷查询：按文件名查询
pub fn lookup_file_name(name: &str) -> Option<String> {
    if let Some(guard) = get_rules_db() {
        if let Some(db) = guard.as_ref() {
            return db.lookup_file_name(name).unwrap_or(None);
        }
    }
    None
}

/// 便捷查询：按文件路径查询
pub fn lookup_file_path(path: &str) -> Option<String> {
    if let Some(guard) = get_rules_db() {
        if let Some(db) = guard.as_ref() {
            return db.lookup_file_path(path).unwrap_or(None);
        }
    }
    None
}

/// 便捷查询：获取病毒家族数据
pub fn virus_family(family: &str) -> Option<String> {
    if let Some(guard) = get_rules_db() {
        if let Some(db) = guard.as_ref() {
            return db.virus_family(family).unwrap_or(None);
        }
    }
    None
}

/// 把现有 JSON 规则文件迁移到 SQLite DB（用于首次升级）
#[cfg(windows)]
pub fn migrate_from_json() -> Result<(), String> {
    use serde::Deserialize;

    #[derive(Deserialize, Default)]
    struct WhitelistData {
        file_hashes: Vec<String>,
        file_names: Vec<String>,
        file_paths: Vec<String>,
    }

    #[derive(Deserialize, Default)]
    struct BlacklistData {
        file_hashes: Vec<String>,
        file_names: Vec<String>,
        file_paths: Vec<String>,
    }

    #[derive(Deserialize, Default)]
    struct VirusFamiliesData {
        signatures: Vec<serde_json::Value>,
    }

    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    let config_dir = PathBuf::from(&local_app_data).join("XIGUASecurity");
    let rules_dir = config_dir.join("rules");

    let whitelist_path = config_dir.join("whitelist.json");
    let blacklist_path = config_dir.join("blacklist.json");
    let virus_families_path = rules_dir.join("virus_families.json");

    let whitelist: WhitelistData = if whitelist_path.exists() {
        let content = std::fs::read_to_string(&whitelist_path).map_err(|e| e.to_string())?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        WhitelistData::default()
    };

    let blacklist: BlacklistData = if blacklist_path.exists() {
        let content = std::fs::read_to_string(&blacklist_path).map_err(|e| e.to_string())?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        BlacklistData::default()
    };

    let virus_families: VirusFamiliesData = if virus_families_path.exists() {
        let content = std::fs::read_to_string(&virus_families_path).map_err(|e| e.to_string())?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        VirusFamiliesData::default()
    };

    let db_path = rules_db_path();
    if let Some(parent) = db_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut conn = Connection::open(&db_path).map_err(|e| e.to_string())?;

    conn.execute_batch(include_str!("rules_db_schema.sql")).map_err(|e| e.to_string())?;

    let tx = conn.transaction().map_err(|e| e.to_string())?;

    for h in whitelist.file_hashes {
        let _ = tx.execute("INSERT OR IGNORE INTO whitelist (hash) VALUES (?1)", [h.to_uppercase()]);
    }
    for name in whitelist.file_names {
        let _ = tx.execute("INSERT OR IGNORE INTO file_names (name, list_type) VALUES (?1, 'whitelist')", [name.to_lowercase()]);
    }
    for path in whitelist.file_paths {
        let _ = tx.execute("INSERT OR IGNORE INTO file_paths (path, list_type) VALUES (?1, 'whitelist')", [path.to_lowercase()]);
    }

    for h in blacklist.file_hashes {
        let s = h.to_uppercase();
        if let Some((hash, family)) = s.split_once(':') {
            let _ = tx.execute(
                "INSERT OR IGNORE INTO blacklist (hash, family, description) VALUES (?1, ?2, 'Blacklisted')",
                [hash, family.trim()],
            );
        } else {
            let _ = tx.execute(
                "INSERT OR IGNORE INTO blacklist (hash, family, description) VALUES (?1, 'Blacklisted', 'Blacklisted')",
                [s.as_str()],
            );
        }
    }
    for name in blacklist.file_names {
        let _ = tx.execute("INSERT OR IGNORE INTO file_names (name, list_type) VALUES (?1, 'blacklist')", [name.to_lowercase()]);
    }
    for path in blacklist.file_paths {
        let _ = tx.execute("INSERT OR IGNORE INTO file_paths (path, list_type) VALUES (?1, 'blacklist')", [path.to_lowercase()]);
    }

    for fam in virus_families.signatures {
        if let Some(name) = fam.get("name").or_else(|| fam.get("family")).and_then(|v| v.as_str()) {
            let _ = tx.execute(
                "INSERT OR REPLACE INTO virus_families (family, data) VALUES (?1, ?2)",
                [name, &serde_json::to_string(&fam).unwrap_or_default()],
            );
        }
    }

    tx.commit().map_err(|e| e.to_string())?;
    println!("[RulesDb] Migrated JSON rules to SQLite DB at {}", db_path.display());
    Ok(())
}

#[cfg(not(windows))]
pub fn migrate_from_json() -> Result<(), String> {
    Err("migrate_from_json is only implemented on Windows".to_string())
}
