CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS whitelist (
    hash TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS blacklist (
    hash TEXT PRIMARY KEY,
    family TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS file_names (
    name TEXT PRIMARY KEY,
    list_type TEXT
);

CREATE TABLE IF NOT EXISTS file_paths (
    path TEXT PRIMARY KEY,
    list_type TEXT
);

CREATE TABLE IF NOT EXISTS virus_families (
    family TEXT PRIMARY KEY,
    data TEXT
);

CREATE INDEX IF NOT EXISTS idx_whitelist_hash ON whitelist(hash);
CREATE INDEX IF NOT EXISTS idx_blacklist_hash ON blacklist(hash);
CREATE INDEX IF NOT EXISTS idx_file_names_name ON file_names(name);
CREATE INDEX IF NOT EXISTS idx_file_paths_path ON file_paths(path);
CREATE INDEX IF NOT EXISTS idx_virus_families_family ON virus_families(family);

INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '1');
