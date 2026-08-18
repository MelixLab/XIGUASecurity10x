import os
import json
import hashlib
import re
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_from_directory, abort

app = Flask(__name__)

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
VERSIONS_DIR = os.path.join(DATA_DIR, "versions")
LATEST_FILE = os.path.join(DATA_DIR, "latest.json")

# 管理后台访问密钥，可通过环境变量覆盖；为空字符串表示不校验
ADMIN_KEY = os.environ.get("RULES_ADMIN_KEY", "xigua_rules_admin")

ALLOWED_FILES = {
    "whitelist.json",
    "blacklist.json",
    "virus_families.json",
}

VERSION_PATTERN = re.compile(r"^\d+(\.\d+)*$")


# ---------------------------------------------------------------------------
# SQLite 规则 DB 构建
# ---------------------------------------------------------------------------
def normalize_rules(data, list_type="blacklist"):
    """统一新旧两种规则格式。
    旧格式：file_hashes / file_names / file_paths 数组
    新格式：type + entries 数组，每个 entry 含 hash/family/file_name/file_path
    """
    if not isinstance(data, dict):
        return {"file_hashes": [], "file_names": [], "file_paths": []}

    # 旧格式直接返回
    if "file_hashes" in data or "file_names" in data or "file_paths" in data:
        return {
            "file_hashes": list(data.get("file_hashes", [])),
            "file_names": list(data.get("file_names", [])),
            "file_paths": list(data.get("file_paths", [])),
        }

    # 新格式：entries 数组
    entries = data.get("entries", [])
    file_hashes = []
    file_names = set()
    file_paths = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        h = entry.get("hash", "")
        if not h:
            continue
        family = entry.get("family", "Blacklisted").strip()
        if family and family != "Blacklisted":
            file_hashes.append(f"{h}:{family}")
        else:
            file_hashes.append(h)
        name = entry.get("file_name", "")
        if name:
            file_names.add(name)
        path = entry.get("file_path", "")
        if path:
            file_paths.add(path)

    return {
        "file_hashes": file_hashes,
        "file_names": list(file_names),
        "file_paths": list(file_paths),
    }


def build_rules_db(version: str) -> str:
    """把当前版本的 JSON 规则合并成一个 SQLite DB，返回 DB 文件路径。"""
    version_dir = os.path.join(VERSIONS_DIR, version)
    db_path = os.path.join(version_dir, "rules.db")

    whitelist = {}
    blacklist = {}
    virus_families = {}

    whitelist_path = os.path.join(version_dir, "whitelist.json")
    blacklist_path = os.path.join(version_dir, "blacklist.json")
    virus_families_path = os.path.join(version_dir, "virus_families.json")

    if os.path.exists(whitelist_path):
        with open(whitelist_path, "r", encoding="utf-8") as f:
            whitelist = json.load(f)
    if os.path.exists(blacklist_path):
        with open(blacklist_path, "r", encoding="utf-8") as f:
            blacklist = json.load(f)
    if os.path.exists(virus_families_path):
        with open(virus_families_path, "r", encoding="utf-8") as f:
            virus_families = json.load(f)

    whitelist = normalize_rules(whitelist, "whitelist")
    blacklist = normalize_rules(blacklist, "blacklist")

    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS whitelist (
            hash TEXT PRIMARY KEY
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            hash TEXT PRIMARY KEY,
            family TEXT,
            description TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS file_names (
            name TEXT PRIMARY KEY,
            list_type TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS file_paths (
            path TEXT PRIMARY KEY,
            list_type TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS virus_families (
            family TEXT PRIMARY KEY,
            data TEXT
        )
    """)

    c.execute("DELETE FROM meta")
    c.execute("DELETE FROM whitelist")
    c.execute("DELETE FROM blacklist")
    c.execute("DELETE FROM file_names")
    c.execute("DELETE FROM file_paths")
    c.execute("DELETE FROM virus_families")

    c.execute("INSERT INTO meta (key, value) VALUES (?, ?)", ("version", version))
    c.execute("INSERT INTO meta (key, value) VALUES (?, ?)", ("updated_at", now_str()))
    c.execute("INSERT INTO meta (key, value) VALUES (?, ?)", ("description", whitelist.get("description", "")))

    for h in whitelist.get("file_hashes", []):
        c.execute("INSERT OR IGNORE INTO whitelist (hash) VALUES (?)", (h.upper(),))
    for name in whitelist.get("file_names", []):
        c.execute("INSERT OR IGNORE INTO file_names (name, list_type) VALUES (?, ?)", (name.lower(), "whitelist"))
    for path in whitelist.get("file_paths", []):
        c.execute("INSERT OR IGNORE INTO file_paths (path, list_type) VALUES (?, ?)", (path.lower(), "whitelist"))

    for h in blacklist.get("file_hashes", []):
        s = h
        if ":" in s:
            hash_part, family = s.split(":", 1)
            c.execute(
                "INSERT OR IGNORE INTO blacklist (hash, family, description) VALUES (?, ?, ?)",
                (hash_part.upper(), family.strip(), "Blacklisted")
            )
        else:
            c.execute(
                "INSERT OR IGNORE INTO blacklist (hash, family, description) VALUES (?, ?, ?)",
                (s.upper(), "Blacklisted", "Blacklisted")
            )
    for name in blacklist.get("file_names", []):
        c.execute("INSERT OR IGNORE INTO file_names (name, list_type) VALUES (?, ?)", (name.lower(), "blacklist"))
    for path in blacklist.get("file_paths", []):
        c.execute("INSERT OR IGNORE INTO file_paths (path, list_type) VALUES (?, ?)", (path.lower(), "blacklist"))

    families = virus_families.get("signatures", [])
    if not families and virus_families:
        # 如果没有 signatures，把整个 virus_families 对象作为默认 family 存起来
        c.execute("INSERT INTO virus_families (family, data) VALUES (?, ?)", ("__all__", json.dumps(virus_families, ensure_ascii=False)))
    else:
        for fam in families:
            if isinstance(fam, dict):
                name = fam.get("name") or fam.get("family") or "unknown"
                c.execute("INSERT OR REPLACE INTO virus_families (family, data) VALUES (?, ?)", (name, json.dumps(fam, ensure_ascii=False)))

    conn.commit()
    conn.close()
    return db_path


def ensure_rules_db(version: str) -> str:
    """确保 rules.db 存在；如果不存在或比 JSON 文件旧，则重新生成。"""
    version_dir = os.path.join(VERSIONS_DIR, version)
    db_path = os.path.join(version_dir, "rules.db")

    json_paths = [
        os.path.join(version_dir, "whitelist.json"),
        os.path.join(version_dir, "blacklist.json"),
        os.path.join(version_dir, "virus_families.json"),
    ]

    db_mtime = os.path.getmtime(db_path) if os.path.exists(db_path) else 0
    json_mtime = max((os.path.getmtime(p) for p in json_paths if os.path.exists(p)), default=0)

    if not os.path.exists(db_path) or json_mtime > db_mtime:
        build_rules_db(version)

    return db_path


def ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(VERSIONS_DIR, exist_ok=True)


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def load_latest() -> dict:
    if not os.path.exists(LATEST_FILE):
        return {}
    with open(LATEST_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_latest(info: dict):
    with open(LATEST_FILE, "w", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False, indent=2)


def empty_whitelist(version: str) -> dict:
    return {
        "version": version,
        "updated_at": now_str(),
        "description": "Auto-created empty whitelist",
        "file_hashes": [],
        "file_names": [],
        "file_paths": [],
    }


def empty_blacklist(version: str) -> dict:
    return {
        "version": version,
        "updated_at": now_str(),
        "description": "Auto-created empty blacklist",
        "file_hashes": [],
        "file_names": [],
        "file_paths": [],
    }


def empty_virus_families(version: str) -> dict:
    return {
        "version": version,
        "updated_at": now_str(),
        "description": "Auto-created empty virus family rules",
        "behavior_categories": [],
        "signatures": [],
        "heuristics": [],
    }


def merge_whitelist(prev: dict, new: dict, version: str) -> dict:
    """合并白名单：new 优先，自动去重。"""
    prev_desc = prev.get("description", "")
    new_desc = new.get("description", "")
    prev = normalize_rules(prev, "whitelist")
    new = normalize_rules(new, "whitelist")

    def union_list(a, b):
        seen = set()
        result = []
        for item in a + b:
            u = item.upper() if isinstance(item, str) else item
            if u not in seen:
                seen.add(u)
                result.append(item)
        return result

    return {
        "version": version,
        "updated_at": now_str(),
        "description": new_desc or prev_desc,
        "file_hashes": union_list(prev.get("file_hashes", []), new.get("file_hashes", [])),
        "file_names": union_list(
            [n.lower() for n in prev.get("file_names", [])],
            [n.lower() for n in new.get("file_names", [])]
        ),
        "file_paths": union_list(
            [p.lower() for p in prev.get("file_paths", [])],
            [p.lower() for p in new.get("file_paths", [])]
        ),
    }


def merge_blacklist(prev: dict, new: dict, version: str) -> dict:
    """合并黑名单：new 优先，自动去重；相同 hash 时 new 的 family 覆盖旧的。"""
    prev_desc = prev.get("description", "")
    new_desc = new.get("description", "")
    prev = normalize_rules(prev, "blacklist")
    new = normalize_rules(new, "blacklist")

    def parse_hashes(items):
        d = {}
        for h in items:
            s = h
            if ":" in s:
                hp, fam = s.split(":", 1)
                d[hp.upper()] = fam.strip()
            else:
                d[s.upper()] = "Blacklisted"
        return d

    prev_map = parse_hashes(prev.get("file_hashes", []))
    new_map = parse_hashes(new.get("file_hashes", []))
    # new 覆盖 prev
    merged_map = {**prev_map, **new_map}
    merged_hashes = [f"{k}:{v}" if v and v != "Blacklisted" else k for k, v in merged_map.items()]

    def union_names(a, b):
        seen = set()
        result = []
        for item in a + b:
            u = item.lower() if isinstance(item, str) else item
            if u not in seen:
                seen.add(u)
                result.append(item)
        return result

    return {
        "version": version,
        "updated_at": now_str(),
        "description": new_desc or prev_desc,
        "file_hashes": merged_hashes,
        "file_names": union_names(
            [n.lower() for n in prev.get("file_names", [])],
            [n.lower() for n in new.get("file_names", [])]
        ),
        "file_paths": union_names(
            [p.lower() for p in prev.get("file_paths", [])],
            [p.lower() for p in new.get("file_paths", [])]
        ),
    }


def merge_virus_families(prev: dict, new: dict, version: str) -> dict:
    """合并病毒家族：相同 family 名称时 new 覆盖旧的。"""
    def by_name(sigs):
        d = {}
        for sig in sigs:
            if isinstance(sig, dict):
                name = sig.get("name") or sig.get("family") or "unknown"
                d[name] = sig
        return d

    prev_map = by_name(prev.get("signatures", []))
    new_map = by_name(new.get("signatures", []))
    merged = {**prev_map, **new_map}

    return {
        "version": version,
        "updated_at": now_str(),
        "description": new.get("description") or prev.get("description", ""),
        "behavior_categories": list({json.dumps(c, ensure_ascii=False, sort_keys=True): c for c in
                                      prev.get("behavior_categories", []) + new.get("behavior_categories", [])}.values()),
        "signatures": list(merged.values()),
        "heuristics": list({json.dumps(h, ensure_ascii=False, sort_keys=True): h for h in
                            prev.get("heuristics", []) + new.get("heuristics", [])}.values()),
    }


def write_json(path: str, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def is_newer_version(remote: str, local: str) -> bool:
    """比较版本号，remote 是否比 local 新"""
    r_parts = [int(x) for x in remote.split(".") if x.isdigit()]
    l_parts = [int(x) for x in local.split(".") if x.isdigit()]
    for i in range(max(len(r_parts), len(l_parts))):
        r = r_parts[i] if i < len(r_parts) else 0
        l = l_parts[i] if i < len(l_parts) else 0
        if r > l:
            return True
        if r < l:
            return False
    return False


def build_file_info(version: str, filename: str) -> dict:
    path = os.path.join(VERSIONS_DIR, version, filename)
    if not os.path.exists(path):
        return {"version": version, "url": "", "hash": ""}
    return {
        "version": version,
        "url": f"/api/rules/download/{version}/{filename}",
        "hash": sha256_file(path),
    }


def build_version_info(version: str, description: str = "") -> dict:
    ensure_rules_db(version)
    db_path = os.path.join(VERSIONS_DIR, version, "rules.db")
    return {
        "version": version,
        "updated_at": now_str(),
        "description": description,
        "files": {
            "db": {
                "version": version,
                "url": f"/api/rules/download/{version}/rules.db",
                "hash": sha256_file(db_path) if os.path.exists(db_path) else "",
            },
            # 保留旧字段，兼容旧客户端
            "whitelist": build_file_info(version, "whitelist.json"),
            "blacklist": build_file_info(version, "blacklist.json"),
            "virus_families": build_file_info(version, "virus_families.json"),
        },
    }


def init_default_version():
    """没有任何版本时，自动创建一个空的 1.0.0 版本"""
    if load_latest():
        return
    version = "1.0.0"
    version_dir = os.path.join(VERSIONS_DIR, version)
    os.makedirs(version_dir, exist_ok=True)
    write_json(os.path.join(version_dir, "whitelist.json"), empty_whitelist(version))
    write_json(os.path.join(version_dir, "blacklist.json"), empty_blacklist(version))
    write_json(os.path.join(version_dir, "virus_families.json"), empty_virus_families(version))
    info = build_version_info(version, "Initial empty rule set")
    save_latest(info)


def list_versions() -> list:
    versions = []
    if not os.path.isdir(VERSIONS_DIR):
        return versions
    for name in sorted(os.listdir(VERSIONS_DIR), key=lambda v: [int(x) for x in v.split(".")], reverse=True):
        d = os.path.join(VERSIONS_DIR, name)
        if not os.path.isdir(d):
            continue
        manifest_path = os.path.join(d, "manifest.json")
        description = ""
        updated_at = ""
        files = {}
        for fname in ALLOWED_FILES:
            fpath = os.path.join(d, fname)
            files[fname] = {
                "hash": sha256_file(fpath) if os.path.exists(fpath) else "",
                "size": os.path.getsize(fpath) if os.path.exists(fpath) else 0,
            }
        db_path = os.path.join(d, "rules.db")
        files["rules.db"] = {
            "hash": sha256_file(db_path) if os.path.exists(db_path) else "",
            "size": os.path.getsize(db_path) if os.path.exists(db_path) else 0,
        }
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    m = json.load(f)
                description = m.get("description", "")
                updated_at = m.get("updated_at", "")
            except Exception:
                pass
        versions.append({
            "version": name,
            "description": description,
            "updated_at": updated_at,
            "files": files,
        })
    return versions


# ---------------------------------------------------------------------------
# 启动初始化
# ---------------------------------------------------------------------------
ensure_dirs()
init_default_version()


# ---------------------------------------------------------------------------
# 跨域支持
# ---------------------------------------------------------------------------
@app.after_request
def after_request(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS")
    return response


# ---------------------------------------------------------------------------
# 权限校验（仅后台管理接口需要）
# ---------------------------------------------------------------------------
def check_admin_key():
    if not ADMIN_KEY:
        return None
    key = request.args.get("key") or request.form.get("key") or ""
    if key != ADMIN_KEY:
        return jsonify({"code": 403, "msg": "access denied: invalid or missing admin key"}), 403
    return None


# ---------------------------------------------------------------------------
# API：获取最新版本
# ---------------------------------------------------------------------------
@app.route("/api/rules/latest")
def api_rules_latest():
    info = load_latest()
    if not info:
        return jsonify({"code": 404, "msg": "no rule version available"}), 404
    return jsonify(info)


# ---------------------------------------------------------------------------
# API：获取历史版本
# ---------------------------------------------------------------------------
@app.route("/api/rules/history")
def api_rules_history():
    return jsonify({"code": 200, "versions": list_versions()})


# ---------------------------------------------------------------------------
# API：下载规则文件（支持 DB 和 JSON 两种格式）
# ---------------------------------------------------------------------------
@app.route("/api/rules/download/<version>/<filename>")
def api_rules_download(version, filename):
    if filename == "rules.db":
        ensure_rules_db(version)
    elif filename not in ALLOWED_FILES:
        abort(404)
    if version == "latest":
        info = load_latest()
        if not info:
            abort(404)
        version = info.get("version", "")
    version_dir = os.path.join(VERSIONS_DIR, version)
    if not os.path.isdir(version_dir):
        abort(404)
    return send_from_directory(version_dir, filename, as_attachment=False)


# ---------------------------------------------------------------------------
# API：上传新版本
# ---------------------------------------------------------------------------
@app.route("/api/rules/upload", methods=["POST"])
def api_rules_upload():
    err = check_admin_key()
    if err:
        return err

    version = (request.form.get("version") or "").strip()
    description = (request.form.get("description") or "").strip()

    if not version:
        return jsonify({"code": 400, "msg": "version is required"}), 400
    if not VERSION_PATTERN.match(version):
        return jsonify({"code": 400, "msg": "version must be like x.y.z"}), 400

    version_dir = os.path.join(VERSIONS_DIR, version)
    if os.path.exists(version_dir):
        return jsonify({"code": 409, "msg": f"version {version} already exists"}), 409

    uploaded_any = False
    os.makedirs(version_dir, exist_ok=True)

    for fname in ALLOWED_FILES:
        file = request.files.get(fname)
        if file and file.filename:
            data = file.read()
            # 校验是否是合法 JSON
            try:
                json.loads(data.decode("utf-8"))
            except Exception as e:
                return jsonify({"code": 400, "msg": f"{fname} is not valid JSON: {e}"}), 400
            path = os.path.join(version_dir, fname)
            with open(path, "wb") as f:
                f.write(data)
            uploaded_any = True

    if not uploaded_any:
        os.rmdir(version_dir)
        return jsonify({"code": 400, "msg": "at least one rule JSON file is required"}), 400

    # 对未上传的文件先补空模板
    if not os.path.exists(os.path.join(version_dir, "whitelist.json")):
        write_json(os.path.join(version_dir, "whitelist.json"), empty_whitelist(version))
    if not os.path.exists(os.path.join(version_dir, "blacklist.json")):
        write_json(os.path.join(version_dir, "blacklist.json"), empty_blacklist(version))
    if not os.path.exists(os.path.join(version_dir, "virus_families.json")):
        write_json(os.path.join(version_dir, "virus_families.json"), empty_virus_families(version))

    # 增量合并：与上一最新版本合并，新数据优先，自动去重（仅当新版本比当前最新版新时）
    latest = load_latest()
    latest_version = latest.get("version", "0.0.0")
    if latest_version != "0.0.0" and latest_version != version and is_newer_version(version, latest_version):
        prev_dir = os.path.join(VERSIONS_DIR, latest_version)
        if os.path.isdir(prev_dir):
            try:
                with open(os.path.join(prev_dir, "whitelist.json"), "r", encoding="utf-8") as f:
                    prev_whitelist = json.load(f)
                with open(os.path.join(prev_dir, "blacklist.json"), "r", encoding="utf-8") as f:
                    prev_blacklist = json.load(f)
                with open(os.path.join(prev_dir, "virus_families.json"), "r", encoding="utf-8") as f:
                    prev_families = json.load(f)

                with open(os.path.join(version_dir, "whitelist.json"), "r", encoding="utf-8") as f:
                    new_whitelist = json.load(f)
                with open(os.path.join(version_dir, "blacklist.json"), "r", encoding="utf-8") as f:
                    new_blacklist = json.load(f)
                with open(os.path.join(version_dir, "virus_families.json"), "r", encoding="utf-8") as f:
                    new_families = json.load(f)

                merged_whitelist = merge_whitelist(prev_whitelist, new_whitelist, version)
                merged_blacklist = merge_blacklist(prev_blacklist, new_blacklist, version)
                merged_families = merge_virus_families(prev_families, new_families, version)

                write_json(os.path.join(version_dir, "whitelist.json"), merged_whitelist)
                write_json(os.path.join(version_dir, "blacklist.json"), merged_blacklist)
                write_json(os.path.join(version_dir, "virus_families.json"), merged_families)
                print(f"[Upload] Merged version {latest_version} into {version}")
            except Exception as e:
                print(f"[Upload] Merge failed: {e}")

    # 写入版本描述清单
    manifest = {
        "version": version,
        "description": description,
        "updated_at": now_str(),
    }
    write_json(os.path.join(version_dir, "manifest.json"), manifest)

    # 如果比当前最新版本新，则更新 latest.json
    latest = load_latest()
    latest_version = latest.get("version", "0.0.0")
    if is_newer_version(version, latest_version):
        info = build_version_info(version, description)
        save_latest(info)

    return jsonify({"code": 200, "msg": "uploaded", "version": version})


# ---------------------------------------------------------------------------
# API：切换最新版本
# ---------------------------------------------------------------------------
@app.route("/api/rules/set_latest", methods=["POST"])
def api_rules_set_latest():
    err = check_admin_key()
    if err:
        return err

    version = (request.args.get("version") or request.form.get("version") or "").strip()
    if not version or not os.path.isdir(os.path.join(VERSIONS_DIR, version)):
        return jsonify({"code": 404, "msg": "version not found"}), 404

    description = ""
    manifest_path = os.path.join(VERSIONS_DIR, version, "manifest.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                description = json.load(f).get("description", "")
        except Exception:
            pass

    info = build_version_info(version, description)
    save_latest(info)
    return jsonify({"code": 200, "msg": "ok", "version": version})


# ---------------------------------------------------------------------------
# API：删除版本（不能删除当前最新版本）
# ---------------------------------------------------------------------------
@app.route("/api/rules/delete", methods=["POST"])
def api_rules_delete():
    err = check_admin_key()
    if err:
        return err

    version = (request.args.get("version") or request.form.get("version") or "").strip()
    if not version:
        return jsonify({"code": 400, "msg": "version is required"}), 400

    latest = load_latest()
    if latest.get("version") == version:
        return jsonify({"code": 400, "msg": "cannot delete current latest version"}), 400

    version_dir = os.path.join(VERSIONS_DIR, version)
    if not os.path.isdir(version_dir):
        return jsonify({"code": 404, "msg": "version not found"}), 404

    for fname in os.listdir(version_dir):
        os.remove(os.path.join(version_dir, fname))
    os.rmdir(version_dir)
    return jsonify({"code": 200, "msg": "deleted"})


# ---------------------------------------------------------------------------
# Web 管理面板
# ---------------------------------------------------------------------------
@app.route("/")
def admin_panel():
    err = check_admin_key()
    if err:
        return err
    latest = load_latest()
    versions = list_versions()
    return render_template(
        "index.html",
        latest=latest,
        versions=versions,
        admin_key=ADMIN_KEY,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
