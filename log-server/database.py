import sqlite3
import json
import os
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs.db")

@dataclass
class Device:
    device_name: str
    created_at: str
    last_seen: str
    is_online: bool = False

@dataclass
class LogEntry:
    id: int
    device_name: str
    timestamp: str
    category: str
    function: str
    summary: str
    details: Optional[Dict[str, Any]]
    file_path: Optional[str]
    threat_name: Optional[str]
    action: str
    result: str
    received_at: str


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS devices (
                device_name TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS log_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_name TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                category TEXT,
                function TEXT,
                summary TEXT,
                details TEXT,
                file_path TEXT,
                threat_name TEXT,
                action TEXT,
                result TEXT,
                received_at TEXT NOT NULL,
                FOREIGN KEY (device_name) REFERENCES devices(device_name)
            );

            CREATE INDEX IF NOT EXISTS idx_logs_device ON log_entries(device_name);
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON log_entries(timestamp);
        """)
        conn.commit()
    finally:
        conn.close()


def register_device(device_name: str) -> str:
    now = datetime.utcnow().isoformat()
    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO devices (device_name, created_at, last_seen)
               VALUES (?, ?, ?)
               ON CONFLICT(device_name) DO UPDATE SET last_seen=excluded.last_seen""",
            (device_name, now, now),
        )
        conn.commit()
    finally:
        conn.close()
    return device_name


def update_last_seen(device_name: str):
    conn = get_db()
    try:
        conn.execute(
            "UPDATE devices SET last_seen = ? WHERE device_name = ?",
            (datetime.utcnow().isoformat(), device_name),
        )
        conn.commit()
    finally:
        conn.close()


def add_log_entry(device_name: str, entry: Dict[str, Any]) -> int:
    update_last_seen(device_name)
    now = datetime.utcnow().isoformat()
    conn = get_db()
    try:
        cursor = conn.execute(
            """INSERT INTO log_entries
               (device_name, timestamp, category, function, summary, details, file_path, threat_name, action, result, received_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                device_name,
                entry.get("timestamp", now),
                entry.get("category"),
                entry.get("function"),
                entry.get("summary"),
                json.dumps(entry.get("details")) if entry.get("details") is not None else None,
                entry.get("file_path"),
                entry.get("threat_name"),
                entry.get("action"),
                entry.get("result"),
                now,
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def add_log_entries(device_name: str, entries: List[Dict[str, Any]]) -> int:
    if not entries:
        return 0
    update_last_seen(device_name)
    now = datetime.utcnow().isoformat()
    conn = get_db()
    try:
        for entry in entries:
            conn.execute(
                """INSERT INTO log_entries
                   (device_name, timestamp, category, function, summary, details, file_path, threat_name, action, result, received_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    device_name,
                    entry.get("timestamp", now),
                    entry.get("category"),
                    entry.get("function"),
                    entry.get("summary"),
                    json.dumps(entry.get("details")) if entry.get("details") is not None else None,
                    entry.get("file_path"),
                    entry.get("threat_name"),
                    entry.get("action"),
                    entry.get("result"),
                    now,
                ),
            )
        conn.commit()
        return len(entries)
    finally:
        conn.close()


def get_devices(online_threshold_minutes: int = 5) -> List[Device]:
    threshold = (datetime.utcnow() - timedelta(minutes=online_threshold_minutes)).isoformat()
    conn = get_db()
    try:
        rows = conn.execute(
            """SELECT device_name, created_at, last_seen,
                      CASE WHEN last_seen > ? THEN 1 ELSE 0 END AS is_online
               FROM devices
               ORDER BY last_seen DESC""",
            (threshold,),
        ).fetchall()
        return [Device(
            device_name=row["device_name"],
            created_at=row["created_at"],
            last_seen=row["last_seen"],
            is_online=bool(row["is_online"]),
        ) for row in rows]
    finally:
        conn.close()


def get_device(device_name: str) -> Optional[Device]:
    threshold = (datetime.utcnow() - timedelta(minutes=5)).isoformat()
    conn = get_db()
    try:
        row = conn.execute(
            """SELECT device_name, created_at, last_seen,
                      CASE WHEN last_seen > ? THEN 1 ELSE 0 END AS is_online
               FROM devices WHERE device_name = ?""",
            (threshold, device_name),
        ).fetchone()
        if not row:
            return None
        return Device(
            device_name=row["device_name"],
            created_at=row["created_at"],
            last_seen=row["last_seen"],
            is_online=bool(row["is_online"]),
        )
    finally:
        conn.close()


def get_logs(
    device_name: Optional[str] = None,
    category: Optional[str] = None,
    keyword: Optional[str] = None,
    limit: int = 1000,
    offset: int = 0,
) -> List[LogEntry]:
    conn = get_db()
    try:
        query = "SELECT * FROM log_entries WHERE 1=1"
        params: List[Any] = []
        if device_name:
            query += " AND device_name = ?"
            params.append(device_name)
        if category:
            query += " AND category = ?"
            params.append(category)
        if keyword:
            query += " AND (summary LIKE ? OR file_path LIKE ? OR threat_name LIKE ?)"
            params.extend([f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"])
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        return [LogEntry(
            id=row["id"],
            device_name=row["device_name"],
            timestamp=row["timestamp"],
            category=row["category"],
            function=row["function"],
            summary=row["summary"],
            details=json.loads(row["details"]) if row["details"] else None,
            file_path=row["file_path"],
            threat_name=row["threat_name"],
            action=row["action"],
            result=row["result"],
            received_at=row["received_at"],
        ) for row in rows]
    finally:
        conn.close()


def get_log_by_id(log_id: int) -> Optional[LogEntry]:
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM log_entries WHERE id = ?", (log_id,)).fetchone()
        if not row:
            return None
        return LogEntry(
            id=row["id"],
            device_name=row["device_name"],
            timestamp=row["timestamp"],
            category=row["category"],
            function=row["function"],
            summary=row["summary"],
            details=json.loads(row["details"]) if row["details"] else None,
            file_path=row["file_path"],
            threat_name=row["threat_name"],
            action=row["action"],
            result=row["result"],
            received_at=row["received_at"],
        )
    finally:
        conn.close()


def get_stats() -> Dict[str, Any]:
    conn = get_db()
    try:
        total_devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        online_threshold = (datetime.utcnow() - timedelta(minutes=5)).isoformat()
        online_devices = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE last_seen > ?", (online_threshold,)
        ).fetchone()[0]
        total_logs = conn.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]
        today = datetime.utcnow().strftime("%Y-%m-%d")
        today_logs = conn.execute(
            "SELECT COUNT(*) FROM log_entries WHERE date(timestamp) = ?", (today,)
        ).fetchone()[0]
        return {
            "total_devices": total_devices,
            "online_devices": online_devices,
            "total_logs": total_logs,
            "today_logs": today_logs,
        }
    finally:
        conn.close()


def get_categories() -> List[str]:
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT DISTINCT category FROM log_entries WHERE category IS NOT NULL ORDER BY category"
        ).fetchall()
        return [row[0] for row in rows]
    finally:
        conn.close()
