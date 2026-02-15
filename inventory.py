import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager


class InventoryDB:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT UNIQUE,
                    ip_address TEXT,
                    device_type TEXT,
                    last_backup TEXT,
                    last_status TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS backups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    hostname TEXT,
                    command TEXT,
                    config_file TEXT,
                    checksum TEXT,
                    backup_time TEXT DEFAULT CURRENT_TIMESTAMP,
                    status TEXT,
                    error_message TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices(id)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_backups_device_time 
                ON backups(device_id, backup_time DESC)
            """)

    def upsert_device(self, hostname: str, ip_address: str, device_type: str) -> int:
        with self._get_conn() as conn:
            cursor = conn.execute(
                """
                INSERT INTO devices (hostname, ip_address, device_type, last_backup, last_status)
                VALUES (?, ?, ?, datetime('now'), 'success')
                ON CONFLICT(hostname) DO UPDATE SET
                    ip_address = excluded.ip_address,
                    device_type = excluded.device_type,
                    last_backup = datetime('now'),
                    last_status = 'success'
                WHERE hostname = excluded.hostname
            """,
                (hostname, ip_address, device_type),
            )
            return cursor.lastrowid

    def record_backup(
        self,
        hostname: str,
        ip_address: str,
        device_type: str,
        command: str,
        config_file: Path,
        status: str,
        error_message: Optional[str] = None,
    ):
        import hashlib

        checksum = ""
        if config_file.exists():
            with open(config_file, "rb") as f:
                checksum = hashlib.md5(f.read()).hexdigest()

        with self._get_conn() as conn:
            cursor = conn.execute(
                "SELECT id FROM devices WHERE hostname = ?", (hostname,)
            )
            row = cursor.fetchone()
            if row:
                device_id = row["id"]
                conn.execute(
                    """
                    UPDATE devices SET last_backup = datetime('now'), last_status = ?
                    WHERE id = ?
                """,
                    (status, device_id),
                )
            else:
                cursor = conn.execute(
                    """
                    INSERT INTO devices (hostname, ip_address, device_type, last_backup, last_status)
                    VALUES (?, ?, ?, datetime('now'), ?)
                """,
                    (hostname, ip_address, device_type, status),
                )
                device_id = cursor.lastrowid

            conn.execute(
                """
                INSERT INTO backups (device_id, hostname, command, config_file, checksum, status, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    device_id,
                    hostname,
                    command,
                    str(config_file),
                    checksum,
                    status,
                    error_message,
                ),
            )

    def get_device(self, hostname: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            cursor = conn.execute(
                "SELECT * FROM devices WHERE hostname = ?", (hostname,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_all_devices(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cursor = conn.execute("SELECT * FROM devices ORDER BY last_backup DESC")
            return [dict(row) for row in cursor.fetchall()]

    def get_backup_history(
        self, hostname: str, limit: int = 10
    ) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM backups 
                WHERE hostname = ? 
                ORDER BY backup_time DESC 
                LIMIT ?
            """,
                (hostname, limit),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_latest_backup(
        self, hostname: str, command: str = "show running-config"
    ) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM backups 
                WHERE hostname = ? AND command = ?
                ORDER BY backup_time DESC 
                LIMIT 1
            """,
                (hostname, command),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_stats(self) -> Dict[str, Any]:
        with self._get_conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            successful = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE last_status = 'success'"
            ).fetchone()[0]
            failed = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE last_status = 'failed'"
            ).fetchone()[0]
            total_backups = conn.execute("SELECT COUNT(*) FROM backups").fetchone()[0]

            return {
                "total_devices": total,
                "successful": successful,
                "failed": failed,
                "total_backups": total_backups,
            }
