"""
database_manager.py - SQLite Database Manager
================================================
Manages all persistence for monitoring events, alerts, processes,
services, and startup entries using SQLite3.

Author: Security Research Team
Version: 1.0.0
"""

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from modules.logger import get_logger

logger = get_logger("database_manager")

DB_PATH = "database/monitoring.db"


class DatabaseManager:
    """
    Thread-safe SQLite database manager for the monitoring agent.
    Handles schema creation, data insertion, and querying.
    """

    def __init__(self, db_path: str = DB_PATH) -> None:
        """
        Initialize the database manager.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        self._lock = threading.Lock()
        self._ensure_db_directory()
        self._conn: Optional[sqlite3.Connection] = None
        self._connect()
        self._create_tables()
        logger.info(f"DatabaseManager initialized: {db_path}")

    def _ensure_db_directory(self) -> None:
        """Ensure the database directory exists."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> None:
        """Establish a persistent SQLite connection with WAL mode."""
        try:
            self._conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=30.0,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.commit()
            logger.info("SQLite connection established with WAL mode.")
        except sqlite3.Error as e:
            logger.critical(f"Failed to connect to database: {e}")
            raise

    def _create_tables(self) -> None:
        """Create all required database tables if they don't already exist."""
        ddl_statements = [
            # Processes table
            """
            CREATE TABLE IF NOT EXISTS processes (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time       TEXT    NOT NULL,
                pid             INTEGER NOT NULL,
                name            TEXT,
                exe_path        TEXT,
                cmdline         TEXT,
                username        TEXT,
                status          TEXT,
                parent_pid      INTEGER,
                parent_name     TEXT,
                cpu_percent     REAL,
                memory_mb       REAL,
                create_time     TEXT,
                is_signed       INTEGER DEFAULT 0,
                sign_status     TEXT,
                is_suspicious   INTEGER DEFAULT 0,
                flags           TEXT
            )
            """,
            # Services table
            """
            CREATE TABLE IF NOT EXISTS services (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time       TEXT    NOT NULL,
                name            TEXT    NOT NULL,
                display_name    TEXT,
                status          TEXT,
                start_type      TEXT,
                exe_path        TEXT,
                account         TEXT,
                description     TEXT,
                is_suspicious   INTEGER DEFAULT 0,
                flags           TEXT
            )
            """,
            # Alerts table
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT    NOT NULL,
                severity        TEXT    NOT NULL,
                category        TEXT,
                process_name    TEXT,
                pid             INTEGER,
                exe_path        TEXT,
                rule_id         TEXT,
                reason          TEXT,
                recommendation  TEXT,
                mitre_technique TEXT,
                details         TEXT,
                acknowledged    INTEGER DEFAULT 0
            )
            """,
            # Startup entries table
            """
            CREATE TABLE IF NOT EXISTS startup_entries (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time       TEXT    NOT NULL,
                name            TEXT,
                location        TEXT,
                command         TEXT,
                source          TEXT,
                is_new          INTEGER DEFAULT 0,
                is_suspicious   INTEGER DEFAULT 0,
                flags           TEXT
            )
            """,
            # Scan sessions table
            """
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id      TEXT    UNIQUE NOT NULL,
                start_time      TEXT    NOT NULL,
                end_time        TEXT,
                scan_type       TEXT,
                total_processes INTEGER DEFAULT 0,
                total_services  INTEGER DEFAULT 0,
                total_alerts    INTEGER DEFAULT 0,
                status          TEXT    DEFAULT 'running'
            )
            """,
            # System health snapshots
            """
            CREATE TABLE IF NOT EXISTS system_health (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT    NOT NULL,
                cpu_percent     REAL,
                memory_percent  REAL,
                disk_percent    REAL,
                process_count   INTEGER,
                service_count   INTEGER,
                alert_count     INTEGER
            )
            """,
        ]
        try:
            with self._lock:
                cursor = self._conn.cursor()
                for stmt in ddl_statements:
                    cursor.execute(stmt)
                self._conn.commit()
            logger.info("All database tables verified/created.")
        except sqlite3.Error as e:
            logger.error(f"Table creation failed: {e}")
            raise

    # ------------------------------------------------------------------
    # Process Operations
    # ------------------------------------------------------------------

    def insert_process(self, proc_data: dict) -> int:
        """
        Insert a process snapshot record.

        Args:
            proc_data: Dictionary with process attributes.

        Returns:
            Row ID of the inserted record.
        """
        sql = """
            INSERT INTO processes
            (scan_time, pid, name, exe_path, cmdline, username, status,
             parent_pid, parent_name, cpu_percent, memory_mb, create_time,
             is_signed, sign_status, is_suspicious, flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            proc_data.get("scan_time", datetime.now().isoformat()),
            proc_data.get("pid"),
            proc_data.get("name"),
            proc_data.get("exe_path"),
            proc_data.get("cmdline"),
            proc_data.get("username"),
            proc_data.get("status"),
            proc_data.get("parent_pid"),
            proc_data.get("parent_name"),
            proc_data.get("cpu_percent"),
            proc_data.get("memory_mb"),
            proc_data.get("create_time"),
            1 if proc_data.get("is_signed") else 0,
            proc_data.get("sign_status"),
            1 if proc_data.get("is_suspicious") else 0,
            json.dumps(proc_data.get("flags", [])),
        )
        return self._execute_insert(sql, params)

    def get_recent_processes(self, limit: int = 500) -> list[dict]:
        """
        Retrieve the most recently scanned processes.

        Args:
            limit: Maximum number of records to return.

        Returns:
            List of process record dicts.
        """
        sql = "SELECT * FROM processes ORDER BY id DESC LIMIT ?"
        return self._fetch_all(sql, (limit,))

    # ------------------------------------------------------------------
    # Service Operations
    # ------------------------------------------------------------------

    def insert_service(self, svc_data: dict) -> int:
        """
        Insert a service snapshot record.

        Args:
            svc_data: Dictionary with service attributes.

        Returns:
            Row ID of the inserted record.
        """
        sql = """
            INSERT INTO services
            (scan_time, name, display_name, status, start_type, exe_path,
             account, description, is_suspicious, flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            svc_data.get("scan_time", datetime.now().isoformat()),
            svc_data.get("name"),
            svc_data.get("display_name"),
            svc_data.get("status"),
            svc_data.get("start_type"),
            svc_data.get("exe_path"),
            svc_data.get("account"),
            svc_data.get("description"),
            1 if svc_data.get("is_suspicious") else 0,
            json.dumps(svc_data.get("flags", [])),
        )
        return self._execute_insert(sql, params)

    def get_recent_services(self, limit: int = 500) -> list[dict]:
        """
        Retrieve recently scanned services.

        Args:
            limit: Maximum number of records.

        Returns:
            List of service record dicts.
        """
        sql = "SELECT * FROM services ORDER BY id DESC LIMIT ?"
        return self._fetch_all(sql, (limit,))

    # ------------------------------------------------------------------
    # Alert Operations
    # ------------------------------------------------------------------

    def insert_alert(self, alert_data: dict) -> int:
        """
        Insert a security alert record.

        Args:
            alert_data: Dictionary with alert attributes.

        Returns:
            Row ID of the inserted record.
        """
        sql = """
            INSERT INTO alerts
            (timestamp, severity, category, process_name, pid, exe_path,
             rule_id, reason, recommendation, mitre_technique, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            alert_data.get("timestamp", datetime.now().isoformat()),
            alert_data.get("severity", "Low"),
            alert_data.get("category"),
            alert_data.get("process_name"),
            alert_data.get("pid"),
            alert_data.get("exe_path"),
            alert_data.get("rule_id"),
            alert_data.get("reason"),
            alert_data.get("recommendation"),
            alert_data.get("mitre_technique"),
            json.dumps(alert_data.get("details", {})),
        )
        return self._execute_insert(sql, params)

    def get_all_alerts(self, severity: Optional[str] = None, limit: int = 1000) -> list[dict]:
        """
        Retrieve alerts, optionally filtered by severity.

        Args:
            severity: Optional severity filter (Critical/High/Medium/Low).
            limit: Maximum records.

        Returns:
            List of alert record dicts.
        """
        if severity:
            sql = "SELECT * FROM alerts WHERE severity=? ORDER BY id DESC LIMIT ?"
            return self._fetch_all(sql, (severity, limit))
        sql = "SELECT * FROM alerts ORDER BY id DESC LIMIT ?"
        return self._fetch_all(sql, (limit,))

    def get_alert_summary(self) -> dict:
        """
        Compute a count summary of alerts by severity.

        Returns:
            Dictionary with counts per severity level.
        """
        sql = "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity"
        rows = self._fetch_all(sql)
        summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Total": 0}
        for row in rows:
            sev = row.get("severity", "Low")
            count = row.get("count", 0)
            if sev in summary:
                summary[sev] = count
            summary["Total"] += count
        return summary

    def acknowledge_alert(self, alert_id: int) -> None:
        """
        Mark an alert as acknowledged.

        Args:
            alert_id: The alert record ID to acknowledge.
        """
        sql = "UPDATE alerts SET acknowledged=1 WHERE id=?"
        self._execute_write(sql, (alert_id,))

    # ------------------------------------------------------------------
    # Startup Entry Operations
    # ------------------------------------------------------------------

    def insert_startup_entry(self, entry: dict) -> int:
        """
        Insert a startup entry record.

        Args:
            entry: Dictionary with startup entry attributes.

        Returns:
            Row ID of inserted record.
        """
        sql = """
            INSERT INTO startup_entries
            (scan_time, name, location, command, source, is_new, is_suspicious, flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            entry.get("scan_time", datetime.now().isoformat()),
            entry.get("name"),
            entry.get("location"),
            entry.get("command"),
            entry.get("source"),
            1 if entry.get("is_new") else 0,
            1 if entry.get("is_suspicious") else 0,
            json.dumps(entry.get("flags", [])),
        )
        return self._execute_insert(sql, params)

    def get_recent_startup_entries(self, limit: int = 200) -> list[dict]:
        """Retrieve recent startup entry scan results."""
        sql = "SELECT * FROM startup_entries ORDER BY id DESC LIMIT ?"
        return self._fetch_all(sql, (limit,))

    # ------------------------------------------------------------------
    # System Health Operations
    # ------------------------------------------------------------------

    def insert_health_snapshot(self, snapshot: dict) -> int:
        """
        Insert a system health snapshot.

        Args:
            snapshot: Health metrics dictionary.

        Returns:
            Row ID of inserted record.
        """
        sql = """
            INSERT INTO system_health
            (timestamp, cpu_percent, memory_percent, disk_percent,
             process_count, service_count, alert_count)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            snapshot.get("timestamp", datetime.now().isoformat()),
            snapshot.get("cpu_percent"),
            snapshot.get("memory_percent"),
            snapshot.get("disk_percent"),
            snapshot.get("process_count"),
            snapshot.get("service_count"),
            snapshot.get("alert_count"),
        )
        return self._execute_insert(sql, params)

    def get_health_history(self, limit: int = 100) -> list[dict]:
        """Retrieve recent system health snapshots."""
        sql = "SELECT * FROM system_health ORDER BY id DESC LIMIT ?"
        return self._fetch_all(sql, (limit,))

    # ------------------------------------------------------------------
    # Scan Session Operations
    # ------------------------------------------------------------------

    def start_scan_session(self, session_id: str, scan_type: str = "Quick") -> None:
        """
        Record a new scan session start.

        Args:
            session_id: Unique session identifier.
            scan_type: Type of scan (Quick / Deep).
        """
        sql = """
            INSERT OR IGNORE INTO scan_sessions
            (session_id, start_time, scan_type, status)
            VALUES (?, ?, ?, 'running')
        """
        self._execute_write(sql, (session_id, datetime.now().isoformat(), scan_type))

    def end_scan_session(self, session_id: str, summary: dict) -> None:
        """
        Update a scan session with completion details.

        Args:
            session_id: Session to complete.
            summary: Summary statistics dictionary.
        """
        sql = """
            UPDATE scan_sessions
            SET end_time=?, total_processes=?, total_services=?,
                total_alerts=?, status='completed'
            WHERE session_id=?
        """
        self._execute_write(sql, (
            datetime.now().isoformat(),
            summary.get("total_processes", 0),
            summary.get("total_services", 0),
            summary.get("total_alerts", 0),
            session_id,
        ))

    # ------------------------------------------------------------------
    # Generic Execute Helpers
    # ------------------------------------------------------------------

    def _execute_insert(self, sql: str, params: tuple) -> int:
        """Execute an INSERT statement and return the last row ID."""
        try:
            with self._lock:
                cursor = self._conn.cursor()
                cursor.execute(sql, params)
                self._conn.commit()
                return cursor.lastrowid or 0
        except sqlite3.Error as e:
            logger.error(f"INSERT failed: {e} | SQL: {sql[:80]}")
            return 0

    def _execute_write(self, sql: str, params: tuple = ()) -> None:
        """Execute an UPDATE/DELETE statement."""
        try:
            with self._lock:
                self._conn.execute(sql, params)
                self._conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Write operation failed: {e}")

    def _fetch_all(self, sql: str, params: tuple = ()) -> list[dict]:
        """Execute a SELECT and return all rows as dicts."""
        try:
            with self._lock:
                cursor = self._conn.execute(sql, params)
                return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"SELECT failed: {e}")
            return []

    def close(self) -> None:
        """Close the database connection gracefully."""
        try:
            if self._conn:
                self._conn.close()
                logger.info("Database connection closed.")
        except Exception as e:
            logger.error(f"Error closing database: {e}")
