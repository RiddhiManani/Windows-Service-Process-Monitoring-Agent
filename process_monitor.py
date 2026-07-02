"""
process_monitor.py - Real-Time Process Monitor
================================================
Enumerates and analyzes all running Windows processes.
Collects PID, name, path, CPU, memory, user, creation time,
digital signature, and flags suspicious activity.

Author: Security Research Team
Version: 1.0.0
"""

import os
import threading
from datetime import datetime
from typing import Optional

import psutil

from modules.alert_manager import AlertManager
from modules.database_manager import DatabaseManager
from modules.logger import get_logger
from modules.utils import (
    check_digital_signature,
    compute_file_hash,
    format_timestamp,
    get_suspicious_path_reason,
    is_suspicious_path,
    load_json_config,
    safe_proc_attr,
    sanitize_path,
)

logger = get_logger("process_monitor")

WHITELIST_PATH = "config/whitelist.json"
BLACKLIST_PATH = "config/blacklist.json"
DETECTION_RULES_PATH = "config/detection_rules.json"


class ProcessInfo:
    """Data class representing a snapshot of a single running process."""

    def __init__(self) -> None:
        self.pid: int = 0
        self.name: str = "N/A"
        self.exe_path: str = "N/A"
        self.cmdline: str = "N/A"
        self.username: str = "N/A"
        self.status: str = "N/A"
        self.parent_pid: int = 0
        self.parent_name: str = "N/A"
        self.cpu_percent: float = 0.0
        self.memory_mb: float = 0.0
        self.create_time: str = "N/A"
        self.is_signed: bool = False
        self.sign_status: str = "Unknown"
        self.is_suspicious: bool = False
        self.flags: list[str] = []
        self.file_hash: Optional[str] = None
        self.scan_time: str = datetime.now().isoformat()

    def to_dict(self) -> dict:
        """Convert ProcessInfo to a serializable dictionary."""
        return {
            "pid": self.pid,
            "name": self.name,
            "exe_path": self.exe_path,
            "cmdline": self.cmdline,
            "username": self.username,
            "status": self.status,
            "parent_pid": self.parent_pid,
            "parent_name": self.parent_name,
            "cpu_percent": self.cpu_percent,
            "memory_mb": self.memory_mb,
            "create_time": self.create_time,
            "is_signed": self.is_signed,
            "sign_status": self.sign_status,
            "is_suspicious": self.is_suspicious,
            "flags": self.flags,
            "file_hash": self.file_hash,
            "scan_time": self.scan_time,
        }


class ProcessMonitor:
    """
    Real-time Windows process monitoring engine.
    Scans all running processes, applies detection rules,
    checks whitelists/blacklists, and raises alerts.
    """

    def __init__(self, db_manager: DatabaseManager, alert_manager: AlertManager) -> None:
        """
        Initialize the ProcessMonitor.

        Args:
            db_manager: Database persistence layer.
            alert_manager: Alert dispatch engine.
        """
        self._db = db_manager
        self._alerts = alert_manager
        self._lock = threading.Lock()

        # Configuration
        self._whitelist = load_json_config(WHITELIST_PATH)
        self._blacklist = load_json_config(BLACKLIST_PATH)
        self._rules = load_json_config(DETECTION_RULES_PATH)

        self._whitelisted_names: set[str] = {
            n.lower() for n in self._whitelist.get("processes", {}).get("names", [])
        }
        self._blacklisted_names: set[str] = {
            n.lower() for n in self._blacklist.get("processes", {}).get("names", [])
        }
        self._blacklist_keywords: list[str] = [
            k.lower() for k in self._blacklist.get("keywords", [])
        ]
        self._whitelisted_paths: list[str] = [
            p.lower() for p in self._whitelist.get("processes", {}).get("paths", [])
        ]

        # Enable signature checking (optional deep scan feature)
        self._deep_scan: bool = False
        self._cpu_alert_threshold: float = 80.0

        # Cache for already-checked signatures to reduce overhead
        self._sig_cache: dict[str, dict] = {}
        self._hash_cache: dict[str, str] = {}

        # Current process snapshots
        self._current_processes: list[ProcessInfo] = []

        logger.info("ProcessMonitor initialized.")

    def set_deep_scan(self, enabled: bool) -> None:
        """
        Toggle deep scan mode (includes digital signature checks).

        Args:
            enabled: True for deep scan, False for quick scan.
        """
        self._deep_scan = enabled
        logger.info(f"Deep scan mode: {enabled}")

    def reload_config(self) -> None:
        """Reload whitelist, blacklist, and detection rules from disk."""
        self._whitelist = load_json_config(WHITELIST_PATH)
        self._blacklist = load_json_config(BLACKLIST_PATH)
        self._rules = load_json_config(DETECTION_RULES_PATH)
        self._whitelisted_names = {
            n.lower() for n in self._whitelist.get("processes", {}).get("names", [])
        }
        self._blacklisted_names = {
            n.lower() for n in self._blacklist.get("processes", {}).get("names", [])
        }
        logger.info("ProcessMonitor configuration reloaded.")

    def scan_all_processes(self) -> list[ProcessInfo]:
        """
        Enumerate and analyze all currently running processes.

        Returns:
            List of ProcessInfo snapshots for all running processes.
        """
        scan_time = datetime.now().isoformat()
        results: list[ProcessInfo] = []

        for proc in psutil.process_iter(["pid", "name", "status"]):
            try:
                pinfo = self._analyze_process(proc, scan_time)
                if pinfo:
                    results.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                logger.debug(f"Error analyzing process {proc.pid}: {e}")
                continue

        with self._lock:
            self._current_processes = results

        logger.info(f"Process scan complete: {len(results)} processes analyzed.")
        return results

    def _analyze_process(
        self, proc: psutil.Process, scan_time: str
    ) -> Optional[ProcessInfo]:
        """
        Analyze a single process and build its ProcessInfo record.

        Args:
            proc: psutil.Process instance.
            scan_time: ISO timestamp for the scan.

        Returns:
            Populated ProcessInfo or None if process is inaccessible.
        """
        pinfo = ProcessInfo()
        pinfo.scan_time = scan_time

        # Core attributes
        pinfo.pid = safe_proc_attr(proc, "pid", 0)
        pinfo.name = safe_proc_attr(proc, "name", "Unknown")
        pinfo.status = safe_proc_attr(proc, "status", "unknown")

        exe = safe_proc_attr(proc, "exe", None)
        pinfo.exe_path = sanitize_path(exe) if exe else "Access Denied"

        cmdline_list = safe_proc_attr(proc, "cmdline", [])
        pinfo.cmdline = " ".join(cmdline_list) if isinstance(cmdline_list, list) else str(cmdline_list)

        pinfo.username = safe_proc_attr(proc, "username", "N/A")
        pinfo.cpu_percent = safe_proc_attr(proc, "cpu_percent", 0.0) or 0.0

        mem_info = safe_proc_attr(proc, "memory_info", None)
        pinfo.memory_mb = round(mem_info.rss / (1024 * 1024), 2) if mem_info else 0.0

        create_ts = safe_proc_attr(proc, "create_time", None)
        pinfo.create_time = format_timestamp(create_ts) if create_ts else "N/A"

        # Parent process
        ppid = safe_proc_attr(proc, "ppid", 0)
        pinfo.parent_pid = ppid
        try:
            parent = psutil.Process(ppid)
            pinfo.parent_name = safe_proc_attr(parent, "name", "Unknown")
        except Exception:
            pinfo.parent_name = "Unknown"

        # Signature check (in deep scan or for suspicious paths)
        if self._deep_scan and exe and os.path.isfile(exe):
            if exe not in self._sig_cache:
                self._sig_cache[exe] = check_digital_signature(exe)
            sig = self._sig_cache[exe]
            pinfo.is_signed = sig.get("signed", False)
            pinfo.sign_status = sig.get("status", "Unknown")
        elif not self._is_whitelisted_path(pinfo.exe_path):
            pinfo.sign_status = "Not Checked"

        # File hash (deep scan only)
        if self._deep_scan and exe and os.path.isfile(exe):
            if exe not in self._hash_cache:
                self._hash_cache[exe] = compute_file_hash(exe) or "N/A"
            pinfo.file_hash = self._hash_cache[exe]

        # Detection logic
        self._apply_detections(pinfo)

        # Persist to DB
        try:
            self._db.insert_process(pinfo.to_dict())
        except Exception as e:
            logger.debug(f"Failed to save process {pinfo.name} to DB: {e}")

        return pinfo

    def _apply_detections(self, pinfo: ProcessInfo) -> None:
        """
        Apply all detection rules to a ProcessInfo.
        Sets pinfo.is_suspicious and pinfo.flags, and raises alerts.

        Args:
            pinfo: The ProcessInfo to analyze.
        """
        name_lower = pinfo.name.lower()
        path_lower = pinfo.exe_path.lower()

        # 1) Blacklist check
        if name_lower in self._blacklisted_names:
            pinfo.is_suspicious = True
            pinfo.flags.append("BLACKLISTED")
            self._alerts.raise_alert(
                severity="Critical",
                category="Blacklisted Process",
                process_name=pinfo.name,
                pid=pinfo.pid,
                reason=f"Process '{pinfo.name}' is on the blacklist.",
                recommendation="Terminate immediately and investigate. Known malicious tool.",
                exe_path=pinfo.exe_path,
                rule_id="BLACKLIST",
                mitre_technique="T1059",
                details=pinfo.to_dict(),
            )
            return  # Critical - no further checks needed

        # 2) Blacklist keyword check
        for kw in self._blacklist_keywords:
            if kw in name_lower or kw in path_lower:
                pinfo.is_suspicious = True
                pinfo.flags.append(f"BLACKLIST_KEYWORD:{kw}")
                self._alerts.raise_alert(
                    severity="High",
                    category="Suspicious Keyword",
                    process_name=pinfo.name,
                    pid=pinfo.pid,
                    reason=f"Process name/path contains suspicious keyword: '{kw}'.",
                    recommendation="Investigate process origin and purpose.",
                    exe_path=pinfo.exe_path,
                    rule_id="KEYWORD_MATCH",
                    mitre_technique="T1036",
                    details=pinfo.to_dict(),
                )

        # 3) Suspicious path detection
        if pinfo.exe_path not in ("Access Denied", "N/A"):
            path_reason = get_suspicious_path_reason(pinfo.exe_path)
            if path_reason:
                pinfo.is_suspicious = True
                flag = f"SUSPICIOUS_PATH:{path_reason}"
                if flag not in pinfo.flags:
                    pinfo.flags.append(flag)
                    severity = "Critical" if "$recycle" in path_lower else "High"
                    self._alerts.raise_alert(
                        severity=severity,
                        category="Suspicious Path",
                        process_name=pinfo.name,
                        pid=pinfo.pid,
                        reason=path_reason,
                        recommendation="Verify the process and remove if unauthorized.",
                        exe_path=pinfo.exe_path,
                        rule_id="PATH_CHECK",
                        mitre_technique="T1036.005",
                        details=pinfo.to_dict(),
                    )

        # 4) High CPU usage (potential cryptominer)
        if pinfo.cpu_percent and pinfo.cpu_percent > self._cpu_alert_threshold:
            if not self._is_whitelisted(name_lower, path_lower):
                pinfo.flags.append(f"HIGH_CPU:{pinfo.cpu_percent:.1f}%")
                self._alerts.raise_alert(
                    severity="Medium",
                    category="High Resource Usage",
                    process_name=pinfo.name,
                    pid=pinfo.pid,
                    reason=f"CPU usage of {pinfo.cpu_percent:.1f}% exceeds threshold.",
                    recommendation="Investigate for cryptomining or runaway processes.",
                    exe_path=pinfo.exe_path,
                    rule_id="RULE-014",
                    mitre_technique="T1496",
                    details=pinfo.to_dict(),
                )

        # 5) Unsigned process (deep scan only, non-whitelisted)
        if (
            self._deep_scan
            and not pinfo.is_signed
            and pinfo.sign_status not in ("Not Checked", "Unknown", "File not found", "Access Denied")
            and not self._is_whitelisted(name_lower, path_lower)
        ):
            pinfo.flags.append("UNSIGNED")
            self._alerts.raise_alert(
                severity="Medium",
                category="Unsigned Process",
                process_name=pinfo.name,
                pid=pinfo.pid,
                reason="Process executable is not digitally signed.",
                recommendation="Verify the process legitimacy before allowing execution.",
                exe_path=pinfo.exe_path,
                rule_id="RULE-008",
                mitre_technique="T1553.002",
                details=pinfo.to_dict(),
            )

        if pinfo.flags:
            pinfo.is_suspicious = True

    def _is_whitelisted(self, name_lower: str, path_lower: str) -> bool:
        """
        Check if a process is whitelisted by name or path.

        Args:
            name_lower: Lowercase process name.
            path_lower: Lowercase executable path.

        Returns:
            True if whitelisted.
        """
        if name_lower in self._whitelisted_names:
            return True
        return self._is_whitelisted_path(path_lower)

    def _is_whitelisted_path(self, path_lower: str) -> bool:
        """
        Check if a path starts with a whitelisted path prefix.

        Args:
            path_lower: Lowercase file path.

        Returns:
            True if path is whitelisted.
        """
        for wp in self._whitelisted_paths:
            if path_lower.startswith(wp.lower()):
                return True
        return False

    def get_current_processes(self) -> list[ProcessInfo]:
        """Return the most recent process scan results."""
        with self._lock:
            return self._current_processes[:]

    def get_process_by_pid(self, pid: int) -> Optional[ProcessInfo]:
        """
        Find a process in the current scan by PID.

        Args:
            pid: Process ID to search.

        Returns:
            ProcessInfo or None if not found.
        """
        with self._lock:
            for p in self._current_processes:
                if p.pid == pid:
                    return p
        return None

    def get_suspicious_processes(self) -> list[ProcessInfo]:
        """Return only suspicious processes from the current scan."""
        with self._lock:
            return [p for p in self._current_processes if p.is_suspicious]

    def get_process_count(self) -> int:
        """Return the total number of processes in the last scan."""
        with self._lock:
            return len(self._current_processes)
