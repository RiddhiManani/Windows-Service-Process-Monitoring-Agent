"""
startup_audit.py - Windows Startup Entry Auditor
==================================================
Scans registry Run keys, startup folders, and startup services
to detect new, hidden, or suspicious persistence mechanisms.

Author: Security Research Team
Version: 1.0.0
"""

import os
import threading
import winreg
from datetime import datetime
from pathlib import Path
from typing import Optional

from modules.alert_manager import AlertManager
from modules.database_manager import DatabaseManager
from modules.logger import get_logger
from modules.utils import (
    get_suspicious_path_reason,
    is_suspicious_path,
    load_json_config,
    sanitize_path,
)

logger = get_logger("startup_audit")

# Registry Run key locations
REGISTRY_RUN_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]

# Startup folder paths
STARTUP_FOLDERS = [
    Path(os.environ.get("APPDATA", "")) / "Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData")) / "Microsoft\\Windows\\Start Menu\\Programs\\Startup",
]

HIVE_NAMES = {
    winreg.HKEY_LOCAL_MACHINE: "HKEY_LOCAL_MACHINE",
    winreg.HKEY_CURRENT_USER: "HKEY_CURRENT_USER",
}


class StartupEntry:
    """Data class representing a single startup entry."""

    def __init__(self) -> None:
        self.name: str = "N/A"
        self.command: str = "N/A"
        self.location: str = "N/A"
        self.source: str = "N/A"  # Registry / Startup Folder
        self.is_new: bool = False
        self.is_suspicious: bool = False
        self.flags: list[str] = []
        self.scan_time: str = datetime.now().isoformat()

    def to_dict(self) -> dict:
        """Convert StartupEntry to serializable dict."""
        return {
            "name": self.name,
            "command": self.command,
            "location": self.location,
            "source": self.source,
            "is_new": self.is_new,
            "is_suspicious": self.is_suspicious,
            "flags": self.flags,
            "scan_time": self.scan_time,
        }


class StartupAuditor:
    """
    Audits Windows startup locations for persistence mechanisms.
    Tracks known-good baseline and alerts on new or suspicious entries.
    """

    def __init__(self, db_manager: DatabaseManager, alert_manager: AlertManager) -> None:
        """
        Initialize the StartupAuditor.

        Args:
            db_manager: Database persistence layer.
            alert_manager: Alert dispatch engine.
        """
        self._db = db_manager
        self._alerts = alert_manager
        self._lock = threading.Lock()
        self._whitelist = load_json_config("config/whitelist.json")
        self._baseline: set[str] = set()
        self._current_entries: list[StartupEntry] = []
        self._baseline_loaded = False
        logger.info("StartupAuditor initialized.")

    def _load_baseline(self) -> None:
        """
        Load the known-good startup baseline from the database
        (entries from the first scan of the session).
        """
        try:
            rows = self._db.get_recent_startup_entries(limit=1000)
            if rows:
                self._baseline = {
                    f"{r.get('name','')}__{r.get('command','')}"
                    for r in rows
                }
                logger.info(f"Startup baseline loaded: {len(self._baseline)} known entries.")
            else:
                logger.info("No existing baseline, first scan will establish it.")
        except Exception as e:
            logger.error(f"Failed to load startup baseline: {e}")

    def scan_startup_entries(self) -> list[StartupEntry]:
        """
        Scan all startup locations: registry, startup folders.

        Returns:
            List of StartupEntry snapshots.
        """
        if not self._baseline_loaded:
            self._load_baseline()
            self._baseline_loaded = True

        scan_time = datetime.now().isoformat()
        entries: list[StartupEntry] = []

        # Registry Run keys
        entries.extend(self._scan_registry_run_keys(scan_time))

        # Startup folders
        entries.extend(self._scan_startup_folders(scan_time))

        with self._lock:
            self._current_entries = entries

        # Update baseline after first scan
        if not self._baseline:
            self._baseline = {
                f"{e.name}__{e.command}" for e in entries
            }

        logger.info(f"Startup audit complete: {len(entries)} entries found.")
        return entries

    def _scan_registry_run_keys(self, scan_time: str) -> list[StartupEntry]:
        """
        Enumerate all registry Run and RunOnce keys.

        Args:
            scan_time: Scan timestamp string.

        Returns:
            List of StartupEntry instances from registry.
        """
        entries: list[StartupEntry] = []

        for hive, key_path in REGISTRY_RUN_KEYS:
            hive_name = HIVE_NAMES.get(hive, str(hive))
            full_path = f"{hive_name}\\{key_path}"
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        value_name, value_data, _ = winreg.EnumValue(key, i)
                        i += 1
                        entry = StartupEntry()
                        entry.scan_time = scan_time
                        entry.name = str(value_name)
                        entry.command = sanitize_path(str(value_data))
                        entry.location = full_path
                        entry.source = "Registry"

                        self._apply_detection(entry)
                        entries.append(entry)
                        self._db.insert_startup_entry(entry.to_dict())

                    except OSError:
                        break
                winreg.CloseKey(key)
            except FileNotFoundError:
                pass
            except PermissionError:
                logger.debug(f"Access denied reading registry key: {full_path}")
            except Exception as e:
                logger.error(f"Registry scan error at {full_path}: {e}")

        return entries

    def _scan_startup_folders(self, scan_time: str) -> list[StartupEntry]:
        """
        Enumerate files in Windows startup folders.

        Args:
            scan_time: Scan timestamp.

        Returns:
            List of StartupEntry instances from startup folders.
        """
        entries: list[StartupEntry] = []

        for folder in STARTUP_FOLDERS:
            if not folder.exists():
                continue
            try:
                for item in folder.iterdir():
                    if item.is_file():
                        entry = StartupEntry()
                        entry.scan_time = scan_time
                        entry.name = item.name
                        entry.command = str(item)
                        entry.location = str(folder)
                        entry.source = "Startup Folder"

                        self._apply_detection(entry)
                        entries.append(entry)
                        self._db.insert_startup_entry(entry.to_dict())

            except PermissionError:
                logger.debug(f"Access denied reading startup folder: {folder}")
            except Exception as e:
                logger.error(f"Startup folder scan error: {e}")

        return entries

    def _apply_detection(self, entry: StartupEntry) -> None:
        """
        Apply detection logic to a startup entry.

        Args:
            entry: StartupEntry to analyze.
        """
        key = f"{entry.name}__{entry.command}"

        # New entry detection
        if self._baseline and key not in self._baseline:
            entry.is_new = True
            entry.flags.append("NEW_STARTUP_ENTRY")
            self._alerts.raise_alert(
                severity="High",
                category="Startup Persistence",
                process_name=entry.name,
                pid=0,
                reason=f"New startup entry detected: '{entry.name}' at {entry.location}",
                recommendation="Investigate this entry. It may be a persistence mechanism.",
                exe_path=entry.command,
                rule_id="RULE-010",
                mitre_technique="T1547.001",
                details=entry.to_dict(),
            )

        # Suspicious path in startup command
        path_reason = get_suspicious_path_reason(entry.command)
        if path_reason:
            entry.is_suspicious = True
            entry.flags.append(f"SUSPICIOUS_PATH:{path_reason}")
            self._alerts.raise_alert(
                severity="Critical",
                category="Suspicious Startup Path",
                process_name=entry.name,
                pid=0,
                reason=f"Startup entry points to suspicious location: {path_reason}",
                recommendation="Remove this startup entry and investigate the binary.",
                exe_path=entry.command,
                rule_id="RULE-010",
                mitre_technique="T1547.001",
                details=entry.to_dict(),
            )

        # Encoded PowerShell in startup command
        if any(
            kw in entry.command.lower()
            for kw in ["-enc ", "-encodedcommand", "iex ", "invoke-expression", "downloadstring"]
        ):
            entry.is_suspicious = True
            entry.flags.append("ENCODED_COMMAND")
            self._alerts.raise_alert(
                severity="Critical",
                category="Encoded Startup Command",
                process_name=entry.name,
                pid=0,
                reason="Startup entry contains encoded/obfuscated command.",
                recommendation="Investigate and remove immediately. Likely malware persistence.",
                exe_path=entry.command,
                rule_id="STARTUP_ENCODED",
                mitre_technique="T1059.001",
                details=entry.to_dict(),
            )

        # Script extensions in startup (vbs, ps1, bat, js, hta)
        cmd_lower = entry.command.lower()
        script_exts = [".vbs", ".ps1", ".bat", ".js", ".hta", ".wsf", ".cmd"]
        for ext in script_exts:
            if ext in cmd_lower:
                entry.is_suspicious = True
                entry.flags.append(f"SCRIPT_STARTUP:{ext}")
                self._alerts.raise_alert(
                    severity="Medium",
                    category="Script in Startup",
                    process_name=entry.name,
                    pid=0,
                    reason=f"Startup entry runs a script file ({ext}).",
                    recommendation="Verify this script. Scripts in startup are often used for persistence.",
                    exe_path=entry.command,
                    rule_id="STARTUP_SCRIPT",
                    mitre_technique="T1547.001",
                    details=entry.to_dict(),
                )
                break

        if entry.flags:
            entry.is_suspicious = True

    def get_current_entries(self) -> list[StartupEntry]:
        """Return the most recent startup scan results."""
        with self._lock:
            return self._current_entries[:]

    def get_suspicious_entries(self) -> list[StartupEntry]:
        """Return only suspicious startup entries."""
        with self._lock:
            return [e for e in self._current_entries if e.is_suspicious]

    def get_new_entries(self) -> list[StartupEntry]:
        """Return entries that are new since the baseline."""
        with self._lock:
            return [e for e in self._current_entries if e.is_new]
