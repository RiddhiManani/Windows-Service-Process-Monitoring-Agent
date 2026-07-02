"""
unauthorized_detector.py - Unauthorized Process Detector
==========================================================
Detects unauthorized, unknown, unsigned, or suspicious processes
using whitelist/blacklist enforcement, path-based detection,
and behavior-based heuristics.

Author: Security Research Team
Version: 1.0.0
"""

import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

import psutil

from modules.alert_manager import AlertManager
from modules.database_manager import DatabaseManager
from modules.logger import get_logger
from modules.utils import (
    check_digital_signature,
    compute_file_hash,
    get_suspicious_path_reason,
    load_json_config,
    safe_proc_attr,
    sanitize_path,
)

logger = get_logger("unauthorized_detector")

WHITELIST_PATH = "config/whitelist.json"
BLACKLIST_PATH = "config/blacklist.json"
DETECTION_RULES_PATH = "config/detection_rules.json"

# Paths that are always considered suspicious for execution
UNAUTHORIZED_EXEC_PATHS = [
    "\\temp\\",
    "\\tmp\\",
    "\\downloads\\",
    "\\desktop\\",
    "c:\\users\\public\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\$recycle.bin\\",
    "\\recycler\\",
    "\\programdata\\",
]

# Trusted system directories (processes here are generally safe)
TRUSTED_SYSTEM_PATHS = [
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
]


class UnauthorizedFinding:
    """Represents a detected unauthorized or suspicious process."""

    def __init__(self) -> None:
        self.pid: int = 0
        self.name: str = "N/A"
        self.exe_path: str = "N/A"
        self.username: str = "N/A"
        self.reason: str = "N/A"
        self.severity: str = "Medium"
        self.category: str = "Unauthorized Process"
        self.flags: list[str] = []
        self.file_hash: Optional[str] = None
        self.is_signed: bool = False
        self.sign_status: str = "Unknown"
        self.detection_time: str = datetime.now().isoformat()
        self.mitre_technique: str = "T1036"
        self.recommendation: str = "Investigate the process and terminate if unauthorized."

    def to_dict(self) -> dict:
        """Convert finding to serializable dictionary."""
        return {
            "pid": self.pid,
            "name": self.name,
            "exe_path": self.exe_path,
            "username": self.username,
            "reason": self.reason,
            "severity": self.severity,
            "category": self.category,
            "flags": self.flags,
            "file_hash": self.file_hash,
            "is_signed": self.is_signed,
            "sign_status": self.sign_status,
            "detection_time": self.detection_time,
            "mitre_technique": self.mitre_technique,
            "recommendation": self.recommendation,
        }


class UnauthorizedDetector:
    """
    Detects unauthorized processes using whitelist/blacklist enforcement,
    path-based detection, signature verification, and behavior heuristics.
    """

    def __init__(self, db_manager: DatabaseManager, alert_manager: AlertManager) -> None:
        """
        Initialize the UnauthorizedDetector.

        Args:
            db_manager: Database persistence layer.
            alert_manager: Alert dispatch engine.
        """
        self._db = db_manager
        self._alerts = alert_manager
        self._lock = threading.Lock()

        self._whitelist = load_json_config(WHITELIST_PATH)
        self._blacklist = load_json_config(BLACKLIST_PATH)
        self._rules = load_json_config(DETECTION_RULES_PATH)

        self._whitelisted_names: set[str] = {
            n.lower() for n in self._whitelist.get("processes", {}).get("names", [])
        }
        self._whitelisted_paths: list[str] = [
            p.lower() for p in self._whitelist.get("processes", {}).get("paths", [])
        ]
        self._blacklisted_names: set[str] = {
            n.lower() for n in self._blacklist.get("processes", {}).get("names", [])
        }
        self._blacklisted_hashes: set[str] = {
            h.lower() for h in self._blacklist.get("processes", {}).get("hashes", [])
        }
        self._blacklist_keywords: list[str] = [
            k.lower() for k in self._blacklist.get("keywords", [])
        ]

        # Signature and hash caches to avoid redundant checks
        self._sig_cache: dict[str, dict] = {}
        self._hash_cache: dict[str, str] = {}

        self._current_findings: list[UnauthorizedFinding] = []
        self._deep_scan_mode: bool = False

        logger.info("UnauthorizedDetector initialized.")

    def set_deep_scan(self, enabled: bool) -> None:
        """
        Enable or disable deep scan (includes signature + hash verification).

        Args:
            enabled: True for deep scan.
        """
        self._deep_scan_mode = enabled
        logger.info(f"UnauthorizedDetector deep scan: {enabled}")

    def reload_config(self) -> None:
        """Reload all configuration files from disk."""
        self._whitelist = load_json_config(WHITELIST_PATH)
        self._blacklist = load_json_config(BLACKLIST_PATH)
        self._rules = load_json_config(DETECTION_RULES_PATH)
        self._whitelisted_names = {
            n.lower() for n in self._whitelist.get("processes", {}).get("names", [])
        }
        self._blacklisted_names = {
            n.lower() for n in self._blacklist.get("processes", {}).get("names", [])
        }
        logger.info("UnauthorizedDetector config reloaded.")

    def scan_for_unauthorized(self) -> list[UnauthorizedFinding]:
        """
        Scan all running processes for unauthorized activity.

        Returns:
            List of UnauthorizedFinding instances.
        """
        findings: list[UnauthorizedFinding] = []

        for proc in psutil.process_iter(["pid", "name", "exe", "username"]):
            try:
                finding = self._inspect_process(proc)
                if finding:
                    findings.append(finding)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                logger.debug(f"Inspection error for PID {proc.pid}: {e}")
                continue

        with self._lock:
            self._current_findings = findings

        logger.info(f"Unauthorized scan: {len(findings)} findings.")
        return findings

    def _inspect_process(self, proc: psutil.Process) -> Optional[UnauthorizedFinding]:
        """
        Inspect a single process for unauthorized indicators.

        Args:
            proc: psutil.Process to inspect.

        Returns:
            UnauthorizedFinding if suspicious, else None.
        """
        pid = safe_proc_attr(proc, "pid", 0)
        name = safe_proc_attr(proc, "name", "Unknown")
        exe = safe_proc_attr(proc, "exe", None)
        username = safe_proc_attr(proc, "username", "N/A")

        name_lower = name.lower()
        exe_path = sanitize_path(exe) if exe else "Access Denied"
        path_lower = exe_path.lower()

        finding = UnauthorizedFinding()
        finding.pid = pid
        finding.name = name
        finding.exe_path = exe_path
        finding.username = username or "N/A"

        triggered = False

        # ---------------------------------------------------------------
        # 1. Blacklist name check (highest priority)
        # ---------------------------------------------------------------
        if name_lower in self._blacklisted_names:
            finding.severity = "Critical"
            finding.category = "Blacklisted Process"
            finding.reason = f"Process '{name}' matches the blacklist."
            finding.mitre_technique = "T1059"
            finding.recommendation = "Terminate immediately. Known malicious tool."
            finding.flags.append("BLACKLISTED_NAME")
            triggered = True

        # ---------------------------------------------------------------
        # 2. Keyword check in name or path
        # ---------------------------------------------------------------
        if not triggered:
            for kw in self._blacklist_keywords:
                if kw in name_lower or (exe_path != "Access Denied" and kw in path_lower):
                    finding.severity = "High"
                    finding.category = "Suspicious Keyword"
                    finding.reason = f"Name/path contains blacklisted keyword: '{kw}'"
                    finding.mitre_technique = "T1036"
                    finding.recommendation = "Investigate process origin. Keyword match indicates risk."
                    finding.flags.append(f"BLACKLIST_KEYWORD:{kw}")
                    triggered = True
                    break

        # ---------------------------------------------------------------
        # 3. Unauthorized execution path
        # ---------------------------------------------------------------
        if exe_path not in ("Access Denied", "N/A"):
            path_reason = get_suspicious_path_reason(exe_path)
            if path_reason:
                flag = f"UNAUTHORIZED_PATH:{path_reason}"
                finding.flags.append(flag)
                finding.is_signed = False
                if not triggered:
                    finding.severity = "Critical" if "$recycle" in path_lower else "High"
                    finding.category = "Unauthorized Execution Path"
                    finding.reason = path_reason
                    finding.mitre_technique = "T1036.005"
                    finding.recommendation = (
                        "Process is executing from an unauthorized location. "
                        "Investigate and terminate if malicious."
                    )
                    triggered = True
                self._alerts.raise_alert(
                    severity=finding.severity,
                    category="Unauthorized Execution Path",
                    process_name=name,
                    pid=pid,
                    reason=path_reason,
                    recommendation=finding.recommendation,
                    exe_path=exe_path,
                    rule_id="PATH_DETECTION",
                    mitre_technique="T1036.005",
                    details=finding.to_dict(),
                )

        # ---------------------------------------------------------------
        # 4. Not whitelisted and not from trusted system paths
        # ---------------------------------------------------------------
        if (
            not triggered
            and not self._is_whitelisted(name_lower, path_lower)
            and exe_path not in ("Access Denied", "N/A")
            and not self._is_trusted_path(path_lower)
        ):
            finding.severity = "Low"
            finding.category = "Unknown Process"
            finding.reason = f"Process '{name}' is not in the whitelist and not from a trusted path."
            finding.mitre_technique = "T1036"
            finding.recommendation = "Review this process. May be legitimate third-party software."
            finding.flags.append("NOT_WHITELISTED")
            triggered = True

        # ---------------------------------------------------------------
        # 5. Deep scan: signature and hash checks
        # ---------------------------------------------------------------
        if self._deep_scan_mode and exe and os.path.isfile(exe):
            # Signature
            if exe not in self._sig_cache:
                self._sig_cache[exe] = check_digital_signature(exe)
            sig = self._sig_cache[exe]
            finding.is_signed = sig.get("signed", False)
            finding.sign_status = sig.get("status", "Unknown")

            # Hash
            if exe not in self._hash_cache:
                self._hash_cache[exe] = compute_file_hash(exe) or "N/A"
            finding.file_hash = self._hash_cache[exe]

            # Blacklisted hash
            if finding.file_hash and finding.file_hash.lower() in self._blacklisted_hashes:
                finding.severity = "Critical"
                finding.category = "Blacklisted Hash"
                finding.reason = f"File hash matches blacklisted malware: {finding.file_hash}"
                finding.mitre_technique = "T1059"
                finding.recommendation = "Terminate immediately. File hash matches known malware."
                finding.flags.append("BLACKLISTED_HASH")
                triggered = True
                self._alerts.raise_alert(
                    severity="Critical",
                    category="Blacklisted Hash",
                    process_name=name,
                    pid=pid,
                    reason=finding.reason,
                    recommendation=finding.recommendation,
                    exe_path=exe_path,
                    rule_id="HASH_BLACKLIST",
                    mitre_technique="T1059",
                    details=finding.to_dict(),
                )

            # Unsigned non-system process
            if (
                not finding.is_signed
                and finding.sign_status not in ("Not Checked", "Unknown", "File not found", "Access Denied", "Timeout")
                and not self._is_whitelisted(name_lower, path_lower)
                and not self._is_trusted_path(path_lower)
            ):
                finding.flags.append("UNSIGNED_BINARY")
                if not triggered:
                    finding.severity = "Medium"
                    finding.category = "Unsigned Process"
                    finding.reason = f"'{name}' is unsigned (status: {finding.sign_status})."
                    finding.mitre_technique = "T1553.002"
                    finding.recommendation = "Verify process legitimacy. Unsigned binaries are higher risk."
                    triggered = True
                self._alerts.raise_alert(
                    severity="Medium",
                    category="Unsigned Process",
                    process_name=name,
                    pid=pid,
                    reason=finding.reason,
                    recommendation=finding.recommendation,
                    exe_path=exe_path,
                    rule_id="RULE-008",
                    mitre_technique="T1553.002",
                    details=finding.to_dict(),
                )

        if not triggered:
            return None

        # Raise alert for critical/high/medium (low is informational)
        if finding.severity in ("Critical", "High", "Medium") and "UNAUTHORIZED_PATH" not in str(finding.flags):
            self._alerts.raise_alert(
                severity=finding.severity,
                category=finding.category,
                process_name=name,
                pid=pid,
                reason=finding.reason,
                recommendation=finding.recommendation,
                exe_path=exe_path,
                rule_id="UNAUTHORIZED_DETECT",
                mitre_technique=finding.mitre_technique,
                details=finding.to_dict(),
            )

        return finding

    def _is_whitelisted(self, name_lower: str, path_lower: str) -> bool:
        """
        Check if process is whitelisted by name or path.

        Args:
            name_lower: Lowercase process name.
            path_lower: Lowercase exe path.

        Returns:
            True if whitelisted.
        """
        if name_lower in self._whitelisted_names:
            return True
        for wp in self._whitelisted_paths:
            if path_lower.startswith(wp.lower()):
                return True
        return False

    def _is_trusted_path(self, path_lower: str) -> bool:
        """
        Check if an executable path belongs to a trusted system directory.

        Args:
            path_lower: Lowercase file path.

        Returns:
            True if trusted.
        """
        return any(path_lower.startswith(tp) for tp in TRUSTED_SYSTEM_PATHS)

    def get_current_findings(self) -> list[UnauthorizedFinding]:
        """Return the most recent unauthorized detection results."""
        with self._lock:
            return self._current_findings[:]

    def get_findings_by_severity(self, severity: str) -> list[UnauthorizedFinding]:
        """
        Filter findings by severity level.

        Args:
            severity: Severity string (Critical/High/Medium/Low).

        Returns:
            Filtered list of UnauthorizedFinding instances.
        """
        with self._lock:
            return [f for f in self._current_findings if f.severity == severity]

    def get_finding_count(self) -> int:
        """Return total count of current findings."""
        with self._lock:
            return len(self._current_findings)

    def add_to_whitelist(self, process_name: str) -> bool:
        """
        Add a process name to the whitelist and save to disk.

        Args:
            process_name: Process name to whitelist.

        Returns:
            True on success.
        """
        try:
            whitelist = load_json_config(WHITELIST_PATH)
            names: list = whitelist.get("processes", {}).get("names", [])
            if process_name not in names:
                names.append(process_name)
                whitelist.setdefault("processes", {})["names"] = names
                from modules.utils import save_json_config
                save_json_config(WHITELIST_PATH, whitelist)
                self.reload_config()
                logger.info(f"Added '{process_name}' to whitelist.")
                return True
        except Exception as e:
            logger.error(f"Failed to add to whitelist: {e}")
        return False

    def add_to_blacklist(self, process_name: str) -> bool:
        """
        Add a process name to the blacklist and save to disk.

        Args:
            process_name: Process name to blacklist.

        Returns:
            True on success.
        """
        try:
            blacklist = load_json_config(BLACKLIST_PATH)
            names: list = blacklist.get("processes", {}).get("names", [])
            if process_name not in names:
                names.append(process_name)
                blacklist.setdefault("processes", {})["names"] = names
                from modules.utils import save_json_config
                save_json_config(BLACKLIST_PATH, blacklist)
                self.reload_config()
                logger.info(f"Added '{process_name}' to blacklist.")
                return True
        except Exception as e:
            logger.error(f"Failed to add to blacklist: {e}")
        return False
