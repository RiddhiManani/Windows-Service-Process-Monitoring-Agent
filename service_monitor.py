"""
service_monitor.py - Windows Service Monitor
=============================================
Enumerates all Windows services and detects unknown, disabled security
services, services running from suspicious paths, and tampered service paths.

Author: Security Research Team
Version: 1.0.0
"""

import threading
import winreg
from datetime import datetime
from typing import Optional

import win32service
import win32serviceutil

from modules.alert_manager import AlertManager
from modules.database_manager import DatabaseManager
from modules.logger import get_logger
from modules.utils import (
    is_suspicious_path,
    get_suspicious_path_reason,
    load_json_config,
    sanitize_path,
)

logger = get_logger("service_monitor")

WHITELIST_PATH = "config/whitelist.json"
BLACKLIST_PATH = "config/blacklist.json"
DETECTION_RULES_PATH = "config/detection_rules.json"

START_TYPE_MAP = {
    0: "Boot",
    1: "System",
    2: "Automatic",
    3: "Manual",
    4: "Disabled",
}

STATUS_MAP = {
    1: "Stopped",
    2: "Start Pending",
    3: "Stop Pending",
    4: "Running",
    5: "Continue Pending",
    6: "Pause Pending",
    7: "Paused",
}

PROTECTED_SECURITY_SERVICES = [
    "WinDefend", "MpsSvc", "wscsvc", "SecurityHealthService",
    "WdNisSvc", "EventLog", "SamSs", "lsass",
]


class ServiceInfo:
    """Data class representing a snapshot of a Windows service."""

    def __init__(self) -> None:
        self.name: str = "N/A"
        self.display_name: str = "N/A"
        self.status: str = "Unknown"
        self.start_type: str = "Unknown"
        self.exe_path: str = "N/A"
        self.account: str = "N/A"
        self.description: str = "N/A"
        self.is_suspicious: bool = False
        self.flags: list[str] = []
        self.scan_time: str = datetime.now().isoformat()

    def to_dict(self) -> dict:
        """Convert ServiceInfo to a serializable dictionary."""
        return {
            "name": self.name,
            "display_name": self.display_name,
            "status": self.status,
            "start_type": self.start_type,
            "exe_path": self.exe_path,
            "account": self.account,
            "description": self.description,
            "is_suspicious": self.is_suspicious,
            "flags": self.flags,
            "scan_time": self.scan_time,
        }


class ServiceMonitor:
    """
    Windows service enumeration and threat detection engine.
    Uses win32service API to enumerate services and applies multiple
    detection layers to identify suspicious or malicious services.
    """

    def __init__(self, db_manager: DatabaseManager, alert_manager: AlertManager) -> None:
        """
        Initialize the ServiceMonitor.

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

        self._whitelisted_services: set[str] = {
            s.lower() for s in self._whitelist.get("services", {}).get("names", [])
        }
        self._blacklisted_services: set[str] = {
            s.lower() for s in self._blacklist.get("services", {}).get("names", [])
        }

        self._current_services: list[ServiceInfo] = []
        logger.info("ServiceMonitor initialized.")

    def reload_config(self) -> None:
        """Reload configuration files from disk."""
        self._whitelist = load_json_config(WHITELIST_PATH)
        self._blacklist = load_json_config(BLACKLIST_PATH)
        self._rules = load_json_config(DETECTION_RULES_PATH)
        self._whitelisted_services = {
            s.lower() for s in self._whitelist.get("services", {}).get("names", [])
        }
        self._blacklisted_services = {
            s.lower() for s in self._blacklist.get("services", {}).get("names", [])
        }
        logger.info("ServiceMonitor configuration reloaded.")

    def scan_all_services(self) -> list[ServiceInfo]:
        """
        Enumerate and analyze all Windows services.

        Returns:
            List of ServiceInfo snapshots.
        """
        scan_time = datetime.now().isoformat()
        results: list[ServiceInfo] = []

        try:
            scm = win32service.OpenSCManager(
                None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE
            )
            statuses = win32service.EnumServicesStatusEx(
                scm,
                win32service.SERVICE_WIN32,
                win32service.SERVICE_STATE_ALL,
            )
            win32service.CloseServiceHandle(scm)
        except Exception as e:
            logger.error(f"Failed to enumerate services via win32service: {e}")
            return self._fallback_service_scan(scan_time)

        for svc_status in statuses:
            try:
                svc = self._analyze_service(svc_status, scan_time)
                if svc:
                    results.append(svc)
            except Exception as e:
                logger.debug(f"Error analyzing service {svc_status.get('ServiceName', '?')}: {e}")
                continue

        with self._lock:
            self._current_services = results

        logger.info(f"Service scan complete: {len(results)} services analyzed.")
        return results

    def _analyze_service(self, svc_status: dict, scan_time: str) -> Optional[ServiceInfo]:
        """
        Analyze a single service status entry.

        Args:
            svc_status: Service status dict from EnumServicesStatusEx.
            scan_time: Scan timestamp.

        Returns:
            Populated ServiceInfo instance.
        """
        sinfo = ServiceInfo()
        sinfo.scan_time = scan_time
        sinfo.name = svc_status.get("ServiceName", "Unknown")
        sinfo.display_name = svc_status.get("DisplayName", "Unknown")

        raw_status = svc_status.get("CurrentState", 0)
        sinfo.status = STATUS_MAP.get(raw_status, "Unknown")

        # Fetch additional config from registry
        config = self._get_service_config(sinfo.name)
        sinfo.exe_path = sanitize_path(config.get("exe_path", "N/A"))
        sinfo.account = config.get("account", "N/A")
        sinfo.start_type = START_TYPE_MAP.get(config.get("start_type", -1), "Unknown")
        sinfo.description = config.get("description", "N/A")

        # Apply detections
        self._apply_detections(sinfo)

        # Persist
        try:
            self._db.insert_service(sinfo.to_dict())
        except Exception as e:
            logger.debug(f"Failed to save service {sinfo.name} to DB: {e}")

        return sinfo

    def _get_service_config(self, service_name: str) -> dict:
        """
        Read service configuration from the Windows registry.

        Args:
            service_name: Service short name.

        Returns:
            Dictionary with exe_path, account, start_type, description.
        """
        config: dict = {}
        registry_key = f"SYSTEM\\CurrentControlSet\\Services\\{service_name}"

        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                registry_key,
                0,
                winreg.KEY_READ,
            )
            try:
                image_path, _ = winreg.QueryValueEx(key, "ImagePath")
                config["exe_path"] = str(image_path)
            except FileNotFoundError:
                config["exe_path"] = "N/A"

            try:
                obj_name, _ = winreg.QueryValueEx(key, "ObjectName")
                config["account"] = str(obj_name)
            except FileNotFoundError:
                config["account"] = "LocalSystem"

            try:
                start_val, _ = winreg.QueryValueEx(key, "Start")
                config["start_type"] = int(start_val)
            except FileNotFoundError:
                config["start_type"] = -1

            try:
                desc, _ = winreg.QueryValueEx(key, "Description")
                config["description"] = str(desc)[:200]
            except FileNotFoundError:
                config["description"] = "N/A"

            winreg.CloseKey(key)
        except PermissionError:
            config["exe_path"] = "Access Denied"
        except FileNotFoundError:
            config["exe_path"] = "Not in Registry"
        except Exception as e:
            logger.debug(f"Registry read error for {service_name}: {e}")

        return config

    def _apply_detections(self, sinfo: ServiceInfo) -> None:
        """
        Apply all detection logic to a ServiceInfo record.

        Args:
            sinfo: The ServiceInfo to analyze and flag.
        """
        name_lower = sinfo.name.lower()
        path_lower = sinfo.exe_path.lower()

        # 1) Blacklisted service
        if name_lower in self._blacklisted_services:
            sinfo.is_suspicious = True
            sinfo.flags.append("BLACKLISTED_SERVICE")
            self._alerts.raise_alert(
                severity="Critical",
                category="Blacklisted Service",
                process_name=sinfo.name,
                pid=0,
                reason=f"Service '{sinfo.name}' is on the blacklist.",
                recommendation="Stop and delete the service immediately.",
                exe_path=sinfo.exe_path,
                rule_id="SERVICE_BLACKLIST",
                mitre_technique="T1543.003",
                details=sinfo.to_dict(),
            )

        # 2) Service from suspicious path
        if sinfo.exe_path not in ("Access Denied", "N/A", "Not in Registry"):
            path_reason = get_suspicious_path_reason(sinfo.exe_path)
            if path_reason:
                sinfo.is_suspicious = True
                sinfo.flags.append(f"SUSPICIOUS_SERVICE_PATH:{path_reason}")
                self._alerts.raise_alert(
                    severity="Critical",
                    category="Service Path Abuse",
                    process_name=sinfo.name,
                    pid=0,
                    reason=f"Service binary in suspicious location: {path_reason}",
                    recommendation="Stop service and investigate binary. Likely a dropped payload.",
                    exe_path=sinfo.exe_path,
                    rule_id="RULE-009",
                    mitre_technique="T1543.003",
                    details=sinfo.to_dict(),
                )

        # 3) Disabled security service
        if sinfo.name in PROTECTED_SECURITY_SERVICES:
            if sinfo.status in ("Stopped", "Disabled") or sinfo.start_type == "Disabled":
                sinfo.is_suspicious = True
                sinfo.flags.append("SECURITY_SERVICE_DISABLED")
                self._alerts.raise_alert(
                    severity="Critical",
                    category="Security Service Tampered",
                    process_name=sinfo.name,
                    pid=0,
                    reason=f"Security service '{sinfo.display_name}' is {sinfo.status}.",
                    recommendation="Re-enable security service immediately. Possible tamper.",
                    exe_path=sinfo.exe_path,
                    rule_id="RULE-015",
                    mitre_technique="T1562.001",
                    details=sinfo.to_dict(),
                )

        # 4) Not in whitelist and not from a standard path
        standard_paths = ["c:\\windows\\system32\\", "c:\\windows\\syswow64\\"]
        if (
            name_lower not in self._whitelisted_services
            and sinfo.exe_path not in ("Access Denied", "N/A", "Not in Registry")
            and not any(path_lower.startswith(p) for p in standard_paths)
            and not any(path_lower.startswith(p) for p in ["c:\\program files\\", "c:\\program files (x86)\\"])
        ):
            sinfo.flags.append("UNKNOWN_SERVICE")
            # Low severity — informational
            self._alerts.raise_alert(
                severity="Low",
                category="Unknown Service",
                process_name=sinfo.name,
                pid=0,
                reason=f"Service '{sinfo.display_name}' is not in the whitelist.",
                recommendation="Verify this service is authorized and expected.",
                exe_path=sinfo.exe_path,
                rule_id="SERVICE_WHITELIST",
                mitre_technique="T1543",
                details=sinfo.to_dict(),
            )

        if sinfo.flags:
            sinfo.is_suspicious = True

    def _fallback_service_scan(self, scan_time: str) -> list[ServiceInfo]:
        """
        Fallback service scan using registry enumeration when win32service fails.

        Args:
            scan_time: Scan timestamp.

        Returns:
            Partial list of ServiceInfo from registry.
        """
        results: list[ServiceInfo] = []
        logger.warning("Using fallback registry-based service scan.")
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services",
                0,
                winreg.KEY_READ,
            )
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    i += 1
                    config = self._get_service_config(subkey_name)
                    sinfo = ServiceInfo()
                    sinfo.scan_time = scan_time
                    sinfo.name = subkey_name
                    sinfo.display_name = subkey_name
                    sinfo.exe_path = sanitize_path(config.get("exe_path", "N/A"))
                    sinfo.start_type = START_TYPE_MAP.get(config.get("start_type", -1), "Unknown")
                    sinfo.status = "Unknown (fallback)"
                    results.append(sinfo)
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception as e:
            logger.error(f"Fallback service scan failed: {e}")
        return results

    def get_current_services(self) -> list[ServiceInfo]:
        """Return the most recent service scan results."""
        with self._lock:
            return self._current_services[:]

    def get_suspicious_services(self) -> list[ServiceInfo]:
        """Return only suspicious services from the current scan."""
        with self._lock:
            return [s for s in self._current_services if s.is_suspicious]

    def get_service_count(self) -> int:
        """Return the total number of services in the last scan."""
        with self._lock:
            return len(self._current_services)

    def get_service_by_name(self, name: str) -> Optional[ServiceInfo]:
        """
        Find a service by name.

        Args:
            name: Service short name.

        Returns:
            ServiceInfo or None.
        """
        with self._lock:
            for s in self._current_services:
                if s.name.lower() == name.lower():
                    return s
        return None
