"""
alert_manager.py - Alert Engine
==================================
Generates, classifies, and manages security alerts with severity levels
(Critical, High, Medium, Low), MITRE ATT&CK mappings, and recommendations.

Author: Security Research Team
Version: 1.0.0
"""

import threading
from datetime import datetime
from typing import Callable, Optional

from modules.database_manager import DatabaseManager
from modules.logger import get_logger

logger = get_logger("alert_manager")

# Severity ordering for comparison
SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


class Alert:
    """Represents a single security alert with all metadata."""

    def __init__(
        self,
        severity: str,
        category: str,
        process_name: str,
        pid: int,
        reason: str,
        recommendation: str,
        exe_path: str = "N/A",
        rule_id: str = "MANUAL",
        mitre_technique: str = "N/A",
        details: Optional[dict] = None,
    ) -> None:
        """
        Initialize an Alert.

        Args:
            severity: Severity level (Critical/High/Medium/Low).
            category: Threat category name.
            process_name: Name of the flagged process.
            pid: Process ID.
            reason: Human-readable reason for the alert.
            recommendation: Suggested remediation step.
            exe_path: Full executable path.
            rule_id: Detection rule ID that triggered this alert.
            mitre_technique: MITRE ATT&CK technique ID.
            details: Additional context dictionary.
        """
        self.timestamp = datetime.now().isoformat()
        self.severity = severity
        self.category = category
        self.process_name = process_name
        self.pid = pid
        self.reason = reason
        self.recommendation = recommendation
        self.exe_path = exe_path
        self.rule_id = rule_id
        self.mitre_technique = mitre_technique
        self.details = details or {}
        self.acknowledged = False
        self.alert_id: Optional[int] = None

    def to_dict(self) -> dict:
        """Convert the alert to a serializable dictionary."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "category": self.category,
            "process_name": self.process_name,
            "pid": self.pid,
            "exe_path": self.exe_path,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "recommendation": self.recommendation,
            "mitre_technique": self.mitre_technique,
            "details": self.details,
            "acknowledged": self.acknowledged,
        }

    def __repr__(self) -> str:
        return (
            f"Alert(severity={self.severity}, category={self.category}, "
            f"process={self.process_name}[{self.pid}], reason={self.reason[:50]})"
        )


class AlertManager:
    """
    Central alert management engine.
    Receives alert data, classifies severity, stores to DB,
    and notifies registered callbacks (e.g. GUI, console).
    """

    def __init__(self, db_manager: DatabaseManager) -> None:
        """
        Initialize the AlertManager.

        Args:
            db_manager: DatabaseManager instance for persistence.
        """
        self._db = db_manager
        self._alerts: list[Alert] = []
        self._lock = threading.Lock()
        self._callbacks: list[Callable[[Alert], None]] = []
        self._max_in_memory = 5000
        logger.info("AlertManager initialized.")

    def register_callback(self, callback: Callable[[Alert], None]) -> None:
        """
        Register a callback function to be called when a new alert is generated.

        Args:
            callback: Function accepting an Alert instance.
        """
        self._callbacks.append(callback)

    def raise_alert(
        self,
        severity: str,
        category: str,
        process_name: str,
        pid: int,
        reason: str,
        recommendation: str,
        exe_path: str = "N/A",
        rule_id: str = "MANUAL",
        mitre_technique: str = "N/A",
        details: Optional[dict] = None,
    ) -> Alert:
        """
        Create, store, and dispatch a new security alert.

        Args:
            severity: Severity level.
            category: Threat category.
            process_name: Flagged process name.
            pid: Process ID.
            reason: Alert reason.
            recommendation: Remediation recommendation.
            exe_path: Executable path.
            rule_id: Triggering rule ID.
            mitre_technique: MITRE technique ID.
            details: Extra context.

        Returns:
            The created Alert instance.
        """
        alert = Alert(
            severity=severity,
            category=category,
            process_name=process_name,
            pid=pid,
            reason=reason,
            recommendation=recommendation,
            exe_path=exe_path,
            rule_id=rule_id,
            mitre_technique=mitre_technique,
            details=details,
        )

        # Persist to database
        try:
            alert.alert_id = self._db.insert_alert(alert.to_dict())
        except Exception as e:
            logger.error(f"Failed to persist alert to DB: {e}")

        # Store in memory with cap
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > self._max_in_memory:
                self._alerts = self._alerts[-self._max_in_memory:]

        logger.warning(
            f"ALERT [{severity}] {category} | Process: {process_name}[{pid}] | {reason}"
        )

        # Notify registered callbacks (e.g. GUI)
        for cb in self._callbacks:
            try:
                cb(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

        return alert

    def get_alerts(
        self,
        severity: Optional[str] = None,
        limit: int = 500,
        include_acknowledged: bool = True,
    ) -> list[Alert]:
        """
        Get in-memory alerts with optional filters.

        Args:
            severity: Filter by severity level.
            limit: Max number of alerts to return.
            include_acknowledged: Whether to include acknowledged alerts.

        Returns:
            List of Alert instances.
        """
        with self._lock:
            filtered = self._alerts[:]

        if severity:
            filtered = [a for a in filtered if a.severity == severity]
        if not include_acknowledged:
            filtered = [a for a in filtered if not a.acknowledged]

        # Sort by severity desc, then timestamp desc
        filtered.sort(
            key=lambda a: (SEVERITY_ORDER.get(a.severity, 0), a.timestamp),
            reverse=True,
        )
        return filtered[:limit]

    def get_alert_counts(self) -> dict:
        """
        Count alerts by severity level.

        Returns:
            Dictionary with severity keys and count values.
        """
        with self._lock:
            counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Total": 0}
            for alert in self._alerts:
                if alert.severity in counts:
                    counts[alert.severity] += 1
                counts["Total"] += 1
        return counts

    def acknowledge_alert(self, alert_id: int) -> bool:
        """
        Acknowledge an alert by ID.

        Args:
            alert_id: The alert's DB ID.

        Returns:
            True if found and acknowledged.
        """
        with self._lock:
            for alert in self._alerts:
                if alert.alert_id == alert_id:
                    alert.acknowledged = True
                    self._db.acknowledge_alert(alert_id)
                    logger.info(f"Alert {alert_id} acknowledged.")
                    return True
        return False

    def clear_alerts(self) -> None:
        """Clear all in-memory alerts (does not delete DB records)."""
        with self._lock:
            count = len(self._alerts)
            self._alerts.clear()
        logger.info(f"Cleared {count} in-memory alerts.")

    def get_recent_critical(self, n: int = 10) -> list[Alert]:
        """
        Return the n most recent Critical alerts.

        Args:
            n: Number of critical alerts to return.

        Returns:
            List of critical Alert instances.
        """
        with self._lock:
            critical = [a for a in self._alerts if a.severity == "Critical"]
        critical.sort(key=lambda a: a.timestamp, reverse=True)
        return critical[:n]

    def has_unacknowledged(self) -> bool:
        """Check if any unacknowledged alerts exist."""
        with self._lock:
            return any(not a.acknowledged for a in self._alerts)

    def get_alert_timeline(self) -> list[dict]:
        """
        Generate an alert timeline grouped by minute for charting.

        Returns:
            List of dicts with timestamp buckets and counts per severity.
        """
        from collections import defaultdict

        with self._lock:
            alerts_copy = self._alerts[:]

        timeline: dict[str, dict] = defaultdict(
            lambda: {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        )
        for alert in alerts_copy:
            bucket = alert.timestamp[:16]  # Minute precision
            timeline[bucket][alert.severity] = timeline[bucket].get(alert.severity, 0) + 1

        return [
            {"time": k, **v}
            for k, v in sorted(timeline.items())
        ]

    def get_top_suspicious_processes(self, n: int = 10) -> list[dict]:
        """
        Return the top n processes with the most alerts.

        Args:
            n: Number of top processes.

        Returns:
            List of dicts with process_name and alert_count.
        """
        from collections import Counter

        with self._lock:
            counter = Counter(a.process_name for a in self._alerts)

        return [
            {"process_name": name, "alert_count": count}
            for name, count in counter.most_common(n)
        ]
