"""
main.py - Windows Service & Process Monitoring Agent
======================================================
Application entry point and MonitoringAgent controller.
Wires together all modules, starts the scheduler, and launches
the dark-theme Tkinter dashboard.

Run as Administrator for full process/service visibility.

Author: Security Research Team
Version: 1.0.0
"""

import ctypes
import sys
import threading
from datetime import datetime
from pathlib import Path

# Ensure project root is on the path (allows running from any cwd)
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from modules.logger import get_logger
from modules.utils import ensure_directory, load_json_config, get_system_info
from modules.database_manager import DatabaseManager
from modules.alert_manager import AlertManager
from modules.process_monitor import ProcessMonitor
from modules.process_tree import ProcessTreeAnalyzer
from modules.service_monitor import ServiceMonitor
from modules.startup_audit import StartupAuditor
from modules.unauthorized_detector import UnauthorizedDetector
from modules.report_generator import ReportGenerator
from modules.scheduler import MonitoringScheduler
from modules.dashboard import Dashboard

logger = get_logger("main")

# ── Directory bootstrap ───────────────────────────────────────────────────
for _d in ("logs", "reports", "exports", "database", "screenshots", "docs", "assets"):
    ensure_directory(str(PROJECT_ROOT / _d))


def is_admin() -> bool:
    """Return True if the current process has Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class MonitoringAgent:
    """
    Central controller that owns all monitoring modules.
    The Dashboard holds a reference to this object and calls its methods.
    """

    def __init__(self) -> None:
        """Initialise every module and wire up callbacks."""
        logger.info("=" * 60)
        logger.info("Windows Service & Process Monitoring Agent starting...")
        logger.info(f"Admin privileges: {is_admin()}")

        settings = load_json_config("config/settings.json")

        # Core infrastructure
        self.db_manager      = DatabaseManager()
        self.alert_manager   = AlertManager(self.db_manager)

        # Detection modules
        self.process_monitor  = ProcessMonitor(self.db_manager, self.alert_manager)
        self.process_tree     = ProcessTreeAnalyzer(self.db_manager, self.alert_manager)
        self.service_monitor  = ServiceMonitor(self.db_manager, self.alert_manager)
        self.startup_auditor  = StartupAuditor(self.db_manager, self.alert_manager)
        self.unauth_detector  = UnauthorizedDetector(self.db_manager, self.alert_manager)

        # Report generator
        self.report_generator = ReportGenerator(self.db_manager, self.alert_manager)

        # Scheduler
        self.scheduler = MonitoringScheduler()

        # Register quick-scan tasks (run every scan_interval_seconds)
        self.scheduler.register_quick_task("Process Scan",  self.process_monitor.scan_all_processes)
        self.scheduler.register_quick_task("Process Tree",  self.process_tree.analyze_relationships)
        self.scheduler.register_quick_task("Service Scan",  self.service_monitor.scan_all_services)
        self.scheduler.register_quick_task("Startup Audit", self.startup_auditor.scan_startup_entries)
        self.scheduler.register_quick_task("Unauth Detect", self.unauth_detector.scan_for_unauthorized)

        # Register deep-scan tasks (run every deep_scan_interval_seconds)
        self.scheduler.register_deep_task("Deep Process Scan",
            lambda: self._deep_process_scan())
        self.scheduler.register_deep_task("System Health Snapshot",
            self._record_health_snapshot)

        # Scan completion hooks
        self.scheduler.on_scan_complete(self._on_scan_cycle_complete)
        self.scheduler.on_deep_scan_complete(self._on_deep_scan_cycle_complete)

        # Dashboard (created but not yet displayed)
        self.dashboard: Dashboard | None = None

        # Record start session
        self.db_manager.start_scan_session(
            self.scheduler.get_session_id(), "Continuous"
        )

        logger.info("MonitoringAgent initialised.")

    # ------------------------------------------------------------------
    # Scan helpers
    # ------------------------------------------------------------------

    def _deep_process_scan(self) -> None:
        """Run process scan with deep scan (signature + hash) enabled."""
        self.process_monitor.set_deep_scan(True)
        self.unauth_detector.set_deep_scan(True)
        self.process_monitor.scan_all_processes()
        self.unauth_detector.scan_for_unauthorized()
        self.process_monitor.set_deep_scan(False)
        self.unauth_detector.set_deep_scan(False)

    def _record_health_snapshot(self) -> None:
        """Capture a system health snapshot into the database."""
        try:
            import psutil
            counts = self.alert_manager.get_alert_counts()
            self.db_manager.insert_health_snapshot({
                "timestamp":      datetime.now().isoformat(),
                "cpu_percent":    psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent":   psutil.disk_usage("/").percent,
                "process_count":  self.process_monitor.get_process_count(),
                "service_count":  self.service_monitor.get_service_count(),
                "alert_count":    counts.get("Total", 0),
            })
        except Exception as e:
            logger.error(f"Health snapshot failed: {e}")

    def _on_scan_cycle_complete(self) -> None:
        """Called after every quick scan cycle. Triggers dashboard refresh."""
        if self.dashboard:
            self.dashboard.after(0, self.dashboard._do_refresh)

    def _on_deep_scan_cycle_complete(self) -> None:
        """Called after every deep scan cycle."""
        logger.info("Deep scan cycle complete.")

    # ------------------------------------------------------------------
    # Public control methods called by the Dashboard
    # ------------------------------------------------------------------

    def run_quick_scan(self) -> None:
        """Execute a manual quick scan synchronously (call from thread)."""
        logger.info("Manual quick scan started.")
        self.process_monitor.scan_all_processes()
        self.process_tree.analyze_relationships()
        self.service_monitor.scan_all_services()
        self.startup_auditor.scan_startup_entries()
        self.unauth_detector.scan_for_unauthorized()
        self._record_health_snapshot()
        if self.dashboard:
            self.dashboard.after(0, self.dashboard._do_refresh)
        logger.info("Manual quick scan complete.")

    def run_deep_scan(self) -> None:
        """Execute a manual deep scan synchronously (call from thread)."""
        logger.info("Manual deep scan started.")
        self._deep_process_scan()
        self.process_tree.analyze_relationships()
        self.service_monitor.scan_all_services()
        self.startup_auditor.scan_startup_entries()
        self._record_health_snapshot()
        if self.dashboard:
            self.dashboard.after(0, self.dashboard._do_refresh)
        logger.info("Manual deep scan complete.")

    def reload_all_configs(self) -> None:
        """Reload all detection configs after whitelist/blacklist edits."""
        self.process_monitor.reload_config()
        self.service_monitor.reload_config()
        self.unauth_detector.reload_config()
        self.process_tree.reload_rules()
        logger.info("All configs reloaded.")

    def shutdown(self) -> None:
        """Gracefully stop all background threads and close resources."""
        logger.info("Shutting down MonitoringAgent...")
        self.scheduler.stop()
        summary = self.alert_manager.get_alert_counts()
        self.db_manager.end_scan_session(
            self.scheduler.get_session_id(),
            {
                "total_processes": self.process_monitor.get_process_count(),
                "total_services":  self.service_monitor.get_service_count(),
                "total_alerts":    summary.get("Total", 0),
            },
        )
        self.db_manager.close()
        logger.info("MonitoringAgent shutdown complete.")


# ── Entry Point ────────────────────────────────────────────────────────────

def main() -> None:
    """Application entry point."""
    if not is_admin():
        print(
            "\n[WARNING] Not running as Administrator.\n"
            "Some processes and services may not be accessible.\n"
            "Right-click and 'Run as Administrator' for full visibility.\n"
        )

    agent = MonitoringAgent()

    # Register alert callback to push popups to dashboard
    def _alert_callback(alert):
        if agent.dashboard:
            agent.dashboard.notify_alert(alert)

    agent.alert_manager.register_callback(_alert_callback)

    # Start the background scheduler
    agent.scheduler.start()

    # Run one initial scan before showing GUI
    init_thread = threading.Thread(target=agent.run_quick_scan,
                                   name="InitialScan", daemon=True)
    init_thread.start()

    # Launch dashboard (Tkinter mainloop — blocks until window closes)
    try:
        dashboard = Dashboard(agent_controller=agent)
        agent.dashboard = dashboard

        def on_close():
            agent.shutdown()
            dashboard.destroy()

        dashboard.protocol("WM_DELETE_WINDOW", on_close)
        logger.info("Dashboard launched.")
        dashboard.mainloop()
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
    except Exception as e:
        logger.critical(f"Fatal error in dashboard: {e}", exc_info=True)
        raise
    finally:
        agent.shutdown()


if __name__ == "__main__":
    main()
