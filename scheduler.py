"""
scheduler.py - Monitoring Scheduler
======================================
Manages the periodic execution of all monitoring modules on
configurable intervals. Supports start/stop/pause/resume and
separate quick/deep scan cycles.

Author: Security Research Team
Version: 1.0.0
"""

import threading
import uuid
from datetime import datetime
from typing import Callable, Optional

from modules.logger import get_logger
from modules.utils import load_json_config

logger = get_logger("scheduler")

SETTINGS_PATH = "config/settings.json"


class SchedulerTask:
    """Represents a single scheduled monitoring task."""

    def __init__(self, name: str, callback: Callable, interval_sec: float) -> None:
        """
        Initialize a scheduler task.

        Args:
            name: Human-readable task name.
            callback: Function to call when task fires.
            interval_sec: Interval between executions in seconds.
        """
        self.name = name
        self.callback = callback
        self.interval_sec = interval_sec
        self.last_run: Optional[datetime] = None
        self.run_count: int = 0
        self.error_count: int = 0
        self.enabled: bool = True


class MonitoringScheduler:
    """
    Coordinates all background monitoring tasks.
    Controls scanning intervals, deep scan cycles, and lifecycle management.
    """

    def __init__(self) -> None:
        """Initialize the MonitoringScheduler."""
        settings = load_json_config(SETTINGS_PATH)
        monitoring = settings.get("monitoring", {})

        self._quick_interval = monitoring.get("scan_interval_seconds", 5)
        self._deep_interval = monitoring.get("deep_scan_interval_seconds", 30)

        self._tasks: list[SchedulerTask] = []
        self._deep_tasks: list[SchedulerTask] = []

        self._running = False
        self._paused = False
        self._lock = threading.Lock()

        self._quick_thread: Optional[threading.Thread] = None
        self._deep_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()  # Not paused by default

        self._session_id = str(uuid.uuid4())
        self._start_time: Optional[datetime] = None

        self._on_scan_complete: Optional[Callable] = None
        self._on_deep_scan_complete: Optional[Callable] = None

        logger.info(
            f"MonitoringScheduler initialized | "
            f"Quick: {self._quick_interval}s | Deep: {self._deep_interval}s"
        )

    # ------------------------------------------------------------------
    # Task Registration
    # ------------------------------------------------------------------

    def register_quick_task(self, name: str, callback: Callable) -> None:
        """
        Register a callback to run every quick scan interval.

        Args:
            name: Display name for the task.
            callback: Function to call on each interval tick.
        """
        task = SchedulerTask(name, callback, self._quick_interval)
        self._tasks.append(task)
        logger.info(f"Quick task registered: '{name}' @ {self._quick_interval}s")

    def register_deep_task(self, name: str, callback: Callable) -> None:
        """
        Register a callback to run every deep scan interval.

        Args:
            name: Display name for the task.
            callback: Function to call on each deep scan tick.
        """
        task = SchedulerTask(name, callback, self._deep_interval)
        self._deep_tasks.append(task)
        logger.info(f"Deep task registered: '{name}' @ {self._deep_interval}s")

    def on_scan_complete(self, callback: Callable) -> None:
        """Register a callback for when a quick scan cycle completes."""
        self._on_scan_complete = callback

    def on_deep_scan_complete(self, callback: Callable) -> None:
        """Register a callback for when a deep scan cycle completes."""
        self._on_deep_scan_complete = callback

    # ------------------------------------------------------------------
    # Lifecycle Control
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the monitoring scheduler and all background threads."""
        if self._running:
            logger.warning("Scheduler already running.")
            return

        self._running = True
        self._paused = False
        self._stop_event.clear()
        self._pause_event.set()
        self._start_time = datetime.now()

        # Quick scan thread
        self._quick_thread = threading.Thread(
            target=self._quick_loop,
            name="QuickScanThread",
            daemon=True,
        )
        self._quick_thread.start()

        # Deep scan thread
        self._deep_thread = threading.Thread(
            target=self._deep_loop,
            name="DeepScanThread",
            daemon=True,
        )
        self._deep_thread.start()

        logger.info(f"Scheduler started | Session: {self._session_id}")

    def stop(self) -> None:
        """Stop all monitoring threads gracefully."""
        self._running = False
        self._stop_event.set()
        self._pause_event.set()  # Unblock paused threads

        if self._quick_thread and self._quick_thread.is_alive():
            self._quick_thread.join(timeout=10)

        if self._deep_thread and self._deep_thread.is_alive():
            self._deep_thread.join(timeout=10)

        logger.info("Scheduler stopped.")

    def pause(self) -> None:
        """Pause all monitoring tasks without stopping threads."""
        self._paused = True
        self._pause_event.clear()
        logger.info("Scheduler paused.")

    def resume(self) -> None:
        """Resume monitoring after a pause."""
        self._paused = False
        self._pause_event.set()
        logger.info("Scheduler resumed.")

    def is_running(self) -> bool:
        """Return True if the scheduler is actively running."""
        return self._running and not self._paused

    def is_paused(self) -> bool:
        """Return True if the scheduler is paused."""
        return self._paused

    # ------------------------------------------------------------------
    # Manual Scan Triggers
    # ------------------------------------------------------------------

    def trigger_quick_scan(self) -> None:
        """Immediately trigger a quick scan cycle in a background thread."""
        thread = threading.Thread(
            target=self._run_quick_tasks,
            name="ManualQuickScan",
            daemon=True,
        )
        thread.start()
        logger.info("Manual quick scan triggered.")

    def trigger_deep_scan(self) -> None:
        """Immediately trigger a deep scan cycle in a background thread."""
        thread = threading.Thread(
            target=self._run_deep_tasks,
            name="ManualDeepScan",
            daemon=True,
        )
        thread.start()
        logger.info("Manual deep scan triggered.")

    # ------------------------------------------------------------------
    # Internal Loop Workers
    # ------------------------------------------------------------------

    def _quick_loop(self) -> None:
        """Background loop that executes quick scan tasks periodically."""
        logger.info("Quick scan loop started.")
        while not self._stop_event.is_set():
            # Wait for unpause
            self._pause_event.wait()
            if self._stop_event.is_set():
                break

            self._run_quick_tasks()

            # Sleep in small increments to allow fast stop response
            for _ in range(self._quick_interval * 10):
                if self._stop_event.is_set():
                    break
                self._stop_event.wait(timeout=0.1)

        logger.info("Quick scan loop exited.")

    def _deep_loop(self) -> None:
        """Background loop that executes deep scan tasks periodically."""
        logger.info("Deep scan loop started.")
        while not self._stop_event.is_set():
            self._pause_event.wait()
            if self._stop_event.is_set():
                break

            self._run_deep_tasks()

            for _ in range(self._deep_interval * 10):
                if self._stop_event.is_set():
                    break
                self._stop_event.wait(timeout=0.1)

        logger.info("Deep scan loop exited.")

    def _run_quick_tasks(self) -> None:
        """Execute all registered quick scan tasks."""
        now = datetime.now()
        for task in self._tasks:
            if not task.enabled:
                continue
            try:
                task.callback()
                task.last_run = now
                task.run_count += 1
            except Exception as e:
                task.error_count += 1
                logger.error(f"Task '{task.name}' failed: {e}")

        if self._on_scan_complete:
            try:
                self._on_scan_complete()
            except Exception as e:
                logger.error(f"Scan complete callback error: {e}")

    def _run_deep_tasks(self) -> None:
        """Execute all registered deep scan tasks."""
        now = datetime.now()
        for task in self._deep_tasks:
            if not task.enabled:
                continue
            try:
                task.callback()
                task.last_run = now
                task.run_count += 1
            except Exception as e:
                task.error_count += 1
                logger.error(f"Deep task '{task.name}' failed: {e}")

        if self._on_deep_scan_complete:
            try:
                self._on_deep_scan_complete()
            except Exception as e:
                logger.error(f"Deep scan complete callback error: {e}")

    # ------------------------------------------------------------------
    # Status & Metrics
    # ------------------------------------------------------------------

    def get_status(self) -> dict:
        """
        Get current scheduler status and task metrics.

        Returns:
            Dictionary with scheduler state information.
        """
        uptime = None
        if self._start_time:
            delta = datetime.now() - self._start_time
            uptime = str(delta).split(".")[0]

        task_statuses = []
        for task in self._tasks + self._deep_tasks:
            task_statuses.append({
                "name": task.name,
                "interval_sec": task.interval_sec,
                "run_count": task.run_count,
                "error_count": task.error_count,
                "last_run": task.last_run.isoformat() if task.last_run else "Never",
                "enabled": task.enabled,
            })

        return {
            "running": self._running,
            "paused": self._paused,
            "session_id": self._session_id,
            "start_time": self._start_time.isoformat() if self._start_time else None,
            "uptime": uptime,
            "quick_interval_sec": self._quick_interval,
            "deep_interval_sec": self._deep_interval,
            "quick_task_count": len(self._tasks),
            "deep_task_count": len(self._deep_tasks),
            "tasks": task_statuses,
        }

    def update_intervals(self, quick_sec: int, deep_sec: int) -> None:
        """
        Update scan intervals (takes effect on next cycle).

        Args:
            quick_sec: New quick scan interval in seconds.
            deep_sec: New deep scan interval in seconds.
        """
        self._quick_interval = max(1, quick_sec)
        self._deep_interval = max(5, deep_sec)
        for task in self._tasks:
            task.interval_sec = self._quick_interval
        for task in self._deep_tasks:
            task.interval_sec = self._deep_interval
        logger.info(f"Intervals updated: quick={self._quick_interval}s, deep={self._deep_interval}s")

    def get_session_id(self) -> str:
        """Return the current monitoring session UUID."""
        return self._session_id
