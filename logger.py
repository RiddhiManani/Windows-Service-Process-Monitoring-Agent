"""
logger.py - Centralized Logging Module
========================================
Provides structured logging to JSON, TXT, and CSV formats.
All modules use this logger for consistent, correlated log output.

Author: Security Research Team
Version: 1.0.0
"""

import json
import csv
import logging
import logging.handlers
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional


class JSONFormatter(logging.Formatter):
    """Custom JSON log formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """
        Format a log record as a JSON string.

        Args:
            record: The log record to format.

        Returns:
            JSON-formatted log string.
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
            "logger": record.name,
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


class CSVLogHandler(logging.Handler):
    """Custom CSV log handler that writes log entries to a CSV file."""

    def __init__(self, filepath: str) -> None:
        """
        Initialize the CSV log handler.

        Args:
            filepath: Path to the CSV log file.
        """
        super().__init__()
        self.filepath = filepath
        self._lock = threading.Lock()
        self._write_header()

    def _write_header(self) -> None:
        """Write the CSV header if the file doesn't exist or is empty."""
        if not os.path.exists(self.filepath) or os.path.getsize(self.filepath) == 0:
            try:
                with open(self.filepath, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["timestamp", "level", "module", "function", "line", "message"])
            except Exception:
                pass

    def emit(self, record: logging.LogRecord) -> None:
        """
        Write a log record to the CSV file.

        Args:
            record: The log record to write.
        """
        try:
            with self._lock:
                with open(self.filepath, "a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        datetime.utcnow().isoformat() + "Z",
                        record.levelname,
                        record.module,
                        record.funcName,
                        record.lineno,
                        record.getMessage(),
                    ])
        except Exception:
            self.handleError(record)


class AgentLogger:
    """
    Centralized logger for the Windows Service & Process Monitoring Agent.
    Manages TXT, JSON, and CSV log outputs simultaneously.
    """

    _instance: Optional["AgentLogger"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "AgentLogger":
        """Implement singleton pattern for the logger."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        """Initialize the logger (only runs once due to singleton)."""
        if self._initialized:
            return
        self._initialized = True
        self._setup_log_directory()
        self._loggers: dict[str, logging.Logger] = {}
        self._base_log_dir = Path("logs")
        self._session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    def _setup_log_directory(self) -> None:
        """Ensure the logs directory exists."""
        Path("logs").mkdir(parents=True, exist_ok=True)

    def get_logger(self, name: str, level: int = logging.DEBUG) -> logging.Logger:
        """
        Get or create a named logger with TXT, JSON, and CSV handlers.

        Args:
            name: The logger name (typically the module name).
            level: The minimum logging level.

        Returns:
            Configured logging.Logger instance.
        """
        if name in self._loggers:
            return self._loggers[name]

        logger = logging.getLogger(f"agent.{name}")
        logger.setLevel(level)
        logger.propagate = False

        if not logger.handlers:
            session_dir = self._base_log_dir / self._session_id
            session_dir.mkdir(parents=True, exist_ok=True)

            # TXT Handler (human-readable)
            txt_path = session_dir / f"{name}.log"
            txt_handler = logging.handlers.RotatingFileHandler(
                txt_path, maxBytes=50 * 1024 * 1024, backupCount=5, encoding="utf-8"
            )
            txt_handler.setFormatter(logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(module)s.%(funcName)s:%(lineno)d | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            ))
            txt_handler.setLevel(logging.DEBUG)

            # JSON Handler (structured)
            json_path = session_dir / f"{name}.json"
            json_handler = logging.handlers.RotatingFileHandler(
                json_path, maxBytes=50 * 1024 * 1024, backupCount=5, encoding="utf-8"
            )
            json_handler.setFormatter(JSONFormatter())
            json_handler.setLevel(logging.DEBUG)

            # CSV Handler (tabular)
            csv_path = session_dir / f"{name}.csv"
            csv_handler = CSVLogHandler(str(csv_path))
            csv_handler.setLevel(logging.INFO)

            # Console Handler (for development visibility)
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%H:%M:%S"
            ))
            console_handler.setLevel(logging.WARNING)

            logger.addHandler(txt_handler)
            logger.addHandler(json_handler)
            logger.addHandler(csv_handler)
            logger.addHandler(console_handler)

        self._loggers[name] = logger
        return logger

    def get_session_id(self) -> str:
        """Return the current session ID used in log directory naming."""
        return self._session_id

    def get_log_directory(self) -> Path:
        """Return the current session log directory path."""
        return self._base_log_dir / self._session_id


# Module-level singleton instance
_agent_logger = AgentLogger()


def get_logger(name: str) -> logging.Logger:
    """
    Convenience function to get a named logger.

    Args:
        name: Logger name (e.g., module name).

    Returns:
        Configured Logger instance.
    """
    return _agent_logger.get_logger(name)


def get_session_id() -> str:
    """Return the current logging session ID."""
    return _agent_logger.get_session_id()


def get_log_directory() -> Path:
    """Return the path to the current log session directory."""
    return _agent_logger.get_log_directory()
