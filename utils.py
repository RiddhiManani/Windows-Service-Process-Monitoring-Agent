"""
utils.py - Shared Utility Functions
======================================
Provides common helper functions used across all modules including
hash computation, digital signature verification, path checks,
config loading, system info gathering, and formatting helpers.

Author: Security Research Team
Version: 1.0.0
"""

import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import psutil

from modules.logger import get_logger

logger = get_logger("utils")


# ---------------------------------------------------------------------------
# Configuration Helpers
# ---------------------------------------------------------------------------

def load_json_config(filepath: str) -> dict:
    """
    Load a JSON configuration file.

    Args:
        filepath: Path to the JSON file.

    Returns:
        Parsed dictionary or empty dict on error.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"Config file not found: {filepath}")
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in {filepath}: {e}")
        return {}
    except Exception as e:
        logger.error(f"Unexpected error loading config {filepath}: {e}")
        return {}


def save_json_config(filepath: str, data: dict) -> bool:
    """
    Save a dictionary to a JSON file.

    Args:
        filepath: Path to the output JSON file.
        data: Dictionary to serialize.

    Returns:
        True on success, False on failure.
    """
    try:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        logger.error(f"Failed to save config {filepath}: {e}")
        return False


# ---------------------------------------------------------------------------
# Hashing & Integrity
# ---------------------------------------------------------------------------

def compute_file_hash(filepath: str, algorithm: str = "sha256") -> Optional[str]:
    """
    Compute the cryptographic hash of a file.

    Args:
        filepath: Path to the file to hash.
        algorithm: Hash algorithm (md5, sha1, sha256).

    Returns:
        Hex digest string or None if the file cannot be read.
    """
    try:
        h = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except FileNotFoundError:
        logger.debug(f"File not found for hashing: {filepath}")
        return None
    except PermissionError:
        logger.debug(f"Permission denied hashing: {filepath}")
        return None
    except Exception as e:
        logger.error(f"Hash computation failed for {filepath}: {e}")
        return None


# ---------------------------------------------------------------------------
# Digital Signature Verification
# ---------------------------------------------------------------------------

def check_digital_signature(filepath: str) -> dict:
    """
    Check the digital signature of an executable using PowerShell.

    Args:
        filepath: Path to the executable to check.

    Returns:
        Dictionary with keys: signed (bool), issuer (str), subject (str), status (str).
    """
    result = {"signed": False, "issuer": "Unknown", "subject": "Unknown", "status": "Unknown"}
    if not filepath or not os.path.isfile(filepath):
        result["status"] = "File not found"
        return result

    try:
        cmd = [
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            f"$sig = Get-AuthenticodeSignature -FilePath '{filepath}'; "
            "$sig | Select-Object -Property Status,SignerCertificate | ConvertTo-Json"
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout)
            status = data.get("Status", {})
            status_value = status.get("Value", "Unknown") if isinstance(status, dict) else str(status)
            result["status"] = status_value
            result["signed"] = status_value == "Valid"
            cert = data.get("SignerCertificate")
            if cert and isinstance(cert, dict):
                result["issuer"] = cert.get("Issuer", "Unknown")
                result["subject"] = cert.get("Subject", "Unknown")
    except subprocess.TimeoutExpired:
        result["status"] = "Timeout"
    except json.JSONDecodeError:
        result["status"] = "Parse Error"
    except Exception as e:
        logger.debug(f"Signature check failed for {filepath}: {e}")
        result["status"] = "Error"
    return result


# ---------------------------------------------------------------------------
# Path Analysis
# ---------------------------------------------------------------------------

SUSPICIOUS_PATH_FRAGMENTS = [
    "\\temp\\", "\\tmp\\", "\\$recycle.bin\\", "\\recycler\\",
    "\\downloads\\", "c:\\users\\public\\", "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\", "\\programdata\\",
]


def is_suspicious_path(filepath: str) -> bool:
    """
    Determine if a file path is considered suspicious.

    Args:
        filepath: File path string.

    Returns:
        True if path matches a suspicious pattern.
    """
    if not filepath:
        return False
    normalized = filepath.lower().replace("/", "\\")
    return any(frag in normalized for frag in SUSPICIOUS_PATH_FRAGMENTS)


def get_suspicious_path_reason(filepath: str) -> Optional[str]:
    """
    Return a human-readable reason why a path is suspicious.

    Args:
        filepath: File path to evaluate.

    Returns:
        Reason string or None if path is not suspicious.
    """
    if not filepath:
        return None
    normalized = filepath.lower().replace("/", "\\")
    path_reasons = {
        "\\temp\\": "Executing from Temp directory",
        "\\tmp\\": "Executing from Tmp directory",
        "\\$recycle.bin\\": "Executing from Recycle Bin",
        "\\recycler\\": "Executing from Recycler folder",
        "\\downloads\\": "Executing directly from Downloads folder",
        "c:\\users\\public\\": "Executing from Public folder",
        "\\appdata\\local\\temp\\": "Executing from AppData Local Temp",
        "\\appdata\\roaming\\": "Executing from AppData Roaming",
    }
    for fragment, reason in path_reasons.items():
        if fragment in normalized:
            return reason
    return None


# ---------------------------------------------------------------------------
# System Information
# ---------------------------------------------------------------------------

def get_system_info() -> dict:
    """
    Collect comprehensive system information.

    Returns:
        Dictionary containing OS, CPU, memory, disk, and network info.
    """
    try:
        uname = platform.uname()
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        cpu_info = {
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "max_frequency_mhz": psutil.cpu_freq().max if psutil.cpu_freq() else "N/A",
            "usage_percent": psutil.cpu_percent(interval=1),
        }
        mem = psutil.virtual_memory()
        mem_info = {
            "total_gb": round(mem.total / (1024 ** 3), 2),
            "available_gb": round(mem.available / (1024 ** 3), 2),
            "used_gb": round(mem.used / (1024 ** 3), 2),
            "percent": mem.percent,
        }
        disk_partitions = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disk_partitions.append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total_gb": round(usage.total / (1024 ** 3), 2),
                    "used_gb": round(usage.used / (1024 ** 3), 2),
                    "free_gb": round(usage.free / (1024 ** 3), 2),
                    "percent": usage.percent,
                })
            except Exception:
                continue
        return {
            "hostname": socket.gethostname(),
            "os": f"{uname.system} {uname.release}",
            "os_version": uname.version,
            "machine": uname.machine,
            "processor": uname.processor,
            "python_version": sys.version,
            "boot_time": boot_time.strftime("%Y-%m-%d %H:%M:%S"),
            "cpu": cpu_info,
            "memory": mem_info,
            "disks": disk_partitions,
            "ip_address": socket.gethostbyname(socket.gethostname()),
        }
    except Exception as e:
        logger.error(f"Failed to collect system info: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Formatting Helpers
# ---------------------------------------------------------------------------

def format_bytes(byte_count: int) -> str:
    """
    Format a byte count into a human-readable string.

    Args:
        byte_count: Number of bytes.

    Returns:
        Formatted string (e.g., "1.23 MB").
    """
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(byte_count) < 1024.0:
            return f"{byte_count:.2f} {unit}"
        byte_count /= 1024.0
    return f"{byte_count:.2f} PB"


def format_timestamp(ts: Optional[float] = None) -> str:
    """
    Format a Unix timestamp or current time into a readable string.

    Args:
        ts: Unix timestamp or None for current time.

    Returns:
        Formatted datetime string.
    """
    try:
        dt = datetime.fromtimestamp(ts) if ts else datetime.now()
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize_path(path: Optional[str]) -> str:
    """
    Sanitize a file path for safe display and logging.

    Args:
        path: Raw path string.

    Returns:
        Cleaned path string.
    """
    if not path:
        return "N/A"
    return str(path).strip().replace("\x00", "")


def truncate(text: str, max_len: int = 60) -> str:
    """
    Truncate a string to a maximum length with ellipsis.

    Args:
        text: String to truncate.
        max_len: Maximum allowed length.

    Returns:
        Truncated string.
    """
    if not text:
        return ""
    return text if len(text) <= max_len else text[: max_len - 3] + "..."


def severity_color(severity: str) -> str:
    """
    Map a severity level to a terminal color code.

    Args:
        severity: Severity string (Critical, High, Medium, Low).

    Returns:
        ANSI color name suitable for Rich library.
    """
    mapping = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "white",
    }
    return mapping.get(severity.lower(), "white")


# ---------------------------------------------------------------------------
# Process Utilities
# ---------------------------------------------------------------------------

def safe_proc_attr(proc: psutil.Process, attr: str, default: Any = "N/A") -> Any:
    """
    Safely retrieve a psutil Process attribute without raising exceptions.

    Args:
        proc: psutil.Process instance.
        attr: Attribute name to retrieve.
        default: Default value if retrieval fails.

    Returns:
        Attribute value or default.
    """
    try:
        val = getattr(proc, attr)
        if callable(val):
            return val()
        return val
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return default
    except Exception:
        return default


def ensure_directory(path: str) -> None:
    """
    Ensure a directory exists, creating it if necessary.

    Args:
        path: Directory path to ensure.
    """
    Path(path).mkdir(parents=True, exist_ok=True)
