import json
import os
import threading
from typing import List, Dict, Any
from backend.utils import get_logger, current_utc_iso

logger = get_logger(__name__)

# Resolve absolute paths relative to this file's location
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_FILE = os.path.join(_BASE_DIR, "data", "logs.json")
BLOCKED_IPS_FILE = os.path.join(_BASE_DIR, "data", "blocked_ips.json")

# Thread locks for safe concurrent access
_logs_lock = threading.Lock()
_blocked_lock = threading.Lock()


def _ensure_file(path: str, default: Any) -> None:
    """Create the file with a default value if it does not exist."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=2)


def _read_json(path: str, default: Any) -> Any:
    """Read JSON from a file; return default on error."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return default
            return json.loads(content)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.warning(f"Failed to read {path}: {e}. Returning default.")
        return default


def _write_json(path: str, data: Any) -> None:
    """Atomically write JSON to a file via a temp file."""
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, path)


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

def init_storage() -> None:
    """Initialize storage files if they do not exist."""
    _ensure_file(LOGS_FILE, [])
    _ensure_file(BLOCKED_IPS_FILE, [])
    logger.info("Storage initialized.")


def get_all_logs() -> List[Dict]:
    with _logs_lock:
        return _read_json(LOGS_FILE, [])


def save_log(log_dict: Dict) -> None:
    with _logs_lock:
        logs = _read_json(LOGS_FILE, [])
        logs.append(log_dict)
        _write_json(LOGS_FILE, logs)


def get_threats() -> List[Dict]:
    with _logs_lock:
        logs = _read_json(LOGS_FILE, [])
        return [log for log in logs if log.get("is_threat", False)]


# ---------------------------------------------------------------------------
# Blocked IPs
# ---------------------------------------------------------------------------

def get_blocked_ips() -> List[Dict]:
    with _blocked_lock:
        return _read_json(BLOCKED_IPS_FILE, [])


def is_ip_blocked(ip: str) -> bool:
    blocked = get_blocked_ips()
    return any(entry.get("ip") == ip for entry in blocked)


def block_ip(ip: str, reason: str = "Score >= 70") -> bool:
    """Add IP to blocked list; returns True if newly blocked, False if already present."""
    with _blocked_lock:
        blocked = _read_json(BLOCKED_IPS_FILE, [])
        if any(entry.get("ip") == ip for entry in blocked):
            return False
        blocked.append({
            "ip": ip,
            "blocked_at": current_utc_iso(),
            "reason": reason,
        })
        _write_json(BLOCKED_IPS_FILE, blocked)
        logger.info(f"IP blocked: {ip} - {reason}")
        return True
