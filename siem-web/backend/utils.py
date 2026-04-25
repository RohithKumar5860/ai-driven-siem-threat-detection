import logging
import sys
from datetime import datetime, timezone


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger instance."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter(
                "[%(asctime)s] [%(levelname)s] %(name)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


def current_utc_iso() -> str:
    """Return current UTC time as ISO 8601 string (timezone-aware)."""
    return datetime.now(timezone.utc).isoformat()


def clamp(value: int, min_val: int = 0, max_val: int = 100) -> int:
    """Clamp an integer value between min_val and max_val."""
    return max(min_val, min(value, max_val))


def classify_severity(score: int) -> str:
    """Classify threat severity based on numeric score."""
    if score <= 30:
        return "LOW"
    elif score <= 60:
        return "MEDIUM"
    else:
        return "HIGH"
