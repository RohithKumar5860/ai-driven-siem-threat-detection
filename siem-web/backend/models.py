from pydantic import BaseModel, Field, field_validator
from typing import Literal
from datetime import datetime, timezone
import uuid


def _utcnow_iso() -> str:
    """Return current UTC time as ISO 8601 string (timezone-aware)."""
    return datetime.now(timezone.utc).isoformat()


class LogEntry(BaseModel):
    """Input model for a log entry submitted via the API."""
    source_ip: str = Field(..., description="Source IP address of the event")
    port: int = Field(..., ge=1, le=65535, description="Destination port number")
    payload_size: int = Field(..., ge=0, description="Size of the payload in bytes")
    action: Literal["login_failed", "normal"] = Field(..., description="Type of action")

    @field_validator("source_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        import re
        pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if not re.match(pattern, v):
            raise ValueError(f"Invalid IP address format: {v}")
        parts = v.split(".")
        for part in parts:
            if int(part) > 255:
                raise ValueError(f"Invalid IP address octet: {part}")
        return v


class ProcessedLog(BaseModel):
    """Fully processed log entry stored in logs.json."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_ip: str
    port: int
    payload_size: int
    action: str
    timestamp: str = Field(default_factory=_utcnow_iso)
    rule_score: int = 0
    ml_score: int = 0
    total_score: int = 0
    severity: str = "LOW"
    is_threat: bool = False
    ml_anomaly: bool = False
    blocked: bool = False


class LogResponse(BaseModel):
    """Response returned after submitting a log."""
    message: str
    log: ProcessedLog


class BlockedIPEntry(BaseModel):
    """A single blocked IP record."""
    ip: str
    blocked_at: str
    reason: str
