"""Data models shared across SentinelLog."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any, Dict, List


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            names = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (choose from {names})") from exc


@dataclass(frozen=True)
class Event:
    """A single parsed authentication event."""

    ts: datetime  # naive, wall-clock time as written in the log
    host: str
    kind: str  # "failed" | "success" | "invalid_user"
    user: str
    ip: str
    method: str = ""


@dataclass
class Finding:
    """A detection produced by one of the rules."""

    rule: str
    severity: Severity
    ip: str
    users: List[str]
    count: int
    first_seen: datetime
    last_seen: datetime
    description: str
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity.name.lower(),
            "ip": self.ip,
            "users": self.users,
            "count": self.count,
            "first_seen": self.first_seen.isoformat(sep=" "),
            "last_seen": self.last_seen.isoformat(sep=" "),
            "description": self.description,
            **self.extra,
        }
