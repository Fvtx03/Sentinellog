"""Parsers for OpenSSH (sshd) authentication log lines.

Supports both classic syslog timestamps (``Nov 14 10:22:01``) and ISO-8601
timestamps (``2026-11-14T10:22:01+01:00``) as written by rsyslog/journald.
Timestamps are normalised to naive wall-clock datetimes.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Iterable, List, Optional

from .models import Event

_SYSLOG = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>.*?) from (?P<ip>\S+) port \d+"
)
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>.*?) from (?P<ip>\S+) port \d+"
)
_INVALID = re.compile(r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)")


def _parse_ts(raw: str, year: int, iso: bool) -> Optional[datetime]:
    try:
        if iso:
            text = raw.replace("Z", "+00:00")
            return datetime.fromisoformat(text).replace(tzinfo=None)
        return datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_line(line: str, year: int) -> Optional[Event]:
    """Parse one log line into an :class:`Event`, or ``None`` if irrelevant."""
    line = line.rstrip("\r\n")
    iso = False
    match = _SYSLOG.match(line)
    if not match:
        match = _ISO.match(line)
        iso = True
    if not match:
        return None

    ts = _parse_ts(match["ts"], year, iso)
    if ts is None:
        return None
    msg = match["msg"]

    for kind, pattern in (
        ("failed", _FAILED),
        ("success", _ACCEPTED),
        ("invalid_user", _INVALID),
    ):
        found = pattern.match(msg)
        if found and _valid_ip(found["ip"]):
            groups = found.groupdict()
            return Event(
                ts=ts,
                host=match["host"],
                kind=kind,
                user=groups["user"] or "<empty>",
                ip=groups["ip"],
                method=groups.get("method", "") or "",
            )
    return None


def parse_lines(lines: Iterable[str], year: int) -> List[Event]:
    """Parse many lines, silently skipping anything that is not an auth event."""
    events = []
    for line in lines:
        event = parse_line(line, year)
        if event is not None:
            events.append(event)
    return events
