"""Detection rules.

Every rule is a pure function ``(events, config) -> list[Finding]`` so rules are
easy to test and to extend. Only ``failed`` events count as failed attempts;
``invalid_user`` lines are informational (sshd emits them *in addition to* the
matching "Failed password" line, so counting both would double-count).
"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from .models import Event, Finding, Severity


@dataclass
class Config:
    window_seconds: int = 300
    brute_threshold: int = 8
    spray_users: int = 5
    compromise_threshold: int = 5
    off_hours: Optional[Tuple[int, int]] = (0, 5)  # [start, end) in hours; None disables

    @property
    def window(self) -> timedelta:
        return timedelta(seconds=self.window_seconds)


def densest_window(
    times: Sequence[datetime], window: timedelta
) -> Tuple[int, Optional[datetime], Optional[datetime]]:
    """Return (count, start, end) of the busiest window. ``times`` must be sorted."""
    best: Tuple[int, Optional[datetime], Optional[datetime]] = (0, None, None)
    left = 0
    for right, ts in enumerate(times):
        while ts - times[left] > window:
            left += 1
        count = right - left + 1
        if count > best[0]:
            best = (count, times[left], ts)
    return best


def _max_distinct_users(
    events: Sequence[Event], window: timedelta
) -> Tuple[int, Optional[datetime], Optional[datetime], Set[str]]:
    queue: deque = deque()
    counts: Counter = Counter()
    best: Tuple[int, Optional[datetime], Optional[datetime], Set[str]] = (0, None, None, set())
    for event in events:
        queue.append(event)
        counts[event.user] += 1
        while event.ts - queue[0].ts > window:
            old = queue.popleft()
            counts[old.user] -= 1
            if counts[old.user] == 0:
                del counts[old.user]
        if len(counts) > best[0]:
            best = (len(counts), queue[0].ts, event.ts, set(counts))
    return best


def _failed_by_ip(events: Sequence[Event]) -> Dict[str, List[Event]]:
    grouped: Dict[str, List[Event]] = defaultdict(list)
    for event in events:
        if event.kind == "failed":
            grouped[event.ip].append(event)
    for items in grouped.values():
        items.sort(key=lambda e: e.ts)
    return grouped


def detect_brute_force(events: Sequence[Event], cfg: Config) -> List[Finding]:
    findings = []
    for ip, items in _failed_by_ip(events).items():
        count, start, end = densest_window([e.ts for e in items], cfg.window)
        if count < cfg.brute_threshold:
            continue
        users = sorted({e.user for e in items if start <= e.ts <= end})
        severity = Severity.HIGH if count >= cfg.brute_threshold * 3 else Severity.MEDIUM
        findings.append(
            Finding(
                rule="brute_force",
                severity=severity,
                ip=ip,
                users=users,
                count=count,
                first_seen=start,
                last_seen=end,
                description=f"{count} failed logins from {ip} within {cfg.window_seconds}s.",
            )
        )
    return findings


def detect_password_spray(events: Sequence[Event], cfg: Config) -> List[Finding]:
    findings = []
    for ip, items in _failed_by_ip(events).items():
        distinct, start, end, users = _max_distinct_users(items, cfg.window)
        if distinct < cfg.spray_users:
            continue
        attempts = sum(1 for e in items if start <= e.ts <= end)
        findings.append(
            Finding(
                rule="password_spray",
                severity=Severity.HIGH,
                ip=ip,
                users=sorted(users),
                count=attempts,
                first_seen=start,
                last_seen=end,
                description=(
                    f"{ip} tried {distinct} different usernames within "
                    f"{cfg.window_seconds}s (username enumeration / spraying)."
                ),
                extra={"distinct_users": distinct},
            )
        )
    return findings


def detect_success_after_failures(events: Sequence[Event], cfg: Config) -> List[Finding]:
    failed_times = {ip: [e.ts for e in items] for ip, items in _failed_by_ip(events).items()}
    best: Dict[Tuple[str, str], Finding] = {}
    for event in sorted((e for e in events if e.kind == "success"), key=lambda e: e.ts):
        times = failed_times.get(event.ip)
        if not times:
            continue
        low = bisect_left(times, event.ts - cfg.window)
        high = bisect_right(times, event.ts)
        failures = high - low
        if failures < cfg.compromise_threshold:
            continue
        key = (event.ip, event.user)
        if key in best and best[key].count >= failures:
            continue
        best[key] = Finding(
            rule="success_after_failures",
            severity=Severity.CRITICAL,
            ip=event.ip,
            users=[event.user],
            count=failures,
            first_seen=times[low],
            last_seen=event.ts,
            description=(
                f"Successful login as '{event.user}' from {event.ip} right after "
                f"{failures} failed attempts - possible credential compromise."
            ),
        )
    return list(best.values())


def _in_hours(hour: int, span: Tuple[int, int]) -> bool:
    start, end = span
    return start <= hour < end if start <= end else hour >= start or hour < end


def detect_off_hours(events: Sequence[Event], cfg: Config) -> List[Finding]:
    if cfg.off_hours is None:
        return []
    groups: Dict[Tuple[str, str], List[Event]] = defaultdict(list)
    for event in events:
        if event.kind == "success" and _in_hours(event.ts.hour, cfg.off_hours):
            groups[(event.user, event.ip)].append(event)
    findings = []
    for (user, ip), items in groups.items():
        items.sort(key=lambda e: e.ts)
        findings.append(
            Finding(
                rule="off_hours_login",
                severity=Severity.LOW,
                ip=ip,
                users=[user],
                count=len(items),
                first_seen=items[0].ts,
                last_seen=items[-1].ts,
                description=(
                    f"'{user}' logged in from {ip} between "
                    f"{cfg.off_hours[0]:02d}:00 and {cfg.off_hours[1]:02d}:00."
                ),
            )
        )
    return findings


RULES: List[Callable[[Sequence[Event], Config], List[Finding]]] = [
    detect_brute_force,
    detect_password_spray,
    detect_success_after_failures,
    detect_off_hours,
]


def run_all(events: Sequence[Event], cfg: Optional[Config] = None) -> List[Finding]:
    cfg = cfg or Config()
    findings: List[Finding] = []
    for rule in RULES:
        findings.extend(rule(events, cfg))
    findings.sort(key=lambda f: (-int(f.severity), -f.count, f.ip))
    return findings
