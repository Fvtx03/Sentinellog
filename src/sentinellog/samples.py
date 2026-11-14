"""Synthetic log generator for demos and tests.

Uses only RFC 5737 documentation IP ranges, so nothing here refers to real hosts.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import List, Tuple

_USERS = ["alice", "bob", "carol"]
_SPRAY = ["admin", "test", "oracle", "ubuntu", "guest", "postgres", "git",
          "jenkins", "ftp", "user", "support", "pi", "dev", "backup", "mysql"]


def generate(seed: int = 7, day: datetime = datetime(2026, 11, 14)) -> List[str]:
    rng = random.Random(seed)
    rows: List[Tuple[datetime, str]] = []

    def stamp(ts: datetime) -> str:
        return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"

    def add(ts: datetime, msg: str) -> None:
        rows.append((ts, f"{stamp(ts)} web01 sshd[{rng.randint(1000, 60000)}]: {msg}"))

    def failed(ts: datetime, user: str, ip: str, invalid: bool = False) -> None:
        port = rng.randint(30000, 65000)
        prefix = "invalid user " if invalid else ""
        if invalid:
            add(ts, f"Invalid user {user} from {ip} port {port}")
        add(ts, f"Failed password for {prefix}{user} from {ip} port {port} ssh2")

    def ok(ts: datetime, user: str, ip: str, method: str) -> None:
        add(ts, f"Accepted {method} for {user} from {ip} port {rng.randint(30000, 65000)} ssh2")

    # Normal daytime logins
    for i, user in enumerate(_USERS):
        ok(day + timedelta(hours=9 + i, minutes=rng.randint(0, 59)), user, f"192.0.2.{10 + i}", "publickey")

    # 1) Brute force against root
    start = day + timedelta(hours=2, minutes=10)
    for i in range(40):
        failed(start + timedelta(seconds=3 * i), "root", "203.0.113.10")

    # 2) Password spraying across many usernames
    start = day + timedelta(hours=9, minutes=30)
    for i, user in enumerate(_SPRAY):
        failed(start + timedelta(seconds=10 * i), user, "198.51.100.77", invalid=True)

    # 3) Brute force followed by a successful login (likely compromise)
    start = day + timedelta(hours=3, minutes=38)
    for i in range(12):
        failed(start + timedelta(seconds=5 * i), "deploy", "203.0.113.99")
    ok(day + timedelta(hours=3, minutes=40), "deploy", "203.0.113.99", "password")

    # 4) Off-hours login by a legitimate user
    ok(day + timedelta(hours=3, minutes=5), "alice", "192.0.2.44", "publickey")

    rows.sort(key=lambda item: item[0])
    return [line for _, line in rows]
