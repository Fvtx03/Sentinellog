"""Report renderers: text, JSON, HTML, plus a firewall-friendly blocklist."""
from __future__ import annotations

import ipaddress
import json
from collections import Counter
from html import escape
from typing import Any, Dict, List, Sequence

from .models import Event, Finding, Severity


def build_summary(events: Sequence[Event], findings: Sequence[Finding]) -> Dict[str, Any]:
    failed = [e for e in events if e.kind == "failed"]
    return {
        "events_total": len(events),
        "failed_logins": len(failed),
        "successful_logins": sum(1 for e in events if e.kind == "success"),
        "unique_source_ips": len({e.ip for e in events}),
        "top_attacking_ips": Counter(e.ip for e in failed).most_common(10),
        "top_targeted_users": Counter(e.user for e in failed).most_common(10),
        "findings_by_severity": {
            s.name.lower(): sum(1 for f in findings if f.severity == s)
            for s in sorted(Severity, reverse=True)
        },
    }


def blocklist(findings: Sequence[Finding], minimum: Severity = Severity.HIGH) -> List[str]:
    """Unique IPs behind findings at or above ``minimum`` severity."""
    ips = {f.ip for f in findings if f.severity >= minimum}
    return sorted(ips, key=lambda s: (ipaddress.ip_address(s).version, ipaddress.ip_address(s)))


def render_json(events: Sequence[Event], findings: Sequence[Finding]) -> str:
    payload = {
        "summary": build_summary(events, findings),
        "findings": [f.to_dict() for f in findings],
        "blocklist": blocklist(findings),
    }
    return json.dumps(payload, indent=2)


def render_text(events: Sequence[Event], findings: Sequence[Finding]) -> str:
    s = build_summary(events, findings)
    out = ["SentinelLog report", "=" * 18]
    out.append(
        f"Events: {s['events_total']}  Failed: {s['failed_logins']}  "
        f"Successful: {s['successful_logins']}  Unique IPs: {s['unique_source_ips']}"
    )
    sev = ", ".join(f"{k}={v}" for k, v in s["findings_by_severity"].items())
    out.append(f"Findings: {len(findings)} ({sev})")
    out.append("")
    if not findings:
        out.append("No suspicious activity detected.")
    for f in findings:
        out.append(f"[{f.severity.name}] {f.rule}  {f.ip}  users={','.join(f.users[:6])}  count={f.count}")
        out.append(f"    {f.first_seen.isoformat(sep=' ')} -> {f.last_seen.isoformat(sep=' ')}")
        out.append(f"    {f.description}")
    block = blocklist(findings)
    if block:
        out += ["", "Suggested blocklist (HIGH and above):"] + [f"  {ip}" for ip in block]
    return "\n".join(out)


_CSS = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#656d76;--line:#d0d7de;--card:#f6f8fa}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#8b949e;--line:#30363d;--card:#161b22}}
body{font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);max-width:1000px;margin:2rem auto;padding:0 1rem}
.cards{display:flex;gap:.75rem;flex-wrap:wrap;margin:1rem 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.6rem 1rem}
.card b{display:block;font-size:1.4rem}
table{border-collapse:collapse;width:100%;display:block;overflow-x:auto}
th,td{border-bottom:1px solid var(--line);padding:.45rem .6rem;text-align:left;vertical-align:top}
.badge{padding:.1rem .5rem;border-radius:999px;font-size:.8rem;font-weight:600;color:#fff}
.critical{background:#cf222e}.high{background:#d1531f}.medium{background:#9a6700}.low{background:#57606a}
.muted{color:var(--muted)}
"""


def render_html(events: Sequence[Event], findings: Sequence[Finding]) -> str:
    s = build_summary(events, findings)
    cards = "".join(
        f'<div class="card"><b>{escape(str(v))}</b><span class="muted">{escape(k)}</span></div>'
        for k, v in [
            ("events", s["events_total"]),
            ("failed logins", s["failed_logins"]),
            ("successful logins", s["successful_logins"]),
            ("unique IPs", s["unique_source_ips"]),
            ("findings", len(findings)),
        ]
    )
    rows = "".join(
        "<tr>"
        f'<td><span class="badge {f.severity.name.lower()}">{f.severity.name}</span></td>'
        f"<td>{escape(f.rule)}</td><td>{escape(f.ip)}</td>"
        f"<td>{escape(', '.join(f.users[:8]))}</td><td>{f.count}</td>"
        f"<td>{escape(f.first_seen.isoformat(sep=' '))}</td>"
        f"<td>{escape(f.description)}</td></tr>"
        for f in findings
    ) or '<tr><td colspan="7">No suspicious activity detected.</td></tr>'
    block = "".join(f"<li><code>{escape(ip)}</code></li>" for ip in blocklist(findings))
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>SentinelLog report</title><style>{_CSS}</style></head><body>"
        f"<h1>SentinelLog report</h1><div class=\"cards\">{cards}</div>"
        "<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Rule</th><th>Source IP</th>"
        "<th>Users</th><th>Count</th><th>First seen</th><th>Details</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        f"<h2>Suggested blocklist</h2><ul>{block or '<li class=\"muted\">None</li>'}</ul>"
        "</body></html>"
    )
