"""Command-line interface."""
from __future__ import annotations

import argparse
import gzip
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from . import __version__
from .detectors import Config, run_all
from .models import Severity
from .parsers import parse_lines
from .report import blocklist, render_html, render_json, render_text
from .samples import generate

_RENDERERS = {"text": render_text, "json": render_json, "html": render_html}


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer")
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _year(value: str) -> int:
    number = _positive_int(value)
    if number > 9999:
        raise argparse.ArgumentTypeError("year must be within 1-9999")
    return number


def _off_hours(value: str) -> Optional[Tuple[int, int]]:
    if value.lower() in {"none", "off"}:
        return None
    try:
        start, end = (int(part) for part in value.split("-"))
    except ValueError:
        raise argparse.ArgumentTypeError("use START-END hours like 0-5, or 'none'")
    if not (0 <= start <= 23 and 0 <= end <= 24):
        raise argparse.ArgumentTypeError("hours must be within 0-24")
    return start, end


def _read(path: str) -> List[str]:
    if path == "-":
        return sys.stdin.read().splitlines()
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        return handle.read().splitlines()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinellog", description="Detect SSH brute force, spraying and likely compromise."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyze one or more auth logs ('-' for stdin, .gz supported)")
    a.add_argument("files", nargs="+")
    a.add_argument("--format", choices=sorted(_RENDERERS), default="text")
    a.add_argument("--output", "-o", help="write the report to this file")
    a.add_argument("--blocklist", help="also write HIGH+ source IPs to this file")
    a.add_argument("--year", type=_year, default=datetime.now().year,
                   help="year for syslog timestamps that lack one (default: current year)")
    a.add_argument("--window", type=_positive_int, default=300, help="detection window in seconds (default 300)")
    a.add_argument("--brute-threshold", type=_positive_int, default=8, help="failures per window (default 8)")
    a.add_argument("--spray-users", type=_positive_int, default=5, help="distinct usernames per window (default 5)")
    a.add_argument("--compromise-threshold", type=_positive_int, default=5,
                   help="failures before a success that raise a critical finding (default 5)")
    a.add_argument("--off-hours", type=_off_hours, default=(0, 5),
                   help="off-hours range START-END or 'none' (default 0-5)")
    a.add_argument("--fail-on", choices=[s.name.lower() for s in Severity],
                   help="exit with code 2 if a finding at this severity or above exists (for CI)")

    g = sub.add_parser("sample", help="print a synthetic demo log (documentation IPs only)")
    g.add_argument("--seed", type=int, default=7)
    return parser


def _analyze(args: argparse.Namespace) -> int:
    lines: List[str] = []
    for path in args.files:
        try:
            lines.extend(_read(path))
        except (OSError, EOFError) as exc:
            print(f"sentinellog: cannot read {path}: {getattr(exc, 'strerror', None) or exc}", file=sys.stderr)
            return 1

    events = parse_lines(lines, args.year)
    cfg = Config(
        window_seconds=args.window,
        brute_threshold=args.brute_threshold,
        spray_users=args.spray_users,
        compromise_threshold=args.compromise_threshold,
        off_hours=args.off_hours,
    )
    findings = run_all(events, cfg)
    report = _RENDERERS[args.format](events, findings)

    try:
        if args.output:
            Path(args.output).write_text(report, encoding="utf-8")
        else:
            print(report)
        if args.blocklist:
            ips = blocklist(findings)
            Path(args.blocklist).write_text("".join(ip + "\n" for ip in ips), encoding="utf-8")
    except OSError as exc:
        print(f"sentinellog: cannot write output: {exc.strerror or exc}", file=sys.stderr)
        return 1

    if args.fail_on and any(f.severity >= Severity.parse(args.fail_on) for f in findings):
        return 2
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "sample":
        print("\n".join(generate(seed=args.seed)))
        return 0
    return _analyze(args)


if __name__ == "__main__":
    raise SystemExit(main())
