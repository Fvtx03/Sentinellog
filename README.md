# SentinelLog

**Defensive SSH auth-log analyzer.** Feed it `/var/log/auth.log` (or journald/rsyslog output) and it tells you who is brute-forcing you, who is spraying usernames, and — most importantly — **who got in after hammering the door**.

- Zero dependencies (Python standard library only), Python 3.9+
- Read-only: never touches the network or your system
- Text, JSON and self-contained HTML reports
- CI-friendly exit codes and a ready-to-use IP blocklist
- Rules are small pure functions, so adding your own takes minutes

## Install

```bash
git clone https://github.com/Fvtx/sentinellog.git
cd sentinellog
pip install -e .
```

## Quick start

```bash
sentinellog sample > demo.log                      # synthetic data (documentation IPs only)
sentinellog analyze demo.log --year 2026           # text report
sentinellog analyze /var/log/auth.log --format html -o report.html
zcat /var/log/auth.log.*.gz | sentinellog analyze - --format json
```

Example output:

```
[CRITICAL] success_after_failures  203.0.113.99  users=deploy  count=12
    Successful login as 'deploy' from 203.0.113.99 right after 12 failed attempts - possible credential compromise.
[HIGH] brute_force  203.0.113.10  users=root  count=40
[HIGH] password_spray  198.51.100.77  users=admin,backup,dev,ftp,git,guest  count=15
...
Suggested blocklist (HIGH and above):
  198.51.100.77
  203.0.113.10
  203.0.113.99
```

## Detection rules

| Rule | Severity | Triggers when |
|------|----------|---------------|
| `success_after_failures` | critical | A login succeeds from an IP that failed ≥ N times in the preceding window |
| `brute_force` | medium / high | ≥ N failed logins from one IP within the window (high at 3× threshold) |
| `password_spray` | high | One IP fails against ≥ N different usernames within the window |
| `off_hours_login` | low | A successful login happens inside the off-hours range |

## Options

| Flag | Default | Meaning |
|------|---------|---------|
| `--format text\|json\|html` | text | Report format |
| `-o, --output FILE` | stdout | Write report to a file |
| `--blocklist FILE` | – | Write HIGH+ source IPs, one per line |
| `--year YYYY` | current | Year for syslog timestamps (they have none) |
| `--window SECONDS` | 300 | Detection window |
| `--brute-threshold N` | 8 | Failures per window |
| `--spray-users N` | 5 | Distinct usernames per window |
| `--compromise-threshold N` | 5 | Failures before a success |
| `--off-hours START-END\|none` | 0-5 | Off-hours range (wraps, e.g. `22-5`) |
| `--fail-on SEVERITY` | – | Exit code 2 if a finding at/above this level exists |

Files ending in `.gz` are read transparently; `-` reads stdin.

## Use it in a cron job or CI

```bash
sentinellog analyze /var/log/auth.log --format html --fail-on high --blocklist /tmp/block.txt -o /tmp/report.html \
  || mail -s "SSH alert" admin@example.com < /tmp/report.html
```

Review the blocklist before feeding it to a firewall — shared NATs and your own scanners can look like attackers.

## Project layout

```
src/sentinellog/
  parsers.py    sshd log lines -> Event (syslog + ISO-8601 timestamps, IPv4/IPv6)
  detectors.py  detection rules and sliding-window helpers
  report.py     text / JSON / HTML renderers, blocklist
  samples.py    synthetic log generator
  cli.py        argparse interface
tests/          parser, detector and CLI tests
```

## Add your own rule

```python
# src/sentinellog/detectors.py
def detect_root_login(events, cfg):
    return [Finding(rule="root_login", severity=Severity.MEDIUM, ip=e.ip, users=[e.user],
                    count=1, first_seen=e.ts, last_seen=e.ts,
                    description=f"Direct root login from {e.ip}")
            for e in events if e.kind == "success" and e.user == "root"]

RULES.append(detect_root_login)
```

## Limitations

- Only OpenSSH `sshd` messages are parsed so far.
- Syslog timestamps have no year/timezone: use `--year`; ISO timestamps are treated as local wall-clock time.
- Detection is heuristic and per-IP, so a distributed attack from many IPs can stay under the thresholds. Tune them for your environment.
- Input files are loaded into memory; very large logs should be split before analysis.
- For classic syslog files spanning New Year, split by year and analyze each part with the correct `--year`.
- An empty report can also mean the input format was not recognized. Check the parsed event count.
- Reports and blocklists can contain sensitive IP addresses and usernames. Do not commit real logs or reports.

## Roadmap

- [ ] nginx/Apache auth failures, Windows Event ID 4625 (CSV export)
- [ ] Distributed brute-force detection (shared username target across IPs)
- [ ] Optional GeoIP/ASN enrichment from a local database
- [ ] `--watch` mode for live tailing

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT — see [LICENSE](LICENSE). Replace `YOUR NAME` in the license file with your own.
