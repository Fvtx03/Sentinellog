from sentinellog.parsers import parse_line, parse_lines

YEAR = 2026


def test_failed_password_valid_user():
    ev = parse_line("Nov 14 10:22:01 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 5555 ssh2", YEAR)
    assert ev and ev.kind == "failed" and ev.user == "root" and ev.ip == "203.0.113.5"
    assert ev.ts.year == YEAR and ev.ts.hour == 10


def test_failed_password_invalid_user():
    ev = parse_line("Nov  4 01:02:03 h sshd[9]: Failed password for invalid user admin from 198.51.100.7 port 22 ssh2", YEAR)
    assert ev and ev.user == "admin" and ev.kind == "failed"


def test_accepted():
    ev = parse_line("Nov 14 03:00:00 h sshd[9]: Accepted publickey for alice from 192.0.2.4 port 40000 ssh2: RSA SHA256:x", YEAR)
    assert ev and ev.kind == "success" and ev.method == "publickey"


def test_invalid_user_line_and_empty_user():
    ev = parse_line("Nov 14 03:00:00 h sshd[9]: Invalid user  from 192.0.2.4 port 1", YEAR)
    assert ev and ev.kind == "invalid_user" and ev.user == "<empty>"


def test_iso_timestamp_with_timezone():
    ev = parse_line("2026-11-14T10:22:01.123456+01:00 h sshd[1]: Failed password for bob from 2001:db8::1 port 22 ssh2", YEAR)
    assert ev and ev.ip == "2001:db8::1" and ev.ts.hour == 10 and ev.ts.tzinfo is None


def test_ignores_noise_and_bad_ips():
    assert parse_line("Nov 14 10:22:01 h CRON[1]: session opened", YEAR) is None
    assert parse_line("Nov 14 10:22:01 h sshd[1]: Failed password for x from not-an-ip port 22 ssh2", YEAR) is None
    assert parse_line("garbage", YEAR) is None
    assert parse_line("Feb 30 10:22:01 h sshd[1]: Failed password for x from 1.2.3.4 port 22 ssh2", YEAR) is None


def test_parse_lines_skips_irrelevant():
    lines = ["noise", "Nov 14 10:22:01 h sshd[1]: Failed password for x from 1.2.3.4 port 22 ssh2"]
    assert len(parse_lines(lines, YEAR)) == 1
