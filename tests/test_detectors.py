from datetime import datetime, timedelta

from sentinellog.detectors import (
    Config, densest_window, detect_brute_force, detect_off_hours,
    detect_password_spray, detect_success_after_failures, run_all,
)
from sentinellog.models import Event, Severity

T0 = datetime(2026, 11, 14, 12, 0, 0)


def fail(sec, user="root", ip="203.0.113.1"):
    return Event(T0 + timedelta(seconds=sec), "h", "failed", user, ip)


def ok(sec, user="root", ip="203.0.113.1", hour=None):
    ts = T0 + timedelta(seconds=sec)
    if hour is not None:
        ts = ts.replace(hour=hour)
    return Event(ts, "h", "success", user, ip)


def test_densest_window():
    times = [T0 + timedelta(seconds=s) for s in (0, 1, 2, 500, 501)]
    count, start, end = densest_window(times, timedelta(seconds=10))
    assert (count, start, end) == (3, times[0], times[2])


def test_brute_force_threshold_and_severity():
    cfg = Config(brute_threshold=5)
    assert detect_brute_force([fail(i) for i in range(4)], cfg) == []
    medium = detect_brute_force([fail(i) for i in range(5)], cfg)
    assert medium[0].severity == Severity.MEDIUM
    high = detect_brute_force([fail(i) for i in range(15)], cfg)
    assert high[0].severity == Severity.HIGH and high[0].count == 15


def test_brute_force_respects_window():
    cfg = Config(brute_threshold=5, window_seconds=10)
    events = [fail(i * 60) for i in range(10)]  # one per minute
    assert detect_brute_force(events, cfg) == []


def test_brute_force_is_per_ip():
    cfg = Config(brute_threshold=5)
    events = [fail(i, ip=f"203.0.113.{i}") for i in range(10)]
    assert detect_brute_force(events, cfg) == []


def test_password_spray():
    cfg = Config(spray_users=4)
    events = [fail(i, user=f"u{i}") for i in range(4)]
    findings = detect_password_spray(events, cfg)
    assert findings and findings[0].extra["distinct_users"] == 4
    assert detect_password_spray(events[:3], cfg) == []


def test_success_after_failures_is_critical():
    cfg = Config(compromise_threshold=3)
    events = [fail(i) for i in range(3)] + [ok(10)]
    findings = detect_success_after_failures(events, cfg)
    assert findings and findings[0].severity == Severity.CRITICAL


def test_success_without_enough_failures_or_wrong_ip():
    cfg = Config(compromise_threshold=3)
    assert detect_success_after_failures([fail(0), fail(1), ok(10)], cfg) == []
    assert detect_success_after_failures([fail(i) for i in range(3)] + [ok(10, ip="192.0.2.1")], cfg) == []


def test_failures_after_success_do_not_count():
    cfg = Config(compromise_threshold=3)
    events = [ok(0)] + [fail(i) for i in range(1, 5)]
    assert detect_success_after_failures(events, cfg) == []


def test_off_hours():
    cfg = Config(off_hours=(0, 5))
    assert len(detect_off_hours([ok(0, hour=3)], cfg)) == 1
    assert detect_off_hours([ok(0, hour=12)], cfg) == []
    assert detect_off_hours([ok(0, hour=3)], Config(off_hours=None)) == []
    wrap = Config(off_hours=(22, 5))
    assert len(detect_off_hours([ok(0, hour=23)], wrap)) == 1


def test_run_all_sorted_by_severity():
    cfg = Config(brute_threshold=5, compromise_threshold=3)
    events = [fail(i) for i in range(6)] + [ok(10)]
    findings = run_all(events, cfg)
    assert findings[0].severity == Severity.CRITICAL
    assert [int(f.severity) for f in findings] == sorted((int(f.severity) for f in findings), reverse=True)
