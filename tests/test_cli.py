import json

from sentinellog.cli import main
from sentinellog.samples import generate


def make_log(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("\n".join(generate()) + "\n", encoding="utf-8")
    return str(path)


def test_sample_finds_all_rules(tmp_path):
    log, out = make_log(tmp_path), tmp_path / "r.json"
    assert main(["analyze", log, "--year", "2026", "--format", "json", "-o", str(out)]) == 0
    data = json.loads(out.read_text())
    rules = {f["rule"] for f in data["findings"]}
    assert rules == {"brute_force", "password_spray", "success_after_failures", "off_hours_login"}
    assert "203.0.113.99" in data["blocklist"] and "192.0.2.44" not in data["blocklist"]


def test_fail_on_exit_code(tmp_path):
    log = make_log(tmp_path)
    assert main(["analyze", log, "--year", "2026", "--fail-on", "critical", "-o", str(tmp_path / "x")]) == 2
    assert main(["analyze", log, "--year", "2026", "--brute-threshold", "999", "--spray-users", "999",
                 "--compromise-threshold", "999", "--off-hours", "none", "--fail-on", "low",
                 "-o", str(tmp_path / "x")]) == 0


def test_html_is_escaped(tmp_path):
    log = tmp_path / "evil.log"
    lines = [f"Nov 14 12:00:{i:02d} h sshd[1]: Failed password for invalid user <script>alert(1)</script> from 203.0.113.5 port 22 ssh2"
             for i in range(10)]
    log.write_text("\n".join(lines))
    out = tmp_path / "r.html"
    main(["analyze", str(log), "--year", "2026", "--format", "html", "-o", str(out)])
    html = out.read_text()
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


def test_missing_file_returns_1(tmp_path, capsys):
    assert main(["analyze", str(tmp_path / "nope.log")]) == 1
    assert "cannot read" in capsys.readouterr().err


def test_blocklist_file(tmp_path):
    log, bl = make_log(tmp_path), tmp_path / "bl.txt"
    main(["analyze", log, "--year", "2026", "--blocklist", str(bl), "-o", str(tmp_path / "x")])
    assert "203.0.113.10" in bl.read_text().split()
