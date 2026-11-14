import gzip

import pytest

from sentinellog.cli import main


@pytest.mark.parametrize(
    "option,value",
    [
        ("--window", "-1"),
        ("--window", "0"),
        ("--brute-threshold", "0"),
        ("--spray-users", "-2"),
        ("--compromise-threshold", "0"),
        ("--year", "0"),
        ("--year", "10000"),
        ("--window", "hello"),
        ("--off-hours", "25-5"),
    ],
)
def test_invalid_arguments_exit_cleanly(option, value):
    with pytest.raises(SystemExit) as exc:
        main(["analyze", "-", option, value])
    assert exc.value.code == 2


def test_unwritable_report_returns_1(tmp_path, capsys):
    log = tmp_path / "empty.log"
    log.write_text("", encoding="utf-8")
    assert main(["analyze", str(log), "-o", str(tmp_path)]) == 1
    assert "cannot write output" in capsys.readouterr().err


def test_unwritable_blocklist_returns_1(tmp_path, capsys):
    log = tmp_path / "empty.log"
    log.write_text("", encoding="utf-8")
    assert main(["analyze", str(log), "--blocklist", str(tmp_path)]) == 1
    assert "cannot write output" in capsys.readouterr().err


def test_empty_blocklist_is_empty_file(tmp_path):
    log = tmp_path / "empty.log"
    log.write_text("", encoding="utf-8")
    blocklist = tmp_path / "blocklist.txt"
    assert main(["analyze", str(log), "--blocklist", str(blocklist)]) == 0
    assert blocklist.read_bytes() == b""


def test_gzip_input(tmp_path):
    log = tmp_path / "auth.log.gz"
    with gzip.open(log, "wt", encoding="utf-8") as handle:
        handle.write("Nov 14 12:00:00 h sshd[1]: Accepted publickey for alice from 192.0.2.1 port 22 ssh2\n")
    assert main(["analyze", str(log), "--year", "2026"]) == 0


def test_truncated_gzip_returns_1(tmp_path, capsys):
    log = tmp_path / "broken.log.gz"
    log.write_bytes(gzip.compress(b"test log")[:-5])
    assert main(["analyze", str(log)]) == 1
    assert "cannot read" in capsys.readouterr().err
