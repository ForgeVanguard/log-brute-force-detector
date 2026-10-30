"""Tests run against the SYNTHETIC samples in samples/."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from lbfd.cli import main
from lbfd.detector import detect, parse_line, parse_lines

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
BASH = ROOT / "bash" / "ssh-bruteforce-detect.sh"


def load(name):
    with open(SAMPLES / name, encoding="utf-8") as fh:
        return list(parse_lines(fh, 2026))


def rules(alerts):
    return sorted((a.rule, a.src_ip) for a in alerts)


def test_parse_failed_invalid_user():
    ev = parse_line("Mar  3 09:20:05 lab-target01 sshd[4151]: Failed password for invalid user admin from 203.0.113.50 port 51001 ssh2", 2026)
    assert ev.outcome == "failure" and ev.user == "admin" and ev.src_ip == "203.0.113.50"


def test_parse_accepted_publickey():
    ev = parse_line("Mar  4 08:00:00 lab-target01 sshd[6000]: Accepted publickey for labadmin from 192.0.2.10 port 50000 ssh2", 2026)
    assert ev.outcome == "success" and ev.user == "labadmin"


def test_parse_iso_timestamp():
    ev = parse_line("2026-03-03T09:10:00.123456+00:00 lab-target01 sshd[1]: Failed password for root from 198.51.100.9 port 22 ssh2", 2026)
    assert ev is not None and ev.timestamp.year == 2026


@pytest.mark.parametrize("line", [
    "Mar  3 09:20:05 lab-target01 sshd[4151]: Invalid user admin from 203.0.113.50 port 51001",
    "Mar  3 09:00:30 lab-target01 sshd[4101]: Connection closed by 192.0.2.11 port 41000 [preauth]",
    "# SYNTHETIC SAMPLE DATA",
    "Mar  3 09:00:00 lab-target01 CRON[1]: pam_unix(cron:session): session opened",
])
def test_ignored_lines(line):
    assert parse_line(line, 2026) is None


def test_sample_alerts():
    alerts = detect(load("auth.log"))
    assert rules(alerts) == [
        ("BRUTE_FORCE", "198.51.100.23"),
        ("BRUTE_FORCE", "203.0.113.50"),
        ("PASSWORD_SPRAY", "203.0.113.50"),
        ("SUCCESS_AFTER_FAILURES", "198.51.100.23"),
    ]


def test_burst_is_one_alert_with_full_count():
    bf = [a for a in detect(load("auth.log")) if a.rule == "BRUTE_FORCE" and a.src_ip == "198.51.100.23"]
    assert len(bf) == 1 and bf[0].count == 12


def test_benign_admin_typo_and_slow_failures_do_not_alert():
    ips = {a.src_ip for a in detect(load("auth.log"))}
    assert "192.0.2.10" not in ips      # one typo then success
    assert "198.51.100.77" not in ips   # 4 failures spread over 15 minutes


def test_slow_failures_alert_with_wider_window():
    alerts = detect(load("auth.log"), threshold=4, window_seconds=3600)
    assert ("BRUTE_FORCE", "198.51.100.77") in rules(alerts)


def test_benign_log_is_clean():
    assert detect(load("auth_benign.log")) == []


def test_allowlist_cidr():
    alerts = detect(load("auth.log"), allowlist={"203.0.113.0/24"})
    assert all(a.src_ip != "203.0.113.50" for a in alerts)


def test_cli_json(capsys):
    rc = main(["--json", "--year", "2026", str(SAMPLES / "auth.log")])
    out = [json.loads(l) for l in capsys.readouterr().out.splitlines()]
    assert rc == 1 and len(out) == 4 and {"rule", "src_ip", "count", "users"} <= out[0].keys()


def test_cli_clean_exit_code(capsys):
    assert main(["--year", "2026", str(SAMPLES / "auth_benign.log")]) == 0


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_bash_detector_matches_python():
    res = subprocess.run(["bash", str(BASH), str(SAMPLES / "auth.log")], capture_output=True, text=True)
    assert res.returncode == 1
    found = sorted((l.split()[0].strip("[]"), l.split()[1]) for l in res.stdout.splitlines())
    assert found == rules(detect(load("auth.log")))


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_bash_detector_clean_and_allowlist():
    clean = subprocess.run(["bash", str(BASH), str(SAMPLES / "auth_benign.log")], capture_output=True, text=True)
    assert clean.returncode == 0 and clean.stdout == ""
    allowed = subprocess.run(["bash", str(BASH), "-a", "203.0.113.50", "-a", "198.51.100.23", str(SAMPLES / "auth.log")],
                             capture_output=True, text=True)
    assert allowed.returncode == 0


def test_module_entry_point():
    res = subprocess.run([sys.executable, "-m", "lbfd", "--year", "2026", str(SAMPLES / "auth_benign.log")],
                         capture_output=True, text=True, cwd=ROOT)
    assert res.returncode == 0
