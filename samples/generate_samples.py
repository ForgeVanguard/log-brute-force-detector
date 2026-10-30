"""Regenerate the SYNTHETIC sample logs in this folder. Deterministic; no real data."""

from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).parent
HOST = "lab-target01"
HEADER = "# SYNTHETIC SAMPLE DATA - created for testing, not from a real system\n"


def line(ts, pid, msg):
    return f"{ts.strftime('%b %d %H:%M:%S').replace(' 0', '  ', 1)} {HOST} sshd[{pid}]: {msg}\n"


def auth_log():
    out = [HEADER]
    t = datetime(2026, 3, 3, 9, 0, 0)
    pid = 4100
    # Benign: an admin mistypes once, then logs in.
    out.append(line(t, pid, "Failed password for labadmin from 192.0.2.10 port 50122 ssh2"))
    out.append(line(t + timedelta(seconds=6), pid, "Accepted password for labadmin from 192.0.2.10 port 50122 ssh2"))
    # Noise lines that must be ignored.
    out.append(line(t + timedelta(seconds=7), pid, "pam_unix(sshd:session): session opened for user labadmin(uid=1000) by (uid=0)"))
    out.append(line(t + timedelta(seconds=30), pid + 1, "Connection closed by 192.0.2.11 port 41000 [preauth]"))

    # Brute force against one account (hydra-style), then a success.
    t2 = t + timedelta(minutes=10)
    for i in range(12):
        out.append(line(t2 + timedelta(seconds=2 * i), pid + 10 + i,
                        f"Failed password for labadmin from 198.51.100.23 port {40000 + i} ssh2"))
    out.append(line(t2 + timedelta(seconds=30), pid + 30, "Accepted password for labadmin from 198.51.100.23 port 40050 ssh2"))

    # Password spray: one attempt each against many accounts, including invalid users.
    t3 = t + timedelta(minutes=20)
    users = ["root", "admin", "test", "oracle", "ubuntu", "postgres", "git"]
    for i, u in enumerate(users):
        if u in ("root", "ubuntu"):
            msg = f"Failed password for {u} from 203.0.113.50 port {51000 + i} ssh2"
        else:
            out.append(line(t3 + timedelta(seconds=5 * i), pid + 50 + i, f"Invalid user {u} from 203.0.113.50 port {51000 + i}"))
            msg = f"Failed password for invalid user {u} from 203.0.113.50 port {51000 + i} ssh2"
        out.append(line(t3 + timedelta(seconds=5 * i), pid + 50 + i, msg))

    # Slow, low-volume failures that stay under a 60 s window (should NOT alert at defaults).
    t4 = t + timedelta(minutes=40)
    for i in range(4):
        out.append(line(t4 + timedelta(minutes=5 * i), pid + 80 + i,
                        f"Failed password for backup from 198.51.100.77 port {42000 + i} ssh2"))
    return "".join(out)


def benign_log():
    out = [HEADER]
    t = datetime(2026, 3, 4, 8, 0, 0)
    for i in range(20):
        out.append(line(t + timedelta(minutes=15 * i), 6000 + i,
                        f"Accepted publickey for labadmin from 192.0.2.{10 + i % 3} port {50000 + i} ssh2"))
    return "".join(out)


if __name__ == "__main__":
    (HERE / "auth.log").write_text(auth_log())
    (HERE / "auth_benign.log").write_text(benign_log())
    print("wrote auth.log and auth_benign.log")
