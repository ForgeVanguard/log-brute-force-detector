"""Core parsing and detection logic.

Detections
----------
BRUTE_FORCE     >= threshold failed logins from one source IP inside a sliding window.
PASSWORD_SPRAY  >= spray_users distinct usernames failing from one source IP inside the window.
SUCCESS_AFTER_FAILURES
                a successful login from a source IP that already triggered BRUTE_FORCE
                or PASSWORD_SPRAY (possible compromise).
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Deque, Dict, Iterable, Iterator, List, Optional, Set

# Classic syslog: "Mar  3 14:02:11 host sshd[1234]: message"
_SYSLOG = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
# RFC 3339 (rsyslog high-precision / journald export): "2026-03-03T14:02:11.123+00:00 host sshd[1]: msg"
_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)

_FAILED = re.compile(r"^Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S*) from (?P<ip>\S+) port \d+")
_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port \d+)?")
_ACCEPTED = re.compile(r"^Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>\S+) port \d+")


@dataclass
class AuthEvent:
    timestamp: datetime
    host: str
    outcome: str  # "failure" | "success"
    user: str
    src_ip: str


@dataclass
class Alert:
    rule: str
    src_ip: str
    first_seen: str
    last_seen: str
    count: int
    users: List[str] = field(default_factory=list)
    host: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _parse_ts(raw: str, year: int) -> datetime:
    if raw[0].isdigit():
        raw = raw.replace("Z", "+00:00")
        ts = datetime.fromisoformat(raw)
        return ts.replace(tzinfo=None) if ts.tzinfo is None else ts.astimezone().replace(tzinfo=None)
    return datetime.strptime(f"{year} {' '.join(raw.split())}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, year: int) -> Optional[AuthEvent]:
    """Parse one sshd auth line. Returns None for lines that are not auth outcomes.

    'Invalid user' lines are ignored because sshd also logs a matching 'Failed password
    for invalid user' line; counting both would double-count.
    """
    m = _SYSLOG.match(line) or _ISO.match(line)
    if not m:
        return None
    msg = m.group("msg")
    for regex, outcome in ((_FAILED, "failure"), (_ACCEPTED, "success")):
        hit = regex.match(msg)
        if hit:
            ip = hit.group("ip")
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return None
            return AuthEvent(_parse_ts(m.group("ts"), year), m.group("host"), outcome, hit.group("user") or "<empty>", ip)
    return None


def parse_lines(lines: Iterable[str], year: int) -> Iterator[AuthEvent]:
    for line in lines:
        ev = parse_line(line.rstrip("\n"), year)
        if ev:
            yield ev


def detect(
    events: Iterable[AuthEvent],
    threshold: int = 5,
    window_seconds: int = 60,
    spray_users: int = 5,
    allowlist: Optional[Set[str]] = None,
) -> List[Alert]:
    """Run all detections over time-ordered events. One alert per rule per source IP burst."""
    allow = {ipaddress.ip_network(a, strict=False) for a in (allowlist or set())}
    windows: Dict[str, Deque[AuthEvent]] = defaultdict(deque)
    open_alerts: Dict[tuple, Alert] = {}
    flagged: Set[str] = set()
    alerts: List[Alert] = []

    def allowed(ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in allow)

    for ev in sorted(events, key=lambda e: e.timestamp):
        if allowed(ev.src_ip):
            continue
        if ev.outcome == "success":
            if ev.src_ip in flagged:
                alerts.append(Alert("SUCCESS_AFTER_FAILURES", ev.src_ip, ev.timestamp.isoformat(),
                                    ev.timestamp.isoformat(), 1, [ev.user], ev.host))
            continue

        win = windows[ev.src_ip]
        win.append(ev)
        while (ev.timestamp - win[0].timestamp).total_seconds() > window_seconds:
            win.popleft()
        users = sorted({e.user for e in win})

        for rule, hit in (("BRUTE_FORCE", len(win) >= threshold), ("PASSWORD_SPRAY", len(users) >= spray_users)):
            key = (rule, ev.src_ip)
            current = open_alerts.get(key)
            # Extend an open alert if this event continues the same burst.
            if current and (ev.timestamp - datetime.fromisoformat(current.last_seen)).total_seconds() <= window_seconds:
                current.last_seen = ev.timestamp.isoformat()
                current.count += 1
                current.users = sorted(set(current.users) | {ev.user})
                continue
            if hit:
                alert = Alert(rule, ev.src_ip, win[0].timestamp.isoformat(), ev.timestamp.isoformat(),
                              len(win), users, ev.host)
                open_alerts[key] = alert
                alerts.append(alert)
                flagged.add(ev.src_ip)
    return alerts
