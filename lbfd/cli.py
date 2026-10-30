"""Command-line entry point: python -m lbfd [options] FILE [FILE ...]"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime

from .detector import detect, parse_lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lbfd", description="Detect SSH brute force and password spraying in auth logs.")
    p.add_argument("files", nargs="+", help="auth.log / secure files, or - for stdin")
    p.add_argument("-t", "--threshold", type=int, default=5, help="failures per source IP in the window (default 5)")
    p.add_argument("-w", "--window", type=int, default=60, help="sliding window in seconds (default 60)")
    p.add_argument("-u", "--spray-users", type=int, default=5, help="distinct users per source IP in the window (default 5)")
    p.add_argument("-a", "--allow", action="append", default=[], help="IP or CIDR to ignore (repeatable)")
    p.add_argument("-y", "--year", type=int, default=datetime.now().year, help="year for syslog timestamps without one")
    p.add_argument("-j", "--json", action="store_true", help="emit JSON lines (for Splunk/Elastic ingestion)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    events = []
    for path in args.files:
        if path == "-":
            events.extend(parse_lines(sys.stdin, args.year))
        else:
            with open(path, encoding="utf-8", errors="replace") as fh:
                events.extend(parse_lines(fh, args.year))

    alerts = detect(events, args.threshold, args.window, args.spray_users, set(args.allow))
    for a in alerts:
        if args.json:
            print(json.dumps(a.to_dict()))
        else:
            print(f"[{a.rule}] {a.src_ip} host={a.host} count={a.count} "
                  f"first={a.first_seen} last={a.last_seen} users={','.join(a.users)}")
    if not args.json:
        print(f"-- {len(events)} auth events parsed, {len(alerts)} alert(s)", file=sys.stderr)
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
