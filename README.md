# log-brute-force-detector

A small, dependency-free host-based detector for **SSH brute force** and **password spraying** in Linux `auth.log` / `secure` logs. It comes in two implementations:

| Implementation | Path | Needs |
|---|---|---|
| Python package (`lbfd`) | `lbfd/` | Python 3.8+, standard library only |
| Portable shell/awk script | `bash/ssh-bruteforce-detect.sh` | bash + any POSIX awk |

This is Lab 05 ("Custom Log IDS") of [soc-detection-labs](https://github.com/ForgeVanguard/soc-detection-labs). The SIEM versions of the same logic (Splunk SPL, KQL, Sigma) are in that repo.

## Detection rules

All rules are evaluated **per source IP** over a **sliding time window**.

| Rule | Fires when | ATT&CK |
|---|---|---|
| `BRUTE_FORCE` | ≥ `threshold` failed logins within `window` seconds | T1110.001 Password Guessing |
| `PASSWORD_SPRAY` | ≥ `spray_users` distinct usernames failing within `window` seconds | T1110.003 Password Spraying |
| `SUCCESS_AFTER_FAILURES` | a successful login from an IP already flagged by either rule above | T1110 → T1021.004 Remote Services: SSH |

Parsed sshd messages: `Failed password|publickey|keyboard-interactive/pam for [invalid user] USER from IP port N` and `Accepted ... for USER from IP port N`. The separate `Invalid user X from IP` line is ignored on purpose, because sshd also logs a `Failed ... for invalid user X` line for the same attempt and counting both would double-count it.

The Python version groups a continuous attack into one alert and keeps extending it while events keep arriving within the window, so the alert shows the full burst count. The shell version alerts once per rule per IP.

## Usage

```bash
# Python
python3 -m lbfd /var/log/auth.log
python3 -m lbfd -t 10 -w 300 -u 8 -a 192.0.2.0/24 /var/log/auth.log*
python3 -m lbfd --json --year 2026 auth.log > alerts.jsonl     # JSON lines for SIEM ingestion
journalctl -u ssh --output=short-iso | python3 -m lbfd -

# Shell
bash/ssh-bruteforce-detect.sh /var/log/auth.log
bash/ssh-bruteforce-detect.sh -t 10 -w 300 -a 192.0.2.10 /var/log/secure
```

| Option | Default | Meaning |
|---|---|---|
| `-t` | 5 | failures per IP in the window |
| `-w` | 60 | window in seconds |
| `-u` | 5 | distinct usernames per IP in the window |
| `-a` | none | allowlist: IP or CIDR (Python), exact IP (shell); repeatable |
| `-y` | current year | year for syslog timestamps (classic syslog has no year) |
| `-j` | off | JSON-lines output (Python) |

Exit codes: `0` = no alerts, `1` = alerts, `2` = usage error. This makes the tools easy to use from cron or a CI check.

## Try it on the sample data

`samples/` contains **SYNTHETIC** logs that use documentation IP ranges (RFC 5737). They were produced by `samples/generate_samples.py` and come from no real system.

| Source IP | Scenario in `samples/auth.log` | Expected result |
|---|---|---|
| 192.0.2.10 | admin mistypes once, then logs in | no alert |
| 198.51.100.23 | 12 rapid failures for one account, then a success | `BRUTE_FORCE` + `SUCCESS_AFTER_FAILURES` |
| 203.0.113.50 | one attempt each against 7 accounts | `PASSWORD_SPRAY` (+ `BRUTE_FORCE` by volume) |
| 198.51.100.77 | 4 failures spread over 15 minutes | no alert at defaults; alerts with `-t 4 -w 3600` |

```bash
python3 -m lbfd --year 2026 samples/auth.log
bash/ssh-bruteforce-detect.sh samples/auth.log
```

## Tests

```bash
pip install pytest
pytest -q                 # parser, rules, CLI, and Python/shell parity on the samples
shellcheck bash/*.sh
```

## Tuning notes

- **Low-and-slow attacks** stay under a 60 s window. Run a second pass with a wide window (`-w 3600 -t 10`) for those.
- **Shared NAT / bastions / vulnerability scanners** produce benign volume, so allowlist them explicitly and review the allowlist regularly.
- **Key-only servers** still log `Failed publickey` when clients offer several keys. If that is noisy, raise `-t` or filter that method upstream.
- **`SUCCESS_AFTER_FAILURES` is the highest-priority alert**: it may mean a guessed credential. Respond by checking the session, the account's recent activity, and resetting the credential.

## Limitations

- sshd only. PAM messages from other services are not parsed.
- Classic syslog has no year or timezone, so pass `--year` when you analyze old logs. ISO timestamps that carry an offset are converted to local time.
- It is a log reader, not a blocker. To block, feed the output to your firewall or fail2ban instead.

## Disclaimer

For defensive use and for authorized lab testing only. Only run attack tooling against systems you own or are explicitly permitted to test.

## License

MIT © 2026 Steven Drew
