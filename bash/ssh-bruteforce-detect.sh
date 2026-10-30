#!/usr/bin/env bash
# ssh-bruteforce-detect.sh - dependency-free SSH brute-force / password-spray detector.
#
# Portable companion to the Python tool (lbfd). Works with any POSIX awk (mawk, gawk, busybox).
# Reads sshd lines from auth.log / secure (classic syslog or RFC 3339 timestamps).
#
# Rules (per source IP, sliding window):
#   BRUTE_FORCE             >= THRESHOLD failures within WINDOW seconds
#   PASSWORD_SPRAY          >= SPRAY_USERS distinct usernames failing within WINDOW seconds
#   SUCCESS_AFTER_FAILURES  successful login from an IP already flagged above
# Each rule alerts once per source IP (the Python tool also reports separate bursts).
#
# Usage: ssh-bruteforce-detect.sh [-t threshold] [-w window_s] [-u spray_users] [-a allow_ip]... FILE...
#        journalctl -u ssh --output=short-iso | ssh-bruteforce-detect.sh -
# Exit:  0 = no alerts, 1 = alerts, 2 = usage error
#
# Author: Steven Drew - License: MIT

set -euo pipefail

THRESHOLD=5
WINDOW=60
SPRAY_USERS=5
ALLOW=""

usage() {
    sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

while getopts ":t:w:u:a:h" opt; do
    case "$opt" in
        t) THRESHOLD="$OPTARG" ;;
        w) WINDOW="$OPTARG" ;;
        u) SPRAY_USERS="$OPTARG" ;;
        a) ALLOW="$ALLOW $OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))
[ "$#" -ge 1 ] || usage

for n in "$THRESHOLD" "$WINDOW" "$SPRAY_USERS"; do
    case "$n" in
        ''|*[!0-9]*) echo "error: numeric options must be positive integers" >&2; exit 2 ;;
    esac
done

awk -v threshold="$THRESHOLD" -v window="$WINDOW" -v spray="$SPRAY_USERS" -v allow="$ALLOW" '
BEGIN {
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", mn, " ")
    split("0 31 59 90 120 151 181 212 243 273 304 334", cum, " ")
    for (i = 1; i <= 12; i++) { mon[mn[i]] = i; mcum[i] = cum[i] }
    n = split(allow, al, " ")
    for (i = 1; i <= n; i++) allowed[al[i]] = 1
    alerts = 0
}
function secs(m, d, hms,   t) {
    split(hms, t, ":")
    return ((mcum[m] + d) * 86400) + t[1] * 3600 + t[2] * 60 + int(t[3])
}
# Return the field index of the sshd tag, or 0.
function sshd_field(   i) {
    for (i = 2; i <= 6 && i <= NF; i++) if ($i ~ /^sshd\[[0-9]+\]:$/) return i
    return 0
}
{
    f = sshd_field()
    if (!f) next
    if ($1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T/) {
        ts = $1
        split(substr(ts, 1, 10), dp, "-")
        now = secs(dp[2] + 0, dp[3] + 0, substr(ts, 12, 8)) + (dp[1] * 400 * 86400)
        stamp = substr(ts, 1, 19)
    } else if ($1 in mon) {
        now = secs(mon[$1], $2 + 0, $3)
        stamp = $1 " " $2 " " $3
    } else next
    host = $(f - 1)

    msg = ""
    for (i = f + 1; i <= NF; i++) msg = msg (msg == "" ? "" : " ") $i

    outcome = ""
    if (msg ~ /^Failed (password|publickey|keyboard-interactive\/pam) for /) outcome = "failure"
    else if (msg ~ /^Accepted (password|publickey|keyboard-interactive\/pam) for /) outcome = "success"
    else next

    # user is the token before "from"; ip the token after
    nm = split(msg, w, " ")
    user = ""; ip = ""
    for (i = 1; i < nm; i++) if (w[i] == "from") { user = w[i - 1]; ip = w[i + 1]; break }
    if (ip == "" || (ip in allowed)) next

    if (outcome == "success") {
        if ((ip in flagged) && !(("S" SUBSEP ip) in fired)) {
            fired["S" SUBSEP ip] = 1; alerts++
            printf "[SUCCESS_AFTER_FAILURES] %s host=%s user=%s at=%s\n", ip, host, user, stamp
        }
        next
    }

    # Append to this IP window, then drop entries older than the window.
    c = ++cnt[ip]; tsq[ip, c] = now; usq[ip, c] = user
    if (!(ip in head)) head[ip] = 1
    while (now - tsq[ip, head[ip]] > window) head[ip]++
    size = c - head[ip] + 1

    delete seen; du = 0; ulist = ""
    for (k = head[ip]; k <= c; k++) {
        u = usq[ip, k]
        if (!(u in seen)) { seen[u] = 1; du++; ulist = ulist (ulist == "" ? "" : ",") u }
    }

    if (size >= threshold && !(("B" SUBSEP ip) in fired)) {
        fired["B" SUBSEP ip] = 1; flagged[ip] = 1; alerts++
        printf "[BRUTE_FORCE] %s host=%s count=%d window=%ds last=%s users=%s\n", ip, host, size, window, stamp, ulist
    }
    if (du >= spray && !(("P" SUBSEP ip) in fired)) {
        fired["P" SUBSEP ip] = 1; flagged[ip] = 1; alerts++
        printf "[PASSWORD_SPRAY] %s host=%s distinct_users=%d window=%ds last=%s users=%s\n", ip, host, du, window, stamp, ulist
    }
}
END {
    printf "-- %d alert(s)\n", alerts > "/dev/stderr"
    exit (alerts > 0 ? 1 : 0)
}' "$@"
