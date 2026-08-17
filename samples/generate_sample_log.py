"""Generates the sample log committed to samples/auth.log.

Deterministic via a fixed seed so that the committed sample, the README output,
and the test expectations never drift apart.

    python samples/generate_sample_log.py > samples/auth.log
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

SEED = 20260317
HOST = "web01"

LEGITIMATE_USERS = ["theo", "deploy", "mmoloi", "kabelo"]
OFFICE_IPS = ["41.79.10.22", "41.79.10.23", "10.0.0.5"]

ATTACK_IP = "203.0.113.45"
SPRAY_IP = "198.51.100.77"
SCANNER_IP = "192.0.2.199"
COMPROMISE_IP = "203.0.113.201"

DICTIONARY_USERS = [
    "admin", "test", "oracle", "postgres", "ubuntu", "pi", "user", "guest",
    "ftp", "mysql", "git", "jenkins", "tomcat", "nagios", "support", "backup",
    "operator", "service", "demo", "default",
]

SPRAY_USERS = [
    "theo", "deploy", "mmoloi", "kabelo", "info", "sales", "hr", "finance",
    "reception", "intern",
]


def syslog(moment: datetime, pid: int, message: str) -> str:
    stamp = moment.strftime("%b %e %H:%M:%S").replace("  ", " ")
    # %e can render a leading space; syslog uses two spaces for single digits.
    day = moment.day
    if day < 10:
        stamp = moment.strftime("%b") + f"  {day} " + moment.strftime("%H:%M:%S")
    else:
        stamp = moment.strftime("%b %d %H:%M:%S")
    return f"{stamp} {HOST} sshd[{pid}]: {message}"


def nginx(moment: datetime, ip: str, method: str, path: str, status: int, agent: str, rng: random.Random) -> str:
    stamp = moment.strftime("%d/%b/%Y:%H:%M:%S +0000")
    size = rng.randint(120, 900)
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'


def main() -> None:
    rng = random.Random(SEED)
    lines: list[tuple[datetime, str]] = []
    pid = 2000

    def next_pid() -> int:
        nonlocal pid
        pid += rng.randint(1, 7)
        return pid

    day = datetime(2026, 3, 17, 0, 0, 0)

    # --- Normal weekday activity: key-based logins during office hours -----
    for offset in range(3):
        base = day + timedelta(days=offset)
        for _ in range(rng.randint(9, 16)):
            moment = base + timedelta(
                hours=rng.randint(7, 18), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59)
            )
            user = rng.choice(LEGITIMATE_USERS)
            ip = rng.choice(OFFICE_IPS)
            lines.append(
                (
                    moment,
                    syslog(
                        moment,
                        next_pid(),
                        f"Accepted publickey for {user} from {ip} port "
                        f"{rng.randint(40000, 60000)} ssh2: ED25519 SHA256:"
                        f"{''.join(rng.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(20))}",
                    ),
                )
            )
            lines.append(
                (
                    moment + timedelta(seconds=1),
                    syslog(
                        moment + timedelta(seconds=1),
                        pid,
                        f"pam_unix(sshd:session): session opened for user {user}(uid=1001) by (uid=0)",
                    ),
                )
            )

        # A couple of ordinary fat-finger failures. A tool that alerts on these
        # is a tool nobody keeps running.
        for _ in range(rng.randint(1, 3)):
            moment = base + timedelta(hours=rng.randint(8, 17), minutes=rng.randint(0, 59))
            user = rng.choice(LEGITIMATE_USERS)
            ip = rng.choice(OFFICE_IPS)
            lines.append(
                (
                    moment,
                    syslog(
                        moment,
                        next_pid(),
                        f"Failed password for {user} from {ip} port {rng.randint(40000, 60000)} ssh2",
                    ),
                )
            )

    # --- Sustained brute force against root -------------------------------
    burst_start = day + timedelta(days=1, hours=2, minutes=14)
    for index in range(46):
        moment = burst_start + timedelta(seconds=index * 6 + rng.randint(0, 2))
        lines.append(
            (
                moment,
                syslog(
                    moment,
                    next_pid(),
                    f"Failed password for root from {ATTACK_IP} port {rng.randint(30000, 65000)} ssh2",
                ),
            )
        )
    closing = burst_start + timedelta(seconds=300)
    lines.append(
        (
            closing,
            syslog(
                closing,
                next_pid(),
                f"Connection closed by authenticating user root {ATTACK_IP} port 51250 [preauth]",
            ),
        )
    )

    # --- Dictionary scan against non-existent accounts ---------------------
    scan_start = day + timedelta(days=1, hours=3, minutes=41)
    for index, user in enumerate(DICTIONARY_USERS):
        moment = scan_start + timedelta(seconds=index * 11)
        lines.append(
            (
                moment,
                syslog(moment, next_pid(), f"Invalid user {user} from {SCANNER_IP} port {rng.randint(30000, 65000)}"),
            )
        )
        moment2 = moment + timedelta(seconds=1)
        lines.append(
            (
                moment2,
                syslog(
                    moment2,
                    pid,
                    f"Failed password for invalid user {user} from {SCANNER_IP} "
                    f"port {rng.randint(30000, 65000)} ssh2",
                ),
            )
        )

    # --- Password spraying: many users, few attempts each ------------------
    spray_start = day + timedelta(days=2, hours=4, minutes=8)
    for index, user in enumerate(SPRAY_USERS):
        moment = spray_start + timedelta(seconds=index * 70)
        lines.append(
            (
                moment,
                syslog(
                    moment,
                    next_pid(),
                    f"Failed password for {user} from {SPRAY_IP} port {rng.randint(30000, 65000)} ssh2",
                ),
            )
        )

    # --- The one that matters: failures then a success ---------------------
    comp_start = day + timedelta(days=2, hours=23, minutes=12)
    for index in range(9):
        moment = comp_start + timedelta(seconds=index * 20)
        lines.append(
            (
                moment,
                syslog(
                    moment,
                    next_pid(),
                    f"Failed password for kabelo from {COMPROMISE_IP} port "
                    f"{rng.randint(30000, 65000)} ssh2",
                ),
            )
        )
    success = comp_start + timedelta(seconds=200)
    lines.append(
        (
            success,
            syslog(
                success,
                next_pid(),
                f"Accepted password for kabelo from {COMPROMISE_IP} port 44122 ssh2",
            ),
        )
    )
    followup = success + timedelta(seconds=3)
    lines.append(
        (
            followup,
            syslog(followup, pid, "pam_unix(sshd:session): session opened for user kabelo(uid=1003) by (uid=0)"),
        )
    )

    # --- rsyslog collapsing a burst into one line -------------------------
    repeat_moment = day + timedelta(days=2, hours=5, minutes=30)
    lines.append(
        (
            repeat_moment,
            syslog(
                repeat_moment,
                next_pid(),
                f"message repeated 12 times: [ Failed password for root from {ATTACK_IP} port 41022 ssh2]",
            ),
        )
    )

    # --- Web login attempts from the same attacking address ---------------
    web_start = day + timedelta(days=1, hours=2, minutes=20)
    for index in range(24):
        moment = web_start + timedelta(seconds=index * 9)
        lines.append(
            (
                moment,
                nginx(moment, ATTACK_IP, "POST", "/wp-login.php", 401, "python-requests/2.31.0", rng),
            )
        )
    # Ordinary traffic that must not be treated as auth activity.
    for index in range(12):
        moment = day + timedelta(days=1, hours=9, minutes=index * 4)
        lines.append((moment, nginx(moment, "41.79.10.22", "GET", "/assets/app.css", 200, "Mozilla/5.0", rng)))
    for index in range(6):
        moment = day + timedelta(days=1, hours=10, minutes=index * 7)
        lines.append((moment, nginx(moment, SCANNER_IP, "GET", "/.env", 404, "Nuclei/3.1", rng)))

    # --- Noise the parser should skip without counting as unparsed --------
    for offset in range(3):
        moment = day + timedelta(days=offset, hours=6, minutes=25)
        lines.append((moment, syslog(moment, next_pid(), "Server listening on 0.0.0.0 port 22.")))

    lines.sort(key=lambda pair: pair[0])
    for _, line in lines:
        print(line)


if __name__ == "__main__":
    main()
