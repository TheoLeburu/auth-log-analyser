"""Log parsers.

Each parser turns raw log lines into :class:`AuthEvent` objects. Adding support
for a new source means adding a Parser subclass and registering it; the
detection rules never need to change.

Syslog's biggest trap is that traditional format lines carry no year. We infer
one and walk backwards across a December-to-January boundary rather than
producing timestamps a year in the future.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from .models import AuthEvent, Outcome, ParseStats

# ---------------------------------------------------------------------------
# OpenSSH (syslog) patterns
# ---------------------------------------------------------------------------

# Mar 15 08:12:33 web01 sshd[2841]: <message>
_SYSLOG_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[a-zA-Z0-9_\-]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# ISO syslog (systemd / rsyslog RFC5424-ish):
# 2026-03-15T08:12:33.123456+00:00 web01 sshd[2841]: <message>
_ISO_SYSLOG_PREFIX = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[a-zA-Z0-9_\-]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Accepted password for theo from 41.79.10.22 port 51299 ssh2
# Accepted publickey for deploy from 10.0.0.5 port 40122 ssh2: RSA SHA256:...
_SSH_ACCEPTED = re.compile(
    r"^Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+"
    r"(?P<ip>[0-9a-fA-F.:]+)\s+port\s+(?P<port>\d+)"
)

# Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2
# Failed password for root from 203.0.113.45 port 51240 ssh2
_SSH_FAILED = re.compile(
    r"^Failed\s+(?P<method>\S+)\s+for\s+(?P<invalid>invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>[0-9a-fA-F.:]+)\s+port\s+(?P<port>\d+)"
)

# Invalid user oracle from 203.0.113.45 port 51240
_SSH_INVALID_USER = re.compile(
    r"^Invalid user\s+(?P<user>\S*)\s+from\s+(?P<ip>[0-9a-fA-F.:]+)(?:\s+port\s+(?P<port>\d+))?"
)

# Connection closed by authenticating user root 203.0.113.45 port 51250 [preauth]
_SSH_PREAUTH_CLOSE = re.compile(
    r"^Connection (?:closed|reset) by (?:authenticating|invalid) user\s+(?P<user>\S+)\s+"
    r"(?P<ip>[0-9a-fA-F.:]+)\s+port\s+(?P<port>\d+)"
)

# message repeated 5 times: [ Failed password for root from ... ]
_SYSLOG_REPEAT = re.compile(r"^message repeated (?P<count>\d+) times:\s*\[\s*(?P<inner>.*?)\s*\]$")

# sshd lines that are noise for our purposes but should not count as failures
_SSH_IGNORE = (
    "pam_unix(sshd:session): session opened",
    "pam_unix(sshd:session): session closed",
    "Received disconnect",
    "Disconnected from",
    "Server listening on",
    "Received signal",
    "error: kex_exchange_identification",
    "Timeout before authentication",
)

# ---------------------------------------------------------------------------
# nginx access log pattern (combined format)
# ---------------------------------------------------------------------------

# 203.0.113.45 - - [15/Mar/2026:08:12:33 +0000] "POST /wp-login.php HTTP/1.1" 401 152 "-" "curl/7.68"
_NGINX_COMBINED = re.compile(
    r"^(?P<ip>[0-9a-fA-F.:]+)\s+\S+\s+(?P<remote_user>\S+)\s+"
    r"\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)[^"]*"\s+'
    r"(?P<status>\d{3})\s+"
)

# Paths where a 401/403 means a genuine login attempt rather than a missing asset.
_NGINX_AUTH_PATHS = (
    "/login", "/signin", "/sign-in", "/auth", "/session", "/admin",
    "/wp-login.php", "/xmlrpc.php", "/user/login", "/api/login",
    "/api/auth", "/api/token", "/oauth", "/administrator",
)


def infer_year(month: int, day: int, reference: datetime) -> int:
    """Pick the year for a syslog line that has none.

    Assumes the log is not from the future. If the parsed date would land more
    than a day ahead of the reference, it belongs to the previous year.
    """
    candidate = datetime(reference.year, month, min(day, 28) if month == 2 else day)
    if candidate > reference + timedelta(days=1):
        return reference.year - 1
    return reference.year


class Parser:
    """Base class for log parsers."""

    name = "base"

    def matches(self, line: str) -> bool:
        raise NotImplementedError

    def parse(self, line: str, reference: datetime) -> list[AuthEvent] | None:
        """Return events, an empty list if the line is known noise, or None if unparseable."""
        raise NotImplementedError


class SSHDParser(Parser):
    """Parses OpenSSH authentication messages from syslog or journald output."""

    name = "sshd"

    def matches(self, line: str) -> bool:
        return bool(_SYSLOG_PREFIX.match(line) or _ISO_SYSLOG_PREFIX.match(line))

    def _timestamp(self, match: re.Match, reference: datetime) -> datetime:
        if "ts" in match.groupdict() and match.groupdict().get("ts"):
            raw = match.group("ts").replace("Z", "+00:00")
            parsed = datetime.fromisoformat(raw)
            return parsed.replace(tzinfo=None)
        month = _MONTHS[match.group("month")]
        day = int(match.group("day"))
        hour, minute, second = (int(p) for p in match.group("time").split(":"))
        year = infer_year(month, day, reference)
        return datetime(year, month, day, hour, minute, second)

    def parse(self, line: str, reference: datetime) -> list[AuthEvent] | None:
        match = _ISO_SYSLOG_PREFIX.match(line) or _SYSLOG_PREFIX.match(line)
        if not match:
            return None

        process = match.group("process")
        if process not in ("sshd", "sshd-session"):
            return []

        timestamp = self._timestamp(match, reference)
        host = match.group("host")
        message = match.group("message")

        # rsyslog collapses identical consecutive lines. Expanding them back out
        # matters a great deal here: a brute-force burst is exactly the kind of
        # repetition that gets collapsed, and undercounting it hides the attack.
        repeat = _SYSLOG_REPEAT.match(message)
        multiplier = 1
        if repeat:
            multiplier = int(repeat.group("count"))
            message = repeat.group("inner")

        event = self._parse_message(message, timestamp, host, line)
        if event is None:
            if any(token in message for token in _SSH_IGNORE):
                return []
            return None
        return [event] * multiplier

    def _parse_message(
        self, message: str, timestamp: datetime, host: str, raw: str
    ) -> AuthEvent | None:
        accepted = _SSH_ACCEPTED.match(message)
        if accepted:
            return AuthEvent(
                timestamp=timestamp,
                source_ip=accepted.group("ip"),
                username=accepted.group("user"),
                outcome=Outcome.SUCCESS,
                service="sshd",
                method=accepted.group("method"),
                host=host,
                port=int(accepted.group("port")),
                raw=raw,
            )

        failed = _SSH_FAILED.match(message)
        if failed:
            return AuthEvent(
                timestamp=timestamp,
                source_ip=failed.group("ip"),
                username=failed.group("user"),
                outcome=Outcome.INVALID_USER if failed.group("invalid") else Outcome.FAILURE,
                service="sshd",
                method=failed.group("method"),
                host=host,
                port=int(failed.group("port")),
                raw=raw,
            )

        invalid = _SSH_INVALID_USER.match(message)
        if invalid:
            return AuthEvent(
                timestamp=timestamp,
                source_ip=invalid.group("ip"),
                username=invalid.group("user") or None,
                outcome=Outcome.INVALID_USER,
                service="sshd",
                host=host,
                port=int(invalid.group("port")) if invalid.group("port") else None,
                raw=raw,
            )

        preauth = _SSH_PREAUTH_CLOSE.match(message)
        if preauth:
            return AuthEvent(
                timestamp=timestamp,
                source_ip=preauth.group("ip"),
                username=preauth.group("user"),
                outcome=Outcome.DISCONNECT,
                service="sshd",
                host=host,
                port=int(preauth.group("port")),
                raw=raw,
            )

        return None


class NginxParser(Parser):
    """Extracts failed web logins from nginx combined-format access logs.

    Only 401 and 403 responses on plausible authentication paths become events.
    Treating every 404 as an auth failure would flood the detections with noise
    from vulnerability scanners probing for files.
    """

    name = "nginx"

    def matches(self, line: str) -> bool:
        return bool(_NGINX_COMBINED.match(line))

    def parse(self, line: str, reference: datetime) -> list[AuthEvent] | None:
        match = _NGINX_COMBINED.match(line)
        if not match:
            return None

        status = int(match.group("status"))
        path = match.group("path").lower()
        is_auth_path = any(path.startswith(p) or p in path for p in _NGINX_AUTH_PATHS)

        if not is_auth_path:
            return []

        try:
            timestamp = datetime.strptime(match.group("ts").split()[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return None

        if status in (401, 403):
            outcome = Outcome.FAILURE
        elif status in (200, 302):
            outcome = Outcome.SUCCESS
        else:
            return []

        remote_user = match.group("remote_user")
        return [
            AuthEvent(
                timestamp=timestamp,
                source_ip=match.group("ip"),
                username=None if remote_user == "-" else remote_user,
                outcome=outcome,
                service="nginx",
                method=f"{match.group('method')} {match.group('path')}",
                raw=line,
            )
        ]


DEFAULT_PARSERS: tuple[Parser, ...] = (SSHDParser(), NginxParser())


def parse_lines(
    lines,
    parsers: tuple[Parser, ...] = DEFAULT_PARSERS,
    reference: datetime | None = None,
) -> tuple[list[AuthEvent], ParseStats]:
    """Parse an iterable of log lines into events plus parsing statistics."""
    reference = reference or datetime.now()
    stats = ParseStats()
    events: list[AuthEvent] = []

    for line in lines:
        line = line.rstrip("\n").rstrip("\r")
        if not line.strip():
            continue
        stats.total_lines += 1

        handled = False
        for parser in parsers:
            if not parser.matches(line):
                continue
            result = parser.parse(line, reference)
            if result is None:
                break
            handled = True
            if result:
                events.extend(result)
                stats.parsed_events += len(result)
            else:
                stats.ignored_lines += 1
            break

        if not handled:
            stats.unparsed_lines += 1
            if len(stats.samples_unparsed) < 5:
                stats.samples_unparsed.append(line[:200])

    events.sort(key=lambda e: e.timestamp)
    return events, stats
