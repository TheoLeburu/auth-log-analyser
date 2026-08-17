"""Detection rules.

Every rule reads the same normalised event stream and emits Alerts. Rules are
independent of each other and of log format, which is what makes the set easy
to extend.

Thresholds are constructor arguments rather than module constants so that they
can be tuned per environment without editing the rules. A threshold that is
right for a home server is wrong for a bastion host serving fifty engineers.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from .models import Alert, AuthEvent, Outcome, Severity

# Usernames that should never be used for interactive login. A successful
# authentication as any of these is worth surfacing on its own.
PRIVILEGED_USERNAMES = {"root", "admin", "administrator"}

# Usernames that only ever appear in automated credential lists.
COMMON_ATTACK_USERNAMES = {
    "admin", "test", "oracle", "postgres", "ubuntu", "pi", "user", "guest",
    "ftp", "mysql", "git", "jenkins", "tomcat", "nagios", "www-data", "support",
    "backup", "operator", "service", "demo", "default", "deploy",
}


def _window_groups(
    events: list[AuthEvent], window: timedelta, threshold: int
) -> list[list[AuthEvent]]:
    """Return maximal bursts of >= threshold events that fit inside window.

    Uses a sliding window over a time-sorted list. Once a burst is emitted its
    events are consumed, so one sustained attack produces one alert rather than
    one alert per event.
    """
    groups: list[list[AuthEvent]] = []
    start = 0
    n = len(events)
    while start < n:
        end = start
        while end + 1 < n and events[end + 1].timestamp - events[start].timestamp <= window:
            end += 1
        burst = events[start : end + 1]
        if len(burst) >= threshold:
            # Extend the burst greedily while attempts keep arriving.
            while end + 1 < n and events[end + 1].timestamp - events[end].timestamp <= window:
                end += 1
                burst = events[start : end + 1]
            groups.append(burst)
            start = end + 1
        else:
            start += 1
    return groups


class Detection:
    """Base class for detection rules."""

    rule_id = "base"
    title = "Base rule"

    def run(self, events: list[AuthEvent]) -> list[Alert]:
        raise NotImplementedError

    @staticmethod
    def _by_ip(events: list[AuthEvent]) -> dict[str, list[AuthEvent]]:
        grouped: dict[str, list[AuthEvent]] = defaultdict(list)
        for event in events:
            grouped[event.source_ip].append(event)
        return grouped


class BruteForceDetection(Detection):
    """Many failed attempts from one address in a short window."""

    rule_id = "brute_force"
    title = "Brute-force attempt"

    def __init__(self, threshold: int = 8, window_seconds: int = 300) -> None:
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

    def run(self, events: list[AuthEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        for ip, ip_events in self._by_ip(events).items():
            failures = [e for e in ip_events if e.is_failure]
            for burst in _window_groups(failures, self.window, self.threshold):
                users = sorted({e.username for e in burst if e.username})
                span = (burst[-1].timestamp - burst[0].timestamp).total_seconds()
                severity = Severity.HIGH if len(burst) >= self.threshold * 3 else Severity.MEDIUM
                if span > 0:
                    timing = f"in {span:.0f} seconds ({len(burst) / (span / 60):.1f} per minute)"
                else:
                    # Zero span means syslog collapsed identical lines into one
                    # "message repeated N times" entry, so per-attempt timing is lost.
                    timing = "within a single collapsed syslog entry"
                alerts.append(
                    Alert(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=severity,
                        source_ip=ip,
                        description=(
                            f"{len(burst)} failed authentication attempts from {ip} "
                            f"{timing} against {len(users)} username(s)."
                        ),
                        recommendation=(
                            "Block the address at the firewall and confirm fail2ban or an "
                            "equivalent rate limiter is active. If SSH is exposed to the "
                            "internet, disable password authentication entirely."
                        ),
                        first_seen=burst[0].timestamp,
                        last_seen=burst[-1].timestamp,
                        event_count=len(burst),
                        usernames=users[:20],
                        evidence=[e.raw for e in burst[:5]],
                    )
                )
        return alerts


class PasswordSprayDetection(Detection):
    """One address trying many different usernames with few attempts each.

    This is the inverse of brute force and evades per-account lockouts, so a
    rule that only counts attempts per account misses it entirely.
    """

    rule_id = "password_spray"
    title = "Password spraying"

    def __init__(self, min_usernames: int = 6, window_seconds: int = 900) -> None:
        self.min_usernames = min_usernames
        self.window = timedelta(seconds=window_seconds)

    def run(self, events: list[AuthEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        for ip, ip_events in self._by_ip(events).items():
            failures = [e for e in ip_events if e.is_failure and e.username]
            if len(failures) < self.min_usernames:
                continue

            start = 0
            while start < len(failures):
                end = start
                while (
                    end + 1 < len(failures)
                    and failures[end + 1].timestamp - failures[start].timestamp <= self.window
                ):
                    end += 1
                window_events = failures[start : end + 1]
                users = sorted({e.username for e in window_events if e.username})
                if len(users) >= self.min_usernames:
                    alerts.append(
                        Alert(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=Severity.HIGH,
                            source_ip=ip,
                            description=(
                                f"{ip} attempted {len(users)} distinct usernames in "
                                f"{self.window.total_seconds() / 60:.0f} minutes. Spreading attempts "
                                "across accounts avoids per-account lockout thresholds."
                            ),
                            recommendation=(
                                "Block the address and review whether any of the attempted "
                                "usernames are real accounts. Enforce key-based authentication "
                                "and multi-factor authentication on any that are."
                            ),
                            first_seen=window_events[0].timestamp,
                            last_seen=window_events[-1].timestamp,
                            event_count=len(window_events),
                            usernames=users[:20],
                            evidence=[e.raw for e in window_events[:5]],
                        )
                    )
                    start = end + 1
                else:
                    start += 1
        return alerts


class SuccessAfterFailuresDetection(Detection):
    """A success from an address that had just been failing repeatedly.

    This is the highest-value signal in the whole tool: it is the difference
    between an attack that was attempted and an attack that worked.
    """

    rule_id = "success_after_failures"
    title = "Successful login after repeated failures"

    def __init__(self, min_failures: int = 5, window_seconds: int = 1800) -> None:
        self.min_failures = min_failures
        self.window = timedelta(seconds=window_seconds)

    def run(self, events: list[AuthEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        for ip, ip_events in self._by_ip(events).items():
            for index, event in enumerate(ip_events):
                if event.outcome is not Outcome.SUCCESS:
                    continue
                preceding = [
                    e
                    for e in ip_events[:index]
                    if e.is_failure and event.timestamp - e.timestamp <= self.window
                ]
                if len(preceding) < self.min_failures:
                    continue
                alerts.append(
                    Alert(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.CRITICAL,
                        source_ip=ip,
                        description=(
                            f"{ip} authenticated successfully as {event.username!r} after "
                            f"{len(preceding)} failed attempts in the preceding "
                            f"{self.window.total_seconds() / 60:.0f} minutes. Treat this account "
                            "as compromised until proven otherwise."
                        ),
                        recommendation=(
                            "Revoke the session immediately, rotate the account's credentials "
                            "and keys, then review command history, sudo logs, cron entries and "
                            "authorized_keys on the host for changes made after this login."
                        ),
                        first_seen=preceding[0].timestamp,
                        last_seen=event.timestamp,
                        event_count=len(preceding) + 1,
                        usernames=[event.username] if event.username else [],
                        evidence=[e.raw for e in preceding[:3]] + [event.raw],
                    )
                )
        return alerts


class UserEnumerationDetection(Detection):
    """Repeated attempts against accounts that do not exist."""

    rule_id = "user_enumeration"
    title = "Account enumeration"

    def __init__(self, threshold: int = 10) -> None:
        self.threshold = threshold

    def run(self, events: list[AuthEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        for ip, ip_events in self._by_ip(events).items():
            invalid = [e for e in ip_events if e.outcome is Outcome.INVALID_USER]
            if len(invalid) < self.threshold:
                continue
            users = sorted({e.username for e in invalid if e.username})
            dictionary_hits = sorted(u for u in users if u.lower() in COMMON_ATTACK_USERNAMES)
            alerts.append(
                Alert(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    source_ip=ip,
                    description=(
                        f"{ip} attempted {len(invalid)} logins against {len(users)} non-existent "
                        f"accounts. {len(dictionary_hits)} match well-known credential-list names, "
                        "which indicates automated scanning rather than a targeted attack."
                    ),
                    recommendation=(
                        "This is usually untargeted internet background noise. Block the address, "
                        "and if it is one of many, move SSH behind a VPN or allowlist rather than "
                        "blocking addresses one at a time."
                    ),
                    first_seen=invalid[0].timestamp,
                    last_seen=invalid[-1].timestamp,
                    event_count=len(invalid),
                    usernames=users[:20],
                    evidence=[e.raw for e in invalid[:5]],
                )
            )
        return alerts


class PrivilegedLoginDetection(Detection):
    """A successful interactive login as root or another privileged account."""

    rule_id = "privileged_login"
    title = "Privileged account login"

    def run(self, events: list[AuthEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        for ip, ip_events in self._by_ip(events).items():
            hits = [
                e
                for e in ip_events
                if e.outcome is Outcome.SUCCESS
                and e.username
                and e.username.lower() in PRIVILEGED_USERNAMES
            ]
            if not hits:
                continue
            # A password-based root login is materially worse than a key-based one.
            password_based = [e for e in hits if e.method.lower() in ("password", "keyboard-interactive")]
            severity = Severity.HIGH if password_based else Severity.MEDIUM
            alerts.append(
                Alert(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=severity,
                    source_ip=ip,
                    description=(
                        f"{len(hits)} successful login(s) as a privileged account from {ip}"
                        + (" using password authentication." if password_based else " using a key.")
                    ),
                    recommendation=(
                        "Disable direct root login with 'PermitRootLogin no' and require named "
                        "accounts with sudo, so that privileged actions are attributable to a person."
                    ),
                    first_seen=hits[0].timestamp,
                    last_seen=hits[-1].timestamp,
                    event_count=len(hits),
                    usernames=sorted({e.username for e in hits if e.username}),
                    evidence=[e.raw for e in hits[:5]],
                )
            )
        return alerts


class OffHoursAccessDetection(Detection):
    """Successful logins outside normal working hours.

    On its own this is weak evidence, so it is reported at LOW. Its value is
    corroboration: an off-hours login from an address that also appears in a
    brute-force alert is a much stronger signal than either alone.
    """

    rule_id = "off_hours_access"
    title = "Off-hours successful login"

    def __init__(self, start_hour: int = 7, end_hour: int = 20, min_events: int = 1) -> None:
        self.start_hour = start_hour
        self.end_hour = end_hour
        self.min_events = min_events

    def _is_off_hours(self, moment: datetime) -> bool:
        if moment.weekday() >= 5:
            return True
        return not (self.start_hour <= moment.hour < self.end_hour)

    def run(self, events: list[AuthEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        for ip, ip_events in self._by_ip(events).items():
            hits = [
                e
                for e in ip_events
                if e.outcome is Outcome.SUCCESS and self._is_off_hours(e.timestamp)
            ]
            if len(hits) < self.min_events:
                continue
            alerts.append(
                Alert(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.LOW,
                    source_ip=ip,
                    description=(
                        f"{len(hits)} successful login(s) from {ip} outside "
                        f"{self.start_hour:02d}:00-{self.end_hour:02d}:00 on a weekday, or at a weekend."
                    ),
                    recommendation=(
                        "Confirm with the account owner that the access was expected. Weak on its "
                        "own; treat it as corroboration if this address appears in other alerts."
                    ),
                    first_seen=hits[0].timestamp,
                    last_seen=hits[-1].timestamp,
                    event_count=len(hits),
                    usernames=sorted({e.username for e in hits if e.username}),
                    evidence=[e.raw for e in hits[:5]],
                )
            )
        return alerts


DEFAULT_DETECTIONS: tuple[Detection, ...] = (
    BruteForceDetection(),
    PasswordSprayDetection(),
    SuccessAfterFailuresDetection(),
    UserEnumerationDetection(),
    PrivilegedLoginDetection(),
    OffHoursAccessDetection(),
)
