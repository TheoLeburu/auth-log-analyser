"""Aggregations for the report and the dashboard trace."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .models import AuthEvent, Outcome


@dataclass
class IPSummary:
    ip: str
    total: int = 0
    failures: int = 0
    successes: int = 0
    usernames: set[str] = field(default_factory=set)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def failure_rate(self) -> float:
        return self.failures / self.total if self.total else 0.0

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "total": self.total,
            "failures": self.failures,
            "successes": self.successes,
            "distinct_usernames": len(self.usernames),
            "usernames": sorted(self.usernames)[:10],
            "failure_rate": round(self.failure_rate, 3),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


@dataclass
class Bucket:
    """One time slice of the activity trace."""

    start: datetime
    failures: int = 0
    successes: int = 0

    def to_dict(self) -> dict:
        return {
            "start": self.start.isoformat(),
            "failures": self.failures,
            "successes": self.successes,
        }


def summarise_ips(events: list[AuthEvent]) -> list[IPSummary]:
    """Per-address totals, ordered by failure count."""
    summaries: dict[str, IPSummary] = {}
    for event in events:
        summary = summaries.setdefault(event.source_ip, IPSummary(ip=event.source_ip))
        summary.total += 1
        if event.is_failure:
            summary.failures += 1
        elif event.outcome is Outcome.SUCCESS:
            summary.successes += 1
        if event.username:
            summary.usernames.add(event.username)
        if summary.first_seen is None or event.timestamp < summary.first_seen:
            summary.first_seen = event.timestamp
        if summary.last_seen is None or event.timestamp > summary.last_seen:
            summary.last_seen = event.timestamp
    return sorted(summaries.values(), key=lambda s: (-s.failures, -s.total))


def build_trace(events: list[AuthEvent], bucket_minutes: int = 60) -> list[Bucket]:
    """Bucket events over time so the dashboard can draw an activity trace.

    Empty buckets are included. Omitting them would compress a quiet week and a
    busy hour into the same visual width, which is exactly the distortion the
    trace exists to prevent.
    """
    if not events:
        return []

    size = timedelta(minutes=bucket_minutes)
    first = events[0].timestamp
    last = events[-1].timestamp

    def floor(moment: datetime) -> datetime:
        total_minutes = moment.hour * 60 + moment.minute
        floored = (total_minutes // bucket_minutes) * bucket_minutes
        return moment.replace(hour=floored // 60, minute=floored % 60, second=0, microsecond=0)

    start = floor(first)
    end = floor(last)
    buckets: dict[datetime, Bucket] = {}
    cursor = start
    # Guard against a pathological range producing millions of buckets.
    max_buckets = 5000
    while cursor <= end and len(buckets) < max_buckets:
        buckets[cursor] = Bucket(start=cursor)
        cursor += size

    for event in events:
        key = floor(event.timestamp)
        bucket = buckets.get(key)
        if bucket is None:
            continue
        if event.is_failure:
            bucket.failures += 1
        elif event.outcome is Outcome.SUCCESS:
            bucket.successes += 1

    return [buckets[k] for k in sorted(buckets)]


def outcome_counts(events: list[AuthEvent]) -> dict[str, int]:
    return dict(Counter(e.outcome.value for e in events))


def top_usernames(events: list[AuthEvent], limit: int = 10) -> list[dict]:
    counter: Counter[str] = Counter()
    for event in events:
        if event.username and event.is_failure:
            counter[event.username] += 1
    return [{"username": u, "attempts": n} for u, n in counter.most_common(limit)]


def service_breakdown(events: list[AuthEvent]) -> dict[str, dict[str, int]]:
    breakdown: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "failures": 0})
    for event in events:
        entry = breakdown[event.service]
        entry["total"] += 1
        if event.is_failure:
            entry["failures"] += 1
    return dict(breakdown)
