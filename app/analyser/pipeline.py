"""The analysis pipeline: lines in, report out."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from pathlib import Path

from .detections import DEFAULT_DETECTIONS, Detection
from .models import Alert, AuthEvent, ParseStats, Severity
from .parsers import DEFAULT_PARSERS, Parser, parse_lines
from .stats import (
    build_trace,
    outcome_counts,
    service_breakdown,
    summarise_ips,
    top_usernames,
)

# Order alerts worst-first so the thing that needs attention is at the top.
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class Report:
    events: list[AuthEvent]
    alerts: list[Alert]
    parse_stats: ParseStats
    bucket_minutes: int = 60
    generated_at: dt.datetime = field(default_factory=dt.datetime.now)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for alert in self.alerts:
            counts[alert.severity.label] = counts.get(alert.severity.label, 0) + 1
        return counts

    @property
    def worst_severity(self) -> Severity | None:
        return max((a.severity for a in self.alerts), default=None)

    @property
    def time_range(self) -> tuple[dt.datetime, dt.datetime] | None:
        if not self.events:
            return None
        return self.events[0].timestamp, self.events[-1].timestamp

    @property
    def flagged_ips(self) -> list[str]:
        """Addresses that appear in at least one alert, worst-first."""
        seen: dict[str, int] = {}
        for alert in sorted(self.alerts, key=lambda a: _SEVERITY_ORDER[a.severity]):
            seen.setdefault(alert.source_ip, _SEVERITY_ORDER[alert.severity])
        return list(seen)

    def to_dict(self) -> dict:
        span = self.time_range
        return {
            "generated_at": self.generated_at.isoformat(),
            "summary": {
                "events": len(self.events),
                "alerts": len(self.alerts),
                "worst_severity": self.worst_severity.label if self.worst_severity else None,
                "severity_counts": self.severity_counts,
                "outcome_counts": outcome_counts(self.events),
                "distinct_ips": len({e.source_ip for e in self.events}),
                "flagged_ips": self.flagged_ips,
                "from": span[0].isoformat() if span else None,
                "to": span[1].isoformat() if span else None,
            },
            "parsing": self.parse_stats.to_dict(),
            "alerts": [a.to_dict() for a in self.alerts],
            "top_sources": [s.to_dict() for s in summarise_ips(self.events)[:15]],
            "top_usernames": top_usernames(self.events),
            "services": service_breakdown(self.events),
            "trace": {
                "bucket_minutes": self.bucket_minutes,
                "buckets": [b.to_dict() for b in build_trace(self.events, self.bucket_minutes)],
            },
        }


def analyse(
    lines,
    parsers: tuple[Parser, ...] = DEFAULT_PARSERS,
    detections: tuple[Detection, ...] = DEFAULT_DETECTIONS,
    reference: dt.datetime | None = None,
    bucket_minutes: int = 60,
) -> Report:
    """Run the full pipeline over an iterable of log lines."""
    events, parse_stats = parse_lines(lines, parsers=parsers, reference=reference)

    alerts: list[Alert] = []
    for detection in detections:
        alerts.extend(detection.run(events))

    alerts.sort(key=lambda a: (_SEVERITY_ORDER[a.severity], -a.event_count, a.first_seen))
    return Report(
        events=events,
        alerts=alerts,
        parse_stats=parse_stats,
        bucket_minutes=bucket_minutes,
    )


def analyse_file(path: str | Path, **kwargs) -> Report:
    """Analyse a log file, streaming it rather than reading it all into memory."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return analyse(handle, **kwargs)
