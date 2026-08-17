"""Core types for the analysis pipeline.

The analyser is dependency-free by design: everything under app/analyser/ uses
only the standard library, so the engine can run as a cron job, inside a
container with no pip install step, or behind the API in app/main.py.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime


class Outcome(enum.Enum):
    """What happened to an authentication attempt."""

    SUCCESS = "success"
    FAILURE = "failure"
    INVALID_USER = "invalid_user"
    DISCONNECT = "disconnect"


class Severity(enum.Enum):
    """Alert severity, ordered so that comparisons work."""

    INFO = ("info", 1)
    LOW = ("low", 2)
    MEDIUM = ("medium", 3)
    HIGH = ("high", 4)
    CRITICAL = ("critical", 5)

    def __init__(self, label: str, rank: int) -> None:
        self.label = label
        self.rank = rank

    def __lt__(self, other: "Severity") -> bool:
        return self.rank < other.rank

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.label


@dataclass(frozen=True)
class AuthEvent:
    """One authentication attempt, normalised across log formats.

    Parsers for different sources (sshd, nginx, and anything added later) all
    produce this shape, which is what lets a single set of detection rules work
    across every source without knowing the log format.
    """

    timestamp: datetime
    source_ip: str
    username: str | None
    outcome: Outcome
    service: str
    method: str = ""
    host: str = ""
    port: int | None = None
    raw: str = ""

    @property
    def is_failure(self) -> bool:
        return self.outcome in (Outcome.FAILURE, Outcome.INVALID_USER)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "username": self.username,
            "outcome": self.outcome.value,
            "service": self.service,
            "method": self.method,
            "host": self.host,
        }


@dataclass
class Alert:
    """A detection rule firing on a group of events."""

    rule_id: str
    title: str
    severity: Severity
    source_ip: str
    description: str
    recommendation: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    usernames: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return (self.last_seen - self.first_seen).total_seconds()

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "source_ip": self.source_ip,
            "description": self.description,
            "recommendation": self.recommendation,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_seconds": self.duration_seconds,
            "event_count": self.event_count,
            "usernames": self.usernames,
            "evidence": self.evidence[:5],
        }


@dataclass
class ParseStats:
    """How much of the input we understood.

    Reporting unparsed lines matters: a tool that silently drops 40% of a log
    file gives false confidence, which is worse than no tool at all.
    """

    total_lines: int = 0
    parsed_events: int = 0
    unparsed_lines: int = 0
    ignored_lines: int = 0
    samples_unparsed: list[str] = field(default_factory=list)

    @property
    def parse_rate(self) -> float:
        relevant = self.parsed_events + self.unparsed_lines
        if relevant == 0:
            return 1.0
        return self.parsed_events / relevant

    def to_dict(self) -> dict:
        return {
            "total_lines": self.total_lines,
            "parsed_events": self.parsed_events,
            "unparsed_lines": self.unparsed_lines,
            "ignored_lines": self.ignored_lines,
            "parse_rate": round(self.parse_rate, 4),
            "samples_unparsed": self.samples_unparsed[:5],
        }
