"""Command-line interface. Standard library only.

    python -m app.cli samples/auth.log
    python -m app.cli /var/log/auth.log --json > report.json
    cat /var/log/auth.log | python -m app.cli -
"""

from __future__ import annotations

import argparse
import json
import sys

from .analyser.detections import (
    BruteForceDetection,
    OffHoursAccessDetection,
    PasswordSprayDetection,
    PrivilegedLoginDetection,
    SuccessAfterFailuresDetection,
    UserEnumerationDetection,
)
from .analyser.models import Severity
from .analyser.pipeline import Report, analyse
from .analyser.stats import summarise_ips

_COLOURS = {
    "critical": "\033[95m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
    "info": "\033[90m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_EXIT_SEVERITY = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def _paint(text: str, colour: str, enabled: bool) -> str:
    return f"{colour}{text}{_RESET}" if enabled else text


def _sparkline(report: Report, width: int = 60) -> list[str]:
    """A compact activity trace for the terminal.

    The same idea as the dashboard's trace: bursts should be visible as shape,
    not buried in a table of numbers.
    """
    buckets = report.to_dict()["trace"]["buckets"]
    if not buckets:
        return []

    blocks = " ▁▂▃▄▅▆▇█"
    step = max(1, len(buckets) // width)
    condensed = []
    for index in range(0, len(buckets), step):
        chunk = buckets[index : index + step]
        condensed.append(
            (
                sum(b["failures"] for b in chunk),
                sum(b["successes"] for b in chunk),
            )
        )

    peak = max((f for f, _ in condensed), default=0)
    if peak == 0:
        return []

    line = "".join(blocks[min(8, round(f / peak * 8))] for f, _ in condensed)
    return [
        f"Failures over time  (peak {peak} per {report.bucket_minutes}min bucket)",
        line,
    ]


def render(report: Report, colour: bool = True, show_events: bool = False) -> str:
    out: list[str] = []
    span = report.time_range

    out.append(_paint("Authentication log analysis", _BOLD, colour))
    if span:
        out.append(f"  Window   {span[0]:%Y-%m-%d %H:%M} to {span[1]:%Y-%m-%d %H:%M}")
    out.append(f"  Events   {len(report.events)} from {len({e.source_ip for e in report.events})} addresses")
    parse = report.parse_stats
    out.append(
        f"  Parsing  {parse.parsed_events} parsed, {parse.ignored_lines} ignored, "
        f"{parse.unparsed_lines} unrecognised ({parse.parse_rate:.0%} of relevant lines understood)"
    )
    if parse.samples_unparsed:
        out.append(_paint(f"           example unrecognised: {parse.samples_unparsed[0][:90]}", _DIM, colour))
    out.append("")

    trace = _sparkline(report)
    if trace:
        out.extend(trace)
        out.append("")

    if not report.alerts:
        out.append("No alerts. Nothing in this log matched a detection rule.")
        return "\n".join(out)

    counts = report.severity_counts
    summary = "  ".join(
        _paint(f"{counts[label]} {label}", _COLOURS[label], colour)
        for label in ("critical", "high", "medium", "low", "info")
        if counts.get(label)
    )
    out.append(f"{_paint(str(len(report.alerts)), _BOLD, colour) if colour else len(report.alerts)} alerts:  {summary}")
    out.append("")

    for alert in report.alerts:
        badge = _paint(alert.severity.label.upper().ljust(8), _COLOURS[alert.severity.label], colour)
        out.append(f"{badge} {_paint(alert.title, _BOLD, colour)}  [{alert.source_ip}]")
        out.append(f"         {alert.description}")
        out.append(f"         {_paint('Window:', _DIM, colour)} {alert.first_seen:%Y-%m-%d %H:%M:%S} "
                   f"to {alert.last_seen:%H:%M:%S}  ({alert.event_count} events)")
        if alert.usernames:
            shown = ", ".join(alert.usernames[:8])
            more = f" (+{len(alert.usernames) - 8} more)" if len(alert.usernames) > 8 else ""
            out.append(f"         {_paint('Accounts:', _DIM, colour)} {shown}{more}")
        out.append(f"         {_paint('Action:', _DIM, colour)} {alert.recommendation}")
        if show_events and alert.evidence:
            out.append(f"         {_paint('Evidence:', _DIM, colour)}")
            for line in alert.evidence[:3]:
                out.append(f"           {_paint(line[:120], _DIM, colour)}")
        out.append("")

    sources = summarise_ips(report.events)[:5]
    if sources:
        out.append(_paint("Most active sources", _BOLD, colour))
        for source in sources:
            flag = " *" if source.ip in report.flagged_ips else "  "
            out.append(
                f"{flag} {source.ip:<18} {source.total:>5} events  "
                f"{source.failures:>5} failed  {len(source.usernames):>3} accounts"
            )
        out.append(_paint("   * appears in at least one alert", _DIM, colour))

    return "\n".join(out)


def build_detections(args) -> tuple:
    """Assemble detections with thresholds from the command line."""
    return (
        BruteForceDetection(threshold=args.brute_force_threshold, window_seconds=args.window),
        PasswordSprayDetection(min_usernames=args.spray_usernames),
        SuccessAfterFailuresDetection(min_failures=args.compromise_failures),
        UserEnumerationDetection(threshold=args.enumeration_threshold),
        PrivilegedLoginDetection(),
        OffHoursAccessDetection(start_hour=args.office_start, end_hour=args.office_end),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="auth-log-analyser",
        description="Find brute-force attempts, credential spraying and successful compromises in authentication logs.",
    )
    parser.add_argument("logfile", help="Path to the log file, or - for standard input")
    parser.add_argument("--json", action="store_true", help="Emit the full report as JSON")
    parser.add_argument("--evidence", action="store_true", help="Include raw log lines under each alert")
    parser.add_argument("--no-colour", action="store_true", help="Disable ANSI colour")
    parser.add_argument("--bucket-minutes", type=int, default=60, help="Trace resolution (default: 60)")
    parser.add_argument(
        "--fail-on",
        choices=list(_EXIT_SEVERITY),
        default=None,
        help="Exit 1 if any alert is at or above this severity. Useful in a cron job or CI.",
    )

    tuning = parser.add_argument_group("detection thresholds")
    tuning.add_argument("--brute-force-threshold", type=int, default=8)
    tuning.add_argument("--window", type=int, default=300, help="Brute-force window in seconds")
    tuning.add_argument("--spray-usernames", type=int, default=6)
    tuning.add_argument("--compromise-failures", type=int, default=5)
    tuning.add_argument("--enumeration-threshold", type=int, default=10)
    tuning.add_argument("--office-start", type=int, default=7)
    tuning.add_argument("--office-end", type=int, default=20)

    args = parser.parse_args(argv)

    try:
        if args.logfile == "-":
            report = analyse(sys.stdin, detections=build_detections(args), bucket_minutes=args.bucket_minutes)
        else:
            with open(args.logfile, "r", encoding="utf-8", errors="replace") as handle:
                report = analyse(handle, detections=build_detections(args), bucket_minutes=args.bucket_minutes)
    except FileNotFoundError:
        print(f"error: no such file: {args.logfile}", file=sys.stderr)
        return 2
    except PermissionError:
        print(
            f"error: cannot read {args.logfile}. Authentication logs are usually root-owned; "
            "try running with sudo.",
            file=sys.stderr,
        )
        return 2

    try:
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            use_colour = not args.no_colour and sys.stdout.isatty()
            print(render(report, colour=use_colour, show_events=args.evidence))
    except BrokenPipeError:
        # Happens when output is piped into head, less, or grep -q. Exiting
        # quietly is the expected Unix behaviour; a traceback here is noise.
        try:
            sys.stdout.close()
        finally:
            return 0

    if args.fail_on:
        threshold = _EXIT_SEVERITY[args.fail_on]
        if any(a.severity.rank >= threshold.rank for a in report.alerts):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
