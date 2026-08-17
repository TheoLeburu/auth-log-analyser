"""Tests for the auth log analyser.

All tests run offline against literal log lines, so the suite is deterministic
and fast. Where a rule depends on timing, the fixtures state the timestamps
explicitly rather than relying on the clock.
"""

from __future__ import annotations

import unittest
from datetime import datetime
from pathlib import Path

from app.analyser.detections import (
    BruteForceDetection,
    OffHoursAccessDetection,
    PasswordSprayDetection,
    PrivilegedLoginDetection,
    SuccessAfterFailuresDetection,
    UserEnumerationDetection,
)
from app.analyser.models import AuthEvent, Outcome, Severity
from app.analyser.parsers import infer_year, parse_lines
from app.analyser.pipeline import analyse, analyse_file
from app.analyser.stats import build_trace, summarise_ips, top_usernames

REFERENCE = datetime(2026, 6, 1, 12, 0, 0)
SAMPLE_LOG = Path(__file__).parent.parent / "samples" / "auth.log"


def event(
    minute: int = 0,
    ip: str = "203.0.113.45",
    user: str | None = "root",
    outcome: Outcome = Outcome.FAILURE,
    second: int = 0,
    hour: int = 3,
    method: str = "password",
    day: int = 16,
) -> AuthEvent:
    """Build an event. Day 16 of March 2026 is a Monday, so weekday rules apply."""
    return AuthEvent(
        timestamp=datetime(2026, 3, day, hour, minute, second),
        source_ip=ip,
        username=user,
        outcome=outcome,
        service="sshd",
        method=method,
        raw=f"synthetic {outcome.value} {user}@{ip}",
    )


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

class SSHDParserTests(unittest.TestCase):
    def parse_one(self, line: str):
        events, stats = parse_lines([line], reference=REFERENCE)
        return events, stats

    def test_accepted_publickey(self):
        line = ("Mar 15 08:12:40 web01 sshd[2843]: Accepted publickey for deploy "
                "from 10.0.0.5 port 40122 ssh2: RSA SHA256:abc123")
        events, _ = self.parse_one(line)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].outcome, Outcome.SUCCESS)
        self.assertEqual(events[0].username, "deploy")
        self.assertEqual(events[0].source_ip, "10.0.0.5")
        self.assertEqual(events[0].method, "publickey")
        self.assertEqual(events[0].host, "web01")

    def test_failed_password(self):
        line = "Mar 15 08:12:33 web01 sshd[2841]: Failed password for root from 203.0.113.45 port 51234 ssh2"
        events, _ = self.parse_one(line)
        self.assertEqual(events[0].outcome, Outcome.FAILURE)
        self.assertEqual(events[0].username, "root")

    def test_failed_password_invalid_user_is_distinguished(self):
        line = ("Mar 15 08:12:33 web01 sshd[2841]: Failed password for invalid user admin "
                "from 203.0.113.45 port 51234 ssh2")
        events, _ = self.parse_one(line)
        self.assertEqual(events[0].outcome, Outcome.INVALID_USER)
        self.assertEqual(events[0].username, "admin")

    def test_invalid_user_line(self):
        line = "Mar 15 08:12:40 web01 sshd[2844]: Invalid user oracle from 203.0.113.45 port 51240"
        events, _ = self.parse_one(line)
        self.assertEqual(events[0].outcome, Outcome.INVALID_USER)
        self.assertEqual(events[0].username, "oracle")

    def test_preauth_disconnect(self):
        line = ("Mar 15 08:12:41 web01 sshd[2845]: Connection closed by authenticating user root "
                "203.0.113.45 port 51250 [preauth]")
        events, _ = self.parse_one(line)
        self.assertEqual(events[0].outcome, Outcome.DISCONNECT)

    def test_iso_timestamp_format(self):
        line = ("2026-03-15T08:12:33.123456+00:00 web01 sshd[2841]: Failed password for root "
                "from 203.0.113.45 port 51234 ssh2")
        events, _ = self.parse_one(line)
        self.assertEqual(events[0].timestamp.year, 2026)
        self.assertEqual(events[0].timestamp.hour, 8)

    def test_repeated_message_is_expanded(self):
        """rsyslog collapses bursts; undercounting them would hide the attack."""
        line = ("Mar 15 08:12:50 web01 sshd[2846]: message repeated 5 times: "
                "[ Failed password for root from 203.0.113.45 port 51234 ssh2]")
        events, _ = self.parse_one(line)
        self.assertEqual(len(events), 5)
        self.assertTrue(all(e.outcome is Outcome.FAILURE for e in events))

    def test_session_lines_are_ignored_not_unparsed(self):
        line = ("Mar 15 08:12:41 web01 sshd[2843]: pam_unix(sshd:session): session opened "
                "for user deploy(uid=1001) by (uid=0)")
        events, stats = self.parse_one(line)
        self.assertEqual(events, [])
        self.assertEqual(stats.ignored_lines, 1)
        self.assertEqual(stats.unparsed_lines, 0)

    def test_non_sshd_process_is_ignored(self):
        line = "Mar 15 08:12:41 web01 cron[1234]: (root) CMD (/usr/bin/backup.sh)"
        events, stats = self.parse_one(line)
        self.assertEqual(events, [])
        self.assertEqual(stats.ignored_lines, 1)

    def test_garbage_line_counts_as_unparsed(self):
        events, stats = self.parse_one("this is not a log line at all")
        self.assertEqual(events, [])
        self.assertEqual(stats.unparsed_lines, 1)
        self.assertEqual(stats.parse_rate, 0.0)

    def test_unknown_sshd_message_counts_as_unparsed(self):
        line = "Mar 15 08:12:41 web01 sshd[2843]: some future message format we do not know"
        _, stats = self.parse_one(line)
        self.assertEqual(stats.unparsed_lines, 1)


class YearInferenceTests(unittest.TestCase):
    """Syslog lines carry no year, so a naive parser produces future dates."""

    def test_same_year_when_date_is_in_the_past(self):
        self.assertEqual(infer_year(3, 15, datetime(2026, 6, 1)), 2026)

    def test_previous_year_across_the_new_year_boundary(self):
        self.assertEqual(infer_year(12, 28, datetime(2026, 1, 3)), 2025)

    def test_today_is_this_year(self):
        self.assertEqual(infer_year(6, 1, datetime(2026, 6, 1)), 2026)


class NginxParserTests(unittest.TestCase):
    def test_401_on_login_path_is_a_failure(self):
        line = ('203.0.113.45 - - [15/Mar/2026:08:12:33 +0000] "POST /wp-login.php HTTP/1.1" '
                '401 152 "-" "curl/7.68"')
        events, _ = parse_lines([line], reference=REFERENCE)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].outcome, Outcome.FAILURE)
        self.assertEqual(events[0].service, "nginx")

    def test_200_on_login_path_is_a_success(self):
        line = ('41.79.10.22 - - [15/Mar/2026:08:12:33 +0000] "POST /api/login HTTP/1.1" '
                '200 512 "-" "Mozilla/5.0"')
        events, _ = parse_lines([line], reference=REFERENCE)
        self.assertEqual(events[0].outcome, Outcome.SUCCESS)

    def test_404_on_asset_path_is_ignored(self):
        """Treating scanner 404s as auth failures would drown the detections in noise."""
        line = ('192.0.2.199 - - [15/Mar/2026:08:12:33 +0000] "GET /.env HTTP/1.1" '
                '404 152 "-" "Nuclei/3.1"')
        events, stats = parse_lines([line], reference=REFERENCE)
        self.assertEqual(events, [])
        self.assertEqual(stats.ignored_lines, 1)
        self.assertEqual(stats.unparsed_lines, 0)

    def test_static_asset_200_is_ignored(self):
        line = ('41.79.10.22 - - [15/Mar/2026:09:00:00 +0000] "GET /assets/app.css HTTP/1.1" '
                '200 4021 "-" "Mozilla/5.0"')
        events, _ = parse_lines([line], reference=REFERENCE)
        self.assertEqual(events, [])


class MixedSourceTests(unittest.TestCase):
    def test_events_are_returned_in_time_order(self):
        lines = [
            "Mar 15 09:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
            "Mar 15 08:00:00 web01 sshd[2]: Failed password for root from 1.2.3.4 port 2 ssh2",
            'Mar 15 07:00:00 web01 sshd[3]: Failed password for root from 1.2.3.4 port 3 ssh2',
        ]
        events, _ = parse_lines(lines, reference=REFERENCE)
        stamps = [e.timestamp for e in events]
        self.assertEqual(stamps, sorted(stamps))


# ---------------------------------------------------------------------------
# Detections
# ---------------------------------------------------------------------------

class BruteForceTests(unittest.TestCase):
    def test_burst_above_threshold_alerts(self):
        events = [event(minute=0, second=i * 5) for i in range(10)]
        alerts = BruteForceDetection(threshold=8, window_seconds=300).run(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].event_count, 10)

    def test_below_threshold_is_quiet(self):
        events = [event(minute=0, second=i * 5) for i in range(4)]
        self.assertEqual(BruteForceDetection(threshold=8).run(events), [])

    def test_large_burst_escalates_to_high(self):
        events = [event(minute=i // 12, second=(i * 4) % 60) for i in range(30)]
        alerts = BruteForceDetection(threshold=8, window_seconds=300).run(events)
        self.assertEqual(alerts[0].severity, Severity.HIGH)

    def test_slow_failures_spread_out_do_not_alert(self):
        """Occasional typos across a day must not look like an attack."""
        events = [event(hour=8 + i, minute=0, ip="10.0.0.5", user="theo") for i in range(9)]
        self.assertEqual(BruteForceDetection(threshold=8, window_seconds=300).run(events), [])

    def test_successes_do_not_count_toward_brute_force(self):
        events = [event(second=i * 5, outcome=Outcome.SUCCESS) for i in range(12)]
        self.assertEqual(BruteForceDetection(threshold=8).run(events), [])

    def test_failures_from_different_ips_are_not_pooled(self):
        events = [event(second=i * 5, ip=f"10.0.0.{i}") for i in range(12)]
        self.assertEqual(BruteForceDetection(threshold=8).run(events), [])

    def test_collapsed_syslog_burst_reports_no_rate(self):
        """Identical timestamps mean per-attempt timing is unknown, not zero."""
        events = [event(second=0) for _ in range(12)]
        alerts = BruteForceDetection(threshold=8).run(events)
        self.assertIn("collapsed syslog entry", alerts[0].description)


class PasswordSprayTests(unittest.TestCase):
    def test_many_usernames_from_one_ip_alerts(self):
        users = ["theo", "deploy", "hr", "finance", "info", "sales", "intern"]
        events = [event(minute=i, user=u) for i, u in enumerate(users)]
        alerts = PasswordSprayDetection(min_usernames=6).run(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.HIGH)

    def test_repeated_attempts_on_one_account_is_not_spraying(self):
        events = [event(minute=i, user="theo") for i in range(12)]
        self.assertEqual(PasswordSprayDetection(min_usernames=6).run(events), [])

    def test_usernames_spread_beyond_the_window_do_not_alert(self):
        users = ["a", "b", "c", "d", "e", "f", "g"]
        events = [event(hour=i, user=u) for i, u in enumerate(users)]
        self.assertEqual(PasswordSprayDetection(min_usernames=6, window_seconds=900).run(events), [])


class SuccessAfterFailuresTests(unittest.TestCase):
    def test_success_following_failures_is_critical(self):
        events = [event(minute=i, user="kabelo") for i in range(6)]
        events.append(event(minute=7, user="kabelo", outcome=Outcome.SUCCESS))
        alerts = SuccessAfterFailuresDetection(min_failures=5).run(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.CRITICAL)
        self.assertIn("kabelo", alerts[0].usernames)

    def test_success_with_few_prior_failures_is_quiet(self):
        events = [event(minute=i, user="theo") for i in range(2)]
        events.append(event(minute=3, user="theo", outcome=Outcome.SUCCESS))
        self.assertEqual(SuccessAfterFailuresDetection(min_failures=5).run(events), [])

    def test_failures_long_before_the_success_are_out_of_window(self):
        events = [event(hour=1, minute=i, user="theo") for i in range(8)]
        events.append(event(hour=9, minute=0, user="theo", outcome=Outcome.SUCCESS))
        self.assertEqual(
            SuccessAfterFailuresDetection(min_failures=5, window_seconds=1800).run(events), []
        )

    def test_success_before_the_failures_does_not_alert(self):
        """Order matters: a success then failures is a user fumbling a second session."""
        events = [event(minute=0, user="theo", outcome=Outcome.SUCCESS)]
        events += [event(minute=i + 1, user="theo") for i in range(8)]
        self.assertEqual(SuccessAfterFailuresDetection(min_failures=5).run(events), [])


class UserEnumerationTests(unittest.TestCase):
    def test_many_invalid_users_alerts(self):
        events = [
            event(minute=i, user=f"svc{i}", outcome=Outcome.INVALID_USER) for i in range(12)
        ]
        alerts = UserEnumerationDetection(threshold=10).run(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.MEDIUM)

    def test_dictionary_names_are_counted_in_the_description(self):
        users = ["admin", "test", "oracle", "postgres", "ubuntu", "pi",
                 "guest", "ftp", "mysql", "git", "jenkins"]
        events = [event(minute=i, user=u, outcome=Outcome.INVALID_USER) for i, u in enumerate(users)]
        alerts = UserEnumerationDetection(threshold=10).run(events)
        self.assertIn("11 match well-known", alerts[0].description)

    def test_valid_user_failures_are_not_enumeration(self):
        events = [event(minute=i, user="theo") for i in range(15)]
        self.assertEqual(UserEnumerationDetection(threshold=10).run(events), [])


class PrivilegedLoginTests(unittest.TestCase):
    def test_root_password_login_is_high(self):
        events = [event(outcome=Outcome.SUCCESS, user="root", method="password")]
        alerts = PrivilegedLoginDetection().run(events)
        self.assertEqual(alerts[0].severity, Severity.HIGH)

    def test_root_key_login_is_medium(self):
        events = [event(outcome=Outcome.SUCCESS, user="root", method="publickey")]
        alerts = PrivilegedLoginDetection().run(events)
        self.assertEqual(alerts[0].severity, Severity.MEDIUM)

    def test_normal_user_login_is_quiet(self):
        events = [event(outcome=Outcome.SUCCESS, user="theo", method="publickey")]
        self.assertEqual(PrivilegedLoginDetection().run(events), [])

    def test_failed_root_login_is_not_a_privileged_login(self):
        events = [event(outcome=Outcome.FAILURE, user="root")]
        self.assertEqual(PrivilegedLoginDetection().run(events), [])


class OffHoursTests(unittest.TestCase):
    def test_night_login_on_a_weekday_alerts(self):
        events = [event(hour=3, outcome=Outcome.SUCCESS, user="theo", day=16)]
        alerts = OffHoursAccessDetection(start_hour=7, end_hour=20).run(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.LOW)

    def test_office_hours_login_is_quiet(self):
        events = [event(hour=11, outcome=Outcome.SUCCESS, user="theo", day=16)]
        self.assertEqual(OffHoursAccessDetection().run(events), [])

    def test_weekend_daytime_login_still_alerts(self):
        # 21 March 2026 is a Saturday.
        events = [event(hour=11, outcome=Outcome.SUCCESS, user="theo", day=21)]
        self.assertEqual(len(OffHoursAccessDetection().run(events)), 1)

    def test_failures_off_hours_are_not_this_rule(self):
        events = [event(hour=3, outcome=Outcome.FAILURE, user="theo")]
        self.assertEqual(OffHoursAccessDetection().run(events), [])


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

class StatsTests(unittest.TestCase):
    def test_ip_summary_orders_by_failures(self):
        events = [event(ip="1.1.1.1") for _ in range(3)]
        events += [event(ip="2.2.2.2") for _ in range(7)]
        summaries = summarise_ips(events)
        self.assertEqual(summaries[0].ip, "2.2.2.2")
        self.assertEqual(summaries[0].failures, 7)

    def test_failure_rate(self):
        events = [event(ip="1.1.1.1") for _ in range(3)]
        events.append(event(ip="1.1.1.1", outcome=Outcome.SUCCESS))
        self.assertAlmostEqual(summarise_ips(events)[0].failure_rate, 0.75)

    def test_trace_includes_empty_buckets(self):
        """A quiet stretch must occupy visual width, or bursts look continuous."""
        events = [event(hour=1), event(hour=6)]
        buckets = build_trace(events, bucket_minutes=60)
        self.assertEqual(len(buckets), 6)
        self.assertEqual(buckets[0].failures, 1)
        self.assertEqual(buckets[1].failures, 0)
        self.assertEqual(buckets[-1].failures, 1)

    def test_trace_of_empty_input(self):
        self.assertEqual(build_trace([]), [])

    def test_top_usernames_counts_only_failures(self):
        events = [event(user="root") for _ in range(4)]
        events += [event(user="theo", outcome=Outcome.SUCCESS) for _ in range(9)]
        top = top_usernames(events)
        self.assertEqual(top[0]["username"], "root")
        self.assertEqual(len(top), 1)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class PipelineTests(unittest.TestCase):
    def test_empty_input_produces_an_empty_report(self):
        report = analyse([])
        self.assertEqual(report.events, [])
        self.assertEqual(report.alerts, [])
        self.assertIsNone(report.worst_severity)
        self.assertIsNone(report.time_range)
        payload = report.to_dict()
        self.assertEqual(payload["summary"]["events"], 0)

    def test_alerts_are_sorted_worst_first(self):
        lines = []
        for index in range(9):
            lines.append(
                f"Mar 16 03:0{index // 6}:{(index * 9) % 60:02d} web01 sshd[{index}]: "
                f"Failed password for kabelo from 203.0.113.201 port 5000{index} ssh2"
            )
        lines.append(
            "Mar 16 03:03:30 web01 sshd[99]: Accepted password for kabelo "
            "from 203.0.113.201 port 44122 ssh2"
        )
        report = analyse(lines, reference=REFERENCE)
        self.assertEqual(report.alerts[0].severity, Severity.CRITICAL)
        ranks = [a.severity.rank for a in report.alerts]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_flagged_ips_reflects_alerting_addresses(self):
        lines = [
            f"Mar 16 03:00:{i * 5:02d} web01 sshd[{i}]: Failed password for root "
            f"from 203.0.113.45 port 5000{i} ssh2"
            for i in range(10)
        ]
        report = analyse(lines, reference=REFERENCE)
        self.assertIn("203.0.113.45", report.flagged_ips)

    def test_report_serialises_completely(self):
        lines = [
            "Mar 16 09:00:00 web01 sshd[1]: Accepted publickey for theo from 10.0.0.5 port 40000 ssh2: ED25519 SHA256:x"
        ]
        payload = analyse(lines, reference=REFERENCE).to_dict()
        for key in ("summary", "parsing", "alerts", "top_sources", "top_usernames", "services", "trace"):
            self.assertIn(key, payload)


class SampleLogTests(unittest.TestCase):
    """The committed sample must keep demonstrating what the README claims."""

    @unittest.skipUnless(SAMPLE_LOG.exists(), "sample log not present")
    def test_sample_log_parses_completely(self):
        report = analyse_file(SAMPLE_LOG)
        self.assertEqual(report.parse_stats.unparsed_lines, 0)
        self.assertGreater(report.parse_stats.parsed_events, 100)

    @unittest.skipUnless(SAMPLE_LOG.exists(), "sample log not present")
    def test_sample_log_surfaces_the_compromise(self):
        report = analyse_file(SAMPLE_LOG)
        critical = [a for a in report.alerts if a.severity is Severity.CRITICAL]
        self.assertTrue(critical, "sample log should contain one compromise")
        self.assertEqual(critical[0].rule_id, "success_after_failures")
        self.assertIn("kabelo", critical[0].usernames)

    @unittest.skipUnless(SAMPLE_LOG.exists(), "sample log not present")
    def test_sample_log_triggers_every_rule(self):
        report = analyse_file(SAMPLE_LOG)
        fired = {a.rule_id for a in report.alerts}
        for rule in (
            "brute_force",
            "password_spray",
            "success_after_failures",
            "user_enumeration",
            "off_hours_access",
        ):
            self.assertIn(rule, fired, f"{rule} did not fire on the sample log")

    @unittest.skipUnless(SAMPLE_LOG.exists(), "sample log not present")
    def test_office_addresses_are_not_flagged(self):
        """False positives on normal staff activity would make the tool unusable."""
        report = analyse_file(SAMPLE_LOG)
        for ip in ("41.79.10.22", "41.79.10.23", "10.0.0.5"):
            self.assertNotIn(ip, report.flagged_ips, f"{ip} was flagged but is legitimate")


if __name__ == "__main__":
    unittest.main()
