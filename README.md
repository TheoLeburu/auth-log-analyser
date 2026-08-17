# Auth Log Analyser

Reads SSH and web authentication logs and tells you whether anyone got in.

Most log tools count things. This one answers a question: *did an attack succeed?* The highest-severity rule fires when a successful login follows a burst of failures from the same address, because that single pattern is the difference between an attack that was attempted and an attack that worked.

```bash
python -m app.cli samples/auth.log
```

```
Authentication log analysis
  Window   2026-03-17 07:33 to 2026-03-19 23:15
  Events   179 from 7 addresses
  Parsing  179 parsed, 52 ignored, 0 unrecognised (100% of relevant lines understood)

Failures over time  (peak 70 per 60min bucket)
                   █▅                        ▁▁                 ▁

9 alerts:  1 critical  4 high  3 medium  1 low

CRITICAL Successful login after repeated failures  [203.0.113.201]
         203.0.113.201 authenticated successfully as 'kabelo' after 9 failed
         attempts in the preceding 30 minutes. Treat this account as
         compromised until proven otherwise.
         Window: 2026-03-19 23:12:00 to 23:15:20  (10 events)
         Action: Revoke the session immediately, rotate the account's
         credentials and keys, then review command history, sudo logs, cron
         entries and authorized_keys on the host for changes made after
         this login.
```

---

## Detection rules

| Rule | Severity | Fires when |
|---|---|---|
| Successful login after repeated failures | Critical | A success follows ≥5 failures from the same address within 30 minutes |
| Brute force | High / Medium | ≥8 failures from one address inside a 5-minute window; High at 3× the threshold |
| Password spraying | High | One address tries ≥6 distinct usernames within 15 minutes |
| Account enumeration | Medium | ≥10 attempts against accounts that do not exist |
| Privileged account login | High / Medium | A successful `root` or `admin` login; High if password-based |
| Off-hours access | Low | A successful login outside working hours or at a weekend |

Every threshold is a constructor argument and every one is exposed on the command line. A threshold that suits a home server is wrong for a bastion host serving fifty engineers, so nothing is hard-coded.

```bash
python -m app.cli /var/log/auth.log --brute-force-threshold 20 --office-start 6 --office-end 22
```

**Why spraying gets its own rule.** Brute force hammers one account; spraying tries one password against many accounts specifically to stay under per-account lockout limits. A tool that only counts attempts per account misses it entirely, which is why the two rules look at the data from opposite directions.

**Why off-hours access is only Low.** On its own it is weak evidence — people work late. Its value is corroboration: an off-hours login from an address that also appears in a brute-force alert is a much stronger signal than either alert alone. Rating it higher would train you to ignore it.

## Supported formats

- **OpenSSH via syslog** — the traditional `Mar 15 08:12:33 host sshd[123]:` format and the ISO-8601 format emitted by systemd
- **nginx access logs** — combined format, where 401 and 403 responses on authentication paths become failure events

Two details that trip up naive parsers, both handled here:

**Syslog carries no year.** A parser that assumes the current year produces December timestamps dated in the future every January. `infer_year()` walks back across the boundary.

**rsyslog collapses repeats.** A line reading `message repeated 12 times: [ Failed password ... ]` represents twelve attempts. Counting it as one undercounts exactly the burst you are trying to detect, so repeats are expanded before analysis.

## Web interface

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://localhost:8000`. Load the bundled sample or upload your own log.

The dashboard leads with a verdict in plain language rather than a row of counters — "An account was accessed after repeated failed attempts" is the thing you need to know, and a grid of numbers buries it. Below that is an activity trace: failures rise above the baseline, successful logins drop below it, and every time bucket occupies equal width so a quiet week and a busy hour are not compressed into the same space. Selecting an alert highlights that address's activity in the trace.

API documentation is at `/docs`.

| Endpoint | Purpose |
|---|---|
| `GET /api/sample` | Analyse the bundled sample log |
| `POST /api/analyse` | Analyse an uploaded file (20MB limit) |
| `POST /api/analyse-text` | Analyse pasted lines (50,000 line limit) |

## Architecture

```
app/
├── analyser/          # Zero-dependency engine. Imports nothing from app/.
│   ├── models.py      # AuthEvent, Alert, Severity, ParseStats
│   ├── parsers.py     # sshd + nginx, with a registry for adding more
│   ├── detections.py  # Six independent rules
│   ├── stats.py       # Per-address summaries and the time-bucketed trace
│   └── pipeline.py    # Orchestration and the report object
├── main.py            # FastAPI interface
├── cli.py             # Command-line interface
└── static/            # Dashboard, no build step
```

Parsers normalise every source into one `AuthEvent` shape, which is what lets a single set of detection rules work across formats. Adding a new log source means writing one parser class; no rule changes. Adding a new rule means writing one `Detection` subclass; no parser changes.

The engine has no third-party dependencies, so it runs as a cron job or in a minimal container without a `pip install` step. FastAPI is one interface onto it, not the thing itself.

## Reporting what it did not understand

Every report states how many lines were parsed, how many were recognised but irrelevant, and how many were not understood at all, with examples of the last group.

A tool that silently discards 40% of a log file gives false confidence, and false confidence about security is worse than no tool. The sample log parses at 100%; on a real server, expect less, and the number tells you how much to trust the result.

## Sample data

`samples/auth.log` contains three days of activity across seven addresses: normal key-based staff logins, a few ordinary mistyped passwords, a sustained brute force against `root`, a dictionary scan, a password spray, and one successful compromise. It is generated deterministically from a fixed seed:

```bash
python samples/generate_sample_log.py > samples/auth.log
```

CI regenerates it and diffs against the committed copy, so the sample, the README output, and the tests cannot drift apart.

## Tests

```bash
python -m unittest discover -s tests -v
```

57 tests, all offline. Alongside the obvious cases, the suite covers what should *not* alert: occasional typos spread across a day, repeated attempts on a single account (not spraying), a success *before* failures rather than after, and — most importantly — a check that none of the legitimate office addresses in the sample log are ever flagged. A detector that cries wolf gets switched off within a week, so false positives are tested as deliberately as true ones.

## Limitations

Worth being straight about:

- **No geolocation or impossible-travel detection.** That needs a GeoIP database and introduces a dependency and a data-freshness problem.
- **Rules are stateless per run.** Analysing the same file twice produces the same alerts. There is no alert history or deduplication across runs.
- **In-memory analysis.** A multi-gigabyte log will exhaust memory. Rotate or split first.
- **No authentication on the web interface.** It is built for local use. Do not expose it to the internet without putting a proxy and access control in front of it — log files contain usernames and internal addresses.

## Roadmap

- [ ] `journalctl` JSON input
- [ ] Alert state across runs, so a cron job only reports what is new
- [ ] Optional GeoIP enrichment behind a feature flag
- [ ] Windows Security Event Log (4624/4625) parser
- [ ] Export findings as CSV for ticketing systems

## Licence

MIT
