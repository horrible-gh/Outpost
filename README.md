# Outpost

Outpost is a small, long-running server patrol tool focused on **observation, security-oriented review, and concise patrol journals**.

The current prototype is intentionally conservative:

> Observe first. Record what happened. Do not modify the target server.

## Current prototype

Implemented now:

- Go single-binary application
- Embedded interval scheduler
- Immediate patrol on startup
- Manual one-shot patrol from the Web UI
- Local Linux / Windows collection
- Read-only collection of:
  - disk information
  - process information
  - network connections
  - successful login history
  - failed login history
  - memory information
  - security/update information where available
- Baseline comparison against the previous patrol
- Structured severity/check model
- JSONL patrol journal
- Small Web patrol console
- JSON APIs for status/history/manual patrol

Not implemented yet:

- Remote SSH / WinRM targets
- Multiple configured targets
- OpenAI / Claude review
- AI-generated follow-up read-only investigation
- persistent configuration UI
- advanced compromise detection
- alert integrations
- remediation / automatic server changes

## Safety policy

The initial Outpost collector performs observation only.

- No automatic remediation
- No service restart
- No package installation
- No file modification on the monitored host
- AI integration, when added, will be advisory by default
- Any future mutating operation must be explicitly separated from patrol collection

## Architecture

```text
Embedded Scheduler ─────┐
                        ├─> Patrol Runner
Web: Run patrol now ────┘        │
                                 v
                         Local Collector
                                 │
                                 v
                           Snapshot
                                 │
                                 v
                      Heuristic Analyzer
                                 │
                         Previous Snapshot
                                 │
                                 v
                     Structured Patrol Report
                         │                 │
                         v                 v
                    JSONL Journal      Web Console
```

The analyzer is deliberately replaceable. AI providers can later implement the same review role without giving them direct mutation authority.

## Run

Requires Go 1.24 or newer according to `go.mod`.

```bash
go run ./cmd/outpost
```

Then open:

```text
http://127.0.0.1:8787
```

A patrol runs immediately on startup and then every hour by default.

### Options

```bash
go run ./cmd/outpost \
  -listen 127.0.0.1:8787 \
  -interval 1h \
  -timeout 30s \
  -journal outpost-journal.jsonl
```

For a quick demo, a shorter interval can be used:

```bash
go run ./cmd/outpost -interval 2m
```

## HTTP endpoints

```text
GET  /api/status
GET  /api/patrols?limit=20
POST /api/patrols/run
```

`POST /api/patrols/run` performs one patrol immediately.

## Patrol report philosophy

The main report is intentionally short. Raw evidence is collected internally, while the patrol journal exposes a compact result:

```text
Target       server-a
Status       WARNING
Time         2026-09-08 06:00

CHECK                STATUS      SUMMARY
Disk                 NORMAL      collected
Processes            NORMAL      collected
Network              NORMAL      collected
Login history        NORMAL      collected
Failed logins        NORMAL      collected
Security updates     NORMAL      collected

ASSESSMENT
- No confirmed compromise detected by the baseline checks.
- Observed changes since the previous patrol.

NEXT
- Re-check changed categories on the next patrol.
```

Detailed evidence and smarter security interpretation will be added separately rather than turning the main report into a long AI narrative.

## Next milestones

1. Verify the prototype on actual Windows and Linux hosts.
2. Add target configuration and remote transport abstraction.
3. Add scheduled patrol definitions such as hourly / daily / one-shot / retry.
4. Add OpenAI and Claude reviewer interfaces.
5. Store snapshots so changes survive process restarts.
6. Improve security-specific detectors for suspicious login, process, port, and file changes.
7. Expand the Web console into a small multi-server monitoring view.

## Status

Early working prototype. The immediate goal is to validate the patrol loop and report shape before increasing autonomy.
