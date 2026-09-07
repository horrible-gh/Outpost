# Outpost

Outpost is a small, long-running server patrol tool focused on **observation, security-oriented review, host health, and concise patrol journals**.

> Observe first. Compare with the baseline. Report meaningful changes. Do not modify the target server.

## What works now

- Go single-binary application
- Embedded interval scheduler
- Immediate patrol on startup
- Manual one-shot patrol from the Web UI
- Local Windows and Linux collection
- JSONL journal with baseline restoration after restart
- Recent patrol history in the Web console
- CI with `go test ./...`

### Host health

- CPU utilization
- memory utilization
- swap/pagefile utilization
- disk utilization thresholds
- resource-heavy process detection

### Security patrol

- listening ports and newly exposed listeners
- unusual outbound connections
- successful / failed login evidence
- new local accounts
- new auto-start services
- suspicious processes running from temporary/download locations
- Windows Defender protection state
- Windows Defender threat detections from the last 24 hours
- Windows Firewall profile state
- security/update evidence

The analyzer produces:

- `NORMAL / WARNING / DANGER / UNKNOWN`
- a separate **security risk score (0–100)**
- classified findings such as `auth`, `identity`, `persistence`, `process`, `network`, `exposure`, `protection`, and `threat`
- concise next-check suggestions

Routine raw changes such as a few MB of free disk movement are intentionally ignored.

## AI foundations

AI providers are not connected yet, but the patrol engine already has the pieces needed to add them without handing an AI unrestricted host access.

### Compact review packet

`BuildReviewPacket` sends only relevant findings and bounded evidence excerpts instead of every raw collector result. The packet can be inspected at:

```text
GET /api/review-packet
```

### Review policies

Supported policy logic:

- `off`
- `always`
- `warning`
- `periodic` (`EveryN`)
- `hybrid` (warning / risk threshold / periodic)

This is intended to keep AI usage controllable when OpenAI / Claude providers are connected later.

## Safety policy

Current patrol collection is read-only.

- no automatic remediation
- no service restart
- no package installation
- no file modification
- no account changes
- no firewall changes
- AI review will be advisory by default

Any future mutating action must be explicitly separated from patrol collection and require a separate authorization path.

## Architecture

```text
Embedded Scheduler ─────┐
                        ├─> Patrol Runner
Web: Run patrol now ────┘        │
                                 v
                         Read-only Collectors
                                 │
                                 v
                           Snapshot
                                 │
                  ┌──────────────┴──────────────┐
                  v                             v
          Baseline / Security             Host Health
             Detectors                    Analysis
                  └──────────────┬──────────────┘
                                 v
                       Structured Assessment
                     status / risk / findings
                         │              │
                         v              v
                    JSONL Journal    Web Console
                         │
                         v
                  Compact AI Review Packet
                  (provider not connected)
```

## Run

Requires Go 1.24 or newer according to `go.mod`.

```bash
go run ./cmd/outpost
```

Open:

```text
http://127.0.0.1:8787
```

A patrol runs immediately and then every hour by default.

### Options

```bash
go run ./cmd/outpost \
  -listen 127.0.0.1:8787 \
  -interval 1h \
  -timeout 30s \
  -journal outpost-journal.jsonl
```

## HTTP endpoints

```text
GET  /api/status
GET  /api/patrols?limit=20
GET  /api/review-packet
POST /api/patrols/run
```

## Still intentionally not implemented

- remote SSH / WinRM targets
- multiple configured targets
- persistent target/schedule configuration
- OpenAI / Claude API calls
- AI-generated dynamic read-only investigation
- suspicious-file scanning beyond process-location heuristics
- alert integrations
- remediation / automatic server changes

## Next milestones

1. Validate the expanded Windows patrol on a real host.
2. Validate Linux collectors on a real host.
3. Introduce target / transport abstraction for multiple remote servers.
4. Add interval / daily-time / one-shot / retry patrol definitions.
5. Connect OpenAI / Claude behind the compact review packet and review policy.
6. Add read-only follow-up investigation as a separate, constrained stage.
7. Evolve the Web console into a multi-server patrol view.

## Status

Working patrol-engine prototype. It now behaves more like a patrol/watchdog than a raw system-information collector, while remaining observation-only.
