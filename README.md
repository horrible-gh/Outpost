# Outpost

Outpost is a small, long-running infrastructure patrol tool focused on **host observation, security-oriented review, external service monitoring, and concise patrol journals**.

> Observe first. Compare with the baseline. Report meaningful changes. Do not modify the target server.

## What works now

- Go single-binary application
- Embedded interval schedulers
- Immediate host patrol and external service checks on startup
- Manual one-shot checks from the Web UI
- Local Windows and Linux host collection
- External HTTP/HTTPS service monitoring
- JSONL host journal with baseline restoration after restart
- Persistent external service target configuration
- Tabbed Web console: Overview / Host Patrol / Service Monitor / Settings
- CI with `go test ./...`

## Host Patrol

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

The host analyzer produces:

- `NORMAL / WARNING / DANGER / UNKNOWN`
- a separate **security risk score (0–100)**
- classified findings such as `auth`, `identity`, `persistence`, `process`, `network`, `exposure`, `protection`, and `threat`
- concise next-check suggestions

Routine raw changes such as a few MB of free disk movement are intentionally ignored.

## Service Monitor

External HTTP/HTTPS targets can be added from the **Settings** tab. Targets are stored locally in `outpost-services.json`.

Each check currently performs:

- DNS resolution
- TCP reachability
- TLS handshake and certificate expiry check for HTTPS
- HTTP status validation
- response latency measurement
- optional response-body text validation

Service states are:

- `UP`
- `WARNING`
- `DOWN`
- `UNKNOWN`

By default external services are checked every 5 minutes. A service becomes `WARNING` when its latency exceeds the configured threshold or its TLS certificate has fewer than 14 days remaining. Connection, DNS, TLS, HTTP-status, or content validation failures produce `DOWN`.

## AI foundations

AI providers are not connected yet, but the host patrol engine already has the pieces needed to add them without handing an AI unrestricted host access.

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

Current host patrol collection is read-only. External service monitoring only performs outbound observation/check requests.

- no automatic remediation
- no service restart
- no package installation
- no target file modification
- no account changes
- no firewall changes
- AI review will be advisory by default

Any future mutating action must be explicitly separated from patrol collection and require a separate authorization path.

## Architecture

```text
                             Outpost
                                │
                 ┌──────────────┴──────────────┐
                 │                             │
            Host Patrol                 Service Monitor
                 │                             │
       Read-only Collectors          DNS / TCP / TLS / HTTP
                 │                             │
              Snapshot                     Result
                 │                             │
       Baseline + Analysis           UP / WARNING / DOWN
                 │                             │
        Structured Assessment                 │
                 └──────────────┬──────────────┘
                                │
                           Web Console
                    Overview / Host / Services
                                │
                  Host Journal / Service Config
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

Host patrol runs immediately and then every hour by default. External services run immediately when configured and then every 5 minutes by default.

### Options

```bash
go run ./cmd/outpost \
  -listen 127.0.0.1:8787 \
  -interval 1h \
  -timeout 30s \
  -journal outpost-journal.jsonl \
  -service-interval 5m \
  -service-timeout 10s \
  -service-config outpost-services.json
```

## HTTP endpoints

```text
GET    /api/status
GET    /api/patrols?limit=20
GET    /api/review-packet
POST   /api/patrols/run

GET    /api/services
POST   /api/services
POST   /api/services/run
POST   /api/services/{id}/run
DELETE /api/services/{id}
```

## Still intentionally not implemented

- remote SSH / WinRM host targets
- multiple remote host patrol targets
- per-service custom intervals
- persistent service-check history
- ICMP / traceroute monitoring
- OpenAI / Claude API calls
- AI-generated dynamic read-only investigation
- suspicious-file scanning beyond process-location heuristics
- alert integrations
- remediation / automatic server changes

## Next milestones

1. Validate the expanded Windows patrol on a real host.
2. Validate Linux collectors on a real host.
3. Run the service monitor against real public services and refine thresholds.
4. Introduce host target / transport abstraction for multiple remote servers.
5. Add interval / daily-time / one-shot / retry patrol definitions.
6. Add persistent service-monitor history and uptime calculations.
7. Connect OpenAI / Claude behind the compact review packet and review policy.
8. Add read-only follow-up investigation as a separate, constrained stage.

## Status

Working infrastructure-patrol prototype. Host Patrol observes the machine from inside; Service Monitor observes public services from the outside. Both remain observation-only.
