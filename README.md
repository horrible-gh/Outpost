# Outpost

Outpost is a small, long-running AI-assisted server patrol daemon.

It periodically inspects configured servers, records patrol results, and can later use an AI reviewer to summarize changes, detect suspicious patterns, and produce an operations journal.

The core idea is intentionally conservative:

> Collect first. Compare second. Ask AI only when useful. Never give AI unrestricted server control by default.

## Goals

- Run unattended for long periods
- Patrol multiple servers on schedules
- Keep collection deterministic and read-only by default
- Compare the current patrol with previous state
- Minimize AI usage by reviewing only meaningful changes
- Write an auditable patrol journal
- Escalate suspicious or repeated findings

## Initial architecture

```text
Scheduler
   ↓
Patrol Runner
   ↓
Collectors
   ↓
Snapshot / Diff
   ↓
Rule Engine
   ↓
AI Reviewer (optional)
   ↓
Journal / Alert
```

## v0 scope

The first version focuses on the patrol loop itself rather than remediation.

- Embedded scheduler
- Local target support
- Basic host checks
  - load / CPU
  - memory
  - disk
  - running processes
  - listening sockets
- JSONL journal
- Timeout and cancellation per patrol
- Rule-based decision on whether AI review is needed

Remote SSH targets, richer security checks, alerts, and AI providers can be added after the core patrol contract is stable.

## Configuration

Outpost currently starts with built-in defaults. A configuration file format will be added next. The intended shape is roughly:

```yaml
patrols:
  - name: hourly-health
    every: 1h
    target: local
    checks:
      - host
      - processes
      - sockets
```

## Safety model

Outpost should treat the AI reviewer as an untrusted decision-support component.

- Collectors own observation.
- The AI receives only the data required for review.
- AI output is advisory by default.
- Server mutation/remediation is out of scope for the first version.
- Network and credential access should follow least privilege.

## Run

```bash
go run ./cmd/outpost
```

## Status

Very early prototype.
