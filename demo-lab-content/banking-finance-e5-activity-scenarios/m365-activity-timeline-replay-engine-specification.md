# Microsoft 365 Activity Timeline Replay Engine Specification

## Purpose

This document defines a replay-engine specification for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services demo lab.

The replay engine is responsible for converting scenario definitions, schedules, browser-agent task plans, and telemetry playbooks into time-aware synthetic activity streams that can be executed, simulated, ingested into ADX, and visualized in Power BI.

The goal is to make synthetic activity feel human, cyclical, and operationally plausible rather than robotic.

All content, identities, telemetry, customers, accounts, incidents, and records must remain fictional.

---

## Core Engine Responsibilities

The replay engine should:

1. Select scenarios based on cadence and demo mode.
2. Expand scenario steps into timestamped user activities.
3. Apply realistic delays, idle periods, lunch gaps, meetings, and after-hours windows.
4. Coordinate multiple personas acting concurrently.
5. Generate or trigger browser-agent actions where possible.
6. Emit normalized synthetic telemetry using `synthetic-telemetry-schema.json`.
7. Preserve deterministic replay through seeds.
8. Support compressed demo timelines.
9. Support background-noise activity.
10. Support investigation and remediation follow-up activity.

---

## Source Files Used by the Replay Engine

| File | Usage |
|---|---|
| `complex-scenarios.json` | Scenario narratives, risk themes, personas, expected signals. |
| `browser-agent-task-plans.json` | Ordered browser-agent execution steps. |
| `daily-schedules.json` | Persona work hours, business cycles, risk windows. |
| `browser-agent-orchestration-rules.json` | Probabilities, mistake models, timing rules, escalation logic. |
| `telemetry-generation-playbooks.json` | Workload-specific telemetry generation patterns. |
| `synthetic-telemetry-schema.json` | Canonical event output schema. |
| `synthetic-risk-correlation-engine.json` | Risk scoring, correlation windows, escalation thresholds. |
| `purview-policy-and-control-matrix.md` | Control actions, coaching templates, policy narratives. |
| `content-generation-blueprints.json` | Document, email, chat, prompt, and investigation artifact generation. |

---

## Replay Modes

### 1. Realistic Mode

Used for long-running lab simulations.

Characteristics:

- 1 simulated day equals 1 real day.
- Human delays are preserved.
- Business hours and lunch windows are respected.
- Event volume is moderate.
- High-risk scenarios are rare.

Recommended use:

- persistent demo tenants
- long-running telemetry generation
- monthly trend dashboards
- realistic UEBA-style baselines

---

### 2. Compressed Demo Mode

Used for live demonstrations.

Characteristics:

- 1 simulated day can be compressed into 20 to 60 minutes.
- Quiet periods are shortened but not removed.
- Multiple personas can act concurrently.
- Scenario causality and timing order are preserved.
- ADX ingestion occurs in small batches.

Recommended use:

- customer demos
- webinars
- Purview workshops
- security storytelling

---

### 3. Instant Replay Mode

Used for dashboard seeding and testing.

Characteristics:

- Events are emitted immediately.
- No browser automation is required.
- Event timestamps are synthetic and backfilled.
- Useful for Power BI, ADX, KQL, and validation tests.

Recommended use:

- dashboard development
- report testing
- scenario validation
- regression testing

---

### 4. SOC Analyst Mode

Used for investigation training.

Characteristics:

- Events are released in investigation batches.
- Some details are delayed to mimic real telemetry arrival.
- Analysts must query, correlate, and pivot.
- The engine can reveal more evidence after each stage.

Recommended use:

- SOC tabletop exercises
- insider-risk training
- KQL hunting workshops
- Defender XDR demonstrations

---

### 5. Executive Demo Mode

Used for short business-oriented walkthroughs.

Characteristics:

- Focuses on high-level events and clear narrative.
- Reduces noisy baseline telemetry.
- Highlights business context, controls, and outcomes.
- Uses preselected scenarios and clean replay sequences.

Recommended use:

- C-level presentations
- board-style briefings
- security strategy sessions

---

### 6. Chaos Mode

Used for stress testing and advanced demos.

Characteristics:

- Higher concurrency.
- More background activity.
- More random errors and retries.
- Multiple overlapping scenarios.
- Higher event volume.

Recommended use:

- report performance testing
- ADX ingestion stress tests
- SOC prioritization exercises

Chaos Mode should not be used for first-time executive demos because it can obscure the story.

---

## Time Compression Model

Recommended compression ratios:

| Mode | Simulated Time | Real Time |
|---|---:|---:|
| realistic | 1 business day | 1 business day |
| compressed-light | 1 business day | 60 minutes |
| compressed-standard | 1 business day | 30 minutes |
| compressed-fast | 1 business day | 15 minutes |
| instant | 1 business day | immediate |

### Compression Rules

The engine should preserve event order and reduce delays proportionally.

Example:

```text
Realistic delay: 60 minutes
Compressed-standard factor: 16x
Compressed delay: 3.75 minutes
```

Minimum delay should be enforced to avoid robotic behavior:

```text
Minimum browser action gap: 5 seconds
Minimum human decision gap: 15 seconds
Minimum post-warning decision gap: 20 seconds
```

---

## Deterministic Replay Seeds

Every replay should be reproducible.

Recommended seed format:

```text
{ScenarioId}-{ReplayDate}-{Mode}-{PrimaryPersona}
```

Example:

```text
BF-SCEN-0030-2026-05-24-compressed-standard-DevonReyes
```

Seed should control:

- event jitter
- user delay variation
- mistake selection
- escalation branch
- file name suffixes
- synthetic event IDs
- batch IDs

---

## Timeline Object Model

A replay timeline should contain:

```json
{
  "replayId": "REPLAY-BF-20260524-001",
  "scenarioId": "BF-SCEN-0030",
  "mode": "compressed-standard",
  "seed": "BF-SCEN-0030-2026-05-24-compressed-standard-DevonReyes",
  "startTimeUtc": "2026-05-24T13:00:00Z",
  "endTimeUtc": "2026-05-24T13:45:00Z",
  "personas": ["Devon Reyes", "Ana Rodriguez", "Marcus Olsson"],
  "events": []
}
```

---

## Event Sequencing Rules

### Normal Sequence

```text
Business context event
        ↓
File or communication activity
        ↓
Sensitive action
        ↓
Control signal
        ↓
User decision
        ↓
Security review or remediation
```

### Risk Sequence

```text
Sensitive file access
        ↓
Download or copy
        ↓
External movement or AI usage
        ↓
DLP / Defender / Purview signal
        ↓
Correlation
        ↓
Investigation
```

### Investigation Sequence

```text
Alert or correlated sequence
        ↓
Security review
        ↓
HR or Legal context if required
        ↓
Access remediation
        ↓
User coaching or formal escalation
        ↓
Case summary
```

---

## Persona Concurrency Model

The engine should allow multiple personas to act in overlapping windows.

Example:

```text
09:00 - Carlos updates credit workbook
09:05 - Sofia prepares committee deck
09:10 - Emily adds legal caveats
09:20 - Devon downloads KYC packet
09:25 - Devon posts file link in Teams
09:35 - Ana reviews DLP alert
```

Concurrency should be controlled by:

- scenario role assignment
- persona work schedule
- workload availability
- dependency between steps
- meeting windows
- risk-trigger windows

---

## Background Noise Generation

Background noise should make the tenant feel alive.

Recommended baseline noise:

| Activity Type | Examples | Risk Level |
|---|---|---|
| routine email | status updates, meeting follow-ups | low |
| Teams chat | clarifications, reminders, approvals | low |
| SharePoint edits | PMO tracker updates, document comments | low |
| Copilot safe use | summarize approved internal notes | low/medium |
| Power BI views | dashboard review | low |
| OneDrive drafts | working notes | low |

Background noise should not overwhelm the main scenario.

Recommended ratio:

```text
Executive demo mode: 10-20% background noise
Compressed demo mode: 25-40% background noise
Realistic mode: 60-80% background noise
Chaos mode: 80-120% background noise relative to scenario events
```

---

## Quiet Period Rules

Quiet periods are important for realism.

Recommended quiet periods:

- lunch window
- between meetings
- after large document edits
- after sending important email
- after DLP warning before user decision
- before security review begins
- after HR/Legal review before final outcome

The engine should avoid generating constant event streams unless running chaos mode.

---

## Error and Retry Behavior

Use `telemetry-generation-playbooks.json` error injection rules.

Recommended handling:

| Error | Action |
|---|---|
| page load failure | retry once or twice with jitter |
| file name collision | append deterministic suffix |
| DLP block | do not retry blindly; follow escalation rule |
| Copilot source unavailable | convert into governance-positive story |
| external share unavailable | emit simulated external-sharing attempt if demo requires |

---

## ADX Ingestion Cadence

### Realistic Mode

```text
Batch every 5-15 minutes
```

### Compressed Demo Mode

```text
Batch every 30-90 seconds
```

### Instant Replay Mode

```text
Single batch or small scenario-based batches
```

### SOC Analyst Mode

```text
Stage 1: initial alert events
Stage 2: file activity evidence
Stage 3: endpoint evidence
Stage 4: AI / DLP evidence
Stage 5: HR / Legal / remediation context
```

---

## Power BI Refresh Coordination

Recommended refresh strategy:

| Mode | Refresh Approach |
|---|---|
| realistic | scheduled refresh or DirectQuery |
| compressed demo | DirectQuery or manual refresh after scenario batch |
| instant replay | import refresh after full load |
| SOC analyst | controlled refresh after each evidence stage |
| executive demo | preloaded import model recommended |

For live demos, preloaded import mode is usually safer unless the demonstration explicitly requires live refresh.

---

## Replay APIs - Conceptual Design

### Start Replay

```http
POST /api/replay/start
```

Payload:

```json
{
  "scenarioId": "BF-SCEN-0030",
  "mode": "compressed-standard",
  "seed": "BF-SCEN-0030-2026-05-24-compressed-standard-DevonReyes",
  "startTimeUtc": "2026-05-24T13:00:00Z",
  "includeBackgroundNoise": true,
  "emitTelemetry": true,
  "executeBrowserActions": false
}
```

### Pause Replay

```http
POST /api/replay/pause
```

### Resume Replay

```http
POST /api/replay/resume
```

### Stop Replay

```http
POST /api/replay/stop
```

### Get Replay Status

```http
GET /api/replay/{replayId}/status
```

### Export Replay Timeline

```http
GET /api/replay/{replayId}/timeline
```

---

## Replay State Model

Recommended states:

```text
Created
Queued
Running
Paused
Completed
Failed
Cancelled
```

Recommended state fields:

```text
ReplayId
ScenarioId
Mode
Seed
State
CurrentSimulatedTime
CurrentRealTime
EventsPlanned
EventsEmitted
BrowserActionsCompleted
BrowserActionsFailed
LastError
StartedAt
CompletedAt
```

---

## Scenario Validation Rules

After replay completion, validate:

1. Expected personas were active.
2. Expected files were created or referenced.
3. Expected labels were applied or changed.
4. Expected DLP events were emitted.
5. Expected AI events were emitted if scenario requires them.
6. Expected endpoint events were emitted if scenario requires them.
7. Expected correlation sequence was produced.
8. Risk score is within expected band.
9. Investigation/remediation artifacts exist when required.
10. All identifiers remain fictional.

---

## Demo Mode Recommendations

### Executive Demo

Recommended scenario:

```text
BF-SCEN-0030 Devon Multi-Day Risk Chain
```

Recommended mode:

```text
executive-demo or instant replay
```

Recommended duration:

```text
5-10 minutes
```

Recommended focus:

- risk sequence
- AI exposure
- endpoint movement
- DLP and investigation response
- governance outcome

---

### SOC Demo

Recommended scenarios:

```text
BF-SCEN-0002 AML External AI
BF-SCEN-0022 Risky Sign-In
BF-SCEN-0025 Role Change Download
BF-SCEN-0030 Devon Multi-Day Risk Chain
```

Recommended mode:

```text
SOC analyst mode
```

Recommended focus:

- staged evidence
- KQL hunting
- cross-workload correlation
- investigation timeline

---

### Purview DLP Demo

Recommended scenarios:

```text
BF-SCEN-0001 Loan Committee Oversharing
BF-SCEN-0005 Treasury Endpoint DLP
BF-SCEN-0013 Label Downgrade
BF-SCEN-0023 Wrong Attachment to Vendor
```

Recommended mode:

```text
compressed demo mode
```

Recommended focus:

- DLP policy tips
- block/warn/override
- endpoint movement
- sanitized remediation

---

## Codex Usage Guidance

Codex should use this specification to:

1. Build a replay controller.
2. Generate timeline objects.
3. Schedule scenario steps using persona availability.
4. Insert human-like delays and quiet periods.
5. Generate deterministic synthetic events.
6. Coordinate browser-agent actions and synthetic telemetry emission.
7. Batch telemetry for ADX ingestion.
8. Validate expected scenario signals.
9. Export replay timelines for Power BI or documentation.
10. Preserve synthetic-only boundaries.

---

## Safety Reminder

This replay engine is for synthetic demo environments only.

Do not use it to simulate, evaluate, or score real employees, customers, financial transactions, HR matters, legal matters, or production incidents without proper legal, privacy, compliance, and governance approval.
