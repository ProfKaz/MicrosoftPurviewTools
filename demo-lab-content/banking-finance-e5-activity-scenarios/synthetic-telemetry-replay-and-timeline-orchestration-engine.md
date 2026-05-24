# Synthetic Telemetry Replay and Timeline Orchestration Engine

## Purpose

This document defines the replay-orchestration and temporal-simulation layer for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It explains how synthetic events, browser-agent actions, telemetry, Power BI visuals, ADX ingestion, SOC timelines, and executive storyboards should be synchronized into deterministic scenario replays.

All events, users, files, cases, prompts, identifiers, customers, incidents, and telemetry are fictional and synthetic.

---

## Core Replay Thesis

> A demo becomes credible when activity unfolds as a sequence. The replay engine should show how normal work becomes risk through timing, context, correlation, and response.

Replay should support:

- deterministic timelines
- compressed time
- cross-user activity
- event correlation
- scenario chaining
- branching outcomes
- incident reconstruction
- Power BI synchronization
- SOC tabletop evidence release
- executive storyboard alignment

---

## Replay Architecture

```text
Scenario Definition
        ↓
Replay Seed
        ↓
Timeline Builder
        ↓
Event Scheduler
        ↓
Browser-Agent Action Queue
        ↓
Synthetic Telemetry Emitter
        ↓
ADX / CSV / JSONL Output
        ↓
Power BI Refresh or Filter Update
        ↓
SOC / Executive Storyboard View
```

---

## Replay Object Model

Recommended replay object:

```json
{
  "ReplayId": "REPLAY-BF-20260524-0001",
  "ReplayName": "Devon Multi-Day Risk Chain - Executive Demo",
  "ScenarioId": "BF-SCEN-0030",
  "Mode": "compressed-standard",
  "Seed": "BF-SCEN-0030-2026-05-24-compressed-standard-DevonReyes",
  "StartTimeUtc": "2026-05-24T13:00:00Z",
  "EndTimeUtc": "2026-05-24T13:45:00Z",
  "PrimaryPersona": "Devon Reyes",
  "Participants": ["Devon Reyes", "Ana Rodriguez", "Marcus Olsson", "Laura Gomez"],
  "Status": "Created",
  "EventCountPlanned": 280,
  "EventCountEmitted": 0,
  "CorrelationIds": ["CORR-DEVON-20260524-001"],
  "Bookmarks": []
}
```

---

## Replay Modes

## Realistic Mode

Purpose:

- long-running demo tenant
- realistic daily rhythms
- baseline behavior generation

Characteristics:

- 1 simulated day equals 1 real day
- quiet periods preserved
- low artificial compression
- best for persistent telemetry generation

---

## Compressed Demo Mode

Purpose:

- live demos
- workshops
- guided storytelling

Characteristics:

- 1 simulated day compressed into 15-60 minutes
- quiet periods shortened
- scenario sequence preserved
- Power BI refresh coordinated with event batches

---

## Instant Replay Mode

Purpose:

- Power BI seeding
- offline demos
- regression testing

Characteristics:

- all events emitted immediately
- timestamps remain simulated
- no browser automation required
- best fallback for live demo reliability

---

## SOC Tabletop Mode

Purpose:

- staged evidence review
- analyst exercises
- investigation training

Characteristics:

- evidence released in phases
- analysts query and pivot between phases
- final event chain is revealed gradually

---

## Executive Storyboard Mode

Purpose:

- board or C-level presentations
- short, clean narrative

Characteristics:

- low noise
- curated visuals
- preselected bookmarks
- simplified risk messages

---

## Chaos Mode

Purpose:

- stress testing
- advanced SOC practice
- dashboard scalability testing

Characteristics:

- high concurrency
- more noise
- more mistakes
- overlapping scenarios
- not recommended for first-time executive demos

---

## Timeline Sequencing Model

A replay timeline should contain ordered blocks.

Recommended block types:

```text
ContextBlock
NormalActivityBlock
SensitiveDataAccessBlock
AIUsageBlock
SharingBlock
DLPResponseBlock
EndpointMovementBlock
IdentityContextBlock
InvestigationBlock
RemediationBlock
ExecutiveSummaryBlock
```

Example flow:

```text
ContextBlock
        ↓
NormalActivityBlock
        ↓
SensitiveDataAccessBlock
        ↓
AIUsageBlock
        ↓
DLPResponseBlock
        ↓
EndpointMovementBlock
        ↓
InvestigationBlock
        ↓
RemediationBlock
```

---

## Event Sequencing Rules

## Rule 1 - Preserve Causality

Do not emit control events before the activity that caused them.

Example:

```text
FileDownloaded must occur before EndpointDLPPolicyMatch for that file.
```

## Rule 2 - Preserve Human Delay

Insert decision delays after:

- DLP warning
- AI output review
- file download
- external sharing prompt
- security question

## Rule 3 - Preserve Cross-User Context

Security response should occur after the risky user activity.

Example:

```text
Devon DLPOverride
        ↓
Marcus DLP review
        ↓
Ana investigation decision
```

## Rule 4 - Preserve Business Context

Risk events should have plausible business motivation.

Example:

```text
Vendor deadline before wrong external sharing.
```

---

## Correlation Model

Use correlation IDs to group event chains.

Recommended patterns:

```text
CORR-DEVON-20260524-001
CORR-AI-AML-20260524-001
CORR-DLP-LABEL-20260524-001
CORR-ENDPOINT-TREASURY-20260524-001
```

Correlation should connect:

- source file access
- download
- AI prompt
- DLP signal
- sharing event
- endpoint event
- investigation note
- remediation action

---

## Seed Management

Replay seeds should be stable and descriptive.

Recommended format:

```text
{ScenarioId}-{Date}-{Mode}-{PrimaryPersona}
```

Example:

```text
BF-SCEN-0030-2026-05-24-compressed-standard-DevonReyes
```

Seed controls:

- timestamp jitter
- baseline noise selection
- branch selection
- DLP outcome
- wrong-file probability
- external recipient selection
- AI prompt variant
- endpoint action selection

---

## Time Compression Logic

Recommended compression formula:

```text
compressedDelay = max(minimumDelay, originalDelay / compressionFactor)
```

Recommended minimums:

```text
Browser action delay: 5 seconds
User decision delay: 15 seconds
DLP warning review: 20 seconds
AI output review: 30 seconds
Security response delay: 60 seconds
```

Recommended compression factors:

| Mode | Factor |
|---|---:|
| realistic | 1x |
| compressed-light | 8x |
| compressed-standard | 16x |
| compressed-fast | 32x |
| instant | immediate |

---

## Branching Outcomes

Scenarios may branch based on user decisions.

Example DLP branch:

```text
DLP warning appears
        ↓
Branch A: user cancels and creates sanitized file
Branch B: user overrides with justification
Branch C: DLP blocks action
Branch D: user asks Security for guidance
```

Branch selection should be:

- deterministic from seed
- influenced by persona profile
- constrained by scenario goals

---

## Playback Controls

Recommended controls:

```text
StartReplay
PauseReplay
ResumeReplay
StopReplay
JumpToBookmark
ReplayFromBookmark
ExportTimeline
EmitNextBatch
ValidateReplay
ResetReplay
```

---

## Replay API Concepts

## Start Replay

```http
POST /api/replay/start
```

Payload:

```json
{
  "ScenarioId": "BF-SCEN-0030",
  "Mode": "compressed-standard",
  "Seed": "BF-SCEN-0030-2026-05-24-compressed-standard-DevonReyes",
  "IncludeBackgroundNoise": true,
  "ExecuteBrowserActions": false,
  "EmitTelemetry": true
}
```

## Emit Next Batch

```http
POST /api/replay/{ReplayId}/emit-next-batch
```

## Export Timeline

```http
GET /api/replay/{ReplayId}/timeline
```

## Validate Replay

```http
POST /api/replay/{ReplayId}/validate
```

---

## Replay Metadata

Recommended metadata fields:

```text
ReplayId
ScenarioId
Mode
Seed
ReplayVersion
DatasetVersion
SchemaVersion
PowerBIReportVersion
StartTimeUtc
EndTimeUtc
PrimaryPersona
Participants
EventCountPlanned
EventCountEmitted
ExpectedSignals
ActualSignals
ValidationStatus
```

---

## Bookmarks

Bookmarks support presenter pacing.

Recommended bookmark types:

```text
BusinessContext
FirstSensitiveAccess
FirstAIInteraction
DLPWarning
DLPOverride
EndpointMovement
InvestigationStart
ExecutiveSummary
RemediationOutcome
```

Example:

```json
{
  "BookmarkId": "BM-DEVON-DLP-OVERRIDE",
  "Label": "DLP override before external send",
  "ReplayTimeUtc": "2026-05-24T13:21:00Z",
  "ScenarioId": "BF-SCEN-0030",
  "CorrelationId": "CORR-DEVON-20260524-001",
  "PresenterCue": "This is where the user's decision becomes part of the risk story."
}
```

---

## Power BI Synchronization

Recommended synchronization options:

## Option 1 - Preloaded Dataset

Use when:

- executive demo
- reliability is more important than live telemetry

Pattern:

```text
Dataset already loaded
        ↓
Presenter uses bookmarks and filters
```

## Option 2 - Batch Refresh

Use when:

- workshop mode
- staged replay

Pattern:

```text
Emit batch
        ↓
Refresh dataset or DirectQuery visual
        ↓
Move to next story point
```

## Option 3 - DirectQuery to ADX

Use when:

- live telemetry demonstration
- technical audience

Pattern:

```text
Emit events to ADX
        ↓
Power BI DirectQuery reflects new events
        ↓
Presenter filters by ReplayId or ScenarioId
```

---

## Incident Reconstruction Logic

A replay should generate an incident timeline when required.

Incident reconstruction fields:

```text
IncidentId
CaseId
ScenarioId
CorrelationId
PrimaryUser
FirstEvent
LastEvent
KeyEvents
AffectedFiles
AffectedLabels
ExternalRecipients
Devices
AIApps
DLPPolicies
RecommendedResponse
ClosurePath
```

---

## Storyboard Integration

Replay should map to storyboards.

Storyboard frame structure:

```text
FrameNumber
Title
PresenterCue
VisualTarget
ScenarioId
CorrelationId
EventFilter
ExpectedAudienceReaction
TransitionPhrase
```

Example:

```text
Frame 1: Normal operations
Frame 2: Sensitive data appears
Frame 3: AI shortcut
Frame 4: DLP response
Frame 5: Endpoint movement
Frame 6: Security review
Frame 7: Executive takeaway
```

---

## Replay Validation

A replay is valid when:

1. All required events exist.
2. Required event order is correct.
3. CorrelationId is consistent.
4. timestamps are valid and ordered.
5. expected personas are present.
6. expected files are present.
7. expected labels are present.
8. expected DLP/AI/endpoint signals exist.
9. Power BI filters can isolate the replay.
10. all data remains synthetic.

---

## Recommended Replay Output Files

```text
sample-data/replays/replay-BF-SCEN-0030-devon-executive.json
sample-data/replays/replay-BF-SCEN-0002-aml-ai-governance.json
sample-data/replays/replay-BF-SCEN-0013-label-downgrade.json
sample-data/replays/replay-validation-report.json
```

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate replay timeline objects.
2. Build deterministic replay controllers.
3. Create replay bookmarks.
4. Generate Power BI filter metadata.
5. Create storyboard frames from scenario timelines.
6. Validate replay event order.
7. Support executive, SOC, and technical replay modes.
8. Generate incident reconstruction outputs.
9. Preserve Devon ambiguity and neutral investigation language.
10. Preserve synthetic-only boundaries.

---

## Safety Reminder

Replay orchestration must remain synthetic.

Do not use this replay engine to reconstruct, present, score, investigate, or simulate real employee activity, real customer data movement, real HR matters, real legal matters, real incidents, or real production telemetry without formal governance and authorization.
