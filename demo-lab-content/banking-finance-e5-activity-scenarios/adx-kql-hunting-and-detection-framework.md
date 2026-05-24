# ADX KQL Hunting and Detection Framework

## Purpose

This document defines the detection-engineering and hunting-operations framework for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It complements:

- `adx-kql-hunting-and-detection-library.md`
- `adx-ingestion-and-table-mappings.md`
- `synthetic-telemetry-schema.json`
- `synthetic-risk-correlation-engine.json`
- `microsoft-sentinel-and-soc-integration-roadmap.md`
- `power-bi-executive-dashboard-and-visual-storytelling-framework.md`

This file focuses on detection strategy, operational hunting workflows, tuning, correlation, watchlists, false-positive handling, and executive-to-technical pivoting rather than duplicating query bodies.

All telemetry, users, files, incidents, entities, customers, identifiers, and cases remain fictional and synthetic.

---

## Core Detection Thesis

> A detection is useful when it helps an analyst or business stakeholder understand a sequence, validate context, and choose the next action. Isolated alerts are less valuable than explainable correlations.

Detection logic should support:

- executive visibility
- SOC triage
- data-security operations
- AI governance review
- DLP tuning
- endpoint movement review
- scenario replay
- investigation timelines
- tabletop exercises

---

## Detection Engineering Principles

1. Detect sequences, not only events.
2. Preserve ScenarioId, ReplayId, and CorrelationId across detections.
3. Separate severity from intent.
4. Keep detection names business-readable.
5. Include recommended response guidance.
6. Include false-positive considerations.
7. Support both executive dashboards and SOC queries.
8. Keep synthetic-data disclaimers visible.
9. Tune detections based on scenario quality, not fear-based volume.
10. Avoid implying malicious behavior unless explicitly defined by the scenario.

---

## Normalized Event Model Requirements

Detection logic assumes the normalized event model contains at least:

```text
EventId
TimeGenerated
ScenarioId
ReplayId
CorrelationId
UserPrincipalName
PersonaName
Department
Workload
Operation
SignalCategory
Severity
RiskScore
IsRiskEvent
IsSynthetic
BusinessContext
FileName
FilePath
SensitivityLabel
PreviousSensitivityLabel
Recipient
TargetDomain
DeviceId
AppName
PolicyName
DlpAction
OverrideJustification
AdditionalProperties
```

Recommended rule:

> Every detection should output enough fields to reconstruct who acted, what content was involved, what control responded, and why the event requires review.

---

## Detection Categories

| Category | Purpose | Example Detection |
|---|---|---|
| AI Governance | identify Copilot or external AI risk | external AI after sensitive access |
| DLP Operations | review warnings, blocks, overrides | DLP warning followed by override |
| Label Governance | identify label downgrade/removal risk | label downgrade before external share |
| Endpoint Movement | identify cloud-to-local movement | download followed by network-share copy |
| External Sharing | identify sensitive outbound paths | highly confidential file sent externally |
| Identity-to-Data | correlate sign-in risk with data movement | risky sign-in before sensitive download |
| Insider Risk-Style | correlate multi-signal sequences | HR context plus mass download |
| False Positive Review | identify noisy but benign matches | training content triggering DLP |
| False Negative Review | find missed classification opportunities | unlabeled KYC file shared externally |
| Replay Integrity | validate simulated scenario completeness | missing expected DLP event in replay |

---

## Detection Lifecycle

Recommended lifecycle:

```text
Idea
        ↓
Draft Query
        ↓
Synthetic Test
        ↓
False Positive Review
        ↓
Business Context Review
        ↓
Dashboard Mapping
        ↓
SOC Playbook Mapping
        ↓
Stable Detection
        ↓
Periodic Tuning
```

---

## Detection Metadata Model

Each detection should have metadata.

```json
{
  "DetectionId": "DET-BF-AI-0001",
  "DetectionName": "External AI after sensitive file access",
  "Category": "AI Governance",
  "DefaultSeverity": "High",
  "RequiredOperations": ["FileDownloaded", "AIAppInteraction"],
  "CorrelationWindow": "4h",
  "PrimaryEntities": ["UserPrincipalName", "FileName", "AppName"],
  "RecommendedResponse": "Review source file sensitivity, AI app approval status, and whether a sanitized source existed.",
  "FalsePositiveConsiderations": ["training content", "approved synthetic demo prompt", "sanitized source file"],
  "MapsToScenarios": ["BF-SCEN-0002", "BF-SCEN-0030"],
  "SyntheticOnly": true
}
```

---

## Correlation Strategy

## Primary Correlation Keys

Use these keys first:

```text
CorrelationId
ReplayId
ScenarioId
UserPrincipalName
FileName / FileKey
```

## Secondary Correlation Keys

Use these for enrichment:

```text
DeviceId
TargetDomain
AppName
PolicyName
SensitivityLabel
Department
```

## Recommended Correlation Windows

| Detection Pattern | Window |
|---|---:|
| DLP warning to override | 30 minutes |
| sensitive access to AI interaction | 4 hours |
| download to endpoint movement | 4 hours |
| label downgrade to external share | 15 minutes |
| risky sign-in to sensitive download | 4 hours |
| HR context to mass download | 72 hours |
| multi-stage Devon sequence | 5 business days |

---

## Watchlist Strategy

Recommended ADX or Sentinel-style watchlists:

## Synthetic High-Risk Personas

Fields:

```text
UserPrincipalName
PersonaName
Department
PersonaType
IsRiskAnchor
ManagerPersona
Notes
```

Use:

- prioritize Devon-centered storylines
- enrich investigation timelines
- avoid hardcoding users in every query

---

## Sensitive Data Domains

Fields:

```text
DataDomain
SyntheticPrefix
DefaultSensitivityLabel
BusinessOwner
RecommendedControls
```

Use:

- enrich AML/KYC/HR/legal detections
- validate label-to-content consistency

---

## Approved External Domains

Fields:

```text
Domain
RecipientType
ApprovedUse
Owner
ExpirationDate
```

Use:

- distinguish approved vendor collaboration from risky external sharing

---

## Approved AI Applications

Fields:

```text
AppName
Domain
ApprovalStatus
AllowedDataTypes
Owner
```

Use:

- classify managed vs unmanaged AI interactions
- support AI governance dashboarding

---

## Executive-to-SOC Pivot Workflow

Recommended pivot path:

```text
Executive dashboard KPI
        ↓
Department or scenario filter
        ↓
Scenario Replay page
        ↓
CorrelationId selection
        ↓
SOC drillthrough
        ↓
ADX KQL query
        ↓
Case summary or remediation action
```

Example:

```text
Sensitive AI Events KPI
        ↓
AI and Copilot Risk page
        ↓
External AI after sensitive access table
        ↓
BF-SCEN-0002 correlation ID
        ↓
SOC investigation timeline
        ↓
review source file, prompt, app, and DLP signal
```

---

## AI Governance Detection Pack

Recommended detections:

1. External AI after sensitive file access.
2. Unmanaged AI upload with regulated pattern.
3. Copilot interaction over highly confidential source.
4. AI output shared externally.
5. AI prompt includes customer-like identifiers.
6. External AI usage by department outside approved use case.
7. Safe Copilot usage baseline.
8. AI Approved Workspace usage trend.

Detection objective:

> Separate governed AI productivity from unmanaged AI exposure.

---

## DLP Detection Pack

Recommended detections:

1. DLP warning followed by override.
2. DLP block after external sharing attempt.
3. Repeated DLP overrides by persona.
4. DLP override involving highly confidential content.
5. DLP event involving external recipient.
6. DLP false positive on training content.
7. DLP false negative candidate for unlabeled sensitive file.

Detection objective:

> Identify policy decision points and tuning opportunities.

---

## Label Governance Detection Pack

Recommended detections:

1. Label downgrade before external sharing.
2. Highly confidential label removed.
3. File shared without label but matching sensitive pattern.
4. Sanitized file still contains regulated pattern.
5. Label changed shortly before DLP event.
6. Sensitive file created in low-governance location.

Detection objective:

> Show that labels are foundational but require process, review, and lifecycle governance.

---

## Endpoint Movement Detection Pack

Recommended detections:

1. Sensitive download followed by print.
2. Sensitive download followed by network-share copy.
3. Sensitive download followed by USB copy.
4. Endpoint movement after DLP warning.
5. Endpoint movement after external AI usage.
6. Multiple endpoint actions in same scenario chain.

Detection objective:

> Show when cloud-governed data enters endpoint or local movement paths.

---

## Insider Risk-Style Detection Pack

Recommended detections:

1. HR signal followed by mass download.
2. Role-change context plus external sharing.
3. Repeated risky shortcuts after coaching.
4. Multi-stage chain across download, AI, DLP, endpoint.
5. Devon multi-day risk chain.
6. Investigation closure path missing after high-risk sequence.

Detection objective:

> Review risky sequences with context while avoiding unsupported assumptions about intent.

---

## False Positive Management

False positives should be part of the demo, not hidden.

Common synthetic false-positive sources:

- training documents containing fake IDs
- public decks with fictional sensitive patterns
- sanitized files that intentionally include masked examples
- test emails sent inside the lab

Recommended handling:

```text
identify source
validate business context
confirm synthetic/training purpose
document tuning recommendation
avoid weakening policy globally unless justified
```

---

## False Negative Management

False negatives are useful for demonstrating classification gaps.

Common synthetic false-negative patterns:

- unlabeled KYC packet
- sanitized file with leftover raw identifier
- sensitive information expressed in notes rather than structured fields
- broad-access file not labeled

Recommended handling:

```text
review sensitive patterns
update classifier or label recommendation
improve content factory sanitization rules
review location and permissions
add scenario to regression tests
```

---

## Detection Tuning Strategy

Tune detections using:

- severity threshold
- correlation window
- sensitivity label
- department
- approved domain watchlist
- approved AI app watchlist
- scenario mode
- business cycle
- persona role

Example tuning decision:

```text
External AI interaction is Medium by default, but High when source file is Highly Confidential or when prompt includes AML-CASE / CUST-BNK patterns.
```

---

## Detection Quality Metrics

Recommended metrics:

```text
Detection Count by Category
High/Critical Detection Count
False Positive Rate
False Negative Candidates
Average Time to Triage
Detections Mapped to Scenarios
Detections with Playbooks
Detections Used in Dashboards
Detections with Watchlist Enrichment
```

---

## Hunting Maturity Roadmap

## Level 1 - Basic Queries

- simple filters by Operation
- manual event review
- no correlation logic

## Level 2 - Correlated Hunting

- joins across event types
- correlation windows
- ScenarioId and CorrelationId usage

## Level 3 - Detection Packs

- named detections
- metadata
- severity logic
- response guidance

## Level 4 - Operationalized Detection

- playbook mapping
- dashboard mapping
- false-positive tracking
- recurring tuning

## Level 5 - Replay-Aware Detection Engineering

- detections validated against deterministic replay
- CI-based validation
- expected signal assertions
- executive-to-SOC pivot workflows

---

## Detection Validation Checklist

A detection is ready when:

- query runs against current schema
- required operations exist
- correlation logic is documented
- severity is justified
- false-positive considerations are documented
- recommended response exists
- scenario mapping exists
- dashboard mapping exists if relevant
- synthetic-only disclaimer exists
- neutral language is preserved

---

## Recommended Future Files

```text
detections/detection-metadata.json
detections/ai-governance-detections.kql
detections/dlp-detections.kql
detections/label-governance-detections.kql
detections/endpoint-movement-detections.kql
detections/insider-risk-style-detections.kql
watchlists/synthetic-high-risk-personas.csv
watchlists/sensitive-data-domains.csv
watchlists/approved-external-domains.csv
watchlists/approved-ai-applications.csv
```

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate detection metadata files.
2. Organize KQL files into detection packs.
3. Create watchlist CSV templates.
4. Build false-positive and false-negative review workflows.
5. Map detections to Power BI visuals and SOC playbooks.
6. Generate executive-to-SOC pivot workflows.
7. Validate detections against replay outputs.
8. Preserve neutral investigation language.
9. Avoid duplicate query content when the KQL library already contains the query body.
10. Preserve synthetic-only boundaries.

---

## Safety Reminder

This detection framework is for synthetic demo telemetry only.

Do not use these detections to monitor, score, investigate, discipline, or profile real employees, real customers, real HR records, real legal matters, real financial transactions, or real incidents without formal governance and authorization.
