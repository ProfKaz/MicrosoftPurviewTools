# Reference Implementation and Minimum Viable Build Guide

## Purpose

This document defines the minimum viable implementation path for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It answers practical delivery questions:

- What should be built first?
- What can be skipped initially?
- What creates the strongest visual impact fastest?
- What is the smallest deployable architecture?
- What is needed for executive demos, SOC demos, and Purview demos?
- How should the platform evolve from MVP to full cyber-range?

All implementation guidance assumes a synthetic demo environment only.

---

## MVP Philosophy

The first version should prove the story, not deploy every possible component.

The MVP should demonstrate:

1. Realistic synthetic banking content.
2. A small number of fictional personas.
3. A few high-impact scenarios.
4. Normalized synthetic telemetry.
5. ADX or local dataset ingestion.
6. Power BI executive dashboard.
7. Scenario replay narrative.
8. Purview/DLP/AI governance storyline.

The MVP does not need to automate every Microsoft 365 action on day one.

---

## Minimum Viable Architecture

```text
Synthetic content generator
        ↓
Scenario event generator
        ↓
Normalized JSON / JSONL telemetry
        ↓
ADX or local Power BI dataset
        ↓
Power BI report
        ↓
Presenter script and scenario replay
```

Optional later:

```text
Browser agents
        ↓
Live Microsoft 365 tenant actions
        ↓
Real + synthetic telemetry blend
```

---

## MVP Components

| Component | Required for MVP | Notes |
|---|---|---|
| Synthetic personas | Yes | Start with 5 personas instead of all 12. |
| SharePoint/Teams topology | Partial | Can be documented or lightly provisioned. |
| Content generator | Yes | Generate files and metadata first. |
| Browser agents | No | Can be deferred. |
| Synthetic telemetry generator | Yes | Highest value for dashboards and replay. |
| ADX | Recommended | Can use CSV/JSON for offline mode. |
| Power BI | Yes | Strongest visual impact. |
| DLP policies | Optional for MVP | Can be simulated if tenant setup is not ready. |
| Endpoint DLP | Optional for MVP | Emit synthetic events first. |
| Sentinel | No | Future enhancement. |
| Fabric | No | Future enhancement. |
| GitHub Actions validation | Recommended | Start with JSON validation only. |

---

## Recommended MVP Persona Set

Start with five personas:

| Persona | Role | Purpose |
|---|---|---|
| Alexander Meyer | CEO | executive summaries and board-level storytelling |
| Ana Rodriguez | Head of IT / Security | security leadership and investigation owner |
| Marcus Olsson | Cybersecurity Manager | SOC and DLP review |
| Priya Sharma | Data Scientist | AI and analytics workflows |
| Devon Reyes | Junior Operations Analyst | ambiguous risky behavior anchor |

Add later:

- HR
- Legal
- Finance
- PMO
- Customer Support
- Engineering

---

## Recommended MVP Scenarios

Start with three high-impact scenarios:

### Scenario 1 - AML External AI Shortcut

Purpose:

- AI governance
- Shadow AI
- DLP risk
- regulated financial data

Signals:

```text
FileAccessed
FileDownloaded
AIAppInteraction
UnmanagedAppUpload
DLPPolicyMatch
TeamsMessageSent
```

---

### Scenario 2 - Label Downgrade Before External Sharing

Purpose:

- label governance
- DLP
- external sharing
- user coaching

Signals:

```text
SensitivityLabelChanged
LabelDowngrade
ExternalEmailSent
DLPWarned
DLPOverride
DLPPolicyMatch
```

---

### Scenario 3 - Devon Multi-Day Risk Chain

Purpose:

- executive storytelling
- Insider Risk-style correlation
- endpoint movement
- AI risk
- HR/Legal process framing

Signals:

```text
FileDownloaded
AIAppInteraction
DLPOverride
FilePrinted
FileCopiedToNetworkShare
InsiderRiskSequence
```

---

## Minimum Synthetic Dataset

Recommended minimum dataset size:

| Dataset | Minimum Count |
|---|---:|
| personas | 5 |
| scenarios | 3 |
| documents | 20 |
| emails | 30 |
| Teams messages | 40 |
| AI prompts | 20 |
| telemetry events | 500-1,500 |
| risk sequences | 5-10 |
| investigation cases | 3-5 |

For an executive demo, 500 high-quality events are better than 50,000 noisy events.

---

## Minimum ADX Build

### Required Table

```text
SyntheticM365ActivityEvents
```

Required columns:

```text
EventId
TimeGenerated
ScenarioId
CorrelationId
UserPrincipalName
PersonaName
Department
Workload
Operation
Severity
RiskScore
IsRiskEvent
IsSynthetic
BusinessContext
FileName
SensitivityLabel
Recipient
TargetDomain
DeviceId
AppName
PolicyName
DlpAction
AdditionalProperties
```

### Optional Tables

```text
SyntheticM365ActivityEventsRaw
ScenarioSummary
UserRiskSummary
SensitiveFileExposure
```

For MVP, materialized views can be skipped if the dataset is small.

---

## Minimum Power BI Model

### Required Fact Table

```text
FactActivityEvents
```

### Required Dimensions

```text
DimDate
DimUser
DimScenario
DimSignal
DimFile
```

### Required Pages

Start with four pages:

1. Executive Risk Snapshot
2. AI and Copilot Risk
3. DLP Operations
4. Scenario Replay and Timeline

Add later:

- Sensitive Data Exposure
- Endpoint DLP
- External Sharing Heatmap
- Insider Risk Overview
- Drillthrough pages

---

## Minimum DAX Measures

Start with:

```DAX
Total Events
Risk Events
High or Critical Events
External Sharing Events
Copilot Interactions
External AI Interactions
Sensitive AI Events
DLP Matches
DLP Overrides
Endpoint Movement Events
Distinct Risky Users
Total Risk Score
Average Risk Score
```

These are enough for a strong first dashboard.

---

## Fast-Start Lab Option

Use this path when a demo is needed quickly.

### Build Order

1. Generate synthetic telemetry JSONL.
2. Load into Power BI directly.
3. Build four report pages.
4. Use presenter scripts for narrative.
5. Skip live tenant automation.
6. Simulate Purview and DLP through telemetry fields.

### Benefits

- fastest path
- no tenant dependency
- safe offline demo
- good for early stakeholder validation

### Limitations

- no live browser activity
- no real DLP policy tips
- no real Purview Activity Explorer data
- less convincing for technical audiences

---

## Cloud-Connected Lab Option

Use this path when a stronger technical demo is needed.

### Build Order

1. Provision synthetic users.
2. Provision SharePoint and Teams topology.
3. Publish sensitivity labels.
4. Create a limited set of DLP policies.
5. Seed synthetic content.
6. Run browser-agent or manual scripted activity.
7. Emit synthetic telemetry to ADX.
8. Connect Power BI to ADX.

### Benefits

- more realistic
- supports live demo interactions
- better for technical audiences
- can show Office Web, SharePoint, Teams, and Purview concepts

### Limitations

- more setup effort
- depends on licensing
- DLP signals may take time
- harder to reset

---

## Small / Medium / Large Deployment Patterns

## Small Deployment

Use case:

- executive demo
- offline workshop
- first build

Includes:

```text
5 personas
3 scenarios
500-1,500 telemetry events
Power BI import model
no browser agents
no real DLP dependency
```

---

## Medium Deployment

Use case:

- security workshop
- Purview demo
- Copilot governance demo

Includes:

```text
8-12 personas
10 scenarios
5,000-25,000 telemetry events
ADX
Power BI DirectQuery or Import
partial SharePoint/Teams provisioning
limited browser automation
```

---

## Large Deployment

Use case:

- full cyber-range
- SOC training
- persistent demo tenant

Includes:

```text
12+ personas
30+ scenarios
100,000+ telemetry events
ADX materialized views
Power BI full semantic model
browser agents
replay controller
CI/CD validation
Sentinel/Fabric optional integrations
```

---

## What to Build First

Highest-impact first build order:

1. Synthetic telemetry generator.
2. Power BI executive dashboard.
3. Scenario replay dataset.
4. AI governance scenario.
5. DLP override scenario.
6. Devon multi-day timeline.
7. ADX ingestion scripts.
8. Content generator.
9. Browser-agent runner.
10. Tenant automation.

Reason:

> Dashboards and timeline replay produce the strongest visible impact fastest.

---

## What to Skip Initially

Skip these in MVP:

- full browser automation
- Sentinel integration
- Fabric integration
- full Endpoint DLP configuration
- full Purview policy deployment
- all 30 scenarios
- all 12 personas
- multi-tenant federation
- autonomous agents
- chaos mode
- advanced materialized views

These can be added after the narrative and telemetry model are validated.

---

## Recommended Azure Services

| Service | MVP Need | Notes |
|---|---|---|
| Azure Data Explorer | Recommended | best for synthetic telemetry and KQL demos |
| Azure Storage | Recommended | store JSONL, exports, generated artifacts |
| Azure Key Vault | Recommended | secrets for automation later |
| Azure App Service | Optional | replay API or browser-agent controller |
| Azure Functions | Optional | lightweight event generation or ingestion |
| Azure Automation | Optional | scheduled resets and maintenance |
| Microsoft Fabric | Future | lakehouse and Direct Lake analytics |
| Microsoft Sentinel | Future | SOC demo expansion |

---

## Estimated Effort Bands

These are practical planning bands, not fixed commitments.

| Build Level | Estimated Effort | Outcome |
|---|---:|---|
| Offline MVP | 2-5 days | sample telemetry + Power BI + presenter story |
| Cloud-connected MVP | 1-3 weeks | tenant topology + seeded content + ADX + Power BI |
| Workshop-ready build | 3-6 weeks | multiple scenarios + replay + reports + scripts |
| Cyber-range build | 2-4 months | agents + replay controller + CI/CD + SOC scenarios |

---

## MVP Success Criteria

The MVP is successful when it can show:

1. A fictional user performs realistic banking activity.
2. Sensitive data is created, accessed, shared, or moved.
3. AI usage changes the risk story.
4. DLP or governance controls respond.
5. A timeline connects the events.
6. Power BI summarizes the risk for executives.
7. The presenter can explain business value in under 10 minutes.
8. No real sensitive data is used.

---

## Minimum Validation Checklist

Before presenting MVP:

- JSON files are valid.
- telemetry events have required fields.
- all IDs are synthetic.
- all external domains are fake or test domains.
- risk scores are within range.
- Power BI refresh succeeds.
- scenario replay page works.
- Devon narrative remains ambiguous and neutral.
- executive script aligns with dashboard pages.
- safety disclaimer is present.

---

## Reference MVP Scenario Flow

```text
Devon opens an AML workbook
        ↓
Devon downloads a working copy
        ↓
Devon asks external AI to summarize raw synthetic AML rows
        ↓
DLP / AI governance event is generated
        ↓
Devon later changes label on a related file
        ↓
External sharing attempt occurs
        ↓
DLP warning or override is recorded
        ↓
Security opens investigation timeline
        ↓
Power BI shows executive risk posture
```

---

## Codex Usage Guidance

Codex should use this guide to:

1. Decide the smallest viable build.
2. Prioritize generators and reports before complex automation.
3. Build a telemetry-first MVP.
4. Avoid overengineering initial deployment.
5. Generate MVP backlog tasks.
6. Produce small, medium, and large implementation plans.
7. Keep demo value visible at every stage.
8. Preserve synthetic-only boundaries.

---

## Safety Reminder

The reference implementation is for synthetic demo environments only.

Do not connect this MVP to production users, production telemetry, real customer data, real HR data, real legal records, real credentials, or real financial transactions.
