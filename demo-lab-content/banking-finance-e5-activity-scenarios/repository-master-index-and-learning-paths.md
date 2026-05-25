# Repository Master Index and Learning Paths

## Purpose

This document is the top-level orchestration and navigation layer for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It provides:

- full repository map
- categorized file inventory
- recommended reading paths
- implementation order
- workshop order
- architecture dependencies
- source-of-truth references
- quickstarts by role
- MVP checklist
- future-state checklist
- repository maturity status

All platform artifacts, scenarios, telemetry, personas, files, prompts, incidents, identifiers, and dashboards must remain fictional and synthetic.

---

## Start Here

If you are new to this repository, start with this file.

Then choose your path:

```text
Codex / Engineer → Build Path
Presenter / Sales / Workshop → Demo Path
Power BI Developer → Analytics Path
SOC / Detection Engineer → Detection Path
AI Governance Consultant → AI Governance Path
Platform Owner → Governance and Maintenance Path
```

---

## Platform Summary

This repository describes and organizes a synthetic Microsoft 365 governance cyber-range and advisory platform.

The platform is designed to simulate realistic but fictional enterprise activity across:

```text
SharePoint Online
OneDrive for Business
Microsoft Teams
Exchange Online
Microsoft Purview
Microsoft Defender concepts
Microsoft Entra concepts
Endpoint DLP concepts
Microsoft Copilot and AI governance concepts
Azure Data Explorer
Power BI
Microsoft Sentinel concepts
```

Primary business domain:

```text
Banking and financial services
```

Primary storytelling anchor:

```text
Normal work becomes governance risk through sequence, context, pressure, and data movement.
```

---

## Primary Source-of-Truth Files

| Area | File |
|---|---|
| Codex build control | `codex-master-build-instructions-and-repository-workplan.md` |
| Build backlog | `demo-lab-build-backlog-and-implementation-epics.md` |
| Reference architecture | `platform-reference-architecture-diagrams-and-component-flows.md` |
| Documentation governance | `repository-maintenance-index-and-documentation-map.md` |
| Responsible use | `synthetic-demo-data-legal-privacy-and-ethical-governance-framework.md` |
| Glossary | `glossary-and-canonical-terms.md` |
| Future roadmap | `platform-roadmap-future-expansion-and-research-directions.md` |

---

## Architecture and Foundation Files

| File | Purpose |
|---|---|
| `platform-reference-architecture-diagrams-and-component-flows.md` | logical architecture, component flows, trust boundaries, deployment topologies |
| `synthetic-tenant-information-architecture-and-collaboration-model.md` | SharePoint, Teams, OneDrive, raw/sanitized zones, guest collaboration model |
| `purview-and-defender-control-mapping-and-capability-matrix.md` | Microsoft capability-to-control mapping across Purview, Defender, Entra, Endpoint, AI |
| `microsoft-purview-deployment-and-governance-maturity-roadmap.md` | maturity journey from visibility to optimization |
| `repository-maintenance-index-and-documentation-map.md` | document ownership, review cadence, source-of-truth map |
| `glossary-and-canonical-terms.md` | canonical language, preferred wording, avoided wording |

---

## Synthetic Data, Personas, and Scenario Files

| File | Purpose |
|---|---|
| `synthetic-data-generation-and-content-factory-architecture.md` | document, email, Teams, AI prompt, and dataset content factory |
| `data-protection-scenario-taxonomy-and-pattern-catalog.md` | reusable scenario categories and risk-pattern taxonomy |
| `browser-agent-behavior-simulation-and-human-activity-engine.md` | browser-agent behavior, timing, mistakes, working rhythms |
| `synthetic-telemetry-replay-and-timeline-orchestration-engine.md` | replay IDs, bookmarks, deterministic timeline logic |
| `platform-roadmap-future-expansion-and-research-directions.md` | future autonomous agents, scenario marketplace, Fabric, replay APIs |

---

## Telemetry, ADX, Detection, and SOC Files

| File | Purpose |
|---|---|
| `adx-kql-hunting-and-detection-library.md` | concrete KQL query library for hunting and replay reconstruction |
| `adx-kql-hunting-and-detection-framework.md` | detection engineering strategy, metadata, watchlists, tuning, FP/FN management |
| `microsoft-sentinel-and-soc-integration-roadmap.md` | Sentinel future-state integration, custom tables, analytics rules, watchlists |
| `microsoft-sentinel-incident-and-case-management-operating-model.md` | incident lifecycle, case management, triage, HR/legal/privacy escalation |

---

## Power BI and Executive Storytelling Files

| File | Purpose |
|---|---|
| `powerbi-semantic-model-and-dashboard-blueprint.md` | semantic model, dimensions, measures, dashboard pages |
| `power-bi-executive-dashboard-and-visual-storytelling-framework.md` | executive analytics, visual storytelling, replay-aware filtering, KPI design |
| `executive-demo-storytelling-and-presentation-flow-guide.md` | executive narrative, audience modes, presentation flow, Q&A guidance |
| `executive-demo-runbooks-and-live-presentation-control-guide.md` | live demo scripts, click paths, fallback plans, presenter cues |

---

## AI Governance and Copilot Files

| File | Purpose |
|---|---|
| `copilot-and-ai-governance-reference-architecture.md` | governed Copilot model, AI Approved Workspace, prompt governance, DSPM for AI concepts |
| `enterprise-ai-governance-and-copilot-adoption-operating-framework.md` | operating model for Copilot adoption, Shadow AI response, AI metrics, maturity |

---

## Commercialization, Assessment, and Managed Services Files

| File | Purpose |
|---|---|
| `customer-workshop-discovery-questionnaire-and-assessment-scorecard.md` | discovery questions, scoring, maturity bands, pre-sales qualification |
| `post-workshop-deliverables-and-customer-roadmap-template.md` | executive summary, findings, roadmap, owner matrix, next engagement proposal |
| `managed-services-operating-model-and-recurring-governance-review-framework.md` | monthly/quarterly governance reviews, service tiers, recurring deliverables |

---

## Responsible-Use and Governance Files

| File | Purpose |
|---|---|
| `synthetic-demo-data-legal-privacy-and-ethical-governance-framework.md` | ethical, legal, privacy, anti-deception, and synthetic-boundary governance |
| `repository-maintenance-index-and-documentation-map.md` | maintainability, ownership, stale-document handling, update dependencies |
| `glossary-and-canonical-terms.md` | language control and terminology consistency |

---

## Build Path - Codex / Engineer

Recommended reading order:

```text
1. codex-master-build-instructions-and-repository-workplan.md
2. demo-lab-build-backlog-and-implementation-epics.md
3. platform-reference-architecture-diagrams-and-component-flows.md
4. synthetic-data-generation-and-content-factory-architecture.md
5. data-protection-scenario-taxonomy-and-pattern-catalog.md
6. synthetic-telemetry-replay-and-timeline-orchestration-engine.md
7. adx-kql-hunting-and-detection-framework.md
8. repository-maintenance-index-and-documentation-map.md
```

Primary goal:

```text
Build the deterministic MVP dataset, validation report, replay timeline, ADX-ready output, and Power BI-ready CSV.
```

---

## Demo Path - Presenter / Sales / Workshop Facilitator

Recommended reading order:

```text
1. executive-demo-runbooks-and-live-presentation-control-guide.md
2. executive-demo-storytelling-and-presentation-flow-guide.md
3. power-bi-executive-dashboard-and-visual-storytelling-framework.md
4. customer-workshop-discovery-questionnaire-and-assessment-scorecard.md
5. post-workshop-deliverables-and-customer-roadmap-template.md
6. synthetic-demo-data-legal-privacy-and-ethical-governance-framework.md
```

Primary goal:

```text
Deliver a safe, synthetic, business-oriented executive or technical demo and convert it into advisory next steps.
```

---

## Analytics Path - Power BI Developer

Recommended reading order:

```text
1. powerbi-semantic-model-and-dashboard-blueprint.md
2. power-bi-executive-dashboard-and-visual-storytelling-framework.md
3. synthetic-telemetry-replay-and-timeline-orchestration-engine.md
4. adx-kql-hunting-and-detection-library.md
5. glossary-and-canonical-terms.md
```

Primary goal:

```text
Build executive, AI governance, DLP, endpoint, replay, SOC, and data-quality pages using the synthetic telemetry model.
```

---

## Detection Path - SOC / Detection Engineer

Recommended reading order:

```text
1. adx-kql-hunting-and-detection-framework.md
2. adx-kql-hunting-and-detection-library.md
3. microsoft-sentinel-and-soc-integration-roadmap.md
4. microsoft-sentinel-incident-and-case-management-operating-model.md
5. synthetic-telemetry-replay-and-timeline-orchestration-engine.md
6. glossary-and-canonical-terms.md
```

Primary goal:

```text
Create hunting packs, replay-aware detections, watchlists, incident models, and SOC tabletop workflows.
```

---

## AI Governance Path - Consultant / Architect

Recommended reading order:

```text
1. copilot-and-ai-governance-reference-architecture.md
2. enterprise-ai-governance-and-copilot-adoption-operating-framework.md
3. synthetic-tenant-information-architecture-and-collaboration-model.md
4. power-bi-executive-dashboard-and-visual-storytelling-framework.md
5. customer-workshop-discovery-questionnaire-and-assessment-scorecard.md
6. post-workshop-deliverables-and-customer-roadmap-template.md
```

Primary goal:

```text
Guide customers through Copilot readiness, safe AI adoption, Shadow AI response, source-data governance, and executive AI metrics.
```

---

## Governance and Maintenance Path - Platform Owner

Recommended reading order:

```text
1. repository-maintenance-index-and-documentation-map.md
2. synthetic-demo-data-legal-privacy-and-ethical-governance-framework.md
3. glossary-and-canonical-terms.md
4. demo-lab-build-backlog-and-implementation-epics.md
5. platform-roadmap-future-expansion-and-research-directions.md
```

Primary goal:

```text
Keep the repository consistent, safe, maintainable, and aligned with MVP and future-state priorities.
```

---

## MVP Implementation Checklist

The MVP is complete when:

```text
persona catalog exists
scenario catalog exists
operation catalog exists
sensitivity-label catalog exists
telemetry generator exists
1,000-event JSONL exists
1,000-event CSV exists
validation report passes
scenario summary exists
replay timeline exists
ADX table and ingestion mapping exist
Power BI report can import CSV
KQL replay can reconstruct BF-SCEN-0030
all data is synthetic
README explains regeneration process
```

---

## Workshop Delivery Checklist

The workshop package is ready when:

```text
executive demo runbook exists
Power BI executive dashboard exists
ScenarioId filters work
Devon replay works
AI governance talking points are prepared
DLP talking points are prepared
fallback screenshots exist
assessment scorecard exists
post-workshop roadmap template exists
synthetic disclaimer is visible
```

---

## SOC Tabletop Checklist

The SOC tabletop package is ready when:

```text
incident summary exists
replay timeline exists
KQL hunting queries exist
case closure taxonomy exists
HR/legal/privacy escalation logic exists
watchlist templates exist
analyst questions exist
executive incident summary template exists
```

---

## Future-State Checklist

Future-state work should not begin until the MVP foundation is stable.

Before future-state expansion:

```text
MVP data generation is reproducible
validation pipeline passes
Power BI dashboard works
ADX ingestion works
replay timeline works
documentation map is current
responsible-use framework is accepted
```

Future-state candidates:

```text
browser agents
Sentinel automation
Fabric integration
Power BI embedded portal
autonomous personas
scenario marketplace
multilingual content packs
governance copilots
advanced anomaly simulation
managed-service customer portal
```

---

## Architecture Dependency Summary

```text
Personas and scenarios
        ↓
Synthetic content factory
        ↓
Telemetry generator
        ↓
Validation pipeline
        ↓
Replay engine
        ↓
ADX and Power BI
        ↓
KQL detections and SOC workflows
        ↓
Executive storytelling and workshops
        ↓
Managed services and customer roadmap
```

---

## Repository Maturity Status

Current repository maturity:

```text
Architecture: Strong
Documentation Coverage: Strong
Implementation Control: Strong
Responsible-Use Governance: Strong
Commercialization Framework: Strong
MVP Code/Data Generation: Pending implementation
Power BI Report Artifact: Pending implementation
ADX Deployment Artifact: Pending implementation
Browser-Agent Automation: Future-state
Sentinel Automation: Future-state
```

---

## Quickstart for Codex

Codex should begin with:

```text
codex-master-build-instructions-and-repository-workplan.md
```

Then implement:

```text
catalogs/personas.json
catalogs/scenarios.json
catalogs/operations.json
catalogs/sensitivity-labels.json
generator/generate_mvp_dataset.py
generator/validators.py
sample-data/*.jsonl
sample-data/*.csv
sample-data/*validation-report.json
sample-data/*replay-timeline.json
```

Do not implement browser agents or Sentinel automation before the MVP dataset passes validation.

---

## Quickstart for Presenters

Start with:

```text
executive-demo-runbooks-and-live-presentation-control-guide.md
```

Prepare:

```text
synthetic disclaimer
Executive Risk Snapshot
AI and Copilot Risk page
DLP Operations page
Scenario Replay page
fallback screenshots
Q&A responses
post-workshop roadmap template
```

---

## Quickstart for Power BI Developers

Start with:

```text
powerbi-semantic-model-and-dashboard-blueprint.md
```

Build first:

```text
FactActivityEvents
DimDate with Week Start (Mon)
DimUser
DimScenario
DimSignal
DimFile
Executive Risk Snapshot
Scenario Replay page
AI and Copilot Risk page
DLP Operations page
```

---

## Quickstart for SOC Engineers

Start with:

```text
adx-kql-hunting-and-detection-framework.md
```

Build first:

```text
ADX table
JSONL ingestion
replay reconstruction queries
AI governance detections
DLP override detections
label downgrade before sharing detection
endpoint movement detection
case closure taxonomy
```

---

## Quickstart for AI Governance Consultants

Start with:

```text
enterprise-ai-governance-and-copilot-adoption-operating-framework.md
```

Prepare:

```text
AI acceptable-use model
AI Approved Workspace strategy
Shadow AI response workflow
AI data-boundary model
AI executive metrics
Copilot readiness questions
post-workshop AI roadmap
```

---

## Responsible-Use Reminder

Every path in this repository must preserve:

```text
synthetic-only data
neutral investigation language
clear demo disclaimers
customer-demo separation
no real production telemetry
no real employee profiling
no unsupported legal or regulatory conclusions
```

---

## Final Platform Statement

This repository defines a complete synthetic Microsoft 365 governance platform that connects:

```text
architecture
synthetic content
human behavior
telemetry
replay
Power BI
ADX/KQL
Purview governance
AI governance
DLP/Endpoint DLP
Sentinel/SOC concepts
executive storytelling
customer discovery
managed services
responsible-use governance
implementation control
future innovation
```

The first engineering objective is simple:

> Build the smallest reliable synthetic dataset and dashboard that can tell the Devon, AI governance, DLP, and sensitive data movement story clearly and safely.
