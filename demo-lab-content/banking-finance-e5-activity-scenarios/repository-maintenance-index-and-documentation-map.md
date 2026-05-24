# Repository Maintenance Index and Documentation Map

## Purpose

This document defines the documentation governance and maintainability layer for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It explains how to manage the growing repository of architecture documents, implementation guides, scenario catalogs, telemetry specifications, Power BI guidance, ADX/KQL guidance, AI governance materials, SOC workflows, and commercialization assets.

All repository artifacts must preserve the synthetic-only boundary of the platform.

---

## Core Documentation Governance Thesis

> A large architecture repository becomes useful only when readers know which files are source-of-truth, which files are implementation guidance, which files are future-state, and which files must be updated together.

Documentation should support:

- human onboarding
- Codex implementation
- workshop preparation
- engineering delivery
- demo certification
- release management
- governance reviews
- future maintainability

---

## Documentation Categories

Recommended categories:

```text
Start Here and Build Control
Architecture and Component Flows
Synthetic Data and Content Factory
Personas and Scenario Design
Telemetry and Replay
Power BI and Executive Analytics
ADX / KQL / Detection Engineering
Purview and AI Governance
Sentinel / SOC / Incident Operations
Commercialization and Workshop Packaging
Operational Governance and Risk Management
Release and Repository Maintenance
```

---

## Source-of-Truth Documents

| Area | Source-of-Truth Document |
|---|---|
| Codex build order | `codex-master-build-instructions-and-repository-workplan.md` |
| Engineering backlog | `demo-lab-build-backlog-and-implementation-epics.md` |
| Reference architecture | `platform-reference-architecture-diagrams-and-component-flows.md` |
| MVP implementation strategy | `reference-implementation-and-minimum-viable-build-guide.md` |
| Telemetry dataset specification | `sample-synthetic-telemetry-dataset-specification.md` |
| Generator design | `synthetic-dataset-generator-pseudocode-and-processing-pipeline.md` |
| Replay architecture | `synthetic-telemetry-replay-and-timeline-orchestration-engine.md` |
| Content factory | `synthetic-data-generation-and-content-factory-architecture.md` |
| Scenario taxonomy | `data-protection-scenario-taxonomy-and-pattern-catalog.md` |
| Human behavior | `persona-behavioral-psychology-and-risk-patterns-guide.md` |
| Collaboration topology | `synthetic-tenant-information-architecture-and-collaboration-model.md` |
| Power BI semantic model | `powerbi-semantic-model-and-dashboard-blueprint.md` |
| Executive visual storytelling | `power-bi-executive-dashboard-and-visual-storytelling-framework.md` |
| ADX/KQL library | `adx-kql-hunting-and-detection-library.md` |
| Detection framework | `adx-kql-hunting-and-detection-framework.md` |
| AI governance architecture | `copilot-and-ai-governance-reference-architecture.md` |
| Enterprise AI operating model | `enterprise-ai-governance-and-copilot-adoption-operating-framework.md` |
| Purview maturity roadmap | `microsoft-purview-deployment-and-governance-maturity-roadmap.md` |
| Sentinel roadmap | `microsoft-sentinel-and-soc-integration-roadmap.md` |
| Incident/case management | `microsoft-sentinel-incident-and-case-management-operating-model.md` |
| Commercial packaging | `platform-commercialization-and-service-packaging-guide.md` |
| Operational risks | `platform-technical-debt-and-operational-risks-register.md` |
| Release strategy | `release-management-and-versioning-strategy.md` |

---

## Reading Paths

## Path 1 - New Engineer / Codex Implementation

Read in this order:

```text
codex-master-build-instructions-and-repository-workplan.md
demo-lab-build-backlog-and-implementation-epics.md
reference-implementation-and-minimum-viable-build-guide.md
sample-synthetic-telemetry-dataset-specification.md
synthetic-dataset-generator-pseudocode-and-processing-pipeline.md
platform-reference-architecture-diagrams-and-component-flows.md
```

Goal:

```text
Build the first deterministic MVP dataset and validation outputs.
```

---

## Path 2 - Power BI Developer

Read in this order:

```text
sample-synthetic-telemetry-dataset-specification.md
powerbi-semantic-model-and-dashboard-blueprint.md
power-bi-executive-dashboard-and-visual-storytelling-framework.md
powerbi-dax-measures-library.md
adx-kql-hunting-and-detection-library.md
```

Goal:

```text
Build executive and replay-aware Power BI dashboards.
```

---

## Path 3 - SOC / Detection Engineer

Read in this order:

```text
adx-kql-hunting-and-detection-framework.md
adx-kql-hunting-and-detection-library.md
microsoft-sentinel-and-soc-integration-roadmap.md
microsoft-sentinel-incident-and-case-management-operating-model.md
synthetic-telemetry-replay-and-timeline-orchestration-engine.md
```

Goal:

```text
Build synthetic hunting packs, detections, and incident workflows.
```

---

## Path 4 - AI Governance Advisor

Read in this order:

```text
copilot-and-ai-governance-reference-architecture.md
enterprise-ai-governance-and-copilot-adoption-operating-framework.md
synthetic-tenant-information-architecture-and-collaboration-model.md
power-bi-executive-dashboard-and-visual-storytelling-framework.md
microsoft-purview-deployment-and-governance-maturity-roadmap.md
```

Goal:

```text
Prepare Copilot readiness, Shadow AI, and AI-safe collaboration narratives.
```

---

## Path 5 - Presenter / Workshop Facilitator

Read in this order:

```text
executive-demo-storytelling-and-presentation-flow-guide.md
power-bi-executive-dashboard-and-visual-storytelling-framework.md
platform-commercialization-and-service-packaging-guide.md
data-protection-scenario-taxonomy-and-pattern-catalog.md
persona-behavioral-psychology-and-risk-patterns-guide.md
```

Goal:

```text
Deliver executive demos, workshops, and tabletop exercises.
```

---

## Document Ownership Model

| Document Type | Owner Role |
|---|---|
| Build instructions | Platform Owner |
| Generator specs | Data Engineer |
| Telemetry schema | Platform Architect |
| Scenario taxonomy | Scenario Designer |
| Persona behavior | Content / Scenario Designer |
| Power BI docs | BI Developer |
| ADX/KQL docs | Detection Engineer |
| AI governance docs | AI Governance Lead |
| Purview roadmap | Purview Specialist |
| Sentinel/SOC docs | SOC Architect |
| Commercialization docs | Services Lead |
| Operational risks | Platform Owner |
| Release docs | Release Manager |
| Documentation map | Platform Owner |

---

## Review Cadence

| Artifact Type | Review Cadence |
|---|---|
| Codex build instructions | every implementation sprint |
| Dataset specification | every generator release |
| Telemetry schema | every schema change |
| Power BI blueprint | every dashboard release |
| ADX/KQL library | every detection release |
| Scenario taxonomy | quarterly or when new scenarios are added |
| Persona behavior | quarterly or when personas change |
| AI governance docs | quarterly or when AI scope changes |
| Purview roadmap | quarterly or when Microsoft capability assumptions change |
| Sentinel/SOC docs | quarterly or when SOC workflows change |
| Commercialization guide | quarterly or when offerings change |
| Operational risks | monthly during active build |
| Release strategy | every major release |
| Documentation map | every major documentation update |

---

## Update Dependency Map

## If telemetry fields change, update:

```text
synthetic-telemetry-schema.json
sample-synthetic-telemetry-dataset-specification.md
synthetic-dataset-generator-pseudocode-and-processing-pipeline.md
powerbi-semantic-model-and-dashboard-blueprint.md
adx-ingestion-and-table-mappings.md
adx-kql-hunting-and-detection-library.md
codex-master-build-instructions-and-repository-workplan.md
```

## If scenario IDs change, update:

```text
complex-scenarios.json
sample-synthetic-telemetry-dataset-specification.md
data-protection-scenario-taxonomy-and-pattern-catalog.md
synthetic-telemetry-replay-and-timeline-orchestration-engine.md
power-bi-executive-dashboard-and-visual-storytelling-framework.md
adx-kql-hunting-and-detection-framework.md
codex-master-build-instructions-and-repository-workplan.md
```

## If personas change, update:

```text
personas catalog
persona-behavioral-psychology-and-risk-patterns-guide.md
browser-agent-behavior-simulation-and-human-activity-engine.md
sample-synthetic-telemetry-dataset-specification.md
synthetic-telemetry-replay-and-timeline-orchestration-engine.md
```

## If Power BI model changes, update:

```text
powerbi-semantic-model-and-dashboard-blueprint.md
power-bi-executive-dashboard-and-visual-storytelling-framework.md
powerbi-dax-measures-library.md
adx-kql-hunting-and-detection-library.md
codex-master-build-instructions-and-repository-workplan.md
```

## If AI governance scope changes, update:

```text
copilot-and-ai-governance-reference-architecture.md
enterprise-ai-governance-and-copilot-adoption-operating-framework.md
synthetic-data-generation-and-content-factory-architecture.md
adx-kql-hunting-and-detection-framework.md
power-bi-executive-dashboard-and-visual-storytelling-framework.md
```

---

## Overlap Management

Some documents intentionally overlap.

| Overlap Area | Primary Source | Supporting Documents |
|---|---|---|
| AI governance | `enterprise-ai-governance-and-copilot-adoption-operating-framework.md` | Copilot architecture, Power BI storytelling, Purview roadmap |
| Replay | `synthetic-telemetry-replay-and-timeline-orchestration-engine.md` | dataset spec, Power BI blueprint, storytelling guide |
| Detection | `adx-kql-hunting-and-detection-framework.md` | KQL library, Sentinel roadmap, incident model |
| Power BI storytelling | `power-bi-executive-dashboard-and-visual-storytelling-framework.md` | semantic model, executive storytelling guide |
| Commercialization | `platform-commercialization-and-service-packaging-guide.md` | Purview roadmap, executive storytelling, AI governance |
| Build execution | `codex-master-build-instructions-and-repository-workplan.md` | backlog, MVP guide, architecture diagrams |

Rule:

```text
When overlap exists, update the primary source first, then update supporting documents only when the change affects implementation or messaging.
```

---

## Stale Document Detection

A document may be stale when:

- it references deprecated field names
- it references removed personas
- it references old scenario IDs
- it conflicts with the Codex build instructions
- it conflicts with the telemetry schema
- it assumes future-state components are already implemented
- it does not mention synthetic-only boundaries
- it has not been reviewed according to cadence

Recommended stale marker:

```text
Status: Needs Review
Reason: [short reason]
Last Reviewed: [YYYY-MM-DD]
Owner: [role]
```

---

## Retirement Rules

A document can be retired when:

- its content is fully replaced by a stronger source-of-truth document
- it duplicates another artifact without adding implementation value
- it describes an abandoned future-state direction
- it contains outdated assumptions that are no longer useful

Retirement process:

```text
1. Mark as Deprecated.
2. Add replacement link.
3. Keep for one release cycle.
4. Archive or remove after confirmation.
```

---

## Required Header Metadata for Future Documents

Future documents should include:

```text
Title
Purpose
Status
Owner Role
Last Reviewed
Related Source-of-Truth Documents
Synthetic-Only Boundary Statement
```

Recommended status values:

```text
Draft
Active
Stable
Needs Review
Deprecated
Archived
```

---

## Glossary Ownership

Recommended future glossary file:

```text
glossary-and-canonical-terms.md
```

The glossary should own terms such as:

```text
ScenarioId
ReplayId
CorrelationId
Synthetic telemetry
AI Approved Workspace
Sensitive AI Event
DLP Override
Endpoint Movement
False Positive
False Negative
Insider Risk-style
Synthetic Incident
```

Owner:

```text
Platform Architect
```

---

## Codex Update Rules

Codex should update documentation when it:

- changes schema fields
- changes output paths
- changes event generation logic
- changes validation rules
- changes scenario IDs
- changes persona definitions
- changes Power BI assumptions
- changes ADX table names
- changes KQL detection names
- adds new generated artifacts

Codex should not:

- silently create new canonical terms
- silently rename source-of-truth files
- treat future-state components as implemented
- delete docs without replacement notes
- remove synthetic-only safety language

---

## Future Consolidation Plan

As implementation matures, consider consolidating into:

```text
README.md
ARCHITECTURE.md
IMPLEMENTATION.md
DATASET.md
POWERBI.md
ADX-KQL.md
AI-GOVERNANCE.md
SOC-OPERATIONS.md
COMMERCIALIZATION.md
CHANGELOG.md
```

Until then, keep detailed domain-specific files to support Codex and modular build phases.

---

## Maintenance Checklist

Before each release:

- verify source-of-truth files are current
- verify Codex build instructions match implementation state
- verify schema-dependent docs are aligned
- verify Power BI docs match current columns and measures
- verify ADX/KQL docs match current table names
- verify scenario IDs are consistent
- verify synthetic-only warnings remain present
- verify stale documents are marked
- update changelog and release notes

---

## Safety Reminder

Documentation maintenance must preserve the synthetic-only boundary.

Do not add real customer data, real employee data, real HR records, real legal matters, real financial transactions, real production telemetry, real credentials, real secrets, or real incident evidence to any documentation artifact.
