# Demo Lab Build Backlog and Implementation Epics

## Purpose

This document converts the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform from architecture into an actionable engineering-delivery backlog.

It defines:

- implementation epics
- backlog items
- user stories
- acceptance criteria
- dependency order
- MVP sequence
- GitHub issue suggestions
- definition of done
- delivery priorities
- documentation tasks
- commercialization tasks

All implementation work must preserve the synthetic-only boundary of the platform.

---

## Delivery Thesis

> The platform should be built in visible increments: first prove the story, then automate the data, then automate the tenant, then operationalize the cyber-range.

Recommended delivery logic:

```text
MVP content and telemetry
        ↓
Power BI visibility
        ↓
ADX ingestion and KQL
        ↓
Replay orchestration
        ↓
Content factory
        ↓
Browser agents
        ↓
Sentinel/SOC expansion
        ↓
Commercial and workshop packaging
```

---

## Priority Levels

| Priority | Meaning |
|---|---|
| P0 | Required for first usable MVP |
| P1 | Required for workshop-ready platform |
| P2 | Required for technical depth and automation |
| P3 | Future cyber-range expansion |

---

## Epic Overview

| Epic ID | Epic Name | Priority |
|---|---|---|
| EPIC-001 | Repository Structure and Documentation Baseline | P0 |
| EPIC-002 | Synthetic Persona and Scenario Core | P0 |
| EPIC-003 | Synthetic Telemetry Generator MVP | P0 |
| EPIC-004 | Power BI MVP Dashboard | P0 |
| EPIC-005 | ADX Ingestion and KQL Hunting | P1 |
| EPIC-006 | Replay Timeline and Scenario Orchestration | P1 |
| EPIC-007 | Synthetic Content Factory | P1 |
| EPIC-008 | Browser-Agent Simulation Engine | P2 |
| EPIC-009 | Validation and CI/CD | P1 |
| EPIC-010 | Sentinel and SOC Integration | P2 |
| EPIC-011 | AI Governance and Copilot Adoption Pack | P1 |
| EPIC-012 | Commercialization and Workshop Packaging | P2 |
| EPIC-013 | Release Management and Operational Governance | P1 |
| EPIC-014 | Long-Term Cyber-Range Expansion | P3 |

---

## EPIC-001 - Repository Structure and Documentation Baseline

## Goal

Ensure all platform documentation is organized, discoverable, and ready for Codex-driven implementation.

## User Story

As a platform maintainer, I want a clear repository structure and navigation index so that humans and Codex can understand which files drive architecture, telemetry, reporting, replay, and commercialization.

## Key Tasks

- verify master navigation index
- group artifacts by architecture, telemetry, Power BI, ADX, SOC, AI, governance, and commercialization
- add README links to major documents
- identify duplicate or overlapping documents
- define file naming standards

## Acceptance Criteria

- master index references all key artifacts
- folder structure is documented
- every major artifact has a clear purpose section
- no artifact contains real sensitive data

## Suggested GitHub Issues

```text
[EPIC-001] Audit platform documentation index
[EPIC-001] Add README links for all major architecture files
[EPIC-001] Identify duplicate or overlapping guidance documents
```

---

## EPIC-002 - Synthetic Persona and Scenario Core

## Goal

Define the minimum set of personas, scenarios, behavioral models, and scenario IDs needed for the MVP.

## User Story

As a scenario designer, I want a stable persona and scenario core so that telemetry, content, Power BI, and replay outputs all reference the same business story.

## Key Tasks

- define MVP personas
- confirm Devon Reyes behavior model
- define three MVP scenarios
- map personas to departments and roles
- map scenarios to sensitive data domains
- validate ScenarioId format

## Acceptance Criteria

- MVP personas have UPNs, departments, roles, and behavioral profiles
- three MVP scenarios are documented and referenced consistently
- scenario IDs match the platform ID convention
- Devon is represented as ambiguous, not malicious by default

## Suggested GitHub Issues

```text
[EPIC-002] Create MVP persona catalog JSON
[EPIC-002] Create MVP scenario catalog JSON
[EPIC-002] Validate ScenarioId references across docs
```

---

## EPIC-003 - Synthetic Telemetry Generator MVP

## Goal

Generate the first 1,000-event synthetic telemetry dataset.

## User Story

As a data engineer, I want a deterministic telemetry generator so that I can produce repeatable JSONL and CSV datasets for ADX, Power BI, and replay demos.

## Key Tasks

- implement event ID factory
- implement persona scheduler
- implement baseline event generator
- implement BF-SCEN-0002 generation
- implement BF-SCEN-0013 generation
- implement BF-SCEN-0030 generation
- implement risk scoring
- export JSONL
- export CSV
- generate validation report

## Acceptance Criteria

- dataset contains 950-1,050 events
- every event has `IsSynthetic = true`
- all required fields are present
- all risk scores are between 0 and 100
- scenario distributions match the dataset specification
- output files are Power BI-ready and ADX-ready

## Suggested GitHub Issues

```text
[EPIC-003] Build deterministic event ID and correlation ID factories
[EPIC-003] Generate baseline business telemetry
[EPIC-003] Generate Devon multi-day risk chain events
[EPIC-003] Export MVP dataset to JSONL and CSV
[EPIC-003] Generate dataset validation report
```

---

## EPIC-004 - Power BI MVP Dashboard

## Goal

Build the first executive and technical Power BI report using the MVP dataset.

## User Story

As a presenter, I want an executive dashboard that explains synthetic data-security and AI-governance risk clearly so that I can deliver a compelling demo without relying on raw telemetry.

## Key Tasks

- create FactActivityEvents table
- create DimDate with `Week Start (Mon)`
- create DimUser, DimScenario, DimSignal, DimFile
- create base DAX measures
- build Executive Risk Snapshot page
- build AI and Copilot Risk page
- build DLP Operations page
- build Scenario Replay page
- add synthetic-data disclaimer

## Acceptance Criteria

- report loads the 1,000-event dataset
- slicers work for ScenarioId, PersonaName, Department, Severity
- replay page reconstructs BF-SCEN-0030
- AI page distinguishes Copilot from external AI
- DLP page shows warnings, blocks, and overrides
- dashboard can support a 10-minute executive demo

## Suggested GitHub Issues

```text
[EPIC-004] Build Power BI MVP semantic model
[EPIC-004] Add DimDate with Week Start (Mon)
[EPIC-004] Build Executive Risk Snapshot page
[EPIC-004] Build Scenario Replay page
[EPIC-004] Add synthetic-data disclaimer and tooltip pages
```

---

## EPIC-005 - ADX Ingestion and KQL Hunting

## Goal

Enable ADX ingestion and reusable KQL hunting workflows.

## User Story

As a SOC analyst, I want synthetic telemetry in ADX with reusable KQL queries so that I can investigate scenario timelines and demonstrate detection logic.

## Key Tasks

- create ADX table definition
- create ingestion mapping
- load JSONL sample dataset
- validate schema
- implement KQL hunting library files
- create replay reconstruction queries
- create dashboard extraction queries

## Acceptance Criteria

- JSONL sample ingests successfully
- KQL queries run against the table
- replay queries return ordered event timelines
- Power BI extract query works
- data quality query identifies invalid rows if introduced

## Suggested GitHub Issues

```text
[EPIC-005] Create ADX table and ingestion mapping scripts
[EPIC-005] Load MVP JSONL dataset into ADX
[EPIC-005] Add KQL files for AI, DLP, Endpoint, and Replay hunting
[EPIC-005] Add ADX data quality validation queries
```

---

## EPIC-006 - Replay Timeline and Scenario Orchestration

## Goal

Create deterministic replay timelines and presenter bookmarks.

## User Story

As a demo facilitator, I want replay metadata and bookmarks so that I can present complex multi-day scenarios as a clear sequence.

## Key Tasks

- define ReplayId format
- generate replay timeline JSON
- generate bookmarks
- map bookmarks to Power BI filters
- validate event ordering
- create executive storyboard frames

## Acceptance Criteria

- BF-SCEN-0030 replay timeline is ordered correctly
- bookmarks exist for AI, DLP, endpoint, and investigation moments
- Power BI can filter by ScenarioId and CorrelationId
- replay validation report passes

## Suggested GitHub Issues

```text
[EPIC-006] Generate replay metadata for Devon scenario
[EPIC-006] Create presenter bookmarks for MVP scenarios
[EPIC-006] Validate replay event ordering and required signals
```

---

## EPIC-007 - Synthetic Content Factory

## Goal

Generate realistic synthetic content linked to telemetry and scenarios.

## User Story

As a content engineer, I want a content factory that produces synthetic documents, emails, Teams messages, and prompts so that telemetry has believable business artifacts behind it.

## Key Tasks

- implement synthetic identifier generator
- generate AML/KYC/finance/HR/legal documents
- generate raw and sanitized variants
- generate companion emails
- generate Teams threads
- generate AI prompt sets
- assign sensitivity labels
- produce content manifest
- validate synthetic safety

## Acceptance Criteria

- MVP content pack contains at least 20 files
- raw and sanitized variants exist for key scenarios
- content manifest links files to scenarios and telemetry
- no real sensitive data is present
- labels match content sensitivity

## Suggested GitHub Issues

```text
[EPIC-007] Build synthetic pattern generator
[EPIC-007] Generate MVP document pack
[EPIC-007] Generate Teams and email companion content
[EPIC-007] Generate content manifest and validation report
```

---

## EPIC-008 - Browser-Agent Simulation Engine

## Goal

Simulate realistic browser-based user activity in a lab tenant.

## User Story

As a demo engineer, I want browser agents to perform realistic Microsoft 365 actions so that the lab can show visible user behavior in addition to synthetic telemetry.

## Key Tasks

- define browser-agent action model
- implement persona timing profiles
- implement Teams posting actions
- implement Outlook send actions
- implement SharePoint/OneDrive file actions
- implement AI prompt simulation
- implement DLP warning response behavior
- link browser actions to telemetry metadata

## Acceptance Criteria

- agents can run in synthetic tenant only
- actions follow persona behavior profiles
- events can be correlated with ReplayId and CorrelationId
- fallback instant replay mode exists
- no real users or real data are used

## Suggested GitHub Issues

```text
[EPIC-008] Define browser-agent action schema
[EPIC-008] Implement Devon task plan runner
[EPIC-008] Implement Teams and Outlook browser actions
[EPIC-008] Add fallback instant replay mode
```

---

## EPIC-009 - Validation and CI/CD

## Goal

Add automated quality gates for JSON, schemas, synthetic-data safety, and cross-file references.

## User Story

As a platform maintainer, I want CI validation so that unsafe, broken, or inconsistent artifacts are detected before use.

## Key Tasks

- create JSON schema files
- validate metadata blocks
- validate ID formats
- validate scenario references
- validate synthetic data prefixes
- validate KQL file presence
- validate Power BI assumptions
- publish validation report

## Acceptance Criteria

- CI fails on invalid JSON
- CI fails on `IsSynthetic = false`
- CI warns on unknown ScenarioId
- CI blocks real-looking secrets or credentials
- validation report is generated for each run

## Suggested GitHub Issues

```text
[EPIC-009] Create metadata and telemetry JSON schemas
[EPIC-009] Add synthetic-data safety scanner
[EPIC-009] Add cross-file ScenarioId validation
[EPIC-009] Create GitHub Actions validation workflow
```

---

## EPIC-010 - Sentinel and SOC Integration

## Goal

Extend the platform into Sentinel-style incidents, watchlists, and SOC workflows.

## User Story

As a SOC lead, I want synthetic Sentinel-style incidents and watchlists so that I can run tabletop exercises and demonstrate data-security investigation processes.

## Key Tasks

- create Sentinel field mapping
- create custom table design
- create watchlist templates
- create analytics-rule metadata
- create incident templates
- create SOC triage workbook outline
- create tabletop exercise guide

## Acceptance Criteria

- incident schema references ScenarioId and CorrelationId
- watchlist templates exist
- at least three analytics rule concepts are documented
- SOC tabletop workflow is usable for BF-SCEN-0030

## Suggested GitHub Issues

```text
[EPIC-010] Create Sentinel field mapping document
[EPIC-010] Create watchlist CSV templates
[EPIC-010] Create Sentinel analytics rule templates
[EPIC-010] Create SOC tabletop workbook
```

---

## EPIC-011 - AI Governance and Copilot Adoption Pack

## Goal

Create reusable assets for AI governance demos, Copilot readiness, and Shadow AI response.

## User Story

As an AI governance advisor, I want a structured Copilot readiness and Shadow AI response pack so that I can guide customers from AI enthusiasm to governed adoption.

## Key Tasks

- create AI readiness scorecard
- create AI acceptable-use template
- create AI Approved Workspace guide
- create safe prompt examples
- create unsafe prompt examples
- create Shadow AI response workflow
- create executive AI metrics list

## Acceptance Criteria

- pack distinguishes Copilot from unmanaged external AI
- safe and unsafe workflows are documented
- AI metrics align to Power BI model
- coaching language is practical and non-punitive

## Suggested GitHub Issues

```text
[EPIC-011] Create AI readiness scorecard
[EPIC-011] Create AI acceptable-use policy outline
[EPIC-011] Create AI Approved Workspace setup guide
[EPIC-011] Create AI prompt governance examples
```

---

## EPIC-012 - Commercialization and Workshop Packaging

## Goal

Package the platform into reusable service offerings, workshop assets, and sales enablement.

## User Story

As a services lead, I want packaged offerings and workshop flows so that the platform can support advisory, implementation, and managed-service opportunities.

## Key Tasks

- create executive briefing outline
- create workshop facilitator guide
- create proposal template
- create maturity questionnaire
- create demo-to-engagement follow-up email
- create service SKU descriptions
- create managed governance service outline

## Acceptance Criteria

- at least three service packages are documented
- workshop flow maps to platform artifacts
- proposal outline includes assumptions and exclusions
- Microsoft-funded workshop caveats are included

## Suggested GitHub Issues

```text
[EPIC-012] Create executive briefing deck outline
[EPIC-012] Create Purview workshop facilitator guide
[EPIC-012] Create customer maturity questionnaire
[EPIC-012] Create service offering descriptions
```

---

## EPIC-013 - Release Management and Operational Governance

## Goal

Create release discipline, issue taxonomy, versioning, and operational review process.

## User Story

As a platform owner, I want release management and operational governance so that the platform remains sustainable and demo-ready.

## Key Tasks

- create CHANGELOG.md
- create release notes template
- define GitHub labels
- define milestone structure
- create demo certification checklist
- create operational risk review cadence
- define archive/deprecation process

## Acceptance Criteria

- release notes template exists
- issue labels and milestones are documented
- demo certification criteria are defined
- rollback guidance exists

## Suggested GitHub Issues

```text
[EPIC-013] Create CHANGELOG.md template
[EPIC-013] Create GitHub issue label taxonomy
[EPIC-013] Create demo certification checklist
[EPIC-013] Create release notes template
```

---

## EPIC-014 - Long-Term Cyber-Range Expansion

## Goal

Expand the platform into a broader Microsoft 365 governance cyber-range.

## User Story

As a platform strategist, I want a long-term expansion backlog so that the platform can evolve into autonomous agents, multi-tenant scenarios, and advanced SOC exercises.

## Key Tasks

- define autonomous persona agents
- define multi-tenant federation model
- define red-team vs blue-team scenarios
- define Fabric integration
- define Defender XDR enrichment
- define immersive replay visualization
- define industry expansion packs

## Acceptance Criteria

- roadmap items are documented as future work
- experimental items are separated from stable demo assets
- safety boundaries are preserved

## Suggested GitHub Issues

```text
[EPIC-014] Define autonomous persona agent roadmap
[EPIC-014] Define multi-tenant federation scenarios
[EPIC-014] Define immersive replay visualization concept
[EPIC-014] Define healthcare/government industry expansion backlog
```

---

## MVP Build Sequence

Recommended first implementation sequence:

```text
1. Persona catalog
2. Scenario catalog
3. Telemetry schema
4. 1,000-event generator
5. CSV and JSONL export
6. Power BI MVP report
7. Replay metadata and bookmarks
8. ADX ingestion scripts
9. KQL hunting pack
10. Validation workflow
```

---

## Definition of Done

An item is done when:

- source file or code is committed
- synthetic-only validation passes
- required metadata exists
- documentation explains usage
- references to scenarios/personas are valid
- outputs are reproducible where applicable
- acceptance criteria are met
- no real sensitive data is present

---

## Release Milestones

Suggested milestones:

```text
M0 - Architecture Documentation Complete
M1 - Offline MVP Dataset
M2 - Power BI MVP Dashboard
M3 - ADX and KQL MVP
M4 - Replay-Oriented Demo Pack
M5 - Content Factory MVP
M6 - Browser-Agent Preview
M7 - SOC Tabletop Preview
M8 - Workshop Packaging Release
M9 - Cyber-Range v1
```

---

## Codex Usage Guidance

Codex should use this file to:

1. Create GitHub issues.
2. Generate implementation plans.
3. Build sprint backlogs.
4. Track acceptance criteria.
5. Prioritize MVP tasks.
6. Avoid building future cyber-range items before MVP validation.
7. Map architecture documents to engineering tasks.
8. Preserve synthetic-only boundaries.
9. Generate release milestones.
10. Keep delivery focused on visible demo value.

---

## Safety Reminder

All backlog items must preserve the synthetic-only nature of the platform.

Do not introduce real users, real customer data, real HR records, real legal matters, real financial transactions, real credentials, real production telemetry, or real incident evidence into any implementation task.
