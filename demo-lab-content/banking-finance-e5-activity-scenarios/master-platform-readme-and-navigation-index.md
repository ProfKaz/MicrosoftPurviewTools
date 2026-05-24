# Master Platform README and Navigation Index

## Banking / Finance Microsoft 365 E5 Simulation Pack

This folder contains a synthetic Microsoft 365 E5, Microsoft Purview, Defender, Copilot governance, DLP, Endpoint DLP, Insider Risk, ADX, Power BI, and SOC operations simulation framework for banking and financial-services demos.

All users, customers, companies, contracts, cases, account-like values, HR records, legal matters, incidents, telemetry, and data patterns are fictional.

---

## Start Here

If you are new to this pack, read these files first:

1. `folder-index-and-runbook.md`
2. `README.md`
3. `CODEX_HANDOFF.md`
4. `synthetic-tenant-information-architecture.md`
5. `complex-scenarios.json`
6. `m365-activity-timeline-replay-engine-specification.md`

These files explain what the platform is, how the pieces connect, and how to run the synthetic demo model.

---

## Platform Purpose

The platform is designed to simulate realistic Microsoft 365 banking activity across fictional employees and departments.

It supports:

- executive security storytelling
- Microsoft Purview demos
- Copilot governance demos
- DSPM for AI discussions
- DLP and Endpoint DLP demonstrations
- Insider Risk-style investigations
- SOC tabletop exercises
- Power BI dashboards
- ADX telemetry replay
- synthetic browser-agent activity
- Codex-driven content and telemetry generation

---

## Architecture Map

```text
Synthetic tenant architecture
        ↓
Personas and schedules
        ↓
Business scenarios
        ↓
Content generation blueprints
        ↓
Browser-agent task plans
        ↓
Timeline replay engine
        ↓
Normalized telemetry schema
        ↓
ADX ingestion and KQL
        ↓
Risk correlation engine
        ↓
Investigation and SOC playbooks
        ↓
Power BI dashboards and DAX
        ↓
Executive value narrative
```

---

## Tracks

## 1. Executive Track

Use this track when preparing C-level, board, or business-leadership conversations.

Recommended files:

1. `executive-value-and-business-outcomes-guide.md`
2. `demo-presenter-scripts.md`
3. `powerbi-visual-layout-and-storytelling-guide.md`
4. `powerbi-risk-dashboard-definitions.json`
5. `purview-policy-and-control-matrix.md`

Main message:

> AI readiness requires data governance maturity. Risk is not one event; it is a sequence across data, identity, collaboration, AI, endpoint, and human behavior.

---

## 2. Codex Engineering Track

Use this track when building generators, validators, replay engines, or automation scripts.

Recommended files:

1. `CODEX_HANDOFF.md`
2. `tenant-deployment-and-automation-guide.md`
3. `synthetic-telemetry-schema.json`
4. `telemetry-generation-playbooks.json`
5. `m365-activity-timeline-replay-engine-specification.md`
6. `adx-ingestion-and-table-mappings.md`
7. `content-generation-blueprints.json`

Main goal:

> Convert scenario definitions into content, browser actions, normalized telemetry, ADX ingestion, and Power BI-ready datasets.

---

## 3. Purview / Data Security Track

Use this track for Microsoft Purview, DLP, labels, Endpoint DLP, and information protection demos.

Recommended files:

1. `purview-policy-and-control-matrix.md`
2. `synthetic-data-pattern-library.json`
3. `content-generation-blueprints.json`
4. `purview-signal-correlation.json`
5. `synthetic-kql-samples.json`
6. `powerbi-risk-dashboard-definitions.json`

Main message:

> Classification, labels, DLP, endpoint controls, and user coaching must operate together.

---

## 4. AI / Copilot Governance Track

Use this track for Copilot readiness, DSPM for AI, external AI, and Shadow AI discussions.

Recommended files:

1. `copilot-conversation-transcripts.json`
2. `purview-policy-and-control-matrix.md`
3. `synthetic-tenant-information-architecture.md`
4. `synthetic-risk-correlation-engine.json`
5. `powerbi-visual-layout-and-storytelling-guide.md`
6. `executive-value-and-business-outcomes-guide.md`

Main message:

> AI does not create the original oversharing problem. It accelerates the visibility and reuse of whatever users already have permission to access.

---

## 5. SOC / Investigation Track

Use this track for analyst, SOC, Insider Risk, tabletop, and incident-response demonstrations.

Recommended files:

1. `synthetic-security-operations-playbooks.md`
2. `synthetic-investigation-case-management-framework.md`
3. `insider-risk-timelines.json`
4. `synthetic-risk-correlation-engine.json`
5. `synthetic-kql-samples.json`
6. `m365-activity-timeline-replay-engine-specification.md`

Main message:

> A signal is not proof of intent. The investigation value comes from correlation, context, evidence, and process.

---

## 6. Power BI / Analytics Track

Use this track for dashboard, semantic model, and reporting development.

Recommended files:

1. `powerbi-risk-dashboard-definitions.json`
2. `powerbi-dax-measures-library.md`
3. `powerbi-visual-layout-and-storytelling-guide.md`
4. `adx-ingestion-and-table-mappings.md`
5. `synthetic-kql-samples.json`
6. `synthetic-telemetry-schema.json`

Main goal:

> Turn synthetic telemetry into executive dashboards, analyst views, scenario replays, and data-security KPIs.

---

## Artifact Catalog

## Foundation Files

| File | Description |
|---|---|
| `README.md` | General overview and initial project explanation. |
| `CODEX_HANDOFF.md` | Instructions for Codex and automation agents. |
| `folder-index-and-runbook.md` | Folder inventory and recommended execution order. |
| `master-platform-readme-and-navigation-index.md` | This master navigation document. |

---

## Tenant and Business Architecture

| File | Description |
|---|---|
| `synthetic-tenant-information-architecture.md` | SharePoint, Teams, OneDrive, labels, collaboration boundaries, and data ownership. |
| `technologies-and-activities.json` | Microsoft 365 technologies and daily, weekly, monthly, event-driven activities. |
| `daily-schedules.json` | Persona schedules, quiet periods, risk windows, and work cycles. |

---

## Scenarios and Personas

| File | Description |
|---|---|
| `complex-scenarios.json` | Thirty complex banking/finance scenarios. |
| `browser-agent-task-plans.json` | Concrete task plans for browser-based agents. |
| `browser-agent-orchestration-rules.json` | Persona behavior, probabilities, timing, mistakes, escalation rules. |
| `insider-risk-timelines.json` | Chronological insider-risk-style timelines. |

---

## Content and Synthetic Data

| File | Description |
|---|---|
| `synthetic-data-pattern-library.json` | Fictional sensitive data patterns for DLP and classification testing. |
| `content-generation-blueprints.json` | Document, email, Teams, AI prompt, spreadsheet, and investigation artifact templates. |
| `copilot-conversation-transcripts.json` | Safe and unsafe Copilot / external AI conversation examples. |

---

## Telemetry and Replay

| File | Description |
|---|---|
| `synthetic-telemetry-schema.json` | Canonical normalized event schema. |
| `telemetry-generation-playbooks.json` | Playbooks for converting scenario actions into telemetry. |
| `m365-activity-timeline-replay-engine-specification.md` | Replay engine modes, timing, seeds, concurrency, and APIs. |
| `adx-ingestion-and-table-mappings.md` | ADX tables, ingestion, update policies, materialized views, and Power BI mappings. |

---

## Risk, Governance, and Controls

| File | Description |
|---|---|
| `purview-signal-correlation.json` | Maps actions to Purview, Defender, DLP, AI, endpoint, and identity signals. |
| `synthetic-risk-correlation-engine.json` | Risk scoring, modifiers, correlation windows, risk decay, and escalation thresholds. |
| `purview-policy-and-control-matrix.md` | DLP, labels, Endpoint DLP, DSPM for AI, Insider Risk, Conditional Access, and coaching controls. |

---

## SOC and Investigation

| File | Description |
|---|---|
| `synthetic-investigation-case-management-framework.md` | Case lifecycle, HR/Legal escalation, closure paths, evidence handling. |
| `synthetic-security-operations-playbooks.md` | SOC playbooks, KQL pivots, escalation matrix, remediation checklists. |

---

## Power BI and Reporting

| File | Description |
|---|---|
| `powerbi-risk-dashboard-definitions.json` | Dashboard pages, visuals, drillthroughs, measure concepts. |
| `powerbi-dax-measures-library.md` | DAX measure patterns for risk, DLP, AI, endpoint, and insider-risk views. |
| `powerbi-visual-layout-and-storytelling-guide.md` | Page layouts, tooltips, presenter flows, storytelling guidance. |
| `synthetic-kql-samples.json` | KQL hunting and reporting query templates. |

---

## Deployment and Business Value

| File | Description |
|---|---|
| `tenant-deployment-and-automation-guide.md` | Tenant bootstrap, provisioning, CI/CD, reset, cleanup, automation guidance. |
| `demo-presenter-scripts.md` | Executive, security, and workshop presenter scripts. |
| `executive-value-and-business-outcomes-guide.md` | Business outcomes, AI maturity, ROI narrative, service conversion model. |

---

## Recommended Demo Modes

## Executive Demo

Duration:

```text
5-10 minutes
```

Use:

- `demo-presenter-scripts.md`
- `powerbi-visual-layout-and-storytelling-guide.md`
- `executive-value-and-business-outcomes-guide.md`

Recommended scenario:

```text
BF-SCEN-0030 - Devon Multi-Day Risk Chain
```

---

## Security Operations Demo

Duration:

```text
15-30 minutes
```

Use:

- `synthetic-security-operations-playbooks.md`
- `synthetic-kql-samples.json`
- `insider-risk-timelines.json`
- `synthetic-investigation-case-management-framework.md`

Recommended scenarios:

```text
BF-SCEN-0002 - AML External AI
BF-SCEN-0022 - Risky Sign-In
BF-SCEN-0025 - Role Change Download
BF-SCEN-0030 - Devon Multi-Day Risk Chain
```

---

## Purview DLP Demo

Duration:

```text
15-20 minutes
```

Use:

- `purview-policy-and-control-matrix.md`
- `synthetic-data-pattern-library.json`
- `telemetry-generation-playbooks.json`
- `synthetic-kql-samples.json`

Recommended scenarios:

```text
Loan committee oversharing
AML external AI upload
Treasury endpoint movement
Label downgrade before sharing
```

---

## Copilot Governance Demo

Duration:

```text
10-20 minutes
```

Use:

- `copilot-conversation-transcripts.json`
- `synthetic-tenant-information-architecture.md`
- `purview-policy-and-control-matrix.md`
- `powerbi-visual-layout-and-storytelling-guide.md`

Recommended storyline:

```text
Safe Copilot over approved source content
        vs
External AI prompt with raw synthetic AML rows
```

---

## Quick Start Demo Flow

1. Read `folder-index-and-runbook.md`.
2. Select scenario from `complex-scenarios.json`.
3. Generate content using `content-generation-blueprints.json`.
4. Generate or simulate events using `telemetry-generation-playbooks.json`.
5. Emit events using `synthetic-telemetry-schema.json`.
6. Ingest into ADX using `adx-ingestion-and-table-mappings.md`.
7. Query using `synthetic-kql-samples.json`.
8. Visualize using `powerbi-risk-dashboard-definitions.json`.
9. Present using `demo-presenter-scripts.md`.
10. Explain business value using `executive-value-and-business-outcomes-guide.md`.

---

## Dependency Graph

```text
synthetic-data-pattern-library.json
        ↓
content-generation-blueprints.json
        ↓
complex-scenarios.json
        ↓
browser-agent-task-plans.json
        ↓
telemetry-generation-playbooks.json
        ↓
synthetic-telemetry-schema.json
        ↓
adx-ingestion-and-table-mappings.md
        ↓
synthetic-kql-samples.json
        ↓
powerbi-risk-dashboard-definitions.json
        ↓
powerbi-dax-measures-library.md
        ↓
powerbi-visual-layout-and-storytelling-guide.md
```

Parallel governance path:

```text
synthetic-tenant-information-architecture.md
        ↓
purview-policy-and-control-matrix.md
        ↓
purview-signal-correlation.json
        ↓
synthetic-risk-correlation-engine.json
        ↓
synthetic-investigation-case-management-framework.md
        ↓
synthetic-security-operations-playbooks.md
```

---

## Key Concepts Glossary

| Term | Meaning |
|---|---|
| Synthetic telemetry | Fictional event data generated for demos and labs. |
| ScenarioId | Identifier for a complex business/risk scenario. |
| CorrelationId | Identifier used to connect events in the same chain. |
| Replay seed | Deterministic value used to reproduce a simulation. |
| AI Approved Workspace | Governed location for safer Copilot source content. |
| Devon Reyes | Fictional ambiguity-anchor persona for unsafe, negligent, erroneous, or suspicious behavior. |
| Regulated Financial Data | Synthetic banking-sensitive content such as AML, KYC, account-like, or treasury patterns. |
| DLP override | A user continues after receiving a DLP warning. |
| Endpoint movement | Printing, USB copy, network-share copy, or other local movement of sensitive content. |
| Scenario replay | Chronological reconstruction of scenario activity. |

---

## Known Limitations

1. The pack is synthetic and does not represent production telemetry fidelity.
2. KQL examples are schema-adaptable templates, not guaranteed production queries.
3. Power BI DAX measures assume a normalized semantic model.
4. Some Microsoft 365 signals may require licensing, configuration, or time to appear in real tenants.
5. Browser automation may not trigger every backend signal; synthetic event emission is allowed when clearly marked.
6. Risk scoring is demo-oriented and not production-grade.
7. Insider-risk-style workflows must not be applied to real employees without governance review.
8. External domains must remain fake or lab-controlled.

---

## Future Roadmap

Recommended next engineering work:

1. JSON schema definitions for all JSON files.
2. CI workflow for JSON and Markdown validation.
3. ADX deployment scripts.
4. Synthetic telemetry generator.
5. Browser-agent runner.
6. Power BI template or semantic model generator.
7. Scenario replay controller.
8. Synthetic content generator.
9. Purview policy deployment scripts.
10. Demo reset automation.
11. Sample data package.
12. Workshop slide deck.
13. Presenter lab guide.
14. SOC tabletop workbook.
15. Customer-facing solution brief.

---

## Safety and Governance Reminder

This platform is for synthetic demo, lab, training, and advisory use.

Do not use it to:

- monitor real employees
- evaluate real insider-risk cases
- process real customer data
- process real HR records
- process real financial transactions
- process real legal matters
- process real credentials
- process real production logs
- make real disciplinary decisions

without formal legal, privacy, HR, compliance, and governance review.
