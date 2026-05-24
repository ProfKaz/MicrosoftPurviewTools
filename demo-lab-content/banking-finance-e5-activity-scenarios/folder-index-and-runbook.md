# Folder Index and Runbook - Banking / Finance Microsoft 365 E5 Activity Scenario Pack

## Purpose

This runbook explains how the files in this folder work together to support a synthetic Microsoft 365 E5 / Microsoft Purview demo lab for banking and financial-services scenarios.

The pack is designed for browser-based agents, Codex, synthetic telemetry generators, Power BI dashboards, KQL hunting, and presenter-led Microsoft Purview / Defender / Copilot governance demonstrations.

All generated content is fictional. Do not replace the synthetic values with real customer, employee, banking, legal, credential, incident, or payment data.

---

## Folder Path

```text
demo-lab-content/banking-finance-e5-activity-scenarios/
```

---

## File Inventory

| File | Purpose |
|---|---|
| `README.md` | High-level project explanation, story context, personas, fictional banking organization, labels, and design principles. |
| `CODEX_HANDOFF.md` | Instructions for Codex on how to consume the pack, orchestrate activity, and preserve synthetic-only boundaries. |
| `technologies-and-activities.json` | Catalog of Microsoft 365 E5 workloads and common daily, weekly, monthly, and event-driven banking/finance activities. |
| `complex-scenarios.json` | Thirty complex multi-workload banking/finance scenarios with personas, narratives, files, labels, risks, signals, and controls. |
| `browser-agent-task-plans.json` | Concrete step-by-step task plans that browser agents can execute or simulate. |
| `daily-schedules.json` | Persona work schedules, recurring business cycles, quiet periods, risk windows, and Devon-specific risky behavior windows. |
| `purview-signal-correlation.json` | Maps activities to Purview, Defender, DLP, AI, endpoint, identity, communication, and insider-risk signals. |
| `insider-risk-timelines.json` | Chronological investigation-ready timelines, especially Devon Reyes multi-day risk sequences. |
| `copilot-conversation-transcripts.json` | Safe and unsafe Copilot / AI conversation examples with risk notes and recommended controls. |
| `synthetic-kql-samples.json` | KQL-style hunting and reporting query templates for synthetic telemetry. |
| `powerbi-risk-dashboard-definitions.json` | Power BI page definitions, visual concepts, pseudo-DAX measures, and drillthrough guidance. |
| `browser-agent-orchestration-rules.json` | Persona behavior probabilities, timing rules, mistake models, AI ratios, escalation rules, and scenario selection logic. |
| `synthetic-telemetry-schema.json` | Canonical normalized event schema for generated telemetry across workloads. |
| `telemetry-generation-playbooks.json` | Practical playbooks for converting scenario plans into telemetry streams. |
| `synthetic-data-pattern-library.json` | Fictional banking/finance sensitive data pattern library for DLP, SIT, classifier, and content-generation demos. |
| `content-generation-blueprints.json` | Reusable templates for documents, emails, Teams messages, AI prompts, spreadsheet rows, and investigation artifacts. |
| `synthetic-risk-correlation-engine.json` | Risk scoring, correlation windows, composite rules, risk decay, severity bands, confidence model, and escalation thresholds. |

---

## Recommended Codex Execution Order

### Phase 1 - Understand the domain and constraints

1. Read `README.md`.
2. Read `CODEX_HANDOFF.md`.
3. Read `technologies-and-activities.json`.
4. Read `synthetic-data-pattern-library.json`.

Outcome:
Codex understands the fictional banking organization, personas, Microsoft 365 E5 workloads, and synthetic sensitive-data conventions.

---

### Phase 2 - Select business scenarios

1. Read `complex-scenarios.json`.
2. Select one or more scenarios based on demo objective.
3. Use `daily-schedules.json` to place activity into realistic business-time windows.
4. Use `browser-agent-orchestration-rules.json` to decide normal, sensitive, mistaken, or risky behavior.

Outcome:
Codex can decide what scenario should run, when it should run, and how each persona should behave.

---

### Phase 3 - Generate content artifacts

1. Read `content-generation-blueprints.json`.
2. Use `synthetic-data-pattern-library.json` to populate fictional sensitive values.
3. Generate required documents, emails, Teams messages, AI prompts, spreadsheet rows, and investigation artifacts.
4. Apply suggested sensitivity labels from scenario and blueprint metadata.

Outcome:
The lab has realistic synthetic content for Purview, DLP, Copilot, Defender, and Insider Risk demonstrations.

---

### Phase 4 - Execute or simulate browser activity

1. Read `browser-agent-task-plans.json`.
2. Read `telemetry-generation-playbooks.json`.
3. Execute browser actions where possible.
4. Emit synthetic telemetry when direct backend signals cannot be generated through browser automation.
5. Use `synthetic-telemetry-schema.json` as the canonical event contract.

Outcome:
Codex can produce both visible user activity and normalized telemetry suitable for ADX, Log Analytics, or Power BI.

---

### Phase 5 - Correlate signals and compute synthetic risk

1. Read `purview-signal-correlation.json`.
2. Read `synthetic-risk-correlation-engine.json`.
3. Map low-level events to signal categories.
4. Apply base weights, modifiers, correlation windows, risk decay, and composite rules.
5. Generate scenario-level risk sequences.

Outcome:
Raw synthetic events become explainable risk narratives and investigation triggers.

---

### Phase 6 - Build investigation timelines

1. Read `insider-risk-timelines.json`.
2. Generate chronological timelines from normalized telemetry.
3. Create investigation notes using `content-generation-blueprints.json`.
4. Include HR, Legal, Security, and Platform remediation actions where appropriate.

Outcome:
The demo can show not only what happened, but how an enterprise should investigate and respond.

---

### Phase 7 - Query and visualize

1. Use `synthetic-kql-samples.json` to create or adapt hunting queries.
2. Use `powerbi-risk-dashboard-definitions.json` to define dashboard pages.
3. Load normalized telemetry into ADX, Log Analytics, or Power BI.
4. Build executive, analyst, AI governance, DLP, endpoint, and insider-risk views.

Outcome:
The synthetic environment becomes demonstrable through dashboards, query-driven investigations, and executive storytelling.

---

## Recommended Demo Paths

### Demo Path A - Executive Purview Overview

Use when presenting to leadership.

Recommended files:

1. `complex-scenarios.json`
2. `powerbi-risk-dashboard-definitions.json`
3. `purview-signal-correlation.json`
4. `synthetic-risk-correlation-engine.json`

Suggested narrative:

> Risk in banking does not appear from one isolated action. It emerges from how sensitive data is created, copied, shared, summarized by AI, downloaded, printed, and investigated across Microsoft 365.

---

### Demo Path B - Copilot / AI Governance

Use when discussing Copilot readiness, oversharing, or DSPM for AI.

Recommended files:

1. `copilot-conversation-transcripts.json`
2. `synthetic-data-pattern-library.json`
3. `purview-signal-correlation.json`
4. `powerbi-risk-dashboard-definitions.json`

Suggested narrative:

> AI inherits the data access reality of the organization. If permissions and labels are weak, AI can surface sensitive content that users technically can access but should not broadly use.

---

### Demo Path C - DLP and Endpoint DLP

Use when demonstrating Microsoft Purview DLP and endpoint data movement.

Recommended files:

1. `synthetic-data-pattern-library.json`
2. `telemetry-generation-playbooks.json`
3. `synthetic-kql-samples.json`
4. `powerbi-risk-dashboard-definitions.json`

Suggested narrative:

> DLP is not only about blocking. It is also about understanding user intent, coaching better workflows, and detecting when data moves outside expected collaboration paths.

---

### Demo Path D - Insider Risk Storytelling

Use when demonstrating investigation complexity.

Recommended files:

1. `insider-risk-timelines.json`
2. `browser-agent-orchestration-rules.json`
3. `synthetic-risk-correlation-engine.json`
4. `content-generation-blueprints.json`

Suggested narrative:

> A single event rarely proves intent. The investigation value comes from combining signals, business context, timing, sensitivity, and user behavior.

---

## Canonical Data Flow

```text
Personas + schedules
        ↓
Scenario selection
        ↓
Content generation
        ↓
Browser-agent activity or synthetic event emission
        ↓
Normalized telemetry schema
        ↓
Signal correlation
        ↓
Synthetic risk scoring
        ↓
Investigation timelines
        ↓
KQL hunting and Power BI dashboards
```

---

## Key Synthetic Identifiers

Common fictional values used across the pack:

```text
CUST-BNK-204919
ACCT-FIC-7721-0044-9081
LOAN-FIC-2026-1187
KYC-FIC-88421
AML-CASE-2026-0519
SAR-DRAFT-FIC-2044
DISPUTE-FIC-60392
EMP-785511
DEV-FIC-2219
ROLE-CHANGE-FIC-2026-05
```

These values are fictional and should not be replaced with real data.

---

## Recommended Labels

```text
Public
Internal
Confidential
Highly Confidential
Highly Confidential - Regulated Financial Data
Highly Confidential - HR Restricted
Highly Confidential - Legal Privileged
```

Codex can map these display names to actual label IDs later.

---

## Primary Personas

| Persona | Role | Simulation Purpose |
|---|---|---|
| Alexander Meyer | CEO | Executive summaries, board materials, Copilot summaries. |
| Ana Rodriguez | Head of IT / Security | Security governance, Purview review, investigation leadership. |
| Carlos Delgado | Data Analyst | Power BI exports, credit risk, analytics workbooks. |
| David Chen | Customer Operations Specialist | Customer complaints, support, operations workflows. |
| Emily Johnson | Corporate Lawyer | Legal review, privileged memos, regulator response. |
| James Wilson | Director of Operations | Operations reporting, vendor due diligence, treasury coordination. |
| Laura Gomez | HR Manager | HR compensation, workforce planning, role-change context. |
| Marcus Olsson | Cybersecurity Manager | Security operations, DLP review, insider-risk investigation. |
| Miguel Santos | Platform Engineer | Endpoint, device, identity, and platform security review. |
| Priya Sharma | Data Scientist | Model data, anonymization, analytics and AI workflows. |
| Sofia Lopez | Project Manager | PMO coordination, task tracking, steering materials. |
| Devon Reyes | Junior Operations Analyst | Ambiguous unsafe, negligent, erroneous, or potentially malicious behavior simulation. |

---

## Devon Reyes Simulation Guidance

Devon should not be modeled as always malicious.

His behavior should be ambiguous and realistic:

- Sometimes normal.
- Sometimes rushed.
- Sometimes careless.
- Sometimes policy-confused.
- Sometimes risky enough to trigger investigation.

Preferred Devon triggers:

- Late-afternoon deadline pressure.
- Similar raw and sanitized filenames.
- Role-change or HR context.
- External vendor request.
- Unclear data handling policy.
- AI shortcut behavior.
- Over-permissioned SharePoint content.

---

## Implementation Notes for Codex

Codex should:

1. Validate all JSON before use.
2. Treat JSON files as source-of-truth configuration.
3. Generate normalized events using `synthetic-telemetry-schema.json`.
4. Avoid hardcoding labels, operations, users, or signals outside the configuration files.
5. Use deterministic seeds for repeatable demos.
6. Use randomness only inside the defined behavioral rules.
7. Generate safe and risky variants intentionally.
8. Preserve synthetic-only data boundaries.
9. Keep scenario IDs and correlation IDs consistent across artifacts.
10. Generate investigation notes with neutral language.

---

## Suggested Next Engineering Tasks

1. Build a JSON schema validator for all files in this folder.
2. Create a content generator that consumes `content-generation-blueprints.json` and `synthetic-data-pattern-library.json`.
3. Create a telemetry generator that emits events based on `synthetic-telemetry-schema.json`.
4. Create a scenario runner that consumes `browser-agent-task-plans.json` and `telemetry-generation-playbooks.json`.
5. Create an ADX ingestion mapping for normalized telemetry.
6. Create Power BI dimensions and fact tables based on `powerbi-risk-dashboard-definitions.json`.
7. Create KQL query adapters for Defender XDR, Log Analytics, ADX, and Purview exports.
8. Create replay controls for compressed demo mode.
9. Add scenario validation checks to confirm expected signals were generated.
10. Create a presenter script for each demo path.

---

## Final Safety Reminder

This pack is for demo, lab, education, and synthetic telemetry generation only.

Never use:

- real customers
- real account numbers
- real payment data
- real employee records
- real HR cases
- real legal matters
- real credentials
- real incidents
- real secrets
- real production logs

All content must remain fictional, controlled, and clearly synthetic.
