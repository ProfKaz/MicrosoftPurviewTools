# Power BI Visual Layout and Storytelling Guide - Banking / Finance Microsoft 365 E5 Simulation Pack

## Purpose

This guide defines the visual layout, storytelling structure, tooltip strategy, drillthrough behavior, and presenter notes for Power BI reports built on the synthetic Microsoft 365 E5 / Microsoft Purview banking simulation pack.

It complements:

- `powerbi-risk-dashboard-definitions.json`
- `powerbi-dax-measures-library.md`
- `adx-ingestion-and-table-mappings.md`
- `synthetic-risk-correlation-engine.json`

The goal is to transform raw synthetic telemetry into an executive-ready and analyst-ready narrative.

---

## General Design Principles

1. Start with business risk, not tool noise.
2. Separate executive interpretation from analyst investigation.
3. Keep normal activity visible so risk does not appear artificially exaggerated.
4. Use timeline visuals to explain sequence, causality, and investigation context.
5. Use drillthrough pages to move from summary to evidence.
6. Avoid implying malicious intent unless the scenario explicitly supports that conclusion.
7. Clearly mark the dataset as synthetic demo telemetry.

---

## Recommended Report Navigation

Recommended page order:

1. Executive Risk Snapshot
2. Sensitive Data Exposure
3. AI and Copilot Risk
4. DLP Operations
5. External Sharing Heatmap
6. Endpoint DLP and Device Movement
7. Insider Risk Overview
8. Scenario Replay and Timeline
9. User Investigation Drillthrough
10. Sensitive File Drillthrough

This order supports a natural story:

```text
What is happening?
        ↓
Where is sensitive data exposed?
        ↓
How does AI change the risk?
        ↓
Which controls reacted?
        ↓
Where did data move externally or to endpoints?
        ↓
Which behavior sequences require investigation?
        ↓
What exactly happened in the scenario?
```

---

## Page 1 - Executive Risk Snapshot

### Audience

Executive leadership, board-level stakeholders, risk committee, security leadership.

### Page Objective

Provide a concise, high-level risk posture view without overwhelming the audience with technical detail.

### Layout

```text
[Header: Executive Risk Snapshot]
[Subtitle: Synthetic Microsoft 365 E5 Banking Telemetry]

[KPI: Total Events] [KPI: Risk Events] [KPI: High/Critical] [KPI: External Sharing] [KPI: AI Risk]

[Line Chart: Risk Events Over Time]
[Stacked Bar: Risk by Department]

[Donut/Bar: Risk Category Mix]
[Table: Top Active Scenarios]

[Text Box: What this means]
```

### Primary Visuals

- KPI cards for total risk posture.
- Line chart showing risk trend over time.
- Department comparison to show where risk concentrates.
- Scenario table to connect telemetry to business stories.

### What This Means Text

Suggested wording:

> Sensitive data risk is not isolated to one tool or one user action. In this simulation, risk emerges from the combination of file movement, external collaboration, AI summarization, label changes, and endpoint activity.

### Presenter Notes

Emphasize that the dashboard is not trying to show that the organization is broken. It is showing that realistic banking activity creates data risk unless governance, classification, DLP, endpoint controls, and AI readiness are aligned.

---

## Page 2 - Sensitive Data Exposure

### Audience

Security, compliance, data governance, information protection owners.

### Page Objective

Show where sensitive information appears, how it moves, and which files or labels require review.

### Layout

```text
[Header: Sensitive Data Exposure]

[KPI: Distinct Sensitive Files] [KPI: Highly Confidential Events] [KPI: Files Shared Externally]

[Matrix: Events by Sensitivity Label and Workload]
[Bar Chart: Top Sensitive Files by Risky Event Count]

[Treemap: Sensitive Events by Department]
[Line Chart: Sensitive Data Movement Trend]

[Table: Files Requiring Review]
```

### Recommended Tooltip Structure

Use the following tooltip format:

```text
Simple Definition:
What this event represents.

Executive Explanation:
Why this matters to the business.

Example:
A fictional file such as Monthly_AML_Review_Workbook_AML-CASE-2026-0519.xlsx was downloaded or shared.
```

### Presenter Notes

Reinforce the governance principle:

> You cannot protect what you cannot classify, and AI cannot safely summarize what the organization has not properly governed.

---

## Page 3 - AI and Copilot Risk

### Audience

AI governance, security, compliance, executive leadership.

### Page Objective

Explain how Copilot and external AI activity interact with permissions, labels, and sensitive source content.

### Layout

```text
[Header: AI and Copilot Risk]

[KPI: Copilot Interactions] [KPI: External AI Interactions] [KPI: Sensitive AI Events] [KPI: Unmanaged AI Uploads]

[Bar Chart: Sensitive Sources Referenced by Copilot]
[Scatter Chart: AI Usage Risk by User]

[Table: Unsafe AI Prompt Samples]
[Table: Recommended AI Governance Actions]

[Text Box: AI Risk Interpretation]
```

### AI Risk Interpretation Text

Suggested wording:

> AI does not create the original oversharing problem. It accelerates the visibility and reuse of whatever users already have permission to access. The most important control is not only prompt monitoring, but permission hygiene, labeling, DLP, and approved AI workflows.

### Visual Interaction Guidance

Selecting a user should cross-filter:

- prompt samples
- sensitive source files
- labels
- related DLP events
- scenario replay

### Presenter Notes

Contrast safe Copilot usage with unmanaged AI usage. Safe usage should still be governed; external AI usage with raw regulated rows should be treated as a high-risk shortcut.

---

## Page 4 - DLP Operations

### Audience

SOC, compliance operations, data protection administrators.

### Page Objective

Operationalize DLP activity by showing matches, warnings, blocks, overrides, and repeat behavior.

### Layout

```text
[Header: DLP Operations]

[KPI: DLP Matches] [KPI: DLP Warnings] [KPI: DLP Blocks] [KPI: DLP Overrides] [KPI: Override Rate]

[Stacked Column: DLP Events by Action]
[Bar Chart: Top DLP Policies]

[Bar Chart: Top DLP Users]
[Table: Overrides Requiring Review]

[Text Box: Coaching vs Blocking]
```

### Coaching vs Blocking Text

Suggested wording:

> DLP should not be presented only as a blocking mechanism. In realistic environments, DLP also identifies where users need better workflows, clearer labels, safer sharing paths, and coaching.

### Presenter Notes

Use override examples to discuss business justification. A DLP override does not automatically mean malicious intent, but it should be reviewable and explainable.

---

## Page 5 - External Sharing Heatmap

### Audience

Security, compliance, data owners, collaboration governance teams.

### Page Objective

Visualize external sharing, guest access, recipient domains, and sensitive files exposed outside expected collaboration boundaries.

### Layout

```text
[Header: External Sharing Heatmap]

[KPI: External Sharing Events] [KPI: External Domains] [KPI: Guest Access Events] [KPI: Sensitive External Files]

[Heatmap: Department x Sensitivity Label]
[Bar Chart: Top External Domains]

[Network Graph: User-to-Domain Sharing Map]
[Table: Active External Links / Shared Files]
```

### Network Graph Guidance

If Power BI custom visuals are allowed, use a network graph to show:

```text
User → External Domain → File → Sensitivity Label
```

If custom visuals are not allowed, replace it with a matrix:

```text
Rows: User
Columns: Target Domain
Values: External Sharing Events
```

### Presenter Notes

Explain that external collaboration is not inherently bad. The objective is to distinguish approved collaboration from unnecessary exposure.

---

## Page 6 - Endpoint DLP and Device Movement

### Audience

Endpoint security, SOC, security engineering.

### Page Objective

Show when data moves from governed cloud locations to endpoints, printers, USB, or network shares.

### Layout

```text
[Header: Endpoint DLP and Device Movement]

[KPI: Endpoint DLP Events] [KPI: File Printed] [KPI: USB Copy] [KPI: Network Share Copy] [KPI: Risky Devices]

[Stacked Bar: Endpoint Actions by Type]
[Bar Chart: Devices by Risk Events]

[Line Chart: Endpoint DLP Trend]
[Table: Sensitive Endpoint Movement]
```

### What This Means Text

Suggested wording:

> Endpoint telemetry gives the risk story physical weight. Data is no longer only being viewed in SharePoint or Teams; it may be printed, copied, or moved into less governed locations.

### Presenter Notes

Use this page to explain why cloud DLP and endpoint DLP complement each other.

---

## Page 7 - Insider Risk Overview

### Audience

Security leadership, insider risk analysts, HR, Legal, privacy stakeholders.

### Page Objective

Show correlated risky behavior sequences while preserving context and avoiding unsupported conclusions about intent.

### Layout

```text
[Header: Insider Risk Overview]

[KPI: Active Risk Sequences] [KPI: Mass Downloads] [KPI: Endpoint Movement] [KPI: HR Context Events]

[Matrix: Signal Combination by User]
[Bar Chart: Risk Sequences by User]

[Timeline: Selected User Timeline]
[Table: Cases Requiring Review]

[Text Box: Investigation Context]
```

### Investigation Context Text

Suggested wording:

> A risk sequence is not proof of malicious intent. It is a signal that multiple activities, timing, data sensitivity, and business context should be reviewed together.

### Presenter Notes

Use Devon Reyes as the main teaching persona. Describe him as ambiguous: rushed, sometimes careless, sometimes policy-confused, and occasionally risky enough to trigger a structured review.

---

## Page 8 - Scenario Replay and Timeline

### Audience

Demo presenters, SOC analysts, solution architects, workshop attendees.

### Page Objective

Replay a selected scenario chronologically and explain the end-to-end story.

### Layout

```text
[Header: Scenario Replay]

[Slicer: Scenario]
[Slicer: Persona]
[Slicer: Workload]

[Timeline Visual: Event Sequence]
[Table: Event Details]

[Bar/Ribbon Chart: Signals by Workload Over Time]
[Text Box: Scenario Narrative]
[Text Box: Recommended Response]
```

### Scenario Narrative Pattern

Use this structure:

```text
Business Context:
Why the user was working with this data.

Risk Trigger:
What changed or went wrong.

Controls Activated:
Which Microsoft 365, Purview, Defender, or endpoint signals appeared.

Investigation Outcome:
What the organization should do next.
```

### Presenter Notes

This is the strongest storytelling page. Use it to connect business reality to telemetry evidence.

---

## Drillthrough Page - User Investigation

### Target Filters

- `UserPrincipalName`
- `ScenarioId`
- `CorrelationId`

### Recommended Layout

```text
[Header: User Investigation]

[User Card: Persona, Role, Department]
[KPI: Risk Events] [KPI: Max Risk Score] [KPI: Sensitive Files] [KPI: External Events]

[Timeline: User Event Sequence]
[Table: Files Accessed or Shared]
[Table: AI Interactions]
[Table: Endpoint Actions]
[Table: DLP Events]

[Text Box: Recommended Review Questions]
```

### Recommended Review Questions

- Was the activity part of an assigned business process?
- Was the content properly labeled?
- Was external sharing approved?
- Did the user receive and override a warning?
- Did data move to endpoint, USB, printer, or network share?
- Is HR or Legal context relevant?

---

## Drillthrough Page - Sensitive File

### Target Filters

- `FileName`
- `FileKey`
- `SensitivityLabel`

### Recommended Layout

```text
[Header: Sensitive File Investigation]

[File Card: File Name, Label, Owner, Site]
[KPI: Event Count] [KPI: Users] [KPI: External Shares] [KPI: Endpoint Movement]

[Timeline: File Lifecycle]
[Table: Users Who Accessed File]
[Table: Sharing History]
[Table: Label History]
[Table: DLP Matches]
```

### Presenter Notes

Use this page to show how a single file can travel through multiple workloads and trigger different types of controls.

---

## Tooltip Standards

Use consistent tooltip sections:

```text
Definition:
Short description of the metric or event.

Why it matters:
Business or governance impact.

Example:
Synthetic example from the banking demo pack.

Recommended action:
What an analyst, data owner, or security leader should do.
```

Example tooltip for `DLP Override`:

```text
Definition:
A user continued after receiving a DLP warning.

Why it matters:
Overrides may be legitimate, but they need review when sensitive data or external recipients are involved.

Example:
Devon justified an external send as urgent vendor review.

Recommended action:
Review justification, file sensitivity, recipient, and whether a sanitized version existed.
```

---

## Visual Interaction Rules

Recommended cross-filter behavior:

| Selecting | Should Filter |
|---|---|
| Department | Users, scenarios, workloads, files, risk events |
| User | timelines, files, AI prompts, DLP events, endpoint activity |
| Scenario | timeline, involved personas, files, controls, response |
| File | users, sharing, labels, DLP, endpoint movement |
| Workload | operations, scenarios, users, risk categories |
| Sensitivity Label | files, sharing events, AI references, DLP events |

Avoid interactions that make executive pages visually unstable. Prefer drillthrough for deep investigation.

---

## Recommended Color Semantics

Use consistent semantic coloring if the report theme supports it:

```text
Low = calm / neutral
Medium = attention
High = risk
Critical = urgent
Informational = muted
```

Do not rely only on color. Include labels, tooltips, and legends.

---

## Page-Level Storytelling Pattern

For each page, use a small narrative box with this structure:

```text
What this page shows:
One-sentence explanation.

Why it matters:
Business impact.

What to review next:
Suggested drillthrough or next page.
```

Example:

```text
What this page shows:
This page shows where sensitive banking data moved across Microsoft 365 workloads.

Why it matters:
Sensitive files that are downloaded, shared externally, or referenced by AI may require stronger governance.

What to review next:
Drill through to a sensitive file or user timeline.
```

---

## Recommended Presenter Flow

### Five-Minute Executive Demo

1. Executive Risk Snapshot
2. Sensitive Data Exposure
3. AI and Copilot Risk
4. Scenario Replay

Core message:

> One control is not enough. Risk emerges from the interaction between data, identity, collaboration, AI, endpoint movement, and human behavior.

---

### Fifteen-Minute Security Demo

1. Executive Risk Snapshot
2. DLP Operations
3. External Sharing Heatmap
4. Endpoint DLP and Device Movement
5. Insider Risk Overview
6. Scenario Replay

Core message:

> Microsoft 365 E5 telemetry becomes powerful when correlated across workloads and interpreted with business context.

---

### Thirty-Minute Workshop Demo

1. Executive Risk Snapshot
2. Sensitive Data Exposure
3. AI and Copilot Risk
4. DLP Operations
5. External Sharing Heatmap
6. Endpoint DLP and Device Movement
7. Insider Risk Overview
8. Scenario Replay
9. User Investigation Drillthrough
10. Sensitive File Drillthrough

Core message:

> The demo lab shows why data security, AI readiness, DLP, endpoint governance, and insider-risk investigation must be designed as an integrated operating model.

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate Power BI report specifications.
2. Create page-level documentation.
3. Generate tooltip text.
4. Create presenter notes.
5. Map visuals to measures from `powerbi-dax-measures-library.md`.
6. Align report navigation with `powerbi-risk-dashboard-definitions.json`.
7. Keep executive pages concise and analyst pages detailed.
8. Preserve synthetic-only language throughout the report.

---

## Safety Reminder

This reporting guide is intended for synthetic demo telemetry only.

Do not use the suggested insider-risk, HR, legal, endpoint, or AI views to evaluate real employees or real cases without appropriate governance, privacy, compliance, and legal review.
