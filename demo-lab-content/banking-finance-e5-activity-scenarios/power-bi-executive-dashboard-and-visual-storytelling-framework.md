# Power BI Executive Dashboard and Visual Storytelling Framework

## Purpose

This document defines the executive analytics and visual-storytelling framework for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It explains how Power BI should present synthetic Microsoft 365 governance telemetry to executive, security leadership, SOC, compliance, and workshop audiences.

It covers:

- executive dashboard structure
- KPI strategy
- visual storytelling rules
- page sequencing
- cross-filter behavior
- DLP visual patterns
- AI governance visualizations
- SOC drilldowns
- tooltip philosophy
- anomaly highlighting
- closed-week logic
- replay-aware filtering
- board-level metrics
- operational metrics
- Power BI UX standards
- semantic storytelling patterns

All data, users, files, incidents, customers, accounts, identifiers, and telemetry shown in dashboards must remain fictional and synthetic.

---

## Core Visual Storytelling Thesis

> A dashboard should not only show risk counts. It should help the audience understand how sensitive data moved, why the sequence matters, which controls responded, and what the organization should do next.

A strong executive dashboard answers:

```text
What happened?
Why does it matter?
Where is the concentration of risk?
Which controls responded?
What action should leadership support?
```

---

## Dashboard Audience Modes

## Executive Mode

Audience:

- CEO
- CIO
- CISO
- board members
- risk committee

Design style:

- simple pages
- few slicers
- high-level KPIs
- strong narrative cards
- no raw event tables on first page

Primary question:

> Are we governing sensitive data and AI usage well enough to reduce business risk?

---

## Security Leadership Mode

Audience:

- CISO office
- compliance operations
- data protection owners

Design style:

- KPIs plus trend analysis
- department and workload breakdowns
- policy outcomes
- scenario drillthrough

Primary question:

> Where should we prioritize governance, remediation, and control tuning?

---

## SOC Analyst Mode

Audience:

- SOC analysts
- incident responders
- insider-risk reviewers

Design style:

- timeline tables
- event details
- CorrelationId filters
- KQL-backed extracts
- evidence-oriented drillthrough

Primary question:

> What is the sequence of evidence and what should we do next?

---

## Recommended Page Sequence

Recommended executive-to-technical flow:

```text
1. Executive Risk Snapshot
2. Sensitive Data Exposure
3. AI and Copilot Risk
4. DLP Operations
5. External Sharing and Collaboration Risk
6. Endpoint DLP and Device Movement
7. Scenario Replay and Timeline
8. SOC Investigation Drillthrough
9. File Investigation Drillthrough
10. Data Quality and Model Health
```

For short executive demos, use only:

```text
Executive Risk Snapshot
AI and Copilot Risk
Scenario Replay and Timeline
Executive Roadmap
```

---

## Page 1 - Executive Risk Snapshot

## Purpose

Create immediate business-level understanding.

## Recommended Layout

```text
Top row: KPI cards
Middle left: Risk events over time
Middle right: Risk by department
Bottom left: Risk by workload
Bottom right: Top scenarios requiring attention
Narrative overlay: Executive takeaway
```

## Recommended KPIs

```text
Total Events
Risk Events
High or Critical Events
Sensitive AI Events
External Sharing Events
Endpoint Movement Events
Distinct Risky Users
Open Synthetic Cases
```

## Narrative Card Example

```text
Synthetic replay shows that most activity is normal business collaboration. The highest-risk sequence combines sensitive file access, external AI usage, DLP override, and endpoint movement.
```

---

## Page 2 - Sensitive Data Exposure

## Purpose

Show which data domains and labels create exposure.

## Recommended Visuals

```text
Matrix: Sensitivity Label by Workload
Bar chart: Top sensitive files by risk events
Treemap: Sensitive events by department
Table: Files requiring review
KPI cards: distinct sensitive files, overexposed files, unlabeled sensitive files
```

## Storytelling Message

> Data cannot be protected consistently if the organization does not know where it lives, how it is labeled, and who can reach it.

---

## Page 3 - AI and Copilot Risk

## Purpose

Contrast governed Copilot usage with unmanaged external AI risk.

## Recommended Visuals

```text
KPI cards: Copilot Interactions, External AI Interactions, Unmanaged AI Uploads, Sensitive AI Events
Bar chart: AI risk by department
Table: Prompt samples requiring review
Table: Source files referenced by AI
Timeline: Sensitive file access followed by AI usage
```

## Safe vs Unsafe Visual Pattern

Create two side-by-side visual panels:

```text
Safe AI Path
Approved Source → Copilot → Reviewed Output

Unsafe AI Path
Raw Sensitive File → External AI → DLP Signal
```

## Storytelling Message

> Safe AI adoption starts before the prompt. It starts with source data governance.

---

## Page 4 - DLP Operations

## Purpose

Show DLP as a governance and coaching mechanism.

## Recommended Visuals

```text
KPI cards: DLP Matches, Warnings, Blocks, Overrides, Override Rate
Stacked bar: DLP action by policy
Table: Overrides requiring review
Line chart: DLP events over time
Matrix: DLP action by sensitivity label
```

## Storytelling Message

> A DLP override is not automatically malicious. It is a decision point that should be reviewed in context.

---

## Page 5 - External Sharing and Collaboration Risk

## Purpose

Show where sensitive content crosses organizational boundaries.

## Recommended Visuals

```text
KPI cards: External Shares, External Emails, Guest Users Added, Sensitive External Events
Bar chart: External events by target domain
Table: External sharing by file and label
Matrix: Department by external recipient type
```

## Storytelling Message

> External collaboration should happen through approved, sanitized, named-user workflows rather than ad hoc sharing paths.

---

## Page 6 - Endpoint DLP and Device Movement

## Purpose

Show data movement from cloud collaboration into endpoint or local contexts.

## Recommended Visuals

```text
KPI cards: File Printed, Network Share Copy, USB Copy, Endpoint DLP Matches
Bar chart: Endpoint actions by persona
Table: Sensitive endpoint movement
Timeline: Download to endpoint movement sequence
```

## Storytelling Message

> Endpoint movement changes the risk model because sensitive data leaves a purely cloud-governed collaboration path.

---

## Page 7 - Scenario Replay and Timeline

## Purpose

Convert events into a human-understandable story.

## Required Filters

```text
ScenarioId
CorrelationId
PersonaName
ReplayId
```

## Recommended Visuals

```text
Timeline table: event sequence
Line chart: risk score over time
Cards: first event, last event, max risk score, affected files
Narrative card: what this scenario means
Response card: recommended next action
```

## Timeline Table Columns

```text
TimeGenerated
PersonaName
Department
Workload
Operation
FileName
SensitivityLabel
Recipient
TargetDomain
RiskScore
BusinessContext
```

## Storytelling Message

> Sequence creates meaning. The individual events matter less than how they connect.

---

## Page 8 - SOC Investigation Drillthrough

## Purpose

Support analyst-level evidence review.

## Recommended Visuals

```text
User profile card
Risk event timeline
Files accessed
AI interactions
DLP events
Endpoint events
External sharing events
Recommended investigation questions
```

## Drillthrough Fields

```text
UserPrincipalName
ScenarioId
CorrelationId
ReplayId
```

---

## Page 9 - File Investigation Drillthrough

## Purpose

Show file-centric lifecycle and exposure.

## Recommended Visuals

```text
File profile card
File access timeline
Label history
Sharing history
AI usage references
Endpoint movement
DLP events
```

## Drillthrough Fields

```text
FileKey
FileName
SensitivityLabel
ScenarioId
```

---

## Page 10 - Data Quality and Model Health

## Purpose

Validate synthetic dataset quality and model readiness.

## Recommended Visuals

```text
Events with missing ScenarioId
Events with missing Operation
Events with invalid RiskScore
Events where IsSynthetic is false
Unknown sensitivity labels
Unknown personas
Refresh status
Dataset version
Replay version
```

This page should be hidden during executive demos but available for maintainers.

---

## KPI Strategy

KPIs should be divided into three groups.

## Business Risk KPIs

```text
High or Critical Events
Sensitive External Sharing Events
Sensitive AI Events
Endpoint Movement Events
Distinct Risky Users
Open Synthetic Cases
```

## Control Effectiveness KPIs

```text
DLP Blocks
DLP Warnings
DLP Overrides
Override Rate
Label Coverage
Label Downgrades
Sanitized Packages Created
```

## Operational Maturity KPIs

```text
Time to Triage
Cases Closed as Coaching
Cases Closed as Remediated
Policy Tuning Items
Access Review Items
AI Governance Review Items
```

---

## Closed-Week Logic

Use closed-week logic for trend pages to avoid misleading partial-period drops.

Required date column:

```text
DimDate[Week Start (Mon)]
```

Recommended logic:

```text
Closed Week = a week whose end date is before the current date's week start
```

Use closed-week filtering for:

- weekly DLP trends
- weekly AI risk trends
- weekly external sharing trends
- weekly endpoint movement trends

Do not use closed-week logic for replay timelines, because replay scenarios may intentionally occur inside a simulated current week.

---

## Replay-Aware Filtering

Recommended replay filters:

```text
ReplayId
ScenarioId
CorrelationId
PersonaName
```

Replay pages should allow:

- full replay view
- single persona view
- single file view
- high/critical only view
- control-specific view

Recommended bookmarks:

```text
Default Replay View
Devon Multi-Day Chain
AML External AI Shortcut
Label Downgrade Before Sharing
High/Critical Events Only
Executive Summary View
```

---

## Cross-Filter Behavior

Recommended behavior:

- executive cards should respond to date, department, scenario, and severity filters
- replay timeline should respond to ScenarioId and CorrelationId
- prompt tables should respond to AI app and sensitivity label filters
- file drillthrough should preserve FileKey
- user drillthrough should preserve UserPrincipalName

Avoid excessive cross-filtering between unrelated visual groups on executive pages.

---

## Tooltip Philosophy

Every important metric should have an explanatory tooltip.

Tooltip structure:

```text
Definition
Why it matters
Synthetic example
Recommended action
```

Example: Sensitive AI Events

```text
Definition:
AI interactions linked to sensitive or highly confidential source content.

Why it matters:
AI may accelerate discovery, summarization, and reuse of sensitive data.

Synthetic example:
Devon uses an unmanaged AI app after downloading an AML workbook.

Recommended action:
Review source permissions, app governance, and approved AI workflow.
```

---

## Anomaly Highlighting

Highlight anomalies such as:

```text
DLP override after warning
Label downgrade before external sharing
External AI after sensitive file access
Endpoint movement after download
Guest access to sensitive workspace
Risky sign-in before sensitive download
HR context plus mass download
```

Avoid labeling anomalies as malicious by default.

Preferred wording:

```text
Requires review
Needs context
Potential exposure path
Policy decision point
```

---

## Executive Narrative Overlays

Use narrative cards to explain what visuals mean.

Recommended overlay types:

```text
What this means
Why this matters
Recommended next action
Control response
Business interpretation
```

Example:

```text
What this means:
Most synthetic activity is normal collaboration, but the highest-risk sequence combines sensitive access, unmanaged AI, DLP override, and endpoint movement.
```

---

## Power BI UX Standards

Recommended standards:

- use consistent page headers
- keep executive pages visually simple
- avoid raw telemetry tables on first page
- use drillthrough for details
- use bookmarks for demo paths
- avoid too many slicers
- include synthetic-data disclaimer
- maintain consistent KPI card naming
- keep color semantics consistent
- show severity labels, not only colors

---

## Board-Level Metrics

Recommended board-level metrics:

```text
Sensitive Data Exposure Trend
External Sharing Risk Trend
AI Governance Risk Trend
DLP Override Rate
Endpoint Movement Trend
Label Coverage
Top Risk Themes
Remediation Progress
```

Board-level metrics should avoid unnecessary technical detail.

---

## SOC-Level Metrics

Recommended SOC-level metrics:

```text
Incidents by Scenario
Events by CorrelationId
DLP Overrides Requiring Review
External AI After Sensitive Access
Endpoint Movement After Download
Label Downgrade Before Sharing
Users with Multi-Stage Risk Chains
Cases by Closure Outcome
```

---

## Visual Anti-Patterns

Avoid:

- too many visuals on one page
- unclear metric names
- red-only dashboards that imply panic
- dense raw event tables for executives
- unfiltered prompt text on executive pages
- ambiguous synthetic vs production language
- unsupported malicious-intent labels
- trend charts with incomplete weeks unless intentionally showing replay

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate Power BI page specifications.
2. Create dashboard build instructions.
3. Generate tooltip definitions.
4. Build executive narrative cards.
5. Create replay-aware filter logic.
6. Generate KPI documentation.
7. Preserve closed-week logic using `Week Start (Mon)`.
8. Avoid overcomplicated executive pages.
9. Preserve neutral risk language.
10. Preserve synthetic-only boundaries.

---

## Safety Reminder

This dashboard framework is for synthetic telemetry only.

Do not use it to evaluate, monitor, investigate, discipline, score, or profile real employees, customers, HR records, legal matters, financial transactions, or production incidents without formal legal, privacy, HR, compliance, and governance approval.
