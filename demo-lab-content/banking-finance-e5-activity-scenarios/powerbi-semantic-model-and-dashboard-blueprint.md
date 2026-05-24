# Power BI Semantic Model and Dashboard Blueprint

## Purpose

This document defines the Power BI semantic model, dashboard blueprint, relationship strategy, page structure, slicer design, drillthrough model, tooltip approach, performance guidance, and replay visualization strategy for the synthetic Microsoft 365 E5 / Microsoft Purview banking simulation platform.

It complements:

- `powerbi-risk-dashboard-definitions.json`
- `powerbi-dax-measures-library.md`
- `powerbi-visual-layout-and-storytelling-guide.md`
- `adx-ingestion-and-table-mappings.md`
- `sample-synthetic-telemetry-dataset-specification.md`

All data visualized by this model must remain synthetic and fictional.

---

## Recommended Semantic Model Strategy

Use a star-schema model centered on a single normalized telemetry fact table.

Recommended model pattern:

```text
DimDate
DimUser
DimScenario
DimSignal
DimFile
DimWorkload
DimDepartment
DimSensitivityLabel
        ↓
FactActivityEvents
```

The model should support both:

- executive summary dashboards
- analyst drillthrough and scenario replay

---

## Fact Table

## `FactActivityEvents`

Source:

```text
SyntheticM365ActivityEvents
```

or CSV export:

```text
banking-finance-e5-mvp-synthetic-telemetry-1000.csv
```

### Required Columns

```text
EventId
TimeGenerated
Date
ScenarioId
CorrelationId
UserPrincipalName
PersonaName
UserRole
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
FileType
FilePath
SiteUrl
LibraryName
FileOwner
SensitivityLabel
PreviousSensitivityLabel
Recipient
TargetDomain
DeviceId
DeviceName
AppName
PolicyName
RuleName
DlpAction
OverrideJustification
AdditionalPropertiesJson
```

### Fact Table Notes

- `EventId` should be unique.
- `TimeGenerated` should be used for time-series analysis.
- `Date` should be derived from `TimeGenerated`.
- `CorrelationId` supports timeline reconstruction.
- `ScenarioId` supports replay filtering.
- `IsSynthetic` should always be true.

---

## Dimension Tables

## `DimDate`

Required columns:

```text
Date
Year
Quarter
Month Number
Month Name
Year Month
Week Number
Week Start (Mon)
Day Name
Day of Week Number
Is Weekend
Is Closed Week
```

Notes:

- `Week Start (Mon)` is required for closed-week logic.
- `Is Closed Week` should exclude the current incomplete week.

---

## `DimUser`

Required columns:

```text
UserPrincipalName
PersonaName
UserRole
Department
ManagerPersona
PersonaType
IsRiskAnchor
IsExecutive
IsSecurityRole
IsHRRole
IsLegalRole
Timezone
```

Recommended `PersonaType` values:

```text
Executive
Security
Operations
Analytics
Legal
HR
Finance
PMO
Support
Engineering
```

---

## `DimScenario`

Required columns:

```text
ScenarioId
ScenarioTitle
ScenarioType
PrimaryPersona
PrimaryDepartment
RiskTheme
ExpectedSeverity
Cadence
IsBaseline
IsReplayScenario
```

Recommended `ScenarioType` values:

```text
Baseline
AI Governance
DLP
Endpoint DLP
External Sharing
Insider Risk
Identity
Legal / HR
Executive Reporting
```

---

## `DimSignal`

Required columns:

```text
Operation
SignalCategory
DefaultSeverity
DefaultRiskWeight
Workload
Description
RecommendedResponse
```

Notes:

- Use `Operation` as relationship key to `FactActivityEvents`.
- `DimSignal` should align with `synthetic-telemetry-schema.json` and `purview-signal-correlation.json`.

---

## `DimFile`

Required columns:

```text
FileKey
FileName
FileType
FilePath
SiteUrl
LibraryName
FileOwner
SensitivityLabel
DataDomain
IsSensitive
IsRegulatedFinancialData
IsHRRestricted
IsLegalPrivileged
```

Recommended `FileKey`:

```DAX
FileKey =
LOWER (
    TRIM (
        COALESCE (
            'FactActivityEvents'[FilePath],
            'FactActivityEvents'[SiteUrl] & "|" & 'FactActivityEvents'[FileName]
        )
    )
)
```

---

## `DimWorkload`

Required columns:

```text
Workload
WorkloadGroup
Microsoft365Area
IsPurviewSignal
IsDefenderSignal
IsAIWorkload
```

Examples:

```text
SharePoint Online
OneDrive for Business
Microsoft Teams
Exchange Online
Microsoft Copilot
External AI App
Microsoft Purview DLP
Endpoint DLP
Entra ID / Identity
Power BI
```

---

## `DimSensitivityLabel`

Required columns:

```text
SensitivityLabel
LabelRank
LabelFamily
IsSensitive
IsHighlyConfidential
IsRegulated
RecommendedHandling
```

Suggested rank:

```text
0 = Public
1 = Internal
2 = Confidential
3 = Highly Confidential
4 = Highly Confidential - Regulated Financial Data
5 = Highly Confidential - HR Restricted
6 = Highly Confidential - Legal Privileged
```

---

## Relationships

Recommended relationships:

```text
FactActivityEvents[Date] -> DimDate[Date]
FactActivityEvents[UserPrincipalName] -> DimUser[UserPrincipalName]
FactActivityEvents[ScenarioId] -> DimScenario[ScenarioId]
FactActivityEvents[Operation] -> DimSignal[Operation]
FactActivityEvents[FileKey] -> DimFile[FileKey]
FactActivityEvents[Workload] -> DimWorkload[Workload]
FactActivityEvents[Department] -> DimDepartment[Department]
FactActivityEvents[SensitivityLabel] -> DimSensitivityLabel[SensitivityLabel]
```

Relationship direction:

```text
Single-direction from dimensions to fact
```

Avoid bidirectional relationships unless a specific drillthrough scenario requires it.

---

## Calculated Columns

## FactActivityEvents[Date]

```DAX
Date = DATEVALUE ( 'FactActivityEvents'[TimeGenerated] )
```

## FactActivityEvents[FileKey]

```DAX
FileKey =
LOWER (
    TRIM (
        COALESCE (
            'FactActivityEvents'[FilePath],
            'FactActivityEvents'[SiteUrl] & "|" & 'FactActivityEvents'[FileName]
        )
    )
)
```

## FactActivityEvents[RiskBand]

```DAX
RiskBand =
SWITCH (
    TRUE (),
    'FactActivityEvents'[RiskScore] >= 80, "Critical",
    'FactActivityEvents'[RiskScore] >= 50, "High",
    'FactActivityEvents'[RiskScore] >= 25, "Medium",
    "Low"
)
```

## FactActivityEvents[IsExternal]

```DAX
IsExternal =
NOT ISBLANK ( 'FactActivityEvents'[TargetDomain] )
    && 'FactActivityEvents'[TargetDomain] <> "mhdemos.com"
```

---

## Core Measure Groups

Use measure folders or naming prefixes:

```text
00 - Base
01 - Risk
02 - DLP
03 - AI Governance
04 - Endpoint
05 - External Sharing
06 - Insider Risk
07 - Scenario Replay
08 - Label Governance
09 - Trends
10 - Narrative Measures
```

Reference measure definitions from:

```text
powerbi-dax-measures-library.md
```

---

## Dashboard Page Blueprint

## Page 1 - Executive Risk Snapshot

Purpose:

Show leadership-level posture.

Recommended visuals:

```text
KPI cards: Total Events, Risk Events, High/Critical, Sensitive AI Events, External Sharing Events
Line chart: Risk Events over Time
Stacked bar: Risk Events by Department
Bar chart: Risk Events by Workload
Table: Top Scenarios by Risk Score
Narrative text: Executive Risk Narrative
```

Slicers:

```text
Date
Department
ScenarioType
Severity
```

---

## Page 2 - Sensitive Data Exposure

Purpose:

Show which files and labels drive sensitive exposure.

Recommended visuals:

```text
KPI cards: Distinct Sensitive Files, Sensitive External Sharing Events, Label Governance Risk Events
Matrix: Sensitivity Label x Workload
Bar chart: Top Sensitive Files by Risk Events
Treemap: Sensitive Events by Department
Table: Files Requiring Review
```

Slicers:

```text
SensitivityLabel
DataDomain
Department
Workload
```

---

## Page 3 - AI and Copilot Risk

Purpose:

Show Copilot and external AI risk posture.

Recommended visuals:

```text
KPI cards: Copilot Interactions, External AI Interactions, Unmanaged AI Uploads, Sensitive AI Events
Bar chart: AI Events by Persona
Table: Prompt Samples
Table: Source Files Referenced by AI
Narrative text: AI Governance Narrative
```

Slicers:

```text
AppName
PersonaName
SensitivityLabel
AI interaction type
```

---

## Page 4 - DLP Operations

Purpose:

Show DLP matches, warnings, blocks, and overrides.

Recommended visuals:

```text
KPI cards: DLP Matches, DLP Warnings, DLP Blocks, DLP Overrides, Override Rate
Stacked column: DLP Events by Action
Bar chart: Top DLP Policies
Table: Overrides Requiring Review
```

Slicers:

```text
PolicyName
DlpAction
Department
SensitivityLabel
```

---

## Page 5 - Scenario Replay and Timeline

Purpose:

Show chronological scenario evidence.

Recommended visuals:

```text
Timeline table: TimeGenerated, PersonaName, Operation, FileName, RiskScore, BusinessContext
Line or ribbon chart: Risk Score over Timeline
Bar chart: Operations by Workload
Text card: Scenario Narrative
Text card: Recommended Response
```

Required slicers:

```text
ScenarioId
CorrelationId
PersonaName
```

Recommended default scenario:

```text
BF-SCEN-0030
```

---

## Page 6 - SOC Investigation View

Purpose:

Analyst-focused evidence reconstruction.

Recommended visuals:

```text
KPI cards: Max Risk Score, Endpoint Movement Events, DLP Overrides, External AI Interactions
Timeline visual/table
Table: Files Accessed
Table: DLP Events
Table: AI Events
Table: Endpoint Events
```

Drillthrough fields:

```text
UserPrincipalName
ScenarioId
CorrelationId
FileKey
```

---

## Page 7 - Endpoint DLP and Device Movement

Purpose:

Show movement from cloud to endpoint.

Recommended visuals:

```text
KPI cards: File Printed Events, Network Share Copy Events, USB Copy Events, Distinct Risky Devices
Bar chart: Endpoint Actions by User
Table: Sensitive Endpoint Movement
Line chart: Endpoint Movement over Time
```

---

## Page 8 - Label Governance

Purpose:

Show label application, changes, removals, and downgrades.

Recommended visuals:

```text
KPI cards: Label Applied, Label Changed, Label Removed, Label Downgrade
Table: Label Changes by File
Bar chart: Label Events by Department
Matrix: Previous Label to Final Label
```

---

## Drillthrough Pages

## User Investigation Drillthrough

Filters:

```text
UserPrincipalName
ScenarioId
CorrelationId
```

Visuals:

```text
User profile card
Risk events timeline
Files accessed/shared
AI interactions
DLP events
Endpoint events
Recommended review questions
```

---

## File Investigation Drillthrough

Filters:

```text
FileKey
FileName
SensitivityLabel
```

Visuals:

```text
File profile card
File lifecycle timeline
Users who accessed file
Sharing history
Label history
DLP matches
Endpoint movement
```

---

## Tooltip Strategy

Tooltip pages should follow this structure:

```text
Definition
Why it matters
Synthetic example
Recommended action
```

Example for DLP Override:

```text
Definition:
A user continued after a DLP warning.

Why it matters:
Overrides may be legitimate, but should be reviewed when sensitive data or external recipients are involved.

Synthetic example:
Devon overrides a warning while sending a vendor evidence package.

Recommended action:
Review justification, file label, recipient, and whether a sanitized version existed.
```

---

## Slicer Strategy

Global slicers:

```text
Date
Department
ScenarioType
Severity
Workload
```

Page-specific slicers:

```text
ScenarioId
PersonaName
SensitivityLabel
PolicyName
AppName
DlpAction
TargetDomain
```

Avoid too many slicers on executive pages. Use drillthrough for deeper analysis.

---

## Bookmark and Navigation Design

Recommended navigation buttons:

```text
Executive View
AI Governance
DLP Operations
Scenario Replay
SOC Investigation
File Investigation
```

Recommended bookmarks:

```text
Default Executive View
Devon Risk Chain Replay
AML External AI Replay
Label Downgrade Replay
Clean Baseline View
High/Critical Only
```

---

## Risk Visual Semantics

Use consistent semantic categories:

```text
Low = normal or minimal concern
Medium = review when context supports it
High = investigation or remediation likely required
Critical = immediate structured review required
```

Do not rely only on color. Include severity labels, legends, and tooltips.

---

## Replay Visualization Model

The scenario replay should support this mental model:

```text
Who acted?
        ↓
What content was involved?
        ↓
Where did it move?
        ↓
Which control responded?
        ↓
What happened next?
```

Recommended columns for replay table:

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

---

## Performance Optimization

For MVP:

- import mode is acceptable
- 1,000 events should perform easily
- calculated columns are acceptable

For larger datasets:

- use ADX aggregation
- avoid loading large prompt text in primary fact table
- move prompt text to detail table if needed
- reduce cardinality of `AdditionalPropertiesJson`
- use materialized views for executive pages
- avoid bidirectional relationships
- avoid complex row-by-row DAX on large fact tables

---

## Data Quality Checks in Power BI

Recommended validation cards:

```text
Events with Missing ScenarioId
Events with Missing User
Events with Missing Operation
Events where IsSynthetic is false
Events with RiskScore outside range
Events with Unknown SensitivityLabel
```

These should be hidden in production-style demos but available on a maintenance page.

---

## Minimum MVP Report Build

For the first working version, build only:

1. Executive Risk Snapshot
2. AI and Copilot Risk
3. DLP Operations
4. Scenario Replay and Timeline

Then add:

5. SOC Investigation View
6. Endpoint DLP
7. Sensitive Data Exposure
8. Label Governance

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate a Power BI model specification.
2. Create semantic model documentation.
3. Generate DAX measure groups.
4. Create dashboard layout instructions.
5. Create drillthrough page specs.
6. Create tooltip definitions.
7. Validate Power BI compatibility with generated datasets.
8. Preserve closed-week logic using `Week Start (Mon)`.
9. Keep executive pages simple and analyst pages detailed.
10. Preserve synthetic-only boundaries.

---

## Safety Reminder

This semantic model is for synthetic telemetry only.

Do not use this model to evaluate real employees, real customers, real financial transactions, real HR data, real legal matters, or real insider-risk cases without formal governance, privacy, HR, legal, and compliance review.
