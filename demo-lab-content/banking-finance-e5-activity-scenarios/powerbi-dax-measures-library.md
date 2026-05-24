# Power BI DAX Measures Library - Banking / Finance Microsoft 365 E5 Simulation Pack

## Purpose

This file provides reusable DAX measure concepts for the synthetic Microsoft 365 E5 / Microsoft Purview banking simulation pack.

The measures are designed for Power BI reports built from the normalized telemetry model described in:

- `synthetic-telemetry-schema.json`
- `powerbi-risk-dashboard-definitions.json`
- `adx-ingestion-and-table-mappings.md`

The primary fact table assumed in this document is:

```DAX
FactActivityEvents
```

Recommended dimensions:

```text
DimDate
DimUser
DimScenario
DimSignal
DimFile
DimSensitivityLabel
DimWorkload
DimDepartment
```

All metrics are synthetic and demo-oriented. They should not be used as production risk scoring without additional validation, privacy review, legal review, and governance controls.

---

## Base Measures

### Total Events

```DAX
Total Events =
COUNTROWS ( 'FactActivityEvents' )
```

### Risk Events

```DAX
Risk Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[IsRiskEvent] = TRUE ()
)
```

### Non-Risk Events

```DAX
Non-Risk Events =
[Total Events] - [Risk Events]
```

### Distinct Users

```DAX
Distinct Users =
DISTINCTCOUNT ( 'FactActivityEvents'[UserPrincipalName] )
```

### Distinct Risky Users

```DAX
Distinct Risky Users =
CALCULATE (
    DISTINCTCOUNT ( 'FactActivityEvents'[UserPrincipalName] ),
    'FactActivityEvents'[IsRiskEvent] = TRUE ()
)
```

### Distinct Files

```DAX
Distinct Files =
DISTINCTCOUNT ( 'FactActivityEvents'[FileName] )
```

### Distinct Sensitive Files

```DAX
Distinct Sensitive Files =
CALCULATE (
    DISTINCTCOUNT ( 'FactActivityEvents'[FileName] ),
    NOT ISBLANK ( 'FactActivityEvents'[SensitivityLabel] ),
    'FactActivityEvents'[SensitivityLabel] <> "Public"
)
```

---

## Severity Measures

### High Events

```DAX
High Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Severity] = "High"
)
```

### Critical Events

```DAX
Critical Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Severity] = "Critical"
)
```

### High or Critical Events

```DAX
High or Critical Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Severity] IN { "High", "Critical" }
)
```

### High Critical Rate

```DAX
High Critical Rate =
DIVIDE ( [High or Critical Events], [Total Events] )
```

---

## Risk Score Measures

### Total Risk Score

```DAX
Total Risk Score =
SUM ( 'FactActivityEvents'[RiskScore] )
```

### Average Risk Score

```DAX
Average Risk Score =
AVERAGE ( 'FactActivityEvents'[RiskScore] )
```

### Max Risk Score

```DAX
Max Risk Score =
MAX ( 'FactActivityEvents'[RiskScore] )
```

### Composite User Risk Score

```DAX
Composite User Risk Score =
SUMX (
    'FactActivityEvents',
    'FactActivityEvents'[RiskScore]
)
```

### Risk Score per Event

```DAX
Risk Score per Event =
DIVIDE ( [Total Risk Score], [Total Events] )
```

---

## DLP Measures

### DLP Matches

```DAX
DLP Matches =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "DLPPolicyMatch"
)
```

### DLP Warnings

```DAX
DLP Warnings =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "DLPWarned"
)
```

### DLP Blocks

```DAX
DLP Blocks =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "DLPBlocked"
)
```

### DLP Overrides

```DAX
DLP Overrides =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "DLPOverride"
)
```

### DLP Override Rate

```DAX
DLP Override Rate =
DIVIDE ( [DLP Overrides], [DLP Warnings] )
```

### DLP Block Rate

```DAX
DLP Block Rate =
DIVIDE ( [DLP Blocks], [DLP Matches] )
```

### Repeat DLP Users

```DAX
Repeat DLP Users =
COUNTROWS (
    FILTER (
        VALUES ( 'FactActivityEvents'[UserPrincipalName] ),
        CALCULATE ( [DLP Matches] ) >= 3
    )
)
```

---

## External Sharing Measures

### External Email Events

```DAX
External Email Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "ExternalEmailSent"
)
```

### File Shared Events

```DAX
File Shared Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "FileShared"
)
```

### Guest Access Events

```DAX
Guest Access Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] IN { "GuestUserAdded", "ExternalUserAccessed" }
)
```

### External Sharing Events

```DAX
External Sharing Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] IN {
        "ExternalEmailSent",
        "FileShared",
        "GuestUserAdded",
        "ExternalUserAccessed"
    }
)
```

### Sensitive External Sharing Events

```DAX
Sensitive External Sharing Events =
CALCULATE (
    [External Sharing Events],
    NOT ISBLANK ( 'FactActivityEvents'[SensitivityLabel] ),
    'FactActivityEvents'[SensitivityLabel] <> "Public"
)
```

### External Domains

```DAX
External Domains =
DISTINCTCOUNT ( 'FactActivityEvents'[TargetDomain] )
```

---

## AI and Copilot Measures

### Copilot Interactions

```DAX
Copilot Interactions =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "CopilotInteraction"
)
```

### External AI Interactions

```DAX
External AI Interactions =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "AIAppInteraction"
)
```

### Unmanaged AI Uploads

```DAX
Unmanaged AI Uploads =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "UnmanagedAppUpload"
)
```

### Sensitive AI Events

```DAX
Sensitive AI Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] IN {
        "CopilotInteraction",
        "AIAppInteraction",
        "UnmanagedAppUpload",
        "SensitiveContentAccessed",
        "FileReferencedByCopilot"
    },
    'FactActivityEvents'[IsRiskEvent] = TRUE ()
)
```

### AI Risk Rate

```DAX
AI Risk Rate =
DIVIDE ( [Sensitive AI Events], [Copilot Interactions] + [External AI Interactions] )
```

### External AI Share of AI Activity

```DAX
External AI Share of AI Activity =
DIVIDE ( [External AI Interactions], [Copilot Interactions] + [External AI Interactions] )
```

---

## Endpoint DLP Measures

### File Printed Events

```DAX
File Printed Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "FilePrinted"
)
```

### Network Share Copy Events

```DAX
Network Share Copy Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "FileCopiedToNetworkShare"
)
```

### USB Copy Events

```DAX
USB Copy Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "FileCopiedToUSB"
)
```

### Endpoint DLP Events

```DAX
Endpoint DLP Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] IN {
        "EndpointDLPPolicyMatch",
        "FilePrinted",
        "FileCopiedToNetworkShare",
        "FileCopiedToUSB"
    }
)
```

### Endpoint Movement Events

```DAX
Endpoint Movement Events =
[File Printed Events] + [Network Share Copy Events] + [USB Copy Events]
```

### Distinct Risky Devices

```DAX
Distinct Risky Devices =
CALCULATE (
    DISTINCTCOUNT ( 'FactActivityEvents'[DeviceId] ),
    'FactActivityEvents'[Operation] IN {
        "EndpointDLPPolicyMatch",
        "FilePrinted",
        "FileCopiedToNetworkShare",
        "FileCopiedToUSB"
    }
)
```

---

## Insider Risk Measures

### Insider Risk Sequences

```DAX
Insider Risk Sequences =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "InsiderRiskSequence"
)
```

### Mass Download Events

```DAX
Mass Download Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "MassDownloadActivity"
)
```

### HR Context Events

```DAX
HR Context Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "HRSignal"
)
```

### After Hours Sensitive Events

```DAX
After Hours Sensitive Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "AfterHoursSensitiveActivity"
)
```

### Users with Insider Risk Sequence

```DAX
Users with Insider Risk Sequence =
CALCULATE (
    DISTINCTCOUNT ( 'FactActivityEvents'[UserPrincipalName] ),
    'FactActivityEvents'[Operation] = "InsiderRiskSequence"
)
```

### Devon Risk Events

```DAX
Devon Risk Events =
CALCULATE (
    [Risk Events],
    'FactActivityEvents'[UserPrincipalName] = "devon.reyes@mhdemos.com"
)
```

### Devon Composite Risk Score

```DAX
Devon Composite Risk Score =
CALCULATE (
    [Total Risk Score],
    'FactActivityEvents'[UserPrincipalName] = "devon.reyes@mhdemos.com"
)
```

---

## Scenario Replay Measures

### Scenario Events

```DAX
Scenario Events =
[Total Events]
```

### Scenario Risk Events

```DAX
Scenario Risk Events =
[Risk Events]
```

### Scenario Duration Minutes

```DAX
Scenario Duration Minutes =
VAR MinTime = MIN ( 'FactActivityEvents'[TimeGenerated] )
VAR MaxTime = MAX ( 'FactActivityEvents'[TimeGenerated] )
RETURN
DATEDIFF ( MinTime, MaxTime, MINUTE )
```

### Distinct Workloads in Scenario

```DAX
Distinct Workloads in Scenario =
DISTINCTCOUNT ( 'FactActivityEvents'[Workload] )
```

### Distinct Personas in Scenario

```DAX
Distinct Personas in Scenario =
DISTINCTCOUNT ( 'FactActivityEvents'[PersonaName] )
```

### Scenario Max Risk Score

```DAX
Scenario Max Risk Score =
MAX ( 'FactActivityEvents'[RiskScore] )
```

---

## Label Governance Measures

### Label Applied Events

```DAX
Label Applied Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "SensitivityLabelApplied"
)
```

### Label Changed Events

```DAX
Label Changed Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "SensitivityLabelChanged"
)
```

### Label Removed Events

```DAX
Label Removed Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "SensitivityLabelRemoved"
)
```

### Label Downgrade Events

```DAX
Label Downgrade Events =
CALCULATE (
    [Total Events],
    'FactActivityEvents'[Operation] = "LabelDowngrade"
)
```

### Label Governance Risk Events

```DAX
Label Governance Risk Events =
[Label Changed Events] + [Label Removed Events] + [Label Downgrade Events]
```

---

## Trend Measures

### Risk Events Previous Period

```DAX
Risk Events Previous Period =
CALCULATE (
    [Risk Events],
    DATEADD ( 'DimDate'[Date], -1, MONTH )
)
```

### Risk Events MoM Change

```DAX
Risk Events MoM Change =
[Risk Events] - [Risk Events Previous Period]
```

### Risk Events MoM Change %

```DAX
Risk Events MoM Change % =
DIVIDE ( [Risk Events MoM Change], [Risk Events Previous Period] )
```

### Cumulative Risk Events

```DAX
Cumulative Risk Events =
VAR MaxVisibleDate = MAX ( 'DimDate'[Date] )
RETURN
CALCULATE (
    [Risk Events],
    FILTER (
        ALLSELECTED ( 'DimDate'[Date] ),
        'DimDate'[Date] <= MaxVisibleDate
    )
)
```

---

## Closed Week Logic

Use this pattern when the current week is incomplete and should not distort trends.

Assumes `DimDate` includes:

```text
Week Start (Mon)
Date
```

### Last Complete Week Start

```DAX
Last Complete Week Start =
VAR TodayDate = TODAY ()
VAR CurrentWeekStart = TodayDate - WEEKDAY ( TodayDate, 2 ) + 1
RETURN
CurrentWeekStart - 7
```

### Closed Week Risk Events

```DAX
Closed Week Risk Events =
VAR LastClosedWeekStart = [Last Complete Week Start]
VAR LastClosedWeekEnd = LastClosedWeekStart + 6
RETURN
CALCULATE (
    [Risk Events],
    'DimDate'[Date] >= LastClosedWeekStart,
    'DimDate'[Date] <= LastClosedWeekEnd
)
```

### Risk Events Excluding Current Week

```DAX
Risk Events Excluding Current Week =
VAR TodayDate = TODAY ()
VAR CurrentWeekStart = TodayDate - WEEKDAY ( TodayDate, 2 ) + 1
RETURN
CALCULATE (
    [Risk Events],
    'DimDate'[Date] < CurrentWeekStart
)
```

---

## Executive Summary Text Measures

### Executive Risk Narrative

```DAX
Executive Risk Narrative =
VAR HighCritical = [High or Critical Events]
VAR ExternalSharing = [External Sharing Events]
VAR AiRisk = [Sensitive AI Events]
VAR EndpointMovement = [Endpoint Movement Events]
RETURN
"During the selected period, the simulation generated "
    & FORMAT ( HighCritical, "#,0" )
    & " high or critical risk events, including "
    & FORMAT ( ExternalSharing, "#,0" )
    & " external sharing events, "
    & FORMAT ( AiRisk, "#,0" )
    & " AI-related risk events, and "
    & FORMAT ( EndpointMovement, "#,0" )
    & " endpoint movement events."
```

### AI Governance Narrative

```DAX
AI Governance Narrative =
VAR CopilotEvents = [Copilot Interactions]
VAR ExternalAI = [External AI Interactions]
VAR SensitiveAI = [Sensitive AI Events]
RETURN
"AI activity included "
    & FORMAT ( CopilotEvents, "#,0" )
    & " Copilot interactions and "
    & FORMAT ( ExternalAI, "#,0" )
    & " external AI interactions. "
    & FORMAT ( SensitiveAI, "#,0" )
    & " events involved sensitive content or risky source context."
```

---

## Recommended Visual Usage

| Page | Key Measures |
|---|---|
| Executive Risk Snapshot | Total Events, Risk Events, High or Critical Events, External Sharing Events, Sensitive AI Events, Endpoint Movement Events |
| Sensitive Data Exposure | Distinct Sensitive Files, Sensitive External Sharing Events, Label Governance Risk Events |
| DLP Operations | DLP Matches, DLP Warnings, DLP Blocks, DLP Overrides, DLP Override Rate |
| AI and Copilot Risk | Copilot Interactions, External AI Interactions, Sensitive AI Events, AI Risk Rate |
| Insider Risk Overview | Insider Risk Sequences, Mass Download Events, HR Context Events, Devon Composite Risk Score |
| Endpoint DLP and Device Movement | Endpoint DLP Events, File Printed Events, Network Share Copy Events, Distinct Risky Devices |
| Scenario Replay and Timeline | Scenario Events, Scenario Duration Minutes, Distinct Workloads in Scenario, Scenario Max Risk Score |

---

## Codex Usage Guidance

Codex should:

1. Treat this file as a DAX pattern library, not a strict deployment script.
2. Validate table and column names against the actual Power BI semantic model.
3. Use the base measures first, then layer more advanced measures.
4. Keep Devon-specific measures optional and clearly marked for demo use.
5. Preserve closed-week logic for trend charts.
6. Avoid using synthetic risk scores as production risk models.
7. Keep all reporting clearly marked as synthetic demo telemetry.

---

## Safety Reminder

These measures are for synthetic demo telemetry only.

Do not use them to evaluate real employees, real customers, real financial transactions, or real insider-risk cases without proper governance, privacy, legal, and compliance review.
