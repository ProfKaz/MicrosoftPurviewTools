# ADX KQL Hunting and Detection Library

## Purpose

This document defines KQL hunting, detection, replay reconstruction, dashboard-support, and SOC triage query patterns for the synthetic Microsoft 365 E5 / Microsoft Purview banking simulation platform.

It is designed for Azure Data Explorer (ADX) tables defined in:

```text
adx-ingestion-and-table-mappings.md
```

Primary table assumed:

```text
SyntheticM365ActivityEvents
```

All queries are designed for synthetic demo telemetry only.

---

## Query Design Principles

1. Filter on `TimeGenerated` early.
2. Use `ScenarioId` and `CorrelationId` for replay reconstruction.
3. Use `UserPrincipalName` for user-centric investigations.
4. Use `Operation` for control-specific detections.
5. Use `SensitivityLabel` and `RiskScore` for risk prioritization.
6. Avoid expanding `AdditionalProperties` unless necessary.
7. Preserve neutral language when query output is used in investigation notes.

---

## Base Query Pattern

```kusto
SyntheticM365ActivityEvents
| where TimeGenerated > ago(30d)
| where IsSynthetic == true
| project
    TimeGenerated,
    ScenarioId,
    CorrelationId,
    UserPrincipalName,
    PersonaName,
    Department,
    Workload,
    Operation,
    Severity,
    RiskScore,
    FileName,
    SensitivityLabel,
    Recipient,
    TargetDomain,
    DeviceId,
    AppName,
    BusinessContext
| order by TimeGenerated desc
```

---

## Executive Summary Queries

## Total Risk Posture

```kusto
SyntheticM365ActivityEvents
| where TimeGenerated > ago(30d)
| summarize
    TotalEvents = count(),
    RiskEvents = countif(IsRiskEvent == true),
    HighCriticalEvents = countif(Severity in ('High', 'Critical')),
    DistinctUsers = dcount(UserPrincipalName),
    DistinctRiskyUsers = dcountif(UserPrincipalName, IsRiskEvent == true),
    DistinctFiles = dcount(FileName),
    SensitiveFiles = dcountif(FileName, SensitivityLabel != '' and SensitivityLabel != 'Public')
```

## Risk by Department

```kusto
SyntheticM365ActivityEvents
| where TimeGenerated > ago(30d)
| summarize
    TotalEvents = count(),
    RiskEvents = countif(IsRiskEvent == true),
    HighCriticalEvents = countif(Severity in ('High', 'Critical')),
    AvgRiskScore = avg(RiskScore),
    MaxRiskScore = max(RiskScore)
  by Department
| order by HighCriticalEvents desc, RiskEvents desc
```

## Risk by Workload

```kusto
SyntheticM365ActivityEvents
| where TimeGenerated > ago(30d)
| summarize
    Events = count(),
    RiskEvents = countif(IsRiskEvent == true),
    HighCriticalEvents = countif(Severity in ('High', 'Critical'))
  by Workload
| order by HighCriticalEvents desc
```

---

## Scenario Replay Queries

## Replay a Scenario by ScenarioId

```kusto
SyntheticM365ActivityEvents
| where ScenarioId == 'BF-SCEN-0030'
| project
    TimeGenerated,
    PersonaName,
    UserPrincipalName,
    Workload,
    Operation,
    FileName,
    SensitivityLabel,
    Recipient,
    TargetDomain,
    DeviceId,
    AppName,
    Severity,
    RiskScore,
    BusinessContext
| order by TimeGenerated asc
```

## Replay by CorrelationId

```kusto
SyntheticM365ActivityEvents
| where CorrelationId == 'CORR-DEVON-20260524-001'
| project
    TimeGenerated,
    ScenarioId,
    PersonaName,
    Workload,
    Operation,
    FileName,
    SensitivityLabel,
    RiskScore,
    BusinessContext
| order by TimeGenerated asc
```

## Scenario Summary

```kusto
SyntheticM365ActivityEvents
| summarize
    FirstEvent = min(TimeGenerated),
    LastEvent = max(TimeGenerated),
    EventCount = count(),
    RiskEvents = countif(IsRiskEvent == true),
    HighCriticalEvents = countif(Severity in ('High', 'Critical')),
    MaxRiskScore = max(RiskScore),
    Personas = make_set(PersonaName),
    Workloads = make_set(Workload),
    Operations = make_set(Operation),
    Files = make_set(FileName)
  by ScenarioId, CorrelationId
| order by MaxRiskScore desc, EventCount desc
```

---

## AI Governance Queries

## Copilot and External AI Activity

```kusto
SyntheticM365ActivityEvents
| where Operation in ('CopilotInteraction', 'AIAppInteraction', 'UnmanagedAppUpload', 'SensitiveContentAccessed', 'FileReferencedByCopilot')
| summarize
    Events = count(),
    RiskEvents = countif(IsRiskEvent == true),
    HighCriticalEvents = countif(Severity in ('High', 'Critical')),
    MaxRiskScore = max(RiskScore)
  by AppName, Operation, PersonaName, Department
| order by HighCriticalEvents desc, RiskEvents desc
```

## External AI After Sensitive File Access

```kusto
let SensitiveAccess = SyntheticM365ActivityEvents
| where Operation in ('FileAccessed', 'FileDownloaded')
| where SensitivityLabel contains 'Highly Confidential'
| project AccessTime = TimeGenerated, UserPrincipalName, FileName, SensitivityLabel, CorrelationId;
let AIUsage = SyntheticM365ActivityEvents
| where Operation in ('AIAppInteraction', 'UnmanagedAppUpload')
| project AITime = TimeGenerated, UserPrincipalName, AppName, PromptText, Operation, RiskScore, CorrelationId;
AIUsage
| join kind=inner SensitiveAccess on UserPrincipalName
| where AccessTime between (AITime - 4h .. AITime)
| project AITime, UserPrincipalName, AppName, Operation, FileName, SensitivityLabel, PromptText, RiskScore, CorrelationId
| order by AITime desc
```

## Unsafe Prompt Samples

```kusto
SyntheticM365ActivityEvents
| where Operation in ('AIAppInteraction', 'UnmanagedAppUpload')
| where RiskScore >= 50 or IsRiskEvent == true
| project
    TimeGenerated,
    PersonaName,
    Department,
    AppName,
    PromptText,
    FileName,
    SensitivityLabel,
    RiskScore,
    BusinessContext
| order by RiskScore desc, TimeGenerated desc
```

---

## DLP Queries

## DLP Operations Summary

```kusto
SyntheticM365ActivityEvents
| where Operation in ('DLPPolicyMatch', 'DLPWarned', 'DLPBlocked', 'DLPOverride')
| summarize
    Events = count(),
    Users = dcount(UserPrincipalName),
    Files = dcount(FileName),
    MaxRiskScore = max(RiskScore)
  by Operation, PolicyName, RuleName, DlpAction
| order by Events desc
```

## DLP Overrides Requiring Review

```kusto
SyntheticM365ActivityEvents
| where Operation == 'DLPOverride'
| project
    TimeGenerated,
    UserPrincipalName,
    PersonaName,
    Department,
    FileName,
    SensitivityLabel,
    Recipient,
    TargetDomain,
    PolicyName,
    RuleName,
    OverrideJustification,
    RiskScore,
    ScenarioId,
    CorrelationId
| order by RiskScore desc, TimeGenerated desc
```

## DLP Warning Followed by Override

```kusto
let Warnings = SyntheticM365ActivityEvents
| where Operation == 'DLPWarned'
| project WarningTime = TimeGenerated, UserPrincipalName, FileName, PolicyName, CorrelationId;
let Overrides = SyntheticM365ActivityEvents
| where Operation == 'DLPOverride'
| project OverrideTime = TimeGenerated, UserPrincipalName, FileName, OverrideJustification, RiskScore, CorrelationId;
Warnings
| join kind=inner Overrides on UserPrincipalName, FileName
| where OverrideTime between (WarningTime .. WarningTime + 30m)
| project WarningTime, OverrideTime, UserPrincipalName, FileName, PolicyName, OverrideJustification, RiskScore, CorrelationId
| order by OverrideTime desc
```

---

## Label Governance Queries

## Label Events Summary

```kusto
SyntheticM365ActivityEvents
| where Operation in ('SensitivityLabelApplied', 'SensitivityLabelChanged', 'SensitivityLabelRemoved', 'LabelDowngrade')
| summarize
    Events = count(),
    Files = dcount(FileName),
    Users = dcount(UserPrincipalName)
  by Operation, SensitivityLabel, PreviousSensitivityLabel, Department
| order by Events desc
```

## Label Downgrade Before Sharing

```kusto
let LabelEvents = SyntheticM365ActivityEvents
| where Operation in ('SensitivityLabelChanged', 'LabelDowngrade', 'SensitivityLabelRemoved')
| project LabelTime = TimeGenerated, UserPrincipalName, FileName, PreviousSensitivityLabel, SensitivityLabel, CorrelationId;
let ShareEvents = SyntheticM365ActivityEvents
| where Operation in ('FileShared', 'ExternalEmailSent')
| project ShareTime = TimeGenerated, UserPrincipalName, FileName, Recipient, TargetDomain, Operation, RiskScore, CorrelationId;
LabelEvents
| join kind=inner ShareEvents on UserPrincipalName, FileName
| where ShareTime between (LabelTime .. LabelTime + 15m)
| project LabelTime, ShareTime, UserPrincipalName, FileName, PreviousSensitivityLabel, SensitivityLabel, Operation, Recipient, TargetDomain, RiskScore, CorrelationId
| order by ShareTime desc
```

---

## External Sharing Queries

## Sensitive External Sharing

```kusto
SyntheticM365ActivityEvents
| where Operation in ('ExternalEmailSent', 'FileShared', 'GuestUserAdded', 'ExternalUserAccessed')
| where TargetDomain != '' and TargetDomain != 'mhdemos.com'
| where SensitivityLabel != '' and SensitivityLabel != 'Public'
| project
    TimeGenerated,
    UserPrincipalName,
    PersonaName,
    Department,
    Operation,
    FileName,
    SensitivityLabel,
    Recipient,
    TargetDomain,
    RiskScore,
    ScenarioId,
    CorrelationId
| order by RiskScore desc, TimeGenerated desc
```

## Top External Domains

```kusto
SyntheticM365ActivityEvents
| where TargetDomain != '' and TargetDomain != 'mhdemos.com'
| summarize
    Events = count(),
    RiskEvents = countif(IsRiskEvent == true),
    SensitiveFiles = dcountif(FileName, SensitivityLabel != '' and SensitivityLabel != 'Public'),
    Users = dcount(UserPrincipalName)
  by TargetDomain
| order by RiskEvents desc, Events desc
```

---

## Endpoint DLP Queries

## Endpoint Movement Summary

```kusto
SyntheticM365ActivityEvents
| where Operation in ('FilePrinted', 'FileCopiedToNetworkShare', 'FileCopiedToUSB', 'EndpointDLPPolicyMatch')
| summarize
    Events = count(),
    Users = dcount(UserPrincipalName),
    Devices = dcount(DeviceId),
    SensitiveFiles = dcountif(FileName, SensitivityLabel contains 'Highly Confidential'),
    MaxRiskScore = max(RiskScore)
  by Operation, Department
| order by MaxRiskScore desc, Events desc
```

## Sensitive Download Followed by Endpoint Movement

```kusto
let Downloads = SyntheticM365ActivityEvents
| where Operation == 'FileDownloaded'
| where SensitivityLabel contains 'Highly Confidential'
| project DownloadTime = TimeGenerated, UserPrincipalName, FileName, SensitivityLabel, CorrelationId;
let EndpointMoves = SyntheticM365ActivityEvents
| where Operation in ('FilePrinted', 'FileCopiedToNetworkShare', 'FileCopiedToUSB')
| project MoveTime = TimeGenerated, UserPrincipalName, FileName, Operation, DeviceId, DeviceName, RiskScore, CorrelationId;
Downloads
| join kind=inner EndpointMoves on UserPrincipalName, FileName
| where MoveTime between (DownloadTime .. DownloadTime + 4h)
| project DownloadTime, MoveTime, UserPrincipalName, FileName, SensitivityLabel, Operation, DeviceId, DeviceName, RiskScore, CorrelationId
| order by MoveTime desc
```

---

## Identity and Conditional Access Queries

## Risky Sign-In Followed by Sensitive Download

```kusto
let RiskySignIns = SyntheticM365ActivityEvents
| where Operation in ('RiskySignIn', 'ConditionalAccessTriggered', 'MFARequired')
| project SignInTime = TimeGenerated, UserPrincipalName, Operation, DeviceId, DeviceName, CorrelationId, AdditionalProperties;
let SensitiveDownloads = SyntheticM365ActivityEvents
| where Operation == 'FileDownloaded'
| where SensitivityLabel contains 'Highly Confidential'
| project DownloadTime = TimeGenerated, UserPrincipalName, FileName, SensitivityLabel, RiskScore, CorrelationId;
RiskySignIns
| join kind=inner SensitiveDownloads on UserPrincipalName
| where DownloadTime between (SignInTime .. SignInTime + 4h)
| project SignInTime, DownloadTime, UserPrincipalName, FileName, SensitivityLabel, Operation, DeviceId, DeviceName, RiskScore, CorrelationId
| order by DownloadTime desc
```

---

## Insider Risk-Style Queries

## HR Context Followed by Mass Download

```kusto
let HRContext = SyntheticM365ActivityEvents
| where Operation == 'HRSignal'
| project HRTime = TimeGenerated, UserPrincipalName, BusinessContext, CorrelationId;
let Downloads = SyntheticM365ActivityEvents
| where Operation in ('MassDownloadActivity', 'FileDownloaded')
| summarize DownloadCount = count(), Files = make_set(FileName), MaxRiskScore = max(RiskScore), FirstDownload = min(TimeGenerated), LastDownload = max(TimeGenerated)
  by UserPrincipalName, CorrelationId;
HRContext
| join kind=inner Downloads on UserPrincipalName
| where FirstDownload between (HRTime .. HRTime + 72h)
| project HRTime, FirstDownload, LastDownload, UserPrincipalName, DownloadCount, Files, MaxRiskScore, BusinessContext, CorrelationId
| order by MaxRiskScore desc
```

## Multi-Stage Risk Chain

```kusto
SyntheticM365ActivityEvents
| where TimeGenerated > ago(30d)
| summarize
    HasDownload = countif(Operation == 'FileDownloaded') > 0,
    HasExternalAI = countif(Operation in ('AIAppInteraction', 'UnmanagedAppUpload')) > 0,
    HasDLPOverride = countif(Operation == 'DLPOverride') > 0,
    HasEndpointMovement = countif(Operation in ('FilePrinted', 'FileCopiedToNetworkShare', 'FileCopiedToUSB')) > 0,
    HasHRContext = countif(Operation == 'HRSignal') > 0,
    EventCount = count(),
    MaxRiskScore = max(RiskScore),
    FirstEvent = min(TimeGenerated),
    LastEvent = max(TimeGenerated),
    Operations = make_set(Operation),
    Files = make_set(FileName)
  by UserPrincipalName, PersonaName, Department, CorrelationId
| extend ChainScore = toint(HasDownload) + toint(HasExternalAI) + toint(HasDLPOverride) + toint(HasEndpointMovement) + toint(HasHRContext)
| where ChainScore >= 3
| order by ChainScore desc, MaxRiskScore desc
```

---

## Power BI Support Queries

## Fact Activity Events Extract

```kusto
SyntheticM365ActivityEvents
| project
    EventId,
    TimeGenerated,
    Date = startofday(TimeGenerated),
    ScenarioId,
    CorrelationId,
    UserPrincipalName,
    PersonaName,
    UserRole,
    Department,
    Workload,
    Operation,
    SignalCategory,
    Severity,
    RiskScore,
    IsRiskEvent,
    IsSynthetic,
    BusinessContext,
    FileName,
    FileType,
    FilePath,
    SiteUrl,
    LibraryName,
    FileOwner,
    SensitivityLabel,
    PreviousSensitivityLabel,
    Recipient,
    TargetDomain,
    DeviceId,
    DeviceName,
    AppName,
    PromptText,
    ResponsePreview,
    PolicyName,
    RuleName,
    DlpAction,
    OverrideJustification,
    AdditionalPropertiesJson = tostring(AdditionalProperties)
```

## Dim User Extract

```kusto
SyntheticM365ActivityEvents
| summarize
    PersonaName = any(PersonaName),
    UserRole = any(UserRole),
    Department = any(Department),
    LastSeen = max(TimeGenerated),
    IsRiskAnchor = any(UserPrincipalName == 'devon.reyes@mhdemos.com')
  by UserPrincipalName
```

## Dim File Extract

```kusto
SyntheticM365ActivityEvents
| where isnotempty(FileName)
| extend FileKey = tolower(trim(' ', coalesce(FilePath, strcat(SiteUrl, '|', FileName))))
| summarize
    FileName = any(FileName),
    FileType = any(FileType),
    FilePath = any(FilePath),
    SiteUrl = any(SiteUrl),
    LibraryName = any(LibraryName),
    FileOwner = any(FileOwner),
    SensitivityLabel = any(SensitivityLabel),
    EventCount = count(),
    RiskEvents = countif(IsRiskEvent == true)
  by FileKey
```

---

## Data Quality Queries

## Required Field Completeness

```kusto
SyntheticM365ActivityEvents
| summarize
    TotalEvents = count(),
    MissingEventId = countif(isempty(EventId)),
    MissingTimeGenerated = countif(isnull(TimeGenerated)),
    MissingUser = countif(isempty(UserPrincipalName)),
    MissingOperation = countif(isempty(Operation)),
    MissingScenarioId = countif(isempty(ScenarioId)),
    NonSyntheticEvents = countif(IsSynthetic != true),
    InvalidRiskScore = countif(RiskScore < 0 or RiskScore > 100)
```

## Unknown Labels

```kusto
let AllowedLabels = dynamic([
    'Public',
    'Internal',
    'Confidential',
    'Highly Confidential',
    'Highly Confidential - Regulated Financial Data',
    'Highly Confidential - HR Restricted',
    'Highly Confidential - Legal Privileged'
]);
SyntheticM365ActivityEvents
| where isnotempty(SensitivityLabel)
| where SensitivityLabel !in (AllowedLabels)
| summarize Events = count() by SensitivityLabel
```

---

## Performance Guidance

Recommended practices:

- Always filter `TimeGenerated` early.
- Use `ScenarioId` or `CorrelationId` for replay queries.
- Use `project` before joins to reduce columns.
- Avoid expanding `AdditionalProperties` in executive queries.
- Use materialized views for daily trends and summary pages.
- Keep prompt text out of high-volume visuals when possible.
- Use `summarize` and `make_set` carefully on large datasets.

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate `.kql` query files.
2. Build ADX functions.
3. Create Power BI source queries.
4. Generate SOC hunting notebooks.
5. Validate scenario replay outputs.
6. Create dashboard-support extracts.
7. Produce customer workshop query handouts.
8. Keep query language aligned with synthetic telemetry schema.
9. Preserve neutral investigation language.
10. Preserve synthetic-only boundaries.

---

## Safety Reminder

These queries are for synthetic demo telemetry only.

Do not use these queries to investigate, monitor, score, discipline, or evaluate real employees or real customers without formal legal, privacy, HR, compliance, and governance approval.
