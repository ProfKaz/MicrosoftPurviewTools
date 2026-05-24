# ADX Ingestion and Table Mappings - Banking / Finance Microsoft 365 E5 Simulation Pack

## Purpose

This document defines a practical Azure Data Explorer (ADX) ingestion and table design for the synthetic Microsoft 365 E5 / Microsoft Purview banking simulation pack.

It is intended for Codex, data engineering scripts, Power BI semantic models, and demo replay engines that need to ingest, query, correlate, and visualize synthetic telemetry generated from browser-agent activity.

All data is synthetic and fictional.

---

## Recommended Architecture

```text
Browser agents / content generators / replay engine
        ↓
Normalized JSON events
        ↓
ADX ingestion table: SyntheticM365ActivityEventsRaw
        ↓
Update policy / transformation
        ↓
Curated fact table: SyntheticM365ActivityEvents
        ↓
Derived materialized views / dimensions
        ↓
KQL hunting + Power BI semantic model
```

---

## Primary Tables

### 1. `SyntheticM365ActivityEventsRaw`

Raw landing table for JSON telemetry records.

Use this table for initial ingestion with minimal transformation.

Recommended columns:

| Column | Type | Description |
|---|---|---|
| `RawEvent` | dynamic | Complete incoming JSON event. |
| `IngestionTime` | datetime | ADX ingestion timestamp. |
| `SourceSystem` | string | Example: `browser-agent`, `replay-engine`, `synthetic-generator`. |
| `BatchId` | string | Batch identifier for replay or ingestion grouping. |

Example create table:

```kusto
.create table SyntheticM365ActivityEventsRaw (
    RawEvent: dynamic,
    IngestionTime: datetime,
    SourceSystem: string,
    BatchId: string
)
```

---

### 2. `SyntheticM365ActivityEvents`

Curated normalized event table aligned with `synthetic-telemetry-schema.json`.

Recommended columns:

| Column | Type |
|---|---|
| `EventId` | string |
| `TimeGenerated` | datetime |
| `ScenarioId` | string |
| `TaskPlanId` | string |
| `TimelineId` | string |
| `CorrelationId` | string |
| `UserPrincipalName` | string |
| `PersonaName` | string |
| `UserRole` | string |
| `Department` | string |
| `Workload` | string |
| `Operation` | string |
| `SignalCategory` | string |
| `Severity` | string |
| `RiskScore` | int |
| `IsRiskEvent` | bool |
| `IsSynthetic` | bool |
| `BusinessContext` | string |
| `FileName` | string |
| `FileType` | string |
| `FilePath` | string |
| `SiteUrl` | string |
| `LibraryName` | string |
| `FileOwner` | string |
| `SensitivityLabel` | string |
| `PreviousSensitivityLabel` | string |
| `Recipient` | string |
| `TargetDomain` | string |
| `DeviceId` | string |
| `DeviceName` | string |
| `AppName` | string |
| `PromptText` | string |
| `ResponsePreview` | string |
| `PolicyName` | string |
| `RuleName` | string |
| `DlpAction` | string |
| `OverrideJustification` | string |
| `AdditionalProperties` | dynamic |

Example create table:

```kusto
.create table SyntheticM365ActivityEvents (
    EventId: string,
    TimeGenerated: datetime,
    ScenarioId: string,
    TaskPlanId: string,
    TimelineId: string,
    CorrelationId: string,
    UserPrincipalName: string,
    PersonaName: string,
    UserRole: string,
    Department: string,
    Workload: string,
    Operation: string,
    SignalCategory: string,
    Severity: string,
    RiskScore: int,
    IsRiskEvent: bool,
    IsSynthetic: bool,
    BusinessContext: string,
    FileName: string,
    FileType: string,
    FilePath: string,
    SiteUrl: string,
    LibraryName: string,
    FileOwner: string,
    SensitivityLabel: string,
    PreviousSensitivityLabel: string,
    Recipient: string,
    TargetDomain: string,
    DeviceId: string,
    DeviceName: string,
    AppName: string,
    PromptText: string,
    ResponsePreview: string,
    PolicyName: string,
    RuleName: string,
    DlpAction: string,
    OverrideJustification: string,
    AdditionalProperties: dynamic
)
```

---

## Update Policy Transformation

Use an update policy to project fields from the raw JSON landing table into the curated table.

Example transformation function:

```kusto
.create-or-alter function TransformSyntheticM365ActivityEventsRaw() {
    SyntheticM365ActivityEventsRaw
    | extend e = RawEvent
    | project
        EventId = tostring(e.EventId),
        TimeGenerated = todatetime(e.TimeGenerated),
        ScenarioId = tostring(e.ScenarioId),
        TaskPlanId = tostring(e.TaskPlanId),
        TimelineId = tostring(e.TimelineId),
        CorrelationId = tostring(e.CorrelationId),
        UserPrincipalName = tostring(e.UserPrincipalName),
        PersonaName = tostring(e.PersonaName),
        UserRole = tostring(e.UserRole),
        Department = tostring(e.Department),
        Workload = tostring(e.Workload),
        Operation = tostring(e.Operation),
        SignalCategory = tostring(e.SignalCategory),
        Severity = tostring(e.Severity),
        RiskScore = toint(e.RiskScore),
        IsRiskEvent = tobool(e.IsRiskEvent),
        IsSynthetic = tobool(e.IsSynthetic),
        BusinessContext = tostring(e.BusinessContext),
        FileName = tostring(e.FileName),
        FileType = tostring(e.FileType),
        FilePath = tostring(e.FilePath),
        SiteUrl = tostring(e.SiteUrl),
        LibraryName = tostring(e.LibraryName),
        FileOwner = tostring(e.FileOwner),
        SensitivityLabel = tostring(e.SensitivityLabel),
        PreviousSensitivityLabel = tostring(e.PreviousSensitivityLabel),
        Recipient = tostring(e.Recipient),
        TargetDomain = tostring(e.TargetDomain),
        DeviceId = tostring(e.DeviceId),
        DeviceName = tostring(e.DeviceName),
        AppName = tostring(e.AppName),
        PromptText = tostring(e.PromptText),
        ResponsePreview = tostring(e.ResponsePreview),
        PolicyName = tostring(e.PolicyName),
        RuleName = tostring(e.RuleName),
        DlpAction = tostring(e.DlpAction),
        OverrideJustification = tostring(e.OverrideJustification),
        AdditionalProperties = todynamic(e.AdditionalProperties)
}
```

Example update policy:

```kusto
.alter table SyntheticM365ActivityEvents policy update
@'[
  {
    "IsEnabled": true,
    "Source": "SyntheticM365ActivityEventsRaw",
    "Query": "TransformSyntheticM365ActivityEventsRaw()",
    "IsTransactional": false,
    "PropagateIngestionProperties": true
  }
]'
```

---

## Recommended Derived Tables or Materialized Views

### 1. `mv_RiskEventsByDay`

Purpose:
Power BI trend charts and executive risk snapshots.

```kusto
.create materialized-view mv_RiskEventsByDay on table SyntheticM365ActivityEvents
{
    SyntheticM365ActivityEvents
    | summarize
        TotalEvents = count(),
        RiskEvents = countif(IsRiskEvent == true),
        HighCriticalEvents = countif(Severity in ('High', 'Critical')),
        DistinctUsers = dcount(UserPrincipalName),
        DistinctFiles = dcount(FileName)
      by bin(TimeGenerated, 1d), Department, Workload, Severity
}
```

---

### 2. `mv_ScenarioSummary`

Purpose:
Scenario replay and validation.

```kusto
.create materialized-view mv_ScenarioSummary on table SyntheticM365ActivityEvents
{
    SyntheticM365ActivityEvents
    | summarize
        FirstEvent = min(TimeGenerated),
        LastEvent = max(TimeGenerated),
        EventCount = count(),
        RiskEvents = countif(IsRiskEvent == true),
        MaxRiskScore = max(RiskScore),
        Personas = make_set(PersonaName),
        Workloads = make_set(Workload),
        Operations = make_set(Operation),
        Files = make_set(FileName)
      by ScenarioId, TimelineId, CorrelationId
}
```

---

### 3. `mv_UserRiskSummary`

Purpose:
User risk overview and insider-risk-style reporting.

```kusto
.create materialized-view mv_UserRiskSummary on table SyntheticM365ActivityEvents
{
    SyntheticM365ActivityEvents
    | summarize
        TotalEvents = count(),
        RiskEvents = countif(IsRiskEvent == true),
        HighCriticalEvents = countif(Severity in ('High', 'Critical')),
        MaxRiskScore = max(RiskScore),
        AvgRiskScore = avg(RiskScore),
        Operations = make_set(Operation),
        Scenarios = make_set(ScenarioId),
        LastSeen = max(TimeGenerated)
      by UserPrincipalName, PersonaName, UserRole, Department
}
```

---

### 4. `mv_SensitiveFileExposure`

Purpose:
Sensitive data exposure and file lifecycle analysis.

```kusto
.create materialized-view mv_SensitiveFileExposure on table SyntheticM365ActivityEvents
{
    SyntheticM365ActivityEvents
    | where isnotempty(FileName)
    | summarize
        EventCount = count(),
        RiskEvents = countif(IsRiskEvent == true),
        Users = make_set(UserPrincipalName),
        Operations = make_set(Operation),
        Labels = make_set(SensitivityLabel),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated)
      by FileName, FileType, FilePath, SiteUrl
}
```

---

## Power BI Semantic Model Mapping

### Fact Table

Power BI table:

```text
FactActivityEvents
```

Source:

```kusto
SyntheticM365ActivityEvents
```

Recommended columns:

```text
EventId
TimeGenerated
ScenarioId
TaskPlanId
TimelineId
CorrelationId
UserPrincipalName
PersonaName
Department
Workload
Operation
SignalCategory
Severity
RiskScore
IsRiskEvent
FileName
SensitivityLabel
Recipient
TargetDomain
DeviceId
AppName
PolicyName
DlpAction
```

---

## Recommended Dimensions

### `DimDate`

Generate from `TimeGenerated`.

Recommended columns:

```text
Date
Year
Month
Month Name
Quarter
Week Number
Week Start (Mon)
Day Name
Is Weekend
Is Closed Day
```

### `DimUser`

Source from distinct user/persona records.

Recommended columns:

```text
UserPrincipalName
PersonaName
UserRole
Department
Timezone
IsRiskAnchor
ManagerPersona
```

### `DimScenario`

Source from `complex-scenarios.json` or distinct event values.

Recommended columns:

```text
ScenarioId
ScenarioTitle
Cadence
PrimaryPersona
RiskTheme
ExpectedSeverity
```

### `DimSignal`

Source from `purview-signal-correlation.json`.

Recommended columns:

```text
SignalName
SignalCategory
DefaultSeverity
RiskWeight
Description
```

### `DimFile`

Source from distinct file records.

Recommended columns:

```text
FileName
FileType
FilePath
SiteUrl
LibraryName
FileOwner
SensitivityLabel
ContentPatternSummary
```

---

## Suggested Power BI Relationships

```text
FactActivityEvents[UserPrincipalName] -> DimUser[UserPrincipalName]
FactActivityEvents[ScenarioId] -> DimScenario[ScenarioId]
FactActivityEvents[Operation] -> DimSignal[SignalName]
FactActivityEvents[FileName] -> DimFile[FileName]
FactActivityEvents[Date] -> DimDate[Date]
```

If multiple files can share the same name across paths, create a stable `FileKey`:

```text
FileKey = lower(trim(coalesce(FilePath, SiteUrl & "|" & FileName)))
```

---

## Retention Strategy

Recommended ADX retention:

| Table | Retention |
|---|---:|
| `SyntheticM365ActivityEventsRaw` | 30 days |
| `SyntheticM365ActivityEvents` | 180 days |
| Materialized views | 180 days |
| Scenario replay exports | 365 days if needed |

Example:

```kusto
.alter-merge table SyntheticM365ActivityEventsRaw policy retention softdelete = 30d
.alter-merge table SyntheticM365ActivityEvents policy retention softdelete = 180d
```

---

## Ingestion Batching Guidance

Recommended batch types:

| Batch Type | Use |
|---|---|
| `baseline-daily` | Normal daily activity noise. |
| `scenario-run` | A specific complex scenario execution. |
| `timeline-replay` | Chronological insider-risk replay. |
| `dashboard-seed` | Precomputed demo data for Power BI. |
| `stress-test` | Larger synthetic data volume for report performance testing. |

Recommended fields:

```text
BatchId
ScenarioId
ExecutionMode
ReplaySeed
GeneratedBy
GeneratedAt
```

---

## Query Optimization Guidance

Use these filters early in KQL:

```kusto
| where TimeGenerated > ago(30d)
| where ScenarioId == 'BF-SCEN-0030'
| where UserPrincipalName == 'devon.reyes@mhdemos.com'
| where Operation in ('FileDownloaded', 'DLPPolicyMatch', 'AIAppInteraction')
```

Recommended high-value indexes are automatically handled by ADX columnar storage, but query design should:

- Filter on `TimeGenerated` early.
- Filter on `ScenarioId` or `CorrelationId` for replay.
- Avoid expanding large dynamic fields unless required.
- Project only required columns before joins.
- Use materialized views for dashboard summaries.

---

## Example Scenario Replay Query

```kusto
SyntheticM365ActivityEvents
| where ScenarioId == 'BF-SCEN-0030'
| where UserPrincipalName == 'devon.reyes@mhdemos.com'
| project
    TimeGenerated,
    PersonaName,
    Workload,
    Operation,
    FileName,
    SensitivityLabel,
    Recipient,
    TargetDomain,
    DeviceId,
    RiskScore,
    BusinessContext
| order by TimeGenerated asc
```

---

## Example Executive Summary Query

```kusto
SyntheticM365ActivityEvents
| where TimeGenerated > ago(30d)
| summarize
    TotalEvents = count(),
    RiskEvents = countif(IsRiskEvent),
    HighCriticalEvents = countif(Severity in ('High', 'Critical')),
    ExternalSharingEvents = countif(Operation in ('ExternalEmailSent', 'FileShared', 'GuestUserAdded', 'ExternalUserAccessed')),
    AiRiskEvents = countif(Operation in ('AIAppInteraction', 'UnmanagedAppUpload', 'SensitiveContentAccessed')),
    EndpointMovementEvents = countif(Operation in ('FilePrinted', 'FileCopiedToUSB', 'FileCopiedToNetworkShare')),
    DistinctRiskyUsers = dcountif(UserPrincipalName, IsRiskEvent)
```

---

## Example Data Quality Checks

```kusto
SyntheticM365ActivityEvents
| summarize
    MissingScenarioId = countif(isempty(ScenarioId)),
    MissingUser = countif(isempty(UserPrincipalName)),
    MissingOperation = countif(isempty(Operation)),
    MissingTimeGenerated = countif(isnull(TimeGenerated)),
    NonSyntheticEvents = countif(IsSynthetic != true)
```

---

## Recommended Validation Rules

Codex should validate that:

1. `EventId` is unique.
2. `TimeGenerated` is populated and valid.
3. `Operation` exists in `synthetic-telemetry-schema.json`.
4. `ScenarioId` exists in `complex-scenarios.json` when populated.
5. `RiskScore` is between 0 and 100.
6. `IsSynthetic` is always true.
7. External domains use test or fictional domains.
8. Sensitive-looking identifiers use the approved fictional pattern library.
9. Events in the same scenario preserve consistent `CorrelationId` values.
10. Investigation artifacts use neutral language.

---

## Suggested Future Enhancements

1. Create `.kql` files for table creation and update policies.
2. Add Bicep or Terraform templates for ADX database deployment.
3. Add Python or PowerShell ingestion scripts.
4. Generate ADX sample data from `synthetic-telemetry-schema.json`.
5. Add Power BI template files.
6. Create a replay controller for compressed demo mode.
7. Add query tests for expected scenario outcomes.
8. Add JSON schema validation for all configuration files.
9. Add CI validation to confirm all JSON files are valid.
10. Add sample ADX dashboards.

---

## Safety Reminder

This ADX model is for synthetic telemetry only.

Do not ingest:

- production Microsoft 365 logs
- real user telemetry
- real customer data
- real HR records
- real legal matters
- real financial transactions
- real credentials
- real secrets
- real incident evidence

unless the environment, governance, approvals, privacy requirements, and legal requirements explicitly support that production use case.
