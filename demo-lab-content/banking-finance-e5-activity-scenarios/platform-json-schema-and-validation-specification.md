# Platform JSON Schema and Validation Specification

## Purpose

This document defines the formal validation, schema governance, naming conventions, cross-file reference checks, and CI/CD quality controls for the synthetic Microsoft 365 E5 / Microsoft Purview banking simulation platform.

It is intended for Codex, maintainers, GitHub Actions workflows, schema validators, content generators, replay engines, and telemetry pipelines.

All validation rules must preserve the synthetic-only nature of the platform.

---

## Validation Goals

The validation layer should ensure that:

1. All JSON files are syntactically valid.
2. Required metadata exists in every configuration file.
3. IDs follow predictable formats.
4. Cross-file references are valid.
5. Operations match the canonical telemetry operation catalog.
6. Scenario IDs are consistent across all files.
7. Persona names and user principal names are consistent.
8. Synthetic sensitive data patterns are used instead of real identifiers.
9. Risk scores and severity values are inside accepted ranges.
10. Power BI, ADX, KQL, and replay-engine assumptions remain aligned.

---

## Files Covered by JSON Validation

Recommended JSON files:

```text
technologies-and-activities.json
complex-scenarios.json
browser-agent-task-plans.json
daily-schedules.json
purview-signal-correlation.json
insider-risk-timelines.json
copilot-conversation-transcripts.json
synthetic-kql-samples.json
powerbi-risk-dashboard-definitions.json
browser-agent-orchestration-rules.json
synthetic-telemetry-schema.json
telemetry-generation-playbooks.json
synthetic-data-pattern-library.json
content-generation-blueprints.json
synthetic-risk-correlation-engine.json
```

Markdown files should also be linted, but JSON schema validation applies primarily to the files above.

---

## Required Metadata Block

Every JSON file should include a top-level `metadata` object.

Required fields:

```json
{
  "metadata": {
    "packName": "string",
    "version": "string",
    "language": "en-US",
    "industry": "Banking and Financial Services",
    "fictionalDataOnly": true,
    "purpose": "string"
  }
}
```

Validation rules:

- `packName` must not be empty.
- `version` should follow semantic-style versioning when practical.
- `language` should be `en-US` unless a specific file intentionally documents otherwise.
- `fictionalDataOnly` must be `true`.
- `purpose` must describe the file clearly.

---

## Canonical ID Formats

Use predictable ID formats across the platform.

| Entity | Format | Example |
|---|---|---|
| Scenario ID | `BF-SCEN-[0-9]{4}` | `BF-SCEN-0030` |
| Task Plan ID | `TASKPLAN-[0-9]{4}` | `TASKPLAN-0010` |
| Timeline ID | `IR-TL-[0-9]{4}` | `IR-TL-0001` |
| Event ID | `EVT-BF-[0-9]{8}-[0-9]{6}` | `EVT-BF-20260524-000001` |
| Correlation ID | `CORR-[A-Z]+-[0-9]{8}-[0-9]{3}` | `CORR-DEVON-20260524-001` |
| Case ID | `CASE-[A-Z]+-FIC-[0-9]{4}-[0-9]{4}` | `CASE-IR-FIC-2026-0001` |
| Playbook ID | `PLAYBOOK-[0-9]{4}` | `PLAYBOOK-0001` |
| Query ID | `KQL-[0-9]{4}` | `KQL-0015` |
| Blueprint ID | `[A-Z]+-BP-[0-9]{3}` | `DOC-BP-001` |
| Pattern ID | `PAT-[0-9]{3}` | `PAT-004` |
| Risk Rule ID | `RISK-RULE-[0-9]{3}` | `RISK-RULE-008` |

---

## Canonical Enumerations

### Sensitivity Levels

Allowed values:

```text
Public
Internal
Confidential
Highly Confidential
Highly Confidential - Regulated Financial Data
Highly Confidential - HR Restricted
Highly Confidential - Legal Privileged
```

### Severity Values

Allowed values:

```text
Informational
Low
Medium
High
Critical
```

### Interaction Types

Allowed values:

```text
CopilotInteraction
AIAppInteraction
```

### Label Event Types

Allowed values:

```text
LabelApplied
LabelChanged
LabelRemoved
LabelRecommended
```

### Replay Modes

Allowed values:

```text
realistic
compressed-light
compressed-standard
compressed-fast
instant
SOC analyst mode
executive-demo
chaos
```

---

## Operation Validation

All telemetry operations must exist in the `normalizedOperations` array inside:

```text
synthetic-telemetry-schema.json
```

Examples:

```text
FileCreated
FileModified
FileDownloaded
ExternalEmailSent
DLPPolicyMatch
DLPOverride
CopilotInteraction
AIAppInteraction
UnmanagedAppUpload
FilePrinted
FileCopiedToNetworkShare
RiskySignIn
InsiderRiskSequence
```

Validation rule:

Any operation referenced by scenario files, playbooks, KQL samples, Power BI definitions, or telemetry examples should resolve to the canonical operation catalog.

---

## Cross-File Reference Validation

### Scenario References

Every `ScenarioId` referenced in supporting files should exist in:

```text
complex-scenarios.json
```

Files that may reference scenarios:

```text
browser-agent-task-plans.json
insider-risk-timelines.json
synthetic-kql-samples.json
powerbi-risk-dashboard-definitions.json
browser-agent-orchestration-rules.json
telemetry-generation-playbooks.json
synthetic-risk-correlation-engine.json
```

### Persona References

Persona names should resolve to the approved persona catalog in the project.

Expected personas:

```text
Alexander Meyer
Ana Rodriguez
Carlos Delgado
David Chen
Emily Johnson
James Wilson
Laura Gomez
Marcus Olsson
Miguel Santos
Priya Sharma
Sofia Lopez
Devon Reyes
```

### User Principal Name References

Expected UPN pattern:

```text
[first].[last]@mhdemos.com
```

Example:

```text
devon.reyes@mhdemos.com
```

### Signal References

Signals should resolve to:

```text
purview-signal-correlation.json
```

or the canonical operation catalog in:

```text
synthetic-telemetry-schema.json
```

---

## Synthetic Data Safety Validation

The validator should detect and block accidental real-looking data where practical.

### Required Synthetic Prefixes

Approved fictional patterns include:

```text
CUST-BNK-
ACCT-FIC-
LOAN-FIC-
LOAN-EXC-FIC-
KYC-FIC-
AML-CASE-
SAR-DRAFT-FIC-
SAR-CASE-FIC-
FRAUD-FIC-
TXN-FIC-
PAY-FIC-
RECON-FIC-
TREAS-FIC-
EMP-
CND-
ROLE-CHANGE-FIC-
SAL-BAND-FIC-
LEGAL-FIC-
REG-REQ-FIC-
PRIV-NOTE-FIC-
INV-FAK-
VENDOR-FIC-
CASE-FIC-
DEV-FIC-
SIGNIN-FIC-
CORR-
```

### Disallowed Content Patterns

Validators should flag:

- real-looking credit card numbers without fictional prefixes
- real-looking national IDs
- real bank routing numbers
- real addresses
- real company names used as customers
- real credentials or tokens
- secrets such as `client_secret`, `password=`, `BEGIN PRIVATE KEY`
- production tenant URLs unless explicitly allowed
- real email domains for external recipients unless lab-controlled

### External Domain Rule

External recipients should use safe fictional or test domains such as:

```text
example.test
vendor-review.example.test
northbridge-example.test
```

---

## Risk Score Validation

Risk scores must be numeric and within range:

```text
0 <= RiskScore <= 100
```

Severity should align approximately with score bands from:

```text
synthetic-risk-correlation-engine.json
```

Recommended alignment:

| Score Range | Expected Severity |
|---|---|
| 0-24 | Low |
| 25-49 | Medium |
| 50-79 | High |
| 80-100 | Critical |

Exceptions are allowed only when business context justifies them.

---

## Telemetry Event Validation

A normalized telemetry event should include:

```text
EventId
TimeGenerated
UserPrincipalName
PersonaName
Workload
Operation
IsRiskEvent
IsSynthetic
```

Recommended validation rules:

- `EventId` must be unique.
- `TimeGenerated` must be a valid ISO 8601 datetime.
- `IsSynthetic` must be `true`.
- `Operation` must be canonical.
- `RiskScore` must be 0-100 when present.
- `Severity` must be an allowed value.
- `ScenarioId` should be present for scenario-linked events.
- `CorrelationId` should be present for multi-step chains.

---

## Replay Validation

A replay is valid when:

1. It has a `ReplayId`.
2. It has a supported mode.
3. It has a deterministic seed.
4. All referenced scenarios exist.
5. All planned personas exist.
6. Event timestamps are ordered logically.
7. Expected signals are emitted.
8. Correlation IDs are preserved across chained events.
9. No real data patterns are detected.
10. Validation output is written to a replay validation report.

---

## Power BI Compatibility Validation

Before publishing a dataset, validate that:

- `FactActivityEvents` can be produced from the telemetry table.
- `DimDate` includes `Week Start (Mon)`.
- `DimUser` includes all personas.
- `DimScenario` includes all active scenarios.
- `DimSignal` includes all operations used by facts.
- DAX measure assumptions match actual column names.
- Devon-specific measures remain optional.
- synthetic-only disclaimer exists in report documentation.

---

## ADX Compatibility Validation

Validate that:

- every telemetry field can map to `SyntheticM365ActivityEvents`.
- `AdditionalProperties` remains valid JSON/dynamic content.
- materialized views can compile.
- KQL samples reference existing table or placeholder names consistently.
- replay queries filter by `TimeGenerated`, `ScenarioId`, or `CorrelationId`.

---

## Markdown Validation

Markdown files should be checked for:

- title heading
- purpose section
- Codex usage guidance where relevant
- safety reminder
- fenced code block closure
- internal file references
- consistent terminology
- no real secrets
- no production customer data

---

## CI/CD Validation Pipeline

Recommended GitHub Actions stages:

```text
checkout
setup-runtime
validate-json-syntax
validate-json-metadata
validate-id-formats
validate-cross-file-references
validate-operation-catalog
validate-synthetic-data-safety
validate-markdown
validate-kql-snippets
validate-powerbi-assumptions
publish-validation-report
```

---

## Example Validation Report

Recommended output:

```json
{
  "validationRunId": "VAL-FIC-2026-0001",
  "status": "passed",
  "validatedAt": "2026-05-24T18:00:00Z",
  "filesChecked": 24,
  "errors": [],
  "warnings": [
    {
      "file": "synthetic-kql-samples.json",
      "message": "Query uses placeholder table name; expected for schema-agnostic examples."
    }
  ]
}
```

---

## Schema Evolution Rules

When changing schemas:

1. Increment version in `metadata.version`.
2. Preserve backward compatibility when possible.
3. Avoid renaming fields used by telemetry, ADX, Power BI, or KQL without migration guidance.
4. Add new fields as optional first.
5. Update this validation specification when new ID formats or enumerations are introduced.
6. Update `master-platform-readme-and-navigation-index.md` when new artifact categories are added.

---

## Recommended Future JSON Schema Files

Create formal JSON Schema files under a future folder such as:

```text
demo-lab-content/banking-finance-e5-activity-scenarios/schemas/
```

Suggested schemas:

```text
metadata.schema.json
scenario.schema.json
telemetry-event.schema.json
browser-task-plan.schema.json
risk-rule.schema.json
content-blueprint.schema.json
pattern-library.schema.json
powerbi-dashboard.schema.json
kql-sample.schema.json
replay-timeline.schema.json
```

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate JSON Schema files.
2. Build CI validation workflows.
3. Create validation scripts.
4. Validate scenario references.
5. Validate telemetry events before ADX ingestion.
6. Validate synthetic data safety.
7. Validate Power BI assumptions before report generation.
8. Prevent accidental real sensitive data from entering the repository.
9. Maintain schema evolution discipline.
10. Produce validation reports for each release.

---

## Safety Reminder

Validation should fail closed when real-looking sensitive data, credentials, secrets, or production identifiers are detected.

This platform must remain synthetic, fictional, and safe for demo use.
