# Codex Master Build Instructions and Repository Workplan

## Purpose

This document is the primary implementation-control file for Codex and other engineering agents working on the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It explains:

- what to read first
- what to build first
- required implementation order
- constraints
- coding standards
- generated output paths
- test expectations
- validation expectations
- data-safety rules
- naming conventions
- task breakdown
- implementation phases
- what not to build yet
- first sprint plan
- expected deliverables
- documentation-update rules

All platform outputs must remain fictional, synthetic, and safe for demo use.

---

## Read This First

Codex should start with this file before making implementation changes.

Then read these files in order:

```text
1. demo-lab-build-backlog-and-implementation-epics.md
2. reference-implementation-and-minimum-viable-build-guide.md
3. sample-synthetic-telemetry-dataset-specification.md
4. synthetic-dataset-generator-pseudocode-and-processing-pipeline.md
5. synthetic-telemetry-schema.json
6. synthetic-data-pattern-library.json
7. data-protection-scenario-taxonomy-and-pattern-catalog.md
8. persona-behavioral-psychology-and-risk-patterns-guide.md
9. synthetic-telemetry-replay-and-timeline-orchestration-engine.md
10. powerbi-semantic-model-and-dashboard-blueprint.md
11. adx-kql-hunting-and-detection-framework.md
12. platform-json-schema-and-validation-specification.md
```

If a referenced file does not exist yet, Codex should create a GitHub issue or backlog note rather than inventing incompatible structures silently.

---

## Current Implementation Goal

The immediate goal is not to build the entire cyber-range.

The first implementation goal is:

```text
Generate a deterministic 1,000-event synthetic telemetry dataset and make it usable by Power BI and ADX.
```

MVP deliverables:

```text
sample-data/banking-finance-e5-mvp-synthetic-telemetry-1000.jsonl
sample-data/banking-finance-e5-mvp-synthetic-telemetry-1000.csv
sample-data/banking-finance-e5-mvp-synthetic-telemetry-1000-validation-report.json
sample-data/banking-finance-e5-mvp-scenario-summary.json
sample-data/banking-finance-e5-mvp-replay-timeline.json
```

---

## Build Order

Codex must follow this order unless explicitly instructed otherwise.

```text
1. Create stable persona catalog.
2. Create stable scenario catalog.
3. Create operation and sensitivity label catalog.
4. Implement deterministic telemetry generator.
5. Generate MVP JSONL and CSV dataset.
6. Generate validation report.
7. Generate scenario summary.
8. Generate replay timeline.
9. Create ADX table and ingestion mapping scripts.
10. Create Power BI-ready semantic model notes or sample queries.
11. Add validation scripts.
12. Add GitHub Actions workflow only after local validation scripts exist.
```

---

## Do Not Build Yet

Do not build these until the MVP dataset and validation pass:

```text
browser-agent automation
live Microsoft 365 tenant automation
Sentinel deployment automation
Fabric integration
autonomous persona agents
multi-tenant federation
red-team / blue-team automation
full cyber-range chaos mode
production-grade managed service automation
```

These are roadmap items and should remain design-stage until the data and replay foundation is stable.

---

## Synthetic-Only Safety Rules

Codex must never introduce:

- real people
- real customers
- real companies as customers
- real financial data
- real bank account numbers
- real credit card numbers
- real national IDs
- real HR records
- real legal matters
- real credentials
- real secrets
- real production telemetry
- real production URLs
- real incident evidence

Every generated event must include:

```text
IsSynthetic = true
```

Use only fictional patterns such as:

```text
CUST-BNK
ACCT-FIC
KYC-FIC
AML-CASE
SAR-DRAFT-FIC
TXN-FIC
LOAN-FIC
TREAS-FIC
INV-FAK
EMP
ROLE-CHANGE-FIC
LEGAL-FIC
REG-REQ-FIC
CASE-IR-FIC
```

---

## Required Repository Structure

Recommended implementation structure:

```text
demo-lab-content/banking-finance-e5-activity-scenarios/
  catalogs/
    personas.json
    scenarios.json
    operations.json
    sensitivity-labels.json
  generator/
    README.md
    generate_mvp_dataset.py
    config.py
    event_factory.py
    persona_scheduler.py
    scenario_injector.py
    risk_scoring.py
    exporters.py
    validators.py
  sample-data/
    banking-finance-e5-mvp-synthetic-telemetry-1000.jsonl
    banking-finance-e5-mvp-synthetic-telemetry-1000.csv
    banking-finance-e5-mvp-synthetic-telemetry-1000-validation-report.json
    banking-finance-e5-mvp-scenario-summary.json
    banking-finance-e5-mvp-replay-timeline.json
  adx/
    create-tables.kql
    ingestion-mapping.kql
    sample-ingestion-commands.kql
  detections/
    ai-governance-detections.kql
    dlp-detections.kql
    label-governance-detections.kql
    endpoint-movement-detections.kql
    replay-reconstruction.kql
  validation/
    validate_dataset.py
    validate_synthetic_safety.py
    validate_replay.py
  docs/
    implementation-notes.md
```

---

## Coding Standards

Recommended language for the MVP generator:

```text
Python 3.11+
```

Use only standard library unless a dependency is clearly justified.

Preferred patterns:

- deterministic random seed
- typed functions where practical
- small modules
- explicit constants
- no hidden network calls
- no real-data imports
- no credentials in code
- reproducible outputs

Generated timestamps should be ISO 8601 UTC.

---

## Required Event Fields

Every event must include at minimum:

```text
EventId
TimeGenerated
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
PromptText
ResponsePreview
PolicyName
RuleName
DlpAction
OverrideJustification
AdditionalProperties
```

CSV export should flatten `AdditionalProperties` into:

```text
AdditionalPropertiesJson
```

---

## First MVP Personas

Use these personas first:

```text
Devon Reyes
Ana Rodriguez
Marcus Olsson
Priya Sharma
Alexander Meyer
Carlos Delgado
Emily Johnson
Laura Gomez
```

Devon Reyes must remain the ambiguity anchor.

Do not write Devon as malicious by default.

---

## First MVP Scenarios

Generate first:

```text
BF-SCEN-0002 - AML External AI Shortcut
BF-SCEN-0013 - Label Downgrade Before External Sharing
BF-SCEN-0030 - Devon Multi-Day Risk Chain
BASELINE-NORMAL - Normal daily activity
```

Required event counts should follow:

```text
BF-SCEN-0002: approximately 220
BF-SCEN-0013: approximately 160
BF-SCEN-0030: approximately 280
BASELINE-NORMAL: approximately 340
```

Total:

```text
approximately 1,000 events
```

Allowed tolerance:

```text
950-1,050 events
```

---

## Required Validation Checks

Validation must check:

```text
event count tolerance
required fields present
IsSynthetic always true
RiskScore between 0 and 100
valid severity values
valid scenario IDs
valid persona UPNs
valid operations
valid sensitivity labels
no real-looking secrets
no non-test external domains
required scenario sequences exist
replay timeline is ordered
Power BI expected KPI ranges are plausible
```

Validation report must include:

```text
status
errors
warnings
eventCount
scenarioCounts
personaCounts
operationCounts
riskDistribution
syntheticSafetyStatus
replayValidationStatus
```

---

## Output Naming Rules

Use lower-case paths and stable filenames.

Dataset names should include:

```text
banking-finance-e5
mvp
synthetic-telemetry
1000
```

Do not include customer names in generated filenames.

---

## Testing Expectations

At minimum, Codex should add or support tests for:

```text
validator detects missing required fields
validator detects IsSynthetic false
validator detects invalid risk score
validator detects invalid scenario ID
validator detects invalid label
generator produces deterministic outputs for same seed
generator produces expected scenario counts
generator produces required Devon scenario sequence
CSV and JSONL row counts match
```

---

## First Sprint Plan

## Sprint Goal

Produce the first deterministic offline MVP dataset.

## Sprint Tasks

```text
1. Create catalogs/personas.json
2. Create catalogs/scenarios.json
3. Create catalogs/operations.json
4. Create catalogs/sensitivity-labels.json
5. Create generator/generate_mvp_dataset.py
6. Create generator/validators.py
7. Generate sample-data JSONL
8. Generate sample-data CSV
9. Generate validation report
10. Generate scenario summary
11. Generate replay timeline
12. Add README usage instructions
```

## Sprint Acceptance Criteria

```text
python generator/generate_mvp_dataset.py runs successfully
JSONL output exists
CSV output exists
validation report status is passed
Devon replay timeline exists
no real data appears
outputs are committed
```

---

## Documentation Update Rules

After code or generated outputs change, update:

```text
generator/README.md
sample-data validation report
scenario summary if scenario counts changed
replay timeline if event order changed
implementation-notes.md for notable decisions
```

If schema fields change, update:

```text
synthetic-telemetry-schema.json
powerbi-semantic-model-and-dashboard-blueprint.md
adx-ingestion-and-table-mappings.md
platform-json-schema-and-validation-specification.md
```

---

## Implementation Guardrails

Codex should not:

- silently rename canonical fields
- create new severity values without updating catalogs
- add new personas without updating persona catalog
- create new scenario IDs without updating scenario catalog
- generate real-like secrets or credentials
- use production domains
- assume Microsoft feature availability without caveats
- replace synthetic telemetry with production telemetry
- remove safety disclaimers

---

## Suggested First GitHub Issues

```text
[P0] Create MVP persona catalog
[P0] Create MVP scenario catalog
[P0] Implement deterministic telemetry generator
[P0] Generate 1,000-event MVP dataset
[P0] Add dataset validation report
[P0] Add replay timeline output
[P0] Add ADX table and ingestion mapping
[P0] Add Power BI MVP build notes
[P1] Add synthetic safety scanner
[P1] Add GitHub Actions validation workflow
```

---

## Definition of Done for MVP

The MVP is complete when:

```text
1,000-event dataset exists
CSV and JSONL outputs exist
validation report passes
scenario summary exists
replay timeline exists
Power BI can import the CSV
ADX can ingest the JSONL
KQL replay query can reconstruct BF-SCEN-0030
all data is synthetic
README explains how to regenerate outputs
```

---

## Codex Final Reminder

Build the smallest working path first.

Do not overbuild browser agents, Sentinel, Fabric, or autonomous behavior before the telemetry generator, validation reports, and Power BI-ready dataset exist.

The first success condition is simple:

> A presenter can open Power BI, filter the synthetic dataset, and tell a clear story about Devon, AI governance, DLP, and sensitive data movement.

---

## Safety Reminder

This repository is for synthetic demo and advisory assets only.

Never introduce real users, real customers, real HR records, real legal matters, real financial data, real credentials, real secrets, real production telemetry, or real incident evidence.
