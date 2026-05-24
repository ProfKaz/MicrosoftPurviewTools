# Sample Synthetic Telemetry Dataset Specification

## Purpose

This document defines the first minimum viable synthetic telemetry dataset for the Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It specifies:

- 1,000-event MVP dataset composition
- persona distribution
- workload distribution
- scenario distribution
- risk-to-noise ratio
- timeline layout
- ADX-ready JSONL format
- Power BI-ready CSV format
- deterministic seed values
- expected dashboard outputs
- validation expectations
- sample generation instructions

All data must remain fictional, synthetic, and safe for demo use.

---

## Dataset Name

```text
banking-finance-e5-mvp-synthetic-telemetry-1000
```

Recommended version:

```text
1.0.0
```

Recommended seed:

```text
BF-MVP-1000-2026-05-24-v1
```

---

## Dataset Goals

The first MVP dataset should prove that the platform can show:

1. Normal daily Microsoft 365 activity.
2. Sensitive banking data handling.
3. DLP and label events.
4. Safe and unsafe AI usage.
5. External sharing risk.
6. Endpoint movement.
7. Scenario replay.
8. Devon-centered ambiguous risk chain.
9. Power BI executive risk summary.
10. SOC-style investigation timeline.

---

## Event Volume

Target event count:

```text
1,000 events
```

Allowed tolerance:

```text
950-1,050 events
```

This size is large enough to produce realistic dashboards but small enough for fast Power BI import mode and easy validation.

---

## Dataset Time Window

Recommended simulated period:

```text
5 business days
```

Example:

```text
2026-05-18 08:00 local time
through
2026-05-22 18:30 local time
```

Recommended timezone assumption:

```text
America/Bogota
```

Use UTC in telemetry fields:

```text
TimeGenerated = ISO 8601 UTC datetime
```

---

## Persona Distribution

Minimum MVP personas:

| Persona | UPN | Target Events | Purpose |
|---|---|---:|---|
| Devon Reyes | devon.reyes@mhdemos.com | 260 | primary ambiguous risk anchor |
| Ana Rodriguez | ana.rodriguez@mhdemos.com | 160 | security leadership and investigation owner |
| Marcus Olsson | marcus.olsson@mhdemos.com | 150 | SOC and DLP review |
| Priya Sharma | priya.sharma@mhdemos.com | 150 | AI and analytics workflows |
| Alexander Meyer | alexander.meyer@mhdemos.com | 100 | executive summaries and board narrative |
| Carlos Delgado | carlos.delgado@mhdemos.com | 90 | Power BI and finance analytics |
| Emily Johnson | emily.johnson@mhdemos.com | 50 | legal and privileged review |
| Laura Gomez | laura.gomez@mhdemos.com | 40 | HR context and role-change support |

Total:

```text
1,000 events
```

---

## Workload Distribution

Recommended distribution:

| Workload | Target Events | Percent |
|---|---:|---:|
| SharePoint Online | 230 | 23% |
| OneDrive for Business | 120 | 12% |
| Microsoft Teams | 180 | 18% |
| Exchange Online | 120 | 12% |
| Microsoft Copilot | 80 | 8% |
| External AI App | 45 | 4.5% |
| Microsoft Purview DLP | 95 | 9.5% |
| Endpoint DLP | 55 | 5.5% |
| Entra ID / Identity | 35 | 3.5% |
| Power BI | 40 | 4% |

Total:

```text
1,000 events
```

---

## Scenario Distribution

The MVP dataset should include three primary scenarios and baseline noise.

| Scenario | Scenario ID | Target Events | Purpose |
|---|---|---:|---|
| AML External AI Shortcut | BF-SCEN-0002 | 220 | AI governance and unmanaged AI risk |
| Label Downgrade Before External Sharing | BF-SCEN-0013 | 160 | label governance and DLP override |
| Devon Multi-Day Risk Chain | BF-SCEN-0030 | 280 | flagship investigation storyline |
| Baseline Normal Activity | BASELINE-NORMAL | 340 | realistic business activity and noise |

Total:

```text
1,000 events
```

---

## Risk-to-Noise Ratio

Recommended ratio:

| Category | Target Events | Percent |
|---|---:|---:|
| Normal / non-risk activity | 670 | 67% |
| Low-risk governance activity | 120 | 12% |
| Medium-risk activity | 90 | 9% |
| High-risk activity | 85 | 8.5% |
| Critical correlated risk activity | 35 | 3.5% |

This keeps the dataset realistic. Most enterprise activity should not be risky.

---

## Operation Distribution

Recommended operation distribution:

| Operation | Target Count |
|---|---:|
| FileAccessed | 110 |
| FileCreated | 55 |
| FileModified | 95 |
| FileDownloaded | 80 |
| FileShared | 45 |
| TeamsMessageSent | 125 |
| ExternalEmailSent | 45 |
| InternalEmailSent | 75 |
| CopilotInteraction | 80 |
| AIAppInteraction | 35 |
| UnmanagedAppUpload | 10 |
| DLPPolicyMatch | 45 |
| DLPWarned | 20 |
| DLPOverride | 10 |
| DLPBlocked | 20 |
| SensitivityLabelApplied | 45 |
| SensitivityLabelChanged | 20 |
| LabelDowngrade | 8 |
| SensitivityLabelRemoved | 2 |
| FilePrinted | 20 |
| FileCopiedToNetworkShare | 15 |
| FileCopiedToUSB | 5 |
| EndpointDLPPolicyMatch | 15 |
| RiskySignIn | 5 |
| ConditionalAccessTriggered | 10 |
| MFARequired | 10 |
| PowerBIReportViewed | 25 |
| PowerBIExported | 15 |
| GuestUserAdded | 5 |
| ExternalUserAccessed | 10 |
| HRSignal | 5 |
| MassDownloadActivity | 5 |
| InsiderRiskSequence | 5 |

Approximate total:

```text
1,000 events
```

Minor variation is acceptable if validation passes.

---

## Required Scenario Timelines

## BF-SCEN-0002 - AML External AI Shortcut

Required sequence:

```text
Priya or Devon accesses AML workbook
        ↓
FileDownloaded
        ↓
AIAppInteraction or UnmanagedAppUpload
        ↓
DLPPolicyMatch
        ↓
Teams clarification with Security
        ↓
Coaching or approved Copilot alternative
```

Required synthetic files:

```text
AML_Monthly_Review_AML-CASE-2026-0519_Internal.xlsx
AML_Trend_Summary_AML-CASE-2026-0519_Sanitized.docx
AI_Prompt_Transcript_AML-CASE-2026-0519.txt
```

---

## BF-SCEN-0013 - Label Downgrade Before External Sharing

Required sequence:

```text
Sensitive file created or modified
        ↓
SensitivityLabelChanged
        ↓
LabelDowngrade
        ↓
ExternalEmailSent or FileShared
        ↓
DLPWarned
        ↓
DLPOverride or DLPBlocked
        ↓
Security review
```

Required synthetic files:

```text
Vendor_Evidence_Package_VENDOR-FIC-7701_Internal.docx
Vendor_Evidence_Package_VENDOR-FIC-7701_Sanitized.pdf
Label_Downgrade_Justification_VENDOR-FIC-7701.txt
```

---

## BF-SCEN-0030 - Devon Multi-Day Risk Chain

Required sequence:

```text
Day 1: Devon accesses KYC and complaint files
Day 2: Devon downloads AML and support files
Day 3: Devon uses external AI with sensitive rows
Day 4: Devon overrides DLP warning before external send
Day 5: Devon prints or copies a sensitive file to network share
Day 5: Security opens investigation and correlates the sequence
```

Required synthetic files:

```text
KYC_Packet_KYC-FIC-88421_Internal.pdf
Customer_Complaint_DISPUTE-FIC-60392_Internal.docx
AML_Monthly_Review_AML-CASE-2026-0519_Internal.xlsx
Treasury_Reconciliation_TREAS-FIC-2026-0524_Internal.xlsx
Devon_Investigation_Case_Summary_CASE-IR-FIC-2026-0001.docx
```

---

## Baseline Normal Activity

Baseline events should include:

- Teams project coordination
- internal email follow-ups
- SharePoint edits
- OneDrive drafts
- Copilot summaries over safe content
- Power BI report views
- routine label application
- normal file access

Baseline should include a few low-risk alerts but should not dominate the story.

---

## ADX-Ready JSONL Format

Each line should be one complete JSON object.

Example:

```json
{"EventId":"EVT-BF-20260518-000001","TimeGenerated":"2026-05-18T13:05:00Z","ScenarioId":"BASELINE-NORMAL","CorrelationId":"CORR-BASELINE-20260518-001","UserPrincipalName":"alexander.meyer@mhdemos.com","PersonaName":"Alexander Meyer","Department":"Executive Leadership","Workload":"Microsoft Copilot","Operation":"CopilotInteraction","Severity":"Low","RiskScore":8,"IsRiskEvent":false,"IsSynthetic":true,"BusinessContext":"Executive summary preparation using approved board notes.","FileName":"Board_Risk_Summary_BRD-FIC-2026-05_Final.pptx","SensitivityLabel":"Highly Confidential","Recipient":"","TargetDomain":"","DeviceId":"","AppName":"Microsoft Copilot","PolicyName":"","DlpAction":"","AdditionalProperties":{"PromptCategory":"ExecutiveSummary","ApprovedSource":true}}
```

---

## Power BI-Ready CSV Columns

Recommended columns:

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
AdditionalPropertiesJson
```

---

## Expected Power BI Outputs

The 1,000-event MVP dataset should produce these approximate dashboard outcomes.

### Executive Risk Snapshot

Expected values:

```text
Total Events: approximately 1,000
Risk Events: approximately 200-330
High or Critical Events: approximately 90-130
External Sharing Events: approximately 55-75
Sensitive AI Events: approximately 35-60
Endpoint Movement Events: approximately 35-45
Distinct Risky Users: approximately 4-6
```

### AI and Copilot Risk

Expected values:

```text
Copilot Interactions: approximately 80
External AI Interactions: approximately 35
Unmanaged AI Uploads: approximately 10
Sensitive AI Events: approximately 35-60
External AI Share of AI Activity: approximately 25-35%
```

### DLP Operations

Expected values:

```text
DLP Matches: approximately 45
DLP Warnings: approximately 20
DLP Overrides: approximately 10
DLP Blocks: approximately 20
DLP Override Rate: approximately 40-60%
```

### Scenario Replay

Expected:

```text
BF-SCEN-0030 should show a coherent 5-day Devon timeline.
BF-SCEN-0002 should show external AI risk after AML file access.
BF-SCEN-0013 should show label downgrade followed by sharing attempt.
```

---

## Validation Expectations

The dataset passes validation when:

1. Event count is between 950 and 1,050.
2. Every event has `IsSynthetic = true`.
3. All scenario IDs are valid or explicitly marked baseline.
4. All UPNs belong to synthetic personas.
5. All external domains are fake or test domains.
6. All sensitive-looking data uses approved fictional prefixes.
7. Risk scores are between 0 and 100.
8. Severity values are valid.
9. Required scenario sequences exist.
10. Power BI expected metrics fall within target ranges.

---

## Sample Generation Instructions

Codex or a generator should:

1. Load persona definitions.
2. Load scenario definitions.
3. Load operation distribution targets.
4. Generate timestamps across five business days.
5. Generate baseline activity first.
6. Generate scenario-specific timelines second.
7. Add DLP, AI, endpoint, and investigation events.
8. Apply deterministic seed.
9. Write ADX-ready JSONL.
10. Write Power BI-ready CSV.
11. Produce validation report.

---

## Recommended Output Files

When the generator is implemented, produce:

```text
sample-data/banking-finance-e5-mvp-synthetic-telemetry-1000.jsonl
sample-data/banking-finance-e5-mvp-synthetic-telemetry-1000.csv
sample-data/banking-finance-e5-mvp-synthetic-telemetry-1000-validation-report.json
sample-data/banking-finance-e5-mvp-scenario-summary.json
```

---

## Dataset Safety Rules

The generator must not create:

- real credit card numbers
- real bank account numbers
- real national IDs
- real addresses
- real credentials
- real secrets
- real customer names
- real company names as customers
- real production URLs
- real employee records

Use only fictional patterns from:

```text
synthetic-data-pattern-library.json
```

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate the first MVP sample dataset.
2. Create data generators for JSONL and CSV.
3. Validate scenario distribution.
4. Validate persona and workload distribution.
5. Create Power BI-ready demo data.
6. Create ADX ingestion-ready files.
7. Confirm expected dashboard outputs.
8. Preserve synthetic-only constraints.

---

## Safety Reminder

This dataset specification is for synthetic telemetry only.

Do not generate, import, or process real Microsoft 365 production logs, real user activity, real customer data, real HR records, real legal matters, real credentials, or real financial transactions.
