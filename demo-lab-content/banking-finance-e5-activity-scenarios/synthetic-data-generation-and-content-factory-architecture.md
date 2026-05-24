# Synthetic Data Generation and Content Factory Architecture

## Purpose

This document defines the synthetic content manufacturing and lifecycle architecture for the Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It explains how to generate realistic but fictional enterprise content for:

- Office documents
- spreadsheets
- presentations
- PDFs
- CSV files
- Teams conversations
- emails
- AI prompts and responses
- AML/KYC/treasury datasets
- HR and legal content
- support cases
- investigation artifacts
- sanitized external packages
- telemetry enrichment
- file aging and lifecycle rotation

All generated data, people, customers, accounts, identifiers, companies, contracts, cases, incidents, financial values, HR records, legal matters, and telemetry must remain fictional and synthetic.

---

## Core Factory Thesis

> A credible Microsoft 365 governance demo requires more than random files. It requires synthetic business content with lifecycle, sensitivity, ownership, collaboration context, and telemetry consequences.

The content factory should generate:

1. Realistic business artifacts.
2. Fictional sensitive patterns.
3. Raw and sanitized variants.
4. Collaboration context.
5. Labels and lifecycle states.
6. File paths aligned to tenant architecture.
7. Telemetry-ready metadata.
8. Scenario-ready content relationships.

---

## Factory Pipeline

```text
Business cycle selection
        ↓
Persona and department selection
        ↓
Content blueprint selection
        ↓
Synthetic data pattern generation
        ↓
Document body generation
        ↓
Label and sensitivity assignment
        ↓
File path and workspace placement
        ↓
Lifecycle state assignment
        ↓
Related email / Teams / AI prompt generation
        ↓
Telemetry metadata enrichment
        ↓
Safety validation
        ↓
Export or tenant seeding
```

---

## Content Factory Modules

Recommended modules:

```text
/business-cycle-generator
/persona-context-generator
/sensitive-pattern-generator
/document-body-generator
/spreadsheet-generator
/presentation-generator
/email-generator
/teams-thread-generator
/ai-prompt-generator
/sanitization-engine
/label-assignment-engine
/file-placement-engine
/lifecycle-engine
/telemetry-enrichment-engine
/safety-validator
/export-packager
```

---

## Business Cycles

The factory should generate content around recurring banking cycles.

| Cycle | Frequency | Example Content |
|---|---|---|
| Daily Operations | daily | complaint updates, KYC notes, support follow-ups |
| AML Review | weekly/monthly | AML case workbook, suspicious activity summary |
| Finance Close | monthly | forecast, reconciliation, invoice review |
| Treasury Review | weekly/monthly | liquidity report, reconciliation exceptions |
| Loan Committee | weekly | loan package, exception notes, approval deck |
| HR Planning | monthly/quarterly | role-change notes, compensation planning |
| Legal / Regulatory Response | event-driven | privileged memo, regulator response tracker |
| Security Review | daily/weekly | DLP review, investigation timeline, coaching note |
| Executive Reporting | monthly/quarterly | board deck, risk summary, KPI report |
| Vendor Collaboration | event-driven | sanitized evidence package, vendor Q&A |

---

## Synthetic Sensitive Pattern Families

Use only fictional prefixes and values.

Recommended pattern families:

```text
CUST-BNK-[6 digits]
ACCT-FIC-[4]-[4]-[4]-[4]
KYC-FIC-[5 digits]
AML-CASE-[YYYY]-[4 digits]
SAR-DRAFT-FIC-[YYYY]-[4 digits]
TXN-FIC-[YYYYMMDD]-[6 digits]
LOAN-FIC-[YYYY]-[5 digits]
TREAS-FIC-[YYYY]-[4 digits]
INV-FAK-[YYYY]-[5 digits]
EMP-[5 digits]
ROLE-CHANGE-FIC-[YYYY]-[4 digits]
LEGAL-FIC-[YYYY]-[4 digits]
REG-REQ-FIC-[YYYY]-[4 digits]
CASE-IR-FIC-[YYYY]-[4 digits]
```

Prohibited:

- real credit card numbers
- real bank account numbers
- real national IDs
- real addresses
- real credentials
- real secrets
- real customer names
- real production tenant URLs

---

## Content Sensitivity Tiers

| Tier | Description | Typical Label |
|---|---|---|
| Public Training | safe demo examples | Public |
| Internal Coordination | routine internal content | Internal |
| Business Confidential | operational internal content | Confidential |
| Sensitive Regulated | AML, KYC, treasury, legal, HR | Highly Confidential variants |
| Sanitized External | reviewed external-safe output | Confidential |
| Investigation Restricted | security/HR/legal case content | Highly Confidential |

---

## Document Families

## AML / SAR Documents

Examples:

```text
AML_Monthly_Review_AML-CASE-2026-0519_Internal.xlsx
SAR_Draft_Summary_SAR-DRAFT-FIC-2026-0042_Internal.docx
AML_Trend_Summary_AML-CASE-2026-0519_Sanitized.docx
```

Typical fields:

```text
AMLCaseId
CustomerId
AccountLikeId
TransactionId
RiskIndicator
ReviewStatus
AnalystNotes
EscalationFlag
```

---

## KYC / Customer Operations Documents

Examples:

```text
KYC_Packet_KYC-FIC-88421_Internal.pdf
Customer_Complaint_DISPUTE-FIC-60392_Internal.docx
Customer_Response_DISPUTE-FIC-60392_Sanitized.docx
```

Typical fields:

```text
KYCId
CustomerId
CaseOwner
ReviewDate
DocumentChecklist
ExceptionReason
CustomerSafeSummary
```

---

## Treasury and Finance Documents

Examples:

```text
Treasury_Reconciliation_TREAS-FIC-2026-0524_Internal.xlsx
Finance_Forecast_FCST-FIC-2026-Q2_Confidential.xlsx
Invoice_Review_INV-FAK-2026-00421_Internal.xlsx
```

Typical fields:

```text
ReconciliationId
InvoiceId
VendorId
AmountRange
VarianceReason
ApprovalStatus
FinanceOwner
```

---

## HR Documents

Examples:

```text
HR_Compensation_Planning_EMP-Restricted_2026-Q2.xlsx
Role_Change_Notes_ROLE-CHANGE-FIC-2026-0017_Internal.docx
Employee_Case_Summary_EMP-48291_HRRestricted.docx
```

Typical fields:

```text
EmployeeId
RoleChangeId
SalaryBand
Manager
EffectiveDate
HRNotes
AccessReviewRequired
```

---

## Legal Documents

Examples:

```text
Legal_Privileged_Memo_LEGAL-FIC-2026-0031_Privileged.docx
Regulatory_Response_Tracker_REG-REQ-FIC-2026-0011_Internal.xlsx
NonPrivileged_Action_Summary_LEGAL-FIC-2026-0031_Sanitized.docx
```

Typical fields:

```text
LegalMatterId
RegulatoryRequestId
PrivilegeStatus
DisclosureRisk
ActionOwner
DueDate
ExternalCounselRequired
```

---

## Security and Investigation Documents

Examples:

```text
Devon_Investigation_Case_Summary_CASE-IR-FIC-2026-0001.docx
DLP_Override_Review_CASE-DLP-FIC-2026-0004.xlsx
AI_Governance_Review_CASE-AI-FIC-2026-0002.docx
```

Typical fields:

```text
CaseId
ScenarioId
PrimaryUser
ObservedSignals
AffectedFiles
RiskScore
ReviewerNotes
ClosurePath
```

---

## Raw vs Sanitized Variant Generation

Every high-risk raw document should optionally produce a sanitized derivative.

Example pair:

```text
AML_Monthly_Review_AML-CASE-2026-0519_Internal.xlsx
AML_Trend_Summary_AML-CASE-2026-0519_Sanitized.docx
```

Sanitization rules:

- remove row-level customer-like identifiers
- aggregate financial values into ranges
- remove employee-specific details
- remove privileged legal analysis
- replace detailed case notes with high-level themes
- preserve enough business value for external or executive review

---

## Label Assignment Engine

Recommended label logic:

| Content Pattern | Suggested Label |
|---|---|
| training-only examples | Public |
| routine internal updates | Internal |
| finance forecast | Confidential |
| raw AML/KYC/treasury | Highly Confidential - Regulated Financial Data |
| HR compensation or role-change | Highly Confidential - HR Restricted |
| privileged legal memo | Highly Confidential - Legal Privileged |
| sanitized external package | Confidential |
| investigation case summary | Highly Confidential |

---

## File Placement Engine

Place files according to collaboration architecture.

Examples:

```text
Raw AML workbook
→ /sites/CustomerOperations/AML Raw Review/

Sanitized AML summary
→ /sites/AIApprovedWorkspace/Anonymized Analytics Datasets/

Vendor-ready package
→ /sites/VendorCollaboration/Sanitized Evidence Packages/

Security investigation summary
→ /sites/ITSecurityOps/Security Investigation Evidence/
```

---

## Email and Teams Companion Generation

Each generated document family should optionally create related communications.

Examples:

```text
Document created
        ↓
Teams message asks for review
        ↓
Email requests approval
        ↓
DLP warning or sharing event occurs
        ↓
Security follow-up message generated
```

Communication types:

- review request
- approval request
- external sharing request
- clarification message
- urgent escalation
- correction after mistake
- coaching note

---

## AI Prompt Companion Generation

Generate safe and unsafe prompts linked to source files.

Safe prompt example:

```text
Summarize the sanitized AML trend summary into three executive bullets. Exclude customer identifiers and case-level details.
```

Unsafe prompt example:

```text
Summarize these AML rows and identify the highest-risk customers: CUST-BNK-884210, ACCT-FIC-7721-0044-9081, AML-CASE-2026-0519.
```

Prompt metadata:

```text
PromptId
SourceFileName
PersonaName
AppName
IsManagedAI
PromptRiskCategory
ExpectedRiskScore
ExpectedControlSignal
```

---

## Lifecycle and Aging Engine

Documents should age naturally.

Lifecycle states:

```text
Created
Draft
In Review
Approved Internal
Sanitized
Approved External
Shared
Archived
Expired
Deleted
```

Aging patterns:

| Age | Behavior |
|---|---|
| same day | active edits, Teams discussion |
| 1-3 days | review, sharing, AI summary |
| 1 week | dashboard/report usage |
| 1 month | archive or close-cycle reference |
| 3+ months | stale access or lifecycle review |

---

## Freshness Rotation

To keep the tenant realistic, periodically generate:

- new monthly finance files
- new AML cases
- new KYC packets
- new executive summaries
- new DLP review notes
- new sanitized vendor packages
- new training examples

Recommended cadence:

```text
Daily: Teams/email noise and support notes
Weekly: AML/KYC/security review files
Monthly: finance close, treasury, executive reporting
Quarterly: HR planning, board materials, compliance review
```

---

## Telemetry Enrichment

Generated content should include metadata useful for telemetry.

Recommended metadata fields:

```text
FileName
FileType
FilePath
SiteUrl
LibraryName
FileOwner
Department
DataDomain
SensitivityLabel
LifecycleState
ScenarioId
CorrelationId
SyntheticPatternFamilies
CreatedByPersona
BusinessCycle
IsRaw
IsSanitized
IsExternalReady
IsAIApproved
```

---

## Content Quality Rules

Generated content should:

- use department-appropriate language
- include plausible business context
- avoid real entities
- include fictional identifiers only
- contain enough detail for DLP testing
- avoid excessive repetition
- include raw and sanitized variants where appropriate
- align with file paths and labels
- support downstream telemetry and Power BI visuals

---

## Validation Rules

The factory should fail or warn when:

- real-looking secrets appear
- real-looking financial identifiers appear without synthetic prefixes
- external domains are not test/fake domains
- raw content is placed in AI Approved Workspace without intentional risk scenario
- raw content is placed in Vendor Collaboration without intentional risk scenario
- file label does not match content sensitivity
- sanitized file still contains raw identifiers
- required metadata is missing

---

## Recommended Output Package

```text
content-output/
  documents/
  spreadsheets/
  presentations/
  pdfs/
  emails/
  teams-threads/
  ai-prompts/
  metadata/
  validation-reports/
```

Recommended metadata file:

```text
content-output/metadata/generated-content-manifest.json
```

Manifest fields:

```text
ContentId
FileName
FileType
Department
DataDomain
SensitivityLabel
LifecycleState
ScenarioId
CorrelationId
IsRaw
IsSanitized
IsExternalReady
IsAIApproved
RelatedEmails
RelatedTeamsThreads
RelatedPrompts
ExpectedTelemetryEvents
```

---

## MVP Content Factory Scope

For the first MVP, generate:

```text
20 documents/spreadsheets/presentations
30 emails
40 Teams messages
20 AI prompts
3 investigation artifacts
3 sanitized external packages
1 content manifest
1 validation report
```

Focus on:

- AML External AI Shortcut
- Label Downgrade Before External Sharing
- Devon Multi-Day Risk Chain

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate synthetic business documents.
2. Generate fake sensitive patterns safely.
3. Create raw and sanitized file variants.
4. Generate related emails, Teams threads, and AI prompts.
5. Assign labels and lifecycle states.
6. Place content in realistic SharePoint/OneDrive paths.
7. Generate metadata manifests.
8. Enrich telemetry with content metadata.
9. Rotate content for long-term tenant realism.
10. Preserve synthetic-only boundaries.

---

## Safety Reminder

The content factory must never generate, ingest, copy, or transform real customer data, real employee data, real financial transactions, real HR records, real legal records, real credentials, real secrets, real production telemetry, or real incident evidence.

All outputs must remain fictional, synthetic, and safe for demo use.
