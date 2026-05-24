# Synthetic Tenant Information Architecture and Collaboration Model

## Purpose

This document defines the collaboration-governance model for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It expands the tenant architecture into practical collaboration patterns for:

- SharePoint sites
- Microsoft Teams teams and channels
- OneDrive working areas
- raw vs sanitized data zones
- AI Approved Workspace placement
- external collaboration boundaries
- guest access
- file-path conventions
- document lifecycle flows
- retention-zone concepts
- collaboration anti-patterns

All examples, users, files, identifiers, customers, telemetry, and business records are fictional and synthetic.

---

## Core Collaboration Thesis

> Information architecture is a security control. Sensitive data becomes easier to protect when collaboration spaces clearly separate raw data, working drafts, approved internal outputs, sanitized external packages, and AI-approved sources.

Supporting principles:

1. Raw data and sanitized data should not live in the same casual workspace.
2. Guest-enabled collaboration should be isolated from restricted internal workspaces.
3. OneDrive should be treated as a personal working area, not an official system of record.
4. Teams channels should reflect audience and sensitivity boundaries.
5. AI-approved content should be curated before Copilot or other AI tools use it broadly.
6. Naming standards should make wrong-file selection less likely.
7. Controlled imperfections should exist in the lab to demonstrate realistic risk.

---

## Collaboration Zone Model

Recommended zones:

| Zone | Purpose | External Access | Typical Label |
|---|---|---|---|
| Restricted Raw Data Zone | AML, KYC, treasury, HR, legal privileged source material | No | Highly Confidential variants |
| Internal Working Zone | internal analysis, drafts, reviews | No by default | Confidential / Highly Confidential |
| Approved Internal Output Zone | reviewed internal summaries and dashboards | No or limited | Internal / Confidential |
| Sanitized External Package Zone | external-ready vendor/customer/legal packages | Yes, controlled | Confidential |
| AI Approved Workspace | curated, sanitized, AI-safe content | No external by default | Internal / Confidential |
| Training and Awareness Zone | synthetic examples and safe training files | broad internal | Public / Internal |

---

## SharePoint Site Model

| Site | Primary Zone | External Sharing | Notes |
|---|---|---|---|
| `/sites/ExecutiveLeadership` | Restricted / Approved Internal | Disabled | Board decks, executive risk summaries. |
| `/sites/HRRestricted` | Restricted Raw Data | Disabled | Compensation, employee, workforce data. |
| `/sites/FinanceClose` | Restricted / Internal Working | Disabled | Forecasts, reconciliation, close evidence. |
| `/sites/LegalPrivileged` | Restricted Raw Data | Limited external counsel area only | Legal memos and regulatory response. |
| `/sites/CustomerOperations` | Restricted / Internal Working | Disabled by default | KYC, complaints, loan exceptions. |
| `/sites/ITSecurityOps` | Restricted / Internal Working | Disabled | DLP, endpoint, AI, investigation evidence. |
| `/sites/VendorCollaboration` | Sanitized External Package Zone | Enabled and controlled | Only approved sanitized content. |
| `/sites/AIApprovedWorkspace` | AI Approved Workspace | Disabled by default | Curated AI-safe sources. |
| `/sites/TrainingAwareness` | Training Zone | Internal broad access | Synthetic training examples. |

---

## Recommended Document Libraries by Zone

## Restricted Raw Data Zone

Examples:

```text
AML Raw Review
KYC Source Packets
Treasury Reconciliation Raw
HR Compensation Restricted
Legal Privileged Memos
Security Investigation Evidence
```

Controls:

- restricted membership
- no guest access
- highly confidential default label
- DLP and Endpoint DLP
- access reviews
- download and sharing restrictions where appropriate

---

## Internal Working Zone

Examples:

```text
Operations Working Drafts
Finance Analysis Drafts
Regulatory Response Drafts
Security Review Working Files
PMO Internal Trackers
```

Controls:

- department-level membership
- internal sharing only
- label recommendations
- versioning enabled
- data owner approval for promotion to output zones

---

## Approved Internal Output Zone

Examples:

```text
Executive Summaries
Approved Risk Dashboards
Internal Steering Materials
Non-Privileged Action Trackers
Approved Management Briefs
```

Controls:

- reviewed content only
- clear owner approval
- no raw customer rows
- labels aligned to audience
- Copilot-safe review when relevant

---

## Sanitized External Package Zone

Examples:

```text
Vendor Evidence Packages
Customer-Safe Responses
External Counsel Packages
Sanitized Audit Responses
Approved Third-Party Deliverables
```

Controls:

- named-user external sharing
- guest expiration
- DLP scan before sharing
- sanitized naming convention
- no raw AML, SAR, KYC, HR, legal privileged, or treasury source files

---

## AI Approved Workspace

Examples:

```text
Sanitized Customer Operations Data
Approved Executive Summaries
Anonymized Analytics Datasets
Approved Prompt Examples
AI Output Review Queue
```

Controls:

- curated source content
- data owner approval
- label and DLP checks
- no raw regulated row-level data
- output review queue
- periodic access review

---

## Teams Structure and Channel Taxonomy

## Recommended Channel Types

| Channel Type | Purpose | Example |
|---|---|---|
| General | low-sensitivity coordination | routine updates only |
| Restricted | sensitive internal discussion | KYC Review, Legal Privileged Review |
| External Coordination | guest-enabled, sanitized only | Vendor Evidence Review |
| Executive | limited leadership discussion | Board Prep |
| Incident / War Room | case-specific security coordination | IR Review - CASE-IR-FIC-2026-0001 |
| AI Review | governed AI content discussion | AI Output Review |

---

## Example Team: Customer Operations Team

Channels:

```text
General
Complaint Intake
KYC Review
Loan Exceptions
Customer-Safe Responses
Restricted Escalations
```

Expected behavior:

- `General` should not contain raw KYC or AML files.
- `Customer-Safe Responses` should contain sanitized outputs.
- `Restricted Escalations` should contain sensitive internal review.

Demo risk pattern:

```text
Devon posts a raw KYC packet link in General instead of Restricted Escalations.
```

---

## Example Team: IT Security Operations Team

Channels:

```text
General
DLP Review
Endpoint DLP
AI Governance
Insider Risk Review
Access Remediation
Executive Reporting
```

Expected behavior:

- security evidence should remain in restricted channels.
- executive summaries should avoid raw evidence unless required.
- case-specific reviews should use dedicated war-room threads.

---

## Example Team: Vendor Collaboration Team

Channels:

```text
General
Vendor Evidence Review
Approved Deliverables
Questions and Clarifications
```

Expected behavior:

- only sanitized content is shared.
- raw evidence packages are not posted.
- guests are time-bound.
- data owner confirms package readiness.

Demo risk pattern:

```text
A user uploads Vendor_Evidence_Package_VENDOR-FIC-7701_Internal.docx instead of Vendor_Evidence_Package_VENDOR-FIC-7701_Sanitized.pdf.
```

---

## OneDrive Usage Model

OneDrive represents personal productivity and working drafts.

Allowed synthetic behaviors:

- draft notes
- temporary working copies
- personal Copilot drafts
- internal analysis drafts
- meeting preparation

Risk behaviors:

- long-term storage of restricted files
- external sharing from personal OneDrive
- raw and sanitized files kept together
- endpoint download before external send
- local copy after role-change context

Recommended folders:

```text
/Working Files
/Drafts
/Copilot Drafts
/Temporary Analysis
/Files To Review
```

Governance message:

> OneDrive is useful for individual work, but sensitive official records should live in governed SharePoint locations with clear ownership and controls.

---

## Raw vs Sanitized Data Flow

Recommended lifecycle:

```text
Raw source file
        ↓
Restricted review
        ↓
Internal analysis draft
        ↓
Sanitization step
        ↓
Data owner approval
        ↓
Approved internal output or external package
        ↓
AI-approved copy only if safe
```

---

## File Naming Conventions

Recommended pattern:

```text
[Domain]_[Description]_[SyntheticId]_[AudienceOrStatus].[extension]
```

Examples:

```text
AML_Monthly_Review_AML-CASE-2026-0519_Internal.xlsx
AML_Trend_Summary_AML-CASE-2026-0519_Sanitized.docx
KYC_Packet_KYC-FIC-88421_Internal.pdf
Vendor_Evidence_Package_VENDOR-FIC-7701_Sanitized.pdf
Board_Risk_Summary_BRD-FIC-2026-05_Final.pptx
```

Required status terms:

```text
Raw
Internal
Draft
Reviewed
Sanitized
Approved
Final
External
```

Risk pattern:

> Similar filenames with `Internal` and `Sanitized` are useful for demonstrating realistic wrong-attachment risk, but they should be controlled and documented.

---

## File Path Conventions

Recommended path pattern:

```text
/sites/[SiteName]/[LibraryName]/[Year-Month]_[BusinessCycle]_[Sensitivity]/[FileName]
```

Examples:

```text
/sites/CustomerOperations/KYC Review/2026-05_KYC_Review_Restricted/KYC_Packet_KYC-FIC-88421_Internal.pdf
/sites/VendorCollaboration/Sanitized Evidence Packages/2026-05_Vendor_Evidence_Sanitized/Vendor_Evidence_Package_VENDOR-FIC-7701_Sanitized.pdf
/sites/AIApprovedWorkspace/Anonymized Analytics Datasets/2026-05_AML_Analytics_Approved/AML_Trend_Summary_AML-CASE-2026-0519_Sanitized.docx
```

---

## Guest Access Model

Guest access should be exceptional, controlled, and isolated.

Recommended rules:

1. Guests should be added only to vendor or external collaboration zones.
2. Guest access should expire.
3. Guest access should use named users, not anonymous links.
4. Sensitive internal workspaces should not allow guests.
5. Data owner approval should be required for external packages.
6. External access should be reviewed after each scenario.

Demo signal examples:

```text
GuestUserAdded
ExternalUserAccessed
FileShared
DLPPolicyMatch
ExternalEmailSent
```

---

## Document Lifecycle States

Recommended document states:

```text
Created
Draft
Internal Review
Sensitive Review
Sanitized
Approved Internal
Approved External
Archived
Expired
```

Lifecycle example:

```text
KYC source packet created
        ↓
Internal review in Customer Operations
        ↓
Sanitized summary created
        ↓
Data owner approves external package
        ↓
File shared through Vendor Collaboration
        ↓
External link expires
        ↓
Package archived
```

---

## Retention Zone Concepts

| Zone | Retention Concept |
|---|---|
| AML / SAR source | regulated review evidence retention |
| KYC source packets | case lifecycle plus audit period |
| Finance close | monthly close evidence retention |
| HR compensation | restricted HR retention |
| Legal privileged | legal governance retention |
| Security investigation | investigation record retention |
| Temporary drafts | short lifecycle cleanup |
| Training samples | periodic refresh |

This is conceptual and does not define production retention schedules.

---

## Collaboration Anti-Patterns

Use these as controlled demo scenarios.

| Anti-Pattern | Risk | Safer Alternative |
|---|---|---|
| Raw KYC file posted in General channel | broad internal exposure | restricted KYC channel |
| Internal vendor package sent externally | sensitive leakage | sanitized external package |
| HR workbook stored in broadly accessible site | Copilot source exposure | HR Restricted site |
| Legal privileged memo copied into PMO tracker | privilege exposure | non-privileged action tracker |
| Raw and sanitized files stored together | wrong file selection | separate raw and sanitized zones |
| External AI prompt from raw AML workbook | unmanaged AI exposure | AI Approved Workspace |
| OneDrive external sharing of regulated file | uncontrolled sharing path | Vendor Collaboration site |
| Guest added to internal team | overexposure | guest-only collaboration team |

---

## Controlled Imperfections

The lab should include some imperfections to remain realistic.

Recommended controlled imperfections:

- one over-permissioned HR file
- one ambiguous raw vs sanitized file pair
- one broad internal Teams channel mistake
- one external guest added to the wrong collaboration area
- one user working-copy in OneDrive
- one AI prompt using unsafe source content

Each imperfection must be documented so the demo remains understandable.

---

## Collaboration Signals for Telemetry

Recommended operations:

```text
FileCreated
FileModified
FileAccessed
FileDownloaded
FileShared
ExternalUserAccessed
GuestUserAdded
TeamsMessageSent
ExternalEmailSent
SensitivityLabelApplied
SensitivityLabelChanged
LabelDowngrade
DLPPolicyMatch
DLPWarned
DLPOverride
DLPBlocked
CopilotInteraction
AIAppInteraction
UnmanagedAppUpload
```

---

## Recommended Collaboration Governance KPIs

```text
Files Shared Externally
Guest Users Added
Sensitive Files in Guest-Enabled Spaces
Raw Files Shared Outside Restricted Zones
Sanitized Packages Created
DLP Matches on External Packages
AI Approved Workspace Usage
OneDrive Sensitive Working Copies
Label Downgrades Before Sharing
External Access Expired On Time
```

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate SharePoint site and library structures.
2. Generate Teams and channel layouts.
3. Place generated files in realistic paths.
4. Separate raw, internal, sanitized, external, and AI-approved content.
5. Create realistic external sharing scenarios.
6. Generate collaboration anti-patterns for demos.
7. Generate file-path conventions for telemetry.
8. Create guest-access and collaboration-governance scenarios.
9. Preserve synthetic-only boundaries.
10. Avoid placing raw regulated data in AI-approved or external zones unless intentionally simulating a mistake.

---

## Safety Reminder

This collaboration model is for synthetic demo environments only.

Do not use real customer data, real HR data, real legal records, real financial information, real credentials, real production telemetry, or real incident evidence in these sites, teams, folders, or files.
