# Synthetic Tenant Information Architecture - Banking / Finance Microsoft 365 E5 Simulation Pack

## Purpose

This document defines the recommended Microsoft 365 tenant information architecture for the synthetic banking and financial-services demo lab.

It describes:

- SharePoint site hierarchy
- Teams structure
- OneDrive usage patterns
- Microsoft Purview sensitivity labels
- external collaboration boundaries
- data ownership model
- restricted workspaces
- AI-approved workspaces
- executive, legal, HR, operations, and security locations
- naming standards
- retention and lifecycle concepts

All examples are fictional and intended for lab/demo use only.

---

## Design Principles

1. Separate sensitive business domains into dedicated collaboration spaces.
2. Use SharePoint and Teams structures that reflect realistic banking operations.
3. Keep external collaboration isolated from internal risk, legal, HR, and regulated data workspaces.
4. Use labels and permissions together; labels alone are not enough.
5. Create both correct and intentionally imperfect areas for demo scenarios.
6. Support Copilot readiness by reducing oversharing and clarifying source ownership.
7. Use synthetic data only.

---

## Recommended Tenant Name

```text
Fabrikam Financial Demo Tenant
```

Recommended test domain examples:

```text
mhdemos.com
fabrikamfinancial.example.test
northbridge-example.test
vendor-review.example.test
```

External domains should remain fake or lab-controlled.

---

## SharePoint Site Architecture

| Site Name | URL Pattern | Owner Role | Sensitivity | Purpose |
|---|---|---|---|---|
| Executive Leadership | `/sites/ExecutiveLeadership` | CEO / Executive Assistant | Highly Confidential | Board decks, executive summaries, strategic plans. |
| HR Restricted | `/sites/HRRestricted` | HR Manager | Highly Confidential - HR Restricted | Compensation planning, workforce planning, role-change documentation. |
| Finance Close | `/sites/FinanceClose` | Finance Director / Data Analyst | Confidential / Highly Confidential | Forecasts, invoices, close evidence, treasury reconciliations. |
| Legal Privileged | `/sites/LegalPrivileged` | Corporate Lawyer | Highly Confidential - Legal Privileged | Legal memos, regulatory response, privileged analysis. |
| Sales and Customer Growth | `/sites/SalesCustomerGrowth` | Sales Manager | Confidential | Customer proposals, pipeline, account plans. |
| Engineering Delivery | `/sites/EngineeringDelivery` | Engineering Manager | Internal / Confidential | Technical designs, deployment notes, change plans. |
| Data Science Lab | `/sites/DataScienceLab` | Data Scientist | Confidential / Highly Confidential | Model features, anonymized datasets, model validation. |
| IT Security Operations | `/sites/ITSecurityOps` | Head of IT / Security | Highly Confidential | Incident notes, DLP reviews, investigation artifacts. |
| Customer Operations | `/sites/CustomerOperations` | Operations Director | Confidential / Highly Confidential | Complaints, support cases, KYC packets, customer escalations. |
| PMO Governance | `/sites/PMOGovernance` | PMO Lead | Internal / Confidential | Steering decks, project trackers, action logs. |
| Vendor Collaboration | `/sites/VendorCollaboration` | Operations Director / Legal | Confidential | Sanitized vendor-facing collaboration only. |
| AI Approved Workspace | `/sites/AIApprovedWorkspace` | Security / Data Governance | Internal / Confidential | Sanitized files approved for Copilot summarization and AI demos. |
| Training and Awareness | `/sites/TrainingAwareness` | Security Awareness Lead | Public / Internal | Synthetic samples, training decks, safe examples. |

---

## SharePoint Document Library Standards

### Executive Leadership

Recommended libraries:

```text
Board Materials
Executive Summaries
Strategic Planning
AI-Generated Drafts
Approved External Versions
```

Recommended controls:

- restricted membership
- default label: Highly Confidential
- external sharing disabled
- versioning enabled
- approval required for board packets

---

### HR Restricted

Recommended libraries:

```text
Compensation Planning
Workforce Planning
Role Change Records
Benefits Review
HR Approved Summaries
```

Recommended controls:

- HR-only membership
- no guest access
- default label: Highly Confidential - HR Restricted
- Copilot exposure review required
- access reviews monthly

---

### Legal Privileged

Recommended libraries:

```text
Privileged Legal Memos
Regulatory Response
Evidence Review
External Counsel Packages
Non-Privileged Action Trackers
```

Recommended controls:

- legal-only default permissions
- external counsel area separated from privileged internal memos
- default label: Highly Confidential - Legal Privileged
- external sharing limited to approved legal domains
- retention and records policies enabled where appropriate

---

### Customer Operations

Recommended libraries:

```text
Customer Complaints
KYC Review
Loan Exceptions
Support Escalations
Customer-Safe Responses
Operations Working Files
```

Recommended controls:

- business-owner managed access
- label recommendations for KYC, AML, complaints, account-like values
- DLP policies for external sharing
- download restrictions for highly sensitive libraries
- separate customer-safe outputs from internal notes

---

### IT Security Operations

Recommended libraries:

```text
DLP Reviews
Insider Risk Reviews
Endpoint Evidence
AI Governance Findings
Access Review Notes
Security Executive Summaries
```

Recommended controls:

- security-only membership
- default label: Highly Confidential
- no guest access
- retention for investigation records
- neutral language guidance for user-risk documentation

---

### Vendor Collaboration

Recommended libraries:

```text
Sanitized Evidence Packages
Vendor Questionnaires
Approved Deliverables
External Meeting Notes
```

Recommended controls:

- guest access allowed only here
- expiration required for guest access
- default label: Confidential
- download restrictions when possible
- no raw KYC, AML, HR, legal privileged, or account-level data

---

## Microsoft Teams Structure

| Team Name | Type | Owners | Guest Access | Purpose |
|---|---|---|---|---|
| Executive Leadership Team | Private | CEO, Executive Assistant | No | Executive alignment and board preparation. |
| HR Restricted Team | Private | HR Manager | No | HR planning and sensitive workforce discussions. |
| Finance Close Team | Private | Finance Director | No | Finance close and forecast coordination. |
| Legal Regulatory Response Team | Private | Corporate Lawyer | Limited only in external counsel channel | Regulatory and legal response. |
| Customer Operations Team | Private | Operations Director | No by default | Complaints, support, KYC, and loan operations. |
| Banking PMO Team | Standard/Internal | PMO Lead | Limited | Project tracking and steering coordination. |
| Vendor Collaboration Team | Shared/Guest-enabled | Operations + Legal | Yes | Sanitized vendor collaboration only. |
| IT Security Operations Team | Private | Head of IT / Security | No | Incident and security investigation coordination. |
| Data Science and Analytics Team | Private | Data Science Lead | No | Model review, analytics, anonymized datasets. |
| Training and Awareness Community | Broad/Internal | Security Awareness Lead | No | Safe examples and training content. |

---

## Recommended Teams Channels

### Customer Operations Team

```text
General
Complaint Intake
KYC Review
Loan Exceptions
Customer-Safe Responses
Restricted Escalations
```

Risk demo opportunity:

Devon posts a KYC link in `General` instead of `Restricted Escalations`.

---

### IT Security Operations Team

```text
General
DLP Review
Endpoint DLP
AI Governance
Insider Risk Review
Access Remediation
Executive Reporting
```

Risk demo opportunity:

Security correlates DLP, endpoint, AI, and HR context into an investigation timeline.

---

### Legal Regulatory Response Team

```text
General
Privileged Legal Review
Evidence Index
External Counsel Coordination
Non-Privileged Action Tracker
```

Risk demo opportunity:

A privileged memo is copied into a shared PMO Loop component.

---

## OneDrive Usage Patterns

OneDrive should represent individual working behavior, not official records.

Recommended patterns:

```text
/Working Files
/Drafts
/Temporary Analysis
/Copilot Drafts
/Customer Operations Working Copies
```

Allowed demo uses:

- normal draft creation
- temporary Excel analysis
- Copilot-generated drafts
- working copies for assigned tasks

Risk demo uses:

- sensitive files copied from restricted SharePoint into personal OneDrive
- stale working copies retained after task completion
- external sharing from personal OneDrive
- raw and sanitized versions stored together

Recommended governance:

- DLP for sensitive content in OneDrive
- sharing restrictions for highly confidential files
- retention cleanup for temporary analysis files
- user coaching for official-record storage

---

## Sensitivity Label Architecture

Recommended labels:

| Label | Intended Use | Example Content |
|---|---|---|
| Public | Approved external/public materials | training flyers, public summaries |
| Internal | Routine internal collaboration | status updates, non-sensitive PMO notes |
| Confidential | business-sensitive internal data | vendor DDQ, operations summaries, finance drafts |
| Highly Confidential | sensitive internal data | executive strategy, security reviews |
| Highly Confidential - Regulated Financial Data | banking/customer/account/AML/KYC/treasury data | AML workbooks, KYC packets, treasury files |
| Highly Confidential - HR Restricted | HR and compensation data | salary planning, role-change notes |
| Highly Confidential - Legal Privileged | privileged or legal-sensitive material | legal memos, regulatory analysis |

---

## Recommended Label Defaults by Location

| Location | Default Label |
|---|---|
| Executive Leadership / Board Materials | Highly Confidential |
| HR Restricted / Compensation Planning | Highly Confidential - HR Restricted |
| Legal Privileged / Privileged Legal Memos | Highly Confidential - Legal Privileged |
| Customer Operations / KYC Review | Highly Confidential - Regulated Financial Data |
| Customer Operations / Customer-Safe Responses | Confidential |
| Finance Close / Treasury Reconciliation | Highly Confidential - Regulated Financial Data |
| Vendor Collaboration / Sanitized Evidence Packages | Confidential |
| Training and Awareness | Internal or Public |
| AI Approved Workspace | Internal or Confidential, depending on source |

---

## Data Ownership Model

| Data Domain | Business Owner | Security Partner | Primary Risks |
|---|---|---|---|
| Executive Strategy | CEO / Executive Assistant | Head of IT / Security | board leakage, Copilot source exposure |
| HR Compensation | HR Manager | Head of IT / Security | compensation exposure, over-permissioning |
| Finance Close | Finance Director / Data Analyst | Security Operations | forecast leakage, treasury movement |
| Legal / Regulatory | Corporate Lawyer | Security Operations | privileged content exposure |
| Customer Operations | Operations Director | Security Operations | KYC, complaints, account data oversharing |
| Data Science | Data Scientist | Data Governance / Security | pre-anonymized data exposure |
| Vendor Collaboration | Operations + Legal | Security Operations | wrong package shared externally |
| Security Investigations | Head of IT / Security | Legal / HR | privacy, investigation handling |

---

## External Collaboration Boundaries

External sharing should be allowed only through controlled locations.

### Allowed

```text
/sites/VendorCollaboration
/sites/LegalPrivileged/External Counsel Packages
approved customer-safe email templates
approved sanitized evidence packages
```

### Not allowed

```text
/sites/HRRestricted
/sites/ITSecurityOps
/sites/CustomerOperations/KYC Review
/sites/CustomerOperations/Loan Exceptions
/sites/FinanceClose/Treasury Reconciliation
/sites/LegalPrivileged/Privileged Legal Memos
```

---

## AI-Approved Workspace Model

The AI Approved Workspace is intended to demonstrate safer Copilot usage.

Recommended content:

- sanitized executive summaries
- aggregated risk summaries
- customer-safe complaint responses
- anonymized datasets
- non-privileged action trackers
- training samples

Not allowed:

- raw AML rows
- SAR drafts
- HR compensation records
- legal privileged analysis
- account-level treasury data
- KYC packets

Demo narrative:

> Copilot becomes safer when users work from governed, labeled, permission-appropriate source content instead of raw sensitive workspaces.

---

## Naming Standards

### File naming pattern

```text
[Domain]_[Description]_[SyntheticId]_[AudienceOrStatus].[extension]
```

Examples:

```text
AML_Monthly_Review_AML-CASE-2026-0519_Internal.xlsx
KYC_Packet_KYC-FIC-88421_Internal.pdf
Vendor_Evidence_Package_VENDOR-FIC-7701_Sanitized.pdf
Board_Risk_Summary_BRD-FIC-2026-05_Final.pptx
HR_Compensation_Planning_ROLE-CHANGE-FIC-2026-05_Restricted.xlsx
```

### Folder naming pattern

```text
[Year]-[Month]_[BusinessCycle]_[SensitivityOrAudience]
```

Examples:

```text
2026-05_AML_Review_Restricted
2026-05_Finance_Close_Internal
2026-05_Regulatory_Response_Privileged
2026-05_Vendor_Evidence_Sanitized
```

---

## Intentional Imperfection Zones

To support realistic demos, create some controlled imperfections.

| Imperfection | Purpose | Example |
|---|---|---|
| Broad inherited permissions | Demonstrate Copilot oversharing risk | HR planning file visible to leadership group |
| Similar raw/sanitized names | Demonstrate wrong attachment risk | `Feature_Matrix_PreAnonymized.xlsx` vs `Feature_Matrix_Anonymized.xlsx` |
| Broad Teams channel | Demonstrate oversharing | KYC link posted in General |
| Personal OneDrive working copies | Demonstrate endpoint/download risk | Devon copies SAR draft into Working Files |
| Guest-enabled workspace | Demonstrate external collaboration governance | Vendor guest added to wrong channel |

These should be controlled and documented so the lab does not become confusing to operate.

---

## Retention and Lifecycle Concepts

Suggested retention approach for demo purposes:

| Content Type | Suggested Retention Concept |
|---|---|
| Customer complaints | retain for case lifecycle plus audit period |
| AML/SAR workbooks | retain as regulated review evidence |
| Finance close evidence | retain by monthly close cycle |
| HR compensation planning | restrict and retain by HR policy |
| Legal privileged memos | retain under legal governance rules |
| Investigation artifacts | retain under security investigation policy |
| Training samples | refresh periodically |
| Temporary working copies | clean up quickly |

This document does not define production retention rules. It only provides demo architecture guidance.

---

## Example Scenario Topology Mapping

| Scenario | Primary Site | Team | Risk Location |
|---|---|---|---|
| Loan Committee Oversharing | Customer Operations | Customer Operations Team | General channel / external advisor email |
| AML External AI Upload | Customer Operations / AML Review | Customer Operations Team | external AI app |
| HR Copilot Exposure | HR Restricted | HR Restricted Team | over-permissioned HR workbook |
| Vendor Due Diligence Guest Exposure | Vendor Collaboration | Vendor Collaboration Team | guest added to internal due diligence space |
| Regulatory Response Leak | Legal Privileged | Legal Regulatory Response Team | PMO shared Loop or broad evidence link |
| Devon Multi-Day Risk Chain | Multiple restricted sites | IT Security Operations Team | OneDrive, endpoint, external AI, network share |

---

## Codex Usage Guidance

Codex should use this document to:

1. Create or simulate SharePoint sites and Teams structures.
2. Place generated documents in the correct logical locations.
3. Apply default labels based on location and content.
4. Decide whether external sharing should be allowed or blocked.
5. Model safe AI usage through the AI Approved Workspace.
6. Model unsafe behavior through intentional imperfection zones.
7. Keep external collaboration restricted to vendor/customer-safe spaces.
8. Preserve consistent naming standards.
9. Generate realistic file paths for telemetry.
10. Avoid production data and real-world identifiers.

---

## Safety Reminder

This information architecture is for synthetic demo environments only.

Do not use real customer, employee, financial, legal, credential, incident, or security data in this structure unless a production governance process explicitly approves it.
