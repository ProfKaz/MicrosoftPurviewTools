# Purview Policy and Control Matrix - Banking / Finance Microsoft 365 E5 Simulation Pack

## Purpose

This document defines the recommended Microsoft Purview, Defender, Entra, Endpoint, and AI governance control plane for the synthetic banking and financial-services Microsoft 365 E5 demo lab.

It maps fictional scenarios and synthetic telemetry to:

- Microsoft Purview Data Loss Prevention
- Sensitivity labels
- Auto-labeling concepts
- Endpoint DLP
- Insider Risk indicators
- Adaptive Protection concepts
- DSPM for AI
- Defender for Cloud Apps governance
- Conditional Access and Conditional Access for Sites concepts
- Retention and records management concepts
- user coaching and override workflows
- false-positive and false-negative simulation guidance

All examples are synthetic and intended for demo, lab, and education use only.

---

## Control Plane Principles

1. Use controls to guide behavior, not only to block behavior.
2. Combine labels, permissions, DLP, endpoint controls, AI governance, and identity signals.
3. Avoid treating a single signal as proof of malicious intent.
4. Preserve business context when reviewing risky user behavior.
5. Keep AI governance connected to data governance.
6. Use synthetic false positives and false negatives to teach tuning, not to imply policy failure.
7. Never use real customer, employee, legal, financial, or incident data in the demo pack.

---

## Recommended Sensitivity Label Taxonomy

| Label | Purpose | Example Synthetic Content | Recommended Protection |
|---|---|---|---|
| Public | Approved public/demo material | public training flyer | no encryption |
| Internal | routine internal collaboration | PMO status, non-sensitive updates | internal marking only |
| Confidential | business-sensitive information | vendor DDQ, project tracker, finance draft | internal sharing controls |
| Highly Confidential | sensitive internal business content | executive board packet, security review | restricted access, watermarking optional |
| Highly Confidential - Regulated Financial Data | customer, account, AML, SAR, KYC, treasury content | AML-CASE-2026-0519, ACCT-FIC-7721-0044-9081 | encryption, external sharing restrictions |
| Highly Confidential - HR Restricted | HR and compensation content | EMP-785511, SAL-BAND-FIC-09 | HR-only access, encryption |
| Highly Confidential - Legal Privileged | privileged legal/regulatory content | LEGAL-FIC-2044, PRIV-NOTE-FIC-771 | legal-only access, encryption, strict sharing |

---

## Recommended DLP Policy Matrix

| Policy Name | Workloads | Trigger Conditions | Recommended Action | Demo Scenarios |
|---|---|---|---|---|
| Regulated Financial Data - External Sharing | Exchange, SharePoint, OneDrive, Teams | ACCT-FIC, CUST-BNK, AML-CASE, SAR-DRAFT, KYC-FIC, TREAS-FIC near banking keywords | block external sharing or require justification | BF-SCEN-0001, BF-SCEN-0002, BF-SCEN-0030 |
| KYC and Loan Packet Protection | SharePoint, OneDrive, Exchange, Teams | KYC-FIC, LOAN-FIC, LOAN-EXC-FIC, customer ID, account-like number | warn internally, block externally | BF-SCEN-0001, BF-SCEN-0008 |
| AML and SAR Handling | SharePoint, OneDrive, Teams, Endpoint | AML-CASE, SAR-DRAFT, FRAUD-FIC, TXN-MON-FIC | block external sharing, audit downloads, restrict endpoint movement | BF-SCEN-0002, BF-SCEN-0030 |
| Treasury Reconciliation Protection | SharePoint, OneDrive, Endpoint | TREAS-FIC, RECON-FIC, PAY-FIC, ACCT-FIC | block USB, audit/limit print, warn on network copy | BF-SCEN-0005 |
| HR Compensation Protection | SharePoint, OneDrive, Exchange, Teams | EMP, SAL-BAND-FIC, ROLE-CHANGE-FIC near HR keywords | restrict to HR groups, block external sharing | BF-SCEN-0007 |
| Legal Privileged Protection | SharePoint, OneDrive, Exchange, Teams, Loop | LEGAL-FIC, PRIV-NOTE-FIC, REG-REQ-FIC near privileged/legal keywords | block broad sharing, encrypt, restrict to legal | BF-SCEN-0021 |
| Power BI Underlying Data Export Review | Power BI, SharePoint, Exchange | underlying export plus customer/account patterns | warn or block external sharing of exports | BF-SCEN-0004, BF-SCEN-0011 |
| External AI Sensitive Data Upload | Browser/cloud app, Endpoint, Defender for Cloud Apps | sensitive banking patterns pasted/uploaded to unmanaged AI | block, warn, or alert depending on demo maturity | BF-SCEN-0002, BF-SCEN-0030 |

---

## DLP Policy Tips and Coaching Messages

### Regulated Financial Data External Sharing

Suggested policy tip:

> This file appears to contain regulated financial data such as fictional customer IDs, account-like values, AML/SAR references, or KYC details. External sharing should use an approved sanitized package or restricted collaboration space.

Suggested user action:

- remove sensitive attachment
- create sanitized version
- use Vendor Collaboration site
- request security approval

---

### External AI Upload

Suggested policy tip:

> This content appears to include regulated financial patterns. Do not paste raw customer, account, AML, SAR, or treasury values into unmanaged AI applications. Use approved Copilot workflows with governed source files.

Suggested user action:

- remove raw rows
- aggregate the data
- use AI Approved Workspace
- ask Security/Data Governance for guidance

---

### Label Downgrade

Suggested policy tip:

> You are changing this file to a lower sensitivity label. Confirm that sensitive identifiers, internal notes, privileged content, or HR details have been removed before sharing.

Suggested user action:

- verify sanitized content
- document justification
- request data owner approval

---

## Sensitivity Label Policy Guidance

### Default label behavior by workspace

| Workspace | Recommended Default Label |
|---|---|
| Executive Leadership / Board Materials | Highly Confidential |
| HR Restricted / Compensation Planning | Highly Confidential - HR Restricted |
| Legal Privileged / Legal Memos | Highly Confidential - Legal Privileged |
| Customer Operations / KYC Review | Highly Confidential - Regulated Financial Data |
| Finance Close / Treasury Reconciliation | Highly Confidential - Regulated Financial Data |
| Vendor Collaboration / Sanitized Evidence | Confidential |
| AI Approved Workspace | Internal or Confidential |
| Training and Awareness | Internal or Public |

### Label downgrade controls

Recommended simulation controls:

- require justification for downgrade
- audit downgrade events
- trigger DLP scan after downgrade
- alert when downgrade is followed by external sharing within 15 minutes
- require data owner approval for repeated downgrades

---

## Auto-Labeling Concepts

| Auto-Label Rule | Detection | Suggested Label | Demo Use |
|---|---|---|---|
| AML/SAR content | AML-CASE, SAR-DRAFT, FRAUD-FIC plus suspicious activity keywords | Highly Confidential - Regulated Financial Data | AML external AI and SAR review scenarios |
| KYC content | KYC-FIC plus customer ID/account-like values | Highly Confidential - Regulated Financial Data | loan committee and KYC packet scenarios |
| HR compensation | EMP, SAL-BAND-FIC, compensation/merit/payroll keywords | Highly Confidential - HR Restricted | HR Copilot exposure scenario |
| Legal privileged content | LEGAL-FIC, PRIV-NOTE-FIC, privileged/counsel/regulator keywords | Highly Confidential - Legal Privileged | regulatory response and Loop leak scenario |
| Treasury reconciliation | TREAS-FIC, RECON-FIC, PAY-FIC, account-like values | Highly Confidential - Regulated Financial Data | Endpoint DLP scenario |

---

## Endpoint DLP Control Matrix

| Endpoint Activity | Content Type | Recommended Action | Demo Signal |
|---|---|---|---|
| Print sensitive treasury workbook | Regulated Financial Data | warn or block depending on policy maturity | FilePrinted, EndpointDLPPolicyMatch |
| Copy SAR draft to network share | Regulated Financial Data | block or alert | FileCopiedToNetworkShare |
| Copy AML workbook to USB | Regulated Financial Data | block | FileCopiedToUSB |
| Upload KYC file to unmanaged browser app | Regulated Financial Data | block or alert | UnmanagedAppUpload |
| Save HR compensation file locally | HR Restricted | warn and audit | FileDownloaded, EndpointDLPPolicyMatch |
| Print legal privileged memo | Legal Privileged | block or require justification | FilePrinted |

---

## Defender for Cloud Apps and AI App Governance

### Recommended governance concepts

- classify external AI apps as unmanaged unless explicitly approved
- detect uploads to unmanaged cloud apps
- detect copy/paste of sensitive patterns where available
- monitor high-volume downloads before external AI usage
- create a coaching workflow for productivity-driven shadow AI behavior

### Approved AI path

```text
Governed source content
        ↓
Sensitivity labels + correct permissions
        ↓
AI Approved Workspace or approved Microsoft 365 location
        ↓
CopilotInteraction
        ↓
Sanitized or aggregate output
```

### Unsafe AI path

```text
Raw AML/KYC/treasury/HR/legal content
        ↓
Copy rows or sensitive text
        ↓
External AI app
        ↓
UnmanagedAppUpload / AIAppInteraction
        ↓
DLP / Defender / investigation response
```

---

## DSPM for AI Demo Concepts

| DSPM for AI Theme | Demo Pattern | Recommended Story |
|---|---|---|
| Sensitive content discoverable by AI | Copilot references HR compensation file | AI inherits permissions and source exposure |
| Over-permissioned sensitive files | broad inherited access to HR or finance files | permissions must be reviewed before Copilot rollout |
| Sensitive AI interactions | prompts reference KYC, AML, SAR, treasury values | AI governance must include data classification and DLP |
| Approved AI workspace | sanitized summaries used for Copilot | safer AI requires governed source content |
| External AI risk | unmanaged app receives synthetic AML rows | Shadow AI is often a productivity shortcut |

---

## Insider Risk and Adaptive Protection Concepts

### Recommended indicators for demo

| Indicator | Example Signal | Scenario |
|---|---|---|
| Mass download | multiple regulated files downloaded in short window | BF-SCEN-0025, BF-SCEN-0030 |
| DLP override | user overrides warning to send external file | BF-SCEN-0030 |
| Endpoint movement | print or network-share copy | BF-SCEN-0005, BF-SCEN-0030 |
| External AI usage | unmanaged AI app prompt with regulated values | BF-SCEN-0002 |
| HR context | role-change notice before download spike | BF-SCEN-0025 |
| Label downgrade | confidential file changed to internal before sharing | BF-SCEN-0013 |

### Adaptive Protection concept

In the demo story, a user with repeated high-risk sequences could move to a higher risk level, causing stricter DLP controls.

Example:

```text
Normal user risk level
        ↓
DLP override + external AI + endpoint movement
        ↓
Elevated user risk level
        ↓
Stricter DLP actions for external sharing and endpoint copy
```

Use this as a conceptual model unless the lab tenant is configured with the required capabilities.

---

## Conditional Access and Site Access Concepts

Recommended scenario controls:

| Control Concept | Use Case | Demo Outcome |
|---|---|---|
| MFA for risky sign-in | Devon signs in from unusual location | ConditionalAccessTriggered, MFARequired |
| Session controls for sensitive sites | access HR, Legal, or KYC libraries | reduce unmanaged session risk |
| Conditional Access for protected SharePoint sites | restrict access to managed devices | sensitive site access requires compliant device |
| Block download from unmanaged device | user attempts KYC download from unmanaged session | download blocked or limited |
| Require compliant device for Endpoint DLP scenarios | enforce device context | device compliance appears in investigation |

---

## Retention and Records Concepts

| Content Type | Suggested Demo Control | Notes |
|---|---|---|
| AML/SAR evidence | retention label or record concept | regulated review evidence |
| Finance close evidence | retention by monthly close cycle | supports audit story |
| Legal privileged memo | legal retention / record concept | privileged content governance |
| HR compensation plan | restricted retention | HR governance |
| Investigation summary | security investigation retention | neutral case record |
| Training examples | short lifecycle or refresh | avoids stale demo clutter |

This section is conceptual and does not define production retention schedules.

---

## Policy Exception Model

Use exceptions sparingly in the demo.

Recommended exception attributes:

```text
ExceptionId
PolicyName
BusinessOwner
ApprovedBy
Justification
StartDate
EndDate
Scope
ReviewFrequency
CompensatingControl
```

Example fictional exception:

```text
ExceptionId: EXC-FIC-2026-004
PolicyName: Regulated Financial Data - External Sharing
BusinessOwner: James Wilson
ApprovedBy: Ana Rodriguez
Justification: Temporary vendor review of sanitized evidence packages only
Scope: /sites/VendorCollaboration/Sanitized Evidence Packages
EndDate: 2026-06-30
CompensatingControl: named-user sharing, expiration, download restriction
```

---

## False Positive Simulation Guidance

Use these examples to show why tuning matters.

| False Positive Type | Example | Tuning Lesson |
|---|---|---|
| Training sample | README lists ACCT-FIC-0000-0000-0000 as a sample | require keyword proximity or confidence thresholds |
| Regex documentation | custom SIT guide includes sample IDs | exclude training site or lower severity |
| Sanitized summary | aggregate risk tier references but no row-level data | distinguish aggregate from raw data |
| Placeholder values | CUST-BNK-000000 in a template | use checksum-like or context-based confidence |

---

## False Negative Simulation Guidance

Use these examples to show classification limits.

| False Negative Type | Example | Teaching Point |
|---|---|---|
| Context-only sensitivity | legal memo contains no exact legal ID but is privileged | trainable classifiers and labels matter |
| Screenshot/PDF image | sensitive value appears in image-only PDF | OCR/content extraction coverage matters |
| Partial identifiers | user pastes only last four synthetic account digits | pattern detection alone is insufficient |
| Sanitized-looking file name | file named Summary.xlsx contains raw rows | content inspection matters more than file name |
| AI paraphrase | external AI response summarizes sensitive source without IDs | risk can persist even after identifiers are removed |

---

## Recommended Scenario-to-Control Mapping

| Scenario | Primary Controls | Secondary Controls |
|---|---|---|
| BF-SCEN-0001 Loan Committee Oversharing | DLP, labels, external sharing restrictions | Teams governance, access reviews |
| BF-SCEN-0002 AML External AI | DLP, Defender for Cloud Apps, AI governance | user coaching, approved Copilot workflow |
| BF-SCEN-0005 Treasury Endpoint Movement | Endpoint DLP, labels | Defender for Endpoint, device compliance |
| BF-SCEN-0007 HR Copilot Exposure | labels, permissions, DSPM for AI | access reviews, HR restricted sites |
| BF-SCEN-0010 Vendor Guest Exposure | guest governance, DLP | access reviews, sanitized workspace |
| BF-SCEN-0013 Label Downgrade | label policy, DLP after downgrade | justification review, data owner approval |
| BF-SCEN-0021 Legal Memo Leak | legal label, DLP, Loop/Teams governance | non-privileged action tracker |
| BF-SCEN-0022 Risky Sign-In | Conditional Access, MFA | Defender XDR investigation |
| BF-SCEN-0025 Role Change Download | Insider Risk indicators, access review | HR/legal coordination |
| BF-SCEN-0030 Devon Multi-Day Risk Chain | Insider Risk, DLP, Endpoint DLP, AI governance | HR/legal/security investigation |

---

## Recommended Alert Severity Mapping

| Condition | Suggested Severity |
|---|---|
| single internal DLP match with low sensitivity | Low |
| sensitive file downloaded by assigned user | Medium |
| regulated financial data shared externally | High |
| DLP override for external sharing | High |
| unmanaged AI upload with regulated data | High |
| endpoint copy to USB or network share | High |
| risky sign-in followed by sensitive download | High |
| HR signal followed by mass download and endpoint movement | Critical |
| multi-stage Devon risk chain | Critical |

---

## User Coaching Templates

### Coaching Template - External Sharing

```text
Hi {UserName},

We noticed an attempt to share {FileName} outside the organization. The file appears to contain regulated or sensitive information.

Please use the approved sanitized version or the Vendor Collaboration workspace for external review. If the sharing is business-critical, contact Security or the data owner before proceeding.
```

### Coaching Template - External AI

```text
Hi {UserName},

We noticed activity that looks like sensitive content may have been used with an unmanaged AI application.

For banking, customer, AML, KYC, HR, legal, or treasury data, please use approved Microsoft 365 Copilot workflows with governed source content. Raw rows and identifiers should not be pasted into external AI tools.
```

### Coaching Template - Label Downgrade

```text
Hi {UserName},

We noticed that {FileName} was changed to a lower sensitivity label before sharing.

Before downgrading a file, confirm that customer identifiers, account-like values, HR details, legal analysis, or other sensitive content have been removed. If you are creating a sanitized version, please use a clear file name and preserve the original label on the source file.
```

---

## Codex Usage Guidance

Codex should use this file to:

1. Map scenarios to control recommendations.
2. Generate DLP, label, endpoint, and AI governance configuration notes.
3. Generate user coaching artifacts after risky events.
4. Populate Power BI recommended actions and tooltips.
5. Explain why a signal should be blocked, warned, audited, or escalated.
6. Generate false-positive and false-negative test content.
7. Keep all data synthetic and all investigation language neutral.

---

## Safety Reminder

This control matrix is for a synthetic demo environment.

Do not use it as a production policy baseline without:

- legal review
- privacy review
- HR review
- compliance review
- business owner validation
- technical testing
- staged deployment
- user communication
- exception governance
