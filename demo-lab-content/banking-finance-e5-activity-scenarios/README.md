# Banking / Finance E5 Daily and Cyclical Activity Scenarios

## Purpose

This folder defines a Microsoft 365 E5 / Microsoft Purview demo scenario pack focused on a fictional banking and financial-services organization. It expands the existing synthetic content pack into daily, weekly, monthly, and event-driven operational activities that can be executed by browser-based agents across Microsoft 365 workloads.

The goal is to simulate realistic work patterns across common Microsoft 365 technologies while generating meaningful telemetry for:

- Microsoft Purview Activity Explorer
- Microsoft Purview Data Loss Prevention
- Microsoft Purview Information Protection sensitivity labels
- Insider Risk Management-style narratives
- Communication Compliance-style narratives
- Microsoft Defender XDR / Defender for Cloud Apps-style monitoring
- Microsoft Entra ID and Conditional Access events
- Microsoft Teams and SharePoint collaboration patterns
- Copilot for Microsoft 365 usage and oversharing scenarios
- External sharing and vendor/customer collaboration controls

All data, customers, account numbers, transaction records, loan files, employee identifiers, contracts, suspicious activity records, support cases, incidents, and personal information patterns are fictional.

---

## User Profile Context

The initial user profile source file is `profiles.md`. It includes the following fictional personas:

- Alexander Meyer - CEO
- Ana Rodriguez - Head of IT / Security
- Carlos Delgado - Data Analyst
- David Chen - Customer Operations Specialist
- Diego Martinez - Sales Manager
- Emily Johnson - Corporate Lawyer
- James Wilson - Director of Operations
- Laura Gomez - HR Manager
- Marcus Olsson - Cybersecurity Manager
- Miguel Santos - Platform Engineer
- Priya Sharma - Data Scientist
- Sofia Lopez - Project Manager

A missing profile was also added for scenario design:

## Devon Reyes

- **UPN:** devon.reyes@mhdemos.com
- **Role:** Junior Operations Analyst
- **Location:** San Juan, Puerto Rico
- **Department:** Customer Operations / Banking Operations
- **Reports to:** Ana Rodriguez through the Security Governance escalation path for risky behavior simulations
- **Licenses:** Microsoft 365 E5 + Copilot
- **Scenario purpose:** Devon is used to model unsafe, erroneous, negligent, or potentially malicious information-handling behaviors. His activities are not assumed to be malicious by default; they are designed to create realistic investigation paths involving accidental oversharing, risky AI usage, insecure downloads, unusual access, external sharing attempts, and endpoint copy/print activity.

---

## Story Context

The fictional organization is called **MH Demos Financial Group**. It operates a banking-style Microsoft 365 E5 tenant with employees distributed across LATAM, North America, Europe, and India.

The organization handles synthetic but realistic banking data such as:

- Customer account files
- KYC review packages
- Loan application records
- Credit-risk spreadsheets
- Transaction monitoring exports
- Fraud investigation notes
- Suspicious activity review workbooks
- Collections case notes
- Treasury worksheets
- Executive financial forecasts
- Legal/regulatory response documents
- HR compensation and workforce planning files
- Customer complaint and dispute records
- Vendor due diligence packages
- AI-assisted analysis outputs

The story emphasizes that in banking and finance, risk does not come from one isolated action. It emerges from combinations of routine work, sensitive data, collaboration, external sharing, AI summarization, endpoint actions, and identity/security posture.

Devon Reyes is introduced as the recurring user whose behavior creates complex signals. Some actions are simple mistakes, some are poor judgment, and some could be interpreted as malicious depending on context.

---

## Generated Files

This folder contains:

```text
README.md
CODEX_HANDOFF.md
technologies-and-activities.json
complex-scenarios.json
```

### `technologies-and-activities.json`

Lists common Microsoft 365 E5 technologies relevant to banking/finance demo activity, including common daily, weekly, monthly, and event-driven user activities.

### `complex-scenarios.json`

Contains 30 complex banking/finance scenarios. Each scenario includes personas, technologies, cadence, business activity, risk narrative, Purview/Defender signals, expected files, labels, and suggested automation flow.

### `CODEX_HANDOFF.md`

Explains how Codex should consume the files, validate the schema, map personas to tenant users, and orchestrate browser-based agent activity.

---

## Design Principles

1. **Banking realism without real banking data**
   - Use plausible terminology such as KYC, AML, suspicious activity review, loan underwriting, credit exposure, treasury, customer disputes, and audit evidence.
   - Never use real customer data or real account numbers.

2. **Full Microsoft 365 E5 surface area**
   - Include SharePoint Online, OneDrive for Business, Teams, Exchange Online, Office Web, Purview, Defender, Entra ID, Intune, Power BI, Planner, Lists, Forms, Loop, Whiteboard, Stream, Viva Engage, and Copilot.

3. **Telemetry-first design**
   - Every scenario should create signals that can be observed, investigated, or explained.

4. **Human behavior matters**
   - Scenarios include routine work, urgency, mistakes, misunderstanding, over-permissioned files, excessive sharing, and AI misuse.

5. **Devon as risky behavior anchor**
   - Devon Reyes is used repeatedly to demonstrate unsafe, erroneous, or suspicious behavior patterns.

---

## Example Scenario Themes

- A weekly loan committee package is created in SharePoint, copied to OneDrive, and accidentally shared externally.
- A monthly AML review workbook is downloaded, renamed, and uploaded to an unmanaged location.
- A Copilot prompt summarizes customer complaint files and unintentionally includes account-like identifiers.
- A Teams chat includes a request to send a KYC package to a vendor mailbox.
- A Power BI export containing customer-level credit-risk data is emailed to a broad distribution list.
- An employee under performance pressure prints and copies multiple sensitive files after receiving a role-change notice.
- Legal prepares a regulator response while Operations accidentally shares the internal draft.
- HR compensation data is surfaced in Copilot because permissions were inherited from a broad SharePoint group.

---

## Label Model Used in This Pack

The scenarios use a simplified demo label model:

```text
Public
Internal
Confidential
Highly Confidential
Highly Confidential - Regulated Financial Data
Highly Confidential - HR Restricted
Highly Confidential - Legal Privileged
```

Codex can map these labels to real sensitivity label IDs later.

---

## Fictional Data Notice

All sensitive-looking values are fictional and should remain fictional.

Example synthetic patterns:

```text
CUST-BNK-204919
ACCT-FIC-7721-0044-9081
LOAN-FIC-2026-1187
KYC-FIC-88421
AML-CASE-2026-0519
SAR-DRAFT-FIC-2044
DISPUTE-FIC-60392
EMP-785511
DEV-FIC-2219
EXT-AUDIT@example.test
```

Do not replace these values with real bank data, real customer data, real financial records, real credentials, real addresses, or real account numbers.
