# Data Protection Scenario Taxonomy and Pattern Catalog

## Purpose

This document defines the reusable scenario-design taxonomy and data-protection pattern catalog for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It organizes realistic scenario patterns for:

- sensitive data exposure
- accidental oversharing
- external collaboration
- AI and Copilot governance
- unmanaged AI usage
- DLP and label governance
- endpoint movement
- HR and legal sensitivity
- finance and banking workflows
- false positives and false negatives
- suspicious sequences
- remediation and coaching

All examples, users, customers, files, cases, identifiers, transactions, telemetry, and incidents are fictional and synthetic.

---

## Core Scenario Design Thesis

> A strong data-protection scenario is not a random risky event. It is a plausible business workflow where data, people, tools, pressure, controls, and response intersect.

A scenario should answer:

```text
Who is doing the work?
What business task are they trying to complete?
What sensitive data is involved?
Where does the data move?
Which control responds?
What context changes interpretation?
What should the organization do next?
```

---

## Scenario Category Taxonomy

| Category | Description | Example |
|---|---|---|
| Normal Business Activity | routine collaboration without material risk | internal file edit or Teams update |
| Sensitive Data Handling | legitimate access to sensitive data | KYC packet review |
| Accidental Oversharing | wrong audience, file, channel, or permission | internal package sent externally |
| External Collaboration | vendor, customer, or counsel sharing | sanitized evidence package |
| AI Governance | Copilot or AI use over sensitive content | Copilot summary of approved file |
| Unmanaged AI Risk | external AI app receives sensitive content | AML rows pasted into AI app |
| Label Governance | label applied, changed, downgraded, or removed | Confidential downgraded before sharing |
| DLP Response | DLP match, warning, block, or override | DLP override with vague justification |
| Endpoint Movement | local print, copy, USB, or network share | treasury file copied locally |
| Identity-to-Data Risk | risky sign-in before sensitive access | unusual sign-in then download |
| HR / Legal Context | workforce, role-change, privileged, or legal-sensitive content | role-change plus mass download |
| Insider Risk-Style Sequence | multi-signal chain requiring review | Devon multi-day risk chain |
| False Positive | control fires on benign or training content | fake pattern in awareness file |
| False Negative | sensitive content not detected or mislabeled | unlabeled KYC packet shared broadly |
| Remediation / Coaching | correction, education, access cleanup | sanitized file created after warning |

---

## Data Exposure Patterns

## Pattern 1 - Broad Internal Exposure

Description:

A sensitive file is stored in or shared to a broad internal location.

Signals:

```text
FileShared
TeamsMessageSent
SensitivityLabelApplied
DLPPolicyMatch
CopilotInteraction
```

Typical causes:

- unclear workspace ownership
- broad Teams channel
- over-permissioned SharePoint site
- urgency or convenience

Safer alternative:

```text
move file to restricted workspace and share sanitized summary broadly
```

---

## Pattern 2 - External Sharing of Internal Package

Description:

A user sends an internal package to an external recipient instead of the sanitized version.

Signals:

```text
ExternalEmailSent
FileShared
DLPWarned
DLPOverride
DLPBlocked
```

Typical causes:

- similar file names
- vendor deadline
- pressure from sales or PMO
- poor raw/sanitized separation

---

## Pattern 3 - Overexposed AI Source

Description:

Copilot can reference sensitive content because permissions are too broad.

Signals:

```text
CopilotInteraction
FileReferencedByCopilot
FileAccessed
SensitivityLabelApplied
```

Typical causes:

- permissions inherited from old project site
- HR/legal/finance file stored in general workspace
- missing access reviews

---

## Pattern 4 - Sensitive Working Copy in OneDrive

Description:

A user downloads or copies restricted content to OneDrive for convenience.

Signals:

```text
FileDownloaded
FileCreated
FileModified
DLPPolicyMatch
FileShared
```

Typical causes:

- individual productivity shortcut
- unclear official location
- meeting preparation
- offline review

---

## AI Risk Patterns

## Pattern 5 - Safe Copilot Summary

Description:

User summarizes approved, sanitized content with Copilot.

Signals:

```text
CopilotInteraction
FileAccessed
SensitivityLabelApplied
```

Risk level:

```text
Low / Medium depending on source sensitivity
```

Teaching point:

```text
Governed AI can be productive when source content is curated and permissions are correct.
```

---

## Pattern 6 - External AI Raw Data Shortcut

Description:

User pastes raw synthetic AML, KYC, HR, legal, or finance rows into an unmanaged AI app.

Signals:

```text
AIAppInteraction
UnmanagedAppUpload
DLPPolicyMatch
DLPBlocked
```

Risk level:

```text
High / Critical
```

Teaching point:

```text
The risky shortcut is not AI itself. It is raw sensitive data leaving governed boundaries.
```

---

## Pattern 7 - AI Derivative Output Risk

Description:

AI output recreates or summarizes sensitive content and is then reused.

Signals:

```text
AIAppInteraction
CopilotInteraction
FileCreated
ExternalEmailSent
DLPPolicyMatch
```

Typical causes:

- user assumes AI output is automatically safe
- source identifiers remain in summary
- output not reviewed before sharing

---

## Endpoint Risk Patterns

## Pattern 8 - Download then Print

Description:

Sensitive document is downloaded and printed before a meeting.

Signals:

```text
FileDownloaded
FilePrinted
EndpointDLPPolicyMatch
```

Risk context:

- board meeting
- loan committee
- legal review
- HR planning

---

## Pattern 9 - Download then Network Share Copy

Description:

Sensitive file is copied to a network share for convenience.

Signals:

```text
FileDownloaded
FileCopiedToNetworkShare
EndpointDLPPolicyMatch
```

Risk context:

- analyst needs team review
- legacy process requires file drop
- user bypasses governed SharePoint space

---

## Pattern 10 - USB or Local Movement

Description:

Sensitive file is copied to removable or local storage.

Signals:

```text
FileDownloaded
FileCopiedToUSB
EndpointDLPPolicyMatch
```

Risk level:

```text
High / Critical depending on data and context
```

---

## HR and Legal Sensitivity Patterns

## Pattern 11 - HR Role-Change Context plus Data Movement

Description:

Role-change context appears near sensitive data download or movement.

Signals:

```text
HRSignal
FileDownloaded
MassDownloadActivity
FileCopiedToNetworkShare
InsiderRiskSequence
```

Important framing:

```text
HR context is not proof of intent. It increases the need for careful review.
```

---

## Pattern 12 - Legal Privileged Content Reused Broadly

Description:

Privileged legal analysis is copied into a broad PMO tracker or executive deck.

Signals:

```text
FileModified
TeamsMessageSent
FileShared
DLPPolicyMatch
SensitivityLabelChanged
```

Safer alternative:

```text
create non-privileged action summary
```

---

## Banking and Finance Data Patterns

## Pattern 13 - AML Review Workbook Exposure

Data patterns:

```text
AML-CASE
SAR-DRAFT-FIC
CUST-BNK
TXN-FIC
ACCT-FIC
```

Common risks:

- external AI shortcut
- analyst export
- raw row sharing
- unmanaged derivative summary

---

## Pattern 14 - KYC Packet Oversharing

Data patterns:

```text
KYC-FIC
CUST-BNK
LOAN-FIC
ACCT-FIC
```

Common risks:

- wrong Teams channel
- wrong external package
- broad internal access
- Copilot overexposure

---

## Pattern 15 - Treasury Reconciliation Movement

Data patterns:

```text
TREAS-FIC
RECON-FIC
INV-FAK
VENDOR-FIC
```

Common risks:

- endpoint printing
- network-share copy
- finance close urgency
- Power BI export reuse

---

## Pattern 16 - HR Compensation Exposure

Data patterns:

```text
EMP
SAL-BAND-FIC
ROLE-CHANGE-FIC
```

Common risks:

- overexposed SharePoint location
- Copilot source exposure
- external AI prompt
- broad executive deck attachment

---

## False Positive Patterns

## Pattern 17 - Training Content Match

Description:

A training document contains fake identifiers for awareness purposes and triggers DLP.

Signals:

```text
DLPPolicyMatch
SensitivityLabelRecommended
TeamsMessageSent
```

Outcome:

```text
policy tuning or training-content exception
```

---

## Pattern 18 - Synthetic Example in Public Deck

Description:

A public training deck contains fictional identifiers with approved prefixes.

Risk:

```text
DLP may detect patterns even though data is safe synthetic content.
```

Teaching point:

```text
Classification and DLP require tuning and context.
```

---

## False Negative Patterns

## Pattern 19 - Unlabeled Sensitive File

Description:

Sensitive file lacks appropriate label and moves without expected control.

Signals:

```text
FileShared
ExternalEmailSent
DLPPolicyMatch missing or delayed
```

Teaching point:

```text
Data discovery and classification gaps reduce control effectiveness.
```

---

## Pattern 20 - Sanitized File Still Contains Raw Identifier

Description:

A sanitized file accidentally retains one customer-like or account-like identifier.

Signals:

```text
DLPPolicyMatch
ExternalEmailSent
FileShared
```

Outcome:

```text
sanitization process improvement
```

---

## Risk Progression Types

## Type A - Benign Activity

```text
normal file access
        ↓
internal edit
        ↓
approved sharing
```

Outcome:

```text
no investigation required
```

---

## Type B - Mistake and Correction

```text
wrong file or channel
        ↓
warning or peer correction
        ↓
sanitized version created
        ↓
case closed as coaching completed
```

---

## Type C - Risky Shortcut

```text
deadline pressure
        ↓
download or external AI
        ↓
DLP warning
        ↓
override or unsafe sharing
        ↓
security review
```

---

## Type D - Suspicious Sequence

```text
sensitive access
        ↓
mass download
        ↓
label downgrade
        ↓
external sharing or endpoint movement
        ↓
formal review
```

---

## Type E - Multi-Signal Critical Chain

```text
identity risk
        ↓
sensitive download
        ↓
unmanaged AI
        ↓
DLP override
        ↓
endpoint movement
        ↓
HR/legal context
        ↓
critical investigation
```

---

## Scenario Severity Taxonomy

| Severity | Scenario Pattern |
|---|---|
| Low | normal activity, safe AI, benign label event |
| Medium | sensitive access with clear business purpose |
| High | DLP override, unmanaged AI, endpoint movement, external sharing |
| Critical | multi-signal chain, HR/legal context, repeated behavior after coaching |

Important:

> Severity describes the risk pattern, not proof of malicious intent.

---

## Persona-to-Risk Mapping

| Persona Type | Common Risk Patterns |
|---|---|
| Executive | overshared summaries, Copilot overexposure, board material handling |
| HR | restricted workbook sharing, role-change data exposure |
| Finance | forecast export, reconciliation urgency, endpoint movement |
| Legal | privileged memo reuse, external counsel package mistakes |
| Sales | external customer pressure, sanitized-vs-internal mix-up |
| Engineering | local export, workaround, script-generated file movement |
| Data Science | AI prompt risk, anonymization assumptions, Power BI export |
| IT Security | evidence handling, investigation summary exposure |
| Customer Support | internal notes forwarded externally, customer escalation urgency |
| PMO | broad tracker oversharing, non-privileged vs privileged summary confusion |
| Devon Reyes | ambiguity anchor: risky shortcut, wrong file, external AI, endpoint movement |

---

## Scenario Composition Rules

A scenario should include:

```text
Persona
Business context
Data domain
Source location
Action sequence
Control response
Business interpretation
Recommended remediation
```

A strong scenario usually includes:

- one primary persona
- one supporting persona
- one sensitive file family
- one collaboration channel
- one control response
- one decision point
- one remediation or learning outcome

Avoid scenarios where:

- every action is risky
- every control fires at once
- no business purpose exists
- the user is treated as malicious by default
- no safer workflow is available

---

## Reusable Scenario Template

```json
{
  "scenarioId": "BF-SCEN-XXXX",
  "scenarioTitle": "Scenario title",
  "category": "AI Governance | DLP | Endpoint | External Sharing | Insider Risk | Baseline",
  "primaryPersona": "Devon Reyes",
  "supportingPersonas": ["Ana Rodriguez", "Marcus Olsson"],
  "department": "Customer Operations",
  "businessContext": "Why the user is doing this work.",
  "dataDomain": "AML / KYC / Treasury / HR / Legal / Executive",
  "sensitivePatterns": ["AML-CASE", "CUST-BNK"],
  "sourceLocation": "/sites/CustomerOperations/AML Raw Review/",
  "riskPattern": "External AI Raw Data Shortcut",
  "expectedSignals": ["FileDownloaded", "AIAppInteraction", "DLPPolicyMatch"],
  "severity": "High",
  "controlResponse": "DLP warning and security coaching",
  "recommendedRemediation": "Use AI Approved Workspace and sanitized source file.",
  "neutralInterpretation": "The activity requires review because raw regulated data appears to have been used outside an approved workflow."
}
```

---

## Future Scenario Expansion Model

Recommended expansion paths:

1. Add more normal business baselines.
2. Add one new risk pattern at a time.
3. Create department-specific variants.
4. Create safe and unsafe versions of the same workflow.
5. Add remediation-only scenarios.
6. Add false-positive and false-negative scenarios.
7. Add Sentinel incident variants.
8. Add multi-tenant or vendor scenarios.
9. Add industry-specific variants.
10. Add autonomous-agent variants.

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate new scenarios consistently.
2. Classify scenarios by risk pattern.
3. Build safe and unsafe variants.
4. Preserve business context.
5. Avoid unsupported malicious-intent assumptions.
6. Generate reusable scenario templates.
7. Expand scenario catalogs by department or industry.
8. Create false-positive and false-negative demos.
9. Map scenarios to telemetry and controls.
10. Preserve synthetic-only boundaries.

---

## Safety Reminder

This taxonomy is for synthetic scenario design only.

Do not use it to classify, score, investigate, or infer intent about real employees, real customers, real incidents, real HR matters, real legal matters, or real financial data without formal governance and authorization.
