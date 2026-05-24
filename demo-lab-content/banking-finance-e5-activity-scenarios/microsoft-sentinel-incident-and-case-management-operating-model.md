# Microsoft Sentinel Incident and Case Management Operating Model

## Purpose

This document defines the incident-response and governance-operations layer for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It explains how synthetic Microsoft Sentinel incidents, Purview signals, Defender context, ADX timelines, Power BI dashboards, HR/legal coordination, SOC workflows, and executive reporting should operate together during a data-security or AI-governance investigation.

All incidents, cases, users, files, entities, customers, identifiers, telemetry, HR records, legal matters, and financial records are fictional and synthetic.

---

## Core Operating Thesis

> A signal is not a conclusion. A good incident process converts signals into context, context into decisions, and decisions into documented outcomes.

The operating model should preserve:

- evidence-first investigation
- neutral language
- privacy-aware escalation
- documented decision-making
- separation between technical signal and user intent
- remediation and coaching options before escalation
- executive visibility without exposing unnecessary personal details

---

## Incident Lifecycle

Recommended incident lifecycle:

```text
Signal Generated
        ↓
Incident Created
        ↓
Triage
        ↓
Evidence Collection
        ↓
Context Validation
        ↓
Severity Confirmation
        ↓
Containment or Remediation
        ↓
HR / Legal / Privacy Review if required
        ↓
Closure Decision
        ↓
Executive Reporting
        ↓
Policy / Process Improvement
```

---

## Case Lifecycle States

Recommended synthetic case states:

```text
New
Triaged
Evidence Collected
Context Review
Awaiting Business Owner
Awaiting HR Review
Awaiting Legal Review
Remediation In Progress
Coaching Completed
Closed - Benign
Closed - Coaching
Closed - Remediated
Closed - Policy Tuning
Closed - Escalated
Closed - False Positive
Closed - Simulation Complete
```

---

## Incident Severity Model

| Severity | Description | Example |
|---|---|---|
| Low | low-risk signal or known training activity | DLP match on synthetic training file |
| Medium | sensitive access with plausible business purpose | KYC file accessed by operations user |
| High | sensitive data movement outside normal path | unmanaged AI after sensitive download |
| Critical | multi-stage risk chain or HR/legal context | Devon chain with AI, DLP override, endpoint movement |

Important:

> Severity describes response priority. It does not prove malicious intent.

---

## Incident Types

Recommended incident types:

```text
AI Governance Incident
DLP Override Incident
External Sharing Incident
Endpoint Movement Incident
Label Governance Incident
Identity-to-Data Incident
Insider Risk-Style Review
False Positive Review
False Negative Review
Scenario Replay Validation Incident
```

---

## Sentinel Incident Normalization

Recommended normalized synthetic incident fields:

```text
IncidentId
CaseId
ScenarioId
ReplayId
CorrelationId
IncidentTitle
IncidentType
Severity
Status
PrimaryUser
PrimaryDepartment
PrimaryFile
SensitivityLabel
PrimaryOperation
FirstEventTime
LastEventTime
EntitySummary
BusinessContext
RecommendedResponse
CurrentOwner
ClosureOutcome
SyntheticDisclaimer
```

---

## Entity Model

Recommended incident entities:

| Entity | Purpose |
|---|---|
| Account | primary persona or user account |
| File | sensitive file or derivative file |
| Host | endpoint or device context |
| URL / Domain | external recipient, vendor, or AI app domain |
| Cloud App | Copilot or unmanaged AI app |
| Mailbox | sender or recipient context |
| SharePoint Site | source or destination workspace |
| Policy | DLP, label, or governance control involved |

---

## SOC Triage Workflow

Recommended triage steps:

```text
1. Confirm incident is synthetic.
2. Identify ScenarioId, ReplayId, and CorrelationId.
3. Review primary user and department.
4. Review affected file and sensitivity label.
5. Review operation sequence.
6. Identify external domains or AI apps.
7. Check DLP outcome and user decision.
8. Check endpoint or identity context.
9. Validate business context.
10. Decide next action.
```

---

## Evidence Collection Checklist

Collect:

```text
Timeline of events
Affected files
Sensitivity labels
Previous labels
Recipients and target domains
AI app name and prompt category
DLP policy and rule
DLP action and override justification
Device and endpoint movement
Identity context
Teams or email clarification messages
Business owner notes
Security reviewer notes
```

Do not collect unnecessary personal details in executive summaries.

---

## Investigation Notebook Structure

Recommended notebook sections:

```text
1. Case summary
2. Scope and synthetic disclaimer
3. Timeline reconstruction
4. Entity summary
5. Affected files
6. AI interaction review
7. DLP and label review
8. Endpoint or identity review
9. Business context
10. Decision log
11. Recommended remediation
12. Closure outcome
```

---

## Escalation Paths

## Security-Only Review

Use when:

- DLP match is clear
- no HR/legal context exists
- remediation is technical or process-based

Examples:

- tune policy
- move file
- remove sharing link
- coach user

---

## Business Owner Review

Use when:

- file ownership is unclear
- sanitized content must be approved
- data domain owner must validate business purpose

Examples:

- KYC package owner
- finance close owner
- legal document owner
- AI approved workspace owner

---

## HR Review

Use only when:

- employee-data context exists
- role-change context is relevant
- repeated risky behavior requires workforce-process review
- coaching outcome requires HR awareness

Do not escalate to HR solely because a user appears in a detection.

---

## Legal Review

Use when:

- privileged content is involved
- external disclosure may be relevant
- regulator response is involved
- incident wording or preservation requirements need review

---

## Privacy Review

Use when:

- investigation scope may expose unnecessary personal information
- monitoring concerns arise
- reporting may include user-level information
- regional privacy requirements need validation

---

## Decision Matrix

| Situation | Recommended Outcome |
|---|---|
| training file triggered DLP | Closed - False Positive / Policy Tuning |
| user selected wrong sanitized/internal file pair | Closed - Coaching / Remediated |
| external AI used with raw regulated content | High-priority remediation and AI governance review |
| label downgraded before external sharing | label governance review and DLP tuning |
| endpoint copy after sensitive download | endpoint DLP review and business justification check |
| HR context plus mass download | structured HR/legal/privacy-aware review |
| repeated risky behavior after coaching | escalation decision with governance approval |

---

## Coaching vs Escalation Logic

## Coaching is preferred when:

- behavior appears accidental
- user asks for clarification
- safer workflow exists
- first occurrence
- file was recovered or link removed
- no evidence of intentional evasion

## Escalation may be required when:

- repeated behavior after coaching
- deliberate workaround pattern
- multiple high-risk signals in sequence
- privileged or HR content involved
- external movement occurred after explicit warning
- business owner confirms no valid purpose

Important:

> Escalation should be process-driven, not dashboard-driven.

---

## Case Closure Outcomes

Recommended closure outcomes:

```text
Closed - Benign Activity
Closed - False Positive
Closed - Coaching Completed
Closed - Remediated
Closed - Policy Tuned
Closed - Access Corrected
Closed - Sanitized Version Created
Closed - Escalated for Governance Review
Closed - Simulation Complete
```

Each closure should include:

- rationale
- evidence summary
- remediation action
- owner
- date/time
- follow-up task if any

---

## Incident-to-Executive Reporting

Executive reporting should summarize patterns, not expose unnecessary personal detail.

Recommended executive fields:

```text
Incident Type
Business Data Domain
Severity
Affected Control Area
Root Cause Theme
Recommended Action
Status
Trend Impact
```

Avoid unnecessary inclusion of:

- full prompt text
- personal HR context
- raw file names with sensitive identifiers
- detailed user-level behavior unless required

Example executive summary:

```text
A synthetic AI governance scenario showed raw regulated financial content moving from a restricted review file into an unmanaged AI workflow. Recommended action: define approved AI workspaces, strengthen DLP controls for external AI destinations, and coach users on sanitized-source workflows.
```

---

## Governance Review Board Model

Recommended participants:

```text
CISO or delegate
Data Governance Owner
Compliance representative
Legal representative
HR representative when applicable
Privacy representative when applicable
Business data owner
SOC lead
Microsoft 365 platform owner
```

Recommended meeting cadence:

```text
Monthly for governance trends
Ad hoc for critical synthetic tabletop scenarios
Quarterly for maturity review
```

---

## Tabletop Workflow

Recommended tabletop flow:

```text
1. Present synthetic incident summary.
2. Reveal first timeline segment.
3. Ask analysts what they would check next.
4. Reveal DLP and AI context.
5. Reveal endpoint or identity context.
6. Ask whether escalation is justified.
7. Review HR/legal/privacy considerations.
8. Decide closure outcome.
9. Identify policy, process, or training improvements.
10. Summarize executive takeaways.
```

---

## Sentinel Enrichment Concepts

Recommended enrichments:

```text
watchlist: approved AI apps
watchlist: approved external domains
watchlist: sensitive data domains
watchlist: synthetic high-risk personas
lookup: file sensitivity label
lookup: scenario metadata
lookup: recommended response
lookup: business owner
```

---

## Automation Playbook Concepts

Potential synthetic playbooks:

| Playbook | Trigger | Action |
|---|---|---|
| Create Case Summary | new high/critical incident | generate synthetic case document |
| Notify AI Governance Owner | unmanaged AI incident | Teams or email notification |
| Request Data Owner Review | external sharing incident | create review task |
| Attach Coaching Template | first-time DLP override | add coaching note |
| Add HR/Legal Checklist | HR or legal context | attach review checklist |
| Revoke Link Simulation | sensitive external share | mark remediation event |

---

## Case Notes Style Guide

Preferred language:

```text
observed
requires review
appears consistent with
business context pending
control response recorded
recommended next step
```

Avoid:

```text
malicious
exfiltration
guilty
insider threat confirmed
data theft
```

unless the scenario explicitly defines that interpretation.

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate incident lifecycle documentation.
2. Create synthetic case-management objects.
3. Build SOC triage runbooks.
4. Generate Sentinel incident templates.
5. Create investigation notebook outlines.
6. Generate coaching vs escalation decision trees.
7. Create executive incident summaries.
8. Preserve neutral investigation language.
9. Preserve HR/legal/privacy escalation boundaries.
10. Preserve synthetic-only constraints.

---

## Safety Reminder

This operating model is for synthetic incident and case-management simulation only.

Do not use it to investigate, monitor, discipline, evaluate, or profile real employees, real customers, real HR records, real legal matters, real financial transactions, or real production incidents without formal legal, privacy, HR, compliance, and governance authorization.
