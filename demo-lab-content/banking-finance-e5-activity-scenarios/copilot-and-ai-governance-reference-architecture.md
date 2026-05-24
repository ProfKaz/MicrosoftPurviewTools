# Copilot and AI Governance Reference Architecture

## Purpose

This document defines the dedicated Copilot and AI governance reference architecture for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It explains how to model governed AI usage, Copilot readiness, unmanaged AI risk, DSPM for AI concepts, DLP for AI interactions, prompt governance, retrieval boundaries, sensitivity labels, permissions, and safe AI operating models.

All users, prompts, files, identifiers, cases, customers, transactions, and telemetry in this architecture are fictional and synthetic.

---

## Core AI Governance Thesis

> AI does not create the original data-governance problem. It accelerates the discovery, summarization, transformation, and reuse of whatever users and agents can already access.

Supporting principles:

1. AI readiness depends on data readiness.
2. Copilot inherits Microsoft 365 permissions and source exposure.
3. Sensitive data should be classified before broad AI adoption.
4. Approved AI workflows should be easier than unsafe shortcuts.
5. External AI tools require separate governance from Microsoft 365 Copilot.
6. Prompt monitoring alone is insufficient without source-data governance.
7. AI outputs may create derivative sensitive content.

---

## Reference Architecture Overview

```text
Data Sources
    SharePoint, OneDrive, Teams, Exchange, Power BI
        ↓
Governance Foundation
    labels, permissions, access reviews, retention, DLP
        ↓
AI Access Layer
    Copilot, approved AI workspace, approved connectors
        ↓
AI Interaction Layer
    prompts, summaries, rewrites, analysis, generated outputs
        ↓
Control Layer
    Purview DLP, DSPM for AI concepts, audit, Defender for Cloud Apps, endpoint controls
        ↓
Response Layer
    coaching, remediation, investigation, executive reporting
```

---

## Governed Copilot Model

### Safe Copilot Pattern

```text
Approved source location
        ↓
Correct permissions
        ↓
Sensitivity label applied
        ↓
User has business need
        ↓
Copilot prompt uses governed content
        ↓
Output reviewed before sharing
        ↓
Sensitive derivative output is labeled or handled appropriately
```

### Example

```text
Priya asks Copilot to summarize an anonymized AML trend summary stored in the AI Approved Workspace. The file is labeled Confidential, contains aggregate data only, and the output is reviewed before inclusion in an executive deck.
```

---

## Unsafe AI Pattern

```text
Raw sensitive content
        ↓
User copies rows or identifiers
        ↓
External unmanaged AI app
        ↓
Generated summary or derivative output
        ↓
Output reused in email, Teams, or document
        ↓
DLP / Defender / investigation signal
```

### Example

```text
Devon pastes synthetic AML rows from AML_Monthly_Review_AML-CASE-2026-0519_Internal.xlsx into an unmanaged AI application to generate a vendor summary before a meeting.
```

---

## AI Approved Workspace Architecture

The AI Approved Workspace is a governed SharePoint site or library used to demonstrate safer AI adoption.

Recommended location:

```text
/sites/AIApprovedWorkspace
```

Recommended libraries:

```text
Approved Executive Summaries
Sanitized Customer Operations Data
Anonymized Analytics Datasets
Approved Prompt Examples
AI Output Review Queue
Training Samples
```

Recommended controls:

- default label: Internal or Confidential
- no raw AML, SAR, KYC, HR, legal privileged, or treasury row-level data
- data owner approval for published source documents
- periodic access review
- DLP policies for accidental sensitive content
- clear naming convention for sanitized content
- output review before external sharing

---

## Copilot Retrieval Boundary Concepts

Copilot-style retrieval should be explained through these principles:

| Concept | Meaning |
|---|---|
| User permission boundary | AI can only retrieve content the user is permitted to access. |
| Source quality boundary | AI output quality depends on source accuracy and governance. |
| Label boundary | labels help users and controls understand sensitivity. |
| Business-purpose boundary | access should align with the user's role and task. |
| Output boundary | generated content may inherit or recreate sensitivity. |

Demo message:

> The safest AI strategy is not only controlling the prompt. It is controlling what sources the user and AI can reach before the prompt is ever written.

---

## DSPM for AI Concepts

Use DSPM for AI concepts to explain AI exposure risk.

Recommended themes:

| Theme | Synthetic Demo Pattern | Governance Message |
|---|---|---|
| Overexposed sensitive files | HR compensation workbook visible too broadly | AI may surface content that permissions already expose. |
| Sensitive source discovery | Copilot references a highly confidential file | source governance must precede AI scale. |
| Unlabeled sensitive content | KYC packet has no label | classification gaps reduce control effectiveness. |
| External AI shortcut | raw AML rows pasted into unmanaged app | approved AI paths must be easier. |
| Sensitive derivative output | AI summary includes customer-like IDs | output needs review and classification. |

---

## Prompt Governance Model

### Prompt Categories

| Category | Example | Risk |
|---|---|---|
| Safe summary | summarize approved internal notes | Low |
| Sensitive summary | summarize highly confidential source | Medium/High |
| Regulated analysis | analyze AML/KYC rows | High |
| HR analysis | compare compensation data | High |
| Legal rewrite | simplify privileged memo | High |
| External AI upload | paste raw source data into unmanaged app | High/Critical |
| Derivative creation | generate customer-facing summary from raw data | Medium/High |

---

## Safe Prompt Examples

```text
Summarize the approved executive risk summary into three board-level talking points. Do not include customer identifiers or internal investigation details.
```

```text
Create a customer-safe response using only the sanitized complaint summary in the AI Approved Workspace.
```

```text
Draft a project status update from the non-sensitive PMO tracker. Exclude employee, customer, financial, legal, or investigation details.
```

---

## Unsafe Prompt Examples

```text
Summarize these AML rows and identify the top customers with suspicious transaction patterns: CUST-BNK-884210, ACCT-FIC-7721-0044-9081, AML-CASE-2026-0519.
```

```text
Rewrite this HR compensation plan for the leadership team and include the employee salary bands and role-change notes.
```

```text
Use this privileged legal memo to draft a broad PMO update for the full project team.
```

---

## DLP for AI Interaction Concepts

Recommended control patterns:

| AI Activity | Control Concept | Response |
|---|---|---|
| Copilot prompt over approved source | audit and monitor | allow |
| Copilot prompt over highly confidential source | monitor and review | allow or warn depending on scenario |
| External AI prompt with regulated patterns | DLP / Defender alert | block, warn, or investigate |
| AI output containing sensitive identifiers | label recommendation / DLP | review before sharing |
| External sharing after AI output | DLP external sharing rule | warn or block |

---

## Defender for Cloud Apps and External AI Governance

Recommended governance model:

```text
Discover AI apps
        ↓
Classify as approved, tolerated, or blocked
        ↓
Monitor sensitive uploads
        ↓
Coach users toward approved workflows
        ↓
Block or restrict high-risk apps when needed
```

Approved app categories:

```text
Microsoft 365 Copilot
approved internal AI app
approved enterprise AI workspace
```

Unmanaged app examples should remain fictional:

```text
quickprompt-ai.example.test
vendor-ai-review.example.test
```

---

## AI Risk Scoring Factors

Recommended synthetic scoring factors:

| Factor | Risk Impact |
|---|---|
| source file is highly confidential | +20 |
| source file contains regulated financial data | +25 |
| prompt includes customer-like identifiers | +25 |
| app is unmanaged external AI | +30 |
| output is shared externally | +25 |
| source is from AI Approved Workspace | -20 |
| prompt explicitly requests sanitization | -10 |
| output reviewed by data owner | -15 |

---

## AI Governance Operating Model

Recommended operating roles:

| Role | Responsibility |
|---|---|
| AI Sponsor | business owner for AI adoption and value realization |
| Data Governance Owner | validates source data quality and sensitivity |
| Security Owner | defines DLP, app governance, and monitoring |
| Compliance Owner | validates regulated data handling |
| Legal Owner | reviews privileged and external disclosure risk |
| HR Owner | reviews employee-data and workforce-data usage |
| Business Data Owner | approves domain-specific AI use cases |
| SOC / SecOps | investigates risky AI events |

---

## AI Governance Maturity Stages

## Stage 1 - Awareness

- AI usage exists but is not well governed.
- External AI usage may be informal.
- Sensitive data locations are not fully known.

## Stage 2 - Visibility

- AI apps are identified.
- sensitive data exposure is reviewed.
- initial prompt and external AI risks are documented.

## Stage 3 - Guardrails

- labels and DLP are applied.
- external AI controls are introduced.
- approved AI workflows are defined.

## Stage 4 - Operationalization

- AI risk signals are integrated into SOC and governance processes.
- executive dashboards track AI risk trends.
- user coaching is active.

## Stage 5 - Continuous Optimization

- AI governance is measured, tuned, and improved continuously.
- data owners participate in recurring reviews.
- safe AI adoption scales with confidence.

---

## Recommended Microsoft Control Mapping

| Governance Need | Microsoft Control Concept |
|---|---|
| classify AI source content | Microsoft Purview sensitivity labels |
| prevent raw sensitive sharing | Microsoft Purview DLP |
| monitor endpoint uploads | Endpoint DLP / Defender for Endpoint concepts |
| govern unmanaged AI apps | Defender for Cloud Apps concepts |
| review AI-related exposure | DSPM for AI concepts |
| govern access to sources | SharePoint permissions, Entra groups, access reviews |
| validate risky sign-ins | Entra Conditional Access concepts |
| investigate AI risk sequences | Defender XDR / Sentinel / ADX hunting |
| report to executives | Power BI governance dashboard |

---

## Safe vs Unsafe AI Workflow Comparison

| Step | Safe Workflow | Unsafe Workflow |
|---|---|---|
| Source | sanitized approved document | raw sensitive workbook |
| Location | AI Approved Workspace | personal OneDrive or local copy |
| App | Microsoft 365 Copilot or approved AI | unmanaged external AI |
| Prompt | excludes identifiers | includes raw rows and identifiers |
| Output | reviewed and labeled | reused without review |
| Sharing | approved internal or sanitized external path | external email or broad Teams channel |
| Control Response | audit / allow | DLP / alert / investigation |

---

## AI Governance Dashboard Concepts

Recommended KPIs:

```text
Copilot Interactions
External AI Interactions
Unmanaged AI Uploads
Sensitive AI Events
AI Events by Department
AI Events by Sensitivity Label
External AI Share of AI Activity
AI Events After Sensitive File Access
AI Output Shared Externally
```

Recommended visuals:

- safe vs unsafe AI workflow comparison
- prompt risk table
- source files referenced by AI
- AI risk by persona
- unmanaged AI app usage trend
- AI risk sequence timeline

---

## Scenario Mapping

| Scenario | AI Governance Theme |
|---|---|
| BF-SCEN-0002 AML External AI Shortcut | external AI with regulated data |
| BF-SCEN-0007 HR Copilot Exposure | Copilot over over-permissioned HR data |
| BF-SCEN-0011 Power BI Export and AI Summary | analytics export reused in AI |
| BF-SCEN-0023 Wrong Attachment to Vendor | AI-generated summary attached incorrectly |
| BF-SCEN-0030 Devon Multi-Day Risk Chain | combined AI, DLP, endpoint, and HR context |

---

## Executive AI Governance Message

Suggested wording:

> The question is not whether AI should be used. The question is whether the organization has governed the data, permissions, labels, sharing paths, and response processes that AI will depend on.

Suggested close:

> Safe AI adoption starts before the prompt. It starts with source data governance.

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate AI governance architecture diagrams.
2. Create safe and unsafe prompt libraries.
3. Generate AI Approved Workspace specifications.
4. Map AI prompts to DLP and risk signals.
5. Create Copilot readiness assessment materials.
6. Generate executive AI governance narratives.
7. Create dashboard KPIs for AI governance.
8. Preserve the difference between Copilot and unmanaged external AI.
9. Avoid implying that prompt monitoring alone solves AI risk.
10. Preserve synthetic-only boundaries.

---

## Safety Reminder

This AI governance architecture is for synthetic demo and advisory use only.

Do not use synthetic AI risk scoring, prompt examples, or investigation workflows to monitor, discipline, evaluate, or profile real employees without proper legal, privacy, HR, compliance, and governance approval.
