# Customer Workshop Discovery Questionnaire and Assessment Scorecard

## Purpose

This document defines the customer-discovery and advisory-assessment layer for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It provides structured discovery questions, scoring guidance, maturity interpretation, and recommended next steps for workshops focused on:

- Microsoft Purview maturity
- data security
- DLP readiness
- Endpoint DLP readiness
- Copilot and AI governance readiness
- external sharing governance
- SOC readiness
- HR, Legal, Privacy, and Compliance operating models
- executive reporting
- roadmap generation

This artifact is designed for pre-sales qualification, executive workshops, technical discovery, and post-workshop advisory planning.

All examples and scenarios remain synthetic and must not use real customer-sensitive data inside the demo lab.

---

## Core Assessment Thesis

> A good workshop does not start with controls. It starts with business risk, data domains, collaboration patterns, AI adoption goals, and operating-model readiness.

The assessment should identify:

```text
current state
priority data domains
governance gaps
technical readiness
operational maturity
AI readiness
quick wins
roadmap priorities
```

---

## Scoring Model

Use a 0 to 4 scale for each question.

| Score | Meaning |
|---:|---|
| 0 | Not implemented / unknown |
| 1 | Informal or ad hoc |
| 2 | Partially implemented |
| 3 | Implemented and repeatable |
| 4 | Mature, measured, and continuously improved |

---

## Maturity Bands

| Average Score | Maturity Band | Interpretation |
|---:|---|---|
| 0.0 - 0.9 | Initial | limited visibility and high dependency on manual judgment |
| 1.0 - 1.9 | Emerging | some controls exist but are fragmented or inconsistent |
| 2.0 - 2.9 | Developing | key capabilities exist but need process and tuning |
| 3.0 - 3.5 | Operational | repeatable governance and response processes exist |
| 3.6 - 4.0 | Optimized | measured, integrated, and continuously improved operating model |

---

## Section 1 - Executive and Business Context

Purpose:

Understand why the customer is interested in Purview, data protection, AI governance, or Microsoft 365 security maturity.

Questions:

| ID | Question |
|---|---|
| EXE-01 | Which business outcomes are driving this initiative: compliance, AI readiness, data protection, incident reduction, audit, productivity, or customer trust? |
| EXE-02 | Which executive sponsor owns the data-security or AI-governance outcome? |
| EXE-03 | Which data domains would create the highest business impact if exposed? |
| EXE-04 | Is there a board-level or risk-committee reporting requirement for data security or AI governance? |
| EXE-05 | Are business units aligned on acceptable data sharing and AI usage expectations? |

Scoring guidance:

```text
High maturity requires clear sponsorship, defined business outcomes, and measurable reporting expectations.
```

---

## Section 2 - Sensitive Data Discovery and Classification

Questions:

| ID | Question |
|---|---|
| CLS-01 | Do you know where regulated, confidential, HR, legal, financial, and customer-sensitive data is stored across Microsoft 365? |
| CLS-02 | Do you have a sensitivity label taxonomy in production? |
| CLS-03 | Are labels mapped to business data domains and handling rules? |
| CLS-04 | Do you use recommended or automatic labeling for priority data types? |
| CLS-05 | Do data owners participate in classification decisions? |
| CLS-06 | Are raw and sanitized files clearly separated and named consistently? |
| CLS-07 | Do you regularly review unlabeled sensitive content? |

Recommended next steps by low score:

```text
perform sensitive data discovery, simplify label taxonomy, identify priority data domains, and define raw vs sanitized workflows.
```

---

## Section 3 - Permissions and Collaboration Governance

Questions:

| ID | Question |
|---|---|
| COL-01 | Are SharePoint, OneDrive, and Teams permissions reviewed periodically for sensitive workspaces? |
| COL-02 | Are guest users isolated to appropriate external collaboration spaces? |
| COL-03 | Are anonymous links restricted or monitored for sensitive content? |
| COL-04 | Are sensitive raw-data spaces separated from external-ready collaboration spaces? |
| COL-05 | Are broad Teams channels prevented from becoming sensitive-data repositories? |
| COL-06 | Are stale sites, orphaned Teams, or legacy permissions reviewed? |
| COL-07 | Are business owners accountable for workspace access decisions? |

Recommended next steps by low score:

```text
review high-risk sites, isolate guest collaboration, create sensitive workspace standards, and define ownership for access reviews.
```

---

## Section 4 - DLP Readiness and Operations

Questions:

| ID | Question |
|---|---|
| DLP-01 | Are DLP policies deployed across Exchange, SharePoint, OneDrive, and Teams? |
| DLP-02 | Are policies initially tuned in audit or warn mode before enforcement? |
| DLP-03 | Are user overrides reviewed with business context? |
| DLP-04 | Are policy tips used to coach users? |
| DLP-05 | Are false positives and false negatives tracked? |
| DLP-06 | Are DLP policies aligned to sensitivity labels and data domains? |
| DLP-07 | Is there a repeatable process for policy tuning? |

Recommended next steps by low score:

```text
start with visibility, define high-confidence policies, introduce policy tips, and create an override review workflow.
```

---

## Section 5 - Endpoint DLP and Device Movement

Questions:

| ID | Question |
|---|---|
| EDP-01 | Are endpoints onboarded and ready for Endpoint DLP scenarios? |
| EDP-02 | Are print, USB, network-share, and local-copy activities monitored for sensitive content? |
| EDP-03 | Are device compliance and Conditional Access requirements aligned with sensitive-data access? |
| EDP-04 | Are endpoint policies piloted with priority users or departments before broad rollout? |
| EDP-05 | Are endpoint movement events reviewed together with cloud activity? |

Recommended next steps by low score:

```text
pilot Endpoint DLP for priority groups, monitor cloud-to-endpoint movement, and align endpoint policies to data sensitivity.
```

---

## Section 6 - Copilot and AI Governance Readiness

Questions:

| ID | Question |
|---|---|
| AIG-01 | Has the organization defined approved AI tools and acceptable AI usage? |
| AIG-02 | Are users trained not to paste raw regulated, HR, legal, or confidential data into unmanaged AI tools? |
| AIG-03 | Is Copilot readiness assessed through data classification and permission hygiene? |
| AIG-04 | Is there an AI Approved Workspace or equivalent curated source model? |
| AIG-05 | Are AI outputs reviewed before broad or external sharing? |
| AIG-06 | Are unmanaged AI applications discovered or monitored? |
| AIG-07 | Are sensitive AI events reported to security or governance teams? |
| AIG-08 | Are Shadow AI events treated as coaching and workflow-design opportunities, not only violations? |

Recommended next steps by low score:

```text
define acceptable AI use, identify unmanaged AI usage, create approved AI workspaces, and improve source-data governance before scaling Copilot.
```

---

## Section 7 - SOC, Incident, and Investigation Readiness

Questions:

| ID | Question |
|---|---|
| SOC-01 | Are DLP, AI, endpoint, and identity signals reviewed together during investigations? |
| SOC-02 | Is there a documented triage process for data-security incidents? |
| SOC-03 | Are HR, Legal, and Privacy escalation boundaries documented? |
| SOC-04 | Are investigation notes written in neutral, evidence-based language? |
| SOC-05 | Are cases closed with outcomes such as benign, coaching, remediated, tuned, or escalated? |
| SOC-06 | Are recurring patterns reported to governance or executive stakeholders? |
| SOC-07 | Are Sentinel, Defender, ADX, or Power BI used to correlate signals? |

Recommended next steps by low score:

```text
define triage workflows, establish escalation boundaries, create case closure taxonomy, and build executive reporting from investigation trends.
```

---

## Section 8 - HR, Legal, Privacy, and Compliance Alignment

Questions:

| ID | Question |
|---|---|
| GOV-01 | Are HR, Legal, Privacy, and Compliance involved in insider-risk-style process design? |
| GOV-02 | Are workforce-related signals handled with privacy-aware governance? |
| GOV-03 | Are privileged legal documents separated from broad project-management content? |
| GOV-04 | Are regulatory response documents classified and retained appropriately? |
| GOV-05 | Are escalation decisions process-driven rather than dashboard-driven? |
| GOV-06 | Are executive reports designed to avoid unnecessary personal detail? |

Recommended next steps by low score:

```text
create governance review board, define escalation criteria, separate legal/HR workspaces, and establish privacy-aware reporting rules.
```

---

## Section 9 - Executive Reporting and Continuous Improvement

Questions:

| ID | Question |
|---|---|
| RPT-01 | Are data-security and AI-governance KPIs reported to leadership? |
| RPT-02 | Are trends tracked over time, not only incident counts? |
| RPT-03 | Are DLP overrides, external sharing, AI risk, and endpoint movement measured together? |
| RPT-04 | Are remediation actions tracked to completion? |
| RPT-05 | Are lessons learned translated into policy, training, or process improvements? |
| RPT-06 | Is there a recurring governance review cadence? |

Recommended next steps by low score:

```text
create executive risk dashboard, define maturity KPIs, track remediation, and establish monthly governance reviews.
```

---

## Scoring Summary Template

```text
Executive Context: ___ / 4
Discovery and Classification: ___ / 4
Collaboration Governance: ___ / 4
DLP Readiness: ___ / 4
Endpoint DLP: ___ / 4
AI Governance: ___ / 4
SOC / Investigation: ___ / 4
HR / Legal / Privacy Alignment: ___ / 4
Executive Reporting: ___ / 4

Overall Average: ___ / 4
Maturity Band: Initial | Emerging | Developing | Operational | Optimized
```

---

## Recommended Next Steps by Overall Score

## 0.0 - 0.9: Initial

Recommended focus:

```text
executive awareness
sensitive data discovery
priority data-domain identification
basic external sharing review
initial AI acceptable-use discussion
```

---

## 1.0 - 1.9: Emerging

Recommended focus:

```text
label taxonomy
DLP audit mode
permission hygiene
AI Approved Workspace design
external sharing guardrails
```

---

## 2.0 - 2.9: Developing

Recommended focus:

```text
DLP tuning
Endpoint DLP pilot
AI governance dashboard
SOC triage workflow
case closure taxonomy
```

---

## 3.0 - 3.5: Operational

Recommended focus:

```text
cross-signal correlation
Sentinel integration
monthly governance reviews
executive scorecards
continuous improvement backlog
```

---

## 3.6 - 4.0: Optimized

Recommended focus:

```text
advanced automation
managed governance reporting
AI risk optimization
mature DLP tuning
cyber-range tabletop exercises
```

---

## Pre-Sales Qualification Signals

Strong fit indicators:

- customer is planning Copilot or AI adoption
- customer has Microsoft 365 E5 or Purview/Defender investment
- customer has regulated data in Microsoft 365
- customer has external sharing concerns
- customer has DLP pain or fear of disruption
- customer needs executive reporting
- customer has banking, finance, government, healthcare, legal, or HR-sensitive workflows

Weak fit indicators:

- no Microsoft 365 security/compliance scope
- no executive sponsor
- no willingness to discuss data ownership
- only wants a tool demo with no governance discussion
- expects production conclusions from synthetic data

---

## Workshop Input Form

Recommended input fields:

```text
Customer Name
Industry
Primary Sponsor
Technical Owner
Security Owner
Compliance Owner
AI Adoption Status
Microsoft 365 Licensing Context
Priority Data Domains
Known Pain Points
External Sharing Concerns
DLP Current State
Copilot Current State
Endpoint DLP Current State
SOC / Sentinel Current State
Workshop Goals
Expected Deliverables
```

Avoid collecting real sensitive examples inside the synthetic lab.

---

## Post-Workshop Roadmap Output

Recommended output sections:

```text
1. Executive summary
2. Current maturity score
3. Priority risk themes
4. Quick wins
5. 30/60/90-day roadmap
6. Microsoft capability alignment
7. Governance operating model recommendations
8. AI readiness recommendations
9. DLP and Endpoint DLP recommendations
10. Executive reporting recommendations
11. Proposed next engagement
```

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate workshop questionnaires.
2. Create assessment forms.
3. Generate scoring workbooks.
4. Create customer maturity summaries.
5. Generate 30/60/90-day roadmap recommendations.
6. Map low scores to platform demos.
7. Create pre-sales qualification notes.
8. Generate post-workshop executive summaries.
9. Preserve licensing and feature caveats.
10. Preserve synthetic-only boundaries.

---

## Safety Reminder

Do not collect or store real sensitive customer data, real employee data, real HR records, real legal matters, real financial transactions, real credentials, real secrets, real production telemetry, or real incident evidence inside this synthetic demo repository or lab.
