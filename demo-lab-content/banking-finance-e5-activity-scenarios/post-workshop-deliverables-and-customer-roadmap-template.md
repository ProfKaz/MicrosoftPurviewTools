# Post-Workshop Deliverables and Customer Roadmap Template

## Purpose

This document defines the post-workshop advisory-deliverables layer for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It provides a reusable customer-facing structure for summarizing workshop findings, interpreting maturity scores, mapping Microsoft capabilities, recommending quick wins, defining a 30/60/90-day roadmap, assigning responsible owners, documenting assumptions and exclusions, and proposing follow-on engagements.

This template is intended for advisory workshops, pre-sales engagements, executive briefings, Purview maturity assessments, Copilot readiness assessments, DLP strategy workshops, and SOC/data-security operating model discussions.

All demo examples and scenarios must remain synthetic. Customer-facing deliverables must not include real sensitive data unless formally approved and handled under the customer's governance process.

---

## Core Deliverable Thesis

> A workshop deliverable should translate discussion into decisions: current state, priority risks, maturity gaps, recommended actions, owners, and next steps.

The deliverable should answer:

```text
What did we learn?
Why does it matter?
Where should the customer focus first?
Which Microsoft capabilities are relevant?
Who needs to own each action?
What should happen in the next 30, 60, and 90 days?
```

---

## Recommended Deliverable Package

Recommended post-workshop package:

```text
1. Executive summary
2. Current-state maturity scorecard
3. Key findings and risk themes
4. Microsoft capability alignment
5. Recommended quick wins
6. 30/60/90-day roadmap
7. Responsible-owner matrix
8. Assumptions and exclusions
9. Recommended next engagement
10. Technical appendix
```

Optional package additions:

```text
Power BI screenshot pack
DLP policy sequencing plan
AI governance readiness checklist
Endpoint DLP pilot plan
Sentinel/SOC tabletop proposal
Managed governance service proposal
```

---

## 1. Executive Summary Template

```text
Based on the workshop discussion, the organization appears to be at a [Maturity Band] stage for Microsoft 365 data security and AI governance.

The highest-priority themes identified were:
1. [Theme 1]
2. [Theme 2]
3. [Theme 3]

The recommended near-term focus is to establish visibility over priority sensitive data domains, validate collaboration and permission boundaries, and define safe AI and external sharing workflows before expanding enforcement.

The proposed roadmap prioritizes quick wins in the first 30 days, control implementation and tuning during days 31-60, and operationalization with reporting and governance cadence during days 61-90.
```

---

## 2. Current-State Maturity Scorecard

Use the scorecard from:

```text
customer-workshop-discovery-questionnaire-and-assessment-scorecard.md
```

Recommended table:

| Domain | Score | Interpretation | Priority |
|---|---:|---|---|
| Executive Context | [0-4] | [summary] | High/Medium/Low |
| Discovery and Classification | [0-4] | [summary] | High/Medium/Low |
| Collaboration Governance | [0-4] | [summary] | High/Medium/Low |
| DLP Readiness | [0-4] | [summary] | High/Medium/Low |
| Endpoint DLP | [0-4] | [summary] | High/Medium/Low |
| AI Governance | [0-4] | [summary] | High/Medium/Low |
| SOC / Investigation | [0-4] | [summary] | High/Medium/Low |
| HR / Legal / Privacy Alignment | [0-4] | [summary] | High/Medium/Low |
| Executive Reporting | [0-4] | [summary] | High/Medium/Low |

Overall maturity:

```text
Overall Average: [score]
Maturity Band: Initial | Emerging | Developing | Operational | Optimized
```

---

## 3. Findings Structure

Recommended finding format:

```text
Finding ID: F-[number]
Finding Title: [short title]
Observation: [what was identified]
Business Impact: [why it matters]
Relevant Microsoft Capabilities: [Purview / Defender / Entra / Intune / Sentinel / Power BI]
Recommended Action: [what to do]
Priority: High / Medium / Low
Suggested Owner: [role]
Suggested Timing: 30 / 60 / 90 days
```

Example:

```text
Finding ID: F-001
Finding Title: AI readiness depends on source-data governance
Observation: The organization is considering broader AI adoption, but sensitive data locations, labels, and permissions are not yet consistently governed.
Business Impact: Copilot and other AI tools may accelerate discovery and reuse of overexposed content if source governance is incomplete.
Relevant Microsoft Capabilities: Microsoft Purview sensitivity labels, DLP, DSPM for AI concepts, SharePoint permissions, Entra access governance.
Recommended Action: Prioritize discovery and classification of high-risk data domains before broad AI expansion.
Priority: High
Suggested Owner: CISO / Data Governance Owner
Suggested Timing: 30 days
```

---

## 4. Risk Theme Summary

Recommended risk themes:

```text
Sensitive data discovery gaps
Inconsistent classification and labeling
Overexposed collaboration workspaces
External sharing governance gaps
DLP visibility and tuning gaps
Endpoint data movement blind spots
Copilot and AI readiness gaps
Shadow AI or unmanaged AI usage
SOC and investigation workflow gaps
Executive reporting gaps
```

For each theme, summarize:

```text
Current observation
Business impact
Recommended response
Relevant Microsoft capabilities
```

---

## 5. Microsoft Capability Mapping

Recommended table:

| Business Need | Relevant Microsoft Capabilities | Recommended Use |
|---|---|---|
| Identify sensitive data | Microsoft Purview discovery, classifiers, Activity Explorer concepts | baseline visibility |
| Classify files | Sensitivity labels, SITs, trainable classifiers, EDM concepts | apply meaning and handling rules |
| Reduce risky sharing | Microsoft Purview DLP | audit, warn, block, coach |
| Control endpoint movement | Endpoint DLP, Defender for Endpoint concepts | monitor print/copy/upload paths |
| Govern external AI | Defender for Cloud Apps concepts, Purview DLP concepts | detect and control unmanaged AI |
| Prepare for Copilot | labels, permissions, DSPM for AI concepts | reduce source overexposure |
| Investigate sequences | ADX/KQL, Defender XDR, Sentinel concepts | correlate evidence and triage |
| Report to leadership | Power BI executive dashboard | track trends and remediation |

---

## 6. Recommended Quick Wins

Recommended quick wins should be realistic and low-friction.

Examples:

```text
Identify top 3 sensitive data domains.
Review external sharing on high-risk SharePoint sites.
Define raw vs sanitized file naming standard.
Create or simplify sensitivity label taxonomy.
Pilot DLP in audit/warn mode for one priority data domain.
Create AI Approved Workspace concept.
Define approved AI tools and prohibited data types.
Create DLP override review process.
Create executive risk dashboard prototype.
```

---

## 7. 30/60/90-Day Roadmap Template

## First 30 Days - Visibility and Alignment

Recommended actions:

```text
Confirm executive sponsor and governance owners.
Identify priority data domains.
Inventory high-risk SharePoint, OneDrive, Teams, and Exchange locations.
Review external sharing posture.
Define AI acceptable-use baseline.
Draft label taxonomy or review existing labels.
Start DLP in audit mode for one priority data domain.
```

Expected outcomes:

```text
shared understanding of priority risk themes
initial visibility baseline
confirmed governance ownership
first quick-win controls identified
```

---

## Days 31-60 - Classification, Guardrails, and AI Readiness

Recommended actions:

```text
Apply labels to priority workspaces and files.
Tune sensitive information types or classifiers.
Define raw vs sanitized collaboration zones.
Create AI Approved Workspace.
Pilot DLP warn mode and policy tips.
Review DLP overrides.
Define Endpoint DLP pilot scope.
Create Power BI governance dashboard prototype.
```

Expected outcomes:

```text
priority data domains classified
safer collaboration paths defined
AI readiness guardrails started
DLP tuning feedback available
```

---

## Days 61-90 - Operationalization and Reporting

Recommended actions:

```text
Expand DLP policies based on tuning results.
Pilot Endpoint DLP for selected users or departments.
Define AI governance review workflow.
Create SOC triage process for DLP/AI/endpoint sequences.
Define HR/Legal/Privacy escalation boundaries.
Publish executive dashboard.
Establish monthly governance review cadence.
```

Expected outcomes:

```text
repeatable governance process
executive visibility
operational response workflow
prioritized improvement backlog
```

---

## 8. Responsible-Owner Matrix

Recommended table:

| Workstream | Primary Owner | Supporting Roles | Timing |
|---|---|---|---|
| Data domain prioritization | Business Data Owner | CISO, Compliance | 30 days |
| Label taxonomy | Data Governance | Security, Legal, HR | 30-60 days |
| DLP policy rollout | Security / Purview Owner | Compliance, Business Owners | 30-90 days |
| External sharing governance | Collaboration Owner | Security, Legal | 30-60 days |
| AI acceptable use | AI Sponsor | CISO, Legal, HR, Compliance | 30 days |
| AI Approved Workspace | Microsoft 365 Platform Owner | Data Owners, Security | 60 days |
| Endpoint DLP pilot | Endpoint Security | Purview Owner, SOC | 60-90 days |
| SOC triage workflow | SOC Lead | Legal, HR, Privacy | 60-90 days |
| Executive reporting | CISO Office | BI Team, Governance | 60-90 days |

---

## 9. Assumptions and Exclusions

## Assumptions

```text
Customer has or is evaluating Microsoft 365 E5, Microsoft Purview, Defender, or Copilot capabilities.
Customer will validate licensing and regional feature availability.
Customer will provide appropriate business, security, compliance, HR, legal, and privacy stakeholders.
Recommendations require tenant-specific validation before production implementation.
```

## Exclusions

```text
No production data was analyzed unless explicitly agreed under a separate governed process.
Synthetic demo findings do not represent production risk conclusions.
This deliverable is not legal advice.
This deliverable is not a regulatory certification.
This deliverable does not replace formal privacy, legal, or compliance review.
```

---

## 10. Recommended Next Engagement

Recommended engagement options:

## Option 1 - Purview Data Security Foundation

Focus:

```text
classification, labels, DLP baseline, external sharing governance
```

Typical outcomes:

```text
label taxonomy
DLP audit/warn policies
sensitive data baseline
executive dashboard prototype
```

---

## Option 2 - Copilot and AI Governance Readiness

Focus:

```text
source-data governance, AI acceptable use, AI Approved Workspace, Shadow AI response
```

Typical outcomes:

```text
Copilot readiness plan
AI data boundary model
safe prompt guidance
AI governance dashboard
```

---

## Option 3 - Endpoint DLP and Data Movement Pilot

Focus:

```text
endpoint print, copy, USB, browser upload, cloud-to-local movement
```

Typical outcomes:

```text
Endpoint DLP pilot policy
priority user group
endpoint movement dashboard
policy tuning recommendations
```

---

## Option 4 - SOC Data-Security Operating Model

Focus:

```text
DLP, AI, endpoint, identity, and external sharing investigation workflows
```

Typical outcomes:

```text
triage process
case closure taxonomy
Sentinel/ADX hunting queries
executive incident reporting model
```

---

## 11. Managed Service Recommendation

Recommended managed service themes:

```text
Monthly DLP override review
External sharing posture review
AI governance risk review
Endpoint movement review
Sensitivity label effectiveness review
Executive governance dashboard update
Policy tuning backlog management
SOC/tabletop readiness exercise
```

Suggested positioning:

> The value of the managed service is not only alert review. The value is continuous governance improvement across data, AI, collaboration, endpoint movement, and executive visibility.

---

## 12. Customer-Facing Language Guidance

Use:

```text
observed opportunity
recommended next step
governance maturity
safe AI adoption
visibility baseline
control tuning
business context
```

Avoid:

```text
customer is exposed
users are negligent
malicious insider
confirmed exfiltration
failed controls
```

unless based on real validated evidence outside the synthetic lab and approved by the customer governance process.

---

## 13. Technical Appendix Structure

Recommended appendix sections:

```text
A. Workshop inputs
B. Scorecard responses
C. Microsoft capability mapping
D. Suggested Purview controls
E. Suggested DLP rollout sequence
F. Suggested AI governance controls
G. Suggested Endpoint DLP pilot
H. Suggested SOC triage workflow
I. Sample executive dashboard KPIs
J. Assumptions and caveats
```

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate customer-facing post-workshop reports.
2. Convert assessment scores into maturity interpretation.
3. Generate findings and recommendations.
4. Build 30/60/90-day roadmaps.
5. Create owner matrices.
6. Generate next-engagement proposals.
7. Create managed-service recommendations.
8. Preserve customer-safe language.
9. Preserve licensing and feature caveats.
10. Preserve synthetic-only boundaries.

---

## Safety Reminder

Post-workshop deliverables must not include real sensitive customer data, real employee data, real HR records, real legal matters, real financial transactions, real credentials, real secrets, real production telemetry, or real incident evidence unless handled under a formally approved customer process outside the synthetic demo repository.
