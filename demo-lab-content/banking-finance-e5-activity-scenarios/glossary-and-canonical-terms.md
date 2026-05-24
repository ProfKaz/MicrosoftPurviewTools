# Glossary and Canonical Terms

## Purpose

This document defines the terminology and language-control layer for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It establishes canonical terms, preferred wording, avoided wording, term ownership, and consistent definitions for architecture, telemetry, replay, AI governance, DLP, Endpoint DLP, Sentinel/SOC operations, executive storytelling, advisory workshops, and managed services.

All terms in this glossary must be used within the synthetic-only boundaries of the platform.

---

## Core Language Thesis

> Consistent terminology protects the platform from ambiguity, overstatement, unsafe conclusions, and implementation drift.

The platform should use language that is:

```text
clear
neutral
synthetic-aware
evidence-first
business-readable
implementation-friendly
privacy-aware
```

---

## Canonical Term Ownership

| Area | Owner Role |
|---|---|
| telemetry terms | Platform Architect |
| scenario terms | Scenario Designer |
| AI governance terms | AI Governance Lead |
| DLP and Purview terms | Purview Specialist |
| SOC and incident terms | SOC Architect |
| Power BI terms | BI Developer |
| commercial/advisory terms | Services Lead |
| responsible-use terms | Platform Owner |

---

## Core Identifiers

## ScenarioId

Definition:

A stable identifier for a synthetic business scenario.

Example:

```text
BF-SCEN-0030
```

Usage:

- scenario catalog
- telemetry events
- Power BI filters
- replay timelines
- KQL hunting
- Sentinel-style incidents

Do not use:

```text
scenario name as primary key
ad hoc scenario labels
real incident IDs
```

---

## ReplayId

Definition:

A unique identifier for a specific replay execution or replay package.

Example:

```text
REPLAY-BF-20260524-0001
```

Usage:

- replay metadata
- Power BI replay filtering
- event batch grouping
- presenter bookmarks

---

## CorrelationId

Definition:

A stable identifier that links related synthetic events within a sequence.

Example:

```text
CORR-DEVON-20260524-001
```

Usage:

- KQL joins
- scenario reconstruction
- SOC timelines
- Power BI drillthrough

Preferred phrase:

```text
Use CorrelationId to reconstruct the sequence.
```

---

## EventId

Definition:

Unique identifier for a single synthetic telemetry event.

Usage:

- row-level event uniqueness
- validation
- troubleshooting

---

## Synthetic Telemetry

Definition:

Fictional telemetry generated to simulate realistic Microsoft 365 activity patterns.

Required property:

```text
IsSynthetic = true
```

Preferred phrase:

```text
Synthetic telemetry demonstrates a realistic pattern, not a production finding.
```

---

## Synthetic Incident

Definition:

A fictional incident-like object generated for demo, tabletop, or SOC workflow simulation.

Preferred phrase:

```text
synthetic incident
```

Avoid:

```text
confirmed breach
real case
customer incident
```

---

## Synthetic Persona

Definition:

A fictional user used to simulate enterprise behavior.

Example:

```text
Devon Reyes
```

Rule:

Do not rename synthetic personas to match real customer employees.

---

## Controlled Imperfection

Definition:

An intentional, documented governance weakness included in the lab to make demos realistic.

Examples:

- overexposed HR file
- ambiguous raw/sanitized filenames
- guest added to wrong collaboration space
- unsafe external AI shortcut

Preferred phrase:

```text
controlled imperfection
```

Avoid:

```text
intentional vulnerability in customer environment
```

---

## Data and Content Terms

## Raw Data

Definition:

Synthetic source content containing detailed fictional identifiers or row-level sensitive patterns.

Examples:

```text
AML rows
KYC packet
HR compensation workbook
treasury reconciliation detail
```

---

## Sanitized Data

Definition:

Synthetic content that has been transformed to remove or aggregate sensitive identifiers so it can be used more safely for external, executive, or AI-assisted workflows.

Preferred phrase:

```text
sanitized source
```

---

## Raw vs Sanitized

Definition:

The governance distinction between detailed source content and safer derivative content.

Teaching point:

```text
Wrong-file risk often occurs when raw and sanitized variants are too similar or poorly separated.
```

---

## AI Approved Workspace

Definition:

A governed SharePoint location containing curated, approved, sanitized, or lower-risk source content for AI-assisted work.

Example:

```text
/sites/AIApprovedWorkspace
```

Preferred phrase:

```text
Safe AI adoption starts before the prompt. It starts with source-data governance.
```

---

## External-Ready Package

Definition:

A sanitized, reviewed, and approved document package intended for external sharing.

Avoid:

```text
external package
```

when it is not clear that it has been reviewed or sanitized.

---

## Telemetry and Risk Terms

## RiskScore

Definition:

Synthetic numerical score representing relative scenario priority.

Important:

```text
RiskScore does not prove malicious intent.
```

---

## Severity

Definition:

A synthetic prioritization category such as Low, Medium, High, or Critical.

Preferred phrase:

```text
Severity indicates response priority, not user intent.
```

---

## Sensitive AI Event

Definition:

An AI-related synthetic event involving sensitive source content, sensitive prompt content, sensitive derivative output, or unmanaged AI usage.

Examples:

```text
Copilot interaction over highly confidential source
external AI upload containing AML-CASE pattern
AI output shared externally
```

---

## AIAppInteraction

Definition:

Synthetic operation representing a user interaction with an AI application, usually external or unmanaged unless otherwise specified.

---

## CopilotInteraction

Definition:

Synthetic operation representing a Microsoft Copilot-style interaction inside governed Microsoft 365 context.

Important distinction:

```text
CopilotInteraction and AIAppInteraction are not interchangeable.
```

---

## UnmanagedAppUpload

Definition:

Synthetic operation representing content uploaded to an unmanaged or unapproved application, often used for Shadow AI scenarios.

---

## DLP Override

Definition:

A user decision to continue after a DLP warning, where policy allows override.

Preferred phrase:

```text
DLP override is a review point, not automatic misconduct.
```

Avoid:

```text
user bypassed security maliciously
```

unless the scenario explicitly defines that behavior.

---

## Endpoint Movement

Definition:

Synthetic movement of sensitive content from cloud collaboration into endpoint, local, removable, print, or network-share contexts.

Examples:

```text
FilePrinted
FileCopiedToUSB
FileCopiedToNetworkShare
```

---

## External Sharing Event

Definition:

Synthetic event where content is shared with a recipient, domain, guest, vendor, customer, or external mailbox outside the fictional organization.

Preferred phrase:

```text
external sharing requires context and control review
```

---

## Investigation and SOC Terms

## Insider Risk-style

Definition:

A synthetic scenario pattern that resembles insider-risk review workflows but does not assert malicious intent.

Preferred phrase:

```text
insider-risk-style sequence
```

Avoid:

```text
insider threat
malicious insider
employee theft
```

unless explicitly defined and governed.

---

## Evidence Timeline

Definition:

Ordered sequence of synthetic events used to reconstruct what happened.

Preferred phrase:

```text
timeline reconstruction
```

---

## Case Closure Outcome

Definition:

Documented conclusion for a synthetic case.

Canonical values:

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

---

## Coaching Event

Definition:

A synthetic remediation outcome where the user receives guidance or a safer workflow recommendation.

Preferred phrase:

```text
coaching opportunity
```

---

## False Positive

Definition:

A control or detection fires on content that is benign, synthetic training material, or otherwise expected.

Teaching point:

```text
False positives are part of tuning, not proof that the control is bad.
```

---

## False Negative

Definition:

A sensitive pattern or risky activity is not detected or is under-classified.

Teaching point:

```text
False negatives show why discovery, classification, and validation matter.
```

---

## Dashboard and Reporting Terms

## Executive Risk Snapshot

Definition:

Power BI page or executive view summarizing synthetic governance risk, control response, and trend themes.

Purpose:

```text
help leadership understand where to prioritize governance action
```

---

## Scenario Replay

Definition:

Power BI, ADX, or storyboard view that reconstructs a synthetic scenario in sequence.

Preferred phrase:

```text
sequence creates meaning
```

---

## Governance Backlog

Definition:

Prioritized list of remediation, tuning, ownership, access, policy, training, or process-improvement items.

---

## Managed Governance Review

Definition:

Recurring customer-facing governance session that reviews KPIs, control effectiveness, incidents, remediation, and maturity progression.

---

## Preferred Wording

Use these phrases consistently:

```text
synthetic telemetry
fictional scenario
requires review
business context pending
observed sequence
potential exposure path
policy decision point
coaching opportunity
safe AI adoption
source-data governance
AI inherits access
sequence creates meaning
DLP is coaching plus control
severity is not intent
```

---

## Avoided Wording

Avoid these phrases unless formally justified and governed:

```text
malicious insider
data theft confirmed
employee misconduct proven
customer breach
real incident
production finding
surveillance
users are negligent
DLP failure
AI caused the leak
Copilot leaked data
```

---

## Canonical Severity Values

```text
Low
Medium
High
Critical
```

Do not introduce new severity values without updating:

```text
operations catalog
telemetry schema
Power BI model
KQL detections
Codex build instructions
```

---

## Canonical Labels

Recommended synthetic label set:

```text
Public
Internal
Confidential
Highly Confidential
Highly Confidential - Regulated Financial Data
Highly Confidential - HR Restricted
Highly Confidential - Legal Privileged
```

---

## Canonical Operation Families

Recommended operation families:

```text
File Activity
Email Activity
Teams Activity
Label Activity
DLP Activity
AI Activity
Endpoint Activity
Identity Activity
Investigation Activity
Remediation Activity
```

---

## Language Review Checklist

Before publishing a customer-facing artifact, check:

```text
Is the synthetic nature clear?
Is severity separated from intent?
Is AI described accurately?
Is Copilot separated from unmanaged AI?
Are DLP overrides described neutrally?
Are HR/legal/privacy topics handled carefully?
Are production claims avoided?
Are Microsoft feature claims caveated where needed?
```

---

## Codex Usage Guidance

Codex should use this file to:

1. Use canonical terms consistently.
2. Avoid unsafe or exaggerated wording.
3. Preserve synthetic-only language.
4. Keep severity separate from intent.
5. Distinguish Copilot from unmanaged AI.
6. Use preferred terms in generated docs.
7. Flag new terms for glossary updates.
8. Update this glossary when canonical fields or terms change.
9. Avoid introducing new severity or label values silently.
10. Preserve responsible-use boundaries.

---

## Safety Reminder

Terminology must support responsible use.

Do not use language that implies real production findings, real employee misconduct, legal conclusions, regulatory certification, or confirmed data loss when working with synthetic telemetry and fictional scenarios.
