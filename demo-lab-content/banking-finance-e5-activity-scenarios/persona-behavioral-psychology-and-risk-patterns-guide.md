# Persona Behavioral Psychology and Risk Patterns Guide

## Purpose

This document defines the human-behavior realism layer for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It explains how fictional personas should behave under normal work, deadline pressure, ambiguity, AI assistance, collaboration overload, role-change context, and security-control friction.

The goal is to make synthetic user activity feel enterprise-like, plausible, and useful for Purview, DLP, Copilot governance, Insider Risk, SOC, and executive storytelling demos.

All personas, behaviors, incidents, files, customers, IDs, and data remain fictional.

---

## Core Behavioral Principle

> Security risk in Microsoft 365 is often created by normal people making reasonable decisions under imperfect conditions.

This guide should help scenario generators avoid simplistic behavior such as:

- every risky action is malicious
- every user ignores policy
- every DLP warning is overridden
- every AI prompt is unsafe
- every executive is careless
- every analyst is overly technical

Realism comes from ambiguity, pressure, habits, incentives, and context.

---

## Behavioral Archetypes

## 1. The Deadline-Driven Operator

### Typical Roles

- Customer Operations Specialist
- Junior Operations Analyst
- Finance Analyst
- PMO Coordinator

### Behavior Pattern

This persona is trying to complete a task quickly. They may know the policy but choose the fastest path when the deadline feels urgent.

### Common Actions

- downloads files for offline review
- shares links in Teams instead of formal workspaces
- uses similar raw and sanitized file names incorrectly
- asks AI to summarize content quickly
- overrides warnings with business justification

### Risk Themes

- accidental oversharing
- wrong attachment
- external AI shortcut
- DLP override
- endpoint movement

### Example Synthetic Behavior

```text
Devon downloads AML_Monthly_Review_AML-CASE-2026-0519_Internal.xlsx before a vendor call and later asks an unmanaged AI app to summarize the rows quickly.
```

---

## 2. The Overconfident Expert

### Typical Roles

- Senior Analyst
- Data Scientist
- Engineer
- Legal Specialist
- Security Specialist

### Behavior Pattern

This persona understands the business domain well and may believe they can judge risk manually better than automated controls.

### Common Actions

- downgrades labels after self-assessing content
- creates exceptions without documentation
- exports underlying data from Power BI
- uses technical workarounds
- stores working files outside approved locations

### Risk Themes

- label downgrade
- false sense of control
- shadow workflow creation
- unmanaged derivative files

### Example Synthetic Behavior

```text
A data scientist exports a pre-anonymized dataset, assuming customer-like values are already safe, but the file still contains CUST-BNK and ACCT-FIC patterns.
```

---

## 3. The Helpful Collaborator

### Typical Roles

- PMO Lead
- Customer Support Specialist
- Sales Manager
- Executive Assistant

### Behavior Pattern

This persona wants to help others move forward. They may overshare because they are optimizing for responsiveness and service quality.

### Common Actions

- forwards internal notes to external partners
- adds guests to Teams quickly
- posts files in broad channels
- creates broad sharing links
- reuses previous documents without sanitizing

### Risk Themes

- guest exposure
- external sharing
- broad-link creation
- customer support data leakage

### Example Synthetic Behavior

```text
A support specialist forwards internal complaint notes to a customer-facing mailbox instead of using the approved customer-safe response document.
```

---

## 4. The AI Optimizer

### Typical Roles

- Data Scientist
- Analyst
- Executive
- Operations Analyst
- PMO Lead

### Behavior Pattern

This persona uses AI to save time and improve output quality. Risk depends on whether they use governed Copilot workflows or unmanaged external AI tools.

### Common Actions

- summarizes internal files with Copilot
- asks AI to rewrite sensitive content
- pastes raw rows into external AI
- asks for customer-level analysis
- creates derivative summaries that retain sensitive context

### Risk Themes

- Copilot source exposure
- unmanaged AI upload
- prompt oversharing
- AI-generated derivative risk

### Example Synthetic Behavior

```text
Priya asks Copilot to summarize an anonymized dataset safely, while Devon pastes raw AML rows into an unmanaged AI tool to save time.
```

---

## 5. The Risk-Aware Guardian

### Typical Roles

- Head of IT / Security
- Cybersecurity Manager
- Corporate Lawyer
- HR Manager
- Compliance Officer

### Behavior Pattern

This persona prioritizes control, evidence, and governance. They may slow down workflows to validate context.

### Common Actions

- asks whether a file is sanitized
- redirects users to approved workspaces
- requests evidence before escalation
- avoids assuming malicious intent
- documents coaching or remediation outcomes

### Risk Themes

- process friction
- delayed decision-making
- over-cautious sharing
- governance bottleneck

### Example Synthetic Behavior

```text
Ana asks the team to validate whether a KYC packet is sanitized before it is shared with a vendor-review mailbox.
```

---

## 6. The Executive Summarizer

### Typical Roles

- CEO
- Executive Leader
- Chief Risk Officer
- Board Liaison

### Behavior Pattern

This persona needs concise summaries and may rely on assistants, Copilot, or dashboards to reduce complexity.

### Common Actions

- requests summary of board materials
- asks for key risks by department
- forwards executive summary drafts
- requests AI-generated talking points
- accesses highly confidential documents

### Risk Themes

- executive oversharing
- Copilot overexposure
- board-material leakage
- sensitive summary reuse

### Example Synthetic Behavior

```text
Alexander asks Copilot to summarize board risk materials, but one source file is over-permissioned and includes restricted finance details.
```

---

## Cognitive Biases to Simulate

## Urgency Bias

The user prioritizes speed over governance.

Signals:

- short messages
- urgent subject lines
- DLP overrides
- wrong attachment
- external sharing before review

Example wording:

```text
I know this is not ideal, but the vendor call starts in 10 minutes.
```

---

## Familiarity Bias

The user trusts a recurring partner or internal colleague and underestimates the risk of sharing.

Signals:

- guest access granted quickly
- internal notes sent externally
- broad link reused

Example wording:

```text
They have reviewed these files before, so it should be fine.
```

---

## Automation Bias

The user trusts AI or automated output too much.

Signals:

- Copilot output reused without source review
- external AI summary accepted as safe
- raw data pasted because AI is perceived as a tool, not a destination

Example wording:

```text
I only used AI to summarize it, not to store it.
```

---

## Optimism Bias

The user assumes nothing will go wrong.

Signals:

- quick external send
- label downgrade
- policy warning ignored

Example wording:

```text
This is just for a quick review. It will not go anywhere else.
```

---

## Authority Bias

The user complies quickly because a senior person requested something.

Signals:

- rushed sharing for executive request
- DLP warning bypassed because request came from leadership
- insufficient review of recipient or file version

Example wording:

```text
Alexander needs this before the steering call, so I sent the current version.
```

---

## Ambiguity Bias

The user chooses the easiest interpretation when policy is unclear.

Signals:

- asks whether external sharing is allowed after sending
- uses personal OneDrive because official workspace is unclear
- shares raw and sanitized variants inconsistently

Example wording:

```text
I was not sure which workspace to use, so I uploaded it to my working folder.
```

---

## Pressure Patterns

## Deadline Pressure

Common in:

- Finance close
- Vendor review
- Loan committee
- Regulatory response
- Executive reporting

Risk behaviors:

- rushed email
- wrong file version
- DLP override
- quick AI prompt
- broad Teams post

---

## Meeting Pressure

Common in:

- board preparation
- steering committee
- vendor calls
- incident review

Risk behaviors:

- file download before meeting
- printed documents
- Teams link posted quickly
- summary generated without source review

---

## Role-Change Pressure

Common in:

- employee transfer
- resignation
- reorganization
- temporary coverage

Risk behaviors:

- mass download
- local copy creation
- knowledge transfer shortcuts
- unclear ownership of files

---

## Customer Escalation Pressure

Common in:

- support cases
- complaints
- disputes
- banking operations

Risk behaviors:

- forwarding internal notes
- attaching investigation details
- exposing account-like values
- using external email under urgency

---

## Department Communication Styles

## Executive Leadership

Style:

- concise
- outcome-oriented
- strategic
- asks for summaries and implications

Example:

```text
Please summarize the top three risk themes and what requires leadership attention before the board review.
```

---

## HR

Style:

- cautious
- privacy-aware
- structured
- sensitive to wording

Example:

```text
Please avoid sharing employee-level compensation details outside the HR restricted workspace.
```

---

## Finance

Style:

- deadline-driven
- numbers-focused
- close-cycle oriented
- evidence-based

Example:

```text
We need the reconciliation exceptions validated before the close review at 4 PM.
```

---

## Legal

Style:

- precise
- privileged-language aware
- careful about disclosure
- asks for approved channels

Example:

```text
Do not include privileged analysis in the PMO tracker. Use the non-privileged action summary instead.
```

---

## Sales

Style:

- relationship-focused
- customer-responsive
- may push for faster external sharing

Example:

```text
Can we send the sanitized version today? The customer wants to keep momentum.
```

---

## Engineering

Style:

- technical
- solution-oriented
- may use workarounds
- comfortable with scripts and exports

Example:

```text
I exported the data to test the mapping locally. I can remove the raw identifiers before sharing.
```

---

## Data Science

Style:

- analytical
- experiment-driven
- comfortable with AI and data transformation
- may underestimate re-identification risk

Example:

```text
The dataset is mostly anonymized, but I will double-check whether any customer-like keys remain.
```

---

## IT Security

Style:

- evidence-based
- process-driven
- cautious but pragmatic
- avoids intent assumptions

Example:

```text
Let us validate the sequence before we decide whether this is a policy issue, a coaching issue, or an escalation.
```

---

## Customer Support

Style:

- empathetic
- urgency-driven
- customer-facing
- may reuse internal notes too quickly

Example:

```text
I want to respond quickly, but I need to make sure the customer-safe version does not include internal review notes.
```

---

## PMO

Style:

- coordination-focused
- action-item oriented
- may copy summaries into broad trackers

Example:

```text
Please add only the non-sensitive action items to the steering tracker.
```

---

## Safe vs Unsafe AI Usage Tendencies

## Safe AI Usage

Examples:

- summarize sanitized documents
- generate aggregate executive summary
- rewrite customer-safe response
- draft project status without identifiers
- create action items from non-privileged tracker

Behavior markers:

- user requests aggregate summary
- user explicitly excludes identifiers
- source file is in AI Approved Workspace
- output is reviewed before sharing

---

## Unsafe AI Usage

Examples:

- paste raw AML rows into external AI
- ask AI to summarize HR compensation workbook
- ask AI to rewrite privileged legal memo for broad audience
- upload treasury reconciliation workbook to unmanaged app
- ask for customer-by-customer risk ranking from sensitive file

Behavior markers:

- raw rows in prompt
- unmanaged AI app
- sensitive labels
- external sharing after AI output
- no source review

---

## Negligent vs Malicious Ambiguity

The platform should preserve ambiguity unless a scenario explicitly defines malicious intent.

### Negligent Pattern

- user is rushed
- user uses wrong file
- user asks for help after warning
- user accepts coaching
- user creates sanitized version after correction

### Suspicious Pattern

- repeated downloads
- label downgrade before sharing
- DLP override with vague justification
- endpoint movement
- external AI after sensitive access
- behavior continues after coaching

### Malicious Pattern

Use sparingly.

- deliberate evasion
- repeated policy bypass
- deceptive justification
- external movement after explicit warning
- unauthorized collection across unrelated domains

Default posture:

> Treat most scenarios as negligent or ambiguous unless explicitly configured otherwise.

---

## Devon Reyes Behavioral Model

Devon is the primary ambiguity-anchor persona.

### Normal Devon

- works in Customer Operations
- handles complaints and KYC support tasks
- asks clarifying questions
- sometimes uses approved templates
- wants to be helpful

### Risky Devon

- rushes under vendor or customer pressure
- downloads sensitive files for convenience
- confuses raw and sanitized versions
- uses external AI for quick summaries
- overrides DLP when deadline pressure is high
- copies files to temporary locations

### Escalated Devon

Use only in advanced scenarios.

- repeats behavior after coaching
- combines downloads, endpoint movement, and external sharing
- has role-change context
- accesses data outside normal scope

### Recommended Devon Language

```text
I thought this was the sanitized version.
I was trying to prepare before the vendor call.
I did not realize the AI tool counted as external sharing.
The warning appeared, but I had to send the package quickly.
I can recreate the file without the customer references.
```

---

## Scenario Realism Heuristics

A scenario feels realistic when:

- the user has a plausible business reason
- the risky action is a shortcut, not cartoonish behavior
- there is a safer path the user could have taken
- controls respond in a graduated way
- another persona provides correction or guidance
- investigation language remains neutral
- the sequence creates meaning

A scenario feels unrealistic when:

- the user behaves maliciously without context
- every control fires at once
- every file is highly confidential
- there is no normal business activity
- the risky action has no business reason
- the conclusion assumes intent too early

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate more realistic persona behavior.
2. Vary communication style by department.
3. Simulate pressure-driven shortcuts.
4. Create safe and unsafe AI usage patterns.
5. Preserve negligent vs malicious ambiguity.
6. Generate Teams and email language that matches role context.
7. Improve Devon-centered storylines.
8. Add cognitive-bias realism to synthetic scenarios.
9. Avoid simplistic or exaggerated risky behavior.
10. Preserve synthetic-only boundaries.

---

## Safety Reminder

Behavioral simulation must remain fictional.

Do not use this guide to profile, evaluate, discipline, monitor, or infer intent about real employees or real users.
