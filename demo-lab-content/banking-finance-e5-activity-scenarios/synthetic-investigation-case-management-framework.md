# Synthetic Investigation Case Management Framework

## Purpose

This document defines the investigation case-management framework for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services demo lab.

It provides a structured, privacy-aware, and neutral approach for handling synthetic alerts, DLP events, AI misuse, endpoint movement, risky sign-ins, role-change context, and insider-risk-style timelines.

All examples are fictional and intended for demo, lab, training, and storytelling use only.

---

## Investigation Principles

1. A signal is not proof of intent.
2. Correlated behavior requires review, context, and documentation.
3. HR and Legal context must be handled carefully and only when relevant.
4. Investigation notes should use neutral, factual language.
5. Remediation can include coaching, access cleanup, policy tuning, or formal escalation.
6. Synthetic evidence must remain clearly fictional.
7. The framework is for demo use and must not be used to evaluate real employees without formal governance.

---

## Case Lifecycle

Recommended case states:

```text
New
Triage
Context Review
Evidence Collection
Correlation Review
HR / Legal Review
Containment or Remediation
User Coaching
Executive Summary
Closed - Benign
Closed - Coaching Completed
Closed - Policy Tuning Required
Closed - Access Remediated
Closed - Escalated
Closed - False Positive
```

---

## Case Object Model

Recommended synthetic case structure:

```json
{
  "caseId": "CASE-IR-FIC-2026-0001",
  "scenarioId": "BF-SCEN-0030",
  "timelineId": "IR-TL-0001",
  "primaryUser": "devon.reyes@mhdemos.com",
  "caseTitle": "Devon Reyes multi-day sensitive data handling review",
  "severity": "Critical",
  "confidence": "High",
  "state": "Evidence Collection",
  "openedBy": "ana.rodriguez@mhdemos.com",
  "openedAt": "2026-05-24T15:45:00Z",
  "signals": [
    "FileDownloaded",
    "AIAppInteraction",
    "DLPOverride",
    "FilePrinted",
    "FileCopiedToNetworkShare",
    "InsiderRiskSequence"
  ],
  "businessContext": "Customer operations deadline and later HR role-change context.",
  "recommendedNextAction": "Review source files, validate business purpose, and include HR/Legal before user conversation."
}
```

---

## Severity and Confidence

### Severity

| Severity | Meaning | Example |
|---|---|---|
| Low | Normal or weakly suspicious activity | isolated file access |
| Medium | Sensitive but explainable event | sensitive file download by assigned user |
| High | Risky action requiring investigation | external AI upload, DLP override, endpoint copy |
| Critical | Multi-signal correlated sequence | HR signal + mass download + endpoint movement |

### Confidence

| Confidence | Meaning |
|---|---|
| Low | Single event or weak evidence. |
| Medium | Multiple related signals, but context remains ambiguous. |
| High | Required signal chain is present, timing aligns, and sensitive data movement is confirmed. |

Important:

High confidence means confidence in the scenario pattern, not confidence in malicious intent.

---

## Triage Process

### Step 1 - Identify the trigger

Examples:

- DLP override
- unmanaged AI upload
- external sharing of regulated financial data
- endpoint copy or print
- risky sign-in followed by sensitive download
- HR context followed by mass download

### Step 2 - Confirm the data sensitivity

Review:

- sensitivity label
- file location
- data pattern category
- business owner
- whether the file was raw or sanitized

### Step 3 - Validate business context

Questions:

- Was the user assigned to this process?
- Was there a deadline?
- Was external collaboration approved?
- Was the user using an approved workspace?
- Was there a safer alternative?

### Step 4 - Determine whether escalation is needed

Escalate if:

- regulated data moved externally
- unmanaged AI app received sensitive content
- endpoint copy or print occurred
- repeated behavior appears after coaching
- HR context exists within the investigation window
- Legal privileged or HR restricted content is involved

---

## Evidence Collection Standards

Recommended evidence categories:

| Evidence Type | Examples |
|---|---|
| File evidence | file name, path, label, owner, content pattern summary |
| Communication evidence | email subject, recipient, Teams message preview, channel |
| DLP evidence | policy name, rule name, action, override justification |
| AI evidence | prompt preview, source file, managed/unmanaged app, response preview |
| Endpoint evidence | device ID, print event, network share path, USB action |
| Identity evidence | risky sign-in, MFA result, location, device compliance |
| Context evidence | scenario, deadline, role-change context, manager validation |
| Remediation evidence | access change, link revoked, sanitized file created, coaching note |

---

## Evidence Handling Guidance

Use neutral terms:

```text
observed
reviewed
correlated
appears to indicate
requires validation
business context pending
user explanation pending
```

Avoid unsupported terms:

```text
stole
exfiltrated
malicious
guilty
intentional theft
insider attack
```

Unless the scenario explicitly defines that conclusion, preserve ambiguity.

---

## HR and Legal Escalation Paths

### Include HR when:

- HRSignal is present.
- role-change context exists.
- user coaching or performance process may be needed.
- repeated risky behavior continues after coaching.
- formal disciplinary path is being considered.

### Include Legal when:

- legal privileged content is involved.
- regulatory response material is involved.
- external disclosure may have occurred.
- case may require formal preservation.
- user monitoring, privacy, or employment implications exist.

### Include both HR and Legal when:

- HR context plus data movement occurs.
- endpoint movement follows role-change context.
- repeated sensitive activity appears after user coaching.
- user-risk escalation may have employment implications.

---

## Case Workflow by Scenario Type

### DLP Override Case

```text
DLPOverride
        ↓
Review file label and recipient
        ↓
Review override justification
        ↓
Check whether sanitized version exists
        ↓
Coach user or tune policy
        ↓
Close as coaching completed or policy tuning required
```

### External AI Case

```text
AIAppInteraction / UnmanagedAppUpload
        ↓
Identify prompt content and source files
        ↓
Check whether raw identifiers were included
        ↓
Validate approved AI alternative
        ↓
Coach user and review app governance
        ↓
Close as coaching completed or escalate if repeated
```

### Endpoint Movement Case

```text
FileDownloaded
        ↓
FilePrinted / FileCopiedToNetworkShare / FileCopiedToUSB
        ↓
Review device compliance
        ↓
Validate business purpose
        ↓
Review Endpoint DLP policy action
        ↓
Remediate access or restrict endpoint movement
```

### HR Context Case

```text
HRSignal
        ↓
MassDownloadActivity or sensitive movement
        ↓
Security triage
        ↓
HR / Legal review
        ↓
Manager validation
        ↓
Coaching, access review, or formal escalation
```

---

## Investigation Artifact Templates

### Case Summary Structure

```text
Case Title:

Case ID:

Primary User:

Scenario ID:

Opened By:

Opened At:

Current State:

Severity:

Confidence:

Business Context:

Observed Signals:

Timeline Summary:

Data Involved:

Controls Triggered:

User Explanation:

HR Context:

Legal Guidance:

Remediation Actions:

Final Outcome:
```

---

### Executive Summary Structure

```text
Summary:
A concise explanation of the risk sequence and business impact.

What Happened:
A neutral description of the event chain.

Why It Matters:
Data sensitivity, external movement, AI usage, endpoint action, or governance concern.

Controls That Responded:
DLP, labels, Endpoint DLP, Defender, Purview, Conditional Access, or investigation workflow.

Recommended Actions:
Access cleanup, coaching, policy tuning, workspace separation, or governance update.
```

---

## Closure Paths

| Closure Path | When to Use | Example Outcome |
|---|---|---|
| Closed - Benign | activity was fully approved and expected | assigned analyst downloaded approved file |
| Closed - Coaching Completed | user made mistake and received guidance | Devon used external AI with synthetic AML rows |
| Closed - Policy Tuning Required | control fired but needs refinement | training sample caused false positive |
| Closed - Access Remediated | permissions were too broad and corrected | HR file permissions restricted |
| Closed - False Positive | event was not actually sensitive or risky | sample pattern in training document |
| Closed - Escalated | repeated or serious sequence needs formal review | HR context plus mass download plus endpoint movement |

---

## Devon Reyes Investigation Narrative Guidance

Devon should be treated as an ambiguity anchor, not as a default malicious actor.

Recommended framing:

```text
Devon performed several actions that, when reviewed individually, may be explainable by business pressure. However, the sequence of downloads, external AI usage, DLP override, and endpoint movement requires structured review.
```

Avoid:

```text
Devon stole data.
Devon is malicious.
Devon is an insider threat.
```

Preferred teaching point:

```text
The value of the investigation is not to assume intent. The value is to correlate behavior, validate context, reduce exposure, and improve controls.
```

---

## Recommended Case Metrics

| Metric | Description |
|---|---|
| Cases Opened | Count of synthetic cases created. |
| Cases Closed | Count of completed cases. |
| Average Time to Triage | Time from first alert to triage start. |
| Average Time to Containment | Time from alert to access remediation or blocked action. |
| Coaching Outcomes | Count of coaching-only closures. |
| Policy Tuning Outcomes | Count of cases closed due to tuning need. |
| Repeat User Cases | Users with more than one case in period. |
| Critical Case Count | Cases with severity Critical. |
| AI-Related Cases | Cases involving CopilotInteraction, AIAppInteraction, or UnmanagedAppUpload. |
| Endpoint Movement Cases | Cases involving print, USB, or network-share copy. |

---

## Suggested Case IDs

Use this format:

```text
CASE-[TYPE]-FIC-[YEAR]-[NUMBER]
```

Examples:

```text
CASE-DLP-FIC-2026-0001
CASE-AI-FIC-2026-0002
CASE-ENDPOINT-FIC-2026-0003
CASE-IR-FIC-2026-0004
CASE-LEGAL-FIC-2026-0005
```

---

## Codex Usage Guidance

Codex should use this framework to:

1. Generate investigation case records.
2. Create neutral case summaries.
3. Decide when HR or Legal should be included.
4. Generate case closure outcomes.
5. Generate coaching artifacts.
6. Create investigation timeline documents.
7. Map synthetic telemetry to case states.
8. Avoid unsupported conclusions about intent.
9. Preserve synthetic-only boundaries.
10. Produce executive-ready summaries for Power BI or reports.

---

## Safety Reminder

This framework is for synthetic demo environments only.

Do not use it to investigate, monitor, evaluate, discipline, or score real employees or real cases without proper legal, privacy, HR, compliance, and governance review.
