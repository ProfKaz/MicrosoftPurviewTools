# Synthetic Security Operations Playbooks - Banking / Finance Microsoft 365 E5 Simulation Pack

## Purpose

This document defines SOC and security-operations playbooks for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services demo lab.

It provides structured response guidance for:

- DLP alerts
- external sharing events
- endpoint DLP events
- unmanaged AI usage
- Copilot sensitive-source exposure
- risky sign-ins
- mass downloads
- label downgrade events
- HR-context insider-risk-style sequences
- multi-stage Devon Reyes risk chains

All examples are fictional and intended for demo, lab, workshop, and training use only.

---

## Operating Principles

1. Start with evidence, not assumptions.
2. Correlate across workloads before escalating.
3. Preserve business context and user intent ambiguity.
4. Use neutral investigation language.
5. Use coaching and workflow correction before formal escalation when appropriate.
6. Include HR and Legal only when context requires it.
7. Keep all telemetry, users, files, cases, and identifiers synthetic.

---

## SOC Triage Lifecycle

```text
Alert Received
        ↓
Initial Triage
        ↓
Data Sensitivity Review
        ↓
Cross-Workload Correlation
        ↓
Business Context Validation
        ↓
Severity Decision
        ↓
Containment or Coaching
        ↓
Remediation Tracking
        ↓
Case Closure
        ↓
Post-Incident Review
```

---

## Severity-Based Response Matrix

| Severity | Typical Conditions | Response |
|---|---|---|
| Low | isolated non-sensitive event, expected business action | log and observe |
| Medium | sensitive file accessed or downloaded by assigned user | validate context and monitor |
| High | external sharing, DLP override, unmanaged AI, endpoint copy | open investigation and remediate |
| Critical | multi-signal chain, HR context plus mass download, endpoint movement | Security + HR + Legal review |

---

## Playbook 1 - DLP Override Review

### Trigger

```text
Operation = DLPOverride
```

### Typical Scenario

A user receives a DLP warning and overrides it to send or share sensitive content.

### Initial Questions

- What file was involved?
- What sensitivity label was applied?
- What DLP policy and rule matched?
- Was the recipient internal or external?
- What justification did the user provide?
- Was a sanitized version available?

### Recommended KQL Pivot

```kusto
SyntheticM365ActivityEvents
| where Operation in ('DLPPolicyMatch', 'DLPWarned', 'DLPOverride', 'ExternalEmailSent', 'FileShared')
| where UserPrincipalName == '{UserPrincipalName}'
| where TimeGenerated between (datetime('{StartTime}') .. datetime('{EndTime}'))
| project TimeGenerated, Operation, FileName, SensitivityLabel, Recipient, TargetDomain, PolicyName, OverrideJustification, RiskScore
| order by TimeGenerated asc
```

### Response Actions

1. Review the file label and content pattern summary.
2. Validate recipient and business justification.
3. Confirm whether the user had an approved workflow.
4. Ask user or manager for business context if needed.
5. Create sanitized derivative if appropriate.
6. Tune policy only if event is a false positive.
7. Close as coaching, policy tuning, benign, or escalated.

### Closure Options

- Closed - Benign
- Closed - Coaching Completed
- Closed - Policy Tuning Required
- Closed - Escalated

---

## Playbook 2 - External AI Sensitive Data Usage

### Trigger

```text
Operation in ('AIAppInteraction', 'UnmanagedAppUpload')
```

### Typical Scenario

A user pastes fictional AML, SAR, KYC, account-like, HR, or legal values into an unmanaged AI application.

### Initial Questions

- Was the AI application managed or unmanaged?
- Did the prompt contain sensitive patterns?
- Which source files were accessed before the prompt?
- Was an approved Copilot workflow available?
- Was the output saved or shared afterward?

### Recommended KQL Pivot

```kusto
let aiEvents = SyntheticM365ActivityEvents
| where Operation in ('AIAppInteraction', 'UnmanagedAppUpload')
| where UserPrincipalName == '{UserPrincipalName}'
| project AiTime = TimeGenerated, UserPrincipalName, Operation, AppName, PromptText, RiskScore, CorrelationId;
let priorFileEvents = SyntheticM365ActivityEvents
| where Operation in ('FileAccessed', 'FileDownloaded')
| where UserPrincipalName == '{UserPrincipalName}'
| project FileTime = TimeGenerated, FileName, SensitivityLabel, Operation, CorrelationId;
aiEvents
| join kind=leftouter priorFileEvents on CorrelationId
| where FileTime between (AiTime - 4h .. AiTime)
| order by AiTime asc
```

### Response Actions

1. Identify the prompt content category.
2. Confirm whether the values were synthetic demo values.
3. Identify source files accessed within four hours.
4. Review whether DLP or Defender for Cloud Apps generated a signal.
5. Coach user on approved AI workflows.
6. Update AI governance guidance or app control if repeated.
7. Consider stronger controls for unmanaged AI upload.

### Coaching Message

```text
Hi {UserName},

We observed activity that appears to involve sensitive content being used with an unmanaged AI application. For banking, customer, AML, KYC, HR, legal, or treasury data, please use approved Microsoft 365 Copilot workflows and governed source files. Raw rows and identifiers should not be pasted into external AI tools.
```

---

## Playbook 3 - Endpoint DLP Movement

### Trigger

```text
Operation in ('FilePrinted', 'FileCopiedToNetworkShare', 'FileCopiedToUSB', 'EndpointDLPPolicyMatch')
```

### Typical Scenario

A sensitive file is downloaded and later printed, copied to a network share, or copied to removable media.

### Initial Questions

- What device was used?
- Was the device compliant?
- Which file was moved?
- What sensitivity label applied?
- Was printing or copying expected for the role?
- Did the user recently receive DLP warnings or HR context?

### Recommended KQL Pivot

```kusto
SyntheticM365ActivityEvents
| where Operation in ('FileDownloaded', 'FilePrinted', 'FileCopiedToNetworkShare', 'FileCopiedToUSB', 'EndpointDLPPolicyMatch')
| where UserPrincipalName == '{UserPrincipalName}'
| where TimeGenerated > ago(7d)
| project TimeGenerated, Operation, FileName, SensitivityLabel, DeviceId, DeviceName, AdditionalProperties, RiskScore, ScenarioId
| order by TimeGenerated asc
```

### Response Actions

1. Validate device compliance.
2. Review destination path, printer, or removable media reference.
3. Confirm business purpose.
4. Review recent related events.
5. Restrict endpoint action if policy requires it.
6. Coach user or escalate depending on severity.
7. Document remediation.

### Recommended Remediations

- block USB copy for regulated data
- warn or block printing of legal/HR/regulated files
- restrict network-share copy
- require managed device for sensitive library access
- create approved offline-review workflow if needed

---

## Playbook 4 - Risky Sign-In Followed by Sensitive Download

### Trigger

```text
RiskySignIn followed by FileDownloaded within 4 hours
```

### Typical Scenario

A persona signs in from an unusual location, satisfies MFA, and downloads sensitive banking files shortly afterward.

### Initial Questions

- Was the sign-in location expected?
- Was the device managed?
- Was MFA satisfied?
- Which sensitive files were accessed?
- Was this during normal work hours?
- Does the user normally access these files?

### Recommended KQL Pivot

```kusto
let risky = SyntheticM365ActivityEvents
| where Operation in ('RiskySignIn', 'ConditionalAccessTriggered', 'MFARequired')
| where UserPrincipalName == '{UserPrincipalName}'
| project SignInTime = TimeGenerated, Operation, DeviceId, AdditionalProperties, CorrelationId;
let data = SyntheticM365ActivityEvents
| where Operation in ('FileAccessed', 'FileDownloaded')
| where UserPrincipalName == '{UserPrincipalName}'
| project DataTime = TimeGenerated, FileName, SensitivityLabel, Operation, CorrelationId;
risky
| join kind=inner data on CorrelationId
| where DataTime between (SignInTime .. SignInTime + 4h)
| order by SignInTime asc
```

### Response Actions

1. Validate user travel or VPN explanation.
2. Confirm MFA and device compliance.
3. Review downloaded files.
4. If suspicious, revoke session in real environments.
5. If benign, close with documented context.
6. If correlated with other risky actions, escalate.

---

## Playbook 5 - Label Downgrade Before Sharing

### Trigger

```text
LabelDowngrade followed by FileShared or ExternalEmailSent within 15 minutes
```

### Typical Scenario

A user changes a file from Confidential or Highly Confidential to a lower label and then shares it.

### Initial Questions

- What was the original label?
- What was the final label?
- Was the file actually sanitized?
- Was the recipient internal or external?
- Did DLP match after downgrade?
- Was there a justification?

### Recommended KQL Pivot

```kusto
let labels = SyntheticM365ActivityEvents
| where Operation in ('SensitivityLabelChanged', 'LabelDowngrade', 'SensitivityLabelRemoved')
| project LabelTime = TimeGenerated, UserPrincipalName, FileName, PreviousSensitivityLabel, SensitivityLabel, CorrelationId;
let shares = SyntheticM365ActivityEvents
| where Operation in ('FileShared', 'ExternalEmailSent')
| project ShareTime = TimeGenerated, UserPrincipalName, FileName, Recipient, TargetDomain, CorrelationId;
labels
| join kind=inner shares on UserPrincipalName, FileName
| where ShareTime between (LabelTime .. LabelTime + 15m)
| order by ShareTime desc
```

### Response Actions

1. Compare source and derivative file.
2. Validate if sensitive patterns remain.
3. Review DLP results.
4. Request user justification if needed.
5. Restore correct label if required.
6. Coach user on sanitized derivative process.

---

## Playbook 6 - Guest Access to Sensitive Workspace

### Trigger

```text
GuestUserAdded followed by FileAccessed or ExternalUserAccessed
```

### Typical Scenario

A guest is added to a team or site that contains sensitive banking, legal, HR, or security files.

### Initial Questions

- Who added the guest?
- Which team or site was affected?
- Was the workspace intended for external collaboration?
- Which files could the guest access?
- Was access time-bound?
- Is a sanitized workspace available?

### Response Actions

1. Review guest identity and target domain.
2. Review site/team permissions.
3. Identify sensitive files in scope.
4. Remove guest if inappropriate.
5. Move collaboration to Vendor Collaboration site.
6. Add access expiration and named-user sharing.
7. Document remediation.

---

## Playbook 7 - HR Context Followed by Mass Download

### Trigger

```text
HRSignal followed by MassDownloadActivity within 72 hours
```

### Typical Scenario

A role-change context appears and the user downloads many sensitive files shortly afterward.

### Initial Questions

- What HR signal exists?
- Did the user require the files for transition work?
- Which files were downloaded?
- Were endpoint movement or external sharing events observed?
- Has the user received prior coaching?
- Does Legal need to advise on the review process?

### Response Actions

1. Open security case.
2. Preserve neutral language.
3. Include HR and Legal.
4. Review user’s normal baseline.
5. Validate manager explanation.
6. Review endpoint and external sharing activity.
7. Remediate access if needed.
8. Close as benign, coaching, access remediated, or escalated.

---

## Playbook 8 - Devon Multi-Stage Risk Chain

### Trigger

```text
Multiple high-risk signals across 5 business days for Devon Reyes
```

### Required Signal Examples

- FileDownloaded
- AIAppInteraction
- DLPPolicyMatch
- DLPOverride
- FilePrinted
- FileCopiedToNetworkShare
- HRSignal
- InsiderRiskSequence

### Recommended Timeline Query

```kusto
SyntheticM365ActivityEvents
| where UserPrincipalName == 'devon.reyes@mhdemos.com'
| where ScenarioId == 'BF-SCEN-0030'
| project TimeGenerated, Workload, Operation, FileName, SensitivityLabel, Recipient, TargetDomain, DeviceId, RiskScore, BusinessContext
| order by TimeGenerated asc
```

### Response Actions

1. Build full timeline.
2. Identify source files.
3. Review AI prompts and unmanaged app usage.
4. Review DLP warnings and overrides.
5. Review endpoint movement.
6. Validate HR context.
7. Include HR and Legal.
8. Restrict access if needed.
9. Coach user if negligence is likely.
10. Escalate if repeated activity continues after coaching.

### Executive Summary Template

```text
A synthetic multi-day review identified a sequence of sensitive data handling events involving Devon Reyes. Individually, some actions may align with customer operations work. However, the combined pattern of sensitive downloads, external AI usage, DLP override, endpoint movement, and HR context requires structured review and remediation.
```

---

## Teams War-Room Structure

Recommended private Teams chat or channel:

```text
IR Review - CASE-IR-FIC-2026-0001
```

Participants:

- Head of IT / Security
- Cybersecurity Manager
- Platform Engineer
- Corporate Lawyer
- HR Manager
- Business owner or manager when appropriate

Recommended tabs or linked files:

- Case Summary
- Timeline Export
- Evidence Index
- Remediation Tracker
- User Coaching Outcome

---

## Escalation Matrix

| Trigger | Notify Security Manager | Notify Head of Security | Include HR | Include Legal | Business Owner |
|---|---|---|---|---|---|
| DLP override external send | Yes | If high severity | No | If legal/regulatory data | Yes |
| Unmanaged AI with AML/KYC | Yes | Yes | No | If regulatory exposure | Yes |
| Endpoint copy to USB/network | Yes | Yes | If user-risk context | If legal exposure | Yes |
| Risky sign-in + sensitive download | Yes | If high severity | No | No unless exposure confirmed | Maybe |
| HR signal + mass download | Yes | Yes | Yes | Yes | Yes |
| Legal privileged content shared broadly | Yes | Yes | No | Yes | Yes |
| Multi-stage Devon risk chain | Yes | Yes | Yes | Yes | Yes |

---

## Remediation Checklist

Use relevant items only:

- revoke external sharing link
- remove guest access
- restore sensitivity label
- create sanitized derivative file
- restrict SharePoint site permissions
- require named-user sharing
- apply access expiration
- block USB copy for regulated data
- block or warn external AI upload
- create AI Approved Workspace alternative
- coach user
- update DLP policy
- tune SIT confidence
- review false positive/false negative
- update executive summary
- close case with documented outcome

---

## Post-Incident Review Template

```text
Case ID:
Scenario ID:
Primary User:
Date Opened:
Date Closed:
Severity:
Confidence:

What happened:

What business context existed:

Which controls responded:

What was missed or delayed:

What was remediated:

What should be improved:

Policy tuning required:

User coaching required:

Access review required:

Follow-up owner:

Follow-up due date:
```

---

## Tabletop Exercise Flow

### 30-Minute Exercise

```text
0-5 min: Scenario briefing
5-10 min: Initial alert triage
10-15 min: KQL pivots and evidence review
15-20 min: Business context and HR/Legal decision
20-25 min: Remediation selection
25-30 min: Executive summary and lessons learned
```

### 60-Minute Exercise

```text
0-10 min: Scenario briefing and alert review
10-20 min: Cross-workload KQL hunting
20-30 min: Timeline construction
30-40 min: HR/Legal/security decision point
40-50 min: Remediation and control tuning
50-60 min: Executive readout and post-incident review
```

---

## Analyst Notes Guidance

Good analyst note:

```text
Observed DLP override for Full_KYC_Packet_KYC-FIC-88421_Internal.pdf sent to an external test recipient. File is labeled Highly Confidential - Regulated Financial Data. User justification references urgent vendor review. Need to validate whether a sanitized package was available.
```

Poor analyst note:

```text
User tried to steal KYC data.
```

Use evidence-first language.

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate SOC playbooks.
2. Create incident-response documentation.
3. Generate Teams war-room messages.
4. Build remediation checklists.
5. Create tabletop exercises.
6. Create analyst notes using neutral language.
7. Map KQL pivots to scenario IDs.
8. Generate post-incident review documents.
9. Support executive readouts.
10. Preserve synthetic-only boundaries.

---

## Safety Reminder

These playbooks are for synthetic demo and training environments only.

Do not use them to investigate, discipline, score, or monitor real employees or real cases without appropriate legal, privacy, HR, compliance, and governance approvals.
