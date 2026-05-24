# Purview and Defender Control Mapping and Capability Matrix

## Purpose

This document defines the Microsoft Purview, Defender, Entra, Intune/Endpoint, Copilot, DSPM, DLP, and governance-control mapping layer for the synthetic Microsoft 365 E5 banking and financial-services simulation platform.

It explains which Microsoft capabilities are represented in the platform, what each capability contributes, how controls depend on each other, which workloads they cover, and how to phase deployment in a realistic customer environment.

All users, telemetry, files, customers, identifiers, incidents, and business scenarios remain fictional and synthetic.

---

## Core Control Thesis

> One control is not enough. Effective Microsoft 365 data security requires a coordinated control plane across data discovery, classification, permissions, DLP, endpoint movement, AI governance, identity, investigation, and reporting.

Supporting principles:

1. Labels provide meaning, but permissions define reach.
2. DLP detects and guides, but users need safe workflows.
3. Endpoint controls matter when cloud data moves locally.
4. AI governance depends on data governance.
5. Defender and Sentinel add security context and operational response.
6. Executive dashboards translate technical telemetry into business decisions.

---

## Capability Domains

Recommended capability domains:

```text
Data Discovery and Classification
Sensitivity Labels and Protection
DLP and Endpoint DLP
AI Governance and DSPM for AI Concepts
External Sharing and Collaboration Governance
Identity and Access Governance
Endpoint and Device Context
SOC Investigation and Response
Executive Reporting and Continuous Improvement
```

---

## Microsoft Purview Capability Mapping

| Capability | Platform Representation | Demo Value | Example Scenario |
|---|---|---|---|
| Sensitivity labels | label taxonomy and label events | classify and govern sensitive files | BF-SCEN-0013 |
| Data Loss Prevention | DLPPolicyMatch, DLPWarned, DLPOverride, DLPBlocked | detect and guide risky sharing | BF-SCEN-0001, BF-SCEN-0013 |
| Endpoint DLP | FilePrinted, FileCopiedToUSB, FileCopiedToNetworkShare | show data leaving cloud-governed locations | BF-SCEN-0005, BF-SCEN-0030 |
| Auto-labeling concepts | synthetic pattern detection and suggested labels | demonstrate scalable classification | AML/KYC/HR/Legal scenarios |
| Activity Explorer concepts | normalized synthetic activity events | show data movement visibility | all telemetry scenarios |
| Insider Risk concepts | correlated timeline and case model | review risky sequences with context | BF-SCEN-0030 |
| Audit concepts | EventId, TimeGenerated, Operation | reconstruct timeline evidence | all replay scenarios |
| DSPM for AI concepts | AI exposure and over-permissioned source patterns | explain AI readiness risk | BF-SCEN-0007, BF-SCEN-0030 |
| Retention concepts | lifecycle guidance and records concepts | support regulated content governance | Legal/AML/Finance scenarios |

---

## Microsoft Defender Capability Mapping

| Capability | Platform Representation | Demo Value | Example Scenario |
|---|---|---|---|
| Defender XDR concepts | cross-signal incident story | connect identity, endpoint, cloud app, and data | Sentinel roadmap / BF-SCEN-0030 |
| Defender for Endpoint concepts | DeviceId, DeviceName, endpoint movement | show endpoint context | BF-SCEN-0005 |
| Defender for Cloud Apps concepts | unmanaged AI app and external cloud app activity | govern Shadow AI and app uploads | BF-SCEN-0002 |
| Email and collaboration protection concepts | external email and attachment activity | track sensitive external sends | BF-SCEN-0023 |
| Incident correlation concepts | CorrelationId and multi-stage chain | show sequence-based detection | BF-SCEN-0030 |
| Investigation graph concepts | user-file-device-app relationships | visualize entity context | SOC/Sentinel expansion |

---

## Microsoft Entra Capability Mapping

| Capability | Platform Representation | Demo Value | Example Scenario |
|---|---|---|---|
| Groups and access control | department and workspace group model | control access to sensitive sites | tenant architecture |
| Conditional Access concepts | ConditionalAccessTriggered, MFARequired | identity-to-data correlation | BF-SCEN-0022 |
| Risky sign-in concepts | RiskySignIn | show identity risk before sensitive download | BF-SCEN-0022 |
| Guest governance | GuestUserAdded, ExternalUserAccessed | show external collaboration risk | BF-SCEN-0010 |
| Access reviews | governance recommendation | reduce overexposure | HR/Copilot scenarios |
| Privileged role separation | operational guidance | reduce admin and investigation risk | deployment guide |

---

## Intune and Endpoint Capability Mapping

| Capability | Platform Representation | Demo Value | Example Scenario |
|---|---|---|---|
| Managed device requirement | device compliance concepts | restrict sensitive data access | Conditional Access scenarios |
| Endpoint DLP | print, copy, USB, network-share events | show local data movement | BF-SCEN-0005, BF-SCEN-0030 |
| Device identity | DeviceId and DeviceName | support investigation pivots | endpoint movement scenarios |
| Browser upload control concepts | UnmanagedAppUpload | govern uploads to unmanaged AI | BF-SCEN-0002 |
| Local file movement monitoring | endpoint activity events | explain cloud-to-endpoint risk | treasury/AML scenarios |

---

## Copilot and AI Governance Mapping

| Governance Need | Platform Representation | Microsoft Control Concept |
|---|---|---|
| safe source content | AI Approved Workspace | SharePoint, labels, permissions |
| Copilot source exposure | FileReferencedByCopilot / CopilotInteraction | Copilot auditing and Purview concepts |
| unmanaged AI usage | AIAppInteraction / UnmanagedAppUpload | Defender for Cloud Apps, DLP concepts |
| prompt-sensitive content | PromptText and risk scoring | AI governance monitoring concepts |
| derivative sensitive output | ResponsePreview and output sharing | DLP, labels, review workflow |
| AI readiness dashboard | AI risk KPIs | Power BI, ADX, Purview concepts |
| overexposed data | broad permissions and sensitive label | DSPM for AI concepts |

---

## Workload-to-Control Matrix

| Workload | Labels | DLP | Endpoint DLP | Defender | Entra | AI Governance | Reporting |
|---|---|---|---|---|---|---|---|
| SharePoint Online | Yes | Yes | Indirect | Yes | Yes | Yes | Yes |
| OneDrive for Business | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Teams | Yes / contextual | Yes | Indirect | Yes | Yes | Yes | Yes |
| Exchange Online | Yes | Yes | No | Yes | Yes | Indirect | Yes |
| Power BI | Sensitivity concepts | Export review | Indirect | Indirect | Yes | Yes | Yes |
| Microsoft Copilot | Source labels | Indirect / scenario-based | No | Indirect | Yes | Yes | Yes |
| External AI App | No native label | DLP / app governance concepts | Upload controls | Yes | Conditional controls | Yes | Yes |
| Endpoint | File labels | Endpoint DLP | Yes | Yes | Device compliance | Upload control | Yes |

---

## DLP Coverage Matrix

| Data Domain | Exchange | SharePoint | OneDrive | Teams | Endpoint | External AI |
|---|---|---|---|---|---|---|
| AML / SAR | block/warn | block/warn | block/warn | warn | block/warn | block/alert |
| KYC / Loan Packets | block/warn | block/warn | block/warn | warn | warn/block | block/alert |
| Treasury | warn/block | warn/block | warn/block | audit/warn | block | alert/block |
| HR Compensation | block | block | block | warn/block | warn/block | block/alert |
| Legal Privileged | block | block | block | warn/block | block | block/alert |
| Executive Board Materials | warn/block | warn/block | warn/block | warn | warn | alert/block |

---

## Control Dependency Map

```text
Data discovery
        ↓
Classification and labels
        ↓
Permission review and access governance
        ↓
DLP policy design
        ↓
Endpoint DLP and app governance
        ↓
AI governance and Copilot readiness
        ↓
SOC investigation and remediation process
        ↓
Executive reporting and continuous improvement
```

Key dependency:

> DLP and AI governance are weaker when classification and permission hygiene are incomplete.

---

## Licensing and Feature Assumption Guidance

This platform assumes a Microsoft 365 E5-style environment for conceptual completeness.

Capabilities may depend on:

- Microsoft 365 E5 licensing
- Microsoft Purview licensing and configuration
- Microsoft Defender licensing and onboarding
- Microsoft Entra ID P2 concepts
- Endpoint onboarding and supported operating systems
- Power BI licensing
- Copilot licensing and availability
- regional and tenant feature availability

Important:

> Always validate current Microsoft licensing, feature availability, and tenant configuration before positioning a capability as deployable for a customer.

---

## Operational Ownership Matrix

| Control Area | Primary Owner | Supporting Roles |
|---|---|---|
| Sensitivity labels | Compliance / Data Governance | Security, business data owners |
| DLP policies | Purview / Security | Compliance, business owners |
| Endpoint DLP | Endpoint Security | Purview, SOC |
| External sharing | SharePoint / Collaboration Governance | Security, Legal |
| Guest access | Entra / Collaboration Admin | Business owners, Security |
| AI governance | AI Sponsor / Security | Compliance, Legal, Data Governance |
| Insider Risk-style process | Security Governance | HR, Legal, Privacy |
| SOC response | Security Operations | IT, Legal, HR |
| Executive reporting | CISO Office / Governance | Power BI, Data Platform |

---

## Control Gaps to Demonstrate

Use controlled synthetic gaps to teach governance maturity.

| Gap | Demo Pattern | Recommended Fix |
|---|---|---|
| unlabeled sensitive file | KYC packet without label | auto-label / label recommendation |
| overexposed HR file | Copilot can reference HR workbook | access review and restricted workspace |
| raw and sanitized file confusion | wrong vendor attachment | naming standards and DLP |
| unmanaged AI app usage | raw AML rows pasted externally | approved AI workflow and app governance |
| endpoint copy risk | sensitive workbook copied to network share | Endpoint DLP and device controls |
| guest added to wrong team | vendor sees internal notes | guest governance and workspace separation |

---

## Recommended Deployment Phases

## Phase 1 - Visibility

Focus:

- identify sensitive data domains
- inventory sites and libraries
- baseline external sharing
- baseline AI usage
- baseline DLP matches

Controls:

- audit mode
- reporting
- label discovery
- Power BI baseline

---

## Phase 2 - Classification and Access Hygiene

Focus:

- publish labels
- classify priority data domains
- review overexposed sites
- separate raw and sanitized workspaces

Controls:

- sensitivity labels
- default labels where appropriate
- access reviews
- external sharing boundaries

---

## Phase 3 - DLP and User Coaching

Focus:

- create DLP policies
- introduce policy tips
- review overrides
- tune false positives

Controls:

- DLP audit/warn/block
- coaching templates
- override review workflow

---

## Phase 4 - Endpoint and AI Governance

Focus:

- control print/copy/upload paths
- govern external AI apps
- create AI Approved Workspace
- monitor sensitive AI interactions

Controls:

- Endpoint DLP
- Defender for Cloud Apps concepts
- DSPM for AI concepts
- AI governance dashboard

---

## Phase 5 - SOC and Executive Operating Model

Focus:

- correlate signals
- create investigation workflow
- define HR/Legal escalation
- report to executives
- tune monthly

Controls:

- KQL hunting
- Sentinel roadmap
- SOC playbooks
- Power BI dashboards
- managed governance review

---

## Maturity Alignment

| Maturity Level | Description | Platform Focus |
|---|---|---|
| Level 1 - Awareness | risks are known but not measured | executive demo and baseline dashboard |
| Level 2 - Visibility | sensitive data and movement are visible | labels, audit, Power BI |
| Level 3 - Guardrails | DLP and sharing controls guide users | DLP, policy tips, guest governance |
| Level 4 - Operationalization | SOC and business processes respond | investigations, playbooks, escalation |
| Level 5 - Optimization | controls are measured and tuned continuously | managed governance and executive KPIs |

---

## Scenario-to-Capability Mapping

| Scenario | Primary Capabilities | Secondary Capabilities |
|---|---|---|
| AML External AI Shortcut | DLP, Defender for Cloud Apps concepts, AI governance | labels, SOC playbook |
| Label Downgrade Before Sharing | sensitivity labels, DLP | investigation, coaching |
| Devon Multi-Day Risk Chain | Insider Risk concepts, DLP, Endpoint DLP, AI governance | HR/Legal, Sentinel roadmap |
| HR Copilot Exposure | DSPM for AI concepts, permissions, labels | access review, Copilot governance |
| Treasury Endpoint Movement | Endpoint DLP, labels | Defender for Endpoint concepts |
| Vendor Guest Exposure | Entra guest governance, SharePoint sharing | DLP, access reviews |
| Risky Sign-In + Download | Entra Conditional Access concepts | Defender XDR/Sentinel correlation |

---

## Executive Capability Message

Suggested wording:

> Microsoft 365 E5 is most valuable when its security, compliance, identity, endpoint, AI, and analytics capabilities are connected into a governance operating model. The objective is not isolated controls. The objective is safer collaboration, safer AI adoption, and measurable risk reduction.

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate control-mapping tables.
2. Build customer capability assessments.
3. Create deployment roadmaps.
4. Map scenarios to Microsoft controls.
5. Generate executive capability slides.
6. Identify control dependencies and gaps.
7. Create maturity scorecards.
8. Preserve accurate licensing caveats.
9. Avoid claiming feature availability without validation.
10. Preserve synthetic-only boundaries.

---

## Safety Reminder

This capability matrix is for synthetic demo and advisory planning only.

Validate current Microsoft licensing, feature availability, legal constraints, privacy requirements, and production tenant readiness before implementing any control in a real customer environment.
