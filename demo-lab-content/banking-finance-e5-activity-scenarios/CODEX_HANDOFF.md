# Codex Handoff - Banking / Finance E5 Activity Scenario Pack

## Purpose

This folder extends the synthetic Microsoft 365 / Purview content pack into realistic banking and financial-services operational behavior.

The goal is not only to create files and messages, but to model:

- Realistic business cadence
- Cross-platform Microsoft 365 activity
- Security-relevant user behavior
- Data lifecycle movement
- Sensitive data exposure paths
- Copilot and AI interaction patterns
- Oversharing scenarios
- Insider risk investigation narratives
- Endpoint DLP-relevant actions
- Label governance workflows

Codex should treat these files as orchestration metadata and activity definitions.

---

## Folder Structure

```text
banking-finance-e5-activity-scenarios/
│
├── README.md
├── CODEX_HANDOFF.md
├── technologies-and-activities.json
└── complex-scenarios.json
```

---

## File Descriptions

### `technologies-and-activities.json`

This file contains:

- Microsoft 365 E5 technologies/workloads
- Banking/finance usage patterns
- Daily activities
- Weekly activities
- Monthly activities
- Event-driven activities
- Typical file types
- Common Purview signals
- Common risk behaviors

Codex should use this file to:

- Build realistic activity distributions
- Select technologies for workflows
- Randomize normal vs risky behavior
- Generate time-based activity patterns
- Create telemetry-aligned orchestration

---

### `complex-scenarios.json`

This file contains 30 complex enterprise banking/finance scenarios.

Each scenario should include:

- Scenario title
- Business objective
- Personas involved
- Technologies used
- Daily/weekly/monthly cadence
- Expected files and labels
- Risk narrative
- Copilot or AI usage
- External sharing behavior
- Endpoint behavior
- Expected Purview/Defender telemetry
- Suggested orchestration flow

Codex should use these scenarios to:

- Create long-running simulation workflows
- Build chained activities across workloads
- Trigger multiple Purview signals from one narrative
- Simulate realistic business pressure and mistakes
- Generate investigation timelines

---

## Persona Notes

### Devon Reyes

Devon is the primary risky-behavior simulation user.

Devon is NOT necessarily malicious.

His scenarios include:

- Accidental oversharing
- Incorrect permissions
- Broad sharing links
- Excessive downloads
- Local copies
- Print activity
- Uploads to unmanaged apps
- Unsafe Copilot prompts
- External sharing confusion
- Large-volume file movement
- AI-assisted summarization of sensitive content
- Last-minute operational pressure

Codex should avoid making Devon a cartoon villain.

The value of the scenarios comes from ambiguity:

- Was it intentional?
- Was it negligence?
- Was it workflow pressure?
- Was it poor governance?
- Was it lack of training?
- Was it malicious?

That ambiguity creates realistic investigation and storytelling opportunities.

---

## Suggested Activity Orchestration Model

Codex should ideally orchestrate activity in layers.

### Layer 1 - Background Normal Activity

Examples:

- Outlook email traffic
- Teams chats
- SharePoint file edits
- OneDrive sync
- Planner updates
- Power BI views
- Forms submissions
- Viva Engage posts
- Whiteboard edits
- Loop component collaboration

Goal:

Create believable baseline noise.

---

### Layer 2 - Cyclical Business Activity

Examples:

Daily:
- Customer onboarding
- Transaction review
- Treasury reconciliation
- Support escalations

Weekly:
- Loan committee
- Risk review
- Security review
- PMO steering review

Monthly:
- Finance close
- Payroll review
- Audit evidence collection
- Regulatory reporting
- Executive forecasting

Goal:

Create repeatable operational cadence.

---

### Layer 3 - Risk and Security Events

Examples:

- External sharing
- Sensitive downloads
- Label changes
- Broad permission inheritance
- Endpoint copies
- Large exports
- Suspicious Copilot prompts
- AI copy-paste into external tools
- Mass file access
- Unusual after-hours access

Goal:

Generate security telemetry and investigation narratives.

---

### Layer 4 - Investigation and Response

Examples:

- SOC review
- Teams escalation
- Email follow-up
- Legal involvement
- HR consultation
- File relabeling
- Access revocation
- DLP override justification
- Audit trail export

Goal:

Complete the lifecycle story.

---

## Technologies That Should Be Referenced

Codex should expect scenarios involving:

- Exchange Online
- Outlook Web
- SharePoint Online
- OneDrive for Business
- Microsoft Teams
- Teams Channels
- Teams Private Channels
- Teams Meetings
- Microsoft Loop
- Microsoft Whiteboard
- Microsoft Lists
- Microsoft Forms
- Microsoft Planner
- Microsoft Stream
- Viva Engage
- Power BI
- Excel Web
- Word Web
- PowerPoint Web
- Copilot for Microsoft 365
- Microsoft Purview
- Microsoft Defender XDR
- Defender for Cloud Apps
- Microsoft Entra ID
- Intune-managed endpoints
- Endpoint DLP-style actions

---

## Telemetry Expectations

Scenarios are designed to create telemetry such as:

```text
FileCreated
FileModified
FileAccessed
FileDownloaded
FileShared
AnonymousLinkCreated
SecureLinkUsed
FileCopiedToUSB
FileCopiedToNetworkShare
FilePrinted
SensitivityLabelApplied
SensitivityLabelChanged
SensitivityLabelRemoved
CopilotInteraction
AIAppInteraction
EmailSent
ExternalEmailSent
TeamsMessageSent
TeamsFileShared
PowerBIExport
ConditionalAccessTriggered
ImpossibleTravelAlert
MassDownloadActivity
InsiderRiskSequence
```

Codex should treat these as orchestration intent names rather than exact Purview schema values.

---

## Suggested Future Expansions

Codex can later extend the pack with:

- Browser automation scripts
- Persona calendars
- Daily schedules
- Randomized work-hour patterns
- Geographic login patterns
- Conditional Access simulation
- Defender incident timelines
- Simulated phishing exercises
- USB copy scenarios
- Remote device risk scoring
- Synthetic audit logs
- Power BI executive dashboards
- Synthetic KQL exports
- ADX ingestion pipelines
- Long-running insider risk narratives

---

## Important Safety Constraint

This project is for controlled demo and testing environments only.

Do not introduce:

- Real banking data
- Real customers
- Real employee records
- Real account numbers
- Real credentials
- Real payment information
- Real legal matters
- Real incidents
- Real personal data

All content must remain synthetic.
