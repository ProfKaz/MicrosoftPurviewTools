# Browser-Agent Behavior Simulation and Human Activity Engine

## Purpose

This document defines the human-activity simulation layer for browser-based agents operating inside the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services demo lab.

It explains how browser agents should simulate realistic daily behavior across Microsoft 365 workloads, including:

- typing cadence
- working hours
- interruptions
- meetings
- multitasking
- tab switching
- Teams behavior
- file-open cadence
- copy/paste behavior
- AI usage timing
- realistic mistakes
- escalation behavior
- urgency simulation
- notification reactions
- activity bursts and quiet periods

All identities, files, messages, prompts, telemetry, and business records must remain fictional and synthetic.

---

## Core Simulation Thesis

> Realistic user activity is not constant activity. It is a pattern of bursts, pauses, interruptions, context switching, corrections, shortcuts, and occasional mistakes.

The browser-agent engine should avoid robotic behavior such as:

- perfectly spaced events
- constant activity every minute
- every file action followed immediately by a risky event
- users always making the same decision
- all departments communicating with the same tone
- every DLP warning being overridden
- every AI prompt being unsafe

---

## Agent Design Principles

1. Simulate work rhythms, not just clicks.
2. Respect persona schedules and department habits.
3. Include normal business noise.
4. Preserve quiet periods and idle time.
5. Create mistakes only when scenario logic supports them.
6. Prefer plausible shortcuts over cartoonish malicious behavior.
7. Keep risky behavior ambiguous unless explicitly scripted.
8. Log all agent actions in synthetic telemetry format.
9. Support deterministic replay through seeds.
10. Never use real user accounts, real data, or real credentials.

---

## Human Activity States

Recommended agent states:

```text
Idle
Reading
Writing
Editing
Reviewing
Searching
Meeting
Chatting
Emailing
Analyzing
UsingAI
Sharing
RespondingToWarning
Escalating
CorrectingMistake
EndingWorkday
```

State transitions should be probabilistic but constrained by scenario goals.

Example:

```text
Reading
    ↓
Editing
    ↓
UsingAI
    ↓
Sharing
    ↓
RespondingToWarning
    ↓
CorrectingMistake or Overriding
```

---

## Persona Activity Profiles

## Devon Reyes - Junior Operations Analyst

Behavior style:

- task-oriented
- deadline-sensitive
- asks clarifying questions
- makes occasional wrong-file or wrong-channel mistakes
- may use external AI when rushed

Common actions:

- opens KYC packets
- downloads working copies
- posts Teams questions
- forwards customer operations notes
- reacts to DLP warnings with uncertainty

Risk triggers:

- vendor call starting soon
- customer escalation
- unclear sanitized file path
- role-change or workload pressure

---

## Ana Rodriguez - Head of IT / Security

Behavior style:

- structured
- evidence-first
- avoids intent assumptions
- redirects risky workflows to approved paths

Common actions:

- reviews DLP events
- asks for context in Teams
- checks scenario timelines
- creates investigation notes
- escalates to HR/Legal when required

Risk triggers:

- DLP override
- external AI use
- endpoint movement
- HR context plus data movement

---

## Marcus Olsson - Cybersecurity Manager

Behavior style:

- operational
- SOC-oriented
- uses KQL and dashboards
- documents findings neutrally

Common actions:

- checks ADX queries
- reviews DLP policy matches
- follows up with Devon or Ana
- creates remediation tasks

---

## Priya Sharma - Data Scientist

Behavior style:

- analytical
- AI-positive
- comfortable with exports and summaries
- may underestimate re-identification risk

Common actions:

- opens Power BI reports
- exports analytical summaries
- asks Copilot for summaries
- reviews anonymized datasets

---

## Alexander Meyer - CEO

Behavior style:

- concise
- executive-summary driven
- asks for board-ready outputs
- does not want raw detail unless needed

Common actions:

- reviews executive deck
- asks Copilot for summary
- sends short direction messages
- requests risk themes

---

## Working Hours Model

Default business hours:

```text
08:00-18:00 local time
```

Recommended local timezone:

```text
America/Bogota
```

Activity intensity:

| Time Window | Activity Pattern |
|---|---|
| 08:00-09:00 | login, email review, Teams catch-up |
| 09:00-11:30 | focused work and meetings |
| 11:30-13:00 | lunch / reduced activity |
| 13:00-15:30 | collaboration and document activity |
| 15:30-17:30 | deadlines, reviews, sharing, follow-ups |
| 17:30-18:30 | wrap-up and occasional risky shortcuts |
| after hours | rare, higher-context significance |

---

## Activity Burst Model

Agents should work in bursts.

Recommended burst patterns:

| Burst Type | Duration | Example |
|---|---:|---|
| short chat burst | 2-6 minutes | Teams clarification |
| email triage burst | 5-15 minutes | reading and replying |
| document editing burst | 15-45 minutes | Office Web editing |
| analysis burst | 20-60 minutes | Excel / Power BI work |
| investigation burst | 30-90 minutes | SOC timeline review |
| urgent sharing burst | 3-10 minutes | deadline-driven send/share |

Between bursts, insert quiet periods.

---

## Typing Cadence

Use realistic typing delay based on message type.

| Content Type | Suggested Cadence |
|---|---|
| Teams short reply | 20-45 words/min equivalent |
| Teams longer explanation | 25-50 words/min equivalent |
| email body | 25-60 words/min equivalent |
| document paragraph | 30-70 words/min equivalent |
| AI prompt | 20-45 words/min equivalent |
| executive message | shorter, faster |
| legal or HR message | slower, more careful |

Agents may pause while typing, revise, or delete partial text.

---

## Reading and Review Delays

Recommended delays:

| Activity | Delay |
|---|---:|
| open file and skim | 20-90 seconds |
| review short email | 10-45 seconds |
| review long email | 45-180 seconds |
| review DLP warning | 20-90 seconds |
| review AI output | 30-180 seconds |
| review legal/HR content | 2-8 minutes |
| review dashboard page | 1-5 minutes |

---

## Tab Switching Behavior

Agents should switch between tabs based on task flow.

Common tab clusters:

```text
Outlook + Teams + SharePoint
SharePoint + Office Web + Copilot
Teams + SharePoint + Power BI
Purview + ADX + Teams
OneDrive + Office Web + external AI app
```

Tab switching signals:

- user copies file name from SharePoint into Teams
- user opens Teams after DLP warning
- user opens external AI after downloading workbook
- analyst switches from Power BI to ADX query

---

## Teams Behavior Model

Teams messages should include:

- clarifying questions
- short confirmations
- urgency cues
- mistakes and corrections
- escalation requests
- reminders to use approved workspace

Example normal behavior:

```text
I updated the sanitized summary and placed it in the Customer-Safe Responses folder.
```

Example risky behavior:

```text
I dropped the KYC packet here so everyone can review before the call.
```

Example correction:

```text
Please remove that link from General and repost only the sanitized version in the restricted channel.
```

---

## Email Behavior Model

Email actions should vary by department.

Common email patterns:

- customer escalation follow-up
- vendor evidence package
- finance forecast review
- legal caveat request
- HR role-change note
- security coaching message
- executive summary request

Risk patterns:

- wrong attachment
- external recipient with internal file
- vague DLP override justification
- forwarding internal notes externally
- sending AI-generated output without review

---

## File Interaction Cadence

Typical file sequence:

```text
FileAccessed
        ↓
FileModified or FileDownloaded
        ↓
SensitivityLabelApplied or DLPPolicyMatch
        ↓
TeamsMessageSent or EmailSent
        ↓
FileShared or ExternalEmailSent
```

Do not always follow this exact pattern. Add realistic variations.

---

## AI Usage Timing

Safe AI timing:

```text
User opens approved source
        ↓
User reads content
        ↓
User asks Copilot for summary
        ↓
User reviews output
        ↓
User edits output before sharing
```

Unsafe AI timing:

```text
User downloads raw file
        ↓
Deadline pressure appears
        ↓
User opens external AI app
        ↓
User pastes sensitive rows
        ↓
User copies generated summary
        ↓
DLP or AI governance signal appears
```

---

## Mistake Simulation

Mistakes should be plausible and controlled.

Recommended mistake types:

| Mistake | Example |
|---|---|
| wrong channel | raw KYC link posted in General |
| wrong attachment | internal package sent instead of sanitized package |
| label downgrade | user downgrades after assuming file is clean |
| external AI shortcut | raw rows pasted to unmanaged app |
| endpoint shortcut | file printed before meeting |
| OneDrive shortcut | restricted file copied to personal working folder |
| guest mistake | vendor guest added to internal team |

Mistakes should have follow-up behavior:

- user notices and corrects
- security notices and coaches
- DLP blocks or warns
- manager asks for sanitized version

---

## DLP Warning Behavior

When a DLP warning appears, agent response should vary.

Possible responses:

```text
Cancel
Edit content
Create sanitized version
Ask Security
Override with justification
Try a different sharing path
Delay action
```

Suggested probability by persona:

| Persona Type | Cancel/Edit | Ask Security | Override | Try Workaround |
|---|---:|---:|---:|---:|
| Security | 70% | 20% | 5% | 5% |
| Legal/HR | 60% | 25% | 10% | 5% |
| Operations under pressure | 25% | 25% | 35% | 15% |
| Executive assistant / PMO | 35% | 25% | 25% | 15% |
| Data Science | 35% | 20% | 25% | 20% |

---

## Urgency Simulation

Urgency should be triggered by:

- meeting starts soon
- customer escalation
- vendor request
- finance close deadline
- regulatory response
- executive request

Urgency markers:

```text
shorter messages
reduced review delay
higher chance of wrong file
higher chance of DLP override
higher chance of external AI shortcut
higher chance of OneDrive working copy
```

Example:

```text
The vendor review starts in 12 minutes. Devon selects the first similarly named package file and shares it before checking whether it is sanitized.
```

---

## Notification Reaction Model

Agents should react to:

- Teams mentions
- Outlook replies
- DLP warnings
- file access notifications
- manager requests
- security coaching
- meeting reminders

Example reaction chain:

```text
Teams mention from manager
        ↓
Devon opens SharePoint file
        ↓
Devon downloads working copy
        ↓
Devon sends external email
        ↓
DLP warning appears
        ↓
Devon asks Ana whether he can proceed
```

---

## Meeting Simulation

Meeting blocks should reduce activity, but may generate pre/post activity.

Before meeting:

- download file
- print file
- generate summary
- send agenda
- ask Copilot for talking points

During meeting:

- reduced activity
- occasional Teams message
- note-taking

After meeting:

- send follow-up
- update tracker
- share summary
- create action items

---

## Quiet Periods

Quiet periods are required for realism.

Insert quiet periods after:

- long document edits
- meetings
- major email sends
- DLP warnings
- AI output reviews
- security escalations
- lunch
- end of workday

Quiet periods can be compressed in demo mode but should not be eliminated.

---

## Human Noise Generation

Human noise includes low-risk, realistic actions:

- opening calendar
- reading email
- short Teams reactions
- updating a non-sensitive tracker
- viewing a Power BI dashboard
- editing a draft title
- applying an Internal label
- asking Copilot for a safe summary

Noise should not dominate the story in executive demo mode.

---

## Agent Telemetry Requirements

Every meaningful agent action should emit or support a synthetic telemetry event with:

```text
EventId
TimeGenerated
ScenarioId
CorrelationId
UserPrincipalName
PersonaName
Workload
Operation
RiskScore
IsRiskEvent
IsSynthetic
BusinessContext
```

Browser actions and telemetry should be linked where possible through:

```text
CorrelationId
ReplayId
TaskPlanId
```

---

## Failure and Recovery Behavior

Agents should handle errors realistically.

Examples:

| Failure | Recovery |
|---|---|
| file not found | search recent files or ask Teams |
| DLP block | create sanitized version or ask Security |
| external sharing blocked | use Vendor Collaboration site |
| Copilot cannot access file | check permissions or use approved source |
| Teams message sent to wrong channel | delete/correct and repost |
| browser session expired | re-authenticate or pause replay |

---

## Demo Modes

## Executive Demo Mode

- fewer browser actions
- cleaner story
- low noise
- pre-seeded events allowed
- focus on replay and dashboard

## Technical Workshop Mode

- more visible browser actions
- show file creation and sharing
- show simulated DLP response
- allow some troubleshooting

## SOC Tabletop Mode

- staged evidence release
- ADX/KQL pivots
- incident timeline
- analyst decisions

## Chaos Mode

- high concurrency
- more mistakes
- more retries
- not recommended for first-time executive demos

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate browser-agent behavior logic.
2. Add realistic timing and pauses.
3. Create persona-specific action patterns.
4. Simulate Teams and email behavior.
5. Generate plausible mistakes and corrections.
6. Model DLP warning decisions.
7. Simulate AI usage timing.
8. Generate activity bursts and quiet periods.
9. Link browser actions to telemetry events.
10. Preserve synthetic-only boundaries.

---

## Safety Reminder

Browser agents must operate only in synthetic demo tenants with fictional accounts and fictional content.

Do not use this engine to automate actions against real employees, real customers, real HR data, real legal records, real financial data, real credentials, real production telemetry, or real incident evidence.
