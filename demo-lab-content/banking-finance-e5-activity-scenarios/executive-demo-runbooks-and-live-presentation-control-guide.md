# Executive Demo Runbooks and Live Presentation Control Guide

## Purpose

This document defines the live-delivery and presenter-orchestration layer for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It provides practical runbooks for executive demos, technical workshops, SOC tabletop exercises, AI governance briefings, and fallback/offline delivery.

All examples, users, files, scenarios, prompts, telemetry, identifiers, incidents, customers, HR records, legal matters, and financial records are fictional and synthetic.

---

## Core Live-Demo Thesis

> A successful demo is not a tour of tools. It is a controlled story where every click, filter, transition, and fallback supports the business message.

The presenter should control:

- audience context
- scenario sequence
- Power BI navigation
- replay bookmarks
- timing
- transitions
- technical depth
- fallback plans
- Q&A boundaries
- synthetic-data disclaimers

---

## Pre-Demo Checklist

Before any live session:

```text
confirm dataset is synthetic
confirm Power BI report opens
confirm ScenarioId slicers work
confirm Devon replay timeline loads
confirm AI and DLP pages show expected KPIs
confirm fallback screenshots or offline dataset are available
confirm synthetic-data disclaimer is visible
confirm demo mode is selected: executive, technical, SOC, or workshop
confirm no real tenant or real customer data is open
```

---

## Demo Modes

## Executive Mode

Recommended duration:

```text
15-25 minutes
```

Focus:

- business risk
- AI readiness
- sensitive data movement
- executive KPIs
- roadmap

Avoid:

- raw KQL
- portal hopping
- long configuration walkthroughs

---

## Technical Workshop Mode

Recommended duration:

```text
60-120 minutes
```

Focus:

- architecture
- telemetry
- Purview controls
- Power BI model
- KQL hunting
- replay logic

---

## SOC Tabletop Mode

Recommended duration:

```text
60-90 minutes
```

Focus:

- incident timeline
- evidence review
- escalation decisions
- case closure
- lessons learned

---

## AI Governance Briefing Mode

Recommended duration:

```text
30-45 minutes
```

Focus:

- Copilot readiness
- Shadow AI
- AI Approved Workspace
- prompt governance
- safe vs unsafe workflows

---

## Executive Demo Runbook

## Objective

Show leadership that AI, data security, DLP, endpoint controls, and investigation workflows must work together.

## Recommended Flow

```text
1. Open with synthetic-data disclaimer
2. Explain business context
3. Show Executive Risk Snapshot
4. Filter to Devon Multi-Day Risk Chain
5. Show AI and Copilot Risk
6. Show DLP Operations
7. Show Scenario Replay Timeline
8. Explain governance response
9. Close with maturity roadmap
```

---

## Executive Timing Guide

| Segment | Time |
|---|---:|
| Opening and disclaimer | 2 minutes |
| Business context | 3 minutes |
| Executive dashboard | 5 minutes |
| AI governance page | 4 minutes |
| DLP and endpoint sequence | 5 minutes |
| Replay timeline | 5 minutes |
| Roadmap and close | 3 minutes |

---

## Power BI Navigation Flow

Recommended navigation sequence:

```text
Executive Risk Snapshot
        ↓
AI and Copilot Risk
        ↓
DLP Operations
        ↓
Scenario Replay and Timeline
        ↓
Sensitive Data Exposure if time allows
```

Recommended slicers:

```text
ScenarioId = BF-SCEN-0030
PersonaName = Devon Reyes
Severity = High / Critical when focusing the story
```

---

## Presenter Cues

## Opening Cue

```text
Everything shown here is synthetic. The users, files, identifiers, incidents, and telemetry are fictional, but the patterns are realistic for Microsoft 365 governance discussions.
```

## Executive Risk Cue

```text
Most activity is normal collaboration. The important question is where normal collaboration starts to create sensitive-data exposure.
```

## AI Governance Cue

```text
AI does not create the original governance problem. It accelerates the discovery and reuse of whatever users can already access.
```

## DLP Cue

```text
A DLP warning is not just a block. It is a decision point where the organization can coach, guide, or enforce.
```

## Replay Cue

```text
Sequence creates meaning. One event may be explainable, but the chain tells us what requires review.
```

## Close Cue

```text
The goal is not to stop collaboration or AI. The goal is to make the safe path easier, measurable, and repeatable.
```

---

## Replay Bookmark Guide

Recommended bookmarks:

```text
Business Context
First Sensitive Access
External AI Shortcut
DLP Warning
DLP Override
Endpoint Movement
Security Review
Executive Takeaway
```

Presenter usage:

```text
Use bookmarks to avoid manually searching during a live demo.
Use filters only after the audience understands the story.
Use drillthrough only for technical or SOC audiences.
```

---

## AI Governance Talking Points

Use these points:

```text
Safe AI adoption starts before the prompt.
Copilot inherits access.
External AI requires separate governance.
AI outputs can become sensitive derivative content.
Approved AI workspaces reduce unsafe shortcuts.
Prompt monitoring without source governance is incomplete.
```

Avoid saying:

```text
AI is unsafe by default.
Copilot causes data leakage by itself.
Prompt monitoring solves AI governance.
```

---

## DLP Talking Points

Use these points:

```text
DLP should begin with visibility and tuning.
Policy tips can coach users before risky sharing.
Overrides are review points, not automatic misconduct.
DLP effectiveness depends on labels, classifiers, permissions, and business process.
Endpoint DLP is critical when cloud data moves locally.
```

---

## Purview Maturity Narrative

Recommended framing:

```text
Awareness
        ↓
Visibility
        ↓
Classification
        ↓
Guardrails
        ↓
Endpoint and AI Governance
        ↓
Operationalization
        ↓
Optimization
```

Presenter phrase:

```text
The platform helps customers see where they are in the journey and what the next practical step should be.
```

---

## Technical Workshop Runbook

## Objective

Show how the synthetic platform is built and how telemetry supports governance analytics.

## Recommended Flow

```text
1. Explain architecture diagram
2. Show dataset specification
3. Show synthetic telemetry schema
4. Show Power BI semantic model
5. Show ADX/KQL hunting examples
6. Show replay timeline
7. Discuss implementation backlog
```

## Technical Click Path

```text
Architecture document
        ↓
Sample dataset CSV / JSONL
        ↓
Power BI semantic model
        ↓
ADX KQL library
        ↓
Replay engine specification
        ↓
Codex build instructions
```

---

## SOC Tabletop Runbook

## Objective

Facilitate investigation decision-making without assuming user intent.

## Flow

```text
1. Present initial incident summary
2. Reveal first timeline segment
3. Ask analysts what they need next
4. Reveal DLP and AI events
5. Reveal endpoint or identity context
6. Discuss HR/Legal/Privacy boundaries
7. Decide closure outcome
8. Capture remediation opportunities
```

## Tabletop Questions

```text
What is the primary data domain?
Which file created the risk?
Was the AI app approved?
Was the DLP action warning, block, or override?
Was there endpoint movement?
What business context is still missing?
Is coaching sufficient or is escalation required?
```

---

## Fallback Plan

If Power BI fails:

```text
use exported screenshots
use CSV summary tables
use markdown storyboard
continue narrative without live filters
```

If ADX fails:

```text
use Power BI replay page
use pre-generated KQL output examples
avoid live query troubleshooting in executive sessions
```

If browser-agent demo fails:

```text
switch to instant replay mode
show preloaded telemetry
explain browser automation is optional and not required for the governance story
```

If internet or tenant access fails:

```text
use offline MVP dataset
use local Power BI file
use static storyboard
```

---

## Q&A Handling

## “Is this real customer data?”

```text
No. Everything is synthetic and fictional. The purpose is to demonstrate realistic patterns without exposing real users or customers.
```

## “Can this be implemented in production?”

```text
The concepts can guide production implementation, but licensing, feature availability, privacy, legal, HR, and tenant readiness must be validated first.
```

## “Does this prove malicious behavior?”

```text
No. The platform shows signals and sequences that require review. Intent must never be assumed from telemetry alone.
```

## “What should we do first?”

```text
Start with priority data domains, classification, permission hygiene, and safe AI collaboration paths before moving into enforcement.
```

---

## Recovery Steps if Demo Breaks

Recommended sequence:

```text
1. Stay in the story.
2. Do not troubleshoot live unless technical audience expects it.
3. Switch to fallback artifact.
4. Explain the concept, not the failure.
5. Resume from next storyboard point.
```

Presenter phrase:

```text
Rather than spending time on the live environment, let me use the prepared replay view so we can stay focused on the governance lesson.
```

---

## Workshop Facilitation Timing

Recommended 90-minute workshop:

| Segment | Time |
|---|---:|
| Context and objectives | 10 minutes |
| Executive story | 15 minutes |
| Power BI replay | 15 minutes |
| AI governance discussion | 15 minutes |
| DLP and endpoint controls | 15 minutes |
| SOC/tabletop exercise | 15 minutes |
| Roadmap and next steps | 5 minutes |

---

## What to Click Next

Executive demo:

```text
Executive Risk Snapshot → AI and Copilot Risk → Scenario Replay → Roadmap
```

Technical demo:

```text
Architecture → Dataset → Power BI model → ADX/KQL → Replay → Backlog
```

SOC demo:

```text
Incident Summary → Timeline → AI Events → DLP Events → Endpoint Events → Closure Outcome
```

AI governance demo:

```text
AI Dashboard → Safe vs Unsafe AI Path → AI Approved Workspace → Shadow AI Response → Maturity Roadmap
```

---

## Post-Demo Follow-Up

Recommended follow-up assets:

```text
executive summary
maturity roadmap
recommended next workshop
sample governance KPIs
AI readiness checklist
DLP rollout sequence
Power BI screenshot pack
```

Recommended follow-up message theme:

```text
The demo showed how synthetic data movement can help leadership understand real governance priorities without exposing real customer or employee data.
```

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate live demo scripts.
2. Generate Power BI click-path notes.
3. Create presenter cue cards.
4. Create fallback runbooks.
5. Generate Q&A sections.
6. Create workshop timing plans.
7. Generate storyboard-to-bookmark mappings.
8. Preserve synthetic-only disclaimers.
9. Avoid unsupported malicious-intent language.
10. Keep demos audience-appropriate.

---

## Safety Reminder

Live demos must use synthetic artifacts only.

Do not open, display, import, or discuss real customer data, real employee data, real HR records, real legal matters, real financial transactions, real credentials, real secrets, real production telemetry, or real incident evidence during these demos.
