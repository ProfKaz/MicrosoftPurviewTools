# Demo Presenter Scripts - Banking / Finance Microsoft 365 E5 Simulation Pack

## Purpose

This document provides presenter-ready scripts for demonstrating the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation framework.

It includes:

- 5-minute executive script
- 15-minute security script
- 30-minute workshop script
- transition phrases
- audience questions
- objection handling
- Devon storyline
- AI governance storyline
- DLP storyline
- endpoint storyline
- final calls to action

All examples, people, files, IDs, cases, and telemetry are fictional and synthetic.

---

## Core Message

> One control is not enough. In a realistic Microsoft 365 environment, risk emerges from the interaction between data, identity, collaboration, AI, endpoint movement, and human behavior.

Supporting themes:

- AI inherits the existing data-access reality.
- DLP is not only blocking; it is coaching, visibility, and control.
- Insider-risk-style investigation requires context, not assumptions.
- Endpoint activity gives cloud data risk a physical dimension.
- Governance must connect labels, permissions, data discovery, DLP, AI, and response.

---

## Opening Narrative

Suggested opening:

> In this demo, we are not trying to show a perfect tenant or an obviously malicious user. We are simulating a realistic banking environment where employees are under pressure, data is sensitive, collaboration is constant, and AI is becoming part of daily work.
>
> The goal is to show how Microsoft 365 E5, Microsoft Purview, Defender, and Copilot governance can help us understand the full story: what happened, why it matters, and what the organization should do next.

---

# 5-Minute Executive Script

## Audience

C-level executives, board members, risk committees, business leaders.

## Objective

Explain business risk and governance value without going too deep into technical controls.

## Flow

```text
1. Executive Risk Snapshot
2. Sensitive Data Exposure
3. AI and Copilot Risk
4. Scenario Replay
5. Call to Action
```

---

## Minute 0-1 - Set the Context

Presenter script:

> This is a synthetic banking scenario. All users, files, accounts, cases, and customers are fictional.
>
> What we are looking at is not a tool demo in isolation. It is a business-risk story. A user is working with sensitive banking data, trying to move fast, and several controls across Microsoft 365 begin to show us where the risk appears.

Key message:

> Risk is not created by one single event. It is created by a sequence.

---

## Minute 1-2 - Executive Risk Snapshot

Presenter script:

> At the top, we see overall telemetry: total events, risk events, high or critical events, external sharing, and AI-related activity.
>
> The important point is not just the number. It is the mix. We see file activity, DLP events, AI interactions, endpoint movement, and external sharing all contributing to the same risk picture.

Transition:

> Now let us move from the summary to the data itself. What kind of information is creating the exposure?

---

## Minute 2-3 - Sensitive Data Exposure

Presenter script:

> Here we see sensitive files by label, workload, and department. In a banking environment, that includes KYC packets, AML reviews, treasury reconciliation, HR planning, and legal privileged material.
>
> This is why classification matters. If the organization does not know where sensitive data is, it cannot govern it, protect it, or prepare it safely for AI.

Key line:

> You cannot protect what you cannot classify.

---

## Minute 3-4 - AI and Copilot Risk

Presenter script:

> AI changes the speed of discovery and reuse. The model does not invent the access problem. It surfaces what users can already reach.
>
> In this synthetic example, we contrast safe Copilot usage against unmanaged external AI usage. The safe path uses governed source content. The unsafe path involves raw sensitive rows being pasted into an external AI app.

Key line:

> AI inherits the permissions and data hygiene of the organization.

---

## Minute 4-5 - Scenario Replay and Close

Presenter script:

> In the replay, we can follow the sequence: sensitive file access, download, AI usage, DLP signal, endpoint movement, and investigation response.
>
> The value is not only detecting one event. The value is connecting the events into a story that business, security, HR, and legal stakeholders can understand.

Call to action:

> The next step is to identify which sensitive data domains matter most, validate permissions, apply labels, configure DLP, and define approved AI workflows before adoption scales further.

---

# 15-Minute Security Script

## Audience

Security leadership, SOC analysts, compliance operations, Microsoft 365 administrators.

## Objective

Show cross-workload telemetry, Purview controls, and investigation workflow.

## Flow

```text
1. Executive Risk Snapshot
2. DLP Operations
3. AI and Copilot Risk
4. Endpoint DLP and Device Movement
5. Insider Risk Overview
6. Scenario Replay
7. Security Operations Response
```

---

## Segment 1 - Risk Overview

Presenter script:

> We begin with the risk snapshot. This gives us the aggregate posture: how many risky events occurred, which departments were involved, which workloads generated signals, and which scenarios are active.
>
> This page is useful for leadership, but security teams need to pivot from summary into evidence.

Transition:

> Let us start with DLP, because it is often the first visible control when sensitive data moves.

---

## Segment 2 - DLP Operations

Presenter script:

> Here we see DLP matches, warnings, blocks, and overrides. The override view is especially important because it tells us where users believe they had a business reason to continue.
>
> A DLP override does not automatically mean malicious behavior. But when the file is highly confidential, the recipient is external, and the justification is vague, it deserves review.

Demo pivot:

> Select Devon Reyes and review the DLP override sequence.

Key message:

> DLP is a visibility and coaching mechanism, not only a blocking mechanism.

---

## Segment 3 - AI and Copilot Risk

Presenter script:

> Now we look at AI usage. We separate Copilot interactions from unmanaged external AI interactions.
>
> Copilot risk is often about source exposure: what files were referenced, what labels they had, and whether permissions were appropriate.
>
> External AI risk is different. It may involve raw sensitive data leaving governed Microsoft 365 boundaries.

Demo pivot:

> Show unsafe prompt sample containing synthetic AML, SAR, customer, and account-like values.

Key message:

> AI governance is data governance under acceleration.

---

## Segment 4 - Endpoint DLP

Presenter script:

> Endpoint activity changes the nature of the risk. A file is no longer only in SharePoint or Teams. It may be printed, copied to a network share, or moved to removable media.
>
> In this scenario, endpoint signals make the investigation stronger because they show movement beyond normal collaboration.

Demo pivot:

> Filter to FilePrinted and FileCopiedToNetworkShare events.

Key message:

> Cloud controls and endpoint controls must work together.

---

## Segment 5 - Insider Risk Overview

Presenter script:

> Here we correlate multiple signals into a sequence. This is where we must be careful.
>
> We are not saying the user is malicious. We are saying the sequence requires review: downloads, AI usage, DLP override, endpoint movement, and possibly HR context.

Devon framing:

> Devon is intentionally modeled as ambiguous. Sometimes he is rushed, sometimes careless, sometimes policy-confused, and sometimes risky enough to trigger structured review.

Key message:

> The goal is not to assume intent. The goal is to validate context and reduce exposure.

---

## Segment 6 - Scenario Replay

Presenter script:

> The replay page lets us walk the sequence chronologically. This is the bridge between security telemetry and business understanding.
>
> We can show what happened first, what controls responded, where the user made a decision, and how the organization reacted.

Recommended sequence to show:

```text
File accessed
File downloaded
Copilot or AI interaction
DLP match
DLP override
Endpoint movement
Security review
HR/Legal context
Coaching or remediation
```

---

## Segment 7 - Security Operations Response

Presenter script:

> From here, the SOC playbook defines the next steps: review the file, validate the recipient, inspect the prompt, check endpoint movement, involve HR or Legal only when appropriate, and close the case with a documented outcome.
>
> The important operational maturity point is that the technology provides the evidence, but the process provides the judgment.

Call to action:

> Build the control plane around your highest-risk data domains first: labels, DLP, endpoint restrictions, AI governance, access reviews, and response playbooks.

---

# 30-Minute Workshop Script

## Audience

Security architects, Microsoft 365 administrators, compliance teams, data governance teams, SOC analysts, business data owners.

## Objective

Provide a complete scenario walkthrough from tenant topology through content, telemetry, risk, investigation, and remediation.

## Flow

```text
1. Tenant architecture
2. Synthetic data patterns
3. Scenario selection
4. Content generation
5. Telemetry generation
6. DLP and label controls
7. AI and Copilot governance
8. Endpoint DLP
9. Insider Risk timeline
10. SOC playbook
11. Power BI executive reporting
12. Lessons learned
```

---

## Segment 1 - Tenant Architecture

Presenter script:

> The lab uses a realistic Microsoft 365 structure: Executive Leadership, HR Restricted, Legal Privileged, Customer Operations, Finance Close, IT Security Operations, Vendor Collaboration, and AI Approved Workspace.
>
> This matters because data protection is not only about policies. It is also about where content lives, who owns it, and which collaboration boundaries exist.

Key message:

> Information architecture is a security control.

---

## Segment 2 - Synthetic Data Patterns

Presenter script:

> The content pack uses fictional identifiers that look realistic enough for DLP demonstrations but are not real: CUST-BNK, ACCT-FIC, AML-CASE, SAR-DRAFT, EMP, LEGAL-FIC, and others.
>
> This lets us demonstrate classification, DLP, KQL, and AI governance safely.

Key message:

> Good synthetic data allows realistic security testing without production exposure.

---

## Segment 3 - Scenario Selection

Presenter script:

> Each scenario combines business context with technical signals. For example, a loan committee package, an AML review, a treasury reconciliation, or a role-change risk chain.
>
> The strongest demo is not the most dramatic one. It is the one that feels operationally plausible.

Recommended scenario:

```text
BF-SCEN-0030 - Devon Multi-Day Risk Chain
```

---

## Segment 4 - Content and Telemetry Generation

Presenter script:

> The browser-agent task plans create the visible activity: documents, emails, Teams messages, AI prompts, downloads, and sharing attempts.
>
> The telemetry schema then normalizes those actions into a common event model so ADX, KQL, and Power BI can reason over the same data.

Key message:

> The demo is not just content. It is content plus behavior plus telemetry.

---

## Segment 5 - Controls and Signals

Presenter script:

> Once the content moves, controls begin to respond: labels, DLP, endpoint DLP, Defender, identity, and AI governance signals.
>
> The correlation engine converts individual signals into a risk sequence.

Transition:

> Now let us look at how this appears from an analyst’s perspective.

---

## Segment 6 - Investigation Timeline

Presenter script:

> The timeline shows the sequence: Devon accesses KYC files, downloads sensitive data, uses external AI, overrides a DLP warning, prints a treasury workbook, and copies a file to a network share.
>
> Individually, some of these actions may have explanations. Together, they require structured review.

Key line:

> Sequence creates meaning.

---

## Segment 7 - SOC Playbook

Presenter script:

> The SOC playbook guides the analyst through triage: identify the trigger, validate data sensitivity, correlate activity, confirm business context, decide severity, and document the outcome.
>
> If HR context exists, HR and Legal are included, but the language remains neutral.

Key message:

> Evidence first. Assumptions later, if ever.

---

## Segment 8 - Executive Reporting

Presenter script:

> Finally, Power BI turns the investigation into a governance story: risk trends, external sharing, AI exposure, endpoint movement, and remediation outcomes.
>
> This lets security move from tool configuration to business conversation.

Call to action:

> The goal is to build a repeatable operating model: discover data, classify it, govern access, control sharing, monitor AI usage, respond to risk, and continuously improve.

---

# Objection Handling

## Objection: “This looks like monitoring employees.”

Suggested response:

> The purpose is not surveillance. The purpose is protecting regulated data and validating risky sequences with context. The process should include privacy, HR, Legal, and governance boundaries, and it should avoid unsupported conclusions about intent.

---

## Objection: “Can AI really expose data if the user already had access?”

Suggested response:

> Yes, the key issue is acceleration and discoverability. AI can make over-permissioned content easier to find, summarize, and reuse. That is why permissions, labels, and data governance matter before AI adoption scales.

---

## Objection: “DLP blocks productivity.”

Suggested response:

> Poorly tuned DLP can block productivity. Well-designed DLP provides warnings, coaching, justified overrides, and safer alternatives. The objective is not to block the business; it is to guide sensitive data into approved workflows.

---

## Objection: “Why model Devon as risky?”

Suggested response:

> Devon is not modeled as a villain. He represents realistic ambiguity: workload pressure, unclear policy, similar file names, AI shortcuts, and occasional poor decisions. That ambiguity is what makes the investigation realistic.

---

## Objection: “Can we just solve this with labels?”

Suggested response:

> Labels are foundational, but not sufficient. They need to work with permissions, DLP, endpoint controls, identity, external sharing governance, AI governance, and response workflows.

---

# Audience Questions

Use these during workshops:

1. Which data domain would be most sensitive in your organization?
2. Where do users currently create working copies?
3. Which external collaboration paths are approved today?
4. Are sanitized and raw files clearly separated?
5. Do users know when to use Copilot versus external AI tools?
6. Are DLP overrides reviewed or simply logged?
7. Are endpoint copy and print actions visible to security?
8. Do HR and Legal have a defined escalation process for user-risk cases?
9. Which Power BI view would be most useful for leadership?
10. Which scenario should be simulated next?

---

# Closing Script

Suggested closing:

> This demo is synthetic, but the pattern is real. Organizations do not lose control of sensitive data through one single failure. They lose control through small, reasonable-looking decisions that compound over time.
>
> The opportunity with Microsoft 365 E5, Microsoft Purview, Defender, and Copilot governance is to connect those signals, understand the sequence, guide users to safer workflows, and build an operating model where security supports the business instead of only reacting to it.

Final call to action:

> Start with your highest-risk data domains. Classify them, validate permissions, define approved collaboration paths, configure DLP and endpoint controls, and establish AI governance before sensitive content becomes easier to discover and reuse at scale.

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate speaker notes.
2. Build presentation outlines.
3. Create demo runbooks.
4. Produce customer-facing narrative scripts.
5. Create workshop facilitator guides.
6. Generate objection-handling cards.
7. Align Power BI pages with presenter flow.
8. Preserve synthetic-only disclaimers.
9. Avoid implying malicious intent without scenario support.
10. Keep the story business-first and evidence-driven.

---

## Safety Reminder

This presenter script is for synthetic demo and training environments only.

Do not use it to present real employee monitoring, real insider-risk cases, real HR actions, real legal matters, real customer data, or real incident evidence unless appropriate governance, privacy, HR, compliance, and legal approvals are in place.
