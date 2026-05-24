# Codex Handoff - Synthetic Microsoft 365 / Purview Demo Lab Content Pack

## Purpose

This folder contains a synthetic enterprise content pack designed for a Microsoft 365 / Microsoft Purview demo lab. The content is intended to be consumed by browser-based agents or automation scripts that simulate realistic employee activity across Microsoft 365 services such as Outlook, Teams, SharePoint, OneDrive, Office Web, and AI/Copilot interactions.

The pack is fully fictional. All people, companies, customers, contracts, employee IDs, invoices, incidents, bank-like values, support cases, HR records, project codes, and PII-like patterns are fake and must remain fake.

The main goal is to generate realistic telemetry for demos involving:

- Microsoft Purview Activity Explorer
- Sensitivity labels
- DLP policies
- External sharing controls
- Endpoint DLP-style actions
- Insider risk-style narratives
- AI/Copilot interaction review
- Shadow AI / external AI app scenarios
- Oversharing and permission-risk demonstrations

---

## Original Prompt Scope

The initial request was to generate a large structured JSON pack with these top-level keys:

```json
{
  "emailSubjects": [],
  "emailTemplates": [],
  "chatThreads": [],
  "documents": [],
  "aiPrompts": [],
  "externalSharingScenarios": [],
  "labelingScenarios": []
}
```

The requested content included:

1. At least 150 unique email subjects grouped by department and scenario.
2. 60 realistic email templates.
3. 40 multi-message Teams/chat conversation threads.
4. 80 document briefs with document metadata, sample rows where applicable, sensitivity labels, and Activity Explorer scenarios.
5. 100 Copilot / AI prompts.
6. 30 external sharing scenarios.
7. 40 labeling scenarios.
8. Output as structured JSON.

---

## Implementation Approach and Changes Made

The original prompt requested one large JSON object containing every content category. During implementation, the content was split into multiple JSON files instead of one monolithic JSON file.

This change was made for practical engineering reasons:

- The complete content pack is large and easier to maintain as modular files.
- Codex and future automation scripts can load only the needed category instead of parsing one very large JSON file.
- Each file can evolve independently.
- Separate files reduce merge conflicts and make validation easier.
- The structure still preserves the original top-level categories through one file per requested key.

No requested content category was removed. The generated files map directly to the original requested top-level keys:

| Original top-level key | Implemented file |
|---|---|
| `emailSubjects` | `email-subjects.json` |
| `emailTemplates` | `email-templates.json` |
| `chatThreads` | `chat-threads.json` |
| `documents` | `documents.json` |
| `aiPrompts` | `ai-prompts.json` |
| `externalSharingScenarios` | `external-sharing-scenarios.json` |
| `labelingScenarios` | `labeling-scenarios.json` |

A future optional improvement is to generate a `content-pack.json` file that imports or aggregates all seven files into the exact original combined JSON shape.

---

## Repository Location

Repository:

```text
ProfKaz/MicrosoftPurviewTools
```

Folder:

```text
demo-lab-content/synthetic-m365-purview-pack/
```

Files currently generated:

```text
README.md
CODEX_HANDOFF.md
email-subjects.json
email-templates.json
chat-threads.json
documents.json
ai-prompts.json
external-sharing-scenarios.json
labeling-scenarios.json
```

---

## File-by-File Description

### 1. `README.md`

General overview of the content pack.

Includes:

- Purpose of the folder.
- Fictional data notice.
- Recommended file layout.
- Main JSON schema requested in the original prompt.
- Usage notes for controlled lab environments.

Use this as the human-readable entry point for the folder.

---

### 2. `email-subjects.json`

Contains the synthetic email subject library.

Generated content:

- 192 unique email subjects.
- Grouped by department and business scenario.
- Covers all requested departments plus cross-functional scenarios.
- Includes normal business operations, sensitive data handling, accidental oversharing risk, customer escalation, contract review, AI/Copilot-assisted analysis, external recipient review, HR compensation planning, security incident follow-up, and finance forecast/invoice review.

Suggested automation use:

- Randomly select subjects for synthetic Outlook email creation.
- Pair subjects with email bodies from `email-templates.json`.
- Use scenario metadata to drive risk-aware workflows.
- Use department grouping to generate realistic persona-specific activity.

Primary JSON key:

```json
"emailSubjects"
```

---

### 3. `email-templates.json`

Contains reusable synthetic email templates.

Generated content:

- 60 realistic enterprise email templates.
- Each template includes:
  - `senderRole`
  - `recipientRole`
  - `subject`
  - `sensitivityLevel`
  - `businessScenario`
  - `body`
  - `optionalAttachmentName`
  - `optionalFollowUpPrompt`
- Includes varied tone and writing style by department.
- Includes fictional sensitive patterns such as employee IDs, customer IDs, invoice IDs, support case IDs, bank-like values, legal matter IDs, and security incident IDs.

Suggested automation use:

- Create Outlook messages between synthetic personas.
- Attach files referenced in `documents.json`.
- Trigger DLP, external recipient warning, and label-based mail flow scenarios.
- Use `optionalFollowUpPrompt` to chain into Copilot or AI interaction simulations.

Primary JSON key:

```json
"emailTemplates"
```

---

### 4. `chat-threads.json`

Contains Teams/chat-style multi-message conversation threads.

Generated content:

- 40 chat threads.
- Each thread includes:
  - `threadTitle`
  - `participants`
  - `department`
  - `riskTheme`
  - `messages`
- Threads include realistic clarifications, urgency, mistakes, corrections, and questions about whether content can be shared externally.
- Scenarios include wrong file shared, external vendor requests, Copilot surfacing sensitive data, endpoint DLP events, HR compensation exposure, and legal redline confusion.

Suggested automation use:

- Create Microsoft Teams channel messages or chats.
- Simulate business discussions leading to file creation, sharing, labeling, or remediation.
- Generate contextual activity before or after file events.
- Use `riskTheme` to align conversations with DLP or Insider Risk storylines.

Primary JSON key:

```json
"chatThreads"
```

Implementation note:

- The original prompt requested 4 to 8 messages per thread. The current file uses 4 messages per thread consistently. This satisfies the lower bound and keeps the dataset compact.

---

### 5. `documents.json`

Contains the document generation library.

Generated content:

- 80 document briefs.
- File types include:
  - `docx`
  - `pptx`
  - `xlsx`
  - `pdf`
  - `txt`
  - `csv`
- Each document includes:
  - `fileName`
  - `fileType`
  - `department`
  - `sensitivityLevel`
  - `title`
  - `shortSummary`
  - `sections`
  - `sampleRows`
  - `suggestedSensitivityLabel`
  - `activityExplorerScenarios`
- Spreadsheet/CSV-style files include 5 sample rows where applicable.
- Non-tabular documents include section outlines.
- Includes Purview-oriented signals such as `FileCreated`, `FileModified`, `FileDownloaded`, `FileShared`, `FilePrinted`, `FileCopiedToNetworkShare`, `LabelApplied`, `LabelChanged`, `LabelRemoved`, and `LabelRecommended`.

Suggested automation use:

- Generate Office files in SharePoint or OneDrive based on the briefs.
- Use `sections` as document headings.
- Use `sampleRows` to create xlsx/csv content.
- Apply `suggestedSensitivityLabel` during file creation or after modification.
- Use `activityExplorerScenarios` to orchestrate browser-based actions.

Primary JSON key:

```json
"documents"
```

Implementation note:

- The original prompt requested 5 to 15 sample rows when applicable. The current implementation uses 5 sample rows for applicable structured files, which satisfies the lower bound.

---

### 6. `ai-prompts.json`

Contains prompts that employees might submit to Copilot or another AI assistant.

Generated content:

- 100 prompts.
- Each prompt includes:
  - `prompt`
  - `personaRole`
  - `sourceContext`
  - `expectedRisk`
  - `safeBusinessPurpose`
  - `interactionType`
- `interactionType` is either:
  - `CopilotInteraction`
  - `AIAppInteraction`
- Prompts include internal Copilot usage and risky external AI / Shadow AI usage.
- Includes examples involving HR compensation, legal redlines, customer predictions, invoice data, endpoint timelines, incident evidence, internal discount guidance, and privileged legal content.

Suggested automation use:

- Simulate Copilot prompts inside Microsoft 365 context.
- Simulate external AI app prompts for Shadow AI / risky copy-paste scenarios.
- Create telemetry narratives around AI usage and sensitive data exposure.
- Use `expectedRisk` and `safeBusinessPurpose` for classification, alerting, or training logic.

Primary JSON key:

```json
"aiPrompts"
```

Implementation note:

- The original prompt said to include whether each prompt should be treated as CopilotInteraction or AIAppInteraction. This is implemented as `interactionType`.

---

### 7. `external-sharing-scenarios.json`

Contains outbound sharing scenarios involving external recipients.

Generated content:

- 30 scenarios.
- Each scenario includes:
  - `senderRole`
  - `externalRecipientType`
  - `subject`
  - `body`
  - `attachmentName`
  - `riskReason`
  - `recommendedPurviewControl`
- Scenarios include vendors, customers, external counsel, managed security providers, external auditors, recruiters, training vendors, compliance advisors, and implementation partners.
- Includes sanitized vs pre-sanitized file variants.
- Includes wrong-recipient and risky outbound content scenarios.

Suggested automation use:

- Generate outbound Outlook messages to external domains.
- Attach files from `documents.json`.
- Trigger external recipient warnings, DLP blocks, DLP overrides, or user justification prompts.
- Validate domain allowlist and sharing restrictions.

Primary JSON key:

```json
"externalSharingScenarios"
```

---

### 8. `labeling-scenarios.json`

Contains sensitivity labeling events for Office Web and SharePoint simulation.

Generated content:

- 40 labeling scenarios.
- Each scenario includes:
  - `fileName`
  - `initialLabel`
  - `finalLabel`
  - `labelEventType`
  - `justification`
  - `userRole`
  - `expectedActivityExplorerSignal`
- Label event types include:
  - `LabelApplied`
  - `LabelChanged`
  - `LabelRemoved`
  - `LabelRecommended`
- Labels include:
  - `None`
  - `Public`
  - `Internal`
  - `Confidential`
  - `Highly Confidential`

Suggested automation use:

- Simulate Office Web sensitivity label application.
- Simulate SharePoint label changes.
- Trigger Activity Explorer label events.
- Demonstrate label downgrade, label upgrade, label recommendation, and label removal workflows.
- Pair with `documents.json` to apply labels to the same file names.

Primary JSON key:

```json
"labelingScenarios"
```

---

## Important Design Conventions

### Fictional data only

All content is intentionally synthetic. Do not replace fictional values with real production data.

Examples of fictional patterns used:

```text
EMP-782143
CUST-449201
INV-FAK-2026-004817
SUP-60392
SEC-2026-0519
IR-91827
LEG-2044
ACCT-9920-4417-0038
sk-demo-7X2Q-ALPHA-9911
vendor.pm@northbridge-example.test
```

### Safe external domains

External domains use reserved or clearly fake-style names such as:

```text
northbridge-example.test
vendor-example.test
training-example.test
counsel-example.test
```

### Labels

The pack uses simplified demo labels:

```text
Public
Internal
Confidential
Highly Confidential
```

Codex can map these to tenant-specific label IDs later if needed.

### Activity Explorer signals

The pack intentionally references common Purview-style activity concepts:

```text
FileCreated
FileModified
FileDownloaded
FileShared
FilePrinted
FileCopiedToNetworkShare
LabelApplied
LabelChanged
LabelRemoved
LabelRecommended
CopilotInteraction
AIAppInteraction
```

Actual event names in Microsoft Purview exports may vary depending on workload, licensing, and audit schema. Treat these as orchestration intent labels unless your collector expects exact normalized names.

---

## Suggested Codex Tasks

Codex can use this handoff to implement the following:

1. Validate every JSON file for syntax and schema consistency.
2. Generate a combined `content-pack.json` with the original requested top-level structure.
3. Build TypeScript or Python interfaces/classes for each file schema.
4. Create a loader that reads each JSON file and exposes content by department, persona, scenario, and sensitivity level.
5. Build browser-agent task plans from the files:
   - Create emails from `email-templates.json`.
   - Create chat messages from `chat-threads.json`.
   - Generate documents from `documents.json`.
   - Apply labels from `labeling-scenarios.json`.
   - Simulate outbound sharing from `external-sharing-scenarios.json`.
   - Simulate AI usage from `ai-prompts.json`.
6. Add schema validation using JSON Schema.
7. Add deterministic random selection using seed values for repeatable demos.
8. Add mapping from persona role to fictional user UPNs if the demo tenant has a persona directory.
9. Add mapping from `suggestedSensitivityLabel` to real tenant label IDs.
10. Add orchestration profiles such as:
    - Normal workday
    - Finance close
    - HR compensation cycle
    - Contract negotiation
    - Customer escalation
    - Security incident
    - Insider risk simulation
    - Copilot oversharing demo

---

## Recommended Combined JSON Shape

If a combined file is needed, generate `content-pack.json` using this exact structure:

```json
{
  "emailSubjects": [],
  "emailTemplates": [],
  "chatThreads": [],
  "documents": [],
  "aiPrompts": [],
  "externalSharingScenarios": [],
  "labelingScenarios": [],
  "metadata": {
    "packName": "Synthetic Microsoft 365 Purview Demo Lab Content Pack",
    "version": "1.0",
    "fictionalDataOnly": true
  }
}
```

Populate each array from the corresponding modular file.

---

## Suggested Validation Rules

Codex should validate these conditions:

- Every item has a unique `id` inside its file.
- Every `fileName` referenced by labeling or sharing scenarios should ideally exist in `documents.json` or be explicitly marked as a sanitized derivative.
- Every `sensitivityLevel`, `initialLabel`, `finalLabel`, and `suggestedSensitivityLabel` should be one of:
  - `Public`
  - `Internal`
  - `Confidential`
  - `Highly Confidential`
  - `None` where applicable.
- Every `interactionType` in `ai-prompts.json` should be one of:
  - `CopilotInteraction`
  - `AIAppInteraction`
- Every document `fileType` should be one of:
  - `docx`
  - `pptx`
  - `xlsx`
  - `pdf`
  - `txt`
  - `csv`
- Every `labelEventType` should be one of:
  - `LabelApplied`
  - `LabelChanged`
  - `LabelRemoved`
  - `LabelRecommended`

---

## Current Commit History for This Pack

The following commits were created during generation:

```text
72750f07eb5affe77701ac5b368932247208b6f3 - Add README.md
77971b229c2079c14fcff4a642ded57dcb9d8a63 - Add email-subjects.json
18690526e16caf3fbe3b24c50cd0feaebcca7568 - Add email-templates.json
1421c0a58b8fecf2a1ab05b3ec9eb5a7cf2d3ab2 - Add chat-threads.json
d6463d975959bf148483a8e40eb0fd2d3d16fdeb - Add documents.json
18ae3c62f5944a61a1f1af06538f53473e1340f5 - Add ai-prompts.json
a59c21f9d5d4c2ac4fc4353ab447f03726f4a5b1 - Add external-sharing-scenarios.json
279619b06d8e27d7629b19becda17b522a19dead - Add labeling-scenarios.json
```

This handoff file was added after those commits.

---

## Final Notes for Codex

Treat this pack as a content source, not as an execution engine.

Recommended implementation pattern:

1. Load JSON files.
2. Validate schemas.
3. Map roles to tenant personas.
4. Map labels to tenant label IDs.
5. Generate actions for browser-based agents.
6. Execute actions in Microsoft 365 Web experiences.
7. Wait for audit/Purview telemetry.
8. Correlate observed events back to `activityExplorerScenarios`, `riskTheme`, `interactionType`, and label scenarios.

Do not introduce real credentials, real secrets, real customers, real employee records, or real financial data into this pack.
