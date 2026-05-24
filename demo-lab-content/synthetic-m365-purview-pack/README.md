# Synthetic Microsoft 365 / Purview Demo Lab Content Pack

This folder is intended to contain a large structured JSON content pack for a Microsoft 365 / Microsoft Purview demo lab.

All names, organizations, customers, identifiers, financial values, support cases, HR records, invoices, bank-like numbers, personal data patterns, incidents, contracts, and operational examples are fictional and are designed for demo/simulation purposes only.

Recommended file layout:

- `content-pack.json` — combined top-level JSON object.
- `email-subjects.json` — grouped subject library.
- `email-templates.json` — reusable email templates.
- `chat-threads.json` — Teams/chat style conversations.
- `documents.json` — Office/document generation briefs.
- `ai-prompts.json` — Copilot and AI prompt library.
- `external-sharing-scenarios.json` — external sharing simulations.
- `labeling-scenarios.json` — sensitivity label event simulations.

Primary schemas requested:

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

Usage notes:

- Use only inside controlled demo tenants or lab environments.
- Do not mix with real production data.
- Do not replace fictional values with real secrets, real employee data, real customer data, real credentials, or real regulated records.
- The content is intentionally designed to exercise Purview signals such as file creation, file modification, sensitivity labeling, file sharing, downloads, print events, and AI/Copilot interaction style activities.
