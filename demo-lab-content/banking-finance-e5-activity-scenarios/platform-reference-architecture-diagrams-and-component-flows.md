# Platform Reference Architecture Diagrams and Component Flows

## Purpose

This document defines the visual systems-architecture and engineering-reference layer for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It provides text-based architecture diagrams, component responsibilities, data flows, trust boundaries, synthetic-data boundaries, deployment topology, and future-state architecture references.

All users, files, telemetry, prompts, incidents, customers, identifiers, financial records, HR records, legal matters, and cases are fictional and synthetic.

---

## Core Architecture Thesis

> The platform is a synthetic Microsoft 365 governance cyber-range. It manufactures fictional business content, simulates human collaboration, emits normalized telemetry, reconstructs timelines, and translates signals into executive, SOC, Purview, and AI-governance stories.

The architecture must preserve three boundaries:

1. Synthetic data boundary.
2. Demo/lab tenant boundary.
3. Production/customer-data exclusion boundary.

---

## Logical Architecture Overview

```mermaid
flowchart LR
    A[Content Factory] --> B[Scenario Catalog]
    B --> C[Telemetry Generator]
    C --> D[JSONL / CSV Outputs]
    D --> E[ADX]
    D --> F[Power BI]
    E --> G[KQL Hunting]
    E --> H[Replay Engine]
    H --> F
    H --> I[SOC / Sentinel Concepts]
    B --> H
    A --> J[SharePoint / Teams / OneDrive Lab Content]
    K[Browser Agents - Future] --> J
    K --> C
    F --> L[Executive Storytelling]
    G --> M[SOC Investigation]
    I --> M
```

---

## Component Responsibility Matrix

| Component | Responsibility | MVP Required |
|---|---|---|
| Content Factory | generates synthetic documents, emails, chats, prompts, metadata | Partial |
| Persona Catalog | defines fictional users, roles, departments, behavior | Yes |
| Scenario Catalog | defines business scenarios and expected signals | Yes |
| Telemetry Generator | creates normalized synthetic events | Yes |
| Risk Scoring Engine | assigns synthetic risk scores and severities | Yes |
| Replay Engine | reconstructs ordered scenario timelines | Yes |
| ADX Layer | ingests JSONL and supports KQL hunting | P1 |
| Power BI Layer | provides executive and analyst dashboards | Yes |
| KQL Detection Layer | supports hunting and replay validation | P1 |
| Browser Agents | performs visible Microsoft 365 actions | Future |
| Sentinel Layer | maps detections to incidents and SOC workflows | Future |
| Validation Layer | enforces schema, safety, and replay correctness | Yes |
| Commercial Layer | packages demos into services and workshops | P2 |

---

## Synthetic Content Flow

```mermaid
flowchart TD
    A[Business Cycle] --> B[Persona Context]
    B --> C[Content Blueprint]
    C --> D[Synthetic Pattern Generation]
    D --> E[Document / Email / Teams / Prompt Body]
    E --> F[Label Assignment]
    F --> G[File Placement]
    G --> H[Lifecycle State]
    H --> I[Content Manifest]
    I --> J[Telemetry Enrichment]
    J --> K[Safety Validation]
```

### Output

```text
content-output/documents
content-output/emails
content-output/teams-threads
content-output/ai-prompts
content-output/metadata/generated-content-manifest.json
```

---

## Telemetry Generation Flow

```mermaid
flowchart TD
    A[Persona Catalog] --> D[Telemetry Generator]
    B[Scenario Catalog] --> D
    C[Operation Catalog] --> D
    E[Dataset Specification] --> D
    D --> F[Baseline Noise Events]
    D --> G[Scenario Timeline Events]
    F --> H[Normalized Event Stream]
    G --> H
    H --> I[Risk Scoring]
    I --> J[Synthetic Safety Filter]
    J --> K[JSONL Export]
    J --> L[CSV Export]
    J --> M[Validation Report]
```

---

## Replay Engine Flow

```mermaid
flowchart TD
    A[ScenarioId] --> B[Replay Seed]
    B --> C[Timeline Builder]
    C --> D[Required Event Sequence]
    D --> E[Event Scheduler]
    E --> F[Bookmarks]
    E --> G[Replay Timeline JSON]
    G --> H[Power BI Replay Filter]
    G --> I[ADX Replay Query]
    G --> J[Presenter Storyboard]
```

### Replay Keys

```text
ReplayId
ScenarioId
CorrelationId
UserPrincipalName
FileName
TimeGenerated
```

---

## Browser-Agent Future Flow

```mermaid
flowchart TD
    A[Task Plan] --> B[Persona Behavior Profile]
    B --> C[Browser Agent Runner]
    C --> D[Microsoft 365 Lab Tenant]
    D --> E[Visible User Activity]
    C --> F[Action Log]
    F --> G[Synthetic Telemetry Emitter]
    G --> H[ADX / CSV / JSONL]
    H --> I[Power BI / Replay]
```

### Important

Browser agents are future-state and should not be implemented before the MVP telemetry generator, validation, and Power BI-ready dataset are stable.

---

## ADX Ingestion Flow

```mermaid
flowchart TD
    A[JSONL Export] --> B[ADX Ingestion Mapping]
    B --> C[SyntheticM365ActivityEvents]
    C --> D[KQL Hunting Queries]
    C --> E[Power BI DirectQuery / Extract]
    C --> F[Replay Reconstruction]
    C --> G[Detection Validation]
```

---

## Power BI Consumption Flow

```mermaid
flowchart TD
    A[CSV Export or ADX Query] --> B[FactActivityEvents]
    B --> C[DimDate]
    B --> D[DimUser]
    B --> E[DimScenario]
    B --> F[DimSignal]
    B --> G[DimFile]
    B --> H[Measures]
    H --> I[Executive Risk Snapshot]
    H --> J[AI Governance Page]
    H --> K[DLP Operations]
    H --> L[Scenario Replay]
    H --> M[SOC Drillthrough]
```

---

## Sentinel Future Enrichment Flow

```mermaid
flowchart TD
    A[SyntheticM365ActivityEvents] --> B[Sentinel Custom Table]
    B --> C[Analytics Rules]
    C --> D[Synthetic Incidents]
    D --> E[Entity Mapping]
    E --> F[Watchlist Enrichment]
    F --> G[Playbooks]
    G --> H[SOC Case Workflow]
    H --> I[Executive Incident Summary]
```

---

## AI Governance Flow

```mermaid
flowchart TD
    A[Source Content] --> B[Permissions and Labels]
    B --> C[Approved AI Workspace]
    B --> D[Copilot Interaction]
    B --> E[External AI Interaction]
    D --> F[Reviewed AI Output]
    E --> G[DLP / App Governance Signal]
    F --> H[Safe Sharing Path]
    G --> I[Security Review / Coaching]
    I --> J[Governance Improvement]
```

---

## Validation Pipeline Flow

```mermaid
flowchart TD
    A[Generated Files] --> B[Schema Validation]
    B --> C[Required Field Validation]
    C --> D[Synthetic Safety Validation]
    D --> E[Scenario Reference Validation]
    E --> F[Replay Order Validation]
    F --> G[Power BI Metric Plausibility]
    G --> H[Validation Report]
```

---

## CI/CD Future Flow

```mermaid
flowchart TD
    A[Pull Request] --> B[JSON Validation]
    B --> C[Markdown Link Check]
    C --> D[Synthetic Safety Scan]
    D --> E[Scenario ID Validation]
    E --> F[Replay Validation]
    F --> G[Dataset Generation Test]
    G --> H[Release Readiness Report]
```

---

## Trust Boundaries

| Boundary | Description | Rule |
|---|---|---|
| Synthetic Data Boundary | generated data is fictional only | never import production data |
| Lab Tenant Boundary | browser agents operate only in lab/demo tenant | never automate production tenants |
| Repository Boundary | repository stores only synthetic examples and code | no credentials or real secrets |
| External Sharing Boundary | external recipients are fake/test domains | no real customer or vendor data |
| AI Boundary | AI prompts use synthetic or sanitized content only | no real sensitive prompt content |
| Investigation Boundary | cases are fictional | no real employee monitoring |

---

## Synthetic Data Boundary Controls

Required controls:

```text
IsSynthetic = true on every event
approved fictional prefixes only
fake/test domains only
no real addresses
no real credentials
no production URLs
validation report generated for each dataset
synthetic disclaimer in dashboards and docs
```

---

## Deployment Topology - Offline MVP

```mermaid
flowchart LR
    A[Python Generator] --> B[CSV]
    A --> C[JSONL]
    B --> D[Power BI Desktop]
    C --> E[Optional ADX Load]
    A --> F[Validation Report]
```

Best for:

- first MVP
- executive demo
- safe offline storytelling
- development validation

---

## Deployment Topology - Cloud-Connected Demo

```mermaid
flowchart LR
    A[Content Factory] --> B[Microsoft 365 Demo Tenant]
    C[Telemetry Generator] --> D[ADX]
    D --> E[Power BI]
    F[Browser Agents] --> B
    F --> C
    D --> G[KQL Hunting]
```

Best for:

- technical workshops
- Purview demo scenarios
- visible browser-based activity

---

## Deployment Topology - Future SOC Cyber-Range

```mermaid
flowchart LR
    A[Browser Agents] --> B[M365 Demo Tenant]
    B --> C[Synthetic Telemetry Layer]
    C --> D[ADX]
    D --> E[Power BI]
    D --> F[Sentinel Custom Table]
    F --> G[Analytics Rules]
    G --> H[Synthetic Incidents]
    H --> I[SOC Tabletop]
    E --> J[Executive Reporting]
```

Best for:

- SOC training
- MDR/MXDR demos
- cyber-range exercises
- multi-day replay

---

## Component Ownership

| Component | Owner Role |
|---|---|
| Content Factory | Content Engineer |
| Persona and Scenario Catalog | Scenario Designer |
| Telemetry Generator | Data Engineer |
| Validation Pipeline | Platform Maintainer |
| ADX / KQL | Detection Engineer |
| Power BI | BI Developer |
| Replay Engine | Simulation Engineer |
| Browser Agents | Automation Engineer |
| Sentinel Layer | SOC Architect |
| AI Governance Layer | AI Governance Lead |
| Commercialization | Services Lead |

---

## Future-State Architecture

Future architecture should support:

```text
autonomous persona agents
multi-tenant federation
Sentinel incident automation
Defender XDR enrichment
Microsoft Fabric lakehouse analytics
replay APIs
Power BI embedded storytelling
scenario marketplace
industry-specific scenario packs
managed governance reporting
```

These should remain future-state until the MVP dataset, validation pipeline, ADX ingestion, and Power BI dashboards are stable.

---

## Codex Usage Guidance

Codex should use this file to:

1. Understand component flows before implementing code.
2. Generate architecture diagrams from Mermaid blocks.
3. Preserve trust boundaries.
4. Place outputs in the correct architecture layer.
5. Avoid building future-state components before MVP dependencies exist.
6. Map implementation tasks to component responsibilities.
7. Update diagrams when major architecture changes occur.
8. Preserve synthetic-only boundaries.

---

## Safety Reminder

This architecture is for synthetic demo, simulation, and advisory use only.

Do not connect it to production tenants, production telemetry, real users, real customers, real HR records, real legal matters, real financial data, real credentials, real secrets, or real incident evidence.
