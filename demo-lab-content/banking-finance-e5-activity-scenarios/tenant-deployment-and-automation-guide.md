# Tenant Deployment and Automation Guide - Banking / Finance Microsoft 365 E5 Simulation Pack

## Purpose

This document defines the recommended deployment and automation approach for building the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services demo lab.

It covers:

- tenant bootstrap
- synthetic user lifecycle
- Entra group creation
- SharePoint provisioning
- Teams provisioning
- sensitivity label deployment
- DLP and Endpoint DLP deployment
- Purview and Defender configuration concepts
- ADX deployment
- Power BI deployment
- browser-agent deployment
- telemetry pipelines
- GitHub Actions / CI/CD
- reset procedures
- cleanup procedures

All data, users, identities, customers, accounts, incidents, and files must remain fictional.

---

## Deployment Principles

1. Automate repeatable setup and reset tasks.
2. Keep configuration separated from generated synthetic content.
3. Use least privilege for automation identities.
4. Use synthetic users and synthetic data only.
5. Keep risky demo behavior isolated from production tenants.
6. Prefer staged deployment: topology first, controls second, content third, telemetry fourth.
7. Make every scenario replayable and disposable.

---

## Recommended Deployment Phases

```text
Phase 0 - Prerequisites and tenant readiness
Phase 1 - Identity and group model
Phase 2 - SharePoint and Teams topology
Phase 3 - Purview labels and policy concepts
Phase 4 - Synthetic content seeding
Phase 5 - Browser-agent orchestration
Phase 6 - Telemetry generation and ADX ingestion
Phase 7 - Power BI reporting
Phase 8 - Scenario replay validation
Phase 9 - Demo reset and cleanup
```

---

## Phase 0 - Prerequisites

### Licensing

Recommended lab licensing:

```text
Microsoft 365 E5
Microsoft Purview capabilities
Microsoft Defender XDR capabilities
Microsoft Entra ID P2 capabilities
Power BI capacity or Power BI Pro/Premium per user for reporting
Azure subscription for ADX, storage, automation, and optional app services
```

### Administrative Roles

Use only the permissions required for the deployment step.

Possible roles:

```text
Global Administrator - initial tenant setup only
Compliance Administrator - Purview labels and DLP
Security Administrator - Defender and security configuration
SharePoint Administrator - sites and sharing controls
Teams Administrator - Teams provisioning
Exchange Administrator - mail flow and DLP testing
Power BI Administrator - report workspace setup
Application Administrator - service principals and app registrations
```

Do not run all automation permanently as Global Administrator.

---

## Phase 1 - Identity and Group Model

### Synthetic Users

Create fictional users only.

Recommended personas:

```text
alexander.meyer@mhdemos.com
ana.rodriguez@mhdemos.com
carlos.delgado@mhdemos.com
david.chen@mhdemos.com
emily.johnson@mhdemos.com
james.wilson@mhdemos.com
laura.gomez@mhdemos.com
marcus.olsson@mhdemos.com
miguel.santos@mhdemos.com
priya.sharma@mhdemos.com
sofia.lopez@mhdemos.com
devon.reyes@mhdemos.com
```

### Recommended Entra Groups

```text
MH Demo - Executive Leadership
MH Demo - HR Restricted
MH Demo - Finance Close
MH Demo - Legal Privileged
MH Demo - Customer Operations
MH Demo - IT Security Operations
MH Demo - Data Science Lab
MH Demo - PMO Governance
MH Demo - Vendor Collaboration Owners
MH Demo - Vendor Collaboration Guests
MH Demo - AI Approved Workspace Users
MH Demo - DLP Reviewers
MH Demo - Insider Risk Reviewers
MH Demo - Security Investigation Reviewers
```

### Group Design Guidance

- Use groups for permissions, not individual assignments.
- Keep HR, Legal, and Security groups separate.
- Create guest-enabled groups only for vendor collaboration.
- Use Devon as a member of Customer Operations and limited PMO/working groups.
- Avoid making Devon a member of HR, Legal, or Security unless a scenario intentionally requires over-permissioning.

---

## Phase 2 - SharePoint and Teams Provisioning

Use `synthetic-tenant-information-architecture.md` as the source of truth.

### SharePoint Sites

Provision sites such as:

```text
/sites/ExecutiveLeadership
/sites/HRRestricted
/sites/FinanceClose
/sites/LegalPrivileged
/sites/CustomerOperations
/sites/ITSecurityOps
/sites/DataScienceLab
/sites/PMOGovernance
/sites/VendorCollaboration
/sites/AIApprovedWorkspace
/sites/TrainingAwareness
```

### Provisioning Guidance

For each site:

1. Create site.
2. Assign owner group.
3. Assign member group.
4. Configure external sharing boundary.
5. Create document libraries.
6. Apply default label concepts where supported.
7. Configure versioning.
8. Configure audit-friendly naming standards.

### Teams Provisioning

Create Teams aligned to major collaboration domains:

```text
Executive Leadership Team
HR Restricted Team
Finance Close Team
Legal Regulatory Response Team
Customer Operations Team
Banking PMO Team
Vendor Collaboration Team
IT Security Operations Team
Data Science and Analytics Team
Training and Awareness Community
```

### External Collaboration

Guest access should be allowed only in controlled spaces such as:

```text
Vendor Collaboration Team
/sites/VendorCollaboration
Legal external counsel package area, if explicitly needed
```

---

## Phase 3 - Purview Labels and Policy Concepts

Use `purview-policy-and-control-matrix.md` as the source of truth.

### Recommended Labels

```text
Public
Internal
Confidential
Highly Confidential
Highly Confidential - Regulated Financial Data
Highly Confidential - HR Restricted
Highly Confidential - Legal Privileged
```

### Deployment Notes

- Publish labels to synthetic users and groups.
- Test label availability in Office Web.
- Validate labels on SharePoint, OneDrive, Outlook, and Teams where applicable.
- Use label downgrade justifications for demo scenarios.
- Configure label recommendations or auto-label simulations where feasible.

---

## Phase 4 - DLP and Endpoint DLP Deployment

Recommended policy concepts:

```text
Regulated Financial Data - External Sharing
KYC and Loan Packet Protection
AML and SAR Handling
Treasury Reconciliation Protection
HR Compensation Protection
Legal Privileged Protection
Power BI Underlying Data Export Review
External AI Sensitive Data Upload
```

### Suggested DLP Actions by Maturity

| Demo Maturity | Action Style |
|---|---|
| basic | audit only |
| intermediate | warn and policy tips |
| advanced | block with override |
| strict | block without override for specific scenarios |

### Endpoint DLP Concepts

Simulate or configure controls for:

- print
- USB copy
- network share copy
- browser upload
- local file movement

If real endpoint signals are not available, emit synthetic events using `synthetic-telemetry-schema.json`.

---

## Phase 5 - Synthetic Content Seeding

Use:

- `content-generation-blueprints.json`
- `synthetic-data-pattern-library.json`
- `complex-scenarios.json`

### Content Types to Seed

```text
Word documents
Excel workbooks
PowerPoint decks
PDF-like exports
CSV files
TXT prompt transcripts
Teams messages
email drafts or sent messages
investigation summaries
sanitized vendor packages
```

### Recommended Seeding Strategy

1. Seed safe baseline content.
2. Seed sensitive internal content.
3. Seed sanitized external variants.
4. Seed intentionally imperfect content.
5. Seed investigation artifacts only after scenario execution.

---

## Phase 6 - Browser-Agent Deployment

Browser agents should use:

- `browser-agent-task-plans.json`
- `browser-agent-orchestration-rules.json`
- `telemetry-generation-playbooks.json`
- `m365-activity-timeline-replay-engine-specification.md`

### Agent Responsibilities

- sign in as synthetic users
- create and edit Office files
- send emails
- post Teams messages
- share files
- use Copilot or simulate AI prompts
- trigger or simulate DLP events
- emit synthetic telemetry

### Execution Modes

```text
realistic
compressed demo
instant replay
SOC analyst mode
executive demo mode
chaos mode
```

### Browser Automation Safety

- Use synthetic accounts only.
- Avoid production tenants.
- Do not store real credentials in scripts.
- Use secure secret management.
- Keep agent logs synthetic.
- Reset sessions between personas.

---

## Phase 7 - ADX Deployment

Use `adx-ingestion-and-table-mappings.md` as the source of truth.

### Recommended ADX Tables

```text
SyntheticM365ActivityEventsRaw
SyntheticM365ActivityEvents
```

### Recommended Materialized Views

```text
mv_RiskEventsByDay
mv_ScenarioSummary
mv_UserRiskSummary
mv_SensitiveFileExposure
```

### Telemetry Sources

```text
browser-agent actions
synthetic event generator
instant replay engine
scenario validation engine
SOC analyst mode staged evidence
```

### Ingestion Strategy

- Use batch ingestion for replay.
- Use small batches for compressed demos.
- Use single or scenario-based batch for instant replay.
- Include BatchId, ReplayId, ScenarioId, and CorrelationId.

---

## Phase 8 - Power BI Deployment

Use:

- `powerbi-risk-dashboard-definitions.json`
- `powerbi-dax-measures-library.md`
- `powerbi-visual-layout-and-storytelling-guide.md`

### Recommended Report Pages

```text
Executive Risk Snapshot
Sensitive Data Exposure
AI and Copilot Risk
DLP Operations
External Sharing Heatmap
Endpoint DLP and Device Movement
Insider Risk Overview
Scenario Replay and Timeline
User Investigation Drillthrough
Sensitive File Drillthrough
```

### Deployment Options

| Option | Use Case |
|---|---|
| Import mode | stable executive demos |
| DirectQuery to ADX | live replay demos |
| composite model | hybrid demo and analysis |
| static sample dataset | offline workshop delivery |

---

## Phase 9 - CI/CD and GitHub Actions Concepts

Recommended pipeline stages:

```text
validate-json
validate-markdown
generate-synthetic-content
validate-telemetry-schema
run-scenario-simulation
publish-sample-events
build-powerbi-artifacts
package-demo-release
```

### JSON Validation

Validate all JSON files in this folder:

```text
*.json
```

Recommended checks:

- valid JSON
- required metadata block
- unique IDs
- valid scenario references
- valid operation names
- synthetic-only patterns

### Markdown Validation

Validate:

- links
- headings
- code fences
- safety reminders
- Codex usage sections

---

## Demo Reset Procedure

Use this before a new customer demo or workshop.

### Soft Reset

Use when you want to preserve topology.

1. Delete generated scenario files.
2. Clear synthetic telemetry batches for selected replay ID.
3. Reset Power BI filters/bookmarks.
4. Remove guest users from Vendor Collaboration.
5. Clear Teams test messages where practical.
6. Re-seed baseline content.

### Hard Reset

Use when the tenant has too much drift.

1. Export useful demo artifacts.
2. Remove generated sites or libraries.
3. Delete synthetic users if required.
4. Remove scenario-specific groups.
5. Recreate topology.
6. Reapply labels and DLP concepts.
7. Re-seed content.
8. Re-ingest telemetry.
9. Validate dashboards.

---

## Cleanup Procedure

Cleanup should remove:

```text
synthetic files
synthetic Teams conversations where possible
synthetic guest users
synthetic telemetry batches
temporary ADX tables
temporary Power BI datasets
browser-agent session data
expired secrets
unused app registrations
```

Do not delete reusable configuration unless performing a hard reset.

---

## Secret and Credential Handling

Recommended approach:

- use managed identities where possible
- use Azure Key Vault for secrets
- never commit credentials to GitHub
- rotate demo credentials regularly
- separate user credentials from automation credentials
- prefer delegated test accounts for browser automation
- use least privilege for service principals

---

## Synthetic User Lifecycle

Recommended lifecycle states:

```text
Created
Licensed
Assigned to Groups
Seeded with Mailbox/OneDrive Activity
Active in Simulation
Paused
Reset
Deleted
```

### Devon-Specific Lifecycle Note

Devon should remain a normal user most of the time.

Risk behavior should be activated only by:

- selected scenario
- role-change context
- deadline pressure
- external vendor request
- unsafe AI prompt path
- wrong file selection
- endpoint movement path

---

## Validation Checklist

Before a demo, confirm:

- synthetic users can sign in
- required licenses are assigned
- SharePoint sites exist
- Teams exist
- labels are available in Office Web
- DLP policies are in correct mode
- browser agents can authenticate
- sample content exists
- ADX tables contain recent telemetry
- Power BI report refresh works
- scenario replay produces expected signals
- all data is synthetic

---

## Recommended Implementation Backlog

1. Create tenant bootstrap script.
2. Create Entra group creation script.
3. Create SharePoint site provisioning script.
4. Create Teams provisioning script.
5. Create label and DLP documentation deployment checklist.
6. Create synthetic content generator.
7. Create browser-agent runner.
8. Create telemetry emitter.
9. Create ADX deployment script.
10. Create Power BI template.
11. Create GitHub Actions JSON validation workflow.
12. Create replay validation test suite.
13. Create demo reset script.
14. Create cleanup script.
15. Create release packaging process.

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate deployment scripts.
2. Create infrastructure-as-code templates.
3. Build CI/CD workflows.
4. Create tenant reset utilities.
5. Create validation scripts.
6. Generate synthetic content seeding tools.
7. Generate ADX deployment assets.
8. Generate Power BI deployment notes.
9. Keep automation identities least-privileged.
10. Preserve synthetic-only constraints.

---

## Safety Reminder

This deployment guide is for synthetic demo environments only.

Do not deploy risky simulation behavior, synthetic insider-risk scoring, browser-agent automation, or fake DLP events into a production tenant.

Do not use real customer, employee, legal, HR, financial, credential, or incident data in this lab.
