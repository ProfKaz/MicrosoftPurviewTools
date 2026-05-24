# Release Management and Versioning Strategy

## Purpose

This document defines the software lifecycle management model for the synthetic Microsoft 365 E5 / Microsoft Purview banking and financial-services simulation platform.

It covers:

- semantic versioning
- release channels
- artifact lifecycle
- scenario lifecycle
- backward compatibility
- changelog structure
- branch strategy
- rollback strategy
- demo certification
- compatibility matrices
- contributor workflow
- GitHub issue taxonomy
- milestone management

All release practices must preserve the synthetic-only boundary of the platform.

---

## Release Management Principles

1. Treat the platform as a reusable product, not a one-time demo.
2. Every release should be reproducible, documented, and validated.
3. Breaking schema changes must be explicit.
4. Demo-ready releases should be certified before customer use.
5. Experimental roadmap items should not destabilize stable demo tracks.
6. Synthetic data safety validation is required for every release.
7. Changelogs should explain business impact, not only technical changes.

---

## Semantic Versioning Model

Use semantic versioning where practical:

```text
MAJOR.MINOR.PATCH
```

Example:

```text
1.4.2
```

### MAJOR Version

Increment when:

- telemetry schema changes in a breaking way
- scenario format changes in a breaking way
- Power BI semantic model changes incompatibly
- ADX table contract changes incompatibly
- replay engine timeline format changes incompatibly

Example:

```text
2.0.0 - New telemetry schema and replay model
```

### MINOR Version

Increment when:

- new scenarios are added
- new personas are added
- new Power BI pages are added
- new DLP policies are added
- new KQL samples are added
- new deployment guidance is added
- compatible schema fields are added

Example:

```text
1.5.0 - Adds Sentinel integration roadmap and new AI governance scenarios
```

### PATCH Version

Increment when:

- typos are fixed
- documentation is clarified
- sample data is corrected
- non-breaking query changes are made
- formatting is improved
- minor validation warnings are resolved

Example:

```text
1.5.1 - Fixes scenario references and DAX measure wording
```

---

## Release Channels

## Stable

Purpose:

- customer-facing demos
- executive briefings
- workshops
- sales enablement

Requirements:

- JSON validation passed
- markdown validation passed
- synthetic-data safety validation passed
- Power BI sample refresh validated
- presenter script aligned
- demo path tested

---

## Preview

Purpose:

- internal testing
- early customer pilots
- new scenario validation
- new dashboard concepts

Requirements:

- no known synthetic-data safety issues
- major schema changes documented
- limitations clearly stated

---

## Experimental

Purpose:

- research
- future roadmap work
- autonomous agents
- Sentinel/Fabric concepts
- multi-tenant federation
- red-team/blue-team simulations

Requirements:

- clearly marked as experimental
- not used for customer demos unless explicitly approved
- synthetic-only safety still required

---

## Artifact Lifecycle

Recommended lifecycle states:

```text
Draft
Validated
Preview
Stable
Deprecated
Archived
Removed
```

### Draft

Work in progress. Not demo-ready.

### Validated

Passes structural checks but may not be customer-ready.

### Preview

Can be used in internal or controlled demos.

### Stable

Approved for customer-facing demos.

### Deprecated

Still present, but replacement exists.

### Archived

Kept for history but not actively maintained.

### Removed

Deleted after migration or replacement.

---

## Scenario Lifecycle

Scenario states:

```text
Proposed
Drafted
Validated
Demo Ready
Deprecated
Archived
```

### Scenario Promotion Criteria

A scenario becomes `Demo Ready` when:

1. Scenario ID is valid.
2. Personas are valid.
3. Synthetic data patterns are valid.
4. Expected telemetry exists.
5. Power BI replay works.
6. Presenter narrative exists.
7. Safety disclaimer is clear.
8. Risk interpretation avoids unsupported intent claims.

---

## Demo Certification Process

Before customer-facing use, a demo path should be certified.

### Certification Checklist

- selected scenario is stable
- telemetry dataset loads successfully
- Power BI report refresh succeeds
- DAX measures calculate correctly
- KQL queries run against the target schema
- presenter script matches visuals
- synthetic-only disclaimer is visible
- no real domains or identifiers are present
- fallback instant replay mode is available
- known limitations are documented

### Certification Outcome

Use one of:

```text
Certified for Executive Demo
Certified for Technical Workshop
Certified for SOC Tabletop
Certified for Internal Use Only
Not Certified
```

---

## Branch Strategy

Recommended branches:

```text
main
release/[version]
feature/[short-description]
fix/[short-description]
experiment/[short-description]
```

### Main Branch

Purpose:

- stable or near-stable content
- latest validated platform state

### Release Branch

Purpose:

- freeze demo-ready versions
- support customer workshops
- prevent last-minute breakage

### Feature Branch

Purpose:

- new scenarios
- new docs
- new schemas
- new automation

### Experiment Branch

Purpose:

- risky or future-looking capabilities
- autonomous agents
- new replay concepts
- prototype integrations

---

## Changelog Structure

Maintain a future file:

```text
CHANGELOG.md
```

Recommended format:

```markdown
# Changelog

## [1.5.0] - 2026-05-24

### Added
- New AI governance scenario.
- New Power BI DAX measures.

### Changed
- Updated telemetry schema with AppName and PromptText fields.

### Fixed
- Corrected scenario references in KQL samples.

### Deprecated
- Deprecated old AI prompt risk field.

### Removed
- Removed obsolete demo placeholder values.

### Security / Safety
- Added synthetic-data validation for external domains.

### Demo Impact
- Executive demo path now supports AI governance storyline.
```

---

## Backward Compatibility Policy

### Compatible Changes

- adding optional fields
- adding new scenarios
- adding new DAX measures
- adding new KQL samples
- adding new documentation
- adding new synthetic patterns with approved prefixes

### Breaking Changes

- renaming canonical telemetry fields
- removing fields used by Power BI or ADX
- changing scenario ID format
- changing operation names
- changing severity enumeration
- changing sensitivity label names
- changing replay timeline structure

Breaking changes require:

- major version increment
- migration notes
- compatibility matrix update
- validation rule update

---

## Compatibility Matrix

Maintain compatibility across:

| Component | Depends On |
|---|---|
| Power BI model | telemetry schema, DAX library, ADX mapping |
| ADX ingestion | telemetry schema, replay output |
| KQL samples | ADX table names and operation catalog |
| replay engine | scenario format, schedules, task plans |
| SOC playbooks | operations, scenario IDs, risk engine |
| presenter scripts | Power BI pages, scenario narratives |
| commercialization content | demo maturity and platform capability |

---

## Rollback Strategy

Rollback may be required when:

- a release breaks Power BI
- schema changes invalidate KQL
- scenarios fail validation
- browser automation breaks before a demo
- synthetic-data safety validation fails

Recommended rollback steps:

1. Identify last certified release.
2. Restore release branch or tag.
3. Re-run validation.
4. Re-load known-good telemetry dataset.
5. Refresh Power BI.
6. Use fallback presenter script.
7. Document rollback reason.

---

## Tagging Strategy

Recommended tags:

```text
v1.0.0
v1.1.0-preview
v1.2.0-demo-certified
v2.0.0-breaking-schema
```

For major customer demos, create a tag:

```text
demo-[customer-or-event]-[date]
```

Example:

```text
demo-executive-ai-governance-2026-05-24
```

Use customer-neutral names if repository visibility requires it.

---

## GitHub Issue Taxonomy

Recommended labels:

```text
type:scenario
type:documentation
type:schema
type:telemetry
type:powerbi
type:adx
type:kql
type:automation
type:security-safety
type:commercialization
type:bug
type:enhancement
priority:low
priority:medium
priority:high
priority:critical
status:blocked
status:ready
status:in-progress
status:needs-review
```

---

## Milestone Model

Suggested milestones:

```text
MVP Offline Demo
Cloud-Connected MVP
Power BI Demo Pack
ADX Ingestion Pack
Browser Agent Preview
SOC Tabletop Pack
Executive Briefing Pack
Purview Workshop Pack
Copilot Governance Pack
Cyber-Range v1
```

---

## Contributor Workflow

Recommended workflow:

1. Create issue.
2. Assign type and priority labels.
3. Create branch.
4. Make changes.
5. Run validation locally where possible.
6. Open pull request.
7. Include validation notes.
8. Review synthetic-data safety.
9. Merge after approval.
10. Update changelog if needed.

---

## Release Readiness Checklist

Before tagging a release:

- all JSON files are valid
- all markdown files render correctly
- cross-file references are valid
- operation catalog validation passes
- synthetic-data safety validation passes
- Power BI assumptions are reviewed
- ADX mappings are reviewed
- KQL samples are reviewed
- presenter scripts are aligned
- known limitations are updated
- changelog is updated
- release notes are created

---

## Release Notes Template

```markdown
# Release Notes - Version X.Y.Z

## Summary

Short explanation of the release.

## Audience Impact

- Executive demos:
- Technical workshops:
- SOC exercises:
- Power BI reporting:
- Codex automation:

## Added

## Changed

## Fixed

## Deprecated

## Removed

## Safety Notes

## Known Limitations

## Upgrade Notes

## Rollback Notes
```

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate changelogs.
2. Create release notes.
3. Validate version increments.
4. Generate GitHub issue labels and milestones.
5. Create release-readiness checklists.
6. Identify breaking changes.
7. Produce rollback instructions.
8. Manage artifact lifecycle states.
9. Prepare demo certification notes.
10. Preserve synthetic-only boundaries.

---

## Safety Reminder

No release should be considered stable if it introduces real sensitive data, real credentials, production customer identifiers, or unsupported claims about employee risk, compliance certification, or Microsoft feature behavior.
