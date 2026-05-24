# Synthetic Dataset Generator Pseudocode and Processing Pipeline

## Purpose

This document defines the generation-engine design for producing synthetic Microsoft 365 E5 / Microsoft Purview banking telemetry datasets.

It explains how a generator should convert platform configuration files into:

- ADX-ready JSONL telemetry
- Power BI-ready CSV datasets
- scenario replay timelines
- validation reports
- scenario summary files

The first target dataset is defined in:

```text
sample-synthetic-telemetry-dataset-specification.md
```

All generated data must remain fictional and synthetic.

---

## Generator Objectives

The generator should:

1. Load platform configuration files.
2. Validate source JSON and Markdown references.
3. Apply deterministic seeds.
4. Generate baseline business activity.
5. Inject scenario-specific timelines.
6. Generate realistic timestamps and quiet periods.
7. Normalize events to `synthetic-telemetry-schema.json`.
8. Apply risk scores and severity.
9. Export JSONL and CSV.
10. Produce validation and summary reports.

---

## Recommended Generator Modules

```text
/config-loader
/schema-validator
/persona-scheduler
/baseline-noise-generator
/scenario-injector
/timeline-builder
/content-reference-generator
/risk-scorer
/telemetry-normalizer
/synthetic-safety-filter
/jsonl-exporter
/csv-exporter
/validation-reporter
```

---

## Input Files

Required inputs:

```text
sample-synthetic-telemetry-dataset-specification.md
complex-scenarios.json
synthetic-telemetry-schema.json
synthetic-data-pattern-library.json
synthetic-risk-correlation-engine.json
content-generation-blueprints.json
daily-schedules.json
browser-agent-orchestration-rules.json
telemetry-generation-playbooks.json
persona-behavioral-psychology-and-risk-patterns-guide.md
```

Optional inputs:

```text
purview-policy-and-control-matrix.md
synthetic-investigation-case-management-framework.md
synthetic-security-operations-playbooks.md
powerbi-dax-measures-library.md
```

---

## Output Files

Recommended outputs:

```text
sample-data/banking-finance-e5-mvp-synthetic-telemetry-1000.jsonl
sample-data/banking-finance-e5-mvp-synthetic-telemetry-1000.csv
sample-data/banking-finance-e5-mvp-synthetic-telemetry-1000-validation-report.json
sample-data/banking-finance-e5-mvp-scenario-summary.json
sample-data/banking-finance-e5-mvp-replay-timeline.json
```

---

## High-Level Processing Pipeline

```text
Load configuration
        ↓
Validate source files
        ↓
Initialize deterministic seed
        ↓
Create persona schedule windows
        ↓
Generate baseline noise
        ↓
Inject primary scenarios
        ↓
Build correlated timelines
        ↓
Attach files, labels, prompts, recipients, devices
        ↓
Apply risk scoring
        ↓
Normalize telemetry fields
        ↓
Run synthetic-data safety filter
        ↓
Export JSONL and CSV
        ↓
Generate validation report
        ↓
Generate scenario summary
```

---

## Deterministic Seed Strategy

The generator should accept a seed such as:

```text
BF-MVP-1000-2026-05-24-v1
```

The seed should control:

- event ordering
- timestamp jitter
- persona activity selection
- file selection
- scenario branch selection
- DLP outcome selection
- external recipient selection
- risk-event intensity
- baseline noise volume

Pseudocode:

```python
seed = "BF-MVP-1000-2026-05-24-v1"
rng = DeterministicRandom(seed)
```

---

## Data Structures

### Event Object

```json
{
  "EventId": "EVT-BF-20260518-000001",
  "TimeGenerated": "2026-05-18T13:05:00Z",
  "ScenarioId": "BASELINE-NORMAL",
  "CorrelationId": "CORR-BASELINE-20260518-001",
  "UserPrincipalName": "alexander.meyer@mhdemos.com",
  "PersonaName": "Alexander Meyer",
  "UserRole": "CEO",
  "Department": "Executive Leadership",
  "Workload": "Microsoft Copilot",
  "Operation": "CopilotInteraction",
  "SignalCategory": "AI Governance",
  "Severity": "Low",
  "RiskScore": 8,
  "IsRiskEvent": false,
  "IsSynthetic": true,
  "BusinessContext": "Executive summary preparation using approved board notes.",
  "FileName": "Board_Risk_Summary_BRD-FIC-2026-05_Final.pptx",
  "FileType": "pptx",
  "FilePath": "/sites/ExecutiveLeadership/Board Materials/Board_Risk_Summary_BRD-FIC-2026-05_Final.pptx",
  "SiteUrl": "https://mhdemos.sharepoint.com/sites/ExecutiveLeadership",
  "LibraryName": "Board Materials",
  "FileOwner": "alexander.meyer@mhdemos.com",
  "SensitivityLabel": "Highly Confidential",
  "PreviousSensitivityLabel": "",
  "Recipient": "",
  "TargetDomain": "",
  "DeviceId": "",
  "DeviceName": "",
  "AppName": "Microsoft Copilot",
  "PromptText": "Summarize the top three board risk themes from the approved summary.",
  "ResponsePreview": "The top themes are data exposure, AI governance, and external collaboration risk.",
  "PolicyName": "",
  "RuleName": "",
  "DlpAction": "",
  "OverrideJustification": "",
  "AdditionalProperties": {
    "PromptCategory": "ExecutiveSummary",
    "ApprovedSource": true
  }
}
```

---

## Pseudocode - Main Generator

```python
def generate_dataset(config_path: str, seed: str) -> GenerationResult:
    config = load_dataset_spec(config_path)
    platform = load_platform_configs()

    validate_source_configs(platform)

    rng = DeterministicRandom(seed)
    event_id_factory = EventIdFactory(prefix="EVT-BF")
    correlation_factory = CorrelationIdFactory()

    schedule = build_persona_schedule(
        personas=config.personas,
        time_window=config.time_window,
        daily_schedules=platform.daily_schedules,
        rng=rng
    )

    baseline_events = generate_baseline_noise(
        target_count=config.scenarios["BASELINE-NORMAL"].target_events,
        schedule=schedule,
        operation_distribution=config.operation_distribution,
        platform=platform,
        rng=rng
    )

    scenario_events = []
    for scenario in config.primary_scenarios:
        events = inject_scenario_timeline(
            scenario_id=scenario.scenario_id,
            target_count=scenario.target_events,
            schedule=schedule,
            platform=platform,
            rng=rng,
            correlation_id=correlation_factory.create(scenario.scenario_id)
        )
        scenario_events.extend(events)

    all_events = merge_and_sort_events(baseline_events, scenario_events)
    all_events = apply_risk_scoring(all_events, platform.risk_engine)
    all_events = normalize_events(all_events, platform.telemetry_schema)
    all_events = enforce_event_count_tolerance(all_events, config.event_count_tolerance, rng)
    all_events = run_synthetic_safety_filter(all_events, platform.pattern_library)

    validation_report = validate_generated_dataset(all_events, config, platform)
    scenario_summary = build_scenario_summary(all_events)
    replay_timeline = build_replay_timeline(all_events)

    write_jsonl(all_events, config.output.jsonl_path)
    write_csv(all_events, config.output.csv_path)
    write_json(validation_report, config.output.validation_report_path)
    write_json(scenario_summary, config.output.scenario_summary_path)
    write_json(replay_timeline, config.output.replay_timeline_path)

    return GenerationResult(
        events=all_events,
        validation_report=validation_report,
        scenario_summary=scenario_summary,
        replay_timeline=replay_timeline
    )
```

---

## Pseudocode - Baseline Noise Generator

```python
def generate_baseline_noise(target_count, schedule, operation_distribution, platform, rng):
    events = []

    while len(events) < target_count:
        persona = weighted_choice(platform.personas, weights="baseline_activity_weight", rng=rng)
        time_slot = schedule.pick_available_slot(persona, rng)
        operation = weighted_choice(operation_distribution.baseline_operations, rng=rng)
        workload = map_operation_to_workload(operation)

        event = create_event(
            scenario_id="BASELINE-NORMAL",
            correlation_id=create_baseline_correlation(time_slot.date),
            persona=persona,
            time_generated=apply_jitter(time_slot, rng),
            workload=workload,
            operation=operation,
            business_context=generate_baseline_context(persona, operation, rng),
            sensitivity_label=select_normal_label(persona, operation, rng),
            risk_score=calculate_baseline_risk(operation),
            is_risk_event=False
        )

        events.append(event)

    return events
```

---

## Pseudocode - Scenario Injector

```python
def inject_scenario_timeline(scenario_id, target_count, schedule, platform, rng, correlation_id):
    scenario = platform.scenarios.get(scenario_id)
    timeline_template = select_timeline_template(scenario_id, platform)
    events = []

    anchor_persona = scenario.primary_persona
    timeline_days = allocate_timeline_days(scenario, schedule, rng)

    for step in timeline_template.required_steps:
        persona = resolve_step_persona(step, scenario, platform, rng)
        timestamp = schedule_step_time(step, timeline_days, persona, rng)
        event = create_event_from_step(
            scenario=scenario,
            step=step,
            persona=persona,
            timestamp=timestamp,
            correlation_id=correlation_id,
            platform=platform,
            rng=rng
        )
        events.append(event)

    filler_events = generate_supporting_context_events(
        scenario=scenario,
        target_count=target_count - len(events),
        correlation_id=correlation_id,
        platform=platform,
        rng=rng
    )

    events.extend(filler_events)
    return sort_events(events)
```

---

## Pseudocode - Risk Scoring

```python
def apply_risk_scoring(events, risk_engine):
    for event in events:
        base_weight = risk_engine.get_base_weight(event.Operation)
        modifiers = risk_engine.find_applicable_modifiers(event)
        score = base_weight + sum(mod.scoreImpact for mod in modifiers)
        event.RiskScore = clamp(score, 0, 100)
        event.Severity = map_score_to_severity(event.RiskScore)
        event.IsRiskEvent = event.RiskScore >= 25 or event.Operation in risk_engine.always_risk_operations

    correlated_sequences = detect_composite_rules(events, risk_engine.compositeRules)
    for sequence in correlated_sequences:
        apply_composite_sequence_score(sequence, risk_engine)

    return events
```

---

## Pseudocode - Synthetic Safety Filter

```python
def run_synthetic_safety_filter(events, pattern_library):
    approved_prefixes = pattern_library.get_approved_prefixes()
    disallowed_patterns = load_disallowed_real_data_patterns()

    for event in events:
        text = serialize_event_text(event)

        if contains_secret_like_value(text):
            raise SafetyValidationError("Potential secret detected")

        if contains_realistic_financial_identifier_without_fictional_prefix(text):
            raise SafetyValidationError("Real-looking financial identifier detected")

        if contains_external_domain_not_in_allowlist(text):
            raise SafetyValidationError("External domain is not fake/test controlled")

        if contains_sensitive_like_value_without_approved_prefix(text):
            warn("Sensitive-like value does not use approved fictional prefix")

        event.IsSynthetic = True

    return events
```

---

## Pseudocode - CSV Exporter

```python
def write_csv(events, output_path):
    columns = [
        "EventId", "TimeGenerated", "ScenarioId", "CorrelationId",
        "UserPrincipalName", "PersonaName", "UserRole", "Department",
        "Workload", "Operation", "SignalCategory", "Severity",
        "RiskScore", "IsRiskEvent", "IsSynthetic", "BusinessContext",
        "FileName", "FileType", "FilePath", "SiteUrl", "LibraryName",
        "FileOwner", "SensitivityLabel", "PreviousSensitivityLabel",
        "Recipient", "TargetDomain", "DeviceId", "DeviceName",
        "AppName", "PromptText", "ResponsePreview", "PolicyName",
        "RuleName", "DlpAction", "OverrideJustification",
        "AdditionalPropertiesJson"
    ]

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = CsvWriter(f, columns)
        writer.write_header()
        for event in events:
            writer.write_row(flatten_event_for_csv(event))
```

---

## Scenario-Specific Generation Rules

## BF-SCEN-0002 - AML External AI Shortcut

Required operations:

```text
FileAccessed
FileDownloaded
AIAppInteraction
UnmanagedAppUpload
DLPPolicyMatch
TeamsMessageSent
```

Risk rules:

- AIAppInteraction with AML content should be High.
- UnmanagedAppUpload with AML content should be High.
- Follow-up Teams clarification should reduce final remediation severity but not erase evidence.

---

## BF-SCEN-0013 - Label Downgrade Before External Sharing

Required operations:

```text
SensitivityLabelChanged
LabelDowngrade
ExternalEmailSent
DLPWarned
DLPOverride or DLPBlocked
```

Risk rules:

- LabelDowngrade followed by external send inside 15 minutes should create high scenario confidence.
- DLPBlocked should produce remediation path.
- DLPOverride should produce coaching and review path.

---

## BF-SCEN-0030 - Devon Multi-Day Risk Chain

Required operations:

```text
FileDownloaded
AIAppInteraction
DLPPolicyMatch
DLPOverride
FilePrinted
FileCopiedToNetworkShare
HRSignal
InsiderRiskSequence
```

Risk rules:

- Events should span five business days.
- Devon should have normal activity mixed with risky activity.
- HRSignal should appear as context, not proof of intent.
- Investigation events should use neutral language.

---

## Validation Report Structure

```json
{
  "validationRunId": "VAL-FIC-2026-0001",
  "datasetName": "banking-finance-e5-mvp-synthetic-telemetry-1000",
  "seed": "BF-MVP-1000-2026-05-24-v1",
  "status": "passed",
  "eventCount": 1000,
  "validatedAt": "2026-05-24T18:00:00Z",
  "scenarioCounts": {},
  "personaCounts": {},
  "operationCounts": {},
  "riskDistribution": {},
  "errors": [],
  "warnings": []
}
```

---

## Performance Expectations

For the MVP dataset:

```text
Target events: 1,000
Generation time: under 10 seconds in a local script
JSONL size: small enough for simple ADX ingestion
CSV size: small enough for Power BI import mode
Validation time: under 10 seconds
```

For larger datasets, optimize by:

- streaming JSONL writes
- avoiding large in-memory dynamic objects
- batching validation
- precomputing distribution tables
- using deterministic ID factories

---

## Implementation Order

Recommended build order:

1. Create static persona catalog.
2. Create static operation catalog.
3. Generate baseline events.
4. Generate BF-SCEN-0002.
5. Generate BF-SCEN-0013.
6. Generate BF-SCEN-0030.
7. Add risk scoring.
8. Add JSONL export.
9. Add CSV export.
10. Add validation report.
11. Add scenario summary.
12. Add replay timeline export.
13. Add CI validation.

---

## Codex Usage Guidance

Codex should use this file to:

1. Generate the first dataset generator implementation.
2. Create deterministic event factories.
3. Generate JSONL and CSV exports.
4. Add safety filters.
5. Add validation reports.
6. Create Power BI-ready datasets.
7. Prepare ADX ingestion batches.
8. Preserve scenario realism.
9. Preserve Devon ambiguity.
10. Preserve synthetic-only boundaries.

---

## Safety Reminder

The generator must never use real Microsoft 365 production logs, real users, real customers, real HR records, real legal matters, real financial transactions, real credentials, real secrets, or real incident data.

All generated outputs must remain fictional and synthetic.
