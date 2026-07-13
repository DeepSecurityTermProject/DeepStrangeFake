## ADDED Requirements

### Requirement: Benchmark JSON is complete and machine-comparable
The system SHALL generate schema-versioned benchmark JSON containing run identity, engine/environment provenance, reuse/protocol fingerprints, declared comparison dimensions, corpus/config identity, every case status, normalized counts, truth matches, metrics, resources, failures, and refs.

#### Scenario: Benchmark output is generated
- **WHEN** selected cases reach terminal states
- **THEN** JSON SHALL include completed, failed, timed-out, and not-run cases without fabricated zeroes.

#### Scenario: Markdown is generated
- **WHEN** benchmark JSON validates
- **THEN** Markdown SHALL be rendered solely from that JSON and remain consistent with completion, effectiveness, coverage, resource, and failure values.

### Requirement: Resource accounting consumes the stable single-run contract
Each case result SHALL derive coverage, timing, LLM, tool, Docker, repair, timeout, budget, and status accounting from validated `run-resource-summary.v1` plus report/runtime identity artifacts.

#### Scenario: Resource summary is valid
- **WHEN** the resource summary and contributing refs agree with the case
- **THEN** values and refs, including actual wall-clock `elapsed_seconds`, SHALL be normalized into the benchmark case result and available to duration comparison gates.

#### Scenario: Accounting is missing or inconsistent
- **WHEN** a field or required summary cannot be validated
- **THEN** the field SHALL be null with an accounting-gap reason and SHALL block promotion when required by the pilot gate.

### Requirement: Baseline comparison separates protocol compatibility from experiment dimensions
The system SHALL compare runs only when `comparison_protocol_fingerprint` matches and all differences are included in declared `comparison_dimensions`.

#### Scenario: Engine revision is the declared dimension
- **WHEN** corpus/truth/commits/scope/matcher/metrics/safety/protocol match and only engine identity differs
- **THEN** comparison SHALL proceed and report engine identity as the experiment axis.

#### Scenario: Undeclared provider or scope differs
- **WHEN** a non-declared field differs
- **THEN** comparison SHALL fail with explicit mismatch fields.

#### Scenario: Human adjudication content differs
- **WHEN** two reports use different canonical adjudication content
- **THEN** their final comparison protocol fingerprints SHALL differ even when the underlying completed scan is reusable, and direct comparison SHALL fail as incompatible.

### Requirement: Comparison gates are explicit
The system SHALL support gates over hard execution invariants and selected metric/resource deltas.

#### Scenario: False completion occurs
- **WHEN** a case is completed without acquisition, commit, coverage, runtime-state, report, and resource proof
- **THEN** comparison SHALL fail regardless of finding counts.

#### Scenario: Safe negative is falsely confirmed
- **WHEN** an eligible negative case has an adjudicated or truth-supported false confirmed finding
- **THEN** the configured negative gate SHALL fail with case/finding IDs.

### Requirement: CI uses a deterministic local fixture corpus
Normal GitHub Actions CI SHALL run a bounded local fixture profile whose benchmark invocation disables clone/fetch, real credentials, and any implicit Docker requirement.

#### Scenario: Pull-request CI runs
- **WHEN** the fixture workflow executes
- **THEN** it SHALL enforce a documented timeout and test schema, state, cleanup doubles, resume, matching, metrics, rendering, secret redaction, and false completion.

### Requirement: Pilot execution is explicit and review-gated
The 3-5 project pilot SHALL require explicit cache/network/provider/Docker/safety configuration and reviewed project/commit/license/truth/scope metadata.

#### Scenario: Pilot is promoted
- **WHEN** every pilot project completes with required accounting, truth, support eligibility, cleanup, and review
- **THEN** the run MAY become a pilot baseline and full-profile readiness MAY be emitted.

#### Scenario: Pilot is partial or unreviewed
- **WHEN** a required case or review gate is missing
- **THEN** promotion SHALL fail with blocking IDs and reasons.

### Requirement: Full-corpus execution is a follow-up change
This change SHALL define full-profile schema/readiness but SHALL NOT claim that the at-least-20-project corpus has been selected, executed, or promoted.

#### Scenario: Pilot baseline exists
- **WHEN** the pilot is promoted and readiness evidence validates
- **THEN** a follow-up `run-locked-20-project-benchmark` change MAY select at least 20 unique eligible projects and execute the full corpus.

#### Scenario: Placeholder full profile is reported as complete
- **WHEN** placeholders, duplicate revisions, unsupported cases, or unexecuted entries are used to claim 20-project completion
- **THEN** validation/promotion SHALL fail.

### Requirement: Only complete compatible runs become baselines
Baseline promotion SHALL reject incomplete, partial, incompatible, unreviewed, cleanup-failed, or required-accounting-incomplete runs.

#### Scenario: Ineligible run is offered as baseline
- **WHEN** any required gate fails
- **THEN** promotion SHALL fail with the exact blocking case/field/reason.
