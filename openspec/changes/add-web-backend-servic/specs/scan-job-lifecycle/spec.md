## ADDED Requirements

### Requirement: Scan jobs have explicit lifecycle state
The system SHALL track each web-created scan job with a stable job ID, target, status, timestamps, output directory, run directory, summary, and error details.

#### Scenario: Job is queued
- **WHEN** a valid scan request is accepted
- **THEN** the job SHALL be stored with status `queued`, a stable `job_id`, the requested target, and a creation timestamp.

#### Scenario: Job is running
- **WHEN** the background runner starts executing the accepted scan
- **THEN** the job SHALL transition to `running` and record a start timestamp.

#### Scenario: Job succeeds
- **WHEN** `run_audit()` completes successfully
- **THEN** the job SHALL transition to `succeeded`, store the returned summary, store `run_dir`, and record a finish timestamp.

#### Scenario: Job fails
- **WHEN** scan execution raises an unrecoverable exception before producing a successful summary
- **THEN** the job SHALL transition to `failed`, record a finish timestamp, and expose a sanitized error message through the status API.

### Requirement: Scan jobs delegate to AgentRuntime through compatibility boundary
The system SHALL execute web-created scans through the existing `run_audit(target, config, output_dir)` compatibility boundary.

#### Scenario: Web scan uses runtime kernel
- **WHEN** a web scan starts
- **THEN** the runner SHALL build an `AuditConfig` from the request, call `run_audit()`, and rely on `AgentRuntime` to create run artifacts.

#### Scenario: Web scan supports mock default
- **WHEN** a client creates a scan job without real model settings
- **THEN** the backend SHALL be able to run with mock LLM configuration and local fixtures without requiring API keys.

#### Scenario: Web scan supports guarded decisions
- **WHEN** a client creates a scan job with `llm_decisions` enabled
- **THEN** the runner SHALL set runtime and LLM decision configuration consistently with the existing CLI flags.

### Requirement: Background execution is bounded
The system SHALL run scan jobs outside the HTTP request handler using a bounded local executor.

#### Scenario: Create request returns before scan completes
- **WHEN** a client creates a scan job
- **THEN** the HTTP response SHALL return after enqueueing the job and SHALL NOT wait for full audit completion.

#### Scenario: Concurrent scan limit
- **WHEN** multiple scan jobs are submitted
- **THEN** the backend SHALL execute them through a configured bounded executor to avoid unbounded concurrent LLM, MCP, or filesystem work.

### Requirement: Job metadata is inspectable
The system SHALL make job metadata available through the API for both in-progress and completed scans.

#### Scenario: Poll running job
- **WHEN** a client polls a running job
- **THEN** the backend SHALL return the latest known lifecycle status even if the final runtime state has not been written yet.

#### Scenario: Poll completed job
- **WHEN** a client polls a completed job
- **THEN** the backend SHALL return final summary fields such as candidate count, rejected count, validated count, validation distribution, and runtime state reference when available.
