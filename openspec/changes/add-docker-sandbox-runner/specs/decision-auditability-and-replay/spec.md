## ADDED Requirements

### Requirement: Sandbox runner metadata is auditable
The system SHALL persist sandbox runner metadata for each PoC execution attempt so reports and replay can distinguish local and Docker-backed validation.

#### Scenario: Docker attempt is persisted
- **WHEN** a PoC is executed through Docker runner
- **THEN** the persisted `SandboxRunResult` SHALL include `environment.runner` or equivalent value set to `docker`, the Docker image, Docker binary, effective Docker context or host when configured, container execution status, and the normalized command argv.

#### Scenario: Local attempt is persisted
- **WHEN** a PoC is executed through local runner
- **THEN** the persisted `SandboxRunResult` SHALL continue to identify local execution and preserve existing stdout/stderr, argv, exit code, timeout, and artifact refs.

### Requirement: Docker security policy is recorded
The system SHALL record the effective Docker sandbox policy used for each Docker-backed attempt.

#### Scenario: Docker policy is written
- **WHEN** Docker runner persists a sandbox run result
- **THEN** the result SHALL include network mode, effective Docker context or host when configured, read-only root filesystem setting, capability policy, no-new-privileges setting, resource limits, mount policy, and privileged mode denial state.

#### Scenario: Policy blocks execution
- **WHEN** Docker runner denies execution because requested configuration or PoC argv violates sandbox policy
- **THEN** the reportable validation evidence SHALL include the policy-denied reason and SHALL classify the candidate as `manual-required` unless other machine evidence rejects it.

### Requirement: Reports expose Docker verification evidence
The system SHALL expose Docker-backed verification evidence in JSON and Markdown reports without treating Docker execution alone as confirmation.

#### Scenario: Report includes Docker runner details
- **WHEN** a finding has a Docker-backed validation attempt
- **THEN** the report SHALL include runner type, Docker image, exit code, timeout state, stdout/stderr previews, sandbox result refs, attempt refs, and Judge reason.

#### Scenario: Docker failure appears in report
- **WHEN** Docker execution is unavailable, image-missing, policy-denied, timed out, or fails before producing Judge-readable evidence
- **THEN** the report SHALL show `manual-required` with the blocking reason and evidence refs instead of hiding the candidate.

#### Scenario: Missing structured evidence appears in report
- **WHEN** a Docker-backed PoC exits successfully but lacks required structured evidence such as `sqli-result.json`
- **THEN** the report SHALL show that missing evidence reason and SHALL NOT count the candidate as confirmed.

### Requirement: Replay summarizes Docker runner lifecycle
The system SHALL make Docker sandbox lifecycle information available to runtime replay and detail inspection.

#### Scenario: Replay includes Docker attempt summary
- **WHEN** a run with Docker-backed validation is replayed
- **THEN** the replay summary SHALL expose Docker attempt counts, statuses, runner type, image, policy-denied events, environment failures, and confirmed/rejected/manual-required outcomes.

#### Scenario: Runtime detail can open artifacts
- **WHEN** a Web or CLI user inspects a Docker-backed run
- **THEN** referenced `SandboxRunResult`, stdout, stderr, PoC metadata, verification attempt, and structured evidence artifact paths SHALL be openable from the run directory.
