## ADDED Requirements

### Requirement: Single audit runs emit a stable resource summary
Every terminal single-project audit SHALL emit schema-versioned `run-resource-summary.v1` containing target/run identity, scanned files/bytes, wall-clock elapsed seconds, stage timing, final status counts, LLM request/token totals, tool calls, Docker starts/results, repair attempts, timeouts, effective budget consumption, accounting gaps, and contributing artifact refs.

#### Scenario: Resource evidence is available
- **WHEN** a run reaches a terminal state with openable contributing artifacts
- **THEN** the summary SHALL contain normalized numeric totals and refs that agree with runtime/report identity.

#### Scenario: Resource evidence is unavailable
- **WHEN** a value cannot be derived
- **THEN** it SHALL be null with a machine-readable accounting-gap reason and SHALL not default to zero.

### Requirement: Resource summaries and child configuration remain secret-safe
The system MUST NOT persist API-key values, credential-bearing URLs, secret-derived hashes, or secret-bearing command arguments in resource summaries, effective child configuration, logs, reports, or replay.

#### Scenario: Real provider is configured
- **WHEN** a run uses a configured API key
- **THEN** persisted configuration SHALL record only the environment-variable name and non-secret provider/model metadata.

#### Scenario: Captured process output contains a configured secret
- **WHEN** stdout or stderr includes a configured credential value or credential-shaped literal
- **THEN** bounded persisted output and downstream artifacts SHALL contain only the redacted form.
