## ADDED Requirements

### Requirement: Decision artifacts are persisted
The system SHALL persist LLM decision proposals, policy-gate results, merge records, and final decision summaries as run artifacts.

#### Scenario: Decision artifacts are written
- **WHEN** an agent decision loop runs
- **THEN** the run directory SHALL contain decision artifacts linking prompts, LLM responses, tool results, memory citations, MCP calls, policy gates, and final outputs.

#### Scenario: Redaction is applied
- **WHEN** decision artifacts include provider metadata, prompts, environment-derived settings, or raw diagnostics
- **THEN** the system SHALL redact configured secrets before writing artifacts.

### Requirement: Message bus records decision lifecycle
The system SHALL publish message bus events for LLM proposal creation, schema validation, policy gate evaluation, tool dispatch, merge results, and fallback use.

#### Scenario: Decision lifecycle is replayable
- **WHEN** the message log is replayed
- **THEN** the replay summary SHALL show role-level decision proposals, accepted/denied gates, final decision sources, and fallback reasons.

### Requirement: Reports explain LLM influence
The system SHALL include LLM decision influence in JSON and Markdown reports.

#### Scenario: Report includes decision source
- **WHEN** a finding or verification decision appears in the report
- **THEN** the report SHALL include decision source, LLM confidence when applicable, policy-gate outcome, and evidence references.

#### Scenario: Report distinguishes contextual intelligence
- **WHEN** CVE MCP or memory context influenced an LLM decision
- **THEN** the report SHALL show it as contextual intelligence unless local evidence also supports the finding.

### Requirement: Default tests remain offline and deterministic
The system SHALL keep default unit tests independent of real model APIs while covering the LLM decision loop through mock responses.

#### Scenario: Default test suite runs without API keys
- **WHEN** the default unit test command runs without model credentials
- **THEN** mock LLM decision tests SHALL run deterministically and live LLM tests SHALL skip.

#### Scenario: Live LLM decision smoke is opt-in
- **WHEN** live integration is explicitly enabled and `LLM_MODEL` is configured
- **THEN** the system SHALL run a bounded live LLM decision smoke and persist redacted evidence artifacts.
