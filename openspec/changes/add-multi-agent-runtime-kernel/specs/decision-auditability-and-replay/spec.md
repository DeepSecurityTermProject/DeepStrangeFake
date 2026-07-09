## MODIFIED Requirements

### Requirement: Decision artifacts are persisted
The system SHALL persist LLM decision proposals, policy-gate results, merge records, final decision summaries, and runtime task-state links as run artifacts through `ArtifactStore`.

#### Scenario: Decision artifacts are written
- **WHEN** an agent decision loop runs inside `AgentRuntime`
- **THEN** the run directory SHALL contain decision artifacts linking prompts, LLM responses, tool results, memory citations, MCP calls, policy gates, runtime task state, and final outputs.

#### Scenario: Redaction is applied
- **WHEN** decision artifacts include provider metadata, prompts, environment-derived settings, runtime diagnostics, or raw service outputs
- **THEN** the system SHALL redact configured secrets before writing artifacts.

### Requirement: Message bus records decision lifecycle
The system SHALL publish message bus events for LLM proposal creation, schema validation, policy gate evaluation, tool dispatch, merge results, fallback use, and runtime task transitions.

#### Scenario: Decision lifecycle is replayable
- **WHEN** the message log is replayed
- **THEN** the replay summary SHALL show role-level decision proposals, accepted/denied gates, final decision sources, runtime task statuses, and fallback reasons.

### Requirement: Reports explain LLM influence
The system SHALL include LLM decision influence and runtime task provenance in JSON and Markdown reports.

#### Scenario: Report includes decision source
- **WHEN** a finding or verification decision appears in the report
- **THEN** the report SHALL include decision source, LLM confidence when applicable, policy-gate outcome, evidence references, and runtime task or artifact refs.

#### Scenario: Report distinguishes contextual intelligence
- **WHEN** CVE MCP or memory context influenced an LLM decision
- **THEN** the report SHALL show it as contextual intelligence unless local evidence also supports the finding.
