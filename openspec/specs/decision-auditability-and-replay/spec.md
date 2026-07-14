# decision-auditability-and-replay Specification

## Purpose
TBD - created by archiving change enable-llm-agent-decision-loop. Update Purpose after archive.
## Requirements
### Requirement: Decision artifacts are persisted
The system SHALL persist LLM decision proposals, graph mutation proposals, policy-gate results, merge and commit records, graph revisions, and final decision and execution summaries as run artifacts.

#### Scenario: Decision artifacts are written
- **WHEN** an agent decision loop or graph replanning checkpoint runs
- **THEN** the run directory SHALL contain artifacts linking prompts, LLM responses, tool results, memory citations, MCP calls, graph mutation operations, policy gates, committed or rejected revisions, and final outputs.

#### Scenario: Initial and final graphs are written
- **WHEN** graph-mode execution starts and reaches a terminal state
- **THEN** the runtime SHALL persist immutable refs for the initial graph, every committed revision, node transitions, actual execution path, and final graph summary.

#### Scenario: Redaction is applied
- **WHEN** decision or graph artifacts include provider metadata, prompts, environment-derived settings, raw diagnostics, or node outputs
- **THEN** the system SHALL redact configured secrets before writing artifacts.

### Requirement: Message bus records decision lifecycle
The system SHALL publish message bus events for LLM proposal creation, schema validation, policy gate evaluation, graph creation, node lifecycle transitions, graph mutation proposal and commit outcomes, tool dispatch, merge results, and fallback use.

#### Scenario: Decision lifecycle is replayable
- **WHEN** the message log is replayed
- **THEN** the replay summary SHALL show role-level decision proposals, accepted or denied gates, graph revision changes, node statuses, actual branch order, final decision sources, and fallback reasons.

#### Scenario: Mutation causation is traceable
- **WHEN** a committed mutation causes an optional node or refinement path to execute
- **THEN** graph, task, message, and artifact records SHALL correlate that node with the checkpoint, proposal, policy result, committed revision, and upstream evidence that caused it.

### Requirement: Reports explain LLM influence
The system SHALL include LLM decision influence and adaptive execution influence in JSON and Markdown reports.

#### Scenario: Report includes decision source
- **WHEN** a finding or verification decision appears in the report
- **THEN** the report SHALL include decision source, LLM confidence when applicable, policy-gate outcome, evidence references, and relevant graph node and revision refs.

#### Scenario: Report summarizes adaptive execution
- **WHEN** graph mode is used
- **THEN** the report SHALL identify graph mode, template and schema versions, committed and denied mutation counts, replanning count, actual execution path summary, fallback reason when applicable, and final graph artifact ref.

#### Scenario: Report distinguishes contextual intelligence
- **WHEN** CVE MCP or memory context influenced an LLM decision or graph mutation
- **THEN** the report SHALL show it as contextual intelligence unless local evidence also supports the finding.

### Requirement: Graph replay has no execution side effects
The system SHALL reconstruct graph revisions, policy outcomes, node lifecycles, skipped branches, retries, fallbacks, and the actual execution path from persisted state and events without re-executing agents or runtime services.

#### Scenario: Reviewer replays a completed graph run
- **WHEN** replay is requested for a run with valid graph artifacts and messages
- **THEN** replay SHALL produce the same normalized graph revision order and actual node path without calling an LLM, MCP server, tool, Docker runner, verification harness, or target repository operation.

#### Scenario: Replay data is incomplete
- **WHEN** graph artifacts or transitions are missing, redacted, or inconsistent
- **THEN** replay SHALL mark the affected segment incomplete, report the missing refs, and SHALL NOT invent or re-execute the missing behavior.

### Requirement: Default tests remain offline and deterministic
The system SHALL keep default unit tests independent of real model APIs while covering the LLM decision loop through mock responses.

#### Scenario: Default test suite runs without API keys
- **WHEN** the default unit test command runs without model credentials
- **THEN** mock LLM decision tests SHALL run deterministically and live LLM tests SHALL skip.

#### Scenario: Live LLM decision smoke is opt-in
- **WHEN** live integration is explicitly enabled and `LLM_MODEL` is configured
- **THEN** the system SHALL run a bounded live LLM decision smoke and persist redacted evidence artifacts.
