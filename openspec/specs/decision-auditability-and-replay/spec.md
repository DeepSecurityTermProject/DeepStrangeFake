# decision-auditability-and-replay Specification

## Purpose
TBD - created by archiving change enable-llm-agent-decision-loop. Update Purpose after archive.
## Requirements
### Requirement: Decision artifacts are persisted
The system SHALL persist LLM request lifecycle events, received responses, decision proposals, graph mutation proposals, policy-gate results, merge and commit records, graph revisions, final decisions, execution summaries, and resource-accounting reconciliation as run artifacts.

#### Scenario: Decision artifacts are written
- **WHEN** an agent decision loop, graph replanning checkpoint, or LLM PoC repair runs
- **THEN** the run directory SHALL contain artifacts linking request groups, provider attempts, prompts, received LLM responses or provider errors, schema outcomes, tool results, memory citations, MCP calls, graph mutation operations, policy gates, committed or rejected revisions, fallbacks, and final outputs.

#### Scenario: Initial and final graphs are written
- **WHEN** graph-mode execution starts and reaches a terminal state
- **THEN** the runtime SHALL persist immutable refs for the initial graph, every committed revision, node transitions, actual execution path, and final graph summary.

#### Scenario: Redaction is applied
- **WHEN** decision, LLM lifecycle, error, response, graph, or resource artifacts include provider metadata, prompts, environment-derived settings, raw diagnostics, or node outputs
- **THEN** the system SHALL redact configured secrets before writing artifacts and SHALL not persist authorization headers, credential-bearing URLs, raw secret environment values, or secret-derived hashes.

### Requirement: Message bus records decision lifecycle
The system SHALL publish correlated message bus events for LLM request start, provider dispatch and outcome, schema validation, policy gate evaluation, fallback use, request terminalization, graph creation, node lifecycle transitions, graph mutation proposal and commit outcomes, tool dispatch, and merge results.

#### Scenario: Decision lifecycle is replayable
- **WHEN** the message log and referenced artifacts are replayed
- **THEN** the replay summary SHALL show request groups, provider attempts and retries, role-level proposals, schema outcomes, accepted or denied gates, graph revision changes, node statuses, actual branch order, final decision sources, terminal statuses, and fallback reasons without calling a provider.

#### Scenario: Mutation causation is traceable
- **WHEN** a committed mutation causes an optional node or refinement path to execute
- **THEN** graph, task, message, lifecycle, and artifact records SHALL correlate that node with the checkpoint request group, provider attempt and response, proposal, policy result, committed revision, and upstream evidence that caused it.

#### Scenario: Lifecycle event is missing during replay
- **WHEN** a request group has missing, duplicate, corrupt, or inconsistent events or refs
- **THEN** replay SHALL mark the affected request group incomplete, report stable gap IDs, and SHALL NOT invoke an LLM or invent the missing transition.

### Requirement: LLM resource accounting is replayable and integrity checked
Every terminal audit run SHALL include schema-versioned LLM accounting derived from reconciled request lifecycle evidence and SHALL expose ledger presence, accounting source, dispatched request groups, physical provider attempts, retries, terminal-status counts, provider-reported tokens, gap IDs, and contributing refs.

#### Scenario: All lifecycle evidence agrees
- **WHEN** request events, response and error refs, decision records, and budget counters reconcile
- **THEN** `run-resource-summary.v1` SHALL expose complete numeric totals and a complete reconciliation status traceable to immutable refs.

#### Scenario: Only token accounting is incomplete
- **WHEN** dispatch counts are exact but one or more provider attempts have unknown usage
- **THEN** the summary SHALL retain exact request and provider-attempt counts, set token totals to null, and identify only the token-accounting gaps.

#### Scenario: Artifact presence disagrees with lifecycle evidence
- **WHEN** response files exist without correlated response events or lifecycle events reference missing response files
- **THEN** the summary SHALL mark reconciliation incomplete and SHALL NOT infer completeness from file count.

#### Scenario: LLM is disabled for the run
- **WHEN** no LLM request is enabled or initiated
- **THEN** the summary SHALL report complete zero LLM usage with no fabricated lifecycle events.

### Requirement: Legacy LLM accounting is explicitly limited
Replay and resource readers SHALL identify runs without an LLM lifecycle ledger as legacy and SHALL not claim knowledge of schema-invalid, policy-denied, provider-failed, timed-out, or omitted requests.

#### Scenario: Legacy run is opened
- **WHEN** a reviewer opens a run containing old LLM response artifacts but no lifecycle ledger
- **THEN** replay SHALL expose legacy artifact-derived evidence separately, mark lifecycle completeness unavailable, and remain side-effect free.

#### Scenario: Legacy run lacks LLM artifacts
- **WHEN** a legacy run has no response artifacts and its historical LLM enablement cannot be proven
- **THEN** the reader SHALL report unknown historical LLM accounting rather than assuming the run used zero requests.

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
