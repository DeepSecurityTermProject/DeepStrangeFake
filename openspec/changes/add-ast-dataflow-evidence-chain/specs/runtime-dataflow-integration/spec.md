## ADDED Requirements

### Requirement: Runtime exposes dataflow scanner as a declared tool
The system SHALL register a `dataflow-scan` tool in the default tool registry.

#### Scenario: Tool registry is built
- **WHEN** the default tool registry is created
- **THEN** it SHALL declare `dataflow-scan` with `static-scan` permission, read-only safety classification, and structured input schema.

#### Scenario: Analysis agent dispatches dataflow scan
- **WHEN** an audit run reaches the analysis tool phase
- **THEN** the runtime SHALL dispatch `dataflow-scan` through ToolBroker/ToolRuntime and persist its normalized result.

#### Scenario: Dataflow scanner is unavailable or degraded
- **WHEN** parser dependencies are missing, a parser fails, or a budget limit is reached
- **THEN** the runtime SHALL continue with available evidence and pattern-scan fallback.

#### Scenario: Dataflow scan budget arguments are supplied
- **WHEN** a caller dispatches `dataflow-scan` with `max_files` or `max_traces`
- **THEN** the scanner SHALL apply those values to file and trace selection for that call.
- **AND** the normalized tool result inputs SHALL report the effective budget values.

### Requirement: Analysis prefers structured dataflow observations
The Analysis agent SHALL convert structured dataflow observations into candidate findings with richer evidence than pattern-only observations.

#### Scenario: Complete flow observation is received
- **WHEN** Analysis receives a `complete-flow` dataflow observation for a configured vulnerability class
- **THEN** it SHALL create a candidate finding with source location, sink location, compact call path, trace artifact refs, tool refs, and confidence rationale.

#### Scenario: Pattern and dataflow overlap
- **WHEN** `pattern-scan` and `dataflow-scan` report the same sink location
- **THEN** Analysis SHALL prefer the dataflow-backed candidate and avoid duplicate findings where a stable trace ID or location match identifies overlap.

#### Scenario: Sanitized flow is received
- **WHEN** Analysis receives a sanitized or blocked dataflow trace
- **THEN** it SHALL either omit the vulnerability candidate or mark the observation as lower-risk according to configured policy.

### Requirement: Verification reasons about dataflow evidence quality
The Verification agent SHALL use dataflow status when accepting, rejecting, or downgrading candidate findings.

#### Scenario: Complete local evidence exists
- **WHEN** a candidate has local source, sink, and unsanitized flow evidence
- **THEN** Verification MAY accept it at higher confidence than pattern-only evidence.

#### Scenario: Sanitizer evidence exists
- **WHEN** a candidate has a recognized sanitizer or blocking guard between source and sink
- **THEN** Verification SHALL reject or downgrade the finding unless other local evidence contradicts the sanitizer.

#### Scenario: Only contextual evidence exists
- **WHEN** a candidate has CVE, memory, or LLM context but lacks local dataflow or source evidence
- **THEN** Verification SHALL continue to reject it as unsupported local evidence.

### Requirement: Runtime and replay preserve dataflow traceability
The system SHALL include dataflow tool calls, trace artifacts, and evidence references in runtime state and replay summaries.

#### Scenario: Runtime state is written
- **WHEN** a dataflow scan runs during an audit
- **THEN** runtime state SHALL include the dataflow tool task, artifact refs, status, and fallback/degraded reason when applicable.

#### Scenario: Replay summary is generated
- **WHEN** a run message log is replayed
- **THEN** the summary SHALL allow reviewers to see that dataflow scanning contributed tool results and artifacts to findings.
