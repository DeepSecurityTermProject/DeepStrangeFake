## ADDED Requirements

### Requirement: Full DataflowTrace records are persisted as artifacts
The system SHALL persist complete dataflow traces as immutable run artifacts rather than storing the full trace only inside `Finding.metadata`.

#### Scenario: Dataflow trace supports a finding
- **WHEN** a scanner trace contributes to a candidate finding
- **THEN** the runtime SHALL write the complete `DataflowTrace` JSON under the run directory and record a stable artifact reference.

#### Scenario: Finding references dataflow evidence compactly
- **WHEN** a finding is created from a dataflow trace
- **THEN** the finding SHALL store a compact call path and summary metadata, plus trace IDs or artifact refs, without embedding the full trace payload.

### Requirement: EvidenceChain references dataflow trace artifacts
The system SHALL link validated findings to their full dataflow trace artifacts through EvidenceChain.

#### Scenario: Finding is validated from complete flow
- **WHEN** Verification accepts a candidate supported by a complete source-to-sink trace
- **THEN** the EvidenceChain SHALL include source locations, sink location, sanitizer status, trace artifact refs, tool result refs, verifier decision, and validation result.

#### Scenario: Trace includes multiple source locations
- **WHEN** a trace includes source, propagation, sanitizer, and sink steps across one or more source lines
- **THEN** the EvidenceChain SHALL preserve those relevant source locations or reference the trace artifact that contains them.

#### Scenario: Evidence artifact is regenerated
- **WHEN** reporting or replay reads an existing completed run
- **THEN** the system SHALL read existing dataflow trace artifacts and SHALL NOT overwrite them in place.

### Requirement: Reports expose source-to-sink evidence
The system SHALL make dataflow evidence reviewable in JSON and Markdown reports.

#### Scenario: JSON report includes dataflow refs
- **WHEN** a reported finding has dataflow evidence
- **THEN** the JSON report SHALL include trace artifact refs, compact call path, source location, sink location, sanitizer status, rule IDs, and confidence.

#### Scenario: Markdown report includes readable summary
- **WHEN** a reported finding has dataflow evidence
- **THEN** the Markdown report SHALL include a concise Dataflow Evidence section showing source, sink, sanitizer status, and trace artifact reference.

#### Scenario: Sanitized flow is not over-reported
- **WHEN** a trace is marked sanitized or blocked
- **THEN** the report SHALL distinguish it from accepted vulnerabilities unless policy explicitly includes informational observations.
