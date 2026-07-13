## ADDED Requirements

### Requirement: PoC repair lifecycle artifacts are complete
The system SHALL persist every PoC repair lifecycle decision as openable, immutable run artifacts linked to the finding and verification attempt.

#### Scenario: Repair attempt is recorded
- **WHEN** the system classifies or repairs a failed PoC
- **THEN** artifacts SHALL include failure class and evidence refs, redacted prompt and normalized response refs, diagnosis, normalized typed edits and edit hash, change list, prior and new script hashes, repair-manifest ref, immutable-envelope ref, semantic-integrity result, safety result, sandbox result, stdout/stderr refs, provisional and final Judge outcome, and stop reason.

#### Scenario: Repair is not invoked
- **WHEN** policy, infrastructure, semantic rejection, unsupported generation, or configuration prevents repair
- **THEN** the artifacts SHALL record the non-invocation reason and SHALL not fabricate prompt, response, or repaired-script refs.

#### Scenario: Secrets occur in repair evidence
- **WHEN** prompts, responses, assembled scripts, stdout, stderr, source snippets, or provider diagnostics contain configured secret values or credential-shaped hard-coded literals
- **THEN** model-facing context and all standard persisted summaries SHALL be redacted, and raw provider payloads SHALL NOT be referenced from reports, replay, or existing Web data.

### Requirement: Message replay explains repair state transitions
The system SHALL publish enough message-bus events to reconstruct the bounded PoC repair state machine.

#### Scenario: Repair loop is replayed
- **WHEN** replay summary is generated for a run with repaired PoCs
- **THEN** it SHALL show PoC classification, repair request/response, exact-contract result, normalized edit hash, assembled script hash, semantic-integrity decision, safety decision, runner start/result, provisional Judge result, target-integrity finalization, attempt count, and final stop reason in order.

#### Scenario: Unsafe script is blocked
- **WHEN** exact-contract, semantic-integrity, or safety policy denies a repair response
- **THEN** replay SHALL show the denial stage and rule IDs and SHALL show no container-start event for that edit or script hash.

### Requirement: Reports expose every PoC repair attempt
The system SHALL include repair summaries and evidence links for all verification candidates in JSON and Markdown reports, including non-confirmed candidates.

#### Scenario: Finding has multiple attempts
- **WHEN** a candidate uses one or more repair attempts
- **THEN** its report entry SHALL show each attempt index, failure class, diagnosis, normalized change summary, edit and script hashes, semantic-integrity and safety status, runner type, exit code, stdout/stderr summary, Judge reason, artifact refs, and final stop reason.

#### Scenario: Missing structured evidence blocks confirmation
- **WHEN** a repaired script exits successfully but omits required structured evidence
- **THEN** the report SHALL show `missing-evidence`, SHALL NOT increment `confirmed_count`, and SHALL link the Judge and sandbox records.

#### Scenario: Target integrity is reported
- **WHEN** verification completes
- **THEN** the report SHALL reference the run-level before/after target manifests, list changed/added/removed counts, and distinguish provisional Judge outcomes from final integrity-gated statuses.

### Requirement: Existing Web surfaces expose compact repair summaries without raw artifact access
The backend and existing Web run-detail data SHALL expose compact repair status summaries without adding a generic host-file or run-artifact read endpoint in this change.

#### Scenario: Web displays repair summary
- **WHEN** a completed run contains PoC repair attempts
- **THEN** existing run-detail data SHALL show final status, repair attempt count, high-signal classifications, semantic/safety outcome, and final stop reason without returning prompt, response, or executable script contents.

#### Scenario: Client requests raw repair artifact content
- **WHEN** a Web client attempts to use existing APIs to read a repair prompt, response, or executable script by path
- **THEN** the backend SHALL not add or infer a generic artifact-read capability and SHALL return no host file content from this change.

### Requirement: Repair tests remain reproducible
The system SHALL keep default repair tests offline and deterministic while providing opt-in live LLM and Docker smoke coverage.

#### Scenario: Default suite tests repair
- **WHEN** the default test suite runs without API keys or a Docker daemon
- **THEN** mock LLM and fake-runner tests SHALL verify classification, exact typed-edit validation, protected semantic hashes, forged-evidence denial, safety denial, duplicate stopping, terminal outcomes, redaction, and artifact linkage deterministically.

#### Scenario: Closed-loop Docker fixture runs
- **WHEN** Docker and `python:3.12-slim` are explicitly available for integration testing
- **THEN** a trace-backed fixture whose initial PoC lacks an import SHALL be repaired through an allowlisted typed edit, assembled by trusted code, run in Docker, produce protected Judge-readable evidence, and preserve unchanged target hashes.

#### Scenario: Nontrivial grounded repair runs
- **WHEN** a synthetic authorized fixture exposes a generator-declared setup slot and fails from a target-derived fixture or name mismatch
- **THEN** the repair agent SHALL produce a grounded typed edit that passes semantic and safety gates and reaches a deterministic terminal result without changing protected evidence code.
