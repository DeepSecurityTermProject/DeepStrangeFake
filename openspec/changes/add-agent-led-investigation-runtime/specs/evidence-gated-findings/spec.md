## ADDED Requirements

### Requirement: Candidate promotion requires trusted dual evidence
The system SHALL allow only trusted EvidenceGate code to promote an investigation into a candidate finding, and promotion SHALL require an in-scope supported class, exact current local source evidence, and independent corroboration.

#### Scenario: Dual evidence is accepted
- **WHEN** a supported hypothesis cites an exact repository-relative path, line, excerpt, and current content hash plus an independent Dataflow trace, call-graph path, normalized SAST result, or second independent source/config/manifest location
- **THEN** EvidenceGate SHALL record satisfied predicates and MAY promote a normalized candidate.

#### Scenario: Pattern and same-line context are offered
- **WHEN** the only evidence is a Pattern signal and a source-context excerpt for the same content and line
- **THEN** EvidenceGate SHALL count them as one origin and SHALL return `refine` or `rejected` rather than promote.

#### Scenario: Nonlocal evidence is offered alone
- **WHEN** the only corroboration is model text, memory, CVE text, a tool error, an unavailable-tool observation, or an unreadable artifact ref
- **THEN** EvidenceGate SHALL reject it as non-promoting evidence.

### Requirement: Local source evidence is exact and drift-checked
EvidenceGate SHALL resolve source evidence against the current in-scope repository view and SHALL validate repository-relative path, line range, normalized excerpt, content hash, and scope before promotion and again before verification.

#### Scenario: Source matches current repository
- **WHEN** the cited path and line resolve in scope and the normalized content hash matches
- **THEN** EvidenceGate SHALL persist the exact local evidence ref as normative evidence.

#### Scenario: Source changed after investigation
- **WHEN** the path, content, or line hash no longer matches the evidence record
- **THEN** EvidenceGate SHALL deny promotion or invalidate the evidence package with a drift reason.

#### Scenario: Source path escapes repository scope
- **WHEN** a cited source resolves through traversal, symlink, absolute path, or metadata mismatch outside the accepted repository root/file tree
- **THEN** EvidenceGate SHALL reject the evidence and SHALL NOT read or verify the escaped target.

### Requirement: Contradictory and sanitizing evidence affects promotion
EvidenceGate SHALL evaluate sanitizer, safe API, parameterization, allowlist, test/example, override, and other class-specific counterevidence before it promotes a candidate.

#### Scenario: Counterexample refutes the hypothesis
- **WHEN** trusted observations show effective sanitization, parameter binding, safe argv handling, path confinement, or a documented non-secret test/example value
- **THEN** EvidenceGate SHALL return `rejected` with the counterevidence refs.

#### Scenario: Evidence is ambiguous
- **WHEN** corroboration exists but class-specific counterevidence cannot be resolved within the current package
- **THEN** EvidenceGate SHALL return `refine` or `rejected` and SHALL NOT create a candidate finding.

### Requirement: Verification receives a normative evidence package
For each promoted candidate, trusted code SHALL construct a versioned `VerificationEvidencePackage` containing normalized claim, class, severity inputs, exact local evidence, independent corroboration, counterevidence, provenance, scope, and content hashes, but no Analysis hidden reasoning.

#### Scenario: Package is constructed after promotion
- **WHEN** EvidenceGate promotes a hypothesis
- **THEN** the runtime SHALL persist the package separately from model decision records and correlate it with the gate decision and candidate ID.

#### Scenario: Verification attempts to use omitted reasoning
- **WHEN** a Verification decision cites data not present in the normative package or registered repository evidence refs
- **THEN** schema or policy validation SHALL deny the plan input.

### Requirement: Evidence-gate artifacts are replayable
EvidenceGate SHALL persist a deterministic decision record containing schema version, input refs, predicate results, origin-identity calculation, counterevidence result, output state, and candidate/package refs.

#### Scenario: Gate is replayed
- **WHEN** the same normalized repository view and evidence inputs are replayed
- **THEN** trusted gate evaluation SHALL produce the same promotion state and normalized diagnostics without a model call.
