## ADDED Requirements

### Requirement: Generator-owned evidence semantics are protected across repair
The system MUST create a repair manifest for every repairable deterministic PoC and MUST preserve protected evidence-producing semantics when typed edits are assembled.

#### Scenario: Repair manifest is created
- **WHEN** a supported deterministic path-traversal or SQLi generator creates the initial PoC
- **THEN** trusted code SHALL persist editable slot IDs and operation kinds plus protected AST hashes for payload construction, target-derived expressions, sink execution, semantic measurements, marker/status derivation, and Judge-facing result writers.

#### Scenario: Declared edit is assembled
- **WHEN** a validated repair response contains an operation allowed by the original repair manifest
- **THEN** trusted code SHALL apply it only to the declared slot and SHALL persist the normalized edit list and assembled script hash.

#### Scenario: Confirmation marker is forged
- **WHEN** an edit inserts or changes `PATH_TRAVERSAL_CONFIRMED`, `PATH_TRAVERSAL_BLOCKED`, `SQLI_CONFIRMED`, or another protected expected marker outside its generator-owned emitter
- **THEN** the semantic-integrity gate SHALL deny execution and no sandbox runner SHALL start for that assembled script.

#### Scenario: SQLi result is forged
- **WHEN** an edit writes `sqli-result.json`, hard-codes baseline or attack counts, changes `marker_seen` or status derivation, or modifies protected query execution or serialization nodes
- **THEN** the semantic-integrity gate SHALL deny execution and the attempt SHALL NOT become `confirmed`.

#### Scenario: Protected node changes
- **WHEN** the assembled script's protected AST hashes do not match the initial repair manifest
- **THEN** the semantic-integrity gate SHALL persist the changed protected node IDs, stop repair as `manual-required`, and SHALL NOT call Docker.

### Requirement: Every executable PoC passes a Python safety gate
The system MUST parse and inspect every initial and repaired Python PoC script before sandbox execution and MUST fail closed when the script cannot be proven compliant with the configured PoC policy.

#### Scenario: Safe generated script is allowed
- **WHEN** a script parses successfully, passes semantic-integrity checks, and uses only approved Python constructs, constrained standard-library APIs, attempt-local artifacts, and the fixed evidence contract
- **THEN** the safety gate SHALL produce an `allowed` decision with script hash, evaluated rule IDs, and source locations before the runner is called.

#### Scenario: Script does not parse
- **WHEN** a generated or repaired script has invalid Python syntax
- **THEN** the safety gate SHALL deny execution, persist the parse error, and the sandbox runner SHALL NOT start.

### Requirement: Dangerous capabilities are denied before execution
The safety gate MUST deny scripts that request process execution, networking, dependency installation, dynamic code loading, Docker control, unsafe host paths, or target-repository mutation.

#### Scenario: Network or process code is generated
- **WHEN** a script imports `subprocess`, `socket`, `requests`, or a network client, or calls `os.system`, `os.popen`, process spawn/exec APIs, `eval`, `exec`, `compile`, or dynamic import APIs
- **THEN** the safety gate SHALL deny the script with machine-readable rule IDs and the container SHALL NOT start.

#### Scenario: Dependency installation is generated
- **WHEN** a script attempts to invoke pip, a package manager, or an installer
- **THEN** the safety gate SHALL deny the script and record a `policy-denied` repair outcome.

#### Scenario: Host or Docker control path is generated
- **WHEN** a script references an absolute host path, Windows drive or UNC path, Docker socket, privileged mode, host mount, or container-management API
- **THEN** the safety gate SHALL deny the script before sandbox execution.

#### Scenario: Target write is generated
- **WHEN** static inspection shows an attempt to write, delete, rename, chmod, or otherwise mutate a target repository path
- **THEN** the safety gate SHALL deny execution and record the target-write rule and location.

### Requirement: LLM-repaired scripts use a fixed Docker execution envelope
The system MUST assemble the repaired script, construct the command, and select sandbox policy outside the LLM and SHALL execute LLM-repaired scripts only through the Docker sandbox runner in this phase.

#### Scenario: Repaired script is executable
- **WHEN** a typed repair response passes exact validation, trusted assembly, semantic-integrity validation, and safety validation
- **THEN** trusted code SHALL write the assembled script as attempt-local `poc.py`, execute the fixed `python /attempt/poc.py` container argv, keep `--network none`, prohibit privileged mode, and expose only the attempt directory as writable.

#### Scenario: Local runner is selected
- **WHEN** an initial PoC needs LLM repair but the configured sandbox runner is `local`
- **THEN** the system SHALL NOT execute the repaired script and SHALL return `manual-required` with an `llm-repair-requires-docker` blocking reason.

#### Scenario: Model includes command or policy fields
- **WHEN** a repair response includes a complete script or extra command, expected-signal, evidence-emitter, Docker, verdict, or policy fields
- **THEN** exact response validation SHALL reject the whole response and no edit from that response SHALL be assembled or executed.

### Requirement: Expected evidence and generator provenance are immutable
The system SHALL preserve generator-owned PoC metadata, repair manifest, and protected evidence semantics across repairs and MUST reject any attempt to weaken, replace, or self-produce the expected evidence contract.

#### Scenario: Repaired artifact is created
- **WHEN** trusted code creates a repaired `PoCArtifact`
- **THEN** vulnerability class, generator ID, target refs, dataflow refs, expected signal, repair-manifest hash, protected AST hashes, and fixed command shape SHALL match the initial artifact's immutable execution-envelope hash.

#### Scenario: Expected signal differs
- **WHEN** a repaired artifact or persistence record does not match the initial expected-signal hash
- **THEN** the safety policy SHALL deny execution and the validation SHALL NOT become `confirmed`.

### Requirement: Target repository integrity is verified
The system SHALL persist one run-level before/after SHA-256 manifest pair for the re-enumerated in-scope target file set around the validation phase and SHALL not finalize a confirmation when target integrity changes.

#### Scenario: Target remains unchanged
- **WHEN** verification and all repair attempts finish without changing target files
- **THEN** the integrity comparison artifact SHALL report no changed, added, or removed in-scope target files and SHALL be referenced by the validation evidence.

#### Scenario: Target changes during verification
- **WHEN** the after manifest differs from the before manifest
- **THEN** the system SHALL record changed, added, and removed files, stop additional repair, downgrade provisional confirmations to `manual-required`, preserve rejected contradiction evidence with an integrity warning, and SHALL NOT report an affected attempt as `confirmed`.
