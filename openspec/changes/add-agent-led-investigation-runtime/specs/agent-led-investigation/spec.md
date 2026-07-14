## ADDED Requirements

### Requirement: Agent-led investigations use versioned bounded contracts
The system SHALL represent every security signal, investigation hypothesis, and investigation step with versioned schema-validated contracts and SHALL reject unknown versions, unknown fields that grant authority, invalid state transitions, and out-of-budget actions before execution.

#### Scenario: Valid hypothesis begins investigation
- **WHEN** Analysis proposes an in-scope hypothesis with valid target refs, class, rationale, confidence, and budget lineage
- **THEN** the runtime SHALL persist it in `proposed` state and MAY transition it to `investigating` through the trusted state machine.

#### Scenario: Invalid hypothesis is denied
- **WHEN** a hypothesis requests an unsupported vulnerability class, out-of-scope path, executable code, command, unregistered tool, Docker option, or verdict
- **THEN** schema or policy validation SHALL reject it without invoking a tool or creating a candidate finding.

#### Scenario: State transitions are finite
- **WHEN** a hypothesis is processed
- **THEN** its states SHALL be limited to `proposed`, `investigating`, `supported`, `refuted`, `inconclusive`, `evidence-gate`, `promoted`, `refine`, and `rejected` with only registered forward transitions.

### Requirement: Startup scanning produces signals rather than findings
The agent-led runtime SHALL run only the lightweight Pattern scanner at startup and SHALL record its matches as `SecuritySignal` inputs that cannot directly become candidate or confirmed findings.

#### Scenario: Pattern match seeds a hypothesis
- **WHEN** the Pattern scanner reports a supported-class match
- **THEN** the runtime SHALL persist a signal with source provenance and make it available to Analysis without promoting it.

#### Scenario: Agent discovers a scanner blind spot
- **WHEN** no startup signal exists for a vulnerable location and Analysis finds repository-grounded evidence using registered actions
- **THEN** the hypothesis SHALL remain eligible for evidence-gate promotion under the same rules as a signal-seeded hypothesis.

### Requirement: Analysis controls evidence gathering through registered actions
The Analysis agent SHALL select only `search`, `source_context`, `callers`, `callees`, `dataflow`, `sast`, `lexical_memory`, `submit_gate`, or `abandon` actions, and trusted code SHALL resolve each action to a registered typed handler.

#### Scenario: Registered action executes
- **WHEN** a schema-valid step requests a registered action with in-scope typed arguments
- **THEN** the runtime SHALL invoke the registered handler, persist normalized observations and artifact refs, and debit the appropriate hypothesis and global budgets.

#### Scenario: Model attempts arbitrary execution
- **WHEN** a step contains shell text, raw argv, source code to run, an executable path, arbitrary environment variables, or container parameters
- **THEN** the runtime SHALL reject the step before any process or sandbox invocation.

#### Scenario: Repository read is out of scope
- **WHEN** an action resolves outside the in-scope `RepositoryMetadata.file_tree` or to a path whose current content hash does not match the repository view
- **THEN** the handler SHALL deny the read and persist a scope or drift observation.

### Requirement: Repository evidence tools are bounded and normalized
The runtime SHALL provide deterministic source search/context, lexical retrieval, Python/JavaScript/TypeScript symbol-import-call indexing, existing Dataflow, and optional Semgrep/Bandit/Gitleaks adapters with bounded inputs and normalized outputs.

#### Scenario: Call graph contains a resolvable direct call
- **WHEN** a supported-language file contains a statically resolvable import, symbol, or direct call
- **THEN** the call-graph tool SHALL return repository-relative symbol and edge refs with source locations.

#### Scenario: Dynamic call cannot be resolved
- **WHEN** a supported-language call target is dynamic or ambiguous
- **THEN** the call-graph tool SHALL return an explicit unresolved edge and SHALL NOT invent a callee.

#### Scenario: Optional SAST tool is unavailable
- **WHEN** Semgrep, Bandit, or Gitleaks is absent, times out, returns malformed output, exceeds the output cap, or uses an unsupported result shape
- **THEN** the adapter SHALL persist a structured non-promoting observation and the investigation SHALL continue within remaining budgets.

#### Scenario: External SAST process is invoked
- **WHEN** a supported optional SAST adapter runs
- **THEN** trusted code SHALL use the registered executable identity, fixed argument template, repository working directory, `shell=False`, timeout, output cap, and redacted normalized result parser.

### Requirement: Investigation checkpoints are immutable and idempotent
The runtime SHALL checkpoint each committed hypothesis transition and completed action with normalized state, action keys, artifact refs, accounting refs, and remaining budgets so resumption cannot repeat completed billable or executable work.

#### Scenario: Run resumes from a checkpoint
- **WHEN** an interrupted agent-led run has a valid latest checkpoint
- **THEN** the runtime SHALL restore committed hypothesis state and SHALL reuse completed action results without dispatching duplicate model, tool, sandbox, or remote work.

#### Scenario: Checkpoint is incomplete or corrupt
- **WHEN** the latest checkpoint fails schema, hash, or artifact-ref validation
- **THEN** the runtime SHALL use the previous valid checkpoint or a documented safe fallback and SHALL record the recovery decision.

### Requirement: Investigation records are auditable without exposing hidden reasoning
The runtime SHALL persist redacted prompts, responses, step decisions, tool refs, observations, transitions, and accounting correlations while excluding hidden chain-of-thought from evidence packages, reports, and Web summaries.

#### Scenario: Investigation step is persisted
- **WHEN** Analysis completes or fails an action decision
- **THEN** the step record SHALL correlate its hypothesis, round, request group, provider attempt, prompt/response refs, tool invocation/result refs, budget debit, schema result, and policy result.

#### Scenario: Secret-like content appears in a tool result
- **WHEN** a source or SAST observation contains secret-like text
- **THEN** persisted prompts, responses, logs, and summaries SHALL redact the sensitive value while retaining stable evidence hashes and source locations.
