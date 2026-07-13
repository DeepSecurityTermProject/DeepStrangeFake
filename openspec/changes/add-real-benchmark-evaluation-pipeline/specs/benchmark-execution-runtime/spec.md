## ADDED Requirements

### Requirement: Benchmark cases use an atomic persistent state machine
The system SHALL persist each case as `pending`, `acquiring`, `ready`, `running`, or terminal `completed`, `failed`, `timed-out`, or `not-run`, with separate acquisition, execution, evaluation, and baseline-eligibility fields.

#### Scenario: Case state changes
- **WHEN** acquisition or scanning advances a case
- **THEN** the coordinator SHALL write a same-directory temporary record, flush it, atomically replace the state file, and persist timestamps, attempts, fingerprints, failures, and artifact refs before scheduling further work.

#### Scenario: Coordinator is interrupted during a write
- **WHEN** the process stops before atomic replacement
- **THEN** readers SHALL ignore temporary/partial files and SHALL not infer terminal completion.

### Requirement: Resume and comparison use different fingerprints
The system SHALL use a strict `reuse_fingerprint` for resume and a separate `comparison_protocol_fingerprint` plus declared `comparison_dimensions` for benchmark comparison.

#### Scenario: Compatible completed case is resumed
- **WHEN** engine, prompts, provider/model, commit, scope, config, budgets, safety, tools, schemas, and required artifacts match the reuse fingerprint
- **THEN** resume SHALL reuse the result and record the decision.

#### Scenario: Engine or prompt changes
- **WHEN** engine or prompt identity differs
- **THEN** resume SHALL rerun the case, while comparison MAY proceed only if that difference is declared as a comparison dimension and all protocol fields remain compatible.

#### Scenario: Undeclared field differs during comparison
- **WHEN** a field outside declared comparison dimensions differs
- **THEN** comparison SHALL fail with explicit mismatch fields.

#### Scenario: Truth content changes at the same reference
- **WHEN** the truth manifest path/reference is unchanged but its version or canonical content digest changes
- **THEN** reuse SHALL rerun affected cases and comparison protocol compatibility SHALL fail.

#### Scenario: Truth changes while resuming the same run ID
- **WHEN** a resume request uses the original run ID with a changed truth identity but the corpus, selected cases, and other immutable manifest fields match
- **THEN** the coordinator SHALL retain the original truth identity in `resolved-manifest.json`, persist the requested identity in `resume-request-*.json`, preserve the prior case result as stale, and rerun rather than rejecting the resume as an immutable-manifest mismatch.

### Requirement: Each project scan is isolated, secret-safe, and timed out
The coordinator SHALL run each case in a dedicated child process using a persisted non-secret configuration reference, dedicated output directory, fixed argv, deadline, bounded redacted output, and platform-specific process-tree ownership.

#### Scenario: Child configuration uses a real provider
- **WHEN** the child needs provider credentials
- **THEN** persisted config and argv SHALL contain only the configured environment-variable name, never the value or a secret-derived hash.

#### Scenario: Real provider model is missing or a placeholder
- **WHEN** runtime LLM execution uses a real provider and the effective model is empty, `disabled`, or `mock`
- **THEN** child configuration SHALL fail closed before scanning or making a provider request.

#### Scenario: Project finishes within its deadline
- **WHEN** the child reaches a successful terminal runtime state
- **THEN** the coordinator SHALL collect and validate artifacts before considering the case completed.

#### Scenario: Project exceeds its deadline
- **WHEN** the child exceeds timeout
- **THEN** POSIX group termination or Windows Job Object termination SHALL stop parent, child, and grandchild processes, verify the group/job has no active processes, persist cleanup evidence, and continue later cases.

#### Scenario: Labeled Docker resource survives timeout
- **WHEN** a container carrying the exact benchmark/run/case labels remains after child termination
- **THEN** bounded cleanup SHALL target only those labels, persist the result, and block baseline eligibility if cleanup fails.

### Requirement: Initial execution is sequential
The MVP coordinator SHALL execute at most one project child at a time.

#### Scenario: Multiple cases are ready
- **WHEN** two or more cases are ready
- **THEN** the coordinator SHALL schedule them sequentially and SHALL not add unreviewed parallelism or shared-cache races.

### Requirement: Completed status proves that a real scan occurred
The system SHALL mark a case completed only when acquisition resolved the commit, scope is non-empty, the child succeeded, and metadata, runtime-state, report, and `run-resource-summary.v1` agree with case identity and commit.

#### Scenario: Safe negative produces zero findings
- **WHEN** a verified scan analyzes a non-empty scope and produces zero findings
- **THEN** the case MAY complete with zero counts and SHALL retain positive coverage evidence.

#### Scenario: Remote project is skipped or artifacts are missing
- **WHEN** the result is `remote-download-skipped` or required checkout/run/report/resource evidence is absent
- **THEN** the case MUST NOT be completed and its finding/resource metrics SHALL be null with reasons.

#### Scenario: Scan scope is empty
- **WHEN** scope filtering leaves no files
- **THEN** the case SHALL fail as `empty-scan-scope` and SHALL not publish zero effectiveness metrics.

### Requirement: Effective budgets and safety policies are enforced
Each case SHALL record and enforce commit, language/support, scope, project timeout, tool/LLM/Docker/repair budgets, validation level, network permission, target-write policy, and secret-handling policy.

#### Scenario: A budget is exceeded
- **WHEN** time, token, tool, Docker, or repair consumption exceeds a bound
- **THEN** execution SHALL stop according to policy, record consumed resources and reason, and SHALL not continue with relaxed limits.

### Requirement: Partial benchmark completion is explicit
The command SHALL distinguish complete, incomplete, and failed execution.

#### Scenario: Required case does not complete
- **WHEN** a required case is failed, timed-out, or not-run
- **THEN** the CLI SHALL exit nonzero unless `--allow-partial` is explicit.

#### Scenario: Partial execution is allowed
- **WHEN** `--allow-partial` is supplied
- **THEN** outputs SHALL retain every non-completed case/reason and the run SHALL remain ineligible for baseline promotion.
