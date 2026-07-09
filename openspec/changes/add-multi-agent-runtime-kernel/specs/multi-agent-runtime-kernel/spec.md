## ADDED Requirements

### Requirement: AgentRuntime owns run lifecycle
The system SHALL provide an `AgentRuntime` that initializes runs, wires runtime services, invokes registered agents, records task transitions, handles fallback, and finalizes reports.

#### Scenario: Runtime starts and finalizes an audit run
- **WHEN** `run_audit()` is called with a target, config, and output directory
- **THEN** it SHALL delegate orchestration to `AgentRuntime` while preserving the existing summary fields, run directory structure, reports, and artifact categories.

#### Scenario: Runtime records lifecycle state
- **WHEN** an audit run starts, invokes agents, dispatches tools, applies decisions, validates findings, and completes reporting
- **THEN** the runtime SHALL persist run/task state records that link message IDs, artifact refs, agent roles, statuses, and fallback reasons.

### Requirement: Runtime preserves existing four-agent behavior
The system SHALL preserve the current Orchestrator, Recon, Analysis, and Verification execution order and outputs unless a validated runtime decision explicitly changes a supported field.

#### Scenario: Default deterministic audit remains compatible
- **WHEN** runtime mode is disabled or LLM decision participation is disabled
- **THEN** the final candidates, accepted findings, evidence chains, and reports SHALL remain compatible with the current deterministic pipeline behavior.

#### Scenario: LLM decision audit remains compatible
- **WHEN** runtime mode and LLM decisions are enabled
- **THEN** the runtime SHALL continue to produce prompt, LLM response, decision, policy-gate, merge, fallback, evidence, message, and report artifacts equivalent to the current decision loop.

### Requirement: Runtime handles failures through explicit fallback
The system SHALL centralize agent, tool, LLM, artifact, and validation failures into runtime task state and deterministic fallback behavior.

#### Scenario: Recoverable task failure is recorded
- **WHEN** an LLM response is malformed, a safe tool request is denied, MCP is degraded, or a role proposal fails policy
- **THEN** the runtime SHALL record the failure in task state, publish a fallback event, persist diagnostics, and continue with deterministic fallback when the configured safety model allows it.

#### Scenario: Non-recoverable task failure stops the run
- **WHEN** a required runtime service cannot create the run directory, write critical artifacts, or produce a required final report
- **THEN** the runtime SHALL mark the run failed, persist available diagnostics, and return a structured failure summary instead of silently dropping the error.

### Requirement: Pipeline becomes a thin compatibility adapter
The system SHALL keep `pipeline.py` focused on public entry points and delegate orchestration details to runtime services.

#### Scenario: Pipeline delegates orchestration
- **WHEN** `pipeline.run_audit()` is executed
- **THEN** it SHALL construct or obtain an `AgentRuntime`, call the runtime execution API, and return the runtime summary without duplicating agent sequencing, tool dispatch, or artifact persistence logic.
