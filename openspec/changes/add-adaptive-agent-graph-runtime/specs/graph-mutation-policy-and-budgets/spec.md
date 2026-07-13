## ADDED Requirements

### Requirement: Graph mutations use a closed operation catalog
The system SHALL accept graph mutation proposals only through registered operations and node templates that resolve to existing agent roles, brokered tools, or runtime service handlers.

#### Scenario: Registered refinement is proposed
- **WHEN** an Orchestrator proposal inserts a registered context-gathering or analysis-refinement template with valid typed parameters
- **THEN** the policy gate SHALL evaluate the operation against structural, safety, and budget policy.

#### Scenario: Proposal invents executable behavior
- **WHEN** a proposal names an unregistered agent, tool, callable, command, source fragment, predicate, or node template
- **THEN** the policy gate SHALL deny it without importing, evaluating, dispatching, or executing the proposed behavior.

### Requirement: Graph mutations are safety and budget gated
The system SHALL validate every mutation against configured target boundaries, read-only policy, tool and role permissions, validation level, node and graph ceilings, token and tool budgets, retry limits, checkpoint limits, and global run budgets.

#### Scenario: Safe operation is within budget
- **WHEN** a registered operation remains within all configured permissions and remaining budgets
- **THEN** the policy result SHALL record it as accepted with the normalized budget delta and supporting policy rules.

#### Scenario: Operation exceeds budget
- **WHEN** a proposal requests more nodes, retries, tool calls, model tokens, sandbox attempts, or replans than policy permits
- **THEN** the excess operation SHALL be denied and SHALL NOT reduce or bypass existing budget accounting.

#### Scenario: Operation escalates target access
- **WHEN** a proposal requests live-target access, target repository writes, network behavior, validation strength, or sandbox permissions beyond run configuration
- **THEN** the policy gate SHALL deny the operation and retain the configured defensive boundary.

### Requirement: Mutations affect only future mutable work
The system SHALL prohibit graph mutations from altering completed, running, immutable required, or policy-owned nodes and SHALL validate dependencies, conditions, reachability, and acyclicity after accepted operations.

#### Scenario: Proposal changes completed work
- **WHEN** a proposal attempts to replace the output, executor, budget, status, or dependencies of a running or completed node
- **THEN** the mutation SHALL be denied and the existing node state SHALL remain unchanged.

#### Scenario: Proposal makes reporting unreachable
- **WHEN** an operation removes the only valid path to required report finalization
- **THEN** candidate graph validation SHALL fail and the active graph revision SHALL remain unchanged.

### Requirement: Replanning is limited to explicit checkpoints
The system SHALL evaluate graph mutation proposals only at registered checkpoints with configured per-checkpoint and global replan ceilings.

#### Scenario: Reconnaissance checkpoint requests more evidence
- **WHEN** the reconnaissance checkpoint has not been consumed and policy accepts a refinement proposal
- **THEN** the runtime SHALL record the checkpoint use and commit at most the allowed bounded refinement path.

#### Scenario: Replan ceiling is exhausted
- **WHEN** a checkpoint or run has reached its permitted number of replans
- **THEN** further mutation proposals SHALL be denied and execution SHALL continue or terminate according to the current committed graph.

### Requirement: Mutation commits are validated, atomic, and revisioned
The system SHALL evaluate ordered mutation operations on a copy of the active graph, record per-operation decisions, validate the resulting candidate, and atomically publish a new immutable graph revision only when the accepted subset forms a valid graph.

#### Scenario: Accepted subset is valid
- **WHEN** some proposal operations are denied but the accepted normalized subset produces a valid graph
- **THEN** the runtime SHALL commit one new revision containing only the accepted subset and link it to the proposal and policy result.

#### Scenario: Candidate graph is invalid
- **WHEN** accepted operations collectively produce an invalid or unsafe graph
- **THEN** the runtime SHALL commit none of those operations, keep the previous revision active, and record validation diagnostics.

### Requirement: Advisory next actions do not execute directly
The system SHALL treat `AgentOutput.next_actions` and model-authored routing text as untrusted advisory input that requires deterministic translation into registered mutation operations and complete policy evaluation.

#### Scenario: Agent returns an unknown next action
- **WHEN** an agent output contains a next action that has no registered deterministic mapping
- **THEN** the runtime SHALL record or ignore the hint and SHALL NOT schedule executable work from it.

#### Scenario: Agent returns a known next action
- **WHEN** an agent output contains a registered next-action hint at an eligible checkpoint
- **THEN** the runtime SHALL translate it into a mutation proposal and apply the same schema, policy, budget, and commit gates used for model proposals.

### Requirement: Invalid or unavailable adaptive decisions fall back deterministically
The system SHALL preserve the last committed valid graph when proposal generation, schema validation, policy evaluation, artifact persistence, or candidate graph validation fails safely.

#### Scenario: LLM proposal is malformed
- **WHEN** the LLM response cannot be parsed into the versioned mutation contract
- **THEN** the runtime SHALL persist redacted diagnostics, publish a fallback event, and continue from the last committed graph without partial mutation.

#### Scenario: Mutation artifact cannot be persisted
- **WHEN** a required proposal or policy artifact cannot be written safely
- **THEN** the runtime SHALL NOT commit the mutation and SHALL follow required runtime failure or fallback behavior.

### Requirement: Mutation policy is testable offline
The system SHALL expose deterministic graph validation and mutation policy interfaces that can be tested without model credentials, MCP servers, Docker, network access, or target writes.

#### Scenario: Default tests run without credentials
- **WHEN** the default test suite evaluates accepted, denied, malformed, over-budget, cyclic, and fallback mutation cases
- **THEN** mock proposals and local fixtures SHALL produce deterministic graph revisions, policy records, and execution paths.
