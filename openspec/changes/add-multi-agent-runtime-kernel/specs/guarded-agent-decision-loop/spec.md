## MODIFIED Requirements

### Requirement: Orchestrator LLM proposals affect audit planning
The system SHALL allow validated Orchestrator LLM proposals to influence audit scope, budgets, focus areas, and agent order through `AgentRuntime` task execution and policy validation.

#### Scenario: Valid plan proposal is merged
- **WHEN** Orchestrator LLM output passes schema and policy gates during a runtime task
- **THEN** the final audit plan SHALL include accepted model-proposed focus areas, budget adjustments, and agent ordering decisions, and the related `TaskState` SHALL link the proposal, gate, merge, and plan artifacts.

#### Scenario: Unsafe plan proposal is denied
- **WHEN** Orchestrator LLM output requests a vulnerability class, validation level, or live action outside configured policy
- **THEN** the system SHALL deny that part of the proposal, record a policy-gate result, publish a runtime fallback event, and keep deterministic planning as the fallback.

### Requirement: Recon LLM proposals select bounded tools and context
The system SHALL allow validated Recon LLM proposals to request safe tools, memory queries, context slices, and CVE MCP lookups through `AgentRuntime` and `ToolBroker`.

#### Scenario: Safe Recon tool request is dispatched
- **WHEN** Recon proposes a registered safe tool call within budget
- **THEN** `ToolBroker` SHALL dispatch the call through the tool protocol and return the normalized result to the Recon task state and agent trace.

#### Scenario: Unsafe Recon tool request is denied
- **WHEN** Recon proposes an unregistered, disallowed, over-budget, or unsafe tool call
- **THEN** `ToolBroker` SHALL deny the call and the final Recon handoff SHALL include the denial reason through runtime task state and message refs.

### Requirement: Decision source is explicit
The system SHALL mark every final agent decision with its source and the runtime task that produced or resolved it.

#### Scenario: Merged decision is produced
- **WHEN** a final plan, handoff, candidate, or verification decision is produced
- **THEN** it SHALL include whether the decision source was `llm`, `deterministic`, `merged`, `fallback`, or `policy-denied`, and it SHALL link to the `TaskState` or runtime artifact refs that explain the merge.
