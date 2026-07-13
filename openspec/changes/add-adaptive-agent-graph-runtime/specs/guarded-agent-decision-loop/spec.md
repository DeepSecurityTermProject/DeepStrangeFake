## MODIFIED Requirements

### Requirement: Orchestrator LLM proposals affect audit planning
The system SHALL allow validated Orchestrator LLM proposals to influence audit scope, budgets, focus areas, initial agent order, and bounded future execution-graph mutations at registered replanning checkpoints.

#### Scenario: Valid plan proposal is merged
- **WHEN** initial Orchestrator LLM output passes schema and policy gates
- **THEN** the final audit plan SHALL include accepted model-proposed focus areas, budget adjustments, and supported ordering decisions used to configure the deterministic graph.

#### Scenario: Valid graph mutation is committed
- **WHEN** an Orchestrator graph proposal at an eligible checkpoint references registered operations and templates and passes graph, safety, and budget gates
- **THEN** the runtime SHALL commit a revisioned mutation whose accepted operations can affect future scheduled nodes.

#### Scenario: Unsafe plan proposal is denied
- **WHEN** Orchestrator LLM output requests a vulnerability class, validation level, live action, graph operation, node template, or budget outside configured policy
- **THEN** the system SHALL deny that part of the proposal and record a policy-gate result without executing the denied behavior.

#### Scenario: Proposal attempts to rewrite completed execution
- **WHEN** an Orchestrator proposal targets a running, completed, or immutable required node
- **THEN** deterministic policy SHALL deny the mutation and retain the last committed valid graph.
