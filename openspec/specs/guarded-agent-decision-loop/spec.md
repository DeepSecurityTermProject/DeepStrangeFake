# guarded-agent-decision-loop Specification

## Purpose
TBD - created by archiving change enable-llm-agent-decision-loop. Update Purpose after archive.
## Requirements
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

### Requirement: Recon LLM proposals select bounded tools and context
The system SHALL allow validated Recon LLM proposals to request safe tools, memory queries, context slices, and CVE MCP lookups through the tool protocol.

#### Scenario: Safe Recon tool request is dispatched
- **WHEN** Recon proposes a registered safe tool call within budget
- **THEN** the tool protocol SHALL dispatch the call and return the normalized result to the agent trace.

#### Scenario: Unsafe Recon tool request is denied
- **WHEN** Recon proposes an unregistered, disallowed, over-budget, or unsafe tool call
- **THEN** the tool protocol SHALL deny the call and the final Recon handoff SHALL include the denial reason.

### Requirement: Analysis LLM proposals contribute evidence-bound candidates
The system SHALL allow Analysis LLM proposals to create or rank candidate findings only when local evidence requirements are met.

#### Scenario: Candidate with local evidence is promoted
- **WHEN** Analysis LLM output proposes a finding with valid vulnerability class, source location, local evidence citation, and confidence
- **THEN** the candidate SHALL be merged into the candidate list and linked to prompt, LLM, memory, tool, and message references.

#### Scenario: Candidate without local evidence is rejected
- **WHEN** Analysis LLM output proposes a finding based only on memory, CVE intelligence, or unsupported rationale
- **THEN** the candidate SHALL be rejected or downgraded and SHALL NOT become an accepted finding.

### Requirement: Verification LLM proposals participate under deterministic override
The system SHALL allow Verification LLM proposals to influence accept/reject, priority, and validation level while deterministic policy gates retain final override authority.

#### Scenario: Verification agrees with evidence
- **WHEN** Verification LLM output accepts a candidate that has local evidence and passes policy gates
- **THEN** the final merged decision MAY use the LLM rationale and validation-level recommendation.

#### Scenario: Verification conflicts with policy
- **WHEN** Verification LLM output accepts a candidate that lacks local evidence, exceeds validation permissions, or references unresolved citations
- **THEN** deterministic policy SHALL override the LLM proposal and reject or downgrade the decision.

### Requirement: Decision source is explicit
The system SHALL mark every final agent decision with its source.

#### Scenario: Merged decision is produced
- **WHEN** a final plan, handoff, candidate, or verification decision is produced
- **THEN** it SHALL include whether the decision source was `llm`, `deterministic`, `merged`, `fallback`, or `policy-denied`.
