# adaptive-agent-execution-graph Specification

## Purpose
Define the validated, dependency-driven execution graph and compatibility behavior for graph-based audits.

## Requirements
### Requirement: Audit execution is represented by a validated graph
The system SHALL represent each graph-mode audit as a schema-versioned `ExecutionGraph` containing stable node IDs, registered template IDs, executor kinds, dependency edges, structured conditions, typed input and output refs, required flags, budgets, retry policies, lineage, and lifecycle state.

#### Scenario: Deterministic graph is created
- **WHEN** a graph-mode audit starts
- **THEN** the runtime SHALL create and validate an execution graph from a registered deterministic template before executing any graph node.

#### Scenario: Invalid graph is rejected before execution
- **WHEN** a graph contains an unknown schema version, missing dependency, duplicate node ID, unregistered template, arbitrary condition, cycle, or unreachable required terminal node
- **THEN** graph validation SHALL reject it and persist structured diagnostics without executing the invalid graph.

### Requirement: The deterministic graph preserves the audit lifecycle
The system SHALL provide a versioned deterministic graph template that preserves the required Orchestrator, reconnaissance, static analysis, Analysis, Verification, validation, evidence, and reporting behavior of the current runtime.

#### Scenario: Adaptive participation is disabled
- **WHEN** graph execution is enabled and adaptive mutation or LLM participation is disabled
- **THEN** the runtime SHALL execute the deterministic template and preserve compatible candidates, accepted findings, evidence chains, report fields, run directories, and artifact categories.

#### Scenario: Required finalization cannot be removed
- **WHEN** an adaptive proposal attempts to remove required evidence or reporting finalization
- **THEN** the runtime SHALL reject the proposal and retain the required deterministic nodes.

### Requirement: Scheduler execution is dependency-driven and deterministic
The system SHALL use a sequential scheduler that derives runnable nodes from committed graph dependencies and conditions and chooses among runnable nodes using stable template priority and node ID ordering.

#### Scenario: Only ready nodes execute
- **WHEN** a node has an unfinished required dependency or an unsatisfied edge condition
- **THEN** the scheduler SHALL NOT invoke that node until its dependencies and conditions are satisfied.

#### Scenario: Accepted branch changes actual execution
- **WHEN** policy commits a graph revision that inserts or routes to an optional registered node
- **THEN** the scheduler SHALL invoke that node when ready and its task, messages, output refs, and transitions SHALL appear in the actual execution path.

#### Scenario: Multiple nodes are ready
- **WHEN** more than one node becomes runnable in the single-threaded scheduler
- **THEN** repeated execution of the same committed graph and normalized node outcomes SHALL select them in the same order.

### Requirement: Graph nodes use existing runtime service boundaries
The system SHALL execute agent nodes through `AgentRegistry`, tool nodes through `ToolBroker`, and registered internal service nodes through runtime-owned handlers while persisting outputs through `ArtifactStore` and events through the message bus.

#### Scenario: Agent node executes
- **WHEN** a registered agent node becomes runnable
- **THEN** the scheduler SHALL create a bounded `AgentInvocation`, invoke the registered role adapter, and bind the structured `AgentOutput` refs to the node result.

#### Scenario: Tool node executes
- **WHEN** a registered tool node becomes runnable
- **THEN** its predefined request SHALL pass through existing tool permission, budget, safety, normalization, artifact, and event handling.

#### Scenario: Node output feeds a dependent node
- **WHEN** a dependent node declares a typed input from an upstream output
- **THEN** the scheduler SHALL resolve the immutable output ref and SHALL fail or follow registered fallback behavior when a required ref is missing or incompatible.

### Requirement: Node lifecycle and failure behavior are explicit
The system SHALL persist graph node transitions through pending, runnable, running, succeeded, failed, skipped, fallback, or blocked states and correlate each transition with task, message, artifact, graph revision, attempt, and causation refs.

#### Scenario: Optional branch is unreachable
- **WHEN** all incoming conditions for an optional pending node become impossible after its dependencies finish
- **THEN** the scheduler SHALL mark the node skipped with the evaluated condition reason rather than leaving it pending.

#### Scenario: Required node fails without fallback
- **WHEN** a required node exhausts its registered retry policy and has no approved fallback edge
- **THEN** the scheduler SHALL mark the graph and run failed, preserve available diagnostics, and stop scheduling dependent work other than required failure finalization.

#### Scenario: Scheduler termination guard is reached
- **WHEN** graph size, scheduler iteration, or task attempt ceilings are reached
- **THEN** the scheduler SHALL stop further expansion or invocation and produce a structured bounded-termination result.

### Requirement: Refinement uses bounded acyclic node expansion
The system SHALL represent repeated context gathering or analysis as new registered node instances with lineage and increasing iteration numbers rather than cyclic edges or re-execution of completed node state.

#### Scenario: Evidence refinement is scheduled
- **WHEN** an approved checkpoint proposal requests additional local context followed by another analysis pass
- **THEN** the runtime SHALL append registered refinement nodes, preserve lineage to the triggering node, and schedule them according to the new acyclic dependencies.

#### Scenario: A mutation introduces a back-edge
- **WHEN** a proposed refinement depends on its own future output or otherwise creates a cycle
- **THEN** graph validation SHALL deny the mutation and continue from the last committed valid graph.

### Requirement: Verification repair remains an encapsulated sub-loop
The system SHALL treat the existing VerificationEngine and its bounded PoC generation, sandbox execution, judging, and repair attempts as a registered verification node outcome rather than recreating those attempts as unrestricted graph mutations.

#### Scenario: Verification performs PoC repair
- **WHEN** a verification node invokes the existing bounded repair loop
- **THEN** graph state SHALL reference its verification attempt artifacts while applying graph-level retry limits independently.

### Requirement: Runtime modes provide compatibility and rollback
The system SHALL expose explicit legacy, deterministic graph, and adaptive graph modes through validated configuration while preserving the public audit entry point.

#### Scenario: Legacy mode is selected
- **WHEN** graph rollout is disabled or rollback selects legacy mode
- **THEN** the existing procedural runtime path SHALL remain available without requiring graph artifacts.

#### Scenario: Adaptive graph cannot obtain a valid decision
- **WHEN** the model is unavailable, malformed, denied, or disabled at a checkpoint
- **THEN** the runtime SHALL continue with the last committed deterministic graph revision and record the fallback reason.
