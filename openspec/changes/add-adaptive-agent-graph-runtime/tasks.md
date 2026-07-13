## 1. Current Runtime Characterization

- [x] 1.1 Add offline characterization tests for the current procedural agent, static scan, verification, evidence, and reporting invocation order.
- [x] 1.2 Capture normalized legacy summary, finding, evidence, artifact-category, and report-field fixtures for deterministic compatibility comparison.
- [x] 1.3 Add characterization tests for malformed LLM output, denied tool requests, optional service degradation, and required finalization failure.
- [x] 1.4 Add graph runtime mode configuration tests for `legacy`, `deterministic-graph`, `adaptive-graph`, invalid values, and serialization.

## 2. Graph Models and Validation

- [x] 2.1 Add failing tests for execution graph, node, edge, transition, retry, budget, lineage, and graph revision serialization.
- [x] 2.2 Implement schema-versioned graph models in a focused `graph_models` module using existing project serialization conventions.
- [x] 2.3 Implement a closed structured condition and predicate vocabulary without arbitrary expression or code evaluation.
- [x] 2.4 Add validator tests for duplicate IDs, missing dependencies, unregistered templates, invalid predicates, cycles, unreachable required terminals, and incompatible refs.
- [x] 2.5 Implement graph structural validation and stable topological ordering.
- [x] 2.6 Implement immutable graph revision and node transition records with correlation and causation refs.

## 3. Deterministic Template and Capability Catalog

- [x] 3.1 Add tests that map the current audit lifecycle to required and optional deterministic graph nodes.
- [x] 3.2 Implement a registered node-template catalog for agent, brokered tool, and internal runtime service executor kinds.
- [x] 3.3 Implement the versioned deterministic audit graph template with stable node priorities and required finalization paths.
- [x] 3.4 Add validation that required safety, evidence, and reporting templates cannot be removed or made unreachable.
- [x] 3.5 Persist and test deterministic template ID, schema version, normalized content hash, and initial graph artifact refs.

## 4. Sequential Graph Scheduler

- [x] 4.1 Add scheduler tests for readiness, unsatisfied dependencies, conditional routing, unreachable optional nodes, and stable tie-breaking.
- [x] 4.2 Implement the single-threaded dependency-driven scheduler and terminal graph-state detection.
- [x] 4.3 Implement typed immutable input-ref resolution and missing or incompatible ref failure behavior.
- [x] 4.4 Invoke agent nodes through `AgentRegistry`, tool nodes through `ToolBroker`, and service nodes through registered runtime handlers.
- [x] 4.5 Persist pending, runnable, running, succeeded, failed, skipped, fallback, and blocked transitions into task state, artifacts, and message events.
- [x] 4.6 Implement required and optional node failure handling, registered fallback edges, bounded retries, and scheduler iteration termination guards.

## 5. AgentRuntime Integration and Compatibility

- [x] 5.1 Extend `TaskState` and `RunState` with additive graph mode, node, dependency, attempt, lineage, revision, checkpoint, mutation, and execution-path refs.
- [x] 5.2 Keep old runtime state readable and add schema-version-aware graph state serialization tests.
- [x] 5.3 Refactor `AgentRuntime` into a compatibility facade that selects legacy or graph execution without duplicating graph scheduling logic.
- [x] 5.4 Keep `pipeline.run_audit()` and existing public summary fields compatible across runtime modes.
- [x] 5.5 Register existing validation, EvidenceBuilder, reporting, and VerificationEngine behavior as service handlers without reimplementing their policy.
- [x] 5.6 Add deterministic graph end-to-end tests that compare normalized outputs and required artifacts with the legacy characterization fixtures.

## 6. Mutation Contract and Policy Gate

- [x] 6.1 Add failing schema tests for mutation proposals, ordered operations, template parameters, policy outcomes, and committed revision refs.
- [x] 6.2 Implement the closed mutation operations for inserting registered templates, routing future edges, skipping optional nodes, bounded budget adjustment, and attaching approved context refs.
- [x] 6.3 Implement policy checks for registrations, target and read-only safety, validation level, future-only mutation, required nodes, graph structure, and remaining budgets.
- [x] 6.4 Implement graph-copy evaluation, per-operation decisions, final candidate validation, atomic accepted-subset commit, and immutable revision publication.
- [x] 6.5 Add deterministic translation for explicitly registered `AgentOutput.next_actions` values and ignore unknown advisory hints.
- [x] 6.6 Persist redacted mutation proposal, policy result, candidate diagnostics, commit or denial, budget delta, and fallback artifacts and events.

## 7. Bounded Adaptive Checkpoints

- [x] 7.1 Add checkpoint state and tests for eligibility, single-use defaults, per-checkpoint ceilings, and global replan ceilings.
- [x] 7.2 Implement the post-reconnaissance checkpoint with registered local-context and scan-refinement template options.
- [x] 7.3 Implement the post-analysis checkpoint with registered evidence-refinement, repeat-analysis, skip-optional, and verification-routing options.
- [x] 7.4 Represent repeated work as new acyclic node instances with iteration and parent lineage and reject every proposed back-edge.
- [x] 7.5 Keep the VerificationEngine PoC and LLM repair attempts inside one verification node and correlate its artifacts without graph-level attempt duplication.
- [x] 7.6 Fall back to the last committed graph for disabled, unavailable, malformed, policy-denied, over-budget, or persistence-failed adaptive decisions.

## 8. Replay, Reports, and Web Contracts

- [x] 8.1 Persist initial, candidate, committed, and final graph artifacts plus node-transition batches through `ArtifactStore` with existing redaction rules.
- [x] 8.2 Extend message events with graph ID, revision, node ID, checkpoint, proposal, policy, correlation, and causation refs.
- [x] 8.3 Implement side-effect-free graph replay that reconstructs revisions, actual node order, skipped branches, retries, fallbacks, and terminal status.
- [x] 8.4 Add replay tests for complete runs and incomplete or inconsistent artifacts without invoking agents, tools, Docker, MCP, or LLM providers.
- [x] 8.5 Add graph mode, versions, mutation counts, checkpoint counts, execution-path summary, fallback reason, and artifact refs to JSON and Markdown reports.
- [x] 8.6 Extend Web API serializers with additive graph summary fields and verify existing clients remain compatible when graph fields are absent.

## 9. Policy and Behavioral Acceptance Tests

- [x] 9.1 Prove an accepted registered mutation changes the agents or tools actually invoked and appears in task state, messages, artifacts, report, and replay.
- [x] 9.2 Prove denied unregistered, unsafe, completed-node, cyclic, and unreachable-report mutations execute no denied behavior and retain the prior revision.
- [x] 9.3 Prove node, graph size, retry, checkpoint, replan, token, tool, sandbox, and scheduler iteration ceilings terminate deterministically.
- [x] 9.4 Prove malformed model output, model unavailability, policy exceptions, and invalid candidate graphs fall back without partial mutation.
- [x] 9.5 Prove required artifact persistence failure prevents mutation commit and follows structured runtime failure or fallback semantics.
- [x] 9.6 Prove repeated offline runs with the same graph and normalized mock outcomes produce the same node order, revisions, policy results, and replay summary.
- [x] 9.7 Prove the default test suite needs no API key, network, Docker daemon, MCP service, target write, or live security target.

## 10. Rollout and Final Verification

- [x] 10.1 Document runtime modes, graph and mutation artifact locations, budgets, fallback behavior, and the distinction between adaptive scheduling and parallel execution.
- [x] 10.2 Add an opt-in bounded real-model graph-decision smoke command with redaction and explicit skip behavior when credentials or policy do not permit it.
- [x] 10.3 Run focused graph model, validator, scheduler, policy, replay, report, and Web contract tests and resolve all regressions.
- [x] 10.4 Run the complete offline test suite and record the command and passing result in the change validation notes.
- [x] 10.5 Demonstrate two distinct accepted graph paths on local defensive fixtures, verify that their actual invoked node sets differ, and verify replay matches each path.
- [x] 10.6 Compare legacy and deterministic graph outputs on representative local fixtures and document intentional additive differences only.
- [x] 10.7 Make deterministic graph mode the default only after compatibility gates pass, retain legacy rollback mode, and keep adaptive graph mode explicitly configurable.

## 11. P1 Review Corrections

- [x] 11.1 Route `deterministic-graph` and `adaptive-graph` through `GraphScheduler` in `AgentRuntime`, with real graph refs, tasks, transitions, and execution paths.
- [x] 11.2 Reject optional-node skips that make required execution or report finalization unreachable.
- [x] 11.3 Require ArtifactStore-issued local refs and enforce aggregate graph budgets across all nodes.
- [x] 11.4 Execute registered fallback paths before treating a required-node failure as terminal.
- [x] 11.5 Permit tightly scoped mutation from the active checkpoint and reconnect inserted refinement nodes into the future main path.
- [x] 11.6 Enforce graph-level `max_node_attempts` as a hard ceiling over per-node retry policy.
- [x] 11.7 Reject required input refs whose source is not a structural upstream dependency of the consumer.
