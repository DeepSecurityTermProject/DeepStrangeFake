## Context

The runtime kernel already provides `AgentRegistry`, `AgentInvocation`, `AgentOutput`, `RunState`, `TaskState`, `ToolBroker`, `ArtifactStore`, message events, policy-gated LLM decisions, and deterministic fallback. However, `AgentRuntime.run_audit()` still owns a fixed sequence of direct calls to Orchestrator, Recon, scanning, Analysis, Verification, validation, evidence, and reporting. `AgentOutput.next_actions` is persisted as advisory data but does not schedule work.

This change moves execution control into an adaptive graph without weakening the project's defensive, read-only safety model. Model output remains untrusted. The runtime must preserve existing offline behavior, verification sandbox policy, report contracts, and deterministic operation when adaptive participation is disabled.

## Goals / Non-Goals

**Goals:**

- Represent the audit workflow as a validated, schema-versioned execution graph.
- Execute graph nodes through existing agent and runtime service boundaries.
- Support bounded evidence refinement and replanning at explicit checkpoints.
- Make every graph mutation and actual node transition policy-controlled and replayable.
- Preserve current deterministic outputs and fallback behavior.
- Split graph concerns out of the growing `runtime.py` module behind a compatible `AgentRuntime` facade.

**Non-Goals:**

- Parallel or distributed node execution.
- Free-form creation or loading of agents, tools, Python code, shell commands, or predicates.
- Arbitrary cyclic graphs or unlimited autonomous loops.
- Cross-process checkpoint resume or exactly-once distributed execution.
- Replacing the existing VerificationEngine PoC generation, Docker execution, or bounded LLM repair loop.
- Adding LangGraph, CrewAI, or another orchestration dependency.
- Expanding permission to scan live targets, write to target repositories, or generate offensive payloads.

## Decisions

### 1. Use a local schema-versioned execution graph

Add graph models in a focused module rather than embedding opaque dictionaries in `RunState`:

- `ExecutionGraph`: schema version, graph ID, run ID, revision, mode, nodes, edges, checkpoint counters, global budgets, and artifact refs.
- `GraphNode`: stable node ID, registered template ID, executor kind, role or service, typed input refs, expected output keys, required flag, node budget, retry policy, lineage, attempt count, status, and timestamps.
- `GraphEdge`: source and destination IDs, dependency type, terminal outcome, and a structured condition from a closed predicate vocabulary.
- `GraphTransition`: immutable lifecycle event containing graph revision, node ID, old and new status, cause, correlation refs, and timestamp.

Conditions SHALL use registered predicates over normalized node outcomes, such as status, output-presence, finding-count, or verification-status. They SHALL NOT contain source code, templates, arbitrary expressions, or model-authored commands.

Alternative considered: reuse free-form dictionaries and `next_actions`. Rejected because they cannot provide schema validation, dependency safety, stable replay, or reliable compatibility tests.

### 2. Start from a deterministic template

Every run starts from a versioned graph template that represents the current audit lifecycle. Agent nodes invoke registered role adapters. Tool nodes dispatch predefined requests through `ToolBroker`. Runtime service nodes call registered internal handlers for validation, evidence, and reporting.

The template is the fallback path and remains valid without an LLM. Adaptive mode mutates only future optional work around this baseline; required report finalization and safety services cannot be removed.

Alternative considered: let the Orchestrator create the whole graph. Rejected because malformed or adversarial model output could omit required stages, invent capabilities, and make fallback non-deterministic.

### 3. Use a deterministic sequential scheduler

Add a scheduler that repeatedly:

1. validates the current graph revision;
2. derives runnable nodes whose dependencies and conditions are satisfied;
3. selects one node by deterministic template priority and stable node ID;
4. marks it running and invokes the registered executor;
5. persists outputs and transitions before selecting the next node;
6. marks unreachable optional nodes skipped and detects terminal success or failure.

Required node failure without an approved fallback terminates the run with structured diagnostics. Optional node failure follows a registered fallback edge or is skipped. Scheduler iteration, node, retry, and replan ceilings provide a final termination guard.

Alternative considered: add parallel scheduling immediately. Rejected because concurrent artifact writes, budget accounting, mutation races, and replay ordering would obscure whether the basic adaptive control flow is correct.

### 4. Mutations use a closed operation and template catalog

The Orchestrator may return a `GraphMutationProposal` only at registered checkpoints. A proposal contains ordered operations from a closed vocabulary:

- insert a registered node template after a future node;
- route a future conditional edge to a registered template;
- skip an optional future node with a reason;
- adjust a future node budget within configured ceilings;
- attach approved focus or context refs to a future node.

The proposal cannot name a callable, tool implementation, command, file write, arbitrary predicate, or unregistered role. Existing `AgentOutput.next_actions` may be translated into a proposal only by a deterministic adapter and never executes directly.

Policy evaluates operations in order against a graph copy, records per-operation outcomes, validates the complete candidate graph, and atomically commits the accepted safe subset only if the resulting graph is valid. Otherwise, the original revision remains active.

Alternative considered: apply model-generated patches to graph JSON. Rejected because field-level patching exposes internal state and permits bypass of template and policy constraints.

### 5. Model refinement as bounded DAG expansion

The first version allows replanning after reconnaissance and after initial analysis. Each checkpoint is invoked at most once by default, with a configurable global maximum no greater than the policy ceiling. Mutations can append a registered context-gathering or analysis-refinement node with lineage back to the triggering node.

No mutation may alter a running or completed node, introduce a back-edge, or create a cycle. Repeated work is represented as a new node instance with a higher iteration number. Existing VerificationEngine PoC repair remains an encapsulated bounded sub-loop inside one verification node and is not expanded into graph-level retries.

Alternative considered: permit cycles with counters. Rejected for the MVP because persisted DAG expansion makes termination, lineage, and replay easier to verify.

### 6. Extend existing state and artifact services

`TaskState` gains graph node ID, graph revision, dependency refs, attempt, lineage, and transition refs. `RunState` gains graph mode, active and final graph refs, mutation refs, checkpoint counts, and actual execution path.

`ArtifactStore` persists immutable initial graph, mutation proposal, policy result, committed revision, transition batch, and final graph summary artifacts. The message bus publishes correlated graph-created, node-ready, node-started, node-finished, mutation-proposed, mutation-denied, mutation-committed, fallback, and graph-finalized events.

Replay reconstructs the actual path from persisted transitions without invoking agents, tools, Docker, MCP, or model APIs. Reports expose a concise graph summary and references rather than embedding every raw artifact.

Alternative considered: store only the final graph. Rejected because it cannot explain denied proposals, skipped branches, retries, or the path actually executed.

### 7. Preserve a compatibility and rollback path

Introduce an explicit runtime mode with `legacy`, `deterministic-graph`, and `adaptive-graph` values. During migration, existing callers retain their current behavior unless graph mode is selected. After characterization and parity tests pass, `deterministic-graph` can become the default while `legacy` remains an emergency rollback path for this change.

Adaptive graph mode without an available or valid LLM decision falls back to the deterministic graph, not to a partially mutated graph. Public `pipeline.run_audit()` and current report fields remain compatible.

Alternative considered: replace the procedural runtime in one step. Rejected because a staged mode switch allows direct output comparison and low-risk rollback.

### 8. Keep module ownership explicit

Add focused modules such as `graph_models.py`, `graph_templates.py`, `graph_policy.py`, `graph_scheduler.py`, and `graph_replay.py`. `runtime.py` remains the facade and composition root. Agent behavior remains in agent adapters, tool permissions remain in `ToolBroker`, and sandbox validation remains in VerificationEngine and runner components.

This prevents the scheduler from becoming a second policy, tool, or verification implementation.

## Risks / Trade-offs

- [The feature is called adaptive but starts single-threaded] -> Document that adaptation concerns path selection and bounded refinement; defer concurrency until state and replay semantics are proven.
- [Graph JSON exists but does not drive behavior] -> Require tests that compare invoked roles, tools, transitions, and artifacts across distinct accepted graph paths.
- [LLM proposals create non-deterministic paths] -> Use closed templates, deterministic policy, stable scheduling, immutable proposal artifacts, and a deterministic fallback graph.
- [Refinement grows indefinitely] -> Enforce graph size, depth, node attempt, checkpoint, replan, token, tool, and scheduler iteration ceilings.
- [Partial mutation leaves an invalid graph] -> Validate on a copy and atomically commit only a complete valid revision.
- [Refactoring the runtime changes findings or reports] -> Add characterization and golden compatibility tests before switching the default mode.
- [State schemas break old runs or Web consumers] -> Add schema versions and optional additive report fields; replay old runs through the current compatibility path.
- [Verification retries are counted twice] -> Treat VerificationEngine as one graph node with its own internal attempt artifacts and separate graph-level retry policy.

## Migration Plan

1. Capture characterization tests and run artifacts for the current fixed workflow.
2. Add graph models, validation, templates, and serialization with no execution change.
3. Add the sequential scheduler and run the deterministic template behind `deterministic-graph` mode.
4. Compare deterministic graph results and artifacts with legacy mode; fix parity regressions.
5. Add mutation policy, mock Orchestrator proposals, and bounded checkpoints behind `adaptive-graph` mode.
6. Extend replay, reports, and Web API serialization with additive graph summaries.
7. Make deterministic graph mode the default only after offline compatibility and failure tests pass; retain legacy mode for rollback during this change.

Rollback selects `legacy` mode and leaves graph artifacts unread but intact. No target repository or persistent external service migration is required.

## Open Questions

- The detailed Web graph visualization is deferred; this change guarantees report and API graph summaries plus artifact references.
- Cross-process resume and parallel execution need separate designs after scheduler state and replay have been exercised on real benchmark runs.
