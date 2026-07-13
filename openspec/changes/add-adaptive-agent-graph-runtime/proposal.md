## Why

The runtime already exposes registered agent adapters, structured task state, brokered tools, artifacts, and `next_actions`, but `AgentRuntime.run_audit()` still invokes the audit stages through a fixed procedural sequence. To become a genuinely adaptive multi-agent runtime, execution order and bounded refinement need to be driven by a policy-controlled graph whose actual path is observable, reproducible, and safe by default.

## What Changes

- Add a schema-versioned execution graph with stable nodes, dependency and conditional edges, typed inputs and outputs, budgets, retry limits, and terminal states.
- Add a deterministic sequential scheduler that executes runnable graph nodes through the existing `AgentRegistry`, `ToolBroker`, `ArtifactStore`, message bus, and run/task state services.
- Build every audit from a compatible deterministic graph template and allow the Orchestrator to propose only bounded mutations from a registered capability and node-template catalog.
- Add policy gates for graph mutations, including role and tool registration, dependency validity, node and replan limits, budget ceilings, safety configuration, and deterministic fallback.
- Add explicit, bounded replanning checkpoints after reconnaissance and initial analysis so the runtime can gather more evidence, repeat analysis, skip irrelevant optional work, or route findings into verification without permitting arbitrary or unbounded loops.
- Persist the initial graph, mutation proposals, policy decisions, node transitions, actual execution path, fallback reasons, and final graph summary for replay and reporting.
- Preserve the current deterministic four-agent behavior when adaptive execution or LLM participation is disabled.
- Keep execution single-threaded in this change; parallel scheduling, free-form agent creation, cross-process resume, and arbitrary cyclic graphs remain out of scope.

## Capabilities

### New Capabilities
- `adaptive-agent-execution-graph`: Defines graph models, deterministic graph templates, dependency-driven scheduling, node lifecycle, bounded refinement, and compatibility behavior.
- `graph-mutation-policy-and-budgets`: Defines the registered mutation surface, graph validation, safety and budget gates, bounded replanning, denial behavior, and deterministic fallback.

### Modified Capabilities
- `guarded-agent-decision-loop`: Extends validated Orchestrator decisions from supported plan fields to bounded execution-graph mutation proposals at explicit replanning checkpoints.
- `decision-auditability-and-replay`: Extends persisted decision evidence and replay output to include graph definitions, mutations, policy outcomes, node transitions, and the actual execution path.

## Impact

- Refactors orchestration responsibilities currently concentrated in `audit_agent/runtime.py` into graph models, templates, policy, scheduler, and replay components while retaining `AgentRuntime` as the compatibility facade.
- Extends runtime task and run-state serialization with graph, node, dependency, attempt, and causation metadata.
- Extends Orchestrator decision contracts and policy-gate handling; untrusted model output never directly creates executable agents, tools, commands, or code.
- Reuses existing agent adapters, verification engine and PoC repair sub-loop, tool permissions, sandbox controls, artifact redaction, reports, and Web APIs.
- Requires deterministic offline characterization, mutation, budget, fallback, replay, and compatibility tests; real-model smoke remains optional and bounded.
