## Why

The current audit flow works end to end, but orchestration concerns are concentrated in `pipeline.py`: run creation, agent ordering, prompt/LLM calls, tool dispatch, state mutation, artifact writes, message events, and fallback handling all live in one procedural path. As the system adds real LLM decision participation, MCP, memory, validation, and replay, those runtime mechanics need to become reusable backend capabilities instead of one-off pipeline glue.

## What Changes

- Introduce a Multi-Agent Runtime Kernel that owns run lifecycle, task scheduling, agent invocation, state transitions, fallback policy, and runtime service wiring.
- Add an `AgentRegistry` contract so Orchestrator, Recon, Analysis, Verification, and future agents can be registered, discovered, and invoked through a stable interface.
- Add explicit `RunState` and `TaskState` records that capture agent status, inputs, outputs, retries, failure modes, fallback decisions, and artifact/message references.
- Add a `ToolBroker` facade over the existing tool protocol so agents request tools through a single runtime service with permission, budget, timeout, and denial handling.
- Add an `ArtifactStore` facade over the existing `RunStore`/artifact directories so runtime code writes prompts, LLM responses, decisions, tool outputs, handoffs, findings, evidence, and reports through one typed boundary.
- Keep existing CLI behavior and report outputs compatible; `run_audit()` remains the public entry point but delegates orchestration to the runtime kernel.
- Preserve the current evidence-first safety model: LLM proposals, MCP/RAG context, and validation decisions still pass through deterministic policy gates and fallback.

## Capabilities

### New Capabilities

- `multi-agent-runtime-kernel`: Defines the reusable `AgentRuntime` execution model, lifecycle hooks, failure handling, and compatibility boundary with `run_audit()`.
- `agent-registry-and-run-state`: Defines `AgentRegistry`, `AgentInvocation`, `RunState`, and `TaskState` contracts for tracking who runs, what they receive, what they emit, and how state flows between agents.
- `runtime-tool-and-artifact-services`: Defines `ToolBroker` and `ArtifactStore` services that agents and the runtime use for tool calls, artifact persistence, message refs, and fallback-safe diagnostics.

### Modified Capabilities

- `guarded-agent-decision-loop`: LLM decision participation shall execute through the runtime kernel rather than direct `pipeline.py` helper calls.
- `decision-auditability-and-replay`: Replay and reports shall include runtime run/task state and kernel-mediated service events in addition to existing decision lifecycle events.

## Impact

- Affected code: `audit_agent/pipeline.py`, new runtime modules under `audit_agent/runtime*.py` or `audit_agent/runtime/`, `audit_agent/agents.py`, `audit_agent/tool_protocol.py`, `audit_agent/storage.py`, `audit_agent/message_bus.py`, `audit_agent/decisions.py`, reporting, integration smoke, and tests.
- Public API: `run_audit(target, config, output_dir)` remains stable; new runtime classes become internal but testable backend APIs.
- Data model: add run/task state records and service result metadata; existing findings, evidence chains, reports, and decision artifacts remain compatible.
- Tests: add unit tests for registry, state transitions, tool broker denial/fallback, artifact store writes, kernel orchestration, and backward-compatible CLI/pipeline output.
- Dependencies: no new external dependency is required.
