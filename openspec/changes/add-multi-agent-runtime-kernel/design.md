## Context

The current runtime has grown organically from the original four-agent MVP. `pipeline.py` now performs repository analysis, run creation, message bus setup, memory retrieval, MCP calls, pattern scanning, agent invocation, prompt rendering, LLM calls, decision policy/merge, tool dispatch, validation, evidence construction, report generation, and runtime summary assembly. This has kept the prototype moving quickly, but it makes the orchestration path hard to reuse, test in isolation, or extend with new agents.

The existing modules already contain the right building blocks: `MessageBus`, `RunStore`, `ToolRuntime`, `LLMClient`, prompt rendering, decision policy gates, memory, MCP, validation, and reporting. This change turns those pieces into runtime services behind an `AgentRuntime` kernel without changing the security model or the public CLI behavior.

## Goals / Non-Goals

**Goals:**
- Extract orchestration from `pipeline.py` into a reusable `AgentRuntime`.
- Add an `AgentRegistry` so agents are invoked by role through a stable interface.
- Represent run and task progress with explicit `RunState` and `TaskState` records.
- Route agent tool requests through a `ToolBroker` instead of ad hoc runtime helper functions.
- Route artifact writes through an `ArtifactStore` that wraps `RunStore` and records artifact refs.
- Preserve existing `run_audit()` output, CLI flags, reports, decision artifacts, and safety checks.
- Make failures and fallback visible as runtime state, message bus events, and artifacts.

**Non-Goals:**
- Do not introduce an external agent framework.
- Do not redesign the four-agent security workflow.
- Do not remove deterministic scanners, decision policy gates, memory, MCP, validation, or report generation.
- Do not make agent execution concurrent in the first implementation.
- Do not change live exploitation or sandbox permissions.

## Decisions

### Decision 1: Add a Small Runtime Kernel Instead of a Large Framework

Create `AgentRuntime` as a narrow orchestration layer that coordinates existing services. It should own lifecycle steps such as `initialize_run`, `invoke_agent`, `dispatch_tool`, `persist_artifact`, `record_fallback`, and `finalize_run`, but delegate domain work to existing agents and services.

Alternative considered: replace the pipeline with a full agent framework. That would be more ambitious but would add unnecessary moving parts and weaken the current reproducibility story.

### Decision 2: Keep `run_audit()` as the Compatibility Boundary

`run_audit(target, config, output_dir)` remains the public API used by CLI, integration smoke, benchmark, and tests. Internally it should construct `AgentRuntime` and return the same summary fields.

Alternative considered: make callers instantiate `AgentRuntime` directly. That is cleaner for new code but creates unnecessary migration work for current users.

### Decision 3: Use Registry-Based Agent Invocation

Agents should be registered by role name, capability metadata, and callable adapter. The registry allows the runtime to invoke `orchestrator`, `recon`, `analysis`, `verification`, and future roles without hard-coding every transition in `pipeline.py`.

Alternative considered: keep direct class construction in the runtime. That is simpler initially, but it repeats the current coupling problem in a new file.

### Decision 4: Make Run and Task State First-Class

Add `RunState` and `TaskState` records with stable IDs, status, role, input refs, output refs, message refs, artifact refs, started/finished timestamps, error details, and fallback reason. These records should be persisted and replayable.

Alternative considered: rely on message events only. Message events are useful but do not provide a compact current-state view or a reliable task transition model.

### Decision 5: Wrap Existing ToolRuntime with ToolBroker

`ToolBroker` should validate agent requests, materialize safe runtime arguments, call `ToolRuntime`, publish tool events, and return normalized results. It should not let agents call Python functions directly or bypass policy.

Alternative considered: move all tool policy into `ToolRuntime`. The broker is preferred because it can translate agent-level requests into concrete tool calls while keeping low-level permission and budget checks in `ToolRuntime`.

### Decision 6: Wrap RunStore with ArtifactStore

`ArtifactStore` should provide typed helpers such as `write_metadata`, `write_prompt`, `write_llm_response`, `write_decision`, `write_tool_result`, `write_handoff`, `write_findings`, and `write_report`. It should return artifact refs and apply redaction where needed.

Alternative considered: keep `run.write_json_artifact()` calls throughout the runtime. That preserves current behavior but does not create a reusable persistence boundary.

### Decision 7: Migrate Incrementally

The first implementation should move orchestration in slices while keeping tests green: introduce models/services, wire the deterministic path, then LLM decision mode, then reporting and integration smoke. At each step, output artifacts and report summaries should match current behavior unless new runtime state fields are explicitly added.

## Risks / Trade-offs

- [Risk] The extraction may accidentally change audit behavior. -> Add compatibility tests around `run_audit()` summary, reports, artifacts, and replay.
- [Risk] New abstractions could become thin wrappers with no value. -> Keep responsibilities explicit: runtime schedules, registry invokes, broker dispatches tools, store persists artifacts.
- [Risk] State records may duplicate message logs. -> State captures current and final task status; message logs capture event history. Reports can link both.
- [Risk] Tool argument materialization could remain tangled. -> Move `_materialize_tool_arguments` into `ToolBroker` and test each supported tool request.
- [Risk] Live LLM behavior is variable. -> Keep default tests mock/offline and keep live smoke opt-in.

## Migration Plan

1. Add runtime state models and service skeletons without changing `run_audit()`.
2. Add focused unit tests for `AgentRegistry`, `RunState`, `TaskState`, `ToolBroker`, and `ArtifactStore`.
3. Move run setup, message bus setup, and artifact writes behind `AgentRuntime` and `ArtifactStore`.
4. Move deterministic four-agent sequencing into `AgentRuntime`.
5. Move LLM prompt/response, decision proposal, policy, merge, and fallback handling into runtime task steps.
6. Move Recon tool dispatch through `ToolBroker`.
7. Update replay/report runtime summaries to include run/task state refs.
8. Keep `pipeline.py` as a thin adapter around `AgentRuntime`.
9. Run unit tests, mock runtime scan, live LLM decision smoke, and OpenSpec validation.

Rollback is straightforward: keep the previous `pipeline.py` behavior behind tests until the runtime adapter is fully green; if the migration fails, callers can continue to use the old procedural path while the new runtime is disabled.

## Open Questions

- Should `AgentRuntime` expose a public Python API beyond `run_audit()`, or stay internal until the benchmark runner needs direct control?
- Should task state be persisted as one `runtime/state.json` file, one file per task, or both?
- Should the first runtime support retry policies, or only record retry-ready metadata while preserving current single-pass behavior?
