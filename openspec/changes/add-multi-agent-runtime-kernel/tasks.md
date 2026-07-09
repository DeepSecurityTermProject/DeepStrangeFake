## 1. Runtime Models and Test Scaffolding

- [x] 1.1 Add offline unit tests for `RunState`, `TaskState`, task status transitions, fallback reasons, artifact refs, and message refs.
- [x] 1.2 Add runtime state models with stable IDs, timestamps, terminal statuses, error details, and serialization helpers.
- [x] 1.3 Add tests for `AgentInvocation` input/output contracts and structured role outputs.
- [x] 1.4 Add `AgentInvocation` and role output models without changing the existing agent classes yet.
- [x] 1.5 Add compatibility tests that capture current `run_audit()` summary fields, report files, key artifact directories, and replay output.

## 2. Agent Registry and Runtime Kernel

- [x] 2.1 Add tests for registering required agent roles, rejecting duplicates, and reporting missing roles.
- [x] 2.2 Implement `AgentRegistry` with role metadata, callable adapters, and required-role validation.
- [x] 2.3 Add tests for `AgentRuntime` initialization, service wiring, run start/finalize events, and persisted runtime state.
- [x] 2.4 Implement `AgentRuntime` skeleton that creates run context, message bus, artifact store, tool broker, and run state.
- [x] 2.5 Add agent adapters for Orchestrator, Recon, Analysis, and Verification that wrap existing agent methods behind the invocation contract.

## 3. ArtifactStore and ToolBroker Services

- [x] 3.1 Add tests for `ArtifactStore` typed writes, immutable paths, redaction, returned refs, and runtime state persistence.
- [x] 3.2 Implement `ArtifactStore` as a typed facade over `RunContext.write_json_artifact()` and existing prompt/LLM/decision persistence helpers.
- [x] 3.3 Add tests for `ToolBroker` permitted tool dispatch, denied tool requests, budget exhaustion, missing tools, and timeout/degraded results.
- [x] 3.4 Implement `ToolBroker` around `ToolRuntime`, including safe argument materialization for repository, source context, pattern scan, memory, MCP, and validation requests.
- [x] 3.5 Add message bus events for artifact writes, tool dispatch, tool denials, service degradation, and broker fallback.

## 4. Pipeline Migration

- [x] 4.1 Move run setup, metadata persistence, message bus setup, memory indexing, scanner invocation, and MCP dependency intelligence into `AgentRuntime` services.
- [x] 4.2 Move deterministic Orchestrator, Recon, Analysis, and Verification sequencing into `AgentRuntime` while preserving existing outputs.
- [x] 4.3 Move prompt rendering, LLM request/response persistence, schema validation, and decision proposal creation into runtime task steps.
- [x] 4.4 Move policy-gate, merge, fallback, and decision artifact persistence into runtime task steps with `TaskState` links.
- [x] 4.5 Move Recon LLM tool request dispatch from pipeline helper functions into `ToolBroker`.
- [x] 4.6 Reduce `pipeline.py` to a thin compatibility adapter that delegates to `AgentRuntime` and returns the same public summary.

## 5. Replay, Reporting, and Integration

- [x] 5.1 Extend message replay summaries with runtime run/task state, task statuses, service failures, and fallback reasons.
- [x] 5.2 Extend JSON reports with runtime task refs and run-state artifact refs without removing existing report fields.
- [x] 5.3 Extend Markdown reports only where useful with concise runtime provenance for decisions and fallback.
- [x] 5.4 Update docs to explain AgentRuntime, AgentRegistry, RunState/TaskState, ToolBroker, ArtifactStore, and how to inspect runtime artifacts.
- [x] 5.5 Update integration smoke so mock and live LLM decision runs exercise the runtime kernel path.

## 6. Verification and Cleanup

- [x] 6.1 Run focused runtime model, registry, broker, artifact store, and pipeline compatibility tests.
- [x] 6.2 Run the full offline unit test suite.
- [x] 6.3 Run a mock runtime scan with `--runtime --llm-decisions` and verify reports, runtime state, decisions, and replay output.
- [x] 6.4 Run opt-in live LLM decision smoke when credentials are configured.
- [x] 6.5 Run `openspec validate "add-multi-agent-runtime-kernel" --strict` and update task status.
