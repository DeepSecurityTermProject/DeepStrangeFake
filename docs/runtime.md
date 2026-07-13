# LLM Agent Runtime

This runtime turns the deterministic four-agent MVP into a configurable LLM
agent system while preserving offline mock mode.

## Execution Graph Modes

The runtime exposes three explicit modes:

- `deterministic-graph` is the default and runs the versioned audit DAG through the single-threaded scheduler.
- `adaptive-graph` starts from the same DAG and permits bounded, policy-approved future-node expansion at post-recon and post-analysis checkpoints.
- `legacy` retains the previous procedural pipeline as a rollback mode.

Select a mode with `audit-agent scan --graph-mode <mode>`. Adaptive scheduling changes the validated path; it does not run nodes in parallel and does not grant new tools, network access, target writes, or executable model-authored behavior.

Graph runs store immutable artifacts under `runs/<run>/graphs/`: the initial graph, transition batches, redacted mutation proposals and policy outcomes, committed revisions, final graph, execution summary, and side-effect-free replay. `runtime_state/state.json` contains additive graph refs, checkpoint counts, fallback reason, and the actual execution path. JSON and Markdown reports contain a concise graph summary and refs.

Adaptive decisions use the strict `orchestrator.graph-decision.v1` schema. Post-recon supports bounded local-context and scan refinement. Post-analysis supports evidence refinement, repeat analysis, optional-node skipping with a safe bypass, and verification routing. Unknown fields/actions, malformed output, provider failure, policy denial, invalid candidates, budget exhaustion, and mutation persistence failure retain the last committed graph.

Limits include maximum nodes, scheduler iterations, attempts per node, replans, checkpoints, LLM tokens, tool calls, and sandbox starts. VerificationEngine's PoC and constrained repair loop remain inside one `validation` graph-node attempt; their artifacts are correlated to that task without graph-level retry duplication.

The optional real-provider contract smoke is separately gated:

```powershell
$env:AUDIT_AGENT_RUN_GRAPH_SMOKE = "1"
audit-agent graph-decision-smoke --live --provider openai-compatible --model <configured-model>
```

It accepts only a local path below `fixtures/`, disables MCP, memory, and sandbox execution, and caps provider usage at 8 requests and 50,000 tokens while preserving any lower configured limit. The command returns `passed` only when the run succeeds and at least one graph-decision checkpoint completes without a fallback; it reports successful and fallback decision counts separately. Without every opt-in/configuration prerequisite it returns `status: skipped` without making a provider request.

## Runtime Kernel

`audit_agent.runtime.AgentRuntime` is now the single orchestration layer behind
`audit_agent.pipeline.run_audit()`. The old public entrypoint is kept for CLI and
test compatibility, but run setup, task sequencing, service calls, fallback, and
finalization flow through the runtime kernel.

The kernel uses these backend contracts:

- `AgentRegistry` registers the Orchestrator, Recon, Analysis, and Verification
  role adapters and rejects duplicate or missing required roles.
- `RunState` stores run status, final summary, artifact refs, message refs, and
  the ordered task list.
- `TaskState` stores per-role task status, input/output refs, artifact refs,
  message refs, errors, and fallback reasons.
- `ArtifactStore` wraps run artifact writes, immutable filenames, prompt/LLM and
  decision persistence, redaction, and `runtime.artifact` events.
- `ToolBroker` wraps the tool protocol, materializes safe context arguments,
  enforces permissions/budgets, and records `runtime.tool` or
  `runtime.tool.denied` events.

Each runtime run writes `runtime_state/state.json`. This file is the fastest way
to inspect who ran, which task produced each artifact, and whether a task used a
fallback path.

## LLMClient

`audit_agent.llm` defines a provider-neutral client contract. Mock mode requires
no API key. Real OpenAI-compatible mode reads the key from `OPENAI_API_KEY` by
default and records normalized request/response artifacts under `llm/`.

## Prompt Templates

`audit_agent.prompts` provides versioned templates for Orchestrator, Recon,
Analysis, and Verification. Each render record stores the template ID, version,
required variables, output schema, safety constraints, and rendered prompt.

## Tool Protocol

`audit_agent.tool_protocol` normalizes tool declarations and tool calls.
Permission groups and per-agent budgets prevent agents from directly invoking
unsafe tools. Denied calls, missing tools, timeouts, and budget exhaustion are
structured results.

## MCP Client

`audit_agent.mcp_client` implements stdio MCP session startup, tool discovery,
structured calls, and degraded behavior. `CveMcpClient` wraps
`mukul975/cve-mcp-server` style operations and converts responses into
contextual vulnerability-intelligence records.

Live integration uses `.env` values for model API settings and a local
`cve-mcp-server` checkout/venv command. The preflight command writes redacted
JSON and Markdown reports under `runs/integration/`:

```powershell
.\.venv\Scripts\python.exe -m audit_agent integration preflight --llm --mcp --output runs
```

## RAG Memory

`audit_agent.memory` implements deterministic lexical retrieval and a fallback
embedding-store interface. Memory records include namespace, target, path, line
range, content hash, artifact reference, and citation.

## Message Bus

`audit_agent.message_bus` provides in-process publish/subscribe routing and an
append-only JSONL log. The `replay` CLI command summarizes message logs for
traceability.

Replay summaries include both `decision_lifecycle` and `runtime_lifecycle`.
`runtime_lifecycle` groups task status counts, tool calls, denials, artifacts,
service failures, and fallback reasons by role.

## LLM Decision Loop

`audit_agent.decisions` promotes model output from auxiliary notes into guarded
decision proposals. Orchestrator, Recon, Analysis, and Verification each use a
role-specific JSON contract with confidence, rationale, selected actions,
requested tools, and evidence refs. A deterministic policy gate checks local
evidence, contextual-only memory/CVE refs, role tool permissions, tool budgets,
validation levels, and live-target restrictions before merge.

Final outputs keep an explicit `decision_source`: `llm`, `deterministic`,
`merged`, `fallback`, or `policy-denied`. Malformed, low-confidence, unsafe, or
over-budget proposals are persisted and then routed to deterministic fallback.
Decision artifacts are written under `decisions/` and linked from reports and
message replay.

## Example

```powershell
.\.venv\Scripts\python.exe -m audit_agent scan --target . --runtime --llm-provider mock --memory-mode lexical --mcp-mode degraded
.\.venv\Scripts\python.exe -m audit_agent scan --target . --runtime --llm-provider mock --llm-decisions --memory-mode lexical --mcp-mode degraded
.\.venv\Scripts\python.exe -m audit_agent replay --messages runs\<run>\messages\messages.jsonl
```
