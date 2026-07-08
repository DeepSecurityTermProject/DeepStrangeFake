# LLM Agent Runtime

This runtime turns the deterministic four-agent MVP into a configurable LLM
agent system while preserving offline mock mode.

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
