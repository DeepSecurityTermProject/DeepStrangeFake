## Context

The current implementation is a Python 3.12 CLI-first security audit MVP. It already has repository analysis, deterministic scanners, four role classes, structured findings, validation levels, evidence chains, reports, and benchmark configuration. However, the four agents are deterministic Python wrappers; the system does not yet have a real model client, prompt templates, tool-call negotiation, MCP sessions, retrieval memory, or a message bus.

This change upgrades the existing pipeline into a real LLM agent runtime while preserving the coursework-friendly offline path. The implementation must keep deterministic tests and mock mode available, because users may not always have API keys, network access, MCP servers, embedding providers, or external scanners installed.

The architecture continues to be evidence-first: LLM output, MCP intelligence, and retrieved memory are context sources. They must not confirm findings without local code/dependency evidence and Verification approval.

## Goals / Non-Goals

**Goals:**

- Add a provider-neutral `LLMClient` abstraction with mock and real provider implementations.
- Make prompt construction explicit through versioned templates and schema-bound outputs for each agent role.
- Standardize tool calls across local tools, external command adapters, MCP tools, RAG retrieval, and validation tools.
- Replace the placeholder CVE MCP command invocation with a real MCP client abstraction, beginning with stdio transport.
- Add a RAG memory layer for repository slices, tool outputs, findings, evidence, and optional external notes.
- Add an in-process message bus that records structured events, routes agent/tool/memory interactions, and supports replay/audit.
- Preserve existing CLI usage, run directory structure, safety constraints, and deterministic unit tests.

**Non-Goals:**

- Do not build a web UI or distributed worker system in this change.
- Do not require one specific LLM vendor; provider adapters must be swappable.
- Do not require network access for tests.
- Do not allow model output, MCP data, or retrieved memory to bypass local evidence requirements.
- Do not implement autonomous patch generation or remediation pull requests.
- Do not replace the existing evidence/reporting model; extend it with runtime traces.

## Decisions

### Decision 1: Add Runtime Modules Around the Current Pipeline

Create focused modules instead of growing `agents.py` and `pipeline.py`:

- `audit_agent/llm.py`: provider-neutral client interface, request/response models, retry/timeout behavior, JSON parsing, and mock provider.
- `audit_agent/prompts.py`: template registry, template rendering, prompt versioning, output schemas, and fixture loading.
- `audit_agent/tool_protocol.py`: tool declaration, tool call, tool result, permissions, budgets, and normalization.
- `audit_agent/mcp_client.py`: MCP client interface, stdio session management, tool discovery, calls, degraded mode, and a CVE wrapper.
- `audit_agent/memory.py`: indexing, chunking, deterministic local retrieval, optional embedding provider, citations, and invalidation.
- `audit_agent/message_bus.py`: event envelopes, correlation IDs, append-only logging, subscriptions, replay, and trace linking.

This keeps each boundary testable and avoids turning a single agent file into the whole runtime.

Alternative considered: integrate a full framework such as LangGraph, AutoGen, or CrewAI. That would accelerate orchestration, but it adds framework-specific concepts before the project has stable contracts. The runtime should be small and explicit first.

### Decision 2: LLMClient Is Provider-Neutral and Mock-First

The first contract is:

1. Render a prompt from a versioned template.
2. Send an `LLMRequest` through a configured client.
3. Receive an `LLMResponse` with text, optional JSON, usage, provider metadata, latency, and raw response.
4. Validate role-specific JSON output before it becomes a finding, handoff, or decision.
5. Persist request/response artifacts and usage counters.

Provider adapters can include OpenAI-compatible HTTP, local Ollama-compatible HTTP, and deterministic mock. API keys are read from config-indicated environment variables, not hardcoded files.

Alternative considered: call one vendor directly inside agents. That is simpler, but it would make tests brittle and make local/offline coursework runs hard.

### Decision 3: Prompts Are Versioned Runtime Artifacts

Each agent role gets templates for system, task, tool-use, and output-format instructions. Templates declare required variables, allowed tool groups, expected JSON schema, safety constraints, and version IDs. Rendered prompts are written to run artifacts so a finding can be reproduced from the exact prompt and context.

Alternative considered: embed prompts as long Python strings in agent classes. That is faster initially, but difficult to diff, test, and cite in evidence chains.

### Decision 4: Tool Calls Use One Protocol

Agents should not call arbitrary Python functions directly once LLM mode is enabled. A model emits a structured `ToolCallRequest`, the runtime checks permissions and budgets, the registry dispatches the tool, and the result returns as a `ToolCallResult`. This protocol covers repository search, source slicing, pattern scanning, external scanners, MCP calls, RAG retrieval, and validation actions.

Tool results must include normalized observations and raw artifacts. Failures, timeouts, missing tools, permission denials, and budget exhaustion are first-class results, not crashes.

Alternative considered: let each agent decide how to call each tool. That would make auditing difficult and duplicate safety checks.

### Decision 5: MCP Client Uses Real Sessions With Degraded Mode

The MCP runtime starts with stdio transport because `mukul975/cve-mcp-server` is commonly launched as a local process. The client performs initialization, lists tools, invokes named tools with structured JSON arguments, tracks call IDs, enforces timeout/query budgets, and logs raw request/response envelopes.

The `CveMcpClient` wrapper exposes typed operations such as dependency scan, CVE lookup, EPSS, KEV, CVSS, CWE, public PoC availability, and risk scoring. When the server is missing or unhealthy, the runtime records degraded status and continues without promoting findings.

Alternative considered: keep the current command-style adapter. It is enough for a placeholder, but it is not a real MCP client and cannot support tool discovery or session semantics.

### Decision 6: RAG Memory Is Local and Citation-First

The initial memory layer uses local chunking and deterministic lexical retrieval so it works without external embedding APIs. Optional embedding providers can be added behind the same interface. Memory records include target commit, source path, line range, artifact path, content hash, namespace, and created-at timestamp.

Agents may retrieve context, but every retrieved item must be cited in `AgentTrace` and, when used for a finding, linked into the evidence chain. Memory indexes must be invalidated when target commit, file hash, or run artifact hash changes.

Alternative considered: require vector databases such as Chroma or FAISS immediately. That improves semantic search, but adds dependencies and setup burden before the retrieval contract is stable.

### Decision 7: Message Bus Is In-Process, Durable, and Replayable

The first message bus is not a distributed queue. It is an in-process event router with append-only JSONL persistence per run. Each envelope has message ID, correlation ID, causation ID, run ID, sender, recipient, type, payload, timestamp, and artifact references.

This supports traceability without requiring Redis/RabbitMQ/Kafka. A later change can replace the transport if the envelope contract stays stable.

Alternative considered: directly call agents in sequence and only persist final outputs. That is what the MVP does, but it hides tool-call and memory interactions that should be auditable in a real agent system.

### Decision 8: Runtime Safety Overrides Model Autonomy

LLM mode must still respect existing safety rules:

- no live-target validation
- no intelligence-only accepted findings
- explicit validation levels
- per-agent tool permissions
- tool budgets and timeout limits
- persisted evidence for every reported finding

If model output requests forbidden tools or unsafe validation, the runtime records a denied tool result and routes the observation back to the agent or verifier.

## Risks / Trade-offs

- LLM responses may be malformed or non-deterministic -> Validate against role schemas, retry with repair prompts, and fall back to deterministic parsing when needed.
- Provider APIs may differ -> Keep provider adapters thin and normalize usage/response metadata into `LLMResponse`.
- API keys and prompts can leak sensitive data -> Read keys from environment, redact logs, and send only selected source context rather than whole repositories.
- MCP servers may hang or change tool schemas -> Enforce timeouts, list tools at session start, cache tool schemas per run, and degrade gracefully.
- RAG retrieval can surface stale context -> Include content hashes, target commit IDs, and artifact hashes; invalidate changed records.
- Message logs can become large -> Store JSONL per run, rotate large raw payload artifacts, and keep envelope payloads bounded.
- Tool calling can become unsafe -> Gate every call through permissions, budgets, validation-level rules, and no-live-target checks.
- More runtime layers increase complexity -> Keep each module small, mockable, and covered by focused tests before wiring into the pipeline.

## Migration Plan

1. Add runtime data models for LLM requests/responses, prompt render records, tool-call envelopes, MCP calls, memory records, and bus messages.
2. Implement `LLMClient` mock mode and JSON schema validation, then add a provider adapter for OpenAI-compatible HTTP.
3. Add prompt templates and make existing agents render prompts even when using deterministic mock output.
4. Add the tool-call protocol and wrap existing repository/search/source/pattern tools behind it.
5. Add MCP stdio client and migrate CVE intelligence from the placeholder command adapter to the MCP wrapper.
6. Add local RAG memory indexing and retrieval for repository files and run artifacts.
7. Add message bus logging and route Orchestrator, agents, tools, memory, and validation through message envelopes.
8. Wire runtime features into the CLI behind config flags while keeping the old deterministic path as default for tests.
9. Extend evidence/reporting to include prompt, LLM, MCP, memory, and message-bus references.
10. Run unit tests, an offline fixture audit, and OpenSpec validation.

Rollback is straightforward because the existing deterministic pipeline remains available. If a provider, MCP server, or memory index fails, the CLI can continue in mock/degraded mode and report unavailable runtime capabilities.

## Open Questions

- Which real provider should be the first documented default: OpenAI-compatible API, DeepSeek-compatible API, or local Ollama-compatible endpoint?
- Should real LLM mode be opt-in with `--llm-provider`, or enabled when a provider API key is present?
- Should prompt templates live under `audit_agent/prompts/` as package files or under top-level `prompts/` for easier editing by students?
- Which embedding provider, if any, should be first-class after deterministic lexical retrieval?
- Should MCP support only stdio in this change, or include streamable HTTP as a second transport if the target server supports it?
