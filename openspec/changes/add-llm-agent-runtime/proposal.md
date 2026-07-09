## Why

The current audit system has a working four-agent pipeline, but the agents are deterministic role wrappers rather than real LLM-driven agents. To make the system match the intended DeepAudit-style architecture, it needs a provider-neutral LLM runtime, prompt contracts, tool-calling protocol, real MCP client integration, retrieval memory, and an auditable agent message bus.

## What Changes

- Add an `LLMClient` layer that supports configured providers, API keys from environment/config, deterministic mock mode, retries, timeouts, JSON-output validation, token/cost accounting, and prompt/response persistence.
- Add versioned Prompt templates for Orchestrator, Recon, Analysis, and Verification agents with explicit variables, safety instructions, tool permissions, output schemas, and regression-test fixtures.
- Add a tool-calling protocol that standardizes tool declarations, tool-call requests, tool results, permission checks, budgets, errors, and evidence references across local tools, external scanners, MCP tools, and validation tools.
- Replace the placeholder CVE MCP command adapter with a real MCP client abstraction supporting stdio transport first, tool discovery, initialized sessions, structured calls, timeout handling, degraded mode, and a typed `cve-mcp-server` wrapper.
- Add a RAG memory layer that indexes repository files, slices, tool outputs, findings, evidence, and optional external notes; retrieves cited context for agents; and records retrieval provenance in traces and evidence chains.
- Add an in-process agent message bus for structured events between Orchestrator, agents, tools, memory, validation, evidence, and reporting; persist all message envelopes for replay and audit.
- Preserve the existing CLI-first architecture and deterministic test path; real LLM/MCP/RAG features must have mockable interfaces and degraded/offline modes.

## Capabilities

### New Capabilities

- `llm-runtime`: Provider-neutral LLM client behavior, configuration, mock mode, response validation, retry/timeout policy, and cost/usage tracing.
- `prompt-runtime`: Versioned prompt templates, rendering, schema-bound agent outputs, safety constraints, and prompt regression fixtures.
- `agent-tool-protocol`: Unified tool schema, tool-call lifecycle, permission enforcement, budget accounting, result normalization, and audit logging.
- `mcp-client-runtime`: Real MCP client sessions, stdio transport, tool discovery/calls, `cve-mcp-server` wrapper behavior, and degraded-mode semantics.
- `rag-memory`: Repository/evidence indexing, retrieval, citations, cache invalidation, and memory provenance.
- `agent-message-bus`: Structured message envelopes, agent event routing, durable run logs, replay support, and trace correlation.

### Modified Capabilities

- None.

## Impact

- Affected code: `audit_agent/config.py`, `audit_agent/models.py`, `audit_agent/agents.py`, `audit_agent/pipeline.py`, `audit_agent/tools.py`, `audit_agent/intelligence.py`, `audit_agent/evidence.py`, `audit_agent/reporting.py`, and new runtime modules for LLM, prompts, MCP, memory, and message bus.
- Affected configuration: provider/model/API-key environment variable mapping, LLM budgets, prompt version selection, MCP server command/transport settings, RAG index path, embedding settings, message-log storage, and tool permissions.
- Affected runtime behavior: agents will be able to use real model calls when configured, but tests and offline coursework runs must still pass through deterministic mocks.
- Affected artifacts: run directories will add rendered prompts, raw LLM responses, tool-call messages, MCP session/call logs, retrieval records, message-bus logs, and token/cost summaries.
- Security constraints remain unchanged: no live-target exploitation, no intelligence-only validation, bounded tool permissions, and full evidence traceability for reported findings.
