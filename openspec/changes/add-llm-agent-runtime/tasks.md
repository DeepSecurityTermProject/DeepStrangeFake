## 1. Runtime Foundation

- [x] 1.1 Add runtime configuration fields for LLM providers, API-key environment variables, prompt versions, tool-call budgets, MCP transport, memory index paths, embedding mode, and message-bus logging.
- [x] 1.2 Add shared runtime models for LLM requests/responses, prompt render records, tool declarations, tool-call requests/results, MCP sessions/calls, memory records/retrievals, and message envelopes.
- [x] 1.3 Extend run directory layout to include `prompts`, `llm`, `messages`, `memory`, `mcp`, and `runtime_errors` artifact folders.
- [x] 1.4 Add baseline serialization and immutable-artifact tests for all new runtime models and run directories.

## 2. LLM Client Runtime

- [x] 2.1 Define the `LLMClient` interface and normalized `LLMRequest` / `LLMResponse` behavior.
- [x] 2.2 Implement deterministic `MockLLMClient` for offline tests and coursework runs.
- [x] 2.3 Implement an OpenAI-compatible HTTP provider adapter with configurable base URL, model, API-key environment variable, timeout, retry count, and JSON response extraction.
- [x] 2.4 Implement provider configuration validation, including structured errors for missing API keys in real-provider mode.
- [x] 2.5 Implement LLM response validation for role-specific JSON output schemas.
- [x] 2.6 Persist rendered prompt references, request metadata, raw response artifacts, normalized responses, validation errors, latency, and token/cost usage.
- [x] 2.7 Add tests for mock mode, missing API key behavior, provider response normalization, malformed JSON rejection, timeout/retry handling, and budget exhaustion.

## 3. Prompt Runtime

- [x] 3.1 Create versioned prompt template files for Orchestrator, Recon, Analysis, and Verification agents.
- [x] 3.2 Implement a prompt template registry with template ID, version, role, required variables, output schema, and safety constraints.
- [x] 3.3 Implement prompt rendering with required-variable validation and structured render artifacts.
- [x] 3.4 Add role-specific output schemas for audit plans, recon handoffs, analysis candidates, and verification decisions.
- [x] 3.5 Add prompt fixture tests proving deterministic rendering for representative repository metadata, tool outputs, CVE intelligence, memory context, and safety constraints.
- [x] 3.6 Link rendered prompt artifacts to agent traces, message envelopes, evidence chains, and report references when prompt output affects findings.

## 4. Agent Tool-Calling Protocol

- [x] 4.1 Add a tool registry that exposes local repository search, source slicing, pattern scan, external scanner adapters, MCP tools, memory retrieval, and validation tools as declarations.
- [x] 4.2 Implement `ToolCallRequest` and `ToolCallResult` execution flow with permission checks, budget checks, timeout handling, normalized observations, and artifact persistence.
- [x] 4.3 Define per-agent tool permission groups for Orchestrator, Recon, Analysis, Verification, Reporting, and Validation.
- [x] 4.4 Route existing `PatternScanner`, `RepositorySearchTool`, `SourceContextTool`, and external command adapters through the tool protocol.
- [x] 4.5 Add denied-call behavior for forbidden tools and unsafe validation requests.
- [x] 4.6 Add tests for successful tool calls, missing tools, unavailable external commands, forbidden tool denial, timeout results, budget exhaustion, and evidence linkage.

## 5. Real MCP Client Runtime

- [x] 5.1 Implement stdio MCP session startup, initialize request/response handling, graceful shutdown, and run-artifact logging.
- [x] 5.2 Implement MCP tool discovery and persist discovered tool schemas per run.
- [x] 5.3 Implement structured MCP tool invocation with call IDs, JSON arguments, timeout handling, malformed-response handling, and normalized tool-call results.
- [x] 5.4 Implement a typed `CveMcpClient` wrapper for dependency scanning, CVE lookup, CVSS, EPSS, CISA KEV, CWE, public proof-of-concept, and risk scoring operations when available.
- [x] 5.5 Replace the placeholder CVE MCP command adapter path in the pipeline with the real MCP client wrapper while preserving degraded mode.
- [x] 5.6 Add tests with a fake MCP stdio server for initialization, tool discovery, successful calls, missing server degraded mode, missing tool degraded mode, timeout handling, query-budget exhaustion, and normalized CVE intelligence output.

## 6. RAG Memory Layer

- [x] 6.1 Implement memory record models for repository chunks, source slices, tool outputs, findings, evidence chains, external notes, and retrieval citations.
- [x] 6.2 Implement repository/file chunking with target identity, commit, path, line range, content hash, namespace, and artifact references.
- [x] 6.3 Implement deterministic lexical retrieval with ranked results, snippets, scores, source paths, line ranges, and citations.
- [x] 6.4 Add optional embedding-provider interface with deterministic lexical fallback when embeddings are unavailable.
- [x] 6.5 Implement memory invalidation when target commit, file hash, or artifact hash changes.
- [x] 6.6 Add sensitive-file exclusion and redaction controls for memory indexing.
- [x] 6.7 Persist memory index metadata and retrieval artifacts under each run.
- [x] 6.8 Add tests for indexing, retrieval ranking, citation output, stale-record invalidation, embedding fallback, exclusion patterns, and trace/evidence linkage.

## 7. Agent Message Bus

- [x] 7.1 Implement message envelope model with message ID, run ID, correlation ID, causation ID, sender, recipient, type, payload, timestamp, and artifact references.
- [x] 7.2 Implement in-process publish/subscribe routing for Orchestrator, agents, tools, MCP client, memory, validation, evidence, and reporting components.
- [x] 7.3 Persist append-only JSONL message logs under each run.
- [x] 7.4 Add replay support that reconstructs agent starts/ends, tool calls, memory retrievals, MCP calls, verification decisions, validation events, evidence persistence, and report generation events.
- [x] 7.5 Represent runtime errors, permission denials, degraded MCP status, timeouts, and budget exhaustion as structured messages.
- [x] 7.6 Add tests for message publishing, subscription routing, durable JSONL logs, replay ordering, correlation/causation IDs, denial messages, and trace correlation.

## 8. Agent Runtime Integration

- [x] 8.1 Refactor Orchestrator, Recon, Analysis, and Verification agents to use prompt templates and `LLMClient` when real LLM mode is enabled.
- [x] 8.2 Preserve deterministic mock behavior so existing tests and offline CLI runs still pass without API keys.
- [x] 8.3 Route agent tool requests through the unified tool protocol instead of direct tool calls in LLM mode.
- [x] 8.4 Add RAG retrieval into Recon and Analysis prompts with cited memory records.
- [x] 8.5 Add MCP vulnerability-intelligence calls through the tool protocol and typed MCP client wrapper.
- [x] 8.6 Route agent lifecycle events, prompt renders, LLM calls, tool calls, memory retrievals, handoffs, and verification decisions through the message bus.
- [x] 8.7 Ensure Verification still rejects intelligence-only or memory-only findings without local evidence.
- [x] 8.8 Add tests for end-to-end mock LLM audit, schema-valid LLM candidate generation, malformed LLM response rejection, tool-call routing, RAG citation use, MCP degraded mode, and message-log replay.

## 9. Evidence, Reporting, and CLI

- [x] 9.1 Extend evidence chains to include rendered prompt artifacts, LLM response artifacts, tool-call messages, MCP call artifacts, memory retrieval artifacts, and message-bus envelope IDs.
- [x] 9.2 Extend JSON and Markdown reports to show LLM provider/model, prompt version, token/cost usage, MCP status, retrieval citations, and message trace references.
- [x] 9.3 Add CLI flags or config support for selecting provider, model, prompt version, MCP mode, memory mode, and message replay.
- [x] 9.4 Add CLI validation output that clearly reports when the audit is running in mock, degraded MCP, lexical-memory, or real-provider mode.
- [x] 9.5 Add tests for report completeness, CLI config parsing, mode reporting, evidence regeneration, and replay-based report traceability.

## 10. Documentation and Verification

- [x] 10.1 Update usage documentation with API-key setup, OpenAI-compatible provider configuration, mock mode, local-model option, and failure modes.
- [x] 10.2 Document prompt template structure, output schemas, and how students can safely edit prompts.
- [x] 10.3 Document the tool-calling protocol, permission model, budgets, and denied-call behavior.
- [x] 10.4 Document MCP server setup for `mukul975/cve-mcp-server`, degraded mode, query budgets, and supported CVE intelligence operations.
- [x] 10.5 Document RAG memory indexing, citations, invalidation, exclusions, and lexical fallback.
- [x] 10.6 Document message-bus logs, replay workflow, and how message IDs connect to evidence/report entries.
- [x] 10.7 Run the full unit test suite with Python 3.12.
- [x] 10.8 Run a mock-mode single-target audit and verify prompts, LLM artifacts, messages, memory, evidence, and reports are generated.
- [x] 10.9 Run OpenSpec strict validation for `add-llm-agent-runtime`.

