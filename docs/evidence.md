# Evidence and Traceability

Each audit run writes immutable artifacts under a run directory. Repeated writes
with the same artifact name receive a numeric suffix instead of overwriting
existing evidence.

## Artifact Layout

- `metadata`: target metadata, repository analysis, and audit plan.
- `tool_outputs`: pattern scanner and optional tool adapter outputs.
- `intelligence`: normalized CVE MCP outputs and degraded-mode records.
- `agent_traces`: agent reasoning summaries, selected context, tool calls, and
  ReAct records.
- `handoffs`: structured Recon-to-Analysis and Analysis-to-Verification
  contracts.
- `findings`: candidate and verification decision records.
- `evidence`: evidence chains linking findings to source, tools, intelligence,
  agents, validation, and artifacts.
- `poc`: local proof-of-concept artifacts when enabled.
- `reports`: JSON and Markdown reports.
- `prompts`: rendered prompt records with template ID, version, variables, and
  safety constraints.
- `llm`: normalized LLM requests/responses, raw provider metadata, validation
  errors, latency, and token usage.
- `decisions`: LLM decision proposals, schema validation status, policy gates,
  merge records, final decision sources, and fallback reasons.
- `mcp`: MCP session/call artifacts and degraded-mode records.
- `memory`: memory index metadata and retrieval artifacts with citations.
- `messages`: append-only message bus logs for replay and trace correlation.
- `runtime_errors`: structured runtime errors that do not belong to a specific
  tool or agent artifact.

## Evidence Chain

An evidence chain includes:

- precise file path and line range
- vulnerability class and rationale
- source-to-sink or call-path hints when available
- SAST/tool outputs
- CVE/CWE/CVSS/EPSS/KEV/public-PoC context when available
- Verification decision and reason
- validation level and result
- agent traces and handoff references
- prompt and LLM response references when LLM runtime mode is enabled
- LLM decision proposal, policy-gate, merge, and fallback references when
  guarded decision mode is enabled
- MCP call references when vulnerability intelligence is retrieved through MCP
- RAG memory citations when retrieved context influenced analysis
- message bus envelope IDs for agent, tool, memory, MCP, validation, and report
  events

Report regeneration should use the structured evidence chain rather than
re-running the model.

## Runtime Replay

When runtime mode is enabled, `messages/messages.jsonl` can be replayed to
reconstruct the high-level audit workflow. Replay links message envelopes to
agent traces, prompt artifacts, tool results, memory retrievals, MCP calls,
validation records, evidence chains, and report entries.
