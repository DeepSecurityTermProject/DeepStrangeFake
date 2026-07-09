## Why

The current deterministic scanner is useful for a baseline demo, but it reports findings from line-oriented patterns. That makes vulnerability evidence shallow: a reviewer can see a suspicious sink line, but cannot reliably inspect where user-controlled input entered, how it propagated, whether a sanitizer was present, and why the verifier accepted or rejected the finding.

To move the project closer to DeepAudit-style auditable security analysis, deterministic scanning should produce explainable `source -> propagation -> sanitizer -> sink` evidence chains. LLM output can then reason over structured local evidence instead of compensating for weak scanner output.

## What Changes

- Add an AST/dataflow analysis subsystem for Python and JS/TS.
- Cover MVP source-to-sink scenarios for routes, request parameters, SQL execution, command execution, and file reads.
- Add explicit source, sink, sanitizer, and propagation rule definitions.
- Add a new `dataflow-scan` tool that emits structured dataflow observations through the existing ToolRuntime/ToolBroker path.
- Preserve a short human-readable summary in `Finding.call_path` and compact metadata, while persisting the full `DataflowTrace` as immutable artifacts.
- Extend EvidenceChain/reporting so validated findings reference the full trace artifacts, not only tool output summaries.
- Keep the existing `PatternScanner` as fallback and for hardcoded-secret detection during the MVP.

## Capabilities

### New Capabilities

- `ast-dataflow-scanner`: Defines AST parsing, language frontends, source/sink/sanitizer rules, and taint propagation behavior.
- `dataflow-evidence-chain`: Defines persisted `DataflowTrace` artifacts and how findings/evidence chains reference them.
- `runtime-dataflow-integration`: Defines how `dataflow-scan` is registered, executed, consumed by agents, and reported.

### Modified Capabilities

- Existing agentic audit behavior is refined: Analysis and Verification should prefer structured dataflow evidence over raw pattern matches when both are available.
- Existing reports are enriched with trace references and readable source-to-sink summaries.

## Impact

- Affected code: new `audit_agent/dataflow/` package, `audit_agent/models.py`, `audit_agent/tools.py`, `audit_agent/tool_protocol.py`, `audit_agent/runtime.py`, `audit_agent/agents.py`, `audit_agent/evidence.py`, `audit_agent/reporting.py`, tests, and docs.
- New dependencies: Python stdlib `ast` for Python parsing; add a Tree-sitter family dependency for JS/TS parsing, such as `tree-sitter` plus a maintained language-pack/parser bundle.
- Runtime behavior: the analysis tool phase runs `dataflow-scan` first and may also run `pattern-scan` for fallback and hardcoded secrets.
- Security behavior: dataflow evidence is local source-code evidence; CVE/MCP/RAG context remains contextual unless tied to local source evidence.
- Compatibility: existing Finding JSON fields remain present; new trace artifact references are additive.
