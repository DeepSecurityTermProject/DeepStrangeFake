## 1. Data Model and Specs

- [x] 1.1 Add dataclasses for `DataflowNode`, `SourceNode`, `SinkNode`, `SanitizerNode`, `FlowStep`, and `DataflowTrace`.
- [x] 1.2 Add stable serialization and IDs for dataflow records.
- [x] 1.3 Add tests proving full traces are not stored only inside `Finding.metadata`.
- [x] 1.4 Add report/evidence schema tests for `dataflow_trace_refs` or equivalent artifact refs.

## 2. Python AST Frontend

- [x] 2.1 Parse Python files with stdlib `ast` and preserve file/line/snippet locations.
- [x] 2.2 Detect Flask/FastAPI/Django route handlers and request parameter sources.
- [x] 2.3 Detect SQL, command execution, and file/path sinks.
- [x] 2.4 Detect MVP sanitizers including parameter binding, allowlists, safe argv, and path base checks.
- [x] 2.5 Add vulnerable and sanitized Python fixture tests.

## 3. JS/TS AST Frontend

- [x] 3.1 Add Tree-sitter parser dependency for JS/TS with Windows/Python 3.12 compatible installation notes.
- [x] 3.2 Parse `.js`, `.jsx`, `.ts`, and `.tsx` files into normalized IR nodes.
- [x] 3.3 Detect Express/Koa/Next-style route/request sources.
- [x] 3.4 Detect SQL, command execution, and file/path sinks.
- [x] 3.5 Detect MVP JS/TS sanitizers including parameter binding, allowlists, safe argv, and path base checks.
- [x] 3.6 Add vulnerable and sanitized JS/TS fixture tests.

## 4. Dataflow Engine

- [x] 4.1 Implement bounded function-local taint propagation.
- [x] 4.2 Add same-file helper call/return propagation for simple cases.
- [x] 4.3 Track sanitizer status and downgrade sanitized traces.
- [x] 4.4 Cap analysis by file count, trace count, and per-file node budget.
- [x] 4.5 Add engine tests for sink-only and no-flow cases.

## 5. Tool Runtime Integration

- [x] 5.1 Add `dataflow-scan` scanner that returns `ToolResult` observations plus trace artifact refs.
- [x] 5.2 Register `dataflow-scan` in the default ToolRegistry under `static-scan`.
- [x] 5.3 Run `dataflow-scan` from `AgentRuntime` before or alongside `pattern-scan`.
- [x] 5.4 Keep `pattern-scan` fallback and hardcoded-secret behavior intact.
- [x] 5.5 Add ToolBroker/ToolRuntime tests for permitted dispatch, artifacts, timeouts, and parser errors.
- [x] 5.6 Ensure `max_files` and `max_traces` tool arguments are honored during dispatch.

## 6. Agent, Evidence, and Report Integration

- [x] 6.1 Update AnalysisAgent to convert dataflow observations into Findings with compact call path and trace refs.
- [x] 6.2 Update VerificationAgent confidence/reasoning for complete, sanitized, sink-only, and pattern-only evidence.
- [x] 6.2a Ensure `sanitized-flow` observations reach Verification and are rejected/downgraded instead of being skipped by Analysis.
- [x] 6.3 Persist full `DataflowTrace` artifacts under the run directory.
- [x] 6.4 Update EvidenceBuilder to reference trace artifacts explicitly.
- [x] 6.5 Update ReportGenerator JSON/Markdown output with Dataflow Evidence summaries.

## 7. Verification and Documentation

- [x] 7.1 Run focused dataflow unit tests.
- [x] 7.2 Run tool/runtime integration tests.
- [x] 7.3 Run full Python offline test suite.
- [x] 7.4 Run a local mock audit smoke and verify report JSON/Markdown include dataflow trace refs.
- [x] 7.5 Update docs with dependency install notes, rule coverage, limits, and examples.
- [x] 7.6 Run `openspec validate "add-ast-dataflow-evidence-chain" --strict`.
