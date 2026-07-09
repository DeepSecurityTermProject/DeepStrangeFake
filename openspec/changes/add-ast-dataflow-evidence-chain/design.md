## Context

The current runtime has a clean tool and evidence path:

- `PatternScanner` emits `ToolObservation` objects.
- `ToolBroker` dispatches the scan through `ToolRuntime`.
- `AnalysisAgent` converts scanner observations to `Finding`.
- `VerificationAgent` accepts candidates when local evidence exists.
- `EvidenceBuilder` persists tool/evidence artifacts.
- `ReportGenerator` serializes findings and evidence chains.

This gives us a good extension point: add a stronger scanner behind the same tool protocol instead of rewriting the multi-agent kernel.

## Goals / Non-Goals

**Goals:**

- Produce explainable `source -> sink -> sanitizer` traces for Python and JS/TS.
- Cover Python Flask/FastAPI/Django-style inputs and JS/TS Express/Koa/Next-style inputs in the MVP.
- Cover SQL execution, command execution, and file-read/path traversal sinks.
- Persist full `DataflowTrace` records as immutable run artifacts.
- Link trace artifacts from `ToolResult`, `Finding`, `EvidenceChain`, and reports.
- Keep deterministic offline tests with fixture projects.

**Non-Goals:**

- Do not attempt whole-program interprocedural precision across arbitrary frameworks in the MVP.
- Do not replace external scanners such as Semgrep/Bandit.
- Do not treat CVE/RAG/LLM-only evidence as validation evidence.
- Do not remove the current pattern scanner.
- Do not generate or execute exploit code as part of this change.

## Data Model

Add explicit dataflow model records, likely in a new `audit_agent/dataflow/ir.py` module:

- `DataflowNode`: stable ID, kind, language, path, line range, symbol, expression, snippet.
- `SourceNode`: a request parameter, route parameter, body field, query param, uploaded file, or CLI/env input.
- `SinkNode`: SQL execution, command execution, file read, path send/read, or unsafe raw query sink.
- `SanitizerNode`: parameter binding, allowlist validation, schema validation, path canonicalization with base-dir check, safe argv construction.
- `FlowStep`: assignment, call argument, return value, object/property access, template/string interpolation, or branch guard.
- `DataflowTrace`: trace ID, vulnerability class, source nodes, sink node, sanitizer nodes, ordered steps, confidence, status, rule IDs, and explanation.

`Finding` should not carry the full trace payload. It should keep:

- `call_path`: compact ordered strings for reviewer scanning.
- `metadata["dataflow_trace_refs"]`: IDs or artifact refs.
- `metadata["dataflow_summary"]`: short source/sink/sanitizer summary.

The complete trace should be written under a run artifact directory such as `dataflow/traces/<trace-id>.json`.

## Scanner Architecture

Add `audit_agent/dataflow/`:

- `rules.py`: declarative source/sink/sanitizer rules per language/framework.
- `python_frontend.py`: Python AST extraction using stdlib `ast`.
- `js_ts_frontend.py`: Tree-sitter-based extraction for `.js`, `.jsx`, `.ts`, `.tsx`, with an offline-safe fallback when optional parser packages are unavailable.
- `engine.py`: bounded trace selection, flow status classification, and shared helper-return matching. In the MVP, language frontends still own AST extraction and local symbol propagation.
- `scanner.py`: converts traces to `ToolResult`/`ToolObservation`.
- `artifacts.py`: persists trace artifacts and returns stable refs.

The target engine should support a bounded, local propagation model:

- function-local assignment propagation;
- route handler parameter propagation;
- call argument propagation;
- simple return value propagation for same-file helper functions;
- object/property path propagation for common request objects;
- sanitizer recognition that can downgrade or mark a trace as sanitized.

MVP accuracy should favor reviewability over aggressive findings. If a sanitizer is detected between source and sink, the trace remains useful but should be marked `sanitized` or `blocked` and should not become a high-confidence vulnerability by default.

## MVP Rules

### Python Sources

- Flask: `request.args`, `request.form`, `request.json`, `request.get_json()`, `request.files`, route parameters.
- FastAPI: handler parameters and `Request.query_params`, `Request.json()`, `UploadFile`.
- Django: `request.GET`, `request.POST`, `request.body`, `request.FILES`.

### Python Sinks

- SQL: `cursor.execute`, `connection.execute`, `session.execute`, raw query helpers.
- Command: `os.system`, `os.popen`, `subprocess.*`, especially `shell=True`.
- File/path: `open`, `Path.read_text`, `Path.read_bytes`, `send_file`, unsafe joined paths.

### JS/TS Sources

- Express: `req.query`, `req.params`, `req.body`, `req.files`.
- Koa: `ctx.query`, `ctx.params`, `ctx.request.body`.
- Next-style handlers: `request.url`, `searchParams`, `await request.json()`.

### JS/TS Sinks

- SQL: `db.query`, `connection.query`, `pool.query`, `sequelize.query`, `prisma.$queryRawUnsafe`.
- Command: `child_process.exec`, `execSync`, `spawn` with shell-like dynamic command strings.
- File/path: `fs.readFile`, `fs.readFileSync`, `fs.createReadStream`, `res.sendFile`.

### Sanitizers

- SQL parameter binding or query builder placeholders.
- Allowlist checks with membership or strict regex validation.
- Path canonicalization with enforced base directory.
- Fixed command argv arrays without shell interpolation.
- Framework/schema validators when a constrained enum/allowlist is visible.

## Runtime Integration

Register a new tool:

- Tool name: `dataflow-scan`.
- Permission group: `static-scan`.
- Input: repository metadata, optional language filter, vulnerability classes, max files, max traces.
- Output: `ToolResult` with observations and `artifact_paths` referencing full traces.

`AgentRuntime` should run `dataflow-scan` in the analysis tool phase. `pattern-scan` should remain available as:

- fallback when AST parsing fails;
- supplemental hardcoded-secret scanner;
- cheap smoke baseline for unsupported languages.

`AnalysisAgent` should convert dataflow observations into candidates with higher-quality evidence:

- source location;
- sink location;
- sanitizer status;
- trace artifact reference;
- compact call path.

`VerificationAgent` should distinguish:

- `complete-flow`: source reaches sink without recognized sanitizer.
- `sanitized-flow`: source reaches sink through a recognized sanitizer.
- `sink-only`: sink detected but no source path. The current MVP classifies this engine status and avoids promoting it as complete vulnerability evidence.
- `pattern-only`: existing fallback finding.

Only complete local evidence should receive the strongest confidence by default.

## Evidence and Reporting

Persist full traces as immutable artifacts. EvidenceChain should reference those artifacts explicitly. The preferred shape is additive:

- `EvidenceChain.artifact_refs` includes trace artifact paths.
- Add a dedicated `dataflow_trace_refs` field if model evolution is acceptable.
- Tool evidence persists normalized `ToolResult` and raw trace artifacts.

Reports should show:

- source line and sink line;
- sanitizer status;
- compact path summary;
- trace artifact refs;
- rule ID and confidence.

Markdown should include a short "Dataflow Evidence" section per finding, while JSON should preserve machine-readable trace refs.

## Testing Strategy

Add fixture projects with vulnerable and sanitized cases:

- Python SQL injection from Flask/FastAPI request param to `cursor.execute`.
- Python command injection to `subprocess.run(..., shell=True)` and safe argv counterexample.
- Python path traversal to `open(base / user_file)` and safe `resolve()` base check.
- JS/TS Express SQL/command/file sinks.
- Sanitized SQL parameter binding and path allowlist false-positive guard.

Test levels:

- IR extraction unit tests.
- Propagation engine unit tests.
- ToolRuntime `dataflow-scan` tests.
- AnalysisAgent conversion tests.
- EvidenceBuilder artifact reference tests.
- Runtime integration smoke verifies report JSON/Markdown include trace refs.

## Risks / Trade-offs

- [Risk] JS/TS parser dependency may be heavier than current Python-only package. -> Keep it explicit in dependencies and add parser-unavailable diagnostics.
- [Risk] Dataflow false positives can still happen. -> Report sanitizer status and trace confidence, not only vulnerability class.
- [Risk] Interprocedural analysis can grow quickly. -> MVP stays bounded to function-local propagation plus simple same-file helper return matching; deeper interprocedural analysis remains deferred.
- [Risk] Trace artifacts can become large. -> Cap max traces and persist compact source snippets, not whole files.
- [Risk] Existing tests assume only pattern scanner output. -> Keep `pattern-scan` compatibility and add new assertions instead of removing old fields.

## Open Questions

- Which Tree-sitter package should be pinned during implementation after checking Python 3.12 Windows wheel availability?
- Should sanitized flows be reported as rejected findings, informational observations, or only tool artifacts in the MVP?
- Should the UI add a dedicated Dataflow tab later, or is exposing trace refs in existing Findings/Markdown Report enough for this change?
