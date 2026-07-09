## Context

The current runtime already has dataflow-backed SQL injection findings, first-class PoC artifacts, a `LocalSandboxRunner`, a Judge, verification status counts, report/Web evidence surfaces, and a bounded PoC repair loop. The executable PoC closure is intentionally narrow: path traversal can be confirmed or rejected through sandbox execution, while SQL injection still falls back to `likely` or `manual-required`.

Python dataflow traces already distinguish raw SQL reaching `execute`/`query` sinks from parameterized SQL that records sanitizer evidence. This change extends the same evidence-bound contract to SQL injection without connecting to a real target database or treating static acceptance as confirmation.

## Goals / Non-Goals

**Goals:**

- Add a Python SQL injection PoC generator for dataflow-backed findings.
- Confirm raw SQLi only when a sandboxed harness proves payload-controlled query semantics with a machine-readable `sqli-result.json` artifact.
- Reject parameterized SQL findings when sandbox execution proves the payload remains a bound value rather than executable SQL syntax.
- Refuse forged traces and unsupported query shapes without writing placeholder PoC artifacts.
- Preserve the existing rule that `confirmed` requires PoC, sandbox result, attempt, stdout/stderr, exit code, semantic evidence, and Judge reason.
- Keep default tests offline and deterministic with Python 3.12 standard-library `sqlite3`.

**Non-Goals:**

- Do not connect to the target project's real database, ORM engine, web server, or network service.
- Do not execute destructive SQL or non-`SELECT` statements.
- Do not support JS/TS SQLi PoC execution in this MVP.
- Do not support arbitrary ORM/session/query-builder semantics in this MVP.
- Do not use LLM output, CVE intelligence, return code 0, or dataflow status alone as confirmation.

## Decisions

### Decision 1: Use an attempt-local sqlite semantic harness

The SQLi PoC generator should emit a Python script that creates an in-memory or attempt-local sqlite database, inserts known marker rows, evaluates the target query construction expression with a benign baseline input and an attack payload, and writes `sqli-result.json` with the observed semantic delta.

For a raw vulnerable query such as `query = "select * from users where name='%s'" % name`, the harness can set `name` to a payload like `' OR '1'='1`, execute the resulting `SELECT`, and confirm only when the attack result includes marker rows that the baseline query does not include.

For a parameterized query such as `cursor.execute("select * from users where name=?", (safe_name,))`, the harness should execute with sqlite binding and reject when the payload is treated as data and no semantic widening occurs.

Alternative considered: call the target application function directly. That is attractive for realism but fragile because route handlers often depend on Flask/FastAPI context, app globals, real database connections, or side effects. The MVP should validate the query construction semantics safely and deterministically.

### Decision 2: Generate PoC only from trace-backed, source-matching query expressions

The generator must load the full `DataflowTrace`, require `vulnerability_class=sql-injection`, require Python language, require the trace status to be `complete-flow` or a sanitizer-backed parameterization case, and verify that the sink expression or relevant query assignment expression exists in the target source file.

For raw SQL, the generator can extract the sink's first SQL argument or follow the compact trace steps to a query assignment. It may support simple AST expressions: string formatting with `%`, f-strings, `+` concatenation, and `.format()` if safely transformable.

If the trace is forged, stale, missing the target expression, or too dynamic to transform safely, the generator must return no PoC and the Verification result must be `likely` or `manual-required`, never `confirmed`.

Alternative considered: trust the trace artifact as sufficient. The recent path traversal review showed why this is unsafe; generator output must be tied back to current target source.

### Decision 3: Introduce generator routing instead of another hard-coded branch

`VerificationEngine` should route supported vulnerability classes through a small registry, for example:

- `path-traversal` -> `PathTraversalPoCGenerator`
- `sql-injection` -> `SQLInjectionPoCGenerator`

Unsupported classes should keep the explicit `likely` or `manual-required` fallback. This avoids duplicating the PoC loop while making supported-class expansion obvious.

Alternative considered: add a second `if finding.vulnerability_class == ...` branch. That works for one class but makes the next generator harder to add and increases the risk of inconsistent fallback behavior.

### Decision 4: Judge SQLi from semantic evidence, not stdout or return code alone

The SQLi PoC should declare an expected signal that references `sqli-result.json`, including fields such as `baseline_count`, `attack_count`, `marker_seen`, `query_expression`, `sink_expression`, `mode`, and `status`.

The Judge can still use stdout/stderr previews as supporting evidence, but SQLi `confirmed` must require the result JSON to exist under the attempt directory and to show the configured semantic confirmation. Return code 0 without that artifact must produce `manual-required` or `rejected`, not `confirmed`.

Alternative considered: reuse the generic `stdout-contains` signal. That is too easy to spoof and would not prove SQL semantics.

### Decision 5: Keep sanitized SQLi visible as rejected evidence in sandbox mode

Existing Verification triage can reject `sanitized-flow` findings before sandbox execution. For this change, sandbox validation should allow parameterized SQLi candidates to enter SQLi PoC generation when the trace has enough context, so the final status can become PoC-backed `rejected`. Static/manual modes can continue to reject sanitizer-backed findings without runtime execution.

Alternative considered: leave all sanitized SQL as deterministic reject. That is correct but misses the user requirement that the parameterized SQL fixture must execute and be rejected with machine-verifiable evidence.

## Risks / Trade-offs

- [Risk] The sqlite harness may not perfectly model every database dialect. -> Mitigation: scope MVP to simple `SELECT` semantics and mark dialect-specific or unsupported expressions as `manual-required`.
- [Risk] Query transformation may accidentally accept forged or stale traces. -> Mitigation: require expression matching against target source and add forged-trace regression tests.
- [Risk] A PoC could be confirmed by placeholder output. -> Mitigation: require `sqli-result.json` semantic evidence and test that return code 0 alone cannot confirm.
- [Risk] Sanitized-flow routing changes existing reject behavior. -> Mitigation: limit runtime execution to `validation_level=sandbox` with `sandbox.enabled=true`; static modes keep current rejection behavior.
- [Risk] Adding a generator registry could disturb path traversal behavior. -> Mitigation: preserve existing path traversal tests and add a regression that path traversal still confirms/rejects as before.

## Migration Plan

1. Add SQLi-specific closed-loop tests first: raw confirmed, parameterized rejected, forged no-PoC, unsupported fallback, and no-result-json no-confirm.
2. Refactor VerificationEngine to use a PoC generator registry while keeping path traversal behavior unchanged.
3. Add `SQLInjectionPoCGenerator` and SQLi harness/result artifact helpers.
4. Extend the Judge to support SQL semantic result artifacts.
5. Adjust VerificationAgent/runtime eligibility so sandbox-mode parameterized SQL can reach PoC-backed rejection.
6. Update report/replay/runtime evidence only if new SQLi result fields need explicit display.
7. Run full Python tests, focused frontend tests if report payload changes, and `openspec validate add-sql-injection-poc-generator --strict`.

Rollback is additive: disable the SQLi generator registry entry and SQLi findings will return to the existing unsupported-class `likely` or `manual-required` fallback.

## Open Questions

- Should SQLi `sanitized-flow` candidates be shown in active findings when rejected by PoC, or only in `verification_candidates`?
- Should future follow-up support JS/TS SQLi with a Node-based sqlite harness, or keep JS/TS as static/dataflow evidence until dependency management is clearer?
