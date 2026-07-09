## 1. Fixture and Red Tests

- [x] 1.1 Add a raw Python SQLi fixture where request input reaches a raw `SELECT` query and sandbox validation must end as `confirmed`.
- [x] 1.2 Add a parameterized Python SQL fixture where request input is bound as a SQL parameter and sandbox validation must end as `rejected`.
- [x] 1.3 Add a forged SQLi trace regression where metadata claims `complete-flow` but the sink/query expression does not exist in the target file; assert no PoC refs and no `confirmed`.
- [x] 1.4 Add unsupported-shape regressions for ORM/query-builder SQLi, JS/TS SQLi, and non-`SELECT` SQL; assert `likely` or `manual-required` with explicit reasons.
- [x] 1.5 Add a Judge regression where a SQLi PoC exits with return code 0 but does not produce `sqli-result.json`; assert it cannot be `confirmed`.
- [x] 1.6 Add a path traversal regression proving the existing path traversal PoC loop still works after generator routing changes.

## 2. SQLi Trace and Harness Planning

- [x] 2.1 Add helper logic to load SQLi dataflow traces, require Python language, and reject missing or unreadable trace artifacts.
- [x] 2.2 Add source-file matching that verifies the SQL sink or query construction expression from the trace exists in the current target file.
- [x] 2.3 Extract supported SQL query expressions from direct sink arguments and simple trace assignment/helper-return steps.
- [x] 2.4 Classify supported SQL shapes as raw interpolation/concatenation, parameterized binding, unsupported ORM/query-builder, unsupported language, non-`SELECT`, or unsupported dynamic expression.
- [x] 2.5 Ensure unsupported or unsafe shapes return no PoC artifact and provide a stable fallback reason for `likely` or `manual-required`.

## 3. SQLInjectionPoCGenerator

- [x] 3.1 Implement `SQLInjectionPoCGenerator` that accepts a finding, repository metadata, run directory, attempt index, and optional repair context.
- [x] 3.2 Generate executable Python PoC scripts under `verification/<finding-id>/attempt-<n>/` using only standard-library `sqlite3`.
- [x] 3.3 Build an attempt-local sqlite dataset with baseline rows and marker rows suitable for semantic widening checks.
- [x] 3.4 Transform supported raw SQL query expressions by substituting controlled baseline and attack payload values without importing or mutating target project code.
- [x] 3.5 Transform supported parameterized SQL sinks into sqlite parameter-binding execution that treats the attack payload as data.
- [x] 3.6 Write `sqli-result.json` under the attempt directory with baseline count, attack count, marker observation, mode, query expression, sink expression, trace ref, and final semantic status.
- [x] 3.7 Persist `PoCArtifact` metadata with SQLi expected signal fields pointing to `sqli-result.json`, source refs, dataflow trace refs, safety profile, and target file refs.

## 4. Verification Engine and Judge Integration

- [x] 4.1 Refactor `VerificationEngine` to route supported classes through a PoC generator registry while preserving existing path traversal behavior.
- [x] 4.2 Register `sql-injection` to use `SQLInjectionPoCGenerator` when sandbox validation is requested and sandbox execution is enabled.
- [x] 4.3 Extend SQLi fallback handling so unsupported SQLi shapes become `likely` or `manual-required` with explicit class/shape reasons instead of generic unsupported-class text.
- [x] 4.4 Extend `VerificationJudge` to evaluate SQLi expected signals from an openable `sqli-result.json` artifact under the attempt directory.
- [x] 4.5 Ensure SQLi `confirmed` requires semantic widening evidence from `sqli-result.json` and cannot be assigned from stdout, return code, LLM text, or dataflow status alone.
- [x] 4.6 Ensure SQLi `rejected` can be assigned from parameter-binding contradiction evidence in `sqli-result.json`.
- [x] 4.7 Keep bounded repair behavior limited to generated PoC artifacts and record repair reasons for any SQLi harness retries.

## 5. Agent, Runtime, and Reporting Behavior

- [x] 5.1 Adjust Verification Agent or runtime eligibility so sandbox-mode parameterized SQLi can reach PoC-backed `rejected` instead of being stopped only by static sanitizer rejection.
- [x] 5.2 Keep static/manual validation behavior for sanitized SQLi at `rejected` without requiring sandbox execution.
- [x] 5.3 Ensure runtime state and replay summaries include SQLi PoC generation, sandbox execution, Judge, fallback, and repair events.
- [x] 5.4 Ensure report JSON and Markdown verification candidates expose SQLi `confirmed`, `rejected`, `likely`, and `manual-required` statuses with PoC refs, sandbox refs, attempt refs, stdout/stderr previews, exit code, Judge reason, and `sqli-result.json` refs.
- [x] 5.5 Update Web report/status rendering only if current verification candidate UI does not already display the new SQLi artifact refs and reasons.

## 6. Verification

- [x] 6.1 Run the focused SQLi verification test suite and confirm raw SQLi is `confirmed`, parameterized SQLi is `rejected`, forged trace has no PoC/no confirmed, unsupported shapes degrade safely, and return code 0 without `sqli-result.json` cannot confirm.
- [x] 6.2 Run the full Python unit suite with `.\.venv\Scripts\python.exe -m unittest discover -s tests`.
- [x] 6.3 Run focused frontend tests if report/Web payloads change.
- [x] 6.4 Run `npm test -- --run` and `npm run build` if frontend files change.
- [x] 6.5 Run `openspec validate add-sql-injection-poc-generator --strict`.
