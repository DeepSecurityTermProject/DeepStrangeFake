## Why

Verification v2 currently has an evidence-bound sandbox loop, but executable PoC support is limited to path traversal. SQL injection findings can already be produced from dataflow traces, yet they still degrade to `likely` or `manual-required`, leaving a gap between high-quality SQLi evidence and machine-verifiable confirmation.

This change adds a safe SQL injection PoC generator and Judge path so Python SQLi dataflow findings can be confirmed or rejected through local sandbox execution without connecting to a real target database or treating static evidence as proof.

## What Changes

- Add a SQL injection PoC generator for Python dataflow-backed findings.
- Generate attempt-local Python harnesses that use standard-library `sqlite3` and execute only safe `SELECT`-style semantic checks.
- Confirm raw SQL injection only when sandbox execution produces machine-verifiable semantic evidence, including an openable `sqli-result.json` artifact.
- Reject parameterized SQL findings when the sandbox harness shows the payload remains data rather than changing query semantics.
- Refuse to generate PoC artifacts for forged traces whose sink/query expression is not present in the target file.
- Degrade unsupported ORM, JS/TS SQLi, non-`SELECT`, or overly dynamic query shapes to `likely` or `manual-required` with explicit reasons.
- Extend the Judge so return code 0 alone cannot confirm SQLi; SQLi confirmation requires the expected SQL semantic result artifact.
- Keep existing path traversal PoC behavior and report/Web evidence surfaces compatible.

## Capabilities

### New Capabilities

- `sql-injection-poc-validation`: Defines safe SQL injection PoC generation, sqlite-backed semantic harness execution, SQLi Judge requirements, unsupported-shape fallback behavior, and closure tests for confirmed/rejected outcomes.

### Modified Capabilities

- `guarded-agent-decision-loop`: Verification decisions must treat SQL injection as a supported sandbox PoC class only when the finding is Python dataflow-backed and the SQLi harness can be generated safely.

## Impact

- Affected backend modules: `audit_agent/verification.py`, `audit_agent/models.py` if artifact metadata needs small extensions, `audit_agent/runtime.py`, `audit_agent/reporting.py`, and possibly `audit_agent/agents.py` for SQLi sandbox eligibility.
- Affected dataflow modules: Python SQL trace handling may need richer metadata for query expressions, source symbols, sanitizer state, and safe/rejected SQLi fixtures.
- Affected tests: add fixture-driven end-to-end SQLi PoC tests, forged-trace negative tests, unsupported-shape fallback tests, and Judge tests proving return code 0 without `sqli-result.json` cannot confirm.
- Dependencies: no new external service and no Docker requirement. The MVP uses Python 3.12 and standard-library `sqlite3` inside the existing `LocalSandboxRunner`.
