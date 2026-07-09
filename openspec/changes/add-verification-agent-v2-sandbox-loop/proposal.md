## Why

The current verifier can accept findings from static evidence and the current sandbox path runs a configured command rather than a finding-specific proof-of-concept. This makes `confirmed`-style metrics hard to trust because reviewers cannot distinguish static acceptance from a PoC that actually executed and was judged from machine-verifiable evidence.

This change upgrades Verification into an auditable sandbox validation loop where `confirmed` can only come from a real PoC execution and Judge decision, while weaker or blocked cases are explicitly reported as `likely`, `rejected`, or `manual-required`.

## What Changes

- Add first-class PoC and verification evidence models for `PoCArtifact`, `SandboxRunResult`, and `VerificationAttempt`.
- Replace configured-command sandbox execution with a `LocalSandboxRunner` that receives a PoC artifact, runs fixed `argv` commands with `shell=False`, uses isolated attempt directories, records stdout/stderr artifacts, records exit code and runtime metadata, and enforces write-boundary checks.
- Add Verification Agent v2 behavior that prioritizes dataflow-backed findings and runs a bounded loop: plan verification, generate PoC, execute in local sandbox, judge output, and retry only by repairing the PoC artifact.
- Enforce that static-only acceptance is never called `confirmed`; static-only evidence can produce at most `likely` and must not increment `confirmed_count`.
- Require every final verification status to have machine-verifiable evidence:
  - `confirmed` requires PoC artifact, sandbox run result, verification attempt, stdout/stderr summary, exit code, and judge reason.
  - `rejected` requires sanitizer, no-flow, policy, or PoC contradiction evidence.
  - `manual-required` requires a blocking reason such as missing dependency, timeout, unsupported class, or sandbox policy denial.
- Limit the MVP execution closure to one real vulnerability class: path traversal dataflow findings must generate a safe executable PoC, run in the local attempt directory, and be judged as `confirmed` or `rejected`.
- Keep SQL injection, command injection, and other classes out of the MVP execution promise; they should be represented as `likely` or `manual-required` until their PoC generators and judges are implemented.
- Update reporting, runtime state, replay summaries, and the Web UI so all verification candidates are visible with `confirmed`, `likely`, `rejected`, and `manual-required` distributions and evidence links.
- Add end-to-end tests around the validation loop outcome rather than class existence, including a path traversal fixture that proves PoC generation, execution, Judge classification, and report artifact references.

## Capabilities

### New Capabilities
- `verification-poc-sandbox-loop`: Defines PoC artifacts, sandbox run results, verification attempts, status semantics, path traversal MVP closure, and the local sandbox runner contract.

### Modified Capabilities
- `guarded-agent-decision-loop`: Verification decisions must distinguish static accept/reject from evidence-backed verification status, and static acceptance must not be promoted to `confirmed`.
- `decision-auditability-and-replay`: Reports, runtime state, replay summaries, and Web views must expose every verification candidate and evidence-backed status distribution instead of only accepted findings.

## Impact

- Affected backend modules: `audit_agent/models.py`, `audit_agent/validation.py`, `audit_agent/agents.py`, `audit_agent/runtime.py`, `audit_agent/evidence.py`, `audit_agent/reporting.py`, and likely new `audit_agent/verification/` or `audit_agent/sandbox/` modules.
- Affected frontend modules: run detail summary and findings views that read `report.json`, runtime state, replay summary, and report artifacts.
- Affected APIs: existing report and run status payloads gain verification status counts, all-candidate visibility, and artifact references; existing endpoints can remain stable.
- Affected tests: add fixture-driven closed-loop verification tests, artifact integrity tests, report/Web serialization tests, and regression tests that static-only results never increment `confirmed_count`.
- Dependencies: no Docker requirement and no new external service requirement for MVP; local execution uses Python 3.12 virtual environment commands with `shell=False`.
