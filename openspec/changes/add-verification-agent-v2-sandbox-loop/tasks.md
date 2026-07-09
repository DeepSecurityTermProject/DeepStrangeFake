## 1. Verification Evidence Model

- [x] 1.1 Add status constants or enums for `confirmed`, `likely`, `rejected`, and `manual-required`, and ensure existing static validation statuses cannot be treated as confirmed.
- [x] 1.2 Add serializable `PoCArtifact`, `SandboxRunResult`, and `VerificationAttempt` models with stable IDs and `to_dict` support.
- [x] 1.3 Add compact verification summary fields to findings/evidence chains while storing full PoC, sandbox, and attempt records as run artifacts.
- [x] 1.4 Add artifact integrity helpers that validate report/runtime artifact refs point to existing files under the run directory.
- [x] 1.5 Add unit tests proving `confirmed` requires PoC, sandbox result, attempt, exit code, stdout/stderr summary, and Judge reason.
- [x] 1.6 Add unit tests proving `likely`, `rejected`, and `manual-required` each require status-specific reasons and evidence refs.

## 2. Local Sandbox Runner

- [x] 2.1 Implement `LocalSandboxRunner` that receives a `PoCArtifact` instead of reading `sandbox.safe_commands[0]`.
- [x] 2.2 Execute PoC commands with `shell=False` and argv allowlist validation for executable and argument shape.
- [x] 2.3 Create an isolated attempt directory for every execution and record cwd, argv, timeout, environment summary, start/end time, duration, exit code, and timeout flag.
- [x] 2.4 Capture stdout and stderr to real files, store bounded previews in `SandboxRunResult`, and preserve partial output on timeout.
- [x] 2.5 Enforce artifact write-boundary checks so generated artifact refs cannot escape the attempt directory.
- [x] 2.6 Add policy-denied and timeout tests that produce `SandboxRunResult` records and `manual-required` blocking reasons.
- [x] 2.7 Add a regression test proving sandbox validation no longer executes configured `safe_commands[0]`.

## 3. PoC Generation and Judge

- [x] 3.1 Implement a path traversal PoC generator for dataflow-backed findings with enough source, sink, and path-expression context.
- [x] 3.2 Ensure generated path traversal PoC scripts are executable files under the run directory and include expected signal metadata.
- [x] 3.3 Implement a Judge that reads `SandboxRunResult`, stdout/stderr previews or files, generated artifacts, and expected signal metadata before assigning `confirmed` or PoC-based `rejected`.
- [x] 3.4 Add unsupported-class handling so SQL injection, command injection, hardcoded secrets, and unsupported findings become `likely` or `manual-required` with explicit reasons during the MVP.
- [x] 3.5 Add tests proving return code 0 alone cannot produce `confirmed` without expected signal evidence.
- [x] 3.6 Add tests proving PoC contradiction evidence can produce `rejected` with a Judge reason.

## 4. Verification Agent v2 Runtime Loop

- [x] 4.1 Update Verification Agent flow to prioritize dataflow-backed path traversal findings for PoC generation and sandbox execution.
- [x] 4.2 Add a bounded repair loop that can repair only generated PoC artifacts and persists every `VerificationAttempt`.
- [x] 4.3 Ensure repair attempts never modify target repository files or scanner/dataflow artifacts.
- [x] 4.4 Update runtime validation orchestration to process all verification candidates, not only accepted findings.
- [x] 4.5 Separate triage decision counts from final status counts, including `confirmed_count`, `likely_count`, `rejected_count`, and `manual_required_count`.
- [x] 4.6 Add regression tests proving static-only acceptance becomes at most `likely` and never increments `confirmed_count`.

## 5. Evidence, Report, Replay, and Web

- [x] 5.1 Extend `EvidenceBuilder` so evidence chains reference PoC artifacts, sandbox run results, verification attempts, stdout/stderr artifacts, and Judge reasons.
- [x] 5.2 Update report JSON to include all verification candidates with final status, reason, evidence refs, artifact refs, and status-specific counts.
- [x] 5.3 Update Markdown reports with a Verification Evidence section covering `confirmed`, `likely`, `rejected`, and `manual-required`.
- [x] 5.4 Update runtime state and replay summary artifacts to include PoC generation, sandbox execution, Judge, repair, and fallback events.
- [x] 5.5 Update backend responses as needed so existing run detail endpoints expose verification candidate evidence without breaking current clients.
- [x] 5.6 Update Web run detail Summary and Findings views to show status distribution, candidate-level status badges, reasons, PoC refs, sandbox refs, stdout/stderr previews, exit code, and artifact refs.
- [x] 5.7 Add serialization/UI tests proving rejected and manual-required candidates remain visible in report/Web data.

## 6. Closed-Loop Acceptance Tests

- [x] 6.1 Add a path traversal fixture that produces a dataflow-backed finding suitable for safe local PoC execution.
- [x] 6.2 Add an end-to-end test asking whether the fixture generates a PoC, executes in an attempt directory, Judges the result as `confirmed`, and writes report references that can be opened from the run directory.
- [x] 6.3 Add an end-to-end rejected-path test where the path traversal PoC executes but the Judge observes sanitization or base-path confinement.
- [x] 6.4 Add a manual-required test where dependency, timeout, unsupported class, or sandbox policy blocking is recorded as the reason.
- [x] 6.5 Run the Python unit test suite and focused frontend tests for report/Web status display.
- [x] 6.6 Run `openspec validate add-verification-agent-v2-sandbox-loop --strict`.
