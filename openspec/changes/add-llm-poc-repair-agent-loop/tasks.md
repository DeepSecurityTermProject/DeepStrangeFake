## 1. Baseline, Repair Fixtures, and Test Doubles

- [x] 1.1 Capture baseline tests for existing path-traversal confirmation/rejection, raw SQLi confirmation, parameterized SQL rejection, Docker failure degradation, report counts, and disabled-by-default offline scans.
- [x] 1.2 Add a trace-backed fixture whose deterministic initial PoC fails only because an allowlisted import is missing and whose protected harness can still produce existing Judge-readable evidence after repair.
- [x] 1.3 Add a nontrivial synthetic authorized fixture whose target-derived setup/name mismatch is repairable through a generator-declared editable slot without changing protected evidence code.
- [x] 1.4 Add adversarial fixtures for direct confirmation-marker output, forged `sqli-result.json`, hard-coded semantic counts, protected query changes, unsafe process/network code, and credential-shaped source/diagnostic text.
- [x] 1.5 Add test doubles that record LLM calls, normalized edits, trusted assembly, semantic/safety decisions, Docker starts, script/edit hashes, provisional Judge outcomes, integrity finalization, and ordered events without requiring network or a real daemon.

## 2. Repair Models and Disabled-by-Default Configuration

- [x] 2.1 Add serializable `PoCFailureClass` and `PoCFailureClassification` records with eligibility, reason, evidence refs, stage, compatible slot IDs, attempt index, and metadata path.
- [x] 2.2 Add a separate `RepairStopReason` model for provider failure, invalid contract, unsupported edit, duplicate edit/script, semantic or safety denial, exhausted budget, and target-integrity change without rewriting the prior PoC failure class.
- [x] 2.3 Add `PoCRepairManifest`, editable-slot, protected-node, and normalized typed-edit models with stable IDs and hashes.
- [x] 2.4 Add `PoCRepairRecord`, `PoCSemanticIntegrityDecision`, and `PoCSafetyDecision` models with prompt/response/edit/script refs, hashes, rule IDs, source locations, provider metadata, and stop reason.
- [x] 2.5 Extend `VerificationAttempt`, validation summaries, evidence-chain summaries, and serialization compatibility with classification, edit, semantic, safety, integrity, provisional/final status, and stop-reason refs.
- [x] 2.6 Add run-level before/after target-manifest and comparison records that re-enumerate the audit scope and detect changed, added, and removed files.
- [x] 2.7 Add `PoCRepairConfig(enabled=False, max_repair_attempts=1)` with an accepted `0..2` repair range and document that total executions equal `1 + max_repair_attempts`.
- [x] 2.8 Add configuration validation and guarded legacy migration: old repair fields may enable PoC repair only when legacy LLM decision mode is also enabled and no explicit new section exists; persist the effective config source.

## 3. Generator Repair Manifests and Immutable Evidence Semantics

- [x] 3.1 Write generator-manifest tests that identify editable imports/setup slots and protected payload, sink, measurement, marker, and result-writer nodes with stable AST hashes.
- [x] 3.2 Extend the path-traversal generator to emit a repair manifest while protecting resolved-path comparisons and confirmation/rejection emitters.
- [x] 3.3 Extend the SQLi generator to emit a repair manifest while protecting payload/query construction, SQLite execution, baseline/attack counts, `marker_seen`, status derivation, and `sqli-result.json` serialization.
- [x] 3.4 Include repair-manifest and protected-node hashes in the initial immutable execution envelope and every repaired artifact reference.
- [x] 3.5 Ensure trusted generator code owns all Judge-facing marker and result emission and editable slots cannot write protected result filenames or emit expected marker literals.
- [x] 3.6 Persist each repair manifest beside the initial PoC and prove it can be reopened and verified before later repair attempts.
- [x] 3.7 Keep unsupported generator shapes without a repair manifest as `likely` or `manual-required` and prevent the repair agent from inventing the first PoC or edit surface.

## 4. Exact Typed-Edit LLM Contract and Redaction

- [x] 4.1 Add versioned `poc-repair.edits.v1` prompt/schema fixtures with repair-manifest slots, untrusted-snippet delimiters, immutable evidence constraints, and no complete-script output field.
- [x] 4.2 Add exact-parser tests for top-level and nested extra fields, wrong nested types, empty or oversized values, unknown operations, undeclared slots, duplicate conflicting edits, authority fields, and count limits.
- [x] 4.3 Implement dedicated `parse_poc_repair_response()` validation for exact key sets, closed typed-edit unions, nested list/item types, non-empty values, size/count limits, and manifest operation/slot membership without relying on the current generic schema helper.
- [x] 4.4 Implement a repair-context builder that reads only the prior script, repair manifest, bounded redacted diagnostics, openable dataflow trace, bounded current source/sink snippets, immutable missing-evidence description, and remaining repair budget.
- [x] 4.5 Extend text redaction for repair context and standard artifacts to cover configured secret values and credential-shaped hard-coded literals; add prompt/response/stdout/source regression tests and keep raw provider payloads out of report/replay/Web refs.
- [x] 4.6 Implement `LLMPoCRepairAgent` against the existing injected `LLMClient` protocol and return only validated diagnosis, normalized typed edits, and change summaries.
- [x] 4.7 Persist redacted prompt, normalized response, exact-contract errors, provider metadata, and repair stop reasons, and publish stable repair request/response/validation/provider events without secret leakage.
- [x] 4.8 Add deterministic `MockLLMClient` tests and an opt-in real-provider smoke that asserts exact-contract, manifest-membership, redaction, and policy invariants rather than exact wording.

## 5. Trusted Edit Assembly, SemanticIntegrityGate, and SafetyGate

- [x] 5.1 Write trusted-assembler tests for each allowed operation, undeclared slots, conflicting edits, stable normalization, edit hashing, assembled script hashing, and no mutation of prior attempt artifacts.
- [x] 5.2 Implement trusted typed-edit assembly against a copy of the original script and produce a new attempt-local script only after exact validation succeeds.
- [x] 5.3 Implement `PoCSemanticIntegrityGate` that verifies protected AST hashes, edit-slot containment, protected marker/result-writer ownership, and immutable execution-envelope values.
- [x] 5.4 Deny and persist direct confirmation-marker output, protected `sqli-result.json` writes, hard-coded confirming counts/status, protected query/sink changes, removed semantic checks, and any changed protected node before Docker starts.
- [x] 5.5 Write `PoCSafetyGate` tests for valid current harnesses, syntax errors, forbidden imports, network/process calls, installers, dynamic loading, Docker control, unsafe host paths, target writes, and opaque unsupported constructs.
- [x] 5.6 Implement conservative Python AST safety rules with stable rule IDs and source locations while allowing only the constrained standard-library APIs required by current path-traversal and sqlite harnesses.
- [x] 5.7 Enforce Docker-only execution and fixed trusted argv for LLM-repaired scripts, retain existing Docker no-network/read-only/resource policies, and return `llm-repair-requires-docker` before any local execution.
- [x] 5.8 Track all normalized edit and assembled script hashes and stop before runner invocation when either repeats a prior attempt.
- [x] 5.9 Persist semantic and safety decisions before execution and prove denied exact-contract, semantic, or safety outcomes produce no container-start event.

## 6. Failure Classification and Verification State Machine

- [x] 6.1 Write classifier tests for `harness-error`, compatible/incompatible `missing-evidence`, pre-run and runner `policy-denied`, Docker `environment-error`, `semantic-rejected`, and unknown fail-closed outcomes.
- [x] 6.2 Implement stage-aware `PoCFailureClassifier` with optional safety, sandbox, and Judge inputs; structured statuses SHALL outrank diagnostic text.
- [x] 6.3 Keep provider failure, invalid model output, duplicate edits/scripts, semantic/safety denial, budget exhaustion, and integrity change as repair stop reasons rather than PoC failure reclassification.
- [x] 6.4 Refactor `VerificationEngine` to accept injected repair services while preserving deterministic initial generator routing and independent Judge construction.
- [x] 6.5 Pass the shared runtime `LLMClient`, artifact/prompt services, and message bus from `AgentRuntime` instead of constructing a second provider client.
- [x] 6.6 Build the run-level before-manifest before validation, then generate, semantic-check, safety-check, execute, and Judge the initial deterministic PoC with existing behavior preserved when repair is disabled.
- [x] 6.7 Replace `_repair_context_from_sandbox_failure` as the primary retry path with classify -> exact typed edits -> trusted assembly -> semantic integrity -> safety -> Docker -> Judge orchestration.
- [x] 6.8 Stop repair immediately on provisional `confirmed` or `rejected`, policy/infrastructure failure, incompatible missing evidence, provider/contract failure, duplicate hash, semantic/safety denial, or exhausted repair budget.
- [x] 6.9 Preserve parameterized SQL rejection as terminal and keep unsupported deterministic generator shapes out of initial LLM generation.
- [x] 6.10 Re-enumerate and hash the target after all attempts but before final persistence; downgrade provisional confirmations on any integrity difference and retain rejected contradiction evidence with an integrity warning.
- [x] 6.11 Preserve every classification, repair stop, edit, semantic/safety decision, attempt, provisional Judge result, target-integrity finalization, and final stop reason in artifacts, message order, and compact finding metadata refs.

## 7. Core Closed-Loop Acceptance Gate

- [x] 7.1 Prove a missing-import initial PoC fails, the LLM returns an allowlisted edit, trusted assembly produces a different script, attempt 2 runs in Docker, and protected Judge evidence reaches the expected terminal result.
- [x] 7.2 Prove the nontrivial target-derived setup/name fixture is repaired through a declared slot and reaches a deterministic terminal result without changing protected evidence code.
- [x] 7.3 Prove direct `PATH_TRAVERSAL_CONFIRMED` or equivalent marker insertion is denied by semantic integrity and no Docker container starts.
- [x] 7.4 Prove forged `sqli-result.json`, hard-coded attack/baseline counts, and protected query/result-writer changes are denied and cannot increment `confirmed_count`.
- [x] 7.5 Prove network/process/package-install output is denied by SafetyGate and no Docker container starts.
- [x] 7.6 Prove missing Docker binary/daemon/image returns `manual-required` without an LLM call, while provider failure preserves the prior PoC failure class and records a separate stop reason.
- [x] 7.7 Prove parameterized SQL remains `rejected`, unsupported shapes do not invoke initial generation, and missing evidence without a compatible slot is not repaired toward confirmation.
- [x] 7.8 Prove repeated normalized edits or assembled scripts stop before Docker and repair counts obey `0..2` with total attempts equal to `1 + max_repair_attempts`.
- [x] 7.9 Prove default and legacy-default configurations do not enable LLM repair, while explicit CLI/API configuration does.
- [x] 7.10 Prove target manifests detect changed, added, and removed files, unchanged runs may finalize provisional outcomes, and changed runs cannot finalize confirmation.
- [x] 7.11 Prove credential-shaped source/stdout/model text is absent from model-facing and standard persisted artifacts.
- [x] 7.12 Do not begin report, replay, or frontend expansion until tasks 7.1-7.11 pass in the focused core suite.

## 8. Reports, Replay, and Compact Run Detail Summaries

- [x] 8.1 Extend JSON report findings and verification candidates with ordered classifications, normalized edit summaries/hashes, script hashes, semantic/safety status, provisional/final outcomes, integrity summary, artifact refs, and final stop reason.
- [x] 8.2 Extend Markdown reports with the same high-signal timeline for all statuses without embedding prompts, model responses, raw provider payloads, or executable scripts.
- [x] 8.3 Extend replay summaries with ordered classification, repair request/response, exact-contract, assembly, semantic, safety, runner, Judge, target-integrity, duplicate, budget, and final-stop events.
- [x] 8.4 Extend existing backend run-detail serialization and frontend API types with compact repair attempt count, high-signal status, semantic/safety outcome, and stop reason only.
- [x] 8.5 Add a compact read-only repair summary to the existing Verification/Findings detail without adding a generic artifact endpoint or prompt/response/script browser.
- [x] 8.6 Add backend/frontend tests proving all final statuses remain visible, denied output has no container-start event, and no existing API returns raw repair artifact content by path.

## 9. CLI, Backend Request, and Scan Creation Controls

- [x] 9.1 Add CLI flags for explicit LLM PoC repair enablement and `max_repair_attempts`, validate the `0..2` repair range, and document that repaired scripts require Docker.
- [x] 9.2 Extend backend scan request/config mapping and `/api/options` with disabled-by-default repair enablement, repair-attempt limit, effective config source, and actionable validation errors.
- [x] 9.3 Add frontend scan controls for LLM PoC repair and a bounded repair-attempt selector shown only for sandbox validation with Docker runner.
- [x] 9.4 Reject scan submissions that enable LLM repair with local runner, disabled sandbox, missing real/mock repair client configuration, or an out-of-range count.
- [x] 9.5 Add CLI/backend/frontend tests proving explicit controls reach `AuditConfig` and existing default offline/local scans remain unchanged.

## 10. Final Validation and Operator Documentation

- [x] 10.1 Run focused classifier, parser, manifest, assembler, semantic, safety, state-machine, Docker, redaction, report, replay, backend, and frontend tests.
- [x] 10.2 Run the full Python suite, full frontend suite, and TypeScript typecheck with no regression in deterministic local or Docker verification.
- [x] 10.3 Run the opt-in live Docker fixture with `python:3.12-slim` and explicit context/host targeting when available; persist an actionable skip reason when unavailable.
- [x] 10.4 Run an opt-in real-provider repair smoke on the authorized synthetic fixture and assert contract/policy/evidence invariants rather than exact edit wording.
- [x] 10.5 Update operator documentation with explicit enablement, Docker/model prerequisites, repair-count semantics, supported edit operations, protected evidence boundaries, artifact locations, status/stop semantics, and provider/Docker/policy troubleshooting.
- [x] 10.6 Document the deferred generic artifact-read API and full Web repair inspector as a separate future change rather than silently implementing them here.
- [x] 10.7 Run `openspec validate add-llm-poc-repair-agent-loop --strict` and resolve every artifact/spec validation error before implementation is considered complete.
