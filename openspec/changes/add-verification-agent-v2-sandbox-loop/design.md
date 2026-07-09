## Context

The current audit runtime already has four agents, dataflow-backed findings, a runtime kernel, artifact storage, replay summaries, backend APIs, and a Web run detail view. Verification currently produces accept/reject decisions from local evidence and policy gates, then the validation service can mark accepted findings with `static-only`, `poc-generate`, `sandbox`, or `manual`.

The weak point is that runtime validation is not yet a real closed loop. `Validator` can write a non-executable PoC JSON artifact or run `safe_commands[0]` in a temp directory with shell command execution. Runtime reporting only receives accepted findings, so rejected and manual-required candidates are not visible in the main report path. This change makes Verification v2 evidence-first in a stricter sense: a finding can be `confirmed` only when a generated PoC executed in a local attempt directory and a Judge classified the execution evidence as confirming the vulnerability.

## Goals / Non-Goals

**Goals:**
- Add explicit PoC and verification records that are persisted as real run artifacts and referenced by findings, evidence chains, runtime state, replay, reports, and Web pages.
- Replace configured-command sandbox validation with a PoC-driven `LocalSandboxRunner` that uses `shell=False`, fixed `argv`, isolated attempt directories, bounded environment, timeouts, stdout/stderr capture, and artifact write-boundary checks.
- Enforce a status model of `confirmed`, `likely`, `rejected`, and `manual-required` where every status has machine-verifiable evidence.
- Ensure static accept is never reported as `confirmed`; static-only evidence can be `likely` at most and must not increment `confirmed_count`.
- Deliver one true MVP closed loop for path traversal dataflow findings: generate a safe executable PoC, run it locally, Judge the result, and report evidence.
- Show all verification candidates in report/Web output, not only accepted findings, so false-positive filtering and blocked validations are auditable.

**Non-Goals:**
- Do not promise SQL injection, command injection, hardcoded secret, or arbitrary vulnerability-class PoC execution in this MVP.
- Do not add Docker, VM, Windows Sandbox, or OS-level network namespaces in this change.
- Do not execute attacks against live third-party services or public targets.
- Do not modify target project source code during self-repair; only generated PoC artifacts may be repaired.
- Do not treat LLM output, CVE MCP intelligence, memory retrieval, or static acceptance as confirmation.

## Decisions

### Decision 1: Separate Verification Status from Accept/Reject Triage

Verification Agent v2 should keep accept/reject or triage decisions separate from final verification status. `accept` means a candidate is eligible for validation or reporting review; `confirmed` means the PoC/Judge loop produced machine-verifiable runtime evidence. Static accept, LLM agreement, and CVE context can influence priority and rationale, but they cannot set `confirmed`.

Alternative considered: overload existing `VerificationDecision.decision` with `confirmed` and `likely`. That would blur triage with verification proof and make it easier to accidentally count static acceptance as confirmed.

### Decision 2: Add First-Class Verification Evidence Models

Add dataclass-style models near existing run models:
- `PoCArtifact`: finding ID, vulnerability class, generator, script path, command argv, target file refs, dataflow trace refs, safety profile, created timestamp, and artifact ID.
- `SandboxRunResult`: PoC ID, attempt ID, cwd, argv, timeout, environment summary, started/finished timestamps, duration, exit code, timed-out flag, stdout/stderr artifact refs, stdout/stderr previews, generated artifact refs, policy decisions, and runner status.
- `VerificationAttempt`: finding ID, attempt index, status, PoC ref, sandbox result ref, Judge reason, repair reason, blocking reason, and evidence refs.
- A final verification summary attached to the finding/evidence chain with `verification_status`, `confirmed_count` eligibility, and status-specific evidence refs.

These records should serialize through existing `to_plain` helpers and be stored under the run directory, for example `verification/<finding-id>/attempt-<n>/`.

Alternative considered: keep full verification state in `Finding.metadata`. Metadata is acceptable for compact summaries, but it is too easy to lose artifact integrity and too hard to validate from reports.

### Decision 3: LocalSandboxRunner Replaces Configured Command Execution

`LocalSandboxRunner` must receive a `PoCArtifact`, not a global `safe_commands[0]`. The runner builds an isolated attempt directory, writes or copies only the PoC and explicitly required fixture files, executes `argv` with `subprocess.run(..., shell=False)`, captures stdout/stderr to files, records exit code and timeout state, and rejects artifact paths outside the attempt directory.

The runner should use a small command allowlist such as Python interpreter commands needed by the current Python 3.12 environment. The allowlist applies to executable and argument shape, not arbitrary command strings. Network control is best-effort in this local MVP: clear proxy env variables, deny URL/network-oriented command/script patterns, and disallow live target inputs. Strong network isolation remains a future Docker/VM responsibility.

Alternative considered: keep configurable safe commands with stricter string filters. That remains too indirect because the command is not tied to a finding-specific PoC and string filtering is not a security boundary.

### Decision 4: Path Traversal Is the Only MVP Executed Vulnerability Class

The first executable PoC generator and Judge should target path traversal dataflow findings. A safe path traversal PoC can create an attempt-local base directory, place a harmless sentinel file, exercise the vulnerable path expression or generated harness, and Judge whether traversal outside the intended base was possible. It can produce either `confirmed` or `rejected` from local execution evidence.

SQL injection, command injection, file-read variants without a usable path traversal harness, and hardcoded secret findings should fall back to `likely` or `manual-required` until they have class-specific PoC generators and Judges.

Alternative considered: implement shallow generators for several classes. That would create a tempting demo surface but weaken evidence semantics and likely reintroduce false confirmation.

### Decision 5: Judge Reads Execution Evidence, Not Return Code Alone

The Judge must inspect `SandboxRunResult`, stdout/stderr previews or artifacts, generated result files, and the expected signal declared by `PoCArtifact`. Return code can be part of the evidence, but a zero return code alone is not enough for `confirmed`. Every final status must include a `judge_reason` and references to the evidence that supports it.

Alternative considered: mark return code 0 as passed. That is easy to test but allows placeholder scripts to confirm findings without proving the vulnerability behavior.

### Decision 6: Retry Repairs Only PoC Artifacts

Verification Agent v2 may run a bounded repair loop, with a default maximum of one or two retries. Repairs can address PoC syntax errors, missing local fixture paths, import path mistakes, or harness construction issues. Repairs must never alter the target repository, scanner output, or product code. Each attempt is persisted and visible in replay/report output.

Alternative considered: let the Agent modify target code or environment until a PoC passes. That would damage reproducibility and could manufacture confirmation.

### Decision 7: Reports and Web Show All Verification Candidates

The runtime should carry all verification candidates into reporting, including confirmed, likely, rejected, and manual-required. The report can keep a separate `findings` view for active vulnerabilities, but it must include an auditable `verification_candidates` or equivalent section that exposes status, reason, evidence refs, and artifact paths. Web detail pages should show status distribution and evidence links without hiding rejected or blocked candidates.

Alternative considered: keep final reports limited to accepted findings and put rejected cases only in runtime artifacts. That makes false-positive filtering hard to audit from the primary output.

## Risks / Trade-offs

- [Risk] Process-level local sandboxing is not strong isolation. -> Mitigation: make the MVP no-live-target, use `shell=False`, bounded argv allowlists, isolated directories, no broad repository writes, best-effort network denial, and document Docker/VM as future strong isolation.
- [Risk] Path traversal PoC generation may not work for every framework shape. -> Mitigation: scope MVP tests to dataflow findings with enough path expression/source/sink context and return `manual-required` when a safe harness cannot be generated.
- [Risk] Report schema changes could confuse existing frontend or benchmark metrics. -> Mitigation: add new status fields and counts while keeping existing run endpoints stable; explicitly separate `confirmed_count`, `likely_count`, `rejected_count`, and `manual_required_count`.
- [Risk] Placeholder artifacts could satisfy superficial tests. -> Mitigation: require tests to open artifact refs from the run directory, execute PoC files, inspect stdout/stderr artifacts, and verify Judge reasons are derived from execution evidence.
- [Risk] LLM-assisted repair may introduce nondeterminism. -> Mitigation: default tests use deterministic or mock repair; live LLM repair remains opt-in and cannot override evidence gates.

## Migration Plan

1. Add models and serialization while keeping existing `ValidationResult` fields available.
2. Add `LocalSandboxRunner`, PoC generator, and Judge behind the existing validation phase.
3. Route dataflow-backed path traversal candidates through the new loop; route unsupported classes to `likely` or `manual-required` with explicit reasons.
4. Update evidence/report/runtime/Web payloads to include all verification candidates and status distributions.
5. Add fixture-driven closed-loop tests and regression tests for static-only not counting as confirmed.
6. Remove or bypass the configured `safe_commands[0]` execution path after the PoC-driven runner is covered.

Rollback is straightforward because the change is additive until the old configured-command sandbox path is removed. If the new loop fails during rollout, candidates should degrade to `manual-required` with blocking reasons instead of being confirmed.

## Open Questions

- Should `validated_count` remain as a backward-compatible alias for accepted/triaged findings, or should it be deprecated in favor of `confirmed_count` plus status distribution?
- Should Web report downloads include stdout/stderr previews only, or also expose direct artifact-file links for local run directories?
