## Why

The verification loop already generates and executes path-traversal and SQL-injection PoCs, but its current repair behavior is limited to two hard-coded missing-import fixes. A constrained LLM repair agent is now the highest-value next step, provided that model-authored changes cannot fabricate the stdout markers or structured result files consumed by the deterministic Judge.

## What Changes

- Add a `PoCFailureClassifier` that classifies failed attempts as `harness-error`, `policy-denied`, `environment-error`, `semantic-rejected`, or `missing-evidence`, and makes retry eligibility explicit.
- Add a generator-owned repair manifest that identifies protected evidence-producing code and the small set of editable imports or setup slots available to repair.
- Add an `LLMPoCRepairAgent` that receives only the prior generated script, repair manifest, redacted diagnostics, grounded dataflow/source context, missing-evidence requirements, and attempt index, then returns a strictly validated typed-edit response rather than a replacement script.
- Add a semantic-integrity gate that applies typed edits in trusted code and proves that payload construction, sink execution, semantic measurements, confirmation markers, and result writers are unchanged.
- Add an AST-based `PoCSafetyGate` that rejects unsafe imports, calls, paths, network access, process execution, dependency installation, target-repository writes, and other forbidden behavior before any repaired script reaches a sandbox runner.
- Keep command construction, `expected_signal`, retry budget, sandbox policy, and final Judge verdict outside LLM control; repaired scripts always run through the existing fixed Python argv and independent Judge.
- Replace fixed-rule retry selection with a bounded classify -> repair -> semantic-integrity -> safety -> sandbox -> Judge loop, while preserving deterministic fallback when LLM repair is disabled, unavailable, malformed, repeated, or unsafe.
- Add repair-specific configuration that is disabled by default, uses an unambiguous `max_repair_attempts` limit, and cannot be enabled accidentally by the legacy default repair flag.
- Persist every classification, prompt, redacted response, diagnosis, normalized edit list, assembled script, script hash, integrity decision, safety result, sandbox result, and Judge outcome as run artifacts.
- Extend JSON/Markdown reports and replay summaries with all repair attempts and stop reasons; expose only compact repair summaries through existing Web run details in this phase.
- Add closed-loop acceptance tests covering a successful Docker repair, forged confirmation output and result-file denial, unsafe output rejection without container startup, infrastructure short-circuiting, semantic rejection terminality, missing structured evidence, duplicate-script stopping, and target-repository immutability.

## Capabilities

### New Capabilities

- `llm-poc-repair-loop`: Classifies PoC failures and performs bounded, evidence-grounded typed repairs without granting the model verdict, evidence-emission, or execution authority.
- `poc-script-safety-gate`: Validates typed repair operations and assembled Python PoC scripts, preserves protected evidence semantics, and enforces fixed-command, no-network, no-host-write, and target-immutability constraints before sandbox execution.

### Modified Capabilities

- `llm-agent-decision-contracts`: Adds a strict typed-edit `poc-repair` request/response contract, allowed context, dedicated exact-field validation, and fail-closed handling for malformed model output.
- `guarded-agent-decision-loop`: Adds repair-specific policy gates so only repairable harness or missing-evidence failures may invoke the LLM and terminal or infrastructure outcomes cannot be retried toward confirmation.
- `decision-auditability-and-replay`: Requires repair classifications, prompts, redacted responses, typed edits, semantic-integrity decisions, script hashes, safety decisions, attempts, stop reasons, and target-integrity evidence to be available in artifacts, reports, and replay.

## Impact

- Verification orchestration and models: `audit_agent/verification.py`, `audit_agent/models.py`, and focused modules for failure classification, repair-agent logic, typed-edit assembly, semantic integrity, and the safety gate.
- LLM and prompt runtime: `audit_agent/llm.py`, `audit_agent/prompts.py`, a dedicated strict repair-response parser, prompt fixtures, provider/mock behavior, text redaction, budgets, and message-bus events.
- Configuration and entrypoints: disabled-by-default repair enablement and unambiguous repair-attempt limits in config, CLI, backend request schemas/options, and frontend scan controls.
- Audit surfaces: report generation, replay summaries, compact existing Web validation summaries, and on-disk artifact refs. A generic artifact-read API and full Web script/prompt browser are deferred to a separate change.
- Tests: unit tests for classification, exact response validation, semantic integrity, safety policy, and redaction plus end-to-end Docker verification tests for repair success, evidence-forgery denial, terminal failures, and repository immutability.
- No new runtime package is expected for the MVP; Python's `ast` module is sufficient for the safety gate, and the existing LLM client and Docker sandbox runner are reused.
