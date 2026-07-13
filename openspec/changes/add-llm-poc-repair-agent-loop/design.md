## Context

The verification subsystem already has deterministic path-traversal and SQL-injection PoC generators, first-class `PoCArtifact` / `SandboxRunResult` / `VerificationAttempt` records, local and Docker sandbox runners, a deterministic Judge, report and replay output, and a Web run-detail page. `AgentRuntime` also builds one provider-neutral `LLMClient`, persists prompt and response artifacts, and publishes runtime events.

The missing part is the repair decision. `VerificationEngine` currently derives a small `repair_context` from stdout/stderr and only prepends `from pathlib import Path` or `import os`. It does not distinguish a broken harness from a terminal semantic rejection, does not ask an LLM for a grounded repair, and has no script-specific safety or semantic-integrity gate before retry execution.

This change adds that repair intelligence without weakening the existing evidence contract. The LLM proposes typed edits only for generator-declared repair slots; it does not replace the complete script or choose the process command, sandbox policy, expected signal, evidence emitter, retry budget, or verdict.

```text
deterministic generator
        |
        v
 repair manifest + protected AST hashes
        |
        v
   Python SafetyGate --------------------------> manual-required
        |                                         (policy denial)
        v
 DockerSandboxRunner
        |
        v
 deterministic Judge
   | confirmed/rejected -----------------------> provisional terminal for finding
   | environment/policy failure --------------> manual-required
   | repairable harness/missing evidence
   v
 PoCFailureClassifier
        |
        v
 LLMPoCRepairAgent -> exact typed-edit validation -> trusted assembler
                                                   |
                                                   v
                 SemanticIntegrityGate -> SafetyGate -> next Docker attempt
                          |
                          +-------------------------> manual-required on invalid,
                                                     forged, unsafe, or repeated output
```

## Goals / Non-Goals

**Goals:**

- Replace fixed import-only repair selection with a deterministic failure classifier and a real LLM-backed typed-edit repair agent.
- Keep repair authority narrow: generator-declared editable imports/setup slots only, grounded context only, fixed Docker execution, immutable evidence-producing code, and independent deterministic Judge.
- Enforce an AST-based safety gate before both initial and repaired PoCs execute, with stricter Docker-only execution for LLM-repaired scripts in this phase.
- Enforce a semantic-integrity gate that proves all non-editable AST nodes, evidence markers, semantic calculations, sink execution, and result writers remain generator-owned.
- Disable LLM PoC repair by default and bound it to one repair attempt by default and two repair attempts at the hard maximum.
- Persist enough structured evidence to reconstruct every classification, model call, normalized edit, assembled script, integrity decision, safety decision, sandbox execution, Judge outcome, and stop reason.
- Make the complete repair lifecycle inspectable in JSON/Markdown reports and replay, with compact summaries in existing Web run details.
- Prove that target repository files remain unchanged across the verification phase.

**Non-Goals:**

- Do not let the LLM generate the first PoC for code shapes unsupported by deterministic generators.
- Do not add command-injection, file-read, ORM, JS/TS, or additional vulnerability-class PoC generators.
- Do not let the LLM replace a complete script or alter `command_argv`, `expected_signal`, protected harness semantics, sandbox configuration, evidence requirements, verification status, or Judge implementation.
- Do not execute LLM-repaired scripts through the local process runner in this phase.
- Do not install packages, enable network access, mount the Docker socket, mount the target repository writable, or run privileged containers.
- Do not claim that AST inspection alone is a complete security boundary; Docker policy remains the runtime isolation boundary.
- Do not add a generic backend artifact-read API or a full Web prompt/response/script browser in this change; those inspection surfaces require a separate security-focused proposal.

## Decisions

### Decision 1: Classify failures before deciding whether repair is allowed

Add a deterministic `PoCFailureClassifier` that reads the PoC metadata, sandbox result, and Judge outcome and produces a first-class classification record:

| Class | Typical evidence | Repair policy |
|---|---|---|
| `harness-error` | Python syntax/import/name/path/fixture setup failure | Eligible for bounded repair |
| `missing-evidence` | Runner completed but the Judge-required artifact or signal is absent | Eligible only when execution infrastructure succeeded and the requirement is immutable |
| `policy-denied` | Safety gate or sandbox policy denial | Terminal `manual-required` |
| `environment-error` | Docker unavailable, image missing, startup failure, or timeout | Terminal `manual-required` |
| `semantic-rejected` | Judge-readable evidence proves sanitization/no-flow/parameter binding | Terminal `rejected` |

The classifier should use status fields and machine-readable artifacts before diagnostic text. Diagnostic pattern matching may refine `harness-error`, but it cannot override a policy, infrastructure, or semantic result.

PoC failure classification and repair-loop termination are separate records. Provider failures, invalid responses, duplicate edits/scripts, exhausted budgets, semantic-integrity failures, and target-integrity changes are `RepairStopReason` values; they do not rewrite the prior PoC attempt's failure class. A pre-execution SafetyGate denial may create `policy-denied` without a `SandboxRunResult`, so classifier inputs are stage-aware and optional rather than assuming every failure has runner and Judge artifacts.

Alternative considered: send every non-confirmed attempt to the LLM. That would encourage the model to turn real rejection evidence into a passing harness and blur infrastructure failures with code repair.

### Decision 2: Reuse the runtime LLM client through dependency injection

`AgentRuntime` should pass its already-constructed `LLMClient`, prompt persistence service, `ArtifactStore`, and `MessageBus` references into `VerificationEngine` or a small repair-runtime context. `LLMPoCRepairAgent` remains independently testable by accepting an `LLMClient` protocol and persistence/event callbacks. Legacy or non-runtime entrypoints pass no repair client and degrade deterministically.

The repair role uses a versioned prompt template such as `poc-repair.edits.v1`. Its request includes only:

- the previous generated Python script;
- the generator-owned repair manifest with editable slot IDs and allowed operation kinds;
- redacted and length-bounded stdout/stderr diagnostics;
- the openable dataflow trace and compact source/sink locations;
- length-bounded source/sink code snippets read from the current target;
- a read-only description of evidence the Judge did not observe; and
- the current repair attempt number and remaining budget.

Repository snippets are delimited as untrusted data. Before prompt submission, text redaction covers known configured secrets and credential-shaped literals found in snippets or diagnostics. API keys, arbitrary environment variables, unrelated repository files, Docker configuration, and host paths are excluded. Standard persisted artifacts contain only redacted prompt/response content; raw provider payloads are not linked from reports or exposed through backend/Web surfaces in this change.

Alternative considered: let `VerificationEngine` construct a second LLM client. Reusing the runtime client keeps provider configuration, budgets, retries, redaction, and test injection consistent and avoids duplicate client state.

### Decision 3: The model returns a strict typed-edit contract

The only accepted response shape is strict JSON with no additional fields:

```json
{
  "diagnosis": "the generated harness is missing pathlib.Path",
  "edits": [
    {
      "op": "add_import",
      "slot_id": "imports",
      "module": "pathlib",
      "name": "Path"
    }
  ],
  "changes": ["add the allowed Path import"]
}
```

`diagnosis` and `changes` are audit explanations. `edits` is a closed union of operation objects such as allowlisted `add_import` and `replace_slot`; every operation must name a slot and operation kind declared by the original generator-owned repair manifest. A dedicated `parse_poc_repair_response` validator checks the exact top-level key set, exact per-operation key set, nested types, non-empty values, list bounds, text-size limits, operation allowlist, and `additionalProperties: false` semantics. The current generic LLM schema helper is not sufficient for this contract.

Trusted code applies normalized edits to a copy of the original script, creates the next attempt directory, computes script and edit-list SHA-256 hashes, clones immutable generator-owned metadata, and constructs the fixed Python command. The model never returns a complete script and never receives an output field for verdict, command, expected signal, policy, or artifact path.

For the `poc-repair` role, the provider request carries the complete nested response schema as an OpenAI-compatible `response_format`. The client requests strict `json_schema` output first and, only when an otherwise reachable compatible endpoint rejects that capability with HTTP 400, retries with `json_object`. The prompt includes a minimal valid JSON example and explicit field-name/type rules. `json_object` is only a generation aid: the dedicated exact parser remains authoritative and MUST reject rather than rename, unwrap, coerce, or otherwise guess malformed model fields.

Parse errors, extra keys, unsupported operations, undeclared slot IDs, empty edits, oversized values, or provider errors do not reach the assembler or runner. They produce a persisted failed repair record and a `RepairStopReason` without reclassifying the prior PoC attempt.

Alternative considered: accept a complete replacement script. That is easy to persist but unsafe for evidence semantics because the model could print a confirmation marker or write a forged Judge result. A typed edit contract keeps the generator in control of executable meaning.

### Decision 4: Use a generator repair manifest and SemanticIntegrityGate

Each supported deterministic generator emits a repair manifest beside the initial `PoCArtifact`. The manifest assigns stable IDs to editable import/setup slots and records protected AST hashes for payload construction, target-derived expressions, sink execution, baseline/attack measurements, marker calculations, confirmation/rejection literals, and Judge-facing result writers.

Trusted assembly applies only declared operations to declared slots. `PoCSemanticIntegrityGate` then parses the assembled script and proves that every protected node hash still matches the initial manifest, that edits occur only in declared slots, and that editable code does not emit expected marker literals or write Judge result filenames. The gate also verifies that no edit removes the protected path/SQL semantic checks or replaces measurements with constants.

For path traversal, the final resolved-path comparison and `PATH_TRAVERSAL_CONFIRMED/BLOCKED` emitter remain protected. For SQLi, payload/query construction, SQLite execution, baseline/attack counts, `marker_seen`, status derivation, and `sqli-result.json` serialization remain protected. A model response that prints an expected marker, writes a Judge artifact, hard-codes confirming counts, or changes protected query semantics is denied before Docker starts.

Alternative considered: rely on immutable `expected_signal` metadata plus the existing Judge. That protects the expected field but not the model-authored script that produces Judge input, so it cannot prevent self-fulfilling evidence.

### Decision 5: Enforce a Python AST SafetyGate before execution

Add `PoCSafetyGate` and run it for the initial deterministic script and every repaired script. It parses the script with Python `ast`, records rule IDs and locations, and fails closed on parse failure. The initial and repaired paths share core rules; repaired scripts additionally require the Docker runner.

The gate denies at least:

- imports of `subprocess`, `socket`, `requests`, network clients, package managers, and dynamic loader helpers;
- `os.system`, `os.popen`, process spawn/exec/fork calls, `eval`, `exec`, `compile`, and dynamic `__import__`;
- URL/network literals and dependency-install commands;
- Docker socket access, privileged/container-management calls, and broad host mounts;
- absolute host paths, Windows drive/UNC paths, and writes not rooted in the attempt directory;
- attempts to import or mutate target project modules/files; and
- script features the gate cannot safely reason about, such as opaque dynamic attribute/call construction.

Safe standard-library use required by current generators remains allowed, including constrained `pathlib`, `json`, `sqlite3`, and safe `os.path` operations. The gate is intentionally conservative. A denied script is never sent to `SandboxRunner.run`, and the denial is `manual-required`, not `rejected` or `confirmed`.

LLM-repaired scripts execute only with `DockerSandboxRunner` using the existing `--network none`, read-only root, dropped capabilities, no-new-privileges, resource limits, and attempt-only writable mount. The target repository is not mounted into the repair container.

Alternative considered: rely only on Docker policy. Defense in depth is needed because a repair model can emit obviously disallowed behavior that should be rejected before container creation and should remain inspectable as a policy decision.

### Decision 6: Make immutable execution inputs explicit

The first deterministic `PoCArtifact` is the authority for vulnerability class, generator ID, target/dataflow refs, safety profile, `expected_signal`, repair manifest, and protected AST hashes. Store an immutable execution-envelope hash over those fields plus the fixed command shape. Each repaired attempt references the original envelope and may replace only declared editable slots, the assembled script path/hash, normalized edit refs, and repair provenance.

The host-side command is always constructed by trusted code as the configured Python executable plus the attempt-local `poc.py`; Docker normalization continues to produce `python /attempt/poc.py`. Any model text resembling argv, evidence emitters, or policy changes is rejected by exact response validation or the semantic-integrity gate.

Alternative considered: copy the whole model-provided PoC metadata object. That would let a repair silently weaken evidence requirements or select a different execution command.

### Decision 7: Use a bounded, monotonic repair state machine

Introduce a dedicated `PoCRepairConfig` with `enabled = false` and `max_repair_attempts = 1`, with the repair count accepting `0..2`. Total execution attempts are always `1 + max_repair_attempts`: one deterministic initial execution plus the bounded repairs. New CLI/API/UI fields map only to this repair-specific config.

The legacy `llm_decisions.repair_enabled` default is true even when LLM decision mode is disabled, so it MUST NOT enable PoC repair by itself. For one migration cycle, legacy enablement is honored only when `llm_decisions.enabled` and `llm_decisions.repair_enabled` are both true and the new `poc_repair` section is absent. Legacy `max_repair_attempts` may then supply the bounded count. Persist the effective source (`explicit`, `legacy`, or `default`) for replay and troubleshooting.

The state machine is monotonic:

1. Build one run-level before-manifest over the current in-scope target file set.
2. Generate the initial deterministic PoC, repair manifest, execution envelope, and protected AST hashes.
3. Semantic-integrity-check and safety-check the initial PoC, then execute it in Docker and Judge.
4. Treat `confirmed` or `rejected` as provisional terminal outcomes for the finding and do not request another repair.
5. Classify any non-terminal PoC evidence.
6. Invoke the repair agent only for eligible `harness-error` or `missing-evidence` that names at least one compatible editable slot.
7. Validate the exact typed-edit contract, normalize/hash edits, apply them in trusted code, and stop if the edit hash or assembled script hash matches a prior attempt.
8. Run SemanticIntegrityGate and SafetyGate, then execute in Docker and Judge the new immutable attempt.
9. After all finding attempts, build the run-level after-manifest before final status/report persistence.
10. If integrity changed, stop repair, downgrade provisional confirmations to `manual-required`, attach the diff, and only then finalize validation outcomes.

No later attempt may convert an earlier `semantic-rejected` result into `confirmed`. Infrastructure and policy failures are not repair prompts. Missing structured SQLi evidence is repairable only when the repair manifest exposes a compatible setup slot; the model cannot edit or recreate the protected result writer. Exit code 0 remains insufficient until the protected writer produces `sqli-result.json` and the existing Judge semantics pass.

Alternative considered: an open-ended agent loop. A hard bound is necessary for cost, reproducibility, and preventing success-seeking behavior.

### Decision 8: Keep the Judge deterministic and independent

`VerificationJudge` continues to consume the trusted original expected signal and actual `SandboxRunResult` artifacts. The repair prompt may describe missing evidence, but the model cannot set the Judge outcome. `confirmed` and PoC-backed `rejected` retain all prior requirements.

The LLM repair response is neither evidence of a vulnerability nor a verdict. If a repaired script exits 0 without required structured evidence, the Judge returns provisional `manual-required`; if parameterized SQL produces contradiction evidence, it returns provisional `rejected` and the loop stops. A final target-integrity gate runs before provisional outcomes are persisted as final report status.

Alternative considered: ask the same model to evaluate its repaired script. That would remove separation of duties and allow plausible prose to substitute for machine evidence.

### Decision 9: Persist a complete repair artifact graph without broadening Web file access

Add first-class records such as `PoCFailureClassification`, `PoCRepairRecord`, `PoCSemanticIntegrityDecision`, and `PoCSafetyDecision`, and extend `VerificationAttempt` with their refs, normalized edit hash, prior/new script hashes, redacted prompt/response refs, repair changes, and stop reason. Suggested attempt artifacts are:

```text
verification/<finding-id>/attempt-<n>/
  poc.py
  poc.json
  repair-manifest.json
  failure-classification.json
  repair-record.json
  semantic-integrity.json
  safety-gate.json
  stdout.txt
  stderr.txt
  sandbox-result.json
  verification-attempt.json
```

Existing redacted prompt and normalized response artifacts remain under their runtime artifact directories, with refs linked from `repair-record.json`. Raw provider payloads, if retained by existing protected diagnostics, are not referenced from reports or Web data. Publish message events for classification, repair request/response, exact-contract failure, semantic-integrity denial, safety denial, sandbox execution, Judge result, duplicate stop, and budget stop.

Reports and replay should summarize all attempts, classifications, normalized edits, semantic-integrity decisions, hashes, safety outcomes, runner metadata, and stop reasons while linking on-disk artifacts. Existing Web validation payloads may expose compact status, attempt count, and stop-reason summaries, but this change does not add a generic artifact endpoint or a browser for prompts, responses, or executable scripts.

Alternative considered: place everything in `Finding.metadata`. Compact summaries belong there, but complete scripts, prompts, responses, and evidence records need independent immutable files.

### Decision 10: Record target integrity around verification

Build one SHA-256 manifest for the run's in-scope target file set immediately before the validation phase and re-enumerate the same audit scope after all attempts, detecting changed, added, and removed files. Persist both manifests and a comparison record before final validation/report persistence. Repaired scripts receive source snippets but no writable target mount. If any in-scope target file changes during verification, stop further repair, downgrade all provisional confirmations to `manual-required`, attach the integrity-diff artifact, and never report those attempts as confirmed. Rejected results retain their contradiction evidence but carry the run-level integrity warning.

This proves the no-target-modification invariant for tests and normal runs while acknowledging that an external process could independently change the repository.

Alternative considered: hash only the finding's source file. A run-level in-scope manifest provides stronger evidence and catches unintended writes to related fixtures or modules.

## Risks / Trade-offs

- [Risk] Model-authored edits can try to manufacture Judge input rather than repair the harness. -> Mitigation: expose typed edits only, protect evidence-producing AST nodes, deny expected markers/result writers in editable slots, and test direct stdout/JSON forgery attempts.
- [Risk] Static AST checks can miss behavior hidden behind complex Python semantics. -> Mitigation: use generator-declared slots, a conservative allowlist, semantic protected-node hashes, Docker-only repaired execution, disabled network, and no target mount.
- [Risk] Source snippets can contain prompt injection text or hard-coded credentials. -> Mitigation: delimit them as untrusted data, cap size, exclude unrelated files, redact known and credential-shaped secrets, validate the response contract, and enforce all authority outside the prompt.
- [Risk] The LLM can repeatedly produce plausible but ineffective repairs. -> Mitigation: cap attempts at two, stop on duplicate hashes, retain all failures, and end `manual-required` without relaxing evidence.
- [Risk] Failure classification based on diagnostics can be wrong. -> Mitigation: give structured runner/Judge statuses precedence, persist classifier evidence, and default unknown cases to non-repairable `manual-required`.
- [Risk] Full in-scope hashing adds I/O on large repositories and can detect external edits. -> Mitigation: reuse repository metadata scope, stream hashes, persist the changed-file list, and explain external-change ambiguity in the blocking reason.
- [Risk] A live provider makes exact edit output nondeterministic. -> Mitigation: default tests use `MockLLMClient`; live repair smoke tests are opt-in and assert exact-contract, semantic-integrity, and Judge invariants rather than exact prose.
- [Risk] The narrow edit DSL cannot repair every runtime harness problem. -> Mitigation: return `manual-required` for unsupported repairs and expand operation types only in later changes with generator-specific protected semantics and tests.

## Migration Plan

1. Add failure-classification, repair-stop, repair-manifest, typed-edit, semantic-integrity, safety, and target-integrity models with serialization tests.
2. Add generator repair manifests and protected AST hashes for the current path-traversal and SQLi harnesses.
3. Add the exact typed-edit parser, prompt fixtures, text redaction, and `LLMPoCRepairAgent` with injected mock/real `LLMClient` support.
4. Add the trusted edit assembler, SemanticIntegrityGate, SafetyGate, and fixed execution-envelope helpers before changing retry orchestration.
5. Refactor `VerificationEngine` and `AgentRuntime` to use the classifier and bounded repair state machine with provisional Judge outcomes and a final run-level integrity gate.
6. Add disabled-by-default repair configuration and CLI/backend/frontend enablement controls with guarded legacy migration.
7. Extend report, replay, and compact existing Web validation summaries without adding broad artifact-read APIs.
8. Pass the core acceptance gate, then run live Docker/provider smoke tests, full Python/frontend suites, type checking, and strict OpenSpec validation.

Rollback is configuration-first: disable `poc_repair.enabled` to retain deterministic initial PoC execution and Judge behavior. The new artifacts are additive and can remain readable even when repair is disabled.

## Open Questions

- A future change may decide whether safe local-runner repair is useful, but phase one deliberately requires Docker for any LLM-repaired script.
- New edit operation kinds require a generator-specific protected-semantics design and cannot be enabled only by adding a prompt example.
- A generic repair artifact-read API and full Web prompt/response/script inspector require a separate proposal with independent path-containment and disclosure review.
- LLM generation of an initial PoC for unsupported deterministic shapes remains a separate proposal after this repair loop is proven.
