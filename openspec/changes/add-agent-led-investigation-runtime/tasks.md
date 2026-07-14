## 1. Contracts and configuration

- [x] 1.1 Add `agent-led` graph mode, agent-led default selection, investigation budget configuration, provider restrictions, and backward-compatible config parsing.
- [x] 1.2 Add versioned SecuritySignal, InvestigationHypothesis, InvestigationStep, EvidenceGateDecision, VerificationEvidencePackage, VerificationPlan, checkpoint, and summary models with strict validation.
- [x] 1.3 Add immutable artifact paths and serializers for signals, hypotheses, steps, checkpoints, evidence gates, and verification plans.

## 2. Repository investigation tools

- [x] 2.1 Implement bounded in-scope source search and source-context actions with exact content hashes and redaction-safe results.
- [x] 2.2 Implement deterministic lexical retrieval over RepositoryMetadata file content without embeddings.
- [x] 2.3 Implement lightweight Python symbol/import/direct-call indexing with explicit unresolved dynamic calls.
- [x] 2.4 Implement lightweight JavaScript/TypeScript symbol/import/direct-call indexing with explicit unresolved dynamic calls.
- [x] 2.5 Expose callers and callees as registered typed actions backed by the call-graph index.
- [x] 2.6 Expose the existing Dataflow engine as an on-demand registered investigation action.
- [x] 2.7 Implement fixed-argv, shell-disabled, timeout/output-capped Semgrep, Bandit, and Gitleaks adapters with normalized result/error observations.
- [x] 2.8 Implement the fixed Analysis action registry and reject unknown actions, arbitrary commands/code, unsafe paths, and untrusted execution parameters.

## 3. Agent-led investigation coordinator

- [x] 3.1 Convert the startup Pattern pass into SecuritySignal records that cannot directly promote findings.
- [x] 3.2 Add schema-validated Analysis hypothesis and next-action prompt/runtime contracts for the four supported classes.
- [x] 3.3 Implement the finite hypothesis state machine, deduplication, per-hypothesis round/tool budgets, and global hypothesis/candidate ceilings.
- [x] 3.4 Implement the investigation loop for signal-seeded and scanner-independent hypotheses through registered actions.
- [x] 3.5 Persist redacted prompts, responses, decisions, steps, tool refs, state transitions, and accounting correlations without hidden reasoning.
- [x] 3.6 Implement atomic hypothesis checkpoints and idempotent resume that never repeats completed billable/executable actions.

## 4. Trusted evidence gate

- [x] 4.1 Implement exact local path/line/excerpt/content-hash validation against the in-scope repository view.
- [x] 4.2 Implement evidence-origin identity and dual-evidence rules for Dataflow, call graph, normalized SAST, and independent source/config/manifest evidence.
- [x] 4.3 Reject Pattern-plus-same-line double counting, model/memory/CVE assertions, tool errors, unavailable tools, unreadable refs, drift, and out-of-scope evidence.
- [x] 4.4 Implement class-specific sanitizer/counterexample handling and deterministic promoted/refine/rejected gate results.
- [x] 4.5 Assemble normalized VerificationEvidencePackage records only for promoted hypotheses and exclude Analysis hidden reasoning.

## 5. Trusted verification planning and execution

- [x] 5.1 Add the VerificationPlan prompt/runtime contract using only normative evidence packages and registered primitives.
- [x] 5.2 Implement the verification primitive registry and reject code, shell, raw argv, external URLs, unknown paths/tools, container authority, and model verdicts.
- [x] 5.3 Implement trusted SQL injection, command injection, and path traversal plan compilers using harmless registered templates and bounded parameters.
- [x] 5.4 Implement the hardcoded-secret static-semantic compiler with literal, format/entropy, test/example exclusion, and configuration-override checks and no live network validation.
- [x] 5.5 Integrate compiled artifacts with the existing sandbox, validation, Judge, evidence, and reporting path, preserving typed-edit repair only after a trusted harness failure.
- [x] 5.6 Map unsafe, unsupported, stale, or inconclusive plans to trusted rejected/failed/manual-required statuses without model verdict authority.

## 6. Runtime lifecycle and observability

- [x] 6.1 Route CLI, Web, and public runtime omitted mode to agent-led while preserving explicit deterministic, adaptive, and legacy execution.
- [x] 6.2 Enforce audited single-model temperature-zero request/token/known-cost/time budgets and explicit dev/test-only mock behavior.
- [x] 6.3 Implement progress-aware deterministic fallback, partial trusted convergence, requested/effective mode, fallback reason, and degraded reasons.
- [x] 6.4 Add terminal `degraded` to job/API/frontend contracts while keeping old persisted payloads and existing client fields readable.
- [x] 6.5 Propagate cancellation through model, investigation tool process, sandbox process tree, remote cleanup, final checkpoint, and resource summary.
- [x] 6.6 Add report and Web summaries for modes, hypothesis/gate counts, verification-plan refs, investigation budgets, checkpoints, and degraded reasons without raw secrets or hidden reasoning.

## 7. Verification and promotion gates

- [x] 7.1 Add contract/state/policy tests covering invalid versions, fields, transitions, actions, paths, commands, code, Docker options, verdicts, and primitive parameters.
- [x] 7.2 Add tool/call-graph/adapter tests covering Python/JS/TS direct and unresolved calls plus Semgrep/Bandit/Gitleaks absent, timeout, malformed, version-varied, capped, and normalized outputs.
- [x] 7.3 Add EvidenceGate tests covering valid dual evidence, same-source rejection, nonlocal assertions/errors, counterevidence, drift, scope, replay, and redaction.
- [x] 7.4 Add verification tests for every primitive and confirmed/rejected/failed/manual-required results, trusted compilation, sandbox/Judge authority, and repair containment.
- [x] 7.5 Add checkpoint, no-repeat accounting, hard-budget, provider failure, mock fallback, partial convergence, degraded status, cancellation, compatibility, report, and Web tests.
- [x] 7.6 Add the reviewed 24-case paired blind-spot corpus across four classes with cross-file wrappers, indirect calls, config-driven behavior, and same-name safe implementations.
- [ ] 7.7 Add deterministic-versus-agent-led corpus evaluation for recall delta, zero negative false confirmation, scanner-no-signal promotion, evidence completeness, latency, and hard-budget gates. *(Runner exists; real-model promotion evidence remains deferred.)*
- [ ] 7.8 Add a documented fixed-commit three-repository real-model stability runner with three repetitions, normalized high/critical comparison, target-write/network/code-authority checks, and complete accounting assertions. *(Runner exists; the live 3 x 3 gate has not passed.)*
- [ ] 7.9 Run the focused and full Python suites, frontend tests/typecheck/build, OpenSpec strict validation, corpus promotion gates, and available real-model stability gate; record exact evidence and any credential-dependent deferred run. *(Local suites may pass independently; promotion gates remain incomplete until live evidence passes.)*
