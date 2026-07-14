## Context

DeepStrangeFake already has deterministic Pattern and Dataflow scanners, an adaptive execution graph, an audited LLM gateway, dependency intelligence, typed PoC repair, Docker-backed validation, Judge decisions, immutable artifacts, reports, and a Web job service. The current discovery path still begins by converting scanner matches into candidate findings; the model can prioritize or repair bounded artifacts, but it does not own a durable investigation loop. Scanner coverage therefore bounds what the system can discover.

This change introduces an agent-led path for the four currently supported vulnerability classes: SQL injection, command injection, path traversal, and hardcoded secrets. The model may form and refine hypotheses and select registered evidence actions. It may not create findings directly, execute arbitrary code or commands, widen repository scope, choose Docker arguments, or decide the final verdict. Trusted code retains those authorities.

The first-phase target is the existing single-machine CLI/Web runtime. It must reuse the current repository metadata, acquisition, LLM accounting, ArtifactStore, ToolBroker, verification, sandbox, Judge, reporting, and job lifecycle rather than create a second platform. Existing `deterministic`, `adaptive`, and `legacy` modes remain rollback choices. No database queue, multi-tenancy, dynamic child agents, real vector database, or unrestricted shell is introduced.

## Goals / Non-Goals

**Goals:**

- Make `agent-led` the default execution mode while keeping all prior modes explicit and compatible.
- Let the Analysis agent initiate bounded investigations from both scanner signals and its own repository-grounded hypotheses.
- Enforce versioned, schema-validated contracts and immutable checkpoints for hypotheses, investigation steps, evidence gates, evidence packages, and verification plans.
- Require exact local source evidence plus independent corroboration before trusted code promotes a candidate.
- Let the Verification agent select only registered class-specific validation primitives, then compile and execute them through trusted code and the existing sandbox/Judge path.
- Provide hard request, token, cost, time, hypothesis, round, tool-call, and candidate budgets with complete redacted accounting.
- Degrade explicitly and preserve completed trusted verdicts when a provider, tool, budget, timeout, or cancellation interrupts the agent-led path.
- Prove scanner-independent discovery on a reviewed paired blind-spot corpus and protect compatibility with existing APIs and reports.

**Non-Goals:**

- Adding vulnerability classes beyond SQL injection, command injection, path traversal, and hardcoded secrets.
- Allowing model-authored executable code, shell commands, tool registrations, repository paths, container settings, or verdicts.
- Replacing the existing deterministic/adaptive graph implementations or the bounded typed-edit PoC repair loop.
- Live credential validation over a network, exploit delivery against external systems, or destructive payloads.
- Real embedding retrieval, distributed scheduling, persistent database queues, multi-user isolation, or runtime human steering.
- Implementing dynamic worker creation or phase-two collaboration topology.

## Decisions

### 1. Add a separate bounded investigation coordinator behind the public runtime entry point

`GraphMode` gains `agent-led`. The public runtime chooses an `AgentLedInvestigationCoordinator` for that mode and continues to use the existing runtime for explicit legacy/deterministic/adaptive requests. The coordinator reuses repository analysis, artifact storage, message emission, LLM gateway/accounting, verification, and reporting services.

This is preferred over expressing every thought/action as adaptive graph mutation. Hypothesis refinement is naturally stateful, while graph mutation policy is designed around committed acyclic execution structure. Investigation state will remain a bounded state machine whose actions call existing registered services. Phase two may later introduce richer collaboration after phase-one evidence and budget invariants are proven.

### 2. Separate weak signals, model hypotheses, trusted promotion, and final verdicts

The runtime uses these schema-versioned records:

- `SecuritySignal`: a weak scanner or repository observation that cannot become a finding by itself.
- `InvestigationHypothesis`: a class, scoped claim, target refs, state, confidence, rationale, and budget lineage proposed by Analysis.
- `InvestigationStep`: one registered action, normalized input/output refs, observations, accounting refs, and resulting state.
- `EvidenceGateDecision`: trusted `promoted`, `refine`, or `rejected` result with rule diagnostics.
- `VerificationEvidencePackage`: the normative, redacted evidence view handed to Verification; model chain-of-thought is excluded.
- `VerificationPlan`: a list of registered primitive IDs and typed parameters, expected observations, and safety metadata.

Candidate findings are assembled only after a successful evidence gate. Final statuses remain owned by trusted verification and Judge. This strict authority split is preferred over asking one model response to emit a complete finding because it makes provenance, replay, and policy testing unambiguous.

### 3. Use a finite hypothesis state machine and checkpoint every committed transition

The state path is `proposed -> investigating -> supported|refuted|inconclusive -> evidence-gate -> promoted|refine|rejected`. Refinement creates a new bounded round under the same hypothesis lineage; completed tool steps are immutable and keyed for idempotent replay. Checkpoints contain normalized hypothesis state, completed action keys, artifact refs, remaining budgets, and last valid evidence package.

On resume, trusted code loads the latest valid checkpoint and will not re-bill or re-execute completed model/tool/sandbox work. Checkpoint files are written atomically through `ArtifactStore`. This is preferred over reconstructing progress solely from logs, which cannot reliably prevent duplicate side effects or billing.

### 4. Seed with lightweight patterns but make discovery agent-owned

Startup runs only the lightweight `PatternScanner` and records matches as `SecuritySignal` objects. Analysis receives repository metadata and a bounded lexical/call-graph summary and may propose hypotheses with or without a matching signal. Dataflow, Semgrep, Bandit, Gitleaks, source context, search, callers/callees, and lexical memory are invoked on demand through registered actions.

The fixed Analysis action vocabulary is: `search`, `source_context`, `callers`, `callees`, `dataflow`, `sast`, `lexical_memory`, `submit_gate`, and `abandon`. Tool requests identify registered IDs and typed arguments; the model cannot provide an executable, argv, shell text, raw Docker configuration, or an out-of-scope path.

This is preferred over running every scanner eagerly because it lets hypotheses direct evidence collection while retaining deterministic safety and cost bounds.

### 5. Build a lightweight local call graph and normalized external-tool adapters

The repository index extracts best-effort symbols, imports, and direct calls for Python, JavaScript, and TypeScript. Unknown or dynamic dispatch is preserved as an explicit unresolved edge instead of being guessed. Lexical retrieval ranks in-scope repository chunks with deterministic token scoring and contains no embedding provider.

Semgrep, Bandit, and Gitleaks adapters use fixed executable identities, fixed argument templates, `shell=False`, controlled working directories, timeouts, output caps, and versioned parsers. Missing executables, timeouts, unsupported versions, malformed output, and nonzero exits become structured observations and cannot alone promote a hypothesis. These tools are optional corroborators, not startup dependencies.

### 6. Enforce a trusted dual-evidence gate

Promotion requires:

1. An in-scope vulnerability class.
2. Exact repository-relative path, line, normalized excerpt, and current content hash from local repository content.
3. At least one independent corroborator: a Dataflow trace, call-graph path, normalized Semgrep/Bandit/Gitleaks result, or a second independent source/config/manifest location.

Pattern output and a source excerpt from the same line count as one source, not two. Memory/CVE text, model assertions, tool errors, unreadable refs, or unavailable tools cannot corroborate. A sanitizer, counterexample, source hash drift, scope escape, or contradictory evidence causes `refine` or `rejected`. The rule engine is deterministic and persists every satisfied/failed predicate.

This is preferred over confidence thresholds alone because confidence is neither independent nor replayable evidence.

### 7. Compile declarative verification plans from registered primitives

Verification receives only a `VerificationEvidencePackage` and returns a `VerificationPlan`. In phase one, each plan must contain exactly one registered primitive with typed fields; multi-primitive sequencing is deferred until execution order, partial failure, accounting, and replay semantics are specified. A `TrustedVerificationCompiler` validates class compatibility, path/content hashes, parameters, payload safety, and resource limits before producing the existing `PoCArtifact` or a non-executable static-semantic artifact.

Phase-one primitives are:

- SQL injection: existing SQLite setup, controlled input, parameter-binding/structured-result observations.
- Command injection: subprocess/argv hook, shell-use observation, and harmless marker.
- Path traversal: controlled root, path transformation, and out-of-bounds observation.
- Hardcoded secret: literal source, format/entropy, test/example exclusion, and config-override checks; no live network credential test.

SQL injection, command injection, and path traversal are sandbox/Judge-confirmed when a safe primitive is available. Hardcoded secrets may be confirmed using dual static-semantic evidence with `verification_type=static-semantic`. Unsafe or unsupported plans become `manual-required`. Existing typed-edit repair is available only after a trusted initial harness fails and never grants free-form code authority.

### 8. Apply hard budgets and progress-aware failure semantics

Defaults are 32 hypotheses, 6 rounds per hypothesis, 8 tool calls per hypothesis, 50 promoted candidates, 200,000 model tokens, 40 model requests, USD 5 when provider cost is known, and a 15-minute absolute run timeout. The audited LLM gateway is mandatory in agent-led mode and uses one configured model at temperature zero. Mock is allowed only when explicitly enabled for development/test.

Before every provider dispatch, the gateway computes a conservative provider-neutral prompt-token upper bound from the UTF-8 bytes of the system role, user prompt, response schema, and a fixed chat-framing allowance. It subtracts that estimate from the remaining run token budget and clamps the outgoing completion `max_tokens` to the smaller of the configured limit and the resulting allowance. A request with no positive completion allowance is recorded as a zero-dispatch budget denial. The estimator identity, pre-request counters, estimate, configured limit, and effective limit are persisted in the lifecycle ledger. Provider-reported usage remains authoritative after a response; a provider that ignores the transmitted completion limit is recorded with its actual usage and fails closed instead of having its overage hidden.

Structured-output negotiation is provider-capability aware. `llm.response_format` may pin `json_schema` or `json_object`; `auto` resolves known provider/endpoint capabilities before dispatch. Unknown OpenAI-compatible endpoints may probe JSON Schema once, then cache an HTTP-400 capability rejection by a provider/endpoint/model hash in run accounting state so later requests and checkpoint resume use JSON Object directly. The rejected attempt remains in the immutable lifecycle and missing provider usage is never rewritten as zero.

If no valid hypothesis exists when the real model is unavailable, the runtime performs a full deterministic fallback. If valid evidence already exists, it stops new hypotheses and completes trusted gates, verification, evidence, and reporting from accumulated work. Budget/time exhaustion behaves similarly. Requested/effective mode divergence, budget exhaustion, or mid-run provider failure produces terminal `degraded`; completed Judge statuses are preserved and remaining candidates become `manual-required`. Explicit legacy/deterministic/adaptive runs can still finish `succeeded`.

Cancellation propagates to the current model request, registered tool, sandbox process tree, and remote cleanup. The runtime still writes a final checkpoint and resource summary.

### 9. Keep public changes additive except for the new default

Configuration, CLI, and Web request schemas accept `agent-led`, which becomes the default when omitted. Old persisted payloads without new fields remain readable. Job lifecycle gains terminal `degraded`. Run/report summaries add requested/effective mode, fallback and degradation reasons, hypothesis/gate counts, verification-plan refs, investigation budget, and checkpoint summary.

Detailed redacted records live under immutable `signals/`, `investigations/hypotheses/`, `investigations/steps/`, `investigations/checkpoints/`, `evidence-gates/`, and `verification-plans/` directories. The Web UI exposes summaries and artifact refs but not hidden model reasoning or raw secrets.

### 10. Gate promotion with a paired blind-spot corpus and real-model stability runs

The repository adds 24 reviewed fixtures: for each of the four supported classes, three vulnerable cases intentionally missed by the lightweight pattern seed and three paired safe/fixed cases. Fixtures cover cross-file wrappers, indirect calls, configuration-driven behavior, and same-name safe implementations.

Acceptance requires agent-led candidate recall improvement of at least 0.30 over deterministic on the 12 positives; zero false-confirmed results on the 12 negatives; one end-to-end hypothesis with no startup signal; dual evidence, independent verification plan, and Judge trace for every confirmed finding; and per-case latency no greater than `max(60 seconds, 3 x deterministic)`. Hard budgets are measured, not inferred.

Three reviewed small public repositories at fixed commits are run three times with a real model. At least one expected high/critical issue must confirm, normalized high/critical confirmed findings must be identical across all three runs, and the runs must prove no target writes, external exploit network, model-authored execution, or incomplete accounting.

## Risks / Trade-offs

- [Model quality produces weak or repetitive hypotheses] -> Enforce schema, action/state budgets, deduplication, deterministic tool observations, and checkpointed fallback.
- [Agent-led mode is slower than eager scanners] -> Use lightweight seed/indexing, per-hypothesis action caps, cached idempotent tool results, global timeout, and the explicit latency gate.
- [External SAST output varies by version] -> Normalize only supported JSON shapes, record tool/version/parser diagnostics, cap output, and treat failures as non-promoting observations.
- [Lightweight call graphs miss dynamic dispatch] -> Mark unresolved calls explicitly, allow source/search/Dataflow corroboration, and do not manufacture edges.
- [Dual evidence still correlates two views of one source] -> Track evidence origin and content identity and reject same-line/same-origin double counting.
- [Default-mode change surprises callers] -> Preserve explicit modes, expose requested/effective mode, read old payloads, and provide deterministic fallback with a degraded terminal state.
- [Static-semantic secret validation over-confirms examples] -> Require format/entropy plus placement/override checks and explicit test/example exclusions; never contact a live provider.
- [Cancellation leaves child processes] -> Reuse bounded process-tree cleanup, propagate cancellation tokens, and verify cleanup in tests.
- [Artifact volume grows] -> Store redacted structured records and refs, cap tool output, and expose compact summaries in reports/UI.

## Migration Plan

1. Add contracts, serializers, default configuration, artifact paths, and backward-compatible API fields without changing runtime routing.
2. Add repository index, registered investigation tools, external adapters, and deterministic EvidenceGate with isolated tests.
3. Add Analysis investigation coordination, checkpoints, budget/cancellation handling, and deterministic fallback.
4. Add VerificationPlan, trusted compiler, class primitives, and integration with the existing verification/sandbox/Judge loop.
5. Route omitted mode requests to `agent-led`, add `degraded`, and expose report/Web summaries.
6. Add blind-spot fixtures and run unit, integration, safety, compatibility, latency, budget, and real-model promotion gates.

Rollback is configuration-only: explicitly select `deterministic`, `adaptive`, or `legacy`. Existing artifact readers ignore additive fields and continue to read old runs. No persistent database migration is required.

## Open Questions

No phase-one architectural questions remain open. Dynamic collaboration topology, richer retrieval, distributed execution, and runtime human intervention are deferred to `add-bounded-dynamic-agent-collaboration` after all phase-one gates pass.
