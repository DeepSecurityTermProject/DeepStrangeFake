# Phase 1 corrective validation

> The earlier offline corpus score was invalid because it constructed evidence from manifest answers without executing the Coordinator. That result is withdrawn. The corrected benchmark now returns `deferred` unless `--live` is explicitly selected and runs both modes through the public audit pipeline on neutralized targets.

Validated on 2026-07-14 in `D:\DeepStrangeFake`.

## Automated suites

- Python: `.\.venv\Scripts\python.exe -m unittest discover -s tests`
  - Result: PASS
  - Evidence: 343 tests in 56.418 seconds; all passed; 7 opt-in integration tests skipped.
- Frontend: `npm test -- --run`
  - Result: PASS
  - Evidence: 4 files passed, 1 skipped; 18 tests passed, 1 skipped.
- Frontend typecheck: `npm run typecheck`
  - Result: PASS
- Frontend production build: `npm run build`
  - Result: PASS IN ISOLATED OUTPUT / SHARED `dist` LOCKED
  - Evidence: the default output completed typecheck and transformed 1769 modules, then was blocked by `EPERM` while creating `frontend/dist/assets`, which was occupied by another session. The same production build run as `npx vite build --configLoader runner --outDir dist-codex-final` completed in 3.44 seconds and emitted `index.html`, CSS, and a 294.06 kB JavaScript bundle. The isolated output was removed after verification; existing `dist` content and concurrent processes were not modified.

## Promotion gates

- OpenSpec: `openspec validate add-agent-led-investigation-runtime --strict`
  - Result: PASS
- Reviewed blind-spot corpus preflight: `.\.venv\Scripts\python.exe -m audit_agent.cli agent-led-benchmark`
  - Result: DEFERRED, exit 0.
  - Evidence: exact 24-case manifest accepted; no score or recall claim emitted; reason `live-execution-not-requested`.
  - Corrected execution contract: `--live` copies each source to neutral `case-xx/app.py`, invokes `run_audit` in deterministic and agent-led modes, rejects non-Agent-led effective mode, and scores only after both runs using hidden manifest truth.
- Fixed-commit real-model stability runner: `.\.venv\Scripts\python.exe -m audit_agent.cli agent-led-stability`
  - Result: PREFLIGHT/DEFERRED
  - Evidence: the three-repository by three-repetition runner and fixed commit manifest loaded successfully for provider `openai-compatible` and model `deepseek-v4-pro`.
  - Deferred reasons: `live-execution-not-requested`, `runtime-not-enabled`, `agent-decision-roles-not-enabled`, and `bounded-docker-sandbox-not-configured`. Docker Desktop 4.81.0 / Engine 29.6.1 is available, but the full external-provider 3 x 3 run was not executed. No stability result is claimed.

## Real-model main-path evidence

- Provider preflight: PASS with `openai-compatible` / `deepseek-v4-pro`; structured JSON was parsed and credentials were redacted from artifacts.
- Agent-led safe-negative smoke: `runs/acceptance-20260714-schema/2026-07-14T104935+0000-fixture-negative`
  - Result: PASS for the P0 routing criterion: `status=succeeded`, `requested_mode=agent-led`, `effective_mode=agent-led`, empty fallback reason, and no degraded reasons.
  - The provider rejected `json_schema` with HTTP 400 and returned the legacy `new_hypotheses` shape through JSON-object fallback. A separately accounted repair request converted it to `hypotheses`, `updates`, and `rationale` using canonical `sql-injection` and registered action IDs. Trusted evidence handling rejected the safe parameterized-query hypothesis.
  - Historical result: promotion accounting was INCOMPLETE because the provider reported no token usage for four failed JSON-Schema negotiation attempts. This run proves the real Agent-led protocol/routing fix, but is intentionally not counted as corpus or stability promotion evidence.
- Provider-format accounting smoke: `runs/acceptance-20260714-accounting-live-120s/2026-07-14T114951+0000-fixture-negative`
  - Result: PASS for the format/accounting corrective criterion: `status=succeeded`, requested/effective mode `agent-led`, empty fallback/degraded reasons, four request groups, four provider attempts, zero retries, 8,584 provider-reported tokens, zero gap IDs, and `llm_reconciliation_status=complete`.
  - Every provider dispatch used `json_object`; the first dispatch source was the known DeepSeek endpoint capability and later requests used the run cache. No JSON-Schema negotiation attempt or HTTP 400 occurred.
  - A preceding default-timeout run also used JSON Object exclusively but had one independently audited 30-second timeout before a successful retry. Its `usage-unknown` gap was preserved rather than rewritten as zero, demonstrating that the corrective change does not weaken fail-closed accounting. The passing smoke used a 120-second timeout and zero transport retries to isolate the structured-output result.
- Hard-token live smoke: `runs/acceptance-20260714-hard-token-16000-cap/2026-07-14T123737+0000-fixture-negative`
  - Result: PASS for the 16,000-token hard-ceiling criterion on the public safe-negative fixture. With both the configured per-request completion limit and run limit set to 16,000, six outgoing completion limits were reduced to 10,738, 8,668, 4,616, 3,645, 24, and 910 after conservative prompt estimates.
  - Provider-reported cumulative usage was 12,192 with 3,808 remaining. All six request groups reconciled to six provider attempts, zero retries, zero accounting gaps, and `llm_reconciliation_status=complete`. The run remained effectively Agent-led and terminated `degraded` for the independent `analysis-no-progress` convergence reason; no budget overage or mode fallback occurred.

## Corrective regression evidence

- Agent-led schema negotiation and repair: all Analysis/Verification requests carry `response_format=auto`; local validation now enforces enum, const, oneOf, closed-field, item-count, and length constraints used by the prompt contracts; invalid and repaired responses have separate lifecycle terminals.
- Schema repair grounding: repair requests now retain the original trusted request context and instruct the model to remove hypotheses that cannot be repaired without inventing repository paths, signal/hypothesis IDs, actions, or facts. This prevents a malformed adjacent-security hypothesis from being repaired into a nonexistent repository path.
- Reasoning-provider structured output: when a structured request returns empty `content` but places a fenced final JSON value in `reasoning_content`, the provider adapter extracts only that schema-bound JSON value. Hidden reasoning is neither promoted to response text nor retained in persisted `raw_response`; schema plus policy validation remain mandatory before any action.
- SQL counterevidence precision: parameterized-query detection now requires the second `execute` argument to occur inside the same call and source line. A regression fixture proves that `execute(query)` cannot consume a comma from a later function signature, while a real `execute(sql, params)` call is still rejected as counterevidence.
- Investigation convergence guidance: the Analysis contract explicitly requires exact local evidence plus an independent call-graph/dataflow/SAST/source/config/manifest corroborator before `submit_gate`, and forbids treating absence of a repository-local caller as proof that a function is unreachable.
- Live promotion command timeout: `agent-led-benchmark --live` and `agent-led-stability --live` default to a configurable 120-second per-attempt timeout so reasoning-model latency does not routinely create unknown-usage retry gaps.
- Provider-format capability and accounting: `llm.response_format` and `AUDIT_AGENT_LLM_RESPONSE_FORMAT` accept `auto`, `json_schema`, or `json_object`; known DeepSeek endpoints select JSON Object before dispatch; unknown endpoint HTTP-400 fallback is cached by a hashed provider/endpoint/model identity in run state and restored after checkpoint resume. A focused lifecycle test proves the known DeepSeek path reconciles one request to one attempt with complete usage.
- Hard token ceiling: focused lifecycle tests prove that the gateway conservatively estimates prompt tokens, clamps consecutive outgoing completion limits to the remaining allowance, records a zero-dispatch denial after exhaustion, and preserves actual usage plus a failed-closed terminal if a provider ignores the transmitted limit.
- Initial scanner-independent action and schema-invalid accounting: focused tests prove both direct structured success and one audited repair request.
- Public completed-run resume: same run directory reused; no new model lifecycle or Pattern scan artifact.
- Interrupted-run resume: a synthetic process exit after a committed source action leaves `status=running`, then the public resume entry restores the same checkpoint, preserves two prior model requests, continues to five total requests, does not repeat Pattern/source actions, and ends with complete lifecycle reconciliation.
- Active cancellation: blocking model returned promptly with `cancelled` lifecycle terminal; ProcessTreeRunner, default SAST adapter, and Local sandbox process trees were terminated.
- Trusted dynamic parameters: SQL `mode`, command `sink`, and path `transform` are required, evidence-matched before execution, persisted as full primitive calls, and consumed by the generator.
- Phase-one plan authority: zero or multiple primitives fail schema/contract validation; compiler metadata always contains the single trusted primitive. Live stability preflight still requires Docker, `network=none`, sandbox validation, and no live target/tool network.

## Code-level final acceptance refresh

- Focused corrective modules: `tests.test_agent_led_investigation`, `tests.test_agent_led_benchmark`, `tests.test_llm_prompt_runtime`, and `tests.test_llm_audit_accounting` passed 75 tests with 1 environment skip in 14.917 seconds.
- Full backend, frontend tests, frontend typecheck, isolated production build, OpenSpec strict validation, and `git diff --check` all passed on 2026-07-14.
- Offline blind-spot invocation returned `status=deferred`, `case_count=24`, reason `live-execution-not-requested`, exit 0, and no fabricated score.
- Offline stability invocation returned `status=deferred`, an empty record matrix, exit 0, and explicit live/runtime/decision-role/Docker preflight reasons.
- Partial live corpus evidence is retained but is not scored:
  - `runs/acceptance-phase1-final-blindspots` completed 4 cases and exposed the initial policy fallback/accounting defects.
  - `runs/acceptance-phase1-final-blindspots-v2` completed 8 cases; all 8 remained effectively Agent-led with complete accounting, then the run was stopped after the cross-line SQL counterevidence and empty-content reasoning-provider defects were identified.
  - `runs/acceptance-phase1-final-blindspots-v3` completed 7 cases before user-directed termination of external-model testing. All 7 completed runs remained effectively Agent-led with complete accounting and zero gaps; 6 evidence gates produced 2 SQL injection evidence packages (`case-02` and `case-04`). The eighth case was in progress and is excluded.
- Because no complete 24-case report and no complete fixed-repository 3 x 3 matrix exist, no recall, false-confirmation, latency, or stability PASS is claimed. Tasks 7.7, 7.8, and the promotion-dependent 7.9 remain unchecked; code-level acceptance is PASS, while release promotion remains DEFERRED.

## Notes

- The default public mode is `agent-led`; explicit `legacy`, `deterministic-graph`, and `adaptive-graph` compatibility paths remain covered by tests.
- Pattern output is advisory SecuritySignal input only. Promotion requires the deterministic EvidenceGate, and verification execution is assembled from registered trusted primitives whose bounded parameters must match normative source/dataflow evidence.
- The two pre-existing nested benchmark worktrees under `.benchmark-selection` were not modified by this change.
