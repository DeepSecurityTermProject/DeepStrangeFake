# Agent-led investigation runtime

The default `agent-led` mode treats deterministic scanners as evidence-producing tools, not as the authority that creates findings. Analysis proposes bounded hypotheses and selects registered read-only actions. Trusted code validates exact repository evidence, requires independent corroboration, compiles a registered verification primitive, and lets the existing Judge determine the result.

## Authority boundary

- Analysis may use only `search`, `source_context`, `callers`, `callees`, `dataflow`, `sast`, `lexical_memory`, `submit_gate`, and `abandon`.
- Analysis output is a hypothesis or next action. It cannot directly create or confirm a finding.
- Analysis and Verification requests use `response_format=auto`, a closed local schema with canonical vulnerability/action IDs, and at most the configured audited schema-repair requests. Provider capability selection sends JSON Object directly to known DeepSeek-compatible endpoints; unknown endpoint fallback is cached for the run and checkpoint resume. A malformed response is terminalized separately and is never treated as an accepted decision.
- The EvidenceGate requires an exact in-scope path, line, excerpt, and content hash plus an independent trusted origin. Pattern output, model assertions, memories, CVE text, tool errors, and same-source duplication do not satisfy the second-evidence rule.
- Verification may select exactly one registered primitive per phase-one plan. It cannot supply code, shell commands, raw argv, external URLs, Docker options, paths outside repository scope, or verdicts; ordered multi-primitive execution is deferred.
- Trusted compilers assemble harmless templates. Dynamic validation remains controlled by the configured sandbox and Judge. Hardcoded secrets use static-semantic validation without live network access.

## Runtime and degraded behavior

`agent-led` is the default for the CLI, public runtime, API, and Web UI. The older `deterministic-graph`, `adaptive-graph`, and `legacy` modes remain explicit rollback options. A missing/unusable real model does not silently use a mock model: the run records requested/effective modes, falls back to the deterministic graph, and ends as `degraded`. Mock use must be explicitly enabled through the investigation development/test setting.

Default hard limits are 32 hypotheses, 6 rounds per hypothesis, 8 tool calls per hypothesis, 50 promoted candidates, 40 model requests, 200,000 tokens, USD 5 of known provider cost, and 15 minutes. Checkpoints atomically persist completed action keys, artifact refs, accounting counters, remaining budgets, and a matching resumable runtime-state snapshot. Resume is available through `scan --resume-run-id <run-directory-name>` and the Web request field `resume_run_id`; completed actions, provider request counters, and completed runs are reused without another model/tool dispatch.

## Blind-spot promotion gate

The reviewed corpus contains 24 paired Python cases: three vulnerable and three safe controls for each of SQL injection, command injection, path traversal, and hardcoded secrets. The families cover wrapper flows, indirect calls, and configuration-driven behavior.

```powershell
.\.venv\Scripts\python.exe -m audit_agent.cli agent-led-benchmark --output agent-led-blindspot-report.json
```

Without `--live`, the command performs manifest preflight and returns `deferred`; it does not claim a recall score. A scored run requires a configured real provider:

```powershell
.\.venv\Scripts\python.exe -m audit_agent.cli --config config\real-model.json agent-led-benchmark --live --runs-output runs\agent-led-blindspots --output agent-led-blindspot-report.json
```

For every case, trusted code copies only the fixture source to a neutral `case-xx/app.py` directory. The evaluator does not pass expected status, fixture filename, vulnerability line, symbol, or family label to the runtime. It invokes the public audit pipeline once in deterministic mode and once through `AgentLedInvestigationCoordinator`, then uses manifest truth only for scoring. The gate fails unless the corpus shape is exact, candidate recall improves by at least 0.30, safe false confirmation is zero, a scanner-no-signal case is promoted with complete evidence/package/plan/Judge artifacts, model accounting reconciles, latency is bounded, and hard budgets are respected.

## Real-model stability gate

`benchmarks/agent_led_real_model_repos.v1.json` locks three small public repositories to complete commits. Each live gate performs three repetitions per repository and compares normalized confirmed high/critical findings. It also verifies the target tree and commit did not change, target/tool network and target execution remained blocked, validation used a network-none bounded Docker sandbox, every run produced at least one typed verification plan, and LLM accounting reconciles completely.

Preflight without spending model quota:

```powershell
.\.venv\Scripts\python.exe -m audit_agent.cli agent-led-stability
```

Live execution (requires the configured provider credential):

```powershell
.\.venv\Scripts\python.exe -m audit_agent.cli --config config\real-model.json agent-led-stability --live --output runs\agent-led-stability
```

Provider API traffic is the only permitted network class for this gate. Generated trusted harnesses may execute only inside the bounded Docker sandbox; the target repository is read-only and never mounted for writes or granted network access. Model output never gains code or process authority. If credentials are absent, preflight records a deferred reason instead of substituting the mock provider.

Promotion accounting remains fail closed. Known or explicitly configured JSON-object-only providers bypass unsupported JSON-Schema negotiation, preventing that accounting gap. If an unknown provider's one-time capability probe is rejected without usage, the audit may continue and later requests will use the cached format, but promotion remains incomplete until every actual provider attempt has authoritative accounting; the rejected attempt is never rewritten as zero.

## Cancellation and artifacts

The Web run page can request cancellation. Cancellation closes the active provider connection, terminates registered SAST and sandbox process trees, force-removes an active Docker container, interrupts bounded Git acquisition, performs contained remote-export cleanup, and then writes a final checkpoint, resource summary, and terminal `cancelled` state. It does not wait for the ordinary provider/tool/sandbox timeout.

Investigation artifacts live under the run directory in `signals`, `investigations`, `evidence-gates`, and `verification-plans`. Reports expose counts, references, budgets, checkpoints, requested/effective modes, fallback reason, and degraded reasons; prompts and reports do not persist hidden reasoning or raw secrets.
