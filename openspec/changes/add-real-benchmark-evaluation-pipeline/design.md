## Context

The repository already has `BenchmarkConfig`, a 20-entry `benchmarks/projects.json`, a sequential `BenchmarkRunner`, and a CLI command. The runner currently accepts any returned dictionary as a completed project and aggregates only candidates, rejected decisions, validated decisions, and validation-level distribution. The CLI returns an all-zero `remote-download-skipped` dictionary for every remote URL, so none of the configured remote projects are scanned even though the summary reports them as completed. The entries also use mutable branch names such as `main` and `master` rather than resolved commits.

Single audit runs already persist target metadata, final verification status counts, reports, runtime state, LLM responses, sandbox metadata, and Docker events. These are useful evidence, but they are not yet a stable resource-accounting contract: for example, runtime state currently says token usage is recorded per LLM artifact rather than publishing canonical totals. The benchmark layer needs a compact, secret-safe single-run resource summary instead of depending on internal directory traversal.

The evaluation has three operating environments: a deterministic local fixture corpus in CI, an initial 3-5 project controlled real-project pilot, and an at-least-20-unique-project corpus run under a later operational change. Real remote acquisition and model calls are authorized opt-in operations; ordinary tests and CI remain network-free.

## Goals / Non-Goals

**Goals:**

- Prove that every completed benchmark case was acquired at the expected commit and actually scanned.
- Make benchmark runs reproducible through exact commits, corpus/config/protocol fingerprints, cached acquisition, bounded budgets, and complete provenance.
- Support per-project timeout, process isolation, atomic state, interruption recovery, and safe resume without repeating valid completed work.
- Evaluate vulnerable revisions, fixed revisions, safe negatives, and human-adjudicated findings with deterministic, inspectable matching and versioned metric formulas.
- Produce stable JSON, derived Markdown, and baseline-comparison artifacts suitable for CI or manual regression review.
- Establish and promote a reviewed 3-5 project pilot before creating the follow-up full-corpus lock/run change.

**Non-Goals:**

- Do not silently clone or fetch repositories during normal scans, unit tests, or CI.
- Do not claim global precision or recall when ground truth, support coverage, or adjudication is incomplete.
- Do not treat external CVE/advisory text as proof that a local finding was detected.
- Do not add scanners or PoC generators merely to improve benchmark numbers.
- Do not execute target build/setup scripts, destructive payloads, deployed targets, submodules, or target writes.
- Do not make the Web UI the primary benchmark controller in this change; CLI and artifact contracts come first.
- Do not select, lock, or execute the final at-least-20-project corpus in this change. That is a follow-up operational change gated by pilot promotion.

## Decisions

### Decision 1: Separate project identity, case identity, and engine support

Use schema-versioned manifests with `fixture`, `pilot`, and `full` profiles. A `project_id` identifies one upstream project. A `case_id` identifies one exact revision and variant; vulnerable/fixed pairs therefore count as two cases but one unique project. The future full profile requires `unique_project_count >= 20` and records `case_count` separately.

Each case records source, complete commit SHA, expected language, variant, scan scope, vulnerability classes, budgets, timeout, safety policy, truth ref, and an engine support declaration: `full-dataflow`, `pattern-only`, or `unsupported`. It also records `effectiveness_eligible`. Unsupported cases and unreviewed pattern-only cases remain visible but cannot satisfy the effective-project quota or effectiveness denominators.

The pilot contains 3-5 small, legally usable, controllable unique projects with known vulnerable/fixed or negative evidence and scan shapes supported by the current engine. Mutable refs are accepted only by a separate lock-maintenance command that emits review provenance and exact SHAs; execution never treats a branch or tag as reproducible. The full profile remains a non-executable readiness template in this change. A future full lock becomes executable only when it carries reviewed `promotion_status = approved` metadata and exact eligible entries.

Alternative considered: count every revision as a project. That lets ten vulnerable/fixed pairs masquerade as twenty independent projects and overstates language/project diversity.

### Decision 2: Use verified mirrors and safe exact-commit source exports

Use a cache root with bare mirrors keyed by a digest of a credential-free normalized source identity. Prefer exporting the exact commit into a dedicated immutable case source directory using `git archive` or an equivalently non-executing mechanism. A detached worktree/checkout is allowed only when the case explicitly requires Git metadata and the same content-safety checks pass.

Only approved `https` or explicitly configured `ssh` sources are allowed. Reject credential-bearing URLs, `file://`, local-path remotes in remote profiles, unsupported protocols, source identity changes, cache escapes, and commit mismatch. Acquisition never initializes submodules, runs hooks, enables Git LFS smudge or repository-defined external filters, or executes project build/setup commands. Exported files are checked for path traversal and escaping symlinks; scanners must not follow links outside the case source root.

With explicit network permission, acquisition may clone a missing mirror or fetch a missing commit using fixed argv, a controlled Git environment, bounded output, and timeout. Without permission it is cache-only. Acquisition artifacts distinguish cache hit, clone, fetch, export/checkout, cache miss, policy denial, unsafe content, timeout, corruption, remote mismatch, and commit mismatch. Source URLs and diagnostics are redacted before persistence.

Alternative considered: ordinary shallow clone/worktree execution. It is less reproducible and leaves more room for filters, links, submodules, and mutable-history behavior.

### Decision 3: Persist an explicit case state machine atomically

Each benchmark run has an immutable resolved manifest and one state/result record per case. Case states are `pending`, `acquiring`, `ready`, `running`, and terminal `completed`, `failed`, `timed-out`, or `not-run`. Acquisition, execution, evaluation, and baseline eligibility are separate fields so a successful scan is not confused with complete truth/adjudication coverage.

The resolved manifest preserves the truth identity from the original run. A resume request with changed truth is recorded separately in `resume-request-*.json` rather than rejected as a different corpus or allowed to overwrite the original manifest. The changed truth still participates in strict case reuse, so the prior result is preserved as stale and the affected case is rerun.

State writes use a temporary file in the destination directory, flush and best-effort fsync, then atomic `os.replace`. Readers ignore incomplete temporary files and reject malformed or schema-incompatible records. State is persisted before and after every acquisition/execution boundary so interruption cannot manufacture completion.

Alternative considered: infer state from existing directories. Partial directories and stale reports cannot prove a terminal outcome.

### Decision 4: Use different identities for reuse and comparison

`reuse_fingerprint` is strict and includes corpus/case identity, exact commit, scope, effective audit config, budgets, safety policy, engine source commit, prompt/schema versions, provider/model settings, deterministic fixture/tool versions, and resource-summary schema. Resume reuses a completed case only when this fingerprint and all required artifacts match.

`comparison_protocol_fingerprint` describes what must remain stable for a defensible comparison: corpus version/digest, truth manifest version/content digest, project/case commits, scope, support eligibility, matching/metric versions, safety policy, execution protocol, and output schemas. It deliberately excludes dimensions that the experiment intends to compare.

Adjudication identity is evaluation metadata rather than scan input. Reports record the adjudication schema, canonical content digest, and record count, and include that identity in the final comparison protocol. Changing adjudication therefore recomputes evaluation and makes old/new reports protocol-incompatible without invalidating an otherwise reusable scan result.

Each comparison declares `comparison_dimensions`, such as `engine`, `prompt`, `model`, or selected audit configuration fields. Differences outside those declared dimensions are incompatibilities. Engine/prompt/model differences therefore prevent stale resume reuse but can be valid comparison axes.

Alternative considered: use one case fingerprint everywhere. That either reuses stale results or makes it impossible to compare the revisions the benchmark exists to measure.

### Decision 5: Run each project in a killable, secret-safe child process

Invoke a dedicated child-scan entrypoint with a persisted effective configuration reference and dedicated output directory. Secret values are never written to the effective configuration, benchmark manifest, child argv, fingerprints, or logs. The child receives only configured secret environment-variable names and inherits authorized values at runtime; captured stdout/stderr is bounded and redacted before persistence.

The coordinator uses a platform abstraction for process-tree ownership. POSIX uses a new session/process group and group termination. Windows starts the child suspended, assigns it to a Job Object configured with `KILL_ON_JOB_CLOSE`, then resumes it; timeout termination queries the job until `ActiveProcesses == 0`. Timeout handling proves that parent, child, and grandchild processes are gone before recording cleanup success. Docker resources carry benchmark/run/case labels and are inspected/cleaned only through those exact labels; cleanup failure is persisted and blocks baseline eligibility.

The MVP coordinator remains sequential (`max_parallel = 1`). Bounded parallel execution is deferred until mirror/checkpoint locking and resource contention have separate acceptance coverage.

Alternative considered: call `run_audit()` in-process. Python cannot reliably cancel a stuck scan and all descendants, and in-process secret/config state is harder to isolate.

### Decision 6: Make completed status evidence-based

A case is `completed` only when acquisition resolved the expected commit, a non-empty in-scope file set was analyzed, the child scan reached a successful terminal runtime state, and openable metadata, runtime-state, report, and resource-summary artifacts agree with project/case identity and commit. Counts come from validated artifacts, not caller-supplied defaults.

Remote skip, cache miss, missing commit, empty scope, timeout, child failure, missing artifacts, cleanup failure, or identity mismatch is `not-run`, `failed`, or `timed-out`. Finding/resource metrics are null with reasons and excluded from effectiveness denominators. A true safe negative may complete with all-zero findings only when nonzero scan coverage is proven.

Unless `--allow-partial` is explicit, any required non-completed case makes the benchmark incomplete and the CLI exits nonzero. Partial runs remain diagnostic and cannot be promoted.

### Decision 7: Model ground truth independently from findings

Truth records use stable truth IDs and include case/project ID, expected presence, vulnerability class/CWE, path, symbol or bounded line range, vulnerable/fixed commit links, evidence refs, source, and review provenance. Vulnerable/fixed revisions are separate cases linked by a pair ID.

The matcher normalizes class aliases and paths, then matches by case, class, path, and symbol/line overlap. It emits matched, missed, unexpected, ambiguous, duplicate, and out-of-scope records. Human adjudication is additive and records reviewer, decision, rationale, timestamp, evidence refs, and the original machine match; it never overwrites raw findings.

Truth and adjudication manifests have separate canonical content identities. Truth affects both case reuse and final comparison because it changes what the scan is evaluated against; adjudication affects metrics and final comparison but is intentionally excluded from scan reuse.

### Decision 8: Version exact metric formulas

Metrics carry `metric_version`. For effectiveness-eligible completed cases:

| Metric | Definition |
| --- | --- |
| Known-positive candidate recall | Distinct expected-present truth IDs matched by at least one candidate divided by all in-scope expected-present truth IDs. |
| Known-positive confirmed recall | Distinct expected-present truth IDs matched by at least one final `confirmed` finding divided by all in-scope expected-present truth IDs. |
| Adjudicated confirmed precision | Distinct deduplicated confirmed finding groups adjudicated true-positive divided by groups adjudicated true-positive or false-positive. |
| Negative-control false-positive rate | Completed eligible fixed/negative cases with at least one final `confirmed` finding divided by completed eligible fixed/negative cases. Unadjudicated confirmation is conservatively counted rather than treated as zero false positives. |
| Rejection accuracy | Distinct negative expectation locations that produced candidates ending `rejected` divided by distinct negative expectation locations that produced any terminal candidate. |
| Manual-required rate | Final `manual-required` candidates divided by all candidates with a final verification status. |

Duplicates count once per normalized finding group. Ambiguous, unresolved, and out-of-scope records remain visible but do not enter true-positive/false-positive numerators. Metrics with missing denominators are JSON null with machine-readable reasons. Reports include micro totals over truth/finding IDs and macro per-project values; neither is substituted for the other.

Real-model repetitions retain each run. Mean/range is computed only across runs sharing the comparison protocol and all effective settings except repetition ID; pooled findings are never used to fabricate one larger sample.

### Decision 9: Add a stable single-run resource summary

Each successful or terminal single scan emits `run-resource-summary.v1.json` containing scanned files/bytes, wall-clock `elapsed_seconds`, elapsed stages, LLM request/token totals, tool calls, Docker starts/results, repair attempts, timeouts, final status counts, effective budget consumption, accounting gaps, and contributing artifact refs. Numeric usage fields are not treated as credentials, while actual credential values remain redacted.

Benchmark normalization consumes this summary plus validated report/runtime metadata. It does not crawl arbitrary prompt/LLM/verification directories as its primary contract. Missing accounting remains null with a reason and may block pilot promotion when the pilot gate requires that field.

### Decision 10: Treat JSON and explicit comparison axes as the source of truth

Emit schema-versioned `benchmark.json` with environment, engine, corpus, protocol, configuration, case, truth-match, metric, resource, failure, and artifact sections. Markdown is rendered only from validated JSON.

Comparison validates `comparison_protocol_fingerprint`, declared dimensions, and per-field compatibility. It emits absolute/relative deltas and configured gates. Incompatible inputs fail with mismatch fields rather than being presented as regressions or improvements.

### Decision 11: Use tiered CI and split full-corpus rollout

Normal GitHub Actions CI runs a bounded local fixture profile whose benchmark invocation disables network acquisition and real credentials, uses deterministic mock responses and fake/gated sandbox execution, and has a documented timeout. It covers false completion, state, timeout, resume, matching, metrics, and rendering.

Real pilot execution is an explicit operator or `workflow_dispatch` path with environment approval, no fork-secret exposure, bounded timeout, artifact upload, and explicit cache/provider/Docker settings. A pilot baseline is promoted only after all 3-5 projects have reviewed commits, licenses, truth, scope, support eligibility, metrics, and resource accounting.

This change ends with pilot promotion and a full-profile readiness artifact/schema. A follow-up `run-locked-20-project-benchmark` change selects at least 20 unique projects, resolves locks, executes the full profile, adjudicates required findings, and publishes the first full baseline. Placeholder or unsupported entries cannot satisfy that follow-up acceptance.

## Risks / Trade-offs

- [Risk] Remote repositories move, disappear, or rewrite history. -> Persist exact commits, use mirrors, verify objects, and fail closed.
- [Risk] Repository content triggers Git filters, links, or submodule behavior. -> Use controlled Git config, prefer archive export, disable hooks/LFS/submodules/filters, and deny escaping links.
- [Risk] Credential-bearing URLs or child configuration leak secrets. -> Reject embedded credentials, persist environment-variable names only, redact bounded process output, and test standard artifacts for leaks.
- [Risk] Cache corruption or wrong remote identity contaminates results. -> Key by normalized source, verify origin/commit, retain acquisition evidence, and support cache audit/rebuild.
- [Risk] Windows/POSIX process cleanup leaves descendants or containers. -> Use platform-specific tree ownership, exact Docker labels, live cleanup smoke tests, and block promotion on cleanup gaps.
- [Risk] Ground truth or location matching drifts. -> Version truth and matcher rules, report ambiguity/coverage, and use fixed commits.
- [Risk] Unsupported languages inflate the project count. -> Record support level and effectiveness eligibility; require unique effective projects in the full follow-up.
- [Risk] LLM nondeterminism obscures regressions. -> Record settings, use explicit repetitions, and separate deterministic CI.
- [Risk] Large projects exceed disk, time, or token budgets. -> Keep MVP sequential, start with bounded pilot projects, and enforce per-case limits.
- [Risk] Precision is overstated from partial adjudication. -> Publish adjudication coverage and null unsupported metrics.

## Migration Plan

1. Add corpus/truth/state/result models, support/cardinality semantics, and separate reuse/comparison fingerprints while retaining the legacy list as migration input only.
2. Add strict manifest validation, conversion/lock tooling, safe cache/export acquisition, and offline doubles.
3. Add secret-safe child execution, platform process-tree cleanup, atomic state, and resume.
4. Add `run-resource-summary.v1`, benchmark normalization, truth matching, versioned metrics, JSON/Markdown, and comparison.
5. Gate normal CI on the local fixture profile and false-completion acceptance test.
6. Select, lock, run, review, and promote the 3-5 project pilot.
7. Create the follow-up `run-locked-20-project-benchmark` change with full-profile readiness evidence; do not claim full-corpus completion in this change.

Rollback disables the new benchmark profiles/command without changing single-project `scan`. New benchmark artifacts remain readable. Legacy benchmark output may be retained under a clearly named compatibility command, but it must not be presented as a real completed evaluation.

## Open Questions

- Which exact 3-5 legally usable repositories and vulnerable/fixed commits satisfy the pilot gates during the authorized corpus-selection pass?
- Which metric/resource thresholds should block pilot promotion beyond hard execution invariants and zero false confirmation on safe negatives?
