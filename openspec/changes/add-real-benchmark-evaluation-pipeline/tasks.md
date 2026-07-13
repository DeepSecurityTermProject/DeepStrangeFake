## 1. Baseline and False-Completion Acceptance

- [x] 1.1 Capture current local-success, partial-failure, remote-URL, aggregate-count, artifact, and exit-code behavior without preserving false completion as an accepted contract.
- [x] 1.2 Add an acceptance test asserting `remote-download-skipped` cannot be completed; confirm it fails against the old implementation before applying the fix and passes only after evidence-based completion exists.
- [x] 1.3 Add local fixtures for known positive, linked fixed revision, safe negative, empty scope, timeout, interrupted state, missing report, missing resource summary, and inconsistent identity.
- [x] 1.4 Add offline Git/cache doubles that record clone, fetch, archive/export, checkout, commit, timeout, content-safety, and network-policy decisions without a real remote.
- [x] 1.5 Add process and Docker cleanup doubles that record parent/child/grandchild termination and exact benchmark/run/case label selection.
- [x] 1.6 Define hard assertions: no unscanned case completes, unavailable values are null with reasons, a scanned negative may complete with zero findings, secrets never enter artifacts/argv, and cleanup gaps block promotion.

## 2. Corpus, Identity, State, and Resource Models

- [x] 2.1 Add strict schema-versioned models for corpus/profile/project/case, exact commit, variant/pair, scope, budgets, timeout, safety, truth refs, support level, and effectiveness eligibility.
- [x] 2.2 Model `unique_project_count` separately from `case_count`; validate that vulnerable/fixed revisions share a project ID and unsupported/placeholders cannot satisfy effective-project quotas.
- [x] 2.3 Add acquisition, state, result, evaluation-status, resource, failure, match, adjudication, metric, summary, comparison, readiness, and promotion records with stable IDs.
- [x] 2.4 Define separate canonical `reuse_fingerprint`, `comparison_protocol_fingerprint`, and declared `comparison_dimensions`; document which fields belong to each.
- [x] 2.5 Make unavailable count/resource fields nullable and require machine-readable reasons; keep execution, evaluation, and baseline eligibility as separate fields.
- [x] 2.6 Add the `run-resource-summary.v1` model with target/run identity, coverage, timing, LLM/tool/Docker/repair/timeout/budget totals, gaps, and contributing refs.
- [x] 2.7 Add strict serialization/schema tests for unknown fields, exact commits, project/case cardinality, support eligibility, enums, bounds, path containment, fingerprints, null reasons, and stable digests.

## 3. Corpus Profiles, Locking, and Full Readiness

- [x] 3.1 Replace/supplement `benchmarks/projects.json` with schema-versioned fixture, pilot, full-readiness, truth, and adjudication manifests.
- [x] 3.2 Implement strict loading and deterministic profile/default/case configuration merging with actionable validation errors.
- [x] 3.3 Reject mutable refs from executable profiles and add an explicit lock/resolve workflow that emits full SHAs, source/license review provenance, resolver identity, timestamp, and lock digest.
- [x] 3.4 Record language/support level, version/commit, scope, vulnerability classes, timeout, tool/LLM/Docker/repair budgets, and safety/network policy for each executable case.
- [x] 3.5 Add a conversion path from the legacy 20-entry list that marks unresolved entries non-executable and never presents conversion as completed evaluation.
- [x] 3.6 Create a network-free local fixture profile for normal CI.
- [x] 3.7 Define pilot gates and non-executable 3-5 case placeholders that require authorized selection of unique projects, commits, scopes, licenses, supported shapes, and truth before execution.
- [x] 3.8 Implement full-profile readiness validation requiring at least 20 unique effectiveness-eligible project IDs, separate case count, exact entries, and reviewed `promotion_status = approved`; do not populate or execute the final full lock in this change.

## 4. Safe Cache-Backed Repository Acquisition

- [x] 4.1 Implement credential-free normalized source identities and contained cache paths for bare mirrors and case exports.
- [x] 4.2 Reject embedded credentials, `file://`, local remotes in remote profiles, unapproved protocols/hosts, malformed identities, and cache traversal before Git starts.
- [x] 4.3 Implement cache-only exact-commit acquisition that verifies mirror identity/object availability and prefers `git archive` or equivalent non-executing export.
- [x] 4.4 If worktrees/checkouts are needed, enforce clean exact commit, containment, controlled Git config, disabled hooks/submodules/LFS/external filters, and no project build/setup execution.
- [x] 4.5 Detect path-traversing archive entries and links escaping the case source root; ensure repository enumeration never follows external links.
- [x] 4.6 Add explicit `--allow-network` fixed-argv clone/fetch with source allowlist, controlled environment, timeout, bounded redacted output, and no implicit fallback.
- [x] 4.7 Persist acquisition artifacts for cache hit, clone, fetch, export/checkout, cache miss, policy denial, unsafe content, timeout, corruption, remote mismatch, and commit mismatch.
- [x] 4.8 Ensure acquisition failure creates no finding/resource counts and never invokes the scan child.
- [x] 4.9 Add tests for safe archive reuse, missing offline commit, authorized fetch double, wrong origin, credential URL, unsafe protocol, corrupt cache, traversal/symlink denial, disabled submodule/filter/LFS behavior, and commit mismatch.

## 5. Atomic State and Resume

- [x] 5.1 Add benchmark run directories with immutable resolved manifest, reuse/protocol/config/engine fingerprints, coordinator metadata, and per-case state/result files.
- [x] 5.2 Implement validated state transitions across `pending`, `acquiring`, `ready`, `running`, `completed`, `failed`, `timed-out`, and `not-run`.
- [x] 5.3 Implement same-directory temporary writes, flush/best-effort fsync, atomic `os.replace`, malformed-state rejection, and temporary-file recovery rules.
- [x] 5.4 Persist state before/after acquisition and execution boundaries so interruption cannot manufacture completion.
- [x] 5.5 Implement `--resume <benchmark-run-id>` and reuse only completed cases whose strict reuse fingerprint and required artifacts match.
- [x] 5.6 Preserve but invalidate stale results when engine, prompt/schema, provider/model, commit, corpus, scope, config, budget, safety, tools, truth, resource schema, or artifacts differ.
- [x] 5.7 Restart interrupted nonterminal cases from the last safe boundary and record attempts/reuse decisions.
- [x] 5.8 Add tests for compatible reuse, engine/prompt forced rerun, stale artifact invalidation, interrupted restart, corrupt/partial state, and no directory-based completion inference.

## 6. Secret-Safe Child Execution, Timeout, and Completion Proof

- [x] 6.1 Add a child-scan entrypoint accepting only a persisted non-secret effective case configuration reference and dedicated output directory.
- [x] 6.2 Ensure persisted config, manifest, fingerprints, child argv, stdout, and stderr never contain API-key values, secret hashes, or credential-bearing URLs; pass only configured environment-variable names and redact bounded output.
- [x] 6.3 Add a process-tree abstraction: POSIX session/group termination and Windows Job Object or tested fixed-argv tree-termination fallback, without `shell=True`.
- [x] 6.4 Keep MVP execution sequential (`max_parallel=1`) and document bounded parallel scheduling as deferred work.
- [x] 6.5 Enforce project timeout and prove parent, child, and grandchild termination before recording cleanup success.
- [x] 6.6 Label Docker resources with exact benchmark/run/case IDs, clean only matching resources, persist cleanup evidence, and block promotion on cleanup failure.
- [x] 6.7 Validate metadata, runtime state, report JSON, `run-resource-summary.v1`, target identity/commit, and non-empty scope before assigning completed.
- [x] 6.8 Derive status/finding/resource counts only from validated artifacts, never child stdout or caller defaults.
- [x] 6.9 Classify missing checkout, remote skip, empty scope, timeout, nonzero exit, missing artifact, identity mismatch, and cleanup failure as explicit non-completed outcomes.
- [x] 6.10 Make incomplete required cases exit nonzero unless `--allow-partial`; partial runs remain ineligible for promotion.
- [x] 6.11 Add acceptance/live-safe tests proving process-tree cleanup, exact Docker label cleanup, unscanned zero rejection, scanned-negative zero acceptance, and secret-free persisted artifacts.

## 7. Stable Single-Run Resource and Provenance Contract

- [x] 7.1 Extend single-run runtime/report finalization to emit schema-versioned `run-resource-summary.v1` for every terminal run.
- [x] 7.2 Aggregate scanned files/bytes, stage durations, final statuses, LLM requests/tokens, tool calls, Docker starts/results, repair attempts, timeouts, and budget consumption with contributing refs.
- [x] 7.3 Preserve numeric token usage as non-secret accounting while redacting actual configured credentials and credential-shaped text.
- [x] 7.4 Record provider/model, prompt/schema, engine commit, language/version, scope, safety, Docker policy, environment, and accounting-gap provenance without secret values.
- [x] 7.5 Normalize benchmark case resources from `run-resource-summary.v1` plus validated identity/report/runtime artifacts instead of crawling internal artifact directories as the primary contract.
- [x] 7.6 Emit null plus accounting-gap reason when resource evidence is unavailable or inconsistent and apply pilot-promotion gates to required fields.
- [x] 7.7 Add tests for deterministic local runs, real-provider-shaped usage, Docker/repair attempts, missing accounting, inconsistent refs, numeric token preservation, and secret redaction.

## 8. Ground Truth, Matching, and Adjudication

- [x] 8.1 Implement strict truth loading for positive, fixed, and safe-negative records with stable truth/project/case/pair IDs, class/CWE, path, symbol/range, commits, evidence, and provenance.
- [x] 8.2 Implement class-alias/path normalization and versioned matching by case, class, path, and symbol/line overlap.
- [x] 8.3 Persist matched, missed, unexpected, ambiguous, duplicate, and out-of-scope records without modifying raw findings.
- [x] 8.4 Define a stable deduplication group key so duplicate findings remain visible but count once in finding-level metrics.
- [x] 8.5 Add additive adjudication with reviewer, decision, rationale, timestamp, evidence refs, and original match refs.
- [x] 8.6 Evaluate vulnerable/fixed pairs independently and report expected presence versus disappearance/rejection.
- [x] 8.7 Add tests for exact match, bounded line drift, class aliases/mismatch, multiple matches, missing truth, duplicate grouping, reviewed false positive, out-of-scope, and unresolved findings.

## 9. Versioned Metrics, Reports, and Comparison

- [x] 9.1 Encode versioned formulas for candidate recall, confirmed recall, adjudicated confirmed precision, case-level negative false-positive rate, negative-location rejection accuracy, manual-required rate, truth/adjudication coverage, and micro/macro reporting.
- [x] 9.2 Keep manual-required as abstention, exclude unsupported/ineligible cases and unresolved/ambiguous/out-of-scope findings from unsupported numerators, and expose all raw counts.
- [x] 9.3 Emit null values and explicit reasons for metrics blocked by execution, support, truth, matching, denominator, or adjudication gaps.
- [x] 9.4 Generate schema-versioned `benchmark.json` with every case, statuses, fingerprints, dimensions, normalized results, matches, metrics, resources, failures, and refs.
- [x] 9.5 Generate Markdown solely from validated JSON with completion, effectiveness, support, coverage, resource, and failure tables.
- [x] 9.6 Implement comparison using matching `comparison_protocol_fingerprint` and explicit dimensions; do not require engine/prompt/model equality when that field is the declared experiment axis.
- [x] 9.7 Reject undeclared differences and emit per-case/aggregate absolute/relative deltas for statuses, metrics, coverage, duration, tokens, Docker, and failures.
- [x] 9.8 Add gates for false completion, missing cases, false-confirmed safe negatives, cleanup/accounting gaps, recall/precision/abstention/resource regressions, and incompatible inputs.
- [x] 9.9 Implement explicit pilot baseline promotion rejecting partial, incompatible, unsupported-quota, unreviewed, cleanup-failed, or required-accounting-incomplete runs.
- [x] 9.10 Retain real-model repetitions separately and compute mean/range only across protocol-compatible runs with equal settings except repetition ID.
- [x] 9.11 Add golden JSON/Markdown/comparison tests for formulas, deduplication, undefined metrics, declared engine comparison, undeclared mismatch, resource regression, and stable output.

## 10. CLI, CI, Pilot, and Follow-Up Handoff

- [x] 10.1 Extend benchmark CLI with profile/case selection, cache root, offline/network policy, timeout, resume, allow-partial, repetition, output, compare, promote, lock, and readiness controls.
- [x] 10.2 Add a bounded GitHub Actions fixture benchmark job whose benchmark invocation disables clone/fetch, real credentials, and implicit Docker, with a documented timeout.
- [x] 10.3 Add an opt-in pilot operator or `workflow_dispatch` path with environment approval, no fork-secret exposure, bounded timeout, artifact upload, and explicit cache/network/provider/Docker/safety inputs.
- [x] 10.4 Run the fixture corpus and prove acquisition/state/atomic-write/timeout/resume/truth/metrics/report/comparison/secret-redaction behavior plus the remote-skip false-completion gate.
- [ ] 10.5 During an authorized corpus-selection pass, choose and document 3-5 unique controllable projects, exact vulnerable/fixed commits, negative controls, scopes, licenses, support eligibility, and truth evidence.
- [ ] 10.6 Run the 3-5 project pilot; resolve acquisition, scope, accounting, matching, cleanup, timeout, and safety failures before promotion.
- [ ] 10.7 For explicitly configured real-model pilot repetitions, retain each run and publish protocol-compatible mean/range without pooling findings.
- [ ] 10.8 Promote a complete reviewed pilot baseline and emit full-profile readiness evidence/schema without claiming a 20-project run.
- [x] 10.9 Create the follow-up OpenSpec change `run-locked-20-project-benchmark` with acceptance requiring at least 20 unique effectiveness-eligible projects, exact locks, execution, adjudication, and first full baseline.
- [x] 10.10 Update operator documentation for safe cache preparation, lock review, offline/network modes, resume, timeout, Windows/POSIX cleanup, truth/adjudication, metrics, comparison dimensions, CI/pilot tiers, and troubleshooting.
- [x] 10.11 Run the full Python suite, affected frontend suite/typecheck, fixture benchmark, JSON/Markdown validation, and `openspec validate add-real-benchmark-evaluation-pipeline --strict`.

## 11. P1 Review Corrections

- [x] 11.1 Persist and enforce case validation level, scope bounds, tool/LLM/Docker/repair budgets, and Docker runner selection in the child audit configuration, with post-run budget verification.
- [x] 11.2 Replace the constant working-tree identity with HEAD, dirty state, engine source digest, and prompt content digest so code or template changes invalidate resume reuse.
- [x] 11.3 Load the integration environment inside benchmark children, honor the `LLM_API_KEY` alias, and pass only case-allowlisted credential environment values.
- [x] 11.4 Key finding status by `(case_id, finding_id)` during metric computation so identical IDs in different revisions cannot overwrite one another.
- [x] 11.5 Require and forward the pilot model input, load `.env` before benchmark identity construction, and reject empty or placeholder models for real providers.

## 12. P2 Review Corrections

- [x] 12.1 Include truth manifest version and canonical content digest in reuse and comparison protocol identities.
- [x] 12.2 Restrict adjudicated confirmed precision to final confirmed groups and conservatively count unadjudicated negative-control confirmations in FPR.
- [x] 12.3 Add actual wall-clock `elapsed_seconds` to `run-resource-summary.v1` and duration comparisons.
- [x] 12.4 Replace Windows `taskkill`-only cleanup with Job Object ownership and live verification that parent, child, and grandchild PIDs are gone.
- [x] 12.5 Allow same-run truth changes to persist a resume request, preserve the original resolved identity and stale result, and safely rerun instead of failing immutable-manifest validation.
- [x] 12.6 Record adjudication schema/content/count identity in reports and the final comparison protocol without invalidating scan reuse.
