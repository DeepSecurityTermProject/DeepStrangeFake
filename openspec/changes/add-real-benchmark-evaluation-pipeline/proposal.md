## Why

The current benchmark command can mark an unscanned remote repository as completed with all-zero metrics via `remote-download-skipped`, so it cannot establish whether later agent, prompt, scanner, or verification changes actually improve effectiveness. A reproducible evaluation pipeline is needed now to lock target versions, prove that scans really ran, compare results against ground truth, and separate deterministic CI coverage from controlled real-project evaluation.

## What Changes

- Replace the current list-only benchmark behavior with schema-versioned corpus manifests that record stable project and case identity, exact commit, language/support level, vulnerable/fixed/negative variant, scan scope, budgets, timeout, safety policy, and ground-truth reference.
- Define project and case cardinality separately: the future full corpus requires at least 20 unique project identities, while vulnerable/fixed revisions remain separate cases.
- Add explicit, cached remote acquisition using verified Git mirrors and safe exact-commit exports/checkouts, with offline cache-only mode and opt-in network access.
- Harden acquisition against credential-bearing or unsafe protocols, hooks, submodules, LFS/filter execution, escaping links, and implicit build/setup execution.
- Add resumable benchmark runs with per-project state, atomic result persistence, project-level process isolation, timeout termination, and deterministic retry/resume rules.
- Separate strict resume/reuse identity from benchmark comparability: `reuse_fingerprint` prevents stale reuse, while `comparison_protocol_fingerprint` and declared `comparison_dimensions` allow intentional engine, prompt, or model changes to be measured.
- Start with a controlled 3-5 project pilot corpus. This change implements full-profile schema/readiness but leaves selection, locking, and execution of the at-least-20-project corpus to a follow-up operational change after pilot promotion.
- Add ground truth for known vulnerable samples, fixed versions, safe negative controls, and human adjudication, including stable finding-to-truth matching and review provenance.
- Record per-project candidates, confirmed, likely, rejected, manual-required, misses, acquisition/execution failures, elapsed time, scanned file count, LLM token usage, Docker invocation count, budgets, and policy/configuration fingerprints.
- Add a secret-safe, schema-versioned single-run resource summary so benchmark accounting does not scrape unstable internal artifact layouts.
- Generate schema-versioned benchmark JSON as the source of truth, derived Markdown summaries, and machine-comparable baseline-versus-candidate deltas using explicit metric formulas.
- Add a small local fixture corpus to normal CI; keep real-project pilot execution opt-in and network/provider guarded.
- **BREAKING**: remote acquisition skips, missing commits, empty scan scope, missing run/report artifacts, and timeouts are no longer counted as completed projects. Their metrics are null/not-applicable rather than fabricated zeroes, and an incomplete benchmark returns failure unless partial execution is explicitly allowed.

## Capabilities

### New Capabilities

- `benchmark-corpus-acquisition`: Versioned corpus manifests, unique-project/case semantics, support eligibility, exact commit locking, cache-backed acquisition, offline/network policy, checkout/export verification, and fixture/pilot/full profiles.
- `benchmark-execution-runtime`: Isolated per-project execution, Windows/POSIX process-tree timeout cleanup, atomic state, resumable execution, fingerprint-based result reuse, explicit terminal statuses, and proof that a real scan occurred.
- `benchmark-ground-truth-evaluation`: Vulnerable/fixed/negative truth records, human adjudication, deterministic finding matching, versioned metric formulas, and defensible effectiveness metrics.
- `benchmark-reporting-and-ci`: Comparable JSON/Markdown outputs, resource/cost accounting, baseline comparison dimensions, fixture CI gates, pilot promotion, and full-corpus readiness artifacts.

### Modified Capabilities

- `decision-auditability-and-replay`: Add a stable `run-resource-summary.v1` artifact with non-secret LLM/tool/Docker/repair/coverage accounting and contributing refs for benchmark normalization.

## Impact

- Core code: `audit_agent/benchmark.py`, benchmark models, CLI benchmark arguments/exit codes, repository acquisition helpers, subprocess/process-tree execution, report/resource aggregation, and run-state persistence.
- Single-run evidence: emit `run-resource-summary.v1` without persisting API-key values, secret hashes, or secret-bearing child argv.
- Configuration/data: replace or supplement `benchmarks/projects.json` with schema-versioned fixture, pilot, full-readiness, ground-truth, and adjudication manifests pinned to exact commits where executable.
- Artifacts: new benchmark run directory containing corpus/config fingerprints, per-project state/results, normalized findings, adjudication/matching records, aggregate JSON, Markdown, and comparison output.
- Tests/CI: offline cache/acquisition doubles, unsafe-source/link/filter denial, Windows/POSIX cleanup doubles, resume and timeout tests, vulnerable/fixed/negative fixtures, all-zero false-completion regression coverage, and a lightweight deterministic CI corpus.
- Operations: remote clone/fetch and real-model execution remain explicit, authorized actions; normal CI benchmark acquisition remains local and receives no network permission. The at-least-20-project real run is a separate follow-up change after this change produces a reviewed pilot baseline.
