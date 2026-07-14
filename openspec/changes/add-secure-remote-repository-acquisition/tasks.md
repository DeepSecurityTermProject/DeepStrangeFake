## 1. Lock Current Gaps and Acceptance Invariants

- [x] 1.1 Add a characterization test proving a normal remote URL currently produces no `root_path`, commit, or files and does not invoke the existing shallow checkout helper.
- [x] 1.2 Add failing end-to-end Web/runtime tests requiring an acquired remote fixture to produce a non-empty file tree, scanner observations/findings, original URL provenance, and one exact resolved commit.
- [x] 1.3 Add a regression test proving acquisition failure or an empty remote scope cannot create a succeeded job or a successful zero-finding report.
- [x] 1.4 Add reusable fake Git/acquisition fixtures, bounded archive builders, credential sentinels, workspace containment assertions, and no-network call counters.
- [x] 1.5 Characterize legacy local-path behavior in Web, CLI, legacy runtime, and graph runtime so the new source contract cannot regress existing scans.

## 2. Add Source, Acquisition, and Policy Models

- [x] 2.1 Add strict discriminated local/GitHub/GitLab source request models, backward-compatible legacy `target` normalization, and validation rejecting ambiguous or incompatible fields.
- [x] 2.2 Add schema-versioned generic acquisition request/result, prepared-target, safety-check, command-outcome, cleanup, cache, and failure models independent of benchmark case types.
- [x] 2.3 Extend repository metadata additively with source provenance and verified-materialization evidence while preserving original URL, remote kind, local export root, requested revision, and resolved commit.
- [x] 2.4 Add `RemoteAcquisitionConfig` with operator enablement, fixed GitHub/GitLab HTTPS host policy, cache/work roots, command/total/lock timeouts, mirror/archive/file/byte budgets, cleanup retries, and environment/config loading.
- [x] 2.5 Add deterministic model/config serialization and backward-compatible readers for jobs, run metadata, and configs created before remote acquisition fields existed.

## 3. Implement the Hardened Git Acquisition Core

- [x] 3.1 Implement canonical public GitHub and GitLab HTTPS normalization and reject SSH, arbitrary hosts, file/local remotes, credentials, query/fragment, redirects, malformed paths, and unsafe revisions before any Git call.
- [x] 3.2 Implement bounded remote `HEAD` resolution and optional complete commit validation, recording requested and resolved identities without supporting mutable branch/tag names.
- [x] 3.3 Implement a `shell=False` Git command runner with minimal environment, non-interactive credentials, disabled system/global config, HTTPS-only protocol, disabled redirects/LFS smudge, redacted bounded output, and timeout classification.
- [x] 3.4 Implement normalized-identity mirror keys, contained cache paths, per-identity locking, atomic mirror creation, existing-origin verification, object integrity checks, and exact-commit fetch only when operator network policy allows it.
- [x] 3.5 Implement exact-commit `git archive` export into unique atomic per-job workspaces without checkout, hooks, submodules, external filters, dependency installation, or project execution.
- [x] 3.6 Validate archive containment, member types, link prohibition, member count, uncompressed bytes, destination collisions, mirror post-operation size, and exported tree containment before returning a ready result.
- [x] 3.7 Persist redacted acquisition evidence with source/revision/commit, cache/network/method, safe command outcomes, timings, budgets, exported files/bytes, safety checks, refs, and stable failure reasons.
- [x] 3.8 Implement bounded cleanup in `finally` for partial and completed per-job exports, retain mirrors by policy, and report a verifiable cleanup failure instead of claiming unqualified success.
- [x] 3.9 Add unit tests covering accepted/denied URLs, HEAD/exact commit, cache hit/miss, wrong origin, corrupt/missing object, clone/fetch failures, timeout, lock contention, interrupted atomic writes, archive attacks, every budget, cleanup failure, and sentinel redaction.
- [x] 3.10 Add offline GitHub and nested-namespace GitLab system-Git fixture tests that exercise mirror, object verification, archive, and export primitives against temporary local bare repositories without weakening the fixed production host policy.

## 4. Preserve Benchmark Acquisition Behavior

- [x] 4.1 Refactor `benchmark_acquisition.py` into a compatibility adapter over the generic acquisition core without routing Web requests through synthetic `BenchmarkCase` objects.
- [x] 4.2 Preserve benchmark fixture copy, remote identity, exact lock, cache-only/network, command recording, failure taxonomy, safety checks, and acquisition record fields byte-for-byte where protocol identity requires it.
- [x] 4.3 Run and extend benchmark tests for verified cache hits, wrong origins, missing commits, explicit network fetch, no-network cache miss, archive safety, timeout, cleanup, resume identity, and promotion gates.
- [x] 4.4 Prove the refactor does not alter existing corpus/truth/adjudication fingerprints or permit `remote-download-skipped`, acquisition failure, or missing evidence to become baseline eligible.

## 5. Prepare the Target Once for AgentRuntime

- [x] 5.1 Add a prepared-target context at the stable pipeline boundary that handles local analysis directly and remote acquisition/materialization before invoking AgentRuntime.
- [x] 5.2 Refactor legacy and graph runtime initialization to consume the same prepared repository metadata rather than independently calling `analyze_target()`.
- [x] 5.3 Ensure DataflowScanner, PatternScanner, repository search, source context, memory indexing, target-integrity checks, and report generation all resolve files beneath the verified export root.
- [x] 5.4 Persist `metadata/acquisition.json` and additive runtime/resource-summary fields linking original source, requested revision, resolved commit, acquisition status/ref, export proof, and cleanup outcome.
- [x] 5.5 Add hard gates requiring ready acquisition, matching commits, present export, non-empty effective scope, expected run artifacts, and known cleanup outcome before a remote job can succeed.
- [x] 5.6 Ensure provider, MCP, graph, replay, and report readers cannot trigger acquisition side effects and that failed-run resource summaries report acquisition/empty-scope reasons without fabricated zeros.
- [x] 5.7 Add legacy/graph integration tests proving the exported fixture is actually scanned, source locations map to exported content, original provenance survives, and local-path results remain unchanged.

## 6. Enforce Remote Snapshot Verification Safety

- [x] 6.1 Replace `target.kind == local` as the sole execution gate with explicit verified-materialization, runner, network, mount, write, and setup/build policy checks.
- [x] 6.2 Permit static analysis and explicitly enabled network-disabled Docker verification with read-only remote-snapshot target access while denying the local process runner and live/network target behavior.
- [x] 6.3 Preserve typed-edit-only LLM PoC repair, attempt-directory writes, target-integrity manifests, Docker labels/budgets, and the prohibition on modifying or installing dependencies into the acquired source.
- [x] 6.4 Add policy and end-to-end tests for allowed Docker verification, denied local execution, denied network/write/setup escalation, target integrity, repair cleanup, and manual-required fallback.

## 7. Extend the Web API and Job Lifecycle

- [x] 7.1 Extend `ScanRunRequest` and API response schemas with structured source intent while retaining legacy local `target` clients and rejecting client-side attempts to enable server network access.
- [x] 7.2 Expose non-secret remote-acquisition capability state and limits from `/api/options` and return deterministic validation errors for malformed or policy-disabled GitHub sources.
- [x] 7.3 Extend persisted jobs with backward-compatible source, phase, requested/resolved revision, acquisition summary/ref, cleanup result, and run directory on terminal failures that produced inspectable artifacts.
- [x] 7.4 Add monotonic job phase transitions for validation, acquisition, resolution, export, analysis, scanning, verification, reporting, and cleanup without changing terminal polling status semantics.
- [x] 7.5 Inject the acquisition service into `ScanJobRunner`, prepare exactly one target, propagate safe progress, run the audit, finalize evidence/cleanup, and sanitize every failure path.
- [x] 7.6 Add API/job-store/runner tests for local compatibility, remote queued/running phases, restart persistence, disabled policy, acquisition failure, empty scope, successful exact-commit scan, cleanup failure, and artifact access after failure.

## 8. Add the Remote Scan Frontend Workflow

- [x] 8.1 Extend frontend API types and client fixtures for structured source, remote capability options, job phase, resolved commit, acquisition summary, and sanitized failure fields.
- [x] 8.2 Add an accessible Local/GitHub/GitLab segmented source control to the scan console, with local path or remote URL input and an exact commit input while preserving all existing scan controls.
- [x] 8.3 Add client validation for canonical GitHub/GitLab HTTPS URLs and complete commits, require a commit when HEAD resolution is unavailable, disable unsupported providers, and rely on backend validation as authoritative.
- [x] 8.4 Display stable acquisition phase, resolved commit, cache/network status, cleanup result, and readable failures in run list/detail views without exposing raw commands or absolute cache/workspace paths.
- [x] 8.5 Add component/client/polling tests for source switching, legacy local submission, remote payloads, disabled capability, validation errors, phase polling, successful provenance, and acquisition/cleanup failures.
- [x] 8.6 Verify responsive desktop/mobile layouts, stable controls, long URL/commit wrapping, loading/disabled/error states, and no overlapping or shifting UI through Playwright screenshots.

## 9. Documentation and Operator Controls

- [x] 9.1 Document system Git prerequisites, remote-acquisition enablement, public GitHub/GitLab scope, CLI `--revision`, cache/work roots, budgets, canonical URL/commit input, network behavior, and Windows/POSIX cleanup troubleshooting.
- [x] 9.2 Update safety documentation to distinguish remote source acquisition from live-target access and explain static, Docker-only, no-network, read-only, no-build, and no-target-write guarantees.
- [x] 9.3 Document cache inspection and bounded cleanup without destructive broad deletion, plus acquisition artifact fields and failure/remediation taxonomy.

## 10. End-to-End Acceptance

- [x] 10.1 Run focused acquisition, repository, runtime, validation, Web backend, benchmark compatibility, redaction, cleanup, and frontend tests and retain exact passing commands/results.
- [x] 10.2 Run the full default Python and frontend suites with remote acquisition disabled and prove no deterministic test invokes clone, fetch, GitHub, Docker, MCP, or a real model unexpectedly.
- [x] 10.3 Run an offline fake-acquisition Web-to-report audit proving a pasted GitHub source resolves to a fixed commit, scans non-empty exported files, creates expected findings/evidence, records acquisition provenance, and cleans the export.
- [x] 10.4 Run offline negative end-to-end cases for denied URL, missing Git, timeout, wrong origin, commit mismatch, empty scope, archive escape, budget exhaustion, scanner failure, and cleanup failure; none may claim success or fabricated zero metrics.
- [x] 10.5 Run the complete benchmark evaluation suite and a fixture benchmark to prove acquisition refactoring preserves protocol identity, resume behavior, metrics, reports, and promotion gates.
- [x] 10.6 Run frontend unit/typecheck/build plus Playwright desktop/mobile smoke for local, GitHub, and GitLab workflows and retain screenshots or structural evidence.
- [x] 10.7 Run one explicitly authorized bounded live smoke against a reviewed small public GitHub repository, record the exact resolved commit, non-empty scan evidence, time/disk budgets, target integrity, cleanup, and artifact credential scan; record a truthful skip when unavailable.
- [x] 10.8 Run syntax, diff/format, secret, artifact-schema, and `openspec validate add-secure-remote-repository-acquisition --type change --strict --no-interactive` checks before marking the change complete.

## 11. P0 Provider and Terminal-Evidence Corrections

- [x] 11.1 Add CLI `--revision` with a backward-compatible `--commit` alias and reject revisions for local targets.
- [x] 11.2 Implement canonical GitLab HTTPS acquisition, including nested namespaces, source-kind/host consistency, exact-commit export, and the same safety limits as GitHub.
- [x] 11.3 Extend Web and frontend source contracts and controls for GitLab while completing GitHub URL/commit input and offline exact-commit validation.
- [x] 11.4 Finalize `report.json` after cleanup with original/normalized URL, requested/resolved revision, non-empty scanned files, real findings/verification candidates, and terminal cleanup status.
- [x] 11.5 Propagate acquisition, empty-scope, and cleanup failures into failed job state without a successful report or fabricated zero-result claim.
- [x] 11.6 Re-run all Python/frontend/benchmark/OpenSpec acceptance and record current evidence for both providers.
