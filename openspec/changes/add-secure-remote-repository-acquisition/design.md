## Context

`scan --target` and the Web API currently advertise or accept repository URLs, but both legacy and graph runtimes call `analyze_target()` without `allow_clone`, producing remote metadata with no `root_path`, commit, or files. The existing shallow-checkout helper is not suitable to wire directly into Web jobs: its destination uses only the repository name, it does not validate an existing origin or refresh it, and it does not provide immutable export, concurrency, cleanup, or acquisition evidence.

The benchmark pipeline has stronger primitives: normalized allowed hosts, URL-derived mirror keys, explicit network/cache-only behavior, exact-commit checks, non-executing `git archive`, link/path checks, bounded subprocesses, and redacted acquisition records. Those primitives are currently coupled to `BenchmarkCase` and cannot be reused cleanly by interactive jobs. The Web job model also has only coarse status, while runtime initialization independently analyzes its target in legacy and graph paths.

The application is a local, single-user defensive audit platform without authentication or remote multi-user deployment. Remote acquisition therefore remains operator-gated, and downloaded code is always untrusted passive input rather than a live target.

## Goals / Non-Goals

**Goals:**

- Turn a public GitHub or GitLab HTTPS URL into one verified, immutable, resource-bounded local source snapshot that normal scanners actually read.
- Reuse one hardened acquisition implementation across interactive and benchmark paths without changing benchmark protocol behavior.
- Preserve original URL provenance and exact commit through AgentRuntime, reports, replay-facing metadata, and Web job views.
- Make network permission, acquisition progress, failure, cleanup, and empty-scope behavior explicit and machine-readable.
- Permit existing static analysis and tightly constrained Docker verification while preventing project-controlled execution and target writes.
- Keep default tests deterministic and offline.

**Non-Goals:**

- Private repositories, authentication tokens, GitHub Apps, SSH, arbitrary Git hosts, URL credentials, branch/tag selection, pull-request refs, or submodule content.
- Project build/setup, dependency installation, package scripts, live-service startup, or network attacks against repository owners.
- Replacing Git with a new library, adding a distributed queue, adding multi-user authorization, or making benchmark selection part of the interactive workflow.
- Persisting per-job source exports indefinitely or treating a successful clone alone as proof that a scan occurred.

## Decisions

### 1. Extract a target-agnostic acquisition core

Create `audit_agent/repository_acquisition.py` for source policy, normalized identity, commit resolution, mirror management, archive export, safety checks, evidence, and cleanup. Create a thin compatibility adapter in `benchmark_acquisition.py` that maps `BenchmarkCase` and `AcquisitionRecord` to the generic request/result.

This avoids copying security-sensitive Git code and avoids passing synthetic benchmark cases through the Web layer. Existing benchmark tests become compatibility tests for the extracted core.

### 2. Model source intent separately from prepared source state

Introduce a discriminated `SourceSpec` with local, GitHub, and GitLab variants. Keep legacy `target: str` input and normalize it as local for backward compatibility. A `PreparedAuditTarget` context owns the resolved `RepositoryMetadata`, acquisition record, local export path, and cleanup lifecycle.

For remote targets, metadata keeps `target.source` and the detected `target.kind`, sets `target.path/root_path` to the verified export, and sets the exact commit. An additive materialization/provenance field distinguishes a verified local snapshot from both a user-local directory and an unresolved live remote.

This is preferred over rewriting the target as local because provenance and remote-origin policy must survive into verification and reports.

### 3. Prepare once above legacy and graph execution

Move target preparation to the stable pipeline/runtime boundary and pass prepared metadata into both runtime modes. Neither `_run_legacy_audit` nor `_GraphAuditExecution._initialize` may independently parse or acquire the target.

The preparation context remains alive through scanning, Docker verification, reporting, and target-integrity checks, then cleans the per-job export in `finally`. Acquisition evidence is copied into the run as soon as a run context exists and finalized with cleanup outcome at termination.

### 4. Resolve HEAD, then operate only on the exact commit

Interactive GitHub/GitLab input supports either remote `HEAD` or a complete 40/64-character hexadecimal object ID. CLI exposes this as `--revision`, with `--commit` retained as an alias. HEAD is resolved with a bounded non-interactive Git query; the returned object is validated before clone/fetch/export. Arbitrary branch/tag names are excluded from MVP to remove option/ref ambiguity and mutable naming from the contract.

Mirrors are stored under a normalized-URL digest, not owner/repository display names. Existing origins are normalized and compared before object lookup. Cache misses clone a filtered mirror only when operator network policy is enabled; missing objects are fetched by exact commit. Export always uses the verified object ID.

### 5. Use explicit operator policy rather than a client network switch

Add `RemoteAcquisitionConfig` to `AuditConfig`, including enabled flag, allowed HTTPS hosts, cache/work roots, Git and total timeouts, archive member/byte budgets, mirror post-check budget, lock timeout, and cleanup policy. Environment/config loading controls enablement; a request cannot turn network on.

`/api/options` exposes whether remote acquisition is available, the allowed GitHub/GitLab host subset, HEAD capability, and non-secret limits. The Web UI disables unavailable providers and requires an exact commit in cache-only mode. This is preferred over a request-level `allow_network` boolean because the unauthenticated local API must not grant itself server egress.

### 6. Harden Git execution and export

All Git commands use `shell=False`, bounded argv, a minimal process environment, `GIT_TERMINAL_PROMPT=0`, disabled system/global config and credential helpers, disabled LFS smudge, HTTPS-only protocol policy, and redirects disabled for GitHub and GitLab. Mirrors and archives do not check out files, initialize submodules, or run hooks/filters/build scripts.

Archive validation occurs before extraction and checks containment, entry type, member count, and uncompressed bytes. Export and mirror creation use temporary siblings followed by atomic replacement. A per-identity lock serializes mirror mutation; each job still receives a distinct export.

### 7. Add phase without expanding terminal job states

Keep `queued/running/succeeded/failed` for frontend polling compatibility. Add monotonic phases: `validating-source`, `acquiring`, `resolving-commit`, `exporting`, `analyzing`, `scanning`, `verifying`, `reporting`, and `cleaning-up`.

Persist safe acquisition summary fields on the job so restarts do not erase progress evidence. Invalid structured input returns a synchronous validation error; Git/network/export failures terminate the already-created asynchronous job with sanitized diagnostics.

### 8. Fail closed on absent proof

A remote job cannot succeed unless acquisition is ready, resolved commit agrees across acquisition and repository metadata, the export exists during execution, effective scope has at least one file, required run artifacts exist, and cleanup reaches a known outcome. The runtime must never fall back from acquisition failure to URL-only metadata analysis.

Cleanup failure leaves report artifacts accessible but prevents an unqualified successful job status. Final report JSON records original/normalized source, requested/resolved revision, the non-empty scanned file list, real finding/verification results, and cleanup outcome. The persistent mirror is intentional cache state; only the per-job export is mandatory cleanup.

### 9. Treat verified snapshots as remote provenance with local materialization

Static scanners consume the verified `root_path`. Docker verification is allowed only when explicitly enabled, sandbox network is disabled, target access is read-only, and existing PoC/repair policy is satisfied. Local-process sandbox execution remains denied for remote provenance, even though files are present locally.

Validation policy therefore checks verified materialization plus runner type and isolation settings instead of using only `target.kind == local`.

### 10. Keep the frontend workflow compact

Add a Local/GitHub/GitLab segmented source control to `CreateScanPage`. Remote modes show URL and exact commit inputs while retaining the existing scan controls. Run list/detail surfaces phase, resolved commit, cache outcome, and sanitized failure; it does not expose raw Git commands or absolute cache/workspace paths.

No separate remote-resolution endpoint is required for MVP. Job creation is asynchronous, and the current polling path already provides the right lifecycle boundary.

## Risks / Trade-offs

- [A public repository can still be very large] -> Bound Git and total time, post-check mirror size, pre-check archive count/bytes, audit scope, and clean partial state on failure.
- [Provider redirects can point outside the approved identity] -> Disable redirects and require the user to submit the canonical GitHub or GitLab repository URL.
- [Windows locks or antivirus can delay cleanup] -> Use unique workspaces, close handles before cleanup, retry a bounded number of times, persist residual path as a redacted artifact ref, and fail the cleanup gate.
- [Refactoring benchmark acquisition can regress protocol identity] -> Keep its public adapter and golden tests unchanged and run the full benchmark suite before acceptance.
- [Deleting the export removes post-run source browsing] -> Reports retain source locations, snippets, hashes, and acquisition provenance; reacquisition from the verified mirror is a future explicit action, not an implicit report read.
- [Remote provenance complicates existing local-only sandbox checks] -> Add an explicit verified-materialization policy and keep local runner denied rather than relabeling the source as local.
- [The unauthenticated Web API could be exposed beyond localhost] -> Remote acquisition is operator-disabled by default, host/protocol/resource policies are server-side, and client payloads cannot enable egress.

## Migration Plan

1. Add generic source/acquisition models, configuration, safety validators, fake-command tests, and the benchmark compatibility adapter without changing interactive behavior.
2. Add prepared-target support at the pipeline/runtime boundary and prove local legacy/graph behavior is unchanged.
3. Add Web API source variants, job phase/provenance persistence, acquisition orchestration, failure/cleanup gates, and injected-service tests.
4. Add frontend source controls and acquisition status/detail presentation with existing local workflow regression coverage.
5. Enable remote acquisition only in an explicit development configuration, run an opt-in bounded public fixture smoke, verify artifacts/redaction/cleanup, then document operator enablement.

Rollback disables remote acquisition and reverts clients to the legacy local `target` contract; local scans and existing benchmark locks remain usable. Cached mirrors and partial workspaces are never silently deleted during rollback and can be removed through the documented bounded cleanup command.

## Open Questions

None for MVP. Private repository authentication, branch/tag refs, retained source browsing, and multi-user authorization require separate changes after the public GitHub/GitLab workflow is validated.
