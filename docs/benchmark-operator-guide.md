# Benchmark Operator Guide

The benchmark pipeline is for authorized, defensive evaluation of reviewed
fixtures and locked source revisions. A case is complete only when acquisition,
scan coverage, runtime/report identity, resource accounting, and cleanup
evidence validate. `remote-download-skipped` is never a successful scan and
cannot produce a completed all-zero result.

## Prepare and review the cache

Use the lock workflow to resolve mutable references before execution. Review
the normalized credential-free source, full commit SHA, license provenance,
scope, support level, truth reference, budgets, and safety policy. Executable
pilot/full cases must use reviewed exact commits; a branch or tag is not a lock.

Normal CI and offline runs use cache-only acquisition. Populate the bare-mirror
cache only in an explicitly authorized network session with `--allow-network`,
then return to offline operation. Acquisition uses fixed Git arguments and does
not run hooks, submodules, LFS smudge, repository filters, build, or setup code.
Do not copy a cache between identities unless its recorded normalized remote and
object checks remain valid.

## Run and resume

Select the versioned corpus profile, cache root, output root, truth manifest,
and optional adjudication manifest explicitly. Network and Docker remain off
unless their separate allow flags are supplied. Case budgets constrain tools,
LLM requests/tokens, Docker starts, repairs, validation level, and timeout.

Resume with the exact benchmark run ID. The immutable
`resolved-manifest.json` remains the record of the original request. A permitted
resume-time change is written to `resume-request-*.json`; it never overwrites
the original manifest. Completed scans are reused only when their strict reuse
fingerprint and required artifacts validate. A changed truth digest invalidates
reuse, preserves the old case as `stale-result-*.json`, and reruns the case.
Interrupted, malformed, or incomplete state also restarts from a safe boundary.

## Truth, adjudication, and evaluation identity

Truth uses `benchmark-truth.v1` records with reviewed stable IDs, expected
presence, class, path/location, exact vulnerable/fixed revisions, and evidence.
The report records the truth schema/version and canonical content digest. Editing
the same truth path therefore changes both reuse and comparison identity.

Adjudication uses `benchmark-adjudication.v1` additive records. The report
records its schema, canonical content digest, and record count. Changing human
adjudication recomputes metrics and makes reports comparison-incompatible, but
does not by itself rerun an otherwise reusable scan. Never edit raw findings to
express a review decision.

## Metrics and comparisons

Review raw counts and denominators as well as metric values. Manual-required is
an abstention, not a rejection. Confirmed precision includes only deduplicated
final-confirmed groups with true-positive or false-positive adjudication. A
confirmed finding in an eligible fixed/safe-negative case contributes to the
case false-positive rate even when it is not adjudicated. Missing denominators
or evidence are `null` with a machine-readable reason.

Comparisons require the same `comparison_protocol_fingerprint` and the same
declared `comparison_dimensions`. Declare an intentional axis such as `engine`,
`prompt`, or `model`; undeclared corpus, commit, scope, truth, adjudication,
matching, metric, safety, schema, or execution changes are incompatible. Do not
override a mismatch by copying fingerprints between reports.

## Timeout and cleanup

Each case runs in a bounded child process. POSIX owns the process tree through a
new session and POSIX process group. Windows starts the child suspended, assigns
it to a Windows Job Object with kill-on-close behavior, resumes it, and verifies
that parent, child, and grandchild processes are gone after timeout. A cleanup
gap prevents baseline promotion.

Docker is opt-in. Resources are selected and cleaned only by the exact
benchmark/run/case labels. Do not use broad container cleanup commands. A case
that cannot prove exact-label cleanup is not promotion-eligible.

## CI and pilot tiers

Normal CI runs the small local fixture corpus with network, real credentials,
and implicit Docker disabled. The real-project pilot is an approved manual or
scheduled workflow with locked 3–5 project inputs, explicit provider/model,
bounded timeout, reviewed secrets, and retained artifacts. The 20-project run is
a separate locked operational change; placeholders and remote skips do not
satisfy its project quota.

## troubleshooting

| Symptom | Action |
| --- | --- |
| `acquisition-cache-miss` | Verify the normalized source and exact commit exist in the reviewed cache; use an authorized `--allow-network` preparation run only if policy permits. |
| Mutable or unresolved commit | Run the lock workflow, review the exact SHA and license/source provenance, then execute the locked manifest. |
| Truth changed during resume | Inspect the new `resume-request-*.json`; expect the original result to become stale and the affected scan to rerun. |
| Adjudication changed | Expect scan reuse, metric reevaluation, a new adjudication digest, and comparison incompatibility with the old report. |
| `comparison_protocol_fingerprint mismatch` | Compare corpus, commits, scope, truth/adjudication digests, schemas, safety, and declared `comparison_dimensions`; do not force compatibility. |
| Missing elapsed time or accounting | Inspect `run-resource-summary.v1.json` and its accounting gaps; missing required evidence blocks promotion. |
| Timeout cleanup failed | On Windows inspect Job Object cleanup evidence; on POSIX inspect process-group termination evidence. Do not promote while any descendant remains. |
| Docker cleanup failed | Verify exact benchmark/run/case labels and daemon availability; never substitute global cleanup. |
| Missing API key or model | Load the approved `.env`, use `LLM_API_KEY`, and provide a non-empty real model for a real provider. Never persist the key value. |
| `remote-download-skipped` or empty scope | Treat the case as not run. Fix acquisition/scope and rerun; `--allow-partial` is diagnostic only. |
