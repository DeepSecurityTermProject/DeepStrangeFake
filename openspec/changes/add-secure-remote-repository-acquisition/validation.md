# Validation Evidence

## Safety envelope

- Remote acquisition remains disabled by default; deterministic tests do not invoke public network access, Docker, MCP, or a real model.
- One explicitly authorized, bounded GitHub smoke used the public `octocat/Hello-World` repository at exact commit `7fd1a60b01f91b314f59955a4e4d4e80d8edf11d`.
- GitLab live network availability could not be established in this environment. GitLab behavior was instead exercised through the production acquisition core with a real temporary bare Git mirror, exact object verification, archive/export, runtime scan, report finalization, and cleanup.

## Focused backend and acquisition tests

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
.\.venv\Scripts\python.exe -m unittest tests.test_repository_acquisition -q
```

Result: `Ran 25 tests in 3.058s`, `OK`. The focused acquisition, cache-only system-Git, archive safety, redaction, cleanup, prepared-target, Web schema/job runner, CLI revision, GitHub, and nested-namespace GitLab tests passed.

The negative matrix covers policy-denied URL/revision, disabled acquisition,
missing Git/clone failure, command timeout, wrong cached origin, missing and
mismatched commits, cache-only miss, lock contention, interrupted temporary
mirror cleanup, archive traversal/link/collision, mirror/member/file/byte
budgets, empty effective scope, scanner/runtime failure handling, cleanup
failure, and credential sentinel redaction. Failures retain null/gap accounting
where work did not occur and do not create a succeeded Web job.

## Full Python suite

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
.\.venv\Scripts\python.exe -m unittest discover -s tests
```

Result: `Ran 281 tests in 46.387s`, `OK (skipped=7)`. The skips are opt-in/live integrations; the deterministic suite completed without public remote acquisition or external provider access.

## Frontend

```powershell
npm test -- --run
npm run typecheck
npx vite build --configLoader runner --outDir "$env:TEMP\deepstrangefake-remote-acquisition-build"
```

Results: 16 tests passed, 1 opt-in screenshot test skipped; TypeScript typecheck passed; production build completed with 1769 transformed modules. Playwright inspection at 1280x720 and 390x844 found no horizontal overflow, overlapping controls, or clipped Local/GitHub/GitLab fields. Invalid offline remote submission displayed the exact-commit validation error without calling the backend.

## Fixture benchmark

```powershell
.\.venv\Scripts\python.exe -m audit_agent benchmark `
  --benchmark-config benchmarks/corpus.v1.json `
  --output "$env:TEMP\deepstrangefake-remote-acquisition-benchmark" `
  --cache-root "$env:TEMP\deepstrangefake-benchmark-cache" `
  --profile fixture --offline --provider mock --model deterministic-local `
  --truth benchmarks/truth.v1.json `
  --adjudications benchmarks/adjudications.v1.json
```

Result: 3/3 cases completed, 0 failed, 0 timed out, report complete, and baseline eligible. Candidate recall and truth coverage were both 1.0; the paired vulnerable/fixed check passed.

The benchmark compatibility suite also passed `43 tests` with `2` opt-in/live skips after routing remote benchmark acquisition through the generic service adapter.

## Provider end-to-end evidence

- GitHub live smoke: the CLI acquired `https://github.com/octocat/Hello-World.git`, retained the original and normalized URLs, requested and resolved the exact commit above, scanned the non-empty `README` file, truthfully reported zero candidates for that content, and finalized cleanup as `complete`.
- GitLab production-core fixture: a nested-namespace GitLab HTTPS identity was mapped to a real temporary bare mirror, acquired at an exact commit, exported a non-empty vulnerable Python fixture, produced at least one real scanner candidate, retained source/commit/file provenance in `report.json`, and finalized cleanup as `complete`.
- Failure gates: acquisition failure, empty effective scope, report-finalization failure, and cleanup failure persist terminal `failed` state and cannot leave a succeeded job or successful zero-result report.
- Artifact inspection confirmed the exported GitHub workspace was absent after cleanup and no credential sentinel appeared in persisted acquisition/report artifacts.
