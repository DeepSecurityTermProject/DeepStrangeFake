# Phase Three Validation Evidence

## Scope and outcome

Phase Three implements tasks 7.1 through 8.10 only. It adds a trusted, rebuildable project-posture projection over authoritative run artifacts and a project dashboard that keeps latest-run truth separate from the latest complete posture. Phase Four compatibility and operational hardening tasks remain intentionally unstarted.

## Trusted posture service

- `audit_agent/server/posture.py` defines and emits explicit versions for posture, completeness, risk formula, finding fingerprint, trend comparison, investigation quality, coverage, dashboard, and unavailable-data records.
- Report projection reads `verification_candidates` and evidence chains. Only `confirmed` candidates whose chain independently records confirmed validation and evidence references enter `findings.validated`. Likely/static candidates, pending, manual, rejected, inconclusive, and forged confirmed-without-chain records remain separate.
- Risk is trusted code, not report narrative: `min(100, round_half_up(sum(weight * clamped_confidence)))` with critical=25, high=15, medium=7, low=2, informational=0. Missing or non-finite confidence uses the published conservative `1.0` fallback and is counted in metadata.
- Fingerprints use normalized vulnerability class, repository-relative path, enclosing symbol, and sink/dangerous-operation identity. Titles, descriptions, confidence, and line numbers are excluded. Missing symbol/sink fields receive documented deterministic fallback anchors and quality labels.
- Completeness requires successful terminal status, a completed report, no degradation, matching report/resource scan counts, complete validation and evidence gates, a successful resource summary, complete LLM reconciliation, and budget accounting metadata.
- Complete, version-compatible runs produce new, persistent, resolved, and reintroduced classifications. Incomplete runs can show persistent/unconfirmed observations but cannot resolve prior findings. Version mismatch returns an explicit non-comparable limitation.
- `WorkspaceStore` persists idempotent posture snapshots and first/last-seen finding identities in the existing SQLite schema. `JobStore` projects terminal runs observationally; dashboard reads also backfill and re-reconcile snapshots in run order so out-of-order completion cannot leave stale trend labels.
- Missing reports, resource summaries, or legacy verification contracts are marked unavailable/incomplete. The service never converts an older `validated_count` or a static candidate into a confirmed finding.

## Dashboard API and frontend

- `GET /api/projects/{project_id}/dashboard` returns safe project metadata, active/latest run truth, latest-run posture limitations, latest complete posture attribution, confirmed severity counts, separate validation states, deterministic risk details, investigation quality, recent trend points, and evidence-linked high-risk findings.
- The project page renders latest status/timing/coverage separately from historical posture, a large deterministic risk card with formula/component disclosure, confirmed severity distribution, separate candidate states, text/numeric trend tables, investigation-quality cards, and finding drill-down.
- No-runs, running-only, no-complete-posture, stale historical posture, incompatible fingerprint version, legacy unavailable, and API failure states avoid a false zero-risk/healthy presentation.
- High-risk links include the owning run and finding identifier. The project-scoped run page consumes the identifier, opens the Findings tab, scrolls to the matching finding, and gives it keyboard focus and an active outline.
- Charts have visible numeric tables and labels; status is not color-only. Reduced-motion behavior remains inherited from the existing kinetic design system.

## Automated verification

### Backend

Command:

```text
.venv\Scripts\python.exe -m unittest tests.test_project_audit_workspace tests.test_web_backend_service tests.test_audit_event_stream tests.test_project_security_posture -q
```

Result: **47 tests passed**.

The seven Phase Three-specific tests cover:

- all severity weights, score cap, half-up rounding, missing/invalid confidence fallback, and out-of-range clamping;
- fingerprint stability across narrative/confidence/line changes and separation by class, symbol, or sink;
- validated/candidate/pending/manual/rejected/inconclusive separation and forged confirmation rejection;
- new, persistent, resolved, reintroduced, unconfirmed, and incompatible-version trends;
- incomplete accounting preventing both an authoritative score and a resolved classification;
- explicit unavailable legacy behavior;
- a three-run dashboard fixture with scores 15 then 40, stable persistence/new classification, a failed newest run, historical posture attribution, high-risk links, and idempotent backfill.

### Frontend

Command:

```text
npm test
```

Result: **12 test files passed, 1 API-environment smoke file skipped; 38 tests passed, 1 skipped**.

Phase Three tests cover formula explanation, confirmed/candidate separation, stale and running-only states, no false zero score, visible trend equivalents, evidence-linked navigation, focused finding context, and dashboard API failure.

Command:

```text
npm run build
```

Result: TypeScript typecheck and Vite production build passed; final bundle was generated successfully.

### OpenSpec and source hygiene

- `openspec validate add-project-centric-audit-console --strict`: passed.
- `git diff --check`: passed; Git emitted only existing LF/CRLF and inaccessible global-ignore warnings.
- The two pre-existing dirty nested benchmark repositories were not modified by Phase Three work.

## Browser and responsive integration fixture

A disposable localhost fixture served two complete project runs followed by one failed run. Browser verification observed:

- latest run `failed`, separately attributed latest complete posture, score **40**, confirmed findings **2**;
- trend points **15**, **40**, then unavailable; the failed run marked two prior findings unconfirmed and resolved none;
- one persistent SQL-injection fingerprint despite a changed finding ID/title/line, plus one new critical command-injection fingerprint;
- high-risk drill-down opened the owning run with the Findings tab selected and the command-injection article marked active;
- at 390x844 (375 CSS-pixel content width), no horizontal overflow, risk and quality grids collapsed to one column, and no visible link/button among the checked controls was smaller than 44x44 pixels;
- no browser console errors.

The disposable server, database, artifacts, and browser tab were removed after verification.

## Known limits retained for Phase Four

- Legacy reports without `verification_candidates` and modern resource accounting remain explicitly unavailable; no heuristic migration is attempted.
- Fingerprint-version changes require a future trusted migration before cross-version continuity can be claimed.
- Dashboard pagination, retention limits, recovery from partially applied migrations, broad security regression coverage, and full-repository compatibility suites belong to Phase Four tasks 9.1-9.10.
- The browser fixture proves the requested dashboard vertical slice, not every deployment/browser combination.
