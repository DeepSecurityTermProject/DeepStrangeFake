## Validation Record

Date: 2026-07-13

Safety scope: local authorized synthetic fixtures only. The only network access
was the explicitly authorized LLM provider request; no real target was contacted
and no destructive operation was run.

### Completed checks

- Focused repair core: `.venv\\Scripts\\python.exe -m unittest tests.test_poc_repair_core -v` -> 12 passed.
- Structured-output and provider-contract focus: `.venv\\Scripts\\python.exe -B -m unittest -v tests.test_llm_prompt_runtime tests.test_poc_repair_core tests.test_poc_repair_live_provider` -> 25 run, 2 opt-in skips, no failures.
- Full Python suite: `.venv\\Scripts\\python.exe -B -m unittest discover -s tests -v` -> 135 run, 5 skipped, no failures.
- Frontend suite: `npm test` -> 13 passed, 1 skipped.
- TypeScript: `npm run typecheck` -> passed with the non-incremental consolidated typecheck config.
- OpenSpec: `openspec validate add-llm-poc-repair-agent-loop --strict` -> valid.
- Live Docker smoke was explicitly attempted with the gated synthetic fixture,
  no image pull, and Docker `--network none`; it skipped with the actionable
  reason `Docker daemon is unavailable or permission denied.`

### Policy-gated live check

- An explicitly authorized real-provider run on 2026-07-13 loaded
  `.env`/`LLM_API_KEY`, reached `deepseek-v4-pro`, and completed in 6.141 seconds.
- The provider returned a schema-valid typed edit for the authorized synthetic
  missing-import fixture. Trusted assembly applied one repair, the fake Docker
  runner executed exactly twice, and the final status was `confirmed`.
- The smoke asserted one applied repair, no final stop reason, unchanged target
  bytes, and unchanged before/after target manifests. Contract, provider,
  semantic-integrity, and safety failures are not accepted as a passing result.
- The request uses the complete nested edit schema and OpenAI-compatible
  structured-output negotiation (`json_schema`, then `json_object` only after
  an HTTP 400 capability rejection). The exact parser remains fail-closed.

### Acceptance notes

- Core repair coverage uses mock LLM responses and fake Docker runners; it does
  not start containers or execute attack logic.
- The multi-finding integrity acceptance leaves Finding A and Finding B
  provisionally confirmed until both attempts finish. Finding B then changes a
  synthetic target file, one shared run-level manifest comparison executes,
  and both provisional confirmations finalize as `manual-required` with the
  same comparison reference. Exactly one before-manifest, one after-manifest,
  and one `poc.target-integrity` event are asserted.
- Default and legacy-default configuration keep LLM PoC repair disabled.
- Semantic or safety denial produces no second runner start.
- Reports, replay, backend data, and the Web UI expose compact summaries only;
  no generic artifact-read endpoint was added.
