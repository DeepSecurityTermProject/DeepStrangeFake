# Validation Evidence

Date: 2026-07-14

All acceptance work used local synthetic fixtures. Networked providers, real
targets, and destructive operations were not used.

## Focused accounting and runtime acceptance

```powershell
python -m unittest tests.test_llm_audit_accounting -q
```

Result: `Ran 13 tests in 3.755s - OK`.

The suite covers schema-invalid responses with nonzero usage, pre- and
post-dispatch budget denial, provider errors and timeouts, successful and
exhausted retries, response-format fallback, immutable-event collisions,
illegal transitions, duplicate usage, budget-counter mismatch, sentinel
redaction, legacy/disabled readers, benchmark blockers, a mixed fake-provider
audit, replay, and response deletion tamper detection.

```powershell
python -m unittest tests.test_llm_audit_accounting tests.test_llm_prompt_runtime tests.test_llm_decision_loop tests.test_mcp_memory_bus_runtime tests.test_runtime_kernel tests.test_agent_runtime_integration tests.test_poc_repair_core tests.test_runtime_cli_docs -q
```

Result: `Ran 78 tests in 12.916s - OK (skipped=2)`.

```powershell
python -m unittest tests.test_benchmark_evaluation_pipeline -q
```

Result: `Ran 43 tests in 9.161s - OK (skipped=2)`. The intentional Markdown
golden digest reflects the new accounting columns.

## Full offline suite

The default unittest suite was run with `OPENAI_API_KEY`, `LLM_API_KEY`,
`AUDIT_AGENT_RUN_INTEGRATION`, and
`AUDIT_AGENT_RUN_REPAIR_PROVIDER_TESTS` unset:

```powershell
$modules = Get-ChildItem tests -Filter "test_*.py" |
    ForEach-Object { "tests." + $_.BaseName }
python -m unittest @modules -q
```

Result: all 256 discovered tests completed without failures. Opt-in live,
Docker, and integration tests remained skipped; no deterministic test invoked a
network provider.

## Static and OpenSpec checks

```powershell
$env:PYTHONPYCACHEPREFIX = Join-Path $env:TEMP "deepstrangefake-codex-pycache"
python -m py_compile audit_agent/llm_accounting.py audit_agent/llm.py audit_agent/runtime.py audit_agent/decisions.py audit_agent/models.py audit_agent/prompts.py audit_agent/message_bus.py audit_agent/poc_repair.py audit_agent/resource_summary.py audit_agent/benchmark_models.py audit_agent/benchmark_runtime.py audit_agent/benchmark_evaluation.py audit_agent/redaction.py tests/test_llm_audit_accounting.py tests/test_benchmark_evaluation_pipeline.py
git diff --check
openspec validate harden-llm-response-audit-accounting --type change --strict --no-interactive
```

Results: syntax check passed, diff check passed, and OpenSpec reported
`Change 'harden-llm-response-audit-accounting' is valid`.

The bytecode prefix was redirected because the existing workspace
`__pycache__` directories reject replacement temp files on this Windows
machine; this did not affect imports or tests.

## Real-provider smoke (2026-07-14)

Task 10.5 was executed with the configured `openai-compatible` provider using
only fixed synthetic prompts. No repository source, finding, target, MCP,
memory, Docker, or PoC content was sent to the provider.

The integration preflight loaded `LLM_API_KEY`, `LLM_API_BASE_URL`, and
`LLM_MODEL` from `.env`, received parseable JSON in 2031 ms, persisted the
response artifact, and reported 49 provider tokens.

An audited structured-response probe exercised provider-format fallback. It
recorded one request group, two physical provider attempts, one retry, and an
accepted 88-token response. The first attempt returned HTTP 400 without usage,
so strict reconciliation correctly produced `llm_tokens: null` and the stable
`usage-unknown` gap instead of inventing zero usage. This is the expected
unknown-usage behavior documented by the design.

A second audited probe received a real provider response and deliberately
validated it against a locally incompatible schema. The gateway persisted the
response before recording `schema-invalid`, `fallback-used`, and terminal
`fallback`. Reconciliation reported:

- one request group and one provider attempt;
- 115 provider-reported tokens;
- an existing correlated response artifact;
- complete request, attempt, and token accounting;
- zero reconciliation gaps.

A credential scan covered all 19 files produced by the preflight and the two
audited probes. It found zero exact API-key matches, zero unredacted
authorization/API-key patterns, and zero credential-bearing URLs.

## P1 tamper re-acceptance (2026-07-14)

Three local probes were converted into deterministic regression tests:

- Corrupt JSON, request-ID substitution, response-ID substitution, and usage
  substitution in a referenced response artifact now produce stable gaps and
  `llm_tokens: null`.
- Benchmark completion recomputes the live ledger with runtime budget counters,
  compares contributing refs and totals with the stored summary, and rejects a
  deleted response even when the stored summary still says `complete`.
- CLI and Web replay merge the message view with authoritative ledger replay;
  deleting an event produces `complete: false`, stable `gap_ids`, and the
  affected request group.

```powershell
python -m unittest tests.test_llm_audit_accounting tests.test_runtime_cli_docs tests.test_web_backend_service -q
python -m unittest tests.test_benchmark_evaluation_pipeline -q
```

Results: `Ran 36 tests in 4.899s - OK`; benchmark `Ran 43 tests in 8.907s - OK
(skipped=2)`.

## Legacy runtime report mode re-acceptance (2026-07-14)

The legacy execution path now reports `token_usage.mode: lifecycle-ledger`, the
same as graph execution. A local mock-LLM legacy audit asserts that the report
also contains a present compatibility-observer lifecycle ledger.

```powershell
python -m unittest tests.test_runtime_kernel.AgentRuntimeCompatibilityTests.test_legacy_runtime_report_declares_lifecycle_ledger_token_usage -q
```

Result after the fix: `Ran 1 test - OK`.
