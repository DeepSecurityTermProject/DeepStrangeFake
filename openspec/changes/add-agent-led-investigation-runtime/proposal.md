## Why

The current audit runtime primarily converts deterministic Pattern/Dataflow scanner output into findings, while LLM agents provide optional bounded proposals and PoC repair. This leaves discovery limited by handwritten scanner coverage and does not satisfy the intended agent-led workflow where agents form hypotheses, gather local evidence through tools, and submit independently verifiable claims.

## What Changes

- Add an `agent-led` execution mode and make it the default for CLI, Web, and configuration while preserving explicit deterministic, adaptive, and legacy modes.
- Introduce versioned security-signal, investigation-hypothesis, investigation-step, evidence-gate, verification-evidence-package, and verification-plan contracts.
- Run a lightweight Pattern seed pass, then let the Analysis agent investigate hypotheses with registered repository, call-graph, Dataflow, Semgrep, Bandit, Gitleaks, and lexical-memory tools.
- Require every candidate to pass a trusted evidence gate with an exact local source location plus independent corroboration.
- Let the Verification agent compose registered validation primitives while trusted code compiles harnesses and the existing sandbox/Judge controls execution and verdicts.
- Add hypothesis-level checkpoints, progress-aware deterministic fallback, a `degraded` terminal state, cancellation, auditable resource budgets, and additive report/Web summaries.
- Add a reviewed 24-case scanner-blind-spot corpus and promotion gates proving discovery gain without false confirmation.
- **BREAKING**: an omitted graph mode now requests `agent-led`; non-development mock or unavailable real providers produce an explicit degraded deterministic fallback instead of silently claiming agent-led execution.

## Capabilities

### New Capabilities
- `agent-led-investigation`: Signal seeding, autonomous bounded hypothesis investigation, registered tool use, and hypothesis checkpoints.
- `evidence-gated-findings`: Trusted dual-evidence promotion rules and normalized evidence packages for independent verification.
- `trusted-verification-plans`: Model-selected registered verification primitives compiled and judged by trusted code.
- `agent-led-runtime-control`: Default-mode selection, hard budgets, progress-aware fallback, cancellation, degraded status, reporting, and promotion gates.

### Modified Capabilities
- `llm-agent-decision-contracts`: Analysis output changes from direct candidate proposals to hypothesis/step contracts, and Verification output changes to evidence-package-based verification plans.
- `adaptive-agent-execution-graph`: The public execution-mode contract gains `agent-led` as the default while existing graph modes remain explicit rollback choices.

## Impact

- Affects runtime configuration, models, prompt contracts, tool protocol/adapters, graph entrypoints, verification, evidence/report serialization, CLI/Web schemas, job lifecycle, frontend run details, and benchmark evaluation.
- Adds trusted parsers for optional Semgrep, Bandit, and Gitleaks executables and lightweight Python/JS/TS call-graph artifacts; unavailable tools remain a recorded degraded observation.
- Reuses existing remote acquisition, dependency intelligence, LLM lifecycle accounting, immutable artifacts, PoC repair, Docker sandbox, Judge, replay, and benchmark infrastructure.
- Does not add new vulnerability classes, arbitrary model-authored code/commands, real embedding retrieval, database queues, multi-tenancy, or dynamic child agents.
