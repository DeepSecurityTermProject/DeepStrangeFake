## 1. Decision Models and Schemas

- [x] 1.1 Add decision record models for LLM proposals, policy gates, merge results, decision sources, and fallback metadata.
- [x] 1.2 Add role-specific JSON schemas for Orchestrator, Recon, Analysis, and Verification decisions.
- [x] 1.3 Add schema validation tests for valid, malformed, missing-field, and wrong-type LLM decision payloads.
- [x] 1.4 Add persistence helpers for decision artifacts under each run directory.
- [x] 1.5 Add redaction coverage for decision artifacts that include provider metadata, prompts, raw model output, or diagnostics.

## 2. Policy Gates and Merge Logic

- [x] 2.1 Add deterministic decision policy gates for local evidence, memory/CVE context, role permissions, tool budgets, validation levels, and no-live-target constraints.
- [x] 2.2 Add tests proving intelligence-only and memory-only LLM proposals cannot become accepted findings.
- [x] 2.3 Add merge logic that combines deterministic outputs and LLM proposals into final decisions with explicit `decision_source`.
- [x] 2.4 Add repair/fallback handling for malformed, unsafe, low-confidence, and over-budget model proposals.
- [x] 2.5 Add tests for LLM-vs-policy conflicts and fallback reason persistence.

## 3. Four-Agent Decision Loop Wiring

- [x] 3.1 Wire Orchestrator LLM decision proposals into audit scope, focus areas, budgets, and agent order after policy validation.
- [x] 3.2 Wire Recon LLM decision proposals into bounded memory queries, context selection, safe MCP queries, and tool requests through `tool_protocol`.
- [x] 3.3 Wire Analysis LLM decision proposals into candidate generation and ranking only when source locations and local evidence citations resolve.
- [x] 3.4 Wire Verification LLM decision proposals into accept/reject rationale, priority, and validation-level selection with deterministic override.
- [x] 3.5 Update `pipeline.py` so each role emits LLM proposal, policy gate, merge result, and final output artifacts.

## 4. Message Bus, Replay, and Reporting

- [x] 4.1 Publish message bus events for LLM proposal creation, schema validation, policy gates, tool dispatch, merge results, and fallback use.
- [x] 4.2 Extend replay summaries to show role-level decision proposals, accepted/denied gates, final decision sources, and fallback reasons.
- [x] 4.3 Extend JSON reports with decision source, LLM confidence, policy-gate outcome, prompt refs, LLM refs, and evidence refs.
- [x] 4.4 Extend Markdown reports with a concise LLM influence section for findings and verification decisions.
- [x] 4.5 Add tests proving replay/report output distinguishes contextual CVE/RAG intelligence from local evidence.

## 5. Runtime Flags and Testing

- [x] 5.1 Add runtime config and CLI flags for enabling LLM decision participation globally and per role.
- [x] 5.2 Keep default unit tests offline by using mock LLM decision payloads.
- [x] 5.3 Add opt-in live LLM decision smoke using the configured `.env` `LLM_MODEL`.
- [x] 5.4 Add docs showing how LLM proposals influence decisions, how fallbacks work, and how to inspect artifacts.
- [x] 5.5 Run full unit tests, live LLM smoke when explicitly enabled, and OpenSpec strict validation.
