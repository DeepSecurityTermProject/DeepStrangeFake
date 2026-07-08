## Why

The current four-agent runtime can call real models and persist prompt/LLM artifacts, but LLM output is still mostly auxiliary: deterministic Python rules remain the primary source of plans, tool choices, candidate selection, and verification decisions. Now that the real `LLM_MODEL` smoke test passes, the system should promote schema-validated LLM outputs into guarded decision inputs while preserving evidence-first safety and deterministic fallback.

## What Changes

- Add LLM-driven decision objects for Orchestrator, Recon, Analysis, and Verification, each with role-specific JSON schemas, confidence, rationale, cited evidence, requested tools, and fallback status.
- Let Orchestrator LLM output modify audit scope, agent order, budgets, and high-priority focus areas after schema validation and policy checks.
- Let Recon LLM output choose safe next tools and context slices from repository metadata, memory retrieval, static observations, and CVE MCP intelligence.
- Let Analysis LLM output contribute candidate findings only when each candidate cites local source evidence and passes schema, scope, and evidence checks.
- Let Verification LLM output participate in accept/reject decisions, validation-level selection, and prioritization, while hard rules continue to reject intelligence-only, memory-only, unsafe, or out-of-scope findings.
- Add decision merger logic that records whether a final decision came from LLM, deterministic fallback, or a conflict-resolution path.
- Add replay and audit reporting for decision inputs, LLM outputs, policy gates, fallback reasons, and final merged decisions.
- Keep mock/offline tests deterministic and keep live LLM execution opt-in or explicitly configured.

## Capabilities

### New Capabilities
- `llm-agent-decision-contracts`: Defines schema-validated LLM decision contracts for each of the four agents and the rules for accepting, repairing, or rejecting model output.
- `guarded-agent-decision-loop`: Defines how LLM decisions affect planning, tool selection, candidate generation, verification, and fallback behavior inside the four-agent pipeline.
- `decision-auditability-and-replay`: Defines how decision inputs, outputs, policy checks, merge results, and final decisions are persisted, reported, and replayed.

### Modified Capabilities
- None.

## Impact

- Affected code: `audit_agent/agents.py`, `audit_agent/pipeline.py`, `audit_agent/llm.py`, `audit_agent/prompts.py`, `audit_agent/tool_protocol.py`, `audit_agent/message_bus.py`, reporting/evidence generation, and prompt templates.
- New models: role-specific LLM decision records, policy-gate results, decision merge records, and fallback metadata.
- New prompts/templates: Orchestrator plan decision, Recon tool/context decision, Analysis candidate decision, and Verification decision merge prompts.
- New tests: schema validation, malformed-output repair/fallback, policy denial, LLM-vs-deterministic conflict resolution, replay consistency, and opt-in live LLM decision smoke.
- External systems: existing OpenAI-compatible model API through `.env`; no new external dependency is required.
