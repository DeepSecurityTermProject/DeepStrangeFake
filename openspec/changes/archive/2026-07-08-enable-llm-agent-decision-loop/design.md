## Context

The current runtime has the required substrate for real agentic decisions: an `LLMClient`, versioned prompt templates, a real MCP client, lexical memory, a message bus, redacted artifacts, and integration preflight. A live LLM smoke test now passes with `.env` values including `LLM_MODEL=deepseek-v4-pro`, proving that the model API can be reached.

However, the four agents still make most decisions through deterministic Python code. LLM responses are rendered, validated, persisted, and sometimes parsed into candidates, but they do not consistently control Orchestrator planning, Recon tool selection, Analysis candidate ranking, or Verification accept/reject outcomes. This change introduces guarded LLM decision participation without removing the evidence-first deterministic safety model.

## Goals / Non-Goals

**Goals:**
- Promote schema-valid LLM outputs into decision inputs for Orchestrator, Recon, Analysis, and Verification.
- Add role-specific decision contracts that distinguish model proposals from final merged decisions.
- Add policy gates that enforce local evidence, tool permissions, budgets, validation levels, and no-live-target rules.
- Add deterministic fallback for missing, malformed, unsafe, or low-confidence LLM outputs.
- Preserve run replayability through decision artifacts, message bus events, prompt refs, LLM response refs, and merge records.
- Keep mock/offline tests deterministic and keep live LLM tests explicitly opt-in.

**Non-Goals:**
- Do not let LLM output bypass local code/dependency evidence.
- Do not let LLM call arbitrary tools directly.
- Do not introduce a new external agent framework.
- Do not enable autonomous exploitation, patch generation, live target probing, or unrestricted PoC search.
- Do not remove the deterministic PatternScanner, validation, evidence-chain, or report paths.

## Decisions

### Decision 1: Add Decision Records Instead of Replacing Existing Agent Outputs

Create explicit records such as `LLMAgentDecision`, `DecisionPolicyGate`, and `MergedAgentDecision`. Each LLM decision stores role, prompt ref, LLM response ref, parsed JSON, confidence, rationale, evidence refs, requested tools, selected actions, schema status, policy status, and fallback reason.

The existing `AgentTrace`, `AgentHandoff`, `Finding`, and `VerificationDecision` objects stay intact. The new decision records are linked into them so current reports and tests can evolve incrementally.

Alternative considered: write LLM choices directly into existing agent objects. That is simpler but makes it hard to explain whether a result came from the model, deterministic fallback, or policy conflict resolution.

### Decision 2: Treat LLM Output as a Proposal, Then Merge

The pipeline will use a two-step pattern:

1. Render a role prompt and obtain a schema-validated LLM proposal.
2. Merge the proposal with deterministic evidence and policy gates to produce the final decision.

The final decision includes `decision_source` values such as `llm`, `deterministic`, `merged`, `fallback`, or `policy-denied`. This allows the system to be more agentic without losing traceability.

Alternative considered: let the LLM directly overwrite deterministic decisions. That would be closer to an autonomous agent, but it is too risky for a security audit system where false positives and unverifiable claims matter.

### Decision 3: Use Role-Specific Schemas

Each agent gets a decision schema:

- Orchestrator: audit scope changes, agent order, budgets, focus areas, tool groups, and rationale.
- Recon: context slices, memory queries, MCP queries, safe tool requests, and attack-surface priorities.
- Analysis: candidate findings, local evidence citations, confidence, vulnerability class, call path, and tool refs.
- Verification: accept/reject, confidence, validation level, priority, reason, required evidence, and remediation confidence.

Schemas should be stored with prompt templates and loaded through the existing prompt registry. Invalid output is repaired once when configured; otherwise the agent falls back to deterministic behavior.

Alternative considered: one generic schema for all agents. That would reduce implementation work but weakens tests and makes role-level safety harder to enforce.

### Decision 4: Policy Gates Are Deterministic and Centralized

Add a central decision policy layer. It checks:

- every accepted finding has local evidence or local dependency evidence;
- memory and CVE intelligence are contextual only;
- requested tools are registered, allowed for the role, and within budget;
- validation level does not exceed configured safety permissions;
- requested live actions comply with sandbox and no-live-target settings;
- LLM confidence and schema completeness meet role thresholds.

Denied proposals are persisted as policy-gate results and routed back into traces/reports.

Alternative considered: encode all safety rules in prompts. Prompts are still useful, but deterministic gates are required because model compliance is not a security boundary.

### Decision 5: Recon Uses LLM Tool Planning, Tool Protocol Executes

Recon may use the LLM to choose next tool requests, such as repository context slices, pattern scanner passes, memory queries, or safe CVE MCP lookups. The LLM emits structured tool requests, but `tool_protocol` validates permissions and dispatches the actual calls.

This creates a bounded ReAct-style loop without letting the model call Python functions directly.

Alternative considered: keep Recon fully deterministic. That is stable, but it leaves the model unable to adapt audit focus based on project shape and external intelligence.

### Decision 6: Verification Has the Strongest Override Rules

Verification can use LLM output to explain, rank, and choose validation levels, but deterministic rules can override it. The system must reject LLM acceptance when local evidence is absent, source locations are missing, validation level is unsafe, or citations do not resolve.

Alternative considered: use LLM as the primary verifier. That would improve flexibility, but it risks hallucinated acceptance and unreproducible results.

### Decision 7: Live LLM Decision Smoke Is Narrow

Add an opt-in live smoke that uses the configured real model on a small local fixture. It should prove that role prompts, schemas, parsing, policy gates, decision merge, and artifacts work. It should not run the full 20-project benchmark or execute costly deep audits.

Alternative considered: require live LLM for all integration tests. That would be expensive and flaky, especially under rate limits or classroom environments.

## Risks / Trade-offs

- [Risk] LLM output may be malformed or inconsistent. -> Validate schemas, allow one repair attempt, and fall back deterministically.
- [Risk] LLM may overstate findings. -> Enforce local evidence gates and require citation resolution before candidate promotion.
- [Risk] LLM may request unsafe tools. -> Route all tool calls through `tool_protocol` permissions, budgets, and safety classifications.
- [Risk] Decisions become hard to reproduce. -> Persist prompt refs, LLM refs, policy-gate records, merge records, and message events.
- [Risk] Cost increases when all roles call the model. -> Add per-role toggles, token budgets, and mock-mode tests.
- [Risk] Decision conflicts confuse users. -> Report final decision source and conflict resolution reason.
- [Risk] Integration tests become slow or flaky. -> Keep live decision smoke opt-in and keep default tests offline.

## Migration Plan

1. Add decision record models and persistence helpers.
2. Add role-specific prompt schemas and tests for schema validation.
3. Add decision policy gates and tests for missing evidence, unsafe tools, out-of-scope classes, and unsafe validation levels.
4. Add Orchestrator LLM plan merge into audit scope, budgets, focus areas, and agent order.
5. Add Recon LLM tool/context planning through the existing tool protocol.
6. Add Analysis LLM candidate merge with evidence citation checks.
7. Add Verification LLM decision merge with deterministic override rules.
8. Add message bus events and report sections for decision sources, policy gates, and fallback reasons.
9. Add mock-mode decision-loop tests plus one opt-in live LLM decision smoke using the configured `LLM_MODEL`.
10. Run full unit tests and OpenSpec strict validation.

Rollback is simple: disable LLM decision participation and continue using the current deterministic agent outputs while still recording LLM artifacts if desired.

## Open Questions

- Should LLM decision participation be enabled by `--runtime` automatically, or require a separate flag such as `--llm-decisions`?
- Should role-level LLM participation be configurable independently, for example Orchestrator-only or Verification-only?
- What minimum confidence threshold should the first implementation use before a model proposal can influence the merged decision?
