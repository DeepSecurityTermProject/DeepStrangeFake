## Context

The system is an end-to-end security audit platform for open-source projects. It must accept a remote repository URL or local directory, analyze source structure and dependencies, coordinate LLM-powered agents with deterministic tools, validate candidate findings, generate exploit evidence where safe, and produce reproducible reports.

The design is inspired by DeepAudit's multi-agent audit model, but the first implementation should be a coursework/research-oriented reproducible audit pipeline rather than a full clone of DeepAudit's web platform. The useful DeepAudit pattern is the agent chain of Orchestrator, Recon, Analysis, and Verification, backed by code-analysis tools, optional RAG-style context retrieval, vulnerability intelligence, and sandboxed proof-of-concept validation.

The main innovation point is integrating `mukul975/cve-mcp-server` as a read-only CVE intelligence MCP tool layer inside the four-Agent architecture. The MCP layer can provide CVE lookup, CVSS/CWE context, EPSS scoring, CISA KEV checks, OSV/GitHub advisory intelligence, MITRE/CAPEC mapping, public proof-of-concept awareness, and composite risk scoring. It should enrich audit reasoning and prioritization, but it must not replace local code evidence or sandbox validation.

The key constraint is trustworthiness: LLM output alone is not enough. Every reported vulnerability must be tied to source locations, tool outputs, call paths, agent traces, validation steps, and reproducibility metadata. The system should support batch evaluation across at least 20 mainstream open-source projects while keeping validation actions sandboxed and auditable.

## Goals / Non-Goals

**Goals:**

- Build a modular CLI-first pipeline from repository intake to report generation.
- Combine deterministic code analysis and LLM agent reasoning instead of relying on model guesses.
- Support Orchestrator, Recon, Analysis, and Verification agents with explicit roles, inputs, outputs, handoff contracts, and tool permissions.
- Integrate `cve-mcp-server` as a bounded vulnerability intelligence tool layer available to agents through declared tool calls.
- Support attack-surface discovery for routes, controllers, API handlers, file upload handlers, command execution points, database access points, and authentication/authorization logic.
- Detect and validate SQL injection, command injection, path traversal, and hardcoded secrets in the initial version.
- Store structured evidence for every validated finding.
- Store agent execution traces for auditability, including reasoning summaries, tool calls, tool outputs, and handoff records.
- Generate proof-of-concept artifacts only in a controlled, local, non-destructive validation environment.
- Support repeatable benchmark runs across at least 20 open-source projects.

**Non-Goals:**

- The system will not attempt real-world exploitation against live third-party services.
- The initial version will not guarantee complete coverage of every CWE category.
- The initial version will not provide autonomous remediation patches or pull requests unless explicitly added in a later change.
- The initial version will not fine-tune or train an LLM.
- The initial version will not require a React/FastAPI/PostgreSQL web platform; those can be added later after the CLI pipeline is stable.

## Decisions

### Decision 1: Pipeline-Oriented Architecture

Use a staged pipeline with explicit artifacts:

1. Repository ingestion
2. Metadata extraction
3. Attack-surface discovery
4. CVE/dependency intelligence enrichment
5. Static scan and heuristic candidate generation
6. Recon agent review
7. Analysis agent review
8. Verification agent review
9. Sandboxed validation and exploit artifact generation
10. Evidence persistence
11. Report generation

This makes each step reproducible and independently testable. A single autonomous agent loop was considered, but it would make state, evidence, and failure modes harder to audit.

### Decision 2: Evidence-First Finding Model

Represent every finding as a structured object with:

- stable finding ID
- vulnerability class
- severity and confidence
- file path and line range
- affected function or entrypoint
- source-to-sink or call-path trace when available
- CVE/CWE/advisory intelligence references when available
- CVSS, EPSS, KEV, and public proof-of-concept context when available
- scanner evidence
- verifier decision
- agent trace references
- handoff references
- validation level
- validation command and environment
- exploit artifact path when generated
- reproduction status and timestamps

This allows reports, JSON exports, and benchmark metrics to share one source of truth. A report-only Markdown output was considered, but it would be difficult to validate or aggregate across 20 projects.

### Decision 3: DeepAudit-Style Agent Roles With Tool Boundaries

Use four primary roles:

- Orchestrator agent: plans audit scope, dispatches sub-agents, enforces budgets, and summarizes final results.
- Recon agent: extracts project structure, technology stack, dependencies, entry points, high-risk areas, and known dependency/advisory context from the CVE MCP layer when useful.
- Analysis agent: combines static-analysis outputs, code search, source slicing, dataflow hints, optional RAG context, CVE/CWE intelligence, and LLM reasoning to produce candidate findings.
- Verification agent: independently reviews each candidate, requests additional tool calls, rejects weak evidence, selects validation level, checks EPSS/KEV/public-PoC context when applicable, and decides whether sandbox validation is warranted.

Tools should be declared by capability. Repository, static-analysis, and vulnerability-intelligence tools are available to Recon and Analysis roles; risk-prioritization intelligence is also available to Verification; validation and sandbox tools are restricted to Verification steps. This reduces false positives and makes agent behavior easier to review. Multiple specialist agents per CWE can be added later, but they would add orchestration complexity before the base pipeline is stable.

### Decision 4: ReAct Loop With Structured Handoffs

Agents should use a bounded ReAct-style loop: reason, call a declared tool, observe the result, and either continue or hand off structured output. Each handoff includes completed work, key findings, evidence references, attention points, and suggested next actions. This is more auditable than a single long model response and mirrors the strongest parts of DeepAudit's agent design without requiring a full event-streaming UI in the first version.

### Decision 5: Tool and RAG Layers Are Optional but Pluggable

The MVP should run with local deterministic tools first: repository search, source slicing, Semgrep-style rules or scripts, Bandit for Python when available, Gitleaks or equivalent secret scanning, and dependency advisory scanners where available. RAG or vector search can be introduced as a pluggable context provider after the first CLI pipeline works. This keeps the project deliverable while leaving a clear path toward DeepAudit-like semantic retrieval.

### Decision 6: CVE Intelligence MCP Is a Shared Tool Layer, Not a Fifth Agent

`cve-mcp-server` should be integrated as a tool gateway that agents call through declared tool adapters. It is not an autonomous agent and should not directly promote findings. Its role is to enrich:

- Recon: dependency/package/product intelligence through OSV, GitHub advisories, NVD, and related sources.
- Analysis: CWE/CAPEC/MITRE context and known CVE pattern grounding for candidate reasoning.
- Verification: CVSS, EPSS, CISA KEV, public proof-of-concept availability, references, and composite risk scoring for prioritization.
- Reporting: CVE IDs, CWE IDs, advisory links, KEV/EPSS status, and risk rationale for final explanation.

All CVE MCP calls must be bounded by timeout, query budget, cache policy, and outbound-network configuration. API keys are optional for the baseline, but configured keys may improve rate limits and coverage. Intelligence results are hints and risk context; local code evidence and validation remain required for confirmed findings.

### Decision 7: Sandboxed Validation by Default

Validation and generated proof-of-concept artifacts must run in an isolated workspace using local test fixtures, temporary services, containers, or process-level sandboxing depending on target language. Validation must not send attack traffic to public deployments. If a target cannot be safely run locally, the system records the finding as manually reproducible rather than executing an exploit.

Validation levels:

- `static-only`: enough static evidence exists, but no runtime execution is attempted.
- `poc-generate`: a non-destructive proof-of-concept is generated but not executed.
- `sandbox`: proof-of-concept is executed in a configured local sandbox.
- `manual`: the system emits human reproduction steps because safe automation is unavailable.

### Decision 8: Benchmark Corpus as Configuration

Store benchmark targets in a configuration file containing project name, source URL or local path, version/ref, expected language family, setup notes, and safety constraints. This makes the 20-project requirement explicit and repeatable. The default corpus can include OpenVPN, MacCMS v10, and additional mainstream projects selected for language diversity and legal accessibility.

## Risks / Trade-offs

- False positives remain possible -> Require verifier approval and validation evidence before labeling a finding as validated.
- LLM cost and latency may be high -> Cache repository metadata, tool outputs, and agent prompts/results by target commit.
- Validation may be unsafe or flaky -> Run only in local sandboxes, record exact commands, and support no-exploit validation levels.
- ReAct loops can drift or waste budget -> Enforce max iterations, max tool calls, and structured handoff requirements per agent.
- CVE intelligence can be stale or unavailable -> Cache raw outputs, record timestamps, support degraded mode, and require local evidence before confirming vulnerabilities.
- External intelligence APIs can leak sensitive target metadata -> Make CVE MCP usage configurable, avoid sending proprietary source code, and only query package/product/CVE/CWE identifiers unless explicitly allowed.
- RAG can introduce stale or irrelevant context -> Treat retrieved context as hints and require source-level evidence before reporting a finding.
- Some projects may be difficult to build -> Separate source-level validation from runtime validation and report setup failures explicitly.
- SAST tools vary by language -> Use a pluggable tool adapter interface and begin with language-agnostic heuristics plus common tools.
- Generated proof-of-concept artifacts can be sensitive -> Store them locally, mark them clearly as controlled validation material, and exclude destructive payloads.

## Migration Plan

1. Create the base project skeleton and configuration model.
2. Implement repository ingestion and metadata extraction.
3. Add attack-surface discovery, CVE MCP intelligence adapter, static-analysis adapters, and candidate finding schema.
4. Add Orchestrator, Recon, Analysis, and Verification agent orchestration.
5. Add structured handoff records, agent traces, and bounded ReAct tool loops.
6. Add CVE/CWE/advisory enrichment into Recon, Analysis, Verification, and Reporting.
7. Add sandboxed validation and proof-of-concept artifact generation.
8. Add evidence persistence and report generation.
9. Add benchmark corpus configuration and batch runner.
10. Validate the workflow on a small local fixture before expanding to 20 projects.

Rollback is straightforward during development: each pipeline stage writes versioned intermediate artifacts under a run directory, so failed stages can be deleted without modifying source targets.

## Open Questions

- Which LLM provider and model should be the default for coursework runs, and should a local Ollama-compatible model be a first-class path?
- Should CVE MCP usage be enabled by default in offline/degraded mode, or require explicit configuration because it may call external intelligence APIs?
- Which SAST tools are guaranteed to be available in the target environment, and which should be optional adapters?
- Should the first implementation prioritize Python/JavaScript/PHP projects, or start with a language-neutral metadata and evidence layer?
- How much proof-of-concept code should be included in the final report versus stored as separate evidence artifacts?
