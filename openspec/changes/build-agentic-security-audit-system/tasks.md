## 1. Project Foundation

- [x] 1.1 Select the CLI-first implementation stack and create the base project structure for CLI, core pipeline, agents, tools, evidence storage, reporting, benchmark configuration, and tests.
- [x] 1.2 Define configuration files for LLM provider settings, optional local-model settings, CVE MCP server settings, tool permissions, benchmark targets, validation levels, sandbox options, and output directories.
- [x] 1.3 Define shared data models for audit targets, repository metadata, attack surfaces, vulnerability-intelligence records, agent traces, agent handoffs, candidate findings, validated findings, evidence artifacts, run metadata, benchmark results, and reports.
- [x] 1.4 Add a run directory layout that stores immutable per-run metadata, logs, tool outputs, vulnerability-intelligence outputs, agent traces, handoffs, findings, evidence, proof-of-concept artifacts, and reports.
- [x] 1.5 Add baseline tests for configuration loading, model serialization, run directory creation, and immutable artifact naming.

## 2. Repository Analysis and Attack-Surface Discovery

- [x] 2.1 Implement target intake for GitHub URLs, GitLab URLs, and local directory paths.
- [x] 2.2 Implement remote checkout with resolved commit recording and local-path intake with VCS metadata detection.
- [x] 2.3 Implement language detection with dominant and secondary language reporting.
- [x] 2.4 Implement normalized file tree extraction with ignore rules for generated caches, dependency folders, and configured exclusions.
- [x] 2.5 Implement dependency manifest discovery and metadata extraction for common ecosystems.
- [x] 2.6 Normalize dependency and product identifiers for OSV, GitHub advisory, NVD keyword, and CVE MCP intelligence lookup.
- [x] 2.7 Implement attack-surface discovery for routes, controllers, API handlers, file upload handlers, command execution points, database access points, authentication logic, and authorization checks.
- [x] 2.8 Add tests for remote target metadata parsing, local target parsing, language detection, file tree filtering, dependency manifest extraction, intelligence identifier normalization, and attack-surface extraction.

## 3. Tool Layer and Optional Context Retrieval

- [x] 3.1 Define a tool adapter interface that records tool name, inputs, outputs, exit status, duration, artifact paths, and normalized observations.
- [x] 3.2 Implement repository search, file reading, source slicing, and function-context tools for agent context collection.
- [x] 3.3 Implement initial SAST adapters or scripted detectors for SQL injection, command injection, path traversal, and hardcoded secrets.
- [x] 3.4 Add optional adapters for Semgrep-style scans, Bandit, Gitleaks-compatible secret scanning, and dependency advisory scanning when tools are available.
- [x] 3.5 Implement a CVE MCP tool adapter for `mukul975/cve-mcp-server` with configurable command or endpoint, environment variables, timeout, cache policy, query budget, and degraded mode.
- [x] 3.6 Normalize CVE MCP outputs for CVE lookup, CVSS, EPSS, CISA KEV, OSV/GHSA advisory checks, CWE/CAPEC/MITRE context, public proof-of-concept availability, and composite risk scoring.
- [x] 3.7 Implement a pluggable context retrieval interface so RAG/vector search can be added without changing agent contracts.
- [x] 3.8 Add tool execution logging, timeout handling, and failure handling so failed tools do not crash the full audit run.
- [x] 3.9 Add tests for adapter output normalization, unavailable-tool behavior, timeout handling, CVE MCP degraded mode, intelligence output normalization, and context retrieval fallback.

## 4. DeepAudit-Style Agent Workflow

- [x] 4.1 Implement the bounded ReAct loop primitive with max iterations, max tool calls, stop reasons, reasoning summaries, action records, and observations.
- [x] 4.2 Implement Orchestrator agent orchestration for audit planning, agent dispatch, scope enforcement, budget enforcement, and final summary generation.
- [x] 4.3 Implement Recon agent orchestration that consumes repository metadata, attack surfaces, and CVE MCP dependency/advisory hints, then emits technology stack, entry points, high-risk areas, dependency concerns, and analysis priorities.
- [x] 4.4 Implement Analysis agent orchestration that consumes Recon handoffs, selected source context, static-analysis outputs, optional retrieved context, CVE/CWE intelligence, and tool outputs.
- [x] 4.5 Implement candidate finding generation using the shared finding schema.
- [x] 4.6 Include vulnerability-intelligence hints and references in structured handoff records from Recon to Analysis and from Analysis to Verification.
- [x] 4.7 Persist agent prompts, selected context references, model metadata, raw model responses, ReAct step records, CVE MCP tool calls, and handoff records for auditability.
- [x] 4.8 Implement configurable audit scope for vulnerability classes, include/exclude patterns, analysis budget, tool budget, CVE intelligence query budget, and validation level.
- [x] 4.9 Add tests using mocked LLM and mocked CVE MCP responses to verify Orchestrator dispatch, Recon handoff, Analysis candidate parsing, intelligence usage, ReAct limits, and scope enforcement.

## 5. Verification and Validation

- [x] 5.1 Implement Verification agent orchestration that independently reviews Analysis candidates and records accept, reject, downgrade, or needs-validation decisions.
- [x] 5.2 Implement verifier rejection reasons and confidence downgrades for weak or incomplete evidence.
- [x] 5.3 Use CVE MCP intelligence for validation prioritization when candidates map to CVEs, CWEs, dependencies, advisories, EPSS, KEV, or public proof-of-concept context.
- [x] 5.4 Ensure intelligence-only matches cannot promote a finding without local code or dependency evidence.
- [x] 5.5 Implement explicit validation levels: `static-only`, `poc-generate`, `sandbox`, and `manual`.
- [x] 5.6 Implement sandboxed validation execution for local fixtures, temporary workspaces, containers, or configured safe commands.
- [x] 5.7 Implement non-destructive proof-of-concept artifact generation for safely reproducible vulnerabilities.
- [x] 5.8 Implement manual-reproduction fallback when safe automated validation is unavailable.
- [x] 5.9 Enforce no-live-target validation so proof-of-concept execution never attacks public third-party deployments.
- [x] 5.10 Add tests for verifier filtering, intelligence-based prioritization, validation-level assignment, validation metadata capture, safe proof-of-concept gating, and no-live-target enforcement.

## 6. Evidence Chain and Traceability

- [x] 6.1 Implement evidence chain persistence for source locations, vulnerability class, Analysis rationale, CVE/CWE/advisory intelligence references, Verification decision, validation level, validation results, and artifact references.
- [x] 6.2 Implement precise file path and line range recording for findings and supporting snippets.
- [x] 6.3 Implement call-path or source-to-sink trace storage when available from tools or agent reasoning.
- [x] 6.4 Link SAST warnings, raw tool outputs, normalized summaries, and dependency evidence to candidate and validated findings.
- [x] 6.5 Link CVE MCP outputs to findings with tool name, query input, output artifact reference, retrieval timestamp, cache hit status, and contextual-vs-validation-evidence marker.
- [x] 6.6 Link findings to agent trace IDs, ReAct step records, and structured handoff records.
- [x] 6.7 Enforce immutable evidence artifacts for completed runs and support report regeneration from existing evidence.
- [x] 6.8 Add tests for evidence serialization, artifact linking, intelligence-output linking, agent-trace linking, validation-level reporting, and report regeneration without mutation.

## 7. Reporting

- [x] 7.1 Implement structured report generation with target metadata, executive summary, vulnerability list, severity, confidence, evidence chain, validation status, validation level, vulnerability-intelligence context, and remediation advice.
- [x] 7.2 Include agent traceability in each finding: producing agent, verifier decision, key tool outputs, and evidence artifact references.
- [x] 7.3 Implement vulnerability-specific remediation guidance for SQL injection, command injection, path traversal, and hardcoded secrets.
- [x] 7.4 Include CVE IDs, CWE IDs, CVSS, EPSS, CISA KEV status, public proof-of-concept availability, advisory references, and risk-score context in reports when CVE MCP enrichment is available.
- [x] 7.5 Implement JSON export for target metadata, findings, evidence references, vulnerability-intelligence references, agent trace references, and run status.
- [x] 7.6 Add optional human-readable Markdown or HTML report output.
- [x] 7.7 Add tests for report content completeness, intelligence context, traceability content, and machine-readable schema stability.

## 8. Benchmark Evaluation

- [x] 8.1 Create benchmark target configuration with at least 20 mainstream open-source projects, including OpenVPN and MacCMS v10 where legally and practically usable.
- [x] 8.2 Implement a batch runner that executes repository analysis, attack-surface discovery, agent audit, validation, and reporting for each configured target.
- [x] 8.3 Record per-project setup status, CVE MCP availability, intelligence query counts, failures, candidate counts, rejected counts, validated vulnerability counts, validation-level distribution, and filtering statistics.
- [x] 8.4 Generate a benchmark summary report across all configured targets.
- [x] 8.5 Add a small fixture benchmark for automated tests without downloading large external repositories.
- [x] 8.6 Add tests for benchmark target loading, CVE MCP degraded mode, partial failure handling, metric aggregation, and summary generation.

## 9. Documentation and Safety Review

- [x] 9.1 Document setup, configuration, LLM provider requirements, local-model option, CVE MCP server setup, optional API keys, tool permissions, validation levels, and safe validation constraints.
- [x] 9.2 Document the expected workflow for single-target audits and 20-project benchmark runs.
- [x] 9.3 Document agent roles, ReAct loop behavior, CVE MCP intelligence usage, handoff records, evidence artifact structure, and report interpretation.
- [x] 9.4 Add a safety note that proof-of-concept artifacts are for local controlled validation only and must not be used against unauthorized live systems.
- [x] 9.5 Run the full validation suite and OpenSpec validation before implementation is considered complete.
