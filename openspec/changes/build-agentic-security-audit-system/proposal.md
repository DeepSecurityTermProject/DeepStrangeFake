## Why

LLM-based agents can already assist code security review, but direct model-only auditing still suffers from high false positives, weak evidence chains, and poor reproducibility. This change introduces an end-to-end, evidence-first security audit and validation system for open-source projects, inspired by systems such as DeepAudit while emphasizing deterministic tooling, independent verification, and repeatable experiment outputs.

## What Changes

- Add a repository ingestion flow that accepts GitHub/GitLab URLs or local paths, identifies project languages, and extracts file structure and dependency metadata.
- Add a DeepAudit-inspired multi-agent audit workflow with Orchestrator, Recon, Analysis, and Verification roles.
- Give agents tool-calling ability for SAST tools, repository analysis scripts, dependency inspection, and controlled validation steps.
- Integrate `mukul975/cve-mcp-server` as a CVE intelligence MCP tool layer for CVE/CWE enrichment, EPSS scoring, CISA KEV checks, OSV/GHSA dependency intelligence, public PoC awareness, and risk prioritization.
- Detect an initial vulnerability set covering SQL injection, command injection, path traversal, and hardcoded secrets.
- Add an automated vulnerability validation and exploit-generation flow that produces proof-of-concept evidence for validated findings.
- Produce structured evidence chains containing source locations, call paths, tool outputs, validation results, and reproducibility metadata.
- Persist agent execution traces so each finding can be linked back to agent reasoning, handoffs, tool calls, and verification decisions.
- Generate audit reports with vulnerability lists, severity, evidence, and remediation advice.
- Add a benchmark workflow for evaluating at least 20 mainstream open-source projects, including targets such as OpenVPN and MacCMS v10 where legally and practically usable.

## Capabilities

### New Capabilities

- `repository-analysis`: Accept target repositories or local directories, detect languages, extract file/dependency metadata, and identify likely attack surfaces.
- `vulnerability-intelligence`: Enrich audit context and findings through `cve-mcp-server` vulnerability intelligence, risk scoring, dependency advisory checks, and CVE/CWE knowledge.
- `agentic-audit`: Coordinate DeepAudit-style LLM agents, ReAct tool loops, and structured agent handoffs to identify candidate security defects.
- `vulnerability-validation`: Independently review, reproduce, and validate candidate vulnerabilities through explicit validation levels while filtering false positives.
- `evidence-chain`: Persist traceable evidence for each finding, including source location, call path, agent trace, validation logs, and exploit artifacts.
- `audit-reporting`: Generate structured audit reports and benchmark summaries for single targets and multi-project evaluation runs.

### Modified Capabilities

- None.

## Impact

- Introduces a new security-audit application architecture and OpenSpec-backed development plan.
- Adds integrations for repository cloning/parsing, language detection, attack-surface extraction, SAST execution, LLM agent orchestration, sandboxed validation, and report generation.
- Adds an MCP-based vulnerability intelligence layer using `mukul975/cve-mcp-server`; API keys are optional for the baseline but can improve NVD/GitHub/threat-intelligence coverage and rate limits.
- Requires configuration for LLM providers, tool permissions, target repository sources, and safe execution constraints.
- Creates project data directories for target metadata, intermediate findings, evidence artifacts, generated exploits, and final reports.
- Establishes a benchmark corpus requirement of at least 20 mainstream open-source projects for evaluation.
