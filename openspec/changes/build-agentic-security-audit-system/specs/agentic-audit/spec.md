## ADDED Requirements

### Requirement: Orchestrator agent plans and controls the audit
The system SHALL provide an Orchestrator agent that plans audit scope, dispatches sub-agents, enforces budgets, and summarizes final results.

#### Scenario: Audit task starts
- **WHEN** a target audit run is created
- **THEN** the Orchestrator agent selects enabled vulnerability classes, dispatches Recon and Analysis work, and records the audit plan

#### Scenario: Agent budget is exhausted
- **WHEN** an agent reaches its configured iteration, tool-call, or token budget
- **THEN** the Orchestrator records the budget stop reason and continues with available evidence instead of allowing an unbounded loop

### Requirement: Recon agent identifies project context and attack surface
The system SHALL provide a Recon agent that reviews repository metadata, dependencies, file structure, and attack-surface records.

#### Scenario: Recon run completes
- **WHEN** repository analysis has produced metadata and attack-surface records
- **THEN** the Recon agent outputs technology stack, entry points, high-risk areas, dependency concerns, and recommended analysis priorities

### Requirement: Analysis agent identifies candidate vulnerabilities
The system SHALL provide an Analysis agent that reviews repository metadata, attack-surface records, source snippets, optional RAG context, and tool outputs to identify candidate security defects.

#### Scenario: Analysis reviews static-analysis output
- **WHEN** static-analysis tools produce warnings for a target project
- **THEN** the Analysis agent converts relevant warnings into candidate findings with vulnerability class, location, rationale, and confidence

#### Scenario: Analysis reviews source context
- **WHEN** source files contain suspicious input-to-sink patterns
- **THEN** the Analysis agent records candidate findings for supported classes including SQL injection, command injection, path traversal, and hardcoded secrets

### Requirement: Agents use bounded ReAct tool loops
The system SHALL execute agent reasoning through bounded reason-action-observation loops with declared tools only.

#### Scenario: Agent performs a tool step
- **WHEN** an agent decides to inspect code, run a static-analysis tool, retrieve context, or prepare validation
- **THEN** the system records the reasoning summary, declared tool call, tool input, observation, and next action decision

#### Scenario: Agent loop reaches limit
- **WHEN** the configured ReAct iteration limit is reached
- **THEN** the agent emits a structured partial result and stop reason

### Requirement: Agents use declared tools
The system SHALL expose code analysis, search, SAST, dependency inspection, CVE intelligence, and validation-preparation tools through explicit tool definitions.

#### Scenario: Agent invokes a tool
- **WHEN** an agent requests code search, static analysis, dependency inspection, or source slicing
- **THEN** the system records the tool name, inputs, outputs, exit status, and timestamp in the run log

#### Scenario: Agent invokes CVE intelligence
- **WHEN** an agent requests CVE, CWE, CVSS, EPSS, KEV, OSV, GitHub advisory, MITRE, CAPEC, public proof-of-concept, or risk-scoring intelligence
- **THEN** the system routes the request through the declared CVE MCP tool adapter and records the normalized output reference in the agent trace

### Requirement: Candidate findings use a structured schema
The system SHALL store Analysis agent output as structured candidate findings rather than free-form prose only.

#### Scenario: Candidate finding is created
- **WHEN** the Analysis agent reports a potential vulnerability
- **THEN** the finding includes vulnerability type, severity estimate, confidence estimate, file path, line range when available, affected symbol when available, and supporting rationale

### Requirement: Agent handoffs are structured
The system SHALL exchange information between agents through structured handoff records.

#### Scenario: Recon hands off to Analysis
- **WHEN** the Recon agent completes its work
- **THEN** the handoff includes completed work, key findings, priority areas, entry points, high-risk files, vulnerability-intelligence hints, evidence references, and suggested next actions

#### Scenario: Analysis hands off to Verification
- **WHEN** the Analysis agent emits candidate findings
- **THEN** the handoff includes candidate IDs, supporting evidence references, relevant CVE/CWE/advisory context, confidence rationale, and requested validation level when known

### Requirement: Agent prompts are auditable
The system SHALL persist the material prompts, selected context, and model responses needed to audit agent decisions.

#### Scenario: Agent run completes
- **WHEN** an agent finishes reviewing a target or candidate
- **THEN** the system stores the agent role, prompt template identifier, selected context references, model identifier, response artifact, and handoff record for the run

### Requirement: Audit scope is configurable
The system SHALL allow users to configure vulnerability classes, file include/exclude patterns, and maximum analysis budget for a run.

#### Scenario: User limits vulnerability classes
- **WHEN** the user enables only command injection and path traversal checks
- **THEN** the Orchestrator, Analysis agent, and static-analysis stage focus on those classes and report the active scope in run metadata
