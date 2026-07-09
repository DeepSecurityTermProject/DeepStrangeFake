## ADDED Requirements

### Requirement: Findings include traceable evidence chains
The system SHALL maintain an evidence chain for every validated vulnerability.

#### Scenario: Vulnerability is validated
- **WHEN** a candidate finding is promoted to validated vulnerability
- **THEN** the evidence chain includes source location, vulnerability class, reasoning summary, verifier decision, validation result, and artifact references

### Requirement: Agent execution traces are linked to findings
The system SHALL link findings to the agent trace records that produced, reviewed, or validated them.

#### Scenario: Finding is produced by Analysis agent
- **WHEN** an Analysis agent creates a candidate finding
- **THEN** the evidence chain stores the agent role, trace ID, reasoning summary reference, tool-call references, and handoff reference

#### Scenario: Finding is reviewed by Verification agent
- **WHEN** a Verification agent accepts, rejects, or downgrades a candidate
- **THEN** the evidence chain stores the verifier trace ID, decision, decision rationale, and validation level

### Requirement: Source locations are precise
The system SHALL record precise file paths and line ranges for vulnerability evidence whenever source locations are available.

#### Scenario: Source line is known
- **WHEN** a tool or agent identifies the vulnerable source line
- **THEN** the evidence chain stores repository-relative file path and start line, and stores end line when available

### Requirement: Call paths are recorded when available
The system SHALL record source-to-sink or call-path traces when static analysis or agent reasoning can identify them.

#### Scenario: Source-to-sink path is found
- **WHEN** the system identifies an input source flowing into a sensitive sink
- **THEN** the evidence chain stores the ordered path with function, file, and line information where available

### Requirement: Tool outputs are linked to evidence
The system SHALL link relevant tool outputs to each finding.

#### Scenario: SAST warning supports a finding
- **WHEN** a SAST tool warning contributes to a candidate or validated finding
- **THEN** the evidence chain stores the tool name, rule ID when available, raw output reference, and normalized summary

### Requirement: Vulnerability intelligence outputs are linked to evidence
The system SHALL link relevant CVE MCP intelligence outputs to each finding when they influence prioritization, severity, or report context.

#### Scenario: CVE intelligence supports prioritization
- **WHEN** CVE MCP output contributes CVSS, EPSS, KEV, advisory, CWE, CAPEC, MITRE, public proof-of-concept, or risk-score context
- **THEN** the evidence chain stores the MCP tool name, query input, output artifact reference, retrieval timestamp, and normalized summary

#### Scenario: Intelligence is contextual only
- **WHEN** CVE MCP output is used as contextual hint rather than local validation evidence
- **THEN** the evidence chain marks the intelligence as contextual and keeps it separate from source-code validation evidence

### Requirement: Evidence artifacts are immutable within a run
The system SHALL preserve evidence artifacts for a completed run without in-place mutation.

#### Scenario: Report is regenerated
- **WHEN** a user regenerates a report from an existing run
- **THEN** the system reads existing evidence artifacts and does not overwrite validation logs or exploit artifacts for that run
