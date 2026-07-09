## ADDED Requirements

### Requirement: Structured audit reports are generated
The system SHALL generate a structured audit report for each completed audit run.

#### Scenario: Audit run completes
- **WHEN** repository analysis, audit, validation, and evidence persistence finish
- **THEN** the system creates a report containing target metadata, executive summary, vulnerability list, severity, evidence chain, validation status, and remediation advice

### Requirement: Reports include severity and confidence
The system SHALL assign severity and confidence values to each reported vulnerability.

#### Scenario: Validated vulnerability is reported
- **WHEN** a vulnerability appears in the final report
- **THEN** the report includes severity, confidence, vulnerability class, affected component, and validation status

### Requirement: Reports include CVE intelligence context when available
The system SHALL include CVE MCP intelligence context in reports when it was used during audit or validation.

#### Scenario: Finding is enriched by CVE MCP
- **WHEN** a finding has CVE MCP enrichment artifacts
- **THEN** the report includes relevant CVE IDs, CWE IDs, CVSS score or vector when available, EPSS score when available, CISA KEV status when available, public proof-of-concept availability when available, advisory references, and intelligence retrieval timestamp

### Requirement: Reports include remediation guidance
The system SHALL provide remediation advice for each validated vulnerability.

#### Scenario: SQL injection is reported
- **WHEN** the report includes a SQL injection finding
- **THEN** the finding includes remediation guidance such as parameterized queries, input validation, and safe ORM usage where applicable

### Requirement: Machine-readable outputs are available
The system SHALL support machine-readable report exports for downstream analysis.

#### Scenario: JSON export is requested
- **WHEN** the user requests machine-readable output
- **THEN** the system writes JSON containing target metadata, findings, evidence references, vulnerability-intelligence references, and run status

### Requirement: Benchmark runs cover at least 20 projects
The system SHALL support benchmark execution across no fewer than 20 configured mainstream open-source projects.

#### Scenario: Benchmark corpus is configured
- **WHEN** the benchmark runner starts
- **THEN** the system loads at least 20 target definitions including project name, source reference, version or commit, language family, and setup notes

#### Scenario: Benchmark run completes
- **WHEN** all configured targets finish or fail with recorded errors
- **THEN** the system generates a benchmark summary with per-project status, finding counts, validated vulnerability counts, false-positive filtering statistics where available, and failure reasons

### Requirement: Reports include agent and validation traceability
The system SHALL include enough traceability for readers to understand how each reported vulnerability was found and validated.

#### Scenario: Validated vulnerability is reported
- **WHEN** a vulnerability appears in the final report
- **THEN** the report includes the producing agent role, verifier decision, validation level, key tool outputs, and evidence artifact references

### Requirement: Benchmark reports include evaluation metrics
The system SHALL summarize benchmark effectiveness and reproducibility metrics.

#### Scenario: Benchmark summary is generated
- **WHEN** a benchmark run completes
- **THEN** the summary includes configured target count, completed target count, failed target count, candidates generated, candidates rejected, validated findings, validation-level distribution, and report artifact paths
