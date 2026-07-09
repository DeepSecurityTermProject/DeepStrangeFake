## ADDED Requirements

### Requirement: Unified tool declaration
The system SHALL represent every callable tool with a declaration containing tool name, description, JSON input schema, output kind, permission group, timeout, and safety classification.

#### Scenario: Tool registry lists local and external tools
- **WHEN** the runtime initializes tools for an audit
- **THEN** the tool registry SHALL expose declarations for repository search, source slicing, pattern scanning, optional external scanners, MCP tools, memory retrieval, and validation tools that are enabled by configuration

### Requirement: Structured tool-call lifecycle
The system SHALL process tool calls through request, permission check, budget check, execution, result normalization, artifact persistence, and observation return.

#### Scenario: Successful source slicing tool call
- **WHEN** an agent requests a permitted source-slicing tool call
- **THEN** the runtime SHALL return a normalized tool result with source path, line range, snippet, duration, and artifact reference

### Requirement: Permission enforcement
The system MUST enforce per-agent tool permissions before executing a tool call.

#### Scenario: Analysis attempts sandbox validation
- **WHEN** the Analysis agent requests a sandbox validation tool that is restricted to Verification
- **THEN** the runtime SHALL deny the call, record a denied tool result, and SHALL NOT execute the validation command

### Requirement: Tool budget enforcement
The system SHALL enforce per-agent and per-run tool-call budgets.

#### Scenario: Tool budget exhausted
- **WHEN** an agent reaches its configured tool-call budget
- **THEN** subsequent tool requests SHALL return a budget-exhausted result and be recorded in the agent trace

### Requirement: Tool result evidence linkage
The system SHALL link tool results to candidate findings, verification decisions, evidence chains, and reports when used as evidence.

#### Scenario: Scanner observation becomes finding evidence
- **WHEN** a pattern scanner observation is converted into a candidate finding
- **THEN** the finding SHALL reference the tool result ID and the evidence chain SHALL include the raw and normalized tool output artifacts

