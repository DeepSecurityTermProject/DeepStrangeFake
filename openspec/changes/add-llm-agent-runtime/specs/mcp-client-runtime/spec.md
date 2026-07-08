## ADDED Requirements

### Requirement: MCP client session
The system SHALL provide an MCP client that can start, initialize, use, and close an MCP server session over stdio transport.

#### Scenario: MCP server initializes successfully
- **WHEN** the configured MCP command starts and responds to initialization
- **THEN** the MCP client SHALL record session metadata, server capabilities, and initialization status in run artifacts

### Requirement: MCP tool discovery
The system SHALL discover MCP tools from the initialized server before invoking server tools.

#### Scenario: Tool list retrieved
- **WHEN** the MCP session is initialized
- **THEN** the client SHALL list available tools and persist their names, descriptions, and input schemas for the run

### Requirement: Structured MCP tool calls
The system SHALL invoke MCP tools with structured JSON arguments and normalize tool responses into the shared tool-call result protocol.

#### Scenario: CVE lookup call succeeds
- **WHEN** an agent or intelligence layer calls a discovered CVE lookup tool
- **THEN** the MCP client SHALL return a normalized tool result with call ID, tool name, input, output, duration, and raw response artifact

### Requirement: CVE MCP typed wrapper
The system SHALL provide a typed wrapper for `mukul975/cve-mcp-server` covering dependency scan, CVE lookup, CVSS, EPSS, CISA KEV, CWE, public proof-of-concept, and risk scoring operations when corresponding tools are available.

#### Scenario: Dependency intelligence enrichment
- **WHEN** Recon requests dependency intelligence for normalized package identifiers
- **THEN** the CVE MCP wrapper SHALL call the appropriate server tools and return contextual vulnerability-intelligence records

### Requirement: MCP degraded mode
The system MUST continue safely when the MCP server is unavailable, missing expected tools, times out, or returns malformed data.

#### Scenario: MCP server missing
- **WHEN** the configured MCP command cannot be started
- **THEN** the runtime SHALL record degraded MCP status and continue the audit without treating missing intelligence as a confirmed finding

### Requirement: MCP safety and budget controls
The system SHALL enforce timeout, query budget, outbound-network policy metadata, and sensitive-input constraints for MCP calls.

#### Scenario: Query budget exhausted
- **WHEN** MCP query budget is exhausted
- **THEN** the runtime SHALL stop further MCP calls, record budget exhaustion, and return degraded contextual intelligence

