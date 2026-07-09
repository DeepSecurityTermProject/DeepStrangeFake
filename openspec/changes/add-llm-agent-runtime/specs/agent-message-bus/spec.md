## ADDED Requirements

### Requirement: Message envelope schema
The system SHALL represent runtime communication with a message envelope containing message ID, run ID, correlation ID, causation ID, sender, recipient, message type, payload, timestamp, and artifact references.

#### Scenario: Agent emits handoff message
- **WHEN** Recon hands work to Analysis
- **THEN** the message bus SHALL persist a handoff envelope linking the Recon trace, handoff payload, run ID, and correlation ID

### Requirement: In-process routing
The system SHALL provide in-process publish/subscribe routing for Orchestrator, agents, tools, MCP client, memory, validation, evidence, and reporting components.

#### Scenario: Tool result routed to agent
- **WHEN** a tool call completes
- **THEN** the message bus SHALL route a tool-result message to the requesting agent and persist the envelope

### Requirement: Durable append-only log
The system SHALL persist message envelopes as append-only JSONL artifacts under each run directory.

#### Scenario: Run message log exists
- **WHEN** an audit run completes
- **THEN** the run directory SHALL contain a message log that can be replayed in timestamp order

### Requirement: Replay support
The system SHALL support replaying message logs to reconstruct the high-level audit workflow and trace relationships.

#### Scenario: Replay reconstructs workflow
- **WHEN** a completed run message log is replayed
- **THEN** the replay SHALL reconstruct agent start/end events, tool calls, memory retrievals, MCP calls, verification decisions, validation events, and report generation events

### Requirement: Error and denial messages
The system SHALL represent runtime errors, permission denials, timeout events, degraded MCP status, and budget exhaustion as structured messages.

#### Scenario: Forbidden tool request denied
- **WHEN** an agent requests a forbidden tool
- **THEN** the message bus SHALL persist a denial message with the original request reference and policy reason

### Requirement: Trace correlation
The system SHALL link message envelopes to agent traces, tool results, memory retrievals, evidence chains, and reports through stable IDs.

#### Scenario: Report includes trace references
- **WHEN** a report finding is generated
- **THEN** the report SHALL include references that allow a reviewer to trace the finding back through message envelopes, agent traces, tool calls, memory retrievals, and validation results

