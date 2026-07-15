## ADDED Requirements

### Requirement: Durable public audit events
The system SHALL project job lifecycle and selected runtime messages into a versioned, append-only public event journal for each run. Every event SHALL have a run-scoped monotonically increasing identifier, timestamp, category, phase, actor, title, bounded structured summary, status, and optional correlation, causation, and authorized artifact references.

#### Scenario: Runtime activity becomes a public event
- **WHEN** the job runner or audit runtime emits an allowlisted lifecycle, Agent, tool, evidence, validation, budget, state, or error record
- **THEN** the projection layer persists a corresponding versioned public event with the next run-scoped event identifier

#### Scenario: Unsupported internal message
- **WHEN** an internal message has no approved public projection
- **THEN** the system omits it from the public event journal rather than serializing the internal payload by default

#### Scenario: Oversized tool output
- **WHEN** an approved tool result exceeds the public event size limit
- **THEN** the event contains a bounded summary and an authorized artifact reference instead of the complete output

### Requirement: Persistence precedes live delivery
The system MUST append and flush a redacted event successfully before it is delivered to live subscribers. The event journal SHALL be the ordering and replay authority, and an event index SHALL be rebuildable from it after interruption.

#### Scenario: Successful event delivery
- **WHEN** a new event is generated
- **THEN** it is durably appended before any SSE client receives that event ID

#### Scenario: Persistence failure
- **WHEN** the event cannot be appended or flushed
- **THEN** the system does not stream it as accepted history and records a sanitized operational failure through a safe fallback path

#### Scenario: Crash between append and index update
- **WHEN** the process restarts after an event was appended but before its SQLite event index was updated
- **THEN** startup reconciliation discovers the journal entry and rebuilds the missing index state without assigning a duplicate ID

### Requirement: Secret-safe rationale projection
The public event stream SHALL expose only structured rationale summaries and auditable actions. It MUST NOT persist or serve hidden chain-of-thought, full prompts, raw provider response bodies, authorization headers, API keys, environment dumps, or unbounded source and tool content. All public event fields and artifact references SHALL receive a second redaction pass before persistence.

#### Scenario: Agent hypothesis update
- **WHEN** an Agent creates or updates a hypothesis
- **THEN** the event may include hypothesis identity, bounded rationale summary, assessment, next action, and evidence references but not hidden reasoning tokens or raw model text

#### Scenario: Secret appears in an input record
- **WHEN** a selected message or tool result contains a configured secret or credential-like value
- **THEN** the persisted and streamed public event replaces the value with a redaction marker

#### Scenario: Evidence code excerpt
- **WHEN** an event includes source evidence
- **THEN** the excerpt is bounded, associated with an authorized file location, and omits unrelated repository content

### Requirement: Resumable SSE delivery
The backend SHALL provide a `text/event-stream` endpoint for a known run that replays persisted events in strict ID order, supports `Last-Event-ID` resumption, sends keepalive heartbeats, and switches to live delivery without gaps or duplicate event IDs.

#### Scenario: Initial connection
- **WHEN** a client connects without a last event ID
- **THEN** the endpoint replays available persisted events in order and then delivers newly persisted events

#### Scenario: Reconnect after interruption
- **WHEN** a client reconnects with a valid last event ID
- **THEN** the endpoint sends only events with greater IDs before resuming live delivery

#### Scenario: Client already has terminal event
- **WHEN** a terminal run's client reconnects at or after the final event ID
- **THEN** the endpoint confirms current terminal state and closes cleanly without inventing another lifecycle event

#### Scenario: Unknown or invalid cursor
- **WHEN** a cursor is malformed or refers to an unavailable run history
- **THEN** the endpoint returns a stable recoverable error or explicit reset instruction rather than silently skipping events

### Requirement: Polling fallback and state reconciliation
The frontend SHALL visibly track stream connection state and SHALL fall back to the existing status and artifact polling APIs after bounded SSE failures. Event handling SHALL be idempotent, and periodic reconciliation SHALL correct missed summary state without duplicating timeline entries.

#### Scenario: Healthy stream
- **WHEN** SSE connects and heartbeats continue
- **THEN** the page labels the connection live and updates timeline and summary state from events

#### Scenario: Repeated SSE failure
- **WHEN** stream reconnection exceeds the bounded retry policy
- **THEN** the page marks live delivery degraded, continues status and artifact updates through polling, and keeps a bounded background reconnect policy

#### Scenario: Browser refresh
- **WHEN** a user refreshes or reopens an active run page
- **THEN** the frontend loads the current snapshot, resumes from its latest known event ID, and does not cancel the backend job

#### Scenario: Duplicate event reception
- **WHEN** a reconnect or race causes the client to receive an already applied event ID
- **THEN** the client ignores the duplicate and preserves one timeline entry

### Requirement: Live investigation workspace
The project-scoped run page SHALL show current phase, status, progress, elapsed time, budget summary, connection state, and a filterable unified timeline. It SHALL support filters by Agent, category, phase, and severity and SHALL provide expandable bounded details for tool, evidence, validation, and error events.

#### Scenario: Active Agent-led run
- **WHEN** an Agent-led scan is running
- **THEN** the workspace presents structured hypotheses, rationale summaries, actions, tool calls, evidence, verification outcomes, fallbacks, and state transitions in event order

#### Scenario: Non-Agent or degraded run
- **WHEN** the effective mode is deterministic, legacy, fallback, or degraded
- **THEN** the workspace labels the effective mode and reason and does not imply Agent activity that did not occur

#### Scenario: Empty event history
- **WHEN** a queued run has no projected runtime events yet
- **THEN** the workspace displays queued state and connection diagnostics rather than an empty successful timeline

#### Scenario: Terminal replay
- **WHEN** a user opens a succeeded, degraded, failed, cancelled, or imported run
- **THEN** the same workspace presents its persisted event history as a replay and makes terminal state explicit

### Requirement: Narrow run controls with evidence retention
The first release SHALL allow cancellation of queued or running jobs and rerun of a terminal job's configuration. It SHALL NOT expose pause, interactive resume, or live Agent instruction controls. Cancellation SHALL preserve already persisted events and artifacts.

#### Scenario: Cancel active run
- **WHEN** a user confirms cancellation of a queued or running run
- **THEN** the backend transitions it toward `cancelled`, preserves partial evidence and events, and emits an auditable terminal lifecycle event

#### Scenario: Closing the page
- **WHEN** a user navigates away from or closes an active run page
- **THEN** the backend run continues unless a separate cancellation request was confirmed

#### Scenario: Rerun terminal configuration
- **WHEN** a user chooses rerun on a terminal job
- **THEN** the system opens a reviewable configuration derived from the prior run and creates a new run rather than mutating the prior record

### Requirement: Live and replay consistency
The system SHALL derive live and post-run console history from the same persisted public event journal. Job status and existing evidence artifacts SHALL remain authoritative when an imported legacy run has no complete public event history.

#### Scenario: Compare live session with later replay
- **WHEN** a user revisits a run after watching it live
- **THEN** the replay contains the same persisted event IDs, order, summaries, and terminal state seen during the live session

#### Scenario: Legacy run without event journal
- **WHEN** an imported run has runtime artifacts but no console event journal
- **THEN** the system clearly labels the history as reconstructed or unavailable and does not fabricate a complete live timeline

