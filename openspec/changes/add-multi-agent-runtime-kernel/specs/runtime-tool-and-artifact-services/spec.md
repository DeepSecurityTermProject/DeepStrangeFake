## ADDED Requirements

### Requirement: ToolBroker mediates agent tool requests
The system SHALL provide a `ToolBroker` that receives agent tool requests, validates role permissions and budgets, materializes safe runtime arguments, dispatches through the existing tool protocol, and records normalized results.

#### Scenario: Safe tool request is dispatched
- **WHEN** a registered agent requests a permitted read-only tool within budget
- **THEN** `ToolBroker` SHALL dispatch the request through `ToolRuntime`, persist the normalized result, publish a tool dispatch event, and return result refs to the calling task.

#### Scenario: Unsafe tool request is denied
- **WHEN** an agent requests an unregistered, disallowed, over-budget, timeout-prone, or unsafe tool
- **THEN** `ToolBroker` SHALL deny or normalize the request without executing unsafe work and SHALL record the denial in task state, message events, and artifact diagnostics.

### Requirement: ToolBroker handles contextual service adapters
The system SHALL route memory retrieval, MCP CVE lookup, repository context, static scanning, and validation requests through service-specific broker adapters.

#### Scenario: Memory and MCP context remain contextual
- **WHEN** an agent requests memory or CVE MCP context through `ToolBroker`
- **THEN** the broker SHALL preserve contextual-only metadata so downstream policy gates cannot treat memory or CVE intelligence as local validation evidence.

#### Scenario: Validation requests respect safety configuration
- **WHEN** an agent requests validation or sandbox execution through `ToolBroker`
- **THEN** the broker SHALL enforce configured validation levels, sandbox settings, and no-live-target policy before dispatch.

### Requirement: ArtifactStore persists typed runtime artifacts
The system SHALL provide an `ArtifactStore` that wraps run directory creation and typed artifact writes for metadata, prompts, LLM responses, decisions, tools, MCP, memory, handoffs, findings, evidence, reports, and runtime state.

#### Scenario: Artifact write returns stable refs
- **WHEN** the runtime writes an artifact through `ArtifactStore`
- **THEN** the store SHALL return a stable artifact reference and SHALL avoid overwriting existing artifacts by using immutable path behavior.

#### Scenario: Artifact redaction is applied
- **WHEN** prompts, raw LLM responses, provider metadata, diagnostics, environment-derived settings, or tool outputs contain secret-like values
- **THEN** `ArtifactStore` SHALL apply the existing redaction rules before persisting artifacts that may be inspected or reported.

### Requirement: Runtime services publish traceable events
The system SHALL publish message bus events for runtime service activity.

#### Scenario: Tool and artifact events are correlated
- **WHEN** `ToolBroker` dispatches a tool or `ArtifactStore` writes an artifact
- **THEN** the runtime SHALL publish events that include run ID, task ID when available, role, service name, status, artifact refs, and correlation or causation IDs.

#### Scenario: Service failures are visible
- **WHEN** a runtime service fails, degrades, denies a request, or falls back
- **THEN** the runtime SHALL publish a message event and persist diagnostics so replay can explain the failure path.

### Requirement: Runtime services are testable independently
The system SHALL expose `ToolBroker` and `ArtifactStore` through small, deterministic interfaces that can be unit tested without live model APIs or live MCP servers.

#### Scenario: Offline tests exercise broker and store behavior
- **WHEN** the default test suite runs without external credentials
- **THEN** tests SHALL cover permitted tool dispatch, denied tool dispatch, artifact writes, redaction, immutable paths, and message event publication using mock or local-only services.
