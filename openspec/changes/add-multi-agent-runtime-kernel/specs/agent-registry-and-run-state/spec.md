## ADDED Requirements

### Requirement: AgentRegistry manages role-to-agent bindings
The system SHALL provide an `AgentRegistry` that registers agent roles, validates duplicate or missing roles, and returns callable agent adapters to the runtime.

#### Scenario: Agent role is registered
- **WHEN** an agent adapter is registered for a role such as `orchestrator`, `recon`, `analysis`, or `verification`
- **THEN** the registry SHALL expose the role metadata and callable adapter to `AgentRuntime`.

#### Scenario: Missing agent role is rejected
- **WHEN** the runtime attempts to invoke an unregistered required role
- **THEN** the registry SHALL return a structured error that can be recorded in task state and surfaced through runtime diagnostics.

### Requirement: AgentInvocation defines agent inputs and outputs
The system SHALL define a runtime invocation contract that separates agent input state, runtime services, and agent output payloads.

#### Scenario: Agent receives bounded runtime context
- **WHEN** an agent is invoked by `AgentRuntime`
- **THEN** it SHALL receive only the run state, task input, config, and approved runtime service handles required for that role.

#### Scenario: Agent returns structured output
- **WHEN** an agent finishes successfully
- **THEN** it SHALL return a structured output containing payload data, handoff or decision refs where applicable, artifact refs, message refs, and next-step hints.

### Requirement: RunState tracks audit-level progress
The system SHALL maintain a `RunState` record for each audit run.

#### Scenario: RunState is created
- **WHEN** a new audit run is initialized
- **THEN** `RunState` SHALL include run ID, target metadata ref, config summary, current status, started timestamp, task IDs, artifact refs, message refs, and final summary when available.

#### Scenario: RunState reaches terminal status
- **WHEN** a run completes, fails, or is cancelled
- **THEN** `RunState` SHALL record the terminal status, finished timestamp, final report refs, failure details if any, and validation counts.

### Requirement: TaskState tracks role-level execution
The system SHALL maintain a `TaskState` record for each agent or service step executed by the runtime.

#### Scenario: TaskState transitions are explicit
- **WHEN** a task moves through pending, running, succeeded, failed, skipped, or fallback status
- **THEN** the runtime SHALL update `TaskState` with timestamps, role, task kind, input refs, output refs, artifact refs, message refs, error details, and fallback reason.

#### Scenario: TaskState is replayable
- **WHEN** a message log or report references a runtime task
- **THEN** the referenced `TaskState` SHALL allow a reviewer to identify the responsible role, inputs, outputs, and fallback path without reading `pipeline.py`.

### Requirement: Runtime state supports deterministic replay summaries
The system SHALL summarize run and task state in replay output without re-executing agents or tools.

#### Scenario: Replay includes task lifecycle
- **WHEN** a run message log is replayed
- **THEN** the replay summary SHALL include role-level task statuses, fallback reasons, tool dispatch counts, and final decision sources when runtime state artifacts are available.
