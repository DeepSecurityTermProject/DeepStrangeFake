## MODIFIED Requirements

### Requirement: Runtime modes provide compatibility and rollback
The system SHALL expose explicit agent-led, legacy, deterministic graph, and adaptive graph modes through validated configuration while preserving the public audit entry point; omitted mode SHALL request agent-led, and the prior three modes SHALL remain explicit compatibility and rollback choices.

#### Scenario: Agent-led mode is omitted and therefore requested
- **WHEN** a valid CLI, Web, or configuration request does not specify runtime mode
- **THEN** the public runtime SHALL request agent-led execution and SHALL expose requested and effective mode in results.

#### Scenario: Legacy mode is selected
- **WHEN** graph rollout is disabled or rollback selects legacy mode
- **THEN** the existing procedural runtime path SHALL remain available without requiring graph or agent-led investigation artifacts.

#### Scenario: Deterministic or adaptive mode is selected
- **WHEN** a caller explicitly selects deterministic or adaptive graph mode
- **THEN** the runtime SHALL preserve the corresponding validated graph behavior and SHALL not require agent-led hypotheses, evidence gates, or verification plans.

#### Scenario: Adaptive graph cannot obtain a valid decision
- **WHEN** the model is unavailable, malformed, denied, or disabled at an adaptive graph checkpoint
- **THEN** the runtime SHALL continue with the last committed deterministic graph revision and record the fallback reason.

#### Scenario: Agent-led mode cannot begin with a real provider
- **WHEN** agent-led mode resolves to no usable real provider or to a mock provider outside explicit development/test configuration
- **THEN** the runtime SHALL run the deterministic fallback, record requested `agent-led` and effective `deterministic`, and terminate with explicit degraded status after successful finalization.
