## ADDED Requirements

### Requirement: Role-specific LLM decision schemas
The system SHALL define schema-validated LLM decision contracts for Orchestrator, Recon, Analysis, and Verification.

#### Scenario: Orchestrator decision schema is enforced
- **WHEN** the Orchestrator receives LLM output
- **THEN** the system SHALL validate audit scope, agent order, budgets, focus areas, confidence, rationale, and cited inputs against the Orchestrator decision schema.

#### Scenario: Verification decision schema is enforced
- **WHEN** the Verification agent receives LLM output
- **THEN** the system SHALL validate accept/reject decisions, validation level, confidence, priority, rationale, and evidence references against the Verification decision schema.

### Requirement: LLM decision records are explicit
The system SHALL persist LLM proposals as decision records separate from final agent outputs.

#### Scenario: Decision record captures provenance
- **WHEN** an agent uses an LLM proposal
- **THEN** the decision record SHALL include role, prompt reference, LLM response reference, model/provider metadata, parsed JSON, confidence, rationale, requested tools, evidence refs, and schema status.

#### Scenario: Malformed output is recorded
- **WHEN** LLM output fails schema validation
- **THEN** the decision record SHALL capture validation errors and SHALL NOT be promoted directly into final agent output.

### Requirement: Repair and fallback handling
The system SHALL handle malformed, unsafe, or missing LLM decisions through configured repair and deterministic fallback.

#### Scenario: Repair attempt succeeds
- **WHEN** an LLM decision fails schema validation and repair is enabled
- **THEN** the system SHALL perform one repair prompt and use the repaired output only if it passes schema and policy gates.

#### Scenario: Fallback is used
- **WHEN** LLM output is absent, malformed after repair, unsafe, or over budget
- **THEN** the system SHALL use deterministic fallback and record the fallback reason.

### Requirement: Decision confidence is bounded
The system SHALL require role-specific confidence and completeness thresholds before an LLM proposal can influence final decisions.

#### Scenario: Low-confidence proposal is downgraded
- **WHEN** a model proposal has confidence below the configured role threshold
- **THEN** the system SHALL record the proposal but SHALL use deterministic or merged fallback behavior for the final decision.
