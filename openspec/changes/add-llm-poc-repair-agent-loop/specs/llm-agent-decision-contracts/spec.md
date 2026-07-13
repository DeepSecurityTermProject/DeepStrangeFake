## ADDED Requirements

### Requirement: PoC repair uses a strict LLM contract
The system SHALL define a versioned `poc-repair.edits.v1` prompt and response contract that allows the model to return only a diagnosis, a closed list of typed edits, and a list of repair changes; the model MUST NOT return a replacement script.

#### Scenario: Repair response is valid
- **WHEN** the LLM returns JSON containing non-empty `diagnosis`, `edits`, and string-array `changes` fields, every edit uses an operation and slot declared by the generator repair manifest, and no additional fields occur at any level
- **THEN** the dedicated repair parser SHALL return normalized typed edits that trusted code MAY apply to the declared slots.

#### Scenario: Provider supports structured output
- **WHEN** the OpenAI-compatible repair provider accepts strict JSON Schema response formatting
- **THEN** the request SHALL include the complete nested `poc-repair.edits.v1` schema through `response_format.json_schema`, including edit-item field names, operation enums, required fields, and string-array item schemas.

#### Scenario: Provider supports JSON object mode only
- **WHEN** an otherwise reachable provider rejects JSON Schema response formatting with HTTP 400 but accepts JSON object response formatting
- **THEN** the client MAY retry once with `response_format.type = json_object`, while the dedicated exact parser SHALL retain the same strict contract and SHALL NOT normalize malformed field names or types.

#### Scenario: Repair response is malformed
- **WHEN** the LLM returns non-JSON, missing fields, wrong or nested item types, extra fields, empty edits, undeclared operation or slot IDs, duplicate conflicting edits, or values outside configured count or size limits
- **THEN** the dedicated repair parser SHALL fail closed, persist exact validation errors, and SHALL NOT assemble or execute a repaired PoC.

#### Scenario: Response attempts to set authority fields
- **WHEN** the LLM returns a complete script, command, expected signal, evidence marker, result filename, evidence policy, sandbox option, retry count, or verification verdict
- **THEN** the response SHALL be rejected as schema-invalid and none of its executable content SHALL reach the runner.

#### Scenario: Generic schema helper accepts extra fields
- **WHEN** the existing generic LLM schema helper would accept a response that contains extra keys or invalid nested edit items
- **THEN** the repair runtime MUST still reject the response through its dedicated exact-field parser before trusted assembly.

### Requirement: PoC repair input is minimized and grounded
The system MUST limit the repair request to the prior generated script, generator repair manifest, redacted diagnostics, openable dataflow context, bounded source/sink snippets, immutable missing-evidence description, and repair attempt number.

#### Scenario: Repair prompt is rendered
- **WHEN** an eligible failure invokes `LLMPoCRepairAgent`
- **THEN** the persisted prompt record SHALL identify the template version and include only the allowed repair context with repository snippets marked as untrusted data.

#### Scenario: Diagnostics contain secrets
- **WHEN** stdout, stderr, source snippets, or provider diagnostics contain configured secret values or credential-shaped hard-coded literals
- **THEN** the system SHALL redact those values before prompt submission and before persistence in standard prompt, response, report, or replay artifacts.

#### Scenario: Unrelated context is available
- **WHEN** the run contains environment variables, unrelated repository files, MCP results, memory records, or Docker host configuration not needed for repair
- **THEN** the repair request SHALL exclude that context.

#### Scenario: Raw provider payload exists
- **WHEN** existing provider diagnostics retain a raw response payload
- **THEN** repair reports and existing Web data SHALL reference only redacted normalized artifacts and SHALL NOT expose the raw payload.

### Requirement: PoC repair uses existing provider controls
The `poc-repair` role SHALL use the provider-neutral LLM client and existing timeout, retry, token, cost, redaction, and raw-response persistence controls.

#### Scenario: Mock repair is tested offline
- **WHEN** default tests run without API credentials
- **THEN** `MockLLMClient` SHALL provide deterministic repair responses and no network call SHALL occur.

#### Scenario: Real provider fails
- **WHEN** the configured real provider is unavailable, times out, exceeds budget, or returns an invalid response
- **THEN** the failure SHALL be persisted as a repair stop reason, no model text SHALL execute, the prior PoC failure classification SHALL remain unchanged, and verification SHALL degrade to `manual-required` with a repair-provider blocking reason.
