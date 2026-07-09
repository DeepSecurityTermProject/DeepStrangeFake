## ADDED Requirements

### Requirement: Provider-neutral LLM client
The system SHALL provide an `LLMClient` interface that accepts normalized requests and returns normalized responses independent of the underlying provider.

#### Scenario: Mock client returns deterministic output
- **WHEN** the audit is configured with provider `mock`
- **THEN** the LLM runtime SHALL return deterministic responses without requiring API keys or network access

#### Scenario: Provider metadata is normalized
- **WHEN** a real provider adapter completes a request
- **THEN** the response SHALL include provider name, model name, latency, usage counters when available, finish reason, raw response reference, and parsed text

### Requirement: API key and provider configuration
The system MUST load provider settings from configuration and API secrets from configured environment variables rather than hardcoded source files.

#### Scenario: Missing API key
- **WHEN** a real provider is selected and its configured API key environment variable is missing
- **THEN** the LLM runtime SHALL fail before the first model call with a structured configuration error and no partial finding promotion

#### Scenario: Mock provider ignores API keys
- **WHEN** the mock provider is selected
- **THEN** the LLM runtime SHALL run without checking real provider API key environment variables

### Requirement: LLM request and response persistence
The system SHALL persist rendered prompts, request metadata, raw provider responses, normalized responses, and validation errors under the run directory.

#### Scenario: Successful model call is auditable
- **WHEN** an agent receives an LLM response
- **THEN** the run artifacts SHALL contain the rendered prompt reference, request parameters, response metadata, and normalized response linked to the agent trace

### Requirement: Structured output validation
The system MUST validate role-specific model outputs before converting them into handoffs, findings, verification decisions, or report data.

#### Scenario: Malformed JSON response
- **WHEN** an LLM response cannot be parsed or does not match the expected role schema
- **THEN** the runtime SHALL record a validation error and SHALL NOT create accepted findings from that response

### Requirement: Retry, timeout, and budget enforcement
The system SHALL enforce per-request timeout, retry count, token budget, and cost budget controls for LLM calls.

#### Scenario: Token budget exhausted
- **WHEN** an agent would exceed its configured token budget
- **THEN** the runtime SHALL stop additional LLM calls for that agent and record a budget-exhausted stop reason

