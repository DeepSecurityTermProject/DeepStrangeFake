## ADDED Requirements

### Requirement: Versioned prompt templates
The system SHALL store prompt templates with explicit role, template ID, version, required variables, output schema, and safety constraints.

#### Scenario: Template version selected
- **WHEN** an agent renders a prompt
- **THEN** the rendered prompt record SHALL include the template ID and version used for that agent call

### Requirement: Prompt variable validation
The system MUST validate required prompt variables before rendering.

#### Scenario: Missing required variable
- **WHEN** a prompt template requires `repository_summary` and the render request omits it
- **THEN** rendering SHALL fail with a structured template validation error before any LLM call is made

### Requirement: Agent role prompts
The system SHALL provide templates for Orchestrator, Recon, Analysis, and Verification roles with role-specific tool permissions and output schemas.

#### Scenario: Verification prompt forbids intelligence-only promotion
- **WHEN** the Verification prompt is rendered
- **THEN** it SHALL include a safety constraint that CVE/MCP/RAG context alone cannot promote a finding without local code or dependency evidence

### Requirement: Prompt regression fixtures
The system SHALL include prompt fixtures that verify stable rendering for representative repository metadata, tool outputs, memory context, and vulnerability-intelligence records.

#### Scenario: Fixture rendering is deterministic
- **WHEN** prompt tests render the same fixture twice
- **THEN** the rendered prompt content and expected schema metadata SHALL match exactly

### Requirement: Prompt artifact linking
The system SHALL link rendered prompts to agent traces, message-bus envelopes, and evidence chains when their outputs affect findings.

#### Scenario: Finding generated from LLM output
- **WHEN** an Analysis response creates a candidate finding
- **THEN** the finding and evidence chain SHALL reference the rendered prompt artifact and normalized LLM response artifact

