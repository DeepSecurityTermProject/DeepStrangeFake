## ADDED Requirements

### Requirement: Backend exposes frontend health endpoint
The system SHALL provide a non-secret health endpoint for the frontend to confirm backend availability.

#### Scenario: Read backend health
- **WHEN** the frontend sends `GET /api/health`
- **THEN** the backend SHALL return a successful JSON response containing service name, status, and API version or equivalent compatibility metadata.

#### Scenario: Health endpoint contains no secrets
- **WHEN** the backend returns health information
- **THEN** the response SHALL NOT contain API keys, tokens, passwords, model credentials, or MCP secrets.

### Requirement: Backend exposes frontend option discovery
The system SHALL provide a non-secret options endpoint for scan form choices.

#### Scenario: Read scan options
- **WHEN** the frontend sends `GET /api/options`
- **THEN** the backend SHALL return supported provider modes, memory modes, MCP modes, validation levels, and LLM decision roles.

#### Scenario: Options match accepted request values
- **WHEN** the frontend uses values returned from `/api/options` to create a scan request
- **THEN** the backend SHALL accept those values through `POST /api/runs`.

#### Scenario: Options endpoint contains no secrets
- **WHEN** the backend returns frontend options
- **THEN** the response SHALL NOT contain API key values or environment secret values.

### Requirement: Frontend development can proxy API requests
The system SHALL support local frontend development against the FastAPI backend.

#### Scenario: Vite proxy forwards API requests
- **WHEN** the frontend dev server receives requests under `/api`
- **THEN** it SHALL forward them to the local FastAPI backend without requiring API URLs to be hardcoded in page components.

#### Scenario: Backend remains compatible with existing API
- **WHEN** health and options endpoints are added
- **THEN** existing scan job, runtime state, replay summary, and report endpoints SHALL continue to behave compatibly.
