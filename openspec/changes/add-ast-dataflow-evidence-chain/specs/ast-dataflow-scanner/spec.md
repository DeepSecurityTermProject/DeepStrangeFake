## ADDED Requirements

### Requirement: AST scanner extracts language-normalized dataflow IR
The system SHALL parse Python and JS/TS source files into normalized source, sink, sanitizer, and propagation records suitable for deterministic dataflow analysis.

#### Scenario: Python source is parsed
- **WHEN** the repository contains Python source files
- **THEN** the scanner SHALL parse them with AST location information and extract route handlers, request sources, sensitive sinks, and sanitizer candidates.

#### Scenario: JS/TS source is parsed
- **WHEN** the repository contains `.js`, `.jsx`, `.ts`, or `.tsx` files
- **THEN** the scanner SHALL use a Tree-sitter based parser when the optional JS/TS parser dependency is available, and SHALL fall back to bounded local line scanning when it is unavailable.
- **AND** extracted traces SHALL record the JS/TS parse backend in trace metadata.

#### Scenario: Parser fails for one file
- **WHEN** a supported source file cannot be parsed
- **THEN** the scanner SHALL continue scanning other files and SHALL preserve available evidence from fallback analysis when possible.

### Requirement: Scanner detects MVP source categories
The system SHALL identify common web request input sources for Python and JS/TS frameworks.

#### Scenario: Python request source is detected
- **WHEN** Python code reads Flask, FastAPI, or Django request parameters, route parameters, request body, uploaded files, or JSON payloads
- **THEN** the scanner SHALL emit a source node with repository-relative path, line range, expression, symbol when available, and framework evidence.

#### Scenario: JS/TS request source is detected
- **WHEN** JS/TS code reads Express, Koa, or Next-style request query, params, body, files, URL search params, or JSON payloads
- **THEN** the scanner SHALL emit a source node with repository-relative path, line range, expression, symbol when available, and framework evidence.

### Requirement: Scanner detects MVP sink categories
The system SHALL identify SQL execution, command execution, and file/path read sinks.

#### Scenario: SQL sink is detected
- **WHEN** source code invokes raw SQL execution APIs or unsafe raw query helpers
- **THEN** the scanner SHALL emit a SQL sink node and classify it as `sql-injection`.

#### Scenario: Command sink is detected
- **WHEN** source code invokes shell or process execution APIs with dynamic command input
- **THEN** the scanner SHALL emit a command sink node and classify it as `command-injection`.

#### Scenario: File read sink is detected
- **WHEN** source code reads or sends a filesystem path derived from dynamic input
- **THEN** the scanner SHALL emit a file/path sink node and classify it as `path-traversal`.

### Requirement: Scanner detects sanitizer and guard evidence
The system SHALL identify common sanitizer, guard, and safe construction patterns.

#### Scenario: SQL parameter binding is detected
- **WHEN** a SQL sink uses bound parameters or a query builder pattern rather than interpolating user input into raw SQL
- **THEN** the scanner SHALL mark the trace as sanitized or safe for that sink.

#### Scenario: Path base check is detected
- **WHEN** path input is canonicalized and checked against an enforced safe base directory before file access
- **THEN** the scanner SHALL mark the trace as sanitized or blocked.

#### Scenario: Command allowlist is detected
- **WHEN** command execution uses fixed argv values or an explicit allowlist before invocation
- **THEN** the scanner SHALL mark the trace as sanitized or lower-risk.

### Requirement: Dataflow engine produces bounded traces
The system SHALL produce bounded source-to-sink traces with clear status rather than unbounded whole-program analysis.

#### Scenario: Unsanitized source reaches sink
- **WHEN** a request source flows through local assignments or call arguments into a sensitive sink without a recognized sanitizer
- **THEN** the engine SHALL produce a `complete-flow` trace with ordered steps from source to sink.

#### Scenario: Sanitized source reaches sink
- **WHEN** a source reaches a sink through a recognized sanitizer or guard
- **THEN** the engine SHALL produce a `sanitized-flow` trace and SHALL NOT treat it as a high-confidence vulnerability by default.

#### Scenario: Sink has no source path
- **WHEN** a sensitive sink is present but no request-controlled source can be connected within analysis bounds
- **THEN** the engine SHALL NOT produce a `complete-flow` trace for that sink.
- **AND** the engine SHALL classify source-less sink candidates as `sink-only` and missing-sink candidates as `no-flow` when those candidates are evaluated internally.
