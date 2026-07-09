## ADDED Requirements

### Requirement: Target intake supports remote and local repositories
The system SHALL accept a GitHub URL, GitLab URL, or local directory as an audit target.

#### Scenario: GitHub target is provided
- **WHEN** the user submits a GitHub repository URL with an optional branch, tag, or commit
- **THEN** the system records the target metadata and prepares a local working copy for analysis

#### Scenario: Local target is provided
- **WHEN** the user submits a local directory path
- **THEN** the system uses that directory as the audit target without requiring a remote clone

### Requirement: Project languages are detected
The system SHALL identify the dominant programming languages and relevant secondary languages in the target project.

#### Scenario: Multi-language project is analyzed
- **WHEN** the target contains source files from multiple language families
- **THEN** the system reports language percentages and marks the dominant language family

### Requirement: File structure metadata is extracted
The system SHALL extract a normalized project file tree suitable for agent context and report references.

#### Scenario: File tree is generated
- **WHEN** repository analysis completes
- **THEN** the system stores a file tree that excludes generated caches, dependency vendor folders, and configured ignore patterns

### Requirement: Dependency metadata is extracted
The system SHALL detect dependency manifests and summarize declared dependencies where supported.

#### Scenario: Dependency manifests are present
- **WHEN** the target includes files such as package manifests, lock files, Python requirements, Composer files, Maven files, or CMake files
- **THEN** the system records manifest paths, package names, versions when available, and ecosystem type

### Requirement: Dependency metadata supports vulnerability intelligence lookup
The system SHALL normalize dependency and product metadata into identifiers usable by advisory and CVE intelligence tools where possible.

#### Scenario: Package dependency is extracted
- **WHEN** the system extracts a package name, version, and ecosystem from a dependency manifest
- **THEN** the system stores normalized package identity suitable for OSV or GitHub advisory lookup

#### Scenario: Product identity is inferred
- **WHEN** the system infers a product, framework, or service name from project metadata
- **THEN** the system stores the source evidence and confidence so CVE search results can be treated as contextual hints

### Requirement: Attack surfaces are identified
The system SHALL identify likely attack surfaces that should be prioritized by downstream agents.

#### Scenario: Web project is analyzed
- **WHEN** the target contains web routes, controllers, API handlers, middleware, or request handlers
- **THEN** the system records entry points with file paths, symbols when available, HTTP method or route when available, and related framework evidence

#### Scenario: High-risk operations are found
- **WHEN** the target contains file upload handling, command execution, database query construction, path manipulation, authentication logic, or authorization checks
- **THEN** the system records these locations as high-risk areas for Recon and Analysis agents

### Requirement: Repository analysis is reproducible
The system SHALL store target source identity and analysis metadata for each run.

#### Scenario: Remote repository is analyzed
- **WHEN** the system analyzes a remote repository
- **THEN** the run metadata includes URL, resolved commit, analysis timestamp, selected ref, and local checkout path

#### Scenario: Local directory is analyzed
- **WHEN** the system analyzes a local directory
- **THEN** the run metadata includes absolute path, detected VCS commit when available, and analysis timestamp
