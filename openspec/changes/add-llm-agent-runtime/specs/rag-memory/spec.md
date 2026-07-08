## ADDED Requirements

### Requirement: Repository and artifact indexing
The system SHALL index selected repository files, source slices, tool outputs, findings, evidence chains, and optional external notes into a retrieval memory store.

#### Scenario: Repository indexed by commit and hash
- **WHEN** a local repository target is indexed
- **THEN** each memory record SHALL include target identity, commit when available, source path, line range when available, content hash, namespace, and artifact reference when applicable

### Requirement: Deterministic local retrieval
The system SHALL provide deterministic lexical retrieval that works without external embedding APIs.

#### Scenario: Offline retrieval returns cited chunks
- **WHEN** an agent queries memory in offline mode
- **THEN** retrieval SHALL return ranked chunks with record IDs, source paths, line ranges, snippets, scores, and citations

### Requirement: Optional embedding retrieval
The system MAY support optional embedding providers behind the same memory interface, but deterministic lexical retrieval MUST remain available.

#### Scenario: Embedding provider unavailable
- **WHEN** embedding retrieval is configured but the provider is unavailable
- **THEN** memory retrieval SHALL fall back to deterministic lexical retrieval and record degraded embedding status

### Requirement: Retrieval provenance
The system SHALL record retrieved memory records in agent traces, message-bus envelopes, and evidence chains when retrieval influences a finding.

#### Scenario: Retrieved chunk supports candidate
- **WHEN** an Analysis prompt includes a retrieved source chunk that contributes to a candidate finding
- **THEN** the candidate finding and evidence chain SHALL reference the memory record ID and retrieval artifact

### Requirement: Memory invalidation
The system MUST invalidate or rebuild stale memory records when target commit, file content hash, or source artifact hash changes.

#### Scenario: Source file changes
- **WHEN** a previously indexed file has a different content hash
- **THEN** retrieval SHALL NOT return the stale record as current context and SHALL schedule or perform re-indexing

### Requirement: Sensitive content controls
The system SHALL support memory exclusion patterns and redaction rules for secrets and sensitive files.

#### Scenario: Excluded file pattern
- **WHEN** a file path matches configured memory exclusion patterns
- **THEN** the memory indexer SHALL skip that file and record the exclusion count in index metadata

