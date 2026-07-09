## ADDED Requirements

### Requirement: Reports include all verification candidates
The system SHALL include every verification candidate in audit outputs with final status, reason, and evidence references, including `confirmed`, `likely`, `rejected`, and `manual-required`.

#### Scenario: Report JSON is generated
- **WHEN** an audit run completes
- **THEN** the JSON report SHALL expose all verification candidates with final verification status, verifier decision, validation level, reason, evidence refs, and artifact refs.

#### Scenario: Markdown report is generated
- **WHEN** an audit run completes
- **THEN** the Markdown report SHALL include a verification evidence section that summarizes confirmed, likely, rejected, and manual-required candidates and links each candidate to its supporting evidence refs.

#### Scenario: Rejected candidate exists
- **WHEN** Verification rejects a candidate
- **THEN** the report SHALL retain the candidate in the verification candidate list with rejection reason instead of hiding it from all primary outputs.

### Requirement: Verification metrics are status-specific
The system SHALL report verification metrics by final status and SHALL NOT count static-only or likely candidates as confirmed.

#### Scenario: Summary counts are computed
- **WHEN** runtime, report, benchmark, or Web summaries compute verification counts
- **THEN** `confirmed_count` SHALL include only candidates with final status `confirmed`, while `likely_count`, `rejected_count`, and `manual_required_count` SHALL be counted separately.

#### Scenario: Static-only finding is likely
- **WHEN** a static-only finding appears in report output
- **THEN** it SHALL contribute to `likely_count` or another non-confirmed bucket and SHALL NOT contribute to `confirmed_count`.

### Requirement: Runtime and replay expose verification evidence
The system SHALL persist verification artifacts and replay events so reviewers can reconstruct the verification loop for each candidate.

#### Scenario: Verification loop runs
- **WHEN** PoC generation, sandbox execution, Judge evaluation, or PoC repair occurs
- **THEN** runtime state and replay summary SHALL include task status, attempt refs, PoC refs, sandbox result refs, Judge reason, and fallback or blocking reason.

#### Scenario: Artifact ref is reported
- **WHEN** a report, runtime state, replay summary, or Web API payload includes a verification artifact ref
- **THEN** the referenced file SHALL exist under the run directory and SHALL be openable by path.

### Requirement: Web run detail displays verification status and evidence
The system SHALL expose verification status distribution and candidate-level evidence in the Web run detail views.

#### Scenario: Run detail is loaded
- **WHEN** the frontend loads a completed run
- **THEN** it SHALL display confirmed, likely, rejected, and manual-required counts from report or runtime data.

#### Scenario: Finding detail is expanded
- **WHEN** a user inspects a verification candidate in the Web UI
- **THEN** the UI SHALL show final status, reason, PoC refs when present, sandbox result refs when present, stdout/stderr summaries when present, exit code when present, and artifact refs.
