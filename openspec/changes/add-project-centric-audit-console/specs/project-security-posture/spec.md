## ADDED Requirements

### Requirement: Project dashboard metadata and latest-run truth
The system SHALL provide a project dashboard containing project identity, safe source display, detected language and dependency metadata, latest run status and timing, scanned-file and coverage information when available, and a separately identified latest complete posture run. The dashboard SHALL NOT represent an older complete result as the newest scan result.

#### Scenario: Latest run is complete
- **WHEN** the newest run satisfies the posture completeness gate
- **THEN** the dashboard identifies that run as both the latest run and latest complete posture source

#### Scenario: Latest run is degraded or failed
- **WHEN** the newest run is failed, cancelled, degraded, or coverage-incomplete
- **THEN** the dashboard shows its actual status and incompleteness reason while separately labeling any older complete posture as historical

#### Scenario: Project has no completed scan
- **WHEN** a project has only queued, running, failed-before-report, or no runs
- **THEN** the dashboard presents an explicit no-posture state and does not display zero risk as if an audit passed

### Requirement: Validated-finding security posture
Core vulnerability counts and the core risk score SHALL use findings that passed the system's validation/evidence gate. Candidate, pending, manual, rejected, and inconclusive findings SHALL be counted separately and SHALL NOT be presented as confirmed vulnerabilities.

#### Scenario: Validated and candidate findings coexist
- **WHEN** a completed report contains both validated findings and unvalidated candidates
- **THEN** severity totals and core risk use only validated findings while the dashboard shows separate candidate and verification-state counts

#### Scenario: No validated findings in a complete scan
- **WHEN** a complete scan contains no validated findings
- **THEN** the dashboard reports zero confirmed findings and zero core risk while still displaying coverage and candidate counts

#### Scenario: Incomplete validation
- **WHEN** validation is unavailable or incomplete
- **THEN** the dashboard marks posture incomplete and does not convert static candidates into confirmed vulnerabilities

### Requirement: Deterministic versioned risk score
The system SHALL calculate risk in trusted code using a published versioned formula and SHALL NOT accept a model-generated score as authoritative. The initial formula SHALL clamp confidence to `[0,1]`, multiply validated findings by severity weights critical=25, high=15, medium=7, low=2, informational=0, sum the products, round to an integer, and cap the result at 100.

#### Scenario: Calculate score from validated findings
- **WHEN** a complete posture contains validated findings with severity and confidence
- **THEN** the API returns the deterministic score, formula version, component counts, and inputs needed to explain the result

#### Scenario: Model supplies a different score
- **WHEN** a report or model-generated text contains a risk number that differs from the trusted calculation
- **THEN** the dashboard uses the trusted calculation and may display the model text only as non-authoritative narrative if otherwise safe

#### Scenario: Missing or invalid confidence
- **WHEN** a validated finding lacks usable confidence
- **THEN** the system applies an explicit versioned fallback rule, reports that fallback in score metadata, and does not silently use an out-of-range value

### Requirement: Stable versioned finding fingerprints
The system SHALL generate finding identity in trusted code from normalized vulnerability class, repository-relative path, enclosing symbol when available, and sink or dangerous-operation identity. Fingerprints SHALL be versioned and SHALL NOT use LLM-generated titles or descriptions as identity inputs.

#### Scenario: Same finding in a later run
- **WHEN** a later comparable run reports the same normalized class, path, symbol, and sink identity
- **THEN** the system assigns the same fingerprint despite changes to title, description, confidence, or line number

#### Scenario: Different vulnerability at same file
- **WHEN** two findings in one file have different normalized class, symbol, or sink identity
- **THEN** the system assigns different fingerprints

#### Scenario: Symbol metadata unavailable
- **WHEN** a finding lacks an enclosing symbol
- **THEN** the system uses a documented deterministic fallback anchor and marks the fingerprint component quality

### Requirement: Completeness-gated vulnerability trends
The system SHALL compare version-compatible fingerprints across comparable runs and classify findings as new, persistent, resolved, or reintroduced. Only a successful non-degraded run with required report and coverage evidence SHALL resolve a finding absent from the new result.

#### Scenario: New finding
- **WHEN** a complete run contains a fingerprint not present in the preceding comparable complete posture
- **THEN** the system classifies it as new

#### Scenario: Persistent finding
- **WHEN** consecutive comparable complete postures contain the same fingerprint
- **THEN** the system classifies it as persistent

#### Scenario: Resolved finding
- **WHEN** a successful complete posture omits a fingerprint present in the preceding comparable complete posture
- **THEN** the system classifies it as resolved

#### Scenario: Reintroduced finding
- **WHEN** a fingerprint classified as resolved appears in a later comparable complete posture
- **THEN** the system classifies it as reintroduced

#### Scenario: Incomplete scan omits a prior finding
- **WHEN** a failed, cancelled, degraded, or coverage-incomplete run does not contain a previous fingerprint
- **THEN** the system leaves the prior finding unconfirmed and does not classify it as resolved

#### Scenario: Fingerprint algorithm version changes
- **WHEN** two runs use incompatible fingerprint versions without a trusted migration
- **THEN** the system does not claim direct trend continuity and reports the comparison limitation

### Requirement: Security posture dashboard presentation
The frontend SHALL present project metadata, latest audit summary, confirmed severity distribution, separate validation-state counts, deterministic risk score, completeness, recent trend, investigation quality, and a high-risk finding list. Charts SHALL have numeric or textual equivalents and SHALL not rely on color alone.

#### Scenario: Complete project dashboard
- **WHEN** a project has comparable complete runs
- **THEN** the dashboard shows current posture, risk and confirmed-finding trends, new/resolved/persistent/reintroduced counts, and links to supporting runs and findings

#### Scenario: High-risk finding drill-down
- **WHEN** a user selects a high-risk dashboard item
- **THEN** the UI opens the owning run and finding evidence without losing the project's dashboard context

#### Scenario: Degraded posture display
- **WHEN** the latest run is degraded or accounting, evidence, validation, or coverage is incomplete
- **THEN** the dashboard prominently displays the limitation and avoids a healthy visual state based on stale or partial data

#### Scenario: Accessible severity chart
- **WHEN** severity or trend data is rendered graphically
- **THEN** the same values and labels are available as text or an accessible data representation and status is not conveyed by color alone

### Requirement: Investigation quality indicators
The dashboard SHALL expose available evidence completeness, validation completion, effective execution mode, fallback/degraded reasons, and budget usage as quality indicators distinct from vulnerability severity.

#### Scenario: Agent-led run completes without fallback
- **WHEN** the posture run completed in the requested Agent-led mode with complete evidence and accounting
- **THEN** the dashboard reports the effective mode and available quality indicators without implying that Agent activity itself proves vulnerability validity

#### Scenario: Runtime falls back
- **WHEN** the requested mode differs from the effective mode or the report contains degraded reasons
- **THEN** the dashboard exposes the fallback and its reason separately from the risk score

#### Scenario: Quality metadata unavailable
- **WHEN** a legacy or partial report lacks a quality indicator
- **THEN** the dashboard labels the value unavailable rather than treating it as zero or complete

