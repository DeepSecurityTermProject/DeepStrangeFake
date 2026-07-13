## ADDED Requirements

### Requirement: Ground truth identifies expected local code outcomes
The system SHALL store schema-versioned truth records with stable truth/project/case IDs, expected presence, vulnerability class or CWE, local path, symbol or bounded line range, vulnerable/fixed links, evidence refs, truth source, and review provenance.

#### Scenario: Known vulnerable case is defined
- **WHEN** a case represents a vulnerable revision
- **THEN** at least one positive truth record SHALL identify the expected local vulnerability independently from scanner output.

#### Scenario: Fixed or safe-negative case is defined
- **WHEN** a case represents a fixed revision or safe negative
- **THEN** truth SHALL state expected absence/rejection and retain evidence explaining the control.

### Requirement: Vulnerable and fixed revisions are linked but independent
Vulnerable and fixed revisions SHALL be separate cases linked by a pair ID and SHALL count as one unique project identity.

#### Scenario: Pair is evaluated
- **WHEN** both revisions complete
- **THEN** evaluation SHALL report expected presence in the vulnerable case and disappearance/rejection in the fixed case without merging raw results.

### Requirement: Finding matching is deterministic, normalized, and inspectable
The evaluator SHALL normalize vulnerability-class aliases and paths, then match by case, class, path, and symbol/line overlap using a versioned matcher.

#### Scenario: Finding uniquely matches truth
- **WHEN** one truth record satisfies all matching rules
- **THEN** stable IDs, rule version, and matching evidence SHALL be linked.

#### Scenario: Finding has no unique match
- **WHEN** zero or multiple truths match
- **THEN** it SHALL remain unexpected or ambiguous and SHALL not be silently counted as a true positive.

#### Scenario: Duplicate findings refer to one location
- **WHEN** multiple normalized findings represent the same class/path/symbol-or-range group
- **THEN** raw findings SHALL remain unchanged while metric computation SHALL count the deduplicated group once.

### Requirement: Human adjudication is additive and auditable
Human decisions MUST NOT modify raw findings or machine-match records.

#### Scenario: Reviewer adjudicates a finding
- **WHEN** a reviewer labels a finding true-positive, false-positive, duplicate, out-of-scope, or unresolved
- **THEN** reviewer, timestamp, rationale, evidence refs, and original match refs SHALL be recorded.

#### Scenario: Finding is not adjudicated
- **WHEN** no human decision exists
- **THEN** metrics requiring adjudication SHALL exclude it or be null and SHALL report adjudication coverage.

#### Scenario: Adjudication manifest identity is recorded
- **WHEN** an adjudication manifest is loaded for evaluation
- **THEN** the report SHALL record `benchmark-adjudication.v1`, its canonical content digest, and record count without modifying raw findings or scan reuse identity.

### Requirement: Metrics use versioned formulas and eligible completed cases
The evaluator SHALL publish `metric_version`, raw matrices, micro totals, macro per-project values, and exact denominator coverage.

#### Scenario: Known-positive candidate recall is computed
- **WHEN** eligible completed cases have expected-present truth
- **THEN** recall SHALL equal distinct truth IDs matched by at least one candidate divided by all in-scope expected-present truth IDs.

#### Scenario: Known-positive confirmed recall is computed
- **WHEN** eligible completed cases have expected-present truth
- **THEN** recall SHALL equal distinct truth IDs matched by at least one final confirmed finding divided by all in-scope expected-present truth IDs.

#### Scenario: Adjudicated confirmed precision is computed
- **WHEN** confirmed deduplicated finding groups are adjudicated
- **THEN** precision SHALL equal adjudicated true-positive groups divided by true-positive plus false-positive groups and SHALL report adjudication coverage.

#### Scenario: A non-confirmed finding is adjudicated
- **WHEN** a likely, rejected, or manual-required finding group has an adjudication
- **THEN** that group SHALL NOT enter `adjudicated-confirmed-precision`.

#### Scenario: Negative-control false-positive rate is computed
- **WHEN** eligible fixed/negative cases complete
- **THEN** the rate SHALL equal cases with at least one final `confirmed` finding divided by eligible completed fixed/negative cases, including confirmations not yet adjudicated.

#### Scenario: Rejection accuracy is computed
- **WHEN** negative expectation locations produced terminal candidates
- **THEN** accuracy SHALL equal distinct negative locations ending rejected divided by distinct negative locations producing any terminal candidate.

#### Scenario: Metric denominator is unsupported
- **WHEN** execution, support, truth, matching, or adjudication is incomplete
- **THEN** the metric SHALL be JSON null with a machine-readable reason, never zero.

### Requirement: Manual-required remains a distinct abstention
The evaluator MUST NOT automatically classify `manual-required` as true-positive or false-positive.

#### Scenario: Positive case is manual-required
- **WHEN** a positive truth produces final `manual-required`
- **THEN** matrices SHALL record abstention/missed confirmation and preserve the blocker separately from precision adjudication.

### Requirement: Real-model repetitions remain separate
Repeated real-model runs SHALL be retained individually and aggregated only when protocol and effective settings match except repetition ID.

#### Scenario: Compatible repetitions complete
- **WHEN** repetition records share the comparison protocol and effective settings
- **THEN** the report MAY publish per-metric mean/range but SHALL NOT pool raw findings into one synthetic run.
