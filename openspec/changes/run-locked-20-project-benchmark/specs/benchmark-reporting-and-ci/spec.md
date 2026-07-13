## ADDED Requirements

### Requirement: Full baseline uses at least 20 unique eligible projects
The promoted full baseline SHALL contain at least 20 unique project IDs with reviewed source/license, exact commit locks, supported scan shapes, bounded scopes, truth, and effectiveness eligibility.

#### Scenario: Revision pairs are counted
- **WHEN** vulnerable and fixed cases belong to one upstream project
- **THEN** they SHALL count as two cases and one unique project.

#### Scenario: Placeholder or unsupported entry is present
- **WHEN** an entry is unresolved, unexecuted, unsupported, or effectiveness-ineligible
- **THEN** it SHALL NOT satisfy the 20-project quota.

### Requirement: Every promoted case proves execution and review
Every required case SHALL complete with matching acquisition commit, non-empty scan coverage, successful runtime/report/resource evidence, cleanup success, truth evaluation, and required adjudication/accounting.

#### Scenario: Remote download is skipped
- **WHEN** acquisition reports `remote-download-skipped`, cache miss, or missing commit
- **THEN** the case SHALL be non-completed with null metrics and the full baseline SHALL NOT be promoted.

### Requirement: Full baseline execution is explicitly authorized
Remote acquisition, real provider use, and Docker SHALL remain independent opt-in operator decisions with bounded time/resource budgets and retained artifacts.

#### Scenario: Complete reviewed run is promoted
- **WHEN** all unique-project, execution, truth, accounting, cleanup, comparison, and review gates pass
- **THEN** the machine JSON, derived Markdown, adjudication, readiness evidence, and comparison protocol SHALL be retained as the first full baseline.
