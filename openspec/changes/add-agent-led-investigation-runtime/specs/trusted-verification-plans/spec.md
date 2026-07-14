## ADDED Requirements

### Requirement: Verification plans are declarative and schema validated
The Verification agent SHALL receive only a normative `VerificationEvidencePackage` and SHALL return a versioned phase-one `VerificationPlan` composed of exactly one registered primitive ID, typed parameters, expected observations, confidence, rationale, and evidence refs.

#### Scenario: Valid registered plan is accepted
- **WHEN** a plan uses exactly one primitive registered for the candidate class and all parameters resolve to the evidence package and configured safety bounds
- **THEN** policy SHALL accept the plan for trusted compilation.

#### Scenario: Multiple primitives are proposed in phase one
- **WHEN** a plan contains zero primitives or more than one primitive
- **THEN** schema and contract validation SHALL reject it before compilation because ordered multi-primitive execution is outside phase-one scope.

#### Scenario: Plan requests arbitrary authority
- **WHEN** a plan contains source code, shell text, raw argv, unknown primitive, external URL, unregistered file, environment override, container option, or final verdict
- **THEN** schema or policy validation SHALL reject it before compilation or execution.

### Requirement: Trusted code compiles verification artifacts
A `TrustedVerificationCompiler` SHALL validate evidence hashes, class-to-primitive compatibility, parameter types, harmless payload policy, resource bounds, and repository scope before producing an existing `PoCArtifact` or a non-executable static-semantic verification artifact.

#### Scenario: Executable plan compiles
- **WHEN** a safe SQL injection, command injection, or path traversal plan passes compiler validation
- **THEN** trusted code SHALL assemble a bounded harness from registered templates and values and SHALL correlate it with the plan and evidence package.

#### Scenario: Static-semantic plan compiles
- **WHEN** a hardcoded-secret plan passes literal, format/entropy, placement, exclusion, and override validation
- **THEN** trusted code SHALL produce a non-executable verification artifact with `verification_type=static-semantic` and SHALL NOT perform live credential or network validation.

#### Scenario: Plan cannot be compiled safely
- **WHEN** a requested primitive is unsupported, unsafe, incompatible, stale, or cannot be bounded
- **THEN** the compiler SHALL emit a structured denial and the candidate SHALL become `manual-required` unless another valid registered plan is available.

### Requirement: Phase-one verification primitives are fixed and harmless
The primitive registry SHALL expose only bounded SQL injection, command injection, path traversal, and hardcoded-secret primitives for agent-led phase one.

#### Scenario: SQL injection primitive executes
- **WHEN** trusted compilation selects the SQL injection primitive
- **THEN** it SHALL use controlled SQLite setup/input and observe parameter binding or structured query results without targeting an external database.

#### Scenario: Command injection primitive executes
- **WHEN** trusted compilation selects the command injection primitive
- **THEN** it SHALL use a subprocess/argv hook, observe shell behavior, and use only a harmless marker inside the sandbox.

#### Scenario: Path traversal primitive executes
- **WHEN** trusted compilation selects the path traversal primitive
- **THEN** it SHALL use a controlled root, registered path transformations, and an out-of-bounds observation without reading arbitrary host files.

#### Scenario: Hardcoded-secret primitive evaluates
- **WHEN** trusted compilation selects the hardcoded-secret primitive
- **THEN** it SHALL combine literal source, format or entropy, test/example exclusion, and configuration-override evidence without contacting a credential provider.

### Requirement: Trusted execution and Judge own confirmation
Executable verification artifacts SHALL run through the existing bounded sandbox and validation/Judge controls, and neither Analysis nor Verification model output SHALL set the final finding status.

#### Scenario: Safe primitive confirms behavior
- **WHEN** sandbox observations satisfy the registered class-specific success predicate and Judge accepts the evidence
- **THEN** the finding MAY become confirmed with independent verification, plan, attempt, observation, and Judge refs.

#### Scenario: Static-semantic secret is confirmed
- **WHEN** dual evidence and the hardcoded-secret semantic primitive satisfy all trusted predicates
- **THEN** Judge MAY confirm the finding with `verification_type=static-semantic` and no sandbox execution.

#### Scenario: Verification is unsafe or inconclusive
- **WHEN** compilation, sandboxing, observation, or Judge cannot safely establish the claim
- **THEN** the result SHALL be `manual-required`, rejected, or failed according to trusted status rules and SHALL NOT be model-confirmed.

### Requirement: Typed-edit repair remains subordinate to the trusted plan
The existing bounded typed-edit PoC repair loop SHALL be available only after a trusted initial executable harness fails and SHALL remain constrained by the original plan, primitive registry, edit policy, attempt budget, sandbox, and Judge.

#### Scenario: Initial trusted harness fails repairably
- **WHEN** a compiled harness fails for a repair-eligible structural reason
- **THEN** Verification MAY request bounded typed edits and trusted code SHALL reassemble and revalidate the artifact before another sandbox attempt.

#### Scenario: Repair attempts to widen authority
- **WHEN** a repair edit introduces new code authority, a command, new path, external network, unregistered primitive, or changed claim
- **THEN** repair policy SHALL reject the edit and preserve the failed or manual-required result.
