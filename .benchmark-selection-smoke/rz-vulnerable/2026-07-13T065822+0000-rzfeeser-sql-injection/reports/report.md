# Agentic Security Audit Report

## Executive Summary

- Target: .benchmark-selection/rzfeeser-sql-injection
- Findings: 3
- Validated/accepted: 3
- Confirmed: 0
- Likely: 3
- Rejected: 0
- Manual required: 0

## Verification Evidence

### Potential SQL injection

- ID: F-b9b7ad12aeca
- Status: likely
- Reason: Static evidence reviewed; no runtime proof-of-concept executed.
- Class: sql-injection
- Location: main_vulnerable.py:23
- Validation level: static-only
- Timed out: False
- Repair attempts: 0
- Provisional status: likely
- Final status: likely
- Target integrity: unchanged (changed=0, added=0, removed=0)
- stdout: 
- stderr: 
- Artifact refs: TCR-8f3739e7af25, .benchmark-selection-smoke\rz-vulnerable\2026-07-13T065822+0000-rzfeeser-sql-injection\dataflow\traces\DFT-49753e7d82ef.json, .benchmark-selection-smoke\rz-vulnerable\2026-07-13T065822+0000-rzfeeser-sql-injection\verification\target-manifest-before.json, .benchmark-selection-smoke\rz-vulnerable\2026-07-13T065822+0000-rzfeeser-sql-injection\verification\target-manifest-after.json, .benchmark-selection-smoke\rz-vulnerable\2026-07-13T065822+0000-rzfeeser-sql-injection\verification\target-integrity-comparison.json

### Potential SQL injection

- ID: F-ba65738b64e8
- Status: likely
- Reason: Static evidence reviewed; no runtime proof-of-concept executed.
- Class: sql-injection
- Location: main_vulnerable.py:22
- Validation level: static-only
- Timed out: False
- Repair attempts: 0
- Provisional status: likely
- Final status: likely
- Target integrity: unchanged (changed=0, added=0, removed=0)
- stdout: 
- stderr: 
- Artifact refs: TCR-57ed69dfd1b4, .benchmark-selection-smoke\rz-vulnerable\2026-07-13T065822+0000-rzfeeser-sql-injection\verification\target-manifest-before.json, .benchmark-selection-smoke\rz-vulnerable\2026-07-13T065822+0000-rzfeeser-sql-injection\verification\target-manifest-after.json, .benchmark-selection-smoke\rz-vulnerable\2026-07-13T065822+0000-rzfeeser-sql-injection\verification\target-integrity-comparison.json

### Potential hardcoded secret

- ID: F-d639010d4bf2
- Status: likely
- Reason: Static evidence reviewed; no runtime proof-of-concept executed.
- Class: hardcoded-secret
- Location: main_vulnerable.py:22
- Validation level: static-only
- Timed out: False
- Repair attempts: 0
- Provisional status: likely
- Final status: likely
- Target integrity: unchanged (changed=0, added=0, removed=0)
- stdout: 
- stderr: 
- Artifact refs: TCR-57ed69dfd1b4, .benchmark-selection-smoke\rz-vulnerable\2026-07-13T065822+0000-rzfeeser-sql-injection\verification\target-manifest-before.json, .benchmark-selection-smoke\rz-vulnerable\2026-07-13T065822+0000-rzfeeser-sql-injection\verification\target-manifest-after.json, .benchmark-selection-smoke\rz-vulnerable\2026-07-13T065822+0000-rzfeeser-sql-injection\verification\target-integrity-comparison.json

## Findings

### Potential SQL injection

- ID: F-b9b7ad12aeca
- Class: sql-injection
- Severity: high
- Confidence: 0.86
- Location: main_vulnerable.py:23
- Source category: product-code
- Verification status: likely
- Validation: static-only
- Remediation: Use parameterized queries and avoid string interpolation for SQL.
- Runtime task refs: TSK-d419efdb168d, TSK-2d897190cff4, TSK-0282ccc9cc73, TSK-cf8966b2716e, TSK-4c90844163dc, TSK-151ac6f0a7f5

#### Dataflow Evidence
- Source: main_vulnerable.py:14 request.form['username']
- Sink: main_vulnerable.py:23 cursor.execute(query)
- Sanitizer: absent
- Trace refs: .benchmark-selection-smoke\rz-vulnerable\2026-07-13T065822+0000-rzfeeser-sql-injection\dataflow\traces\DFT-49753e7d82ef.json

#### LLM Influence
- Decision source: deterministic

### Potential SQL injection

- ID: F-ba65738b64e8
- Class: sql-injection
- Severity: high
- Confidence: 0.72
- Location: main_vulnerable.py:22
- Source category: product-code
- Verification status: likely
- Validation: static-only
- Remediation: Use parameterized queries and avoid string interpolation for SQL.
- Runtime task refs: TSK-d419efdb168d, TSK-2d897190cff4, TSK-0282ccc9cc73, TSK-cf8966b2716e, TSK-4c90844163dc, TSK-151ac6f0a7f5

#### LLM Influence
- Decision source: deterministic

### Potential hardcoded secret

- ID: F-d639010d4bf2
- Class: hardcoded-secret
- Severity: medium
- Confidence: 0.72
- Location: main_vulnerable.py:22
- Source category: product-code
- Verification status: likely
- Validation: static-only
- Remediation: Move secrets into a managed secret store and rotate exposed credentials.
- Runtime task refs: TSK-d419efdb168d, TSK-2d897190cff4, TSK-0282ccc9cc73, TSK-cf8966b2716e, TSK-4c90844163dc, TSK-151ac6f0a7f5

#### LLM Influence
- Decision source: deterministic
