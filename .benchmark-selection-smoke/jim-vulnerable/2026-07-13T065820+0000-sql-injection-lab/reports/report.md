# Agentic Security Audit Report

## Executive Summary

- Target: .benchmark-selection/sql-injection-lab
- Findings: 13
- Validated/accepted: 13
- Confirmed: 0
- Likely: 13
- Rejected: 0
- Manual required: 0

## Verification Evidence

### Potential SQL injection

- ID: F-4fbe4bb5c565
- Status: likely
- Reason: Static evidence reviewed; no runtime proof-of-concept executed.
- Class: sql-injection
- Location: python/vulnerable_app.py:199
- Validation level: static-only
- Timed out: False
- Repair attempts: 0
- Provisional status: likely
- Final status: likely
- Target integrity: unchanged (changed=0, added=0, removed=0)
- stdout: 
- stderr: 
- Artifact refs: TCR-b66c18887fcd, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\dataflow\traces\DFT-74796f4ccedb.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-before.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-after.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-integrity-comparison.json

### Potential SQL injection

- ID: F-0a29eaf9aee3
- Status: likely
- Reason: Static evidence reviewed; no runtime proof-of-concept executed.
- Class: sql-injection
- Location: python/vulnerable_app.py:265
- Validation level: static-only
- Timed out: False
- Repair attempts: 0
- Provisional status: likely
- Final status: likely
- Target integrity: unchanged (changed=0, added=0, removed=0)
- stdout: 
- stderr: 
- Artifact refs: TCR-b66c18887fcd, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\dataflow\traces\DFT-8a26dbb869be.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-before.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-after.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-integrity-comparison.json

### Potential SQL injection

- ID: F-adc1f7a91d77
- Status: likely
- Reason: Static evidence reviewed; no runtime proof-of-concept executed.
- Class: sql-injection
- Location: python/vulnerable_app.py:76
- Validation level: static-only
- Timed out: False
- Repair attempts: 0
- Provisional status: likely
- Final status: likely
- Target integrity: unchanged (changed=0, added=0, removed=0)
- stdout: 
- stderr: 
- Artifact refs: TCR-5a0e3f4ae7d5, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-before.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-after.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-integrity-comparison.json

### Potential hardcoded secret

- ID: F-b6c46718bc0b
- Status: likely
- Reason: Static evidence reviewed; no runtime proof-of-concept executed.
- Class: hardcoded-secret
- Location: python/vulnerable_app.py:76
- Validation level: static-only
- Timed out: False
- Repair attempts: 0
- Provisional status: likely
- Final status: likely
- Target integrity: unchanged (changed=0, added=0, removed=0)
- stdout: 
- stderr: 
- Artifact refs: TCR-5a0e3f4ae7d5, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-before.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-after.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-integrity-comparison.json

### Potential SQL injection

- ID: F-c67f9889d5a8
- Status: likely
- Reason: Static evidence reviewed; no runtime proof-of-concept executed.
- Class: sql-injection
- Location: python/vulnerable_app.py:134
- Validation level: static-only
- Timed out: False
- Repair attempts: 0
- Provisional status: likely
- Final status: likely
- Target integrity: unchanged (changed=0, added=0, removed=0)
- stdout: 
- stderr: 
- Artifact refs: TCR-5a0e3f4ae7d5, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-before.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-after.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-integrity-comparison.json

### Potential SQL injection

- ID: F-16b59c5facdd
- Status: likely
- Reason: Static evidence reviewed; no runtime proof-of-concept executed.
- Class: sql-injection
- Location: python/vulnerable_app.py:174
- Validation level: static-only
- Timed out: False
- Repair attempts: 0
- Provisional status: likely
- Final status: likely
- Target integrity: unchanged (changed=0, added=0, removed=0)
- stdout: 
- stderr: 
- Artifact refs: TCR-5a0e3f4ae7d5, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-before.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-after.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-integrity-comparison.json

### Potential SQL injection

- ID: F-1cf184695530
- Status: likely
- Reason: Static evidence reviewed; no runtime proof-of-concept executed.
- Class: sql-injection
- Location: python/vulnerable_app.py:175
- Validation level: static-only
- Timed out: False
- Repair attempts: 0
- Provisional status: likely
- Final status: likely
- Target integrity: unchanged (changed=0, added=0, removed=0)
- stdout: 
- stderr: 
- Artifact refs: TCR-5a0e3f4ae7d5, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-before.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-after.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-integrity-comparison.json

### Potential SQL injection

- ID: F-a3b25cf4450f
- Status: likely
- Reason: Static evidence reviewed; no runtime proof-of-concept executed.
- Class: sql-injection
- Location: python/vulnerable_app.py:176
- Validation level: static-only
- Timed out: False
- Repair attempts: 0
- Provisional status: likely
- Final status: likely
- Target integrity: unchanged (changed=0, added=0, removed=0)
- stdout: 
- stderr: 
- Artifact refs: TCR-5a0e3f4ae7d5, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-before.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-after.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-integrity-comparison.json

### Potential SQL injection

- ID: F-5e4923963653
- Status: likely
- Reason: Static evidence reviewed; no runtime proof-of-concept executed.
- Class: sql-injection
- Location: python/vulnerable_app.py:177
- Validation level: static-only
- Timed out: False
- Repair attempts: 0
- Provisional status: likely
- Final status: likely
- Target integrity: unchanged (changed=0, added=0, removed=0)
- stdout: 
- stderr: 
- Artifact refs: TCR-5a0e3f4ae7d5, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-before.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-after.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-integrity-comparison.json

### Potential SQL injection

- ID: F-51ea1821ce61
- Status: likely
- Reason: Static evidence reviewed; no runtime proof-of-concept executed.
- Class: sql-injection
- Location: python/vulnerable_app.py:194
- Validation level: static-only
- Timed out: False
- Repair attempts: 0
- Provisional status: likely
- Final status: likely
- Target integrity: unchanged (changed=0, added=0, removed=0)
- stdout: 
- stderr: 
- Artifact refs: TCR-5a0e3f4ae7d5, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-before.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-after.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-integrity-comparison.json

### Potential SQL injection

- ID: F-11ca02a48cfc
- Status: likely
- Reason: Static evidence reviewed; no runtime proof-of-concept executed.
- Class: sql-injection
- Location: python/vulnerable_app.py:259
- Validation level: static-only
- Timed out: False
- Repair attempts: 0
- Provisional status: likely
- Final status: likely
- Target integrity: unchanged (changed=0, added=0, removed=0)
- stdout: 
- stderr: 
- Artifact refs: TCR-5a0e3f4ae7d5, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-before.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-after.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-integrity-comparison.json

### Potential SQL injection

- ID: F-ea94dbeb2e28
- Status: likely
- Reason: Static evidence reviewed; no runtime proof-of-concept executed.
- Class: sql-injection
- Location: python/vulnerable_app.py:312
- Validation level: static-only
- Timed out: False
- Repair attempts: 0
- Provisional status: likely
- Final status: likely
- Target integrity: unchanged (changed=0, added=0, removed=0)
- stdout: 
- stderr: 
- Artifact refs: TCR-5a0e3f4ae7d5, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-before.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-after.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-integrity-comparison.json

### Potential SQL injection

- ID: F-7e390cdbf38c
- Status: likely
- Reason: Static evidence reviewed; no runtime proof-of-concept executed.
- Class: sql-injection
- Location: python/vulnerable_app.py:370
- Validation level: static-only
- Timed out: False
- Repair attempts: 0
- Provisional status: likely
- Final status: likely
- Target integrity: unchanged (changed=0, added=0, removed=0)
- stdout: 
- stderr: 
- Artifact refs: TCR-5a0e3f4ae7d5, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-before.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-manifest-after.json, .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\verification\target-integrity-comparison.json

## Findings

### Potential SQL injection

- ID: F-4fbe4bb5c565
- Class: sql-injection
- Severity: high
- Confidence: 0.86
- Location: python/vulnerable_app.py:199
- Source category: product-code
- Verification status: likely
- Validation: static-only
- Remediation: Use parameterized queries and avoid string interpolation for SQL.
- Runtime task refs: TSK-d33fa394154e, TSK-28961431ac92, TSK-ead3798c156f, TSK-8cdc21878b2d, TSK-502fc460064f, TSK-e8cf1e1b827c

#### Dataflow Evidence
- Source: python/vulnerable_app.py:189 request.args.get('id', '1')
- Sink: python/vulnerable_app.py:199 db.execute(query)
- Sanitizer: absent
- Trace refs: .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\dataflow\traces\DFT-74796f4ccedb.json

#### LLM Influence
- Decision source: deterministic

### Potential SQL injection

- ID: F-0a29eaf9aee3
- Class: sql-injection
- Severity: high
- Confidence: 0.86
- Location: python/vulnerable_app.py:265
- Source category: product-code
- Verification status: likely
- Validation: static-only
- Remediation: Use parameterized queries and avoid string interpolation for SQL.
- Runtime task refs: TSK-d33fa394154e, TSK-28961431ac92, TSK-ead3798c156f, TSK-8cdc21878b2d, TSK-502fc460064f, TSK-e8cf1e1b827c

#### Dataflow Evidence
- Source: python/vulnerable_app.py:255 request.args.get('id', '1')
- Sink: python/vulnerable_app.py:265 db.execute(query)
- Sanitizer: absent
- Trace refs: .benchmark-selection-smoke\jim-vulnerable\2026-07-13T065820+0000-sql-injection-lab\dataflow\traces\DFT-8a26dbb869be.json

#### LLM Influence
- Decision source: deterministic

### Potential SQL injection

- ID: F-adc1f7a91d77
- Class: sql-injection
- Severity: high
- Confidence: 0.72
- Location: python/vulnerable_app.py:76
- Source category: product-code
- Verification status: likely
- Validation: static-only
- Remediation: Use parameterized queries and avoid string interpolation for SQL.
- Runtime task refs: TSK-d33fa394154e, TSK-28961431ac92, TSK-ead3798c156f, TSK-8cdc21878b2d, TSK-502fc460064f, TSK-e8cf1e1b827c

#### LLM Influence
- Decision source: deterministic

### Potential hardcoded secret

- ID: F-b6c46718bc0b
- Class: hardcoded-secret
- Severity: medium
- Confidence: 0.72
- Location: python/vulnerable_app.py:76
- Source category: product-code
- Verification status: likely
- Validation: static-only
- Remediation: Move secrets into a managed secret store and rotate exposed credentials.
- Runtime task refs: TSK-d33fa394154e, TSK-28961431ac92, TSK-ead3798c156f, TSK-8cdc21878b2d, TSK-502fc460064f, TSK-e8cf1e1b827c

#### LLM Influence
- Decision source: deterministic

### Potential SQL injection

- ID: F-c67f9889d5a8
- Class: sql-injection
- Severity: high
- Confidence: 0.72
- Location: python/vulnerable_app.py:134
- Source category: product-code
- Verification status: likely
- Validation: static-only
- Remediation: Use parameterized queries and avoid string interpolation for SQL.
- Runtime task refs: TSK-d33fa394154e, TSK-28961431ac92, TSK-ead3798c156f, TSK-8cdc21878b2d, TSK-502fc460064f, TSK-e8cf1e1b827c

#### LLM Influence
- Decision source: deterministic

### Potential SQL injection

- ID: F-16b59c5facdd
- Class: sql-injection
- Severity: high
- Confidence: 0.72
- Location: python/vulnerable_app.py:174
- Source category: product-code
- Verification status: likely
- Validation: static-only
- Remediation: Use parameterized queries and avoid string interpolation for SQL.
- Runtime task refs: TSK-d33fa394154e, TSK-28961431ac92, TSK-ead3798c156f, TSK-8cdc21878b2d, TSK-502fc460064f, TSK-e8cf1e1b827c

#### LLM Influence
- Decision source: deterministic

### Potential SQL injection

- ID: F-1cf184695530
- Class: sql-injection
- Severity: high
- Confidence: 0.72
- Location: python/vulnerable_app.py:175
- Source category: product-code
- Verification status: likely
- Validation: static-only
- Remediation: Use parameterized queries and avoid string interpolation for SQL.
- Runtime task refs: TSK-d33fa394154e, TSK-28961431ac92, TSK-ead3798c156f, TSK-8cdc21878b2d, TSK-502fc460064f, TSK-e8cf1e1b827c

#### LLM Influence
- Decision source: deterministic

### Potential SQL injection

- ID: F-a3b25cf4450f
- Class: sql-injection
- Severity: high
- Confidence: 0.72
- Location: python/vulnerable_app.py:176
- Source category: product-code
- Verification status: likely
- Validation: static-only
- Remediation: Use parameterized queries and avoid string interpolation for SQL.
- Runtime task refs: TSK-d33fa394154e, TSK-28961431ac92, TSK-ead3798c156f, TSK-8cdc21878b2d, TSK-502fc460064f, TSK-e8cf1e1b827c

#### LLM Influence
- Decision source: deterministic

### Potential SQL injection

- ID: F-5e4923963653
- Class: sql-injection
- Severity: high
- Confidence: 0.72
- Location: python/vulnerable_app.py:177
- Source category: product-code
- Verification status: likely
- Validation: static-only
- Remediation: Use parameterized queries and avoid string interpolation for SQL.
- Runtime task refs: TSK-d33fa394154e, TSK-28961431ac92, TSK-ead3798c156f, TSK-8cdc21878b2d, TSK-502fc460064f, TSK-e8cf1e1b827c

#### LLM Influence
- Decision source: deterministic

### Potential SQL injection

- ID: F-51ea1821ce61
- Class: sql-injection
- Severity: high
- Confidence: 0.72
- Location: python/vulnerable_app.py:194
- Source category: product-code
- Verification status: likely
- Validation: static-only
- Remediation: Use parameterized queries and avoid string interpolation for SQL.
- Runtime task refs: TSK-d33fa394154e, TSK-28961431ac92, TSK-ead3798c156f, TSK-8cdc21878b2d, TSK-502fc460064f, TSK-e8cf1e1b827c

#### LLM Influence
- Decision source: deterministic

### Potential SQL injection

- ID: F-11ca02a48cfc
- Class: sql-injection
- Severity: high
- Confidence: 0.72
- Location: python/vulnerable_app.py:259
- Source category: product-code
- Verification status: likely
- Validation: static-only
- Remediation: Use parameterized queries and avoid string interpolation for SQL.
- Runtime task refs: TSK-d33fa394154e, TSK-28961431ac92, TSK-ead3798c156f, TSK-8cdc21878b2d, TSK-502fc460064f, TSK-e8cf1e1b827c

#### LLM Influence
- Decision source: deterministic

### Potential SQL injection

- ID: F-ea94dbeb2e28
- Class: sql-injection
- Severity: high
- Confidence: 0.72
- Location: python/vulnerable_app.py:312
- Source category: product-code
- Verification status: likely
- Validation: static-only
- Remediation: Use parameterized queries and avoid string interpolation for SQL.
- Runtime task refs: TSK-d33fa394154e, TSK-28961431ac92, TSK-ead3798c156f, TSK-8cdc21878b2d, TSK-502fc460064f, TSK-e8cf1e1b827c

#### LLM Influence
- Decision source: deterministic

### Potential SQL injection

- ID: F-7e390cdbf38c
- Class: sql-injection
- Severity: high
- Confidence: 0.72
- Location: python/vulnerable_app.py:370
- Source category: product-code
- Verification status: likely
- Validation: static-only
- Remediation: Use parameterized queries and avoid string interpolation for SQL.
- Runtime task refs: TSK-d33fa394154e, TSK-28961431ac92, TSK-ead3798c156f, TSK-8cdc21878b2d, TSK-502fc460064f, TSK-e8cf1e1b827c

#### LLM Influence
- Decision source: deterministic
