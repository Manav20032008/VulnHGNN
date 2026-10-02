# VulnHGNN 2.0 SecureCC — Security Model

## 1. Design objective

VulnHGNN 2.0 is designed as a security verification pipeline rather than a system that blindly trusts generated fixes or model output.

The core flow is:

```text
C/C++ Source
     │
     ▼
Security Analysis
     │
     ▼
Localization
     │
     ▼
Evidence
     │
     ▼
Repair
     │
     ▼
Verification
     │
     ▼
Clang / LLVM
     │
     ▼
Hardened Binary
     │
     ▼
Protection + Measurement
```

Security acceptance is determined by verifiable artifacts and deterministic checks.

## 2. Deterministic detection

The security detector analyzes LLVM-level program information.

The current detection foundation covers:

- CWE-190 — Integer Overflow
- CWE-191 — Integer Underflow
- CWE-369 — Divide by Zero
- CWE-476 — NULL Pointer Dereference

Detection identifies concrete vulnerable operations rather than relying only on textual pattern matching.

## 3. Localization

A finding is localized through program structure.

Evidence may include:

```text
source
  ↓
function
  ↓
basic block
  ↓
LLVM instruction
  ↓
data-flow / use relationship
```

The localization layer provides the basis for developer-facing explanations and verification.

## 4. Evidence-first explanation

Security explanations are built from analyzed program evidence.

The system records information such as:

- vulnerable instruction
- function
- basic block
- node identifier
- incoming data flow
- allocation origin
- pointer propagation
- null checks
- downstream use

The system avoids inventing source locations, probabilities, or evidence that is not present in the analyzed representation.

## 5. Repair model

Repairs are deterministic transformations for supported vulnerability classes.

A repair is not considered secure merely because the transformed source looks reasonable.

The repaired program must pass subsequent verification.

The principle is:

```text
Repair generated
      ↓
Compile
      ↓
Security re-analysis
      ↓
Runtime verification
      ↓
Behavior verification
      ↓
Verification Gate
```

## 6. Verification Gate

The Verification Gate combines security and behavioral evidence.

Depending on the workflow, verification can include:

- compilation
- hardening
- runtime execution
- expected behavior
- security re-analysis
- provenance integrity

A repair is accepted only when the required verification conditions pass.

## 7. Behavioral verification

Behavioral verification uses explicit expectations.

The behavior oracle can define:

- stdin
- expected stdout
- expected stderr
- expected exit code

This allows the repaired program to be compared against an explicit behavioral contract.

## 8. Runtime sandbox

Runtime verification is executed through a controlled sandbox.

The sandbox provides controls such as:

- execution timeout
- resource limits
- sanitized environment
- controlled input
- network restriction
- temporary execution workspace

Runtime verification is treated as a controlled verification step rather than unrestricted execution.

## 9. Binary hardening

SecureCC audits generated ELF binaries for configured hardening properties.

The hardening model includes checks such as:

- ELF validity
- PIE
- RELRO
- BIND_NOW
- NX stack
- stack protector
- configured Fortify-related requirements

Hardening is evidence that the generated binary satisfies the configured security policy.

## 10. Provenance

Secure builds generate provenance manifests.

The provenance model records information including:

- source path
- source SHA-256
- binary SHA-256
- compiler
- compiler command
- security analysis
- hardening information
- build status
- environment information

Binary and source hashes allow later verification to detect tampering.

## 11. Binary protection

Binary protection operates on an already-built binary.

Supported transformations currently include:

```text
strip-unneeded
strip-debug
```

A protection result is accepted only when:

1. the transformation succeeds,
2. hardening remains valid,
3. behavior is preserved.

Protection evidence also records measurements and hashes.

## 12. Measurement

Protection is measured using repeated controlled executions.

The measurement system records statistics including:

- number of runs
- minimum
- median
- mean
- maximum
- standard deviation
- size before/after
- runtime delta
- behavior preservation
- hardening preservation

Runtime measurements are controlled process-execution measurements. Small differences should therefore be interpreted as measurements of the verification environment rather than as universal application-performance conclusions.

## 13. Security policy

SecureCC exposes policy requirements for:

### Hardening

- ELF
- PIE
- RELRO
- BIND_NOW
- NX stack
- stack protector
- Fortify-related checks

### Verification

- security re-scan
- runtime verification
- behavior verification
- provenance verification

The policy layer provides an explicit machine-readable security contract.

## 14. AI and model trust boundary

AI/model output is not treated as security authority.

Models may assist with:

- explanation
- development
- reasoning
- suggested changes
- developer assistance

Security acceptance remains dependent on deterministic analysis and verification.

The trust boundary is therefore:

```text
Model suggestion
      │
      ▼
Evidence / candidate action
      │
      ▼
Deterministic verification
      │
      ▼
Security decision
```

## 15. Fail-closed principle

When required verification fails, the result must not be presented as verified.

Examples include:

- security verification failure
- behavior mismatch
- provenance mismatch
- hardening failure
- compilation failure
- runtime verification failure

These conditions must remain distinguishable from a verified result.

## 16. Core security principle

VulnHGNN 2.0 follows:

> Evidence first. Verification before acceptance.

The system is designed so that security claims are backed by reproducible artifacts rather than trust in an unverified transformation.
