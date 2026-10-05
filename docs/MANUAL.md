# VulnHGNN 2.0 SecureCC — User Manual

## 1. Overview

VulnHGNN 2.0 SecureCC is a local-first C/C++ security toolchain.

Core pipeline:

```text
C/C++ Source
    ↓
Security Analysis
    ↓
Localization
    ↓
Evidence
    ↓
Repair
    ↓
Verification
    ↓
Clang / LLVM
    ↓
Hardened Binary
    ↓
Protection + Measurement
```

Current supported vulnerability classes:

- CWE-190 — Integer Overflow
- CWE-191 — Integer Underflow
- CWE-369 — Divide by Zero
- CWE-476 — NULL Pointer Dereference

Security acceptance is based on deterministic analysis and verification rather than an unverified generated repair.

---

## 2. Requirements

### Operating system

GNU/Linux is the primary validated environment.

### Python

Python 3.12 or newer.

```bash
python --version
```

### Clang / LLVM

Clang and LLVM are required.

```bash
clang --version
```

The current validated development environment uses Clang/LLVM 18.

### ELF tools

```bash
file --version
readelf --version
```

---

## 3. Install on another computer

Clone the repository:

```bash
git clone <YOUR_REPOSITORY_URL>
cd VulnHGNN
```

Replace `<YOUR_REPOSITORY_URL>` with the actual Git repository URL.

Check:

```bash
git status
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install VulnHGNN:

```bash
python -m pip install -e . --no-deps
```

Verify:

```bash
command -v securecc
securecc --version
securecc --help
```

Expected version:

```text
VulnHGNN 2.0 SecureCC 2.0.0
```

The current development metadata may also display:

```text
release : development
```

---

## 4. First installation test

Run:

```bash
securecc scan test_files/
```

Then run the complete benchmark:

```bash
securecc benchmark test_files/
```

A successful benchmark ends with:

```text
FINAL STATUS : VULNHGNN_2.0_VERIFIED
```

Run the complete regression suite:

```bash
./tests/regression_all.sh
```

A successful regression ends with:

```text
FINAL STATUS : VULNHGNN_2.0_REGRESSION_VERIFIED
```

---

## 5. CLI commands

The current CLI contains:

```text
build
report
scan
fix
verify
explain
diagnose
harden
protect
learn
benchmark
```

Show help:

```bash
securecc --help
```

Show version:

```bash
securecc --version
```

---

## 6. Scan

Scan one source:

```bash
securecc scan test_files/test_02_cwe190.c
```

Scan a directory:

```bash
securecc scan test_files/
```

JSON output:

```bash
securecc scan test_files/ --format json
```

The scan reports files scanned, findings, CWE counts, failures, and per-file results.

---

## 7. Explain

Generate an evidence-first explanation:

```bash
securecc explain test_files/test_02_cwe190.c
```

JSON:

```bash
securecc explain test_files/test_02_cwe190.c --format json
```

Explanations can contain:

- CWE
- severity
- vulnerable operation
- function
- basic block
- LLVM node
- data-flow evidence
- root cause
- security impact
- repair strategy
- verification information

---

## 8. Diagnose

Generate developer-facing diagnostics:

```bash
securecc diagnose test_files/test_02_cwe190.c
```

JSON:

```bash
securecc diagnose test_files/test_02_cwe190.c --format json
```

Diagnostic artifacts are stored under:

```text
build/evidence/
```

---

## 9. Fix

Run the repair pipeline:

```bash
securecc fix test_files/
```

A repair is not automatically accepted because the source changed.

The repaired result must pass the verification pipeline.

---

## 10. Verify

Verify a project:

```bash
securecc verify test_files/
```

JSON:

```bash
securecc verify test_files/ --format json
```

Verification can include:

```text
compilation
hardening
runtime verification
behavior verification
security re-analysis
provenance validation
verification gate
```

A fully verified project reports:

```text
PROJECT_VERIFY_VERIFIED
```

---

## 11. Behavior oracle

Behavior expectations are stored in:

```text
configs/behavior.json
```

The behavior oracle defines expected:

- stdin
- stdout
- stderr
- exit code

The repaired program is compared against the explicit behavioral contract.

---

## 12. Secure build

Build a secure binary:

```bash
securecc build <source>
```

Example:

```bash
securecc build test_files/test_01_clean.c
```

Successful secure builds generate provenance information.

---

## 13. Harden

Run the hardening pipeline:

```bash
securecc harden <source>
```

Hardening audits properties including:

- ELF
- PIE
- RELRO
- BIND_NOW
- NX stack
- stack protector
- configured Fortify-related checks

---

## 14. Binary verification

Binary verification can check:

- binary integrity
- source integrity
- security re-analysis
- hardening
- runtime behavior
- verification gate
- provenance

Do not modify a verified binary or its associated source without verifying again.

---

## 15. Protect

Current protection profiles:

```text
strip-unneeded
strip-debug
```

Use:

```bash
securecc protect <binary>
```

Protection is accepted only when:

1. transformation succeeds,
2. hardening is preserved,
3. behavior is preserved.

Protection artifacts are stored under:

```text
build/protection/
```

---

## 16. Measurement

Protection measurement records:

- number of runs
- minimum
- median
- mean
- maximum
- standard deviation
- binary size before/after
- runtime delta
- behavior preservation
- hardening preservation

Run:

```bash
securecc benchmark test_files/
```

to execute the measurement stage as part of the complete pipeline.

Small runtime differences should be interpreted as controlled process-execution measurements, not universal application-performance conclusions.

---

## 17. Provenance

Secure builds generate provenance manifests containing information such as:

- source path
- source SHA-256
- binary SHA-256
- compiler
- compiler command
- security analysis
- hardening
- build status
- environment

The current manifest schema is version 2.

Binary and source hashes allow later verification to detect tampering.

---

## 18. Artifact layout

Generated artifacts are stored under:

```text
build/
├── evidence/
├── verify/
├── benchmark/
├── measurement/
├── protection/
└── evaluation/
```

These are generated artifacts, not source code.

---

## 19. Security policy

Hardening requirements include:

```text
ELF
PIE
RELRO
BIND_NOW
NX stack
stack protector
Fortify-related checks
```

Verification requirements include:

```text
security re-scan
runtime verification
behavior verification
provenance verification
```

---

## 20. AI/model trust boundary

AI or model output is not treated as the final security authority.

The trust boundary is:

```text
Model suggestion
      ↓
Evidence / candidate action
      ↓
Deterministic verification
      ↓
Security decision
```

Security acceptance comes from reproducible analysis and verification.

---

## 21. Recommended workflow

For a project:

```bash
securecc scan test_files/
securecc fix test_files/
securecc verify test_files/
securecc benchmark test_files/
```

For a single vulnerable file:

```bash
securecc scan test_files/test_02_cwe190.c
securecc explain test_files/test_02_cwe190.c
securecc diagnose test_files/test_02_cwe190.c
```

For a complete pre-release check:

```bash
./tests/regression_all.sh
securecc benchmark test_files/
./tests/final_release_audit.sh
```

---

## 22. Current development machine

For the current validated development environment:

```bash
source ~/Desktop/Dev/Env/bin/activate
cd ~/Desktop/Academics/Automata/VulnHGNN
```

Check:

```bash
securecc --version
```

Because the package is installed in editable mode, the CLI uses the current repository source.

---

## 23. Updating from Git

On another machine:

```bash
cd VulnHGNN
git pull
```

Activate the environment:

```bash
source .venv/bin/activate
```

Reinstall/update the editable package:

```bash
python -m pip install -e . --no-deps
```

Validate:

```bash
securecc --version
./tests/regression_all.sh
```

---

## 24. Troubleshooting

### `securecc: command not found`

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Then reinstall:

```bash
python -m pip install -e . --no-deps
```

Check:

```bash
command -v securecc
```

### Clang not found

Check:

```bash
clang --version
```

Install the appropriate Clang/LLVM package for the Linux distribution.

### Python version too old

Check:

```bash
python --version
```

Python 3.12 or newer is required.

### Regression failure

Run:

```bash
./tests/regression_all.sh
```

Identify the first failing test and run it independently:

```bash
./tests/<failing_test>.sh
```

### Benchmark failure

Run:

```bash
securecc benchmark test_files/
```

The benchmark identifies the failed pipeline stage.

---

## 25. Uninstall

Inside the active virtual environment:

```bash
python -m pip uninstall vulnhgnn-securecc
```

This removes the installed package and CLI from the environment.

The Git repository itself is not deleted.

---

## 26. Source vs generated files

Important source/configuration:

```text
src/
configs/
tests/
test_files/
docs/
pyproject.toml
securecc
```

Generated artifacts:

```text
build/
```

Do not manually delete artifacts while a verification or regression process is running.

---

## 27. Reproduce the validated installation

On a new machine:

```bash
git clone <YOUR_REPOSITORY_URL>
cd VulnHGNN

python3 -m venv .venv
source .venv/bin/activate

python -m pip install -e . --no-deps

securecc --version
securecc --help

./tests/regression_all.sh
securecc benchmark test_files/
```

A successful installation reproduces the core validated VulnHGNN 2.0 workflow.

---

## 28. Current validated project state

The validated project contains:

```text
Project fixtures       : 10
Verified fixtures      : 10
Security findings      : 18
Regression tests       : 11
Regression failures    : 0
Benchmark stages       : 6/6
Behavior fixtures      : 10/10
Protection profiles    : 2/2
```

The final release audit is the project-level validation step.

Run:

```bash
./tests/final_release_audit.sh
```

A successful audit ends with:

```text
FINAL STATUS : VULNHGNN_2.0_RELEASE_AUDIT_VERIFIED
```

---

# VulnHGNN 2.0

**Evidence first. Verification before acceptance.**
