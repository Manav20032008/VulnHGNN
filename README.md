# VulnHGNN 2.0 — SecureCC

**VulnHGNN 2.0 SecureCC** is a local-first C/C++ security toolchain designed to detect, localize, explain, repair, verify, harden, and protect vulnerable C/C++ programs.

The 2.0 system moves beyond the original ML-focused prototype into a deterministic security pipeline where automated analysis and repair are accepted only after verification.

---

## Security Pipeline

```text
C/C++ Source
     │
     ▼
┌───────────────┐
│    Analyze    │
└───────┬───────┘
        ▼
┌───────────────┐
│    Detect     │
└───────┬───────┘
        ▼
┌───────────────┐
│   Localize    │
└───────┬───────┘
        ▼
┌───────────────┐
│    Explain    │
└───────┬───────┘
        ▼
┌───────────────┐
│     Repair    │
└───────┬───────┘
        ▼
┌───────────────┐
│    Verify     │
└───────┬───────┘
        ▼
┌───────────────┐
│    Harden     │
└───────┬───────┘
        ▼
┌───────────────┐
│    Protect    │
└───────┬───────┘
        ▼
  Verified Binary
        +
 Evidence / Reports
```

The central design principle is:

> **Automated analysis may produce evidence and proposed changes, but verification is the security authority.**

---

# Features

## Vulnerability Detection

The deterministic detector supports (each with a `test_files/test_*` fixture; see `/api/vulnerability-catalog` in the web UI):

| CWE | Title | Typical compiler stage |
|-----|--------|-------------------------|
| CWE-190 | Integer Overflow | LLVM IR graph |
| CWE-191 | Integer Underflow | LLVM IR graph |
| CWE-369 | Divide by Zero | LLVM IR graph |
| CWE-476 | NULL Pointer Dereference | LLVM IR graph |
| CWE-121 | Stack-based Buffer Overflow | LLVM IR graph |
| CWE-134 | Externally-Controlled Format String | LLVM IR graph |
| CWE-457 | Uninitialized Variable | Clang `-Wall` diagnostic |
| CWE-787 | Out-of-bounds Write | Clang `-Wall` diagnostic |
| CWE-122 | Heap-based Buffer Overflow | LLVM IR graph |
| CWE-125 | Out-of-bounds Read | Clang bounds + IR GEP heuristics |
| CWE-789 | Excessive allocation (OOM risk) | LLVM IR graph |
| CWE-400 | Uncontrolled resource / OOM | LLVM IR graph |
| CWE-415 | Double free | LLVM IR graph |
| CWE-416 | Use after free | LLVM IR graph |
| CWE-401 | Memory leak | LLVM IR graph |
| CWE-835 | Infinite loop | LLVM IR CFG (+ Clang when reported) |
| CWE-833 | Deadlock (nested locks) | LLVM IR graph |
| CWE-667 | Double mutex lock | LLVM IR graph |

Multi-vulnerability fixtures: `test_06`–`test_10`, `test_15`–`test_16`, `test_23`, `test_27_logic_combo.c`. Per-CWE fixtures: `test_11`–`test_26` (see `/api/vulnerability-catalog`).

Every finding includes `compiler_stage` / `compiler_stage_label` (frontend error, compiler warning, LLVM IR emission, or IR graph analysis).

---

## Vulnerability Localization

Findings are localized to:

- LLVM instruction
- Basic block
- Function
- Relevant graph/data-flow context
- Evidence supporting the finding

---

## Automated Repair

SecureCC can generate verified repairs for supported vulnerabilities.

Repair strategies include:

- Checked arithmetic for integer overflow/underflow
- Zero-divisor protection
- NULL-pointer protection
- Memory/string handling protection

A repair is not accepted merely because a patch was generated.

It must pass the verification pipeline.

---

## Verification

SecureCC verifies repaired programs through multiple stages:

- Compilation
- Security re-analysis
- Runtime verification
- Behavioral verification
- Hardening verification
- Provenance validation

Behavior is accepted only when it has been explicitly verified.

---

## Explainability

SecureCC produces evidence-first explanations containing:

- CWE classification
- Vulnerable operation
- Root cause
- Security impact
- Local graph context
- Repair strategy
- Verification information

The explanation is derived from deterministic analysis evidence.

---

## Binary Hardening

SecureCC can build hardened C/C++ binaries using Clang/LLVM.

The hardening system checks properties including:

- ELF format
- PIE
- RELRO
- BIND_NOW
- NX stack
- Stack protector
- Fortify requirements

Hardening results are included in the generated evidence.

---

## Binary Protection

SecureCC supports binary protection profiles including:

- `strip-unneeded`
- `strip-debug`

Protection is followed by verification of:

- Transformation
- Hardening
- Runtime behavior
- Evidence

---

## Sandbox Verification

Runtime verification uses a controlled execution environment with restrictions such as:

- Execution timeout
- CPU limits
- Memory limits
- Controlled stdin
- Sanitized environment
- Network restrictions
- Temporary execution workspace

---

## Provenance

SecureCC maintains provenance information for verified artifacts.

The provenance system records information such as:

- Source hash
- Binary hash
- Environment information
- Validation information

Tampering with verified source or binary artifacts is detected during provenance verification.

---

# Current Validation

The current project validation suite contains:

- 10 C/C++ security fixtures
- 18 detected findings
- 9 files requiring repair
- 10 verified files
- 10/10 behavioral fixtures

The complete benchmark covers:

```text
Detection
Repair
Verification
Evidence
Regression
Measurement
```

The validated benchmark target is:

```text
Stages passed : 6/6
```

The project also contains an 11-test regression suite covering:

- CLI
- Artifacts
- Policy
- Project verification
- Provenance
- Provenance tampering
- Evidence
- Diagnostics
- Binary protection
- Measurement
- Packaging

---

# Requirements

## Operating System

SecureCC is designed for a Unix-like development environment.

The project has been developed and tested on:

```text
Pop!_OS / Ubuntu-based Linux
```

## Python

Required:

```text
Python >= 3.12
```

Check:

```bash
python3 --version
```

## Clang / LLVM

SecureCC requires Clang/LLVM for C/C++ compilation and LLVM IR generation.

Check:

```bash
clang --version
```

The development environment currently uses:

```text
Clang/LLVM 18.1.3
```

---

# Installation

Clone the repository:

```bash
git clone <repository-url>
cd VulnHGNN
```

Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Upgrade packaging tools:

```bash
python -m pip install --upgrade pip setuptools
```

Install the project in editable mode:

```bash
python -m pip install -e . --no-deps
```

The `securecc` command should then be available:

```bash
securecc --version
```

Expected format:

```text
VulnHGNN 2.0 SecureCC 2.0.0
release : development
```

---

# CLI

SecureCC provides the following commands:

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
web
aai-security
agent
```

View the complete command help:

```bash
securecc --help
```

---

# Basic Usage

## Scan

```bash
securecc scan test_files/test_02_cwe190.c
```

## Explain

```bash
securecc explain test_files/test_02_cwe190.c
```

## Fix

```bash
securecc fix test_files/
```

## Verify

```bash
securecc verify test_files/
```

## Diagnose

```bash
securecc diagnose test_files/test_02_cwe190.c
```

## Build

```bash
securecc build test_files/test_01_clean.c
```

## Harden

```bash
securecc harden <binary>
```

## Protect

```bash
securecc protect <binary> --profile strip-unneeded
```

## Benchmark

```bash
securecc benchmark test_files/
```

## Web dashboard

Interactive UI for scan, localization, explain, diagnostics, learn, optional repair, IR graph, and raw JSON:

```bash
pip install flask
securecc web
```

Open [http://127.0.0.1:5050](http://127.0.0.1:5050) in your browser.

### Journey mode (step-by-step)

In the sidebar, switch **Classic → Journey**, pick or upload a `.c` file, then **Start journey**. The UI walks through compile → IR parse → graph → detection → per-finding review → repair plan. **Approve & verify fix** runs the deterministic repair pipeline; **Continue** advances only when you choose. Use **Ask** (or optional text-to-speech) for grounded explanations such as “How did you catch this?”

API: `POST /api/journey/start` `{ "path": "..." }`, `POST /api/journey/advance` `{ "session_id", "action": "continue|approve_fix|reject_fix|skip_fix|restart|ask", "question"?: "..." }`.

## Agentic AI security (PBL)

Simulate prompt-injection / policy-bypass attacks, block malicious tool use, and print detection metrics:

```bash
python3 aai_security_demo.py
# or
securecc aai-security
```

See `docs/PBL_AAI_SECURITY.md` and artifacts under `build/aai_security/`.

### Groq agent

```bash
cp .env.example .env
# Edit .env and set GROQ_API_KEY=...
python -m pip install groq python-dotenv
securecc agent test_files/test_02_cwe190.c -m "Scan and explain the security issues."
```

`securecc` loads `.env` from the project root automatically (variables already set in the shell take precedence). Or use the **AI analysis** tab in `securecc web`.

---

# Project Structure

```text
VulnHGNN/
│
├── configs/
│   └── behavior.json
│
├── data/
│   ├── ir/
│   └── parsed_ir/
│
├── docs/
│   ├── CLI.md
│   ├── INSTALL.md
│   ├── MANUAL.md
│   ├── RELEASE_CHECKLIST.md
│   └── SECURITY_MODEL.md
│
├── src/
│   ├── V2/
│   │   ├── analysis/
│   │   ├── compilation/
│   │   ├── detection/
│   │   ├── explain/
│   │   ├── hardening/
│   │   ├── localization/
│   │   ├── model/
│   │   ├── repair/
│   │   ├── sandbox/
│   │   ├── securecc/
│   │   └── verification/
│   │
│   └── ...
│
├── test_files/
│
├── tests/
│   ├── regression_all.sh
│   ├── regression_cli.sh
│   ├── regression_artifacts.sh
│   ├── regression_policy.sh
│   ├── regression_project_verify.sh
│   ├── regression_provenance.sh
│   ├── regression_provenance_tamper.sh
│   ├── regression_evidence.sh
│   ├── regression_diagnostics.sh
│   ├── regression_protection.sh
│   ├── regression_measurement.sh
│   └── regression_packaging.sh
│
├── pyproject.toml
├── requirements.txt
└── securecc
```

---

# Testing

Run the complete regression suite:

```bash
./tests/regression_all.sh
```

Run the end-to-end benchmark:

```bash
securecc benchmark test_files/
```

Run the final release audit:

```bash
./tests/final_release_audit.sh
```

The release audit validates:

- Repository structure
- Python syntax
- Version and packaging
- CLI command surface
- Documentation
- Full regression
- End-to-end benchmark
- Release artifacts

---

# Security Model

SecureCC follows a verification-first security model.

The system does not treat:

- A generated patch
- A model prediction
- A successful compilation
- A single static-analysis result

as sufficient proof that a repaired program is secure.

Instead, the verification pipeline combines multiple independent checks.

For more information, see:

```text
docs/SECURITY_MODEL.md
```

---

# Documentation

Detailed documentation is available in:

```text
docs/
├── INSTALL.md
├── CLI.md
├── MANUAL.md
├── RELEASE_CHECKLIST.md
└── SECURITY_MODEL.md
```

---

# Development

Check the working version:

```bash
securecc --version
```

Check available commands:

```bash
securecc --help
```

Run syntax validation:

```bash
python -m py_compile $(find src/V2 -name "*.py" -type f)
```

Run regression:

```bash
./tests/regression_all.sh
```

Run the final audit:

```bash
./tests/final_release_audit.sh
```

---

# Version

```text
VulnHGNN 2.0 SecureCC
Version: 2.0.0
Release: development
```

---

# License

Add the project's applicable license here before public distribution.
