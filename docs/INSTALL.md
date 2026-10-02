# VulnHGNN 2.0 SecureCC — Installation

## Overview

VulnHGNN 2.0 SecureCC is a local-first C/C++ security toolchain that combines:

- deterministic source security analysis
- vulnerability localization
- evidence-first diagnostics
- verified source repair
- hardened compilation
- runtime and behavioral verification
- provenance tracking
- binary protection
- security and performance measurement

The tool is designed to keep security decisions deterministic and locally verifiable.

## Requirements

### Operating system

GNU/Linux is the primary supported development environment.

### Python

Python 3.12 or newer.

Check:

```bash
python --version
```

### LLVM / Clang

Clang and LLVM tooling are required.

Check:

```bash
clang --version
```

The current development environment uses Clang/LLVM 18.

### ELF tooling

The binary hardening and audit pipeline uses standard ELF tooling such as:

```bash
file
readelf
```

Check:

```bash
file --version
readelf --version
```

## Repository setup

Enter the repository:

```bash
cd VulnHGNN
```

Create or activate a Python virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

The project can also be installed into an existing development virtual environment.

## Editable installation

Install the package without downloading runtime dependencies:

```bash
python -m pip install -e . --no-deps
```

This installs the `securecc` command.

Verify:

```bash
securecc --version
```

Expected form:

```text
VulnHGNN 2.0 SecureCC 2.0.0
release : development
```

## CLI verification

Check the command interface:

```bash
securecc --help
```

The current interface provides:

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

## Basic validation

Run a project scan:

```bash
securecc scan test_files/
```

Run project verification:

```bash
securecc verify test_files/
```

Run diagnostics:

```bash
securecc diagnose test_files/test_02_cwe190.c
```

Run the complete benchmark:

```bash
securecc benchmark test_files/
```

## Regression validation

Run the complete regression suite:

```bash
./tests/regression_all.sh
```

A successful run ends with:

```text
FINAL STATUS : VULNHGNN_2.0_REGRESSION_VERIFIED
```

## Project artifacts

Generated artifacts are stored under:

```text
build/
```

The artifact registry organizes results into:

```text
build/
├── evidence/
├── verify/
├── benchmark/
├── measurement/
├── protection/
└── evaluation/
```

## Security principle

The toolchain is local-first. Security acceptance is based on deterministic analysis, compilation, hardening, runtime/behavioral verification, provenance, and regression evidence.

AI or model-generated information may assist development, but it is not treated as the final security authority.
