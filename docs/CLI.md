# VulnHGNN 2.0 SecureCC — CLI Reference

## Global options

Display version information:

```bash
securecc --version
```

Display help:

```bash
securecc --help
```

Most reporting commands support:

```text
--format text
--format json
```

JSON output is intended for automation and machine-readable workflows.

# Commands

## 1. scan

Analyze C/C++ source files for supported security findings.

```bash
securecc scan <source-or-directory>
```

Example:

```bash
securecc scan test_files/
```

JSON:

```bash
securecc scan test_files/ --format json
```

The scan reports:

- files scanned
- files containing findings
- failed files
- total findings
- CWE counts
- per-file findings

## 2. fix

Run the deterministic repair pipeline.

```bash
securecc fix <source-or-directory>
```

Example:

```bash
securecc fix test_files/
```

The repair pipeline does not treat a generated patch as automatically correct. Repaired code must pass the verification pipeline.

## 3. verify

Verify source files or a project.

```bash
securecc verify <source-or-directory>
```

Example:

```bash
securecc verify test_files/
```

JSON:

```bash
securecc verify test_files/ --format json
```

Verification can include:

- compilation
- binary hardening
- runtime verification
- behavior verification
- security re-analysis
- provenance validation
- verification gate evaluation

## 4. explain

Generate evidence-first security explanations.

```bash
securecc explain <source>
```

Example:

```bash
securecc explain test_files/test_05_cwe476.c
```

JSON:

```bash
securecc explain test_files/test_05_cwe476.c --format json
```

Explanations include deterministic evidence such as:

- CWE
- vulnerable operation
- function
- basic block
- LLVM instruction/node
- data-flow evidence
- allocation origin
- pointer propagation
- null checks
- downstream use
- repair strategy
- verification information

## 5. diagnose

Generate developer-facing diagnostics.

```bash
securecc diagnose <source>
```

Example:

```bash
securecc diagnose test_files/test_02_cwe190.c
```

JSON:

```bash
securecc diagnose test_files/test_02_cwe190.c --format json
```

Diagnostic artifacts are written under:

```text
build/evidence/
```

## 6. build

Build a secure binary from a source file.

```bash
securecc build <source>
```

A secure build performs security analysis and hardened compilation. The build records provenance information for the generated binary.

## 7. report

Generate reporting information for supported project artifacts.

```bash
securecc report <source>
```

Use JSON output when integrating results into other tooling.

## 8. harden

Apply the SecureCC hardening compilation pipeline.

```bash
securecc harden <source>
```

Hardening is audited through ELF-level checks including:

- PIE
- RELRO
- BIND_NOW
- NX stack
- stack protector
- other configured hardening requirements

## 9. protect

Apply a supported binary protection transformation.

```bash
securecc protect <binary>
```

Available protection profiles currently include:

```text
strip-unneeded
strip-debug
```

Example:

```bash
securecc protect build/test_01_clean
```

Protection acceptance includes transformation, hardening preservation, and behavioral comparison.

## 10. learn

Display learning/development information exposed by SecureCC.

```bash
securecc learn
```

## 11. benchmark

Run the complete security pipeline benchmark.

```bash
securecc benchmark test_files/
```

The benchmark evaluates:

- detection
- repair
- verification
- evidence
- regression
- measurement

A successful benchmark reports:

```text
FINAL STATUS : VULNHGNN_2.0_VERIFIED
```

# Recommended workflow

For a project:

```bash
securecc scan test_files/
securecc fix test_files/
securecc verify test_files/
securecc benchmark test_files/
```

For a single vulnerable source:

```bash
securecc scan test_files/test_02_cwe190.c
securecc explain test_files/test_02_cwe190.c
securecc diagnose test_files/test_02_cwe190.c
```

For a verified binary:

```bash
securecc verify <binary>
securecc protect <binary>
```

# Machine-readable workflows

Prefer JSON when integrating SecureCC into scripts:

```bash
securecc scan test_files/ --format json
securecc verify test_files/ --format json
securecc diagnose test_files/test_02_cwe190.c --format json
```

Persistent machine-readable artifacts are stored under `build/`.
