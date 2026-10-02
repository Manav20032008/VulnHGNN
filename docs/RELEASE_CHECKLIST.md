# VulnHGNN 2.0 — Release Checklist

## Version

- [ ] Version is `2.0.0`
- [ ] CLI reports the expected version
- [ ] Packaging metadata matches the CLI version
- [ ] Release state is intentionally documented

## Source integrity

- [ ] Repository imports successfully
- [ ] Python source passes compilation checks
- [ ] No accidental debug code remains
- [ ] No temporary development files are part of the release

## CLI

- [ ] `securecc --version` works
- [ ] `securecc --help` works
- [ ] All supported commands are registered
- [ ] Text output works
- [ ] JSON output works where supported
- [ ] CLI regression passes

Current command surface:

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

## Artifact system

- [ ] Evidence directory works
- [ ] Verification directory works
- [ ] Benchmark directory works
- [ ] Measurement directory works
- [ ] Protection directory works
- [ ] Evaluation directory works

## Security pipeline

- [ ] Detection regression passes
- [ ] Repair regression passes
- [ ] Project verification passes
- [ ] Behavioral verification passes
- [ ] Security re-analysis passes
- [ ] Hardening checks pass
- [ ] Provenance validation passes
- [ ] Provenance tamper test rejects modified artifacts

## Diagnostics

- [ ] Developer diagnostics contain CWE information
- [ ] Function information is present
- [ ] Basic-block information is present
- [ ] LLVM node information is present
- [ ] Evidence is present
- [ ] Repair strategy is present
- [ ] Verification information is present
- [ ] Diagnostic artifact is generated

## Binary protection

- [ ] `strip-unneeded` transformation passes
- [ ] `strip-debug` transformation passes
- [ ] Hardening is preserved
- [ ] Behavior is preserved
- [ ] Protection evidence is generated
- [ ] Size measurements are recorded

## Measurement

- [ ] Baseline measurements complete
- [ ] Protected measurements complete
- [ ] Repeated runtime measurements complete
- [ ] Behavior comparison passes
- [ ] Hardening comparison passes
- [ ] Measurement artifact is generated

## Evaluation

- [ ] End-to-end benchmark passes
- [ ] Evaluation status is verified
- [ ] Security findings are accounted for
- [ ] All project fixtures are verified
- [ ] Benchmark artifact is generated
- [ ] Evaluation artifact is generated

## Documentation

Required documentation:

```text
docs/INSTALL.md
docs/CLI.md
docs/SECURITY_MODEL.md
docs/RELEASE_CHECKLIST.md
```

- [ ] Installation instructions verified
- [ ] CLI documentation verified
- [ ] Security model documented
- [ ] Release checklist updated

## Final validation

Run:

```bash
./tests/regression_all.sh
```

Then:

```bash
securecc benchmark test_files/
```

The regression suite must finish with:

```text
FINAL STATUS : VULNHGNN_2.0_REGRESSION_VERIFIED
```

The benchmark must finish with:

```text
FINAL STATUS : VULNHGNN_2.0_VERIFIED
```

Only after these checks should the current VulnHGNN 2.0 state be treated as release-audit ready.
