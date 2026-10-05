#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PASS=0
FAIL=0

pass() {
    echo "  PASS : $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  FAIL : $1"
    FAIL=$((FAIL + 1))
}

echo "=============================================="
echo " VulnHGNN 2.0 — FINAL RELEASE AUDIT"
echo "=============================================="
echo

# ------------------------------------------------
# 1. Repository structure
# ------------------------------------------------

echo "[1/8] Repository structure"

REQUIRED=(
    "pyproject.toml"
    "securecc"
    "src/V2"
    "test_files"
    "tests"
    "docs/INSTALL.md"
    "docs/CLI.md"
    "docs/SECURITY_MODEL.md"
    "docs/RELEASE_CHECKLIST.md"
)

STRUCTURE_OK=1

for path in "${REQUIRED[@]}"; do
    if [ -e "$ROOT/$path" ]; then
        echo "  [OK] $path"
    else
        echo "  [MISSING] $path"
        STRUCTURE_OK=0
    fi
done

if [ "$STRUCTURE_OK" -eq 1 ]; then
    pass "repository structure"
else
    fail "repository structure"
fi

echo

# ------------------------------------------------
# 2. Python syntax
# ------------------------------------------------

echo "[2/8] Python source validation"

if python -m py_compile $(find src/V2 -name "*.py" -type f); then
    pass "Python syntax"
else
    fail "Python syntax"
fi

echo

# ------------------------------------------------
# 3. Version / packaging
# ------------------------------------------------

echo "[3/8] Version and packaging"

VERSION_OUTPUT="$(securecc --version 2>&1 || true)"

echo "$VERSION_OUTPUT"

if echo "$VERSION_OUTPUT" | grep -q "VulnHGNN 2.0 SecureCC 2.0.0"; then
    pass "CLI version"
else
    fail "CLI version"
fi

if grep -q 'version = "2.0.0"' pyproject.toml; then
    pass "package version"
else
    fail "package version"
fi

if command -v securecc >/dev/null 2>&1; then
    pass "installed securecc command"
else
    fail "installed securecc command"
fi

echo

# ------------------------------------------------
# 4. CLI command surface
# ------------------------------------------------

echo "[4/8] CLI command surface"

HELP="$(securecc --help 2>&1)"

COMMANDS=(
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
)

COMMAND_OK=1

for command in "${COMMANDS[@]}"; do
    if echo "$HELP" | grep -qE "^[[:space:]]*$command([[:space:]]|$)"; then
        echo "  [OK] $command"
    else
        echo "  [MISSING] $command"
        COMMAND_OK=0
    fi
done

if [ "$COMMAND_OK" -eq 1 ]; then
    pass "CLI command surface (${#COMMANDS[@]}/${#COMMANDS[@]})"
else
    fail "CLI command surface"
fi

echo

# ------------------------------------------------
# 5. Documentation
# ------------------------------------------------

echo "[5/8] Documentation"

DOCS=(
    "docs/INSTALL.md"
    "docs/CLI.md"
    "docs/SECURITY_MODEL.md"
    "docs/RELEASE_CHECKLIST.md"
)

DOC_OK=1

for doc in "${DOCS[@]}"; do
    if [ -s "$ROOT/$doc" ]; then
        echo "  [OK] $doc"
    else
        echo "  [MISSING/EMPTY] $doc"
        DOC_OK=0
    fi
done

if [ "$DOC_OK" -eq 1 ]; then
    pass "documentation (4/4)"
else
    fail "documentation"
fi

echo

# ------------------------------------------------
# 6. Full regression suite
# ------------------------------------------------

echo "[6/8] Full regression suite"

if ./tests/regression_all.sh; then
    pass "full regression suite"
else
    fail "full regression suite"
fi

echo

# ------------------------------------------------
# 7. End-to-end benchmark
# ------------------------------------------------

echo "[7/8] End-to-end benchmark"

BENCHMARK_OUTPUT="$(securecc benchmark test_files/ 2>&1)"
BENCHMARK_STATUS=$?

echo "$BENCHMARK_OUTPUT"

if [ "$BENCHMARK_STATUS" -eq 0 ] &&
   echo "$BENCHMARK_OUTPUT" | grep -q "FINAL STATUS : VULNHGNN_2.0_VERIFIED"; then
    pass "end-to-end benchmark"
else
    fail "end-to-end benchmark"
fi

echo

# ------------------------------------------------
# 8. Final artifacts
# ------------------------------------------------

echo "[8/8] Final artifacts"

ARTIFACTS=(
    "build/benchmark/test_files/benchmark.json"
    "build/benchmark/test_files/measurement.json"
    "build/evaluation/vulnhgnn_evaluation.json"
)

ARTIFACT_OK=1

for artifact in "${ARTIFACTS[@]}"; do
    if [ -s "$ROOT/$artifact" ]; then
        echo "  [OK] $artifact"
    else
        echo "  [MISSING/EMPTY] $artifact"
        ARTIFACT_OK=0
    fi
done

if [ "$ARTIFACT_OK" -eq 1 ]; then
    pass "release artifacts"
else
    fail "release artifacts"
fi

echo
echo "=============================================="
echo " FINAL RELEASE AUDIT SUMMARY"
echo "=============================================="
echo
echo "Checks passed : $PASS"
echo "Checks failed : $FAIL"
echo

if [ "$FAIL" -ne 0 ]; then
    echo "FINAL STATUS : VULNHGNN_2.0_RELEASE_AUDIT_FAILED"
    exit 1
fi

echo "FINAL STATUS : VULNHGNN_2.0_RELEASE_AUDIT_VERIFIED"
exit 0