from .models import VerificationGate


def main():
    print("=" * 68)
    print("VulnHGNN 2.0 — VERIFICATION GATE BENCHMARK")
    print("=" * 68)

    gate = VerificationGate()

    cases = [
        (
            "all_checks_pass",
            dict(
                compile_passed=True,
                hardening_passed=True,
                runtime_passed=True,
                security_rescan_passed=True,
                behavior_passed=True,
            ),
            True,
        ),
        (
            "runtime_failure_rejected",
            dict(
                compile_passed=True,
                hardening_passed=True,
                runtime_passed=False,
                security_rescan_passed=True,
                behavior_passed=True,
            ),
            False,
        ),
        (
            "security_rescan_failure_rejected",
            dict(
                compile_passed=True,
                hardening_passed=True,
                runtime_passed=True,
                security_rescan_passed=False,
                behavior_passed=True,
            ),
            False,
        ),
        (
            "hardening_failure_rejected",
            dict(
                compile_passed=True,
                hardening_passed=False,
                runtime_passed=True,
                security_rescan_passed=True,
                behavior_passed=True,
            ),
            False,
        ),
    ]

    passed = 0
    for name, kwargs, expected in cases:
        result = gate.evaluate(**kwargs)
        ok = result.accepted == expected
        if ok:
            passed += 1
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {name}")
        if result.reasons:
            print("       reasons:", "; ".join(result.reasons))

    print()
    print(f"VERIFICATION GATE RESULT: {passed}/{len(cases)} cases passed")
    print("=" * 68)
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())
