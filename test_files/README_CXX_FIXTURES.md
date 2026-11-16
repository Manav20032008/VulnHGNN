# C and C++ test fixtures

Each `test_files/test_*.c` has a C++ twin `test_files/test_*.cpp` with the **same CWE intent**, written in idiomatic C++ (`<iostream>`, `int main()`, `std::cout`, `new`/`delete` where appropriate).

Regenerate all idiomatic `.cpp` fixtures:

```bash
python3 scripts/write_idiomatic_cpp_fixtures.py
```

Do **not** use `sync_cpp_fixtures_from_c.py` (disabled; it produced C-style `<cstdio>` twins).

## Detectors exercised by these fixtures

| CWE | Title | Stage |
|-----|--------|--------|
| CWE-190 | Integer overflow | IR graph |
| CWE-191 | Integer underflow | IR graph |
| CWE-369 | Divide by zero | IR graph |
| CWE-476 | NULL pointer dereference | IR graph |
| CWE-121 | Stack-based buffer overflow | IR graph |
| CWE-134 | Externally-controlled format string | IR graph |
| CWE-457 | Uninitialized variable | Clang warning |
| CWE-787 | Out-of-bounds write | Clang warning |
| CWE-122 | Heap-based buffer overflow | IR graph |
| CWE-125 | Out-of-bounds read | Clang + IR GEP |
| CWE-789 | Excessive allocation size | IR graph |
| CWE-400 | Uncontrolled resource consumption | IR graph |
| CWE-415 | Double free | IR graph |
| CWE-416 | Use after free | IR graph |
| CWE-401 | Memory leak | IR graph |
| CWE-835 | Infinite loop | IR graph (CFG) |
| CWE-833 | Deadlock (nested locks) | IR graph |
| CWE-667 | Improper locking (double lock) | IR graph |
