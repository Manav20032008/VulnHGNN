# VulnHGNN 2.0 — SecureCC

**SecureCC** is a local-first security workbench for **C, C++, and Java** source. It compiles to LLVM IR (where applicable), builds a heterogeneous graph for CWE detectors, localizes findings, explains them from evidence, and optionally repairs and verifies changes. A browser **workbench** provides live lint, pipeline visualization, IR graphs, AI chat, and catalog-backed healing.

> **Design principle:** Automated analysis may propose patches and narratives, but **verification** is the authority for accepting repairs.

---

## Quick start

```bash
git clone <repository-url>
cd VulnHGNN
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
python -m pip install --upgrade pip setuptools
python -m pip install -e . --no-deps
python -m pip install flask groq python-dotenv networkx   # web UI + optional AI

clang --version   # required for C/C++; JDK/clang for Java features

cp .env.example .env   # optional: set GROQ_API_KEY for adjudication, Explain, Chat, Heal AI

securecc --version
securecc web
```

Open **http://127.0.0.1:5050** — load a sample from **Project explorer** (e.g. `test_04_cwe369.c`), click **Analyze**, then browse **Output**, **Detection**, and **Live**.

---

## Docker (UI + API in one container)

The image installs the Python backend, CWE pipeline, and Flask-served workbench static assets. Port **5050** is the web UI and REST API.

```bash
docker build -t vulnhgnn-securecc:2.0 .

# Optional Groq (copy .env.example to .env first)
docker run --rm -p 5050:5050 --env-file .env vulnhgnn-securecc:2.0

# Or pass the key directly
docker run --rm -p 5050:5050 -e GROQ_API_KEY=gsk_... vulnhgnn-securecc:2.0
```

Open **http://localhost:5050**. Uploads and build artifacts are written under `/app/build` inside the container.

Environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `SECURECC_WEB_HOST` | `0.0.0.0` | Bind address (use `0.0.0.0` in Docker) |
| `SECURECC_WEB_PORT` | `5050` | HTTP port |
| `GROQ_API_KEY` | — | Optional AI chat, adjudication, heal |

---

## What you can do

| Capability | CLI | Web workbench |
|------------|-----|----------------|
| Compile → IR → HGNN-style graph detection | `securecc scan` | **Analyze** |
| Per-CWE localization & evidence | (JSON / reports) | **Detection** tabs |
| Live edits: compiler + heuristics + semantic hints | — | **Live** (Health / Code / Engine) |
| Explanations & diagnostics | `explain`, `diagnose` | **Intelligence** tabs |
| Catalog heal + verify | `fix`, `verify` | **Heal** toggle + **Remediation** |
| IR graph exploration | — | **IR Graph**, Engine preview |
| Grounded AI chat (Groq) | `securecc agent` | **Chat** |
| Step-by-step guided review | — | Journey mode (sidebar) |

---

## Web workbench overview

After `securecc web`, the UI is organized as:

- **Editor (center):** Monaco editor, language selector (C / C++ / Java), **Engine preview** toggle, **Analyze**, optional **Heal**.
- **Live:** Real-time lint KPIs, health charts, **Problems** list (click a row to jump to the line).
- **Output:** Post-analyze summary, program stdout when clean, optional **quality ratings** (Groq).
- **Detection / Intelligence / Remediation:** Findings, localization, evidence, explain, agent activity, repair diff — populated after **Analyze**.

**Optional AI:** Create `.env` with `GROQ_API_KEY` and `GROQ_MODEL` (see `.env.example`). Without Groq, deterministic scan/localization still run; some adjudication and AI panels may be reduced.

---

## Security pipeline

```text
Source (C / C++ / Java)
        │
        ▼
   Analyze / compile → LLVM IR (C/C++) or Java IR path
        │
        ▼
   Detect (CWE detectors on IR graph + Clang diagnostics)
        │
        ▼
   Localize → Explain → Repair (optional) → Verify → Harden / Protect
        │
        ▼
   Evidence, reports, verified artifacts
```

Pipeline stages are surfaced in the workbench **Overview** / pipeline visualization after a full analyze.

---

## Supported weakness classes (fixtures)

Each CWE below has matching files under `test_files/test_*.c` and `test_files/test_*.cpp` (see `test_files/README_CXX_FIXTURES.md`). The catalog API lists them in the UI: `/api/vulnerability-catalog`.

| CWE | Title | Primary stage |
|-----|--------|----------------|
| CWE-190 | Integer overflow | IR graph |
| CWE-191 | Integer underflow | IR graph |
| CWE-369 | Divide by zero | IR graph |
| CWE-476 | NULL pointer dereference | IR graph |
| CWE-121 | Stack-based buffer overflow | IR graph |
| CWE-134 | Externally-controlled format string | IR graph |
| CWE-457 | Uninitialized variable | Clang warning |
| CWE-787 | Out-of-bounds write | Clang warning |
| CWE-122 | Heap-based buffer overflow | IR graph |
| CWE-125 | Out-of-bounds read | Clang + IR |
| CWE-789 | Excessive allocation | IR graph |
| CWE-400 | Uncontrolled resource consumption | IR graph |
| CWE-415 | Double free | IR graph |
| CWE-416 | Use after free | IR graph |
| CWE-401 | Memory leak | IR graph |
| CWE-835 | Infinite loop | CFG / Clang |
| CWE-833 | Deadlock (nested locks) | IR graph |
| CWE-667 | Improper locking | IR graph |

**Demo / report fixtures (suggested order):**

| File | Purpose |
|------|---------|
| `test_01_clean.c` | Clean baseline, zero findings |
| `test_04_cwe369.c` | Single clear divide-by-zero |
| `test_08_triple_190_191_369.c` | Multiple arithmetic CWEs |
| `test_16_all_detectable.c` | Broad IR detector showcase |
| `test_21_cwe416.c` / `test_22_cwe401.c` | Memory safety examples |

---

## Requirements

| Dependency | Notes |
|------------|--------|
| **Python** | ≥ 3.12 |
| **Clang/LLVM** | C/C++ compile and IR (`clang`, `clang++`) |
| **JDK / javac** | Java analysis (when using `.java`) |
| **Flask** | Web UI (`pip install flask`) |
| **networkx** | Graph pipeline |
| **Groq + python-dotenv** | Optional AI (`.env`) |
| **torch / torch_geometric** | Optional legacy GNN training only |

Developed primarily on Linux; macOS is supported for analysis and the web UI (sandbox/hardening tooling may be Linux-oriented).

---

## Installation (detail)

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip setuptools
python -m pip install -e . --no-deps
```

Install optional stacks as needed:

```bash
pip install -r requirements.txt    # full optional set
# minimal web + scan:
pip install flask networkx groq python-dotenv
```

Expected version string:

```bash
securecc --version
# VulnHGNN 2.0 SecureCC 2.0.0
```

See also **docs/INSTALL.md**.

---

## Configuration

```bash
cp .env.example .env
```

| Variable | Purpose |
|----------|---------|
| `GROQ_API_KEY` | Groq API for agent, chat, adjudication, heal fallback |
| `GROQ_MODEL` | Model id (default in example: `openai/gpt-oss-120b`) |

`securecc` loads `.env` from the project root; existing shell variables take precedence.

---

## CLI reference

```bash
securecc --help
```

Common commands:

```bash
securecc scan test_files/test_02_cwe190.c
securecc explain test_files/test_02_cwe190.c
securecc diagnose test_files/test_02_cwe190.c
securecc fix test_files/test_02_cwe190.c
securecc verify test_files/
securecc build test_files/test_01_clean.c
securecc benchmark test_files/
securecc web
securecc agent test_files/test_02_cwe190.c -m "Scan and explain issues."
securecc aai-security
```

Full command list and flags: **docs/CLI.md** and **docs/MANUAL.md**.

---

## Web dashboard

```bash
securecc web
```

Default URL: **http://127.0.0.1:5050**

- Upload `.c`, `.cpp`, `.cc`, `.cxx`, or `.java`, or pick **Test & CWE samples** in the explorer.
- **Analyze** runs the engine pipeline (and integrated agent/AI path when configured).
- **Journey mode** (sidebar): step-through compile → detect → review → optional fix with human approval (`POST /api/journey/*`).

---

## Project layout

```text
VulnHGNN/
├── configs/              # behavior profiles
├── data/                 # IR / parsed graph assets
├── docs/                 # INSTALL, CLI, MANUAL, SECURITY_MODEL, …
├── scripts/              # fixture sync, utilities
├── src/V2/
│   ├── analysis/         # compile, IR, scan orchestration
│   ├── detection/        # CWE catalog & detectors
│   ├── localization/     # graph-localized findings
│   ├── explain/ diagnose/ learn/ fix/ verify/
│   ├── securecc/         # CLI + web (app.py, static/, templates/)
│   └── …
├── test_files/           # C/C++ (and Java) regression & demo fixtures
├── tests/                # shell regression suites
├── pyproject.toml
├── requirements.txt
└── .env.example
```

---

## Testing

```bash
./tests/regression_all.sh
securecc benchmark test_files/
pytest test_files/test_cpp_catalog_regression.py   # needs deps
```

Release audit:

```bash
./tests/final_release_audit.sh
```

---

## Security model

Repairs and “clean” outcomes are not trusted from a single static pass or model output alone. Multiple checks (re-scan, runtime where applicable, provenance) gate acceptance. Details: **docs/SECURITY_MODEL.md**.

---

## Documentation

| Document | Content |
|----------|---------|
| [docs/INSTALL.md](docs/INSTALL.md) | Install & environment |
| [docs/CLI.md](docs/CLI.md) | Command reference |
| [docs/MANUAL.md](docs/MANUAL.md) | User manual |
| [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) | Verification-first model |
| [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) | Release steps |

---

## Version

```text
VulnHGNN 2.0 SecureCC
Version: 2.0.0
Release: development
```

---

## License

Add your project license here before public distribution.