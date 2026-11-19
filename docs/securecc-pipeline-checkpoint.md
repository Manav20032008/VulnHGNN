# SecureCC analyze pipeline checkpoint

**Checkpoint date:** 2025-11-19 (post–AI adjudication baseline)

**Integration checkpoint:** 2025-11-19 — compile repair + enrichment + `analyze_orchestrator` wired in `build_dashboard_payload` (C/C++); catalog heal re-runs full pass when `VERIFIED`.

Use this doc to restore behavior or debug regressions after later pipeline changes.

## Intended flow (C/C++/Java Analyze)

Java uses the same LLVM → HGNN → adjudication path as C/C++ via **javac** + **jllvm** (set `SECURECC_JLLVM` if not on PATH). Python analysis was removed from the web workbench.

1. **Compile gate** — `clang` / `clang++` or **javac+jllvm** → LLVM IR; on failure, **AI compile repair** (up to 2 attempts) then retry.
2. **Evidence** — IR → heterogeneous graph → **HGNN** → `engine_scan` (candidates only).
3. **Adjudication** — Groq compares each candidate to source → `CONFIRMED` / `REJECTED` / `INCONCLUSIVE`.
4. **Enrichment** — Classifier + explainer agents on **confirmed** findings only.
5. **Display** — `payload.scan` = confirmed; metrics show **Confirmed** vs **HGNN candidates**.
6. **Heal (optional)** — Catalog heal → **re-run engine + adjudication** on patched source; final `scan` from post-heal pass.

## Key modules

| Module | Role |
|--------|------|
| `src/V2/securecc/adjudication.py` | AI adjudicator (Groq) |
| `src/V2/securecc/java_ir.py` | Java → LLVM via javac + jllvm |
| `src/V2/securecc/compile_repair.py` | AI compile repair before IR |
| `src/V2/securecc/agent_enrichment.py` | Classifier + explainer on confirmed |
| `src/V2/securecc/pipeline_stages.py` | UI pipeline stages |
| `src/V2/securecc/web/analyze_orchestrator.py` | `run_engine_pipeline_pass` (single C pass) |
| `src/V2/securecc/web/app.py` | `build_dashboard_payload` + heal re-pass |

## API payload fields

- `engine_scan` — raw HGNN output
- `adjudication` — counts, rejected/inconclusive lists, status
- `verification` — `CLEAN` | `FINDINGS` | `PARTIAL`
- `scan` — user-facing confirmed findings
- `compile_repair` — repair attempts (if any)
- `enrichment` — classifier/explainer meta
- `post_heal_adjudication` — after catalog heal when re-run succeeds

## Requirements

- `GROQ_API_KEY` for adjudication, compile repair, and enrichment. Without it: adjudication SKIPPED → 0 confirmed, `PARTIAL`.

## Frontend

- `metric-cards.js`: Confirmed + HGNN candidates
- `app-core.js` `renderDashboard`: navigates to Findings or Overview; syncs Live `flow`/`graph`
- Findings panel: confirmed table + collapsed rejected list

## Rollback

1. **Pre-adjudication (engine-only UI):** set `display_scan = engine_scan` in `build_dashboard_payload` and drop adjudication calls.
2. **Adjudication only (no compile repair / enrichment / orchestrator):** restore inline `analyze_source` + `adjudicate_engine_scan` in `app.py` (see git before orchestrator integration). Keep `adjudication.py` as the stable baseline you validated as “works perfect.”
3. **Frontend:** `metric-cards.js` / `app-core.js` tolerate missing `compile_repair` and `enrichment`; safe to leave in place when rolling back backend.