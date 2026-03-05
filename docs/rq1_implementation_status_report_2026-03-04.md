# RQ1 Implementation Status Report (as of March 4, 2026)

## 1) Executive Summary

This report maps the design in `docs/RQ1_Detailed_Planning_Semantic_Recovery_v1_3.pdf` to the current `sourceagent` implementation.

Current state:

- The end-to-end pipeline is implemented and runnable (`mine`/`eval` CLI).
- Source-side capabilities (MMIO/ISR/DMA-L1/L2) are substantially implemented and already evaluated on P2IM-style datasets.
- Sink-side capabilities are implemented but still the main bottleneck for precision/recall in realistic stripped-firmware conditions.
- Evaluation infrastructure and GT bundling are in place, including per-sample raw JSON artifacts.

---

## 2) Implemented Modules in `/sourceagent`

### 2.1 Pipeline orchestration and CLI

- `sourceagent/interface/main.py`
  - `mine`, `eval`, `export`, `gt-sinks` subcommands.
  - Stage orchestration (loader -> facts/miners -> evidence -> proposer -> verifier).
  - Online/offline mode, run metadata, detailed eval artifact output.

### 2.2 Stage M1: Loader/Normalizer

- `sourceagent/pipeline/loader.py`
  - Supports both ELF and raw `.bin`.
  - Vector-table-based Cortex-M bootstrapping for raw binaries.
  - Region inference (flash/SRAM/MMIO/system), ISR entry extraction.

### 2.3 Stage M2(+2.5): Program facts

- `sourceagent/pipeline/memory_access_index.py`
  - Builds `MemoryAccessIndex` from decompiled output.
  - Access provenance classification (`CONST`, `ARG`, `GLOBAL_PTR`, `STACK_PTR`, etc.).
  - Typed struct field resolution with MCU tables.
  - Flash-constant pointer assisted resolution and multiple regex improvements.
- `sourceagent/pipeline/interprocedural.py`
  - Interprocedural ARG-based resolution (depth-1 + depth-2 propagation).
- `sourceagent/pipeline/cmsis_parser.py`, `cmsis_generated.py`, `peripheral_types.py`
  - STM32 + SAM3 + K64F register/offset support.

### 2.4 Source miners (VS0/VS2/VS3)

- `miners/mmio_read.py`: `MMIO_READ` with per-register/polling penalties.
- `miners/isr_context.py`: `ISR_MMIO_READ`, `ISR_FILLED_BUFFER`.
- `miners/dma_buffer.py`: `DMA_BACKED_BUFFER` Level 1/2 heuristics.

### 2.5 Sink miners (VS1/VS4/VS5 + extensions)

- `miners/copy_sink.py`: `COPY_SINK` (API/symbol/sig + stripped fallbacks).
- `miners/additional_sinks.py`: `MEMSET_SINK`, `STORE_SINK`, `LOOP_WRITE_SINK`.
- `miners/format_string_sink.py`: `FORMAT_STRING_SINK`.
- `miners/func_ptr_sink.py`: `FUNC_PTR_SINK`.
- `miners/func_classifier.py`: helper classification for stripped libc-like functions.

### 2.6 M5/M6/M7/M8/M9 components

- `evidence_packer.py` (M5): deterministic evidence packs.
- `proposer.py` (M6): heuristic mode + LLM mode (top-K, cache, deterministic settings).
- `verifier.py` (M7): obligation-based verification and fail-closed verdicting.
- `facts_bundle.py` (M8): export/query APIs and BinAgent-oriented callsite queue.
- `eval_harness.py`, `gt_sink_catalog.py` (M0/M9): comparison/scoring and normalized sink GT generation.

---

## 3) Current Test Datasets and Ground Truth

### 3.1 Firmware datasets currently present under `firmware/`

- `firmware/microbench`
  - 14 authored microbench/CVE-style source files (`.c`).
  - Built artifacts: 14 `.elf`, 14 `_stripped.elf`, 14 `.bin`, 14 `.map`.
- `firmware/p2im-unit_tests`
  - P2IM unit test firmware + per-test CSVs.
- `firmware/p2im-ground_truth`
  - 4 global GT CSVs (STM32F103, STM32F429, AtmelSAM3, NXPK64F).
- `firmware/uSBS` and copied references.
- `firmware/monolithic-firmware-collection` (including Fuzzware-like subsets and CVE samples).

### 3.2 Ground-truth bundle status

Directory: `firmware/ground_truth_bundle`

- `ground_truth_inventory.json/csv`
  - 36 inventory entries:
    - `uSBS`: 14
    - `monolithic-firmware-collection`: 15
    - `sourceagent-microbench`: 3
    - `p2im-ground_truth`: 4
  - Both ELF and BIN are represented (`elf`: 32 entries, `bin`: 32 entries).
- `normalized_gt_sinks.json/csv`
  - 18 normalized sink GT entries across 10 binary stems.
  - Includes semantic labels (`COPY_SINK`, `MEMSET_SINK`, `STORE_SINK`, `LOOP_WRITE_SINK`, `FORMAT_STRING_SINK`, `FUNC_PTR_SINK`, and CVE semantic subtypes with `pipeline_label_hint`).
- `uSBS_trigger_inputs/`
  - Trigger/replay artifacts copied for uSBS benchmark cases.

---

## 4) Existing Tests

### 4.1 Automated test suite

- `pytest --collect-only` (March 4, 2026) reports **783 tests collected**.
- Coverage includes:
  - Core pipeline data models and orchestrator.
  - Loader and firmware-context setup.
  - MAI/parsing/interprocedural resolution.
  - Each miner (sources + sinks).
  - Proposer, verifier, evidence packer, facts bundle.
  - Evaluation harness, GT sink catalog, CLI helpers.
  - Real firmware integration tests (`test_real_firmware_p2im.py`, environment-dependent).

### 4.2 Evaluation scripts and artifacts

- `tests/eval_p2im.py`: P2IM-style source detection evaluation.
- Eval artifact structure documented in `docs/eval_artifacts.md`.
- Per-sample raw JSON outputs (candidate/proposal/verified) and matching/scoring artifacts are generated by `eval --output-dir ...`.

### 4.3 Recent quantitative snapshots

- Source-side update report (`docs/pipeline_update_p0p1_report.md`):
  - P2IM unit-test aggregate recall improved to **52.5%** across 47 binaries.
  - Microbench source recall reached **100%** on the reported set.
- Sink-side phase snapshots:
  - `/tmp/eval_phase3`: strict TP=0, FP=20, FN=18 (early failure state).
  - `/tmp/eval_phase4e_fpfn_tune2`: strict TP=6, FP=27, FN=12; weighted TP=8.5, FP=24.5, FN=9.5.

---

## 5) Plan-vs-Implementation Check (from RQ1 v1.3)

Status legend: `Implemented`, `Partially Implemented`, `Not Implemented`.

| RQ1 Stage / Milestone | Planned in PDF | Current Status | Notes |
|---|---|---|---|
| M0 (Stage 0) | Microbench + eval harness | Implemented | Microbench, eval harness, scoring policy, detailed artifacts present. |
| M1 (Stage 1) | Loader + memory-map hypotheses | Partially Implemented | ELF/raw BIN loader and vector-table bootstrap implemented; multi-hypothesis scoring/alternative persistence is limited. |
| M2 (Stage 2) | MAI + bounded pcode slicing | Partially Implemented | MAI and provenance extraction implemented; no explicit generic backward/forward slice API exposed as in the plan wording. |
| VS0 (Stage 3) | MMIO_READ vertical slice | Implemented | Miner + obligations + eval path implemented. |
| VS1 (Stage 4) | COPY_SINK (API/sig first) | Partially Implemented | Works for many API callsites; still misses key inline/variant patterns. |
| M5 (Stage 5) | Stable evidence packer | Partially Implemented | Deterministic pack IDs implemented; richer slice-backbone packaging/truncation metadata is lighter than planned. |
| M6 (Stage 6) | Budgeted, reproducible LLM proposer | Implemented | Heuristic + LLM modes, top-K and caching implemented. |
| M7 (Stage 7) | Obligation verifier + deep-check fallback | Partially Implemented | Obligation system implemented; deep-check fallback (bounded symbolic/value-set) not implemented. |
| VS2 (Stage 8) | ISR context + ISR_FILLED_BUFFER | Implemented | ISR entry handling and ISR-buffer miner are in pipeline. |
| VS3 (Stage 9) | DMA staged support | Partially Implemented | Level 1/2 heuristic path implemented; Level 3 descriptor-chain analysis deferred; `O_DMA_3`-style consumption obligation not formalized as required verifier step. |
| VS4/VS5 (Stage 10) | MEMSET/STORE/LOOP_WRITE sinks | Partially Implemented | All miners exist, but recall/precision are not yet at desired stability. |
| M8 (Stage 11) | Storage/reporting + BinAgent integration | Implemented | Facts bundle export/query and callsite queue are implemented. |
| M9 (Stage 12) | End-to-end eval/ablation/case-study protocol | Partially Implemented | End-to-end eval works with detailed outputs; ablation automation and broader case-study pipelines remain incomplete. |

---

## 6) What Is Still Missing (Most Important Gaps)

1. Sink detection quality is still below target.
- Main misses: non-API copy idioms, robust format-string and function-pointer patterns, and loop/write edge cases.
- Main FP source: over-broad `STORE_SINK` and loop-write heuristics in library/helper internals.

2. Stage-2 "slicing API" depth is lighter than planned.
- Current system depends heavily on regex + localized context extraction rather than a general reusable pcode slicing interface.

3. Verifier deep-check fallback is absent.
- The planned optional bounded symbolic/value-set fallback for borderline cases is not implemented.

4. DMA advanced semantics are incomplete.
- Level-3 descriptor/ring reasoning is intentionally deferred.
- Stronger DMA consumption linkage (`O_DMA_3` style) is not yet enforced as a core obligation.

5. GT normalization is sink-centric.
- `normalized_gt_sinks.json` is strong for sink scoring, but a similarly standardized source GT schema for microbench/CVE-level source labels is not yet unified in the same way.

---

## 7) Recommended Next Updates / Optimizations

### Priority A: Sink recall and precision

1. COPY sink upgrades:
- Add robust detection for inline loop-copy idioms (not only named APIs).
- Improve stripped callee alias recovery for `strcpy`-like and wrapper paths.

2. STORE/LOOP_WRITE FP control:
- Add stronger gating (function-size/fanout/library-shape suppression).
- Require stronger influence signals before high-confidence emission.

3. FORMAT/FUNC_PTR robustness:
- Expand pattern families to match more stripped decompiler variants.
- Strengthen anti-FP checks (e.g., callback-safe patterns vs dangerous dispatch).

### Priority B: Verifier and facts depth

4. Implement optional deep-check fallback in verifier:
- Trigger for high-value borderline cases only.
- Persist extra evidence IDs and deterministic logs.

5. Formalize DMA strengthening obligations:
- Add explicit consumption linkage check (planned `O_DMA_3` behavior).

### Priority C: Evaluation closure

6. Expand standardized GT:
- Add normalized source GT (machine-readable) aligned with sink GT style.

7. Add reproducible ablation scripts:
- Heuristic-only vs LLM proposer.
- Obligations on/off comparisons.
- ELF-only vs ELF+BIN mixed-format runs.

8. Keep sink progress tracking with both strict and weighted metrics:
- Strict for exact semantic label claims.
- Weighted for controlled subtype/proxy progress.

---

## 8) Conclusion

The project has already reached a real end-to-end, evidence-grounded implementation with broad module coverage and strong source-side progress. The next phase should focus on closing sink-specific quality gaps and completing the remaining planned verification/evaluation depth (deep-check fallback, stronger DMA obligations, and broader ablation-ready benchmarking).

