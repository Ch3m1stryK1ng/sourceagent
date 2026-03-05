# Unstripped ELF Evaluation Suite Report (English, Enhanced)

## 1. Objective
- Evaluate SourceAgent's source/sink detection capability under **unstripped ELF**.
- Cover 4 datasets: `microbench`, `p2im-unit_tests`, `uSBS`, and `monolithic-firmware-collection`.
- Run strict TP/FP/FN on samples with GT; report detection distribution and platform profile on samples without GT.

## 2. Experiment Setup
- Suite directory: `/tmp/eval_suite_unstripped_elf_20260305_131606`
- Input format: `unstripped .elf` (`--only-unstripped-elf`)
- Run mode: `--online --stage 7`
- Proposer: heuristic (`model=null`)
- Accepted verdicts: `VERIFIED, PARTIAL`
- GT: `firmware/ground_truth_bundle/normalized_gt_sinks.json` (**sink-oriented GT in this round**)
- Important handling: uSBS duplicate ELF names were rewritten as unique copies (`usbs_XX_*.elf`) to avoid stem collisions.

## 3. Artifacts
- Global summary JSON: `/tmp/eval_suite_unstripped_elf_20260305_131606/summary/eval_summary.json`
- Per-file table: `/tmp/eval_suite_unstripped_elf_20260305_131606/tables/by_file.csv`
- Platform profile: `/tmp/eval_suite_unstripped_elf_20260305_131606/tables/sample_platform_profile.csv`

## 4. Results
### 4.1 Overall
- Total samples: **48**
- Status distribution: `{'ok': 10, 'ok_no_ground_truth': 37, 'eval_timeout': 1}`
- Total detections: **3588** (`source=2529`, `sink=1059`)
- Strict sink GT metrics: `TP=17, FP=0, FN=0, P=1.000, R=1.000, F1=1.000`

### 4.2 Source Label Statistics (denominator = total sources)
Total sources = 2529

| Source Label | Count | Share Within Sources | In GT Samples | In Non-GT Samples |
|---|---|---|---|---|
| MMIO_READ | 2398 | 94.82% | 22 | 2376 |
| DMA_BACKED_BUFFER | 114 | 4.51% | 1 | 113 |
| ISR_MMIO_READ | 16 | 0.63% | 0 | 16 |
| ISR_FILLED_BUFFER | 1 | 0.04% | 0 | 1 |

### 4.3 Sink Label Statistics (denominator = total sinks)
Total sinks = 1059

| Sink Label | Count | Share Within Sinks | In GT Samples | In Non-GT Samples | GT Coverage (matched/total) |
|---|---|---|---|---|---|
| COPY_SINK | 370 | 34.94% | 7 | 363 | 7/8 |
| STORE_SINK | 335 | 31.63% | 8 | 327 | 1/1 |
| LOOP_WRITE_SINK | 160 | 15.11% | 2 | 158 | 1/1 |
| FUNC_PTR_SINK | 111 | 10.48% | 1 | 110 | 1/1 |
| FORMAT_STRING_SINK | 46 | 4.34% | 1 | 45 | 1/1 |
| MEMSET_SINK | 37 | 3.49% | 1 | 36 | 1/1 |

### 4.4 microbench (with GT): Source and Sink separated
- Note: the current GT is sink-oriented, so **TP/FP/FN are only defined for sinks**.

#### 4.4.1 Strict Sink Evaluation (TP/FP/FN)
| Sample | TP | FP | FN | Precision | Recall | F1 | Total Sink Detections |
|---|---|---|---|---|---|---|---|
| cve_2018_16525_freertos_dns | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 | 3 |
| cve_2020_10065_hci_spi | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |
| cve_2021_34259_usb_host | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 | 6 |
| t0_copy_sink | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 | 2 |
| t0_dma_length_overflow | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |
| t0_format_string | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |
| t0_func_ptr_dispatch | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |
| t0_indirect_memcpy | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |
| t0_store_loop_sink | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 | 3 |
| t0_uart_rx_overflow | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |

#### 4.4.2 Source Detection Distribution (no source TP/FP/FN)
| Sample | Total Source Detections | MMIO_READ | ISR_MMIO_READ | ISR_FILLED_BUFFER | DMA_BACKED_BUFFER |
|---|---|---|---|---|---|
| cve_2018_16525_freertos_dns | 2 | 2 | 0 | 0 | 0 |
| cve_2020_10065_hci_spi | 3 | 3 | 0 | 0 | 0 |
| cve_2021_34259_usb_host | 1 | 1 | 0 | 0 | 0 |
| t0_copy_sink | 2 | 2 | 0 | 0 | 0 |
| t0_dma_length_overflow | 5 | 4 | 0 | 0 | 1 |
| t0_format_string | 2 | 2 | 0 | 0 | 0 |
| t0_func_ptr_dispatch | 2 | 2 | 0 | 0 | 0 |
| t0_indirect_memcpy | 2 | 2 | 0 | 0 | 0 |
| t0_store_loop_sink | 2 | 2 | 0 | 0 | 0 |
| t0_uart_rx_overflow | 2 | 2 | 0 | 0 | 0 |

### 4.5 Dataset-Level Summary
| Dataset | Samples | GT Samples | Success (ok*) | Errors | Total Detections | Sources | Sinks | GT-TP | GT-FP | GT-FN | GT-F1 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| microbench | 14 | 10 | 14 | 0 | 55 | 32 | 23 | 17 | 0 | 0 | 1.000 |
| monolithic-firmware-collection | 12 | 0 | 12 | 0 | 1716 | 1159 | 557 | 0 | 0 | 0 | 0.000 |
| p2im-unit_tests | 12 | 0 | 12 | 0 | 960 | 695 | 265 | 0 | 0 | 0 | 0.000 |
| uSBS | 10 | 0 | 9 | 1 | 857 | 643 | 214 | 0 | 0 | 0 | 0.000 |

## 5. Why these labels? Do they cover all source/sink types?
### 5.1 Why these source labels
- We prioritized the most common and stable firmware input paths: polling register reads, ISR-context reads, ISR-produced/shared buffers consumed in main flow, and DMA-filled RAM buffers consumed by logic.
- These four patterns are common across both bare-metal and RTOS firmware and map well to verifiable static features, so they are suitable as a first-stage source baseline.

### 5.2 Why these sink labels
- We prioritized direct memory-corruption risk patterns: copy writes, memset writes, pointer-based writes, loop writes, plus format-string and function-pointer control-flow risks.
- This label set covers the main path of "external input -> dangerous write/control-flow impact" and supports a measurable optimization loop.

### 5.3 Coverage statement
- This is a **core coverage set** for Type II/III, not a complete vulnerability taxonomy.
- Not fully covered yet: finer semantic sink subtypes, memory-management-specific sinks (UAF/double-free specializations), non-memory-corruption outcomes, and OOB-read/information-leak read sinks.
- So the result should be read as "stable performance in the current label space", not "complete detection for all vulnerability classes".

## 6. Method: How Source/Sink are detected (implementation-level)
### 6.1 Source labels (actual implementation)
- `MMIO_READ`
  - Input: `MemoryAccessIndex.mmio_accesses`.
  - Filters: `kind=="load"`, `base_provenance in {CONST, FLASH_CONST_PTR, INTERPROCEDURAL, STRUCT_RESOLVED, INTRA_RESOLVED}`, `in_isr==False`, `target_addr!=None`.
  - Dedup key: `(function_name, target_addr)`.
  - Output: candidate with facts such as `addr_expr/provenance/cluster/rmw/multi_function` and a confidence score.
- `ISR_MMIO_READ`
  - Same core logic as `MMIO_READ`, but requires `in_isr==True`.
  - Uses the same dedup key and records ISR-specific facts.
- `ISR_FILLED_BUFFER`
  - Scans `mai.accesses` and intersects `ISR store` clusters with `non-ISR load` clusters in SRAM (256B granularity).
  - Emits candidates when both conditions co-exist in the same cluster, including writer/reader function sets and counts.
- `DMA_BACKED_BUFFER`
  - First finds DMA config sites: `store count >= 3` to the same MMIO cluster in the same function.
  - Then requires pointer-like config writes (e.g., `GLOBAL_PTR/CONST`) and uses SRAM-consumption evidence to raise confidence.

### 6.2 Sink labels (actual implementation)
- `COPY_SINK`
  - Symbol search for `memcpy/memmove/strcpy/sprintf...` (including ARM intrinsics), with heuristic fallback for stripped-like cases.
  - Uses xrefs to find callers; if xrefs are empty, falls back to decompile-cache call-pattern scanning.
  - Extracts args, length constness, dst provenance, and bounds-guard presence from caller decompilation.
- `MEMSET_SINK`
  - Same framework as `COPY_SINK` (symbol/xref/decompile).
  - Adds noise filtering for low-risk initialization patterns (e.g., typical constant-size stack clears).
- `STORE_SINK`
  - MAI path: `kind=="store"` with `provenance in {ARG, GLOBAL_PTR, UNKNOWN}`, while excluding MMIO/Flash writes.
  - Param-store fallback path: decompiled patterns such as `*param_N=...`, `param_N[idx]=...`, `ptr->field=...`.
  - Noise control: library filtering, high-fanout filtering, per-function top-k, and global cap.
- `LOOP_WRITE_SINK`
  - Detects `for/while/do` loops and write patterns inside loop bodies (indexed writes or pointer writes).
  - If a copy idiom (e.g., `dst[i]=src[i]`) is recognized, it is promoted from `LOOP_WRITE_SINK` to `COPY_SINK`.
- `FORMAT_STRING_SINK`
  - Identifies printf-family calls and checks the format argument.
  - Literal format => skip; variable/parameter format => keep as sink.
- `FUNC_PTR_SINK`
  - Matches indirect-call patterns: `(*param_N)()`, table dispatch, casted indirect calls, etc.
  - Then checks whether target/index shows input-related features (e.g., `param_` participation).

### 6.3 Evidence verification and final decision
- Each candidate carries structured facts (site, args, provenance, bounds/context).
- Verifier applies label-specific obligations:
  - all required obligations satisfied => `VERIFIED`
  - any required obligation violated => `REJECTED`
  - no violation but unknown required obligations remain => `PARTIAL`
- Final output is therefore determined by both "pattern hit" and "obligation consistency", not by a single rule hit.

## 7. Sample Platform Profile (Architecture / RTOS or runtime environment)
> Note: this profile is an engineering inference based on `readelf` + strings + path features.

| Architecture Guess | Count |
|---|---|
| ARM Cortex-M4/M7 (v7E-M) | 32 |
| ARM Cortex-M3 (STM32F103) | 7 |
| ARM (Cortex-M likely) | 4 |
| ARM Cortex-M3 (Atmel SAM3) | 4 |
| ARM Cortex-M4 (NXP K64F) | 1 |

| Runtime Environment Guess | Count |
|---|---|
| Microbench synthetic bare-metal | 14 |
| STM32 HAL + LwIP (bare-metal style) | 10 |
| Arduino framework (bare-metal style) | 7 |
| Zephyr RTOS | 6 |
| RIOT OS | 4 |
| NuttX | 3 |
| Contiki-NG | 2 |
| Mixed real firmware (framework varies) | 1 |
| FreeRTOS-based | 1 |

Full 48-sample profile: `/tmp/eval_suite_unstripped_elf_20260305_131606/tables/sample_platform_profile.csv`.

## 8. Limitations and Next Steps
1. Add source-side GT (strict scoring is currently sink-only).
2. Upgrade output naming from `stem` to `sample_id` to permanently remove same-name ELF collisions.
3. Improve robustness on large firmware (decompile caching/chunking/retry) to reduce timeouts.
4. Add a small manually labeled subset for non-GT datasets to close the precision loop.
