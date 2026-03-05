# Phase4e Sink Evaluation Report (TP/FP/FN + Root Cause Analysis)

## 1) Evaluation Scope and Run Configuration

- Run artifacts: `/tmp/eval_phase4e_fpfn_tune2`
- Evaluated command:
  - `python3 -m sourceagent.interface.main eval --all firmware/microbench --formats elf --gt-json firmware/ground_truth_bundle/normalized_gt_sinks.json --output-dir /tmp/eval_phase4e_fpfn_tune2 --online`
- Run config (from `run_manifest.json`):
  - `online=true`
  - `stage=7`
  - proposer mode: `heuristic` (no LLM)
  - accepted verdicts: `VERIFIED,PARTIAL`
  - requested eval scope: `auto`
- Dataset selection:
  - 28 ELF files were scanned under `firmware/microbench` (14 normal + 14 `_stripped`)
  - Only 10 stems had sink GT and were scored
  - Effective scored scope was `sinks` for all 10 scored stems

## 2) Aggregate Metrics

### Strict metrics

- TP: **6**
- FP: **27**
- FN: **12**
- Precision: **0.1818**
- Recall: **0.3333**
- F1: **0.2353**

### Weighted metrics (partial-credit = 0.5)

- TP: **8.5**
- FP: **24.5**
- FN: **9.5**
- Precision: **0.2576**
- Recall: **0.4722**
- F1: **0.3333**

## 3) Sample-Level TP/FP/FN (Strict)

| Binary | TP | FP | FN |
|---|---:|---:|---:|
| cve_2018_16525_freertos_dns | 1 | 3 | 2 |
| cve_2020_10065_hci_spi | 1 | 4 | 1 |
| cve_2021_34259_usb_host | 0 | 6 | 3 |
| t0_copy_sink | 1 | 1 | 1 |
| t0_dma_length_overflow | 1 | 0 | 0 |
| t0_format_string | 0 | 12 | 1 |
| t0_func_ptr_dispatch | 0 | 0 | 1 |
| t0_indirect_memcpy | 1 | 0 | 0 |
| t0_store_loop_sink | 1 | 1 | 2 |
| t0_uart_rx_overflow | 0 | 0 | 1 |

## 4) GT Outcome Breakdown

### Exact TP (6)

- `COPY_SINK`: 5 exact hits
  - `cve_2018_16525_freertos_dns @ 0x080000a0`
  - `cve_2020_10065_hci_spi @ 0x08000088`
  - `t0_copy_sink @ 0x0800005c`
  - `t0_dma_length_overflow @ 0x0800007c`
  - `t0_indirect_memcpy @ 0x0800005c`
- `MEMSET_SINK`: 1 exact/near-address hit
  - `t0_store_loop_sink` GT `0x0800007a` matched by prediction `0x08000076` (`address_near`)

### Partial matches (5)

- `LENGTH_TRUST_SINK`: 1 partial via `STORE_SINK` label hint
- `COPY_SINK`: 1 partial via sink-family (`MEMSET_SINK`)
- `PARSING_OVERFLOW_SINK`: 3 partial via `STORE_SINK` label hint

### Hard unmatched FN (7)

- `UNBOUNDED_WALK_SINK`: 1
- `COPY_SINK`: 2
- `FORMAT_STRING_SINK`: 1
- `FUNC_PTR_SINK`: 1
- `STORE_SINK`: 1
- `LOOP_WRITE_SINK`: 1

Note: strict FN is 12 because strict scoring treats partial matches as non-exact.

## 5) FP Breakdown

### Unmatched FP by predicted label (from `fp_by_label`)

- `STORE_SINK`: **13**
- `COPY_SINK`: **5**
- `LOOP_WRITE_SINK`: **4**
- Total unmatched FP: **22**

### Why strict FP is 27 (not 22)

Strict FP counts predictions that are only partial matches as FP.
There are 5 such near-miss predictions:

- 4 `STORE_SINK` used in label-hint partial matching
- 1 `MEMSET_SINK` used in sink-family partial matching

So: 22 unmatched FP + 5 partial-matched predictions = strict FP 27.

## 6) Root Cause Analysis (Code-Level)

### FN Root Causes

1. Missing/insufficient specialized miners for non-copy sink types
- Affected:
  - `t0_format_string` (`FORMAT_STRING_SINK`)
  - `t0_func_ptr_dispatch` (`FUNC_PTR_SINK`)
  - `cve_2018_16525_freertos_dns` (`UNBOUNDED_WALK_SINK`)
- Why:
  - Current fallback pattern coverage is still narrow for stripped/decompiler variants.
  - True sink pattern exists in source GT but not recovered from current decompiled forms.

2. COPY sink misses on non-API copy idioms / incomplete alias recovery
- Affected:
  - `t0_copy_sink` second sink (`handle_name`, `strcpy` path)
  - `t0_uart_rx_overflow` (`uart_receive`, loop-based overflow copy)
- Why:
  - Current `COPY_SINK` focuses on recovered copy APIs plus limited heuristics.
  - Loop-based byte-copy sink (`for i < len: buf[i]=...`) is not yet promoted as `COPY_SINK`.

3. STORE/LOOP_WRITE under-detection in minimal functions
- Affected:
  - `t0_store_loop_sink` (`write_register`, `fill_buffer`)
- Why:
  - Current `STORE_SINK`/`LOOP_WRITE_SINK` still depends on MAI/decompile coverage that can miss small target functions and rank wrong helper functions.

4. Semantic label granularity mismatch (strict metric)
- Affected:
  - `cve_2021_34259_usb_host` (`PARSING_OVERFLOW_SINK`)
  - `cve_2018_16525_freertos_dns` (`LENGTH_TRUST_SINK`)
- Why:
  - Pipeline emits generalized memory-write sink labels (`STORE_SINK`/`MEMSET_SINK`) while GT carries semantic subtypes.
  - Weighted mode captures this as partial; strict mode penalizes as FN.

### FP Root Causes

1. Over-broad `STORE_SINK` heuristics (dominant FP source)
- Count impact: 13 unmatched FP (+4 partial-matched strict-FP contributors)
- Typical pattern:
  - `param-store` or unresolved pointer stores in helper/lib internals.
  - Not vulnerability-relevant sink sites but still satisfy current store obligations.

2. `LOOP_WRITE_SINK` over-trigger in library/runtime loops
- Count impact: 4 unmatched FP (all in `t0_format_string`)
- Typical pattern:
  - General loops with writes inside formatting/runtime code paths are labeled as sinks without vulnerability context.

3. `COPY_SINK` extra detections on non-vulnerable copy sites
- Count impact: 5 unmatched FP
- Typical pattern:
  - Additional `memcpy`-style sites exist, but GT records only intended vulnerable sink instances.

## 7) Concrete Code Pattern Examples (Why Hit / Why Miss)

This section ties GT cases to concrete code/decompiler patterns and current miner rules.

### Example A: COPY_SINK correctly detected (API-style call)

- GT source snippet: `t0_copy_sink.c`
  - `memcpy(dst, src, n);` at [t0_copy_sink.c](/home/a347908610/sourceagent/firmware/microbench/t0_copy_sink.c:58)
- Observed mined pattern (raw result):
  - `callee=memcpy`
  - `args=['param_1','auStack_58','param_2']`
  - candidate at `FUN_0800005c`
- Why detected:
  - `copy_sink` matches known copy APIs from `COPY_FUNCTION_NAMES` and extracts args/len (`_LEN_ARG_INDEX`)
  - Rule fit: variable `len` + no strong guard => `COPY_SINK`

### Example B: COPY_SINK missed (strcpy path in same sample)

- GT source snippet: `t0_copy_sink.c`
  - `strcpy(local_name, g_name);` at [t0_copy_sink.c](/home/a347908610/sourceagent/firmware/microbench/t0_copy_sink.c:64)
- Outcome:
  - GT `COPY_SINK@0x08000094` is FN
  - Only `COPY_SINK@0x0800005c` (memcpy path) was found
- Why missed:
  - Current run recovered only one usable copy callee path in this binary (`memcpy`)
  - `strcpy` callsite path was not recovered as a separate mined site, so no second `COPY_SINK` proposal

### Example C: MEMSET_SINK detected with near-address tolerance

- GT source snippet: `t0_store_loop_sink.c`
  - `memset(buf, 0, n);` at [t0_store_loop_sink.c](/home/a347908610/sourceagent/firmware/microbench/t0_store_loop_sink.c:67)
- Observed mined pattern:
  - candidate `MEMSET_SINK@0x08000076` (GT is `0x0800007a`)
  - extracted args: `['param_1','0','param_2', ...]`
- Why detected:
  - `additional_sinks` memset miner matched callsite and extracted variable length
  - Eval `address_near` matching absorbed small callsite/entry skew

### Example D: LOOP_WRITE_SINK missed (variable-bound loop write)

- GT source snippet: `t0_store_loop_sink.c`
  - `for (i=0; i<n; i++) buf[i] = spi_read_byte();` at [t0_store_loop_sink.c](/home/a347908610/sourceagent/firmware/microbench/t0_store_loop_sink.c:59)
- Outcome:
  - GT `LOOP_WRITE_SINK@fill_buffer` is FN
- Why missed:
  - Current loop miner relies on decompiled loop/store shapes (e.g., `dst[idx]=...`, `*(ptr+idx)=...`)
  - In this binary’s analyzed decompile coverage, the `fill_buffer` site was not emitted as a loop-write candidate

### Example E: COPY-like overflow missed (loop copy, no memcpy API)

- GT source snippet: `t0_uart_rx_overflow.c`
  - `for (i=0; i<len; i++) buf[i] = uart_read_byte();` at [t0_uart_rx_overflow.c](/home/a347908610/sourceagent/firmware/microbench/t0_uart_rx_overflow.c:53)
- Outcome:
  - GT `COPY_SINK@uart_receive` is FN
- Why missed:
  - This is an inline loop-copy idiom, not an API call (`memcpy/strcpy`)
  - Current `COPY_SINK` miner is still primarily API/signature driven; loop-copy promotion to `COPY_SINK` is incomplete

### Example F: FORMAT_STRING_SINK missed

- GT source snippet: `t0_format_string.c`
  - `sprintf(g_log_buf, fmt);` at [t0_format_string.c](/home/a347908610/sourceagent/firmware/microbench/t0_format_string.c:70)
- Outcome:
  - GT `FORMAT_STRING_SINK@log_message` is FN
- Why missed:
  - In this analyzed binary context, no stable printf-family symbol/xref path was recovered for this callsite
  - Strict fallback pattern (2-arg wrapper with param-derived format) did not trigger on recovered function set

### Example G: FUNC_PTR_SINK missed

- GT source snippet: `t0_func_ptr_dispatch.c`
  - `handler = cmd_table[cmd_id]; handler();` at [t0_func_ptr_dispatch.c](/home/a347908610/sourceagent/firmware/microbench/t0_func_ptr_dispatch.c:72)
- Outcome:
  - GT `FUNC_PTR_SINK@dispatch_command` is FN
- Why missed:
  - Current indirect-call miner patterns (`indexed_dispatch`, `table_dispatch`, `local_fptr`, etc.) did not match the recovered decompiler form for this function
  - Also indicates a coverage gap: target function did not produce a miner-visible indirect-call pattern in this run

### Example H: Major FP cluster in `t0_format_string`

- Observed FP patterns from raw results:
  - `STORE_SINK`: 6 unmatched FPs
  - `LOOP_WRITE_SINK`: 4 unmatched FPs
  - `COPY_SINK`: 2 unmatched FPs
- Typical mined loop/store expressions:
  - `store_expr=puVar2[1]`, `store_expr=pcVar14[-1]`, `store_expr=piVar3[1]`
- Why these become FP:
  - They are internal runtime/formatting helper loops and pointer stores
  - Current heuristics label memory-write-heavy library internals as sinks without enough vulnerability context gating

### Rule-to-Pattern Mapping (Current Miners)

- `STORE_SINK` param-store heuristic:
  - Regex: `*param_N = ...`, `*(type *)(param_N + off) = ...`, `param_N[idx] = ...`
  - Implemented in [additional_sinks.py](/home/a347908610/sourceagent/sourceagent/pipeline/miners/additional_sinks.py:40)
  - Typical matched decompiler shape: `*param_1 = ...` (can over-fire in helper/lib code)

- `LOOP_WRITE_SINK` loop-store heuristic:
  - Regex families: `dst[idx]=...`, `*(ptr+idx)=...`, `*ptr++=...`, `param_N[idx]=...`
  - Implemented in [additional_sinks.py](/home/a347908610/sourceagent/sourceagent/pipeline/miners/additional_sinks.py:772)
  - Observed FP examples in `t0_format_string`: `puVar2[1]`, `pcVar14[-1]`, `piVar3[1]`

- `FORMAT_STRING_SINK` stripped fallback wrapper:
  - Pattern intent: `CALL(dst, param_N);` with non-parameter destination and no loop
  - Implemented in [format_string_sink.py](/home/a347908610/sourceagent/sourceagent/pipeline/miners/format_string_sink.py:171)
  - Failure mode in this run: no recovered function matched this strict wrapper form for `log_message`

- `FUNC_PTR_SINK` indirect-call detection:
  - Pattern families: `(*(code **)(table + idx*4))()`, `table[idx]()`, local-fptr call chains
  - Implemented in [func_ptr_sink.py](/home/a347908610/sourceagent/sourceagent/pipeline/miners/func_ptr_sink.py:31)
  - Miss reason in `t0_func_ptr_dispatch`: recovered decompile did not match any supported indirect-call shape

- `COPY_SINK` API/signature detection:
  - Callee set includes `memcpy/strcpy/...`
  - Implemented in [copy_sink.py](/home/a347908610/sourceagent/sourceagent/pipeline/miners/copy_sink.py:38)
  - Works well for explicit `memcpy(...)` but misses loop-copy idioms unless promoted by additional logic

## 8) High-Priority Fix Plan

1. Add a dedicated loop-copy-to-fixed-buffer sink miner
- Target labels: `COPY_SINK`, `UNBOUNDED_WALK_SINK`
- Impact:
  - `t0_uart_rx_overflow`, part of `cve_2018_16525_freertos_dns`

2. Improve stripped-callsite recovery for `strcpy`/wrapper path
- Target labels: `COPY_SINK`
- Impact:
  - `t0_copy_sink` second sink (`handle_name`)

3. Tighten `STORE_SINK` with context gates
- Add gates:
  - exclude high-fanout libc-like helper functions
  - require source-to-sink influence evidence for high-confidence emission
- Impact:
  - largest FP reduction (especially CVE and `t0_format_string`)

4. Strengthen `FORMAT_STRING_SINK` and `FUNC_PTR_SINK` miners on stripped forms
- Expand decompile-shape templates with stronger anti-FP filters
- Impact:
  - resolve hard FNs in `t0_format_string`, `t0_func_ptr_dispatch`

5. Keep strict and weighted views side-by-side in reporting
- Strict for exact-label claims
- Weighted for semantic-family progress tracking

## 9) Key Files/Artifacts

- Summary:
  - `/tmp/eval_phase4e_fpfn_tune2/summary/eval_summary.json`
- Per-sample matching:
  - `/tmp/eval_phase4e_fpfn_tune2/detailed/*.matching.json`
- Full detailed list:
  - `/tmp/eval_phase4e_fpfn_tune2/detailed/all_samples_detailed.json`
- Run parameters:
  - `/tmp/eval_phase4e_fpfn_tune2/run_manifest.json`
