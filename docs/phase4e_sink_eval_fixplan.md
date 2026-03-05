# Phase4e Sink Evaluation – Analysis & Fix Plan (SourceAgent)

This document summarizes the **Phase4e Sink Evaluation Report** and proposes concrete engineering updates to improve **sink detection** accuracy and completeness. It also includes a ready-to-paste prompt for Claude.

---

## 1. Executive Summary

**Current state (strict scoring):**
- **TP=6, FP=27, FN=12**
- **Precision=0.1818**, **Recall=0.3333**, **F1=0.2353**

**Current state (weighted scoring; partial-credit=0.5):**
- **TP=8.5, FP=24.5, FN=9.5**
- **Precision=0.2576**, **Recall=0.4722**, **F1=0.3333**

**Interpretation:**
- The pipeline is already **good at API-style COPY sinks** (memcpy-like) and can sometimes hit **MEMSET** (near-address).
- The main blockers are:
  1) **Missing/weak miners** for non-copy sink types (FORMAT_STRING, FUNC_PTR, UNBOUNDED_WALK, loop-copy promotion).
  2) **STORE_SINK over-fires** (dominant FP source), especially inside formatting/runtime internals.
  3) **Loop-based writes/copies** are under-detected (FN) or over-triggered (FP) depending on where they appear.
  4) **Label granularity mismatch**: GT contains semantic subtypes, while the pipeline emits generalized sink families.

---

## 2. What Works (Signal)

### 2.1 API-style COPY_SINK detection is the strongest component
- 5 exact `COPY_SINK` hits were recorded (e.g., memcpy callsites in multiple targets).
- `t0_dma_length_overflow` and `t0_indirect_memcpy` are strict-perfect for sinks (TP=1, FP=0, FN=0).

### 2.2 MEMSET_SINK can be recovered (with near-address tolerance)
- `t0_store_loop_sink`: GT `0x0800007a` matched by prediction `0x08000076` under address-near matching.

### 2.3 Partial-credit pipeline-label-hints are meaningful progress
- Parsing-overflow and length-trust style GT entries can be partially matched via `STORE_SINK` hints.
- Weighted metrics better reflect semantic-family progress than strict metrics.

---

## 3. What Fails (Root Causes)

### 3.1 Hard FNs are dominated by missing specialized miners and weak “loop idiom” coverage
Hard unmatched sink types include:
- `FORMAT_STRING_SINK` (t0_format_string)
- `FUNC_PTR_SINK` (t0_func_ptr_dispatch)
- `UNBOUNDED_WALK_SINK` (cve_2018_16525_freertos_dns)
- `LOOP_WRITE_SINK` (t0_store_loop_sink)
- `COPY_SINK` on non-API loop-copy idioms (t0_uart_rx_overflow)

**Key insight:** Many “real” vulnerabilities in firmware do **not** manifest as explicit `memcpy()` calls; they appear as loop copies and pointer walks.

### 3.2 FP cluster is dominated by STORE_SINK (and library/runtime internals)
- Unmatched FP by predicted label:
  - `STORE_SINK`: 13 (plus 4 more that become strict-FP due to partial-match accounting)
  - `COPY_SINK`: 5
  - `LOOP_WRITE_SINK`: 4
- The single worst offender is `t0_format_string`: **12 strict FPs**, largely due to STORE/LOOP_WRITE patterns inside formatting internals.

**Key insight:** “Writes happen” ≠ “dangerous sink”. STORE_SINK needs stronger **context gating** and/or **callsite attribution**.

### 3.3 Strict scoring penalizes partial matches
- 5 predictions that contributed to partial matches are still counted as strict FP.
- Without dual reporting (strict vs weighted), regression analysis becomes confusing.

---

## 4. Prioritized Engineering Fix Plan (P0–P2)

### P0 (Highest impact, lowest risk): Fix “callsite recovery” and stabilize sink attribution
**Goal:** Ensure we can reliably map API-like sinks to their callsites, even when symbols/thunks differ.

1) **Robust callsite discovery helper**
   - Prefer Ghidra References / P-code `CALL` sites over decompiler-text regex.
   - Resolve **thunks / wrappers / alternative entrypoints**:
     - If a function is a thunk, also search xrefs to the thunk target and vice versa.
     - Search xrefs to *all plausible entrypoints*.
   - Fallback to decompile-cache scanning only if IR-based reference lookup yields 0.

**Expected impact:**
- Recover additional `COPY_SINK` and `MEMSET_SINK` callsites in stripped variants.
- Reduce “missing strcpy path” cases where the callee exists but xref discovery fails.

---

### P0: Promote loop-copy idioms to COPY_SINK (and UNBOUNDED_WALK family)
**Goal:** Turn `t0_uart_rx_overflow`-like patterns into sinks.

2) **Loop-copy miner (new)**
   - Detect loops where:
     - `dst[i] = src_like(...)` or `*(dst+i) = *(src+i)` style store occurs
     - loop bound depends on variable length (`len`, `n`, `param_k`, MMIO-derived)
   - Output label:
     - `COPY_SINK` if loop semantics match copy
     - `UNBOUNDED_WALK_SINK` if pointer increments until delimiter/0 without bound

**Implementation hint (robust approach):**
- Use P-code: locate `STORE` in a loop body; back-slice the stored value and address expression.
- Require: address expression uses an induction-like variable or pointer post-increment.

**Expected impact:**
- Convert at least 1 hard FN (t0_uart_rx_overflow) to TP.
- Improve realism beyond memcpy-only benchmarks.

---

### P1: Make FORMAT_STRING and FUNC_PTR miners robust to stripped/decompiler variation
3) **FORMAT_STRING_SINK miner improvements**
   - Find callsites to printf-family (sprintf/snprintf/vsnprintf/printf/fprintf/…):
     - Strategy order: symbol → signature → decompiler fallback
   - Vulnerability rule (minimal viable):
     - If **format argument is NOT a string literal** (not `"..."`) ⇒ emit `FORMAT_STRING_SINK`
     - Optionally boost confidence if format is a parameter or MMIO/ISR-derived buffer pointer
   - Add a “library-internal filter”: prefer caller-level sinks over internal loops in libc.

**Expected impact:**
- Fix `t0_format_string` hard FN without flooding FP in formatting internals.

4) **FUNC_PTR_SINK miner (use CALLIND)**
   - Do not rely on decompiler patterns. Use P-code `CALLIND`.
   - Emit `FUNC_PTR_SINK` when:
     - indirect target value originates from:
       - input parameter, or
       - memory load indexed by input, or
       - MMIO-derived byte/word
   - Keep it conservative (fail-closed): if origin is unknown, emit low-confidence or PARTIAL.

**Expected impact:**
- Fix `t0_func_ptr_dispatch` hard FN.

---

### P1: Reduce STORE_SINK false positives with context gates (precision booster)
5) **STORE_SINK gating rules**
   - Add at least two of these gates before emitting high-confidence STORE_SINK:
     - **Exclude libc-like high fanout functions** (many callers; runtime helpers).
     - Require a **size/length variable** in the same basic block/loop condition (or strong evidence of unboundedness).
     - Require **source influence** on either:
       - destination pointer, or
       - stored value, or
       - length/loop bound.
   - Additionally:
     - Deduplicate: keep top-K sinks per function by confidence.
     - Down-rank sinks inside known library regions (if you can identify them).

**Expected impact:**
- Large FP reduction (dominant FP label is STORE_SINK).
- Particularly reduces `t0_format_string` FP cluster.

---

### P2: Reporting & Evaluation hygiene (so you can iterate faster)
6) **Always report strict + weighted side-by-side**
   - Strict: exact label+address claims
   - Weighted: semantic-family progress
   - Add a third view: “strict but do not count partial matches as FP” to reduce confusion.

7) **Address matching: keep `address_near`, but standardize tolerance**
   - Use a consistent window for callsite/entry skew.
   - Prefer function-level match for wrappers where exact callsite is unstable.

---

## 5. Acceptance Criteria (What to re-run and what to expect)

Re-run:
```bash
python3 -m sourceagent.interface.main eval \
  --all firmware/microbench --formats elf \
  --gt-json firmware/ground_truth_bundle/normalized_gt_sinks.json \
  --output-dir /tmp/eval_after_fixes \
  --online
```

Targets (realistic, incremental):
- **Recall (strict)**: 0.33 → **0.55+**
- **Precision (strict)**: 0.18 → **0.30+** (mainly via STORE_SINK gating)
- Must specifically flip these hard FNs:
  - `t0_uart_rx_overflow` (loop-copy → COPY_SINK)
  - `t0_format_string` (FORMAT_STRING_SINK)
  - `t0_func_ptr_dispatch` (FUNC_PTR_SINK)
  - `t0_store_loop_sink` (LOOP_WRITE_SINK)

---

## 6. Prompt for Claude (paste as-is)

```text
You are Claude, acting as a senior engineer improving a firmware static-analysis pipeline (“SourceAgent”) for sink detection.

CONTEXT
- We ran: `python3 -m sourceagent.interface.main eval --all firmware/microbench --formats elf --gt-json firmware/ground_truth_bundle/normalized_gt_sinks.json --output-dir /tmp/eval_phase4e_fpfn_tune2 --online`
- Scored 10 stems with sink GT.
- Strict results: TP=6 FP=27 FN=12 (Precision=0.1818, Recall=0.3333, F1=0.2353).
- Weighted (partial=0.5): TP=8.5 FP=24.5 FN=9.5 (Precision=0.2576, Recall=0.4722, F1=0.3333).
- Exact hits are mainly API-style COPY_SINK (memcpy) and 1 MEMSET near-hit.
- Hard FNs: FORMAT_STRING_SINK, FUNC_PTR_SINK, UNBOUNDED_WALK_SINK, LOOP_WRITE_SINK, plus COPY_SINK for loop-copy idioms.
- Dominant FP source: STORE_SINK (especially runtime/formatting internals; t0_format_string has 12 strict FPs).

TASK
Design and implement a patch plan that increases strict sink recall and improves precision, prioritizing deterministic, verifier-friendly logic.

P0: Robust callsite recovery (avoid fragile decompiler regex)
- Implement a shared helper to find callsites to a callee:
  1) Use Ghidra ReferenceManager / P-code CALL sites to gather callers.
  2) Resolve thunk/wrapper/alternate entrypoints (search refs to thunk target and thunk entry).
  3) Only if IR-based lookup fails, fall back to decompile-cache scanning.
- Apply this to COPY_SINK and MEMSET_SINK callsite discovery.

P0: Add a loop-copy miner and promote to COPY_SINK / UNBOUNDED_WALK
- Detect loops where a STORE writes to dst[i] / *(dst+i) and the stored value is sourced from:
  - another memory load *(src+i), OR
  - a function returning a byte/word (uart_read_byte/spi_read_byte), OR
  - buffer reads.
- Require variable/untrusted bounds (len/param, MMIO-derived, etc.).
- Emit COPY_SINK (or UNBOUNDED_WALK_SINK if pointer walk until delimiter/0 w/o bound).
- Prefer P-code based detection (STORE + loop backedge + def-use slice). Avoid pure regex.

P1: Strengthen FORMAT_STRING and FUNC_PTR miners
- FORMAT_STRING_SINK:
  - Find printf-family callsites even when symbols are stripped (symbol → signature → fallback).
  - Emit sink when format argument is NOT a string literal.
  - Avoid FP by preferring caller-level sink attribution vs libc internal loops.
- FUNC_PTR_SINK:
  - Implement using P-code CALLIND detection, not decompiler text.
  - Trace indirect target origin; flag high-confidence when derived from param or input-indexed table lookup or MMIO-derived data.

P1: Reduce STORE_SINK false positives with context gates
- Add gates before emitting high-confidence STORE_SINK:
  - exclude high-fanout libc-like helpers,
  - require size/length involvement or strong unboundedness evidence,
  - require source influence on dst/value/len when possible.
- Deduplicate / top-K sinks per function.

P2: Evaluation hygiene
- Ensure reports always show strict + weighted side-by-side.
- Consider a third metric where partial matches are not counted as strict FP (for debugging clarity).
- Keep address_near matching consistent.

DELIVERABLES
1) Proposed code changes (file-level plan + short pseudocode snippets).
2) Minimal unit tests for the new miners (microbench targets: t0_uart_rx_overflow, t0_format_string, t0_func_ptr_dispatch, t0_store_loop_sink).
3) Expected metric improvements and how to validate with the eval command.

Now produce the patch plan and implementation guidance.
```

---

## 7. Notes / Caveats

- Do not optimize only for GT: some GT entries record only *one* intended vulnerable sink among multiple real copy sites. Your precision may appear low if you correctly find “extra” copy sites. In that case, report both:
  - “GT-strict precision”
  - “All-real-sink precision” (if you build a broader GT later)

- Keep strict vs weighted metrics in all reports; otherwise partial-credit improvements will look like regressions.

