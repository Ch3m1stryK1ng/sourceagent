# Raw `.bin` minimal structure recovery + LLM supervision (Phase-A extension)

This doc is a **supplemental planning** for the “raw / stripped reality” step:

> **First** make raw binaries analyzable (vector table / base addr / function seeding).  
> **Then** use LLM supervision to resolve *semantic ambiguity* (not to “fix lifting”).

---

## 0) Why raw `.bin` is fundamentally harder

A raw firmware dump lacks the metadata that makes static analysis easy:

- **No loader facts**: no segments, no entry point, no relocations.
- **No symbol names / types**: everything looks like `FUN_...` and `DAT_...`.
- **CFG / function boundaries depend on correct base mapping**.

So for raw binaries, your bottleneck is usually:

1. **Where is the vector table?** (may not be at file offset 0)
2. **What is the image base address?** (0x08000000 vs 0x08008000 vs 0x00400000, …)
3. **How to seed function discovery** so Ghidra can decompile meaningful code.

LLM can *explain* code snippets, but it cannot recover structure if the snippet is garbage.

---

## 1) Current baseline in SourceAgent (already exists)

SourceAgent already has a Stage-1 loader that can load raw `.bin` by:

- using a vector-table heuristic detector
- inferring a base address
- building canonical FLASH/SRAM/MMIO regions
- extracting ISR handler addresses from the vector table

However, the current detector is **offset-0 only** (assumes vector table is at file start), and base inference is coarse.

---

## 2) What we need to add for real raw dumps

### 2.1 Vector table may be not at offset 0

Typical situations:

- **bootloader + application** packed together
  - bootloader VT at 0x08000000 (file offset 0)
  - app VT at 0x08008000 (file offset 0x8000)
- extracted app-only image starts at 0x08008000
  - VT at file offset 0 but base is 0x08008000 (not 0x08000000)

So we need **VT scanning** and **VT ranking**.

### 2.2 Base address may be “page aligned”, not “upper-16bits aligned”

A very common raw dump case:

- reset vector points to `0x08008123`
- correct base should be `0x08008000`

If we only use `upper16(reset)` we get `0x08000000` → wrong mapping → poor decompilation.

So we need a better base inference strategy.

### 2.3 Function boundaries need seeding

Even with correct base, stripped/raw can still yield poor function recovery unless we:

- create/reset functions at **Reset_Handler + ISR handlers**
- expand from them via **direct call targets** (`BL imm`) to seed more functions

---

## 3) Proposed architecture: “RawBootstrap” as Stage-0.5

Add a *lightweight* bootstrap step **before** Ghidra-heavy Stage-2.

```
Stage 1  (existing): load MemoryMap hypothesis
Stage 0.5 (NEW): RawBootstrap
    - scan vector-table candidates (offset-aware)
    - generate base hypotheses
    - score hypotheses (cheap disasm sanity)
    - output: best MemoryMap + bootstrap_report.json
Stage 2  (existing): Ghidra import + MAI build
Stage 2b (NEW): function seeding in Ghidra (vector + call targets)
Stage 3+ (existing): sources/sinks/objects/chains + Phase-B review
```

Key property:

- **Phase A remains fail-closed.** RawBootstrap only chooses the best hypothesis and documents why.
- If confidence is low → optionally run **top-K hypotheses** (K=2) to avoid missing the “real image”.

---

## 4) RawBootstrap details

### 4.1 Scan vector tables anywhere in the file

Implement an offset-aware scan:

- scan window (default): first `max_scan = 0x40000` bytes (configurable)
- step: 4 bytes (uint32 aligned)

Candidate acceptance rules (cheap):

- word0 (SP) in `[0x2000_0000, 0x3FFF_FFFF]` (broaden a bit vs strict 0x20FF…)
- word1 (Reset) is odd (Thumb bit) and not tiny (<0x100)
- reserved core vectors have plausible pattern (don’t require all zero; allow MCU-specific deviations)

Then parse extended table (up to N entries) and extract handler pointers.

Output: `VectorTableCandidate(file_offset, sp, reset, handlers[], vt_score, notes)`.

### 4.2 Generate base hypotheses (narrow search space)

For each candidate VT:

- collect a set of handler addresses: `{reset_addr} ∪ handlers[:M]`
- generate base candidates by alignment:

  - `align_down(min(handler_addrs), 0x1000)`
  - `align_down(min(handler_addrs), 0x2000)`
  - `align_down(min(handler_addrs), 0x4000)`
  - `align_down(min(handler_addrs), 0x10000)`

- also include “canonical bases”:
  - `0x08000000`, `0x00000000`, `0x00400000` (QEMU/Zephyr style)

This keeps base search small (tens of candidates, not millions).

### 4.3 Score each (VT_offset, base) pair (deterministic)

We want a *cheap* score that correlates with “good lifting”:

**Score components** (example):

1. **addr_coverage**: how many handler addresses map into file
   - for addr in handlers: `off = addr - base`
   - count `0 <= off < file_size`

2. **reset_decode_ratio**: quick disasm sanity around Reset_Handler
   - compute `reset_off = reset_addr - base`
   - disassemble ~0x100 bytes with Capstone (Thumb)
   - ratio = decoded_insns / expected

3. **prologue sanity**: does reset handler start with plausible prologue
   - typical patterns: `push {..., lr}`, `sub sp, ...`, `ldr rX, =...`

4. **vector self-consistency**
   - vector table address = base + vt_offset
   - ensure handler addrs are “near” the image region (not wildly outside)

Pick best scoring hypothesis.

### 4.4 Multi-image / bootloader case: top-K hypotheses

If the best score is not “confident enough”, allow:

- keep top-K hypotheses (K=2 by default)
- run Phase-A chain assembly for each
- choose better one using post-Ghidra quality metrics (see 4.6)

This is controlled by CLI flags, not hardcoded.

### 4.5 Function seeding (critical for stripped/raw)

After importing into Ghidra:

- create functions at:
  - `Reset_Handler`
  - every ISR handler address from the selected VT

Then **expand seeds** using direct call targets:

- for each seed function:
  - disassemble/decompile first N lines
  - extract immediate `BL` targets (direct calls)
  - add to seed set if within flash range

Bound the expansion:

- depth ≤ 2
- max seeds ≤ 500 (config)

This improves coverage without exploding runtime.

### 4.6 LiftingQualityReport and hypothesis fallback

After Ghidra analysis, compute a small quality report:

- number of discovered functions
- number of successfully decompiled functions
- percent of “valid instructions” in key regions
- MAI coverage: #functions with at least one access parsed

If quality is bad and we kept top-2 hypotheses → try hypothesis #2.

Write: `raw_bootstrap_report.json` with all candidates/scores.

---

## 5) Code-level planning (repo layout)

### 5.1 New dataclasses

**File:** `sourceagent/pipeline/models.py`

- `VectorTableCandidate`
- `RawHypothesis`
- `LiftingQualityReport`

Extend `MemoryMap`:

- `vector_table_file_offset: int`
- `hypotheses: List[RawHypothesis]` (optional, for auditing)

### 5.2 Detector upgrade

**File:** `sourceagent/agents/firmware_detect.py`

Add:

- `scan_vector_tables(data: bytes, max_scan: int, step: int) -> List[VectorTableCandidate]`
- `detect_cortex_m_raw_candidates(path) -> List[RawHypothesis]`

Keep old `detect_cortex_m_raw()` as wrapper returning best.

### 5.3 Loader upgrade

**File:** `sourceagent/pipeline/loader.py`

Modify `_load_from_raw_bin()`:

- use candidate list
- select best (or keep top-K)
- set:
  - `base_address`
  - `vector_table_addr = base_address + vector_table_file_offset`
  - `entry_point = reset_handler`

### 5.4 New bootstrap module

**New file:** `sourceagent/pipeline/raw_bootstrap.py`

Responsibilities:

- hypothesis scoring (addr_coverage + capstone sanity)
- selection / top-K logic
- write `raw_bootstrap_report.json`

### 5.5 Ghidra function seeding helper

**New file:** `sourceagent/pipeline/ghidra_seed.py`

- `seed_vector_functions(mcp, prog, addrs)`
- `expand_seeds_by_direct_calls(mcp, prog, seeds, depth, budget)`

Integrate call target extraction:

- prefer Ghidra listing/pcode if available
- else fallback to Capstone using raw bytes (addr→file_offset via base)

### 5.6 CLI controls

**File:** `sourceagent/interface/main.py`

Add args:

- `--raw-scan-max` (default 0x40000)
- `--raw-topk` (default 1 or 2)
- `--raw-page-align` (default 0x1000)
- `--raw-base` (manual override)
- `--raw-vt-offset` (manual override)
- `--raw-bootstrap-mode` (`auto | force_manual | vt_scan_only`)

---

## 6) Where LLM supervision fits (and where it does not)

### 6.1 LLM is **not** the raw lifting engine

LLM supervision should **not** be used for:

- “guess the base address”
- “guess function boundaries”
- “fix CFG”

Those should be deterministic + auditable.

### 6.2 LLM supervision is for *semantic ambiguity* only

Once we have decent decompile snippets, LLM can help with:

- **sink classification** in stripped/raw:
  - copy loop vs benign loop
  - format-string usage
  - function-pointer dispatch semantics

- **check adequacy**:
  - does the check actually bound the sink argument?

- **derive semantics**:
  - header parsing → length/type fields

Implementation style:

- miner emits `candidate(confidence, evidence)`
- if confidence below threshold → send to supervising LLM
- LLM returns `accept/reject/refine + reason_codes + evidence_map`
- Phase A keeps deterministic gates, but stores LLM rationale even when rejected

---

## 7) Why this approach is “heuristic + bounded enumeration”

You asked: “穷举还是启发式？”

For raw bootstrap we should do:

- **Heuristic ranking** (cheap scores) to avoid huge search
- **Bounded top-K enumeration** only when confidence is low

This is similar in spirit to Mango’s sink-first heuristics, but applied to *lifting hypotheses*:

- we don’t enumerate all bases
- we enumerate only a few high-quality candidates

---

## 8) Minimal implementation order (engineering)

1. VT scan (offset-aware) + base candidates
2. Loader update (vt_offset + base mapping)
3. Capstone sanity scoring + RawBootstrap report
4. Ghidra function seeding (vector + BL targets)
5. top-K fallback when quality low
6. then connect to Phase-A LLM supervision and Phase-B reviewer

