# Detailed Planning Memo
## Async Context Communication, ChannelGraph Recovery, and Sink-to-Source Tunnel Detection (Code-Level Implementation)

## Executive Summary
The current SourceAgent RQ1 layer is usable: source/sink labeling is largely in place. The next phase is not about adding more isolated labels; it is about connecting labels into verifiable, explainable, reproducible chains.

This document defines:
- A unified JSON contract for ChannelGraph and Chain artifacts.
- Module-level inputs/outputs, dependencies, and failure modes.
- Concrete case studies on microbench and CVE-2020-10065.

---

## 3. Architecture Overview (Pipeline + Artifacts)

### 3.1 Logical Module View
```text
+---------------------------------------------------------------+
| Stage 1/2/2.5: Loader + MAI + Interprocedural                |
+---------------------------------------------------------------+
                            |
                            v
+---------------------------------------------------------------+
| Stage 3/4: Source/Sink Miners                                 |
| - Sources: MMIO_READ / ISR_* / DMA_BACKED_BUFFER             |
| - Sinks: COPY / MEMSET / STORE / LOOP_WRITE / FUNC_PTR / FMT |
+---------------------------------------------------------------+
                            |
                            v
+---------------------------------------------------------------+
| Stage 5/6/7: Evidence Pack -> Proposal -> Verifier           |
| Output: verified labels                                      |
+---------------------------------------------------------------+
                            |
                            v
+---------------------------------------------------------------+
| M8.5/M8.6: ChannelGraph + Object Boundary Refinement         |
| Output: channel_graph.json / refined_objects.json            |
+---------------------------------------------------------------+
                            |
                            v
+---------------------------------------------------------------+
| M9/M9.1/M9.2: Sink Roots -> Tunnel Linker -> Derive/Check    |
| Output: sink_roots.json / chains.json / chain_eval.json      |
+---------------------------------------------------------------+
                            |
                            v
+---------------------------------------------------------------+
| M9.3: Suspicious Queue Export                                |
| Output: low_conf_sinks.json / triage_queue.json              |
+---------------------------------------------------------------+
```

### 3.2 Artifact Flow
```text
MAI
 |- source_candidates.json
 |- sink_candidates.json
 `- verified_labels.json
      |- channel_graph.json       (M8.5)
      |- refined_objects.json     (M8.6)
      |- sink_roots.json          (M9)
      |- chains.json              (M9.1, primary output)
      |- chain_eval.json          (M9.2 summary)
      |- low_conf_sinks.json      (M9.3 input-side snapshot)
      `- triage_queue.json        (M9.3 top-K queue)
```

---

## 4. Async Context Communication and ChannelGraph (Definitions and Spec)

### 4.1 Terms and Boundaries

#### 4.1.1 MAI
`MAI = MemoryAccessIndex` from Stage 2:
- Per access fields: `address/kind(load|store)/target_addr/base_provenance/function/in_isr`.
- Subset: `mmio_accesses`.
- Cache: `decompiled_cache` (function-level decompilation text).

#### 4.1.2 `src_context` / `dst_context`
These are context boundaries, not caller/callee:
- `src_context`: producer context (`ISR/TASK/MAIN/DMA/UNKNOWN`).
- `dst_context`: consumer context.

Examples:
- ISR writes `g_rx_buf`, MAIN reads `g_rx_buf` -> `ISR -> MAIN`.
- DMA writes `dma_rx_buf`, TASK reads it -> `DMA -> TASK`.

#### 4.1.3 Where constraints should live
Two kinds of constraints:
- Channel enable constraints: in `ChannelEdge.constraints` (for example `tail!=head`, `dma_done!=0`).
- Sink safety constraints: in chain `check_facts` (for example whether `len<=MAX` dominates the sink).

Both must be modeled, but at different layers.

#### 4.1.4 Producer / Consumer
- Producer: context that writes/assigns an object.
- Consumer: context that reads the object and uses it for data/control flow.

These define edges even without direct callgraph links.

#### 4.1.5 Sink root
A sink root is the risk-carrying value expression to track.
- COPY_SINK typical root: `len`.
- FUNC_PTR_SINK typical root: dispatch index.

Root is value-centric; object is memory-centric. They connect when root tracing maps to an object range.

#### 4.1.6 `derive_facts` / `check_facts`
- `derive_facts`: how dangerous arguments are derived from input/shared objects.
- `check_facts`: whether guards are `effective/weak/absent` before sink.

#### 4.1.7 Chain verdict
- `CONFIRMED`: source reached + controllable root + missing/weak key check.
- `SUSPICIOUS`: strong sink signal but chain is incomplete or uncertain.
- `SAFE_OR_LOW_RISK`: effective upper-bound check exists.
- `DROP`: contradictory or insufficient evidence.

### 4.2 Unified ChannelGraph Contract

#### 4.2.1 ObjectNode schema
Use one main schema for all object kinds, with optional `type_facts` per kind.

```json
{
  "object_id": "obj_rx_buf_20000000_2000007f",
  "region_kind": "SRAM_CLUSTER",
  "addr_range": ["0x20000000", "0x2000007f"],
  "writers": ["USART1_IRQHandler"],
  "readers": ["process_packet"],
  "producer_contexts": ["ISR"],
  "consumer_contexts": ["MAIN"],
  "evidence_refs": ["E_ISR_STORE_1", "E_MAIN_LOAD_3"],
  "confidence": 0.82,
  "type_facts": {
    "index_vars": ["g_rx_head", "g_rx_tail"],
    "is_ring_like": true
  },
  "notes": "ring payload"
}
```

#### 4.2.2 ChannelEdge schema
```json
{
  "src_context": "ISR",
  "object_id": "obj_rx_buf_20000000_2000007f",
  "dst_context": "MAIN",
  "edge_kind": "DATA",
  "constraints": [
    {"kind": "ring_guard", "expr": "g_rx_tail != g_rx_head", "site": "process_packet"}
  ],
  "evidence_refs": ["E_ISR_STORE_1", "E_LOOP_COND_2"],
  "score": 0.79
}
```

### 4.3 M8.5 ChannelGraph Builder (new)
- Target file: `sourceagent/pipeline/channel_graph.py`
- Input: `MAI + verified source labels + MemoryMap`
- Output: `channel_graph.json`

Interface:
```python
def build_channel_graph(mai, verified_labels, memory_map, *, top_k=3) -> dict:
    ...
```

Logic:
1. Extract SRAM/DMA/flag candidates from MAI.
2. Build writer/reader/context sets.
3. Keep only cross-context objects.
4. Collect edge constraints and evidence refs.
5. Keep top-K conflicting candidates instead of forcing one explanation.

Failure modes:
- No cross-context object -> emit empty graph (valid).
- Unknown context -> keep as `UNKNOWN` and downscore.

### 4.4 M8.6 Object Boundary Refiner (new)
- Target file: `sourceagent/pipeline/object_refine.py`
- Input: `raw_objects + access_traces`
- Output: `refined_objects.json`

Interface:
```python
def refine_object_boundaries(raw_objects, access_traces) -> list[dict]:
    ...
```

Split rules:
1. Dense indexed array accesses -> payload object.
2. Scalar values used in `if/while` conditions -> flag/control object.
3. `head/tail/index` update vars split from payload.

### 4.5 Why M8.6 is needed if objects already exist
- M8.5 emits coarse objects (recall-oriented).
- M8.6 refines/splits/merges them (precision and explainability).

Before (coarse):
```json
{
  "object_id": "obj_cluster_20000000_200000ff",
  "members": ["g_rx_buf", "g_rx_head", "g_rx_tail", "g_mode_flag"],
  "region_kind": "SRAM_CLUSTER"
}
```

After (refined):
```json
[
  {"object_id":"obj_rx_payload","members":["g_rx_buf"],"region_kind":"SRAM_CLUSTER"},
  {"object_id":"obj_rx_ctrl","members":["g_rx_head","g_rx_tail"],"region_kind":"FLAG"},
  {"object_id":"obj_mode_flag","members":["g_mode_flag"],"region_kind":"FLAG"}
]
```

Without M8.6, DATA and CONTROL edges are mixed, root-to-object mapping becomes noisy, and tunnel jumps become error-prone.

---

## 5. Sink Roots, Linker, and Chain Artifacts

### 5.0 Module DAG
```text
M8.5 ChannelGraph Builder
  -> M8.6 Object Boundary Refiner
  -> M9 Sink Root Extractor
  -> M9.1 Tunnel-Aware Backward Linker
  -> M9.2 Derive+Check Summarizer
  -> M9.3 Suspicious Queue + Chain Verdict Export
```

### 5.1 M9 Sink Root Extractor (new)
- Target file: `sourceagent/pipeline/linker/sink_roots.py`
- Input: `verified sinks + decompiled code + sink facts`
- Output: `sink_roots.json`

Interface:
```python
def extract_sink_roots(verified_sinks, decompiled_cache) -> list[dict]:
    ...
```

Root mapping:
- COPY_SINK: primary `len`, secondary `dst`.
- LOOP_WRITE_SINK: loop bound/index.
- MEMSET_SINK: length.
- FUNC_PTR_SINK: dispatch index/target pointer.
- FORMAT_STRING_SINK: format argument.

Example output:
```json
[
  {
    "sink_id": "SINK_t0_copy_1",
    "sink_label": "COPY_SINK",
    "sink_function": "process_packet",
    "sink_site": "0x08000120",
    "roots": [
      {"role": "primary", "expr": "count", "kind": "length"},
      {"role": "secondary", "expr": "out", "kind": "dst_ptr"}
    ],
    "evidence_refs": ["E_COPY_CALL", "E_ARG_PARSE"],
    "confidence": 0.78
  }
]
```

Relationship between roots and objects:
- Roots are value expressions.
- Objects are cross-context storage carriers.
- They connect when backward tracing maps root expressions to object ranges.

### 5.2 M9.1 Tunnel-Aware Backward Linker (new)
- Target file: `sourceagent/pipeline/linker/tunnel_linker.py`
- Input: `sink_roots.json + channel_graph.json + MAI/decompiled_cache + sources`
- Output: `chains.json`

Interface:
```python
def link_chains(sink_roots, channel_graph, mai, sources, *, budget=200) -> list[dict]:
    ...
```

Tunnel jump is not function-call jump. It is context switch along object edges after root tracing reaches an object node.

### 5.3 M9.2 Derive + Check Summarizer (new)
- Target file: `sourceagent/pipeline/linker/derive_check.py`
- Input: slice path (SSA nodes / expression edges)
- Output: `derive_facts` and `check_facts`

Purpose:
- Linker gives a path.
- This module turns path into security-meaningful explanation.

Input (example):
```json
{
  "slice_nodes": [
    "payload_len = (rxmsg[2] | rxmsg[3]<<8)",
    "if (payload_len > 0)",
    "net_buf_add_mem(buf, rxmsg+5, payload_len)"
  ]
}
```

Output (example):
```json
{
  "derive_facts": [
    {"expr":"payload_len = rxmsg[2] | (rxmsg[3] << 8)", "kind":"len_from_header", "site":"bt_spi_rx_thread"}
  ],
  "check_facts": [
    {"expr":"payload_len > 0", "strength":"weak", "reason":"non-upper-bound", "site":"bt_spi_rx_thread"},
    {"expr":"payload_len <= NET_BUF_DATA_SIZE", "strength":"absent", "site":"bt_spi_rx_thread"}
  ]
}
```

### 5.4 M9.3 Suspicious Triage Queue (new)
- Target file: `sourceagent/pipeline/triage_queue.py`
- Input: low-confidence sinks, unclosed chains, contradictory checks
- Output: `triage_queue.json` (top-K)

Low-confidence sources:
1. Miner confidence `< T_low`.
2. Verifier status is `PARTIAL/UNKNOWN`.
3. Root extraction fails or root-object mapping fails.
4. Sink reached but source not reached.

Persist both:
- `low_conf_sinks.json` (full snapshot)
- `triage_queue.json` (ranked top-K)

---

## 6. Sink-First Tunnel Detection (Algorithm, Complexity, Heuristics)

### 6.1 How Section 5 modules compose
- Section 5 artifacts are intermediate outputs.
- Section 6 algorithm consumes those artifacts to produce final chain verdicts.

Mapping:
- `sink_roots.json` -> root selection.
- `channel_graph.json` -> tunnel jump.
- `derive/check` -> semantic decision inputs.
- `chains.json` -> final linker output from M9.1.

### 6.2 Pseudocode
```python
for sink in sink_roots:
    for root in sink.roots:
        path = backward_slice(root, budget=B)
        while path.hit_object_node():
            producers = topk_producers(path.object_id, K)
            path = tunnel_jump_and_continue(path, producers, budget=B)
        derive = summarize_derive(path)
        checks = summarize_checks(path, sink.site)
        verdict = score_and_decide(path, derive, checks)
        emit_chain(sink, root, path, derive, checks, verdict)
```

### 6.3 Complexity and why heuristics are necessary
Without sink-first (`source x sink`):
- Approx complexity: `O(|Src| * |Sink| * C_slice)`.

With sink-first and bounded search:
- Approx complexity: `O(|Sink| * R * B * K^d)`.
  - `R`: roots per sink (typically 1-2)
  - `B`: backward slice budget
  - `K`: top-K producers on tunnel jump
  - `d`: tunnel depth (small)

Heuristics are needed because static recovery is incomplete in stripped/optimized binaries (aliasing, boundary precision, callsite recovery).

### 6.4 M9.1 `chains.json` example output
```json
{
  "chain_id": "chain_cve2020_10065_evt_1",
  "sink": {
    "sink_id": "SINK_evt_add_mem",
    "label": "COPY_SINK",
    "function": "bt_spi_rx_thread",
    "root_expr": "rxmsg[2] + 2"
  },
  "steps": [
    {"kind":"DERIVE", "expr":"payload_len = rxmsg[2] + 2", "site":"bt_spi_rx_thread"},
    {"kind":"CHANNEL", "object_id":"obj_rxmsg", "edge":"DMA->TASK", "evidence_refs":["E_CH_1"]},
    {"kind":"SOURCE", "label":"MMIO_READ", "site":"SPI1_DR", "evidence_refs":["E_SRC_2"]}
  ],
  "checks": [
    {"expr":"payload_len <= NET_BUF_DATA_SIZE", "strength":"absent", "site":"bt_spi_rx_thread"}
  ],
  "verdict": "CONFIRMED",
  "score": 0.93,
  "evidence_refs": ["E1","E2","E7"]
}
```

---

## 7. SourceAgent and BinAgent Split
- SourceAgent: deterministic rule implementation, structured facts, graph/chain preflight.
- BinAgent: runtime validation, deep checks, execution-side prioritization.

Plan:
1. Near-term: SourceAgent ships `channel_graph + chains` baseline.
2. Mid-term: migrate minimal stable linker back into SourceAgent for single-repo reproducibility.
3. Long-term: shared schema and evaluation scripts across both repos.

---

## 8. Roadmap and Evaluation (No LLM in this version)

### 8.1 Roadmap (P0-P3)
- P0: ContextIndex MVP + ChannelGraph(SRAM/DMA) + baseline linker.
- P1: object boundary refinement + DMA consumer binding + multi-callsite completeness.
- P2: stronger derive/check and chain-level evaluation.
- P3: RTOS queue strong-evidence recovery + schema convergence.

### 8.2 Evaluation metrics (label -> chain)
1. Label-level: TP/FP/FN.
2. Chain-level:
- Reachability (sink to source)
- Derive correctness
- Check consistency
- Verdict stability

### 8.3 Success criteria
1. At least one real CVE full chain + two microbench full chains.
2. No source x sink exhaustive pairing.
3. Every step traceable by evidence refs.
4. Outputs remain explainable and auditable.

---

## 9. Case Studies with Target Chains

### 9.1 Case A: `t0_isr_filled_buffer.c`
```c
void USART1_IRQHandler(void) {
    uint8_t b = (uint8_t)(USART1_DR & 0xFFu);
    g_rx_buf[g_rx_head] = b;
}

void process_packet(char *out, unsigned int max_len) {
    while (g_rx_tail != g_rx_head) {
        tmp[count++] = g_rx_buf[g_rx_tail];
    }
    memcpy(out, tmp, count);
}
```
Target chain:
`MMIO_READ(USART1_DR) -> obj(g_rx_buf) -> derive(count) -> check(count<max_len?) -> COPY_SINK(memcpy)`

### 9.2 Case B: `t0_dma_backed_buffer.c`
```c
DMA1_CH5_CPAR  = USART1_DR_ADDR;
DMA1_CH5_CMAR  = (uint32_t)g_dma_rx_buf;
DMA1_CH5_CNDTR = sizeof(g_dma_rx_buf);

if (g_dma_rx_buf[0] != 0) {
    parse_frame(g_dma_rx_buf, 256);
}
```
Requirements:
- Bind `CMAR` to `g_dma_rx_buf`.
- Consumer must read the same object/range.

Positive match: `parse_frame(g_dma_rx_buf, ...)`.
Negative match: reading `g_cfg_buf` should not count as this DMA consumer.

DMA-style target chain output:
```json
{
  "chain_id": "chain_dma_rxbuf_parse_1",
  "source": {"label":"DMA_BACKED_BUFFER", "site":"dma_uart_rx_init", "object_id":"obj_dma_rx_buf"},
  "steps": [
    {"kind":"CHANNEL", "edge":"DMA->MAIN", "object_id":"obj_dma_rx_buf"},
    {"kind":"DERIVE", "expr":"frame_tag = g_dma_rx_buf[0]", "site":"main"}
  ],
  "sink": {"label":"STORE_SINK", "function":"parse_frame", "root_expr":"buf[idx]"},
  "checks": [
    {"expr":"idx < len", "strength":"effective", "site":"parse_frame"}
  ],
  "verdict": "SAFE_OR_LOW_RISK"
}
```

### 9.3 Case C: `cve_2020_10065_hci_spi.c` (Full marking)

Source site:
```c
while (!(SPI1_SR & 0x01u)) {}
dst[i] = (uint8_t)(SPI1_DR & 0xFFu);   // MMIO_READ(SPI1_DR)
```

Sink trigger sites:
```c
net_buf_add_mem(buf, &rxmsg[1], rxmsg[EVT_HEADER_SIZE] + 2);  // EVT sink
net_buf_add_mem(buf, &rxmsg[5], sys_le16_to_cpu(acl_hdr.len)); // ACL sink
```

Semantic sink inside helper:
```c
memcpy(dst, mem, len); // inside net_buf_add_mem
```

Required chains:
- Chain-1 EVT root: `rxmsg[2]+2`, missing upper bound, up to ~257 into 76-byte buffer.
- Chain-2 ACL root: `acl_hdr.len`, missing tailroom bound, potentially huge overflow.

Why this is CVE-2020-10065:
1. Input-controlled length fields from MMIO stream.
2. Length flows directly into copy size.
3. No effective upper bound before copy.

Both chains should be `CONFIRMED` with sufficient static evidence.

---

## 10. Frozen Implementation Spec (Pre-coding)

This section is the coding baseline (`v1`).

### 10.1 Final field-level contracts for 6 JSON artifacts

#### 10.1.1 `channel_graph.json`
- Required top-level: `schema_version`, `binary`, `object_nodes`, `channel_edges`.
- Optional top-level: `build_meta`.

`object_nodes[]` required fields:
- `object_id`(string), `region_kind`(enum), `addr_range`([hex,hex]),
- `writers`(string[]), `readers`(string[]),
- `producer_contexts`(enum[]), `consumer_contexts`(enum[]),
- `evidence_refs`(string[]), `confidence`(float).

`channel_edges[]` required fields:
- `src_context`, `object_id`, `dst_context`, `edge_kind`,
- `constraints`(object[]), `evidence_refs`(string[]), `score`(float).

#### 10.1.2 `refined_objects.json`
- Required top-level: `schema_version`, `binary`, `objects`.
- Optional top-level: `refine_meta`.
- `objects[]` follows ObjectNode schema; optional `members` and `source_raw_object_ids`.

#### 10.1.3 `sink_roots.json`
- Required top-level: `schema_version`, `binary`, `sink_roots`.
- `sink_roots[]` required: `sink_id`, `sink_label`, `sink_function`, `sink_site`, `roots`, `evidence_refs`, `confidence`, `status`.
- Optional: `failure_code`, `failure_detail`.

#### 10.1.4 `chains.json`
- Required top-level: `schema_version`, `binary`, `chains`.
- `chains[]` required: `chain_id`, `sink`, `steps`, `checks`, `derive_facts`, `verdict`, `score`, `status`, `evidence_refs`.
- Optional: `source`, `failure_code`, `failure_detail`, `fallback_action`.

#### 10.1.5 `chain_eval.json`
- Required: `schema_version`, `binary`, `stats`, `by_verdict`.
- Optional: `timing_ms`.

#### 10.1.6 `low_conf_sinks.json`
- Required top-level: `schema_version`, `binary`, `items`.
- `items[]` required: `sink_id`, `sink_label`, `function`, `site`, `confidence`, `reason_codes`, `evidence_refs`.

### 10.2 Verdict decision table (looser suspicious, stricter confirmed)

Inputs:
- `source_reached` (bool)
- `root_controllable` (bool)
- `check_strength` (`effective/weak/absent/unknown`)
- `chain_complete` (bool)
- `has_contradiction` (bool)
- `endpoint_in_app` (bool)
- `chain_score` (0..1)

Rules:
- `CONFIRMED`:
  - `source_reached=true`
  - `root_controllable=true`
  - `check_strength in {weak, absent}`
  - `chain_complete=true`
  - `has_contradiction=false`
  - `endpoint_in_app=true`
  - `chain_score >= 0.80`
- `SUSPICIOUS`:
  - sink/root evidence exists, but confirmed conditions not fully met;
  - recommended `chain_score >= 0.35`.
- `SAFE_OR_LOW_RISK`:
  - `check_strength=effective` and chain is explainable.
- `DROP`:
  - contradiction, or very weak evidence (`chain_score < 0.35`), or both endpoints in library code without app anchor.

Policy:
- Be conservative for `CONFIRMED`.
- Keep `SUSPICIOUS` broad to avoid losing potentially valid cases.

### 10.3 Default global parameters (speed first)
- `T_low = 0.45`
- `top_k = 3`
- `B = 160` (slice budget)
- `K = 2` (tunnel producer top-K)
- `max_depth d = 2`
- `max_chains_per_sink = 4`
- `max_chains_per_binary = 200`

### 10.4 Context classification rules
Priority order:
1. `ISR`: `in_isr=true` from MAI.
2. `TASK`: symbol/name pattern (`*task*/*thread*`) or RTOS-create trace.
3. `MAIN`: `main` or reset-path non-ISR/non-task function.
4. `UNKNOWN`: if uncertain.

Never force hard classification when uncertain.

### 10.5 Multi-callsite strategy
Goal: collect more, not less.

Sink ID format:
```text
{label}@{function}@{callsite_hex}@{root_kind}:{hash8}
```

Dedup key:
```text
(label, function, callsite_hex, normalized_root_expr)
```

Policy:
- Keep different callsites in same function.
- Keep multiple roots on same callsite.
- Only cap by per-sink/per-binary limits.

### 10.6 Unified fallback format
Common fields in `sink_roots/chains`:
- `status` (`ok/partial/failed`)
- `failure_code`
- optional `failure_detail`, `fallback_action`

Recommended failure codes:
- `ROOT_UNRESOLVED`
- `OBJECT_MAP_MISS`
- `BUDGET_EXCEEDED`
- `NO_SOURCE_REACH`
- `CONTRADICTION`
- `LIB_BARRIER`

Fallback behavior:
1. Root extraction fails -> `partial`, `SUSPICIOUS`.
2. Object mapping fails -> `partial`, `SUSPICIOUS` with local path kept.
3. Budget exceeded -> `SUSPICIOUS` if sink/root evidence is strong; otherwise `DROP`.
4. Contradictory evidence -> `DROP`.

### 10.7 What to do when backward tracing enters library internals
This is not auto-canceled; explicit handling is required.

Policy:
1. `summary mode`: for known APIs (`memcpy/memset/strcpy/...`), use semantic summaries, no deep in-library tracing.
2. `barrier mode`: for unknown library internals, set strict step cap; if exceeded -> `LIB_BARRIER`.
3. `endpoint policy`: if both endpoints are in library code and no app object anchor exists -> `DROP`.
4. `app-anchor exception`: if sink is in library code but root is anchored to app object evidence -> keep as `SUSPICIOUS`.

Reason:
- Deep library tracing increases runtime and noise.
- App anchors keep chain relevance focused.

### 10.8 Minimal open items before coding
- Keep label name `SAFE_OR_LOW_RISK` as-is, or rename to `SAFE`.
- Finalize `chain_score` formula (start linear; calibrate later).

---

## References and Source Documents
- [I1] RQ1 Detailed Planning: Semantic Recovery v1.3 (internal)
- [I2] SourceAgent `update_0305.md` (internal)
- [I3] `eval_suite_unstripped_elf_report_en.md` (internal)
- [R1] Operation Mango, USENIX Security 2024
- [R2] KARONTE, IEEE S&P 2020
- [R3] Sharing More and Checking Less, USENIX Security 2021
- [R4] P2IM, USENIX Security 2020
- [R5] DICE, IEEE S&P 2021
- [R6] Fuzzware, USENIX Security 2022
- [R7] RTCON, NDSS 2026
- [R8] HEAPSTER, IEEE S&P 2022
- [R9] FirmXRay, CCS 2020
- [R10] LATTE, ACM TOSEM 2025
- [R11] IRIS, ICLR 2025
- [R12] AdaTaint, 2025 preprint
