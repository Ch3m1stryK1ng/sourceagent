# Detailed Planning Memo (PATCH v1.1)
## Async Context Communication, ChannelGraph Recovery, and Sink-to-Source Tunnel Detection (Code-Level Implementation)

## Executive Summary
The current SourceAgent RQ1 layer is usable: source/sink labeling is largely in place. The next phase is not about adding more isolated labels; it is about **connecting labels into verifiable, explainable, reproducible source-to-sink chains**, including **cross-context propagation** (ISR/task/main/DMA).

This PATCH v1.1 version fixes spec inconsistencies that would otherwise cause implementation confusion (especially around DMA, object identity, and chain examples) and strengthens reproducibility for stripped binaries.

### Patch changelog (v1.1)
1. **DMA context made explicit and consistent:** DMA is treated as a *synthetic producer context* (not a CPU function context). Added rules and schema fields.
2. **Fixed inconsistent chain example:** removed the misleading `DMA->TASK + MMIO_READ` mixture. Added two examples: (a) single-context MMIO chain, (b) true cross-context ISR->MAIN tunnel chain.
3. **Object schema strengthened for stripped binaries:** added `writer_sites` / `reader_sites` (address-level evidence) and optional `binary_sha256`.
4. **Do not discard object nodes:** keep all object nodes (for app anchors and explainability); only filter **edges** to cross-context (plus DMA->CPU).
5. **Constraints schema tightened:** constraints include `vars` and `strength` to separate “channel enable” from “sink bounds check”.
6. **Sink root extraction priority clarified:** prefer miner facts / p-code call arguments; decompile-regex is fallback.
7. **Tunnel linker changed to best-first search + caching + state de-dup** to avoid exponential blowup.
8. **`endpoint_in_app` replaced with implementable `has_app_anchor`** (MMIO/DMA/object evidence).
9. Added **Goals / Non-goals / Assumptions** section and a **minimal chain-level GT format** for evaluation.
10. Related Work section cleaned up: concrete citations included; uncertain placeholders marked TODO.

---

## 1. Goals, Non-goals, Assumptions (NEW)

### 1.1 Goals (v1)
- **G1. Produce actionable, auditable source-to-sink chains** for Type II/III firmware:
  - Each chain is evidence-grounded (`evidence_refs`, addresses, sites).
  - Each chain explains: **source**, **carrier object**, **derive**, **check**, **sink**.
- **G2. Handle cross-context propagation** via async communication objects:
  - ISR <-> task/main
  - DMA -> CPU contexts
- **G3. Avoid source x sink exhaustive pairing.** Use sink-first bounded search + tunnel jumps.

### 1.2 Non-goals (v1)
- **NG1. No full interleaving/concurrency proof.** Approximate async behavior via producer-consumer edges.
- **NG2. No whole-program precise points-to.** Accept alias uncertainty and keep top-K candidates.
- **NG3. No requirement to recover RTOS queues in stripped binaries in v1.**
  - Start with shared-memory channels + DMA channels (highest yield / stability).
- **NG4. No deep tracing inside unknown library internals.**
  - Use summary/barrier modes.

### 1.3 Assumptions
- **A1. MAI (MemoryAccessIndex) quality is “good enough”**: loads/stores, target addresses, `in_isr` tagging.
- **A2. Memory map hypotheses exist** (ELF best; raw bin acceptable).
- **A3. Budgets are required** (slice budgets, K, d) because stripped/optimized binaries prevent full recovery.

---

## 2. Inputs, Threat Model, Outputs (NEW)

### 2.1 Inputs
- Firmware binary (ELF preferred; raw bin supported with memory map hypotheses)
- SourceAgent verified labels (RQ1 layer): sources + sinks
- MAI artifacts (access traces, decompiled cache)

### 2.2 Threat model (what “attacker control” means)
- Type II/III inputs are hardware-driven:
  - **MMIO reads** (UART/SPI/I2C/USB FIFO registers)
  - **DMA transfers** into RAM
  - ISR/task/main communication via shared objects
- “Control” is established by reaching those sources (MMIO/DMA) and showing a derived value feeds a sink argument without effective bounds checks.

### 2.3 Outputs
- `channel_graph.json`: async producer-consumer object graph
- `refined_objects.json`: refined object boundaries (payload vs flags vs indices)
- `sink_roots.json`: sink argument roots to trace
- `chains.json`: evidence-grounded chains with verdicts
- `triage_queue.json`: top suspicious items for deeper analysis (BinAgent / human / optional LLM)

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

#### 4.1.2 `src_context` / `dst_context` (PATCHED)
These are **execution context boundaries**, not caller/callee.

We distinguish:
- **CPU contexts** (functions run by CPU):
  - `ISR`: interrupt handler context
  - `TASK`: RTOS task/thread entry context
  - `MAIN`: reset/main/super-loop context
  - `UNKNOWN`: uncertain CPU context
- **Synthetic producer context** (not a CPU function):
  - `DMA`: indicates the object is written by the DMA engine, identified via DMA controller configuration + buffer binding.

Examples:
- ISR writes `g_rx_buf`, MAIN reads `g_rx_buf` -> `ISR -> MAIN`.
- DMA writes `dma_rx_buf`, TASK reads it -> `DMA -> TASK`.

Important: `DMA` should not be assigned by function-name heuristics. It is derived from **DMA configuration evidence** and buffer binding.

#### 4.1.3 Where constraints should live (PATCHED)
Two kinds of constraints:
- **Channel enable constraints**: belong to `ChannelEdge.constraints`.
  - Example: ring non-empty (`tail!=head`), ready flag (`rx_ready==1`), DMA done flag.
- **Sink safety constraints**: belong to chain `check_facts`.
  - Example: whether `len<=MAX` dominates the sink; whether clamp exists.

Both must be modeled, but at different layers.

#### 4.1.4 Producer / Consumer
- Producer: context that writes/assigns an object.
- Consumer: context that reads the object and uses it for data/control flow.

These define edges even without direct callgraph links.

#### 4.1.5 Sink root
A sink root is the risk-carrying value expression to track.
- COPY_SINK typical root: `len` (plus `dst` / index).
- FUNC_PTR_SINK typical root: dispatch index or computed function pointer.

Root is value-centric; object is memory-centric. They connect when root tracing maps to an object range.

#### 4.1.6 `derive_facts` / `check_facts`
- `derive_facts`: how dangerous args are derived from input/shared objects.
- `check_facts`: whether guards are `effective/weak/absent/unknown` before sink.

#### 4.1.7 Chain verdict
- `CONFIRMED`: source reached + controllable root + missing/weak key check.
- `SUSPICIOUS`: strong sink signal but chain is incomplete or uncertain.
- `SAFE_OR_LOW_RISK`: effective upper-bound check exists.
- `DROP`: contradictory or insufficient evidence.

---

### 4.2 Unified ChannelGraph Contract

#### 4.2.1 ObjectNode schema (PATCHED: address-level evidence)
Use one main schema for all object kinds, with optional `type_facts` per kind.

```json
{
  "object_id": "obj_rx_buf_20000000_2000007f",
  "region_kind": "SRAM_CLUSTER",
  "addr_range": ["0x20000000", "0x2000007f"],

  "producer_contexts": ["ISR"],
  "consumer_contexts": ["MAIN"],

  "writer_sites": [
    {
      "context": "ISR",
      "fn": "USART1_IRQHandler",
      "fn_addr": "0x08001234",
      "site_addr": "0x08001288",
      "access_kind": "store",
      "target_addr": "0x20000010"
    }
  ],
  "reader_sites": [
    {
      "context": "MAIN",
      "fn": "process_packet",
      "fn_addr": "0x08002000",
      "site_addr": "0x08002044",
      "access_kind": "load",
      "target_addr": "0x20000010"
    },
    {
      "context": "MAIN",
      "fn": "process_packet",
      "fn_addr": "0x08002000",
      "site_addr": "0x08002010",
      "access_kind": "guard",
      "expr": "g_rx_tail != g_rx_head"
    }
  ],

  "writers": ["USART1_IRQHandler"],
  "readers": ["process_packet"],

  "evidence_refs": ["E_ISR_STORE_1", "E_MAIN_LOAD_3"],
  "confidence": 0.82,

  "type_facts": {
    "kind_hint": "payload",
    "index_vars": ["g_rx_head", "g_rx_tail"],
    "is_ring_like": true
  },

  "notes": "ring payload"
}
```

Notes:
- `writer_sites/reader_sites` make the artifact stable under stripping and symbol loss.
- `writers/readers` are optional convenience fields.

#### 4.2.2 ChannelEdge schema (PATCHED constraints)
```json
{
  "src_context": "ISR",
  "object_id": "obj_rx_buf_20000000_2000007f",
  "dst_context": "MAIN",

  "edge_kind": "DATA",

  "constraints": [
    {
      "kind": "ring_guard",
      "vars": ["g_rx_tail", "g_rx_head"],
      "expr": "g_rx_tail != g_rx_head",
      "site": {"fn": "process_packet", "site_addr": "0x08002010"},
      "strength": "likely"
    }
  ],

  "evidence_refs": ["E_ISR_STORE_1", "E_LOOP_COND_2"],
  "score": 0.79
}
```

---

### 4.3 M8.5 ChannelGraph Builder (PATCHED)
- Target file: `sourceagent/pipeline/channel_graph.py`
- Input: `MAI + verified labels + MemoryMap`
- Output: `channel_graph.json`

Interface:
```python
def build_channel_graph(mai, verified_labels, memory_map, *, top_k=3) -> dict:
    ...
```

Logic (PATCHED):
1. Extract candidate objects from MAI:
   - SRAM clusters (payload/flags/indices candidates)
   - DMA-backed objects (from verified `DMA_BACKED_BUFFER` bindings)
2. Build writer/reader/context sets and `writer_sites/reader_sites`.
3. **Keep all object nodes** (recall + app anchors), but:
   - only emit **cross-context edges** (ISR<->MAIN/TASK) and **DMA->CPU edges**.
4. Collect edge constraints and evidence refs.
5. Keep top-K conflicting producer candidates instead of forcing one explanation.

Failure modes:
- No cross-context edges -> emit graph with only `object_nodes` (valid).
- Unknown context -> keep as `UNKNOWN` and downscore.

---

### 4.4 M8.6 Object Boundary Refiner (clarified feature-based MVP)
- Target file: `sourceagent/pipeline/object_refine.py`
- Input: `raw_objects + access_traces`
- Output: `refined_objects.json`

Interface:
```python
def refine_object_boundaries(raw_objects, access_traces) -> list[dict]:
    ...
```

Split rules (feature-based MVP):
1. **Payload-like**:
   - many distinct offsets accessed (>= 16), or indexed stores/loads in loops
2. **Flag-like**:
   - scalar (1/2/4 bytes), read in `if/while` guard patterns
3. **Index-like**:
   - monotonic updates (`++/--/+=`), modulo, compared against another index (`head!=tail`)

---

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

### 5.1 M9 Sink Root Extractor (PATCHED priority)
- Target file: `sourceagent/pipeline/linker/sink_roots.py`
- Input: `verified sinks + sink miner facts + MAI (p-code call arguments) + decompiled cache (fallback)`
- Output: `sink_roots.json`

Interface:
```python
def extract_sink_roots(verified_sinks, *, sink_facts, mai, decompiled_cache) -> list[dict]:
    ...
```

Priority order (PATCHED):
1. **Use sink miner facts** if available (already extracted args, callsite, roles).
2. **Use p-code call argument recovery** for wrappers/thunks.
3. **Use decompiled-cache regex only as fallback**, and emit `status=partial` if ambiguous.

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
    "confidence": 0.78,
    "status": "ok"
  }
]
```

---

### 5.2 M9.1 Tunnel-Aware Backward Linker (PATCHED best-first + caching)
- Target file: `sourceagent/pipeline/linker/tunnel_linker.py`
- Input: `sink_roots.json + channel_graph.json + MAI + sources`
- Output: `chains.json`

Interface:
```python
def link_chains(
    sink_roots, channel_graph, mai, sources,
    *, budget=200, K=2, max_depth=2, max_chains_per_sink=4
) -> list[dict]:
    ...
```

Definition: a tunnel jump is not a function-call jump. It is a context switch along object edges after root tracing reaches an object node.

Implementation strategy (PATCHED):
- **Best-first search** prioritized by partial score.
- **State de-dup** by `(ctx, normalized_expr, object_id, depth)`.
- **Slice caching** by `(fn_addr, normalized_expr)`.

Pseudo:
```python
pq = PriorityQueue()
pq.push(initial_state_from(sink_root))
seen = set()

while pq and emitted < max_chains_per_sink:
    st = pq.pop_best()
    if st.key in seen:
        continue
    seen.add(st.key)

    slice_res = cached_backward_slice(st.ctx, st.expr, budget=budget)

    if slice_res.hit_source():
        emit_chain(st, slice_res, status="ok")
        continue

    obj_hits = slice_res.hit_objects()
    if not obj_hits:
        emit_partial_chain(st, slice_res, failure_code="NO_SOURCE_REACH")
        continue

    for obj in obj_hits:
        producers = topK_producers(channel_graph, obj.object_id, K=K)
        for prod in producers:
            st2 = tunnel_jump(st, obj, prod)
            if st2.depth <= max_depth:
                pq.push(st2)
```

---

### 5.3 M9.2 Derive + Check Summarizer (PATCHED check taxonomy)
- Target file: `sourceagent/pipeline/linker/derive_check.py`
- Input: slice path (SSA nodes / p-code / decompile lines)
- Output: `derive_facts` and `check_facts`

Derive facts (examples):
- `len = buf[k]`
- `len = (buf[k]<<8)|buf[k+1]`
- `len = *(uint16_t*)(buf+off)`
- `idx = cmd_byte` (dispatch index)

Check strength taxonomy (PATCHED):
- `effective`:
  - clear upper bound that dominates sink, e.g. `if (len > C) return;`
  - clamp: `len = MIN(len, C)`
- `weak`:
  - not an upper bound (`len > 0`)
  - checks unrelated field (header only) but sink uses payload len
  - check does not dominate sink
- `absent`:
  - no upper bound / clamp discovered
- `unknown`:
  - dominance unclear; decompile missing

---

### 5.4 M9.3 Suspicious Triage Queue
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

### 6.1 Composition
- `sink_roots.json` -> root selection
- `channel_graph.json` -> tunnel jump
- `derive/check` -> semantic decision inputs
- `chains.json` -> final linker output

### 6.2 Why sink-first and why heuristics
- Exhaustive `source x sink` is infeasible at scale.
- Stripping/optimization make precise static recovery incomplete.
- Sink-first bounded search preserves runtime while maximizing vulnerability-yield.

### 6.3 Complexity recap
- Without sink-first (`source x sink`): `O(|Src| * |Sink| * C_slice)`
- With sink-first and bounded search: `O(|Sink| * R * B * K^d)`
  - `R`: roots per sink (typically 1-2)
  - `B`: slice budget
  - `K`: top-K producers
  - `d`: tunnel depth

### 6.4 `chains.json` example outputs (PATCHED)

#### Example 1: Single-context MMIO chain (CVE-like; no tunnel needed)
```json
{
  "chain_id": "chain_cve2020_10065_evt_like_1",
  "sink": {
    "sink_id": "SINK_evt_add_mem",
    "label": "COPY_SINK",
    "function": "bt_spi_rx_thread",
    "root_expr": "payload_len"
  },
  "steps": [
    {"kind":"SOURCE", "label":"MMIO_READ", "site":"SPI1_DR", "evidence_refs":["E_SRC_SPI_DR"]},
    {"kind":"DERIVE", "expr":"payload_len = rxmsg[2] + 2", "site":"bt_spi_rx_thread", "evidence_refs":["E_DERIVE_LEN"]},
    {"kind":"SINK", "label":"COPY_SINK", "callee":"net_buf_add_mem", "arg_role":"len", "site":"0x0800abcd", "evidence_refs":["E_SINK_CALL"]}
  ],
  "derive_facts": [
    {"expr":"payload_len = rxmsg[2] + 2", "kind":"len_from_header", "site":"bt_spi_rx_thread"}
  ],
  "checks": [
    {"expr":"payload_len <= NET_BUF_DATA_SIZE", "strength":"absent", "site":"bt_spi_rx_thread"}
  ],
  "has_app_anchor": true,
  "verdict": "CONFIRMED",
  "score": 0.91,
  "status": "ok",
  "evidence_refs": ["E_SRC_SPI_DR","E_DERIVE_LEN","E_SINK_CALL"]
}
```

#### Example 2: True cross-context tunnel chain (ISR -> MAIN)
```json
{
  "chain_id": "chain_t0_isr_buf_copy_1",
  "sink": {
    "sink_id": "SINK_memcpy_1",
    "label": "COPY_SINK",
    "function": "process_packet",
    "root_expr": "count"
  },
  "steps": [
    {"kind":"SOURCE", "label":"MMIO_READ", "site":"USART1_DR", "evidence_refs":["E_SRC_UART_DR"]},
    {"kind":"CHANNEL", "edge":"ISR->MAIN", "object_id":"obj_rx_buf_20000000_2000007f", "evidence_refs":["E_ISR_STORE_1","E_MAIN_LOAD_3"]},
    {"kind":"DERIVE", "expr":"count++ while (tail!=head)", "site":"process_packet", "evidence_refs":["E_DERIVE_COUNT"]},
    {"kind":"SINK", "label":"COPY_SINK", "callee":"memcpy", "arg_role":"len", "site":"0x08001200", "evidence_refs":["E_SINK_MEMCPY"]}
  ],
  "checks": [
    {"expr":"count < max_len", "strength":"unknown", "site":"process_packet"}
  ],
  "has_app_anchor": true,
  "verdict": "SUSPICIOUS",
  "score": 0.63,
  "status": "partial",
  "failure_code": "CHECK_UNCERTAIN",
  "evidence_refs": ["E_SRC_UART_DR","E_ISR_STORE_1","E_MAIN_LOAD_3","E_SINK_MEMCPY"]
}
```

---

## 7. SourceAgent and BinAgent Split
- SourceAgent: deterministic rule implementation, structured facts, graph/chain preflight.
- BinAgent: deeper validation (dynamic/hybrid), execution-side prioritization.

Plan:
1. Near-term: SourceAgent ships `channel_graph + chains` baseline.
2. Mid-term: share schema and evaluation scripts across both repos.
3. Long-term: BinAgent consumes SourceAgent chain artifacts for deep confirmation.

---

## 8. Roadmap and Evaluation

### 8.1 Roadmap (P0-P3)
- P0: ChannelGraph(SRAM + DMA) + best-first linker baseline + two example chains.
- P1: object boundary refinement + producer ranking + stable evidence fields.
- P2: stronger derive/check + chain-level evaluation GT + verdict calibration.
- P3: RTOS queue recovery (symbolic first) + schema convergence with BinAgent.

### 8.2 Evaluation metrics (label -> chain)
1. Label-level: TP/FP/FN.
2. Chain-level:
   - Source reached?
   - Tunnel correctness (object + producer site match)
   - Derive correctness (len/index extracted correctly)
   - Check strength consistency
   - Verdict stability (same firmware build)

### 8.3 Minimal chain-level GT format (NEW)
```json
{
  "binary": "cve_2020_10065_hci_spi.elf",
  "gt_chains": [
    {
      "sink_site": "0x0800abcd",
      "sink_label": "COPY_SINK",
      "root_role": "len",
      "expected_source": {"label":"MMIO_READ", "site":"SPI1_DR"},
      "expected_object_hint": {"addr_range":["0x20001f00","0x20001fff"]},
      "expected_check_strength": "absent"
    }
  ]
}
```

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
`MMIO_READ(USART1_DR) -> object(g_rx_buf) -> derive(count) -> check(count<max_len?) -> COPY_SINK(memcpy)`

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

### 9.3 Case C: `cve_2020_10065_hci_spi.c` (full marking)
Source site:
```c
while (!(SPI1_SR & 0x01u)) {}
dst[i] = (uint8_t)(SPI1_DR & 0xFFu);   // MMIO_READ(SPI1_DR)
```

Sink trigger sites:
```c
net_buf_add_mem(buf, &rxmsg[1], rxmsg[EVT_HEADER_SIZE] + 2);   // EVT
net_buf_add_mem(buf, &rxmsg[5], sys_le16_to_cpu(acl_hdr.len)); // ACL
```

Semantic sink inside helper:
```c
memcpy(dst, mem, len); // inside net_buf_add_mem
```

Required chains:
- Chain-1 EVT root: `rxmsg[2]+2`, missing upper bound.
- Chain-2 ACL root: `acl_hdr.len`, missing tailroom bound.

Why this is CVE-2020-10065:
1. Input-controlled length fields from MMIO stream.
2. Length flows into copy size.
3. No effective upper bound before copy.

---

## 10. Frozen Implementation Spec (Pre-coding) (PATCHED)

### 10.1 Final field-level contracts for JSON artifacts

#### 10.1.1 `channel_graph.json` (PATCHED)
Required top-level: `schema_version`, `binary`, `object_nodes`, `channel_edges`.
Recommended top-level: `binary_sha256`, `build_meta`.

`object_nodes[]` required fields:
- `object_id` (string), `region_kind` (enum), `addr_range` ([hex,hex])
- `producer_contexts` (enum[]), `consumer_contexts` (enum[])
- `writer_sites` (object[]), `reader_sites` (object[])
- `evidence_refs` (string[]), `confidence` (float)
Optional: `writers/readers` (names), `type_facts`, `notes`

`channel_edges[]` required fields:
- `src_context`, `object_id`, `dst_context`, `edge_kind`
- `constraints` (object[]), `evidence_refs` (string[]), `score` (float)

#### 10.1.2 `refined_objects.json`
Same as ObjectNode schema, preserving `writer_sites/reader_sites`.

#### 10.1.3 `sink_roots.json`
Required: `schema_version`, `binary`, `sink_roots`.
Each root entry requires: `sink_id`, `sink_label`, `sink_function`, `sink_site`, `roots`, `evidence_refs`, `confidence`, `status`.

#### 10.1.4 `chains.json` (PATCHED)
Each chain requires:
- `chain_id`, `sink`, `steps`, `checks`, `derive_facts`
- `verdict`, `score`, `status`, `evidence_refs`
- `has_app_anchor` (bool)
Optional: `failure_code`, `failure_detail`, `fallback_action`

#### 10.1.5 `chain_eval.json`
Required: `schema_version`, `binary`, `stats`, `by_verdict`.

#### 10.1.6 `low_conf_sinks.json`
Required: `schema_version`, `binary`, `items`.

---

### 10.2 Verdict decision table (PATCHED: `has_app_anchor`)
Inputs:
- `source_reached` (bool)
- `root_controllable` (bool)
- `check_strength` (`effective/weak/absent/unknown`)
- `chain_complete` (bool)
- `has_contradiction` (bool)
- `has_app_anchor` (bool)
- `chain_score` (0..1)

Definition: `has_app_anchor=true` if chain contains any of:
- MMIO register evidence (address in peripheral range)
- DMA config evidence + bound dst object
- SRAM object evidence (object_id with writer/reader sites)
- verified source label tied to the chain

Rules:
- `CONFIRMED`:
  - `source_reached=true`
  - `root_controllable=true`
  - `check_strength in {weak, absent}`
  - `chain_complete=true`
  - `has_contradiction=false`
  - `has_app_anchor=true`
  - `chain_score >= 0.80`
- `SUSPICIOUS`:
  - sink/root evidence exists, but confirmed conditions not fully met
  - recommended `chain_score >= 0.35`
- `SAFE_OR_LOW_RISK`:
  - `check_strength=effective` and chain is explainable
- `DROP`:
  - contradiction, or very weak evidence (`chain_score < 0.35`), or
  - both endpoints in library internals and `has_app_anchor=false`

Policy:
- Be conservative for `CONFIRMED`.
- Keep `SUSPICIOUS` broad.

---

### 10.3 Default global parameters (speed first)
- `T_low = 0.45`
- `top_k = 3`
- `B = 160` (slice budget)
- `K = 2` (tunnel producer top-K)
- `max_depth d = 2`
- `max_chains_per_sink = 4`
- `max_chains_per_binary = 200`

### 10.4 Context classification rules (PATCHED)
CPU-function context (for functions):
1. `ISR`: `in_isr=true` from MAI.
2. `TASK`: RTOS task-entry evidence (create callsites) OR name heuristic (best-effort).
3. `MAIN`: reset/main/super-loop.
4. `UNKNOWN`: uncertain.

DMA context (synthetic producer, not a function):
- Set `src_context="DMA"` only when:
  - verified `DMA_BACKED_BUFFER` exists AND
  - DMA config site binds `dst_object` AND
  - consumer sites read from that object range.

Never force classification when uncertain.

### 10.5 Unified fallback format (PATCHED)
Common fields in `sink_roots/chains`:
- `status` (`ok/partial/failed`)
- `failure_code`

Recommended failure codes:
- `ROOT_UNRESOLVED`
- `OBJECT_MAP_MISS`
- `BUDGET_EXCEEDED`
- `NO_SOURCE_REACH`
- `CONTRADICTION`
- `LIB_BARRIER`
- `CHECK_UNCERTAIN`

### 10.6 What to do when backward tracing enters library internals (PATCHED)
Policy:
1. `summary mode`: known APIs (`memcpy/memset/strcpy/...`) use semantic summaries.
2. `barrier mode`: unknown library internals impose strict step cap; if exceeded -> `LIB_BARRIER`.
3. `anchor policy`:
   - If sink is inside library but `has_app_anchor=true`, keep as `SUSPICIOUS`.
   - If both endpoints are in library and no anchor, `DROP`.

Reason:
- Deep library tracing increases runtime and noise.
- Anchors preserve relevance.

---

## References and Source Documents
Internal:
- [I1] RQ1 Detailed Planning: Semantic Recovery v1.3
- [I2] SourceAgent `update_0305.md`
- [I3] `eval_suite_unstripped_elf_report_en.md`

External (non-exhaustive):
- [R1] Operation Mango, USENIX Security 2024
- [R2] KARONTE, IEEE S&P 2020
- [R3] Sharing More and Checking Less (SaTC), USENIX Security 2021
- [R4] P2IM, USENIX Security 2020
- [R5] Fuzzware, USENIX Security 2022
- [R6] HALucinator, USENIX Security 2020
- [R7] FirmXRay, CCS 2020
- [R8] Heapster, IEEE S&P 2022

Placeholders / TODO (verify before final paper):
- LATTE (TODO)
- IRIS (TODO)
- AdaTaint (TODO)
