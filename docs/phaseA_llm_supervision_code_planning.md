# Phase A LLM Supervision — Code-Level Planning (SourceAgent × BinAgent)

Date: 2026-03-10  
Owner: SourceAgent (Phase A), BinAgent/LLM (Phase B reviewer), plus new **Phase A.5 “Supervised Enrichment”**

## 0) Goal (what we are adding)

Phase A is already producing **deterministic chain candidates** (source → object/channel → derive/check → sink) with GT-backed structural success.

However, with:

- **semantic/hand-written parsing loops**,
- **wrappers/thunks**,
- **stripped ELF** (no symbol names) and **raw .bin** (missing section metadata/base address uncertainty),

pure hard-coded miners will increasingly miss **true sources/sinks/objects/channels**, or will output many “low-confidence” candidates.

### New capability: LLM-supervised enrichment for Phase A

Add an *optional* supervision layer that:

1. Takes **Phase A suspicious items** (ambiguous source/sink/object/channel candidates).
2. Asks an LLM to **classify / refine / explain** them *with evidence grounding requirements*.
3. Converts the LLM output into **structured suggestions**.
4. Re-runs deterministic verification gates; only evidence-supported suggestions can be promoted.

**Important:** The LLM does *not* become the source of truth. It becomes a **semantic assistant** that helps recover meaning where heuristics break, while Phase A remains **fail-closed** and evidence-grounded.

This is inspired by IRIS/LATTE-style “LLM assisted specification/triage”, but we keep a strict contract:

- *LLM may propose* → *deterministic verifier must accept* → otherwise **keep suggestion but mark as untrusted**.

## 1) Where this fits in the pipeline

### Current structure (already implemented)

- **Phase A: Deterministic Chain Assembly**
  - mine sources/sinks
  - recover objects + channels
  - link into chains (root-aware + channel enforced)
  - produce strict/soft deterministic calibration queue

- **Phase B: Semantic Review & Trigger Validation**
  - reviewer checks triggerability and explains preconditions per hop
  - outputs review transcript artifacts

### Proposed addition

Insert **Phase A.5: Supervised Enrichment** between deterministic mining and Phase B:

- **A.0** deterministic miners produce candidates + flags `needs_supervision`.
- **A.5** LLM “supervisor” reviews suspicious candidates, outputs structured decisions.
- **A.6** deterministic verifier merges only accepted items into Phase A artifacts.

This ensures Phase B receives **richer and cleaner** chain candidates.

## 2) What should be supervised

We need to be explicit and narrow; otherwise LLM costs/variance explode.

### 2.1 Supervise sinks (highest value)

**When:**

- sink is discovered via weak heuristics (e.g., loop-copy, wrapper call)
- missing symbol names (stripped)
- xref/callsite ambiguous (thunks, tailcalls)

**Typical questions to ask:**

- “Is this loop a buffer copy / store loop, or a benign loop?”
- “Is this call effectively memcpy/strcpy/sprintf-like, or something else?”
- “Which argument is the size/len/index? Is it attacker-influenced?”

**Output:** a proposed sink label + argument role binding.

### 2.2 Supervise sources (medium value)

**When:**

- MMIO reads go through wrappers or indirect loads
- DMA-backed buffers are inferred but the DMA engine setup is indirect
- raw .bin base/sections uncertain → entrypoints and MMIO ranges harder

**Questions:**

- “Is this load reading peripheral input (MMIO FIFO/DR) or reading normal RAM?”
- “Is this ISR function a producer? Does it fill a buffer or set a flag?”

**Output:** source label + evidence (e.g., address range, register name if known).

### 2.3 Supervise object & channel hypotheses (hard but critical for stripped/raw)

**When:**

- object boundaries are unclear (struct-like clusters, ring buffers)
- channels are weakly inferred (flags/head-tail/queue)

**Questions:**

- “Do these globals form a ring buffer (head/tail/mod N)?”
- “Is this pattern ISR producer → task consumer via shared object?”

**Output:** object boundary suggestion + channel edge suggestion.

### 2.4 Do NOT supervise everything

Avoid asking the LLM to:

- “find vulnerabilities from scratch”
- “rebuild CFG/callgraph”
- “guess missing code”

Supervision must be anchored to a **candidate produced by deterministic mining**.

### 2.5 Conservative rollout policy

Phase A.5 should not launch as a broad semantic layer over every artifact type at once.

Recommended rollout order:

1. **Sinks first**
   - loop-copy
   - wrapper/thunk copy sinks
   - format wrappers
   - indirect dispatch helpers
2. **Sources second**
   - wrapper MMIO
   - ISR producer helpers
   - DMA setup wrappers
3. **Objects/channels last**
   - ring-buffer boundary suggestions
   - ISR/task and DMA/task edges

Rationale:
- sink supervision gives the best immediate recall gain
- source supervision is useful but slightly noisier
- object/channel supervision has the highest variance and should be added only after sink supervision is stable

### 2.6 Stripped / raw-binary expansion boundary

Phase A.5 is most valuable when deterministic miners lose semantic structure:

- **unstripped ELF**
  - use as calibration baseline
  - expect minimal supervision effect
- **stripped ELF**
  - use supervision for missing symbols, wrapper recovery, thunk ambiguity, loop sinks
- **raw .bin**
  - supervision may assist after deterministic import/entry/base inference, but it must not replace:
    - base-address selection
    - vector-table parsing
    - code/data separation

For raw binaries, supervision must remain scoped to candidate interpretation, not binary lifting.

## 3) New artifacts & schemas

We will mirror the Stage-10 review transcript approach, but at “micro decision” granularity.

### 3.1 `supervision_queue.json`

One file per binary; contains a list of `SupervisionItem`.

**Schema (draft):**

```json
{
  "schema": "sourceagent.supervision_queue.v0",
  "binary": "...",
  "run_id": "...",
  "items": [
    {
      "item_id": "sink:0x08001234:loop_write",
      "item_kind": "sink" ,
      "proposed_label": "LOOP_WRITE_SINK",
      "confidence": 0.42,
      "why_suspicious": ["no_symbol", "loop_pattern_weak"],
      "context": {
        "function": "FUN_08001200",
        "callsite": null,
        "address": "0x08001234"
      },
      "evidence_pack": {
        "decompile_snippet": "...",
        "pcode_summaries": ["..."],
        "xref_summary": "...",
        "nearby_strings": ["..."],
        "mai_facts": {"stores": 12, "loads": 7}
      },
      "constraints": {
        "max_tokens": 1200,
        "allowed_outputs": ["accept", "reject", "uncertain"],
        "must_quote_evidence": true
      }
    }
  ]
}
```

### 3.2 Per-item prompt/response/session (raw views)

Store per item:

- `supervision_prompt.<item_id>.json`
- `supervision_raw_response.<item_id>.json`
- `supervision_session.<item_id>.json`

These must be written into `raw_views/` for auditability (same principle as Stage-10 transcripts).

### 3.3 `supervision_decisions.json`

Aggregated structured decisions:

```json
{
  "schema": "sourceagent.supervision_decisions.v0",
  "binary": "...",
  "items": [
    {
      "item_id": "...",
      "decision": "accept",
      "final_label": "COPY_SINK",
      "confidence": 0.71,
      "arg_roles": {"dst": "param_1", "src": "param_2", "len": "param_3"},
      "reason_codes": ["wrapper_like_memcpy", "loop_copy"],
      "evidence_quotes": [
        {"kind": "decompile", "span": "for(i=0; i<len; i++) dst[i]=src[i];"}
      ],
      "followup": {
        "ask_verifier_to_check": ["len_tainted", "guard_dominates"]
      }
    }
  ]
}
```

### 3.4 Merge policy

- `decision=accept` → candidate promoted to “verified candidate set” **only if** deterministic checks pass.
- `decision=uncertain` → keep candidate in triage (soft) but do not promote.
- `decision=reject` → keep candidate for audit (do not delete) but mark as rejected.

## 4) Deterministic acceptance gates (critical)

We need explicit “LLM suggestion acceptance” rules.

### 4.1 Sink acceptance gates

If LLM says `COPY_SINK`, accept only if we can deterministically show at least one:

- a callsite to a known copy primitive (including resolved wrapper entry) OR
- a loop-copy pattern with clear `dst[i]=src[i]` semantics and a loop bound variable.

Also record whether:

- bound var is **root-derived** (tainted length) vs constant
- any check dominates the sink

### 4.2 Source acceptance gates

Accept `MMIO_READ` only if address range is in peripheral space or matches known CMSIS region (where available), or is computed from a known peripheral base.

Accept `DMA_BACKED_BUFFER` only if:

- memory region is written by a DMA configuration routine, OR
- buffer is in a region marked as DMA target via deterministic pattern.

### 4.3 Channel acceptance gates

Accept `channel edge` only if we observe deterministic “producer writes object” and “consumer reads object” in different contexts (ISR/task/main), plus at least one of:

- head/tail monotonic update pattern
- flag set/clear handshake
- RTOS primitive calls (queue/semaphore) when symbols exist

If we cannot prove, keep as soft (triage) for Phase B.

## 5) Code integration plan (files & responsibilities)

### 5.1 New modules

1) `sourceagent/agents/supervision_prompt.py`

- Build prompt text + JSON schema spec per `item_kind`.
- Keep prompts short; enforce evidence quoting.

2) `sourceagent/agents/supervision_runner.py`

- Batch items by kind and budget.
- Call LLM (same infra as review_runner).
- Write raw transcript artifacts.
- Return `supervision_decisions.json` structure.

3) `sourceagent/pipeline/supervision_queue.py`

- Collect suspicious candidates from:
  - miners output (sources/sinks)
  - object_refine output (object boundaries)
  - channel_graph output (edges with low confidence)
  - linker output (chains with missing bindings)

4) `sourceagent/pipeline/supervision_reason_codes.py`

- Centralize typed reason codes for supervision decisions.
- Reuse the same high-level families as Stage-10 review where possible.

5) `sourceagent/pipeline/supervision_metrics.py`

- Summarize:
  - accepted / uncertain / rejected
  - strict merge success
  - soft-only suggestions
  - improvements in sink/source/channel recall on stripped/raw subsets

4) `sourceagent/pipeline/supervision_merge.py`

- Apply merge rules:
  - accept → run deterministic acceptance gates
  - uncertain/reject → keep audit trail
- Output “enriched” artifacts:
  - `verified_enriched.json`
  - `objects_enriched.json`
  - `channels_enriched.json`

### 5.2 Update existing modules

1) `sourceagent/pipeline/chain_artifacts.py`

- Add writers for supervision artifacts:
  - `write_supervision_queue()`
  - `write_supervision_prompt()`
  - `write_supervision_response()`
  - `write_supervision_session()`
  - `write_supervision_decisions()`

2) `sourceagent/interface/main.py`

Add CLI flags:

- `--enable-supervision` (bool)
- `--supervision-scope` = `{sinks,sources,channels,objects,all}`
- `--supervision-model` (default: same as `--review-model` fallback)
- `--max-supervision-items` (per binary)
- `--supervision-batch-size`
- `--supervision-timeout-sec`

3) Pipeline orchestrator

- After Stage 4/Stage 8 (depending on your stage numbering), if `--enable-supervision`:
  - build queue
  - run supervisor
  - merge suggestions
  - continue with chain linking + verdict calibration

### 5.3 Testing

Add tests similar to existing review integration tests:

- `tests/test_supervision_queue.py`
- `tests/test_supervision_merge.py`
- `tests/test_supervision_integration.py`

Key test invariants:

- With `--enable-supervision=false`, outputs are byte-for-byte identical to baseline.
- With supervision on + mocked LLM output, accepted suggestions must pass gates.
- Rejected/uncertain suggestions must be persisted (auditability).

Additional required tests:

- **no-supervision identity**
  - with `--enable-supervision=false`, outputs must remain byte-for-byte identical
- **stripped-elf supervision regression**
  - supervision improves or preserves sink/source recall on selected stripped ELF cases
- **raw-bin boundedness**
  - supervision may add suggestions, but must not invent entrypoints/base addresses or mutate deterministic import facts
- **oracle isolation**
  - SampleMeta/GT fields must not be read by supervision logic during detection

## 6) Interaction with BinAgent

BinAgent already does “evidence chain” reasoning sink→source; SourceAgent Phase A does structural assembly source→sink.

**Integration contract:**

- SourceAgent exports `chains.json + verdict_feature_pack.json + raw_views/*`.
- BinAgent / external LLM can:
  - provide **review decisions** (current Stage 10 input)
  - in the future, provide **supervision decisions** (new A.5 input)

We should define one common format for both external inputs:

- `external_semantic_decisions.json`
  - `kind = supervision | review`
  - each decision references an `item_id` or `chain_id`

This allows:

- running supervision in SourceAgent OR externally in BinAgent,
- then replaying/merging deterministically.

## 7) Minimal implementation order (PR-sized)

### PR-S0: Plumbing + queue (no LLM yet)

- Implement `supervision_queue.json` creation from low-confidence sink candidates.
- Write artifacts; no LLM calls.

### PR-S1: Internal supervisor runner + transcripts

- Add `supervision_runner.py` mirroring `review_runner.py`.
- Output per-item prompt/response/session files.

### PR-S2: Merge gates for sinks

- Implement acceptance gates for sink upgrades (loop-copy + wrapper).

### PR-S3: Sink supervision hardening

- Add typed reason codes.
- Add strict/soft merge states for accepted vs audit-only sink suggestions.
- Report sink-level supervision gains on stripped ELF.

### PR-S4: Extend supervision to sources (wrapper MMIO / DMA helpers)

- Add source supervision items.
- Add deterministic acceptance gates for wrapper MMIO and DMA wrappers.

### PR-S5: Extend supervision to channels/objects (optional, last)

- Add channel/object items.
- Implement acceptance gates for ring buffer / flag / queue edges.

### PR-S6: Evaluation + ablation hooks

- Add eval switches `--enable-supervision`.
- Measure recall/precision improvements vs baseline on:
  - stripped ELF
  - raw .bin (known base)

### Why this order

This order is intentionally conservative:
- it gets measurable value early from sinks
- it avoids exploding variance on channels/objects too early
- it keeps stripped/raw support grounded in deterministic import facts rather than LLM speculation

## 8) What success looks like

- On **unstripped**: minimal change (deterministic already good).
- On **stripped/raw**:
  - improved sink recall (esp. loop-copy, wrappers)
  - improved channel edge recall (ISR↔task via shared object)
  - reviewer receives more complete chains and can focus on triggerability.

## 9) Performance and budget boundaries

Because Phase A.5 will eventually be used on stripped and raw binaries, it needs explicit budget controls.

Recommended controls:

- `--max-supervision-items`
- `--supervision-batch-size`
- `--supervision-timeout-sec`
- per-kind quotas:
  - sinks > sources > channels > objects
- prompt-size budgeting similar to Stage-10 review

Recommended default policy:
- prefer supervising fewer high-value sink items over many weak object/channel items
- allow `uncertain` instead of forcing `accept/reject`
- preserve all rejected rationale for later audit

## 10) Evaluation expansion plan

We should explicitly separate three evaluation tracks:

### Track A0: unstripped baseline
- confirm supervision does not perturb current strong deterministic performance

### Track A1: stripped ELF
- first serious supervision benchmark
- measure gains for:
  - wrapper sinks
  - loop-copy sinks
  - wrapper MMIO sources

### Track A2: raw .bin
- only after stripped ELF is stable
- supervision may refine candidates, but deterministic import facts remain authoritative

Suggested success metrics:
- accepted supervision suggestions per kind
- strict merge rate
- soft-only suggestion rate
- recall gain on stripped/raw sink/source/channel recovery
- no increase in strict false positives on unstripped baseline

---

If you want, I can also produce:

- a compact “supervision prompt template v0.1” (JSON schema + examples),
- and a PR-by-PR checklist mapped to the actual repo paths.
