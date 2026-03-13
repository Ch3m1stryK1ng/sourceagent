# SourceAgent Progress Report

Date: March 12, 2026


It is written for a progress-update audience and focuses on:

- what SourceAgent is trying to recover
- how Phase A, Phase A.5, and Phase B fit together
- how chain assembly works
- how the benchmark assets and GT were built
- what we can already claim with confidence
- what is still incomplete

## 1. One-Slide Summary

The current system is becoming a 2-phase analysis pipeline for Type-II/III
monolithic firmware:

- **Phase A** performs deterministic, fail-closed structure recovery
- **Phase A.5** applies bounded LLM supervision to low-confidence artifacts
- **Phase B** performs semantic review and risk calibration without rewriting
  Phase A facts

The strongest current result is that **structural chain recovery already looks
very strong on the 44-sample GT-backed baseline**.

The biggest remaining gap is not chain assembly anymore. It is:

- verdict calibration
- stripped/raw robustness
- and benchmark-grade proof on broader real-firmware binaries

## 2. Why This Problem Needs Structure

The target is **monolithic firmware**, not Linux-style multi-process software.

In this setting:

- input often enters through **MMIO**
- data may be written by an **ISR** or **DMA**
- the dangerous sink may run later in a different context
- the key exploit-driving value is often not the whole object, but a specific
  **root** such as a length, index, format string, or dispatch selector

So a sink hit alone is not enough.

To explain a real chain, we need to recover at least:

- `source`
- `sink`
- `object`
- `channel`
- `sink_root`
- `derive/check`

Those are the core structural primitives that the current system models.

In the GT documents, these primitives expand into a slightly larger benchmark
schema with sections such as:

- `sources`
- `objects`
- `channels`
- `sinks`
- `sink_roots`
- `derive_checks`
- `chains`
- `negative_expectations`

## 3. End-to-End Architecture

### 3.1 Phase A

Phase A is the deterministic core.

It runs in the following broad order:

1. `MemoryMap` recovery
2. `MemoryAccessIndex` construction
3. source mining
4. sink mining
5. evidence packing
6. proposal
7. verifier
8. ChannelGraph and object refinement
9. sink-root extraction, derive/check summarization, and chain linking
10. triage and verdict-calibration artifacts

### 3.2 Phase A.5

Phase A.5 is an **optional bounded supervision loop**.

Its job is **not** to find vulnerabilities from scratch.

Its job is to improve ambiguous low-confidence Phase A artifacts such as:

- weak sink candidates in stripped binaries
- weak source candidates hidden behind wrappers
- weak object hypotheses
- weak channel hypotheses

The key rule is:

> the LLM may suggest, but deterministic merge gates must still accept

So supervision can enrich Phase A outputs, but it cannot replace the
deterministic authority of Phase A.

### 3.3 Phase B

Phase B is the semantic review layer.

It consumes the chain artifacts produced by Phase A and answers bounded
questions such as:

- does the visible check actually bind the active root?
- does the attacker still control the root at the sink?
- is this chain better interpreted as `SAFE_OR_LOW_RISK`, `SUSPICIOUS`, or
  `CONFIRMED`?
- what should the final risk band and review priority be?

Phase B does **not** get to re-decide:

- source reachability
- object binding
- channel traversal
- root extraction

## 4. What Some Core Terms Mean

### 4.1 Deterministic

“Deterministic” means the core structure-recovery path does not depend on
open-ended generation.

For the same binary and the same configuration, the primary structural outputs
should be reproducible.

### 4.2 Fail-closed

“Fail-closed” means missing evidence does not upgrade into stronger claims.

Examples:

- if a source proposal fails required obligations, it does not become a trusted
  source label
- if a sink root cannot be recovered, the chain remains partial or weak
- if a channel is required but not satisfied, the chain should be dropped

### 4.3 `MemoryMap`

`MemoryMap` is the Stage 1 address-space model for the binary.

It records:

- base address
- entry point
- flash / SRAM / MMIO regions
- vector table
- ISR handler hypotheses

It answers:

> what kind of address space does this firmware binary live in?

### 4.4 `MemoryAccessIndex`

`MemoryAccessIndex` is the Stage 2 memory-access inventory.

It records:

- loads and stores
- target addresses when recoverable
- provenance of the base expression
- function / ISR context
- global symbols
- cached decompiled code

It answers:

> who reads or writes which addresses, and from which context?

### 4.5 Proposal and verifier

Stage 6 proposal creates a candidate label for each evidence pack.

In the cheapest path, that proposal is just the miner hint.

Stage 7 verifier then checks **label-specific obligations**.

Examples:

- `MMIO_READ`: constant-base evidence and peripheral-range evidence
- `ISR_MMIO_READ`: MMIO evidence plus ISR-context evidence
- `COPY_SINK`: callsite match plus argument extraction
- `FORMAT_STRING_SINK`: printf-like sink plus non-literal format argument

The verifier is intentionally placed **before chain linking**, because the
system wants local source/sink facts to be cleaned before they are composed into
larger structures.

### 4.6 Chain verdict

There are two different “verdict” levels in the system:

1. **label verifier verdict**
   - `VERIFIED`
   - `PARTIAL`
   - `REJECTED`
   - `UNKNOWN`
2. **chain verdict**
   - `CONFIRMED`
   - `SUSPICIOUS`
   - `SAFE_OR_LOW_RISK`
   - `DROP`

Stage 10 then adds side-band risk output such as:

- `LOW / MEDIUM / HIGH`
- `P0 / P1 / P2`

### 4.7 Stage 10 artifacts

Stage 10 materializes the main reviewer-facing and risk-facing artifacts.

The most important ones are:

- `triage_queue.json`
  - the highest-priority suspicious chains that deserve operator attention
- `verdict_feature_pack.json`
  - the deterministic per-chain fact bundle used for semantic review
- `verdict_calibration_queue.json`
  - the bounded subset selected for semantic review or calibration
- `verdict_soft_triage.json`
  - the final merged output carrying strict verdict, soft review state, final
    risk band, and review priority

So if someone asks “where does the semantic/risk-facing output begin?”, the
short answer is:

> Stage 10 turns structurally assembled chains into reviewer-facing and
> calibration-facing JSON contracts

## 5. How a Chain Is Assembled

The important point is that SourceAgent does **not** ask an LLM to “guess the
whole chain”.

Instead, the chain linker composes local facts:

1. find a real `source`
2. bind the path to an `object`
3. require a `channel` if the path is cross-context
4. identify the active `sink_root`
5. summarize `derive/check` facts
6. emit a chain verdict

So the core question is not:

> is there some graph path?

It is:

> is there a source-reached, object-bound, root-matched, channel-satisfied,
> derive/check-explained chain?

That is why chain-level metrics are more meaningful than raw artifact precision.

## 6. What Phase A.5 Supervision Actually Does

Phase A.5 is the part that was easy to under-explain in a short verbal summary.

It should be described as:

> a bounded enrichment loop inside late Phase A

It takes low-confidence or ambiguous items and asks for a structured supervision
decision. Those decisions then go through deterministic merge gates.

The supervision queue can include:

- sinks
- sources
- objects
- channels

The current implementation writes and uses artifacts such as:

- `supervision_queue.json`
- `supervision_decisions.json`
- `supervision_prompt.json`
- `supervision_raw_response.json`
- `supervision_session.json`
- `supervision_trace.json`
- `supervision_merge.json`

### 6.1 Why Phase A.5 exists

It is most useful when deterministic miners lose semantic clarity, especially on:

- stripped ELF
- wrappers / thunks
- loop-based sinks
- weak object or channel boundaries

### 6.2 What it is not allowed to do

It is **not** allowed to:

- replace binary lifting
- invent entry points
- guess base addresses for raw binaries
- declare new whole chains from scratch

It must stay anchored to deterministic candidates produced by Phase A.

### 6.3 Current supervision evidence

From the current supervision summary:

- queue total: `148`
- reviewed total: `122`
- accepted total: `70`
- audit-only total: `30`
- rejected total: `22`

Accepted enrichments by kind:

- `source`: `43`
- `sink`: `13`
- `object`: `12`
- `channel`: `2`

Interpretation:

- source/sink supervision is already clearly useful
- object/channel supervision is wired and measurable
- but object/channel merge gates are still intentionally conservative

### 6.4 Where Phase A.5 sits in the current implementation

Conceptually, Phase A.5 sits **after deterministic artifact recovery and before
final semantic calibration**.

In the current implementation, it behaves like a **late Phase A enrichment
loop**:

1. build initial Phase A artifacts
2. produce `supervision_queue.json`
3. run the supervision model on bounded suspicious items
4. apply deterministic merge gates
5. rebuild the affected Phase A artifacts with accepted enrichments
6. continue to final Stage 10 calibration outputs

So it is best described as:

> a bounded feedback loop inside late Phase A, not a second reviewer

![Supervision summary](figures/progress_report_20260312/supervision_summary.png)

## 7. Benchmark Assets and GT Tiers

The current benchmark assets are already layered.

### 7.1 L1 sink-only GT

This is the scalable layer.

It records sink locations and sink labels.

Use case:

- strict TP/FP/FN sink metrics
- scalable runs over large binary counts

Here, “strict metrics” means exact-match scoring against the official answer.
At L1, a predicted sink is counted as correct only when the sink label and the
relevant location identity match the GT entry; “roughly similar” does not count
as a true positive.

Current combined L1 sink-only readiness:

- `150` binaries
- `484` sink rows

This comes from:

- `42` GT-backed sink-bearing binaries
- `108` auto-generated microbench variants

### 7.2 L2 artifact GT

This is the debugging and regression layer.

It records intermediate artifacts such as:

- sources
- objects
- channels
- sinks
- sink roots
- derive/check facts

Current scale:

- `14` curated microbench samples

### 7.3 L3 full chain GT

This is the full end-to-end benchmark layer.

It records:

- positive chains
- negative expectations
- channel-required flags
- expected chain verdicts

Current scale:

- `30` mesobench samples
- `44` GT-backed baseline samples in the combined benchmark view

![GT tiers and current asset inventory](figures/progress_report_20260312/gt_tiers_and_assets.png)

### 7.4 Two useful terms: canonical and autogen

- `canonical`
  - the frozen, official benchmark view that should be used for reruns and
    reported numbers
- `autogen`
  - the recently added automatically generated microbench extension used to
    scale L1 sink-only coverage; it is useful for strict sink evaluation, but
    it is not full-chain GT

## 8. How GT Is Built

There are three main GT construction modes in the current repo.

### 8.1 Microbench

Microbench samples are small and controlled.

They are good for:

- tight regression tests
- artifact-complete GT
- explicit source/object/root/check examples

Example:

- `firmware/ground_truth_bundle/microbench/samples/cve_2020_10065_hci_spi.json`

That sample explicitly carries:

- a real source
- explicit SRAM objects
- sink roots
- derive/check evidence
- two full confirmed chains
- curated chain-level risk GT

### 8.2 Mesobench / GT-backed: draft then freeze

For more realistic binaries, the workflow is often:

1. run the live pipeline on the sample
2. auto-promote structural artifacts into a draft GT document
3. manually curate the important chains, negatives, and risk anchors
4. freeze the GT file

That is what “draft-then-freeze” means.

It does **not** mean the current sample is vague forever.

It means the first version is produced with pipeline help, then curated into a
stable benchmark document.

### 8.3 Chain-level risk GT

The repo now also supports risk GT at the chain level.

For selected anchor chains, GT can record:

- `expected_final_verdict`
- `expected_final_risk_band`
- `expected_review_priority`

Example:

```json
{
  "chain_id": "C1_evt_overflow",
  "expected_verdict": "CONFIRMED",
  "expected_final_verdict": "CONFIRMED",
  "expected_final_risk_band": "HIGH",
  "expected_review_priority": "P0"
}
```

This means evaluation can now ask:

- was the chain found?
- was it classified with the right final risk?

Current checked-in real-CVE risk GT coverage:

- `16` CVE samples total inside `gt_backed_suite`
- `12` with at least one chain-level risk GT annotation
- `19` curated anchor-risk chains

## 9. What We Can Already Claim with Confidence

The strongest current claim is the **structural validity of Phase A** on the
GT-backed baseline.

Headline result from the 44-sample GT-backed suite:

- positive chains: `386 / 386`
- spurious non-drop chains: `0`
- channel-required chains satisfied: `253 / 253`
- negative expectations satisfied: `27 / 27`

That is the main reason the project can now honestly say:

> structure recovery is no longer the main bottleneck

![Structural results](figures/progress_report_20260312/structural_results.png)

Interpretation:

- root-aware linking is working
- channel enforcement is working
- spurious non-drop suppression is working
- the main open problem has shifted toward semantic calibration

## 10. Case Studies from the Latest Full Live Run

These examples come from:

- `/tmp/eval_gt_backed_full_live_20260312`

They are useful because they show four different states of the current system:

- a small curated case that already survives the full pipeline cleanly
- a case where structure is present but semantic calibration is still
  conservative
- a noisy real-style binary where one strong anchor chain already surfaces
- a larger firmware where scale and cross-context structure are already visible

### 10.1 `cve_2018_16525_freertos_dns`

- `3` chains total
- strict chain verdicts: `1 CONFIRMED`, `2 SUSPICIOUS`
- final calibrated output: `2 CONFIRMED`, `2 P0`

Why it matters:

> at least some curated CVE chains already survive the full pipeline and remain
> high-priority after review

### 10.2 `cve_2021_34259_usb_host`

- `3` chains total
- strict chain verdicts: `3 SUSPICIOUS`
- final calibrated output: all `SUSPICIOUS / MEDIUM / P1`

Why it matters:

> the structure is present, but parser/store semantics are still conservative
> when extent reasoning is weak

### 10.3 `usbs_tcp_echo_client_vuln_bof`

- `24` chains total
- strict chain verdicts: `1 CONFIRMED`, `17 SUSPICIOUS`, `6 DROP`
- final calibrated output includes `1 CONFIRMED / HIGH / P0`

Why it matters:

> in a much noisier real-style BOF sample, the system can already surface one
> strong high-risk anchor chain instead of only producing a flat suspicious set

### 10.4 `contiki_cve_2020_12140_hello_world`

- `65` chains total
- `21` channel-bearing chains
- strict chain verdicts: `6 CONFIRMED`, `57 SUSPICIOUS`, `2 DROP`
- final calibrated output: `64 SUSPICIOUS`, `24` LLM-reviewed

Why it matters:

> large firmware already shows structural richness and cross-context linking,
> but the semantic layer is still intentionally conservative

![Case studies from the latest full live run](figures/progress_report_20260312/case_studies.png)

## 11. What We Can and Cannot Yet Claim on Real Firmware

This is the gap that deserves explicit acknowledgment in the presentation.

### 11.1 What we can say now

The system already runs at Stage 10 on real firmware binaries and produces:

- many source and sink candidates
- non-trivial chain sets
- cross-context channel-bearing chains
- review queues and calibrated outputs

Representative no-GT real-firmware stage-10 runs:

- Contiki `hello-world`
  - detected labels: `173`
  - chains: `65`
  - channel-bearing chains: `21`
  - review queue: `64`
- Zephyr `CVE-2020-10065`
  - detected labels: `104`
  - chains: `50`
  - channel-bearing chains: `10`
  - review queue: `44`

![Representative real-firmware stage-10 runs](figures/progress_report_20260312/real_firmware_scan.png)

### 11.2 What we cannot yet claim

We cannot yet say that broad real-firmware effectiveness is benchmark-proven.

Why not:

- many real-firmware runs are still no-GT stress runs
- the canonical real-firmware benchmark track is not yet frozen
- correctness on broad real firmware still needs more benchmark-grade GT

So the honest statement is:

> real-firmware results are promising and operationally useful, but not yet
> benchmark-grade proof

## 12. Main Innovations

The project currently has four main innovations worth emphasizing.

### 12.1 Firmware target choice

The target is Type-II/III monolithic firmware rather than Linux-style systems.

### 12.2 Structure beyond labels

The core contribution is not only label recovery.

It is the combination of:

- ChannelGraph
- root-aware linking
- derive/check evidence
- chain-level reasoning

### 12.3 Bounded use of LLMs

LLMs are not allowed to replace deterministic fact extraction.

They are only used in bounded, auditable roles:

- Phase A.5 supervision
- Phase B semantic review

### 12.4 Benchmark direction

The repo is being turned into a benchmark-quality asset stack, not just a one-off detector.

That includes:

- canonical manifests
- GT tiers
- stripped peers
- no-GT workloads
- chain-level risk GT
- and sample catalog metadata

## 13. What Is Still Missing

The biggest remaining gaps are:

1. benchmark v1 still needs frozen dev/report splits
2. raw `.bin` tracks are not yet canonical benchmark tracks
3. risk calibration needs a dedicated frozen subset and more patched/negative GT
4. ablations need to be frozen as standard presets
5. suite summaries still need better stratification by format, size, execution model, and framework
6. most importantly, **real-firmware effectiveness still needs stronger benchmark-grade proof**

## 14. Recommended Verbal Closing

If a short verbal summary is needed, this is a good closing paragraph:

> Phase A deterministic chain assembly is now structurally strong on the
> GT-backed baseline, and Phase A.5 plus Phase B give us bounded ways to recover
> or calibrate the remaining ambiguous cases without giving up deterministic
> authority. The next major step is no longer inventing new structure, but
> formalizing the benchmark protocol and proving broader effectiveness on real
> firmware.
