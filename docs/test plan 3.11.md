# SourceAgent Benchmark Expansion & Testing Plan (Stripped-ELF First)

Alignment note (2026-03-12):

- this file remains a useful expansion sketch
- the current canonical alignment note is now
  `docs/benchmark_gap_and_experiment_design_20260312.md`
- the active asset-status companion is `docs/sample_status.md`
- the current practical run plan remains `docs/test_full.md`

Use this file as background design context, not as the only up-to-date source of
benchmark scope.

This document is a practical “what to run next” plan to:

1) **expand the number of test samples** (especially stripped ELF),
2) **manufacture more Ground Truth (GT) samples** (both sink-only GT and full chain GT),
3) provide a **repeatable evaluation + tuning loop** for SourceAgent (and later BinAgent/LLM review).

The end goal is still: **static detection of CWE/CVE candidates in Type-II/III firmware binaries** (RTOS/bare-metal/monolithic Cortex-M style), and the benchmark must support both:

- **scientific evaluation** (GT-backed, strict metrics), and
- **scale stress-testing** (large no-GT corpora + review workload metrics).

---

## 0) What we already have (baseline reality check)

### 0.1 Unstripped ELF “labeling” suite (sink-oriented GT)

The repo already has an unstripped evaluation suite report that:

- runs `--online --stage 7` on **48 samples** across: `microbench`, `p2im-unit_tests`, `uSBS`, `monolithic-firmware-collection`
- uses sink-oriented GT (`normalized_gt_sinks.json`) for strict TP/FP/FN (only for the GT-covered subset)
- reports **perfect strict sink metrics on GT samples in that round** (TP=17, FP=0, FN=0)

This proves: on **unstripped ELF**, your current miners + verifier are already strong for the current sink label space.

**But** this is not the finish line. Unstripped can hide “name leakage”. The next step must be **stripped ELF evaluation** to confirm the system really works when symbols/types are gone.

### 0.2 GT-backed Suite v2 (full chain GT)

You already have a chain-level baseline:

- **44 samples total** = `14 microbench` + `30 mesobench full-GT`
- **386/386 positive chains matched** (100% chain hit rate)
- **0 spurious non-drop chains**, **253/253 channel-required satisfied**, and **27/27 negative expectations satisfied**

This proves Phase A “deterministic chain assembly” is structurally correct on the current benchmark.

The remaining open problem there is **verdict calibration / semantic triggerability** (which you are now addressing with the LLM reviewer + strict/soft gate design).

### 0.3 No-GT large scan (review workload)

You also have a combined summary over no-GT shards:

- **94 no-GT samples**, generating **1937 chains**, with triage counts (confirmed / suspicious / safe / dropped) and review_queue sizing.

This is key for “top-tier story”: you can evaluate both **GT correctness** and **realistic triage workload**.

---

## 1) Why we need to massively expand samples (and what “good expansion” means)

If we only report unstripped ELF + a small GT suite, reviewers will (reasonably) worry about:

- **symbol leakage** (miners hit by function names rather than semantics)
- limited coverage of stripped/optimized builds
- limited coverage of real firmware diversity
- lack of stress testing (candidate explosion / runtime)

So the benchmark expansion must satisfy 4 properties:

1) **Stripped-first**: primary metrics should be on stripped ELFs.
2) **GT-backed core**: a smaller subset with **full chain GT** stays frozen and reproducible.
3) **Large no-GT corpora**: a larger subset gives scale + triage workload statistics.
4) **Diversity**: cover multiple source types (MMIO/ISR/DMA), channel types (ring/queue/flag/callback), sink types, parse patterns, and check patterns.

---

## 2) Sample expansion strategy (stripped ELF first)

### 2.1 “Free” expansion: strip everything you already have

This is the fastest way to validate you are not benefiting from symbol names.

**Idea:** For every ELF you already test today:

- keep an **unstripped build** only for GT extraction/debug (not for the final paper metric),
- generate a corresponding **stripped build** for actual evaluation:

```bash
# Make a stripped copy (addresses stay stable)
cp foo.elf foo.stripped.elf
arm-none-eabi-strip --strip-all foo.stripped.elf
# or: llvm-strip / strip depending on toolchain
```

**GT portability rule:**
- stripping removes symbols/sections, but **does not relocate code**, so your address-based GT should still match.

**What this buys you:**
- A clean “symbols removed” benchmark with minimal engineering.

**What can break:**
- if your pipeline currently relies on debug sections or symbol names in any way (it shouldn’t),
- if your build system produces non-identical code layouts between “debug” and “release”.

So do it explicitly as:
- build once → copy → strip.

### 2.2 Expand the GT-backed baseline (the thing you will publish)

Your own report already defines what “add more mesobench to baseline” really means:

- *not* just collecting binaries
- but **promoting** more mesobench samples to **full GT** (anchors + object/channel/root/derive/check + pos/neg expectations)

Target growth:

- from **14 microbench + 30 mesobench = 44**
- to **14 microbench + 40/50 mesobench = 54/64**

#### How to choose which mesobench to promote

Pick samples that maximize *new behavior*, not just count:

- different protocol stacks / OS families (Zephyr / Contiki / lwIP / uSBS / STM32Cube)
- different channel styles (ISR→queue, ISR→ring, DMA→flag, callback dispatch)
- different root families (length roots, dispatch roots, format-arg roots)
- both vulnerable and patched/negative samples

#### “Promotion to full GT” checklist

A mesobench becomes publishable full-GT only when it has:

1) **Source-code anchors** (file:function:line or stable code anchors)
2) **source annotation** (what is the actual attacker-controlled entry: MMIO FIFO, DMA buffer, ISR fill, etc.)
3) **object + channel** annotations
   - object = which buffer/state struct carries the data
   - channel = ISR/task boundary crossing mechanism (ring/queue/flag/callback)
4) **root bundle expectations**
   - what should be the primary “risk root” (length/dispatch/format)
   - what aliases are acceptable
5) **derive + check** expectations
   - derive: how root is computed (e.g., `len = hdr[2] + 2`)
   - check: what guard is expected (and whether it is strong/weak)
6) **positive chains** (what must be found)
7) **negative expectations** (what must *not* be non-drop)

You already have the evaluator infrastructure. The main work is GT authoring.

### 2.3 Expand sink-only GT (cheap GT that scales)

Full chain GT is expensive. A scalable intermediate step is to create **sink-only GT** for many more binaries:

- Known “danger points” (memcpy callsites, suspicious loops, format string callsites, indirect callsites)
- Anchored using `addr2line` from a debug build (then evaluated on stripped build)

This allows you to scale **sink detection metrics** to 100+ binaries while only doing full chain GT on ~50.

### 2.4 Expand no-GT corpora (stress test + triage workload)

No-GT corpora answer questions reviewers will ask:

- How many candidates do you generate on real firmware?
- How big is the review queue?
- Do you explode on large binaries?
- Does the channel requirement suppress same-context noise?

Best sources (practical and compatible with your current repo layout):

- `monolithic-firmware-collection` already used by your no-GT runs
- `p2im-unit_tests` already used by your no-GT runs
- `uSBS` already used by your no-GT runs

Add external corpora only when your local pipeline is stable. Recommended external add-on corpora:

- **Fuzzware examples + experiments corpora** (they publish many firmware images and a large evaluation set)
- **P2IM externals** (they explicitly have unit tests + real-world firmware submodules)

Reference links (put in a code block to avoid MD-render link issues):

```text
Fuzzware (USENIX Security 2022):
  https://www.usenix.org/conference/usenixsecurity22/presentation/scharnowski
  https://github.com/fuzzware-fuzzer/fuzzware
  (README points to fuzzware-experiments repo for datasets)

P2IM (USENIX Security 2020):
  https://www.usenix.org/conference/usenixsecurity20/presentation/feng
  https://github.com/RiS3-Lab/p2im
```

---

## 3) Manufacturing new GT samples (what to build next)

You want two kinds of manufactured GT:

- **Microbench GT** (synthetic but systematic; fast to scale; excellent for ablations)
- **Mesobench full chain GT** (realistic codebases + injected vulns; slower but publishable)

### 3.1 Microbench vNext: build a generator, not a handful of hand-written tests

**Goal:** go from 14 microbench → 100+ automatically generated variants.

#### What microbench should cover (pattern matrix)

Think in dimensions (cross product), not “one test per bug”:

**A. Source type**
- MMIO polling source: `val = *(volatile uint32_t*)MMIO_ADDR`
- ISR MMIO source: ISR reads DR/FIFO and writes a buffer
- ISR filled buffer: ISR fills `rx_buf[]`, main consumes
- DMA backed buffer: DMA writes RAM, ISR/task consumes

**B. Channel type (async boundary)**
- ring buffer (head/tail)
- RTOS queue/mailbox (simulated if needed)
- flag/event gate (`rx_ready`)
- callback dispatch / function pointer table

**C. Root family (what attacker controls that matters)**
- `length`: copy length derived from header/byte
- `dispatch`: handler index derived from byte
- `format_arg`: format pointer derived from byte/ptr

**D. Sink type**
- COPY: `memcpy`, `strcpy`, `memmove`, loop-copy
- MEMSET: `memset(dst, 0, len)`
- STORE: `*(dst + idx) = x` or `dst[idx] = x`
- FORMAT STRING: `sprintf(dst, fmt, ...)`
- FUNC PTR: `handlers[cmd]()` or indirect call

**E. Check strength**
- strong check (bounds check that dominates sink)
- weak check (wrong variable, off-by-one, state-only gate)
- missing check

**F. Compiler variation**
- `-O0` vs `-O2`
- inlining enabled/disabled
- `-ffunction-sections -fdata-sections` and link-time GC
- static linking of libc-nano (forces thunk/alias issues)

This matrix gives you systematic ablations:

- stripped vs unstripped
- optimization sensitivity
- channel modeling sensitivity
- root-check matching sensitivity

#### How to generate microbench GT safely (avoid leakage)

Use a 2-build workflow:

1) build `debug.elf` (unstripped, `-g`) → extract GT addresses
2) copy and strip it → `eval.elf` (the thing you test)

GT extraction methods:

- map-based: parse linker map for function + label addresses
- `nm`-based: `arm-none-eabi-nm -n debug.elf`
- source-line based: `addr2line -e debug.elf <addr>`

**Important rule:**
- SourceAgent must never read GT during mining.
- GT is only for evaluation.

### 3.2 Mesobench vNext: “real code + injectable bug knobs”

Microbench gives clean ablations but is toy-ish. Mesobench is where you tell the “real firmware” story.

A scalable way to grow mesobench is to use a few **real stacks** and generate variants by toggling bug knobs.

#### Recommended mesobench families

1) **uSBS/lwIP echo clients/servers**
   - already present in your GT-backed suite
   - easy to add more variants: off-by-one, wrong check, missing check, different header layouts

2) **Zephyr prebuilt CVE samples** (if you already carry them as binaries)
   - good for stripped testing because the code is real and large enough

3) **Contiki network parsers**
   - good unbounded-walk style loops

4) **STM32Cube USB Host parsing**
   - good “MMIO FIFO → parse → store/copy” patterns

#### Mesobench GT authoring workflow (semi-automatic)

You can reduce manual GT time by a “draft-then-freeze” process:

1) Run Phase A on an *unstripped* build (debug only)
2) Export all artifacts (sources/objects/channels/roots/derive/check/chains)
3) Manually confirm and edit into GT JSON (freeze)
4) Evaluate on the *stripped* build

This avoids the trap of “hand writing full GT from scratch”, but still keeps GT human-curated.

### 3.3 Negative samples (precision matters)

To argue “review workload reduction”, you need negatives:

- patched variants of the same program
- programs with correct bounds checks
- programs where “sink exists” but **root is not attacker-controlled**

In full chain GT, negatives should be expressed as **negative expectations** (i.e., must be DROP or SAFE_OR_LOW_RISK).

---

## 4) Testing methodology (what to report)

### 4.1 GT levels (3-tier GT)

Use three GT tiers:

- **Tier L1: sink-only GT**
  - addresses of sink callsites + sink label
  - scalable to 100+ binaries

- **Tier L2: artifact GT**
  - sources/objects/channels/roots/derive/check GT inventory
  - useful for debugging miner/linker regressions

- **Tier L3: full chain GT**
  - positive chains + negative expectations + channel-required flags
  - publishable “end-to-end” evidence

### 4.2 Metrics (the ones that matter)

**For L1 (sink-only GT):**
- strict TP/FP/FN per sink type
- macro F1 across sink types

**For L3 (full chain GT):**
- chain hit rate (positives matched / total positives)
- spurious_non_drop (should be near zero)
- must_use_channel_ok (channel-required correctness)
- negative expectations satisfied

**For no-GT corpora:**
- #chains total
- #review_queue (how many require reviewer)
- breakdown: confirmed / suspicious / safe / dropped
- runtime per binary (including timeouts)

### 4.3 Stripped-ELF A/B test protocol

Every GT-backed sample should be evaluated in 2 modes:

- unstripped (debug only; helps debugging)
- stripped (the actual metric)

Report:

- delta in sink recall/precision
- delta in chain hit rate
- delta in review queue size

This directly answers the “name leakage” criticism.

---

## 5) Performance tuning guide (practical knobs)

### 5.1 Deterministic pipeline knobs

Your biggest scale risks are:

- too many sinks per binary
- too many roots per sink
- too many channel edges
- too many tunnel expansions

So tune with budgets:

- cap sinks examined per binary (top-K by confidence)
- cap roots per sink (keep primary root families first)
- cap channel path search depth / branching
- cap chains per sink and chains per binary

When expanding to stripped + large corpora, default to **conservative budgets** (reduce explosion), then loosen once stable.

### 5.2 Ghidra/decompilation cost controls

For large corpora:

- cache decompilation results (already used in your pipeline design)
- reuse the same Ghidra project per shard when possible
- prioritize decompiling only:
  - sink caller functions
  - suspected channel producers/consumers

### 5.3 Strict vs soft verdict (important for reviewer integration)

To keep “more auditable material”:

- strict gates: prevent nonsense chains (fail-closed for structure)
- soft gates: preserve semantic reviewer rationale even when structure is incomplete

This should be reflected in evaluation:

- strict metrics (publishable correctness)
- soft metrics (how well the system surfaces candidates for review)

---

## 6) How to run (repro patterns you should standardize)

### 6.1 GT-backed evaluator rerun

```bash
cd /home/a347908610/sourceagent
python3 -m sourceagent.pipeline.microbench_gt_v2_eval \
  /tmp/<eval_dir> \
  --gt-root /home/a347908610/sourceagent/firmware/ground_truth_bundle/gt_backed_suite
```

### 6.2 Main online eval pattern

```bash
cd /home/a347908610/sourceagent
python3 -m sourceagent.interface.main eval \
  --manifest-json <manifest.json> \
  --gt-json firmware/ground_truth_bundle/normalized_gt_bundle.json \
  --online --stage 10 \
  --mcp-connect-timeout-sec 40 \
  --sample-timeout 300 \
  --analysis-wait-sec 90 \
  --output-dir <out_dir>
```

### 6.3 Stripped suite run

Recommended structure:

- produce a manifest that points to `*.stripped.elf`
- reuse the same GT JSON as the unstripped version (address-stable)

---

## 7) Concrete next actions (what I would do now)

### Week 1: Prove stripped-ELF robustness + expand microbench quickly

1) **Generate stripped variants** of the entire current GT-backed suite.
2) Run Stage 7 (label-only) and Stage 10 (full chain + reviewer prompt export) on stripped.
3) Compare:
   - sink metrics on microbench sink-only GT
   - chain hit/spurious on GT-backed suite
4) Build a **microbench generator** to create +50 new variants:
   - start with (source type × sink type × check strength) and add channels.
5) Add at least **10 negative samples** (patched variants) to prevent “always suspicious” behavior.

### Week 2: Expand mesobench full GT and scale no-GT corpora

1) Pick **10 additional mesobench seeds** and promote to full GT.
2) Add a large shard of no-GT binaries (e.g., more monolithic-firmware-collection samples or external corpora).
3) Tune budgets to keep:
   - spurious_non_drop ~ 0
   - review_queue manageable
4) Start plotting:
   - runtime vs binary size
   - review workload vs budgets

---

## 8) Notes on “where to find more samples” (pragmatic)

### Inside your repo (lowest friction)

- `monolithic-firmware-collection`
- `p2im-unit_tests`
- `uSBS`
- additional Zephyr/Contiki prebuilt samples that are already present as binaries (even before you promote them to GT)

### Introduced-vulnerability suites (high value for verdict calibration)

If you are seeing cases like:

```
<cve_named_sample>
<chains_kept> / <chains_total>
spurious = <spurious>
```

…where the binary is *known* to be vulnerable (CVE-labeled), but the system only outputs **medium risk**, then you need **positive controls** where vulnerabilities exist **by construction**.

These “introduced vuln” suites are ideal because they let you answer two questions unambiguously:

1) *Is the chain actually describing a triggerable vulnerability?*
2) *Can our strict/soft gates + LLM reviewer separate vulnerable vs patched variants?*

#### A) uSBS “Ground-truth Benchmark” (bare-metal, injected vulns, triggers)

Repo: [pwnforce/uSBS](https://github.com/pwnforce/uSBS)

The **Ground-truth Benchmark** subdirectory is particularly relevant:

- [Ground-truth Benchmark/](https://github.com/pwnforce/uSBS/tree/master/Ground-truth%20Benchmark)
- [fw/](https://github.com/pwnforce/uSBS/tree/master/Ground-truth%20Benchmark/fw)
  - contains compiled vulnerable firmware (**.elf + .bin** in many cases), plus **P2IM fuzz scripts** and **inputs/pcaps** that trigger the vulnerability
  - example: [udp_echo_server_bof_expl/](https://github.com/pwnforce/uSBS/tree/master/Ground-truth%20Benchmark/fw/udp_echo_server_bof_expl) includes both an ELF/BIN and multiple test scripts
- [injected_snippets/](https://github.com/pwnforce/uSBS/tree/master/Ground-truth%20Benchmark/injected_snippets)
  - contains the injected vulnerability snippets (bof, off-by-one, double-free, use-after-free)

**Why uSBS is the best “introduced vuln” suite for your current problem**

- It’s **Type-III-ish** (monolithic bare-metal Cortex-M style), and the vulnerable code is “realistic glue” around lwIP / STM32 example firmware.
- You get not only “vulnerable binaries”, but often also **triggering inputs**, which helps you sanity-check whether a chain’s trigger summary makes sense.
- Many samples have **paired variants** (patched/instrumented versions), which are the strongest controls for evaluating strict/soft verdict calibration.

**Good starting families (vuln-by-construction)**

- BOF / off-by-one:
  - `tcp_echo_client_vuln_bof/`
  - `tcp_echo_client_vuln_off_by_one/`
  - `tcp_echo_client_vuln_off_by_one_test_payload_len/`
  - `udp_echo_server_bof/`
  - `udp_echo_server_bof_expl/`
  - `udp_echo_server_off_by_one/`
- Heap bugs:
  - `udp_echo_server_double_free/`
  - `udp_echo_server_uaf/`

**Paired variants you can use as negative controls (examples)**

- `udp_echo_server_bof_expl_patched/`
- `udp_echo_server_bof_instrumented/`
- `udp_echo_server_bof_instrumented_patched/`
- `udp_echo_server_bof_expl_patched_instrumented/`
- `udp_echo_server_bof_expl_patched_instrumented_patched/`

**How to integrate uSBS into our evaluation (recommended)**

1) Add the uSBS `fw/*/*.elf` into your **mesobench pool**.
2) Maintain a small manifest table (YAML/JSON) for each sample:
   - `sample_id`, `family`, `expect_vuln` (true/false), `vuln_kind`, `paired_with` (patched variant if exists)
3) Promote a subset (e.g., 6–10) into GT tiers:
   - **Tier L1 sink-only GT** (fast): known sink callsites + sink label
   - **Tier L3 full chain GT** (slow, publishable): source/object/channel/root/check expectations + positives + negatives
4) Add a new “verdict calibration” report section:
   - vulnerable variants should produce **at least one non-drop chain** and land in top-k triage
   - patched variants should be **dropped or ranked much lower**

**Licensing caveat (important)**

The uSBS benchmark README includes redistribution/execution constraints for STMicroelectronics firmware. Before redistributing binaries in a paper artifact, verify the license terms.

#### B) Juliet Test Suite (synthetic introduced vulns; use as sink/check stress-test)

Juliet is not firmware, but it is useful as a *huge introduced-vuln corpus* to stress-test sink/check detection and stripped/optimized robustness.

- Official NIST SARD page: [Juliet C/C++ 1.3](https://samate.nist.gov/SARD/test-suites/112)
- NIST publication overview: [Juliet 1.1 overview paper](https://www.nist.gov/publications/juliet-11-cc-and-java-test-suite)

**How to use Juliet without polluting the Type-II/III story**

- Treat Juliet as **Tier L0 regression** for:
  - COPY/MEMSET/FORMAT sinks
  - check modeling (strong vs weak)
  - runtime scaling on large corpora
- Do **not** claim it validates MMIO/ISR/DMA source mining or async channel recovery.

Practical usage:

1) Select CWE families that overlap your sink taxonomy (e.g., CWE121/CWE122/CWE134/CWE190).
2) Cross-compile for ARM + strip (`-Os/-O2` + `strip`) to stress your symbol-free miners.
3) Use Juliet’s metadata (`good`/`bad`) to derive sink-only GT.

Optional binary dataset derived from Juliet:

- [ROMEO dataset paper](https://arxiv.org/pdf/2112.06623v2) (binary dataset built from Juliet)

#### C) Debugging: why a CVE-named sample only gets “medium risk”

In practice, “CVE in filename” does **not** guarantee your pipeline will output **high risk**, because your scoring/verdict is based on:

- *what the chain assembly can prove structurally* (Phase A)
- *what the semantic reviewer can justify from the available evidence* (Phase B)
- and the strict/soft gate thresholds you configured

If you want to know *exactly* why a sample is only medium-risk, use this workflow:

1) Identify the **winning chain id** that produced the final verdict.
   - Look at `verdict_soft_triage.json` (or the CLI summary) and find the top-ranked chain.

2) Check whether the “true CVE chain” is actually present but ranked lower.
   - If there are many chains kept and `spurious` is high, it’s common that the *real chain* exists but loses ranking to generic STORE/LOOP candidates.
   - This is a ranking problem (Phase A feature weighting), not a detection problem.

3) Compare **Phase A strict gates** vs **Phase B reviewer suggestion**.
   - Phase A evidence lives in: `chains.json`, `chain_eval.json`, `verdict_feature_pack.json`, `verdict_audit_flags.json`.
   - Phase B evidence lives in: `verdict_review_session.json` + `verdict_review_raw_response.json`.
   - If reviewer says “high/confirmed” but final is “medium/suspicious”, it often means:
     - a strict post-check rejected the chain (e.g., missing bound object path),
     - and you didn’t preserve enough rejected rationale (this is what P4 addresses).

4) Classify the root cause (most common buckets):
   - **Root binding missing**: chain has a sink but cannot prove attacker control of the length/index/root.
   - **Check modeling too optimistic**: a weak/irrelevant check is treated as a real guard.
   - **Channel hop under-specified**: the cross-context handoff exists, but Phase A couldn’t prove the same bytes survive (ISR/queue/global).
   - **Library attribution noise**: sinks are detected in libc/printf internals rather than at the callsite.

5) Use introduced-vuln pairs (uSBS patched vs vuln) to calibrate.
   - If both vulnerable and patched variants remain “medium”, your soft gates are too permissive or reviewer prompt is too vague.
   - If vulnerable becomes “high” but patched is still “medium/high”, your check modeling or ranking needs refinement.

### External corpora (only after you stabilize stripped)

- Fuzzware examples + fuzzware-experiments corpora
- P2IM externals (10 real-world firmware + unit tests)

The external corpora are best used first as **no-GT stress tests**, and only later promoted into sink-only GT or full chain GT.
