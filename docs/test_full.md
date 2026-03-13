# SourceAgent Benchmark Expansion & Testing Plan (Stripped-ELF First)

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

### 0.4 Benchmark-readiness update (2026-03-12)

Since this plan was first drafted, the repo has added:

- canonical stripped manifests for the GT-backed and mesobench suites
- a canonical `94`-sample no-GT workload manifest
- a `sample_catalog.json` with size / format / stripped-state / execution-model
  metadata
- first-pass chain-level risk GT for a subset of real CVE binaries

That means the bottleneck is no longer “do we have enough files?”.
The main remaining work is turning the current assets into a **frozen benchmark
protocol**:

- explicit benchmark task splits
- dev vs report separation
- canonical risk subset manifest
- raw `.bin` benchmark track
- ablation presets and stratified reporting

See `docs/benchmark_gap_and_experiment_design_20260312.md` for the aligned
gap analysis and revised experiment structure against
`proposal_updated_v3_10_20260310.docx`.

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

### 3.4 Introduced-vuln / injected-vuln corpora (to debug “CVE-named sample but only medium risk”)

Your current “real CVE” samples (e.g., Contiki/Zephyr CVE reproductions) are great for realism, but they are **not ideal for calibrating verdict** because:

- they often require subtle trigger preconditions (protocol state, compile-time options, specific packet sequences),
- ground-truth may be “a vulnerable code location” but not a guaranteed *static trigger* chain,
- and the program name containing `CVE-xxxx-xxxx` is **not** a reliable oracle for severity.

To answer *why* the system outputs only `MEDIUM` risk, you need binaries where “vulnerable vs patched” is controlled and reproducible.

#### Recommended: uSBS Ground-truth Benchmark (injected snippets + vulnerable/patched variants)

uSBS provides an **injected-vulnerability benchmark family** designed exactly for this purpose:

- `Ground-truth Benchmark/fw/` contains many firmware programs with **vulnerable / patched / instrumented** variants.
- `Ground-truth Benchmark/injected_snippets/vulns.c` contains the injected vulnerability snippets (e.g., BOF, off-by-one, UAF, double-free).
- Many `fw/<case>/` folders contain not just the binary but also **trigger inputs/scripts** (useful later for dynamic confirmation, but your pipeline is static).

**How to use it for SourceAgent (static):**

1) Treat uSBS cases as a Tier-L2/L3 “verdict calibration corpus”.
2) For each case, create a pair (or triple):
   - `vuln.elf` (or `*_vuln.elf`)
   - `patched.elf`
   - optionally `instrumented.elf` (as extra negative / sanity)
3) Generate **sink-only GT** cheaply from debug builds (addr2line + map), then evaluate on **stripped** copies.
4) For a smaller subset, promote to **full chain GT** by annotating:
   - the intended source entry (MMIO/ISR/DMA/simulated peripheral input),
   - the channel boundary (if any),
   - the intended root family (length/index/dispatch/format),
   - the sink site.
5) Use patched variants to build **negative expectations**:
   - same sinks may still exist, but *must not* be marked CONFIRMED, and ideally should fall to SAFE/LOW.

**Why this helps your ‘medium risk’ question:**

- If your system reports `MEDIUM` on vuln but also `MEDIUM` on patched, your risk scoring / check binding is too weak.
- If it reports `MEDIUM` on vuln but `LOW` on patched, the system is doing something sensible — the remaining step is to have Phase B LLM summarize trigger conditions and upgrade only when check is truly absent/weak.

#### Optional: Juliet / ROMEO (L0, not firmware-specific)

If you need a large volume of injected vulnerability binaries purely to stress “symbol-free sink + guard modeling”, you can add Juliet-like corpora.
Use them **only** as L0 stress tests (no MMIO/ISR/DMA relevance), and never as the headline evaluation for the paper.



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

### 4.4 Debug workflow: why a CVE-named sample only yields MEDIUM risk

When you see logs like:

- `zephyr-CVE-2020-10065: matched 21/22 but spurious=38`
- `contiki_cve_2020_12140_hello_world: matched 30/64, spurious=36`

…do **not** treat the filename as ground truth severity. Use the artifacts to identify the actual reason.

#### Step-by-step (per binary)

1) **Confirm whether the vulnerable sink/root was actually captured**
   - Look in: `raw_views/<sample>.chains.json` and `raw_views/<sample>.sink_roots.json`
   - If the expected sink/root is absent, the issue is in Phase A mining.

2) **Check structural reasons for non-CONFIRMED** (Phase A verdict gating)
   - `raw_views/<sample>.chain_eval.json` tells you which hard facts are missing:
     - `object_bound=false`, `root_matched=false`, `channel_required_not_satisfied`, etc.
   - `summary/<sample>.verdict_audit_flags.json` highlights systematic issues (root mismatch, control-only path, etc.).

3) **If Phase B review ran, inspect the semantic rationale**
   - `raw_views/<sample>.verdict_review_session.json` (and `*_raw_response.json`) contains:
     - trigger summary, preconditions, why check is weak/strong, and which snippets support it.

4) **Find out if the semantic suggestion was rejected and why**
   - `summary/<sample>.verdict_calibration_decisions.json`
     - check `accepted=false` cases and the `reject_reason`/`blocked_by` fields.
   - If “LLM said the right thing but it got rejected”, that’s exactly what P3/P4 are meant to fix:
     - strict vs soft gates
     - preserve rejected rationale

5) **Quantify what is causing spurious non-drop**
   - For spurious chains, count which reason codes / audit flags dominate:
     - too permissive STORE_SINK/LOOP_WRITE
     - missing channel enforcement
     - overly large tunnel budget
   - This drives tuning decisions (see §5).



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

### 5.4 Tuning loop (how to optimize in a controlled way)

To keep optimization scientific (and avoid “we tweaked until it looked good”), use this loop:

1) **Run a frozen baseline**
   - GT-backed suite (L3) + sink-only suite (L1) + a fixed no-GT shard.

2) **Collect structured error categories**
   - From `verdict_audit_flags`, `reason_codes`, and spurious chain stats:
     - miner miss (no sink/root)
     - root mismatch
     - object binding failure
     - channel enforcement failure
     - check binding ambiguity
     - candidate explosion (budget / ranking)

3) **Apply one targeted change at a time** (ablation discipline)
   Examples:
   - enable function seeding on stripped
   - enable FID on stripped
   - enable symbol-free memcpy/memset mining
   - tighten STORE_SINK gating
   - reduce tunnel branching / max chains per sink

4) **Re-run and compare deltas**
   - strict metrics: TP/FP/FN (L1), chain hit/spurious (L3)
   - soft metrics: review_queue size, suspicious ratio
   - cost metrics: runtime, decompile count, LLM calls (if enabled)

5) **Only then** adjust thresholds/budgets
   - budgets should be tuned against the no-GT shard so scale doesn’t explode.

This loop also produces clean “ablation tables” for a top-tier submission.



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

### External corpora (only after you stabilize stripped)

- Fuzzware examples + fuzzware-experiments corpora
- P2IM externals (10 real-world firmware + unit tests)

The external corpora are best used first as **no-GT stress tests**, and only later promoted into sink-only GT or full chain GT.
