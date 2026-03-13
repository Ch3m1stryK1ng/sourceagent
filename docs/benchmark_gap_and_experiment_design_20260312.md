# Benchmark Gaps and Experiment Design Alignment (2026-03-12)

This note aligns three things:

- the paper-facing requirements in `docs/proposal_updated_v3_10_20260310.docx`
- the practical benchmark-growth plan in `docs/test_full.md`
- the current SourceAgent asset state in `firmware/eval_suite/` and
  `firmware/ground_truth_bundle/`

The goal is to answer two questions clearly:

1. what is still missing before the current assets qualify as a publishable
   benchmark?
2. how should the experiments be organized so they actually answer the proposal
   research questions?

## 1. What a Benchmark Needs

A publishable benchmark is not just “many binaries + some GT”.

At minimum it needs:

1. **A frozen scope**
   - versioned manifests
   - clear inclusion rules
   - stable sample identifiers

2. **Explicit tasks**
   - what is being measured?
   - label detection, chain assembly, risk calibration, format robustness, or
     no-GT workload?

3. **Machine-readable GT**
   - sink-only GT for scalable strict metrics
   - full chain GT for end-to-end structural scoring
   - risk GT for the subset where `P0/P1/P2` and `HIGH/MEDIUM/LOW` are part of
     the claim

4. **A scoring protocol**
   - metrics
   - accepted outputs
   - strict vs soft output handling
   - failure/timeout treatment

5. **A tuning policy**
   - what is allowed for development and threshold tuning
   - what is frozen for final reporting

6. **A reproducible run recipe**
   - commands
   - manifests
   - artifact locations
   - summary outputs

7. **A benchmark story**
   - why these samples matter
   - what diversity they represent
   - what claims they support

## 2. Proposal v3.10: What the Paper Actually Needs

From Section 7 of `proposal_updated_v3_10_20260310.docx`, the paper-facing
evaluation now needs five distinct experiment tracks:

1. **format robustness**
   - unstripped ELF
   - stripped ELF
   - raw `.bin` with known base
   - raw `.bin` with inferred base

2. **strict structural evaluation**
   - source/sink/root recall
   - chain hit rate
   - spurious non-drop
   - must-use-channel correctness

3. **semantic/risk calibration**
   - verdict under/over
   - strict vs soft outputs
   - reviewer coverage
   - manual review effort proxies

4. **ablations**
   - no ChannelGraph
   - no root-aware binding
   - no check modeling
   - no reviewer
   - no Phase A.5 supervision
   - reviewer schema variants

5. **scalability + case studies**
   - runtime vs binary size/function count
   - large firmware stress runs
   - deep source→channel→derive/check→sink case studies

This means the current benchmark must do more than prove “we can recover 386/386
chains on the current suite”.

## 3. What the Repo Already Has

The current asset situation is already strong enough to support a serious first
benchmark package.

### 3.1 Canonical manifests and sample catalog

- `firmware/eval_suite/gt_backed_suite_manifest.json`
- `firmware/eval_suite/gt_backed_suite_stripped_manifest.json`
- `firmware/eval_suite/unstripped_elf_manifest.json`
- `firmware/eval_suite/mesobench_stripped_elf_manifest.json`
- `firmware/eval_suite/no_gt_94_manifest.json`
- `firmware/eval_suite/microbench_autogen_unstripped_manifest.json`
- `firmware/eval_suite/microbench_autogen_stripped_manifest.json`
- `firmware/eval_suite/l1_sink_only_combined_manifest.json`
- `firmware/eval_suite/negative_patched_candidates_manifest.json`
- `firmware/eval_suite/sample_catalog.json`

### 3.2 Current scale snapshot

From `sample_catalog.json`:

- `568` tracked binary artifacts total
- `162` raw bins
- `155` stripped ELFs
- `251` unstripped ELFs
- `523` coarse bare-metal binaries
- `45` coarse RTOS binaries

From the benchmark manifests:

- `44` GT-backed full benchmark samples
- `44` GT-backed stripped peers
- `30` mesobench stripped peers
- `94` canonical no-GT binaries
- `108` autogen microbench variants
- `8` negative/patched candidates

### 3.3 Current GT depth

- L1 sink-only coverage:
  - `150` binaries
  - `484` sink rows
- L2 curated microbench:
  - `14` samples
- L3 mesobench full GT:
  - `30` samples
- GT-backed structural benchmark:
  - `44` samples

### 3.4 Current risk GT status

For real CVE binaries in `gt_backed_suite`:

- `16` CVE samples total
- `12` samples already have at least one chain-level risk GT annotation
- `19` curated anchor-risk chains are present

This is enough for a real risk-calibration subset, but not yet enough for
“complete risk GT over every chain in the benchmark”.

## 4. The Main Gaps To Benchmark-Ready State

The current repo is **asset-rich but benchmark-partial**.

The biggest gaps are no longer sample count. They are protocol and evaluation
discipline.

### Gap A: no frozen benchmark release boundary

We have manifests, but not yet a formal “Benchmark v1” package with:

- a frozen publishable split
- a separate development/tuning split
- an explicit statement of which manifests count for the paper

Right now it is too easy to tune and report on the same suite.

### Gap B: raw `.bin` track is not yet a canonical benchmark track

The proposal explicitly asks for:

- raw `.bin` with known base
- raw `.bin` with inferred base

The repo already contains raw bins, but there is not yet a paper-facing canonical
raw benchmark manifest family with:

- known-base subset
- inferred-base subset
- format-paired peers for comparison against ELF

### Gap C: risk calibration is not yet a full benchmark layer

We now have:

- chain-level risk GT schema
- evaluator support
- a real subset of curated risk anchors

But we still do not have:

- a frozen risk-calibration subset manifest
- suite-level risk summary reports as a standard benchmark artifact
- broad negative/patched risk GT beyond the first anchor subset

### Gap D: ablations are described, but not frozen as benchmark presets

The proposal needs ablations. The repo already has the conceptual components,
but it still lacks a benchmark-facing table of canonical ablation modes such as:

- deterministic full
- no ChannelGraph
- no root-aware matching
- no check modeling
- no reviewer
- no supervision

Without frozen presets, ablations become ad hoc and hard to reproduce.

### Gap E: no held-out policy for tuning vs reporting

This is the most important scientific gap.

We currently need an explicit split such as:

- `dev/calibration`: for thresholds, reviewer prompt tuning, supervision gates
- `report/frozen`: for headline numbers

Without this, verdict calibration and risk thresholds are vulnerable to
benchmark overfitting.

### Gap F: benchmark summaries are not yet stratified by metadata axes

The proposal wants robustness and scalability claims. Those should be stratified
by:

- binary format
- size bucket
- execution model
- framework family
- dataset family

The repo now has `sample_catalog.json` to support this, but the reporting layer
does not yet treat those as standard benchmark dimensions.

## 5. Revised Experiment Structure

The easiest way to make the experiments paper-ready is to split them into five
tracks with fixed roles.

### Track T1: Label and Sink Detection Benchmark

Purpose:
- answer the proposal's RQ1-style “can we recover sources/sinks without symbol
  leakage?”

Primary assets:
- `firmware/eval_suite/l1_sink_only_combined_manifest.json`
- `firmware/ground_truth_bundle/normalized_gt_sinks_l1_combined.json`

Primary formats:
- stripped first
- unstripped as reference
- raw known-base subset later

Metrics:
- TP / FP / FN
- per-sink-family macro F1
- runtime / timeout

What is missing:
- canonical raw-bin L1 subset
- standard stratified summary by size / framework / execution model

### Track T2: Structural Chain Benchmark

Purpose:
- answer the proposal's Phase A structural claim

Primary assets:
- `firmware/eval_suite/gt_backed_suite_manifest.json`
- `firmware/eval_suite/gt_backed_suite_stripped_manifest.json`
- `firmware/ground_truth_bundle/gt_backed_suite/`

Metrics:
- chain hit rate
- spurious non-drop
- must-use-channel correctness
- negative expectations satisfied
- verdict exact / under / over

Recommended headline protocol:
- report stripped numbers first
- show unstripped as a reference/control

What is missing:
- frozen dev/report split
- official raw-bin counterpart for the GT-backed subset

### Track T3: Risk Calibration Benchmark

Purpose:
- answer the proposal's Phase B claim
- verify whether chains are not only found, but calibrated to the correct final
  severity/priority

Primary assets:
- GT-backed risk-annotated subset inside
  `firmware/ground_truth_bundle/gt_backed_suite/samples/`
- current chain-level risk evaluator

Metrics:
- exact match on `expected_final_verdict`
- exact match on `expected_final_risk_band`
- exact match on `expected_review_priority`
- `P0` recall / precision on the annotated subset
- review queue size after gating

What is missing:
- canonical subset manifest for risk GT
- more patched/negative pairs with explicit risk expectations
- suite-level risk summary as a standard artifact

### Track T4: No-GT Workload and Scalability Benchmark

Purpose:
- answer scale and triage-cost questions

Primary assets:
- `firmware/eval_suite/no_gt_94_manifest.json`
- `firmware/eval_suite/no_gt_94_shard1_manifest.json`
- `firmware/eval_suite/no_gt_94_shard2_manifest.json`
- sample catalog stratification

Metrics:
- runtime
- timeout rate
- chains per binary
- review queue volume
- strict/soft triage distributions
- P0/P1/P2 distribution

What is missing:
- automated stratified summaries by size bucket and execution model
- a larger large-image shard if the paper wants stronger scalability claims

### Track T5: Ablation and Case-Study Track

Purpose:
- prove which components actually matter
- provide interpretable stories for reviewers

Canonical ablations to freeze:

- full deterministic structural pipeline
- no ChannelGraph
- no root-aware root binding
- no check/derive modeling
- no review
- no supervision

Canonical case studies:

- `zephyr_cve_2020_10065`
- `cve_2021_34259_usb_host`
- `cve_2018_16525_freertos_dns`
- one Contiki parser case

What is missing:
- explicit manifest/preset definitions for each ablation
- a benchmark document that maps each ablation to the claim it supports

## 6. Recommended Benchmark Package Layout

To turn the repo into a paper-facing benchmark, the next packaging step should
look like this:

```text
firmware/eval_suite/benchmark_v1/
  README.md
  tasks.json
  splits/
    t1_l1_sink_stripped_manifest.json
    t2_gt_backed_stripped_manifest.json
    t2_gt_backed_unstripped_manifest.json
    t3_risk_gt_manifest.json
    t4_no_gt_94_manifest.json
    t4_no_gt_94_shard1_manifest.json
    t4_no_gt_94_shard2_manifest.json
    t5_case_studies_manifest.json
  ablations/
    deterministic_full.json
    no_channel_graph.json
    no_root_binding.json
    no_check_modeling.json
    no_review.json
    no_supervision.json
```

This does not require moving the current assets. It just provides a frozen,
paper-facing layer on top of them.

## 7. Immediate Improvements To The Experimental Loop

These are the highest-value changes to make next.

### E1. Freeze a dev/report split

Create two benchmark views:

- `benchmark_dev`
  - used for threshold tuning, reviewer prompt updates, supervision gating
- `benchmark_report`
  - never used for tuning after freeze

For the current repo, the easiest start is:

- keep the current `44`-sample GT-backed suite as the structural frozen core
- create a smaller risk-calibration development subset from the currently
  annotated real CVEs and patched pairs

### E2. Make stripped the headline metric for T1 and T2

The proposal is explicit about metadata robustness. So the reporting order
should become:

1. stripped
2. unstripped reference
3. raw known-base
4. raw inferred-base

### E3. Add a canonical T3 risk subset manifest

This should contain the current risk-GT-covered samples only, rather than
relying on “whatever samples happen to have risk fields”.

### E4. Use the sample catalog in every suite summary

Every benchmark summary should emit stratified views by:

- `binary_format`
- `symbol_state`
- `size_bucket`
- `execution_model`
- `framework_family`

### E5. Promote negative/patched binaries from “candidate” to benchmark role

The proposal needs calibrated severity, not only structural hit rate.

That requires:

- vulnerable vs patched pairs
- explicit “must not be `CONFIRMED/HIGH/P0`” expectations

The current `negative_patched_candidates_manifest.json` is the right seed, but
it is not yet a benchmark track by itself.

## 8. Short Answer: Are We Already At “Benchmark” Quality?

Almost, but not fully.

We already have:

- enough samples
- enough manifests
- enough GT depth
- enough evaluator infrastructure

We still need to formalize:

- frozen benchmark splits
- raw-format benchmark tracks
- canonical risk subset
- benchmark ablation presets
- tuning-vs-report separation
- stratified reporting

Once those are in place, the current repo can support a credible Type-II/III
firmware benchmark rather than only an internal evaluation suite.
