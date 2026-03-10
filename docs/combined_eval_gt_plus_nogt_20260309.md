# Combined SourceAgent Evaluation Before BinAgent Integration (2026-03-09)

## Scope

This report answers four pre-integration questions:

1. How stable is the current GT-backed baseline?
2. What deterministic artifacts does SourceAgent produce on larger no-GT unstripped firmware samples?
3. Why do no-GT chain counts differ from sink counts, and why are many chains dropped?
4. Which parts are ready for semantic review, and which gaps still belong to deterministic extraction?

## Evaluation Layout

The evaluation is intentionally split into two parts.

### Part A: GT-backed quality baseline

Dataset:

- `44` GT-backed samples
- `14` `microbench`
- `30` `mesobench`

Reference directory:

- `/tmp/eval_gt_backed_suite_v2_p35plus_rerun2_merged`

This part measures structural correctness, because these samples have artifact-level and chain-level GT.

### Part B: no-GT scale / artifact generation scan

Dataset:

- `94` additional unstripped firmware binaries without GT
- `47` `p2im-unit_tests`
- `37` `monolithic-firmware-collection`
- `10` `uSBS`

Reference directories:

- `/tmp/eval_extra_no_gt_shard1_20260309_010532`
- `/tmp/eval_extra_no_gt_shard2_20260309_010532`

This part measures discovery volume, intermediate artifact volume, queue pressure, and review-readiness. It does **not** claim precision/recall on no-GT binaries.

## Why the split is correct

A single mixed metric across GT-backed and no-GT samples would be misleading.

- GT-backed samples are for correctness and hit-rate.
- no-GT samples are for discovery volume, intermediate artifact shape, and review load.

That split is the correct pre-integration view for semantic review / BinAgent-style auditing.

## Part A: GT-backed Baseline

Source:

- `/tmp/eval_gt_backed_suite_v2_p35plus_rerun2_merged/summary/artifact_eval_summary.json`

### Chain-level result

- GT-backed samples: `44`
- positive chains: `386`
- matched: `386`
- missed: `0`
- chain hit rate: `100%`
- `must_use_channel`: `253 / 253`
- negative expectations: `27 / 27`
- spurious non-drop: `0`

### Artifact-level recall

- sources: `97 / 105`
- objects: `51 / 58`
- channels: `42 / 48`
- sinks: `374 / 376`
- sink roots: `718 / 721`
- derive/checks: `361 / 390`

### Verdict situation

- verdict exact: `276`
- verdict under: `109`
- verdict over: `1`

Interpretation:

- structural chain recovery is already stable
- the remaining GT-backed problem is not chain construction anymore
- the remaining GT-backed problem is verdict calibration

## Part B: no-GT Scale Scan

Sources:

- `/tmp/eval_extra_no_gt_shard1_20260309_010532`
- `/tmp/eval_extra_no_gt_shard2_20260309_010532`

### Overall totals

Across `94` no-GT samples, SourceAgent produced:

- verified source labels: `7640`
- verified sink labels: `2135`
- total verified labels: `9775`
- object nodes: `903`
- refined objects: `954`
- channel edges: `369`
- sink roots extracted: `2058`
- chains materialized: `1937`
- chains with source: `655`
- chains with channel: `546`
- confirmed: `118`
- suspicious: `194`
- safe_or_low_risk: `88`
- dropped: `1537`
- calibration queue entries: `658`
- soft triage entries: `752`

### By dataset family

`monolithic-firmware-collection`

- labels: `6058`
- sources: `4979`
- sinks: `1079`
- object nodes: `402`
- refined objects: `437`
- channel edges: `191`
- chains: `945`
- with_source: `326`
- with_channel: `237`
- confirmed: `80`
- suspicious: `105`
- safe_or_low_risk: `72`
- dropped: `688`
- review queue: `259`
- soft triage: `296`

`p2im-unit_tests`

- labels: `3052`
- sources: `2159`
- sinks: `893`
- object nodes: `374`
- refined objects: `383`
- channel edges: `167`
- chains: `830`
- with_source: `278`
- with_channel: `279`
- confirmed: `37`
- suspicious: `40`
- safe_or_low_risk: `15`
- dropped: `738`
- review queue: `329`
- soft triage: `376`

`uSBS`

- labels: `665`
- sources: `502`
- sinks: `163`
- object nodes: `127`
- refined objects: `134`
- channel edges: `11`
- chains: `162`
- with_source: `51`
- with_channel: `30`
- confirmed: `1`
- suspicious: `49`
- safe_or_low_risk: `1`
- dropped: `111`
- review queue: `70`
- soft triage: `80`

## What the no-GT scan shows

### 1. SourceAgent produces substantial intermediate artifacts, not just labels

The no-GT scan is not merely a list of sources and sinks.

It already emits a large pre-review surface:

- `903` coarse object nodes
- `954` refined objects
- `369` inferred channel edges
- `2058` sink roots
- `1937` assembled chains

This is enough material for a semantic reviewer. The remaining problem is quality and prioritization, not lack of evidence.

### 2. Why `chains < sinks`

A sink label is **not** equivalent to a chain.

The current pipeline is root-aware and bounded:

- a verified sink only becomes chain-ready if at least one usable root is extracted
- some verified sinks never yield a usable root
- some roots are intentionally pruned before chain emission
- some roots are merged/deduplicated because they are secondary or redundant
- chain counts are bounded by per-sink / per-binary limits

In the no-GT scan:

- verified sink labels: `2135`
- sink roots extracted: `2058`
- chains materialized: `1937`

So there are **two separate reductions**:

1. `2135 -> 2058`
- `77` sink labels did not produce a usable root bundle
- typical reasons: root parse failure, weak fallback only, non-capacity-relevant secondary site

2. `2058 -> 1937`
- `121` root candidates were not materialized as final chains
- typical reasons: chain pruning, root-family dedup, bridge-only copy suppression, secondary-pointer suppression, per-sink cap

This is expected behavior. A healthy chain layer is **not** one-chain-per-sink. It is a filtered subset of sink candidates that still have actionable root semantics.

The main deterministic pruning code is in:

- [tunnel_linker.py](/home/a347908610/sourceagent/sourceagent/pipeline/linker/tunnel_linker.py)

Relevant mechanisms there include:

- `max_chains_per_sink`
- `max_chains_per_binary`
- `_prune_redundant_chains(...)`
- `_pointer_companion_redundant(...)`
- `_should_drop_bridge_only_copy_group(...)`
- `_should_skip_store_chain(...)`

### 3. Why `dropped` is large

`DROP` is currently the dominant no-GT verdict because the pipeline is intentionally fail-closed.

This is not a bug by itself. It reflects the current rule:

- if the chain cannot preserve enough deterministic structure, it should not survive as a non-drop result

Top drop failure buckets in the no-GT scan:

- `OBJECT_HIT_NONE = 646`
- `MAX_DEPTH_REACHED = 211`
- `OBJECT_HIT_NO_EDGE = 192`
- `ROOT_PARSE_FAILED = 97`
- `ROOT_WEAK_FALLBACK = 87`
- `CHECK_UNCERTAIN = 55`

Interpretation:

- the largest bucket is still object anchoring
- the next large bucket is bounded search depth
- cross-context chains also fail when object hits exist but no usable edge is found
- some sink families still produce weak root recovery

So `DROP = 1537` is high because the no-GT corpus is deliberately large and noisy, while the chain layer is designed to reject weakly justified paths rather than over-claiming exploitability.

### 4. Did we record reasons for `CONFIRMED / SUSPICIOUS` chains in that older no-GT run?

Not fully.

This matters.

That two-shard no-GT scan predates the later reviewer upgrades (`P0`, `P1`, `P2`, `P3`, `P4`) that now preserve:

- review transcript
- typed semantic reason codes
- segment assessment
- rejected semantic rationale
- semantic-only soft application

So for that older no-GT run:

- `CONFIRMED / SUSPICIOUS / SAFE_OR_LOW_RISK` are mostly deterministic chain verdicts
- they do **not** yet carry the full semantic reviewer rationale we now preserve in later runs
- therefore those counts are useful as workload signals, but not yet a rich explanation ledger

This is exactly why the reviewer work was added afterward.

### 5. What do `calibration queue = 658` and `soft triage = 752` mean?

They are related, but not the same.

`calibration queue`

- chains selected for possible semantic review
- filtered by calibration policy (`calibration_mode`, risk, suspicious ratio, max queue size)
- intended to be the reviewer worklist

`soft triage`

- the broader stage-10 soft-view ledger
- includes all chains that survive into `soft` / `dual` bookkeeping
- includes both reviewer-eligible chains and deterministic soft-widened chains
- therefore it can be larger than the review queue

So in the no-GT scan:

- `658` chains were selected as reviewer candidates
- `752` chains appeared in the broader soft triage surface

This difference is expected.

The relevant code is in:

- [verdict_calibration.py](/home/a347908610/sourceagent/sourceagent/pipeline/verdict_calibration.py)

Specifically:

- `_select_calibration_queue(...)`
- `_soft_candidate(...)`
- `_derive_soft_verdict(...)`
- `_summarize_soft_triage(...)`

## What this means for SourceAgent vs reviewer/BinAgent

### What is already solved

- SourceAgent is already a stable deterministic pre-flight owner
- it can mine labels at scale
- it can build intermediate artifacts at scale
- it can assemble and aggressively filter chains
- it can prepare a bounded semantic review queue

### What is not solved by the no-GT scan

The no-GT scan does **not** prove exploitability.

It only proves that SourceAgent can produce enough structured material for semantic review.

That is the correct role split:

- SourceAgent: deterministic facts and bounded chain candidates
- reviewer / BinAgent-style semantic phase: trigger validation, check effectiveness, exploitability semantics

## Practical interpretation

The no-GT scan answers the pre-integration question positively:

- SourceAgent now produces enough structured material to feed a reviewer at scale.

But it also shows where deterministic work is still expensive:

- object anchoring
- channel completion
- root extraction quality
- search depth

And it confirms that the remaining “is this really a vuln candidate?” question should be answered in the semantic review stage, not by over-expanding deterministic heuristics.

## Next steps

1. Improve reviewer snippet coverage and tool-assisted review.
2. Re-run focused reviewer-heavy samples:
   - `usb_host`
   - `dns`
   - `contiki`
   - `zephyr`
3. Keep deterministic baseline metrics separate from no-GT discovery metrics.
4. Continue treating SourceAgent as the single pre-flight authority; do not revive BinAgent deterministic stages.
