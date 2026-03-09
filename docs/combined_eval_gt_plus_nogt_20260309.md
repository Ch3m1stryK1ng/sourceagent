# Combined SourceAgent Evaluation Before BinAgent Integration (2026-03-09)

## Scope

This report answers three questions before wiring SourceAgent into BinAgent:

1. How does SourceAgent perform on the current GT-backed benchmark set?
2. What volume and shape of artifacts does SourceAgent generate on additional unstripped no-GT firmware samples?
3. Which parts of BinAgent should be retained, and which parts should be bypassed because SourceAgent already covers them?

## Evaluation Layout

The evaluation was split into two parts on purpose.

### Part A: GT-backed quality baseline

Dataset:

- `44` GT-backed samples
- `14` `microbench`
- `30` `mesobench`

Reference result directory:

- `/tmp/eval_gt_backed_suite_v2_p35plus_rerun2_merged`

This part is used to measure structural correctness, because these samples have chain-level GT.

### Part B: no-GT scale / artifact generation scan

Dataset:

- `94` additional unstripped firmware binaries without GT
- family breakdown:
  - `47` `p2im-unit_tests`
  - `37` `monolithic-firmware-collection`
  - `10` `uSBS`

Reference result directories:

- `/tmp/eval_extra_no_gt_shard1_20260309_010532`
- `/tmp/eval_extra_no_gt_shard2_20260309_010532`

This part is used to measure how much deterministic review material SourceAgent produces for BinAgent.

## Why the split is correct

A single mixed metric across GT-backed and no-GT samples would be misleading.

- GT-backed samples are for correctness and hit-rate
- no-GT samples are for discovery volume, queue pressure, and artifact distribution

That split is the correct pre-integration view for BinAgent.

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

Source:

- `/tmp/eval_extra_no_gt_shard1_20260309_010532`
- `/tmp/eval_extra_no_gt_shard2_20260309_010532`

### Overall totals

Across `94` no-GT samples, SourceAgent produced:

- verified source labels: `7640`
- verified sink labels: `2135`
- total verified labels: `9775`
- chains: `1937`
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

### 1. SourceAgent now produces enough review material for BinAgent

This is no longer a toy output surface.

Even without GT, the current pipeline yields at scale:

- thousands of verified labels
- nearly two thousand chains
- hundreds of review candidates
- hundreds of soft triage entries

That is enough material for a review-stage consumer.

### 2. The main review load will not come from microbench

The dominant review pressure comes from:

- `monolithic-firmware-collection`
- `p2im-unit_tests`

not from `microbench`.

That matters for BinAgent planning: review batching and queue limits should be tuned for these larger families, not for the toy set.

### 3. `uSBS` remains review-heavy despite smaller size

`uSBS` contributes fewer samples but a relatively high suspicious count compared with its size.

That makes it useful for semantic review stress testing.

## Largest review-queue samples

Representative high-pressure examples from the no-GT scan:

- `monolithic_firmware_collection_armcortex_m_st_plc_st_plc` — `96` chains, `7` review queue, `8` soft triage
- `monolithic_firmware_collection_armcortex_m_atmel_6lowpan_udp_tx_atmel_6lowpan_udp_tx` — `73` chains, `7` review queue, `8` soft triage
- `monolithic_firmware_collection_armcortex_m_atmel_6lowpan_udp_rx_atmel_6lowpan_udp_rx` — `73` chains, `7` review queue, `8` soft triage
- `monolithic_firmware_collection_armcortex_m_samr21_http_samr21_http` — `49` chains, `7` review queue, `8` soft triage
- `monolithic_firmware_collection_armcortex_m_expat_panda_expat_panda` — `47` chains, `7` review queue, `8` soft triage
- `p2im_unit_tests_nuttx_gpio_int_f103_nuttx_gpio_int` — `37` chains, `7` review queue, `8` soft triage
- `p2im_unit_tests_nuttx_usart_f103_nuttx_usart` — `37` chains, `7` review queue, `8` soft triage

Interpretation:

- BinAgent should expect queue saturation on large monolithic networked samples
- BinAgent should not expect review pressure to be evenly distributed across samples

## What SourceAgent Should Pass To BinAgent

SourceAgent should pass deterministic pre-flight artifacts only once.

The minimum useful handoff is:

- `verdict_feature_pack.json`
- `verdict_calibration_queue.json`

Helpful optional context:

- `chains.json`
- `chain_eval.json`
- `channel_graph.json`
- `sink_roots.json`
- `verdict_soft_triage.json`
- `verdict_audit_flags.json`

## BinAgent Overlap Check

The current BinAgent repo still duplicates deterministic recovery work.

### Duplicated modules

`/home/a347908610/binagent/pentestagent/agents/preflight.py`

- builds sink/source hints
- builds ranked sink callsite queue

`/home/a347908610/binagent/pentestagent/agents/stage2.py`

- decompiles caller functions
- extracts tracked bindings
- builds slice closures
- assembles evidence packs

`/home/a347908610/binagent/pentestagent/agents/general_agent.py`

- stage3 classifies findings into `confirmed / suspicious / dropped`
- creates review plans for suspicious findings

These stages overlap with SourceAgent's current deterministic pipeline.

## Recommendation

### Do not keep two deterministic pipelines

Recommended split:

- SourceAgent = deterministic firmware pre-flight owner
- BinAgent = semantic review / audit layer only

### What SourceAgent should continue owning

- source detection
- object recovery
- channel graph
- sink detection
- root recovery
- derive/check extraction
- deterministic chain construction
- deterministic verdict basis
- calibration queue generation

### What BinAgent should keep

- review planning
- review batching / budget handling
- LLM prompt orchestration
- semantic trigger summarization
- audit-only review mode
- review decision persistence

### What BinAgent should stop doing when SourceAgent artifacts are available

- preflight ranking as authoritative recovery
- stage2 closure building as authoritative recovery
- stage3 deterministic verdicting as authoritative recovery

## Practical Integration Path

### Near-term

Keep BinAgent external and consume SourceAgent artifacts.

Flow:

1. SourceAgent runs stages 1-10
2. SourceAgent writes feature packs and review queue
3. BinAgent reads queued chains only
4. BinAgent writes `review_decisions.json`
5. SourceAgent applies those decisions via fail-closed post-check

### Later

If the review contract stabilizes, move only the review shell into SourceAgent.

Do not migrate BinAgent's old deterministic preflight/stage2/stage3 logic into SourceAgent.

## Progress Against Planning

Already done:

- deterministic source/sink detection
- channel graph and refined objects
- sink root extraction
- tunnel-aware chain recovery
- derive/check extraction
- chain evaluation
- verdict feature pack
- calibration queue
- audit flags and soft triage
- GT-backed suite (`microbench + mesobench`)
- no-GT scale scan on additional unstripped firmware

Not done yet:

- BinAgent adapter that directly consumes SourceAgent review queue
- LLM semantic review execution loop on top of `verdict_calibration_queue`
- verdict exactness improvement after external review

## Bottom Line

SourceAgent is already producing enough deterministic pre-flight material to become the single upstream provider for BinAgent.

The engineering decision now is not whether SourceAgent can feed BinAgent. It can.

The real decision is to stop duplicating deterministic recovery inside BinAgent and reduce BinAgent to review-only semantics.
