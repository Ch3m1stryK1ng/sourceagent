# Default Review-On Integration Status (2026-03-09)

## Goal

Integrate semantic review directly into SourceAgent so that the default execution path becomes:

1. deterministic source/object/channel/root/chain recovery
2. automatic review queue generation
3. internal LLM-backed semantic review on queued chains
4. fail-closed application of review decisions
5. strict / soft / dual verdict outputs

The purpose is not to re-run structural recovery inside an external repo, but to let SourceAgent own deterministic facts while a reviewer only calibrates semantic verdicts.

## Implementation Status

Current commit:

- `c97977a` `Integrate default-on verdict review flow`

### New Modules

- `sourceagent/agents/review_plan.py`
- `sourceagent/agents/review_runner.py`
- `sourceagent/llm/review_schema.py`

### Updated Modules

- `sourceagent/interface/main.py`
- `sourceagent/pipeline/chain_artifacts.py`
- `sourceagent/pipeline/verdict_calibration.py`

### Default Behavior

`eval` / `mine` now run review by default.

Review is skipped only when:

- `--disable-review` is set, or
- the calibration queue is empty.

Current knobs:

- `--review-mode semantic|audit_only`
- `--review-model <model>`
- `--max-review-items <n>`
- `--review-batch-size <n>`
- `--review-timeout-sec <sec>`
- existing calibration controls (`--calibration-mode`, budgets, thresholds, output mode)

External review remains supported via:

- `--verdict-review-json`

External decisions are merged with internal decisions using chain id as the key.

## Artifacts Added / Stabilized

Per sample, stage 10 now emits:

- `verdict_feature_pack.json`
- `verdict_calibration_queue.json`
- `verdict_calibration_decisions.json`
- `verdict_audit_flags.json`
- `verdict_soft_triage.json`
- `verdict_review_plan.json`
- `verdict_review_trace.json`

These artifacts are the canonical handoff contract to any future external reviewer.

## Review Contract

### Deterministic Facts Owned by SourceAgent

These are not overridable by a reviewer:

- source reachability
- object binding
- channel traversal
- root matching
- chain existence

### Reviewer Scope

The reviewer only answers semantic questions such as:

- whether a check really constrains the active root
- whether the root remains attacker-controllable at the sink
- whether parser/helper semantics make the chain more like `SAFE_OR_LOW_RISK`, `SUSPICIOUS`, or `CONFIRMED`
- what trigger conditions are required

### Fail-Closed Rules

A review decision is accepted only if:

- the payload is structurally valid
- `evidence_map` is present for semantic promotion
- referenced snippet keys exist in the feature pack
- hard deterministic constraints are not violated
- the applicable review budget is not exhausted

`audit_only` never changes the deterministic verdict.

## Tests

### Code / Unit Tests

Executed after integration:

- `tests/test_review_integration.py`
- `tests/test_verdict_calibration.py`
- `tests/test_chain_artifacts.py`
- `tests/test_pipeline_orchestrator.py`
- `tests/test_microbench_gt_v2_eval.py`
- `tests/test_mesobench_v1.py`
- `tests/test_eval_harness.py`
- `tests/test_tunnel_linker.py`
- `tests/test_sink_roots.py`

Key results observed during development:

- focused regression: `62 passed`
- broader regression: `93 passed`
- current repo regression baseline remained green after commit

### Runtime Smoke: mixed GT + no-GT

Smoke run directory:

- `/tmp/eval_review_smoke_20260309_153033`

Samples:

- `cve_2018_16525_freertos_dns`
- `cve_2021_34259_usb_host`
- `t0_format_string`
- `contiki_cve_2020_12141_snmp_server`
- `zephyr_cve_2020_10065`
- `usbs_tcp_echo_client_vuln_bof_dhcp`

Observed review behavior:

- samples completed: `6`
- total queued chains: `40`
- `llm_reviewed`: `27`

This confirmed that the default review-on path works on:

- microbench
- large mesobench samples
- uSBS-style no-GT firmware

### Combined Run (partial but representative)

Run directory:

- `/tmp/eval_combined_review_20260309_154123`

This run was started with `56` samples:

- `44` GT-backed (`microbench + mesobench`)
- `12` extra unstripped no-GT samples (`p2im-unit_tests + pw-discovery + demo`)

The run was intentionally stopped after enough coverage had been collected. Completed samples at stop time:

- `24`

Completed coverage included:

- all `14` microbench samples
- `10` large mesobench samples, including Contiki, STM32/lwIP, and Zephyr prebuilt firmware

Partial combined stats over completed samples:

- chains: `473`
- chains with source: `259`
- chains with channel: `322`
- confirmed: `17`
- suspicious: `92`
- safe_or_low_risk: `82`
- dropped: `282`
- review queue items: `100`
- `llm_reviewed`: `67`

These numbers are not directly comparable to the finished GT-backed baseline because the 56-sample run was stopped mid-way, but they are sufficient to show that the default review-on path scales beyond microbench.

### Microbench Regression Under Default Review-On

Using the completed microbench subset in `/tmp/eval_combined_review_20260309_154123` and the canonical microbench GT:

- `positive_total = 18`
- `matched = 18`
- `missed = 0`
- `spurious_non_drop = 0`
- `must_use_channel_ok = 2/2`
- `negative_expectations = 20/20`

This is the key guardrail: default review-on did not regress the microbench chain baseline.

## Current Architectural Conclusion

SourceAgent should remain the only deterministic pre-flight owner.

BinAgent should not continue to run its own preflight / stage2 / stage3 as an authority whenever SourceAgent artifacts are available.

The useful parts of BinAgent are:

- review planning ideas
- review batching / budget control
- reviewer-oriented prompt / response structure
- decision normalization

Those are better re-implemented inside SourceAgent than maintained as a second execution pipeline.

## Practical Next Step

The next implementation step is not more structural recovery. It is reviewer refinement:

1. keep SourceAgent as the default execution surface
2. optionally accept external `review_decisions.json`
3. if needed, port more of the old BinAgent review shell into SourceAgent
4. do not revive duplicated deterministic recovery in a second repo

