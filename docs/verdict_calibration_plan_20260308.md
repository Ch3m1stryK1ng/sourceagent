# Verdict Calibration Plan

Date: 2026-03-08

## Goal

The chain layer is now structurally stable on the current GT-backed baseline:
- positive-chain hit rate: 100%
- spurious non-drop chains: 0
- channel-required chains: 253 / 253
- explicit negative expectations: 27 / 27

The remaining problem is **verdict calibration** rather than chain recovery.

That means the next stage should not re-decide:
- source reachability
- object binding
- channel traversal
- root matching

Those are already deterministic outputs from `SourceAgent`.

Instead, the next stage should calibrate the semantic verdict assigned to a chain that is already structurally valid:
- `SAFE_OR_LOW_RISK`
- `SUSPICIOUS`
- `CONFIRMED`

## Scope Split

### SourceAgent responsibilities (deterministic)

`SourceAgent` remains the sole owner of fact extraction:
- source labels
- sink labels
- object path
- channel path
- sink roots
- derive facts
- check facts
- structural chain assembly
- current deterministic verdict and reason code

### BinAgent / LLM responsibilities (semantic calibration)

`BinAgent` or an LLM-backed calibration stage may evaluate:
- whether a check actually constrains the active root
- whether the active root remains attacker-controllable at the sink
- whether parser/helper semantics make the chain closer to `SAFE_OR_LOW_RISK`, `SUSPICIOUS`, or `CONFIRMED`
- whether a state predicate is a real exploit barrier or only a weak gate

### What the LLM must not override directly

The LLM must not be the authority for:
- source reachability
- object binding
- channel existence or traversal
- root extraction correctness
- derive fact extraction

Those remain fail-closed deterministic steps.

## Deliverable A: Verdict Feature Pack

For every matched chain, `SourceAgent` should emit a stable JSON record.

Suggested filename pattern:
- `raw_views/<sample>.verdict_feature_pack.json`

Suggested top-level structure:

```json
{
  "schema_version": "0.1",
  "sample_id": "zephyr_cve_2020_10065",
  "eval_stem": "zephyr_cve_2020_10065",
  "chain_id": "chain_...",
  "current_verdict": "SUSPICIOUS",
  "current_verdict_reason": "WEAK_CHECK_OR_PARSER_SEMANTICS_UNKNOWN",
  "sink": {
    "label": "COPY_SINK",
    "function": "net_buf_add_mem",
    "site": "0x08001234"
  },
  "root": {
    "expr": "rxmsg[2] + 2",
    "canonical_expr": "rxmsg[2]+2",
    "family": "length",
    "source": "call_args",
    "role": "primary"
  },
  "object_path": [...],
  "channel_path": [...],
  "derive_facts": [...],
  "check_facts": [...],
  "evidence_refs": [...],
  "decompiled_snippets": {
    "sink_function": "...",
    "caller_bridge": "...",
    "producer_function": "..."
  },
  "deterministic_constraints": {
    "source_reached": true,
    "object_bound": true,
    "channel_required": true,
    "channel_satisfied": true,
    "root_bound": true
  }
}
```

## Deliverable B: LLM Input Filter

Only a bounded subset should go to `BinAgent` / LLM.

Default candidate classes:
- `verdict_under`
- `verdict_over`
- chains currently labeled `SUSPICIOUS`
- samples whose suspicious ratio exceeds a threshold

This boundary should be tunable.

Suggested CLI/config knobs:
- `--calibration-mode exact_mismatch|suspicious_only|all_non_exact`
- `--max-calibration-chains N`
- `--sample-suspicious-ratio-threshold F`
- `--allow-manual-llm-supervision`
- `--llm-promote-budget N`
- `--llm-demote-budget N`

Rationale:
- the user may want broader LLM review than only strict exact mismatches
- verifier runtime is not the main bottleneck
- manual supervision should be allowed when deterministic boundaries are respected

## Deliverable C: LLM Question Contract

The LLM should answer only bounded semantic questions.

Allowed questions:
1. Does the extracted check actually constrain the active root at the sink?
2. Does the active root remain attacker-controllable at the sink site?
3. Under the parser/helper semantics visible in the snippets, should this chain be treated as:
   - `SAFE_OR_LOW_RISK`
   - `SUSPICIOUS`
   - `CONFIRMED`
4. Is a state predicate a real safety barrier, a weak gate, or unrelated to the sink root?

Disallowed questions:
- Did the source really reach the sink?
- Is this the correct object binding?
- Is the channel path real?
- Is the chosen root the correct root?

## Deliverable D: Manual Supervision Path

The user requested a supervised override path. That is reasonable as long as it does not bypass deterministic facts.

Suggested flow:
1. `SourceAgent` emits the verdict feature pack.
2. The pack enters a `calibration_queue.json`.
3. The user or `BinAgent` explicitly selects a chain for semantic review.
4. The LLM returns a calibrated verdict suggestion plus rationale.
5. A deterministic verifier checks that the suggestion does not violate hard constraints.
6. The final output stores:
   - original deterministic verdict
   - LLM-suggested verdict
   - final accepted verdict
   - acceptance reason

This preserves auditability.

## Fail-Closed Policy

Any calibration stage must fail closed.

That means:
- if the LLM response is malformed, keep the deterministic verdict
- if the LLM suggestion conflicts with deterministic constraints, reject it
- if required evidence snippets are missing, do not promote
- if the suggestion tries to upgrade a chain whose structural status is not valid, reject it

## Proposed Output Artifacts

New files to add in a future implementation:
- `raw_views/<sample>.verdict_feature_pack.json`
- `summary/verdict_calibration_queue.json`
- `summary/verdict_calibration_decisions.json`
- `summary/verdict_calibration_report.md`

## Suggested Implementation Order

1. Emit deterministic verdict feature packs from `SourceAgent`.
2. Add queue selection with tunable boundaries.
3. Add a local `BinAgent`/LLM adapter that reads only the feature packs.
4. Add fail-closed post-checks.
5. Compare:
   - exact verdict before calibration
   - exact verdict after calibration
   - any over-promotion regressions

## Success Criteria

A calibration stage is useful only if it improves verdict quality without weakening structural guarantees.

Minimum success criteria:
- structural chain metrics remain unchanged
- no new spurious non-drop chains are introduced
- no channel-required failures are introduced
- `verdict_under` decreases materially
- `verdict_over` does not increase
