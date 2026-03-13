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
- whether a chain candidate is statically triggerable under some input/state sketch
- whether a pipeline artifact bundle contains an internal inconsistency that should raise an audit flag

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
  "sink_semantics_hints": {
    "dst_expr": "buf",
    "src_expr": "&rxmsg[1]",
    "len_expr": "rxmsg[2] + 2",
    "dst_capacity_candidates": ["sizeof(buf)", "NET_BUF_AVAILABLE(buf)"]
  },
  "guard_context": [
    {"expr": "payload_len < max_len", "site": "caller_bridge", "dominance": "unknown"}
  ],
  "capacity_evidence": [
    {"expr": "sizeof(buf)", "site": "sink_function", "kind": "local_array_size"}
  ],
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

Additional deterministic requirements:
- `sink_semantics_hints` must be emitted when the sink class supports them.
- `guard_context` should include nearby syntactic guards even when dominance is not yet proven.
- `capacity_evidence` should include any deterministic capacity candidate that might matter for exploitability.
- the pack should preserve the current deterministic verdict and the reason code that produced it.

## Deliverable B: LLM Input Filter

Only a bounded subset should go to `BinAgent` / LLM.

Default candidate classes:
- `verdict_under`
- `verdict_over`
- chains currently labeled `SUSPICIOUS`
- samples whose suspicious ratio exceeds a threshold
- optionally, all structurally valid matched chains if the user explicitly wants broader semantic review

This boundary should be tunable.

Suggested CLI/config knobs:
- `--calibration-mode exact_mismatch|suspicious_only|all_non_exact|audit_only|all_matched`
- `--max-calibration-chains N`
- `--sample-suspicious-ratio-threshold F`
- `--allow-manual-llm-supervision`
- `--llm-promote-budget N`
- `--llm-demote-budget N`
- `--llm-soft-budget N`
- `--min-risk-score F`
- `--review-needs-threshold F`
- `--verdict-output-mode strict|soft|dual`

Rationale:
- the user may want broader LLM review than only strict exact mismatches
- verifier runtime is not the main bottleneck
- manual supervision should be allowed when deterministic boundaries are respected
- the system should support a softer review boundary when the goal is to produce richer auditable material for `BinAgent`

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

## Deliverable D: Trigger Sketch Contract

The LLM should not only return a verdict suggestion. It should also summarize the static trigger logic in a bounded, auditable format.

Suggested output shape:

```json
{
  "suggested_semantic_verdict": "SUSPICIOUS",
  "confidence": 0.74,
  "trigger_summary": "The attacker controls payload_len through rxmsg[2], the sink copies payload_len bytes into buf, and the visible guard does not constrain payload_len at the callsite.",
  "preconditions": {
    "state_predicates": ["rx_ready != 0"],
    "root_constraints": ["payload_len > dst_capacity"],
    "why_check_fails": ["visible check compares msg_type, not payload_len"]
  },
  "audit_flags": [],
  "evidence_map": {
    "trigger_summary": ["sink_function", "caller_bridge"],
    "root_constraints": ["sink_function"],
    "why_check_fails": ["caller_bridge"]
  }
}
```

Mandatory rule:
- no semantic conclusion may be accepted without an `evidence_map`.
- missing `evidence_map` means fail-closed and keep the deterministic verdict.

## Deliverable E: Manual Supervision Path

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

Recommended addition:
- store whether the review was automatic or manually supervised
- store the exact calibration mode and threshold values used for the decision

## Deliverable F: Audit-Only Mode

`BinAgent` should also support an audit-only path.

Goal:
- inspect pipeline artifacts
- flag inconsistencies
- request more context
- do not change the verdict

Typical audit flags:
- `root_mismatch`
- `sink_arg_mismatch`
- `check_not_binding_root`
- `channel_inconsistency`
- `needs_more_context`

This is the right place to let the LLM act as the "supervisor" you described without letting it replace deterministic fact extraction.

## Verdict Representation

Keep the existing three verdict classes:
- `SAFE_OR_LOW_RISK`
- `SUSPICIOUS`
- `CONFIRMED`

Do not expand the core class set.

Instead, make the output softer by adding side-band fields:
- `risk_score`
- `confidence`
- `reasons[]`
- `needs_review`
- `llm_reviewed`
- `audit_flags[]`

Recommended extension for the current implementation:
- keep the core verdict classes unchanged
- add a final risk layer alongside the verdict:
  - `final_risk_score`
  - `final_risk_band`
  - `final_confidence`
  - `review_priority`
  - `trigger_summary`
  - `reason_codes`

This preserves evaluator compatibility while giving downstream review systems a better sorting signal.

Recommended policy:
- `strict` output remains the canonical evaluator-facing verdict.
- `soft` output carries richer review material for `BinAgent`.
- `dual` writes both forms side by side.

## Risk-Layer Reporting

The calibrated risk layer should not stay buried inside per-chain JSON. It should be surfaced in both per-binary and suite-level summaries.

### Per-binary summary

Each binary summary should expose:
- `final_verdict` distribution
- `final_risk_band` distribution
- `review_priority` distribution
- top risky chains
- top blockers
- top reason codes
- reviewer coverage
- `semantic_only_applied` count

Suggested outputs:
- `summary/verdict_risk_summary.json`
- `summary/verdict_risk_summary.md`

### Suite-level report

The suite report should add:
- `High-Risk Suspicious Chains`
- `Confirmed but Medium-Risk Chains`
- `P0 review targets`
- `Top reason codes across corpus`

This is the layer that answers:
- which chains are structurally matched but still worth escalation
- which suspicious chains are the highest-value follow-up targets

## Review Priority Semantics

`P0/P1/P2` are review-priority labels, not pipeline stages.

- `P0`
  - highest-value follow-up
  - typically `SUSPICIOUS + HIGH`, `CONFIRMED + HIGH`, or semantic-only chains blocked by a single structural gap
- `P1`
  - medium/high value follow-up
  - typically `SUSPICIOUS + MEDIUM`
- `P2`
  - lower urgency
  - typically `SAFE_OR_LOW_RISK + LOW`, or chains that remain structurally weak after review

### What "deeper review" means

Deeper review does not mean rebuilding the chain. It means spending more semantic budget on an already assembled chain:
- more capacity/context evidence
- helper body inspection
- second-pass tool-assisted review
- focused questions such as:
  - does the visible check truly bind the active root?
  - is the target object extent sufficient to rule out overflow?
  - is taint preserved, weakened, or cleansed at a specific hop?
  - why is the chain still only `SUSPICIOUS`?

### What "manual review" means

Manual review should focus on the minimum high-value set. A reviewer should inspect:
- `verdict_soft_triage.json`
- `verdict_calibration_decisions.json`
- `verdict_review_session.json`

The purpose is to decide:
- whether a chain deserves stronger escalation
- whether the reviewer was too conservative
- whether the reviewer was too aggressive

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
- `summary/verdict_audit_flags.json`
- `summary/verdict_soft_triage.json`

## Suggested Implementation Order

1. Emit deterministic verdict feature packs from `SourceAgent`.
2. Add queue selection with tunable boundaries and output modes.
3. Add trigger-sketch JSON output for the LLM path.
4. Add a local `BinAgent`/LLM adapter that reads only the feature packs.
5. Add fail-closed post-checks.
6. Add audit-only mode.
7. Compare:
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
- every accepted LLM-driven promotion includes evidence-backed trigger conditions
