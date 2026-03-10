# Semantic Reviewer Framework (2026-03-09)

## 1. Two-Phase Model

### Phase A: Deterministic Chain Assembly
SourceAgent owns all deterministic recovery and fail-closed structural facts.

Outputs of Phase A are authoritative:
- binary + memory map
- source candidates / sink candidates
- evidence packs
- proposals / verified labels
- channel graph / refined objects
- sink roots
- chains / chain eval
- low-conf sinks / triage queue
- verdict feature pack / calibration queue / audit flags / soft triage

### Phase B: Semantic Review and Trigger Validation
The reviewer consumes Phase A outputs as prior facts and uses the binary + decompiler to assess whether a structurally valid chain is semantically triggerable.

The reviewer must not re-decide:
- source reachability
- object binding
- channel traversal
- root matching

The reviewer is allowed to judge:
- whether checks truly bind the active root
- whether taint is semantically preserved or cleansed across hops
- whether helper/parser logic still leaves the sink triggerable
- what input/state preconditions are required to trigger the chain
- whether the chain is closer to SAFE_OR_LOW_RISK / SUSPICIOUS / CONFIRMED

## 2. Phase A Artifact Inventory

### Core mining artifacts
- `candidate.json`
- `proposal.json`
- `verified.json`
- `phase_a_artifacts.json`

### Structural chain artifacts
- `channel_graph.json`
- `refined_objects.json`
- `sink_roots.json`
- `chains.json`
- `chain_eval.json`
- `low_conf_sinks.json`
- `triage_queue.json`

### Verdict calibration artifacts
- `verdict_feature_pack.json`
- `verdict_calibration_queue.json`
- `verdict_calibration_decisions.json`
- `verdict_audit_flags.json`
- `verdict_soft_triage.json`

### Review logging artifacts
- `verdict_review_plan.json`
- `verdict_review_prompt.json`
- `verdict_review_raw_response.json`
- `verdict_review_session.json`
- `verdict_review_trace.json`

## 3. Reviewer Input Contract

The reviewer should receive:
- the binary path / binary sha256
- the selected chain candidates from `verdict_calibration_queue.json`
- the matching items from `verdict_feature_pack.json`
- the full `chains.json` entry for each selected chain
- the binary itself as decompiler target
- deterministic snippets from `decompiled_snippets`
- optional supporting context from:
  - `channel_graph.json`
  - `refined_objects.json`
  - `sink_roots.json`
  - `verified.json`

## 4. Reviewer Work Model

### B0. Session bootstrap
- load Phase A prior facts
- select chains from review queue
- materialize prompt/session metadata

### B1. Bidirectional chain walk
For each chain, walk both directions:
- forward: source -> object -> channel -> derive/check -> sink
- backward: sink/root -> check -> derive -> object/channel -> source

### B2. Per-hop semantic audit
At each hop, the reviewer must assess one of:
- taint preserved
- taint weakened
- taint cleansed
- taint unknown

Targets:
- source -> object
- object -> channel
- channel -> consumer
- derive -> active root
- check -> active root binding
- sink -> triggerability

### B3. Branch and helper handling
The reviewer should inspect:
- parser branches
- helper-returned lengths
- branch-local checks
- loop bounds
- copied/aliased root expressions

The goal is to decide whether the chain survives realistic branch/helper semantics.

### B4. Trigger synthesis
The reviewer must output:
- trigger summary
- state predicates
- root constraints
- why-check-fails summary
- evidence map back to deterministic snippets / reviewed functions

### B5. Verdict suggestion
The reviewer suggests:
- `SAFE_OR_LOW_RISK`
- `SUSPICIOUS`
- `CONFIRMED`

SourceAgent then applies the suggestion through fail-closed post-check.

## 5. Required Reasoning Fields for Future Prompt Contract

The semantic reviewer should return structured assessments for:
- `source_to_object`
- `object_to_channel`
- `channel_to_sink`
- `check_binding`
- `triggerability`

Each should include:
- `status`
- `reason_codes`
- `summary`
- `evidence_map`

## 6. Planned Follow-up After P0

### P1. Strengthen reviewer prompt/schema
- require per-hop semantic assessment
- require explicit triggerability reasoning
- require branch/helper analysis when relevant

### P2. Typed semantic reason codes
Add reviewer-visible codes for:
- taint preservation/cleansing
- root controllability
- check effectiveness
- parser/helper uncertainty
- triggerability classes

### P3. Split strict vs soft acceptance gates
- strict gates remain structural and hard
- soft gates allow semantic rationale to survive even when strict promotion is blocked
- rejected reviews must still preserve rationale and preconditions

### P4. Preserve rejected semantic reviews
When a review suggestion is rejected by fail-closed checks, SourceAgent should still keep:
- suggested verdict
- trigger summary
- preconditions
- semantic reason codes
- evidence map

The rejection should only block application, not erase the semantic review.

## 7. Detailed P1 Plan: Reviewer Schema v0.2

### Goal
Upgrade the reviewer from "single verdict with short rationale" to "segment-aware semantic audit".

### Input additions from Phase A
Each `verdict_feature_pack` item should carry a deterministic `chain_segments` array. The reviewer does not invent hops; it only evaluates the hops that Phase A already assembled.

Recommended segment kinds:
- `source_to_object`
- `source_to_sink`
- `object_to_channel`
- `channel_to_sink`
- `derive_to_root`
- `check_binding`
- `sink_triggerability`

Each segment should contain:
- `segment_id`
- `kind`
- `src`
- `dst`
- `facts`
- `snippet_keys`

### Reviewer output v0.2
Every review decision should include:
- `chain_id`
- `suggested_semantic_verdict`
- `trigger_summary`
- `preconditions`
- `segment_assessment[]`
- `reason_codes[]`
- `review_quality_flags[]`
- `evidence_map`
- `audit_flags[]`
- `confidence`
- `review_mode`

Each `segment_assessment` entry should include:
- `segment_id`
- `status`
- `reason_codes[]`
- `summary`
- `evidence_map`

### Reviewer prompt requirements
The prompt must explicitly require the model to:
- review the chain in both directions
- inspect every segment
- decide whether taint is preserved / weakened / cleansed / unknown
- decide whether each visible check actually constrains the active root
- use only provided snippet keys as evidence
- return `unknown` rather than inventing facts

### Optional tool-assisted review mode
The long-term reviewer should support two backends:
- `prompt_only`: only use the pre-exported snippets
- `tool_assisted`: allow guided decompiler inspection of functions already named by the chain

`tool_assisted` is still constrained. It may inspect:
- `sink_function`
- `caller_bridge`
- `producer_function`
- functions named in `chain_segments`

It must not rediscover new sources/sinks or run a second preflight.

## 8. Detailed P2 Plan: Typed Semantic Reason Codes

### Goal
Make reviewer output measurable and aggregatable instead of free-form.

### Reason code families
#### Taint propagation
- `TAINT_PRESERVED_DIRECT_ASSIGN`
- `TAINT_PRESERVED_COPY_FROM_IO`
- `TAINT_PRESERVED_LOOP_COPY`
- `TAINT_WEAKENED_MASKED_OR_CLAMPED`
- `TAINT_CLEANSED_CONST_ASSIGN`
- `TAINT_UNKNOWN_ALIASING`

#### Root controllability
- `ROOT_FROM_MMIO_OR_DMA`
- `ROOT_FROM_ISR_BUFFER`
- `ROOT_DERIVED_ARITHMETIC`
- `ROOT_DEPENDS_ON_HELPER_RETURN`
- `ROOT_SECONDARY_ONLY`
- `ROOT_NOT_CAPACITY_RELEVANT`

#### Check effectiveness
- `CHECK_DOMINATES_SINK`
- `CHECK_NON_DOMINATING`
- `CHECK_WRONG_VARIABLE`
- `CHECK_NOT_BINDING_ROOT`
- `CHECK_ONLY_STATE_GATE`
- `CHECK_INCOMPLETE_UPPER_BOUND`

#### Parser/helper semantics
- `PARSER_BRANCH_CONDITION_TAINTED`
- `PARSER_DESCRIPTOR_WALK_UNBOUNDED`
- `PARSER_LENGTH_FIELD_TRUSTED`
- `HELPER_SEMANTICS_UNKNOWN`
- `HELPER_RETURNS_ROOT_EQUIVALENT`

#### Triggerability
- `TRIGGERABLE_WITH_SIMPLE_CONSTRAINTS`
- `TRIGGERABLE_LEN_GT_CAPACITY`
- `TRIGGERABLE_INDEX_OOB`
- `TRIGGERABLE_FORMAT_CONTROLLED`
- `TRIGGER_UNCERTAIN_MISSING_CAPACITY`
- `LIKELY_SAFE_BOUND_PRESENT`

### Why this matters
Reason codes are not only for logs. They should feed:
- `verdict_review_session.json`
- `verdict_calibration_decisions.json`
- future review summary reports
- reason-code distribution statistics for tuning deterministic extractors

## 9. Detailed P3 Plan: Strict vs Soft Gates

### Goal
Decouple "LLM semantic opinion" from "strict verdict change".

### Strict gates
A review suggestion may change the strict verdict only if:
- `source_reached = true`
- `root_bound = true`
- `object_bound = true`
- if `channel_required`, then `channel_satisfied = true`
- `evidence_map` references only valid snippet keys
- no hard-block reason code is triggered

### Soft gates
Even if strict promotion is blocked, the system should still preserve semantic review output. In `soft` or `dual` output modes, a decision may remain:
- `accepted = false`
- `strict_verdict` unchanged
- `soft_verdict` preserved as semantic-only commentary
- `accept_reason = STRUCTURAL_CONSTRAINT_NOT_MET`
- `soft_accept_state = semantic_only_not_applied`

### Recommended parameters
Potential CLI knobs:
- `--review-strict-gates source_reached,root_bound,object_bound`
- `--review-soft-gates source_reached,root_bound`
- `--review-allow-soft-on-structural-gap`
- `--review-preserve-rejected-rationale`
- `--review-tool-mode off|prompt_only|tool_assisted`

## 10. Detailed P4 Plan: Preserve Rejected Semantic Rationale

### Goal
Never lose useful semantic review output just because fail-closed gates blocked application.

### Required behavior
Whether or not a review is accepted, the final decision ledger should preserve:
- `suggested_semantic_verdict`
- `trigger_summary`
- `preconditions`
- `segment_assessment`
- `reason_codes`
- `review_quality_flags`
- `evidence_map`
- `confidence`
- `review_mode`

The only thing rejection should change is application state:
- `accepted`
- `accept_reason`
- `strict_verdict_changed`
- `soft_verdict_changed`
- optional `reject_reason_codes`

### Expected effect on difficult cases
For cases such as `cve_2021_34259_usb_host`, even if strict gates keep the final verdict at `SUSPICIOUS`, the artifacts should still show:
- why the parser path looks triggerable
- which checks are weak or non-binding
- which structural gaps blocked a stricter verdict

## 11. Recommended Implementation Order

Implement in this order:
1. `P1`: schema/prompt v0.2
2. `P4`: preserve rejected rationale
3. `P2`: typed reason codes
4. `P3`: strict/soft gate split

Rationale:
- first make the reviewer explain each hop
- then guarantee the explanation is never lost
- then normalize the explanation into typed codes
- finally refine the application policy

## 12. Acceptance Criteria

### P1
- reviewer output includes `segment_assessment`
- each segment has `status`, `reason_codes`, `summary`, `evidence_map`
- prompt forces bidirectional hop review

### P2
- reason codes are centrally defined and validated
- review artifacts can be aggregated by reason code

### P3
- strict and soft verdict paths are distinct
- semantic-only review survives structural gaps in dual output

### P4
- rejected decisions still preserve full semantic rationale
- no rejected review should lose `trigger_summary` / `preconditions` / `segment_assessment`
