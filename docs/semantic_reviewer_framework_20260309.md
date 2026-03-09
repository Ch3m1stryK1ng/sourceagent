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
