# BinAgent-Compatible Review Contract on Top of SourceAgent (2026-03-09)

## Goal

Reuse the useful semantic-review behavior historically explored in BinAgent without preserving duplicated deterministic recovery stages.

## Default Execution Model

SourceAgent is now the default execution surface:

1. stages 1-10 run deterministically
2. SourceAgent emits review artifacts
3. SourceAgent runs internal review by default unless `--disable-review` is set
4. external review decisions are optional overrides supplied via `--verdict-review-json`

That means an external reviewer is no longer the primary path. It is a compatibility and experimentation path.

## SourceAgent Input to a Reviewer

Per sample, a reviewer consumes:

- `raw_views/<sample>.verdict_feature_pack.json`
- `raw_views/<sample>.verdict_calibration_queue.json`
- optional:
  - `raw_views/<sample>.chains.json`
  - `raw_views/<sample>.chain_eval.json`
  - `raw_views/<sample>.channel_graph.json`
  - `raw_views/<sample>.sink_roots.json`
  - `raw_views/<sample>.verdict_soft_triage.json`
  - `raw_views/<sample>.verdict_audit_flags.json`

## Minimum Required Fields Per Queued Chain

For each queued chain, SourceAgent exposes:

- `chain_id`
- `sample_id`
- `current_verdict`
- `sink`
- `root`
- `derive_facts`
- `check_facts`
- `object_path`
- `channel_path`
- `decision_basis`
- `decompiled_snippets`
- `deterministic_constraints`
- `review_reason`
- `sink_semantics_hints`
- `guard_context`
- `capacity_evidence`

## Review Decision Output

A compatible reviewer writes one JSON file per run:

- `review_decisions.json`

Each decision item should include:

- `sample_id`
- `chain_id`
- `mode`: `semantic_review` or `audit_only`
- `suggested_semantic_verdict`
- `confidence`
- `trigger_summary`
- `preconditions`
- `why_check_fails`
- `evidence_map`
- `audit_flags`
- `needs_more_context`

## Strict Rules

A reviewer is not allowed to override deterministic facts:

- source reachability
- object binding
- channel traversal
- root matching
- chain existence

If a reviewer believes any of those are wrong, it must emit an audit flag instead of rewriting them.

## Audit Flags

Allowed audit flags include:

- `root_mismatch`
- `sink_arg_mismatch`
- `check_not_binding_root`
- `channel_inconsistency`
- `control_only_path`
- `needs_more_context`

## Application Path

1. SourceAgent runs stages 1-10.
2. SourceAgent writes feature pack and calibration queue.
3. SourceAgent optionally runs internal review.
4. SourceAgent optionally merges external review decisions.
5. SourceAgent applies decisions via fail-closed post-check.
6. SourceAgent emits final strict / soft / dual verdict outputs.

## What To Remove From BinAgent

The following deterministic functionality should not remain active in the long-term path when SourceAgent artifacts are available:

- preflight sink/source prioritisation as authority
- stage2 callsite expansion as authority
- stage3 deterministic verdicting as authority

Those can remain temporarily for compatibility testing, but should be bypassed whenever SourceAgent artifacts exist.

## Recommended Compatibility Mode

If BinAgent remains in use during transition, add a mode equivalent to:

- `--input-sourceagent-review-queue <dir>`

Behavior:

- load SourceAgent queue and feature packs
- create review plan only from queued chains
- skip BinAgent preflight / stage2 / stage3 deterministic reconstruction
- emit `review_decisions.json`

This keeps BinAgent useful while avoiding duplicated recovery logic.
