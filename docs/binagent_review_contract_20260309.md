# BinAgent Review Contract on Top of SourceAgent (2026-03-09)

## Goal

Reuse BinAgent for semantic review without preserving duplicated deterministic recovery stages.

## Proposed Contract

### SourceAgent Input to BinAgent

Per sample, BinAgent receives:

- `raw_views/<sample>.verdict_feature_pack.json`
- `raw_views/<sample>.verdict_calibration_queue.json`
- optional:
  - `raw_views/<sample>.chains.json`
  - `raw_views/<sample>.chain_eval.json`
  - `raw_views/<sample>.channel_graph.json`
  - `raw_views/<sample>.sink_roots.json`

### Minimum Required Fields From SourceAgent

For each queued chain, SourceAgent must expose:

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

## BinAgent Output

BinAgent should write one JSON file per run:

- `review_decisions.json`

Each decision entry should include:

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

BinAgent is not allowed to override deterministic facts:

- source reachability
- object binding
- channel traversal
- root matching
- chain existence

If BinAgent believes any of those are wrong, it must emit an audit flag instead of rewriting them.

## Audit Flags

Allowed audit flags:

- `root_mismatch`
- `sink_arg_mismatch`
- `check_not_binding_root`
- `channel_inconsistency`
- `control_only_path`
- `needs_more_context`

## Application Path

1. SourceAgent runs stages 1-10.
2. SourceAgent writes feature pack and calibration queue.
3. BinAgent reviews queued chains only.
4. SourceAgent post-checks the review decisions.
5. SourceAgent emits final strict/soft/dual verdict outputs.

## What To Remove From BinAgent

The following deterministic functionality should not remain active in the long-term path when SourceAgent artifacts are available:

- preflight sink/source prioritisation as authority
- stage2 callsite expansion as authority
- stage3 deterministic verdicting as authority

Those can remain temporarily for compatibility testing, but should be bypassed in the SourceAgent-backed path.

## Recommended Near-Term Implementation

Add a new BinAgent mode:

- `--input-sourceagent-review-queue <dir>`

Behavior:

- load SourceAgent queue and feature packs
- create review plan only from queued chains
- skip BinAgent preflight/stage2/stage3 deterministic reconstruction
- emit `review_decisions.json`

This keeps BinAgent useful while avoiding duplicated recovery logic.
