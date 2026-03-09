# SourceAgent / BinAgent Integration Recommendation (2026-03-09)

## Scope

This note answers two practical questions:

1. What information should SourceAgent expose to a semantic reviewer before any LLM review?
2. Should BinAgent's existing preflight / stage2 / stage3 logic be ported into SourceAgent, or should SourceAgent become the single execution surface?

The answer below is based on the current code in both repos and on the current SourceAgent default review-on path.

## Current State

SourceAgent already produces the deterministic pre-flight materials needed for semantic review:

- verified source/sink labels
- evidence packs
- refined objects
- channel graph
- sink roots
- chains
- chain evaluation
- verdict feature pack
- verdict calibration queue
- verdict soft triage
- verdict audit flags
- internal review plan / review trace

In other words, SourceAgent already owns the deterministic facts and now also owns the default review execution path.

BinAgent still contains its own deterministic pipeline:

- `pentestagent/agents/preflight.py`
- `pentestagent/agents/stage2.py`
- `pentestagent/agents/general_agent.py` stage3 flow

This is duplicated recovery logic if used in parallel with SourceAgent.

## Concrete Overlap

### BinAgent Preflight

`/home/a347908610/binagent/pentestagent/agents/preflight.py`

What it builds:

- `SOURCE_HINTS`
- `HOT_REGIONS`
- `SINK_CALLSITES_QUEUE`
- sink taxonomy with tracked argument templates
- ranked sink callsite queue

This overlaps with SourceAgent's:

- verified sink labels
- sink roots
- low-confidence queue / triage queue
- verdict calibration queue
- verdict feature pack

### BinAgent Stage 2

`/home/a347908610/binagent/pentestagent/agents/stage2.py`

What it builds:

- caller decompilation
- tracked bindings
- tracked symbols
- slice closure
- evidence pack
- context expansion per callsite

This overlaps with SourceAgent's:

- sink root extraction
- caller bridge / transitive caller bridge
- derive/check extraction
- object / channel path recovery
- verdict feature pack snippets and evidence refs

### BinAgent Stage 3

`/home/a347908610/binagent/pentestagent/agents/general_agent.py`

What it builds:

- evidence-chain based classification
- `confirmed / suspicious / dropped`
- stage3 findings, dropped findings, clusters, summaries
- review plan for suspicious findings

This overlaps with SourceAgent's:

- chain verdicts
- `SAFE_OR_LOW_RISK / SUSPICIOUS / CONFIRMED / DROP`
- chain evaluation
- verdict calibration queue
- verdict soft triage
- verdict audit flags

## Recommendation

### Short Version

Do **not** keep two deterministic pipelines.

Use this split:

- SourceAgent = single execution surface, deterministic pre-flight owner, and default review runner
- external reviewer (LLM / BinAgent-compatible implementation) = optional semantic reviewer only

### Why

If two repos both recover roots, closures, evidence packs, and verdicts independently, three problems appear:

1. duplicated engineering effort
2. inconsistent facts across repos
3. unclear ownership when review disagrees with the structural chain

A single deterministic owner is cleaner and easier to debug.

SourceAgent is already the stronger candidate because it owns:

- firmware-oriented source detection
- channel graph
- cross-context tunnel linking
- microbench / mesobench GT-backed evaluation
- deterministic verdict feature pack
- default review-on orchestration

## Recommended Architecture

### SourceAgent Responsibilities

SourceAgent should remain responsible for all deterministic facts:

- source reachability
- object binding
- channel traversal
- sink detection
- root matching
- derive/check extraction
- deterministic verdict basis
- queue building for semantic review
- default in-process review planning / batching / result application

### Semantic Review Responsibilities

The semantic reviewer should only operate on a narrowed candidate set:

- review non-exact verdicts
- review suspicious-heavy samples
- review parser/helper semantics
- explain why a guard is or is not effective
- produce trigger sketches
- produce audit flags against deterministic artifacts

### Artifacts to Pass to a Semantic Reviewer

Per sample, the reviewer should consume:

- `*.verdict_feature_pack.json`
- `*.verdict_calibration_queue.json`
- optional:
  - `*.chains.json`
  - `*.chain_eval.json`
  - `*.channel_graph.json`
  - `*.sink_roots.json`
  - `*.verdict_soft_triage.json`
  - `*.verdict_audit_flags.json`

Minimum required input for review should be:

- `verdict_feature_pack.json`
- `verdict_calibration_queue.json`

Everything else is optional context.

## Migration Options

### Option A: Keep an External Reviewer Adapter

This is the compatibility path, not the preferred end-state.

Implementation:

- keep SourceAgent deterministic pipeline and default internal review-on behavior as-is
- add an external adapter that reads SourceAgent review queue
- run semantic review only on queued chains
- emit `review_decisions.json`
- feed that decision file back into SourceAgent fail-closed post-check via `--verdict-review-json`

Pros:

- smallest code churn
- preserves existing BinAgent prompt / orchestration experiments
- useful for A/B testing reviewer prompts

Cons:

- two repos remain active
- schema coordination is still needed

### Option B: Rebuild the Useful BinAgent Review Shell Inside SourceAgent

This is the recommended end-state.

Implementation:

- keep SourceAgent artifacts as single source of truth
- keep review enabled by default in `eval` / `mine`
- move only the useful LLM review planning / execution scaffolding in-process
- do **not** port BinAgent preflight / stage2 / stage3 deterministic logic

Pros:

- one repo
- one authority for facts
- one CLI path (`eval` / `mine`) for deterministic + review output
- easier end-to-end evaluation

Cons:

- more immediate refactoring work
- review workflow and prompts must be revalidated inside SourceAgent

## What To Reuse From BinAgent

The part worth reusing from BinAgent is not its deterministic recovery code, but its review orchestration logic.

Good reuse candidates:

- suspicious-finding review planning around `general_agent._create_s3_review_plan(...)`
- review loop budgeting and batching
- LLM-facing prompt / response plumbing for reviewer mode
- final review decision persistence (`review_decisions.json` style output)

Poor reuse candidates:

- `preflight.py` sink/source ranking as an authority
- `stage2.py` callsite extraction / closure building as an authority
- `run_stage3(...)` deterministic verdicting as an authority

In practice, BinAgent should be treated as a source of reusable review ideas and prompt structure, not as a second analysis authority.

## Recommended Sequence

### Phase 1

Keep the current SourceAgent review-on path as the default execution surface.

Stabilize:

1. `verdict_feature_pack.json`
2. `verdict_calibration_queue.json`
3. internal review planning / batching
4. fail-closed decision application

### Phase 2

If an external reviewer is still useful, keep it as an optional adapter that only consumes SourceAgent artifacts and only emits `review_decisions.json`.

### Phase 3

When prompt / decision schemas stop changing, retire BinAgent as an execution dependency and keep only prompt assets or review experiments that still provide value.
