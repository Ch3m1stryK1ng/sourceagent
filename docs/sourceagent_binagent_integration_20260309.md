# SourceAgent / BinAgent Integration Recommendation (2026-03-09)

## Scope

This note answers two practical questions:

1. What information should SourceAgent pass to BinAgent before any LLM review?
2. Should BinAgent's existing preflight / stage2 / stage3 logic be ported into SourceAgent, or should BinAgent consume SourceAgent artifacts instead?

The answer below is based on the current code in both repos, not on older planning notes.

## Current State

SourceAgent now already produces the deterministic pre-flight materials that BinAgent needs:

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

In other words, SourceAgent already owns the deterministic facts.

BinAgent still contains its own deterministic pipeline:

- `pentestagent/agents/preflight.py`
- `pentestagent/agents/stage2.py`
- `pentestagent/agents/general_agent.py` stage3 flow

This creates overlap.

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

- SourceAgent = single deterministic pre-flight and structural recovery engine
- BinAgent = semantic reviewer / auditor / verdict calibrator

### Why

If both repos continue to recover roots, closures, evidence packs, and verdicts independently, three problems appear:

1. duplicated engineering effort
2. inconsistent facts across repos
3. unclear ownership when a review disagrees with a structural chain

A single deterministic owner is cleaner and easier to debug.

SourceAgent is already the stronger candidate because it owns:

- firmware-oriented source detection
- channel graph
- cross-context tunnel linking
- microbench / mesobench GT-backed evaluation
- deterministic verdict feature pack

BinAgent should stop re-deriving those facts.

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

### BinAgent Responsibilities

BinAgent should only perform semantic review on a narrowed candidate set:

- review non-exact verdicts
- review suspicious-heavy samples
- review parser/helper semantics
- explain why a guard is or is not effective
- produce trigger sketches
- produce audit flags against deterministic artifacts

### Artifacts to Pass from SourceAgent to BinAgent

Per sample, BinAgent should consume:

- `*.pipeline.json`
- `*.channel_graph.json`
- `*.sink_roots.json`
- `*.chains.json`
- `*.chain_eval.json`
- `*.verdict_feature_pack.json`
- `*.verdict_calibration_queue.json`
- `*.verdict_soft_triage.json`
- `*.verdict_audit_flags.json`

Minimum required input for BinAgent review should be:

- `verdict_feature_pack.json`
- `verdict_calibration_queue.json`

Everything else is optional context.

## Migration Options

### Option A: Keep BinAgent As Semantic Review-Only Layer

This is the recommended near-term plan.

Implementation:

- leave SourceAgent deterministic pipeline as-is
- add a BinAgent adapter that reads SourceAgent review queue
- run LLM review only on queued chains
- emit `review_decisions.json`
- feed that decision file back into SourceAgent fail-closed post-check

Pros:

- smallest code churn
- preserves existing BinAgent LLM orchestration patterns
- avoids deterministic duplication
- easiest to test incrementally

Cons:

- two repos remain active
- some artifact schema coordination is still needed

### Option B: Port BinAgent Review Logic Into SourceAgent

This is reasonable only after the review loop stabilizes.

Implementation:

- move only LLM review planning / execution scaffolding
- do **not** port BinAgent preflight / stage2 / stage3 deterministic logic
- keep SourceAgent artifacts as single source of truth

Pros:

- one repo
- simpler operational story
- easier end-to-end evaluation

Cons:

- more immediate refactoring work
- review workflow and prompts will need revalidation

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

In practice, BinAgent should keep the orchestration shell and drop the duplicated recovery core whenever SourceAgent artifacts are present.

## Recommended Sequence

### Phase 1

Keep BinAgent external.

Build a SourceAgent -> BinAgent review adapter:

1. SourceAgent writes deterministic review queue
2. BinAgent reads queue and feature packs
3. BinAgent writes semantic review decisions
4. SourceAgent applies those decisions via fail-closed post-check

### Phase 2

After the adapter is stable and the review contract stops changing, consider collapsing the review loop into SourceAgent.

## What Should Not Move Into BinAgent

BinAgent should not become the authority for:

- source reachability
- object matching
- channel recovery
- root extraction
- chain construction
- deterministic verdict basis

Those are pre-flight facts and should stay in SourceAgent.

## What BinAgent Should Be Allowed To Override

Only soft semantic fields, and only through post-check:

- suggested semantic verdict
- trigger summary
- guard effectiveness comment
- attacker controllability comment
- audit flags

Even then, the final applied result must remain fail-closed.

## Practical Next Step

The next implementation step should be a thin adapter contract, not another recovery stage.

Suggested files:

- SourceAgent output:
  - `verdict_feature_pack.json`
  - `verdict_calibration_queue.json`
- BinAgent output:
  - `review_decisions.json`
  - optional `audit_decisions.json`

Then measure:

- verdict exactness improvement
- under/over reduction
- review acceptance rate
- false promotion rate after post-check

## Bottom Line

SourceAgent should own deterministic pre-flight.

BinAgent should be reduced to semantic review and audit only.

That is the cleanest way to avoid duplicated recovery logic while still reusing BinAgent's review-oriented strengths.
