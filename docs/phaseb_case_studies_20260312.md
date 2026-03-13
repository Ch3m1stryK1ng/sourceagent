# Phase B Case Studies

Date: `2026-03-12`

Primary evidence roots:

- `/tmp/phaseb_cve_answer_batch_20260312`
- `/tmp/phaseb_cve_answer_batch_20260312_v2`

This note explains why some canonical answer chains still do **not** end at
`CONFIRMED / HIGH / P0`, even when they are directly injected into Phase B.

## Core Observation

The current misses are not all the same.

There are at least two distinct failure modes:

1. `structural gate not met`
   Phase B finds the chain risky, but the final diagnostic output is still
   limited by deterministic structural constraints such as `source_reached`.
2. `semantic caution after structural acceptance`
   The review is accepted and the chain may already reach `HIGH / P0`, but the
   reviewer still refuses to call it fully `CONFIRMED` because the concrete
   trigger/capacity story is not explicit enough in the supplied evidence.

The two Zephyr BLE cases (`10065`, `10066`) belong to the first category.
The Contiki HALucinator case belongs to the second category.

## Case A: Zephyr CVE-2020-10065

Source files:

- GT sample: `firmware/ground_truth_bundle/mesobench/samples/zephyr_cve_2020_10065.json`
- Diagnostic outputs: `/tmp/phaseb_cve_answer_batch_20260312/zephyr_cve_2020_10065`

Canonical anchors diagnosed:

- `chain_zephyr-CVE-2020-10065_SINK_zephyr-CVE-2020-10065_0002_a1d90589`
- `chain_zephyr-CVE-2020-10065_SINK_zephyr-CVE-2020-10065_0006_4a18cb0f`

Observed output:

- both anchors ended at `SUSPICIOUS / MEDIUM / P1`

Observed diagnostic pattern:

- `accept_reason = STRUCTURAL_CONSTRAINT_NOT_MET`
- `soft_accept_state = semantic_only_applied`
- `blocked_by = ["source_reached"]`
- dominant reason codes:
  - `CHECK_NOT_BINDING_ROOT`
  - `TRIGGER_UNCERTAIN_MISSING_CAPACITY`
  - `WEAK_GUARDING`

What this means:

- Phase B believes the sink/root side is risky enough to keep the chain above
  `SAFE_OR_LOW_RISK`
- however, the formal producer-side source proof is still too weak for strict
  escalation
- because of that, the semantic review can only apply in a soft/limited way

In other words, this is **not** mainly “the reviewer is too conservative”.
It is “the reviewer is being held back by deterministic structural gates”.

Why it stopped at `MEDIUM / P1` instead of `HIGH / P0`:

- the anchor is synthetic rather than backed by a strong runtime-aligned chain
- the destination extent is visible (`256` bytes), but the exact copy/capacity
  semantics are still indirect
- the reviewer explicitly asked for a stronger source-to-object anchor on the
  producer side

Practical takeaway:

- improving Phase B alone is unlikely to fix this case
- the highest-value next step is strengthening the deterministic
  `source -> object` proof or providing better source-side snippets/context

## Case B: Zephyr CVE-2020-10066

Source files:

- GT sample: `firmware/ground_truth_bundle/mesobench/samples/zephyr_cve_2020_10066.json`
- Diagnostic outputs: `/tmp/phaseb_cve_answer_batch_20260312/zephyr_cve_2020_10066`

Canonical anchors diagnosed:

- `chain_zephyr-CVE-2020-10066_SINK_zephyr-CVE-2020-10066_0002_531986f9`
- `chain_zephyr-CVE-2020-10066_SINK_zephyr-CVE-2020-10066_0006_e72ac38e`

Observed output:

- both anchors ended at `SUSPICIOUS / MEDIUM / P1`

Observed diagnostic pattern:

- `accept_reason = STRUCTURAL_CONSTRAINT_NOT_MET`
- `soft_accept_state = semantic_only_applied`
- `blocked_by = ["source_reached"]`
- dominant reason codes:
  - `CHECK_NOT_BINDING_ROOT`
  - `TRIGGER_UNCERTAIN_MISSING_CAPACITY`
  - `WEAK_GUARDING`

Why this case looks almost identical to `10065`:

- both are currently represented by provisional GATT notify/indicate anchors
- both expose a plausible attacker-controlled length root
- both still lack a sufficiently strong formal producer-side story
- both rely on synthetic evidence that does not expose the concrete copy
  primitive or a definitive capacity comparison

Implication:

`10065` and `10066` should be treated as a **shared diagnosis cluster** rather
than two unrelated failures.

The likely fix path is also shared:

- recover stronger producer/source evidence
- expose richer sink-capacity snippets
- if possible, align these anchors to a runtime-predicted chain instead of
  staying synthetic-only

## Case C: Contiki HALucinator CVE-2019-9183

Source files:

- GT sample: `firmware/ground_truth_bundle/mesobench/samples/contiki_halucinator_cve_2019_9183_hello_world.json`
- Diagnostic outputs: `/tmp/phaseb_cve_answer_batch_20260312/contiki_halucinator_cve_2019_9183_hello_world`

Canonical anchor diagnosed:

- `chain_hello-world_SINK_hello-world_0001_6141a72f`

Expected GT:

- `CONFIRMED / HIGH / P0`

Observed output:

- `SUSPICIOUS / HIGH / P0`

Observed diagnostic pattern:

- `accept_reason = ACCEPTED_REVIEW`
- `soft_accept_state = strictly_applied`
- `blocked_by = []`
- dominant reason codes:
  - `CHECK_NOT_BINDING_ROOT`
  - `TRIGGER_UNCERTAIN_MISSING_CAPACITY`
  - `ROOT_FROM_MMIO_OR_DMA`

This is a fundamentally different failure mode from `10065/10066`.

What it means:

- deterministic structural gates did **not** block the review
- Phase B already accepts the chain as high priority and high risk
- the remaining hesitation is specifically about the final semantic jump from
  `SUSPICIOUS` to `CONFIRMED`

Why it still stopped short of `CONFIRMED`:

- the synthetic snippets do not show the concrete copy operation in enough
  detail
- the destination capacity story is still indirect rather than explicit
- the reviewer sees a strong risk story, but not a complete exploitability
  story

Practical takeaway:

- this case is a true **Phase B semantic calibration** gap
- unlike `10065/10066`, it is not waiting on a structural source gate first
- the most promising next step is richer sink-side/capacity-side context, not a
  full structural rewrite

## Side-by-Side Comparison

| Sample family | Final output | Structural gate status | Main blocker |
|---|---|---|---|
| `zephyr_cve_2020_10065` | `SUSPICIOUS / MEDIUM / P1` | blocked by `source_reached` | weak producer/source proof plus incomplete capacity evidence |
| `zephyr_cve_2020_10066` | `SUSPICIOUS / MEDIUM / P1` | blocked by `source_reached` | weak producer/source proof plus incomplete capacity evidence |
| `contiki_halucinator_cve_2019_9183` | `SUSPICIOUS / HIGH / P0` | no structural block | semantic trigger/capacity story not explicit enough for `CONFIRMED` |

## What This Tells Us About Phase B

Phase B is already behaving in a fairly interpretable way.

It is **not** just collapsing everything into one vague “not enough evidence”
bucket.

Instead, it is separating:

- chains that are semantically risky but still structurally under-anchored
- chains that are structurally acceptable and high-risk, but still short of a
  fully confirmed exploitability story

That distinction is useful because it tells us where to spend engineering time:

- `10065/10066`: improve deterministic source/object evidence
- `HALucinator 2019-9183`: improve sink-capacity / triggerability context for
  review
