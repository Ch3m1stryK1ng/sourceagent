# Phase B CVE Answer-Chain Diagnostic

Date: `2026-03-12`

Run roots:

- `/tmp/phaseb_cve_answer_batch_20260312`
- `/tmp/phaseb_cve_answer_batch_20260312_v2`

This batch asks a narrow question:

`If we directly feed the canonical answer chains into Phase B, does Phase B produce the expected final severity output?`

The run covers the current `16` CVE-named benchmark samples:

- `3` microbench CVE samples
- `13` GT-backed / mesobench CVE samples

Only canonical main chains were diagnosed in this batch.
Related/supporting risky chains were not included.

## Headline Result

- Total CVE-named samples considered: `16`
- Runnable with canonical answer chains today: `16`
- Blocked because no canonical answer chain is defined yet: `0`
- Total canonical-main answer chains diagnosed: `25`
- Exact matches against chain-level risk GT: `18`
- Under-promoted relative to risk GT: `1`
- Not yet risk-annotated in GT: `6`

Aggregate output over the `25` diagnosed answer chains:

- Final verdicts: `18 CONFIRMED`, `7 SUSPICIOUS`
- Final risk bands: `19 HIGH`, `5 MEDIUM`, `1 LOW`
- Review priorities: `19 P0`, `6 P1`

## Interpretation

The current Phase B diagnostic path is already strong enough to answer the main semantic-risk question on most of the canonical answer chains that exist today.

For answer chains that already have explicit chain-level risk GT, the observed behavior is:

- `18/19` risk-annotated canonical chains matched exactly at `final_verdict + risk_band + review_priority`
- the only under-promotion was a single Contiki HALucinator case that stayed at `SUSPICIOUS / HIGH / P0`

For the six canonical anchors that do not yet have chain-level risk GT, Phase B kept them at conservative outputs:

- `zephyr_cve_2020_10065`: `SUSPICIOUS / MEDIUM / P1`
- `zephyr_cve_2020_10066`: `SUSPICIOUS / MEDIUM / P1`
- `zephyr_cve_2021_3329`: `SUSPICIOUS / LOW / P1`
- `zephyr_cve_2021_3330`: `SUSPICIOUS / MEDIUM / P1`

This is useful because it shows Phase B is not blindly upgrading every injected answer chain to `CONFIRMED / HIGH / P0`.

## Per-Sample Result

| Sample | Canonical chains | Output |
|---|---:|---|
| `cve_2018_16525_freertos_dns` | 2 | both `CONFIRMED / HIGH / P0` (`exact`) |
| `cve_2020_10065_hci_spi` | 2 | both `CONFIRMED / HIGH / P0` (`exact`) |
| `cve_2021_34259_usb_host` | 2 | both `CONFIRMED / HIGH / P0` (`exact`) |
| `contiki_cve_2020_12140_hello_world` | 5 | all `CONFIRMED / HIGH / P0` (`exact`) |
| `contiki_cve_2020_12141_snmp_server` | 1 | `CONFIRMED / HIGH / P0` (`exact`) |
| `contiki_halucinator_cve_2019_9183_hello_world` | 1 | `SUSPICIOUS / HIGH / P0` (`under`) |
| `zephyr_cve_2020_10064` | 1 | `CONFIRMED / HIGH / P0` (`exact`) |
| `zephyr_cve_2020_10065` | 2 | both `SUSPICIOUS / MEDIUM / P1` (`not_annotated`) |
| `zephyr_cve_2020_10066` | 2 | both `SUSPICIOUS / MEDIUM / P1` (`not_annotated`) |
| `zephyr_cve_2021_3319` | 1 | `CONFIRMED / HIGH / P0` (`exact`) |
| `zephyr_cve_2021_3320` | 1 | `CONFIRMED / HIGH / P0` (`exact`) |
| `zephyr_cve_2021_3321` | 1 | `CONFIRMED / HIGH / P0` (`exact`) |
| `zephyr_cve_2021_3322` | 1 | `CONFIRMED / HIGH / P0` (`exact`) |
| `zephyr_cve_2021_3323` | 1 | `CONFIRMED / HIGH / P0` (`exact`) |
| `zephyr_cve_2021_3329` | 1 | `SUSPICIOUS / LOW / P1` (`not_annotated`) |
| `zephyr_cve_2021_3330` | 1 | `SUSPICIOUS / MEDIUM / P1` (`not_annotated`) |

## Important Cases

### Strong exact cases

These samples show the intended behavior clearly:

- `cve_2018_16525_freertos_dns`
- `cve_2020_10065_hci_spi`
- `cve_2021_34259_usb_host`
- `contiki_cve_2020_12140_hello_world`
- `zephyr_cve_2021_3319`

In these cases, feeding the answer chain directly into Phase B was enough to reach the expected `CONFIRMED / HIGH / P0` output.

### Conservative-but-useful cases

`zephyr_cve_2020_10065` and `zephyr_cve_2020_10066` stayed at `SUSPICIOUS / MEDIUM / P1`.

Observed reason-code pattern:

- `CHECK_NOT_BINDING_ROOT`
- `TRIGGER_UNCERTAIN_MISSING_CAPACITY`
- `WEAK_GUARDING`

This suggests Phase B currently sees these answer chains as plausible and risky, but still lacking enough trigger/capacity evidence to escalate them all the way to `CONFIRMED / HIGH / P0`.

`zephyr_cve_2021_3329` and `zephyr_cve_2021_3330` now also participate in the experiment through newly added provisional canonical anchors.

- `3329` came out as `SUSPICIOUS / LOW / P1`
- `3330` came out as `SUSPICIOUS / MEDIUM / P1`

That behavior is consistent with their current GT state: both anchors are deliberately evaluation-only and still describe chains that look guarded or only weakly triggerable under the visible evidence.

### One under-promotion against current risk GT

`contiki_halucinator_cve_2019_9183_hello_world` came out as:

- actual: `SUSPICIOUS / HIGH / P0`
- expected: `CONFIRMED / HIGH / P0`

Observed reason codes:

- `CHECK_NOT_BINDING_ROOT`
- `TRIGGER_UNCERTAIN_MISSING_CAPACITY`
- `ROOT_FROM_MMIO_OR_DMA`

This is the cleanest current example where Phase B is semantically close to the expected answer, but still slightly too conservative in final verdict.

## Current Limitation Exposed by This Batch

The biggest blocker is no longer anchor coverage.

The current blocker is semantic evidence quality:

- some provisional anchors still rely on synthetic snippets
- some chains remain blocked by weak source/object proof or incomplete capacity context
- some visible guards look strong enough that Phase B refuses to over-claim exploitability

## Takeaway

As of `2026-03-12`, the standalone Phase B diagnostic path is already good enough to support the claim:

`When given a canonical answer chain, Phase B usually produces the expected high-risk outcome.`

More precisely:

- it is exact on most risk-annotated canonical answer chains
- it remains conservative on some weaker Zephyr cases
- it is now benchmark-complete at the `16/16` canonical-anchor level, and the remaining gap is semantic/risk refinement rather than missing diagnostic infrastructure
