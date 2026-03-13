# Sample Status

This note is the current single-page summary of SourceAgent sample collection,
curation, and evaluation readiness.

It complements:

- `docs/test_assets_alignment.md` for alignment against `docs/test_full.md`
- `firmware/eval_suite/` for runnable benchmark manifests
- `firmware/ground_truth_bundle/` for curated GT artifacts
- `firmware/eval_suite/sample_catalog.json` for a unified per-binary metadata catalog

## Directory Roles

- `firmware/demo/`
  - small quick-start binaries for smoke testing and local iteration
- `firmware/eval_suite/`
  - canonical manifests used to run evaluation workloads
- `firmware/ground_truth_bundle/`
  - curated GT assets, inventory, sink-only exports, and benchmark mirrors
- `firmware/microbench/`
  - hand-authored microbench binaries and sources
- `firmware/monolithic-firmware-collection/`
  - large no-GT corpus of real firmware binaries
- `firmware/p2im-unit_tests/`
  - structured no-GT firmware/unit-test corpus
- `firmware/uSBS/`
  - mixed real/negative/patched firmware set used for calibration and promotion

## Current Curated Sets

| Set | Size | Current Role | Canonical File |
|---|---:|---|---|
| Demo smoke binaries | small | quick-start / local verification | `firmware/demo/` |
| Unstripped ELF baseline | 48 | broad stripped-vs-unstripped evaluation root | `firmware/eval_suite/unstripped_elf_manifest.json` |
| GT-backed baseline | 44 | primary benchmark with checked-in GT | `firmware/eval_suite/gt_backed_suite_manifest.json` |
| GT-backed stripped peers | 44 | stripped-first mirror of the GT-backed set | `firmware/eval_suite/gt_backed_suite_stripped_manifest.json` |
| Mesobench full-GT set | 30 | higher-semantic L3 benchmark | `firmware/ground_truth_bundle/mesobench/index.json` |
| Mesobench stripped peers | 30 | stripped mirror of mesobench | `firmware/eval_suite/mesobench_stripped_elf_manifest.json` |
| Microbench curated set | 14 | compact L2 semantic benchmark | `firmware/ground_truth_bundle/microbench/index.json` |
| Canonical no-GT workload | 94 | workload/review-cost evaluation without semantic GT | `firmware/eval_suite/no_gt_94_manifest.json` |
| no-GT shard 1 | 47 | split run of the canonical no-GT workload | `firmware/eval_suite/no_gt_94_shard1_manifest.json` |
| no-GT shard 2 | 47 | split run of the canonical no-GT workload | `firmware/eval_suite/no_gt_94_shard2_manifest.json` |
| Microbench autogen variants | 108 | scalable L1 sink-only stress set | `firmware/ground_truth_bundle/microbench_autogen/index.json` |
| Microbench autogen stripped peers | 108 | stripped mirror for autogen L1 | `firmware/eval_suite/microbench_autogen_stripped_manifest.json` |
| Negative / patched candidates | 8 | calibration and future promotion candidates | `firmware/eval_suite/negative_patched_candidates_manifest.json` |

## GT Processing Status

## Unified Sample Catalog

The repo now also ships a normalized per-binary catalog at:

- `firmware/eval_suite/sample_catalog.json`
- `firmware/eval_suite/sample_catalog.csv`

This catalog records, for each tracked binary artifact:

- file size in bytes and MiB
- binary format and symbol state (`raw_bin` / `unstripped` / `stripped`)
- inferred architecture family
- coarse execution-model classification (`bare_metal` / `rtos`)
- framework family where known
- suite membership across the checked-in benchmark manifests
- GT coverage flags such as `has_gt`, `gt_level`, and `has_sink_only_gt`

### Inventory and Tiering

The checked-in GT inventory currently contains `77` entries in:

- `firmware/ground_truth_bundle/ground_truth_inventory.json`
- `firmware/ground_truth_bundle/ground_truth_inventory.csv`

The inventory now tracks:

- `gt_level`
- `in_gt_backed_suite`
- `has_sink_only_gt`
- `negative_or_patched`
- `has_stripped_peer`
- `stripped_elf_path`
- `stripped_origin`

Current tier split:

- `L2`: `14` microbench samples
- `L3`: `30` mesobench samples
- `REFERENCE`: `33` raw/reference entries

### Sink-Only GT Coverage

Current sink-only exports are split into three practical layers:

- base normalized sink GT:
  - `18` legacy/reference entries in
    `firmware/ground_truth_bundle/normalized_gt_sinks.json`
- GT-backed sink-only expansion:
  - `42` binaries
  - `376` sink rows
  - `firmware/ground_truth_bundle/normalized_gt_sinks_gt_backed.json`
- autogen L1 sink-only expansion:
  - `108` binaries
  - `firmware/ground_truth_bundle/normalized_gt_sinks_microbench_autogen.json`

Combined L1 sink-only readiness:

- `150` binaries
- `484` sink rows
- `firmware/ground_truth_bundle/normalized_gt_sinks_l1_combined.json`
- `firmware/eval_suite/l1_sink_only_combined_manifest.json`

### Chain-Level Risk GT

Chain-level risk GT is now supported by the sample schema and evaluator.

Today the checked-in risk GT is intentionally conservative:

- only high-confidence anchor chains are labeled
- anchors are expected to match the final calibrated outputs:
  - `expected_final_verdict`
  - `expected_final_risk_band`
  - `expected_review_priority`

Current real-CVE coverage inside `gt_backed_suite`:

- `16` CVE samples total
- `12` CVE samples with at least one chain-level risk GT annotation
- `19` anchor chains with curated risk GT

This means the repo can already test not only whether a chain was found, but
also whether the final calibrated answer matches the expected risk outcome such
as `CONFIRMED / HIGH / P0`.

## What Is Fully Ready Today

- stripped-vs-unstripped evaluation for the main GT-backed baseline
- full-GT semantic benchmarking for microbench and mesobench
- canonical no-GT workload re-runs using checked-in manifests
- L1 sink-only stress evaluation over `150` binaries
- negative / patched candidate sampling for calibration experiments
- chain-level risk GT checks for a growing subset of real CVE samples

## Remaining Gaps

- `4` CVE samples still do not have chain-level risk GT because they currently
  do not expose sufficiently strong `CONFIRMED` anchor chains
- most risk-annotated binaries still label anchor chains rather than every chain
  in the sample
- the current L1 sink-only corpus is strong on breadth, but still lighter on
  real parser diversity than the long-term target
- some no-GT and negative/patched binaries are still candidates for future
  promotion into mesobench/L3

## Suggested Reading Order

If you want the repo's current sample story in the fastest order, read:

1. `docs/sample_status.md`
2. `docs/test_assets_alignment.md`
3. `firmware/eval_suite/`
4. `firmware/ground_truth_bundle/`

## Last Sanity Snapshot

As of `2026-03-12`, the most recent focused GT/risk regression run used:

```bash
python3 -m pytest -q \
  tests/test_chain_risk_gt_assets.py \
  tests/test_mesobench_v1.py \
  tests/test_microbench_gt_v2.py \
  tests/test_microbench_gt_v2_eval.py
```

Result:

- `27 passed`
