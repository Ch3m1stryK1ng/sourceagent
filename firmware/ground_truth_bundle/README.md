# Ground Truth Bundle

Unified testing metadata and references for firmware datasets copied under `firmware/`.

## Included Repositories

- `firmware/uSBS`
- `firmware/monolithic-firmware-collection`
- `firmware/microbench` (CVE reproductions)
- `firmware/p2im-ground_truth` (global register CSVs, copied into this bundle)
- `firmware/ground_truth_bundle/mesobench` (30 full-GT mesobench samples)

These are the main local GT/context sources used by the bundle.

## Files in This Bundle

- `ground_truth_inventory.json`: broad structured metadata/reference inventory
- `ground_truth_inventory.csv`: spreadsheet-friendly view
- `normalized_gt_sinks.json`: machine-readable sink GT list (`binary + label + function + address`)
- `normalized_gt_sinks_gt_backed.json`: sink-only GT export derived from the current `44`-sample GT-backed suite
- `normalized_gt_sinks_microbench_autogen.json`: sink-only GT export for the auto-generated microbench variant corpus
- `normalized_gt_sinks_l1_combined.json`: combined L1 sink-only export (`gt_backed + microbench_autogen`)
- `normalized_gt_sources.json`: machine-readable source GT list
- `normalized_gt_bundle.json`: combined source + sink GT view
- `normalized_gt_sinks.csv`: spreadsheet view of normalized sink GT
- `normalized_gt_sinks_gt_backed.csv`: spreadsheet view of the GT-backed sink-only export
- `normalized_gt_sinks_microbench_autogen.csv`: spreadsheet view of the auto-generated sink-only export
- `normalized_gt_sinks_l1_combined.csv`: spreadsheet view of the combined L1 sink-only export
- `references/uSBS/README.md`: uSBS GT benchmark description
- `references/uSBS/injected_snippets_vulns.c`: injected vulnerability definitions
- `references/monolithic/README.md`: monolithic-firmware-collection dataset overview
- `references/monolithic/D_FUZZWARE_README.md`: Fuzzware subset description
- `microbench/`: 14 artifact-complete microbench GT documents
- `microbench_autogen/`: 108 auto-generated sink-only microbench variants
- `mesobench/`: 30 full-GT mesobench documents
- `gt_backed_suite/`: 44-sample combined benchmark view (`14 microbench + 30 mesobench`)
- `uSBS_trigger_inputs/`: copied trigger/replay inputs (`test/inputs` + `pcaps/crasher`)
- `p2im_ground_truth_csv/`: copied P2IM global GT CSVs

## Inventory Counts

`ground_truth_inventory.json` currently contains `77` inventory/reference entries:

- `mesobench`: 30
- `monolithic-firmware-collection`: 15
- `uSBS`: 14
- `p2im-ground_truth`: 4
- `sourceagent-microbench`: 14

Current GT tier tagging in the inventory:

- `L2`: 14 microbench regression/archetype samples
- `L3`: 30 mesobench full-GT samples
- `REFERENCE`: 33 broader raw/reference entries (`uSBS`, monolithic labels, P2IM CSVs)

Important:
- this inventory is not the same thing as the eval benchmark manifests
- full microbench coverage lives in `microbench/index.json` (`14` samples)
- the current GT-backed baseline lives in `gt_backed_suite/index.json` (`44` samples)
- stripped-first batch manifests now live in `firmware/eval_suite/gt_backed_suite_stripped_manifest.json`
  and `firmware/eval_suite/mesobench_stripped_elf_manifest.json`
- canonical no-GT manifests now live in `firmware/eval_suite/no_gt_94_manifest.json`
  plus `no_gt_94_shard1_manifest.json` / `no_gt_94_shard2_manifest.json`
- the generated L1 microbench variant manifests live in
  `firmware/eval_suite/microbench_autogen_unstripped_manifest.json` and
  `firmware/eval_suite/microbench_autogen_stripped_manifest.json`
- the combined L1 sink-only eval manifest lives in
  `firmware/eval_suite/l1_sink_only_combined_manifest.json`
- phase-4 verdict-calibration candidates live in
  `firmware/eval_suite/negative_patched_candidates_manifest.json`

## Notes

- For Fuzzware/Monolithic CVE samples, directory names provide CVE labels; deeper oracle artifacts are usually maintained in upstream `fuzzware-experiments`.
- uSBS entries include copied trigger input files where present.
- Paths in inventory are relative to `firmware/`.
- `mesobench` and `microbench` carry the benchmark-grade artifact GT used by the current chain-centric evaluators.
- `normalized_gt_sinks_gt_backed.json` expands sink-only GT coverage from the older `10`-binary
  label set to `42` GT-backed binaries (`376` sink entries). The remaining `2` GT-backed samples are
  intentionally sinkless source-only controls.
- `microbench_autogen` contributes `108` additional stripped/unstripped sink-bearing binaries, pushing
  the combined checked-in L1 sink-only corpus to `150` binaries.
