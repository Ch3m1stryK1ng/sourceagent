# Ground Truth Bundle

Unified testing metadata and references for firmware datasets copied under `firmware/`.

## Included Repositories

- `firmware/uSBS`
- `firmware/monolithic-firmware-collection`
- Existing local sets used as GT/context:
- `firmware/microbench` (CVE reproductions)
- `firmware/p2im-ground_truth` (global register CSVs, copied into this bundle)

## Files in This Bundle

- `ground_truth_inventory.json`: full structured metadata per sample
- `ground_truth_inventory.csv`: spreadsheet-friendly view
- `normalized_gt_sinks.json`: machine-readable sink GT list (`binary + label + function + address`)
- `normalized_gt_sinks.csv`: spreadsheet view of normalized sink GT
- `references/uSBS/README.md`: uSBS GT benchmark description
- `references/uSBS/injected_snippets_vulns.c`: injected vulnerability definitions
- `references/monolithic/README.md`: monolithic-firmware-collection dataset overview
- `references/monolithic/D_FUZZWARE_README.md`: Fuzzware subset description
- `uSBS_trigger_inputs/`: copied trigger/replay inputs (`test/inputs` + `pcaps/crasher`)
- `p2im_ground_truth_csv/`: copied P2IM global GT CSVs

## Dataset Entry Counts

- `monolithic-firmware-collection`: 15 entries
- `p2im-ground_truth`: 4 entries
- `sourceagent-microbench`: 3 entries
- `uSBS`: 14 entries

## Notes

- For Fuzzware/Monolithic CVE samples, directory names provide CVE labels; deeper oracle artifacts are usually maintained in upstream `fuzzware-experiments`.
- uSBS entries include copied trigger input files where present.
- Paths in inventory are relative to `firmware/`.
