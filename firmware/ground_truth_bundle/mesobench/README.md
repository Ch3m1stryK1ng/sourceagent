# Mesobench GT v1

This directory extends `microbench` with a larger, more realistic set for
chain-centric optimization.

Design goals:
- keep `microbench` as the regression layer
- add `mesobench` as the next optimization layer
- prefer binaries that already look like Type II/III evaluation objects
- keep source-code anchoring explicit, even when the exact vulnerable file still
  needs manual resolution

Current scope:
- `30` source-backed mesobench samples
- all `30` have been promoted to `full_gt` at pipeline scope
- `19` high-priority real-chain samples from Contiki-NG / Zephyr / STM32Cube-backed
  examples or negative-control targets
- `11` uSBS networking samples, anchored to STM32CubeF4 base sources plus uSBS
  overlay artifacts

Per-sample GT files contain:
- sample metadata
- binary paths
- source repository anchors
- source/object/channel/sink/root/derive/check/chain sections
- expected channel mode and chain scope
- negative expectations when known
- provenance notes describing whether the GT was manual, targeted, or auto-promoted

Notes:
- this started as a seed GT layer, but the current checked-in sample files are
  `full_gt` within the current SourceAgent pipeline scope
- "full_gt" here means the sample carries explicit artifact-level constraints for
  the current research scope; it does not claim perfect whole-program semantic
  completeness
- use `index.json` to see which samples are primary chain drivers vs controls

Build:

```bash
python3 -m sourceagent.pipeline.mesobench build
```

Validate:

```bash
python3 -m sourceagent.pipeline.mesobench validate
```

Related outputs:
- `samples/*.json`: one artifact-level GT document per sample
- `index.json`: mesobench manifest and source-repo registry
- `mesobench_inventory.json/csv`: operator-facing sample inventory
- `global_inventory_patch.json`: entries injected into the global inventory
- `firmware/eval_suite/mesobench_unstripped_elf_manifest.json`: batch-eval manifest
