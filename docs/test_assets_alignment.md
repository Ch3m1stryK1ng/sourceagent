# Test Asset Alignment

This note records the current alignment status between
`docs/test_full.md` and the checked-in test assets after the Phase 1-4 sync.

## What Is Now Aligned

### Phase 1: stripped-first baseline

- `firmware/eval_suite/gt_backed_suite_stripped_manifest.json`
  - `44` GT-backed samples
  - every sample now has a ready stripped peer
- `firmware/eval_suite/mesobench_stripped_elf_manifest.json`
  - `30` mesobench samples
  - derived from the current unstripped mesobench manifest

Implementation note:
- the repo does not currently ship `arm-none-eabi-strip`, so stripped peers were
  generated via `objcopy -F elf32-little --strip-all` plus ELF-header machine-field
  restoration to preserve `Machine: ARM`

### Phase 2: GT tier metadata

- `firmware/ground_truth_bundle/ground_truth_inventory.json`
- `firmware/ground_truth_bundle/ground_truth_inventory.csv`

The inventory now carries:

- `gt_level`
- `in_gt_backed_suite`
- `has_sink_only_gt`
- `negative_or_patched`
- `has_stripped_peer`
- `stripped_elf_path`
- `stripped_origin`

Current tier split:

- `L2`: `14` SourceAgent microbench samples
- `L3`: `30` mesobench full-GT samples
- `REFERENCE`: `33` raw/reference entries

### Phase 3: expanded sink-only GT

- `firmware/ground_truth_bundle/normalized_gt_sinks_gt_backed.json`
- `firmware/ground_truth_bundle/normalized_gt_sinks_gt_backed.csv`

Current coverage:

- `376` sink entries
- `42` GT-backed binaries
- includes the newer `FORMAT_STRING_SINK` and `FUNC_PTR_SINK` archetypes

Not covered by design:

- `t0_dma_backed_buffer`
- `t0_isr_mmio_read`

These are source-only / sinkless controls, so they do not belong in a sink-only GT export.

### Phase 4: negative / patched organization

- `firmware/eval_suite/negative_patched_candidates_manifest.json`

Current calibration set size:

- `8` candidates
- includes patched and instrumented uSBS variants
- includes `negative_only` and `negative_control` GT-backed samples

## Newly Aligned After Phase 5+

### Canonical no-GT workload

- `firmware/eval_suite/no_gt_94_manifest.json`
- `firmware/eval_suite/no_gt_94_shard1_manifest.json`
- `firmware/eval_suite/no_gt_94_shard2_manifest.json`

This now freezes the `94`-sample no-GT workload referenced by `docs/test_full.md`:

- `47` `p2im-unit_tests`
- `37` monolithic binaries not already promoted into the GT-backed suite
- `10` uSBS binaries not already promoted into the GT-backed suite

### 100+ sink-only binaries

- `firmware/ground_truth_bundle/microbench_autogen/index.json`
- `firmware/ground_truth_bundle/normalized_gt_sinks_microbench_autogen.json`
- `firmware/ground_truth_bundle/normalized_gt_sinks_l1_combined.json`
- `firmware/eval_suite/l1_sink_only_combined_manifest.json`

Current L1 coverage is now:

- `108` auto-generated microbench variants
- `42` GT-backed sink-bearing binaries
- `150` combined sink-only binaries

### Microbench auto-variant generator

- `sourceagent/pipeline/microbench_autogen.py`

What it produces:

- `108` generated C sources
- unstripped + stripped ELF pairs
- `.bin` and `.map` files
- per-variant sink-only GT rows

## Remaining Follow-Up

The biggest remaining work after this is no longer asset-count alignment. It is quality expansion:

- promote a second real-world L1 shard beyond GT-backed + autogen microbench
- decide whether some no-GT or phase-4 candidates should become new mesobench/L3 samples
- add stronger semantic diversity to the autogen templates if we want them to mimic more real parser shapes
