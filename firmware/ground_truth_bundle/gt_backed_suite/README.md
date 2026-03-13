# GT-Backed Suite v2

This suite combines all current GT-backed microbench and mesobench samples.

- microbench: 14
- mesobench: 30
- total: 44

Operationally relevant aligned outputs:

- `firmware/eval_suite/gt_backed_suite_manifest.json`: current unstripped baseline
- `firmware/eval_suite/gt_backed_suite_stripped_manifest.json`: stripped-first counterpart
- `firmware/ground_truth_bundle/normalized_gt_sinks_gt_backed.json`: sink-only GT export
  derived from the checked-in sample docs
- `firmware/eval_suite/negative_patched_candidates_manifest.json`: phase-4 verdict-calibration set

Coverage notes:

- the stripped manifest covers all `44` GT-backed binaries
- the sink-only export covers `42/44` GT-backed binaries (`376` sink entries)
- the remaining `2` suite members (`t0_dma_backed_buffer`, `t0_isr_mmio_read`) are
  intentional source-only / sinkless controls
