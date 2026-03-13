# Microbench Autogen L1

This directory records the large auto-generated sink-only microbench corpus.

Current scope:

- `108` generated variants
- `6` sink families:
  - `COPY_SINK`
  - `MEMSET_SINK`
  - `LOOP_WRITE_SINK`
  - `STORE_SINK`
  - `FORMAT_STRING_SINK`
  - `FUNC_PTR_SINK`

What is generated:

- C sources and build outputs live under `firmware/microbench_autogen/`
- `index.json` records the generated sample registry
- `../normalized_gt_sinks_microbench_autogen.json` exports one sink-only GT row per variant
- `../normalized_gt_sinks_l1_combined.json` merges this corpus with the GT-backed L1 sink export

Eval manifests:

- `firmware/eval_suite/microbench_autogen_unstripped_manifest.json`
- `firmware/eval_suite/microbench_autogen_stripped_manifest.json`
- `firmware/eval_suite/l1_sink_only_combined_manifest.json`

Build / regenerate:

```bash
python3 -m sourceagent.pipeline.microbench_autogen
```

Notes:

- these variants are template-generated L1 samples, not full-chain GT programs
- the goal is stripped-first sink coverage and pattern diversity, not semantic completeness
