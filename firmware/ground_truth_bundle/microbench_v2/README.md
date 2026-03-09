# Microbench GT v2

This directory holds the artifact-level ground-truth skeleton for the 14 `firmware/microbench` samples.

Scope:
- keep the existing normalized label GT (`normalized_gt_sources.json`, `normalized_gt_sinks.json`) as the v1 label baseline
- add a v2 layer for intermediate artifacts:
  - `sources`
  - `objects`
  - `channels`
  - `sinks`
  - `sink_roots`
  - `derive_checks`
  - `chains`
  - `negative_expectations`

Current state:
- `sources` and `sinks` are seeded automatically from the v1 normalized GT files
- all other sections are skeleton placeholders and still require manual per-sample annotation

Files:
- `index.json`: manifest for all microbench samples
- `samples/<binary_stem>.json`: one artifact-level skeleton per sample

Build:

```bash
python3 -m sourceagent.pipeline.microbench_gt_v2 build
```

`build` preserves existing sample annotations by default. Use `--force` only when regenerating skeletons from scratch.

Validate:

```bash
python3 -m sourceagent.pipeline.microbench_gt_v2 validate
```

Notes:
- validation is schema-only by default; it does not require every section to be fully annotated yet
- this v2 GT is intended to drive chain-centric evaluation and failure taxonomy, not replace the existing v1 label GT
