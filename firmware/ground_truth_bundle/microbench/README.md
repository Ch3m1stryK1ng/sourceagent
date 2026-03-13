# Microbench GT v2

This directory holds the artifact-level ground truth for the 14
`firmware/microbench` samples.

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
- `sources` and `sinks` were originally seeded from the v1 normalized GT files
- all 14 checked-in sample documents are now `annotation_level=complete`
- repo tests assert that the checked-in tree remains artifact-complete for the
  current SourceAgent chain evaluator
- `microbench_autogen` now provides a large L1 companion corpus for stripped-first
  sink-only evaluation

Files:
- `index.json`: manifest for all microbench samples
- `samples/<binary_stem>.json`: one artifact-level GT document per sample
- `../microbench_autogen/index.json`: auto-generated sink-only variant manifest

Build:

```bash
python3 -m sourceagent.pipeline.microbench_gt_v2 build
```

`build` preserves existing sample annotations by default. Use `--force` only
when regenerating skeletons from scratch.

Validate:

```bash
python3 -m sourceagent.pipeline.microbench_gt_v2 validate
```

Notes:
- validation remains schema-oriented, but the checked-in repo state is expected
  to stay complete
- this v2 GT drives chain-centric evaluation and failure taxonomy; it does not
  replace the existing v1 label GT exports
