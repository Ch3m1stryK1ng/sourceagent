# Eval Artifacts for Optimization Loop

This document describes the new evaluation artifacts used for strict source/sink optimization.

## 1) Run Eval with Raw Per-Sample JSON

```bash
python3 -m sourceagent.interface.main eval \
  --all firmware/microbench \
  --formats elf,bin \
  --gt-json firmware/ground_truth_bundle/normalized_gt_bundle.json \
  --output-dir /tmp/sourceagent_eval \
  --stage 7 \
  --online \
  --model <your_model>
```

Default mode is offline; add `--online` to enable MCP-backed stages.

MCP stability note:

- Current default is **shared** Ghidra project mode (more stable on this host).
- Avoid forcing isolated mode unless needed:
  `SOURCEAGENT_GHIDRA_PROJECT_MODE=isolated ...`

## 2) Output Layout

Under `--output-dir`, the CLI writes:

- `raw_results/<sample>.pipeline.json`
  - Full raw pipeline result (candidates, proposals, verified, etc.).
- `raw_views/<sample>.candidate.json`
  - `source_candidates` + `sink_candidates` only.
- `raw_views/<sample>.proposal.json`
  - `proposals` only.
- `raw_views/<sample>.verified.json`
  - `verified_labels` only.
- `detailed/<sample>.matching.json`
  - GT entries, strict per-label metrics, detailed match decisions.
- `detailed/all_samples_detailed.json`
  - Concatenated detailed matching for all samples.
- `summary/eval_summary.json`
  - Aggregate strict/weighted TP/FP/FN + precision/recall/F1 + FP-by-label.
- `run_manifest.json`
  - Run parameters (`offline`, proposer mode, model, formats, stripped/mixed info).
- `scoring_policy.json` and `scoring_policy.md`
  - Exact TP/FN/FP scoring rules, including near-miss (`~1`) partial-credit rule.

## 3) `~1` (Near-Miss) Rule

Weighted scoring adds partial credit for unresolved sink-label mismatches:

- Strict TP requires exact label + site match.
- If exact match fails, and GT/detected labels share sink family and match address/function,
  it is counted as partial with `partial_credit` (default `0.5`).

This formalizes manual bookkeeping like `~1` in reports.

## 4) Machine-Readable GT Lists

Generate/update normalized sink GT:

```bash
python3 -m sourceagent.interface.main gt-sinks \
  --microbench-dir firmware/microbench \
  --output-json firmware/ground_truth_bundle/normalized_gt_sinks.json \
  --output-csv  firmware/ground_truth_bundle/normalized_gt_sinks.csv
```

Fields include:

- `binary_stem`
- `gt_sink_id`
- `label`
- `pipeline_label_hint`
- `function_name`
- `address` / `address_hex`
- `address_status` (`resolved` or `unresolved`)
- `notes`

Generate/update normalized source GT:

```bash
python3 -m sourceagent.interface.main gt-sources \
  --output-json firmware/ground_truth_bundle/normalized_gt_sources.json \
  --output-csv  firmware/ground_truth_bundle/normalized_gt_sources.csv
```

Generate/update combined GT bundle (sources + sinks):

```bash
python3 -m sourceagent.interface.main gt-bundle \
  --microbench-dir firmware/microbench \
  --output-json firmware/ground_truth_bundle/normalized_gt_bundle.json \
  --output-csv  firmware/ground_truth_bundle/normalized_gt_bundle.csv
```

Bundle-specific field:

- `gt_kind` (`source` or `sink`)
