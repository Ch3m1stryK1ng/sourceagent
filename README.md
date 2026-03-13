# SourceAgent

SourceAgent is a Cortex-M firmware analysis and evaluation repo for semantic
source/sink recovery, chain linking, and calibrated risk triage.

The current repo is not just a mining demo. It includes:

- a staged static-analysis pipeline for `.bin` and `.elf` firmware
- optional LLM-assisted proposal, review, and supervision paths
- checked-in benchmark manifests for stripped, unstripped, GT-backed, and no-GT
  workloads
- curated ground-truth assets for labels, chains, and a growing set of
  chain-level risk annotations

For the current sample inventory and processing status, see
`docs/sample_status.md`.

For alignment against the full test plan, see
`docs/test_assets_alignment.md`.

For machine-readable per-binary size and platform metadata, see
`firmware/eval_suite/sample_catalog.json`.

## What It Does

SourceAgent mines security-relevant labels from ARM Cortex-M firmware binaries.
It focuses on where attacker-controlled data enters a program and where that
data is later consumed in dangerous ways.

Current source labels:

- `MMIO_READ`
- `ISR_MMIO_READ`
- `ISR_FILLED_BUFFER`
- `DMA_BACKED_BUFFER`

Current sink labels:

- `COPY_SINK`
- `MEMSET_SINK`
- `STORE_SINK`
- `LOOP_WRITE_SINK`
- `FORMAT_STRING_SINK`
- `FUNC_PTR_SINK`

Downstream of label mining, the repo also builds:

- evidence packs
- label proposals and verification verdicts
- channel graphs and refined memory objects
- sink roots and linked positive chains
- deterministic and soft verdict calibration artifacts
- optional LLM review and bounded supervision outputs

## Pipeline

The main entry point is `sourceagent.interface.main`.

The pipeline currently runs in up to 10 stages:

| Stage | Description |
|---|---|
| 1 | Binary loader and memory-map hypotheses |
| 2 | MemoryAccessIndex via Ghidra MCP |
| 2.5 | Interprocedural constant propagation |
| 3 | Source miners for MMIO, ISR, and DMA-backed data paths |
| 4 | Sink miners for copy, store, loop-write, memset, format-string, and function-pointer sinks |
| 5 | Evidence packing |
| 6 | Heuristic or LLM proposal |
| 7 | Verification with label-specific obligations |
| 8 | Channel graph and refined object construction |
| 9 | Sink-root extraction, tunnel-aware linking, and chain evaluation |
| 10 | Triage queue, verdict calibration, optional review, and optional supervision |

Important defaults:

- `sourceagent mine` defaults to `--stage 7`
- `sourceagent eval` defaults to `--stage 7`
- full chain and risk artifacts require `--stage 10`
- `mine` is online by default unless `--offline` is used
- `eval` is offline by default unless `--online` is used

## Repository Layout

- `sourceagent/interface/`
  - CLI entry points and orchestration
- `sourceagent/pipeline/`
  - core staged pipeline, evaluation harnesses, GT helpers, parity tooling
- `sourceagent/pipeline/miners/`
  - source and sink miners
- `sourceagent/pipeline/linker/`
  - derive checks, sink-root extraction, tunnel linker, triage queue
- `sourceagent/agents/`
  - internal review and supervision runners
- `sourceagent/mcp/`
  - MCP transport and Ghidra integration
- `firmware/demo/`
  - small smoke-test binaries for local runs
- `firmware/eval_suite/`
  - canonical manifests for benchmark workloads
- `firmware/ground_truth_bundle/`
  - curated GT assets, inventory, normalized catalogs, benchmark mirrors
- `docs/`
  - planning notes, eval reports, and current asset status docs
- `tests/`
  - pytest coverage for loaders, miners, eval harnesses, GT schema, parity,
    and calibration logic

## Requirements

- Python `>=3.10`
- Java and Ghidra for Stage 2+ online analysis
- at least one API key if you want LLM proposal, review, or supervision

The repo auto-loads `.env` through `python-dotenv`.

Relevant environment variables live in `.env.example`:

- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `SOURCEAGENT_MODEL`
- `LAUNCH_GHIDRA`
- `GHIDRA_INSTALL_DIR`
- `JAVA_HOME`

## Installation

```bash
pip install -e ".[dev]"
cp .env.example .env
```

Then edit `.env` with the model and runtime settings you want.

Typical minimal settings for online analysis:

```dotenv
SOURCEAGENT_MODEL=gpt-4.1
LAUNCH_GHIDRA=1
GHIDRA_INSTALL_DIR=/path/to/ghidra
JAVA_HOME=/path/to/jdk
```

If you want deterministic-only local runs, you can skip the API keys and avoid
LLM-enabled options.

## CLI Overview

Current top-level commands:

- `sourceagent mine`
  - run the staged mining pipeline on one binary
- `sourceagent export`
  - export a facts bundle from a saved pipeline JSON result
- `sourceagent eval`
  - evaluate one binary, one directory, or one manifest against GT
- `sourceagent eval-parity`
  - compare stripped eval output against unstripped reference runs
- `sourceagent diagnose`
  - run standalone Phase B diagnosis on runtime chains, canonical anchor chains, or external diagnostic JSON
- `sourceagent gt-sinks`
  - regenerate normalized sink GT exports
- `sourceagent gt-sources`
  - regenerate normalized source GT exports
- `sourceagent gt-bundle`
  - regenerate the combined normalized GT bundle

## Quick Start

Run a smoke-test binary through the default deterministic pipeline:

```bash
sourceagent mine firmware/demo/nxp_uart_polling.bin
```

Run the full 10-stage pipeline and save artifacts:

```bash
sourceagent mine firmware/demo/p2im_controllino.elf \
  --stage 10 \
  --output loot/p2im_controllino.json
```

Run Stage 10 with facts export:

```bash
sourceagent mine firmware/demo/p2im_controllino.elf \
  --stage 10 \
  --output loot/p2im_controllino.json \
  --export loot/facts/p2im_controllino
```

Export facts from a saved JSON result:

```bash
sourceagent export loot/p2im_controllino.json loot/facts/p2im_controllino
```

Evaluate the GT-backed benchmark suite:

```bash
sourceagent eval \
  --manifest-json firmware/eval_suite/gt_backed_suite_manifest.json \
  --stage 10 \
  --online \
  --output-dir loot/eval/gt_backed
```

Run stripped/unstripped parity over a completed eval pair:

```bash
sourceagent eval-parity \
  loot/eval/gt_backed_stripped \
  --unstripped-eval-dir loot/eval/gt_backed_unstripped \
  --manifest-json firmware/eval_suite/gt_backed_suite_stripped_manifest.json \
  --output-dir loot/eval/parity
```

Run standalone Phase B diagnosis on a canonical answer chain:

```bash
sourceagent diagnose \
  --diagnostic-source anchor \
  --sample cve_2021_34259_usb_host \
  --chain-id C1_cfg_total_length_overwalk \
  --review-model gpt-4.1 \
  --output-dir loot/diagnose/usb_host
```

Run diagnosis on runtime chains from an existing eval directory:

```bash
sourceagent diagnose \
  --diagnostic-source runtime \
  --eval-dir loot/eval/gt_backed \
  --sample zephyr_cve_2020_10065 \
  --chain-id chain_zephyr-CVE-2020-10065_SINK_zephyr-CVE-2020-10065_0002_a1d90589 \
  --output-dir loot/diagnose/zephyr_10065
```

Run diagnosis on an external diagnostic JSON payload:

```bash
sourceagent diagnose \
  --diagnostic-source file \
  --diagnostic-json loot/diagnostic_chains.json \
  --review-model gpt-4.1 \
  --output-dir loot/diagnose/external
```

Regenerate normalized GT catalogs:

```bash
sourceagent gt-sinks
sourceagent gt-sources
sourceagent gt-bundle
```

## Benchmark And GT Assets

The repo now has several benchmark families with checked-in manifests:

- GT-backed benchmark manifests in `firmware/eval_suite/`
- stripped peers for the GT-backed and mesobench suites
- canonical no-GT workload manifests
- combined L1 sink-only manifests
- negative and patched candidate manifests

Ground-truth assets live in `firmware/ground_truth_bundle/` and include:

- microbench GT
- mesobench GT
- GT-backed suite mirrors
- normalized source and sink catalogs
- ground-truth inventory with tier metadata
- chain-level risk GT for a subset of real CVE anchor chains

The current repo also includes:

- `sourceagent/pipeline/gt_asset_alignment.py`
  - syncs manifests, stripped peers, and inventory metadata
- `sourceagent/pipeline/no_gt_manifest.py`
  - freezes the canonical no-GT workload
- `sourceagent/pipeline/microbench_autogen.py`
  - generates scalable sink-only microbench variants

## Risk And Chain Evaluation

Stage 8-10 artifacts are part of the current architecture, not a future plan.

The repo can already evaluate:

- whether expected source and sink labels were found
- whether expected chains were linked
- whether chain verdicts matched GT
- whether selected chain-level risk answers matched calibrated outputs

That last part now covers a growing subset of real CVE binaries using GT fields
such as:

- `expected_final_verdict`
- `expected_final_risk_band`
- `expected_review_priority`

This allows tests to check not only whether SourceAgent found a chain, but also
whether it ended up labeled like `CONFIRMED / HIGH / P0` when the GT says it
should.

## Testing

Run the full pytest suite:

```bash
pytest -q
```

Focused GT and risk regression:

```bash
python3 -m pytest -q \
  tests/test_chain_risk_gt_assets.py \
  tests/test_mesobench_v1.py \
  tests/test_microbench_gt_v2.py \
  tests/test_microbench_gt_v2_eval.py
```

Focused loader and real-firmware smoke coverage:

```bash
python3 -m pytest -q \
  tests/test_loader.py \
  tests/test_real_firmware_p2im.py
```

## Notes

- Online analysis depends on MCP and a working Ghidra setup.
- LLM paths are optional. Deterministic stages still run without a model.
- If you are looking for the current sample counts and coverage numbers, prefer
  `docs/sample_status.md` over hard-coding them into new docs.
