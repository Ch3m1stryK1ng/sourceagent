# SourceAgent

RQ1: Semantic source/sink label recovery for monolithic firmware binaries.

## Overview

SourceAgent mines security-relevant **source** and **sink** labels from stripped
Type-II/III (RTOS-based and bare-metal) ARM Cortex-M firmware binaries. It uses
a "mine -> LLM proposes -> static analysis verifies" architecture with fail-closed
verification obligations.

### Label Taxonomy

**Sources** (where attacker-controlled data enters):
- `MMIO_READ` — Direct peripheral register read (0x40000000-0x5FFFFFFF)
- `ISR_MMIO_READ` — MMIO read inside an Interrupt Service Routine
- `ISR_FILLED_BUFFER` — SRAM buffer populated by an ISR
- `DMA_BACKED_BUFFER` — Buffer filled by DMA engine transfer

**Sinks** (where data is consumed unsafely):
- `COPY_SINK` — memcpy/memmove with runtime-derived length
- `MEMSET_SINK` — memset with non-constant size
- `STORE_SINK` — Direct memory store with non-constant offset
- `LOOP_WRITE_SINK` — Bounded loop writing to buffer

## Pipeline Stages

| Stage | Milestone | Description |
|-------|-----------|-------------|
| 0 | M0 | Microbench suite + eval harness |
| 1 | M1 | Binary loader + memory-map hypotheses |
| 2 | M2 | MemoryAccessIndex + bounded p-code slicing |
| 3 | VS0 | MMIO_READ source mining |
| 4 | VS1 | COPY_SINK detection |
| 5 | M5 | Evidence packer |
| 6 | M6 | LLM proposer |
| 7 | M7 | Verifier + obligations |
| 8 | VS2 | ISR context + ISR_FILLED_BUFFER |
| 9 | VS3 | DMA_BACKED_BUFFER |
| 10 | VS4-5 | Additional sinks |
| 11 | M8 | BinAgent integration |
| 12 | M9 | End-to-end evaluation |

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Configure
cp .env.example .env
# Edit .env with your API key and model

# Run mining pipeline
sourceagent mine firmware/nxp_uart_polling.bin

# Run evaluation
sourceagent eval firmware/nxp_uart_polling.bin

# Run tests
pytest -v
```

## Architecture

Built on BinAgent's framework (LLM, MCP, tool system) with Ghidra MCP for
binary analysis. See `docs/rq1_planning_v1.2.pdf` for the full research plan.
