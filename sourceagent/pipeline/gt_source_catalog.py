"""Normalized GT source inventory generator for microbench/CVE samples.

Produces a machine-readable list with:
  - binary stem
  - source label
  - source site address (MMIO/register/buffer anchor)
  - function name
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, List


# Curated source GT definitions for the current benchmark set.
# Addresses are source-site anchors used by the current pipeline for source labels.
_SOURCE_GT_CATALOG: List[Dict[str, object]] = [
    # T0 microbench sources
    {"binary_stem": "t0_mmio_read", "gt_source_id": "R1", "label": "MMIO_READ", "address": 0x4001100C, "function_name": "uart_enable_rx", "notes": "USART CR1 read"},
    {"binary_stem": "t0_mmio_read", "gt_source_id": "R2", "label": "MMIO_READ", "address": 0x40011000, "function_name": "uart_read_byte", "notes": "USART SR polling read"},
    {"binary_stem": "t0_mmio_read", "gt_source_id": "R3", "label": "MMIO_READ", "address": 0x40011004, "function_name": "uart_read_byte", "notes": "USART DR read"},
    {"binary_stem": "t0_isr_mmio_read", "gt_source_id": "R1", "label": "ISR_MMIO_READ", "address": 0x40011000, "function_name": "USART1_IRQHandler", "notes": "ISR status read"},
    {"binary_stem": "t0_isr_mmio_read", "gt_source_id": "R2", "label": "ISR_MMIO_READ", "address": 0x40011004, "function_name": "USART1_IRQHandler", "notes": "ISR data read"},
    {"binary_stem": "t0_isr_filled_buffer", "gt_source_id": "R1", "label": "ISR_MMIO_READ", "address": 0x40011000, "function_name": "USART1_IRQHandler", "notes": "ISR status read"},
    {"binary_stem": "t0_isr_filled_buffer", "gt_source_id": "R2", "label": "ISR_MMIO_READ", "address": 0x40011004, "function_name": "USART1_IRQHandler", "notes": "ISR data read"},
    {"binary_stem": "t0_isr_filled_buffer", "gt_source_id": "R3", "label": "ISR_FILLED_BUFFER", "address": 0x20000000, "function_name": "USART1_IRQHandler", "notes": "ISR-filled shared RX buffer"},
    {"binary_stem": "t0_dma_backed_buffer", "gt_source_id": "R1", "label": "DMA_BACKED_BUFFER", "address": 0x40020000, "function_name": "dma_uart_rx_init", "notes": "DMA-backed RX buffer configured"},
    {"binary_stem": "t0_copy_sink", "gt_source_id": "R1", "label": "MMIO_READ", "address": 0x40011000, "function_name": "uart_read_byte", "notes": "USART SR polling read"},
    {"binary_stem": "t0_copy_sink", "gt_source_id": "R2", "label": "MMIO_READ", "address": 0x40011004, "function_name": "uart_read_byte", "notes": "USART DR read"},
    {"binary_stem": "t0_store_loop_sink", "gt_source_id": "R1", "label": "MMIO_READ", "address": 0x40004400, "function_name": "spi_read_byte", "notes": "SPI SR read"},
    {"binary_stem": "t0_store_loop_sink", "gt_source_id": "R2", "label": "MMIO_READ", "address": 0x40004404, "function_name": "spi_read_byte", "notes": "SPI DR read"},
    {"binary_stem": "t0_uart_rx_overflow", "gt_source_id": "R1", "label": "MMIO_READ", "address": 0x40011000, "function_name": "uart_read_byte", "notes": "USART SR polling read"},
    {"binary_stem": "t0_uart_rx_overflow", "gt_source_id": "R2", "label": "MMIO_READ", "address": 0x40011004, "function_name": "uart_read_byte", "notes": "USART DR read"},
    {"binary_stem": "t0_dma_length_overflow", "gt_source_id": "R1", "label": "MMIO_READ", "address": 0x4002005C, "function_name": "main", "notes": "DMA status/poll register read"},
    {"binary_stem": "t0_dma_length_overflow", "gt_source_id": "R2", "label": "MMIO_READ", "address": 0x40011004, "function_name": "dma_start_rx", "notes": "USART DR read during DMA path"},
    {"binary_stem": "t0_dma_length_overflow", "gt_source_id": "R3", "label": "MMIO_READ", "address": 0x40011000, "function_name": "uart_read_word", "notes": "USART SR read"},
    {"binary_stem": "t0_dma_length_overflow", "gt_source_id": "R4", "label": "MMIO_READ", "address": 0x40011004, "function_name": "uart_read_word", "notes": "USART DR read"},
    {"binary_stem": "t0_dma_length_overflow", "gt_source_id": "R5", "label": "DMA_BACKED_BUFFER", "address": 0x40020000, "function_name": "dma_start_rx", "notes": "DMA-backed buffer config"},
    {"binary_stem": "t0_indirect_memcpy", "gt_source_id": "R1", "label": "MMIO_READ", "address": 0x40004400, "function_name": "spi_read_byte", "notes": "SPI SR read"},
    {"binary_stem": "t0_indirect_memcpy", "gt_source_id": "R2", "label": "MMIO_READ", "address": 0x40004404, "function_name": "spi_read_byte", "notes": "SPI DR read"},
    {"binary_stem": "t0_format_string", "gt_source_id": "R1", "label": "MMIO_READ", "address": 0x40011000, "function_name": "uart_read_byte", "notes": "USART SR polling read"},
    {"binary_stem": "t0_format_string", "gt_source_id": "R2", "label": "MMIO_READ", "address": 0x40011004, "function_name": "uart_read_byte", "notes": "USART DR read"},
    {"binary_stem": "t0_func_ptr_dispatch", "gt_source_id": "R1", "label": "MMIO_READ", "address": 0x40011000, "function_name": "uart_read_byte", "notes": "USART SR polling read"},
    {"binary_stem": "t0_func_ptr_dispatch", "gt_source_id": "R2", "label": "MMIO_READ", "address": 0x40011004, "function_name": "uart_read_byte", "notes": "USART DR read"},
    # CVE reproductions
    {"binary_stem": "cve_2020_10065_hci_spi", "gt_source_id": "R1", "label": "MMIO_READ", "address": 0x4001300C, "function_name": "bt_spi_transceive", "notes": "SPI1 data register read"},
    {"binary_stem": "cve_2021_34259_usb_host", "gt_source_id": "R1", "label": "MMIO_READ", "address": 0x50001000, "function_name": "USB_ReadPacket", "notes": "USB FIFO read"},
    {"binary_stem": "cve_2018_16525_freertos_dns", "gt_source_id": "R1", "label": "MMIO_READ", "address": 0x40029000, "function_name": "ETH_ReadFrame", "notes": "ETH RX FIFO read"},
]


def build_normalized_source_gt() -> List[Dict[str, object]]:
    """Build normalized source GT entries."""
    rows: List[Dict[str, object]] = []
    for entry in _SOURCE_GT_CATALOG:
        stem = str(entry["binary_stem"])
        addr = int(entry["address"])
        rows.append({
            "binary_stem": stem,
            "gt_source_id": str(entry["gt_source_id"]),
            "label": str(entry["label"]),
            "function_name": str(entry.get("function_name", "") or ""),
            "address": addr,
            "address_hex": f"0x{addr:08x}",
            "address_status": "resolved",
            "notes": str(entry.get("notes", "") or ""),
            "source_file": f"{stem}.c",
            "map_file": f"{stem}.map",
        })

    rows.sort(key=lambda x: (str(x["binary_stem"]), str(x["gt_source_id"])))
    return rows


def write_normalized_source_gt(
    output_json: Path,
    output_csv: Path,
) -> Dict[str, int]:
    """Generate and write normalized source GT JSON + CSV."""
    rows = build_normalized_source_gt()

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    output_json.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    fieldnames = [
        "binary_stem",
        "gt_source_id",
        "label",
        "function_name",
        "address",
        "address_hex",
        "address_status",
        "notes",
        "source_file",
        "map_file",
    ]
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    samples = {str(r["binary_stem"]) for r in rows}
    return {
        "entry_count": len(rows),
        "sample_count": len(samples),
        "unresolved_count": 0,
    }

