"""Normalized GT sink inventory generator for microbench/CVE samples.

Produces a machine-readable list with:
  - binary stem
  - sink label
  - function name
  - resolved function address (from linker .map)
"""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Dict, List, Optional


# Curated sink GT definitions for the current benchmark set.
# `label` is the semantic GT label; `pipeline_label_hint` is optional and
# indicates which current pipeline sink label is the closest proxy.
_SINK_GT_CATALOG: List[Dict[str, str]] = [
    # T0 microbench
    {
        "binary_stem": "t0_copy_sink",
        "gt_sink_id": "S1",
        "label": "COPY_SINK",
        "function_name": "handler",
        "pipeline_label_hint": "COPY_SINK",
        "notes": "memcpy with DR-controlled length",
    },
    {
        "binary_stem": "t0_copy_sink",
        "gt_sink_id": "S2",
        "label": "COPY_SINK",
        "function_name": "handle_name",
        "pipeline_label_hint": "COPY_SINK",
        "notes": "strcpy unbounded copy",
    },
    {
        "binary_stem": "t0_store_loop_sink",
        "gt_sink_id": "S1",
        "label": "STORE_SINK",
        "function_name": "write_register",
        "pipeline_label_hint": "STORE_SINK",
        "notes": "store through argument pointer",
    },
    {
        "binary_stem": "t0_store_loop_sink",
        "gt_sink_id": "S2",
        "label": "LOOP_WRITE_SINK",
        "function_name": "fill_buffer",
        "pipeline_label_hint": "LOOP_WRITE_SINK",
        "notes": "variable-bound loop write",
    },
    {
        "binary_stem": "t0_store_loop_sink",
        "gt_sink_id": "S3",
        "label": "MEMSET_SINK",
        "function_name": "clear_buffer",
        "pipeline_label_hint": "MEMSET_SINK",
        "notes": "memset with variable length",
    },
    {
        "binary_stem": "t0_uart_rx_overflow",
        "gt_sink_id": "S1",
        "label": "COPY_SINK",
        "function_name": "uart_receive",
        "pipeline_label_hint": "COPY_SINK",
        "notes": "DR-controlled loop writes to fixed buffer",
    },
    {
        "binary_stem": "t0_dma_length_overflow",
        "gt_sink_id": "S1",
        "label": "COPY_SINK",
        "function_name": "process_dma_data",
        "pipeline_label_hint": "COPY_SINK",
        "notes": "memcpy with DMA-controlled length",
    },
    {
        "binary_stem": "t0_indirect_memcpy",
        "gt_sink_id": "S1",
        "label": "COPY_SINK",
        "function_name": "do_copy",
        "pipeline_label_hint": "COPY_SINK",
        "notes": "2-hop taint to memcpy length",
    },
    {
        "binary_stem": "t0_format_string",
        "gt_sink_id": "S1",
        "label": "FORMAT_STRING_SINK",
        "function_name": "log_message",
        "pipeline_label_hint": "",
        "notes": "attacker-controlled format string in sprintf",
    },
    {
        "binary_stem": "t0_func_ptr_dispatch",
        "gt_sink_id": "S1",
        "label": "FUNC_PTR_SINK",
        "function_name": "dispatch_command",
        "pipeline_label_hint": "",
        "notes": "unchecked function-pointer dispatch",
    },
    # CVE reproductions
    {
        "binary_stem": "cve_2020_10065_hci_spi",
        "gt_sink_id": "S1",
        "label": "COPY_SINK",
        "function_name": "bt_spi_rx_thread",
        "pipeline_label_hint": "COPY_SINK",
        "notes": "HCI EVT path overflow",
    },
    {
        "binary_stem": "cve_2020_10065_hci_spi",
        "gt_sink_id": "S2",
        "label": "COPY_SINK",
        "function_name": "bt_spi_rx_thread",
        "pipeline_label_hint": "COPY_SINK",
        "notes": "HCI ACL path overflow",
    },
    {
        "binary_stem": "cve_2021_34259_usb_host",
        "gt_sink_id": "S1",
        "label": "PARSING_OVERFLOW_SINK",
        "function_name": "USBH_ParseCfgDesc",
        "pipeline_label_hint": "STORE_SINK",
        "notes": "wTotalLength-driven overflow path",
    },
    {
        "binary_stem": "cve_2021_34259_usb_host",
        "gt_sink_id": "S2",
        "label": "PARSING_OVERFLOW_SINK",
        "function_name": "USBH_ParseInterfaceDesc",
        "pipeline_label_hint": "STORE_SINK",
        "notes": "bNumEndpoints not clamped",
    },
    {
        "binary_stem": "cve_2021_34259_usb_host",
        "gt_sink_id": "S3",
        "label": "PARSING_OVERFLOW_SINK",
        "function_name": "USBH_ParseEPDesc",
        "pipeline_label_hint": "STORE_SINK",
        "notes": "endpoint descriptor overflow path",
    },
    {
        "binary_stem": "cve_2018_16525_freertos_dns",
        "gt_sink_id": "S1",
        "label": "LENGTH_TRUST_SINK",
        "function_name": "prvProcessIPPacket",
        "pipeline_label_hint": "STORE_SINK",
        "notes": "trusted UDP length propagates unsafe size",
    },
    {
        "binary_stem": "cve_2018_16525_freertos_dns",
        "gt_sink_id": "S2",
        "label": "UNBOUNDED_WALK_SINK",
        "function_name": "prvSkipNameField",
        "pipeline_label_hint": "LOOP_WRITE_SINK",
        "notes": "DNS name walk without bounds",
    },
    {
        "binary_stem": "cve_2018_16525_freertos_dns",
        "gt_sink_id": "S3",
        "label": "COPY_SINK",
        "function_name": "prvParseDNSReply",
        "pipeline_label_hint": "COPY_SINK",
        "notes": "memcpy with corrupted length",
    },
]


_MAP_SYMBOL_RE = re.compile(r"^\s*(0x[0-9A-Fa-f]+)\s+([A-Za-z_][A-Za-z0-9_.$]*)\s*$")
_MAP_TEXT_WITH_ADDR_RE = re.compile(
    r"^\s*\.text\.([A-Za-z_][A-Za-z0-9_.$]*)\s+(0x[0-9A-Fa-f]+)\b.*$",
)
_MAP_TEXT_ONLY_RE = re.compile(r"^\s*\.text\.([A-Za-z_][A-Za-z0-9_.$]*)\s*$")
_MAP_ADDR_SIZE_LINE_RE = re.compile(r"^\s*(0x[0-9A-Fa-f]+)\s+0x[0-9A-Fa-f]+\s+.*$")


def _parse_map_symbols(map_path: Path) -> Dict[str, int]:
    """Parse symbol -> address mapping from a GNU LD .map file."""
    symbols: Dict[str, int] = {}
    if not map_path.exists():
        return symbols

    pending_text_symbol: Optional[str] = None
    lines = map_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    for line in lines:
        # Case A: direct symbol row "0x0800005c symbol".
        m = _MAP_SYMBOL_RE.match(line)
        if not m:
            # Case B: .text.<func> on the same line as address.
            m_text_addr = _MAP_TEXT_WITH_ADDR_RE.match(line)
            if m_text_addr:
                name = m_text_addr.group(1)
                addr = int(m_text_addr.group(2), 16)
                if addr != 0:
                    symbols.setdefault(name, addr)
                pending_text_symbol = None
                continue

            # Case C: .text.<func> followed by next-line address/size row.
            m_text_only = _MAP_TEXT_ONLY_RE.match(line)
            if m_text_only:
                pending_text_symbol = m_text_only.group(1)
                continue

            if pending_text_symbol:
                m_addr_size = _MAP_ADDR_SIZE_LINE_RE.match(line)
                if m_addr_size:
                    addr = int(m_addr_size.group(1), 16)
                    if addr != 0:
                        symbols.setdefault(pending_text_symbol, addr)
                pending_text_symbol = None
            continue

        addr = int(m.group(1), 16)
        name = m.group(2)
        if addr != 0:
            symbols.setdefault(name, addr)
        pending_text_symbol = None
    return symbols


def build_normalized_sink_gt(microbench_dir: Path) -> List[Dict[str, object]]:
    """Build normalized sink GT entries with resolved addresses."""
    by_binary: Dict[str, Dict[str, int]] = {}
    for entry in _SINK_GT_CATALOG:
        stem = entry["binary_stem"]
        if stem in by_binary:
            continue
        by_binary[stem] = _parse_map_symbols(microbench_dir / f"{stem}.map")

    rows: List[Dict[str, object]] = []
    for entry in _SINK_GT_CATALOG:
        stem = entry["binary_stem"]
        fn = entry["function_name"]
        addr: Optional[int] = by_binary.get(stem, {}).get(fn)
        rows.append({
            "binary_stem": stem,
            "gt_sink_id": entry["gt_sink_id"],
            "label": entry["label"],
            "pipeline_label_hint": entry["pipeline_label_hint"] or None,
            "function_name": fn,
            "address": addr,
            "address_hex": f"0x{addr:08x}" if addr is not None else None,
            "address_status": "resolved" if addr is not None else "unresolved",
            "notes": entry["notes"],
            "source_file": f"{stem}.c",
            "map_file": f"{stem}.map",
        })

    rows.sort(key=lambda x: (str(x["binary_stem"]), str(x["gt_sink_id"])))
    return rows


def write_normalized_sink_gt(
    microbench_dir: Path,
    output_json: Path,
    output_csv: Path,
) -> Dict[str, int]:
    """Generate and write normalized sink GT JSON + CSV."""
    rows = build_normalized_sink_gt(microbench_dir)

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    output_json.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    fieldnames = [
        "binary_stem",
        "gt_sink_id",
        "label",
        "pipeline_label_hint",
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

    unresolved = sum(1 for r in rows if r["address_status"] != "resolved")
    samples = {str(r["binary_stem"]) for r in rows}
    return {
        "entry_count": len(rows),
        "sample_count": len(samples),
        "unresolved_count": unresolved,
    }
