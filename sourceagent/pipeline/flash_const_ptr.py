"""Scan raw firmware .bin for flash-resident constant pointers to MMIO addresses.

In decompiled C from Ghidra, raw .bin firmware uses flash constant pointers
(e.g. DAT_080022xx) that resolve to MMIO addresses at runtime but are invisible
to the regex-based access parser. This module scans the raw binary for 4-byte
LE words that fall in MMIO/system peripheral ranges, producing a lookup table
of {flash_addr: mmio_value} for post-hoc resolution in the MAI builder.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Dict

from .loader import is_mmio_address


def _is_peripheral_value(val: int) -> bool:
    """Check if a 32-bit value is an MMIO or system peripheral address."""
    return is_mmio_address(val) or (0xE0000000 <= val <= 0xFFFFFFFF)


def build_flash_const_ptr_table(
    bin_path: Path,
    base_address: int = 0x08000000,
) -> Dict[int, int]:
    """Scan .bin as 4-byte LE words; return {flash_addr: mmio_value} for MMIO pointers.

    Example: if offset 0x2200 contains bytes [00 10 01 40], then
    flash_addr=0x0800_2200 maps to mmio_value=0x4001_1000.

    Args:
        bin_path: Path to the raw .bin firmware file.
        base_address: Flash base address (typically 0x08000000 for STM32).

    Returns:
        Dict mapping flash addresses to their MMIO target values.
    """
    data = Path(bin_path).read_bytes()
    table: Dict[int, int] = {}

    # Scan 4-byte aligned words
    for offset in range(0, len(data) - 3, 4):
        val = struct.unpack_from("<I", data, offset)[0]
        if _is_peripheral_value(val):
            flash_addr = base_address + offset
            table[flash_addr] = val

    return table
