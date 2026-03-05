"""Auto-detection of raw ARM Cortex-M firmware binaries.

Detects headerless .bin files by inspecting the interrupt vector table
(first 64 bytes) and returns Ghidra language/base-address hints so the
binary can be imported with the correct processor and memory map.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Optional


def detect_cortex_m_raw(file_path: str | Path) -> Optional[dict]:
    """Detect a raw ARM Cortex-M firmware image from its vector table.

    Reads the first 64 bytes (16 LE uint32 words) and checks:
      - Not an ELF or PE file (has no magic header).
      - Word 0 (Initial SP) is in ARM SRAM range 0x2000_0000..0x20FF_FFFF.
      - Word 1 (Reset vector) has Thumb bit set (odd) and is a plausible
        code address (non-zero upper halfword).
      - Words 7-10 are all zero (ARM reserved vector entries).

    Returns:
        ``{"language": "ARM:LE:32:Cortex", "base_address": "0x08000000"}``
        (base address inferred from reset vector), or ``None`` if the file
        does not look like a Cortex-M vector table.
    """
    try:
        p = Path(file_path)
        if not p.is_file():
            return None

        data = p.read_bytes()
        if len(data) < 64:
            return None
    except OSError:
        return None

    # Reject known executable formats
    if data[:4] == b"\x7fELF":
        return None
    if data[:2] == b"MZ":
        return None

    words = struct.unpack("<16I", data[:64])

    initial_sp = words[0]
    reset_vector = words[1]

    # Initial SP must be in ARM SRAM: 0x20000000..0x20FFFFFF
    if not (0x20000000 <= initial_sp <= 0x20FFFFFF):
        return None

    # Reset vector must have Thumb bit set (odd) and point to real code
    if reset_vector & 1 == 0:
        return None
    if reset_vector < 0x100:
        return None

    # ARM reserved entries (words 7-10) must be zero
    for i in range(7, 11):
        if words[i] != 0:
            return None

    # Infer base address from reset vector
    reset_addr = reset_vector & ~1  # clear Thumb bit
    upper = reset_addr & 0xFFFF0000

    if upper == 0x08000000:
        base_address = "0x08000000"  # STM32 flash
    elif upper == 0x00400000:
        base_address = "0x00400000"  # Zephyr / QEMU
    elif upper == 0x00000000:
        base_address = "0x00000000"  # flash alias
    else:
        base_address = f"0x{upper:08X}"

    return {
        "language": "ARM:LE:32:Cortex",
        "base_address": base_address,
    }
