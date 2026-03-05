"""Stage 1 — Binary loader and memory-map hypothesis generator (M1).

Given a raw .bin or .elf file, produces a MemoryMap with:
  - Architecture hint (from detect_cortex_m_raw or ELF program headers)
  - FLASH / SRAM / PERIPHERAL region hypotheses
  - Vector table location and entry point
  - ISR handler addresses extracted from vector table

ARM Cortex-M canonical memory map:
  0x00000000-0x1FFFFFFF: Code (FLASH alias or actual flash)
  0x20000000-0x3FFFFFFF: SRAM
  0x40000000-0x5FFFFFFF: APB/AHB Peripherals (MMIO)
  0xE0000000-0xFFFFFFFF: System (Cortex-M internal peripherals)

Supports two input formats:
  1. ELF: parse program headers for precise segment layout
  2. Raw .bin: detect vector table, infer base address, apply canonical regions
"""

from __future__ import annotations

import logging
import struct
from pathlib import Path
from typing import List, Optional

from .models import MemoryMap, MemoryRegion
from ..agents.firmware_detect import detect_cortex_m_raw

logger = logging.getLogger("sourceagent.pipeline.loader")

# ARM Cortex-M canonical address ranges
CORTEX_M_FLASH_BASE = 0x00000000
CORTEX_M_FLASH_END = 0x1FFFFFFF
CORTEX_M_SRAM_BASE = 0x20000000
CORTEX_M_SRAM_END = 0x3FFFFFFF
CORTEX_M_MMIO_BASE = 0x40000000
CORTEX_M_MMIO_END = 0x5FFFFFFF
CORTEX_M_SYSTEM_BASE = 0xE0000000
CORTEX_M_SYSTEM_END = 0xFFFFFFFF

# ELF constants
ELF_MAGIC = b"\x7fELF"
ELF_CLASS_32 = 1
ELF_DATA_LE = 1
ELF_MACHINE_ARM = 40
PT_LOAD = 1
PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

# Common STM32 flash bases (for hypothesis scoring)
COMMON_FLASH_BASES = [0x08000000, 0x00000000, 0x00400000, 0x00200000]

# Default SRAM size assumption when we can't determine it
DEFAULT_SRAM_SIZE = 0x20000  # 128KB — conservative for most Cortex-M


def load_binary(binary_path: str | Path) -> Optional[MemoryMap]:
    """Load a firmware binary and produce a MemoryMap.

    Tries ELF parsing first, falls back to raw .bin vector table detection.
    Returns None if the file cannot be recognized as ARM Cortex-M firmware.
    """
    path = Path(binary_path)
    if not path.is_file():
        logger.warning("Not a file: %s", path)
        return None

    try:
        header = path.read_bytes()[:4]
    except OSError as e:
        logger.warning("Cannot read file: %s (%s)", path, e)
        return None

    if header[:4] == ELF_MAGIC:
        result = _load_from_elf(path)
        if result is not None:
            return result
        logger.info("ELF parsing failed, trying raw .bin fallback")

    return _load_from_raw_bin(path)


def _load_from_elf(path: Path) -> Optional[MemoryMap]:
    """Parse ELF program headers to build a precise memory map.

    Handles 32-bit little-endian ARM ELF only (Cortex-M).
    Extracts LOAD segments and classifies them by address range.
    """
    try:
        data = path.read_bytes()
    except OSError as e:
        logger.warning("Cannot read ELF: %s", e)
        return None

    if len(data) < 52:  # Minimum ELF header size (32-bit)
        return None
    if data[:4] != ELF_MAGIC:
        return None

    ei_class = data[4]
    ei_data = data[5]

    if ei_class != ELF_CLASS_32:
        logger.info("Not a 32-bit ELF (class=%d)", ei_class)
        return None
    if ei_data != ELF_DATA_LE:
        logger.info("Not little-endian ELF (data=%d)", ei_data)
        return None

    # Parse ELF header (32-bit LE)
    e_machine = struct.unpack_from("<H", data, 18)[0]
    if e_machine != ELF_MACHINE_ARM:
        logger.info("Not ARM ELF (machine=%d)", e_machine)
        return None

    e_entry = struct.unpack_from("<I", data, 24)[0]
    e_phoff = struct.unpack_from("<I", data, 28)[0]
    e_phentsize = struct.unpack_from("<H", data, 42)[0]
    e_phnum = struct.unpack_from("<H", data, 44)[0]

    if e_phoff == 0 or e_phnum == 0:
        logger.info("No program headers in ELF")
        return None

    # Parse program headers → LOAD segments
    regions: List[MemoryRegion] = []
    flash_base = None

    for i in range(e_phnum):
        offset = e_phoff + i * e_phentsize
        if offset + 32 > len(data):
            break

        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = (
            struct.unpack_from("<8I", data, offset)
        )

        if p_type != PT_LOAD:
            continue
        if p_memsz == 0:
            continue

        # Classify the segment by address range
        perm = _elf_flags_to_perm(p_flags)
        region = _classify_region(p_vaddr, p_memsz, perm)
        regions.append(region)

        # Track the lowest executable/readable segment as flash base
        if p_flags & PF_X and (flash_base is None or p_vaddr < flash_base):
            flash_base = p_vaddr

    if not regions:
        return None

    if flash_base is None:
        # No executable segment — use lowest LOAD vaddr
        flash_base = min(r.base for r in regions)

    # Add canonical MMIO region (not in ELF but always present on Cortex-M)
    has_mmio = any(r.kind == "mmio" for r in regions)
    if not has_mmio:
        regions.append(MemoryRegion(
            name="PERIPHERAL",
            base=CORTEX_M_MMIO_BASE,
            size=CORTEX_M_MMIO_END - CORTEX_M_MMIO_BASE + 1,
            permissions="rw",
            kind="mmio",
        ))

    # Add system peripheral region
    regions.append(MemoryRegion(
        name="SYSTEM",
        base=CORTEX_M_SYSTEM_BASE,
        size=CORTEX_M_SYSTEM_END - CORTEX_M_SYSTEM_BASE + 1,
        permissions="rw",
        kind="mmio",
    ))

    # Parse vector table from flash segment for ISR info
    vt_addr, isr_entries = _parse_vector_table_from_data(data, e_phoff, e_phentsize, e_phnum, flash_base)

    mm = MemoryMap(
        binary_path=str(path),
        arch="ARM:LE:32:Cortex",
        base_address=flash_base,
        entry_point=e_entry,
        regions=sorted(regions, key=lambda r: r.base),
        vector_table_addr=vt_addr,
        hypotheses_source="elf_segments",
        isr_handler_addrs=isr_entries,
    )

    logger.info(
        "ELF loaded: base=0x%08x entry=0x%08x regions=%d ISRs=%d",
        flash_base, e_entry, len(regions), len(isr_entries),
    )
    return mm


def _load_from_raw_bin(path: Path) -> Optional[MemoryMap]:
    """Use detect_cortex_m_raw() for vector table heuristics,
    then apply canonical Cortex-M region map.

    Steps:
      1. Detect ARM Cortex-M via vector table inspection
      2. Parse base address from detection result
      3. Build canonical regions: FLASH (backed by .bin bytes), SRAM, MMIO, SYSTEM
      4. Parse vector table entries for ISR handler addresses
    """
    hint = detect_cortex_m_raw(path)
    if hint is None:
        logger.info("Not recognized as ARM Cortex-M raw firmware: %s", path)
        return None

    try:
        file_data = path.read_bytes()
    except OSError:
        return None

    base_address = int(hint["base_address"], 16)
    file_size = len(file_data)

    # Parse vector table
    words = struct.unpack("<16I", file_data[:64])
    initial_sp = words[0]
    reset_vector = words[1] & ~1  # clear Thumb bit

    # Infer SRAM size from initial SP
    # SP is typically at top of SRAM: sp = sram_base + sram_size
    sram_base = CORTEX_M_SRAM_BASE
    sp_offset = initial_sp - sram_base
    # Round up to nearest power of 2 for a plausible SRAM size
    sram_size = _round_up_power_of_2(sp_offset) if sp_offset > 0 else DEFAULT_SRAM_SIZE

    # Build canonical memory regions
    regions = [
        MemoryRegion(
            name="FLASH",
            base=base_address,
            size=file_size,
            permissions="rx",
            kind="flash",
        ),
        MemoryRegion(
            name="SRAM",
            base=sram_base,
            size=sram_size,
            permissions="rw",
            kind="sram",
        ),
        MemoryRegion(
            name="PERIPHERAL",
            base=CORTEX_M_MMIO_BASE,
            size=CORTEX_M_MMIO_END - CORTEX_M_MMIO_BASE + 1,
            permissions="rw",
            kind="mmio",
        ),
        MemoryRegion(
            name="SYSTEM",
            base=CORTEX_M_SYSTEM_BASE,
            size=CORTEX_M_SYSTEM_END - CORTEX_M_SYSTEM_BASE + 1,
            permissions="rw",
            kind="mmio",
        ),
    ]

    # If base_address is 0x08000000, also add the flash alias at 0x00000000
    if base_address == 0x08000000:
        regions.insert(0, MemoryRegion(
            name="FLASH_ALIAS",
            base=0x00000000,
            size=file_size,
            permissions="rx",
            kind="flash",
        ))

    # Parse extended vector table (beyond the first 16 words)
    isr_entries = parse_vector_table(file_data, base_address, file_size)

    mm = MemoryMap(
        binary_path=str(path),
        arch=hint["language"],
        base_address=base_address,
        entry_point=reset_vector,
        regions=sorted(regions, key=lambda r: r.base),
        vector_table_addr=base_address,  # Vector table is at start of .bin
        hypotheses_source="vector_table",
        isr_handler_addrs=isr_entries,
    )

    logger.info(
        "Raw .bin loaded: base=0x%08x entry=0x%08x sram=%dKB ISRs=%d file=%dB",
        base_address, reset_vector, sram_size // 1024, len(isr_entries), file_size,
    )
    return mm


# ── Vector table parsing ────────────────────────────────────────────────────


def parse_vector_table(
    data: bytes,
    base_address: int,
    file_size: int,
    max_entries: int = 256,
) -> List[int]:
    """Parse ARM Cortex-M vector table and return unique ISR handler addresses.

    The vector table layout:
      Word 0: Initial SP (not a handler)
      Word 1: Reset vector
      Words 2-15: Core exception handlers (NMI, HardFault, etc.)
      Words 16+: Peripheral IRQ handlers (MCU-specific)

    We scan until we find an entry that doesn't look like a valid code pointer
    (not odd/Thumb, not in plausible code range, or past max_entries).

    Returns list of unique, non-zero ISR handler addresses (Thumb bit cleared).
    """
    code_end = base_address + file_size
    handlers = set()

    # Determine how many words we can read
    max_words = min(max_entries, len(data) // 4)

    for i in range(2, max_words):  # Skip word 0 (SP) and word 1 (Reset)
        if i * 4 + 4 > len(data):
            break

        word = struct.unpack_from("<I", data, i * 4)[0]

        if word == 0:
            continue  # Zero entries are valid (unused/reserved)

        # Valid Thumb code pointer?
        if word & 1 == 0:
            # Even address — not a valid Thumb handler
            # This likely means we've read past the vector table into code
            break

        addr = word & ~1  # Clear Thumb bit

        # Must point within the code region
        if not (base_address <= addr < code_end):
            # Out of range — likely past the vector table
            break

        handlers.add(addr)

    return sorted(handlers)


def _parse_vector_table_from_data(
    elf_data: bytes,
    e_phoff: int,
    e_phentsize: int,
    e_phnum: int,
    flash_base: int,
) -> tuple[int, List[int]]:
    """Extract vector table from ELF by finding the LOAD segment at flash_base.

    Returns (vector_table_addr, list_of_isr_addresses).
    """
    for i in range(e_phnum):
        offset = e_phoff + i * e_phentsize
        if offset + 32 > len(elf_data):
            break

        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, _ = (
            struct.unpack_from("<8I", elf_data, offset)
        )

        if p_type != PT_LOAD:
            continue

        # Find the segment that contains the vector table (starts at flash_base)
        if p_vaddr == flash_base and p_filesz >= 64:
            segment_data = elf_data[p_offset:p_offset + p_filesz]
            isr_entries = parse_vector_table(segment_data, flash_base, p_filesz)
            return flash_base, isr_entries

    return flash_base, []


# ── Helpers ─────────────────────────────────────────────────────────────────


def _elf_flags_to_perm(flags: int) -> str:
    """Convert ELF p_flags to permission string."""
    return (
        ("r" if flags & PF_R else "")
        + ("w" if flags & PF_W else "")
        + ("x" if flags & PF_X else "")
    ) or "r"


def _classify_region(vaddr: int, memsz: int, perm: str) -> MemoryRegion:
    """Classify a memory region by its address range."""
    if CORTEX_M_SRAM_BASE <= vaddr <= CORTEX_M_SRAM_END:
        return MemoryRegion(name="SRAM", base=vaddr, size=memsz, permissions=perm, kind="sram")
    elif CORTEX_M_MMIO_BASE <= vaddr <= CORTEX_M_MMIO_END:
        return MemoryRegion(name="PERIPHERAL", base=vaddr, size=memsz, permissions=perm, kind="mmio")
    elif CORTEX_M_SYSTEM_BASE <= vaddr:
        return MemoryRegion(name="SYSTEM", base=vaddr, size=memsz, permissions=perm, kind="mmio")
    elif vaddr < CORTEX_M_SRAM_BASE:
        # Anything below SRAM is code/flash region
        name = "FLASH" if "x" in perm else "RODATA"
        return MemoryRegion(name=name, base=vaddr, size=memsz, permissions=perm, kind="flash")
    else:
        return MemoryRegion(name="UNKNOWN", base=vaddr, size=memsz, permissions=perm, kind="unknown")


def _round_up_power_of_2(n: int) -> int:
    """Round up to the nearest power of 2. Useful for inferring SRAM size."""
    if n <= 0:
        return 0
    p = 1
    while p < n:
        p <<= 1
    return p


def is_mmio_address(addr: int) -> bool:
    """Check if an address falls in the Cortex-M peripheral MMIO range."""
    return CORTEX_M_MMIO_BASE <= addr <= CORTEX_M_MMIO_END


def is_sram_address(addr: int) -> bool:
    """Check if an address falls in the Cortex-M SRAM range."""
    return CORTEX_M_SRAM_BASE <= addr <= CORTEX_M_SRAM_END


def is_flash_address(addr: int) -> bool:
    """Check if an address falls in the Cortex-M code/flash range."""
    return CORTEX_M_FLASH_BASE <= addr <= CORTEX_M_FLASH_END
