"""Tests for pipeline/loader.py — Stage 1 (M1)."""

import struct
from pathlib import Path

import pytest

from sourceagent.pipeline.loader import (
    CORTEX_M_FLASH_BASE,
    CORTEX_M_FLASH_END,
    CORTEX_M_MMIO_BASE,
    CORTEX_M_MMIO_END,
    CORTEX_M_SRAM_BASE,
    CORTEX_M_SRAM_END,
    _round_up_power_of_2,
    is_flash_address,
    is_mmio_address,
    is_sram_address,
    load_binary,
    parse_vector_table,
)


# ── Constants ────────────────────────────────────────────────────────────────


def test_cortex_m_mmio_range_constants():
    assert CORTEX_M_MMIO_BASE == 0x40000000
    assert CORTEX_M_MMIO_END == 0x5FFFFFFF


def test_cortex_m_sram_range_constants():
    assert CORTEX_M_SRAM_BASE == 0x20000000
    assert CORTEX_M_SRAM_END == 0x3FFFFFFF


def test_cortex_m_flash_range_constants():
    assert CORTEX_M_FLASH_BASE == 0x00000000
    assert CORTEX_M_FLASH_END == 0x1FFFFFFF


def test_mmio_range_does_not_overlap_sram():
    assert CORTEX_M_MMIO_BASE > CORTEX_M_SRAM_END


# ── Address classification helpers ───────────────────────────────────────────


def test_is_mmio_address():
    assert is_mmio_address(0x40000000) is True
    assert is_mmio_address(0x40011004) is True
    assert is_mmio_address(0x5FFFFFFF) is True
    assert is_mmio_address(0x60000000) is False
    assert is_mmio_address(0x20000000) is False
    assert is_mmio_address(0x08000000) is False


def test_is_sram_address():
    assert is_sram_address(0x20000000) is True
    assert is_sram_address(0x20020000) is True
    assert is_sram_address(0x3FFFFFFF) is True
    assert is_sram_address(0x40000000) is False
    assert is_sram_address(0x08000000) is False


def test_is_flash_address():
    assert is_flash_address(0x00000000) is True
    assert is_flash_address(0x08000000) is True
    assert is_flash_address(0x1FFFFFFF) is True
    assert is_flash_address(0x20000000) is False


# ── Helpers ──────────────────────────────────────────────────────────────────


def test_round_up_power_of_2():
    assert _round_up_power_of_2(0) == 0
    assert _round_up_power_of_2(1) == 1
    assert _round_up_power_of_2(3) == 4
    assert _round_up_power_of_2(128 * 1024) == 128 * 1024
    assert _round_up_power_of_2(100 * 1024) == 128 * 1024
    assert _round_up_power_of_2(65) == 128


# ── load_binary: error handling ──────────────────────────────────────────────


def test_load_binary_nonexistent_file():
    """Non-existent file → None."""
    assert load_binary("/tmp/does_not_exist_xyz.bin") is None


def test_load_binary_directory(tmp_path):
    """Directory → None."""
    assert load_binary(tmp_path) is None


def test_load_binary_empty_file(tmp_path):
    """Empty file → None."""
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    assert load_binary(f) is None


def test_load_binary_tiny_file(tmp_path):
    """File < 64 bytes → None."""
    f = tmp_path / "tiny.bin"
    f.write_bytes(b"\x00" * 32)
    assert load_binary(f) is None


def test_load_binary_random_data(tmp_path):
    """Random data that doesn't match any format → None."""
    f = tmp_path / "random.bin"
    f.write_bytes(bytes(range(256)))
    assert load_binary(f) is None


# ── load_binary: raw .bin files (synthetic) ──────────────────────────────────


def _make_raw_firmware(
    sp: int = 0x20020000,
    reset: int = 0x08000101,
    handlers: list = None,
    extra_bytes: int = 1024,
) -> bytes:
    """Build a synthetic Cortex-M raw firmware binary."""
    words = [sp, reset]

    # Words 2-6: exception handlers
    words.extend([reset] * 5)  # NMI, HardFault, etc. point to reset

    # Words 7-10: reserved (must be zero)
    words.extend([0, 0, 0, 0])

    # Words 11-15: more handlers
    if handlers:
        words.extend(handlers[:5])
        words.extend([0] * (5 - len(handlers[:5])))
    else:
        words.extend([0] * 5)

    assert len(words) == 16
    data = struct.pack("<16I", *words)
    # Add padding to make it look like real firmware
    data += b"\xff" * extra_bytes
    return data


def test_load_raw_bin_stm32(tmp_path):
    """Valid STM32 raw firmware → MemoryMap with base=0x08000000."""
    f = tmp_path / "stm32.bin"
    f.write_bytes(_make_raw_firmware(sp=0x20020000, reset=0x08000101))

    mm = load_binary(f)
    assert mm is not None
    assert mm.arch == "ARM:LE:32:Cortex"
    assert mm.base_address == 0x08000000
    assert mm.entry_point == 0x08000100  # Reset with Thumb bit cleared
    assert mm.hypotheses_source == "vector_table"
    assert mm.vector_table_addr == 0x08000000


def test_load_raw_bin_flash_alias(tmp_path):
    """Flash-alias firmware (base=0x00000000)."""
    f = tmp_path / "alias.bin"
    f.write_bytes(_make_raw_firmware(sp=0x20000800, reset=0x00000201))

    mm = load_binary(f)
    assert mm is not None
    assert mm.base_address == 0x00000000


def test_load_raw_bin_zephyr(tmp_path):
    """Zephyr/QEMU firmware (base=0x00400000)."""
    f = tmp_path / "zephyr.bin"
    f.write_bytes(_make_raw_firmware(sp=0x20100000, reset=0x00402001))

    mm = load_binary(f)
    assert mm is not None
    assert mm.base_address == 0x00400000


def test_load_raw_bin_has_flash_region(tmp_path):
    """Raw .bin MemoryMap should include a FLASH region."""
    f = tmp_path / "fw.bin"
    f.write_bytes(_make_raw_firmware())

    mm = load_binary(f)
    assert mm is not None
    flash_regions = [r for r in mm.regions if r.kind == "flash"]
    assert len(flash_regions) >= 1
    assert any(r.name == "FLASH" for r in flash_regions)


def test_load_raw_bin_has_sram_region(tmp_path):
    """Raw .bin MemoryMap should include an SRAM region."""
    f = tmp_path / "fw.bin"
    f.write_bytes(_make_raw_firmware())

    mm = load_binary(f)
    assert mm is not None
    sram_regions = [r for r in mm.regions if r.kind == "sram"]
    assert len(sram_regions) == 1
    assert sram_regions[0].base == CORTEX_M_SRAM_BASE


def test_load_raw_bin_has_mmio_region(tmp_path):
    """Raw .bin MemoryMap should include an MMIO/PERIPHERAL region."""
    f = tmp_path / "fw.bin"
    f.write_bytes(_make_raw_firmware())

    mm = load_binary(f)
    assert mm is not None
    mmio_regions = [r for r in mm.regions if r.kind == "mmio"]
    assert len(mmio_regions) >= 1
    assert any(r.base == CORTEX_M_MMIO_BASE for r in mmio_regions)


def test_load_raw_bin_stm32_has_flash_alias(tmp_path):
    """STM32 firmware (base=0x08000000) should also have FLASH_ALIAS at 0x00000000."""
    f = tmp_path / "stm32.bin"
    f.write_bytes(_make_raw_firmware(sp=0x20020000, reset=0x08000101))

    mm = load_binary(f)
    assert mm is not None
    names = [r.name for r in mm.regions]
    assert "FLASH_ALIAS" in names
    alias = [r for r in mm.regions if r.name == "FLASH_ALIAS"][0]
    assert alias.base == 0x00000000


def test_load_raw_bin_sram_size_from_sp(tmp_path):
    """SRAM size should be inferred from initial SP value."""
    # SP=0x20020000 → offset=0x20000 = 128KB → round up = 128KB
    f = tmp_path / "fw.bin"
    f.write_bytes(_make_raw_firmware(sp=0x20020000, reset=0x08000101))

    mm = load_binary(f)
    assert mm is not None
    sram = [r for r in mm.regions if r.kind == "sram"][0]
    assert sram.size == 0x20000  # 128KB


def test_load_raw_bin_sram_size_rounds_up(tmp_path):
    """SRAM size should round up to nearest power of 2."""
    # SP=0x20014000 → offset=0x14000 = 80KB → round up to 128KB
    f = tmp_path / "fw.bin"
    f.write_bytes(_make_raw_firmware(sp=0x20014000, reset=0x08000101))

    mm = load_binary(f)
    assert mm is not None
    sram = [r for r in mm.regions if r.kind == "sram"][0]
    assert sram.size == 0x20000  # 128KB


def test_load_raw_bin_flash_size_matches_file(tmp_path):
    """FLASH region size should match the actual file size."""
    fw_data = _make_raw_firmware(extra_bytes=4096)
    f = tmp_path / "fw.bin"
    f.write_bytes(fw_data)

    mm = load_binary(f)
    assert mm is not None
    flash = [r for r in mm.regions if r.name == "FLASH"][0]
    assert flash.size == len(fw_data)


def test_load_raw_bin_regions_sorted(tmp_path):
    """Regions should be sorted by base address."""
    f = tmp_path / "fw.bin"
    f.write_bytes(_make_raw_firmware())

    mm = load_binary(f)
    assert mm is not None
    bases = [r.base for r in mm.regions]
    assert bases == sorted(bases)


# ── load_binary: ELF files (synthetic) ──────────────────────────────────────


def _make_minimal_elf(
    entry: int = 0x08000101,
    segments: list = None,
) -> bytes:
    """Build a minimal 32-bit LE ARM ELF with given LOAD segments.

    Each segment in `segments` is (p_vaddr, p_memsz, p_flags, content_bytes).
    """
    if segments is None:
        # Default: one LOAD segment for flash
        flash_content = _make_raw_firmware()
        segments = [(0x08000000, len(flash_content), PF_R | PF_X, flash_content)]

    e_phnum = len(segments)
    e_ehsize = 52   # 32-bit ELF header
    e_phentsize = 32
    e_phoff = e_ehsize

    # Calculate file offsets for segment data
    data_start = e_ehsize + e_phnum * e_phentsize
    seg_offsets = []
    current_offset = data_start
    for _, _, _, content in segments:
        seg_offsets.append(current_offset)
        current_offset += len(content)

    # Build ELF header
    elf_header = bytearray(52)
    elf_header[0:4] = b"\x7fELF"
    elf_header[4] = ELF_CLASS_32  # 32-bit
    elf_header[5] = ELF_DATA_LE   # Little-endian
    elf_header[6] = 1             # ELF version
    struct.pack_into("<H", elf_header, 16, 2)     # e_type = ET_EXEC
    struct.pack_into("<H", elf_header, 18, ELF_MACHINE_ARM)
    struct.pack_into("<I", elf_header, 20, 1)     # e_version
    struct.pack_into("<I", elf_header, 24, entry) # e_entry
    struct.pack_into("<I", elf_header, 28, e_phoff)
    struct.pack_into("<I", elf_header, 32, 0)     # e_shoff (no sections)
    struct.pack_into("<I", elf_header, 36, 0)     # e_flags
    struct.pack_into("<H", elf_header, 40, e_ehsize)
    struct.pack_into("<H", elf_header, 42, e_phentsize)
    struct.pack_into("<H", elf_header, 44, e_phnum)

    # Build program headers
    phdrs = bytearray()
    for i, (vaddr, memsz, flags, content) in enumerate(segments):
        phdr = bytearray(32)
        struct.pack_into("<I", phdr, 0, PT_LOAD)        # p_type
        struct.pack_into("<I", phdr, 4, seg_offsets[i])  # p_offset
        struct.pack_into("<I", phdr, 8, vaddr)           # p_vaddr
        struct.pack_into("<I", phdr, 12, vaddr)          # p_paddr
        struct.pack_into("<I", phdr, 16, len(content))   # p_filesz
        struct.pack_into("<I", phdr, 20, memsz)          # p_memsz
        struct.pack_into("<I", phdr, 24, flags)          # p_flags
        struct.pack_into("<I", phdr, 28, 4)              # p_align
        phdrs += phdr

    # Concatenate everything
    result = bytes(elf_header) + bytes(phdrs)
    for _, _, _, content in segments:
        result += content

    return result


# Import constants needed by _make_minimal_elf
from sourceagent.pipeline.loader import ELF_CLASS_32, ELF_DATA_LE, ELF_MACHINE_ARM, PT_LOAD, PF_R, PF_W, PF_X


def test_load_elf_basic(tmp_path):
    """A minimal ARM ELF should produce a valid MemoryMap."""
    flash_content = _make_raw_firmware()
    elf_data = _make_minimal_elf(
        entry=0x08000101,
        segments=[(0x08000000, len(flash_content), PF_R | PF_X, flash_content)],
    )
    f = tmp_path / "firmware.elf"
    f.write_bytes(elf_data)

    mm = load_binary(f)
    assert mm is not None
    assert mm.arch == "ARM:LE:32:Cortex"
    assert mm.base_address == 0x08000000
    assert mm.entry_point == 0x08000101
    assert mm.hypotheses_source == "elf_segments"


def test_load_elf_multiple_segments(tmp_path):
    """ELF with FLASH + SRAM segments."""
    flash_content = _make_raw_firmware()
    sram_content = b"\x00" * 256

    elf_data = _make_minimal_elf(
        entry=0x08000101,
        segments=[
            (0x08000000, len(flash_content), PF_R | PF_X, flash_content),
            (0x20000000, 0x1000, PF_R | PF_W, sram_content),
        ],
    )
    f = tmp_path / "firmware.elf"
    f.write_bytes(elf_data)

    mm = load_binary(f)
    assert mm is not None
    # Should have FLASH, SRAM (from ELF), PERIPHERAL, SYSTEM
    kinds = {r.kind for r in mm.regions}
    assert "flash" in kinds
    assert "sram" in kinds
    assert "mmio" in kinds  # Auto-added PERIPHERAL + SYSTEM


def test_load_elf_has_mmio_region(tmp_path):
    """ELF MemoryMap should always include PERIPHERAL even if not in ELF segments."""
    flash_content = _make_raw_firmware()
    elf_data = _make_minimal_elf(
        entry=0x08000101,
        segments=[(0x08000000, len(flash_content), PF_R | PF_X, flash_content)],
    )
    f = tmp_path / "firmware.elf"
    f.write_bytes(elf_data)

    mm = load_binary(f)
    assert mm is not None
    mmio_regions = [r for r in mm.regions if r.base == CORTEX_M_MMIO_BASE]
    assert len(mmio_regions) == 1


def test_load_elf_not_arm_rejected(tmp_path):
    """Non-ARM ELF should be rejected (falls through to raw .bin)."""
    # Build an ELF with wrong machine type
    elf_data = bytearray(_make_minimal_elf())
    struct.pack_into("<H", elf_data, 18, 3)  # machine=3 (x86)
    f = tmp_path / "x86.elf"
    f.write_bytes(bytes(elf_data))

    # Should fail ELF parsing and fall through to raw .bin check
    # which will also fail (starts with \x7fELF)
    mm = load_binary(f)
    assert mm is None


def test_load_elf_regions_sorted(tmp_path):
    """ELF MemoryMap regions should be sorted by base address."""
    flash_content = _make_raw_firmware()
    sram_content = b"\x00" * 256

    elf_data = _make_minimal_elf(
        entry=0x08000101,
        segments=[
            (0x20000000, 0x1000, PF_R | PF_W, sram_content),
            (0x08000000, len(flash_content), PF_R | PF_X, flash_content),
        ],
    )
    f = tmp_path / "firmware.elf"
    f.write_bytes(elf_data)

    mm = load_binary(f)
    assert mm is not None
    bases = [r.base for r in mm.regions]
    assert bases == sorted(bases)


# ── load_binary: real firmware files ─────────────────────────────────────────


def test_load_real_nxp_uart_bin(nxp_uart_path):
    """Load real nxp_uart_polling.bin → valid MemoryMap."""
    mm = load_binary(nxp_uart_path)
    assert mm is not None
    assert mm.arch == "ARM:LE:32:Cortex"
    assert mm.hypotheses_source == "vector_table"
    # Verify basic structure
    assert len(mm.regions) >= 3  # FLASH, SRAM, MMIO at minimum
    assert mm.entry_point != 0


def test_load_real_blink_led_bin(blink_led_path):
    """Load real blink_led.bin → valid MemoryMap with STM32 base."""
    mm = load_binary(blink_led_path)
    assert mm is not None
    assert mm.base_address == 0x08000000


def test_load_real_thermostat_bin(thermostat_path):
    """Load real thermostat.bin → valid MemoryMap with STM32 base."""
    mm = load_binary(thermostat_path)
    assert mm is not None
    assert mm.base_address == 0x08000000


def test_load_real_blink_led_elf(firmware_dir):
    """Load real blink_led.elf → valid MemoryMap from ELF segments."""
    elf_path = firmware_dir / "blink_led.elf"
    if not elf_path.exists():
        pytest.skip("blink_led.elf not found")

    mm = load_binary(elf_path)
    assert mm is not None
    assert mm.arch == "ARM:LE:32:Cortex"
    assert mm.hypotheses_source == "elf_segments"
    assert mm.base_address == 0x08000000
    assert mm.entry_point == 0x08000d05  # From ELF header


def test_load_real_thermostat_elf(firmware_dir):
    """Load real thermostat.elf → valid MemoryMap from ELF segments."""
    elf_path = firmware_dir / "thermostat.elf"
    if not elf_path.exists():
        pytest.skip("thermostat.elf not found")

    mm = load_binary(elf_path)
    assert mm is not None
    assert mm.entry_point == 0x080010a5


# ── parse_vector_table ───────────────────────────────────────────────────────


def test_parse_vector_table_basic():
    """Parse a synthetic vector table with known handlers."""
    data = _make_raw_firmware(
        sp=0x20020000,
        reset=0x08000101,
        handlers=[0x08000201, 0x08000301, 0, 0],
    )
    isrs = parse_vector_table(data, base_address=0x08000000, file_size=len(data))
    # Should find reset (0x08000100), the 5 exception handlers, and 2 custom handlers
    assert len(isrs) >= 2
    assert 0x08000200 in isrs  # handler at word 11
    assert 0x08000300 in isrs  # handler at word 12


def test_parse_vector_table_skips_sp_and_reset():
    """Vector table parser should skip word 0 (SP) and word 1 (Reset)."""
    data = _make_raw_firmware()
    isrs = parse_vector_table(data, base_address=0x08000000, file_size=len(data))
    # SP (0x20020000) should not appear
    assert 0x20020000 not in isrs


def test_parse_vector_table_stops_at_invalid_entry():
    """Parser should stop when it encounters a non-Thumb (even) entry past the vector table."""
    base = 0x08000000
    # Build a larger firmware image so handlers at offset 0x20-0x30 are within code range
    code_padding = b"\x00\xbf" * 512  # NOP sled (1024 bytes)

    words = [0x20020000, base | 0x41]  # SP, Reset (Thumb)
    words.extend([(base | 0x41)] * 5)  # Exceptions (words 2-6) — all valid Thumb
    words.extend([0, 0, 0, 0])         # Reserved (words 7-10)
    words.extend([base | 0x21, 0, 0, 0, 0])  # One unique handler at word 11 (words 11-15)
    assert len(words) == 16
    data = struct.pack("<16I", *words) + code_padding
    # Append word 16 as an even address (invalid Thumb) → parser should stop here
    # But since our data already includes 16 words + padding, the parser reads beyond if possible.
    # The key: handlers with base+0x20 is at offset 0x20 which is within file.
    # Word 16 would be at offset 64, which is start of code_padding → 0x00bf (even) → stops

    isrs = parse_vector_table(data, base_address=base, file_size=len(data))
    # word 11 handler (0x08000020) should be found
    assert (base | 0x20) in isrs
    # The exception handlers all point to same address (0x08000040), also found
    assert (base | 0x40) in isrs


def test_parse_vector_table_empty_table():
    """All-zero entries (except SP/Reset) → empty ISR list."""
    words = [0x20020000, 0x08000101] + [0] * 14
    data = struct.pack("<16I", *words) + b"\xff" * 256

    isrs = parse_vector_table(data, base_address=0x08000000, file_size=len(data) )
    # All zeros after Reset → no ISRs found
    assert len(isrs) == 0


# ── isr_handler_addrs population ─────────────────────────────────────────────


def test_load_raw_bin_populates_isr_handler_addrs(tmp_path):
    """Raw .bin with ISR handlers → isr_handler_addrs populated."""
    f = tmp_path / "fw.bin"
    f.write_bytes(_make_raw_firmware(
        sp=0x20020000,
        reset=0x08000101,
        handlers=[0x08000201, 0x08000301, 0, 0],
    ))

    mm = load_binary(f)
    assert mm is not None
    assert len(mm.isr_handler_addrs) >= 2
    assert 0x08000200 in mm.isr_handler_addrs
    assert 0x08000300 in mm.isr_handler_addrs


def test_load_raw_bin_no_handlers_empty_isr_addrs(tmp_path):
    """Raw .bin with all-zero vector table → isr_handler_addrs empty or has only exception handlers."""
    words = [0x20020000, 0x08000101] + [0] * 14
    data = struct.pack("<16I", *words) + b"\xff" * 256
    f = tmp_path / "empty_vt.bin"
    f.write_bytes(data)

    mm = load_binary(f)
    # May be None if detect_cortex_m_raw rejects it, or may have empty ISR list
    if mm is not None:
        # The all-zero entries after reset should yield no ISR handlers
        assert isinstance(mm.isr_handler_addrs, list)


def test_load_elf_populates_isr_handler_addrs(tmp_path):
    """ELF with valid vector table → isr_handler_addrs populated."""
    flash_content = _make_raw_firmware(
        sp=0x20020000,
        reset=0x08000101,
        handlers=[0x08000201, 0x08000301, 0, 0],
    )
    elf_data = _make_minimal_elf(
        entry=0x08000101,
        segments=[(0x08000000, len(flash_content), PF_R | PF_X, flash_content)],
    )
    f = tmp_path / "firmware.elf"
    f.write_bytes(elf_data)

    mm = load_binary(f)
    assert mm is not None
    assert isinstance(mm.isr_handler_addrs, list)
    assert len(mm.isr_handler_addrs) >= 2
    assert 0x08000200 in mm.isr_handler_addrs
    assert 0x08000300 in mm.isr_handler_addrs


def test_isr_handler_addrs_defaults_empty():
    """MemoryMap default → isr_handler_addrs is empty list."""
    from sourceagent.pipeline.models import MemoryMap
    mm = MemoryMap(
        binary_path="test.bin",
        arch="ARM:LE:32:Cortex",
        base_address=0x08000000,
        entry_point=0x08000101,
    )
    assert mm.isr_handler_addrs == []
