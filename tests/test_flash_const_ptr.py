"""Tests for pipeline/flash_const_ptr.py — flash constant pointer scanner."""

import struct
import tempfile
from pathlib import Path

import pytest

from sourceagent.pipeline.flash_const_ptr import (
    build_flash_const_ptr_table,
    _is_peripheral_value,
)


def _write_bin(words: list[int], tmp_path: Path) -> Path:
    """Write a list of 32-bit LE words to a temporary .bin file."""
    data = b"".join(struct.pack("<I", w) for w in words)
    p = tmp_path / "test.bin"
    p.write_bytes(data)
    return p


# ── _is_peripheral_value tests ───────────────────────────────────────────────


def test_mmio_address_is_peripheral():
    assert _is_peripheral_value(0x40011000)  # USART1 on STM32


def test_system_address_is_peripheral():
    assert _is_peripheral_value(0xE000E100)  # NVIC


def test_sram_address_not_peripheral():
    assert not _is_peripheral_value(0x20000100)


def test_flash_address_not_peripheral():
    assert not _is_peripheral_value(0x08001000)


def test_zero_not_peripheral():
    assert not _is_peripheral_value(0x00000000)


# ── build_flash_const_ptr_table tests ─────────────────────────────────────────


def test_mmio_pointer_found(tmp_path):
    """MMIO address at known offset should appear in table."""
    # Offset 0x100: MMIO addr 0x40011000
    words = [0] * 64 + [0x40011000]
    p = _write_bin(words, tmp_path)
    table = build_flash_const_ptr_table(p, base_address=0x08000000)
    flash_addr = 0x08000000 + 64 * 4  # offset 0x100
    assert flash_addr in table
    assert table[flash_addr] == 0x40011000


def test_sram_pointer_excluded(tmp_path):
    """SRAM address should NOT be in the table."""
    words = [0x20000100]
    p = _write_bin(words, tmp_path)
    table = build_flash_const_ptr_table(p, base_address=0x08000000)
    assert len(table) == 0


def test_system_peripheral_included(tmp_path):
    """System peripheral address (0xE000E100 = NVIC) should be in the table."""
    words = [0xE000E100]
    p = _write_bin(words, tmp_path)
    table = build_flash_const_ptr_table(p, base_address=0x08000000)
    assert 0x08000000 in table
    assert table[0x08000000] == 0xE000E100


def test_empty_bin(tmp_path):
    """Empty file should produce empty table."""
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    table = build_flash_const_ptr_table(p, base_address=0x08000000)
    assert table == {}


def test_custom_base_address(tmp_path):
    """Custom base address should shift flash_addr keys accordingly."""
    words = [0x40021000]
    p = _write_bin(words, tmp_path)
    table = build_flash_const_ptr_table(p, base_address=0x00000000)
    assert 0x00000000 in table
    assert table[0x00000000] == 0x40021000


def test_flash_address_excluded(tmp_path):
    """Flash-range address (0x08001000) should NOT be treated as MMIO."""
    words = [0x08001000]
    p = _write_bin(words, tmp_path)
    table = build_flash_const_ptr_table(p, base_address=0x08000000)
    assert len(table) == 0


def test_vector_table_sram_sp_init_excluded(tmp_path):
    """First word (SP init, typically SRAM like 0x20010000) should be excluded."""
    words = [0x20010000, 0x08000101]  # SP init + reset vector
    p = _write_bin(words, tmp_path)
    table = build_flash_const_ptr_table(p, base_address=0x08000000)
    assert len(table) == 0


def test_multiple_mmio_pointers(tmp_path):
    """Multiple MMIO pointers should all appear in the table."""
    words = [0x40011000, 0x40021004, 0x00000000, 0xE000ED00]
    p = _write_bin(words, tmp_path)
    table = build_flash_const_ptr_table(p, base_address=0x08000000)
    assert len(table) == 3
    assert table[0x08000000] == 0x40011000
    assert table[0x08000004] == 0x40021004
    assert table[0x0800000C] == 0xE000ED00


def test_only_aligned_offsets_scanned(tmp_path):
    """Only 4-byte aligned offsets should be scanned (no mid-word matches)."""
    # Write raw bytes: first 2 bytes padding + 4 bytes of MMIO addr
    # The MMIO addr at non-aligned offset should not appear
    data = b"\x00\x00" + struct.pack("<I", 0x40011000) + b"\x00\x00"
    p = tmp_path / "test.bin"
    p.write_bytes(data)
    table = build_flash_const_ptr_table(p, base_address=0x08000000)
    # At offset 0: bytes are 0x0000 + first 2 bytes of MMIO = not a valid MMIO
    # At offset 4: last 2 bytes of MMIO + 0x0000 = not a valid MMIO
    # So table should be empty or at least not contain the MMIO value at offset 2
    for flash_addr, val in table.items():
        assert val != 0x40011000 or (flash_addr - 0x08000000) % 4 == 0


# ── Integration: flash_const_ptr → resolve → MMIO ─────────────────────────


def test_flash_ptr_resolves_to_mmio_in_mai(tmp_path):
    """Flash pointer table entry + decompiled DAT_ ref → FLASH_CONST_PTR in MAI."""
    from sourceagent.pipeline.memory_access_index import (
        parse_memory_accesses,
        _resolve_flash_const_ptrs,
    )

    # Simulate: Ghidra decompiles a function that reads from a flash address
    # that actually contains an MMIO pointer
    code = "  uVar1 = *(uint *)0x08000100;"
    accesses = parse_memory_accesses(code, "read_periph", 0x08001000)
    assert len(accesses) == 1
    assert accesses[0].target_addr == 0x08000100
    assert accesses[0].base_provenance == "CONST"

    # Flash ptr table says 0x08000100 → 0x40011000 (USART1)
    flash_ptr_table = {0x08000100: 0x40011000}
    resolved = _resolve_flash_const_ptrs(accesses, flash_ptr_table)

    assert len(resolved) == 1
    assert resolved[0].target_addr == 0x40011000
    assert resolved[0].base_provenance == "FLASH_CONST_PTR"


def test_flash_ptr_table_real_microbench_bin():
    """Verify flash_const_ptr finds MMIO pointers in real t0_mmio_read.bin."""
    bin_path = Path(__file__).resolve().parent.parent / "firmware" / "microbench" / "t0_mmio_read.bin"
    if not bin_path.exists():
        pytest.skip("Microbench .bin not built")

    table = build_flash_const_ptr_table(bin_path, 0x08000000)
    # t0_mmio_read uses USART1 (0x40011000) — should appear in the table
    mmio_values = set(table.values())
    assert 0x40011000 in mmio_values, (
        f"Expected 0x40011000 (USART1) in flash ptr table values, "
        f"got: {sorted(f'0x{v:08x}' for v in mmio_values)}"
    )
