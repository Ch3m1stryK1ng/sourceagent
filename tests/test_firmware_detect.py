"""Unit tests for sourceagent.agents.firmware_detect."""

import struct
import tempfile
from pathlib import Path

import pytest

from sourceagent.agents.firmware_detect import detect_cortex_m_raw


def _make_vector_table(
    sp: int = 0x20020000,
    reset: int = 0x08000101,
    words2_6: tuple = (0, 0, 0, 0, 0),
    words7_10: tuple = (0, 0, 0, 0),
    words11_15: tuple = (0, 0, 0, 0, 0),
) -> bytes:
    """Build a 64-byte synthetic Cortex-M vector table."""
    all_words = (sp, reset) + words2_6 + words7_10 + words11_15
    assert len(all_words) == 16
    return struct.pack("<16I", *all_words)


class TestDetectCortexMRaw:
    """Tests for detect_cortex_m_raw()."""

    def test_valid_stm32(self, tmp_path: Path):
        """Valid STM32 vector table → detected, base=0x08000000."""
        f = tmp_path / "firmware.bin"
        f.write_bytes(_make_vector_table(sp=0x20020000, reset=0x08000101))
        result = detect_cortex_m_raw(f)
        assert result is not None
        assert result["language"] == "ARM:LE:32:Cortex"
        assert result["base_address"] == "0x08000000"

    def test_valid_zephyr(self, tmp_path: Path):
        """Zephyr/QEMU vector table → detected, base=0x00400000."""
        f = tmp_path / "zephyr.bin"
        f.write_bytes(_make_vector_table(sp=0x20100000, reset=0x00402001))
        result = detect_cortex_m_raw(f)
        assert result is not None
        assert result["language"] == "ARM:LE:32:Cortex"
        assert result["base_address"] == "0x00400000"

    def test_valid_flash_alias(self, tmp_path: Path):
        """Flash-alias vector table → detected, base=0x00000000."""
        f = tmp_path / "alias.bin"
        f.write_bytes(_make_vector_table(sp=0x20000400, reset=0x00000201))
        result = detect_cortex_m_raw(f)
        assert result is not None
        assert result["base_address"] == "0x00000000"

    def test_valid_custom_base(self, tmp_path: Path):
        """Non-standard reset region → inferred from upper halfword."""
        f = tmp_path / "custom.bin"
        f.write_bytes(_make_vector_table(sp=0x20010000, reset=0x10000101))
        result = detect_cortex_m_raw(f)
        assert result is not None
        assert result["base_address"] == "0x10000000"

    def test_elf_file_rejected(self, tmp_path: Path):
        """ELF magic header → None."""
        f = tmp_path / "binary.elf"
        data = b"\x7fELF" + b"\x00" * 60
        f.write_bytes(data)
        assert detect_cortex_m_raw(f) is None

    def test_pe_file_rejected(self, tmp_path: Path):
        """PE/MZ magic header → None."""
        f = tmp_path / "binary.exe"
        data = b"MZ" + b"\x00" * 62
        f.write_bytes(data)
        assert detect_cortex_m_raw(f) is None

    def test_sp_out_of_range(self, tmp_path: Path):
        """SP outside SRAM range → None."""
        f = tmp_path / "bad_sp.bin"
        f.write_bytes(_make_vector_table(sp=0x10000000, reset=0x08000101))
        assert detect_cortex_m_raw(f) is None

    def test_reset_even_address(self, tmp_path: Path):
        """Reset vector without Thumb bit (even) → None."""
        f = tmp_path / "no_thumb.bin"
        f.write_bytes(_make_vector_table(sp=0x20020000, reset=0x08000100))
        assert detect_cortex_m_raw(f) is None

    def test_reserved_words_nonzero(self, tmp_path: Path):
        """Reserved words (7-10) non-zero → None."""
        f = tmp_path / "bad_reserved.bin"
        f.write_bytes(
            _make_vector_table(
                sp=0x20020000, reset=0x08000101,
                words7_10=(0xDEADBEEF, 0, 0, 0),
            )
        )
        assert detect_cortex_m_raw(f) is None

    def test_file_too_small(self, tmp_path: Path):
        """File < 64 bytes → None, no crash."""
        f = tmp_path / "tiny.bin"
        f.write_bytes(b"\x00" * 32)
        assert detect_cortex_m_raw(f) is None

    def test_empty_file(self, tmp_path: Path):
        """Empty file → None."""
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        assert detect_cortex_m_raw(f) is None

    def test_nonexistent_file(self, tmp_path: Path):
        """Non-existent file → None."""
        assert detect_cortex_m_raw(tmp_path / "does_not_exist.bin") is None

    def test_directory_rejected(self, tmp_path: Path):
        """Directory path → None."""
        assert detect_cortex_m_raw(tmp_path) is None

    def test_large_valid_file(self, tmp_path: Path):
        """Valid vector table + trailing data → still detected."""
        f = tmp_path / "large.bin"
        f.write_bytes(_make_vector_table() + b"\xff" * 1024)
        result = detect_cortex_m_raw(f)
        assert result is not None
        assert result["language"] == "ARM:LE:32:Cortex"
