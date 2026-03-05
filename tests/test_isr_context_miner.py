"""Tests for pipeline/miners/isr_context.py — Stage 8 (VS2)."""

import pytest

from sourceagent.pipeline.models import (
    MemoryAccess,
    MemoryAccessIndex,
    MemoryMap,
    SourceLabel,
)
from sourceagent.pipeline.miners.isr_context import mine_isr_sources


def _make_mai(accesses=None, mmio_accesses=None, isr_functions=None):
    mai = MemoryAccessIndex(binary_path="test.bin")
    mai.accesses = accesses or []
    mai.mmio_accesses = mmio_accesses or []
    mai.isr_functions = isr_functions or []
    return mai


def _make_mm():
    return MemoryMap(
        binary_path="test.bin",
        arch="ARM:LE:32:Cortex",
        base_address=0x08000000,
        entry_point=0x08000101,
    )


def _mmio_load(target, func, in_isr=False, provenance="CONST"):
    return MemoryAccess(
        address=0x08001000, kind="load", width=4,
        target_addr=target, base_provenance=provenance,
        function_name=func, function_addr=0x08001000, in_isr=in_isr,
    )


def _sram_store(target, func, in_isr=False, provenance="CONST"):
    return MemoryAccess(
        address=0x08001000, kind="store", width=4,
        target_addr=target, base_provenance=provenance,
        function_name=func, function_addr=0x08001000, in_isr=in_isr,
    )


def _sram_load(target, func, in_isr=False, provenance="CONST"):
    return MemoryAccess(
        address=0x08002000, kind="load", width=4,
        target_addr=target, base_provenance=provenance,
        function_name=func, function_addr=0x08002000, in_isr=in_isr,
    )


# ── Empty cases ──────────────────────────────────────────────────────────────


def test_empty_mai_returns_no_candidates():
    mai = _make_mai()
    result = mine_isr_sources(mai, _make_mm())
    assert result == []


# ── ISR_MMIO_READ ────────────────────────────────────────────────────────────


def test_isr_mmio_read_basic():
    """MMIO load inside ISR → ISR_MMIO_READ candidate."""
    load = _mmio_load(0x40011000, func="USART1_IRQHandler", in_isr=True)
    mai = _make_mai(mmio_accesses=[load])

    result = mine_isr_sources(mai, _make_mm())
    isr_mmio = [c for c in result if c.preliminary_label == SourceLabel.ISR_MMIO_READ]
    assert len(isr_mmio) == 1
    assert isr_mmio[0].address == 0x40011000
    assert isr_mmio[0].function_name == "USART1_IRQHandler"
    assert isr_mmio[0].facts["in_isr"] is True


def test_isr_mmio_read_excludes_non_isr():
    """Non-ISR MMIO loads should not produce ISR_MMIO_READ."""
    load = _mmio_load(0x40011000, func="main", in_isr=False)
    mai = _make_mai(mmio_accesses=[load])

    result = mine_isr_sources(mai, _make_mm())
    isr_mmio = [c for c in result if c.preliminary_label == SourceLabel.ISR_MMIO_READ]
    assert isr_mmio == []


def test_isr_mmio_read_excludes_non_const():
    """ISR MMIO loads with non-CONST provenance should be excluded."""
    load = _mmio_load(0x40011000, func="handler", in_isr=True, provenance="ARG")
    mai = _make_mai(mmio_accesses=[load])

    result = mine_isr_sources(mai, _make_mm())
    isr_mmio = [c for c in result if c.preliminary_label == SourceLabel.ISR_MMIO_READ]
    assert isr_mmio == []


def test_isr_mmio_read_excludes_stores():
    """ISR MMIO stores should not produce ISR_MMIO_READ."""
    store = MemoryAccess(
        address=0x08001000, kind="store", width=4,
        target_addr=0x40011000, base_provenance="CONST",
        function_name="handler", function_addr=0x08001000, in_isr=True,
    )
    mai = _make_mai(mmio_accesses=[store])

    result = mine_isr_sources(mai, _make_mm())
    isr_mmio = [c for c in result if c.preliminary_label == SourceLabel.ISR_MMIO_READ]
    assert isr_mmio == []


def test_isr_mmio_read_deduplicates():
    """Same (function, target) in ISR → only one candidate."""
    load1 = _mmio_load(0x40011000, func="handler", in_isr=True)
    load2 = _mmio_load(0x40011000, func="handler", in_isr=True)
    mai = _make_mai(mmio_accesses=[load1, load2])

    result = mine_isr_sources(mai, _make_mm())
    isr_mmio = [c for c in result if c.preliminary_label == SourceLabel.ISR_MMIO_READ]
    assert len(isr_mmio) == 1


def test_isr_mmio_read_has_evidence():
    """ISR_MMIO_READ candidate should have E1 and E2 evidence."""
    load = _mmio_load(0x40011000, func="handler", in_isr=True)
    mai = _make_mai(mmio_accesses=[load])

    result = mine_isr_sources(mai, _make_mm())
    assert len(result) >= 1
    evidence_ids = {e.evidence_id for e in result[0].evidence}
    assert "E1" in evidence_ids
    assert "E2" in evidence_ids


# ── ISR_FILLED_BUFFER ────────────────────────────────────────────────────────


def test_isr_filled_buffer_basic():
    """ISR writes SRAM + non-ISR reads same SRAM → ISR_FILLED_BUFFER."""
    isr_write = _sram_store(0x20000100, func="USART1_IRQHandler", in_isr=True)
    main_read = _sram_load(0x20000100, func="main", in_isr=False)
    mai = _make_mai(accesses=[isr_write, main_read])

    result = mine_isr_sources(mai, _make_mm())
    buf_candidates = [c for c in result if c.preliminary_label == SourceLabel.ISR_FILLED_BUFFER]
    assert len(buf_candidates) == 1
    assert buf_candidates[0].facts["isr_write_count"] >= 1
    assert buf_candidates[0].facts["non_isr_read_count"] >= 1


def test_isr_filled_buffer_requires_isr_write():
    """Only non-ISR reads (no ISR writes) → no ISR_FILLED_BUFFER."""
    read = _sram_load(0x20000100, func="main", in_isr=False)
    mai = _make_mai(accesses=[read])

    result = mine_isr_sources(mai, _make_mm())
    buf_candidates = [c for c in result if c.preliminary_label == SourceLabel.ISR_FILLED_BUFFER]
    assert buf_candidates == []


def test_isr_filled_buffer_requires_non_isr_read():
    """Only ISR writes (no non-ISR reads) → no ISR_FILLED_BUFFER."""
    write = _sram_store(0x20000100, func="handler", in_isr=True)
    mai = _make_mai(accesses=[write])

    result = mine_isr_sources(mai, _make_mm())
    buf_candidates = [c for c in result if c.preliminary_label == SourceLabel.ISR_FILLED_BUFFER]
    assert buf_candidates == []


def test_isr_filled_buffer_ignores_non_sram():
    """ISR writes to MMIO (not SRAM) → no ISR_FILLED_BUFFER."""
    write = _sram_store(0x40011000, func="handler", in_isr=True)  # MMIO, not SRAM
    read = _sram_load(0x40011000, func="main", in_isr=False)
    mai = _make_mai(accesses=[write, read])

    result = mine_isr_sources(mai, _make_mm())
    buf_candidates = [c for c in result if c.preliminary_label == SourceLabel.ISR_FILLED_BUFFER]
    assert buf_candidates == []


def test_isr_filled_buffer_has_evidence():
    """ISR_FILLED_BUFFER should have E1 (ISR write) and E2 (non-ISR read)."""
    write = _sram_store(0x20000100, func="handler", in_isr=True)
    read = _sram_load(0x20000100, func="main", in_isr=False)
    mai = _make_mai(accesses=[write, read])

    result = mine_isr_sources(mai, _make_mm())
    buf_candidates = [c for c in result if c.preliminary_label == SourceLabel.ISR_FILLED_BUFFER]
    assert len(buf_candidates) == 1
    evidence_ids = {e.evidence_id for e in buf_candidates[0].evidence}
    assert "E1" in evidence_ids
    assert "E2" in evidence_ids


# ── Combined output ──────────────────────────────────────────────────────────


def test_both_labels_produced():
    """MAI with ISR MMIO load + ISR buffer write → both label types."""
    isr_mmio = _mmio_load(0x40011004, func="USART1_IRQHandler", in_isr=True)
    isr_write = _sram_store(0x20000100, func="USART1_IRQHandler", in_isr=True)
    main_read = _sram_load(0x20000100, func="main", in_isr=False)

    mai = _make_mai(
        accesses=[isr_write, main_read],
        mmio_accesses=[isr_mmio],
    )

    result = mine_isr_sources(mai, _make_mm())
    labels = {c.preliminary_label for c in result}
    assert SourceLabel.ISR_MMIO_READ in labels
    assert SourceLabel.ISR_FILLED_BUFFER in labels
