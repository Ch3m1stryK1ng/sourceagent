"""Tests for pipeline/miners/dma_buffer.py — Stage 9 (VS3)."""

import pytest

from sourceagent.pipeline.models import (
    MemoryAccess,
    MemoryAccessIndex,
    MemoryMap,
    SourceLabel,
)
from sourceagent.pipeline.miners.dma_buffer import mine_dma_sources


def _make_mai(accesses=None, mmio_accesses=None):
    mai = MemoryAccessIndex(binary_path="test.bin")
    mai.accesses = accesses or []
    mai.mmio_accesses = mmio_accesses or []
    mai.isr_functions = []
    return mai


def _make_mm():
    return MemoryMap(
        binary_path="test.bin",
        arch="ARM:LE:32:Cortex",
        base_address=0x08000000,
        entry_point=0x08000101,
    )


def _mmio_store(target, func="dma_init", provenance="CONST"):
    """Build an MMIO store access."""
    return MemoryAccess(
        address=0x08001000, kind="store", width=4,
        target_addr=target, base_provenance=provenance,
        function_name=func, function_addr=0x08001000,
    )


# ── Empty / no candidates ────────────────────────────────────────────────────


def test_empty_mai_returns_no_candidates():
    mai = _make_mai()
    result = mine_dma_sources(mai, _make_mm())
    assert result == []


def test_fewer_than_3_writes_no_candidate():
    """Only 2 writes to same peripheral → no DMA config site."""
    stores = [
        _mmio_store(0x40002534),
        _mmio_store(0x40002538),
    ]
    mai = _make_mai(mmio_accesses=stores)

    result = mine_dma_sources(mai, _make_mm())
    assert result == []


# ── Level 1: DMA config site detection ───────────────────────────────────────


def test_3_writes_same_cluster_produces_candidate():
    """>=3 MMIO stores to same 4KB cluster with GLOBAL_PTR → DMA candidate."""
    stores = [
        _mmio_store(0x40002534, provenance="GLOBAL_PTR"),  # PTR register
        _mmio_store(0x40002538, provenance="CONST"),       # LEN register
        _mmio_store(0x4000253C, provenance="CONST"),       # CTRL/enable
    ]
    mai = _make_mai(mmio_accesses=stores)

    result = mine_dma_sources(mai, _make_mm())
    assert len(result) == 1
    assert result[0].preliminary_label == SourceLabel.DMA_BACKED_BUFFER


def test_config_site_requires_pointer_like_write():
    """3 writes but all CONST (no GLOBAL_PTR) → still produces candidate
    because CONST is also pointer-like per the checker."""
    stores = [
        _mmio_store(0x40002534, provenance="CONST"),
        _mmio_store(0x40002538, provenance="CONST"),
        _mmio_store(0x4000253C, provenance="CONST"),
    ]
    mai = _make_mai(mmio_accesses=stores)

    result = mine_dma_sources(mai, _make_mm())
    assert len(result) == 1  # CONST counts as pointer-like


def test_config_site_no_pointer_like_excluded():
    """3 writes with ARG provenance (not pointer-like) → no candidate."""
    stores = [
        _mmio_store(0x40002534, provenance="ARG"),
        _mmio_store(0x40002538, provenance="ARG"),
        _mmio_store(0x4000253C, provenance="ARG"),
    ]
    mai = _make_mai(mmio_accesses=stores)

    result = mine_dma_sources(mai, _make_mm())
    assert result == []


def test_different_clusters_separate():
    """Writes to different 4KB blocks → counted separately."""
    stores = [
        _mmio_store(0x40002534),  # Cluster A
        _mmio_store(0x40002538),  # Cluster A
        _mmio_store(0x40003000),  # Cluster B — different 4KB block
    ]
    mai = _make_mai(mmio_accesses=stores)

    result = mine_dma_sources(mai, _make_mm())
    # Only 2 writes in cluster A, 1 in cluster B → neither qualifies
    assert result == []


# ── Evidence and facts ───────────────────────────────────────────────────────


def test_candidate_has_evidence():
    """DMA candidate should have E1 (config site) and E2 (function)."""
    stores = [
        _mmio_store(0x40002534, provenance="GLOBAL_PTR"),
        _mmio_store(0x40002538),
        _mmio_store(0x4000253C),
    ]
    mai = _make_mai(mmio_accesses=stores)

    result = mine_dma_sources(mai, _make_mm())
    assert len(result) == 1
    evidence_ids = {e.evidence_id for e in result[0].evidence}
    assert "E1" in evidence_ids
    assert "E2" in evidence_ids


def test_candidate_has_facts():
    """DMA candidate facts should include config details."""
    stores = [
        _mmio_store(0x40002534, provenance="GLOBAL_PTR"),
        _mmio_store(0x40002538),
        _mmio_store(0x4000253C),
    ]
    mai = _make_mai(mmio_accesses=stores)

    result = mine_dma_sources(mai, _make_mm())
    facts = result[0].facts
    assert facts["config_write_count"] == 3
    assert facts["has_pointer_like_write"] is True
    assert facts["config_function"] == "dma_init"


# ── Multiple config sites ────────────────────────────────────────────────────


def test_two_config_clusters():
    """Two separate DMA peripherals → two candidates."""
    stores_a = [
        _mmio_store(0x40002534, provenance="GLOBAL_PTR"),
        _mmio_store(0x40002538),
        _mmio_store(0x4000253C),
    ]
    stores_b = [
        _mmio_store(0x40003534, func="dma2_init", provenance="GLOBAL_PTR"),
        _mmio_store(0x40003538, func="dma2_init"),
        _mmio_store(0x4000353C, func="dma2_init"),
    ]
    mai = _make_mai(mmio_accesses=stores_a + stores_b)

    result = mine_dma_sources(mai, _make_mm())
    assert len(result) == 2
    funcs = {c.function_name for c in result}
    assert "dma_init" in funcs
    assert "dma2_init" in funcs
