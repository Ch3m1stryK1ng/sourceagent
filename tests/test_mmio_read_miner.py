"""Tests for pipeline/miners/mmio_read.py — Stage 3 (VS0)."""

import pytest

from sourceagent.pipeline.models import (
    MemoryAccess,
    MemoryAccessIndex,
    MemoryMap,
    MemoryRegion,
    SourceLabel,
)
from sourceagent.pipeline.miners.mmio_read import (
    mine_mmio_read_sources,
    _cluster_id,
    _filter_mmio_read_accesses,
    _build_cluster_context,
)


def _make_mai(accesses=None, mmio_accesses=None, isr_functions=None):
    """Build a MemoryAccessIndex for testing."""
    mai = MemoryAccessIndex(binary_path="test.bin")
    mai.accesses = accesses or []
    mai.mmio_accesses = mmio_accesses or []
    mai.isr_functions = isr_functions or []
    return mai


def _make_mm():
    """Build a minimal MemoryMap."""
    return MemoryMap(
        binary_path="test.bin",
        arch="ARM:LE:32:Cortex",
        base_address=0x08000000,
        entry_point=0x08000101,
    )


def _mmio_load(target, func="uart_read", width=4, provenance="CONST", in_isr=False):
    """Build a typical MMIO load access."""
    return MemoryAccess(
        address=0x08001000,
        kind="load",
        width=width,
        target_addr=target,
        base_provenance=provenance,
        function_name=func,
        function_addr=0x08001000,
        in_isr=in_isr,
    )


def _mmio_store(target, func="rcc_enable", width=4, provenance="CONST"):
    """Build a typical MMIO store access."""
    return MemoryAccess(
        address=0x08001100,
        kind="store",
        width=width,
        target_addr=target,
        base_provenance=provenance,
        function_name=func,
        function_addr=0x08001100,
    )


# ── Label value ──────────────────────────────────────────────────────────────


def test_source_label_mmio_read_value():
    """MMIO_READ label should have the expected string value."""
    assert SourceLabel.MMIO_READ.value == "MMIO_READ"


# ── Empty / no candidates ────────────────────────────────────────────────────


def test_empty_mai_returns_no_candidates():
    """Empty MAI → no candidates."""
    mai = _make_mai()
    result = mine_mmio_read_sources(mai, _make_mm())
    assert result == []


def test_no_loads_returns_no_candidates():
    """Only stores in MMIO range → no candidates."""
    mai = _make_mai(mmio_accesses=[_mmio_store(0x40011000)])
    result = mine_mmio_read_sources(mai, _make_mm())
    assert result == []


# ── Basic MMIO_READ detection ────────────────────────────────────────────────


def test_single_mmio_load_produces_candidate():
    """A single CONST MMIO load → one MMIO_READ candidate."""
    load = _mmio_load(0x40011000)
    mai = _make_mai(mmio_accesses=[load])

    result = mine_mmio_read_sources(mai, _make_mm())
    assert len(result) == 1
    assert result[0].preliminary_label == SourceLabel.MMIO_READ
    assert result[0].address == 0x40011000
    assert result[0].function_name == "uart_read"


def test_candidate_has_evidence():
    """Candidate should have E1 (SITE) and E2 (DEF) evidence items."""
    load = _mmio_load(0x40011000)
    mai = _make_mai(mmio_accesses=[load])

    result = mine_mmio_read_sources(mai, _make_mm())
    assert len(result) == 1
    evidence_ids = {e.evidence_id for e in result[0].evidence}
    assert "E1" in evidence_ids
    assert "E2" in evidence_ids


def test_candidate_has_facts():
    """Candidate should have structured facts dict."""
    load = _mmio_load(0x40011000)
    mai = _make_mai(mmio_accesses=[load])

    result = mine_mmio_read_sources(mai, _make_mm())
    facts = result[0].facts
    assert "addr_expr" in facts
    assert "CONST" in facts["addr_expr"]
    assert facts["segment_of_base"] == "PERIPHERAL_RANGE"
    assert facts["in_isr"] is False


# ── Filtering ────────────────────────────────────────────────────────────────


def test_non_const_provenance_excluded():
    """Loads with ARG or UNKNOWN provenance should not produce candidates."""
    load = _mmio_load(0x40011000, provenance="ARG")
    mai = _make_mai(mmio_accesses=[load])

    result = mine_mmio_read_sources(mai, _make_mm())
    assert result == []


def test_isr_loads_excluded():
    """Loads in ISR context are excluded (handled by Stage 8)."""
    load = _mmio_load(0x40011000, in_isr=True)
    mai = _make_mai(mmio_accesses=[load])

    result = mine_mmio_read_sources(mai, _make_mm())
    assert result == []


def test_stores_excluded():
    """Stores should not produce MMIO_READ candidates."""
    store = _mmio_store(0x40011000)
    mai = _make_mai(mmio_accesses=[store])

    result = mine_mmio_read_sources(mai, _make_mm())
    assert result == []


def test_none_target_excluded():
    """Accesses with target_addr=None should be excluded."""
    load = MemoryAccess(
        address=0x08001000, kind="load", width=4,
        target_addr=None, base_provenance="CONST", function_name="f",
    )
    mai = _make_mai(mmio_accesses=[load])

    result = mine_mmio_read_sources(mai, _make_mm())
    assert result == []


# ── Deduplication ────────────────────────────────────────────────────────────


def test_dedup_same_function_same_target():
    """Same (function, target) appearing twice → only one candidate."""
    load1 = _mmio_load(0x40011000, func="uart_read")
    load2 = _mmio_load(0x40011000, func="uart_read")
    mai = _make_mai(mmio_accesses=[load1, load2])

    result = mine_mmio_read_sources(mai, _make_mm())
    assert len(result) == 1


def test_different_functions_not_deduped():
    """Same target in different functions → separate candidates."""
    load1 = _mmio_load(0x40011000, func="uart_read")
    load2 = _mmio_load(0x40011000, func="spi_read")
    mai = _make_mai(mmio_accesses=[load1, load2])

    result = mine_mmio_read_sources(mai, _make_mm())
    assert len(result) == 2


def test_different_targets_not_deduped():
    """Different targets in same function → separate candidates."""
    load1 = _mmio_load(0x40011000, func="uart_read")
    load2 = _mmio_load(0x40011004, func="uart_read")
    mai = _make_mai(mmio_accesses=[load1, load2])

    result = mine_mmio_read_sources(mai, _make_mm())
    assert len(result) == 2


# ── Cluster context and ranking ──────────────────────────────────────────────


def test_read_modify_write_boosts_confidence():
    """Cluster with both loads and stores → higher confidence."""
    load = _mmio_load(0x40011000, func="rcc_cfg")
    store = _mmio_store(0x40011000, func="rcc_cfg")
    mai = _make_mai(mmio_accesses=[load, store])

    result = mine_mmio_read_sources(mai, _make_mm())
    assert len(result) == 1
    # Should have higher confidence than baseline (0.5)
    assert result[0].confidence_score > 0.5
    assert result[0].facts.get("has_read_modify_write") is True


def test_multi_function_cluster_boosts_confidence():
    """Cluster accessed by multiple functions → higher confidence."""
    load1 = _mmio_load(0x40011000, func="uart_read")
    load2 = _mmio_load(0x40011004, func="uart_init")
    mai = _make_mai(mmio_accesses=[load1, load2])

    result = mine_mmio_read_sources(mai, _make_mm())
    assert len(result) == 2
    # At least one candidate should see multi-function cluster
    multi = [c for c in result if c.facts.get("multi_function_cluster")]
    assert len(multi) > 0


def test_candidates_sorted_by_confidence():
    """Candidates should be sorted by confidence (descending)."""
    # High-confidence: has read-modify-write
    load1 = _mmio_load(0x40011000, func="uart_poll")
    store1 = _mmio_store(0x40011000, func="uart_poll")
    # Low-confidence: simple read
    load2 = _mmio_load(0x40022000, func="gpio_read")
    mai = _make_mai(mmio_accesses=[load1, store1, load2])

    result = mine_mmio_read_sources(mai, _make_mm())
    assert len(result) == 2
    assert result[0].confidence_score >= result[1].confidence_score


# ── Cluster ID helper ────────────────────────────────────────────────────────


def test_cluster_id_groups_nearby_addrs():
    """Addresses in same 4KB block should have same cluster ID."""
    assert _cluster_id(0x40011000) == _cluster_id(0x40011004)
    assert _cluster_id(0x40011000) == _cluster_id(0x40011FFC)


def test_cluster_id_separates_different_peripherals():
    """Addresses in different 4KB blocks should have different cluster IDs."""
    assert _cluster_id(0x40011000) != _cluster_id(0x40012000)


# ── System peripheral (0xE000xxxx) support ───────────────────────────────────


def test_system_peripheral_produces_candidate():
    """NVIC/SysTick reads (0xE000xxxx) should also produce candidates."""
    load = _mmio_load(0xE000E100)  # NVIC
    mai = _make_mai(mmio_accesses=[load])

    result = mine_mmio_read_sources(mai, _make_mm())
    assert len(result) == 1
    assert result[0].address == 0xE000E100
