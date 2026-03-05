"""Tests for peripheral_types register classification and mmio_read per-register RMW."""

import pytest

from sourceagent.pipeline.peripheral_types import (
    classify_register,
    get_field_name,
)
from sourceagent.pipeline.models import (
    MemoryAccess,
    MemoryAccessIndex,
    MemoryMap,
    SourceLabel,
)
from sourceagent.pipeline.miners.mmio_read import (
    mine_mmio_read_sources,
    _cluster_id,
    _detect_polling_loop,
    _detect_indirect_polling,
)


# ── get_field_name tests ─────────────────────────────────────────────────


def test_get_field_name_usart_sr():
    assert get_field_name("USART_TypeDef", 0x00) == "SR"


def test_get_field_name_usart_dr():
    assert get_field_name("USART_TypeDef", 0x04) == "DR"


def test_get_field_name_usart_cr1():
    assert get_field_name("USART_TypeDef", 0x0C) == "CR1"


def test_get_field_name_unknown_offset():
    assert get_field_name("USART_TypeDef", 0xFF) is None


def test_get_field_name_unknown_type():
    assert get_field_name("NonExistent_TypeDef", 0x00) is None


def test_get_field_name_conflict_suffix():
    """Ghidra _conflict suffix should be stripped."""
    assert get_field_name("USART_TypeDef_conflict", 0x04) == "DR"


# ── classify_register tests ─────────────────────────────────────────────


def test_classify_register_sr():
    assert classify_register("SR") == "STATUS"


def test_classify_register_isr():
    assert classify_register("ISR") == "STATUS"


def test_classify_register_dr():
    assert classify_register("DR") == "DATA"


def test_classify_register_cr1():
    assert classify_register("CR1") == "CONTROL"


def test_classify_register_ccr():
    assert classify_register("CCR") == "CONTROL"


def test_classify_register_unknown():
    assert classify_register("CUSTOM_REG") == "UNKNOWN"


# ── Per-register RMW tests ──────────────────────────────────────────────


def _make_mai(mmio_accesses=None, typed_bases=None):
    mai = MemoryAccessIndex(binary_path="test.bin")
    mai.mmio_accesses = mmio_accesses or []
    if typed_bases:
        mai.typed_bases = typed_bases
    return mai


def _make_mm():
    return MemoryMap(
        binary_path="test.bin",
        arch="ARM:LE:32:Cortex",
        base_address=0x08000000,
        entry_point=0x08000101,
    )


def _mmio_load(target, func="uart_read", width=4, provenance="CONST"):
    return MemoryAccess(
        address=0x08001000, kind="load", width=width,
        target_addr=target, base_provenance=provenance,
        function_name=func, function_addr=0x08001000,
    )


def _mmio_store(target, func="uart_write", width=4, provenance="CONST"):
    return MemoryAccess(
        address=0x08001100, kind="store", width=width,
        target_addr=target, base_provenance=provenance,
        function_name=func, function_addr=0x08001100,
    )


def test_per_register_rmw_full_bonus():
    """Register with both load+store gets full +0.2 RMW bonus."""
    # CR1 at 0x4001100C has both load and store
    load_cr1 = _mmio_load(0x4001100C, func="cfg")
    store_cr1 = _mmio_store(0x4001100C, func="cfg")
    mai = _make_mai(mmio_accesses=[load_cr1, store_cr1])

    result = mine_mmio_read_sources(mai, _make_mm())
    assert len(result) == 1
    assert result[0].facts.get("per_register_rmw") is True
    # Baseline 0.5 + 0.2 RMW = 0.7 (may have register penalty too)
    assert result[0].confidence_score >= 0.5


def test_cluster_rmw_does_not_bleed():
    """Cluster-level RMW should not give full bonus to load-only registers."""
    # USART base 0x40011000: SR at +0, DR at +4, CR1 at +0xC
    sr_load = _mmio_load(0x40011000, func="poll")     # SR load
    cr1_store = _mmio_store(0x4001100C, func="cfg")    # CR1 store

    mai = _make_mai(mmio_accesses=[sr_load, cr1_store])

    result = mine_mmio_read_sources(mai, _make_mm())
    assert len(result) == 1  # Only SR load produces a candidate

    candidate = result[0]
    assert candidate.address == 0x40011000

    # Cluster has RMW (SR load + CR1 store) but SR itself is load-only
    assert candidate.facts.get("has_read_modify_write") is True
    assert candidate.facts.get("per_register_rmw") is False
    # Should get weak +0.05 instead of strong +0.2
    # Baseline 0.5 + 0.05 cluster RMW = 0.55
    assert candidate.confidence_score < 0.7


def test_sr_penalty_reduces_confidence():
    """SR reads should get lower confidence than DR reads when typed_bases available."""
    sr_load = _mmio_load(0x40011000, func="poll")   # SR
    dr_load = _mmio_load(0x40011004, func="read")   # DR

    mai = _make_mai(
        mmio_accesses=[sr_load, dr_load],
        typed_bases={0x40011000: "USART_TypeDef"},
    )

    result = mine_mmio_read_sources(mai, _make_mm())
    assert len(result) == 2

    by_addr = {c.address: c for c in result}
    sr_candidate = by_addr[0x40011000]
    dr_candidate = by_addr[0x40011004]

    assert sr_candidate.facts.get("register_class") == "STATUS"
    assert dr_candidate.facts.get("register_class") == "DATA"
    assert sr_candidate.confidence_score < dr_candidate.confidence_score


def test_cr1_penalty_reduces_confidence():
    """CR1 reads should get lower confidence than DR reads."""
    cr1_load = _mmio_load(0x4001100C, func="check")  # CR1
    dr_load = _mmio_load(0x40011004, func="read")     # DR

    mai = _make_mai(
        mmio_accesses=[cr1_load, dr_load],
        typed_bases={0x40011000: "USART_TypeDef"},
    )

    result = mine_mmio_read_sources(mai, _make_mm())
    assert len(result) == 2

    by_addr = {c.address: c for c in result}
    cr1_candidate = by_addr[0x4001100C]
    dr_candidate = by_addr[0x40011004]

    assert cr1_candidate.facts.get("register_class") == "CONTROL"
    assert dr_candidate.facts.get("register_class") == "DATA"
    assert cr1_candidate.confidence_score < dr_candidate.confidence_score


def test_no_typed_bases_no_penalty():
    """Without typed_bases, no register classification or penalty applied."""
    sr_load = _mmio_load(0x40011000, func="poll")
    mai = _make_mai(mmio_accesses=[sr_load])
    # No typed_bases

    result = mine_mmio_read_sources(mai, _make_mm())
    assert len(result) == 1
    assert "register_class" not in result[0].facts


# ══════════════════════════════════════════════════════════════════════════════
# P7: Polling-loop detection tests
# ══════════════════════════════════════════════════════════════════════════════


def test_polling_loop_direct_penalty():
    """SR in while (*(uint *)0x40011000 & 0x20) → extra polling penalty."""
    code = """\
void uart_wait(void) {
  while (*(uint *)0x40011000 & 0x20) {
    // busy wait
  }
}"""
    assert _detect_polling_loop(code, 0x40011000) is True


def test_polling_loop_indirect_penalty():
    """while (uart_status() & 0x20) → indirect polling detected."""
    code = """\
void recv(void) {
  while (uart_status() & 0x20) {
    // wait for data
  }
}"""
    func_read_map = {"uart_status": {0x40011000}}
    assert _detect_indirect_polling(code, func_read_map) is True


def test_no_polling_penalty_for_dr():
    """DR read, no loop → no polling detection."""
    code = """\
void read_data(void) {
  uint val = *(uint *)0x40011004;
}"""
    assert _detect_polling_loop(code, 0x40011004) is False


def test_polling_detection_do_while():
    """do {...} while (!(SR & RXNE)) pattern."""
    code = """\
void uart_poll(void) {
  do {
    nop();
  } while (!(*(uint *)0x40011000 & 0x20));
}"""
    assert _detect_polling_loop(code, 0x40011000) is True


def test_polling_loop_reduces_confidence():
    """End-to-end: SR with polling loop gets lower confidence than SR without."""
    sr_load = _mmio_load(0x40011000, func="poll")

    mai = _make_mai(
        mmio_accesses=[sr_load],
        typed_bases={0x40011000: "USART_TypeDef"},
    )
    mai.decompiled_cache = {
        "poll": """\
void poll(void) {
  while (*(uint *)0x40011000 & 0x20) { }
}""",
    }

    result = mine_mmio_read_sources(mai, _make_mm())
    assert len(result) == 1
    c = result[0]
    assert c.facts.get("polling_loop") is True
    assert c.facts.get("register_class") == "STATUS"
    # Baseline 0.5 - 0.20 (STATUS) - 0.15 (polling) = 0.15
    assert c.confidence_score <= 0.20


def test_no_polling_no_extra_penalty():
    """SR without polling loop → no polling_loop fact, only register penalty."""
    sr_load = _mmio_load(0x40011000, func="check")

    mai = _make_mai(
        mmio_accesses=[sr_load],
        typed_bases={0x40011000: "USART_TypeDef"},
    )
    mai.decompiled_cache = {
        "check": """\
void check(void) {
  uint status = *(uint *)0x40011000;
  if (status & 0x20) process();
}""",
    }

    result = mine_mmio_read_sources(mai, _make_mm())
    assert len(result) == 1
    c = result[0]
    assert "polling_loop" not in c.facts
    # Only STATUS penalty, no polling penalty
    assert c.confidence_score >= 0.25
