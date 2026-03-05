"""Tests for pipeline/evidence_packer.py — Stage 5 (M5)."""

import pytest

from sourceagent.pipeline.models import (
    EvidencePack,
    EvidenceItem,
    SinkCandidate,
    SinkLabel,
    SourceCandidate,
    SourceLabel,
)
from sourceagent.pipeline.evidence_packer import pack_evidence, _make_pack_id


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_source(label=SourceLabel.MMIO_READ, addr=0x40011000, func="uart_read"):
    return SourceCandidate(
        address=addr,
        function_name=func,
        preliminary_label=label,
        evidence=[
            EvidenceItem("E1", "SITE", f"load from 0x{addr:08x}", address=addr),
            EvidenceItem("E2", "DEF", "CONST provenance"),
        ],
        confidence_score=0.7,
        facts={"addr_expr": f"CONST(0x{addr:08x})", "in_isr": False},
    )


def _make_sink(label=SinkLabel.COPY_SINK, addr=0x08001234, func="handler"):
    return SinkCandidate(
        address=addr,
        function_name=func,
        preliminary_label=label,
        evidence=[
            EvidenceItem("E1", "SITE", "memcpy callsite", address=addr),
        ],
        confidence_score=0.6,
        facts={"callsite": "memcpy"},
    )


# ── Basic packing ────────────────────────────────────────────────────────────


def test_pack_single_source():
    """One source candidate → one EvidencePack."""
    src = _make_source()
    packs = pack_evidence([src], [])

    assert len(packs) == 1
    p = packs[0]
    assert p.candidate_hint == "MMIO_READ"
    assert p.address == 0x40011000
    assert p.function_name == "uart_read"
    assert len(p.evidence) == 2


def test_pack_single_sink():
    """One sink candidate → one EvidencePack."""
    sink = _make_sink()
    packs = pack_evidence([], [sink])

    assert len(packs) == 1
    assert packs[0].candidate_hint == "COPY_SINK"


def test_pack_sources_and_sinks():
    """Mixed sources and sinks → one pack each."""
    packs = pack_evidence([_make_source()], [_make_sink()])
    assert len(packs) == 2
    hints = {p.candidate_hint for p in packs}
    assert "MMIO_READ" in hints
    assert "COPY_SINK" in hints


def test_pack_empty_inputs():
    """No candidates → empty list."""
    packs = pack_evidence([], [])
    assert packs == []


# ── Pack ID ──────────────────────────────────────────────────────────────────


def test_pack_id_contains_label():
    """Pack ID should contain the label type."""
    src = _make_source()
    packs = pack_evidence([src], [])
    assert "MMIO_READ" in packs[0].pack_id


def test_pack_id_contains_function():
    """Pack ID should contain the function name."""
    src = _make_source(func="spi_read")
    packs = pack_evidence([src], [])
    assert "spi_read" in packs[0].pack_id


def test_pack_id_contains_address():
    """Pack ID should contain the hex address."""
    src = _make_source(addr=0x40022000)
    packs = pack_evidence([src], [])
    assert "40022000" in packs[0].pack_id


def test_pack_id_stable_across_calls():
    """Same candidate → same pack_id on repeated calls."""
    src = _make_source()
    packs1 = pack_evidence([src], [])
    packs2 = pack_evidence([src], [])
    assert packs1[0].pack_id == packs2[0].pack_id


def test_pack_id_unique_for_different_candidates():
    """Different candidates → different pack_ids."""
    src1 = _make_source(addr=0x40011000)
    src2 = _make_source(addr=0x40022000)
    packs = pack_evidence([src1, src2], [])
    assert packs[0].pack_id != packs[1].pack_id


# ── Facts and evidence preservation ──────────────────────────────────────────


def test_facts_preserved():
    """Candidate facts should be carried into the EvidencePack."""
    src = _make_source()
    packs = pack_evidence([src], [])
    assert packs[0].facts["addr_expr"] == "CONST(0x40011000)"
    assert packs[0].facts["in_isr"] is False


def test_evidence_items_preserved():
    """Evidence items from miner should be carried into the pack."""
    src = _make_source()
    packs = pack_evidence([src], [])
    evidence_ids = {e.evidence_id for e in packs[0].evidence}
    assert "E1" in evidence_ids
    assert "E2" in evidence_ids


# ── _make_pack_id helper ─────────────────────────────────────────────────────


def test_make_pack_id_format():
    """pack_id format should be {label}@{func}-0x{addr}-{hash}."""
    evidence = [EvidenceItem("E1", "SITE", "test")]
    pid = _make_pack_id("my_func", "MMIO_READ", 0x40011000, evidence)
    assert pid.startswith("MMIO_READ@my_func-0x40011000-")
    assert len(pid.split("-")) >= 3


def test_evidence_pack_id_format():
    """EvidencePack.pack_id should be a string identifier."""
    p = EvidencePack(
        pack_id="fw-0x100084",
        candidate_hint="MMIO_READ",
        binary_path="fw.bin",
        address=0x100084,
        function_name="uart_poll",
    )
    assert isinstance(p.pack_id, str)
    assert "0x100084" in p.pack_id


def test_evidence_item_fields():
    """EvidenceItem should capture kind, text, and optional address."""
    e = EvidenceItem(
        evidence_id="E1",
        kind="SITE",
        text="ldr r1, [r0,#0x04]  // read",
        address=0x100084,
    )
    assert e.evidence_id == "E1"
    assert e.kind == "SITE"
    assert e.address == 0x100084
