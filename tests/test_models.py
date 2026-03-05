"""Tests for pipeline data models."""

import json
from dataclasses import asdict

from sourceagent.pipeline.models import (
    EvalResult,
    EvidenceItem,
    EvidencePack,
    GroundTruthEntry,
    LLMProposal,
    MemoryAccess,
    MemoryAccessIndex,
    MemoryMap,
    MemoryRegion,
    Obligation,
    ObligationStatus,
    PipelineResult,
    SinkCandidate,
    SinkLabel,
    SourceCandidate,
    SourceLabel,
    VerificationVerdict,
    VerifiedLabel,
)


# ── Enum membership tests ───────────────────────────────────────────────────


def test_source_label_values():
    assert SourceLabel.MMIO_READ == "MMIO_READ"
    assert SourceLabel.ISR_MMIO_READ == "ISR_MMIO_READ"
    assert SourceLabel.ISR_FILLED_BUFFER == "ISR_FILLED_BUFFER"
    assert SourceLabel.DMA_BACKED_BUFFER == "DMA_BACKED_BUFFER"
    assert len(SourceLabel) == 4


def test_sink_label_values():
    assert SinkLabel.COPY_SINK == "COPY_SINK"
    assert SinkLabel.MEMSET_SINK == "MEMSET_SINK"
    assert SinkLabel.STORE_SINK == "STORE_SINK"
    assert SinkLabel.LOOP_WRITE_SINK == "LOOP_WRITE_SINK"
    assert SinkLabel.FORMAT_STRING_SINK == "FORMAT_STRING_SINK"
    assert SinkLabel.FUNC_PTR_SINK == "FUNC_PTR_SINK"
    assert len(SinkLabel) == 6


def test_obligation_status_values():
    assert ObligationStatus.PENDING == "pending"
    assert ObligationStatus.SATISFIED == "satisfied"
    assert ObligationStatus.VIOLATED == "violated"
    assert ObligationStatus.UNKNOWN == "unknown"
    assert len(ObligationStatus) == 4


def test_verification_verdict_values():
    assert VerificationVerdict.VERIFIED == "VERIFIED"
    assert VerificationVerdict.PARTIAL == "PARTIAL"
    assert VerificationVerdict.REJECTED == "REJECTED"
    assert VerificationVerdict.UNKNOWN == "UNKNOWN"
    assert len(VerificationVerdict) == 4


# ── EvalResult precision/recall/F1 ──────────────────────────────────────────


def test_eval_result_perfect_precision():
    r = EvalResult("test", "MMIO_READ", true_positives=10, false_positives=0, false_negatives=0)
    assert r.precision == 1.0
    assert r.recall == 1.0
    assert r.f1 == 1.0


def test_eval_result_zero_precision():
    r = EvalResult("test", "MMIO_READ", true_positives=0, false_positives=5, false_negatives=0)
    assert r.precision == 0.0


def test_eval_result_zero_recall():
    r = EvalResult("test", "MMIO_READ", true_positives=0, false_positives=0, false_negatives=5)
    assert r.recall == 0.0


def test_eval_result_f1_zero_when_empty():
    r = EvalResult("test", "MMIO_READ", true_positives=0, false_positives=0, false_negatives=0)
    assert r.f1 == 0.0


def test_eval_result_mixed():
    r = EvalResult("test", "COPY_SINK", true_positives=8, false_positives=2, false_negatives=4)
    assert r.precision == 0.8
    assert abs(r.recall - 8 / 12) < 1e-9
    expected_f1 = 2 * 0.8 * (8 / 12) / (0.8 + 8 / 12)
    assert abs(r.f1 - expected_f1) < 1e-9


# ── Dataclass field presence tests ──────────────────────────────────────────


def test_memory_region_fields():
    r = MemoryRegion(name="FLASH", base=0x08000000, size=0x100000, permissions="rx", kind="flash")
    assert r.base == 0x08000000
    assert r.kind == "flash"


def test_memory_map_defaults():
    m = MemoryMap(binary_path="test.bin", arch="ARM:LE:32:Cortex", base_address=0x08000000, entry_point=0x08000101)
    assert m.regions == []
    assert m.hypotheses_source == "vector_table"


def test_memory_access_defaults():
    a = MemoryAccess(address=0x1000, kind="load", width=4)
    assert a.target_addr is None
    assert a.base_provenance == "UNKNOWN"
    assert a.in_isr is False


def test_source_candidate_fields():
    c = SourceCandidate(address=0x40011004, function_name="uart_read", preliminary_label=SourceLabel.MMIO_READ)
    assert c.preliminary_label == SourceLabel.MMIO_READ
    assert c.confidence_score == 0.0
    assert c.evidence == []


def test_sink_candidate_fields():
    c = SinkCandidate(address=0x08001234, function_name="handler", preliminary_label=SinkLabel.COPY_SINK)
    assert c.preliminary_label == SinkLabel.COPY_SINK


def test_evidence_pack_fields():
    p = EvidencePack(pack_id="test-0x100-0x200", candidate_hint="MMIO_READ", binary_path="fw.bin", address=0x100, function_name="f")
    assert p.pack_id == "test-0x100-0x200"
    assert p.evidence == []
    assert p.facts == {}


def test_obligation_defaults():
    o = Obligation(obligation_id="O_MMIO_1", kind="addr_range", description="Address in MMIO range")
    assert o.status == ObligationStatus.PENDING
    assert o.required is True


def test_verified_label_defaults():
    prop = LLMProposal(pack_id="p1", label="MMIO_READ", address=0x100, function_name="f")
    v = VerifiedLabel(pack_id="p1", proposal=prop)
    assert v.verdict == VerificationVerdict.UNKNOWN
    assert v.final_label is None


# ── JSON serialization ──────────────────────────────────────────────────────


def test_evidence_pack_serializable():
    p = EvidencePack(
        pack_id="fw-0x100",
        candidate_hint="MMIO_READ",
        binary_path="fw.bin",
        address=0x100,
        function_name="uart_poll",
        evidence=[EvidenceItem(evidence_id="E1", kind="SITE", text="ldr r1, [r0,#0x04]")],
    )
    d = asdict(p)
    s = json.dumps(d)
    assert "E1" in s
    assert "SITE" in s


def test_pipeline_result_defaults():
    r = PipelineResult(binary_path="fw.bin", run_id="test001")
    assert r.source_candidates == []
    assert r.sink_candidates == []
    assert r.stage_errors == {}
