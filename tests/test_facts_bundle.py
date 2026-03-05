"""Tests for M8 — Facts Bundle: build, write, load, query, callsite queue."""

import json
import os
from pathlib import Path

import pytest

from sourceagent.pipeline.facts_bundle import (
    FactsBundle,
    LabelEntry,
    build_callsite_queue,
    build_facts_bundle,
    get_labels,
    get_sinks,
    get_sources,
    load_facts_bundle,
    write_facts_bundle,
    _entry_to_dict,
    _dict_to_entry,
    _verified_label_to_entry,
)
from sourceagent.pipeline.models import (
    LLMProposal,
    Obligation,
    ObligationStatus,
    PipelineResult,
    VerificationVerdict,
    VerifiedLabel,
)


# ── Helpers ───────────────────────────────────────────────────────────────


def _make_verified_label(
    label="MMIO_READ",
    address=0x40004400,
    function_name="uart_poll",
    verdict=VerificationVerdict.VERIFIED,
    confidence=0.85,
    pack_id="pack_001",
    evidence_refs=None,
    claims=None,
    obligations=None,
    notes="",
):
    """Create a VerifiedLabel for testing."""
    proposal = LLMProposal(
        pack_id=pack_id,
        label=label,
        address=address,
        function_name=function_name,
        claims=claims or [],
        confidence=confidence,
        evidence_refs=evidence_refs or ["E1", "E2"],
        notes=notes,
    )
    if obligations is None:
        obligations = [
            Obligation(
                obligation_id="O_MMIO_1",
                kind="const_base_trace",
                description="CONST provenance",
                required=True,
                status=ObligationStatus.SATISFIED,
            ),
            Obligation(
                obligation_id="O_MMIO_2",
                kind="addr_range",
                description="MMIO range",
                required=True,
                status=ObligationStatus.SATISFIED,
            ),
        ]
    return VerifiedLabel(
        pack_id=pack_id,
        proposal=proposal,
        obligations=obligations,
        verdict=verdict,
        final_label=label if verdict in (VerificationVerdict.VERIFIED, VerificationVerdict.PARTIAL) else None,
    )


def _make_pipeline_result(verified_labels=None):
    """Create a PipelineResult for testing."""
    return PipelineResult(
        binary_path="/firmware/test.bin",
        run_id="test-run-001",
        verified_labels=verified_labels or [],
    )


def _make_bundle_with_entries():
    """Build a FactsBundle with diverse entries for query testing."""
    entries = [
        LabelEntry(
            label_id="MMIO_READ@0x40004400",
            label="MMIO_READ",
            address=0x40004400,
            function_name="uart_poll",
            verdict="VERIFIED",
            confidence=0.85,
            obligations_satisfied=2,
            obligations_total=2,
            evidence_refs=["E1", "E2"],
            pack_id="pack_001",
        ),
        LabelEntry(
            label_id="ISR_MMIO_READ@0x40004404",
            label="ISR_MMIO_READ",
            address=0x40004404,
            function_name="USART1_IRQHandler",
            verdict="VERIFIED",
            confidence=0.90,
            obligations_satisfied=3,
            obligations_total=3,
            evidence_refs=["E3"],
            pack_id="pack_002",
        ),
        LabelEntry(
            label_id="COPY_SINK@0x08001234",
            label="COPY_SINK",
            address=0x08001234,
            function_name="handler",
            verdict="VERIFIED",
            confidence=0.80,
            obligations_satisfied=2,
            obligations_total=3,
            evidence_refs=["E4", "E5"],
            pack_id="pack_003",
            facts={"callee": "memcpy"},
        ),
        LabelEntry(
            label_id="MEMSET_SINK@0x08001300",
            label="MEMSET_SINK",
            address=0x08001300,
            function_name="handler",
            verdict="PARTIAL",
            confidence=0.60,
            obligations_satisfied=1,
            obligations_total=3,
            evidence_refs=["E6"],
            pack_id="pack_004",
        ),
        LabelEntry(
            label_id="MMIO_READ@0x40004400_2",
            label="MMIO_READ",
            address=0x40004400,
            function_name="spi_read",
            verdict="VERIFIED",
            confidence=0.75,
            pack_id="pack_005",
        ),
    ]
    return FactsBundle(
        binary_path="/firmware/test.bin",
        run_id="test-run-001",
        created_at="2026-03-01T00:00:00+00:00",
        entries=entries,
    )


# ── LabelEntry tests ─────────────────────────────────────────────────────


def test_label_entry_defaults():
    entry = LabelEntry(label_id="x", label="MMIO_READ", address=0, function_name="f", verdict="VERIFIED")
    assert entry.confidence == 0.0
    assert entry.evidence_refs == []
    assert entry.facts == {}


def test_entry_to_dict_roundtrip():
    entry = LabelEntry(
        label_id="MMIO_READ@0x40004400",
        label="MMIO_READ",
        address=0x40004400,
        function_name="uart_poll",
        verdict="VERIFIED",
        confidence=0.85,
        obligations_satisfied=2,
        obligations_total=4,
        evidence_refs=["E1"],
        pack_id="p1",
        rationale="test",
        facts={"key": "val"},
    )
    d = _entry_to_dict(entry)
    restored = _dict_to_entry(d)
    assert restored.label_id == entry.label_id
    assert restored.address == entry.address
    assert restored.facts == {"key": "val"}
    assert restored.evidence_refs == ["E1"]


def test_dict_to_entry_missing_fields():
    entry = _dict_to_entry({"label": "COPY_SINK"})
    assert entry.label == "COPY_SINK"
    assert entry.address == 0
    assert entry.function_name == ""
    assert entry.confidence == 0.0


# ── FactsBundle tests ────────────────────────────────────────────────────


def test_facts_bundle_empty():
    bundle = FactsBundle()
    assert bundle.label_count == 0
    assert bundle.source_count == 0
    assert bundle.sink_count == 0


def test_facts_bundle_indices_built_on_init():
    bundle = _make_bundle_with_entries()
    assert len(bundle._by_function["handler"]) == 2  # COPY_SINK + MEMSET_SINK
    assert len(bundle._by_label["MMIO_READ"]) == 2
    assert len(bundle._by_address[0x40004400]) == 2
    assert len(bundle._by_verdict["VERIFIED"]) == 4
    assert len(bundle._by_verdict["PARTIAL"]) == 1


def test_facts_bundle_counts():
    bundle = _make_bundle_with_entries()
    assert bundle.label_count == 5
    assert bundle.source_count == 3  # MMIO_READ x2, ISR_MMIO_READ
    assert bundle.sink_count == 2  # COPY_SINK, MEMSET_SINK


def test_facts_bundle_rebuild_indices():
    bundle = FactsBundle(entries=[
        LabelEntry(label_id="a", label="MMIO_READ", address=1, function_name="f", verdict="VERIFIED"),
    ])
    assert len(bundle._by_label["MMIO_READ"]) == 1
    bundle.entries.append(
        LabelEntry(label_id="b", label="COPY_SINK", address=2, function_name="g", verdict="VERIFIED"),
    )
    bundle._build_indices()
    assert len(bundle._by_label) == 2


# ── build_facts_bundle tests ─────────────────────────────────────────────


def test_build_facts_bundle_empty():
    result = _make_pipeline_result()
    bundle = build_facts_bundle(result)
    assert bundle.label_count == 0
    assert bundle.binary_path == "/firmware/test.bin"
    assert bundle.run_id == "test-run-001"


def test_build_facts_bundle_filters_rejected():
    vl_verified = _make_verified_label(verdict=VerificationVerdict.VERIFIED)
    vl_rejected = _make_verified_label(
        label="COPY_SINK", address=0x08001234,
        verdict=VerificationVerdict.REJECTED, pack_id="rej_001",
    )
    vl_partial = _make_verified_label(
        label="MEMSET_SINK", address=0x08001300,
        verdict=VerificationVerdict.PARTIAL, pack_id="part_001",
    )
    result = _make_pipeline_result([vl_verified, vl_rejected, vl_partial])
    bundle = build_facts_bundle(result)
    assert bundle.label_count == 2  # VERIFIED + PARTIAL, not REJECTED
    labels = {e.label for e in bundle.entries}
    assert "MMIO_READ" in labels
    assert "MEMSET_SINK" in labels


def test_build_facts_bundle_custom_verdicts():
    vl = _make_verified_label(verdict=VerificationVerdict.VERIFIED)
    result = _make_pipeline_result([vl])
    bundle = build_facts_bundle(result, accepted_verdicts=["REJECTED"])
    assert bundle.label_count == 0  # VERIFIED not in accepted


def test_build_facts_bundle_all_verdicts():
    labels = [
        _make_verified_label(verdict=VerificationVerdict.VERIFIED, pack_id="p1"),
        _make_verified_label(
            label="COPY_SINK", address=0x08001234,
            verdict=VerificationVerdict.REJECTED, pack_id="p2",
        ),
        _make_verified_label(
            label="STORE_SINK", address=0x08001300,
            verdict=VerificationVerdict.UNKNOWN, pack_id="p3",
        ),
    ]
    result = _make_pipeline_result(labels)
    bundle = build_facts_bundle(result, accepted_verdicts=["VERIFIED", "REJECTED", "UNKNOWN"])
    assert bundle.label_count == 3


def test_build_facts_bundle_label_id_format():
    vl = _make_verified_label(label="MMIO_READ", address=0x40004400)
    result = _make_pipeline_result([vl])
    bundle = build_facts_bundle(result)
    entry = bundle.entries[0]
    assert entry.label_id == "MMIO_READ@0x40004400"


def test_build_facts_bundle_preserves_claims_as_facts():
    vl = _make_verified_label(
        claims=[{"callee": "memcpy"}, {"dst_provenance": "ARG"}],
    )
    result = _make_pipeline_result([vl])
    bundle = build_facts_bundle(result)
    entry = bundle.entries[0]
    assert entry.facts.get("callee") == "memcpy"
    assert entry.facts.get("dst_provenance") == "ARG"


def test_build_facts_bundle_obligations_count():
    obs = [
        Obligation("O1", "k1", "d1", required=True, status=ObligationStatus.SATISFIED),
        Obligation("O2", "k2", "d2", required=True, status=ObligationStatus.VIOLATED),
        Obligation("O3", "k3", "d3", required=False, status=ObligationStatus.SATISFIED),
    ]
    vl = _make_verified_label(obligations=obs, verdict=VerificationVerdict.PARTIAL)
    result = _make_pipeline_result([vl])
    bundle = build_facts_bundle(result)
    entry = bundle.entries[0]
    assert entry.obligations_satisfied == 2  # O1 + O3
    assert entry.obligations_total == 3


def test_build_facts_bundle_created_at():
    result = _make_pipeline_result([_make_verified_label()])
    bundle = build_facts_bundle(result)
    assert bundle.created_at  # Non-empty ISO timestamp


# ── _verified_label_to_entry tests ────────────────────────────────────────


def test_verified_label_to_entry_basic():
    vl = _make_verified_label(
        label="COPY_SINK", address=0x08001234, function_name="handler",
        confidence=0.8, evidence_refs=["E1", "E2"],
    )
    entry = _verified_label_to_entry(vl)
    assert entry.label == "COPY_SINK"
    assert entry.address == 0x08001234
    assert entry.function_name == "handler"
    assert entry.confidence == 0.8
    assert entry.evidence_refs == ["E1", "E2"]
    assert entry.verdict == "VERIFIED"


def test_verified_label_to_entry_no_final_label_uses_proposal():
    vl = _make_verified_label(verdict=VerificationVerdict.REJECTED)
    # final_label is None for REJECTED
    entry = _verified_label_to_entry(vl)
    assert entry.label == "MMIO_READ"  # Falls back to proposal.label


def test_verified_label_to_entry_zero_address():
    vl = _make_verified_label(address=0)
    entry = _verified_label_to_entry(vl)
    assert entry.label_id == "MMIO_READ@0x00000000"


# ── write / load roundtrip tests ─────────────────────────────────────────


def test_write_and_load_roundtrip(tmp_path):
    bundle = _make_bundle_with_entries()
    out = write_facts_bundle(bundle, str(tmp_path / "facts"))
    assert (out / "labels.jsonl").exists()
    assert (out / "index.json").exists()

    loaded = load_facts_bundle(str(out))
    assert loaded.label_count == bundle.label_count
    assert loaded.binary_path == bundle.binary_path
    assert loaded.run_id == bundle.run_id

    # Verify entry content preserved
    for orig, loaded_entry in zip(bundle.entries, loaded.entries):
        assert orig.label_id == loaded_entry.label_id
        assert orig.address == loaded_entry.address
        assert orig.label == loaded_entry.label
        assert orig.function_name == loaded_entry.function_name
        assert orig.verdict == loaded_entry.verdict
        assert orig.confidence == loaded_entry.confidence


def test_write_creates_directory(tmp_path):
    bundle = FactsBundle(entries=[
        LabelEntry(label_id="a", label="MMIO_READ", address=1, function_name="f", verdict="VERIFIED"),
    ])
    nested = tmp_path / "deep" / "nested" / "dir"
    write_facts_bundle(bundle, str(nested))
    assert (nested / "labels.jsonl").exists()


def test_write_empty_bundle(tmp_path):
    bundle = FactsBundle()
    out = write_facts_bundle(bundle, str(tmp_path / "empty"))
    assert (out / "labels.jsonl").exists()
    assert (out / "index.json").exists()

    loaded = load_facts_bundle(str(out))
    assert loaded.label_count == 0


def test_load_missing_labels_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_facts_bundle(str(tmp_path / "nonexistent"))


def test_load_missing_index_still_works(tmp_path):
    """labels.jsonl is required, index.json is optional."""
    labels_path = tmp_path / "labels.jsonl"
    entry = LabelEntry(
        label_id="MMIO_READ@0x40004400", label="MMIO_READ",
        address=0x40004400, function_name="f", verdict="VERIFIED",
    )
    labels_path.write_text(json.dumps(_entry_to_dict(entry)) + "\n")

    loaded = load_facts_bundle(str(tmp_path))
    assert loaded.label_count == 1
    assert loaded.binary_path == ""  # No index.json


def test_write_index_json_content(tmp_path):
    bundle = _make_bundle_with_entries()
    out = write_facts_bundle(bundle, str(tmp_path / "facts"))
    index = json.loads((out / "index.json").read_text())
    assert index["label_count"] == 5
    assert index["source_count"] == 3
    assert index["sink_count"] == 2
    assert "MMIO_READ" in index["by_label"]
    assert index["by_label"]["MMIO_READ"] == 2
    assert "handler" in index["functions"]
    assert "uart_poll" in index["functions"]


def test_write_labels_jsonl_format(tmp_path):
    bundle = _make_bundle_with_entries()
    out = write_facts_bundle(bundle, str(tmp_path / "facts"))
    lines = (out / "labels.jsonl").read_text().strip().split("\n")
    assert len(lines) == 5
    for line in lines:
        data = json.loads(line)
        assert "label_id" in data
        assert "label" in data
        assert "address" in data


def test_load_preserves_facts(tmp_path):
    bundle = FactsBundle(entries=[
        LabelEntry(
            label_id="x", label="COPY_SINK", address=1,
            function_name="f", verdict="VERIFIED",
            facts={"callee": "memcpy", "len_is_constant": False},
        ),
    ])
    write_facts_bundle(bundle, str(tmp_path))
    loaded = load_facts_bundle(str(tmp_path))
    assert loaded.entries[0].facts["callee"] == "memcpy"
    assert loaded.entries[0].facts["len_is_constant"] is False


# ── Query API: get_sources ────────────────────────────────────────────────


def test_get_sources_all():
    bundle = _make_bundle_with_entries()
    sources = get_sources(bundle)
    assert len(sources) == 3
    for s in sources:
        assert s.label in ("MMIO_READ", "ISR_MMIO_READ", "ISR_FILLED_BUFFER", "DMA_BACKED_BUFFER")


def test_get_sources_by_function():
    bundle = _make_bundle_with_entries()
    sources = get_sources(bundle, func="uart_poll")
    assert len(sources) == 1
    assert sources[0].function_name == "uart_poll"


def test_get_sources_by_label_type():
    bundle = _make_bundle_with_entries()
    sources = get_sources(bundle, label_type="ISR_MMIO_READ")
    assert len(sources) == 1
    assert sources[0].label == "ISR_MMIO_READ"


def test_get_sources_by_verdict():
    bundle = _make_bundle_with_entries()
    sources = get_sources(bundle, verdict="VERIFIED")
    assert len(sources) == 3  # All sources are VERIFIED


def test_get_sources_no_match():
    bundle = _make_bundle_with_entries()
    sources = get_sources(bundle, func="nonexistent_func")
    assert len(sources) == 0


def test_get_sources_excludes_sinks():
    bundle = _make_bundle_with_entries()
    sources = get_sources(bundle)
    for s in sources:
        assert s.label not in ("COPY_SINK", "MEMSET_SINK", "STORE_SINK", "LOOP_WRITE_SINK")


# ── Query API: get_sinks ─────────────────────────────────────────────────


def test_get_sinks_all():
    bundle = _make_bundle_with_entries()
    sinks = get_sinks(bundle)
    assert len(sinks) == 2
    for s in sinks:
        assert s.label in ("COPY_SINK", "MEMSET_SINK", "STORE_SINK", "LOOP_WRITE_SINK")


def test_get_sinks_by_function():
    bundle = _make_bundle_with_entries()
    sinks = get_sinks(bundle, func="handler")
    assert len(sinks) == 2  # COPY_SINK + MEMSET_SINK in handler


def test_get_sinks_by_label_type():
    bundle = _make_bundle_with_entries()
    sinks = get_sinks(bundle, label_type="COPY_SINK")
    assert len(sinks) == 1
    assert sinks[0].label == "COPY_SINK"


def test_get_sinks_by_verdict_partial():
    bundle = _make_bundle_with_entries()
    sinks = get_sinks(bundle, verdict="PARTIAL")
    assert len(sinks) == 1
    assert sinks[0].label == "MEMSET_SINK"


def test_get_sinks_excludes_sources():
    bundle = _make_bundle_with_entries()
    sinks = get_sinks(bundle)
    for s in sinks:
        assert s.label not in ("MMIO_READ", "ISR_MMIO_READ", "ISR_FILLED_BUFFER", "DMA_BACKED_BUFFER")


# ── Query API: get_labels ─────────────────────────────────────────────────


def test_get_labels_all():
    bundle = _make_bundle_with_entries()
    labels = get_labels(bundle)
    assert len(labels) == 5


def test_get_labels_by_address():
    bundle = _make_bundle_with_entries()
    labels = get_labels(bundle, addr=0x40004400)
    assert len(labels) == 2  # Two MMIO_READ at same address


def test_get_labels_by_address_no_match():
    bundle = _make_bundle_with_entries()
    labels = get_labels(bundle, addr=0xDEADBEEF)
    assert len(labels) == 0


def test_get_labels_combined_filters():
    bundle = _make_bundle_with_entries()
    labels = get_labels(bundle, func="handler", label_type="COPY_SINK")
    assert len(labels) == 1
    assert labels[0].label == "COPY_SINK"


def test_get_labels_address_plus_function():
    bundle = _make_bundle_with_entries()
    labels = get_labels(bundle, addr=0x40004400, func="spi_read")
    assert len(labels) == 1
    assert labels[0].function_name == "spi_read"


def test_get_labels_func_substring_match():
    bundle = _make_bundle_with_entries()
    labels = get_labels(bundle, func="IRQ")
    assert len(labels) == 1
    assert "IRQ" in labels[0].function_name


# ── build_callsite_queue tests ────────────────────────────────────────────


def test_callsite_queue_basic():
    bundle = _make_bundle_with_entries()
    queue = build_callsite_queue(bundle)
    assert len(queue) == 2  # COPY_SINK + MEMSET_SINK


def test_callsite_queue_fields():
    bundle = _make_bundle_with_entries()
    queue = build_callsite_queue(bundle)
    task = queue[0]
    assert task["task"] == "analyze_sink"
    assert "sink_label_id" in task
    assert "label" in task
    assert "address" in task
    assert "function" in task
    assert "verdict" in task
    assert "confidence" in task
    assert "context" in task
    assert "evidence_refs" in task["context"]
    assert "source_hints" in task["context"]
    assert "facts" in task["context"]


def test_callsite_queue_empty_bundle():
    bundle = FactsBundle()
    queue = build_callsite_queue(bundle)
    assert queue == []


def test_callsite_queue_sources_only():
    bundle = FactsBundle(entries=[
        LabelEntry(label_id="MMIO_READ@0x40004400", label="MMIO_READ",
                    address=0x40004400, function_name="f", verdict="VERIFIED"),
    ])
    queue = build_callsite_queue(bundle)
    assert queue == []  # No sinks


def test_callsite_queue_includes_source_hints():
    """Source hints should cross-reference sources in the same function."""
    bundle = FactsBundle(entries=[
        LabelEntry(label_id="MMIO_READ@0x40004400", label="MMIO_READ",
                    address=0x40004400, function_name="handler", verdict="VERIFIED"),
        LabelEntry(label_id="COPY_SINK@0x08001234", label="COPY_SINK",
                    address=0x08001234, function_name="handler", verdict="VERIFIED"),
    ])
    queue = build_callsite_queue(bundle)
    assert len(queue) == 1
    assert queue[0]["context"]["source_hints"] == ["MMIO_READ@0x40004400"]


def test_callsite_queue_no_cross_function_hints():
    """Sources in different functions shouldn't appear as hints."""
    bundle = FactsBundle(entries=[
        LabelEntry(label_id="MMIO_READ@0x40004400", label="MMIO_READ",
                    address=0x40004400, function_name="uart_poll", verdict="VERIFIED"),
        LabelEntry(label_id="COPY_SINK@0x08001234", label="COPY_SINK",
                    address=0x08001234, function_name="handler", verdict="VERIFIED"),
    ])
    queue = build_callsite_queue(bundle)
    assert queue[0]["context"]["source_hints"] == []


def test_callsite_queue_preserves_facts():
    bundle = FactsBundle(entries=[
        LabelEntry(label_id="COPY_SINK@0x08001234", label="COPY_SINK",
                    address=0x08001234, function_name="handler", verdict="VERIFIED",
                    facts={"callee": "memcpy", "dst_provenance": "ARG"}),
    ])
    queue = build_callsite_queue(bundle)
    assert queue[0]["context"]["facts"]["callee"] == "memcpy"


# ── CLI integration: _reconstruct_pipeline_result ─────────────────────────


def test_reconstruct_pipeline_result():
    from sourceagent.interface.main import _reconstruct_pipeline_result

    data = {
        "binary_path": "/test.bin",
        "run_id": "r1",
        "verified_labels": [
            {
                "pack_id": "p1",
                "proposal": {
                    "pack_id": "p1",
                    "label": "MMIO_READ",
                    "address": 0x40004400,
                    "function_name": "uart_poll",
                    "claims": [{"callee": "test"}],
                    "confidence": 0.85,
                    "evidence_refs": ["E1"],
                    "notes": "test note",
                },
                "obligations": [
                    {
                        "obligation_id": "O1",
                        "kind": "addr_range",
                        "description": "MMIO range",
                        "required": True,
                        "status": "satisfied",
                        "evidence": "ok",
                    },
                ],
                "verdict": "VERIFIED",
                "final_label": "MMIO_READ",
            },
        ],
        "stage_errors": {},
    }

    result = _reconstruct_pipeline_result(data)
    assert result.binary_path == "/test.bin"
    assert len(result.verified_labels) == 1

    vl = result.verified_labels[0]
    assert vl.verdict == VerificationVerdict.VERIFIED
    assert vl.proposal.label == "MMIO_READ"
    assert vl.proposal.confidence == 0.85
    assert len(vl.obligations) == 1
    assert vl.obligations[0].status == ObligationStatus.SATISFIED


def test_reconstruct_handles_unknown_verdict():
    from sourceagent.interface.main import _reconstruct_pipeline_result

    data = {
        "binary_path": "/test.bin",
        "run_id": "r1",
        "verified_labels": [
            {
                "pack_id": "p1",
                "proposal": {"pack_id": "p1", "label": "X", "address": 0, "function_name": ""},
                "obligations": [],
                "verdict": "INVALID_VERDICT",
                "final_label": None,
            },
        ],
    }
    result = _reconstruct_pipeline_result(data)
    assert result.verified_labels[0].verdict == VerificationVerdict.UNKNOWN


def test_reconstruct_empty():
    from sourceagent.interface.main import _reconstruct_pipeline_result

    data = {"binary_path": "", "run_id": "", "verified_labels": []}
    result = _reconstruct_pipeline_result(data)
    assert result.verified_labels == []


# ── Full pipeline integration ─────────────────────────────────────────────


def test_build_write_load_query_roundtrip(tmp_path):
    """End-to-end: build from PipelineResult, write, load, query."""
    verified = [
        _make_verified_label(label="MMIO_READ", address=0x40004400, pack_id="p1"),
        _make_verified_label(label="COPY_SINK", address=0x08001234, function_name="handler", pack_id="p2"),
        _make_verified_label(label="STORE_SINK", address=0x08001300, verdict=VerificationVerdict.REJECTED, pack_id="p3"),
    ]
    result = _make_pipeline_result(verified)

    # Build (default: VERIFIED + PARTIAL)
    bundle = build_facts_bundle(result)
    assert bundle.label_count == 2  # REJECTED excluded

    # Write
    out = write_facts_bundle(bundle, str(tmp_path / "export"))

    # Load
    loaded = load_facts_bundle(str(out))
    assert loaded.label_count == 2

    # Query
    sources = get_sources(loaded)
    assert len(sources) == 1
    assert sources[0].label == "MMIO_READ"

    sinks = get_sinks(loaded)
    assert len(sinks) == 1
    assert sinks[0].label == "COPY_SINK"

    # Callsite queue
    queue = build_callsite_queue(loaded)
    assert len(queue) == 1
    assert queue[0]["label"] == "COPY_SINK"


def test_export_from_mine_json_roundtrip(tmp_path):
    """Simulate: mine --output result.json, then export from that JSON."""
    from sourceagent.interface.main import _reconstruct_pipeline_result, _write_json_output

    verified = [
        _make_verified_label(label="MMIO_READ", address=0x40004400, pack_id="p1"),
        _make_verified_label(
            label="COPY_SINK", address=0x08001234,
            function_name="handler", pack_id="p2",
            claims=[{"callee": "memcpy"}],
        ),
    ]
    result = _make_pipeline_result(verified)

    # Write JSON (like mine --output)
    json_path = str(tmp_path / "result.json")
    _write_json_output(result, json_path)

    # Reconstruct (like export subcommand)
    data = json.loads(Path(json_path).read_text())
    reconstructed = _reconstruct_pipeline_result(data)

    # Build bundle from reconstructed result
    bundle = build_facts_bundle(reconstructed)
    assert bundle.label_count == 2

    # Verify facts survived the roundtrip
    sinks = get_sinks(bundle)
    assert len(sinks) == 1
    assert sinks[0].facts.get("callee") == "memcpy"
