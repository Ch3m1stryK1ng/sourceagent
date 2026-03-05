"""Tests for pipeline/proposer.py — Stage 6 (M6)."""

import json
import pytest

from sourceagent.pipeline.models import (
    EvidencePack,
    EvidenceItem,
    LLMProposal,
)
from sourceagent.pipeline.proposer import (
    propose_labels,
    _propose_heuristic,
    _heuristic_confidence,
    _build_prompt,
    _parse_llm_response,
    _extract_json,
    _apply_budget,
    _cache_key,
    _fallback_proposal,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_pack(
    label="MMIO_READ",
    addr=0x40011000,
    func="uart_read",
    facts=None,
    evidence=None,
):
    """Build an EvidencePack for testing."""
    if evidence is None:
        evidence = [
            EvidenceItem("E1", "SITE", f"load from 0x{addr:08x}", address=addr),
            EvidenceItem("E2", "DEF", "CONST provenance"),
        ]
    if facts is None:
        facts = {"addr_expr": f"CONST(0x{addr:08x})", "segment_of_base": "PERIPHERAL_RANGE"}

    return EvidencePack(
        pack_id=f"{label}@{func}-0x{addr:08x}-abc123",
        candidate_hint=label,
        binary_path="test.bin",
        address=addr,
        function_name=func,
        facts=facts,
        evidence=evidence,
    )


class MockLLM:
    """Mock LLM callable that returns pre-configured JSON responses."""

    def __init__(self, response_json=None, response_text=None, raise_error=None):
        self.response_json = response_json
        self.response_text = response_text
        self.raise_error = raise_error
        self.call_count = 0
        self.last_messages = None
        self.last_model = None

    async def __call__(self, messages, model="", temperature=0, max_tokens=1000, **kwargs):
        self.call_count += 1
        self.last_messages = messages
        self.last_model = model

        if self.raise_error:
            raise self.raise_error

        if self.response_text is not None:
            return self.response_text

        if self.response_json is not None:
            return json.dumps(self.response_json)

        return json.dumps({
            "label": "MMIO_READ",
            "claims": [{"type": "CONST_ADDR_LOAD", "evidence_refs": ["E1", "E2"]}],
            "confidence": 0.78,
            "evidence_refs": ["E1", "E2"],
            "notes": "Load from peripheral-range constant base.",
        })


# ── Heuristic mode ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_heuristic_mode_basic():
    """Heuristic mode should accept miner hint as label."""
    pack = _make_pack()
    results = await propose_labels([pack], mode="heuristic")

    assert len(results) == 1
    assert results[0].label == "MMIO_READ"
    assert results[0].pack_id == pack.pack_id
    assert results[0].address == pack.address
    assert results[0].function_name == pack.function_name


@pytest.mark.asyncio
async def test_heuristic_mode_passes_facts_in_claims():
    """Facts from evidence pack should be in claims for verifier."""
    facts = {"addr_expr": "CONST(0x40011000)", "in_isr": False}
    pack = _make_pack(facts=facts)
    results = await propose_labels([pack], mode="heuristic")

    assert len(results[0].claims) >= 1
    assert results[0].claims[0] == facts


@pytest.mark.asyncio
async def test_heuristic_mode_evidence_refs():
    """Evidence refs should list all evidence IDs from the pack."""
    pack = _make_pack()
    results = await propose_labels([pack], mode="heuristic")

    assert "E1" in results[0].evidence_refs
    assert "E2" in results[0].evidence_refs


@pytest.mark.asyncio
async def test_heuristic_mode_empty_packs():
    """Empty pack list should return empty results."""
    results = await propose_labels([], mode="heuristic")
    assert results == []


@pytest.mark.asyncio
async def test_heuristic_mode_multiple_packs():
    """Multiple packs should each produce one proposal."""
    packs = [
        _make_pack(label="MMIO_READ", addr=0x40011000),
        _make_pack(label="ISR_MMIO_READ", addr=0x40022000, func="handler"),
    ]
    results = await propose_labels(packs, mode="heuristic")

    assert len(results) == 2
    labels = {r.label for r in results}
    assert "MMIO_READ" in labels
    assert "ISR_MMIO_READ" in labels


@pytest.mark.asyncio
async def test_heuristic_mode_empty_facts():
    """Pack with no facts should produce proposal with empty claims."""
    pack = _make_pack(facts={})
    results = await propose_labels([pack], mode="heuristic")

    assert results[0].claims == []


@pytest.mark.asyncio
async def test_heuristic_mode_notes():
    """Heuristic proposals should have explanatory notes."""
    pack = _make_pack()
    results = await propose_labels([pack], mode="heuristic")

    assert "Heuristic" in results[0].notes
    assert "MMIO_READ" in results[0].notes


# ── Heuristic confidence ────────────────────────────────────────────────────


def test_heuristic_confidence_baseline():
    """Minimal pack should get baseline confidence (0.5+)."""
    pack = _make_pack(facts={}, evidence=[])
    assert _heuristic_confidence(pack) >= 0.5


def test_heuristic_confidence_evidence_bonus():
    """More evidence items should increase confidence."""
    pack_few = _make_pack(evidence=[
        EvidenceItem("E1", "SITE", "test"),
    ])
    pack_many = _make_pack(evidence=[
        EvidenceItem("E1", "SITE", "test"),
        EvidenceItem("E2", "DEF", "test"),
        EvidenceItem("E3", "GUARD", "test"),
    ])

    assert _heuristic_confidence(pack_many) > _heuristic_confidence(pack_few)


def test_heuristic_confidence_rmw_bonus():
    """Read-modify-write fact should boost confidence."""
    pack_plain = _make_pack(facts={})
    pack_rmw = _make_pack(facts={"has_read_modify_write": True})

    assert _heuristic_confidence(pack_rmw) > _heuristic_confidence(pack_plain)


def test_heuristic_confidence_capped():
    """Confidence should never exceed 0.95."""
    pack = _make_pack(
        facts={
            "has_read_modify_write": True,
            "multi_function_cluster": True,
            "in_isr": True,
            "has_pointer_like_write": True,
        },
        evidence=[
            EvidenceItem("E1", "SITE", "test"),
            EvidenceItem("E2", "DEF", "test"),
            EvidenceItem("E3", "GUARD", "test"),
        ],
    )
    assert _heuristic_confidence(pack) <= 0.95


# ── LLM mode ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_llm_mode_basic():
    """LLM mode should call the LLM and parse JSON response."""
    llm = MockLLM(response_json={
        "label": "MMIO_READ",
        "claims": [{"type": "CONST_ADDR_LOAD", "evidence_refs": ["E1"]}],
        "confidence": 0.85,
        "evidence_refs": ["E1", "E2"],
        "notes": "MMIO register read.",
    })
    pack = _make_pack()
    results = await propose_labels([pack], llm=llm, model="test-model", mode="llm")

    assert len(results) == 1
    assert results[0].label == "MMIO_READ"
    assert results[0].confidence == 0.85
    assert "E1" in results[0].evidence_refs
    assert llm.call_count == 1


@pytest.mark.asyncio
async def test_llm_mode_requires_llm():
    """LLM mode without llm= should raise ValueError."""
    pack = _make_pack()
    with pytest.raises(ValueError, match="LLM callable required"):
        await propose_labels([pack], llm=None, model="test", mode="llm")


@pytest.mark.asyncio
async def test_llm_mode_requires_model():
    """LLM mode without model= should raise ValueError."""
    pack = _make_pack()
    with pytest.raises(ValueError, match="Model name required"):
        await propose_labels([pack], llm=MockLLM(), model="", mode="llm")


@pytest.mark.asyncio
async def test_llm_mode_unknown_label():
    """LLM proposing UNKNOWN should be passed through."""
    llm = MockLLM(response_json={
        "label": "UNKNOWN",
        "claims": [],
        "confidence": 0.2,
        "evidence_refs": [],
        "notes": "Not enough evidence for MMIO_READ.",
    })
    pack = _make_pack()
    results = await propose_labels([pack], llm=llm, model="test", mode="llm")

    assert results[0].label == "UNKNOWN"
    assert results[0].confidence == 0.2


@pytest.mark.asyncio
async def test_llm_mode_fallback_on_error():
    """LLM call failure should fall back to heuristic."""
    llm = MockLLM(raise_error=RuntimeError("API error"))
    pack = _make_pack()
    results = await propose_labels([pack], llm=llm, model="test", mode="llm")

    assert len(results) == 1
    assert results[0].label == "MMIO_READ"  # Falls back to hint
    assert "fallback" in results[0].notes.lower()


@pytest.mark.asyncio
async def test_llm_mode_caching():
    """Same pack should use cached result on second call."""
    llm = MockLLM()
    pack = _make_pack()
    cache = {}

    results1 = await propose_labels([pack], llm=llm, model="test", mode="llm", cache=cache)
    results2 = await propose_labels([pack], llm=llm, model="test", mode="llm", cache=cache)

    assert llm.call_count == 1  # Only called once
    assert results1[0].label == results2[0].label


@pytest.mark.asyncio
async def test_llm_mode_passes_facts_in_claims():
    """LLM proposals should include pack facts in claims for verifier."""
    llm = MockLLM(response_json={
        "label": "MMIO_READ",
        "claims": [{"type": "CONST_ADDR_LOAD", "evidence_refs": ["E1"]}],
        "confidence": 0.8,
        "evidence_refs": ["E1"],
        "notes": "test",
    })
    facts = {"addr_expr": "CONST(0x40011000)", "segment_of_base": "PERIPHERAL_RANGE"}
    pack = _make_pack(facts=facts)
    results = await propose_labels([pack], llm=llm, model="test", mode="llm")

    # First claim should be the pack facts
    assert facts in results[0].claims


# ── Invalid mode ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_invalid_mode_raises():
    """Unknown mode should raise ValueError."""
    with pytest.raises(ValueError, match="Unknown proposer mode"):
        await propose_labels([_make_pack()], mode="invalid")


# ── Prompt construction ──────────────────────────────────────────────────────


def test_build_prompt_mmio_read():
    """MMIO_READ prompt should contain label-specific instructions."""
    pack = _make_pack(label="MMIO_READ")
    messages = _build_prompt(pack)

    assert len(messages) == 2
    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    assert "MMIO_READ" in messages[1]["content"]
    assert "peripheral" in messages[1]["content"].lower()


def test_build_prompt_includes_evidence():
    """Prompt should include evidence items from the pack."""
    pack = _make_pack()
    messages = _build_prompt(pack)

    user_content = messages[1]["content"]
    assert "[E1]" in user_content
    assert "[E2]" in user_content


def test_build_prompt_includes_facts():
    """Prompt should include structured facts."""
    pack = _make_pack(facts={"addr_expr": "CONST(0x40011000)", "in_isr": False})
    messages = _build_prompt(pack)

    user_content = messages[1]["content"]
    assert "addr_expr" in user_content
    assert "CONST(0x40011000)" in user_content


def test_build_prompt_isr_label():
    """ISR_MMIO_READ should use ISR-specific template."""
    pack = _make_pack(label="ISR_MMIO_READ")
    messages = _build_prompt(pack)

    assert "interrupt" in messages[1]["content"].lower()


def test_build_prompt_unknown_label_uses_default():
    """Unknown label should use default template."""
    pack = _make_pack(label="SOME_NEW_LABEL")
    messages = _build_prompt(pack)

    assert "SOME_NEW_LABEL" in messages[1]["content"]


def test_build_prompt_empty_evidence():
    """Pack with no evidence should still produce valid prompt."""
    pack = _make_pack(evidence=[])
    messages = _build_prompt(pack)

    assert "no evidence items" in messages[1]["content"]


def test_build_prompt_empty_facts():
    """Pack with no facts should still produce valid prompt."""
    pack = _make_pack(facts={})
    messages = _build_prompt(pack)

    assert "no facts" in messages[1]["content"]


def test_build_prompt_json_schema():
    """Prompt should include expected JSON output schema."""
    pack = _make_pack()
    messages = _build_prompt(pack)

    user_content = messages[1]["content"]
    assert '"label"' in user_content
    assert '"claims"' in user_content
    assert '"confidence"' in user_content
    assert '"evidence_refs"' in user_content


# ── JSON extraction ──────────────────────────────────────────────────────────


def test_extract_json_plain():
    """Plain JSON should pass through."""
    text = '{"label": "MMIO_READ"}'
    assert _extract_json(text) == text


def test_extract_json_markdown_block():
    """JSON inside markdown code block should be extracted."""
    text = '```json\n{"label": "MMIO_READ"}\n```'
    assert json.loads(_extract_json(text))["label"] == "MMIO_READ"


def test_extract_json_with_preamble():
    """JSON with text before should extract the JSON object."""
    text = 'Here is the result:\n{"label": "MMIO_READ"}'
    assert json.loads(_extract_json(text))["label"] == "MMIO_READ"


def test_extract_json_nested_braces():
    """Nested JSON should be extracted correctly."""
    text = '{"label": "X", "claims": [{"type": "A"}]}'
    parsed = json.loads(_extract_json(text))
    assert parsed["label"] == "X"
    assert parsed["claims"][0]["type"] == "A"


def test_extract_json_no_braces():
    """Text without JSON should return as-is."""
    text = "Not a JSON response"
    assert _extract_json(text) == text


# ── LLM response parsing ────────────────────────────────────────────────────


def test_parse_valid_response():
    """Valid JSON response should produce correct proposal."""
    pack = _make_pack()
    response = json.dumps({
        "label": "MMIO_READ",
        "claims": [{"type": "CONST_ADDR_LOAD", "evidence_refs": ["E1"]}],
        "confidence": 0.85,
        "evidence_refs": ["E1", "E2"],
        "notes": "Peripheral read.",
    })
    proposal = _parse_llm_response(response, pack)

    assert proposal.label == "MMIO_READ"
    assert proposal.confidence == 0.85
    assert "E1" in proposal.evidence_refs


def test_parse_invalid_json_falls_back():
    """Invalid JSON should produce fallback proposal."""
    pack = _make_pack()
    proposal = _parse_llm_response("not json at all", pack)

    assert proposal.label == "MMIO_READ"  # Falls back to hint
    assert proposal.confidence == 0.4  # Fallback confidence
    assert "parse" in proposal.notes.lower()


def test_parse_confidence_clamped():
    """Confidence outside 0-1 should be clamped."""
    pack = _make_pack()
    response = json.dumps({"label": "MMIO_READ", "confidence": 5.0})
    proposal = _parse_llm_response(response, pack)
    assert proposal.confidence == 1.0

    response = json.dumps({"label": "MMIO_READ", "confidence": -1.0})
    proposal = _parse_llm_response(response, pack)
    assert proposal.confidence == 0.0


def test_parse_missing_fields_default():
    """Missing optional fields should use defaults."""
    pack = _make_pack()
    response = json.dumps({"label": "MMIO_READ"})
    proposal = _parse_llm_response(response, pack)

    assert proposal.label == "MMIO_READ"
    assert proposal.confidence == 0.5  # default
    assert proposal.evidence_refs == []
    assert proposal.notes == ""


def test_parse_non_dict_response_falls_back():
    """Non-dict JSON (e.g., array) should fall back."""
    pack = _make_pack()
    proposal = _parse_llm_response("[1, 2, 3]", pack)

    assert proposal.label == "MMIO_READ"
    assert "fallback" in proposal.notes.lower()


def test_parse_includes_pack_facts():
    """Parsed proposal should include pack facts in claims."""
    facts = {"addr_expr": "CONST(0x40011000)"}
    pack = _make_pack(facts=facts)
    response = json.dumps({
        "label": "MMIO_READ",
        "claims": [{"type": "LLM_CLAIM"}],
        "confidence": 0.8,
    })
    proposal = _parse_llm_response(response, pack)

    assert facts in proposal.claims


def test_parse_llm_disagrees_with_hint():
    """LLM proposing different label should be allowed (verifier decides)."""
    pack = _make_pack(label="MMIO_READ")
    response = json.dumps({"label": "UNKNOWN", "confidence": 0.3})
    proposal = _parse_llm_response(response, pack)

    assert proposal.label == "UNKNOWN"


# ── Budget enforcement ───────────────────────────────────────────────────────


def test_budget_top_k():
    """Only top-K packs per label should be selected."""
    packs = [
        _make_pack(addr=0x40011000 + i, evidence=[
            EvidenceItem("E1", "SITE", f"test{i}"),
        ] * (i + 1))  # Varying evidence count for ranking
        for i in range(5)
    ]
    budgeted = _apply_budget(packs, top_k=3)
    assert len(budgeted) == 3


def test_budget_separate_labels():
    """Top-K should apply independently per label type."""
    packs = [
        _make_pack(label="MMIO_READ", addr=0x40011000 + i)
        for i in range(3)
    ] + [
        _make_pack(label="ISR_MMIO_READ", addr=0x40022000 + i, func="handler")
        for i in range(3)
    ]
    budgeted = _apply_budget(packs, top_k=2)

    labels = [p.candidate_hint for p in budgeted]
    assert labels.count("MMIO_READ") == 2
    assert labels.count("ISR_MMIO_READ") == 2


def test_budget_all_pass_when_under_limit():
    """All packs should pass when count <= top_k."""
    packs = [_make_pack(addr=0x40011000 + i) for i in range(3)]
    budgeted = _apply_budget(packs, top_k=10)
    assert len(budgeted) == 3


# ── Cache key ─────────────────────────────────────────────────────────────────


def test_cache_key_stable():
    """Same pack should produce same cache key."""
    pack = _make_pack()
    assert _cache_key(pack) == _cache_key(pack)


def test_cache_key_different_packs():
    """Different packs should produce different cache keys."""
    pack1 = _make_pack(addr=0x40011000)
    pack2 = _make_pack(addr=0x40022000)
    assert _cache_key(pack1) != _cache_key(pack2)


def test_cache_key_different_facts():
    """Different facts should produce different cache keys."""
    pack1 = _make_pack(facts={"a": 1})
    pack2 = _make_pack(facts={"a": 2})
    assert _cache_key(pack1) != _cache_key(pack2)


# ── Fallback proposal ────────────────────────────────────────────────────────


def test_fallback_proposal_uses_hint():
    """Fallback should use pack's candidate_hint as label."""
    pack = _make_pack(label="DMA_BACKED_BUFFER")
    proposal = _fallback_proposal(pack, "test reason")

    assert proposal.label == "DMA_BACKED_BUFFER"
    assert proposal.confidence == 0.4
    assert "test reason" in proposal.notes


def test_fallback_proposal_preserves_evidence_refs():
    """Fallback should preserve evidence refs."""
    pack = _make_pack()
    proposal = _fallback_proposal(pack, "error")

    assert "E1" in proposal.evidence_refs
    assert "E2" in proposal.evidence_refs


# ── Model tests (preserved from original) ────────────────────────────────────


def test_llm_proposal_fields():
    """LLMProposal should have required fields."""
    p = LLMProposal(
        pack_id="fw-0x100",
        label="MMIO_READ",
        address=0x100,
        function_name="uart_poll",
        confidence=0.85,
        evidence_refs=["E1", "E2"],
        notes="Load from peripheral-range constant base; used in bit-test loop.",
    )
    assert p.label == "MMIO_READ"
    assert p.confidence == 0.85
    assert "E1" in p.evidence_refs


def test_llm_proposal_claims_default_empty():
    """Claims should default to empty list."""
    p = LLMProposal(pack_id="p1", label="COPY_SINK", address=0x200, function_name="f")
    assert p.claims == []


# ── End-to-end: heuristic → verifier-compatible ──────────────────────────────


@pytest.mark.asyncio
async def test_heuristic_proposals_verifier_compatible():
    """Heuristic proposals should work with the verifier's _get_facts()."""
    pack = _make_pack(facts={
        "addr_expr": "CONST(0x40011000)",
        "segment_of_base": "PERIPHERAL_RANGE",
    })
    proposals = await propose_labels([pack], mode="heuristic")
    proposal = proposals[0]

    # Simulate what verifier._get_facts does
    facts = {}
    for claim in proposal.claims:
        if isinstance(claim, dict):
            facts.update(claim)

    assert facts["addr_expr"] == "CONST(0x40011000)"
    assert facts["segment_of_base"] == "PERIPHERAL_RANGE"


@pytest.mark.asyncio
async def test_all_source_labels_heuristic():
    """All source label types should work in heuristic mode."""
    labels = ["MMIO_READ", "ISR_MMIO_READ", "ISR_FILLED_BUFFER", "DMA_BACKED_BUFFER"]
    packs = [_make_pack(label=l, addr=0x40011000 + i) for i, l in enumerate(labels)]
    results = await propose_labels(packs, mode="heuristic")

    assert len(results) == 4
    result_labels = {r.label for r in results}
    for l in labels:
        assert l in result_labels
