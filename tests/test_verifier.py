"""Tests for pipeline/verifier.py — Stage 7 (M7)."""

import pytest

from sourceagent.pipeline.models import (
    LLMProposal,
    Obligation,
    ObligationStatus,
    VerificationVerdict,
    VerifiedLabel,
)
from sourceagent.pipeline.verifier import (
    verify_proposals,
    _compute_verdict,
    _generate_obligations,
    _check_obligations,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_proposal(label="MMIO_READ", addr=0x40011000, func="uart_read", facts=None):
    """Build a proposal with facts encoded in claims."""
    claims = [facts] if facts else []
    return LLMProposal(
        pack_id=f"test-{label}-0x{addr:08x}",
        label=label,
        address=addr,
        function_name=func,
        claims=claims,
        confidence=0.7,
    )


# ── Obligation generation ────────────────────────────────────────────────────


def test_mmio_read_generates_obligations():
    """MMIO_READ proposal → O_MMIO_1, O_MMIO_2, O_MMIO_3, O_MMIO_4."""
    proposal = _make_proposal("MMIO_READ")
    obligations = _generate_obligations(proposal)
    ids = {o.obligation_id for o in obligations}
    assert "O_MMIO_1" in ids
    assert "O_MMIO_2" in ids
    assert "O_MMIO_3" in ids
    assert "O_MMIO_4" in ids


def test_mmio_read_required_obligations():
    """O_MMIO_1 and O_MMIO_2 should be required; O_MMIO_3/4 optional."""
    proposal = _make_proposal("MMIO_READ")
    obligations = _generate_obligations(proposal)
    ob_map = {o.obligation_id: o for o in obligations}
    assert ob_map["O_MMIO_1"].required is True
    assert ob_map["O_MMIO_2"].required is True
    assert ob_map["O_MMIO_3"].required is False
    assert ob_map["O_MMIO_4"].required is False


def test_isr_mmio_read_has_isr_obligation():
    """ISR_MMIO_READ → has O_ISR_1 in addition to MMIO obligations."""
    proposal = _make_proposal("ISR_MMIO_READ")
    obligations = _generate_obligations(proposal)
    ids = {o.obligation_id for o in obligations}
    assert "O_ISR_1" in ids
    assert "O_MMIO_1" in ids
    assert "O_MMIO_2" in ids


def test_isr_filled_buffer_obligations():
    """ISR_FILLED_BUFFER → O_BUF_1, O_BUF_2."""
    proposal = _make_proposal("ISR_FILLED_BUFFER")
    obligations = _generate_obligations(proposal)
    ids = {o.obligation_id for o in obligations}
    assert "O_BUF_1" in ids
    assert "O_BUF_2" in ids


def test_dma_obligations():
    """DMA_BACKED_BUFFER → O_DMA_1, O_DMA_2."""
    proposal = _make_proposal("DMA_BACKED_BUFFER")
    obligations = _generate_obligations(proposal)
    ids = {o.obligation_id for o in obligations}
    assert "O_DMA_1" in ids
    assert "O_DMA_2" in ids


def test_unknown_label_no_obligations():
    """Unknown label → no obligations generated."""
    proposal = _make_proposal("UNKNOWN_LABEL")
    obligations = _generate_obligations(proposal)
    assert obligations == []


# ── Obligation checking ──────────────────────────────────────────────────────


def test_mmio_const_provenance_passes():
    """MMIO_READ with CONST in addr_expr → O_MMIO_1 satisfied."""
    proposal = _make_proposal("MMIO_READ", facts={
        "addr_expr": "CONST(0x40011000)",
        "segment_of_base": "PERIPHERAL_RANGE",
    })
    obligations = _generate_obligations(proposal)
    _check_obligations(obligations, proposal)

    ob1 = next(o for o in obligations if o.obligation_id == "O_MMIO_1")
    assert ob1.status == ObligationStatus.SATISFIED


def test_mmio_range_check_passes():
    """Target 0x40011000 → O_MMIO_2 satisfied (MMIO range)."""
    proposal = _make_proposal("MMIO_READ", addr=0x40011000, facts={
        "addr_expr": "CONST(0x40011000)",
        "segment_of_base": "PERIPHERAL_RANGE",
    })
    obligations = _generate_obligations(proposal)
    _check_obligations(obligations, proposal)

    ob2 = next(o for o in obligations if o.obligation_id == "O_MMIO_2")
    assert ob2.status == ObligationStatus.SATISFIED


def test_flash_address_fails_mmio_range():
    """Target 0x08001000 (flash) → O_MMIO_2 violated."""
    proposal = _make_proposal("MMIO_READ", addr=0x08001000, facts={
        "addr_expr": "CONST(0x08001000)",
        "segment_of_base": "FLASH",
    })
    obligations = _generate_obligations(proposal)
    _check_obligations(obligations, proposal)

    ob2 = next(o for o in obligations if o.obligation_id == "O_MMIO_2")
    assert ob2.status == ObligationStatus.VIOLATED


def test_system_peripheral_passes_range():
    """Target 0xE000E100 (NVIC) → O_MMIO_2 satisfied."""
    proposal = _make_proposal("MMIO_READ", addr=0xE000E100, facts={
        "addr_expr": "CONST(0xE000E100)",
    })
    obligations = _generate_obligations(proposal)
    _check_obligations(obligations, proposal)

    ob2 = next(o for o in obligations if o.obligation_id == "O_MMIO_2")
    assert ob2.status == ObligationStatus.SATISFIED


def test_read_modify_write_optional_satisfied():
    """Facts with has_read_modify_write → O_MMIO_3 satisfied."""
    proposal = _make_proposal("MMIO_READ", facts={
        "addr_expr": "CONST(0x40011000)",
        "segment_of_base": "PERIPHERAL_RANGE",
        "has_read_modify_write": True,
    })
    obligations = _generate_obligations(proposal)
    _check_obligations(obligations, proposal)

    ob3 = next(o for o in obligations if o.obligation_id == "O_MMIO_3")
    assert ob3.status == ObligationStatus.SATISFIED


def test_isr_context_check():
    """ISR_MMIO_READ with in_isr=True → O_ISR_1 satisfied."""
    proposal = _make_proposal("ISR_MMIO_READ", facts={
        "addr_expr": "CONST(0x40011000)",
        "segment_of_base": "PERIPHERAL_RANGE",
        "in_isr": True,
        "isr_function": "USART1_IRQHandler",
    })
    obligations = _generate_obligations(proposal)
    _check_obligations(obligations, proposal)

    ob_isr = next(o for o in obligations if o.obligation_id == "O_ISR_1")
    assert ob_isr.status == ObligationStatus.SATISFIED


def test_isr_context_check_fails_non_isr():
    """ISR_MMIO_READ with in_isr=False → O_ISR_1 violated."""
    proposal = _make_proposal("ISR_MMIO_READ", facts={
        "addr_expr": "CONST(0x40011000)",
        "segment_of_base": "PERIPHERAL_RANGE",
        "in_isr": False,
    })
    obligations = _generate_obligations(proposal)
    _check_obligations(obligations, proposal)

    ob_isr = next(o for o in obligations if o.obligation_id == "O_ISR_1")
    assert ob_isr.status == ObligationStatus.VIOLATED


def test_dma_config_cluster_check():
    """DMA with config_write_count >= 3 → O_DMA_1 satisfied."""
    proposal = _make_proposal("DMA_BACKED_BUFFER", facts={
        "config_write_count": 4,
        "has_pointer_like_write": True,
    })
    obligations = _generate_obligations(proposal)
    _check_obligations(obligations, proposal)

    ob = next(o for o in obligations if o.obligation_id == "O_DMA_1")
    assert ob.status == ObligationStatus.SATISFIED


def test_isr_buffer_obligations_check():
    """ISR_FILLED_BUFFER with write and read counts → both satisfied."""
    proposal = _make_proposal("ISR_FILLED_BUFFER", facts={
        "isr_write_count": 3,
        "non_isr_read_count": 2,
        "isr_writers": ["USART1_IRQHandler"],
        "non_isr_readers": ["main"],
    })
    obligations = _generate_obligations(proposal)
    _check_obligations(obligations, proposal)

    ob1 = next(o for o in obligations if o.obligation_id == "O_BUF_1")
    ob2 = next(o for o in obligations if o.obligation_id == "O_BUF_2")
    assert ob1.status == ObligationStatus.SATISFIED
    assert ob2.status == ObligationStatus.SATISFIED


# ── Verdict computation ──────────────────────────────────────────────────────


def test_all_satisfied_verified():
    """All required obligations satisfied → VERIFIED."""
    obligations = [
        Obligation("O1", "test", "Test", required=True, status=ObligationStatus.SATISFIED),
        Obligation("O2", "test", "Test", required=True, status=ObligationStatus.SATISFIED),
    ]
    assert _compute_verdict(obligations) == VerificationVerdict.VERIFIED


def test_any_required_violated_rejected():
    """One required obligation violated → REJECTED."""
    obligations = [
        Obligation("O1", "test", "Test", required=True, status=ObligationStatus.SATISFIED),
        Obligation("O2", "test", "Test", required=True, status=ObligationStatus.VIOLATED),
    ]
    assert _compute_verdict(obligations) == VerificationVerdict.REJECTED


def test_required_unknown_partial():
    """Required obligation unknown, none violated → PARTIAL."""
    obligations = [
        Obligation("O1", "test", "Test", required=True, status=ObligationStatus.SATISFIED),
        Obligation("O2", "test", "Test", required=True, status=ObligationStatus.UNKNOWN),
    ]
    assert _compute_verdict(obligations) == VerificationVerdict.PARTIAL


def test_empty_obligations_unknown():
    """No obligations → UNKNOWN."""
    assert _compute_verdict([]) == VerificationVerdict.UNKNOWN


def test_only_optional_obligations_verified():
    """Only optional obligations (none required) → VERIFIED."""
    obligations = [
        Obligation("O1", "test", "Test", required=False, status=ObligationStatus.VIOLATED),
    ]
    assert _compute_verdict(obligations) == VerificationVerdict.VERIFIED


def test_optional_violated_doesnt_reject():
    """Optional obligation violated + required satisfied → VERIFIED."""
    obligations = [
        Obligation("O1", "test", "Test", required=True, status=ObligationStatus.SATISFIED),
        Obligation("O2", "test", "Test", required=False, status=ObligationStatus.VIOLATED),
    ]
    assert _compute_verdict(obligations) == VerificationVerdict.VERIFIED


# ── End-to-end verify_proposals ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_verify_mmio_read_verified():
    """MMIO_READ with valid facts → VERIFIED verdict."""
    proposal = _make_proposal("MMIO_READ", addr=0x40011000, facts={
        "addr_expr": "CONST(0x40011000)",
        "segment_of_base": "PERIPHERAL_RANGE",
    })
    results = await verify_proposals([proposal])

    assert len(results) == 1
    assert results[0].verdict == VerificationVerdict.VERIFIED
    assert results[0].final_label == "MMIO_READ"


@pytest.mark.asyncio
async def test_verify_mmio_read_rejected_flash():
    """MMIO_READ at flash address → REJECTED (O_MMIO_2 fails)."""
    proposal = _make_proposal("MMIO_READ", addr=0x08001000, facts={
        "addr_expr": "CONST(0x08001000)",
    })
    results = await verify_proposals([proposal])

    assert len(results) == 1
    assert results[0].verdict == VerificationVerdict.REJECTED
    assert results[0].final_label is None


@pytest.mark.asyncio
async def test_verify_empty_proposals():
    """Empty proposal list → empty results."""
    results = await verify_proposals([])
    assert results == []


@pytest.mark.asyncio
async def test_verify_multiple_proposals():
    """Multiple proposals → one result each."""
    proposals = [
        _make_proposal("MMIO_READ", addr=0x40011000, facts={
            "addr_expr": "CONST(0x40011000)",
            "segment_of_base": "PERIPHERAL_RANGE",
        }),
        _make_proposal("MMIO_READ", addr=0x40022000, facts={
            "addr_expr": "CONST(0x40022000)",
            "segment_of_base": "PERIPHERAL_RANGE",
        }),
    ]
    results = await verify_proposals(proposals)
    assert len(results) == 2
    assert all(r.verdict == VerificationVerdict.VERIFIED for r in results)


# ── Model tests (preserved from original) ────────────────────────────────────


def test_obligation_status_transitions():
    """Obligations should be creatable in each status."""
    for status in ObligationStatus:
        o = Obligation(
            obligation_id="O_TEST",
            kind="test",
            description="Test obligation",
            status=status,
        )
        assert o.status == status


def test_mmio_read_obligations_structure():
    """MMIO_READ obligations should have specific kinds."""
    required_kinds = ["addr_range", "const_base_trace"]
    optional_kinds = ["polling_or_bittest", "multi_function_cluster"]

    for kind in required_kinds + optional_kinds:
        o = Obligation(
            obligation_id=f"O_MMIO_{kind}",
            kind=kind,
            description=f"Check {kind}",
            required=(kind in required_kinds),
        )
        assert o.required == (kind in required_kinds)


def test_verified_label_with_all_satisfied():
    """When all obligations are satisfied, verdict should be deterministic."""
    prop = LLMProposal(pack_id="p1", label="MMIO_READ", address=0x100, function_name="f")
    v = VerifiedLabel(
        pack_id="p1",
        proposal=prop,
        obligations=[
            Obligation("O1", "addr_range", "Address in MMIO", status=ObligationStatus.SATISFIED),
            Obligation("O2", "const_base", "CONST provenance", status=ObligationStatus.SATISFIED),
        ],
        verdict=VerificationVerdict.VERIFIED,
        final_label="MMIO_READ",
    )
    assert v.verdict == VerificationVerdict.VERIFIED
    assert v.final_label == "MMIO_READ"


def test_verified_label_with_violation():
    """When a required obligation is violated, verdict should be REJECTED."""
    prop = LLMProposal(pack_id="p2", label="MMIO_READ", address=0x200, function_name="g")
    v = VerifiedLabel(
        pack_id="p2",
        proposal=prop,
        obligations=[
            Obligation("O1", "addr_range", "Address in MMIO", status=ObligationStatus.VIOLATED),
        ],
        verdict=VerificationVerdict.REJECTED,
    )
    assert v.verdict == VerificationVerdict.REJECTED
    assert v.final_label is None


# ── COPY_SINK obligations ─────────────────────────────────────────────────────


def test_copy_sink_generates_obligations():
    """COPY_SINK proposal → O_COPY_1, O_COPY_2, O_COPY_3."""
    proposal = _make_proposal("COPY_SINK", addr=0x08001234, func="handler")
    obligations = _generate_obligations(proposal)
    ids = {o.obligation_id for o in obligations}
    assert "O_COPY_1" in ids
    assert "O_COPY_2" in ids
    assert "O_COPY_3" in ids


def test_copy_sink_required_obligations():
    """O_COPY_1 and O_COPY_2 required; O_COPY_3 optional."""
    proposal = _make_proposal("COPY_SINK", addr=0x08001234, func="handler")
    obligations = _generate_obligations(proposal)
    ob_map = {o.obligation_id: o for o in obligations}
    assert ob_map["O_COPY_1"].required is True
    assert ob_map["O_COPY_2"].required is True
    assert ob_map["O_COPY_3"].required is False


def test_copy_callsite_check_passes():
    """COPY_SINK with callee in facts → O_COPY_1 satisfied."""
    proposal = _make_proposal("COPY_SINK", addr=0x08001234, func="handler", facts={
        "callee": "memcpy",
        "args": ["dst", "src", "n"],
        "dst_provenance": "STACK_PTR",
    })
    obligations = _generate_obligations(proposal)
    _check_obligations(obligations, proposal)

    ob1 = next(o for o in obligations if o.obligation_id == "O_COPY_1")
    assert ob1.status == ObligationStatus.SATISFIED


def test_copy_args_check_passes():
    """COPY_SINK with args → O_COPY_2 satisfied."""
    proposal = _make_proposal("COPY_SINK", addr=0x08001234, func="handler", facts={
        "callee": "memcpy",
        "args": ["dst", "src", "n"],
    })
    obligations = _generate_obligations(proposal)
    _check_obligations(obligations, proposal)

    ob2 = next(o for o in obligations if o.obligation_id == "O_COPY_2")
    assert ob2.status == ObligationStatus.SATISFIED


def test_copy_loop_fallback_checks_pass_without_named_callee():
    """Stripped loop-copy facts should satisfy O_COPY_1/O_COPY_2 via fallback."""
    proposal = _make_proposal("COPY_SINK", addr=0x08001234, func="FUN_08001234", facts={
        "promoted_from": "LOOP_WRITE_SINK",
        "in_loop": True,
        "store_expr": "param_1[i]",
        "src_expr": "param_2[i]",
        "loop_bound": "param_3",
        "len_expr": "param_3",
    })
    obligations = _generate_obligations(proposal)
    _check_obligations(obligations, proposal)

    ob_map = {o.obligation_id: o for o in obligations}
    assert ob_map["O_COPY_1"].status == ObligationStatus.SATISFIED
    assert ob_map["O_COPY_2"].status == ObligationStatus.SATISFIED


def test_copy_no_guard_check_satisfied():
    """Variable-length + no guard → O_COPY_3 satisfied (strengthening)."""
    proposal = _make_proposal("COPY_SINK", addr=0x08001234, func="handler", facts={
        "callee": "memcpy",
        "args": ["dst", "src", "n"],
        "len_is_constant": False,
        "has_bounds_guard": False,
    })
    obligations = _generate_obligations(proposal)
    _check_obligations(obligations, proposal)

    ob3 = next(o for o in obligations if o.obligation_id == "O_COPY_3")
    assert ob3.status == ObligationStatus.SATISFIED


def test_copy_with_guard_check_violated():
    """Has bounds guard → O_COPY_3 violated (optional, doesn't reject)."""
    proposal = _make_proposal("COPY_SINK", addr=0x08001234, func="handler", facts={
        "callee": "memcpy",
        "args": ["dst", "src", "n"],
        "has_bounds_guard": True,
    })
    obligations = _generate_obligations(proposal)
    _check_obligations(obligations, proposal)

    ob3 = next(o for o in obligations if o.obligation_id == "O_COPY_3")
    assert ob3.status == ObligationStatus.VIOLATED


@pytest.mark.asyncio
async def test_verify_copy_sink_verified():
    """COPY_SINK with callee + args → VERIFIED."""
    proposal = _make_proposal("COPY_SINK", addr=0x08001234, func="handler", facts={
        "callee": "memcpy",
        "args": ["&local_20", "src", "n"],
        "dst_provenance": "STACK_PTR",
    })
    results = await verify_proposals([proposal])

    assert len(results) == 1
    assert results[0].verdict == VerificationVerdict.VERIFIED
    assert results[0].final_label == "COPY_SINK"


@pytest.mark.asyncio
async def test_verify_copy_sink_no_callee_rejected():
    """COPY_SINK without callee → O_COPY_1 fails → REJECTED."""
    proposal = _make_proposal("COPY_SINK", addr=0x08001234, func="handler", facts={
        "args": ["dst", "src", "n"],
    })
    results = await verify_proposals([proposal])

    assert len(results) == 1
    assert results[0].verdict == VerificationVerdict.REJECTED


@pytest.mark.asyncio
async def test_verify_copy_sink_loop_fallback_verified():
    """Stripped loop-copy fallback should survive verifier into COPY_SINK."""
    proposal = _make_proposal("COPY_SINK", addr=0x08001234, func="FUN_08001234", facts={
        "promoted_from": "LOOP_WRITE_SINK",
        "in_loop": True,
        "store_expr": "param_1[i]",
        "dst_expr": "param_1[i]",
        "src_expr": "param_2[i]",
        "loop_bound": "param_3",
        "len_expr": "param_3",
    })
    results = await verify_proposals([proposal])

    assert len(results) == 1
    assert results[0].verdict == VerificationVerdict.VERIFIED
    assert results[0].final_label == "COPY_SINK"
