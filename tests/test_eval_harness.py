"""Tests for pipeline/eval_harness.py — M0/M9 evaluation harness.

Tests cover:
  - Ground truth registry structure
  - compare_labels() — pure matching function (no pipeline)
  - _match_entries() — flexible address/function/label matching
  - _functions_match() — Ghidra vs debug symbol name matching
  - _collect_predictions() — verdict filtering
  - aggregate_results() — micro-average aggregation
  - print_eval_report() — formatted output
  - run_eval() — with pre-computed PipelineResult (no actual pipeline run)
  - Edge cases: empty inputs, negative tests, mixed verdicts
"""

import pytest
from unittest.mock import AsyncMock, patch

from sourceagent.pipeline.eval_harness import (
    GROUND_TRUTH,
    _collect_predictions,
    _functions_match,
    _match_entries,
    _normalize_label,
    aggregate_results,
    collect_prediction_records,
    compare_labels,
    compare_labels_detailed,
    default_scoring_policy,
    eval_results_to_dict,
    print_eval_report,
    run_eval,
)
from sourceagent.pipeline.models import (
    EvalResult,
    GroundTruthEntry,
    LLMProposal,
    PipelineResult,
    SinkLabel,
    SourceLabel,
    VerificationVerdict,
    VerifiedLabel,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_verified(label, addr, func, verdict=VerificationVerdict.VERIFIED):
    """Create a VerifiedLabel for testing."""
    proposal = LLMProposal(
        pack_id=f"test-{label}-0x{addr:08x}",
        label=label,
        address=addr,
        function_name=func,
        confidence=0.8,
    )
    return VerifiedLabel(
        pack_id=proposal.pack_id,
        proposal=proposal,
        verdict=verdict,
        final_label=label,
    )


def _make_result(binary_path="/tmp/test_fw.bin", verified_labels=None):
    """Create a PipelineResult for testing."""
    return PipelineResult(
        binary_path=binary_path,
        run_id="test-eval",
        verified_labels=verified_labels or [],
    )


def _make_gt(label, addr=None, func="", stem="test_fw"):
    """Create a GroundTruthEntry for testing."""
    return GroundTruthEntry(
        binary_stem=stem,
        label=label,
        address=addr,
        function_name=func,
    )


# ── Ground Truth Registry ───────────────────────────────────────────────────


def test_ground_truth_registry_has_nxp_uart():
    """Ground truth registry should include nxp_uart_polling."""
    assert "nxp_uart_polling" in GROUND_TRUTH
    entries = GROUND_TRUTH["nxp_uart_polling"]
    assert len(entries) >= 1
    assert entries[0].label == SourceLabel.MMIO_READ.value


def test_ground_truth_registry_has_thermostat():
    """Ground truth registry should include thermostat."""
    assert "thermostat" in GROUND_TRUTH
    entries = GROUND_TRUTH["thermostat"]
    assert len(entries) >= 2


def test_ground_truth_registry_has_blink_led():
    """Blink_led should be a negative test (no external input sources)."""
    assert "blink_led" in GROUND_TRUTH
    entries = GROUND_TRUTH["blink_led"]
    assert any(e.label.startswith("_") for e in entries)


def test_ground_truth_labels_are_strings():
    """All GT labels should be string values (not enum instances)."""
    for stem, entries in GROUND_TRUTH.items():
        for entry in entries:
            assert isinstance(entry.label, str), f"{stem}: {entry.label}"


# ── _normalize_label ─────────────────────────────────────────────────────


def test_normalize_label_string():
    assert _normalize_label("MMIO_READ") == "MMIO_READ"


def test_normalize_label_enum():
    assert _normalize_label(SourceLabel.MMIO_READ) == "MMIO_READ"


def test_normalize_label_sink_enum():
    assert _normalize_label(SinkLabel.COPY_SINK) == "COPY_SINK"


# ── _functions_match ─────────────────────────────────────────────────────


def test_functions_match_exact():
    assert _functions_match("UART_ReadBlocking", "UART_ReadBlocking")


def test_functions_match_substring():
    assert _functions_match("UART_ReadBlocking", "ReadBlocking")


def test_functions_match_reverse_substring():
    assert _functions_match("ReadBlock", "UART_ReadBlocking")


def test_functions_match_no_match():
    assert not _functions_match("main", "UART_ReadBlocking")


def test_functions_match_empty():
    assert not _functions_match("", "UART_ReadBlocking")
    assert not _functions_match("main", "")


# ── _match_entries ───────────────────────────────────────────────────────


def test_match_entries_exact_address():
    """Should match when addresses are equal."""
    preds = [(0x40011000, "FUN_08001000")]
    gt = [_make_gt("MMIO_READ", addr=0x40011000, func="UART_ReadBlocking")]

    tp, fp, fn = _match_entries(preds, gt)
    assert tp == 1
    assert fp == 0
    assert fn == 0


def test_match_entries_near_address_tolerance():
    """Small address skew (e.g., callsite vs entry) should still match."""
    preds = [(0x08001004, "FUN_08001000")]
    gt = [_make_gt("MMIO_READ", addr=0x08001000, func="")]

    tp, fp, fn = _match_entries(preds, gt)
    assert tp == 1
    assert fp == 0
    assert fn == 0


def test_match_entries_function_match():
    """Should match by function name when GT has no address."""
    preds = [(0x08001000, "UART_ReadBlocking")]
    gt = [_make_gt("MMIO_READ", addr=None, func="UART_ReadBlocking")]

    tp, fp, fn = _match_entries(preds, gt)
    assert tp == 1
    assert fp == 0
    assert fn == 0


def test_match_entries_label_only():
    """Should match label-only GT entry (no addr, no func) with any prediction."""
    preds = [(0x08001000, "FUN_08001000")]
    gt = [_make_gt("MMIO_READ", addr=None, func="")]

    tp, fp, fn = _match_entries(preds, gt)
    assert tp == 1
    assert fp == 0
    assert fn == 0


def test_match_entries_false_positive():
    """Extra predictions beyond GT should be false positives."""
    preds = [(0x08001000, "F1"), (0x08002000, "F2")]
    gt = [_make_gt("MMIO_READ", addr=0x08001000)]

    tp, fp, fn = _match_entries(preds, gt)
    assert tp == 1
    assert fp == 1
    assert fn == 0


def test_match_entries_false_negative():
    """Unmatched GT entries should be false negatives."""
    preds = []
    gt = [_make_gt("MMIO_READ", addr=0x40011000, func="UART_ReadBlocking")]

    tp, fp, fn = _match_entries(preds, gt)
    assert tp == 0
    assert fp == 0
    assert fn == 1


def test_match_entries_empty_both():
    """Empty predictions and GT should give all zeros."""
    tp, fp, fn = _match_entries([], [])
    assert (tp, fp, fn) == (0, 0, 0)


def test_match_entries_multiple_gt():
    """Should handle multiple GT entries with different match types."""
    preds = [
        (0x40011000, "UART_ReadBlocking"),
        (0x08002000, "UART_GetStatusFlags"),
        (0x08003000, "FUN_08003000"),  # Extra — FP
    ]
    gt = [
        _make_gt("X", addr=0x40011000, func="UART_ReadBlocking"),  # addr match
        _make_gt("X", addr=None, func="UART_GetStatusFlags"),  # func match
    ]

    tp, fp, fn = _match_entries(preds, gt)
    assert tp == 2
    assert fp == 1
    assert fn == 0


def test_match_entries_address_takes_priority():
    """Address match should take priority over function match."""
    # Both GT entries could match by function, but first should match by addr
    preds = [(0x08001000, "UART_ReadBlocking")]
    gt = [
        _make_gt("X", addr=0x08001000, func=""),  # addr match
        _make_gt("X", addr=None, func="UART_ReadBlocking"),  # func match — FN
    ]

    tp, fp, fn = _match_entries(preds, gt)
    assert tp == 1  # addr match
    assert fp == 0
    assert fn == 1  # func GT unmatched (pred already consumed by addr)


def test_match_entries_no_double_match():
    """Each prediction should match at most one GT entry."""
    preds = [(0x08001000, "F1")]
    gt = [
        _make_gt("X", addr=None, func=""),  # label-only
        _make_gt("X", addr=None, func=""),  # label-only
    ]

    tp, fp, fn = _match_entries(preds, gt)
    assert tp == 1
    assert fp == 0
    assert fn == 1  # Second GT entry unmatched


# ── _collect_predictions ────────────────────────────────────────────────


def test_collect_predictions_verified():
    """Should collect VERIFIED labels."""
    result = _make_result(verified_labels=[
        _make_verified("MMIO_READ", 0x08001000, "F1", VerificationVerdict.VERIFIED),
    ])
    preds = _collect_predictions(result, {VerificationVerdict.VERIFIED})
    assert "MMIO_READ" in preds
    assert len(preds["MMIO_READ"]) == 1


def test_collect_predictions_partial():
    """Should collect PARTIAL labels when included in accepted verdicts."""
    result = _make_result(verified_labels=[
        _make_verified("MMIO_READ", 0x08001000, "F1", VerificationVerdict.PARTIAL),
    ])
    preds = _collect_predictions(result, {VerificationVerdict.VERIFIED, VerificationVerdict.PARTIAL})
    assert "MMIO_READ" in preds


def test_collect_predictions_rejects_rejected():
    """Should not collect REJECTED labels."""
    result = _make_result(verified_labels=[
        _make_verified("MMIO_READ", 0x08001000, "F1", VerificationVerdict.REJECTED),
    ])
    preds = _collect_predictions(result, {VerificationVerdict.VERIFIED})
    assert len(preds) == 0


def test_collect_predictions_multiple_labels():
    """Should group predictions by label class."""
    result = _make_result(verified_labels=[
        _make_verified("MMIO_READ", 0x08001000, "F1"),
        _make_verified("COPY_SINK", 0x08002000, "F2"),
        _make_verified("MMIO_READ", 0x08003000, "F3"),
    ])
    preds = _collect_predictions(result, {VerificationVerdict.VERIFIED})
    assert len(preds["MMIO_READ"]) == 2
    assert len(preds["COPY_SINK"]) == 1


# ── compare_labels ──────────────────────────────────────────────────────


def test_compare_labels_perfect_match():
    """All predictions match all GT entries → P=1, R=1, F1=1."""
    result = _make_result(verified_labels=[
        _make_verified("MMIO_READ", 0x08001000, "UART_ReadBlocking"),
    ])
    gt = [_make_gt("MMIO_READ", addr=0x08001000, func="UART_ReadBlocking")]

    eval_results = compare_labels(result, gt)
    assert len(eval_results) == 1
    assert eval_results[0].precision == 1.0
    assert eval_results[0].recall == 1.0
    assert eval_results[0].f1 == 1.0


def test_compare_labels_no_predictions():
    """No predictions → P=0, R=0, FN=len(GT)."""
    result = _make_result(verified_labels=[])
    gt = [_make_gt("MMIO_READ", func="UART_ReadBlocking")]

    eval_results = compare_labels(result, gt)
    assert len(eval_results) == 1
    assert eval_results[0].true_positives == 0
    assert eval_results[0].false_negatives == 1
    assert eval_results[0].recall == 0.0


def test_compare_labels_no_ground_truth():
    """Predictions but no GT → all FP, P=0."""
    result = _make_result(verified_labels=[
        _make_verified("MMIO_READ", 0x08001000, "F1"),
    ])
    gt = []

    eval_results = compare_labels(result, gt)
    assert len(eval_results) == 1
    assert eval_results[0].false_positives == 1
    assert eval_results[0].true_positives == 0


def test_compare_labels_negative_test_skipped():
    """GT entries with _ prefix labels should be skipped."""
    result = _make_result(verified_labels=[])
    gt = [_make_gt("_NEGATIVE_TEST", func="")]

    eval_results = compare_labels(result, gt)
    # _NEGATIVE_TEST should not appear in results
    assert len(eval_results) == 0


def test_compare_labels_mixed_labels():
    """Should produce separate EvalResult per label class."""
    result = _make_result(verified_labels=[
        _make_verified("MMIO_READ", 0x08001000, "F1"),
        _make_verified("COPY_SINK", 0x08002000, "F2"),
    ])
    gt = [
        _make_gt("MMIO_READ", func="F1"),
        _make_gt("COPY_SINK", func="F2"),
    ]

    eval_results = compare_labels(result, gt)
    assert len(eval_results) == 2

    by_label = {r.label_class: r for r in eval_results}
    assert by_label["MMIO_READ"].true_positives == 1
    assert by_label["COPY_SINK"].true_positives == 1


def test_compare_labels_rejected_not_counted():
    """REJECTED predictions should not count as positive predictions."""
    result = _make_result(verified_labels=[
        _make_verified("MMIO_READ", 0x08001000, "F1", VerificationVerdict.REJECTED),
    ])
    gt = [_make_gt("MMIO_READ", addr=0x08001000)]

    eval_results = compare_labels(result, gt)
    assert len(eval_results) == 1
    assert eval_results[0].true_positives == 0
    assert eval_results[0].false_negatives == 1


def test_compare_labels_custom_accepted_verdicts():
    """Should respect custom accepted_verdicts parameter."""
    result = _make_result(verified_labels=[
        _make_verified("MMIO_READ", 0x08001000, "F1", VerificationVerdict.PARTIAL),
    ])
    gt = [_make_gt("MMIO_READ", addr=0x08001000)]

    # Only VERIFIED accepted → PARTIAL not counted
    results_strict = compare_labels(
        result, gt, accepted_verdicts={VerificationVerdict.VERIFIED},
    )
    assert results_strict[0].true_positives == 0

    # PARTIAL also accepted → counted
    results_lenient = compare_labels(
        result, gt, accepted_verdicts={VerificationVerdict.VERIFIED, VerificationVerdict.PARTIAL},
    )
    assert results_lenient[0].true_positives == 1


def test_collect_prediction_records_includes_label_and_verdict():
    result = _make_result(verified_labels=[
        _make_verified("MMIO_READ", 0x08001000, "F1", VerificationVerdict.VERIFIED),
        _make_verified("COPY_SINK", 0x08001010, "F2", VerificationVerdict.REJECTED),
    ])
    rows = collect_prediction_records(result, {VerificationVerdict.VERIFIED})
    assert len(rows) == 1
    assert rows[0]["label"] == "MMIO_READ"
    assert rows[0]["verdict"] == "VERIFIED"


def test_compare_labels_detailed_partial_sink_family_credit():
    """COPY_SINK GT matched by STORE_SINK in same function => partial credit."""
    result = _make_result(
        binary_path="/tmp/t0_copy_sink.bin",
        verified_labels=[
            _make_verified("STORE_SINK", 0x0800005C, "handler"),
        ],
    )
    gt = [_make_gt("COPY_SINK", func="handler", stem="t0_copy_sink")]

    detail = compare_labels_detailed(result, gt, partial_credit=0.5)
    assert detail["strict"]["tp"] == 0
    assert detail["strict"]["fn"] == 1
    assert detail["weighted"]["tp"] == 0.5
    assert detail["weighted"]["fn"] == 0.5
    assert detail["weighted"]["partial_match_count"] == 1


def test_compare_labels_detailed_exact_match_beats_partial():
    result = _make_result(
        binary_path="/tmp/t0_copy_sink.bin",
        verified_labels=[
            _make_verified("COPY_SINK", 0x0800005C, "handler"),
            _make_verified("STORE_SINK", 0x08000060, "handler"),
        ],
    )
    gt = [_make_gt("COPY_SINK", func="handler", stem="t0_copy_sink")]
    detail = compare_labels_detailed(result, gt, partial_credit=0.5)
    assert detail["strict"]["tp"] == 1
    assert detail["weighted"]["partial_match_count"] == 0
    assert detail["strict"]["fp"] == 1


def test_eval_results_to_dict_includes_micro_average():
    rows = [
        EvalResult("a", "MMIO_READ", true_positives=2, false_positives=1, false_negatives=1),
        EvalResult("a", "COPY_SINK", true_positives=1, false_positives=0, false_negatives=2),
    ]
    data = eval_results_to_dict(rows)
    assert "rows" in data
    assert "micro_average" in data
    assert data["micro_average"]["tp"] == 3
    assert data["micro_average"]["fp"] == 1


def test_default_scoring_policy_has_partial_credit():
    policy = default_scoring_policy(partial_credit=0.6)
    assert policy["weighted_partial_scoring"]["partial_credit"] == 0.6
    assert "partial_rule_summary" in policy


def test_compare_labels_enum_gt():
    """GT labels as enum instances should work (auto-normalized)."""
    result = _make_result(verified_labels=[
        _make_verified("MMIO_READ", 0x08001000, "F1"),
    ])
    gt = [GroundTruthEntry(
        binary_stem="test_fw",
        label=SourceLabel.MMIO_READ,
        address=0x08001000,
    )]

    eval_results = compare_labels(result, gt)
    assert eval_results[0].true_positives == 1


# ── aggregate_results ───────────────────────────────────────────────────


def test_aggregate_results_empty():
    agg = aggregate_results([])
    assert agg.true_positives == 0
    assert agg.f1 == 0.0


def test_aggregate_results_micro_average():
    results = [
        EvalResult("a", "MMIO_READ", true_positives=5, false_positives=2, false_negatives=1),
        EvalResult("a", "COPY_SINK", true_positives=3, false_positives=1, false_negatives=2),
    ]
    agg = aggregate_results(results)
    assert agg.true_positives == 8
    assert agg.false_positives == 3
    assert agg.false_negatives == 3
    assert agg.precision == pytest.approx(8 / 11)
    assert agg.recall == pytest.approx(8 / 11)


# ── print_eval_report ───────────────────────────────────────────────────


def test_print_eval_report_output(capsys):
    results = [
        EvalResult("test_fw", "MMIO_READ", true_positives=3, false_positives=1, false_negatives=0),
    ]
    print_eval_report(results, "test_fw")

    output = capsys.readouterr().out
    assert "MMIO_READ" in output
    assert "MICRO-AVERAGE" in output
    assert "test_fw" in output


def test_print_eval_report_empty(capsys):
    print_eval_report([])
    output = capsys.readouterr().out
    assert "No evaluation results" in output


# ── run_eval ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_eval_with_precomputed_result():
    """run_eval with pre-computed PipelineResult should skip pipeline."""
    result = _make_result(
        binary_path="/tmp/test_fw.bin",
        verified_labels=[
            _make_verified("MMIO_READ", 0x08001000, "UART_ReadBlocking"),
        ],
    )
    gt = [_make_gt("MMIO_READ", func="UART_ReadBlocking")]

    eval_results = await run_eval("/tmp/test_fw.bin", gt, pipeline_result=result)
    assert len(eval_results) == 1
    assert eval_results[0].true_positives == 1


@pytest.mark.asyncio
async def test_run_eval_calls_pipeline_when_no_result():
    """run_eval without pre-computed result should invoke the pipeline."""
    mock_result = _make_result(
        binary_path="/tmp/test_fw.bin",
        verified_labels=[
            _make_verified("MMIO_READ", 0x08001000, "F1"),
        ],
    )

    with patch(
        "sourceagent.pipeline.eval_harness._run_pipeline",
        new_callable=AsyncMock,
        return_value=mock_result,
    ):
        gt = [_make_gt("MMIO_READ", addr=0x08001000)]
        eval_results = await run_eval("/tmp/test_fw.bin", gt)

    assert len(eval_results) == 1
    assert eval_results[0].true_positives == 1


# ── EvalResult model tests ──────────────────────────────────────────────


def test_eval_result_f1_symmetric():
    """F1 formula should work correctly with different P/R."""
    r1 = EvalResult("test", "X", true_positives=5, false_positives=3, false_negatives=2)
    r2 = EvalResult("test", "X", true_positives=5, false_positives=2, false_negatives=3)
    assert r1.f1 > 0
    assert r2.f1 > 0
    assert r1.precision != r2.precision
    assert r1.recall != r2.recall


def test_eval_result_perfect():
    r = EvalResult("test", "X", true_positives=10, false_positives=0, false_negatives=0)
    assert r.precision == 1.0
    assert r.recall == 1.0
    assert r.f1 == 1.0


def test_eval_result_zero_tp():
    r = EvalResult("test", "X", true_positives=0, false_positives=5, false_negatives=3)
    assert r.precision == 0.0
    assert r.recall == 0.0
    assert r.f1 == 0.0


def test_eval_result_all_zero():
    r = EvalResult("test", "X")
    assert r.precision == 0.0
    assert r.recall == 0.0
    assert r.f1 == 0.0


# ── Integration-style tests ─────────────────────────────────────────────


def test_compare_labels_nxp_uart_scenario():
    """Simulate nxp_uart_polling scenario: 2 MMIO reads detected, GT has 2."""
    result = _make_result(
        binary_path="/tmp/nxp_uart_polling.bin",
        verified_labels=[
            _make_verified("MMIO_READ", 0x0000097b, "UART_ReadBlocking"),
            _make_verified("MMIO_READ", 0x0000094f, "UART_GetStatusFlags"),
            _make_verified("MMIO_READ", 0x0000081d, "UART_Init"),  # FP
        ],
    )
    gt = GROUND_TRUTH["nxp_uart_polling"]

    eval_results = compare_labels(result, gt)
    assert len(eval_results) == 1  # Only MMIO_READ label class

    r = eval_results[0]
    assert r.label_class == "MMIO_READ"
    assert r.true_positives == 2  # ReadBlocking + GetStatusFlags matched
    assert r.false_positives == 1  # UART_Init not in GT
    assert r.false_negatives == 0


def test_compare_labels_thermostat_scenario():
    """Simulate thermostat scenario: MMIO_READ and COPY_SINK."""
    result = _make_result(
        binary_path="/tmp/thermostat.bin",
        verified_labels=[
            _make_verified("MMIO_READ", 0x08000249, "evil_read"),
            _make_verified("COPY_SINK", 0x08003eed, "memcpy"),
        ],
    )
    gt = GROUND_TRUTH["thermostat"]

    eval_results = compare_labels(result, gt)
    by_label = {r.label_class: r for r in eval_results}

    # thermostat GT has label-only entries (no addr, no func)
    # so any prediction with matching label counts
    assert by_label["MMIO_READ"].true_positives == 1
    assert by_label["COPY_SINK"].true_positives == 1


def test_compare_labels_blink_led_negative_test():
    """blink_led negative test: no predictions, negative GT should be skipped."""
    result = _make_result(
        binary_path="/tmp/blink_led.bin",
        verified_labels=[],
    )
    gt = GROUND_TRUTH["blink_led"]

    eval_results = compare_labels(result, gt)
    # _NEGATIVE_TEST entries are skipped → no label classes
    assert len(eval_results) == 0


def test_compare_labels_blink_led_false_positive():
    """blink_led with false positive detection (should be 0 true sources)."""
    result = _make_result(
        binary_path="/tmp/blink_led.bin",
        verified_labels=[
            _make_verified("MMIO_READ", 0x08001000, "F1"),  # Spurious
        ],
    )
    gt = GROUND_TRUTH["blink_led"]

    eval_results = compare_labels(result, gt)
    # _NEGATIVE_TEST is skipped, but the FP MMIO_READ creates a result
    assert len(eval_results) == 1
    assert eval_results[0].label_class == "MMIO_READ"
    assert eval_results[0].false_positives == 1
    assert eval_results[0].true_positives == 0
