"""Tests for eval_mode and eval_tier parameters in eval_p2im.evaluate_result().

Verifies that:
  - read_only vs all_accessed modes correctly handle write-only registers
  - source_only tier restricts evaluation to DR (data registers) only
"""

import sys
from pathlib import Path

# Ensure tests/ sibling imports work
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.eval_p2im import RegisterGT, evaluate_result


def _make_gt_registers():
    """Create GT registers with mixed read/write flags.

    Returns:
        List of RegisterGT with:
          - 0x40011000: SR — Read=1, Write=0 (read-only)
          - 0x40011004: DR — Read=1, Write=1 (read+write)
          - 0x40011008: BRR — Read=0, Write=1 (write-only)
          - 0x4001100c: CR1 — Read=1, Write=1 (read+write)
    """
    return [
        RegisterGT(base_addr=0x40011000, reg_addr=0x40011000, reg_name="SR",
                    category="SR", read=True, write=False),
        RegisterGT(base_addr=0x40011000, reg_addr=0x40011004, reg_name="DR",
                    category="DR", read=True, write=True),
        RegisterGT(base_addr=0x40011000, reg_addr=0x40011008, reg_name="BRR",
                    category="CR", read=False, write=True),
        RegisterGT(base_addr=0x40011000, reg_addr=0x4001100c, reg_name="CR1",
                    category="CR", read=True, write=True),
    ]


def _make_result(detected_addrs):
    """Create a minimal sourceagent result dict with given detected addresses."""
    return {
        "source_candidates": [
            {"address": addr} for addr in detected_addrs
        ],
        "verified_labels": [],
        "evidence_packs": [],
    }


def test_write_only_not_fn_in_read_only_mode():
    """Write-only register (BRR, Read=0, Write=1) is NOT counted as FN in read_only mode."""
    gt = _make_gt_registers()
    # Detect SR and DR but not BRR or CR1
    result = _make_result([0x40011000, 0x40011004])

    ev = evaluate_result(result, gt, "test_fw", eval_mode="read_only")

    # In read_only mode, GT = {SR(0x40011000), DR(0x40011004), CR1(0x4001100c)} = 3 read addrs
    # Detected: SR and DR → TP=2
    # Missed: CR1 → FN=1
    # BRR is write-only → NOT counted as FN
    assert ev.true_positives == 2
    assert ev.false_negatives == 1  # Only CR1 missed (BRR excluded from eval)


def test_write_only_is_fn_in_all_accessed_mode():
    """Write-only register (BRR) IS counted as FN in all_accessed mode."""
    gt = _make_gt_registers()
    result = _make_result([0x40011000, 0x40011004])

    ev = evaluate_result(result, gt, "test_fw", eval_mode="all_accessed")

    # In all_accessed mode, GT = all 4 registers
    # Detected: SR and DR → TP=2
    # Missed: BRR and CR1 → FN=2
    assert ev.true_positives == 2
    assert ev.false_negatives == 2


def test_read_write_register_tp_in_both_modes():
    """Read+Write register (DR) counted as TP in both modes when detected."""
    gt = _make_gt_registers()
    result = _make_result([0x40011004])  # Only detect DR

    ev_ro = evaluate_result(result, gt, "test_fw", eval_mode="read_only")
    ev_all = evaluate_result(result, gt, "test_fw", eval_mode="all_accessed")

    assert ev_ro.true_positives == 1
    assert ev_all.true_positives == 1


def test_precision_unchanged_between_modes():
    """Precision should be the same in both modes (FP computation is mode-independent)."""
    gt = _make_gt_registers()
    # Detect: SR (TP), DR (TP), 0x40012000 (FP — not in GT)
    result = _make_result([0x40011000, 0x40011004, 0x40012000])

    ev_ro = evaluate_result(result, gt, "test_fw", eval_mode="read_only")
    ev_all = evaluate_result(result, gt, "test_fw", eval_mode="all_accessed")

    # Both modes: TP=2, FP=1 (0x40012000 not in GT)
    assert ev_ro.true_positives == 2
    assert ev_all.true_positives == 2
    assert ev_ro.false_positives == ev_all.false_positives
    assert ev_ro.precision == ev_all.precision


def test_read_only_mode_higher_recall_than_all_accessed():
    """read_only mode should have higher recall since write-only FNs are excluded."""
    gt = _make_gt_registers()
    # Detect all read registers but miss write-only BRR
    result = _make_result([0x40011000, 0x40011004, 0x4001100c])

    ev_ro = evaluate_result(result, gt, "test_fw", eval_mode="read_only")
    ev_all = evaluate_result(result, gt, "test_fw", eval_mode="all_accessed")

    # read_only: TP=3/3 read addrs → recall=1.0
    # all_accessed: TP=3/4 accessed addrs → recall=0.75
    assert ev_ro.recall == 1.0
    assert ev_all.recall == 0.75


def test_default_eval_mode_is_read_only():
    """Default eval_mode parameter should be read_only."""
    gt = _make_gt_registers()
    result = _make_result([0x40011000, 0x40011004])

    # Call without eval_mode → should default to read_only
    ev = evaluate_result(result, gt, "test_fw")

    # Same as read_only: BRR not counted as FN
    ev_explicit = evaluate_result(result, gt, "test_fw", eval_mode="read_only")
    assert ev.true_positives == ev_explicit.true_positives
    assert ev.false_negatives == ev_explicit.false_negatives


# ══════════════════════════════════════════════════════════════════════════════
# eval_tier tests: source_only vs coverage
# ══════════════════════════════════════════════════════════════════════════════


def test_source_only_tier_counts_only_dr():
    """source_only tier: only DR registers count for TP/FN."""
    gt = _make_gt_registers()
    # Detect DR only
    result = _make_result([0x40011004])

    ev = evaluate_result(result, gt, "test_fw", eval_tier="source_only")

    # GT_eval = only DR(0x40011004) → 1 address
    assert ev.gt_eval_count == 1
    assert ev.true_positives == 1
    assert ev.false_negatives == 0
    assert ev.recall == 1.0  # 1/1 DR detected


def test_source_only_tier_ignores_sr_cr_fn():
    """source_only tier: missing SR and CR are NOT counted as FN."""
    gt = _make_gt_registers()
    # Detect nothing
    result = _make_result([])

    ev_source = evaluate_result(result, gt, "test_fw", eval_tier="source_only")
    ev_coverage = evaluate_result(result, gt, "test_fw", eval_tier="coverage")

    # source_only: FN = 1 (only DR missed)
    # coverage: FN = 3 (SR + DR + CR1 all missed)
    assert ev_source.false_negatives == 1
    assert ev_coverage.false_negatives == 3


def test_source_only_higher_recall_when_dr_detected():
    """source_only gives higher recall when DR is detected but SR/CR are not."""
    gt = _make_gt_registers()
    # Detect only DR
    result = _make_result([0x40011004])

    ev_source = evaluate_result(result, gt, "test_fw", eval_tier="source_only")
    ev_coverage = evaluate_result(result, gt, "test_fw", eval_tier="coverage")

    # source_only: 1/1 DR → 100% recall
    # coverage: 1/3 read regs → 33% recall
    assert ev_source.recall == 1.0
    assert ev_coverage.recall < 0.5


def test_source_only_zero_dr_in_gt():
    """source_only with no DR registers in GT → gt_eval_count=0, recall=0."""
    gt = [
        RegisterGT(base_addr=0x40011000, reg_addr=0x40011000, reg_name="SR",
                    category="SR", read=True, write=False),
        RegisterGT(base_addr=0x40011000, reg_addr=0x4001100c, reg_name="CR1",
                    category="CR", read=True, write=True),
    ]
    result = _make_result([0x40011000, 0x4001100c])

    ev = evaluate_result(result, gt, "test_fw", eval_tier="source_only")

    # No DR in GT → nothing to evaluate
    assert ev.gt_eval_count == 0
    assert ev.true_positives == 0
    assert ev.false_negatives == 0


def test_source_only_write_only_dr_excluded_in_read_only_mode():
    """source_only + read_only: a write-only DR (Read=0) is excluded."""
    gt = [
        RegisterGT(base_addr=0x40011000, reg_addr=0x40011004, reg_name="DR",
                    category="DR", read=False, write=True),  # write-only DR
        RegisterGT(base_addr=0x40011000, reg_addr=0x40011010, reg_name="DR2",
                    category="DR", read=True, write=True),   # read+write DR
    ]
    result = _make_result([0x40011010])

    ev = evaluate_result(result, gt, "test_fw", eval_mode="read_only", eval_tier="source_only")

    # read_only filters to Read=1 only: {DR2}
    # source_only filters to DR only: {DR2} (write-only DR already excluded)
    assert ev.gt_eval_count == 1
    assert ev.true_positives == 1
    assert ev.false_negatives == 0


def test_default_eval_tier_is_coverage():
    """Default eval_tier parameter should be coverage."""
    gt = _make_gt_registers()
    result = _make_result([0x40011004])

    ev_default = evaluate_result(result, gt, "test_fw")
    ev_explicit = evaluate_result(result, gt, "test_fw", eval_tier="coverage")

    assert ev_default.true_positives == ev_explicit.true_positives
    assert ev_default.false_negatives == ev_explicit.false_negatives
    assert ev_default.gt_eval_count == ev_explicit.gt_eval_count


def test_source_only_per_category_breakdown_only_dr():
    """source_only: tp_by_category and fn_by_category should only reflect DR."""
    gt = _make_gt_registers()
    # Detect SR and DR
    result = _make_result([0x40011000, 0x40011004])

    ev = evaluate_result(result, gt, "test_fw", eval_tier="source_only")

    # Only DR should be counted in TP (SR is outside the tier scope)
    # Note: SR is detected but not in gt_eval_addrs, so it's either FP or OOS
    assert ev.true_positives == 1  # Only DR
