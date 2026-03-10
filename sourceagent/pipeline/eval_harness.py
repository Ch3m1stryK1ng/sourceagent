"""Stage 0 / Stage 12 — Microbench suite and evaluation harness (M0/M9).

Provides:
  - Ground truth registry: maps binary stem -> list of GroundTruthEntry
  - compare_labels(): pure function comparing verified labels to ground truth
  - run_eval(): run pipeline then compare (thin wrapper)
  - EvalResult per label class with precision/recall/F1

Matching strategy (site-level):
  1. If ground truth has an address: match by (label, address)
  2. If no address but function_name: match by (label, function_name)
  3. Label-only: counted as match if at least one prediction shares the label

Dataset tiers:
  T0 (Microbench): Hand-written C programs, exact ground truth by construction
  T1 (Source-available firmware): Compile with debug + stripped, extract oracle
  T2 (Real-world blobs): No full oracle, partial manual validation
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import (
    EvalResult,
    GroundTruthEntry,
    PipelineResult,
    SinkLabel,
    SourceLabel,
    VerificationVerdict,
)

logger = logging.getLogger("sourceagent.pipeline.eval_harness")


_MEMORY_WRITE_SINK_LABELS = {
    SinkLabel.COPY_SINK.value,
    SinkLabel.MEMSET_SINK.value,
    SinkLabel.STORE_SINK.value,
    SinkLabel.LOOP_WRITE_SINK.value,
}
_ADDRESS_NEAR_TOLERANCE = 16


def _sink_family(label: str) -> str:
    """Return a coarse sink family used for partial-credit matching."""
    if label in _MEMORY_WRITE_SINK_LABELS:
        return "MEMORY_WRITE"
    if label in {
        "LENGTH_TRUST_SINK",
        "UNBOUNDED_WALK_SINK",
        "PARSING_OVERFLOW_SINK",
    }:
        return "MEMORY_WRITE"
    if label in {"FORMAT_STRING", "FORMAT_STRING_SINK"}:
        return "FORMAT_STRING"
    if label in {"FUNC_PTR", "FUNC_PTR_SINK"}:
        return "FUNC_PTR"
    return label


# ── Ground Truth Registry ──────────────────────────────────────────────────
#
# Populated incrementally as annotations are made.
# Address values come from ELF symbol tables; None means "not yet resolved".
# Ground truth is defined at the function level — the pipeline should detect
# *some* labeled site within that function.


GROUND_TRUTH: Dict[str, List[GroundTruthEntry]] = {
    # ── T0: Microbench (exact oracle) ────────────────────────────────────
    "nxp_uart_polling": [
        GroundTruthEntry(
            binary_stem="nxp_uart_polling",
            label=SourceLabel.MMIO_READ.value,
            address=None,  # Multiple UART MMIO reads across functions
            function_name="UART_ReadBlocking",
            notes="UART data register polling read (UART0 D register)",
        ),
        GroundTruthEntry(
            binary_stem="nxp_uart_polling",
            label=SourceLabel.MMIO_READ.value,
            address=None,
            function_name="UART_GetStatusFlags",
            notes="UART status register read in polling loop",
        ),
    ],
    "thermostat": [
        GroundTruthEntry(
            binary_stem="thermostat",
            label=SourceLabel.MMIO_READ.value,
            address=None,
            function_name="",
            notes="UART/ADC register reads (evil_read + UART driver)",
        ),
        GroundTruthEntry(
            binary_stem="thermostat",
            label=SinkLabel.COPY_SINK.value,
            address=None,
            function_name="",
            notes="memcpy at 0x08003eed — copy operations in firmware",
        ),
    ],
    "blink_led": [
        # blink_led is a minimal firmware; may have MMIO writes but
        # no external input (no UART/ADC reads). Serves as a negative
        # test: pipeline should produce zero source labels.
        GroundTruthEntry(
            binary_stem="blink_led",
            label="_NEGATIVE_TEST",
            address=None,
            function_name="",
            notes="No external input sources — expect zero source labels",
        ),
    ],
}


# ── Label Matching ─────────────────────────────────────────────────────────

# Verdicts that count as a "positive prediction"
_POSITIVE_VERDICTS = {
    VerificationVerdict.VERIFIED,
    VerificationVerdict.PARTIAL,
}


def compare_labels(
    result: PipelineResult,
    ground_truth: List[GroundTruthEntry],
    accepted_verdicts: Optional[Set[VerificationVerdict]] = None,
) -> List[EvalResult]:
    """Compare pipeline verified labels against ground truth.

    Matching hierarchy (per label class):
      1. Address match: if GT entry has address, find a prediction with same
         label and matching address.
      2. Function match: if GT entry has function_name, find a prediction with
         same label in the same function.
      3. Label-only match: GT entry has neither address nor function_name —
         any prediction with matching label counts.

    Returns one EvalResult per label class found in either predictions or GT.
    Skips GT entries with label starting with '_' (negative test markers).
    """
    if accepted_verdicts is None:
        accepted_verdicts = _POSITIVE_VERDICTS

    # Collect positive predictions as (label, address, function_name) tuples
    predictions = _collect_predictions(result, accepted_verdicts)

    # Organize ground truth by label class (skip negative markers)
    gt_by_label: Dict[str, List[GroundTruthEntry]] = defaultdict(list)
    for gt in ground_truth:
        label = _normalize_label(gt.label)
        if label.startswith("_"):
            continue
        gt_by_label[label].append(gt)

    # All label classes from both sides
    all_labels = set(predictions.keys()) | set(gt_by_label.keys())

    results = []
    binary_stem = Path(result.binary_path).stem

    for label in sorted(all_labels):
        pred_entries = predictions.get(label, [])
        gt_entries = gt_by_label.get(label, [])

        tp, fp, fn = _match_entries(pred_entries, gt_entries)
        results.append(EvalResult(
            binary_stem=binary_stem,
            label_class=label,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
        ))

    return results


def _collect_predictions(
    result: PipelineResult,
    accepted_verdicts: Set[VerificationVerdict],
) -> Dict[str, List[Tuple[int, str]]]:
    """Extract (address, function_name) tuples per label from verified labels."""
    predictions: Dict[str, List[Tuple[int, str]]] = defaultdict(list)
    for vl in result.verified_labels:
        if vl.verdict not in accepted_verdicts:
            continue
        label = _normalize_label(vl.final_label or vl.proposal.label)
        addr = vl.proposal.address
        func = vl.proposal.function_name or ""
        predictions[label].append((addr, func))
    return dict(predictions)


def collect_prediction_records(
    result: PipelineResult,
    accepted_verdicts: Optional[Set[VerificationVerdict]] = None,
) -> List[Dict[str, Any]]:
    """Collect positive predictions with labels for detailed matching."""
    if accepted_verdicts is None:
        accepted_verdicts = _POSITIVE_VERDICTS

    records: List[Dict[str, Any]] = []
    for idx, vl in enumerate(result.verified_labels):
        if vl.verdict not in accepted_verdicts:
            continue
        label = _normalize_label(vl.final_label or vl.proposal.label)
        records.append({
            "index": idx,
            "label": label,
            "address": vl.proposal.address,
            "function_name": vl.proposal.function_name or "",
            "verdict": vl.verdict.value,
            "pack_id": vl.pack_id,
        })
    return records


def _dedup_prediction_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate overlapping predictions.

    For each (label, function):
      - Keep all unique non-zero addresses.
      - Drop zero-address entries when non-zero entries exist.
      - If only zero-address entries exist, keep one.
    """
    by_key: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        key = (r.get("label", ""), r.get("function_name", "") or "")
        by_key[key].append(r)

    out: List[Dict[str, Any]] = []
    for group in by_key.values():
        nonzero = [r for r in group if int(r.get("address") or 0) != 0]
        if nonzero:
            seen_addr: Set[int] = set()
            for r in nonzero:
                addr = int(r.get("address") or 0)
                if addr in seen_addr:
                    continue
                seen_addr.add(addr)
                out.append(r)
            continue
        out.append(group[0])

    return out


def _normalize_label(label) -> str:
    """Normalize a label to its string value."""
    if hasattr(label, "value"):
        return label.value
    return str(label)


def _gt_hint_label(gt: GroundTruthEntry) -> str:
    """Normalized hint label for GT entry, if provided."""
    hint = getattr(gt, "pipeline_label_hint", "") or ""
    return _normalize_label(hint) if hint else ""


def _strict_label_matches(pred_label: str, gt: GroundTruthEntry) -> bool:
    """Strict label match: exact label only.

    pipeline_label_hint is evaluated later as a partial alias rule so that
    semantic subtype matches (for example PARSING_OVERFLOW_SINK -> STORE_SINK)
    do not inflate strict exact-match metrics.
    """
    gt_label = _normalize_label(gt.label)
    return pred_label == gt_label


def _dedup_gt_entries(entries: List[GroundTruthEntry]) -> List[GroundTruthEntry]:
    """Deduplicate indistinguishable GT sites.

    If multiple GT entries share the same (label, address, function_name),
    keep one; this avoids over-penalizing when GT encodes multiple paths that
    collapse to the same site-level oracle.
    """
    out: List[GroundTruthEntry] = []
    seen: Set[Tuple[str, Optional[int], str]] = set()
    for gt in entries:
        label = _normalize_label(gt.label)
        func = (gt.function_name or "").strip().lower()
        # Keep label-only entries as-is; they are intentionally coarse.
        if gt.address is None and not func:
            out.append(gt)
            continue
        key = (label, gt.address, func)
        if key in seen:
            continue
        seen.add(key)
        out.append(gt)
    return out


def _match_entries(
    pred_entries: List[Tuple[int, str]],
    gt_entries: List[GroundTruthEntry],
) -> Tuple[int, int, int]:
    """Match predictions against ground truth entries.

    Returns (true_positives, false_positives, false_negatives).

    Matching priority:
      1. Address match (if GT has address): pred address == GT address
      2. Function match (if GT has function_name): pred function contains GT function
      3. Label-only (GT has neither): any prediction counts
    """
    gt_entries = _dedup_gt_entries(gt_entries)
    matched_pred_indices: Set[int] = set()
    matched_gt_indices: Set[int] = set()

    # Pass 1: Exact address match (highest priority)
    for gi, gt in enumerate(gt_entries):
        if gt.address is None:
            continue
        for pi, (addr, func) in enumerate(pred_entries):
            if pi in matched_pred_indices:
                continue
            if addr == gt.address:
                matched_pred_indices.add(pi)
                matched_gt_indices.add(gi)
                break

    # Pass 1b: Near-address match to tolerate callsite/function-entry skew.
    for gi, gt in enumerate(gt_entries):
        if gi in matched_gt_indices:
            continue
        if gt.address is None:
            continue
        for pi, (addr, func) in enumerate(pred_entries):
            if pi in matched_pred_indices:
                continue
            if _addresses_near(addr, gt.address):
                matched_pred_indices.add(pi)
                matched_gt_indices.add(gi)
                break

    # Pass 2: Function name match
    for gi, gt in enumerate(gt_entries):
        if gi in matched_gt_indices:
            continue
        if not gt.function_name:
            continue
        for pi, (addr, func) in enumerate(pred_entries):
            if pi in matched_pred_indices:
                continue
            # Flexible function matching: GT func in pred func or vice versa
            # (handles Ghidra FUN_xxx vs debug-symbol names)
            if _functions_match(func, gt.function_name):
                matched_pred_indices.add(pi)
                matched_gt_indices.add(gi)
                break

    # Pass 3: Label-only match (GT has neither address nor function)
    for gi, gt in enumerate(gt_entries):
        if gi in matched_gt_indices:
            continue
        if gt.address is not None or gt.function_name:
            continue
        # Any unmatched prediction counts
        for pi in range(len(pred_entries)):
            if pi not in matched_pred_indices:
                matched_pred_indices.add(pi)
                matched_gt_indices.add(gi)
                break

    tp = len(matched_gt_indices)
    fp = len(pred_entries) - len(matched_pred_indices)
    fn = len(gt_entries) - len(matched_gt_indices)

    return tp, fp, fn


def _functions_match(pred_func: str, gt_func: str) -> bool:
    """Check if a predicted function name matches a ground truth function name.

    Handles:
      - Exact match
      - Ghidra FUN_xxx contains the GT address
      - GT function name is substring of pred function name
    """
    if not pred_func or not gt_func:
        return False

    # Exact match
    if pred_func == gt_func:
        return True

    # Substring match (e.g., GT="UART_ReadBlocking", pred="UART_ReadBlocking")
    if gt_func in pred_func or pred_func in gt_func:
        return True

    return False


def _match_mode(pred: Dict[str, Any], gt: GroundTruthEntry) -> str:
    """Return match mode between one prediction and one GT entry."""
    if gt.address is not None:
        if pred["address"] == gt.address:
            return "address"
        if _addresses_near(pred["address"], gt.address):
            return "address_near"
        # For partial/hint matching, allow function-level fallback when
        # callsite address is unavailable or shifted in decompiler output.
        if gt.function_name and _functions_match(pred["function_name"], gt.function_name):
            return "function"
        return ""
    if gt.function_name:
        return "function" if _functions_match(pred["function_name"], gt.function_name) else ""
    return "label_only"


_SOURCE_LABELS = {
    SourceLabel.MMIO_READ.value,
    SourceLabel.ISR_MMIO_READ.value,
    SourceLabel.ISR_FILLED_BUFFER.value,
    SourceLabel.DMA_BACKED_BUFFER.value,
}


def _is_source_label(label: str) -> bool:
    return label in _SOURCE_LABELS


def _is_sink_label(label: str) -> bool:
    return label in _MEMORY_WRITE_SINK_LABELS or label in {
        "FORMAT_STRING_SINK", "FUNC_PTR_SINK",
        "LENGTH_TRUST_SINK", "UNBOUNDED_WALK_SINK", "PARSING_OVERFLOW_SINK",
    }


def compare_labels_detailed(
    result: PipelineResult,
    ground_truth: List[GroundTruthEntry],
    accepted_verdicts: Optional[Set[VerificationVerdict]] = None,
    partial_credit: float = 0.5,
    eval_scope: str = "all",
) -> Dict[str, Any]:
    """Detailed matching report with strict and weighted metrics.

    Strict matching requires identical label + site match.
    Partial matching (for sink-family near-miss bookkeeping) is applied only to
    unmatched GT entries, when a prediction with the same sink family matches
    the same address/function but has a different label.

    eval_scope: "all" (default), "sinks" (exclude source labels), "sources" (exclude sink labels).
    """
    if accepted_verdicts is None:
        accepted_verdicts = _POSITIVE_VERDICTS

    preds = collect_prediction_records(result, accepted_verdicts)
    gts = [gt for gt in ground_truth if not _normalize_label(gt.label).startswith("_")]

    # Apply eval_scope filtering
    if eval_scope == "sinks":
        preds = [p for p in preds if not _is_source_label(p["label"])]
        gts = [gt for gt in gts if not _is_source_label(_normalize_label(gt.label))]
    elif eval_scope == "sources":
        preds = [p for p in preds if not _is_sink_label(p["label"])]
        gts = [gt for gt in gts if not _is_sink_label(_normalize_label(gt.label))]
    gts = _dedup_gt_entries(gts)
    preds = _dedup_prediction_records(preds)
    # Re-index predictions after filtering
    for i, p in enumerate(preds):
        p["index"] = i

    used_pred_indices: Set[int] = set()
    matched_gt_indices: Set[int] = set()
    details: List[Dict[str, Any]] = []

    # Pass 1: strict address matches.
    for gi, gt in enumerate(gts):
        gt_label = _normalize_label(gt.label)
        if gt.address is None:
            continue
        for pred in preds:
            pi = pred["index"]
            if pi in used_pred_indices:
                continue
            if not _strict_label_matches(pred["label"], gt):
                continue
            if pred["address"] == gt.address:
                used_pred_indices.add(pi)
                matched_gt_indices.add(gi)
                details.append({
                    "gt_index": gi,
                    "gt_label": gt_label,
                    "gt_address": gt.address,
                    "gt_function_name": gt.function_name,
                    "status": "exact",
                    "match_type": "address",
                    "prediction": pred,
                    "credit": 1.0,
                })
                break

    # Pass 1b: strict near-address matches (same label, small delta).
    for gi, gt in enumerate(gts):
        if gi in matched_gt_indices:
            continue
        gt_label = _normalize_label(gt.label)
        if gt.address is None:
            continue
        for pred in preds:
            pi = pred["index"]
            if pi in used_pred_indices:
                continue
            if not _strict_label_matches(pred["label"], gt):
                continue
            if _addresses_near(pred["address"], gt.address):
                used_pred_indices.add(pi)
                matched_gt_indices.add(gi)
                details.append({
                    "gt_index": gi,
                    "gt_label": gt_label,
                    "gt_address": gt.address,
                    "gt_function_name": gt.function_name,
                    "status": "exact",
                    "match_type": "address_near",
                    "prediction": pred,
                    "credit": 1.0,
                })
                break

    # Pass 2: strict function matches.
    for gi, gt in enumerate(gts):
        if gi in matched_gt_indices:
            continue
        gt_label = _normalize_label(gt.label)
        if not gt.function_name:
            continue
        for pred in preds:
            pi = pred["index"]
            if pi in used_pred_indices:
                continue
            if not _strict_label_matches(pred["label"], gt):
                continue
            if _functions_match(pred["function_name"], gt.function_name):
                used_pred_indices.add(pi)
                matched_gt_indices.add(gi)
                details.append({
                    "gt_index": gi,
                    "gt_label": gt_label,
                    "gt_address": gt.address,
                    "gt_function_name": gt.function_name,
                    "status": "exact",
                    "match_type": "function",
                    "prediction": pred,
                    "credit": 1.0,
                })
                break

    # Pass 3: strict label-only matches.
    for gi, gt in enumerate(gts):
        if gi in matched_gt_indices:
            continue
        gt_label = _normalize_label(gt.label)
        if gt.address is not None or gt.function_name:
            continue
        for pred in preds:
            pi = pred["index"]
            if pi in used_pred_indices:
                continue
            if _strict_label_matches(pred["label"], gt):
                used_pred_indices.add(pi)
                matched_gt_indices.add(gi)
                details.append({
                    "gt_index": gi,
                    "gt_label": gt_label,
                    "gt_address": gt.address,
                    "gt_function_name": gt.function_name,
                    "status": "exact",
                    "match_type": "label_only",
                    "prediction": pred,
                    "credit": 1.0,
                })
                break

    # Pass 4: partial sink-family matches.
    for gi, gt in enumerate(gts):
        if gi in matched_gt_indices:
            continue

        gt_label = _normalize_label(gt.label)
        gt_family = _sink_family(gt_label)
        partial_match = None

        for pred in preds:
            pi = pred["index"]
            if pi in used_pred_indices:
                continue

            pred_family = _sink_family(pred["label"])
            if pred_family != gt_family or pred["label"] == gt_label:
                continue

            mode = _match_mode(pred, gt)
            if mode and mode != "label_only":
                partial_match = (pred, mode)
                break

        if partial_match:
            pred, mode = partial_match
            used_pred_indices.add(pred["index"])
            matched_gt_indices.add(gi)
            details.append({
                "gt_index": gi,
                "gt_label": gt_label,
                "gt_address": gt.address,
                "gt_function_name": gt.function_name,
                "status": "partial",
                "match_type": f"sink_family_{mode}",
                "prediction": pred,
                "credit": partial_credit,
                "partial_rule": (
                    "same sink family + same function/address, different label"
                ),
            })
            continue

        # Pass 5: pipeline_label_hint — if the GT entry has a hint label,
        # check if the pipeline produced the hinted label at the same site.
        hint = getattr(gt, "pipeline_label_hint", "") or ""
        hint_match = None
        if hint:
            for pred in preds:
                pi = pred["index"]
                if pi in used_pred_indices:
                    continue
                if pred["label"] != hint:
                    continue
                mode = _match_mode(pred, gt)
                if mode and mode != "label_only":
                    hint_match = (pred, mode)
                    break

        if hint_match:
            pred, mode = hint_match
            used_pred_indices.add(pred["index"])
            matched_gt_indices.add(gi)
            details.append({
                "gt_index": gi,
                "gt_label": gt_label,
                "gt_address": gt.address,
                "gt_function_name": gt.function_name,
                "status": "partial",
                "match_type": f"label_hint_{mode}",
                "prediction": pred,
                "credit": partial_credit,
                "partial_rule": (
                    f"pipeline_label_hint={hint} matched at same site"
                ),
            })
        else:
            details.append({
                "gt_index": gi,
                "gt_label": gt_label,
                "gt_address": gt.address,
                "gt_function_name": gt.function_name,
                "status": "fn",
                "match_type": "unmatched_gt",
                "prediction": None,
                "credit": 0.0,
            })

    matched_pred_ids = {
        d["prediction"]["index"]
        for d in details
        if d.get("prediction") is not None
    }
    fp_predictions = [p for p in preds if p["index"] not in matched_pred_ids]

    exact_count = sum(1 for d in details if d["status"] == "exact")
    partial_count = sum(1 for d in details if d["status"] == "partial")

    strict_tp = float(exact_count)
    strict_fn = float(len(gts) - exact_count)
    strict_fp = float(len(preds) - exact_count)

    weighted_tp = strict_tp + partial_credit * partial_count
    weighted_fn = max(0.0, len(gts) - weighted_tp)
    weighted_fp = max(0.0, len(preds) - weighted_tp)

    # strict_no_partial_penalty: partial matches excluded from both FP and FN
    snpp_tp = float(exact_count)
    snpp_fn = float(len(gts) - exact_count - partial_count)
    snpp_fp = float(len(preds) - exact_count - partial_count)

    strict_precision = _safe_div(strict_tp, strict_tp + strict_fp)
    strict_recall = _safe_div(strict_tp, strict_tp + strict_fn)
    strict_f1 = _safe_div(2 * strict_precision * strict_recall, strict_precision + strict_recall)

    weighted_precision = _safe_div(weighted_tp, weighted_tp + weighted_fp)
    weighted_recall = _safe_div(weighted_tp, weighted_tp + weighted_fn)
    weighted_f1 = _safe_div(2 * weighted_precision * weighted_recall, weighted_precision + weighted_recall)

    snpp_precision = _safe_div(snpp_tp, snpp_tp + snpp_fp)
    snpp_recall = _safe_div(snpp_tp, snpp_tp + snpp_fn)
    snpp_f1 = _safe_div(2 * snpp_precision * snpp_recall, snpp_precision + snpp_recall)

    fp_by_label: Dict[str, int] = defaultdict(int)
    for pred in fp_predictions:
        fp_by_label[pred["label"]] += 1

    partial_breakdown: Dict[str, int] = defaultdict(int)
    for d in details:
        if d.get("status") != "partial":
            continue
        mtype = str(d.get("match_type", ""))
        if mtype.startswith("label_hint_"):
            partial_breakdown["label_hint"] += 1
        elif mtype.startswith("sink_family_"):
            partial_breakdown["sink_family"] += 1

    return {
        "binary_path": result.binary_path,
        "binary_stem": Path(result.binary_path).stem,
        "gt_count": len(gts),
        "prediction_count": len(preds),
        "partial_credit": partial_credit,
        "matches": details,
        "fp_predictions": fp_predictions,
        "fp_by_label": dict(sorted(fp_by_label.items())),
        "partial_breakdown": dict(sorted(partial_breakdown.items())),
        "strict": {
            "tp": strict_tp,
            "fp": strict_fp,
            "fn": strict_fn,
            "precision": strict_precision,
            "recall": strict_recall,
            "f1": strict_f1,
            "exact_match_count": exact_count,
            "partial_match_count": partial_count,
        },
        "weighted": {
            "tp": weighted_tp,
            "fp": weighted_fp,
            "fn": weighted_fn,
            "precision": weighted_precision,
            "recall": weighted_recall,
            "f1": weighted_f1,
            "exact_match_count": exact_count,
            "partial_match_count": partial_count,
        },
        "strict_no_partial_penalty": {
            "tp": snpp_tp,
            "fp": snpp_fp,
            "fn": snpp_fn,
            "precision": snpp_precision,
            "recall": snpp_recall,
            "f1": snpp_f1,
            "note": "partial matches excluded from both FP and FN",
        },
    }


def _safe_div(a: float, b: float) -> float:
    return a / b if b > 0 else 0.0


def _addresses_near(pred_addr: int, gt_addr: int, tol: int = _ADDRESS_NEAR_TOLERANCE) -> bool:
    """Best-effort near-address match for callsite/function-entry mismatches."""
    try:
        if pred_addr is None or gt_addr is None:
            return False
        return abs(int(pred_addr) - int(gt_addr)) <= tol
    except (TypeError, ValueError):
        return False


# ── Run Eval ───────────────────────────────────────────────────────────────


async def run_eval(
    binary_path: str,
    ground_truth: List[GroundTruthEntry],
    pipeline_result: Optional[PipelineResult] = None,
    stage: int = 7,
    offline: bool = False,
    model: str = "",
    analysis_wait_sec: int = 60,
    mcp_connect_timeout_sec: int = 30,
    accepted_verdicts: Optional[Set[VerificationVerdict]] = None,
    output_path: Optional[str] = None,
    run_id: Optional[str] = None,
    return_pipeline_result: bool = False,
    review_kwargs: Optional[Dict[str, Any]] = None,
) -> Any:
    """Run the full pipeline on a binary and compare against ground truth.

    If pipeline_result is provided, uses it directly (avoids re-running the
    pipeline). Otherwise, imports and runs _cmd_mine internally.

    Returns per-label-class EvalResult with precision/recall/F1.
    """
    if pipeline_result is None:
        merged_review_kwargs = dict(review_kwargs or {})
        merged_review_kwargs.setdefault("has_ground_truth", bool(ground_truth))
        pipeline_result = await _run_pipeline(
            binary_path,
            stage=stage,
            offline=offline,
            model=model,
            analysis_wait_sec=analysis_wait_sec,
            mcp_connect_timeout_sec=mcp_connect_timeout_sec,
            output_path=output_path,
            run_id=run_id,
            review_kwargs=merged_review_kwargs,
        )

    eval_results = compare_labels(
        pipeline_result, ground_truth, accepted_verdicts=accepted_verdicts,
    )
    if return_pipeline_result:
        return eval_results, pipeline_result
    return eval_results


async def _run_pipeline(
    binary_path: str,
    stage: int = 7,
    offline: bool = False,
    model: str = "",
    analysis_wait_sec: int = 60,
    mcp_connect_timeout_sec: int = 30,
    output_path: Optional[str] = None,
    run_id: Optional[str] = None,
    review_kwargs: Optional[Dict[str, Any]] = None,
) -> PipelineResult:
    """Run the mining pipeline and return PipelineResult."""
    import types
    from sourceagent.interface.main import _cmd_mine

    review_kwargs = dict(review_kwargs or {})
    args = types.SimpleNamespace(
        binary=binary_path,
        stage=stage,
        model=model or None,
        run_id=run_id or f"eval-{Path(binary_path).stem}",
        offline=offline,
        analysis_wait_sec=analysis_wait_sec,
        mcp_connect_timeout_sec=mcp_connect_timeout_sec,
        output=output_path,
        **review_kwargs,
    )
    result = await _cmd_mine(args)
    return result


# ── Aggregate Results ──────────────────────────────────────────────────────


def aggregate_results(results: List[EvalResult]) -> EvalResult:
    """Aggregate multiple EvalResult objects into a single micro-average result."""
    tp = sum(r.true_positives for r in results)
    fp = sum(r.false_positives for r in results)
    fn = sum(r.false_negatives for r in results)
    return EvalResult(
        binary_stem="__aggregate__",
        label_class="__all__",
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
    )


def eval_results_to_dict(results: List[EvalResult]) -> Dict[str, Any]:
    """Serialize per-label eval rows plus micro-average summary."""
    rows = []
    for r in results:
        rows.append({
            "binary_stem": r.binary_stem,
            "label_class": r.label_class,
            "tp": r.true_positives,
            "fp": r.false_positives,
            "fn": r.false_negatives,
            "precision": r.precision,
            "recall": r.recall,
            "f1": r.f1,
        })
    agg = aggregate_results(results)
    return {
        "rows": rows,
        "micro_average": {
            "tp": agg.true_positives,
            "fp": agg.false_positives,
            "fn": agg.false_negatives,
            "precision": agg.precision,
            "recall": agg.recall,
            "f1": agg.f1,
        },
    }


def default_scoring_policy(partial_credit: float = 0.5) -> Dict[str, Any]:
    """Machine-readable scoring policy used for strict/weighted accounting."""
    return {
        "matching_priority": [
            "exact address (same label)",
            "exact function (same label)",
            "label-only (same label, GT has no address/function)",
        ],
        "verdicts_counted_positive": [v.value for v in sorted(_POSITIVE_VERDICTS, key=lambda x: x.value)],
        "strict_scoring": {
            "tp": "count(exact matches)",
            "fn": "gt_count - tp",
            "fp": "prediction_count - tp",
        },
        "weighted_partial_scoring": {
            "enabled_for": "unmatched GT entries with same sink family match at same address/function",
            "partial_credit": partial_credit,
            "tp": "exact_matches + partial_credit * partial_matches",
            "fn": "gt_count - weighted_tp",
            "fp": "prediction_count - weighted_tp",
        },
        "partial_rule_summary": (
            "Near-miss example: GT=COPY_SINK, detected=STORE_SINK in the same function "
            "counts as partial (used to formalize manual '~1')."
        ),
    }


def print_eval_report(results: List[EvalResult], binary_stem: str = ""):
    """Print a formatted evaluation report."""
    if not results:
        print("No evaluation results.")
        return

    if binary_stem:
        print(f"\n{'=' * 60}")
        print(f"  Evaluation Report: {binary_stem}")
        print(f"{'=' * 60}")

    print(f"  {'Label':<25s} {'TP':>4s} {'FP':>4s} {'FN':>4s} {'P':>6s} {'R':>6s} {'F1':>6s}")
    print(f"  {'-' * 25} {'-' * 4} {'-' * 4} {'-' * 4} {'-' * 6} {'-' * 6} {'-' * 6}")

    for r in results:
        print(
            f"  {r.label_class:<25s} "
            f"{r.true_positives:>4d} {r.false_positives:>4d} {r.false_negatives:>4d} "
            f"{r.precision:>6.2f} {r.recall:>6.2f} {r.f1:>6.2f}"
        )

    # Aggregate
    agg = aggregate_results(results)
    print(f"  {'-' * 25} {'-' * 4} {'-' * 4} {'-' * 4} {'-' * 6} {'-' * 6} {'-' * 6}")
    print(
        f"  {'MICRO-AVERAGE':<25s} "
        f"{agg.true_positives:>4d} {agg.false_positives:>4d} {agg.false_negatives:>4d} "
        f"{agg.precision:>6.2f} {agg.recall:>6.2f} {agg.f1:>6.2f}"
    )
    print()
