"""Summary / report helpers for Phase B diagnostic mode."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence

SCHEMA_VERSION = "0.1"
_VERDICT_RANK = {
    "DROP": 0,
    "SAFE_OR_LOW_RISK": 1,
    "SUSPICIOUS": 2,
    "CONFIRMED": 3,
}
_RISK_RANK = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
}
_PRIORITY_RANK = {
    "P2": 0,
    "P1": 1,
    "P0": 2,
}
_CHECK_BINDING_REASONS = {
    "CHECK_NOT_BINDING_ROOT",
    "CHECK_NON_DOMINATING",
    "CHECK_INCOMPLETE_UPPER_BOUND",
    "PARTIAL_GUARD_WRITE_BOUND_ONLY",
    "PARTIAL_GUARD_READ_BOUND_ONLY",
    "WEAK_GUARDING",
    "EFFECTIVE_GUARD_UNSCOPED",
}
_CAPACITY_REASONS = {
    "TRIGGERABLE_LEN_GT_CAPACITY",
    "TRIGGERABLE_INDEX_OOB",
    "TRIGGER_UNCERTAIN_MISSING_CAPACITY",
    "PARSER_LENGTH_FIELD_TRUSTED",
    "PARSER_DESCRIPTOR_WALK_UNBOUNDED",
}


def build_phaseb_diagnostic_summary(
    *,
    bundle: Mapping[str, Any],
    review_plan: Mapping[str, Any],
    review_run: Mapping[str, Any],
    calibration_outputs: Mapping[str, Any],
) -> Dict[str, Any]:
    items = list(bundle.get("items", []) or [])
    soft_by_id = _index_by_chain_id((calibration_outputs.get("verdict_soft_triage", {}) or {}).get("items", []) or [])
    decisions_by_id = _index_by_chain_id((calibration_outputs.get("verdict_calibration_decisions", {}) or {}).get("items", []) or [])
    rows: List[Dict[str, Any]] = []
    counts_by_sample: Counter[str] = Counter()
    exact_count = 0
    anchor_count = 0
    for item in items:
        feature_item = dict(item.get("feature_item", {}) or {})
        meta = dict(item.get("meta", {}) or {})
        chain_id = str(feature_item.get("chain_id", "") or meta.get("diagnostic_chain_id", "") or "")
        soft_row = dict(soft_by_id.get(chain_id, {}) or {})
        decision_row = dict(decisions_by_id.get(chain_id, {}) or {})
        sample_id = str(meta.get("sample_id", "") or feature_item.get("sample_id", "") or bundle.get("sample_id", "") or "sample")
        counts_by_sample[sample_id] += 1
        if meta.get("diagnostic_source") == "anchor":
            anchor_count += 1
        row = {
            "sample_id": sample_id,
            "diagnostic_source": str(meta.get("diagnostic_source", bundle.get("diagnostic_source", "")) or ""),
            "diagnostic_mode": str(meta.get("diagnostic_mode", "") or ""),
            "diagnostic_role": str(meta.get("diagnostic_role", "") or ""),
            "is_canonical_main": str(meta.get("diagnostic_role", "") or "") == "canonical_main",
            "gt_chain_id": meta.get("gt_chain_id"),
            "runtime_pred_chain_id": meta.get("runtime_pred_chain_id"),
            "diagnostic_chain_id": chain_id,
            "anchor_status": meta.get("anchor_status"),
            "structural_status": meta.get("structural_status"),
            "strict_verdict": feature_item.get("strict_verdict", feature_item.get("current_verdict")),
            "existing_final_verdict": meta.get("existing_final_verdict"),
            "existing_final_risk_band": meta.get("existing_final_risk_band"),
            "existing_review_priority": meta.get("existing_review_priority"),
            "diagnostic_final_verdict": soft_row.get("final_verdict"),
            "diagnostic_final_risk_band": soft_row.get("final_risk_band"),
            "diagnostic_review_priority": soft_row.get("review_priority"),
            "expected_verdict": meta.get("expected_verdict"),
            "expected_final_verdict": meta.get("expected_final_verdict"),
            "expected_final_risk_band": meta.get("expected_final_risk_band"),
            "expected_review_priority": meta.get("expected_review_priority"),
            "accepted": decision_row.get("accepted"),
            "accept_reason": decision_row.get("accept_reason"),
            "soft_accept_state": soft_row.get("soft_accept_state", decision_row.get("soft_accept_state")),
            "blocked_by": list(soft_row.get("blocked_by", []) or decision_row.get("blocked_by", []) or []),
            "reason_codes": list(soft_row.get("reason_codes", []) or decision_row.get("reason_codes", []) or []),
            "review_quality_flags": list(soft_row.get("review_quality_flags", []) or decision_row.get("review_quality_flags", []) or []),
            "trigger_summary": soft_row.get("trigger_summary", decision_row.get("trigger_summary")),
            "final_summary": dict(soft_row.get("final_summary", decision_row.get("final_summary", {})) or {}),
        }
        row["agreement_status"] = _agreement_status(row)
        row["root_cause_class"] = _root_cause_class(row)
        row["recommended_fix_layer"] = _recommended_fix_layer(row["root_cause_class"])
        if row["agreement_status"] == "exact":
            exact_count += 1
        rows.append(row)

    verdict_counter = Counter(
        str(row.get("diagnostic_final_verdict", "") or "")
        for row in rows
        if str(row.get("diagnostic_final_verdict", "") or "")
    )
    risk_counter = Counter(
        str(row.get("diagnostic_final_risk_band", "") or "")
        for row in rows
        if str(row.get("diagnostic_final_risk_band", "") or "")
    )
    priority_counter = Counter(
        str(row.get("diagnostic_review_priority", "") or "")
        for row in rows
        if str(row.get("diagnostic_review_priority", "") or "")
    )
    cause_counter = Counter(
        str(row.get("root_cause_class", "") or "")
        for row in rows
        if str(row.get("root_cause_class", "") or "")
    )
    role_counter = Counter(
        str(row.get("diagnostic_role", "") or "")
        for row in rows
        if str(row.get("diagnostic_role", "") or "")
    )
    agreement_counter = Counter(
        str(row.get("agreement_status", "") or "")
        for row in rows
        if str(row.get("agreement_status", "") or "")
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "diagnostic_source": str(bundle.get("diagnostic_source", "") or ""),
        "sample_id": str(bundle.get("sample_id", "") or ""),
        "binary": str(bundle.get("binary", "") or ""),
        "binary_sha256": str(bundle.get("binary_sha256", "") or ""),
        "review_plan_status": str(review_plan.get("status", "") or ""),
        "review_session_status": str((review_run.get("review_session", {}) or {}).get("status", "") or ""),
        "counts": {
            "sample_count": len(counts_by_sample),
            "chain_count": len(rows),
            "anchor_chain_count": anchor_count,
            "agreement_exact": exact_count,
            "canonical_main_count": role_counter.get("canonical_main", 0),
            "related_risky_count": role_counter.get("related_risky", 0) + role_counter.get("supporting_risky", 0),
            "peripheral_suspicious_count": role_counter.get("peripheral_suspicious", 0),
        },
        "diagnostic_final_verdict": dict(sorted(verdict_counter.items())),
        "diagnostic_final_risk_band": dict(sorted(risk_counter.items())),
        "diagnostic_review_priority": dict(sorted(priority_counter.items())),
        "agreement_status": dict(sorted(agreement_counter.items())),
        "root_cause_class": dict(sorted(cause_counter.items())),
        "per_sample": [
            {"sample_id": sample_id, "chain_count": count}
            for sample_id, count in sorted(counts_by_sample.items())
        ],
        "rows": rows,
    }


def render_phaseb_diagnostic_markdown(summary: Mapping[str, Any]) -> str:
    lines: List[str] = [
        "# Phase B Diagnostic Summary",
        "",
        f"- Diagnostic source: `{summary.get('diagnostic_source', '')}`",
        f"- Sample: `{summary.get('sample_id', '')}`",
        f"- Binary: `{summary.get('binary', '')}`",
        f"- Chains reviewed: `{(summary.get('counts', {}) or {}).get('chain_count', 0)}`",
        f"- Exact expectation matches: `{(summary.get('counts', {}) or {}).get('agreement_exact', 0)}`",
        "",
        "## Aggregate Counters",
        "",
        f"- Final verdicts: `{summary.get('diagnostic_final_verdict', {})}`",
        f"- Final risk bands: `{summary.get('diagnostic_final_risk_band', {})}`",
        f"- Review priorities: `{summary.get('diagnostic_review_priority', {})}`",
        f"- Root-cause classes: `{summary.get('root_cause_class', {})}`",
        "",
        "## Per-Chain Findings",
        "",
    ]
    for row in summary.get("rows", []) or []:
        chain_label = str(row.get("gt_chain_id") or row.get("diagnostic_chain_id") or "chain")
        lines.extend(
            [
                f"### {chain_label}",
                "",
                f"- Role: `{row.get('diagnostic_role', '')}`",
                f"- Mode: `{row.get('diagnostic_mode', '')}`",
                f"- Existing runtime state: `{row.get('existing_final_verdict', 'n/a')}` / `{row.get('existing_final_risk_band', 'n/a')}` / `{row.get('existing_review_priority', 'n/a')}`",
                f"- Diagnostic result: `{row.get('diagnostic_final_verdict', 'n/a')}` / `{row.get('diagnostic_final_risk_band', 'n/a')}` / `{row.get('diagnostic_review_priority', 'n/a')}`",
                f"- Expected answer: `{row.get('expected_final_verdict', 'n/a')}` / `{row.get('expected_final_risk_band', 'n/a')}` / `{row.get('expected_review_priority', 'n/a')}`",
                f"- Agreement: `{row.get('agreement_status', '')}`",
                f"- Root cause class: `{row.get('root_cause_class', '')}`",
                f"- Recommended fix layer: `{row.get('recommended_fix_layer', '')}`",
            ]
        )
        if row.get("blocked_by"):
            lines.append(f"- Blocked by: `{row.get('blocked_by')}`")
        if row.get("reason_codes"):
            lines.append(f"- Reason codes: `{row.get('reason_codes')}`")
        if row.get("trigger_summary"):
            lines.append(f"- Trigger summary: {row.get('trigger_summary')}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_phaseb_diagnostic_outputs(
    *,
    output_dir: str | Path,
    bundle: Mapping[str, Any],
    review_plan: Mapping[str, Any],
    review_run: Mapping[str, Any],
    calibration_outputs: Mapping[str, Any],
    summary: Mapping[str, Any],
) -> None:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    _dump_json(output_dir / "phaseb_diagnostic_inputs.json", bundle)
    _dump_json(output_dir / "phaseb_diagnostic_plan.json", review_plan)
    _dump_json(output_dir / "phaseb_diagnostic_prompt.json", review_run.get("review_prompt", {}) or {})
    _dump_json(output_dir / "phaseb_diagnostic_raw_response.json", review_run.get("review_raw_response", {}) or {})
    _dump_json(output_dir / "phaseb_diagnostic_session.json", review_run.get("review_session", {}) or {})
    _dump_json(output_dir / "phaseb_diagnostic_trace.json", review_run.get("review_trace", {}) or {})
    _dump_json(output_dir / "phaseb_diagnostic_decisions.json", calibration_outputs.get("verdict_calibration_decisions", {}) or {})
    _dump_json(output_dir / "phaseb_diagnostic_soft_triage.json", calibration_outputs.get("verdict_soft_triage", {}) or {})
    _dump_json(output_dir / "phaseb_diagnostic_summary.json", summary)
    (output_dir / "phaseb_diagnostic_summary.md").write_text(
        render_phaseb_diagnostic_markdown(summary),
        encoding="utf-8",
    )


def _agreement_status(row: Mapping[str, Any]) -> str:
    expected_v = str(row.get("expected_final_verdict", "") or "")
    expected_r = str(row.get("expected_final_risk_band", "") or "")
    expected_p = str(row.get("expected_review_priority", "") or "")
    if not (expected_v or expected_r or expected_p):
        return "not_annotated"
    actual_v = str(row.get("diagnostic_final_verdict", "") or "")
    actual_r = str(row.get("diagnostic_final_risk_band", "") or "")
    actual_p = str(row.get("diagnostic_review_priority", "") or "")
    if actual_v == expected_v and actual_r == expected_r and actual_p == expected_p:
        return "exact"
    if (
        _VERDICT_RANK.get(actual_v, -1) <= _VERDICT_RANK.get(expected_v, -1)
        and _RISK_RANK.get(actual_r, -1) <= _RISK_RANK.get(expected_r, -1)
        and _PRIORITY_RANK.get(actual_p, -1) <= _PRIORITY_RANK.get(expected_p, -1)
    ):
        return "under"
    if (
        _VERDICT_RANK.get(actual_v, -1) >= _VERDICT_RANK.get(expected_v, -1)
        and _RISK_RANK.get(actual_r, -1) >= _RISK_RANK.get(expected_r, -1)
        and _PRIORITY_RANK.get(actual_p, -1) >= _PRIORITY_RANK.get(expected_p, -1)
    ):
        return "over"
    return "mismatch"


def _root_cause_class(row: Mapping[str, Any]) -> str:
    mode = str(row.get("diagnostic_mode", "") or "")
    role = str(row.get("diagnostic_role", "") or "")
    agreement = str(row.get("agreement_status", "") or "")
    blocked = {str(v) for v in (row.get("blocked_by", []) or []) if str(v)}
    reasons = {str(v) for v in (row.get("reason_codes", []) or []) if str(v)}
    if role == "canonical_main" and mode == "anchor_synthetic":
        return "alignment_gap"
    if agreement == "exact":
        return "matched_expectation"
    if blocked.intersection({"object_bound", "source_reached", "channel_satisfied"}):
        return "structural_gate_gap"
    if reasons.intersection(_CHECK_BINDING_REASONS):
        return "check_binding_gap"
    if reasons.intersection(_CAPACITY_REASONS):
        return "capacity_evidence_gap"
    return "risk_policy_too_conservative"


def _recommended_fix_layer(root_cause_class: str) -> str:
    mapping = {
        "alignment_gap": "evaluator_alignment_or_anchor_mapping",
        "structural_gate_gap": "phasea_or_anchor_adapter",
        "check_binding_gap": "phaseb_check_binding_reasoning",
        "capacity_evidence_gap": "phaseb_capacity_reasoning",
        "risk_policy_too_conservative": "phaseb_risk_policy",
        "matched_expectation": "none",
    }
    return mapping.get(str(root_cause_class or ""), "phaseb_diagnostic_followup")


def _index_by_chain_id(rows: Iterable[Mapping[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        chain_id = str(row.get("chain_id", "") or "").strip()
        if chain_id:
            out[chain_id] = dict(row)
    return out


def _dump_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
