"""Build semantic-review plans from verdict calibration artifacts."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence

from sourceagent.agents.review_context_ranker import (
    MAX_BATCH_PROMPT_CHARS,
    build_review_context_plan,
)

DEFAULT_REVIEW_BATCH_SIZE = 4
DEFAULT_MAX_REVIEW_ITEMS = 24
DEFAULT_REVIEW_TOOL_MODE = "prompt_only"


def build_review_plan(
    feature_pack: Mapping[str, Any],
    calibration_queue: Mapping[str, Any],
    *,
    review_mode: str = "semantic",
    review_tool_mode: str = DEFAULT_REVIEW_TOOL_MODE,
    max_items: int = DEFAULT_MAX_REVIEW_ITEMS,
    batch_size: int = DEFAULT_REVIEW_BATCH_SIZE,
) -> Dict[str, Any]:
    feature_items = {
        str(item.get("chain_id", "") or ""): dict(item)
        for item in (feature_pack or {}).get("items", []) or []
        if str(item.get("chain_id", "") or "")
    }
    queue_items = [
        dict(item)
        for item in (calibration_queue or {}).get("items", []) or []
        if str(item.get("chain_id", "") or "") in feature_items
    ]
    queue_items.sort(key=_queue_sort_key)
    queue_items = _select_review_items(queue_items, feature_items, max_items=max_items)

    work_items: List[Dict[str, Any]] = []
    for idx, q in enumerate(queue_items):
        chain_id = str(q.get("chain_id", "") or "")
        feat = dict(feature_items.get(chain_id, {}) or {})
        snippets = dict(feat.get("decompiled_snippets", {}) or {})
        context_plan = build_review_context_plan(feat)
        work_items.append({
            "plan_rank": idx,
            "chain_id": chain_id,
            "queue_reasons": list(q.get("queue_reasons", []) or []),
            "queue_score": float(q.get("queue_score", feat.get("risk_score", 0.0)) or 0.0),
            "sample_id": feat.get("sample_id", ""),
            "current_verdict": feat.get("current_verdict", "DROP"),
            "current_verdict_reason": feat.get("current_verdict_reason", ""),
            "soft_verdict": feat.get("soft_verdict", feat.get("current_verdict", "DROP")),
            "risk_score": float(feat.get("risk_score", 0.0) or 0.0),
            "review_priority": str(feat.get("review_priority", "") or ""),
            "needs_review": bool(feat.get("needs_review", False)),
            "review_state": feat.get("review_state", "non_exact"),
            "audit_flags": list(feat.get("audit_flags", []) or []),
            "soft_candidate": bool(feat.get("soft_candidate", False)),
            "blocked_by": list(feat.get("blocked_by", []) or []),
            "sink": dict(feat.get("sink", {}) or {}),
            "root": dict(feat.get("root", {}) or {}),
            "derive_facts": list(feat.get("derive_facts", []) or []),
            "check_facts": list(feat.get("check_facts", []) or []),
            "object_path": list(feat.get("object_path", []) or []),
            "channel_path": list(feat.get("channel_path", []) or []),
            "sink_semantics_hints": dict(feat.get("sink_semantics_hints", {}) or {}),
            "guard_context": list(feat.get("guard_context", []) or []),
            "capacity_evidence": list(feat.get("capacity_evidence", []) or []),
            "target_object_extent": dict(feat.get("target_object_extent", {}) or {}),
            "chain_segments": list(feat.get("chain_segments", []) or []),
            "deterministic_constraints": dict(feat.get("deterministic_constraints", {}) or {}),
            "decision_basis": dict(feat.get("decision_basis", {}) or {}),
            "decompiled_snippets": snippets,
            "snippet_index": dict(feat.get("snippet_index", {}) or {}),
            "available_snippet_keys": [key for key, val in snippets.items() if str(val or "").strip()],
            "review_context_plan": context_plan,
        })

    batches = _batch_items(work_items, batch_size=max(1, int(batch_size or 1)))
    return {
        "schema_version": "0.2",
        "review_mode": str(review_mode or "semantic"),
        "review_tool_mode": str(review_tool_mode or DEFAULT_REVIEW_TOOL_MODE),
        "max_items": int(max_items),
        "batch_size": int(batch_size),
        "items": work_items,
        "batches": batches,
        "status": "ok" if work_items else "empty",
    }


def _queue_sort_key(item: Mapping[str, Any]):
    root_family = str((((item.get("root", {}) or {}).get("family", "")) or ""))
    verdict = str(item.get("current_verdict", "") or "")
    verdict_reason = str(item.get("current_verdict_reason", "") or "")
    sink_label = str((item.get("sink", {}) or {}).get("label", "") or "")
    check_strength = str(item.get("check_strength", "") or "")
    check_scope = str(item.get("check_capacity_scope", "") or "")
    risk_band = str(item.get("risk_band", "") or "")
    reasons = set(str(v) for v in (item.get("queue_reasons", []) or []) if str(v))
    high_value_reason = bool(reasons & {
        "CHECK_NOT_BINDING_ROOT",
        "TRIGGER_UNCERTAIN_MISSING_CAPACITY",
        "WEAK_GUARDING",
        "PARTIAL_GUARD_WRITE_BOUND_ONLY",
        "CHECK_UNCERTAIN",
        "SEMANTIC_REVIEW_NEEDED",
        "ABSENT_GUARD_CONTROLLABLE_ROOT",
        "PARTIAL_GUARD_READ_BOUND_ONLY",
        "STATE_GATE_ONLY",
        "EFFECTIVE_GUARD_UNSCOPED",
        "CHECK_BINDS_OTHER_VALUE",
    })
    low_value_reason = verdict_reason in {
        "CONTROL_PATH_ONLY",
        "SECONDARY_ROOT_ONLY",
        "ROOT_NOT_CAPACITY_RELEVANT",
        "LIKELY_SAFE_BOUND_PRESENT",
    }
    parser_like_sink = sink_label in {"COPY_SINK", "STORE_SINK", "LOOP_WRITE_SINK", "FORMAT_STRING_SINK", "FUNC_PTR_SINK"}
    high_value_root = root_family in {"length", "index_or_bound", "format_arg", "dispatch"}
    weak_or_absent_check = check_strength in {"absent", "weak"}
    absent_or_uncertain_check = check_strength in {"absent", "weak", "unknown"}
    low_value_scope = check_scope in {"state_gate"} and not high_value_reason
    blocked = {str(v) for v in (item.get("blocked_by", []) or []) if str(v)}
    structural_gap = bool(blocked & {"object_bound", "source_reached", "channel_satisfied", "review_required"})
    strong_risk = risk_band in {"HIGH", "MEDIUM"}
    return (
        str(item.get("review_priority", "") or "P9"),
        verdict != "SUSPICIOUS",
        not bool(item.get("soft_candidate", False)),
        not structural_gap,
        not strong_risk,
        not high_value_root,
        not high_value_reason,
        not absent_or_uncertain_check,
        not parser_like_sink,
        low_value_reason,
        low_value_scope,
        verdict != "DROP",
        -float(item.get("queue_score", item.get("risk_score", 0.0)) or 0.0),
        str(item.get("chain_id", "") or ""),
    )


def _batch_items(items: Sequence[Mapping[str, Any]], *, batch_size: int) -> List[Dict[str, Any]]:
    batches: List[Dict[str, Any]] = []
    current: List[Dict[str, Any]] = []
    current_budget = 0
    batch_idx = 0

    for raw in items:
        item = dict(raw)
        item_budget = int(((item.get("review_context_plan", {}) or {}).get("estimated_prompt_chars", 12_000)) or 12_000)
        should_flush = bool(current) and (
            len(current) >= batch_size or current_budget + item_budget > MAX_BATCH_PROMPT_CHARS
        )
        if should_flush:
            batches.append({
                "batch_id": f"batch_{batch_idx:03d}",
                "chain_ids": [str(v.get("chain_id", "") or "") for v in current],
                "items": current,
                "estimated_prompt_chars": current_budget,
            })
            batch_idx += 1
            current = []
            current_budget = 0
        current.append(item)
        current_budget += item_budget

    if current:
        batches.append({
            "batch_id": f"batch_{batch_idx:03d}",
            "chain_ids": [str(v.get("chain_id", "") or "") for v in current],
            "items": current,
            "estimated_prompt_chars": current_budget,
        })
    return batches


def _select_review_items(
    queue_items: Sequence[Mapping[str, Any]],
    feature_items: Mapping[str, Mapping[str, Any]],
    *,
    max_items: int,
) -> List[Dict[str, Any]]:
    ordered = [dict(item) for item in queue_items]
    if max_items <= 0 or len(ordered) <= max_items:
        return ordered

    if max_items <= 0:
        return []

    strong_cap = min(len(ordered), max_items, max(1, int(max_items * 0.9)))
    selected: List[Dict[str, Any]] = [dict(item) for item in ordered[:strong_cap]]
    seen = {str(item.get("chain_id", "") or "") for item in selected}
    seen_functions = set()
    for item in selected:
        chain_id = str(item.get("chain_id", "") or "")
        feat = dict(feature_items.get(chain_id, {}) or {})
        sink_fn = str((feat.get("sink", {}) or {}).get("function", "") or "")
        root_family = str((feat.get("root", {}) or {}).get("family", "") or "")
        verdict_bucket = str(feat.get("current_verdict", "") or "")
        if sink_fn:
            seen_functions.add((sink_fn, root_family, verdict_bucket))

    for item in ordered[strong_cap:]:
        chain_id = str(item.get("chain_id", "") or "")
        feat = dict(feature_items.get(chain_id, {}) or {})
        sink_fn = str((feat.get("sink", {}) or {}).get("function", "") or "")
        root_family = str((feat.get("root", {}) or {}).get("family", "") or "")
        verdict_bucket = str(feat.get("current_verdict", "") or "")
        bucket_key = (sink_fn, root_family, verdict_bucket)
        if sink_fn and bucket_key not in seen_functions:
            selected.append(dict(item))
            seen.add(chain_id)
            seen_functions.add(bucket_key)
            if len(selected) >= max_items:
                return selected

    for item in ordered:
        chain_id = str(item.get("chain_id", "") or "")
        if chain_id in seen:
            continue
        selected.append(dict(item))
        seen.add(chain_id)
        if len(selected) >= max_items:
            break
    return selected
