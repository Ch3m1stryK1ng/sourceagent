"""Build semantic-review plans from verdict calibration artifacts."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence

DEFAULT_REVIEW_BATCH_SIZE = 4
DEFAULT_MAX_REVIEW_ITEMS = 8


def build_review_plan(
    feature_pack: Mapping[str, Any],
    calibration_queue: Mapping[str, Any],
    *,
    review_mode: str = "semantic",
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
    if max_items > 0:
        queue_items = queue_items[: int(max_items)]

    work_items: List[Dict[str, Any]] = []
    for idx, q in enumerate(queue_items):
        chain_id = str(q.get("chain_id", "") or "")
        feat = dict(feature_items.get(chain_id, {}) or {})
        work_items.append({
            "plan_rank": idx,
            "chain_id": chain_id,
            "queue_reasons": list(q.get("queue_reasons", []) or []),
            "queue_score": float(q.get("queue_score", feat.get("risk_score", 0.0)) or 0.0),
            "sample_id": feat.get("sample_id", ""),
            "current_verdict": feat.get("current_verdict", "DROP"),
            "soft_verdict": feat.get("soft_verdict", feat.get("current_verdict", "DROP")),
            "risk_score": float(feat.get("risk_score", 0.0) or 0.0),
            "needs_review": bool(feat.get("needs_review", False)),
            "review_state": feat.get("review_state", "non_exact"),
            "audit_flags": list(feat.get("audit_flags", []) or []),
            "sink": dict(feat.get("sink", {}) or {}),
            "root": dict(feat.get("root", {}) or {}),
            "derive_facts": list(feat.get("derive_facts", []) or []),
            "check_facts": list(feat.get("check_facts", []) or []),
            "object_path": list(feat.get("object_path", []) or []),
            "channel_path": list(feat.get("channel_path", []) or []),
            "sink_semantics_hints": dict(feat.get("sink_semantics_hints", {}) or {}),
            "guard_context": list(feat.get("guard_context", []) or []),
            "capacity_evidence": list(feat.get("capacity_evidence", []) or []),
            "chain_segments": list(feat.get("chain_segments", []) or []),
            "deterministic_constraints": dict(feat.get("deterministic_constraints", {}) or {}),
            "decision_basis": dict(feat.get("decision_basis", {}) or {}),
            "decompiled_snippets": dict(feat.get("decompiled_snippets", {}) or {}),
        })

    batches = _batch_items(work_items, batch_size=max(1, int(batch_size or 1)))
    return {
        "schema_version": "0.1",
        "review_mode": str(review_mode or "semantic"),
        "max_items": int(max_items),
        "batch_size": int(batch_size),
        "items": work_items,
        "batches": batches,
        "status": "ok" if work_items else "empty",
    }


def _queue_sort_key(item: Mapping[str, Any]):
    return (
        -float(item.get("queue_score", item.get("risk_score", 0.0)) or 0.0),
        str(item.get("chain_id", "") or ""),
    )


def _batch_items(items: Sequence[Mapping[str, Any]], *, batch_size: int) -> List[Dict[str, Any]]:
    batches: List[Dict[str, Any]] = []
    for idx in range(0, len(items), batch_size):
        batch_items = [dict(v) for v in items[idx: idx + batch_size]]
        batches.append({
            "batch_id": f"batch_{idx // batch_size:03d}",
            "chain_ids": [str(item.get("chain_id", "") or "") for item in batch_items],
            "items": batch_items,
        })
    return batches
