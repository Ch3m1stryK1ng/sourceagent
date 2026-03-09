"""Low-confidence sink snapshot and triage queue builder (M9.3)."""

from __future__ import annotations

from typing import Any, Dict, List


def build_low_conf_sinks(chains: List[Dict[str, Any]], *, t_low: float) -> List[Dict[str, Any]]:
    """Project chain-level uncertainty into low_conf_sinks entries."""
    items: List[Dict[str, Any]] = []

    for ch in chains:
        sink = ch.get("sink", {})
        score = float(ch.get("score", 0.0))
        verdict = str(ch.get("verdict", ""))
        status = str(ch.get("status", ""))
        reasons = []

        if score < t_low:
            reasons.append("score_below_t_low")
        if status != "ok":
            reasons.append(f"status_{status}")
        if verdict in {"SUSPICIOUS", "DROP"}:
            reasons.append(f"verdict_{verdict.lower()}")

        if not reasons:
            continue

        items.append({
            "sink_id": sink.get("sink_id", ""),
            "sink_label": sink.get("label", ""),
            "sink_function": sink.get("function", ""),
            "sink_site": str(sink.get("site", "")),
            "root_expr": sink.get("root_expr", "UNKNOWN"),
            "chain_id": ch.get("chain_id", ""),
            "score": score,
            "status": status,
            "verdict": verdict,
            "failure_code": ch.get("failure_code", ""),
            "reasons": reasons,
            "evidence_refs": list(ch.get("evidence_refs", [])),
        })

    return items


def build_triage_queue(items: List[Dict[str, Any]], *, top_k: int) -> List[Dict[str, Any]]:
    """Rank low-confidence items for manual/LLM triage."""
    ranked = []
    for item in items:
        priority = 0.0
        reasons = item.get("reasons", [])
        if "verdict_suspicious" in reasons:
            priority += 0.45
        if "status_partial" in reasons:
            priority += 0.25
        if "score_below_t_low" in reasons:
            priority += 0.15
        failure_code = str(item.get("failure_code", ""))
        if failure_code.startswith("ROOT_"):
            priority += 0.18
        elif failure_code in {"NO_SOURCE_REACH", "SOURCE_NOT_IN_CONTEXT", "PRODUCER_SOURCE_MISS"}:
            priority += 0.15
        elif failure_code in {"OBJECT_HIT_NONE", "OBJECT_HIT_NO_EDGE"}:
            priority += 0.12
        elif failure_code in {"MAX_DEPTH_REACHED", "BUDGET_EXCEEDED"}:
            priority += 0.1
        ranked.append((priority, item))

    ranked.sort(key=lambda x: x[0], reverse=True)
    out = []
    for rank, (priority, item) in enumerate(ranked[: max(0, int(top_k))], start=1):
        e = dict(item)
        e["triage_rank"] = rank
        e["triage_priority"] = round(priority, 4)
        out.append(e)
    return out
