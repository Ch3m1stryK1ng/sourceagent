"""Context ranking and budgeting for semantic review."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence

BASE_PROMPT_BUDGET_CHARS = 35_000
MAX_PROMPT_BUDGET_CHARS = 90_000
MAX_BATCH_PROMPT_CHARS = 140_000

DEFAULT_BUCKET_QUOTAS = {
    "sink_function": 1,
    "guard_context": 2,
    "capacity_context": 2,
    "caller_bridge": 2,
    "object_context": 2,
    "producer_context": 1,
}

EXPANDED_BUCKET_QUOTAS = {
    "sink_function": 1,
    "guard_context": 3,
    "capacity_context": 3,
    "caller_bridge": 3,
    "object_context": 3,
    "producer_context": 2,
}

KEY_CHAR_LIMITS = {
    "sink_function": 12_000,
    "guard_context": 8_000,
    "capacity_context": 8_000,
    "caller_bridge": 8_000,
    "object_context": 8_000,
    "producer_context": 6_000,
    "source_context": 6_000,
    "channel_context": 6_000,
    "derive_context": 6_000,
    "check_context": 6_000,
    "related_functions": 6_000,
}

SECOND_PASS_REASON_CODES = {
    "TRIGGER_UNCERTAIN_MISSING_CAPACITY",
    "HELPER_SEMANTICS_UNKNOWN",
    "CHECK_NOT_BINDING_ROOT",
}

SECOND_PASS_FLAGS = {
    "needs_more_context",
}


def build_review_context_plan(
    item: Mapping[str, Any],
    *,
    expanded: bool = False,
) -> Dict[str, Any]:
    quotas = dict(EXPANDED_BUCKET_QUOTAS if expanded else DEFAULT_BUCKET_QUOTAS)
    focus = _focus_flags(item)

    if focus["source"]:
        quotas["producer_context"] += 1
        quotas["caller_bridge"] += 1
    if focus["capacity"]:
        quotas["capacity_context"] += 1
        quotas["object_context"] += 1
    if focus["guard"]:
        quotas["guard_context"] += 1
    if focus["helper"]:
        quotas["caller_bridge"] += 1

    candidate_map = _candidate_functions_by_bucket(item)
    selected: Dict[str, List[str]] = {}
    score_rows: Dict[str, List[Dict[str, Any]]] = {}
    estimated_chars = 4_000

    for key, rows in candidate_map.items():
        limit = max(0, int(quotas.get(key, 0)))
        ranked = _rank_rows(rows)
        if limit > 0:
            chosen_rows = ranked[:limit]
            selected[key] = [row["function"] for row in chosen_rows]
            score_rows[key] = chosen_rows
            estimated_chars += min(
                KEY_CHAR_LIMITS.get(key, 6_000),
                len(chosen_rows) * max(2_000, KEY_CHAR_LIMITS.get(key, 6_000) // max(1, limit)),
            )
        else:
            selected[key] = []
            score_rows[key] = []

    uncertain_segments = _uncertain_segment_count(item)
    hop_count = len(list(item.get("chain_segments", []) or []))
    prompt_budget = min(
        MAX_PROMPT_BUDGET_CHARS,
        BASE_PROMPT_BUDGET_CHARS + 6_000 * uncertain_segments + 4_000 * hop_count,
    )
    prompt_budget = max(prompt_budget, estimated_chars + 8_000)
    prompt_budget = min(prompt_budget, MAX_PROMPT_BUDGET_CHARS)

    return {
        "version": "1.0",
        "expanded": bool(expanded),
        "focus": [k for k, v in focus.items() if v],
        "quotas": quotas,
        "selected_functions": selected,
        "selection_scores": score_rows,
        "estimated_prompt_chars": int(estimated_chars),
        "prompt_budget_chars": int(prompt_budget),
        "key_char_limits": dict(KEY_CHAR_LIMITS),
    }


def should_request_second_pass(decision: Mapping[str, Any], *, review_priority: str = "", current_verdict: str = "") -> bool:
    reason_codes = {str(v) for v in (decision.get("reason_codes", []) or []) if str(v)}
    flags = {str(v) for v in (decision.get("review_quality_flags", []) or []) if str(v)}
    blocked = {str(v) for v in (decision.get("blocked_by", []) or []) if str(v)}
    item = dict(decision.get("_feature_item", {}) or {})
    if str(review_priority or "") not in {"P0", "P1"}:
        return False
    soft_candidate = bool(item.get("soft_candidate", False))
    if str(current_verdict or "") not in {"SUSPICIOUS", "CONFIRMED"} and not soft_candidate:
        return False
    constraints = dict(item.get("deterministic_constraints", {}) or {})
    if (
        "source_reached" in blocked
        or "source_reached_or_proxy" in blocked
        or (
            not bool(constraints.get("source_reached", False))
            and not bool(constraints.get("source_reached_or_proxy", False))
            and not bool(constraints.get("source_proxy_ok", False))
        )
    ):
        return True
    return bool(reason_codes & SECOND_PASS_REASON_CODES or flags & SECOND_PASS_FLAGS)


def expand_review_context_plan(item: Mapping[str, Any]) -> Dict[str, Any]:
    return build_review_context_plan(item, expanded=True)


def _focus_flags(item: Mapping[str, Any]) -> Dict[str, bool]:
    constraints = dict(item.get("deterministic_constraints", {}) or {})
    current_verdict = str(item.get("current_verdict", "") or "")
    reason = str(item.get("current_verdict_reason", "") or "")
    review_state = str(item.get("review_state", "") or "")
    root_family = str((item.get("root", {}) or {}).get("family", "") or "")

    return {
        "source": (not bool(constraints.get("source_reached_or_proxy", constraints.get("source_reached")))) or bool(constraints.get("source_proxy_ok")),
        "capacity": (not bool(constraints.get("object_bound"))) or root_family in {"length", "index_or_bound"},
        "guard": current_verdict in {"SUSPICIOUS", "SAFE_OR_LOW_RISK"} or reason in {"CHECK_UNCERTAIN", "LOW_CHAIN_SCORE"},
        "helper": review_state == "non_exact" or reason in {"ROOT_WEAK_FALLBACK", "MAX_DEPTH_REACHED"},
    }


def _candidate_functions_by_bucket(item: Mapping[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    sink_fn = str((item.get("sink", {}) or {}).get("function", "") or "")
    snippet_index = dict(item.get("snippet_index", {}) or {})
    chain_segments = list(item.get("chain_segments", []) or [])
    derive_facts = list(item.get("derive_facts", []) or [])
    check_facts = list(item.get("check_facts", []) or [])
    guard_context = list(item.get("guard_context", []) or [])
    capacity_evidence = list(item.get("capacity_evidence", []) or [])
    target_object_extent = dict(item.get("target_object_extent", {}) or {})
    object_path = list(item.get("object_path", []) or [])
    channel_path = list(item.get("channel_path", []) or [])

    buckets: Dict[str, Dict[str, Dict[str, Any]]] = {
        "sink_function": {},
        "guard_context": {},
        "capacity_context": {},
        "caller_bridge": {},
        "object_context": {},
        "producer_context": {},
    }

    def add(bucket: str, fn: Any, score: int, reason: str) -> None:
        name = str(fn or "").strip()
        if not _looks_like_function_name(name):
            return
        row = buckets[bucket].setdefault(name, {"function": name, "score": 0, "reasons": []})
        row["score"] += int(score)
        if reason not in row["reasons"]:
            row["reasons"].append(reason)

    add("sink_function", sink_fn, 100, "sink_anchor")

    for fn in snippet_index.get("caller_bridge", []) or []:
        add("caller_bridge", fn, 16, "caller_bridge")
    for fn in snippet_index.get("producer_function", []) or []:
        add("producer_context", fn, 16, "producer_function")
    for fn in snippet_index.get("source_context", []) or []:
        add("producer_context", fn, 15, "source_context")

    for row in chain_segments:
        src = dict(row.get("src", {}) or {})
        dst = dict(row.get("dst", {}) or {})
        kind = str(row.get("kind", "") or "")
        for key in ("function", "sink_function"):
            fn = src.get(key)
            if kind in {"SOURCE_TO_OBJECT", "SOURCE_TO_SINK"}:
                add("producer_context", fn, 14, f"segment:{kind}:src")
            else:
                add("caller_bridge", fn, 8, f"segment:{kind}:src")
            add("object_context", fn, 4, f"segment:{kind}:src")
            fn2 = dst.get(key)
            add("caller_bridge", fn2, 10, f"segment:{kind}:dst")
            add("object_context", fn2, 5, f"segment:{kind}:dst")

    for row in derive_facts:
        add("caller_bridge", row.get("site"), 12, "derive_fact")
    for row in check_facts:
        add("guard_context", row.get("site"), 16, "check_fact")
        add("caller_bridge", row.get("site"), 8, "check_fact")
    for row in guard_context:
        add("guard_context", row.get("site"), 18, "guard_context")
        add("capacity_context", row.get("site"), 10, "guard_capacity")

    for row in capacity_evidence:
        add("capacity_context", row.get("site"), 20, "capacity_evidence")
        expr = str(row.get("expr", "") or "")
        for token in (expr.split("::")[0], expr.split("(")[0]):
            add("capacity_context", token, 6, "capacity_expr_token")

    add("capacity_context", target_object_extent.get("sink_function"), 12, "target_extent")

    for obj in object_path:
        for fn in list((obj or {}).get("writers", []) or []):
            add("object_context", fn, 14, "object_writer")
            add("capacity_context", fn, 6, "object_writer")
        for fn in list((obj or {}).get("readers", []) or []):
            add("object_context", fn, 8, "object_reader")
        type_facts = dict((obj or {}).get("type_facts", {}) or {})
        if any(k in type_facts for k in ("capacity", "capacity_expr", "buffer_size", "elem_count", "element_size", "byte_size", "array_len")):
            for fn in list((obj or {}).get("writers", []) or []):
                add("capacity_context", fn, 8, "object_type_fact")

    for edge in channel_path:
        add("producer_context", edge.get("producer_function"), 12, "channel_producer")
        add("caller_bridge", edge.get("consumer_function"), 8, "channel_consumer")

    if sink_fn:
        add("guard_context", sink_fn, 6, "sink_local_guard")
        add("capacity_context", sink_fn, 6, "sink_local_capacity")
        add("caller_bridge", sink_fn, 4, "sink_local")

    return {key: list(rows.values()) for key, rows in buckets.items()}


def _rank_rows(rows: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    ranked = [dict(row) for row in rows if str(row.get("function", "") or "")]
    ranked.sort(key=lambda row: (-int(row.get("score", 0) or 0), str(row.get("function", ""))))
    return ranked


def _uncertain_segment_count(item: Mapping[str, Any]) -> int:
    count = 0
    for row in list(item.get("chain_segments", []) or []):
        facts = list(row.get("facts", []) or [])
        if any(str(f).endswith("unknown") or str(f) in {"dominance_unknown"} for f in facts):
            count += 1
    count += len(list(item.get("audit_flags", []) or [])) // 2
    return max(1, count)


def _looks_like_function_name(value: Any) -> bool:
    s = str(value or "").strip()
    if not s:
        return False
    lowered = s.lower()
    if lowered in {"unknown", "root", "check_expr", "derive_expr", "sink_function", "caller_bridge", "producer_function"}:
        return False
    if s.startswith("0x"):
        return False
    if any(ch.isspace() for ch in s):
        return False
    if any(ch in s for ch in "(){}[];,"):
        return False
    return True
