"""Phase A.5 bounded supervision queue builder."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Set, Tuple


DEFAULT_MAX_SUPERVISION_ITEMS = 8
DEFAULT_SUPERVISION_SCOPE = "sinks"
SUPPORTED_SUPERVISION_SCOPES = {"sinks", "sources", "objects", "channels", "all"}

_SINK_LABELS = {
    "COPY_SINK",
    "MEMSET_SINK",
    "STORE_SINK",
    "LOOP_WRITE_SINK",
    "FORMAT_STRING_SINK",
    "FUNC_PTR_SINK",
}
_SOURCE_LABELS = {
    "MMIO_READ",
    "ISR_MMIO_READ",
    "ISR_FILLED_BUFFER",
    "DMA_BACKED_BUFFER",
}
_OBJECT_LABELS = {
    "SRAM_CLUSTER",
    "DMA_BUFFER",
    "FLAG",
    "QUEUE_OBJECT",
    "RING_BUFFER",
    "GLOBAL_SYMBOL",
    "RODATA_TABLE",
}
_CHANNEL_LABELS = {
    "DATA",
    "ISR_SHARED_CHANNEL",
    "DMA_CHANNEL",
    "QUEUE_CHANNEL",
    "RING_BUFFER_CHANNEL",
}

_SCOPE_DEFAULT_QUOTAS = {
    "sinks": 3,
    "sources": 1,
    "channels": 2,
    "objects": 2,
}


def build_supervision_queue(
    *,
    binary_name: str,
    binary_sha256: str,
    low_conf_sinks: Sequence[Mapping[str, Any]],
    triage_queue: Sequence[Mapping[str, Any]],
    feature_pack: Mapping[str, Any],
    verified_sinks: Sequence[Mapping[str, Any]],
    sink_facts_by_pack: Mapping[str, Mapping[str, Any]],
    verified_sources: Sequence[Mapping[str, Any]] | None = None,
    source_candidates: Sequence[Mapping[str, Any]] | None = None,
    sink_candidates: Sequence[Mapping[str, Any]] | None = None,
    sink_evidence_packs: Sequence[Mapping[str, Any]] | None = None,
    decompiled_cache: Mapping[str, str] | None = None,
    channel_graph: Mapping[str, Any] | None = None,
    refined_objects: Mapping[str, Any] | None = None,
    max_items: int = DEFAULT_MAX_SUPERVISION_ITEMS,
    scope: str = DEFAULT_SUPERVISION_SCOPE,
) -> Dict[str, Any]:
    scope_set = _parse_scope(scope)
    if not scope_set:
        return {
            "schema_version": "0.2",
            "binary": binary_name,
            "binary_sha256": binary_sha256,
            "scope": str(scope or DEFAULT_SUPERVISION_SCOPE),
            "status": "unsupported_scope",
            "items": [],
        }

    triage_by_chain = {
        str(item.get("chain_id", "") or ""): dict(item)
        for item in triage_queue or []
        if str(item.get("chain_id", "") or "")
    }
    feature_by_chain = {
        str(item.get("chain_id", "") or ""): dict(item)
        for item in (feature_pack or {}).get("items", []) or []
        if str(item.get("chain_id", "") or "")
    }
    feature_by_pack = {}
    for item in (feature_pack or {}).get("items", []) or []:
        feature_row = dict(item or {})
        pack_id = str(feature_row.get("pack_id", "") or "")
        if not pack_id:
            sink = dict(feature_row.get("sink", {}) or {})
            pack_id = str(sink.get("pack_id", "") or "")
        if pack_id and pack_id not in feature_by_pack:
            feature_by_pack[pack_id] = feature_row
    items_by_scope: Dict[str, List[Dict[str, Any]]] = {}

    if "sinks" in scope_set:
        stage_sink_items = _build_sink_items(
            low_conf_sinks=low_conf_sinks,
            triage_by_chain=triage_by_chain,
            feature_by_chain=feature_by_chain,
            verified_sinks=verified_sinks,
            sink_facts_by_pack=sink_facts_by_pack,
        )
        raw_sink_items = _build_raw_sink_items(
            sink_candidates=sink_candidates or [],
            sink_evidence_packs=sink_evidence_packs or [],
            verified_sinks=verified_sinks,
            sink_facts_by_pack=sink_facts_by_pack,
            feature_by_pack=feature_by_pack,
            decompiled_cache=decompiled_cache or {},
        )
        items_by_scope["sinks"] = _merge_sink_item_sets(stage_sink_items, raw_sink_items)
    if "sources" in scope_set:
        items_by_scope["sources"] = _build_source_items(
            verified_sources=verified_sources or [],
            source_candidates=source_candidates or [],
            decompiled_cache=decompiled_cache or {},
        )
    if "objects" in scope_set:
        items_by_scope["objects"] = _build_object_items(
            refined_objects=refined_objects or {},
            channel_graph=channel_graph or {},
            decompiled_cache=decompiled_cache or {},
        )
    if "channels" in scope_set:
        items_by_scope["channels"] = _build_channel_items(
            channel_graph=channel_graph or {},
            refined_objects=refined_objects or {},
            decompiled_cache=decompiled_cache or {},
        )

    items = _apply_scope_quotas(items_by_scope, max_items=max_items)
    for rank, item in enumerate(items, start=1):
        item["supervision_rank"] = rank

    return {
        "schema_version": "0.2",
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "scope": str(scope or DEFAULT_SUPERVISION_SCOPE),
        "scope_set": sorted(scope_set),
        "status": "ok" if items else "empty",
        "items": items,
        "stats": {
            "count": len(items),
            "by_kind": _count_by_kind(items),
        },
    }


def _parse_scope(scope: str) -> Set[str]:
    raw = str(scope or DEFAULT_SUPERVISION_SCOPE).strip().lower()
    if not raw:
        raw = DEFAULT_SUPERVISION_SCOPE
    if raw == "all":
        return {"sinks", "sources", "objects", "channels"}
    parts = {part.strip() for part in raw.split(",") if part.strip()}
    if not parts:
        parts = {DEFAULT_SUPERVISION_SCOPE}
    if not parts.issubset(SUPPORTED_SUPERVISION_SCOPES):
        return set()
    return parts


def _build_sink_items(
    *,
    low_conf_sinks: Sequence[Mapping[str, Any]],
    triage_by_chain: Mapping[str, Mapping[str, Any]],
    feature_by_chain: Mapping[str, Mapping[str, Any]],
    verified_sinks: Sequence[Mapping[str, Any]],
    sink_facts_by_pack: Mapping[str, Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    verified_by_pack = {
        str(item.get("pack_id", "") or ""): dict(item)
        for item in verified_sinks or []
        if str(item.get("pack_id", "") or "")
    }

    grouped: Dict[str, Dict[str, Any]] = {}
    for raw in low_conf_sinks or []:
        item = dict(raw)
        chain_id = str(item.get("chain_id", "") or "")
        if not chain_id:
            continue
        feat = dict(feature_by_chain.get(chain_id, {}) or {})
        sink = dict(feat.get("sink", {}) or {})
        sink_id = str(item.get("sink_id", "") or sink.get("sink_id", "") or chain_id)
        pack_id = str(sink.get("pack_id", "") or "")
        key = f"{sink_id}|{pack_id or chain_id}"
        grouped.setdefault(key, {
            "sink_id": sink_id,
            "chain_ids": [],
            "triage_rank": 999999,
            "triage_priority": 0.0,
            "queue_score": 0.0,
            "reasons": set(),
            "feature": feat,
            "pack_id": pack_id,
            "sink": sink,
        })
        g = grouped[key]
        g["chain_ids"].append(chain_id)
        tri = triage_by_chain.get(chain_id, {})
        if tri:
            g["triage_rank"] = min(int(tri.get("triage_rank", g["triage_rank"]) or g["triage_rank"]), g["triage_rank"])
            g["triage_priority"] = max(float(tri.get("triage_priority", 0.0) or 0.0), g["triage_priority"])
        g["queue_score"] = max(float(item.get("score", 0.0) or 0.0), g["queue_score"])
        g["reasons"].update(str(v) for v in (item.get("reasons", []) or []) if str(v))

    items: List[Dict[str, Any]] = []
    for grouped_item in grouped.values():
        feat = dict(grouped_item.get("feature", {}) or {})
        sink = dict(grouped_item.get("sink", {}) or {})
        pack_id = str(grouped_item.get("pack_id", "") or "")
        verified = dict(verified_by_pack.get(pack_id, {}) or {})
        sink_facts = dict(sink_facts_by_pack.get(pack_id, {}) or {})
        snippets = dict(feat.get("decompiled_snippets", {}) or {})
        sink_fn = str((sink or {}).get("function", "") or verified.get("function_name", "") or "")
        sink_site = str((sink or {}).get("site", "") or "")
        proposed_label = str((sink or {}).get("label", "") or verified.get("label", "") or "")
        fallback_chain_id = next(iter(grouped_item.get("chain_ids", []) or []), "")
        unique_anchor = str(grouped_item.get("sink_id", "") or pack_id or fallback_chain_id or sink_site or sink_fn or "unknown")
        item_id = f"sink:{unique_anchor}:{sink_site or sink_fn or 'unknown'}:{proposed_label}"
        snippet_keys = [key for key, val in snippets.items() if str(val or "").strip()]
        items.append({
            "item_id": item_id,
            "item_kind": "sink",
            "scope": "sinks",
            "sink_id": str(grouped_item.get("sink_id", "") or ""),
            "proposed_label": proposed_label,
            "allowed_labels": sorted(_SINK_LABELS),
            "related_chain_ids": sorted({str(v) for v in grouped_item.get("chain_ids", []) if str(v)}),
            "decision": "not_reviewed",
            "confidence": float(verified.get("confidence", grouped_item.get("queue_score", 0.0)) or 0.0),
            "why_suspicious": sorted(grouped_item.get("reasons", set())),
            "triage_rank": int(grouped_item.get("triage_rank", 999999) or 999999),
            "triage_priority": float(grouped_item.get("triage_priority", 0.0) or 0.0),
            "context": {
                "function": sink_fn,
                "address": sink_site,
                "pack_id": pack_id,
                "root_families": sorted({
                    str((feature_by_chain.get(cid, {}).get("root", {}) or {}).get("family", "") or "")
                    for cid in grouped_item.get("chain_ids", [])
                    if str((feature_by_chain.get(cid, {}).get("root", {}) or {}).get("family", "") or "")
                }),
            },
            "evidence_pack": {
                "decompiled_snippets": snippets,
                "available_snippet_keys": snippet_keys,
                "sink_semantics_hints": dict(feat.get("sink_semantics_hints", {}) or {}),
                "guard_context": list(feat.get("guard_context", []) or []),
                "capacity_evidence": list(feat.get("capacity_evidence", []) or []),
                "decision_basis": dict(feat.get("decision_basis", {}) or {}),
                "sink_facts": sink_facts,
                "evidence_refs": list(verified.get("evidence_refs", []) or []),
            },
            "constraints": {
                "allowed_outputs": ["accept", "reject", "uncertain"],
                "allowed_labels": sorted(_SINK_LABELS),
                "must_quote_evidence": True,
                "must_not_add_new_labels": True,
            },
        })
    items.sort(key=_item_sort_key)
    return items


def _build_raw_sink_items(
    *,
    sink_candidates: Sequence[Mapping[str, Any]],
    sink_evidence_packs: Sequence[Mapping[str, Any]],
    verified_sinks: Sequence[Mapping[str, Any]],
    sink_facts_by_pack: Mapping[str, Mapping[str, Any]],
    feature_by_pack: Mapping[str, Mapping[str, Any]],
    decompiled_cache: Mapping[str, str],
) -> List[Dict[str, Any]]:
    verified_by_pack = {
        str(item.get("pack_id", "") or ""): dict(item)
        for item in verified_sinks or []
        if str(item.get("pack_id", "") or "")
    }
    verified_by_site = {
        (
            _hex_addr(item.get("address", 0)),
            str(item.get("function_name", "") or ""),
        ): dict(item)
        for item in verified_sinks or []
        if str(item.get("function_name", "") or "") or int(item.get("address", 0) or 0)
    }
    candidates_by_site_label = defaultdict(list)
    candidates_by_site = defaultdict(list)
    for raw in sink_candidates or []:
        candidate = dict(raw or {})
        label = str(candidate.get("preliminary_label", "") or candidate.get("label", "") or "")
        site_key = (_hex_addr(candidate.get("address", 0)), str(candidate.get("function_name", "") or ""))
        candidates_by_site_label[(site_key[0], site_key[1], label)].append(candidate)
        candidates_by_site[site_key].append(candidate)

    items: List[Dict[str, Any]] = []
    covered_site_keys = set()
    for raw in sink_evidence_packs or []:
        pack = dict(raw or {})
        pack_id = str(pack.get("pack_id", "") or "")
        label = str(pack.get("candidate_hint", "") or "")
        address = int(pack.get("address", 0) or 0)
        function_name = str(pack.get("function_name", "") or "")
        site_hex = _hex_addr(address)
        site_key = (site_hex, function_name)
        covered_site_keys.add(site_key)

        candidates = list(candidates_by_site_label.get((site_hex, function_name, label), []) or [])
        if not candidates:
            candidates = list(candidates_by_site.get(site_key, []) or [])
        candidate = _best_sink_candidate(candidates)
        verified = dict(
            verified_by_pack.get(pack_id, {}) or verified_by_site.get(site_key, {}) or {}
        )
        feature = dict(feature_by_pack.get(pack_id, {}) or {})
        sink_facts = dict(sink_facts_by_pack.get(pack_id, {}) or pack.get("facts", {}) or {})
        if candidate:
            sink_facts.update(dict(candidate.get("facts", {}) or {}))
        item = _make_raw_sink_item(
            pack_id=pack_id,
            label=(str(verified.get("label", "") or "") or label or str((candidate or {}).get("preliminary_label", "") or "")),
            address=address,
            function_name=function_name,
            candidate=candidate,
            verified=verified,
            feature=feature,
            sink_facts=sink_facts,
            pack=pack,
            decompiled_cache=decompiled_cache,
        )
        if item is not None:
            items.append(item)

    for raw in sink_candidates or []:
        candidate = dict(raw or {})
        address = int(candidate.get("address", 0) or 0)
        function_name = str(candidate.get("function_name", "") or "")
        site_key = (_hex_addr(address), function_name)
        if site_key in covered_site_keys:
            continue
        label = str(candidate.get("preliminary_label", "") or candidate.get("label", "") or "")
        verified = dict(verified_by_site.get(site_key, {}) or {})
        item = _make_raw_sink_item(
            pack_id="",
            label=(str(verified.get("label", "") or "") or label),
            address=address,
            function_name=function_name,
            candidate=candidate,
            verified=verified,
            feature={},
            sink_facts=dict(candidate.get("facts", {}) or {}),
            pack={},
            decompiled_cache=decompiled_cache,
        )
        if item is not None:
            items.append(item)

    items.sort(key=_item_sort_key)
    return items


def _best_sink_candidate(candidates: Sequence[Mapping[str, Any]]) -> Dict[str, Any] | None:
    best: Dict[str, Any] | None = None
    best_score = -1.0
    for raw in candidates or []:
        candidate = dict(raw or {})
        score = float(candidate.get("confidence_score", 0.0) or 0.0)
        if score > best_score:
            best = candidate
            best_score = score
    return best


def _make_raw_sink_item(
    *,
    pack_id: str,
    label: str,
    address: int,
    function_name: str,
    candidate: Mapping[str, Any] | None,
    verified: Mapping[str, Any],
    feature: Mapping[str, Any],
    sink_facts: Mapping[str, Any],
    pack: Mapping[str, Any],
    decompiled_cache: Mapping[str, str],
) -> Dict[str, Any] | None:
    if label not in _SINK_LABELS:
        return None
    site_hex = _hex_addr(address)
    snippets = dict((feature or {}).get("decompiled_snippets", {}) or {})
    if not snippets:
        fallback = str((decompiled_cache or {}).get(function_name, "") or "")
        if fallback.strip():
            snippets = {"sink_function": fallback}

    candidate = dict(candidate or {})
    feature = dict(feature or {})
    verified = dict(verified or {})
    pack = dict(pack or {})
    sink_facts = dict(sink_facts or {})
    why = []
    if not feature:
        why.append("no_chain_feature_pack")
    if not verified:
        why.append("unverified_sink_candidate")
    elif float(verified.get("confidence", 0.0) or 0.0) < 0.8:
        why.append("low_confidence_verified_sink")
    if candidate and float(candidate.get("confidence_score", 0.0) or 0.0) < 0.8:
        why.append("low_confidence_sink_candidate")
    if not sink_facts:
        why.append("weak_sink_facts")

    item_id = f"sink:{pack_id or _raw_sink_anchor(site_hex, function_name)}:{site_hex}:{label}"
    candidate_evidence = _evidence_texts(candidate.get("evidence", []) or pack.get("evidence", []) or [])
    evidence_refs = _evidence_ids(candidate.get("evidence", []) or pack.get("evidence", []) or [])
    if verified.get("evidence_refs"):
        evidence_refs = _uniq(evidence_refs, verified.get("evidence_refs", []) or [])
    priority = max(
        float(candidate.get("confidence_score", 0.0) or 0.0),
        float(verified.get("confidence", 0.0) or 0.0),
        float(feature.get("risk_score", 0.0) or 0.0),
    )
    triage_rank = 0 if not feature else 200000
    if verified:
        triage_rank = min(triage_rank, 150000)

    return {
        "item_id": item_id,
        "item_kind": "sink",
        "scope": "sinks",
        "sink_id": pack_id or _raw_sink_anchor(site_hex, function_name),
        "proposed_label": label,
        "allowed_labels": sorted(_SINK_LABELS),
        "related_chain_ids": [],
        "decision": "not_reviewed",
        "confidence": max(
            float(verified.get("confidence", 0.0) or 0.0),
            float(candidate.get("confidence_score", 0.0) or 0.0),
        ),
        "why_suspicious": why,
        "triage_rank": triage_rank,
        "triage_priority": priority,
        "context": {
            "function": function_name,
            "address": site_hex,
            "pack_id": pack_id,
            "root_families": sorted({
                str((feature.get("root", {}) or {}).get("family", "") or "")
            } - {""}),
        },
        "evidence_pack": {
            "decompiled_snippets": snippets,
            "available_snippet_keys": [key for key, val in snippets.items() if str(val or "").strip()],
            "sink_semantics_hints": dict(feature.get("sink_semantics_hints", {}) or _raw_sink_semantics_hints(label, sink_facts)),
            "guard_context": list(feature.get("guard_context", []) or []),
            "capacity_evidence": list(feature.get("capacity_evidence", []) or []),
            "decision_basis": dict(feature.get("decision_basis", {}) or {}),
            "sink_facts": sink_facts,
            "candidate_evidence": candidate_evidence[:8],
            "evidence_refs": evidence_refs,
            "candidate_hint": str(pack.get("candidate_hint", "") or candidate.get("preliminary_label", "") or ""),
        },
        "constraints": {
            "allowed_outputs": ["accept", "reject", "uncertain"],
            "allowed_labels": sorted(_SINK_LABELS),
            "must_quote_evidence": True,
            "must_not_add_new_labels": True,
        },
    }


def _merge_sink_item_sets(
    primary_items: Sequence[Mapping[str, Any]],
    extra_items: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for raw in list(primary_items or []) + list(extra_items or []):
        item = dict(raw or {})
        key = _sink_item_merge_key(item)
        if key not in merged:
            merged[key] = item
            order.append(key)
            continue
        merged[key] = _merge_sink_items(merged[key], item)
    rows = [merged[key] for key in order]
    rows.sort(key=_item_sort_key)
    return rows


def _sink_item_merge_key(item: Mapping[str, Any]) -> str:
    context = dict(item.get("context", {}) or {})
    pack_id = str(context.get("pack_id", "") or "")
    if pack_id:
        return f"pack:{pack_id}"
    return (
        f"site:{str(context.get('address', '') or '')}|"
        f"{str(context.get('function', '') or '')}"
    ) or str(item.get("item_id", "") or "")


def _merge_sink_items(base: Mapping[str, Any], extra: Mapping[str, Any]) -> Dict[str, Any]:
    out = dict(base or {})
    context = dict(out.get("context", {}) or {})
    new_context = dict(extra.get("context", {}) or {})
    root_families = _uniq(context.get("root_families", []) or [], new_context.get("root_families", []) or [])
    context.update({k: v for k, v in new_context.items() if v not in (None, "", [], {})})
    context["root_families"] = root_families
    out["context"] = context

    out["related_chain_ids"] = _uniq(
        out.get("related_chain_ids", []) or [],
        extra.get("related_chain_ids", []) or [],
    )
    out["confidence"] = max(float(out.get("confidence", 0.0) or 0.0), float(extra.get("confidence", 0.0) or 0.0))
    out["why_suspicious"] = _uniq(
        out.get("why_suspicious", []) or [],
        extra.get("why_suspicious", []) or [],
    )
    out["triage_rank"] = min(int(out.get("triage_rank", 999999) or 999999), int(extra.get("triage_rank", 999999) or 999999))
    out["triage_priority"] = max(
        float(out.get("triage_priority", 0.0) or 0.0),
        float(extra.get("triage_priority", 0.0) or 0.0),
    )
    if not str(out.get("proposed_label", "") or ""):
        out["proposed_label"] = str(extra.get("proposed_label", "") or "")

    evidence_pack = dict(out.get("evidence_pack", {}) or {})
    new_pack = dict(extra.get("evidence_pack", {}) or {})
    snippets = dict(evidence_pack.get("decompiled_snippets", {}) or {})
    snippets.update({k: v for k, v in (new_pack.get("decompiled_snippets", {}) or {}).items() if str(v or "").strip()})
    sink_hints = dict(evidence_pack.get("sink_semantics_hints", {}) or {})
    sink_hints.update(dict(new_pack.get("sink_semantics_hints", {}) or {}))
    sink_facts = dict(evidence_pack.get("sink_facts", {}) or {})
    sink_facts.update(dict(new_pack.get("sink_facts", {}) or {}))
    decision_basis = dict(evidence_pack.get("decision_basis", {}) or {})
    decision_basis.update(dict(new_pack.get("decision_basis", {}) or {}))
    evidence_pack.update({
        "decompiled_snippets": snippets,
        "available_snippet_keys": _uniq(
            evidence_pack.get("available_snippet_keys", []) or [],
            new_pack.get("available_snippet_keys", []) or [],
        ),
        "sink_semantics_hints": sink_hints,
        "guard_context": _uniq_rows(
            evidence_pack.get("guard_context", []) or [],
            new_pack.get("guard_context", []) or [],
        ),
        "capacity_evidence": _uniq_rows(
            evidence_pack.get("capacity_evidence", []) or [],
            new_pack.get("capacity_evidence", []) or [],
        ),
        "decision_basis": decision_basis,
        "sink_facts": sink_facts,
        "evidence_refs": _uniq(
            evidence_pack.get("evidence_refs", []) or [],
            new_pack.get("evidence_refs", []) or [],
        ),
        "candidate_evidence": _uniq(
            evidence_pack.get("candidate_evidence", []) or [],
            new_pack.get("candidate_evidence", []) or [],
        ),
    })
    out["evidence_pack"] = evidence_pack
    return out


def _raw_sink_anchor(site_hex: str, function_name: str) -> str:
    return f"{function_name or 'unknown'}@{site_hex or '0x00000000'}"


def _raw_sink_semantics_hints(label: str, sink_facts: Mapping[str, Any]) -> Dict[str, Any]:
    sink_facts = dict(sink_facts or {})
    if label == "COPY_SINK":
        return _pick_sink_fact_hints(sink_facts, ("len_expr", "dst_expr", "src_expr", "guard_expr"))
    if label == "MEMSET_SINK":
        return _pick_sink_fact_hints(sink_facts, ("len_expr", "dst_expr", "guard_expr"))
    if label == "STORE_SINK":
        return _pick_sink_fact_hints(sink_facts, ("dst_expr", "target_expr", "offset_expr", "base_expr"))
    if label == "LOOP_WRITE_SINK":
        return _pick_sink_fact_hints(sink_facts, ("loop_bound", "bound_expr", "index_expr", "dst_expr"))
    if label == "FORMAT_STRING_SINK":
        return _pick_sink_fact_hints(sink_facts, ("format_arg_expr", "format_arg_is_variable"))
    if label == "FUNC_PTR_SINK":
        return _pick_sink_fact_hints(sink_facts, ("dispatch_index", "target_ptr", "func_ptr_expr"))
    return {}


def _pick_sink_fact_hints(sink_facts: Mapping[str, Any], keys: Sequence[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key in keys:
        value = sink_facts.get(key)
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        out[key] = value
    return out


def _evidence_texts(rows: Sequence[Mapping[str, Any]]) -> List[str]:
    out = []
    for row in rows or []:
        text = str((row or {}).get("text", "") or "").strip()
        if text:
            out.append(text)
    return out


def _evidence_ids(rows: Sequence[Mapping[str, Any]]) -> List[str]:
    out = []
    for row in rows or []:
        evidence_id = str((row or {}).get("evidence_id", "") or "").strip()
        if evidence_id:
            out.append(evidence_id)
    return out


def _build_source_items(
    *,
    verified_sources: Sequence[Mapping[str, Any]],
    source_candidates: Sequence[Mapping[str, Any]],
    decompiled_cache: Mapping[str, str],
) -> List[Dict[str, Any]]:
    verified_index = {
        (
            str(item.get("label", "") or ""),
            int(item.get("address", 0) or 0),
            str(item.get("function_name", "") or ""),
        ): dict(item)
        for item in verified_sources or []
    }
    candidate_rows: List[Dict[str, Any]] = []
    for cand in source_candidates or []:
        label = str(cand.get("preliminary_label", "") or cand.get("label", "") or "")
        addr = int(cand.get("address", 0) or 0)
        fn = str(cand.get("function_name", "") or "")
        key = (label, addr, fn)
        verified = dict(verified_index.get(key, {}) or {})
        facts = dict(cand.get("facts", {}) or {})
        snippets = _snippets_for_functions(decompiled_cache, [fn])
        evidence = [str((row or {}).get("text", "") or "") for row in cand.get("evidence", []) or [] if str((row or {}).get("text", "") or "").strip()]
        why = []
        if verified:
            if float(verified.get("confidence", 0.0) or 0.0) < 0.8:
                why.append("low_confidence_verified_source")
        else:
            why.append("unverified_source_candidate")
        if facts.get("wrapper_like"):
            why.append("wrapper_like_source")
        if facts.get("dma_like"):
            why.append("dma_like_source")
        if facts.get("shared_buffer_like"):
            why.append("shared_buffer_like_source")
        candidate_rows.append({
            "item_id": f"source:{label}:{addr:08x}:{fn or 'unknown'}",
            "item_kind": "source",
            "scope": "sources",
            "proposed_label": label,
            "allowed_labels": sorted(_SOURCE_LABELS),
            "decision": "not_reviewed",
            "confidence": float(verified.get("confidence", cand.get("confidence_score", 0.0)) or 0.0),
            "why_suspicious": why,
            "triage_rank": 500000,
            "triage_priority": float(cand.get("confidence_score", 0.0) or 0.0),
            "context": {
                "function": fn,
                "address": _hex_addr(addr),
                "in_isr": bool(facts.get("in_isr") or "irq" in fn.lower()),
                "target_addr": _hex_addr(facts.get("target_addr", 0)),
            },
            "evidence_pack": {
                "decompiled_snippets": snippets,
                "available_snippet_keys": [k for k, v in snippets.items() if str(v).strip()],
                "source_facts": facts,
                "candidate_evidence": evidence[:8],
                "evidence_refs": list(verified.get("evidence_refs", []) or []),
            },
            "constraints": {
                "allowed_outputs": ["accept", "reject", "uncertain"],
                "allowed_labels": sorted(_SOURCE_LABELS),
                "must_quote_evidence": True,
                "must_not_add_new_labels": True,
            },
        })
    candidate_rows.sort(key=_item_sort_key)
    return candidate_rows


def _build_object_items(
    *,
    refined_objects: Mapping[str, Any],
    channel_graph: Mapping[str, Any],
    decompiled_cache: Mapping[str, str],
) -> List[Dict[str, Any]]:
    object_rows = list((refined_objects or {}).get("objects", []) or (channel_graph or {}).get("object_nodes", []) or [])
    items: List[Dict[str, Any]] = []
    for obj in object_rows:
        region_kind = str(obj.get("region_kind", "") or "")
        confidence = float(obj.get("confidence", 0.0) or 0.0)
        type_facts = dict(obj.get("type_facts", {}) or {})
        writers = list(obj.get("writers", []) or [])
        readers = list(obj.get("readers", []) or [])
        interesting_object = (
            _looks_ring_buffer_object(obj)
            or region_kind in {"FLAG", "DMA_BUFFER", "QUEUE_OBJECT", "RING_BUFFER", "GLOBAL_SYMBOL"}
            or bool(writers and readers)
            or bool(type_facts)
        )
        if confidence >= 0.85 and str(type_facts.get("refine_status", "") or "") == "refined" and not interesting_object:
            continue
        func_names = [str(v) for v in (writers[:2] + readers[:2]) if str(v)]
        snippets = _snippets_for_functions(decompiled_cache, func_names)
        why = ["low_confidence_object"] if confidence < 0.85 else []
        if _looks_ring_buffer_object(obj):
            why.append("ring_buffer_candidate")
        if region_kind == "FLAG":
            why.append("flag_like_object")
        items.append({
            "item_id": f"object:{str(obj.get('object_id', '') or 'unknown')}",
            "item_kind": "object",
            "scope": "objects",
            "proposed_label": region_kind or "SRAM_CLUSTER",
            "allowed_labels": sorted(_OBJECT_LABELS),
            "decision": "not_reviewed",
            "confidence": confidence,
            "why_suspicious": why,
            "triage_rank": 700000,
            "triage_priority": confidence,
            "context": {
                "object_id": str(obj.get("object_id", "") or ""),
                "region_kind": region_kind,
                "addr_range": list(obj.get("addr_range", []) or []),
                "producer_contexts": list(obj.get("producer_contexts", []) or []),
                "consumer_contexts": list(obj.get("consumer_contexts", []) or []),
            },
            "evidence_pack": {
                "decompiled_snippets": snippets,
                "available_snippet_keys": [k for k, v in snippets.items() if str(v).strip()],
                "members": list(obj.get("members", []) or []),
                "writers": writers,
                "readers": readers,
                "type_facts": type_facts,
                "writer_sites": list(obj.get("writer_sites", []) or [])[:6],
                "reader_sites": list(obj.get("reader_sites", []) or [])[:6],
            },
            "constraints": {
                "allowed_outputs": ["accept", "reject", "uncertain"],
                "allowed_labels": sorted(_OBJECT_LABELS),
                "must_quote_evidence": True,
                "must_not_add_new_labels": True,
            },
        })
    items.sort(key=_item_sort_key)
    return items


def _build_channel_items(
    *,
    channel_graph: Mapping[str, Any],
    refined_objects: Mapping[str, Any],
    decompiled_cache: Mapping[str, str],
) -> List[Dict[str, Any]]:
    objects_by_id = {
        str(obj.get("object_id", "") or ""): dict(obj)
        for obj in (refined_objects or {}).get("objects", []) or (channel_graph or {}).get("object_nodes", []) or []
        if str(obj.get("object_id", "") or "")
    }
    items: List[Dict[str, Any]] = []
    for edge in (channel_graph or {}).get("channel_edges", []) or []:
        object_id = str(edge.get("object_id", "") or "")
        obj = dict(objects_by_id.get(object_id, {}) or {})
        score = float(edge.get("score", 0.0) or 0.0)
        src_ctx = str(edge.get("src_context", "") or "UNKNOWN")
        dst_ctx = str(edge.get("dst_context", "") or "UNKNOWN")
        if (
            score >= 0.95
            and not _looks_ring_buffer_object(obj)
            and src_ctx != "UNKNOWN"
            and dst_ctx != "UNKNOWN"
            and edge.get("constraints")
        ):
            continue
        funcs = []
        for site in (obj.get("writer_sites", []) or [])[:2]:
            fn = str((site or {}).get("fn", "") or "")
            if fn:
                funcs.append(fn)
        for site in (obj.get("reader_sites", []) or [])[:2]:
            fn = str((site or {}).get("fn", "") or "")
            if fn:
                funcs.append(fn)
        snippets = _snippets_for_functions(decompiled_cache, funcs)
        why = ["low_score_channel"] if score < 0.9 else []
        if _looks_ring_buffer_object(obj):
            why.append("ring_buffer_channel_candidate")
        items.append({
            "item_id": (
                f"channel:{object_id}:{str(edge.get('src_context', '') or 'UNKNOWN')}:"
                f"{str(edge.get('dst_context', '') or 'UNKNOWN')}"
            ),
            "item_kind": "channel",
            "scope": "channels",
            "proposed_label": _proposed_channel_label(edge, obj),
            "allowed_labels": sorted(_CHANNEL_LABELS),
            "decision": "not_reviewed",
            "confidence": score,
            "why_suspicious": why,
            "triage_rank": 800000,
            "triage_priority": score,
            "context": {
                "object_id": object_id,
                "src_context": str(edge.get("src_context", "") or "UNKNOWN"),
                "dst_context": str(edge.get("dst_context", "") or "UNKNOWN"),
                "score": score,
                "region_kind": str(obj.get("region_kind", "") or ""),
            },
            "evidence_pack": {
                "decompiled_snippets": snippets,
                "available_snippet_keys": [k for k, v in snippets.items() if str(v).strip()],
                "object_members": list(obj.get("members", []) or []),
                "type_facts": dict(obj.get("type_facts", {}) or {}),
                "writer_sites": list(obj.get("writer_sites", []) or [])[:6],
                "reader_sites": list(obj.get("reader_sites", []) or [])[:6],
                "edge_constraints": list(edge.get("constraints", []) or []),
            },
            "constraints": {
                "allowed_outputs": ["accept", "reject", "uncertain"],
                "allowed_labels": sorted(_CHANNEL_LABELS),
                "must_quote_evidence": True,
                "must_not_add_new_labels": True,
            },
        })
    items.sort(key=_item_sort_key)
    return items


def _snippets_for_functions(decompiled_cache: Mapping[str, str], functions: Sequence[str]) -> Dict[str, str]:
    snippets: Dict[str, str] = {}
    for idx, fn in enumerate(functions):
        key = str(fn or "").strip()
        if not key or key not in decompiled_cache:
            continue
        snippets[f"context_fn_{idx}"] = str(decompiled_cache.get(key, "") or "")
    return snippets


def _looks_ring_buffer_object(obj: Mapping[str, Any]) -> bool:
    members = [str(v).lower() for v in (obj.get("members", []) or [])]
    lower = " ".join(members)
    if "head" in lower and "tail" in lower:
        return True
    tf = dict(obj.get("type_facts", {}) or {})
    return str(tf.get("kind_hint", "") or "").lower() in {"buffer", "queue"} and any("head" in m or "tail" in m for m in members)


def _proposed_channel_label(edge: Mapping[str, Any], obj: Mapping[str, Any]) -> str:
    src = str(edge.get("src_context", "") or "UNKNOWN")
    dst = str(edge.get("dst_context", "") or "UNKNOWN")
    if src == "DMA":
        return "DMA_CHANNEL"
    if src == "ISR" and dst in {"MAIN", "TASK"}:
        return "ISR_SHARED_CHANNEL"
    if _looks_ring_buffer_object(obj):
        return "RING_BUFFER_CHANNEL"
    if str(obj.get("region_kind", "") or "") in {"QUEUE_OBJECT"}:
        return "QUEUE_CHANNEL"
    return "DATA"


def _apply_scope_quotas(items_by_scope: Mapping[str, Sequence[Dict[str, Any]]], *, max_items: int) -> List[Dict[str, Any]]:
    if max_items <= 0:
        max_items = DEFAULT_MAX_SUPERVISION_ITEMS
    quotas = dict(_SCOPE_DEFAULT_QUOTAS)
    scopes = ("sinks", "sources", "channels", "objects")
    available = {scope: list(items_by_scope.get(scope, []) or []) for scope in scopes}
    active = [scope for scope in scopes if available[scope]]
    if not active:
        return []

    total_quota = sum(quotas.get(scope, 0) for scope in active) or 1
    if max_items < total_quota:
        trimmed = {scope: min(quotas.get(scope, 0), len(available[scope])) for scope in active}
        while sum(trimmed.values()) > max_items:
            reducible = [scope for scope in active if trimmed[scope] > 1]
            if not reducible:
                break
            scope = max(reducible, key=lambda s: (trimmed[s], len(available[s])))
            trimmed[scope] -= 1
        quotas = {scope: trimmed.get(scope, 0) for scope in scopes}
    else:
        quotas = {scope: min(quotas.get(scope, 0), len(available[scope])) for scope in scopes}

    out: List[Dict[str, Any]] = []
    used_ids = set()
    leftovers: List[Dict[str, Any]] = []
    for scope in scopes:
        rows = available[scope]
        take = quotas.get(scope, 0)
        chosen = rows[:take]
        for row in chosen:
            out.append(row)
            used_ids.add(str(row.get("item_id", "") or ""))
        for row in rows[take:]:
            if str(row.get("item_id", "") or "") not in used_ids:
                leftovers.append(row)
    if len(out) < max_items:
        leftovers.sort(key=_item_sort_key)
        for row in leftovers:
            if len(out) >= max_items:
                break
            row_id = str(row.get("item_id", "") or "")
            if row_id in used_ids:
                continue
            out.append(row)
            used_ids.add(row_id)
    out.sort(key=_item_sort_key)
    return out[:max_items]


def _item_sort_key(item: Mapping[str, Any]) -> Tuple[Any, ...]:
    return (
        int(item.get("triage_rank", 999999) or 999999),
        -float(item.get("triage_priority", 0.0) or 0.0),
        -float(item.get("confidence", 0.0) or 0.0),
        str(item.get("item_kind", "") or ""),
        str(item.get("item_id", "") or ""),
    )


def _count_by_kind(items: Sequence[Mapping[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for item in items or []:
        kind = str(item.get("item_kind", "") or "unknown")
        out[kind] = out.get(kind, 0) + 1
    return dict(sorted(out.items()))


def _uniq(existing: Sequence[Any], new_values: Sequence[Any]) -> List[Any]:
    out: List[Any] = []
    seen = set()
    for value in list(existing or []) + list(new_values or []):
        key = repr(value)
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
    return out


def _uniq_rows(
    existing: Sequence[Mapping[str, Any] | Any],
    new_rows: Sequence[Mapping[str, Any] | Any],
) -> List[Any]:
    out: List[Any] = []
    seen = set()
    for row in list(existing or []) + list(new_rows or []):
        if isinstance(row, Mapping):
            key = repr(sorted(dict(row).items()))
            item: Any = dict(row)
        else:
            key = repr(row)
            item = row
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _hex_addr(value: Any) -> str:
    try:
        num = int(value or 0)
    except Exception:
        num = 0
    return f"0x{num:08x}"
