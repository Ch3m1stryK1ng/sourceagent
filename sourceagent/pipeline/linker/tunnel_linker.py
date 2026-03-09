"""Tunnel-aware backward linker (M9.1).

Implements sink-first bounded best-first search with:
- state de-dup
- lightweight slice caching
- object-hit driven tunnel jumps
- conservative verdict policy
"""

from __future__ import annotations

import hashlib
import heapq
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .derive_check import summarize_derive_and_checks


_HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
_GENERIC_ROOT_MARKERS = {
    "",
    "UNKNOWN",
    "format_arg_variable",
    "indirect_call_target",
    "store_target",
}
_CONTROL_ROOT_NAMES = {
    "cb",
    "callback",
    "cfg",
    "config",
    "ctx",
    "dev",
    "device",
    "driver",
    "func",
    "handler",
    "ops",
    "priv",
    "userdata",
    "user_data",
}
_INIT_LIKE_NAME_PARTS = (
    "init",
    "config",
    "setup",
    "clock",
    "start",
    "probe",
    "enable",
    "msp",
)
_WEAK_BRIDGE_NAME_PARTS = (
    "fatal",
    "panic",
    "abort",
    "assert",
    "oops",
    "exception",
    "thread_abort",
    "log_",
    "print",
)
_WEAK_SOURCE_NAME_PARTS = _WEAK_BRIDGE_NAME_PARTS + (
    "status",
    "poll",
    "idle",
    "sched",
)
_WEAK_OBJECT_HIT_MODES = {"local_sram_access", "fn_expr_heuristic", "context_rw"}


def link_chains(
    sink_roots: List[Dict[str, Any]],
    channel_graph: Dict[str, Any],
    mai: Any,
    sources: List[Dict[str, Any]],
    *,
    sink_facts_by_pack: Optional[Dict[str, Dict[str, Any]]] = None,
    sink_pack_id_by_site: Optional[Dict[str, str]] = None,
    binary_stem: str,
    budget: int = 160,
    K: int = 2,
    max_depth: int = 2,
    max_chains_per_sink: int = 4,
    max_chains_per_binary: int = 200,
) -> List[Dict[str, Any]]:
    """Build sink-first chains with bounded best-first expansion."""
    sink_facts_by_pack = sink_facts_by_pack or {}
    sink_pack_id_by_site = sink_pack_id_by_site or {}

    object_nodes = list((channel_graph or {}).get("object_nodes", []))
    channel_edges = list((channel_graph or {}).get("channel_edges", []))
    objects_by_id = {str(o.get("object_id", "")): o for o in object_nodes}
    edges_by_object = _edges_by_object(channel_edges)

    sources_by_fn = _sources_by_function(sources)
    access_by_fn = _accesses_by_function(mai)
    decompiled_cache = dict(getattr(mai, "decompiled_cache", {}) or {})

    slice_cache: Dict[Tuple[str, str, int, Tuple[str, ...]], Dict[str, Any]] = {}
    chains: List[Dict[str, Any]] = []

    for sink_root in sink_roots:
        if len(chains) >= max_chains_per_binary:
            break

        emitted_for_sink = 0
        pq: List[Tuple[float, int, Dict[str, Any]]] = []
        counter = 0
        seen = set()
        expansions = 0
        best_partial: Optional[Dict[str, Any]] = None

        sink_site_hex = str(sink_root.get("sink_site", ""))
        sink_fn = str(sink_root.get("sink_function", ""))
        sink_label = str(sink_root.get("sink_label", ""))

        for init_state in _initial_states_for_sink(sink_root, sink_label=sink_label, sink_fn=sink_fn):
            heapq.heappush(pq, (-init_state["state_score"], counter, init_state))
            counter += 1

        while pq and emitted_for_sink < max_chains_per_sink and len(chains) < max_chains_per_binary:
            if expansions >= max(1, int(budget)):
                budget_failure_code = "BUDGET_EXCEEDED"
                budget_failure_detail = f"search budget exceeded ({budget})"
                if str(sink_root.get("status", "")) != "ok":
                    budget_failure_code = ""
                    budget_failure_detail = ""
                budget_chain = _materialize_chain(
                    sink_root=sink_root,
                    sink_site_hex=sink_site_hex,
                    sink_fn=sink_fn,
                    sink_label=sink_label,
                    active_root=st.get("active_root"),
                    source=None,
                    source_resolve_mode="none",
                    bridge_steps=[],
                    channel_steps=best_partial.get("steps", []) if best_partial else [],
                    sink_facts=sink_facts_by_pack.get(
                        sink_pack_id_by_site.get(_sink_site_key(sink_site_hex, sink_fn, sink_label), ""),
                        {},
                    ),
                    binary_stem=binary_stem,
                    link_debug=_build_link_debug(sink_root, st, None, [], budget_failure_code),
                    force_status="partial",
                    force_failure_code=budget_failure_code,
                    force_failure_detail=budget_failure_detail,
                )
                chains.append(budget_chain)
                emitted_for_sink += 1
                best_partial = None
                break

            _, _, st = heapq.heappop(pq)
            key = _state_key(st)
            if key in seen:
                continue
            seen.add(key)
            expansions += 1

            slice_res = _cached_slice(
                st,
                sink_label=sink_label,
                sources=sources,
                sources_by_fn=sources_by_fn,
                objects_by_id=objects_by_id,
                edges_by_object=edges_by_object,
                access_by_fn=access_by_fn,
                decompiled_cache=decompiled_cache,
                cache=slice_cache,
            )

            source = slice_res.get("source")
            obj_hits = list(slice_res.get("object_hits", []))
            prefer_tunnel = _should_prefer_tunnel(
                st,
                slice_res,
                obj_hits,
                edges_by_object,
            )
            if source is not None and not prefer_tunnel:
                chain = _materialize_chain(
                    sink_root=sink_root,
                    sink_site_hex=sink_site_hex,
                    sink_fn=sink_fn,
                    sink_label=sink_label,
                    active_root=st.get("active_root"),
                    source=source,
                    source_resolve_mode=str(slice_res.get("source_resolve_mode", "none")),
                    bridge_steps=list(slice_res.get("bridge_steps", [])),
                    channel_steps=st.get("channel_steps", []),
                    sink_facts=sink_facts_by_pack.get(
                        sink_pack_id_by_site.get(_sink_site_key(sink_site_hex, sink_fn, sink_label), ""),
                        {},
                    ),
                    function_code=str(decompiled_cache.get(sink_fn, "") or ""),
                    decompiled_cache=decompiled_cache,
                    binary_stem=binary_stem,
                    link_debug=_build_link_debug(
                        sink_root,
                        st,
                        slice_res,
                        list(slice_res.get("object_hits", [])),
                        "",
                    ),
                )
                chains.append(chain)
                emitted_for_sink += 1
                continue

            expanded = False
            producer_candidates: List[str] = []
            loop_failure_code = str(slice_res.get("failure_code", "NO_SOURCE_REACH"))
            loop_failure_detail = str(slice_res.get("failure_detail", "No source reached on this branch"))
            if st.get("depth", 0) < max_depth and obj_hits:
                for obj_id in obj_hits[: max(1, int(K))]:
                    edges = edges_by_object.get(obj_id, [])[: max(1, int(K))]
                    if not edges:
                        loop_failure_code = "OBJECT_HIT_NO_EDGE"
                        loop_failure_detail = f"Object {obj_id} matched root but has no channel edge"
                        continue
                    for edge in edges:
                        obj = objects_by_id.get(obj_id, {})
                        producer_fn = _pick_producer_fn(
                            obj,
                            str(edge.get("src_context", "UNKNOWN")),
                            fallback=str(st.get("current_fn", "")),
                        )
                        if producer_fn:
                            producer_candidates.append(producer_fn)
                        ch_step = {
                            "kind": "CHANNEL",
                            "edge": f"{edge.get('src_context', 'UNKNOWN')}->{edge.get('dst_context', 'UNKNOWN')}",
                            "object_id": obj_id,
                            "evidence_refs": list(edge.get("evidence_refs", [])),
                        }
                        next_state = {
                            "current_fn": producer_fn,
                            "expr": str(st.get("expr", "UNKNOWN")),
                            "active_root": dict(st.get("active_root", {}) or {}),
                            "all_roots": list(st.get("all_roots", []) or []),
                            "depth": int(st.get("depth", 0)) + 1,
                            "channel_steps": list(st.get("channel_steps", [])) + [ch_step],
                            "object_history": tuple(list(st.get("object_history", ())) + [obj_id]),
                            "state_score": _next_state_score(st, edge_score=float(edge.get("score", 0.0))),
                            "tunnel_attempts": int(st.get("tunnel_attempts", 0)) + 1,
                            "producer_candidates": tuple(list(st.get("producer_candidates", ())) + [producer_fn]),
                        }
                        heapq.heappush(pq, (-next_state["state_score"], counter, next_state))
                        counter += 1
                        expanded = True
                if expanded:
                    loop_failure_code = "PRODUCER_SOURCE_MISS"
                    loop_failure_detail = "Tunnel jump expanded to producer contexts but no source was reached yet"
            elif obj_hits:
                loop_failure_code = "MAX_DEPTH_REACHED"
                loop_failure_detail = f"Reached max tunnel depth ({max_depth}) before source resolution"

            if not expanded:
                applied_failure_code = loop_failure_code
                applied_failure_detail = loop_failure_detail
                if str(sink_root.get("status", "")) != "ok":
                    applied_failure_code = ""
                    applied_failure_detail = ""
                partial_chain = _materialize_chain(
                    sink_root=sink_root,
                    sink_site_hex=sink_site_hex,
                    sink_fn=sink_fn,
                    sink_label=sink_label,
                    active_root=st.get("active_root"),
                    source=None,
                    source_resolve_mode="none",
                    bridge_steps=[],
                    channel_steps=st.get("channel_steps", []),
                    sink_facts=sink_facts_by_pack.get(
                        sink_pack_id_by_site.get(_sink_site_key(sink_site_hex, sink_fn, sink_label), ""),
                        {},
                    ),
                    function_code=str(decompiled_cache.get(sink_fn, "") or ""),
                    decompiled_cache=decompiled_cache,
                    binary_stem=binary_stem,
                    link_debug=_build_link_debug(sink_root, st, slice_res, obj_hits, applied_failure_code),
                    force_status="partial",
                    force_failure_code=applied_failure_code,
                    force_failure_detail=applied_failure_detail,
                )
                if best_partial is None or float(partial_chain.get("score", 0.0)) > float(best_partial.get("score", 0.0)):
                    best_partial = partial_chain

        if emitted_for_sink == 0 and best_partial is not None and len(chains) < max_chains_per_binary:
            chains.append(best_partial)

    return _prune_redundant_chains(chains, max_chains_per_sink=max_chains_per_sink)


def summarize_chain_eval(chains: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate chain-level stats for chain_eval.json."""
    total = len(chains)
    with_source = sum(1 for c in chains if any(s.get("kind") == "SOURCE" for s in c.get("steps", [])))
    with_channel = sum(1 for c in chains if any(s.get("kind") == "CHANNEL" for s in c.get("steps", [])))
    confirmed = sum(1 for c in chains if c.get("verdict") == "CONFIRMED")
    suspicious = sum(1 for c in chains if c.get("verdict") == "SUSPICIOUS")
    safe = sum(1 for c in chains if c.get("verdict") == "SAFE_OR_LOW_RISK")
    dropped = sum(1 for c in chains if c.get("verdict") == "DROP")

    return {
        "chain_count": total,
        "with_source": with_source,
        "with_channel": with_channel,
        "confirmed": confirmed,
        "suspicious": suspicious,
        "safe_or_low_risk": safe,
        "dropped": dropped,
    }


def _materialize_chain(
    *,
    sink_root: Dict[str, Any],
    sink_site_hex: str,
    sink_fn: str,
    sink_label: str,
    active_root: Optional[Dict[str, Any]],
    source: Optional[Dict[str, Any]],
    source_resolve_mode: str,
    bridge_steps: Sequence[Dict[str, Any]],
    channel_steps: Sequence[Dict[str, Any]],
    sink_facts: Dict[str, Any],
    function_code: str,
    decompiled_cache: Optional[Dict[str, str]],
    binary_stem: str,
    link_debug: Optional[Dict[str, Any]] = None,
    force_status: Optional[str] = None,
    force_failure_code: str = "",
    force_failure_detail: str = "",
) -> Dict[str, Any]:
    evidence_refs = set(sink_root.get("evidence_refs", []))
    steps: List[Dict[str, Any]] = []
    active_root = active_root or _first_linkable_root(sink_root.get("roots", []))

    if source is not None:
        src_step = {
            "kind": "SOURCE",
            "label": source.get("label", ""),
            "site": _hex_addr(source.get("address", 0)),
            "function": source.get("function_name", ""),
            "evidence_refs": list(source.get("evidence_refs", [])),
        }
        steps.append(src_step)
        for ref in src_step.get("evidence_refs", []):
            evidence_refs.add(ref)

    for br in bridge_steps:
        steps.append(dict(br))
        for ref in br.get("evidence_refs", []):
            evidence_refs.add(ref)

    for ch in channel_steps:
        steps.append(dict(ch))
        for ref in ch.get("evidence_refs", []):
            evidence_refs.add(ref)

    primary_root = str((active_root or {}).get("expr", "")) or _first_primary_root_expr(sink_root.get("roots", []))
    root_bundle = _serialize_root_bundle(
        active_root=active_root,
        all_roots=list(sink_root.get("roots", []) or []),
    )
    related_function_codes = _collect_related_function_codes(
        sink_fn=sink_fn,
        bridge_steps=bridge_steps,
        decompiled_cache=decompiled_cache or {},
    )
    derive_facts, checks, check_strength = summarize_derive_and_checks(
        sink_function=sink_fn,
        primary_root_expr=primary_root,
        sink_facts=sink_facts,
        function_code=function_code,
        active_root_kind=str((active_root or {}).get("kind", "")),
        related_function_codes=related_function_codes,
    )
    if derive_facts:
        steps.append({
            "kind": "DERIVE",
            "expr": derive_facts[0]["expr"],
            "site": sink_fn,
            "evidence_refs": list(sink_root.get("evidence_refs", [])),
        })

    steps.append({
        "kind": "SINK",
        "label": sink_label,
        "site": sink_site_hex,
        "function": sink_fn,
        "evidence_refs": list(sink_root.get("evidence_refs", [])),
    })

    source_reached = source is not None
    has_channel = any(s.get("kind") == "CHANNEL" for s in steps)
    has_app_anchor = bool(source_reached or has_channel)
    active_root_kind = str((active_root or {}).get("kind", ""))
    object_hit_mode = str((link_debug or {}).get("object_hit_mode", "none"))
    producer_candidates = [str(fn) for fn in ((link_debug or {}).get("producer_candidates", []) or []) if str(fn)]
    weak_source_anchor = bool(
        source is not None
        and _is_weak_source_anchor(
            source,
            source_resolve_mode=source_resolve_mode,
            object_hit_mode=object_hit_mode,
            active_root_kind=active_root_kind,
            has_channel=has_channel,
        )
    )
    weak_producer_only = bool(
        source is None
        and has_channel
        and object_hit_mode in _WEAK_OBJECT_HIT_MODES
        and producer_candidates
        and all(_is_weak_bridge_function(fn) or _is_init_like_function(fn) for fn in producer_candidates)
    )
    control_path_only = bool(
        source is not None
        and _is_control_root_expr(primary_root, active_root_kind)
        and _is_init_like_function(str(source.get("function_name", "")))
        and str(source.get("label", "")) in {"MMIO_READ", "DMA_BACKED_BUFFER", "ISR_MMIO_READ"}
    )
    if weak_source_anchor or weak_producer_only:
        control_path_only = True
    channel_required_hint = bool((link_debug or {}).get("channel_required_hint", False))
    secondary_root_only = _is_secondary_root_only_chain(
        sink_label=sink_label,
        active_root_kind=active_root_kind,
        root_bundle=root_bundle,
    )
    if control_path_only:
        has_app_anchor = False
    root_controllable = bool(
        source_reached
        and primary_root
        and (not _looks_constant_expr(primary_root) or str((active_root or {}).get("kind", "")).lower() in {"format_arg", "dispatch", "dst_ptr"})
        and _is_actionable_source_mode(source_resolve_mode, has_channel=has_channel)
    )
    chain_complete = bool(primary_root and primary_root != "UNKNOWN")
    has_contradiction = False

    score = _chain_score(
        sink_conf=float(sink_root.get("confidence", 0.0)),
        source_reached=source_reached,
        has_channel=has_channel,
        check_strength=check_strength,
        root_controllable=root_controllable,
    )

    status = "ok"
    failure_code = ""
    failure_detail = ""

    if sink_root.get("status") != "ok":
        status = "partial"
        failure_code = str(sink_root.get("failure_code", "ROOT_UNRESOLVED"))
        failure_detail = str(sink_root.get("failure_detail", ""))
    elif not source_reached:
        status = "partial"
        failure_code = "NO_SOURCE_REACH"
        failure_detail = "No verified source candidate linked to this sink"
    elif not chain_complete:
        status = "partial"
        failure_code = "ROOT_UNRESOLVED"
        failure_detail = "Primary root is unresolved"
    elif check_strength == "unknown":
        status = "partial"
        failure_code = "CHECK_UNCERTAIN"
        failure_detail = "Check strength could not be determined"

    if force_status:
        status = force_status
    if force_failure_code:
        failure_code = force_failure_code
    if force_failure_detail:
        failure_detail = force_failure_detail

    verdict, decision_basis = _decide_verdict(
        sink_label=sink_label,
        active_root_kind=str((active_root or {}).get("kind", "")),
        source_reached=source_reached,
        root_controllable=root_controllable,
        check_strength=check_strength,
        chain_complete=chain_complete,
        has_contradiction=has_contradiction,
        has_app_anchor=has_app_anchor,
        control_path_only=control_path_only,
        chain_score=score,
        source_resolve_mode=source_resolve_mode,
        secondary_root_only=secondary_root_only,
        channel_required_hint=channel_required_hint,
        has_channel=has_channel,
    )

    chain = {
        "chain_id": _make_chain_id(
            binary_stem=binary_stem,
            sink_root=sink_root,
            active_root=active_root,
            source=source,
            source_resolve_mode=source_resolve_mode,
            bridge_steps=bridge_steps,
            channel_steps=channel_steps,
        ),
        "sink": {
            "sink_id": sink_root["sink_id"],
            "label": sink_label,
            "function": sink_fn,
            "site": sink_site_hex,
            "root_expr": primary_root or "UNKNOWN",
        },
        "root_bundle": root_bundle,
        "steps": steps,
        "checks": checks,
        "derive_facts": derive_facts,
        "verdict": verdict,
        "current_verdict_reason": str(decision_basis.get("reason_code", "UNKNOWN") or "UNKNOWN"),
        "score": score,
        "status": status,
        "evidence_refs": sorted(evidence_refs),
        "has_app_anchor": bool(has_app_anchor),
        "root_source": str((active_root or {}).get("source", "") or sink_root.get("root_source", "none")),
        "decision_basis": decision_basis,
        "link_debug": link_debug or {
            "root_source": str((active_root or {}).get("source", "") or sink_root.get("root_source", "none")),
            "object_hit_mode": "none",
            "source_resolve_mode": "none",
            "tunnel_attempts": 0,
            "producer_candidates": [],
            "failure_stage": "none",
        },
    }
    if control_path_only:
        chain["link_debug"]["control_path_only"] = True
    if weak_source_anchor:
        chain["link_debug"]["weak_source_anchor"] = True
    if weak_producer_only:
        chain["link_debug"]["weak_producer_only"] = True
    if secondary_root_only:
        chain["link_debug"]["secondary_root_only"] = True

    if failure_code:
        chain["failure_code"] = failure_code
    if failure_detail:
        chain["failure_detail"] = failure_detail
        chain["fallback_action"] = "triage_queue"

    return chain


def _cached_slice(
    st: Dict[str, Any],
    *,
    sink_label: str,
    sources: List[Dict[str, Any]],
    sources_by_fn: Dict[str, List[Dict[str, Any]]],
    objects_by_id: Dict[str, Dict[str, Any]],
    edges_by_object: Dict[str, List[Dict[str, Any]]],
    access_by_fn: Dict[str, List[Any]],
    decompiled_cache: Dict[str, str],
    cache: Dict[Tuple[str, str, int, Tuple[str, ...]], Dict[str, Any]],
) -> Dict[str, Any]:
    key = _state_key(st)
    if key in cache:
        return dict(cache[key])

    current_fn = str(st.get("current_fn", ""))
    expr = str(st.get("expr", ""))

    object_hits, object_hit_mode = _resolve_object_hits(expr, current_fn, objects_by_id, access_by_fn)
    # If we already hit object nodes, prefer tunnel expansion over singleton-source
    # shortcut so the chain can carry CHANNEL evidence.
    active_root = dict(st.get("active_root", {}) or {})
    source, source_mode, bridge_steps = _resolve_source(
        current_fn,
        expr,
        sources,
        sources_by_fn,
        active_root=active_root,
        decompiled_cache=decompiled_cache,
        allow_singleton_fallback=not bool(object_hits),
        allow_label_guided_fallback=not bool(object_hits),
    )

    if not object_hits:
        support_hits, support_mode = _resolve_supporting_object_hits(
            current_fn=current_fn,
            active_root=active_root,
            all_roots=list(st.get("all_roots", []) or []),
            bridge_steps=bridge_steps,
            objects_by_id=objects_by_id,
            access_by_fn=access_by_fn,
        )
        if support_hits:
            object_hits = support_hits
            object_hit_mode = support_mode
    channel_required_hint = any(_object_requires_channel(obj_id, edges_by_object) for obj_id in object_hits)

    failure_code = ""
    failure_detail = ""
    if source is None:
        if _is_unresolved_expr(expr):
            failure_code = "ROOT_UNRESOLVED"
            failure_detail = "Primary root expression is unresolved or only has a generic fallback"
        elif object_hits:
            failure_code = "SOURCE_NOT_IN_CONTEXT"
            failure_detail = "Matched object(s) but no source was found in the current context"
        else:
            failure_code = "OBJECT_HIT_NONE"
            failure_detail = "Root expression did not map to any known object"

    res = {
        "source": source,
        "source_resolve_mode": source_mode,
        "bridge_steps": bridge_steps,
        "object_hits": object_hits,
        "object_hit_mode": object_hit_mode,
        "channel_required_hint": channel_required_hint,
        "failure_code": failure_code,
        "failure_detail": failure_detail,
    }
    cache[key] = dict(res)
    return res


def _resolve_source(
    current_fn: str,
    expr: str,
    sources: List[Dict[str, Any]],
    sources_by_fn: Dict[str, List[Dict[str, Any]]],
    *,
    active_root: Optional[Dict[str, Any]] = None,
    decompiled_cache: Optional[Dict[str, str]] = None,
    allow_singleton_fallback: bool = True,
    allow_label_guided_fallback: bool = True,
) -> Tuple[Optional[Dict[str, Any]], str, List[Dict[str, Any]]]:
    decompiled_cache = decompiled_cache or {}
    candidates: List[Tuple[Dict[str, Any], str, List[Dict[str, Any]]]] = []

    same_fn = sources_by_fn.get(current_fn, [])
    if same_fn:
        candidates.append(
            (
                _choose_best_source(same_fn, expr=expr, active_root=active_root),
                "same_function",
                [],
            )
        )

    direct_src = _resolve_same_context_direct_call(
        current_fn,
        sources,
        decompiled_cache,
        expr=expr,
        active_root=active_root,
    )
    if direct_src is not None:
        candidates.append((direct_src, "same_context_direct_call", []))

    bridge_src, bridge_via = _resolve_unique_caller_bridge(
        current_fn,
        sources,
        decompiled_cache,
        expr=expr,
        active_root=active_root,
    )
    if bridge_src is not None:
        candidates.append((bridge_src, "caller_bridge", [_make_bridge_step(bridge_via, current_fn)]))

    nested_bridge_src, nested_bridge_via = _resolve_nested_caller_bridge(
        current_fn,
        sources,
        decompiled_cache,
        expr=expr,
        active_root=active_root,
    )
    if nested_bridge_src is not None:
        candidates.append((nested_bridge_src, "nested_caller_bridge", [_make_bridge_step(nested_bridge_via, current_fn)]))

    transitive_bridge_src, transitive_bridge_path = _resolve_transitive_caller_bridge(
        current_fn,
        sources,
        decompiled_cache,
        expr=expr,
        active_root=active_root,
    )
    if transitive_bridge_src is not None and transitive_bridge_path:
        candidates.append((
            transitive_bridge_src,
            "transitive_caller_bridge",
            _make_bridge_steps(transitive_bridge_path, current_fn),
        ))

    if candidates:
        chosen_src, chosen_mode, chosen_steps = max(
            candidates,
            key=lambda item: _source_candidate_rank(item[0], item[1], expr=expr, active_root=active_root),
        )
        return chosen_src, chosen_mode, chosen_steps

    # Conservative fallback: if there is a single source in the binary,
    # allow linking for chain completeness.
    if allow_singleton_fallback and len(sources) == 1:
        return _choose_best_source(sources, expr=expr, active_root=active_root), "singleton_fallback", []

    # Expression-guided fallback by source label keywords.
    if allow_label_guided_fallback:
        exp = expr.lower()
        for src in sources:
            label = str(src.get("label", "")).lower()
            if "dma" in exp and "dma" in label:
                return src, "label_guided", []
            if "isr" in exp and "isr" in label:
                return src, "label_guided", []
    return None, "none", []


def _resolve_same_context_direct_call(
    current_fn: str,
    sources: Sequence[Dict[str, Any]],
    decompiled_cache: Dict[str, str],
    *,
    expr: str,
    active_root: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    code = str(decompiled_cache.get(current_fn, "") or "")
    if not code:
        return None

    matches: List[Dict[str, Any]] = []
    for src in sources:
        src_fn = str(src.get("function_name", "") or "")
        if not src_fn or src_fn == current_fn:
            continue
        if _code_calls_function(code, src_fn):
            matches.append(src)

    if not matches:
        return None
    return _choose_best_source(matches, expr=expr, active_root=active_root)


def _resolve_unique_caller_bridge(
    current_fn: str,
    sources: Sequence[Dict[str, Any]],
    decompiled_cache: Dict[str, str],
    *,
    expr: str,
    active_root: Optional[Dict[str, Any]],
) -> Tuple[Optional[Dict[str, Any]], str]:
    if not current_fn or not decompiled_cache:
        return None, ""

    callers: List[Tuple[str, str]] = []
    for fn, code in decompiled_cache.items():
        if fn == current_fn:
            continue
        if _is_weak_bridge_function(fn):
            continue
        if _code_calls_function(str(code or ""), current_fn):
            callers.append((str(fn), str(code or "")))

    if len(callers) != 1:
        return None, ""

    caller_fn, caller_code = callers[0]
    matches: List[Dict[str, Any]] = []
    for src in sources:
        src_fn = str(src.get("function_name", "") or "")
        if not src_fn:
            continue
        if _is_weak_source_function(src_fn):
            continue
        if _code_calls_function(caller_code, src_fn):
            matches.append(src)

    if not matches:
        return None, ""
    return _choose_best_source(matches, expr=expr, active_root=active_root), caller_fn


def _resolve_nested_caller_bridge(
    current_fn: str,
    sources: Sequence[Dict[str, Any]],
    decompiled_cache: Dict[str, str],
    *,
    expr: str,
    active_root: Optional[Dict[str, Any]],
) -> Tuple[Optional[Dict[str, Any]], str]:
    if not current_fn or not decompiled_cache:
        return None, ""

    callers: List[Tuple[str, str]] = []
    for fn, code in decompiled_cache.items():
        if fn == current_fn:
            continue
        if _is_weak_bridge_function(fn):
            continue
        if _code_calls_function(str(code or ""), current_fn):
            callers.append((str(fn), str(code or "")))

    if len(callers) != 1:
        return None, ""

    caller_fn, caller_code = callers[0]
    matches: List[Dict[str, Any]] = []
    for helper_fn, helper_code in decompiled_cache.items():
        helper_fn = str(helper_fn or "")
        if not helper_fn or helper_fn in {current_fn, caller_fn}:
            continue
        if _is_weak_bridge_function(helper_fn):
            continue
        if not _code_calls_function(caller_code, helper_fn):
            continue
        for src in sources:
            src_fn = str(src.get("function_name", "") or "")
            if not src_fn or src_fn in {current_fn, caller_fn}:
                continue
            if _is_weak_source_function(src_fn):
                continue
            if _code_calls_function(str(helper_code or ""), src_fn):
                matches.append(src)

    if not matches:
        return None, ""
    return _choose_best_source(matches, expr=expr, active_root=active_root), caller_fn


def _resolve_transitive_caller_bridge(
    current_fn: str,
    sources: Sequence[Dict[str, Any]],
    decompiled_cache: Dict[str, str],
    *,
    expr: str,
    active_root: Optional[Dict[str, Any]],
    max_depth: int = 4,
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    if not current_fn or not decompiled_cache:
        return None, []

    q: List[Tuple[str, List[str]]] = [(current_fn, [])]
    seen = {current_fn}

    while q:
        fn, path = q.pop(0)
        if len(path) >= max_depth:
            continue
        callers = _find_callers(fn, decompiled_cache)
        for caller_fn, caller_code in callers:
            if caller_fn in seen:
                continue
            if _is_weak_bridge_function(caller_fn):
                continue
            seen.add(caller_fn)
            next_path = path + [caller_fn]

            matches: List[Dict[str, Any]] = []
            for src in sources:
                src_fn = str(src.get("function_name", "") or "")
                if _is_weak_source_function(src_fn):
                    continue
                if src_fn and _code_calls_function(caller_code, src_fn):
                    matches.append(src)
            if matches:
                return _choose_best_source(matches, expr=expr, active_root=active_root), next_path

            q.append((caller_fn, next_path))
    return None, []


def _find_callers(target_fn: str, decompiled_cache: Dict[str, str]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for fn, code in decompiled_cache.items():
        fn = str(fn or "")
        if not fn or fn == target_fn:
            continue
        if _code_calls_function(str(code or ""), target_fn):
            out.append((fn, str(code or "")))
    return out


def _choose_best_source(
    sources: Sequence[Dict[str, Any]],
    *,
    expr: str,
    active_root: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    ranked = sorted(
        (dict(src) for src in sources),
        key=lambda src: _source_sort_key(src, expr=expr, active_root=active_root),
    )
    return ranked[0]


def _source_candidate_rank(
    src: Dict[str, Any],
    mode: str,
    *,
    expr: str,
    active_root: Optional[Dict[str, Any]],
) -> Tuple[int, int, int, str, int]:
    mode_bonus = {
        "same_function": 30,
        "same_context_direct_call": 40,
        "nested_caller_bridge": 28,
        "transitive_caller_bridge": 24,
        "caller_bridge": 25,
        "singleton_fallback": 5,
        "label_guided": 10,
    }.get(mode, 0)
    sort_key = _source_sort_key(src, expr=expr, active_root=active_root)
    return (mode_bonus, -sort_key[0], -sort_key[1], sort_key[2], -sort_key[3])


def _resolve_object_hits(
    expr: str,
    current_fn: str,
    objects_by_id: Dict[str, Dict[str, Any]],
    access_by_fn: Dict[str, List[Any]],
) -> Tuple[List[str], str]:
    member_hits = _member_object_hits(expr, objects_by_id)
    if member_hits:
        return member_hits, "expr_member"

    hits: List[str] = []

    expr_lower = str(expr or "").lower()
    for obj_id in objects_by_id:
        if obj_id.lower() in expr_lower:
            hits.append(obj_id)
    if hits:
        return hits, "expr_object_id"

    for m in _HEX_RE.finditer(str(expr or "")):
        try:
            addr = int(m.group(0), 16)
        except Exception:
            continue
        obj_id = _object_for_addr(addr, objects_by_id)
        if obj_id and obj_id not in hits:
            hits.append(obj_id)
    if hits:
        return hits, "expr_address"

    # Fallback: function-local SRAM accesses mapped to known objects.
    for a in access_by_fn.get(current_fn, [])[:16]:
        addr = int(getattr(a, "target_addr", 0) or 0)
        if addr <= 0:
            continue
        obj_id = _object_for_addr(addr, objects_by_id)
        if obj_id and obj_id not in hits:
            hits.append(obj_id)
            if len(hits) >= 3:
                break

    if hits:
        return hits, "local_sram_access"

    hits = _heuristic_object_hits(expr, current_fn, objects_by_id)
    if hits:
        return hits, "fn_expr_heuristic"
    return [], "none"


def _resolve_supporting_object_hits(
    *,
    current_fn: str,
    active_root: Dict[str, Any],
    all_roots: Sequence[Dict[str, Any]],
    bridge_steps: Sequence[Dict[str, Any]],
    objects_by_id: Dict[str, Dict[str, Any]],
    access_by_fn: Dict[str, List[Any]],
) -> Tuple[List[str], str]:
    kind = str(active_root.get("kind", "")).lower()
    if kind not in {"length", "index_or_bound", "dispatch", "format_arg"}:
        return [], "none"

    scored: List[Tuple[float, str]] = []
    for root in all_roots:
        if root is active_root:
            continue
        root_kind = str(root.get("kind", "")).lower()
        if root_kind not in {"src_ptr", "dst_ptr", "src_data", "target_addr"}:
            continue
        hits, _ = _resolve_object_hits(str(root.get("expr", "")), current_fn, objects_by_id, access_by_fn)
        for idx, obj_id in enumerate(hits):
            score = 1.0 - 0.05 * idx
            if root_kind in {"src_ptr", "src_data"}:
                score += 0.15
            scored.append((score, obj_id))
    if scored:
        scored.sort(key=lambda x: (-x[0], x[1]))
        return _uniq_keep_order([obj_id for _, obj_id in scored]), "support_root"

    anchor_fns = {str(current_fn)}
    for step in bridge_steps or []:
        if str(step.get("kind", "")) != "BRIDGE":
            continue
        if step.get("from_function"):
            anchor_fns.add(str(step.get("from_function")))
        if step.get("to_function"):
            anchor_fns.add(str(step.get("to_function")))

    local_hits: List[str] = []
    for fn in anchor_fns:
        for obj_id, obj in objects_by_id.items():
            readers = {str(r).lower() for r in (obj.get("readers", []) or [])}
            writers = {str(w).lower() for w in (obj.get("writers", []) or [])}
            if fn.lower() in readers or fn.lower() in writers:
                local_hits.append(obj_id)
    if local_hits:
        return _rank_context_objects(_uniq_keep_order(local_hits), objects_by_id), "context_rw"
    heur_hits = _heuristic_object_hits(str(active_root.get("expr", "")), current_fn, objects_by_id)
    if heur_hits:
        return heur_hits, "fn_expr_heuristic"
    return [], "none"


def _member_object_hits(expr: str, objects_by_id: Dict[str, Dict[str, Any]]) -> List[str]:
    tokens = _expr_tokens(expr)
    if not tokens:
        return []

    scored: List[Tuple[float, str]] = []
    for obj_id, obj in objects_by_id.items():
        score = 0.0
        members = {str(m).lower() for m in (obj.get("members", []) or []) if str(m).strip()}
        if any(tok in members for tok in tokens):
            score += 1.0

        writers = {str(w).lower() for w in (obj.get("writers", []) or []) if str(w).strip()}
        readers = {str(r).lower() for r in (obj.get("readers", []) or []) if str(r).strip()}

        kind_hint = str(obj.get("type_facts", {}).get("kind_hint", "")).lower()
        if kind_hint and kind_hint in str(expr or "").lower():
            score += 0.1

        source_label = str(obj.get("type_facts", {}).get("source_label", "")).lower()
        region_kind = str(obj.get("region_kind", "")).lower()
        if source_label == "dma_backed_buffer" or region_kind == "dma_buffer":
            if any("dma" in tok for tok in tokens):
                score += 0.85
            if any(tok in {"rx", "tx", "buf", "buffer", "payload"} for tok in tokens):
                score += 0.05
        if source_label == "isr_filled_buffer" and any(tok in {"rx", "buf", "buffer"} for tok in tokens):
            score += 0.15

        if score <= 0:
            continue
        if any(tok in writers or tok in readers for tok in tokens):
            score += 0.05
        if "source_label" in (obj.get("type_facts", {}) or {}):
            score += 0.05
        scored.append((score, obj_id))

    scored.sort(key=lambda x: (-x[0], x[1]))
    return [obj_id for _, obj_id in scored]


def _expr_tokens(expr: str) -> List[str]:
    text = str(expr or "")
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    text = text.replace("->", ".").replace("[", " ").replace("]", " ").replace(".", " ")
    toks = re.findall(r"[A-Za-z_]\w*", text)
    out: List[str] = []
    for tok in toks:
        parts = re.split(r"_+", tok)
        for part in parts:
            low = part.lower()
            if low and low not in out:
                out.append(low)
    return out


def _heuristic_object_hits(
    expr: str,
    current_fn: str,
    objects_by_id: Dict[str, Dict[str, Any]],
) -> List[str]:
    expr_tokens = set(_expr_tokens(expr))
    fn_tokens = set(_expr_tokens(current_fn))
    if not expr_tokens and not fn_tokens:
        return []

    scored: List[Tuple[float, str]] = []
    for obj_id, obj in objects_by_id.items():
        obj_tokens = _object_tokens(obj)
        if not obj_tokens:
            continue

        score = 0.0
        if expr_tokens:
            overlap = expr_tokens & obj_tokens
            if overlap:
                score += 1.2 + 0.15 * len(overlap)
        if fn_tokens:
            overlap = fn_tokens & obj_tokens
            if overlap:
                score += 0.8 + 0.1 * len(overlap)

        site_fns = _object_site_functions(obj)
        if current_fn and current_fn.lower() in site_fns:
            score += 1.0

        region_kind = str(obj.get("region_kind", "")).lower()
        if region_kind == "rodata_table" and (expr_tokens | fn_tokens) & {"cmd", "dispatch", "table", "handler"}:
            score += 0.8

        notes = str(obj.get("notes", "") or "").lower()
        if "descriptor" in notes and (expr_tokens | fn_tokens) & {"descriptor", "cfg", "if", "ep", "desc"}:
            score += 0.5
        if "network" in notes and (expr_tokens | fn_tokens) & {"network", "packet", "dns", "udp", "buf", "buffer"}:
            score += 0.5

        if score > 0.9:
            scored.append((score, obj_id))

    scored.sort(key=lambda x: (-x[0], x[1]))
    return [obj_id for _, obj_id in scored[:3]]


def _object_tokens(obj: Dict[str, Any]) -> set[str]:
    toks: set[str] = set()
    for key in ("members", "writers", "readers"):
        for row in obj.get(key, []) or []:
            toks.update(_expr_tokens(str(row)))
    for site_key in ("reader_sites", "writer_sites"):
        for row in obj.get(site_key, []) or []:
            toks.update(_expr_tokens(str(row.get("fn", ""))))
    toks.update(_expr_tokens(str(obj.get("notes", "") or "")))
    toks.update(_expr_tokens(str(obj.get("region_kind", "") or "")))
    for value in (obj.get("type_facts", {}) or {}).values():
        if isinstance(value, str):
            toks.update(_expr_tokens(value))
        elif isinstance(value, list):
            for row in value:
                toks.update(_expr_tokens(str(row)))
    return toks


def _object_site_functions(obj: Dict[str, Any]) -> set[str]:
    out = {str(fn).lower() for fn in (obj.get("writers", []) or []) if str(fn).strip()}
    out |= {str(fn).lower() for fn in (obj.get("readers", []) or []) if str(fn).strip()}
    for site_key in ("reader_sites", "writer_sites"):
        for row in obj.get(site_key, []) or []:
            fn = str(row.get("fn", "") or "").lower()
            if fn:
                out.add(fn)
    return out


def _source_sort_key(
    src: Dict[str, Any],
    *,
    expr: str = "",
    active_root: Optional[Dict[str, Any]] = None,
) -> Tuple[int, int, str, int]:
    fn = str(src.get("function_name", "") or "")
    priority = _source_payload_priority(src, expr=expr, active_root=active_root)
    try:
        addr = int(src.get("address", 0) or 0)
    except Exception:
        addr = 0
    return (-priority, addr, fn, addr)


def _source_payload_priority(
    src: Dict[str, Any],
    *,
    expr: str = "",
    active_root: Optional[Dict[str, Any]] = None,
) -> int:
    label = str(src.get("label", "") or "")
    fn = str(src.get("function_name", "") or "").lower()
    try:
        addr = int(src.get("address", 0) or 0)
    except Exception:
        addr = 0
    offset = addr & 0xFF if addr > 0 else 0

    score = 10
    if label == "DMA_BACKED_BUFFER":
        score = 100
    elif label == "ISR_FILLED_BUFFER":
        score = 95
    elif label == "ISR_MMIO_READ":
        score = 70
    elif label == "MMIO_READ":
        score = 60

    if any(tok in fn for tok in ("enable", "config", "setup", "init", "status", "poll", "flag", "ready")):
        score -= 25
    if any(tok in fn for tok in _WEAK_SOURCE_NAME_PARTS):
        score -= 40
    if any(tok in fn for tok in ("read_byte", "read_word", "recv", "rx", "packet", "transceive", "parse")):
        score += 10
    if any(tok in fn for tok in ("frame", "fifo")):
        score += 6

    if offset in {0x00, 0x08, 0x10, 0x14, 0x18, 0x1C}:
        score -= 10
    if offset in {0x04, 0x0C}:
        score += 10
    if any(tok in fn for tok in ("frame", "packet", "fifo")) and offset == 0x00:
        score += 12
    if any(tok in fn for tok in ("frame", "packet", "fifo")) and offset in {0x14, 0x18, 0x1C}:
        score -= 8

    root_kind = str((active_root or {}).get("kind", "")).lower()
    expr_low = str(expr or "").lower()
    if root_kind in {"length", "src_ptr", "src_data"}:
        if label in {"DMA_BACKED_BUFFER", "ISR_FILLED_BUFFER"}:
            score += 20
        if "dma" in expr_low and label == "DMA_BACKED_BUFFER":
            score += 15
        if "rx" in expr_low and ("rx" in fn or offset in {0x04, 0x0C}):
            score += 5
    if _is_system_mmio_address(addr):
        score -= 60
    return score


def _code_calls_function(code: str, fn_name: str) -> bool:
    if not code or not fn_name:
        return False
    pat = r"\b" + re.escape(str(fn_name)) + r"\s*\("
    return re.search(pat, str(code)) is not None


def _make_bridge_step(via_function: str, sink_function: str) -> Dict[str, Any]:
    return {
        "kind": "BRIDGE",
        "bridge_type": "CALLER_BRIDGE",
        "from_function": via_function,
        "to_function": sink_function,
        "evidence_refs": [],
    }


def _make_bridge_steps(path: Sequence[str], sink_function: str) -> List[Dict[str, Any]]:
    if not path:
        return []
    ordered = list(reversed([str(p) for p in path if str(p)]))
    steps: List[Dict[str, Any]] = []
    prev = ordered[0]
    for nxt in ordered[1:]:
        steps.append(_make_bridge_step(prev, nxt))
        prev = nxt
    steps.append(_make_bridge_step(prev, sink_function))
    return steps


def _edges_by_object(edges: Sequence[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in edges:
        out[str(e.get("object_id", ""))].append(e)
    for obj_id, lst in out.items():
        lst.sort(key=lambda x: float(x.get("score", 0.0)), reverse=True)
    return dict(out)


def _sources_by_function(sources: Sequence[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for s in sources:
        out[str(s.get("function_name", ""))].append(s)
    for fn, rows in out.items():
        out[fn] = sorted((dict(r) for r in rows), key=lambda src: _source_sort_key(src))
    return dict(out)


def _accesses_by_function(mai: Any) -> Dict[str, List[Any]]:
    out: Dict[str, List[Any]] = defaultdict(list)
    if mai is None:
        return {}
    for a in getattr(mai, "accesses", []) or []:
        fn = str(getattr(a, "function_name", "") or "")
        out[fn].append(a)
    return dict(out)


def _pick_producer_fn(obj: Dict[str, Any], src_context: str, fallback: str) -> str:
    for ws in obj.get("writer_sites", []) or []:
        if str(ws.get("context", "")) == src_context and ws.get("fn"):
            return str(ws.get("fn"))
    writers = obj.get("writers", []) or []
    if writers:
        return str(writers[0])
    return fallback


def _object_for_addr(addr: int, objects_by_id: Dict[str, Dict[str, Any]]) -> Optional[str]:
    for obj_id, obj in objects_by_id.items():
        rng = obj.get("addr_range", [])
        if not isinstance(rng, list) or len(rng) != 2:
            continue
        start = _parse_hex(str(rng[0]))
        end = _parse_hex(str(rng[1]))
        if start <= addr <= end:
            return obj_id
    return None


def _first_primary_root_expr(roots: List[Dict[str, Any]]) -> str:
    for r in roots:
        if str(r.get("role", "")) == "primary":
            return str(r.get("expr", ""))
    if roots:
        return str(roots[0].get("expr", ""))
    return ""


def _first_linkable_root(roots: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    ordered = _ordered_roots(roots, sink_label="")
    return ordered[0] if ordered else None


def _initial_states_for_sink(sink_root: Dict[str, Any], *, sink_label: str, sink_fn: str) -> List[Dict[str, Any]]:
    ordered_roots = _ordered_roots(list(sink_root.get("roots", []) or []), sink_label=sink_label)
    if not ordered_roots:
        ordered_roots = [{"role": "primary", "expr": "UNKNOWN", "kind": "unknown", "source": "none"}]

    states: List[Dict[str, Any]] = []
    max_roots = max(4, min(8, len(ordered_roots)))
    for idx, root in enumerate(ordered_roots[:max_roots]):
        expr = str(root.get("expr", "") or "UNKNOWN")
        states.append({
            "current_fn": sink_fn,
            "expr": expr,
            "active_root": dict(root),
            "all_roots": list(ordered_roots),
            "depth": 0,
            "channel_steps": [],
            "object_history": tuple(),
            "state_score": max(0.35, 0.55 - 0.03 * idx + _root_seed_bonus(root, sink_label=sink_label)),
            "tunnel_attempts": 0,
            "producer_candidates": tuple(),
        })
    return states


def _ordered_roots(roots: List[Dict[str, Any]], *, sink_label: str) -> List[Dict[str, Any]]:
    ranked = []
    for root in roots:
        expr = str(root.get("expr", "") or "")
        if not expr:
            continue
        ranked.append((_root_priority(root, sink_label=sink_label), dict(root)))
    ranked.sort(key=lambda item: item[0], reverse=True)
    return [root for _, root in ranked]


def _root_priority(root: Dict[str, Any], *, sink_label: str) -> float:
    role = str(root.get("role", "")).lower()
    kind = str(root.get("kind", "")).lower()
    expr = str(root.get("expr", "") or "")
    score = 0.0

    if sink_label == "COPY_SINK":
        if kind == "length":
            score += 2.4
        elif kind in {"src_ptr", "src_data"}:
            score += 1.6
        elif kind == "dst_ptr":
            score += 0.9
    elif sink_label == "STORE_SINK":
        if kind in {"dst_ptr", "target_addr"}:
            score += 1.8
    elif sink_label == "LOOP_WRITE_SINK":
        if kind in {"dst_ptr", "target_addr"}:
            score += 1.7
        elif kind == "index_or_bound":
            score += 1.3
    elif sink_label == "MEMSET_SINK":
        if kind == "length":
            score += 1.6
        elif kind == "dst_ptr":
            score += 1.2
    elif sink_label == "FORMAT_STRING_SINK":
        if kind == "format_arg":
            score += 1.8
    elif sink_label == "FUNC_PTR_SINK":
        if kind == "dispatch":
            score += 1.8

    if role == "primary":
        score += 0.4
    if not _looks_constant_expr(expr):
        score += 0.2
    return score


def _root_seed_bonus(root: Dict[str, Any], *, sink_label: str) -> float:
    expr = str(root.get("expr", "") or "")
    kind = str(root.get("kind", "")).lower()
    bonus = 0.0
    if sink_label == "COPY_SINK" and kind == "length":
        bonus += 0.08
    elif sink_label == "COPY_SINK" and kind in {"src_ptr", "src_data"}:
        bonus += 0.08
    if not _looks_constant_expr(expr):
        bonus += 0.02
    return bonus


def _build_link_debug(
    sink_root: Dict[str, Any],
    st: Dict[str, Any],
    slice_res: Optional[Dict[str, Any]],
    object_hits: Sequence[str],
    failure_code: str,
) -> Dict[str, Any]:
    slice_res = slice_res or {}
    return {
        "root_source": str((st.get("active_root") or {}).get("source", "") or sink_root.get("root_source", "none")),
        "active_root_expr": str((st.get("active_root") or {}).get("expr", "")),
        "active_root_role": str((st.get("active_root") or {}).get("role", "")),
        "active_root_kind": str((st.get("active_root") or {}).get("kind", "")),
        "object_hit_mode": str(slice_res.get("object_hit_mode", "none")),
        "source_resolve_mode": str(slice_res.get("source_resolve_mode", "none")),
        "bridge_functions": [
            str(step.get("from_function", ""))
            for step in (slice_res.get("bridge_steps", []) or [])
            if str(step.get("kind", "")) == "BRIDGE"
        ],
        "object_hits": list(object_hits),
        "channel_required_hint": bool(slice_res.get("channel_required_hint", False)),
        "tunnel_attempts": int(st.get("tunnel_attempts", 0)),
        "producer_candidates": list(st.get("producer_candidates", ())),
        "failure_stage": _failure_stage(failure_code or str(slice_res.get("failure_code", ""))),
    }


def _failure_stage(failure_code: str) -> str:
    code = str(failure_code or "")
    if code.startswith("ROOT_"):
        return "root"
    if code.startswith("OBJECT_"):
        return "object"
    if code.startswith("SOURCE_") or code.startswith("PRODUCER_"):
        return "source"
    if code.startswith("MAX_DEPTH") or code.startswith("BUDGET"):
        return "search"
    if code.startswith("CHECK_"):
        return "check"
    if code:
        return "link"
    return "none"


def _is_unresolved_expr(expr: str) -> bool:
    return str(expr or "").strip() in _GENERIC_ROOT_MARKERS


def _next_state_score(st: Dict[str, Any], *, edge_score: float) -> float:
    base = float(st.get("state_score", 0.5))
    depth_penalty = 0.05 * float(st.get("depth", 0) + 1)
    return max(0.0, min(1.0, base + 0.15 * max(0.0, min(1.0, edge_score)) - depth_penalty))


def _state_key(st: Dict[str, Any]) -> Tuple[str, str, int, Tuple[str, ...]]:
    return (
        str(st.get("current_fn", "")),
        _norm_expr(str(st.get("expr", ""))),
        int(st.get("depth", 0)),
        tuple(st.get("object_history", ())),
    )


def _norm_expr(expr: str) -> str:
    return re.sub(r"\s+", "", str(expr or "")).lower()


def _sink_site_key(site_hex: str, fn: str, label: str) -> str:
    return f"{site_hex}|{fn}|{label}"


def _make_chain_id(
    *,
    binary_stem: str,
    sink_root: Dict[str, Any],
    active_root: Optional[Dict[str, Any]],
    source: Optional[Dict[str, Any]],
    source_resolve_mode: str,
    bridge_steps: Sequence[Dict[str, Any]],
    channel_steps: Sequence[Dict[str, Any]],
) -> str:
    root = active_root or {}
    digest_src = "|".join([
        str(sink_root.get("sink_id", "")),
        str(root.get("role", "")),
        str(root.get("kind", "")),
        _norm_expr(str(root.get("expr", ""))),
        str(source_resolve_mode or ""),
        str((source or {}).get("function_name", "")),
        ",".join(str(step.get("from_function", "")) for step in bridge_steps),
        ",".join(str(step.get("edge", "")) + ":" + str(step.get("object_id", "")) for step in channel_steps),
    ])
    variant = hashlib.md5(digest_src.encode("utf-8")).hexdigest()[:8]
    return f"chain_{binary_stem}_{sink_root['sink_id']}_{variant}"


def _looks_constant_expr(expr: str) -> bool:
    expr = str(expr or "").strip()
    if not expr:
        return True
    return bool(re.fullmatch(r"(?:0x[0-9a-fA-F]+|\d+)", expr))


def _chain_score(
    *,
    sink_conf: float,
    source_reached: bool,
    has_channel: bool,
    check_strength: str,
    root_controllable: bool,
) -> float:
    score = 0.25 + 0.35 * max(0.0, min(1.0, sink_conf))
    if source_reached:
        score += 0.20
    if has_channel:
        score += 0.10

    if check_strength in {"absent", "weak"}:
        score += 0.15
    elif check_strength == "effective":
        score -= 0.15

    if root_controllable:
        score += 0.05

    return round(max(0.0, min(1.0, score)), 4)


def _decide_verdict(
    *,
    sink_label: str,
    active_root_kind: str,
    source_reached: bool,
    root_controllable: bool,
    check_strength: str,
    chain_complete: bool,
    has_contradiction: bool,
    has_app_anchor: bool,
    control_path_only: bool,
    chain_score: float,
    source_resolve_mode: str,
    secondary_root_only: bool,
    channel_required_hint: bool,
    has_channel: bool,
) -> Tuple[str, Dict[str, Any]]:
    confirm_threshold = 0.80
    if str(active_root_kind or "").lower() in {"format_arg", "dispatch"}:
        confirm_threshold = 0.75
    if str(source_resolve_mode or "") in {"caller_bridge", "nested_caller_bridge", "transitive_caller_bridge"}:
        confirm_threshold = min(confirm_threshold, 0.78)

    decision_basis = {
        "sink_label": str(sink_label or ""),
        "active_root_kind": str(active_root_kind or ""),
        "source_reached": bool(source_reached),
        "root_controllable": bool(root_controllable),
        "check_strength": str(check_strength or "unknown"),
        "chain_complete": bool(chain_complete),
        "has_contradiction": bool(has_contradiction),
        "has_app_anchor": bool(has_app_anchor),
        "control_path_only": bool(control_path_only),
        "chain_score": float(chain_score or 0.0),
        "source_resolve_mode": str(source_resolve_mode or ""),
        "secondary_root_only": bool(secondary_root_only),
        "channel_required_hint": bool(channel_required_hint),
        "has_channel": bool(has_channel),
        "confirm_threshold": float(confirm_threshold),
        "reason_code": "UNKNOWN",
    }

    if has_contradiction:
        decision_basis["reason_code"] = "HARD_CONTRADICTION"
        return "DROP", decision_basis
    if control_path_only:
        decision_basis["reason_code"] = "CONTROL_PATH_ONLY"
        return "DROP", decision_basis
    if secondary_root_only:
        decision_basis["reason_code"] = "SECONDARY_ROOT_ONLY"
        return "DROP", decision_basis
    if channel_required_hint and not has_channel and not _is_strong_source_mode(source_resolve_mode):
        decision_basis["reason_code"] = "CHANNEL_REQUIRED_MISSING"
        return "DROP", decision_basis

    if (
        _is_confirmable_root_kind(sink_label, active_root_kind)
        and source_reached
        and root_controllable
        and check_strength == "absent"
        and chain_complete
        and not has_contradiction
        and has_app_anchor
        and chain_score >= confirm_threshold
    ):
        decision_basis["reason_code"] = "ABSENT_GUARD_CONTROLLABLE_ROOT"
        return "CONFIRMED", decision_basis

    if check_strength == "effective" and has_app_anchor:
        decision_basis["reason_code"] = "EFFECTIVE_GUARD_PRESENT"
        return "SAFE_OR_LOW_RISK", decision_basis

    if chain_score < 0.45:
        decision_basis["reason_code"] = "LOW_CHAIN_SCORE"
        return "DROP", decision_basis
    if not has_app_anchor:
        decision_basis["reason_code"] = "NO_APP_ANCHOR"
        return "DROP", decision_basis

    if check_strength == "unknown":
        decision_basis["reason_code"] = "CHECK_UNCERTAIN"
    else:
        decision_basis["reason_code"] = "SEMANTIC_REVIEW_NEEDED"
    return "SUSPICIOUS", decision_basis


def _is_control_root_expr(expr: str, root_kind: str) -> bool:
    kind = str(root_kind or "").lower()
    if kind not in {"dst_ptr", "dispatch", "funcptr"}:
        return False
    cleaned = re.sub(r"[^A-Za-z0-9_]", "", str(expr or "")).lower()
    if not cleaned:
        return False
    if cleaned in _CONTROL_ROOT_NAMES:
        return True
    return any(cleaned.startswith(name) for name in _CONTROL_ROOT_NAMES)


def _is_init_like_function(func_name: str) -> bool:
    lowered = str(func_name or "").lower()
    if not lowered:
        return False
    return any(part in lowered for part in _INIT_LIKE_NAME_PARTS)


def _is_weak_bridge_function(func_name: str) -> bool:
    lowered = str(func_name or "").lower()
    if not lowered:
        return False
    return any(part in lowered for part in _WEAK_BRIDGE_NAME_PARTS)


def _is_weak_source_function(func_name: str) -> bool:
    lowered = str(func_name or "").lower()
    if not lowered:
        return False
    return any(part in lowered for part in _WEAK_SOURCE_NAME_PARTS)


def _is_system_mmio_address(addr: int) -> bool:
    if addr <= 0:
        return False
    return 0xE0000000 <= addr <= 0xE00FFFFF


def _source_address_int(source: Dict[str, Any]) -> int:
    try:
        return int(source.get("address", 0) or 0)
    except Exception:
        return 0


def _is_weak_source_anchor(
    source: Dict[str, Any],
    *,
    source_resolve_mode: str,
    object_hit_mode: str,
    active_root_kind: str,
    has_channel: bool,
) -> bool:
    label = str(source.get("label", "") or "")
    fn = str(source.get("function_name", "") or "")
    addr = _source_address_int(source)
    source_mode = str(source_resolve_mode or "").lower()
    root_kind = str(active_root_kind or "").lower()
    hit_mode = str(object_hit_mode or "").lower()

    if label == "MMIO_READ" and _is_system_mmio_address(addr):
        return True
    if _is_weak_source_function(fn) and source_mode in {"caller_bridge", "nested_caller_bridge", "transitive_caller_bridge"}:
        return True
    if label in {"MMIO_READ", "DMA_BACKED_BUFFER", "ISR_MMIO_READ"} and _is_init_like_function(fn):
        if source_mode in {"caller_bridge", "nested_caller_bridge", "transitive_caller_bridge"}:
            return True
        if hit_mode in _WEAK_OBJECT_HIT_MODES:
            return True
        if root_kind in {"dst_ptr", "src_ptr", "target_addr"} and has_channel:
            return True
    return False


def _is_strong_source_mode(source_mode: str) -> bool:
    return str(source_mode or "") in {
        "same_function",
        "same_context_direct_call",
    }


def _is_actionable_source_mode(source_mode: str, *, has_channel: bool) -> bool:
    if has_channel:
        return True
    return str(source_mode or "") in {
        "same_function",
        "same_context_direct_call",
        "nested_caller_bridge",
        "transitive_caller_bridge",
        "singleton_fallback",
    }


def _is_confirmable_root_kind(sink_label: str, active_root_kind: str) -> bool:
    label = str(sink_label or "")
    kind = str(active_root_kind or "").lower()

    if label == "COPY_SINK":
        return kind in {"length", "index_or_bound"}
    if label == "MEMSET_SINK":
        return kind in {"length"}
    if label == "STORE_SINK":
        return kind in {"dst_ptr", "target_addr", "index_or_bound"}
    if label == "LOOP_WRITE_SINK":
        return kind in {"index_or_bound", "target_addr", "dst_ptr"}
    if label == "FORMAT_STRING_SINK":
        return kind == "format_arg"
    if label == "FUNC_PTR_SINK":
        return kind == "dispatch"
    return False


def _should_prefer_tunnel(
    st: Dict[str, Any],
    slice_res: Dict[str, Any],
    object_hits: Sequence[str],
    edges_by_object: Dict[str, List[Dict[str, Any]]],
) -> bool:
    if not object_hits:
        return False
    source_mode = str(slice_res.get("source_resolve_mode", "none"))
    if source_mode == "same_function":
        return False
    for obj_id in object_hits:
        for edge in edges_by_object.get(obj_id, []):
            if str(edge.get("src_context", "")) in {"DMA", "ISR"}:
                return True
    return False


def _object_requires_channel(
    obj_id: str,
    edges_by_object: Dict[str, List[Dict[str, Any]]],
) -> bool:
    for edge in edges_by_object.get(obj_id, []):
        if str(edge.get("src_context", "")) in {"DMA", "ISR"}:
            return True
    return False


def _rank_context_objects(object_ids: Sequence[str], objects_by_id: Dict[str, Dict[str, Any]]) -> List[str]:
    scored: List[Tuple[float, str]] = []
    for obj_id in object_ids:
        obj = objects_by_id.get(obj_id, {})
        score = 1.0
        tf = dict(obj.get("type_facts", {}) or {})
        if str(tf.get("kind_hint", "")).lower() == "payload":
            score += 0.25
        if str(tf.get("source_label", "")).upper() in {"DMA_BACKED_BUFFER", "ISR_FILLED_BUFFER"}:
            score += 0.35
        if str(obj.get("region_kind", "")).upper() == "DMA_BUFFER":
            score += 0.25
        scored.append((score, obj_id))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [obj_id for _, obj_id in scored]


def _uniq_keep_order(items: Sequence[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _prune_redundant_chains(chains: List[Dict[str, Any]], *, max_chains_per_sink: int) -> List[Dict[str, Any]]:
    deduped_by_signature: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for chain in chains:
        if _should_skip_store_chain(chain):
            continue
        sig = (
            str(chain.get("sink", {}).get("label", "")),
            str(chain.get("sink", {}).get("function", "")),
            str(chain.get("sink", {}).get("root_expr", "")),
        )
        prev = deduped_by_signature.get(sig)
        if prev is None or _chain_keep_priority(chain) > _chain_keep_priority(prev):
            deduped_by_signature[sig] = chain

    by_sink: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for chain in deduped_by_signature.values():
        sink_id = str(chain.get("sink", {}).get("sink_id", ""))
        by_sink[sink_id].append(chain)

    kept: List[Dict[str, Any]] = []
    for _, group in by_sink.items():
        group.sort(key=_chain_keep_priority, reverse=True)
        if not group:
            continue
        if _should_drop_bridge_only_copy_group(group):
            continue
        non_drop_group = [chain for chain in group if chain.get("verdict") != "DROP"]
        if not non_drop_group:
            kept.append(group[0])
            continue
        if any(_chain_channel_required_hint(chain) for chain in non_drop_group):
            channel_non_drop = [chain for chain in non_drop_group if any(step.get("kind") == "CHANNEL" for step in chain.get("steps", []))]
            if channel_non_drop:
                non_drop_group = channel_non_drop
        remaining = max(1, int(max_chains_per_sink))
        kept_families: set[str] = set()
        for chain in non_drop_group:
            if remaining <= 0:
                break
            fam = _root_family_from_chain(chain)
            has_channel = any(step.get("kind") == "CHANNEL" for step in chain.get("steps", []))
            if fam in kept_families and not has_channel:
                continue
            if fam == "pointer" and _pointer_companion_redundant(chain, kept_families):
                continue
            kept.append(chain)
            kept_families.add(fam)
            remaining -= 1
    kept.sort(key=lambda c: c.get("chain_id", ""))
    return kept


def _serialize_root_bundle(
    *,
    active_root: Optional[Dict[str, Any]],
    all_roots: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen = set()
    active_canon = _norm_expr(str((active_root or {}).get("canonical_expr", "") or (active_root or {}).get("expr", "")))
    for idx, root in enumerate(all_roots or []):
        expr = str(root.get("expr", "") or "")
        canon = _norm_expr(str(root.get("canonical_expr", "") or expr))
        key = (
            canon or _norm_expr(expr),
            str(root.get("kind", "")).lower(),
            str(root.get("role", "")).lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        aliases = []
        for alias in root.get("aliases", []) or []:
            alias_norm = _norm_expr(str(alias))
            if alias_norm and alias_norm not in aliases:
                aliases.append(alias_norm)
        rows.append({
            "index": idx,
            "expr": expr,
            "canonical_expr": canon or _norm_expr(expr),
            "aliases": aliases,
            "kind": str(root.get("kind", "")),
            "role": str(root.get("role", "")),
            "family": _root_family_from_kind(str(root.get("kind", ""))),
            "source": str(root.get("source", "")),
            "active": bool(active_canon and active_canon == (canon or _norm_expr(expr))),
        })
    return rows


def _root_family_from_kind(kind: str) -> str:
    low = str(kind or "").lower()
    if low in {"length", "index_or_bound"}:
        return "length"
    if low == "format_arg":
        return "format_arg"
    if low == "dispatch":
        return "dispatch"
    if low in {"src_ptr", "src_data", "dst_ptr", "target_addr"}:
        return "pointer"
    return low or "unknown"


def _root_family_from_chain(chain: Dict[str, Any]) -> str:
    kind = str(chain.get("link_debug", {}).get("active_root_kind", "") or "")
    fam = _root_family_from_kind(kind)
    if fam != "unknown":
        return fam
    bundle = list(chain.get("root_bundle", []) or [])
    for row in bundle:
        fam = str(row.get("family", "") or "")
        if fam:
            return fam
    return "unknown"


def _chain_channel_required_hint(chain: Dict[str, Any]) -> bool:
    return bool(dict(chain.get("link_debug", {}) or {}).get("channel_required_hint", False))


def _pointer_companion_redundant(chain: Dict[str, Any], kept_families: set[str]) -> bool:
    sink_label = str(chain.get("sink", {}).get("label", "") or "")
    if sink_label in {"COPY_SINK", "MEMSET_SINK"}:
        return "length" in kept_families
    if sink_label in {"LOOP_WRITE_SINK", "STORE_SINK"}:
        return bool({"length", "index", "dispatch", "format_arg"} & kept_families)
    return bool({"length", "dispatch", "format_arg"} & kept_families)


def _is_secondary_root_only_chain(
    *,
    sink_label: str,
    active_root_kind: str,
    root_bundle: Sequence[Dict[str, Any]],
) -> bool:
    fam = _root_family_from_kind(active_root_kind)
    if fam != "pointer":
        return False
    bundle_families = {
        str(row.get("family", "") or "")
        for row in (root_bundle or [])
        if not bool(row.get("active", False))
    }
    if sink_label in {"COPY_SINK", "MEMSET_SINK"}:
        return "length" in bundle_families
    if sink_label in {"LOOP_WRITE_SINK", "STORE_SINK"}:
        return bool({"length", "index", "dispatch"} & bundle_families)
    return False


def _should_drop_bridge_only_copy_group(group: Sequence[Dict[str, Any]]) -> bool:
    if not group:
        return False
    if str(group[0].get("sink", {}).get("label", "")) != "COPY_SINK":
        return False

    root_kinds = {
        str(ch.get("link_debug", {}).get("active_root_kind", "")).lower()
        for ch in group
        if str(ch.get("verdict", "")) != "DROP"
    }
    if not root_kinds:
        return False
    if root_kinds & {"length", "index_or_bound"}:
        return False

    modes = {
        str(ch.get("link_debug", {}).get("source_resolve_mode", "")).lower()
        for ch in group
        if str(ch.get("verdict", "")) != "DROP"
    }
    if not modes or not modes <= {"caller_bridge", "nested_caller_bridge", "transitive_caller_bridge"}:
        return False

    for ch in group:
        if any(step.get("kind") == "CHANNEL" for step in ch.get("steps", [])):
            return False
    return True


def _should_skip_store_chain(chain: Dict[str, Any]) -> bool:
    sink = dict(chain.get("sink", {}) or {})
    if str(sink.get("label", "")) != "STORE_SINK":
        return False

    debug = dict(chain.get("link_debug", {}) or {})
    source_mode = str(debug.get("source_resolve_mode", "")).lower()
    root_kind = str(debug.get("active_root_kind", "")).lower()
    sink_fn = str(sink.get("function", "") or "").lower()

    if "irqhandler" in sink_fn or sink_fn.endswith("_irqhandler"):
        return root_kind in {"target_addr", "dst_ptr"}

    if source_mode in {"caller_bridge", "nested_caller_bridge", "transitive_caller_bridge"} and root_kind in {"target_addr", "dst_ptr"}:
        if not list(debug.get("object_hits", []) or []) and sink_fn.startswith("write_"):
            return True

    return False


def _chain_keep_priority(chain: Dict[str, Any]) -> Tuple[int, int, int, float]:
    verdict_rank = {
        "CONFIRMED": 4,
        "SAFE_OR_LOW_RISK": 3,
        "SUSPICIOUS": 2,
        "DROP": 1,
    }.get(str(chain.get("verdict", "")), 0)
    root_kind = str(chain.get("link_debug", {}).get("active_root_kind", ""))
    root_rank = 0
    if root_kind in {"length", "index_or_bound", "dispatch", "format_arg"}:
        root_rank = 3
    elif root_kind in {"src_ptr", "src_data"}:
        root_rank = 2
    elif root_kind in {"dst_ptr", "target_addr"}:
        root_rank = 1
    has_channel = 1 if any(step.get("kind") == "CHANNEL" for step in chain.get("steps", [])) else 0
    return (verdict_rank, has_channel, root_rank, float(chain.get("score", 0.0)))


def _collect_related_function_codes(
    *,
    sink_fn: str,
    bridge_steps: Sequence[Dict[str, Any]],
    decompiled_cache: Dict[str, str],
) -> List[Tuple[str, str]]:
    seen = {str(sink_fn)}
    out: List[Tuple[str, str]] = []
    for step in bridge_steps or []:
        if str(step.get("kind", "")) != "BRIDGE":
            continue
        from_fn = str(step.get("from_function", "") or "")
        if from_fn and from_fn not in seen:
            seen.add(from_fn)
            out.append((from_fn, str(decompiled_cache.get(from_fn, "") or "")))
    for caller_fn, caller_code in _find_callers(sink_fn, decompiled_cache):
        if caller_fn in seen:
            continue
        seen.add(caller_fn)
        out.append((caller_fn, caller_code))
    return out


def _hex_addr(v: Any) -> str:
    try:
        n = int(v or 0)
    except Exception:
        n = 0
    return f"0x{n:08x}"


def _parse_hex(text: str) -> int:
    try:
        return int(str(text or "0"), 16)
    except Exception:
        return 0
