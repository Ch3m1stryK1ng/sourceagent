"""Deterministic merge gates for Phase A.5 bounded supervision."""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from .supervision_queue import _CHANNEL_LABELS, _OBJECT_LABELS, _SINK_LABELS, _SOURCE_LABELS

SUPPORTED_LABELS = _SINK_LABELS | _SOURCE_LABELS | _OBJECT_LABELS | _CHANNEL_LABELS

_COPY_CALL_TOKENS = ("memcpy(", "memmove(", "strcpy(", "strncpy(", "sprintf(", "snprintf(")
_FORMAT_CALL_TOKENS = ("printf(", "sprintf(", "snprintf(", "fprintf(", "vsprintf(", "vsnprintf(")
_LOOP_TOKENS = ("for (", "for(", "while (", "while(", "do {", "do{")
_MMIO_TOKENS = ("0x400", "0x500", "->dr", "->sr", "uart", "usart", "spi", "i2c", "otg", "fifo")
_DMA_TOKENS = ("dma", "cmar", "cpar", "cndtr", "stream", "channel")
_OBJECT_REASON_SIGNAL_MAP = {
    "OBJECT_KIND_SUPPORTED": "object_kind",
    "OBJECT_SHARED_WRITER_READER": "shared_access",
    "OBJECT_RING_BUFFER_PATTERN": "ring_members",
    "OBJECT_FLAG_PATTERN": "flag_members",
}
_CHANNEL_REASON_SIGNAL_MAP = {
    "CHANNEL_EDGE_SUPPORTED": "edge_supported",
    "CHANNEL_ISR_MAIN": "isr_ctx",
    "CHANNEL_DMA_CPU": "dma_ctx",
    "CHANNEL_QUEUE_LIKE": "queue_pattern",
    "CHANNEL_RING_BUFFER_LIKE": "ring_members",
}


def apply_supervision_merge(
    *,
    binary_name: str,
    binary_sha256: str,
    supervision_queue: Mapping[str, Any],
    supervision_decisions: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    queue_items = {
        str(item.get("item_id", "") or ""): dict(item)
        for item in (supervision_queue or {}).get("items", []) or []
        if str(item.get("item_id", "") or "")
    }
    rows: List[Dict[str, Any]] = []
    verified_enriched: List[Dict[str, Any]] = []
    objects_enriched: List[Dict[str, Any]] = []
    channels_enriched: List[Dict[str, Any]] = []

    for raw in supervision_decisions or []:
        decision = dict(raw or {})
        item_id = str(decision.get("item_id", "") or "")
        queue_item = dict(queue_items.get(item_id, {}) or {})
        item_kind = str(queue_item.get("item_kind", "") or "sink")
        proposed_label = str(queue_item.get("proposed_label", "") or "")
        final_label = str(decision.get("final_label", "") or proposed_label or "").strip()
        parsed_decision = str(decision.get("decision", "") or "").strip().lower()
        gate = _evaluate_merge_gate(queue_item, decision, final_label)
        gate_level = str(gate.get("gate_level", "reject") or "reject")
        has_rationale = bool(decision.get("review_notes", "") or decision.get("reason_codes", []))
        strict_uncertain_soft = (
            parsed_decision == "uncertain"
            and gate_level == "strict_accept"
            and has_rationale
            and item_kind in {"object", "channel"}
        )
        accepted = parsed_decision == "accept" and gate_level == "strict_accept"
        soft_accepted = (
            (
                parsed_decision == "accept" and gate_level == "soft_accept"
            ) or (
                parsed_decision == "uncertain" and gate_level == "soft_accept" and has_rationale
            ) or strict_uncertain_soft
            or (
                parsed_decision == "accept"
                and gate_level == "strict_accept"
                and item_kind in {"object", "channel"}
                and bool(decision.get("reason_codes", []))
            )
        )
        audit_only = parsed_decision == "uncertain" and has_rationale and not soft_accepted
        merge_state = (
            "strictly_accepted"
            if accepted
            else (
                "soft_accepted"
                if soft_accepted
                else ("audit_only" if audit_only else ("unsupported_label" if gate["failure_code"] == "UNSUPPORTED_LABEL" else "rejected"))
            )
        )
        row = {
            "item_id": item_id,
            "item_kind": item_kind,
            "decision": parsed_decision,
            "proposed_label": proposed_label,
            "final_label": final_label,
            "accepted": accepted or soft_accepted,
            "merge_state": merge_state,
            "accept_reason": (
                    gate["accept_reason"]
                    if accepted
                    else (
                        gate["accept_reason"]
                        if strict_uncertain_soft
                        else (
                        gate.get("soft_accept_reason", "")
                        if soft_accepted
                        else ("audit_only_preserved" if audit_only else "")
                        )
                    )
                ),
            "failure_code": gate["failure_code"] if not accepted and not soft_accepted and not audit_only else "",
            "support_signals": list(gate.get("support_signals", []) or []),
            "gate_level": gate_level,
            "arg_roles": dict(decision.get("arg_roles", {}) or {}),
            "reason_codes": list(decision.get("reason_codes", []) or []),
            "evidence_map": dict(decision.get("evidence_map", {}) or {}),
            "review_notes": str(decision.get("review_notes", "") or ""),
            "confidence": float(decision.get("confidence", 0.0) or 0.0),
            "context": dict(queue_item.get("context", {}) or {}),
        }
        rows.append(row)

        if accepted or soft_accepted:
            enriched_row = {
                "item_id": item_id,
                "item_kind": item_kind,
                "label": final_label,
                "source": "phase_a5_supervision",
                "merge_state": merge_state,
                "arg_roles": dict(decision.get("arg_roles", {}) or {}),
                "confidence": float(decision.get("confidence", 0.0) or 0.0),
                "support_signals": list(gate.get("support_signals", []) or []),
                "context": dict(queue_item.get("context", {}) or {}),
                "reason_codes": list(decision.get("reason_codes", []) or []),
                "evidence_pack": dict(queue_item.get("evidence_pack", {}) or {}),
                "review_notes": str(decision.get("review_notes", "") or ""),
                "evidence_map": dict(decision.get("evidence_map", {}) or {}),
            }
            if item_kind in {"sink", "source"}:
                verified_enriched.append(enriched_row)
            elif item_kind == "object":
                objects_enriched.append(enriched_row)
            elif item_kind == "channel":
                channels_enriched.append(enriched_row)

    stats = {
        "queued": len(queue_items),
        "decided": len(rows),
        "accepted": sum(1 for row in rows if row.get("accepted")),
        "strictly_accepted": sum(1 for row in rows if row.get("merge_state") == "strictly_accepted"),
        "soft_accepted": sum(1 for row in rows if row.get("merge_state") == "soft_accepted"),
        "audit_only": sum(1 for row in rows if row.get("merge_state") == "audit_only"),
        "rejected": sum(1 for row in rows if row.get("merge_state") == "rejected"),
        "accepted_by_kind": _count_by_key(verified_enriched + objects_enriched + channels_enriched, "item_kind"),
        "accepted_by_label": _count_by_key(verified_enriched + objects_enriched + channels_enriched, "label"),
    }

    return {
        "supervision_merge": {
            "schema_version": "0.2",
            "binary": binary_name,
            "binary_sha256": binary_sha256,
            "status": "ok" if rows else ("empty" if queue_items else "not_run"),
            "items": rows,
            "stats": stats,
        },
        "verified_enriched": {
            "schema_version": "0.2",
            "binary": binary_name,
            "binary_sha256": binary_sha256,
            "status": "ok" if verified_enriched else ("empty" if rows else "not_run"),
            "items": verified_enriched,
            "stats": {
                "count": len(verified_enriched),
                "by_kind": _count_by_key(verified_enriched, "item_kind"),
                "by_label": _count_by_key(verified_enriched, "label"),
            },
        },
        "objects_enriched": {
            "schema_version": "0.2",
            "binary": binary_name,
            "binary_sha256": binary_sha256,
            "status": "ok" if objects_enriched else ("empty" if rows else "not_run"),
            "items": objects_enriched,
            "stats": {
                "count": len(objects_enriched),
                "by_label": _count_by_key(objects_enriched, "label"),
            },
        },
        "channels_enriched": {
            "schema_version": "0.2",
            "binary": binary_name,
            "binary_sha256": binary_sha256,
            "status": "ok" if channels_enriched else ("empty" if rows else "not_run"),
            "items": channels_enriched,
            "stats": {
                "count": len(channels_enriched),
                "by_label": _count_by_key(channels_enriched, "label"),
            },
        },
    }


def _evaluate_merge_gate(
    queue_item: Mapping[str, Any],
    decision: Mapping[str, Any],
    final_label: str,
) -> Dict[str, Any]:
    item_kind = str(queue_item.get("item_kind", "") or "sink")
    if final_label not in SUPPORTED_LABELS:
        return {
            "accepted": False,
            "failure_code": "UNSUPPORTED_LABEL",
            "accept_reason": "",
            "support_signals": [],
        }
    if item_kind == "sink":
        return _evaluate_sink_merge_gate(queue_item, decision, final_label)
    if item_kind == "source":
        return _evaluate_source_merge_gate(queue_item, decision, final_label)
    if item_kind == "object":
        return _evaluate_object_merge_gate(queue_item, decision, final_label)
    if item_kind == "channel":
        return _evaluate_channel_merge_gate(queue_item, decision, final_label)
    return {
        "accepted": False,
        "failure_code": "UNSUPPORTED_KIND",
        "accept_reason": "",
        "support_signals": [],
    }


def _evaluate_sink_merge_gate(
    queue_item: Mapping[str, Any],
    decision: Mapping[str, Any],
    final_label: str,
) -> Dict[str, Any]:
    if final_label not in _SINK_LABELS:
        return _unsupported_label()
    evidence_pack = dict(queue_item.get("evidence_pack", {}) or {})
    snippets = dict(evidence_pack.get("decompiled_snippets", {}) or {})
    sink_hints = dict(evidence_pack.get("sink_semantics_hints", {}) or {})
    sink_facts = dict(evidence_pack.get("sink_facts", {}) or {})
    arg_roles = dict(decision.get("arg_roles", {}) or {})
    combined = _combined_text(snippets)
    support_signals: List[str] = []

    if final_label == "COPY_SINK":
        if any(tok in combined for tok in _COPY_CALL_TOKENS):
            support_signals.append("copy_primitive")
        if _looks_like_copy_loop(combined):
            support_signals.append("copy_loop")
        if any(k in arg_roles for k in ("len", "size", "dst", "src")):
            support_signals.append("arg_roles")
        if any(str(sink_hints.get(k, "") or "").strip() for k in ("len_expr", "dst_expr", "src_expr")):
            support_signals.append("sink_hints")
    elif final_label == "LOOP_WRITE_SINK":
        if any(tok in combined for tok in _LOOP_TOKENS):
            support_signals.append("loop_detected")
        if _looks_like_store_loop(combined):
            support_signals.append("store_pattern")
        if any(k in arg_roles for k in ("index", "bound", "dst", "len")):
            support_signals.append("arg_roles")
    elif final_label == "STORE_SINK":
        if _looks_like_store_loop(combined):
            support_signals.append("store_pattern")
        if any(k in arg_roles for k in ("dst", "index", "offset", "src")):
            support_signals.append("arg_roles")
        if any(str(sink_hints.get(k, "") or "").strip() for k in ("dst_expr", "target_expr", "offset_expr", "base_expr")):
            support_signals.append("sink_hints")
    elif final_label == "MEMSET_SINK":
        if "memset(" in combined:
            support_signals.append("memset_primitive")
        if any(k in arg_roles for k in ("dst", "len", "size")):
            support_signals.append("arg_roles")
        if any(str(sink_hints.get(k, "") or "").strip() for k in ("len_expr", "dst_expr")):
            support_signals.append("sink_hints")
    elif final_label == "FORMAT_STRING_SINK":
        if any(tok in combined for tok in _FORMAT_CALL_TOKENS):
            support_signals.append("format_primitive")
        if any(k in arg_roles for k in ("fmt", "format")):
            support_signals.append("arg_roles")
        if sink_hints.get("format_arg_variable"):
            support_signals.append("format_variable")
    elif final_label == "FUNC_PTR_SINK":
        if "(*" in combined or _looks_like_dispatch_call(combined):
            support_signals.append("indirect_call")
        if any(k in arg_roles for k in ("dispatch", "index", "target")):
            support_signals.append("arg_roles")

    if any(bool(v) for v in sink_facts.values()):
        support_signals.append("sink_facts")
    signal_count = len(set(support_signals))
    if signal_count >= 2:
        return _gate_result(True, support_signals, "deterministic_sink_gate")
    if signal_count >= 1:
        return _soft_gate_result(support_signals, "semantic_sink_soft_gate")
    return _gate_result(False, support_signals, "deterministic_sink_gate")


def _evaluate_source_merge_gate(
    queue_item: Mapping[str, Any],
    decision: Mapping[str, Any],
    final_label: str,
) -> Dict[str, Any]:
    if final_label not in _SOURCE_LABELS:
        return _unsupported_label()
    evidence_pack = dict(queue_item.get("evidence_pack", {}) or {})
    source_facts = dict(evidence_pack.get("source_facts", {}) or {})
    snippets = dict(evidence_pack.get("decompiled_snippets", {}) or {})
    evidence = [str(v) for v in (evidence_pack.get("candidate_evidence", []) or []) if str(v)]
    combined = _combined_text(snippets, evidence)
    ctx = dict(queue_item.get("context", {}) or {})
    support_signals: List[str] = []

    if final_label == "MMIO_READ":
        if any(tok in combined for tok in _MMIO_TOKENS) or int(_parse_addr(ctx.get("target_addr")) or 0) >= 0x40000000:
            support_signals.append("mmio_address")
        if source_facts.get("wrapper_like") or "read" in str(ctx.get("function", "")).lower():
            support_signals.append("wrapper_like")
    elif final_label == "ISR_MMIO_READ":
        if bool(ctx.get("in_isr")):
            support_signals.append("isr_context")
        if any(tok in combined for tok in _MMIO_TOKENS):
            support_signals.append("mmio_address")
    elif final_label == "DMA_BACKED_BUFFER":
        if any(tok in combined for tok in _DMA_TOKENS) or source_facts.get("dma_like"):
            support_signals.append("dma_config")
        if source_facts.get("buffer_addr") or source_facts.get("sram_addr"):
            support_signals.append("buffer_binding")
    elif final_label == "ISR_FILLED_BUFFER":
        if bool(ctx.get("in_isr")) or source_facts.get("shared_buffer_like"):
            support_signals.append("shared_buffer")
        if any(tok in combined for tok in ("head", "tail", "buf[", "ring")):
            support_signals.append("ring_buffer")

    if evidence:
        support_signals.append("candidate_evidence")
    signal_count = len(set(support_signals))
    if signal_count >= 2:
        return _gate_result(True, support_signals, "deterministic_source_gate")
    if signal_count >= 1:
        return _soft_gate_result(support_signals, "semantic_source_soft_gate")
    return _gate_result(False, support_signals, "deterministic_source_gate")


def _evaluate_object_merge_gate(
    queue_item: Mapping[str, Any],
    decision: Mapping[str, Any],
    final_label: str,
) -> Dict[str, Any]:
    if final_label not in _OBJECT_LABELS:
        return _unsupported_label()
    evidence_pack = dict(queue_item.get("evidence_pack", {}) or {})
    members = [str(v).lower() for v in (evidence_pack.get("members", []) or [])]
    type_facts = dict(evidence_pack.get("type_facts", {}) or {})
    writers = list(evidence_pack.get("writer_sites", []) or evidence_pack.get("writers", []) or [])
    readers = list(evidence_pack.get("reader_sites", []) or evidence_pack.get("readers", []) or [])
    combined = _combined_text(dict(evidence_pack.get("decompiled_snippets", {}) or {}))
    context = dict(queue_item.get("context", {}) or {})
    reason_codes = {str(v).strip().upper() for v in (decision.get("reason_codes", []) or []) if str(v).strip()}
    confidence = float(decision.get("confidence", 0.0) or 0.0)
    support_signals: List[str] = []
    if final_label in {"SRAM_CLUSTER", "DMA_BUFFER", "FLAG", "GLOBAL_SYMBOL", "RODATA_TABLE"}:
        support_signals.append("object_kind")
    if writers and readers:
        support_signals.append("shared_access")
    if final_label == "DMA_BUFFER" and str(type_facts.get("source_label", "")).upper() == "DMA_BACKED_BUFFER":
        support_signals.append("dma_source")
    if final_label == "FLAG" and any(tok in " ".join(members) for tok in ("flag", "ready", "done")):
        support_signals.append("flag_members")
    if final_label == "RING_BUFFER" and ("head" in " ".join(members) and "tail" in " ".join(members)):
        support_signals.append("ring_members")
    if final_label == "QUEUE_OBJECT" and any(tok in combined for tok in ("queue", "fifo", "msgq")):
        support_signals.append("queue_pattern")
    if context.get("addr_range"):
        support_signals.append("addr_range")
    if context.get("producer_contexts") or context.get("consumer_contexts"):
        support_signals.append("ctx_roles")
    if any(k in type_facts for k in ("source_label", "buffer_size", "capacity", "array_like", "condition_sites")):
        support_signals.append("type_facts")
    support_signals.extend(_reason_signals(reason_codes, _OBJECT_REASON_SIGNAL_MAP))
    signal_count = len(set(support_signals))
    if signal_count >= 2 or (signal_count >= 1 and confidence >= 0.8 and bool(reason_codes)):
        return _gate_result(True, support_signals, "deterministic_object_gate")
    if signal_count >= 1 or (confidence >= 0.7 and bool(reason_codes)):
        return _soft_gate_result(support_signals, "semantic_object_soft_gate")
    return _gate_result(False, support_signals, "deterministic_object_gate")


def _evaluate_channel_merge_gate(
    queue_item: Mapping[str, Any],
    decision: Mapping[str, Any],
    final_label: str,
) -> Dict[str, Any]:
    if final_label not in _CHANNEL_LABELS:
        return _unsupported_label()
    evidence_pack = dict(queue_item.get("evidence_pack", {}) or {})
    ctx = dict(queue_item.get("context", {}) or {})
    members = [str(v).lower() for v in (evidence_pack.get("object_members", []) or [])]
    combined = _combined_text(dict(evidence_pack.get("decompiled_snippets", {}) or {}))
    src = str(ctx.get("src_context", "") or "UNKNOWN")
    dst = str(ctx.get("dst_context", "") or "UNKNOWN")
    reason_codes = {str(v).strip().upper() for v in (decision.get("reason_codes", []) or []) if str(v).strip()}
    confidence = float(decision.get("confidence", 0.0) or 0.0)
    support_signals: List[str] = []

    if final_label == "DMA_CHANNEL" and src == "DMA":
        support_signals.append("dma_ctx")
    if final_label == "ISR_SHARED_CHANNEL" and src == "ISR" and dst in {"MAIN", "TASK"}:
        support_signals.append("isr_ctx")
    if final_label == "RING_BUFFER_CHANNEL" and ("head" in " ".join(members) and "tail" in " ".join(members)):
        support_signals.append("ring_members")
    if final_label == "QUEUE_CHANNEL" and any(tok in combined for tok in ("queue", "fifo", "msgq")):
        support_signals.append("queue_pattern")
    if final_label == "DATA":
        support_signals.append("data_edge")
    if evidence_pack.get("writer_sites") and evidence_pack.get("reader_sites"):
        support_signals.append("writer_reader")
    if src != "UNKNOWN" and dst != "UNKNOWN":
        support_signals.append("ctx_pair")
    if ctx.get("object_id"):
        support_signals.append("object_bound")
    if evidence_pack.get("edge_constraints"):
        support_signals.append("edge_constraints")
    support_signals.extend(_reason_signals(reason_codes, _CHANNEL_REASON_SIGNAL_MAP))
    signal_count = len(set(support_signals))
    if signal_count >= 2 or (signal_count >= 1 and confidence >= 0.8 and bool(reason_codes)):
        return _gate_result(True, support_signals, "deterministic_channel_gate")
    if signal_count >= 1 or (confidence >= 0.7 and bool(reason_codes)):
        return _soft_gate_result(support_signals, "semantic_channel_soft_gate")
    return _gate_result(False, support_signals, "deterministic_channel_gate")


def _gate_result(accepted: bool, support_signals: Sequence[str], accept_reason: str) -> Dict[str, Any]:
    return {
        "accepted": bool(accepted),
        "gate_level": "strict_accept" if accepted else "reject",
        "failure_code": "" if accepted else "GATE_NOT_SATISFIED",
        "accept_reason": accept_reason if accepted else "",
        "soft_accept_reason": "",
        "support_signals": sorted(set(str(v) for v in support_signals if str(v))),
    }


def _soft_gate_result(support_signals: Sequence[str], soft_accept_reason: str) -> Dict[str, Any]:
    return {
        "accepted": False,
        "gate_level": "soft_accept",
        "failure_code": "",
        "accept_reason": "",
        "soft_accept_reason": soft_accept_reason,
        "support_signals": sorted(set(str(v) for v in support_signals if str(v))),
    }


def _unsupported_label() -> Dict[str, Any]:
    return {
        "accepted": False,
        "gate_level": "reject",
        "failure_code": "UNSUPPORTED_LABEL",
        "accept_reason": "",
        "soft_accept_reason": "",
        "support_signals": [],
    }


def _combined_text(*parts: Any) -> str:
    chunks: List[str] = []
    for value in parts:
        if isinstance(value, Mapping):
            chunks.extend(str(v or "") for v in value.values() if str(v or "").strip())
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            chunks.extend(str(v or "") for v in value if str(v or "").strip())
        else:
            if str(value or "").strip():
                chunks.append(str(value))
    return "\n\n".join(chunks).lower()


def _looks_like_copy_loop(text: str) -> bool:
    return bool(re.search(r"\[[^\]]+\]\s*=\s*[A-Za-z0-9_]+\[[^\]]+\]", text))


def _looks_like_store_loop(text: str) -> bool:
    return bool(re.search(r"\*[^=;]+\s*=\s*[^;]+", text) or re.search(r"\[[^\]]+\]\s*=\s*[^;]+", text))


def _looks_like_dispatch_call(text: str) -> bool:
    return bool(re.search(r"\(\*\s*[A-Za-z0-9_]+\s*\)\s*\(", text))


def _parse_addr(value: Any) -> int:
    try:
        return int(str(value or "0"), 16) if str(value).startswith("0x") else int(value or 0)
    except Exception:
        return 0


def _count_by_key(items: Iterable[Mapping[str, Any]], key: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for item in items:
        value = str(item.get(key, "") or "").strip()
        if not value:
            continue
        out[value] = out.get(value, 0) + 1
    return dict(sorted(out.items()))


def _reason_signals(reason_codes: Iterable[str], mapping: Mapping[str, str]) -> List[str]:
    out: List[str] = []
    for code in reason_codes or []:
        signal = mapping.get(str(code).strip().upper())
        if signal and signal not in out:
            out.append(signal)
    return out
