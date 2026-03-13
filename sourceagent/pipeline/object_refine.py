"""Object boundary refiner (M8.6).

Feature-based heuristics:
- split coarse objects into payload-like vs control-like parts when symbols exist
- infer subobject extent hints from addr_range, type facts, and access-site density
- preserve coarse objects when the evidence is too weak, but attach richer metadata
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


_RE_CTRL_MEMBER = re.compile(r"(?:head|tail|idx|index|flag|ready|done|state)", re.IGNORECASE)
_RE_PAYLOAD_MEMBER = re.compile(
    r"(?:buf|buffer|payload|data|pkt|packet|frame|msg|message|rx|tx|body|content)",
    re.IGNORECASE,
)


def derive_object_refinement_metadata(
    obj: Mapping[str, Any],
    access_traces: Iterable[Dict[str, Any]] = (),
) -> Dict[str, Any]:
    """Infer coarse object extent/subobject metadata without changing identity."""

    item = dict(obj)
    type_facts = dict(item.get("type_facts", {}) or {})
    members = [str(v) for v in (item.get("members", []) or []) if str(v).strip()]
    ctrl_members = [m for m in members if _RE_CTRL_MEMBER.search(m)]
    payload_members = [m for m in members if m not in ctrl_members]
    kind_hint = str(type_facts.get("kind_hint", "") or "")

    writer_sites = _site_rows(item.get("writer_sites", []) or [], access_traces, obj_id=str(item.get("object_id", "") or ""))
    reader_sites = _site_rows(item.get("reader_sites", []) or [], access_traces, obj_id=str(item.get("object_id", "") or ""))
    writer_count = len(writer_sites)
    reader_count = len(reader_sites)
    cross_context = _cross_context_access(writer_sites, reader_sites)

    extent, extent_source = _object_extent(item, type_facts, member_count=len(members))
    meta: Dict[str, Any] = {
        "refine_status": "coarse",
        "byte_size_estimate": extent if extent is not None else "unknown",
        "byte_size_source": extent_source,
        "writer_site_count": writer_count,
        "reader_site_count": reader_count,
        "cross_context": bool(cross_context),
    }

    if payload_members:
        meta["payload_members"] = payload_members
    if ctrl_members:
        meta["control_members"] = ctrl_members

    if extent is not None:
        meta["extent_confidence"] = _extent_confidence(
            extent_source=extent_source,
            has_members=bool(members),
            writer_count=writer_count,
            reader_count=reader_count,
        )

    has_split = bool(ctrl_members and payload_members)
    payloadish = (
        kind_hint in {"payload", "payload_or_ctrl", "payload_like"}
        or bool(payload_members)
        or bool(writer_count and reader_count)
    )
    if has_split and extent is not None and extent >= 16:
        payload_extent, control_extent = _split_extent(
            extent,
            payload_members=payload_members,
            ctrl_members=ctrl_members,
            writer_count=writer_count,
            reader_count=reader_count,
        )
        payload_range = _subrange(item.get("addr_range", []), offset=0, size=payload_extent)
        control_range = _subrange(item.get("addr_range", []), offset=payload_extent, size=control_extent)
        meta.update(
            {
                "refine_status": "split_by_members",
                "payload_byte_size": payload_extent,
                "control_byte_size": control_extent,
                "payload_addr_range": payload_range,
                "control_addr_range": control_range,
            }
        )
    elif payloadish and extent is not None:
        meta["refine_status"] = "extent_inferred"
        meta["payload_byte_size"] = extent
        payload_range = _subrange(item.get("addr_range", []), offset=0, size=extent)
        if payload_range:
            meta["payload_addr_range"] = payload_range

    return meta


def refine_object_boundaries(
    raw_objects: Iterable[Dict[str, Any]],
    access_traces: Iterable[Dict[str, Any]] = (),
) -> List[Dict[str, Any]]:
    """Refine coarse object clusters.

    Input objects follow ObjectNode-like schema.
    Output keeps the same schema with optional splits.
    """
    refined: List[Dict[str, Any]] = []

    for obj in raw_objects:
        item = dict(obj)
        tf = dict(item.get("type_facts", {}) or {})
        meta = derive_object_refinement_metadata(item, access_traces)
        members = [str(v) for v in (item.get("members", []) or []) if str(v).strip()]
        ctrl_members = list(meta.get("control_members", []) or [])
        payload_members = list(meta.get("payload_members", []) or [])

        if not members or not ctrl_members or not payload_members:
            tf.update(meta)
            item["type_facts"] = tf
            refined.append(item)
            continue

        payload = dict(item)
        payload["object_id"] = f"{item.get('object_id', 'obj')}_payload"
        payload["members"] = payload_members
        payload["parent_object_id"] = str(item.get("object_id", "") or "")
        payload["region_kind"] = "SRAM_CLUSTER"
        payload_range = list(meta.get("payload_addr_range", []) or [])
        if payload_range:
            payload["addr_range"] = payload_range
        payload_tf = dict(tf)
        payload_tf.update(meta)
        payload_tf.update(
            {
                "kind_hint": "payload",
                "refine_status": str(meta.get("refine_status", "") or "split_by_members"),
                "byte_size_estimate": meta.get("payload_byte_size", meta.get("byte_size_estimate", "unknown")),
                "byte_size_source": "payload_subrange" if payload_range else meta.get("byte_size_source", "unknown"),
            }
        )
        payload["type_facts"] = payload_tf

        ctrl = dict(item)
        ctrl["object_id"] = f"{item.get('object_id', 'obj')}_ctrl"
        ctrl["members"] = ctrl_members
        ctrl["parent_object_id"] = str(item.get("object_id", "") or "")
        ctrl["region_kind"] = "FLAG"
        control_range = list(meta.get("control_addr_range", []) or [])
        if control_range:
            ctrl["addr_range"] = control_range
        ctrl_tf = dict(tf)
        ctrl_tf.update(meta)
        ctrl_tf.update(
            {
                "kind_hint": "control",
                "refine_status": str(meta.get("refine_status", "") or "split_by_members"),
                "byte_size_estimate": meta.get("control_byte_size", meta.get("byte_size_estimate", "unknown")),
                "byte_size_source": "control_subrange" if control_range else meta.get("byte_size_source", "unknown"),
            }
        )
        ctrl["type_facts"] = ctrl_tf

        refined.append(payload)
        refined.append(ctrl)

    return refined


def _site_rows(
    rows: Iterable[Mapping[str, Any]],
    access_traces: Iterable[Dict[str, Any]],
    *,
    obj_id: str,
) -> List[Dict[str, Any]]:
    out = [dict(row) for row in rows if isinstance(row, Mapping)]
    if out or not obj_id:
        return out
    for row in access_traces or ():
        item = dict(row or {})
        if str(item.get("object_id", "") or "") != obj_id:
            continue
        out.append(item)
    return out


def _cross_context_access(
    writer_sites: Iterable[Mapping[str, Any]],
    reader_sites: Iterable[Mapping[str, Any]],
) -> bool:
    writers = {
        str(row.get("context", "") or "").upper()
        for row in writer_sites
        if str(row.get("context", "") or "").strip()
    }
    readers = {
        str(row.get("context", "") or "").upper()
        for row in reader_sites
        if str(row.get("context", "") or "").strip()
    }
    writers.discard("UNKNOWN")
    readers.discard("UNKNOWN")
    return bool(writers and readers and writers != readers)


def _object_extent(
    obj: Mapping[str, Any],
    type_facts: Mapping[str, Any],
    *,
    member_count: int,
) -> Tuple[Optional[int], str]:
    addr_extent = _range_extent_bytes(obj.get("addr_range", []) or [])
    if addr_extent is not None:
        return addr_extent, "addr_range"

    for key in ("byte_size", "buffer_size", "capacity", "array_len", "elem_count"):
        value = _coerce_int(type_facts.get(key))
        if value is not None and value > 0:
            return value, f"type_facts.{key}"

    if member_count > 0:
        # Conservative fallback for symbol-backed objects when only member names exist.
        estimate = max(16, min(512, member_count * 16))
        return estimate, "member_count_estimate"
    return None, "unknown"


def _split_extent(
    extent: int,
    *,
    payload_members: List[str],
    ctrl_members: List[str],
    writer_count: int,
    reader_count: int,
) -> Tuple[int, int]:
    payload_weight = max(1, len(payload_members)) * 3
    control_weight = max(1, len(ctrl_members))
    if writer_count and reader_count:
        payload_weight += 1
    ratio = payload_weight / max(1, payload_weight + control_weight)
    ratio = max(0.55, min(0.90, ratio))
    payload_extent = max(8, int(round(extent * ratio)))
    payload_extent = min(payload_extent, max(8, extent - 4))
    control_extent = max(4, extent - payload_extent)
    return payload_extent, control_extent


def _subrange(addr_range: Iterable[Any], *, offset: int, size: int) -> List[str]:
    bounds = list(addr_range or [])
    if len(bounds) != 2 or size <= 0:
        return []
    start = _coerce_int(bounds[0])
    end = _coerce_int(bounds[1])
    if start is None or end is None or end < start:
        return []
    lo = start + max(0, int(offset))
    hi = min(end, lo + max(1, int(size)) - 1)
    if hi < lo:
        return []
    return [f"0x{lo:08x}", f"0x{hi:08x}"]


def _extent_confidence(
    *,
    extent_source: str,
    has_members: bool,
    writer_count: int,
    reader_count: int,
) -> float:
    score = 0.45
    if extent_source == "addr_range":
        score += 0.30
    elif extent_source.startswith("type_facts."):
        score += 0.20
    elif extent_source == "member_count_estimate":
        score += 0.08
    if has_members:
        score += 0.07
    if writer_count and reader_count:
        score += 0.08
    elif writer_count or reader_count:
        score += 0.04
    return round(min(score, 0.95), 4)


def _range_extent_bytes(addr_range: Iterable[Any]) -> Optional[int]:
    bounds = list(addr_range or [])
    if len(bounds) != 2:
        return None
    start = _coerce_int(bounds[0])
    end = _coerce_int(bounds[1])
    if start is None or end is None or end < start:
        return None
    return (end - start) + 1


def _coerce_int(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        if isinstance(value, int):
            return int(value)
        text = str(value).strip()
        if not text:
            return None
        return int(text, 0)
    except Exception:
        return None
