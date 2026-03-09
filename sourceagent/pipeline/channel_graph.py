"""ChannelGraph builder (M8.5).

Phase-B baseline implementation:
- Keeps all object nodes (recall/app-anchor friendly)
- Emits cross-context edges only (plus DMA->CPU)
- Produces address-level writer/reader evidence sites
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .models import MemoryAccess, MemoryAccessIndex, MemoryMap


SCHEMA_VERSION = "0.1"

_SRAM_BASE = 0x20000000
_SRAM_END = 0x3FFFFFFF
_CLUSTER_MASK = 0xFFFFFF00

_CONTEXTS = {"ISR", "TASK", "MAIN", "UNKNOWN", "DMA"}
_LINKER_NOISE_SYMBOLS = {
    "_sbss",
    "_ebss",
    "_sdata",
    "_edata",
    "_estack",
    "__stack_top__",
}


def build_channel_graph(
    mai: Optional[MemoryAccessIndex],
    verified_labels: Iterable[Any],
    memory_map: Optional[MemoryMap],
    *,
    top_k: int = 3,
    binary_sha256: str = "",
) -> Dict[str, Any]:
    """Build a contract-complete channel graph.

    Args:
        mai: MemoryAccessIndex with resolved accesses.
        verified_labels: verified labels (dataclass rows or dict rows).
        memory_map: stage-1 memory map (for binary metadata).
        top_k: keep top-K producer interpretations when conflicting.
        binary_sha256: optional precomputed file hash.
    """
    binary = ""
    if memory_map is not None:
        binary = memory_map.binary_path
    elif mai is not None:
        binary = mai.binary_path

    object_nodes = _build_sram_objects(mai)
    object_nodes.extend(_build_symbol_only_objects(mai))
    _augment_symbol_backed_consumers(object_nodes, mai)
    _augment_objects_from_labels(object_nodes, verified_labels)

    channel_edges = _build_channel_edges(object_nodes, top_k=top_k)

    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary,
        "binary_sha256": binary_sha256,
        "object_nodes": object_nodes,
        "channel_edges": channel_edges,
        "params": {
            "top_k": int(top_k),
            "cluster_mask": hex(_CLUSTER_MASK),
        },
    }


def _build_sram_objects(mai: Optional[MemoryAccessIndex]) -> List[Dict[str, Any]]:
    if mai is None:
        return []

    by_cluster: Dict[int, List[MemoryAccess]] = defaultdict(list)
    members_by_cluster: Dict[int, List[str]] = defaultdict(list)
    for access in getattr(mai, "accesses", []):
        addr = getattr(access, "target_addr", None)
        if addr is None:
            continue
        if not (_SRAM_BASE <= int(addr) <= _SRAM_END):
            continue
        by_cluster[int(addr) & _CLUSTER_MASK].append(access)

    for sym_name, sym_addr in (getattr(mai, "global_symbol_table", {}) or {}).items():
        if not _is_meaningful_symbol(str(sym_name)):
            continue
        try:
            addr = int(sym_addr)
        except Exception:
            continue
        if not (_SRAM_BASE <= addr <= _SRAM_END):
            continue
        cluster = addr & _CLUSTER_MASK
        members_by_cluster[cluster].append(str(sym_name))

    objects: List[Dict[str, Any]] = []
    all_clusters = sorted(set(by_cluster.keys()) | set(members_by_cluster.keys()))
    for cluster in all_clusters:
        accesses = by_cluster.get(cluster, [])
        members = sorted(set(members_by_cluster.get(cluster, [])))
        start = cluster
        end = cluster + 0xFF

        writer_sites = []
        reader_sites = []
        producers: Set[str] = set()
        consumers: Set[str] = set()

        for a in accesses:
            ctx = _context_from_access(a)
            site = {
                "context": ctx,
                "fn": getattr(a, "function_name", "") or "UNKNOWN",
                "fn_addr": _hex_addr(getattr(a, "function_addr", 0)),
                "site_addr": _hex_addr(getattr(a, "address", 0)),
                "access_kind": getattr(a, "kind", ""),
                "target_addr": _hex_addr(getattr(a, "target_addr", 0)),
            }
            if getattr(a, "kind", "") == "store":
                writer_sites.append(site)
                producers.add(ctx)
            elif getattr(a, "kind", "") == "load":
                reader_sites.append(site)
                consumers.add(ctx)

        if not writer_sites and not reader_sites and not members:
            continue

        producer_contexts = sorted(producers) or (["UNKNOWN"] if writer_sites else [])
        consumer_contexts = sorted(consumers) or (["UNKNOWN"] if reader_sites else [])
        kind_hint = _kind_hint_from_members(members)
        region_kind = "FLAG" if kind_hint == "control" else "SRAM_CLUSTER"

        objects.append({
            "object_id": f"obj_sram_{start:08x}_{end:08x}",
            "region_kind": region_kind,
            "addr_range": [_hex_addr(start), _hex_addr(end)],
            "producer_contexts": producer_contexts or ["UNKNOWN"],
            "consumer_contexts": consumer_contexts or ["UNKNOWN"],
            "writer_sites": writer_sites[:24],
            "reader_sites": reader_sites[:24],
            "writers": sorted({s["fn"] for s in writer_sites}),
            "readers": sorted({s["fn"] for s in reader_sites}),
            "members": members,
            "evidence_refs": [],
            "confidence": _object_confidence(writer_sites, reader_sites, member_count=len(members)),
            "type_facts": {
                "kind_hint": kind_hint,
                "writer_count": len(writer_sites),
                "reader_count": len(reader_sites),
                "member_count": len(members),
                "symbol_backed": bool(members),
            },
            "notes": "m8.5 cluster object" if not members else "m8.5 symbol-backed cluster object",
        })

    return objects


def _build_symbol_only_objects(mai: Optional[MemoryAccessIndex]) -> List[Dict[str, Any]]:
    if mai is None:
        return []

    objects: List[Dict[str, Any]] = []
    seen_members: set[str] = set()
    for sym_name, sym_addr in (getattr(mai, "global_symbol_table", {}) or {}).items():
        if not _is_meaningful_symbol(str(sym_name)):
            continue
        try:
            addr = int(sym_addr)
        except Exception:
            continue
        if _SRAM_BASE <= addr <= _SRAM_END:
            continue

        member = str(sym_name)
        if member in seen_members:
            continue
        seen_members.add(member)

        kind_hint = _kind_hint_from_members([member])
        lower = member.lower()
        if any(tok in lower for tok in ("table", "dispatch", "handler")):
            region_kind = "RODATA_TABLE"
        else:
            region_kind = "GLOBAL_SYMBOL"

        objects.append({
            "object_id": f"obj_sym_{member}_{addr:08x}",
            "region_kind": region_kind,
            "addr_range": [_hex_addr(addr), _hex_addr(addr + 0x3F)],
            "producer_contexts": ["UNKNOWN"],
            "consumer_contexts": ["UNKNOWN"],
            "writer_sites": [],
            "reader_sites": [],
            "writers": [],
            "readers": [],
            "members": [member],
            "evidence_refs": [],
            "confidence": 0.45,
            "type_facts": {
                "kind_hint": kind_hint,
                "member_count": 1,
                "symbol_backed": True,
            },
            "notes": "m8.5 symbol-only object",
        })
    return objects


def _augment_objects_from_labels(
    object_nodes: List[Dict[str, Any]],
    verified_labels: Iterable[Any],
) -> None:
    existing = {o["object_id"] for o in object_nodes}

    for row in verified_labels:
        label, addr, fn, refs, facts = _label_row_fields(row)
        if label not in {"DMA_BACKED_BUFFER", "ISR_FILLED_BUFFER"}:
            continue

        base = addr if addr > 0 else 0
        if label == "DMA_BACKED_BUFFER":
            if _merge_dma_label_into_symbol_object(object_nodes, base=base, fn=fn, refs=refs, facts=facts):
                continue
        merged = _merge_label_into_existing_object(object_nodes, label, base, fn, refs)
        if merged:
            continue

        if label == "DMA_BACKED_BUFFER":
            obj_id = f"obj_dma_{base:08x}_{(base + 0xFF):08x}"
            region_kind = "DMA_BUFFER"
            prod_context = "DMA"
            cons_context = "UNKNOWN"
            notes = "m8.5 DMA synthetic producer object"
        else:
            obj_id = f"obj_isr_{base:08x}_{(base + 0xFF):08x}"
            region_kind = "SRAM_CLUSTER"
            prod_context = "ISR"
            cons_context = "MAIN"
            notes = "m8.5 ISR shared-buffer object"
        if obj_id in existing:
            continue
        existing.add(obj_id)

        object_nodes.append({
            "object_id": obj_id,
            "region_kind": region_kind,
            "addr_range": [_hex_addr(base), _hex_addr(base + 0xFF)],
            "producer_contexts": [prod_context],
            "consumer_contexts": [cons_context],
            "writer_sites": [{
                "context": prod_context,
                "fn": fn or "DMA_CONFIG",
                "fn_addr": _hex_addr(addr),
                "site_addr": _hex_addr(addr),
                "access_kind": "store",
                "target_addr": _hex_addr(base),
            }],
            "reader_sites": [],
            "writers": [fn or "DMA_CONFIG"],
            "readers": [],
            "members": [],
            "evidence_refs": refs,
            "confidence": 0.60,
            "type_facts": {
                "kind_hint": "payload",
                "source_label": label,
                "config_function": fn or "",
            },
            "notes": notes,
        })


def _build_channel_edges(
    object_nodes: List[Dict[str, Any]],
    *,
    top_k: int,
) -> List[Dict[str, Any]]:
    edges: List[Dict[str, Any]] = []

    for obj in object_nodes:
        srcs = _normalize_contexts(obj.get("producer_contexts", []))
        dsts = _normalize_contexts(obj.get("consumer_contexts", []))

        candidates: List[Tuple[str, str, float]] = []
        for src in srcs:
            for dst in dsts:
                if src == dst:
                    continue
                if src != "DMA" and (src == "UNKNOWN" or dst == "UNKNOWN"):
                    continue
                score = float(obj.get("confidence", 0.0))
                if src == "DMA":
                    score = min(1.0, score + 0.10)
                candidates.append((src, dst, score))

        candidates.sort(key=lambda x: x[2], reverse=True)
        kept = candidates[: max(1, int(top_k))] if candidates else []

        for src, dst, score in kept:
            edges.append({
                "src_context": src,
                "object_id": obj["object_id"],
                "dst_context": dst,
                "edge_kind": "DATA",
                "constraints": [],
                "evidence_refs": list(obj.get("evidence_refs", [])),
                "score": round(float(score), 4),
            })

    return edges


def _context_from_access(access: MemoryAccess) -> str:
    if bool(getattr(access, "in_isr", False)):
        return "ISR"

    fn = str(getattr(access, "function_name", "") or "")
    return _context_from_function_name(fn)


def _context_from_function_name(fn: str) -> str:
    fn = str(fn or "").lower()
    if not fn:
        return "UNKNOWN"
    if fn in {"main", "reset_handler", "startup"}:
        return "MAIN"
    if any(tok in fn for tok in ("task", "thread", "worker")):
        return "TASK"
    return "MAIN"


def _normalize_contexts(values: Iterable[str]) -> List[str]:
    out = []
    for v in values:
        s = str(v or "UNKNOWN").upper()
        if s not in _CONTEXTS:
            s = "UNKNOWN"
        if s not in out:
            out.append(s)
    return out or ["UNKNOWN"]


def _label_row_fields(row: Any) -> Tuple[str, int, str, List[str], Dict[str, Any]]:
    if isinstance(row, dict):
        return (
            str(row.get("label", "")),
            int(row.get("address", 0) or 0),
            str(row.get("function_name", "") or ""),
            list(row.get("evidence_refs", []) or []),
            dict(row.get("facts", {}) or {}),
        )

    label = str(getattr(getattr(row, "final_label", None), "value", "") or "")
    if not label:
        label = str(getattr(getattr(row, "proposal", None), "label", "") or "")

    proposal = getattr(row, "proposal", None)
    addr = int(getattr(proposal, "address", 0) or 0)
    fn = str(getattr(proposal, "function_name", "") or "")
    refs = list(getattr(proposal, "evidence_refs", []) or [])
    facts: Dict[str, Any] = {}
    for claim in list(getattr(proposal, "claims", []) or []):
        if isinstance(claim, dict):
            facts.update(claim)
    return label, addr, fn, refs, facts


def _object_confidence(
    writer_sites: List[Dict[str, Any]],
    reader_sites: List[Dict[str, Any]],
    *,
    member_count: int = 0,
) -> float:
    score = 0.35
    if writer_sites:
        score += 0.20
    if reader_sites:
        score += 0.20
    if writer_sites and reader_sites:
        score += 0.15
    if member_count:
        score += min(0.10, 0.02 * member_count)
    return round(min(score, 0.95), 4)


def _kind_hint_from_members(members: List[str]) -> str:
    if not members:
        return "payload_or_ctrl"
    ctrl = 0
    payload = 0
    for name in members:
        lower = str(name).lower()
        if any(tok in lower for tok in ("head", "tail", "idx", "index", "flag", "ready", "done", "state")):
            ctrl += 1
        else:
            payload += 1
    if ctrl and not payload:
        return "control"
    if payload and not ctrl:
        return "payload"
    return "payload_or_ctrl"


def _is_meaningful_symbol(name: str) -> bool:
    sym = str(name or "").strip()
    if not sym:
        return False
    if sym in _LINKER_NOISE_SYMBOLS:
        return False
    return True


def _merge_label_into_existing_object(
    object_nodes: List[Dict[str, Any]],
    label: str,
    base: int,
    fn: str,
    refs: List[str],
) -> bool:
    if base <= 0:
        return False
    for obj in object_nodes:
        rng = obj.get("addr_range", [])
        if not isinstance(rng, list) or len(rng) != 2:
            continue
        start = _parse_hex(str(rng[0]))
        end = _parse_hex(str(rng[1]))
        if not (start <= base <= end):
            continue

        evidence_refs = list(obj.get("evidence_refs", []) or [])
        for ref in refs:
            if ref not in evidence_refs:
                evidence_refs.append(ref)
        obj["evidence_refs"] = evidence_refs

        producers = _normalize_contexts(obj.get("producer_contexts", []))
        consumers = _normalize_contexts(obj.get("consumer_contexts", []))
        if label == "DMA_BACKED_BUFFER":
            if "DMA" not in producers:
                producers.append("DMA")
            if obj.get("region_kind") == "SRAM_CLUSTER":
                obj["region_kind"] = "DMA_BUFFER"
            _append_site(
                obj,
                site_kind="writer_sites",
                site={
                    "context": "DMA",
                    "fn": fn or "DMA_CONFIG",
                    "fn_addr": _hex_addr(base),
                    "site_addr": _hex_addr(base),
                    "access_kind": "store",
                    "target_addr": _hex_addr(base),
                },
            )
        else:
            if "ISR" not in producers:
                producers.append("ISR")
            if "MAIN" not in consumers:
                consumers.append("MAIN")
            _append_site(
                obj,
                site_kind="writer_sites",
                site={
                    "context": "ISR",
                    "fn": fn or "ISR_WRITER",
                    "fn_addr": _hex_addr(base),
                    "site_addr": _hex_addr(base),
                    "access_kind": "store",
                    "target_addr": _hex_addr(base),
                },
            )

        obj["producer_contexts"] = producers
        obj["consumer_contexts"] = consumers or ["UNKNOWN"]
        writers = sorted(set(obj.get("writers", []) or []))
        if fn:
            writers = sorted(set(writers + [fn]))
        obj["writers"] = writers
        type_facts = dict(obj.get("type_facts", {}))
        type_facts["source_label"] = label
        if label == "ISR_FILLED_BUFFER":
            type_facts["kind_hint"] = "payload"
        obj["type_facts"] = type_facts
        obj["confidence"] = round(min(1.0, float(obj.get("confidence", 0.0)) + 0.05), 4)
        notes = str(obj.get("notes", "") or "")
        suffix = f"; merged {label}"
        if suffix not in notes:
            obj["notes"] = (notes + suffix).strip("; ")
        return True
    return False


def _merge_dma_label_into_symbol_object(
    object_nodes: List[Dict[str, Any]],
    *,
    base: int,
    fn: str,
    refs: List[str],
    facts: Dict[str, Any],
) -> bool:
    wanted_members = _infer_dma_buffer_members(object_nodes, fn=fn, facts=facts)
    if not wanted_members:
        return False

    best_obj: Optional[Dict[str, Any]] = None
    best_score = -1.0
    for obj in object_nodes:
        members = {str(m) for m in (obj.get("members", []) or [])}
        overlap = len(members & wanted_members)
        if overlap <= 0:
            continue
        score = float(overlap)
        if str(obj.get("region_kind", "")) == "DMA_BUFFER":
            score += 0.25
        if score > best_score:
            best_score = score
            best_obj = obj

    if best_obj is None:
        return False

    evidence_refs = list(best_obj.get("evidence_refs", []) or [])
    for ref in refs:
        if ref not in evidence_refs:
            evidence_refs.append(ref)
    best_obj["evidence_refs"] = evidence_refs

    producers = _normalize_contexts(best_obj.get("producer_contexts", []))
    if "DMA" not in producers:
        producers.append("DMA")
    best_obj["producer_contexts"] = producers

    if best_obj.get("region_kind") == "SRAM_CLUSTER":
        best_obj["region_kind"] = "DMA_BUFFER"

    _append_site(
        best_obj,
        site_kind="writer_sites",
        site={
            "context": "DMA",
            "fn": fn or "DMA_CONFIG",
            "fn_addr": _hex_addr(base),
            "site_addr": _hex_addr(base),
            "access_kind": "store",
            "target_addr": _hex_addr(base),
        },
    )

    writers = sorted(set(best_obj.get("writers", []) or []))
    if fn:
        writers = sorted(set(writers + [fn]))
    best_obj["writers"] = writers

    type_facts = dict(best_obj.get("type_facts", {}))
    type_facts["source_label"] = "DMA_BACKED_BUFFER"
    type_facts["kind_hint"] = "payload"
    if fn:
        type_facts["config_function"] = fn
    type_facts["dma_buffer_members"] = sorted(wanted_members)
    best_obj["type_facts"] = type_facts

    best_obj["confidence"] = round(min(1.0, float(best_obj.get("confidence", 0.0)) + 0.08), 4)
    notes = str(best_obj.get("notes", "") or "")
    suffix = "; merged DMA_BACKED_BUFFER by symbol binding"
    if suffix not in notes:
        best_obj["notes"] = (notes + suffix).strip("; ")
    return True


def _infer_dma_buffer_members(
    object_nodes: List[Dict[str, Any]],
    *,
    fn: str,
    facts: Dict[str, Any],
) -> Set[str]:
    explicit: Set[str] = set()
    for key in ("buffer_symbol", "buffer_symbols", "associated_buffer", "associated_buffers"):
        value = facts.get(key)
        if isinstance(value, str) and value.strip():
            explicit.add(value.strip())
        elif isinstance(value, list):
            explicit.update(str(v).strip() for v in value if str(v).strip())
    if explicit:
        return explicit

    text_parts = [str(fn or "")]
    for value in facts.values():
        if isinstance(value, str):
            text_parts.append(value)
        elif isinstance(value, list):
            text_parts.extend(str(v) for v in value)
    text = " ".join(text_parts).lower()

    scored: List[Tuple[float, str]] = []
    for obj in object_nodes:
        for member in (obj.get("members", []) or []):
            sym = str(member or "").strip()
            if not sym:
                continue
            sym_l = sym.lower()
            score = 0.0
            if sym_l in text:
                score += 1.0
            if any(tok in sym_l for tok in ("dma", "rx", "buf", "buffer")):
                score += 0.25
            if score > 0:
                scored.append((score, sym))

    scored.sort(key=lambda x: (-x[0], x[1]))
    return {sym for _, sym in scored[:3]}


def _augment_symbol_backed_consumers(
    object_nodes: List[Dict[str, Any]],
    mai: Optional[MemoryAccessIndex],
) -> None:
    if mai is None:
        return

    decompiled = dict(getattr(mai, "decompiled_cache", {}) or {})
    isr_funcs = {str(fn or "") for fn in (getattr(mai, "isr_functions", []) or [])}

    for obj in object_nodes:
        members = [str(m) for m in (obj.get("members", []) or []) if str(m).strip()]
        if not members:
            continue

        obj_start = _parse_hex(str((obj.get("addr_range") or ["0x0"])[0]))
        writer_names = set(obj.get("writers", []) or [])
        for fn_name, code in decompiled.items():
            fn_name = str(fn_name or "")
            if not fn_name or not code or fn_name in writer_names:
                continue
            if not any(_symbol_read_like_usage(member, code) for member in members):
                continue

            ctx = "ISR" if fn_name in isr_funcs else _context_from_function_name(fn_name)
            _append_site(
                obj,
                site_kind="reader_sites",
                site={
                    "context": ctx,
                    "fn": fn_name,
                    "fn_addr": _hex_addr(0),
                    "site_addr": _hex_addr(0),
                    "access_kind": "load",
                    "target_addr": _hex_addr(obj_start),
                },
            )
            readers = sorted(set(obj.get("readers", []) or []))
            if fn_name not in readers:
                readers.append(fn_name)
            obj["readers"] = sorted(readers)

        consumers = sorted({
            str(site.get("context", "UNKNOWN"))
            for site in (obj.get("reader_sites", []) or [])
            if str(site.get("context", "")).strip()
        })
        if consumers:
            obj["consumer_contexts"] = consumers
            tf = dict(obj.get("type_facts", {}))
            tf["reader_count"] = len(obj.get("reader_sites", []) or [])
            obj["type_facts"] = tf


def _symbol_read_like_usage(symbol: str, code: str) -> bool:
    sym = str(symbol or "").strip()
    if not sym:
        return False

    for line in str(code or "").splitlines():
        if sym not in line:
            continue
        if f"{sym} =" in line:
            continue
        if f"{sym}[" in line or f"({sym}" in line or f", {sym}" in line or f"{sym}," in line:
            return True
        if sym in line and "=" in line and line.index(sym) > line.index("="):
            return True
    return False


def _append_site(obj: Dict[str, Any], *, site_kind: str, site: Dict[str, Any]) -> None:
    sites = list(obj.get(site_kind, []) or [])
    sig = (site.get("context"), site.get("fn"), site.get("target_addr"))
    for existing in sites:
        if (existing.get("context"), existing.get("fn"), existing.get("target_addr")) == sig:
            return
    sites.append(site)
    obj[site_kind] = sites[:24]


def _parse_hex(text: str) -> int:
    try:
        return int(str(text or "0"), 16)
    except Exception:
        return 0


def _hex_addr(v: Any) -> str:
    try:
        n = int(v or 0)
    except Exception:
        n = 0
    return f"0x{n:08x}"
