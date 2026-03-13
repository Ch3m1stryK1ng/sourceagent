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
_SLICE_MERGE_GAP = 0x20

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
    _finalize_object_metadata(object_nodes)
    object_nodes.extend(_augment_object_overlays(object_nodes))
    _finalize_object_metadata(object_nodes)

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
        binding_targets = _binding_target_rows(label, base=base, facts=facts)
        merged = False
        if binding_targets:
            merged = _merge_label_binding_targets(
                object_nodes,
                label=label,
                binding_targets=binding_targets,
                fn=fn,
                refs=refs,
                facts=facts,
            )
        if not merged:
            merged = _merge_label_into_existing_object(object_nodes, label, base, fn, refs, facts=facts)
        if merged:
            continue

        if binding_targets:
            synth_base = int(binding_targets[0].get("cluster", base) or base)
            obj_id = f"obj_sram_{synth_base:08x}_{(synth_base + 0xFF):08x}"
            region_kind = "DMA_BUFFER" if label == "DMA_BACKED_BUFFER" else "SRAM_CLUSTER"
            prod_context = "DMA" if label == "DMA_BACKED_BUFFER" else "ISR"
            cons_context = "MAIN"
            notes = "m8.5 payload synthetic producer object"
        elif label == "DMA_BACKED_BUFFER":
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
            "addr_range": [_hex_addr(synth_base if binding_targets else base), _hex_addr((synth_base if binding_targets else base) + 0xFF)],
            "producer_contexts": [prod_context],
            "consumer_contexts": [cons_context],
            "writer_sites": [{
                "context": prod_context,
                "fn": fn or "DMA_CONFIG",
                "fn_addr": _hex_addr(addr),
                "site_addr": _hex_addr(addr),
                "access_kind": "store",
                "target_addr": _hex_addr(synth_base if binding_targets else base),
            }],
            "reader_sites": _buffer_reader_sites(base=synth_base if binding_targets else base, facts=facts),
            "writers": [fn or "DMA_CONFIG"],
            "readers": [str(v) for v in ((facts or {}).get("buffer_readers", []) or []) if str(v).strip()],
            "members": [],
            "evidence_refs": refs,
            "confidence": 0.60,
                "type_facts": {
                    "kind_hint": "payload",
                    "source_label": label,
                    "config_function": fn or "",
                    **_binding_type_facts(label=label, base=base, facts=facts),
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
                quality = _object_quality_score(obj)
                ambiguity = _object_ambiguity_penalty(obj)
                score = 0.55 * float(obj.get("confidence", 0.0)) + 0.35 * quality - 0.15 * ambiguity
                if src == "DMA":
                    score = min(1.0, score + 0.10)
                if str(obj.get("region_kind", "")).upper() == "DMA_BUFFER":
                    score = min(1.0, score + 0.05)
                candidates.append((src, dst, score))

        candidates.sort(key=lambda x: x[2], reverse=True)
        kept = candidates[: max(1, int(top_k))] if candidates else []

        for src, dst, score in kept:
            quality = _object_quality_score(obj)
            ambiguity = _object_ambiguity_penalty(obj)
            edges.append({
                "src_context": src,
                "object_id": obj["object_id"],
                "dst_context": dst,
                "edge_kind": "DATA",
                "constraints": [],
                "evidence_refs": list(obj.get("evidence_refs", [])),
                "score": round(float(score), 4),
                "object_quality": round(quality, 4),
                "ambiguity_penalty": round(ambiguity, 4),
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


def _looks_stripped_function_name(fn: str) -> bool:
    lowered = str(fn or "").strip().lower()
    if not lowered:
        return False
    return bool(
        lowered.startswith("fun_")
        or lowered.startswith("lab_")
        or lowered.startswith("sub_")
        or lowered.startswith("thunk_fun_")
    )


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
    *,
    facts: Optional[Dict[str, Any]] = None,
    site_addr: Optional[int] = None,
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
                    "fn_addr": _hex_addr(site_addr or base),
                    "site_addr": _hex_addr(site_addr or base),
                    "access_kind": "store",
                    "target_addr": _hex_addr(base),
                },
            )
            for reader_site in _buffer_reader_sites(base=base, facts=facts):
                _append_site(obj, site_kind="reader_sites", site=reader_site)
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
                    "fn_addr": _hex_addr(site_addr or base),
                    "site_addr": _hex_addr(site_addr or base),
                    "access_kind": "store",
                    "target_addr": _hex_addr(base),
                },
            )

        obj["producer_contexts"] = producers
        if facts and label == "DMA_BACKED_BUFFER":
            for reader in list((facts or {}).get("buffer_readers", []) or []):
                ctx = _context_from_function_name(str(reader or ""))
                if ctx and ctx not in consumers:
                    consumers.append(ctx)
        obj["consumer_contexts"] = consumers or ["UNKNOWN"]
        writers = sorted(set(obj.get("writers", []) or []))
        if fn:
            writers = sorted(set(writers + [fn]))
        obj["writers"] = writers
        readers = sorted(set(obj.get("readers", []) or []))
        if facts:
            readers = sorted(set(readers + [str(name) for name in ((facts or {}).get("buffer_readers", []) or []) if str(name)]))
        obj["readers"] = readers
        type_facts = dict(obj.get("type_facts", {}))
        type_facts["source_label"] = label
        if label == "ISR_FILLED_BUFFER":
            type_facts["kind_hint"] = "payload"
        type_facts.update(_binding_type_facts(label=label, base=base, facts=facts or {}))
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
    type_facts.update(_binding_type_facts(label="DMA_BACKED_BUFFER", base=base, facts=facts))
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


def _binding_target_rows(label: str, *, base: int, facts: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: Dict[int, Dict[str, Any]] = {}

    def _add(cluster: int, *, score: float, reason: str) -> None:
        if not (_SRAM_BASE <= cluster <= _SRAM_END):
            return
        existing = rows.get(cluster)
        payload = {
            "cluster": cluster,
            "score": round(max(0.0, min(1.0, score)), 4),
            "reason": reason,
        }
        if existing is None or float(payload["score"]) > float(existing.get("score", 0.0) or 0.0):
            rows[cluster] = payload

    if _SRAM_BASE <= int(base or 0) <= _SRAM_END:
        _add(int(base), score=0.62, reason="label_address")

    binding_conf = _coerce_float((facts or {}).get("buffer_binding_confidence"))
    explicit_cluster = _parse_hex(str((facts or {}).get("buffer_cluster", "") or ""))
    if explicit_cluster > 0:
        _add(explicit_cluster, score=max(0.55, binding_conf), reason="buffer_cluster")

    for row in list((facts or {}).get("buffer_cluster_candidates", []) or []):
        if isinstance(row, str):
            cluster = _parse_hex(row)
            score = binding_conf
        else:
            cluster = _parse_hex(str((row or {}).get("cluster", "") or ""))
            score = _coerce_float((row or {}).get("confidence"))
            if score <= 0.0:
                raw_score = _coerce_float((row or {}).get("score"))
                score = raw_score / 3.8 if raw_score > 1.0 else raw_score
        if cluster > 0:
            _add(cluster, score=max(0.2, score), reason="buffer_cluster_candidate")

    if label == "ISR_FILLED_BUFFER":
        isr_cluster = _parse_hex(str((facts or {}).get("buffer_cluster", "") or ""))
        if isr_cluster > 0:
            _add(isr_cluster, score=max(0.55, binding_conf or 0.55), reason="isr_buffer_cluster")

    return sorted(rows.values(), key=lambda row: (-float(row.get("score", 0.0) or 0.0), int(row.get("cluster", 0) or 0)))


def _merge_label_binding_targets(
    object_nodes: List[Dict[str, Any]],
    *,
    label: str,
    binding_targets: List[Dict[str, Any]],
    fn: str,
    refs: List[str],
    facts: Dict[str, Any],
) -> bool:
    scored: List[Tuple[float, int, Dict[str, Any]]] = []
    for idx, obj in enumerate(object_nodes):
        start, end = _object_bounds(obj)
        if end < start:
            continue
        for row in binding_targets:
            cluster = int(row.get("cluster", 0) or 0)
            if start <= cluster <= end:
                score = float(row.get("score", 0.0) or 0.0)
                scored.append((score, idx, row))
                _annotate_object_binding_candidate(obj, label=label, row=row)
                break

    if not scored:
        return False

    scored.sort(key=lambda item: (-item[0], item[1]))
    best_score, best_idx, best_row = scored[0]
    second_score = scored[1][0] if len(scored) > 1 else -1.0
    if len(scored) > 1 and best_score < 0.7 and best_score < second_score + 0.15:
        return False
    target_cluster = int(best_row.get("cluster", 0) or 0)
    site_addr = _parse_hex(str((facts or {}).get("config_cluster", "") or ""))
    if site_addr <= 0:
        site_addr = target_cluster
    return _merge_label_into_existing_object(
        [object_nodes[best_idx]],
        label,
        target_cluster,
        fn,
        refs,
        facts=facts,
        site_addr=site_addr,
    )


def _annotate_object_binding_candidate(obj: Dict[str, Any], *, label: str, row: Dict[str, Any]) -> None:
    tf = dict(obj.get("type_facts", {}) or {})
    candidates = list(tf.get("source_binding_candidates", []) or [])
    entry = {
        "label": label,
        "cluster": _hex_addr(row.get("cluster", 0)),
        "score": round(float(row.get("score", 0.0) or 0.0), 4),
        "reason": str(row.get("reason", "") or ""),
    }
    if entry not in candidates:
        candidates.append(entry)
    tf["source_binding_candidates"] = candidates[:6]
    obj["type_facts"] = tf


def _binding_type_facts(*, label: str, base: int, facts: Dict[str, Any]) -> Dict[str, Any]:
    tf: Dict[str, Any] = {}
    if label not in {"DMA_BACKED_BUFFER", "ISR_FILLED_BUFFER"}:
        return tf
    config_cluster = str((facts or {}).get("config_cluster", "") or "")
    if config_cluster:
        tf["config_cluster"] = config_cluster
    buffer_cluster = str((facts or {}).get("buffer_cluster", "") or "")
    if buffer_cluster:
        tf["buffer_cluster"] = buffer_cluster
    elif _SRAM_BASE <= int(base or 0) <= _SRAM_END:
        tf["buffer_cluster"] = _hex_addr(base)
    buffer_candidates = list((facts or {}).get("buffer_cluster_candidates", []) or [])
    if buffer_candidates:
        tf["buffer_cluster_candidates"] = buffer_candidates[:4]
    readers = [str(v) for v in ((facts or {}).get("buffer_readers", []) or []) if str(v).strip()]
    if readers:
        tf["buffer_readers"] = readers[:8]
    conf = _coerce_float((facts or {}).get("buffer_binding_confidence"))
    if conf > 0.0:
        tf["buffer_binding_confidence"] = round(conf, 4)
    return tf


def _buffer_reader_sites(*, base: int, facts: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for reader in list((facts or {}).get("buffer_readers", []) or []):
        fn = str(reader or "").strip()
        if not fn:
            continue
        out.append({
            "context": _context_from_function_name(fn),
            "fn": fn,
            "fn_addr": _hex_addr(0),
            "site_addr": _hex_addr(0),
            "access_kind": "load",
            "target_addr": _hex_addr(base),
        })
    return out[:8]


def _finalize_object_metadata(object_nodes: List[Dict[str, Any]]) -> None:
    for obj in object_nodes:
        _refresh_object_metadata(obj)


def _refresh_object_metadata(obj: Dict[str, Any]) -> None:
    start, end = _object_bounds(obj)
    observed = _observed_ranges(obj, start=start, end=end)
    slice_facts = _slice_facts(observed, start=start, end=end)
    quality = _object_quality(obj, slice_facts=slice_facts)

    obj["slice_facts"] = slice_facts
    obj["quality"] = quality

    tf = dict(obj.get("type_facts", {}) or {})
    tf["slice_count"] = int(slice_facts.get("slice_count", 0) or 0)
    tf["coverage_ratio"] = float(slice_facts.get("coverage_ratio", 0.0) or 0.0)
    tf["object_quality"] = {
        "score": round(float(quality.get("score", 0.0) or 0.0), 4),
        "specificity": round(float(quality.get("specificity", 0.0) or 0.0), 4),
        "ambiguity_penalty": round(float(quality.get("ambiguity_penalty", 0.0) or 0.0), 4),
    }
    handoff = _shared_handoff_hint(obj, quality=quality)
    if handoff:
        tf["shared_handoff_hint"] = handoff
    else:
        tf.pop("shared_handoff_hint", None)
    obj["type_facts"] = tf


def _augment_object_overlays(object_nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    overlays: List[Dict[str, Any]] = []
    existing = {str(obj.get("object_id", "") or "") for obj in object_nodes}
    for builder in (_build_slice_overlay_objects, _build_source_overlay_objects):
        for obj in builder(object_nodes):
            obj_id = str(obj.get("object_id", "") or "")
            if not obj_id or obj_id in existing:
                continue
            existing.add(obj_id)
            overlays.append(obj)
    return overlays


def _build_slice_overlay_objects(object_nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    overlays: List[Dict[str, Any]] = []
    for obj in object_nodes:
        tf = dict(obj.get("type_facts", {}) or {})
        if bool(tf.get("symbol_backed")) or bool(tf.get("slice_overlay")) or bool(tf.get("source_overlay")):
            continue
        quality = dict(obj.get("quality", {}) or {})
        slice_facts = dict(obj.get("slice_facts", {}) or {})
        slices = list(slice_facts.get("slices", []) or [])
        if len(slices) < 2:
            continue
        if float(quality.get("ambiguity_penalty", 0.0) or 0.0) < 0.35 and int(quality.get("site_fn_count", 0) or 0) < 8:
            continue
        for row in slices[:2]:
            rng = list(row.get("addr_range", []) or [])
            if len(rng) != 2:
                continue
            writer_sites = _filter_sites_for_range(obj.get("writer_sites", []), rng)
            reader_sites = _filter_sites_for_range(obj.get("reader_sites", []), rng)
            if len(writer_sites) + len(reader_sites) < 2:
                continue
            overlays.append(_make_overlay_object(
                parent=obj,
                object_id=f"{obj.get('object_id', 'obj')}__{str(row.get('slice_id', 's')).lower()}",
                addr_range=rng,
                writer_sites=writer_sites,
                reader_sites=reader_sites,
                note_suffix="slice overlay",
                extra_type_facts={"slice_overlay": True, "slice_id": str(row.get("slice_id", ""))},
            ))
    return overlays


def _build_source_overlay_objects(object_nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    overlays: List[Dict[str, Any]] = []
    for obj in object_nodes:
        tf = dict(obj.get("type_facts", {}) or {})
        source_label = str(tf.get("source_label", "") or "").upper()
        if source_label not in {"DMA_BACKED_BUFFER", "ISR_FILLED_BUFFER"}:
            continue
        if bool(tf.get("source_overlay")):
            continue
        quality = dict(obj.get("quality", {}) or {})
        if float(quality.get("ambiguity_penalty", 0.0) or 0.0) < 0.4 and int(quality.get("site_fn_count", 0) or 0) < 10:
            continue

        readers_hint = {str(v).lower() for v in (tf.get("buffer_readers", []) or []) if str(v).strip()}
        writer_sites = [
            dict(site)
            for site in (obj.get("writer_sites", []) or [])
            if str(site.get("context", "")).upper() in {"DMA", "ISR"}
        ] or list(obj.get("writer_sites", []) or [])[:4]
        reader_sites = [
            dict(site)
            for site in (obj.get("reader_sites", []) or [])
            if not readers_hint or str(site.get("fn", "")).lower() in readers_hint
        ] or list(obj.get("reader_sites", []) or [])[:6]
        if not writer_sites or not reader_sites:
            continue
        overlays.append(_make_overlay_object(
            parent=obj,
            object_id=f"{obj.get('object_id', 'obj')}__bound",
            addr_range=list(obj.get("addr_range", []) or []),
            writer_sites=writer_sites,
            reader_sites=reader_sites,
            note_suffix="source-bound overlay",
            extra_type_facts={"source_overlay": True, "source_overlay_label": source_label},
        ))
    return overlays


def _make_overlay_object(
    *,
    parent: Dict[str, Any],
    object_id: str,
    addr_range: List[str],
    writer_sites: List[Dict[str, Any]],
    reader_sites: List[Dict[str, Any]],
    note_suffix: str,
    extra_type_facts: Dict[str, Any],
) -> Dict[str, Any]:
    tf = dict(parent.get("type_facts", {}) or {})
    tf.update(extra_type_facts)
    return {
        "object_id": object_id,
        "parent_object_id": str(parent.get("object_id", "") or ""),
        "region_kind": str(parent.get("region_kind", "") or "SRAM_CLUSTER"),
        "addr_range": list(addr_range or []),
        "producer_contexts": sorted({str(site.get("context", "") or "UNKNOWN") for site in writer_sites if str(site.get("context", "") or "").strip()}) or ["UNKNOWN"],
        "consumer_contexts": sorted({str(site.get("context", "") or "UNKNOWN") for site in reader_sites if str(site.get("context", "") or "").strip()}) or ["UNKNOWN"],
        "writer_sites": writer_sites[:24],
        "reader_sites": reader_sites[:24],
        "writers": sorted({str(site.get("fn", "") or "") for site in writer_sites if str(site.get("fn", "") or "").strip()}),
        "readers": sorted({str(site.get("fn", "") or "") for site in reader_sites if str(site.get("fn", "") or "").strip()}),
        "members": list(parent.get("members", []) or []),
        "evidence_refs": list(parent.get("evidence_refs", []) or []),
        "confidence": round(min(0.92, max(0.45, float(parent.get("confidence", 0.0) or 0.0) + 0.04)), 4),
        "type_facts": tf,
        "notes": f"{str(parent.get('notes', '') or '')}; {note_suffix}".strip("; "),
    }


def _filter_sites_for_range(rows: Iterable[Dict[str, Any]], addr_range: List[str]) -> List[Dict[str, Any]]:
    start = _parse_hex(str((addr_range or ["0x0"])[0]))
    end = _parse_hex(str((addr_range or ["0x0", "0x0"])[1]))
    out: List[Dict[str, Any]] = []
    for row in rows or []:
        addr = _parse_hex(str((row or {}).get("target_addr", "") or "0x0"))
        if start <= addr <= end:
            out.append(dict(row))
    return out[:24]


def _shared_handoff_hint(obj: Dict[str, Any], *, quality: Dict[str, Any]) -> Dict[str, Any]:
    tf = dict(obj.get("type_facts", {}) or {})
    if bool(tf.get("symbol_backed")):
        return {}
    if str(obj.get("region_kind", "") or "").upper() not in {"SRAM_CLUSTER", "DMA_BUFFER"}:
        return {}
    writers = {str(fn).lower() for fn in (obj.get("writers", []) or []) if str(fn).strip()}
    readers = {str(fn).lower() for fn in (obj.get("readers", []) or []) if str(fn).strip()}
    if not writers or not readers:
        return {}
    shared = writers & readers
    disjoint_writers = writers - readers
    disjoint_readers = readers - writers
    if not disjoint_writers or not disjoint_readers:
        return {}

    slice_count = int((obj.get("slice_facts", {}) or {}).get("slice_count", 0) or 0)
    coverage_ratio = float((obj.get("slice_facts", {}) or {}).get("coverage_ratio", 0.0) or 0.0)
    ambiguity = float(quality.get("ambiguity_penalty", 0.0) or 0.0)
    quality_score = float(quality.get("score", 0.0) or 0.0)
    kind_hint = str(tf.get("kind_hint", "") or "").lower()

    score = 0.0
    if kind_hint in {"payload", "payload_or_ctrl"}:
        score += 0.12
    if disjoint_writers and disjoint_readers:
        score += 0.28
    if len(disjoint_readers) >= max(2, len(disjoint_writers)):
        score += 0.14
    if slice_count <= 2:
        score += 0.08
    if quality_score >= 0.55:
        score += 0.14
    if ambiguity <= 0.4:
        score += 0.12
    if coverage_ratio <= 0.45:
        score += 0.06
    if any(_looks_stripped_function_name(fn) for fn in (writers | readers)):
        score += 0.06
    if len(shared) > 1:
        score -= 0.08
    if len(writers | readers) > 12:
        score -= 0.10

    score = round(max(0.0, min(1.0, score)), 4)
    if score < 0.68:
        return {}
    return {
        "edge": "MAIN->TASK",
        "score": score,
        "writer_functions": sorted(disjoint_writers)[:6],
        "reader_functions": sorted(disjoint_readers)[:6],
    }


def _object_bounds(obj: Dict[str, Any]) -> Tuple[int, int]:
    rng = obj.get("addr_range", [])
    if not isinstance(rng, list) or len(rng) != 2:
        return 0, 0
    start = _parse_hex(str(rng[0]))
    end = _parse_hex(str(rng[1]))
    if end < start:
        start, end = end, start
    return start, end


def _observed_ranges(obj: Dict[str, Any], *, start: int, end: int) -> List[Tuple[int, int]]:
    ranges: List[Tuple[int, int]] = []
    for site_key in ("writer_sites", "reader_sites"):
        for row in (obj.get(site_key, []) or []):
            addr = _parse_hex(str(row.get("target_addr", "") or "0x0"))
            if addr <= 0:
                continue
            hi = addr
            if start <= addr <= end:
                hi = min(end, addr + 3)
            ranges.append((addr, hi))
    if not ranges and start <= end:
        ranges.append((start, end))
    return ranges


def _slice_facts(
    observed: List[Tuple[int, int]],
    *,
    start: int,
    end: int,
) -> Dict[str, Any]:
    if not observed:
        return {
            "slice_count": 0,
            "coverage_ratio": 0.0,
            "dominant_slice_span": 0,
            "slices": [],
        }

    ordered = sorted(
        ((min(lo, hi), max(lo, hi)) for lo, hi in observed if max(lo, hi) >= 0),
        key=lambda item: (item[0], item[1]),
    )
    merged: List[List[int]] = []
    for lo, hi in ordered:
        if not merged or lo > merged[-1][1] + _SLICE_MERGE_GAP:
            merged.append([lo, hi])
            continue
        merged[-1][1] = max(merged[-1][1], hi)

    total_span = max(1, end - start + 1) if end >= start else 1
    slices: List[Dict[str, Any]] = []
    covered = 0
    for idx, (lo, hi) in enumerate(merged):
        span = max(1, hi - lo + 1)
        covered += span
        slices.append({
            "slice_id": f"S{idx}",
            "addr_range": [_hex_addr(lo), _hex_addr(hi)],
            "span": span,
        })

    dominant = max((row["span"] for row in slices), default=0)
    return {
        "slice_count": len(slices),
        "coverage_ratio": round(min(1.0, covered / float(total_span)), 4),
        "dominant_slice_span": dominant,
        "slices": slices[:8],
    }


def _object_quality(obj: Dict[str, Any], *, slice_facts: Dict[str, Any]) -> Dict[str, Any]:
    tf = dict(obj.get("type_facts", {}) or {})
    producers = _normalize_contexts(obj.get("producer_contexts", []))
    consumers = _normalize_contexts(obj.get("consumer_contexts", []))
    writers = {str(fn) for fn in (obj.get("writers", []) or []) if str(fn).strip()}
    readers = {str(fn) for fn in (obj.get("readers", []) or []) if str(fn).strip()}
    members = [str(member).strip() for member in (obj.get("members", []) or []) if str(member).strip()]

    site_fn_count = len(writers | readers)
    producer_count = len([ctx for ctx in producers if ctx != "UNKNOWN"])
    consumer_count = len([ctx for ctx in consumers if ctx != "UNKNOWN"])
    slice_count = int(slice_facts.get("slice_count", 0) or 0)
    coverage_ratio = float(slice_facts.get("coverage_ratio", 0.0) or 0.0)
    region_kind = str(obj.get("region_kind", "") or "").upper()
    kind_hint = str(tf.get("kind_hint", "") or "").lower()
    symbol_backed = bool(tf.get("symbol_backed")) or bool(members)

    specificity = 0.25
    if symbol_backed:
        specificity += 0.25
    if region_kind in {"DMA_BUFFER", "RODATA_TABLE"}:
        specificity += 0.10
    if kind_hint == "payload":
        specificity += 0.08
    if slice_count == 1:
        specificity += 0.12
    elif slice_count == 2:
        specificity += 0.06
    specificity += max(0.0, 0.18 - 0.18 * coverage_ratio)
    specificity += max(0.0, 0.10 - 0.02 * max(site_fn_count - 1, 0))

    ambiguity = 0.0
    ambiguity += 0.12 * max(producer_count - 1, 0)
    ambiguity += 0.12 * max(consumer_count - 1, 0)
    ambiguity += 0.08 * max(site_fn_count - 2, 0)
    ambiguity += 0.06 * max(slice_count - 2, 0)
    if not symbol_backed and kind_hint == "payload_or_ctrl":
        ambiguity += 0.08
    if coverage_ratio > 0.65:
        ambiguity += min(0.18, (coverage_ratio - 0.65) * 0.5)

    score = max(0.0, min(1.0, 0.35 + specificity - 0.45 * ambiguity))
    return {
        "score": round(score, 4),
        "specificity": round(max(0.0, min(1.0, specificity)), 4),
        "ambiguity_penalty": round(max(0.0, min(1.0, ambiguity)), 4),
        "producer_count": producer_count,
        "consumer_count": consumer_count,
        "site_fn_count": site_fn_count,
        "symbol_poor": not symbol_backed,
    }


def _object_quality_score(obj: Dict[str, Any]) -> float:
    return float((obj.get("quality", {}) or {}).get("score", obj.get("confidence", 0.0)) or 0.0)


def _object_ambiguity_penalty(obj: Dict[str, Any]) -> float:
    return float((obj.get("quality", {}) or {}).get("ambiguity_penalty", 0.0) or 0.0)


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


def _coerce_float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except Exception:
        return 0.0
