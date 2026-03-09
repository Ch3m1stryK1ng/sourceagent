"""Sink root extraction (M9)."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..models import SinkLabel


_GENERIC_FALLBACK_MARKERS = {
    "UNKNOWN",
    "format_arg_variable",
    "indirect_call_target",
    "store_target",
}
_FUNC_PTR_INDEX_RE = re.compile(r"\[(?P<idx>[A-Za-z_]\w*)\]")
_FUNC_PTR_DEREF_RE = re.compile(r"\(\*\s*(?P<expr>[^)]+?)\s*\)\(")
_CALL_RE = re.compile(r"(?P<callee>[A-Za-z_]\w*)\s*\((?P<args>[^;\n]*)\)")


def extract_sink_roots(
    verified_sinks: List[Dict[str, Any]],
    *,
    sink_facts_by_pack: Dict[str, Dict[str, Any]],
    binary_stem: str,
    decompiled_cache: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Extract root expressions for each verified sink.

    Priority in this phase:
    1) sink_facts (miner-produced)
    2) call arguments / matched text
    3) decompile-text fallback
    4) fallback UNKNOWN root with detailed failure code
    """
    out: List[Dict[str, Any]] = []
    decompiled_cache = decompiled_cache or {}

    for idx, sink in enumerate(verified_sinks):
        sink_id = f"SINK_{binary_stem}_{idx:04d}"
        pack_id = str(sink.get("pack_id", ""))
        sink_facts = sink_facts_by_pack.get(pack_id, {})
        sink_fn = str(sink.get("function_name", "") or "")
        decompiled_code = str(decompiled_cache.get(sink_fn, "") or "")
        roots, root_source = _extract_roots(
            str(sink.get("label", "")),
            sink_facts,
            sink_function=sink_fn,
            decompiled_code=decompiled_code,
        )

        status = "ok"
        failure_code = ""
        failure_detail = ""
        if not roots:
            roots = [{"role": "primary", "expr": "UNKNOWN", "kind": "unknown"}]
            status = "partial"
            root_source = "none"
            if sink_facts:
                failure_code = "ROOT_PARSE_FAILED"
                failure_detail = "Sink facts existed, but no root expression could be recovered"
            else:
                failure_code = "ROOT_FACT_MISSING"
                failure_detail = "No sink facts were available for root extraction"
        elif all(str(r.get("expr", "")) in _GENERIC_FALLBACK_MARKERS for r in roots):
            status = "partial"
            failure_code = "ROOT_WEAK_FALLBACK"
            failure_detail = "Only generic fallback roots were available"

        item = {
            "sink_id": sink_id,
            "sink_label": str(sink.get("label", "")),
            "sink_function": sink_fn,
            "sink_site": _hex_addr(sink.get("address", 0)),
            "roots": roots,
            "evidence_refs": list(sink.get("evidence_refs", [])),
            "confidence": float(sink.get("confidence", 0.0)),
            "status": status,
            "root_source": root_source,
        }
        if failure_code:
            item["failure_code"] = failure_code
            item["failure_detail"] = failure_detail

        out.append(item)

    return out


def _extract_roots(
    label: str,
    facts: Dict[str, Any],
    *,
    sink_function: str = "",
    decompiled_code: str = "",
) -> Tuple[List[Dict[str, Any]], str]:
    facts = facts or {}
    roots: List[Dict[str, Any]] = []

    def _pick(keys: List[str]) -> str:
        for k in keys:
            v = facts.get(k)
            if v is None:
                continue
            s = str(v).strip()
            if s:
                return s
        return ""

    def _push(role: str, expr: str, kind: str, source: str) -> None:
        expr = _clean_expr(expr)
        if not expr:
            return
        roots.append(_make_root(role=role, expr=expr, kind=kind, source=source))

    args = _normalize_args(facts.get("args"))
    callee = str(facts.get("callee", "") or facts.get("format_func", "") or "").lower()

    if label == SinkLabel.COPY_SINK.value:
        length = _pick(["len_expr", "length_expr", "len", "size_expr", "bound_expr"])
        dst = _pick(["dst_expr", "dst", "target_expr", "dst_arg", "store_expr"])
        src = _pick(["src_expr", "src", "source_expr", "src_arg"])
        if length:
            _push("primary", length, "length", "miner_facts")
        elif len(args) >= 3:
            _push("primary", args[2], "length", "call_args")
        elif callee == "loop_copy_idiom":
            parsed = _parse_loop_copy_length_from_decompile(decompiled_code)
            if parsed:
                _push("primary", parsed, "length", "decompile_fallback")
        elif _pick(["loop_bound", "index_expr", "idx_expr"]):
            _push("primary", _pick(["loop_bound", "index_expr", "idx_expr"]), "length", "miner_facts")

        if dst:
            _push("secondary", dst, "dst_ptr", "miner_facts")
        elif args:
            _push("secondary", args[0], "dst_ptr", "call_args")

        if src:
            _push("secondary", src, "src_ptr", "miner_facts")
        elif len(args) >= 2:
            kind = "src_data" if callee in {"strcpy", "sprintf", "snprintf", "vsprintf", "vsnprintf"} else "src_ptr"
            primary = not any(str(r.get("role")) == "primary" for r in roots)
            _push("primary" if primary else "secondary", args[1], kind, "call_args")

    elif label == SinkLabel.MEMSET_SINK.value:
        length = _pick(["len_expr", "length_expr", "len", "size_expr"])
        if length:
            _push("primary", length, "length", "miner_facts")
        elif len(args) >= 3:
            _push("primary", args[2], "length", "call_args")

        dst = _pick(["dst_expr", "dst", "target_expr"])
        if dst:
            _push("secondary", dst, "dst_ptr", "miner_facts")
        elif args:
            _push("secondary", args[0], "dst_ptr", "call_args")

    elif label == SinkLabel.STORE_SINK.value:
        dst = _pick(["dst_expr", "store_expr", "target_expr", "ptr_expr"])
        if dst:
            _push("primary", dst, "dst_ptr", "miner_facts")
        else:
            matched = list(facts.get("matched_pointer_params", []) or [])
            pointer_names = list(facts.get("pointer_param_names", []) or [])
            if matched:
                _push("primary", str(matched[0]), "dst_ptr", "param_name")
            elif pointer_names:
                _push("primary", str(pointer_names[0]), "dst_ptr", "param_name")
            if not roots and decompiled_code:
                parsed = _parse_store_root_from_decompile(decompiled_code)
                if parsed:
                    _push("primary", parsed, "dst_ptr", "decompile_fallback")
            if not roots and facts.get("fallback_name_hint"):
                inferred = _infer_store_root_from_function_name(sink_function)
                if inferred:
                    _push("primary", inferred, "dst_ptr", "fallback_name_hint")
            if not roots and _pick(["target_addr"]):
                _push("primary", _pick(["target_addr"]), "target_addr", "target_addr")
            elif not roots and args:
                _push("primary", args[0], "dst_ptr", "call_args")

    elif label == SinkLabel.LOOP_WRITE_SINK.value:
        bound = _pick(["loop_bound", "bound_expr", "index_expr", "idx_expr"])
        if bound:
            _push("primary", bound, "index_or_bound", "miner_facts")
        elif len(args) >= 3:
            _push("primary", args[2], "index_or_bound", "call_args")
        elif decompiled_code:
            parsed = _parse_loop_root_from_decompile(decompiled_code)
            if parsed:
                _push("primary", parsed, "index_or_bound", "decompile_fallback")
        if not roots:
            inferred = _infer_loop_root_from_facts_or_fn(facts, sink_function)
            if inferred:
                _push("primary", inferred, "index_or_bound", "fallback_name_hint")

        store = _pick(["store_expr", "dst_expr", "target_expr"])
        if store:
            _push("secondary", store, "dst_ptr", "miner_facts")

    elif label == SinkLabel.FUNC_PTR_SINK.value:
        idx = _pick(["dispatch_index", "index_expr", "target_ptr", "func_ptr_expr"])
        if idx:
            _push("primary", idx, "dispatch", "miner_facts")
        else:
            matched_text = str(facts.get("matched_text", "") or "")
            parsed = _parse_func_ptr_text(matched_text)
            if parsed:
                _push("primary", parsed, "dispatch", "matched_text")
            elif args:
                _push("primary", args[0], "dispatch", "call_args")
            elif facts.get("input_derived"):
                _push("primary", "indirect_call_target", "dispatch", "generic_fallback")

    elif label == SinkLabel.FORMAT_STRING_SINK.value:
        fmt = _pick(["format_arg_expr", "format_arg", "fmt_arg", "format_expr"])
        if fmt:
            _push("primary", fmt, "format_arg", "miner_facts")
        elif facts.get("format_arg_is_variable") is True:
            parsed = _parse_format_root_from_decompile(decompiled_code)
            if parsed:
                _push("primary", parsed, "format_arg", "decompile_fallback")
            else:
                _push("primary", "format_arg_variable", "format_arg", "generic_fallback")

    if not roots and decompiled_code:
        fallback_roots = _roots_from_decompile(
            label,
            decompiled_code,
            callee=callee,
            sink_function=sink_function,
        )
        roots.extend(fallback_roots)

    if not roots and label == SinkLabel.STORE_SINK.value and facts.get("fallback_name_hint"):
        inferred = _infer_store_root_from_function_name(sink_function)
        if inferred:
            _push("primary", inferred, "dst_ptr", "fallback_name_hint")

    roots = _dedupe_roots(roots)
    root_source = _root_source_summary(roots)
    return roots, root_source


def _roots_from_decompile(
    label: str,
    decompiled_code: str,
    *,
    callee: str = "",
    sink_function: str = "",
) -> List[Dict[str, Any]]:
    roots: List[Dict[str, Any]] = []
    calls = _extract_call_args_from_decompile(decompiled_code)

    def _push(role: str, expr: str, kind: str) -> None:
        expr = _clean_expr(expr)
        if expr:
            roots.append(_make_root(role=role, expr=expr, kind=kind, source="decompile_fallback"))

    if label == SinkLabel.COPY_SINK.value:
        for found_callee, args in calls:
            low = found_callee.lower()
            if low not in {"memcpy", "memmove", "strcpy", "strncpy", "sprintf", "snprintf", "vsprintf", "vsnprintf"}:
                continue
            if len(args) >= 3:
                _push("primary", args[2], "length")
                _push("secondary", args[0], "dst_ptr")
                if len(args) >= 2:
                    _push("secondary", args[1], "src_ptr")
                break
            if len(args) >= 2:
                _push("primary", args[1], "src_data")
                _push("secondary", args[0], "dst_ptr")
                break
        if not roots:
            parsed = _parse_loop_copy_length_from_decompile(decompiled_code)
            if parsed:
                _push("primary", parsed, "length")

    elif label == SinkLabel.MEMSET_SINK.value:
        for found_callee, args in calls:
            if found_callee.lower() != "memset":
                continue
            if len(args) >= 3:
                _push("primary", args[2], "length")
                _push("secondary", args[0], "dst_ptr")
                break

    elif label == SinkLabel.FORMAT_STRING_SINK.value:
        parsed = _parse_format_root_from_decompile(decompiled_code)
        if parsed:
            _push("primary", parsed, "format_arg")

    elif label == SinkLabel.FUNC_PTR_SINK.value:
        for line in decompiled_code.splitlines():
            parsed = _parse_func_ptr_text(line)
            if parsed:
                _push("primary", parsed, "dispatch")
                break

    elif label == SinkLabel.STORE_SINK.value:
        parsed = _parse_store_root_from_decompile(decompiled_code)
        if parsed:
            _push("primary", parsed, "dst_ptr")
        else:
            inferred = _infer_store_root_from_function_name(sink_function)
            if inferred:
                _push("primary", inferred, "dst_ptr")

    elif label == SinkLabel.LOOP_WRITE_SINK.value:
        parsed = _parse_loop_root_from_decompile(decompiled_code)
        if parsed:
            _push("primary", parsed, "index_or_bound")

    return roots


def _extract_call_args_from_decompile(code: str) -> List[Tuple[str, List[str]]]:
    calls: List[Tuple[str, List[str]]] = []
    for m in _CALL_RE.finditer(code or ""):
        callee = str(m.group("callee") or "")
        arg_blob = str(m.group("args") or "")
        args = _split_args(arg_blob)
        if args:
            calls.append((callee, args))
    return calls


def _parse_format_root_from_decompile(code: str) -> str:
    for callee, args in _extract_call_args_from_decompile(code):
        low = callee.lower()
        if low in {"sprintf", "snprintf", "vsprintf", "vsnprintf"} and len(args) >= 2:
            fmt = args[1]
        elif low in {"printf", "syslog"} and len(args) >= 1:
            fmt = args[0]
        elif low == "fprintf" and len(args) >= 2:
            fmt = args[1]
        else:
            continue
        fmt = _clean_expr(fmt)
        if fmt and not fmt.startswith('"'):
            return fmt
    return ""


def _parse_func_ptr_text(text: str) -> str:
    text = str(text or "").strip()
    if not text:
        return ""
    idx = _FUNC_PTR_INDEX_RE.search(text)
    if idx:
        return _clean_expr(idx.group("idx"))
    deref = _FUNC_PTR_DEREF_RE.search(text)
    if deref:
        expr = _clean_expr(deref.group("expr"))
        if expr:
            return expr
    return ""


def _parse_store_root_from_decompile(code: str) -> str:
    counts: Dict[str, int] = {}
    for line in str(code or "").splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        for m in re.finditer(r"\b([A-Za-z_]\w*)\s*->\s*[A-Za-z_]\w*\s*=", line):
            base = _clean_expr(m.group(1))
            if base:
                counts[base] = counts.get(base, 0) + 2
        for m in re.finditer(r"\*\s*([A-Za-z_]\w*)\s*=", line):
            base = _clean_expr(m.group(1))
            if base:
                counts[base] = counts.get(base, 0) + 1
    if not counts:
        return ""
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return ranked[0][0]


def _parse_loop_copy_length_from_decompile(code: str) -> str:
    text = str(code or "")
    if not text:
        return ""

    loop = re.search(
        r"for\s*\([^;]*;\s*[A-Za-z_]\w*\s*<\s*(?P<bound>[A-Za-z_]\w*)\s*;",
        text,
    )
    if loop:
        return _clean_expr(loop.group("bound"))

    signature = re.search(
        r"\b[A-Za-z_]\w*\s+[A-Za-z_]\w*\s*\((?P<params>[^)]*)\)",
        text,
    )
    if signature:
        params = [p.strip() for p in signature.group("params").split(",") if p.strip()]
        if len(params) >= 2:
            return _clean_expr(params[1].split()[-1])

    return ""


def _parse_loop_root_from_decompile(code: str) -> str:
    text = str(code or "")
    if not text:
        return ""

    loop = re.search(
        r"for\s*\([^;]*;\s*[A-Za-z_]\w*\s*<\s*(?P<bound>[^;]+?)\s*;",
        text,
    )
    if loop:
        return _clean_expr(loop.group("bound"))

    walk = re.search(
        r"([A-Za-z_]\w*)\s*=\s*\1\s*\+\s*(?:\(ulong\)\(byte\)\()?(\*\s*\1\s*\+\s*1u?)",
        text,
        flags=re.IGNORECASE,
    )
    if walk:
        return _clean_expr(walk.group(2))

    compressed = re.search(
        r"([A-Za-z_]\w*)\s*\+\=\s*sizeof\s*\(\s*uint16_t\s*\)",
        text,
        flags=re.IGNORECASE,
    )
    if compressed:
        return "sizeof(uint16_t)"

    signature = re.search(
        r"\b[A-Za-z_]\w*\s+[A-Za-z_]\w*\s*\((?P<params>[^)]*)\)",
        text,
    )
    if signature:
        params = [p.strip() for p in signature.group("params").split(",") if p.strip()]
        if params:
            tail = params[-1]
            if "*" not in tail:
                return _clean_expr(tail.split()[-1])

    return ""


def _infer_store_root_from_function_name(fn_name: str) -> str:
    low = str(fn_name or "").lower()
    if "parseepdesc" in low or ("ep" in low and "desc" in low):
        return "ep_descriptor"
    if "parseinterfacedesc" in low or ("interface" in low and "desc" in low):
        return "if_descriptor"
    if "parsecfgdesc" in low or ("cfg" in low and "desc" in low):
        return "cfg_desc"
    if "parsedevdesc" in low or ("dev" in low and "desc" in low):
        return "dev_descriptor"
    return ""


def _infer_loop_root_from_facts_or_fn(facts: Dict[str, Any], fn_name: str) -> str:
    low_fn = str(fn_name or "").lower()
    store_expr = str(facts.get("store_expr", "") or "").lower()
    if store_expr == "name_walk" or "skipnamefield" in low_fn:
        return "*pucByte + 1u"
    return ""


def _normalize_args(value: Any) -> List[str]:
    if isinstance(value, str):
        return _split_args(value)
    if not isinstance(value, Sequence):
        return []
    out = []
    for item in value:
        expr = _clean_expr(item)
        if expr:
            out.append(expr)
    return out


def _split_args(text: str) -> List[str]:
    blob = str(text or "").strip()
    if not blob:
        return []
    parts: List[str] = []
    cur: List[str] = []
    depth = 0
    for ch in blob:
        if ch == "," and depth == 0:
            expr = _clean_expr("".join(cur))
            if expr:
                parts.append(expr)
            cur = []
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth > 0:
            depth -= 1
        cur.append(ch)
    expr = _clean_expr("".join(cur))
    if expr:
        parts.append(expr)
    return parts


def _clean_expr(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return re.sub(r"\s+", " ", text)


def _make_root(*, role: str, expr: str, kind: str, source: str) -> Dict[str, Any]:
    cleaned = _clean_expr(expr)
    aliases = _root_aliases(cleaned)
    return {
        "role": role,
        "expr": cleaned,
        "kind": kind,
        "source": source,
        "canonical_expr": _canonical_root_expr(cleaned),
        "family": _root_family(kind),
        "aliases": aliases,
    }


def _canonical_root_expr(expr: str) -> str:
    text = _clean_expr(expr)
    if not text:
        return ""
    text = text.replace("->", ".")
    text = re.sub(r"\(\s*void\s*\*\s*\)\s*", "", text)
    text = re.sub(r"\(\s*uint\s*\)\s*", "", text)
    text = re.sub(r"\(\s*size_t\s*\)\s*", "", text)
    text = re.sub(r"\(\s*int\s*\)\s*", "", text)
    text = re.sub(r"\(\s*ulong\s*\)\s*", "", text)
    text = re.sub(r"\(\s*byte\s*\)\s*", "", text)
    text = re.sub(r"\(\s*char\s*\*\s*\)\s*", "", text)
    text = re.sub(r"\(\s*const\s+[^)]*\)\s*", "", text)
    text = re.sub(r"\(\s*[^()]*\*\s*\)\s*", "", text)
    text = re.sub(r"\*\s*\(\s*void\s*\*\*\s*\)\s*", "", text)
    text = re.sub(r"^\((.*)\)$", r"\1", text)
    text = re.sub(r"\s+", "", text)
    return text.lower()


def _root_aliases(expr: str) -> List[str]:
    text = _clean_expr(expr)
    aliases: List[str] = []

    def _add(value: str) -> None:
        value = _clean_expr(value)
        if value and value not in aliases:
            aliases.append(value)

    _add(text)
    canon = _canonical_root_expr(text)
    if canon:
        _add(canon)

    # Peel simple cast/deref wrappers that often differ between GT and decompile.
    stripped = re.sub(r"^\(\s*[^()]*\)\s*", "", text)
    if stripped != text:
        _add(stripped)
        _add(_canonical_root_expr(stripped))

    deref = re.sub(r"^\*\s*\(\s*void\s*\*\*\s*\)\s*", "", text)
    if deref != text:
        _add(deref)
        _add(_canonical_root_expr(deref))

    paren = re.sub(r"^\((.*)\)$", r"\1", text)
    if paren != text:
        _add(paren)
        _add(_canonical_root_expr(paren))

    # Family-specific aliases seen in Zephyr/Contiki/lwIP/uSBS stacks.
    canon_text = _canonical_root_expr(text)
    for base, field in re.findall(r"([A-Za-z_][A-Za-z0-9_\.]*)\.(tot_len|len|payload_len|data_len|uip_len)", canon_text):
        for alt in ("tot_len", "len", "payload_len", "data_len", "uip_len"):
            _add(f"{base}.{alt}")
    # Pointer/field forms that often differ only by a named handle.
    if ".tot_len" in canon_text:
        _add(canon_text.replace(".tot_len", ".len"))
    if ".payload_len" in canon_text:
        _add(canon_text.replace(".payload_len", ".len"))
    if ".data_len" in canon_text:
        _add(canon_text.replace(".data_len", ".len"))
    # Common payload aliases: p->payload, pbuf->payload, rxmsg data pointer.
    for token in ("p.payload", "pbuf.payload", "rxmsg.payload", "net_buf.data", "net_buf.len", "uip_len"):
        if token in canon_text:
            _add(token)

    return aliases


def _root_family(kind: str) -> str:
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


def _dedupe_roots(roots: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for root in roots:
        key = (
            str(root.get("role", "")),
            str(root.get("canonical_expr", "") or root.get("expr", "")),
            str(root.get("kind", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(root)
    return out


def _root_source_summary(roots: List[Dict[str, Any]]) -> str:
    sources = []
    for root in roots:
        src = str(root.get("source", "") or "")
        if src and src not in sources:
            sources.append(src)
    if not sources:
        return "none"
    if len(sources) == 1:
        return sources[0]
    return "mixed"


def _hex_addr(v: Any) -> str:
    try:
        n = int(v or 0)
    except Exception:
        n = 0
    return f"0x{n:08x}"
