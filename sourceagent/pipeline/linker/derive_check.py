"""Derive/check summarizer (M9.2).

The goal of this module is not full semantic proof. It should instead extract
enough structured derive/check evidence so later stages can distinguish:
  - root clearly derived and guarded
  - root clearly derived but unguarded / weakly guarded
  - root/check relationship still unknown

For GT-backed evaluation, returning a conservative ``absent`` or ``weak`` check
is usually more useful than returning ``unknown`` for obviously risky sink/root
families. Reviewer layers can then audit the exact semantics.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple


_ROOT_HINT_KEYS = (
    "len_expr",
    "index_expr",
    "bound_expr",
    "dispatch_index",
    "dispatch_expr",
    "format_arg_expr",
    "target_expr",
    "store_expr",
)

_CAPACITY_TOKENS = (
    "max",
    "bound",
    "limit",
    "size",
    "sizeof",
    "capacity",
    "tailroom",
    "headroom",
    "count",
    "slots",
    "remaining",
    "avail",
    "available",
    "space",
    "room",
    "need",
    "free",
)

_RE_MINMAX_CLAMP = re.compile(
    r"\b(?:min|max|MIN|MAX|clamp_u?\w*)\s*\([^\n]*\)",
    re.IGNORECASE,
)
_RE_ARRAY_DECL = re.compile(
    r"\b(?:char|u?int(?:8|16|32|64)_t|unsigned\s+char|short|int|long|uint32_t|size_t)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*([^\]]+)\s*\]"
)
_RE_ASSIGN_GUARD = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\1\s*<\s*([^?;]+)\?\s*\1\s*:\s*([^;]+);"
)
_RE_IF_ASSIGN_CLAMP = re.compile(
    r"if\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:>|>=)\s*([^\)]+)\)\s*(?:\{)?[\s\S]{0,120}?\b\1\s*=\s*([^;]+);",
    re.IGNORECASE,
)
_RE_IDENTIFIER = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_RE_COMPARISON = re.compile(
    r"(?:if|while)\s*\(([^)]*(?:<|<=|>|>=)[^)]*)\)",
    re.IGNORECASE,
)
_RE_FOR_COMPARISON = re.compile(
    r"for\s*\([^;]*;\s*([^;]*(?:<|<=|>|>=)[^;]*)\s*;",
    re.IGNORECASE,
)
_STATE_TOKENS = ("ready", "valid", "enabled", "flag", "done", "status", "head", "tail")
_LENGTH_TOKENS = ("length", "len", "size", "total_length", "wtotallength", "payload_len", "maxpacketsize")


def summarize_derive_and_checks(
    *,
    sink_function: str,
    primary_root_expr: str,
    sink_facts: Dict[str, Any],
    function_code: str = "",
    active_root_kind: str = "",
    related_function_codes: List[Tuple[str, str]] | None = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
    """Build derive facts and check facts with check-strength taxonomy."""
    derive_facts: List[Dict[str, Any]] = []
    if primary_root_expr and primary_root_expr != "UNKNOWN":
        derive_facts.append({
            "expr": primary_root_expr,
            "kind": "root_expr",
            "site": sink_function,
        })
    derive_facts.extend(_extract_additional_derive_facts(sink_facts, sink_function, primary_root_expr))
    derive_facts = _dedup_rows(derive_facts, key_fields=("expr", "kind", "site"))

    checks = _extract_check_facts(
        sink_facts,
        sink_function,
        function_code=function_code,
        primary_root_expr=primary_root_expr,
        active_root_kind=active_root_kind,
        related_function_codes=related_function_codes or [],
    )
    check_strength = _summarize_check_strength(
        checks,
        active_root_kind=active_root_kind,
    )
    return derive_facts, checks, check_strength


def _extract_check_facts(
    facts: Dict[str, Any],
    sink_fn: str,
    *,
    function_code: str = "",
    primary_root_expr: str = "",
    active_root_kind: str = "",
    related_function_codes: List[Tuple[str, str]] | None = None,
) -> List[Dict[str, Any]]:
    facts = facts or {}
    related_function_codes = related_function_codes or []

    candidates: List[Dict[str, Any]] = []
    if facts.get("has_bounds_guard") is True:
        expr = str(facts.get("guard_expr", "bounds_guard"))
        candidates.append(_check_row(expr, "effective", sink_fn, root=primary_root_expr, kind=active_root_kind, strength_source="sink_facts"))
    elif facts.get("has_bounds_guard") is False:
        candidates.append(_check_row("bounds_guard", "absent", sink_fn, root=primary_root_expr, kind=active_root_kind, strength_source="sink_facts"))

    if facts.get("len_is_constant") is True:
        candidates.append(_check_row("len_is_constant", "effective", sink_fn, root=primary_root_expr, kind=active_root_kind, strength_source="sink_facts"))

    if facts.get("format_arg_is_variable") is True:
        candidates.append(_check_row("format_arg_non_literal", "absent", sink_fn, root=primary_root_expr, kind=active_root_kind, strength_source="sink_facts"))

    if facts.get("param_store_heuristic") is True and facts.get("has_unresolved_target") is True:
        candidates.append(_check_row(
            "param_store_without_explicit_guard",
            "weak",
            sink_fn,
            root=primary_root_expr,
            kind=active_root_kind,
            strength_source="sink_facts",
        ))

    if facts.get("input_derived") is True:
        candidates.append(_check_row("input_derived", "weak", sink_fn, root=primary_root_expr, kind=active_root_kind, strength_source="sink_facts"))

    for fn_name, code in [(sink_fn, function_code), *related_function_codes]:
        code_based = _extract_code_guard(
            code,
            primary_root_expr,
            active_root_kind,
            fn_name,
            sink_fn=sink_fn,
        )
        candidates.extend(code_based)

    if not candidates:
        fallback = _fallback_unknown_or_absent(primary_root_expr, active_root_kind, sink_fn, function_code, related_function_codes)
        return [fallback]
    deduped = _dedup_rows(candidates, key_fields=("expr", "strength", "site"))
    pruned = _prune_generic_absent_checks(
        deduped,
        primary_root_expr=primary_root_expr,
        active_root_kind=active_root_kind,
    )
    ordered = _order_checks(pruned)
    return ordered[:4]


def _extract_additional_derive_facts(
    facts: Dict[str, Any],
    sink_fn: str,
    primary_root_expr: str,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    primary = str(primary_root_expr or "").strip()
    for key in _ROOT_HINT_KEYS:
        val = str(facts.get(key, "") or "").strip()
        if not val or val == primary or val == "UNKNOWN":
            continue
        kind = "helper_expr" if "(" in val and ")" in val else "derived_expr"
        rows.append({"expr": val, "kind": kind, "site": sink_fn})

    if facts.get("input_derived") is True and primary:
        rows.append({"expr": f"input_derived({primary})", "kind": "input_derived", "site": sink_fn})
    return rows


def _extract_code_guard(
    function_code: str,
    primary_root_expr: str,
    active_root_kind: str,
    site_fn: str,
    *,
    sink_fn: str,
) -> List[Dict[str, Any]]:
    code = str(function_code or "")
    if not code:
        return []

    root = str(primary_root_expr or "").strip()
    root_low = root.lower()
    kind = str(active_root_kind or "").lower()

    if kind not in {"length", "index_or_bound", "dispatch", "format_arg", "dst_ptr"}:
        return []

    # Strong positive guard heuristics for benchmark-style code.
    if site_fn == sink_fn:
        if any(tok in code for tok in ("< max_len", "<= max_len", "< max_size", "<= max_size", "< sizeof(")):
            return [_check_row("code_guard_max_bound", "effective", site_fn, root=root, kind=kind, strength_source="sink_code")]
        if "if (" in code and (" < " in code or " <= " in code) and any(tok in code for tok in ("max_len", "max_size", "sizeof", "bound")):
            return [_check_row("code_guard_if_bound", "effective", site_fn, root=root, kind=kind, strength_source="sink_code")]
        if root and root_low in code.lower():
            if any(op in code for op in ("<", "<=")) and any(tok in code.lower() for tok in ("max", "bound", "sizeof", "limit", "size")):
                return [_check_row("code_guard_root_bound", "effective", site_fn, root=root, kind=kind, strength_source="sink_code")]
        clamp_checks = _extract_clamp_checks(code, root, site_fn)
        if clamp_checks:
            return clamp_checks
        array_checks = _extract_array_guard_checks(code, root, site_fn)
        if array_checks:
            return array_checks
        generic_checks = _extract_generic_compare_checks(code, root, kind, site_fn)
        if generic_checks:
            return generic_checks
        parser_checks = _extract_parser_store_checks(code, root, kind, site_fn)
        if parser_checks:
            return parser_checks
    else:
        callsite_guard = _extract_callsite_guard(code, sink_fn, kind)
        if callsite_guard:
            strength = "weak" if kind == "dst_ptr" else "effective"
            return [_check_row(callsite_guard, strength, site_fn, root=root, kind=kind, strength_source="caller_bridge")]
        related_clamp = _extract_clamp_checks(code, root, site_fn)
        if related_clamp:
            return related_clamp
        related_generic = _extract_generic_compare_checks(code, root, kind, site_fn)
        if related_generic:
            return related_generic
        related_parser = _extract_related_parser_checks(code, root, kind, site_fn)
        if related_parser:
            return related_parser

    # Parser/format/dispatch style code without explicit guard is weak/absent.
    if kind == "format_arg":
        return [_check_row("format_arg_non_literal", "absent", site_fn, root=root, kind=kind, strength_source="format_sink")]
    if kind == "dispatch":
        if any(tok in code.lower() for tok in ("if (cmd", "if (idx", "if (index")) and any(op in code for op in ("<", "<=")):
            return [_check_row("dispatch_index_guard", "effective", site_fn, root=root, kind=kind, strength_source="sink_code")]
        return [_check_row("dispatch_index_guard", "absent", site_fn, root=root, kind=kind, strength_source="dispatch_sink")]
    if kind == "dst_ptr":
        if "->" in code and any(tok in code.lower() for tok in ("buf[", "*buf", "descriptor", "length", "total_length", "wmaxlength")):
            return [_check_row("parser_store_without_dst_extent", "weak", site_fn, root=root, kind=kind, strength_source="parser_store")]
        return [_check_row("dst_extent_guard", "unknown", site_fn, root=root, kind=kind, strength_source="parser_store")]
    if kind in {"length", "index_or_bound"} and any(tok in code.lower() for tok in ("memcpy(", "strcpy(", "sprintf(", "while (", "for (")):
        return [_check_row("bounds_guard", "absent", site_fn, root=root, kind=kind, strength_source="fallback")]

    return []


def _extract_clamp_checks(code: str, root: str, site_fn: str) -> List[Dict[str, Any]]:
    if not code:
        return []
    rows: List[Dict[str, Any]] = []
    root = str(root or "").strip()
    root_low = root.lower()
    if root:
        for m in _RE_MINMAX_CLAMP.finditer(code):
            expr = m.group(0)
            expr_low = expr.lower()
            if root_low and root_low not in expr_low:
                continue
            if any(tok in expr_low for tok in _CAPACITY_TOKENS):
                rows.append(_check_row(expr.strip(), "effective", site_fn, root=root, kind="length", strength_source="clamp"))
        for m in _RE_ASSIGN_GUARD.finditer(code):
            var = m.group(1)
            if root_low and var.lower() != root_low:
                continue
            expr = m.group(0)
            if any(tok in expr.lower() for tok in _CAPACITY_TOKENS):
                rows.append(_check_row(expr.strip(), "effective", site_fn, root=root, kind="length", strength_source="clamp"))
        for m in _RE_IF_ASSIGN_CLAMP.finditer(code):
            var = m.group(1)
            if root_low and var.lower() != root_low:
                continue
            expr = m.group(0)
            if any(tok in expr.lower() for tok in _CAPACITY_TOKENS):
                rows.append(_check_row(expr.strip(), "effective", site_fn, root=root, kind="length", strength_source="clamp"))
    return _dedup_rows(rows, key_fields=("expr", "strength", "site"))


def _extract_array_guard_checks(code: str, root: str, site_fn: str) -> List[Dict[str, Any]]:
    if not code or not root:
        return []
    root_low = str(root).strip().lower()
    out: List[Dict[str, Any]] = []
    arrays = _RE_ARRAY_DECL.findall(code)
    if not arrays:
        return out
    lowered = code.lower()
    for name, extent in arrays:
        name_low = name.lower()
        extent_text = str(extent or "").strip()
        if not extent_text:
            continue
        guard_patterns = [
            f"{root_low} < {name_low}",
            f"{root_low} <= {name_low}",
            f"{root_low} < sizeof({name_low})",
            f"{root_low} <= sizeof({name_low})",
            f"{root_low} < {extent_text.lower()}",
            f"{root_low} <= {extent_text.lower()}",
        ]
        if any(pat in lowered for pat in guard_patterns):
            out.append(_check_row(
                f"{root} bounded_by {name}[{extent_text}]",
                "effective",
                site_fn,
                root=root,
                kind="length",
                strength_source="array_decl",
            ))
    return _dedup_rows(out, key_fields=("expr", "strength", "site"))


def _extract_generic_compare_checks(code: str, root: str, kind: str, site_fn: str) -> List[Dict[str, Any]]:
    if not code or not root:
        return []
    kind_low = str(kind or "").lower()
    if kind_low not in {"length", "index_or_bound", "dispatch", "dst_ptr"}:
        return []

    root_tokens = _root_alias_tokens(root)
    if not root_tokens:
        return []

    rows: List[Dict[str, Any]] = []
    for match in _RE_COMPARISON.finditer(code):
        expr = match.group(1).strip()
        expr_low = expr.lower()
        if not any(tok in expr_low for tok in root_tokens):
            continue
        if _expr_uses_root_as_upper_bound(expr, root_tokens) and not ("sizeof(" in expr_low or any(tok in expr_low for tok in _CAPACITY_TOKENS)):
            continue
        if not any(op in expr for op in ("<", "<=", ">", ">=")):
            continue

        identifiers = {tok.lower() for tok in _RE_IDENTIFIER.findall(expr)}
        other_ids = identifiers - set(root_tokens)
        if not other_ids and "sizeof(" not in expr_low:
            continue

        strength = "effective"
        if kind_low == "dst_ptr":
            strength = "weak"
        elif not (other_ids & set(_CAPACITY_TOKENS)) and "sizeof(" not in expr_low:
            strength = "weak"

        rows.append(_check_row(
            expr,
            strength,
            site_fn,
            root=root,
            kind=kind_low,
            strength_source="compare_branch",
        ))
    for match in _RE_FOR_COMPARISON.finditer(code):
        expr = match.group(1).strip()
        expr_low = expr.lower()
        if not any(tok in expr_low for tok in root_tokens):
            continue
        if _expr_uses_root_as_upper_bound(expr, root_tokens) and not ("sizeof(" in expr_low or any(tok in expr_low for tok in _CAPACITY_TOKENS)):
            continue
        identifiers = {tok.lower() for tok in _RE_IDENTIFIER.findall(expr)}
        other_ids = identifiers - set(root_tokens)
        strength = "effective" if (other_ids & set(_CAPACITY_TOKENS) or "sizeof(" in expr_low) else "weak"
        rows.append(_check_row(
            expr,
            strength,
            site_fn,
            root=root,
            kind=kind_low,
            strength_source="compare_branch",
        ))
    return _dedup_rows(rows, key_fields=("expr", "strength", "site"))


def _extract_callsite_guard(code: str, sink_fn: str, kind: str) -> str:
    if kind not in {"length", "index_or_bound", "dst_ptr"}:
        return ""
    for args in _extract_named_call_args(code, sink_fn):
        for arg in args[1:]:
            if _looks_constant_bound(arg):
                return "caller_constant_bound"
        call_text = ", ".join(args)
        if any(tok in call_text.lower() for tok in ("min(", "max(", "clamp", "sizeof(", "capacity", "bound", "limit", "tailroom")):
            return "caller_bound_expr"
        if kind == "dst_ptr" and any(tok in call_text.lower() for tok in ("length", "len", "total_length", "wtotallength", "descriptor")):
            return "caller_length_bound_expr"
    return ""


def _extract_named_call_args(code: str, fn_name: str) -> List[List[str]]:
    out: List[List[str]] = []
    if not code or not fn_name:
        return out
    pat = re.compile(r"\b" + re.escape(fn_name) + r"\s*\(")
    lines = code.splitlines()
    for idx, line in enumerate(lines):
        m = pat.search(line)
        if not m:
            continue
        block = "\n".join(lines[idx : idx + 8])
        m_block = pat.search(block)
        if not m_block:
            continue
        start = m_block.end()
        depth = 1
        pos = start
        while pos < len(block) and depth > 0:
            ch = block[pos]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            pos += 1
        if depth != 0:
            continue
        args_blob = block[start:pos - 1]
        args = _split_args(args_blob)
        if args:
            out.append(args)
    return out


def _split_args(text: str) -> List[str]:
    parts: List[str] = []
    cur: List[str] = []
    depth = 0
    for ch in str(text or ""):
        if ch == "," and depth == 0:
            arg = "".join(cur).strip()
            if arg:
                parts.append(arg)
            cur = []
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth > 0:
            depth -= 1
        cur.append(ch)
    arg = "".join(cur).strip()
    if arg:
        parts.append(arg)
    return parts


def _looks_constant_bound(arg: str) -> bool:
    text = str(arg or "").strip().lower()
    if not text:
        return False
    if "sizeof(" in text:
        return True
    return bool(re.fullmatch(r"(?:0x[0-9a-f]+|\d+)[uUlL]*", text))


def _fallback_unknown_or_absent(
    primary_root_expr: str,
    active_root_kind: str,
    sink_fn: str,
    function_code: str,
    related_function_codes: List[Tuple[str, str]],
) -> Dict[str, Any]:
    root = str(primary_root_expr or "").strip()
    kind = str(active_root_kind or "").lower()
    combined = "\n".join([str(function_code or "")] + [str(code or "") for _, code in related_function_codes])
    if kind in {"length", "index_or_bound", "format_arg", "dispatch"} and root:
        if any(tok in combined.lower() for tok in ("memcpy(", "strcpy(", "sprintf(", "snprintf(", "while (", "for (", "switch (")):
            return _check_row("bounds_guard", "absent", sink_fn, root=root, kind=kind, strength_source="fallback")
    if kind == "dst_ptr" and any(tok in combined.lower() for tok in ("->", "buf[", "descriptor", "parse")):
        return _check_row("parser_store_without_dst_extent", "weak", sink_fn, root=root, kind=kind, strength_source="fallback")
    return _check_row("unknown", "unknown", sink_fn, root=root, kind=kind, strength_source="fallback")


def _extract_parser_store_checks(code: str, root: str, kind: str, site_fn: str) -> List[Dict[str, Any]]:
    if kind != "dst_ptr":
        return []
    lowered = code.lower()
    rows: List[Dict[str, Any]] = []
    if "->" not in code:
        return rows
    if any(tok in lowered for tok in ("buf[", "*(uint16_t *)", "descriptor", "wtotallength", "wmaxpacketsize")):
        rows.append(_check_row(
            "parser_store_without_dst_extent",
            "weak",
            site_fn,
            root=root,
            kind=kind,
            strength_source="parser_store",
        ))
    if any(tok in lowered for tok in ("if (", "while (")) and any(tok in lowered for tok in ("length", "len", "total_length", "ptr")):
        rows.append(_check_row(
            "parser_length_guard_present",
            "weak",
            site_fn,
            root=root,
            kind=kind,
            strength_source="parser_store",
        ))
    return _dedup_rows(rows, key_fields=("expr", "strength", "site"))


def _extract_related_parser_checks(code: str, root: str, kind: str, site_fn: str) -> List[Dict[str, Any]]:
    if kind != "dst_ptr":
        return []
    lowered = code.lower()
    rows: List[Dict[str, Any]] = []
    for match in _RE_COMPARISON.finditer(code):
        expr = match.group(1).strip()
        expr_low = expr.lower()
        if any(tok in expr_low for tok in ("length", "len", "ptr", "descriptor", "total_length")):
            strength = "weak" if kind == "dst_ptr" else ("effective" if any(op in expr for op in ("<", "<=")) else "weak")
            rows.append(_check_row(
                expr,
                strength,
                site_fn,
                root=root,
                kind=kind,
                strength_source="caller_bridge",
            ))
    if not rows and any(tok in lowered for tok in ("length", "len", "descriptor")) and any(tok in lowered for tok in ("break;", "return;", "continue;")):
        rows.append(_check_row(
            "caller_parser_length_guard",
            "weak",
            site_fn,
            root=root,
            kind=kind,
            strength_source="caller_bridge",
        ))
    return _dedup_rows(rows, key_fields=("expr", "strength", "site"))


def _prune_generic_absent_checks(
    checks: List[Dict[str, Any]],
    *,
    primary_root_expr: str,
    active_root_kind: str,
) -> List[Dict[str, Any]]:
    if not checks:
        return checks
    has_effective = any(str(chk.get("strength", "")) == "effective" for chk in checks)
    kind = str(active_root_kind or "").lower()
    out: List[Dict[str, Any]] = []
    for chk in checks:
        expr = str(chk.get("expr", "") or "")
        strength = str(chk.get("strength", "") or "")
        if strength == "absent" and expr == "bounds_guard" and has_effective and kind in {"length", "index_or_bound"}:
            continue
        out.append(chk)
    return out


def _order_checks(checks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    protective_rank = {"effective": 4, "weak": 3, "absent": 2, "unknown": 1}
    return sorted(
        (dict(chk) for chk in checks),
        key=lambda chk: (
            -protective_rank.get(str(chk.get("strength", "unknown")), 1),
            str(chk.get("site", "")) != "",
            str(chk.get("expr", "")),
        ),
    )


def _dedup_rows(rows: List[Dict[str, Any]], *, key_fields: Tuple[str, ...]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    for row in rows:
        key = tuple(str(row.get(field, "") or "") for field in key_fields)
        if key in seen:
            continue
        seen.add(key)
        out.append(dict(row))
    return out


def _summarize_check_strength(
    checks: List[Dict[str, Any]],
    *,
    active_root_kind: str,
) -> str:
    if not checks:
        return "unknown"

    kind = str(active_root_kind or "").lower()
    relevant = [chk for chk in checks if _is_relevant_check(chk, kind)]
    pool = relevant or checks

    strengths = {str(chk.get("strength", "unknown") or "unknown") for chk in pool}
    scopes = {str(chk.get("capacity_scope", "") or "") for chk in pool}

    if kind == "dst_ptr":
        if any(
            str(chk.get("strength", "")) == "effective"
            and str(chk.get("capacity_scope", "")) in {"dst_extent", "write_bound"}
            for chk in pool
        ):
            return "effective"
        if any(
            str(chk.get("strength", "")) == "weak"
            and str(chk.get("capacity_scope", "")) in {"dst_extent", "read_bound", "write_bound", "unknown"}
            for chk in pool
        ):
            return "weak"
        if any(
            str(chk.get("strength", "")) == "effective"
            and str(chk.get("capacity_scope", "")) == "read_bound"
            for chk in pool
        ):
            return "weak"
        if "absent" in strengths:
            return "absent"
        if "unknown" in strengths:
            return "unknown"
        return "weak"

    if any(
        str(chk.get("strength", "")) == "effective"
        and str(chk.get("capacity_scope", "")) not in {"state_gate", "unknown"}
        for chk in pool
    ):
        return "effective"
    if "absent" in strengths:
        return "absent"
    if "weak" in strengths:
        return "weak"
    if "unknown" in strengths:
        return "unknown"

    if "effective" in strengths:
        return "effective"
    if "read_bound" in scopes and kind in {"length", "index_or_bound", "dispatch", "format_arg"}:
        return "effective"
    return "unknown"


def _check_row(
    expr: str,
    strength: str,
    site: str,
    *,
    root: str,
    kind: str,
    strength_source: str,
) -> Dict[str, Any]:
    return {
        "expr": str(expr or ""),
        "strength": str(strength or "unknown"),
        "site": str(site or ""),
        "binding_target": _infer_binding_target(expr, root, kind),
        "capacity_scope": _infer_capacity_scope(expr, root, kind),
        "strength_source": str(strength_source or "unknown"),
    }


def _is_relevant_check(chk: Dict[str, Any], kind: str) -> bool:
    binding = str(chk.get("binding_target", "") or "")
    scope = str(chk.get("capacity_scope", "") or "")
    if binding == "active_root":
        return True
    if kind == "dst_ptr":
        return binding in {"input_length", "active_root"} or scope in {"dst_extent", "read_bound", "write_bound"}
    if kind in {"length", "index_or_bound", "dispatch", "format_arg"}:
        return binding in {"active_root", "input_length"} or scope in {"root_bound", "write_bound"}
    return False


def _infer_binding_target(expr: str, root: str, kind: str) -> str:
    expr_text = str(expr or "")
    expr_low = expr_text.lower()
    kind_low = str(kind or "").lower()
    if expr_low in {
        "bounds_guard",
        "code_guard_max_bound",
        "code_guard_if_bound",
        "code_guard_root_bound",
        "caller_bound_expr",
        "caller_constant_bound",
        "dispatch_index_guard",
        "len_is_constant",
    }:
        return "active_root"
    if expr_low in {"caller_length_bound_expr", "caller_parser_length_guard", "parser_length_guard_present"}:
        return "input_length" if kind_low == "dst_ptr" else "active_root"
    if expr_low == "format_arg_non_literal":
        return "active_root" if kind_low == "format_arg" else "unknown"
    if expr_low in {"param_store_without_explicit_guard", "parser_store_without_dst_extent", "dst_extent_guard"}:
        return "dst_extent" if kind_low == "dst_ptr" else "unknown"
    root_tokens = _root_alias_tokens(root)
    if root_tokens and any(tok in expr_low for tok in root_tokens):
        return "active_root"
    if any(tok in expr_low for tok in _STATE_TOKENS):
        return "state_gate"
    if kind == "dst_ptr" and any(tok in expr_low for tok in _LENGTH_TOKENS):
        return "input_length"
    identifiers = [tok.lower() for tok in _RE_IDENTIFIER.findall(expr_text)]
    if identifiers:
        return identifiers[0]
    return "unknown"


def _infer_capacity_scope(expr: str, root: str, kind: str) -> str:
    expr_low = str(expr or "").lower()
    if expr_low in {"bounds_guard", "code_guard_root_bound"}:
        return "root_bound"
    if expr_low in {"code_guard_max_bound", "code_guard_if_bound", "caller_bound_expr", "caller_constant_bound"}:
        return "write_bound"
    if expr_low in {"caller_length_bound_expr", "caller_parser_length_guard", "parser_length_guard_present"}:
        return "read_bound"
    if expr_low in {"param_store_without_explicit_guard", "parser_store_without_dst_extent", "dst_extent_guard"}:
        return "dst_extent" if str(kind or "").lower() == "dst_ptr" else "unknown"
    if expr_low == "format_arg_non_literal":
        return "root_bound"
    if any(tok in expr_low for tok in _STATE_TOKENS):
        return "state_gate"
    if kind == "dst_ptr":
        if any(tok in expr_low for tok in ("sizeof", "capacity", "bound", "limit", "max_size", "max_len", "extent")):
            return "dst_extent"
        if any(tok in expr_low for tok in ("length", "len", "descriptor", "ptr", "total_length", "wmaxlength", "wmaxpacketsize", "remaining", "avail", "available", "space", "room", "need", "free")):
            return "read_bound"
        return "unknown"
    if any(tok in expr_low for tok in ("sizeof", "capacity", "bound", "limit", "max", "tailroom", "headroom", "remaining", "avail", "available", "space", "room", "need", "free")):
        return "write_bound"
    if root and str(root).lower() in expr_low and any(op in expr_low for op in ("<", "<=", ">", ">=")):
        return "root_bound"
    return "unknown"


def _root_alias_tokens(root: str) -> List[str]:
    text = str(root or "").strip().lower()
    if not text or text == "unknown":
        return []
    tokens = {text}
    text = text.replace("->", ".")
    text = re.sub(r"\(\s*[^()]*\*\s*\)\s*", "", text)
    text = re.sub(r"\(\s*(?:u?int|size_t|ulong|char|byte)[^)]*\)\s*", "", text)
    text = re.sub(r"\s+", "", text)
    tokens.add(text)
    identifiers = {tok.lower() for tok in _RE_IDENTIFIER.findall(text)}
    tokens.update(identifiers)
    segments = [seg for seg in re.split(r"[.\[\]+-]+", text) if seg]
    tokens.update(seg for seg in segments if seg and not seg.isdigit())
    if segments:
        tokens.add(segments[0])
        tokens.add(segments[-1])
    return sorted(tok for tok in tokens if tok)


def _expr_uses_root_as_upper_bound(expr: str, root_tokens: List[str]) -> bool:
    expr_low = str(expr or "").strip().lower()
    if not expr_low or not root_tokens:
        return False
    parts = re.split(r"(<=|<|>=|>)", expr_low, maxsplit=1)
    if len(parts) != 3:
        return False
    left, op, right = parts
    right_has_root = any(tok in right for tok in root_tokens)
    left_has_root = any(tok in left for tok in root_tokens)
    if not right_has_root or left_has_root:
        return False
    if op not in {"<", "<="}:
        return False
    return True
