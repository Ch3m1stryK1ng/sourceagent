"""Derive/check summarizer (M9.2)."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple


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

    checks = _extract_check_facts(
        sink_facts,
        sink_function,
        function_code=function_code,
        primary_root_expr=primary_root_expr,
        active_root_kind=active_root_kind,
        related_function_codes=related_function_codes or [],
    )
    check_strength = _worst_check_strength(checks)
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
        candidates.append({"expr": expr, "strength": "effective", "site": sink_fn})
    elif facts.get("has_bounds_guard") is False:
        candidates.append({"expr": "bounds_guard", "strength": "absent", "site": sink_fn})

    if facts.get("len_is_constant") is True:
        candidates.append({"expr": "len_is_constant", "strength": "effective", "site": sink_fn})

    if facts.get("format_arg_is_variable") is True:
        candidates.append({"expr": "format_arg_non_literal", "strength": "absent", "site": sink_fn})

    if facts.get("param_store_heuristic") is True and facts.get("has_unresolved_target") is True:
        candidates.append({
            "expr": "param_store_without_explicit_guard",
            "strength": "weak",
            "site": sink_fn,
        })

    if facts.get("input_derived") is True:
        candidates.append({"expr": "input_derived", "strength": "weak", "site": sink_fn})

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
        return [{"expr": "unknown", "strength": "unknown", "site": sink_fn}]
    return [_pick_best_check(candidates)]


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

    if kind not in {"length", "index_or_bound", "dispatch", "format_arg"}:
        return []

    # Strong positive guard heuristics for benchmark-style code.
    if site_fn == sink_fn:
        if any(tok in code for tok in ("< max_len", "<= max_len", "< max_size", "<= max_size", "< sizeof(")):
            return [{"expr": "code_guard_max_bound", "strength": "effective", "site": site_fn}]
        if "if (" in code and (" < " in code or " <= " in code) and any(tok in code for tok in ("max_len", "max_size", "sizeof", "bound")):
            return [{"expr": "code_guard_if_bound", "strength": "effective", "site": site_fn}]
        if root and root_low in code.lower():
            if any(op in code for op in ("<", "<=")) and any(tok in code.lower() for tok in ("max", "bound", "sizeof", "limit", "size")):
                return [{"expr": "code_guard_root_bound", "strength": "effective", "site": site_fn}]
    else:
        callsite_guard = _extract_callsite_guard(code, sink_fn, kind)
        if callsite_guard:
            return [{"expr": callsite_guard, "strength": "effective", "site": site_fn}]

    # Parser/format/dispatch style code without explicit guard is weak/absent.
    if kind == "format_arg":
        return [{"expr": "format_arg_non_literal", "strength": "absent", "site": site_fn}]
    if kind == "dispatch":
        if any(tok in code.lower() for tok in ("if (cmd", "if (idx", "if (index")) and any(op in code for op in ("<", "<=")):
            return [{"expr": "dispatch_index_guard", "strength": "effective", "site": site_fn}]
        return [{"expr": "dispatch_index_guard", "strength": "absent", "site": site_fn}]
    if kind in {"length", "index_or_bound"} and any(tok in code.lower() for tok in ("memcpy(", "strcpy(", "sprintf(", "while (", "for (")):
        return [{"expr": "bounds_guard", "strength": "absent", "site": site_fn}]

    return []


def _extract_callsite_guard(code: str, sink_fn: str, kind: str) -> str:
    if kind not in {"length", "index_or_bound"}:
        return ""
    for args in _extract_named_call_args(code, sink_fn):
        for arg in args[1:]:
            if _looks_constant_bound(arg):
                return "caller_constant_bound"
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


def _pick_best_check(checks: List[Dict[str, Any]]) -> Dict[str, Any]:
    protective_rank = {"effective": 4, "weak": 3, "absent": 2, "unknown": 1}
    ordered = sorted(
        (dict(chk) for chk in checks),
        key=lambda chk: (
            -protective_rank.get(str(chk.get("strength", "unknown")), 1),
            str(chk.get("site", "")) != "",
            str(chk.get("expr", "")),
        ),
    )
    return ordered[0]


def _worst_check_strength(checks: List[Dict[str, Any]]) -> str:
    order = {"absent": 3, "weak": 2, "unknown": 1, "effective": 0}
    best = "effective"
    best_rank = -1
    for chk in checks:
        s = str(chk.get("strength", "unknown"))
        rank = order.get(s, 1)
        if rank > best_rank:
            best_rank = rank
            best = s
    return best
