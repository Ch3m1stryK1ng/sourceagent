"""Stage 4 — FORMAT_STRING_SINK miner.

Detects calls to printf-family functions where the format string argument
is not a compile-time string literal (i.e., attacker-controlled format).

Strategy:
  1. Find printf-family symbols (symbol search + heuristic classifier fallback)
  2. For each symbol, find callsites via xrefs (with decompile-cache fallback)
  3. Decompile each caller, check if format argument is a string literal
  4. If format arg is variable/parameter → FORMAT_STRING_SINK
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from ..models import (
    EvidenceItem,
    MemoryAccessIndex,
    MemoryMap,
    SinkCandidate,
    SinkLabel,
)

logger = logging.getLogger("sourceagent.pipeline.miners.format_string_sink")

# Printf-family functions and which arg index (0-based) is the format string.
_FORMAT_FUNCTIONS: Dict[str, int] = {
    "printf": 0,
    "fprintf": 1,
    "sprintf": 1,
    "snprintf": 2,
    "vprintf": 0,
    "vfprintf": 1,
    "vsprintf": 1,
    "vsnprintf": 2,
    "syslog": 1,
}

# Regex: call to a format function with a string literal as format arg.
# If this matches, the format is constant → not a sink.
_RE_CONST_FORMAT = re.compile(
    r'\b(?:printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|vsnprintf|syslog)'
    r'\s*\('
    r'(?:[^,]*,\s*)*'   # skip preceding args
    r'"'                 # opening quote → constant format
)


async def mine_format_string_sinks(
    memory_map: MemoryMap,
    mcp_manager: object,
    ghidra_binary_name: str,
    mai: Optional[MemoryAccessIndex] = None,
) -> List[SinkCandidate]:
    """Mine FORMAT_STRING_SINK candidates."""
    if mcp_manager is None:
        return []

    # Step 1: Find printf-family symbols
    symbols = await _find_format_symbols(mcp_manager, ghidra_binary_name)
    if not symbols:
        logger.info("No printf-family symbols found in %s", ghidra_binary_name)

    if symbols:
        logger.info(
            "Found %d format function symbols: %s",
            len(symbols), [s["name"] for s in symbols],
        )

    candidates: List[SinkCandidate] = []
    seen: set = set()

    for sym in symbols:
        callee_name = sym["name"]
        callee_addr = sym["address"]

        # Step 2: Find callsites
        xrefs = await _find_xrefs(mcp_manager, ghidra_binary_name, callee_addr)
        if not xrefs and mai and mai.decompiled_cache:
            from .copy_sink import _find_callers_from_decompile_cache
            xrefs = _find_callers_from_decompile_cache(
                mai.decompiled_cache, callee_name, callee_addr,
            )

        for xref in xrefs:
            caller_func = xref.get("function_name") or ""
            if not caller_func:
                continue
            dedup_key = (caller_func, callee_name)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # Step 3: Decompile caller, check format argument
            code = None
            if mai and mai.decompiled_cache:
                code = mai.decompiled_cache.get(caller_func)
            if not code:
                resp = await _call_mcp_json(mcp_manager, "decompile_function", {
                    "binary_name": ghidra_binary_name,
                    "name_or_address": caller_func,
                })
                if resp:
                    code = resp.get("code", "")
            if not code:
                continue

            # Check if this specific call uses a constant format string
            if _has_const_format(code, callee_name):
                continue  # safe — format is a string literal

            # Variable/parameter format → FORMAT_STRING_SINK
            func_addr = _parse_func_addr(caller_func)
            candidates.append(SinkCandidate(
                address=func_addr,
                function_name=caller_func,
                preliminary_label=SinkLabel.FORMAT_STRING_SINK,
                evidence=[
                    EvidenceItem(
                        evidence_id="E1", kind="SITE",
                        text=f"{callee_name}() called with non-literal format string",
                        address=func_addr,
                    ),
                ],
                confidence_score=0.60,
                facts={
                    "format_func": callee_name,
                    "format_arg_is_variable": True,
                },
            ))

    # Parallel path: scan decompile cache for format function calls even
    # when symbol-based mining found nothing (small firmware may not have
    # printf symbols in the symbol table but still use them).
    if mai and mai.decompiled_cache:
        for func_name, code in mai.decompiled_cache.items():
            lines = code.strip().split('\n')
            if len(lines) > 120:
                continue  # skip large functions (likely library internals)
            for fmt_func in _FORMAT_FUNCTIONS:
                # Quick check: is this function name in the code?
                if fmt_func + "(" not in code and fmt_func + " (" not in code:
                    continue
                dedup_key = (func_name, fmt_func)
                if dedup_key in seen:
                    continue
                # Check if ALL calls use constant format strings
                if _has_const_format(code, fmt_func):
                    continue  # safe — all calls use literal format
                seen.add(dedup_key)
                func_addr = _parse_func_addr(func_name)
                candidates.append(SinkCandidate(
                    address=func_addr,
                    function_name=func_name,
                    preliminary_label=SinkLabel.FORMAT_STRING_SINK,
                    evidence=[
                        EvidenceItem(
                            evidence_id="E1", kind="SITE",
                            text=f"{fmt_func}() with non-literal format (decompile-cache scan)",
                            address=func_addr,
                        ),
                    ],
                    confidence_score=0.60,
                    facts={
                        "format_func": fmt_func,
                        "format_arg_is_variable": True,
                    },
                ))

    # Fallback for stripped/unnamed binaries: only if symbol-based mining
    # produced nothing. Keep this strict to avoid generic wrapper false positives.
    if not candidates:
        fallback_cache: Dict[str, str] = {}
        if mai and mai.decompiled_cache:
            fallback_cache.update(mai.decompiled_cache)
        if mcp_manager is not None and len(fallback_cache) < 20:
            extra = await _load_extra_decompiled_functions(
                mcp_manager, ghidra_binary_name, limit=120,
            )
            for fn, code in extra.items():
                fallback_cache.setdefault(fn, code)

        # Scan MCP-loaded functions for printf-family calls (same logic as
        # decompile-cache scan above, but on freshly decompiled functions).
        for func_name, code in fallback_cache.items():
            lines = code.strip().split('\n')
            if len(lines) > 120:
                continue
            for fmt_func in _FORMAT_FUNCTIONS:
                if fmt_func + "(" not in code and fmt_func + " (" not in code:
                    continue
                dedup_key = (func_name, fmt_func)
                if dedup_key in seen:
                    continue
                if _has_const_format(code, fmt_func):
                    continue
                seen.add(dedup_key)
                func_addr = _parse_func_addr(func_name)
                candidates.append(SinkCandidate(
                    address=func_addr,
                    function_name=func_name,
                    preliminary_label=SinkLabel.FORMAT_STRING_SINK,
                    evidence=[
                        EvidenceItem(
                            evidence_id="E1", kind="SITE",
                            text=f"{fmt_func}() with non-literal format (MCP fallback scan)",
                            address=func_addr,
                        ),
                    ],
                    confidence_score=0.55,
                    facts={
                        "format_func": fmt_func,
                        "format_arg_is_variable": True,
                        "fallback_mcp_scan": True,
                    },
                ))

        # Also try wrapper-pattern mining
        fallback = _mine_from_decompile_patterns(fallback_cache)
        for c in fallback:
            key = (c.function_name, c.preliminary_label.value)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(c)

    logger.info("Mined %d FORMAT_STRING_SINK candidates", len(candidates))
    return candidates


def _mine_from_decompile_patterns(
    decompiled_cache: Dict[str, str],
) -> List[SinkCandidate]:
    """Fallback miner for stripped binaries without printf symbols.

    Looks for stack-buffer formatting style calls where format arg is
    parameter-derived: FUN_xxx(local_buf, param_N, ...).
    """
    candidates: List[SinkCandidate] = []
    seen: set = set()
    # Strict wrapper pattern:
    #   CALL(dst, param_N);
    # where dst is stack/global-like buffer and function has no loop.
    # This is tuned to catch log_message-style wrappers and avoid memcpy wrappers.
    pattern = re.compile(
        r'\b(?:FUN_[0-9a-fA-F]+|[A-Za-z_]\w+)\s*\(\s*'
        r'(?P<dst>(?:&?local_\w+|auStack_\w+|DAT_[0-9a-fA-F]+|[A-Za-z_]\w+))'
        r'\s*,\s*'
        r'(?P<fmt>(?:\([^)]*\)\s*)?param_\d+)'
        r'\s*\)\s*;',
    )

    for func_name, code in decompiled_cache.items():
        lines = code.splitlines()
        if len(lines) > 90:
            continue
        if any(kw in code for kw in ("for (", "while (", "do {")):
            continue
        m = pattern.search(code)
        if not m:
            continue
        dst = m.group("dst")
        if dst.startswith("param_"):
            continue
        if func_name in seen:
            continue
        seen.add(func_name)
        func_addr = _parse_func_addr(func_name)
        candidates.append(SinkCandidate(
            address=func_addr,
            function_name=func_name,
            preliminary_label=SinkLabel.FORMAT_STRING_SINK,
            evidence=[
                EvidenceItem(
                    evidence_id="E1", kind="SITE",
                    text="stack-buffer formatting call with param-derived format argument",
                    address=func_addr,
                ),
            ],
            confidence_score=0.55,
            facts={
                "fallback_pattern": "stack_buf_param_format_call",
                "format_arg_is_variable": True,
                "format_arg_expr": m.group("fmt"),
                "dst_expr": dst,
            },
        ))
    return candidates


def _has_const_format(code: str, func_name: str) -> bool:
    """Check if all calls to func_name in code use a constant format string."""
    fmt_arg_idx = _FORMAT_FUNCTIONS.get(func_name, 0)

    # Find all calls to the function
    call_pattern = re.compile(re.escape(func_name) + r'\s*\(')
    for m in call_pattern.finditer(code):
        # Extract the argument list starting after the opening paren
        start = m.end()
        # Walk forward to find matching args, counting commas
        depth = 1
        pos = start
        arg_start = start
        current_arg = 0
        found_format = False

        while pos < len(code) and depth > 0:
            ch = code[pos]
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    # Check the last arg if it's the format arg
                    if current_arg == fmt_arg_idx:
                        arg_text = code[arg_start:pos].strip()
                        if not arg_text.startswith('"'):
                            return False  # variable format
                        found_format = True
                    break
            elif ch == ',' and depth == 1:
                if current_arg == fmt_arg_idx:
                    arg_text = code[arg_start:pos].strip()
                    if not arg_text.startswith('"'):
                        return False  # variable format
                    found_format = True
                    break
                current_arg += 1
                arg_start = pos + 1
            elif ch == '"':
                # Skip string literal
                pos += 1
                while pos < len(code) and code[pos] != '"':
                    if code[pos] == '\\':
                        pos += 1
                    pos += 1
            pos += 1

        if not found_format and current_arg < fmt_arg_idx:
            # Couldn't parse enough args — treat as variable format
            return False

    return True  # All calls have constant formats (or no calls found)


async def _find_format_symbols(
    mcp_manager: object, binary_name: str,
) -> List[Dict[str, Any]]:
    """Find printf-family function symbols."""
    from .copy_sink import _pick_best_symbol

    found: List[Dict[str, Any]] = []
    for func_name in _FORMAT_FUNCTIONS:
        resp = await _call_mcp_json(mcp_manager, "search_symbols_by_name", {
            "binary_name": binary_name,
            "query": func_name,
            "limit": 20,
        })
        if not resp:
            continue
        symbols = resp.get("symbols", [])
        best = _pick_best_symbol(symbols, func_name)
        if best:
            found.append(best)

    if found:
        return found

    # Heuristic fallback: identify sprintf-like functions from decompiled patterns
    # (printf family is harder to classify heuristically — skip for now)
    return []


async def _find_xrefs(
    mcp_manager: object, binary_name: str, callee_address: str,
) -> List[Dict[str, Any]]:
    """Find cross-references to a function."""
    resp = await _call_mcp_json(mcp_manager, "list_cross_references", {
        "binary_name": binary_name,
        "name_or_address": callee_address,
    })
    if not resp:
        return []
    return [
        x for x in resp.get("references", [])
        if "CALL" in x.get("type", "").upper()
    ]


def _parse_func_addr(func_name: str) -> int:
    """Extract address from FUN_XXXXXXXX name."""
    m = re.match(r'FUN_([0-9a-fA-F]+)', func_name)
    if m:
        return int(m.group(1), 16)
    return 0


async def _call_mcp_json(
    mcp_manager: object, tool_name: str, args: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Call a Ghidra MCP tool and parse JSON response."""
    try:
        result = await mcp_manager.call_tool("ghidra", tool_name, args)
    except Exception as e:
        logger.warning("MCP call %s failed: %s", tool_name, e)
        return None
    if not result:
        return None
    try:
        if isinstance(result, dict):
            return result
        text = getattr(result, "text", None) or str(result)
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


async def _load_extra_decompiled_functions(
    mcp_manager: object,
    binary_name: str,
    limit: int = 120,
) -> Dict[str, str]:
    """Decompile additional FUN_* functions for stripped fallback mining."""
    resp = await _call_mcp_json(mcp_manager, "search_symbols_by_name", {
        "binary_name": binary_name,
        "query": "FUN_",
        "limit": min(max(limit, 20), 240),
    })
    if not resp:
        return {}

    out: Dict[str, str] = {}
    symbols = resp.get("symbols", [])
    for sym in symbols[:limit]:
        func_name = str(sym.get("name", ""))
        if not func_name.startswith("FUN_"):
            continue
        dresp = await _call_mcp_json(mcp_manager, "decompile_function", {
            "binary_name": binary_name,
            "name_or_address": func_name,
        })
        if not dresp:
            continue
        code = dresp.get("decompiled_code", "") or dresp.get("code", "")
        if code:
            out[func_name] = code
    return out
