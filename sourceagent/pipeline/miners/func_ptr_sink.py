"""Stage 4 — FUNC_PTR_SINK miner.

Detects indirect function calls through attacker-controllable pointers or
table indices in decompiled code.

Strategy:
  1. Scan decompiled_cache for indirect call patterns:
     - (*(code **)(table + index * N))()  — array-indexed dispatch
     - (*param_N)()  — call through function pointer parameter
  2. Check if the pointer/index derives from external input (param, MMIO)
  3. Emit FUNC_PTR_SINK candidates
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
from .lib_filter import estimate_fanout, is_library_function

logger = logging.getLogger("sourceagent.pipeline.miners.func_ptr_sink")

# Pattern: array-indexed function pointer dispatch via cast
# Matches: (*(code **)(&table + (uint)param_1 * 4))();
#          (*(code *)(PTR + uVar1 * 4))();
_RE_INDEXED_DISPATCH = re.compile(
    r'\(\*\s*\(\s*code\s*\*+\s*\)'
    r'\s*\([^)]*'
    r'(?:param_\d+|[a-z]Var\d+|local_\w+)'  # variable index
    r'[^)]*\)\s*\)\s*\(',
)

# Pattern: simple array indexing into function table
# Matches: (*(code **)((int)&handlers + cmd * 4))()
#          handlers[idx]()  — less common in Ghidra output
_RE_TABLE_DISPATCH = re.compile(
    r'\(\*\s*\(\s*code\s*\*+\s*\)'
    r'\s*\('
    r'[^)]*'
    r'(?:\*\s*(?:4|8|0x[48]))'  # pointer-size multiplication
    r'[^)]*\)\s*\)\s*\(',
)

# Pattern: call through function pointer parameter
# Matches: (*param_1)(args)
_RE_PARAM_FPTR_CALL = re.compile(
    r'\(\*\s*param_(\d+)\s*\)\s*\(',
)

# Pattern: call through local function pointer variable
# Matches: (*pfunc)(args)  where pfunc = some_table[idx]
_RE_LOCAL_FPTR_CALL = re.compile(
    r'\(\*\s*([A-Za-z_]\w*)\s*\)\s*\(',
)

# Pattern: generic casted indirect call using computed expression
# Matches forms like: (*(undefined4 (*)())(param_1 + (uVar2 << 2)))();
_RE_GENERIC_CAST_INDIRECT = re.compile(
    r'\(\*\s*\(\s*[^)]*\)\s*\([^;]*'
    r'(?:param_\d+|[a-z]Var\d+|uVar\d+|iVar\d+|local_\w+)'
    r'[^;]*\)\s*\)\s*\(',
)

# Pattern: table[index](...) direct syntax
_RE_DIRECT_TABLE_CALL = re.compile(
    r'\b[A-Za-z_]\w*\s*\[\s*'
    r'(?:param_\d+|[a-z]Var\d+|uVar\d+|iVar\d+|[A-Za-z_]\w+)'
    r'\s*\]\s*\(',
)

# Pattern: (*table[idx])(...)
_RE_DEREF_TABLE_CALL = re.compile(
    r'\(\*\s*[A-Za-z_]\w*\s*\[\s*[^]]+'
    r'(?:param_\d+|[a-z]Var\d+|uVar\d+|iVar\d+|[A-Za-z_]\w+)'
    r'[^]]*\]\s*\)\s*\(',
)

# Pattern: local function pointer assigned from table[index] then called.
_RE_TABLE_ASSIGN = re.compile(
    r'\b([A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*\s*\[\s*[^]]*'
    r'(?:param_\d+|[a-z]Var\d+|uVar\d+|iVar\d+|local_\w+|[A-Za-z_]\w+)'
    r'[^]]*\]\s*;'
)

# Pattern: local fp assigned from casted pointer arithmetic over table/index.
_RE_TABLE_ASSIGN_CAST = re.compile(
    r'\b([A-Za-z_]\w*)\s*=\s*\*\s*\([^)]*\)\s*\([^;]*'
    r'(?:param_\d+|[a-z]Var\d+|uVar\d+|iVar\d+|local_\w+|[A-Za-z_]\w+)'
    r'[^;]*\)\s*;'
)


async def mine_func_ptr_sinks(
    memory_map: MemoryMap,
    mcp_manager: object,
    ghidra_binary_name: str,
    mai: Optional[MemoryAccessIndex] = None,
) -> List[SinkCandidate]:
    """Mine FUNC_PTR_SINK candidates from decompiled code cache."""
    candidates: List[SinkCandidate] = []
    code_map: Dict[str, str] = {}
    if mai and mai.decompiled_cache:
        code_map.update(mai.decompiled_cache)

    def _scan_func(func_name: str, code: str) -> Optional[SinkCandidate]:
        if is_library_function(func_name):
            return None
        if estimate_fanout(func_name, mai) >= 5:
            return None
        lines = code.strip().split('\n')
        if len(lines) > 180:
            return None  # skip very large functions

        match_info = _detect_indirect_call(code)
        if not match_info:
            return None

        func_addr = _parse_func_addr(func_name)
        pattern_type, matched_text = match_info

        facts: Dict[str, Any] = {
            "indirect_call_pattern": pattern_type,
            "matched_text": matched_text[:120],
        }
        if "param_" in matched_text:
            facts["input_derived"] = True

        confidence = 0.55
        if pattern_type == "indexed_dispatch":
            confidence = 0.65  # higher: explicit table + variable index
        elif pattern_type == "param_fptr":
            confidence = 0.50  # lower: might be legitimate callback

        return SinkCandidate(
            address=func_addr,
            function_name=func_name,
            preliminary_label=SinkLabel.FUNC_PTR_SINK,
            evidence=[
                EvidenceItem(
                    evidence_id="E1", kind="SITE",
                    text=f"indirect call ({pattern_type}): {matched_text[:80]}",
                    address=func_addr,
                ),
            ],
            confidence_score=confidence,
            facts=facts,
        )

    for func_name, code in code_map.items():
        c = _scan_func(func_name, code)
        if c is not None:
            candidates.append(c)

    # If stage-2 cache did not include the relevant function, sample additional
    # auto-named functions directly from MCP.
    if not candidates and mcp_manager is not None:
        extra = await _load_extra_decompiled_functions(
            mcp_manager, ghidra_binary_name, limit=120,
        )
        for func_name, code in extra.items():
            if func_name in code_map:
                continue
            c = _scan_func(func_name, code)
            if c is not None:
                candidates.append(c)

    logger.info("Mined %d FUNC_PTR_SINK candidates", len(candidates))
    return candidates


def _detect_indirect_call(code: str) -> Optional[tuple]:
    """Detect indirect function call patterns in decompiled code.

    Returns (pattern_type, matched_text) or None.
    """
    # Priority 1: indexed dispatch (most dangerous — table + variable index)
    m = _RE_INDEXED_DISPATCH.search(code)
    if m:
        return ("indexed_dispatch", m.group(0))

    m = _RE_TABLE_DISPATCH.search(code)
    if m:
        return ("table_dispatch", m.group(0))

    # Priority 2: call through function pointer parameter
    m = _RE_PARAM_FPTR_CALL.search(code)
    if m:
        return ("param_fptr", m.group(0))

    # Priority 3: call through local function pointer variable
    m = _RE_LOCAL_FPTR_CALL.search(code)
    if m:
        var_name = m.group(1)
        # Skip self-references (function name appearing as call is normal code)
        if var_name.startswith("FUN_") or var_name in ("code", "void", "int", "uint"):
            pass
        else:
            # Check if the variable is assigned from a table/array/param/cast
            assign_pat = re.compile(
                re.escape(var_name) + r'\s*=\s*[^;]*'
                r'(?:\[[^]]+\]|param_\d+|\*\s*\(|'
                r'\+\s*\(?\s*(?:uVar|iVar|param_|local_|uint))'
            )
            if assign_pat.search(code):
                return ("local_fptr", m.group(0))

    m = _RE_GENERIC_CAST_INDIRECT.search(code)
    if m:
        return ("cast_indirect", m.group(0))

    m = _RE_DIRECT_TABLE_CALL.search(code)
    if m:
        return ("direct_table_call", m.group(0))

    m = _RE_DEREF_TABLE_CALL.search(code)
    if m:
        return ("deref_table_call", m.group(0))

    m = _RE_TABLE_ASSIGN.search(code)
    if m:
        local_fp = m.group(1)
        direct_call = re.search(
            r'(?m)^\s*(?:\(\*\s*' + re.escape(local_fp) + r'\s*\)|'
            + re.escape(local_fp) + r')\s*\(',
            code,
        )
        if direct_call:
            return ("table_assign_call", m.group(0))

    m = _RE_TABLE_ASSIGN_CAST.search(code)
    if m:
        local_fp = m.group(1)
        direct_call = re.search(
            r'(?m)^\s*(?:\(\*\s*' + re.escape(local_fp) + r'\s*\)|'
            + re.escape(local_fp) + r')\s*\(',
            code,
        )
        if direct_call:
            return ("table_assign_cast_call", m.group(0))

    return None


def _parse_func_addr(func_name: str) -> int:
    """Extract address from FUN_XXXXXXXX name."""
    m = re.match(r'FUN_([0-9a-fA-F]+)', func_name)
    if m:
        return int(m.group(1), 16)
    return 0


async def _load_extra_decompiled_functions(
    mcp_manager: object,
    binary_name: str,
    limit: int = 120,
) -> Dict[str, str]:
    """Fallback: decompile additional functions directly via MCP.

    Searches both FUN_* (auto-named) and named functions to cover
    non-stripped binaries where dispatch functions have real names.
    """
    out: Dict[str, str] = {}

    # Search auto-named functions
    for query in ("FUN_", "dispatch", "handler", "cmd", "process", "callback"):
        resp = await _call_mcp_json(mcp_manager, "search_symbols_by_name", {
            "binary_name": binary_name,
            "query": query,
            "limit": min(max(limit, 20), 240),
        })
        if not resp:
            continue
        symbols = resp.get("symbols", [])
        for sym in symbols[:limit]:
            func_name = str(sym.get("name", ""))
            if not func_name or func_name in out:
                continue
            # Skip thunks and PLT stubs
            if func_name.startswith("_") and not func_name.startswith("__"):
                pass  # allow single-underscore names
            dresp = await _call_mcp_json(mcp_manager, "decompile_function", {
                "binary_name": binary_name,
                "name_or_address": func_name,
            })
            if not dresp:
                continue
            code = dresp.get("decompiled_code", "") or dresp.get("code", "")
            if code:
                out[func_name] = code
            if len(out) >= limit:
                break
        if len(out) >= limit:
            break

    return out


async def _call_mcp_json(
    mcp_manager: object,
    tool_name: str,
    args: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Call an MCP tool and decode JSON-ish responses."""
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
        if isinstance(result, list):
            for block in result:
                if isinstance(block, dict) and block.get("type") == "text":
                    return json.loads(block.get("text", "{}"))
        text = getattr(result, "text", None) or str(result)
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
