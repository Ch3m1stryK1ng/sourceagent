"""Heuristic function classification for stripped binaries.

When symbol names are unavailable (stripped ELF), this module identifies
common library functions (memcpy, memset, strcpy) by decompiling Ghidra's
auto-named FUN_ functions and matching structural patterns in the pseudo-C.

Used as a fallback by copy_sink.py and additional_sinks.py when symbol-based
strategies return empty.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("sourceagent.pipeline.miners.func_classifier")

# ── Decompiled-code pattern classifiers ──────────────────────────────────

_RE_BYTE_COPY_LOOP = re.compile(
    r"\*[^=;]*=\s*\*[^;]*;",  # *<anything> = *<anything>; (byte copy)
)
_RE_FILL_LOOP = re.compile(
    r"\*[^=;]*=\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*;",  # *dst = fill_val
)
_RE_NULL_CHECK = re.compile(
    r"!=\s*(?:0\b|'\\0')|==\s*(?:0\b|'\\0')",  # null terminator check
)
_RE_TEMP_FROM_PARAM2 = re.compile(
    r"(?:bVar\d+|uVar\d+)\s*=\s*(?:\([^)]*\)\s*)?param_2\b",
)


def classify_function(code: str) -> Optional[str]:
    """Classify decompiled code as memcpy/memset/strcpy or None.

    Returns the canonical function name if the code matches a known pattern,
    or None if it does not match any pattern.
    """
    lines = code.strip().split('\n')
    if len(lines) > 80:
        return None

    has_loop = 'while' in code or 'for' in code or 'do {' in code
    if not has_loop:
        return None

    has_copy = bool(_RE_BYTE_COPY_LOOP.search(code))
    fill_rhs = _RE_FILL_LOOP.findall(code)
    has_fill_raw = bool(fill_rhs)
    # Avoid classifying generic loop writes (e.g., reading bytes from MMIO/helper)
    # as memset unless the fill value is directly param_2 or clearly copied from it.
    sig_text = code.split("{", 1)[0]
    has_fill = False
    if has_fill_raw:
        for rhs in fill_rhs:
            if rhs == "param_2":
                has_fill = True
                break
            if rhs.startswith(("bVar", "uVar")):
                if _RE_TEMP_FROM_PARAM2.search(code):
                    has_fill = True
                    break
                # Common stripped pattern: fill byte is a renamed parameter.
                if re.search(rf'\b{re.escape(rhs)}\b', sig_text):
                    has_fill = True
                    break
    has_null = bool(_RE_NULL_CHECK.search(code))

    # Count parameters (param_1, param_2, param_3)
    params = set(re.findall(r'param_(\d+)', code))
    param_count = len(params)

    # Prefer strcpy when a null terminator check exists, even if Ghidra inferred
    # an extra synthetic parameter.
    if has_copy and has_null and param_count >= 2:
        return "strcpy"
    # Stripped/newlib variants sometimes omit obvious null-check syntax.
    if has_copy and not has_fill and param_count == 2:
        return "strcpy"
    if has_copy and param_count >= 3:
        return "memcpy"
    if has_fill and param_count >= 2:
        return "memset"
    return None


# ── MCP-based heuristic identification ───────────────────────────────────


async def identify_library_functions(
    mcp_manager: object,
    binary_name: str,
    target_types: Set[str],
    max_candidates: int = 50,
) -> List[Dict[str, Any]]:
    """Identify library functions by decompiled code patterns.

    Enumerates all FUN_ functions via MCP, decompiles small ones, and
    classifies by structural patterns.

    Args:
        mcp_manager: MCP manager for Ghidra.
        binary_name: Ghidra project binary name.
        target_types: Set of function types to look for,
            e.g. {"memcpy", "strcpy"} or {"memset"}.
        max_candidates: Maximum number of functions to decompile.

    Returns list of dicts with "name" (canonical) and "address" keys.
    """
    # Get all auto-named functions
    resp = await _call_mcp_json(mcp_manager, "search_symbols_by_name", {
        "binary_name": binary_name,
        "query": "FUN_",
        "limit": 200,
    })

    if resp is None:
        return []

    symbols = resp.get("symbols", [])
    if not symbols:
        return []

    # Filter to non-external function symbols
    candidates = []
    for sym in symbols:
        name = sym.get("name", "")
        if not name.startswith("FUN_"):
            continue
        addr_str = sym.get("address", "")
        if addr_str.startswith("EXTERNAL"):
            continue
        try:
            addr_int = int(addr_str, 16)
        except (ValueError, TypeError):
            continue
        # Skip functions at very high addresses (likely thunks/external)
        if addr_int > 0x20000000:
            continue
        candidates.append((name, addr_str, addr_int))

    if not candidates:
        return []

    # Limit to avoid excessive MCP calls
    candidates = candidates[:max_candidates]

    logger.info(
        "Heuristic classification: examining %d FUN_ functions for %s",
        len(candidates), target_types,
    )

    found: List[Dict[str, Any]] = []
    found_types: set = set()

    for func_name, addr_str, addr_int in candidates:
        resp = await _call_mcp_json(mcp_manager, "decompile_function", {
            "binary_name": binary_name,
            "name_or_address": func_name,
        })

        if resp is None:
            continue

        code = resp.get("decompiled_code", "") or resp.get("code", "")
        if not code:
            continue

        classification = classify_function(code)
        if classification and classification in target_types:
            logger.info(
                "Heuristic: %s classified as %s", func_name, classification,
            )
            found.append({
                "name": classification,
                "address": addr_str,
            })
            found_types.add(classification)

            # Stop early if we found all target types
            if found_types == target_types:
                break

    return found


# ── MCP helper ───────────────────────────────────────────────────────────


async def _call_mcp_json(
    mcp_manager: object,
    tool_name: str,
    args: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Call a Ghidra MCP tool and parse the JSON response."""
    try:
        result = await mcp_manager.call_tool("ghidra", tool_name, args)
    except Exception as e:
        logger.warning("MCP call %s failed: %s", tool_name, e)
        return None

    if not result:
        return None

    try:
        if isinstance(result, list):
            for block in result:
                if isinstance(block, dict) and block.get("type") == "text":
                    return json.loads(block["text"])
        elif isinstance(result, dict):
            return result
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.warning("Failed to parse MCP response for %s: %s", tool_name, e)

    return None
