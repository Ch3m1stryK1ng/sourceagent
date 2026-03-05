"""Stage 4 — COPY_SINK miner (VS1).

Staged approach:
  S1: If symbols/imports exist, directly match memcpy/memmove/strcpy/strncpy/
      sprintf patterns by name via Ghidra symbol search.
  S2: For each found symbol, resolve PLT address and find callsites via xrefs.
  S3: Decompile each caller to extract dst/src/len argument context.

For each qualifying callsite, extracts:
  - dst/src/len arguments via decompiled C parsing
  - Whether len is a compile-time constant or runtime-derived
  - dst pointer provenance (stack/global/arg)
  - Whether a bounds guard exists before the call

Ranking: variable length, arg-provenance destination, and missing bounds guard
increase priority (higher risk = higher confidence).
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from ..models import (
    EvidenceItem,
    MemoryAccessIndex,
    MemoryMap,
    SinkCandidate,
    SinkLabel,
)
from .lib_filter import estimate_fanout, is_library_function

logger = logging.getLogger("sourceagent.pipeline.miners.copy_sink")

# ── Canonical copy function names ────────────────────────────────────────────

COPY_FUNCTION_NAMES = [
    "memcpy", "memmove", "__aeabi_memcpy", "__aeabi_memcpy4", "__aeabi_memcpy8",
    "bcopy", "strcpy", "strncpy", "strlcpy",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "strcat", "strncat",
]

# Functions where the length argument is the Nth arg (0-indexed)
_LEN_ARG_INDEX: Dict[str, Optional[int]] = {
    "memcpy": 2,
    "memmove": 2,
    "__aeabi_memcpy": 2,
    "__aeabi_memcpy4": 2,
    "__aeabi_memcpy8": 2,
    "bcopy": 2,
    "strncpy": 2,
    "strlcpy": 2,
    "snprintf": 1,  # snprintf(dst, size, fmt, ...)
    "vsnprintf": 1,
    "strncat": 2,
    # These have no explicit length arg:
    "strcpy": None,
    "sprintf": None,
    "vsprintf": None,
    "strcat": None,
}


# ── Public API ───────────────────────────────────────────────────────────────


async def mine_copy_sinks(
    memory_map: MemoryMap,
    mcp_manager: object,
    ghidra_binary_name: str,
    mai: Optional[MemoryAccessIndex] = None,
) -> List[SinkCandidate]:
    """Mine COPY_SINK candidates via Ghidra MCP.

    For each canonical copy function name found in the binary's symbols,
    resolves callsites and decompiles callers to extract argument context.

    Returns list of SinkCandidate with preliminary_label=COPY_SINK.
    """
    if mcp_manager is None:
        logger.warning("No MCP manager — cannot mine copy sinks")
        return []

    # Step 1: Find copy function symbols
    copy_symbols = await _find_copy_symbols(mcp_manager, ghidra_binary_name)
    if not copy_symbols:
        logger.info("No copy function symbols found in %s", ghidra_binary_name)
        return []

    logger.info(
        "Found %d copy function symbols: %s",
        len(copy_symbols),
        [s["name"] for s in copy_symbols],
    )

    # Step 2: For each copy function, find callsites via xrefs
    candidates: List[SinkCandidate] = []
    seen_callsites: set = set()  # (caller_func, callee_name, callsite) dedup

    for sym in copy_symbols:
        callee_name = sym["name"]
        callee_addr = sym["address"]
        callee_aliases = _build_callee_aliases(callee_name, sym, callee_addr)

        xrefs = await _find_callsite_xrefs(
            mcp_manager, ghidra_binary_name, callee_addr,
        )

        # Fallback: if MCP xrefs are empty, scan decompiled code cache
        if not xrefs and mai and mai.decompiled_cache:
            xrefs = _find_callers_from_decompile_cache(
                mai.decompiled_cache, callee_name, callee_addr,
                callee_aliases=callee_aliases,
            )

        for xref in xrefs:
            caller_func = xref.get("function_name") or ""
            from_addr_str = xref.get("from_address", "")
            ref_type = xref.get("type", "")

            # Only interested in calls, not data references
            if ref_type and "CALL" not in ref_type:
                continue

            if not caller_func:
                continue

            # Parse callsite address
            try:
                callsite_addr = int(from_addr_str, 16)
            except (ValueError, TypeError):
                callsite_addr = 0

            # Dedup: keep multiple callsites in the same function.
            dedup_key = (caller_func, callee_name, callsite_addr)
            if dedup_key in seen_callsites:
                continue
            seen_callsites.add(dedup_key)

            # Gate obvious runtime/library internals and broad utility wrappers.
            if is_library_function(caller_func):
                continue
            if mai is not None and estimate_fanout(caller_func, mai) >= 6:
                continue

            # Step 3: Decompile the caller to extract argument context
            call_context = await _extract_call_context(
                mcp_manager, ghidra_binary_name,
                caller_func, callee_name, callee_aliases=callee_aliases,
            )

            # Build candidate (argless candidates now accepted — verifier
            # passes O_COPY_2 when callsite is confirmed via callee fact)
            candidate = _build_candidate(
                callee_name=callee_name,
                caller_func=caller_func,
                callsite_addr=callsite_addr,
                call_context=call_context,
            )
            if candidate is None:
                continue
            candidates.append(candidate)

    # Sort by confidence descending
    candidates.sort(key=lambda c: -c.confidence_score)

    logger.info("Mined %d COPY_SINK candidates", len(candidates))
    return candidates


# ── Symbol search ────────────────────────────────────────────────────────────


async def _find_copy_symbols(
    mcp_manager: object,
    binary_name: str,
) -> List[Dict[str, Any]]:
    """Search for canonical copy function symbols in the binary.

    Multi-strategy approach:
      1. Exact name match for each canonical copy function name
      2. Broader substring search for common fragments (cpy, mov, cat, printf)
      3. ARM compiler intrinsic names (__aeabi_memcpy, __rt_memcpy, etc.)

    For each matched symbol, picks the best candidate (lowest non-EXTERNAL
    address = PLT thunk for imported functions).
    """
    found_by_name: Dict[str, Dict[str, Any]] = {}

    def _addr_int(sym: Dict[str, Any]) -> int:
        try:
            return int(str(sym.get("address", "")), 16)
        except (TypeError, ValueError):
            return 1 << 62

    def _merge_symbol(sym: Optional[Dict[str, Any]]) -> None:
        """Merge a symbol by canonical name, preferring lower addresses."""
        if not sym:
            return
        name = str(sym.get("name", "")).strip()
        if not name:
            return
        old = found_by_name.get(name)
        if old is None or _addr_int(sym) < _addr_int(old):
            found_by_name[name] = sym

    # Strategy 1: Exact name match (original behavior)
    for func_name in COPY_FUNCTION_NAMES:
        resp = await _call_mcp_json(mcp_manager, "search_symbols_by_name", {
            "binary_name": binary_name,
            "query": func_name,
            "limit": 20,
        })

        if resp is None:
            continue

        symbols = resp.get("symbols", [])
        if not symbols:
            continue

        best = _pick_best_symbol(symbols, func_name)
        _merge_symbol(best)

    # Strategy 2: Broader substring search for common fragments
    # These queries are broader — search for substrings that appear in
    # common copy/string function names, catching variations like
    # _memcpy, __memcpy_r4, etc.
    _SUBSTRING_QUERIES = ["cpy", "mov", "cat", "printf", "memset"]

    for query in _SUBSTRING_QUERIES:
        resp = await _call_mcp_json(mcp_manager, "search_symbols_by_name", {
            "binary_name": binary_name,
            "query": query,
            "limit": 50,
        })

        if resp is None:
            continue

        symbols = resp.get("symbols", [])
        for sym in symbols:
            name = sym.get("name", "")
            # Check if this matches any canonical copy function
            for canonical in COPY_FUNCTION_NAMES:
                if canonical in found_by_name:
                    continue
                if canonical in name or name == canonical:
                    best = _pick_best_symbol([sym], canonical)
                    _merge_symbol(best)

    # Strategy 3: ARM compiler intrinsic names
    _ARM_INTRINSICS = [
        "__aeabi_memcpy", "__aeabi_memcpy4", "__aeabi_memcpy8",
        "__aeabi_memmove", "__aeabi_memmove4", "__aeabi_memmove8",
        "__aeabi_memset", "__aeabi_memset4", "__aeabi_memset8",
        "__rt_memcpy", "__rt_memmove", "__rt_memset",
        "__memcpy_r4", "__memcpy_r7",
    ]

    for intrinsic in _ARM_INTRINSICS:
        resp = await _call_mcp_json(mcp_manager, "search_symbols_by_name", {
            "binary_name": binary_name,
            "query": intrinsic,
            "limit": 10,
        })

        if resp is None:
            continue

        symbols = resp.get("symbols", [])
        if not symbols:
            continue

        # Map ARM intrinsics to their canonical names for length arg lookup
        canonical = intrinsic
        for canon_name in COPY_FUNCTION_NAMES:
            if canon_name in intrinsic:
                canonical = canon_name
                break

        best = _pick_best_symbol(symbols, intrinsic)
        if best:
            # Use the canonical name for the "name" field so _LEN_ARG_INDEX works
            best["name"] = canonical
            _merge_symbol(best)

    # Strategy 4: Heuristic function classification (stripped binaries)
    from .func_classifier import identify_library_functions
    # Only ask heuristic classifier for still-missing high-value copy types.
    missing_types = {"memcpy", "strcpy"} - set(found_by_name.keys())
    if not missing_types:
        return list(found_by_name.values())
    found_heuristic = await identify_library_functions(
        mcp_manager, binary_name,
        target_types=missing_types,
    )
    if found_heuristic:
        for sym in found_heuristic:
            sym["heuristic"] = True
            _merge_symbol(sym)
        logger.info(
            "Strategy 4 (heuristic): found %d copy functions", len(found_heuristic),
        )
    return list(found_by_name.values())


def _pick_best_symbol(
    symbols: List[Dict[str, Any]],
    target_name: str,
) -> Optional[Dict[str, Any]]:
    """Pick the best symbol match for a copy function name.

    Prefers exact name match. Among matches, picks lowest non-EXTERNAL
    address (PLT thunk) which is what user code actually calls.
    """
    candidates = []
    for sym in symbols:
        name = sym.get("name", "")
        addr = sym.get("address", "")

        # Exact match or close match (e.g., "memcpy" in "_memcpy")
        if name != target_name and target_name not in name:
            continue

        # Skip EXTERNAL entries
        if str(addr).startswith("EXTERNAL"):
            continue

        # Skip source-file label symbols (e.g., "strcpy.c", "memcpy-stub.o")
        if name.endswith(('.c', '.o', '.s', '.S')):
            continue

        try:
            addr_int = int(addr, 16)
        except (ValueError, TypeError):
            continue

        # Skip 0-address stub symbols
        if addr_int == 0:
            continue

        exactness = 0 if name == target_name else 1
        candidates.append((exactness, addr_int, sym))

    if not candidates:
        return None

    # Prefer exact-name symbol first, then lower address (entry thunk).
    candidates.sort(key=lambda x: (x[0], x[1]))
    best_sym = candidates[0][2]

    return {
        "name": target_name,
        "address": best_sym.get("address", ""),
        "original_name": best_sym.get("name", ""),
    }


# ── Callsite discovery ───────────────────────────────────────────────────────


async def _find_callsite_xrefs(
    mcp_manager: object,
    binary_name: str,
    callee_address: str,
) -> List[Dict[str, Any]]:
    """Find cross-references (callsites) to a copy function."""
    resp = await _call_mcp_json(mcp_manager, "list_cross_references", {
        "binary_name": binary_name,
        "name_or_address": callee_address,
    })

    if resp is None:
        return []

    return resp.get("references", [])


def _find_callers_from_decompile_cache(
    decompiled_cache: Dict[str, str],
    callee_name: str,
    callee_addr: str,
    callee_aliases: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Fallback xref discovery by scanning decompiled code for call patterns.

    Used when MCP list_cross_references returns empty (common for
    heuristic-classified functions in stripped binaries).
    """
    names = _normalize_callee_names(callee_name, callee_aliases)

    xrefs: List[Dict[str, Any]] = []
    for func_name, code in decompiled_cache.items():
        lines = code.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            matched = _match_callee_name(line, names)
            if not matched:
                continue
            if _is_definition_line(lines, i, matched):
                continue

            args, _ = _extract_call_arguments(lines, i, matched)
            if not args:
                continue
            if _args_look_like_param_decls(args):
                continue

            # Extract function address from FUN_XXXXXXXX name
            func_addr = "0x0"
            m = re.match(r'FUN_([0-9a-fA-F]+)', func_name)
            if m:
                func_addr = f"0x{m.group(1)}"
            xrefs.append({
                "function_name": func_name,
                "from_address": func_addr,
                "type": "UNCONDITIONAL_CALL",
            })
            break  # one xref per calling function
    return xrefs


# ── Call context extraction ──────────────────────────────────────────────────


async def _extract_call_context(
    mcp_manager: object,
    binary_name: str,
    caller_func: str,
    callee_name: str,
    callee_aliases: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Decompile the caller and extract argument context around the callsite."""
    resp = await _call_mcp_json(mcp_manager, "decompile_function", {
        "binary_name": binary_name,
        "name_or_address": caller_func,
    })

    if resp is None:
        return {"decompile_failed": True}

    code = resp.get("decompiled_code", "") or resp.get("code", "")
    if not code:
        return {"decompile_failed": True}

    return parse_call_context(code, callee_name, callee_names=callee_aliases)


def parse_call_context(
    code: str,
    callee_name: str,
    callee_names: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Parse decompiled C to extract argument context for a copy function call.

    Pure function (no MCP). Looks for the callsite line, extracts argument
    expressions, checks for bounds guards, and classifies length/dst provenance.
    """
    context: Dict[str, Any] = {
        "callee": callee_name,
        "call_found": False,
        "args": [],
        "raw_call_line": "",
        "has_bounds_guard": False,
        "len_is_constant": False,
        "len_value": None,
        "dst_provenance": "UNKNOWN",
    }

    lines = code.splitlines()
    names = _normalize_callee_names(callee_name, callee_names)
    call_line_idx = None
    saw_unparsed_call = False

    # Find the callsite line
    for i, line in enumerate(lines):
        matched = _match_callee_name(line, names)
        if not matched:
            continue
        if _is_definition_line(lines, i, matched):
            continue

        args, raw_call = _extract_call_arguments(lines, i, matched)
        saw_unparsed_call = True
        if not args:
            continue
        if _args_look_like_param_decls(args):
            continue

        context["call_found"] = True
        context["raw_call_line"] = raw_call
        call_line_idx = i
        context["args"] = args

        if matched != callee_name:
            context["callee_alias_used"] = matched

        # Classify dst provenance
        context["dst_provenance"] = _classify_arg_provenance(args[0])

        # Check length argument
        len_idx = _LEN_ARG_INDEX.get(callee_name)
        if len_idx is not None and len_idx < len(args):
            len_arg = args[len_idx]
            is_const, value = _analyze_length_arg(len_arg)
            context["len_is_constant"] = is_const
            context["len_value"] = value
        elif len_idx is None:
            # No length arg (strcpy, sprintf, strcat) → unbounded
            context["len_is_constant"] = False

        break  # Take first parsed call occurrence

    if not context["call_found"] and saw_unparsed_call:
        context["call_found"] = True

    # Check for bounds guard before the call
    if call_line_idx is not None:
        context["has_bounds_guard"] = _has_bounds_guard(lines, call_line_idx)

    return context


def _build_callee_aliases(
    callee_name: str,
    symbol: Dict[str, Any],
    callee_addr: str,
) -> List[str]:
    """Build candidate names that may appear in decompiled callsites."""
    aliases = [callee_name]
    original = str(symbol.get("original_name", "")).strip()
    if original:
        aliases.append(original)
        if original.startswith("_") and len(original) > 1:
            aliases.append(original.lstrip("_"))
    try:
        aliases.append(f"FUN_{int(callee_addr, 16):08x}")
    except (ValueError, TypeError):
        pass
    return _normalize_callee_names(callee_name, aliases)


def _normalize_callee_names(
    primary: str,
    aliases: Optional[List[str]],
) -> List[str]:
    names: List[str] = [primary]
    for name in aliases or []:
        n = str(name or "").strip()
        if n and n not in names:
            names.append(n)
    return names


def _match_callee_name(line: str, callee_names: List[str]) -> Optional[str]:
    for name in callee_names:
        if _is_call_to(line, name):
            return name
    return None


def _is_definition_line(lines: List[str], line_idx: int, func_name: str) -> bool:
    """Best-effort filter to avoid treating function definitions as calls."""
    if line_idx < 0 or line_idx >= len(lines):
        return False
    line = lines[line_idx]
    idx = line.find(func_name)
    if idx < 0:
        return False

    prefix = line[:idx]
    suffix = line[idx + len(func_name):]

    stripped_prefix = prefix.strip()
    if not stripped_prefix:
        return False
    if not re.match(r"^\s*[A-Za-z_][\w\s\*]*$", prefix):
        return False
    if re.search(r"\b(return|if|while|for|switch|case)\b", stripped_prefix):
        return False
    if "=" in stripped_prefix:
        return False
    if "(" not in suffix:
        return False

    # A declaration/definition line usually starts with type-like tokens.
    first_tok = stripped_prefix.split()[0]
    type_like = {
        "void", "char", "short", "int", "long", "float", "double", "bool",
        "byte", "word", "dword", "qword", "undefined", "undefined1",
        "undefined2", "undefined4", "undefined8", "uint", "uint8_t",
        "uint16_t", "uint32_t", "uint64_t", "size_t", "ssize_t", "code",
        "const", "volatile", "signed", "unsigned", "struct", "union", "enum",
    }
    if first_tok not in type_like and not first_tok.startswith("undefined"):
        return False

    brace_idx = line.find("{")
    semicolon_idx = line.find(";")

    # Function definition: opening brace appears before first statement semicolon.
    if brace_idx != -1 and (semicolon_idx == -1 or brace_idx < semicolon_idx):
        return True
    # Function prototype declaration.
    if brace_idx == -1 and semicolon_idx != -1 and line.strip().endswith(");"):
        return True
    # Common Ghidra style: signature line, opening brace on the next line.
    if line.strip().endswith(")"):
        j = line_idx + 1
        while j < len(lines) and not lines[j].strip():
            j += 1
        if j < len(lines) and lines[j].strip().startswith("{"):
            return True
    return False


def _args_look_like_param_decls(args: List[str]) -> bool:
    """Heuristically detect function-signature args, not callsite args."""
    if not args:
        return False
    type_token = r"(?:const|volatile|signed|unsigned|struct\s+\w+|enum\s+\w+|union\s+\w+|[A-Za-z_]\w*)"
    decl_re = re.compile(
        rf"^\s*(?:{type_token}\s+)+\**\s*(?:param_\d+|[A-Za-z_]\w*)\s*$"
    )
    return all(bool(decl_re.match(a.strip())) for a in args)


def _extract_call_arguments(
    lines: List[str],
    start_idx: int,
    func_name: str,
    max_lines: int = 12,
) -> Tuple[List[str], str]:
    """Extract call args from possibly multi-line decompiler call expressions."""
    end = min(len(lines), start_idx + max_lines)
    block = "\n".join(lines[start_idx:end])
    pattern = re.escape(func_name) + r"\s*\("
    m = re.search(pattern, block)
    if not m:
        return [], ""

    start = m.end()
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
        return [], ""

    args_str = block[start:pos - 1]
    args = _split_args(args_str)
    raw_call = block[m.start():pos].replace("\n", " ").strip()
    return args, raw_call


def _is_call_to(line: str, func_name: str) -> bool:
    """Check if a line contains a call to the specified function."""
    pattern = r'(?<![.\w])' + re.escape(func_name) + r'\s*\('
    return bool(re.search(pattern, line))


def _extract_arguments(line: str, func_name: str) -> List[str]:
    """Extract argument expressions from a function call in decompiled C."""
    pattern = re.escape(func_name) + r'\s*\('
    m = re.search(pattern, line)
    if not m:
        return []

    start = m.end()
    depth = 1
    i = start
    while i < len(line) and depth > 0:
        if line[i] == '(':
            depth += 1
        elif line[i] == ')':
            depth -= 1
        i += 1

    if depth != 0:
        return []

    args_str = line[start:i - 1]
    return _split_args(args_str)


def _split_args(args_str: str) -> List[str]:
    """Split comma-separated arguments respecting nested parens."""
    args = []
    depth = 0
    current = []

    for ch in args_str:
        if ch in ('(', '['):
            depth += 1
            current.append(ch)
        elif ch in (')', ']'):
            depth -= 1
            current.append(ch)
        elif ch == ',' and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(ch)

    if current:
        arg = "".join(current).strip()
        if arg:
            args.append(arg)

    return args


def _classify_arg_provenance(arg_expr: str) -> str:
    """Classify the provenance of a destination argument."""
    arg = arg_expr.strip()

    if re.search(r'&?local_|auStack_|&Stack', arg):
        return "STACK_PTR"

    if re.search(r'DAT_|^0x[0-9a-fA-F]+$', arg):
        return "GLOBAL_PTR"

    if re.search(r'param_\d+', arg):
        return "ARG"

    # Unwrap type cast: (type *)expr
    inner = re.search(r'\(\s*\w+\s*\*?\s*\)\s*(.+)', arg)
    if inner:
        return _classify_arg_provenance(inner.group(1))

    return "UNKNOWN"


def _analyze_length_arg(len_arg: str) -> Tuple[bool, Optional[int]]:
    """Analyze whether a length argument is a compile-time constant."""
    arg = len_arg.strip()

    if re.fullmatch(r'\d+', arg):
        return True, int(arg)

    if re.fullmatch(r'0x[0-9a-fA-F]+', arg):
        return True, int(arg, 16)

    if 'sizeof' in arg:
        return True, None

    # Cast of constant
    cast_match = re.fullmatch(r'\(\s*\w+\s*\)\s*(0x[0-9a-fA-F]+|\d+)', arg)
    if cast_match:
        val_str = cast_match.group(1)
        try:
            val = int(val_str, 16) if val_str.startswith('0x') else int(val_str)
            return True, val
        except ValueError:
            pass

    return False, None


def _has_bounds_guard(lines: List[str], call_line_idx: int) -> bool:
    """Check for bounds-checking guard before the copy call."""
    start = max(0, call_line_idx - 10)
    preceding = "\n".join(lines[start:call_line_idx])

    if re.search(r'if\s*\([^)]*[>>=]\s*\d+', preceding):
        return True

    if re.search(r'if\s*\([^)]*>\s*[^)]+\)\s*(return|goto|break)', preceding):
        return True

    if re.search(r'\b(MIN|min|clamp|fmin)\b', preceding, re.IGNORECASE):
        return True

    if re.search(r'\?\s*\d+\s*:', preceding):
        return True

    return False


# ── Candidate construction ───────────────────────────────────────────────────


def _build_candidate(
    callee_name: str,
    caller_func: str,
    callsite_addr: int,
    call_context: Dict[str, Any],
) -> Optional[SinkCandidate]:
    """Build a SinkCandidate from extracted call context."""
    evidence = []
    facts: Dict[str, Any] = {
        "callee": callee_name,
        "caller": caller_func,
        "call_found": bool(call_context.get("call_found", False)),
    }

    # E1: callsite evidence
    call_line = call_context.get("raw_call_line", f"{callee_name}(...)")
    evidence.append(EvidenceItem(
        evidence_id="E1",
        kind="SITE",
        text=f"Call to {callee_name}: {call_line}",
        address=callsite_addr,
    ))

    # E2: argument analysis
    args = call_context.get("args", [])
    if args:
        facts["args"] = args
        facts["args_extracted"] = True
        facts["dst_provenance"] = call_context.get("dst_provenance", "UNKNOWN")
        evidence.append(EvidenceItem(
            evidence_id="E2",
            kind="DEF",
            text=f"dst={args[0]}, provenance={facts['dst_provenance']}",
        ))
    else:
        facts["args_extracted"] = False

    alias_used = call_context.get("callee_alias_used")
    if alias_used:
        facts["callee_alias_used"] = alias_used

    # E3: length / guard analysis
    len_is_const = call_context.get("len_is_constant", False)
    len_value = call_context.get("len_value")
    has_guard = call_context.get("has_bounds_guard", False)
    facts["len_is_constant"] = len_is_const
    facts["len_value"] = len_value
    facts["has_bounds_guard"] = has_guard

    if not len_is_const:
        evidence.append(EvidenceItem(
            evidence_id="E3",
            kind="GUARD",
            text=f"Length is runtime-derived; bounds guard={'present' if has_guard else 'MISSING'}",
        ))

    if call_context.get("decompile_failed"):
        facts["decompile_failed"] = True

    # Suppress likely bounded copy wrappers where guarded variable length is
    # propagated via a structure field (e.g., pkt->len), which tends to be
    # scored as a LENGTH_TRUST site instead of COPY in our GT semantics.
    len_arg_expr = ""
    len_idx = _LEN_ARG_INDEX.get(callee_name)
    if len_idx is not None and args and len_idx < len(args):
        len_arg_expr = str(args[len_idx])
    if (
        callee_name in ("memcpy", "memmove", "__aeabi_memcpy")
        and len_is_const is False
        and has_guard is True
        and "->" in len_arg_expr
    ):
        return None

    confidence = _compute_confidence(call_context, callee_name)

    return SinkCandidate(
        address=callsite_addr,
        function_name=caller_func,
        preliminary_label=SinkLabel.COPY_SINK,
        evidence=evidence,
        confidence_score=confidence,
        facts=facts,
    )


def _compute_confidence(context: Dict[str, Any], callee_name: str) -> float:
    """Compute confidence score for a COPY_SINK candidate.

    Higher confidence = higher risk:
    - No explicit length arg (strcpy, sprintf) → dangerous
    - Variable-length copy without guard → high risk
    - Constant length → low risk
    - Arg-provenance dst → bonus
    """
    score = 0.4  # Baseline: found a callsite to a copy function

    len_idx = _LEN_ARG_INDEX.get(callee_name)
    if len_idx is None:
        score += 0.25  # No length bound at all

    if not context.get("len_is_constant", True):
        score += 0.15

    if not context.get("has_bounds_guard", False):
        score += 0.10

    dst_prov = context.get("dst_provenance", "UNKNOWN")
    if dst_prov == "ARG":
        score += 0.05
    elif dst_prov == "STACK_PTR":
        score += 0.03

    if context.get("call_found"):
        score += 0.05

    return min(score, 0.95)


# ── MCP helper ───────────────────────────────────────────────────────────────


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
