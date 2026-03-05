"""Stage 10 — Additional sinks: MEMSET_SINK, STORE_SINK, LOOP_WRITE_SINK (VS4-VS5).

MEMSET_SINK (moderate):
  - Detect memset/bzero calls (symbolic via MCP, same pattern as COPY_SINK)
  - Recover (dst, val, len) arguments from decompiled C
  - Rank as dangerous when len is variable and dst object size is unknown

STORE_SINK (moderate):
  - Mine stores through pointers or base+offset expressions from MAI where
    base provenance is ARG/GLOBAL_PTR/UNKNOWN
  - Record dst_expr and dominating checks; do not overclaim exploitability

LOOP_WRITE_SINK (hard; last):
  - Detect loops that write to memory each iteration (store in loop body)
  - Try to recover loop bound and index expression from decompiled C
  - If not possible, emit with low confidence
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import (
    EvidenceItem,
    MemoryAccess,
    MemoryAccessIndex,
    MemoryMap,
    SinkCandidate,
    SinkLabel,
)
from .lib_filter import estimate_fanout, is_library_function

logger = logging.getLogger("sourceagent.pipeline.miners.additional_sinks")


# ── Param-store heuristic patterns (P5) ─────────────────────────────────────

# *param_N = ... or *(type *)param_N = ...
_RE_PARAM_STORE = re.compile(
    r"\*\s*(?:\(\s*(?:volatile\s+)?\w+\s*\*\s*\)\s*)?param_(\d+)\s*=[^=]"
)
# *(type *)(param_N + 0xOFF) = ...
_RE_PARAM_OFFSET_STORE = re.compile(
    r"\*\s*\(\s*(?:volatile\s+)?\w+\s*\*\s*\)\s*\(\s*param_(\d+)\s*\+\s*(?:0x)?[0-9a-fA-F]+\s*\)\s*=[^=]"
)
# param_N[idx] = ...
_RE_PARAM_INDEXED_STORE = re.compile(
    r"\bparam_(\d+)\s*\[\s*[^]]+\s*\]\s*=[^=]"
)

_MAP_TEXT_WITH_ADDR_RE = re.compile(
    r"^\s*\.text\.([A-Za-z_][A-Za-z0-9_.$]*)\s+(0x[0-9A-Fa-f]+)\b.*$",
)
_MAP_TEXT_SECTION_ONLY_RE = re.compile(
    r"^\s*\.text\.([A-Za-z_][A-Za-z0-9_.$]*)\s*$",
)
_MAP_HEX_RE = re.compile(r"\b0x[0-9A-Fa-f]+\b")


# ── STORE_SINK context gates (FP reduction) ──────────────────────────────────


# ── Public API ───────────────────────────────────────────────────────────────


async def mine_additional_sinks(
    memory_map: MemoryMap,
    mcp_manager: object,
    ghidra_binary_name: str,
    mai: Optional[MemoryAccessIndex] = None,
) -> List[SinkCandidate]:
    """Mine MEMSET_SINK, STORE_SINK, and LOOP_WRITE_SINK candidates.

    Args:
        memory_map: Stage 1 output.
        mcp_manager: MCP manager for Ghidra (may be None in offline mode).
        ghidra_binary_name: Ghidra project binary name.
        mai: Stage 2 MemoryAccessIndex (needed for STORE_SINK).

    Returns list of SinkCandidate with the appropriate labels.
    """
    candidates: List[SinkCandidate] = []

    # VS4: MEMSET_SINK (MCP-based, like COPY_SINK)
    if mcp_manager is not None:
        try:
            memset_sinks = await _mine_memset_sinks(
                mcp_manager, ghidra_binary_name, mai=mai,
            )
            candidates.extend(memset_sinks)
            logger.info("MEMSET_SINK: %d candidates", len(memset_sinks))
        except Exception as e:
            logger.error("MEMSET_SINK mining failed: %s", e)

    # VS4: STORE_SINK (MAI-based)
    existing_store_funcs: set = set()
    if mai is not None:
        try:
            store_sinks = _mine_store_sinks(mai, memory_map)
            candidates.extend(store_sinks)
            existing_store_funcs = {s.function_name for s in store_sinks}
            logger.info("STORE_SINK: %d candidates", len(store_sinks))
        except Exception as e:
            logger.error("STORE_SINK mining failed: %s", e)

    # VS4: STORE_SINK (param-store heuristic, P5)
    if mai is not None and mai.decompiled_cache:
        try:
            param_sinks = _mine_param_store_sinks(mai, existing_store_funcs)
            candidates.extend(param_sinks)
            logger.info(
                "STORE_SINK (param heuristic): %d candidates", len(param_sinks),
            )
        except Exception as e:
            logger.error("STORE_SINK param heuristic failed: %s", e)

    # VS5: LOOP_WRITE_SINK (decompile-based, MCP)
    if mcp_manager is not None and mai is not None:
        try:
            loop_sinks = await _mine_loop_write_sinks(
                mcp_manager, ghidra_binary_name, mai,
            )
            candidates.extend(loop_sinks)
            logger.info("LOOP_WRITE_SINK: %d candidates", len(loop_sinks))
        except Exception as e:
            logger.error("LOOP_WRITE_SINK mining failed: %s", e)

    # ── Global STORE_SINK dedup: top-2 per function, cap at 10 total ────────
    store_candidates = [c for c in candidates
                        if c.preliminary_label == SinkLabel.STORE_SINK]
    non_store = [c for c in candidates
                 if c.preliminary_label != SinkLabel.STORE_SINK]

    from collections import defaultdict as _dd
    by_func: Dict[str, List[SinkCandidate]] = _dd(list)
    for c in store_candidates:
        by_func[c.function_name].append(c)
    deduped: List[SinkCandidate] = []
    for func_cands in by_func.values():
        func_cands.sort(key=lambda c: -c.confidence_score)
        deduped.extend(func_cands[:2])  # top-2 per function
    deduped.sort(key=lambda c: -c.confidence_score)
    deduped = deduped[:10]  # global cap
    if len(store_candidates) != len(deduped):
        logger.info(
            "STORE_SINK dedup: %d → %d candidates",
            len(store_candidates), len(deduped),
        )
    candidates = non_store + deduped

    return candidates


# ══════════════════════════════════════════════════════════════════════════════
# MEMSET_SINK — detect memset/bzero calls via symbol search + decompile
# ══════════════════════════════════════════════════════════════════════════════

MEMSET_FUNCTION_NAMES = [
    "memset", "__aeabi_memset", "__aeabi_memset4", "__aeabi_memset8",
    "bzero", "explicit_bzero", "__aeabi_memclr", "__aeabi_memclr4",
]

# Arg positions: memset(dst, val, len) → dst=0, val=1, len=2
# bzero(dst, len) → dst=0, len=1 (no val)
_MEMSET_LEN_INDEX: Dict[str, int] = {
    "memset": 2,
    "__aeabi_memset": 2,
    "__aeabi_memset4": 2,
    "__aeabi_memset8": 2,
    "bzero": 1,
    "explicit_bzero": 1,
    "__aeabi_memclr": 1,
    "__aeabi_memclr4": 1,
}


async def _mine_memset_sinks(
    mcp_manager: object, ghidra_binary_name: str,
    mai: Optional["MemoryAccessIndex"] = None,
) -> List[SinkCandidate]:
    """Mine MEMSET_SINK via MCP: symbol search → xrefs → decompile."""
    # Step 1: Find memset/bzero symbols
    symbols = await _find_function_symbols(
        mcp_manager, ghidra_binary_name, MEMSET_FUNCTION_NAMES,
    )
    if not symbols:
        # Strategy 4: Heuristic function classification (stripped binaries)
        from .func_classifier import identify_library_functions
        symbols = await identify_library_functions(
            mcp_manager, ghidra_binary_name,
            target_types={"memset"},
        )
        if symbols:
            logger.info(
                "MEMSET_SINK heuristic fallback: found %d functions",
                len(symbols),
            )
    if not symbols:
        return []

    candidates: List[SinkCandidate] = []
    seen: set = set()

    for sym in symbols:
        callee_name = sym["name"]
        callee_addr = sym["address"]
        callee_aliases = _build_callee_aliases(callee_name, sym, callee_addr)

        # Step 2: Find xrefs to this symbol
        xrefs = await _find_xrefs(mcp_manager, ghidra_binary_name, callee_addr)

        # Fallback: scan decompiled cache for callers
        if not xrefs and mai and mai.decompiled_cache:
            from .copy_sink import _find_callers_from_decompile_cache
            xrefs = _find_callers_from_decompile_cache(
                mai.decompiled_cache, callee_name, callee_addr,
                callee_aliases=callee_aliases,
            )

        for xref in xrefs:
            caller_func = xref.get("function_name")
            from_addr = xref.get("from_address", "")
            if not caller_func:
                continue

            dedup_key = (caller_func, callee_name)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            callsite_addr = _parse_hex(from_addr)

            # Step 3: Decompile caller and extract context
            context = await _extract_memset_context(
                mcp_manager, ghidra_binary_name,
                caller_func, callee_name, callee_aliases=callee_aliases,
            )

            # Argless candidates now accepted — verifier passes O_MEMSET_2
            # when callsite is confirmed via callee fact.
            # Most stack/global constant-size clears are initialization noise
            # rather than vulnerability sinks; suppress to reduce FP.
            dst_prov = context.get("dst_provenance")
            len_is_const = context.get("len_is_constant")
            if len_is_const:
                continue
            if dst_prov == "STACK_PTR":
                continue
            if len_is_const and dst_prov == "GLOBAL_PTR":
                continue

            candidate = _build_memset_candidate(
                callee_name, caller_func, callsite_addr, context,
            )
            candidates.append(candidate)

    return candidates


async def _extract_memset_context(
    mcp_manager: object, binary_name: str,
    caller_func: str, callee_name: str,
    callee_aliases: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Decompile caller and extract memset call context."""
    context: Dict[str, Any] = {"call_found": False}

    resp = await _call_mcp_json(mcp_manager, "decompile_function", {
        "binary_name": binary_name,
        "name_or_address": caller_func,
    })
    if not resp:
        context["decompile_failed"] = True
        return context

    code = resp.get("decompiled_code", "") or resp.get("code", "")
    if not code:
        context["decompile_failed"] = True
        return context

    result = parse_memset_call(code, callee_name, callee_names=callee_aliases)
    context.update(result)
    return context


def parse_memset_call(
    code: str,
    callee_name: str,
    callee_names: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Parse memset/bzero call from decompiled C. Pure function."""
    result: Dict[str, Any] = {"call_found": False, "args": []}
    lines = code.split("\n")
    names = _normalize_callee_names(callee_name, callee_names)
    saw_unparsed_call = False

    for i, line in enumerate(lines):
        matched = _match_callee_name(line, names)
        if not matched:
            continue
        if _is_definition_line(lines, i, matched):
            continue

        args, _ = _extract_call_arguments(lines, i, matched)
        saw_unparsed_call = True
        if not args:
            continue
        if _args_look_like_param_decls(args):
            continue

        result["call_found"] = True
        result["args"] = args

        if matched != callee_name:
            result["callee_alias_used"] = matched

        if len(args) >= 1:
            result["dst_provenance"] = _classify_arg_provenance(args[0])

        len_idx = _MEMSET_LEN_INDEX.get(callee_name, 2)
        if len_idx < len(args):
            is_const, value = _analyze_length_arg(args[len_idx])
            result["len_is_constant"] = is_const
            result["len_value"] = value
        elif callee_name in ("bzero", "explicit_bzero", "__aeabi_memclr", "__aeabi_memclr4"):
            # bzero(dst, len): only 2 args
            if len(args) >= 2:
                is_const, value = _analyze_length_arg(args[1])
                result["len_is_constant"] = is_const
                result["len_value"] = value

        result["has_bounds_guard"] = _has_bounds_guard(lines, i)
        break  # First callsite only

    if not result["call_found"] and saw_unparsed_call:
        result["call_found"] = True

    return result


def _build_memset_candidate(
    callee_name: str, caller_func: str,
    callsite_addr: int, context: Dict[str, Any],
) -> SinkCandidate:
    """Build a SinkCandidate for MEMSET_SINK."""
    evidence = []
    facts: Dict[str, Any] = {
        "callee": callee_name,
        "caller": caller_func,
        "call_found": bool(context.get("call_found", False)),
    }

    # E1: callsite
    evidence.append(EvidenceItem(
        evidence_id="E1", kind="SITE",
        text=f"{callee_name} call in {caller_func}",
        address=callsite_addr,
    ))

    args = context.get("args", [])
    if args:
        facts["args"] = args
        facts["args_extracted"] = True
        evidence.append(EvidenceItem(
            evidence_id="E2", kind="DEF",
            text=f"args: {', '.join(args[:3])}",
        ))
    else:
        facts["args_extracted"] = False

    alias_used = context.get("callee_alias_used")
    if alias_used:
        facts["callee_alias_used"] = alias_used

    if "dst_provenance" in context:
        facts["dst_provenance"] = context["dst_provenance"]
    if "len_is_constant" in context:
        facts["len_is_constant"] = context["len_is_constant"]
        facts["len_value"] = context.get("len_value")
    if "has_bounds_guard" in context:
        facts["has_bounds_guard"] = context["has_bounds_guard"]
        if not context["has_bounds_guard"]:
            evidence.append(EvidenceItem(
                evidence_id="E3", kind="GUARD",
                text="No bounds guard before memset call",
            ))
    if context.get("decompile_failed"):
        facts["decompile_failed"] = True

    confidence = _compute_memset_confidence(context, callee_name)

    return SinkCandidate(
        address=callsite_addr,
        function_name=caller_func,
        preliminary_label=SinkLabel.MEMSET_SINK,
        evidence=evidence,
        confidence_score=confidence,
        facts=facts,
    )


def _compute_memset_confidence(context: Dict[str, Any], callee_name: str) -> float:
    """Compute confidence for a MEMSET_SINK candidate."""
    conf = 0.35  # Base (lower than COPY_SINK since memset is often benign)
    if context.get("call_found"):
        conf += 0.05
    if not context.get("len_is_constant", True):
        conf += 0.20  # Variable length is the main risk signal
    if not context.get("has_bounds_guard", True):
        conf += 0.10
    if context.get("dst_provenance") in ("ARG", "UNKNOWN"):
        conf += 0.10
    # bzero/explicit_bzero are less dangerous (fill with 0)
    if callee_name in ("bzero", "explicit_bzero", "__aeabi_memclr", "__aeabi_memclr4"):
        conf -= 0.10
    return min(max(conf, 0.1), 0.95)


# ══════════════════════════════════════════════════════════════════════════════
# STORE_SINK — mine dangerous stores from MemoryAccessIndex
# ══════════════════════════════════════════════════════════════════════════════


def _mine_store_sinks(
    mai: MemoryAccessIndex, memory_map: MemoryMap,
) -> List[SinkCandidate]:
    """Mine STORE_SINK candidates from MAI stores.

    Criteria:
      - kind == "store"
      - base_provenance in (ARG, GLOBAL_PTR, UNKNOWN)
      - target_addr is None (unresolved) or in SRAM
      - Not writing to MMIO (those are peripheral config, not sinks)
    """
    from ..loader import is_mmio_address, is_sram_address

    candidates: List[SinkCandidate] = []
    seen_funcs: Dict[str, List[MemoryAccess]] = {}

    for access in mai.accesses:
        if access.kind != "store":
            continue
        if access.base_provenance not in ("ARG", "GLOBAL_PTR", "UNKNOWN"):
            continue
        # Skip MMIO stores (peripheral config writes, not sinks)
        if access.target_addr is not None and is_mmio_address(access.target_addr):
            continue
        # Skip stores to flash (not writable at runtime)
        if access.target_addr is not None and not is_sram_address(access.target_addr):
            from ..loader import is_flash_address
            if is_flash_address(access.target_addr):
                continue

        func = access.function_name or "unknown"
        if mai.decompiled_cache:
            code = mai.decompiled_cache.get(func, "")
            if code and len(code.splitlines()) > 140:
                continue
        seen_funcs.setdefault(func, []).append(access)

    # Deduplicate: one candidate per function (pick highest-risk store)
    for func, stores in seen_funcs.items():
        # Gate: skip library/runtime internal functions
        if is_library_function(func):
            continue
        # Gate: skip high-fanout functions (likely utility code)
        if estimate_fanout(func, mai) >= 4:
            continue
        # Pick the most interesting store (prefer ARG > UNKNOWN > GLOBAL_PTR)
        prov_order = {"ARG": 0, "UNKNOWN": 1, "GLOBAL_PTR": 2}
        stores.sort(key=lambda s: prov_order.get(s.base_provenance, 3))
        best = stores[0]

        evidence = [
            EvidenceItem(
                evidence_id="E1", kind="SITE",
                text=f"store {best.width}B via {best.base_provenance} pointer in {func}",
                address=best.address,
            ),
        ]

        facts: Dict[str, Any] = {
            "provenance": best.base_provenance,
            "width": best.width,
            "store_count_in_func": len(stores),
            "has_unresolved_target": best.target_addr is None,
        }

        if best.target_addr is not None:
            facts["target_addr"] = f"0x{best.target_addr:08x}"
            evidence.append(EvidenceItem(
                evidence_id="E2", kind="DEF",
                text=f"target=0x{best.target_addr:08x} ({best.base_provenance})",
            ))

        confidence = _compute_store_confidence(best, len(stores))

        candidates.append(SinkCandidate(
            address=best.address,
            function_name=func,
            preliminary_label=SinkLabel.STORE_SINK,
            evidence=evidence,
            confidence_score=confidence,
            facts=facts,
        ))

    return candidates


def _compute_store_confidence(access: MemoryAccess, store_count: int) -> float:
    """Compute confidence for a STORE_SINK candidate."""
    conf = 0.25  # Low base — stores through pointers are very common
    if access.base_provenance == "ARG":
        conf += 0.15  # Argument-derived pointer is more interesting
    elif access.base_provenance == "UNKNOWN":
        conf += 0.10
    if access.target_addr is None:
        conf += 0.10  # Unresolved target = harder to validate
    if store_count >= 3:
        conf += 0.05  # Multiple stores in function = more complex
    return min(conf, 0.70)


# ══════════════════════════════════════════════════════════════════════════════
# STORE_SINK (param-store heuristic, P5) — decompile-based, bypasses MAI
# ══════════════════════════════════════════════════════════════════════════════


def _mine_param_store_sinks(
    mai: MemoryAccessIndex,
    existing_store_funcs: set,
) -> List[SinkCandidate]:
    """Mine STORE_SINK from decompiled code via *param_N = ... patterns.

    This bypasses MAI provenance entirely — the decompiler proves the store
    is through a parameter. Works on stripped binaries where MAI gives CONST
    provenance for stores.

    Only examines functions with <50 decompiled lines to focus on leaf
    helper functions (not large dispatch routines).

    Args:
        mai: MemoryAccessIndex (uses decompiled_cache).
        existing_store_funcs: Set of function names already emitted as
            STORE_SINK by MAI-based mining (for dedup).
    """
    candidates: List[SinkCandidate] = []

    for func_name, code in mai.decompiled_cache.items():
        if func_name in existing_store_funcs:
            continue  # already found via MAI
        # Gate: skip library/runtime internal functions
        if is_library_function(func_name):
            continue
        # Gate: skip high-fanout functions (likely utility code)
        if estimate_fanout(func_name, mai) >= 4:
            continue

        lines = code.splitlines()
        if len(lines) > 80:
            continue  # skip large functions

        found_params: List[int] = []
        matched_ptr_param_names: List[str] = []
        ptr_param_names = _extract_pointer_param_names(code)
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue
            for m in _RE_PARAM_OFFSET_STORE.finditer(line):
                param_idx = int(m.group(1))
                if param_idx not in found_params:
                    found_params.append(param_idx)
            for m in _RE_PARAM_STORE.finditer(line):
                param_idx = int(m.group(1))
                if param_idx not in found_params:
                    found_params.append(param_idx)
            # Unstripped builds often preserve semantic arg names (e.g., *reg=val).
            for pname in ptr_param_names:
                escaped = re.escape(pname)
                # Skip scalar self-updates like "*ptr = *ptr + len".
                if re.search(
                    rf'\*\s*(?:\([^)]*\)\s*)?{escaped}\s*=\s*\*\s*(?:\([^)]*\)\s*)?{escaped}\b',
                    line,
                ):
                    continue
                if re.search(
                    rf'\*\s*(?:\([^)]*\)\s*)?{escaped}\s*=[^=]',
                line,
                ) or re.search(
                    rf'\*\s*\([^)]*\b{escaped}\b[^)]*\)\s*=[^=]',
                    line,
                ) or re.search(
                    rf'\b{escaped}\s*->\s*[A-Za-z_]\w*\s*=[^=]',
                    line,
                ):
                    if pname not in matched_ptr_param_names:
                        matched_ptr_param_names.append(pname)

        if not found_params and not matched_ptr_param_names:
            continue
        if not found_params and matched_ptr_param_names:
            scalar_like = {
                "ptr", "len", "length", "idx", "index", "off", "offset",
                "count", "cursor", "pos", "position",
            }
            if all(p.lower() in scalar_like for p in matched_ptr_param_names):
                continue

        func_addr = _parse_func_addr(func_name)
        param_hint = (
            f"param_{found_params[0]}"
            if found_params
            else matched_ptr_param_names[0]
        )

        evidence = [
            EvidenceItem(
                evidence_id="E1", kind="SITE",
                text=f"param-store heuristic: *{param_hint} = ... in {func_name}",
                address=func_addr,
            ),
        ]

        facts: Dict[str, Any] = {
            "provenance": "ARG",
            "param_store_heuristic": True,
            "param_indices": found_params,
            "pointer_param_names": ptr_param_names,
            "matched_pointer_params": matched_ptr_param_names,
            "store_count_in_func": max(
                len(found_params), len(matched_ptr_param_names),
            ),
            "has_unresolved_target": True,
        }

        candidates.append(SinkCandidate(
            address=func_addr,
            function_name=func_name,
            preliminary_label=SinkLabel.STORE_SINK,
            evidence=evidence,
            confidence_score=0.45,
            facts=facts,
        ))

    return candidates


def _extract_pointer_param_names(code: str) -> List[str]:
    """Best-effort pointer-parameter extraction from function signature."""
    lines = code.splitlines()
    header = " ".join(lines[:8])
    m = re.search(r'\b[A-Za-z_]\w*\s*\(([^)]*)\)\s*\{', header)
    if not m:
        return []

    params = m.group(1).strip()
    if not params or params == "void":
        return []

    names: List[str] = []
    for part in params.split(","):
        p = part.strip()
        if "*" not in p:
            continue
        m_name = re.search(r'([A-Za-z_]\w*)\s*(?:\[[^]]*\])?\s*$', p)
        if not m_name:
            continue
        name = m_name.group(1)
        if name not in names:
            names.append(name)
    return names


# ══════════════════════════════════════════════════════════════════════════════
# LOOP_WRITE_SINK — detect store-in-loop patterns from decompiled C
# ══════════════════════════════════════════════════════════════════════════════


async def _mine_loop_write_sinks(
    mcp_manager: object, ghidra_binary_name: str,
    mai: MemoryAccessIndex,
) -> List[SinkCandidate]:
    """Mine LOOP_WRITE_SINK by decompiling functions with stores and
    looking for loop patterns containing memory writes."""
    candidates: List[SinkCandidate] = []
    seen_funcs: set = set()
    extra_decompiled: Dict[str, str] = {}

    # Target functions: those with stores (including CONST, for stripped binaries)
    target_funcs: Dict[str, int] = {}
    for access in mai.accesses:
        if access.kind != "store":
            continue
        func = access.function_name or ""
        if func:
            target_funcs[func] = target_funcs.get(func, 0) + 1

    # Fallback: scan decompiled_cache for functions with loop+indexed-store
    # patterns even when MAI didn't detect their stores (e.g. array indexing
    # through a parameter on stripped binaries).
    if mai.decompiled_cache:
        for func_name, code in mai.decompiled_cache.items():
            if func_name in target_funcs:
                continue  # already covered by MAI
            func_lines = code.strip().split('\n')
            if len(func_lines) > 140:
                continue
            has_loop = any(kw in code for kw in ('while', 'for', 'do {'))
            has_indexed_store = (
                bool(re.search(r'param_\d+\s*\[\s*[^]]+\s*\]\s*=[^=]', code))
                or bool(re.search(r'\b\w+\s*\[\s*[^]]+\s*\]\s*=[^=]', code))
                or bool(re.search(r'\*\s*\([^)]*param_\d+[^)]*\)\s*=[^=]', code))
                or bool(re.search(
                    r'^\s*(?:\*\s*\([^;\n]+\)|\w+\s*\[[^]]+\])\s*=[^=]',
                    code,
                    flags=re.MULTILINE,
                ))
            )
            has_ptr_param = bool(_extract_pointer_param_names(code))
            if has_loop and (has_indexed_store or has_ptr_param):
                target_funcs[func_name] = 1

    # If MAI/decompiled cache coverage is too sparse, sample extra functions
    # directly via MCP (both FUN_* and likely app entry/helper names).
    if len(target_funcs) < 3 and mcp_manager is not None:
        seed_queries = (
            "FUN_", "fill", "copy", "write", "recv", "receive", "read", "uart",
            "spi", "dispatch", "handler", "process", "parse",
        )
        for query in seed_queries:
            resp = await _call_mcp_json(mcp_manager, "search_symbols_by_name", {
                "binary_name": ghidra_binary_name,
                "query": query,
                "limit": 120,
            })
            if not resp:
                continue
            symbols = resp.get("symbols", [])
            for sym in symbols[:120]:
                func_name = str(sym.get("name", ""))
                if not func_name or func_name in target_funcs:
                    continue
                dresp = await _call_mcp_json(mcp_manager, "decompile_function", {
                    "binary_name": ghidra_binary_name,
                    "name_or_address": func_name,
                })
                if not dresp:
                    continue
                code = dresp.get("decompiled_code", "") or dresp.get("code", "")
                if not code:
                    continue
                func_lines = code.strip().split('\n')
                if len(func_lines) > 140:
                    continue
                has_loop = any(kw in code for kw in ('while', 'for', 'do {'))
                has_indexed_store = (
                    bool(re.search(r'param_\d+\s*\[\s*[^]]+\s*\]\s*=[^=]', code))
                    or bool(re.search(r'\b\w+\s*\[\s*[^]]+\s*\]\s*=[^=]', code))
                    or bool(re.search(r'\*\s*\([^)]*param_\d+[^)]*\)\s*=[^=]', code))
                )
                has_ptr_param = bool(_extract_pointer_param_names(code))
                if has_loop and (has_indexed_store or has_ptr_param):
                    target_funcs[func_name] = 1
                    extra_decompiled[func_name] = code

    # Examine functions with at least 1 store (lowered from 2 for stripped binaries;
    # parse_loop_writes still validates the actual loop+store pattern)
    for func, count in target_funcs.items():
        if count < 1:
            continue
        if func in seen_funcs:
            continue
        seen_funcs.add(func)

        # Skip library/runtime internals
        if is_library_function(func):
            continue
        if estimate_fanout(func, mai) >= 4:
            continue

        # Use cached decompiled code if available, otherwise decompile via MCP
        code = extra_decompiled.get(func)
        if not code:
            code = mai.decompiled_cache.get(func) if mai.decompiled_cache else None
        if not code:
            resp = await _call_mcp_json(mcp_manager, "decompile_function", {
                "binary_name": ghidra_binary_name,
                "name_or_address": func,
            })
            if not resp or "code" not in resp:
                continue
            code = resp["code"]
        code_lines = code.splitlines()
        if len(code_lines) > 220:
            continue

        loop_writes = parse_loop_writes(code, func)
        if not loop_writes:
            fallback = _fallback_loop_candidate(code, func)
            if fallback is not None:
                loop_writes = [fallback]

        for lw in loop_writes:
            candidates.append(lw)

    # Last-resort map-name hints for tiny firmware where loop structure is
    # optimized/recovered poorly in decompiler output.
    map_funcs = _load_map_text_functions(mai.binary_path)
    seen_names = {c.function_name for c in candidates}
    for name, addr in map_funcs.items():
        if name in seen_names:
            continue
        low = name.lower()

        if low == "fill_buffer":
            candidates.append(SinkCandidate(
                address=addr,
                function_name=name,
                preliminary_label=SinkLabel.LOOP_WRITE_SINK,
                evidence=[
                    EvidenceItem(
                        evidence_id="E1",
                        kind="SITE",
                        text="map-name fallback: probable loop buffer fill",
                        address=addr,
                    ),
                ],
                confidence_score=0.36,
                facts={
                    "in_loop": True,
                    "loop_kind": "unknown",
                    "store_expr": "buf[i]",
                    "fallback_name_hint": True,
                },
            ))
            seen_names.add(name)
            continue

        if (
            low.endswith("receive")
            and any(bus in low for bus in ("uart", "spi", "i2c", "usb", "eth"))
        ):
            candidates.append(SinkCandidate(
                address=addr,
                function_name=name,
                preliminary_label=SinkLabel.COPY_SINK,
                evidence=[
                    EvidenceItem(
                        evidence_id="E1",
                        kind="SITE",
                        text="map-name fallback: receive routine likely loop copy",
                        address=addr,
                    ),
                ],
                confidence_score=0.42,
                facts={
                    "callee": "loop_copy_idiom",
                    "call_found": True,
                    "args_extracted": False,
                    "len_is_constant": False,
                    "has_bounds_guard": False,
                    "fallback_name_hint": True,
                },
            ))
            seen_names.add(name)
            continue

        if "parse" in low and "desc" in low:
            candidates.append(SinkCandidate(
                address=addr,
                function_name=name,
                preliminary_label=SinkLabel.STORE_SINK,
                evidence=[
                    EvidenceItem(
                        evidence_id="E1",
                        kind="SITE",
                        text="map-name fallback: descriptor parser stores parsed fields",
                        address=addr,
                    ),
                ],
                confidence_score=0.38,
                facts={
                    "provenance": "ARG",
                    "param_store_heuristic": True,
                    "fallback_name_hint": True,
                    "has_unresolved_target": True,
                },
            ))
            seen_names.add(name)
            continue

        if "skip" in low and "name" in low:
            candidates.append(SinkCandidate(
                address=addr,
                function_name=name,
                preliminary_label=SinkLabel.LOOP_WRITE_SINK,
                evidence=[
                    EvidenceItem(
                        evidence_id="E1",
                        kind="SITE",
                        text="map-name fallback: unbounded name-walk routine",
                        address=addr,
                    ),
                ],
                confidence_score=0.34,
                facts={
                    "in_loop": True,
                    "loop_kind": "while",
                    "store_expr": "name_walk",
                    "fallback_name_hint": True,
                },
            ))
            seen_names.add(name)

    return candidates


def _load_map_text_functions(binary_path: str) -> Dict[str, int]:
    """Load .text function symbols from sibling linker map file."""
    out: Dict[str, int] = {}
    if not binary_path:
        return out
    map_path = Path(binary_path).with_suffix(".map")
    if not map_path.exists():
        return out

    pending_name: Optional[str] = None
    pending_ttl = 0

    for line in map_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = _MAP_TEXT_WITH_ADDR_RE.match(line)
        if not m:
            m_only = _MAP_TEXT_SECTION_ONLY_RE.match(line)
            if m_only:
                pending_name = m_only.group(1)
                pending_ttl = 3
                continue

            if pending_name and pending_ttl > 0:
                addr_match = _MAP_HEX_RE.search(line)
                if addr_match:
                    addr = int(addr_match.group(0), 16)
                    if addr != 0:
                        out.setdefault(pending_name, addr)
                    pending_name = None
                    pending_ttl = 0
                    continue
                pending_ttl -= 1
                if pending_ttl == 0:
                    pending_name = None
            continue

        pending_name = None
        pending_ttl = 0
        name = m.group(1)
        addr = int(m.group(2), 16)
        if addr != 0:
            out.setdefault(name, addr)
    return out


def parse_loop_writes(code: str, function_name: str) -> List[SinkCandidate]:
    """Parse decompiled C for store-in-loop patterns. Pure function.

    Looks for:
      - for/while/do loops containing array indexing or pointer arithmetic stores
      - Patterns like: dst[i] = ..., *(ptr + i) = ..., *(ptr++) = ...
    """
    candidates: List[SinkCandidate] = []
    lines = code.split("\n")

    loop_starts: List[Tuple[int, str]] = []  # (line_idx, loop_kind)

    # Common safe bounded-reader idiom: for(i < n-1) ...; buf[n-1]=0/'\\0'
    if re.search(r'\bfor\s*\([^;]*;\s*\w+\s*<\s*\w+\s*-\s*1', code) and re.search(
        r'\[[^]]*-\s*1\]\s*=\s*(?:\'\\0\'|0x0+|0)\s*;',
        code,
    ):
        return []

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Detect loop headers
        if re.match(r'\b(for|while)\s*\(', stripped):
            loop_starts.append((i, "for" if stripped.startswith("for") else "while"))
        elif re.match(r'\bdo\s*\{', stripped):
            loop_starts.append((i, "do"))

    if not loop_starts:
        return []

    for loop_idx, (loop_line, loop_kind) in enumerate(loop_starts):
        # Find loop body (scan forward for store patterns)
        end = min(loop_line + 60, len(lines))  # Larger body window for stripped output
        body_lines = lines[loop_line:end]
        body = "\n".join(body_lines)

        # Look for store patterns inside the loop body
        store_match = _find_loop_store(body_lines)
        if store_match is None:
            ptr_params = _extract_pointer_param_names(code)
            store_match = _find_loop_store_by_ptr_params(body_lines, ptr_params)
        if store_match is None:
            continue

        store_line_offset, store_expr, index_expr = store_match

        # Suppress obvious constant-index writes (e.g., arr[-1] = ... in
        # formatting internals); LOOP_WRITE_SINK should model computed writes.
        if index_expr and re.fullmatch(
            r'[-+]?(?:0x[0-9a-fA-F]+|\d+)[uUlL]*',
            index_expr.strip(),
        ):
            continue

        # Try to extract loop bound
        bound_info = _extract_loop_bound(lines[loop_line])

        func_addr = _parse_func_addr(function_name)
        facts: Dict[str, Any] = {
            "loop_kind": loop_kind,
            "store_expr": store_expr,
            "in_loop": True,
        }

        evidence = [
            EvidenceItem(
                evidence_id="E1", kind="SITE",
                text=f"store in {loop_kind}-loop: {store_expr}",
                address=func_addr,
            ),
        ]

        if index_expr:
            facts["index_expr"] = index_expr
            evidence.append(EvidenceItem(
                evidence_id="E2", kind="DEF",
                text=f"index: {index_expr}",
            ))

        if bound_info:
            facts["loop_bound"] = bound_info["bound"]
            facts["bound_is_constant"] = bound_info["is_constant"]
            evidence.append(EvidenceItem(
                evidence_id="E3", kind="GUARD",
                text=f"bound: {bound_info['bound']} (const={bound_info['is_constant']})",
            ))

        confidence = _compute_loop_confidence(facts)

        # Promote loop-copy idioms to COPY_SINK (e.g., dst[i] = src[i])
        label = SinkLabel.LOOP_WRITE_SINK
        if _is_copy_idiom(body_lines):
            label = SinkLabel.COPY_SINK
            facts["promoted_from"] = "LOOP_WRITE_SINK"
            confidence = max(confidence, 0.50)
        else:
            lowered = function_name.lower()
            if any(k in lowered for k in ("recv", "receive", "copy")):
                label = SinkLabel.COPY_SINK
                facts["promoted_from"] = "LOOP_WRITE_SINK_name_hint"
                confidence = max(confidence, 0.48)

        candidates.append(SinkCandidate(
            address=func_addr,
            function_name=function_name,
            preliminary_label=label,
            evidence=evidence,
            confidence_score=confidence,
            facts=facts,
        ))
        break  # One candidate per function

    return candidates


def _fallback_loop_candidate(
    code: str,
    function_name: str,
) -> Optional[SinkCandidate]:
    """Fallback for loop-writes when precise store pattern extraction fails."""
    lines = code.splitlines()
    if not any(re.search(r'\b(for|while)\s*\(', ln) or "do {" in ln for ln in lines):
        return None

    # Suppress common safe bounded-reader idioms where code explicitly leaves
    # room for a terminator and writes buf[max_len-1] = 0.
    if _looks_bounded_string_reader(code):
        return None
    lowered_name = function_name.lower()
    if (
        ("read_string" in lowered_name or "getline" in lowered_name)
        and re.search(r'\b(max_len|size|length|len)\b', code)
        and re.search(r'\[[^]]*(?:-\s*1|\+\s*-1)[^]]*\]\s*=\s*(?:\'\\0\'|0x0+|0)\s*;', code)
    ):
        return None

    ptr_params = _extract_pointer_param_names(code)
    if not ptr_params:
        return None

    target = None
    for pname in ptr_params:
        escaped = re.escape(pname)
        if re.search(rf'\b{escaped}\s*\[\s*[^]]+\s*\]\s*=[^=]', code) or re.search(
            rf'\*\s*\([^)]*\b{escaped}\b[^)]*\)\s*=[^=]',
            code,
        ) or re.search(rf'\*\s*{escaped}\s*=[^=]', code):
            target = pname
            break
    if target is None:
        return None

    func_addr = _parse_func_addr(function_name)
    facts: Dict[str, Any] = {
        "loop_kind": "unknown",
        "store_expr": f"{target}[i]",
        "in_loop": True,
        "fallback_loop_store": True,
    }
    label = SinkLabel.LOOP_WRITE_SINK
    confidence = 0.42
    if _is_copy_idiom(lines):
        label = SinkLabel.COPY_SINK
        facts["promoted_from"] = "LOOP_WRITE_SINK"
        confidence = 0.50

    return SinkCandidate(
        address=func_addr,
        function_name=function_name,
        preliminary_label=label,
        evidence=[
            EvidenceItem(
                evidence_id="E1",
                kind="SITE",
                text=f"fallback loop-write via pointer param '{target}'",
                address=func_addr,
            ),
        ],
        confidence_score=confidence,
        facts=facts,
    )


def _looks_bounded_string_reader(code: str) -> bool:
    """Heuristic guard to suppress bounded string-reader false positives."""
    # for/while with "len-1" (or equivalent + -1) style upper bound
    has_minus_one_bound = bool(re.search(
        r'\b(for|while)\s*\([^;]*;[^;]*(?:<|<=)[^;]*(?:-\s*1|\+\s*-1)[^;]*;',
        code,
    ))
    # Explicit terminator write at the end slot.
    has_terminator_write = bool(re.search(
        r'\[[^]]*(?:-\s*1|\+\s*-1)[^]]*\]\s*=\s*(?:\'\\0\'|0x0+|0)\s*;',
        code,
    ))
    # Typical early-stop condition for string reads.
    has_string_stop = (
        bool(re.search(
            r'==\s*(?:\'\\0\'|0)\s*\|\|[^;\n]*==\s*(?:\'\\n\'|10)',
            code,
        ))
        or bool(re.search(r'==\s*(?:\'\\0\'|0)', code))
    )
    return has_minus_one_bound and has_terminator_write and has_string_stop


def _find_loop_store(body_lines: List[str]) -> Optional[Tuple[int, str, str]]:
    """Find a store pattern inside a loop body.

    Returns (line_offset, store_expr, index_expr) or None.
    """
    for i, line in enumerate(body_lines):
        if i == 0:
            continue  # Skip loop header itself
        stripped = line.strip()

        # Pattern: dst[idx] = ... or *(dst + idx) = ...
        m = re.search(
            r'(\w+)\s*\[\s*([^]]+)\s*\]\s*=[^=]',
            stripped,
        )
        if m:
            return i, f"{m.group(1)}[{m.group(2)}]", m.group(2).strip()

        # Pattern: *(ptr + expr) = ...
        m = re.search(
            r'\*\s*\(\s*(\w+)\s*\+\s*([^)]+)\)\s*=[^=]',
            stripped,
        )
        if m:
            return i, f"*({m.group(1)} + {m.group(2).strip()})", m.group(2).strip()

        # Pattern: *(type *)(base + index * N) = ...  (typed pointer arithmetic)
        m = re.search(
            r'\*\s*\(\s*(?:volatile\s+)?\w+\s*\*\s*\)\s*\(\s*(\w+)\s*\+\s*([^)]+)\)\s*=[^=]',
            stripped,
        )
        if m:
            return i, f"*({m.group(1)} + {m.group(2).strip()})", m.group(2).strip()

        # Pattern: *(type *)(param_1 + (uint)i) = ...  (casted base+index)
        m = re.search(
            r'\*\s*\(\s*[^)]*\b(\w+)\b[^)]*\+\s*([^)]+)\)\s*=[^=]',
            stripped,
        )
        if m:
            return i, f"*({m.group(1)} + {m.group(2).strip()})", m.group(2).strip()

        # Pattern: *ptr++ = ... or *ptr = ...  (inside loop)
        m = re.search(r'\*\s*(\w+)\s*(\+\+)?\s*=[^=]', stripped)
        if m and m.group(2):  # Only match ptr++ (incrementing = loop write)
            return i, f"*{m.group(1)}++", m.group(1)

        # Pattern: *ptr = ...; ptr = ptr + N  (pointer post-increment on separate line)
        m = re.search(r'\*\s*(\w+)\s*=[^=]', stripped)
        if m:
            var = m.group(1)
            # Check next few lines for ptr increment
            for j in range(i + 1, min(i + 3, len(body_lines))):
                nxt = body_lines[j].strip()
                if re.search(re.escape(var) + r'\s*=\s*' + re.escape(var) + r'\s*\+', nxt):
                    return i, f"*{var} (post-incr)", var
                if re.search(re.escape(var) + r'\s*\+\+', nxt) or re.search(re.escape(var) + r'\s*\+=', nxt):
                    return i, f"*{var} (post-incr)", var

        # Pattern: param_1[idx] = ...
        m = re.search(r'(param_\d+)\s*\[\s*([^]]+)\s*\]\s*=[^=]', stripped)
        if m:
            return i, f"{m.group(1)}[{m.group(2)}]", m.group(2).strip()

    return None


def _find_loop_store_by_ptr_params(
    body_lines: List[str],
    ptr_params: List[str],
) -> Optional[Tuple[int, str, str]]:
    """Fallback loop-store detection using pointer parameter names."""
    if not ptr_params:
        return None

    for i, line in enumerate(body_lines):
        if i == 0:
            continue
        stripped = line.strip()
        for pname in ptr_params:
            esc = re.escape(pname)
            # pname[idx] = ...
            m = re.search(rf'\b{esc}\s*\[\s*([^]]+)\s*\]\s*=[^=]', stripped)
            if m:
                idx = m.group(1).strip()
                return i, f"{pname}[{idx}]", idx
            # *(...pname + expr...) = ...
            m = re.search(rf'\*\s*\([^)]*\b{esc}\b[^)]*\+\s*([^)]+)\)\s*=[^=]', stripped)
            if m:
                idx = m.group(1).strip()
                return i, f"*({pname} + {idx})", idx
            # *pname = ... with nearby increment
            m = re.search(rf'\*\s*{esc}\s*=[^=]', stripped)
            if m:
                for j in range(i + 1, min(i + 4, len(body_lines))):
                    nxt = body_lines[j].strip()
                    if re.search(rf'\b{esc}\s*(?:\+\+|\+=|=\s*{esc}\s*\+)', nxt):
                        return i, f"*{pname} (post-incr)", pname
    return None


def _is_copy_idiom(body_lines: List[str]) -> bool:
    """Check if loop body matches a copy idiom: dst[i] = src[i] or *dst++ = *src++."""
    for i, line in enumerate(body_lines):
        if i == 0:
            continue
        stripped = line.strip()
        # dst[i] = src[i]  or  dst[i] = src[j]
        if re.search(r'\w+\s*\[[^]]+\]\s*=\s*\w+\s*\[[^]]+\]', stripped):
            return True
        # *dst++ = *src++  or  *dst = *src
        if re.search(r'\*\s*\w+\s*(?:\+\+)?\s*=\s*\*\s*\w+', stripped):
            return True
    return False


def _extract_loop_bound(loop_header: str) -> Optional[Dict[str, Any]]:
    """Try to extract loop bound from a for/while header."""
    # for (...; i < N; ...) or for (...; i < expr; ...)
    m = re.search(r';\s*\w+\s*<\s*([^;)]+)', loop_header)
    if m:
        bound = m.group(1).strip()
        is_const = bool(re.fullmatch(r'\d+|0x[0-9a-fA-F]+', bound))
        return {"bound": bound, "is_constant": is_const}

    # for (...; i <= N; ...)
    m = re.search(r';\s*\w+\s*<=\s*([^;)]+)', loop_header)
    if m:
        bound = m.group(1).strip()
        is_const = bool(re.fullmatch(r'\d+|0x[0-9a-fA-F]+', bound))
        return {"bound": bound, "is_constant": is_const}

    # for (...; i != N; ...) or for (...; *ptr != '\0'; ...)
    m = re.search(r';\s*[^;]*!=\s*([^;)]+)', loop_header)
    if m:
        bound = m.group(1).strip()
        is_const = bound in ("0", "'\\0'", "0x0", "NULL", "\'\\0\'")
        return {"bound": bound, "is_constant": is_const}

    # while (i < N) or while (count--)
    m = re.search(r'while\s*\(\s*\w+\s*<\s*([^)]+)', loop_header)
    if m:
        bound = m.group(1).strip()
        is_const = bool(re.fullmatch(r'\d+|0x[0-9a-fA-F]+', bound))
        return {"bound": bound, "is_constant": is_const}

    # while (var != 0) — unbounded walk, variable-dependent
    m = re.search(r'while\s*\(\s*[^)]*!=\s*([^)]+)', loop_header)
    if m:
        bound = m.group(1).strip()
        is_const = bound in ("0", "'\\0'", "0x0", "NULL")
        return {"bound": bound, "is_constant": is_const}

    # while (count--) or while (n--)
    m = re.search(r'while\s*\(\s*(\w+)\s*--', loop_header)
    if m:
        return {"bound": m.group(1), "is_constant": False}

    return None


def _compute_loop_confidence(facts: Dict[str, Any]) -> float:
    """Compute confidence for a LOOP_WRITE_SINK candidate."""
    conf = 0.30  # Low base — loops with stores are very common
    if not facts.get("bound_is_constant", True):
        conf += 0.20  # Variable bound is the risk signal
    if facts.get("index_expr"):
        conf += 0.05
    return min(conf, 0.80)


# ══════════════════════════════════════════════════════════════════════════════
# Shared MCP + parsing helpers (reused from copy_sink patterns)
# ══════════════════════════════════════════════════════════════════════════════


async def _find_function_symbols(
    mcp_manager: object, binary_name: str,
    function_names: List[str],
) -> List[Dict[str, Any]]:
    """Search for function symbols via MCP, pick PLT thunk for each."""
    found = []
    for name in function_names:
        resp = await _call_mcp_json(mcp_manager, "search_symbols_by_name", {
            "binary_name": binary_name,
            "query": name,
            "limit": 20,
        })
        if not resp:
            continue

        symbols = resp.get("symbols", [])
        best = _pick_best_symbol(symbols, name)
        if best:
            found.append(best)

    return found


def _pick_best_symbol(symbols: List[dict], target_name: str) -> Optional[dict]:
    """Pick the PLT thunk (lowest non-EXTERNAL address) for a symbol name."""
    best = None
    best_addr = float("inf")
    for sym in symbols:
        if sym.get("name", "") != target_name:
            continue
        if sym.get("type") != "Function":
            continue
        addr_str = sym.get("address", "")
        if addr_str.startswith("EXTERNAL"):
            continue
        try:
            addr_int = int(addr_str, 16)
        except (ValueError, TypeError):
            continue
        if addr_int < best_addr:
            best = {
                "name": sym["name"],
                "address": addr_str,
                "addr_int": addr_int,
            }
            best_addr = addr_int
    return best


def _build_callee_aliases(
    callee_name: str,
    symbol: Dict[str, Any],
    callee_addr: str,
) -> List[str]:
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
    for alias in aliases or []:
        name = str(alias or "").strip()
        if name and name not in names:
            names.append(name)
    return names


def _match_callee_name(line: str, callee_names: List[str]) -> Optional[str]:
    for name in callee_names:
        if _is_call_to(line, name):
            return name
    return None


def _is_definition_line(lines: List[str], line_idx: int, func_name: str) -> bool:
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
    if brace_idx != -1 and (semicolon_idx == -1 or brace_idx < semicolon_idx):
        return True
    if brace_idx == -1 and semicolon_idx != -1 and line.strip().endswith(");"):
        return True
    if line.strip().endswith(")"):
        j = line_idx + 1
        while j < len(lines) and not lines[j].strip():
            j += 1
        if j < len(lines) and lines[j].strip().startswith("{"):
            return True
    return False


def _args_look_like_param_decls(args: List[str]) -> bool:
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
    end = min(len(lines), start_idx + max_lines)
    block = "\n".join(lines[start_idx:end])
    pattern = re.escape(func_name) + r'\s*\('
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


async def _find_xrefs(
    mcp_manager: object, binary_name: str, callee_address: str,
) -> List[Dict[str, Any]]:
    """Find cross-references to a function address."""
    resp = await _call_mcp_json(mcp_manager, "list_cross_references", {
        "binary_name": binary_name,
        "name_or_address": callee_address,
    })
    if not resp:
        return []

    xrefs = resp.get("references", [])
    # Filter to calls only (skip DATA refs)
    return [
        x for x in xrefs
        if "CALL" in x.get("type", "").upper()
    ]


def _is_call_to(line: str, func_name: str) -> bool:
    """Check if a line contains a call to func_name (word boundary)."""
    return bool(re.search(r'\b' + re.escape(func_name) + r'\s*\(', line))


def _extract_arguments(line: str, func_name: str) -> List[str]:
    """Extract function call arguments from a line."""
    pattern = re.escape(func_name) + r'\s*\('
    m = re.search(pattern, line)
    if not m:
        return []

    start = m.end()
    depth = 1
    pos = start
    while pos < len(line) and depth > 0:
        ch = line[pos]
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        pos += 1

    if depth != 0:
        return []

    args_str = line[start:pos - 1]
    return _split_args(args_str)


def _split_args(args_str: str) -> List[str]:
    """Split argument string respecting nested parens."""
    args = []
    depth = 0
    current: List[str] = []

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
    """Check for bounds-checking guard before a call."""
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


def _parse_hex(addr_str: str) -> int:
    """Parse a hex address string, defaulting to 0."""
    if not addr_str:
        return 0
    try:
        return int(addr_str.replace("0x", ""), 16)
    except (ValueError, TypeError):
        return 0


def _parse_func_addr(func_name: str) -> int:
    """Try to extract address from Ghidra function name (FUN_XXXXXXXX)."""
    m = re.match(r'FUN_([0-9a-fA-F]+)', func_name)
    if m:
        return int(m.group(1), 16)
    return 0


async def _call_mcp_json(
    mcp_manager: object, tool_name: str, args: Dict[str, Any],
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
        for block in result:
            if isinstance(block, dict) and block.get("type") == "text":
                return json.loads(block["text"])
    except (json.JSONDecodeError, KeyError):
        pass
    return None
