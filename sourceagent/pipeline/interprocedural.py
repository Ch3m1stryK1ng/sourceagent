"""Stage 2.5 — Inter-procedural constant propagation for HAL struct indirection.

Resolves MMIO accesses hidden behind HAL handle-struct patterns:
  Source:   huart->Instance->SR
  Ghidra:   *(*(param_1 + off1) + off2)

This pass runs after the MAI is built (Stage 2) and before miners (Stage 3).

Algorithm:
  1. Identify unresolved ARG-provenance accesses with double-deref patterns
  2. For each callee function, find callers via cross-references
  3. Decompile each caller, extract argument values at the callsite
  4. If argument is a known constant/global, compute resolved MMIO address
  5. Reclassify access with provenance INTERPROCEDURAL

Depth-1 only: looks one caller up. Deeply nested handle passing is future work.
"""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from .loader import is_mmio_address
from .models import MemoryAccess, MemoryAccessIndex

logger = logging.getLogger("sourceagent.pipeline.interprocedural")


# ── Data structures ───────────────────────────────────────────────────────


@dataclass
class HandleFieldAccess:
    """A double-deref pattern: *(*(param_N + struct_off) + reg_off)"""
    function_name: str
    function_addr: int
    param_index: int
    struct_offset: int   # offset into handle struct to get Instance ptr
    reg_offset: int      # offset into peripheral register block
    original_access_idx: int  # index into mai.accesses for replacement
    kind: str = "load"   # load or store
    width: int = 4
    in_isr: bool = False


@dataclass
class ArgBinding:
    """A resolved argument binding from caller to callee."""
    caller_func: str
    callee_func: str
    param_index: int
    bound_value: Optional[int]  # Resolved constant value
    provenance: str             # CONST, GLOBAL_PTR, etc.


@dataclass
class UnresolvedBinding:
    """Tracks an unresolved depth-1 binding where caller also received value as param."""
    callee_func: str
    caller_func: str
    param_index_in_caller: int  # Which param of the caller holds the value
    handle_access: HandleFieldAccess


# ── Regex patterns for double-deref detection ─────────────────────────────

# Pattern A: *(type *)(*(type *)(param_N + off1) + off2)
# e.g. *(volatile uint *)(*(int *)(param_1 + 0) + 0x18)
# Groups: 1=volatile?, 2=outer_type, 3=inner_volatile?, 4=inner_type,
#         5=param_idx, 6=struct_off (hex, optional), 7=reg_off (hex)
_RE_DOUBLE_DEREF = re.compile(
    r"\*\s*\(\s*(?:volatile\s+)?(\w+)\s*\*\s*\)"       # outer *(type *)
    r"\s*\(\s*"                                          # (
    r"\*\s*\(\s*(?:volatile\s+)?\w+\s*\*\s*\)"          # inner *(type *)
    r"\s*\(\s*param_(\d+)"                               # (param_N
    r"(?:\s*\+\s*(?:0x)?([0-9a-fA-F]+))?"               # + struct_off (optional)
    r"\s*\)"                                             # )
    r"\s*\+\s*(?:0x)?([0-9a-fA-F]+)"                    # + reg_off
    r"\s*\)"                                             # )
)

# Pattern B: *(type *)(*param_N + off) — simpler double-deref (Instance at offset 0)
# e.g. *(uint *)(*param_1 + 0x18)  or *(uint *)(*(int *)param_1 + 0x18)
_RE_DOUBLE_DEREF_SIMPLE = re.compile(
    r"\*\s*\(\s*(?:volatile\s+)?(\w+)\s*\*\s*\)"       # outer *(type *)
    r"\s*\(\s*"                                          # (
    r"\*\s*(?:\(\s*(?:volatile\s+)?\w+\s*\*\s*\)\s*)?"  # optional inner *(type *)
    r"param_(\d+)"                                       # param_N
    r"\s*\+\s*(?:0x)?([0-9a-fA-F]+)"                    # + reg_off
    r"\s*\)"                                             # )
)


# Pattern C: *(type *)(param_N + off) — single deref (param IS the peripheral base)
# e.g. *(volatile uint *)(param_1 + 0x44) = mask;
_RE_SINGLE_DEREF_PARAM = re.compile(
    r"\*\s*\(\s*(?:volatile\s+)?(\w+)\s*\*\s*\)"       # *(type *)
    r"\s*\(\s*param_(\d+)\s*\+\s*(?:0x)?([0-9a-fA-F]+)"  # (param_N + offset
    r"\s*\)"                                             # )
)


# ── Detection: scan decompiled C for double-deref patterns ────────────────


def detect_double_derefs(
    code: str,
    function_name: str,
    function_addr: int,
    access_indices: Dict[Tuple[str, int], List[int]],
) -> List[HandleFieldAccess]:
    """Scan decompiled C for double-deref patterns matching HAL struct access.

    Args:
        code: Decompiled C source
        function_name: Name of the function
        function_addr: Address of the function
        access_indices: Map from (function_name, param_index) to list of
            MAI access indices with provenance=ARG and target_addr=None

    Returns:
        List of HandleFieldAccess descriptors
    """
    results: List[HandleFieldAccess] = []

    for line in code.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("/*"):
            continue

        # Try Pattern A: full double-deref with struct offset
        for m in _RE_DOUBLE_DEREF.finditer(line):
            outer_type = m.group(1)
            param_idx = int(m.group(2))
            struct_off_str = m.group(3)
            reg_off_str = m.group(4)

            struct_off = int(struct_off_str, 16) if struct_off_str else 0
            reg_off = int(reg_off_str, 16)

            # Find matching unresolved access
            key = (function_name, param_idx)
            indices = access_indices.get(key, [])
            if not indices:
                continue

            from .memory_access_index import _classify_load_store, _width_from_type
            kinds = _classify_load_store(line, m.start())
            width = _width_from_type(outer_type)

            for kind in kinds:
                results.append(HandleFieldAccess(
                    function_name=function_name,
                    function_addr=function_addr,
                    param_index=param_idx,
                    struct_offset=struct_off,
                    reg_offset=reg_off,
                    original_access_idx=indices[0],  # first matching
                    kind=kind,
                    width=width,
                ))

        # Try Pattern B: simple double-deref (struct_offset = 0)
        for m in _RE_DOUBLE_DEREF_SIMPLE.finditer(line):
            # Skip if already matched by Pattern A on this line
            outer_type = m.group(1)
            param_idx = int(m.group(2))
            reg_off_str = m.group(3)
            reg_off = int(reg_off_str, 16)

            key = (function_name, param_idx)
            indices = access_indices.get(key, [])
            if not indices:
                continue

            from .memory_access_index import _classify_load_store, _width_from_type
            kinds = _classify_load_store(line, m.start())
            width = _width_from_type(outer_type)

            for kind in kinds:
                results.append(HandleFieldAccess(
                    function_name=function_name,
                    function_addr=function_addr,
                    param_index=param_idx,
                    struct_offset=0,
                    reg_offset=reg_off,
                    original_access_idx=indices[0],
                    kind=kind,
                    width=width,
                ))

    return results


def detect_single_derefs(
    code: str,
    function_name: str,
    function_addr: int,
    access_indices: Dict[Tuple[str, int], List[int]],
) -> List[HandleFieldAccess]:
    """Scan decompiled C for single-deref patterns: *(type *)(param_N + off).

    Unlike double-deref, param IS the peripheral base address directly (no
    Instance pointer indirection). Used by SAM3 PIO functions.

    Returns HandleFieldAccess with struct_offset=-1 sentinel to indicate
    that base_value + reg_offset should be used directly.
    """
    results: List[HandleFieldAccess] = []

    for line in code.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("/*"):
            continue

        for m in _RE_SINGLE_DEREF_PARAM.finditer(line):
            outer_type = m.group(1)
            param_idx = int(m.group(2))
            reg_off_str = m.group(3)
            reg_off = int(reg_off_str, 16)

            key = (function_name, param_idx)
            indices = access_indices.get(key, [])
            if not indices:
                continue

            from .memory_access_index import _classify_load_store, _width_from_type
            kinds = _classify_load_store(line, m.start())
            width = _width_from_type(outer_type)

            for kind in kinds:
                results.append(HandleFieldAccess(
                    function_name=function_name,
                    function_addr=function_addr,
                    param_index=param_idx,
                    struct_offset=-1,  # Sentinel: param IS the base
                    reg_offset=reg_off,
                    original_access_idx=indices[0],
                    kind=kind,
                    width=width,
                ))

    return results


def _get_raw_arg_expr(
    caller_code: str,
    callee_name: str,
    param_index: int,
) -> Optional[str]:
    """Extract the raw argument expression at a callsite for a given param index.

    Ghidra param_1 = first arg (callsite index 0).
    Returns the raw text of the argument, or None.
    """
    pattern = re.escape(callee_name) + r'\s*\('
    for line in caller_code.splitlines():
        m_call = re.search(pattern, line)
        if not m_call:
            continue

        start = m_call.end()
        depth = 1
        i = start
        while i < len(line) and depth > 0:
            if line[i] == '(':
                depth += 1
            elif line[i] == ')':
                depth -= 1
            i += 1
        if depth != 0:
            continue

        args_str = line[start:i - 1]
        args = _split_args(args_str)
        # Ghidra param_1 → callsite_idx 0
        callsite_idx = param_index - 1
        if 0 <= callsite_idx < len(args):
            return args[callsite_idx].strip()
        break

    return None


# ── Callsite argument extraction ──────────────────────────────────────────


# Match: callee_name(arg0, arg1, ...)
def _extract_arg_bindings(
    caller_code: str,
    callee_name: str,
) -> Dict[int, ArgBinding]:
    """Extract argument values from callsite in caller's decompiled C.

    Handles:
      - Constant: 0x40011000 → CONST
      - DAT_ reference: DAT_20000100 → GLOBAL_PTR (address of the DAT label)
      - Address-of global: &huart1 → look for huart1 symbol
      - Type-cast wrapping: (TYPE *)expr → unwrap and recurse
    """
    # Find the call: callee_name(expr0, expr1, ...)
    pattern = re.escape(callee_name) + r'\s*\('
    bindings: Dict[int, ArgBinding] = {}

    for line in caller_code.splitlines():
        m = re.search(pattern, line)
        if not m:
            continue

        # Extract argument list
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
            continue

        args_str = line[start:i - 1]
        args = _split_args(args_str)

        for idx, arg_expr in enumerate(args):
            value, prov = _resolve_arg_expr(arg_expr.strip())
            bindings[idx] = ArgBinding(
                caller_func="",  # filled later
                callee_func=callee_name,
                param_index=idx,
                bound_value=value,
                provenance=prov,
            )
        break  # take first callsite

    return bindings


def _split_args(args_str: str) -> List[str]:
    """Split comma-separated arguments respecting nested parens."""
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


def _resolve_arg_expr(expr: str) -> Tuple[Optional[int], str]:
    """Resolve an argument expression to a constant value if possible.

    Returns (value, provenance).
    """
    expr = expr.strip()

    # Strip type cast: (TYPE *)expr
    cast_m = re.match(r'\(\s*\w+\s*\*?\s*\)\s*(.+)', expr)
    if cast_m:
        return _resolve_arg_expr(cast_m.group(1))

    # Hex constant: 0x40011000
    hex_m = re.fullmatch(r'0x([0-9a-fA-F]+)', expr)
    if hex_m:
        return int(hex_m.group(1), 16), "CONST"

    # Decimal constant
    dec_m = re.fullmatch(r'(\d+)', expr)
    if dec_m:
        return int(dec_m.group(1)), "CONST"

    # DAT_ label: DAT_20000100 or _DAT_20000100
    dat_m = re.fullmatch(r'_?DAT_([0-9a-fA-F]+)', expr)
    if dat_m:
        return int(dat_m.group(1), 16), "GLOBAL_PTR"

    # Address-of global: &symbol_name
    addr_of_m = re.fullmatch(r'&([a-zA-Z_]\w*)', expr)
    if addr_of_m:
        # Can't resolve without symbol table; mark as needing lookup
        return None, "ADDR_OF:" + addr_of_m.group(1)

    # param_N — propagation from outer caller, can't resolve at depth-1
    if re.match(r'param_\d+', expr):
        return None, "ARG"

    return None, "UNKNOWN"


# ── Peripheral address check ─────────────────────────────────────────────


def _is_peripheral_address(addr: int) -> bool:
    """Check if address falls in MMIO or system peripheral range."""
    return is_mmio_address(addr) or (0xE0000000 <= addr <= 0xFFFFFFFF)


# ── MCP helpers ──────────────────────────────────────────────────────────


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


async def _get_callers(
    mcp_manager: object,
    binary_name: str,
    func_addr_hex: str,
) -> List[str]:
    """Get caller function names via cross-references."""
    resp = await _call_mcp_json(mcp_manager, "list_cross_references", {
        "binary_name": binary_name,
        "name_or_address": func_addr_hex,
    })
    if resp is None:
        return []

    callers: List[str] = []
    for ref in resp.get("references", []):
        ref_type = ref.get("type", "")
        func_name = ref.get("function_name", "")
        if func_name and ("CALL" in ref_type or not ref_type):
            if func_name not in callers:
                callers.append(func_name)
    return callers


async def _decompile(
    mcp_manager: object,
    binary_name: str,
    func_name: str,
) -> Optional[str]:
    """Decompile a function and return its code."""
    resp = await _call_mcp_json(mcp_manager, "decompile_function", {
        "binary_name": binary_name,
        "name_or_address": func_name,
    })
    if resp is None:
        return None
    return resp.get("decompiled_code", "") or resp.get("code", "")


async def _read_word(
    mcp_manager: object,
    binary_name: str,
    address: int,
) -> Optional[int]:
    """Read a 4-byte word from the binary at the given address."""
    resp = await _call_mcp_json(mcp_manager, "read_bytes", {
        "binary_name": binary_name,
        "address": f"0x{address:x}",
        "length": 4,
    })
    if resp is None:
        return None

    # Parse bytes from response
    byte_values = resp.get("bytes", [])
    if len(byte_values) < 4:
        # Try hex string format
        hex_str = resp.get("hex", "")
        if len(hex_str) >= 8:
            try:
                return int.from_bytes(bytes.fromhex(hex_str[:8]), "little")
            except ValueError:
                pass
        return None

    # Little-endian 32-bit
    try:
        return (byte_values[0] | (byte_values[1] << 8) |
                (byte_values[2] << 16) | (byte_values[3] << 24))
    except (IndexError, TypeError):
        return None


async def _resolve_symbol_address(
    mcp_manager: object,
    binary_name: str,
    symbol_name: str,
) -> Optional[int]:
    """Resolve a symbol name to its address via Ghidra."""
    resp = await _call_mcp_json(mcp_manager, "search_symbols_by_name", {
        "binary_name": binary_name,
        "query": symbol_name,
        "limit": 10,
    })
    if resp is None:
        return None

    for sym in resp.get("symbols", []):
        name = sym.get("name", "")
        addr_str = sym.get("address", "")
        if name == symbol_name and not str(addr_str).startswith("EXTERNAL"):
            try:
                return int(addr_str, 16)
            except (ValueError, TypeError):
                continue
    return None


# ── Main resolution pass ─────────────────────────────────────────────────


async def resolve_interprocedural(
    mai: MemoryAccessIndex,
    mcp_manager: object,
    binary_name: str,
) -> MemoryAccessIndex:
    """Stage 2.5: Resolve ARG-provenance accesses via caller-side analysis.

    For functions with unresolved parameter-derived MMIO accesses (double-deref
    and single-deref patterns), finds callers, extracts argument values, and
    resolves the final MMIO target address.

    Supports depth-1 (caller → callee) and depth-2 (grandparent → caller → callee)
    resolution for deeply wrapped HAL functions (P4).

    Args:
        mai: MemoryAccessIndex from Stage 2
        mcp_manager: MCPManager for Ghidra tool calls
        binary_name: Ghidra binary name

    Returns:
        Updated MemoryAccessIndex with INTERPROCEDURAL-resolved accesses
    """
    if mcp_manager is None:
        return mai

    # Step 1: Collect unresolved ARG accesses
    # Build map: (function_name, param_index) → list of access indices
    arg_access_map: Dict[Tuple[str, int], List[int]] = defaultdict(list)
    unresolved_funcs: Set[str] = set()

    for i, acc in enumerate(mai.accesses):
        if acc.base_provenance == "ARG" and acc.target_addr is None:
            unresolved_funcs.add(acc.function_name)
            for param_idx in range(10):  # reasonable max params
                arg_access_map[(acc.function_name, param_idx)].append(i)

    if not unresolved_funcs:
        logger.debug("No unresolved ARG accesses — skipping interprocedural pass")
        return mai

    logger.info(
        "Stage 2.5: %d functions with unresolved ARG accesses: %s",
        len(unresolved_funcs), sorted(unresolved_funcs),
    )

    # Step 2: For each function, decompile and detect deref patterns
    new_accesses: List[MemoryAccess] = []
    resolved_indices: Set[int] = set()
    unresolved_bindings: List[UnresolvedBinding] = []

    for func_name in unresolved_funcs:
        # Get function address from first matching access
        func_addr = 0
        for i, acc in enumerate(mai.accesses):
            if acc.function_name == func_name:
                func_addr = acc.function_addr
                break

        if not func_addr:
            continue

        # Decompile the callee
        callee_code = await _decompile(mcp_manager, binary_name, func_name)
        if not callee_code:
            logger.debug("Stage 2.5: Could not decompile %s", func_name)
            continue

        # Log lines containing param_ for debugging
        param_lines = [l.strip() for l in callee_code.splitlines()
                       if 'param_' in l and ('*' in l or '+' in l)]
        if param_lines:
            logger.debug(
                "Stage 2.5: %s has %d param-deref lines, e.g.: %s",
                func_name, len(param_lines),
                param_lines[0][:120],
            )

        # Detect double-deref patterns
        handle_accesses = detect_double_derefs(
            callee_code, func_name, func_addr, arg_access_map,
        )

        # Also detect single-deref patterns (P4): *(type *)(param_N + off)
        single_accesses = detect_single_derefs(
            callee_code, func_name, func_addr, arg_access_map,
        )

        all_accesses = handle_accesses + single_accesses
        if not all_accesses:
            logger.debug("Stage 2.5: No deref patterns in %s", func_name)
            continue

        logger.debug(
            "Found %d deref patterns in %s (%d double, %d single)",
            len(all_accesses), func_name,
            len(handle_accesses), len(single_accesses),
        )

        # Step 3: Find callers via xrefs
        func_addr_hex = f"0x{func_addr:x}"
        callers = await _get_callers(mcp_manager, binary_name, func_addr_hex)

        if not callers:
            logger.debug("No callers found for %s", func_name)
            continue

        # Step 4: For each caller, extract argument values and resolve
        for caller_name in callers:
            caller_code = await _decompile(mcp_manager, binary_name, caller_name)
            if not caller_code:
                continue

            bindings = _extract_arg_bindings(caller_code, func_name)
            if not bindings:
                continue

            for ha in all_accesses:
                # Ghidra param_1 = first arg (callsite index 0)
                callsite_idx = ha.param_index - 1
                binding = bindings.get(callsite_idx)
                if binding is None:
                    continue

                base_value = binding.bound_value

                # If binding is an &symbol, try to resolve the symbol address
                if base_value is None and binding.provenance.startswith("ADDR_OF:"):
                    sym_name = binding.provenance.split(":", 1)[1]
                    base_value = await _resolve_symbol_address(
                        mcp_manager, binary_name, sym_name,
                    )

                # If binding is ARG (caller also received as param), track for depth-2
                if base_value is None and binding.provenance == "ARG":
                    # Extract which param of the caller holds this value
                    raw_expr = _get_raw_arg_expr(caller_code, func_name, ha.param_index)
                    if raw_expr:
                        param_m = re.match(r'param_(\d+)', raw_expr.strip())
                        if param_m:
                            unresolved_bindings.append(UnresolvedBinding(
                                callee_func=func_name,
                                caller_func=caller_name,
                                param_index_in_caller=int(param_m.group(1)),
                                handle_access=ha,
                            ))
                    continue

                if base_value is None:
                    continue

                # Resolve the target address
                target = await _resolve_handle_access(
                    mcp_manager, binary_name, callee_code,
                    ha, base_value,
                )
                if target is None:
                    continue

                orig_in_isr = mai.accesses[ha.original_access_idx].in_isr
                new_accesses.append(MemoryAccess(
                    address=func_addr,
                    kind=ha.kind,
                    width=ha.width,
                    target_addr=target,
                    base_provenance="INTERPROCEDURAL",
                    function_name=func_name,
                    function_addr=func_addr,
                    in_isr=orig_in_isr,
                ))
                resolved_indices.add(ha.original_access_idx)

                logger.info(
                    "Resolved (depth-1): %s param_%d via %s → 0x%08x",
                    func_name, ha.param_index, caller_name, target,
                )

    # ── Depth-2 resolution (P4) ─────────────────────────────────────────
    if unresolved_bindings:
        depth2_accesses = await _resolve_depth2(
            mcp_manager, binary_name, mai, unresolved_bindings,
        )
        new_accesses.extend(depth2_accesses)

    if not new_accesses:
        logger.info("Stage 2.5: No accesses resolved")
        return mai

    # Step 5: Add new resolved accesses to MAI
    mai.accesses.extend(new_accesses)

    # Rebuild mmio_accesses
    mai.mmio_accesses = [
        a for a in mai.accesses
        if a.target_addr is not None and _is_peripheral_address(a.target_addr)
    ]

    logger.info(
        "Stage 2.5: Resolved %d accesses via interprocedural analysis "
        "(MAI now: %d total, %d MMIO)",
        len(new_accesses), len(mai.accesses), len(mai.mmio_accesses),
    )

    return mai


async def _resolve_handle_access(
    mcp_manager: object,
    binary_name: str,
    callee_code: str,
    ha: HandleFieldAccess,
    base_value: int,
) -> Optional[int]:
    """Resolve a HandleFieldAccess to its final MMIO target address.

    For double-deref (struct_offset >= 0): reads Instance pointer and adds reg_offset.
    For single-deref (struct_offset == -1): uses base_value + reg_offset directly.
    """
    if ha.struct_offset == -1:
        # Single-deref: param IS the peripheral base
        target = base_value + ha.reg_offset
        if _is_peripheral_address(target):
            return target
        return None

    # Double-deref: read the Instance pointer
    instance_ptr = await _read_word(
        mcp_manager, binary_name,
        base_value + ha.struct_offset,
    )

    if instance_ptr is None:
        # Fallback: scan callee code for direct assignment
        instance_ptr = _scan_init_assignment(
            callee_code, ha.param_index, ha.struct_offset,
        )

    if instance_ptr is None or not _is_peripheral_address(instance_ptr):
        return None

    target = instance_ptr + ha.reg_offset
    if not _is_peripheral_address(target):
        return None

    return target


async def _resolve_depth2(
    mcp_manager: object,
    binary_name: str,
    mai: MemoryAccessIndex,
    unresolved: List[UnresolvedBinding],
) -> List[MemoryAccess]:
    """Depth-2 resolution: for bindings where caller received value as param,
    look one more level up (grandparent callers).

    Budget cap: process at most 20 unique callers.
    """
    new_accesses: List[MemoryAccess] = []

    # Group by caller function
    by_caller: Dict[str, List[UnresolvedBinding]] = defaultdict(list)
    for ub in unresolved:
        by_caller[ub.caller_func].append(ub)

    # Cap at 20 callers to bound MCP budget
    callers_to_process = list(by_caller.keys())[:20]

    logger.info(
        "Stage 2.5 depth-2: %d unresolved bindings across %d callers (processing %d)",
        len(unresolved), len(by_caller), len(callers_to_process),
    )

    for caller_func in callers_to_process:
        bindings_for_caller = by_caller[caller_func]

        # Get caller's address for xref lookup
        caller_addr = 0
        for acc in mai.accesses:
            if acc.function_name == caller_func:
                caller_addr = acc.function_addr
                break
        if not caller_addr:
            # Try to extract from function name
            m = re.match(r'FUN_([0-9a-fA-F]+)', caller_func)
            if m:
                caller_addr = int(m.group(1), 16)
        if not caller_addr:
            continue

        # Find grandparent callers via xrefs (cap at 5 per caller)
        caller_addr_hex = f"0x{caller_addr:x}"
        grandparents = await _get_callers(mcp_manager, binary_name, caller_addr_hex)
        grandparents = grandparents[:5]

        if not grandparents:
            continue

        for gp_name in grandparents:
            gp_code = await _decompile(mcp_manager, binary_name, gp_name)
            if not gp_code:
                continue

            gp_bindings = _extract_arg_bindings(gp_code, caller_func)
            if not gp_bindings:
                continue

            for ub in bindings_for_caller:
                # Grandparent's callsite_idx for the caller's param
                gp_callsite_idx = ub.param_index_in_caller - 1
                gp_binding = gp_bindings.get(gp_callsite_idx)
                if gp_binding is None:
                    continue

                base_value = gp_binding.bound_value

                # If binding is &symbol, resolve it
                if base_value is None and gp_binding.provenance.startswith("ADDR_OF:"):
                    sym_name = gp_binding.provenance.split(":", 1)[1]
                    base_value = await _resolve_symbol_address(
                        mcp_manager, binary_name, sym_name,
                    )

                if base_value is None:
                    continue

                ha = ub.handle_access

                # For single-deref: base_value + reg_offset directly
                if ha.struct_offset == -1:
                    target = base_value + ha.reg_offset
                    if not _is_peripheral_address(target):
                        continue
                else:
                    # For double-deref: read Instance pointer
                    instance_ptr = await _read_word(
                        mcp_manager, binary_name,
                        base_value + ha.struct_offset,
                    )
                    if instance_ptr is None or not _is_peripheral_address(instance_ptr):
                        continue
                    target = instance_ptr + ha.reg_offset
                    if not _is_peripheral_address(target):
                        continue

                orig_in_isr = mai.accesses[ha.original_access_idx].in_isr
                new_accesses.append(MemoryAccess(
                    address=ha.function_addr,
                    kind=ha.kind,
                    width=ha.width,
                    target_addr=target,
                    base_provenance="INTERPROCEDURAL",
                    function_name=ha.function_name,
                    function_addr=ha.function_addr,
                    in_isr=orig_in_isr,
                ))

                logger.info(
                    "Resolved (depth-2): %s param_%d via %s → %s → 0x%08x",
                    ha.function_name, ha.param_index,
                    gp_name, ub.caller_func, target,
                )

    return new_accesses


def _scan_init_assignment(
    code: str,
    param_index: int,
    struct_offset: int,
) -> Optional[int]:
    """Scan decompiled C for direct assignment to param struct field.

    Looks for patterns like:
      *(param_1 + 0) = 0x40011000;   (struct_offset = 0)
      *param_1 = 0x40011000;          (struct_offset = 0)
      *(param_1) = 0x40011000;        (struct_offset = 0)
    """
    param_name = f"param_{param_index}"

    if struct_offset == 0:
        # Match: *(param_N) = 0xHEX or *param_N = 0xHEX
        patterns = [
            re.compile(
                r"\*\s*(?:\(\s*\w+\s*\*\s*\)\s*)?"
                + re.escape(param_name)
                + r"\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?0x([0-9a-fA-F]+)\s*;"
            ),
            re.compile(
                r"\*\s*\(\s*(?:\w+\s*\*\s*\)\s*\(\s*)?"
                + re.escape(param_name)
                + r"(?:\s*\+\s*0(?:x0)?)?\s*\)\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?0x([0-9a-fA-F]+)\s*;"
            ),
        ]
    else:
        # Match: *(param_N + off) = 0xHEX
        off_hex = f"{struct_offset:x}"
        patterns = [
            re.compile(
                r"\*\s*\(\s*(?:\w+\s*\*\s*\)\s*\(\s*)?"
                + re.escape(param_name)
                + r"\s*\+\s*(?:0x)?" + off_hex
                + r"\s*\)\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?0x([0-9a-fA-F]+)\s*;"
            ),
        ]

    for line in code.splitlines():
        for pat in patterns:
            m = pat.search(line)
            if m:
                try:
                    return int(m.group(1), 16)
                except (ValueError, IndexError):
                    continue

    return None
