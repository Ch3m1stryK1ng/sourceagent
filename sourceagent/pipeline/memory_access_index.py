"""Stage 2 — MemoryAccessIndex builder using Ghidra decompiled C via MCP (M2).

For each function in the binary:
  1. Enumerate functions via search_symbols_by_name MCP tool (paginated)
  2. Decompile via decompile_function MCP tool
  3. Parse pointer dereferences from Ghidra pseudo-C with regex
  4. Classify target address (MMIO/SRAM/flash) and base provenance
  5. Mark functions reachable from vector table ISR entries

Since Ghidra MCP has no direct p-code tool, we parse decompiled pseudo-C from
decompile_function to extract memory access patterns. This is practical for
Cortex-M firmware where MMIO accesses use constant addresses that Ghidra
preserves in decompiled output.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .loader import is_flash_address, is_mmio_address, is_sram_address
from .models import MemoryAccess, MemoryAccessIndex, MemoryMap
from .peripheral_types import (
    ALL_BASE_ADDRESSES,
    ALL_STRUCT_OFFSETS,
    HANDLE_TO_PERIPHERAL,
    _normalize_type_name,
    get_field_offset,
    get_register_address,
    resolve_handle_type,
)

logger = logging.getLogger("sourceagent.pipeline.memory_access_index")

# ── Type-width map ──────────────────────────────────────────────────────────

_TYPE_WIDTH: Dict[str, int] = {
    "uint": 4,
    "int": 4,
    "undefined4": 4,
    "ulong": 4,
    "long": 4,
    "dword": 4,
    "ushort": 2,
    "short": 2,
    "undefined2": 2,
    "word": 2,
    "byte": 1,
    "char": 1,
    "undefined": 1,
    "uchar": 1,
    "undefined1": 1,
}

# Default width when type is unknown
_DEFAULT_WIDTH = 4

# ── Regex patterns for Ghidra ARM Cortex-M decompiled C ────────────────────

# Pattern 1: *(type *)0xHEX  — constant address dereference
_RE_CONST_DEREF = re.compile(
    r"\*\s*\(\s*(volatile\s+)?(\w+)\s*\*\s*\)\s*0x([0-9a-fA-F]+)"
)

# Pattern 2: *(type *)DAT_HEX or _DAT_HEX — Ghidra DAT label (resolved constant)
# Ghidra may use either DAT_ or _DAT_ prefix for global data labels
_RE_DAT_DEREF = re.compile(
    r"\*\s*\(\s*(volatile\s+)?(\w+)\s*\*\s*\)\s*_?DAT_([0-9a-fA-F]+)"
)

# Pattern 2b: _DAT_HEX bare access (no cast/deref) — Ghidra global at MMIO address
# e.g. `_DAT_40021004 & 0xc` or `_DAT_40021004 >> 0x12`
_RE_DAT_BARE = re.compile(
    r"(?<!\w)_?DAT_([0-9a-fA-F]{8})(?!\w)"
)

# Pattern 3: *(type *)(0xHEX + ...) — constant base with offset
_RE_CONST_OFFSET = re.compile(
    r"\*\s*\(\s*(volatile\s+)?(\w+)\s*\*\s*\)\s*\(\s*0x([0-9a-fA-F]+)\s*\+"
)

# Pattern 3b: *(type *)(... + 0xHEX) — variable + constant MMIO offset
# e.g. *(uint *)(uVar3 + 0xe000ed1c) or *((param_1 & mask) + 0xe000e400)
# Uses .*? instead of [^)]* to handle nested parentheses in expressions like
# *(int *)((pin & 0xfffffff0) + 0x10) where inner ')' breaks [^)]*
_RE_VAR_PLUS_CONST = re.compile(
    r"\*\s*\(\s*(volatile\s+)?(\w+)\s*\*\s*\)\s*\(.*?\+\s*0x([0-9a-fA-F]+)\s*\)"
)

# Pattern 3d: *(type *)(... + DECIMAL) — variable + decimal constant
# Ghidra sometimes emits decimal constants: *(uint *)(uVar1 + 1073809416) instead of 0x hex.
# Only emits when the decimal value is >= 0x40000000 (MMIO address range).
_RE_VAR_PLUS_DEC = re.compile(
    r"\*\s*\(\s*(volatile\s+)?(\w+)\s*\*\s*\)\s*\(.*?\+\s*(\d+)\s*\)"
)

# Pattern 4: *(type *)(DAT_HEX + ...) — global pointer with offset
_RE_GLOBAL_OFFSET = re.compile(
    r"\*\s*\(\s*(volatile\s+)?(\w+)\s*\*\s*\)\s*\(\s*_?DAT_([0-9a-fA-F]+)\s*\+"
)

# Pattern 5: *(type *)(param_N ...) — function argument dereference
# Uses .*? instead of [^)]* to handle double-deref patterns like
# *(int *)(*(int *)param_1 + 0xc) where inner ')' breaks [^)]*
_RE_ARG_DEREF = re.compile(
    r"\*\s*\(\s*(volatile\s+)?(\w+)\s*\*\s*\)\s*\(?.*?param_\d+"
)

# Pattern 6: *(type *)(&local_...) — stack pointer dereference
_RE_STACK_DEREF = re.compile(
    r"\*\s*\(\s*(volatile\s+)?(\w+)\s*\*\s*\)\s*\(\s*&local_"
)

# Pattern 7: *localVar / *(type *)puVarN — unknown pointer dereference
_RE_UNKNOWN_DEREF = re.compile(
    r"\*\s*\(\s*(volatile\s+)?(\w+)\s*\*\s*\)\s*(\w+)"
)

# Pattern 8: symbolic_global[index] — array access via named global variable.
# Matches: g_rx_buf[expr], g_dma_buf[0], etc.
# Captures the symbol name only; address resolved via global_symbol_table.
_RE_GLOBAL_ARRAY = re.compile(
    r"(?<!\w)([a-zA-Z_]\w*)\s*\[([^\]]+)\]"
)

# Pattern 9: *(symbolic_global + offset) — pointer arithmetic with named global.
# Matches: *(g_rx_buf + 4), *(some_buffer + uVar1), etc.
_RE_GLOBAL_PTR_ARITH = re.compile(
    r"\*\s*\(\s*(volatile\s+)?(\w+)\s*\*\s*\)\s*\(\s*([a-zA-Z_]\w*)\s*[+\-]"
)


# Pattern 10: (TypeName *)0xHEX — typed MMIO base pointer cast
# Matches comparisons (if ptr == (TYPE *)0x...) and assignments (var = (TYPE *)0x...)
# Captures: (1) type_name, (2) hex_addr
# Broad regex: matches any (Word *)0xHEX, then filters in _extract_typed_mmio_bases()
# to only accept types in ALL_STRUCT_OFFSETS (STM32 _TypeDef, SAM3 Uart, K64F UART_Type).
_RE_TYPED_CAST_GENERIC = re.compile(
    r"\(\s*(\w+)\s*\*\s*\)\s*0x([0-9a-fA-F]+)"
)
# Keep the old pattern name as an alias for backward compatibility in tests
_RE_TYPED_MMIO_CAST = _RE_TYPED_CAST_GENERIC

# Pattern 11a: handle->Instance->FIELD — struct field access through HAL handle
# Captures: (1) variable name, (2) field name
_RE_HANDLE_INSTANCE_FIELD = re.compile(
    r"(\w+)->Instance->(\w+)"
)

# Pattern 11b: var->FIELD — direct peripheral struct field access
# Used for local vars declared as XXX_TypeDef *var or params of peripheral type
# Captures: (1) variable name, (2) field name
_RE_PERIPH_FIELD = re.compile(
    r"(\w+)->(\w+)"
)

# Pattern for extracting function parameter declarations:
# TYPE *name  e.g.  UART_HandleTypeDef *huart
_RE_PARAM_DECL = re.compile(
    r"(\w+)\s+\*\s*(\w+)"
)

# Pattern for local variable declarations of peripheral pointer type:
# TYPE *varname;  e.g.  I2C_TypeDef *pIVar2;  or  Uart *pUVar3;
# Broad regex: matches any TYPE *varname;, then filters to types in ALL_STRUCT_OFFSETS.
_RE_LOCAL_PERIPH_DECL = re.compile(
    r"^\s*(\w+)\s+\*\s*(\w+)\s*;",
    re.MULTILINE,
)


# ── Intra-procedural base propagation patterns ────────────────────────────

# Pattern for base assignment: var = ...0xHEX...;
# Matches lines like:  uVar3 = (pin & 0xf) + 0x40010800;
#                       uVar1 = 0x40005400;
# Captures: (1) variable name, (2) hex constant
_RE_BASE_ASSIGN = re.compile(
    r"(\w+)\s*=\s*.*?0x([0-9a-fA-F]+)\s*;"
)

# Pattern for small-offset dereference: *(type *)(varname + offset)
# Matches: *(uint *)(uVar3 + 0x10) or *(int *)(uVar1 + 8)
# Captures: (1) volatile?, (2) type, (3) varname, (4) offset (hex or decimal)
_RE_SMALL_OFFSET_DEREF = re.compile(
    r"\*\s*\(\s*(volatile\s+)?(\w+)\s*\*\s*\)\s*\(\s*(\w+)\s*\+\s*(?:0x)?([0-9a-fA-F]+)\s*\)"
)


# ── Address classification ──────────────────────────────────────────────────


def _is_peripheral_address(addr: int) -> bool:
    """Check if address falls in MMIO or system peripheral range (0xE0000000+)."""
    return is_mmio_address(addr) or (0xE0000000 <= addr <= 0xFFFFFFFF)


# ── Load/store classification ───────────────────────────────────────────────


def _classify_load_store(line: str, match_start: int) -> List[str]:
    """Determine if a matched dereference is a load, store, or both.

    Rules:
    - LHS of `=` (but not `==`, `!=`, `<=`, `>=`) → store
    - Compound assignment (`|=`, `&=`, `+=`, `-=`, `^=`, `<<=`, `>>=`) → both
    - RHS of `=`, in function args, or no `=` at all → load
    """
    # Find the assignment operator on the line
    # We need to look at the context around the match
    # Strategy: find all '=' that are actual assignments (not ==, !=, <=, >=)

    # First, check if match is on LHS of an assignment
    # Look for '=' after the match, but skip ==, !=, <=, >=
    after = line[match_start:]

    # Find the position of the first non-comparison '=' in the whole line
    i = 0
    eq_pos = None
    while i < len(line):
        ch = line[i]
        if ch in ('"', "'"):
            # Skip string literals
            quote = ch
            i += 1
            while i < len(line) and line[i] != quote:
                if line[i] == '\\':
                    i += 1
                i += 1
            i += 1
            continue
        if ch == '=' and i + 1 < len(line) and line[i + 1] == '=':
            i += 2  # skip ==
            continue
        if ch == '!' and i + 1 < len(line) and line[i + 1] == '=':
            i += 2  # skip !=
            continue
        if ch == '<' and i + 1 < len(line) and line[i + 1] == '=':
            i += 2  # skip <=
            continue
        if ch == '>' and i + 1 < len(line) and line[i + 1] == '=':
            i += 2  # skip >=
            continue
        # Compound assignments: |=, &=, +=, -=, ^=, <<=, >>=
        if ch in ('|', '&', '+', '-', '^') and i + 1 < len(line) and line[i + 1] == '=':
            eq_pos = i
            # Match is on LHS if it starts before this compound assignment
            if match_start < eq_pos:
                return ["load", "store"]  # read-modify-write
            else:
                return ["load"]  # On RHS
        if ch == '<' and i + 1 < len(line) and line[i + 1] == '<' and i + 2 < len(line) and line[i + 2] == '=':
            eq_pos = i
            if match_start < eq_pos:
                return ["load", "store"]
            else:
                return ["load"]
        if ch == '>' and i + 1 < len(line) and line[i + 1] == '>' and i + 2 < len(line) and line[i + 2] == '=':
            eq_pos = i
            if match_start < eq_pos:
                return ["load", "store"]
            else:
                return ["load"]
        if ch == '=':
            eq_pos = i
            break
        i += 1

    if eq_pos is None:
        # No assignment on this line → load (e.g., function arg, return, condition)
        return ["load"]

    if match_start < eq_pos:
        return ["store"]
    else:
        return ["load"]


# ── Width extraction ────────────────────────────────────────────────────────


def _width_from_type(type_str: str) -> int:
    """Get byte width from a Ghidra C type string."""
    return _TYPE_WIDTH.get(type_str, _DEFAULT_WIDTH)


# ── Decompiled C parser (pure function, no MCP) ────────────────────────────


def parse_memory_accesses(
    code: str,
    function_name: str,
    function_addr: int,
    global_symbol_table: Optional[Dict[str, int]] = None,
) -> List[MemoryAccess]:
    """Extract memory access patterns from Ghidra decompiled pseudo-C.

    Pure function — no MCP calls. Processes regex patterns in priority order
    with span dedup to avoid double-counting overlapping matches.

    Args:
        code: Decompiled C source from Ghidra
        function_name: Name of the function being analyzed
        function_addr: Address of the function
        global_symbol_table: Optional {symbol_name: address} for resolving
            symbolic global variable references (e.g. g_rx_buf → 0x20000008)

    Returns:
        List of MemoryAccess instances found in the code
    """
    accesses: List[MemoryAccess] = []
    seen_spans: set = set()  # (line_idx, match_start, match_end) for dedup

    for line_idx, line in enumerate(code.splitlines()):
        # Skip comments and preprocessor directives
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("/*"):
            continue

        # Process patterns in priority order (most specific first)
        _extract_from_line(
            line, line_idx, function_name, function_addr,
            accesses, seen_spans,
        )

        # Process symbolic global variable accesses (array indexing and ptr arith)
        if global_symbol_table:
            _extract_global_symbol_accesses(
                line, line_idx, function_name, function_addr,
                accesses, seen_spans, global_symbol_table,
            )

    # Second pass: intra-procedural base propagation
    # Resolve *(type *)(var + small_offset) where var was assigned an MMIO base.
    # Uses a separate span set because the first pass may have consumed the span
    # with a non-MMIO target (e.g. *(uint *)(uVar1 + 0x14) → target=0x14).
    base_map = _extract_base_assignments(code)
    if base_map:
        intra_seen: set = set()
        intra_resolved = _resolve_small_offset_derefs(
            code, base_map, function_name, function_addr, intra_seen,
        )
        accesses.extend(intra_resolved)

    return accesses


def _extract_from_line(
    line: str,
    line_idx: int,
    function_name: str,
    function_addr: int,
    accesses: List[MemoryAccess],
    seen_spans: set,
) -> None:
    """Extract all memory access patterns from a single line."""

    # Ordered by specificity: const_offset before const_deref (more specific first),
    # global_offset before dat_deref, etc.
    # Tuple: (regex, provenance, target_group_index_or_None, has_type_groups)
    patterns = [
        # Cast-based patterns: groups = (volatile?, type, hex_addr)
        (_RE_CONST_OFFSET, "CONST", 3, True),
        (_RE_VAR_PLUS_CONST, "CONST", 3, True),
        (_RE_GLOBAL_OFFSET, "GLOBAL_PTR", 3, True),
        (_RE_CONST_DEREF, "CONST", 3, True),
        (_RE_DAT_DEREF, "CONST", 3, True),
        (_RE_ARG_DEREF, "ARG", None, True),
        (_RE_STACK_DEREF, "STACK_PTR", None, True),
    ]

    for regex, provenance, target_group, has_type in patterns:
        for m in regex.finditer(line):
            span_key = (line_idx, m.start(), m.end())
            if span_key in seen_spans:
                continue

            # Check for overlap with already-seen spans on same line
            if _overlaps(seen_spans, line_idx, m.start(), m.end()):
                continue

            seen_spans.add(span_key)

            if has_type:
                type_str = m.group(2)
                width = _width_from_type(type_str)
            else:
                width = _DEFAULT_WIDTH

            target_addr = None
            if target_group and m.lastindex >= target_group:
                target_addr = _target_from_hex(m.group(target_group))

            kinds = _classify_load_store(line, m.start())

            for kind in kinds:
                accesses.append(MemoryAccess(
                    address=function_addr,
                    kind=kind,
                    width=width,
                    target_addr=target_addr,
                    base_provenance=provenance,
                    function_name=function_name,
                    function_addr=function_addr,
                ))

    # Pattern 2b: _DAT_HEX bare access (no cast) — Ghidra global at MMIO addr
    # Must run after cast-based patterns to avoid duplicates
    for m in _RE_DAT_BARE.finditer(line):
        span_key = (line_idx, m.start(), m.end())
        if span_key in seen_spans:
            continue
        if _overlaps(seen_spans, line_idx, m.start(), m.end()):
            continue
        seen_spans.add(span_key)

        target_addr = _target_from_hex(m.group(1))
        kinds = _classify_load_store(line, m.start())

        for kind in kinds:
            accesses.append(MemoryAccess(
                address=function_addr,
                kind=kind,
                width=_DEFAULT_WIDTH,
                target_addr=target_addr,
                base_provenance="CONST",
                function_name=function_name,
                function_addr=function_addr,
            ))

    # Pattern 3d: *(type *)(... + DECIMAL) — decimal constant that may be MMIO
    # Must run after hex patterns to avoid double-matching (hex patterns take priority)
    for m in _RE_VAR_PLUS_DEC.finditer(line):
        span_key = (line_idx, m.start(), m.end())
        if span_key in seen_spans:
            continue
        if _overlaps(seen_spans, line_idx, m.start(), m.end()):
            continue

        try:
            dec_val = int(m.group(3))
        except ValueError:
            continue

        # Only emit if the decimal value is in MMIO address range
        if not _is_peripheral_address(dec_val):
            continue

        seen_spans.add(span_key)

        if m.group(2):
            type_str = m.group(2)
            width = _width_from_type(type_str)
        else:
            width = _DEFAULT_WIDTH

        kinds = _classify_load_store(line, m.start())
        for kind in kinds:
            accesses.append(MemoryAccess(
                address=function_addr,
                kind=kind,
                width=width,
                target_addr=dec_val,
                base_provenance="CONST",
                function_name=function_name,
                function_addr=function_addr,
            ))


# ── Tokens to exclude from symbolic global matching ──────────────────────

_GLOBAL_EXCLUDE = frozenset({
    # C keywords
    "if", "else", "while", "for", "do", "return", "switch", "case",
    "break", "continue", "goto", "sizeof", "typedef", "struct", "union",
    "enum", "void", "int", "char", "short", "long", "float", "double",
    "unsigned", "signed", "const", "volatile", "static", "extern",
    "register", "auto", "inline", "bool", "true", "false", "NULL",
    # Ghidra type names
    "uint", "uchar", "ushort", "ulong", "undefined", "undefined1",
    "undefined2", "undefined4", "byte", "word", "dword",
    # Common Ghidra auto-names (local variables / params)
    "param", "local",
})


def _extract_global_symbol_accesses(
    line: str,
    line_idx: int,
    function_name: str,
    function_addr: int,
    accesses: List[MemoryAccess],
    seen_spans: set,
    global_symbol_table: Dict[str, int],
) -> None:
    """Extract memory accesses through symbolic global variable references.

    Matches patterns like ``g_rx_buf[index]`` and ``*(type *)(g_rx_buf + off)``
    where the symbol name exists in the global_symbol_table.  The resolved SRAM
    address is used as the MemoryAccess target_addr with provenance GLOBAL_PTR.
    """

    def _should_skip(name: str) -> bool:
        if name in _GLOBAL_EXCLUDE:
            return True
        # Skip Ghidra auto-generated local names like bVar1, uVar2, iVar3, ...
        if len(name) > 4 and name[0] in "biupfsa" and "Var" in name:
            return True
        return name not in global_symbol_table

    # Pattern 8: symbol[index]
    for m in _RE_GLOBAL_ARRAY.finditer(line):
        sym_name = m.group(1)
        if _should_skip(sym_name):
            continue

        span_key = (line_idx, m.start(), m.end())
        if span_key in seen_spans or _overlaps(seen_spans, line_idx, m.start(), m.end()):
            continue
        seen_spans.add(span_key)

        target_addr = global_symbol_table[sym_name]
        kinds = _classify_load_store(line, m.start())

        for kind in kinds:
            accesses.append(MemoryAccess(
                address=function_addr,
                kind=kind,
                width=_DEFAULT_WIDTH,
                target_addr=target_addr,
                base_provenance="GLOBAL_PTR",
                function_name=function_name,
                function_addr=function_addr,
            ))

    # Pattern 9: *(type *)(symbol + offset)
    for m in _RE_GLOBAL_PTR_ARITH.finditer(line):
        sym_name = m.group(3)
        if _should_skip(sym_name):
            continue

        span_key = (line_idx, m.start(), m.end())
        if span_key in seen_spans or _overlaps(seen_spans, line_idx, m.start(), m.end()):
            continue
        seen_spans.add(span_key)

        target_addr = global_symbol_table[sym_name]
        width_str = m.group(2)  # type in *(type *)
        width = _width_from_type(width_str)
        kinds = _classify_load_store(line, m.start())

        for kind in kinds:
            accesses.append(MemoryAccess(
                address=function_addr,
                kind=kind,
                width=width,
                target_addr=target_addr,
                base_provenance="GLOBAL_PTR",
                function_name=function_name,
                function_addr=function_addr,
            ))


def _overlaps(seen_spans: set, line_idx: int, start: int, end: int) -> bool:
    """Check if a span overlaps with any already-seen span on the same line."""
    for (li, s, e) in seen_spans:
        if li == line_idx and not (end <= s or start >= e):
            return True
    return False


def _target_from_hex(hex_str: str) -> int:
    """Convert hex string to int target address."""
    return int(hex_str, 16)


# ── Intra-procedural base propagation ─────────────────────────────────────


def _is_mask_constant(hex_val: int, assignment_text: str) -> bool:
    """Return True if hex_val looks like a bitmask, not a peripheral base address.

    Criteria (ALL must be met):
      1. hex_val >= 0xFFFF0000 (high-bit constant)
      2. Leading-ones + trailing-zeros bit pattern (mask shape)
      3. At least 4 trailing zeros
      4. '&' appears near the hex constant in the assignment expression
    """
    # 1. Must be in the high range
    if hex_val < 0xFFFF0000:
        return False

    # 2+3. Bit pattern check: leading ones then trailing zeros, ≥4 trailing zeros
    # A mask like 0xFFFFFFF0 in binary is 11111111111111111111111111110000
    # Invert → trailing ones count = number of trailing zeros in original
    inverted = (~hex_val) & 0xFFFFFFFF
    if inverted == 0:
        return False  # 0xFFFFFFFF is not a useful mask
    # Check inverted is a power-of-2 minus 1 (all low bits set)
    if (inverted & (inverted + 1)) != 0:
        return False  # Not a contiguous mask shape
    # Count trailing zeros (= number of set bits in inverted)
    trailing_zeros = inverted.bit_length()
    if trailing_zeros < 4:
        return False

    # 4. '&' must appear in the assignment context
    # Look for '&' within ~40 chars before the hex constant
    hex_str_lower = f"0x{hex_val:x}"
    hex_str_upper = f"0x{hex_val:X}"
    pos = assignment_text.lower().find(hex_str_lower)
    if pos < 0:
        pos = assignment_text.find(hex_str_upper)
    if pos < 0:
        # Try without leading zeros
        for fmt in (f"{hex_val:x}", f"{hex_val:X}"):
            p = assignment_text.lower().find(fmt)
            if p >= 0:
                pos = p
                break
    if pos < 0:
        return False

    # Check for '&' in the 40 chars before the hex literal
    context_start = max(0, pos - 40)
    context = assignment_text[context_start:pos]
    return "&" in context


def _extract_base_assignments(code: str) -> Dict[str, int]:
    """Scan for ``var = ...0xHEX...`` where HEX is in MMIO range.

    Returns {var_name: mmio_base_addr} for intra-procedural propagation.
    When multiple MMIO constants appear on the same assignment line,
    the *last* one (rightmost) is used since it's typically the dominant constant
    in expressions like ``uVar3 = (pin & 0xf) + 0x40010800``.
    """
    base_map: Dict[str, int] = {}
    for m in _RE_BASE_ASSIGN.finditer(code):
        var_name = m.group(1)
        try:
            hex_val = int(m.group(2), 16)
        except ValueError:
            continue
        if _is_peripheral_address(hex_val):
            if _is_mask_constant(hex_val, m.group(0)):
                continue  # Skip mask assignments (P6)
            base_map[var_name] = hex_val
    return base_map


def _resolve_small_offset_derefs(
    code: str,
    base_map: Dict[str, int],
    function_name: str,
    function_addr: int,
    seen_spans: set,
) -> List[MemoryAccess]:
    """Second-pass: resolve *(type *)(var + small_offset) using base_map.

    For matches where:
      - offset < 0x1000 (small struct/register offset)
      - var is in base_map (has a known MMIO base)
    Compute: target_addr = base_map[var] + offset
    """
    resolved: List[MemoryAccess] = []
    for line_idx, line in enumerate(code.splitlines()):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("/*"):
            continue

        for m in _RE_SMALL_OFFSET_DEREF.finditer(line):
            var_name = m.group(3)
            if var_name not in base_map:
                continue

            # Parse offset (may be hex or decimal since regex allows both)
            offset_str = m.group(4)
            try:
                offset = int(offset_str, 16)
            except ValueError:
                continue

            if offset >= 0x1000:
                continue  # Not a small struct offset

            span_key = (line_idx, m.start(), m.end())
            if span_key in seen_spans:
                continue
            if _overlaps(seen_spans, line_idx, m.start(), m.end()):
                continue
            seen_spans.add(span_key)

            target_addr = base_map[var_name] + offset

            type_str = m.group(2)
            width = _width_from_type(type_str) if type_str else _DEFAULT_WIDTH

            kinds = _classify_load_store(line, m.start())
            for kind in kinds:
                resolved.append(MemoryAccess(
                    address=function_addr,
                    kind=kind,
                    width=width,
                    target_addr=target_addr,
                    base_provenance="INTRA_RESOLVED",
                    function_name=function_name,
                    function_addr=function_addr,
                ))
    return resolved


# ── Typed MMIO struct field resolution ─────────────────────────────────────

# Dataclass-like tuples used internally during struct field resolution.
# We avoid heavy imports; these are just named tuples for clarity.

from dataclasses import dataclass as _dataclass


@_dataclass
class _TypedMMIOBase:
    """A typed MMIO base address from ``(TYPE_TypeDef *)0xHEX``."""
    peripheral_type: str   # e.g. "USART_TypeDef"
    base_addr: int
    function_name: str


@_dataclass
class _StructFieldAccess:
    """A struct field MMIO access: ``handle->Instance->FIELD``."""
    peripheral_type: str   # e.g. "USART_TypeDef"
    field_name: str        # e.g. "DR", "CR1"
    kind: str              # "load" or "store"
    function_name: str
    function_addr: int
    in_isr: bool = False


def _extract_typed_mmio_bases(code: str, function_name: str) -> List[_TypedMMIOBase]:
    """Extract typed MMIO base addresses from ``(TypeName *)0xHEX`` casts.

    These appear in comparisons, assignments, and conditionals when Ghidra
    performs type recovery on firmware.  Supports STM32 (USART_TypeDef),
    SAM3 (Uart), and K64F (UART_Type) type names.

    Only accepts types found in ALL_STRUCT_OFFSETS (after normalization).
    """
    bases: List[_TypedMMIOBase] = []
    seen: set = set()

    for m in _RE_TYPED_CAST_GENERIC.finditer(code):
        type_name = _normalize_type_name(m.group(1))

        # Only accept known peripheral types
        if type_name not in ALL_STRUCT_OFFSETS:
            continue

        try:
            addr = int(m.group(2), 16)
        except ValueError:
            continue

        # Only keep addresses in peripheral MMIO range
        if not _is_peripheral_address(addr):
            continue

        # Skip NULL pointers
        if addr == 0:
            continue

        key = (type_name, addr)
        if key in seen:
            continue
        seen.add(key)

        bases.append(_TypedMMIOBase(
            peripheral_type=type_name,
            base_addr=addr,
            function_name=function_name,
        ))

    return bases


def _extract_struct_field_accesses(
    code: str,
    function_name: str,
    function_addr: int,
) -> List[_StructFieldAccess]:
    """Extract struct field MMIO accesses from decompiled C.

    Handles two patterns:
    1. ``handle->Instance->FIELD`` — access through HAL handle struct
    2. ``periph_var->FIELD`` — direct access via typed peripheral pointer

    The peripheral type is inferred from:
    - Function parameter types (e.g. ``UART_HandleTypeDef *huart``)
    - Local variable declarations (e.g. ``I2C_TypeDef *pIVar2``)
    """
    accesses: List[_StructFieldAccess] = []

    # Step 1: Parse function signature to identify handle parameters
    # Map: variable_name → peripheral_type (e.g. "huart" → "USART_TypeDef")
    handle_params: Dict[str, str] = {}    # var → handle typedef
    periph_params: Dict[str, str] = {}    # var → peripheral typedef (direct)

    # Find function signature (first line with parentheses)
    sig_match = re.search(r"\w+\s+\w+\s*\(([^)]*)\)", code)
    if sig_match:
        params_str = sig_match.group(1)
        for pm in _RE_PARAM_DECL.finditer(params_str):
            ptype = pm.group(1)
            pname = pm.group(2)
            # Check if it's a HAL handle type
            periph_type = resolve_handle_type(ptype)
            if periph_type:
                handle_params[pname] = periph_type
            # Check if it's a direct peripheral type (normalize Ghidra suffixes)
            elif _normalize_type_name(ptype) in ALL_STRUCT_OFFSETS:
                periph_params[pname] = _normalize_type_name(ptype)

    # Step 2: Parse local variable declarations for peripheral pointer types
    for dm in _RE_LOCAL_PERIPH_DECL.finditer(code):
        dtype = dm.group(1)
        dname = dm.group(2)
        normalized = _normalize_type_name(dtype)
        if normalized in ALL_STRUCT_OFFSETS:
            periph_params[dname] = normalized

    # Step 3: Extract handle->Instance->FIELD accesses
    for line_idx, line in enumerate(code.splitlines()):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue

        # Pattern 11a: handle->Instance->FIELD
        for m in _RE_HANDLE_INSTANCE_FIELD.finditer(line):
            var_name = m.group(1)
            field_name = m.group(2)

            # Look up which peripheral type this handle corresponds to
            periph_type = handle_params.get(var_name)
            if periph_type is None:
                continue

            # Verify the field exists in the peripheral struct
            if get_field_offset(periph_type, field_name) is None:
                continue

            kinds = _classify_load_store(line, m.start())
            for kind in kinds:
                accesses.append(_StructFieldAccess(
                    peripheral_type=periph_type,
                    field_name=field_name,
                    kind=kind,
                    function_name=function_name,
                    function_addr=function_addr,
                ))

        # Pattern 11b: periph_var->FIELD (direct peripheral pointer access)
        for m in _RE_PERIPH_FIELD.finditer(line):
            var_name = m.group(1)
            field_name = m.group(2)

            # Skip if this is an Instance sub-access (already handled above)
            if field_name == "Instance":
                continue

            periph_type = periph_params.get(var_name)
            if periph_type is None:
                continue

            if get_field_offset(periph_type, field_name) is None:
                continue

            kinds = _classify_load_store(line, m.start())
            for kind in kinds:
                accesses.append(_StructFieldAccess(
                    peripheral_type=periph_type,
                    field_name=field_name,
                    kind=kind,
                    function_name=function_name,
                    function_addr=function_addr,
                ))

    return accesses


def _resolve_struct_accesses(
    typed_bases: List[_TypedMMIOBase],
    field_accesses: List[_StructFieldAccess],
) -> List[MemoryAccess]:
    """Cross-reference typed MMIO bases with struct field accesses.

    For each field access on peripheral type T with field F:
      target_addr = base + offset_of(F) for EACH known base of type T.

    This may produce multiple MemoryAccess entries per source access when
    multiple instances of the same peripheral type exist (e.g. USART1 and
    USART2), which is correct — the function may be called with either.
    """
    # Build type → set of base addresses
    type_bases: Dict[str, set] = {}
    for tb in typed_bases:
        type_bases.setdefault(tb.peripheral_type, set()).add(tb.base_addr)

    resolved: List[MemoryAccess] = []
    for fa in field_accesses:
        bases = type_bases.get(fa.peripheral_type, set())
        if not bases:
            continue

        offset = get_field_offset(fa.peripheral_type, fa.field_name)
        if offset is None:
            continue

        for base in sorted(bases):
            target = base + offset
            resolved.append(MemoryAccess(
                address=fa.function_addr,
                kind=fa.kind,
                width=4,  # all STM32 peripheral registers are 32-bit
                target_addr=target,
                base_provenance="STRUCT_RESOLVED",
                in_isr=fa.in_isr,
                function_name=fa.function_name,
                function_addr=fa.function_addr,
            ))

    return resolved


# ── MCP helpers ─────────────────────────────────────────────────────────────


async def _call_mcp_json(
    mcp_manager: object,
    tool_name: str,
    args: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Call a Ghidra MCP tool and parse the JSON response.

    MCP content blocks are [{\"type\": \"text\", \"text\": \"{json}\"}].
    Returns parsed dict or None on failure.
    """
    try:
        result = await mcp_manager.call_tool("ghidra", tool_name, args)
    except Exception as e:
        logger.warning("MCP call %s failed: %s", tool_name, e)
        return None

    if not result:
        return None

    # Extract text from content blocks
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


async def _enumerate_all_symbols(
    mcp_manager: object,
    binary_name: str,
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Enumerate all non-external symbols via paginated symbol search.

    Uses search_symbols_by_name(query=\"_\", limit=100) which matches all
    symbols. Returns two collections:
      1. Function symbols (type==\"Function\", not external)
      2. Global data symbol table: {name: address} for non-function,
         non-external symbols whose address falls in SRAM range.

    The data symbol table is used to resolve symbolic references like
    ``g_rx_buf[idx]`` in decompiled C back to concrete SRAM addresses.
    """
    functions: List[Dict[str, Any]] = []
    global_symbol_table: Dict[str, int] = {}
    seen_functions: set = set()

    def _ingest_symbols(symbols: List[Dict[str, Any]]) -> None:
        for sym in symbols:
            is_external = sym.get("external", False)
            sym_type = sym.get("type", "")
            sym_name = sym.get("name", "")
            addr_str = sym.get("address", "")

            if is_external or not sym_name:
                continue

            try:
                addr = int(addr_str, 16)
            except (ValueError, TypeError):
                continue

            if sym_type == "Function":
                key = (sym_name, addr)
                if key in seen_functions:
                    continue
                seen_functions.add(key)
                functions.append(sym)
            elif is_sram_address(addr):
                # Non-function symbol at SRAM address → global data variable
                global_symbol_table[sym_name] = addr

    async def _collect_query(
        query: str,
        *,
        paginate: bool = True,
        max_pages: int = 100,
    ) -> None:
        offset = 0
        limit = 100
        page = 0
        while True:
            resp = await _call_mcp_json(mcp_manager, "search_symbols_by_name", {
                "binary_name": binary_name,
                "query": query,
                "limit": limit,
                "offset": offset,
            })
            if resp is None:
                break
            symbols = resp.get("symbols", [])
            if not symbols:
                break
            _ingest_symbols(symbols)

            page += 1
            if not paginate or len(symbols) < limit or page >= max_pages:
                break
            offset += limit

    # Primary path: historical query "_" with full pagination.
    await _collect_query("_", paginate=True)

    # Coverage fallback: some projects expose many named functions without "_".
    if len(functions) < 20:
        before = len(functions)
        for query in (
            "", "FUN_", "main", "handler", "dispatch", "process", "parse",
            "read", "write", "copy", "recv", "receive", "fill",
            "uart", "spi", "usb", "bt", "dns",
            "cmd", "prv",
        ):
            # Fallback queries can be broad; keep them cheap (single page).
            await _collect_query(query, paginate=False, max_pages=1)
            if len(functions) >= 80:
                break
        logger.info(
            "Function enumeration fallback: %d -> %d functions for %s",
            before, len(functions), binary_name,
        )

    logger.info(
        "Enumerated %d functions, %d SRAM data symbols from %s",
        len(functions), len(global_symbol_table), binary_name,
    )
    return functions, global_symbol_table


_MAP_TEXT_WITH_ADDR_RE = re.compile(
    r"^\s*\.text\.([A-Za-z_][A-Za-z0-9_.$]*)\s+(0x[0-9A-Fa-f]+)\b.*$",
)


def _supplement_functions_from_map(
    binary_path: str,
    functions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Supplement function list from adjacent linker .map file when available."""
    if not binary_path:
        return functions

    map_path = Path(binary_path).with_suffix(".map")
    if not map_path.exists():
        return functions

    seen = set()
    for f in functions:
        try:
            seen.add((str(f.get("name", "")), int(str(f.get("address", "")), 16)))
        except (TypeError, ValueError):
            continue

    added = 0
    for line in map_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = _MAP_TEXT_WITH_ADDR_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        addr = int(m.group(2), 16)

        if addr == 0:
            continue
        key = (name, addr)
        if key in seen:
            continue
        seen.add(key)
        functions.append(
            {
                "name": name,
                "address": f"{addr:08x}",
                "type": "Function",
                "external": False,
                "from_map": True,
            },
        )
        added += 1

    if added:
        logger.info(
            "Function enumeration map-supplement: +%d functions from %s",
            added,
            map_path.name,
        )
    return functions


def _identify_isr_functions(
    functions: List[Dict[str, Any]],
    isr_handler_addrs: List[int],
) -> set:
    """Match function addresses against vector table ISR handler addresses.

    Ghidra addresses are hex strings without 0x prefix; ISR addresses are ints.
    Returns set of function names that are ISR handlers.
    """
    isr_addrs = set(isr_handler_addrs)
    isr_names: set = set()

    for func in functions:
        addr_str = func.get("address", "")
        try:
            addr = int(addr_str, 16)
        except (ValueError, TypeError):
            continue

        if addr in isr_addrs:
            name = func.get("name", "")
            if name:
                isr_names.add(name)

    return isr_names


# ── Flash constant pointer resolution ──────────────────────────────────────


def _resolve_flash_const_ptrs(
    accesses: List[MemoryAccess],
    flash_ptr_table: Dict[int, int],
) -> List[MemoryAccess]:
    """Reclassify flash CONST accesses whose target is in the flash ptr table.

    If an access has target_addr in flash_ptr_table and the resolved value is
    a peripheral address, update its target_addr to the MMIO address and set
    base_provenance to FLASH_CONST_PTR.
    """
    resolved = []
    for access in accesses:
        if (
            access.base_provenance == "CONST"
            and access.target_addr is not None
            and access.target_addr in flash_ptr_table
        ):
            mmio_addr = flash_ptr_table[access.target_addr]
            if _is_peripheral_address(mmio_addr):
                resolved.append(MemoryAccess(
                    address=access.address,
                    kind=access.kind,
                    width=access.width,
                    target_addr=mmio_addr,
                    base_provenance="FLASH_CONST_PTR",
                    in_isr=access.in_isr,
                    function_name=access.function_name,
                    function_addr=access.function_addr,
                ))
                continue
        resolved.append(access)
    return resolved


# ── Orchestrator ────────────────────────────────────────────────────────────


async def build_memory_access_index(
    memory_map: MemoryMap,
    mcp_manager: object,
    ghidra_binary_name: str,
    flash_ptr_table: Optional[Dict[int, int]] = None,
) -> MemoryAccessIndex:
    """Build the MemoryAccessIndex via Ghidra MCP tool calls.

    Args:
        memory_map: Stage 1 output with address regions and ISR handler addrs
        mcp_manager: MCPManager instance for Ghidra tool calls
        ghidra_binary_name: Binary name in Ghidra project (includes hash suffix)
        flash_ptr_table: Optional {flash_addr: mmio_value} from flash_const_ptr scanner

    Returns:
        MemoryAccessIndex with all classified memory accesses
    """
    mai = MemoryAccessIndex(binary_path=memory_map.binary_path)

    # Step 1: Enumerate all functions and SRAM data symbols
    functions, global_symbol_table = await _enumerate_all_symbols(
        mcp_manager, ghidra_binary_name,
    )
    if len(functions) < 20:
        functions = _supplement_functions_from_map(memory_map.binary_path, functions)

    if not functions:
        logger.warning("No functions found in %s", ghidra_binary_name)
        return mai

    if global_symbol_table:
        logger.info(
            "Global symbol table: %d SRAM symbols (e.g. %s)",
            len(global_symbol_table),
            list(global_symbol_table.keys())[:5],
        )

    # Step 2: Identify ISR handler functions
    isr_func_names = _identify_isr_functions(
        functions, memory_map.isr_handler_addrs,
    )
    mai.isr_functions = sorted(isr_func_names)

    # Step 3: Decompile each function and extract memory accesses
    # Also accumulate typed MMIO bases and struct field accesses for cross-function resolution
    all_typed_bases: List[_TypedMMIOBase] = []
    all_field_accesses: List[_StructFieldAccess] = []

    failed_funcs: List[Dict[str, Any]] = []
    for func in functions:
        func_name = func.get("name", "")
        addr_str = func.get("address", "")
        try:
            func_addr = int(addr_str, 16)
        except (ValueError, TypeError):
            func_addr = 0

        # Decompile
        resp = await _call_mcp_json(mcp_manager, "decompile_function", {
            "binary_name": ghidra_binary_name,
            "name_or_address": func_name,
        })

        if resp is None:
            failed_funcs.append(func)
            continue

        code = resp.get("decompiled_code", "") or resp.get("code", "")
        if not code:
            continue

        # Cache decompiled code for downstream stages (P5 param-store, P7 polling)
        if code:
            mai.decompiled_cache[func_name] = code

        # DEBUG: dump decompiled code for inspection
        _dump_file = os.environ.get("SOURCEAGENT_DUMP_DECOMPILED")
        if _dump_file:
            with open(_dump_file, "a") as _df:
                _df.write(f"\n===== {func_name} @ 0x{func_addr:08x} =====\n")
                _df.write(code)
                _df.write("\n")

        # Parse memory accesses from decompiled C
        func_accesses = parse_memory_accesses(
            code, func_name, func_addr,
            global_symbol_table=global_symbol_table or None,
        )

        # Tag ISR functions
        is_isr = func_name in isr_func_names
        for access in func_accesses:
            access.in_isr = is_isr

        mai.accesses.extend(func_accesses)

        # Extract typed MMIO bases and struct field accesses for cross-function resolution
        typed_bases = _extract_typed_mmio_bases(code, func_name)
        all_typed_bases.extend(typed_bases)

        field_accesses = _extract_struct_field_accesses(code, func_name, func_addr)
        for fa in field_accesses:
            fa.in_isr = is_isr
        all_field_accesses.extend(field_accesses)

    # Retry failed decompilations (analysis may still be completing)
    if failed_funcs:
        logger.info(
            "%d functions failed to decompile, retrying after delay...",
            len(failed_funcs),
        )
        await asyncio.sleep(5)
        still_failed = 0
        for func in failed_funcs:
            func_name = func.get("name", "")
            addr_str = func.get("address", "")
            try:
                func_addr = int(addr_str, 16)
            except (ValueError, TypeError):
                func_addr = 0

            resp = await _call_mcp_json(mcp_manager, "decompile_function", {
                "binary_name": ghidra_binary_name,
                "name_or_address": func_name,
            })

            if resp is None:
                still_failed += 1
                logger.debug("Decompile retry failed for %s", func_name)
                continue

            code = resp.get("decompiled_code", "") or resp.get("code", "")
            if not code:
                continue

            # Cache decompiled code for downstream stages
            if code:
                mai.decompiled_cache[func_name] = code

            func_accesses = parse_memory_accesses(
                code, func_name, func_addr,
                global_symbol_table=global_symbol_table or None,
            )
            is_isr = func_name in isr_func_names
            for access in func_accesses:
                access.in_isr = is_isr
            mai.accesses.extend(func_accesses)

            # Also extract typed bases and field accesses from retried functions
            typed_bases = _extract_typed_mmio_bases(code, func_name)
            all_typed_bases.extend(typed_bases)

            field_accesses = _extract_struct_field_accesses(code, func_name, func_addr)
            for fa in field_accesses:
                fa.in_isr = is_isr
            all_field_accesses.extend(field_accesses)

        if still_failed:
            logger.warning(
                "%d/%d functions could not be decompiled after retry",
                still_failed, len(failed_funcs),
            )

    # Step 4: Resolve flash constant pointers → MMIO targets
    if flash_ptr_table:
        mai.accesses = _resolve_flash_const_ptrs(mai.accesses, flash_ptr_table)
        logger.info(
            "Flash ptr resolution: %d FLASH_CONST_PTR accesses",
            sum(1 for a in mai.accesses if a.base_provenance == "FLASH_CONST_PTR"),
        )

    # Step 5: Cross-function struct field resolution
    # Combine typed MMIO bases collected across all functions with struct field
    # accesses to produce resolved MemoryAccess entries.
    if all_typed_bases and all_field_accesses:
        struct_resolved = _resolve_struct_accesses(all_typed_bases, all_field_accesses)
        mai.accesses.extend(struct_resolved)
        logger.info(
            "Struct field resolution: %d typed bases (%d types), "
            "%d field accesses → %d resolved MMIO accesses",
            len(all_typed_bases),
            len({tb.peripheral_type for tb in all_typed_bases}),
            len(all_field_accesses),
            len(struct_resolved),
        )
    elif all_field_accesses:
        logger.info(
            "Struct field resolution: %d field accesses but 0 typed bases — "
            "no peripheral base addresses found via typed casts",
            len(all_field_accesses),
        )

    # Step 5b: Populate typed_bases for downstream register classification
    for tb in all_typed_bases:
        mai.typed_bases[tb.base_addr] = tb.peripheral_type
    for _inst_name, (ptype, base_addr) in ALL_BASE_ADDRESSES.items():
        if base_addr not in mai.typed_bases:
            mai.typed_bases[base_addr] = ptype

    # Step 6: Build MMIO access index (filter accesses with resolved MMIO targets)
    for access in mai.accesses:
        if access.target_addr is not None and _is_peripheral_address(access.target_addr):
            mai.mmio_accesses.append(access)

    # Log provenance distribution
    prov_dist: dict = {}
    for a in mai.accesses:
        prov_dist[a.base_provenance] = prov_dist.get(a.base_provenance, 0) + 1
    logger.info(
        "MAI built: %d total accesses, %d MMIO, %d ISR functions",
        len(mai.accesses), len(mai.mmio_accesses), len(mai.isr_functions),
    )
    logger.info("Provenance distribution: %s", prov_dist)
    if failed_funcs:
        failed_names = [f.get("name", "?") for f in failed_funcs]
        logger.info("Functions that failed to decompile: %s", failed_names)
    return mai
