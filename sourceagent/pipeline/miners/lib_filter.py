"""Shared filters for library/runtime helper functions.

These heuristics are intentionally conservative: avoid emitting sink candidates
for obvious C library internals and high-fanout utility wrappers.
"""

from __future__ import annotations

import re
from typing import Optional

from ..models import MemoryAccessIndex

# Prefixes that strongly indicate runtime/library internals in firmware images.
_LIB_PREFIXES = (
    "__",
    "_printf",
    "_vfprintf",
    "_vfiprintf",
    "_svfiprintf",
    "_dtoa",
    "_malloc",
    "_free",
    "_realloc",
    "_calloc",
    "_sbrk",
    "_locale",
    "_ctype",
    "_str",
    "_mem",
    "_puts",
    "_fputs",
    "_putc",
    "_fflush",
    "_fclose",
    "_fopen",
    "net_buf_",
)

_LIB_EXACT = frozenset(
    {
        "__ssputs_r",
        "_printf_common",
        "_printf_i",
        "_vfprintf_internal",
        "__sfvwrite_r",
        "__sflush_r",
        "__sinit",
        "_realloc_r",
        "_malloc_r",
        "_free_r",
        "_calloc_r",
        "_sbrk_r",
        "_memalign_r",
        "memcpy",
        "memmove",
        "memset",
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "sprintf",
        "snprintf",
        "net_buf_add_mem",
    }
)


def is_library_function(func_name: str) -> bool:
    """Return True when a function name looks like runtime/library code."""
    if not func_name:
        return False

    # Auto-named functions need separate handling; do not over-filter here.
    if func_name.startswith("FUN_"):
        return False

    if func_name in _LIB_EXACT:
        return True
    return any(func_name.startswith(p) for p in _LIB_PREFIXES)


def estimate_fanout(func_name: str, mai: Optional[MemoryAccessIndex]) -> int:
    """Estimate incoming call fanout using decompiled cache text matching."""
    if not func_name or not mai or not mai.decompiled_cache:
        return 0

    needle = re.compile(r"\b" + re.escape(func_name) + r"\s*\(")
    count = 0
    for other_name, code in mai.decompiled_cache.items():
        if other_name == func_name:
            continue
        if needle.search(code or ""):
            count += 1
    return count
