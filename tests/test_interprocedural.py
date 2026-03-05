"""Tests for pipeline/interprocedural.py — Stage 2.5 inter-procedural resolution.

Covers:
  - Double-deref pattern detection (Patterns A and B)
  - Argument binding extraction from callsite
  - Init assignment scanning fallback
  - End-to-end resolution with MockMCPManager
  - Edge cases: no callers, unresolvable args, non-peripheral addresses
"""

import json

import pytest

from sourceagent.pipeline.models import MemoryAccess, MemoryAccessIndex
from sourceagent.pipeline.interprocedural import (
    HandleFieldAccess,
    UnresolvedBinding,
    detect_double_derefs,
    detect_single_derefs,
    resolve_interprocedural,
    _extract_arg_bindings,
    _get_raw_arg_expr,
    _resolve_arg_expr,
    _scan_init_assignment,
    _split_args,
)


# ── Mock infrastructure ─────────────────────────────────────────────────────


class MockMCPManager:
    """Mock MCPManager for testing without real Ghidra connection."""

    def __init__(self):
        self.responses = {}
        self.call_log = []

    def add_response(self, tool_name: str, key: str, data: dict):
        self.responses[(tool_name, key)] = data

    async def call_tool(self, server: str, tool_name: str, args: dict):
        self.call_log.append((server, tool_name, args))

        if tool_name == "decompile_function":
            key = args.get("name_or_address", "")
        elif tool_name == "list_cross_references":
            key = args.get("name_or_address", "")
        elif tool_name == "read_bytes":
            key = args.get("address", "")
        elif tool_name == "search_symbols_by_name":
            key = args.get("query", "")
        else:
            key = ""

        data = self.responses.get((tool_name, key))
        if data is None:
            return None
        return [{"type": "text", "text": json.dumps(data)}]


def _make_access(func_name, func_addr, provenance="ARG", target=None,
                 kind="load", width=4, in_isr=False):
    return MemoryAccess(
        address=func_addr,
        kind=kind,
        width=width,
        target_addr=target,
        base_provenance=provenance,
        function_name=func_name,
        function_addr=func_addr,
        in_isr=in_isr,
    )


# ── Double-deref detection tests ────────────────────────────────────────────


def test_detect_double_deref_pattern_a():
    """Pattern A: *(uint *)(*(int *)(param_1 + 0) + 0x18)"""
    code = """\
void HAL_UART_Receive(int *param_1) {
  uVar1 = *(uint *)(*(int *)(param_1 + 0) + 0x18);
}
"""
    access_indices = {("HAL_UART_Receive", 1): [0]}
    results = detect_double_derefs(code, "HAL_UART_Receive", 0x08001000, access_indices)
    assert len(results) >= 1
    ha = results[0]
    assert ha.param_index == 1
    assert ha.struct_offset == 0
    assert ha.reg_offset == 0x18
    assert ha.kind == "load"


def test_detect_double_deref_pattern_b():
    """Pattern B: *(uint *)(*param_1 + 0x18) — simple double-deref."""
    code = """\
void read_reg(int *param_1) {
  uVar1 = *(uint *)(*param_1 + 0x18);
}
"""
    access_indices = {("read_reg", 1): [0]}
    results = detect_double_derefs(code, "read_reg", 0x08001000, access_indices)
    assert len(results) >= 1
    ha = results[0]
    assert ha.param_index == 1
    assert ha.struct_offset == 0
    assert ha.reg_offset == 0x18


def test_detect_double_deref_with_struct_offset():
    """Pattern A with non-zero struct offset: *(uint *)(*(int *)(param_1 + 4) + 0xc)"""
    code = """\
void func(int *param_1) {
  uVar1 = *(uint *)(*(int *)(param_1 + 4) + 0xc);
}
"""
    access_indices = {("func", 1): [0]}
    results = detect_double_derefs(code, "func", 0x08001000, access_indices)
    assert len(results) >= 1
    ha = results[0]
    assert ha.param_index == 1
    assert ha.struct_offset == 4
    assert ha.reg_offset == 0xc


def test_detect_double_deref_store():
    """Double-deref on LHS = store."""
    code = """\
void write_reg(int *param_1) {
  *(uint *)(*(int *)(param_1 + 0) + 0x18) = 0x100;
}
"""
    access_indices = {("write_reg", 1): [0]}
    results = detect_double_derefs(code, "write_reg", 0x08001000, access_indices)
    assert len(results) >= 1
    assert results[0].kind == "store"


def test_detect_double_deref_no_match():
    """No double-deref pattern → empty results."""
    code = """\
void simple(int *param_1) {
  uVar1 = *(uint *)(param_1 + 4);
}
"""
    access_indices = {("simple", 1): [0]}
    results = detect_double_derefs(code, "simple", 0x08001000, access_indices)
    assert len(results) == 0


def test_detect_double_deref_no_matching_access():
    """Double-deref found but no unresolved access for that param → empty."""
    code = """\
void func(int *param_1) {
  uVar1 = *(uint *)(*param_1 + 0x18);
}
"""
    access_indices = {}  # no entries
    results = detect_double_derefs(code, "func", 0x08001000, access_indices)
    assert len(results) == 0


# ── Argument binding extraction tests ────────────────────────────────────────


def test_extract_arg_bindings_constant():
    """Call with hex constant argument."""
    code = "  HAL_UART_Init((UART_HandleTypeDef *)0x20000100);"
    bindings = _extract_arg_bindings(code, "HAL_UART_Init")
    assert 0 in bindings
    assert bindings[0].bound_value == 0x20000100
    assert bindings[0].provenance == "CONST"


def test_extract_arg_bindings_dat_label():
    """Call with DAT_ label argument."""
    code = "  HAL_UART_Init(DAT_20000100);"
    bindings = _extract_arg_bindings(code, "HAL_UART_Init")
    assert 0 in bindings
    assert bindings[0].bound_value == 0x20000100
    assert bindings[0].provenance == "GLOBAL_PTR"


def test_extract_arg_bindings_addr_of():
    """Call with &symbol argument."""
    code = "  HAL_UART_Init(&huart1);"
    bindings = _extract_arg_bindings(code, "HAL_UART_Init")
    assert 0 in bindings
    assert bindings[0].bound_value is None
    assert bindings[0].provenance == "ADDR_OF:huart1"


def test_extract_arg_bindings_multiple_args():
    """Call with multiple arguments."""
    code = "  HAL_UART_Receive(&huart1, 0x20000200, 10);"
    bindings = _extract_arg_bindings(code, "HAL_UART_Receive")
    assert len(bindings) == 3
    assert bindings[1].bound_value == 0x20000200
    assert bindings[2].bound_value == 10


def test_extract_arg_bindings_no_match():
    """No callsite → empty bindings."""
    code = "  some_other_func(0x100);"
    bindings = _extract_arg_bindings(code, "HAL_UART_Init")
    assert len(bindings) == 0


# ── Argument expression resolution tests ─────────────────────────────────────


def test_resolve_hex_constant():
    val, prov = _resolve_arg_expr("0x40011000")
    assert val == 0x40011000
    assert prov == "CONST"


def test_resolve_decimal_constant():
    val, prov = _resolve_arg_expr("42")
    assert val == 42
    assert prov == "CONST"


def test_resolve_dat_label():
    val, prov = _resolve_arg_expr("DAT_20000100")
    assert val == 0x20000100
    assert prov == "GLOBAL_PTR"


def test_resolve_dat_with_underscore():
    val, prov = _resolve_arg_expr("_DAT_20000100")
    assert val == 0x20000100
    assert prov == "GLOBAL_PTR"


def test_resolve_addr_of():
    val, prov = _resolve_arg_expr("&huart1")
    assert val is None
    assert prov == "ADDR_OF:huart1"


def test_resolve_type_cast_unwrap():
    val, prov = _resolve_arg_expr("(UART_HandleTypeDef *)0x20000100")
    assert val == 0x20000100
    assert prov == "CONST"


def test_resolve_param():
    val, prov = _resolve_arg_expr("param_2")
    assert val is None
    assert prov == "ARG"


def test_resolve_unknown():
    val, prov = _resolve_arg_expr("uVar3 + 4")
    assert val is None
    assert prov == "UNKNOWN"


# ── Split args tests ─────────────────────────────────────────────────────────


def test_split_simple():
    assert _split_args("a, b, c") == ["a", "b", "c"]


def test_split_nested_parens():
    assert _split_args("(int *)a, func(b, c), d") == ["(int *)a", "func(b, c)", "d"]


def test_split_empty():
    assert _split_args("") == []


# ── Init assignment scanning tests ───────────────────────────────────────────


def test_scan_init_assignment_basic():
    """Find *(param_1) = 0x40011000 with struct_offset=0."""
    code = """\
void HAL_UART_Init(int *param_1) {
  *param_1 = 0x40011000;
  *(param_1 + 4) = 0x100;
}
"""
    result = _scan_init_assignment(code, 1, 0)
    assert result == 0x40011000


def test_scan_init_assignment_with_cast():
    """Find *(int *)(param_1 + 0) = (USART_TypeDef *)0x40011000."""
    code = """\
void init(int *param_1) {
  *(int *)(param_1 + 0) = (USART_TypeDef *)0x40011000;
}
"""
    result = _scan_init_assignment(code, 1, 0)
    assert result == 0x40011000


def test_scan_init_assignment_not_found():
    """No matching assignment → None."""
    code = """\
void func(int *param_1) {
  int x = *(param_1 + 4);
}
"""
    result = _scan_init_assignment(code, 1, 0)
    assert result is None


# ── End-to-end resolution tests ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_resolve_interprocedural_basic():
    """Basic end-to-end: HAL function called with handle → MMIO resolved."""
    # Setup MAI with an unresolved ARG access
    mai = MemoryAccessIndex(binary_path="test.elf")
    mai.accesses = [
        _make_access("HAL_UART_Receive", 0x08001000, "ARG", None),
    ]

    # Setup mock MCP
    mcp = MockMCPManager()

    # Callee decompilation (HAL_UART_Receive has double-deref)
    mcp.add_response("decompile_function", "HAL_UART_Receive", {
        "code": """\
void HAL_UART_Receive(int *param_1) {
  uVar1 = *(uint *)(*(int *)param_1 + 0x18);
}
""",
    })

    # Callers (xrefs)
    mcp.add_response("list_cross_references", "0x8001000", {
        "references": [
            {"function_name": "main", "from_address": "08000100", "type": "UNCONDITIONAL_CALL"},
        ],
    })

    # Caller decompilation (main calls HAL_UART_Receive with DAT label)
    mcp.add_response("decompile_function", "main", {
        "code": "  HAL_UART_Receive(DAT_20000100);",
    })

    # Read Instance pointer from handle struct at 0x20000100
    mcp.add_response("read_bytes", "0x20000100", {
        "bytes": [0x00, 0x10, 0x01, 0x40],  # 0x40011000 LE
    })

    mai = await resolve_interprocedural(mai, mcp, "test-abc123")

    # Should have added a resolved INTERPROCEDURAL access
    interp = [a for a in mai.accesses if a.base_provenance == "INTERPROCEDURAL"]
    assert len(interp) == 1
    assert interp[0].target_addr == 0x40011000 + 0x18  # Instance + reg_off
    assert interp[0].function_name == "HAL_UART_Receive"

    # Should be in mmio_accesses
    assert len(mai.mmio_accesses) >= 1
    assert any(a.target_addr == 0x40011018 for a in mai.mmio_accesses)


@pytest.mark.asyncio
async def test_resolve_interprocedural_addr_of_symbol():
    """Resolve &huart1 via symbol lookup then read_bytes."""
    mai = MemoryAccessIndex(binary_path="test.elf")
    mai.accesses = [
        _make_access("HAL_UART_Init", 0x08002000, "ARG", None),
    ]

    mcp = MockMCPManager()

    # Callee with double-deref
    mcp.add_response("decompile_function", "HAL_UART_Init", {
        "code": """\
void HAL_UART_Init(int *param_1) {
  uVar1 = *(uint *)(*(int *)param_1 + 0xc);
}
""",
    })

    # Callers
    mcp.add_response("list_cross_references", "0x8002000", {
        "references": [
            {"function_name": "setup", "from_address": "08000200", "type": "UNCONDITIONAL_CALL"},
        ],
    })

    # Caller passes &huart1
    mcp.add_response("decompile_function", "setup", {
        "code": "  HAL_UART_Init(&huart1);",
    })

    # Symbol lookup for huart1
    mcp.add_response("search_symbols_by_name", "huart1", {
        "symbols": [
            {"name": "huart1", "address": "20000100", "type": "Label", "external": False},
        ],
    })

    # Read Instance pointer from huart1 at 0x20000100
    mcp.add_response("read_bytes", "0x20000100", {
        "bytes": [0x00, 0x38, 0x01, 0x40],  # 0x40013800 LE = USART1
    })

    mai = await resolve_interprocedural(mai, mcp, "test-abc123")

    interp = [a for a in mai.accesses if a.base_provenance == "INTERPROCEDURAL"]
    assert len(interp) == 1
    assert interp[0].target_addr == 0x40013800 + 0xc


@pytest.mark.asyncio
async def test_resolve_interprocedural_init_fallback():
    """When read_bytes fails, fall back to scanning init function for assignment."""
    mai = MemoryAccessIndex(binary_path="test.bin")
    mai.accesses = [
        _make_access("HAL_UART_Receive", 0x08001000, "ARG", None),
    ]

    mcp = MockMCPManager()

    # Callee with double-deref AND init assignment
    mcp.add_response("decompile_function", "HAL_UART_Receive", {
        "code": """\
void HAL_UART_Receive(int *param_1) {
  *param_1 = 0x40011000;
  uVar1 = *(uint *)(*param_1 + 0x18);
}
""",
    })

    # Callers
    mcp.add_response("list_cross_references", "0x8001000", {
        "references": [
            {"function_name": "main", "from_address": "08000100", "type": "UNCONDITIONAL_CALL"},
        ],
    })

    # Caller passes constant handle address
    mcp.add_response("decompile_function", "main", {
        "code": "  HAL_UART_Receive(0x20000100);",
    })

    # read_bytes fails (not registered → returns None)
    # Fallback: scan for *(param_1) = 0x40011000

    mai = await resolve_interprocedural(mai, mcp, "test-abc123")

    interp = [a for a in mai.accesses if a.base_provenance == "INTERPROCEDURAL"]
    assert len(interp) == 1
    assert interp[0].target_addr == 0x40011018


@pytest.mark.asyncio
async def test_resolve_interprocedural_no_callers():
    """No callers found → no resolution, no crash."""
    mai = MemoryAccessIndex(binary_path="test.elf")
    mai.accesses = [
        _make_access("orphan_fn", 0x08003000, "ARG", None),
    ]

    mcp = MockMCPManager()

    mcp.add_response("decompile_function", "orphan_fn", {
        "code": "void orphan_fn(int *param_1) {\n  uVar1 = *(uint *)(*param_1 + 0x18);\n}",
    })

    mcp.add_response("list_cross_references", "0x8003000", {
        "references": [],
    })

    mai = await resolve_interprocedural(mai, mcp, "test-abc123")

    interp = [a for a in mai.accesses if a.base_provenance == "INTERPROCEDURAL"]
    assert len(interp) == 0


@pytest.mark.asyncio
async def test_resolve_interprocedural_non_peripheral():
    """Resolved address not in MMIO range → not added."""
    mai = MemoryAccessIndex(binary_path="test.elf")
    mai.accesses = [
        _make_access("func", 0x08001000, "ARG", None),
    ]

    mcp = MockMCPManager()

    mcp.add_response("decompile_function", "func", {
        "code": "void func(int *param_1) {\n  uVar1 = *(uint *)(*param_1 + 0x4);\n}",
    })

    mcp.add_response("list_cross_references", "0x8001000", {
        "references": [
            {"function_name": "caller", "from_address": "08000100", "type": "UNCONDITIONAL_CALL"},
        ],
    })

    mcp.add_response("decompile_function", "caller", {
        "code": "  func(0x20000100);",
    })

    # Instance pointer is in SRAM, not MMIO
    mcp.add_response("read_bytes", "0x20000100", {
        "bytes": [0x00, 0x01, 0x00, 0x20],  # 0x20000100 LE = SRAM
    })

    mai = await resolve_interprocedural(mai, mcp, "test-abc123")

    interp = [a for a in mai.accesses if a.base_provenance == "INTERPROCEDURAL"]
    assert len(interp) == 0


@pytest.mark.asyncio
async def test_resolve_interprocedural_no_arg_accesses():
    """No ARG-provenance accesses → skip pass entirely."""
    mai = MemoryAccessIndex(binary_path="test.elf")
    mai.accesses = [
        _make_access("func", 0x08001000, "CONST", 0x40011000),
    ]

    mcp = MockMCPManager()
    mai = await resolve_interprocedural(mai, mcp, "test-abc123")

    # No MCP calls should have been made
    assert len(mcp.call_log) == 0
    assert len(mai.accesses) == 1


@pytest.mark.asyncio
async def test_resolve_interprocedural_preserves_isr():
    """ISR flag should be preserved on resolved accesses."""
    mai = MemoryAccessIndex(binary_path="test.elf")
    mai.accesses = [
        _make_access("ISR_Handler", 0x08005000, "ARG", None, in_isr=True),
    ]

    mcp = MockMCPManager()

    mcp.add_response("decompile_function", "ISR_Handler", {
        "code": "void ISR_Handler(int *param_1) {\n  uVar1 = *(uint *)(*param_1 + 0x18);\n}",
    })

    mcp.add_response("list_cross_references", "0x8005000", {
        "references": [
            {"function_name": "vector_dispatch", "from_address": "08000050", "type": "UNCONDITIONAL_CALL"},
        ],
    })

    mcp.add_response("decompile_function", "vector_dispatch", {
        "code": "  ISR_Handler(0x20000100);",
    })

    mcp.add_response("read_bytes", "0x20000100", {
        "bytes": [0x00, 0x10, 0x01, 0x40],  # 0x40011000
    })

    mai = await resolve_interprocedural(mai, mcp, "test-abc123")

    interp = [a for a in mai.accesses if a.base_provenance == "INTERPROCEDURAL"]
    assert len(interp) == 1
    assert interp[0].in_isr is True


@pytest.mark.asyncio
async def test_resolve_interprocedural_null_mcp():
    """mcp_manager=None → return MAI unchanged."""
    mai = MemoryAccessIndex(binary_path="test.elf")
    mai.accesses = [
        _make_access("func", 0x08001000, "ARG", None),
    ]

    result = await resolve_interprocedural(mai, None, "test-abc123")
    assert result is mai


# ══════════════════════════════════════════════════════════════════════════════
# P4: Single-deref pattern detection tests
# ══════════════════════════════════════════════════════════════════════════════


def test_detect_single_deref_basic():
    """*(uint *)(param_1 + 0x44) = mask; → single-deref with struct_offset=-1."""
    code = """\
void PIO_Configure(uint *param_1, uint param_2) {
  *(volatile uint *)(param_1 + 0x44) = param_2;
}
"""
    access_indices = {("PIO_Configure", 1): [0]}
    results = detect_single_derefs(code, "PIO_Configure", 0x08001000, access_indices)
    assert len(results) >= 1
    ha = results[0]
    assert ha.param_index == 1
    assert ha.struct_offset == -1  # Sentinel
    assert ha.reg_offset == 0x44
    assert ha.kind == "store"


def test_detect_single_deref_load():
    """*(uint *)(param_1 + 0x3c) → load with single-deref."""
    code = """\
void PIO_GetOutputDataStatus(uint *param_1) {
  uVar1 = *(uint *)(param_1 + 0x3c);
}
"""
    access_indices = {("PIO_GetOutputDataStatus", 1): [0]}
    results = detect_single_derefs(
        code, "PIO_GetOutputDataStatus", 0x08002000, access_indices,
    )
    assert len(results) >= 1
    assert results[0].kind == "load"
    assert results[0].struct_offset == -1
    assert results[0].reg_offset == 0x3c


def test_detect_single_deref_no_match():
    """No single-deref pattern → empty results."""
    code = """\
void simple(int param_1) {
  return param_1 + 4;
}
"""
    access_indices = {("simple", 1): [0]}
    results = detect_single_derefs(code, "simple", 0x08001000, access_indices)
    assert len(results) == 0


# ══════════════════════════════════════════════════════════════════════════════
# P4: Single-deref end-to-end resolution tests
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_single_deref_param_resolve():
    """Single-deref: *(uint *)(param_1 + 0x44), caller passes PIO base → resolved."""
    mai = MemoryAccessIndex(binary_path="test.elf")
    mai.accesses = [
        _make_access("PIO_Configure", 0x08001000, "ARG", None, kind="store"),
    ]

    mcp = MockMCPManager()

    # Callee with single-deref
    mcp.add_response("decompile_function", "PIO_Configure", {
        "code": """\
void PIO_Configure(uint *param_1, uint param_2) {
  *(volatile uint *)(param_1 + 0x44) = param_2;
}
""",
    })

    # Callers
    mcp.add_response("list_cross_references", "0x8001000", {
        "references": [
            {"function_name": "setup", "from_address": "08000100", "type": "UNCONDITIONAL_CALL"},
        ],
    })

    # Caller passes PIO base directly
    mcp.add_response("decompile_function", "setup", {
        "code": "  PIO_Configure(0x400e0e00, 0x100);",
    })

    mai = await resolve_interprocedural(mai, mcp, "test-abc123")

    interp = [a for a in mai.accesses if a.base_provenance == "INTERPROCEDURAL"]
    assert len(interp) == 1
    assert interp[0].target_addr == 0x400e0e00 + 0x44  # PIO base + reg_offset


@pytest.mark.asyncio
async def test_single_deref_non_peripheral():
    """Single-deref resolved to SRAM → skipped."""
    mai = MemoryAccessIndex(binary_path="test.elf")
    mai.accesses = [
        _make_access("func", 0x08001000, "ARG", None),
    ]

    mcp = MockMCPManager()

    mcp.add_response("decompile_function", "func", {
        "code": """\
void func(uint *param_1) {
  uVar1 = *(uint *)(param_1 + 0x10);
}
""",
    })

    mcp.add_response("list_cross_references", "0x8001000", {
        "references": [
            {"function_name": "caller", "from_address": "08000100", "type": "UNCONDITIONAL_CALL"},
        ],
    })

    # Caller passes SRAM address
    mcp.add_response("decompile_function", "caller", {
        "code": "  func(0x20000100);",
    })

    mai = await resolve_interprocedural(mai, mcp, "test-abc123")

    interp = [a for a in mai.accesses if a.base_provenance == "INTERPROCEDURAL"]
    assert len(interp) == 0  # SRAM, not peripheral


# ══════════════════════════════════════════════════════════════════════════════
# P4: Depth-2 resolution tests
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_depth2_resolve_basic():
    """Depth-2: callee has single-deref, caller passes param_2, grandparent passes 0x400e0e00."""
    mai = MemoryAccessIndex(binary_path="test.elf")
    mai.accesses = [
        _make_access("PIO_Set", 0x08001000, "ARG", None, kind="store"),
    ]

    mcp = MockMCPManager()

    # Callee with single-deref (param IS PIO base)
    mcp.add_response("decompile_function", "PIO_Set", {
        "code": """\
void PIO_Set(uint *param_1, uint param_2) {
  *(volatile uint *)(param_1 + 0x30) = param_2;
}
""",
    })

    # Callee's callers → intermediate wrapper
    mcp.add_response("list_cross_references", "0x8001000", {
        "references": [
            {"function_name": "PIO_SetPin", "from_address": "08000500", "type": "UNCONDITIONAL_CALL"},
        ],
    })

    # Intermediate wrapper passes param_2 through
    mcp.add_response("decompile_function", "PIO_SetPin", {
        "code": "void PIO_SetPin(uint pin, uint *param_2) {\n  PIO_Set(param_2, 1 << pin);\n}",
    })

    # Give PIO_SetPin an address for xref lookup
    mai.accesses.append(
        _make_access("PIO_SetPin", 0x08000500, "CONST", 0x08001000),
    )

    # Grandparent callers of PIO_SetPin
    mcp.add_response("list_cross_references", "0x8000500", {
        "references": [
            {"function_name": "main", "from_address": "08000100", "type": "UNCONDITIONAL_CALL"},
        ],
    })

    # Grandparent passes the actual PIO base
    mcp.add_response("decompile_function", "main", {
        "code": "  PIO_SetPin(5, 0x400e0e00);",
    })

    mai = await resolve_interprocedural(mai, mcp, "test-abc123")

    interp = [a for a in mai.accesses if a.base_provenance == "INTERPROCEDURAL"]
    assert len(interp) >= 1
    assert any(a.target_addr == 0x400e0e00 + 0x30 for a in interp)


@pytest.mark.asyncio
async def test_depth2_no_grandparents():
    """Depth-2: caller passes param but no grandparent callers → graceful, no crash."""
    mai = MemoryAccessIndex(binary_path="test.elf")
    mai.accesses = [
        _make_access("leaf_fn", 0x08001000, "ARG", None, kind="store"),
    ]

    mcp = MockMCPManager()

    mcp.add_response("decompile_function", "leaf_fn", {
        "code": """\
void leaf_fn(uint *param_1) {
  *(uint *)(param_1 + 0x10) = 1;
}
""",
    })

    mcp.add_response("list_cross_references", "0x8001000", {
        "references": [
            {"function_name": "wrapper", "from_address": "08000500", "type": "UNCONDITIONAL_CALL"},
        ],
    })

    mcp.add_response("decompile_function", "wrapper", {
        "code": "void wrapper(uint *param_1) {\n  leaf_fn(param_1);\n}",
    })

    mai.accesses.append(
        _make_access("wrapper", 0x08000500, "CONST", 0x08001000),
    )

    # No grandparents registered → empty xrefs
    mcp.add_response("list_cross_references", "0x8000500", {
        "references": [],
    })

    mai = await resolve_interprocedural(mai, mcp, "test-abc123")

    interp = [a for a in mai.accesses if a.base_provenance == "INTERPROCEDURAL"]
    assert len(interp) == 0  # Graceful: no resolution, no crash


@pytest.mark.asyncio
async def test_depth2_budget_cap():
    """>20 callers: processes at most 20 (no crash, bounded budget)."""
    mai = MemoryAccessIndex(binary_path="test.elf")
    mai.accesses = [
        _make_access("leaf", 0x08001000, "ARG", None),
    ]

    mcp = MockMCPManager()

    mcp.add_response("decompile_function", "leaf", {
        "code": "void leaf(uint *param_1) {\n  uVar1 = *(uint *)(param_1 + 0x10);\n}",
    })

    # Create 25 callers all passing param_1
    callers = []
    for i in range(25):
        caller_name = f"caller_{i}"
        callers.append({
            "function_name": caller_name,
            "from_address": f"0800{i:04x}",
            "type": "UNCONDITIONAL_CALL",
        })
        mcp.add_response("decompile_function", caller_name, {
            "code": f"void {caller_name}(uint *param_1) {{\n  leaf(param_1);\n}}",
        })
        # Add access so wrapper has an addr
        mai.accesses.append(
            _make_access(caller_name, 0x08000000 + i, "CONST", 0x08001000),
        )
        # Empty grandparent xrefs
        mcp.add_response("list_cross_references", f"0x{0x08000000 + i:x}", {
            "references": [],
        })

    mcp.add_response("list_cross_references", "0x8001000", {
        "references": callers,
    })

    # Should not crash and should complete in bounded time
    mai = await resolve_interprocedural(mai, mcp, "test-abc123")
    # No resolution expected (empty grandparents), but no crash
    assert isinstance(mai, MemoryAccessIndex)


@pytest.mark.asyncio
async def test_depth2_addr_of_symbol():
    """Depth-2: grandparent passes &pio_a → resolves via symbol lookup."""
    mai = MemoryAccessIndex(binary_path="test.elf")
    mai.accesses = [
        _make_access("PIO_Write", 0x08001000, "ARG", None, kind="store"),
    ]

    mcp = MockMCPManager()

    # Callee: single-deref
    mcp.add_response("decompile_function", "PIO_Write", {
        "code": """\
void PIO_Write(uint *param_1, uint param_2) {
  *(volatile uint *)(param_1 + 0x30) = param_2;
}
""",
    })

    # Callee callers → wrapper
    mcp.add_response("list_cross_references", "0x8001000", {
        "references": [
            {"function_name": "pio_wrapper", "from_address": "08000500", "type": "UNCONDITIONAL_CALL"},
        ],
    })

    # Wrapper passes param_1 through
    mcp.add_response("decompile_function", "pio_wrapper", {
        "code": "void pio_wrapper(uint *param_1) {\n  PIO_Write(param_1, 0xff);\n}",
    })

    mai.accesses.append(
        _make_access("pio_wrapper", 0x08000500, "CONST", 0x08001000),
    )

    # Grandparent callers
    mcp.add_response("list_cross_references", "0x8000500", {
        "references": [
            {"function_name": "main", "from_address": "08000100", "type": "UNCONDITIONAL_CALL"},
        ],
    })

    # Grandparent passes &pio_a
    mcp.add_response("decompile_function", "main", {
        "code": "  pio_wrapper(&pio_a);",
    })

    # Symbol resolution: pio_a is at 0x400e0e00 (PIO base directly)
    mcp.add_response("search_symbols_by_name", "pio_a", {
        "symbols": [
            {"name": "pio_a", "address": "400e0e00", "type": "Label"},
        ],
    })

    mai = await resolve_interprocedural(mai, mcp, "test-abc123")

    interp = [a for a in mai.accesses if a.base_provenance == "INTERPROCEDURAL"]
    assert len(interp) >= 1
    assert any(a.target_addr == 0x400e0e00 + 0x30 for a in interp)
