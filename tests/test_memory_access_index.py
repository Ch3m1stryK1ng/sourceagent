"""Tests for pipeline/memory_access_index.py — Stage 2 (M2).

Covers:
  - Model defaults and init
  - parse_memory_accesses (pure function) with various Ghidra decompiled C patterns
  - Load/store/both classification
  - Type-width mapping (byte/ushort/uint)
  - Address provenance (CONST/GLOBAL_PTR/STACK_PTR/ARG)
  - MMIO vs SRAM vs flash address classification
  - ISR function identification
  - build_memory_access_index with MockMCPManager (pagination, errors, etc.)
"""

import json

import pytest

from sourceagent.pipeline.models import MemoryAccess, MemoryAccessIndex, MemoryMap, MemoryRegion
from sourceagent.pipeline.memory_access_index import (
    build_memory_access_index,
    parse_memory_accesses,
    _classify_load_store,
    _is_peripheral_address,
    _is_mask_constant,
    _resolve_flash_const_ptrs,
    _width_from_type,
    _identify_isr_functions,
)


# ── Mock infrastructure ─────────────────────────────────────────────────────


class MockMCPManager:
    """Mock MCPManager for testing without real Ghidra connection."""

    def __init__(self):
        self.responses = {}  # (tool_name, key) → response
        self.call_log = []

    def add_response(self, tool_name: str, key: str, data: dict):
        """Register a response for a tool call.

        key is used to differentiate calls to the same tool with different args.
        For search_symbols_by_name, key is the offset.
        For decompile_function, key is the function name.
        """
        self.responses[(tool_name, key)] = data

    async def call_tool(self, server: str, tool_name: str, args: dict):
        self.call_log.append((server, tool_name, args))

        # Determine key based on tool
        if tool_name == "search_symbols_by_name":
            key = str(args.get("offset", 0))
        elif tool_name == "decompile_function":
            key = args.get("name_or_address", "") or args.get("name", "")
        else:
            key = ""

        data = self.responses.get((tool_name, key))
        if data is None:
            return None

        return _mcp_text(data)


class FailingMCPManager:
    """MCPManager that always raises exceptions."""

    async def call_tool(self, server, tool_name, args):
        raise ConnectionError("Ghidra MCP unavailable")


def _mcp_text(data: dict) -> list:
    """Build MCP content block from dict."""
    return [{"type": "text", "text": json.dumps(data)}]


def _make_memory_map(isr_addrs=None):
    """Build a minimal MemoryMap for testing."""
    return MemoryMap(
        binary_path="test.bin",
        arch="ARM:LE:32:Cortex",
        base_address=0x08000000,
        entry_point=0x08000101,
        regions=[
            MemoryRegion("FLASH", 0x08000000, 0x100000, "rx", "flash"),
            MemoryRegion("SRAM", 0x20000000, 0x20000, "rw", "sram"),
            MemoryRegion("PERIPHERAL", 0x40000000, 0x20000000, "rw", "mmio"),
            MemoryRegion("SYSTEM", 0xE0000000, 0x20000000, "rw", "mmio"),
        ],
        isr_handler_addrs=isr_addrs or [],
    )


def _symbols_response(funcs):
    """Build a search_symbols_by_name response from a list of (name, addr_hex) tuples."""
    return {
        "symbols": [
            {"name": name, "address": addr, "type": "Function", "external": False}
            for name, addr in funcs
        ]
    }


def _decompile_response(code):
    """Build a decompile_function response."""
    return {"code": code}


# ── Model init tests ────────────────────────────────────────────────────────


def test_memory_access_index_empty_on_init():
    """A fresh MemoryAccessIndex should have empty lists."""
    mai = MemoryAccessIndex(binary_path="test.bin")
    assert mai.accesses == []
    assert mai.mmio_accesses == []
    assert mai.isr_functions == []


def test_memory_access_kind_values():
    """MemoryAccess kind should be 'load' or 'store'."""
    load = MemoryAccess(address=0x1000, kind="load", width=4)
    store = MemoryAccess(address=0x1004, kind="store", width=4)
    assert load.kind == "load"
    assert store.kind == "store"


def test_memory_access_width_values():
    """Common ARM access widths: 1, 2, 4 bytes."""
    for w in [1, 2, 4]:
        a = MemoryAccess(address=0x1000, kind="load", width=w)
        assert a.width == w


def test_isr_handler_addrs_default():
    """MemoryMap should default isr_handler_addrs to empty list."""
    mm = MemoryMap(
        binary_path="test.bin",
        arch="ARM:LE:32:Cortex",
        base_address=0x08000000,
        entry_point=0x08000101,
    )
    assert mm.isr_handler_addrs == []


# ── Width extraction tests ──────────────────────────────────────────────────


def test_width_word():
    """uint/int/undefined4 → 4 bytes."""
    assert _width_from_type("uint") == 4
    assert _width_from_type("int") == 4
    assert _width_from_type("undefined4") == 4


def test_width_halfword():
    """ushort/short/undefined2 → 2 bytes."""
    assert _width_from_type("ushort") == 2
    assert _width_from_type("short") == 2
    assert _width_from_type("undefined2") == 2


def test_width_byte():
    """byte/char/undefined → 1 byte."""
    assert _width_from_type("byte") == 1
    assert _width_from_type("char") == 1
    assert _width_from_type("undefined") == 1


def test_width_unknown_defaults_to_4():
    """Unknown type defaults to 4 bytes (word-sized)."""
    assert _width_from_type("float") == 4
    assert _width_from_type("SomeStruct") == 4


# ── Address classification tests ────────────────────────────────────────────


def test_peripheral_mmio_range():
    """Standard MMIO range (0x40000000-0x5FFFFFFF) is peripheral."""
    assert _is_peripheral_address(0x40000000) is True
    assert _is_peripheral_address(0x40011000) is True
    assert _is_peripheral_address(0x5FFFFFFF) is True


def test_system_peripheral_is_mmio():
    """System peripheral range (0xE0000000+) is also peripheral (NVIC, SysTick)."""
    assert _is_peripheral_address(0xE000E100) is True  # NVIC
    assert _is_peripheral_address(0xE000E010) is True  # SysTick
    assert _is_peripheral_address(0xE0000000) is True


def test_sram_not_peripheral():
    """SRAM range should not be classified as peripheral."""
    assert _is_peripheral_address(0x20000000) is False
    assert _is_peripheral_address(0x20000100) is False


def test_flash_not_peripheral():
    """Flash range should not be classified as peripheral."""
    assert _is_peripheral_address(0x08000000) is False
    assert _is_peripheral_address(0x00000000) is False


# ── Load/store classification tests ─────────────────────────────────────────


def test_classify_store():
    """LHS of = → store."""
    line = "  *(uint *)0x40011000 = uVar1;"
    kinds = _classify_load_store(line, line.index("*"))
    assert kinds == ["store"]


def test_classify_load():
    """RHS of = → load."""
    line = "  uVar1 = *(uint *)0x40011000;"
    kinds = _classify_load_store(line, line.index("*(uint"))
    assert kinds == ["load"]


def test_classify_read_modify_write():
    """Compound assignment |= → both load and store."""
    line = "  *(uint *)0x40011000 |= 0x100;"
    kinds = _classify_load_store(line, line.index("*"))
    assert set(kinds) == {"load", "store"}


def test_classify_and_equals():
    """Compound assignment &= → both."""
    line = "  *(uint *)0x40011000 &= ~0x100;"
    kinds = _classify_load_store(line, line.index("*"))
    assert set(kinds) == {"load", "store"}


def test_equality_not_assignment():
    """== is comparison, not assignment → load."""
    line = "  if (*(uint *)0x40011000 == 0) {"
    kinds = _classify_load_store(line, line.index("*(uint"))
    assert kinds == ["load"]


def test_function_arg_is_load():
    """Dereference as function argument → load."""
    line = "  func(*(uint *)0x40011000);"
    kinds = _classify_load_store(line, line.index("*(uint"))
    assert kinds == ["load"]


def test_no_assignment_is_load():
    """No = on line → load."""
    line = "  return *(uint *)0x40011000;"
    kinds = _classify_load_store(line, line.index("*(uint"))
    assert kinds == ["load"]


# ── parse_memory_accesses — pattern tests ───────────────────────────────────


def test_mmio_const_load():
    """*(uint *)0x40011000 on RHS → load, CONST, target=0x40011000."""
    code = "  uVar1 = *(uint *)0x40011000;"
    accesses = parse_memory_accesses(code, "uart_read", 0x08001000)
    assert len(accesses) == 1
    a = accesses[0]
    assert a.kind == "load"
    assert a.base_provenance == "CONST"
    assert a.target_addr == 0x40011000
    assert a.width == 4
    assert a.function_name == "uart_read"


def test_mmio_const_store():
    """*(uint *)0x40011000 = val → store, CONST."""
    code = "  *(uint *)0x40011000 = uVar1;"
    accesses = parse_memory_accesses(code, "uart_write", 0x08001100)
    assert len(accesses) == 1
    assert accesses[0].kind == "store"
    assert accesses[0].base_provenance == "CONST"
    assert accesses[0].target_addr == 0x40011000


def test_mmio_read_modify_write():
    """*(uint *)0x40011000 |= 0x100 → both load and store."""
    code = "  *(uint *)0x40011000 |= 0x100;"
    accesses = parse_memory_accesses(code, "rcc_enable", 0x08001200)
    assert len(accesses) == 2
    kinds = {a.kind for a in accesses}
    assert kinds == {"load", "store"}
    for a in accesses:
        assert a.target_addr == 0x40011000


def test_dat_label_mmio():
    """*(uint *)DAT_40011000 → CONST, target=0x40011000."""
    code = "  uVar1 = *(uint *)DAT_40011000;"
    accesses = parse_memory_accesses(code, "read_reg", 0x08001300)
    assert len(accesses) == 1
    a = accesses[0]
    assert a.base_provenance == "CONST"
    assert a.target_addr == 0x40011000


def test_const_offset_pattern():
    """*(uint *)(0x40000000 + 0x11000) → CONST with base address."""
    code = "  uVar1 = *(uint *)(0x40000000 + 0x11000);"
    accesses = parse_memory_accesses(code, "periph_read", 0x08001400)
    assert len(accesses) == 1
    a = accesses[0]
    assert a.base_provenance == "CONST"
    assert a.target_addr == 0x40000000  # Base address captured


def test_arg_provenance():
    """*(uint *)(param_1 + 4) → ARG, target=None."""
    code = "  uVar1 = *(uint *)(param_1 + 4);"
    accesses = parse_memory_accesses(code, "read_struct", 0x08001500)
    assert len(accesses) == 1
    a = accesses[0]
    assert a.base_provenance == "ARG"
    assert a.target_addr is None


def test_stack_provenance():
    """*(uint *)(&local_20 + 4) → STACK_PTR."""
    code = "  uVar1 = *(uint *)(&local_20 + 4);"
    accesses = parse_memory_accesses(code, "stack_fn", 0x08001600)
    assert len(accesses) == 1
    assert accesses[0].base_provenance == "STACK_PTR"
    assert accesses[0].target_addr is None


def test_global_ptr_provenance():
    """*(uint *)(DAT_20000100 + iVar1) → GLOBAL_PTR, target=0x20000100."""
    code = "  uVar1 = *(uint *)(DAT_20000100 + iVar1);"
    accesses = parse_memory_accesses(code, "global_fn", 0x08001700)
    assert len(accesses) == 1
    a = accesses[0]
    assert a.base_provenance == "GLOBAL_PTR"
    assert a.target_addr == 0x20000100


def test_width_byte_in_parse():
    """*(byte *)0x40011000 → width=1."""
    code = "  bVar1 = *(byte *)0x40011000;"
    accesses = parse_memory_accesses(code, "byte_read", 0x08001800)
    assert len(accesses) == 1
    assert accesses[0].width == 1


def test_width_halfword_in_parse():
    """*(ushort *)0x40011000 → width=2."""
    code = "  sVar1 = *(ushort *)0x40011000;"
    accesses = parse_memory_accesses(code, "half_read", 0x08001900)
    assert len(accesses) == 1
    assert accesses[0].width == 2


def test_volatile_qualifier():
    """*(volatile uint *)0x40011000 → parsed correctly, same as non-volatile."""
    code = "  uVar1 = *(volatile uint *)0x40011000;"
    accesses = parse_memory_accesses(code, "vol_read", 0x08002000)
    assert len(accesses) == 1
    a = accesses[0]
    assert a.target_addr == 0x40011000
    assert a.width == 4
    assert a.base_provenance == "CONST"


def test_empty_function():
    """void f(void) { return; } → 0 accesses."""
    code = "void f(void) {\n  return;\n}"
    accesses = parse_memory_accesses(code, "empty_fn", 0x08002100)
    assert accesses == []


def test_multiple_accesses_same_line():
    """Two dereferences on same line should both be captured."""
    code = "  *(uint *)0x40011000 = *(uint *)0x40011004;"
    accesses = parse_memory_accesses(code, "copy_reg", 0x08002200)
    # Should find both: store to 0x40011000 and load from 0x40011004
    assert len(accesses) == 2
    targets = {a.target_addr for a in accesses}
    assert 0x40011000 in targets
    assert 0x40011004 in targets


def test_comment_line_skipped():
    """Lines starting with // should be skipped."""
    code = "  // *(uint *)0x40011000 = val;\n  uVar1 = *(uint *)0x40011004;"
    accesses = parse_memory_accesses(code, "comment_fn", 0x08002300)
    assert len(accesses) == 1
    assert accesses[0].target_addr == 0x40011004


# ── ISR identification tests ────────────────────────────────────────────────


def test_identify_isr_functions_match():
    """Functions at ISR handler addresses should be identified."""
    funcs = [
        {"name": "TIM2_IRQHandler", "address": "08001000", "type": "Function", "external": False},
        {"name": "main", "address": "08000100", "type": "Function", "external": False},
    ]
    isr_addrs = [0x08001000, 0x08002000]
    isr_names = _identify_isr_functions(funcs, isr_addrs)
    assert "TIM2_IRQHandler" in isr_names
    assert "main" not in isr_names


def test_identify_isr_functions_no_match():
    """No ISR addresses → empty set."""
    funcs = [
        {"name": "main", "address": "08000100", "type": "Function", "external": False},
    ]
    isr_names = _identify_isr_functions(funcs, [])
    assert isr_names == set()


# ── build_memory_access_index integration tests (MockMCPManager) ───────────


@pytest.mark.asyncio
async def test_build_index_basic():
    """Basic end-to-end: 1 function with MMIO read → appears in mmio_accesses."""
    mcp = MockMCPManager()
    mcp.add_response("search_symbols_by_name", "0", _symbols_response([
        ("uart_read", "08001000"),
    ]))
    mcp.add_response("decompile_function", "uart_read", _decompile_response(
        "uint uart_read(void) {\n  return *(uint *)0x40011000;\n}"
    ))

    mm = _make_memory_map()
    mai = await build_memory_access_index(mm, mcp, "test-abc123")

    assert len(mai.accesses) == 1
    assert len(mai.mmio_accesses) == 1
    assert mai.accesses[0].target_addr == 0x40011000
    assert mai.accesses[0].kind == "load"


@pytest.mark.asyncio
async def test_build_index_sram_not_in_mmio():
    """SRAM access (0x20000100) → in accesses but NOT in mmio_accesses."""
    mcp = MockMCPManager()
    mcp.add_response("search_symbols_by_name", "0", _symbols_response([
        ("sram_fn", "08001000"),
    ]))
    mcp.add_response("decompile_function", "sram_fn", _decompile_response(
        "void sram_fn(void) {\n  *(uint *)0x20000100 = 42;\n}"
    ))

    mm = _make_memory_map()
    mai = await build_memory_access_index(mm, mcp, "test-abc123")

    assert len(mai.accesses) == 1
    assert mai.accesses[0].target_addr == 0x20000100
    assert len(mai.mmio_accesses) == 0


@pytest.mark.asyncio
async def test_build_index_flash_not_mmio():
    """Flash access (0x08001000) → in accesses but NOT in mmio_accesses."""
    mcp = MockMCPManager()
    mcp.add_response("search_symbols_by_name", "0", _symbols_response([
        ("flash_fn", "08001000"),
    ]))
    mcp.add_response("decompile_function", "flash_fn", _decompile_response(
        "void flash_fn(void) {\n  uVar1 = *(uint *)0x08001000;\n}"
    ))

    mm = _make_memory_map()
    mai = await build_memory_access_index(mm, mcp, "test-abc123")

    assert len(mai.accesses) == 1
    assert len(mai.mmio_accesses) == 0


@pytest.mark.asyncio
async def test_build_index_system_peripheral_is_mmio():
    """System peripheral (NVIC, 0xE000E100) → in mmio_accesses."""
    mcp = MockMCPManager()
    mcp.add_response("search_symbols_by_name", "0", _symbols_response([
        ("nvic_fn", "08001000"),
    ]))
    mcp.add_response("decompile_function", "nvic_fn", _decompile_response(
        "void nvic_fn(void) {\n  *(uint *)0xE000E100 = 1;\n}"
    ))

    mm = _make_memory_map()
    mai = await build_memory_access_index(mm, mcp, "test-abc123")

    assert len(mai.mmio_accesses) == 1
    assert mai.mmio_accesses[0].target_addr == 0xE000E100


@pytest.mark.asyncio
async def test_build_index_isr_tagging():
    """ISR handler functions → in_isr=True, in mai.isr_functions."""
    mcp = MockMCPManager()
    mcp.add_response("search_symbols_by_name", "0", _symbols_response([
        ("TIM2_IRQHandler", "08002000"),
        ("main", "08000100"),
    ]))
    mcp.add_response("decompile_function", "TIM2_IRQHandler", _decompile_response(
        "void TIM2_IRQHandler(void) {\n  uVar1 = *(uint *)0x40011000;\n}"
    ))
    mcp.add_response("decompile_function", "main", _decompile_response(
        "void main(void) {\n  uVar1 = *(uint *)0x40011004;\n}"
    ))

    mm = _make_memory_map(isr_addrs=[0x08002000])
    mai = await build_memory_access_index(mm, mcp, "test-abc123")

    assert "TIM2_IRQHandler" in mai.isr_functions
    assert "main" not in mai.isr_functions

    # ISR function accesses should have in_isr=True
    isr_accesses = [a for a in mai.accesses if a.in_isr]
    non_isr = [a for a in mai.accesses if not a.in_isr]
    assert len(isr_accesses) == 1
    assert isr_accesses[0].function_name == "TIM2_IRQHandler"
    assert len(non_isr) == 1
    assert non_isr[0].function_name == "main"


@pytest.mark.asyncio
async def test_build_index_decompile_failure_graceful():
    """Failed decompile → skip function, no crash."""
    mcp = MockMCPManager()
    mcp.add_response("search_symbols_by_name", "0", _symbols_response([
        ("good_fn", "08001000"),
        ("bad_fn", "08002000"),
    ]))
    mcp.add_response("decompile_function", "good_fn", _decompile_response(
        "void good_fn(void) {\n  uVar1 = *(uint *)0x40011000;\n}"
    ))
    # bad_fn has no decompile response → returns None

    mm = _make_memory_map()
    mai = await build_memory_access_index(mm, mcp, "test-abc123")

    assert len(mai.accesses) == 1
    assert mai.accesses[0].function_name == "good_fn"


@pytest.mark.asyncio
async def test_build_index_no_functions_empty_mai():
    """0 functions enumerated → empty MAI."""
    mcp = MockMCPManager()
    mcp.add_response("search_symbols_by_name", "0", {"symbols": []})

    mm = _make_memory_map()
    mai = await build_memory_access_index(mm, mcp, "test-abc123")

    assert mai.accesses == []
    assert mai.mmio_accesses == []
    assert mai.isr_functions == []


@pytest.mark.asyncio
async def test_build_index_multiple_functions():
    """2 functions → accesses from both."""
    mcp = MockMCPManager()
    mcp.add_response("search_symbols_by_name", "0", _symbols_response([
        ("fn_a", "08001000"),
        ("fn_b", "08002000"),
    ]))
    mcp.add_response("decompile_function", "fn_a", _decompile_response(
        "void fn_a(void) {\n  uVar1 = *(uint *)0x40011000;\n}"
    ))
    mcp.add_response("decompile_function", "fn_b", _decompile_response(
        "void fn_b(void) {\n  *(ushort *)0x40012000 = sVar1;\n}"
    ))

    mm = _make_memory_map()
    mai = await build_memory_access_index(mm, mcp, "test-abc123")

    assert len(mai.accesses) == 2
    func_names = {a.function_name for a in mai.accesses}
    assert func_names == {"fn_a", "fn_b"}


@pytest.mark.asyncio
async def test_build_index_pagination():
    """150 functions across 2 pages → all enumerated."""
    mcp = MockMCPManager()

    # Page 1: 100 functions
    page1_funcs = [(f"FUN_{0x08001000 + i * 4:08x}", f"{0x08001000 + i * 4:08x}") for i in range(100)]
    mcp.add_response("search_symbols_by_name", "0", _symbols_response(page1_funcs))

    # Page 2: 50 functions
    page2_funcs = [(f"FUN_{0x08002000 + i * 4:08x}", f"{0x08002000 + i * 4:08x}") for i in range(50)]
    mcp.add_response("search_symbols_by_name", "100", _symbols_response(page2_funcs))

    # All functions have a simple decompile response
    for name, _ in page1_funcs + page2_funcs:
        mcp.add_response("decompile_function", name, _decompile_response(
            f"void {name}(void) {{\n  return;\n}}"
        ))

    mm = _make_memory_map()
    mai = await build_memory_access_index(mm, mcp, "test-abc123")

    # Verify pagination: should have called search_symbols_by_name twice
    search_calls = [c for c in mcp.call_log if c[1] == "search_symbols_by_name"]
    assert len(search_calls) == 2
    assert search_calls[0][2]["offset"] == 0
    assert search_calls[1][2]["offset"] == 100


@pytest.mark.asyncio
async def test_build_index_mcp_failure_returns_empty():
    """MCP connection failure → returns empty MAI (graceful degradation)."""
    mcp = FailingMCPManager()
    mm = _make_memory_map()
    mai = await build_memory_access_index(mm, mcp, "test-abc123")

    assert mai.accesses == []
    assert mai.mmio_accesses == []


# ── Flash constant pointer resolution tests ──────────────────────────────────


def _make_access(target_addr, provenance="CONST", kind="load", in_isr=False, func="fn"):
    """Build a MemoryAccess for flash ptr resolution testing."""
    return MemoryAccess(
        address=0x08001000,
        kind=kind,
        width=4,
        target_addr=target_addr,
        base_provenance=provenance,
        function_name=func,
        function_addr=0x08001000,
        in_isr=in_isr,
    )


def test_resolve_flash_const_ptrs_basic():
    """Flash CONST access with target in flash_ptr_table → resolved to MMIO."""
    accesses = [_make_access(0x08002200)]
    flash_ptr_table = {0x08002200: 0x40011000}

    resolved = _resolve_flash_const_ptrs(accesses, flash_ptr_table)

    assert len(resolved) == 1
    assert resolved[0].target_addr == 0x40011000
    assert resolved[0].base_provenance == "FLASH_CONST_PTR"


def test_resolve_flash_const_ptrs_preserves_unmatched():
    """Access not in flash_ptr_table → unchanged."""
    accesses = [_make_access(0x40011000)]
    flash_ptr_table = {0x08002200: 0x40011000}

    resolved = _resolve_flash_const_ptrs(accesses, flash_ptr_table)

    assert len(resolved) == 1
    assert resolved[0].target_addr == 0x40011000
    assert resolved[0].base_provenance == "CONST"


def test_resolve_flash_const_ptrs_non_const_skipped():
    """Non-CONST provenance → not resolved even if target is in table."""
    accesses = [_make_access(0x08002200, provenance="GLOBAL_PTR")]
    flash_ptr_table = {0x08002200: 0x40011000}

    resolved = _resolve_flash_const_ptrs(accesses, flash_ptr_table)

    assert len(resolved) == 1
    assert resolved[0].base_provenance == "GLOBAL_PTR"
    assert resolved[0].target_addr == 0x08002200


def test_resolve_flash_const_ptrs_preserves_isr():
    """ISR flag should be preserved through resolution."""
    accesses = [_make_access(0x08002200, in_isr=True)]
    flash_ptr_table = {0x08002200: 0x40011000}

    resolved = _resolve_flash_const_ptrs(accesses, flash_ptr_table)

    assert len(resolved) == 1
    assert resolved[0].in_isr is True
    assert resolved[0].base_provenance == "FLASH_CONST_PTR"


@pytest.mark.asyncio
async def test_build_index_with_flash_ptr_table():
    """build_memory_access_index with flash_ptr_table → resolves flash→MMIO."""
    mcp = MockMCPManager()
    mcp.add_response("search_symbols_by_name", "0", _symbols_response([
        ("read_periph", "08001000"),
    ]))
    mcp.add_response("decompile_function", "read_periph", _decompile_response(
        "uint read_periph(void) {\n  return *(uint *)0x08002200;\n}"
    ))

    flash_ptr_table = {0x08002200: 0x40011000}

    mm = _make_memory_map()
    mai = await build_memory_access_index(
        mm, mcp, "test-abc123", flash_ptr_table=flash_ptr_table,
    )

    assert len(mai.accesses) == 1
    assert mai.accesses[0].target_addr == 0x40011000
    assert mai.accesses[0].base_provenance == "FLASH_CONST_PTR"
    assert len(mai.mmio_accesses) == 1
    assert mai.mmio_accesses[0].target_addr == 0x40011000


# ── Nested parentheses regex tests (P0-T2) ──────────────────────────────────


def test_var_plus_const_nested_parens():
    """*(int *)((pin & 0xfffffff0) + 0x40010810) → matches with nested parens."""
    code = "  uVar1 = *(int *)((pin & 0xfffffff0) + 0x40010810);"
    accesses = parse_memory_accesses(code, "gpio_read", 0x08001000)
    assert len(accesses) == 1
    a = accesses[0]
    assert a.target_addr == 0x40010810
    assert a.base_provenance == "CONST"
    assert a.kind == "load"


def test_var_plus_const_nested_shift():
    """*(uint *)((uVar1 >> 4) + 0xe000e100) → matches nested shift expression."""
    code = "  *(uint *)((uVar1 >> 4) + 0xe000e100) = 1;"
    accesses = parse_memory_accesses(code, "nvic_enable", 0x08001000)
    assert len(accesses) == 1
    a = accesses[0]
    assert a.target_addr == 0xe000e100
    assert a.kind == "store"


def test_var_plus_const_simple_still_works():
    """*(uint *)(uVar3 + 0xe000ed1c) → simple case still works after regex change."""
    code = "  uVar1 = *(uint *)(uVar3 + 0xe000ed1c);"
    accesses = parse_memory_accesses(code, "scb_read", 0x08001000)
    assert len(accesses) == 1
    assert accesses[0].target_addr == 0xe000ed1c


# ── Decimal offset pattern tests (P0-T3) ────────────────────────────────────


def test_var_plus_decimal_mmio():
    """*(uint *)(uVar1 + 1073809416) where 1073809416=0x40010808 → MMIO target."""
    code = "  uVar1 = *(uint *)(uVar1 + 1073809416);"
    accesses = parse_memory_accesses(code, "gpio_read", 0x08001000)
    assert len(accesses) == 1
    a = accesses[0]
    assert a.target_addr == 0x40010808
    assert a.base_provenance == "CONST"
    assert a.kind == "load"


def test_var_plus_decimal_small_ignored():
    """*(uint *)(uVar1 + 8) → small decimal offset, NOT in MMIO range → no match."""
    code = "  uVar1 = *(uint *)(uVar1 + 8);"
    accesses = parse_memory_accesses(code, "struct_read", 0x08001000)
    # Small decimal is not MMIO; should not produce a CONST access
    mmio_accesses = [a for a in accesses if a.base_provenance == "CONST" and a.target_addr == 8]
    assert len(mmio_accesses) == 0


def test_var_plus_decimal_no_dup_with_hex():
    """When hex pattern matches, decimal pattern should not double-match."""
    code = "  uVar1 = *(uint *)(uVar3 + 0x40011000);"
    accesses = parse_memory_accesses(code, "uart_read", 0x08001000)
    # Should only match once via _RE_VAR_PLUS_CONST (hex), not also via decimal
    const_accesses = [a for a in accesses if a.base_provenance == "CONST"]
    assert len(const_accesses) == 1


# ── Intra-procedural base propagation tests (P1-T2) ─────────────────────────


def test_riot_direct_mmio_base_assign():
    """uVar1 = 0x40005400; *(uint *)(uVar1 + 0x14) → target=0x40005414."""
    code = """\
void i2c_read(void) {
    uint uVar1;
    uVar1 = 0x40005400;
    return *(uint *)(uVar1 + 0x14);
}"""
    accesses = parse_memory_accesses(code, "i2c_read", 0x08001000)
    intra = [a for a in accesses if a.base_provenance == "INTRA_RESOLVED"]
    assert len(intra) >= 1
    assert any(a.target_addr == 0x40005414 for a in intra)


def test_riot_computed_base_with_mmio_const():
    """uVar3 = (pin & 0xf) + 0x40010800; *(int *)(uVar3 + 0x10) → 0x40010810."""
    code = """\
void gpio_init(uint pin) {
    uint uVar3;
    uVar3 = (pin & 0xf) + 0x40010800;
    *(int *)(uVar3 + 0x10) = 1;
}"""
    accesses = parse_memory_accesses(code, "gpio_init", 0x08001000)
    # uVar3 = expr + 0x40010800 → base = 0x40010800
    # *(int *)(uVar3 + 0x10) → target = 0x40010800 + 0x10 = 0x40010810
    intra = [a for a in accesses if a.base_provenance == "INTRA_RESOLVED"]
    assert len(intra) >= 1
    assert any(a.target_addr == 0x40010810 for a in intra)


def test_riot_no_mmio_const_no_resolve():
    """uVar1 = pin & 0xfffffff0; *(uint *)(uVar1 + 0x8) → no INTRA_RESOLVED.

    0xfffffff0 is a mask, not an MMIO address (P6 mask filter).
    """
    code = """\
void gpio_read(uint pin) {
    uint uVar1;
    uVar1 = pin & 0xfffffff0;
    return *(uint *)(uVar1 + 0x8);
}"""
    accesses = parse_memory_accesses(code, "gpio_read", 0x08001000)
    intra = [a for a in accesses if a.base_provenance == "INTRA_RESOLVED"]
    assert len(intra) == 0


def test_intra_resolved_does_not_dup_hex_match():
    """When *(uint *)(uVar1 + 0x40010808) already matches _RE_VAR_PLUS_CONST,
    INTRA_RESOLVED should not duplicate it."""
    code = """\
void fn(void) {
    uint uVar1;
    uVar1 = 0x40010800;
    return *(uint *)(uVar1 + 0x40010808);
}"""
    accesses = parse_memory_accesses(code, "fn", 0x08001000)
    # The hex pattern should match *(uint *)(uVar1 + 0x40010808) → target=0x40010808
    # INTRA_RESOLVED would try *(uint *)(uVar1 + 0x40010808) but 0x40010808 >= 0x1000
    # so it's skipped by the offset threshold
    const_accesses = [a for a in accesses if a.base_provenance == "CONST"]
    assert len(const_accesses) >= 1


# ── P6: Mask constant filter tests ───────────────────────────────────────────


def test_mask_0xffffff00_filtered():
    """uVar1 = addr & 0xffffff00; → no INTRA_RESOLVED base."""
    code = """\
void fn(uint addr) {
    uint uVar1;
    uVar1 = addr & 0xffffff00;
    return *(uint *)(uVar1 + 0x10);
}"""
    accesses = parse_memory_accesses(code, "fn", 0x08001000)
    intra = [a for a in accesses if a.base_provenance == "INTRA_RESOLVED"]
    assert len(intra) == 0


def test_mask_does_not_affect_legitimate_base():
    """uVar1 = (pin & 0xf) + 0x40010800; → base IS 0x40010800 (not filtered)."""
    code = """\
void gpio_init(uint pin) {
    uint uVar3;
    uVar3 = (pin & 0xf) + 0x40010800;
    *(int *)(uVar3 + 0x10) = 1;
}"""
    accesses = parse_memory_accesses(code, "gpio_init", 0x08001000)
    intra = [a for a in accesses if a.base_provenance == "INTRA_RESOLVED"]
    assert len(intra) >= 1
    assert any(a.target_addr == 0x40010810 for a in intra)


def test_non_mask_high_address_kept():
    """uVar1 = 0xe000e010; → kept as base (no & in assignment, not a mask)."""
    code = """\
void systick(void) {
    uint uVar1;
    uVar1 = 0xe000e010;
    return *(uint *)(uVar1 + 0x4);
}"""
    accesses = parse_memory_accesses(code, "systick", 0x08001000)
    intra = [a for a in accesses if a.base_provenance == "INTRA_RESOLVED"]
    assert len(intra) >= 1
    assert any(a.target_addr == 0xe000e014 for a in intra)


def test_mask_0xfffff000_filtered():
    """GPIO page mask 0xfffff000 → filtered out."""
    code = """\
void gpio_page(uint pin) {
    uint uVar1;
    uVar1 = pin & 0xfffff000;
    *(uint *)(uVar1 + 0x8) = 1;
}"""
    accesses = parse_memory_accesses(code, "gpio_page", 0x08001000)
    intra = [a for a in accesses if a.base_provenance == "INTRA_RESOLVED"]
    assert len(intra) == 0


def test_is_mask_constant_direct():
    """Unit test for _is_mask_constant helper."""
    # True: mask with &
    assert _is_mask_constant(0xFFFFFFF0, "uVar1 = pin & 0xfffffff0;") is True
    assert _is_mask_constant(0xFFFFF000, "uVar1 = addr & 0xfffff000;") is True
    assert _is_mask_constant(0xFFFFFF00, "uVar1 = x & 0xffffff00;") is True
    # False: no & in context
    assert _is_mask_constant(0xFFFFFFF0, "uVar1 = 0xfffffff0;") is False
    # False: legitimate system address (not mask-shaped — has mixed bits)
    assert _is_mask_constant(0xE000E010, "uVar1 = x & 0xe000e010;") is False
    # False: below threshold
    assert _is_mask_constant(0x40010800, "uVar1 = x & 0x40010800;") is False
    # False: 0xFFFFFFFF (not a useful mask, inverted=0)
    assert _is_mask_constant(0xFFFFFFFF, "uVar1 = x & 0xffffffff;") is False


# ── Multi-MCU typed cast tests (P1-T3) ──────────────────────────────────────


def test_typed_cast_sam3_uart():
    """SAM3: (Uart *)0x400e0800 → recognized as typed MMIO base."""
    from sourceagent.pipeline.memory_access_index import _extract_typed_mmio_bases
    code = "  if (ptr == (Uart *)0x400e0800) {"
    bases = _extract_typed_mmio_bases(code, "test_fn")
    assert len(bases) == 1
    assert bases[0].peripheral_type == "Uart"
    assert bases[0].base_addr == 0x400e0800


def test_typed_cast_k64f_uart():
    """K64F: (UART_Type *)0x4006a000 → recognized as typed MMIO base."""
    from sourceagent.pipeline.memory_access_index import _extract_typed_mmio_bases
    code = "  var = (UART_Type *)0x4006a000;"
    bases = _extract_typed_mmio_bases(code, "test_fn")
    assert len(bases) == 1
    assert bases[0].peripheral_type == "UART_Type"
    assert bases[0].base_addr == 0x4006a000


def test_typed_cast_stm32_still_works():
    """STM32: (USART_TypeDef *)0x40013800 → still recognized (regression)."""
    from sourceagent.pipeline.memory_access_index import _extract_typed_mmio_bases
    code = "  if (ptr == (USART_TypeDef *)0x40013800) {"
    bases = _extract_typed_mmio_bases(code, "test_fn")
    assert len(bases) == 1
    assert bases[0].peripheral_type == "USART_TypeDef"


def test_typed_cast_non_peripheral_filtered():
    """Non-peripheral type: (int *)0x40013800 → NOT matched (filtered by ALL_STRUCT_OFFSETS)."""
    from sourceagent.pipeline.memory_access_index import _extract_typed_mmio_bases
    code = "  val = (int *)0x40013800;"
    bases = _extract_typed_mmio_bases(code, "test_fn")
    assert len(bases) == 0


def test_local_periph_decl_sam3():
    """SAM3 local var: Uart *pUVar2; → recognized as peripheral pointer."""
    from sourceagent.pipeline.memory_access_index import _extract_struct_field_accesses
    code = """\
void test_fn(void) {
    Uart *pUVar2;
    pUVar2->UART_SR;
}"""
    accesses = _extract_struct_field_accesses(code, "test_fn", 0x08001000)
    # Should recognize pUVar2 as Uart type and UART_SR as valid field
    uart_fields = [a for a in accesses if a.peripheral_type == "Uart"]
    assert len(uart_fields) >= 1
    assert uart_fields[0].field_name == "UART_SR"


def test_local_periph_decl_k64f():
    """K64F local var: UART_Type *pUVar3; → recognized as peripheral pointer."""
    from sourceagent.pipeline.memory_access_index import _extract_struct_field_accesses
    code = """\
void test_fn(void) {
    UART_Type *pUVar3;
    pUVar3->S1;
}"""
    accesses = _extract_struct_field_accesses(code, "test_fn", 0x08001000)
    uart_fields = [a for a in accesses if a.peripheral_type == "UART_Type"]
    assert len(uart_fields) >= 1
    assert uart_fields[0].field_name == "S1"
