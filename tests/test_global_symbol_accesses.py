"""Tests for symbolic global variable resolution in memory_access_index.

Validates that parse_memory_accesses correctly resolves symbolic global
references (array indexing, pointer arithmetic) to SRAM addresses via
the global_symbol_table, which is critical for ISR_FILLED_BUFFER detection.
"""

import pytest

from sourceagent.pipeline.memory_access_index import parse_memory_accesses


# ── Fixture: a global symbol table mapping names → SRAM addresses ──────────

SYMBOL_TABLE = {
    "g_rx_buf": 0x20000008,
    "g_rx_head": 0x20000088,
    "g_rx_tail": 0x2000008C,
    "g_dma_buf": 0x20001000,
    "sensor_data": 0x20002000,
}

FUNC_NAME = "test_func"
FUNC_ADDR = 0x08000100


# ── Tests for Pattern 8: symbol[index] ─────────────────────────────────────


def test_global_array_store():
    """ISR writes: g_rx_buf[g_rx_head] = (char)val;"""
    code = '  g_rx_buf[g_rx_head] = (char)_DAT_40011004;'
    accesses = parse_memory_accesses(code, FUNC_NAME, FUNC_ADDR, SYMBOL_TABLE)

    # Should find: g_rx_buf[...] as store, g_rx_head as load (within brackets),
    # and _DAT_40011004 as load (MMIO). But g_rx_head is inside brackets of
    # g_rx_buf[...], so overlap handling applies.
    sram_stores = [a for a in accesses if a.target_addr == 0x20000008 and a.kind == "store"]
    assert len(sram_stores) >= 1, f"Expected store to g_rx_buf (0x20000008), got {accesses}"
    assert sram_stores[0].base_provenance == "GLOBAL_PTR"


def test_global_array_load():
    """Non-ISR reads: val = g_rx_buf[g_rx_tail];"""
    code = '  val = g_rx_buf[g_rx_tail];'
    accesses = parse_memory_accesses(code, FUNC_NAME, FUNC_ADDR, SYMBOL_TABLE)

    sram_loads = [a for a in accesses if a.target_addr == 0x20000008 and a.kind == "load"]
    assert len(sram_loads) >= 1, f"Expected load from g_rx_buf (0x20000008), got {accesses}"
    assert sram_loads[0].base_provenance == "GLOBAL_PTR"


def test_global_array_constant_index():
    """Direct constant index: g_dma_buf[0]"""
    code = '  x = g_dma_buf[0];'
    accesses = parse_memory_accesses(code, FUNC_NAME, FUNC_ADDR, SYMBOL_TABLE)

    dma_loads = [a for a in accesses if a.target_addr == 0x20001000 and a.kind == "load"]
    assert len(dma_loads) >= 1


def test_global_array_compound_assign():
    """Read-modify-write: g_rx_head = (g_rx_head + 1) & 0x7f;"""
    # g_rx_head doesn't have array indexing, so Pattern 8 won't match.
    # This is expected — bare scalar globals without [] are not matched.
    code = '  g_rx_head = (g_rx_head + 1) & 0x7f;'
    accesses = parse_memory_accesses(code, FUNC_NAME, FUNC_ADDR, SYMBOL_TABLE)
    # No array pattern, so no GLOBAL_PTR accesses expected
    gptr = [a for a in accesses if a.base_provenance == "GLOBAL_PTR"]
    assert len(gptr) == 0


# ── Tests for Pattern 9: *(type *)(symbol + offset) ───────────────────────


def test_global_ptr_arith():
    """Pointer arithmetic: *(uint *)(g_dma_buf + 4)"""
    code = '  x = *(uint *)(g_dma_buf + 4);'
    accesses = parse_memory_accesses(code, FUNC_NAME, FUNC_ADDR, SYMBOL_TABLE)

    gptr = [a for a in accesses if a.target_addr == 0x20001000 and a.base_provenance == "GLOBAL_PTR"]
    assert len(gptr) >= 1
    assert gptr[0].kind == "load"
    assert gptr[0].width == 4  # uint → 4 bytes


def test_global_ptr_arith_volatile():
    """Volatile cast: *(volatile uint *)(sensor_data + offset)"""
    code = '  val = *(volatile uint *)(sensor_data + uVar1);'
    accesses = parse_memory_accesses(code, FUNC_NAME, FUNC_ADDR, SYMBOL_TABLE)

    gptr = [a for a in accesses if a.target_addr == 0x20002000 and a.base_provenance == "GLOBAL_PTR"]
    assert len(gptr) >= 1


# ── Tests for exclusion of non-global names ────────────────────────────────


def test_c_keyword_excluded():
    """C keywords like 'int' should not match as global symbols."""
    # Even if somehow 'int' were in the symbol table, we exclude it
    bad_table = {"int": 0x20000000}
    code = '  int[0] = 5;'  # nonsensical but tests exclusion
    accesses = parse_memory_accesses(code, FUNC_NAME, FUNC_ADDR, bad_table)

    gptr = [a for a in accesses if a.base_provenance == "GLOBAL_PTR"]
    assert len(gptr) == 0


def test_local_var_not_matched():
    """Local variable names not in symbol table should be ignored."""
    code = '  local_buf[0] = 5;'
    accesses = parse_memory_accesses(code, FUNC_NAME, FUNC_ADDR, SYMBOL_TABLE)

    gptr = [a for a in accesses if a.base_provenance == "GLOBAL_PTR"]
    assert len(gptr) == 0


def test_ghidra_auto_var_excluded():
    """Ghidra auto-generated names like uVar1 should not match."""
    weird_table = {"uVar1": 0x20000000}
    code = '  uVar1[0] = 5;'
    accesses = parse_memory_accesses(code, FUNC_NAME, FUNC_ADDR, weird_table)

    gptr = [a for a in accesses if a.base_provenance == "GLOBAL_PTR"]
    assert len(gptr) == 0


# ── Test: no symbol table → no GLOBAL_PTR accesses ────────────────────────


def test_no_symbol_table():
    """Without a symbol table, symbolic globals should not be resolved."""
    code = '  g_rx_buf[g_rx_head] = val;'
    accesses = parse_memory_accesses(code, FUNC_NAME, FUNC_ADDR, global_symbol_table=None)

    gptr = [a for a in accesses if a.base_provenance == "GLOBAL_PTR"]
    assert len(gptr) == 0


# ── Test: overlap with existing patterns ───────────────────────────────────


def test_dat_pattern_takes_precedence():
    """DAT_ patterns should take precedence over symbolic matching."""
    # _DAT_20000008 is a known pattern; if symbol table also has g_rx_buf→0x20000008
    # the DAT_ pattern should fire first (more specific).
    code = '  _DAT_20000008 = val;'
    accesses = parse_memory_accesses(code, FUNC_NAME, FUNC_ADDR, SYMBOL_TABLE)

    const_accesses = [a for a in accesses if a.base_provenance == "CONST"]
    assert len(const_accesses) >= 1
    assert const_accesses[0].target_addr == 0x20000008


def test_mmio_and_sram_on_same_line():
    """Mixed line: g_rx_buf[head] = (char)_DAT_40011004;"""
    code = '  g_rx_buf[g_rx_head] = (char)_DAT_40011004;'
    accesses = parse_memory_accesses(code, FUNC_NAME, FUNC_ADDR, SYMBOL_TABLE)

    # Should have both: MMIO load (_DAT_40011004) and SRAM store (g_rx_buf)
    mmio = [a for a in accesses if a.target_addr == 0x40011004]
    sram = [a for a in accesses if a.target_addr == 0x20000008]
    assert len(mmio) >= 1, "Should detect MMIO read from _DAT_40011004"
    assert len(sram) >= 1, "Should detect SRAM write to g_rx_buf"


# ── Integration test: realistic ISR decompilation output ───────────────────


def test_realistic_isr_handler():
    """Simulate Ghidra decompilation of USART1_IRQHandler with debug symbols."""
    code = """
void USART1_IRQHandler(void)
{
  if ((_DAT_40011000 & 0x20) != 0) {
    g_rx_buf[g_rx_head] = (char)_DAT_40011004;
    g_rx_head = (g_rx_head + 1) & 0x7f;
  }
  return;
}
"""
    accesses = parse_memory_accesses(
        code, "USART1_IRQHandler", 0x08000060, SYMBOL_TABLE,
    )

    # Expect: MMIO reads (0x40011000, 0x40011004) and SRAM store (g_rx_buf)
    mmio_reads = [a for a in accesses if a.target_addr is not None and 0x40000000 <= a.target_addr <= 0x5FFFFFFF]
    sram_writes = [a for a in accesses if a.target_addr == 0x20000008 and a.kind == "store"]

    assert len(mmio_reads) >= 2, f"Expected >=2 MMIO reads, got {mmio_reads}"
    assert len(sram_writes) >= 1, f"Expected SRAM store to g_rx_buf, got {sram_writes}"
    assert sram_writes[0].base_provenance == "GLOBAL_PTR"


def test_realistic_process_function():
    """Simulate non-ISR function reading from the shared buffer."""
    code = """
void process_packet(void)
{
  while (g_rx_tail != g_rx_head) {
    local_buf[idx] = g_rx_buf[g_rx_tail];
    g_rx_tail = (g_rx_tail + 1) & 0x7f;
    idx = idx + 1;
  }
  return;
}
"""
    accesses = parse_memory_accesses(
        code, "process_packet", 0x08000100, SYMBOL_TABLE,
    )

    sram_loads = [a for a in accesses if a.target_addr == 0x20000008 and a.kind == "load"]
    assert len(sram_loads) >= 1, f"Expected SRAM load from g_rx_buf, got {sram_loads}"
    assert sram_loads[0].base_provenance == "GLOBAL_PTR"
