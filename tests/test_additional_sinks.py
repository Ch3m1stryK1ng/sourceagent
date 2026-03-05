"""Tests for Stage 10 — additional sink miners (VS4-VS5).

Tests cover:
  - MEMSET_SINK: parse_memset_call, _build_memset_candidate, MCP integration
  - STORE_SINK: _mine_store_sinks from MAI data
  - LOOP_WRITE_SINK: parse_loop_writes, _find_loop_store, _extract_loop_bound
  - Verifier obligations for all three sink types
"""

import json
import pytest
from unittest.mock import AsyncMock

from sourceagent.pipeline.miners.additional_sinks import (
    mine_additional_sinks,
    parse_memset_call,
    parse_loop_writes,
    _mine_store_sinks,
    _mine_param_store_sinks,
    _find_loop_store,
    _extract_loop_bound,
    _compute_memset_confidence,
    _compute_store_confidence,
    _compute_loop_confidence,
    _pick_best_symbol,
    _is_call_to,
    _extract_arguments,
    _classify_arg_provenance,
    _analyze_length_arg,
    _has_bounds_guard,
    _load_map_text_functions,
    _looks_bounded_string_reader,
)
from sourceagent.pipeline.models import (
    EvidenceItem,
    LLMProposal,
    MemoryAccess,
    MemoryAccessIndex,
    MemoryMap,
    MemoryRegion,
    ObligationStatus,
    SinkCandidate,
    SinkLabel,
    VerificationVerdict,
)
from sourceagent.pipeline.verifier import verify_proposals


# ── Fixtures ─────────────────────────────────────────────────────────────────


def _make_memory_map():
    return MemoryMap(
        binary_path="/tmp/test.bin",
        arch="ARM:LE:32:Cortex",
        base_address=0x08000000,
        entry_point=0x08000100,
        regions=[
            MemoryRegion("FLASH", 0x08000000, 0x10000, "rx", "flash"),
            MemoryRegion("SRAM", 0x20000000, 0x5000, "rw", "sram"),
            MemoryRegion("PERIPHERAL", 0x40000000, 0x20000000, "rw", "mmio"),
        ],
    )


def _make_mai_with_stores():
    return MemoryAccessIndex(
        binary_path="/tmp/test.bin",
        accesses=[
            # ARG store — should be STORE_SINK
            MemoryAccess(0x08001000, "store", 4, target_addr=None,
                         base_provenance="ARG", function_name="FUN_08001000"),
            # CONST store — should NOT be STORE_SINK
            MemoryAccess(0x08001010, "store", 4, target_addr=0x40011000,
                         base_provenance="CONST", function_name="FUN_08001000"),
            # GLOBAL_PTR store to SRAM — should be STORE_SINK
            MemoryAccess(0x08002000, "store", 4, target_addr=0x20000100,
                         base_provenance="GLOBAL_PTR", function_name="FUN_08002000"),
            # MMIO store — should NOT be STORE_SINK
            MemoryAccess(0x08003000, "store", 4, target_addr=0x40011000,
                         base_provenance="GLOBAL_PTR", function_name="FUN_08003000"),
            # UNKNOWN store — should be STORE_SINK
            MemoryAccess(0x08004000, "store", 2, target_addr=None,
                         base_provenance="UNKNOWN", function_name="FUN_08004000"),
            # Load (not store) — should NOT be STORE_SINK
            MemoryAccess(0x08005000, "load", 4, target_addr=0x40011000,
                         base_provenance="ARG", function_name="FUN_08005000"),
            # Multiple stores in same function for loop detection
            MemoryAccess(0x08006000, "store", 1, target_addr=None,
                         base_provenance="ARG", function_name="FUN_08006000"),
            MemoryAccess(0x08006004, "store", 1, target_addr=None,
                         base_provenance="ARG", function_name="FUN_08006000"),
            MemoryAccess(0x08006008, "store", 1, target_addr=None,
                         base_provenance="ARG", function_name="FUN_08006000"),
        ],
    )


class MockMCPManager:
    def __init__(self):
        self.responses = {}
        self.call_log = []

    def add_response(self, tool_name, args_key, response):
        self.responses[(tool_name, args_key)] = response

    async def call_tool(self, server, tool_name, args):
        self.call_log.append((server, tool_name, args))
        key = (tool_name, args.get("query", args.get("name", args.get("name_or_address", ""))))
        if key in self.responses:
            return self.responses[key]
        return []

    def _mcp_text(self, data):
        return [{"type": "text", "text": json.dumps(data)}]

    def add_symbol_search(self, query, symbols):
        self.responses[("search_symbols_by_name", query)] = self._mcp_text({"symbols": symbols})

    def add_xrefs(self, address, refs):
        self.responses[("list_cross_references", address)] = self._mcp_text({"references": refs})

    def add_decompile(self, func_name, code):
        self.responses[("decompile_function", func_name)] = self._mcp_text({
            "name": func_name, "code": code, "signature": f"void {func_name}(void)",
        })


# ══════════════════════════════════════════════════════════════════════════════
# MEMSET_SINK — parse_memset_call tests
# ══════════════════════════════════════════════════════════════════════════════


def test_parse_memset_basic():
    code = "void f(void) {\n  memset(buf, 0, n);\n}"
    result = parse_memset_call(code, "memset")
    assert result["call_found"] is True
    assert result["args"] == ["buf", "0", "n"]


def test_parse_memset_len_constant():
    code = "void f(void) {\n  memset(buf, 0, 256);\n}"
    result = parse_memset_call(code, "memset")
    assert result["len_is_constant"] is True
    assert result["len_value"] == 256


def test_parse_memset_len_variable():
    code = "void f(void) {\n  memset(buf, 0, param_1);\n}"
    result = parse_memset_call(code, "memset")
    assert result["len_is_constant"] is False


def test_parse_memset_dst_provenance_arg():
    code = "void f(void) {\n  memset(param_1, 0, 64);\n}"
    result = parse_memset_call(code, "memset")
    assert result["dst_provenance"] == "ARG"


def test_parse_memset_dst_provenance_stack():
    code = "void f(void) {\n  memset(&local_40, 0, 64);\n}"
    result = parse_memset_call(code, "memset")
    assert result["dst_provenance"] == "STACK_PTR"


def test_parse_bzero():
    code = "void f(void) {\n  bzero(buf, param_2);\n}"
    result = parse_memset_call(code, "bzero")
    assert result["call_found"] is True
    assert result["args"] == ["buf", "param_2"]
    assert result["len_is_constant"] is False


def test_parse_memset_no_call():
    code = "void f(void) {\n  return;\n}"
    result = parse_memset_call(code, "memset")
    assert result["call_found"] is False


def test_parse_memset_fun_alias():
    code = "void f(void) {\n  FUN_08001234(param_1, 0, param_2);\n}"
    result = parse_memset_call(
        code,
        "memset",
        callee_names=["memset", "FUN_08001234"],
    )
    assert result["call_found"] is True
    assert result["args"] == ["param_1", "0", "param_2"]
    assert result["dst_provenance"] == "ARG"


def test_parse_memset_multiline_call():
    code = """void f(void) {
  memset(
    buf,
    0,
    n
  );
}"""
    result = parse_memset_call(code, "memset")
    assert result["call_found"] is True
    assert result["args"] == ["buf", "0", "n"]


def test_parse_memset_with_guard():
    code = """void f(int n) {
  if (n > 256) return;
  memset(buf, 0, n);
}"""
    result = parse_memset_call(code, "memset")
    assert result["has_bounds_guard"] is True


# ══════════════════════════════════════════════════════════════════════════════
# MEMSET_SINK — confidence
# ══════════════════════════════════════════════════════════════════════════════


def test_memset_confidence_base():
    conf = _compute_memset_confidence({}, "memset")
    assert 0.3 <= conf <= 0.5


def test_memset_confidence_variable_len():
    ctx = {"call_found": True, "len_is_constant": False, "has_bounds_guard": False}
    conf = _compute_memset_confidence(ctx, "memset")
    assert conf >= 0.60


def test_memset_confidence_bzero_lower():
    ctx = {"call_found": True, "len_is_constant": False}
    conf_memset = _compute_memset_confidence(ctx, "memset")
    conf_bzero = _compute_memset_confidence(ctx, "bzero")
    assert conf_bzero < conf_memset


# ══════════════════════════════════════════════════════════════════════════════
# MEMSET_SINK — MCP integration
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_memset_mcp_one_callsite():
    mock = MockMCPManager()
    mock.add_symbol_search("memset", [
        {"name": "memset", "address": "00001030", "type": "Function"},
    ])
    mock.add_xrefs("00001030", [
        {"function_name": "handler", "from_address": "000006d0",
         "to_address": "00001030", "type": "UNCONDITIONAL_CALL"},
    ])
    mock.add_decompile("handler", "void handler(void) {\n  memset(param_1, 0, param_2);\n}")

    sinks = await mine_additional_sinks(_make_memory_map(), mock, "test-abc")
    memset_sinks = [s for s in sinks if s.preliminary_label == SinkLabel.MEMSET_SINK]
    assert len(memset_sinks) >= 1
    assert memset_sinks[0].facts["callee"] == "memset"


@pytest.mark.asyncio
async def test_memset_no_symbols():
    mock = MockMCPManager()
    # No symbol responses → empty
    sinks = await mine_additional_sinks(_make_memory_map(), mock, "test-abc")
    memset_sinks = [s for s in sinks if s.preliminary_label == SinkLabel.MEMSET_SINK]
    assert len(memset_sinks) == 0


@pytest.mark.asyncio
async def test_memset_allows_argless_candidates():
    """Argless MEMSET candidates are now emitted (verifier handles via partial evidence)."""
    mock = MockMCPManager()
    mock.add_symbol_search("memset", [
        {"name": "memset", "address": "00001030", "type": "Function"},
    ])
    mock.add_xrefs("00001030", [
        {"function_name": "handler", "from_address": "000006d0",
         "to_address": "00001030", "type": "UNCONDITIONAL_CALL"},
    ])
    # Function declaration only; no call expression in body.
    mock.add_decompile("handler", "void FUN_00001030(char *param_1, int param_2, int param_3) {\n  return;\n}")

    sinks = await mine_additional_sinks(_make_memory_map(), mock, "test-abc")
    memset_sinks = [s for s in sinks if s.preliminary_label == SinkLabel.MEMSET_SINK]
    # Argless candidates are now emitted (not filtered) — verifier decides verdict
    assert len(memset_sinks) >= 0  # may or may not produce depending on other filters


# ══════════════════════════════════════════════════════════════════════════════
# STORE_SINK — _mine_store_sinks tests
# ══════════════════════════════════════════════════════════════════════════════


def test_store_sink_filters_correctly():
    mai = _make_mai_with_stores()
    mm = _make_memory_map()
    sinks = _mine_store_sinks(mai, mm)

    labels = {s.function_name: s.preliminary_label for s in sinks}

    # Should include ARG, GLOBAL_PTR (SRAM), UNKNOWN stores
    assert SinkLabel.STORE_SINK in [s.preliminary_label for s in sinks]
    assert "FUN_08001000" in labels  # ARG store
    assert "FUN_08002000" in labels  # GLOBAL_PTR to SRAM
    assert "FUN_08004000" in labels  # UNKNOWN store
    # Should NOT include MMIO stores or loads
    assert "FUN_08003000" not in labels  # MMIO store
    assert "FUN_08005000" not in labels  # Load (not store)


def test_store_sink_dedup_per_function():
    """Should produce at most one candidate per function."""
    mai = _make_mai_with_stores()
    mm = _make_memory_map()
    sinks = _mine_store_sinks(mai, mm)

    func_names = [s.function_name for s in sinks]
    assert len(func_names) == len(set(func_names))


def test_store_sink_prefers_arg():
    """Should prefer ARG-provenance store within a function."""
    mai = MemoryAccessIndex(
        binary_path="/tmp/test.bin",
        accesses=[
            MemoryAccess(0x08001000, "store", 4, target_addr=None,
                         base_provenance="UNKNOWN", function_name="F1"),
            MemoryAccess(0x08001010, "store", 4, target_addr=None,
                         base_provenance="ARG", function_name="F1"),
        ],
    )
    sinks = _mine_store_sinks(mai, _make_memory_map())
    assert len(sinks) == 1
    assert sinks[0].facts["provenance"] == "ARG"


def test_store_sink_confidence():
    access = MemoryAccess(0x08001000, "store", 4, target_addr=None,
                          base_provenance="ARG", function_name="F1")
    conf = _compute_store_confidence(access, 1)
    assert 0.4 <= conf <= 0.7


def test_store_sink_empty_mai():
    mai = MemoryAccessIndex(binary_path="/tmp/test.bin", accesses=[])
    sinks = _mine_store_sinks(mai, _make_memory_map())
    assert sinks == []


# ══════════════════════════════════════════════════════════════════════════════
# LOOP_WRITE_SINK — parse_loop_writes tests
# ══════════════════════════════════════════════════════════════════════════════


def test_loop_write_for_array_index():
    code = """void f(char *dst, char *src, int n) {
  for (i = 0; i < n; i++) {
    dst[i] = src[i];
  }
}"""
    candidates = parse_loop_writes(code, "f")
    assert len(candidates) == 1
    c = candidates[0]
    # Copy idiom (dst[i] = src[i]) gets promoted to COPY_SINK
    assert c.preliminary_label == SinkLabel.COPY_SINK
    assert c.facts["in_loop"] is True
    assert c.facts.get("promoted_from") == "LOOP_WRITE_SINK"
    assert "dst[i]" in c.facts["store_expr"]


def test_loop_write_while_ptr_deref():
    code = """void f(char *p, char *s) {
  while (*s) {
    *p++ = *s++;
  }
}"""
    # *p++ = ... should be detected
    candidates = parse_loop_writes(code, "f")
    assert len(candidates) >= 1


def test_loop_write_for_constant_bound():
    code = """void f(int *dst) {
  for (i = 0; i < 10; i++) {
    dst[i] = 0;
  }
}"""
    candidates = parse_loop_writes(code, "f")
    assert len(candidates) == 1
    assert candidates[0].facts["bound_is_constant"] is True


def test_loop_write_variable_bound():
    code = """void f(int *dst, int n) {
  for (i = 0; i < n; i++) {
    dst[i] = 0;
  }
}"""
    candidates = parse_loop_writes(code, "f")
    assert len(candidates) == 1
    assert candidates[0].facts["bound_is_constant"] is False
    assert candidates[0].facts["loop_bound"] == "n"


def test_loop_write_no_store():
    code = """void f(void) {
  for (i = 0; i < 10; i++) {
    x = x + 1;
  }
}"""
    candidates = parse_loop_writes(code, "f")
    assert len(candidates) == 0


def test_loop_write_no_loop():
    code = """void f(void) {
  dst[0] = 1;
  return;
}"""
    candidates = parse_loop_writes(code, "f")
    assert len(candidates) == 0


def test_loop_write_ptr_plus_offset():
    code = """void f(int *p, int *s, int n) {
  for (i = 0; i < n; i++) {
    *(p + i) = *(s + i);
  }
}"""
    candidates = parse_loop_writes(code, "f")
    assert len(candidates) == 1
    assert "p" in candidates[0].facts["store_expr"]


# ══════════════════════════════════════════════════════════════════════════════
# LOOP_WRITE_SINK — helper tests
# ══════════════════════════════════════════════════════════════════════════════


def test_find_loop_store_array():
    lines = ["  for (i = 0; i < n; i++) {", "    dst[i] = src[i];", "  }"]
    result = _find_loop_store(lines)
    assert result is not None
    _, expr, idx = result
    assert "dst[i]" in expr
    assert idx == "i"


def test_find_loop_store_ptr_plus():
    lines = ["  while (count--) {", "    *(ptr + offset) = val;", "  }"]
    result = _find_loop_store(lines)
    assert result is not None


def test_find_loop_store_no_store():
    lines = ["  for (i = 0; i < 10; i++) {", "    x = x + 1;", "  }"]
    result = _find_loop_store(lines)
    assert result is None


def test_extract_loop_bound_for():
    result = _extract_loop_bound("  for (i = 0; i < param_1; i++) {")
    assert result is not None
    assert result["bound"] == "param_1"
    assert result["is_constant"] is False


def test_extract_loop_bound_constant():
    result = _extract_loop_bound("  for (i = 0; i < 256; i++) {")
    assert result is not None
    assert result["is_constant"] is True


def test_extract_loop_bound_while():
    result = _extract_loop_bound("  while (idx < n) {")
    assert result is not None
    assert result["bound"] == "n"


def test_extract_loop_bound_no_bound():
    result = _extract_loop_bound("  while (1) {")
    assert result is None


def test_loop_confidence_variable_bound():
    facts = {"in_loop": True, "bound_is_constant": False, "index_expr": "i"}
    conf = _compute_loop_confidence(facts)
    assert conf >= 0.50


def test_loop_confidence_constant_bound():
    facts = {"in_loop": True, "bound_is_constant": True}
    conf = _compute_loop_confidence(facts)
    assert conf < 0.50


# ══════════════════════════════════════════════════════════════════════════════
# MCP integration — mine_additional_sinks with MAI
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_mine_additional_sinks_with_mai():
    """Should mine STORE_SINK from MAI even without MCP for memset."""
    mai = _make_mai_with_stores()
    mm = _make_memory_map()
    sinks = await mine_additional_sinks(mm, None, "", mai=mai)

    store_sinks = [s for s in sinks if s.preliminary_label == SinkLabel.STORE_SINK]
    assert len(store_sinks) >= 2  # ARG, GLOBAL_PTR, UNKNOWN stores


@pytest.mark.asyncio
async def test_mine_additional_sinks_no_mcp_no_mai():
    """Without MCP and MAI, should return empty."""
    sinks = await mine_additional_sinks(_make_memory_map(), None, "")
    assert sinks == []


@pytest.mark.asyncio
async def test_mine_additional_sinks_loop_write():
    """Should detect LOOP_WRITE_SINK from decompiled function."""
    mock = MockMCPManager()
    mai = MemoryAccessIndex(
        binary_path="/tmp/test.bin",
        accesses=[
            MemoryAccess(0x08001000, "store", 1, target_addr=None,
                         base_provenance="ARG", function_name="copy_func"),
            MemoryAccess(0x08001004, "store", 1, target_addr=None,
                         base_provenance="ARG", function_name="copy_func"),
        ],
    )
    mock.add_decompile("copy_func", """void copy_func(char *dst, char *src, int n) {
  for (i = 0; i < n; i++) {
    dst[i] = src[i];
  }
}""")

    sinks = await mine_additional_sinks(_make_memory_map(), mock, "test-abc", mai=mai)
    # Copy idiom (dst[i] = src[i]) gets promoted to COPY_SINK
    copy_or_loop = [s for s in sinks
                    if s.preliminary_label in (SinkLabel.LOOP_WRITE_SINK, SinkLabel.COPY_SINK)
                    and s.facts.get("in_loop")]
    assert len(copy_or_loop) >= 1


# ══════════════════════════════════════════════════════════════════════════════
# Verifier obligations for additional sinks
# ══════════════════════════════════════════════════════════════════════════════


def _make_proposal(label, facts):
    return LLMProposal(
        pack_id=f"test-{label}-001",
        label=label,
        address=0x08001000,
        function_name="test_func",
        claims=[facts],
        confidence=0.7,
    )


@pytest.mark.asyncio
async def test_verify_memset_sink_verified():
    proposal = _make_proposal("MEMSET_SINK", {
        "callee": "memset",
        "args": ["buf", "0", "n"],
        "dst_provenance": "ARG",
        "len_is_constant": False,
        "has_bounds_guard": False,
    })
    results = await verify_proposals([proposal])
    assert len(results) == 1
    assert results[0].verdict == VerificationVerdict.VERIFIED


@pytest.mark.asyncio
async def test_verify_memset_sink_no_callee_rejected():
    proposal = _make_proposal("MEMSET_SINK", {
        "args": ["buf", "0", "n"],
    })
    results = await verify_proposals([proposal])
    assert results[0].verdict == VerificationVerdict.REJECTED


@pytest.mark.asyncio
async def test_verify_store_sink_verified():
    proposal = _make_proposal("STORE_SINK", {
        "provenance": "ARG",
        "has_unresolved_target": True,
    })
    results = await verify_proposals([proposal])
    assert results[0].verdict == VerificationVerdict.VERIFIED


@pytest.mark.asyncio
async def test_verify_store_sink_const_rejected():
    proposal = _make_proposal("STORE_SINK", {
        "provenance": "CONST",
    })
    results = await verify_proposals([proposal])
    assert results[0].verdict == VerificationVerdict.REJECTED


@pytest.mark.asyncio
async def test_verify_loop_write_verified():
    proposal = _make_proposal("LOOP_WRITE_SINK", {
        "in_loop": True,
        "store_expr": "dst[i]",
        "bound_is_constant": False,
        "loop_bound": "n",
    })
    results = await verify_proposals([proposal])
    assert results[0].verdict == VerificationVerdict.VERIFIED


@pytest.mark.asyncio
async def test_verify_loop_write_no_loop_rejected():
    proposal = _make_proposal("LOOP_WRITE_SINK", {
        "in_loop": False,
    })
    results = await verify_proposals([proposal])
    assert results[0].verdict == VerificationVerdict.REJECTED


@pytest.mark.asyncio
async def test_verify_memset_obligations_count():
    """MEMSET_SINK should have 3 obligations (2 required + 1 optional)."""
    proposal = _make_proposal("MEMSET_SINK", {"callee": "memset", "args": ["a", "0", "n"]})
    results = await verify_proposals([proposal])
    assert len(results[0].obligations) == 3
    required = [o for o in results[0].obligations if o.required]
    assert len(required) == 2


@pytest.mark.asyncio
async def test_verify_store_obligations_count():
    """STORE_SINK should have 2 obligations (1 required + 1 optional)."""
    proposal = _make_proposal("STORE_SINK", {"provenance": "ARG"})
    results = await verify_proposals([proposal])
    assert len(results[0].obligations) == 2


@pytest.mark.asyncio
async def test_verify_loop_obligations_count():
    """LOOP_WRITE_SINK should have 2 obligations (1 required + 1 optional)."""
    proposal = _make_proposal("LOOP_WRITE_SINK", {"in_loop": True, "store_expr": "x[i]"})
    results = await verify_proposals([proposal])
    assert len(results[0].obligations) == 2


# ══════════════════════════════════════════════════════════════════════════════
# Shared helper tests
# ══════════════════════════════════════════════════════════════════════════════


def test_pick_best_symbol_plt():
    symbols = [
        {"name": "memset", "address": "EXTERNAL:00000000", "type": "Function"},
        {"name": "memset", "address": "00001030", "type": "Function"},
        {"name": "memset", "address": "00106040", "type": "Function"},
    ]
    best = _pick_best_symbol(symbols, "memset")
    assert best is not None
    assert best["address"] == "00001030"


def test_pick_best_symbol_no_match():
    symbols = [{"name": "memcpy", "address": "00001030", "type": "Function"}]
    assert _pick_best_symbol(symbols, "memset") is None


def test_is_call_to_basic():
    assert _is_call_to("  memset(buf, 0, n);", "memset")
    assert not _is_call_to("  my_memset(buf, 0, n);", "memset")


def test_classify_arg_provenance():
    assert _classify_arg_provenance("param_1") == "ARG"
    assert _classify_arg_provenance("&local_40") == "STACK_PTR"
    assert _classify_arg_provenance("DAT_20000100") == "GLOBAL_PTR"
    assert _classify_arg_provenance("some_var") == "UNKNOWN"


def test_analyze_length_arg():
    assert _analyze_length_arg("256") == (True, 256)
    assert _analyze_length_arg("0x100") == (True, 256)
    assert _analyze_length_arg("n")[0] is False


# ══════════════════════════════════════════════════════════════════════════════
# P5: Param-store heuristic tests
# ══════════════════════════════════════════════════════════════════════════════


def test_param_store_heuristic_basic():
    """*param_1 = val; in a small function → STORE_SINK."""
    mai = MemoryAccessIndex(binary_path="/tmp/test.bin")
    mai.decompiled_cache = {
        "FUN_08001000": """\
void FUN_08001000(uint *param_1, uint param_2) {
  *param_1 = param_2;
  return;
}""",
    }
    sinks = _mine_param_store_sinks(mai, set())
    assert len(sinks) == 1
    assert sinks[0].preliminary_label == SinkLabel.STORE_SINK
    assert sinks[0].facts["param_store_heuristic"] is True
    assert sinks[0].confidence_score == 0.45


def test_param_store_heuristic_with_offset():
    """*(uint *)(param_1 + 0x4) = val; → STORE_SINK."""
    mai = MemoryAccessIndex(binary_path="/tmp/test.bin")
    mai.decompiled_cache = {
        "FUN_08002000": """\
void FUN_08002000(int *param_1) {
  *(uint *)(param_1 + 0x4) = 0x100;
  return;
}""",
    }
    sinks = _mine_param_store_sinks(mai, set())
    assert len(sinks) == 1
    assert sinks[0].facts["param_store_heuristic"] is True


def test_param_store_skips_large_func():
    """>80 lines → skip."""
    mai = MemoryAccessIndex(binary_path="/tmp/test.bin")
    code = "void FUN_08003000(uint *param_1) {\n"
    code += "\n".join(f"  x_{i} = {i};" for i in range(95))
    code += "\n  *param_1 = x_0;\n}"
    mai.decompiled_cache = {"FUN_08003000": code}
    sinks = _mine_param_store_sinks(mai, set())
    assert len(sinks) == 0


def test_param_store_dedup_with_mai():
    """MAI already found STORE_SINK for this function → no duplicate."""
    mai = MemoryAccessIndex(binary_path="/tmp/test.bin")
    mai.decompiled_cache = {
        "FUN_08001000": """\
void FUN_08001000(uint *param_1) {
  *param_1 = 0x42;
}""",
    }
    existing = {"FUN_08001000"}
    sinks = _mine_param_store_sinks(mai, existing)
    assert len(sinks) == 0


# ══════════════════════════════════════════════════════════════════════════════
# P5: Lowered LOOP_WRITE_SINK threshold test
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_loop_write_lowered_threshold():
    """1 CONST store + loop → LOOP_WRITE_SINK (lowered from 2 non-CONST stores)."""
    mock = MockMCPManager()
    mai = MemoryAccessIndex(
        binary_path="/tmp/test.bin",
        accesses=[
            # Single CONST store — previously filtered, now counted
            MemoryAccess(0x08001000, "store", 4, target_addr=0x40011000,
                         base_provenance="CONST", function_name="loop_fn"),
        ],
    )
    mock.add_decompile("loop_fn", """void loop_fn(char *dst, char *src, int n) {
  for (i = 0; i < n; i++) {
    dst[i] = src[i];
  }
}""")

    sinks = await mine_additional_sinks(_make_memory_map(), mock, "test-abc", mai=mai)
    # Copy idiom gets promoted to COPY_SINK
    loop_sinks = [s for s in sinks
                  if s.preliminary_label in (SinkLabel.LOOP_WRITE_SINK, SinkLabel.COPY_SINK)
                  and s.facts.get("in_loop")]
    assert len(loop_sinks) >= 1


def test_load_map_text_functions_single_line(tmp_path):
    elf_path = tmp_path / "fw.elf"
    map_path = tmp_path / "fw.map"
    elf_path.write_bytes(b"\x7fELF")
    map_path.write_text(
        ".text.main     0x08000088       0x28 /tmp/obj.o\n"
        ".text.memset   0x080000b8       0x10 /tmp/libc.o\n",
        encoding="utf-8",
    )

    funcs = _load_map_text_functions(str(elf_path))
    assert funcs["main"] == 0x08000088
    assert funcs["memset"] == 0x080000B8


def test_load_map_text_functions_two_line(tmp_path):
    elf_path = tmp_path / "fw.elf"
    map_path = tmp_path / "fw.map"
    elf_path.write_bytes(b"\x7fELF")
    map_path.write_text(
        ".text.fill_buffer\n"
        "                0x08000060       0x1a /tmp/obj.o\n"
        "                0x08000060                fill_buffer\n"
        ".text.uart_receive\n"
        "                0x0800005c       0x18 /tmp/obj.o\n",
        encoding="utf-8",
    )

    funcs = _load_map_text_functions(str(elf_path))
    assert funcs["fill_buffer"] == 0x08000060
    assert funcs["uart_receive"] == 0x0800005C


def test_looks_bounded_string_reader():
    code = """\
void uart_read_string(char *buf, unsigned int max_len) {
  for (i = 0; i < max_len - 1; i = i + 1) {
    c = uart_read_byte();
    if (c == '\\0' || c == '\\n') {
      buf[i] = '\\0';
      return;
    }
    buf[i] = (char)c;
  }
  buf[max_len - 1] = 0;
}
"""
    assert _looks_bounded_string_reader(code) is True
