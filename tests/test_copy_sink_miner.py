"""Tests for pipeline/miners/copy_sink.py — Stage 4 (VS1)."""

import json
import pytest

from sourceagent.pipeline.models import MemoryAccessIndex, MemoryMap, SinkLabel
from sourceagent.pipeline.miners.copy_sink import (
    COPY_FUNCTION_NAMES,
    mine_copy_sinks,
    parse_call_context,
    _is_call_to,
    _extract_arguments,
    _split_args,
    _classify_arg_provenance,
    _analyze_length_arg,
    _has_bounds_guard,
    _pick_best_symbol,
    _compute_confidence,
    _find_copy_symbols,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_mm():
    return MemoryMap(
        binary_path="test.bin",
        arch="ARM:LE:32:Cortex",
        base_address=0x08000000,
        entry_point=0x08000101,
    )


def _mcp_text(data: dict) -> list:
    return [{"type": "text", "text": json.dumps(data)}]


class MockMCPManager:
    """Mock MCP manager that returns pre-configured responses."""

    def __init__(self):
        self.responses = {}
        self.call_log = []

    def add_response(self, tool_name, args_match, response):
        """Register a response for a tool call."""
        key = (tool_name, json.dumps(args_match, sort_keys=True))
        self.responses[key] = response

    def add_symbol_search(self, query, symbols):
        """Helper: register symbol search response."""
        self.add_response("search_symbols_by_name",
            {"binary_name": "test-abc123", "query": query, "limit": 20},
            _mcp_text({"symbols": symbols}))

    def add_xrefs(self, address, references):
        """Helper: register xref response."""
        self.add_response("list_cross_references",
            {"binary_name": "test-abc123", "name_or_address": address},
            _mcp_text({"references": references}))

    def add_decompile(self, func_name, code):
        """Helper: register decompile response."""
        self.add_response("decompile_function",
            {"binary_name": "test-abc123", "name_or_address": func_name},
            _mcp_text({"decompiled_code": code}))

    async def call_tool(self, server, tool_name, args):
        self.call_log.append((tool_name, args))
        key = (tool_name, json.dumps(args, sort_keys=True))
        if key in self.responses:
            return self.responses[key]
        # Fallback: try matching just tool name with partial args
        for (tn, _), resp in self.responses.items():
            if tn == tool_name:
                return resp
        return None


# ── Canonical names ──────────────────────────────────────────────────────────


def test_copy_function_names_includes_memcpy():
    """The canonical copy function list must include memcpy."""
    assert "memcpy" in COPY_FUNCTION_NAMES
    assert "memmove" in COPY_FUNCTION_NAMES
    assert "__aeabi_memcpy" in COPY_FUNCTION_NAMES


def test_copy_function_names_includes_string_funcs():
    """Should also include string copy functions."""
    assert "strcpy" in COPY_FUNCTION_NAMES
    assert "strncpy" in COPY_FUNCTION_NAMES
    assert "sprintf" in COPY_FUNCTION_NAMES


def test_sink_label_copy_sink_value():
    """COPY_SINK label should have the expected string value."""
    assert SinkLabel.COPY_SINK.value == "COPY_SINK"


# ── _is_call_to ──────────────────────────────────────────────────────────────


def test_is_call_to_basic():
    assert _is_call_to("  memcpy(dst, src, n);", "memcpy") is True


def test_is_call_to_with_cast():
    assert _is_call_to("  memcpy((void *)dst, src, n);", "memcpy") is True


def test_is_call_to_no_match():
    assert _is_call_to("  strcpy(dst, src);", "memcpy") is False


def test_is_call_to_substring_no_match():
    """Should not match 'my_memcpy' when looking for 'memcpy'."""
    assert _is_call_to("  my_memcpy(dst, src, n);", "memcpy") is False


def test_is_call_to_method_no_match():
    """Should not match 'obj.memcpy(...)' as memcpy."""
    assert _is_call_to("  obj.memcpy(dst, src, n);", "memcpy") is False


# ── _extract_arguments ───────────────────────────────────────────────────────


def test_extract_args_memcpy():
    args = _extract_arguments("  memcpy(dst, src, 256);", "memcpy")
    assert args == ["dst", "src", "256"]


def test_extract_args_nested_parens():
    args = _extract_arguments("  memcpy((char *)dst, (char *)src, sizeof(buf));", "memcpy")
    assert len(args) == 3
    assert "(char *)dst" in args[0]
    assert "sizeof(buf)" in args[2]


def test_extract_args_sprintf():
    args = _extract_arguments('  sprintf(buf, "%s:%d", name, port);', "sprintf")
    assert len(args) == 4
    assert args[0] == "buf"


def test_extract_args_no_args():
    args = _extract_arguments("  unrelated_func();", "memcpy")
    assert args == []


def test_extract_args_snprintf():
    args = _extract_arguments("  snprintf(buf, 64, fmt, val);", "snprintf")
    assert args == ["buf", "64", "fmt", "val"]


# ── _split_args ──────────────────────────────────────────────────────────────


def test_split_args_simple():
    assert _split_args("a, b, c") == ["a", "b", "c"]


def test_split_args_nested():
    assert _split_args("(char *)a, b") == ["(char *)a", "b"]


def test_split_args_empty():
    assert _split_args("") == []


def test_split_args_single():
    assert _split_args("x") == ["x"]


# ── _classify_arg_provenance ─────────────────────────────────────────────────


def test_classify_stack():
    assert _classify_arg_provenance("&local_20") == "STACK_PTR"
    assert _classify_arg_provenance("local_20") == "STACK_PTR"
    assert _classify_arg_provenance("auStack_80") == "STACK_PTR"


def test_classify_global():
    assert _classify_arg_provenance("DAT_20001000") == "GLOBAL_PTR"
    assert _classify_arg_provenance("0x20001000") == "GLOBAL_PTR"


def test_classify_arg():
    assert _classify_arg_provenance("param_1") == "ARG"
    assert _classify_arg_provenance("param_2") == "ARG"


def test_classify_cast_unwrap():
    """Cast expressions should unwrap to inner provenance."""
    assert _classify_arg_provenance("(char *)param_1") == "ARG"
    assert _classify_arg_provenance("(void *)&local_20") == "STACK_PTR"


def test_classify_unknown():
    assert _classify_arg_provenance("some_var") == "UNKNOWN"


# ── _analyze_length_arg ──────────────────────────────────────────────────────


def test_len_decimal_constant():
    is_const, val = _analyze_length_arg("256")
    assert is_const is True
    assert val == 256


def test_len_hex_constant():
    is_const, val = _analyze_length_arg("0x100")
    assert is_const is True
    assert val == 256


def test_len_sizeof():
    is_const, val = _analyze_length_arg("sizeof(buf)")
    assert is_const is True
    assert val is None  # Value unknown but constant


def test_len_cast_constant():
    is_const, val = _analyze_length_arg("(size_t)256")
    assert is_const is True
    assert val == 256


def test_len_variable():
    is_const, val = _analyze_length_arg("n")
    assert is_const is False
    assert val is None


def test_len_expression():
    is_const, val = _analyze_length_arg("param_2 + 4")
    assert is_const is False


# ── _has_bounds_guard ────────────────────────────────────────────────────────


def test_bounds_guard_if_greater():
    lines = [
        "  if (n > 256) n = 256;",
        "  memcpy(dst, src, n);",
    ]
    assert _has_bounds_guard(lines, 1) is True


def test_bounds_guard_if_return():
    lines = [
        "  if (n > max_size) return;",
        "  memcpy(dst, src, n);",
    ]
    assert _has_bounds_guard(lines, 1) is True


def test_bounds_guard_min():
    lines = [
        "  n = MIN(n, 256);",
        "  memcpy(dst, src, n);",
    ]
    assert _has_bounds_guard(lines, 1) is True


def test_bounds_guard_ternary():
    lines = [
        "  n = (n > 256) ? 256 : n;",
        "  memcpy(dst, src, n);",
    ]
    assert _has_bounds_guard(lines, 1) is True


def test_no_bounds_guard():
    lines = [
        "  int x = 5;",
        "  memcpy(dst, src, n);",
    ]
    assert _has_bounds_guard(lines, 1) is False


# ── _pick_best_symbol ────────────────────────────────────────────────────────


def test_pick_best_symbol_plt():
    """Should pick lowest non-EXTERNAL address (PLT thunk)."""
    symbols = [
        {"name": "memcpy", "address": "EXTERNAL:00000001", "type": "Function"},
        {"name": "memcpy", "address": "00101100", "type": "Function"},  # PLT
        {"name": "memcpy", "address": "00106500", "type": "Function"},  # GOT
    ]
    best = _pick_best_symbol(symbols, "memcpy")
    assert best is not None
    assert best["address"] == "00101100"


def test_pick_best_symbol_no_match():
    symbols = [
        {"name": "strcmp", "address": "00101100", "type": "Function"},
    ]
    assert _pick_best_symbol(symbols, "memcpy") is None


def test_pick_best_symbol_close_match():
    """Should match '_memcpy' when searching for 'memcpy'."""
    symbols = [
        {"name": "_memcpy", "address": "00101100", "type": "Function"},
    ]
    best = _pick_best_symbol(symbols, "memcpy")
    assert best is not None


# ── parse_call_context (pure function) ───────────────────────────────────────


def test_parse_context_memcpy_basic():
    """memcpy with constant length should be detected."""
    code = """\
void handler(void) {
  char buf[64];
  memcpy(buf, src, 64);
}
"""
    ctx = parse_call_context(code, "memcpy")
    assert ctx["call_found"] is True
    assert len(ctx["args"]) == 3
    assert ctx["len_is_constant"] is True
    assert ctx["len_value"] == 64


def test_parse_context_memcpy_variable_len():
    """memcpy with variable length should flag runtime-derived."""
    code = """\
void handler(char *dst, char *src, int n) {
  memcpy(dst, src, n);
}
"""
    ctx = parse_call_context(code, "memcpy")
    assert ctx["call_found"] is True
    assert ctx["len_is_constant"] is False
    assert ctx["dst_provenance"] == "UNKNOWN"


def test_parse_context_memcpy_stack_dst():
    """Stack-local destination should be classified."""
    code = """\
void handler(void) {
  memcpy(&local_20, src, n);
}
"""
    ctx = parse_call_context(code, "memcpy")
    assert ctx["dst_provenance"] == "STACK_PTR"


def test_parse_context_memcpy_param_dst():
    """Param destination should be classified as ARG."""
    code = """\
void handler(char *param_1, char *param_2, int param_3) {
  memcpy(param_1, param_2, param_3);
}
"""
    ctx = parse_call_context(code, "memcpy")
    assert ctx["dst_provenance"] == "ARG"
    assert ctx["len_is_constant"] is False


def test_parse_context_strcpy():
    """strcpy has no length arg → len_is_constant should be False."""
    code = """\
void handler(void) {
  strcpy(&local_20, src);
}
"""
    ctx = parse_call_context(code, "strcpy")
    assert ctx["call_found"] is True
    assert ctx["len_is_constant"] is False
    assert ctx["dst_provenance"] == "STACK_PTR"


def test_parse_context_snprintf():
    """snprintf length is arg index 1."""
    code = """\
void handler(void) {
  snprintf(buf, 256, "%s", name);
}
"""
    ctx = parse_call_context(code, "snprintf")
    assert ctx["call_found"] is True
    assert ctx["len_is_constant"] is True
    assert ctx["len_value"] == 256


def test_parse_context_with_guard():
    """Bounds guard before call should be detected."""
    code = """\
void handler(char *dst, char *src, int n) {
  if (n > 256) n = 256;
  memcpy(dst, src, n);
}
"""
    ctx = parse_call_context(code, "memcpy")
    assert ctx["has_bounds_guard"] is True


def test_parse_context_no_guard():
    """Missing bounds guard should be flagged."""
    code = """\
void handler(char *dst, char *src, int n) {
  memcpy(dst, src, n);
}
"""
    ctx = parse_call_context(code, "memcpy")
    assert ctx["has_bounds_guard"] is False


def test_parse_context_no_call():
    """Code without the callee should return call_found=False."""
    code = """\
void handler(void) {
  printf("hello");
}
"""
    ctx = parse_call_context(code, "memcpy")
    assert ctx["call_found"] is False


def test_parse_context_global_dst():
    """DAT_ destination should classify as GLOBAL_PTR."""
    code = """\
void handler(void) {
  memcpy(DAT_20001000, src, 32);
}
"""
    ctx = parse_call_context(code, "memcpy")
    assert ctx["dst_provenance"] == "GLOBAL_PTR"


def test_parse_context_fun_alias():
    """Should parse calls routed through FUN_xxx aliases."""
    code = """\
void handler(char *param_1, char *param_2, int param_3) {
  FUN_08001234(param_1, param_2, param_3);
}
"""
    ctx = parse_call_context(
        code,
        "memcpy",
        callee_names=["memcpy", "FUN_08001234"],
    )
    assert ctx["call_found"] is True
    assert len(ctx["args"]) == 3
    assert ctx["dst_provenance"] == "ARG"


def test_parse_context_multiline_call():
    """Multi-line calls should still recover all arguments."""
    code = """\
void handler(char *param_1, char *param_2, int param_3) {
  memcpy(
    param_1,
    param_2,
    param_3
  );
}
"""
    ctx = parse_call_context(code, "memcpy")
    assert ctx["call_found"] is True
    assert len(ctx["args"]) == 3
    assert ctx["len_is_constant"] is False


def test_parse_context_definition_not_counted_as_call():
    """Function definition lines should not be interpreted as callsites."""
    code = """\
void FUN_080000dc(char *param_1, char *param_2, int param_3) {
  return;
}
"""
    ctx = parse_call_context(
        code,
        "memcpy",
        callee_names=["memcpy", "FUN_080000dc"],
    )
    assert ctx["call_found"] is False
    assert ctx["args"] == []


# ── _compute_confidence ──────────────────────────────────────────────────────


def test_confidence_strcpy_no_guard():
    """strcpy without guard should have high confidence."""
    ctx = {"call_found": True, "len_is_constant": False, "has_bounds_guard": False,
           "dst_provenance": "ARG"}
    score = _compute_confidence(ctx, "strcpy")
    assert score >= 0.80  # No len arg + no guard + ARG dst


def test_confidence_memcpy_const_len():
    """memcpy with constant length should have lower confidence."""
    ctx = {"call_found": True, "len_is_constant": True, "has_bounds_guard": True,
           "dst_provenance": "STACK_PTR"}
    score = _compute_confidence(ctx, "memcpy")
    assert score < 0.60  # Has length + has guard


def test_confidence_memcpy_variable_no_guard():
    """memcpy with variable length and no guard → medium-high."""
    ctx = {"call_found": True, "len_is_constant": False, "has_bounds_guard": False,
           "dst_provenance": "STACK_PTR"}
    score = _compute_confidence(ctx, "memcpy")
    assert 0.60 <= score <= 0.80


def test_confidence_capped():
    """Confidence should never exceed 0.95."""
    ctx = {"call_found": True, "len_is_constant": False, "has_bounds_guard": False,
           "dst_provenance": "ARG"}
    score = _compute_confidence(ctx, "strcpy")
    assert score <= 0.95


# ── End-to-end with MockMCPManager ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_mine_no_mcp():
    """No MCP manager should return empty."""
    result = await mine_copy_sinks(_make_mm(), None, "test-abc123")
    assert result == []


@pytest.mark.asyncio
async def test_mine_no_symbols_found():
    """No matching symbols → empty results."""
    mcp = MockMCPManager()
    # Register empty responses for all copy function searches
    for name in COPY_FUNCTION_NAMES:
        mcp.add_symbol_search(name, [])

    result = await mine_copy_sinks(_make_mm(), mcp, "test-abc123")
    assert result == []


@pytest.mark.asyncio
async def test_mine_memcpy_one_callsite():
    """Single memcpy callsite → one COPY_SINK candidate."""
    mcp = MockMCPManager()

    # memcpy symbol found
    mcp.add_symbol_search("memcpy", [
        {"name": "memcpy", "address": "00101100", "type": "Function"},
    ])
    # All other symbols not found
    for name in COPY_FUNCTION_NAMES:
        if name != "memcpy":
            mcp.add_symbol_search(name, [])

    # One xref to memcpy
    mcp.add_xrefs("00101100", [
        {"function_name": "handler", "from_address": "08001234",
         "type": "UNCONDITIONAL_CALL"},
    ])

    # Decompile handler
    mcp.add_decompile("handler", """\
void handler(char *param_1, char *param_2, int param_3) {
  memcpy(param_1, param_2, param_3);
}
""")

    result = await mine_copy_sinks(_make_mm(), mcp, "test-abc123")

    assert len(result) == 1
    c = result[0]
    assert c.preliminary_label == SinkLabel.COPY_SINK
    assert c.function_name == "handler"
    assert c.facts["callee"] == "memcpy"
    assert c.facts["dst_provenance"] == "ARG"
    assert c.facts["len_is_constant"] is False


@pytest.mark.asyncio
async def test_mine_memcpy_with_guard():
    """memcpy with bounds guard → has_bounds_guard=True."""
    mcp = MockMCPManager()

    mcp.add_symbol_search("memcpy", [
        {"name": "memcpy", "address": "00101100", "type": "Function"},
    ])
    for name in COPY_FUNCTION_NAMES:
        if name != "memcpy":
            mcp.add_symbol_search(name, [])

    mcp.add_xrefs("00101100", [
        {"function_name": "safe_copy", "from_address": "08002000",
         "type": "UNCONDITIONAL_CALL"},
    ])

    mcp.add_decompile("safe_copy", """\
void safe_copy(char *dst, char *src, int n) {
  if (n > 256) n = 256;
  memcpy(dst, src, n);
}
""")

    result = await mine_copy_sinks(_make_mm(), mcp, "test-abc123")

    assert len(result) == 1
    assert result[0].facts["has_bounds_guard"] is True


@pytest.mark.asyncio
async def test_mine_multiple_callees():
    """Multiple copy functions found → candidates from each."""
    mcp = MockMCPManager()

    mcp.add_symbol_search("memcpy", [
        {"name": "memcpy", "address": "00101100", "type": "Function"},
    ])
    mcp.add_symbol_search("strcpy", [
        {"name": "strcpy", "address": "00101200", "type": "Function"},
    ])
    for name in COPY_FUNCTION_NAMES:
        if name not in ("memcpy", "strcpy"):
            mcp.add_symbol_search(name, [])

    mcp.add_xrefs("00101100", [
        {"function_name": "func_a", "from_address": "08001000",
         "type": "UNCONDITIONAL_CALL"},
    ])
    mcp.add_xrefs("00101200", [
        {"function_name": "func_b", "from_address": "08002000",
         "type": "UNCONDITIONAL_CALL"},
    ])

    mcp.add_decompile("func_a", "void func_a(void) { memcpy(&local_20, src, n); }")
    mcp.add_decompile("func_b", "void func_b(void) { strcpy(&local_40, src); }")

    result = await mine_copy_sinks(_make_mm(), mcp, "test-abc123")

    assert len(result) == 2
    callees = {c.facts["callee"] for c in result}
    assert "memcpy" in callees
    assert "strcpy" in callees


@pytest.mark.asyncio
async def test_mine_dedup_same_caller_callee():
    """Exact duplicate xrefs should be deduped."""
    mcp = MockMCPManager()

    mcp.add_symbol_search("memcpy", [
        {"name": "memcpy", "address": "00101100", "type": "Function"},
    ])
    for name in COPY_FUNCTION_NAMES:
        if name != "memcpy":
            mcp.add_symbol_search(name, [])

    # Two identical xrefs from same function to same callee
    mcp.add_xrefs("00101100", [
        {"function_name": "handler", "from_address": "08001234",
         "type": "UNCONDITIONAL_CALL"},
        {"function_name": "handler", "from_address": "08001234",
         "type": "UNCONDITIONAL_CALL"},
    ])

    mcp.add_decompile("handler", "void handler(void) { memcpy(dst, src, 64); }")

    result = await mine_copy_sinks(_make_mm(), mcp, "test-abc123")
    assert len(result) == 1


@pytest.mark.asyncio
async def test_mine_keeps_truncated_memcpy_args_if_call_parsed():
    """If call is parsed, candidate is kept even with short arg list."""
    mcp = MockMCPManager()

    mcp.add_symbol_search("memcpy", [
        {"name": "memcpy", "address": "00101100", "type": "Function"},
    ])
    for name in COPY_FUNCTION_NAMES:
        if name != "memcpy":
            mcp.add_symbol_search(name, [])

    mcp.add_xrefs("00101100", [
        {"function_name": "handler", "from_address": "08001234",
         "type": "UNCONDITIONAL_CALL"},
    ])
    mcp.add_decompile("handler", """\
void handler(char *param_1, char *param_2) {
  memcpy(param_1, param_2);
}
""")

    result = await mine_copy_sinks(_make_mm(), mcp, "test-abc123")
    assert len(result) == 1
    assert result[0].facts["args"] == ["param_1", "param_2"]


@pytest.mark.asyncio
async def test_mine_skips_data_refs():
    """DATA type xrefs should be skipped (only CALL refs matter)."""
    mcp = MockMCPManager()

    mcp.add_symbol_search("memcpy", [
        {"name": "memcpy", "address": "00101100", "type": "Function"},
    ])
    for name in COPY_FUNCTION_NAMES:
        if name != "memcpy":
            mcp.add_symbol_search(name, [])

    mcp.add_xrefs("00101100", [
        {"function_name": "data_user", "from_address": "08001234",
         "type": "DATA"},
    ])

    result = await mine_copy_sinks(_make_mm(), mcp, "test-abc123")
    assert result == []


@pytest.mark.asyncio
async def test_mine_evidence_items():
    """Candidates should have E1 (callsite) and E2 (args) evidence."""
    mcp = MockMCPManager()

    mcp.add_symbol_search("memcpy", [
        {"name": "memcpy", "address": "00101100", "type": "Function"},
    ])
    for name in COPY_FUNCTION_NAMES:
        if name != "memcpy":
            mcp.add_symbol_search(name, [])

    mcp.add_xrefs("00101100", [
        {"function_name": "handler", "from_address": "08001234",
         "type": "UNCONDITIONAL_CALL"},
    ])

    mcp.add_decompile("handler", """\
void handler(void) {
  memcpy(&local_20, src, n);
}
""")

    result = await mine_copy_sinks(_make_mm(), mcp, "test-abc123")

    assert len(result) == 1
    evidence_ids = {e.evidence_id for e in result[0].evidence}
    assert "E1" in evidence_ids  # Callsite
    assert "E2" in evidence_ids  # Arg analysis
    assert "E3" in evidence_ids  # Length/guard analysis (runtime len)


@pytest.mark.asyncio
async def test_mine_fallback_decompile_cache_skips_definition_lines():
    """Fallback xref discovery should use real callsites, not function definitions."""
    mcp = MockMCPManager()

    mcp.add_symbol_search("memcpy", [
        {"name": "memcpy", "address": "080000dc", "type": "Function"},
    ])
    for name in COPY_FUNCTION_NAMES:
        if name != "memcpy":
            mcp.add_symbol_search(name, [])

    # No xrefs from MCP -> force decompile-cache fallback
    mcp.add_xrefs("080000dc", [])

    # Caller body includes a FUN_ alias call to memcpy implementation.
    mcp.add_decompile("FUN_0800005c", """\
void FUN_0800005c(char *param_1, char *param_2, int param_3) {
  FUN_080000dc(param_1, param_2, param_3);
}
""")

    mai = MemoryAccessIndex(
        binary_path="/tmp/test.bin",
        decompiled_cache={
            # Callee definition should not become a synthetic caller.
            "FUN_080000dc": "void FUN_080000dc(char *param_1, char *param_2, int param_3) { return; }",
            "FUN_0800005c": "void FUN_0800005c(char *param_1, char *param_2, int param_3) { FUN_080000dc(param_1, param_2, param_3); }",
        },
    )

    result = await mine_copy_sinks(_make_mm(), mcp, "test-abc123", mai=mai)

    assert len(result) == 1
    assert result[0].function_name == "FUN_0800005c"
    assert result[0].facts["args_extracted"] is True


@pytest.mark.asyncio
async def test_mine_sorted_by_confidence():
    """Results should be sorted by confidence descending."""
    mcp = MockMCPManager()

    mcp.add_symbol_search("memcpy", [
        {"name": "memcpy", "address": "00101100", "type": "Function"},
    ])
    mcp.add_symbol_search("strcpy", [
        {"name": "strcpy", "address": "00101200", "type": "Function"},
    ])
    for name in COPY_FUNCTION_NAMES:
        if name not in ("memcpy", "strcpy"):
            mcp.add_symbol_search(name, [])

    mcp.add_xrefs("00101100", [
        {"function_name": "safe_func", "from_address": "08001000",
         "type": "UNCONDITIONAL_CALL"},
    ])
    mcp.add_xrefs("00101200", [
        {"function_name": "unsafe_func", "from_address": "08002000",
         "type": "UNCONDITIONAL_CALL"},
    ])

    # memcpy with constant len + guard = low risk
    mcp.add_decompile("safe_func", """\
void safe_func(void) {
  if (n > 64) n = 64;
  memcpy(&local_20, src, 64);
}
""")
    # strcpy with no len = high risk
    mcp.add_decompile("unsafe_func", "void unsafe_func(void) { strcpy(param_1, src); }")

    result = await mine_copy_sinks(_make_mm(), mcp, "test-abc123")

    assert len(result) == 2
    # strcpy (higher risk) should come first
    assert result[0].confidence_score >= result[1].confidence_score


# ── Multi-strategy symbol search ─────────────────────────────────────────────


class QueryMatchMCPManager:
    """Mock MCP manager that matches search_symbols_by_name by query value,
    regardless of limit parameter. Needed for testing multi-strategy search
    where different strategies use different limit values."""

    def __init__(self):
        self._symbol_responses = {}  # query -> symbols list
        self.call_log = []

    def add_query_response(self, query: str, symbols: list):
        """Register a symbol search response for a specific query."""
        self._symbol_responses[query] = symbols

    async def call_tool(self, server, tool_name, args):
        self.call_log.append((tool_name, args))
        if tool_name == "search_symbols_by_name":
            query = args.get("query", "")
            symbols = self._symbol_responses.get(query, [])
            return [{"type": "text", "text": json.dumps({"symbols": symbols})}]
        return None


@pytest.mark.asyncio
async def test_strategy1_exact_match_keeps_found_symbol():
    """Strategy 1 exact match should be preserved in final result set."""
    mcp = QueryMatchMCPManager()
    mcp.add_query_response("memcpy", [
        {"name": "memcpy", "address": "00101100", "type": "Function"},
    ])
    # Other queries return empty.
    for name in COPY_FUNCTION_NAMES:
        if name != "memcpy":
            mcp.add_query_response(name, [])
    for q in ("cpy", "mov", "cat", "printf", "memset"):
        mcp.add_query_response(q, [])
    for intr in ("__aeabi_memcpy", "__aeabi_memcpy4", "__aeabi_memcpy8",
                  "__aeabi_memmove", "__aeabi_memmove4", "__aeabi_memmove8",
                  "__aeabi_memset", "__aeabi_memset4", "__aeabi_memset8",
                  "__rt_memcpy", "__rt_memmove", "__rt_memset",
                  "__memcpy_r4", "__memcpy_r7"):
        mcp.add_query_response(intr, [])

    found = await _find_copy_symbols(mcp, "test-abc123")

    assert len(found) == 1
    assert found[0]["name"] == "memcpy"
    assert found[0]["address"] == "00101100"


@pytest.mark.asyncio
async def test_strategy4_heuristic_adds_missing_type():
    """If symbol strategies find memcpy only, heuristic may add missing strcpy."""
    mcp = QueryMatchMCPManager()
    # Symbol strategy finds memcpy.
    mcp.add_query_response("memcpy", [
        {"name": "memcpy", "address": "00101100", "type": "Function"},
    ])
    for name in COPY_FUNCTION_NAMES:
        if name != "memcpy":
            mcp.add_query_response(name, [])
    for q in ("cpy", "mov", "cat", "printf", "memset"):
        mcp.add_query_response(q, [])
    for intr in ("__aeabi_memcpy", "__aeabi_memcpy4", "__aeabi_memcpy8",
                  "__aeabi_memmove", "__aeabi_memmove4", "__aeabi_memmove8",
                  "__aeabi_memset", "__aeabi_memset4", "__aeabi_memset8",
                  "__rt_memcpy", "__rt_memmove", "__rt_memset",
                  "__memcpy_r4", "__memcpy_r7"):
        mcp.add_query_response(intr, [])

    # Heuristic discovery for missing strcpy:
    async def extended_call(server, tool_name, args):
        if tool_name == "search_symbols_by_name" and args.get("query") == "FUN_":
            return [{"type": "text", "text": json.dumps({"symbols": [
                {"name": "FUN_08001000", "address": "08001000", "type": "Function"},
            ]})}]
        if tool_name == "decompile_function":
            return [{"type": "text", "text": json.dumps({
                "decompiled_code": "void FUN_08001000(char *param_1,char *param_2){while(*param_2!=0){*param_1=*param_2;param_1++;param_2++;}*param_1=0;}",
            })}]
        return await QueryMatchMCPManager.call_tool(mcp, server, tool_name, args)

    mcp.call_tool = extended_call

    found = await _find_copy_symbols(mcp, "test-abc123")
    found_names = {f["name"] for f in found}
    assert "memcpy" in found_names
    assert "strcpy" in found_names


@pytest.mark.asyncio
async def test_strategy4_heuristic_scans_beyond_first_50_fun_symbols():
    """Stripped fallback should keep scanning until later FUN_ candidates."""
    mcp = QueryMatchMCPManager()
    for name in COPY_FUNCTION_NAMES:
        mcp.add_query_response(name, [])
    for q in ("cpy", "mov", "cat", "printf", "memset"):
        mcp.add_query_response(q, [])
    for intr in ("__aeabi_memcpy", "__aeabi_memcpy4", "__aeabi_memcpy8",
                  "__aeabi_memmove", "__aeabi_memmove4", "__aeabi_memmove8",
                  "__aeabi_memset", "__aeabi_memset4", "__aeabi_memset8",
                  "__rt_memcpy", "__rt_memmove", "__rt_memset",
                  "__memcpy_r4", "__memcpy_r7"):
        mcp.add_query_response(intr, [])

    fun_symbols = [
        {"name": f"FUN_0800{i:04x}", "address": f"0800{i:04x}", "type": "Function"}
        for i in range(60)
    ]
    target_symbol = fun_symbols[55]
    mcp.add_query_response("FUN_", fun_symbols)

    async def extended_call(server, tool_name, args):
        if tool_name == "decompile_function":
            name = args.get("name_or_address")
            code = "void dummy(void) { return; }"
            if name == target_symbol["name"]:
                code = (
                    "void FUN_08000037(char *param_1,char *param_2){"
                    "while(*param_2!=0){*param_1=*param_2;param_1++;param_2++;}"
                    "*param_1=0;}"
                )
            return [{"type": "text", "text": json.dumps({"decompiled_code": code})}]
        return await QueryMatchMCPManager.call_tool(mcp, server, tool_name, args)

    mcp.call_tool = extended_call

    found = await _find_copy_symbols(mcp, "test-abc123")
    assert any(row["name"] == "strcpy" for row in found)


@pytest.mark.asyncio
async def test_strategy2_substring_fallback():
    """When Strategy 1 finds nothing, Strategy 2 substring search finds variants."""
    mcp = QueryMatchMCPManager()
    # Strategy 1: all exact names return empty
    for name in COPY_FUNCTION_NAMES:
        mcp.add_query_response(name, [])

    # Strategy 2: substring "cpy" finds a variant "_memcpy"
    mcp.add_query_response("cpy", [
        {"name": "_memcpy", "address": "00101100", "type": "Function"},
    ])
    # Other substrings return empty
    for q in ("mov", "cat", "printf", "memset"):
        mcp.add_query_response(q, [])

    found = await _find_copy_symbols(mcp, "test-abc123")

    assert len(found) == 1
    assert found[0]["name"] == "memcpy"  # Matched to canonical name
    assert found[0]["address"] == "00101100"


@pytest.mark.asyncio
async def test_strategy2_finds_multiple_variants():
    """Strategy 2 can find multiple canonical functions via substrings."""
    mcp = QueryMatchMCPManager()
    for name in COPY_FUNCTION_NAMES:
        mcp.add_query_response(name, [])

    # "cpy" finds _memcpy and _strcpy
    mcp.add_query_response("cpy", [
        {"name": "_memcpy", "address": "00101100", "type": "Function"},
        {"name": "_strcpy", "address": "00101200", "type": "Function"},
    ])
    for q in ("mov", "cat", "printf", "memset"):
        mcp.add_query_response(q, [])

    found = await _find_copy_symbols(mcp, "test-abc123")

    assert len(found) == 2
    found_names = {f["name"] for f in found}
    assert "memcpy" in found_names
    assert "strcpy" in found_names


@pytest.mark.asyncio
async def test_strategy3_arm_intrinsics_fallback():
    """When Strategies 1 and 2 find nothing, Strategy 3 finds ARM intrinsics.

    Uses __rt_memcpy which is NOT in COPY_FUNCTION_NAMES (only in Strategy 3),
    so Strategy 1 won't pick it up.
    """
    mcp = QueryMatchMCPManager()
    # Strategies 1 & 2: nothing
    for name in COPY_FUNCTION_NAMES:
        mcp.add_query_response(name, [])
    for q in ("cpy", "mov", "cat", "printf", "memset"):
        mcp.add_query_response(q, [])

    # Strategy 3: ARM intrinsic (__rt_memcpy is NOT in COPY_FUNCTION_NAMES)
    mcp.add_query_response("__rt_memcpy", [
        {"name": "__rt_memcpy", "address": "00101300", "type": "Function"},
    ])
    # Other intrinsics not found
    for intr in ("__aeabi_memcpy", "__aeabi_memcpy4", "__aeabi_memcpy8",
                  "__aeabi_memmove", "__aeabi_memmove4", "__aeabi_memmove8",
                  "__aeabi_memset", "__aeabi_memset4", "__aeabi_memset8",
                  "__rt_memmove", "__rt_memset",
                  "__memcpy_r4", "__memcpy_r7"):
        mcp.add_query_response(intr, [])

    found = await _find_copy_symbols(mcp, "test-abc123")

    assert len(found) == 1
    # Should map to canonical name for _LEN_ARG_INDEX lookup
    assert found[0]["name"] == "memcpy"
    assert found[0]["address"] == "00101300"


@pytest.mark.asyncio
async def test_strategy3_canonical_name_mapping():
    """ARM intrinsic __aeabi_memmove should map to canonical 'memmove'."""
    mcp = QueryMatchMCPManager()
    for name in COPY_FUNCTION_NAMES:
        mcp.add_query_response(name, [])
    for q in ("cpy", "mov", "cat", "printf", "memset"):
        mcp.add_query_response(q, [])

    mcp.add_query_response("__aeabi_memmove4", [
        {"name": "__aeabi_memmove4", "address": "00101400", "type": "Function"},
    ])
    # All other intrinsics empty
    for intr in ("__aeabi_memcpy", "__aeabi_memcpy4", "__aeabi_memcpy8",
                  "__aeabi_memmove", "__aeabi_memmove8",
                  "__aeabi_memset", "__aeabi_memset4", "__aeabi_memset8",
                  "__rt_memcpy", "__rt_memmove", "__rt_memset",
                  "__memcpy_r4", "__memcpy_r7"):
        mcp.add_query_response(intr, [])

    found = await _find_copy_symbols(mcp, "test-abc123")

    assert len(found) == 1
    assert found[0]["name"] == "memmove"


@pytest.mark.asyncio
async def test_all_strategies_empty_returns_nothing():
    """When all strategies fail, return empty list."""
    mcp = QueryMatchMCPManager()
    # Everything returns empty
    for name in COPY_FUNCTION_NAMES:
        mcp.add_query_response(name, [])
    for q in ("cpy", "mov", "cat", "printf", "memset"):
        mcp.add_query_response(q, [])
    for intr in ("__aeabi_memcpy", "__aeabi_memcpy4", "__aeabi_memcpy8",
                  "__aeabi_memmove", "__aeabi_memmove4", "__aeabi_memmove8",
                  "__aeabi_memset", "__aeabi_memset4", "__aeabi_memset8",
                  "__rt_memcpy", "__rt_memmove", "__rt_memset",
                  "__memcpy_r4", "__memcpy_r7"):
        mcp.add_query_response(intr, [])

    found = await _find_copy_symbols(mcp, "test-abc123")
    assert found == []


@pytest.mark.asyncio
async def test_strategy2_skips_already_found_names():
    """Strategy 2 should not duplicate names already found."""
    mcp = QueryMatchMCPManager()
    for name in COPY_FUNCTION_NAMES:
        mcp.add_query_response(name, [])

    # "cpy" returns both memcpy and memcpy again (different symbol entries)
    mcp.add_query_response("cpy", [
        {"name": "_memcpy", "address": "00101100", "type": "Function"},
        {"name": "memcpy_wrapper", "address": "00101200", "type": "Function"},
    ])
    for q in ("mov", "cat", "printf", "memset"):
        mcp.add_query_response(q, [])

    found = await _find_copy_symbols(mcp, "test-abc123")

    # Only one "memcpy" entry — dedup by canonical name
    memcpy_entries = [f for f in found if f["name"] == "memcpy"]
    assert len(memcpy_entries) == 1


@pytest.mark.asyncio
async def test_mine_end_to_end_strategy2_fallback():
    """End-to-end: Strategy 2 finds _memcpy → xref → decompile → candidate."""
    mcp = QueryMatchMCPManager()
    # Strategy 1: nothing
    for name in COPY_FUNCTION_NAMES:
        mcp.add_query_response(name, [])
    # Strategy 2: _memcpy found
    mcp.add_query_response("cpy", [
        {"name": "_memcpy", "address": "00101100", "type": "Function"},
    ])
    for q in ("mov", "cat", "printf", "memset"):
        mcp.add_query_response(q, [])

    # Wire up xrefs and decompile for end-to-end
    # Override call_tool to handle xrefs and decompile too
    original_call = mcp.call_tool

    async def extended_call(server, tool_name, args):
        if tool_name == "list_cross_references":
            return [{"type": "text", "text": json.dumps({"references": [
                {"function_name": "recv_handler", "from_address": "08001234",
                 "type": "UNCONDITIONAL_CALL"},
            ]})}]
        if tool_name == "decompile_function":
            return [{"type": "text", "text": json.dumps({"decompiled_code":
                "void recv_handler(void) { memcpy(&local_20, param_1, param_2); }"})}]
        return await original_call(server, tool_name, args)

    mcp.call_tool = extended_call

    result = await mine_copy_sinks(_make_mm(), mcp, "test-abc123")

    assert len(result) == 1
    c = result[0]
    assert c.preliminary_label == SinkLabel.COPY_SINK
    assert c.function_name == "recv_handler"
    assert c.facts["callee"] == "memcpy"
    assert c.facts["dst_provenance"] == "STACK_PTR"
