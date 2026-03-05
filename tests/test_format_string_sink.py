"""Tests for pipeline/miners/format_string_sink.py."""

from sourceagent.pipeline.miners.format_string_sink import _mine_from_decompile_patterns


def test_fallback_mines_stack_buf_param_format():
    cache = {
        "FUN_08000090": """void FUN_08000090(char *param_1) {
  FUN_08000104(auStack_48, param_1);
}""",
    }
    sinks = _mine_from_decompile_patterns(cache)
    assert len(sinks) == 1
    assert sinks[0].function_name == "FUN_08000090"
    assert sinks[0].preliminary_label.value == "FORMAT_STRING_SINK"


def test_fallback_skips_large_functions():
    big = "void FUN_08000100(void) {\n" + ("  int x = 1;\n" * 80) + "}\n"
    sinks = _mine_from_decompile_patterns({"FUN_08000100": big})
    assert sinks == []


def test_fallback_skips_three_arg_wrapper_like_memcpy():
    cache = {
        "FUN_080000a0": """void FUN_080000a0(char *param_1, char *param_2, int param_3) {
  FUN_08000120(param_1, param_2, param_3);
}""",
    }
    sinks = _mine_from_decompile_patterns(cache)
    assert sinks == []
