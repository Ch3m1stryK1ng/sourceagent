"""Tests for pipeline/miners/func_ptr_sink.py."""

from sourceagent.pipeline.miners.func_ptr_sink import _detect_indirect_call


def test_detect_param_fptr_call():
    code = "void f(uint param_1){ x = param_1 + 4; (*param_1)(a,b); }"
    kind = _detect_indirect_call(code)
    assert kind is not None
    assert kind[0] == "param_fptr"


def test_detect_cast_indirect_call():
    code = "void f(void){ (*(undefined4 (*)())(param_1 + (uVar2 << 2)))(); }"
    kind = _detect_indirect_call(code)
    assert kind is not None
    assert kind[0] in {"cast_indirect", "indexed_dispatch", "table_dispatch"}


def test_detect_direct_table_call():
    code = "void f(void){ handlers[param_1](); }"
    kind = _detect_indirect_call(code)
    assert kind is not None
    assert kind[0] == "direct_table_call"


def test_detect_local_fptr_call_pcvar_assignment():
    code = """void f(uint param_1){
  pcVar1 = *(code **)(DAT_08001000 + (uint)param_1 * 4);
  (*pcVar1)();
}"""
    kind = _detect_indirect_call(code)
    assert kind is not None
    assert kind[0] in {"local_fptr", "indexed_dispatch", "table_dispatch"}
