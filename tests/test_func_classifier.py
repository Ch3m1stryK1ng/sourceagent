"""Tests for pipeline/miners/func_classifier.py — heuristic function classification."""

import pytest

from sourceagent.pipeline.miners.func_classifier import classify_function


class TestClassifyMemcpy:
    def test_byte_copy_loop_three_params(self):
        code = """void FUN_08001234(void *param_1, void *param_2, uint param_3) {
            uint i = 0;
            while (i < param_3) {
                *(byte *)((int)param_1 + i) = *(byte *)((int)param_2 + i);
                i = i + 1;
            }
            return;
        }"""
        assert classify_function(code) == "memcpy"

    def test_for_loop_variant(self):
        code = """void FUN_08001234(byte *param_1, byte *param_2, int param_3) {
            int i;
            for (i = 0; i < param_3; i = i + 1) {
                *param_1 = *param_2;
                param_1 = param_1 + 1;
                param_2 = param_2 + 1;
            }
        }"""
        assert classify_function(code) == "memcpy"


class TestClassifyMemset:
    def test_fill_loop_pattern(self):
        code = """void FUN_08001280(void *param_1, int param_2, uint param_3) {
            uint i = 0;
            while (i < param_3) {
                *(byte *)((int)param_1 + i) = (byte)param_2;
                i = i + 1;
            }
        }"""
        assert classify_function(code) == "memset"

    def test_fill_with_bvar(self):
        code = """void FUN_08001280(void *param_1, byte bVar1, uint param_3) {
            uint uVar2 = 0;
            while (uVar2 < param_3) {
                *param_1 = bVar1;
                param_1 = param_1 + 1;
                uVar2 = uVar2 + 1;
            }
        }"""
        assert classify_function(code) == "memset"

    def test_fill_temp_derived_from_param2(self):
        code = """void FUN_08001280(void *param_1, int param_2, uint param_3) {
            byte bVar1;
            bVar1 = (byte)param_2;
            while (param_3 != 0) {
                *param_1 = bVar1;
                param_1 = param_1 + 1;
                param_3 = param_3 - 1;
            }
        }"""
        assert classify_function(code) == "memset"


class TestClassifyStrcpy:
    def test_null_terminated_copy(self):
        code = """void FUN_080012c0(char *param_1, char *param_2) {
            while (*param_2 != 0) {
                *param_1 = *param_2;
                param_1 = param_1 + 1;
                param_2 = param_2 + 1;
            }
            *param_1 = 0;
        }"""
        assert classify_function(code) == "strcpy"

    def test_null_check_with_char_literal(self):
        code = """void FUN_080012c0(char *param_1, char *param_2) {
            while (*param_2 != '\\0') {
                *param_1 = *param_2;
                param_1 = param_1 + 1;
                param_2 = param_2 + 1;
            }
            *param_1 = '\\0';
        }"""
        assert classify_function(code) == "strcpy"


class TestClassifyNone:
    def test_non_copy_function(self):
        code = """void FUN_08001300(int param_1) {
            *(int *)(param_1 + 4) = 0x20;
            return;
        }"""
        assert classify_function(code) is None

    def test_large_function_rejected(self):
        code = "void big() {\n" + "  int x = 1;\n" * 120 + "}\n"
        assert classify_function(code) is None

    def test_no_loop_rejected(self):
        code = """void FUN_08001300(byte *param_1, byte *param_2, int param_3) {
            *param_1 = *param_2;
            return;
        }"""
        assert classify_function(code) is None

    def test_empty_string(self):
        assert classify_function("") is None

    def test_loop_write_from_call_not_memset(self):
        code = """void FUN_0800005c(byte *param_1, int param_2) {
            uint uVar1 = 0;
            while (uVar1 < param_2) {
                bVar2 = uart_read_byte();
                param_1[uVar1] = bVar2;
                uVar1 = uVar1 + 1;
            }
        }"""
        assert classify_function(code) is None
