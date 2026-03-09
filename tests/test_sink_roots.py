"""Tests for linker.sink_roots."""

from sourceagent.pipeline.linker.sink_roots import extract_sink_roots


def test_extract_sink_roots_copy_len_and_dst():
    verified_sinks = [
        {
            "pack_id": "p1",
            "label": "COPY_SINK",
            "address": 0x08001000,
            "function_name": "copy_fn",
            "confidence": 0.9,
            "evidence_refs": ["E1"],
        },
    ]
    facts = {
        "p1": {
            "len_expr": "payload_len",
            "dst_expr": "out",
        },
    }

    rows = extract_sink_roots(verified_sinks, sink_facts_by_pack=facts, binary_stem="fw")

    assert len(rows) == 1
    assert rows[0]["status"] == "ok"
    assert rows[0]["roots"][0]["expr"] == "payload_len"
    assert rows[0]["roots"][1]["expr"] == "out"
    assert rows[0]["root_source"] == "miner_facts"
    assert rows[0]["roots"][0]["canonical_expr"] == "payload_len"
    assert rows[0]["roots"][0]["family"] == "length"
    assert "payload_len" in rows[0]["roots"][0]["aliases"]


def test_extract_sink_roots_missing_facts_marks_partial():
    verified_sinks = [
        {
            "pack_id": "p2",
            "label": "STORE_SINK",
            "address": 0x08002000,
            "function_name": "store_fn",
            "confidence": 0.2,
            "evidence_refs": [],
        },
    ]

    rows = extract_sink_roots(verified_sinks, sink_facts_by_pack={}, binary_stem="fw")

    assert rows[0]["status"] == "partial"
    assert rows[0]["failure_code"] == "ROOT_FACT_MISSING"
    assert rows[0]["roots"][0]["expr"] == "UNKNOWN"


def test_extract_sink_roots_uses_decompile_fallback_for_format_string():
    verified_sinks = [
        {
            "pack_id": "p3",
            "label": "FORMAT_STRING_SINK",
            "address": 0x08003000,
            "function_name": "log_message",
            "confidence": 0.7,
            "evidence_refs": [],
        },
    ]
    facts = {
        "p3": {
            "format_arg_is_variable": True,
        },
    }
    decompiled_cache = {
        "log_message": 'void log_message(char *fmt) {\n  sprintf(g_log_buf, fmt);\n}\n',
    }

    rows = extract_sink_roots(
        verified_sinks,
        sink_facts_by_pack=facts,
        binary_stem="fw",
        decompiled_cache=decompiled_cache,
    )

    assert rows[0]["status"] == "ok"
    assert rows[0]["roots"][0]["expr"] == "fmt"
    assert rows[0]["root_source"] == "decompile_fallback"


def test_extract_sink_roots_uses_store_fallback_name_hint_from_decompile():
    verified_sinks = [
        {
            "pack_id": "p4",
            "label": "STORE_SINK",
            "address": 0x08000072,
            "function_name": "USBH_ParseEPDesc",
            "confidence": 0.5,
            "evidence_refs": ["E1"],
        },
    ]
    facts = {
        "p4": {
            "param_store_heuristic": True,
            "fallback_name_hint": True,
            "has_unresolved_target": True,
        },
    }
    decompiled_cache = {
        "USBH_ParseEPDesc": """
static void USBH_ParseEPDesc(USBH_EpDescTypeDef *ep_descriptor, uint8_t *buf) {
  ep_descriptor->wMaxPacketSize = LE16(buf + 4);
  ep_descriptor->bInterval = *(uint8_t *)(buf + 6);
}
""",
    }

    rows = extract_sink_roots(
        verified_sinks,
        sink_facts_by_pack=facts,
        binary_stem="fw",
        decompiled_cache=decompiled_cache,
    )

    assert rows[0]["status"] == "ok"
    assert rows[0]["roots"][0]["expr"] == "ep_descriptor"
    assert rows[0]["root_source"] == "decompile_fallback"


def test_extract_sink_roots_uses_function_name_hint_when_store_decompile_missing():
    verified_sinks = [
        {
            "pack_id": "p5",
            "label": "STORE_SINK",
            "address": 0x080000b8,
            "function_name": "USBH_ParseCfgDesc",
            "confidence": 0.5,
            "evidence_refs": ["E1"],
        },
    ]
    facts = {
        "p5": {
            "param_store_heuristic": True,
            "fallback_name_hint": True,
            "has_unresolved_target": True,
        },
    }

    rows = extract_sink_roots(
        verified_sinks,
        sink_facts_by_pack=facts,
        binary_stem="fw",
        decompiled_cache={},
    )

    assert rows[0]["status"] == "ok"
    assert rows[0]["roots"][0]["expr"] == "cfg_desc"
    assert rows[0]["root_source"] == "fallback_name_hint"


def test_extract_sink_roots_recovers_loop_copy_length_from_decompile():
    verified_sinks = [
        {
            "pack_id": "p6",
            "label": "COPY_SINK",
            "address": 0x0800005C,
            "function_name": "uart_receive",
            "confidence": 0.5,
            "evidence_refs": ["E1"],
        },
    ]
    facts = {
        "p6": {
            "callee": "loop_copy_idiom",
            "call_found": True,
            "args_extracted": False,
            "fallback_name_hint": True,
        },
    }
    decompiled_cache = {
        "uart_receive": """
void uart_receive(byte *buf, byte len) {
  for (byte i = 0; i < len; i = i + 1) {
    buf[i] = uart_read_byte();
  }
}
""",
    }

    rows = extract_sink_roots(
        verified_sinks,
        sink_facts_by_pack=facts,
        binary_stem="fw",
        decompiled_cache=decompiled_cache,
    )

    assert rows[0]["status"] == "ok"
    assert rows[0]["roots"][0]["expr"] == "len"
    assert rows[0]["root_source"] == "decompile_fallback"


def test_extract_sink_roots_recovers_loop_write_bound_from_decompile():
    verified_sinks = [
        {
            "pack_id": "p7",
            "label": "LOOP_WRITE_SINK",
            "address": 0x08000060,
            "function_name": "fill_buffer",
            "confidence": 0.5,
            "evidence_refs": ["E1"],
        },
    ]
    facts = {
        "p7": {
            "store_expr": "buf[i]",
        },
    }
    decompiled_cache = {
        "fill_buffer": """
void fill_buffer(byte *buf, uint n) {
  for (uint i = 0; i < n; i = i + 1) {
    buf[i] = spi_read_byte();
  }
}
""",
    }

    rows = extract_sink_roots(
        verified_sinks,
        sink_facts_by_pack=facts,
        binary_stem="fw",
        decompiled_cache=decompiled_cache,
    )

    assert rows[0]["status"] == "ok"
    assert rows[0]["roots"][0]["expr"] == "n"
    assert rows[0]["roots"][0]["kind"] == "index_or_bound"
