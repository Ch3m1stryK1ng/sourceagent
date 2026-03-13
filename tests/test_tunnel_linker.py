"""Tests for linker.tunnel_linker."""

from sourceagent.pipeline.linker.tunnel_linker import link_chains


class _FakeMai:
    def __init__(self, *, decompiled_cache=None, accesses=None):
        self.decompiled_cache = decompiled_cache or {}
        self.accesses = accesses or []


def test_link_chains_confirmed_when_source_reached_and_check_absent():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0000",
            "sink_label": "COPY_SINK",
            "sink_function": "copy_fn",
            "sink_site": "0x08001000",
            "roots": [{"role": "primary", "expr": "payload_len", "kind": "length"}],
            "evidence_refs": ["E_SINK"],
            "confidence": 0.95,
            "status": "ok",
        },
    ]
    sources = [
        {
            "label": "MMIO_READ",
            "address": 0x40011004,
            "function_name": "uart_receive",
            "evidence_refs": ["E_SRC"],
        },
    ]
    key = "0x08001000|copy_fn|COPY_SINK"
    mai = _FakeMai(
        decompiled_cache={
            "copy_fn": """
void copy_fn(char *dst, unsigned int payload_len) {
  payload_len = uart_receive();
  memcpy(dst, local, payload_len);
}
""",
        },
    )

    chains = link_chains(
        sink_roots,
        {"object_nodes": [], "channel_edges": []},
        mai=mai,
        sources=sources,
        sink_facts_by_pack={"p1": {"has_bounds_guard": False}},
        sink_pack_id_by_site={key: "p1"},
        binary_stem="fw",
    )

    assert len(chains) == 1
    assert chains[0]["status"] == "ok"
    assert chains[0]["verdict"] == "CONFIRMED"


def test_link_chains_partial_when_no_source_reach():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0001",
            "sink_label": "MEMSET_SINK",
            "sink_function": "clear",
            "sink_site": "0x08002000",
            "roots": [{"role": "primary", "expr": "count", "kind": "length"}],
            "evidence_refs": [],
            "confidence": 0.3,
            "status": "ok",
        },
    ]

    chains = link_chains(
        sink_roots,
        {"object_nodes": [], "channel_edges": []},
        mai=None,
        sources=[],
        sink_facts_by_pack={},
        sink_pack_id_by_site={},
        binary_stem="fw",
    )

    assert chains[0]["status"] == "partial"
    assert chains[0]["failure_code"] == "OBJECT_HIT_NONE"
    assert chains[0]["link_debug"]["failure_stage"] == "object"


def test_link_chains_uses_channel_jump_when_object_hit_exists():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0002",
            "sink_label": "COPY_SINK",
            "sink_function": "process_packet",
            "sink_site": "0x08003000",
            "roots": [{"role": "primary", "expr": "obj_isr_20000000_200000ff", "kind": "length"}],
            "evidence_refs": [],
            "confidence": 0.7,
            "status": "ok",
        },
    ]
    channel_graph = {
        "object_nodes": [
            {
                "object_id": "obj_isr_20000000_200000ff",
                "addr_range": ["0x20000000", "0x200000ff"],
                "writer_sites": [{"context": "ISR", "fn": "USART1_IRQHandler"}],
                "writers": ["USART1_IRQHandler"],
            },
        ],
        "channel_edges": [
            {
                "src_context": "ISR",
                "dst_context": "MAIN",
                "object_id": "obj_isr_20000000_200000ff",
                "score": 0.9,
                "evidence_refs": ["E_CH1"],
            },
        ],
    }
    sources = [
        {
            "label": "MMIO_READ",
            "address": 0x40011004,
            "function_name": "USART1_IRQHandler",
            "evidence_refs": ["E_SRC"],
        },
    ]

    chains = link_chains(
        sink_roots,
        channel_graph,
        mai=None,
        sources=sources,
        sink_facts_by_pack={"p3": {"has_bounds_guard": False}},
        sink_pack_id_by_site={"0x08003000|process_packet|COPY_SINK": "p3"},
        binary_stem="fw",
        max_depth=2,
    )

    assert len(chains) == 1
    assert any(step.get("kind") == "CHANNEL" for step in chains[0]["steps"])
    assert chains[0]["link_debug"]["tunnel_attempts"] >= 1


def test_link_chains_hits_object_by_member_name_and_tunnels_to_source():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0003",
            "sink_label": "COPY_SINK",
            "sink_function": "process_packet",
            "sink_site": "0x08004000",
            "roots": [{"role": "primary", "expr": "g_rx_buf", "kind": "src_ptr"}],
            "evidence_refs": [],
            "confidence": 0.7,
            "status": "ok",
            "root_source": "call_args",
        },
    ]
    channel_graph = {
        "object_nodes": [
            {
                "object_id": "obj_sram_20000000_200000ff",
                "addr_range": ["0x20000000", "0x200000ff"],
                "members": ["g_rx_buf", "g_rx_head"],
                "writer_sites": [{"context": "ISR", "fn": "USART1_IRQHandler"}],
                "writers": ["USART1_IRQHandler"],
                "reader_sites": [{"context": "MAIN", "fn": "process_packet"}],
                "readers": ["process_packet"],
                "type_facts": {"source_label": "ISR_FILLED_BUFFER", "kind_hint": "payload"},
            },
        ],
        "channel_edges": [
            {
                "src_context": "ISR",
                "dst_context": "MAIN",
                "object_id": "obj_sram_20000000_200000ff",
                "score": 0.9,
                "evidence_refs": ["E_CH2"],
            },
        ],
    }
    sources = [
        {
            "label": "ISR_MMIO_READ",
            "address": 0x40011004,
            "function_name": "USART1_IRQHandler",
            "evidence_refs": ["E_SRC2"],
        },
    ]

    chains = link_chains(
        sink_roots,
        channel_graph,
        mai=None,
        sources=sources,
        sink_facts_by_pack={"p4": {"has_bounds_guard": False}},
        sink_pack_id_by_site={"0x08004000|process_packet|COPY_SINK": "p4"},
        binary_stem="fw",
        max_depth=2,
    )

    assert len(chains) == 1
    assert any(step.get("kind") == "CHANNEL" for step in chains[0]["steps"])
    assert any(step.get("kind") == "SOURCE" for step in chains[0]["steps"])
    assert chains[0]["link_debug"]["object_hit_mode"] == "expr_member"


def test_link_chains_infers_dma_channel_for_stripped_payload_proxy_object():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0003b",
            "sink_label": "STORE_SINK",
            "sink_function": "FUN_08001234",
            "sink_site": "0x08001234",
            "roots": [{"role": "primary", "expr": "0x20001020", "kind": "dst_ptr"}],
            "evidence_refs": [],
            "confidence": 0.7,
            "status": "ok",
            "root_source": "call_args",
        },
    ]
    channel_graph = {
        "object_nodes": [
            {
                "object_id": "obj_sram_20001000_200010ff",
                "addr_range": ["0x20001000", "0x200010ff"],
                "members": [],
                "writer_sites": [{"context": "MAIN", "fn": "FUN_08000100"}],
                "writers": ["FUN_08000100"],
                "reader_sites": [{"context": "MAIN", "fn": "FUN_08001234"}],
                "readers": ["FUN_08001234"],
                "type_facts": {"kind_hint": "payload", "symbol_backed": False},
            },
        ],
        "channel_edges": [],
    }
    sources = [
        {
            "label": "DMA_BACKED_BUFFER",
            "address": 0x40001000,
            "function_name": "FUN_08000080",
            "evidence_refs": ["E_DMA"],
            "facts": {
                "buffer_cluster": "0x20001000",
                "buffer_binding_confidence": 0.84,
            },
        },
        {
            "label": "MMIO_READ",
            "address": 0x40011004,
            "function_name": "FUN_08000100",
            "evidence_refs": ["E_MMIO"],
        },
    ]

    chains = link_chains(
        sink_roots,
        channel_graph,
        mai=None,
        sources=sources,
        sink_facts_by_pack={"p3b": {"has_bounds_guard": False}},
        sink_pack_id_by_site={"0x08001234|FUN_08001234|STORE_SINK": "p3b"},
        binary_stem="fw",
        max_depth=1,
    )

    assert any(any(step.get("kind") == "SOURCE" and step.get("label") == "DMA_BACKED_BUFFER" for step in ch["steps"]) for ch in chains)
    assert any(
        any(step.get("kind") == "CHANNEL" and step.get("edge") == "DMA->MAIN" and step.get("object_id") == "obj_sram_20001000_200010ff" for step in ch["steps"])
        for ch in chains
    )


def test_link_chains_rejects_unbound_dma_source_for_payload_proxy_object():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0003bb",
            "sink_label": "STORE_SINK",
            "sink_function": "FUN_08001234",
            "sink_site": "0x08001234",
            "roots": [{"role": "primary", "expr": "0x20001020", "kind": "dst_ptr"}],
            "evidence_refs": [],
            "confidence": 0.7,
            "status": "ok",
            "root_source": "call_args",
        },
    ]
    channel_graph = {
        "object_nodes": [
            {
                "object_id": "obj_sram_20001000_200010ff",
                "addr_range": ["0x20001000", "0x200010ff"],
                "members": [],
                "writer_sites": [{"context": "MAIN", "fn": "FUN_08000100"}],
                "writers": ["FUN_08000100"],
                "reader_sites": [{"context": "MAIN", "fn": "FUN_08001234"}],
                "readers": ["FUN_08001234"],
                "type_facts": {"kind_hint": "payload", "symbol_backed": False},
            },
        ],
        "channel_edges": [],
    }
    sources = [
        {
            "label": "DMA_BACKED_BUFFER",
            "address": 0x40001000,
            "function_name": "FUN_08000080",
            "evidence_refs": ["E_DMA"],
        },
    ]

    chains = link_chains(
        sink_roots,
        channel_graph,
        mai=None,
        sources=sources,
        sink_facts_by_pack={"p3bb": {"has_bounds_guard": False}},
        sink_pack_id_by_site={"0x08001234|FUN_08001234|STORE_SINK": "p3bb"},
        binary_stem="fw",
        max_depth=1,
    )

    assert chains
    assert all(not any(step.get("kind") == "SOURCE" and step.get("label") == "DMA_BACKED_BUFFER" for step in ch["steps"]) for ch in chains)


def test_link_chains_infers_main_to_task_shared_handoff_for_bound_dma_object():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0003bc",
            "sink_label": "COPY_SINK",
            "sink_function": "FUN_08002222",
            "sink_site": "0x08002222",
            "roots": [{"role": "primary", "expr": "0x20002040", "kind": "dst_ptr"}],
            "evidence_refs": [],
            "confidence": 0.74,
            "status": "ok",
            "root_source": "call_args",
        },
    ]
    channel_graph = {
        "object_nodes": [
            {
                "object_id": "obj_sram_20002000_200020ff",
                "addr_range": ["0x20002000", "0x200020ff"],
                "members": [],
                "writer_sites": [{"context": "DMA", "fn": "FUN_08000080"}],
                "writers": ["FUN_08000080"],
                "reader_sites": [
                    {"context": "MAIN", "fn": "FUN_08001000"},
                    {"context": "MAIN", "fn": "FUN_08002222"},
                    {"context": "MAIN", "fn": "FUN_08003333"},
                ],
                "readers": ["FUN_08001000", "FUN_08002222", "FUN_08003333"],
                "type_facts": {
                    "kind_hint": "payload",
                    "symbol_backed": False,
                    "source_label": "DMA_BACKED_BUFFER",
                    "buffer_cluster": "0x20002000",
                    "buffer_binding_confidence": 0.88,
                    "shared_handoff_hint": {"edge": "MAIN->TASK", "score": 0.84},
                },
                "quality": {"score": 0.78, "ambiguity_penalty": 0.18},
            },
        ],
        "channel_edges": [],
    }
    sources = [
        {
            "label": "DMA_BACKED_BUFFER",
            "address": 0x40001000,
            "function_name": "FUN_08000080",
            "evidence_refs": ["E_DMA"],
            "facts": {
                "buffer_cluster": "0x20002000",
                "buffer_binding_confidence": 0.88,
            },
        },
    ]

    chains = link_chains(
        sink_roots,
        channel_graph,
        mai=None,
        sources=sources,
        sink_facts_by_pack={"p3bc": {"has_bounds_guard": False}},
        sink_pack_id_by_site={"0x08002222|FUN_08002222|COPY_SINK": "p3bc"},
        binary_stem="fw",
        max_depth=1,
    )

    assert any(any(step.get("kind") == "CHANNEL" and step.get("edge") == "DMA->MAIN" for step in ch["steps"]) for ch in chains)
    assert any(any(step.get("kind") == "CHANNEL" and step.get("edge") == "MAIN->TASK" for step in ch["steps"]) for ch in chains)


def test_link_chains_does_not_infer_proxy_channel_for_symbol_rich_named_functions():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0003c",
            "sink_label": "STORE_SINK",
            "sink_function": "process_packet",
            "sink_site": "0x08001240",
            "roots": [{"role": "primary", "expr": "0x20001120", "kind": "dst_ptr"}],
            "evidence_refs": [],
            "confidence": 0.7,
            "status": "ok",
            "root_source": "call_args",
        },
    ]
    channel_graph = {
        "object_nodes": [
            {
                "object_id": "obj_sram_20001100_200011ff",
                "addr_range": ["0x20001100", "0x200011ff"],
                "members": [],
                "writer_sites": [{"context": "MAIN", "fn": "uart_rx"}],
                "writers": ["uart_rx"],
                "reader_sites": [{"context": "MAIN", "fn": "process_packet"}],
                "readers": ["process_packet"],
                "type_facts": {"kind_hint": "payload", "source_label": "MMIO_READ", "symbol_backed": False},
            },
        ],
        "channel_edges": [],
    }
    sources = [
        {
            "label": "MMIO_READ",
            "address": 0x40011004,
            "function_name": "uart_rx",
            "evidence_refs": ["E_SRC"],
        },
    ]

    chains = link_chains(
        sink_roots,
        channel_graph,
        mai=None,
        sources=sources,
        sink_facts_by_pack={"p3c": {"has_bounds_guard": False}},
        sink_pack_id_by_site={"0x08001240|process_packet|STORE_SINK": "p3c"},
        binary_stem="fw",
        max_depth=1,
    )

    assert chains
    assert all(not any(step.get("kind") == "CHANNEL" for step in ch["steps"]) for ch in chains)


def test_link_chains_does_not_infer_proxy_channel_for_isr_proxy_support_root():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0003d",
            "sink_label": "COPY_SINK",
            "sink_function": "FUN_08001244",
            "sink_site": "0x08001244",
            "roots": [
                {"role": "primary", "expr": "copy_len", "kind": "length"},
                {"role": "secondary", "expr": "0x20001220", "kind": "src_ptr"},
            ],
            "evidence_refs": [],
            "confidence": 0.72,
            "status": "ok",
            "root_source": "miner_facts",
        },
    ]
    channel_graph = {
        "object_nodes": [
            {
                "object_id": "obj_sram_20001200_200012ff",
                "addr_range": ["0x20001200", "0x200012ff"],
                "members": [],
                "writer_sites": [{"context": "MAIN", "fn": "FUN_08000080"}],
                "writers": ["FUN_08000080"],
                "reader_sites": [{"context": "MAIN", "fn": "FUN_08001244"}],
                "readers": ["FUN_08001244"],
                "type_facts": {"kind_hint": "payload", "symbol_backed": False},
            },
        ],
        "channel_edges": [],
    }
    sources = [
        {
            "label": "ISR_FILLED_BUFFER",
            "address": 0x20001200,
            "function_name": "FUN_08000080",
            "evidence_refs": ["E_ISR"],
        },
    ]

    chains = link_chains(
        sink_roots,
        channel_graph,
        mai=None,
        sources=sources,
        sink_facts_by_pack={"p3d": {"has_bounds_guard": False}},
        sink_pack_id_by_site={"0x08001244|FUN_08001244|COPY_SINK": "p3d"},
        binary_stem="fw",
        max_depth=1,
    )

    assert chains
    assert all(not any(step.get("kind") == "CHANNEL" for step in ch["steps"]) for ch in chains)
    assert all(ch["verdict"] == "DROP" for ch in chains)


def test_link_chains_does_not_infer_proxy_channel_for_func_ptr_proxy_source():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0003e",
            "sink_label": "FUNC_PTR_SINK",
            "sink_function": "FUN_08001248",
            "sink_site": "0x08001248",
            "roots": [{"role": "primary", "expr": "dispatch_idx", "kind": "dispatch"}],
            "evidence_refs": [],
            "confidence": 0.68,
            "status": "ok",
            "root_source": "call_args",
        },
    ]
    channel_graph = {
        "object_nodes": [
            {
                "object_id": "obj_sram_20001300_200013ff",
                "addr_range": ["0x20001300", "0x200013ff"],
                "members": [],
                "writer_sites": [{"context": "MAIN", "fn": "FUN_08000084"}],
                "writers": ["FUN_08000084"],
                "reader_sites": [{"context": "MAIN", "fn": "FUN_08001248"}],
                "readers": ["FUN_08001248"],
                "type_facts": {"kind_hint": "payload", "symbol_backed": False},
            },
        ],
        "channel_edges": [],
    }
    sources = [
        {
            "label": "DMA_BACKED_BUFFER",
            "address": 0x40026000,
            "function_name": "FUN_08000084",
            "evidence_refs": ["E_DMA"],
        },
    ]

    chains = link_chains(
        sink_roots,
        channel_graph,
        mai=None,
        sources=sources,
        sink_facts_by_pack={"p3e": {"has_bounds_guard": False}},
        sink_pack_id_by_site={"0x08001248|FUN_08001248|FUNC_PTR_SINK": "p3e"},
        binary_stem="fw",
        max_depth=1,
    )

    assert chains
    assert all(not any(step.get("kind") == "CHANNEL" for step in ch["steps"]) for ch in chains)
    assert all(ch["verdict"] == "DROP" for ch in chains)


def test_link_chains_can_use_secondary_root_when_primary_misses():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0004",
            "sink_label": "COPY_SINK",
            "sink_function": "process_dma_data",
            "sink_site": "0x08005000",
            "roots": [
                {"role": "primary", "expr": "rx_len", "kind": "length", "source": "call_args"},
                {"role": "secondary", "expr": "g_dma_rx_buf", "kind": "src_ptr", "source": "call_args"},
            ],
            "evidence_refs": [],
            "confidence": 0.7,
            "status": "ok",
            "root_source": "call_args",
        },
    ]
    channel_graph = {
        "object_nodes": [
            {
                "object_id": "obj_sram_20000000_200000ff",
                "addr_range": ["0x20000000", "0x200000ff"],
                "members": ["g_dma_rx_buf"],
                "writer_sites": [{"context": "DMA", "fn": "dma_start_rx"}],
                "writers": ["dma_start_rx"],
                "reader_sites": [{"context": "MAIN", "fn": "process_dma_data"}],
                "readers": ["process_dma_data"],
                "type_facts": {"source_label": "DMA_BACKED_BUFFER", "kind_hint": "payload"},
            },
        ],
        "channel_edges": [
            {
                "src_context": "DMA",
                "dst_context": "MAIN",
                "object_id": "obj_sram_20000000_200000ff",
                "score": 0.9,
                "evidence_refs": ["E_CH3"],
            },
        ],
    }
    sources = [
        {
            "label": "DMA_BACKED_BUFFER",
            "address": 0x40020000,
            "function_name": "dma_start_rx",
            "evidence_refs": ["E_DMA_SRC"],
        },
    ]

    chains = link_chains(
        sink_roots,
        channel_graph,
        mai=None,
        sources=sources,
        sink_facts_by_pack={"p5": {"has_bounds_guard": False}},
        sink_pack_id_by_site={"0x08005000|process_dma_data|COPY_SINK": "p5"},
        binary_stem="fw",
        max_depth=2,
    )

    assert len(chains) >= 1
    assert any(any(step.get("kind") == "CHANNEL" for step in ch["steps"]) for ch in chains)
    assert any(
        ch["link_debug"]["active_root_expr"] in {"g_dma_rx_buf", "rx_len"}
        for ch in chains
    )
    assert any(
        any(row.get("expr") == "g_dma_rx_buf" for row in ch.get("root_bundle", []))
        and any(row.get("expr") == "rx_len" for row in ch.get("root_bundle", []))
        for ch in chains
    )


def test_link_chains_resolves_same_context_direct_call_without_channel():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0005",
            "sink_label": "COPY_SINK",
            "sink_function": "handler",
            "sink_site": "0x08006000",
            "roots": [
                {"role": "primary", "expr": "n", "kind": "length", "source": "call_args"},
                {"role": "secondary", "expr": "src", "kind": "src_ptr", "source": "call_args"},
            ],
            "evidence_refs": [],
            "confidence": 0.95,
            "status": "ok",
        },
    ]
    sources = [
        {
            "label": "MMIO_READ",
            "address": 0x40011004,
            "function_name": "uart_read_byte",
            "evidence_refs": ["E_SRC3"],
        },
    ]
    mai = _FakeMai(
        decompiled_cache={
            "handler": """
void handler(char *dst, unsigned int n) {
  for (i = 0; i < n; i++) { src[i] = uart_read_byte(); }
  memcpy(dst, src, n);
}
""",
        },
    )

    chains = link_chains(
        sink_roots,
        {"object_nodes": [], "channel_edges": []},
        mai=mai,
        sources=sources,
        sink_facts_by_pack={"p6": {"has_bounds_guard": False}},
        sink_pack_id_by_site={"0x08006000|handler|COPY_SINK": "p6"},
        binary_stem="fw",
    )

    assert any(step.get("kind") == "SOURCE" for step in chains[0]["steps"])
    assert any(ch["verdict"] == "CONFIRMED" for ch in chains)
    assert any(ch["link_debug"]["source_resolve_mode"] == "same_context_direct_call" for ch in chains)


def test_link_chains_uses_unique_caller_bridge_as_weak_source_anchor():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0006",
            "sink_label": "COPY_SINK",
            "sink_function": "do_copy",
            "sink_site": "0x08007000",
            "roots": [
                {"role": "primary", "expr": "len", "kind": "length", "source": "call_args"},
                {"role": "secondary", "expr": "src", "kind": "src_ptr", "source": "call_args"},
            ],
            "evidence_refs": [],
            "confidence": 0.9,
            "status": "ok",
        },
    ]
    sources = [
        {
            "label": "MMIO_READ",
            "address": 0x40004404,
            "function_name": "spi_read_byte",
            "evidence_refs": ["E_SRC4"],
        },
    ]
    mai = _FakeMai(
        decompiled_cache={
            "do_copy": """
void do_copy(const uint8_t *src, unsigned int len) {
  memcpy(local, src, len);
}
""",
            "parse_packet": """
void parse_packet(void) {
  unsigned int payload_len = read_header();
  for (i = 0; i < payload_len; i++) { g_staging[i] = spi_read_byte(); }
  do_copy(g_staging, payload_len);
}
""",
        },
    )

    chains = link_chains(
        sink_roots,
        {"object_nodes": [], "channel_edges": []},
        mai=mai,
        sources=sources,
        sink_facts_by_pack={"p7": {"has_bounds_guard": False}},
        sink_pack_id_by_site={"0x08007000|do_copy|COPY_SINK": "p7"},
        binary_stem="fw",
    )

    assert any(step.get("kind") == "SOURCE" for step in chains[0]["steps"])
    assert any(step.get("kind") == "BRIDGE" for step in chains[0]["steps"])
    assert any(ch["link_debug"]["source_resolve_mode"] == "caller_bridge" for ch in chains)
    assert any(ch["link_debug"]["bridge_functions"] == ["parse_packet"] for ch in chains)
    assert all(ch["verdict"] != "CONFIRMED" for ch in chains)


def test_link_chains_assigns_unique_chain_ids_per_root_variant():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0007",
            "sink_label": "COPY_SINK",
            "sink_function": "handler",
            "sink_site": "0x08008000",
            "roots": [
                {"role": "primary", "expr": "n", "kind": "length", "source": "call_args"},
                {"role": "secondary", "expr": "src", "kind": "src_ptr", "source": "call_args"},
                {"role": "secondary", "expr": "dst", "kind": "dst_ptr", "source": "call_args"},
            ],
            "evidence_refs": [],
            "confidence": 0.95,
            "status": "ok",
        },
    ]
    sources = [
        {
            "label": "MMIO_READ",
            "address": 0x40011004,
            "function_name": "uart_read_byte",
            "evidence_refs": ["E_SRC5"],
        },
    ]
    mai = _FakeMai(
        decompiled_cache={
            "handler": """
void handler(char *dst, unsigned int n) {
  for (i = 0; i < n; i++) { src[i] = uart_read_byte(); }
  memcpy(dst, src, n);
}
""",
        },
    )

    chains = link_chains(
        sink_roots,
        {"object_nodes": [], "channel_edges": []},
        mai=mai,
        sources=sources,
        sink_facts_by_pack={"p8": {"has_bounds_guard": False}},
        sink_pack_id_by_site={"0x08008000|handler|COPY_SINK": "p8"},
        binary_stem="fw",
    )

    ids = [ch["chain_id"] for ch in chains]
    assert len(ids) == len(set(ids))


def test_copy_sink_secondary_pointer_root_does_not_confirm_without_risk_root():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0005",
            "sink_label": "COPY_SINK",
            "sink_function": "bt_spi_rx_thread",
            "sink_site": "0x08006000",
            "roots": [
                {"role": "primary", "expr": "4", "kind": "length", "source": "call_args"},
                {"role": "secondary", "expr": "rxmsg + 1", "kind": "src_ptr", "source": "call_args"},
            ],
            "evidence_refs": [],
            "confidence": 0.6,
            "status": "ok",
            "root_source": "call_args",
        },
    ]
    sources = [
        {
            "label": "MMIO_READ",
            "address": 0x4001300c,
            "function_name": "bt_spi_rx_thread",
            "evidence_refs": ["E_SRC3"],
        },
    ]

    chains = link_chains(
        sink_roots,
        {"object_nodes": [], "channel_edges": []},
        mai=None,
        sources=sources,
        sink_facts_by_pack={"p6": {"has_bounds_guard": False}},
        sink_pack_id_by_site={"0x08006000|bt_spi_rx_thread|COPY_SINK": "p6"},
        binary_stem="fw",
        max_depth=2,
    )

    matched = [ch for ch in chains if ch["sink"]["root_expr"] == "rxmsg + 1"]
    if matched:
        assert matched[0]["verdict"] == "SUSPICIOUS"
    else:
        assert all(ch["verdict"] != "CONFIRMED" for ch in chains)


def test_link_chains_drops_bridge_only_copy_group_without_length_root():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0009",
            "sink_label": "COPY_SINK",
            "sink_function": "handle_name",
            "sink_site": "0x08009000",
            "roots": [
                {"role": "primary", "expr": "g_name", "kind": "src_data", "source": "call_args"},
                {"role": "secondary", "expr": "local_name", "kind": "dst_ptr", "source": "call_args"},
            ],
            "evidence_refs": [],
            "confidence": 0.7,
            "status": "ok",
            "root_source": "call_args",
        },
    ]
    sources = [
        {
            "label": "MMIO_READ",
            "address": 0x40011004,
            "function_name": "uart_read_byte",
            "evidence_refs": ["E_SRC6"],
        },
    ]
    mai = _FakeMai(
        decompiled_cache={
            "handle_name": """
void handle_name(char *dst) {
  strcpy(dst, g_name);
}
""",
            "main": """
void main(void) {
  uart_read_byte();
  handle_name(buf);
}
""",
        },
    )

    chains = link_chains(
        sink_roots,
        {"object_nodes": [], "channel_edges": []},
        mai=mai,
        sources=sources,
        sink_facts_by_pack={"p9": {"has_bounds_guard": False}},
        sink_pack_id_by_site={"0x08009000|handle_name|COPY_SINK": "p9"},
        binary_stem="fw",
    )

    assert chains == []


def test_link_chains_skips_non_actionable_isr_store_sink():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0010",
            "sink_label": "STORE_SINK",
            "sink_function": "USART1_IRQHandler",
            "sink_site": "0x080000c0",
            "roots": [
                {"role": "primary", "expr": "0x20000008", "kind": "target_addr", "source": "target_addr"},
            ],
            "evidence_refs": [],
            "confidence": 0.6,
            "status": "ok",
            "root_source": "target_addr",
        },
    ]
    sources = [
        {
            "label": "ISR_FILLED_BUFFER",
            "address": 0x20000000,
            "function_name": "USART1_IRQHandler",
            "evidence_refs": ["E_ISR_SRC"],
        },
    ]

    chains = link_chains(
        sink_roots,
        {"object_nodes": [], "channel_edges": []},
        mai=None,
        sources=sources,
        sink_facts_by_pack={"p10": {}},
        sink_pack_id_by_site={"0x080000c0|USART1_IRQHandler|STORE_SINK": "p10"},
        binary_stem="fw",
    )

    assert chains == []


def test_dma_labeled_object_can_be_ranked_even_without_members():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0006",
            "sink_label": "COPY_SINK",
            "sink_function": "process_dma_data",
            "sink_site": "0x08007000",
            "roots": [
                {"role": "primary", "expr": "rx_len", "kind": "length", "source": "call_args"},
                {"role": "secondary", "expr": "g_dma_rx_buf", "kind": "src_ptr", "source": "call_args"},
            ],
            "evidence_refs": [],
            "confidence": 0.7,
            "status": "ok",
            "root_source": "call_args",
        },
    ]
    channel_graph = {
        "object_nodes": [
            {
                "object_id": "obj_sram_20000000_200000ff",
                "addr_range": ["0x20000000", "0x200000ff"],
                "members": ["g_dma_rx_buf"],
                "writer_sites": [],
                "writers": [],
                "reader_sites": [{"context": "MAIN", "fn": "process_dma_data"}],
                "readers": ["process_dma_data"],
                "type_facts": {"kind_hint": "payload"},
            },
            {
                "object_id": "obj_dma_40020000_400200ff",
                "addr_range": ["0x40020000", "0x400200ff"],
                "members": [],
                "writer_sites": [{"context": "DMA", "fn": "dma_start_rx"}],
                "writers": ["dma_start_rx"],
                "reader_sites": [],
                "readers": [],
                "region_kind": "DMA_BUFFER",
                "type_facts": {"source_label": "DMA_BACKED_BUFFER", "kind_hint": "payload"},
            },
        ],
        "channel_edges": [
            {
                "src_context": "DMA",
                "dst_context": "MAIN",
                "object_id": "obj_dma_40020000_400200ff",
                "score": 0.9,
                "evidence_refs": ["E_CH4"],
            },
        ],
    }
    sources = [
        {
            "label": "DMA_BACKED_BUFFER",
            "address": 0x40020000,
            "function_name": "dma_start_rx",
            "evidence_refs": ["E_DMA_SRC2"],
        },
    ]

    chains = link_chains(
        sink_roots,
        channel_graph,
        mai=None,
        sources=sources,
        sink_facts_by_pack={"p7": {"has_bounds_guard": False}},
        sink_pack_id_by_site={"0x08007000|process_dma_data|COPY_SINK": "p7"},
        binary_stem="fw",
        max_depth=2,
    )

    assert any(any(step.get("kind") == "CHANNEL" for step in ch["steps"]) for ch in chains)
    assert any(
        ch["link_debug"]["object_hit_mode"] in {"expr_member", "support_root", "context_rw"}
        for ch in chains
    )


def test_store_sink_control_root_from_init_path_is_dropped():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0010",
            "sink_label": "STORE_SINK",
            "sink_function": "wdt_sam_feed",
            "sink_site": "0x0800a000",
            "roots": [
                {"role": "primary", "expr": "dev", "kind": "dst_ptr", "source": "param_name"},
            ],
            "evidence_refs": ["E_SINK"],
            "confidence": 0.5,
            "status": "ok",
        },
    ]
    channel_graph = {
        "object_nodes": [
            {
                "object_id": "obj_sram_20002000_200020ff",
                "addr_range": ["0x20002000", "0x200020ff"],
                "writer_sites": [{"context": "DMA", "fn": "atmel_sam4s_init"}],
                "writers": ["atmel_sam4s_init"],
                "members": ["dev"],
            },
        ],
        "channel_edges": [
            {
                "src_context": "DMA",
                "dst_context": "MAIN",
                "object_id": "obj_sram_20002000_200020ff",
                "score": 0.8,
                "evidence_refs": ["E_CH"],
            },
        ],
    }
    sources = [
        {
            "label": "DMA_BACKED_BUFFER",
            "address": 0x400E0000,
            "function_name": "atmel_sam4s_init",
            "evidence_refs": ["E_SRC"],
        },
    ]

    chains = link_chains(
        sink_roots,
        channel_graph,
        mai=None,
        sources=sources,
        sink_facts_by_pack={"p10": {"has_bounds_guard": False}},
        sink_pack_id_by_site={"0x0800a000|wdt_sam_feed|STORE_SINK": "p10"},
        binary_stem="fw",
        max_depth=2,
    )

    assert len(chains) == 1
    assert chains[0]["verdict"] == "DROP"
    assert chains[0]["link_debug"]["control_path_only"] is True


def test_bridge_from_fatal_system_source_is_dropped():
    sink_roots = [
        {
            "sink_id": "SINK_fw_0011",
            "sink_label": "COPY_SINK",
            "sink_function": "net_pkt_compact",
            "sink_site": "0x0800b000",
            "roots": [
                {"role": "primary", "expr": "n", "kind": "length", "source": "call_args"},
            ],
            "evidence_refs": ["E_SINK"],
            "confidence": 0.7,
            "status": "ok",
        },
    ]
    channel_graph = {
        "object_nodes": [
            {
                "object_id": "obj_sram_20103600_201036ff",
                "addr_range": ["0x20103600", "0x201036ff"],
                "reader_sites": [{"context": "TASK", "fn": "net_pkt_compact"}],
                "readers": ["net_pkt_compact"],
                "writer_sites": [{"context": "MAIN", "fn": "log_strdup"}],
                "writers": ["log_strdup"],
            }
        ],
        "channel_edges": [
            {
                "src_context": "MAIN",
                "dst_context": "TASK",
                "object_id": "obj_sram_20103600_201036ff",
                "score": 0.7,
                "evidence_refs": [],
            }
        ],
    }
    sources = [
        {
            "label": "MMIO_READ",
            "address": 0xE000ED04,
            "function_name": "z_impl_k_thread_abort",
            "evidence_refs": ["E_SRC"],
        },
    ]
    mai = _FakeMai(
        decompiled_cache={
            "net_pkt_compact": "void net_pkt_compact(size_t n) { memcpy(dst, src, n); }",
            "log_strdup": "void log_strdup(void) { net_pkt_compact(8); }",
            "z_fatal_error": "void z_fatal_error(void) { log_strdup(); z_impl_k_thread_abort(); }",
        },
    )

    chains = link_chains(
        sink_roots,
        channel_graph,
        mai=mai,
        sources=sources,
        sink_facts_by_pack={"p11": {"has_bounds_guard": False}},
        sink_pack_id_by_site={"0x0800b000|net_pkt_compact|COPY_SINK": "p11"},
        binary_stem="fw",
    )

    assert len(chains) == 1
    assert chains[0]["verdict"] == "DROP"
