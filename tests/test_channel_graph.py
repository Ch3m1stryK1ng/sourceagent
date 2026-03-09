"""Tests for M8.5 channel graph builder."""

from sourceagent.pipeline.channel_graph import build_channel_graph
from sourceagent.pipeline.models import MemoryAccess, MemoryAccessIndex


def test_build_channel_graph_emits_isr_to_main_edge():
    mai = MemoryAccessIndex(binary_path="/tmp/fw.elf")
    mai.accesses = [
        MemoryAccess(
            address=0x08001010,
            kind="store",
            width=1,
            target_addr=0x20000010,
            function_name="USART1_IRQHandler",
            function_addr=0x08001000,
            in_isr=True,
        ),
        MemoryAccess(
            address=0x08002020,
            kind="load",
            width=1,
            target_addr=0x20000010,
            function_name="main",
            function_addr=0x08002000,
            in_isr=False,
        ),
    ]

    graph = build_channel_graph(mai, verified_labels=[], memory_map=None)

    assert graph["schema_version"] == "0.1"
    assert len(graph["object_nodes"]) >= 1
    assert any(
        e["src_context"] == "ISR" and e["dst_context"] == "MAIN"
        for e in graph["channel_edges"]
    )


def test_build_channel_graph_augments_dma_object_from_labels():
    mai = MemoryAccessIndex(binary_path="/tmp/fw.elf")
    labels = [
        {
            "label": "DMA_BACKED_BUFFER",
            "address": 0x20001000,
            "function_name": "dma_setup",
            "evidence_refs": ["E_DMA_1"],
        },
    ]

    graph = build_channel_graph(mai, verified_labels=labels, memory_map=None)

    assert any(o["region_kind"] == "DMA_BUFFER" for o in graph["object_nodes"])
    assert any(e["src_context"] == "DMA" for e in graph["channel_edges"])


def test_build_channel_graph_merges_isr_label_into_symbol_backed_cluster():
    mai = MemoryAccessIndex(
        binary_path="/tmp/fw.elf",
        global_symbol_table={
            "g_rx_buf": 0x20000010,
            "g_rx_head": 0x20000020,
        },
    )
    mai.accesses = [
        MemoryAccess(
            address=0x08001010,
            kind="store",
            width=1,
            target_addr=0x20000010,
            function_name="USART1_IRQHandler",
            function_addr=0x08001000,
            in_isr=True,
        ),
        MemoryAccess(
            address=0x08002020,
            kind="load",
            width=1,
            target_addr=0x20000010,
            function_name="process_packet",
            function_addr=0x08002000,
            in_isr=False,
        ),
    ]
    labels = [
        {
            "label": "ISR_FILLED_BUFFER",
            "address": 0x20000000,
            "function_name": "USART1_IRQHandler",
            "evidence_refs": ["E_ISR"],
        },
    ]

    graph = build_channel_graph(mai, verified_labels=labels, memory_map=None)

    assert len(graph["object_nodes"]) == 1
    obj = graph["object_nodes"][0]
    assert "g_rx_buf" in obj["members"]
    assert "g_rx_head" in obj["members"]
    assert obj["producer_contexts"] == ["ISR"]
    assert obj["consumer_contexts"] == ["MAIN"]
    assert obj["type_facts"]["source_label"] == "ISR_FILLED_BUFFER"
    assert len(graph["channel_edges"]) == 1
    assert graph["channel_edges"][0]["object_id"] == obj["object_id"]


def test_build_channel_graph_merges_dma_label_into_symbol_backed_cluster_and_recovers_main_consumer():
    mai = MemoryAccessIndex(
        binary_path="/tmp/fw.elf",
        global_symbol_table={
            "g_dma_rx_buf": 0x20000010,
        },
        decompiled_cache={
            "dma_start_rx": "DMA1_CMAR = (uint32_t)g_dma_rx_buf;",
            "process_dma_data": "memcpy(local_buf, g_dma_rx_buf, rx_len);",
        },
    )
    labels = [
        {
            "label": "DMA_BACKED_BUFFER",
            "address": 0x40020000,
            "function_name": "dma_start_rx",
            "evidence_refs": ["E_DMA"],
            "facts": {
                "config_function": "dma_start_rx",
                "write_targets": ["0x40020010", "0x40020014", "0x40020000"],
            },
        },
    ]

    graph = build_channel_graph(mai, verified_labels=labels, memory_map=None)

    assert len(graph["object_nodes"]) == 1
    obj = graph["object_nodes"][0]
    assert obj["region_kind"] == "DMA_BUFFER"
    assert "g_dma_rx_buf" in obj["members"]
    assert "DMA" in obj["producer_contexts"]
    assert "MAIN" in obj["consumer_contexts"]
    assert any(reader["fn"] == "process_dma_data" for reader in obj["reader_sites"])
    assert any(
        e["src_context"] == "DMA" and e["dst_context"] == "MAIN"
        for e in graph["channel_edges"]
    )
