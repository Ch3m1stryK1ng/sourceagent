"""Tests for M8.6 object boundary refiner."""

from sourceagent.pipeline.object_refine import refine_object_boundaries


def test_refine_object_boundaries_splits_payload_and_control():
    raw = [
        {
            "object_id": "obj_rx",
            "region_kind": "SRAM_CLUSTER",
            "members": ["g_rx_buf", "g_rx_head", "g_rx_tail"],
            "addr_range": ["0x20000000", "0x200000ff"],
            "writer_sites": [{"context": "ISR", "fn": "uart_isr"}],
            "reader_sites": [{"context": "MAIN", "fn": "copy_fn"}],
            "type_facts": {},
        },
    ]

    out = refine_object_boundaries(raw, access_traces=[])

    ids = {o["object_id"] for o in out}
    assert "obj_rx_payload" in ids
    assert "obj_rx_ctrl" in ids

    by_id = {o["object_id"]: o for o in out}
    assert by_id["obj_rx_payload"]["region_kind"] == "SRAM_CLUSTER"
    assert by_id["obj_rx_ctrl"]["region_kind"] == "FLAG"
    assert by_id["obj_rx_payload"]["type_facts"]["byte_size_estimate"] != "unknown"
    assert by_id["obj_rx_ctrl"]["type_facts"]["byte_size_estimate"] != "unknown"
    assert by_id["obj_rx_payload"]["addr_range"] != by_id["obj_rx_ctrl"]["addr_range"]


def test_refine_object_boundaries_keeps_coarse_when_no_members():
    raw = [
        {
            "object_id": "obj_unknown",
            "region_kind": "SRAM_CLUSTER",
            "members": [],
            "type_facts": {},
        },
    ]

    out = refine_object_boundaries(raw, access_traces=[])

    assert len(out) == 1
    assert out[0]["object_id"] == "obj_unknown"
    assert out[0]["type_facts"]["refine_status"] == "coarse"


def test_refine_object_boundaries_attaches_extent_metadata_without_split():
    raw = [
        {
            "object_id": "obj_dma",
            "region_kind": "DMA_BUFFER",
            "members": ["dma_rx_buf"],
            "addr_range": ["0x20000100", "0x2000017f"],
            "writer_sites": [{"context": "DMA", "fn": "dma_irq"}],
            "reader_sites": [{"context": "MAIN", "fn": "net_copy"}],
            "type_facts": {"kind_hint": "payload"},
        },
    ]

    out = refine_object_boundaries(raw, access_traces=[])

    assert len(out) == 1
    item = out[0]
    assert item["type_facts"]["byte_size_estimate"] == 128
    assert item["type_facts"]["byte_size_source"] == "addr_range"
    assert item["type_facts"]["cross_context"] is True
    assert item["type_facts"]["payload_byte_size"] == 128
