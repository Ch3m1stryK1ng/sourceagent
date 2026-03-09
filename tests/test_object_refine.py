"""Tests for M8.6 object boundary refiner."""

from sourceagent.pipeline.object_refine import refine_object_boundaries


def test_refine_object_boundaries_splits_payload_and_control():
    raw = [
        {
            "object_id": "obj_rx",
            "region_kind": "SRAM_CLUSTER",
            "members": ["g_rx_buf", "g_rx_head", "g_rx_tail"],
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
