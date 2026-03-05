"""Tests for eval CLI helper utilities in interface/main.py."""

import json

from sourceagent.interface.main import (
    _infer_eval_scope_from_gt,
    _load_gt_registry_from_json,
    _parse_eval_formats,
)
from sourceagent.pipeline.models import GroundTruthEntry


def test_parse_eval_formats_defaults_and_dedup():
    assert _parse_eval_formats("") == ["bin", "elf"]
    assert _parse_eval_formats("bin,elf,bin,.elf") == ["bin", "elf"]


def test_load_gt_registry_from_json_list(tmp_path):
    gt_path = tmp_path / "gt.json"
    gt_path.write_text(json.dumps([
        {
            "binary_stem": "fw1",
            "label": "COPY_SINK",
            "address": 0x08000010,
            "function_name": "handler",
            "notes": "test",
        },
    ]), encoding="utf-8")

    reg = _load_gt_registry_from_json(gt_path)
    assert "fw1" in reg
    assert len(reg["fw1"]) == 1
    assert reg["fw1"][0].label == "COPY_SINK"
    assert reg["fw1"][0].address == 0x08000010


def test_load_gt_registry_from_json_dict(tmp_path):
    gt_path = tmp_path / "gt.json"
    gt_path.write_text(json.dumps({
        "fw2": [
            {"label": "MMIO_READ", "function_name": "read_byte"},
        ],
    }), encoding="utf-8")

    reg = _load_gt_registry_from_json(gt_path)
    assert "fw2" in reg
    assert reg["fw2"][0].binary_stem == "fw2"
    assert reg["fw2"][0].label == "MMIO_READ"


def test_infer_eval_scope_from_gt_sinks():
    gt = [
        GroundTruthEntry(binary_stem="fw", label="COPY_SINK"),
        GroundTruthEntry(binary_stem="fw", label="STORE_SINK"),
    ]
    assert _infer_eval_scope_from_gt(gt) == "sinks"


def test_infer_eval_scope_from_gt_sources():
    gt = [
        GroundTruthEntry(binary_stem="fw", label="MMIO_READ"),
        GroundTruthEntry(binary_stem="fw", label="DMA_BACKED_BUFFER"),
    ]
    assert _infer_eval_scope_from_gt(gt) == "sources"
