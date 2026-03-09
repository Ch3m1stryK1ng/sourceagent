import json
from pathlib import Path

from sourceagent.pipeline.microbench_gt_v2 import (
    MICROBENCH_SAMPLES,
    SCHEMA_VERSION,
    build_microbench_gt_v2,
    validate_microbench_gt_v2_tree,
    validate_sample_schema,
)


def test_build_microbench_gt_v2_skeletons(tmp_path):
    manifest = build_microbench_gt_v2(
        repo_root=Path("/home/a347908610/sourceagent"),
        out_dir=tmp_path,
    )
    assert manifest["schema_version"] == SCHEMA_VERSION
    assert manifest["sample_count"] == len(MICROBENCH_SAMPLES)
    sample_dir = tmp_path / "samples"
    assert len(list(sample_dir.glob("*.json"))) == len(MICROBENCH_SAMPLES)

    sample = json.loads((sample_dir / "t0_isr_filled_buffer.json").read_text())
    assert sample["annotation_status"]["sources"] == "seeded_from_v1"
    assert sample["annotation_status"]["objects"] == "todo_manual"
    assert sample["sample_meta"]["expected_channel_mode"] == "required"
    assert len(sample["sources"]) >= 1
    assert len(sample["sinks"]) >= 1

    mmio = json.loads((sample_dir / "t0_mmio_read.json").read_text())
    assert any(sink["function_name"] == "process_data" for sink in mmio["sinks"])


def test_build_microbench_gt_v2_preserves_existing_annotations(tmp_path):
    manifest = build_microbench_gt_v2(
        repo_root=Path("/home/a347908610/sourceagent"),
        out_dir=tmp_path,
    )
    assert manifest["sample_count"] == len(MICROBENCH_SAMPLES)
    sample_path = tmp_path / "samples" / "t0_mmio_read.json"
    sample = json.loads(sample_path.read_text())
    sample["annotation_status"]["overall"] = "complete"
    sample["notes"] = ["preserve me"]
    sample_path.write_text(json.dumps(sample, indent=2) + "\n")

    manifest2 = build_microbench_gt_v2(
        repo_root=Path("/home/a347908610/sourceagent"),
        out_dir=tmp_path,
    )
    assert manifest2["sample_count"] == len(MICROBENCH_SAMPLES)
    sample2 = json.loads(sample_path.read_text())
    assert sample2["annotation_status"]["overall"] == "complete"
    assert sample2["notes"] == ["preserve me"]


def test_validate_microbench_gt_v2_repo_tree():
    root = Path("/home/a347908610/sourceagent/firmware/ground_truth_bundle/microbench_v2")
    report = validate_microbench_gt_v2_tree(root)
    assert report["ok"], report["errors"]


def test_repo_contains_completed_archetype_annotations():
    root = Path("/home/a347908610/sourceagent/firmware/ground_truth_bundle/microbench_v2/samples")

    isr = json.loads((root / "t0_isr_filled_buffer.json").read_text())
    assert isr["annotation_status"]["overall"] == "complete"
    assert len(isr["objects"]) == 2
    assert len(isr["channels"]) == 1
    assert isr["chains"][0]["must_use_channel"] is True
    assert isr["chains"][0]["expected_verdict"] == "SAFE_OR_LOW_RISK"

    dma = json.loads((root / "t0_dma_backed_buffer.json").read_text())
    assert dma["annotation_status"]["overall"] == "complete"
    assert len(dma["objects"]) == 1
    assert len(dma["channels"]) == 1
    assert dma["sinks"] == []
    assert dma["negative_expectations"][0]["target_kind"] == "sample"

    cve = json.loads((root / "cve_2020_10065_hci_spi.json").read_text())
    assert cve["annotation_status"]["overall"] == "complete"
    assert len(cve["sink_roots"]) == 2
    assert {chain["expected_verdict"] for chain in cve["chains"]} == {"CONFIRMED"}


def test_all_microbench_samples_are_now_artifact_complete():
    manifest = json.loads(
        Path("/home/a347908610/sourceagent/firmware/ground_truth_bundle/microbench_v2/index.json").read_text()
    )
    complete = [item["binary_stem"] for item in manifest["samples"] if item["annotation_level"] == "complete"]
    assert len(complete) == len(MICROBENCH_SAMPLES)

    usb = json.loads(
        Path("/home/a347908610/sourceagent/firmware/ground_truth_bundle/microbench_v2/samples/cve_2021_34259_usb_host.json").read_text()
    )
    assert [chain["expected_verdict"] for chain in usb["chains"]] == ["CONFIRMED", "CONFIRMED", "SUSPICIOUS"]

    dns = json.loads(
        Path("/home/a347908610/sourceagent/firmware/ground_truth_bundle/microbench_v2/samples/cve_2018_16525_freertos_dns.json").read_text()
    )
    assert [chain["expected_verdict"] for chain in dns["chains"]] == ["SUSPICIOUS", "CONFIRMED", "CONFIRMED"]


def test_validate_sample_schema_requires_known_references():
    sample = {
        "schema_version": SCHEMA_VERSION,
        "binary_stem": "demo",
        "binary_paths": {
            "source_file": "a.c",
            "map_file": "a.map",
            "elf_file": "a.elf",
            "bin_file": "a.bin",
        },
        "sample_meta": {
            "title": "demo",
            "mechanism_group": "same_context_direct",
            "runtime_style": "baremetal_polling",
            "inspiration": "toy",
            "arch": "ARM_CORTEX_M",
            "expected_channel_mode": "none",
            "chain_shape": "same_context_direct_call",
        },
        "annotation_status": {
            "sources": "complete",
            "objects": "complete",
            "channels": "complete",
            "sinks": "complete",
            "sink_roots": "complete",
            "derive_checks": "complete",
            "chains": "complete",
            "negative_expectations": "complete",
            "overall": "complete",
        },
        "sources": [{"source_id": "R1", "label": "MMIO_READ", "function_name": "f", "site_kind": "mmio_read", "context": "MAIN", "status": "complete"}],
        "objects": [{"object_id": "O1", "region_kind": "SRAM_CLUSTER", "producer_contexts": ["MAIN"], "consumer_contexts": ["MAIN"]}],
        "channels": [{"channel_id": "C1", "src_context": "MAIN", "object_id": "O1", "dst_context": "MAIN", "edge_kind": "DATA", "constraints": [], "evidence_refs": []}],
        "sinks": [{"sink_id": "S1", "label": "COPY_SINK", "function_name": "g", "site_kind": "copy_call_or_copy_idiom", "status": "complete"}],
        "sink_roots": [{"root_id": "SR1", "sink_id": "S1", "root_role": "len", "expr": "n", "status": "complete"}],
        "derive_checks": [{"derive_check_id": "D1", "sink_id": "S1", "root_id": "SR1", "derive_facts": [], "check_facts": [], "status": "complete"}],
        "chains": [{"chain_id": "CH1", "sink_id": "S1", "expected_verdict": "CONFIRMED", "required_source_ids": ["R1"], "required_object_ids": ["O1"], "required_channel_ids": ["C1"], "required_root_ids": ["SR1"], "required_derive_check_ids": ["D1"]}],
        "negative_expectations": [{"negative_id": "N1", "target_kind": "source", "target_id": "R1", "expected_verdict": "DROP", "reason": "demo"}],
    }
    assert validate_sample_schema(sample, strict=True) == []
