import json
from pathlib import Path


REPO_ROOT = Path("/home/a347908610/sourceagent")


def _load_json(path: str):
    return json.loads((REPO_ROOT / path).read_text())


def _elf_machine(path: Path) -> int:
    data = path.read_bytes()[:20]
    assert data[:4] == b"\x7fELF"
    return int.from_bytes(data[18:20], "little")


def test_gt_backed_stripped_manifest_is_complete():
    stripped_manifest = _load_json("firmware/eval_suite/gt_backed_suite_stripped_manifest.json")
    unstripped_manifest = _load_json("firmware/eval_suite/gt_backed_suite_manifest.json")

    assert stripped_manifest["count"] == 44
    assert len(stripped_manifest["samples"]) == 44
    assert {sample["sample_id"] for sample in stripped_manifest["samples"]} == {
        sample["sample_id"] for sample in unstripped_manifest["samples"]
    }

    for sample in stripped_manifest["samples"]:
        stripped_path = Path(sample["binary_path"])
        unstripped_path = Path(sample["unstripped_binary_path"])
        assert stripped_path.exists(), stripped_path
        assert unstripped_path.exists(), unstripped_path
        assert stripped_path.name.endswith("_stripped.elf")
        assert sample["stripped_status"] == "ready"
        assert stripped_path.stat().st_size < unstripped_path.stat().st_size
        assert _elf_machine(stripped_path) == 40


def test_mesobench_stripped_manifest_is_complete():
    manifest = _load_json("firmware/eval_suite/mesobench_stripped_elf_manifest.json")

    assert len(manifest["samples"]) == 30
    assert all(sample["binary_path"].endswith("_stripped.elf") for sample in manifest["samples"])
    assert all(sample["stripped_status"] == "ready" for sample in manifest["samples"])


def test_ground_truth_inventory_has_aligned_gt_tiers():
    inventory = _load_json("firmware/ground_truth_bundle/ground_truth_inventory.json")
    microbench = [entry for entry in inventory if entry["dataset"] == "sourceagent-microbench"]
    mesobench = [entry for entry in inventory if entry["dataset"] == "mesobench"]

    assert len(inventory) == 77
    assert len(microbench) == 14
    assert len(mesobench) == 30
    assert {entry["gt_level"] for entry in microbench} == {"L2"}
    assert {entry["gt_level"] for entry in mesobench} == {"L3"}
    assert all(entry["has_stripped_peer"] for entry in microbench)
    assert any(entry["sample_id"] == "t0_format_string" for entry in microbench)


def test_gt_backed_sink_only_export_covers_current_suite():
    rows = _load_json("firmware/ground_truth_bundle/normalized_gt_sinks_gt_backed.json")

    assert len(rows) > 300
    assert len({row["sample_id"] for row in rows}) == 42
    assert any(
        row["sample_id"] == "t0_format_string" and row["label"] == "FORMAT_STRING_SINK"
        for row in rows
    )
    assert any(
        row["sample_id"] == "t0_func_ptr_dispatch" and row["label"] == "FUNC_PTR_SINK"
        for row in rows
    )
    assert any(row["sample_id"] == "zephyr_cve_2020_10065" for row in rows)


def test_negative_patched_candidate_manifest_curates_phase4_set():
    manifest = _load_json("firmware/eval_suite/negative_patched_candidates_manifest.json")

    assert manifest["count"] == 8
    ids = {sample["sample_id"] for sample in manifest["samples"]}
    assert "udp_echo_server_bof_expl_patched" in ids
    assert "usbs_test_printf_fw" in ids
    assert "zephyr_false_positive_rf_size_check" in ids
    assert all(sample["binary_path"].endswith("_stripped.elf") for sample in manifest["samples"])
