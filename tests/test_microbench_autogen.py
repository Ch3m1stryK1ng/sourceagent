import json
from pathlib import Path


REPO_ROOT = Path("/home/a347908610/sourceagent")


def _load_json(path: str):
    return json.loads((REPO_ROOT / path).read_text())


def _elf_machine(path: Path) -> int:
    data = path.read_bytes()[:20]
    assert data[:4] == b"\x7fELF"
    return int.from_bytes(data[18:20], "little")


def test_microbench_autogen_index_and_sink_gt_are_large_enough():
    index = _load_json("firmware/ground_truth_bundle/microbench_autogen/index.json")
    sink_rows = _load_json("firmware/ground_truth_bundle/normalized_gt_sinks_microbench_autogen.json")
    combined_rows = _load_json("firmware/ground_truth_bundle/normalized_gt_sinks_l1_combined.json")
    combined_manifest = _load_json("firmware/eval_suite/l1_sink_only_combined_manifest.json")

    assert index["sample_count"] == 108
    assert index["family_count"] == 6
    assert len(sink_rows) == 108
    assert {sample["sink_label"] for sample in index["samples"]} == {
        "COPY_SINK",
        "MEMSET_SINK",
        "LOOP_WRITE_SINK",
        "STORE_SINK",
        "FORMAT_STRING_SINK",
        "FUNC_PTR_SINK",
    }
    assert combined_manifest["count"] == 150
    assert len({row["sample_id"] for row in combined_rows}) == 150


def test_microbench_autogen_stripped_manifest_and_files_exist():
    manifest = _load_json("firmware/eval_suite/microbench_autogen_stripped_manifest.json")
    index = _load_json("firmware/ground_truth_bundle/microbench_autogen/index.json")

    assert manifest["count"] == 108
    assert len(manifest["samples"]) == 108
    assert {sample["sample_id"] for sample in manifest["samples"]} == {
        sample["binary_stem"] for sample in index["samples"]
    }

    first = Path(manifest["samples"][0]["binary_path"])
    source = Path(manifest["samples"][0]["unstripped_binary_path"])
    assert first.exists()
    assert source.exists()
    assert first.stat().st_size < source.stat().st_size
    assert _elf_machine(first) == 40
