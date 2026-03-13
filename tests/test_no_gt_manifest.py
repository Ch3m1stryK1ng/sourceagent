import json
from pathlib import Path


REPO_ROOT = Path("/home/a347908610/sourceagent")


def _load_json(path: str):
    return json.loads((REPO_ROOT / path).read_text())


def test_no_gt_manifest_matches_historical_counts():
    manifest = _load_json("firmware/eval_suite/no_gt_94_manifest.json")
    shard1 = _load_json("firmware/eval_suite/no_gt_94_shard1_manifest.json")
    shard2 = _load_json("firmware/eval_suite/no_gt_94_shard2_manifest.json")
    gt_backed = _load_json("firmware/eval_suite/gt_backed_suite_manifest.json")

    assert manifest["count"] == 94
    assert manifest["by_dataset"] == {
        "monolithic-firmware-collection": 37,
        "p2im-unit_tests": 47,
        "uSBS": 10,
    }
    assert shard1["count"] == 47
    assert shard2["count"] == 47
    assert shard1["by_dataset"] == {
        "monolithic-firmware-collection": 18,
        "p2im-unit_tests": 24,
        "uSBS": 5,
    }
    assert shard2["by_dataset"] == {
        "monolithic-firmware-collection": 19,
        "p2im-unit_tests": 23,
        "uSBS": 5,
    }

    gt_paths = {sample["binary_path"] for sample in gt_backed["samples"]}
    no_gt_paths = {sample["binary_path"] for sample in manifest["samples"]}
    assert not (gt_paths & no_gt_paths)
    assert all(Path(sample["binary_path"]).exists() for sample in manifest["samples"])
