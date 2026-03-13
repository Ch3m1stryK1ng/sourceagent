"""Build the canonical no-GT evaluation manifests used by docs/test_full.md."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List


REPO_ROOT = Path(__file__).resolve().parents[2]
FIRMWARE_ROOT = REPO_ROOT / "firmware"
EVAL_SUITE_ROOT = FIRMWARE_ROOT / "eval_suite"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()
    return slug or "sample"


def _build_sample_id(dataset: str, rel_path: Path) -> str:
    rel_parts = list(rel_path.with_suffix("").parts)
    if rel_parts and rel_parts[0].lower() == dataset.lower():
        rel_parts = rel_parts[1:]
    parts = [dataset.replace("-", "_")] + rel_parts
    return _slug("__".join(parts))


def _iter_unstripped_elfs(root: Path) -> List[Path]:
    return sorted(path for path in root.glob("**/*.elf") if not path.name.endswith("_stripped.elf"))


def _dataset_counts(samples: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counter = Counter(sample["dataset"] for sample in samples)
    return dict(sorted(counter.items()))


def _build_samples() -> List[Dict[str, Any]]:
    gt_backed = _load_json(EVAL_SUITE_ROOT / "gt_backed_suite_manifest.json")
    gt_paths = {Path(sample["binary_path"]).resolve() for sample in gt_backed["samples"]}

    datasets = [
        ("p2im-unit_tests", FIRMWARE_ROOT / "p2im-unit_tests"),
        ("monolithic-firmware-collection", FIRMWARE_ROOT / "monolithic-firmware-collection"),
        ("uSBS", FIRMWARE_ROOT / "uSBS"),
    ]

    samples: List[Dict[str, Any]] = []
    for dataset, root in datasets:
        for binary_path in _iter_unstripped_elfs(root):
            if binary_path.resolve() in gt_paths:
                continue
            rel_path = binary_path.relative_to(FIRMWARE_ROOT)
            sample_id = _build_sample_id(dataset, rel_path)
            samples.append(
                {
                    "dataset": dataset,
                    "sample_id": sample_id,
                    "output_stem": sample_id,
                    "binary_path": str(binary_path),
                    "relative_binary_path": rel_path.as_posix(),
                    "has_gt": False,
                    "notes": "no_gt_canonical_20260309",
                }
            )
    samples.sort(key=lambda sample: (sample["dataset"], sample["sample_id"]))
    return samples


def _split_into_shards(samples: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    by_dataset: Dict[str, List[Dict[str, Any]]] = {}
    for sample in samples:
        by_dataset.setdefault(sample["dataset"], []).append(sample)

    shard1: List[Dict[str, Any]] = []
    shard2: List[Dict[str, Any]] = []

    p2im = by_dataset["p2im-unit_tests"]
    mono = by_dataset["monolithic-firmware-collection"]
    usbs = by_dataset["uSBS"]

    shard1.extend(p2im[::2])
    shard2.extend(p2im[1::2])

    shard2.extend(mono[::2])
    shard1.extend(mono[1::2])

    shard1.extend(usbs[::2])
    shard2.extend(usbs[1::2])

    shard1.sort(key=lambda sample: (sample["dataset"], sample["sample_id"]))
    shard2.sort(key=lambda sample: (sample["dataset"], sample["sample_id"]))
    return [shard1, shard2]


def build_no_gt_manifests(repo_root: Path | None = None) -> Dict[str, Any]:
    if repo_root is not None and repo_root != REPO_ROOT:
        raise ValueError("Only the checked-out repository root is supported")

    samples = _build_samples()
    if len(samples) != 94:
        raise RuntimeError(f"Expected 94 no-GT samples, found {len(samples)}")

    canonical = {
        "name": "no_gt_94_canonical",
        "created_at": _now_utc(),
        "description": (
            "Canonical no-GT corpus matching the 2026-03-09 combined eval summary: "
            "47 p2im-unit_tests + 37 remaining monolithic ELFs + 10 remaining uSBS ELFs."
        ),
        "source_reference": "docs/combined_eval_gt_plus_nogt_20260309.json",
        "count": len(samples),
        "by_dataset": _dataset_counts(samples),
        "samples": samples,
    }

    shard_payloads: List[Dict[str, Any]] = []
    for idx, shard_samples in enumerate(_split_into_shards(samples), start=1):
        shard_payloads.append(
            {
                "name": f"no_gt_94_shard{idx}",
                "created_at": _now_utc(),
                "parent_manifest": "firmware/eval_suite/no_gt_94_manifest.json",
                "count": len(shard_samples),
                "by_dataset": _dataset_counts(shard_samples),
                "samples": shard_samples,
            }
        )

    _write_json(EVAL_SUITE_ROOT / "no_gt_94_manifest.json", canonical)
    for idx, payload in enumerate(shard_payloads, start=1):
        _write_json(EVAL_SUITE_ROOT / f"no_gt_94_shard{idx}_manifest.json", payload)

    return {
        "count": canonical["count"],
        "by_dataset": canonical["by_dataset"],
        "shard_counts": [payload["count"] for payload in shard_payloads],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build canonical no-GT manifests.")
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    args = parser.parse_args()
    summary = build_no_gt_manifests(Path(args.repo_root).resolve())
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
