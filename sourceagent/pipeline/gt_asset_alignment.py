"""Align benchmark assets with the current full-repo test plan.

This module materializes four practical outputs:
  - stripped peers and stripped manifests for the GT-backed suites
  - an expanded sink-only GT export derived from checked-in full-GT samples
  - an updated global ground-truth inventory with GT tier metadata
  - a curated negative/patched candidate manifest for verdict calibration
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List


REPO_ROOT = Path(__file__).resolve().parents[2]
FIRMWARE_ROOT = REPO_ROOT / "firmware"
GROUND_TRUTH_ROOT = FIRMWARE_ROOT / "ground_truth_bundle"
EVAL_SUITE_ROOT = FIRMWARE_ROOT / "eval_suite"
GT_BACKED_SAMPLES_ROOT = GROUND_TRUTH_ROOT / "gt_backed_suite" / "samples"
MICROBENCH_ROOT = GROUND_TRUTH_ROOT / "microbench"

ARM_ELF_MACHINE = 40


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _csv_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple, set)):
        return ";".join(_csv_value(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str] | None = None) -> None:
    if fieldnames is None:
        keys = {key for row in rows for key in row.keys()}
        fieldnames = sorted(keys)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: _csv_value(row.get(field)) for field in fieldnames})


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _as_repo_path(path_str: str) -> Path:
    path = Path(path_str)
    if path.is_absolute():
        return path
    return REPO_ROOT / path


def _as_firmware_relative(path_str: str) -> str:
    path = Path(path_str)
    if path.is_absolute():
        path = path.relative_to(FIRMWARE_ROOT)
    elif path.parts and path.parts[0] == "firmware":
        path = Path(*path.parts[1:])
    return path.as_posix()


def _make_stripped_path(unstripped_path: Path) -> Path:
    return unstripped_path.with_name(f"{unstripped_path.stem}_stripped{unstripped_path.suffix}")


def _elf_machine_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) < 20 or data[:4] != b"\x7fELF":
        raise ValueError(f"{path} is not a valid ELF file")
    return data[18:20]


def _elf_machine_value(path: Path) -> int:
    return int.from_bytes(_elf_machine_bytes(path), "little")


def _generate_arm_stripped_peer(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = dst.with_name(f"{dst.name}.tmp")
    if tmp_path.exists():
        tmp_path.unlink()
    cmd = [
        "objcopy",
        "-F",
        "elf32-little",
        "--strip-all",
        str(src),
        str(tmp_path),
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    stripped = bytearray(tmp_path.read_bytes())
    stripped[18:20] = _elf_machine_bytes(src)
    tmp_path.write_bytes(stripped)
    os.chmod(tmp_path, src.stat().st_mode)
    tmp_path.replace(dst)


def ensure_arm_stripped_peer(src: Path, dst: Path) -> Dict[str, Any]:
    src_machine = _elf_machine_value(src)
    src_size = src.stat().st_size
    had_existing = dst.exists()
    valid_existing = False
    if had_existing:
        try:
            valid_existing = _elf_machine_value(dst) == src_machine and dst.stat().st_size < src_size
        except ValueError:
            valid_existing = False
    if valid_existing:
        status = "existing"
    else:
        _generate_arm_stripped_peer(src, dst)
        status = "repaired" if had_existing else "generated"
    dst_size = dst.stat().st_size
    if _elf_machine_value(dst) != src_machine:
        raise RuntimeError(f"stripped peer lost ELF machine header: {dst}")
    if dst_size >= src_size:
        raise RuntimeError(f"stripped peer is not smaller than source: {dst}")
    return {
        "unstripped_path": str(src),
        "stripped_path": str(dst),
        "status": status,
        "source_size": src_size,
        "stripped_size": dst_size,
    }


def _load_gt_backed_sample_docs() -> Dict[str, Dict[str, Any]]:
    docs: Dict[str, Dict[str, Any]] = {}
    for sample_path in sorted(GT_BACKED_SAMPLES_ROOT.glob("*.json")):
        docs[sample_path.stem] = _load_json(sample_path)
    return docs


def _load_microbench_inventory_entries() -> List[Dict[str, Any]]:
    manifest = _load_json(MICROBENCH_ROOT / "index.json")
    entries: List[Dict[str, Any]] = []
    for item in manifest["samples"]:
        sample = _load_json(REPO_ROOT / item["sample_path"])
        stem = item["binary_stem"]
        title = sample["sample_meta"]["title"]
        stripped_name = f"{stem}_stripped.elf"
        gt_type = "in-source_reproduction" if stem.startswith("cve_") else "artifact_complete_microbench"
        gt_ref_files = [
            _as_firmware_relative(sample["binary_paths"]["source_file"]),
            _as_firmware_relative(item["sample_path"]),
        ]
        if sample["binary_paths"].get("map_file"):
            gt_ref_files.append(_as_firmware_relative(sample["binary_paths"]["map_file"]))
        entries.append(
            {
                "dataset": "sourceagent-microbench",
                "subset": "microbench",
                "sample_id": stem,
                "elf_path": _as_firmware_relative(sample["binary_paths"]["elf_file"]),
                "bin_path": _as_firmware_relative(sample["binary_paths"]["bin_file"]),
                "gt_type": gt_type,
                "gt_ref_files": gt_ref_files,
                "trigger_inputs_count": 0,
                "trigger_inputs": [],
                "notes": f"{title}; stripped ELF: {stripped_name}",
            }
        )
    return entries


def _sink_rows_from_gt_backed(
    gt_backed_manifest: Dict[str, Any],
    gt_backed_docs: Dict[str, Dict[str, Any]],
    stripped_info_by_src: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for sample in gt_backed_manifest["samples"]:
        sample_id = sample["sample_id"]
        doc = gt_backed_docs[sample_id]
        src = Path(sample["binary_path"])
        strip_info = stripped_info_by_src[str(src)]
        binary_stem = doc.get("binary_stem") or src.stem
        for sink in doc.get("sinks", []):
            address = sink.get("address")
            rows.append(
                {
                    "sample_id": sample_id,
                    "dataset": sample["dataset"],
                    "binary_stem": binary_stem,
                    "binary_path": str(src),
                    "stripped_binary_path": strip_info["stripped_path"],
                    "gt_sink_id": sink.get("sink_id") or sink.get("gt_sink_id"),
                    "label": sink.get("label"),
                    "pipeline_label_hint": sink.get("pipeline_label_hint"),
                    "function_name": sink.get("function_name"),
                    "site_kind": sink.get("site_kind"),
                    "address": address,
                    "address_hex": sink.get("address_hex")
                    or (f"0x{address:08x}" if isinstance(address, int) else None),
                    "address_status": "resolved" if isinstance(address, int) else "unresolved",
                    "status": sink.get("status"),
                    "notes": sink.get("notes"),
                    "gt_level": "L1",
                }
            )
    rows.sort(key=lambda row: (row["sample_id"], row["gt_sink_id"] or "", row["function_name"] or ""))
    return rows


def _collect_phase4_candidates(
    base_inventory: List[Dict[str, Any]],
    gt_backed_manifest: Dict[str, Any],
    gt_backed_docs: Dict[str, Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    gt_backed_by_path = {sample["binary_path"]: sample for sample in gt_backed_manifest["samples"]}
    candidates: Dict[str, Dict[str, Any]] = {}

    def add_candidate(
        *,
        unstripped_path: Path,
        sample_id: str,
        dataset: str,
        tags: Iterable[str],
        source_kind: str,
        notes: Iterable[str] = (),
    ) -> None:
        key = str(unstripped_path)
        record = candidates.setdefault(
            key,
            {
                "aliases": set(),
                "datasets": set(),
                "tags": set(),
                "source_kinds": set(),
                "notes": set(),
                "unstripped_path": key,
                "preferred_id": sample_id,
            },
        )
        record["aliases"].add(sample_id)
        record["datasets"].add(dataset)
        record["tags"].update(tag for tag in tags if tag)
        record["source_kinds"].add(source_kind)
        record["notes"].update(note for note in notes if note)
        if key in gt_backed_by_path:
            record["preferred_id"] = gt_backed_by_path[key]["sample_id"]

    for entry in base_inventory:
        if entry.get("dataset") != "uSBS":
            continue
        sample_id = entry["sample_id"]
        lower = sample_id.lower()
        tags: List[str] = []
        if "patched" in lower:
            tags.append("patched")
        if "instrumented" in lower:
            tags.append("instrumented")
        if sample_id == "test_printf_fw":
            tags.append("negative_only")
        if not tags:
            continue
        add_candidate(
            unstripped_path=FIRMWARE_ROOT / entry["elf_path"],
            sample_id=sample_id,
            dataset=entry["dataset"],
            tags=tags,
            source_kind="inventory",
            notes=[entry.get("notes", "")],
        )

    for sample in gt_backed_manifest["samples"]:
        sample_id = sample["sample_id"]
        doc = gt_backed_docs[sample_id]
        title = doc.get("title") or doc.get("sample_meta", {}).get("title", "")
        lower = f"{sample_id} {title}".lower()
        tags: List[str] = []
        if "patched" in lower:
            tags.append("patched")
        if doc.get("role") == "negative_control":
            tags.append("negative_control")
        if doc.get("chain_gt_scope") == "negative_only":
            tags.append("negative_only")
        if not tags:
            continue
        add_candidate(
            unstripped_path=Path(sample["binary_path"]),
            sample_id=sample_id,
            dataset=sample["dataset"],
            tags=tags,
            source_kind="gt_backed_suite",
            notes=doc.get("notes", []),
        )

    return candidates


def _candidate_category(tags: Iterable[str]) -> str:
    tag_set = set(tags)
    if "negative_control" in tag_set:
        return "negative_control"
    if "negative_only" in tag_set:
        return "negative_only"
    if "patched" in tag_set and "instrumented" in tag_set:
        return "patched_instrumented_variant"
    if "patched" in tag_set:
        return "patched_variant"
    if "instrumented" in tag_set:
        return "instrumented_variant"
    return "calibration_candidate"


def _build_phase4_manifest(
    candidates: Dict[str, Dict[str, Any]],
    stripped_info_by_src: Dict[str, Dict[str, Any]],
    gt_backed_manifest: Dict[str, Any],
) -> Dict[str, Any]:
    gt_backed_paths = {sample["binary_path"] for sample in gt_backed_manifest["samples"]}
    rows: List[Dict[str, Any]] = []
    for unstripped_path, record in sorted(candidates.items(), key=lambda item: item[1]["preferred_id"]):
        strip_info = stripped_info_by_src[unstripped_path]
        tags = sorted(record["tags"])
        rows.append(
            {
                "dataset": "mixed" if len(record["datasets"]) > 1 else sorted(record["datasets"])[0],
                "sample_id": record["preferred_id"],
                "aliases": sorted(record["aliases"]),
                "binary_path": strip_info["stripped_path"],
                "unstripped_binary_path": unstripped_path,
                "stripped_binary_path": strip_info["stripped_path"],
                "stripped_status": "ready",
                "stripped_origin": strip_info["status"],
                "category": _candidate_category(tags),
                "tags": tags,
                "in_gt_backed_suite": unstripped_path in gt_backed_paths,
                "notes": sorted(record["notes"]),
                "source_kinds": sorted(record["source_kinds"]),
            }
        )
    return {
        "name": "negative_patched_candidates",
        "created_at": _now_utc(),
        "description": (
            "Phase 4 verdict-calibration set built from patched/instrumented uSBS variants "
            "plus negative-control GT-backed samples."
        ),
        "count": len(rows),
        "samples": rows,
    }


def _gt_level_for_entry(entry: Dict[str, Any]) -> str:
    dataset = entry.get("dataset")
    if dataset == "mesobench":
        return "L3"
    if dataset == "sourceagent-microbench":
        return "L2"
    return "REFERENCE"


def _build_aligned_inventory(
    base_inventory: List[Dict[str, Any]],
    stripped_info_by_src: Dict[str, Dict[str, Any]],
    sink_rows: List[Dict[str, Any]],
    gt_backed_manifest: Dict[str, Any],
    phase4_manifest: Dict[str, Any],
) -> List[Dict[str, Any]]:
    gt_backed_paths = {sample["binary_path"] for sample in gt_backed_manifest["samples"]}
    sink_paths = {row["binary_path"] for row in sink_rows}
    phase4_paths = {sample["unstripped_binary_path"] for sample in phase4_manifest["samples"]}

    rows: List[Dict[str, Any]] = []
    for entry in sorted(base_inventory, key=lambda row: (row["dataset"], row["sample_id"])):
        abs_elf_path = str(FIRMWARE_ROOT / entry["elf_path"])
        strip_info = stripped_info_by_src.get(abs_elf_path)
        row = dict(entry)
        row["gt_level"] = _gt_level_for_entry(entry)
        row["in_gt_backed_suite"] = abs_elf_path in gt_backed_paths
        row["has_sink_only_gt"] = abs_elf_path in sink_paths
        row["negative_or_patched"] = abs_elf_path in phase4_paths
        row["has_stripped_peer"] = strip_info is not None
        row["stripped_elf_path"] = _as_firmware_relative(strip_info["stripped_path"]) if strip_info else None
        row["stripped_origin"] = strip_info["status"] if strip_info else "missing"
        rows.append(row)
    return rows


def _build_gt_backed_stripped_manifest(
    gt_backed_manifest: Dict[str, Any], stripped_info_by_src: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    samples: List[Dict[str, Any]] = []
    for sample in gt_backed_manifest["samples"]:
        src = Path(sample["binary_path"])
        strip_info = stripped_info_by_src[str(src)]
        samples.append(
            {
                "dataset": sample["dataset"],
                "sample_id": sample["sample_id"],
                "gt_stem": sample["gt_stem"],
                "output_stem": f"{sample['output_stem']}_stripped",
                "binary_variant": "stripped",
                "binary_path": strip_info["stripped_path"],
                "unstripped_binary_path": str(src),
                "stripped_binary_path": strip_info["stripped_path"],
                "stripped_status": "ready",
                "stripped_origin": strip_info["status"],
                "eval_scope": sample.get("eval_scope", "auto"),
                "notes": "gt_backed_suite stripped peer",
            }
        )
    return {
        "name": "gt_backed_suite_stripped",
        "created_at": _now_utc(),
        "created_from_gt": True,
        "count": len(samples),
        "description": "Stripped-first variant of the 44-sample GT-backed suite.",
        "samples": samples,
    }


def _build_mesobench_stripped_manifest(
    mesobench_manifest: Dict[str, Any], stripped_info_by_src: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    samples: List[Dict[str, Any]] = []
    for sample in mesobench_manifest["samples"]:
        src = Path(sample["binary_path"])
        strip_info = stripped_info_by_src[str(src)]
        samples.append(
            {
                "dataset": sample["dataset"],
                "sample_id": sample["sample_id"],
                "output_stem": f"{sample['output_stem']}_stripped",
                "binary_variant": "stripped",
                "binary_path": strip_info["stripped_path"],
                "unstripped_binary_path": str(src),
                "stripped_binary_path": strip_info["stripped_path"],
                "has_gt": sample.get("has_gt", False),
                "artifact_gt_seed": sample.get("artifact_gt_seed", False),
                "artifact_gt_path": sample.get("artifact_gt_path"),
                "stripped_status": "ready",
                "stripped_origin": strip_info["status"],
                "notes": sample.get("notes"),
            }
        )
    return {
        "name": "mesobench_stripped_elf",
        "created_at": _now_utc(),
        "description": "Stripped-first mesobench manifest derived from the current 30-sample unstripped suite.",
        "samples": samples,
    }


def sync_gt_asset_alignment(repo_root: Path | None = None) -> Dict[str, Any]:
    if repo_root is not None and repo_root != REPO_ROOT:
        raise ValueError("Only the checked-out repository root is supported in this sync helper")

    gt_backed_manifest = _load_json(EVAL_SUITE_ROOT / "gt_backed_suite_manifest.json")
    mesobench_manifest = _load_json(EVAL_SUITE_ROOT / "mesobench_unstripped_elf_manifest.json")
    gt_backed_docs = _load_gt_backed_sample_docs()

    stripped_info_by_src: Dict[str, Dict[str, Any]] = {}

    for sample in gt_backed_manifest["samples"]:
        src = Path(sample["binary_path"])
        dst = _make_stripped_path(src)
        stripped_info_by_src[str(src)] = ensure_arm_stripped_peer(src, dst)

    base_inventory = _load_json(GROUND_TRUTH_ROOT / "ground_truth_inventory.json")
    base_inventory = [entry for entry in base_inventory if entry["dataset"] != "sourceagent-microbench"]
    base_inventory.extend(_load_microbench_inventory_entries())

    phase4_candidates = _collect_phase4_candidates(base_inventory, gt_backed_manifest, gt_backed_docs)
    for unstripped_path in sorted(phase4_candidates):
        src = Path(unstripped_path)
        dst = _make_stripped_path(src)
        stripped_info_by_src[unstripped_path] = ensure_arm_stripped_peer(src, dst)

    gt_backed_stripped_manifest = _build_gt_backed_stripped_manifest(gt_backed_manifest, stripped_info_by_src)
    mesobench_stripped_manifest = _build_mesobench_stripped_manifest(mesobench_manifest, stripped_info_by_src)
    sink_rows = _sink_rows_from_gt_backed(gt_backed_manifest, gt_backed_docs, stripped_info_by_src)
    phase4_manifest = _build_phase4_manifest(phase4_candidates, stripped_info_by_src, gt_backed_manifest)
    aligned_inventory = _build_aligned_inventory(
        base_inventory=base_inventory,
        stripped_info_by_src=stripped_info_by_src,
        sink_rows=sink_rows,
        gt_backed_manifest=gt_backed_manifest,
        phase4_manifest=phase4_manifest,
    )

    _write_json(EVAL_SUITE_ROOT / "gt_backed_suite_stripped_manifest.json", gt_backed_stripped_manifest)
    _write_json(EVAL_SUITE_ROOT / "mesobench_stripped_elf_manifest.json", mesobench_stripped_manifest)
    _write_json(GROUND_TRUTH_ROOT / "normalized_gt_sinks_gt_backed.json", sink_rows)
    _write_csv(
        GROUND_TRUTH_ROOT / "normalized_gt_sinks_gt_backed.csv",
        sink_rows,
        fieldnames=[
            "sample_id",
            "dataset",
            "binary_stem",
            "binary_path",
            "stripped_binary_path",
            "gt_sink_id",
            "label",
            "pipeline_label_hint",
            "function_name",
            "site_kind",
            "address",
            "address_hex",
            "address_status",
            "status",
            "notes",
            "gt_level",
        ],
    )
    _write_json(GROUND_TRUTH_ROOT / "ground_truth_inventory.json", aligned_inventory)
    _write_csv(
        GROUND_TRUTH_ROOT / "ground_truth_inventory.csv",
        aligned_inventory,
        fieldnames=[
            "dataset",
            "subset",
            "sample_id",
            "elf_path",
            "bin_path",
            "gt_type",
            "gt_level",
            "gt_ref_files",
            "trigger_inputs_count",
            "trigger_inputs",
            "notes",
            "in_gt_backed_suite",
            "has_sink_only_gt",
            "negative_or_patched",
            "has_stripped_peer",
            "stripped_elf_path",
            "stripped_origin",
        ],
    )
    _write_json(EVAL_SUITE_ROOT / "negative_patched_candidates_manifest.json", phase4_manifest)

    return {
        "gt_backed_stripped_count": gt_backed_stripped_manifest["count"],
        "mesobench_stripped_count": len(mesobench_stripped_manifest["samples"]),
        "sink_only_samples": len({row["sample_id"] for row in sink_rows}),
        "sink_only_entries": len(sink_rows),
        "aligned_inventory_count": len(aligned_inventory),
        "phase4_candidate_count": phase4_manifest["count"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync stripped manifests and GT asset alignment files.")
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    args = parser.parse_args()
    summary = sync_gt_asset_alignment(Path(args.repo_root).resolve())
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
