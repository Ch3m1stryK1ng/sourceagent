"""Build a unified per-binary sample catalog for SourceAgent assets.

The catalog normalizes the binaries referenced by:

- checked-in benchmark manifests in ``firmware/eval_suite/``
- curated GT inventory entries in ``firmware/ground_truth_bundle/``
- demo smoke-test binaries in ``firmware/demo/``

Each row is keyed by the binary path rather than sample ID so stripped and
unstripped peers can be tracked independently while still recording suite
membership, GT coverage, size, and coarse platform classification.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from sourceagent.pipeline.loader import load_binary


REPO_ROOT = Path(__file__).resolve().parents[2]
FIRMWARE_ROOT = REPO_ROOT / "firmware"
EVAL_SUITE_ROOT = FIRMWARE_ROOT / "eval_suite"
GROUND_TRUTH_ROOT = FIRMWARE_ROOT / "ground_truth_bundle"
DEMO_ROOT = FIRMWARE_ROOT / "demo"


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


def _repo_relative(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _to_abs_path(path_str: str) -> Path:
    path = Path(path_str)
    if path.is_absolute():
        return path.resolve()
    if path.parts and path.parts[0] == "firmware":
        return (REPO_ROOT / path).resolve()
    if path.parts and path.parts[0] in {
        "demo",
        "microbench",
        "microbench_autogen",
        "monolithic-firmware-collection",
        "p2im-unit_tests",
        "uSBS",
    }:
        return (FIRMWARE_ROOT / path).resolve()
    return (REPO_ROOT / path).resolve()


def _infer_dataset_from_path(path: Path) -> str:
    rel = _repo_relative(path)
    if rel.startswith("firmware/demo/"):
        return "demo"
    if rel.startswith("firmware/microbench_autogen/"):
        return "microbench-autogen"
    if rel.startswith("firmware/microbench/"):
        return "microbench"
    if rel.startswith("firmware/p2im-unit_tests/"):
        return "p2im-unit_tests"
    if rel.startswith("firmware/monolithic-firmware-collection/"):
        return "monolithic-firmware-collection"
    if rel.startswith("firmware/uSBS/"):
        return "uSBS"
    return "unknown"


def _binary_format(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".elf":
        return "elf"
    if suffix == ".bin":
        return "bin"
    return suffix.lstrip(".") or "unknown"


def _symbol_state(path: Path, row: Dict[str, Any] | None = None) -> str:
    if path.suffix.lower() == ".bin":
        return "raw_bin"
    if path.name.endswith("_stripped.elf"):
        return "stripped"
    if row and str(row.get("binary_variant", "")).lower() == "stripped":
        return "stripped"
    return "unstripped"


def _size_bucket(size_mib: float | None) -> str:
    if size_mib is None:
        return "unknown"
    if size_mib < 0.1:
        return "<0.1 MiB"
    if size_mib < 0.5:
        return "0.1-0.5 MiB"
    if size_mib < 1.0:
        return "0.5-1 MiB"
    if size_mib < 2.0:
        return "1-2 MiB"
    return ">=2 MiB"


def _has_cve_marker(value: str) -> bool:
    lowered = value.lower()
    return "cve" in lowered


def _new_record(path: Path) -> Dict[str, Any]:
    return {
        "_path": path,
        "_sample_ids": set(),
        "_manifest_datasets": set(),
        "_curation_sets": set(),
        "_suite_memberships": set(),
        "_notes": set(),
        "_tags": set(),
        "_aliases": set(),
        "_source_repo_ids": set(),
        "_source_code_levels": set(),
        "_peer_paths": set(),
        "_manifest_refs": set(),
        "_gt_ref_files": set(),
        "_gt_levels": set(),
        "_gt_types": set(),
        "_trigger_inputs_count": 0,
        "_sample_kinds": set(),
        "has_gt": False,
        "has_sink_only_gt": False,
        "negative_or_patched": False,
        "in_demo_set": False,
        "in_gt_backed_suite": False,
        "in_gt_backed_stripped_suite": False,
        "in_unstripped_elf_suite": False,
        "in_mesobench_unstripped_suite": False,
        "in_mesobench_stripped_suite": False,
        "in_no_gt_suite": False,
        "in_no_gt_shard1": False,
        "in_no_gt_shard2": False,
        "in_microbench_autogen_unstripped_suite": False,
        "in_microbench_autogen_stripped_suite": False,
        "in_l1_sink_only_suite": False,
        "in_negative_patched_candidates": False,
        "in_gt_inventory": False,
        "has_stripped_peer": False,
        "stripped_peer_path": None,
        "unstripped_peer_path": None,
    }


def _record_for(records: Dict[str, Dict[str, Any]], path: Path) -> Dict[str, Any]:
    key = str(path.resolve())
    record = records.get(key)
    if record is None:
        record = _new_record(path.resolve())
        records[key] = record
    return record


def _add_peer_link(
    records: Dict[str, Dict[str, Any]],
    left_path: Path | None,
    right_path: Path | None,
) -> None:
    if left_path is None or right_path is None:
        return
    if left_path.resolve() == right_path.resolve():
        return
    left = _record_for(records, left_path)
    right = _record_for(records, right_path)
    left["_peer_paths"].add(str(right_path.resolve()))
    right["_peer_paths"].add(str(left_path.resolve()))
    if _symbol_state(left_path) == "stripped":
        left["unstripped_peer_path"] = str(right_path.resolve())
        right["stripped_peer_path"] = str(left_path.resolve())
        left["has_stripped_peer"] = True
        right["has_stripped_peer"] = True
    elif _symbol_state(right_path) == "stripped":
        left["stripped_peer_path"] = str(right_path.resolve())
        right["unstripped_peer_path"] = str(left_path.resolve())
        left["has_stripped_peer"] = True
        right["has_stripped_peer"] = True


def _register_manifest_samples(
    records: Dict[str, Dict[str, Any]],
    manifest_path: Path,
    suite_flag: str,
) -> None:
    payload = _load_json(manifest_path)
    samples = payload["samples"] if isinstance(payload, dict) else payload
    suite_name = manifest_path.name
    for sample in samples:
        binary_path = _to_abs_path(sample["binary_path"])
        record = _record_for(records, binary_path)
        record["_sample_ids"].add(sample.get("sample_id") or binary_path.stem)
        if sample.get("dataset"):
            record["_manifest_datasets"].add(sample["dataset"])
        record["_suite_memberships"].add(suite_flag)
        record["_manifest_refs"].add(f"firmware/eval_suite/{suite_name}")
        if sample.get("notes"):
            record["_notes"].add(str(sample["notes"]))
        if sample.get("binary_variant"):
            record["_notes"].add(f"binary_variant={sample['binary_variant']}")
        record[suite_flag] = True
        if sample.get("has_gt") is True:
            record["has_gt"] = True

        unstripped_path = sample.get("unstripped_binary_path")
        stripped_path = sample.get("stripped_binary_path")
        if unstripped_path:
            _add_peer_link(records, binary_path, _to_abs_path(unstripped_path))
        if stripped_path:
            _add_peer_link(records, binary_path, _to_abs_path(stripped_path))


def _register_demo_binaries(records: Dict[str, Dict[str, Any]]) -> None:
    for path in sorted(DEMO_ROOT.glob("*")):
        if path.suffix.lower() not in {".elf", ".bin"} or not path.is_file():
            continue
        record = _record_for(records, path.resolve())
        record["_sample_ids"].add(path.stem)
        record["_suite_memberships"].add("in_demo_set")
        record["_manifest_refs"].add("firmware/demo")
        record["in_demo_set"] = True


def _load_mesobench_meta() -> Dict[str, Dict[str, Any]]:
    meta: Dict[str, Dict[str, Any]] = {}
    payload = _load_json(GROUND_TRUTH_ROOT / "mesobench" / "index.json")
    for sample in payload["samples"]:
        meta[sample["sample_id"]] = sample
    return meta


def _load_microbench_meta() -> Dict[str, Dict[str, Any]]:
    meta: Dict[str, Dict[str, Any]] = {}
    payload = _load_json(GROUND_TRUTH_ROOT / "microbench" / "index.json")
    for sample in payload["samples"]:
        meta[sample["binary_stem"]] = sample
    return meta


def _load_microbench_autogen_meta() -> Dict[str, Dict[str, Any]]:
    meta: Dict[str, Dict[str, Any]] = {}
    payload = _load_json(GROUND_TRUTH_ROOT / "microbench_autogen" / "index.json")
    for sample in payload["samples"]:
        meta[sample["binary_stem"]] = sample
    return meta


def _register_microbench_autogen_index(records: Dict[str, Dict[str, Any]]) -> None:
    payload = _load_json(GROUND_TRUTH_ROOT / "microbench_autogen" / "index.json")
    for sample in payload["samples"]:
        sample_id = sample["binary_stem"]
        for key in ("elf_path", "stripped_elf_path", "bin_path"):
            rel_path = sample.get(key)
            if not rel_path:
                continue
            path = _to_abs_path(rel_path)
            record = _record_for(records, path)
            record["_sample_ids"].add(sample_id)
            record["_manifest_datasets"].add("microbench-autogen")
            record["_suite_memberships"].add("microbench_autogen_index")
            record["_manifest_refs"].add("firmware/ground_truth_bundle/microbench_autogen/index.json")
            record["has_gt"] = True
            record["has_sink_only_gt"] = True
            record["_gt_levels"].add("L1")
            record["_sample_kinds"].add("synthetic")
            if sample.get("description"):
                record["_notes"].add(str(sample["description"]))


def _register_inventory(records: Dict[str, Dict[str, Any]]) -> None:
    inventory = _load_json(GROUND_TRUTH_ROOT / "ground_truth_inventory.json")
    for entry in inventory:
        sample_id = entry["sample_id"]
        curation_set = entry.get("dataset") or ""
        rel_elf = entry.get("elf_path")
        rel_bin = entry.get("bin_path")

        def _apply_common(record: Dict[str, Any]) -> None:
            record["_sample_ids"].add(sample_id)
            if curation_set:
                record["_curation_sets"].add(curation_set)
            record["_suite_memberships"].add("in_gt_inventory")
            record["_manifest_refs"].add("firmware/ground_truth_bundle/ground_truth_inventory.json")
            record["in_gt_inventory"] = True
            record["has_gt"] = True
            record["has_sink_only_gt"] = bool(record["has_sink_only_gt"] or entry.get("has_sink_only_gt"))
            record["negative_or_patched"] = bool(record["negative_or_patched"] or entry.get("negative_or_patched"))
            if entry.get("gt_level"):
                record["_gt_levels"].add(entry["gt_level"])
            if entry.get("gt_type"):
                record["_gt_types"].add(entry["gt_type"])
            record["_trigger_inputs_count"] = max(
                int(record["_trigger_inputs_count"] or 0),
                int(entry.get("trigger_inputs_count") or 0),
            )
            if entry.get("notes"):
                record["_notes"].add(str(entry["notes"]))
            for ref in entry.get("gt_ref_files", []):
                record["_gt_ref_files"].add(str(ref))

        if rel_elf:
            elf_path = _to_abs_path(rel_elf)
            elf_record = _record_for(records, elf_path)
            _apply_common(elf_record)
        if rel_bin:
            bin_path = _to_abs_path(rel_bin)
            bin_record = _record_for(records, bin_path)
            _apply_common(bin_record)

        stripped_rel = entry.get("stripped_elf_path")
        if rel_elf and stripped_rel:
            _add_peer_link(records, _to_abs_path(rel_elf), _to_abs_path(stripped_rel))

        kind = ""
        if entry.get("negative_or_patched"):
            kind = "negative_or_patched"
        elif _has_cve_marker(sample_id):
            kind = "cve"
        elif str(curation_set).lower() == "sourceagent-microbench":
            kind = "synthetic"
        elif str(curation_set).lower() == "mesobench":
            kind = "real_world_benchmark"
        if kind:
            if rel_elf:
                _record_for(records, _to_abs_path(rel_elf))["_sample_kinds"].add(kind)
            if rel_bin:
                _record_for(records, _to_abs_path(rel_bin))["_sample_kinds"].add(kind)


def _register_negative_candidate_metadata(records: Dict[str, Dict[str, Any]]) -> None:
    payload = _load_json(EVAL_SUITE_ROOT / "negative_patched_candidates_manifest.json")
    for sample in payload["samples"]:
        binary_path = _to_abs_path(sample["binary_path"])
        record = _record_for(records, binary_path)
        record["negative_or_patched"] = True
        record["_sample_kinds"].add("negative_or_patched")
        if sample.get("category"):
            record["_tags"].add(str(sample["category"]))
        for tag in sample.get("tags", []):
            record["_tags"].add(str(tag))
        for alias in sample.get("aliases", []):
            record["_aliases"].add(str(alias))


def _register_sink_only_gt(records: Dict[str, Dict[str, Any]]) -> None:
    for rel in (
        "normalized_gt_sinks_gt_backed.json",
        "normalized_gt_sinks_microbench_autogen.json",
    ):
        rows = _load_json(GROUND_TRUTH_ROOT / rel)
        for row in rows:
            sample_id = row.get("sample_id") or row.get("binary_stem") or ""
            binary_path = row.get("binary_path")
            if binary_path:
                record = _record_for(records, _to_abs_path(binary_path))
                if sample_id:
                    record["_sample_ids"].add(sample_id)
                record["has_gt"] = True
                record["has_sink_only_gt"] = True
                if row.get("gt_level"):
                    record["_gt_levels"].add(str(row["gt_level"]))
                record["_manifest_refs"].add(f"firmware/ground_truth_bundle/{rel}")
            stripped_path = row.get("stripped_binary_path")
            if stripped_path:
                record = _record_for(records, _to_abs_path(stripped_path))
                if sample_id:
                    record["_sample_ids"].add(sample_id)
                record["has_gt"] = True
                record["has_sink_only_gt"] = True
                if row.get("gt_level"):
                    record["_gt_levels"].add(str(row["gt_level"]))
                record["_manifest_refs"].add(f"firmware/ground_truth_bundle/{rel}")
                if binary_path:
                    _add_peer_link(records, _to_abs_path(binary_path), _to_abs_path(stripped_path))


def _arch_info(path: Path, cache: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    key = str(path)
    cached = cache.get(key)
    if cached is not None:
        return cached

    info = {
        "arch": "",
        "arch_family": "unknown",
        "arch_source": "none",
        "base_address_hex": "",
    }
    if path.exists():
        mm = load_binary(path)
        if mm is not None:
            info["arch"] = mm.arch
            info["base_address_hex"] = f"0x{mm.base_address:08x}"
            if "Cortex" in mm.arch:
                info["arch_family"] = "arm-cortex-m"
            elif "ARM" in mm.arch:
                info["arch_family"] = "arm"
            info["arch_source"] = "loader"
    cache[key] = info
    return info


def _framework_and_execution_model(
    sample_ids: Iterable[str],
    path: Path,
    curation_sets: Iterable[str],
    manifest_datasets: Iterable[str],
    mesobench_meta: Dict[str, Dict[str, Any]],
    microbench_meta: Dict[str, Dict[str, Any]],
    microbench_autogen_meta: Dict[str, Dict[str, Any]],
) -> Tuple[str, str, str, str]:
    sample_ids = list(sample_ids)
    sample_text = " ".join(sample_ids).lower()
    rel = _repo_relative(path).lower()
    curation_sets = {value.lower() for value in curation_sets if value}
    manifest_datasets = {value.lower() for value in manifest_datasets if value}

    for sample_id in sample_ids:
        meta = mesobench_meta.get(sample_id)
        if meta:
            repo_id = str(meta.get("source_repo_id") or "unknown")
            if repo_id == "zephyr":
                return "zephyr", "rtos", "high", "mesobench.source_repo_id=zephyr"
            if repo_id == "contiki-ng":
                return "contiki-ng", "rtos", "high", "mesobench.source_repo_id=contiki-ng"
            if repo_id == "stm32cubef4":
                return "stm32cubef4", "bare_metal", "high", "mesobench.source_repo_id=stm32cubef4"

    if path.parent == DEMO_ROOT or rel.startswith("firmware/demo/"):
        if "controllino" in rel or "arduino" in rel or ".ino" in rel:
            return "arduino", "bare_metal", "medium", "demo path/name matches Arduino-style sample"
        return "demo-cortexm", "bare_metal", "medium", "demo binaries are local Cortex-M smoke samples"

    for sample_id in sample_ids:
        if sample_id in microbench_autogen_meta or rel.startswith("firmware/microbench_autogen/"):
            return "sourceagent-microbench-autogen", "bare_metal", "high", "microbench_autogen index/path"
        if sample_id in microbench_meta or rel.startswith("firmware/microbench/") or "sourceagent-microbench" in curation_sets:
            return "sourceagent-microbench", "bare_metal", "high", "microbench index/path"

    if "p2im-unit_tests" in manifest_datasets or rel.startswith("firmware/p2im-unit_tests/"):
        return "p2im-unit_tests", "bare_metal", "high", "p2im-unit_tests dataset/path"
    if "uSBS".lower() in rel or rel.startswith("firmware/usbs/"):
        return "stm32cubef4", "bare_metal", "medium", "uSBS path; STM32Cube-style benchmark firmware"
    if "zephyr" in sample_text or "zephyr" in rel:
        return "zephyr", "rtos", "high", "sample/path contains zephyr"
    if "contiki" in sample_text or "contiki" in rel:
        return "contiki-ng", "rtos", "high", "sample/path contains contiki"
    if "freertos" in sample_text or "freertos" in rel:
        return "freertos", "rtos", "high", "sample/path contains freertos"
    if "arduino" in rel or ".ino" in rel or "controllino" in sample_text:
        return "arduino", "bare_metal", "medium", "path/name indicates Arduino build"
    if "stm32cube" in sample_text or "lwip" in sample_text or "lwip" in rel:
        return "stm32cube-lwip", "bare_metal", "medium", "sample/path indicates STM32Cube + lwIP style firmware"
    if "armcortex-m" in rel:
        return "arm-cortex-m-app", "bare_metal", "low", "corpus path is under ARMCortex-M monolithic collection"
    return "unknown", "unknown", "low", "no strong framework or execution-model signal"


def _finalize_records(records: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    mesobench_meta = _load_mesobench_meta()
    microbench_meta = _load_microbench_meta()
    microbench_autogen_meta = _load_microbench_autogen_meta()
    arch_cache: Dict[str, Dict[str, Any]] = {}

    rows: List[Dict[str, Any]] = []
    for record in records.values():
        path = record.pop("_path")
        sample_ids = sorted(record.pop("_sample_ids"))
        manifest_datasets = sorted(record.pop("_manifest_datasets"))
        curation_sets = sorted(record.pop("_curation_sets"))
        suite_memberships = sorted(record.pop("_suite_memberships"))
        notes = sorted(record.pop("_notes"))
        tags = sorted(record.pop("_tags"))
        aliases = sorted(record.pop("_aliases"))
        source_repo_ids = sorted(record.pop("_source_repo_ids"))
        source_code_levels = sorted(record.pop("_source_code_levels"))
        peer_paths = sorted(record.pop("_peer_paths"))
        manifest_refs = sorted(record.pop("_manifest_refs"))
        gt_ref_files = sorted(record.pop("_gt_ref_files"))
        gt_levels = sorted(record.pop("_gt_levels"))
        gt_types = sorted(record.pop("_gt_types"))
        trigger_inputs_count = int(record.pop("_trigger_inputs_count") or 0)
        sample_kinds = sorted(record.pop("_sample_kinds"))

        exists = path.exists()
        binary_format = _binary_format(path)
        symbol_state = _symbol_state(path)
        size_bytes = path.stat().st_size if exists else None
        size_mib = round(size_bytes / (1024 * 1024), 4) if size_bytes is not None else None
        arch_info = _arch_info(path, arch_cache)
        framework_family, execution_model, classification_confidence, classification_reason = (
            _framework_and_execution_model(
                sample_ids,
                path,
                curation_sets,
                manifest_datasets,
                mesobench_meta,
                microbench_meta,
                microbench_autogen_meta,
            )
        )

        for sample_id in sample_ids:
            meta = mesobench_meta.get(sample_id)
            if meta:
                if meta.get("source_repo_id"):
                    source_repo_ids.append(str(meta["source_repo_id"]))
                if meta.get("source_code_level"):
                    source_code_levels.append(str(meta["source_code_level"]))
        source_repo_ids = sorted(set(source_repo_ids))
        source_code_levels = sorted(set(source_code_levels))

        if not sample_kinds:
            if any("negative" in tag or "patched" in tag for tag in tags) or record["negative_or_patched"]:
                sample_kinds = ["negative_or_patched"]
            elif any(_has_cve_marker(value) for value in sample_ids):
                sample_kinds = ["cve"]
            elif framework_family.startswith("sourceagent-microbench"):
                sample_kinds = ["synthetic"]
            else:
                sample_kinds = ["functional"]

        row = {
            "sample_id": sample_ids[0] if sample_ids else path.stem,
            "sample_ids": sample_ids,
            "dataset": _infer_dataset_from_path(path),
            "manifest_datasets": manifest_datasets,
            "curation_sets": curation_sets,
            "suite_memberships": suite_memberships,
            "binary_path": str(path),
            "relative_binary_path": _repo_relative(path),
            "binary_name": path.name,
            "binary_format": binary_format,
            "symbol_state": symbol_state,
            "file_size_bytes": size_bytes,
            "file_size_mib": size_mib,
            "size_bucket": _size_bucket(size_mib),
            "exists": exists,
            "arch": arch_info["arch"],
            "arch_family": arch_info["arch_family"],
            "arch_source": arch_info["arch_source"],
            "base_address_hex": arch_info["base_address_hex"],
            "framework_family": framework_family,
            "source_repo_ids": source_repo_ids,
            "source_code_levels": source_code_levels,
            "execution_model": execution_model,
            "classification_confidence": classification_confidence,
            "classification_reason": classification_reason,
            "has_gt": bool(record["has_gt"]),
            "gt_level": gt_levels[0] if len(gt_levels) == 1 else ";".join(gt_levels),
            "gt_levels": gt_levels,
            "gt_type": gt_types[0] if len(gt_types) == 1 else ";".join(gt_types),
            "gt_types": gt_types,
            "has_sink_only_gt": bool(record["has_sink_only_gt"]),
            "negative_or_patched": bool(record["negative_or_patched"]),
            "trigger_inputs_count": trigger_inputs_count,
            "sample_kind": sample_kinds[0] if len(sample_kinds) == 1 else ";".join(sample_kinds),
            "sample_kinds": sample_kinds,
            "tags": tags,
            "aliases": aliases,
            "peer_paths": peer_paths,
            "stripped_peer_path": record["stripped_peer_path"],
            "unstripped_peer_path": record["unstripped_peer_path"],
            "has_stripped_peer": bool(record["has_stripped_peer"] or record["stripped_peer_path"] or record["unstripped_peer_path"]),
            "manifest_refs": manifest_refs,
            "gt_ref_files": gt_ref_files,
            "notes": notes,
            "in_demo_set": bool(record["in_demo_set"]),
            "in_gt_backed_suite": bool(record["in_gt_backed_suite"]),
            "in_gt_backed_stripped_suite": bool(record["in_gt_backed_stripped_suite"]),
            "in_unstripped_elf_suite": bool(record["in_unstripped_elf_suite"]),
            "in_mesobench_unstripped_suite": bool(record["in_mesobench_unstripped_suite"]),
            "in_mesobench_stripped_suite": bool(record["in_mesobench_stripped_suite"]),
            "in_no_gt_suite": bool(record["in_no_gt_suite"]),
            "in_no_gt_shard1": bool(record["in_no_gt_shard1"]),
            "in_no_gt_shard2": bool(record["in_no_gt_shard2"]),
            "in_microbench_autogen_unstripped_suite": bool(record["in_microbench_autogen_unstripped_suite"]),
            "in_microbench_autogen_stripped_suite": bool(record["in_microbench_autogen_stripped_suite"]),
            "in_l1_sink_only_suite": bool(record["in_l1_sink_only_suite"]),
            "in_negative_patched_candidates": bool(record["in_negative_patched_candidates"]),
            "in_gt_inventory": bool(record["in_gt_inventory"]),
        }
        rows.append(row)

    rows.sort(key=lambda row: (row["dataset"], row["sample_id"], row["binary_name"]))

    # Propagate Cortex-M architecture to raw/bin variants that share a sample ID
    # with a loader-confirmed peer.
    known_arch_by_sample: Dict[str, Dict[str, str]] = {}
    for row in rows:
        if row["arch_family"] == "arm-cortex-m":
            for sample_id in row["sample_ids"]:
                known_arch_by_sample[sample_id] = {
                    "arch": row["arch"],
                    "arch_family": row["arch_family"],
                    "base_address_hex": row["base_address_hex"],
                }
    for row in rows:
        if row["arch_family"] != "unknown":
            continue
        for sample_id in row["sample_ids"]:
            peer = known_arch_by_sample.get(sample_id)
            if peer is None:
                continue
            row["arch"] = peer["arch"]
            row["arch_family"] = peer["arch_family"]
            row["arch_source"] = "sample_peer"
            if not row["base_address_hex"]:
                row["base_address_hex"] = peer["base_address_hex"]
            break

    return rows


def _counter(rows: List[Dict[str, Any]], field: str) -> Dict[str, int]:
    counter = Counter(str(row.get(field) or "unknown") for row in rows)
    return dict(sorted(counter.items()))


def _bool_counter(rows: List[Dict[str, Any]], field: str) -> int:
    return sum(1 for row in rows if row.get(field))


def build_sample_catalog(repo_root: Path | None = None) -> Dict[str, Any]:
    if repo_root is not None and repo_root != REPO_ROOT:
        raise ValueError("Only the checked-out repository root is supported")

    records: Dict[str, Dict[str, Any]] = {}

    manifest_specs = [
        ("gt_backed_suite_manifest.json", "in_gt_backed_suite"),
        ("gt_backed_suite_stripped_manifest.json", "in_gt_backed_stripped_suite"),
        ("unstripped_elf_manifest.json", "in_unstripped_elf_suite"),
        ("mesobench_unstripped_elf_manifest.json", "in_mesobench_unstripped_suite"),
        ("mesobench_stripped_elf_manifest.json", "in_mesobench_stripped_suite"),
        ("no_gt_94_manifest.json", "in_no_gt_suite"),
        ("no_gt_94_shard1_manifest.json", "in_no_gt_shard1"),
        ("no_gt_94_shard2_manifest.json", "in_no_gt_shard2"),
        ("microbench_autogen_unstripped_manifest.json", "in_microbench_autogen_unstripped_suite"),
        ("microbench_autogen_stripped_manifest.json", "in_microbench_autogen_stripped_suite"),
        ("l1_sink_only_combined_manifest.json", "in_l1_sink_only_suite"),
        ("negative_patched_candidates_manifest.json", "in_negative_patched_candidates"),
    ]

    for manifest_name, suite_flag in manifest_specs:
        _register_manifest_samples(records, EVAL_SUITE_ROOT / manifest_name, suite_flag)

    _register_demo_binaries(records)
    _register_microbench_autogen_index(records)
    _register_inventory(records)
    _register_negative_candidate_metadata(records)
    _register_sink_only_gt(records)

    rows = _finalize_records(records)
    payload = {
        "name": "sourceagent_sample_catalog",
        "created_at": _now_utc(),
        "description": (
            "Unified per-binary catalog for demo binaries, eval-suite workloads, "
            "and GT-tracked artifacts. Rows are keyed by binary path so stripped "
            "and unstripped peers remain distinguishable."
        ),
        "count": len(rows),
        "existing_count": sum(1 for row in rows if row["exists"]),
        "by_dataset": _counter(rows, "dataset"),
        "by_binary_format": _counter(rows, "binary_format"),
        "by_symbol_state": _counter(rows, "symbol_state"),
        "by_execution_model": _counter(rows, "execution_model"),
        "by_framework_family": _counter(rows, "framework_family"),
        "by_size_bucket": _counter(rows, "size_bucket"),
        "has_gt_count": _bool_counter(rows, "has_gt"),
        "has_sink_only_gt_count": _bool_counter(rows, "has_sink_only_gt"),
        "negative_or_patched_count": _bool_counter(rows, "negative_or_patched"),
        "has_stripped_peer_count": _bool_counter(rows, "has_stripped_peer"),
        "samples": rows,
    }

    _write_json(EVAL_SUITE_ROOT / "sample_catalog.json", payload)
    _write_csv(EVAL_SUITE_ROOT / "sample_catalog.csv", rows)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the unified SourceAgent sample catalog.")
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    args = parser.parse_args()
    payload = build_sample_catalog(Path(args.repo_root).resolve())
    summary = {
        "count": payload["count"],
        "by_dataset": payload["by_dataset"],
        "by_symbol_state": payload["by_symbol_state"],
        "by_execution_model": payload["by_execution_model"],
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
