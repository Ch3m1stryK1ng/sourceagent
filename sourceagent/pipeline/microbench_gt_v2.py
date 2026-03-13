from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


SCHEMA_VERSION = "2.0-seed"
DEFAULT_REL_DIR = Path("firmware/ground_truth_bundle/microbench")
SAMPLE_REL_DIR = DEFAULT_REL_DIR / "samples"
_ALLOWED_CHAIN_VERDICTS = {"DROP", "SAFE_OR_LOW_RISK", "SUSPICIOUS", "CONFIRMED"}
_ALLOWED_RISK_BANDS = {"LOW", "MEDIUM", "HIGH"}
_ALLOWED_REVIEW_PRIORITIES = {"P0", "P1", "P2"}
_CHAIN_RISK_GT_FIELDS = (
    "expected_final_verdict",
    "expected_final_risk_band",
    "expected_review_priority",
)


@dataclass(frozen=True)
class SampleMeta:
    title: str
    mechanism_group: str
    runtime_style: str
    inspiration: str
    expected_channel_mode: str
    chain_shape: str
    todo_items: Tuple[str, ...]


MICROBENCH_SAMPLES: Dict[str, SampleMeta] = {
    "t0_mmio_read": SampleMeta(
        title="Direct MMIO polling with copy sink",
        mechanism_group="same_context_direct",
        runtime_style="baremetal_polling",
        inspiration="toy_direct_mmio",
        expected_channel_mode="none",
        chain_shape="same_context_direct_call",
        todo_items=(
            "Annotate rx_buf as payload object.",
            "Mark uart_status as control-only source if chaining should exclude it.",
            "Bind COPY_SINK root to n and same-context source proof.",
        ),
    ),
    "t0_isr_mmio_read": SampleMeta(
        title="ISR MMIO read without downstream sink",
        mechanism_group="isr_source_only",
        runtime_style="baremetal_interrupt",
        inspiration="toy_isr_mmio",
        expected_channel_mode="optional",
        chain_shape="source_only",
        todo_items=(
            "Annotate ISR data source sites and any shared flag/object if present.",
            "Record that no vulnerability sink is expected.",
        ),
    ),
    "t0_isr_filled_buffer": SampleMeta(
        title="ISR-filled ring buffer copied in main loop",
        mechanism_group="isr_cross_context",
        runtime_style="baremetal_interrupt",
        inspiration="toy_ring_buffer",
        expected_channel_mode="required",
        chain_shape="source_object_channel_copy",
        todo_items=(
            "Split payload object g_rx_buf from control objects g_rx_head/g_rx_tail.",
            "Annotate ISR->MAIN channel with guard next!=g_rx_tail and g_rx_tail!=g_rx_head.",
            "Bind COPY_SINK root to count and note count<max_len check strength.",
        ),
    ),
    "t0_dma_backed_buffer": SampleMeta(
        title="DMA-backed buffer consumed in main loop",
        mechanism_group="dma_cross_context",
        runtime_style="baremetal_dma",
        inspiration="toy_dma_consumer",
        expected_channel_mode="required",
        chain_shape="source_object_channel_consume",
        todo_items=(
            "Bind DMA CMAR/CNDTR configuration to g_dma_rx_buf.",
            "Annotate DMA->MAIN channel and buf[0]!=0 gate.",
            "Record that this sample has source/object/channel but no vulnerability sink.",
        ),
    ),
    "t0_copy_sink": SampleMeta(
        title="Same-context memcpy/strcpy sink",
        mechanism_group="same_context_direct",
        runtime_style="baremetal_polling",
        inspiration="toy_copy_sink",
        expected_channel_mode="none",
        chain_shape="same_context_direct_call",
        todo_items=(
            "Annotate all payload objects touched by handler/handle_name.",
            "Record which roots are attacker-controlled and which are not.",
            "Mark g_name path separately if it should remain dropped.",
        ),
    ),
    "t0_store_loop_sink": SampleMeta(
        title="Store, memset, and loop-write sink archetypes",
        mechanism_group="sink_archetype",
        runtime_style="baremetal_polling",
        inspiration="toy_store_loop",
        expected_channel_mode="none",
        chain_shape="same_context_mixed_sinks",
        todo_items=(
            "Annotate STORE_SINK, MEMSET_SINK, and LOOP_WRITE_SINK sites separately.",
            "Record which object each sink writes through.",
            "Capture effective vs absent bounds checks per sink root.",
        ),
    ),
    "t0_uart_rx_overflow": SampleMeta(
        title="Manual UART loop-copy overflow",
        mechanism_group="same_context_direct",
        runtime_style="baremetal_polling",
        inspiration="toy_loop_copy",
        expected_channel_mode="none",
        chain_shape="same_context_loop_copy",
        todo_items=(
            "Annotate manual loop-write sink as copy-equivalent.",
            "Record that the sink root is the loop bound/count rather than API length.",
        ),
    ),
    "t0_dma_length_overflow": SampleMeta(
        title="DMA-fed length drives copy overflow",
        mechanism_group="dma_cross_context",
        runtime_style="baremetal_dma",
        inspiration="toy_dma_length",
        expected_channel_mode="required",
        chain_shape="source_object_channel_derive_copy",
        todo_items=(
            "Annotate DMA buffer object and derived length field.",
            "Record DMA->MAIN channel and length derivation.",
            "Bind COPY_SINK root to DMA-derived length expression.",
        ),
    ),
    "t0_indirect_memcpy": SampleMeta(
        title="Caller-bridge into memcpy helper",
        mechanism_group="same_context_bridge",
        runtime_style="baremetal_polling",
        inspiration="toy_indirect_copy",
        expected_channel_mode="none",
        chain_shape="caller_bridge_copy",
        todo_items=(
            "Annotate bridge from caller parse_packet into do_copy.",
            "Mark which roots can be confirmed only through caller_bridge evidence.",
        ),
    ),
    "t0_format_string": SampleMeta(
        title="Format-string sink archetype",
        mechanism_group="sink_archetype",
        runtime_style="baremetal_polling",
        inspiration="toy_format_string",
        expected_channel_mode="none",
        chain_shape="same_context_format_string",
        todo_items=(
            "Annotate format argument root and its controllability.",
            "Record safe local formatting helpers that must not be promoted.",
        ),
    ),
    "t0_func_ptr_dispatch": SampleMeta(
        title="Function-pointer dispatch sink archetype",
        mechanism_group="sink_archetype",
        runtime_style="baremetal_polling",
        inspiration="toy_func_ptr_dispatch",
        expected_channel_mode="none",
        chain_shape="same_context_indirect_call",
        todo_items=(
            "Annotate dispatch table object and index root.",
            "Record any bounds checks on the dispatch index.",
        ),
    ),
    "cve_2020_10065_hci_spi": SampleMeta(
        title="Zephyr HCI-over-SPI overflow reproduction",
        mechanism_group="real_cve_semantic",
        runtime_style="baremetal_thread_model",
        inspiration="zephyr",
        expected_channel_mode="none",
        chain_shape="same_context_multi_sink_semantic",
        todo_items=(
            "Annotate rxmsg as payload object and header subfields used for derive facts.",
            "Record two independent COPY_SINK roots: EVT and ACL.",
            "Mark missing tailroom/upper-bound checks explicitly.",
        ),
    ),
    "cve_2021_34259_usb_host": SampleMeta(
        title="STM32Cube USB host descriptor parsing overflow reproduction",
        mechanism_group="real_cve_semantic",
        runtime_style="baremetal_polling",
        inspiration="stm32cube_usb",
        expected_channel_mode="none",
        chain_shape="same_context_parser_overflow",
        todo_items=(
            "Annotate descriptor objects for cfg/interface/endpoint parsing.",
            "Promote STORE_SINK sites into parser-overflow semantic chains.",
            "Record which roots come from descriptor length/offset fields.",
        ),
    ),
    "cve_2018_16525_freertos_dns": SampleMeta(
        title="FreeRTOS DNS parser overflow reproduction",
        mechanism_group="real_cve_semantic",
        runtime_style="baremetal_polling",
        inspiration="freertos",
        expected_channel_mode="none",
        chain_shape="same_context_parser_overflow",
        todo_items=(
            "Annotate packet buffer object and length/name-walk fields.",
            "Split COPY_SINK, LENGTH_TRUST_SINK, and UNBOUNDED_WALK_SINK chains.",
            "Mark trusted-length and walk-bound checks as absent or weak.",
        ),
    ),
}

MANUAL_EXTRA_SINKS: Dict[str, List[dict]] = {
    "t0_mmio_read": [
        {
            "gt_sink_id": "S_MANUAL_1",
            "label": "COPY_SINK",
            "pipeline_label_hint": "COPY_SINK",
            "function_name": "process_data",
            "address": None,
            "address_hex": None,
            "notes": "Seeded from source comment: memcpy(dst, rx_buf, n) in process_data().",
            "source_file": "t0_mmio_read.c",
            "map_file": "t0_mmio_read.map",
        }
    ],
    "t0_isr_filled_buffer": [
        {
            "gt_sink_id": "S_MANUAL_1",
            "label": "COPY_SINK",
            "pipeline_label_hint": "COPY_SINK",
            "function_name": "process_packet",
            "address": None,
            "address_hex": None,
            "notes": "Seeded from source comment: memcpy(out, tmp, count) in process_packet().",
            "source_file": "t0_isr_filled_buffer.c",
            "map_file": "t0_isr_filled_buffer.map",
        }
    ],
}


SOURCE_SITE_KIND = {
    "MMIO_READ": "mmio_read",
    "ISR_MMIO_READ": "mmio_read_in_isr",
    "ISR_FILLED_BUFFER": "shared_buffer",
    "DMA_BACKED_BUFFER": "dma_buffer",
}

SINK_SITE_KIND = {
    "COPY_SINK": "copy_call_or_copy_idiom",
    "STORE_SINK": "pointer_store",
    "LOOP_WRITE_SINK": "loop_write",
    "MEMSET_SINK": "memset_call",
    "FORMAT_STRING_SINK": "format_call",
    "FUNC_PTR_SINK": "indirect_call",
    "PARSING_OVERFLOW_SINK": "parser_write",
    "LENGTH_TRUST_SINK": "length_trust",
    "UNBOUNDED_WALK_SINK": "unbounded_walk",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _load_existing_gt(repo_root: Path) -> Tuple[Dict[str, List[dict]], Dict[str, List[dict]]]:
    gt_dir = repo_root / "firmware" / "ground_truth_bundle"
    sources = _load_json(gt_dir / "normalized_gt_sources.json")
    sinks = _load_json(gt_dir / "normalized_gt_sinks.json")
    by_source: Dict[str, List[dict]] = {}
    by_sink: Dict[str, List[dict]] = {}
    for row in sources:
        by_source.setdefault(row["binary_stem"], []).append(row)
    for row in sinks:
        by_sink.setdefault(row["binary_stem"], []).append(row)
    for rows in by_source.values():
        rows.sort(key=lambda x: (x.get("function_name", ""), x.get("address", 0), x.get("gt_source_id", "")))
    for rows in by_sink.values():
        rows.sort(key=lambda x: (x.get("function_name", ""), x.get("address", 0), x.get("gt_sink_id", "")))
    for stem, extras in MANUAL_EXTRA_SINKS.items():
        merged = list(by_sink.get(stem, []))
        existing_ids = {row["gt_sink_id"] for row in merged}
        for row in extras:
            if row["gt_sink_id"] not in existing_ids:
                merged.append(row)
        merged.sort(key=lambda x: (x.get("function_name", ""), x.get("address", 0) or 0, x.get("gt_sink_id", "")))
        by_sink[stem] = merged
    return by_source, by_sink


def _source_context(label: str) -> str:
    if label == "ISR_MMIO_READ":
        return "ISR"
    if label == "DMA_BACKED_BUFFER":
        return "DMA"
    return "MAIN"


def _seed_source_entry(row: dict) -> dict:
    return {
        "source_id": row["gt_source_id"],
        "label": row["label"],
        "function_name": row["function_name"],
        "address": row.get("address"),
        "address_hex": row.get("address_hex"),
        "site_kind": SOURCE_SITE_KIND.get(row["label"], "unknown"),
        "context": _source_context(row["label"]),
        "role": "data" if row["label"] != "MMIO_READ" or "status" not in row.get("notes", "").lower() else "control",
        "notes": row.get("notes", ""),
        "status": "seeded_from_v1",
        "source_file": row.get("source_file"),
        "map_file": row.get("map_file"),
    }


def _seed_sink_entry(row: dict) -> dict:
    return {
        "sink_id": row["gt_sink_id"],
        "label": row["label"],
        "pipeline_label_hint": row.get("pipeline_label_hint"),
        "function_name": row["function_name"],
        "address": row.get("address"),
        "address_hex": row.get("address_hex"),
        "site_kind": SINK_SITE_KIND.get(row["label"], "unknown"),
        "notes": row.get("notes", ""),
        "status": "seeded_from_v1",
        "source_file": row.get("source_file"),
        "map_file": row.get("map_file"),
    }


def build_sample_skeleton(
    stem: str,
    meta: SampleMeta,
    source_rows: List[dict],
    sink_rows: List[dict],
) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary_stem": stem,
        "binary_paths": {
            "source_file": f"firmware/microbench/{stem}.c",
            "map_file": f"firmware/microbench/{stem}.map",
            "elf_file": f"firmware/microbench/{stem}.elf",
            "bin_file": f"firmware/microbench/{stem}.bin",
        },
        "sample_meta": {
            "title": meta.title,
            "mechanism_group": meta.mechanism_group,
            "runtime_style": meta.runtime_style,
            "inspiration": meta.inspiration,
            "arch": "ARM_CORTEX_M",
            "expected_channel_mode": meta.expected_channel_mode,
            "chain_shape": meta.chain_shape,
        },
        "annotation_status": {
            "sources": "seeded_from_v1",
            "objects": "todo_manual",
            "channels": "todo_manual",
            "sinks": "seeded_from_v1",
            "sink_roots": "todo_manual",
            "derive_checks": "todo_manual",
            "chains": "todo_manual",
            "negative_expectations": "todo_manual",
            "overall": "skeleton_seed",
        },
        "todo_items": list(meta.todo_items),
        "sources": [_seed_source_entry(row) for row in source_rows],
        "objects": [],
        "channels": [],
        "sinks": [_seed_sink_entry(row) for row in sink_rows],
        "sink_roots": [],
        "derive_checks": [],
        "chains": [],
        "negative_expectations": [],
        "notes": [
            "This file is a skeleton seed. Sources and sinks were imported from normalized_gt_* v1 files.",
            "Objects/channels/roots/derive_checks/chains still require manual artifact-level annotation.",
        ],
    }


def build_microbench_gt_v2(
    repo_root: Path | None = None,
    out_dir: Path | None = None,
    *,
    force: bool = False,
) -> dict:
    repo_root = repo_root or _repo_root()
    out_dir = out_dir or (repo_root / DEFAULT_REL_DIR)
    sample_dir = out_dir / "samples"
    sample_dir.mkdir(parents=True, exist_ok=True)

    by_source, by_sink = _load_existing_gt(repo_root)
    manifest_samples = []
    for stem, meta in MICROBENCH_SAMPLES.items():
        sample_path = sample_dir / f"{stem}.json"
        if sample_path.exists() and not force:
            sample = _load_json(sample_path)
        else:
            sample = build_sample_skeleton(
                stem,
                meta,
                by_source.get(stem, []),
                by_sink.get(stem, []),
            )
            with sample_path.open("w", encoding="utf-8") as f:
                json.dump(sample, f, indent=2, sort_keys=False)
                f.write("\n")
        manifest_samples.append(
            {
                "binary_stem": stem,
                "sample_path": (
                    str(sample_path.relative_to(repo_root))
                    if sample_path.is_relative_to(repo_root)
                    else str(sample_path)
                ),
                "mechanism_group": meta.mechanism_group,
                "expected_channel_mode": meta.expected_channel_mode,
                "source_count_seed": len(sample.get("sources", [])),
                "sink_count_seed": len(sample.get("sinks", [])),
                "annotation_level": sample.get("annotation_status", {}).get("overall", "unknown"),
            }
        )

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sample_count": len(manifest_samples),
        "samples": manifest_samples,
    }
    with (out_dir / "index.json").open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=False)
        f.write("\n")
    return manifest


class ValidationError(ValueError):
    pass


def _require_keys(obj: dict, required: Iterable[str], where: str, errors: List[str]) -> None:
    for key in required:
        if key not in obj:
            errors.append(f"{where}: missing required key '{key}'")


def _require_type(value: Any, expected: type | Tuple[type, ...], where: str, errors: List[str]) -> None:
    if not isinstance(value, expected):
        if isinstance(expected, tuple):
            expect = ",".join(t.__name__ for t in expected)
        else:
            expect = expected.__name__
        errors.append(f"{where}: expected {expect}, got {type(value).__name__}")


def _validate_optional_chain_risk_gt(row: dict, where: str, errors: List[str]) -> None:
    present = [key for key in _CHAIN_RISK_GT_FIELDS if key in row]
    if not present:
        return
    missing = [key for key in _CHAIN_RISK_GT_FIELDS if key not in row]
    for key in missing:
        errors.append(f"{where}: missing required key '{key}' when chain-level risk GT is present")
    verdict = row.get("expected_final_verdict")
    if verdict is not None and verdict not in _ALLOWED_CHAIN_VERDICTS:
        errors.append(f"{where}: unknown expected_final_verdict '{verdict}'")
    risk_band = row.get("expected_final_risk_band")
    if risk_band is not None and risk_band not in _ALLOWED_RISK_BANDS:
        errors.append(f"{where}: unknown expected_final_risk_band '{risk_band}'")
    priority = row.get("expected_review_priority")
    if priority is not None and priority not in _ALLOWED_REVIEW_PRIORITIES:
        errors.append(f"{where}: unknown expected_review_priority '{priority}'")


def validate_sample_schema(sample: dict, *, strict: bool = False) -> List[str]:
    errors: List[str] = []
    _require_keys(
        sample,
        (
            "schema_version",
            "binary_stem",
            "binary_paths",
            "sample_meta",
            "annotation_status",
            "sources",
            "objects",
            "channels",
            "sinks",
            "sink_roots",
            "derive_checks",
            "chains",
            "negative_expectations",
        ),
        "sample",
        errors,
    )
    if errors:
        return errors

    if sample["schema_version"] != SCHEMA_VERSION:
        errors.append(
            f"sample {sample.get('binary_stem', '<unknown>')}: schema_version="
            f"{sample['schema_version']} expected {SCHEMA_VERSION}"
        )

    _require_type(sample["binary_stem"], str, "sample.binary_stem", errors)
    _require_type(sample["binary_paths"], dict, "sample.binary_paths", errors)
    _require_type(sample["sample_meta"], dict, "sample.sample_meta", errors)
    _require_type(sample["annotation_status"], dict, "sample.annotation_status", errors)

    for field in ("sources", "objects", "channels", "sinks", "sink_roots", "derive_checks", "chains", "negative_expectations"):
        _require_type(sample[field], list, f"sample.{field}", errors)

    binary_paths = sample["binary_paths"]
    _require_keys(binary_paths, ("source_file", "map_file", "elf_file", "bin_file"), "sample.binary_paths", errors)

    meta = sample["sample_meta"]
    _require_keys(
        meta,
        ("title", "mechanism_group", "runtime_style", "inspiration", "arch", "expected_channel_mode", "chain_shape"),
        "sample.sample_meta",
        errors,
    )

    ann = sample["annotation_status"]
    _require_keys(
        ann,
        ("sources", "objects", "channels", "sinks", "sink_roots", "derive_checks", "chains", "negative_expectations", "overall"),
        "sample.annotation_status",
        errors,
    )

    allowed_status = {"seeded_from_v1", "todo_manual", "complete", "n/a", "skeleton_seed"}
    for key, value in ann.items():
        if not isinstance(value, str):
            errors.append(f"sample.annotation_status.{key}: expected str")
        elif value not in allowed_status:
            errors.append(f"sample.annotation_status.{key}: unknown status '{value}'")

    source_ids = set()
    for i, row in enumerate(sample["sources"]):
        where = f"sources[{i}]"
        _require_keys(row, ("source_id", "label", "function_name", "site_kind", "context", "status"), where, errors)
        if "source_id" in row:
            if row["source_id"] in source_ids:
                errors.append(f"{where}: duplicate source_id '{row['source_id']}'")
            source_ids.add(row["source_id"])

    object_ids = set()
    for i, row in enumerate(sample["objects"]):
        where = f"objects[{i}]"
        _require_keys(row, ("object_id", "region_kind", "producer_contexts", "consumer_contexts"), where, errors)
        if "object_id" in row:
            if row["object_id"] in object_ids:
                errors.append(f"{where}: duplicate object_id '{row['object_id']}'")
            object_ids.add(row["object_id"])

    channel_ids = set()
    for i, row in enumerate(sample["channels"]):
        where = f"channels[{i}]"
        _require_keys(
            row,
            ("channel_id", "src_context", "object_id", "dst_context", "edge_kind", "constraints", "evidence_refs"),
            where,
            errors,
        )
        cid = row.get("channel_id")
        if cid:
            if cid in channel_ids:
                errors.append(f"{where}: duplicate channel_id '{cid}'")
            channel_ids.add(cid)
        object_id = row.get("object_id")
        if object_ids and object_id not in object_ids:
            errors.append(f"{where}: unknown object_id '{object_id}'")

    sink_ids = set()
    for i, row in enumerate(sample["sinks"]):
        where = f"sinks[{i}]"
        _require_keys(row, ("sink_id", "label", "function_name", "site_kind", "status"), where, errors)
        if "sink_id" in row:
            if row["sink_id"] in sink_ids:
                errors.append(f"{where}: duplicate sink_id '{row['sink_id']}'")
            sink_ids.add(row["sink_id"])

    root_ids = set()
    for i, row in enumerate(sample["sink_roots"]):
        where = f"sink_roots[{i}]"
        _require_keys(row, ("root_id", "sink_id", "root_role", "expr", "status"), where, errors)
        rid = row.get("root_id")
        if rid:
            if rid in root_ids:
                errors.append(f"{where}: duplicate root_id '{rid}'")
            root_ids.add(rid)
        if row.get("sink_id") not in sink_ids:
            errors.append(f"{where}: unknown sink_id '{row.get('sink_id')}'")

    derive_ids = set()
    for i, row in enumerate(sample["derive_checks"]):
        where = f"derive_checks[{i}]"
        _require_keys(row, ("derive_check_id", "sink_id", "root_id", "derive_facts", "check_facts", "status"), where, errors)
        did = row.get("derive_check_id")
        if did:
            if did in derive_ids:
                errors.append(f"{where}: duplicate derive_check_id '{did}'")
            derive_ids.add(did)
        if row.get("sink_id") not in sink_ids:
            errors.append(f"{where}: unknown sink_id '{row.get('sink_id')}'")
        if row.get("root_id") not in root_ids:
            errors.append(f"{where}: unknown root_id '{row.get('root_id')}'")

    chain_ids = set()
    for i, row in enumerate(sample["chains"]):
        where = f"chains[{i}]"
        _require_keys(
            row,
            ("chain_id", "sink_id", "expected_verdict", "required_source_ids", "required_object_ids", "required_channel_ids"),
            where,
            errors,
        )
        cid = row.get("chain_id")
        if cid:
            if cid in chain_ids:
                errors.append(f"{where}: duplicate chain_id '{cid}'")
            chain_ids.add(cid)
        if row.get("sink_id") not in sink_ids:
            errors.append(f"{where}: unknown sink_id '{row.get('sink_id')}'")
        for sid in row.get("required_source_ids", []):
            if sid not in source_ids:
                errors.append(f"{where}: unknown source id '{sid}'")
        for oid in row.get("required_object_ids", []):
            if oid not in object_ids:
                errors.append(f"{where}: unknown object id '{oid}'")
        for chid in row.get("required_channel_ids", []):
            if chid not in channel_ids:
                errors.append(f"{where}: unknown channel id '{chid}'")
        for rid in row.get("required_root_ids", []):
            if rid not in root_ids:
                errors.append(f"{where}: unknown root id '{rid}'")
        for did in row.get("required_derive_check_ids", []):
            if did not in derive_ids:
                errors.append(f"{where}: unknown derive_check id '{did}'")
        _validate_optional_chain_risk_gt(row, where, errors)

    for i, row in enumerate(sample["negative_expectations"]):
        where = f"negative_expectations[{i}]"
        _require_keys(row, ("negative_id", "target_kind", "expected_verdict", "reason"), where, errors)
        tk = row.get("target_kind")
        target_id = row.get("target_id")
        if target_id:
            if tk == "source" and target_id not in source_ids:
                errors.append(f"{where}: unknown source target_id '{target_id}'")
            if tk == "object" and target_id not in object_ids:
                errors.append(f"{where}: unknown object target_id '{target_id}'")
            if tk == "channel" and target_id not in channel_ids:
                errors.append(f"{where}: unknown channel target_id '{target_id}'")
            if tk == "sink" and target_id not in sink_ids:
                errors.append(f"{where}: unknown sink target_id '{target_id}'")
            if tk == "chain" and target_id not in chain_ids:
                errors.append(f"{where}: unknown chain target_id '{target_id}'")

    if strict:
        for section in ("objects", "channels", "sink_roots", "derive_checks", "chains"):
            if sample["annotation_status"].get(section) != "complete":
                errors.append(f"strict mode: section '{section}' is not complete")

    return errors


def validate_microbench_gt_v2_tree(root: Path) -> dict:
    sample_dir = root / "samples"
    sample_files = sorted(sample_dir.glob("*.json"))
    errors: Dict[str, List[str]] = {}
    for path in sample_files:
        sample = _load_json(path)
        sample_errors = validate_sample_schema(sample, strict=False)
        if sample_errors:
            errors[str(path)] = sample_errors

    index_path = root / "index.json"
    if not index_path.exists():
        errors[str(index_path)] = ["missing index.json"]
    else:
        manifest = _load_json(index_path)
        listed = {item["binary_stem"] for item in manifest.get("samples", [])}
        actual = {path.stem for path in sample_files}
        if listed != actual:
            errors.setdefault(str(index_path), []).append(
                f"manifest/sample mismatch listed={sorted(listed)} actual={sorted(actual)}"
            )

    return {
        "schema_version": SCHEMA_VERSION,
        "root": str(root),
        "sample_count": len(sample_files),
        "ok": not errors,
        "errors": errors,
    }


def _build_cmd(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root).resolve()
    out_dir = Path(args.out_dir).resolve()
    manifest = build_microbench_gt_v2(repo_root=repo_root, out_dir=out_dir, force=args.force)
    print(json.dumps(manifest, indent=2))
    return 0


def _validate_cmd(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    report = validate_microbench_gt_v2_tree(root)
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build and validate microbench GT v2 skeletons.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_build = sub.add_parser("build", help="Build microbench GT v2 skeleton files.")
    p_build.add_argument("--repo-root", default=str(_repo_root()))
    p_build.add_argument("--out-dir", default=str(_repo_root() / DEFAULT_REL_DIR))
    p_build.add_argument("--force", action="store_true", help="Overwrite existing sample files.")
    p_build.set_defaults(func=_build_cmd)

    p_validate = sub.add_parser("validate", help="Validate microbench GT v2 skeleton files.")
    p_validate.add_argument("--root", default=str(_repo_root() / DEFAULT_REL_DIR))
    p_validate.set_defaults(func=_validate_cmd)

    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
