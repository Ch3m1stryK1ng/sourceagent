"""Input adapters for Phase B diagnostic mode."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from sourceagent.pipeline.microbench_gt_v2_eval import (
    _load_gt_samples,
    _load_predicted_sample,
    _sample_eval_stem,
    evaluate_sample_artifacts,
)
from sourceagent.pipeline.verdict_calibration import (
    DEFAULT_CALIBRATION_MODE,
    DEFAULT_VERDICT_OUTPUT_MODE,
    build_verdict_calibration_artifacts,
)

SCHEMA_VERSION = "0.1"
DEFAULT_GT_ROOT = (
    Path(__file__).resolve().parents[2]
    / "firmware"
    / "ground_truth_bundle"
    / "gt_backed_suite"
)


def load_runtime_diagnostic_bundle(
    *,
    eval_dir: str | Path,
    sample: str,
    chain_ids: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    eval_dir = Path(eval_dir)
    sample = str(sample or "").strip()
    if not sample:
        raise ValueError("runtime_diagnostic_requires_sample")

    raw_views_dir = eval_dir / "raw_views"
    feature_pack = _load_required_json(raw_views_dir / f"{sample}.verdict_feature_pack.json")
    calibration_queue = _load_optional_json(raw_views_dir / f"{sample}.verdict_calibration_queue.json")
    soft_triage = _load_optional_json(raw_views_dir / f"{sample}.verdict_soft_triage.json")

    feature_by_id = _index_by_chain_id(feature_pack.get("items", []) or [])
    queue_by_id = _index_by_chain_id(calibration_queue.get("items", []) or [])
    soft_by_id = _index_by_chain_id(soft_triage.get("items", []) or [])
    selected_ids = _select_runtime_chain_ids(feature_pack, calibration_queue, soft_triage, chain_ids=chain_ids)

    items: List[Dict[str, Any]] = []
    for chain_id in selected_ids:
        feature_item = feature_by_id.get(chain_id)
        if not feature_item:
            continue
        queue_item = queue_by_id.get(chain_id) or _queue_item_from_feature_item(
            feature_item,
            queue_reasons=["runtime_selected"],
        )
        existing = soft_by_id.get(chain_id, {})
        items.append(
            {
                "feature_item": dict(feature_item),
                "queue_item": dict(queue_item),
                "meta": {
                    "diagnostic_source": "runtime",
                    "diagnostic_mode": "runtime_feature_item",
                    "diagnostic_role": "runtime_selected",
                    "sample_id": str(feature_item.get("sample_id", "") or sample),
                    "diagnostic_chain_id": chain_id,
                    "runtime_pred_chain_id": chain_id,
                    "structural_status": "runtime_feature_item",
                    "existing_final_verdict": existing.get("final_verdict"),
                    "existing_final_risk_band": existing.get("final_risk_band"),
                    "existing_review_priority": existing.get("review_priority"),
                },
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "diagnostic_source": "runtime",
        "sample_id": sample,
        "binary": str(feature_pack.get("binary", "") or sample),
        "binary_sha256": str(feature_pack.get("binary_sha256", "") or ""),
        "calibration_mode": str(feature_pack.get("mode", "") or DEFAULT_CALIBRATION_MODE),
        "verdict_output_mode": str(feature_pack.get("output_mode", "") or DEFAULT_VERDICT_OUTPUT_MODE),
        "items": items,
    }


def load_anchor_diagnostic_bundle(
    *,
    sample: str,
    gt_root: str | Path | None = None,
    eval_dir: str | Path | None = None,
    chain_ids: Optional[Sequence[str]] = None,
    include_related: bool = True,
    include_supporting: bool = True,
    include_peripheral_suspicious: bool = False,
) -> Dict[str, Any]:
    gt_root_path = Path(gt_root) if gt_root else DEFAULT_GT_ROOT
    gt_sample = _find_gt_sample(sample, gt_root_path)
    eval_stem = _sample_eval_stem(gt_sample)

    feature_pack: Dict[str, Any] = {}
    calibration_queue: Dict[str, Any] = {}
    soft_triage: Dict[str, Any] = {}
    pred_eval: Dict[str, Any] = {}
    canonical_eval: Dict[str, Any] = {}
    if eval_dir is not None:
        eval_dir = Path(eval_dir)
        raw_views_dir = eval_dir / "raw_views"
        feature_pack = _load_optional_json(raw_views_dir / f"{eval_stem}.verdict_feature_pack.json")
        calibration_queue = _load_optional_json(raw_views_dir / f"{eval_stem}.verdict_calibration_queue.json")
        soft_triage = _load_optional_json(raw_views_dir / f"{eval_stem}.verdict_soft_triage.json")
        predicted = _load_predicted_sample(eval_dir, eval_stem)
        if predicted.get("present"):
            pred_eval = predicted
            canonical_eval = evaluate_sample_artifacts(gt_sample, predicted).get("canonical_cve", {}) or {}

    feature_by_id = _index_by_chain_id(feature_pack.get("items", []) or [])
    queue_by_id = _index_by_chain_id(calibration_queue.get("items", []) or [])
    soft_by_id = _index_by_chain_id(soft_triage.get("items", []) or [])

    selected_roles = _selected_anchor_ids(
        gt_sample,
        chain_ids=chain_ids,
        include_related=include_related,
        include_supporting=include_supporting,
    )
    gt_chains_by_id = {
        str(chain.get("chain_id", "") or ""): dict(chain)
        for chain in (gt_sample.get("chains", []) or [])
        if str(chain.get("chain_id", "") or "")
    }
    matched_map = _canonical_pred_chain_map(canonical_eval)
    items: List[Dict[str, Any]] = []
    used_runtime_chain_ids: set[str] = set()

    for role, gt_chain_id in selected_roles:
        gt_chain = gt_chains_by_id.get(gt_chain_id)
        if not gt_chain:
            continue
        matched_runtime_id = matched_map.get(gt_chain_id)
        if not matched_runtime_id and gt_chain_id in feature_by_id:
            matched_runtime_id = gt_chain_id

        if matched_runtime_id and matched_runtime_id in feature_by_id:
            feature_item = dict(feature_by_id[matched_runtime_id])
            queue_item = dict(
                queue_by_id.get(matched_runtime_id)
                or _queue_item_from_feature_item(feature_item, queue_reasons=[role])
            )
            existing = dict(soft_by_id.get(matched_runtime_id, {}) or {})
            diagnostic_mode = "anchor_matched"
            used_runtime_chain_ids.add(matched_runtime_id)
        else:
            synthesized = _build_synthetic_anchor_bundle(gt_sample, gt_chain_id)
            feature_item = dict(synthesized["feature_item"])
            queue_item = dict(
                synthesized["queue_item"]
                or _queue_item_from_feature_item(feature_item, queue_reasons=[role])
            )
            existing = {}
            diagnostic_mode = "anchor_synthetic"

        items.append(
            {
                "feature_item": feature_item,
                "queue_item": queue_item,
                "meta": {
                    "diagnostic_source": "anchor",
                    "diagnostic_mode": diagnostic_mode,
                    "diagnostic_role": role,
                    "sample_id": str(gt_sample.get("sample_id", "") or gt_sample.get("binary_stem", "") or sample),
                    "diagnostic_chain_id": str(feature_item.get("chain_id", "") or gt_chain_id),
                    "gt_chain_id": gt_chain_id,
                    "runtime_pred_chain_id": matched_runtime_id,
                    "anchor_status": str(
                        ((gt_sample.get("evaluation_only", {}) or {}).get("canonical_cve_anchor_status", "absent"))
                        or "absent"
                    ),
                    "structural_status": diagnostic_mode,
                    "expected_verdict": gt_chain.get("expected_verdict"),
                    "expected_final_verdict": gt_chain.get("expected_final_verdict"),
                    "expected_final_risk_band": gt_chain.get("expected_final_risk_band"),
                    "expected_review_priority": gt_chain.get("expected_review_priority"),
                    "risk_gt_provenance": gt_chain.get("risk_gt_provenance"),
                    "existing_final_verdict": existing.get("final_verdict"),
                    "existing_final_risk_band": existing.get("final_risk_band"),
                    "existing_review_priority": existing.get("review_priority"),
                },
            }
        )

    if include_peripheral_suspicious and feature_by_id:
        for chain_id, soft_row in soft_by_id.items():
            if chain_id in used_runtime_chain_ids:
                continue
            if str(soft_row.get("final_verdict", "") or "") != "SUSPICIOUS":
                continue
            feature_item = feature_by_id.get(chain_id)
            if not feature_item:
                continue
            items.append(
                {
                    "feature_item": dict(feature_item),
                    "queue_item": dict(
                        queue_by_id.get(chain_id)
                        or _queue_item_from_feature_item(feature_item, queue_reasons=["peripheral_suspicious"])
                    ),
                    "meta": {
                        "diagnostic_source": "anchor",
                        "diagnostic_mode": "peripheral_runtime",
                        "diagnostic_role": "peripheral_suspicious",
                        "sample_id": str(gt_sample.get("sample_id", "") or gt_sample.get("binary_stem", "") or sample),
                        "diagnostic_chain_id": chain_id,
                        "runtime_pred_chain_id": chain_id,
                        "structural_status": "peripheral_runtime",
                        "existing_final_verdict": soft_row.get("final_verdict"),
                        "existing_final_risk_band": soft_row.get("final_risk_band"),
                        "existing_review_priority": soft_row.get("review_priority"),
                    },
                }
            )

    binary_name = str(feature_pack.get("binary", "") or gt_sample.get("binary_stem", "") or sample)
    binary_sha256 = str(feature_pack.get("binary_sha256", "") or pred_eval.get("pipeline", {}).get("binary_sha256", "") or "")
    return {
        "schema_version": SCHEMA_VERSION,
        "diagnostic_source": "anchor",
        "sample_id": str(gt_sample.get("sample_id", "") or gt_sample.get("binary_stem", "") or sample),
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "calibration_mode": str(feature_pack.get("mode", "") or DEFAULT_CALIBRATION_MODE),
        "verdict_output_mode": str(feature_pack.get("output_mode", "") or DEFAULT_VERDICT_OUTPUT_MODE),
        "items": items,
    }


def load_file_diagnostic_bundle(path: str | Path) -> Dict[str, Any]:
    data = _load_required_json(Path(path))
    items: List[Dict[str, Any]] = []
    top_meta = dict(data.get("meta", {}) or {})
    for idx, raw in enumerate(data.get("items", []) or []):
        if not isinstance(raw, Mapping):
            continue
        feature_item = dict(raw.get("feature_item", raw) or {})
        if not feature_item:
            continue
        chain_id = str(feature_item.get("chain_id", "") or raw.get("diagnostic_chain_id", "") or f"file_chain_{idx:03d}")
        feature_item.setdefault("chain_id", chain_id)
        queue_item = dict(
            raw.get("queue_item")
            or _queue_item_from_feature_item(
                feature_item,
                queue_reasons=["file_input"],
            )
        )
        meta = dict(top_meta)
        meta.update(dict(raw.get("meta", {}) or {}))
        meta.setdefault("diagnostic_source", "file")
        meta.setdefault("diagnostic_mode", "file_input")
        meta.setdefault("diagnostic_role", "file_input")
        meta.setdefault("diagnostic_chain_id", chain_id)
        meta.setdefault("sample_id", str(feature_item.get("sample_id", "") or data.get("sample_id", "") or "external"))
        meta.setdefault("structural_status", "file_input")
        items.append(
            {
                "feature_item": feature_item,
                "queue_item": queue_item,
                "meta": meta,
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "diagnostic_source": "file",
        "sample_id": str(data.get("sample_id", "") or (items[0]["meta"]["sample_id"] if items else "external")),
        "binary": str(data.get("binary", "") or ""),
        "binary_sha256": str(data.get("binary_sha256", "") or ""),
        "calibration_mode": str(data.get("calibration_mode", "") or DEFAULT_CALIBRATION_MODE),
        "verdict_output_mode": str(data.get("verdict_output_mode", "") or DEFAULT_VERDICT_OUTPUT_MODE),
        "items": items,
    }


def load_phaseb_diagnostic_bundle(
    *,
    diagnostic_source: str,
    eval_dir: str | Path | None = None,
    sample: str | None = None,
    chain_ids: Optional[Sequence[str]] = None,
    diagnostic_json: str | Path | None = None,
    gt_root: str | Path | None = None,
    include_related: bool = True,
    include_supporting: bool = True,
    include_peripheral_suspicious: bool = False,
) -> Dict[str, Any]:
    source = str(diagnostic_source or "").strip().lower()
    if source == "runtime":
        if not eval_dir or not sample:
            raise ValueError("runtime_diagnostic_requires_eval_dir_and_sample")
        return load_runtime_diagnostic_bundle(
            eval_dir=eval_dir,
            sample=sample,
            chain_ids=chain_ids,
        )
    if source == "anchor":
        if not sample:
            raise ValueError("anchor_diagnostic_requires_sample")
        return load_anchor_diagnostic_bundle(
            sample=sample,
            gt_root=gt_root,
            eval_dir=eval_dir,
            chain_ids=chain_ids,
            include_related=include_related,
            include_supporting=include_supporting,
            include_peripheral_suspicious=include_peripheral_suspicious,
        )
    if source == "file":
        if not diagnostic_json:
            raise ValueError("file_diagnostic_requires_diagnostic_json")
        return load_file_diagnostic_bundle(diagnostic_json)
    raise ValueError(f"unsupported_diagnostic_source:{source}")


def _find_gt_sample(sample: str, gt_root: Path) -> Dict[str, Any]:
    sample_key = str(sample or "").strip()
    if not sample_key:
        raise ValueError("empty_gt_sample_key")
    for row in _load_gt_samples(gt_root):
        if sample_key in {
            str(row.get("sample_id", "") or "").strip(),
            str(row.get("binary_stem", "") or "").strip(),
            str(row.get("eval_stem", "") or "").strip(),
        }:
            return row
    raise FileNotFoundError(f"gt_sample_not_found:{sample_key}")


def _selected_anchor_ids(
    gt_sample: Mapping[str, Any],
    *,
    chain_ids: Optional[Sequence[str]],
    include_related: bool,
    include_supporting: bool,
) -> List[Tuple[str, str]]:
    evaluation_only = dict(gt_sample.get("evaluation_only", {}) or {})
    selected: List[Tuple[str, str]] = []
    selected.extend(
        ("canonical_main", str(chain_id))
        for chain_id in (evaluation_only.get("canonical_cve_chain_ids", []) or [])
        if str(chain_id)
    )
    if include_related:
        selected.extend(
            ("related_risky", str(chain_id))
            for chain_id in (evaluation_only.get("related_cve_chain_ids", []) or [])
            if str(chain_id)
        )
    if include_supporting:
        selected.extend(
            ("supporting_risky", str(chain_id))
            for chain_id in (evaluation_only.get("supporting_cve_chain_ids", []) or [])
            if str(chain_id)
        )
    if not chain_ids:
        return selected
    allowed = {str(chain_id or "").strip() for chain_id in chain_ids if str(chain_id or "").strip()}
    return [(role, chain_id) for role, chain_id in selected if chain_id in allowed]


def _canonical_pred_chain_map(canonical_eval: Mapping[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for bucket_name in ("canonical_main", "related_risky", "supporting_risky"):
        bucket = dict(canonical_eval.get(bucket_name, {}) or {})
        for row in bucket.get("details", []) or []:
            if not isinstance(row, Mapping):
                continue
            gt_chain_id = str(row.get("gt_chain_id", "") or "").strip()
            pred_chain_id = str(row.get("pred_chain_id", "") or "").strip()
            if gt_chain_id and pred_chain_id:
                out[gt_chain_id] = pred_chain_id
    return out


def _build_synthetic_anchor_bundle(gt_sample: Mapping[str, Any], gt_chain_id: str) -> Dict[str, Any]:
    chain_by_id = {
        str(chain.get("chain_id", "") or ""): dict(chain)
        for chain in (gt_sample.get("chains", []) or [])
        if str(chain.get("chain_id", "") or "")
    }
    gt_chain = dict(chain_by_id.get(gt_chain_id, {}) or {})
    if not gt_chain:
        raise FileNotFoundError(f"gt_chain_not_found:{gt_chain_id}")

    sources_by_id = _index_by_id(gt_sample.get("sources", []) or [], "source_id")
    objects_by_id = _index_by_id(gt_sample.get("objects", []) or [], "object_id")
    channels_by_id = _index_by_id(gt_sample.get("channels", []) or [], "channel_id")
    sinks_by_id = _index_by_id(gt_sample.get("sinks", []) or [], "sink_id")
    roots_by_id = _index_by_id(gt_sample.get("sink_roots", []) or [], "root_id")
    derives_by_id = _index_by_id(gt_sample.get("derive_checks", []) or [], "derive_check_id")

    gt_sink = dict(sinks_by_id.get(str(gt_chain.get("sink_id", "") or ""), {}) or {})
    required_source_ids = [str(v) for v in (gt_chain.get("required_source_ids", []) or []) if str(v)]
    required_object_ids = [str(v) for v in (gt_chain.get("required_object_ids", []) or []) if str(v)]
    required_channel_ids = [str(v) for v in (gt_chain.get("required_channel_ids", []) or []) if str(v)]
    required_root_ids = [str(v) for v in (gt_chain.get("required_root_ids", []) or []) if str(v)]
    required_derive_ids = [str(v) for v in (gt_chain.get("required_derive_check_ids", []) or []) if str(v)]

    active_root = dict(roots_by_id.get(required_root_ids[0], {}) or {}) if required_root_ids else {}
    root_expr = str(active_root.get("expr", "") or "")
    root_role = str(active_root.get("root_role", "") or "len")
    check_rows: List[Dict[str, Any]] = []
    derive_rows: List[Dict[str, Any]] = []
    producer_sites: List[str] = []
    bridge_sites: List[str] = []
    for derive_id in required_derive_ids:
        derive = dict(derives_by_id.get(derive_id, {}) or {})
        for row in derive.get("derive_facts", []) or []:
            site = str(row.get("site", "") or "")
            derive_rows.append({"expr": row.get("expr"), "site": site})
            if site:
                bridge_sites.append(site)
        for row in derive.get("check_facts", []) or []:
            site = str(row.get("site", "") or "")
            check_rows.append(
                {
                    "expr": row.get("expr"),
                    "site": site,
                    "strength": str(row.get("strength", "") or "unknown"),
                    "binding_target": "active_root",
                    "capacity_scope": _capacity_scope_from_root_role(root_role),
                    "strength_source": "gt_anchor",
                }
            )
            if site:
                bridge_sites.append(site)

    source_steps: List[Dict[str, Any]] = []
    for source_id in required_source_ids:
        row = dict(sources_by_id.get(source_id, {}) or {})
        if row:
            site = _format_address(row.get("address_hex") or row.get("address"))
            source_steps.append(
                {
                    "kind": "SOURCE",
                    "label": row.get("label"),
                    "function": row.get("function_name"),
                    "site": site,
                }
            )
            if row.get("function_name"):
                producer_sites.append(str(row.get("function_name")))

    channel_steps: List[Dict[str, Any]] = []
    for channel_id in required_channel_ids:
        row = dict(channels_by_id.get(channel_id, {}) or {})
        if row:
            channel_steps.append(
                {
                    "kind": "CHANNEL",
                    "edge": f"{row.get('src_context', '')}->{row.get('dst_context', '')}",
                    "object_id": row.get("object_id"),
                }
            )

    sink_site = _format_address(gt_sink.get("address_hex") or gt_sink.get("address"))
    sink_label = _normalize_sink_label(str(gt_sink.get("label", "") or ""))
    seed_verdict = _diagnostic_seed_verdict(str(gt_chain.get("expected_verdict", "") or "SUSPICIOUS"))
    # Canonical synthetic anchors are seeded as high-confidence structural
    # inputs so Phase B can answer the semantic/risk question rather than
    # being dominated by a weak synthetic prior.
    score = 0.97 if str(gt_chain.get("expected_verdict", "") or "") == "CONFIRMED" else 0.68
    pseudo_chain = {
        "chain_id": f"gt::{gt_sample.get('sample_id', gt_sample.get('binary_stem', 'sample'))}::{gt_chain_id}",
        "verdict": seed_verdict,
        "score": score,
        "status": "ok",
        "sink": {
            "sink_id": gt_sink.get("sink_id"),
            "label": sink_label,
            "function": gt_sink.get("function_name"),
            "site": sink_site,
            "root_expr": root_expr or "UNKNOWN",
        },
        "steps": source_steps + channel_steps + [
            {
                "kind": "SINK",
                "label": sink_label,
                "function": gt_sink.get("function_name"),
                "site": sink_site,
            }
        ],
        "checks": check_rows,
        "derive_facts": derive_rows,
        "root_bundle": {
            "active_root": {
                "expr": root_expr or "UNKNOWN",
                "canonical_expr": root_expr or "UNKNOWN",
                "kind": _root_kind_from_role(root_role),
                "role": root_role or "primary",
                "source": "gt_anchor",
                "active": True,
            }
        },
        "link_debug": {
            "object_hits": required_object_ids,
            "producer_candidates": producer_sites,
            "bridge_functions": sorted({site for site in bridge_sites if site}),
            "active_root_expr": root_expr or "UNKNOWN",
        },
        "decision_basis": {
            "source_reached": bool(required_source_ids),
            "root_controllable": bool(required_root_ids),
            "check_strength": _dominant_check_strength(check_rows),
            "chain_complete": bool(required_root_ids),
            "has_contradiction": False,
            "has_app_anchor": bool(required_object_ids or required_source_ids or required_channel_ids),
            "control_path_only": False,
            "chain_score": score,
            "source_resolve_mode": "gt_anchor",
            "secondary_root_only": False,
            "channel_required_hint": bool(required_channel_ids or gt_chain.get("must_use_channel")),
            "has_channel": bool(required_channel_ids),
            "confirm_threshold": 0.8,
            "reason_code": _reason_code_for_checks(check_rows),
        },
    }

    channel_graph = {
        "object_nodes": [
            _object_node_from_gt(objects_by_id[object_id])
            for object_id in required_object_ids
            if object_id in objects_by_id
        ]
    }
    pack_id = f"diag_pack::{gt_chain_id}"
    sink_facts = {
        "len_expr": root_expr,
        "dst_expr": required_object_ids[0] if required_object_ids else "",
        "guard_expr": "; ".join(str(row.get("expr", "") or "") for row in check_rows if str(row.get("expr", "") or "")),
    }
    decompiled_cache = _synthetic_decompiled_cache(
        gt_sample=gt_sample,
        gt_chain=gt_chain,
        gt_sink=gt_sink,
        source_rows=[sources_by_id[source_id] for source_id in required_source_ids if source_id in sources_by_id],
        object_rows=[objects_by_id[object_id] for object_id in required_object_ids if object_id in objects_by_id],
        derive_rows=derive_rows,
        check_rows=check_rows,
        root_expr=root_expr,
    )
    artifacts = build_verdict_calibration_artifacts(
        binary_name=str(gt_sample.get("binary_stem", "") or gt_sample.get("sample_id", "") or "gt_anchor"),
        binary_sha256="",
        chains=[pseudo_chain],
        channel_graph=channel_graph,
        sink_facts_by_pack={pack_id: sink_facts},
        sink_pack_id_by_site={f"{sink_site}|{gt_sink.get('function_name', '')}|{sink_label}": pack_id},
        decompiled_cache=decompiled_cache,
        calibration_mode=DEFAULT_CALIBRATION_MODE,
        verdict_output_mode=DEFAULT_VERDICT_OUTPUT_MODE,
        has_ground_truth=False,
    )
    feature_item = dict((artifacts.get("verdict_feature_pack", {}) or {}).get("items", [{}])[0] or {})
    queue_items = list(((artifacts.get("verdict_calibration_queue", {}) or {}).get("items", []) or []))
    queue_item = dict(queue_items[0] or {}) if queue_items else _queue_item_from_feature_item(
        feature_item,
        queue_reasons=["anchor_selected"],
    )
    return {
        "feature_item": feature_item,
        "queue_item": queue_item,
    }


def _synthetic_decompiled_cache(
    *,
    gt_sample: Mapping[str, Any],
    gt_chain: Mapping[str, Any],
    gt_sink: Mapping[str, Any],
    source_rows: Sequence[Mapping[str, Any]],
    object_rows: Sequence[Mapping[str, Any]],
    derive_rows: Sequence[Mapping[str, Any]],
    check_rows: Sequence[Mapping[str, Any]],
    root_expr: str,
) -> Dict[str, str]:
    cache: Dict[str, str] = {}
    sink_fn = str(gt_sink.get("function_name", "") or "sink_fn")
    derive_text = "\n".join(f"// derive: {row.get('expr', '')}" for row in derive_rows) or "// derive: none recorded"
    check_text = "\n".join(
        f"// check[{row.get('strength', 'unknown')}]: {row.get('expr', '')}"
        for row in check_rows
    ) or "// check: none recorded"
    cache[sink_fn] = (
        f"/* GT synthetic anchor for {gt_sample.get('sample_id', gt_sample.get('binary_stem', 'sample'))} */\n"
        f"void {sink_fn}(void) {{\n"
        f"  // sink label: {gt_sink.get('label', '')}\n"
        f"  // root: {root_expr or 'UNKNOWN'}\n"
        f"{_indent_text(derive_text, prefix='  ')}\n"
        f"{_indent_text(check_text, prefix='  ')}\n"
        f"}}\n"
    )
    for row in source_rows:
        fn = str(row.get("function_name", "") or "")
        if not fn:
            continue
        cache[fn] = (
            f"void {fn}(void) {{\n"
            f"  // GT source label: {row.get('label', '')}\n"
            f"  // role: {row.get('role', '')}\n"
            f"}}\n"
        )
    for row in object_rows:
        members = ", ".join(str(v) for v in (row.get("members", []) or []))
        for fn in list(row.get("writer_sites", []) or []) + list(row.get("reader_sites", []) or []):
            site_fn = str(fn or "").strip()
            if not site_fn or site_fn in cache:
                continue
            cache[site_fn] = (
                f"void {site_fn}(void) {{\n"
                f"  // GT object interaction: {row.get('object_id', '')}\n"
                f"  // members: {members}\n"
                f"}}\n"
            )
    return cache


def _object_node_from_gt(row: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "object_id": row.get("object_id"),
        "members": list(row.get("members", []) or []),
        "addr_range": list(row.get("addr_range", []) or []),
        "producer_contexts": list(row.get("producer_contexts", []) or []),
        "consumer_contexts": list(row.get("consumer_contexts", []) or []),
        "writers": _site_names(row.get("writer_sites", []) or []),
        "readers": _site_names(row.get("reader_sites", []) or []),
        "type_facts": {},
    }


def _queue_item_from_feature_item(
    feature_item: Mapping[str, Any],
    *,
    queue_reasons: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    return {
        "chain_id": str(feature_item.get("chain_id", "") or ""),
        "queue_score": float(feature_item.get("risk_score", 0.0) or 0.0),
        "queue_reasons": list(queue_reasons or ["diagnostic_selected"]),
        "current_verdict": feature_item.get("current_verdict"),
        "current_verdict_reason": feature_item.get("current_verdict_reason"),
        "sink": dict(feature_item.get("sink", {}) or {}),
        "root": dict(feature_item.get("root", {}) or {}),
        "check_strength": feature_item.get("check_strength"),
        "check_capacity_scope": feature_item.get("check_capacity_scope"),
        "risk_band": feature_item.get("risk_band"),
        "review_priority": feature_item.get("review_priority"),
        "blocked_by": list(feature_item.get("blocked_by", []) or []),
        "soft_candidate": bool(feature_item.get("soft_candidate", False)),
    }


def _select_runtime_chain_ids(
    feature_pack: Mapping[str, Any],
    calibration_queue: Mapping[str, Any],
    soft_triage: Mapping[str, Any],
    *,
    chain_ids: Optional[Sequence[str]],
) -> List[str]:
    if chain_ids:
        return [str(chain_id) for chain_id in chain_ids if str(chain_id)]
    queue_items = calibration_queue.get("items", []) or []
    if queue_items:
        return [str(item.get("chain_id", "") or "") for item in queue_items if str(item.get("chain_id", "") or "")]
    soft_items = soft_triage.get("items", []) or []
    if soft_items:
        return [
            str(item.get("chain_id", "") or "")
            for item in soft_items
            if str(item.get("chain_id", "") or "")
            and (
                bool(item.get("needs_review"))
                or str(item.get("review_priority", "") or "") in {"P0", "P1"}
            )
        ]
    return [
        str(item.get("chain_id", "") or "")
        for item in (feature_pack.get("items", []) or [])
        if str(item.get("chain_id", "") or "")
    ]


def _index_by_chain_id(rows: Iterable[Mapping[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        chain_id = str(row.get("chain_id", "") or "").strip()
        if chain_id:
            out[chain_id] = dict(row)
    return out


def _index_by_id(rows: Iterable[Mapping[str, Any]], key: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        row_id = str(row.get(key, "") or "").strip()
        if row_id:
            out[row_id] = dict(row)
    return out


def _load_required_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(str(path))
    return _load_optional_json(path)


def _load_optional_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _site_names(rows: Sequence[Any]) -> List[str]:
    names: List[str] = []
    for row in rows:
        if isinstance(row, Mapping):
            name = str(row.get("function", "") or row.get("site", "") or "").strip()
        else:
            name = str(row or "").strip()
        if name:
            names.append(name)
    return names


def _format_address(value: Any) -> str:
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return ""
        return text if text.lower().startswith("0x") else text
    if isinstance(value, int):
        return f"0x{value:08x}"
    return ""


def _normalize_sink_label(label: str) -> str:
    text = str(label or "").strip()
    if not text:
        return "COPY_SINK"
    if text.endswith("_SINK"):
        return text
    mapping = {
        "PARSING_OVERFLOW_SINK": "COPY_SINK",
        "UNBOUNDED_WALK_SINK": "LOOP_WRITE_SINK",
        "LENGTH_TRUST_SINK": "COPY_SINK",
        "FORMAT_STRING": "FORMAT_STRING_SINK",
        "FUNC_PTR": "FUNC_PTR_SINK",
    }
    return mapping.get(text, text)


def _diagnostic_seed_verdict(expected_verdict: str) -> str:
    verdict = str(expected_verdict or "SUSPICIOUS")
    if verdict == "CONFIRMED":
        return "SUSPICIOUS"
    return verdict if verdict in {"SAFE_OR_LOW_RISK", "SUSPICIOUS", "CONFIRMED", "DROP"} else "SUSPICIOUS"


def _capacity_scope_from_root_role(root_role: str) -> str:
    family = str(root_role or "").lower()
    if family in {"len", "length_bound", "size_field", "loop_bound", "walk_step"}:
        return "write_bound"
    if family in {"format_arg", "dispatch_index"}:
        return "unknown"
    return "unknown"


def _root_kind_from_role(root_role: str) -> str:
    family = str(root_role or "").lower()
    if family in {"len", "length_bound", "size_field", "loop_bound", "walk_step"}:
        return "length"
    if family == "format_arg":
        return "format_arg"
    if family == "dispatch_index":
        return "dispatch"
    return "length"


def _dominant_check_strength(check_rows: Sequence[Mapping[str, Any]]) -> str:
    rank = {"effective": 3, "weak": 2, "absent": 1, "unknown": 0}
    best = "unknown"
    best_rank = -1
    for row in check_rows:
        cur = str(row.get("strength", "") or "unknown").lower()
        if rank.get(cur, 0) > best_rank:
            best_rank = rank.get(cur, 0)
            best = cur
    if not check_rows:
        return "absent"
    return best


def _reason_code_for_checks(check_rows: Sequence[Mapping[str, Any]]) -> str:
    if not check_rows:
        return "ABSENT_GUARD_CONTROLLABLE_ROOT"
    strength = _dominant_check_strength(check_rows)
    if strength == "effective":
        return "TRIGGER_UNCERTAIN_MISSING_CAPACITY"
    if strength == "weak":
        return "CHECK_UNCERTAIN"
    if strength == "absent":
        return "ABSENT_GUARD_CONTROLLABLE_ROOT"
    return "CHECK_UNCERTAIN"


def _indent_text(text: str, *, prefix: str) -> str:
    return "\n".join(f"{prefix}{line}" for line in str(text or "").splitlines())
