"""Artifact-level evaluator for microbench GT v2.

This evaluator compares microbench GT v2 annotations against an existing
evaluation run directory that contains:

  - raw_results/*.pipeline.json
  - raw_views/*.channel_graph.json
  - raw_views/*.sink_roots.json
  - raw_views/*.chains.json

It intentionally uses tolerant matching rather than exact JSON equality:
objects can match by member overlap or address overlap, sink semantic subtypes
can match via pipeline_label_hint/sink-family aliases, and chains are matched by
required artifact presence plus verdict compatibility.
"""

from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


SCHEMA_VERSION = "0.1"
POSITIVE_CHAIN_VERDICTS = {"CONFIRMED", "SUSPICIOUS", "SAFE_OR_LOW_RISK"}
POSITIVE_LABEL_VERDICTS = {"VERIFIED", "PARTIAL"}

_MEMORY_WRITE_SINK_LABELS = {
    "COPY_SINK",
    "MEMSET_SINK",
    "STORE_SINK",
    "LOOP_WRITE_SINK",
}
_ADDRESS_NEAR_TOLERANCE = 16
_VERDICT_RANK = {
    "DROP": 0,
    "SAFE_OR_LOW_RISK": 1,
    "SUSPICIOUS": 2,
    "CONFIRMED": 3,
}
_ROOT_ROLE_FAMILY = {
    "len": "length",
    "length_bound": "length",
    "length_state": "length",
    "loop_bound": "length",
    "size_field": "length",
    "walk_step": "length",
    "format_arg": "format_arg",
    "dispatch_index": "dispatch",
    "ptr": "pointer",
    "src_object": "pointer",
}
_ROOT_KIND_FAMILY = {
    "length": "length",
    "dst_ptr": "pointer",
    "src_ptr": "pointer",
    "target_addr": "pointer",
    "format_arg": "format_arg",
    "dispatch": "dispatch",
    "src_data": "pointer",
}
_CHAIN_GT_SCOPES = {"exhaustive", "targeted_only", "negative_only"}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _dump_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=False)
        f.write("\n")


def _to_int_address(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.lower().startswith("0x"):
            try:
                return int(text, 16)
            except ValueError:
                return None
        try:
            return int(text, 10)
        except ValueError:
            return None
    return None


def _addresses_near(a: Any, b: Any, tolerance: int = _ADDRESS_NEAR_TOLERANCE) -> bool:
    ai = _to_int_address(a)
    bi = _to_int_address(b)
    if ai is None or bi is None:
        return False
    return abs(ai - bi) <= tolerance


def _functions_match(pred_func: str, gt_func: str) -> bool:
    if not pred_func or not gt_func:
        return False
    pred = pred_func.strip().lower()
    gt = gt_func.strip().lower()
    return pred == gt or gt in pred or pred in gt


def _sink_family(label: str) -> str:
    if label in _MEMORY_WRITE_SINK_LABELS:
        return "MEMORY_WRITE"
    if label in {
        "LENGTH_TRUST_SINK",
        "UNBOUNDED_WALK_SINK",
        "PARSING_OVERFLOW_SINK",
    }:
        return "MEMORY_WRITE"
    if label in {"FORMAT_STRING", "FORMAT_STRING_SINK"}:
        return "FORMAT_STRING"
    if label in {"FUNC_PTR", "FUNC_PTR_SINK"}:
        return "FUNC_PTR"
    return label


def _normalize_expr(expr: Any) -> str:
    if expr is None:
        return ""
    text = str(expr).strip().lower()
    text = text.replace("->", ".")
    text = re.sub(r"\s+", "", text)
    return text


def _expr_tokens(expr: Any) -> List[str]:
    text = _normalize_expr(expr)
    if not text:
        return []
    return re.findall(r"[a-z_][a-z0-9_]*|0x[0-9a-f]+|\d+", text)


def _expr_compatible(gt_expr: Any, pred_expr: Any) -> bool:
    gt_norm = _normalize_expr(gt_expr)
    pred_norm = _normalize_expr(pred_expr)
    if not gt_norm or not pred_norm:
        return False
    if gt_norm == pred_norm:
        return True
    if gt_norm in pred_norm or pred_norm in gt_norm:
        return True
    gt_tokens = set(_expr_tokens(gt_expr))
    pred_tokens = set(_expr_tokens(pred_expr))
    if not gt_tokens or not pred_tokens:
        return False
    common = gt_tokens & pred_tokens
    if len(common) >= max(1, min(len(gt_tokens), len(pred_tokens)) // 2):
        return True
    if any(tok in common for tok in ("count", "len", "length", "size", "wmaxlength", "wtotallength", "bnumendpoints")):
        return True
    return False


def _expr_compatible_many(gt_expr: Any, pred_exprs: Sequence[Any]) -> bool:
    for pred_expr in pred_exprs:
        if _expr_compatible(gt_expr, pred_expr):
            return True
    return False


def _strongest_check_strength(checks: Sequence[Dict[str, Any]]) -> str:
    rank = {"unknown": 0, "weak": 1, "absent": 2, "effective": 3}
    strongest = "unknown"
    best = -1
    for row in checks:
        cur = str(row.get("strength", "unknown") or "unknown").lower()
        if rank.get(cur, -1) > best:
            strongest = cur
            best = rank.get(cur, -1)
    return strongest


def _metric_dict(gt_total: int, pred_total: int, matched_gt: int, used_pred: int) -> Dict[str, Any]:
    fp = max(pred_total - used_pred, 0)
    fn = max(gt_total - matched_gt, 0)
    precision = (matched_gt / pred_total) if pred_total else 0.0
    recall = (matched_gt / gt_total) if gt_total else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "gt_total": gt_total,
        "pred_total": pred_total,
        "matched_gt": matched_gt,
        "used_pred": used_pred,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def _dedup_label_records(records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: set[Tuple[str, Optional[int], str]] = set()
    for row in records:
        key = (
            str(row.get("label", "")),
            _to_int_address(row.get("address")),
            str(row.get("function_name", "") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(dict(row))
    return out


def _iter_verified_labels(pipeline_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for idx, row in enumerate(pipeline_json.get("verified_labels", [])):
        verdict = str(row.get("verdict", "") or "")
        if verdict not in POSITIVE_LABEL_VERDICTS:
            continue
        proposal = row.get("proposal", {}) or {}
        rows.append(
            {
                "index": idx,
                "pack_id": row.get("pack_id"),
                "label": str(row.get("final_label") or proposal.get("label") or ""),
                "address": _to_int_address(proposal.get("address")),
                "function_name": str(proposal.get("function_name") or ""),
                "verdict": verdict,
            }
        )
    return _dedup_label_records(rows)


def _iter_pred_sources(pipeline_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        row for row in _iter_verified_labels(pipeline_json)
        if row["label"] in {"MMIO_READ", "ISR_MMIO_READ", "ISR_FILLED_BUFFER", "DMA_BACKED_BUFFER"}
    ]


def _iter_pred_sinks(pipeline_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        row for row in _iter_verified_labels(pipeline_json)
        if row["label"] not in {"MMIO_READ", "ISR_MMIO_READ", "ISR_FILLED_BUFFER", "DMA_BACKED_BUFFER"}
    ]


def _flatten_pred_roots(sink_roots_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for group in sink_roots_json.get("sink_roots", []):
        for root in group.get("roots", []):
            out.append(
                {
                    "sink_id": group.get("sink_id"),
                    "sink_label": group.get("sink_label"),
                    "sink_function": group.get("sink_function"),
                    "sink_site": group.get("sink_site"),
                    "root_expr": root.get("expr"),
                    "root_role": root.get("role"),
                    "root_kind": root.get("kind"),
                    "root_source": root.get("source") or group.get("root_source"),
                    "canonical_expr": root.get("canonical_expr"),
                    "aliases": list(root.get("aliases", []) or []),
                    "root_family": root.get("family"),
                }
            )
    return out


def _sample_eval_stem(sample: Dict[str, Any]) -> str:
    return str(sample.get("eval_stem") or sample.get("sample_id") or sample["binary_stem"])


def _sample_display_name(sample: Dict[str, Any]) -> str:
    return str(sample.get("sample_id") or sample.get("eval_stem") or sample["binary_stem"])


def _chain_gt_scope(sample: Dict[str, Any]) -> str:
    scope = str(sample.get("chain_gt_scope", "exhaustive") or "exhaustive").lower()
    if scope not in _CHAIN_GT_SCOPES:
        return "exhaustive"
    return scope


def _load_predicted_sample(eval_dir: Path, stem: str) -> Dict[str, Any]:
    raw_results_dir = eval_dir / "raw_results"
    raw_views_dir = eval_dir / "raw_views"
    pipeline_path = raw_results_dir / f"{stem}.pipeline.json"
    channel_path = raw_views_dir / f"{stem}.channel_graph.json"
    sink_roots_path = raw_views_dir / f"{stem}.sink_roots.json"
    chains_path = raw_views_dir / f"{stem}.chains.json"
    chain_eval_path = raw_views_dir / f"{stem}.chain_eval.json"

    out = {
        "present": pipeline_path.exists(),
        "pipeline": _load_json(pipeline_path) if pipeline_path.exists() else {},
        "channel_graph": _load_json(channel_path) if channel_path.exists() else {"object_nodes": [], "channel_edges": []},
        "sink_roots": _load_json(sink_roots_path) if sink_roots_path.exists() else {"sink_roots": []},
        "chains": _load_json(chains_path) if chains_path.exists() else {"chains": []},
        "chain_eval": _load_json(chain_eval_path) if chain_eval_path.exists() else {},
    }
    out["pred_sources"] = _iter_pred_sources(out["pipeline"])
    out["pred_sinks"] = _iter_pred_sinks(out["pipeline"])
    out["pred_objects"] = list(out["channel_graph"].get("object_nodes", []))
    out["pred_channels"] = list(out["channel_graph"].get("channel_edges", []))
    out["pred_roots"] = _flatten_pred_roots(out["sink_roots"])
    out["pred_chains"] = list(out["chains"].get("chains", []))
    return out


def _load_gt_samples(gt_root: Path) -> List[Dict[str, Any]]:
    sample_dir = gt_root / "samples"
    samples: List[Dict[str, Any]] = []
    for path in sorted(sample_dir.glob("*.json")):
        sample = _load_json(path)
        sample["_gt_path"] = str(path)
        samples.append(sample)
    return samples


def _source_match_score(gt: Dict[str, Any], pred: Dict[str, Any]) -> int:
    if gt.get("label") != pred.get("label"):
        return -1
    score = 0
    gt_addr = _to_int_address(gt.get("address"))
    pred_addr = _to_int_address(pred.get("address"))
    strict_mmio = str(gt.get("label", "")).upper() in {"MMIO_READ", "ISR_MMIO_READ"}
    if gt_addr is not None and pred_addr is not None:
        if pred_addr == gt_addr:
            score += 4
        elif not strict_mmio and _addresses_near(pred_addr, gt_addr):
            score += 3
        else:
            return -1
    if _functions_match(str(pred.get("function_name", "")), str(gt.get("function_name", ""))):
        score += 3
    if gt_addr is None and not gt.get("function_name"):
        score += 1
    return score


def _chain_sink_is_compatible(gt_sink: Dict[str, Any], pred_sink: Dict[str, Any]) -> bool:
    label_kind = _sink_label_match_kind(gt_sink, str(pred_sink.get("label", "")))
    if not label_kind:
        return False
    if label_kind in {"exact", "hint"}:
        return True
    gt_addr = _to_int_address(gt_sink.get("address"))
    pred_addr = _to_int_address(pred_sink.get("address"))
    meaningful_addr_match = bool(
        gt_addr not in (None, 0)
        and pred_addr not in (None, 0)
        and _addresses_near(pred_addr, gt_addr)
    )
    return bool(
        _functions_match(str(pred_sink.get("function_name", "")), str(gt_sink.get("function_name", "")))
        or meaningful_addr_match
    )


def _negative_sink_is_compatible(gt_sink: Dict[str, Any], pred_sink: Dict[str, Any]) -> bool:
    gt_addr = _to_int_address(gt_sink.get("address"))
    pred_addr = _to_int_address(pred_sink.get("address"))
    if gt_addr not in (None, 0) and pred_addr not in (None, 0) and pred_addr == gt_addr:
        return True
    return _functions_match(str(pred_sink.get("function_name", "")), str(gt_sink.get("function_name", "")))


def _sink_label_match_kind(gt: Dict[str, Any], pred_label: str) -> str:
    gt_label = str(gt.get("label", ""))
    hint = str(gt.get("pipeline_label_hint", "") or "")
    if pred_label == gt_label:
        return "exact"
    if hint and pred_label == hint:
        return "hint"
    if _sink_family(pred_label) == _sink_family(gt_label):
        return "family"
    return ""


def _sink_match_score(gt: Dict[str, Any], pred: Dict[str, Any]) -> int:
    label_kind = _sink_label_match_kind(gt, str(pred.get("label", "")))
    if not label_kind:
        return -1
    score = {"exact": 6, "hint": 5, "family": 4}[label_kind]
    gt_addr = _to_int_address(gt.get("address"))
    pred_addr = _to_int_address(pred.get("address"))
    if gt_addr is not None and pred_addr is not None:
        if pred_addr == gt_addr:
            score += 4
        elif _addresses_near(pred_addr, gt_addr):
            score += 3
    if _functions_match(str(pred.get("function_name", "")), str(gt.get("function_name", ""))):
        score += 3
    return score


def _range_pair(range_row: Sequence[Any]) -> Optional[Tuple[int, int]]:
    if not range_row or len(range_row) != 2:
        return None
    lo = _to_int_address(range_row[0])
    hi = _to_int_address(range_row[1])
    if lo is None or hi is None:
        return None
    if hi < lo:
        lo, hi = hi, lo
    return (lo, hi)


def _ranges_overlap(a: Sequence[Any], b: Sequence[Any]) -> bool:
    pa = _range_pair(a)
    pb = _range_pair(b)
    if not pa or not pb:
        return False
    return not (pa[1] < pb[0] or pb[1] < pa[0])


def _object_match_score(gt: Dict[str, Any], pred: Dict[str, Any]) -> int:
    score = 0
    gt_members = {str(x).lower() for x in gt.get("members", [])}
    pred_members = {str(x).lower() for x in pred.get("members", [])}
    if gt_members and pred_members:
        overlap = gt_members & pred_members
        if overlap:
            score += 5 + len(overlap)
    if _ranges_overlap(gt.get("addr_range", []), pred.get("addr_range", [])):
        score += 3
    if gt.get("region_kind") == pred.get("region_kind"):
        score += 2
    if set(gt.get("producer_contexts", [])) & set(pred.get("producer_contexts", [])):
        score += 1
    if set(gt.get("consumer_contexts", [])) & set(pred.get("consumer_contexts", [])):
        score += 1
    return score


def _channel_match_score(
    gt: Dict[str, Any],
    pred: Dict[str, Any],
    object_assignment: Dict[str, str],
) -> int:
    gt_obj = gt.get("object_id")
    pred_obj = pred.get("object_id")
    if gt_obj not in object_assignment:
        return -1
    if object_assignment[gt_obj] != pred_obj:
        return -1
    score = 0
    if gt.get("src_context") == pred.get("src_context"):
        score += 3
    if gt.get("dst_context") == pred.get("dst_context"):
        score += 3
    if gt.get("edge_kind") == pred.get("edge_kind"):
        score += 1
    if gt.get("constraints"):
        pred_constraints = pred.get("constraints", [])
        if pred_constraints:
            score += 1
    return score


def _gt_root_family(gt_root: Dict[str, Any]) -> str:
    kind = str(gt_root.get("root_kind", "") or "")
    if kind in _ROOT_KIND_FAMILY:
        return _ROOT_KIND_FAMILY[kind]
    role = str(gt_root.get("root_role", "") or "")
    return _ROOT_ROLE_FAMILY.get(role, role or "unknown")


def _pred_root_family(pred_root: Dict[str, Any]) -> str:
    direct_family = str(pred_root.get("root_family", "") or "")
    if direct_family:
        return direct_family
    kind = str(pred_root.get("root_kind", "") or pred_root.get("active_root_kind", "") or "")
    if kind in _ROOT_KIND_FAMILY:
        return _ROOT_KIND_FAMILY[kind]
    role = str(pred_root.get("root_role", "") or "")
    return _ROOT_ROLE_FAMILY.get(role, role or "unknown")


def _chain_root_family(pred_chain: Dict[str, Any]) -> str:
    debug = pred_chain.get("link_debug", {}) or {}
    kind = str(debug.get("active_root_kind", "") or "")
    if kind in _ROOT_KIND_FAMILY:
        return _ROOT_KIND_FAMILY[kind]
    bundle = list(pred_chain.get("root_bundle", []) or [])
    families = [str(row.get("family", "") or "") for row in bundle if str(row.get("family", "") or "")]
    if families:
        ranked = [fam for fam in families if fam in {"length", "dispatch", "format_arg", "pointer"}]
        if ranked:
            return ranked[0]
        return families[0]
    expr = pred_chain.get("sink", {}).get("root_expr")
    tokens = set(_expr_tokens(expr))
    if tokens & {"len", "length", "count", "size", "num"}:
        return "length"
    if tokens & {"fmt", "format"}:
        return "format_arg"
    if tokens & {"dispatch", "index", "idx"}:
        return "dispatch"
    return "unknown"


def _root_match_score(gt_root: Dict[str, Any], pred_root: Dict[str, Any], gt_sink: Dict[str, Any]) -> int:
    score = 0
    sink_pred = {
        "label": pred_root.get("sink_label"),
        "function_name": pred_root.get("sink_function"),
        "address": _to_int_address(pred_root.get("sink_site")),
    }
    sink_score = _sink_match_score(gt_sink, sink_pred)
    if sink_score < 0:
        return -1
    score += sink_score
    pred_exprs = [
        pred_root.get("root_expr"),
        pred_root.get("canonical_expr"),
        *(pred_root.get("aliases", []) or []),
    ]
    if _expr_compatible_many(gt_root.get("expr"), pred_exprs):
        score += 5
    if _gt_root_family(gt_root) == _pred_root_family(pred_root):
        score += 3
    return score


def _chain_root_exprs(pred_chain: Dict[str, Any]) -> List[str]:
    exprs: List[str] = []

    def _add(value: Any) -> None:
        text = str(value or "").strip()
        if text and text not in exprs:
            exprs.append(text)

    _add(pred_chain.get("sink", {}).get("root_expr"))
    debug = pred_chain.get("link_debug", {}) or {}
    _add(debug.get("active_root_expr"))
    for row in pred_chain.get("root_bundle", []) or []:
        _add(row.get("expr"))
        _add(row.get("canonical_expr"))
        for alias in row.get("aliases", []) or []:
            _add(alias)
    return exprs


def _chain_root_families(pred_chain: Dict[str, Any]) -> set[str]:
    fams = set()
    fam = _chain_root_family(pred_chain)
    if fam:
        fams.add(fam)
    for row in pred_chain.get("root_bundle", []) or []:
        rf = str(row.get("family", "") or "")
        if rf:
            fams.add(rf)
        rk = str(row.get("kind", "") or "")
        if rk in _ROOT_KIND_FAMILY:
            fams.add(_ROOT_KIND_FAMILY[rk])
    return fams


def _chain_source_matches(gt_source: Dict[str, Any], pred_chain: Dict[str, Any]) -> bool:
    for step in pred_chain.get("steps", []):
        if step.get("kind") != "SOURCE":
            continue
        pred = {
            "label": step.get("label"),
            "function_name": step.get("function"),
            "address": _to_int_address(step.get("site")),
        }
        if _source_match_score(gt_source, pred) >= 3:
            return True
    return False


def _chain_sources_match(
    chain_gt: Dict[str, Any],
    gt_source_by_id: Dict[str, Dict[str, Any]],
    pred_chain: Dict[str, Any],
) -> bool:
    required_ids = list(chain_gt.get("required_source_ids", []) or [])
    if not required_ids:
        return True
    mode = str(chain_gt.get("required_source_mode", "all") or "all").lower()
    checks = [
        _chain_source_matches(gt_source_by_id[sid], pred_chain)
        for sid in required_ids
        if sid in gt_source_by_id
    ]
    if not checks:
        return False
    if mode == "any":
        return any(checks)
    return all(checks)


def _chain_object_refs(pred_chain: Dict[str, Any]) -> set[str]:
    refs = set()
    for step in pred_chain.get("steps", []):
        if step.get("kind") == "CHANNEL" and step.get("object_id"):
            refs.add(str(step["object_id"]))
    debug = pred_chain.get("link_debug", {}) or {}
    for oid in debug.get("object_hits", []) or []:
        refs.add(str(oid))
    return refs


def _chain_object_matches(
    gt_object: Dict[str, Any],
    pred_chain: Dict[str, Any],
    object_assignment: Dict[str, str],
    pred_objects_by_id: Dict[str, Dict[str, Any]],
) -> bool:
    pred_obj_refs = _chain_object_refs(pred_chain)
    want_obj = object_assignment.get(gt_object.get("object_id"))
    if want_obj and want_obj in pred_obj_refs:
        return True
    for pred_oid in pred_obj_refs:
        pred_obj = pred_objects_by_id.get(pred_oid)
        if pred_obj and _object_match_score(gt_object, pred_obj) > 0:
            return True
    return False


def _chain_has_required_channel(gt_channel: Dict[str, Any], pred_chain: Dict[str, Any], object_assignment: Dict[str, str]) -> bool:
    want_obj = object_assignment.get(gt_channel.get("object_id"))
    if not want_obj:
        return False
    for step in pred_chain.get("steps", []):
        if step.get("kind") != "CHANNEL":
            continue
        if step.get("object_id") != want_obj:
            continue
        edge = str(step.get("edge", "") or "")
        want_edge = f"{gt_channel.get('src_context')}->{gt_channel.get('dst_context')}"
        if want_edge in edge:
            return True
    return False


def _chain_check_status(gt_derive: Dict[str, Any], pred_chain: Dict[str, Any]) -> Dict[str, Any]:
    pred_checks = pred_chain.get("checks", []) or []
    pred_derive = pred_chain.get("derive_facts", []) or []
    gt_checks = gt_derive.get("check_facts", []) or []
    gt_derive_facts = gt_derive.get("derive_facts", []) or []
    pred_strength = _strongest_check_strength(pred_checks)
    gt_strength = _strongest_check_strength(gt_checks)
    return {
        "derive_present": bool(pred_derive),
        "derive_expected": bool(gt_derive_facts),
        "check_present": bool(pred_checks),
        "check_expected": bool(gt_checks),
        "pred_check_strength": pred_strength,
        "gt_check_strength": gt_strength,
        "check_strength_exact": pred_strength == gt_strength,
    }


def _verdict_status(pred: str, expected: str) -> str:
    if pred == expected:
        return "exact"
    pred_rank = _VERDICT_RANK.get(pred, -1)
    exp_rank = _VERDICT_RANK.get(expected, -1)
    if pred_rank > exp_rank:
        return "over"
    if pred_rank < exp_rank:
        return "under"
    return "mismatch"


def _greedy_assign(
    gt_rows: Sequence[Dict[str, Any]],
    pred_rows: Sequence[Dict[str, Any]],
    scorer,
) -> Tuple[Dict[int, int], List[Dict[str, Any]]]:
    candidates: List[Tuple[int, int, int]] = []
    for gi, gt in enumerate(gt_rows):
        for pi, pred in enumerate(pred_rows):
            score = scorer(gt, pred)
            if score >= 0:
                candidates.append((score, gi, pi))
    candidates.sort(reverse=True)
    gt_to_pred: Dict[int, int] = {}
    used_pred: set[int] = set()
    details: List[Dict[str, Any]] = []
    for score, gi, pi in candidates:
        if gi in gt_to_pred or pi in used_pred:
            continue
        gt_to_pred[gi] = pi
        used_pred.add(pi)
        details.append({"gt_index": gi, "pred_index": pi, "score": score})
    return gt_to_pred, details


def evaluate_sample_artifacts(gt_sample: Dict[str, Any], predicted: Dict[str, Any]) -> Dict[str, Any]:
    stem = gt_sample["binary_stem"]
    eval_stem = _sample_eval_stem(gt_sample)
    display_name = _sample_display_name(gt_sample)
    gt_sources = list(gt_sample.get("sources", []))
    gt_objects = list(gt_sample.get("objects", []))
    gt_channels = list(gt_sample.get("channels", []))
    gt_sinks = list(gt_sample.get("sinks", []))
    gt_roots = list(gt_sample.get("sink_roots", []))
    gt_derives = list(gt_sample.get("derive_checks", []))
    gt_chains = list(gt_sample.get("chains", []))
    gt_negative = list(gt_sample.get("negative_expectations", []))
    chain_scope = _chain_gt_scope(gt_sample)

    pred_sources = list(predicted.get("pred_sources", []))
    pred_sinks = list(predicted.get("pred_sinks", []))
    pred_objects = list(predicted.get("pred_objects", []))
    pred_channels = list(predicted.get("pred_channels", []))
    pred_roots = list(predicted.get("pred_roots", []))
    pred_chains = list(predicted.get("pred_chains", []))

    source_assign, source_details = _greedy_assign(gt_sources, pred_sources, _source_match_score)
    sink_assign, sink_details = _greedy_assign(gt_sinks, pred_sinks, _sink_match_score)
    object_assign_idx, object_details = _greedy_assign(gt_objects, pred_objects, _object_match_score)
    object_assignment = {
        gt_objects[gi]["object_id"]: pred_objects[pi]["object_id"]
        for gi, pi in object_assign_idx.items()
    }
    pred_objects_by_id = {row.get("object_id"): row for row in pred_objects}

    def _channel_scorer(gt: Dict[str, Any], pred: Dict[str, Any]) -> int:
        return _channel_match_score(gt, pred, object_assignment)

    channel_assign, channel_details = _greedy_assign(gt_channels, pred_channels, _channel_scorer)

    gt_sink_by_id = {row["sink_id"]: row for row in gt_sinks}

    def _root_scorer(gt: Dict[str, Any], pred: Dict[str, Any]) -> int:
        return _root_match_score(gt, pred, gt_sink_by_id[gt["sink_id"]])

    root_assign, root_details = _greedy_assign(gt_roots, pred_roots, _root_scorer)
    root_assignment = {
        gt_roots[gi]["root_id"]: pred_roots[pi]
        for gi, pi in root_assign.items()
    }

    derive_rows: List[Dict[str, Any]] = []
    for gi, gt in enumerate(gt_derives):
        root = root_assignment.get(gt.get("root_id"))
        matched_chain = None
        for chain in pred_chains:
            if not _functions_match(str(chain.get("sink", {}).get("function", "")), str(gt_sink_by_id[gt["sink_id"]].get("function_name", ""))):
                continue
            if root and not _expr_compatible(gt_roots[[r["root_id"] for r in gt_roots].index(gt["root_id"])].get("expr"), chain.get("sink", {}).get("root_expr")):
                continue
            matched_chain = chain
            break
        check_status = _chain_check_status(gt, matched_chain or {})
        derive_rows.append(
            {
                "derive_check_id": gt["derive_check_id"],
                "sink_id": gt["sink_id"],
                "root_id": gt["root_id"],
                "matched": bool(matched_chain) and check_status["derive_present"] == check_status["derive_expected"] and (
                    (not check_status["check_expected"]) or check_status["check_present"]
                ),
                "check_status": check_status,
            }
        )

    derive_matched = sum(1 for row in derive_rows if row["matched"])

    gt_source_by_id = {row["source_id"]: row for row in gt_sources}
    gt_object_by_id = {row["object_id"]: row for row in gt_objects}
    gt_channel_by_id = {row["channel_id"]: row for row in gt_channels}
    gt_root_by_id = {row["root_id"]: row for row in gt_roots}
    gt_derive_by_id = {row["derive_check_id"]: row for row in gt_derives}

    used_pred_chain_indices: set[int] = set()
    chain_details: List[Dict[str, Any]] = []
    for chain in gt_chains:
        candidates: List[Tuple[int, int, Dict[str, Any]]] = []
        gt_sink = gt_sink_by_id[chain["sink_id"]]
        gt_required_roots = [gt_root_by_id[rid] for rid in chain.get("required_root_ids", [])]
        gt_required_derives = [gt_derive_by_id[did] for did in chain.get("required_derive_check_ids", [])]
        for pi, pred_chain in enumerate(pred_chains):
            pred_sink = {
                "label": pred_chain.get("sink", {}).get("label"),
                "function_name": pred_chain.get("sink", {}).get("function"),
                "address": _to_int_address(pred_chain.get("sink", {}).get("site")),
            }
            sink_score = _sink_match_score(gt_sink, pred_sink)
            if sink_score < 0 or not _chain_sink_is_compatible(gt_sink, pred_sink):
                continue
            if pred_chain.get("sink", {}).get("sink_id") == chain.get("sink_id"):
                sink_score += 2

            source_ok = _chain_sources_match(chain, gt_source_by_id, pred_chain)

            required_object_ids = list(chain.get("required_object_ids", []) or [])
            optional_object_ids = set(chain.get("optional_object_ids", []) or [])
            object_mode = str(chain.get("required_object_mode", "all") or "all").lower()
            object_checks = [
                _chain_object_matches(gt_object_by_id[oid], pred_chain, object_assignment, pred_objects_by_id)
                for oid in required_object_ids
                if oid in gt_object_by_id and oid not in optional_object_ids
            ]
            if not object_checks:
                object_ok = True
            elif object_mode == "any":
                object_ok = any(object_checks)
            else:
                object_ok = all(object_checks)

            channel_ok = all(
                _chain_has_required_channel(gt_channel_by_id[cid], pred_chain, object_assignment)
                for cid in chain.get("required_channel_ids", [])
            )
            if chain.get("must_use_channel") and not any(step.get("kind") == "CHANNEL" for step in pred_chain.get("steps", [])):
                channel_ok = False

            root_ok = True
            pred_root_exprs = _chain_root_exprs(pred_chain)
            pred_root_families = _chain_root_families(pred_chain)
            for gt_root in gt_required_roots:
                expr_ok = _expr_compatible_many(gt_root.get("expr"), pred_root_exprs)
                family_ok = _gt_root_family(gt_root) in pred_root_families
                if not (expr_ok or family_ok):
                    root_ok = False
                    break

            derive_ok = True
            derive_states = []
            for gt_derive in gt_required_derives:
                state = _chain_check_status(gt_derive, pred_chain)
                derive_states.append(state)
                if gt_derive.get("derive_facts") and not state["derive_present"]:
                    derive_ok = False
                if gt_derive.get("check_facts") and not state["check_present"]:
                    derive_ok = False

            structural_ok = source_ok and object_ok and channel_ok and root_ok and derive_ok
            score = sink_score
            score += 3 if source_ok else -3
            score += 2 if object_ok else -2
            score += 3 if channel_ok else -3 if chain.get("required_channel_ids") or chain.get("must_use_channel") else 0
            score += 3 if root_ok else -3
            score += 2 if derive_ok else -2
            if structural_ok:
                score += 5
            candidates.append(
                (
                    score,
                    pi,
                    {
                        "structural_ok": structural_ok,
                        "source_ok": source_ok,
                        "object_ok": object_ok,
                        "channel_ok": channel_ok,
                        "root_ok": root_ok,
                        "derive_ok": derive_ok,
                        "pred_chain": pred_chain,
                        "derive_states": derive_states,
                    },
                )
            )

        candidates.sort(reverse=True, key=lambda item: (item[0], item[1]))
        match_info: Optional[Dict[str, Any]] = None
        match_index: Optional[int] = None
        for score, pi, info in candidates:
            if pi in used_pred_chain_indices:
                continue
            if info["structural_ok"]:
                match_info = {"score": score, **info}
                match_index = pi
                used_pred_chain_indices.add(pi)
                break
        if match_info is None and candidates:
            score, pi, info = candidates[0]
            match_info = {"score": score, **info}
            match_index = None
        if match_info and match_info["structural_ok"]:
            pred_verdict = str(match_info["pred_chain"].get("verdict", "DROP"))
            verdict_status = _verdict_status(pred_verdict, str(chain.get("expected_verdict", "DROP")))
            used = True
        else:
            pred_verdict = None
            verdict_status = "missing"
            used = False
        chain_details.append(
            {
                "chain_id": chain["chain_id"],
                "sink_id": chain["sink_id"],
                "expected_verdict": chain.get("expected_verdict"),
                "matched": bool(match_info and match_info["structural_ok"]),
                "pred_chain_id": match_info["pred_chain"].get("chain_id") if match_info and match_info.get("pred_chain") else None,
                "pred_verdict": pred_verdict,
                "verdict_status": verdict_status,
                "used_pred_chain": used,
                "must_use_channel": bool(chain.get("must_use_channel")),
                "source_ok": match_info["source_ok"] if match_info else False,
                "object_ok": match_info["object_ok"] if match_info else False,
                "channel_ok": match_info["channel_ok"] if match_info else False,
                "root_ok": match_info["root_ok"] if match_info else False,
                "derive_ok": match_info["derive_ok"] if match_info else False,
            }
        )

    pred_non_drop_indices = {
        idx for idx, chain in enumerate(pred_chains)
        if str(chain.get("verdict", "")) in POSITIVE_CHAIN_VERDICTS
    }
    if chain_scope == "targeted_only":
        spurious_non_drop = []
    else:
        spurious_non_drop = sorted(idx for idx in pred_non_drop_indices if idx not in used_pred_chain_indices)

    # Negative expectations.
    negative_rows: List[Dict[str, Any]] = []
    for neg in gt_negative:
        target_kind = str(neg.get("target_kind", ""))
        violated_by: List[str] = []
        if target_kind == "sample":
            neg_text = f"{neg.get('negative_id', '')} {neg.get('reason', '')}".lower()
            if "no_vuln_chain_expected" in neg_text or "no sink" in neg_text or "source only" in neg_text:
                violated_by = [
                    chain.get("chain_id")
                    for chain in pred_chains
                    if str(chain.get("verdict", "")) in POSITIVE_CHAIN_VERDICTS
                ]
            else:
                violated_by = []
        elif target_kind == "source":
            gt_source = gt_source_by_id.get(neg.get("target_id"))
            for chain in pred_chains:
                if str(chain.get("verdict", "")) not in POSITIVE_CHAIN_VERDICTS:
                    continue
                if gt_source and _chain_source_matches(gt_source, chain):
                    violated_by.append(chain.get("chain_id"))
        elif target_kind == "sink":
            gt_sink = gt_sink_by_id.get(neg.get("target_id"))
            for chain in pred_chains:
                if str(chain.get("verdict", "")) not in POSITIVE_CHAIN_VERDICTS:
                    continue
                pred_sink = {
                    "label": chain.get("sink", {}).get("label"),
                    "function_name": chain.get("sink", {}).get("function"),
                    "address": _to_int_address(chain.get("sink", {}).get("site")),
                }
                if gt_sink and _sink_match_score(gt_sink, pred_sink) >= 0 and _negative_sink_is_compatible(gt_sink, pred_sink):
                    violated_by.append(chain.get("chain_id"))
        elif target_kind == "object":
            pred_oid = object_assignment.get(neg.get("target_id"))
            if pred_oid:
                for chain in pred_chains:
                    if str(chain.get("verdict", "")) not in POSITIVE_CHAIN_VERDICTS:
                        continue
                    if pred_oid in _chain_object_refs(chain):
                        violated_by.append(chain.get("chain_id"))
        negative_rows.append(
            {
                "negative_id": neg.get("negative_id"),
                "target_kind": target_kind,
                "target_id": neg.get("target_id"),
                "expected_verdict": neg.get("expected_verdict"),
                "satisfied": not violated_by,
                "violated_by": violated_by,
            }
        )

    source_report = _metric_dict(len(gt_sources), len(pred_sources), len(source_assign), len(source_assign))
    sink_report = _metric_dict(len(gt_sinks), len(pred_sinks), len(sink_assign), len(sink_assign))
    object_report = _metric_dict(len(gt_objects), len(pred_objects), len(object_assign_idx), len(object_assign_idx))
    channel_report = _metric_dict(len(gt_channels), len(pred_channels), len(channel_assign), len(channel_assign))
    root_report = _metric_dict(len(gt_roots), len(pred_roots), len(root_assign), len(root_assign))
    pred_derive_total = sum(1 for chain in pred_chains if chain.get("derive_facts") or chain.get("checks"))
    derive_report = _metric_dict(len(gt_derives), pred_derive_total, derive_matched, derive_matched)

    chain_positive_total = len(gt_chains)
    chain_matched = sum(1 for row in chain_details if row["matched"])
    verdict_exact = sum(1 for row in chain_details if row["verdict_status"] == "exact")
    verdict_over = sum(1 for row in chain_details if row["verdict_status"] == "over")
    verdict_under = sum(1 for row in chain_details if row["verdict_status"] == "under")
    must_use_channel_total = sum(1 for row in gt_chains if row.get("must_use_channel"))
    must_use_channel_ok = sum(
        1 for row in chain_details if row["must_use_channel"] and row["channel_ok"] and row["matched"]
    )

    negative_total = len(negative_rows)
    negative_satisfied = sum(1 for row in negative_rows if row["satisfied"])

    return {
        "schema_version": SCHEMA_VERSION,
        "binary_stem": stem,
        "eval_stem": eval_stem,
        "sample_id": gt_sample.get("sample_id"),
        "display_name": display_name,
        "sample_present": bool(predicted.get("present")),
        "chain_gt_scope": chain_scope,
        "artifacts": {
            "sources": {**source_report, "matches": source_details},
            "objects": {**object_report, "matches": object_details, "assignment": object_assignment},
            "channels": {**channel_report, "matches": channel_details},
            "sinks": {**sink_report, "matches": sink_details},
            "sink_roots": {**root_report, "matches": root_details},
            "derive_checks": {**derive_report, "details": derive_rows},
        },
        "chains": {
            "positive_total": chain_positive_total,
            "matched": chain_matched,
            "missed": chain_positive_total - chain_matched,
            "verdict_exact": verdict_exact,
            "verdict_over": verdict_over,
            "verdict_under": verdict_under,
            "pred_total": len(pred_chains),
            "pred_non_drop": len(pred_non_drop_indices),
            "spurious_non_drop": len(spurious_non_drop),
            "spurious_chain_ids": [pred_chains[idx].get("chain_id") for idx in spurious_non_drop],
            "must_use_channel_total": must_use_channel_total,
            "must_use_channel_ok": must_use_channel_ok,
            "details": chain_details,
        },
        "negative_expectations": {
            "total": negative_total,
            "satisfied": negative_satisfied,
            "violated": negative_total - negative_satisfied,
            "details": negative_rows,
        },
    }


def _aggregate_metric_rows(rows: Sequence[Dict[str, Any]], key: str) -> Dict[str, Any]:
    gt_total = sum(int(row["artifacts"][key]["gt_total"]) for row in rows)
    pred_total = sum(int(row["artifacts"][key]["pred_total"]) for row in rows)
    matched_gt = sum(int(row["artifacts"][key]["matched_gt"]) for row in rows)
    used_pred = sum(int(row["artifacts"][key]["used_pred"]) for row in rows)
    return _metric_dict(gt_total, pred_total, matched_gt, used_pred)


def _render_markdown(summary: Dict[str, Any], per_sample: Sequence[Dict[str, Any]]) -> str:
    lines = [
        "# Microbench GT v2 Artifact Evaluation",
        "",
        f"- Samples evaluated: {summary['sample_count']}",
        f"- Missing samples: {summary['missing_samples']}",
        f"- Eval dir: `{summary['eval_dir']}`",
        "",
        "## Aggregate",
        "",
        "| Artifact | GT | Pred | Matched | FP | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for key in ("sources", "objects", "channels", "sinks", "sink_roots", "derive_checks"):
        row = summary["artifacts"][key]
        lines.append(
            f"| {key} | {row['gt_total']} | {row['pred_total']} | {row['matched_gt']} | "
            f"{row['fp']} | {row['fn']} | {row['precision']:.3f} | {row['recall']:.3f} | {row['f1']:.3f} |"
        )
    chain = summary["chains"]
    neg = summary["negative_expectations"]
    lines.extend(
        [
            "",
            "## Chains",
            "",
            f"- Positive GT chains: {chain['positive_total']}",
            f"- Matched positive chains: {chain['matched']}",
            f"- Missed positive chains: {chain['missed']}",
            f"- Exact verdict matches: {chain['verdict_exact']}",
            f"- Over-promoted verdicts: {chain['verdict_over']}",
            f"- Under-promoted verdicts: {chain['verdict_under']}",
            f"- Predicted non-drop chains: {chain['pred_non_drop']}",
            f"- Spurious non-drop chains: {chain['spurious_non_drop']}",
            f"- Required-channel chains satisfied: {chain['must_use_channel_ok']}/{chain['must_use_channel_total']}",
            "",
            "## Negative Expectations",
            "",
            f"- Total: {neg['total']}",
            f"- Satisfied: {neg['satisfied']}",
            f"- Violated: {neg['violated']}",
            "",
            "## Per Sample",
            "",
            "| Sample | Sources R | Objects R | Channels R | Roots R | Chains Matched | Spurious+ | Neg Violations |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in per_sample:
        lines.append(
            f"| {row.get('display_name') or row['binary_stem']} | {row['artifacts']['sources']['recall']:.3f} | "
            f"{row['artifacts']['objects']['recall']:.3f} | {row['artifacts']['channels']['recall']:.3f} | "
            f"{row['artifacts']['sink_roots']['recall']:.3f} | {row['chains']['matched']}/{row['chains']['positive_total']} | "
            f"{row['chains']['spurious_non_drop']} | {row['negative_expectations']['violated']} |"
        )
    lines.append("")
    return "\n".join(lines)


def evaluate_microbench_v2_run(
    eval_dir: Path,
    *,
    gt_root: Optional[Path] = None,
    output_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    gt_root = gt_root or (_repo_root() / "firmware" / "ground_truth_bundle" / "microbench_v2")
    output_dir = output_dir or (eval_dir / "summary")

    gt_samples = _load_gt_samples(gt_root)
    per_sample: List[Dict[str, Any]] = []
    missing: List[str] = []
    for sample in sorted(gt_samples, key=lambda row: _sample_display_name(row)):
        eval_stem = _sample_eval_stem(sample)
        predicted = _load_predicted_sample(eval_dir, eval_stem)
        report = evaluate_sample_artifacts(sample, predicted)
        per_sample.append(report)
        if not report["sample_present"]:
            missing.append(eval_stem)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "eval_dir": str(eval_dir),
        "gt_root": str(gt_root),
        "sample_count": len(per_sample),
        "missing_samples": len(missing),
        "missing_sample_stems": missing,
        "artifacts": {
            key: _aggregate_metric_rows(per_sample, key)
            for key in ("sources", "objects", "channels", "sinks", "sink_roots", "derive_checks")
        },
        "chains": {
            "positive_total": sum(row["chains"]["positive_total"] for row in per_sample),
            "matched": sum(row["chains"]["matched"] for row in per_sample),
            "missed": sum(row["chains"]["missed"] for row in per_sample),
            "verdict_exact": sum(row["chains"]["verdict_exact"] for row in per_sample),
            "verdict_over": sum(row["chains"]["verdict_over"] for row in per_sample),
            "verdict_under": sum(row["chains"]["verdict_under"] for row in per_sample),
            "pred_total": sum(row["chains"]["pred_total"] for row in per_sample),
            "pred_non_drop": sum(row["chains"]["pred_non_drop"] for row in per_sample),
            "spurious_non_drop": sum(row["chains"]["spurious_non_drop"] for row in per_sample),
            "must_use_channel_total": sum(row["chains"]["must_use_channel_total"] for row in per_sample),
            "must_use_channel_ok": sum(row["chains"]["must_use_channel_ok"] for row in per_sample),
        },
        "negative_expectations": {
            "total": sum(row["negative_expectations"]["total"] for row in per_sample),
            "satisfied": sum(row["negative_expectations"]["satisfied"] for row in per_sample),
            "violated": sum(row["negative_expectations"]["violated"] for row in per_sample),
        },
    }

    _dump_json(output_dir / "artifact_eval_summary.json", summary)
    _dump_json(output_dir / "artifact_eval_by_sample.json", {"samples": per_sample})
    (output_dir / "artifact_eval_report.md").write_text(
        _render_markdown(summary, per_sample),
        encoding="utf-8",
    )
    return {
        "summary": summary,
        "per_sample": per_sample,
        "output_dir": str(output_dir),
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate microbench GT v2 artifacts against an eval run directory.")
    parser.add_argument("eval_dir", type=Path, help="Evaluation run directory containing raw_results/ and raw_views/")
    parser.add_argument("--gt-root", type=Path, default=None, help="GT v2 root directory")
    parser.add_argument("--output-dir", type=Path, default=None, help="Output directory (default: <eval_dir>/summary)")
    args = parser.parse_args(argv)

    report = evaluate_microbench_v2_run(
        args.eval_dir,
        gt_root=args.gt_root,
        output_dir=args.output_dir,
    )
    print(json.dumps(report["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
