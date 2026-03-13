"""Paired parity harness for stripped vs. unstripped eval runs."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .microbench_gt_v2_eval import (
    POSITIVE_CHAIN_VERDICTS,
    _chain_root_exprs,
    _chain_root_families,
    _dump_json,
    _expr_compatible_many,
    _flatten_pred_roots,
    _greedy_assign,
    _load_json,
    _load_predicted_sample,
    _metric_dict,
    _root_match_score,
    _sink_match_score,
    _source_match_score,
    _to_int_address,
    _verdict_status,
)


SCHEMA_VERSION = "0.1"


def _load_manifest_samples(manifest_path: Path) -> List[Dict[str, Any]]:
    raw = _load_json(manifest_path)
    if isinstance(raw, dict):
        samples = raw.get("samples", [])
    elif isinstance(raw, list):
        samples = raw
    else:
        raise ValueError(f"unsupported manifest format: {type(raw)}")

    if not isinstance(samples, list):
        raise ValueError("manifest 'samples' must be a list")

    out: List[Dict[str, Any]] = []
    for item in samples:
        if isinstance(item, dict):
            out.append(dict(item))
    return out


def _strip_suffix(text: str, suffix: str) -> str:
    if text.endswith(suffix):
        return text[: -len(suffix)]
    return text


def _derive_unstripped_stem(sample: Dict[str, Any]) -> str:
    direct = str(sample.get("unstripped_output_stem", "") or "").strip()
    if direct:
        return direct

    raw_path = str(sample.get("unstripped_binary_path", "") or "").strip()
    if raw_path:
        return Path(raw_path).stem

    sample_id = str(sample.get("sample_id", "") or "").strip()
    if sample_id:
        return sample_id

    gt_stem = str(sample.get("gt_stem", "") or "").strip()
    if gt_stem:
        return gt_stem

    output_stem = str(sample.get("output_stem", "") or "").strip()
    if output_stem:
        return _strip_suffix(output_stem, "_stripped")

    binary_path = str(sample.get("binary_path", "") or "").strip()
    if binary_path:
        return _strip_suffix(Path(binary_path).stem, "_stripped")
    return ""


def _derive_stripped_stem(sample: Dict[str, Any]) -> str:
    direct = str(sample.get("stripped_output_stem", "") or "").strip()
    if direct:
        return direct

    output_stem = str(sample.get("output_stem", "") or "").strip()
    if output_stem:
        return output_stem

    raw_path = str(sample.get("stripped_binary_path", "") or sample.get("binary_path", "") or "").strip()
    if raw_path:
        return Path(raw_path).stem

    sample_id = str(sample.get("sample_id", "") or "").strip()
    if sample_id:
        return f"{sample_id}_stripped"
    return ""


def _positive_chains(predicted: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        dict(row)
        for row in predicted.get("pred_chains", [])
        if str(row.get("verdict", "") or "") in POSITIVE_CHAIN_VERDICTS
    ]


def _verdict_counter(chains: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts = Counter(str(row.get("verdict", "") or "") for row in chains)
    return {key: int(counts.get(key, 0)) for key in sorted(counts)}


def _sample_counts(predicted: Dict[str, Any]) -> Dict[str, Any]:
    positive = _positive_chains(predicted)
    return {
        "verified_sources": len(predicted.get("pred_sources", [])),
        "verified_sinks": len(predicted.get("pred_sinks", [])),
        "objects": len(predicted.get("pred_objects", [])),
        "channels": len(predicted.get("pred_channels", [])),
        "sink_roots": len(predicted.get("pred_roots", [])),
        "chains_total": len(predicted.get("pred_chains", [])),
        "positive_chains": len(positive),
        "positive_chain_verdicts": _verdict_counter(positive),
    }


def _root_parity_score(reference_root: Dict[str, Any], stripped_root: Dict[str, Any]) -> int:
    gt_root = {
        "expr": reference_root.get("root_expr"),
        "root_kind": reference_root.get("root_kind"),
        "root_role": reference_root.get("root_role"),
    }
    gt_sink = {
        "label": reference_root.get("sink_label"),
        "function_name": reference_root.get("sink_function"),
        "address": _to_int_address(reference_root.get("sink_site")),
    }
    return _root_match_score(gt_root, stripped_root, gt_sink)


def _chain_source_steps(chain: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for step in chain.get("steps", []) or []:
        if step.get("kind") != "SOURCE":
            continue
        out.append(
            {
                "label": step.get("label"),
                "address": _to_int_address(step.get("site")),
                "function_name": step.get("function"),
            }
        )
    return out


def _chain_channel_steps(chain: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for step in chain.get("steps", []) or []:
        if step.get("kind") == "CHANNEL":
            edge = str(step.get("edge", "") or "")
            if edge:
                out.append(edge)
    return out


def _chain_sink_payload(chain: Dict[str, Any]) -> Dict[str, Any]:
    sink = chain.get("sink", {}) or {}
    return {
        "label": sink.get("label"),
        "function_name": sink.get("function"),
        "address": _to_int_address(sink.get("site")),
    }


def _chain_parity_score(reference_chain: Dict[str, Any], stripped_chain: Dict[str, Any]) -> int:
    sink_score = _sink_match_score(_chain_sink_payload(reference_chain), _chain_sink_payload(stripped_chain))
    if sink_score < 0:
        return -1

    score = sink_score

    ref_sources = _chain_source_steps(reference_chain)
    stripped_sources = _chain_source_steps(stripped_chain)
    if ref_sources and stripped_sources:
        source_matches = 0
        for ref_step in ref_sources:
            best = max((_source_match_score(ref_step, test_step) for test_step in stripped_sources), default=-1)
            if best >= 3:
                source_matches += 1
        if source_matches:
            score += 2 + source_matches
        else:
            score -= 2

    ref_root_exprs = _chain_root_exprs(reference_chain)
    stripped_root_exprs = _chain_root_exprs(stripped_chain)
    if ref_root_exprs and stripped_root_exprs:
        root_expr_ok = any(
            _expr_compatible_many(ref_expr, stripped_root_exprs)
            for ref_expr in ref_root_exprs
        )
        if root_expr_ok:
            score += 3
        else:
            score -= 2

    ref_root_families = _chain_root_families(reference_chain)
    stripped_root_families = _chain_root_families(stripped_chain)
    if ref_root_families and stripped_root_families:
        if ref_root_families & stripped_root_families:
            score += 2
        else:
            score -= 1

    ref_channels = set(_chain_channel_steps(reference_chain))
    stripped_channels = set(_chain_channel_steps(stripped_chain))
    if ref_channels and stripped_channels:
        if ref_channels & stripped_channels:
            score += 1
        else:
            score -= 1
    elif bool(ref_channels) == bool(stripped_channels):
        score += 1

    if bool(reference_chain.get("derive_facts")) == bool(stripped_chain.get("derive_facts")):
        score += 1
    if bool(reference_chain.get("checks")) == bool(stripped_chain.get("checks")):
        score += 1

    return score


def _chain_parity_metrics(
    reference_chains: Sequence[Dict[str, Any]],
    stripped_chains: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    assignment, details = _greedy_assign(reference_chains, stripped_chains, _chain_parity_score)
    used_pred = len(assignment)
    metrics = _metric_dict(len(reference_chains), len(stripped_chains), len(assignment), used_pred)

    verdict_exact = 0
    verdict_over = 0
    verdict_under = 0
    matched_pairs: List[Dict[str, Any]] = []
    for ref_idx, stripped_idx in assignment.items():
        ref_chain = reference_chains[ref_idx]
        stripped_chain = stripped_chains[stripped_idx]
        verdict_state = _verdict_status(
            str(stripped_chain.get("verdict", "") or "DROP"),
            str(ref_chain.get("verdict", "") or "DROP"),
        )
        if verdict_state == "exact":
            verdict_exact += 1
        elif verdict_state == "over":
            verdict_over += 1
        elif verdict_state == "under":
            verdict_under += 1
        matched_pairs.append(
            {
                "reference_chain_id": ref_chain.get("chain_id"),
                "stripped_chain_id": stripped_chain.get("chain_id"),
                "reference_verdict": ref_chain.get("verdict"),
                "stripped_verdict": stripped_chain.get("verdict"),
                "verdict_status": verdict_state,
            }
        )

    metrics.update(
        {
            "verdict_exact": verdict_exact,
            "verdict_over": verdict_over,
            "verdict_under": verdict_under,
            "details": details,
            "matched_pairs": matched_pairs,
        }
    )
    return metrics


def evaluate_stripped_parity_sample(
    sample: Dict[str, Any],
    *,
    stripped_eval_dir: Path,
    unstripped_eval_dir: Path,
) -> Dict[str, Any]:
    stripped_stem = _derive_stripped_stem(sample)
    unstripped_stem = _derive_unstripped_stem(sample)
    stripped_pred = _load_predicted_sample(stripped_eval_dir, stripped_stem)
    unstripped_pred = _load_predicted_sample(unstripped_eval_dir, unstripped_stem)

    ref_sinks = list(unstripped_pred.get("pred_sinks", []))
    test_sinks = list(stripped_pred.get("pred_sinks", []))
    sink_assign, sink_details = _greedy_assign(ref_sinks, test_sinks, _sink_match_score)
    sink_parity = _metric_dict(len(ref_sinks), len(test_sinks), len(sink_assign), len(sink_assign))
    sink_parity["matches"] = sink_details

    ref_roots = _flatten_pred_roots(unstripped_pred.get("sink_roots", {"sink_roots": []}))
    test_roots = _flatten_pred_roots(stripped_pred.get("sink_roots", {"sink_roots": []}))
    root_assign, root_details = _greedy_assign(ref_roots, test_roots, _root_parity_score)
    root_parity = _metric_dict(len(ref_roots), len(test_roots), len(root_assign), len(root_assign))
    root_parity["matches"] = root_details

    chain_parity = _chain_parity_metrics(
        _positive_chains(unstripped_pred),
        _positive_chains(stripped_pred),
    )

    ref_counts = _sample_counts(unstripped_pred)
    stripped_counts = _sample_counts(stripped_pred)

    return {
        "sample_id": str(sample.get("sample_id", "") or sample.get("gt_stem", "") or stripped_stem),
        "dataset": str(sample.get("dataset", "") or ""),
        "gt_stem": str(sample.get("gt_stem", "") or ""),
        "reference_eval_stem": unstripped_stem,
        "stripped_eval_stem": stripped_stem,
        "reference_present": bool(unstripped_pred.get("present")),
        "stripped_present": bool(stripped_pred.get("present")),
        "reference_counts": ref_counts,
        "stripped_counts": stripped_counts,
        "parity": {
            "sinks": sink_parity,
            "sink_roots": root_parity,
            "positive_chains": chain_parity,
        },
        "deltas": {
            "verified_sources": stripped_counts["verified_sources"] - ref_counts["verified_sources"],
            "verified_sinks": stripped_counts["verified_sinks"] - ref_counts["verified_sinks"],
            "sink_roots": stripped_counts["sink_roots"] - ref_counts["sink_roots"],
            "positive_chains": stripped_counts["positive_chains"] - ref_counts["positive_chains"],
        },
    }


def _aggregate_counts(rows: Sequence[Dict[str, Any]], key: str) -> Dict[str, Any]:
    acc = Counter()
    verdicts = Counter()
    for row in rows:
        cur = row.get(key, {}) or {}
        for name in ("verified_sources", "verified_sinks", "objects", "channels", "sink_roots", "chains_total", "positive_chains"):
            acc[name] += int(cur.get(name, 0) or 0)
        for verdict, count in (cur.get("positive_chain_verdicts", {}) or {}).items():
            verdicts[verdict] += int(count)
    out = {name: int(acc.get(name, 0)) for name in sorted(acc)}
    out["positive_chain_verdicts"] = {name: int(verdicts.get(name, 0)) for name in sorted(verdicts)}
    return out


def _aggregate_metric_rows(rows: Sequence[Dict[str, Any]], metric_key: str) -> Dict[str, Any]:
    gt_total = sum(int(row["parity"][metric_key]["gt_total"]) for row in rows)
    pred_total = sum(int(row["parity"][metric_key]["pred_total"]) for row in rows)
    matched_gt = sum(int(row["parity"][metric_key]["matched_gt"]) for row in rows)
    used_pred = sum(int(row["parity"][metric_key]["used_pred"]) for row in rows)
    return _metric_dict(gt_total, pred_total, matched_gt, used_pred)


def evaluate_stripped_parity_run(
    stripped_eval_dir: Path,
    *,
    unstripped_eval_dir: Path,
    manifest_path: Path,
    output_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    samples = _load_manifest_samples(manifest_path)
    rows = [
        evaluate_stripped_parity_sample(
            sample,
            stripped_eval_dir=stripped_eval_dir,
            unstripped_eval_dir=unstripped_eval_dir,
        )
        for sample in samples
    ]

    output_dir = output_dir or (stripped_eval_dir / "summary" / "stripped_parity")

    sinks_summary = _aggregate_metric_rows(rows, "sinks")
    roots_summary = _aggregate_metric_rows(rows, "sink_roots")
    chains_summary = _aggregate_metric_rows(rows, "positive_chains")
    chains_summary.update(
        {
            "verdict_exact": sum(int(row["parity"]["positive_chains"]["verdict_exact"]) for row in rows),
            "verdict_over": sum(int(row["parity"]["positive_chains"]["verdict_over"]) for row in rows),
            "verdict_under": sum(int(row["parity"]["positive_chains"]["verdict_under"]) for row in rows),
        }
    )

    reference_counts = _aggregate_counts(rows, "reference_counts")
    stripped_counts = _aggregate_counts(rows, "stripped_counts")

    summary = {
        "schema_version": SCHEMA_VERSION,
        "manifest_path": str(manifest_path),
        "reference_eval_dir": str(unstripped_eval_dir),
        "stripped_eval_dir": str(stripped_eval_dir),
        "sample_count": len(rows),
        "complete_pairs": sum(
            1 for row in rows if row.get("reference_present") and row.get("stripped_present")
        ),
        "missing_reference_samples": [
            row["sample_id"] for row in rows if not row.get("reference_present")
        ],
        "missing_stripped_samples": [
            row["sample_id"] for row in rows if not row.get("stripped_present")
        ],
        "counts": {
            "reference": reference_counts,
            "stripped": stripped_counts,
            "delta": {
                "verified_sources": int(stripped_counts.get("verified_sources", 0)) - int(reference_counts.get("verified_sources", 0)),
                "verified_sinks": int(stripped_counts.get("verified_sinks", 0)) - int(reference_counts.get("verified_sinks", 0)),
                "sink_roots": int(stripped_counts.get("sink_roots", 0)) - int(reference_counts.get("sink_roots", 0)),
                "positive_chains": int(stripped_counts.get("positive_chains", 0)) - int(reference_counts.get("positive_chains", 0)),
            },
        },
        "parity": {
            "sinks": sinks_summary,
            "sink_roots": roots_summary,
            "positive_chains": chains_summary,
        },
    }

    _dump_json(output_dir / "stripped_parity_summary.json", summary)
    _dump_json(output_dir / "stripped_parity_by_sample.json", {"samples": rows})
    (output_dir / "stripped_parity_report.md").write_text(
        render_markdown(summary, rows),
        encoding="utf-8",
    )
    return {"summary": summary, "samples": rows, "output_dir": str(output_dir)}


def render_markdown(summary: Dict[str, Any], rows: Sequence[Dict[str, Any]]) -> str:
    lines = [
        "# Stripped Parity Report",
        "",
        f"- Samples: {summary['sample_count']}",
        f"- Complete pairs: {summary['complete_pairs']}",
        f"- Reference eval dir: `{summary['reference_eval_dir']}`",
        f"- Stripped eval dir: `{summary['stripped_eval_dir']}`",
        "",
        "## Aggregate Parity",
        "",
        "| Metric | Ref | Stripped | Matched | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for key, label in (
        ("sinks", "verified sinks"),
        ("sink_roots", "sink roots"),
        ("positive_chains", "positive chains"),
    ):
        row = summary["parity"][key]
        lines.append(
            f"| {label} | {row['gt_total']} | {row['pred_total']} | {row['matched_gt']} | "
            f"{row['precision']:.3f} | {row['recall']:.3f} | {row['f1']:.3f} |"
        )
    lines.extend(
        [
            "",
            "## Stage Delta",
            "",
            f"- Verified sink delta: {summary['counts']['delta']['verified_sinks']}",
            f"- Sink root delta: {summary['counts']['delta']['sink_roots']}",
            f"- Positive chain delta: {summary['counts']['delta']['positive_chains']}",
            f"- Chain verdict exact/over/under: "
            f"{summary['parity']['positive_chains']['verdict_exact']}/"
            f"{summary['parity']['positive_chains']['verdict_over']}/"
            f"{summary['parity']['positive_chains']['verdict_under']}",
            "",
            "## Per Sample",
            "",
            "| Sample | Ref sinks | Stripped sinks | Sink recall | Root recall | Chain recall | Chain verdict |",
            "|---|---:|---:|---:|---:|---:|---|",
        ]
    )
    for row in rows:
        chain = row["parity"]["positive_chains"]
        lines.append(
            f"| {row['sample_id']} | {row['reference_counts']['verified_sinks']} | "
            f"{row['stripped_counts']['verified_sinks']} | {row['parity']['sinks']['recall']:.3f} | "
            f"{row['parity']['sink_roots']['recall']:.3f} | {chain['recall']:.3f} | "
            f"{chain['verdict_exact']}/{chain['verdict_over']}/{chain['verdict_under']} |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Compare stripped eval output against unstripped reference runs.")
    parser.add_argument("stripped_eval_dir", type=Path, help="Eval directory for stripped binaries")
    parser.add_argument("--unstripped-eval-dir", type=Path, required=True, help="Eval directory for unstripped reference binaries")
    parser.add_argument("--manifest-json", type=Path, required=True, help="Stripped manifest with peer metadata")
    parser.add_argument("--output-dir", type=Path, default=None, help="Output directory (default: <stripped_eval_dir>/summary/stripped_parity)")
    args = parser.parse_args(argv)

    report = evaluate_stripped_parity_run(
        args.stripped_eval_dir,
        unstripped_eval_dir=args.unstripped_eval_dir,
        manifest_path=args.manifest_json,
        output_dir=args.output_dir,
    )
    print(json.dumps(report["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
