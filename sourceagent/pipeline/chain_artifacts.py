"""Phase-A chain artifact builders.

This module materializes the frozen JSON contracts for:
  - channel_graph.json
  - refined_objects.json
  - sink_roots.json
  - chains.json
  - chain_eval.json
  - low_conf_sinks.json
  - triage_queue.json
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .channel_graph import build_channel_graph
from .linker.sink_roots import extract_sink_roots
from .linker.triage_queue import build_low_conf_sinks, build_triage_queue
from .linker.tunnel_linker import link_chains, summarize_chain_eval
from .verdict_calibration import (
    DEFAULT_ALLOW_MANUAL_LLM_SUPERVISION,
    DEFAULT_CALIBRATION_MODE,
    DEFAULT_LLM_DEMOTE_BUDGET,
    DEFAULT_LLM_PROMOTE_BUDGET,
    DEFAULT_LLM_SOFT_BUDGET,
    DEFAULT_MAX_CALIBRATION_CHAINS,
    DEFAULT_MIN_RISK_SCORE,
    DEFAULT_REVIEW_NEEDS_THRESHOLD,
    DEFAULT_SAMPLE_SUSPICIOUS_RATIO_THRESHOLD,
    DEFAULT_VERDICT_OUTPUT_MODE,
    build_verdict_calibration_artifacts,
)
from .models import PipelineResult, SinkLabel, SourceLabel, VerificationVerdict
from .object_refine import refine_object_boundaries


SCHEMA_VERSION = "0.1"

DEFAULT_T_LOW = 0.45
DEFAULT_TOP_K = 3
DEFAULT_BUDGET = 160
DEFAULT_TUNNEL_K = 2
DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_CHAINS_PER_SINK = 4
DEFAULT_MAX_CHAINS_PER_BINARY = 200
DEFAULT_CALIBRATION_MAX_CHAINS = DEFAULT_MAX_CALIBRATION_CHAINS

SINK_LABELS = {
    SinkLabel.COPY_SINK.value,
    SinkLabel.MEMSET_SINK.value,
    SinkLabel.STORE_SINK.value,
    SinkLabel.LOOP_WRITE_SINK.value,
    SinkLabel.FORMAT_STRING_SINK.value,
    SinkLabel.FUNC_PTR_SINK.value,
}

SOURCE_LABELS = {
    SourceLabel.MMIO_READ.value,
    SourceLabel.ISR_MMIO_READ.value,
    SourceLabel.ISR_FILLED_BUFFER.value,
    SourceLabel.DMA_BACKED_BUFFER.value,
}


def build_phase_a_artifacts(
    result: PipelineResult,
    *,
    max_stage: int = 10,
    t_low: float = DEFAULT_T_LOW,
    top_k: int = DEFAULT_TOP_K,
    budget: int = DEFAULT_BUDGET,
    tunnel_k: int = DEFAULT_TUNNEL_K,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_chains_per_sink: int = DEFAULT_MAX_CHAINS_PER_SINK,
    max_chains_per_binary: int = DEFAULT_MAX_CHAINS_PER_BINARY,
    calibration_mode: str = DEFAULT_CALIBRATION_MODE,
    verdict_output_mode: str = DEFAULT_VERDICT_OUTPUT_MODE,
    max_calibration_chains: int = DEFAULT_MAX_CALIBRATION_CHAINS,
    sample_suspicious_ratio_threshold: float = DEFAULT_SAMPLE_SUSPICIOUS_RATIO_THRESHOLD,
    min_risk_score: float = DEFAULT_MIN_RISK_SCORE,
    review_needs_threshold: float = DEFAULT_REVIEW_NEEDS_THRESHOLD,
    allow_manual_llm_supervision: bool = DEFAULT_ALLOW_MANUAL_LLM_SUPERVISION,
    llm_promote_budget: int = DEFAULT_LLM_PROMOTE_BUDGET,
    llm_demote_budget: int = DEFAULT_LLM_DEMOTE_BUDGET,
    llm_soft_budget: int = DEFAULT_LLM_SOFT_BUDGET,
    review_decisions: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    """Build all phase-A artifacts from the current pipeline result."""
    max_stage = int(max_stage or 10)
    binary_path = str(result.binary_path or "")
    binary_name = Path(binary_path).name or binary_path
    binary_stem = Path(binary_path).stem
    binary_sha256 = _file_sha256(binary_path)

    verified_sources, verified_sinks = _collect_verified_labels(result)

    channel_graph = _empty_channel_graph(binary_name, binary_sha256)
    refined_objects = _empty_refined_objects(binary_name, binary_sha256)
    sink_roots = _empty_sink_roots(binary_name, binary_sha256, t_low=t_low)
    chains = _empty_chains(
        binary_name,
        binary_sha256,
        budget=budget,
        tunnel_k=tunnel_k,
        max_depth=max_depth,
        max_chains_per_sink=max_chains_per_sink,
        max_chains_per_binary=max_chains_per_binary,
    )
    chain_eval = _empty_chain_eval(binary_name, binary_sha256)
    low_conf_sinks = _empty_low_conf(binary_name, binary_sha256)
    triage_queue = _empty_triage(binary_name, binary_sha256, top_k=top_k)
    verdict_feature_pack = _empty_verdict_feature_pack(binary_name, binary_sha256, calibration_mode=calibration_mode, verdict_output_mode=verdict_output_mode)
    verdict_calibration_queue = _empty_verdict_calibration_queue(binary_name, binary_sha256, calibration_mode=calibration_mode, verdict_output_mode=verdict_output_mode)
    verdict_calibration_decisions = _empty_verdict_calibration_decisions(binary_name, binary_sha256, calibration_mode=calibration_mode, verdict_output_mode=verdict_output_mode)
    verdict_audit_flags = _empty_verdict_audit_flags(binary_name, binary_sha256)
    verdict_soft_triage = _empty_verdict_soft_triage(binary_name, binary_sha256, calibration_mode=calibration_mode, verdict_output_mode=verdict_output_mode)

    if max_stage >= 8:
        channel_graph = build_channel_graph(
            mai=getattr(result, "_mai", None),
            verified_labels=verified_sources,
            memory_map=getattr(result, "memory_map", None),
            top_k=top_k,
            binary_sha256=binary_sha256,
        )
        channel_graph = {
            **channel_graph,
            "status": "ok",
            "stage_required": 8,
        }

        refined_objects = {
            "schema_version": channel_graph.get("schema_version", SCHEMA_VERSION),
            "binary": channel_graph.get("binary", binary_name),
            "binary_sha256": channel_graph.get("binary_sha256", binary_sha256),
            "objects": _refine_objects(list(channel_graph.get("object_nodes", []))),
            "status": "ok",
            "stage_required": 8,
        }

    sink_facts_by_pack = _pack_facts_by_pack_id(result)
    sink_roots_rows: List[Dict[str, Any]] = []
    chains_rows: List[Dict[str, Any]] = []
    low_conf_items: List[Dict[str, Any]] = []

    if max_stage >= 9:
        sink_roots_rows = extract_sink_roots(
            verified_sinks,
            sink_facts_by_pack=sink_facts_by_pack,
            binary_stem=binary_stem,
            decompiled_cache=getattr(getattr(result, "_mai", None), "decompiled_cache", None),
        )
        sink_roots = {
            "schema_version": SCHEMA_VERSION,
            "binary": binary_name,
            "binary_sha256": binary_sha256,
            "sink_roots": sink_roots_rows,
            "params": {
                "t_low": float(t_low),
            },
            "status": "ok",
            "stage_required": 9,
        }

        chains_rows = link_chains(
            sink_roots_rows,
            channel_graph,
            mai=getattr(result, "_mai", None),
            sources=verified_sources,
            sink_facts_by_pack=sink_facts_by_pack,
            sink_pack_id_by_site=_sink_pack_id_by_site(result),
            binary_stem=binary_stem,
            budget=budget,
            K=tunnel_k,
            max_depth=max_depth,
            max_chains_per_sink=max_chains_per_sink,
            max_chains_per_binary=max_chains_per_binary,
        )
        chains = {
            "schema_version": SCHEMA_VERSION,
            "binary": binary_name,
            "binary_sha256": binary_sha256,
            "chains": chains_rows,
            "params": {
                "budget": int(budget),
                "tunnel_k": int(tunnel_k),
                "max_depth": int(max_depth),
                "max_chains_per_sink": int(max_chains_per_sink),
                "max_chains_per_binary": int(max_chains_per_binary),
            },
            "status": "ok",
            "stage_required": 9,
        }

        chain_eval = {
            "schema_version": SCHEMA_VERSION,
            "binary": binary_name,
            "binary_sha256": binary_sha256,
            "stats": summarize_chain_eval(chains_rows),
            "by_verdict": _count_by_key(chains_rows, "verdict"),
            "by_status": _count_by_key(chains_rows, "status"),
            "by_failure_code": _count_by_key(chains_rows, "failure_code", skip_empty=True),
            "status": "ok",
            "stage_required": 9,
        }

    if max_stage >= 10:
        low_conf_items = build_low_conf_sinks(chains_rows, t_low=t_low)
        low_conf_sinks = {
            "schema_version": SCHEMA_VERSION,
            "binary": binary_name,
            "binary_sha256": binary_sha256,
            "items": low_conf_items,
            "status": "ok",
            "stage_required": 10,
        }

        triage_queue = {
            "schema_version": SCHEMA_VERSION,
            "binary": binary_name,
            "binary_sha256": binary_sha256,
            "top_k": int(top_k),
            "items": build_triage_queue(low_conf_items, top_k=top_k),
            "status": "ok",
            "stage_required": 10,
        }

        verdict_artifacts = build_verdict_calibration_artifacts(
            binary_name=binary_name,
            binary_sha256=binary_sha256,
            chains=chains_rows,
            channel_graph=channel_graph,
            sink_facts_by_pack=sink_facts_by_pack,
            sink_pack_id_by_site=_sink_pack_id_by_site(result),
            decompiled_cache=getattr(getattr(result, "_mai", None), "decompiled_cache", None),
            calibration_mode=calibration_mode,
            verdict_output_mode=verdict_output_mode,
            max_calibration_chains=max_calibration_chains,
            sample_suspicious_ratio_threshold=sample_suspicious_ratio_threshold,
            min_risk_score=min_risk_score,
            review_needs_threshold=review_needs_threshold,
            allow_manual_llm_supervision=allow_manual_llm_supervision,
            llm_promote_budget=llm_promote_budget,
            llm_demote_budget=llm_demote_budget,
            llm_soft_budget=llm_soft_budget,
            review_decisions=review_decisions or [],
        )
        verdict_feature_pack = verdict_artifacts.get("verdict_feature_pack", verdict_feature_pack)
        verdict_calibration_queue = verdict_artifacts.get("verdict_calibration_queue", verdict_calibration_queue)
        verdict_calibration_decisions = verdict_artifacts.get("verdict_calibration_decisions", verdict_calibration_decisions)
        verdict_audit_flags = verdict_artifacts.get("verdict_audit_flags", verdict_audit_flags)
        verdict_soft_triage = verdict_artifacts.get("verdict_soft_triage", verdict_soft_triage)

    return {
        "channel_graph": channel_graph,
        "refined_objects": refined_objects,
        "sink_roots": sink_roots,
        "chains": chains,
        "chain_eval": chain_eval,
        "low_conf_sinks": low_conf_sinks,
        "triage_queue": triage_queue,
        "verdict_feature_pack": verdict_feature_pack,
        "verdict_calibration_queue": verdict_calibration_queue,
        "verdict_calibration_decisions": verdict_calibration_decisions,
        "verdict_audit_flags": verdict_audit_flags,
        "verdict_soft_triage": verdict_soft_triage,
    }


def _empty_verdict_feature_pack(binary_name: str, binary_sha256: str, *, calibration_mode: str, verdict_output_mode: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "mode": calibration_mode,
        "output_mode": verdict_output_mode,
        "items": [],
        "status": "not_run",
        "stage_required": 10,
    }


def _empty_verdict_calibration_queue(binary_name: str, binary_sha256: str, *, calibration_mode: str, verdict_output_mode: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "mode": calibration_mode,
        "output_mode": verdict_output_mode,
        "items": [],
        "status": "not_run",
        "stage_required": 10,
    }


def _empty_verdict_calibration_decisions(binary_name: str, binary_sha256: str, *, calibration_mode: str, verdict_output_mode: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "mode": calibration_mode,
        "output_mode": verdict_output_mode,
        "items": [],
        "status": "not_run",
        "stage_required": 10,
    }


def _empty_verdict_audit_flags(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "items": [],
        "status": "not_run",
        "stage_required": 10,
    }


def _empty_verdict_soft_triage(binary_name: str, binary_sha256: str, *, calibration_mode: str, verdict_output_mode: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "mode": calibration_mode,
        "output_mode": verdict_output_mode,
        "items": [],
        "stats": {},
        "status": "not_run",
        "stage_required": 10,
    }


def _empty_channel_graph(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "object_nodes": [],
        "channel_edges": [],
        "status": "not_run",
        "stage_required": 8,
    }


def _empty_refined_objects(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "objects": [],
        "status": "not_run",
        "stage_required": 8,
    }


def _empty_sink_roots(binary_name: str, binary_sha256: str, *, t_low: float) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "sink_roots": [],
        "params": {"t_low": float(t_low)},
        "status": "not_run",
        "stage_required": 9,
    }


def _empty_chains(
    binary_name: str,
    binary_sha256: str,
    *,
    budget: int,
    tunnel_k: int,
    max_depth: int,
    max_chains_per_sink: int,
    max_chains_per_binary: int,
) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "chains": [],
        "params": {
            "budget": int(budget),
            "tunnel_k": int(tunnel_k),
            "max_depth": int(max_depth),
            "max_chains_per_sink": int(max_chains_per_sink),
            "max_chains_per_binary": int(max_chains_per_binary),
        },
        "status": "not_run",
        "stage_required": 9,
    }


def _empty_chain_eval(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "stats": {
            "chain_count": 0,
            "with_source": 0,
            "with_channel": 0,
            "confirmed": 0,
            "suspicious": 0,
            "safe_or_low_risk": 0,
            "dropped": 0,
        },
        "by_verdict": {},
        "by_status": {},
        "status": "not_run",
        "stage_required": 9,
    }


def _empty_low_conf(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "items": [],
        "status": "not_run",
        "stage_required": 10,
    }


def _empty_triage(binary_name: str, binary_sha256: str, *, top_k: int) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "top_k": int(top_k),
        "items": [],
        "status": "not_run",
        "stage_required": 10,
    }


def _collect_verified_labels(
    result: PipelineResult,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    accepted = {VerificationVerdict.VERIFIED, VerificationVerdict.PARTIAL}
    sources: List[Dict[str, Any]] = []
    sinks: List[Dict[str, Any]] = []

    for vl in getattr(result, "verified_labels", []):
        if vl.verdict not in accepted:
            continue
        label = str(vl.final_label or vl.proposal.label or "")
        if not label:
            continue
        facts: Dict[str, Any] = {}
        for claim in getattr(vl.proposal, "claims", []) or []:
            if isinstance(claim, dict):
                facts.update(claim)
        item = {
            "pack_id": str(vl.pack_id or ""),
            "label": label,
            "address": int(vl.proposal.address or 0),
            "function_name": str(vl.proposal.function_name or ""),
            "verdict": str(vl.verdict.value),
            "confidence": float(vl.proposal.confidence or 0.0),
            "evidence_refs": [str(x) for x in (vl.proposal.evidence_refs or [])],
            "facts": facts,
        }
        if label in SOURCE_LABELS:
            sources.append(item)
        elif label in SINK_LABELS:
            sinks.append(item)

    return sources, sinks


def _refine_objects(object_nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    for obj in object_nodes:
        item = dict(obj)
        item.setdefault("members", [])
        tf = dict(item.get("type_facts", {}))
        tf.setdefault("refine_status", "coarse")
        item["type_facts"] = tf
        normalized.append(item)
    return refine_object_boundaries(normalized, ())


def _pack_facts_by_pack_id(result: PipelineResult) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for pack in getattr(result, "evidence_packs", []):
        out[str(pack.pack_id)] = dict(pack.facts or {})
    return out


def _sink_pack_id_by_site(result: PipelineResult) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for vl in getattr(result, "verified_labels", []):
        label = str(vl.final_label or vl.proposal.label or "")
        if label not in SINK_LABELS:
            continue
        key = f"{_hex_addr(vl.proposal.address)}|{vl.proposal.function_name or ''}|{label}"
        out[key] = str(vl.pack_id or "")
    return out


def _count_by_key(rows: List[Dict[str, Any]], key: str, *, skip_empty: bool = False) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for row in rows:
        v = str(row.get(key, ""))
        if skip_empty and not v:
            continue
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: kv[0]))


def _hex_addr(v: Any) -> str:
    try:
        n = int(v or 0)
    except Exception:
        n = 0
    return f"0x{n:08x}"


def _file_sha256(path: str) -> str:
    try:
        p = Path(path)
        if not p.exists() or not p.is_file():
            return ""
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""
