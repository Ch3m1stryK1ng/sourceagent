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
import copy
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from .channel_graph import build_channel_graph
from .linker.sink_roots import extract_sink_roots
from .linker.triage_queue import build_low_conf_sinks, build_triage_queue
from .linker.tunnel_linker import link_chains, summarize_chain_eval
from .supervision_queue import DEFAULT_SUPERVISION_SCOPE, build_supervision_queue
from .supervision_merge import apply_supervision_merge
from .verdict_calibration import (
    DEFAULT_ALLOW_MANUAL_LLM_SUPERVISION,
    DEFAULT_CALIBRATION_MODE,
    DEFAULT_LLM_DEMOTE_BUDGET,
    DEFAULT_LLM_PROMOTE_BUDGET,
    DEFAULT_LLM_SOFT_BUDGET,
    DEFAULT_MAX_CALIBRATION_CHAINS,
    DEFAULT_MIN_RISK_SCORE,
    DEFAULT_REVIEW_ALLOW_SOFT_ON_STRUCTURAL_GAP,
    DEFAULT_REVIEW_PRESERVE_REJECTED_RATIONALE,
    DEFAULT_REVIEW_SOFT_GATES,
    DEFAULT_REVIEW_STRICT_GATES,
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
DEFAULT_BUDGET = 320
DEFAULT_TUNNEL_K = 3
DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_CHAINS_PER_SINK = 6
DEFAULT_MAX_CHAINS_PER_BINARY = 400
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
    review_strict_gates: Sequence[str] = DEFAULT_REVIEW_STRICT_GATES,
    review_soft_gates: Sequence[str] = DEFAULT_REVIEW_SOFT_GATES,
    review_allow_soft_on_structural_gap: bool = DEFAULT_REVIEW_ALLOW_SOFT_ON_STRUCTURAL_GAP,
    review_preserve_rejected_rationale: bool = DEFAULT_REVIEW_PRESERVE_REJECTED_RATIONALE,
    has_ground_truth: bool | None = None,
    review_decisions: List[Dict[str, Any]] | None = None,
    review_plan: Dict[str, Any] | None = None,
    review_trace: Dict[str, Any] | None = None,
    supervision_queue: Dict[str, Any] | None = None,
    supervision_decisions: List[Dict[str, Any]] | None = None,
    supervision_prompt: Dict[str, Any] | None = None,
    supervision_raw_response: Dict[str, Any] | None = None,
    supervision_session: Dict[str, Any] | None = None,
    supervision_trace: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Build all phase-A artifacts from the current pipeline result."""
    max_stage = int(max_stage or 10)
    binary_path = str(result.binary_path or "")
    binary_name = Path(binary_path).name or binary_path
    binary_stem = Path(binary_path).stem
    binary_sha256 = _file_sha256(binary_path)
    if has_ground_truth is None:
        has_ground_truth = bool(getattr(result, "_has_ground_truth", False))

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
    verdict_review_plan = _empty_verdict_review_plan(binary_name, binary_sha256)
    verdict_review_prompt = _empty_verdict_review_prompt(binary_name, binary_sha256)
    verdict_review_raw_response = _empty_verdict_review_raw_response(binary_name, binary_sha256)
    verdict_review_session = _empty_verdict_review_session(binary_name, binary_sha256)
    verdict_review_trace = _empty_verdict_review_trace(binary_name, binary_sha256)
    supervision_queue_artifact = _empty_supervision_queue(binary_name, binary_sha256)
    supervision_decisions_artifact = _empty_supervision_decisions(binary_name, binary_sha256)
    supervision_prompt_artifact = _empty_supervision_prompt(binary_name, binary_sha256)
    supervision_raw_response_artifact = _empty_supervision_raw_response(binary_name, binary_sha256)
    supervision_session_artifact = _empty_supervision_session(binary_name, binary_sha256)
    supervision_trace_artifact = _empty_supervision_trace(binary_name, binary_sha256)
    supervision_merge_artifact = _empty_supervision_merge(binary_name, binary_sha256)
    verified_enriched_artifact = _empty_verified_enriched(binary_name, binary_sha256)
    objects_enriched_artifact = _empty_objects_enriched(binary_name, binary_sha256)
    channels_enriched_artifact = _empty_channels_enriched(binary_name, binary_sha256)

    if max_stage >= 8:
        channel_graph, refined_objects = _build_stage8_artifacts(
            result=result,
            verified_sources=verified_sources,
            binary_name=binary_name,
            binary_sha256=binary_sha256,
            top_k=top_k,
        )

    sink_facts_by_pack = _pack_facts_by_pack_id(result)
    sink_pack_id_by_site = _sink_pack_id_by_site(result, verified_sinks=verified_sinks)
    sink_roots_rows: List[Dict[str, Any]] = []
    chains_rows: List[Dict[str, Any]] = []
    low_conf_items: List[Dict[str, Any]] = []

    if max_stage >= 9:
        sink_roots_rows, sink_roots, chains_rows, chains, chain_eval = _build_stage9_artifacts(
            result=result,
            verified_sources=verified_sources,
            verified_sinks=verified_sinks,
            sink_facts_by_pack=sink_facts_by_pack,
            sink_pack_id_by_site=sink_pack_id_by_site,
            channel_graph=channel_graph,
            binary_name=binary_name,
            binary_sha256=binary_sha256,
            binary_stem=binary_stem,
            t_low=t_low,
            budget=budget,
            tunnel_k=tunnel_k,
            max_depth=max_depth,
            max_chains_per_sink=max_chains_per_sink,
            max_chains_per_binary=max_chains_per_binary,
        )

    if max_stage >= 10:
        (
            low_conf_items,
            low_conf_sinks,
            triage_queue,
            verdict_feature_pack,
            verdict_calibration_queue,
            verdict_calibration_decisions,
            verdict_audit_flags,
            verdict_soft_triage,
        ) = _build_stage10_artifacts(
            result=result,
            chains_rows=chains_rows,
            channel_graph=channel_graph,
            sink_facts_by_pack=sink_facts_by_pack,
            sink_pack_id_by_site=sink_pack_id_by_site,
            binary_name=binary_name,
            binary_sha256=binary_sha256,
            t_low=t_low,
            top_k=top_k,
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
            review_strict_gates=review_strict_gates,
            review_soft_gates=review_soft_gates,
            review_allow_soft_on_structural_gap=review_allow_soft_on_structural_gap,
            review_preserve_rejected_rationale=review_preserve_rejected_rationale,
            has_ground_truth=bool(has_ground_truth),
            review_decisions=review_decisions or [],
        )
        if supervision_queue is not None:
            supervision_queue_artifact = dict(supervision_queue or {})
            supervision_queue_artifact.setdefault("binary", binary_name)
            supervision_queue_artifact.setdefault("binary_sha256", binary_sha256)
            supervision_queue_artifact.setdefault("scope", DEFAULT_SUPERVISION_SCOPE)
            supervision_queue_artifact.setdefault("stage_required", 10)
        else:
            supervision_queue_artifact = build_supervision_queue(
                binary_name=binary_name,
                binary_sha256=binary_sha256,
                low_conf_sinks=low_conf_items,
                triage_queue=(triage_queue or {}).get("items", []) or [],
                feature_pack=verdict_feature_pack,
                verified_sinks=verified_sinks,
                sink_facts_by_pack=sink_facts_by_pack,
                verified_sources=verified_sources,
                source_candidates=_normalize_source_candidates(getattr(result, "source_candidates", []) or []),
                sink_candidates=_normalize_sink_candidates(getattr(result, "sink_candidates", []) or []),
                sink_evidence_packs=_normalize_sink_evidence_packs(getattr(result, "evidence_packs", []) or []),
                decompiled_cache=getattr(getattr(result, "_mai", None), "decompiled_cache", {}) or {},
                channel_graph=channel_graph,
                refined_objects=refined_objects,
                max_items=0,
                scope=DEFAULT_SUPERVISION_SCOPE,
            )
            supervision_queue_artifact["status"] = "not_run"
            supervision_queue_artifact["stage_required"] = 10
        if supervision_decisions is not None:
            supervision_decisions_artifact = {
                "schema_version": SCHEMA_VERSION,
                "binary": binary_name,
                "binary_sha256": binary_sha256,
                "items": list(supervision_decisions or []),
                "status": "ok" if list(supervision_decisions or []) else "empty",
                "stage_required": 10,
            }
        if supervision_prompt is not None:
            supervision_prompt_artifact = dict(supervision_prompt or {})
            supervision_prompt_artifact.setdefault("binary", binary_name)
            supervision_prompt_artifact.setdefault("binary_sha256", binary_sha256)
            supervision_prompt_artifact.setdefault("stage_required", 10)
        if supervision_raw_response is not None:
            supervision_raw_response_artifact = dict(supervision_raw_response or {})
            supervision_raw_response_artifact.setdefault("binary", binary_name)
            supervision_raw_response_artifact.setdefault("binary_sha256", binary_sha256)
            supervision_raw_response_artifact.setdefault("stage_required", 10)
        if supervision_session is not None:
            supervision_session_artifact = dict(supervision_session or {})
            supervision_session_artifact.setdefault("binary", binary_name)
            supervision_session_artifact.setdefault("binary_sha256", binary_sha256)
            supervision_session_artifact.setdefault("stage_required", 10)
        if supervision_trace is not None:
            supervision_trace_artifact = dict(supervision_trace or {})
            supervision_trace_artifact.setdefault("binary", binary_name)
            supervision_trace_artifact.setdefault("binary_sha256", binary_sha256)
            supervision_trace_artifact.setdefault("stage_required", 10)
        if supervision_decisions_artifact.get("items"):
            merge_outputs = apply_supervision_merge(
                binary_name=binary_name,
                binary_sha256=binary_sha256,
                supervision_queue=supervision_queue_artifact,
                supervision_decisions=(supervision_decisions_artifact.get("items", []) or []),
            )
            supervision_merge_artifact = dict(merge_outputs.get("supervision_merge", {}) or supervision_merge_artifact)
            supervision_merge_artifact.setdefault("binary", binary_name)
            supervision_merge_artifact.setdefault("binary_sha256", binary_sha256)
            supervision_merge_artifact.setdefault("stage_required", 10)
            verified_enriched_artifact = dict(merge_outputs.get("verified_enriched", {}) or verified_enriched_artifact)
            verified_enriched_artifact.setdefault("binary", binary_name)
            verified_enriched_artifact.setdefault("binary_sha256", binary_sha256)
            verified_enriched_artifact.setdefault("stage_required", 10)
            objects_enriched_artifact = dict(merge_outputs.get("objects_enriched", {}) or objects_enriched_artifact)
            objects_enriched_artifact.setdefault("binary", binary_name)
            objects_enriched_artifact.setdefault("binary_sha256", binary_sha256)
            objects_enriched_artifact.setdefault("stage_required", 10)
            channels_enriched_artifact = dict(merge_outputs.get("channels_enriched", {}) or channels_enriched_artifact)
            channels_enriched_artifact.setdefault("binary", binary_name)
            channels_enriched_artifact.setdefault("binary_sha256", binary_sha256)
            channels_enriched_artifact.setdefault("stage_required", 10)

            augmented_sources, source_feedback_count = _augment_verified_sources(
                verified_sources,
                (verified_enriched_artifact.get("items", []) or []),
            )
            (
                augmented_sinks,
                augmented_sink_facts,
                sink_feedback_count,
            ) = _augment_verified_sinks(
                verified_sinks,
                (verified_enriched_artifact.get("items", []) or []),
                sink_facts_by_pack=sink_facts_by_pack,
            )
            object_feedback_count = int((objects_enriched_artifact.get("stats", {}) or {}).get("count", 0) or 0)
            channel_feedback_count = int((channels_enriched_artifact.get("stats", {}) or {}).get("count", 0) or 0)
            if source_feedback_count > 0:
                verified_sources = augmented_sources
                if max_stage >= 8:
                    channel_graph, refined_objects = _build_stage8_artifacts(
                        result=result,
                        verified_sources=verified_sources,
                        binary_name=binary_name,
                        binary_sha256=binary_sha256,
                        top_k=top_k,
                    )
            if sink_feedback_count > 0:
                verified_sinks = augmented_sinks
                sink_facts_by_pack = augmented_sink_facts
                sink_pack_id_by_site = _sink_pack_id_by_site(result, verified_sinks=verified_sinks)
            if (object_feedback_count > 0 or channel_feedback_count > 0) and max_stage >= 8:
                channel_graph, refined_objects = _augment_stage8_from_supervision(
                    channel_graph=channel_graph,
                    refined_objects=refined_objects,
                    objects_enriched=(objects_enriched_artifact.get("items", []) or []),
                    channels_enriched=(channels_enriched_artifact.get("items", []) or []),
                    binary_name=binary_name,
                    binary_sha256=binary_sha256,
                )
            if source_feedback_count > 0 or sink_feedback_count > 0 or object_feedback_count > 0 or channel_feedback_count > 0:
                if max_stage >= 9:
                    sink_roots_rows, sink_roots, chains_rows, chains, chain_eval = _build_stage9_artifacts(
                        result=result,
                        verified_sources=verified_sources,
                        verified_sinks=verified_sinks,
                        sink_facts_by_pack=sink_facts_by_pack,
                        sink_pack_id_by_site=sink_pack_id_by_site,
                        channel_graph=channel_graph,
                        binary_name=binary_name,
                        binary_sha256=binary_sha256,
                        binary_stem=binary_stem,
                        t_low=t_low,
                        budget=budget,
                        tunnel_k=tunnel_k,
                        max_depth=max_depth,
                        max_chains_per_sink=max_chains_per_sink,
                        max_chains_per_binary=max_chains_per_binary,
                    )
                if max_stage >= 10:
                    (
                        low_conf_items,
                        low_conf_sinks,
                        triage_queue,
                        verdict_feature_pack,
                        verdict_calibration_queue,
                        verdict_calibration_decisions,
                        verdict_audit_flags,
                        verdict_soft_triage,
                    ) = _build_stage10_artifacts(
                        result=result,
                        chains_rows=chains_rows,
                        channel_graph=channel_graph,
                        sink_facts_by_pack=sink_facts_by_pack,
                        sink_pack_id_by_site=sink_pack_id_by_site,
                        binary_name=binary_name,
                        binary_sha256=binary_sha256,
                        t_low=t_low,
                        top_k=top_k,
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
                        review_strict_gates=review_strict_gates,
                        review_soft_gates=review_soft_gates,
                        review_allow_soft_on_structural_gap=review_allow_soft_on_structural_gap,
                        review_preserve_rejected_rationale=review_preserve_rejected_rationale,
                        has_ground_truth=bool(has_ground_truth),
                        review_decisions=review_decisions or [],
                    )
                for artifact in (channel_graph, refined_objects, sink_roots, chains, chain_eval, low_conf_sinks, triage_queue, verdict_feature_pack, verdict_calibration_queue, verdict_calibration_decisions, verdict_audit_flags, verdict_soft_triage):
                    if isinstance(artifact, dict):
                        artifact.setdefault("feedback_applied", {})
                        artifact["feedback_applied"]["source_supervision"] = source_feedback_count
                        artifact["feedback_applied"]["sink_supervision"] = sink_feedback_count
                        artifact["feedback_applied"]["object_supervision"] = object_feedback_count
                        artifact["feedback_applied"]["channel_supervision"] = channel_feedback_count

    if max_stage >= 10:
        if review_plan is not None:
            verdict_review_plan = dict(review_plan)
            verdict_review_plan.setdefault("binary", binary_name)
            verdict_review_plan.setdefault("binary_sha256", binary_sha256)
            verdict_review_plan.setdefault("stage_required", 10)
        if isinstance(review_plan, dict):
            if isinstance(review_plan.get("review_prompt"), dict):
                verdict_review_prompt = dict(review_plan.get("review_prompt") or {})
                verdict_review_prompt.setdefault("binary", binary_name)
                verdict_review_prompt.setdefault("binary_sha256", binary_sha256)
                verdict_review_prompt.setdefault("stage_required", 10)
            if isinstance(review_plan.get("review_raw_response"), dict):
                verdict_review_raw_response = dict(review_plan.get("review_raw_response") or {})
                verdict_review_raw_response.setdefault("binary", binary_name)
                verdict_review_raw_response.setdefault("binary_sha256", binary_sha256)
                verdict_review_raw_response.setdefault("stage_required", 10)
            if isinstance(review_plan.get("review_session"), dict):
                verdict_review_session = dict(review_plan.get("review_session") or {})
                verdict_review_session.setdefault("binary", binary_name)
                verdict_review_session.setdefault("binary_sha256", binary_sha256)
                verdict_review_session.setdefault("stage_required", 10)
        if review_trace is not None:
            verdict_review_trace = dict(review_trace)
            verdict_review_trace.setdefault("binary", binary_name)
            verdict_review_trace.setdefault("binary_sha256", binary_sha256)
            verdict_review_trace.setdefault("stage_required", 10)

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
        "verdict_review_plan": verdict_review_plan,
        "verdict_review_prompt": verdict_review_prompt,
        "verdict_review_raw_response": verdict_review_raw_response,
        "verdict_review_session": verdict_review_session,
        "verdict_review_trace": verdict_review_trace,
        "supervision_queue": supervision_queue_artifact,
        "supervision_decisions": supervision_decisions_artifact,
        "supervision_prompt": supervision_prompt_artifact,
        "supervision_raw_response": supervision_raw_response_artifact,
        "supervision_session": supervision_session_artifact,
        "supervision_trace": supervision_trace_artifact,
        "supervision_merge": supervision_merge_artifact,
        "verified_enriched": verified_enriched_artifact,
        "objects_enriched": objects_enriched_artifact,
        "channels_enriched": channels_enriched_artifact,
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


def _empty_verdict_review_plan(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "items": [],
        "batches": [],
        "status": "not_run",
        "stage_required": 10,
    }



def _empty_verdict_review_prompt(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "batches": [],
        "status": "not_run",
        "stage_required": 10,
    }


def _empty_verdict_review_raw_response(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "batches": [],
        "status": "not_run",
        "stage_required": 10,
    }


def _empty_verdict_review_session(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "batches": [],
        "status": "not_run",
        "stage_required": 10,
    }

def _empty_verdict_review_trace(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "batches": [],
        "status": "not_run",
        "stage_required": 10,
    }


def _empty_supervision_queue(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "scope": DEFAULT_SUPERVISION_SCOPE,
        "items": [],
        "status": "not_run",
        "stage_required": 10,
    }


def _empty_supervision_decisions(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "items": [],
        "status": "not_run",
        "stage_required": 10,
    }


def _empty_supervision_prompt(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "items": [],
        "batches": [],
        "status": "not_run",
        "stage_required": 10,
    }


def _empty_supervision_raw_response(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "items": [],
        "batches": [],
        "status": "not_run",
        "stage_required": 10,
    }


def _empty_supervision_session(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "items": [],
        "batches": [],
        "status": "not_run",
        "stage_required": 10,
    }


def _empty_supervision_trace(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "items": [],
        "batches": [],
        "status": "not_run",
        "stage_required": 10,
    }


def _empty_supervision_merge(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "items": [],
        "stats": {},
        "status": "not_run",
        "stage_required": 10,
    }


def _empty_verified_enriched(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "items": [],
        "stats": {},
        "status": "not_run",
        "stage_required": 10,
    }


def _empty_objects_enriched(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "items": [],
        "stats": {},
        "status": "not_run",
        "stage_required": 10,
    }


def _empty_channels_enriched(binary_name: str, binary_sha256: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "items": [],
        "stats": {},
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


def _build_stage8_artifacts(
    *,
    result: PipelineResult,
    verified_sources: Sequence[Dict[str, Any]],
    binary_name: str,
    binary_sha256: str,
    top_k: int,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    mai = getattr(result, "_mai", None)
    memory_map = getattr(result, "memory_map", None)
    channel_graph = build_channel_graph(
        mai,
        verified_sources,
        memory_map,
        top_k=top_k,
        binary_sha256=binary_sha256,
    )
    channel_graph.setdefault("schema_version", SCHEMA_VERSION)
    channel_graph.setdefault("binary", binary_name)
    channel_graph.setdefault("binary_sha256", binary_sha256)
    channel_graph["status"] = "ok"
    channel_graph["stage_required"] = 8

    refined_rows = _refine_objects((channel_graph.get("object_nodes", []) or []))
    refined_objects = {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "objects": refined_rows,
        "status": "ok",
        "stage_required": 8,
    }
    return channel_graph, refined_objects


def _build_stage9_artifacts(
    *,
    result: PipelineResult,
    verified_sources: Sequence[Dict[str, Any]],
    verified_sinks: Sequence[Dict[str, Any]],
    sink_facts_by_pack: Mapping[str, Dict[str, Any]],
    sink_pack_id_by_site: Mapping[str, str],
    channel_graph: Mapping[str, Any],
    binary_name: str,
    binary_sha256: str,
    binary_stem: str,
    t_low: float,
    budget: int,
    tunnel_k: int,
    max_depth: int,
    max_chains_per_sink: int,
    max_chains_per_binary: int,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], List[Dict[str, Any]], Dict[str, Any], Dict[str, Any]]:
    mai = getattr(result, "_mai", None)
    decompiled_cache = getattr(mai, "decompiled_cache", {}) or {}
    sink_roots_rows = extract_sink_roots(
        list(verified_sinks or []),
        sink_facts_by_pack=sink_facts_by_pack,
        binary_stem=binary_stem,
        decompiled_cache=decompiled_cache,
    )
    sink_roots = {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "sink_roots": sink_roots_rows,
        "params": {"t_low": float(t_low)},
        "status": "ok",
        "stage_required": 9,
    }

    chains_rows = link_chains(
        sink_roots_rows,
        channel_graph,
        mai,
        list(verified_sources or []),
        sink_facts_by_pack=sink_facts_by_pack,
        sink_pack_id_by_site=dict(sink_pack_id_by_site or {}),
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
    stats = summarize_chain_eval(chains_rows)
    chain_eval = {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "stats": stats,
        "by_verdict": _count_by_key(chains_rows, "verdict", skip_empty=True),
        "by_status": _count_by_key(chains_rows, "status", skip_empty=True),
        "by_failure_code": _count_by_key(chains_rows, "failure_code", skip_empty=True),
        "status": "ok",
        "stage_required": 9,
    }
    return sink_roots_rows, sink_roots, chains_rows, chains, chain_eval


def _augment_stage8_from_supervision(
    *,
    channel_graph: Mapping[str, Any],
    refined_objects: Mapping[str, Any],
    objects_enriched: Sequence[Mapping[str, Any]],
    channels_enriched: Sequence[Mapping[str, Any]],
    binary_name: str,
    binary_sha256: str,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    graph = copy.deepcopy(dict(channel_graph or {}))
    refined = copy.deepcopy(dict(refined_objects or {}))
    object_nodes = [dict(row or {}) for row in (graph.get("object_nodes", []) or [])]
    refined_rows = [dict(row or {}) for row in (refined.get("objects", []) or [])]
    nodes_by_id = {str(row.get("object_id", "") or ""): row for row in object_nodes if str(row.get("object_id", "") or "")}
    refined_by_id = {str(row.get("object_id", "") or ""): row for row in refined_rows if str(row.get("object_id", "") or "")}

    for item in objects_enriched or []:
        _merge_supervision_object(
            item=item,
            nodes_by_id=nodes_by_id,
            refined_by_id=refined_by_id,
            object_nodes=object_nodes,
            refined_rows=refined_rows,
        )

    channel_edges = [dict(row or {}) for row in (graph.get("channel_edges", []) or [])]
    edge_keys = {
        (
            str(edge.get("object_id", "") or ""),
            str(edge.get("src_context", "") or ""),
            str(edge.get("dst_context", "") or ""),
            str(edge.get("edge_kind", "") or "DATA"),
        ): edge
        for edge in channel_edges
        if str(edge.get("object_id", "") or "")
    }
    for item in channels_enriched or []:
        _merge_supervision_channel(
            item=item,
            edge_keys=edge_keys,
            channel_edges=channel_edges,
            nodes_by_id=nodes_by_id,
            refined_by_id=refined_by_id,
            object_nodes=object_nodes,
            refined_rows=refined_rows,
        )

    graph["object_nodes"] = object_nodes
    graph["channel_edges"] = channel_edges
    graph.setdefault("schema_version", SCHEMA_VERSION)
    graph.setdefault("binary", binary_name)
    graph.setdefault("binary_sha256", binary_sha256)
    graph.setdefault("status", "ok")
    graph.setdefault("stage_required", 8)

    refined["objects"] = refined_rows
    refined.setdefault("schema_version", SCHEMA_VERSION)
    refined.setdefault("binary", binary_name)
    refined.setdefault("binary_sha256", binary_sha256)
    refined.setdefault("status", "ok")
    refined.setdefault("stage_required", 8)
    return graph, refined


def _build_stage10_artifacts(
    *,
    result: PipelineResult,
    chains_rows: Sequence[Dict[str, Any]],
    channel_graph: Mapping[str, Any],
    sink_facts_by_pack: Mapping[str, Dict[str, Any]],
    sink_pack_id_by_site: Mapping[str, str],
    binary_name: str,
    binary_sha256: str,
    t_low: float,
    top_k: int,
    calibration_mode: str,
    verdict_output_mode: str,
    max_calibration_chains: int,
    sample_suspicious_ratio_threshold: float,
    min_risk_score: float,
    review_needs_threshold: float,
    allow_manual_llm_supervision: bool,
    llm_promote_budget: int,
    llm_demote_budget: int,
    llm_soft_budget: int,
    review_strict_gates: Sequence[str],
    review_soft_gates: Sequence[str],
    review_allow_soft_on_structural_gap: bool,
    review_preserve_rejected_rationale: bool,
    has_ground_truth: bool,
    review_decisions: Sequence[Dict[str, Any]],
) -> Tuple[
    List[Dict[str, Any]],
    Dict[str, Any],
    Dict[str, Any],
    Dict[str, Any],
    Dict[str, Any],
    Dict[str, Any],
    Dict[str, Any],
    Dict[str, Any],
]:
    low_conf_items = build_low_conf_sinks(list(chains_rows or []), t_low=t_low)
    low_conf_sinks = {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "items": low_conf_items,
        "status": "ok",
        "stage_required": 10,
    }
    triage_items = build_triage_queue(low_conf_items, top_k=top_k)
    triage_queue = {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "top_k": int(top_k),
        "items": triage_items,
        "status": "ok",
        "stage_required": 10,
    }

    verdict_outputs = build_verdict_calibration_artifacts(
        binary_name=binary_name,
        binary_sha256=binary_sha256,
        chains=list(chains_rows or []),
        channel_graph=channel_graph,
        sink_facts_by_pack=sink_facts_by_pack,
        sink_pack_id_by_site=dict(sink_pack_id_by_site or {}),
        decompiled_cache=getattr(getattr(result, "_mai", None), "decompiled_cache", {}) or {},
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
        review_strict_gates=review_strict_gates,
        review_soft_gates=review_soft_gates,
        review_allow_soft_on_structural_gap=review_allow_soft_on_structural_gap,
        review_preserve_rejected_rationale=review_preserve_rejected_rationale,
        has_ground_truth=bool(has_ground_truth),
        review_decisions=list(review_decisions or []),
    )
    verdict_feature_pack = dict(verdict_outputs.get("verdict_feature_pack", {}) or {})
    verdict_feature_pack.setdefault("binary", binary_name)
    verdict_feature_pack.setdefault("binary_sha256", binary_sha256)
    verdict_feature_pack["status"] = "ok"
    verdict_feature_pack["stage_required"] = 10

    verdict_calibration_queue = dict(verdict_outputs.get("verdict_calibration_queue", {}) or {})
    verdict_calibration_queue.setdefault("binary", binary_name)
    verdict_calibration_queue.setdefault("binary_sha256", binary_sha256)
    verdict_calibration_queue["status"] = "ok"
    verdict_calibration_queue["stage_required"] = 10

    verdict_calibration_decisions = dict(verdict_outputs.get("verdict_calibration_decisions", {}) or {})
    verdict_calibration_decisions.setdefault("binary", binary_name)
    verdict_calibration_decisions.setdefault("binary_sha256", binary_sha256)
    verdict_calibration_decisions["status"] = "ok"
    verdict_calibration_decisions["stage_required"] = 10

    verdict_audit_flags = dict(verdict_outputs.get("verdict_audit_flags", {}) or {})
    verdict_audit_flags.setdefault("binary", binary_name)
    verdict_audit_flags.setdefault("binary_sha256", binary_sha256)
    verdict_audit_flags["status"] = "ok"
    verdict_audit_flags["stage_required"] = 10

    verdict_soft_triage = dict(verdict_outputs.get("verdict_soft_triage", {}) or {})
    verdict_soft_triage.setdefault("binary", binary_name)
    verdict_soft_triage.setdefault("binary_sha256", binary_sha256)
    verdict_soft_triage["status"] = "ok"
    verdict_soft_triage["stage_required"] = 10

    return (
        low_conf_items,
        low_conf_sinks,
        triage_queue,
        verdict_feature_pack,
        verdict_calibration_queue,
        verdict_calibration_decisions,
        verdict_audit_flags,
        verdict_soft_triage,
    )


def _collect_verified_labels(
    result: PipelineResult,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    accepted = {VerificationVerdict.VERIFIED, VerificationVerdict.PARTIAL}
    sources: List[Dict[str, Any]] = []
    sinks: List[Dict[str, Any]] = []
    pack_facts_by_pack = _pack_facts_by_pack_id(result)

    for vl in getattr(result, "verified_labels", []):
        if vl.verdict not in accepted:
            continue
        label = str(vl.final_label or vl.proposal.label or "")
        if not label:
            continue
        facts: Dict[str, Any] = dict(pack_facts_by_pack.get(str(vl.pack_id or ""), {}) or {})
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
    return refine_object_boundaries(normalized, _object_access_traces(normalized))


def _object_access_traces(object_nodes: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    traces: List[Dict[str, Any]] = []
    for obj in object_nodes or []:
        obj_id = str((obj or {}).get("object_id", "") or "")
        for key in ("writer_sites", "reader_sites"):
            for row in (obj or {}).get(key, []) or []:
                if not isinstance(row, Mapping):
                    continue
                traces.append({
                    "object_id": obj_id,
                    "access_kind": "store" if key == "writer_sites" else "load",
                    "context": str(row.get("context", "") or ""),
                    "fn": str(row.get("fn", "") or ""),
                    "site_addr": str(row.get("site_addr", "") or ""),
                    "target_addr": str(row.get("target_addr", "") or ""),
                })
    return traces


def _pack_facts_by_pack_id(result: PipelineResult) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for pack in getattr(result, "evidence_packs", []):
        out[str(pack.pack_id)] = dict(pack.facts or {})
    return out


def _normalize_source_candidates(candidates: Sequence[Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for cand in candidates or []:
        label = getattr(getattr(cand, "preliminary_label", None), "value", None)
        rows.append({
            "address": int(getattr(cand, "address", 0) or 0),
            "function_name": str(getattr(cand, "function_name", "") or ""),
            "preliminary_label": str(label or getattr(cand, "preliminary_label", "") or ""),
            "confidence_score": float(getattr(cand, "confidence_score", 0.0) or 0.0),
            "facts": dict(getattr(cand, "facts", {}) or {}),
            "evidence": [
                {
                    "evidence_id": str(getattr(ev, "evidence_id", "") or ""),
                    "kind": str(getattr(ev, "kind", "") or ""),
                    "text": str(getattr(ev, "text", "") or ""),
                    "address": getattr(ev, "address", None),
                    "metadata": dict(getattr(ev, "metadata", {}) or {}),
                }
                for ev in (getattr(cand, "evidence", []) or [])
            ],
        })
    return rows


def _normalize_sink_candidates(candidates: Sequence[Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for cand in candidates or []:
        label = getattr(getattr(cand, "preliminary_label", None), "value", None)
        rows.append({
            "address": int(getattr(cand, "address", 0) or 0),
            "function_name": str(getattr(cand, "function_name", "") or ""),
            "preliminary_label": str(label or getattr(cand, "preliminary_label", "") or ""),
            "confidence_score": float(getattr(cand, "confidence_score", 0.0) or 0.0),
            "facts": dict(getattr(cand, "facts", {}) or {}),
            "evidence": [
                {
                    "evidence_id": str(getattr(ev, "evidence_id", "") or ""),
                    "kind": str(getattr(ev, "kind", "") or ""),
                    "text": str(getattr(ev, "text", "") or ""),
                    "address": getattr(ev, "address", None),
                    "metadata": dict(getattr(ev, "metadata", {}) or {}),
                }
                for ev in (getattr(cand, "evidence", []) or [])
            ],
        })
    return rows


def _normalize_sink_evidence_packs(packs: Sequence[Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for pack in packs or []:
        label = str(getattr(pack, "candidate_hint", "") or "")
        if label not in SINK_LABELS:
            continue
        rows.append({
            "pack_id": str(getattr(pack, "pack_id", "") or ""),
            "candidate_hint": label,
            "address": int(getattr(pack, "address", 0) or 0),
            "function_name": str(getattr(pack, "function_name", "") or ""),
            "facts": dict(getattr(pack, "facts", {}) or {}),
            "evidence": [
                {
                    "evidence_id": str(getattr(ev, "evidence_id", "") or ""),
                    "kind": str(getattr(ev, "kind", "") or ""),
                    "text": str(getattr(ev, "text", "") or ""),
                    "address": getattr(ev, "address", None),
                    "metadata": dict(getattr(ev, "metadata", {}) or {}),
                }
                for ev in (getattr(pack, "evidence", []) or [])
            ],
        })
    return rows


def _sink_pack_id_by_site(
    result: PipelineResult,
    *,
    verified_sinks: Sequence[Mapping[str, Any]] | None = None,
) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if verified_sinks is not None:
        for sink in verified_sinks or []:
            label = str(sink.get("label", "") or "")
            if label not in SINK_LABELS:
                continue
            key = f"{_hex_addr(sink.get('address', 0))}|{str(sink.get('function_name', '') or '')}|{label}"
            out[key] = str(sink.get("pack_id", "") or "")
        return out
    for vl in getattr(result, "verified_labels", []):
        label = str(vl.final_label or vl.proposal.label or "")
        if label not in SINK_LABELS:
            continue
        key = f"{_hex_addr(vl.proposal.address)}|{vl.proposal.function_name or ''}|{label}"
        out[key] = str(vl.pack_id or "")
    return out


def _augment_verified_sources(
    base_sources: Sequence[Mapping[str, Any]],
    enriched_items: Sequence[Mapping[str, Any]],
) -> Tuple[List[Dict[str, Any]], int]:
    rows = [dict(row or {}) for row in (base_sources or [])]
    seen = {
        (
            str(row.get("label", "") or ""),
            int(row.get("address", 0) or 0),
            str(row.get("function_name", "") or ""),
        )
        for row in rows
    }
    added = 0
    for item in enriched_items or []:
        if str(item.get("item_kind", "") or "") != "source":
            continue
        label = str(item.get("label", "") or "")
        if label not in SOURCE_LABELS:
            continue
        context = dict(item.get("context", {}) or {})
        address = _parse_addr(context.get("target_addr", context.get("address", 0)))
        function_name = str(context.get("function", "") or "")
        key = (label, address, function_name)
        if key in seen:
            continue
        rows.append(
            {
                "pack_id": str(item.get("item_id", "") or ""),
                "label": label,
                "address": address,
                "function_name": function_name,
                "verdict": (
                    "PHASE_A5_SOFT"
                    if str(item.get("merge_state", "") or "") == "soft_accepted"
                    else "PHASE_A5_VERIFIED"
                ),
                "confidence": float(item.get("confidence", 0.0) or 0.0),
                "evidence_refs": [],
                "facts": {
                    "supervision": True,
                    "merge_state": str(item.get("merge_state", "") or ""),
                    "context": context,
                    "arg_roles": dict(item.get("arg_roles", {}) or {}),
                    "reason_codes": list(item.get("reason_codes", []) or []),
                    "support_signals": list(item.get("support_signals", []) or []),
                },
            }
        )
        seen.add(key)
        added += 1
    return rows, added


def _augment_verified_sinks(
    base_sinks: Sequence[Mapping[str, Any]],
    enriched_items: Sequence[Mapping[str, Any]],
    *,
    sink_facts_by_pack: Mapping[str, Mapping[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]], int]:
    rows = [dict(row or {}) for row in (base_sinks or [])]
    facts = {
        str(pack_id or ""): dict(pack_facts or {})
        for pack_id, pack_facts in (sink_facts_by_pack or {}).items()
        if str(pack_id or "")
    }
    applied = 0
    for item in enriched_items or []:
        if str(item.get("item_kind", "") or "") != "sink":
            continue
        label = str(item.get("label", "") or "")
        if label not in SINK_LABELS:
            continue
        context = dict(item.get("context", {}) or {})
        address = _parse_addr(context.get("address", 0))
        function_name = str(context.get("function", "") or "")
        pack_id = str(context.get("pack_id", "") or item.get("item_id", "") or "")
        if not pack_id and not function_name and not address:
            continue
        merged_facts = _merge_supervision_sink_facts(
            label=label,
            item=item,
            base_facts=facts.get(pack_id, {}),
        )
        row = {
            "pack_id": pack_id,
            "label": label,
            "address": address,
            "function_name": function_name,
            "verdict": (
                "PHASE_A5_SOFT"
                if str(item.get("merge_state", "") or "") == "soft_accepted"
                else "PHASE_A5_VERIFIED"
            ),
            "confidence": float(item.get("confidence", 0.0) or 0.0),
            "evidence_refs": [
                str(v)
                for v in (
                    (dict(item.get("evidence_pack", {}) or {}).get("evidence_refs", []) or [])
                )
                if str(v)
            ],
            "facts": merged_facts,
        }
        existing = _find_matching_sink_row(rows, pack_id=pack_id, address=address, function_name=function_name)
        if existing is None:
            rows.append(row)
        else:
            existing["pack_id"] = pack_id or str(existing.get("pack_id", "") or "")
            existing["label"] = label or str(existing.get("label", "") or "")
            existing["address"] = address or int(existing.get("address", 0) or 0)
            existing["function_name"] = function_name or str(existing.get("function_name", "") or "")
            existing["verdict"] = row["verdict"]
            existing["confidence"] = max(
                float(existing.get("confidence", 0.0) or 0.0),
                float(row.get("confidence", 0.0) or 0.0),
            )
            existing["evidence_refs"] = _uniq(
                list(existing.get("evidence_refs", []) or []),
                row.get("evidence_refs", []) or [],
            )
            merged_existing_facts = dict(existing.get("facts", {}) or {})
            merged_existing_facts.update(merged_facts)
            existing["facts"] = merged_existing_facts
        if pack_id:
            facts[pack_id] = merged_facts
        applied += 1
    return rows, facts, applied


def _find_matching_sink_row(
    rows: Sequence[Dict[str, Any]],
    *,
    pack_id: str,
    address: int,
    function_name: str,
) -> Dict[str, Any] | None:
    if pack_id:
        for row in rows:
            if str(row.get("pack_id", "") or "") == pack_id:
                return row
    for row in rows:
        if (
            int(row.get("address", 0) or 0) == int(address or 0)
            and str(row.get("function_name", "") or "") == function_name
        ):
            return row
    return None


def _merge_supervision_sink_facts(
    *,
    label: str,
    item: Mapping[str, Any],
    base_facts: Mapping[str, Any],
) -> Dict[str, Any]:
    context = dict(item.get("context", {}) or {})
    evidence_pack = dict(item.get("evidence_pack", {}) or {})
    out = dict(base_facts or {})
    out.update(_non_empty_mapping(dict(evidence_pack.get("sink_facts", {}) or {})))
    out.update(_non_empty_mapping(dict(evidence_pack.get("sink_semantics_hints", {}) or {})))
    arg_roles = dict(item.get("arg_roles", {}) or {})

    if label == SinkLabel.COPY_SINK.value:
        _set_if_present(out, "len_expr", arg_roles.get("len") or arg_roles.get("size"))
        _set_if_present(out, "dst_expr", arg_roles.get("dst"))
        _set_if_present(out, "src_expr", arg_roles.get("src"))
    elif label == SinkLabel.MEMSET_SINK.value:
        _set_if_present(out, "len_expr", arg_roles.get("len") or arg_roles.get("size"))
        _set_if_present(out, "dst_expr", arg_roles.get("dst"))
    elif label == SinkLabel.STORE_SINK.value:
        _set_if_present(out, "dst_expr", arg_roles.get("dst") or arg_roles.get("target"))
        _set_if_present(out, "target_expr", arg_roles.get("target") or arg_roles.get("dst"))
        _set_if_present(out, "src_expr", arg_roles.get("src"))
        _set_if_present(out, "offset_expr", arg_roles.get("offset"))
    elif label == SinkLabel.LOOP_WRITE_SINK.value:
        _set_if_present(out, "loop_bound", arg_roles.get("bound") or arg_roles.get("len"))
        _set_if_present(out, "index_expr", arg_roles.get("index"))
        _set_if_present(out, "dst_expr", arg_roles.get("dst"))
    elif label == SinkLabel.FORMAT_STRING_SINK.value:
        _set_if_present(out, "format_arg_expr", arg_roles.get("fmt") or arg_roles.get("format"))
    elif label == SinkLabel.FUNC_PTR_SINK.value:
        _set_if_present(out, "dispatch_index", arg_roles.get("dispatch") or arg_roles.get("index"))
        _set_if_present(out, "target_ptr", arg_roles.get("target"))

    out["supervision"] = True
    out["supervision_state"] = str(item.get("merge_state", "") or "")
    out["supervision_reason_codes"] = list(item.get("reason_codes", []) or [])
    out["supervision_support_signals"] = list(item.get("support_signals", []) or [])
    out["supervision_arg_roles"] = arg_roles
    if context.get("address"):
        out.setdefault("site", context.get("address"))
    return out


def _non_empty_mapping(values: Mapping[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in (values or {}).items():
        if _meaningful_supervision_value(value):
            out[str(key)] = value
    return out


def _meaningful_supervision_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True


def _set_if_present(target: Dict[str, Any], key: str, value: Any) -> None:
    if _meaningful_supervision_value(value):
        target[key] = value


def _merge_supervision_object(
    *,
    item: Mapping[str, Any],
    nodes_by_id: Dict[str, Dict[str, Any]],
    refined_by_id: Dict[str, Dict[str, Any]],
    object_nodes: List[Dict[str, Any]],
    refined_rows: List[Dict[str, Any]],
) -> None:
    context = dict(item.get("context", {}) or {})
    evidence_pack = dict(item.get("evidence_pack", {}) or {})
    object_id = str(context.get("object_id", "") or item.get("item_id", "") or "")
    if not object_id:
        return
    label = str(item.get("label", "") or context.get("region_kind", "") or "SRAM_CLUSTER")
    addr_range = list(context.get("addr_range", []) or [])
    members = [str(v) for v in (evidence_pack.get("members", []) or []) if str(v)]
    writers = [str(v) for v in (evidence_pack.get("writers", []) or []) if str(v)]
    readers = [str(v) for v in (evidence_pack.get("readers", []) or []) if str(v)]
    writer_sites = [dict(v or {}) for v in (evidence_pack.get("writer_sites", []) or [])]
    reader_sites = [dict(v or {}) for v in (evidence_pack.get("reader_sites", []) or [])]
    type_facts = dict(evidence_pack.get("type_facts", {}) or {})
    type_facts["supervision_state"] = str(item.get("merge_state", "") or "")
    base = {
        "object_id": object_id,
        "region_kind": label or "SRAM_CLUSTER",
        "addr_range": addr_range,
        "members": members,
        "writers": writers,
        "readers": readers,
        "producer_contexts": list(context.get("producer_contexts", []) or []),
        "consumer_contexts": list(context.get("consumer_contexts", []) or []),
        "confidence": max(float(item.get("confidence", 0.0) or 0.0), 0.75),
        "notes": "phase_a5 object supervision",
        "writer_sites": writer_sites,
        "reader_sites": reader_sites,
        "type_facts": type_facts,
    }
    node = nodes_by_id.get(object_id)
    if node is None:
        node = dict(base)
        object_nodes.append(node)
        nodes_by_id[object_id] = node
    else:
        _merge_object_like(node, base)
    ref = refined_by_id.get(object_id)
    if ref is None:
        ref = dict(base)
        refined_rows.append(ref)
        refined_by_id[object_id] = ref
    else:
        _merge_object_like(ref, base)


def _merge_supervision_channel(
    *,
    item: Mapping[str, Any],
    edge_keys: Dict[Tuple[str, str, str, str], Dict[str, Any]],
    channel_edges: List[Dict[str, Any]],
    nodes_by_id: Dict[str, Dict[str, Any]],
    refined_by_id: Dict[str, Dict[str, Any]],
    object_nodes: List[Dict[str, Any]],
    refined_rows: List[Dict[str, Any]],
) -> None:
    context = dict(item.get("context", {}) or {})
    evidence_pack = dict(item.get("evidence_pack", {}) or {})
    object_id = str(context.get("object_id", "") or "")
    if not object_id:
        return
    if object_id not in nodes_by_id or object_id not in refined_by_id:
        _merge_supervision_object(
            item={
                "item_id": f"object:{object_id}",
                "label": str(context.get("region_kind", "") or "SRAM_CLUSTER"),
                "merge_state": item.get("merge_state", ""),
                "confidence": item.get("confidence", 0.0),
                "context": {
                    "object_id": object_id,
                    "region_kind": context.get("region_kind", "SRAM_CLUSTER"),
                    "producer_contexts": [context.get("src_context")] if context.get("src_context") else [],
                    "consumer_contexts": [context.get("dst_context")] if context.get("dst_context") else [],
                },
                "evidence_pack": {
                    "members": list(evidence_pack.get("object_members", []) or []),
                    "type_facts": dict(evidence_pack.get("type_facts", {}) or {}),
                    "writer_sites": list(evidence_pack.get("writer_sites", []) or []),
                    "reader_sites": list(evidence_pack.get("reader_sites", []) or []),
                },
            },
            nodes_by_id=nodes_by_id,
            refined_by_id=refined_by_id,
            object_nodes=object_nodes,
            refined_rows=refined_rows,
        )
    src = str(context.get("src_context", "") or "UNKNOWN")
    dst = str(context.get("dst_context", "") or "UNKNOWN")
    label = str(item.get("label", "") or "DATA")
    edge_kind = _channel_edge_kind(label)
    key = (object_id, src, dst, edge_kind)
    base = {
        "object_id": object_id,
        "src_context": src,
        "dst_context": dst,
        "edge_kind": edge_kind,
        "constraints": list(evidence_pack.get("edge_constraints", []) or []),
        "evidence_refs": [],
        "score": max(float(item.get("confidence", 0.0) or 0.0), 0.75),
        "notes": "phase_a5 channel supervision",
    }
    edge = edge_keys.get(key)
    if edge is None:
        edge = dict(base)
        channel_edges.append(edge)
        edge_keys[key] = edge
    else:
        edge["score"] = max(float(edge.get("score", 0.0) or 0.0), base["score"])
        edge["constraints"] = _uniq(edge.get("constraints", []), base["constraints"])
        if "phase_a5 channel supervision" not in str(edge.get("notes", "") or ""):
            edge["notes"] = "; ".join(
                [part for part in [str(edge.get("notes", "") or "").strip(), "phase_a5 channel supervision"] if part]
            )


def _merge_object_like(target: Dict[str, Any], update: Mapping[str, Any]) -> None:
    target["region_kind"] = str(update.get("region_kind", target.get("region_kind", "")) or target.get("region_kind", ""))
    if update.get("addr_range"):
        target["addr_range"] = list(update.get("addr_range", []) or [])
    target["members"] = _uniq(target.get("members", []), update.get("members", []))
    target["writers"] = _uniq(target.get("writers", []), update.get("writers", []))
    target["readers"] = _uniq(target.get("readers", []), update.get("readers", []))
    target["producer_contexts"] = _uniq(target.get("producer_contexts", []), update.get("producer_contexts", []))
    target["consumer_contexts"] = _uniq(target.get("consumer_contexts", []), update.get("consumer_contexts", []))
    target["writer_sites"] = _uniq_rows(target.get("writer_sites", []), update.get("writer_sites", []))
    target["reader_sites"] = _uniq_rows(target.get("reader_sites", []), update.get("reader_sites", []))
    target["confidence"] = max(float(target.get("confidence", 0.0) or 0.0), float(update.get("confidence", 0.0) or 0.0))
    merged_type_facts = dict(target.get("type_facts", {}) or {})
    merged_type_facts.update(dict(update.get("type_facts", {}) or {}))
    target["type_facts"] = merged_type_facts
    note = str(update.get("notes", "") or "").strip()
    if note and note not in str(target.get("notes", "") or ""):
        target["notes"] = "; ".join([part for part in [str(target.get("notes", "") or "").strip(), note] if part])


def _uniq(existing: Sequence[Any], new_values: Sequence[Any]) -> List[Any]:
    out: List[Any] = []
    seen = set()
    for value in list(existing or []) + list(new_values or []):
        key = repr(value)
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
    return out


def _uniq_rows(existing: Sequence[Mapping[str, Any]], new_rows: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    for row in list(existing or []) + list(new_rows or []):
        item = dict(row or {})
        key = repr(sorted(item.items()))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _channel_edge_kind(label: str) -> str:
    upper = str(label or "").upper()
    if upper == "DMA_CHANNEL":
        return "DATA"
    if upper == "ISR_SHARED_CHANNEL":
        return "DATA"
    if upper == "QUEUE_CHANNEL":
        return "DATA"
    if upper == "RING_BUFFER_CHANNEL":
        return "DATA"
    return "DATA"


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


def _parse_addr(v: Any) -> int:
    try:
        if isinstance(v, str):
            return int(v, 0)
        return int(v or 0)
    except Exception:
        return 0


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
