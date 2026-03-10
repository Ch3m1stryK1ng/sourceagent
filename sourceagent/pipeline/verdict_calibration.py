"""Deterministic verdict-calibration artifacts and fail-closed review application."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


SCHEMA_VERSION = "0.1"
DEFAULT_CALIBRATION_MODE = "suspicious_only"
DEFAULT_VERDICT_OUTPUT_MODE = "dual"
DEFAULT_MAX_CALIBRATION_CHAINS = 64
DEFAULT_SAMPLE_SUSPICIOUS_RATIO_THRESHOLD = 0.40
DEFAULT_MIN_RISK_SCORE = 0.45
DEFAULT_REVIEW_NEEDS_THRESHOLD = 0.55
DEFAULT_ALLOW_MANUAL_LLM_SUPERVISION = False
DEFAULT_LLM_PROMOTE_BUDGET = 24
DEFAULT_LLM_DEMOTE_BUDGET = 24
DEFAULT_LLM_SOFT_BUDGET = 48

_ALLOWED_CALIBRATION_MODES = {
    "exact_mismatch",
    "suspicious_only",
    "all_non_exact",
    "audit_only",
    "all_matched",
}
_ALLOWED_OUTPUT_MODES = {"strict", "soft", "dual"}
_ALLOWED_VERDICTS = {"SAFE_OR_LOW_RISK", "SUSPICIOUS", "CONFIRMED"}
_HARD_BLOCK_REASON_CODES = {
    "HARD_CONTRADICTION",
    "CONTROL_PATH_ONLY",
    "SECONDARY_ROOT_ONLY",
    "CHANNEL_REQUIRED_MISSING",
}
_SNIPPET_KEYS = {"sink_function", "caller_bridge", "producer_function"}


def build_verdict_calibration_artifacts(
    *,
    binary_name: str,
    binary_sha256: str,
    chains: Sequence[Dict[str, Any]],
    channel_graph: Mapping[str, Any],
    sink_facts_by_pack: Mapping[str, Dict[str, Any]],
    sink_pack_id_by_site: Mapping[str, str],
    decompiled_cache: Optional[Mapping[str, str]] = None,
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
    review_decisions: Optional[Sequence[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build deterministic feature packs, queue, soft triage, and applied decisions."""
    calibration_mode = _normalize_calibration_mode(calibration_mode)
    verdict_output_mode = _normalize_output_mode(verdict_output_mode)
    decompiled_cache = dict(decompiled_cache or {})

    object_nodes = {
        str(obj.get("object_id", "")): dict(obj)
        for obj in (channel_graph or {}).get("object_nodes", []) or []
        if str(obj.get("object_id", ""))
    }

    feature_items: List[Dict[str, Any]] = []
    sample_id = Path(binary_name).stem or binary_name
    for chain in chains or []:
        feature_items.append(
            _build_feature_item(
                chain,
                sample_id=sample_id,
                object_nodes=object_nodes,
                sink_facts_by_pack=sink_facts_by_pack,
                sink_pack_id_by_site=sink_pack_id_by_site,
                decompiled_cache=decompiled_cache,
                min_risk_score=min_risk_score,
                review_needs_threshold=review_needs_threshold,
            )
        )

    queue_items = _select_calibration_queue(
        feature_items,
        calibration_mode=calibration_mode,
        max_items=max_calibration_chains,
        sample_suspicious_ratio_threshold=sample_suspicious_ratio_threshold,
    )

    applied = _apply_review_decisions(
        feature_items,
        queue_items,
        review_decisions=review_decisions or [],
        calibration_mode=calibration_mode,
        verdict_output_mode=verdict_output_mode,
        allow_manual_llm_supervision=allow_manual_llm_supervision,
        llm_promote_budget=int(llm_promote_budget),
        llm_demote_budget=int(llm_demote_budget),
        llm_soft_budget=int(llm_soft_budget),
        min_risk_score=float(min_risk_score),
    )

    decision_rows = applied["decision_rows"]
    audit_rows = applied["audit_rows"]
    soft_rows = applied["soft_rows"]

    feature_pack = {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "mode": calibration_mode,
        "output_mode": verdict_output_mode,
        "items": feature_items,
        "status": "ok",
    }
    calibration_queue = {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "mode": calibration_mode,
        "params": {
            "max_calibration_chains": int(max_calibration_chains),
            "sample_suspicious_ratio_threshold": float(sample_suspicious_ratio_threshold),
            "min_risk_score": float(min_risk_score),
            "review_needs_threshold": float(review_needs_threshold),
            "allow_manual_llm_supervision": bool(allow_manual_llm_supervision),
            "llm_promote_budget": int(llm_promote_budget),
            "llm_demote_budget": int(llm_demote_budget),
            "llm_soft_budget": int(llm_soft_budget),
        },
        "items": queue_items,
        "status": "ok",
    }
    calibration_decisions = {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "mode": calibration_mode,
        "output_mode": verdict_output_mode,
        "items": decision_rows,
        "status": "ok",
    }
    audit_flags = {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "items": audit_rows,
        "status": "ok",
    }
    soft_triage = {
        "schema_version": SCHEMA_VERSION,
        "binary": binary_name,
        "binary_sha256": binary_sha256,
        "mode": calibration_mode,
        "output_mode": verdict_output_mode,
        "items": soft_rows,
        "stats": _summarize_soft_triage(soft_rows),
        "status": "ok",
    }

    return {
        "verdict_feature_pack": feature_pack,
        "verdict_calibration_queue": calibration_queue,
        "verdict_calibration_decisions": calibration_decisions,
        "verdict_audit_flags": audit_flags,
        "verdict_soft_triage": soft_triage,
    }


def load_review_decisions(path: Optional[str | Path]) -> List[Dict[str, Any]]:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        return []
    data = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [dict(item) for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        if isinstance(data.get("items"), list):
            return [dict(item) for item in data.get("items", []) if isinstance(item, dict)]
        if isinstance(data.get("decisions"), list):
            return [dict(item) for item in data.get("decisions", []) if isinstance(item, dict)]
    return []


def merge_review_decisions(
    internal_decisions: Sequence[Mapping[str, Any]],
    external_decisions: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    """Merge review decisions by chain_id, preferring explicit external overrides."""
    merged: Dict[str, Dict[str, Any]] = {}
    for raw in internal_decisions:
        chain_id = str(raw.get("chain_id", "") or "")
        if chain_id:
            merged[chain_id] = dict(raw)
    for raw in external_decisions:
        chain_id = str(raw.get("chain_id", "") or "")
        if chain_id:
            merged[chain_id] = dict(raw)
    return list(merged.values())


def _build_feature_item(
    chain: Mapping[str, Any],
    *,
    sample_id: str,
    object_nodes: Mapping[str, Dict[str, Any]],
    sink_facts_by_pack: Mapping[str, Dict[str, Any]],
    sink_pack_id_by_site: Mapping[str, str],
    decompiled_cache: Mapping[str, str],
    min_risk_score: float,
    review_needs_threshold: float,
) -> Dict[str, Any]:
    sink = dict(chain.get("sink", {}) or {})
    raw_root_bundle = chain.get("root_bundle", []) or []
    if isinstance(raw_root_bundle, dict):
        if isinstance(raw_root_bundle.get("active_root"), dict):
            active = dict(raw_root_bundle.get("active_root") or {})
            active.setdefault("active", True)
            roots = raw_root_bundle.get("roots")
            if isinstance(roots, list):
                root_bundle_rows = [dict(row) for row in roots if isinstance(row, dict)]
                if active and not any(bool(row.get("active")) for row in root_bundle_rows):
                    root_bundle_rows.insert(0, active)
            else:
                root_bundle_rows = [active]
        else:
            root_bundle_rows = [dict(raw_root_bundle)]
    elif isinstance(raw_root_bundle, list):
        root_bundle_rows = [dict(row) for row in raw_root_bundle if isinstance(row, dict)]
    else:
        root_bundle_rows = []
    active_root = next((row for row in root_bundle_rows if row.get("active")), None) or (
        root_bundle_rows[0] if root_bundle_rows else {}
    )
    checks = [dict(chk) for chk in (chain.get("checks", []) or [])]
    derive_facts = [dict(f) for f in (chain.get("derive_facts", []) or [])]
    link_debug = dict(chain.get("link_debug", {}) or {})
    decision_basis = dict(chain.get("decision_basis", {}) or {})
    sink_label = str(sink.get("label", "") or "")
    sink_fn = str(sink.get("function", "") or "")
    sink_site = str(sink.get("site", "") or "")
    pack_id = sink_pack_id_by_site.get(_sink_site_key(sink_site, sink_fn, sink_label), "")
    sink_facts = dict(sink_facts_by_pack.get(pack_id, {}) or {})
    current_verdict = str(chain.get("verdict", "DROP") or "DROP")
    reason_code = str(decision_basis.get("reason_code", chain.get("failure_code", "UNKNOWN")) or "UNKNOWN")
    risk_score = _risk_score(chain, decision_basis, checks)
    confidence = float(chain.get("score", 0.0) or 0.0)
    current_verdict_reason = reason_code
    audit_flags = _deterministic_audit_flags(chain, sink_facts=sink_facts, checks=checks)
    snippets = _collect_snippets(chain, sink_function=sink_fn, decompiled_cache=decompiled_cache)
    strict_verdict = current_verdict
    soft_candidate = _soft_candidate(chain, decision_basis, risk_score, min_risk_score=min_risk_score)
    soft_verdict = _derive_soft_verdict(strict_verdict, soft_candidate)
    needs_review = _needs_review(
        current_verdict=current_verdict,
        risk_score=risk_score,
        reason_code=current_verdict_reason,
        audit_flags=audit_flags,
        review_needs_threshold=review_needs_threshold,
        soft_candidate=soft_candidate,
    )

    return {
        "chain_id": str(chain.get("chain_id", "") or ""),
        "sample_id": sample_id,
        "current_verdict": current_verdict,
        "current_verdict_reason": current_verdict_reason,
        "strict_verdict": strict_verdict,
        "soft_verdict": soft_verdict,
        "risk_score": round(risk_score, 4),
        "confidence": round(confidence, 4),
        "needs_review": bool(needs_review),
        "review_state": _review_state(current_verdict, needs_review),
        "sink": {
            "label": sink_label,
            "function": sink_fn,
            "site": sink_site,
        },
        "root": {
            "expr": str(active_root.get("expr", sink.get("root_expr", "UNKNOWN")) or "UNKNOWN"),
            "canonical_expr": str(active_root.get("canonical_expr", active_root.get("expr", sink.get("root_expr", "UNKNOWN"))) or "UNKNOWN"),
            "family": _root_family(active_root),
            "source": str(active_root.get("source", chain.get("root_source", "none")) or "none"),
            "role": str(active_root.get("role", "") or ""),
            "kind": str(active_root.get("kind", "") or ""),
        },
        "object_path": _build_object_path(chain, object_nodes=object_nodes),
        "channel_path": _build_channel_path(chain),
        "derive_facts": derive_facts,
        "check_facts": checks,
        "sink_semantics_hints": _sink_semantics_hints(sink_label, sink_facts, active_root, derive_facts, checks),
        "guard_context": _guard_context(sink_facts, checks),
        "capacity_evidence": _capacity_evidence(sink_label, sink_facts, checks, active_root),
        "chain_segments": _build_chain_segments(
            chain,
            sink_label=sink_label,
            sink_function=sink_fn,
            active_root=active_root,
            object_nodes=object_nodes,
            checks=checks,
            derive_facts=derive_facts,
        ),
        "evidence_refs": list(chain.get("evidence_refs", []) or []),
        "decompiled_snippets": snippets,
        "deterministic_constraints": _deterministic_constraints(chain, decision_basis),
        "decision_basis": decision_basis,
        "audit_flags": audit_flags,
        "soft_candidate": bool(soft_candidate),
        "llm_reviewed": False,
        "reasons": [current_verdict_reason],
        "pack_id": pack_id,
    }


def _select_calibration_queue(
    feature_items: Sequence[Dict[str, Any]],
    *,
    calibration_mode: str,
    max_items: int,
    sample_suspicious_ratio_threshold: float,
) -> List[Dict[str, Any]]:
    by_sample: Dict[str, Dict[str, int]] = {}
    for item in feature_items:
        sample = str(item.get("sample_id", "") or "sample")
        cur = by_sample.setdefault(sample, {"total": 0, "suspicious": 0})
        cur["total"] += 1
        if str(item.get("current_verdict", "")) == "SUSPICIOUS":
            cur["suspicious"] += 1

    selected: List[Dict[str, Any]] = []
    for item in feature_items:
        sample = str(item.get("sample_id", "") or "sample")
        stats = by_sample.get(sample, {"total": 0, "suspicious": 0})
        total = max(1, int(stats.get("total", 0)))
        suspicious_ratio = float(stats.get("suspicious", 0)) / total
        include, reasons = _queue_predicate(
            item,
            calibration_mode=calibration_mode,
            suspicious_ratio=suspicious_ratio,
            suspicious_ratio_threshold=sample_suspicious_ratio_threshold,
        )
        if not include:
            continue
        row = {
            "chain_id": item.get("chain_id"),
            "current_verdict": item.get("current_verdict"),
            "soft_verdict": item.get("soft_verdict"),
            "risk_score": item.get("risk_score"),
            "needs_review": item.get("needs_review"),
            "review_state": item.get("review_state"),
            "queue_reasons": reasons,
            "sample_suspicious_ratio": round(suspicious_ratio, 4),
            "sink": item.get("sink", {}),
            "root": item.get("root", {}),
        }
        selected.append(row)

    selected.sort(key=lambda row: (
        -float(row.get("risk_score", 0.0) or 0.0),
        row.get("current_verdict") != "SUSPICIOUS",
        str(row.get("chain_id", "")),
    ))
    return selected[: max(0, int(max_items))]


def _apply_review_decisions(
    feature_items: Sequence[Dict[str, Any]],
    queue_items: Sequence[Dict[str, Any]],
    *,
    review_decisions: Sequence[Dict[str, Any]],
    calibration_mode: str,
    verdict_output_mode: str,
    allow_manual_llm_supervision: bool,
    llm_promote_budget: int,
    llm_demote_budget: int,
    llm_soft_budget: int,
    min_risk_score: float,
) -> Dict[str, Any]:
    queued = {str(item.get("chain_id", "")): dict(item) for item in queue_items}
    features = {str(item.get("chain_id", "")): dict(item) for item in feature_items}
    decisions_by_chain: Dict[str, Dict[str, Any]] = {}
    for raw in review_decisions:
        chain_id = str(raw.get("chain_id", "") or "")
        if chain_id and chain_id in features:
            decisions_by_chain[chain_id] = dict(raw)

    promote_left = max(0, int(llm_promote_budget))
    demote_left = max(0, int(llm_demote_budget))
    soft_left = max(0, int(llm_soft_budget))

    decision_rows: List[Dict[str, Any]] = []
    audit_rows: List[Dict[str, Any]] = []
    soft_rows: List[Dict[str, Any]] = []

    for item in feature_items:
        chain_id = str(item.get("chain_id", "") or "")
        raw_decision = decisions_by_chain.get(chain_id)
        strict_verdict = str(item.get("strict_verdict", item.get("current_verdict", "DROP")) or "DROP")
        soft_verdict = str(item.get("soft_verdict", strict_verdict) or strict_verdict)
        final_verdict = strict_verdict if verdict_output_mode == "strict" else soft_verdict
        accepted = False
        accept_reason = "NO_EXTERNAL_REVIEW"
        applied_review_mode = "none"
        llm_reviewed = False
        audit_flags = list(item.get("audit_flags", []) or [])
        trigger_summary = ""
        preconditions = {}
        segment_assessment = []
        reason_codes = []
        evidence_map = {}
        review_quality_flags = []
        review_confidence = None
        review_notes = ""

        if raw_decision is not None:
            verdict_candidate, decision_record = _validate_and_apply_decision(
                item,
                raw_decision,
                calibration_mode=calibration_mode,
                allow_manual_llm_supervision=allow_manual_llm_supervision,
            )
            accepted = bool(decision_record.get("accepted", False))
            accept_reason = str(decision_record.get("accept_reason", "REJECTED_REVIEW") or "REJECTED_REVIEW")
            applied_review_mode = str(decision_record.get("review_mode", "external") or "external")
            llm_reviewed = True
            trigger_summary = str(decision_record.get("trigger_summary", "") or "")
            preconditions = dict(decision_record.get("preconditions", {}) or {})
            segment_assessment = list(decision_record.get("segment_assessment", []) or [])
            reason_codes = list(decision_record.get("reason_codes", []) or [])
            evidence_map = dict(decision_record.get("evidence_map", {}) or {})
            review_quality_flags = list(decision_record.get("review_quality_flags", []) or [])
            review_confidence = decision_record.get("confidence")
            review_notes = str(decision_record.get("review_notes", "") or "")
            audit_flags.extend(str(flag) for flag in (decision_record.get("audit_flags", []) or []) if str(flag))
            if accepted and calibration_mode != "audit_only":
                if strict_verdict != verdict_candidate:
                    if _verdict_rank(verdict_candidate) > _verdict_rank(strict_verdict):
                        if promote_left > 0:
                            soft_verdict = verdict_candidate
                            promote_left -= 1
                        else:
                            accept_reason = "PROMOTE_BUDGET_EXHAUSTED"
                            accepted = False
                    elif _verdict_rank(verdict_candidate) < _verdict_rank(strict_verdict):
                        if demote_left > 0:
                            soft_verdict = verdict_candidate
                            demote_left -= 1
                        else:
                            accept_reason = "DEMOTE_BUDGET_EXHAUSTED"
                            accepted = False
                else:
                    soft_verdict = verdict_candidate
            elif accepted and calibration_mode == "audit_only":
                accept_reason = "AUDIT_ONLY_NO_VERDICT_CHANGE"

            decision_rows.append({
                "chain_id": chain_id,
                "accepted": accepted,
                "accept_reason": accept_reason,
                "review_mode": applied_review_mode,
                "strict_verdict": strict_verdict,
                "suggested_verdict": str(raw_decision.get("suggested_semantic_verdict", "") or ""),
                "soft_verdict": soft_verdict,
                "trigger_summary": trigger_summary,
                "preconditions": preconditions,
                "segment_assessment": segment_assessment,
                "reason_codes": reason_codes,
                "evidence_map": evidence_map,
                "review_quality_flags": review_quality_flags,
                "confidence": review_confidence,
                "review_notes": review_notes,
                "audit_flags": sorted(set(audit_flags)),
            })
        else:
            decision_rows.append({
                "chain_id": chain_id,
                "accepted": False,
                "accept_reason": "NO_EXTERNAL_REVIEW",
                "review_mode": "none",
                "strict_verdict": strict_verdict,
                "suggested_verdict": "",
                "soft_verdict": soft_verdict,
                "trigger_summary": "",
                "preconditions": {},
                "segment_assessment": [],
                "reason_codes": [],
                "evidence_map": {},
                "review_quality_flags": [],
                "confidence": None,
                "review_notes": "",
                "audit_flags": sorted(set(audit_flags)),
            })

        if not raw_decision and item.get("soft_candidate") and soft_left > 0 and verdict_output_mode in {"soft", "dual"}:
            # Deterministic soft widening for richer BinAgent review material.
            if strict_verdict == "DROP" and float(item.get("risk_score", 0.0) or 0.0) >= float(min_risk_score):
                soft_verdict = "SUSPICIOUS"
                soft_left -= 1
                accept_reason = "DETERMINISTIC_SOFT_WIDEN"

        if verdict_output_mode == "strict":
            final_verdict = strict_verdict
        elif verdict_output_mode == "soft":
            final_verdict = soft_verdict
        else:
            final_verdict = soft_verdict

        audit_rows.extend(
            {
                "chain_id": chain_id,
                "flag": flag,
                "review_mode": applied_review_mode,
            }
            for flag in sorted(set(audit_flags))
        )
        soft_rows.append({
            "chain_id": chain_id,
            "strict_verdict": strict_verdict,
            "soft_verdict": soft_verdict,
            "final_verdict": final_verdict,
            "risk_score": item.get("risk_score"),
            "needs_review": item.get("needs_review"),
            "llm_reviewed": llm_reviewed,
            "review_mode": applied_review_mode,
            "accept_reason": accept_reason,
            "queue_eligible": chain_id in queued,
            "sink": item.get("sink", {}),
            "root": item.get("root", {}),
            "trigger_summary": trigger_summary,
            "preconditions": preconditions,
            "segment_assessment": segment_assessment,
            "reason_codes": reason_codes,
            "evidence_map": evidence_map,
            "review_quality_flags": review_quality_flags,
            "confidence": review_confidence,
            "audit_flags": sorted(set(audit_flags)),
        })

    return {
        "decision_rows": decision_rows,
        "audit_rows": audit_rows,
        "soft_rows": soft_rows,
    }


def _validate_and_apply_decision(
    feature_item: Mapping[str, Any],
    raw_decision: Mapping[str, Any],
    *,
    calibration_mode: str,
    allow_manual_llm_supervision: bool,
) -> Tuple[str, Dict[str, Any]]:
    suggested = str(raw_decision.get("suggested_semantic_verdict", "") or "")
    base_record = {
        "review_mode": str(raw_decision.get("review_mode", "external") or "external"),
        "trigger_summary": str(raw_decision.get("trigger_summary", "") or ""),
        "preconditions": dict(raw_decision.get("preconditions", {}) or {}),
        "segment_assessment": list(raw_decision.get("segment_assessment", []) or []),
        "reason_codes": list(raw_decision.get("reason_codes", []) or []),
        "evidence_map": dict(raw_decision.get("evidence_map", {}) or {}),
        "review_quality_flags": list(raw_decision.get("review_quality_flags", []) or []),
        "confidence": raw_decision.get("confidence"),
        "review_notes": str(raw_decision.get("review_notes", "") or ""),
    }

    if suggested not in _ALLOWED_VERDICTS:
        return feature_item.get("strict_verdict", "DROP"), {
            **base_record,
            "accepted": False,
            "accept_reason": "INVALID_SUGGESTED_VERDICT",
            "audit_flags": ["invalid_suggested_verdict"],
        }
    evidence_map = raw_decision.get("evidence_map")
    if not isinstance(evidence_map, dict) or not evidence_map:
        return feature_item.get("strict_verdict", "DROP"), {
            **base_record,
            "accepted": False,
            "accept_reason": "MISSING_EVIDENCE_MAP",
            "audit_flags": ["missing_evidence_map"],
        }
    snippets = dict(feature_item.get("decompiled_snippets", {}) or {})
    for refs in evidence_map.values():
        if not isinstance(refs, list) or not refs:
            return feature_item.get("strict_verdict", "DROP"), {
                **base_record,
                "accepted": False,
                "accept_reason": "INVALID_EVIDENCE_MAP_ENTRY",
                "audit_flags": ["invalid_evidence_map_entry"],
            }
        for key in refs:
            if str(key) not in _SNIPPET_KEYS:
                return feature_item.get("strict_verdict", "DROP"), {
                    **base_record,
                    "accepted": False,
                    "accept_reason": "UNKNOWN_SNIPPET_KEY",
                    "audit_flags": ["unknown_snippet_key"],
                }
            if not str(snippets.get(str(key), "") or "").strip():
                return feature_item.get("strict_verdict", "DROP"), {
                    **base_record,
                    "accepted": False,
                    "accept_reason": "SNIPPET_MISSING",
                    "audit_flags": ["snippet_missing"],
                }

    if bool(raw_decision.get("manual_supervision", False)) and not allow_manual_llm_supervision:
        return feature_item.get("strict_verdict", "DROP"), {
            **base_record,
            "accepted": False,
            "accept_reason": "MANUAL_SUPERVISION_DISABLED",
            "audit_flags": ["manual_supervision_disabled"],
        }

    constraints = dict(feature_item.get("deterministic_constraints", {}) or {})
    if not (constraints.get("source_reached") and constraints.get("root_bound") and constraints.get("object_bound")):
        return feature_item.get("strict_verdict", "DROP"), {
            **base_record,
            "accepted": False,
            "accept_reason": "STRUCTURAL_CONSTRAINT_NOT_MET",
            "audit_flags": ["structural_constraint_not_met"],
        }
    if constraints.get("channel_required") and not constraints.get("channel_satisfied"):
        return feature_item.get("strict_verdict", "DROP"), {
            **base_record,
            "accepted": False,
            "accept_reason": "CHANNEL_REQUIRED_NOT_SATISFIED",
            "audit_flags": ["channel_required_not_satisfied"],
        }

    reason_code = str((feature_item.get("decision_basis", {}) or {}).get("reason_code", "") or "")
    if reason_code in _HARD_BLOCK_REASON_CODES:
        return feature_item.get("strict_verdict", "DROP"), {
            **base_record,
            "accepted": False,
            "accept_reason": "HARD_BLOCK_REASON_CODE",
            "audit_flags": ["hard_block_reason_code"],
        }

    accepted = True
    final_suggested = suggested
    if calibration_mode == "audit_only":
        final_suggested = str(
            feature_item.get("strict_verdict", feature_item.get("current_verdict", "DROP")) or "DROP"
        )

    return final_suggested, {
        **base_record,
        "accepted": accepted,
        "accept_reason": "ACCEPTED_REVIEW",
        "audit_flags": list(raw_decision.get("audit_flags", []) or []),
    }


def _build_object_path(chain: Mapping[str, Any], *, object_nodes: Mapping[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    debug = dict(chain.get("link_debug", {}) or {})
    out: List[Dict[str, Any]] = []
    seen = set()
    for obj_id in list(debug.get("object_hits", []) or []):
        obj = dict(object_nodes.get(str(obj_id), {}) or {})
        if not obj or obj_id in seen:
            continue
        seen.add(obj_id)
        out.append({
            "object_id": str(obj.get("object_id", obj_id)),
            "members": list(obj.get("members", []) or []),
            "addr_range": list(obj.get("addr_range", []) or []),
            "producer_contexts": list(obj.get("producer_contexts", []) or []),
            "consumer_contexts": list(obj.get("consumer_contexts", []) or []),
            "type_facts": dict(obj.get("type_facts", {}) or {}),
        })
    return out


def _build_chain_segments(
    chain: Mapping[str, Any],
    *,
    sink_label: str,
    sink_function: str,
    active_root: Mapping[str, Any],
    object_nodes: Mapping[str, Dict[str, Any]],
    checks: Sequence[Mapping[str, Any]],
    derive_facts: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    object_path = _build_object_path(chain, object_nodes=object_nodes)
    channel_path = _build_channel_path(chain)
    source_steps = [dict(step) for step in (chain.get("steps", []) or []) if str(step.get("kind", "")) == "SOURCE"]
    segments: List[Dict[str, Any]] = []

    if source_steps and object_path:
        segments.append({
            "segment_id": "source_to_object",
            "kind": "SOURCE_TO_OBJECT",
            "src": {
                "label": str(source_steps[0].get("label", "") or ""),
                "function": str(source_steps[0].get("function", "") or ""),
                "site": str(source_steps[0].get("site", "") or ""),
            },
            "dst": {
                "object_id": str(object_path[0].get("object_id", "") or ""),
                "members": list(object_path[0].get("members", []) or []),
            },
            "facts": ["source_reached", "object_candidate"],
            "snippet_keys": ["producer_function"],
        })
    elif source_steps:
        segments.append({
            "segment_id": "source_to_sink",
            "kind": "SOURCE_TO_SINK",
            "src": {
                "label": str(source_steps[0].get("label", "") or ""),
                "function": str(source_steps[0].get("function", "") or ""),
                "site": str(source_steps[0].get("site", "") or ""),
            },
            "dst": {
                "sink_function": sink_function,
                "sink_label": sink_label,
            },
            "facts": ["source_reached"],
            "snippet_keys": ["producer_function", "sink_function"],
        })

    if object_path and channel_path:
        segments.append({
            "segment_id": "object_to_channel",
            "kind": "OBJECT_TO_CHANNEL",
            "src": {
                "object_id": str(object_path[0].get("object_id", "") or ""),
            },
            "dst": {
                "edge": str(channel_path[0].get("edge", "") or ""),
                "object_id": str(channel_path[0].get("object_id", "") or ""),
            },
            "facts": ["channel_candidate"],
            "snippet_keys": ["producer_function", "caller_bridge"],
        })

    if channel_path:
        segments.append({
            "segment_id": "channel_to_sink",
            "kind": "CHANNEL_TO_SINK",
            "src": {
                "edge": str(channel_path[0].get("edge", "") or ""),
                "object_id": str(channel_path[0].get("object_id", "") or ""),
            },
            "dst": {
                "sink_function": sink_function,
                "sink_label": sink_label,
            },
            "facts": ["channel_satisfied"],
            "snippet_keys": ["caller_bridge", "sink_function"],
        })

    if derive_facts:
        segments.append({
            "segment_id": "derive_to_root",
            "kind": "DERIVE_TO_ROOT",
            "src": {
                "derive_exprs": [str(row.get("expr", "") or "") for row in derive_facts],
            },
            "dst": {
                "root_expr": str(active_root.get("expr", "") or ""),
                "root_kind": str(active_root.get("kind", "") or ""),
            },
            "facts": ["root_bound"],
            "snippet_keys": ["sink_function", "caller_bridge"],
        })

    segments.append({
        "segment_id": "check_binding",
        "kind": "CHECK_BINDING",
        "src": {
            "check_exprs": [str(row.get("expr", "") or "") for row in checks],
        },
        "dst": {
            "root_expr": str(active_root.get("expr", "") or ""),
            "root_kind": str(active_root.get("kind", "") or ""),
        },
        "facts": [str(row.get("strength", "unknown") or "unknown") for row in checks] or ["unknown"],
        "snippet_keys": ["sink_function", "caller_bridge"],
    })

    segments.append({
        "segment_id": "sink_triggerability",
        "kind": "SINK_TRIGGERABILITY",
        "src": {
            "sink_label": sink_label,
            "sink_function": sink_function,
        },
        "dst": {
            "root_expr": str(active_root.get("expr", "") or ""),
            "root_kind": str(active_root.get("kind", "") or ""),
        },
        "facts": ["verdict_target"],
        "snippet_keys": ["sink_function", "caller_bridge", "producer_function"],
    })

    return segments


def _build_channel_path(chain: Mapping[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for step in chain.get("steps", []) or []:
        if str(step.get("kind", "")) != "CHANNEL":
            continue
        out.append({
            "edge": str(step.get("edge", "") or ""),
            "object_id": str(step.get("object_id", "") or ""),
            "evidence_refs": list(step.get("evidence_refs", []) or []),
        })
    return out


def _sink_semantics_hints(
    sink_label: str,
    sink_facts: Mapping[str, Any],
    active_root: Mapping[str, Any],
    derive_facts: Sequence[Mapping[str, Any]],
    checks: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    hints: Dict[str, Any] = {
        "root_kind": str(active_root.get("kind", "") or ""),
        "root_role": str(active_root.get("role", "") or ""),
    }
    if sink_label in {"COPY_SINK", "MEMSET_SINK", "STORE_SINK"}:
        for key in ("dst_expr", "src_expr", "len_expr", "target_expr", "store_expr"):
            val = sink_facts.get(key)
            if val not in (None, ""):
                hints[key] = val
    if sink_label == "FORMAT_STRING_SINK":
        hints["format_arg_expr"] = sink_facts.get("format_arg_expr") or active_root.get("expr", "")
        hints["format_arg_is_variable"] = bool(sink_facts.get("format_arg_is_variable"))
    if sink_label == "FUNC_PTR_SINK":
        for key in ("dispatch_index", "index_expr", "target_ptr", "func_ptr_expr"):
            val = sink_facts.get(key)
            if val not in (None, ""):
                hints[key] = val
    cap_candidates = []
    for chk in checks:
        expr = str(chk.get("expr", "") or "")
        if any(tok in expr.lower() for tok in ("sizeof", "max_", "bound", "limit", "capacity", "tailroom")):
            cap_candidates.append(expr)
    if cap_candidates:
        hints["dst_capacity_candidates"] = cap_candidates
    if derive_facts:
        hints["derive_exprs"] = [str(row.get("expr", "") or "") for row in derive_facts]
    return hints


def _guard_context(sink_facts: Mapping[str, Any], checks: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    guard_expr = sink_facts.get("guard_expr")
    if guard_expr:
        out.append({"expr": str(guard_expr), "site": "sink_function", "dominance": "claimed"})
    for chk in checks:
        expr = str(chk.get("expr", "") or "")
        if expr and expr not in {"unknown", "bounds_guard", "len_is_constant", "input_derived"}:
            out.append({
                "expr": expr,
                "site": str(chk.get("site", "") or ""),
                "dominance": "unknown",
            })
    return _dedup_dict_rows(out, key_fields=("expr", "site"))


def _capacity_evidence(
    sink_label: str,
    sink_facts: Mapping[str, Any],
    checks: Sequence[Mapping[str, Any]],
    active_root: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for key in ("dst_capacity", "buffer_size", "capacity_expr"):
        val = sink_facts.get(key)
        if val not in (None, ""):
            out.append({"expr": str(val), "site": "sink_facts", "kind": key})
    for chk in checks:
        expr = str(chk.get("expr", "") or "")
        if any(tok in expr.lower() for tok in ("sizeof", "max_", "bound", "limit", "capacity", "tailroom")):
            out.append({"expr": expr, "site": str(chk.get("site", "") or ""), "kind": "check_expr"})
    if not out and sink_label in {"COPY_SINK", "LOOP_WRITE_SINK", "STORE_SINK"}:
        root_expr = str(active_root.get("expr", "") or "")
        if root_expr:
            out.append({"expr": root_expr, "site": "root", "kind": "root_expr"})
    return _dedup_dict_rows(out, key_fields=("expr", "site", "kind"))


def _collect_snippets(
    chain: Mapping[str, Any],
    *,
    sink_function: str,
    decompiled_cache: Mapping[str, str],
) -> Dict[str, str]:
    debug = dict(chain.get("link_debug", {}) or {})
    source_steps = [dict(step) for step in (chain.get("steps", []) or []) if str(step.get("kind", "")) == "SOURCE"]
    producer_candidates = [str(fn) for fn in (debug.get("producer_candidates", []) or []) if str(fn)]
    bridge_functions = [str(fn) for fn in (debug.get("bridge_functions", []) or []) if str(fn)]

    sink_code = str(decompiled_cache.get(sink_function, "") or "")
    caller_blobs = []
    for fn in bridge_functions:
        code = str(decompiled_cache.get(fn, "") or "")
        if code:
            caller_blobs.append(f"/* {fn} */\n{code}")
    producer_blobs = []
    for fn in producer_candidates + [str(step.get("function", "") or "") for step in source_steps]:
        code = str(decompiled_cache.get(fn, "") or "")
        if code and fn not in sink_function:
            producer_blobs.append(f"/* {fn} */\n{code}")

    return {
        "sink_function": sink_code,
        "caller_bridge": "\n\n".join(dict.fromkeys(caller_blobs)),
        "producer_function": "\n\n".join(dict.fromkeys(producer_blobs)),
    }


def _deterministic_constraints(chain: Mapping[str, Any], decision_basis: Mapping[str, Any]) -> Dict[str, Any]:
    source_reached = bool(decision_basis.get("source_reached", any(str(step.get("kind", "")) == "SOURCE" for step in (chain.get("steps", []) or []))))
    has_channel = bool(decision_basis.get("has_channel", any(str(step.get("kind", "")) == "CHANNEL" for step in (chain.get("steps", []) or []))))
    root_bound = bool(decision_basis.get("chain_complete", False))
    object_bound = bool((chain.get("link_debug", {}) or {}).get("object_hits", [])) or has_channel
    channel_required = bool(decision_basis.get("channel_required_hint", False))
    return {
        "source_reached": source_reached,
        "object_bound": object_bound,
        "channel_required": channel_required,
        "channel_satisfied": (not channel_required) or has_channel,
        "root_bound": root_bound,
    }


def _deterministic_audit_flags(chain: Mapping[str, Any], *, sink_facts: Mapping[str, Any], checks: Sequence[Mapping[str, Any]]) -> List[str]:
    flags: List[str] = []
    debug = dict(chain.get("link_debug", {}) or {})
    decision_basis = dict(chain.get("decision_basis", {}) or {})
    if str(decision_basis.get("reason_code", "")) == "CHECK_UNCERTAIN":
        flags.append("check_not_binding_root")
    if decision_basis.get("channel_required_hint") and not decision_basis.get("has_channel"):
        flags.append("channel_inconsistency")
    if not sink_facts and not checks:
        flags.append("needs_more_context")
    if debug.get("active_root_expr") in {"UNKNOWN", "format_arg_variable", "indirect_call_target", "store_target"}:
        flags.append("root_mismatch")
    return sorted(set(flags))


def _risk_score(chain: Mapping[str, Any], decision_basis: Mapping[str, Any], checks: Sequence[Mapping[str, Any]]) -> float:
    score = float(chain.get("score", 0.0) or 0.0)
    if bool(decision_basis.get("root_controllable", False)):
        score += 0.12
    strength = str(decision_basis.get("check_strength", _strongest_check_strength(checks)) or "unknown")
    if strength == "absent":
        score += 0.12
    elif strength == "weak":
        score += 0.05
    elif strength == "effective":
        score -= 0.12
    if bool(decision_basis.get("channel_required_hint", False)) and bool(decision_basis.get("has_channel", False)):
        score += 0.05
    if str(decision_basis.get("reason_code", "")) in {"SEMANTIC_REVIEW_NEEDED", "LOW_CHAIN_SCORE"}:
        score += 0.04
    return max(0.0, min(1.0, score))


def _needs_review(
    *,
    current_verdict: str,
    risk_score: float,
    reason_code: str,
    audit_flags: Sequence[str],
    review_needs_threshold: float,
    soft_candidate: bool,
) -> bool:
    if audit_flags:
        return True
    if current_verdict == "SUSPICIOUS":
        return True
    if current_verdict == "DROP" and soft_candidate:
        return True
    if reason_code in {"CHECK_UNCERTAIN", "SEMANTIC_REVIEW_NEEDED", "LOW_CHAIN_SCORE"} and risk_score >= review_needs_threshold:
        return True
    return False


def _soft_candidate(chain: Mapping[str, Any], decision_basis: Mapping[str, Any], risk_score: float, *, min_risk_score: float) -> bool:
    if str(chain.get("verdict", "")) != "DROP":
        return False
    if str(decision_basis.get("reason_code", "")) in _HARD_BLOCK_REASON_CODES:
        return False
    if not bool(decision_basis.get("source_reached", False)):
        return False
    if not bool(decision_basis.get("chain_complete", False)):
        return False
    if not bool(decision_basis.get("root_controllable", False)):
        return False
    return risk_score >= float(min_risk_score)


def _derive_soft_verdict(strict_verdict: str, soft_candidate: bool) -> str:
    if strict_verdict == "DROP" and soft_candidate:
        return "SUSPICIOUS"
    return strict_verdict


def _review_state(current_verdict: str, needs_review: bool) -> str:
    if current_verdict == "CONFIRMED":
        return "exact"
    if current_verdict == "DROP" and not needs_review:
        return "closed"
    return "non_exact"


def _queue_predicate(
    item: Mapping[str, Any],
    *,
    calibration_mode: str,
    suspicious_ratio: float,
    suspicious_ratio_threshold: float,
) -> Tuple[bool, List[str]]:
    verdict = str(item.get("current_verdict", "") or "")
    review_state = str(item.get("review_state", "") or "")
    needs_review = bool(item.get("needs_review", False))
    soft_candidate = bool(item.get("soft_candidate", False))
    reasons: List[str] = []

    if calibration_mode == "audit_only":
        if needs_review or item.get("audit_flags"):
            reasons.append("audit_only")
            return True, reasons
        return False, reasons
    if calibration_mode == "suspicious_only":
        if verdict == "SUSPICIOUS":
            reasons.append("suspicious_verdict")
        if needs_review:
            reasons.append("needs_review")
        return bool(reasons), reasons
    if calibration_mode == "all_non_exact":
        if review_state != "exact":
            reasons.append("non_exact_verdict")
        if suspicious_ratio >= suspicious_ratio_threshold:
            reasons.append("sample_suspicious_ratio")
        return bool(reasons), reasons
    if calibration_mode == "all_matched":
        if verdict != "DROP" or soft_candidate:
            reasons.append("all_matched_mode")
            return True, reasons
        return False, reasons
    # exact_mismatch fallback without GT-aware mismatch data: treat review-needed non-exacts as candidates.
    if review_state != "exact" and needs_review:
        reasons.append("exact_mismatch_fallback")
        return True, reasons
    return False, reasons


def _summarize_soft_triage(rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    stats = {
        "strict_confirmed": 0,
        "strict_suspicious": 0,
        "strict_safe_or_low_risk": 0,
        "strict_drop": 0,
        "soft_confirmed": 0,
        "soft_suspicious": 0,
        "soft_safe_or_low_risk": 0,
        "soft_drop": 0,
        "final_confirmed": 0,
        "final_suspicious": 0,
        "final_safe_or_low_risk": 0,
        "final_drop": 0,
        "needs_review": 0,
        "llm_reviewed": 0,
        "queue_eligible": 0,
    }
    for row in rows:
        stats_key = f"strict_{str(row.get('strict_verdict', '')).lower()}"
        if stats_key in stats:
            stats[stats_key] += 1
        stats_key = f"soft_{str(row.get('soft_verdict', '')).lower()}"
        if stats_key in stats:
            stats[stats_key] += 1
        stats_key = f"final_{str(row.get('final_verdict', '')).lower()}"
        if stats_key in stats:
            stats[stats_key] += 1
        if row.get("needs_review"):
            stats["needs_review"] += 1
        if row.get("llm_reviewed"):
            stats["llm_reviewed"] += 1
        if row.get("queue_eligible"):
            stats["queue_eligible"] += 1
    return stats


def _root_family(root: Mapping[str, Any]) -> str:
    kind = str(root.get("kind", "") or "").lower()
    if kind in {"length", "index_or_bound"}:
        return "length"
    if kind in {"format_arg"}:
        return "format_arg"
    if kind in {"dispatch", "funcptr"}:
        return "dispatch"
    if kind in {"dst_ptr", "src_ptr", "src_data", "target_addr"}:
        return "pointer"
    return kind or "unknown"


def _strongest_check_strength(checks: Sequence[Mapping[str, Any]]) -> str:
    order = {"effective": 3, "weak": 2, "absent": 1, "unknown": 0}
    best = "unknown"
    best_rank = -1
    for row in checks:
        cur = str(row.get("strength", "unknown") or "unknown")
        rank = order.get(cur, 0)
        if rank > best_rank:
            best_rank = rank
            best = cur
    return best


def _deterministic_constraints_for_reason(decision_basis: Mapping[str, Any]) -> bool:
    return bool(decision_basis.get("source_reached")) and bool(decision_basis.get("chain_complete"))


def _sink_site_key(site_hex: str, fn: str, label: str) -> str:
    return f"{site_hex}|{fn}|{label}"


def _normalize_calibration_mode(mode: str) -> str:
    text = str(mode or DEFAULT_CALIBRATION_MODE)
    return text if text in _ALLOWED_CALIBRATION_MODES else DEFAULT_CALIBRATION_MODE


def _normalize_output_mode(mode: str) -> str:
    text = str(mode or DEFAULT_VERDICT_OUTPUT_MODE)
    return text if text in _ALLOWED_OUTPUT_MODES else DEFAULT_VERDICT_OUTPUT_MODE


def _dedup_dict_rows(rows: Iterable[Dict[str, Any]], *, key_fields: Sequence[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    for row in rows:
        key = tuple(str(row.get(field, "") or "") for field in key_fields)
        if key in seen:
            continue
        seen.add(key)
        out.append(dict(row))
    return out


def _verdict_rank(verdict: str) -> int:
    return {
        "DROP": 0,
        "SAFE_OR_LOW_RISK": 1,
        "SUSPICIOUS": 2,
        "CONFIRMED": 3,
    }.get(str(verdict or ""), 0)
