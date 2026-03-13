"""Reusable Phase B diagnostic mode."""

from __future__ import annotations

from typing import Any, Dict, Optional, Sequence

from sourceagent.agents.review_plan import build_review_plan
from sourceagent.agents.review_runner import (
    DEFAULT_REVIEW_TIMEOUT_SEC,
    run_review_plan,
)
from sourceagent.pipeline.phaseb_diagnostic_inputs import load_phaseb_diagnostic_bundle
from sourceagent.pipeline.phaseb_diagnostic_report import (
    build_phaseb_diagnostic_summary,
    render_phaseb_diagnostic_markdown,
    write_phaseb_diagnostic_outputs,
)
from sourceagent.pipeline.verdict_calibration import (
    DEFAULT_ALLOW_MANUAL_LLM_SUPERVISION,
    DEFAULT_LLM_DEMOTE_BUDGET,
    DEFAULT_LLM_PROMOTE_BUDGET,
    DEFAULT_LLM_SOFT_BUDGET,
    DEFAULT_MIN_RISK_SCORE,
    DEFAULT_REVIEW_ALLOW_SOFT_ON_STRUCTURAL_GAP,
    DEFAULT_REVIEW_PRESERVE_REJECTED_RATIONALE,
    DEFAULT_REVIEW_SOFT_GATES,
    DEFAULT_REVIEW_STRICT_GATES,
    apply_review_decisions_to_feature_pack,
)

SCHEMA_VERSION = "0.1"


async def run_phaseb_diagnostic(
    *,
    diagnostic_source: str,
    eval_dir: str | None = None,
    sample: str | None = None,
    chain_ids: Optional[Sequence[str]] = None,
    diagnostic_json: str | None = None,
    gt_root: str | None = None,
    include_related: bool = True,
    include_supporting: bool = True,
    include_peripheral_suspicious: bool = False,
    review_model: str | None = None,
    review_mode: str = "semantic",
    review_tool_mode: str = "prompt_only",
    batch_size: int = 1,
    max_items: int = 0,
    timeout_sec: int = DEFAULT_REVIEW_TIMEOUT_SEC,
    mcp_manager: object | None = None,
    ghidra_binary_name: str = "",
    output_dir: str | None = None,
    allow_manual_llm_supervision: bool = DEFAULT_ALLOW_MANUAL_LLM_SUPERVISION,
    llm_promote_budget: int = DEFAULT_LLM_PROMOTE_BUDGET,
    llm_demote_budget: int = DEFAULT_LLM_DEMOTE_BUDGET,
    llm_soft_budget: int = DEFAULT_LLM_SOFT_BUDGET,
    review_strict_gates: Sequence[str] = DEFAULT_REVIEW_STRICT_GATES,
    review_soft_gates: Sequence[str] = DEFAULT_REVIEW_SOFT_GATES,
    review_allow_soft_on_structural_gap: bool = DEFAULT_REVIEW_ALLOW_SOFT_ON_STRUCTURAL_GAP,
    review_preserve_rejected_rationale: bool = DEFAULT_REVIEW_PRESERVE_REJECTED_RATIONALE,
    min_risk_score: float = DEFAULT_MIN_RISK_SCORE,
) -> Dict[str, Any]:
    bundle = load_phaseb_diagnostic_bundle(
        diagnostic_source=diagnostic_source,
        eval_dir=eval_dir,
        sample=sample,
        chain_ids=chain_ids,
        diagnostic_json=diagnostic_json,
        gt_root=gt_root,
        include_related=include_related,
        include_supporting=include_supporting,
        include_peripheral_suspicious=include_peripheral_suspicious,
    )
    feature_items = [dict(item.get("feature_item", {}) or {}) for item in (bundle.get("items", []) or [])]
    queue_items = [dict(item.get("queue_item", {}) or {}) for item in (bundle.get("items", []) or [])]
    feature_pack = {
        "schema_version": SCHEMA_VERSION,
        "binary": bundle.get("binary", ""),
        "binary_sha256": bundle.get("binary_sha256", ""),
        "mode": bundle.get("calibration_mode", ""),
        "output_mode": bundle.get("verdict_output_mode", ""),
        "items": feature_items,
        "status": "ok" if feature_items else "empty",
    }
    calibration_queue = {
        "schema_version": SCHEMA_VERSION,
        "binary": bundle.get("binary", ""),
        "binary_sha256": bundle.get("binary_sha256", ""),
        "mode": bundle.get("calibration_mode", ""),
        "output_mode": bundle.get("verdict_output_mode", ""),
        "items": queue_items,
        "status": "ok" if queue_items else "empty",
    }

    review_plan = build_review_plan(
        feature_pack,
        calibration_queue,
        review_mode=review_mode,
        review_tool_mode=review_tool_mode,
        max_items=int(max_items or len(feature_items) or 0),
        batch_size=max(1, int(batch_size or 1)),
    )
    review_run = await run_review_plan(
        review_plan,
        model=review_model,
        review_mode=review_mode,
        review_tool_mode=review_tool_mode,
        timeout_sec=int(timeout_sec or DEFAULT_REVIEW_TIMEOUT_SEC),
        mcp_manager=mcp_manager,
        ghidra_binary_name=ghidra_binary_name,
    )
    calibration_outputs = apply_review_decisions_to_feature_pack(
        feature_pack=feature_pack,
        calibration_queue=calibration_queue,
        review_decisions=list(review_run.get("review_decisions", []) or []),
        calibration_mode=str(bundle.get("calibration_mode", "") or ""),
        verdict_output_mode=str(bundle.get("verdict_output_mode", "") or ""),
        allow_manual_llm_supervision=allow_manual_llm_supervision,
        llm_promote_budget=int(llm_promote_budget),
        llm_demote_budget=int(llm_demote_budget),
        llm_soft_budget=int(llm_soft_budget),
        review_strict_gates=review_strict_gates,
        review_soft_gates=review_soft_gates,
        review_allow_soft_on_structural_gap=review_allow_soft_on_structural_gap,
        review_preserve_rejected_rationale=review_preserve_rejected_rationale,
        min_risk_score=float(min_risk_score),
    )
    summary = build_phaseb_diagnostic_summary(
        bundle=bundle,
        review_plan=review_plan,
        review_run=review_run,
        calibration_outputs=calibration_outputs,
    )
    markdown = render_phaseb_diagnostic_markdown(summary)
    if output_dir:
        write_phaseb_diagnostic_outputs(
            output_dir=output_dir,
            bundle=bundle,
            review_plan=review_plan,
            review_run=review_run,
            calibration_outputs=calibration_outputs,
            summary=summary,
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "bundle": bundle,
        "review_plan": review_plan,
        "review_run": review_run,
        "calibration_outputs": calibration_outputs,
        "summary": summary,
        "summary_markdown": markdown,
    }
