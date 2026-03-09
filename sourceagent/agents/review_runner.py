"""LLM-backed semantic review runner for verdict calibration."""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Mapping, Optional

from sourceagent.config.settings import get_settings
from sourceagent.llm.llm import LLM
from sourceagent.llm.review_schema import parse_review_response

DEFAULT_REVIEW_TIMEOUT_SEC = 120

_SYSTEM_PROMPT = """You are a semantic firmware vulnerability reviewer.
Deterministic facts from SourceAgent are authoritative and must not be contradicted.
Do not infer or rewrite source reachability, object binding, channel traversal, or root matching.
Your job is only to judge exploitability semantics for already-assembled chains.
Return JSON only.
"""


def _semantic_prompt(batch: Mapping[str, Any], *, review_mode: str) -> str:
    mode_text = (
        "Audit only. Keep the current verdict unless there is an explicit semantic inconsistency worth flagging. "
        "Focus on audit_flags and weak or missing semantic checks."
        if review_mode == "audit_only"
        else "Review each chain semantically and choose SAFE_OR_LOW_RISK, SUSPICIOUS, or CONFIRMED."
    )
    contract = {
        "required_output": {
            "decisions": [
                {
                    "chain_id": "string",
                    "suggested_semantic_verdict": "SAFE_OR_LOW_RISK|SUSPICIOUS|CONFIRMED",
                    "trigger_summary": "one sentence",
                    "preconditions": {
                        "state_predicates": ["..."],
                        "root_constraints": ["..."],
                        "why_check_fails": ["..."],
                    },
                    "evidence_map": {
                        "trigger_summary": ["sink_function", "caller_bridge", "producer_function"],
                        "root_controllability": ["sink_function"],
                    },
                    "audit_flags": ["CHECK_NOT_BINDING_ROOT"],
                    "confidence": 0.0,
                    "review_mode": "semantic_review"
                }
            ]
        },
        "constraints": [
            "Only cite snippet keys: sink_function, caller_bridge, producer_function",
            "Do not leave evidence_map empty",
            "Do not invent facts absent from the provided items",
            "If evidence is weak, prefer SUSPICIOUS over CONFIRMED",
            "If review_mode is audit_only, keep the current verdict unless absolutely necessary",
        ],
        "task": mode_text,
        "batch": batch,
    }
    return json.dumps(contract, indent=2, ensure_ascii=True)


async def run_review_plan(
    review_plan: Mapping[str, Any],
    *,
    model: Optional[str] = None,
    review_mode: str = "semantic",
    timeout_sec: int = DEFAULT_REVIEW_TIMEOUT_SEC,
) -> Dict[str, Any]:
    items = list((review_plan or {}).get("items", []) or [])
    batches = list((review_plan or {}).get("batches", []) or [])
    if not items:
        return {
            "review_decisions": [],
            "review_trace": {
                "schema_version": "0.1",
                "review_mode": review_mode,
                "status": "empty",
                "batches": [],
            },
        }

    settings = get_settings()
    chosen_model = str(model or settings.model or "").strip()
    if not chosen_model:
        return {
            "review_decisions": [],
            "review_trace": {
                "schema_version": "0.1",
                "review_mode": review_mode,
                "status": "skipped_unconfigured",
                "reason": "missing_model",
                "batches": [],
            },
        }

    llm = LLM(model=chosen_model)
    all_decisions: List[Dict[str, Any]] = []
    trace_batches: List[Dict[str, Any]] = []

    for batch in batches:
        batch_id = str(batch.get("batch_id", "") or "")
        chain_ids = [str(v) for v in (batch.get("chain_ids", []) or []) if str(v)]
        prompt = _semantic_prompt(batch, review_mode=review_mode)
        try:
            text = await asyncio.wait_for(
                llm.simple_completion(prompt, system=_SYSTEM_PROMPT),
                timeout=max(1, int(timeout_sec)),
            )
            decisions, meta = parse_review_response(
                text,
                default_review_mode=("audit_only" if review_mode == "audit_only" else "semantic_review"),
                allowed_chain_ids=chain_ids,
            )
            all_decisions.extend(decisions)
            trace_batches.append({
                "batch_id": batch_id,
                "chain_ids": chain_ids,
                "ok": bool(meta.get("ok", False)),
                "decision_count": len(decisions),
                "model": chosen_model,
                "raw_excerpt": str(text or "")[:4000],
                "error": meta.get("error", ""),
            })
        except Exception as exc:
            trace_batches.append({
                "batch_id": batch_id,
                "chain_ids": chain_ids,
                "ok": False,
                "decision_count": 0,
                "model": chosen_model,
                "raw_excerpt": "",
                "error": str(exc),
            })

    return {
        "review_decisions": all_decisions,
        "review_trace": {
            "schema_version": "0.1",
            "review_mode": review_mode,
            "model": chosen_model,
            "status": "ok" if any(batch.get("ok") for batch in trace_batches) else "error",
            "decision_count": len(all_decisions),
            "batches": trace_batches,
        },
    }
