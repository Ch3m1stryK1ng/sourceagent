"""LLM-backed semantic review runner for verdict calibration."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
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


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _jsonable(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return {}


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
            "review_prompt": {
                "schema_version": "0.1",
                "review_mode": review_mode,
                "status": "empty",
                "batches": [],
            },
            "review_raw_response": {
                "schema_version": "0.1",
                "review_mode": review_mode,
                "status": "empty",
                "batches": [],
            },
            "review_session": {
                "schema_version": "0.1",
                "review_mode": review_mode,
                "status": "empty",
                "decision_count": 0,
                "batches": [],
            },
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
            "review_prompt": {
                "schema_version": "0.1",
                "review_mode": review_mode,
                "status": "skipped_unconfigured",
                "reason": "missing_model",
                "batches": [],
            },
            "review_raw_response": {
                "schema_version": "0.1",
                "review_mode": review_mode,
                "status": "skipped_unconfigured",
                "reason": "missing_model",
                "batches": [],
            },
            "review_session": {
                "schema_version": "0.1",
                "review_mode": review_mode,
                "status": "skipped_unconfigured",
                "reason": "missing_model",
                "decision_count": 0,
                "batches": [],
            },
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
    prompt_batches: List[Dict[str, Any]] = []
    raw_response_batches: List[Dict[str, Any]] = []
    session_batches: List[Dict[str, Any]] = []
    trace_batches: List[Dict[str, Any]] = []

    for batch in batches:
        batch_id = str(batch.get("batch_id", "") or "")
        chain_ids = [str(v) for v in (batch.get("chain_ids", []) or []) if str(v)]
        prompt = _semantic_prompt(batch, review_mode=review_mode)
        prompt_batches.append({
            "batch_id": batch_id,
            "chain_ids": chain_ids,
            "created_at": _now_iso(),
            "model": chosen_model,
            "system_prompt": _SYSTEM_PROMPT,
            "user_prompt": prompt,
        })
        try:
            response = await asyncio.wait_for(
                llm.generate(
                    system_prompt=_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                    tools=None,
                ),
                timeout=max(1, int(timeout_sec)),
            )
            text = str(response.content or "")
            decisions, meta = parse_review_response(
                text,
                default_review_mode=("audit_only" if review_mode == "audit_only" else "semantic_review"),
                allowed_chain_ids=chain_ids,
            )
            all_decisions.extend(decisions)
            raw_response_batches.append({
                "batch_id": batch_id,
                "chain_ids": chain_ids,
                "created_at": _now_iso(),
                "ok": bool(meta.get("ok", False)),
                "model": str(response.model or chosen_model),
                "finish_reason": str(response.finish_reason or ""),
                "usage": _jsonable(response.usage or {}),
                "raw_text": text,
                "error": meta.get("error", ""),
            })
            session_batches.append({
                "batch_id": batch_id,
                "chain_ids": chain_ids,
                "ok": bool(meta.get("ok", False)),
                "model": str(response.model or chosen_model),
                "finish_reason": str(response.finish_reason or ""),
                "decision_count": len(decisions),
                "parsed_decisions": decisions,
                "error": meta.get("error", ""),
            })
            trace_batches.append({
                "batch_id": batch_id,
                "chain_ids": chain_ids,
                "ok": bool(meta.get("ok", False)),
                "decision_count": len(decisions),
                "model": str(response.model or chosen_model),
                "raw_excerpt": str(text or "")[:4000],
                "error": meta.get("error", ""),
            })
        except Exception as exc:
            raw_response_batches.append({
                "batch_id": batch_id,
                "chain_ids": chain_ids,
                "created_at": _now_iso(),
                "ok": False,
                "model": chosen_model,
                "finish_reason": "error",
                "usage": {},
                "raw_text": "",
                "error": str(exc),
            })
            session_batches.append({
                "batch_id": batch_id,
                "chain_ids": chain_ids,
                "ok": False,
                "model": chosen_model,
                "finish_reason": "error",
                "decision_count": 0,
                "parsed_decisions": [],
                "error": str(exc),
            })
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
        "review_prompt": {
            "schema_version": "0.1",
            "review_mode": review_mode,
            "model": chosen_model,
            "status": "ok" if prompt_batches else "empty",
            "batches": prompt_batches,
        },
        "review_raw_response": {
            "schema_version": "0.1",
            "review_mode": review_mode,
            "model": chosen_model,
            "status": "ok" if raw_response_batches else "empty",
            "decision_count": len(all_decisions),
            "batches": raw_response_batches,
        },
        "review_session": {
            "schema_version": "0.1",
            "review_mode": review_mode,
            "model": chosen_model,
            "status": "ok" if any(batch.get("ok") for batch in session_batches) else "error",
            "decision_count": len(all_decisions),
            "plan_summary": {
                "item_count": len(items),
                "batch_count": len(batches),
                "chain_ids": [str(item.get("chain_id", "") or "") for item in items if str(item.get("chain_id", "") or "")],
            },
            "batches": session_batches,
        },
        "review_trace": {
            "schema_version": "0.1",
            "review_mode": review_mode,
            "model": chosen_model,
            "status": "ok" if any(batch.get("ok") for batch in trace_batches) else "error",
            "decision_count": len(all_decisions),
            "batches": trace_batches,
        },
    }
