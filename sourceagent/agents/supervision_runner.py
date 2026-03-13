"""Internal runner for Phase A.5 sink supervision."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence

from sourceagent.config.settings import get_settings
from sourceagent.llm.llm import LLM
from sourceagent.agents.supervision_prompt import (
    SUPERVISION_SYSTEM_PROMPT,
    SUPERVISION_TRANSCRIPT_SCHEMA_VERSION,
    build_supervision_prompt,
)
from sourceagent.llm.supervision_schema import parse_supervision_response

DEFAULT_SUPERVISION_BATCH_SIZE = 4
DEFAULT_SUPERVISION_TIMEOUT_SEC = 240


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _jsonable(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return {}


def build_supervision_batches(
    supervision_queue: Mapping[str, Any],
    *,
    batch_size: int = DEFAULT_SUPERVISION_BATCH_SIZE,
) -> Dict[str, Any]:
    items = [dict(item) for item in (supervision_queue or {}).get("items", []) or []]
    batches: List[Dict[str, Any]] = []
    for idx in range(0, len(items), max(1, int(batch_size or 1))):
        chunk = items[idx: idx + max(1, int(batch_size or 1))]
        batches.append({
            "batch_id": f"batch_{idx // max(1, int(batch_size or 1)):03d}",
            "item_ids": [str(item.get("item_id", "") or "") for item in chunk],
            "items": chunk,
        })
    return {
        "schema_version": SUPERVISION_TRANSCRIPT_SCHEMA_VERSION,
        "scope": str((supervision_queue or {}).get("scope", "sinks") or "sinks"),
        "status": "ok" if items else "empty",
        "items": items,
        "batches": batches,
    }


async def run_supervision_plan(
    supervision_plan: Mapping[str, Any],
    *,
    model: Optional[str] = None,
    timeout_sec: int = DEFAULT_SUPERVISION_TIMEOUT_SEC,
) -> Dict[str, Any]:
    items = [dict(item) for item in (supervision_plan or {}).get("items", []) or []]
    batches = [dict(batch) for batch in (supervision_plan or {}).get("batches", []) or []]
    if not items:
        empty = {
            "schema_version": SUPERVISION_TRANSCRIPT_SCHEMA_VERSION,
            "status": "empty",
            "items": [],
            "batches": [],
        }
        return {
            "supervision_decisions": [],
            "supervision_prompt": dict(empty),
            "supervision_raw_response": dict(empty),
            "supervision_session": {
                **dict(empty),
                "decision_count": 0,
            },
            "supervision_trace": dict(empty),
        }

    settings = get_settings()
    chosen_model = str(model or settings.model or "").strip()
    if not chosen_model:
        skipped = {
            "schema_version": SUPERVISION_TRANSCRIPT_SCHEMA_VERSION,
            "status": "skipped_unconfigured",
            "reason": "missing_model",
            "items": items,
            "batches": batches,
        }
        return {
            "supervision_decisions": [],
            "supervision_prompt": dict(skipped),
            "supervision_raw_response": dict(skipped),
            "supervision_session": {**dict(skipped), "decision_count": 0},
            "supervision_trace": dict(skipped),
        }

    llm = LLM(model=chosen_model)
    all_decisions: List[Dict[str, Any]] = []
    prompt_batches: List[Dict[str, Any]] = []
    raw_batches: List[Dict[str, Any]] = []
    session_batches: List[Dict[str, Any]] = []
    trace_batches: List[Dict[str, Any]] = []

    for batch in batches:
        batch_id = str(batch.get("batch_id", "") or "")
        item_ids = [str(v) for v in (batch.get("item_ids", []) or []) if str(v)]
        targets = []
        for item in batch.get("items", []) or []:
            ctx = dict(item.get("context", {}) or {})
            label = str(item.get("proposed_label", "") or "")
            targets.append(f"{ctx.get('function', '?')}[{label}]")
        if targets:
            print(
                f"[Stage 10] Supervision batch {batch_id}: reviewing {len(item_ids)} sink candidates for "
                f"{', '.join(targets[:4])}"
            )
        prompt = build_supervision_prompt(batch)
        prompt_batches.append({
            "batch_id": batch_id,
            "item_ids": item_ids,
            "created_at": _now_iso(),
            "model": chosen_model,
            "system_prompt": SUPERVISION_SYSTEM_PROMPT,
            "user_prompt": prompt,
        })
        try:
            response = await asyncio.wait_for(
                llm.generate(
                    system_prompt=SUPERVISION_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                    tools=None,
                ),
                timeout=max(1, int(timeout_sec)),
            )
            text = str(response.content or "")
            decisions, meta = parse_supervision_response(text, allowed_item_ids=item_ids)
            all_decisions.extend(decisions)
            raw_batches.append({
                "batch_id": batch_id,
                "item_ids": item_ids,
                "created_at": _now_iso(),
                "model": str(getattr(response, "model", "") or chosen_model),
                "raw_text": text,
                "usage": _jsonable(getattr(response, "usage", None)),
                "finish_reason": str(getattr(response, "finish_reason", "") or ""),
            })
            session_batches.append({
                "batch_id": batch_id,
                "item_ids": item_ids,
                "decision_count": len(decisions),
                "ok": bool(meta.get("ok", False)),
                "reviewed_at": _now_iso(),
            })
            trace_batches.append({
                "batch_id": batch_id,
                "item_ids": item_ids,
                "ok": bool(meta.get("ok", False)),
                "decision_count": len(decisions),
                "raw_excerpt": text[:2000],
            })
        except Exception as exc:
            raw_batches.append({
                "batch_id": batch_id,
                "item_ids": item_ids,
                "created_at": _now_iso(),
                "model": chosen_model,
                "error": str(exc),
                "raw_text": "",
            })
            session_batches.append({
                "batch_id": batch_id,
                "item_ids": item_ids,
                "decision_count": 0,
                "ok": False,
                "error": str(exc),
                "reviewed_at": _now_iso(),
            })
            trace_batches.append({
                "batch_id": batch_id,
                "item_ids": item_ids,
                "ok": False,
                "decision_count": 0,
                "error": str(exc),
            })

    status = "ok" if all_decisions else "empty"
    return {
        "supervision_decisions": all_decisions,
        "supervision_prompt": {
            "schema_version": SUPERVISION_TRANSCRIPT_SCHEMA_VERSION,
            "status": status,
            "items": items,
            "batches": prompt_batches,
        },
        "supervision_raw_response": {
            "schema_version": SUPERVISION_TRANSCRIPT_SCHEMA_VERSION,
            "status": status,
            "items": items,
            "batches": raw_batches,
        },
        "supervision_session": {
            "schema_version": SUPERVISION_TRANSCRIPT_SCHEMA_VERSION,
            "status": status,
            "decision_count": len(all_decisions),
            "items": items,
            "batches": session_batches,
        },
        "supervision_trace": {
            "schema_version": SUPERVISION_TRANSCRIPT_SCHEMA_VERSION,
            "status": status,
            "items": items,
            "batches": trace_batches,
        },
    }
