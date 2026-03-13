"""Schema helpers for Phase A.5 supervision decisions."""

from __future__ import annotations

import json
import re
from json import JSONDecoder
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from sourceagent.pipeline.supervision_reason_codes import normalize_supervision_reason_codes

SUPERVISION_SCHEMA_VERSION = "0.1"
_ALLOWED_DECISIONS = {"accept", "reject", "uncertain"}


def extract_json_payload(text: str) -> Any:
    raw = str(text or "").strip()
    if not raw:
        raise ValueError("empty_supervision_response")

    for candidate in _candidate_json_strings(raw):
        try:
            return json.loads(candidate)
        except Exception:
            continue

    decoder = JSONDecoder()
    for idx, ch in enumerate(raw):
        if ch not in "[{":
            continue
        try:
            payload, _ = decoder.raw_decode(raw[idx:])
            return payload
        except Exception:
            continue
    raise ValueError("no_json_payload_found")


def normalize_supervision_response(
    payload: Any,
    *,
    allowed_item_ids: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    items = _payload_items(payload)
    allowed = {str(v) for v in (allowed_item_ids or []) if str(v)} or None
    out: List[Dict[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        item_id = str(item.get("item_id", "") or "").strip()
        if not item_id:
            continue
        if allowed is not None and item_id not in allowed:
            continue
        decision = str(item.get("decision", "") or "").strip().lower()
        if decision not in _ALLOWED_DECISIONS:
            continue
        out.append({
            "item_id": item_id,
            "decision": decision,
            "final_label": str(item.get("final_label", "") or "").strip(),
            "arg_roles": _normalize_arg_roles(item.get("arg_roles")),
            "reason_codes": normalize_supervision_reason_codes(item.get("reason_codes") or []),
            "evidence_map": _normalize_evidence_map(item.get("evidence_map")),
            "confidence": _normalize_confidence(item.get("confidence")),
            "review_notes": str(item.get("review_notes", "") or "").strip(),
        })
    return out


def parse_supervision_response(
    text: str,
    *,
    allowed_item_ids: Optional[Iterable[str]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    try:
        payload = extract_json_payload(text)
    except Exception as exc:
        return [], {
            "ok": False,
            "error": str(exc),
            "raw_excerpt": str(text or "")[:2000],
        }
    decisions = normalize_supervision_response(payload, allowed_item_ids=allowed_item_ids)
    return decisions, {
        "ok": True,
        "decision_count": len(decisions),
    }


def _payload_items(payload: Any) -> List[Any]:
    if isinstance(payload, list):
        return list(payload)
    if isinstance(payload, Mapping):
        if isinstance(payload.get("items"), list):
            return list(payload.get("items") or [])
        if isinstance(payload.get("decisions"), list):
            return list(payload.get("decisions") or [])
        return [payload]
    return []


def _candidate_json_strings(text: str) -> List[str]:
    candidates: List[str] = [text]
    fence_matches = re.findall(r"```(?:json)?\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
    for match in fence_matches:
        if match.strip():
            candidates.append(match.strip())
    return candidates


def _normalize_arg_roles(value: Any) -> Dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    out: Dict[str, str] = {}
    for key, raw in value.items():
        k = str(key or "").strip()
        v = str(raw or "").strip()
        if k and v:
            out[k] = v
    return out


def _normalize_evidence_map(value: Any) -> Dict[str, List[str]]:
    if not isinstance(value, Mapping):
        return {}
    out: Dict[str, List[str]] = {}
    for key, refs in value.items():
        k = str(key or "").strip()
        if not k:
            continue
        if isinstance(refs, str):
            vals = [refs.strip()] if refs.strip() else []
        elif isinstance(refs, Sequence):
            vals = [str(v).strip() for v in refs if str(v).strip()]
        else:
            vals = []
        if vals:
            out[k] = vals
    return out


def _normalize_confidence(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except Exception:
        return 0.0
