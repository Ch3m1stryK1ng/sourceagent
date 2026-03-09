"""Schema helpers for semantic review decisions."""

from __future__ import annotations

import json
import re
from json import JSONDecoder
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

REVIEW_SCHEMA_VERSION = "0.1"
_ALLOWED_VERDICTS = {"SAFE_OR_LOW_RISK", "SUSPICIOUS", "CONFIRMED"}


def extract_json_payload(text: str) -> Any:
    """Best-effort extraction of a JSON object/array from model output."""
    raw = str(text or "").strip()
    if not raw:
        raise ValueError("empty_review_response")

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


def normalize_review_response(
    payload: Any,
    *,
    default_review_mode: str,
    allowed_chain_ids: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    items = _payload_items(payload)
    allowed = {str(v) for v in (allowed_chain_ids or []) if str(v)} or None
    out: List[Dict[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        chain_id = str(item.get("chain_id", "") or "").strip()
        if not chain_id:
            continue
        if allowed is not None and chain_id not in allowed:
            continue
        suggested = str(item.get("suggested_semantic_verdict", "") or "").strip().upper()
        if suggested not in _ALLOWED_VERDICTS:
            continue
        out.append({
            "chain_id": chain_id,
            "suggested_semantic_verdict": suggested,
            "trigger_summary": str(item.get("trigger_summary", "") or "").strip(),
            "preconditions": _normalize_preconditions(item.get("preconditions")),
            "evidence_map": _normalize_evidence_map(item.get("evidence_map")),
            "audit_flags": _normalize_str_list(item.get("audit_flags")),
            "manual_supervision": bool(item.get("manual_supervision", False)),
            "review_mode": str(item.get("review_mode", default_review_mode) or default_review_mode),
            "confidence": _normalize_confidence(item.get("confidence")),
            "review_notes": str(item.get("review_notes", "") or "").strip(),
        })
    return out


def parse_review_response(
    text: str,
    *,
    default_review_mode: str,
    allowed_chain_ids: Optional[Iterable[str]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    try:
        payload = extract_json_payload(text)
    except Exception as exc:
        return [], {
            "ok": False,
            "error": str(exc),
            "raw_excerpt": str(text or "")[:2000],
        }
    decisions = normalize_review_response(
        payload,
        default_review_mode=default_review_mode,
        allowed_chain_ids=allowed_chain_ids,
    )
    return decisions, {
        "ok": True,
        "decision_count": len(decisions),
    }


def _payload_items(payload: Any) -> List[Any]:
    if isinstance(payload, list):
        return list(payload)
    if isinstance(payload, Mapping):
        if isinstance(payload.get("decisions"), list):
            return list(payload.get("decisions") or [])
        if isinstance(payload.get("items"), list):
            return list(payload.get("items") or [])
        required = payload.get("required_output")
        if isinstance(required, Mapping):
            if isinstance(required.get("decisions"), list):
                return list(required.get("decisions") or [])
            if isinstance(required.get("items"), list):
                return list(required.get("items") or [])
        output = payload.get("output")
        if isinstance(output, Mapping):
            if isinstance(output.get("decisions"), list):
                return list(output.get("decisions") or [])
            if isinstance(output.get("items"), list):
                return list(output.get("items") or [])
        return [payload]
    return []


def _candidate_json_strings(text: str) -> List[str]:
    candidates: List[str] = [text]
    fence_matches = re.findall(r"```(?:json)?\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
    for match in fence_matches:
        if match.strip():
            candidates.append(match.strip())
    return candidates


def _normalize_preconditions(value: Any) -> Dict[str, List[str]]:
    if not isinstance(value, Mapping):
        return {
            "state_predicates": [],
            "root_constraints": [],
            "why_check_fails": [],
        }
    return {
        "state_predicates": _normalize_str_list(value.get("state_predicates")),
        "root_constraints": _normalize_str_list(value.get("root_constraints")),
        "why_check_fails": _normalize_str_list(value.get("why_check_fails")),
    }


def _normalize_evidence_map(value: Any) -> Dict[str, List[str]]:
    if not isinstance(value, Mapping):
        return {}
    out: Dict[str, List[str]] = {}
    for k, refs in value.items():
        key = str(k or "").strip()
        if not key:
            continue
        ref_list = _normalize_str_list(refs)
        if ref_list:
            out[key] = ref_list
    return out


def _normalize_str_list(value: Any) -> List[str]:
    if isinstance(value, str):
        s = value.strip()
        return [s] if s else []
    if not isinstance(value, Sequence):
        return []
    out: List[str] = []
    for item in value:
        s = str(item or "").strip()
        if s:
            out.append(s)
    return out


def _normalize_confidence(value: Any) -> Optional[float]:
    try:
        if value is None or value == "":
            return None
        num = float(value)
        return max(0.0, min(1.0, num))
    except Exception:
        return None
