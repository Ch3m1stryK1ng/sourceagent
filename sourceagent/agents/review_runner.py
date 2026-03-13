"""LLM-backed semantic review runner for verdict calibration."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from sourceagent.config.settings import get_settings
from sourceagent.llm.llm import LLM
from sourceagent.agents.review_context_ranker import (
    KEY_CHAR_LIMITS,
    build_review_context_plan,
    expand_review_context_plan,
    should_request_second_pass,
)
from sourceagent.llm.review_schema import parse_review_response
from sourceagent.pipeline.review_reason_codes import PROMPT_REASON_CODES

logger = logging.getLogger(__name__)

DEFAULT_REVIEW_TIMEOUT_SEC = 300
DEFAULT_REVIEW_TOOL_MODE = "prompt_only"
REVIEW_TRANSCRIPT_SCHEMA_VERSION = "0.2"
DEFAULT_MAX_REVIEW_PROMPT_CHARS = 180000
DEFAULT_MAX_REVIEW_SNIPPET_CHARS_PER_KEY = 12000

_SYSTEM_PROMPT = """You are a semantic firmware vulnerability reviewer.
Deterministic facts from SourceAgent are authoritative and must not be contradicted.
Do not infer or rewrite source reachability, object binding, channel traversal, or root matching.
Your job is only to judge exploitability semantics for already-assembled chains.
Return JSON only.
"""


def _semantic_prompt(batch: Mapping[str, Any], *, review_mode: str, review_tool_mode: str) -> str:
    mode_text = (
        "Audit only. Keep the current verdict unless there is an explicit semantic inconsistency worth flagging. "
        "Focus on audit_flags, semantic gaps, and whether checks truly bind the active root."
        if review_mode == "audit_only"
        else "Review each chain semantically and choose SAFE_OR_LOW_RISK, SUSPICIOUS, or CONFIRMED."
    )
    contract = {
        "schema_version": REVIEW_TRANSCRIPT_SCHEMA_VERSION,
        "required_output": {
            "decisions": [
                {
                    "chain_id": "string",
                    "suggested_semantic_verdict": "SAFE_OR_LOW_RISK|SUSPICIOUS|CONFIRMED",
                    "trigger_summary": "one to three sentences describing how the chain could trigger or why it is blocked",
                    "preconditions": {
                        "state_predicates": ["..."],
                        "root_constraints": ["..."],
                        "why_check_fails": ["..."],
                        "environment_assumptions": ["..."],
                    },
                    "segment_assessment": [
                        {
                            "segment_id": "source_to_object|object_to_channel|channel_to_sink|derive_to_root|check_binding|sink_triggerability|source_to_sink",
                            "status": "taint_preserved|taint_weakened|taint_cleansed|effective|weak|absent|mismatch|triggerable|possible|unlikely|unknown|n/a",
                            "reason_codes": ["CHECK_NOT_BINDING_ROOT"],
                            "summary": "brief explanation",
                            "evidence_map": {
                                "summary": ["sink_function", "caller_bridge", "producer_function", "capacity_context", "guard_context"]
                            }
                        }
                    ],
                    "reason_codes": ["CHECK_NOT_BINDING_ROOT"],
                    "review_quality_flags": ["needs_more_context"],
                    "evidence_map": {
                        "trigger_summary": ["sink_function", "caller_bridge", "producer_function", "capacity_context"],
                        "root_controllability": ["sink_function", "producer_function"],
                        "capacity_reasoning": ["capacity_context", "guard_context", "object_context"]
                    },
                    "audit_flags": ["CHECK_NOT_BINDING_ROOT"],
                    "confidence": 0.0,
                    "review_mode": "semantic_review"
                }
            ]
        },
        "allowed_reason_codes": PROMPT_REASON_CODES,
        "constraints": [
            "Deterministic facts are authoritative; do not contradict source reachability, object binding, channel traversal, or root matching.",
            "Review the chain in both directions: source->...->sink and sink/root->...->source.",
            "Inspect every chain segment and decide whether taint is preserved, weakened, cleansed, or unknown.",
            "Judge whether each visible check truly constrains the active root, not just nearby state.",
            "Only cite snippet keys listed in each item's available_snippet_keys.",
            "Prefer capacity_context and guard_context when reasoning about bounds, extent, or whether a check binds the active root.",
            "Do not leave evidence_map empty.",
            "Do not invent facts absent from the provided items.",
            "If evidence is weak, prefer SUSPICIOUS over CONFIRMED.",
            "If review_mode is audit_only, keep the current verdict unless absolutely necessary.",
        ],
        "review_mode": review_mode,
        "review_tool_mode": review_tool_mode,
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


async def _call_mcp_json(
    mcp_manager: object,
    tool_name: str,
    args: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    try:
        result = await mcp_manager.call_tool("ghidra", tool_name, args)
    except Exception as exc:
        logger.warning("review MCP call %s failed: %s", tool_name, exc)
        return None

    if not result:
        return None

    try:
        if isinstance(result, list):
            for block in result:
                if isinstance(block, dict) and block.get("type") == "text":
                    text = str(block.get("text", "") or "")
                    try:
                        return json.loads(text)
                    except Exception:
                        if text.strip():
                            return {"decompiled_code": text}
        elif isinstance(result, dict):
            return result
    except Exception as exc:
        logger.warning("review MCP parse failed for %s: %s", tool_name, exc)
    return None


async def _decompile_function(
    mcp_manager: object,
    ghidra_binary_name: str,
    func_name: str,
) -> str:
    if not mcp_manager or not ghidra_binary_name or not func_name:
        return ""
    resp = await _call_mcp_json(
        mcp_manager,
        "decompile_function",
        {
            "binary_name": ghidra_binary_name,
            "name_or_address": func_name,
        },
    )
    if resp is None:
        return ""
    return str(resp.get("decompiled_code", "") or resp.get("code", "") or "")


async def _decompile_many(
    mcp_manager: object,
    ghidra_binary_name: str,
    functions: Sequence[str],
) -> Dict[str, str]:
    out: Dict[str, str] = {}
    seen: Set[str] = set()
    for func_name in functions:
        fn = str(func_name or "").strip()
        if not fn or fn in seen:
            continue
        seen.add(fn)
        code = await _decompile_function(mcp_manager, ghidra_binary_name, fn)
        if code:
            out[fn] = code
    return out


def _looks_like_function_name(value: Any) -> bool:
    s = str(value or "").strip()
    if not s:
        return False
    lowered = s.lower()
    if lowered in {"sink_function", "caller_bridge", "producer_function", "unknown", "root", "check_expr", "derive_expr"}:
        return False
    if s.startswith("0x"):
        return False
    if any(ch.isspace() for ch in s):
        return False
    if any(ch in s for ch in "(){}[];,"):
        return False
    return True


def _uniq(seq: Iterable[str]) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for raw in seq:
        s = str(raw or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _truncate_blob(text: str, *, max_chars: int) -> str:
    raw = str(text or "")
    if max_chars <= 0 or len(raw) <= max_chars:
        return raw
    marker = "\n/* ... truncated for review budget ... */\n"
    keep = max(32, max_chars - len(marker))
    head = max(16, int(keep * 0.65))
    tail = max(16, keep - head)
    return raw[:head] + marker + raw[-tail:]


def _render_blob(
    functions: Sequence[str],
    code_by_name: Mapping[str, str],
    *,
    max_chars: int = DEFAULT_MAX_REVIEW_SNIPPET_CHARS_PER_KEY,
) -> Tuple[str, List[str]]:
    names = []
    parts = []
    for fn in _uniq(functions):
        code = str(code_by_name.get(fn, "") or "")
        if not code:
            continue
        names.append(fn)
        parts.append(f"/* {fn} */\n{code}")
    return _truncate_blob("\n\n".join(parts), max_chars=max_chars), names


def _candidate_tool_functions(item: Mapping[str, Any]) -> Dict[str, List[str]]:
    sink_fn = str((item.get("sink", {}) or {}).get("function", "") or "")
    plan = dict(item.get("review_context_plan", {}) or {})
    if not plan:
        plan = build_review_context_plan(item)
    selected = {str(k): _uniq(v or []) for k, v in dict(plan.get("selected_functions", {}) or {}).items()}

    if sink_fn and sink_fn not in selected.get("sink_function", []):
        selected["sink_function"] = [sink_fn] + list(selected.get("sink_function", []) or [])

    producer = _uniq(selected.get("producer_context", []) or [])
    bridges = _uniq(selected.get("caller_bridge", []) or [])
    guards = _uniq(selected.get("guard_context", []) or [])
    capacity = _uniq(selected.get("capacity_context", []) or [])
    objects = _uniq(selected.get("object_context", []) or [])
    channel_functions = _uniq(producer + bridges + objects) if list(item.get("channel_path", []) or []) else []
    related = _uniq((selected.get("sink_function", []) or []) + producer + bridges + guards + capacity + objects)

    return {
        "sink_function": _uniq(selected.get("sink_function", []) or []),
        "caller_bridge": bridges,
        "producer_function": producer,
        "source_context": producer,
        "channel_context": channel_functions,
        "derive_context": bridges or ([sink_fn] if sink_fn else []),
        "check_context": guards or bridges or ([sink_fn] if sink_fn else []),
        "capacity_context": capacity or objects or bridges or ([sink_fn] if sink_fn else []),
        "guard_context": guards or bridges or ([sink_fn] if sink_fn else []),
        "object_context": objects,
        "related_functions": [fn for fn in related if fn and fn != sink_fn],
    }


def _merge_tool_snippets(
    item: Mapping[str, Any],
    code_by_name: Mapping[str, str],
    *,
    max_chars_per_key: int = DEFAULT_MAX_REVIEW_SNIPPET_CHARS_PER_KEY,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    updated = dict(item)
    snippets = dict(updated.get("decompiled_snippets", {}) or {})
    snippet_index = {str(k): list(v or []) for k, v in dict(updated.get("snippet_index", {}) or {}).items()}
    context_plan = dict(updated.get("review_context_plan", {}) or {})
    candidate_map = _candidate_tool_functions(updated)
    key_char_limits = dict(context_plan.get("key_char_limits", {}) or {})
    fetched_functions = 0
    rejected_functions = {}

    for key, functions in candidate_map.items():
        existing_names = list(snippet_index.get(key, []) or [])
        merged_names = _uniq(existing_names + list(functions or []))
        cap = int(key_char_limits.get(key, max_chars_per_key) or max_chars_per_key)
        text, final_names = _render_blob(
            merged_names,
            code_by_name,
            max_chars=cap,
        )
        if text:
            snippets[key] = text
            snippet_index[key] = final_names
            fetched_functions += max(0, len([fn for fn in final_names if fn in code_by_name and fn not in existing_names]))
            rejected = [fn for fn in merged_names if fn not in final_names]
            if rejected:
                rejected_functions[key] = rejected
        else:
            snippets.setdefault(key, str(snippets.get(key, "") or ""))
            if key not in snippet_index:
                snippet_index[key] = existing_names

    updated["decompiled_snippets"] = snippets
    updated["snippet_index"] = snippet_index
    updated["available_snippet_keys"] = [key for key, val in snippets.items() if str(val or "").strip()]
    summary = {
        "available_snippet_keys": list(updated.get("available_snippet_keys", []) or []),
        "snippet_index": snippet_index,
        "tool_added_function_count": fetched_functions,
        "context_plan": context_plan,
        "rejected_functions": rejected_functions,
    }
    return updated, summary


async def _augment_batches_for_tool_mode(
    batches: Sequence[Mapping[str, Any]],
    *,
    review_tool_mode: str,
    mcp_manager: Optional[object],
    ghidra_binary_name: Optional[str],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    out_batches: List[Dict[str, Any]] = []
    tool_logs: List[Dict[str, Any]] = []

    if review_tool_mode != "tool_assisted":
        return [dict(batch) for batch in batches], tool_logs

    if not mcp_manager or not ghidra_binary_name:
        return [dict(batch) for batch in batches], [{
            "status": "tool_unavailable",
            "reason": "missing_mcp_or_binary",
        }]

    for batch in batches:
        batch_id = str(batch.get("batch_id", "") or "")
        items = [dict(item) for item in (batch.get("items", []) or [])]
        fn_names: List[str] = []
        for item in items:
            candidates = _candidate_tool_functions(item)
            for group in candidates.values():
                fn_names.extend(group)
        fn_names = _uniq(fn_names)
        if fn_names:
            print(
                f"[Stage 10] Review batch {batch_id}: tool-assisted context fetch for {len(fn_names)} functions"
            )
        code_by_name = await _decompile_many(mcp_manager, str(ghidra_binary_name or ""), fn_names)
        new_items: List[Dict[str, Any]] = []
        summaries: List[Dict[str, Any]] = []
        for item in items:
            merged, summary = _merge_tool_snippets(item, code_by_name)
            new_items.append(merged)
            summaries.append({
                "chain_id": str(item.get("chain_id", "") or ""),
                **summary,
            })
        out_batches.append({
            **dict(batch),
            "items": new_items,
            "tool_context": {
                "mode": review_tool_mode,
                "decompiled_functions": sorted(code_by_name.keys()),
                "summary": summaries,
            },
        })
        tool_logs.append({
            "batch_id": batch_id,
            "mode": review_tool_mode,
            "requested_function_count": len(fn_names),
            "decompiled_function_count": len(code_by_name),
            "decompiled_functions": sorted(code_by_name.keys()),
        })
    return out_batches, tool_logs


def _filtered_tool_context(
    tool_context: Mapping[str, Any],
    *,
    chain_ids: Sequence[str],
) -> Dict[str, Any]:
    chain_id_set = {str(v) for v in chain_ids if str(v)}
    return {
        "mode": str((tool_context or {}).get("mode", "") or ""),
        "decompiled_functions": list((tool_context or {}).get("decompiled_functions", []) or []),
        "summary": [
            dict(row)
            for row in (tool_context or {}).get("summary", []) or []
            if str((row or {}).get("chain_id", "") or "") in chain_id_set
        ],
    }


def _split_batch(batch: Mapping[str, Any]) -> List[Dict[str, Any]]:
    items = [dict(item) for item in (batch.get("items", []) or [])]
    if len(items) <= 1:
        return [dict(batch)]
    mid = max(1, len(items) // 2)
    base_id = str(batch.get("batch_id", "") or "batch")
    tool_context = dict(batch.get("tool_context", {}) or {})
    out: List[Dict[str, Any]] = []
    for idx, chunk in enumerate((items[:mid], items[mid:])):
        if not chunk:
            continue
        chain_ids = [str(item.get("chain_id", "") or "") for item in chunk if str(item.get("chain_id", "") or "")]
        out.append({
            **dict(batch),
            "batch_id": f"{base_id}_{idx}",
            "chain_ids": chain_ids,
            "items": chunk,
            "tool_context": _filtered_tool_context(tool_context, chain_ids=chain_ids),
        })
    return out


def _should_split_for_error(error_text: str) -> bool:
    lowered = str(error_text or "").lower()
    return any(
        needle in lowered for needle in (
            "missing_required_parameter",
            'one of "input"',
            "400 bad request",
            "apiconnectionerror",
            "context length",
            "request too large",
            "too large",
        )
    )


def _build_second_pass_batches(batch: Mapping[str, Any], decisions: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    items_by_chain = {str(item.get("chain_id", "") or ""): dict(item) for item in (batch.get("items", []) or [])}
    out: List[Dict[str, Any]] = []
    base_id = str(batch.get("batch_id", "") or "batch")
    for idx, decision in enumerate(decisions):
        chain_id = str(decision.get("chain_id", "") or "")
        if not chain_id:
            continue
        item = dict(items_by_chain.get(chain_id, {}) or {})
        if not item:
            continue
        plan = dict(item.get("review_context_plan", {}) or {})
        if bool(plan.get("expanded", False)):
            continue
        decision_with_item = {
            **dict(decision),
            "_feature_item": item,
        }
        if not should_request_second_pass(
            decision_with_item,
            review_priority=str(item.get("review_priority", "") or ""),
            current_verdict=str(item.get("current_verdict", "") or ""),
        ):
            continue
        new_item = dict(item)
        new_item["review_context_plan"] = expand_review_context_plan(item)
        out.append({
            **dict(batch),
            "batch_id": f"{base_id}_pass2_{idx:02d}",
            "chain_ids": [chain_id],
            "items": [new_item],
            "estimated_prompt_chars": int(((new_item.get("review_context_plan", {}) or {}).get("estimated_prompt_chars", 0)) or 0),
            "second_pass": True,
        })
    return out


async def run_review_plan(
    review_plan: Mapping[str, Any],
    *,
    model: Optional[str] = None,
    review_mode: str = "semantic",
    review_tool_mode: str = DEFAULT_REVIEW_TOOL_MODE,
    timeout_sec: int = DEFAULT_REVIEW_TIMEOUT_SEC,
    mcp_manager: Optional[object] = None,
    ghidra_binary_name: Optional[str] = None,
) -> Dict[str, Any]:
    items = list((review_plan or {}).get("items", []) or [])
    batches = list((review_plan or {}).get("batches", []) or [])
    if not items:
        return {
            "review_decisions": [],
            "review_prompt": {
                "schema_version": REVIEW_TRANSCRIPT_SCHEMA_VERSION,
                "review_mode": review_mode,
                "review_tool_mode": review_tool_mode,
                "status": "empty",
                "batches": [],
            },
            "review_raw_response": {
                "schema_version": REVIEW_TRANSCRIPT_SCHEMA_VERSION,
                "review_mode": review_mode,
                "review_tool_mode": review_tool_mode,
                "status": "empty",
                "batches": [],
            },
            "review_session": {
                "schema_version": REVIEW_TRANSCRIPT_SCHEMA_VERSION,
                "review_mode": review_mode,
                "review_tool_mode": review_tool_mode,
                "status": "empty",
                "decision_count": 0,
                "batches": [],
            },
            "review_trace": {
                "schema_version": REVIEW_TRANSCRIPT_SCHEMA_VERSION,
                "review_mode": review_mode,
                "review_tool_mode": review_tool_mode,
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
                "schema_version": REVIEW_TRANSCRIPT_SCHEMA_VERSION,
                "review_mode": review_mode,
                "review_tool_mode": review_tool_mode,
                "status": "skipped_unconfigured",
                "reason": "missing_model",
                "batches": [],
            },
            "review_raw_response": {
                "schema_version": REVIEW_TRANSCRIPT_SCHEMA_VERSION,
                "review_mode": review_mode,
                "review_tool_mode": review_tool_mode,
                "status": "skipped_unconfigured",
                "reason": "missing_model",
                "batches": [],
            },
            "review_session": {
                "schema_version": REVIEW_TRANSCRIPT_SCHEMA_VERSION,
                "review_mode": review_mode,
                "review_tool_mode": review_tool_mode,
                "status": "skipped_unconfigured",
                "reason": "missing_model",
                "decision_count": 0,
                "batches": [],
            },
            "review_trace": {
                "schema_version": REVIEW_TRANSCRIPT_SCHEMA_VERSION,
                "review_mode": review_mode,
                "review_tool_mode": review_tool_mode,
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

    augmented_batches, tool_logs = await _augment_batches_for_tool_mode(
        batches,
        review_tool_mode=review_tool_mode,
        mcp_manager=mcp_manager,
        ghidra_binary_name=ghidra_binary_name,
    )

    pending_batches: List[Dict[str, Any]] = [dict(batch) for batch in augmented_batches]

    while pending_batches:
        batch = pending_batches.pop(0)
        batch_id = str(batch.get("batch_id", "") or "")
        batch_tool_mode = str(batch.get("review_tool_mode", review_tool_mode) or review_tool_mode)
        chain_ids = [str(v) for v in (batch.get("chain_ids", []) or []) if str(v)]
        targets = []
        for item in batch.get("items", []) or []:
            sink = dict(item.get("sink", {}) or {})
            root = dict(item.get("root", {}) or {})
            targets.append(
                f"{sink.get('function', '?')}[{root.get('family', 'unknown')}:{root.get('expr', 'UNKNOWN')}]"
            )
        if targets:
            print(
                f"[Stage 10] Review batch {batch_id}: reviewing {len(chain_ids)} chains for "
                f"{', '.join(targets[:4])}"
            )
        prompt = _semantic_prompt(batch, review_mode=review_mode, review_tool_mode=batch_tool_mode)
        prompt_len = len(prompt)
        if prompt_len > DEFAULT_MAX_REVIEW_PROMPT_CHARS and len(batch.get("items", []) or []) > 1:
            split_batches = _split_batch(batch)
            print(
                f"[Stage 10] Review batch {batch_id}: prompt too large ({prompt_len} chars), splitting into {len(split_batches)} batches"
            )
            pending_batches = split_batches + pending_batches
            continue
        prompt_batches.append({
            "batch_id": batch_id,
            "chain_ids": chain_ids,
            "second_pass": bool(batch.get("second_pass", False)),
            "created_at": _now_iso(),
            "model": chosen_model,
            "review_tool_mode": batch_tool_mode,
            "system_prompt": _SYSTEM_PROMPT,
            "user_prompt": prompt,
            "tool_context": _jsonable(batch.get("tool_context", {})),
            "prompt_char_count": prompt_len,
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
            print(
                f"[Stage 10] Review batch {batch_id}: received {len(decisions)} parsed decisions "
                f"(ok={bool(meta.get('ok', False))})"
            )
            second_pass_batches = []
            if decisions:
                second_pass_batches = _build_second_pass_batches(batch, decisions)
                if second_pass_batches:
                    pass2_tool_mode = (
                        "tool_assisted"
                        if mcp_manager and ghidra_binary_name
                        else batch_tool_mode
                    )
                    for second_pass_batch in second_pass_batches:
                        second_pass_batch["review_tool_mode"] = pass2_tool_mode
                    if pass2_tool_mode == "tool_assisted":
                        second_pass_batches, pass2_tool_logs = await _augment_batches_for_tool_mode(
                            second_pass_batches,
                            review_tool_mode=pass2_tool_mode,
                            mcp_manager=mcp_manager,
                            ghidra_binary_name=ghidra_binary_name,
                        )
                        tool_logs.extend(pass2_tool_logs)
                    print(
                        f"[Stage 10] Review batch {batch_id}: scheduling {len(second_pass_batches)} second-pass review batches"
                    )
                    pending_batches = second_pass_batches + pending_batches
            if len(batch.get("items", []) or []) > 1 and (not bool(meta.get("ok", False)) or len(decisions) == 0):
                split_batches = _split_batch(batch)
                print(
                    f"[Stage 10] Review batch {batch_id}: unparsable/empty response, splitting into {len(split_batches)} batches"
                )
                pending_batches = split_batches + pending_batches
            raw_response_batches.append({
                "batch_id": batch_id,
                "chain_ids": chain_ids,
                "second_pass": bool(batch.get("second_pass", False)),
                "created_at": _now_iso(),
                "ok": bool(meta.get("ok", False)),
                "model": str(response.model or chosen_model),
                "review_tool_mode": batch_tool_mode,
                "finish_reason": str(response.finish_reason or ""),
                "usage": _jsonable(response.usage or {}),
                "raw_text": text,
                "error": meta.get("error", ""),
                "prompt_char_count": prompt_len,
            })
            session_batches.append({
                "batch_id": batch_id,
                "chain_ids": chain_ids,
                "second_pass": bool(batch.get("second_pass", False)),
                "ok": bool(meta.get("ok", False)),
                "model": str(response.model or chosen_model),
                "review_tool_mode": batch_tool_mode,
                "finish_reason": str(response.finish_reason or ""),
                "decision_count": len(decisions),
                "parsed_decisions": decisions,
                "tool_context": _jsonable(batch.get("tool_context", {})),
                "error": meta.get("error", ""),
                "prompt_char_count": prompt_len,
            })
            trace_batches.append({
                "batch_id": batch_id,
                "chain_ids": chain_ids,
                "second_pass": bool(batch.get("second_pass", False)),
                "ok": bool(meta.get("ok", False)),
                "decision_count": len(decisions),
                "model": str(response.model or chosen_model),
                "review_tool_mode": batch_tool_mode,
                "raw_excerpt": str(text or "")[:4000],
                "tool_context": _jsonable(batch.get("tool_context", {})),
                "error": meta.get("error", ""),
                "prompt_char_count": prompt_len,
            })
        except Exception as exc:
            print(f"[Stage 10] Review batch {batch_id}: ERROR {exc}")
            if len(batch.get("items", []) or []) > 1 and _should_split_for_error(str(exc)):
                split_batches = _split_batch(batch)
                print(
                    f"[Stage 10] Review batch {batch_id}: retrying as {len(split_batches)} smaller batches after request error"
                )
                pending_batches = split_batches + pending_batches
            raw_response_batches.append({
                "batch_id": batch_id,
                "chain_ids": chain_ids,
                "second_pass": bool(batch.get("second_pass", False)),
                "created_at": _now_iso(),
                "ok": False,
                "model": chosen_model,
                "review_tool_mode": batch_tool_mode,
                "finish_reason": "error",
                "usage": {},
                "raw_text": "",
                "error": str(exc),
                "prompt_char_count": prompt_len,
            })
            session_batches.append({
                "batch_id": batch_id,
                "chain_ids": chain_ids,
                "second_pass": bool(batch.get("second_pass", False)),
                "ok": False,
                "model": chosen_model,
                "review_tool_mode": batch_tool_mode,
                "finish_reason": "error",
                "decision_count": 0,
                "parsed_decisions": [],
                "tool_context": _jsonable(batch.get("tool_context", {})),
                "error": str(exc),
                "prompt_char_count": prompt_len,
            })
            trace_batches.append({
                "batch_id": batch_id,
                "chain_ids": chain_ids,
                "second_pass": bool(batch.get("second_pass", False)),
                "ok": False,
                "decision_count": 0,
                "model": chosen_model,
                "review_tool_mode": batch_tool_mode,
                "raw_excerpt": "",
                "tool_context": _jsonable(batch.get("tool_context", {})),
                "error": str(exc),
                "prompt_char_count": prompt_len,
            })

    status = "ok" if any(batch.get("ok") for batch in trace_batches) else "error"
    return {
        "review_decisions": all_decisions,
        "review_prompt": {
            "schema_version": REVIEW_TRANSCRIPT_SCHEMA_VERSION,
            "review_mode": review_mode,
            "review_tool_mode": review_tool_mode,
            "model": chosen_model,
            "status": "ok" if prompt_batches else "empty",
            "batches": prompt_batches,
        },
        "review_raw_response": {
            "schema_version": REVIEW_TRANSCRIPT_SCHEMA_VERSION,
            "review_mode": review_mode,
            "review_tool_mode": review_tool_mode,
            "model": chosen_model,
            "status": "ok" if raw_response_batches else "empty",
            "decision_count": len(all_decisions),
            "batches": raw_response_batches,
        },
        "review_session": {
            "schema_version": REVIEW_TRANSCRIPT_SCHEMA_VERSION,
            "review_mode": review_mode,
            "review_tool_mode": review_tool_mode,
            "model": chosen_model,
            "status": status,
            "decision_count": len(all_decisions),
            "plan_summary": {
                "item_count": len(items),
                "batch_count": len(prompt_batches),
                "chain_ids": [str(item.get("chain_id", "") or "") for item in items if str(item.get("chain_id", "") or "")],
            },
            "tool_logs": tool_logs,
            "batches": session_batches,
        },
        "review_trace": {
            "schema_version": REVIEW_TRANSCRIPT_SCHEMA_VERSION,
            "review_mode": review_mode,
            "review_tool_mode": review_tool_mode,
            "model": chosen_model,
            "status": status,
            "decision_count": len(all_decisions),
            "tool_logs": tool_logs,
            "batches": trace_batches,
        },
    }
