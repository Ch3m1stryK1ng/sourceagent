"""Prompt builder for Phase A.5 bounded supervision."""

from __future__ import annotations

import json
from typing import Any, Mapping

from sourceagent.pipeline.supervision_reason_codes import SUPERVISION_REASON_CODES

SUPERVISION_TRANSCRIPT_SCHEMA_VERSION = "0.1"

SUPERVISION_SYSTEM_PROMPT = """You are a bounded supervision assistant for deterministic firmware candidates.
You may only classify or refine the provided candidate items.
Do not discover new sources, sinks, objects, channels, or vulnerabilities from scratch.
Return JSON only.
"""


def build_supervision_prompt(batch: Mapping[str, Any]) -> str:
    contract = {
        "schema_version": SUPERVISION_TRANSCRIPT_SCHEMA_VERSION,
        "required_output": {
            "items": [
                {
                    "item_id": "string",
                    "decision": "accept|reject|uncertain",
                    "final_label": "must be one of item.constraints.allowed_labels",
                    "arg_roles": {"dst": "expr", "src": "expr", "len": "expr"},
                    "reason_codes": list(sorted(SUPERVISION_REASON_CODES)),
                    "evidence_map": {"classification": ["sink_function", "caller_bridge"]},
                    "confidence": 0.0,
                    "review_notes": "brief explanation"
                }
            ]
        },
        "constraints": [
            "Only classify the provided candidate items.",
            "Do not propose new labels outside the current per-item allowed_labels set.",
            "Do not invent new chains or facts.",
            "Use available snippet keys only in evidence_map.",
            "If evidence is weak, choose uncertain instead of accept.",
        ],
        "batch": batch,
    }
    return json.dumps(contract, indent=2, ensure_ascii=True)
