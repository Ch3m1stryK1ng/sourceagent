"""Canonical semantic review reason codes used by reviewer prompts and decision parsing."""

from __future__ import annotations

from typing import Iterable, List

# Taint propagation
_TAINT_CODES = {
    "TAINT_PRESERVED_DIRECT_ASSIGN",
    "TAINT_PRESERVED_COPY_FROM_IO",
    "TAINT_PRESERVED_LOOP_COPY",
    "TAINT_WEAKENED_MASKED_OR_CLAMPED",
    "TAINT_CLEANSED_CONST_ASSIGN",
    "TAINT_UNKNOWN_ALIASING",
}

# Root controllability
_ROOT_CODES = {
    "ROOT_FROM_MMIO_OR_DMA",
    "ROOT_FROM_ISR_BUFFER",
    "ROOT_DERIVED_ARITHMETIC",
    "ROOT_DEPENDS_ON_HELPER_RETURN",
    "ROOT_SECONDARY_ONLY",
    "ROOT_NOT_CAPACITY_RELEVANT",
}

# Check effectiveness
_CHECK_CODES = {
    "CHECK_DOMINATES_SINK",
    "CHECK_NON_DOMINATING",
    "CHECK_WRONG_VARIABLE",
    "CHECK_NOT_BINDING_ROOT",
    "CHECK_ONLY_STATE_GATE",
    "CHECK_INCOMPLETE_UPPER_BOUND",
    "WEAK_GUARDING",
}

# Parser/helper semantics
_PARSER_CODES = {
    "PARSER_BRANCH_CONDITION_TAINTED",
    "PARSER_DESCRIPTOR_WALK_UNBOUNDED",
    "PARSER_LENGTH_FIELD_TRUSTED",
    "HELPER_SEMANTICS_UNKNOWN",
    "HELPER_RETURNS_ROOT_EQUIVALENT",
}

# Triggerability
_TRIGGER_CODES = {
    "TRIGGERABLE_WITH_SIMPLE_CONSTRAINTS",
    "TRIGGERABLE_LEN_GT_CAPACITY",
    "TRIGGERABLE_INDEX_OOB",
    "TRIGGERABLE_FORMAT_CONTROLLED",
    "TRIGGER_UNCERTAIN_MISSING_CAPACITY",
    "LIKELY_SAFE_BOUND_PRESENT",
}

# Structural / bookkeeping codes still useful for review artifacts.
_STRUCTURAL_CODES = {
    "NO_OBJECT_SEGMENT",
    "NO_CHANNEL_SEGMENT",
    "NO_SOURCE_SEGMENT",
    "SEMANTIC_ONLY_NOT_APPLIED",
    "STRUCTURAL_CONSTRAINT_NOT_MET",
    "CHANNEL_REQUIRED_NOT_SATISFIED",
    "SOFT_GATE_NOT_MET",
    "HARD_BLOCK_REASON_CODE",
}

ALLOWED_REVIEW_REASON_CODES = set().union(
    _TAINT_CODES,
    _ROOT_CODES,
    _CHECK_CODES,
    _PARSER_CODES,
    _TRIGGER_CODES,
    _STRUCTURAL_CODES,
)

REVIEW_REASON_CODE_ALIASES = {
    "CHECK_NOT_BOUND_TO_ROOT": "CHECK_NOT_BINDING_ROOT",
    "WEAK_CHECK": "WEAK_GUARDING",
    "NO_OBJECT_HOP": "NO_OBJECT_SEGMENT",
}

PROMPT_REASON_CODES = sorted(ALLOWED_REVIEW_REASON_CODES)


def normalize_review_reason_codes(values: Iterable[object]) -> List[str]:
    out: List[str] = []
    seen = set()
    for raw in values or []:
        code = str(raw or "").strip().upper()
        if not code:
            continue
        code = REVIEW_REASON_CODE_ALIASES.get(code, code)
        if code not in ALLOWED_REVIEW_REASON_CODES:
            continue
        if code in seen:
            continue
        seen.add(code)
        out.append(code)
    return out
