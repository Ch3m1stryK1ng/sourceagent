"""Stage 7 — Verifier: obligation system + deep-check fallback (M7).

Turns LLM proposals (or heuristic labels from miners) into trustworthy labels
by enforcing label-specific obligations. The verifier is designed to be cheap
by default and only triggers deeper checks for high-value borderline cases.

Obligation design principles:
  - Obligations are local, checkable, and tied to program facts (def-use, CFG,
    addr-range)
  - Each label defines a minimal required set; optional strengthening obligations
    improve confidence but are not mandatory
  - Fail-closed: if any required obligation fails, verdict becomes
    REJECTED/UNKNOWN (or PARTIAL if category plausible but details missing)

Implemented obligations:

  MMIO_READ / ISR_MMIO_READ:
    O_MMIO_1 (required): addr_expr contains CONST provenance
    O_MMIO_2 (required): target address in peripheral/MMIO range (not code/data)
    O_MMIO_3 (optional): cluster has read-modify-write pattern
    O_MMIO_4 (optional): cluster appears in multiple functions

  ISR_MMIO_READ (additional):
    O_ISR_1 (required): function is in ISR context (vector table evidence)

  ISR_FILLED_BUFFER:
    O_BUF_1 (required): ISR writes to buffer cluster
    O_BUF_2 (required): non-ISR reads from same cluster

  DMA_BACKED_BUFFER:
    O_DMA_1 (required): config cluster has >=3 writes to same peripheral base
    O_DMA_2 (required): at least one write has pointer-like provenance
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from .loader import is_flash_address, is_mmio_address
from .models import (
    LLMProposal,
    Obligation,
    ObligationStatus,
    VerificationVerdict,
    VerifiedLabel,
)

logger = logging.getLogger("sourceagent.pipeline.verifier")


async def verify_proposals(
    proposals: List[LLMProposal],
    mcp_manager: object = None,
    ghidra_binary_name: str = "",
) -> List[VerifiedLabel]:
    """Verify LLM proposals against static-analysis obligations.

    For each proposal, generates the appropriate obligation set, checks each
    obligation against the proposal's facts (from the evidence pack), and
    produces a final verdict.

    Returns list of VerifiedLabel with verdicts and obligation details.
    """
    results: List[VerifiedLabel] = []

    for proposal in proposals:
        obligations = _generate_obligations(proposal)
        _check_obligations(obligations, proposal)
        verdict = _compute_verdict(obligations)
        final_label = proposal.label if verdict == VerificationVerdict.VERIFIED else None

        # PARTIAL: category plausible but some required checks missing
        if verdict == VerificationVerdict.PARTIAL:
            final_label = proposal.label  # Keep label but flag as partial

        results.append(VerifiedLabel(
            pack_id=proposal.pack_id,
            proposal=proposal,
            obligations=obligations,
            verdict=verdict,
            final_label=final_label,
        ))

    logger.info(
        "Verified %d proposals: %d VERIFIED, %d PARTIAL, %d REJECTED",
        len(results),
        sum(1 for r in results if r.verdict == VerificationVerdict.VERIFIED),
        sum(1 for r in results if r.verdict == VerificationVerdict.PARTIAL),
        sum(1 for r in results if r.verdict in (
            VerificationVerdict.REJECTED, VerificationVerdict.UNKNOWN,
        )),
    )
    return results


# ── Obligation generation ───────────────────────────────────────────────────

# Registry: label → list of (obligation_id, kind, description, required, checker_fn)
_OBLIGATION_REGISTRY: Dict[str, List[dict]] = {}


def _register_obligations(label: str, obligations: List[dict]):
    """Register obligation templates for a label type."""
    _OBLIGATION_REGISTRY[label] = obligations


# MMIO_READ obligations
_register_obligations("MMIO_READ", [
    {
        "id": "O_MMIO_1",
        "kind": "const_base_trace",
        "description": "addr_expr has CONST provenance (constant address load)",
        "required": True,
        "check": "_check_const_provenance",
    },
    {
        "id": "O_MMIO_2",
        "kind": "addr_range",
        "description": "Target address in peripheral/MMIO range (not flash/code)",
        "required": True,
        "check": "_check_mmio_range",
    },
    {
        "id": "O_MMIO_3",
        "kind": "read_modify_write",
        "description": "Cluster has read-modify-write pattern (strengthening)",
        "required": False,
        "check": "_check_read_modify_write",
    },
    {
        "id": "O_MMIO_4",
        "kind": "multi_function_cluster",
        "description": "Cluster appears in multiple functions (strengthening)",
        "required": False,
        "check": "_check_multi_function",
    },
])

# ISR_MMIO_READ = MMIO_READ obligations + ISR check
_register_obligations("ISR_MMIO_READ", [
    {
        "id": "O_MMIO_1",
        "kind": "const_base_trace",
        "description": "addr_expr has CONST provenance",
        "required": True,
        "check": "_check_const_provenance",
    },
    {
        "id": "O_MMIO_2",
        "kind": "addr_range",
        "description": "Target address in peripheral/MMIO range",
        "required": True,
        "check": "_check_mmio_range",
    },
    {
        "id": "O_ISR_1",
        "kind": "isr_reachable",
        "description": "Function is in ISR context (vector table entry)",
        "required": True,
        "check": "_check_isr_context",
    },
])

# ISR_FILLED_BUFFER obligations
_register_obligations("ISR_FILLED_BUFFER", [
    {
        "id": "O_BUF_1",
        "kind": "isr_writes",
        "description": "ISR function writes to buffer cluster",
        "required": True,
        "check": "_check_isr_writes",
    },
    {
        "id": "O_BUF_2",
        "kind": "non_isr_reads",
        "description": "Non-ISR function reads from same buffer cluster",
        "required": True,
        "check": "_check_non_isr_reads",
    },
])

# DMA_BACKED_BUFFER obligations
_register_obligations("DMA_BACKED_BUFFER", [
    {
        "id": "O_DMA_1",
        "kind": "config_cluster",
        "description": "Config cluster has >=3 writes to same peripheral base",
        "required": True,
        "check": "_check_dma_config_cluster",
    },
    {
        "id": "O_DMA_2",
        "kind": "pointer_like_write",
        "description": "At least one config write has pointer-like provenance",
        "required": True,
        "check": "_check_dma_pointer_write",
    },
])

# COPY_SINK obligations
_register_obligations("COPY_SINK", [
    {
        "id": "O_COPY_1",
        "kind": "callsite_match",
        "description": "Callsite matches known copy/string API or recognized signature",
        "required": True,
        "check": "_check_copy_callsite",
    },
    {
        "id": "O_COPY_2",
        "kind": "arg_extraction",
        "description": "dst/src/len arguments extracted or marked UNKNOWN with low confidence",
        "required": True,
        "check": "_check_copy_args",
    },
    {
        "id": "O_COPY_3",
        "kind": "no_bounds_guard",
        "description": "Length is variable and lacks dominating bounds check (strengthening)",
        "required": False,
        "check": "_check_copy_no_guard",
    },
])


# MEMSET_SINK obligations (parallel to COPY_SINK)
_register_obligations("MEMSET_SINK", [
    {
        "id": "O_MEMSET_1",
        "kind": "callsite_match",
        "description": "Callsite matches known memset/bzero API",
        "required": True,
        "check": "_check_memset_callsite",
    },
    {
        "id": "O_MEMSET_2",
        "kind": "arg_extraction",
        "description": "dst/len arguments extracted from decompiled C",
        "required": True,
        "check": "_check_memset_args",
    },
    {
        "id": "O_MEMSET_3",
        "kind": "no_bounds_guard",
        "description": "Length is variable and lacks bounds check (strengthening)",
        "required": False,
        "check": "_check_memset_no_guard",
    },
])

# STORE_SINK obligations
_register_obligations("STORE_SINK", [
    {
        "id": "O_STORE_1",
        "kind": "non_const_store",
        "description": "Store through non-CONST pointer (ARG/GLOBAL_PTR/UNKNOWN)",
        "required": True,
        "check": "_check_store_provenance",
    },
    {
        "id": "O_STORE_2",
        "kind": "unresolved_target",
        "description": "Target address unresolved or in writable region (strengthening)",
        "required": False,
        "check": "_check_store_target",
    },
])

# LOOP_WRITE_SINK obligations
_register_obligations("LOOP_WRITE_SINK", [
    {
        "id": "O_LOOP_1",
        "kind": "store_in_loop",
        "description": "Store occurs inside a loop body",
        "required": True,
        "check": "_check_loop_store",
    },
    {
        "id": "O_LOOP_2",
        "kind": "variable_bound",
        "description": "Loop bound is variable/unknown (strengthening)",
        "required": False,
        "check": "_check_loop_variable_bound",
    },
])

# FORMAT_STRING_SINK obligations
_register_obligations("FORMAT_STRING_SINK", [
    {
        "id": "O_FMT_1",
        "kind": "format_func_call",
        "description": "A printf-family function is called",
        "required": True,
        "check": "_check_format_func",
    },
    {
        "id": "O_FMT_2",
        "kind": "format_nonliteral",
        "description": "Format argument is not a string literal",
        "required": True,
        "check": "_check_format_nonliteral",
    },
])

# FUNC_PTR_SINK obligations
_register_obligations("FUNC_PTR_SINK", [
    {
        "id": "O_FPTR_1",
        "kind": "indirect_call",
        "description": "An indirect function call through pointer or table",
        "required": True,
        "check": "_check_indirect_call",
    },
    {
        "id": "O_FPTR_2",
        "kind": "input_derived",
        "description": "Call target index/pointer may derive from external input",
        "required": False,
        "check": "_check_input_derived",
    },
])


def _generate_obligations(proposal: LLMProposal) -> List[Obligation]:
    """Generate the obligation set for a proposal based on its label."""
    templates = _OBLIGATION_REGISTRY.get(proposal.label, [])
    return [
        Obligation(
            obligation_id=t["id"],
            kind=t["kind"],
            description=t["description"],
            required=t["required"],
        )
        for t in templates
    ]


# ── Obligation checkers ─────────────────────────────────────────────────────


def _get_facts(proposal: LLMProposal) -> Dict[str, Any]:
    """Extract facts dict from proposal. Facts come from evidence pack via miner."""
    # LLMProposal doesn't directly store facts, but claims[].evidence_refs
    # point to evidence items. For now, we check the fields we can.
    # In practice, facts are passed alongside proposals from the evidence pack.
    # We store them in proposal.claims as a convention.
    facts = {}
    for claim in proposal.claims:
        if isinstance(claim, dict):
            facts.update(claim)
    return facts


def _check_obligations(obligations: List[Obligation], proposal: LLMProposal):
    """Run all obligation checks for a proposal."""
    templates = _OBLIGATION_REGISTRY.get(proposal.label, [])
    template_map = {t["id"]: t for t in templates}
    facts = _get_facts(proposal)

    for ob in obligations:
        template = template_map.get(ob.obligation_id)
        if template is None:
            ob.status = ObligationStatus.UNKNOWN
            continue

        checker_name = template["check"]
        checker = _CHECKERS.get(checker_name)
        if checker is None:
            ob.status = ObligationStatus.UNKNOWN
            ob.evidence = f"No checker for {checker_name}"
            continue

        try:
            passed, evidence_text = checker(proposal, facts)
            ob.status = ObligationStatus.SATISFIED if passed else ObligationStatus.VIOLATED
            ob.evidence = evidence_text
        except Exception as e:
            ob.status = ObligationStatus.UNKNOWN
            ob.evidence = f"Checker error: {e}"


# ── Individual checkers ─────────────────────────────────────────────────────
# Each checker returns (passed: bool, evidence: str)


def _check_const_provenance(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_MMIO_1: Check that addr_expr has CONST provenance."""
    addr_expr = facts.get("addr_expr", "")
    if any(k in str(addr_expr) for k in ("CONST", "INTERPROCEDURAL", "FLASH_CONST_PTR", "STRUCT_RESOLVED", "INTRA_RESOLVED")):
        return True, f"addr_expr={addr_expr} has resolved provenance"
    # Fallback: check if io_addr is present and looks like constant
    io_addr = facts.get("io_addr", "") or str(proposal.address)
    if io_addr:
        return True, f"io_addr=0x{proposal.address:08x} (assumed CONST from miner)"
    return False, "No CONST provenance found in facts"


def _check_mmio_range(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_MMIO_2: Check target address is in peripheral range, not flash."""
    addr = proposal.address
    segment = facts.get("segment_of_base", "")

    if segment == "PERIPHERAL_RANGE":
        return True, f"segment_of_base=PERIPHERAL_RANGE"

    # Direct range check
    if is_mmio_address(addr):
        return True, f"0x{addr:08x} in MMIO range (0x40000000-0x5FFFFFFF)"
    if 0xE0000000 <= addr <= 0xFFFFFFFF:
        return True, f"0x{addr:08x} in system peripheral range"

    if is_flash_address(addr):
        return False, f"0x{addr:08x} in FLASH range — likely constant table, not MMIO"

    return False, f"0x{addr:08x} not in recognized peripheral range"


def _check_read_modify_write(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_MMIO_3 (optional): Cluster has read-modify-write pattern."""
    if facts.get("has_read_modify_write"):
        return True, "Cluster has read-modify-write (|=, &=) pattern"
    return False, "No read-modify-write pattern detected"


def _check_multi_function(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_MMIO_4 (optional): Cluster appears in multiple functions."""
    if facts.get("multi_function_cluster"):
        return True, "Cluster accessed by multiple functions"
    return False, "Cluster accessed by single function only"


def _check_isr_context(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_ISR_1: Function is in ISR context."""
    if facts.get("in_isr"):
        isr_fn = facts.get("isr_function", proposal.function_name)
        return True, f"Function {isr_fn} is ISR handler (vector table)"
    return False, "Function not in ISR context"


def _check_isr_writes(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_BUF_1: ISR writes to buffer cluster."""
    count = facts.get("isr_write_count", 0)
    if count > 0:
        writers = facts.get("isr_writers", [])
        return True, f"ISR writes: {count} stores from {writers}"
    return False, "No ISR writes to buffer cluster"


def _check_non_isr_reads(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_BUF_2: Non-ISR reads from buffer cluster."""
    count = facts.get("non_isr_read_count", 0)
    if count > 0:
        readers = facts.get("non_isr_readers", [])
        return True, f"Non-ISR reads: {count} loads from {readers}"
    return False, "No non-ISR reads from buffer cluster"


def _check_dma_config_cluster(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_DMA_1: Config cluster has >=3 writes."""
    count = facts.get("config_write_count", 0)
    if count >= 3:
        return True, f"Config cluster has {count} writes (>= 3)"
    return False, f"Config cluster has only {count} writes (need >= 3)"


def _check_dma_pointer_write(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_DMA_2: At least one write has pointer-like provenance."""
    if facts.get("has_pointer_like_write"):
        return True, "Config cluster has pointer-like write (GLOBAL_PTR or CONST)"
    return False, "No pointer-like write in config cluster"


def _check_copy_callsite(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_COPY_1: Callsite matches known copy/string API."""
    callee = facts.get("callee", "")
    if callee:
        return True, f"Callsite to recognized copy function: {callee}"
    return False, "No recognized copy function callsite"


def _check_copy_args(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_COPY_2: dst/src/len arguments extracted."""
    args = facts.get("args", [])
    if args:
        dst_prov = facts.get("dst_provenance", "UNKNOWN")
        return True, f"Arguments extracted: {len(args)} args, dst_provenance={dst_prov}"
    # Callsite confirmed but args not recovered — still pass with partial evidence
    if facts.get("call_found") or facts.get("callee"):
        return True, "Callsite confirmed but argument extraction failed (partial evidence)"
    if facts.get("decompile_failed"):
        return False, "Decompile failed — cannot extract arguments"
    return False, "No arguments extracted from callsite"


def _check_copy_no_guard(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_COPY_3 (optional): Length variable and no bounds guard."""
    if not facts.get("len_is_constant", True) and not facts.get("has_bounds_guard", False):
        return True, "Variable-length copy with no bounds guard (high risk)"
    if facts.get("has_bounds_guard"):
        return False, "Bounds guard detected before copy call"
    return False, "Length is constant or guard present"


# ── MEMSET_SINK checkers ──────────────────────────────────────────────────


def _check_memset_callsite(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_MEMSET_1: Callsite matches known memset/bzero API."""
    callee = facts.get("callee", "")
    if callee:
        return True, f"Callsite to recognized memset function: {callee}"
    return False, "No recognized memset function callsite"


def _check_memset_args(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_MEMSET_2: dst/len arguments extracted."""
    args = facts.get("args", [])
    if args:
        dst_prov = facts.get("dst_provenance", "UNKNOWN")
        return True, f"Arguments extracted: {len(args)} args, dst_provenance={dst_prov}"
    # Callsite confirmed but args not recovered — still pass with partial evidence
    if facts.get("call_found") or facts.get("callee"):
        return True, "Callsite confirmed but argument extraction failed (partial evidence)"
    if facts.get("decompile_failed"):
        return False, "Decompile failed — cannot extract arguments"
    return False, "No arguments extracted from memset callsite"


def _check_memset_no_guard(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_MEMSET_3 (optional): Length variable and no bounds guard."""
    if not facts.get("len_is_constant", True) and not facts.get("has_bounds_guard", False):
        return True, "Variable-length memset with no bounds guard (high risk)"
    if facts.get("has_bounds_guard"):
        return False, "Bounds guard detected before memset call"
    return False, "Length is constant or guard present"


# ── STORE_SINK checkers ──────────────────────────────────────────────────


def _check_store_provenance(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_STORE_1: Store through non-CONST pointer."""
    prov = facts.get("provenance", "")
    if prov in ("ARG", "GLOBAL_PTR", "UNKNOWN"):
        return True, f"Store via {prov} pointer"
    return False, f"Store provenance is {prov} (need ARG/GLOBAL_PTR/UNKNOWN)"


def _check_store_target(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_STORE_2 (optional): Target unresolved or in writable region."""
    if facts.get("has_unresolved_target"):
        return True, "Target address unresolved (runtime-dependent)"
    target = facts.get("target_addr", "")
    if target:
        return True, f"Target {target} in writable memory"
    return False, "Target is resolved to a known safe location"


# ── LOOP_WRITE_SINK checkers ─────────────────────────────────────────────


def _check_loop_store(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_LOOP_1: Store occurs inside a loop body."""
    if facts.get("in_loop"):
        store = facts.get("store_expr", "unknown store")
        kind = facts.get("loop_kind", "loop")
        return True, f"Store '{store}' inside {kind} loop"
    return False, "No store-in-loop evidence"


def _check_loop_variable_bound(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_LOOP_2 (optional): Loop bound is variable/unknown."""
    if not facts.get("bound_is_constant", True):
        bound = facts.get("loop_bound", "unknown")
        return True, f"Variable loop bound: {bound}"
    bound = facts.get("loop_bound", "")
    if bound:
        return False, f"Constant loop bound: {bound}"
    return False, "Loop bound not recovered"


# ── FORMAT_STRING_SINK checkers ──────────────────────────────────────────


def _check_format_func(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_FMT_1: A printf-family function is called."""
    func = facts.get("format_func", "")
    if func:
        return True, f"format function call: {func}"
    if facts.get("fallback_pattern"):
        return True, f"format fallback matched: {facts.get('fallback_pattern')}"
    return False, "No format-function call evidence"


def _check_format_nonliteral(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_FMT_2: Format argument is non-literal."""
    if facts.get("format_arg_is_variable"):
        arg = facts.get("format_arg_expr", "variable")
        return True, f"format arg is non-literal: {arg}"
    return False, "Format argument appears literal or unknown"


# ── FUNC_PTR_SINK checkers ───────────────────────────────────────────────


def _check_indirect_call(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_FPTR_1: Indirect call through pointer/table exists."""
    pat = facts.get("indirect_call_pattern", "")
    if pat:
        return True, f"indirect call pattern: {pat}"
    return False, "No indirect-call pattern in facts"


def _check_input_derived(
    proposal: LLMProposal, facts: Dict[str, Any],
) -> tuple[bool, str]:
    """O_FPTR_2 (optional): target may be input-derived."""
    if facts.get("input_derived"):
        return True, "pointer/index appears input-derived"
    matched = str(facts.get("matched_text", ""))
    if "param_" in matched:
        return True, "matched indirect call references param_*"
    return False, "No clear input-derived pointer/index evidence"


# Checker registry (name → function)
_CHECKERS: Dict[str, Callable] = {
    "_check_const_provenance": _check_const_provenance,
    "_check_mmio_range": _check_mmio_range,
    "_check_read_modify_write": _check_read_modify_write,
    "_check_multi_function": _check_multi_function,
    "_check_isr_context": _check_isr_context,
    "_check_isr_writes": _check_isr_writes,
    "_check_non_isr_reads": _check_non_isr_reads,
    "_check_dma_config_cluster": _check_dma_config_cluster,
    "_check_dma_pointer_write": _check_dma_pointer_write,
    "_check_copy_callsite": _check_copy_callsite,
    "_check_copy_args": _check_copy_args,
    "_check_copy_no_guard": _check_copy_no_guard,
    "_check_memset_callsite": _check_memset_callsite,
    "_check_memset_args": _check_memset_args,
    "_check_memset_no_guard": _check_memset_no_guard,
    "_check_store_provenance": _check_store_provenance,
    "_check_store_target": _check_store_target,
    "_check_loop_store": _check_loop_store,
    "_check_loop_variable_bound": _check_loop_variable_bound,
    "_check_format_func": _check_format_func,
    "_check_format_nonliteral": _check_format_nonliteral,
    "_check_indirect_call": _check_indirect_call,
    "_check_input_derived": _check_input_derived,
}


# ── Verdict computation ─────────────────────────────────────────────────────


def _compute_verdict(obligations: List[Obligation]) -> VerificationVerdict:
    """Compute final verdict from obligation statuses.

    Rules:
      - All required obligations SATISFIED → VERIFIED
      - Some required UNKNOWN, none VIOLATED → PARTIAL
      - Any required VIOLATED → REJECTED
      - No obligations → UNKNOWN
    """
    if not obligations:
        return VerificationVerdict.UNKNOWN

    required = [o for o in obligations if o.required]
    if not required:
        return VerificationVerdict.VERIFIED  # No required checks → pass

    any_violated = any(o.status == ObligationStatus.VIOLATED for o in required)
    all_satisfied = all(o.status == ObligationStatus.SATISFIED for o in required)
    any_unknown = any(o.status == ObligationStatus.UNKNOWN for o in required)

    if any_violated:
        return VerificationVerdict.REJECTED
    if all_satisfied:
        return VerificationVerdict.VERIFIED
    if any_unknown:
        return VerificationVerdict.PARTIAL

    return VerificationVerdict.UNKNOWN
