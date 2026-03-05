"""Stage 6 — LLM proposer: budgeted, reproducible, verifier-aware (M6).

Uses LLMs only where they add value (semantic interpretation), under strict
budgets and schemas. The verifier is the final arbiter; the proposer must
never override failed obligations.

Two modes:
  1. Heuristic (mode="heuristic"): accept miner's candidate_hint directly.
     Facts pass through to the verifier for obligation checking.  No LLM
     call — cheapest path to end-to-end pipeline execution.

  2. LLM (mode="llm"): label-specific prompts, temperature=0 for
     reproducibility, strict JSON parser, cache by evidence-pack hash.

Approach:
  - Prompt templates are label-specific and short
  - Model receives the evidence pack and must output schema-valid JSON
    with evidence_refs
  - Budgeting: only query LLM for the top-K ranked candidates per label type;
    cache by evidence-pack hash
  - Conflict handling: miner provides a hint; LLM may disagree; verifier decides

Reproducibility:
  - temperature=0, deterministic decoding, fixed prompt text
  - Strict JSON parser with canonical key ordering, stable sorting
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any, Dict, List, Optional

from .models import EvidencePack, EvidenceItem, LLMProposal

logger = logging.getLogger("sourceagent.pipeline.proposer")


# ── Public API ──────────────────────────────────────────────────────────────


async def propose_labels(
    packs: List[EvidencePack],
    llm: object = None,
    model: str = "",
    mode: str = "heuristic",
    max_tokens_per_candidate: int = 1000,
    top_k_per_label: int = 50,
    cache: Optional[Dict[str, LLMProposal]] = None,
) -> List[LLMProposal]:
    """Propose source/sink label assignments for evidence packs.

    Args:
        packs: Evidence packs to classify (from M5 evidence packer).
        llm: LLM callable (async) — required for mode="llm".
            Expected signature: async llm(messages, model, ...) → response.
        model: Model name for LiteLLM (e.g. "gpt-4.1"). Required for LLM mode.
        mode: "heuristic" (no LLM, passthrough) or "llm" (LLM classification).
        max_tokens_per_candidate: Token budget per evidence pack (LLM mode).
        top_k_per_label: Max candidates per label type to send to LLM.
        cache: Optional dict for caching proposals by pack hash.

    Returns:
        List of LLMProposal with structured label assignments.
    """
    if not packs:
        return []

    if mode == "heuristic":
        return _propose_heuristic(packs)
    elif mode == "llm":
        return await _propose_with_llm(
            packs,
            llm=llm,
            model=model,
            max_tokens=max_tokens_per_candidate,
            top_k_per_label=top_k_per_label,
            cache=cache if cache is not None else {},
        )
    else:
        raise ValueError(f"Unknown proposer mode: {mode!r} (expected 'heuristic' or 'llm')")


# ── Heuristic mode ──────────────────────────────────────────────────────────


def _propose_heuristic(packs: List[EvidencePack]) -> List[LLMProposal]:
    """Accept miner's candidate_hint directly as the proposed label.

    Facts from the evidence pack are passed through claims[] so the
    verifier can run obligation checks against them.  This is the cheapest
    path to an end-to-end pipeline: miner → packer → proposer → verifier.
    """
    proposals: List[LLMProposal] = []

    for pack in packs:
        evidence_refs = [e.evidence_id for e in pack.evidence]

        proposal = LLMProposal(
            pack_id=pack.pack_id,
            label=pack.candidate_hint,
            address=pack.address,
            function_name=pack.function_name,
            claims=[pack.facts] if pack.facts else [],
            confidence=_heuristic_confidence(pack),
            evidence_refs=evidence_refs,
            notes=f"Heuristic: accepted miner hint '{pack.candidate_hint}'",
        )
        proposals.append(proposal)

    logger.info(
        "Heuristic proposer: %d packs → %d proposals",
        len(packs), len(proposals),
    )
    return proposals


def _heuristic_confidence(pack: EvidencePack) -> float:
    """Compute baseline confidence for heuristic mode.

    Starts at 0.5 (miner produced a candidate) and adds bonuses for
    evidence richness and fact completeness.
    """
    score = 0.5

    # More evidence items → higher confidence
    n_evidence = len(pack.evidence)
    if n_evidence >= 3:
        score += 0.15
    elif n_evidence >= 2:
        score += 0.10

    # Facts with structural indicators boost confidence
    facts = pack.facts
    if facts.get("has_read_modify_write"):
        score += 0.10
    if facts.get("multi_function_cluster"):
        score += 0.05
    if facts.get("in_isr"):
        score += 0.05
    if facts.get("has_pointer_like_write"):
        score += 0.05

    return min(score, 0.95)


# ── LLM mode ────────────────────────────────────────────────────────────────


async def _propose_with_llm(
    packs: List[EvidencePack],
    llm: object,
    model: str,
    max_tokens: int,
    top_k_per_label: int,
    cache: Dict[str, LLMProposal],
) -> List[LLMProposal]:
    """Use LLM to classify evidence packs into labels.

    Budget enforcement: only the top-K packs per label type are sent to
    the LLM.  Results are cached by evidence-pack content hash.
    """
    if llm is None:
        raise ValueError("LLM callable required for mode='llm'. Pass llm=... or use mode='heuristic'.")
    if not model:
        raise ValueError("Model name required for mode='llm'. Pass model=... .")

    # Budget: group by label, take top-K per label type
    budgeted_packs = _apply_budget(packs, top_k_per_label)

    proposals: List[LLMProposal] = []
    for pack in budgeted_packs:
        cache_key = _cache_key(pack)

        # Check cache first
        if cache_key in cache:
            logger.debug("Cache hit for pack %s", pack.pack_id)
            proposals.append(cache[cache_key])
            continue

        # Build prompt and call LLM
        messages = _build_prompt(pack)
        try:
            response = await _call_llm(llm, messages, model, max_tokens)
            proposal = _parse_llm_response(response, pack)
        except Exception as e:
            logger.warning(
                "LLM call failed for pack %s: %s. Falling back to heuristic.",
                pack.pack_id, e,
            )
            proposal = _propose_heuristic([pack])[0]
            proposal.notes = f"LLM fallback: {e}"

        cache[cache_key] = proposal
        proposals.append(proposal)

    logger.info(
        "LLM proposer: %d packs → %d proposals (%d from cache)",
        len(packs), len(proposals),
        sum(1 for p in proposals if "Cache" not in (p.notes or "")),
    )
    return proposals


def _apply_budget(
    packs: List[EvidencePack], top_k: int,
) -> List[EvidencePack]:
    """Select top-K packs per label type.

    Within each label type, packs are sorted by evidence count (descending)
    as a simple ranking proxy.
    """
    by_label: Dict[str, List[EvidencePack]] = {}
    for pack in packs:
        label = pack.candidate_hint
        by_label.setdefault(label, []).append(pack)

    budgeted: List[EvidencePack] = []
    for label, label_packs in sorted(by_label.items()):
        # Sort by evidence count descending, then by address for stability
        sorted_packs = sorted(
            label_packs,
            key=lambda p: (-len(p.evidence), p.address),
        )
        budgeted.extend(sorted_packs[:top_k])

    return budgeted


def _cache_key(pack: EvidencePack) -> str:
    """Stable hash key for an evidence pack (content-based)."""
    content_parts = [
        pack.candidate_hint,
        pack.function_name,
        f"0x{pack.address:08x}",
        json.dumps(pack.facts, sort_keys=True, default=str),
    ]
    for e in pack.evidence:
        content_parts.append(f"{e.evidence_id}:{e.kind}:{e.text}")

    content_str = "|".join(content_parts)
    return hashlib.sha256(content_str.encode()).hexdigest()


# ── Prompt construction ──────────────────────────────────────────────────────


# Label-specific prompt templates
_PROMPT_TEMPLATES: Dict[str, str] = {
    "MMIO_READ": (
        "You are labeling a firmware candidate as MMIO_READ or UNKNOWN.\n"
        "MMIO_READ: a load instruction that reads from a memory-mapped I/O "
        "peripheral register (address in 0x40000000-0x5FFFFFFF or 0xE0000000+).\n"
        "Evidence must show: (1) constant base address, (2) address in peripheral range.\n"
        "Strengthening: bit-test/polling loop, read-modify-write, multi-function access."
    ),
    "ISR_MMIO_READ": (
        "You are labeling a firmware candidate as ISR_MMIO_READ or UNKNOWN.\n"
        "ISR_MMIO_READ: an MMIO register read occurring inside an interrupt service "
        "routine (ISR). Evidence must show: (1) MMIO address with constant base, "
        "(2) address in peripheral range, (3) function is an ISR handler."
    ),
    "ISR_FILLED_BUFFER": (
        "You are labeling a firmware candidate as ISR_FILLED_BUFFER or UNKNOWN.\n"
        "ISR_FILLED_BUFFER: a global/static buffer written by an ISR and read by "
        "non-ISR code (cross-context shared object). Evidence must show: "
        "(1) ISR writes to SRAM buffer, (2) non-ISR reads from same buffer."
    ),
    "DMA_BACKED_BUFFER": (
        "You are labeling a firmware candidate as DMA_BACKED_BUFFER or UNKNOWN.\n"
        "DMA_BACKED_BUFFER: a RAM buffer whose contents are populated by a DMA "
        "engine. Evidence must show: (1) DMA configuration write cluster (>=3 MMIO "
        "stores to same peripheral), (2) pointer-like write to DMA destination register."
    ),
    "COPY_SINK": (
        "You are labeling a firmware candidate as COPY_SINK or UNKNOWN.\n"
        "COPY_SINK: a callsite to a memory-copy function (memcpy, memmove, strcpy, "
        "strncpy, sprintf, etc.) where the length or source is potentially attacker-"
        "controlled. Evidence must show: (1) callsite to recognized copy function, "
        "(2) argument analysis for dst/src/len."
    ),
}

_DEFAULT_TEMPLATE = (
    "You are labeling a firmware candidate. Classify it as {label} or UNKNOWN.\n"
    "Use ONLY the evidence items provided. Cite evidence_refs for every claim."
)


def _build_prompt(pack: EvidencePack) -> List[Dict[str, str]]:
    """Build a chat prompt for the LLM from an evidence pack."""
    label = pack.candidate_hint
    template = _PROMPT_TEMPLATES.get(label, _DEFAULT_TEMPLATE.format(label=label))

    # Format evidence items
    evidence_lines = []
    for e in pack.evidence:
        addr_str = f" addr=0x{e.address:08x}" if e.address else ""
        evidence_lines.append(f"[{e.evidence_id}] type={e.kind} text=\"{e.text}\"{addr_str}")

    evidence_text = "\n".join(evidence_lines) if evidence_lines else "(no evidence items)"

    # Format facts
    facts_text = "; ".join(
        f"{k}={v}" for k, v in sorted(pack.facts.items())
    ) if pack.facts else "(no facts)"

    user_prompt = (
        f"{template}\n\n"
        f"EvidencePack:\n"
        f"{evidence_text}\n"
        f"Facts: {facts_text}\n\n"
        f"Task: Label as {label} or UNKNOWN and provide claims/evidence_refs.\n"
        f"Output MUST be valid JSON matching this schema:\n"
        f'{{"label": "{label}"|"UNKNOWN", '
        f'"claims": [{{"type": "...", "evidence_refs": ["E1",...]}}], '
        f'"confidence": 0.0-1.0, '
        f'"evidence_refs": ["E1",...], '
        f'"notes": "brief rationale"}}'
    )

    return [
        {"role": "system", "content": "You are a firmware binary analyst. "
         "Respond with ONLY valid JSON. No markdown, no explanation outside JSON."},
        {"role": "user", "content": user_prompt},
    ]


# ── LLM call + response parsing ─────────────────────────────────────────────


async def _call_llm(
    llm: object, messages: List[Dict[str, str]], model: str, max_tokens: int,
) -> str:
    """Call the LLM and extract text response.

    Supports two calling conventions:
      1. litellm.acompletion(messages=..., model=...) → OpenAI-style response
      2. Callable(messages, model=...) → string or response object
    """
    # Try litellm.acompletion style
    if hasattr(llm, "acompletion"):
        response = await llm.acompletion(
            messages=messages,
            model=model,
            temperature=0,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
        )
        return response.choices[0].message.content

    # Try direct callable
    if callable(llm):
        response = await llm(
            messages=messages,
            model=model,
            temperature=0,
            max_tokens=max_tokens,
        )
        if isinstance(response, str):
            return response
        # OpenAI-style response object
        if hasattr(response, "choices"):
            return response.choices[0].message.content
        return str(response)

    raise TypeError(f"LLM object {type(llm)} is not callable and has no acompletion method")


def _parse_llm_response(response_text: str, pack: EvidencePack) -> LLMProposal:
    """Parse LLM JSON response into an LLMProposal.

    Strict parser: extracts JSON object, validates required fields,
    falls back to heuristic if parsing fails.
    """
    # Extract JSON from response (handle markdown code blocks)
    json_str = _extract_json(response_text)

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        logger.warning("JSON parse error for pack %s: %s", pack.pack_id, e)
        return _fallback_proposal(pack, f"JSON parse error: {e}")

    if not isinstance(data, dict):
        return _fallback_proposal(pack, "Response is not a JSON object")

    # Extract fields with validation
    label = data.get("label", pack.candidate_hint)
    if label not in (pack.candidate_hint, "UNKNOWN"):
        # LLM proposed a different label — let verifier decide
        logger.info(
            "LLM proposed %s instead of miner hint %s for pack %s",
            label, pack.candidate_hint, pack.pack_id,
        )

    claims = data.get("claims", [])
    if not isinstance(claims, list):
        claims = []

    confidence = data.get("confidence", 0.5)
    if not isinstance(confidence, (int, float)):
        confidence = 0.5
    confidence = max(0.0, min(1.0, float(confidence)))

    evidence_refs = data.get("evidence_refs", [])
    if not isinstance(evidence_refs, list):
        evidence_refs = []

    notes = data.get("notes", "")
    if not isinstance(notes, str):
        notes = str(notes)

    # Build claims with facts from evidence pack (so verifier can check)
    all_claims = [pack.facts] if pack.facts else []
    all_claims.extend(claims)

    return LLMProposal(
        pack_id=pack.pack_id,
        label=label,
        address=pack.address,
        function_name=pack.function_name,
        claims=all_claims,
        confidence=confidence,
        evidence_refs=evidence_refs,
        notes=notes,
    )


def _extract_json(text: str) -> str:
    """Extract JSON object from text, handling markdown code blocks."""
    text = text.strip()

    # Remove markdown code blocks
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first line (```json) and last line (```)
        inner_lines = []
        started = False
        for line in lines:
            if not started:
                if line.startswith("```"):
                    started = True
                    continue
            elif line.strip() == "```":
                break
            else:
                inner_lines.append(line)
        text = "\n".join(inner_lines).strip()

    # Find first { ... } block
    brace_start = text.find("{")
    if brace_start == -1:
        return text

    depth = 0
    for i in range(brace_start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace_start:i + 1]

    # Unclosed brace — return from first brace to end
    return text[brace_start:]


def _fallback_proposal(pack: EvidencePack, reason: str) -> LLMProposal:
    """Build a heuristic fallback proposal when LLM parsing fails."""
    evidence_refs = [e.evidence_id for e in pack.evidence]
    return LLMProposal(
        pack_id=pack.pack_id,
        label=pack.candidate_hint,
        address=pack.address,
        function_name=pack.function_name,
        claims=[pack.facts] if pack.facts else [],
        confidence=0.4,  # Lower confidence for fallback
        evidence_refs=evidence_refs,
        notes=f"LLM parse fallback: {reason}",
    )
