"""Stage 5 — Evidence packer: stable, compressed, auditable (M5).

Converts source and sink candidates into compact EvidencePack objects that are:
  (a) human-auditable — evidence items have human-readable text
  (b) LLM-readable — facts section avoids long prose, stays under token budget
  (c) stable across runs — same candidate → same pack_id via deterministic hashing

Each candidate produces one EvidencePack containing:
  - Evidence items (E1, E2, ...) from the miner's evidence list
  - Structured facts section (addr_expr, segment, provenance, context flags)
  - Stable hash-based pack_id

Pack IDs use the format: "{binary_stem}-{label}-0x{address:08x}" for
human readability, with a short content hash suffix for uniqueness.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import List

from .models import (
    EvidencePack,
    EvidenceItem,
    SinkCandidate,
    SourceCandidate,
)

logger = logging.getLogger("sourceagent.pipeline.evidence_packer")


def pack_evidence(
    sources: List[SourceCandidate],
    sinks: List[SinkCandidate],
    mcp_manager: object = None,
) -> List[EvidencePack]:
    """Build EvidencePacks from source and sink candidates.

    Each candidate becomes one EvidencePack with stable hash-based ID.
    Evidence items are carried over from the miner; facts are structured
    for LLM consumption.

    Args:
        sources: Source candidates from miners (MMIO_READ, ISR_*, DMA_*)
        sinks: Sink candidates from miners (COPY_SINK, etc.)
        mcp_manager: Optional MCP manager for enrichment (future use)

    Returns:
        List of EvidencePack, one per candidate.
    """
    packs: List[EvidencePack] = []

    for src in sources:
        pack = _pack_source(src)
        packs.append(pack)

    for sink in sinks:
        pack = _pack_sink(sink)
        packs.append(pack)

    logger.info(
        "Packed %d evidence packs (%d source, %d sink)",
        len(packs), len(sources), len(sinks),
    )
    return packs


def _pack_source(candidate: SourceCandidate) -> EvidencePack:
    """Build an EvidencePack for a source candidate."""
    pack_id = _make_pack_id(
        candidate.function_name,
        candidate.preliminary_label.value,
        candidate.address,
        candidate.evidence,
    )

    return EvidencePack(
        pack_id=pack_id,
        candidate_hint=candidate.preliminary_label.value,
        binary_path="",  # Filled by caller if needed
        address=candidate.address,
        function_name=candidate.function_name,
        facts=candidate.facts,
        evidence=candidate.evidence,
    )


def _pack_sink(candidate: SinkCandidate) -> EvidencePack:
    """Build an EvidencePack for a sink candidate."""
    pack_id = _make_pack_id(
        candidate.function_name,
        candidate.preliminary_label.value,
        candidate.address,
        candidate.evidence,
    )

    return EvidencePack(
        pack_id=pack_id,
        candidate_hint=candidate.preliminary_label.value,
        binary_path="",
        address=candidate.address,
        function_name=candidate.function_name,
        facts=candidate.facts,
        evidence=candidate.evidence,
    )


def _make_pack_id(
    function_name: str,
    label: str,
    address: int,
    evidence: List[EvidenceItem],
) -> str:
    """Generate a stable, human-readable pack ID.

    Format: "{label}@{function}-0x{address:08x}-{hash6}"
    The hash suffix ensures uniqueness when the same function has
    multiple candidates at different addresses.
    """
    # Build a deterministic content string for hashing
    content_parts = [
        function_name,
        label,
        f"0x{address:08x}",
    ]
    for e in evidence:
        content_parts.append(f"{e.evidence_id}:{e.kind}:{e.text}")

    content_str = "|".join(content_parts)
    content_hash = hashlib.sha256(content_str.encode()).hexdigest()[:6]

    return f"{label}@{function_name}-0x{address:08x}-{content_hash}"
