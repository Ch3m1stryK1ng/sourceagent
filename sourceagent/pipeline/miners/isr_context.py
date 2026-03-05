"""Stage 8 — ISR context and ISR_FILLED_BUFFER mining (VS2).

Models interrupt-driven input propagation common in Type-III (bare-metal)
firmware and many Type-II systems.

ISR_MMIO_READ:
  - MMIO loads with CONST provenance that occur inside ISR-context functions.
  - Stronger evidence of external input than plain MMIO_READ because ISR
    handlers are triggered by hardware events (interrupts).

ISR_FILLED_BUFFER:
  - Global/static objects written by ISR-context functions and read by
    non-ISR functions. Classic pattern: ISR fills ring buffer, main loop
    reads and parses it.
  - Detected via cross-context shared-object heuristic: find SRAM addresses
    that appear in both ISR stores and non-ISR loads.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Dict, List, Set, Tuple

from ..models import (
    EvidenceItem,
    MemoryAccess,
    MemoryAccessIndex,
    MemoryMap,
    SourceCandidate,
    SourceLabel,
)

logger = logging.getLogger("sourceagent.pipeline.miners.isr_context")


def mine_isr_sources(
    mai: MemoryAccessIndex,
    memory_map: MemoryMap,
) -> List[SourceCandidate]:
    """Mine ISR_MMIO_READ and ISR_FILLED_BUFFER source candidates.

    Returns list of SourceCandidate with ISR-related labels.
    """
    candidates: List[SourceCandidate] = []

    candidates.extend(_mine_isr_mmio_read(mai))
    candidates.extend(_mine_isr_filled_buffer(mai))

    logger.info(
        "Mined %d ISR source candidates (%d ISR_MMIO_READ, %d ISR_FILLED_BUFFER)",
        len(candidates),
        sum(1 for c in candidates if c.preliminary_label == SourceLabel.ISR_MMIO_READ),
        sum(1 for c in candidates if c.preliminary_label == SourceLabel.ISR_FILLED_BUFFER),
    )
    return candidates


# ── ISR_MMIO_READ ───────────────────────────────────────────────────────────


def _mine_isr_mmio_read(mai: MemoryAccessIndex) -> List[SourceCandidate]:
    """Find MMIO loads with CONST provenance inside ISR functions.

    Same criteria as MMIO_READ (Stage 3) but restricted to in_isr==True.
    """
    seen: Set[Tuple[str, int]] = set()
    candidates: List[SourceCandidate] = []

    for access in mai.mmio_accesses:
        if access.kind != "load":
            continue
        if access.base_provenance not in ("CONST", "FLASH_CONST_PTR", "INTERPROCEDURAL", "STRUCT_RESOLVED", "INTRA_RESOLVED"):
            continue
        if not access.in_isr:
            continue
        if access.target_addr is None:
            continue

        key = (access.function_name, access.target_addr)
        if key in seen:
            continue
        seen.add(key)

        evidence = [
            EvidenceItem(
                evidence_id="E1",
                kind="SITE",
                text=(
                    f"*(uint{access.width * 8} *)0x{access.target_addr:08x}"
                    f"  // ISR load in {access.function_name}"
                ),
                address=access.function_addr,
                metadata={"width": access.width, "target": access.target_addr},
            ),
            EvidenceItem(
                evidence_id="E2",
                kind="DEF",
                text=f"ISR function: {access.function_name} (vector table entry)",
                address=access.function_addr,
                metadata={"provenance": access.base_provenance, "in_isr": True},
            ),
        ]

        prov = access.base_provenance
        candidates.append(SourceCandidate(
            address=access.target_addr,
            function_name=access.function_name,
            preliminary_label=SourceLabel.ISR_MMIO_READ,
            evidence=evidence,
            confidence_score=0.7,  # Higher baseline — ISR context is strong signal
            facts={
                "addr_expr": f"{prov}(0x{access.target_addr:08x})",
                "segment_of_base": "PERIPHERAL_RANGE",
                "in_isr": True,
                "isr_function": access.function_name,
            },
        ))

    return candidates


# ── ISR_FILLED_BUFFER ───────────────────────────────────────────────────────

# SRAM address range for Cortex-M
_SRAM_BASE = 0x20000000
_SRAM_END = 0x3FFFFFFF

# Cluster SRAM addresses by 256-byte blocks for buffer-object grouping.
# Global buffers (rx_buf, tx_buf) are typically 64-256 bytes.
_SRAM_CLUSTER_MASK = 0xFFFFFF00


def _is_sram_target(access: MemoryAccess) -> bool:
    """Check if the access targets SRAM (resolved constant address)."""
    if access.target_addr is None:
        return False
    return _SRAM_BASE <= access.target_addr <= _SRAM_END


def _mine_isr_filled_buffer(mai: MemoryAccessIndex) -> List[SourceCandidate]:
    """Find global/static buffers written in ISR and read outside ISR.

    Heuristic: group SRAM accesses by address cluster (256-byte blocks).
    If a cluster has ISR writes AND non-ISR reads, it's a shared-object
    candidate for ISR_FILLED_BUFFER.
    """
    # Collect ISR writes and non-ISR reads to SRAM with known addresses
    isr_store_clusters: Dict[int, List[MemoryAccess]] = defaultdict(list)
    non_isr_load_clusters: Dict[int, List[MemoryAccess]] = defaultdict(list)

    for access in mai.accesses:
        if not _is_sram_target(access):
            continue
        if access.base_provenance not in ("CONST", "GLOBAL_PTR", "FLASH_CONST_PTR", "INTERPROCEDURAL", "STRUCT_RESOLVED", "INTRA_RESOLVED"):
            continue

        cluster = access.target_addr & _SRAM_CLUSTER_MASK

        if access.in_isr and access.kind == "store":
            isr_store_clusters[cluster].append(access)
        elif not access.in_isr and access.kind == "load":
            non_isr_load_clusters[cluster].append(access)

    # Find clusters that have both ISR writes and non-ISR reads
    shared_clusters = set(isr_store_clusters.keys()) & set(non_isr_load_clusters.keys())

    candidates: List[SourceCandidate] = []
    for cluster in sorted(shared_clusters):
        isr_writes = isr_store_clusters[cluster]
        non_isr_reads = non_isr_load_clusters[cluster]

        # Pick representative ISR write for the candidate
        rep_write = isr_writes[0]
        rep_read = non_isr_reads[0]

        evidence = [
            EvidenceItem(
                evidence_id="E1",
                kind="SITE",
                text=(
                    f"ISR store to 0x{rep_write.target_addr:08x}"
                    f" in {rep_write.function_name}"
                ),
                address=rep_write.function_addr,
                metadata={
                    "target": rep_write.target_addr,
                    "isr_function": rep_write.function_name,
                },
            ),
            EvidenceItem(
                evidence_id="E2",
                kind="XREF",
                text=(
                    f"Non-ISR read from 0x{rep_read.target_addr:08x}"
                    f" in {rep_read.function_name}"
                ),
                address=rep_read.function_addr,
                metadata={
                    "target": rep_read.target_addr,
                    "reader_function": rep_read.function_name,
                },
            ),
        ]

        # Confidence based on evidence strength
        score = 0.4  # Baseline
        if len(isr_writes) >= 2:
            score += 0.1  # Multiple writes suggest buffer fill
        if len(non_isr_reads) >= 2:
            score += 0.1  # Multiple reads suggest parsing
        writer_funcs = {a.function_name for a in isr_writes}
        reader_funcs = {a.function_name for a in non_isr_reads}
        if writer_funcs != reader_funcs:
            score += 0.1  # Different functions writing vs reading
        score = min(score, 1.0)

        candidates.append(SourceCandidate(
            address=cluster,  # Cluster base as representative address
            function_name=rep_write.function_name,
            preliminary_label=SourceLabel.ISR_FILLED_BUFFER,
            evidence=evidence,
            confidence_score=score,
            facts={
                "buffer_cluster": f"0x{cluster:08x}",
                "isr_write_count": len(isr_writes),
                "non_isr_read_count": len(non_isr_reads),
                "isr_writers": sorted(writer_funcs),
                "non_isr_readers": sorted(reader_funcs),
            },
        ))

    return candidates
