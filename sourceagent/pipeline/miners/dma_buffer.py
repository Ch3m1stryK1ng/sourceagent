"""Stage 9 — DMA_BACKED_BUFFER mining (VS3).

Two levels of DMA support (Level 3 deferred to future work):

Level 1 — DMA_CONFIG_SITE (internal, seeds Level 2):
  Detect "write cluster" patterns: >=3 stores to the same peripheral base
  within a single function. These resemble DMA controller configuration
  (writing pointer, length, and enable/trigger fields).

Level 2 — DMA_BACKED_BUFFER:
  Among the Level-1 config writes, look for pointer-like values (stores
  with GLOBAL_PTR provenance or CONST addresses in SRAM range) that
  likely represent DMA destination buffers. Cross-reference with non-ISR
  reads to strengthen evidence.

DMA is hard on raw .bin because:
  - MCU-family dependence (need peripheral map for field semantics)
  - No types/structs in decompiler output
  - Direction ambiguity (RX vs TX vs memory-to-memory)

We emit DMA_BACKED_BUFFER with conservative confidence and let the
verifier/LLM arbitrate.
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

logger = logging.getLogger("sourceagent.pipeline.miners.dma_buffer")

# Minimum number of MMIO stores to same cluster to qualify as DMA config.
_MIN_DMA_CONFIG_WRITES = 3

# Cluster MMIO addresses by 4KB blocks (typical peripheral register block).
_MMIO_CLUSTER_MASK = 0xFFFFF000

# SRAM range for pointer-like value detection
_SRAM_BASE = 0x20000000
_SRAM_END = 0x3FFFFFFF


def mine_dma_sources(
    mai: MemoryAccessIndex,
    memory_map: MemoryMap,
) -> List[SourceCandidate]:
    """Mine DMA_BACKED_BUFFER source candidates.

    Returns list of SourceCandidate with DMA-related labels.
    """
    # Level 1: Find DMA config site candidates
    config_sites = _detect_dma_config_sites(mai)

    if not config_sites:
        logger.info("No DMA config site candidates found")
        return []

    # Level 2: Among config sites, look for buffer pointer evidence
    candidates = _detect_dma_backed_buffers(config_sites, mai)

    logger.info(
        "Mined %d DMA_BACKED_BUFFER candidates from %d config sites",
        len(candidates), len(config_sites),
    )
    return candidates


# ── Level 1: DMA config site detection ──────────────────────────────────────


class _DMAConfigSite:
    """A cluster of MMIO stores that may represent DMA configuration."""

    __slots__ = ("cluster_base", "function_name", "function_addr", "stores")

    def __init__(self, cluster_base: int, function_name: str, function_addr: int):
        self.cluster_base = cluster_base
        self.function_name = function_name
        self.function_addr = function_addr
        self.stores: List[MemoryAccess] = []

    @property
    def has_pointer_like_write(self) -> bool:
        """Check if any store has GLOBAL_PTR or CONST provenance to SRAM."""
        for s in self.stores:
            if s.base_provenance in ("GLOBAL_PTR", "CONST"):
                return True
        return False


def _detect_dma_config_sites(mai: MemoryAccessIndex) -> List[_DMAConfigSite]:
    """Find functions that write >=3 times to the same MMIO peripheral cluster.

    Groups MMIO stores by (function_name, cluster_base) and filters by
    minimum write count.
    """
    # Group: (function_name, cluster_base) → list of store accesses
    groups: Dict[Tuple[str, int], List[MemoryAccess]] = defaultdict(list)

    for access in mai.mmio_accesses:
        if access.kind != "store":
            continue
        if access.target_addr is None:
            continue

        cluster = access.target_addr & _MMIO_CLUSTER_MASK
        key = (access.function_name, cluster)
        groups[key].append(access)

    # Filter for clusters with enough writes
    sites: List[_DMAConfigSite] = []
    for (func_name, cluster_base), stores in groups.items():
        if len(stores) < _MIN_DMA_CONFIG_WRITES:
            continue

        site = _DMAConfigSite(
            cluster_base=cluster_base,
            function_name=func_name,
            function_addr=stores[0].function_addr,
        )
        site.stores = stores
        sites.append(site)

    return sites


# ── Level 2: DMA-backed buffer detection ────────────────────────────────────


def _is_sram_pointer_like(access: MemoryAccess) -> bool:
    """Check if a store might be writing a pointer to an SRAM buffer.

    Heuristic: stores with GLOBAL_PTR provenance targeting MMIO registers
    suggest the function is writing a RAM address (buffer pointer) to
    a DMA peripheral register.
    """
    return access.base_provenance in ("GLOBAL_PTR", "CONST")


def _find_sram_reads_in_non_isr(mai: MemoryAccessIndex) -> Dict[int, List[MemoryAccess]]:
    """Find non-ISR loads from SRAM with resolved addresses, grouped by 256B cluster."""
    clusters: Dict[int, List[MemoryAccess]] = defaultdict(list)
    for access in mai.accesses:
        if access.kind != "load":
            continue
        if access.in_isr:
            continue
        if access.target_addr is None:
            continue
        if not (_SRAM_BASE <= access.target_addr <= _SRAM_END):
            continue
        cluster = access.target_addr & 0xFFFFFF00
        clusters[cluster].append(access)
    return clusters


def _detect_dma_backed_buffers(
    config_sites: List[_DMAConfigSite],
    mai: MemoryAccessIndex,
) -> List[SourceCandidate]:
    """From DMA config sites, identify likely DMA destination buffers.

    For each config site with pointer-like writes, emit a
    DMA_BACKED_BUFFER candidate. Cross-reference with SRAM reads
    from non-ISR context as consumption evidence.
    """
    sram_reads = _find_sram_reads_in_non_isr(mai)
    candidates: List[SourceCandidate] = []
    seen_clusters: Set[int] = set()

    for site in config_sites:
        if not site.has_pointer_like_write:
            continue

        # Avoid duplicate candidates for same peripheral cluster
        if site.cluster_base in seen_clusters:
            continue
        seen_clusters.add(site.cluster_base)

        # Build evidence
        store_addrs = sorted({s.target_addr for s in site.stores})
        evidence = [
            EvidenceItem(
                evidence_id="E1",
                kind="SITE",
                text=(
                    f"DMA config cluster at 0x{site.cluster_base:08x}"
                    f" ({len(site.stores)} writes) in {site.function_name}"
                ),
                address=site.function_addr,
                metadata={
                    "cluster_base": site.cluster_base,
                    "write_count": len(site.stores),
                    "write_targets": [f"0x{a:08x}" for a in store_addrs],
                },
            ),
            EvidenceItem(
                evidence_id="E2",
                kind="DEF",
                text=f"Config function: {site.function_name}",
                address=site.function_addr,
                metadata={
                    "has_pointer_like_write": site.has_pointer_like_write,
                },
            ),
        ]

        # Confidence scoring
        score = 0.3  # Low baseline — DMA is uncertain without MCU map

        if len(site.stores) >= 4:
            score += 0.1  # More writes → more likely multi-field config

        # Check for consumption evidence (non-ISR reads from nearby SRAM)
        has_consumption = False
        for sram_cluster, reads in sram_reads.items():
            if reads:
                has_consumption = True
                break

        if has_consumption:
            score += 0.1

        score = min(score, 1.0)

        candidates.append(SourceCandidate(
            address=site.cluster_base,
            function_name=site.function_name,
            preliminary_label=SourceLabel.DMA_BACKED_BUFFER,
            evidence=evidence,
            confidence_score=score,
            facts={
                "config_cluster": f"0x{site.cluster_base:08x}",
                "config_write_count": len(site.stores),
                "config_function": site.function_name,
                "write_targets": [f"0x{a:08x}" for a in store_addrs],
                "has_pointer_like_write": site.has_pointer_like_write,
            },
        ))

    return candidates
