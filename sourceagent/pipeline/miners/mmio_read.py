"""Stage 3 — MMIO_READ source miner (VS0).

Criteria for labeling a memory access as MMIO_READ:
  - Load instruction (kind == "load")
  - Target address in MMIO/system-peripheral range
  - Base provenance is CONST (loaded from literal pool / constant address)
  - Not inside an ISR (those become ISR_MMIO_READ in VS2)

For each qualifying access, emits a SourceCandidate(MMIO_READ) with:
  - E1: site — the load instruction with target address and width
  - E2: provenance — base provenance classification

Context features stored in facts for ranking and downstream evidence:
  - Peripheral cluster ID (upper bits of target address)
  - Whether a read-modify-write pattern exists at the same cluster
  - Whether multiple functions access the same cluster
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from ..models import (
    EvidenceItem,
    MemoryAccess,
    MemoryAccessIndex,
    MemoryMap,
    SourceCandidate,
    SourceLabel,
)

logger = logging.getLogger("sourceagent.pipeline.miners.mmio_read")

# Cluster MMIO addresses by masking lower 12 bits (4KB peripheral blocks).
# Typical Cortex-M peripherals (UART, SPI, TIM, etc.) occupy 1-4KB blocks.
_CLUSTER_MASK = 0xFFFFF000


def mine_mmio_read_sources(
    mai: MemoryAccessIndex,
    memory_map: MemoryMap,
) -> List[SourceCandidate]:
    """Mine MMIO_READ source candidates from MemoryAccessIndex.

    Filters for CONST-provenance loads in MMIO range, deduplicates by
    (function, target_address) to avoid per-instruction duplicates,
    clusters by peripheral base, and ranks by context features.

    Returns list of SourceCandidate with preliminary_label=MMIO_READ.
    """
    # Step 1: Filter qualifying accesses
    qualifying = _filter_mmio_read_accesses(mai)

    if not qualifying:
        logger.info("No MMIO_READ candidates found")
        return []

    # Step 2: Deduplicate by (function_name, target_addr) — keep first occurrence
    deduped = _deduplicate_accesses(qualifying)

    # Step 3: Build cluster context (for ranking features)
    cluster_ctx = _build_cluster_context(mai)

    # Step 3b: Build func_read_map for indirect polling detection (P7)
    func_read_map = _build_func_read_map(qualifying)

    # Step 4: Emit SourceCandidates with evidence and ranking
    candidates = []
    for access in deduped:
        candidate = _build_candidate(access, cluster_ctx, mai, func_read_map)
        candidates.append(candidate)

    # Step 5: Sort by confidence (descending)
    candidates.sort(key=lambda c: c.confidence_score, reverse=True)

    logger.info(
        "Mined %d MMIO_READ candidates from %d qualifying accesses",
        len(candidates), len(qualifying),
    )
    return candidates


# ── Filtering ───────────────────────────────────────────────────────────────


def _filter_mmio_read_accesses(mai: MemoryAccessIndex) -> List[MemoryAccess]:
    """Select MMIO loads with CONST provenance, excluding ISR context."""
    result = []
    for access in mai.mmio_accesses:
        if access.kind != "load":
            continue
        if access.base_provenance not in ("CONST", "FLASH_CONST_PTR", "INTERPROCEDURAL", "STRUCT_RESOLVED", "INTRA_RESOLVED"):
            continue
        if access.in_isr:
            continue  # ISR_MMIO_READ handled by Stage 8
        if access.target_addr is None:
            continue
        result.append(access)
    return result


# ── Deduplication ───────────────────────────────────────────────────────────


def _deduplicate_accesses(accesses: List[MemoryAccess]) -> List[MemoryAccess]:
    """Deduplicate by (function_name, target_addr), keeping first occurrence."""
    seen: Set[Tuple[str, int]] = set()
    result: List[MemoryAccess] = []
    for a in accesses:
        key = (a.function_name, a.target_addr)
        if key not in seen:
            seen.add(key)
            result.append(a)
    return result


# ── Cluster context ─────────────────────────────────────────────────────────


def _cluster_id(addr: int) -> int:
    """Get the peripheral cluster ID for an MMIO address."""
    return addr & _CLUSTER_MASK


class _ClusterContext:
    """Aggregated context about an MMIO peripheral cluster."""

    __slots__ = (
        "cluster_base", "functions", "has_store", "load_count", "store_count",
        "addr_has_load", "addr_has_store",
    )

    def __init__(self, cluster_base: int):
        self.cluster_base = cluster_base
        self.functions: Set[str] = set()
        self.has_store = False
        self.load_count = 0
        self.store_count = 0
        self.addr_has_load: Set[int] = set()
        self.addr_has_store: Set[int] = set()

    @property
    def multi_function(self) -> bool:
        return len(self.functions) > 1

    @property
    def has_read_modify_write(self) -> bool:
        return self.has_store and self.load_count > 0

    def addr_has_rmw(self, addr: int) -> bool:
        """Check if a specific address has read-modify-write (both load + store)."""
        return addr in self.addr_has_load and addr in self.addr_has_store


def _build_cluster_context(
    mai: MemoryAccessIndex,
) -> Dict[int, _ClusterContext]:
    """Build per-cluster context from all MMIO accesses (loads + stores)."""
    clusters: Dict[int, _ClusterContext] = {}

    for access in mai.mmio_accesses:
        if access.target_addr is None:
            continue

        cid = _cluster_id(access.target_addr)
        if cid not in clusters:
            clusters[cid] = _ClusterContext(cid)

        ctx = clusters[cid]
        ctx.functions.add(access.function_name)

        if access.kind == "load":
            ctx.load_count += 1
            ctx.addr_has_load.add(access.target_addr)
        elif access.kind == "store":
            ctx.has_store = True
            ctx.store_count += 1
            ctx.addr_has_store.add(access.target_addr)

    return clusters


# ── Polling-loop detection (P7) ─────────────────────────────────────────────


# Matches: while (...0xADDR... & 0xMASK) or do {...} while (...0xADDR... & 0xMASK)
_RE_WHILE_COND = re.compile(
    r"\b(?:while|for)\s*\(([^{;]*)\)",
    re.MULTILINE,
)
_RE_DO_WHILE_COND = re.compile(
    r"\}\s*while\s*\(([^;]*)\)\s*;",
    re.MULTILINE,
)


def _detect_polling_loop(code: str, target_addr: int) -> bool:
    """Check if target_addr appears inside a while/do-while condition with a & mask.

    This indicates a polling loop (e.g., while (!(SR & RXNE))).
    """
    addr_hex = f"0x{target_addr:08x}"
    addr_hex_no_pad = f"0x{target_addr:x}"

    for pattern in (_RE_WHILE_COND, _RE_DO_WHILE_COND):
        for m in pattern.finditer(code):
            cond = m.group(1)
            if (addr_hex in cond or addr_hex_no_pad in cond) and "&" in cond:
                return True
    return False


def _detect_indirect_polling(
    code: str,
    func_read_map: Dict[str, Set[int]],
) -> bool:
    """Check for while (func_call() & MASK) where func_call reads a STATUS register.

    Args:
        code: Decompiled C code of the function.
        func_read_map: Maps function_name → set of MMIO addresses read.
    """
    for pattern in (_RE_WHILE_COND, _RE_DO_WHILE_COND):
        for m in pattern.finditer(code):
            cond = m.group(1)
            if "&" not in cond:
                continue
            # Look for function calls in condition
            for call_m in re.finditer(r"\b(\w+)\s*\(", cond):
                called_func = call_m.group(1)
                if called_func in ("while", "for", "if"):
                    continue
                if called_func in func_read_map:
                    return True
    return False


def _build_func_read_map(
    qualifying: List[MemoryAccess],
) -> Dict[str, Set[int]]:
    """Build map: function_name → set of MMIO addresses read."""
    result: Dict[str, Set[int]] = defaultdict(set)
    for access in qualifying:
        if access.target_addr is not None:
            result[access.function_name].add(access.target_addr)
    return dict(result)


# ── Candidate construction ──────────────────────────────────────────────────


def _classify_mmio_register(
    target_addr: int, cluster_base: int, mai: MemoryAccessIndex,
) -> Optional[Tuple[str, str]]:
    """Classify MMIO register by looking up peripheral type + field name.

    Returns (field_name, classification) or None.
    """
    from ..peripheral_types import get_field_name, classify_register

    # Try to find peripheral type for this cluster base
    periph_type = mai.typed_bases.get(cluster_base)

    # Also check nearby base addresses (cluster may not exactly match base)
    if periph_type is None:
        for base, ptype in mai.typed_bases.items():
            if _cluster_id(base) == cluster_base:
                periph_type = ptype
                break

    if periph_type is None:
        return None

    offset = target_addr - cluster_base
    field_name = get_field_name(periph_type, offset)
    if field_name is None:
        return None

    return (field_name, classify_register(field_name))


def _build_candidate(
    access: MemoryAccess,
    cluster_ctx: Dict[int, _ClusterContext],
    mai: MemoryAccessIndex,
    func_read_map: Optional[Dict[str, Set[int]]] = None,
) -> SourceCandidate:
    """Build a SourceCandidate from a qualifying MMIO load access."""
    cid = _cluster_id(access.target_addr)
    ctx = cluster_ctx.get(cid)

    # Evidence items
    evidence = [
        EvidenceItem(
            evidence_id="E1",
            kind="SITE",
            text=(
                f"*(uint{access.width * 8} *)0x{access.target_addr:08x}"
                f"  // load in {access.function_name}"
            ),
            address=access.function_addr,
            metadata={"width": access.width, "target": access.target_addr},
        ),
        EvidenceItem(
            evidence_id="E2",
            kind="DEF",
            text=f"base_provenance={access.base_provenance}, target=0x{access.target_addr:08x}",
            address=access.target_addr,
            metadata={"provenance": access.base_provenance},
        ),
    ]

    # Facts for downstream stages
    prov = access.base_provenance
    facts: Dict = {
        "addr_expr": f"{prov}(0x{access.target_addr:08x})",
        "segment_of_base": "PERIPHERAL_RANGE",
        "cluster_base": f"0x{cid:08x}",
        "in_isr": False,
    }

    # Confidence scoring
    score = 0.5  # Baseline: CONST load in MMIO range

    if ctx:
        per_reg_rmw = ctx.addr_has_rmw(access.target_addr)
        facts["multi_function_cluster"] = ctx.multi_function
        facts["has_read_modify_write"] = ctx.has_read_modify_write
        facts["per_register_rmw"] = per_reg_rmw
        facts["cluster_load_count"] = ctx.load_count
        facts["cluster_store_count"] = ctx.store_count

        if per_reg_rmw:
            score += 0.2  # Strong: THIS register has RMW pattern
        elif ctx.has_read_modify_write:
            score += 0.05  # Weak: cluster has RMW but not this register
        if ctx.multi_function:
            score += 0.1  # Multiple functions using same peripheral
        if ctx.load_count >= 3:
            score += 0.1  # Multiple reads from same cluster

    # Per-register classification penalty (SR/CR reads are less interesting)
    reg_class = _classify_mmio_register(access.target_addr, cid, mai)
    if reg_class:
        facts["register_name"] = reg_class[0]
        facts["register_class"] = reg_class[1]
        if reg_class[1] == "STATUS":
            score -= 0.20  # Status registers are polling reads, not data sources
        elif reg_class[1] == "CONTROL":
            score -= 0.15  # Control registers are config, not data sources

    # Polling-loop penalty (P7): suppress SR reads used only as loop conditions
    if reg_class and reg_class[1] in ("STATUS", "UNKNOWN"):
        func_code = mai.decompiled_cache.get(access.function_name, "")
        if func_code and access.target_addr is not None:
            if _detect_polling_loop(func_code, access.target_addr):
                score -= 0.15  # Direct polling: strong penalty
                facts["polling_loop"] = True
            elif func_read_map and _detect_indirect_polling(func_code, func_read_map):
                score -= 0.10  # Indirect polling: softer penalty
                facts["indirect_polling"] = True

    score = min(score, 1.0)

    return SourceCandidate(
        address=access.target_addr,
        function_name=access.function_name,
        preliminary_label=SourceLabel.MMIO_READ,
        evidence=evidence,
        confidence_score=score,
        facts=facts,
    )
