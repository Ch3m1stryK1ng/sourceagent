"""M8 — Facts Bundle: export + query API for verified source/sink labels.

Exports the pipeline's verified labels as a portable facts bundle that
downstream tools (BinAgent, manual review) can load and query.

On-disk format:
  <output_dir>/
    labels.jsonl      — One JSON line per verified label
    index.json        — Metadata + summary statistics

In-memory representation:
  FactsBundle        — Dataclass holding all LabelEntry objects with indexed
                       lookup by function, address, label type, and verdict.

Query API:
  get_sources(bundle, ...)  — Filter source labels
  get_sinks(bundle, ...)    — Filter sink labels
  get_labels(bundle, ...)   — General label query
  build_callsite_queue(bundle) — BinAgent-format task queue entries
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .models import (
    PipelineResult,
    SinkLabel,
    SourceLabel,
    VerificationVerdict,
    VerifiedLabel,
)

logger = logging.getLogger("sourceagent.pipeline.facts_bundle")

# Label type classification
_SOURCE_LABELS = {e.value for e in SourceLabel}
_SINK_LABELS = {e.value for e in SinkLabel}


# ── Data model ────────────────────────────────────────────────────────────


@dataclass
class LabelEntry:
    """A single verified label entry in the facts bundle."""

    label_id: str  # e.g. "MMIO_READ@0x08001234"
    label: str  # SourceLabel or SinkLabel value
    address: int
    function_name: str
    verdict: str  # VerificationVerdict value
    confidence: float = 0.0
    obligations_satisfied: int = 0
    obligations_total: int = 0
    evidence_refs: List[str] = field(default_factory=list)
    pack_id: str = ""
    rationale: str = ""
    facts: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FactsBundle:
    """In-memory collection of verified label entries with indices."""

    binary_path: str = ""
    run_id: str = ""
    created_at: str = ""
    entries: List[LabelEntry] = field(default_factory=list)

    # Lazy-built indices (call _build_indices to populate)
    _by_function: Dict[str, List[LabelEntry]] = field(
        default_factory=dict, repr=False,
    )
    _by_label: Dict[str, List[LabelEntry]] = field(
        default_factory=dict, repr=False,
    )
    _by_address: Dict[int, List[LabelEntry]] = field(
        default_factory=dict, repr=False,
    )
    _by_verdict: Dict[str, List[LabelEntry]] = field(
        default_factory=dict, repr=False,
    )

    def __post_init__(self):
        if self.entries:
            self._build_indices()

    def _build_indices(self):
        """Rebuild lookup indices from entries."""
        self._by_function.clear()
        self._by_label.clear()
        self._by_address.clear()
        self._by_verdict.clear()

        for entry in self.entries:
            self._by_function.setdefault(entry.function_name, []).append(entry)
            self._by_label.setdefault(entry.label, []).append(entry)
            self._by_address.setdefault(entry.address, []).append(entry)
            self._by_verdict.setdefault(entry.verdict, []).append(entry)

    @property
    def label_count(self) -> int:
        return len(self.entries)

    @property
    def source_count(self) -> int:
        return sum(1 for e in self.entries if e.label in _SOURCE_LABELS)

    @property
    def sink_count(self) -> int:
        return sum(1 for e in self.entries if e.label in _SINK_LABELS)


# ── Build from pipeline result ────────────────────────────────────────────


def build_facts_bundle(
    result: PipelineResult,
    accepted_verdicts: Optional[Sequence[str]] = None,
) -> FactsBundle:
    """Build a FactsBundle from a completed PipelineResult.

    Args:
        result: Completed pipeline result with verified_labels.
        accepted_verdicts: Which verdicts to include. Default: VERIFIED + PARTIAL.

    Returns:
        FactsBundle with LabelEntry objects for each accepted label.
    """
    if accepted_verdicts is None:
        accepted_verdicts = (
            VerificationVerdict.VERIFIED.value,
            VerificationVerdict.PARTIAL.value,
        )

    entries: List[LabelEntry] = []
    for vl in result.verified_labels:
        if vl.verdict.value not in accepted_verdicts:
            continue
        entry = _verified_label_to_entry(vl)
        entries.append(entry)

    bundle = FactsBundle(
        binary_path=result.binary_path,
        run_id=result.run_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        entries=entries,
    )
    bundle._build_indices()

    logger.info(
        "Built facts bundle: %d entries (%d sources, %d sinks) from %d verified labels",
        len(entries), bundle.source_count, bundle.sink_count,
        len(result.verified_labels),
    )
    return bundle


def _verified_label_to_entry(vl: VerifiedLabel) -> LabelEntry:
    """Convert a VerifiedLabel to a LabelEntry."""
    label = vl.final_label or vl.proposal.label
    addr = vl.proposal.address
    label_id = f"{label}@0x{addr:08x}" if addr is not None else f"{label}@{vl.pack_id}"

    ob_satisfied = sum(
        1 for o in vl.obligations if o.status.value == "satisfied"
    )

    # Extract facts from proposal claims
    facts: Dict[str, Any] = {}
    for claim in vl.proposal.claims:
        if isinstance(claim, dict):
            facts.update(claim)

    return LabelEntry(
        label_id=label_id,
        label=label,
        address=addr,
        function_name=vl.proposal.function_name,
        verdict=vl.verdict.value,
        confidence=vl.proposal.confidence,
        obligations_satisfied=ob_satisfied,
        obligations_total=len(vl.obligations),
        evidence_refs=list(vl.proposal.evidence_refs),
        pack_id=vl.pack_id,
        rationale=vl.proposal.notes,
        facts=facts,
    )


# ── Disk I/O ──────────────────────────────────────────────────────────────


def write_facts_bundle(bundle: FactsBundle, output_dir: str) -> Path:
    """Write a FactsBundle to disk as labels.jsonl + index.json.

    Args:
        bundle: The facts bundle to write.
        output_dir: Directory to write into (created if needed).

    Returns:
        Path to the output directory.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # labels.jsonl
    labels_path = out / "labels.jsonl"
    with labels_path.open("w", encoding="utf-8") as f:
        for entry in bundle.entries:
            line = json.dumps(_entry_to_dict(entry), default=str)
            f.write(line + "\n")

    # index.json
    by_label: Dict[str, int] = {}
    by_verdict: Dict[str, int] = {}
    for entry in bundle.entries:
        by_label[entry.label] = by_label.get(entry.label, 0) + 1
        by_verdict[entry.verdict] = by_verdict.get(entry.verdict, 0) + 1

    index = {
        "binary_path": bundle.binary_path,
        "run_id": bundle.run_id,
        "created_at": bundle.created_at,
        "label_count": bundle.label_count,
        "source_count": bundle.source_count,
        "sink_count": bundle.sink_count,
        "by_label": by_label,
        "by_verdict": by_verdict,
        "functions": sorted(set(e.function_name for e in bundle.entries if e.function_name)),
    }

    index_path = out / "index.json"
    index_path.write_text(
        json.dumps(index, indent=2, default=str),
        encoding="utf-8",
    )

    logger.info("Wrote facts bundle to %s (%d labels)", out, bundle.label_count)
    return out


def load_facts_bundle(input_dir: str) -> FactsBundle:
    """Load a FactsBundle from a directory containing labels.jsonl + index.json.

    Args:
        input_dir: Directory containing the bundle files.

    Returns:
        FactsBundle with all entries loaded and indexed.

    Raises:
        FileNotFoundError: If labels.jsonl doesn't exist.
    """
    inp = Path(input_dir)
    labels_path = inp / "labels.jsonl"
    index_path = inp / "index.json"

    if not labels_path.exists():
        raise FileNotFoundError(f"labels.jsonl not found in {inp}")

    # Load entries
    entries: List[LabelEntry] = []
    with labels_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            entries.append(_dict_to_entry(data))

    # Load index metadata
    binary_path = ""
    run_id = ""
    created_at = ""
    if index_path.exists():
        index = json.loads(index_path.read_text(encoding="utf-8"))
        binary_path = index.get("binary_path", "")
        run_id = index.get("run_id", "")
        created_at = index.get("created_at", "")

    bundle = FactsBundle(
        binary_path=binary_path,
        run_id=run_id,
        created_at=created_at,
        entries=entries,
    )
    bundle._build_indices()

    logger.info("Loaded facts bundle from %s: %d entries", inp, len(entries))
    return bundle


def _entry_to_dict(entry: LabelEntry) -> dict:
    """Serialize a LabelEntry to a JSON-safe dict."""
    return {
        "label_id": entry.label_id,
        "label": entry.label,
        "address": entry.address,
        "function_name": entry.function_name,
        "verdict": entry.verdict,
        "confidence": entry.confidence,
        "obligations_satisfied": entry.obligations_satisfied,
        "obligations_total": entry.obligations_total,
        "evidence_refs": entry.evidence_refs,
        "pack_id": entry.pack_id,
        "rationale": entry.rationale,
        "facts": entry.facts,
    }


def _dict_to_entry(data: dict) -> LabelEntry:
    """Deserialize a dict to a LabelEntry."""
    return LabelEntry(
        label_id=data.get("label_id", ""),
        label=data.get("label", ""),
        address=data.get("address", 0),
        function_name=data.get("function_name", ""),
        verdict=data.get("verdict", ""),
        confidence=data.get("confidence", 0.0),
        obligations_satisfied=data.get("obligations_satisfied", 0),
        obligations_total=data.get("obligations_total", 0),
        evidence_refs=data.get("evidence_refs", []),
        pack_id=data.get("pack_id", ""),
        rationale=data.get("rationale", ""),
        facts=data.get("facts", {}),
    )


# ── Query API ─────────────────────────────────────────────────────────────


def get_sources(
    bundle: FactsBundle,
    func: Optional[str] = None,
    label_type: Optional[str] = None,
    verdict: Optional[str] = None,
) -> List[LabelEntry]:
    """Query source labels from the bundle.

    Args:
        bundle: Facts bundle to query.
        func: Filter by function name (substring match).
        label_type: Filter by specific source label (e.g. "MMIO_READ").
        verdict: Filter by verdict (e.g. "VERIFIED").

    Returns:
        Matching LabelEntry objects (source labels only).
    """
    results = [e for e in bundle.entries if e.label in _SOURCE_LABELS]
    return _apply_filters(results, func=func, label_type=label_type, verdict=verdict)


def get_sinks(
    bundle: FactsBundle,
    func: Optional[str] = None,
    label_type: Optional[str] = None,
    verdict: Optional[str] = None,
) -> List[LabelEntry]:
    """Query sink labels from the bundle.

    Args:
        bundle: Facts bundle to query.
        func: Filter by function name (substring match).
        label_type: Filter by specific sink label (e.g. "COPY_SINK").
        verdict: Filter by verdict (e.g. "VERIFIED").

    Returns:
        Matching LabelEntry objects (sink labels only).
    """
    results = [e for e in bundle.entries if e.label in _SINK_LABELS]
    return _apply_filters(results, func=func, label_type=label_type, verdict=verdict)


def get_labels(
    bundle: FactsBundle,
    addr: Optional[int] = None,
    func: Optional[str] = None,
    label_type: Optional[str] = None,
    verdict: Optional[str] = None,
) -> List[LabelEntry]:
    """General label query with optional filters.

    Args:
        bundle: Facts bundle to query.
        addr: Filter by exact address.
        func: Filter by function name (substring match).
        label_type: Filter by label type.
        verdict: Filter by verdict.

    Returns:
        Matching LabelEntry objects.
    """
    if addr is not None:
        results = list(bundle._by_address.get(addr, []))
    else:
        results = list(bundle.entries)
    return _apply_filters(results, func=func, label_type=label_type, verdict=verdict)


def _apply_filters(
    entries: List[LabelEntry],
    func: Optional[str] = None,
    label_type: Optional[str] = None,
    verdict: Optional[str] = None,
) -> List[LabelEntry]:
    """Apply optional filters to a list of label entries."""
    if func is not None:
        entries = [e for e in entries if func in e.function_name]
    if label_type is not None:
        entries = [e for e in entries if e.label == label_type]
    if verdict is not None:
        entries = [e for e in entries if e.verdict == verdict]
    return entries


# ── BinAgent Integration ──────────────────────────────────────────────────


def build_callsite_queue(bundle: FactsBundle) -> List[Dict[str, Any]]:
    """Build BinAgent-format callsite queue from sink labels.

    Each queue entry tells BinAgent which sink to investigate, with context
    about evidence and potential source taint roots.

    Args:
        bundle: Facts bundle with verified labels.

    Returns:
        List of task dicts for BinAgent's callsite queue.
    """
    # Collect source hints for cross-referencing
    source_hints: Dict[str, List[str]] = {}  # function -> list of source label_ids
    for entry in bundle.entries:
        if entry.label in _SOURCE_LABELS:
            source_hints.setdefault(entry.function_name, []).append(entry.label_id)

    queue: List[Dict[str, Any]] = []
    for entry in bundle.entries:
        if entry.label not in _SINK_LABELS:
            continue

        # Find source hints for the same function or all functions
        hints = source_hints.get(entry.function_name, [])

        task = {
            "task": "analyze_sink",
            "sink_label_id": entry.label_id,
            "label": entry.label,
            "address": entry.address,
            "function": entry.function_name,
            "verdict": entry.verdict,
            "confidence": entry.confidence,
            "context": {
                "evidence_refs": entry.evidence_refs,
                "source_hints": hints,
                "facts": entry.facts,
            },
        }
        queue.append(task)

    logger.info("Built callsite queue: %d tasks from %d sink labels", len(queue), bundle.sink_count)
    return queue
