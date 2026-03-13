"""Typed reason codes for Phase A.5 supervision decisions."""

from __future__ import annotations

from typing import Iterable, List


SUPERVISION_REASON_CODES = {
    # Generic / merge-state hints
    "AUDIT_ONLY_PRESERVED",
    "DETERMINISTIC_GATE_PASSED",
    "INSUFFICIENT_STRUCTURAL_SUPPORT",
    "UNSUPPORTED_LABEL",
    # Sink-side
    "ARG_ROLE_DST",
    "ARG_ROLE_SRC",
    "ARG_ROLE_LEN",
    "ARG_ROLE_INDEX",
    "COPY_WRAPPER_LIKE",
    "FORMAT_WRAPPER_LIKE",
    "LOOP_COPY_PATTERN",
    "LOOP_WRITE_PATTERN",
    "FUNC_PTR_DISPATCH_PATTERN",
    "MEMSET_PATTERN",
    "SINK_LABEL_MISMATCH",
    "SINK_LABEL_SUPPORTED",
    "SINK_SEMANTICS_UNCLEAR",
    "THUNK_OR_WRAPPER_CALL",
    "WEAK_XREF_RECOVERY",
    # Source-side
    "SOURCE_LABEL_SUPPORTED",
    "MMIO_WRAPPER_LIKE",
    "DMA_WRAPPER_LIKE",
    "ISR_WRAPPER_LIKE",
    "SHARED_BUFFER_SOURCE",
    "MMIO_ADDRESS_PRESENT",
    "ISR_CONTEXT_PRESENT",
    "DMA_CONFIG_PRESENT",
    # Object / channel-side
    "OBJECT_KIND_SUPPORTED",
    "OBJECT_SHARED_WRITER_READER",
    "OBJECT_RING_BUFFER_PATTERN",
    "OBJECT_FLAG_PATTERN",
    "CHANNEL_EDGE_SUPPORTED",
    "CHANNEL_ISR_MAIN",
    "CHANNEL_DMA_CPU",
    "CHANNEL_QUEUE_LIKE",
    "CHANNEL_RING_BUFFER_LIKE",
}

_ALIASES = {
    "arg_role_dst": "ARG_ROLE_DST",
    "arg_role_src": "ARG_ROLE_SRC",
    "arg_role_len": "ARG_ROLE_LEN",
    "arg_role_index": "ARG_ROLE_INDEX",
    "audit_only": "AUDIT_ONLY_PRESERVED",
    "gate_passed": "DETERMINISTIC_GATE_PASSED",
    "insufficient_support": "INSUFFICIENT_STRUCTURAL_SUPPORT",
    "unsupported_label": "UNSUPPORTED_LABEL",
    "copy_wrapper": "COPY_WRAPPER_LIKE",
    "format_wrapper": "FORMAT_WRAPPER_LIKE",
    "loop_copy": "LOOP_COPY_PATTERN",
    "loop_write": "LOOP_WRITE_PATTERN",
    "func_ptr_dispatch": "FUNC_PTR_DISPATCH_PATTERN",
    "memset": "MEMSET_PATTERN",
    "label_mismatch": "SINK_LABEL_MISMATCH",
    "label_supported": "SINK_LABEL_SUPPORTED",
    "semantics_unclear": "SINK_SEMANTICS_UNCLEAR",
    "wrapper_call": "THUNK_OR_WRAPPER_CALL",
    "weak_xref": "WEAK_XREF_RECOVERY",
    "source_label_supported": "SOURCE_LABEL_SUPPORTED",
    "mmio_wrapper": "MMIO_WRAPPER_LIKE",
    "dma_wrapper": "DMA_WRAPPER_LIKE",
    "isr_wrapper": "ISR_WRAPPER_LIKE",
    "shared_buffer": "SHARED_BUFFER_SOURCE",
    "mmio_address": "MMIO_ADDRESS_PRESENT",
    "isr_context": "ISR_CONTEXT_PRESENT",
    "dma_config": "DMA_CONFIG_PRESENT",
    "object_kind_supported": "OBJECT_KIND_SUPPORTED",
    "shared_writer_reader": "OBJECT_SHARED_WRITER_READER",
    "ring_buffer": "OBJECT_RING_BUFFER_PATTERN",
    "flag_pattern": "OBJECT_FLAG_PATTERN",
    "channel_edge_supported": "CHANNEL_EDGE_SUPPORTED",
    "channel_isr_main": "CHANNEL_ISR_MAIN",
    "channel_dma_cpu": "CHANNEL_DMA_CPU",
    "queue_like": "CHANNEL_QUEUE_LIKE",
    "channel_ring_buffer": "CHANNEL_RING_BUFFER_LIKE",
}


def normalize_supervision_reason_codes(values: Iterable[object]) -> List[str]:
    out: List[str] = []
    for raw in values or []:
        key = str(raw or "").strip()
        if not key:
            continue
        key = _ALIASES.get(key.lower(), key.upper())
        if key in SUPERVISION_REASON_CODES and key not in out:
            out.append(key)
    return out
