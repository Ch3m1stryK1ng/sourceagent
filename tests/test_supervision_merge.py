from sourceagent.pipeline.supervision_merge import apply_supervision_merge


def test_apply_supervision_merge_accepts_copy_sink_with_supporting_evidence():
    queue = {
        "items": [
            {
                "item_id": "sink:0x08000100:COPY_SINK",
                "item_kind": "sink",
                "sink_id": "s1",
                "proposed_label": "COPY_SINK",
                "context": {"function": "copy_fn", "address": "0x08000100"},
                "evidence_pack": {
                    "decompiled_snippets": {
                        "sink_function": "void copy_fn(char *dst, char *src, int n) { memcpy(dst, src, n); }"
                    },
                    "sink_semantics_hints": {"len_expr": "n", "dst_expr": "dst", "src_expr": "src"},
                    "sink_facts": {"len_expr": "n"},
                },
            }
        ]
    }
    decisions = [
        {
            "item_id": "sink:0x08000100:COPY_SINK",
            "decision": "accept",
            "final_label": "COPY_SINK",
            "arg_roles": {"dst": "dst", "src": "src", "len": "n"},
            "reason_codes": ["COPY_WRAPPER_LIKE", "ARG_ROLE_LEN"],
            "evidence_map": {"classification": ["sink_function"]},
            "confidence": 0.91,
            "review_notes": "wrapper looks like a copy sink",
        }
    ]

    out = apply_supervision_merge(
        binary_name="fw.elf",
        binary_sha256="abc123",
        supervision_queue=queue,
        supervision_decisions=decisions,
    )

    merge = out["supervision_merge"]
    enriched = out["verified_enriched"]

    assert merge["status"] == "ok"
    assert merge["stats"]["accepted"] == 1
    assert merge["items"][0]["accepted"] is True
    assert "copy_primitive" in merge["items"][0]["support_signals"]
    assert enriched["status"] == "ok"
    assert enriched["stats"]["count"] == 1
    assert enriched["items"][0]["label"] == "COPY_SINK"


def test_apply_supervision_merge_rejects_without_gate_support():
    queue = {
        "items": [
            {
                "item_id": "sink:0x08000200:FUNC_PTR_SINK",
                "item_kind": "sink",
                "sink_id": "s2",
                "proposed_label": "FUNC_PTR_SINK",
                "context": {"function": "fn", "address": "0x08000200"},
                "evidence_pack": {
                    "decompiled_snippets": {"sink_function": "void fn(void) { return; }"},
                    "sink_semantics_hints": {},
                    "sink_facts": {},
                },
            }
        ]
    }
    decisions = [
        {
            "item_id": "sink:0x08000200:FUNC_PTR_SINK",
            "decision": "accept",
            "final_label": "FUNC_PTR_SINK",
            "arg_roles": {},
            "reason_codes": [],
            "evidence_map": {},
            "confidence": 0.55,
            "review_notes": "",
        }
    ]

    out = apply_supervision_merge(
        binary_name="fw.elf",
        binary_sha256="abc123",
        supervision_queue=queue,
        supervision_decisions=decisions,
    )

    assert out["supervision_merge"]["items"][0]["accepted"] is False
    assert out["supervision_merge"]["items"][0]["failure_code"] == "GATE_NOT_SATISFIED"
    assert out["verified_enriched"]["status"] == "empty"


def test_apply_supervision_merge_accepts_store_sink_with_supporting_evidence():
    queue = {
        "items": [
            {
                "item_id": "sink:SINK_store:0x08000300:STORE_SINK",
                "item_kind": "sink",
                "sink_id": "SINK_store",
                "proposed_label": "STORE_SINK",
                "context": {"function": "USBH_ParseCfgDesc", "address": "0x08000300"},
                "evidence_pack": {
                    "decompiled_snippets": {
                        "sink_function": "void USBH_ParseCfgDesc(uint8_t *buf, cfg_t *cfg_desc) { cfg_desc->wTotalLength = buf[2]; cfg_desc->bNumInterfaces = buf[4]; }"
                    },
                    "sink_semantics_hints": {"dst_expr": "cfg_desc", "target_expr": "cfg_desc->wTotalLength"},
                    "sink_facts": {"input_derived": True},
                },
            }
        ]
    }
    decisions = [
        {
            "item_id": "sink:SINK_store:0x08000300:STORE_SINK",
            "decision": "accept",
            "final_label": "STORE_SINK",
            "arg_roles": {"dst": "cfg_desc", "src": "buf"},
            "reason_codes": ["SINK_LABEL_SUPPORTED", "ARG_ROLE_DST", "ARG_ROLE_SRC"],
            "evidence_map": {"classification": ["sink_function"]},
            "confidence": 0.92,
            "review_notes": "field stores into destination object from attacker-controlled bytes",
        }
    ]

    out = apply_supervision_merge(
        binary_name="fw.elf",
        binary_sha256="abc123",
        supervision_queue=queue,
        supervision_decisions=decisions,
    )

    assert out["supervision_merge"]["items"][0]["accepted"] is True
    assert out["verified_enriched"]["stats"]["count"] == 1
    assert out["verified_enriched"]["items"][0]["label"] == "STORE_SINK"


def test_apply_supervision_merge_accepts_mmio_source():
    queue = {
        "items": [
            {
                "item_id": "source:MMIO_READ:40011004:uart_read",
                "item_kind": "source",
                "proposed_label": "MMIO_READ",
                "context": {"function": "uart_read", "address": "0x08000040", "target_addr": "0x40011004", "in_isr": False},
                "evidence_pack": {
                    "decompiled_snippets": {"context_fn_0": "uint8_t uart_read(void) { return *(volatile uint8_t *)0x40011004; }"},
                    "source_facts": {"wrapper_like": True, "target_addr": 0x40011004},
                    "candidate_evidence": ["MMIO read from USART DR"],
                },
            }
        ]
    }
    decisions = [
        {
            "item_id": "source:MMIO_READ:40011004:uart_read",
            "decision": "accept",
            "final_label": "MMIO_READ",
            "reason_codes": ["SOURCE_LABEL_SUPPORTED", "MMIO_WRAPPER_LIKE", "MMIO_ADDRESS_PRESENT"],
            "evidence_map": {"classification": ["context_fn_0"]},
            "confidence": 0.87,
            "review_notes": "wrapper reads directly from a peripheral register",
        }
    ]

    out = apply_supervision_merge(
        binary_name="fw.elf",
        binary_sha256="abc123",
        supervision_queue=queue,
        supervision_decisions=decisions,
    )

    assert out["supervision_merge"]["items"][0]["accepted"] is True
    assert out["verified_enriched"]["stats"]["count"] == 1
    assert out["verified_enriched"]["items"][0]["label"] == "MMIO_READ"


def test_apply_supervision_merge_accepts_object_candidate():
    queue = {
        "items": [
            {
                "item_id": "object:obj_rx",
                "item_kind": "object",
                "proposed_label": "RING_BUFFER",
                "context": {
                    "object_id": "obj_rx",
                    "region_kind": "SRAM_CLUSTER",
                    "addr_range": ["0x20000000", "0x2000007f"],
                    "producer_contexts": ["ISR"],
                    "consumer_contexts": ["MAIN"],
                },
                "evidence_pack": {
                    "members": ["g_rx_buf", "g_rx_head", "g_rx_tail"],
                    "writers": ["USART1_IRQHandler"],
                    "readers": ["process_packet"],
                    "type_facts": {"refine_status": "coarse"},
                },
            }
        ]
    }
    decisions = [
        {
            "item_id": "object:obj_rx",
            "decision": "accept",
            "final_label": "RING_BUFFER",
            "reason_codes": ["OBJECT_KIND_SUPPORTED", "OBJECT_RING_BUFFER_PATTERN"],
            "evidence_map": {"classification": ["context_fn_0"]},
            "confidence": 0.8,
            "review_notes": "shared head/tail members indicate a ring buffer object",
        }
    ]

    out = apply_supervision_merge(
        binary_name="fw.elf",
        binary_sha256="abc123",
        supervision_queue=queue,
        supervision_decisions=decisions,
    )

    assert out["supervision_merge"]["items"][0]["accepted"] is True
    assert out["objects_enriched"]["stats"]["count"] == 1
    assert out["objects_enriched"]["items"][0]["label"] == "RING_BUFFER"


def test_apply_supervision_merge_accepts_channel_candidate():
    queue = {
        "items": [
            {
                "item_id": "channel:obj_rx:ISR:MAIN",
                "item_kind": "channel",
                "proposed_label": "ISR_SHARED_CHANNEL",
                "context": {"object_id": "obj_rx", "src_context": "ISR", "dst_context": "MAIN", "score": 0.72},
                "evidence_pack": {
                    "object_members": ["g_rx_buf", "g_rx_head", "g_rx_tail"],
                    "type_facts": {"refine_status": "coarse"},
                    "writer_sites": [{"fn": "USART1_IRQHandler"}],
                    "reader_sites": [{"fn": "process_packet"}],
                },
            }
        ]
    }
    decisions = [
        {
            "item_id": "channel:obj_rx:ISR:MAIN",
            "decision": "accept",
            "final_label": "ISR_SHARED_CHANNEL",
            "reason_codes": ["CHANNEL_EDGE_SUPPORTED", "CHANNEL_ISR_MAIN", "CHANNEL_RING_BUFFER_LIKE"],
            "evidence_map": {"classification": ["context_fn_0"]},
            "confidence": 0.83,
            "review_notes": "ISR writes and MAIN reads the same ring-buffer-like object",
        }
    ]

    out = apply_supervision_merge(
        binary_name="fw.elf",
        binary_sha256="abc123",
        supervision_queue=queue,
        supervision_decisions=decisions,
    )

    assert out["supervision_merge"]["items"][0]["accepted"] is True
    assert out["channels_enriched"]["stats"]["count"] == 1
    assert out["channels_enriched"]["items"][0]["label"] == "ISR_SHARED_CHANNEL"


def test_apply_supervision_merge_soft_accepts_object_from_semantic_support():
    queue = {
        "items": [
            {
                "item_id": "object:obj_cfg",
                "item_kind": "object",
                "proposed_label": "DMA_BUFFER",
                "context": {
                    "object_id": "obj_cfg",
                    "region_kind": "SRAM_CLUSTER",
                },
                "evidence_pack": {
                    "members": ["cfg_desc_raw"],
                    "type_facts": {},
                },
            }
        ]
    }
    decisions = [
        {
            "item_id": "object:obj_cfg",
            "decision": "uncertain",
            "final_label": "DMA_BUFFER",
            "reason_codes": ["OBJECT_KIND_SUPPORTED"],
            "evidence_map": {"classification": ["context_fn_0"]},
            "confidence": 0.75,
            "review_notes": "looks like a dma-fed shared object",
        }
    ]

    out = apply_supervision_merge(
        binary_name="fw.elf",
        binary_sha256="abc123",
        supervision_queue=queue,
        supervision_decisions=decisions,
    )

    row = out["supervision_merge"]["items"][0]
    assert row["accepted"] is True
    assert row["merge_state"] == "soft_accepted"
    assert out["objects_enriched"]["stats"]["count"] == 1
    assert out["objects_enriched"]["items"][0]["label"] == "DMA_BUFFER"
    assert "evidence_pack" in out["objects_enriched"]["items"][0]


def test_apply_supervision_merge_soft_accepts_channel_from_semantic_support():
    queue = {
        "items": [
            {
                "item_id": "channel:obj_cfg:DMA:MAIN",
                "item_kind": "channel",
                "proposed_label": "DMA_CHANNEL",
                "context": {"src_context": "UNKNOWN", "dst_context": "MAIN"},
                "evidence_pack": {
                    "object_members": ["cfg_desc_raw"],
                },
            }
        ]
    }
    decisions = [
        {
            "item_id": "channel:obj_cfg:DMA:MAIN",
            "decision": "uncertain",
            "final_label": "DMA_CHANNEL",
            "reason_codes": ["CHANNEL_DMA_CPU"],
            "evidence_map": {"classification": ["context_fn_0"]},
            "confidence": 0.75,
            "review_notes": "dma to cpu handoff is plausible",
        }
    ]

    out = apply_supervision_merge(
        binary_name="fw.elf",
        binary_sha256="abc123",
        supervision_queue=queue,
        supervision_decisions=decisions,
    )

    row = out["supervision_merge"]["items"][0]
    assert row["accepted"] is True
    assert row["merge_state"] == "soft_accepted"
    assert out["channels_enriched"]["stats"]["count"] == 1
    assert out["channels_enriched"]["items"][0]["label"] == "DMA_CHANNEL"
    assert "evidence_pack" in out["channels_enriched"]["items"][0]


def test_apply_supervision_merge_soft_accepts_uncertain_object_with_strict_gate():
    queue = {
        "items": [
            {
                "item_id": "object:obj_flag",
                "item_kind": "object",
                "proposed_label": "FLAG",
                "context": {
                    "object_id": "obj_flag",
                    "region_kind": "FLAG",
                    "addr_range": ["0x20000000", "0x20000003"],
                    "producer_contexts": ["ISR"],
                    "consumer_contexts": ["MAIN"],
                },
                "evidence_pack": {
                    "members": ["rx_ready_flag"],
                    "writers": ["irq_handler"],
                    "readers": ["main_loop"],
                    "type_facts": {"condition_sites": ["if (rx_ready_flag != 0)"]},
                },
            }
        ]
    }
    decisions = [
        {
            "item_id": "object:obj_flag",
            "decision": "uncertain",
            "final_label": "FLAG",
            "reason_codes": ["OBJECT_KIND_SUPPORTED", "OBJECT_FLAG_PATTERN", "OBJECT_SHARED_WRITER_READER"],
            "evidence_map": {"classification": ["context_fn_0"]},
            "confidence": 0.82,
            "review_notes": "shared ISR/main flag object is likely real but semantically conservative",
        }
    ]

    out = apply_supervision_merge(
        binary_name="fw.elf",
        binary_sha256="abc123",
        supervision_queue=queue,
        supervision_decisions=decisions,
    )

    row = out["supervision_merge"]["items"][0]
    assert row["accepted"] is True
    assert row["merge_state"] == "soft_accepted"
    assert out["objects_enriched"]["stats"]["count"] == 1


def test_apply_supervision_merge_soft_accepts_uncertain_channel_with_strict_gate():
    queue = {
        "items": [
            {
                "item_id": "channel:obj_dma:DMA:MAIN",
                "item_kind": "channel",
                "proposed_label": "DMA_CHANNEL",
                "context": {"object_id": "obj_dma", "src_context": "DMA", "dst_context": "MAIN", "score": 0.81},
                "evidence_pack": {
                    "writer_sites": [{"fn": "dma_irq"}],
                    "reader_sites": [{"fn": "main_loop"}],
                    "edge_constraints": [{"expr": "dma_done != 0"}],
                },
            }
        ]
    }
    decisions = [
        {
            "item_id": "channel:obj_dma:DMA:MAIN",
            "decision": "uncertain",
            "final_label": "DMA_CHANNEL",
            "reason_codes": ["CHANNEL_EDGE_SUPPORTED", "CHANNEL_DMA_CPU"],
            "evidence_map": {"classification": ["context_fn_0"]},
            "confidence": 0.84,
            "review_notes": "dma handoff is likely real though reviewer stays conservative",
        }
    ]

    out = apply_supervision_merge(
        binary_name="fw.elf",
        binary_sha256="abc123",
        supervision_queue=queue,
        supervision_decisions=decisions,
    )

    row = out["supervision_merge"]["items"][0]
    assert row["accepted"] is True
    assert row["merge_state"] == "soft_accepted"
    assert out["channels_enriched"]["stats"]["count"] == 1
