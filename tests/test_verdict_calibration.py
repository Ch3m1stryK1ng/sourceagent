from sourceagent.pipeline.verdict_calibration import build_verdict_calibration_artifacts


def _sample_chain(verdict="SUSPICIOUS"):
    return {
        "chain_id": "chain_fw_0001_root000",
        "verdict": verdict,
        "score": 0.63,
        "sink": {
            "label": "COPY_SINK",
            "function": "copy_fn",
            "site": "0x08001000",
            "root_expr": "payload_len",
        },
        "steps": [
            {"kind": "SOURCE", "label": "MMIO_READ", "function": "uart_receive"},
        ],
        "checks": [{"expr": "payload_len <= max_len", "strength": "unknown", "site": "copy_fn"}],
        "derive_facts": [{"expr": "payload_len = hdr->len", "site": "copy_fn"}],
        "evidence_refs": ["E1", "E2"],
        "root_bundle": {
            "active_root": {
                "expr": "payload_len",
                "canonical_expr": "hdr->len",
                "kind": "length",
                "role": "primary",
                "source": "miner_facts",
            },
        },
        "link_debug": {
            "object_hits": ["obj_rx"],
            "producer_candidates": ["uart_receive"],
            "bridge_functions": ["parse_packet"],
        },
        "decision_basis": {
            "source_reached": True,
            "root_controllable": True,
            "check_strength": "unknown",
            "chain_complete": True,
            "has_contradiction": False,
            "has_app_anchor": True,
            "control_path_only": False,
            "chain_score": 0.63,
            "source_resolve_mode": "same_context_direct_call",
            "secondary_root_only": False,
            "channel_required_hint": False,
            "has_channel": False,
            "confirm_threshold": 0.8,
            "reason_code": "CHECK_UNCERTAIN",
        },
    }


def test_build_verdict_calibration_artifacts_emits_feature_pack_and_queue():
    artifacts = build_verdict_calibration_artifacts(
        binary_name="fw.elf",
        binary_sha256="deadbeef",
        chains=[_sample_chain()],
        channel_graph={
            "object_nodes": [
                {
                    "object_id": "obj_rx",
                    "members": ["g_rx_buf"],
                    "addr_range": ["0x20000000", "0x2000007f"],
                    "producer_contexts": ["ISR"],
                    "consumer_contexts": ["MAIN"],
                    "type_facts": {"kind_hint": "payload"},
                },
            ],
        },
        sink_facts_by_pack={"p1": {"len_expr": "payload_len", "dst_expr": "dst", "guard_expr": "payload_len <= max_len"}},
        sink_pack_id_by_site={"0x08001000|copy_fn|COPY_SINK": "p1"},
        decompiled_cache={
            "copy_fn": "void copy_fn(char *dst, int payload_len) { if (payload_len <= max_len) memcpy(dst, src, payload_len); }",
            "parse_packet": "void parse_packet(void) { copy_fn(dst, hdr->len); }",
            "uart_receive": "int uart_receive(void) { return USART1_DR; }",
        },
        calibration_mode="suspicious_only",
        verdict_output_mode="dual",
    )

    item = artifacts["verdict_feature_pack"]["items"][0]
    queue = artifacts["verdict_calibration_queue"]["items"]
    soft = artifacts["verdict_soft_triage"]["items"][0]

    assert item["sample_id"] == "fw"
    assert item["sink"]["label"] == "COPY_SINK"
    assert item["root"]["family"] == "length"
    assert item["sink_semantics_hints"]["len_expr"] == "payload_len"
    assert item["guard_context"]
    assert item["capacity_evidence"]
    assert item["decompiled_snippets"]["sink_function"]
    assert len(queue) == 1
    assert queue[0]["queue_reasons"]
    assert soft["queue_eligible"] is True



def test_review_decision_fails_closed_without_evidence_map():
    artifacts = build_verdict_calibration_artifacts(
        binary_name="fw.elf",
        binary_sha256="deadbeef",
        chains=[_sample_chain()],
        channel_graph={"object_nodes": [{"object_id": "obj_rx", "members": ["g_rx_buf"]}]},
        sink_facts_by_pack={"p1": {"len_expr": "payload_len"}},
        sink_pack_id_by_site={"0x08001000|copy_fn|COPY_SINK": "p1"},
        decompiled_cache={"copy_fn": "memcpy(dst, src, payload_len);"},
        calibration_mode="all_non_exact",
        verdict_output_mode="dual",
        allow_manual_llm_supervision=True,
        review_decisions=[
            {
                "chain_id": "chain_fw_0001_root000",
                "suggested_semantic_verdict": "CONFIRMED",
                "trigger_summary": "payload_len can exceed destination capacity",
                "manual_supervision": True,
            },
        ],
    )

    decision = artifacts["verdict_calibration_decisions"]["items"][0]
    soft = artifacts["verdict_soft_triage"]["items"][0]

    assert decision["accepted"] is False
    assert decision["accept_reason"] == "MISSING_EVIDENCE_MAP"
    assert soft["soft_verdict"] == "SUSPICIOUS"



def test_review_decision_can_promote_when_evidence_is_present():
    artifacts = build_verdict_calibration_artifacts(
        binary_name="fw.elf",
        binary_sha256="deadbeef",
        chains=[_sample_chain()],
        channel_graph={"object_nodes": [{"object_id": "obj_rx", "members": ["g_rx_buf"]}]},
        sink_facts_by_pack={"p1": {"len_expr": "payload_len"}},
        sink_pack_id_by_site={"0x08001000|copy_fn|COPY_SINK": "p1"},
        decompiled_cache={
            "copy_fn": "void copy_fn(char *dst, int payload_len) { memcpy(dst, src, payload_len); }",
            "parse_packet": "void parse_packet(void) { copy_fn(dst, hdr->len); }",
            "uart_receive": "int uart_receive(void) { return USART1_DR; }",
        },
        calibration_mode="all_non_exact",
        verdict_output_mode="dual",
        allow_manual_llm_supervision=True,
        review_decisions=[
            {
                "chain_id": "chain_fw_0001_root000",
                "suggested_semantic_verdict": "CONFIRMED",
                "trigger_summary": "payload_len remains attacker-controlled at sink",
                "manual_supervision": True,
                "evidence_map": {
                    "trigger_summary": ["sink_function", "caller_bridge"],
                    "root_controllability": ["sink_function"],
                },
                "preconditions": {
                    "state_predicates": ["rx_ready != 0"],
                    "root_constraints": ["payload_len > dst_capacity"],
                },
            },
        ],
    )

    decision = artifacts["verdict_calibration_decisions"]["items"][0]
    soft = artifacts["verdict_soft_triage"]["items"][0]

    assert decision["accepted"] is True
    assert decision["accept_reason"] == "ACCEPTED_REVIEW"
    assert soft["soft_verdict"] == "CONFIRMED"
    assert soft["llm_reviewed"] is True


def test_audit_only_keeps_strict_verdict_even_with_valid_review():
    artifacts = build_verdict_calibration_artifacts(
        binary_name="fw.elf",
        binary_sha256="deadbeef",
        chains=[_sample_chain()],
        channel_graph={"object_nodes": [{"object_id": "obj_rx", "members": ["g_rx_buf"]}]},
        sink_facts_by_pack={"p1": {"len_expr": "payload_len"}},
        sink_pack_id_by_site={"0x08001000|copy_fn|COPY_SINK": "p1"},
        decompiled_cache={
            "copy_fn": "void copy_fn(char *dst, int payload_len) { memcpy(dst, src, payload_len); }",
            "parse_packet": "void parse_packet(void) { copy_fn(dst, hdr->len); }",
            "uart_receive": "int uart_receive(void) { return USART1_DR; }",
        },
        calibration_mode="audit_only",
        verdict_output_mode="dual",
        review_decisions=[
            {
                "chain_id": "chain_fw_0001_root000",
                "suggested_semantic_verdict": "CONFIRMED",
                "trigger_summary": "payload_len remains attacker-controlled at sink",
                "evidence_map": {
                    "trigger_summary": ["sink_function"],
                },
                "audit_flags": ["CHECK_NOT_BINDING_ROOT"],
            },
        ],
    )

    soft = artifacts["verdict_soft_triage"]["items"][0]
    decision = artifacts["verdict_calibration_decisions"]["items"][0]
    assert decision["accepted"] is True
    assert soft["final_verdict"] == soft["strict_verdict"]


def test_rejected_review_preserves_semantic_rationale():
    chain = _sample_chain()
    chain["link_debug"] = {
        "object_hits": [],
        "producer_candidates": ["uart_receive"],
        "bridge_functions": ["parse_packet"],
    }
    artifacts = build_verdict_calibration_artifacts(
        binary_name="fw.elf",
        binary_sha256="deadbeef",
        chains=[chain],
        channel_graph={"object_nodes": []},
        sink_facts_by_pack={"p1": {"len_expr": "payload_len"}},
        sink_pack_id_by_site={"0x08001000|copy_fn|COPY_SINK": "p1"},
        decompiled_cache={
            "copy_fn": "void copy_fn(char *dst, int payload_len) { memcpy(dst, src, payload_len); }",
            "parse_packet": "void parse_packet(void) { copy_fn(dst, hdr->len); }",
            "uart_receive": "int uart_receive(void) { return USART1_DR; }",
        },
        calibration_mode="all_non_exact",
        verdict_output_mode="dual",
        review_decisions=[
            {
                "chain_id": "chain_fw_0001_root000",
                "suggested_semantic_verdict": "CONFIRMED",
                "trigger_summary": "payload_len can exceed destination capacity",
                "preconditions": {
                    "state_predicates": ["rx_ready != 0"],
                    "root_constraints": ["payload_len > dst_capacity"],
                    "why_check_fails": ["guard missing"],
                },
                "segment_assessment": [
                    {
                        "segment_id": "sink_triggerability",
                        "status": "possible",
                        "reason_codes": ["TRIGGERABLE_LEN_GT_CAPACITY"],
                        "summary": "root can exceed destination capacity",
                        "evidence_map": {"summary": ["sink_function"]}
                    }
                ],
                "reason_codes": ["TRIGGERABLE_LEN_GT_CAPACITY"],
                "evidence_map": {
                    "trigger_summary": ["sink_function"],
                    "root_controllability": ["sink_function"],
                },
            }
        ],
    )

    decision = artifacts["verdict_calibration_decisions"]["items"][0]
    assert decision["accepted"] is False
    assert decision["accept_reason"] == "STRUCTURAL_CONSTRAINT_NOT_MET"
    assert decision["trigger_summary"] == "payload_len can exceed destination capacity"
    assert decision["preconditions"]["root_constraints"] == ["payload_len > dst_capacity"]
    assert decision["segment_assessment"][0]["segment_id"] == "sink_triggerability"
    assert decision["reason_codes"] == ["TRIGGERABLE_LEN_GT_CAPACITY"]
