"""Tests for phase-A chain artifact contracts."""

from sourceagent.pipeline.chain_artifacts import build_phase_a_artifacts
from sourceagent.pipeline.models import (
    EvidencePack,
    LLMProposal,
    PipelineResult,
    SourceCandidate,
    SourceLabel,
    SinkCandidate,
    SinkLabel,
    VerificationVerdict,
    VerifiedLabel,
)


def _mk_verified(pack_id: str, label: str, addr: int, fn: str, conf: float = 0.9) -> VerifiedLabel:
    return VerifiedLabel(
        pack_id=pack_id,
        proposal=LLMProposal(
            pack_id=pack_id,
            label=label,
            address=addr,
            function_name=fn,
            confidence=conf,
            evidence_refs=["E1"],
        ),
        obligations=[],
        verdict=VerificationVerdict.VERIFIED,
        final_label=label,
    )


def test_phase_a_contracts_and_confirmed_verdict():
    result = PipelineResult(binary_path="/tmp/fw.elf", run_id="r1")
    class _FakeMai:
        binary_path = "/tmp/fw.elf"
        accesses = []
        decompiled_cache = {
            "process_packet": """
void process_packet(char *dst, unsigned int payload_len) {
  payload_len = uart_receive();
  memcpy(dst, local, payload_len);
}
""",
        }
    result._mai = _FakeMai()
    result.source_candidates = [
        SourceCandidate(
            address=0x40011004,
            function_name="uart_receive",
            preliminary_label=SourceLabel.MMIO_READ,
            confidence_score=0.9,
        ),
    ]
    result.sink_candidates = [
        SinkCandidate(
            address=0x08000100,
            function_name="process_packet",
            preliminary_label=SinkLabel.COPY_SINK,
            confidence_score=0.95,
        ),
    ]
    result.evidence_packs = [
        EvidencePack(
            pack_id="p_sink",
            candidate_hint="COPY_SINK",
            binary_path=result.binary_path,
            address=0x08000100,
            function_name="process_packet",
            facts={
                "len_expr": "payload_len",
                "has_bounds_guard": False,
            },
        ),
    ]
    result.verified_labels = [
        _mk_verified("p_src", SourceLabel.MMIO_READ.value, 0x40011004, "uart_receive", conf=0.92),
        _mk_verified("p_sink", SinkLabel.COPY_SINK.value, 0x08000100, "process_packet", conf=0.95),
    ]

    artifacts = build_phase_a_artifacts(result)

    assert set(artifacts.keys()) >= {
        "channel_graph",
        "refined_objects",
        "sink_roots",
        "chains",
        "chain_eval",
        "low_conf_sinks",
        "triage_queue",
        "verdict_feature_pack",
        "verdict_calibration_queue",
        "verdict_calibration_decisions",
        "verdict_audit_flags",
        "verdict_soft_triage",
        "verdict_review_plan",
        "verdict_review_prompt",
        "verdict_review_raw_response",
        "verdict_review_session",
        "verdict_review_trace",
        "supervision_queue",
        "supervision_decisions",
        "supervision_prompt",
        "supervision_raw_response",
        "supervision_session",
        "supervision_trace",
        "supervision_merge",
        "verified_enriched",
        "objects_enriched",
        "channels_enriched",
    }

    sink_roots = artifacts["sink_roots"]["sink_roots"]
    assert len(sink_roots) == 1
    assert sink_roots[0]["status"] == "ok"
    assert sink_roots[0]["roots"][0]["expr"] == "payload_len"
    assert sink_roots[0]["root_source"] == "miner_facts"

    chains = artifacts["chains"]["chains"]
    assert len(chains) == 1
    ch = chains[0]
    assert ch["has_app_anchor"] is True
    assert ch["verdict"] == "CONFIRMED"
    assert ch["status"] == "ok"
    assert artifacts["chain_eval"]["by_failure_code"] == {}
    assert artifacts["verdict_feature_pack"]["status"] == "ok"
    assert artifacts["verdict_feature_pack"]["items"]
    assert artifacts["verdict_soft_triage"]["status"] == "ok"
    assert artifacts["verdict_calibration_queue"]["status"] == "ok"
    assert artifacts["verdict_review_plan"]["status"] == "not_run"
    assert artifacts["verdict_review_prompt"]["status"] == "not_run"
    assert artifacts["verdict_review_raw_response"]["status"] == "not_run"
    assert artifacts["verdict_review_session"]["status"] == "not_run"
    assert artifacts["verdict_review_trace"]["status"] == "not_run"
    assert artifacts["supervision_queue"]["status"] == "not_run"
    assert artifacts["supervision_decisions"]["status"] == "not_run"
    assert artifacts["supervision_prompt"]["status"] == "not_run"
    assert artifacts["supervision_raw_response"]["status"] == "not_run"
    assert artifacts["supervision_session"]["status"] == "not_run"
    assert artifacts["supervision_trace"]["status"] == "not_run"
    assert artifacts["supervision_merge"]["status"] == "not_run"
    assert artifacts["verified_enriched"]["status"] == "not_run"
    assert artifacts["objects_enriched"]["status"] == "not_run"
    assert artifacts["channels_enriched"]["status"] == "not_run"


def test_phase_a_root_unresolved_generates_low_conf_item():
    result = PipelineResult(binary_path="/tmp/fw2.elf", run_id="r2")
    result.verified_labels = [
        _mk_verified("p_sink2", SinkLabel.COPY_SINK.value, 0x08000200, "copy_fn", conf=0.20),
    ]

    artifacts = build_phase_a_artifacts(result, t_low=0.45)

    sink_roots = artifacts["sink_roots"]["sink_roots"]
    assert sink_roots[0]["status"] == "partial"
    assert sink_roots[0]["failure_code"] == "ROOT_FACT_MISSING"

    chains = artifacts["chains"]["chains"]
    assert chains[0]["status"] == "partial"
    assert chains[0]["failure_code"] == "ROOT_FACT_MISSING"

    low_conf = artifacts["low_conf_sinks"]["items"]
    assert len(low_conf) == 1
    assert "status_partial" in low_conf[0]["reasons"]


def test_phase_a_effective_root_bound_check_marks_suspicious_until_dst_extent_is_known():
    result = PipelineResult(binary_path="/tmp/fw3.elf", run_id="r3")
    result.evidence_packs = [
        EvidencePack(
            pack_id="p_sink3",
            candidate_hint="MEMSET_SINK",
            binary_path=result.binary_path,
            address=0x08000300,
            function_name="clear_buf",
            facts={
                "len_expr": "count",
                "has_bounds_guard": True,
                "guard_expr": "count <= 64",
            },
        ),
    ]
    result.verified_labels = [
        _mk_verified("p_src3", SourceLabel.MMIO_READ.value, 0x40011000, "read_len", conf=0.8),
        _mk_verified("p_sink3", SinkLabel.MEMSET_SINK.value, 0x08000300, "clear_buf", conf=0.8),
    ]

    artifacts = build_phase_a_artifacts(result)
    ch = artifacts["chains"]["chains"][0]

    assert ch["checks"][0]["strength"] == "effective"
    assert ch["checks"][0]["capacity_scope"] == "root_bound"
    assert ch["verdict"] == "SUSPICIOUS"
    assert ch["decision_basis"]["reason_code"] == "EFFECTIVE_GUARD_UNSCOPED"


def test_phase_a_stage8_only_produces_channel_side():
    result = PipelineResult(binary_path="/tmp/fw_stage8.elf", run_id="r8")
    result.verified_labels = [
        _mk_verified("p_src8", SourceLabel.MMIO_READ.value, 0x40011000, "uart_isr", conf=0.9),
        _mk_verified("p_sink8", SinkLabel.COPY_SINK.value, 0x08001000, "copy_fn", conf=0.9),
    ]

    artifacts = build_phase_a_artifacts(result, max_stage=8)

    assert artifacts["channel_graph"]["status"] == "ok"
    assert artifacts["refined_objects"]["status"] == "ok"
    assert artifacts["sink_roots"]["status"] == "not_run"
    assert artifacts["chains"]["status"] == "not_run"
    assert artifacts["chain_eval"]["status"] == "not_run"
    assert artifacts["low_conf_sinks"]["status"] == "not_run"
    assert artifacts["triage_queue"]["status"] == "not_run"


def test_phase_a_stage9_produces_linking_but_not_triage():
    result = PipelineResult(binary_path="/tmp/fw_stage9.elf", run_id="r9")
    result.verified_labels = [
        _mk_verified("p_src9", SourceLabel.MMIO_READ.value, 0x40011000, "uart_isr", conf=0.9),
        _mk_verified("p_sink9", SinkLabel.COPY_SINK.value, 0x08002000, "copy_fn", conf=0.9),
    ]

    artifacts = build_phase_a_artifacts(result, max_stage=9)

    assert artifacts["sink_roots"]["status"] == "ok"
    assert artifacts["chains"]["status"] == "ok"
    assert artifacts["chain_eval"]["status"] == "ok"
    assert artifacts["low_conf_sinks"]["status"] == "not_run"
    assert artifacts["triage_queue"]["status"] == "not_run"
    assert artifacts["verdict_feature_pack"]["status"] == "not_run"
    assert artifacts["verdict_calibration_queue"]["status"] == "not_run"
    assert artifacts["verdict_calibration_decisions"]["status"] == "not_run"
    assert artifacts["verdict_audit_flags"]["status"] == "not_run"
    assert artifacts["verdict_soft_triage"]["status"] == "not_run"
    assert artifacts["verdict_review_plan"]["status"] == "not_run"
    assert artifacts["verdict_review_prompt"]["status"] == "not_run"
    assert artifacts["verdict_review_raw_response"]["status"] == "not_run"
    assert artifacts["verdict_review_session"]["status"] == "not_run"
    assert artifacts["verdict_review_trace"]["status"] == "not_run"
    assert artifacts["supervision_queue"]["status"] == "not_run"
    assert artifacts["supervision_decisions"]["status"] == "not_run"
    assert artifacts["supervision_prompt"]["status"] == "not_run"
    assert artifacts["supervision_raw_response"]["status"] == "not_run"
    assert artifacts["supervision_session"]["status"] == "not_run"
    assert artifacts["supervision_trace"]["status"] == "not_run"
    assert artifacts["supervision_merge"]["status"] == "not_run"
    assert artifacts["verified_enriched"]["status"] == "not_run"
    assert artifacts["objects_enriched"]["status"] == "not_run"
    assert artifacts["channels_enriched"]["status"] == "not_run"


def test_phase_a_stage9_stage10_keep_loop_copy_parity_for_stripped_names():
    class _FakeMai:
        accesses = []

        def __init__(self, binary_path: str, function_name: str):
            self.binary_path = binary_path
            self.decompiled_cache = {
                function_name: """
void FUN_08000100(char *param_1, char *param_2, unsigned int param_3) {
  for (i = 0; i < param_3; i = i + 1) {
    param_1[i] = param_2[i];
  }
}
""",
            }

    def _make_result(binary_path: str, function_name: str) -> PipelineResult:
        result = PipelineResult(binary_path=binary_path, run_id=f"r-{function_name}")
        result._mai = _FakeMai(binary_path, function_name)
        result.evidence_packs = [
            EvidencePack(
                pack_id="p_sink",
                candidate_hint="COPY_SINK",
                binary_path=binary_path,
                address=0x08000100,
                function_name=function_name,
                facts={
                    "promoted_from": "LOOP_WRITE_SINK",
                    "callee": "loop_copy_idiom",
                    "in_loop": True,
                    "len_expr": "param_3",
                    "dst_expr": "param_1[i]",
                    "src_expr": "param_2[i]",
                    "store_expr": "param_1[i]",
                },
            ),
        ]
        result.verified_labels = [
            _mk_verified("p_sink", SinkLabel.COPY_SINK.value, 0x08000100, function_name, conf=0.82),
        ]
        return result

    artifacts_unstripped = build_phase_a_artifacts(_make_result("/tmp/fw_unstripped.elf", "copy_fn"))
    artifacts_stripped = build_phase_a_artifacts(_make_result("/tmp/fw_stripped.elf", "FUN_08000100"))

    roots_unstripped = artifacts_unstripped["sink_roots"]["sink_roots"][0]["roots"]
    roots_stripped = artifacts_stripped["sink_roots"]["sink_roots"][0]["roots"]
    assert [row["expr"] for row in roots_unstripped] == [row["expr"] for row in roots_stripped]

    chain_unstripped = artifacts_unstripped["chains"]["chains"][0]
    chain_stripped = artifacts_stripped["chains"]["chains"][0]
    assert chain_unstripped["status"] == chain_stripped["status"]
    assert chain_unstripped["verdict"] == chain_stripped["verdict"]

    low_conf_unstripped = artifacts_unstripped["low_conf_sinks"]["items"]
    low_conf_stripped = artifacts_stripped["low_conf_sinks"]["items"]
    assert len(low_conf_unstripped) == len(low_conf_stripped)


def test_phase_a_source_supervision_feedback_marks_rebuilt_artifacts():
    result = PipelineResult(binary_path="/tmp/fw_feedback.elf", run_id="r-feedback")

    class _FakeMai:
        binary_path = "/tmp/fw_feedback.elf"
        accesses = []
        decompiled_cache = {
            "copy_fn": """
void copy_fn(char *dst, unsigned int payload_len) {
  payload_len = uart_read();
  memcpy(dst, local, payload_len);
}
""",
        }

    result._mai = _FakeMai()
    result.evidence_packs = [
        EvidencePack(
            pack_id="p_sink",
            candidate_hint="COPY_SINK",
            binary_path=result.binary_path,
            address=0x08004000,
            function_name="copy_fn",
            facts={"len_expr": "payload_len", "has_bounds_guard": False},
        ),
    ]
    result.verified_labels = [
        _mk_verified("p_sink", SinkLabel.COPY_SINK.value, 0x08004000, "copy_fn", conf=0.95),
    ]

    supervision_queue = {
        "schema_version": "0.2",
        "binary": "/tmp/fw_feedback.elf",
        "items": [
            {
                "item_id": "source:mmio:uart_read",
                "item_kind": "source",
                "proposed_label": "MMIO_READ",
                "context": {"function": "uart_read", "target_addr": "0x40011004"},
            }
        ],
        "status": "ok",
    }
    supervision_decisions = [
        {
            "item_id": "source:mmio:uart_read",
            "decision": "accept",
            "final_label": "MMIO_READ",
            "reason_codes": ["SOURCE_LABEL_SUPPORTED", "MMIO_ADDRESS_PRESENT"],
            "evidence_map": {"classification": ["context_fn_0"]},
            "confidence": 0.88,
            "review_notes": "mmio wrapper source",
        }
    ]

    artifacts = build_phase_a_artifacts(
        result,
        supervision_queue=supervision_queue,
        supervision_decisions=supervision_decisions,
    )

    assert artifacts["channel_graph"]["feedback_applied"]["source_supervision"] == 1
    assert artifacts["verdict_feature_pack"]["feedback_applied"]["source_supervision"] == 1
    assert artifacts["verdict_calibration_queue"]["feedback_applied"]["source_supervision"] == 1


def test_phase_a_sink_supervision_feedback_rebuilds_stage9_stage10():
    result = PipelineResult(binary_path="/tmp/fw_sink_feedback.elf", run_id="r-sink-feedback")

    class _FakeMai:
        binary_path = "/tmp/fw_sink_feedback.elf"
        accesses = []
        decompiled_cache = {
            "copy_fn": """
void copy_fn(char *dst, char *src, unsigned int payload_len) {
  memcpy(dst, src, payload_len);
}
""",
        }

    result._mai = _FakeMai()
    result.evidence_packs = [
        EvidencePack(
            pack_id="p_sink_feedback",
            candidate_hint="COPY_SINK",
            binary_path=result.binary_path,
            address=0x08006000,
            function_name="copy_fn",
            facts={"len_expr": "payload_len", "dst_expr": "dst", "src_expr": "src"},
        ),
    ]
    result.verified_labels = [
        _mk_verified("p_src", SourceLabel.MMIO_READ.value, 0x40011004, "uart_read", conf=0.92),
    ]

    supervision_queue = {
        "schema_version": "0.2",
        "binary": "/tmp/fw_sink_feedback.elf",
        "items": [
            {
                "item_id": "sink:p_sink_feedback:0x08006000:COPY_SINK",
                "item_kind": "sink",
                "proposed_label": "COPY_SINK",
                "context": {
                    "function": "copy_fn",
                    "address": "0x08006000",
                    "pack_id": "p_sink_feedback",
                },
                "evidence_pack": {
                    "decompiled_snippets": {
                        "sink_function": "void copy_fn(char *dst, char *src, unsigned int payload_len) { memcpy(dst, src, payload_len); }",
                    },
                    "sink_semantics_hints": {"len_expr": "payload_len", "dst_expr": "dst", "src_expr": "src"},
                    "sink_facts": {"len_expr": "payload_len", "dst_expr": "dst", "src_expr": "src"},
                },
            }
        ],
        "status": "ok",
    }
    supervision_decisions = [
        {
            "item_id": "sink:p_sink_feedback:0x08006000:COPY_SINK",
            "decision": "accept",
            "final_label": "COPY_SINK",
            "arg_roles": {"dst": "dst", "src": "src", "len": "payload_len"},
            "reason_codes": ["COPY_WRAPPER_LIKE", "ARG_ROLE_LEN"],
            "evidence_map": {"classification": ["sink_function"]},
            "confidence": 0.89,
            "review_notes": "copy wrapper sink confirmed",
        }
    ]

    artifacts = build_phase_a_artifacts(
        result,
        supervision_queue=supervision_queue,
        supervision_decisions=supervision_decisions,
    )

    assert artifacts["supervision_merge"]["stats"]["accepted"] == 1
    assert len(artifacts["sink_roots"]["sink_roots"]) == 1
    assert artifacts["sink_roots"]["sink_roots"][0]["sink_function"] == "copy_fn"
    assert artifacts["verdict_feature_pack"]["items"]
    assert artifacts["sink_roots"]["feedback_applied"]["sink_supervision"] == 1
    assert artifacts["chains"]["feedback_applied"]["sink_supervision"] == 1
    assert artifacts["verdict_feature_pack"]["feedback_applied"]["sink_supervision"] == 1


def test_phase_a_object_channel_supervision_feedback_augments_stage8():
    result = PipelineResult(binary_path="/tmp/fw_obj_feedback.elf", run_id="r-obj-feedback")

    class _FakeMai:
        binary_path = "/tmp/fw_obj_feedback.elf"
        accesses = []
        decompiled_cache = {
            "copy_fn": """
void copy_fn(char *dst, unsigned int payload_len) {
  payload_len = uart_read();
  memcpy(dst, local, payload_len);
}
""",
            "producer": """
void producer(void) {
  g_rx_buf[0] = uart_read();
}
""",
        }

    result._mai = _FakeMai()
    result.evidence_packs = [
        EvidencePack(
            pack_id="p_sink",
            candidate_hint="COPY_SINK",
            binary_path=result.binary_path,
            address=0x08005000,
            function_name="copy_fn",
            facts={"len_expr": "payload_len", "has_bounds_guard": False},
        ),
    ]
    result.verified_labels = [
        _mk_verified("p_src", SourceLabel.MMIO_READ.value, 0x40011004, "producer", conf=0.92),
        _mk_verified("p_sink", SinkLabel.COPY_SINK.value, 0x08005000, "copy_fn", conf=0.95),
    ]

    supervision_queue = {
        "schema_version": "0.2",
        "binary": "/tmp/fw_obj_feedback.elf",
        "items": [
            {
                "item_id": "object:obj_rx_buf",
                "item_kind": "object",
                "proposed_label": "RING_BUFFER",
                "context": {
                    "object_id": "obj_rx_buf",
                    "region_kind": "RING_BUFFER",
                    "addr_range": ["0x20000000", "0x2000003f"],
                    "producer_contexts": ["ISR"],
                    "consumer_contexts": ["MAIN"],
                },
                "evidence_pack": {
                    "members": ["g_rx_buf", "g_rx_head", "g_rx_tail"],
                    "writer_sites": [{"fn": "producer", "addr": "0x08001000"}],
                    "reader_sites": [{"fn": "copy_fn", "addr": "0x08005000"}],
                    "type_facts": {"kind_hint": "buffer"},
                },
            },
            {
                "item_id": "channel:obj_rx_buf:ISR:MAIN",
                "item_kind": "channel",
                "proposed_label": "RING_BUFFER_CHANNEL",
                "context": {
                    "object_id": "obj_rx_buf",
                    "src_context": "ISR",
                    "dst_context": "MAIN",
                    "region_kind": "RING_BUFFER",
                },
                "evidence_pack": {
                    "object_members": ["g_rx_buf", "g_rx_head", "g_rx_tail"],
                    "writer_sites": [{"fn": "producer", "addr": "0x08001000"}],
                    "reader_sites": [{"fn": "copy_fn", "addr": "0x08005000"}],
                },
            },
        ],
        "status": "ok",
    }
    supervision_decisions = [
        {
            "item_id": "object:obj_rx_buf",
            "decision": "accept",
            "final_label": "RING_BUFFER",
            "reason_codes": ["OBJECT_RING_BUFFER_PATTERN"],
            "evidence_map": {"classification": ["context_fn_0"]},
            "confidence": 0.91,
            "review_notes": "shared ring buffer object",
        },
        {
            "item_id": "channel:obj_rx_buf:ISR:MAIN",
            "decision": "accept",
            "final_label": "RING_BUFFER_CHANNEL",
            "reason_codes": ["CHANNEL_ISR_TO_MAIN"],
            "evidence_map": {"classification": ["context_fn_0"]},
            "confidence": 0.9,
            "review_notes": "shared ISR to MAIN channel",
        },
    ]

    artifacts = build_phase_a_artifacts(
        result,
        supervision_queue=supervision_queue,
        supervision_decisions=supervision_decisions,
    )

    object_ids = {str(row.get("object_id", "") or "") for row in artifacts["channel_graph"].get("object_nodes", [])}
    edge_keys = {
        (
            str(row.get("object_id", "") or ""),
            str(row.get("src_context", "") or ""),
            str(row.get("dst_context", "") or ""),
        )
        for row in artifacts["channel_graph"].get("channel_edges", [])
    }
    assert "obj_rx_buf" in object_ids
    assert ("obj_rx_buf", "ISR", "MAIN") in edge_keys
    assert artifacts["channel_graph"]["feedback_applied"]["object_supervision"] == 1
    assert artifacts["channel_graph"]["feedback_applied"]["channel_supervision"] == 1
    assert artifacts["verdict_feature_pack"]["feedback_applied"]["object_supervision"] == 1
    assert artifacts["verdict_calibration_queue"]["feedback_applied"]["channel_supervision"] == 1
