import asyncio
from types import SimpleNamespace

from sourceagent.pipeline.models import (
    EvidencePack,
    LLMProposal,
    PipelineResult,
    SinkCandidate,
    SinkLabel,
    VerificationVerdict,
    VerifiedLabel,
)
from sourceagent.pipeline.supervision_queue import build_supervision_queue


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


def _sample_result() -> PipelineResult:
    result = PipelineResult(binary_path="/tmp/fw_supervision.elf", run_id="r-supervision")

    class _FakeMai:
        binary_path = "/tmp/fw_supervision.elf"
        accesses = []
        decompiled_cache = {
            "copy_fn": "void copy_fn(char *dst, int payload_len) { memcpy(dst, src, payload_len); }",
        }

    result._mai = _FakeMai()
    result.sink_candidates = [
        SinkCandidate(
            address=0x08000100,
            function_name="copy_fn",
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
            function_name="copy_fn",
            facts={"len_expr": "payload_len", "has_bounds_guard": False},
        ),
    ]
    result.verified_labels = [
        _mk_verified("p_sink", SinkLabel.COPY_SINK.value, 0x08000100, "copy_fn", conf=0.20),
    ]
    return result


def _sample_raw_sink_only_result() -> PipelineResult:
    result = PipelineResult(binary_path="/tmp/fw_supervision_raw.elf", run_id="r-supervision-raw")

    class _FakeMai:
        binary_path = "/tmp/fw_supervision_raw.elf"
        accesses = []
        decompiled_cache = {
            "copy_fn": "void copy_fn(char *dst, char *src, int payload_len) { memcpy(dst, src, payload_len); }",
        }

    result._mai = _FakeMai()
    result.sink_candidates = [
        SinkCandidate(
            address=0x08000200,
            function_name="copy_fn",
            preliminary_label=SinkLabel.COPY_SINK,
            confidence_score=0.72,
        ),
    ]
    result.evidence_packs = [
        EvidencePack(
            pack_id="p_sink_raw",
            candidate_hint="COPY_SINK",
            binary_path=result.binary_path,
            address=0x08000200,
            function_name="copy_fn",
            facts={"len_expr": "payload_len", "dst_expr": "dst", "src_expr": "src"},
        ),
    ]
    result.verified_labels = []
    return result


def test_build_supervision_queue_sink_scope():
    queue = build_supervision_queue(
        binary_name="fw.elf",
        binary_sha256="abc",
        low_conf_sinks=[
            {
                "chain_id": "c1",
                "sink_id": "s1",
                "score": 0.7,
                "reasons": ["low_confidence"],
            }
        ],
        triage_queue=[
            {
                "chain_id": "c1",
                "triage_rank": 1,
                "triage_priority": 0.9,
            }
        ],
        feature_pack={
            "items": [
                {
                    "chain_id": "c1",
                    "sink": {
                        "sink_id": "s1",
                        "pack_id": "p1",
                        "label": "COPY_SINK",
                        "function": "copy_fn",
                        "site": "0x08000100",
                    },
                    "decompiled_snippets": {"sink_function": "memcpy(...)"},
                    "sink_semantics_hints": {"len_expr": "payload_len"},
                    "decision_basis": {"strict_verdict": "SUSPICIOUS"},
                }
            ]
        },
        verified_sinks=[
            {
                "pack_id": "p1",
                "label": "COPY_SINK",
                "function_name": "copy_fn",
                "confidence": 0.33,
                "evidence_refs": ["E1"],
            }
        ],
        sink_facts_by_pack={"p1": {"len_expr": "payload_len"}},
        max_items=4,
        scope="sinks",
    )
    assert queue["status"] == "ok"
    assert len(queue["items"]) == 1
    item = queue["items"][0]
    assert item["item_kind"] == "sink"
    assert item["proposed_label"] == "COPY_SINK"
    assert item["constraints"]["must_not_add_new_labels"] is True


def test_build_supervision_queue_sink_scope_from_raw_candidates():
    queue = build_supervision_queue(
        binary_name="fw.elf",
        binary_sha256="abc",
        low_conf_sinks=[],
        triage_queue=[],
        feature_pack={"items": []},
        verified_sinks=[],
        sink_facts_by_pack={"p_raw": {"len_expr": "payload_len", "dst_expr": "dst", "src_expr": "src"}},
        sink_candidates=[
            {
                "address": 0x08000200,
                "function_name": "copy_fn",
                "preliminary_label": "COPY_SINK",
                "confidence_score": 0.72,
                "facts": {"len_expr": "payload_len", "dst_expr": "dst", "src_expr": "src"},
                "evidence": [{"evidence_id": "Eraw1", "text": "memcpy(dst, src, payload_len)"}],
            }
        ],
        sink_evidence_packs=[
            {
                "pack_id": "p_raw",
                "candidate_hint": "COPY_SINK",
                "address": 0x08000200,
                "function_name": "copy_fn",
                "facts": {"len_expr": "payload_len", "dst_expr": "dst", "src_expr": "src"},
                "evidence": [{"evidence_id": "Eraw1", "text": "memcpy(dst, src, payload_len)"}],
            }
        ],
        decompiled_cache={
            "copy_fn": "void copy_fn(char *dst, char *src, int payload_len) { memcpy(dst, src, payload_len); }",
        },
        max_items=4,
        scope="sinks",
    )

    assert queue["status"] == "ok"
    assert len(queue["items"]) == 1
    item = queue["items"][0]
    assert item["item_kind"] == "sink"
    assert item["context"]["pack_id"] == "p_raw"
    assert "no_chain_feature_pack" in item["why_suspicious"]
    assert "unverified_sink_candidate" in item["why_suspicious"]
    assert item["evidence_pack"]["sink_facts"]["len_expr"] == "payload_len"


def test_run_stage_8_10_runs_internal_supervision(monkeypatch):
    from sourceagent.interface.main import _run_stage_8_10

    async def _fake_run_review_plan(*args, **kwargs):
        return {
            "review_decisions": [],
            "review_prompt": {"schema_version": "0.2", "status": "empty", "batches": []},
            "review_raw_response": {"schema_version": "0.2", "status": "empty", "batches": []},
            "review_session": {"schema_version": "0.2", "status": "empty", "batches": []},
            "review_trace": {"schema_version": "0.2", "status": "empty", "batches": []},
        }

    async def _fake_run_supervision_plan(supervision_plan, *, model=None, timeout_sec=120):
        item_id = supervision_plan["items"][0]["item_id"]
        return {
            "supervision_decisions": [
                {
                    "item_id": item_id,
                    "decision": "accept",
                    "final_label": "COPY_SINK",
                    "arg_roles": {"dst": "dst", "src": "src", "len": "payload_len"},
                    "reason_codes": ["COPY_WRAPPER_LIKE", "ARG_ROLE_LEN"],
                    "evidence_map": {"review_notes": ["sink_function"]},
                    "confidence": 0.86,
                    "review_notes": "wrapper semantics align with copy sink",
                }
            ],
            "supervision_prompt": {"schema_version": "0.1", "status": "ok", "batches": [{"batch_id": "b0"}]},
            "supervision_raw_response": {"schema_version": "0.1", "status": "ok", "batches": [{"batch_id": "b0", "raw_text": "{}"}]},
            "supervision_session": {"schema_version": "0.1", "status": "ok", "batches": [{"batch_id": "b0", "decision_count": 1}]},
            "supervision_trace": {"schema_version": "0.1", "status": "ok", "batches": [{"batch_id": "b0", "ok": True}]},
        }

    monkeypatch.setattr("sourceagent.agents.review_runner.run_review_plan", _fake_run_review_plan)
    monkeypatch.setattr("sourceagent.interface.main.run_supervision_plan", _fake_run_supervision_plan)

    result = _sample_result()
    args = SimpleNamespace(
        disable_review=False,
        review_mode="semantic",
        review_model="mock-model",
        review_timeout_sec=10,
        max_review_items=0,
        review_batch_size=2,
        verdict_review_json=None,
        calibration_mode="all_matched",
        verdict_output_mode="dual",
        max_calibration_chains=8,
        sample_suspicious_ratio_threshold=0.4,
        min_risk_score=0.45,
        review_needs_threshold=0.55,
        allow_manual_llm_supervision=False,
        llm_promote_budget=4,
        llm_demote_budget=4,
        llm_soft_budget=4,
        review_strict_gates=None,
        review_soft_gates=None,
        review_allow_soft_on_structural_gap=None,
        review_preserve_rejected_rationale=None,
        model=None,
        review_tool_mode="prompt_only",
        enable_supervision=True,
        supervision_scope="sinks",
        supervision_model="mock-model",
        max_supervision_items=4,
        supervision_batch_size=2,
        supervision_timeout_sec=10,
    )

    asyncio.run(_run_stage_8_10(result, max_stage=10, args=args))
    artifacts = result._phase_a_artifacts
    assert artifacts["supervision_queue"]["status"] == "ok"
    assert artifacts["supervision_decisions"]["status"] == "ok"
    assert artifacts["supervision_prompt"]["status"] == "ok"
    assert artifacts["supervision_raw_response"]["status"] == "ok"
    assert artifacts["supervision_session"]["status"] == "ok"
    assert artifacts["supervision_trace"]["status"] == "ok"
    assert artifacts["supervision_decisions"]["items"][0]["item_id"].startswith("sink:")
    assert artifacts["supervision_merge"]["status"] == "ok"
    assert artifacts["supervision_merge"]["stats"]["accepted"] == 1
    assert artifacts["verified_enriched"]["status"] == "ok"
    assert artifacts["verified_enriched"]["stats"]["count"] == 1


def test_run_stage_8_10_enqueues_raw_sink_candidate_without_chain(monkeypatch):
    from sourceagent.interface.main import _run_stage_8_10

    async def _fake_run_review_plan(*args, **kwargs):
        return {
            "review_decisions": [],
            "review_prompt": {"schema_version": "0.2", "status": "empty", "batches": []},
            "review_raw_response": {"schema_version": "0.2", "status": "empty", "batches": []},
            "review_session": {"schema_version": "0.2", "status": "empty", "batches": []},
            "review_trace": {"schema_version": "0.2", "status": "empty", "batches": []},
        }

    async def _fake_run_supervision_plan(supervision_plan, *, model=None, timeout_sec=120):
        item_id = supervision_plan["items"][0]["item_id"]
        return {
            "supervision_decisions": [
                {
                    "item_id": item_id,
                    "decision": "accept",
                    "final_label": "COPY_SINK",
                    "arg_roles": {"dst": "dst", "src": "src", "len": "payload_len"},
                    "reason_codes": ["COPY_WRAPPER_LIKE", "ARG_ROLE_LEN"],
                    "evidence_map": {"classification": ["sink_function"]},
                    "confidence": 0.84,
                    "review_notes": "raw sink candidate looks like a copy sink",
                }
            ],
            "supervision_prompt": {"schema_version": "0.1", "status": "ok", "batches": [{"batch_id": "b0"}]},
            "supervision_raw_response": {"schema_version": "0.1", "status": "ok", "batches": [{"batch_id": "b0", "raw_text": "{}"}]},
            "supervision_session": {"schema_version": "0.1", "status": "ok", "batches": [{"batch_id": "b0", "decision_count": 1}]},
            "supervision_trace": {"schema_version": "0.1", "status": "ok", "batches": [{"batch_id": "b0", "ok": True}]},
        }

    monkeypatch.setattr("sourceagent.agents.review_runner.run_review_plan", _fake_run_review_plan)
    monkeypatch.setattr("sourceagent.interface.main.run_supervision_plan", _fake_run_supervision_plan)

    result = _sample_raw_sink_only_result()
    args = SimpleNamespace(
        disable_review=False,
        review_mode="semantic",
        review_model="mock-model",
        review_timeout_sec=10,
        max_review_items=0,
        review_batch_size=2,
        verdict_review_json=None,
        calibration_mode="all_matched",
        verdict_output_mode="dual",
        max_calibration_chains=8,
        sample_suspicious_ratio_threshold=0.4,
        min_risk_score=0.45,
        review_needs_threshold=0.55,
        allow_manual_llm_supervision=False,
        llm_promote_budget=4,
        llm_demote_budget=4,
        llm_soft_budget=4,
        review_strict_gates=None,
        review_soft_gates=None,
        review_allow_soft_on_structural_gap=None,
        review_preserve_rejected_rationale=None,
        model=None,
        review_tool_mode="prompt_only",
        enable_supervision=True,
        supervision_scope="sinks",
        supervision_model="mock-model",
        max_supervision_items=4,
        supervision_batch_size=2,
        supervision_timeout_sec=10,
    )

    asyncio.run(_run_stage_8_10(result, max_stage=10, args=args))
    artifacts = result._phase_a_artifacts
    assert artifacts["supervision_queue"]["status"] == "ok"
    assert artifacts["supervision_queue"]["items"][0]["context"]["pack_id"] == "p_sink_raw"
    assert "no_chain_feature_pack" in artifacts["supervision_queue"]["items"][0]["why_suspicious"]
    assert artifacts["supervision_decisions"]["status"] == "ok"
    assert artifacts["verified_enriched"]["stats"]["count"] == 1
    assert artifacts["sink_roots"]["feedback_applied"]["sink_supervision"] == 1


def test_run_stage_8_10_runs_all_scope_supervision(monkeypatch):
    from sourceagent.interface.main import _run_stage_8_10

    captured = {}

    async def _fake_run_review_plan(*args, **kwargs):
        return {
            "review_decisions": [],
            "review_prompt": {"schema_version": "0.2", "status": "empty", "batches": []},
            "review_raw_response": {"schema_version": "0.2", "status": "empty", "batches": []},
            "review_session": {"schema_version": "0.2", "status": "empty", "batches": []},
            "review_trace": {"schema_version": "0.2", "status": "empty", "batches": []},
        }

    def _fake_build_supervision_queue(**kwargs):
        return {
            "schema_version": "0.2",
            "binary": "fw.elf",
            "binary_sha256": "abc",
            "scope": "all",
            "status": "ok",
            "items": [
                {
                    "item_id": "sink:copy:0x08000100:COPY_SINK",
                    "item_kind": "sink",
                    "proposed_label": "COPY_SINK",
                    "context": {"function": "copy_fn", "address": "0x08000100"},
                    "evidence_pack": {
                        "decompiled_snippets": {"sink_function": "void copy_fn(char *dst, char *src, int n) { memcpy(dst, src, n); }"},
                        "sink_semantics_hints": {"len_expr": "n", "dst_expr": "dst", "src_expr": "src"},
                        "sink_facts": {"len_expr": "n"},
                    },
                },
                {
                    "item_id": "source:MMIO_READ:40011004:uart_read",
                    "item_kind": "source",
                    "proposed_label": "MMIO_READ",
                    "context": {"function": "uart_read", "target_addr": "0x40011004", "in_isr": False},
                    "evidence_pack": {
                        "decompiled_snippets": {"context_fn_0": "uint8_t uart_read(void) { return *(volatile uint8_t *)0x40011004; }"},
                        "source_facts": {"wrapper_like": True, "target_addr": 0x40011004},
                        "candidate_evidence": ["MMIO read from USART DR"],
                    },
                },
                {
                    "item_id": "object:obj_rx",
                    "item_kind": "object",
                    "proposed_label": "RING_BUFFER",
                    "context": {"object_id": "obj_rx", "region_kind": "SRAM_CLUSTER"},
                    "evidence_pack": {
                        "members": ["g_rx_buf", "g_rx_head", "g_rx_tail"],
                        "writers": ["USART1_IRQHandler"],
                        "readers": ["process_packet"],
                    },
                },
                {
                    "item_id": "channel:obj_rx:ISR:MAIN",
                    "item_kind": "channel",
                    "proposed_label": "ISR_SHARED_CHANNEL",
                    "context": {"object_id": "obj_rx", "src_context": "ISR", "dst_context": "MAIN"},
                    "evidence_pack": {
                        "object_members": ["g_rx_buf", "g_rx_head", "g_rx_tail"],
                        "writer_sites": [{"fn": "USART1_IRQHandler"}],
                        "reader_sites": [{"fn": "process_packet"}],
                    },
                },
            ],
        }

    async def _fake_run_supervision_plan(supervision_plan, *, model=None, timeout_sec=120):
        return {
            "supervision_decisions": [
                {
                    "item_id": "sink:copy:0x08000100:COPY_SINK",
                    "decision": "accept",
                    "final_label": "COPY_SINK",
                    "arg_roles": {"dst": "dst", "src": "src", "len": "n"},
                    "reason_codes": ["COPY_WRAPPER_LIKE", "ARG_ROLE_LEN"],
                    "evidence_map": {"classification": ["sink_function"]},
                    "confidence": 0.86,
                    "review_notes": "copy wrapper",
                },
                {
                    "item_id": "source:MMIO_READ:40011004:uart_read",
                    "decision": "accept",
                    "final_label": "MMIO_READ",
                    "reason_codes": ["SOURCE_LABEL_SUPPORTED", "MMIO_WRAPPER_LIKE", "MMIO_ADDRESS_PRESENT"],
                    "evidence_map": {"classification": ["context_fn_0"]},
                    "confidence": 0.85,
                    "review_notes": "mmio source",
                },
                {
                    "item_id": "object:obj_rx",
                    "decision": "accept",
                    "final_label": "RING_BUFFER",
                    "reason_codes": ["OBJECT_KIND_SUPPORTED", "OBJECT_RING_BUFFER_PATTERN"],
                    "evidence_map": {"classification": ["context_fn_0"]},
                    "confidence": 0.82,
                    "review_notes": "ring buffer object",
                },
                {
                    "item_id": "channel:obj_rx:ISR:MAIN",
                    "decision": "accept",
                    "final_label": "ISR_SHARED_CHANNEL",
                    "reason_codes": ["CHANNEL_EDGE_SUPPORTED", "CHANNEL_ISR_MAIN", "CHANNEL_RING_BUFFER_LIKE"],
                    "evidence_map": {"classification": ["context_fn_0"]},
                    "confidence": 0.81,
                    "review_notes": "isr channel",
                },
            ],
            "supervision_prompt": {"schema_version": "0.2", "status": "ok", "batches": [{"batch_id": "b0"}]},
            "supervision_raw_response": {"schema_version": "0.2", "status": "ok", "batches": [{"batch_id": "b0", "raw_text": "{}"}]},
            "supervision_session": {"schema_version": "0.2", "status": "ok", "batches": [{"batch_id": "b0", "decision_count": 4}]},
            "supervision_trace": {"schema_version": "0.2", "status": "ok", "batches": [{"batch_id": "b0", "ok": True}]},
        }

    def _fake_build_review_plan(feature_pack, calibration_queue, **kwargs):
        captured["feature_pack"] = feature_pack
        captured["calibration_queue"] = calibration_queue
        return {
            "schema_version": "0.2",
            "binary": "fw.elf",
            "status": "empty",
            "items": [],
            "batches": [],
        }

    monkeypatch.setattr("sourceagent.agents.review_runner.run_review_plan", _fake_run_review_plan)
    monkeypatch.setattr("sourceagent.interface.main.build_supervision_queue", _fake_build_supervision_queue)
    monkeypatch.setattr("sourceagent.interface.main.run_supervision_plan", _fake_run_supervision_plan)
    monkeypatch.setattr("sourceagent.agents.review_plan.build_review_plan", _fake_build_review_plan)

    result = _sample_result()
    args = SimpleNamespace(
        disable_review=False,
        review_mode="semantic",
        review_model="mock-model",
        review_timeout_sec=10,
        max_review_items=0,
        review_batch_size=2,
        verdict_review_json=None,
        calibration_mode="all_matched",
        verdict_output_mode="dual",
        max_calibration_chains=8,
        sample_suspicious_ratio_threshold=0.4,
        min_risk_score=0.45,
        review_needs_threshold=0.55,
        allow_manual_llm_supervision=False,
        llm_promote_budget=4,
        llm_demote_budget=4,
        llm_soft_budget=4,
        review_strict_gates=None,
        review_soft_gates=None,
        review_allow_soft_on_structural_gap=None,
        review_preserve_rejected_rationale=None,
        model=None,
        review_tool_mode="prompt_only",
        enable_supervision=True,
        supervision_scope="all",
        supervision_model="mock-model",
        max_supervision_items=8,
        supervision_batch_size=4,
        supervision_timeout_sec=10,
    )

    asyncio.run(_run_stage_8_10(result, max_stage=10, args=args))
    artifacts = result._phase_a_artifacts
    assert artifacts["supervision_queue"]["status"] == "ok"
    assert artifacts["supervision_merge"]["stats"]["accepted"] == 4
    assert artifacts["verified_enriched"]["stats"]["count"] == 2
    assert artifacts["objects_enriched"]["stats"]["count"] == 1
    assert artifacts["channels_enriched"]["stats"]["count"] == 1
    assert captured["feature_pack"]["feedback_applied"]["source_supervision"] == 1
    assert captured["calibration_queue"]["feedback_applied"]["source_supervision"] == 1
