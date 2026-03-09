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


def test_phase_a_effective_check_marks_safe_or_low_risk():
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
    assert ch["verdict"] == "SAFE_OR_LOW_RISK"


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
