import asyncio
from types import SimpleNamespace

from sourceagent.agents.review_plan import build_review_plan
from sourceagent.agents.review_runner import run_review_plan
from sourceagent.llm.review_schema import parse_review_response
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


def _sample_result() -> PipelineResult:
    result = PipelineResult(binary_path="/tmp/fw_review.elf", run_id="r-review")

    class _FakeMai:
        binary_path = "/tmp/fw_review.elf"
        accesses = []
        decompiled_cache = {
            "copy_fn": "void copy_fn(char *dst, int payload_len) { memcpy(dst, src, payload_len); }",
            "parse_packet": "void parse_packet(void) { copy_fn(dst, hdr->len); }",
            "uart_receive": "int uart_receive(void) { return USART1_DR; }",
        }

    result._mai = _FakeMai()
    result.source_candidates = [
        SourceCandidate(address=0x40011004, function_name="uart_receive", preliminary_label=SourceLabel.MMIO_READ, confidence_score=0.9),
    ]
    result.sink_candidates = [
        SinkCandidate(address=0x08000100, function_name="copy_fn", preliminary_label=SinkLabel.COPY_SINK, confidence_score=0.95),
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
        _mk_verified("p_src", SourceLabel.MMIO_READ.value, 0x40011004, "uart_receive", conf=0.92),
        _mk_verified("p_sink", SinkLabel.COPY_SINK.value, 0x08000100, "copy_fn", conf=0.95),
    ]
    return result


def test_parse_review_response_accepts_fenced_json():
    text = """```json
{"decisions": [{"chain_id": "c1", "suggested_semantic_verdict": "SUSPICIOUS", "trigger_summary": "x", "preconditions": {}, "evidence_map": {"trigger_summary": ["sink_function"]}}]}
```"""
    decisions, meta = parse_review_response(text, default_review_mode="semantic_review", allowed_chain_ids=["c1"])
    assert meta["ok"] is True
    assert len(decisions) == 1
    assert decisions[0]["chain_id"] == "c1"




def test_parse_review_response_accepts_required_output_wrapper():
    text = '{"required_output": {"decisions": [{"chain_id": "c2", "suggested_semantic_verdict": "CONFIRMED", "trigger_summary": "x", "preconditions": {}, "evidence_map": {"trigger_summary": ["sink_function"]}}]}}'
    decisions, meta = parse_review_response(text, default_review_mode="semantic_review", allowed_chain_ids=["c2"])
    assert meta["ok"] is True
    assert len(decisions) == 1
    assert decisions[0]["chain_id"] == "c2"


def test_build_review_plan_batches_items():
    feature_pack = {
        "items": [
            {"chain_id": "c1", "risk_score": 0.8, "sink": {}, "root": {}, "derive_facts": [], "check_facts": [], "object_path": [], "channel_path": [], "sink_semantics_hints": {}, "guard_context": [], "capacity_evidence": [], "deterministic_constraints": {}, "decision_basis": {}, "decompiled_snippets": {}},
            {"chain_id": "c2", "risk_score": 0.6, "sink": {}, "root": {}, "derive_facts": [], "check_facts": [], "object_path": [], "channel_path": [], "sink_semantics_hints": {}, "guard_context": [], "capacity_evidence": [], "deterministic_constraints": {}, "decision_basis": {}, "decompiled_snippets": {}},
        ]
    }
    queue = {
        "items": [
            {"chain_id": "c2", "queue_score": 0.6, "queue_reasons": ["needs_review"]},
            {"chain_id": "c1", "queue_score": 0.8, "queue_reasons": ["suspicious_verdict"]},
        ]
    }
    plan = build_review_plan(feature_pack, queue, max_items=2, batch_size=1)
    assert plan["status"] == "ok"
    assert [item["chain_id"] for item in plan["items"]] == ["c1", "c2"]
    assert len(plan["batches"]) == 2


def test_review_runner_uses_mock_llm(monkeypatch):
    class _FakeLLM:
        def __init__(self, model=None):
            self.model = model

        async def simple_completion(self, prompt, system=None):
            return '{"decisions": [{"chain_id": "c1", "suggested_semantic_verdict": "SUSPICIOUS", "trigger_summary": "len can exceed dst", "preconditions": {"state_predicates": ["rx_ready != 0"], "root_constraints": ["len > cap"], "why_check_fails": ["guard missing"]}, "evidence_map": {"trigger_summary": ["sink_function"], "root_controllability": ["producer_function"]}, "audit_flags": ["CHECK_NOT_BINDING_ROOT"], "review_mode": "semantic_review"}]}'

    monkeypatch.setattr("sourceagent.agents.review_runner.LLM", _FakeLLM)
    plan = {
        "items": [{"chain_id": "c1"}],
        "batches": [{"batch_id": "b0", "chain_ids": ["c1"], "items": [{"chain_id": "c1", "current_verdict": "SUSPICIOUS", "sink": {}, "root": {}, "derive_facts": [], "check_facts": [], "object_path": [], "channel_path": [], "sink_semantics_hints": {}, "guard_context": [], "capacity_evidence": [], "deterministic_constraints": {}, "decision_basis": {}, "decompiled_snippets": {"sink_function": "memcpy(...)", "caller_bridge": "", "producer_function": "src"}}]}],
    }
    out = asyncio.run(run_review_plan(plan, model="mock-model"))
    assert out["review_trace"]["status"] == "ok"
    assert len(out["review_decisions"]) == 1
    assert out["review_decisions"][0]["chain_id"] == "c1"


def test_run_stage_8_10_runs_internal_review(monkeypatch):
    from sourceagent.interface.main import _run_stage_8_10

    async def _fake_run_review_plan(review_plan, *, model=None, review_mode="semantic", timeout_sec=120):
        chain_id = review_plan["items"][0]["chain_id"]
        return {
            "review_decisions": [{
                "chain_id": chain_id,
                "suggested_semantic_verdict": "CONFIRMED",
                "trigger_summary": "payload_len remains attacker-controlled",
                "preconditions": {"state_predicates": ["rx_ready != 0"], "root_constraints": ["payload_len > dst_capacity"], "why_check_fails": ["guard missing"]},
                "evidence_map": {"trigger_summary": ["sink_function"], "root_controllability": ["sink_function"]},
                "audit_flags": ["CHECK_NOT_BINDING_ROOT"],
                "review_mode": "semantic_review",
            }],
            "review_trace": {"schema_version": "0.1", "status": "ok", "batches": [{"batch_id": "b0", "ok": True}]},
        }

    monkeypatch.setattr("sourceagent.agents.review_runner.run_review_plan", _fake_run_review_plan)

    result = _sample_result()
    args = SimpleNamespace(
        disable_review=False,
        review_mode="semantic",
        review_model="mock-model",
        review_timeout_sec=10,
        max_review_items=4,
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
        model=None,
    )

    asyncio.run(_run_stage_8_10(result, max_stage=10, args=args))
    artifacts = result._phase_a_artifacts
    assert artifacts["verdict_review_plan"]["status"] == "ok"
    assert artifacts["verdict_review_trace"]["status"] == "ok"
    assert artifacts["verdict_calibration_decisions"]["items"]
    assert any(row.get("llm_reviewed") for row in artifacts["verdict_soft_triage"]["items"])
