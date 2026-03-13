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




def test_parse_review_response_preserves_segment_assessment_v2():
    text = json_text = """{
  "decisions": [
    {
      "chain_id": "c3",
      "suggested_semantic_verdict": "SUSPICIOUS",
      "trigger_summary": "review summary",
      "preconditions": {
        "state_predicates": ["rx_ready != 0"],
        "root_constraints": ["len > cap"],
        "why_check_fails": ["wrong variable"],
        "environment_assumptions": ["network input reachable"]
      },
      "segment_assessment": [
        {
          "segment_id": "check_binding",
          "status": "mismatch",
          "reason_codes": ["CHECK_NOT_BINDING_ROOT"],
          "summary": "guard checks a different variable",
          "evidence_map": {
            "summary": ["sink_function"]
          }
        }
      ],
      "reason_codes": ["CHECK_NOT_BINDING_ROOT"],
      "review_quality_flags": ["needs_more_context"],
      "evidence_map": {
        "trigger_summary": ["sink_function"]
      }
    }
  ]
}"""
    decisions, meta = parse_review_response(text, default_review_mode="semantic_review", allowed_chain_ids=["c3"])
    assert meta["ok"] is True
    assert len(decisions) == 1
    row = decisions[0]
    assert row["segment_assessment"][0]["segment_id"] == "check_binding"
    assert row["segment_assessment"][0]["status"] == "mismatch"
    assert row["reason_codes"] == ["CHECK_NOT_BINDING_ROOT"]
    assert row["review_quality_flags"] == ["needs_more_context"]


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

        async def generate(self, system_prompt, messages, tools=None, metadata=None, stream=False):
            return SimpleNamespace(
                content='{"decisions": [{"chain_id": "c1", "suggested_semantic_verdict": "SUSPICIOUS", "trigger_summary": "len can exceed dst", "preconditions": {"state_predicates": ["rx_ready != 0"], "root_constraints": ["len > cap"], "why_check_fails": ["guard missing"]}, "evidence_map": {"trigger_summary": ["sink_function"], "root_controllability": ["producer_function"]}, "audit_flags": ["CHECK_NOT_BINDING_ROOT"], "review_mode": "semantic_review"}]}',
                usage={"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
                model=self.model,
                finish_reason="stop",
            )

    monkeypatch.setattr("sourceagent.agents.review_runner.LLM", _FakeLLM)
    plan = {
        "items": [{"chain_id": "c1"}],
        "batches": [{"batch_id": "b0", "chain_ids": ["c1"], "items": [{"chain_id": "c1", "current_verdict": "SUSPICIOUS", "sink": {}, "root": {}, "derive_facts": [], "check_facts": [], "object_path": [], "channel_path": [], "sink_semantics_hints": {}, "guard_context": [], "capacity_evidence": [], "deterministic_constraints": {}, "decision_basis": {}, "decompiled_snippets": {"sink_function": "memcpy(...)", "caller_bridge": "", "producer_function": "src"}}]}],
    }
    out = asyncio.run(run_review_plan(plan, model="mock-model"))
    assert out["review_trace"]["status"] == "ok"
    assert len(out["review_decisions"]) == 1
    assert out["review_decisions"][0]["chain_id"] == "c1"
    assert out["review_prompt"]["status"] == "ok"
    assert out["review_raw_response"]["status"] == "ok"
    assert out["review_session"]["status"] == "ok"
    assert out["review_raw_response"]["batches"][0]["finish_reason"] == "stop"
    assert out["review_prompt"]["batches"][0]["system_prompt"]


def test_run_stage_8_10_runs_internal_review(monkeypatch):
    from sourceagent.interface.main import _run_stage_8_10

    async def _fake_run_review_plan(review_plan, *, model=None, review_mode="semantic", review_tool_mode="prompt_only", timeout_sec=120, mcp_manager=None, ghidra_binary_name=None):
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
            "review_prompt": {"schema_version": "0.1", "status": "ok", "batches": [{"batch_id": "b0", "user_prompt": "prompt"}]},
            "review_raw_response": {"schema_version": "0.1", "status": "ok", "batches": [{"batch_id": "b0", "raw_text": "{}"}]},
            "review_session": {"schema_version": "0.1", "status": "ok", "batches": [{"batch_id": "b0", "decision_count": 1}]},
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
    assert artifacts["verdict_review_prompt"]["status"] == "ok"
    assert artifacts["verdict_review_raw_response"]["status"] == "ok"
    assert artifacts["verdict_review_session"]["status"] == "ok"
    assert artifacts["verdict_review_trace"]["status"] == "ok"
    assert artifacts["verdict_calibration_decisions"]["items"]
    assert any(row.get("llm_reviewed") for row in artifacts["verdict_soft_triage"]["items"])


def test_parse_review_response_normalizes_reason_codes_v2():
    text = """{
  "decisions": [
    {
      "chain_id": "c4",
      "suggested_semantic_verdict": "SUSPICIOUS",
      "trigger_summary": "review summary",
      "preconditions": {},
      "segment_assessment": [
        {
          "segment_id": "sink_triggerability",
          "status": "possible",
          "reason_codes": ["weak_check", "bogus_reason"],
          "summary": "summary",
          "evidence_map": {"summary": ["sink_function"]}
        }
      ],
      "reason_codes": ["check_not_bound_to_root", "unknown_reason"],
      "evidence_map": {"trigger_summary": ["sink_function"]}
    }
  ]
}"""
    decisions, meta = parse_review_response(text, default_review_mode="semantic_review", allowed_chain_ids=["c4"])
    assert meta["ok"] is True
    assert decisions[0]["reason_codes"] == ["CHECK_NOT_BINDING_ROOT"]
    assert decisions[0]["segment_assessment"][0]["reason_codes"] == ["WEAK_GUARDING"]


def test_build_review_plan_includes_available_snippet_keys():
    feature_pack = {
        "items": [
            {
                "chain_id": "c1",
                "risk_score": 0.8,
                "review_priority": "P0",
                "sink": {},
                "root": {},
                "derive_facts": [],
                "check_facts": [],
                "object_path": [],
                "channel_path": [],
                "sink_semantics_hints": {},
                "guard_context": [],
                "capacity_evidence": [],
                "chain_segments": [],
                "deterministic_constraints": {},
                "decision_basis": {},
                "decompiled_snippets": {"sink_function": "memcpy(...)", "check_context": "if (len < n)"},
                "snippet_index": {"sink_function": ["copy_fn"], "check_context": ["copy_fn"]},
            }
        ]
    }
    queue = {"items": [{"chain_id": "c1", "queue_score": 0.8, "queue_reasons": ["needs_review"]}]}
    plan = build_review_plan(feature_pack, queue, review_tool_mode="tool_assisted", max_items=1, batch_size=1)
    assert plan["review_tool_mode"] == "tool_assisted"
    assert set(plan["items"][0]["available_snippet_keys"]) == {"sink_function", "check_context"}
    assert plan["items"][0]["snippet_index"]["sink_function"] == ["copy_fn"]
    assert plan["items"][0]["review_priority"] == "P0"


def test_review_runner_tool_assisted_augments_snippets(monkeypatch):
    class _FakeLLM:
        def __init__(self, model=None):
            self.model = model

        async def generate(self, system_prompt, messages, tools=None, metadata=None, stream=False):
            prompt = messages[0]["content"]
            assert "check_context" in prompt
            return SimpleNamespace(
                content='{"decisions": [{"chain_id": "c1", "suggested_semantic_verdict": "SUSPICIOUS", "trigger_summary": "len can exceed dst", "preconditions": {"state_predicates": ["rx_ready != 0"], "root_constraints": ["len > cap"], "why_check_fails": ["guard weak"]}, "segment_assessment": [{"segment_id": "check_binding", "status": "weak", "reason_codes": ["CHECK_NOT_BINDING_ROOT"], "summary": "weak guard", "evidence_map": {"summary": ["check_context"]}}], "reason_codes": ["CHECK_NOT_BINDING_ROOT"], "evidence_map": {"trigger_summary": ["sink_function"], "root_controllability": ["check_context"]}, "audit_flags": ["CHECK_NOT_BINDING_ROOT"], "review_mode": "semantic_review"}]}',
                usage={"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
                model=self.model,
                finish_reason="stop",
            )

    class _FakeMCP:
        async def call_tool(self, server_name, tool_name, arguments):
            assert server_name == "ghidra"
            assert tool_name == "decompile_function"
            fn = arguments["name_or_address"]
            return [{"type": "text", "text": '{"decompiled_code": "void %s(void) { /* body */ }"}' % fn}]

    monkeypatch.setattr("sourceagent.agents.review_runner.LLM", _FakeLLM)
    plan = {
        "items": [{"chain_id": "c1"}],
        "batches": [{
            "batch_id": "b0",
            "chain_ids": ["c1"],
            "items": [{
                "chain_id": "c1",
                "current_verdict": "SUSPICIOUS",
                "sink": {"function": "copy_fn"},
                "root": {"family": "length", "expr": "payload_len"},
                "derive_facts": [{"site": "parse_packet"}],
                "check_facts": [{"site": "guard_fn"}],
                "object_path": [],
                "channel_path": [],
                "chain_segments": [{"segment_id": "check_binding", "src": {}, "dst": {}, "snippet_keys": ["check_context"]}],
                "sink_semantics_hints": {},
                "guard_context": [{"site": "guard_fn"}],
                "capacity_evidence": [],
                "deterministic_constraints": {},
                "decision_basis": {},
                "decompiled_snippets": {"sink_function": "void copy_fn(void) {}", "caller_bridge": "", "producer_function": "", "check_context": ""},
                "snippet_index": {"sink_function": ["copy_fn"], "caller_bridge": ["parse_packet"], "producer_function": ["uart_receive"]},
                "available_snippet_keys": ["sink_function"],
            }],
        }],
    }
    out = asyncio.run(
        run_review_plan(
            plan,
            model="mock-model",
            review_tool_mode="tool_assisted",
            mcp_manager=_FakeMCP(),
            ghidra_binary_name="fw.elf-deadbeef",
        )
    )
    assert out["review_trace"]["status"] == "ok"
    assert out["review_trace"]["tool_logs"][0]["decompiled_function_count"] >= 1
    assert out["review_prompt"]["batches"][0]["tool_context"]["summary"][0]["available_snippet_keys"]


def test_review_runner_prompt_only_can_auto_schedule_tool_assisted_second_pass(monkeypatch):
    call_prompts = []

    class _FakeLLM:
        def __init__(self, model=None):
            self.model = model

        async def generate(self, system_prompt, messages, tools=None, metadata=None, stream=False):
            prompt = messages[0]["content"]
            call_prompts.append(prompt)
            return SimpleNamespace(
                content='{"decisions": [{"chain_id": "c2", "suggested_semantic_verdict": "SUSPICIOUS", "trigger_summary": "producer evidence still indirect", "preconditions": {"root_constraints": ["len > cap"]}, "reason_codes": [], "review_quality_flags": [], "evidence_map": {"trigger_summary": ["sink_function"]}, "review_mode": "semantic_review"}]}',
                usage={"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
                model=self.model,
                finish_reason="stop",
            )

    class _FakeMCP:
        async def call_tool(self, server_name, tool_name, arguments):
            fn = arguments["name_or_address"]
            return [{"type": "text", "text": '{"decompiled_code": "void %s(void) { /* fetched */ }"}' % fn}]

    monkeypatch.setattr("sourceagent.agents.review_runner.LLM", _FakeLLM)
    plan = {
        "items": [{"chain_id": "c2"}],
        "batches": [{
            "batch_id": "b1",
            "chain_ids": ["c2"],
            "items": [{
                "chain_id": "c2",
                "current_verdict": "SUSPICIOUS",
                "review_priority": "P0",
                "soft_candidate": False,
                "sink": {"function": "copy_fn"},
                "root": {"family": "length", "expr": "payload_len"},
                "derive_facts": [{"site": "parse_packet"}],
                "check_facts": [{"site": "guard_fn"}],
                "object_path": [{
                    "object_id": "obj_rx",
                    "writers": ["uart_receive"],
                    "readers": ["copy_fn"],
                    "writer_sites": [{"context": "ISR", "fn": "uart_receive"}],
                    "reader_sites": [{"context": "MAIN", "fn": "copy_fn"}],
                    "producer_contexts": ["ISR"],
                    "consumer_contexts": ["MAIN"],
                    "type_facts": {"kind_hint": "payload"},
                }],
                "channel_path": [{"edge": "ISR->MAIN", "object_id": "obj_rx"}],
                "chain_segments": [{"segment_id": "source_to_object", "src": {}, "dst": {}, "snippet_keys": ["producer_function"]}],
                "sink_semantics_hints": {},
                "guard_context": [{"site": "guard_fn"}],
                "capacity_evidence": [{"site": "obj_rx", "expr": "128", "kind": "object_extent_bytes"}],
                "deterministic_constraints": {
                    "source_reached": False,
                    "source_proxy_ok": False,
                    "source_reached_or_proxy": False,
                    "object_bound": True,
                    "root_bound": True,
                    "channel_satisfied": True,
                },
                "decision_basis": {"source_resolve_mode": "object_source_proxy"},
                "decompiled_snippets": {"sink_function": "void copy_fn(void) {}", "producer_function": "", "source_context": "", "channel_context": ""},
                "snippet_index": {"sink_function": ["copy_fn"], "producer_function": ["uart_receive"], "source_context": ["uart_receive"], "channel_context": ["uart_receive", "parse_packet"]},
                "available_snippet_keys": ["sink_function"],
                "review_context_plan": {
                    "selected_functions": {
                        "sink_function": ["copy_fn"],
                        "producer_context": ["uart_receive"],
                        "caller_bridge": ["parse_packet"],
                    },
                    "estimated_prompt_chars": 8000,
                    "expanded": False,
                    "key_char_limits": {},
                },
            }],
        }],
    }
    out = asyncio.run(
        run_review_plan(
            plan,
            model="mock-model",
            review_tool_mode="prompt_only",
            mcp_manager=_FakeMCP(),
            ghidra_binary_name="fw.elf-deadbeef",
        )
    )
    assert len(call_prompts) == 2
    assert '"review_tool_mode": "prompt_only"' in call_prompts[0]
    assert '"review_tool_mode": "tool_assisted"' in call_prompts[1]
    assert any(batch.get("second_pass") for batch in out["review_prompt"]["batches"])
    assert any(log.get("decompiled_function_count", 0) >= 1 for log in out["review_trace"]["tool_logs"])


def test_review_runner_tool_assisted_accepts_plain_text_mcp_payload(monkeypatch):
    class _FakeLLM:
        def __init__(self, model=None):
            self.model = model

        async def generate(self, system_prompt, messages, tools=None, metadata=None, stream=False):
            return SimpleNamespace(
                content='{"decisions": [{"chain_id": "c3", "suggested_semantic_verdict": "SUSPICIOUS", "trigger_summary": "plain text snippets loaded", "preconditions": {}, "evidence_map": {"trigger_summary": ["sink_function"]}, "review_mode": "semantic_review"}]}',
                usage={"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
                model=self.model,
                finish_reason="stop",
            )

    class _FakeMCP:
        async def call_tool(self, server_name, tool_name, arguments):
            fn = arguments["name_or_address"]
            return [{"type": "text", "text": f"void {fn}(void) {{ /* plain */ }}"}]

    monkeypatch.setattr("sourceagent.agents.review_runner.LLM", _FakeLLM)
    plan = {
        "items": [{"chain_id": "c3"}],
        "batches": [{
            "batch_id": "b2",
            "chain_ids": ["c3"],
            "items": [{
                "chain_id": "c3",
                "current_verdict": "SUSPICIOUS",
                "review_priority": "P1",
                "sink": {"function": "copy_fn"},
                "root": {"family": "length", "expr": "n"},
                "derive_facts": [],
                "check_facts": [],
                "object_path": [],
                "channel_path": [],
                "chain_segments": [],
                "sink_semantics_hints": {},
                "guard_context": [],
                "capacity_evidence": [],
                "deterministic_constraints": {"source_reached": True, "source_reached_or_proxy": True, "object_bound": True, "root_bound": True},
                "decision_basis": {},
                "decompiled_snippets": {"sink_function": "", "caller_bridge": "", "producer_function": ""},
                "snippet_index": {"sink_function": ["copy_fn"]},
                "available_snippet_keys": [],
                "review_context_plan": {
                    "selected_functions": {"sink_function": ["copy_fn"]},
                    "estimated_prompt_chars": 4000,
                    "expanded": False,
                    "key_char_limits": {},
                },
            }],
        }],
    }
    out = asyncio.run(
        run_review_plan(
            plan,
            model="mock-model",
            review_tool_mode="tool_assisted",
            mcp_manager=_FakeMCP(),
            ghidra_binary_name="fw.elf-deadbeef",
        )
    )
    summary = out["review_prompt"]["batches"][0]["tool_context"]["summary"][0]
    assert "sink_function" in summary["available_snippet_keys"]
