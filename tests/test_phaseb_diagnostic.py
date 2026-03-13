import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from sourceagent.pipeline.phaseb_diagnostic import run_phaseb_diagnostic
from sourceagent.pipeline.phaseb_diagnostic_inputs import (
    load_anchor_diagnostic_bundle,
    load_file_diagnostic_bundle,
    load_runtime_diagnostic_bundle,
)
from sourceagent.pipeline.microbench_gt_v2_eval import _load_gt_samples
from sourceagent.pipeline.verdict_calibration import build_verdict_calibration_artifacts


def _sample_chain(verdict="SUSPICIOUS"):
    return {
        "chain_id": "chain_fw_0001_root000",
        "verdict": verdict,
        "score": 0.89,
        "sink": {
            "label": "COPY_SINK",
            "function": "copy_fn",
            "site": "0x08001000",
            "root_expr": "payload_len",
        },
        "steps": [
            {"kind": "SOURCE", "label": "MMIO_READ", "function": "uart_receive"},
        ],
        "checks": [
            {
                "expr": "payload_len <= max_len",
                "strength": "unknown",
                "site": "copy_fn",
                "binding_target": "active_root",
                "capacity_scope": "write_bound",
                "strength_source": "sink_code",
            }
        ],
        "derive_facts": [{"expr": "payload_len = hdr->len", "site": "parse_packet"}],
        "root_bundle": {
            "active_root": {
                "expr": "payload_len",
                "canonical_expr": "hdr->len",
                "kind": "length",
                "role": "primary",
                "source": "miner_facts",
            }
        },
        "link_debug": {
            "object_hits": ["obj_rx"],
            "producer_candidates": ["uart_receive"],
            "bridge_functions": ["parse_packet"],
            "active_root_expr": "payload_len",
        },
        "decision_basis": {
            "source_reached": True,
            "root_controllable": True,
            "check_strength": "unknown",
            "chain_complete": True,
            "has_contradiction": False,
            "has_app_anchor": True,
            "control_path_only": False,
            "chain_score": 0.89,
            "source_resolve_mode": "same_context_direct_call",
            "secondary_root_only": False,
            "channel_required_hint": False,
            "has_channel": False,
            "confirm_threshold": 0.8,
            "reason_code": "CHECK_UNCERTAIN",
        },
    }


def _runtime_artifacts():
    return build_verdict_calibration_artifacts(
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
                    "writers": ["uart_receive"],
                    "readers": ["copy_fn"],
                    "type_facts": {"kind_hint": "payload"},
                }
            ]
        },
        sink_facts_by_pack={
            "p1": {
                "len_expr": "payload_len",
                "dst_expr": "dst",
                "guard_expr": "payload_len <= max_len",
            }
        },
        sink_pack_id_by_site={"0x08001000|copy_fn|COPY_SINK": "p1"},
        decompiled_cache={
            "copy_fn": "void copy_fn(char *dst, int payload_len) { memcpy(dst, src, payload_len); }",
            "parse_packet": "void parse_packet(void) { copy_fn(dst, hdr->len); }",
            "uart_receive": "int uart_receive(void) { return USART1_DR; }",
        },
        calibration_mode="all_non_exact",
        verdict_output_mode="dual",
    )


def _write_runtime_eval_dir(tmp_path: Path, stem: str = "fw") -> Path:
    eval_dir = tmp_path / "eval"
    raw_views = eval_dir / "raw_views"
    raw_views.mkdir(parents=True)
    artifacts = _runtime_artifacts()
    (raw_views / f"{stem}.verdict_feature_pack.json").write_text(
        json.dumps(artifacts["verdict_feature_pack"], indent=2) + "\n",
        encoding="utf-8",
    )
    (raw_views / f"{stem}.verdict_calibration_queue.json").write_text(
        json.dumps(artifacts["verdict_calibration_queue"], indent=2) + "\n",
        encoding="utf-8",
    )
    (raw_views / f"{stem}.verdict_soft_triage.json").write_text(
        json.dumps(artifacts["verdict_soft_triage"], indent=2) + "\n",
        encoding="utf-8",
    )
    return eval_dir


class _FakeLLM:
    def __init__(self, model=None):
        self.model = model

    async def generate(self, system_prompt, messages, tools=None, metadata=None, stream=False):
        contract = json.loads(messages[0]["content"])
        decisions = []
        for item in contract["batch"]["items"]:
            available = set(item.get("available_snippet_keys", []) or [])
            key = "sink_function" if "sink_function" in available else next(iter(available), "")
            evidence_map = {"trigger_summary": [key]} if key else {"trigger_summary": ["sink_function"]}
            decisions.append(
                {
                    "chain_id": item["chain_id"],
                    "suggested_semantic_verdict": "CONFIRMED",
                    "trigger_summary": "active length remains attacker-controlled and can exceed destination capacity",
                    "preconditions": {
                        "state_predicates": ["input reachable"],
                        "root_constraints": ["payload_len > dst_capacity"],
                        "why_check_fails": ["check does not bind the active root"],
                        "environment_assumptions": ["malformed input delivered"],
                    },
                    "segment_assessment": [
                        {
                            "segment_id": "sink_triggerability",
                            "status": "triggerable",
                            "reason_codes": [
                                "TRIGGERABLE_LEN_GT_CAPACITY",
                                "CHECK_NOT_BINDING_ROOT",
                            ],
                            "summary": "the active length can exceed destination capacity",
                            "evidence_map": {"summary": [key] if key else ["sink_function"]},
                        }
                    ],
                    "reason_codes": [
                        "TRIGGERABLE_LEN_GT_CAPACITY",
                        "CHECK_NOT_BINDING_ROOT",
                        "PARSER_DESCRIPTOR_WALK_UNBOUNDED",
                        "TAINT_PRESERVED_COPY_FROM_IO",
                    ],
                    "review_quality_flags": [],
                    "evidence_map": evidence_map,
                    "audit_flags": ["CHECK_NOT_BINDING_ROOT"],
                    "confidence": 0.95,
                    "review_mode": contract.get("review_mode", "semantic"),
                }
            )
        return SimpleNamespace(
            content=json.dumps({"decisions": decisions}),
            usage={"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
            model=self.model,
            finish_reason="stop",
        )


def test_load_runtime_diagnostic_bundle_selects_requested_chain(tmp_path):
    eval_dir = _write_runtime_eval_dir(tmp_path)
    bundle = load_runtime_diagnostic_bundle(
        eval_dir=eval_dir,
        sample="fw",
        chain_ids=["chain_fw_0001_root000"],
    )
    assert bundle["diagnostic_source"] == "runtime"
    assert len(bundle["items"]) == 1
    item = bundle["items"][0]
    assert item["meta"]["diagnostic_mode"] == "runtime_feature_item"
    assert item["feature_item"]["chain_id"] == "chain_fw_0001_root000"


def test_load_anchor_diagnostic_bundle_builds_synthetic_anchor():
    bundle = load_anchor_diagnostic_bundle(
        sample="cve_2021_34259_usb_host",
        gt_root=Path("firmware/ground_truth_bundle/gt_backed_suite"),
        eval_dir=None,
        chain_ids=["C1_cfg_total_length_overwalk"],
        include_related=False,
        include_supporting=False,
    )
    assert bundle["diagnostic_source"] == "anchor"
    assert len(bundle["items"]) == 1
    item = bundle["items"][0]
    assert item["meta"]["diagnostic_mode"] == "anchor_synthetic"
    assert item["meta"]["expected_final_risk_band"] == "HIGH"
    assert item["meta"]["expected_review_priority"] == "P0"
    assert item["feature_item"]["sink"]["function"] == "USBH_ParseCfgDesc"
    assert item["feature_item"]["chain_id"].startswith("gt::")


def test_load_anchor_diagnostic_bundle_builds_safe_anchor_without_queue_item():
    bundle = load_anchor_diagnostic_bundle(
        sample="zephyr_cve_2021_3329",
        gt_root=Path("firmware/ground_truth_bundle/gt_backed_suite"),
        eval_dir=None,
        include_related=False,
        include_supporting=False,
    )
    assert bundle["diagnostic_source"] == "anchor"
    assert len(bundle["items"]) == 1
    item = bundle["items"][0]
    assert item["meta"]["diagnostic_mode"] == "anchor_synthetic"
    assert item["meta"]["diagnostic_role"] == "canonical_main"
    assert item["feature_item"]["current_verdict"] == "SAFE_OR_LOW_RISK"
    assert item["queue_item"]["chain_id"] == item["feature_item"]["chain_id"]


def test_gt_backed_cve_anchor_inventory_includes_3329_and_3330():
    samples = {
        str(row.get("sample_id", "") or row.get("binary_stem", "") or ""): dict(row)
        for row in _load_gt_samples(Path("firmware/ground_truth_bundle/gt_backed_suite"))
    }
    for sample_id in ("zephyr_cve_2021_3329", "zephyr_cve_2021_3330"):
        evaluation_only = dict((samples.get(sample_id, {}) or {}).get("evaluation_only", {}) or {})
        assert evaluation_only.get("canonical_cve_chain_ids")
        assert evaluation_only.get("canonical_cve_anchor_status") == "provisional"


def test_load_file_diagnostic_bundle_accepts_direct_feature_items(tmp_path):
    feature_item = _runtime_artifacts()["verdict_feature_pack"]["items"][0]
    path = tmp_path / "diagnostic.json"
    path.write_text(
        json.dumps(
            {
                "sample_id": "external_demo",
                "items": [
                    {
                        "feature_item": feature_item,
                        "meta": {
                            "expected_final_verdict": "CONFIRMED",
                            "expected_final_risk_band": "HIGH",
                            "expected_review_priority": "P0",
                        },
                    }
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    bundle = load_file_diagnostic_bundle(path)
    assert bundle["diagnostic_source"] == "file"
    assert len(bundle["items"]) == 1
    assert bundle["items"][0]["meta"]["expected_final_risk_band"] == "HIGH"


def test_run_phaseb_diagnostic_runtime_writes_summary(tmp_path, monkeypatch):
    monkeypatch.setattr("sourceagent.agents.review_runner.LLM", _FakeLLM)
    eval_dir = _write_runtime_eval_dir(tmp_path)
    output_dir = tmp_path / "diag_runtime"
    result = asyncio.run(
        run_phaseb_diagnostic(
            diagnostic_source="runtime",
            eval_dir=str(eval_dir),
            sample="fw",
            chain_ids=["chain_fw_0001_root000"],
            review_model="mock-model",
            output_dir=str(output_dir),
        )
    )
    row = result["summary"]["rows"][0]
    assert row["diagnostic_final_verdict"] == "CONFIRMED"
    assert row["diagnostic_final_risk_band"] in {"MEDIUM", "HIGH"}
    assert row["diagnostic_review_priority"] in {"P0", "P1"}
    assert (output_dir / "phaseb_diagnostic_summary.json").exists()
    assert (output_dir / "phaseb_diagnostic_summary.md").exists()


def test_run_phaseb_diagnostic_anchor_can_reach_expected_high_p0(tmp_path, monkeypatch):
    monkeypatch.setattr("sourceagent.agents.review_runner.LLM", _FakeLLM)
    output_dir = tmp_path / "diag_anchor"
    result = asyncio.run(
        run_phaseb_diagnostic(
            diagnostic_source="anchor",
            sample="cve_2021_34259_usb_host",
            gt_root="firmware/ground_truth_bundle/gt_backed_suite",
            chain_ids=["C1_cfg_total_length_overwalk"],
            include_related=False,
            include_supporting=False,
            review_model="mock-model",
            output_dir=str(output_dir),
        )
    )
    row = result["summary"]["rows"][0]
    assert row["diagnostic_role"] == "canonical_main"
    assert row["diagnostic_final_verdict"] == "CONFIRMED"
    assert row["diagnostic_final_risk_band"] == "HIGH"
    assert row["diagnostic_review_priority"] == "P0"
    assert row["agreement_status"] == "exact"
    assert (output_dir / "phaseb_diagnostic_decisions.json").exists()


def test_run_phaseb_diagnostic_file_input(tmp_path, monkeypatch):
    monkeypatch.setattr("sourceagent.agents.review_runner.LLM", _FakeLLM)
    feature_item = _runtime_artifacts()["verdict_feature_pack"]["items"][0]
    path = tmp_path / "diagnostic.json"
    path.write_text(
        json.dumps(
            {
                "sample_id": "external_demo",
                "items": [
                    {
                        "feature_item": feature_item,
                        "meta": {
                            "expected_final_verdict": "CONFIRMED",
                            "expected_final_risk_band": "HIGH",
                            "expected_review_priority": "P0",
                        },
                    }
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    result = asyncio.run(
        run_phaseb_diagnostic(
            diagnostic_source="file",
            diagnostic_json=str(path),
            review_model="mock-model",
        )
    )
    assert result["summary"]["rows"][0]["diagnostic_source"] == "file"
    assert result["summary"]["rows"][0]["diagnostic_final_verdict"] == "CONFIRMED"
