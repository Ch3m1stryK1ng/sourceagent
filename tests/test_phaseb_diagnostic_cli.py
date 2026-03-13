import asyncio
import sys
from types import SimpleNamespace

from sourceagent.interface import main as cli


def test_main_parses_diagnose_command(monkeypatch, tmp_path):
    captured = {}

    async def fake_dispatch(args):
        captured["args"] = args

    monkeypatch.setattr(cli, "_dispatch", fake_dispatch)
    monkeypatch.setattr(cli, "_quiet_asyncio_run", lambda coro: asyncio.run(coro))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sourceagent",
            "diagnose",
            "--diagnostic-source",
            "file",
            "--diagnostic-json",
            str(tmp_path / "diagnostic.json"),
            "--review-model",
            "mock-model",
            "--chain-id",
            "chain_a",
            "--chain-id",
            "chain_b",
        ],
    )

    cli.main()

    args = captured["args"]
    assert args.command == "diagnose"
    assert args.diagnostic_source == "file"
    assert args.review_model == "mock-model"
    assert args.chain_id == ["chain_a", "chain_b"]


def test_dispatch_routes_diagnose(monkeypatch):
    captured = {}

    async def fake_cmd(args):
        captured["args"] = args

    monkeypatch.setattr(cli, "_cmd_diagnose", fake_cmd)
    args = SimpleNamespace(command="diagnose")

    asyncio.run(cli._dispatch(args))

    assert captured["args"] is args


def test_cmd_diagnose_invokes_runner_and_prints_summary(monkeypatch, tmp_path, capsys):
    captured = {}

    async def fake_run_phaseb_diagnostic(**kwargs):
        captured.update(kwargs)
        return {
            "summary": {
                "diagnostic_source": kwargs["diagnostic_source"],
                "sample_id": kwargs.get("sample") or "",
                "counts": {"chain_count": 2, "agreement_exact": 1},
                "diagnostic_final_verdict": {"CONFIRMED": 1, "SUSPICIOUS": 1},
                "diagnostic_final_risk_band": {"HIGH": 1, "MEDIUM": 1},
                "diagnostic_review_priority": {"P0": 1, "P1": 1},
            }
        }

    monkeypatch.setattr(
        "sourceagent.pipeline.phaseb_diagnostic.run_phaseb_diagnostic",
        fake_run_phaseb_diagnostic,
    )

    args = SimpleNamespace(
        diagnostic_source="anchor",
        eval_dir=str(tmp_path / "eval"),
        sample="cve_2021_34259_usb_host",
        chain_id=["C1_cfg_total_length_overwalk"],
        diagnostic_json=None,
        gt_root="firmware/ground_truth_bundle/gt_backed_suite",
        include_related=False,
        include_supporting=False,
        include_peripheral_suspicious=False,
        review_model="mock-model",
        review_mode="semantic",
        review_tool_mode="prompt_only",
        review_batch_size=2,
        max_items=3,
        review_timeout_sec=45,
        output_dir=str(tmp_path / "diag_out"),
        allow_manual_llm_supervision=True,
        llm_promote_budget=4,
        llm_demote_budget=2,
        llm_soft_budget=5,
        review_strict_gates="source_reached,object_bound",
        review_soft_gates="source_reached",
        review_allow_soft_on_structural_gap=True,
        review_preserve_rejected_rationale=True,
        min_risk_score=0.55,
    )

    asyncio.run(cli._cmd_diagnose(args))

    assert captured["diagnostic_source"] == "anchor"
    assert captured["sample"] == "cve_2021_34259_usb_host"
    assert captured["chain_ids"] == ["C1_cfg_total_length_overwalk"]
    assert captured["include_related"] is False
    assert captured["review_model"] == "mock-model"
    assert captured["batch_size"] == 2
    assert captured["max_items"] == 3
    assert captured["review_strict_gates"] == ("source_reached", "object_bound")
    assert captured["review_soft_gates"] == ("source_reached",)
    assert captured["output_dir"] == str((tmp_path / "diag_out").resolve())

    out = capsys.readouterr().out
    assert "Phase B diagnostic complete" in out
    assert "Chains reviewed:   2" in out
    assert str((tmp_path / "diag_out").resolve()) in out


def test_cmd_diagnose_validates_required_args(capsys):
    args = SimpleNamespace(
        diagnostic_source="runtime",
        eval_dir=None,
        sample=None,
        chain_id=None,
        diagnostic_json=None,
        gt_root=None,
        include_related=True,
        include_supporting=True,
        include_peripheral_suspicious=False,
        review_model=None,
        review_mode="semantic",
        review_tool_mode="prompt_only",
        review_batch_size=1,
        max_items=0,
        review_timeout_sec=60,
        output_dir=None,
        allow_manual_llm_supervision=False,
        llm_promote_budget=0,
        llm_demote_budget=0,
        llm_soft_budget=0,
        review_strict_gates="",
        review_soft_gates="",
        review_allow_soft_on_structural_gap=True,
        review_preserve_rejected_rationale=True,
        min_risk_score=0.0,
    )

    asyncio.run(cli._cmd_diagnose(args))

    out = capsys.readouterr().out
    assert "--sample is required for runtime/anchor diagnostics" in out
