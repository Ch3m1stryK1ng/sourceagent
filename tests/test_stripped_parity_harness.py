import json
from pathlib import Path

from sourceagent.pipeline.stripped_parity_harness import evaluate_stripped_parity_run


def _write_eval_case(
    eval_dir: Path,
    stem: str,
    *,
    source_function: str,
    sink_function: str,
    sink_verdict: str = "CONFIRMED",
) -> None:
    (eval_dir / "raw_results").mkdir(parents=True, exist_ok=True)
    (eval_dir / "raw_views").mkdir(parents=True, exist_ok=True)

    pipeline = {
        "verified_labels": [
            {
                "pack_id": f"{stem}-src",
                "proposal": {
                    "label": "ISR_MMIO_READ",
                    "address": 0x40011000,
                    "function_name": source_function,
                },
                "verdict": "VERIFIED",
                "final_label": "ISR_MMIO_READ",
            },
            {
                "pack_id": f"{stem}-sink",
                "proposal": {
                    "label": "COPY_SINK",
                    "address": 0x08000108,
                    "function_name": sink_function,
                },
                "verdict": "VERIFIED",
                "final_label": "COPY_SINK",
            },
        ]
    }
    (eval_dir / "raw_results" / f"{stem}.pipeline.json").write_text(
        json.dumps(pipeline, indent=2) + "\n",
        encoding="utf-8",
    )
    (eval_dir / "raw_views" / f"{stem}.channel_graph.json").write_text(
        json.dumps(
            {
                "object_nodes": [
                    {
                        "object_id": "obj_rx",
                        "region_kind": "SRAM_CLUSTER",
                        "addr_range": ["0x20000000", "0x2000003f"],
                        "members": ["g_rx_buf"],
                        "producer_contexts": ["ISR"],
                        "consumer_contexts": ["MAIN"],
                    }
                ],
                "channel_edges": [
                    {
                        "object_id": "obj_rx",
                        "src_context": "ISR",
                        "dst_context": "MAIN",
                        "edge_kind": "DATA",
                        "constraints": [{"expr": "count < max_len", "strength": "effective"}],
                    }
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (eval_dir / "raw_views" / f"{stem}.sink_roots.json").write_text(
        json.dumps(
            {
                "sink_roots": [
                    {
                        "sink_id": f"{stem}-sink",
                        "sink_label": "COPY_SINK",
                        "sink_function": sink_function,
                        "sink_site": "0x08000108",
                        "roots": [
                            {
                                "role": "primary",
                                "expr": "count",
                                "kind": "length",
                                "source": "miner_facts",
                                "canonical_expr": "count",
                                "aliases": ["count"],
                                "family": "length",
                            }
                        ],
                    }
                ]
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (eval_dir / "raw_views" / f"{stem}.chains.json").write_text(
        json.dumps(
            {
                "chains": [
                    {
                        "chain_id": f"{stem}-chain",
                        "sink": {
                            "sink_id": f"{stem}-sink",
                            "label": "COPY_SINK",
                            "function": sink_function,
                            "site": "0x08000108",
                            "root_expr": "count",
                        },
                        "steps": [
                            {
                                "kind": "SOURCE",
                                "label": "ISR_MMIO_READ",
                                "site": "0x40011000",
                                "function": source_function,
                            },
                            {
                                "kind": "CHANNEL",
                                "edge": "ISR->MAIN",
                                "object_id": "obj_rx",
                            },
                            {
                                "kind": "SINK",
                                "label": "COPY_SINK",
                                "site": "0x08000108",
                                "function": sink_function,
                            },
                        ],
                        "checks": [{"expr": "count < max_len", "strength": "effective"}],
                        "derive_facts": [{"expr": "count", "site": sink_function}],
                        "verdict": sink_verdict,
                        "root_bundle": [
                            {
                                "expr": "count",
                                "canonical_expr": "count",
                                "aliases": ["count"],
                                "family": "length",
                                "kind": "length",
                            }
                        ],
                    }
                ]
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (eval_dir / "raw_views" / f"{stem}.chain_eval.json").write_text(
        json.dumps({"stats": {"chain_count": 1}}, indent=2) + "\n",
        encoding="utf-8",
    )


def test_evaluate_stripped_parity_run_matches_stripped_peer(tmp_path: Path):
    manifest_path = tmp_path / "stripped_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "samples": [
                    {
                        "dataset": "microbench",
                        "sample_id": "demo",
                        "gt_stem": "demo",
                        "output_stem": "demo_stripped",
                        "binary_path": str(tmp_path / "demo_stripped.elf"),
                        "unstripped_binary_path": str(tmp_path / "demo.elf"),
                    }
                ]
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    stripped_eval = tmp_path / "eval_stripped"
    unstripped_eval = tmp_path / "eval_unstripped"
    _write_eval_case(unstripped_eval, "demo", source_function="USART1_IRQHandler", sink_function="process_packet")
    _write_eval_case(stripped_eval, "demo_stripped", source_function="FUN_08001000", sink_function="FUN_08000108")

    report = evaluate_stripped_parity_run(
        stripped_eval,
        unstripped_eval_dir=unstripped_eval,
        manifest_path=manifest_path,
    )

    summary = report["summary"]
    assert summary["sample_count"] == 1
    assert summary["complete_pairs"] == 1
    assert summary["parity"]["sinks"]["matched_gt"] == 1
    assert summary["parity"]["sink_roots"]["matched_gt"] == 1
    assert summary["parity"]["positive_chains"]["matched_gt"] == 1
    assert summary["parity"]["positive_chains"]["verdict_exact"] == 1
    assert (stripped_eval / "summary" / "stripped_parity" / "stripped_parity_summary.json").exists()
    assert (stripped_eval / "summary" / "stripped_parity" / "stripped_parity_report.md").exists()


def test_evaluate_stripped_parity_run_flags_underpromoted_chain(tmp_path: Path):
    manifest_path = tmp_path / "stripped_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "samples": [
                    {
                        "dataset": "microbench",
                        "sample_id": "demo2",
                        "gt_stem": "demo2",
                        "output_stem": "demo2_stripped",
                        "binary_path": str(tmp_path / "demo2_stripped.elf"),
                        "unstripped_binary_path": str(tmp_path / "demo2.elf"),
                    }
                ]
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    stripped_eval = tmp_path / "eval_stripped"
    unstripped_eval = tmp_path / "eval_unstripped"
    _write_eval_case(unstripped_eval, "demo2", source_function="handler", sink_function="process_packet", sink_verdict="CONFIRMED")
    _write_eval_case(stripped_eval, "demo2_stripped", source_function="handler", sink_function="FUN_08000108", sink_verdict="SUSPICIOUS")

    report = evaluate_stripped_parity_run(
        stripped_eval,
        unstripped_eval_dir=unstripped_eval,
        manifest_path=manifest_path,
        output_dir=tmp_path / "parity_out",
    )

    summary = report["summary"]
    assert summary["parity"]["positive_chains"]["matched_gt"] == 1
    assert summary["parity"]["positive_chains"]["verdict_under"] == 1
    assert summary["counts"]["delta"]["positive_chains"] == 0
    assert (tmp_path / "parity_out" / "stripped_parity_by_sample.json").exists()
