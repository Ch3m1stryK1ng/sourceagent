import json
from pathlib import Path

from sourceagent.pipeline.microbench_gt_v2 import SCHEMA_VERSION
from sourceagent.pipeline.microbench_gt_v2_eval import (
    evaluate_microbench_v2_run,
    evaluate_sample_artifacts,
)


def _sample_base(stem: str = "demo") -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "binary_stem": stem,
        "binary_paths": {
            "source_file": f"firmware/microbench/{stem}.c",
            "map_file": f"firmware/microbench/{stem}.map",
            "elf_file": f"firmware/microbench/{stem}.elf",
            "bin_file": f"firmware/microbench/{stem}.bin",
        },
        "sample_meta": {
            "title": "demo",
            "mechanism_group": "isr_cross_context",
            "runtime_style": "baremetal_interrupt",
            "inspiration": "toy",
            "arch": "ARM_CORTEX_M",
            "expected_channel_mode": "required",
            "chain_shape": "source_object_channel_copy",
        },
        "annotation_status": {
            "sources": "complete",
            "objects": "complete",
            "channels": "complete",
            "sinks": "complete",
            "sink_roots": "complete",
            "derive_checks": "complete",
            "chains": "complete",
            "negative_expectations": "complete",
            "overall": "complete",
        },
        "todo_items": [],
        "sources": [
            {
                "source_id": "R1",
                "label": "ISR_MMIO_READ",
                "function_name": "USART1_IRQHandler",
                "address": 0x40011000,
                "address_hex": "0x40011000",
                "site_kind": "mmio_read_in_isr",
                "context": "ISR",
                "role": "data",
                "status": "complete",
            },
            {
                "source_id": "R2",
                "label": "MMIO_READ",
                "function_name": "uart_enable_rx",
                "address": 0x4001100C,
                "address_hex": "0x4001100c",
                "site_kind": "mmio_read",
                "context": "MAIN",
                "role": "config",
                "status": "complete",
            },
        ],
        "objects": [
            {
                "object_id": "O1_buf",
                "region_kind": "SRAM_CLUSTER",
                "addr_range": ["0x20000000", "0x2000007f"],
                "members": ["g_rx_buf"],
                "producer_contexts": ["ISR"],
                "consumer_contexts": ["MAIN"],
                "writer_sites": [],
                "reader_sites": [],
                "evidence_refs": [],
                "confidence": 1.0,
            }
        ],
        "channels": [
            {
                "channel_id": "C1",
                "src_context": "ISR",
                "object_id": "O1_buf",
                "dst_context": "MAIN",
                "edge_kind": "DATA",
                "constraints": [{"expr": "count < max_len", "strength": "effective"}],
                "evidence_refs": [],
                "score": 1.0,
            }
        ],
        "sinks": [
            {
                "sink_id": "S1",
                "label": "COPY_SINK",
                "pipeline_label_hint": "COPY_SINK",
                "function_name": "process_packet",
                "address": 0x08000108,
                "address_hex": "0x08000108",
                "site_kind": "copy_call_or_copy_idiom",
                "status": "complete",
            }
        ],
        "sink_roots": [
            {
                "root_id": "SR1",
                "sink_id": "S1",
                "root_role": "len",
                "expr": "count",
                "status": "complete",
            }
        ],
        "derive_checks": [
            {
                "derive_check_id": "D1",
                "sink_id": "S1",
                "root_id": "SR1",
                "derive_facts": [{"expr": "count++", "site": "process_packet"}],
                "check_facts": [{"expr": "count < max_len", "strength": "effective", "site": "process_packet"}],
                "status": "complete",
            }
        ],
        "chains": [
            {
                "chain_id": "CH1",
                "sink_id": "S1",
                "expected_verdict": "SAFE_OR_LOW_RISK",
                "required_source_ids": ["R1"],
                "required_object_ids": ["O1_buf"],
                "required_channel_ids": ["C1"],
                "required_root_ids": ["SR1"],
                "required_derive_check_ids": ["D1"],
                "must_use_channel": True,
            }
        ],
        "negative_expectations": [
            {
                "negative_id": "N1",
                "target_kind": "source",
                "target_id": "R2",
                "expected_verdict": "DROP",
                "reason": "config register must not anchor a vulnerability chain",
            }
        ],
        "notes": [],
    }


def _predicted_base(include_spurious=False) -> dict:
    return {
        "present": True,
        "pred_sources": [
            {
                "label": "ISR_MMIO_READ",
                "address": 0x40011000,
                "function_name": "USART1_IRQHandler",
            },
            {
                "label": "MMIO_READ",
                "address": 0x4001100C,
                "function_name": "uart_enable_rx",
            },
        ],
        "pred_sinks": [
            {
                "label": "COPY_SINK",
                "address": 0x08000108,
                "function_name": "process_packet",
            }
        ],
        "pred_objects": [
            {
                "object_id": "obj_rx_buf",
                "region_kind": "SRAM_CLUSTER",
                "addr_range": ["0x20000000", "0x2000007f"],
                "members": ["g_rx_buf"],
                "producer_contexts": ["ISR"],
                "consumer_contexts": ["MAIN"],
                "writer_sites": [],
                "reader_sites": [],
                "writers": ["USART1_IRQHandler"],
                "readers": ["process_packet"],
                "type_facts": {},
                "notes": "",
                "evidence_refs": [],
                "confidence": 1.0,
            }
        ],
        "pred_channels": [
            {
                "src_context": "ISR",
                "object_id": "obj_rx_buf",
                "dst_context": "MAIN",
                "edge_kind": "DATA",
                "constraints": [{"expr": "count < max_len", "strength": "effective"}],
                "evidence_refs": [],
                "score": 1.0,
            }
        ],
        "pred_roots": [
            {
                "sink_id": "P1",
                "sink_label": "COPY_SINK",
                "sink_function": "process_packet",
                "sink_site": "0x08000108",
                "root_expr": "count",
                "root_role": "primary",
                "root_kind": "length",
                "root_source": "call_args",
            }
        ],
        "pred_chains": [
            {
                "chain_id": "pred_good",
                "sink": {
                    "sink_id": "P1",
                    "label": "COPY_SINK",
                    "function": "process_packet",
                    "site": "0x08000108",
                    "root_expr": "count",
                },
                "steps": [
                    {
                        "kind": "SOURCE",
                        "label": "ISR_MMIO_READ",
                        "site": "0x40011000",
                        "function": "USART1_IRQHandler",
                        "evidence_refs": [],
                    },
                    {
                        "kind": "CHANNEL",
                        "edge": "ISR->MAIN",
                        "object_id": "obj_rx_buf",
                        "evidence_refs": [],
                    },
                    {
                        "kind": "DERIVE",
                        "expr": "count",
                        "site": "process_packet",
                        "evidence_refs": [],
                    },
                    {
                        "kind": "SINK",
                        "label": "COPY_SINK",
                        "site": "0x08000108",
                        "function": "process_packet",
                        "evidence_refs": [],
                    },
                ],
                "checks": [{"expr": "count < max_len", "strength": "effective", "site": "process_packet"}],
                "derive_facts": [{"expr": "count++", "site": "process_packet"}],
                "verdict": "SAFE_OR_LOW_RISK",
                "score": 0.7,
                "status": "ok",
                "evidence_refs": [],
                "has_app_anchor": True,
                "root_source": "call_args",
                "link_debug": {"object_hits": ["obj_rx_buf"]},
            }
        ],
    }


def test_evaluate_sample_artifacts_matches_required_channel_chain():
    gt = _sample_base()
    pred = _predicted_base()
    report = evaluate_sample_artifacts(gt, pred)

    assert report["artifacts"]["sources"]["matched_gt"] == 2
    assert report["artifacts"]["objects"]["matched_gt"] == 1
    assert report["artifacts"]["channels"]["matched_gt"] == 1
    assert report["artifacts"]["sink_roots"]["matched_gt"] == 1
    assert report["chains"]["matched"] == 1
    assert report["chains"]["verdict_exact"] == 1
    assert report["chains"]["must_use_channel_ok"] == 1
    assert report["negative_expectations"]["violated"] == 0


def test_evaluate_sample_artifacts_flags_spurious_chain_and_negative_violation():
    gt = _sample_base()
    pred = _predicted_base(include_spurious=True)
    pred["pred_chains"].append(
        {
            "chain_id": "pred_bad_cfg",
            "sink": {
                "sink_id": "P1",
                "label": "COPY_SINK",
                "function": "process_packet",
                "site": "0x08000108",
                "root_expr": "dst",
            },
            "steps": [
                {
                    "kind": "SOURCE",
                    "label": "MMIO_READ",
                    "site": "0x4001100c",
                    "function": "uart_enable_rx",
                    "evidence_refs": [],
                },
                {
                    "kind": "DERIVE",
                    "expr": "dst",
                    "site": "process_packet",
                    "evidence_refs": [],
                },
                {
                    "kind": "SINK",
                    "label": "COPY_SINK",
                    "site": "0x08000108",
                    "function": "process_packet",
                    "evidence_refs": [],
                },
            ],
            "checks": [{"expr": "bounds_guard", "strength": "absent", "site": "process_packet"}],
            "derive_facts": [{"expr": "dst", "site": "process_packet"}],
            "verdict": "SUSPICIOUS",
            "score": 0.5,
            "status": "ok",
            "evidence_refs": [],
            "has_app_anchor": True,
            "root_source": "call_args",
            "link_debug": {"object_hits": []},
        }
    )
    report = evaluate_sample_artifacts(gt, pred)

    assert report["chains"]["matched"] == 1
    assert report["chains"]["spurious_non_drop"] == 1
    assert report["negative_expectations"]["violated"] == 1
    assert report["negative_expectations"]["details"][0]["violated_by"] == ["pred_bad_cfg"]


def test_targeted_only_scope_does_not_count_unmodeled_non_drop_chains_as_spurious():
    gt = _sample_base()
    gt["chain_gt_scope"] = "targeted_only"
    pred = _predicted_base()
    pred["pred_chains"].append(
        {
            "chain_id": "pred_extra",
            "sink": {
                "sink_id": "P2",
                "label": "COPY_SINK",
                "function": "helper_copy",
                "site": "0x08000120",
                "root_expr": "n",
            },
            "steps": [
                {
                    "kind": "CHANNEL",
                    "edge": "ISR->MAIN",
                    "object_id": "obj_rx_buf",
                    "evidence_refs": [],
                },
                {
                    "kind": "SINK",
                    "label": "COPY_SINK",
                    "site": "0x08000120",
                    "function": "helper_copy",
                    "evidence_refs": [],
                },
            ],
            "checks": [],
            "derive_facts": [],
            "verdict": "SUSPICIOUS",
            "score": 0.5,
            "status": "ok",
            "evidence_refs": [],
            "has_app_anchor": True,
            "root_source": "call_args",
            "link_debug": {"object_hits": ["obj_rx_buf"]},
        }
    )
    report = evaluate_sample_artifacts(gt, pred)
    assert report["chain_gt_scope"] == "targeted_only"
    assert report["chains"]["matched"] == 1
    assert report["chains"]["spurious_non_drop"] == 0


def test_negative_only_scope_counts_all_non_drop_chains_as_spurious():
    gt = _sample_base()
    gt["chain_gt_scope"] = "negative_only"
    gt["chains"] = []
    gt["negative_expectations"] = [
        {
            "negative_id": "N_sample",
            "target_kind": "sample",
            "target_id": "",
            "expected_verdict": "DROP",
            "reason": "no_vuln_chain_expected",
        }
    ]
    pred = _predicted_base()
    report = evaluate_sample_artifacts(gt, pred)
    assert report["chain_gt_scope"] == "negative_only"
    assert report["chains"]["positive_total"] == 0
    assert report["chains"]["pred_non_drop"] == 1
    assert report["chains"]["spurious_non_drop"] == 1
    assert report["negative_expectations"]["violated"] == 1


def test_evaluate_sample_artifacts_does_not_confuse_same_function_mmio_addresses():
    gt = _sample_base()
    pred = _predicted_base()
    pred["pred_chains"][0]["steps"][0]["label"] = "MMIO_READ"
    pred["pred_chains"][0]["steps"][0]["site"] = "0x40011000"
    pred["pred_chains"][0]["steps"][0]["function"] = "uart_enable_rx"
    report = evaluate_sample_artifacts(gt, pred)

    assert report["negative_expectations"]["violated"] == 0

    pred["pred_chains"][0]["steps"][0]["site"] = "0x40011000"
    pred["pred_chains"][0]["steps"][0]["function"] = "USART1_IRQHandler"
    # Wrong label/function for the positive chain should not satisfy the GT source.
    report = evaluate_sample_artifacts(gt, pred)
    assert report["chains"]["matched"] == 0


def test_evaluate_sample_artifacts_does_not_match_family_only_wrong_sink():
    gt = _sample_base()
    gt["sinks"][0]["label"] = "LOOP_WRITE_SINK"
    gt["sinks"][0]["pipeline_label_hint"] = "LOOP_WRITE_SINK"
    gt["sinks"][0]["function_name"] = "fill_buffer"
    gt["sinks"][0]["address"] = 0x08000060
    gt["sinks"][0]["address_hex"] = "0x08000060"
    gt["chains"][0]["sink_id"] = "S1"
    gt["chains"][0]["expected_verdict"] = "SAFE_OR_LOW_RISK"

    pred = _predicted_base()
    pred["pred_sinks"][0]["label"] = "MEMSET_SINK"
    pred["pred_sinks"][0]["function_name"] = "clear_buffer"
    pred["pred_sinks"][0]["address"] = 0x0800007A
    pred["pred_roots"][0]["sink_label"] = "MEMSET_SINK"
    pred["pred_roots"][0]["sink_function"] = "clear_buffer"
    pred["pred_roots"][0]["sink_site"] = "0x0800007a"
    pred["pred_chains"][0]["sink"]["label"] = "MEMSET_SINK"
    pred["pred_chains"][0]["sink"]["function"] = "clear_buffer"
    pred["pred_chains"][0]["sink"]["site"] = "0x0800007a"

    report = evaluate_sample_artifacts(gt, pred)
    assert report["chains"]["matched"] == 0


def test_negative_sink_does_not_match_unrelated_same_family_chain():
    gt = _sample_base()
    gt["negative_expectations"] = [
        {
            "negative_id": "N_sink",
            "target_kind": "sink",
            "target_id": "S1",
            "expected_verdict": "DROP",
            "reason": "unrelated sink in the same family should not violate this negative",
        }
    ]
    pred = _predicted_base()
    pred["pred_chains"][0]["sink"]["label"] = "MEMSET_SINK"
    pred["pred_chains"][0]["sink"]["function"] = "clear_buffer"
    pred["pred_chains"][0]["sink"]["site"] = "0x0800007a"

    report = evaluate_sample_artifacts(gt, pred)
    assert report["negative_expectations"]["violated"] == 0


def test_evaluate_microbench_v2_run_writes_reports(tmp_path: Path):
    gt_root = tmp_path / "gt"
    sample_dir = gt_root / "samples"
    sample_dir.mkdir(parents=True)
    sample = _sample_base("demo")
    (sample_dir / "demo.json").write_text(json.dumps(sample, indent=2) + "\n")
    (gt_root / "index.json").write_text(
        json.dumps({"schema_version": SCHEMA_VERSION, "sample_count": 1, "samples": [{"binary_stem": "demo"}]}, indent=2) + "\n"
    )

    eval_dir = tmp_path / "eval"
    (eval_dir / "raw_results").mkdir(parents=True)
    (eval_dir / "raw_views").mkdir(parents=True)
    pipeline = {
        "verified_labels": [
            {
                "pack_id": "p1",
                "proposal": {"label": "ISR_MMIO_READ", "address": 0x40011000, "function_name": "USART1_IRQHandler"},
                "verdict": "VERIFIED",
                "final_label": "ISR_MMIO_READ",
            },
            {
                "pack_id": "p2",
                "proposal": {"label": "MMIO_READ", "address": 0x4001100C, "function_name": "uart_enable_rx"},
                "verdict": "VERIFIED",
                "final_label": "MMIO_READ",
            },
            {
                "pack_id": "p3",
                "proposal": {"label": "COPY_SINK", "address": 0x08000108, "function_name": "process_packet"},
                "verdict": "VERIFIED",
                "final_label": "COPY_SINK",
            },
        ]
    }
    (eval_dir / "raw_results" / "demo.pipeline.json").write_text(json.dumps(pipeline, indent=2) + "\n")
    (eval_dir / "raw_views" / "demo.channel_graph.json").write_text(
        json.dumps(
            {
                "object_nodes": _predicted_base()["pred_objects"],
                "channel_edges": _predicted_base()["pred_channels"],
            },
            indent=2,
        )
        + "\n"
    )
    (eval_dir / "raw_views" / "demo.sink_roots.json").write_text(
        json.dumps(
            {
                "sink_roots": [
                    {
                        "sink_id": "P1",
                        "sink_label": "COPY_SINK",
                        "sink_function": "process_packet",
                        "sink_site": "0x08000108",
                        "roots": [
                            {
                                "role": "primary",
                                "expr": "count",
                                "kind": "length",
                                "source": "call_args",
                            }
                        ],
                    }
                ]
            },
            indent=2,
        )
        + "\n"
    )
    (eval_dir / "raw_views" / "demo.chains.json").write_text(
        json.dumps({"chains": _predicted_base()["pred_chains"]}, indent=2) + "\n"
    )
    (eval_dir / "raw_views" / "demo.chain_eval.json").write_text(
        json.dumps({"stats": {"chain_count": 1}}, indent=2) + "\n"
    )

    report = evaluate_microbench_v2_run(eval_dir, gt_root=gt_root)
    assert report["summary"]["sample_count"] == 1
    assert report["summary"]["chains"]["matched"] == 1
    assert (eval_dir / "summary" / "artifact_eval_summary.json").exists()
    assert (eval_dir / "summary" / "artifact_eval_by_sample.json").exists()
    assert (eval_dir / "summary" / "artifact_eval_report.md").exists()


def test_evaluate_sample_artifacts_matches_multi_root_chain_via_root_bundle():
    gt = _sample_base("bundle_demo")
    gt["sink_roots"] = [
        {"root_id": "SR1", "sink_id": "S1", "root_role": "len", "expr": "count", "status": "complete"},
        {"root_id": "SR2", "sink_id": "S1", "root_role": "src_object", "expr": "g_rx_buf", "status": "complete"},
    ]
    gt["chains"] = [
        {
            "chain_id": "CH1",
            "sink_id": "S1",
            "expected_verdict": "SAFE_OR_LOW_RISK",
            "required_source_ids": ["R1"],
            "required_object_ids": ["O1_buf"],
            "required_channel_ids": ["C1"],
            "required_root_ids": ["SR1", "SR2"],
            "required_derive_check_ids": ["D1"],
            "must_use_channel": True,
        }
    ]

    pred = _predicted_base()
    pred["pred_roots"] = [
        {
            "sink_id": "P1",
            "sink_label": "COPY_SINK",
            "sink_function": "process_packet",
            "sink_site": "0x08000108",
            "root_expr": "count",
            "root_role": "primary",
            "root_kind": "length",
            "root_source": "call_args",
            "canonical_expr": "count",
            "aliases": ["count"],
            "root_family": "length",
        }
    ]
    pred["pred_chains"][0]["root_bundle"] = [
        {
            "expr": "count",
            "canonical_expr": "count",
            "aliases": ["count"],
            "family": "length",
            "kind": "length",
        },
        {
            "expr": "g_rx_buf",
            "canonical_expr": "g_rx_buf",
            "aliases": ["g_rx_buf"],
            "family": "pointer",
            "kind": "src_ptr",
        },
    ]

    report = evaluate_sample_artifacts(gt, pred)
    assert report["chains"]["matched"] == 1
    assert report["chains"]["details"][0]["root_ok"] is True


def test_evaluate_microbench_v2_run_uses_eval_stem_for_duplicate_binary_stems(tmp_path: Path):
    gt_root = tmp_path / "gt"
    sample_dir = gt_root / "samples"
    sample_dir.mkdir(parents=True)

    sample_a = _sample_base("shared")
    sample_a["sample_id"] = "sample_a"
    sample_a["eval_stem"] = "sample_a"
    sample_a["negative_expectations"] = []

    sample_b = _sample_base("shared")
    sample_b["sample_id"] = "sample_b"
    sample_b["eval_stem"] = "sample_b"
    sample_b["negative_expectations"] = []
    sample_b["sources"][0]["function_name"] = "IRQ_B"
    sample_b["sources"][0]["address"] = 0x40012000
    sample_b["sources"][0]["address_hex"] = "0x40012000"
    sample_b["chains"][0]["required_source_ids"] = ["R1"]

    (sample_dir / "sample_a.json").write_text(json.dumps(sample_a, indent=2) + "\n")
    (sample_dir / "sample_b.json").write_text(json.dumps(sample_b, indent=2) + "\n")
    (gt_root / "index.json").write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "sample_count": 2,
                "samples": [
                    {"binary_stem": "shared", "sample_id": "sample_a", "eval_stem": "sample_a"},
                    {"binary_stem": "shared", "sample_id": "sample_b", "eval_stem": "sample_b"},
                ],
            },
            indent=2,
        )
        + "\n"
    )

    eval_dir = tmp_path / "eval"
    (eval_dir / "raw_results").mkdir(parents=True)
    (eval_dir / "raw_views").mkdir(parents=True)

    def _write_case(stem: str, fn_name: str, mmio_addr: int):
        pipeline = {
            "verified_labels": [
                {
                    "pack_id": "p1",
                    "proposal": {"label": "ISR_MMIO_READ", "address": mmio_addr, "function_name": fn_name},
                    "verdict": "VERIFIED",
                    "final_label": "ISR_MMIO_READ",
                },
                {
                    "pack_id": "p3",
                    "proposal": {"label": "COPY_SINK", "address": 0x08000108, "function_name": "process_packet"},
                    "verdict": "VERIFIED",
                    "final_label": "COPY_SINK",
                },
            ]
        }
        (eval_dir / "raw_results" / f"{stem}.pipeline.json").write_text(json.dumps(pipeline, indent=2) + "\n")
        (eval_dir / "raw_views" / f"{stem}.channel_graph.json").write_text(
            json.dumps({"object_nodes": _predicted_base()["pred_objects"], "channel_edges": _predicted_base()["pred_channels"]}, indent=2) + "\n"
        )
        (eval_dir / "raw_views" / f"{stem}.sink_roots.json").write_text(
            json.dumps(
                {
                    "sink_roots": [
                        {
                            "sink_id": "P1",
                            "sink_label": "COPY_SINK",
                            "sink_function": "process_packet",
                            "sink_site": "0x08000108",
                            "roots": [{"role": "primary", "expr": "count", "kind": "length", "source": "call_args"}],
                        }
                    ]
                },
                indent=2,
            )
            + "\n"
        )
        chain = _predicted_base()["pred_chains"][0]
        chain = json.loads(json.dumps(chain))
        chain["steps"][0]["function"] = fn_name
        chain["steps"][0]["site"] = hex(mmio_addr)
        (eval_dir / "raw_views" / f"{stem}.chains.json").write_text(json.dumps({"chains": [chain]}, indent=2) + "\n")
        (eval_dir / "raw_views" / f"{stem}.chain_eval.json").write_text(json.dumps({"stats": {"chain_count": 1}}, indent=2) + "\n")

    _write_case("sample_a", "USART1_IRQHandler", 0x40011000)
    _write_case("sample_b", "IRQ_B", 0x40012000)

    report = evaluate_microbench_v2_run(eval_dir, gt_root=gt_root)
    assert report["summary"]["sample_count"] == 2
    assert report["summary"]["missing_samples"] == 0
    assert report["summary"]["chains"]["matched"] == 2
