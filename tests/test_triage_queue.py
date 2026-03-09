"""Tests for linker.triage_queue."""

from sourceagent.pipeline.linker.triage_queue import build_low_conf_sinks, build_triage_queue


def test_build_low_conf_sinks_filters_by_reason_rules():
    chains = [
        {
            "chain_id": "c1",
            "sink": {"sink_id": "s1", "label": "COPY_SINK", "function": "f", "site": "0x1", "root_expr": "x"},
            "score": 0.2,
            "status": "partial",
            "verdict": "SUSPICIOUS",
            "failure_code": "ROOT_UNRESOLVED",
            "evidence_refs": [],
        },
        {
            "chain_id": "c2",
            "sink": {"sink_id": "s2", "label": "COPY_SINK", "function": "f", "site": "0x2", "root_expr": "x"},
            "score": 0.9,
            "status": "ok",
            "verdict": "CONFIRMED",
            "evidence_refs": [],
        },
    ]

    items = build_low_conf_sinks(chains, t_low=0.45)

    assert len(items) == 1
    assert items[0]["sink_id"] == "s1"
    assert "status_partial" in items[0]["reasons"]


def test_build_triage_queue_ranks_items():
    items = [
        {"sink_id": "s1", "reasons": ["verdict_suspicious", "status_partial"], "failure_code": "ROOT_FACT_MISSING"},
        {"sink_id": "s2", "reasons": ["score_below_t_low"], "failure_code": ""},
    ]

    q = build_triage_queue(items, top_k=2)

    assert len(q) == 2
    assert q[0]["sink_id"] == "s1"
    assert q[0]["triage_rank"] == 1
    assert q[1]["triage_rank"] == 2
