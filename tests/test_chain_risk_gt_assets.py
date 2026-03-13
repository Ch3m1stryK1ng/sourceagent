import json
from pathlib import Path


def _load(path: str) -> dict:
    return json.loads(Path(path).read_text())


def _chains_by_id(doc: dict) -> dict:
    return {chain["chain_id"]: chain for chain in doc.get("chains", [])}


def _risk_triplet(chain: dict) -> tuple[str | None, str | None, str | None]:
    return (
        chain.get("expected_final_verdict"),
        chain.get("expected_final_risk_band"),
        chain.get("expected_review_priority"),
    )


def test_selected_microbench_samples_have_curated_chain_risk_gt():
    cve_2020 = _chains_by_id(
        _load("/home/a347908610/sourceagent/firmware/ground_truth_bundle/microbench/samples/cve_2020_10065_hci_spi.json")
    )
    assert _risk_triplet(cve_2020["C1_evt_overflow"]) == ("CONFIRMED", "HIGH", "P0")
    assert _risk_triplet(cve_2020["C2_acl_overflow"]) == ("CONFIRMED", "HIGH", "P0")

    cve_2021 = _chains_by_id(
        _load("/home/a347908610/sourceagent/firmware/ground_truth_bundle/microbench/samples/cve_2021_34259_usb_host.json")
    )
    assert _risk_triplet(cve_2021["C1_cfg_total_length_overwalk"]) == ("CONFIRMED", "HIGH", "P0")
    assert _risk_triplet(cve_2021["C2_endpoint_count_overflow"]) == ("CONFIRMED", "HIGH", "P0")
    assert "expected_final_verdict" not in cve_2021["C3_ep_packet_size_risky_state"]

    cve_2018 = _chains_by_id(
        _load("/home/a347908610/sourceagent/firmware/ground_truth_bundle/microbench/samples/cve_2018_16525_freertos_dns.json")
    )
    assert _risk_triplet(cve_2018["C2_dns_name_walk_oob"]) == ("CONFIRMED", "HIGH", "P0")
    assert _risk_triplet(cve_2018["C3_llmnr_copy_overflow"]) == ("CONFIRMED", "HIGH", "P0")
    assert "expected_final_verdict" not in cve_2018["C1_trusted_udp_length"]


def test_selected_mesobench_samples_have_first_pass_chain_risk_gt_or_explicit_negative_only_status():
    bof = _chains_by_id(
        _load("/home/a347908610/sourceagent/firmware/ground_truth_bundle/mesobench/samples/usbs_tcp_echo_client_vuln_bof.json")
    )
    assert _risk_triplet(
        bof["chain_STM32469I_EVAL_tcp_echo_base_SINK_STM32469I_EVAL_tcp_echo_base_0012_c43980c2"]
    ) == ("CONFIRMED", "HIGH", "P0")

    printf_fw = _load(
        "/home/a347908610/sourceagent/firmware/ground_truth_bundle/mesobench/samples/usbs_test_printf_fw.json"
    )
    assert printf_fw["chain_gt_scope"] == "negative_only"
    assert printf_fw["chains"] == []
    assert any("Chain-level risk GT is intentionally absent" in note for note in printf_fw["notes"])


def test_gt_backed_suite_mirrors_curated_chain_risk_gt_annotations():
    mirrored = [
        (
            "/home/a347908610/sourceagent/firmware/ground_truth_bundle/microbench/samples/cve_2020_10065_hci_spi.json",
            "/home/a347908610/sourceagent/firmware/ground_truth_bundle/gt_backed_suite/samples/cve_2020_10065_hci_spi.json",
            ["C1_evt_overflow", "C2_acl_overflow"],
        ),
        (
            "/home/a347908610/sourceagent/firmware/ground_truth_bundle/microbench/samples/cve_2021_34259_usb_host.json",
            "/home/a347908610/sourceagent/firmware/ground_truth_bundle/gt_backed_suite/samples/cve_2021_34259_usb_host.json",
            ["C1_cfg_total_length_overwalk", "C2_endpoint_count_overflow"],
        ),
        (
            "/home/a347908610/sourceagent/firmware/ground_truth_bundle/microbench/samples/cve_2018_16525_freertos_dns.json",
            "/home/a347908610/sourceagent/firmware/ground_truth_bundle/gt_backed_suite/samples/cve_2018_16525_freertos_dns.json",
            ["C2_dns_name_walk_oob", "C3_llmnr_copy_overflow"],
        ),
        (
            "/home/a347908610/sourceagent/firmware/ground_truth_bundle/mesobench/samples/usbs_tcp_echo_client_vuln_bof.json",
            "/home/a347908610/sourceagent/firmware/ground_truth_bundle/gt_backed_suite/samples/usbs_tcp_echo_client_vuln_bof.json",
            ["chain_STM32469I_EVAL_tcp_echo_base_SINK_STM32469I_EVAL_tcp_echo_base_0012_c43980c2"],
        ),
    ]
    for src_path, dst_path, chain_ids in mirrored:
        src = _chains_by_id(_load(src_path))
        dst = _chains_by_id(_load(dst_path))
        for chain_id in chain_ids:
            assert _risk_triplet(src[chain_id]) == _risk_triplet(dst[chain_id])
            assert src[chain_id].get("risk_gt_provenance") == dst[chain_id].get("risk_gt_provenance")

    src_printf = _load("/home/a347908610/sourceagent/firmware/ground_truth_bundle/mesobench/samples/usbs_test_printf_fw.json")
    dst_printf = _load("/home/a347908610/sourceagent/firmware/ground_truth_bundle/gt_backed_suite/samples/usbs_test_printf_fw.json")
    assert src_printf["notes"] == dst_printf["notes"]


def test_second_batch_real_cve_anchor_risk_gt_is_present_and_mirrored():
    anchors = [
        (
            "zephyr_cve_2020_10064",
            "chain_zephyr-CVE-2020-10064_SINK_zephyr-CVE-2020-10064_0045_e99db807",
        ),
        (
            "zephyr_cve_2021_3319",
            "chain_zephyr-CVE-2021-3319_SINK_zephyr-CVE-2021-3319_0041_4a55fb5a",
        ),
        (
            "zephyr_cve_2021_3320",
            "chain_zephyr-CVE-2021-3320_SINK_zephyr-CVE-2021-3320_0041_e5d67a78",
        ),
        (
            "zephyr_cve_2021_3321",
            "chain_zephyr-CVE-2021-3321_SINK_zephyr-CVE-2021-3321_0041_7f52a27e",
        ),
        (
            "zephyr_cve_2021_3322",
            "chain_zephyr-CVE-2021-3322_SINK_zephyr-CVE-2021-3322_0041_45184c9b",
        ),
        (
            "zephyr_cve_2021_3323",
            "chain_zephyr-CVE-2021-3323_SINK_zephyr-CVE-2021-3323_0041_10c3ac19",
        ),
        (
            "contiki_halucinator_cve_2019_9183_hello_world",
            "chain_hello-world_SINK_hello-world_0001_6141a72f",
        ),
        (
            "contiki_cve_2020_12141_snmp_server",
            "chain_snmp-server_SINK_snmp-server_0024_49588c64",
        ),
    ]
    for sample_id, chain_id in anchors:
        meso = _chains_by_id(
            _load(f"/home/a347908610/sourceagent/firmware/ground_truth_bundle/mesobench/samples/{sample_id}.json")
        )
        suite = _chains_by_id(
            _load(f"/home/a347908610/sourceagent/firmware/ground_truth_bundle/gt_backed_suite/samples/{sample_id}.json")
        )
        assert _risk_triplet(meso[chain_id]) == ("CONFIRMED", "HIGH", "P0")
        assert _risk_triplet(suite[chain_id]) == ("CONFIRMED", "HIGH", "P0")
        assert meso[chain_id]["risk_gt_provenance"] == "manual_anchor_chain_v2"
        assert suite[chain_id]["risk_gt_provenance"] == "manual_anchor_chain_v2"
        assert meso[chain_id]["risk_gt_notes"] == suite[chain_id]["risk_gt_notes"]


def test_third_batch_contiki_anchor_risk_gt_is_present_and_mirrored():
    chain_ids = [
        "chain_hello-world_SINK_hello-world_0000_b9bbad48",
        "chain_hello-world_SINK_hello-world_0001_daa00ed7",
        "chain_hello-world_SINK_hello-world_0007_06a0a259",
        "chain_hello-world_SINK_hello-world_0009_affe0a8d",
        "chain_hello-world_SINK_hello-world_0041_7e71eff9",
    ]
    meso = _chains_by_id(
        _load(
            "/home/a347908610/sourceagent/firmware/ground_truth_bundle/mesobench/samples/contiki_cve_2020_12140_hello_world.json"
        )
    )
    suite = _chains_by_id(
        _load(
            "/home/a347908610/sourceagent/firmware/ground_truth_bundle/gt_backed_suite/samples/contiki_cve_2020_12140_hello_world.json"
        )
    )
    for chain_id in chain_ids:
        assert _risk_triplet(meso[chain_id]) == ("CONFIRMED", "HIGH", "P0")
        assert _risk_triplet(suite[chain_id]) == ("CONFIRMED", "HIGH", "P0")
        assert meso[chain_id]["risk_gt_provenance"] == "manual_anchor_chain_v3"
        assert suite[chain_id]["risk_gt_provenance"] == "manual_anchor_chain_v3"
        assert meso[chain_id]["risk_gt_notes"] == suite[chain_id]["risk_gt_notes"]
