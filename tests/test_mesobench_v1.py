import json
from pathlib import Path

from sourceagent.pipeline.mesobench import SCHEMA_VERSION, validate_mesobench_tree


def test_validate_mesobench_repo_tree():
    root = Path("/home/a347908610/sourceagent/firmware/ground_truth_bundle/mesobench")
    report = validate_mesobench_tree(root)
    assert report["ok"], report["errors"]
    assert report["sample_count"] == 30


def test_mesobench_index_and_manifest_counts():
    idx = json.loads(
        Path("/home/a347908610/sourceagent/firmware/ground_truth_bundle/mesobench/index.json").read_text()
    )
    manifest = json.loads(
        Path("/home/a347908610/sourceagent/firmware/eval_suite/mesobench_unstripped_elf_manifest.json").read_text()
    )
    assert idx["schema_version"] == SCHEMA_VERSION
    assert idx["sample_count"] == 30
    assert len(idx["samples"]) == 30
    assert len(manifest["samples"]) == 30
    assert any(s["sample_id"] == "contiki_cve_2020_12141_snmp_server" for s in idx["samples"])
    assert any(s["sample_id"] == "usbs_test_printf_fw" for s in idx["samples"])
    assert any(s["sample_id"] == "stm32cube_lwip_tcp_echo_server" for s in idx["samples"])
    assert any(s["sample_id"] == "usbs_udp_echo_server_bof_instrumented" for s in idx["samples"])
    assert any(s.get("output_stem") == s["sample_id"] for s in manifest["samples"])
    assert any(s.get("output_stem") == "usbs_test_printf_fw" for s in manifest["samples"])


def test_global_inventory_contains_mesobench_entries():
    inv = json.loads(
        Path("/home/a347908610/sourceagent/firmware/ground_truth_bundle/ground_truth_inventory.json").read_text()
    )
    meso = [e for e in inv if e.get("dataset") == "mesobench"]
    assert len(meso) == 30
    assert any(e["sample_id"] == "zephyr_cve_2020_10065" for e in meso)
    assert any(e["sample_id"] == "usbs_tcp_echo_client_vuln_off_by_one_dhcp" for e in meso)
    assert any(e["sample_id"] == "usbs_udp_echo_server_bof_instrumented_patched" for e in meso)
    assert any(e["sample_id"] == "stm32cube_lwip_udp_echo_server" for e in meso)
