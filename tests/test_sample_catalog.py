import csv
import json
from pathlib import Path


REPO_ROOT = Path("/home/a347908610/sourceagent")


def _load_catalog() -> dict:
    return json.loads((REPO_ROOT / "firmware/eval_suite/sample_catalog.json").read_text())


def _rows_by_relpath(payload: dict) -> dict[str, dict]:
    return {row["relative_binary_path"]: row for row in payload["samples"]}


def test_sample_catalog_summary_matches_current_repo_assets():
    payload = _load_catalog()

    assert payload["count"] == 568
    assert payload["existing_count"] == 568
    assert payload["by_dataset"] == {
        "demo": 10,
        "microbench": 42,
        "microbench-autogen": 324,
        "monolithic-firmware-collection": 94,
        "p2im-unit_tests": 47,
        "uSBS": 51,
    }
    assert payload["by_symbol_state"] == {
        "raw_bin": 162,
        "stripped": 155,
        "unstripped": 251,
    }
    assert payload["by_execution_model"] == {
        "bare_metal": 523,
        "rtos": 45,
    }
    assert payload["has_gt_count"] == 464
    assert payload["has_sink_only_gt_count"] == 444
    assert payload["negative_or_patched_count"] == 24
    assert payload["has_stripped_peer_count"] == 310


def test_sample_catalog_classifies_representative_assets():
    payload = _load_catalog()
    rows = _rows_by_relpath(payload)

    autogen_bin = rows["firmware/microbench_autogen/copy_variant_00.bin"]
    assert autogen_bin["dataset"] == "microbench-autogen"
    assert autogen_bin["binary_format"] == "bin"
    assert autogen_bin["symbol_state"] == "raw_bin"
    assert autogen_bin["arch_family"] == "arm-cortex-m"
    assert autogen_bin["framework_family"] == "sourceagent-microbench-autogen"
    assert autogen_bin["execution_model"] == "bare_metal"
    assert autogen_bin["has_gt"] is True
    assert autogen_bin["gt_level"] == "L1"
    assert autogen_bin["has_sink_only_gt"] is True

    contiki_stripped = rows[
        "firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/contiki-ng/prebuilt_samples/CVE-2020-12140/hello-world_stripped.elf"
    ]
    assert contiki_stripped["symbol_state"] == "stripped"
    assert contiki_stripped["framework_family"] == "contiki-ng"
    assert contiki_stripped["execution_model"] == "rtos"
    assert contiki_stripped["has_gt"] is True
    assert contiki_stripped["has_sink_only_gt"] is True
    assert contiki_stripped["unstripped_peer_path"].endswith("hello-world.elf")

    patched = rows[
        "firmware/uSBS/Ground-truth Benchmark/fw/udp_echo_server_bof_expl_patched/STM32469I_EVAL_stm32_udp_echo_server_stripped.elf"
    ]
    assert patched["dataset"] == "uSBS"
    assert patched["symbol_state"] == "stripped"
    assert patched["framework_family"] == "stm32cubef4"
    assert patched["execution_model"] == "bare_metal"
    assert patched["negative_or_patched"] is True
    assert patched["has_gt"] is False
    assert patched["unstripped_peer_path"].endswith("STM32469I_EVAL_stm32_udp_echo_server.elf")

    no_gt = rows["firmware/monolithic-firmware-collection/ARMCortex-M/blink_led_2/blink.ino.elf"]
    assert no_gt["sample_id"] == "monolithic_firmware_collection_armcortex_m_blink_led_2_blink_ino"
    assert no_gt["dataset"] == "monolithic-firmware-collection"
    assert no_gt["has_gt"] is False
    assert no_gt["framework_family"] == "arduino"
    assert no_gt["execution_model"] == "bare_metal"


def test_sample_catalog_covers_demo_and_gt_backed_microbench_variants():
    payload = _load_catalog()
    rows = _rows_by_relpath(payload)

    demo_bin = rows["firmware/demo/nxp_uart_polling.bin"]
    assert demo_bin["dataset"] == "demo"
    assert demo_bin["symbol_state"] == "raw_bin"
    assert demo_bin["arch_family"] == "arm-cortex-m"
    assert demo_bin["execution_model"] == "bare_metal"

    microbench_elf = rows["firmware/microbench/cve_2018_16525_freertos_dns.elf"]
    assert microbench_elf["dataset"] == "microbench"
    assert microbench_elf["symbol_state"] == "unstripped"
    assert microbench_elf["has_gt"] is True
    assert microbench_elf["gt_level"] == "L1;L2"
    assert microbench_elf["has_sink_only_gt"] is True
    assert microbench_elf["has_stripped_peer"] is True
    assert microbench_elf["stripped_peer_path"].endswith("cve_2018_16525_freertos_dns_stripped.elf")


def test_sample_catalog_csv_matches_json_row_count():
    payload = _load_catalog()
    csv_path = REPO_ROOT / "firmware/eval_suite/sample_catalog.csv"

    with csv_path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    assert len(rows) == payload["count"]
