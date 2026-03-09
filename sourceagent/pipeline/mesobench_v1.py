from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List


SCHEMA_VERSION = "1.0-seed"
DEFAULT_REL_DIR = Path("firmware/ground_truth_bundle/mesobench_v1")
SAMPLE_REL_DIR = DEFAULT_REL_DIR / "samples"
REFERENCE_REL_DIR = Path("firmware/ground_truth_bundle/references/mesobench")
GLOBAL_INVENTORY_REL = Path("firmware/ground_truth_bundle/ground_truth_inventory.json")
GLOBAL_INVENTORY_CSV_REL = Path("firmware/ground_truth_bundle/ground_truth_inventory.csv")
EVAL_MANIFEST_REL = Path("firmware/eval_suite/mesobench_v1_unstripped_elf_manifest.json")


@dataclass(frozen=True)
class SourceRepo:
    repo_id: str
    display_name: str
    repo_url: str | None
    local_checkout: str | None
    source_code_level: str
    notes: str


@dataclass(frozen=True)
class SampleMeta:
    sample_id: str
    dataset: str
    subset: str
    binary_path: str
    bin_path: str | None
    title: str
    priority: str
    role: str
    type_family: str
    source_repo_id: str
    source_locator: List[str]
    source_code_level: str
    chain_depth: str
    chain_breadth: str
    expected_channel_mode: str
    likely_source_labels: List[str]
    likely_sink_labels: List[str]
    current_support_status: str
    notes: str
    todo_items: List[str]
    negative_expectations: List[dict]


SOURCE_REPOS: Dict[str, SourceRepo] = {
    "contiki-ng": SourceRepo(
        repo_id="contiki-ng",
        display_name="Contiki-NG official repository",
        repo_url="https://github.com/contiki-ng/contiki-ng",
        local_checkout="firmware/source_repos/contiki-ng",
        source_code_level="full_upstream_repo",
        notes="Primary source anchor for Contiki-NG prebuilt CVE samples from D_FUZZWARE.",
    ),
    "zephyr": SourceRepo(
        repo_id="zephyr",
        display_name="Zephyr official repository",
        repo_url="https://github.com/zephyrproject-rtos/zephyr",
        local_checkout="firmware/source_repos/zephyr",
        source_code_level="full_upstream_repo",
        notes="Primary source anchor for Zephyr prebuilt CVE samples from D_FUZZWARE.",
    ),
    "stm32cubef4": SourceRepo(
        repo_id="stm32cubef4",
        display_name="STM32CubeF4 official repository",
        repo_url="https://github.com/STMicroelectronics/STM32CubeF4",
        local_checkout="firmware/source_repos/STM32CubeF4",
        source_code_level="upstream_base_plus_overlay",
        notes="Base source anchor for STM32469I_EVAL networking examples used by uSBS; combine with uSBS injected snippets and trigger inputs.",
    ),
    "usbs_overlay": SourceRepo(
        repo_id="usbs_overlay",
        display_name="uSBS benchmark overlay",
        repo_url="https://github.com/ucsb-seclab/uSBS",
        local_checkout="firmware/uSBS",
        source_code_level="benchmark_overlay",
        notes="Provides injected vulnerability snippets, benchmark descriptions, and replay inputs; use together with STM32CubeF4 base sources.",
    ),
    "freertos-plus-tcp": SourceRepo(
        repo_id="freertos-plus-tcp",
        display_name="FreeRTOS-Plus-TCP official repository",
        repo_url="https://github.com/FreeRTOS/FreeRTOS-Plus-TCP",
        local_checkout="firmware/source_repos/FreeRTOS-Plus-TCP",
        source_code_level="full_upstream_repo",
        notes="Second-priority source target for future real FreeRTOS parser builds and GT expansion.",
    ),
    "stm32-mw-usb-host": SourceRepo(
        repo_id="stm32-mw-usb-host",
        display_name="STM32 USB Host middleware official repository",
        repo_url="https://github.com/STMicroelectronics/stm32-mw-usb-host",
        local_checkout="firmware/source_repos/stm32-mw-usb-host",
        source_code_level="full_upstream_repo",
        notes="Second-priority source target for future real USB descriptor parser builds and GT expansion.",
    ),
}


def _neg_no_vuln(note: str) -> dict:
    return {
        "kind": "no_vuln_chain_expected",
        "reason": note,
    }


MESOBENCH_SAMPLES: List[SampleMeta] = [
    SampleMeta(
        sample_id="contiki_cve_2020_12140_hello_world",
        dataset="monolithic-firmware-collection",
        subset="D_FUZZWARE/new-targets/contiki-ng/prebuilt_samples",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/contiki-ng/prebuilt_samples/CVE-2020-12140/hello-world.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/contiki-ng/prebuilt_samples/CVE-2020-12140/hello-world.bin",
        title="Contiki-NG CVE-2020-12140 prebuilt sample",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="contiki-ng",
        source_locator=["firmware/source_repos/contiki-ng", "resolve exact vulnerable path from CVE-2020-12140 issue history"],
        source_code_level="full_upstream_repo",
        chain_depth="medium",
        chain_breadth="medium",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ"],
        likely_sink_labels=["COPY_SINK", "LOOP_WRITE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Good mesobench seed: real stack behavior with moderate parsing depth and official Contiki sources.",
        todo_items=[
            "Locate the exact vulnerable source file/function in Contiki-NG history.",
            "Annotate payload object(s), parser state object(s), and downstream sink roots.",
            "Record whether source-to-sink path stays same-context or crosses ISR/network callback boundaries.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="contiki_cve_2020_12141_snmp_server",
        dataset="monolithic-firmware-collection",
        subset="D_FUZZWARE/new-targets/contiki-ng/prebuilt_samples",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/contiki-ng/prebuilt_samples/CVE-2020-12141/snmp-server.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/contiki-ng/prebuilt_samples/CVE-2020-12141/snmp-server.bin",
        title="Contiki-NG SNMP server CVE sample",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="contiki-ng",
        source_locator=["firmware/source_repos/contiki-ng", "inspect SNMP server application and parser paths"],
        source_code_level="full_upstream_repo",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK", "LOOP_WRITE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="This is one of the best candidates for chain-depth calibration because parser objects and derived bounds are richer than microbench.",
        todo_items=[
            "Identify main packet ingress buffer and any derived varbind/ASN.1 length fields.",
            "Annotate parser object graph and any loop-based write sites.",
            "Capture check strength for SNMP field lengths and walker bounds.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="contiki_halucinator_cve_2019_9183_hello_world",
        dataset="monolithic-firmware-collection",
        subset="D_FUZZWARE/new-targets/contiki-ng/prebuilt_samples",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/contiki-ng/prebuilt_samples/CVE-HALucinator-CVE-2019-9183/hello-world.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/contiki-ng/prebuilt_samples/CVE-HALucinator-CVE-2019-9183/hello-world.bin",
        title="Contiki-NG HALucinator CVE sample",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="contiki-ng",
        source_locator=["firmware/source_repos/contiki-ng", "map HALucinator sample label back to Contiki app path"],
        source_code_level="full_upstream_repo",
        chain_depth="medium",
        chain_breadth="medium",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Useful as a Contiki negative/alternative CVE family with different parser shape than SNMP.",
        todo_items=[
            "Resolve exact upstream application path and driver ingress point.",
            "Annotate any callback or process-thread bridge into sink.",
            "Mark control-only registers or status reads that must not become payload anchors.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="zephyr_cve_2020_10064",
        dataset="monolithic-firmware-collection",
        subset="D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2020-10064/zephyr-CVE-2020-10064.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2020-10064/zephyr-CVE-2020-10064.bin",
        title="Zephyr CVE-2020-10064 prebuilt sample",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="zephyr",
        source_locator=["firmware/source_repos/zephyr", "resolve vulnerable subsystem using CVE tag"],
        source_code_level="full_upstream_repo",
        chain_depth="medium",
        chain_breadth="medium",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Zephyr prebuilt CVE sample with realistic subsystem plumbing and official source availability.",
        todo_items=[
            "Locate the vulnerable subsystem/file for CVE-2020-10064.",
            "Annotate ingress object and downstream dangerous write or copy site.",
            "Record any thread or callback bridge relevant to chain construction.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="zephyr_cve_2020_10065",
        dataset="monolithic-firmware-collection",
        subset="D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2020-10065/zephyr-CVE-2020-10065.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2020-10065/zephyr-CVE-2020-10065.bin",
        title="Zephyr CVE-2020-10065 prebuilt sample",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="zephyr",
        source_locator=["firmware/source_repos/zephyr", "focus on HCI-over-SPI or related parser path"],
        source_code_level="full_upstream_repo",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK"],
        current_support_status="high_value_gt_target",
        notes="This is the strongest real-source follow-up to the existing microbench reproduction and should be prioritized for deep GT.",
        todo_items=[
            "Split EVT vs ACL roots and annotate independent chains.",
            "Annotate header objects and length derivations.",
            "Capture missing tailroom or bounds checks as check facts.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="zephyr_cve_2020_10066",
        dataset="monolithic-firmware-collection",
        subset="D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2020-10066/zephyr-CVE-2020-10066.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2020-10066/zephyr-CVE-2020-10066.bin",
        title="Zephyr CVE-2020-10066 prebuilt sample",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="zephyr",
        source_locator=["firmware/source_repos/zephyr", "resolve vulnerable subsystem using CVE tag"],
        source_code_level="full_upstream_repo",
        chain_depth="deep",
        chain_breadth="medium",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "LOOP_WRITE_SINK", "STORE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Complements 10064/10065 with a different Zephyr chain shape.",
        todo_items=[
            "Locate exact parser/driver path for CVE-2020-10066.",
            "Annotate if the chain requires callback or worker thread bridging.",
            "Capture any semantic subtype if coarse sink labels are insufficient.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="zephyr_cve_2021_3319",
        dataset="monolithic-firmware-collection",
        subset="D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2021-3319/zephyr-CVE-2021-3319.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2021-3319/zephyr-CVE-2021-3319.bin",
        title="Zephyr CVE-2021-3319 prebuilt sample",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="zephyr",
        source_locator=["firmware/source_repos/zephyr", "resolve CVE-specific subsystem"],
        source_code_level="full_upstream_repo",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK", "FORMAT_STRING_SINK", "FUNC_PTR_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="2021 Zephyr cluster gives better horizontal diversity than the 2020 trio and should surface more parser idioms.",
        todo_items=[
            "Resolve subsystem and ingress object for CVE-2021-3319.",
            "Identify whether sink is copy/store/control-flow family.",
            "Annotate positive and forbidden chain variants.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="zephyr_cve_2021_3320",
        dataset="monolithic-firmware-collection",
        subset="D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2021-3320/zephyr-CVE-2021-3320.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2021-3320/zephyr-CVE-2021-3320.bin",
        title="Zephyr CVE-2021-3320 prebuilt sample",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="zephyr",
        source_locator=["firmware/source_repos/zephyr", "resolve CVE-specific subsystem"],
        source_code_level="full_upstream_repo",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK", "LOOP_WRITE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Use this and adjacent 2021 Zephyr samples as a batch for broader chain coverage without leaving one codebase.",
        todo_items=[
            "Resolve subsystem and ingress path.",
            "Annotate the dominant chain family and negative alternatives.",
            "Track shared objects if worker thread or callback queues are involved.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="zephyr_cve_2021_3321",
        dataset="monolithic-firmware-collection",
        subset="D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2021-3321/zephyr-CVE-2021-3321.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2021-3321/zephyr-CVE-2021-3321.bin",
        title="Zephyr CVE-2021-3321 prebuilt sample",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="zephyr",
        source_locator=["firmware/source_repos/zephyr", "resolve CVE-specific subsystem"],
        source_code_level="full_upstream_repo",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK", "LOOP_WRITE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Another 2021 Zephyr parser/driver chain candidate; annotate only 1-3 representative paths first.",
        todo_items=[
            "Resolve subsystem and vulnerable call path.",
            "Annotate primary chain, not every possible sink.",
            "Record constraints that must hold before the sink executes.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="zephyr_cve_2021_3322",
        dataset="monolithic-firmware-collection",
        subset="D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2021-3322/zephyr-CVE-2021-3322.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2021-3322/zephyr-CVE-2021-3322.bin",
        title="Zephyr CVE-2021-3322 prebuilt sample",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="zephyr",
        source_locator=["firmware/source_repos/zephyr", "resolve CVE-specific subsystem"],
        source_code_level="full_upstream_repo",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK", "LOOP_WRITE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Use together with the adjacent 2021 Zephyr set to test family-generalization, not only one-off heuristics.",
        todo_items=[
            "Resolve exact vulnerable function and surrounding object graph.",
            "Capture root derivation and check strength.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="zephyr_cve_2021_3323",
        dataset="monolithic-firmware-collection",
        subset="D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2021-3323/zephyr-CVE-2021-3323.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2021-3323/zephyr-CVE-2021-3323.bin",
        title="Zephyr CVE-2021-3323 prebuilt sample",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="zephyr",
        source_locator=["firmware/source_repos/zephyr", "resolve CVE-specific subsystem"],
        source_code_level="full_upstream_repo",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK", "LOOP_WRITE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Expected to be useful for parser-object and derive/check calibration inside Zephyr.",
        todo_items=[
            "Annotate the first representative chain only.",
            "Document any false-positive nearby sources that should be pruned.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="zephyr_cve_2021_3329",
        dataset="monolithic-firmware-collection",
        subset="D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2021-3329/zephyr-CVE-2021-3329.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2021-3329/zephyr-CVE-2021-3329.bin",
        title="Zephyr CVE-2021-3329 prebuilt sample",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="zephyr",
        source_locator=["firmware/source_repos/zephyr", "resolve CVE-specific subsystem"],
        source_code_level="full_upstream_repo",
        chain_depth="deep",
        chain_breadth="medium",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK", "FUNC_PTR_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Broader horizontal coverage candidate; keep as a seed until exact source path is resolved.",
        todo_items=[
            "Resolve source path and dominant chain shape.",
            "Annotate whether indirect control-flow should be modeled as sink or auxiliary evidence.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="zephyr_cve_2021_3330",
        dataset="monolithic-firmware-collection",
        subset="D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2021-3330/zephyr-CVE-2021-3330.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2021-3330/zephyr-CVE-2021-3330.bin",
        title="Zephyr CVE-2021-3330 prebuilt sample",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="zephyr",
        source_locator=["firmware/source_repos/zephyr", "resolve CVE-specific subsystem"],
        source_code_level="full_upstream_repo",
        chain_depth="deep",
        chain_breadth="medium",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK", "FORMAT_STRING_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Another 2021 Zephyr seed with enough complexity to justify mesobench-level annotation later.",
        todo_items=[
            "Resolve source path and main sink family.",
            "Document any channel-like object transfer across callbacks or worker contexts.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="zephyr_false_positive_rf_size_check",
        dataset="monolithic-firmware-collection",
        subset="D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-no-CVE-false-positive-rf-size-check/zephyr-CVE-no-CVE-false-positive-rf-size-check.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-no-CVE-false-positive-rf-size-check/zephyr-CVE-no-CVE-false-positive-rf-size-check.bin",
        title="Zephyr false-positive control: RF size check",
        priority="high",
        role="negative_control",
        type_family="type_ii_or_iii_ready",
        source_repo_id="zephyr",
        source_locator=["firmware/source_repos/zephyr", "resolve RF size check path"],
        source_code_level="full_upstream_repo",
        chain_depth="medium",
        chain_breadth="medium",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK"],
        current_support_status="negative_control_gt_target",
        notes="This sample should help suppress over-generated chains and over-promoted verdicts.",
        todo_items=[
            "Annotate the candidate chain that looks risky but is actually protected by effective checks.",
            "Record negative expectations for no_vuln_chain or safe_or_low_risk verdict.",
        ],
        negative_expectations=[_neg_no_vuln("Directory label indicates an intentional no-CVE false-positive control sample.")],
    ),
    SampleMeta(
        sample_id="zephyr_false_positive_watchdog_callback",
        dataset="monolithic-firmware-collection",
        subset="D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-no-CVE-false-positive-watchdog-callback/zephyr-CVE-no-CVE-false-positive-watchdog-callback.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-no-CVE-false-positive-watchdog-callback/zephyr-CVE-no-CVE-false-positive-watchdog-callback.bin",
        title="Zephyr false-positive control: watchdog callback",
        priority="high",
        role="negative_control",
        type_family="type_ii_or_iii_ready",
        source_repo_id="zephyr",
        source_locator=["firmware/source_repos/zephyr", "resolve watchdog callback path"],
        source_code_level="full_upstream_repo",
        chain_depth="medium",
        chain_breadth="medium",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ"],
        likely_sink_labels=["FUNC_PTR_SINK", "STORE_SINK"],
        current_support_status="negative_control_gt_target",
        notes="A good control sample for pruning indirect-call or callback chains that are not true vulnerabilities.",
        todo_items=[
            "Annotate the callback/control-flow path and the effective guard that keeps it safe.",
            "Mark forbidden over-promotions to CONFIRMED or SUSPICIOUS vulnerability chains.",
        ],
        negative_expectations=[_neg_no_vuln("Directory label indicates an intentional no-CVE false-positive control sample.")],
    ),
    SampleMeta(
        sample_id="stm32cube_lwip_tcp_echo_client",
        dataset="monolithic-firmware-collection",
        subset="ARMCortex-M",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/stm32_tcp_echo_client/stm32_tcp_echo_client.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/stm32_tcp_echo_client/stm32_tcp_echo_client.bin",
        title="STM32CubeF4 LwIP TCP echo client",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="stm32cubef4",
        source_locator=[
            "firmware/source_repos/STM32CubeF4/Projects/STM32469I_EVAL/Applications/LwIP/LwIP_TCP_Echo_Client",
            "focus on tcp_echoclient.c, app_ethernet.c, ethernetif.c",
        ],
        source_code_level="full_upstream_repo",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="likely",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK", "LOOP_WRITE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Large STM32Cube networking example with raw-API callback chains and DMA-backed Ethernet buffers.",
        todo_items=[
            "Resolve RX DMA buffer object(s) and tcp recv callback handoff.",
            "Annotate one positive copy/write chain rooted in pbuf length or payload pointer.",
            "Record control-only network stack helpers that must not become payload anchors.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="stm32cube_lwip_tcp_echo_server",
        dataset="monolithic-firmware-collection",
        subset="ARMCortex-M",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/stm32_tcp_echo_server/stm32_tcp_echo_server.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/stm32_tcp_echo_server/stm32_tcp_echo_server.bin",
        title="STM32CubeF4 LwIP TCP echo server",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="stm32cubef4",
        source_locator=[
            "firmware/source_repos/STM32CubeF4/Projects/STM32469I_EVAL/Applications/LwIP/LwIP_TCP_Echo_Server",
            "focus on tcp_echoserver.c, app_ethernet.c, ethernetif.c",
        ],
        source_code_level="full_upstream_repo",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="likely",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK", "LOOP_WRITE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Server-side STM32Cube networking example with richer horizontal chain variants than the client and good DMA/channel structure.",
        todo_items=[
            "Annotate server RX -> pbuf -> echo/writeback chain.",
            "Capture one representative payload_len derived chain and one negative safe branch.",
            "Model DMA->MAIN or DMA->TASK transfer if Ethernet DMA is explicit in the binary.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="stm32cube_lwip_udp_echo_client",
        dataset="monolithic-firmware-collection",
        subset="ARMCortex-M",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/stm32_udp_echo_client/stm32_udp_echo_client.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/stm32_udp_echo_client/stm32_udp_echo_client.bin",
        title="STM32CubeF4 LwIP UDP echo client",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="stm32cubef4",
        source_locator=[
            "firmware/source_repos/STM32CubeF4/Projects/STM32469I_EVAL/Applications/LwIP/LwIP_UDP_Echo_Client",
            "focus on udp_echoclient.c, app_ethernet.c, ethernetif.c",
        ],
        source_code_level="full_upstream_repo",
        chain_depth="deep",
        chain_breadth="medium",
        expected_channel_mode="likely",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Useful UDP-specific chain shape with pbuf-driven packet handling but less noise than the server variant.",
        todo_items=[
            "Resolve UDP RX/TX payload object lifecycle.",
            "Annotate one callback-rooted chain with explicit length/root facts.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="stm32cube_lwip_udp_echo_server",
        dataset="monolithic-firmware-collection",
        subset="ARMCortex-M",
        binary_path="firmware/monolithic-firmware-collection/ARMCortex-M/stm32_udp_echo_server/stm32_udp_echo_server.elf",
        bin_path="firmware/monolithic-firmware-collection/ARMCortex-M/stm32_udp_echo_server/stm32_udp_echo_server.bin",
        title="STM32CubeF4 LwIP UDP echo server",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="stm32cubef4",
        source_locator=[
            "firmware/source_repos/STM32CubeF4/Projects/STM32469I_EVAL/Applications/LwIP/LwIP_UDP_Echo_Server",
            "focus on udp_echoserver.c, app_ethernet.c, ethernetif.c",
        ],
        source_code_level="full_upstream_repo",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="likely",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK", "LOOP_WRITE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Large UDP server example with deeper callback fan-out and Ethernet DMA backing; good for object/channel GT beyond toy firmware.",
        todo_items=[
            "Annotate one positive packet ingress -> response chain.",
            "Add at least one forbidden chain rooted only in status/config MMIO or DHCP control paths.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="usbs_tcp_echo_client_vuln_bof",
        dataset="uSBS",
        subset="Ground-truth Benchmark/fw",
        binary_path="firmware/uSBS/Ground-truth Benchmark/fw/tcp_echo_client_vuln_bof/STM32469I_EVAL_tcp_echo_base.elf",
        bin_path="firmware/uSBS/Ground-truth Benchmark/fw/tcp_echo_client_vuln_bof/STM32469I_EVAL_tcp_echo_base.bin",
        title="uSBS TCP echo client buffer overflow",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="stm32cubef4",
        source_locator=[
            "firmware/source_repos/STM32CubeF4",
            "firmware/uSBS/Ground-truth Benchmark/fw/tcp_echo_client_vuln_bof",
            "firmware/ground_truth_bundle/references/uSBS/injected_snippets_vulns.c",
        ],
        source_code_level="upstream_base_plus_overlay",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "LOOP_WRITE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="uSBS sample with concrete replay inputs and benchmark overlay; useful for deeper network stack chains than microbench.",
        todo_items=[
            "Map STM32Cube base example source to uSBS overlay and injected snippet.",
            "Annotate ingress buffer, parser/callback steps, and final copy/write sink.",
            "Link replay inputs to the annotated positive chain.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="usbs_tcp_echo_client_vuln_bof_dhcp",
        dataset="uSBS",
        subset="Ground-truth Benchmark/fw",
        binary_path="firmware/uSBS/Ground-truth Benchmark/fw/tcp_echo_client_vuln_bof/STM32469I_EVAL_tcp_echo_base_DHCP/STM32469I_EVAL_tcp_echo_base.elf",
        bin_path="firmware/uSBS/Ground-truth Benchmark/fw/tcp_echo_client_vuln_bof/STM32469I_EVAL_tcp_echo_base_DHCP/STM32469I_EVAL_tcp_echo_base.bin",
        title="uSBS TCP echo client BOF (DHCP variant)",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="stm32cubef4",
        source_locator=[
            "firmware/source_repos/STM32CubeF4",
            "firmware/uSBS/Ground-truth Benchmark/fw/tcp_echo_client_vuln_bof/STM32469I_EVAL_tcp_echo_base_DHCP",
            "firmware/ground_truth_bundle/references/uSBS/injected_snippets_vulns.c",
        ],
        source_code_level="upstream_base_plus_overlay",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="likely",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "LOOP_WRITE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="DHCP-enabled uSBS variant is larger than the base BOF sample and adds extra network-stack objects and callback paths.",
        todo_items=[
            "Separate DHCP/control-plane objects from the attacker-controlled payload chain.",
            "Annotate one positive BOF chain and at least one control-only forbidden chain.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="usbs_tcp_echo_client_vuln_off_by_one",
        dataset="uSBS",
        subset="Ground-truth Benchmark/fw",
        binary_path="firmware/uSBS/Ground-truth Benchmark/fw/tcp_echo_client_vuln_off_by_one/STM32469I_EVAL_tcp_echo_base.elf",
        bin_path="firmware/uSBS/Ground-truth Benchmark/fw/tcp_echo_client_vuln_off_by_one/STM32469I_EVAL_tcp_echo_base.bin",
        title="uSBS TCP echo client off-by-one",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="stm32cubef4",
        source_locator=[
            "firmware/source_repos/STM32CubeF4",
            "firmware/uSBS/Ground-truth Benchmark/fw/tcp_echo_client_vuln_off_by_one",
            "firmware/ground_truth_bundle/references/uSBS/injected_snippets_vulns.c",
        ],
        source_code_level="upstream_base_plus_overlay",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "LOOP_WRITE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Same protocol family as the BOF case but with different boundary semantics; useful for derive/check GT.",
        todo_items=[
            "Annotate exact off-by-one root and boundary expectation.",
            "Record the check that should exist but does not.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="usbs_tcp_echo_client_payload_len_variant",
        dataset="uSBS",
        subset="Ground-truth Benchmark/fw",
        binary_path="firmware/uSBS/Ground-truth Benchmark/fw/tcp_echo_client_vuln_off_by_one_test_payload_len/STM32469I_EVAL_tcp_echo_base.elf",
        bin_path="firmware/uSBS/Ground-truth Benchmark/fw/tcp_echo_client_vuln_off_by_one_test_payload_len/STM32469I_EVAL_tcp_echo_base.bin",
        title="uSBS TCP echo client payload-length variant",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="stm32cubef4",
        source_locator=[
            "firmware/source_repos/STM32CubeF4",
            "firmware/uSBS/Ground-truth Benchmark/fw/tcp_echo_client_vuln_off_by_one_test_payload_len",
            "firmware/ground_truth_bundle/references/uSBS/injected_snippets_vulns.c",
        ],
        source_code_level="upstream_base_plus_overlay",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "LOOP_WRITE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Specifically useful for length-derived chains; prioritize root and derive/check annotation.",
        todo_items=[
            "Annotate payload_len-style derived root and downstream copy/write site.",
            "Capture whether any guard is only partial or completely absent.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="usbs_test_printf_fw",
        dataset="uSBS",
        subset="Ground-truth Benchmark/fw",
        binary_path="firmware/uSBS/Ground-truth Benchmark/fw/test_printf_fw/STM32469I_EVAL_stm32_udp_echo_server.elf",
        bin_path="firmware/uSBS/Ground-truth Benchmark/fw/test_printf_fw/STM32469I_EVAL_stm32_udp_echo_server.bin",
        title="uSBS printf-oriented firmware variant",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="stm32cubef4",
        source_locator=[
            "firmware/source_repos/STM32CubeF4",
            "firmware/uSBS/Ground-truth Benchmark/fw/test_printf_fw",
            "firmware/ground_truth_bundle/references/uSBS/injected_snippets_vulns.c",
        ],
        source_code_level="upstream_base_plus_overlay",
        chain_depth="deep",
        chain_breadth="medium",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["FORMAT_STRING_SINK", "COPY_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Useful for scaling the format-string sink family beyond toy microbench patterns.",
        todo_items=[
            "Identify exact format root and whether it is network-controlled.",
            "Record local safe formatting helpers that must stay dropped or safe.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="usbs_udp_echo_server_bof",
        dataset="uSBS",
        subset="Ground-truth Benchmark/fw",
        binary_path="firmware/uSBS/Ground-truth Benchmark/fw/udp_echo_server_bof/STM32469I_EVAL_stm32_udp_echo_server.elf",
        bin_path="firmware/uSBS/Ground-truth Benchmark/fw/udp_echo_server_bof/STM32469I_EVAL_stm32_udp_echo_server.bin",
        title="uSBS UDP echo server buffer overflow",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="stm32cubef4",
        source_locator=[
            "firmware/source_repos/STM32CubeF4",
            "firmware/uSBS/Ground-truth Benchmark/fw/udp_echo_server_bof",
            "firmware/ground_truth_bundle/references/uSBS/injected_snippets_vulns.c",
        ],
        source_code_level="upstream_base_plus_overlay",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "LOOP_WRITE_SINK", "STORE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Primary uSBS UDP BOF case; richer than microbench due to stack and callback layers.",
        todo_items=[
            "Annotate RX buffer object, parser state, and final BOF sink.",
            "Link replay trigger inputs to source objects when possible.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="usbs_udp_echo_server_bof_expl",
        dataset="uSBS",
        subset="Ground-truth Benchmark/fw",
        binary_path="firmware/uSBS/Ground-truth Benchmark/fw/udp_echo_server_bof_expl/STM32469I_EVAL_stm32_udp_echo_server.elf",
        bin_path="firmware/uSBS/Ground-truth Benchmark/fw/udp_echo_server_bof_expl/STM32469I_EVAL_stm32_udp_echo_server.bin",
        title="uSBS UDP echo server exploitable BOF variant",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="stm32cubef4",
        source_locator=[
            "firmware/source_repos/STM32CubeF4",
            "firmware/uSBS/Ground-truth Benchmark/fw/udp_echo_server_bof_expl",
            "firmware/ground_truth_bundle/references/uSBS/injected_snippets_vulns.c",
        ],
        source_code_level="upstream_base_plus_overlay",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK", "LOOP_WRITE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Keep alongside the plain BOF variant to compare exploitability-related checks and chain confidence.",
        todo_items=[
            "Differentiate exploitability-specific conditions from plain bug reachability.",
            "Capture whether verdict should stay CONFIRMED or only SUSPICIOUS under current evidence.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="usbs_tcp_echo_client_vuln_off_by_one_dhcp",
        dataset="uSBS",
        subset="Ground-truth Benchmark/fw",
        binary_path="firmware/uSBS/Ground-truth Benchmark/fw/tcp_echo_client_vuln_off_by_one/STM32469I_EVAL_tcp_echo_base_DHCP/STM32469I_EVAL_tcp_echo_base.elf",
        bin_path="firmware/uSBS/Ground-truth Benchmark/fw/tcp_echo_client_vuln_off_by_one/STM32469I_EVAL_tcp_echo_base_DHCP/STM32469I_EVAL_tcp_echo_base.bin",
        title="uSBS TCP echo client off-by-one (DHCP variant)",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="stm32cubef4",
        source_locator=[
            "firmware/source_repos/STM32CubeF4",
            "firmware/uSBS/Ground-truth Benchmark/fw/tcp_echo_client_vuln_off_by_one/STM32469I_EVAL_tcp_echo_base_DHCP",
            "firmware/ground_truth_bundle/references/uSBS/injected_snippets_vulns.c",
        ],
        source_code_level="upstream_base_plus_overlay",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="likely",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "LOOP_WRITE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="DHCP-enabled off-by-one variant is larger and noisier than the base case while staying inside the current sink family scope.",
        todo_items=[
            "Separate DHCP/control-plane paths from the attacker-controlled payload chain.",
            "Annotate one positive off-by-one chain and one forbidden control-only chain.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="usbs_udp_echo_server_off_by_one",
        dataset="uSBS",
        subset="Ground-truth Benchmark/fw",
        binary_path="firmware/uSBS/Ground-truth Benchmark/fw/udp_echo_server_off_by_one/STM32469I_EVAL_stm32_udp_echo_server.elf",
        bin_path="firmware/uSBS/Ground-truth Benchmark/fw/udp_echo_server_off_by_one/STM32469I_EVAL_stm32_udp_echo_server.bin",
        title="uSBS UDP echo server off-by-one",
        priority="high",
        role="primary_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="stm32cubef4",
        source_locator=[
            "firmware/source_repos/STM32CubeF4",
            "firmware/uSBS/Ground-truth Benchmark/fw/udp_echo_server_off_by_one",
            "firmware/ground_truth_bundle/references/uSBS/injected_snippets_vulns.c",
        ],
        source_code_level="upstream_base_plus_overlay",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="optional",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "LOOP_WRITE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Pairs well with the TCP off-by-one case for generalizing derive/check handling.",
        todo_items=[
            "Annotate exact off-by-one root and expected boundary contract.",
            "Record replay input family that reaches the bug.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="usbs_udp_echo_server_bof_instrumented_patched",
        dataset="uSBS",
        subset="Ground-truth Benchmark/fw",
        binary_path="firmware/uSBS/Ground-truth Benchmark/fw/udp_echo_server_bof_instrumented_patched/STM32469I_EVAL_stm32_udp_echo_server.elf",
        bin_path="firmware/uSBS/Ground-truth Benchmark/fw/udp_echo_server_bof_instrumented_patched/STM32469I_EVAL_stm32_udp_echo_server.bin",
        title="uSBS UDP echo server BOF (instrumented patched variant)",
        priority="high",
        role="hard_mode_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="stm32cubef4",
        source_locator=[
            "firmware/source_repos/STM32CubeF4",
            "firmware/uSBS/Ground-truth Benchmark/fw/udp_echo_server_bof_instrumented_patched",
            "firmware/ground_truth_bundle/references/uSBS/injected_snippets_vulns.c",
        ],
        source_code_level="upstream_base_plus_overlay",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="likely",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK", "LOOP_WRITE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Another large, noisy BOF variant that stays within current sink scope and is better suited than UAF for current optimization loops.",
        todo_items=[
            "Keep GT targeted: one positive BOF chain plus one forbidden noisy chain.",
            "Compare against the non-patched instrumented variant to test chain suppression stability.",
        ],
        negative_expectations=[],
    ),
    SampleMeta(
        sample_id="usbs_udp_echo_server_bof_instrumented",
        dataset="uSBS",
        subset="Ground-truth Benchmark/fw",
        binary_path="firmware/uSBS/Ground-truth Benchmark/fw/udp_echo_server_bof_instrumented/STM32469I_EVAL_stm32_udp_echo_server.elf",
        bin_path="firmware/uSBS/Ground-truth Benchmark/fw/udp_echo_server_bof_instrumented/STM32469I_EVAL_stm32_udp_echo_server.bin",
        title="uSBS UDP echo server BOF (instrumented variant)",
        priority="high",
        role="hard_mode_chain_driver",
        type_family="type_ii_or_iii_ready",
        source_repo_id="stm32cubef4",
        source_locator=[
            "firmware/source_repos/STM32CubeF4",
            "firmware/uSBS/Ground-truth Benchmark/fw/udp_echo_server_bof_instrumented",
            "firmware/ground_truth_bundle/references/uSBS/injected_snippets_vulns.c",
        ],
        source_code_level="upstream_base_plus_overlay",
        chain_depth="deep",
        chain_breadth="wide",
        expected_channel_mode="likely",
        likely_source_labels=["MMIO_READ", "ISR_MMIO_READ", "DMA_BACKED_BUFFER"],
        likely_sink_labels=["COPY_SINK", "STORE_SINK", "LOOP_WRITE_SINK"],
        current_support_status="target_for_artifact_gt",
        notes="Very large instrumented uSBS variant that should stress object binding, chain suppression, and library/noise pruning.",
        todo_items=[
            "Keep GT targeted: one positive BOF chain plus one or two forbidden noisy chains.",
            "Use this as a scale-up sample for larger symbol tables and noisier helper code.",
        ],
        negative_expectations=[],
    ),
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _rel(repo_root: Path, path: str | None) -> str | None:
    if not path:
        return None
    p = Path(path)
    if not p.is_absolute():
        return p.as_posix()
    return p.relative_to(repo_root).as_posix()


def _load_existing_global_inventory(repo_root: Path) -> List[dict]:
    path = repo_root / GLOBAL_INVENTORY_REL
    if not path.exists():
        return []
    return json.loads(path.read_text())


def _existing_inventory_map(entries: Iterable[dict]) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    for entry in entries:
        elf_path = entry.get("elf_path")
        if elf_path:
            out[elf_path] = entry
    return out


def _sample_template(repo_root: Path, meta: SampleMeta) -> dict:
    repo = SOURCE_REPOS[meta.source_repo_id]
    return {
        "schema_version": SCHEMA_VERSION,
        "sample_id": meta.sample_id,
        "binary_stem": Path(meta.binary_path).stem,
        "eval_stem": meta.sample_id,
        "annotation_level": "seed",
        "chain_gt_scope": "targeted_only",
        "dataset": meta.dataset,
        "subset": meta.subset,
        "priority": meta.priority,
        "role": meta.role,
        "type_family": meta.type_family,
        "title": meta.title,
        "binary_artifacts": {
            "elf_path": _rel(repo_root, meta.binary_path),
            "bin_path": _rel(repo_root, meta.bin_path),
            "formats": ["elf"] + (["bin"] if meta.bin_path else []),
        },
        "source_code": {
            "source_repo_id": repo.repo_id,
            "source_repo_url": repo.repo_url,
            "local_checkout": _rel(repo_root, repo.local_checkout),
            "source_code_level": meta.source_code_level,
            "source_locator": meta.source_locator,
            "repo_notes": repo.notes,
        },
        "analysis_hints": {
            "chain_depth": meta.chain_depth,
            "chain_breadth": meta.chain_breadth,
            "expected_channel_mode": meta.expected_channel_mode,
            "likely_source_labels": meta.likely_source_labels,
            "likely_sink_labels": meta.likely_sink_labels,
            "current_support_status": meta.current_support_status,
        },
        "sources": [],
        "objects": [],
        "channels": [],
        "sinks": [],
        "sink_roots": [],
        "derive_checks": [],
        "chains": [],
        "negative_expectations": meta.negative_expectations,
        "todo_items": meta.todo_items,
        "notes": meta.notes,
    }


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def _mesobench_inventory_entries(repo_root: Path, sample_docs: List[dict], existing_inventory: List[dict]) -> List[dict]:
    old_by_elf = _existing_inventory_map(existing_inventory)
    out: List[dict] = []
    for sample in sample_docs:
        elf_path = sample["binary_artifacts"]["elf_path"]
        old = old_by_elf.get(elf_path, {})
        source_code = sample["source_code"]
        entry = {
            "dataset": "mesobench-v1",
            "subset": sample["subset"],
            "sample_id": sample["sample_id"],
            "elf_path": elf_path,
            "bin_path": sample["binary_artifacts"]["bin_path"] or "",
            "gt_type": "artifact_gt_seed",
            "gt_ref_files": [
                "ground_truth_bundle/mesobench_v1/README.md",
                f"ground_truth_bundle/mesobench_v1/samples/{sample['sample_id']}.json",
                "ground_truth_bundle/references/mesobench/README.md",
            ],
            "trigger_inputs_count": int(old.get("trigger_inputs_count", 0) or 0),
            "trigger_inputs": list(old.get("trigger_inputs", []) or []),
            "notes": (
                f"priority={sample['priority']}; role={sample['role']}; "
                f"source={source_code['source_repo_id']}({source_code['source_code_level']})"
            ),
        }
        out.append(entry)
    return out


def _write_inventory_csv(path: Path, entries: List[dict]) -> None:
    fieldnames = [
        "dataset",
        "subset",
        "sample_id",
        "elf_path",
        "bin_path",
        "gt_type",
        "gt_ref_files",
        "trigger_inputs_count",
        "trigger_inputs",
        "notes",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for entry in entries:
            row = dict(entry)
            row["gt_ref_files"] = ";".join(row.get("gt_ref_files", []))
            row["trigger_inputs"] = ";".join(row.get("trigger_inputs", []))
            writer.writerow(row)


def _write_mesobench_inventory(out_dir: Path, sample_docs: List[dict], source_repos: Dict[str, SourceRepo]) -> None:
    inv_json = []
    for sample in sample_docs:
        code = sample["source_code"]
        inv_json.append(
            {
                "sample_id": sample["sample_id"],
                "dataset": sample["dataset"],
                "priority": sample["priority"],
                "role": sample["role"],
                "chain_depth": sample["analysis_hints"]["chain_depth"],
                "chain_breadth": sample["analysis_hints"]["chain_breadth"],
                "expected_channel_mode": sample["analysis_hints"]["expected_channel_mode"],
                "elf_path": sample["binary_artifacts"]["elf_path"],
                "bin_path": sample["binary_artifacts"]["bin_path"],
                "source_repo_id": code["source_repo_id"],
                "source_repo_url": code["source_repo_url"],
                "local_checkout": code["local_checkout"],
                "source_code_level": code["source_code_level"],
                "current_support_status": sample["analysis_hints"]["current_support_status"],
                "notes": sample["notes"],
            }
        )
    _write_json(out_dir / "mesobench_inventory.json", inv_json)
    fieldnames = list(inv_json[0].keys()) if inv_json else []
    with (out_dir / "mesobench_inventory.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in inv_json:
            writer.writerow(row)


def _write_summary_md(out_dir: Path, sample_docs: List[dict]) -> None:
    lines = [
        "# Mesobench v1 Candidate Summary",
        "",
        f"- sample_count: {len(sample_docs)}",
        f"- primary_chain_driver: {sum(1 for s in sample_docs if s['role'] == 'primary_chain_driver')}",
        f"- hard_mode_chain_driver: {sum(1 for s in sample_docs if s['role'] == 'hard_mode_chain_driver')}",
        f"- negative_control: {sum(1 for s in sample_docs if s['role'] == 'negative_control')}",
        f"- future_sink_expansion: {sum(1 for s in sample_docs if s['role'] == 'future_sink_expansion')}",
        "",
        "| sample_id | dataset | priority | role | source_repo | channel | sink families |",
        "|---|---|---|---|---|---|---|",
    ]
    for sample in sample_docs:
        hints = sample["analysis_hints"]
        lines.append(
            "| {sample_id} | {dataset} | {priority} | {role} | {repo} | {channel} | {sinks} |".format(
                sample_id=sample["sample_id"],
                dataset=sample["dataset"],
                priority=sample["priority"],
                role=sample["role"],
                repo=sample["source_code"]["source_repo_id"],
                channel=hints["expected_channel_mode"],
                sinks=", ".join(hints["likely_sink_labels"]) or "-",
            )
        )
    (out_dir / "candidate_summary.md").write_text("\n".join(lines) + "\n")


def _write_eval_manifest(repo_root: Path, sample_docs: List[dict]) -> None:
    manifest = {
        "name": "mesobench_v1_unstripped_elf",
        "created_at": _now_iso(),
        "description": (
            "Mesobench v1: 30 source-backed or source-mappable firmware samples "
            "selected to extend chain-centric optimization beyond microbench."
        ),
        "samples": [
            {
                "dataset": sample["dataset"],
                "sample_id": sample["sample_id"],
                "output_stem": sample.get("eval_stem", sample["sample_id"]),
                "binary_path": str((repo_root / sample["binary_artifacts"]["elf_path"]).resolve()),
                "has_gt": False,
                "artifact_gt_seed": True,
                "artifact_gt_path": str(
                    (repo_root / SAMPLE_REL_DIR / f"{sample['sample_id']}.json").resolve()
                ),
                "notes": f"priority={sample['priority']}; role={sample['role']}",
            }
            for sample in sample_docs
        ],
    }
    _write_json(repo_root / EVAL_MANIFEST_REL, manifest)


def build_mesobench_v1(repo_root: Path | None = None, out_dir: Path | None = None, *, force: bool = False) -> dict:
    repo_root = repo_root or _repo_root()
    out_dir = out_dir or (repo_root / DEFAULT_REL_DIR)
    sample_dir = out_dir / "samples"
    sample_dir.mkdir(parents=True, exist_ok=True)

    existing_inventory = _load_existing_global_inventory(repo_root)

    sample_docs: List[dict] = []
    index_entries: List[dict] = []

    for meta in MESOBENCH_SAMPLES:
        sample_doc = _sample_template(repo_root, meta)
        sample_path = sample_dir / f"{meta.sample_id}.json"
        if sample_path.exists() and not force:
            sample_doc = json.loads(sample_path.read_text())
        else:
            _write_json(sample_path, sample_doc)
        sample_docs.append(sample_doc)
        index_entries.append(
            {
                "sample_id": meta.sample_id,
                "dataset": meta.dataset,
                "priority": meta.priority,
                "role": meta.role,
                "elf_path": _rel(repo_root, meta.binary_path),
                "bin_path": _rel(repo_root, meta.bin_path),
                "source_repo_id": meta.source_repo_id,
                "source_code_level": meta.source_code_level,
                "chain_depth": meta.chain_depth,
                "chain_breadth": meta.chain_breadth,
                "expected_channel_mode": meta.expected_channel_mode,
            }
        )

    index_doc = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _now_iso(),
        "sample_count": len(sample_docs),
        "primary_chain_driver_count": sum(1 for s in sample_docs if s["role"] == "primary_chain_driver"),
        "hard_mode_chain_driver_count": sum(1 for s in sample_docs if s["role"] == "hard_mode_chain_driver"),
        "negative_control_count": sum(1 for s in sample_docs if s["role"] == "negative_control"),
        "future_sink_expansion_count": sum(1 for s in sample_docs if s["role"] == "future_sink_expansion"),
        "source_repositories": {
            repo_id: {
                "display_name": repo.display_name,
                "repo_url": repo.repo_url,
                "local_checkout": _rel(repo_root, repo.local_checkout),
                "source_code_level": repo.source_code_level,
                "notes": repo.notes,
            }
            for repo_id, repo in SOURCE_REPOS.items()
        },
        "samples": index_entries,
        "next_priority_build_targets": [
            {
                "target": "freertos_plus_tcp_dns_parser_real_build",
                "source_repo_id": "freertos-plus-tcp",
                "notes": "Use this to grow beyond the microbench reproduction of CVE-2018-16525.",
            },
            {
                "target": "stm32_usb_host_descriptor_real_build",
                "source_repo_id": "stm32-mw-usb-host",
                "notes": "Use this to grow beyond the microbench reproduction of CVE-2021-34259.",
            },
        ],
    }
    _write_json(out_dir / "index.json", index_doc)

    _write_mesobench_inventory(out_dir, sample_docs, SOURCE_REPOS)
    _write_summary_md(out_dir, sample_docs)

    mesobench_entries = _mesobench_inventory_entries(repo_root, sample_docs, existing_inventory)
    _write_json(out_dir / "global_inventory_patch.json", mesobench_entries)

    combined_inventory = [
        entry
        for entry in existing_inventory
        if not (entry.get("dataset") == "mesobench-v1")
    ] + mesobench_entries
    _write_json(repo_root / GLOBAL_INVENTORY_REL, combined_inventory)
    _write_inventory_csv(repo_root / GLOBAL_INVENTORY_CSV_REL, combined_inventory)
    _write_eval_manifest(repo_root, sample_docs)

    return {
        "schema_version": SCHEMA_VERSION,
        "sample_count": len(sample_docs),
        "out_dir": str(out_dir),
    }


def validate_mesobench_v1_tree(root: Path) -> dict:
    index_path = root / "index.json"
    if not index_path.exists():
        return {"ok": False, "errors": ["missing index.json"]}
    index_doc = json.loads(index_path.read_text())
    samples = index_doc.get("samples", [])
    errors: List[str] = []
    sample_dir = root / "samples"
    for sample in samples:
        sample_id = sample.get("sample_id")
        path = sample_dir / f"{sample_id}.json"
        if not path.exists():
            errors.append(f"missing sample file: {sample_id}")
            continue
        doc = json.loads(path.read_text())
        for field in (
            "schema_version",
            "sample_id",
            "binary_artifacts",
            "source_code",
            "analysis_hints",
            "sources",
            "objects",
            "channels",
            "sinks",
            "sink_roots",
            "derive_checks",
            "chains",
            "negative_expectations",
        ):
            if field not in doc:
                errors.append(f"{sample_id}: missing {field}")
        if doc.get("schema_version") != SCHEMA_VERSION:
            errors.append(f"{sample_id}: schema mismatch")
    return {
        "ok": not errors,
        "sample_count": len(samples),
        "errors": errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build or validate mesobench v1 GT seeds.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_build = sub.add_parser("build", help="Build mesobench_v1 seed GT tree")
    p_build.add_argument("--force", action="store_true", help="Overwrite sample seed files")

    sub.add_parser("validate", help="Validate mesobench_v1 tree")

    args = parser.parse_args()
    repo_root = _repo_root()
    out_dir = repo_root / DEFAULT_REL_DIR
    if args.cmd == "build":
        report = build_mesobench_v1(repo_root=repo_root, out_dir=out_dir, force=args.force)
    else:
        report = validate_mesobench_v1_tree(out_dir)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
