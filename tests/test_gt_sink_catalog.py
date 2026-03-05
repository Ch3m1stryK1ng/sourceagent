"""Tests for normalized GT sink catalog generation."""

from pathlib import Path

from sourceagent.pipeline.gt_sink_catalog import (
    build_normalized_sink_gt,
    write_normalized_sink_gt,
)


def _write_map(path: Path, symbols):
    lines = []
    for addr, name in symbols:
        lines.append(f"                0x{addr:08x}                {name}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_build_normalized_sink_gt_resolves_addresses(tmp_path):
    _write_map(tmp_path / "t0_copy_sink.map", [
        (0x0800005C, "handler"),
        (0x08000094, "handle_name"),
    ])
    _write_map(tmp_path / "t0_store_loop_sink.map", [
        (0x08000050, "write_register"),
        (0x0800005C, "fill_buffer"),
        (0x08000076, "clear_buffer"),
    ])
    _write_map(tmp_path / "t0_uart_rx_overflow.map", [(0x08000052, "uart_receive")])
    _write_map(tmp_path / "t0_dma_length_overflow.map", [(0x080000A0, "process_dma_data")])
    _write_map(tmp_path / "t0_indirect_memcpy.map", [(0x08000088, "do_copy")])
    _write_map(tmp_path / "t0_format_string.map", [(0x08000070, "log_message")])
    _write_map(tmp_path / "t0_func_ptr_dispatch.map", [(0x08000064, "dispatch_command")])
    _write_map(tmp_path / "cve_2020_10065_hci_spi.map", [(0x080000B0, "bt_spi_rx_thread")])
    _write_map(tmp_path / "cve_2021_34259_usb_host.map", [
        (0x08000072, "USBH_ParseEPDesc"),
        (0x08000092, "USBH_ParseInterfaceDesc"),
        (0x080000B8, "USBH_ParseCfgDesc"),
    ])
    _write_map(tmp_path / "cve_2018_16525_freertos_dns.map", [
        (0x080000A0, "prvSkipNameField"),
        (0x080000C0, "prvParseDNSReply"),
        (0x080000E0, "prvProcessIPPacket"),
    ])

    rows = build_normalized_sink_gt(tmp_path)
    assert rows

    by_key = {
        (row["binary_stem"], row["function_name"], row["gt_sink_id"]): row
        for row in rows
    }
    assert by_key[("t0_copy_sink", "handler", "S1")]["address"] == 0x0800005C
    assert by_key[("t0_copy_sink", "handle_name", "S2")]["address"] == 0x08000094
    assert by_key[("cve_2021_34259_usb_host", "USBH_ParseCfgDesc", "S1")]["address"] == 0x080000B8


def test_write_normalized_sink_gt_outputs_files(tmp_path):
    (tmp_path / "t0_copy_sink.map").write_text(
        "                0x0800005c                handler\n"
        "                0x08000094                handle_name\n",
        encoding="utf-8",
    )
    out_json = tmp_path / "sinks.json"
    out_csv = tmp_path / "sinks.csv"

    summary = write_normalized_sink_gt(tmp_path, out_json, out_csv)
    assert out_json.exists()
    assert out_csv.exists()
    assert summary["entry_count"] > 0
