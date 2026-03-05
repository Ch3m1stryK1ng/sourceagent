"""Tests for firmware context integration in interface/main.py."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from sourceagent.pipeline.models import MemoryMap, MemoryRegion


# ── Helper to build a MemoryMap ──────────────────────────────────────────────


def _make_memory_map(
    regions=None,
    isr_handler_addrs=None,
    base_address=0x08000000,
):
    """Build a MemoryMap for testing."""
    return MemoryMap(
        binary_path="test.bin",
        arch="ARM:LE:32:Cortex",
        base_address=base_address,
        entry_point=0x08000101,
        regions=regions or [],
        isr_handler_addrs=isr_handler_addrs or [],
    )


# ── Tests for _setup_firmware_context ────────────────────────────────────────


@pytest.mark.asyncio
async def test_setup_firmware_context_call():
    """Correct JSON args should be passed to MCP for setup_firmware_context."""
    from sourceagent.interface.main import _setup_firmware_context

    mm = _make_memory_map(
        regions=[
            MemoryRegion(name="SRAM", base=0x20000000, size=0x10000, permissions="rw", kind="sram"),
            MemoryRegion(name="PERIPHERAL", base=0x40000000, size=0x20000000, permissions="rw", kind="mmio"),
        ],
        isr_handler_addrs=[0x08000101, 0x08000201],
    )

    mock_mcp = AsyncMock()
    mock_mcp.call_tool.return_value = [
        {"type": "text", "text": json.dumps({
            "binary_name": "test-abc123",
            "memory_blocks_created": ["SRAM", "PERIPHERAL"],
            "entry_points_added": 2,
            "functions_created": 2,
            "reanalysis_triggered": True,
            "errors": [],
        })}
    ]

    await _setup_firmware_context(mock_mcp, "ghidra", "test-abc123", mm)

    mock_mcp.call_tool.assert_called_once()
    call_args = mock_mcp.call_tool.call_args
    assert call_args[0][1] == "setup_firmware_context"

    args = call_args[0][2]
    assert args["binary_name"] == "test-abc123"

    regions = args["regions"]
    assert len(regions) == 2
    assert regions[0]["name"] == "SRAM"
    assert regions[1]["name"] == "PERIPHERAL"

    entry_points = args["entry_points"]
    assert len(entry_points) == 2
    assert "0x08000101" in entry_points
    assert "0x08000201" in entry_points


@pytest.mark.asyncio
async def test_flash_region_excluded():
    """Flash region should not be included in regions JSON."""
    from sourceagent.interface.main import _setup_firmware_context

    mm = _make_memory_map(
        regions=[
            MemoryRegion(name="FLASH", base=0x08000000, size=0x80000, permissions="rx", kind="flash"),
            MemoryRegion(name="SRAM", base=0x20000000, size=0x10000, permissions="rw", kind="sram"),
        ],
        isr_handler_addrs=[0x08000101],
    )

    mock_mcp = AsyncMock()
    mock_mcp.call_tool.return_value = [
        {"type": "text", "text": json.dumps({
            "binary_name": "test-abc123",
            "memory_blocks_created": ["SRAM"],
            "entry_points_added": 1,
            "functions_created": 1,
            "reanalysis_triggered": True,
            "errors": [],
        })}
    ]

    await _setup_firmware_context(mock_mcp, "ghidra", "test-abc123", mm)

    args = mock_mcp.call_tool.call_args[0][2]
    regions = args["regions"]
    region_names = [r["name"] for r in regions]
    assert "FLASH" not in region_names
    assert "SRAM" in region_names


@pytest.mark.asyncio
async def test_isr_addrs_as_entry_points():
    """ISR addresses should appear as entry points in the JSON args."""
    from sourceagent.interface.main import _setup_firmware_context

    isr_addrs = [0x08000101, 0x08000201, 0x08000301]
    mm = _make_memory_map(
        regions=[
            MemoryRegion(name="SRAM", base=0x20000000, size=0x10000, permissions="rw", kind="sram"),
        ],
        isr_handler_addrs=isr_addrs,
    )

    mock_mcp = AsyncMock()
    mock_mcp.call_tool.return_value = [
        {"type": "text", "text": json.dumps({
            "binary_name": "test-abc123",
            "memory_blocks_created": ["SRAM"],
            "entry_points_added": 3,
            "functions_created": 3,
            "reanalysis_triggered": True,
            "errors": [],
        })}
    ]

    await _setup_firmware_context(mock_mcp, "ghidra", "test-abc123", mm)

    args = mock_mcp.call_tool.call_args[0][2]
    entry_points = args["entry_points"]
    assert len(entry_points) == 3
    for addr in isr_addrs:
        assert f"0x{addr:08x}" in entry_points


@pytest.mark.asyncio
async def test_zero_addrs_excluded():
    """ISR address=0 should be filtered out of entry points."""
    from sourceagent.interface.main import _setup_firmware_context

    mm = _make_memory_map(
        regions=[
            MemoryRegion(name="SRAM", base=0x20000000, size=0x10000, permissions="rw", kind="sram"),
        ],
        isr_handler_addrs=[0x08000101, 0, 0, 0x08000301],
    )

    mock_mcp = AsyncMock()
    mock_mcp.call_tool.return_value = [
        {"type": "text", "text": json.dumps({
            "binary_name": "test-abc123",
            "memory_blocks_created": ["SRAM"],
            "entry_points_added": 2,
            "functions_created": 2,
            "reanalysis_triggered": True,
            "errors": [],
        })}
    ]

    await _setup_firmware_context(mock_mcp, "ghidra", "test-abc123", mm)

    args = mock_mcp.call_tool.call_args[0][2]
    entry_points = args["entry_points"]
    assert len(entry_points) == 2
    assert "0x00000000" not in entry_points


@pytest.mark.asyncio
async def test_skip_when_no_regions_or_entry_points():
    """Should not call MCP if no regions and no entry points."""
    from sourceagent.interface.main import _setup_firmware_context

    mm = _make_memory_map(regions=[], isr_handler_addrs=[])

    mock_mcp = AsyncMock()
    await _setup_firmware_context(mock_mcp, "ghidra", "test-abc123", mm)

    mock_mcp.call_tool.assert_not_called()
