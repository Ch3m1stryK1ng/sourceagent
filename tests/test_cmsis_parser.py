"""Tests for CMSIS header parser (cmsis_parser.py).

Covers:
  - SAM3 component header parsing (struct offsets)
  - K64F MK64F12.h parsing (struct offsets)
  - Base address extraction for both styles
  - Array fields and padding handled correctly
  - Generated data sanity checks
"""

import os
from pathlib import Path

import pytest

from sourceagent.pipeline.cmsis_parser import parse_cmsis_header, parse_base_addresses
from sourceagent.pipeline.peripheral_types import (
    ALL_STRUCT_OFFSETS,
    SAM3_STRUCT_OFFSETS,
    K64F_STRUCT_OFFSETS,
    get_field_offset,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SAM3_COMPONENT_DIR = REPO_ROOT / "firmware" / "p2im-unit_tests" / "RIOT" / "RIOT-ENV" / "cpu" / "sam_common" / "include" / "vendor" / "sam3x" / "include"
K64F_HEADER = REPO_ROOT / "firmware" / "p2im-unit_tests" / "RIOT" / "RIOT-ENV" / "cpu" / "kinetis" / "include" / "vendor" / "MK64F12.h"


# Skip if headers not available
has_sam3 = (SAM3_COMPONENT_DIR / "component" / "component_uart.h").exists()
has_k64f = K64F_HEADER.exists()


# ── SAM3 struct parsing ──────────────────────────────────────────────────────


@pytest.mark.skipif(not has_sam3, reason="SAM3 headers not available")
def test_sam3_uart_struct():
    """Parse SAM3 Uart struct from component_uart.h."""
    path = SAM3_COMPONENT_DIR / "component" / "component_uart.h"
    structs = parse_cmsis_header(str(path))
    assert "Uart" in structs
    uart = structs["Uart"]
    assert uart["UART_CR"] == 0x0000
    assert uart["UART_MR"] == 0x0004
    assert uart["UART_SR"] == 0x0014
    assert uart["UART_RHR"] == 0x0018
    assert uart["UART_THR"] == 0x001C


@pytest.mark.skipif(not has_sam3, reason="SAM3 headers not available")
def test_sam3_spi_struct():
    """Parse SAM3 Spi struct from component_spi.h."""
    path = SAM3_COMPONENT_DIR / "component" / "component_spi.h"
    structs = parse_cmsis_header(str(path))
    assert "Spi" in structs
    spi = structs["Spi"]
    assert spi["SPI_CR"] == 0x00
    assert spi["SPI_SR"] == 0x10


@pytest.mark.skipif(not has_sam3, reason="SAM3 headers not available")
def test_sam3_base_addresses():
    """Parse SAM3 base addresses from sam3x8e.h."""
    path = SAM3_COMPONENT_DIR / "sam3x8e.h"
    bases = parse_base_addresses(str(path))
    assert "UART" in bases
    typ, addr = bases["UART"]
    assert typ == "Uart"
    assert addr == 0x400E0800

    assert "PIOA" in bases
    typ, addr = bases["PIOA"]
    assert typ == "Pio"
    assert addr == 0x400E0E00


# ── K64F struct parsing ──────────────────────────────────────────────────────


@pytest.mark.skipif(not has_k64f, reason="K64F header not available")
def test_k64f_uart_struct():
    """Parse K64F UART_Type struct."""
    structs = parse_cmsis_header(str(K64F_HEADER))
    assert "UART_Type" in structs
    uart = structs["UART_Type"]
    assert uart["BDH"] == 0x0
    assert uart["BDL"] == 0x1
    assert uart["S1"] == 0x4
    assert uart["D"] == 0x7


@pytest.mark.skipif(not has_k64f, reason="K64F header not available")
def test_k64f_gpio_struct():
    """Parse K64F GPIO_Type struct."""
    structs = parse_cmsis_header(str(K64F_HEADER))
    assert "GPIO_Type" in structs
    gpio = structs["GPIO_Type"]
    assert "PDOR" in gpio
    assert "PDIR" in gpio


@pytest.mark.skipif(not has_k64f, reason="K64F header not available")
def test_k64f_base_addresses():
    """Parse K64F base addresses."""
    bases = parse_base_addresses(str(K64F_HEADER))
    assert "UART0" in bases
    typ, addr = bases["UART0"]
    assert typ == "UART_Type"
    assert addr == 0x4006A000

    assert "GPIOA" in bases
    typ, addr = bases["GPIOA"]
    assert typ == "GPIO_Type"


# ── Generated data sanity checks ───────────────────────────────────────────


def test_sam3_struct_offsets_nonempty():
    """SAM3_STRUCT_OFFSETS should have entries from cmsis_generated.py."""
    assert len(SAM3_STRUCT_OFFSETS) > 0
    assert "Uart" in SAM3_STRUCT_OFFSETS
    assert "Spi" in SAM3_STRUCT_OFFSETS


def test_k64f_struct_offsets_nonempty():
    """K64F_STRUCT_OFFSETS should have entries from cmsis_generated.py."""
    assert len(K64F_STRUCT_OFFSETS) > 0
    assert "UART_Type" in K64F_STRUCT_OFFSETS


def test_all_struct_offsets_merges_families():
    """ALL_STRUCT_OFFSETS should contain STM32 + SAM3 + K64F types."""
    # STM32
    assert "USART_TypeDef" in ALL_STRUCT_OFFSETS
    assert "GPIO_TypeDef" in ALL_STRUCT_OFFSETS
    # SAM3
    assert "Uart" in ALL_STRUCT_OFFSETS
    assert "Pio" in ALL_STRUCT_OFFSETS
    # K64F
    assert "UART_Type" in ALL_STRUCT_OFFSETS
    assert "GPIO_Type" in ALL_STRUCT_OFFSETS


def test_get_field_offset_sam3():
    """get_field_offset() should work for SAM3 types."""
    offset = get_field_offset("Uart", "UART_SR")
    assert offset is not None
    assert offset == 0x14


def test_get_field_offset_k64f():
    """get_field_offset() should work for K64F types."""
    offset = get_field_offset("UART_Type", "S1")
    assert offset is not None
    assert offset == 0x4


def test_get_field_offset_stm32_still_works():
    """get_field_offset() should still work for STM32 types (regression)."""
    offset = get_field_offset("USART_TypeDef", "SR")
    assert offset == 0x00
    offset = get_field_offset("USART_TypeDef", "DR")
    assert offset == 0x04
