"""Shared pytest fixtures for SourceAgent tests."""

import os
from pathlib import Path

import pytest

# Firmware sample directory
FIRMWARE_DIR = Path(__file__).parent.parent / "firmware"


@pytest.fixture
def firmware_dir():
    """Path to the firmware samples directory."""
    return FIRMWARE_DIR


@pytest.fixture
def nxp_uart_path(firmware_dir):
    """Path to nxp_uart_polling.bin (smallest sample, 4.4K)."""
    p = firmware_dir / "nxp_uart_polling.bin"
    if not p.exists():
        pytest.skip("nxp_uart_polling.bin not found in firmware/")
    return p


@pytest.fixture
def blink_led_path(firmware_dir):
    """Path to blink_led.bin."""
    p = firmware_dir / "blink_led.bin"
    if not p.exists():
        pytest.skip("blink_led.bin not found in firmware/")
    return p


@pytest.fixture
def thermostat_path(firmware_dir):
    """Path to thermostat.bin."""
    p = firmware_dir / "thermostat.bin"
    if not p.exists():
        pytest.skip("thermostat.bin not found in firmware/")
    return p
