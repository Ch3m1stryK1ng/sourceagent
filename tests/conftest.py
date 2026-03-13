"""Shared pytest fixtures for SourceAgent tests."""

from pathlib import Path

import pytest

# Firmware directories
FIRMWARE_ROOT = Path(__file__).parent.parent / "firmware"
FIRMWARE_DEMO_DIR = FIRMWARE_ROOT / "demo"


def _resolve_demo_sample(name: str) -> Path:
    """Resolve a small checked-in firmware sample from legacy or demo paths."""
    candidates = [
        FIRMWARE_ROOT / name,
        FIRMWARE_DEMO_DIR / name,
    ]
    for path in candidates:
        if path.exists():
            return path
    pytest.skip(f"{name} not found in firmware/ or firmware/demo/")


@pytest.fixture
def firmware_dir():
    """Primary quick-start firmware directory used by path-based smoke tests."""
    if FIRMWARE_DEMO_DIR.exists():
        return FIRMWARE_DEMO_DIR
    return FIRMWARE_ROOT


@pytest.fixture
def firmware_root():
    """Path to the firmware root directory."""
    return FIRMWARE_ROOT


@pytest.fixture
def nxp_uart_path():
    """Path to nxp_uart_polling.bin (smallest sample, 4.4K)."""
    return _resolve_demo_sample("nxp_uart_polling.bin")


@pytest.fixture
def blink_led_path():
    """Path to blink_led.bin."""
    return _resolve_demo_sample("blink_led.bin")


@pytest.fixture
def thermostat_path():
    """Path to thermostat.bin."""
    return _resolve_demo_sample("thermostat.bin")
