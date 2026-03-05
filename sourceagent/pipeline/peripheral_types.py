"""Multi-MCU peripheral struct field offsets for type-recovered MMIO resolution.

When Ghidra performs type recovery on firmware, it produces struct field access
syntax (``huart->Instance->CR1``) instead of raw pointer arithmetic
(``*(*(param_1 + 0) + 0xc)``).  This module provides the mapping from struct
field names to byte offsets so that the MAI builder can resolve these accesses
to concrete MMIO register addresses.

Supports:
  - STM32F103: field offsets from stm32f103xb.h (manually defined)
  - SAM3X8E: field offsets from Atmel SAM3X component headers (auto-generated)
  - K64F: field offsets from NXP MK64F12.h (auto-generated)
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

# ── Peripheral struct field → byte-offset tables ─────────────────────────

# Each dict maps field_name → byte_offset within the peripheral register block.
# Offsets verified against firmware/p2im-real_firmware/Drone/Drivers/CMSIS/
# Device/ST/STM32F1xx/Include/stm32f103xb.h.

STM32_STRUCT_OFFSETS: Dict[str, Dict[str, int]] = {
    "USART_TypeDef": {
        "SR": 0x00, "DR": 0x04, "BRR": 0x08,
        "CR1": 0x0C, "CR2": 0x10, "CR3": 0x14, "GTPR": 0x18,
    },
    "I2C_TypeDef": {
        "CR1": 0x00, "CR2": 0x04, "OAR1": 0x08, "OAR2": 0x0C,
        "DR": 0x10, "SR1": 0x14, "SR2": 0x18, "CCR": 0x1C, "TRISE": 0x20,
    },
    "SPI_TypeDef": {
        "CR1": 0x00, "CR2": 0x04, "SR": 0x08, "DR": 0x0C,
        "CRCPR": 0x10, "RXCRCR": 0x14, "TXCRCR": 0x18,
        "I2SCFGR": 0x1C, "I2SPR": 0x20,
    },
    "GPIO_TypeDef": {
        "CRL": 0x00, "CRH": 0x04, "IDR": 0x08, "ODR": 0x0C,
        "BSRR": 0x10, "BRR": 0x14, "LCKR": 0x18,
    },
    "TIM_TypeDef": {
        "CR1": 0x00, "CR2": 0x04, "SMCR": 0x08, "DIER": 0x0C,
        "SR": 0x10, "EGR": 0x14, "CCMR1": 0x18, "CCMR2": 0x1C,
        "CCER": 0x20, "CNT": 0x24, "PSC": 0x28, "ARR": 0x2C,
        "RCR": 0x30, "CCR1": 0x34, "CCR2": 0x38, "CCR3": 0x3C,
        "CCR4": 0x40, "BDTR": 0x44, "DCR": 0x48, "DMAR": 0x4C,
    },
    "DMA_Channel_TypeDef": {
        "CCR": 0x00, "CNDTR": 0x04, "CPAR": 0x08, "CMAR": 0x0C,
    },
    "DMA_TypeDef": {
        "ISR": 0x00, "IFCR": 0x04,
    },
    "RCC_TypeDef": {
        "CR": 0x00, "CFGR": 0x04, "CIR": 0x08,
        "APB2RSTR": 0x0C, "APB1RSTR": 0x10,
        "AHBENR": 0x14, "APB2ENR": 0x18, "APB1ENR": 0x1C,
        "BDCR": 0x20, "CSR": 0x24,
    },
    "ADC_TypeDef": {
        "SR": 0x00, "CR1": 0x04, "CR2": 0x08,
        "SMPR1": 0x0C, "SMPR2": 0x10,
        "JOFR1": 0x14, "JOFR2": 0x18, "JOFR3": 0x1C, "JOFR4": 0x20,
        "HTR": 0x24, "LTR": 0x28,
        "SQR1": 0x2C, "SQR2": 0x30, "SQR3": 0x34,
        "JSQR": 0x38,
        "JDR1": 0x3C, "JDR2": 0x40, "JDR3": 0x44, "JDR4": 0x48,
        "DR": 0x4C,
    },
    "EXTI_TypeDef": {
        "IMR": 0x00, "EMR": 0x04, "RTSR": 0x08, "FTSR": 0x0C,
        "SWIER": 0x10, "PR": 0x14,
    },
    "IWDG_TypeDef": {
        "KR": 0x00, "PR": 0x04, "RLR": 0x08, "SR": 0x0C,
    },
    "WWDG_TypeDef": {
        "CR": 0x00, "CFR": 0x04, "SR": 0x08,
    },
    "PWR_TypeDef": {
        "CR": 0x00, "CSR": 0x04,
    },
    "RTC_TypeDef": {
        "CRH": 0x00, "CRL": 0x04,
        "PRLH": 0x08, "PRLL": 0x0C,
        "DIVH": 0x10, "DIVL": 0x14,
        "CNTH": 0x18, "CNTL": 0x1C,
        "ALRH": 0x20, "ALRL": 0x24,
    },
    "FLASH_TypeDef": {
        "ACR": 0x00, "KEYR": 0x04, "OPTKEYR": 0x08,
        "SR": 0x0C, "CR": 0x10, "AR": 0x14,
        "OBR": 0x1C, "WRPR": 0x20,
    },
    "AFIO_TypeDef": {
        "EVCR": 0x00, "MAPR": 0x04,
        "EXTICR1": 0x08, "EXTICR2": 0x0C,
        "EXTICR3": 0x10, "EXTICR4": 0x14,
        "MAPR2": 0x1C,
    },
}

# ── HAL handle typedef → peripheral typedef mapping ──────────────────────

# STM32 HAL uses handle structs (e.g. UART_HandleTypeDef) whose first field
# ``Instance`` points to the peripheral register block typedef.

HANDLE_TO_PERIPHERAL: Dict[str, str] = {
    "UART_HandleTypeDef": "USART_TypeDef",
    "USART_HandleTypeDef": "USART_TypeDef",
    "I2C_HandleTypeDef": "I2C_TypeDef",
    "SPI_HandleTypeDef": "SPI_TypeDef",
    "TIM_HandleTypeDef": "TIM_TypeDef",
    "DMA_HandleTypeDef": "DMA_Channel_TypeDef",
    "ADC_HandleTypeDef": "ADC_TypeDef",
    "RTC_HandleTypeDef": "RTC_TypeDef",
    "IWDG_HandleTypeDef": "IWDG_TypeDef",
    "WWDG_HandleTypeDef": "WWDG_TypeDef",
    "PCD_HandleTypeDef": "USB_TypeDef",
    "CAN_HandleTypeDef": "CAN_TypeDef",
}


def _normalize_type_name(name: str) -> str:
    """Strip Ghidra-generated suffixes from type names.

    Ghidra appends ``_conflict``, ``_conflict1``, etc. when multiple data type
    archives define the same name.  E.g. ``I2C_TypeDef_conflict`` →
    ``I2C_TypeDef``, ``I2C_HandleTypeDef_conflict`` → ``I2C_HandleTypeDef``.
    """
    import re
    return re.sub(r"_conflict\d*$", "", name)


def get_field_offset(
    peripheral_type: str,
    field_name: str,
) -> Optional[int]:
    """Look up byte offset for a struct field in a peripheral type.

    Automatically normalizes Ghidra ``_conflict`` suffixes.
    Searches ALL_STRUCT_OFFSETS (STM32 + SAM3 + K64F).
    Returns None if the type or field is unknown.
    """
    normalized = _normalize_type_name(peripheral_type)
    fields = ALL_STRUCT_OFFSETS.get(normalized)
    if fields is None:
        return None
    return fields.get(field_name)


def resolve_handle_type(handle_type: str) -> Optional[str]:
    """Map a HAL handle typedef to its peripheral typedef.

    E.g. ``UART_HandleTypeDef`` → ``USART_TypeDef``.
    Automatically normalizes Ghidra ``_conflict`` suffixes.
    Returns None if the handle type is not recognized.
    """
    return HANDLE_TO_PERIPHERAL.get(_normalize_type_name(handle_type))


def get_field_name(peripheral_type: str, offset: int) -> Optional[str]:
    """Reverse lookup: (type, offset) -> field name.

    Returns the first field name matching the given byte offset within the
    peripheral register block, or None if no match.
    """
    normalized = _normalize_type_name(peripheral_type)
    fields = ALL_STRUCT_OFFSETS.get(normalized)
    if not fields:
        return None
    for name, off in fields.items():
        if off == offset:
            return name
    return None


# ── Register classification ───────────────────────────────────────────────

_STATUS_PATTERNS = {"SR", "ISR", "CSR", "IMR", "EMR", "FLAG", "STATUS"}
_CONTROL_PATTERNS = {
    "CR", "CR1", "CR2", "CR3", "CCR", "CTRL", "CFR",
    "SMCR", "DIER", "EGR", "CCER", "BDTR", "DCR",
    "CCMR1", "CCMR2", "BRR", "GTPR", "TRISE",
    "KR", "PR", "RLR",  # IWDG
    "PRLH", "PRLL", "CRH", "CRL",  # RTC
    "ACR", "KEYR", "OPTKEYR", "AR", "WRPR",  # FLASH
    "EVCR", "MAPR", "MAPR2",  # AFIO
    "EXTICR1", "EXTICR2", "EXTICR3", "EXTICR4",
}
_DATA_PATTERNS = {
    "DR", "DATA", "RHR", "THR", "RXDATA", "TXDATA",
    "JDR1", "JDR2", "JDR3", "JDR4", "DMAR",
    "BDH", "BDL", "D", "S1", "S2",  # K64F UART data
}


def classify_register(field_name: str) -> str:
    """Classify a register field name as STATUS, CONTROL, DATA, or UNKNOWN."""
    if field_name in _STATUS_PATTERNS:
        return "STATUS"
    if field_name in _CONTROL_PATTERNS:
        return "CONTROL"
    if field_name in _DATA_PATTERNS:
        return "DATA"
    return "UNKNOWN"


def get_register_address(
    peripheral_type: str,
    field_name: str,
    base_addr: int,
) -> Optional[int]:
    """Compute concrete MMIO register address from type, field, and base.

    Returns ``base_addr + field_offset`` or None if field is unknown.
    """
    offset = get_field_offset(peripheral_type, field_name)
    if offset is None:
        return None
    return base_addr + offset


# ── Unified multi-MCU struct offset table ──────────────────────────────────

try:
    from .cmsis_generated import (
        SAM3_STRUCT_OFFSETS,
        SAM3_BASE_ADDRESSES,
        K64F_STRUCT_OFFSETS,
        K64F_BASE_ADDRESSES,
    )
except ImportError:
    SAM3_STRUCT_OFFSETS: Dict[str, Dict[str, int]] = {}
    SAM3_BASE_ADDRESSES: Dict[str, tuple] = {}
    K64F_STRUCT_OFFSETS: Dict[str, Dict[str, int]] = {}
    K64F_BASE_ADDRESSES: Dict[str, tuple] = {}

# Merge all MCU families into a single lookup table.
# STM32 takes priority if there's a name collision (unlikely across families).
ALL_STRUCT_OFFSETS: Dict[str, Dict[str, int]] = {}
ALL_STRUCT_OFFSETS.update(SAM3_STRUCT_OFFSETS)
ALL_STRUCT_OFFSETS.update(K64F_STRUCT_OFFSETS)
ALL_STRUCT_OFFSETS.update(STM32_STRUCT_OFFSETS)

# Merge all base addresses
ALL_BASE_ADDRESSES: Dict[str, tuple] = {}
ALL_BASE_ADDRESSES.update(SAM3_BASE_ADDRESSES)
ALL_BASE_ADDRESSES.update(K64F_BASE_ADDRESSES)
