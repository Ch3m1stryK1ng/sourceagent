"""Tests for typed MMIO struct field resolution (Patterns 10–11).

Validates extraction of typed MMIO base addresses from ``(TYPE_TypeDef *)0xHEX``
casts, struct field accesses (``handle->Instance->FIELD``), and the cross-function
resolution that combines them into concrete MMIO register addresses.
"""

import pytest

from sourceagent.pipeline.memory_access_index import (
    _extract_struct_field_accesses,
    _extract_typed_mmio_bases,
    _resolve_struct_accesses,
    parse_memory_accesses,
)
from sourceagent.pipeline.peripheral_types import (
    HANDLE_TO_PERIPHERAL,
    STM32_STRUCT_OFFSETS,
    _normalize_type_name,
    get_field_offset,
    get_register_address,
    resolve_handle_type,
)


# ── peripheral_types tests ────────────────────────────────────────────────


class TestPeripheralTypes:
    """Tests for peripheral_types.py helper functions."""

    def test_usart_field_offsets(self):
        assert get_field_offset("USART_TypeDef", "SR") == 0x00
        assert get_field_offset("USART_TypeDef", "DR") == 0x04
        assert get_field_offset("USART_TypeDef", "BRR") == 0x08
        assert get_field_offset("USART_TypeDef", "CR1") == 0x0C
        assert get_field_offset("USART_TypeDef", "CR2") == 0x10
        assert get_field_offset("USART_TypeDef", "CR3") == 0x14
        assert get_field_offset("USART_TypeDef", "GTPR") == 0x18

    def test_i2c_field_offsets(self):
        assert get_field_offset("I2C_TypeDef", "CR1") == 0x00
        assert get_field_offset("I2C_TypeDef", "DR") == 0x10
        assert get_field_offset("I2C_TypeDef", "SR1") == 0x14
        assert get_field_offset("I2C_TypeDef", "SR2") == 0x18

    def test_gpio_field_offsets(self):
        assert get_field_offset("GPIO_TypeDef", "CRL") == 0x00
        assert get_field_offset("GPIO_TypeDef", "IDR") == 0x08
        assert get_field_offset("GPIO_TypeDef", "ODR") == 0x0C
        assert get_field_offset("GPIO_TypeDef", "BSRR") == 0x10

    def test_unknown_type_returns_none(self):
        assert get_field_offset("UNKNOWN_TypeDef", "SR") is None

    def test_unknown_field_returns_none(self):
        assert get_field_offset("USART_TypeDef", "NONEXISTENT") is None

    def test_handle_to_peripheral_mapping(self):
        assert resolve_handle_type("UART_HandleTypeDef") == "USART_TypeDef"
        assert resolve_handle_type("USART_HandleTypeDef") == "USART_TypeDef"
        assert resolve_handle_type("I2C_HandleTypeDef") == "I2C_TypeDef"
        assert resolve_handle_type("SPI_HandleTypeDef") == "SPI_TypeDef"
        assert resolve_handle_type("TIM_HandleTypeDef") == "TIM_TypeDef"
        assert resolve_handle_type("DMA_HandleTypeDef") == "DMA_Channel_TypeDef"

    def test_unknown_handle_returns_none(self):
        assert resolve_handle_type("SomeRandomType") is None

    def test_get_register_address(self):
        # USART1 at 0x40013800, DR at offset 0x04
        assert get_register_address("USART_TypeDef", "DR", 0x40013800) == 0x40013804
        # I2C1 at 0x40005400, SR1 at offset 0x14
        assert get_register_address("I2C_TypeDef", "SR1", 0x40005400) == 0x40005414

    def test_get_register_address_unknown_field(self):
        assert get_register_address("USART_TypeDef", "NONEXISTENT", 0x40013800) is None


# ── _extract_typed_mmio_bases tests ───────────────────────────────────────


class TestExtractTypedMMIOBases:
    """Tests for Pattern 10: (TYPE_TypeDef *)0xHEX."""

    def test_usart_cast_in_comparison(self):
        code = """
void HAL_RCC_ClockConfig(void) {
  if (pUVar10 != (USART_TypeDef *)0x40013800) {
    do_something();
  }
}
"""
        bases = _extract_typed_mmio_bases(code, "HAL_RCC_ClockConfig")
        assert len(bases) == 1
        assert bases[0].peripheral_type == "USART_TypeDef"
        assert bases[0].base_addr == 0x40013800

    def test_multiple_casts_same_type(self):
        code = """
void uart_init(void) {
  if (pUVar1 == (USART_TypeDef *)0x40013800) { }
  else if (pUVar1 == (USART_TypeDef *)0x40004400) { }
  else if (pUVar1 == (USART_TypeDef *)0x40004800) { }
}
"""
        bases = _extract_typed_mmio_bases(code, "uart_init")
        assert len(bases) == 3
        addrs = {b.base_addr for b in bases}
        assert addrs == {0x40013800, 0x40004400, 0x40004800}

    def test_gpio_casts(self):
        code = """
void HAL_GPIO_Init(void) {
  if (GPIOx == (GPIO_TypeDef *)0x40010800) { }
  else if (GPIOx == (GPIO_TypeDef *)0x40011000) { }
}
"""
        bases = _extract_typed_mmio_bases(code, "HAL_GPIO_Init")
        assert len(bases) == 2
        assert all(b.peripheral_type == "GPIO_TypeDef" for b in bases)

    def test_dma_channel_casts(self):
        code = """
void DMA_Setup(void) {
  if (pDVar1 == (DMA_Channel_TypeDef *)0x40020008) { }
  else if (pDVar1 == (DMA_Channel_TypeDef *)0x4002001c) { }
}
"""
        bases = _extract_typed_mmio_bases(code, "DMA_Setup")
        assert len(bases) == 2

    def test_assignment_cast(self):
        code = """
void init(void) {
  pGVar1 = (GPIO_TypeDef *)0x40010800;
}
"""
        bases = _extract_typed_mmio_bases(code, "init")
        assert len(bases) == 1
        assert bases[0].base_addr == 0x40010800

    def test_null_pointer_skipped(self):
        code = """
void check(void) {
  if (huart == (UART_HandleTypeDef *)0x0) { return; }
}
"""
        bases = _extract_typed_mmio_bases(code, "check")
        # 0x0 is not in MMIO range, should be filtered
        assert len(bases) == 0

    def test_non_mmio_address_skipped(self):
        code = """
void check(void) {
  ptr = (USART_TypeDef *)0x20000100;
}
"""
        bases = _extract_typed_mmio_bases(code, "check")
        # SRAM address, not MMIO
        assert len(bases) == 0

    def test_dedup_same_type_and_address(self):
        code = """
void func(void) {
  if (x == (USART_TypeDef *)0x40013800) { }
  if (y != (USART_TypeDef *)0x40013800) { }
}
"""
        bases = _extract_typed_mmio_bases(code, "func")
        assert len(bases) == 1


# ── _extract_struct_field_accesses tests ──────────────────────────────────


class TestExtractStructFieldAccesses:
    """Tests for Pattern 11: handle->Instance->FIELD and periph_ptr->FIELD."""

    def test_uart_instance_field_access(self):
        code = """
HAL_StatusTypeDef UART_Transmit_IT(UART_HandleTypeDef *huart) {
  huart->Instance->DR = (uint)*pbVar2;
}
"""
        accesses = _extract_struct_field_accesses(code, "UART_Transmit_IT", 0x08001000)
        assert len(accesses) >= 1
        dr_accesses = [a for a in accesses if a.field_name == "DR"]
        assert len(dr_accesses) == 1
        assert dr_accesses[0].peripheral_type == "USART_TypeDef"
        assert dr_accesses[0].kind == "store"

    def test_uart_instance_field_load(self):
        code = """
HAL_StatusTypeDef UART_Receive_IT(UART_HandleTypeDef *huart) {
  *puVar3 = (uint8_t)huart->Instance->DR;
}
"""
        accesses = _extract_struct_field_accesses(code, "UART_Receive_IT", 0x08001000)
        dr_accesses = [a for a in accesses if a.field_name == "DR"]
        assert len(dr_accesses) == 1
        assert dr_accesses[0].kind == "load"

    def test_i2c_instance_multiple_fields(self):
        code = """
HAL_StatusTypeDef I2C_Master_ADDR(I2C_HandleTypeDef *hi2c) {
  hi2c->Instance->CR1 = hi2c->Instance->CR1 | 0x100;
  hi2c->Instance->DR = hi2c->Devaddress & 0xff;
}
"""
        accesses = _extract_struct_field_accesses(code, "I2C_Master_ADDR", 0x08001000)
        field_names = {a.field_name for a in accesses}
        assert "CR1" in field_names
        assert "DR" in field_names

    def test_read_modify_write_produces_both(self):
        code = """
void UART_SetConfig(UART_HandleTypeDef *huart) {
  huart->Instance->CR1 = huart->Instance->CR1 | 0x2000;
}
"""
        accesses = _extract_struct_field_accesses(code, "UART_SetConfig", 0x08001000)
        cr1_accesses = [a for a in accesses if a.field_name == "CR1"]
        kinds = {a.kind for a in cr1_accesses}
        # RHS is a load, LHS is a store
        assert "load" in kinds or "store" in kinds

    def test_direct_peripheral_param_access(self):
        """Test direct access via GPIO_TypeDef *GPIOx parameter."""
        code = """
void HAL_GPIO_Init(GPIO_TypeDef *GPIOx, uint32_t mode) {
  GPIOx->CRL = mode;
  uint32_t val = GPIOx->IDR;
}
"""
        accesses = _extract_struct_field_accesses(code, "HAL_GPIO_Init", 0x08001000)
        field_names = {a.field_name for a in accesses}
        assert "CRL" in field_names
        assert "IDR" in field_names
        # Verify types
        for a in accesses:
            assert a.peripheral_type == "GPIO_TypeDef"

    def test_local_peripheral_var_declaration(self):
        """Test access via locally declared I2C_TypeDef *pIVar2."""
        code = """
void I2C_Master_ADDR(I2C_HandleTypeDef *hi2c) {
  I2C_TypeDef *pIVar2;
  pIVar2 = hi2c->Instance;
  pIVar2->CR1 = pIVar2->CR1 | 0x200;
  pIVar2->CR2 = pIVar2->CR2 | 0x1000;
}
"""
        accesses = _extract_struct_field_accesses(code, "I2C_Master_ADDR", 0x08001000)
        # Should detect CR1 and CR2 accesses through pIVar2
        field_names = {a.field_name for a in accesses}
        assert "CR1" in field_names
        assert "CR2" in field_names
        for a in accesses:
            if a.field_name in ("CR1", "CR2"):
                assert a.peripheral_type == "I2C_TypeDef"

    def test_unknown_handle_type_ignored(self):
        code = """
void do_something(SomeRandomType *ptr) {
  ptr->Instance->FIELD = 42;
}
"""
        accesses = _extract_struct_field_accesses(code, "do_something", 0x08001000)
        assert len(accesses) == 0

    def test_non_peripheral_field_ignored(self):
        """Fields not in the struct offset table should be ignored."""
        code = """
void func(UART_HandleTypeDef *huart) {
  huart->Instance->NONEXISTENT_FIELD = 42;
}
"""
        accesses = _extract_struct_field_accesses(code, "func", 0x08001000)
        assert len(accesses) == 0

    def test_handle_struct_fields_not_treated_as_peripheral(self):
        """Accesses to handle fields (not Instance->FIELD) should be ignored."""
        code = """
void func(UART_HandleTypeDef *huart) {
  huart->ErrorCode = 0;
  huart->State = HAL_UART_STATE_READY;
}
"""
        accesses = _extract_struct_field_accesses(code, "func", 0x08001000)
        # ErrorCode and State are handle struct fields, not peripheral registers
        assert len(accesses) == 0


# ── _resolve_struct_accesses tests ─────────────────────────────────────────


class TestResolveStructAccesses:
    """Tests for cross-function resolution."""

    def _make_base(self, periph_type, addr, func="init"):
        from sourceagent.pipeline.memory_access_index import _TypedMMIOBase
        return _TypedMMIOBase(periph_type, addr, func)

    def _make_field(self, periph_type, field, kind="load", func="read", addr=0x08001000):
        from sourceagent.pipeline.memory_access_index import _StructFieldAccess
        return _StructFieldAccess(periph_type, field, kind, func, addr)

    def test_single_base_single_field(self):
        bases = [self._make_base("USART_TypeDef", 0x40013800)]
        fields = [self._make_field("USART_TypeDef", "DR")]

        resolved = _resolve_struct_accesses(bases, fields)
        assert len(resolved) == 1
        assert resolved[0].target_addr == 0x40013800 + 0x04  # DR offset
        assert resolved[0].base_provenance == "STRUCT_RESOLVED"
        assert resolved[0].kind == "load"

    def test_multiple_bases_single_field(self):
        """When 3 USART instances exist, each field access generates 3 entries."""
        bases = [
            self._make_base("USART_TypeDef", 0x40013800),  # USART1
            self._make_base("USART_TypeDef", 0x40004400),  # USART2
            self._make_base("USART_TypeDef", 0x40004800),  # USART3
        ]
        fields = [self._make_field("USART_TypeDef", "SR")]

        resolved = _resolve_struct_accesses(bases, fields)
        assert len(resolved) == 3
        target_addrs = {r.target_addr for r in resolved}
        # SR offset is 0x00
        assert target_addrs == {0x40013800, 0x40004400, 0x40004800}

    def test_multiple_fields_single_base(self):
        bases = [self._make_base("I2C_TypeDef", 0x40005400)]
        fields = [
            self._make_field("I2C_TypeDef", "CR1", kind="store"),
            self._make_field("I2C_TypeDef", "DR", kind="load"),
            self._make_field("I2C_TypeDef", "SR1", kind="load"),
        ]

        resolved = _resolve_struct_accesses(bases, fields)
        assert len(resolved) == 3
        targets = {r.target_addr for r in resolved}
        assert targets == {
            0x40005400 + 0x00,  # CR1
            0x40005400 + 0x10,  # DR
            0x40005400 + 0x14,  # SR1
        }

    def test_no_matching_bases_produces_nothing(self):
        bases = [self._make_base("GPIO_TypeDef", 0x40010800)]
        fields = [self._make_field("USART_TypeDef", "DR")]  # Different type

        resolved = _resolve_struct_accesses(bases, fields)
        assert len(resolved) == 0

    def test_empty_bases_produces_nothing(self):
        fields = [self._make_field("USART_TypeDef", "DR")]
        resolved = _resolve_struct_accesses([], fields)
        assert len(resolved) == 0

    def test_empty_fields_produces_nothing(self):
        bases = [self._make_base("USART_TypeDef", 0x40013800)]
        resolved = _resolve_struct_accesses(bases, [])
        assert len(resolved) == 0

    def test_resolved_access_preserves_metadata(self):
        bases = [self._make_base("USART_TypeDef", 0x40013800)]
        field = self._make_field("USART_TypeDef", "CR1", kind="store",
                                 func="UART_SetConfig", addr=0x08002000)
        field.in_isr = True

        resolved = _resolve_struct_accesses(bases, [field])
        assert len(resolved) == 1
        r = resolved[0]
        assert r.function_name == "UART_SetConfig"
        assert r.function_addr == 0x08002000
        assert r.in_isr is True
        assert r.kind == "store"
        assert r.width == 4

    def test_mixed_types_resolved_correctly(self):
        bases = [
            self._make_base("USART_TypeDef", 0x40013800),
            self._make_base("I2C_TypeDef", 0x40005400),
        ]
        fields = [
            self._make_field("USART_TypeDef", "DR"),
            self._make_field("I2C_TypeDef", "DR"),
        ]

        resolved = _resolve_struct_accesses(bases, fields)
        assert len(resolved) == 2
        targets = {r.target_addr for r in resolved}
        assert targets == {
            0x40013800 + 0x04,  # USART DR at offset 0x04
            0x40005400 + 0x10,  # I2C DR at offset 0x10
        }


# ── Integration test: full decompiled function snippet ────────────────────


class TestIntegrationRealisticCode:
    """Test with realistic Ghidra decompiled output."""

    UART_IRQ_CODE = """\
void HAL_UART_IRQHandler(UART_HandleTypeDef *huart)
{
  uint32_t isrflags;
  uint32_t cr1its;
  uint32_t cr3its;

  isrflags = huart->Instance->SR;
  cr1its = huart->Instance->CR1;
  cr3its = huart->Instance->CR3;

  if (((isrflags & 0x20) != 0) && ((cr1its & 0x20) != 0)) {
    UART_Receive_IT(huart);
  }
  if (((isrflags & 0x80) != 0) && ((cr1its & 0x80) != 0)) {
    huart->Instance->DR = (uint)*pbVar1;
  }
}
"""

    UART_INIT_CODE = """\
void HAL_UART_MspInit(UART_HandleTypeDef *huart)
{
  if (huart->Instance == (USART_TypeDef *)0x40013800) {
    __HAL_RCC_USART1_CLK_ENABLE();
  }
  else if (huart->Instance == (USART_TypeDef *)0x40004400) {
    __HAL_RCC_USART2_CLK_ENABLE();
  }
}
"""

    def test_full_resolution_pipeline(self):
        """End-to-end: extract bases from init, fields from IRQ, resolve."""
        # Extract typed bases from init function
        bases = _extract_typed_mmio_bases(self.UART_INIT_CODE, "HAL_UART_MspInit")
        assert len(bases) == 2
        assert {b.base_addr for b in bases} == {0x40013800, 0x40004400}

        # Extract field accesses from IRQ handler
        fields = _extract_struct_field_accesses(
            self.UART_IRQ_CODE, "HAL_UART_IRQHandler", 0x08003000,
        )
        field_names = {f.field_name for f in fields}
        assert "SR" in field_names
        assert "CR1" in field_names
        assert "CR3" in field_names
        assert "DR" in field_names

        # Cross-function resolution
        resolved = _resolve_struct_accesses(bases, fields)
        # Each field × each base = multiple resolved accesses
        assert len(resolved) > 0

        target_addrs = {r.target_addr for r in resolved}
        # USART1 registers
        assert 0x40013800 + 0x00 in target_addrs  # SR
        assert 0x40013800 + 0x04 in target_addrs  # DR
        assert 0x40013800 + 0x0C in target_addrs  # CR1
        assert 0x40013800 + 0x14 in target_addrs  # CR3
        # USART2 registers
        assert 0x40004400 + 0x00 in target_addrs  # SR
        assert 0x40004400 + 0x04 in target_addrs  # DR
        assert 0x40004400 + 0x0C in target_addrs  # CR1
        assert 0x40004400 + 0x14 in target_addrs  # CR3

        # Verify provenance
        for r in resolved:
            assert r.base_provenance == "STRUCT_RESOLVED"

    def test_i2c_with_local_var(self):
        """I2C code uses local variable alias: pIVar2 = hi2c->Instance."""
        code = """\
HAL_StatusTypeDef I2C_Master_ADDR(I2C_HandleTypeDef *hi2c)
{
  I2C_TypeDef *pIVar2;

  hi2c->Instance->CR1 = hi2c->Instance->CR1 | 0x200;
  pIVar2 = hi2c->Instance;
  if ((pIVar2->CR2 & 0x800) == 0) {
    pIVar2->CR1 = pIVar2->CR1 | 0x200;
  }
}
"""
        fields = _extract_struct_field_accesses(code, "I2C_Master_ADDR", 0x08002000)
        field_names = {f.field_name for f in fields}
        # Should detect CR1, CR2 from both handle->Instance-> and pIVar2->
        assert "CR1" in field_names
        assert "CR2" in field_names

        # Resolve with a known I2C base
        from sourceagent.pipeline.memory_access_index import _TypedMMIOBase
        bases = [_TypedMMIOBase("I2C_TypeDef", 0x40005400, "init")]

        resolved = _resolve_struct_accesses(bases, fields)
        targets = {r.target_addr for r in resolved}
        assert 0x40005400 + 0x00 in targets  # CR1
        assert 0x40005400 + 0x04 in targets  # CR2


# ── Regression: existing parse_memory_accesses patterns unaffected ────────


class TestExistingPatternsUnaffected:
    """Ensure the new patterns don't break existing pattern matching."""

    def test_const_deref_still_works(self):
        code = "  *(volatile uint *)0x40021014 = val;"
        accesses = parse_memory_accesses(code, "func", 0x08001000)
        const_accesses = [a for a in accesses if a.base_provenance == "CONST"]
        assert len(const_accesses) >= 1
        assert any(a.target_addr == 0x40021014 for a in const_accesses)

    def test_dat_deref_still_works(self):
        code = "  val = *(uint *)DAT_40021014;"
        accesses = parse_memory_accesses(code, "func", 0x08001000)
        assert any(a.target_addr == 0x40021014 for a in accesses)

    def test_arg_deref_still_works(self):
        code = "  *(int *)param_1 = 42;"
        accesses = parse_memory_accesses(code, "func", 0x08001000)
        arg_accesses = [a for a in accesses if a.base_provenance == "ARG"]
        assert len(arg_accesses) >= 1


# ── Ghidra _conflict suffix handling ────────────────────────────────────


class TestGhidraConflictSuffix:
    """Tests for Ghidra _conflict suffix normalization.

    Ghidra appends _conflict, _conflict1, etc. to type names when multiple
    data type archives define the same name.  E.g. I2C_TypeDef_conflict.
    """

    def test_normalize_strips_conflict(self):
        assert _normalize_type_name("I2C_TypeDef_conflict") == "I2C_TypeDef"
        assert _normalize_type_name("I2C_HandleTypeDef_conflict") == "I2C_HandleTypeDef"

    def test_normalize_strips_numbered_conflict(self):
        assert _normalize_type_name("SPI_TypeDef_conflict1") == "SPI_TypeDef"
        assert _normalize_type_name("SPI_TypeDef_conflict23") == "SPI_TypeDef"

    def test_normalize_preserves_clean_name(self):
        assert _normalize_type_name("USART_TypeDef") == "USART_TypeDef"
        assert _normalize_type_name("GPIO_TypeDef") == "GPIO_TypeDef"

    def test_get_field_offset_with_conflict(self):
        """get_field_offset should work with _conflict suffix."""
        assert get_field_offset("I2C_TypeDef_conflict", "CR1") == 0x00
        assert get_field_offset("I2C_TypeDef_conflict", "DR") == 0x10
        assert get_field_offset("I2C_TypeDef_conflict", "SR1") == 0x14

    def test_resolve_handle_type_with_conflict(self):
        """resolve_handle_type should work with _conflict suffix."""
        assert resolve_handle_type("I2C_HandleTypeDef_conflict") == "I2C_TypeDef"
        assert resolve_handle_type("UART_HandleTypeDef_conflict") == "USART_TypeDef"

    def test_get_register_address_with_conflict(self):
        """get_register_address should work with _conflict suffix."""
        assert get_register_address("I2C_TypeDef_conflict", "SR1", 0x40005400) == 0x40005414

    def test_typed_cast_with_conflict_suffix(self):
        """Pattern 10 regex should match I2C_TypeDef_conflict."""
        code = """
void HAL_I2C_Init(I2C_HandleTypeDef_conflict *hi2c) {
  if (pIVar1 == (I2C_TypeDef_conflict *)0x40005400) {
    do_something();
  }
}
"""
        bases = _extract_typed_mmio_bases(code, "HAL_I2C_Init")
        assert len(bases) == 1
        # Type name should be normalized
        assert bases[0].peripheral_type == "I2C_TypeDef"
        assert bases[0].base_addr == 0x40005400

    def test_local_decl_with_conflict_suffix(self):
        """Local variable declaration with _conflict suffix."""
        code = """
void I2C_Transfer(I2C_HandleTypeDef_conflict *hi2c) {
  I2C_TypeDef_conflict *pIVar2;
  pIVar2 = hi2c->Instance;
  pIVar2->CR1 = pIVar2->CR1 | 0x200;
  pIVar2->DR = 0x50;
}
"""
        accesses = _extract_struct_field_accesses(code, "I2C_Transfer", 0x08001000)
        field_names = {a.field_name for a in accesses}
        assert "CR1" in field_names
        assert "DR" in field_names
        # Peripheral type should be normalized in the accesses
        for a in accesses:
            if a.field_name in ("CR1", "DR"):
                assert a.peripheral_type == "I2C_TypeDef"

    def test_handle_param_with_conflict_suffix(self):
        """Handle parameter with _conflict suffix for Instance-> access."""
        code = """
HAL_StatusTypeDef_conflict I2C_Master_SB(I2C_HandleTypeDef_conflict *hi2c) {
  hi2c->Instance->DR = hi2c->Devaddress & 0xff;
  uint32_t sr1 = hi2c->Instance->SR1;
}
"""
        accesses = _extract_struct_field_accesses(code, "I2C_Master_SB", 0x08001000)
        field_names = {a.field_name for a in accesses}
        assert "DR" in field_names
        assert "SR1" in field_names

    def test_full_pipeline_with_conflict_suffix(self):
        """End-to-end: typed casts with _conflict, field accesses, and resolution."""
        init_code = """
void HAL_I2C_MspInit(I2C_HandleTypeDef_conflict *hi2c) {
  if (hi2c->Instance == (I2C_TypeDef_conflict *)0x40005400) {
    __HAL_RCC_I2C1_CLK_ENABLE();
  }
}
"""
        io_code = """
HAL_StatusTypeDef_conflict I2C_SendData(I2C_HandleTypeDef_conflict *hi2c) {
  hi2c->Instance->DR = hi2c->Devaddress & 0xff;
  uint32_t sr = hi2c->Instance->SR1;
  hi2c->Instance->CR1 = hi2c->Instance->CR1 | 0x200;
}
"""
        bases = _extract_typed_mmio_bases(init_code, "HAL_I2C_MspInit")
        assert len(bases) == 1
        assert bases[0].peripheral_type == "I2C_TypeDef"
        assert bases[0].base_addr == 0x40005400

        fields = _extract_struct_field_accesses(io_code, "I2C_SendData", 0x08002000)
        assert len(fields) > 0

        resolved = _resolve_struct_accesses(bases, fields)
        assert len(resolved) > 0

        targets = {r.target_addr for r in resolved}
        assert 0x40005400 + 0x00 in targets  # CR1
        assert 0x40005400 + 0x10 in targets  # DR
        assert 0x40005400 + 0x14 in targets  # SR1

        for r in resolved:
            assert r.base_provenance == "STRUCT_RESOLVED"
