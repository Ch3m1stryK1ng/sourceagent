"""Real firmware integration test — P2IM Controllino (STM32F0 Modbus).

Runs the source/sink mining pipeline on:
  - p2im_controllino.elf  (not stripped, debug symbols, ground truth)
  - p2im_controllino.bin  (raw binary, no symbols)

Compares Stage 1 (loader) outputs offline, then runs full Stages 1-7
through Ghidra MCP for MMIO_READ/ISR source detection.

Ground truth is derived from the ELF symbol table:
  - STM32F0 peripheral base addresses: USART (0x40004400-0x40013800),
    I2C (0x40005400-0x40005800), TIM (0x40000000-0x40012C00)
  - ISR handlers: USART1_IRQHandler, HAL_UART_IRQHandler, I2C1_IRQHandler,
    SysTick_Handler, TIM* handlers, EXTI* handlers
  - Known copy functions: memcpy (0x080035a9)
"""

import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path

import pytest

# ── Ground truth from ELF symbols ────────────────────────────────────────

# ISR handler addresses (from vector table, Thumb bit cleared)
GROUND_TRUTH_ISR_ADDRS = {
    0x08002C12,  # SysTick_Handler
    0x08002C5C,  # EXTI0_1_IRQHandler
    0x08002C6C,  # EXTI2_3_IRQHandler
    0x08002C7C,  # EXTI4_15_IRQHandler
    0x08002EF4,  # RTC_IRQHandler
    0x08000D04,  # TIM1_BRK_UP_TRG_COM_IRQHandler
    0x08000D1C,  # TIM1_CC_IRQHandler
    0x08000D24,  # TIM2_IRQHandler
    0x08000D3C,  # TIM3_IRQHandler
    0x08000D54,  # TIM6_DAC_IRQHandler
    0x08000D6C,  # TIM7_IRQHandler
    0x08000D84,  # TIM14_IRQHandler
    0x08000D9C,  # TIM15_IRQHandler
    0x08000DB4,  # TIM16_IRQHandler
    0x08000DCC,  # TIM17_IRQHandler
    0x08003198,  # I2C1_IRQHandler
    0x080031B0,  # I2C2_IRQHandler
    0x080034F4,  # USART1_IRQHandler
    0x0800350C,  # USART2_IRQHandler
    0x08003524,  # USART3_4_IRQHandler
    0x08002F54,  # Default_Handler (weak — covers many unused IRQs)
}

# ISR handler function names (from ELF symbol table)
GROUND_TRUTH_ISR_NAMES = {
    "SysTick_Handler",
    "EXTI0_1_IRQHandler",
    "EXTI2_3_IRQHandler",
    "EXTI4_15_IRQHandler",
    "RTC_IRQHandler",
    "TIM1_BRK_UP_TRG_COM_IRQHandler",
    "TIM1_CC_IRQHandler",
    "TIM2_IRQHandler",
    "TIM3_IRQHandler",
    "TIM6_DAC_IRQHandler",
    "TIM7_IRQHandler",
    "TIM14_IRQHandler",
    "TIM15_IRQHandler",
    "TIM16_IRQHandler",
    "TIM17_IRQHandler",
    "I2C1_IRQHandler",
    "I2C2_IRQHandler",
    "USART1_IRQHandler",
    "USART2_IRQHandler",
    "USART3_4_IRQHandler",
}

# Known MMIO peripheral base addresses on STM32F091RC
STM32F0_PERIPH_BASES = {
    "USART2": 0x40004400,
    "USART3": 0x40004800,
    "USART4": 0x40004C00,
    "I2C1": 0x40005400,
    "I2C2": 0x40005800,
    "TIM2": 0x40000000,
    "TIM3": 0x40000400,
    "TIM6": 0x40001000,
    "TIM7": 0x40001400,
    "TIM14": 0x40002000,
    "RTC": 0x40002800,
    "GPIOA": 0x48000000,
    "GPIOB": 0x48000400,
    "GPIOC": 0x48000800,
    "GPIOD": 0x48000C00,
    "GPIOF": 0x48001400,
    "TIM1": 0x40012C00,
    "USART1": 0x40013800,
    "TIM15": 0x40014000,
    "TIM16": 0x40014400,
    "TIM17": 0x40014800,
    "RCC": 0x40021000,
    "FLASH_IF": 0x40022000,
    "EXTI": 0x40010400,
    "SYSCFG": 0x40010000,
    "DMA1": 0x40020000,
    "NVIC": 0xE000E100,
    "SCB": 0xE000ED00,
    "SysTick": 0xE000E010,
}

# Functions that MUST read MMIO registers (from HAL source knowledge)
EXPECTED_MMIO_FUNCTIONS = {
    "HAL_UART_IRQHandler",       # Reads USART ISR, RDR registers
    "UART_Receive_IT",           # Reads USART RDR
    "UART_Transmit_IT",          # Reads USART ISR
    "UART_SetConfig",            # Reads/writes USART CR1/CR2/BRR
    "HAL_UART_Init",             # Configures USART registers
    "HAL_RCC_GetSysClockFreq",   # Reads RCC registers
    "HAL_RCC_ClockConfig",       # Reads/writes RCC registers
    "HAL_RCC_OscConfig",         # Reads/writes RCC registers
    "HAL_RCC_GetHCLKFreq",       # Reads RCC CFGR
    "HAL_RCC_GetPCLK1Freq",      # Reads RCC CFGR
    "HAL_I2C_EV_IRQHandler",     # Reads I2C ISR
    "HAL_I2C_ER_IRQHandler",     # Reads I2C ISR
    "HAL_TIM_IRQHandler",        # Reads TIM SR
    "HAL_GPIO_EXTI_IRQHandler",  # Reads EXTI PR
    "SysTick_Handler",           # Reads SysTick registers
    "HAL_Init",                  # Configures NVIC, SysTick
}

FIRMWARE_DIR = Path(__file__).parent.parent / "firmware"
FIRMWARE_DEMO_DIR = FIRMWARE_DIR / "demo"


def _resolve_demo_sample(name: str) -> Path:
    for path in (FIRMWARE_DIR / name, FIRMWARE_DEMO_DIR / name):
        if path.exists():
            return path
    return FIRMWARE_DIR / name


ELF_PATH = _resolve_demo_sample("p2im_controllino.elf")
BIN_PATH = _resolve_demo_sample("p2im_controllino.bin")

# Skip all tests if firmware files don't exist
pytestmark = pytest.mark.skipif(
    not ELF_PATH.exists() or not BIN_PATH.exists(),
    reason="Firmware files not found in firmware/ or firmware/demo/",
)


# ── Stage 1: Loader tests (offline, no Ghidra) ───────────────────────────


class TestStage1Loader:
    """Test the binary loader on real P2IM firmware."""

    def test_elf_loads_successfully(self):
        from sourceagent.pipeline.loader import load_binary
        mm = load_binary(ELF_PATH)
        assert mm is not None
        assert mm.arch == "ARM:LE:32:Cortex"

    def test_bin_loads_successfully(self):
        from sourceagent.pipeline.loader import load_binary
        mm = load_binary(BIN_PATH)
        assert mm is not None
        assert mm.arch == "ARM:LE:32:Cortex"

    def test_base_address_matches(self):
        """Both ELF and BIN should detect 0x08000000 base."""
        from sourceagent.pipeline.loader import load_binary
        mm_elf = load_binary(ELF_PATH)
        mm_bin = load_binary(BIN_PATH)
        assert mm_elf.base_address == 0x08000000
        assert mm_bin.base_address == 0x08000000

    def test_entry_point_consistent(self):
        """Entry points should be within 1 byte (Thumb bit difference)."""
        from sourceagent.pipeline.loader import load_binary
        mm_elf = load_binary(ELF_PATH)
        mm_bin = load_binary(BIN_PATH)
        # ELF gets entry from header (may have Thumb bit), BIN from vector table
        assert abs(mm_elf.entry_point - mm_bin.entry_point) <= 1

    def test_vector_table_detected(self):
        from sourceagent.pipeline.loader import load_binary
        mm_elf = load_binary(ELF_PATH)
        mm_bin = load_binary(BIN_PATH)
        assert mm_elf.vector_table_addr == 0x08000000
        assert mm_bin.vector_table_addr == 0x08000000

    def test_isr_handler_count_matches(self):
        """Both files should detect the same ISR handlers."""
        from sourceagent.pipeline.loader import load_binary
        mm_elf = load_binary(ELF_PATH)
        mm_bin = load_binary(BIN_PATH)
        assert len(mm_elf.isr_handler_addrs) == len(mm_bin.isr_handler_addrs)

    def test_isr_handlers_match_between_elf_and_bin(self):
        """ISR handler addresses should be identical from both file types."""
        from sourceagent.pipeline.loader import load_binary
        mm_elf = load_binary(ELF_PATH)
        mm_bin = load_binary(BIN_PATH)
        assert set(mm_elf.isr_handler_addrs) == set(mm_bin.isr_handler_addrs)

    def test_isr_handlers_match_ground_truth(self):
        """Detected ISR handlers should match ELF symbol table."""
        from sourceagent.pipeline.loader import load_binary
        mm = load_binary(BIN_PATH)
        detected = set(mm.isr_handler_addrs)
        # Every detected handler should be in our ground truth set
        # (Some may be deduplicated — Default_Handler appears many times)
        for addr in detected:
            assert addr in GROUND_TRUTH_ISR_ADDRS, (
                f"Detected ISR 0x{addr:08x} not in ground truth"
            )

    def test_flash_region_present(self):
        from sourceagent.pipeline.loader import load_binary
        for path in [ELF_PATH, BIN_PATH]:
            mm = load_binary(path)
            flash = [r for r in mm.regions if r.kind == "flash"]
            assert len(flash) >= 1, f"No flash region in {path.name}"
            assert any(r.base == 0x08000000 for r in flash)

    def test_sram_region_present(self):
        from sourceagent.pipeline.loader import load_binary
        for path in [ELF_PATH, BIN_PATH]:
            mm = load_binary(path)
            sram = [r for r in mm.regions if r.kind == "sram"]
            assert len(sram) >= 1, f"No SRAM region in {path.name}"
            assert any(r.base == 0x20000000 for r in sram)

    def test_peripheral_region_present(self):
        from sourceagent.pipeline.loader import load_binary
        for path in [ELF_PATH, BIN_PATH]:
            mm = load_binary(path)
            mmio = [r for r in mm.regions if r.kind == "mmio"]
            assert len(mmio) >= 1, f"No MMIO region in {path.name}"
            # Should cover 0x40000000 range
            assert any(r.base == 0x40000000 for r in mmio)


# ── Full pipeline test (requires Ghidra MCP) ─────────────────────────────


def _ghidra_available():
    """Check if Ghidra dependencies exist."""
    ghidra = Path("/home/a347908610/local/ghidra_12.0.2_PUBLIC/ghidraRun")
    java = Path("/home/a347908610/local/jdk-21.0.6+7/bin/java")
    return ghidra.exists() and java.exists()


@pytest.mark.skipif(not _ghidra_available(), reason="Ghidra not installed")
class TestFullPipeline:
    """Full pipeline test through Ghidra MCP.

    These tests are slow (~60-120s each) because they start Ghidra headless,
    import the binary, wait for analysis, then run all stages.
    """

    @pytest.fixture(scope="class")
    def pipeline_results(self):
        """Run the pipeline once on both ELF and BIN, cache results."""
        results = {}
        for label, path in [("elf", ELF_PATH), ("bin", BIN_PATH)]:
            result = asyncio.get_event_loop().run_until_complete(
                _run_pipeline_on(path)
            )
            results[label] = result
        return results

    @staticmethod
    async def _run_single(path):
        """Run pipeline stages 1-7 on a firmware file."""
        return await _run_pipeline_on(path)


async def _run_pipeline_on(firmware_path: Path):
    """Run the full mining pipeline and return PipelineResult.

    Stages 1-7: Load → MAI → Source miners → Sink miners → Pack → Propose → Verify.
    Uses heuristic proposer (no LLM needed).
    """
    from sourceagent.pipeline.models import PipelineResult
    from sourceagent.pipeline.loader import load_binary
    from sourceagent.mcp.manager import MCPManager
    from sourceagent.interface.main import (
        _find_ghidra_server, _import_and_analyze,
        _run_stage_2, _run_stage_3, _run_stage_4,
        _run_stage_5,
    )
    from sourceagent.pipeline.proposer import propose_labels
    from sourceagent.pipeline.verifier import verify_proposals

    run_id = f"test-{firmware_path.stem}-{int(time.time())}"
    result = PipelineResult(binary_path=str(firmware_path), run_id=run_id)

    # Stage 1: Load
    mm = load_binary(firmware_path)
    result.memory_map = mm

    # Connect Ghidra MCP
    mcp_manager = MCPManager()
    try:
        await mcp_manager.connect_all()
    except Exception as e:
        result.stage_errors["MCP"] = str(e)
        return result

    ghidra_server = _find_ghidra_server(mcp_manager)
    if not ghidra_server:
        result.stage_errors["MCP"] = "No Ghidra server"
        return result

    # Import and analyze
    ghidra_binary_name = await _import_and_analyze(
        mcp_manager, ghidra_server, firmware_path,
        max_wait=180, poll_interval=5,
        memory_map=mm,
    )
    if not ghidra_binary_name:
        result.stage_errors["MCP"] = "Import failed"
        await mcp_manager.disconnect_all()
        return result

    # Stage 2: MAI
    mai = await _run_stage_2(mm, mcp_manager, ghidra_binary_name, False, result)

    # Stage 3: Source miners
    sources = _run_stage_3(mai, mm, result)
    result.source_candidates = sources

    # Stage 4: Sink miners
    sinks = await _run_stage_4(mm, mcp_manager, ghidra_binary_name, False, result, mai)
    result.sink_candidates = sinks

    # Stage 5: Evidence packing
    from sourceagent.pipeline.evidence_packer import pack_evidence
    packs = pack_evidence(sources, sinks)
    result.evidence_packs = packs

    # Stage 6: Propose (heuristic, no LLM)
    proposals = await propose_labels(packs, mode="heuristic")
    result.proposals = proposals

    # Stage 7: Verify
    verified = await verify_proposals(proposals, mcp_manager, ghidra_binary_name)
    result.verified_labels = verified

    # Cleanup
    try:
        await mcp_manager.disconnect_all()
    except Exception:
        pass

    return result


# ── Standalone runner (not pytest) ────────────────────────────────────────

def _print_result_summary(label: str, result):
    """Print a detailed summary of pipeline results."""
    print(f"\n{'='*70}")
    print(f"  {label}")
    print(f"{'='*70}")

    mm = result.memory_map
    if mm:
        print(f"\n  Stage 1 — Memory Map:")
        print(f"    Base: 0x{mm.base_address:08x}, Entry: 0x{mm.entry_point:08x}")
        print(f"    Regions: {len(mm.regions)}, ISR handlers: {len(mm.isr_handler_addrs)}")

    # Source candidates
    print(f"\n  Stage 3 — Source Candidates: {len(result.source_candidates)}")
    by_label = {}
    for c in result.source_candidates:
        lbl = c.preliminary_label.value if hasattr(c.preliminary_label, 'value') else str(c.preliminary_label)
        by_label[lbl] = by_label.get(lbl, 0) + 1
    for lbl, cnt in sorted(by_label.items()):
        print(f"    {lbl}: {cnt}")
    # Show first 15 sources
    for i, c in enumerate(result.source_candidates[:15]):
        lbl = c.preliminary_label.value if hasattr(c.preliminary_label, 'value') else str(c.preliminary_label)
        print(f"    [{i+1:2d}] {lbl:20s} @ 0x{c.address:08x} in {c.function_name}  conf={c.confidence_score:.2f}")
    if len(result.source_candidates) > 15:
        print(f"    ... and {len(result.source_candidates)-15} more")

    # Sink candidates
    print(f"\n  Stage 4 — Sink Candidates: {len(result.sink_candidates)}")
    by_label = {}
    for c in result.sink_candidates:
        lbl = c.preliminary_label.value if hasattr(c.preliminary_label, 'value') else str(c.preliminary_label)
        by_label[lbl] = by_label.get(lbl, 0) + 1
    for lbl, cnt in sorted(by_label.items()):
        print(f"    {lbl}: {cnt}")
    for i, c in enumerate(result.sink_candidates[:10]):
        lbl = c.preliminary_label.value if hasattr(c.preliminary_label, 'value') else str(c.preliminary_label)
        print(f"    [{i+1:2d}] {lbl:20s} @ 0x{c.address:08x} in {c.function_name}  conf={c.confidence_score:.2f}")

    # Verified labels
    print(f"\n  Stage 7 — Verified Labels: {len(result.verified_labels)}")
    by_verdict = {}
    for v in result.verified_labels:
        key = v.verdict.value
        by_verdict[key] = by_verdict.get(key, 0) + 1
    for k, cnt in sorted(by_verdict.items()):
        print(f"    {k}: {cnt}")

    for v in result.verified_labels[:20]:
        status = v.verdict.value
        label = v.final_label or v.proposal.label
        addr = f"0x{v.proposal.address:08x}" if v.proposal.address else "?"
        func = v.proposal.function_name or "?"
        print(f"    [{status:8s}] {label:20s} @ {addr} in {func}")

    if result.stage_errors:
        print(f"\n  Errors: {result.stage_errors}")


def _compare_results(elf_result, bin_result):
    """Compare ELF vs BIN pipeline results."""
    print(f"\n{'='*70}")
    print("  COMPARISON: ELF vs BIN")
    print(f"{'='*70}")

    # Stage 1
    mm_e, mm_b = elf_result.memory_map, bin_result.memory_map
    if mm_e and mm_b:
        match_base = mm_e.base_address == mm_b.base_address
        match_isr = set(mm_e.isr_handler_addrs) == set(mm_b.isr_handler_addrs)
        print(f"\n  Stage 1:")
        print(f"    Base address match:     {'YES' if match_base else 'NO'}")
        print(f"    ISR handlers match:     {'YES' if match_isr else 'NO'}")
        print(f"    ELF regions: {len(mm_e.regions)}, BIN regions: {len(mm_b.regions)}")

    # Source candidates
    elf_sources = set()
    for c in elf_result.source_candidates:
        lbl = c.preliminary_label.value if hasattr(c.preliminary_label, 'value') else str(c.preliminary_label)
        elf_sources.add((lbl, c.address))

    bin_sources = set()
    for c in bin_result.source_candidates:
        lbl = c.preliminary_label.value if hasattr(c.preliminary_label, 'value') else str(c.preliminary_label)
        bin_sources.add((lbl, c.address))

    common = elf_sources & bin_sources
    elf_only = elf_sources - bin_sources
    bin_only = bin_sources - elf_sources

    print(f"\n  Source Candidates:")
    print(f"    ELF: {len(elf_sources)}, BIN: {len(bin_sources)}, Common: {len(common)}")
    if elf_only:
        print(f"    ELF-only ({len(elf_only)}):")
        for lbl, addr in sorted(elf_only)[:10]:
            print(f"      {lbl} @ 0x{addr:08x}")
    if bin_only:
        print(f"    BIN-only ({len(bin_only)}):")
        for lbl, addr in sorted(bin_only)[:10]:
            print(f"      {lbl} @ 0x{addr:08x}")

    # Verified labels
    elf_verified = set()
    for v in elf_result.verified_labels:
        if v.verdict.value in ("VERIFIED", "PARTIAL"):
            label = v.final_label or v.proposal.label
            elf_verified.add((label, v.proposal.address))

    bin_verified = set()
    for v in bin_result.verified_labels:
        if v.verdict.value in ("VERIFIED", "PARTIAL"):
            label = v.final_label or v.proposal.label
            bin_verified.add((label, v.proposal.address))

    common_v = elf_verified & bin_verified
    print(f"\n  Verified Labels (VERIFIED+PARTIAL):")
    print(f"    ELF: {len(elf_verified)}, BIN: {len(bin_verified)}, Common: {len(common_v)}")

    # Check against expected MMIO functions
    elf_mmio_funcs = {c.function_name for c in elf_result.source_candidates
                      if hasattr(c.preliminary_label, 'value') and 'MMIO' in c.preliminary_label.value}
    expected_found = EXPECTED_MMIO_FUNCTIONS & elf_mmio_funcs
    expected_missing = EXPECTED_MMIO_FUNCTIONS - elf_mmio_funcs
    print(f"\n  Expected MMIO Functions (ELF):")
    print(f"    Found:   {len(expected_found)}/{len(EXPECTED_MMIO_FUNCTIONS)}")
    for fn in sorted(expected_found):
        print(f"      [+] {fn}")
    if expected_missing:
        print(f"    Missing: {len(expected_missing)}")
        for fn in sorted(expected_missing):
            print(f"      [-] {fn}")


async def _main():
    """Run the full comparison test from command line."""
    logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s: %(message)s")

    print("Running P2IM Controllino firmware analysis...")
    print(f"  ELF: {ELF_PATH}")
    print(f"  BIN: {BIN_PATH}")

    results = {}
    for label, path in [("ELF", ELF_PATH), ("BIN", BIN_PATH)]:
        print(f"\n>>> Analyzing {label}: {path.name} ...")
        result = await _run_pipeline_on(path)
        results[label] = result
        _print_result_summary(f"{label}: {path.name}", result)

    if "ELF" in results and "BIN" in results:
        _compare_results(results["ELF"], results["BIN"])


if __name__ == "__main__":
    asyncio.run(_main())
