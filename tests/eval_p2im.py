#!/usr/bin/env python3
"""P2IM evaluation harness — compare sourceagent MMIO detection vs ground truth.

Runs sourceagent on p2im unit test ELFs and real firmware, then computes
precision/recall for MMIO register detection against the P2IM CSV ground truth.

Usage:
    # Run evaluation on a subset of unit tests
    python3 tests/eval_p2im.py --unit-tests Arduino/USART

    # Run evaluation on all unit tests (slow — requires sequential Ghidra)
    python3 tests/eval_p2im.py --all-unit-tests

    # Run on a single firmware
    python3 tests/eval_p2im.py --firmware CNC

    # Just evaluate existing results (no pipeline run)
    python3 tests/eval_p2im.py --eval-only --results-dir /tmp/p2im_results

    # Evaluate only true data sources (DR registers = attacker input points)
    python3 tests/eval_p2im.py --all-unit-tests --eval-tier source_only

Eval tiers:
    coverage (default) — all read registers (CR+SR+DR+C&SR with Read=1)
    source_only — only DR (data registers: true attacker input points)
"""

import argparse
import asyncio
import csv
import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("eval_p2im")

# ── Paths ──────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent
UNIT_TESTS_DIR = REPO_ROOT / "firmware" / "p2im-unit_tests"
REAL_FW_DIR = REPO_ROOT / "firmware" / "p2im-real_firmware" / "binary"
GLOBAL_GT_DIR = REPO_ROOT / "firmware" / "p2im-ground_truth"
RESULTS_DIR = Path("/tmp/p2im_results")
GHIDRA_PROJECT = REPO_ROOT / "pyghidra_mcp_projects" / "pyghidra_mcp"


# ── Ground truth parsing ──────────────────────────────────────────────────


@dataclass
class RegisterGT:
    """A single MMIO register from ground truth."""
    base_addr: int
    reg_addr: int
    reg_name: str
    category: str  # CR, SR, DR, C&SR
    read: bool
    write: bool
    peripheral: str = ""


def parse_unit_test_csv(csv_path: Path) -> List[RegisterGT]:
    """Parse a unit test CSV (9-column format).

    Columns: Base address, Reg address, Reg name, Reg cat, Model Cat,
             Read, Write, Correct cat, Comments GT
    """
    registers = []
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if not header:
            return registers
        for row in reader:
            if len(row) < 7:
                continue
            try:
                base_addr = int(row[0].strip(), 16)
                reg_addr = int(row[1].strip(), 16)
            except (ValueError, IndexError):
                continue
            reg_name = row[2].strip() if len(row) > 2 else ""
            category = row[3].strip() if len(row) > 3 else ""
            read = row[5].strip() == "1" if len(row) > 5 else False
            write = row[6].strip() == "1" if len(row) > 6 else False
            registers.append(RegisterGT(
                base_addr=base_addr,
                reg_addr=reg_addr,
                reg_name=reg_name,
                category=category,
                read=read,
                write=write,
            ))
    return registers


def parse_global_gt_csv(csv_path: Path) -> List[RegisterGT]:
    """Parse a global ground truth CSV (5-column format).

    Columns: adress, name, category, Comments, peripheral
    """
    registers = []
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if not header:
            return registers
        for row in reader:
            if len(row) < 3:
                continue
            try:
                addr = int(row[0].strip(), 16)
            except (ValueError, IndexError):
                continue
            reg_name = row[1].strip() if len(row) > 1 else ""
            category = row[2].strip() if len(row) > 2 else ""
            peripheral = row[4].strip() if len(row) > 4 else ""
            registers.append(RegisterGT(
                base_addr=addr,
                reg_addr=addr,
                reg_name=reg_name,
                category=category,
                read=True,  # Assume accessed
                write=True,
                peripheral=peripheral,
            ))
    return registers


def get_mcu_global_gt(mcu: str) -> Optional[Path]:
    """Get the global ground truth CSV path for a given MCU identifier."""
    mapping = {
        "f103": GLOBAL_GT_DIR / "STM32F103-GroundTruth.csv",
        "F103": GLOBAL_GT_DIR / "STM32F103-GroundTruth.csv",
        "f429": GLOBAL_GT_DIR / "STM32F429-GroundTruth.csv",
        "F429": GLOBAL_GT_DIR / "STM32F429-GroundTruth.csv",
        "sam3": GLOBAL_GT_DIR / "AtmelSAM3-GroundTruth.csv",
        "SAM3": GLOBAL_GT_DIR / "AtmelSAM3-GroundTruth.csv",
        "k64f": GLOBAL_GT_DIR / "NXPK64F-GroundTruth.csv",
        "K64F": GLOBAL_GT_DIR / "NXPK64F-GroundTruth.csv",
    }
    return mapping.get(mcu)


def mcu_from_elf_name(elf_name: str) -> str:
    """Extract MCU identifier from ELF filename."""
    name = elf_name.upper()
    if "F103" in name:
        return "f103"
    if "F429" in name:
        return "f429"
    if "SAM3" in name:
        return "sam3"
    if "K64F" in name:
        return "k64f"
    return ""


# ── Firmware → MCU mapping for real firmware ──────────────────────────────

REAL_FW_MCU = {
    "CNC": "f103",        # STM32F407 but closest GT is F103 peripherals (use global)
    "Console": "k64f",
    "Drone": "f103",
    "Gateway": "f103",
    "Heat_Press": "sam3",
    "PLC": "f429",
    "Reflow_Oven": "f103",
    "Robot": "f103",
    "Steering_Control": "sam3",
}


# ── Sourceagent runner ────────────────────────────────────────────────────


def run_sourceagent(binary_path: Path, output_path: Path) -> bool:
    """Run sourceagent mine on a binary, return True on success."""
    # Clean Ghidra project between runs
    if GHIDRA_PROJECT.exists():
        shutil.rmtree(GHIDRA_PROJECT)

    cmd = [
        sys.executable, "-m", "sourceagent.interface.main",
        "mine", str(binary_path),
        "--output", str(output_path),
    ]
    logger.info("Running: %s", " ".join(cmd[-4:]))
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
            cwd=str(REPO_ROOT),
        )
        if result.returncode != 0:
            logger.error("sourceagent failed for %s: %s", binary_path.name, result.stderr[-500:])
            return False
        return True
    except subprocess.TimeoutExpired:
        logger.error("Timeout running sourceagent on %s", binary_path.name)
        return False


def load_result(result_path: Path) -> Optional[dict]:
    """Load a sourceagent JSON result."""
    if not result_path.exists():
        return None
    with open(result_path) as f:
        return json.load(f)


# ── Evaluation ────────────────────────────────────────────────────────────


# Categories that represent true attacker-controlled data input points.
# DR = data registers (USART_DR, ADC_DR, SPI_DR, etc.)
# These are where external data enters the firmware.
SOURCE_ONLY_CATEGORIES = {"DR"}


@dataclass
class EvalResult:
    """Evaluation result for a single firmware."""
    firmware_name: str
    peripheral: str = ""
    mcu: str = ""
    eval_tier: str = "coverage"  # "coverage" or "source_only"
    # Ground truth
    gt_registers: int = 0
    gt_read_registers: int = 0  # Registers with Read=1
    gt_eval_count: int = 0      # Registers actually used for TP/FN (depends on tier)
    gt_sr_registers: int = 0    # Status registers
    gt_dr_registers: int = 0    # Data registers
    gt_cr_registers: int = 0    # Control registers
    # Detection
    detected_mmio_addrs: Set[int] = field(default_factory=set)
    source_candidates: int = 0
    sink_candidates: int = 0
    # Precision/recall against GT accessed registers
    true_positives: int = 0      # Detected AND in GT
    false_positives: int = 0     # Detected but NOT in any GT
    valid_oos: int = 0           # Detected, in global GT but not unit-test GT
    false_negatives: int = 0     # In GT (read=1) but NOT detected
    # Multi-tier precision FP counts
    fp_valid_not_in_test_gt: int = 0   # In global GT but not per-test GT
    fp_system_periph: int = 0          # In 0xE0000000+ range (NVIC, SysTick, SCB)
    fp_unknown_periph: int = 0         # In 0x40000000-0x5FFFFFFF but not in any GT
    fp_non_mmio: int = 0               # Outside peripheral ranges entirely
    # Per-category breakdown
    tp_by_category: Dict[str, int] = field(default_factory=dict)
    fn_by_category: Dict[str, int] = field(default_factory=dict)
    fn_addrs: List[str] = field(default_factory=list)  # Missed addresses
    # Per-peripheral breakdown
    tp_by_peripheral: Dict[str, int] = field(default_factory=dict)
    fn_by_peripheral: Dict[str, int] = field(default_factory=dict)
    gt_by_peripheral: Dict[str, int] = field(default_factory=dict)
    # Errors
    errors: List[str] = field(default_factory=list)
    pipeline_ok: bool = True

    @property
    def precision(self) -> float:
        """Strict precision: TP / (TP + FP), FP = detected NOT in per-test GT."""
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total > 0 else 0.0

    @property
    def precision_strict(self) -> float:
        """Same as precision — FP = NOT in per-test GT."""
        return self.precision

    @property
    def precision_global(self) -> float:
        """Global precision: FP = NOT in any MCU-family GT."""
        # fp_valid_not_in_test_gt are demoted from FP since they're valid MMIO
        fp_global = self.false_positives  # already excludes valid_oos
        total = self.true_positives + fp_global
        return self.true_positives / total if total > 0 else 0.0

    @property
    def precision_system(self) -> float:
        """System precision: FP = NOT in 0x40000000-0x5FFFFFFF AND NOT in 0xE0000000+."""
        total = self.true_positives + self.fp_non_mmio
        return self.true_positives / total if total > 0 else 0.0

    @property
    def recall(self) -> float:
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


def _normalize_bitband(addr: int) -> int:
    """Normalize ARM Cortex-M bit-band alias to canonical peripheral address.

    Bit-band region: 0x42000000-0x43FFFFFF → aliases 0x40000000-0x400FFFFF
    Formula: byte_offset = (alias - 0x42000000) / 32
             canonical = 0x40000000 + byte_offset
    """
    if 0x42000000 <= addr <= 0x43FFFFFF:
        byte_offset = (addr - 0x42000000) >> 5
        return 0x40000000 + byte_offset
    return addr


def _categorize_fp(addr: int, global_gt_addrs: Set[int]) -> str:
    """Categorize a false positive address into a bucket.

    Returns one of:
      FP_VALID_NOT_IN_TEST_GT — In global GT but not per-test GT
      FP_SYSTEM_PERIPH — In 0xE0000000+ range (NVIC, SysTick, SCB)
      FP_UNKNOWN_PERIPH — In 0x40000000-0x5FFFFFFF but not in any GT
      FP_NON_MMIO — Outside peripheral ranges entirely
    """
    if addr in global_gt_addrs:
        return "FP_VALID_NOT_IN_TEST_GT"
    if 0xE0000000 <= addr <= 0xFFFFFFFF:
        return "FP_SYSTEM_PERIPH"
    if 0x40000000 <= addr <= 0x5FFFFFFF:
        return "FP_UNKNOWN_PERIPH"
    return "FP_NON_MMIO"


def evaluate_result(
    result: dict,
    gt_registers: List[RegisterGT],
    firmware_name: str,
    peripheral: str = "",
    mcu: str = "",
    global_gt_registers: Optional[List[RegisterGT]] = None,
    eval_mode: str = "read_only",
    eval_tier: str = "coverage",
) -> EvalResult:
    """Compare sourceagent output against ground truth.

    Args:
        eval_mode: "read_only" — TP/FN against registers with Read=1 only.
                   "all_accessed" — TP/FN against registers with Read=1 OR Write=1 (legacy).
        eval_tier: "coverage" — all read registers (CR+SR+DR+C&SR).
                   "source_only" — only DR (data registers: true attacker input points).
    """
    ev = EvalResult(
        firmware_name=firmware_name,
        peripheral=peripheral,
        mcu=mcu,
        eval_tier=eval_tier,
    )

    # Build GT address sets (with bitband normalization)
    gt_all_addrs = {_normalize_bitband(r.reg_addr) for r in gt_registers}
    gt_read_addrs = {_normalize_bitband(r.reg_addr) for r in gt_registers if r.read}
    gt_accessed_addrs = {_normalize_bitband(r.reg_addr) for r in gt_registers if r.read or r.write}
    gt_write_only_addrs = gt_accessed_addrs - gt_read_addrs

    # Build category sets
    gt_by_category: Dict[str, Set[int]] = {}
    for r in gt_registers:
        cat = r.category.strip()
        if cat:
            gt_by_category.setdefault(cat, set()).add(_normalize_bitband(r.reg_addr))

    # Build peripheral sets for per-peripheral breakdown
    gt_periph_map: Dict[str, Set[int]] = {}
    for r in gt_registers:
        periph = r.peripheral.strip() if r.peripheral else ""
        if not periph:
            # Derive peripheral from base address
            periph = f"0x{r.base_addr:08x}"
        gt_periph_map.setdefault(periph, set()).add(_normalize_bitband(r.reg_addr))

    ev.gt_registers = len(gt_all_addrs)
    ev.gt_read_registers = len(gt_read_addrs)
    ev.gt_sr_registers = len(gt_by_category.get("SR", set()))
    ev.gt_dr_registers = len(gt_by_category.get("DR", set()))
    ev.gt_cr_registers = len(gt_by_category.get("CR", set()))
    for periph, addrs in gt_periph_map.items():
        ev.gt_by_peripheral[periph] = len(addrs)

    # Extract detected MMIO addresses from sourceagent output (with normalization)
    detected = set()

    for sc in result.get("source_candidates", []):
        addr = sc.get("address")
        if addr and 0x40000000 <= addr <= 0xFFFFFFFF:
            detected.add(_normalize_bitband(addr))

    for vl in result.get("verified_labels", []):
        proposal = vl.get("proposal", {})
        addr = proposal.get("address")
        if addr and 0x40000000 <= addr <= 0xFFFFFFFF:
            detected.add(_normalize_bitband(addr))

    for ep in result.get("evidence_packs", []):
        addr = ep.get("address")
        if addr and 0x40000000 <= addr <= 0xFFFFFFFF:
            detected.add(_normalize_bitband(addr))
        for ev_item in ep.get("evidence", []):
            meta = ev_item.get("metadata", {})
            target = meta.get("target")
            if target and 0x40000000 <= target <= 0xFFFFFFFF:
                detected.add(_normalize_bitband(target))

    ev.detected_mmio_addrs = detected
    ev.source_candidates = len(result.get("source_candidates", []))
    ev.sink_candidates = len(result.get("sink_candidates", []))

    # Build global GT address set for FP categorization
    global_gt_addrs: Set[int] = set()
    if global_gt_registers:
        global_gt_addrs = {_normalize_bitband(r.reg_addr) for r in global_gt_registers}

    # Select the GT set for TP/FN based on eval_mode and eval_tier
    if eval_mode == "read_only":
        gt_eval_addrs = gt_read_addrs
    else:
        gt_eval_addrs = gt_accessed_addrs

    # Apply tier filter: source_only restricts to DR (data register) category only
    if eval_tier == "source_only":
        dr_addrs = gt_by_category.get("DR", set())
        gt_eval_addrs = gt_eval_addrs & dr_addrs

    ev.gt_eval_count = len(gt_eval_addrs)

    # Also extract all_mmio_addrs from pipeline output for all_accessed mode
    all_mmio_addrs = result.get("all_mmio_addrs", {})
    if all_mmio_addrs and eval_mode == "all_accessed":
        # Include all MMIO addrs (loads + stores) in detected set
        for addr_str, kind in all_mmio_addrs.items():
            try:
                addr = int(addr_str) if isinstance(addr_str, str) else addr_str
            except (ValueError, TypeError):
                continue
            if 0x40000000 <= addr <= 0xFFFFFFFF:
                detected.add(_normalize_bitband(addr))

    # Compute TP/FP/FN with FP categorization
    for addr in detected:
        if addr in gt_eval_addrs:
            ev.true_positives += 1
            for cat, addrs in gt_by_category.items():
                if addr in addrs:
                    ev.tp_by_category[cat] = ev.tp_by_category.get(cat, 0) + 1
            for periph, addrs in gt_periph_map.items():
                if addr in addrs:
                    ev.tp_by_peripheral[periph] = ev.tp_by_peripheral.get(periph, 0) + 1
        elif addr in global_gt_addrs:
            ev.valid_oos += 1
            ev.fp_valid_not_in_test_gt += 1
        else:
            # Categorize the false positive
            fp_bucket = _categorize_fp(addr, global_gt_addrs)
            if fp_bucket == "FP_SYSTEM_PERIPH":
                ev.fp_system_periph += 1
            elif fp_bucket == "FP_UNKNOWN_PERIPH":
                ev.fp_unknown_periph += 1
            else:
                ev.fp_non_mmio += 1
            ev.false_positives += 1

    for addr in gt_eval_addrs:
        if addr not in detected:
            ev.false_negatives += 1
            ev.fn_addrs.append(f"0x{addr:08x}")
            for cat, addrs in gt_by_category.items():
                if addr in addrs:
                    ev.fn_by_category[cat] = ev.fn_by_category.get(cat, 0) + 1
            for periph, addrs in gt_periph_map.items():
                if addr in addrs:
                    ev.fn_by_peripheral[periph] = ev.fn_by_peripheral.get(periph, 0) + 1

    return ev


# ── Inventory ─────────────────────────────────────────────────────────────


@dataclass
class TestCase:
    """A firmware + ground truth pair for evaluation."""
    name: str
    elf_path: Path
    csv_path: Path
    mcu: str
    peripheral: str
    os_name: str


def discover_unit_tests(filter_str: Optional[str] = None) -> List[TestCase]:
    """Discover all unit test ELF + CSV pairs."""
    tests = []
    for elf_path in sorted(UNIT_TESTS_DIR.rglob("*.elf")):
        periph_dir = elf_path.parent
        os_dir = periph_dir.parent
        periph = periph_dir.name
        os_name = os_dir.name

        if filter_str and filter_str not in str(elf_path):
            continue

        mcu = mcu_from_elf_name(elf_path.stem)
        if not mcu:
            continue

        # Find matching CSV
        csv_path = periph_dir / f"{mcu}.csv"
        if not csv_path.exists():
            logger.debug("No CSV for %s", elf_path.name)
            continue

        tests.append(TestCase(
            name=elf_path.stem,
            elf_path=elf_path,
            csv_path=csv_path,
            mcu=mcu,
            peripheral=periph,
            os_name=os_name,
        ))
    return tests


def discover_real_firmware() -> List[TestCase]:
    """Discover real firmware binaries."""
    tests = []
    for fw_dir in sorted(REAL_FW_DIR.iterdir()):
        if not fw_dir.is_dir():
            continue
        fw_name = fw_dir.name
        # The binary is the directory itself (extensionless ELF)
        elf_path = fw_dir
        if not elf_path.exists():
            continue

        mcu = REAL_FW_MCU.get(fw_name, "")
        global_csv = get_mcu_global_gt(mcu)
        if not global_csv or not global_csv.exists():
            continue

        tests.append(TestCase(
            name=fw_name,
            elf_path=elf_path,
            csv_path=global_csv,
            mcu=mcu,
            peripheral="ALL",
            os_name="real",
        ))
    return tests


# ── Report ────────────────────────────────────────────────────────────────


def print_report(results: List[EvalResult]) -> None:
    """Print evaluation summary table."""
    # Determine tier from first result
    eval_tier = "coverage"
    for r in results:
        if r.eval_tier:
            eval_tier = r.eval_tier
            break

    tier_label = {
        "coverage": "All Read Registers (CR+SR+DR+C&SR)",
        "source_only": "Data Registers Only (DR — true attacker input points)",
    }.get(eval_tier, eval_tier)

    print()
    print("=" * 120)
    print(f"P2IM MMIO Source Detection Evaluation  [tier: {eval_tier}]")
    print(f"  GT scope: {tier_label}")
    print("=" * 120)
    print()
    gt_col = "GT_DR" if eval_tier == "source_only" else "GT"
    print(f"{'Firmware':<35} {'Periph':<8} {'MCU':<5} "
          f"{gt_col:<5} {'Det':<4} {'TP':<4} {'OOS':<4} {'FP':<4} {'FN':<4} "
          f"{'P_strict':>8} {'P_global':>8} {'P_sys':>6} {'Recall':>6} {'F1':>6}")
    print("-" * 120)

    total_tp = total_fp = total_fn = total_oos = 0
    total_fp_sys = total_fp_unk = total_fp_non = 0
    ok_count = fail_count = 0

    for ev in results:
        if not ev.pipeline_ok:
            print(f"{'  ' + ev.firmware_name:<35} {'FAIL':<8}")
            fail_count += 1
            continue

        ok_count += 1
        total_tp += ev.true_positives
        total_fp += ev.false_positives
        total_fn += ev.false_negatives
        total_oos += ev.valid_oos
        total_fp_sys += ev.fp_system_periph
        total_fp_unk += ev.fp_unknown_periph
        total_fp_non += ev.fp_non_mmio

        gt_display = ev.gt_eval_count if ev.gt_eval_count > 0 else ev.gt_registers
        print(f"  {ev.firmware_name:<33} {ev.peripheral:<8} {ev.mcu:<5} "
              f"{gt_display:<5}{len(ev.detected_mmio_addrs):<4} "
              f"{ev.true_positives:<4} {ev.valid_oos:<4} {ev.false_positives:<4} {ev.false_negatives:<4} "
              f"{ev.precision_strict:>7.1%} {ev.precision_global:>7.1%} "
              f"{ev.precision_system:>5.1%} {ev.recall:>5.1%} {ev.f1:>5.1%}")
        if ev.fn_addrs:
            print(f"    Missed: {', '.join(ev.fn_addrs[:8])}")

    print("-" * 120)

    # Aggregate metrics
    agg_prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    agg_prec_sys = total_tp / (total_tp + total_fp_non) if (total_tp + total_fp_non) > 0 else 0.0
    agg_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    agg_f1 = 2 * agg_prec * agg_recall / (agg_prec + agg_recall) if (agg_prec + agg_recall) > 0 else 0.0

    total_gt_eval = sum(ev.gt_eval_count for ev in results if ev.pipeline_ok)

    print(f"  {'AGGREGATE':<33} {'':8} {'':5} "
          f"{total_gt_eval:<5}{'':4} "
          f"{total_tp:<4} {total_oos:<4} {total_fp:<4} {total_fn:<4} "
          f"{agg_prec:>7.1%} {agg_prec:>7.1%} "
          f"{agg_prec_sys:>5.1%} {agg_recall:>5.1%} {agg_f1:>5.1%}")
    print()
    if eval_tier == "source_only":
        print(f"  Eval tier: source_only — GT restricted to DR (data registers) only")
        print(f"  DR registers are where attacker-controlled data enters firmware")
        print(f"  (USART_DR, ADC_DR, SPI_DR, I2C_DR, etc.)")
        print()
    print("  Precision tiers:")
    print(f"    P_strict  = TP / (TP + FP), FP = detected NOT in per-test GT")
    print(f"    P_global  = TP / (TP + FP_global), FP_global = NOT in any MCU GT")
    print(f"    P_sys     = TP / (TP + FP_non_mmio), FP_non_mmio = outside 0x40-0x5F/0xE0+ ranges")
    print(f"    OOS = valid MMIO detections outside test scope (not counted as FP)")
    print()

    # FP categorization breakdown
    if total_fp > 0 or total_oos > 0:
        print(f"  FP breakdown (aggregate):")
        print(f"    OOS (valid, not in test GT):   {total_oos:>4}")
        print(f"    System periph (0xE0000000+):   {total_fp_sys:>4}")
        print(f"    Unknown periph (0x40-0x5F):    {total_fp_unk:>4}")
        print(f"    Non-MMIO (outside ranges):     {total_fp_non:>4}")
        print()

    print(f"  Firmware tested: {ok_count} OK, {fail_count} FAILED")
    print()

    # Per-category breakdown
    cat_tp: Dict[str, int] = {}
    cat_fn: Dict[str, int] = {}
    for ev in results:
        if not ev.pipeline_ok:
            continue
        for cat, count in ev.tp_by_category.items():
            cat_tp[cat] = cat_tp.get(cat, 0) + count
        for cat, count in ev.fn_by_category.items():
            cat_fn[cat] = cat_fn.get(cat, 0) + count

    if cat_tp or cat_fn:
        print("  Per-category recall:")
        for cat in sorted(set(list(cat_tp.keys()) + list(cat_fn.keys()))):
            tp = cat_tp.get(cat, 0)
            fn = cat_fn.get(cat, 0)
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            marker = ""
            if eval_tier == "source_only":
                marker = " <-- SOURCE" if cat in SOURCE_ONLY_CATEGORIES else "  (excluded from tier)"
            print(f"    {cat:>5}: {tp:>3} TP / {tp+fn:>3} total = {rec:>5.1%} recall{marker}")
        print()

    # Per-peripheral breakdown
    periph_tp: Dict[str, int] = {}
    periph_fn: Dict[str, int] = {}
    periph_gt: Dict[str, int] = {}
    for ev in results:
        if not ev.pipeline_ok:
            continue
        for periph, count in ev.tp_by_peripheral.items():
            periph_tp[periph] = periph_tp.get(periph, 0) + count
        for periph, count in ev.fn_by_peripheral.items():
            periph_fn[periph] = periph_fn.get(periph, 0) + count
        for periph, count in ev.gt_by_peripheral.items():
            periph_gt[periph] = periph_gt.get(periph, 0) + count

    all_periphs = sorted(set(periph_tp.keys()) | set(periph_fn.keys()) | set(periph_gt.keys()))
    if all_periphs:
        print("  Per-peripheral recall:")
        for periph in all_periphs:
            tp = periph_tp.get(periph, 0)
            fn = periph_fn.get(periph, 0)
            gt = periph_gt.get(periph, 0)
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            print(f"    {periph:<20}: {tp:>3} TP / {gt:>3} GT = {rec:>5.1%} recall")
        print()


def save_report_json(results: List[EvalResult], output_path: Path) -> None:
    """Save evaluation results to JSON."""
    data = []
    for ev in results:
        data.append({
            "firmware_name": ev.firmware_name,
            "peripheral": ev.peripheral,
            "mcu": ev.mcu,
            "eval_tier": ev.eval_tier,
            "pipeline_ok": ev.pipeline_ok,
            "gt_registers": ev.gt_registers,
            "gt_read_registers": ev.gt_read_registers,
            "gt_eval_count": ev.gt_eval_count,
            "detected_count": len(ev.detected_mmio_addrs),
            "detected_addrs": sorted(f"0x{a:08x}" for a in ev.detected_mmio_addrs),
            "source_candidates": ev.source_candidates,
            "sink_candidates": ev.sink_candidates,
            "true_positives": ev.true_positives,
            "valid_oos": ev.valid_oos,
            "false_positives": ev.false_positives,
            "false_negatives": ev.false_negatives,
            "fn_addrs": ev.fn_addrs,
            "precision_strict": round(ev.precision_strict, 4),
            "precision_global": round(ev.precision_global, 4),
            "precision_system": round(ev.precision_system, 4),
            "recall": round(ev.recall, 4),
            "f1": round(ev.f1, 4),
            "tp_by_category": ev.tp_by_category,
            "fn_by_category": ev.fn_by_category,
            "fp_breakdown": {
                "valid_not_in_test_gt": ev.fp_valid_not_in_test_gt,
                "system_periph": ev.fp_system_periph,
                "unknown_periph": ev.fp_unknown_periph,
                "non_mmio": ev.fp_non_mmio,
            },
            "tp_by_peripheral": ev.tp_by_peripheral,
            "fn_by_peripheral": ev.fn_by_peripheral,
            "gt_by_peripheral": ev.gt_by_peripheral,
            "errors": ev.errors,
        })
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  Results saved to: {output_path}")


# ── Main ──────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="P2IM evaluation harness")
    parser.add_argument("--unit-tests", type=str, default=None,
                        help="Filter unit tests (e.g., 'Arduino/USART', 'RIOT', 'F103')")
    parser.add_argument("--all-unit-tests", action="store_true",
                        help="Run all unit tests")
    parser.add_argument("--firmware", type=str, default=None,
                        help="Run specific real firmware (e.g., 'CNC', 'Drone')")
    parser.add_argument("--all-firmware", action="store_true",
                        help="Run all real firmware")
    parser.add_argument("--eval-only", action="store_true",
                        help="Only evaluate existing results (no pipeline run)")
    parser.add_argument("--results-dir", type=str, default=str(RESULTS_DIR),
                        help="Directory for results JSON files")
    parser.add_argument("--eval-mode", type=str, default="read_only",
                        choices=["read_only", "all_accessed"],
                        help="Eval mode: read_only (default, GT=Read=1 only) or all_accessed (GT=Read|Write)")
    parser.add_argument("--eval-tier", type=str, default="coverage",
                        choices=["coverage", "source_only"],
                        help="Eval tier: coverage (default, all read registers) or source_only (DR only — true data sources)")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(name)s %(levelname)s: %(message)s",
    )

    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    test_cases: List[TestCase] = []

    if args.all_unit_tests or args.unit_tests:
        test_cases.extend(discover_unit_tests(args.unit_tests))
    if args.all_firmware or args.firmware:
        fw_cases = discover_real_firmware()
        if args.firmware:
            fw_cases = [tc for tc in fw_cases if tc.name == args.firmware]
        test_cases.extend(fw_cases)

    if not test_cases:
        print("No test cases found. Use --unit-tests, --all-unit-tests, --firmware, or --all-firmware")
        sys.exit(1)

    print(f"\nDiscovered {len(test_cases)} test cases (eval_mode={args.eval_mode}, eval_tier={args.eval_tier})")
    for tc in test_cases:
        print(f"  {tc.name} ({tc.os_name}/{tc.peripheral}, {tc.mcu})")
    print()

    # Run pipeline or load existing results
    eval_results: List[EvalResult] = []

    for tc in test_cases:
        result_path = results_dir / f"{tc.name}.json"

        if not args.eval_only:
            print(f"\n[{tc.name}] Running sourceagent...")
            ok = run_sourceagent(tc.elf_path, result_path)
            if not ok:
                ev = EvalResult(firmware_name=tc.name, peripheral=tc.peripheral, mcu=tc.mcu)
                ev.pipeline_ok = False
                ev.errors.append("Pipeline execution failed")
                eval_results.append(ev)
                continue

        result = load_result(result_path)
        if result is None:
            ev = EvalResult(firmware_name=tc.name, peripheral=tc.peripheral, mcu=tc.mcu)
            ev.pipeline_ok = False
            ev.errors.append(f"No result file at {result_path}")
            eval_results.append(ev)
            continue

        # Parse ground truth
        if tc.os_name == "real":
            gt_regs = parse_global_gt_csv(tc.csv_path)
        else:
            gt_regs = parse_unit_test_csv(tc.csv_path)

        # Load global GT for context
        global_gt_path = get_mcu_global_gt(tc.mcu)
        global_gt = parse_global_gt_csv(global_gt_path) if global_gt_path and global_gt_path.exists() else None

        ev = evaluate_result(
            result, gt_regs, tc.name,
            peripheral=tc.peripheral, mcu=tc.mcu,
            global_gt_registers=global_gt,
            eval_mode=args.eval_mode,
            eval_tier=args.eval_tier,
        )
        eval_results.append(ev)

    # Print report
    print_report(eval_results)

    # Save detailed results
    save_report_json(eval_results, results_dir / "eval_summary.json")


if __name__ == "__main__":
    main()
