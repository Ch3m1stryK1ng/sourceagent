"""Generate a large sink-only microbench variant corpus.

The generated corpus is intentionally L1-oriented:
  - one known sink family per binary
  - stable function names for cheap GT extraction
  - stripped/unstripped pairs for stripped-first evaluation
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[2]
FIRMWARE_ROOT = REPO_ROOT / "firmware"
EVAL_SUITE_ROOT = FIRMWARE_ROOT / "eval_suite"
GROUND_TRUTH_ROOT = FIRMWARE_ROOT / "ground_truth_bundle"

AUTOGEN_ROOT = FIRMWARE_ROOT / "microbench_autogen"
AUTOGEN_GT_ROOT = GROUND_TRUTH_ROOT / "microbench_autogen"
LINKER_SCRIPT = FIRMWARE_ROOT / "microbench" / "cortexm.ld"

ARM_GCC_DIR = Path(
    os.environ.get(
        "ARM_GCC_DIR",
        "/home/a347908610/local/arm-gnu-toolchain-13.3.rel1-x86_64-arm-none-eabi",
    )
)
CC = ARM_GCC_DIR / "bin" / "arm-none-eabi-gcc"
OBJCOPY = ARM_GCC_DIR / "bin" / "arm-none-eabi-objcopy"
STRIP = ARM_GCC_DIR / "bin" / "arm-none-eabi-strip"
NM = ARM_GCC_DIR / "bin" / "arm-none-eabi-nm"

CFLAGS = [
    "-mcpu=cortex-m4",
    "-mthumb",
    "-mfloat-abi=soft",
    "-O1",
    "-g",
    "-gdwarf-4",
    "-fno-builtin",
    "-fno-lto",
    "-ffunction-sections",
    "-fdata-sections",
    "-Wall",
    "-Wextra",
]

LDFLAGS = [
    "-nostartfiles",
    "-specs=nosys.specs",
    "-specs=nano.specs",
    "-Wl,--gc-sections",
]

VARIANTS_PER_FAMILY = 18
FAMILIES = (
    "copy",
    "memset",
    "loop_write",
    "store",
    "format",
    "func_ptr",
)


@dataclass(frozen=True)
class VariantSpec:
    binary_stem: str
    family: str
    sink_label: str
    sink_function: str
    description: str
    params: Dict[str, Any]


COMMON_VECTOR_TABLE = """
extern uint32_t __stack_top__;

void Reset_Handler(void);
void Default_Handler(void);
int main(void);

__attribute__((used, section(".isr_vector")))
uint32_t vector_table[16] = {
    (uint32_t)&__stack_top__,
    (uint32_t)Reset_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    0, 0, 0, 0,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    0,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
};

void Reset_Handler(void) { main(); while (1) {} }
void Default_Handler(void) { while (1) {} }
"""


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _csv_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple, set)):
        return ";".join(_csv_value(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: _csv_value(row.get(field)) for field in fieldnames})


def _require_toolchain() -> None:
    for tool in (CC, OBJCOPY, STRIP, NM):
        if not tool.exists():
            raise FileNotFoundError(f"Required ARM toolchain binary not found: {tool}")


def _copy_params(idx: int) -> Dict[str, Any]:
    dst_sizes = [8, 12, 16, 20, 24, 28]
    guard_modes = ["none", "weak_floor", "weak_cap"]
    return {
        "dst_size": dst_sizes[idx % len(dst_sizes)],
        "raw_len": 24 + (idx % len(dst_sizes)) * 4,
        "guard_mode": guard_modes[idx // len(dst_sizes)],
        "api": "memcpy" if idx % 2 == 0 else "memmove",
        "mmio": hex(0x40011004 + ((idx % 4) * 4)),
    }


def _memset_params(idx: int) -> Dict[str, Any]:
    dst_sizes = [16, 24, 32, 40, 48, 56]
    len_bumps = [4, 8, 12]
    return {
        "dst_size": dst_sizes[idx % len(dst_sizes)],
        "len_bump": len_bumps[idx // len(dst_sizes)],
        "pattern": hex((idx * 17) & 0xFF),
    }


def _loop_params(idx: int) -> Dict[str, Any]:
    dst_sizes = [16, 24, 32, 40, 48, 56]
    overshoots = [2, 4, 6]
    return {
        "dst_size": dst_sizes[idx % len(dst_sizes)],
        "overshoot": overshoots[idx // len(dst_sizes)],
        "stride": 1 + (idx % 3),
    }


def _store_params(idx: int) -> Dict[str, Any]:
    reg_offsets = [0x00, 0x04, 0x08, 0x0C, 0x10, 0x14]
    transforms = ["raw", "shifted", "xor_tag"]
    return {
        "reg_offset": reg_offsets[idx % len(reg_offsets)],
        "transform": transforms[idx // len(reg_offsets)],
        "base_addr": hex(0x40020000 + reg_offsets[idx % len(reg_offsets)]),
    }


def _format_params(idx: int) -> Dict[str, Any]:
    log_sizes = [32, 48, 64, 80, 96, 112]
    wrapper_depth = idx // len(log_sizes)
    return {
        "log_size": log_sizes[idx % len(log_sizes)],
        "wrapper_depth": wrapper_depth,
        "api": "sprintf" if idx % 2 == 0 else "snprintf",
    }


def _func_ptr_params(idx: int) -> Dict[str, Any]:
    table_sizes = [2, 3, 4, 5, 6, 7]
    wrapper_depth = idx // len(table_sizes)
    return {
        "table_size": table_sizes[idx % len(table_sizes)],
        "wrapper_depth": wrapper_depth,
        "mask_bias": wrapper_depth * 3,
    }


def _make_variant_specs() -> List[VariantSpec]:
    specs: List[VariantSpec] = []
    for idx in range(VARIANTS_PER_FAMILY):
        specs.append(
            VariantSpec(
                binary_stem=f"copy_variant_{idx:02d}",
                family="copy",
                sink_label="COPY_SINK",
                sink_function="copy_handler",
                description="Auto-generated copy sink variant",
                params=_copy_params(idx),
            )
        )
        specs.append(
            VariantSpec(
                binary_stem=f"memset_variant_{idx:02d}",
                family="memset",
                sink_label="MEMSET_SINK",
                sink_function="clear_buffer",
                description="Auto-generated memset sink variant",
                params=_memset_params(idx),
            )
        )
        specs.append(
            VariantSpec(
                binary_stem=f"loop_variant_{idx:02d}",
                family="loop_write",
                sink_label="LOOP_WRITE_SINK",
                sink_function="fill_buffer",
                description="Auto-generated loop-write sink variant",
                params=_loop_params(idx),
            )
        )
        specs.append(
            VariantSpec(
                binary_stem=f"store_variant_{idx:02d}",
                family="store",
                sink_label="STORE_SINK",
                sink_function="write_register",
                description="Auto-generated store sink variant",
                params=_store_params(idx),
            )
        )
        specs.append(
            VariantSpec(
                binary_stem=f"format_variant_{idx:02d}",
                family="format",
                sink_label="FORMAT_STRING_SINK",
                sink_function="log_message",
                description="Auto-generated format-string variant",
                params=_format_params(idx),
            )
        )
        specs.append(
            VariantSpec(
                binary_stem=f"funcptr_variant_{idx:02d}",
                family="func_ptr",
                sink_label="FUNC_PTR_SINK",
                sink_function="dispatch_command",
                description="Auto-generated function-pointer variant",
                params=_func_ptr_params(idx),
            )
        )
    return specs


def _guard_assignment(raw_expr: str, params: Dict[str, Any]) -> str:
    mode = params.get("guard_mode")
    dst_size = params.get("dst_size", 16)
    raw_len = params.get("raw_len", dst_size + 8)
    if mode == "weak_floor":
        return f"unsigned int n = ({raw_expr} < {raw_len // 2}u) ? {raw_len // 2}u : {raw_expr};"
    if mode == "weak_cap":
        return (
            f"unsigned int n = {raw_expr};\n"
            f"    if (n > {dst_size}u) n = {dst_size + 4}u;"
        )
    return f"unsigned int n = {raw_expr};"


def _render_copy(spec: VariantSpec) -> str:
    p = spec.params
    return f"""#include <stdint.h>
#include <string.h>

{COMMON_VECTOR_TABLE}

#define USART_SR (*(volatile uint32_t *)0x40011000u)
#define USART_DR (*(volatile uint32_t *){p['mmio']}u)

static uint8_t uart_read_byte(void) {{
    while (!(USART_SR & 0x20u)) {{}}
    return (uint8_t)(USART_DR & 0xFFu);
}}

static uint8_t g_src[96];
static char g_dst[{p['dst_size']}];

__attribute__((noinline))
void copy_handler(char *dst, const uint8_t *src, unsigned int raw_len) {{
    {_guard_assignment('raw_len', p)}
    {p['api']}(dst, src, n);
}}

int main(void) {{
    for (unsigned int i = 0; i < sizeof(g_src); i++) {{
        g_src[i] = uart_read_byte();
    }}
    copy_handler(g_dst, g_src, {p['raw_len']}u);
    return 0;
}}
"""


def _render_memset(spec: VariantSpec) -> str:
    p = spec.params
    return f"""#include <stdint.h>
#include <string.h>

{COMMON_VECTOR_TABLE}

#define DMA_CNDTR (*(volatile uint32_t *)0x40020004u)

static uint8_t g_buf[{p['dst_size']}];

__attribute__((noinline))
void clear_buffer(uint8_t *buf, unsigned int raw_len) {{
    unsigned int n = raw_len;
    if (n > {p['dst_size']}u) n = {p['dst_size'] + p['len_bump']}u;
    memset(buf, {p['pattern']}, n);
}}

int main(void) {{
    unsigned int dma_len = (DMA_CNDTR & 0xFFu) + {p['dst_size']}u;
    clear_buffer(g_buf, dma_len);
    return 0;
}}
"""


def _render_loop(spec: VariantSpec) -> str:
    p = spec.params
    return f"""#include <stdint.h>

{COMMON_VECTOR_TABLE}

#define SPI_SR (*(volatile uint32_t *)0x40004400u)
#define SPI_DR (*(volatile uint32_t *)0x40004404u)

static uint8_t spi_read_byte(void) {{
    while (!(SPI_SR & 0x01u)) {{}}
    return (uint8_t)(SPI_DR & 0xFFu);
}}

static uint8_t g_buf[{p['dst_size']}];

__attribute__((noinline))
void fill_buffer(uint8_t *buf, unsigned int raw_len) {{
    unsigned int n = raw_len;
    if (n > {p['dst_size']}u) n = {p['dst_size'] + p['overshoot']}u;
    for (unsigned int i = 0; i < n; i++) {{
        buf[i] = (uint8_t)(spi_read_byte() + (uint8_t){p['stride']});
    }}
}}

int main(void) {{
    fill_buffer(g_buf, {p['dst_size'] + p['overshoot'] + 2}u);
    return 0;
}}
"""


def _render_store(spec: VariantSpec) -> str:
    p = spec.params
    transform = {
        "raw": "val",
        "shifted": "(val << 1)",
        "xor_tag": "(val ^ 0x55AA0000u)",
    }[p["transform"]]
    return f"""#include <stdint.h>

{COMMON_VECTOR_TABLE}

#define ADC_DR (*(volatile uint32_t *)0x4001244Cu)
static volatile uint32_t *const g_mmio_regs[3] = {{
    (volatile uint32_t *){p['base_addr']}u,
    (volatile uint32_t *)({p['base_addr']}u + 0x20u),
    (volatile uint32_t *)({p['base_addr']}u + 0x40u),
}};

__attribute__((noinline))
void write_register(volatile uint32_t *reg, uint32_t val) {{
    *reg = {transform};
}}

int main(void) {{
    uint32_t idx = (ADC_DR >> 2) & 0x03u;
    write_register(g_mmio_regs[idx % 3u], ADC_DR + {p['reg_offset']}u);
    return 0;
}}
"""


def _render_format(spec: VariantSpec) -> str:
    p = spec.params
    if p["api"] == "snprintf":
        call = f"snprintf(g_log_buf, sizeof(g_log_buf), fmt);"
    else:
        call = "sprintf(g_log_buf, fmt);"

    wrapper = ""
    invoke = "log_message(cmd_buf);"
    if p["wrapper_depth"] >= 1:
        wrapper += """
__attribute__((noinline))
static void log_wrapper_1(const char *fmt) {
    log_message(fmt);
}
"""
        invoke = "log_wrapper_1(cmd_buf);"
    if p["wrapper_depth"] >= 2:
        wrapper += """
__attribute__((noinline))
static void log_wrapper_2(const char *fmt) {
    log_wrapper_1(fmt);
}
"""
        invoke = "log_wrapper_2(cmd_buf);"

    return f"""#include <stdint.h>
#include <stdio.h>

{COMMON_VECTOR_TABLE}

#define USART_SR (*(volatile uint32_t *)0x40013800u)
#define USART_DR (*(volatile uint32_t *)0x40013804u)

static uint8_t uart_read_byte(void) {{
    while (!(USART_SR & 0x20u)) {{}}
    return (uint8_t)(USART_DR & 0xFFu);
}}

static char g_log_buf[{p['log_size']}];

__attribute__((noinline))
void log_message(const char *fmt) {{
    {call}
}}
{wrapper}
int main(void) {{
    char cmd_buf[48];
    for (unsigned int i = 0; i < sizeof(cmd_buf) - 1; i++) {{
        uint8_t c = uart_read_byte();
        if (c == '\\n' || c == 0) {{
            cmd_buf[i] = 0;
            break;
        }}
        cmd_buf[i] = (char)c;
        cmd_buf[i + 1] = 0;
    }}
    {invoke}
    return 0;
}}
"""


def _render_func_ptr(spec: VariantSpec) -> str:
    p = spec.params
    handlers = "\n".join(
        f"static void cmd_{idx}(void) {{ g_state ^= 0x{(idx + 1) * 17:02x}u; }}"
        for idx in range(p["table_size"])
    )
    table = ",\n    ".join(f"cmd_{idx}" for idx in range(p["table_size"]))
    wrapper = ""
    invoke = "dispatch_command(cmd_id);"
    if p["wrapper_depth"] >= 1:
        wrapper += """
__attribute__((noinline))
static void dispatch_wrapper_1(uint8_t cmd_id) {
    dispatch_command(cmd_id);
}
"""
        invoke = "dispatch_wrapper_1(cmd_id);"
    if p["wrapper_depth"] >= 2:
        wrapper += """
__attribute__((noinline))
static void dispatch_wrapper_2(uint8_t cmd_id) {
    dispatch_wrapper_1(cmd_id);
}
"""
        invoke = "dispatch_wrapper_2(cmd_id);"
    return f"""#include <stdint.h>

{COMMON_VECTOR_TABLE}

#define USART_SR (*(volatile uint32_t *)0x40011000u)
#define USART_DR (*(volatile uint32_t *)0x40011004u)

static uint8_t uart_read_byte(void) {{
    while (!(USART_SR & 0x20u)) {{}}
    return (uint8_t)(USART_DR & 0xFFu);
}}

static volatile uint32_t g_state;
{handlers}

typedef void (*cmd_handler_t)(void);
static const cmd_handler_t cmd_table[{p['table_size']}] = {{
    {table}
}};

__attribute__((noinline))
void dispatch_command(uint8_t cmd_id) {{
    cmd_handler_t handler = cmd_table[(uint32_t)cmd_id + {p['mask_bias']}u];
    handler();
}}
{wrapper}
int main(void) {{
    uint8_t cmd_id = uart_read_byte();
    {invoke}
    return 0;
}}
"""


def _render_source(spec: VariantSpec) -> str:
    if spec.family == "copy":
        return _render_copy(spec)
    if spec.family == "memset":
        return _render_memset(spec)
    if spec.family == "loop_write":
        return _render_loop(spec)
    if spec.family == "store":
        return _render_store(spec)
    if spec.family == "format":
        return _render_format(spec)
    if spec.family == "func_ptr":
        return _render_func_ptr(spec)
    raise ValueError(f"Unknown family: {spec.family}")


def _variant_paths(stem: str) -> Dict[str, Path]:
    return {
        "source": AUTOGEN_ROOT / f"{stem}.c",
        "elf": AUTOGEN_ROOT / f"{stem}.elf",
        "stripped": AUTOGEN_ROOT / f"{stem}_stripped.elf",
        "bin": AUTOGEN_ROOT / f"{stem}.bin",
        "map": AUTOGEN_ROOT / f"{stem}.map",
    }


def _write_sources(specs: List[VariantSpec]) -> None:
    AUTOGEN_ROOT.mkdir(parents=True, exist_ok=True)
    for spec in specs:
        paths = _variant_paths(spec.binary_stem)
        paths["source"].write_text(_render_source(spec), encoding="utf-8")


def _build_one(spec: VariantSpec) -> Dict[str, Any]:
    paths = _variant_paths(spec.binary_stem)
    cmd = [
        str(CC),
        *CFLAGS,
        "-T",
        str(LINKER_SCRIPT),
        f"-Wl,-Map,{paths['map']}",
        *LDFLAGS,
        "-o",
        str(paths["elf"]),
        str(paths["source"]),
        "-lc",
        "-lgcc",
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    shutil.copy2(paths["elf"], paths["stripped"])
    subprocess.run([str(STRIP), "--strip-all", str(paths["stripped"])], check=True, capture_output=True, text=True)
    subprocess.run(
        [str(OBJCOPY), "-O", "binary", str(paths["stripped"]), str(paths["bin"])],
        check=True,
        capture_output=True,
        text=True,
    )
    nm_out = subprocess.run([str(NM), str(paths["elf"])], check=True, capture_output=True, text=True).stdout
    addr = None
    for line in nm_out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == spec.sink_function:
            addr = int(parts[0], 16)
            break
    if addr is None:
        raise RuntimeError(f"Failed to resolve sink function {spec.sink_function} in {paths['elf']}")
    return {
        "binary_stem": spec.binary_stem,
        "family": spec.family,
        "sink_label": spec.sink_label,
        "sink_function": spec.sink_function,
        "sink_address": addr,
        "sink_address_hex": f"0x{addr:08x}",
        "description": spec.description,
        "params": spec.params,
    }


def _build_variants(specs: List[VariantSpec], jobs: int) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        future_map = {executor.submit(_build_one, spec): spec for spec in specs}
        for future in as_completed(future_map):
            results.append(future.result())
    results.sort(key=lambda row: row["binary_stem"])
    return results


def _build_index(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    samples: List[Dict[str, Any]] = []
    for row in rows:
        paths = _variant_paths(row["binary_stem"])
        samples.append(
            {
                "binary_stem": row["binary_stem"],
                "family": row["family"],
                "sink_label": row["sink_label"],
                "sink_function": row["sink_function"],
                "sink_address_hex": row["sink_address_hex"],
                "description": row["description"],
                "params": row["params"],
                "source_path": str(paths["source"].relative_to(REPO_ROOT)),
                "elf_path": str(paths["elf"].relative_to(REPO_ROOT)),
                "stripped_elf_path": str(paths["stripped"].relative_to(REPO_ROOT)),
                "bin_path": str(paths["bin"].relative_to(REPO_ROOT)),
                "map_path": str(paths["map"].relative_to(REPO_ROOT)),
            }
        )
    return {
        "schema_version": "1.0",
        "generated_at_utc": _now_utc(),
        "sample_count": len(samples),
        "family_count": len(FAMILIES),
        "variants_per_family": VARIANTS_PER_FAMILY,
        "samples": samples,
    }


def _build_sink_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    sink_rows: List[Dict[str, Any]] = []
    for row in rows:
        paths = _variant_paths(row["binary_stem"])
        sink_rows.append(
            {
                "binary_stem": row["binary_stem"],
                "sample_id": row["binary_stem"],
                "family": row["family"],
                "label": row["sink_label"],
                "pipeline_label_hint": row["sink_label"],
                "function_name": row["sink_function"],
                "address": row["sink_address"],
                "address_hex": row["sink_address_hex"],
                "address_status": "resolved",
                "notes": row["description"],
                "source_file": paths["source"].name,
                "map_file": paths["map"].name,
                "binary_path": str(paths["elf"]),
                "stripped_binary_path": str(paths["stripped"]),
                "gt_level": "L1",
            }
        )
    return sink_rows


def _build_eval_manifests(rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    unstripped_samples: List[Dict[str, Any]] = []
    stripped_samples: List[Dict[str, Any]] = []
    for row in rows:
        paths = _variant_paths(row["binary_stem"])
        unstripped_samples.append(
            {
                "dataset": "microbench_autogen",
                "sample_id": row["binary_stem"],
                "gt_stem": row["binary_stem"],
                "output_stem": row["binary_stem"],
                "binary_path": str(paths["elf"]),
                "notes": row["family"],
            }
        )
        stripped_samples.append(
            {
                "dataset": "microbench_autogen",
                "sample_id": row["binary_stem"],
                "gt_stem": row["binary_stem"],
                "output_stem": f"{row['binary_stem']}_stripped",
                "binary_variant": "stripped",
                "binary_path": str(paths["stripped"]),
                "unstripped_binary_path": str(paths["elf"]),
                "stripped_binary_path": str(paths["stripped"]),
                "stripped_status": "ready",
                "stripped_origin": "generated",
                "notes": row["family"],
            }
        )
    return {
        "unstripped": {
            "name": "microbench_autogen_unstripped",
            "created_at": _now_utc(),
            "count": len(unstripped_samples),
            "description": "Auto-generated L1 microbench variant corpus (unstripped).",
            "samples": unstripped_samples,
        },
        "stripped": {
            "name": "microbench_autogen_stripped",
            "created_at": _now_utc(),
            "count": len(stripped_samples),
            "description": "Auto-generated L1 microbench variant corpus (stripped).",
            "samples": stripped_samples,
        },
    }


def _build_combined_l1(sink_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    gt_backed_path = GROUND_TRUTH_ROOT / "normalized_gt_sinks_gt_backed.json"
    gt_backed_rows: List[Dict[str, Any]] = []
    if gt_backed_path.exists():
        gt_backed_rows = json.loads(gt_backed_path.read_text(encoding="utf-8"))
    combined_rows = list(gt_backed_rows) + list(sink_rows)

    combined_manifest_samples: List[Dict[str, Any]] = []
    for row in gt_backed_rows:
        combined_manifest_samples.append(
            {
                "dataset": row["dataset"],
                "sample_id": row["sample_id"],
                "gt_stem": row["sample_id"],
                "output_stem": f"{row['sample_id']}_stripped",
                "binary_path": row["stripped_binary_path"],
                "notes": "gt_backed_l1",
            }
        )
    for row in sink_rows:
        combined_manifest_samples.append(
            {
                "dataset": "microbench_autogen",
                "sample_id": row["sample_id"],
                "gt_stem": row["sample_id"],
                "output_stem": f"{row['sample_id']}_stripped",
                "binary_path": row["stripped_binary_path"],
                "notes": row["family"],
            }
        )

    dedup = {}
    for sample in combined_manifest_samples:
        dedup[(sample["dataset"], sample["sample_id"])] = sample

    return {
        "rows": combined_rows,
        "manifest": {
            "name": "l1_sink_only_combined",
            "created_at": _now_utc(),
            "count": len(dedup),
            "description": "Combined L1 sink-only corpus: GT-backed sink GT + auto-generated microbench variants.",
            "samples": sorted(dedup.values(), key=lambda row: (row["dataset"], row["sample_id"])),
        },
    }


def generate_microbench_autogen(repo_root: Path | None = None, jobs: int = 8) -> Dict[str, Any]:
    if repo_root is not None and repo_root != REPO_ROOT:
        raise ValueError("Only the checked-out repository root is supported")

    _require_toolchain()
    AUTOGEN_ROOT.mkdir(parents=True, exist_ok=True)
    AUTOGEN_GT_ROOT.mkdir(parents=True, exist_ok=True)

    specs = _make_variant_specs()
    _write_sources(specs)
    build_rows = _build_variants(specs, jobs=max(1, jobs))

    index_payload = _build_index(build_rows)
    sink_rows = _build_sink_rows(build_rows)
    manifests = _build_eval_manifests(build_rows)
    combined_l1 = _build_combined_l1(sink_rows)

    _write_json(AUTOGEN_GT_ROOT / "index.json", index_payload)
    _write_json(GROUND_TRUTH_ROOT / "normalized_gt_sinks_microbench_autogen.json", sink_rows)
    _write_csv(
        GROUND_TRUTH_ROOT / "normalized_gt_sinks_microbench_autogen.csv",
        sink_rows,
        fieldnames=[
            "binary_stem",
            "sample_id",
            "family",
            "label",
            "pipeline_label_hint",
            "function_name",
            "address",
            "address_hex",
            "address_status",
            "notes",
            "source_file",
            "map_file",
            "binary_path",
            "stripped_binary_path",
            "gt_level",
        ],
    )
    _write_json(EVAL_SUITE_ROOT / "microbench_autogen_unstripped_manifest.json", manifests["unstripped"])
    _write_json(EVAL_SUITE_ROOT / "microbench_autogen_stripped_manifest.json", manifests["stripped"])
    _write_json(GROUND_TRUTH_ROOT / "normalized_gt_sinks_l1_combined.json", combined_l1["rows"])
    _write_csv(
        GROUND_TRUTH_ROOT / "normalized_gt_sinks_l1_combined.csv",
        combined_l1["rows"],
        fieldnames=sorted({key for row in combined_l1["rows"] for key in row.keys()}),
    )
    _write_json(EVAL_SUITE_ROOT / "l1_sink_only_combined_manifest.json", combined_l1["manifest"])

    return {
        "sample_count": index_payload["sample_count"],
        "family_count": index_payload["family_count"],
        "l1_binary_count": combined_l1["manifest"]["count"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the microbench auto-variant corpus.")
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 4))
    args = parser.parse_args()
    summary = generate_microbench_autogen(Path(args.repo_root).resolve(), jobs=args.jobs)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
