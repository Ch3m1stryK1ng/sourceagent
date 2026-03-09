"""SourceAgent CLI — entry point for source/sink label recovery.

Subcommands:
  sourceagent mine <binary>          # Run full mining pipeline
  sourceagent mine <binary> --stage 3  # Run up to Stage N
  sourceagent eval <binary>          # Evaluate against ground truth
  sourceagent eval --all <dir>       # Batch evaluation
"""

import argparse
import asyncio
import csv
import json
import logging
import os
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from sourceagent.config.constants import APP_NAME, APP_VERSION
from sourceagent.pipeline.verdict_calibration import (
    DEFAULT_ALLOW_MANUAL_LLM_SUPERVISION,
    DEFAULT_CALIBRATION_MODE,
    DEFAULT_LLM_DEMOTE_BUDGET,
    DEFAULT_LLM_PROMOTE_BUDGET,
    DEFAULT_LLM_SOFT_BUDGET,
    DEFAULT_MAX_CALIBRATION_CHAINS,
    DEFAULT_MIN_RISK_SCORE,
    DEFAULT_REVIEW_NEEDS_THRESHOLD,
    DEFAULT_SAMPLE_SUSPICIOUS_RATIO_THRESHOLD,
    DEFAULT_VERDICT_OUTPUT_MODE,
    load_review_decisions,
)

logger = logging.getLogger("sourceagent.pipeline")


def _add_verdict_calibration_args(parser):
    parser.add_argument(
        "--calibration-mode",
        default=DEFAULT_CALIBRATION_MODE,
        choices=["exact_mismatch", "suspicious_only", "all_non_exact", "audit_only", "all_matched"],
        help="Select which structurally matched chains enter verdict calibration (default: %(default)s)",
    )
    parser.add_argument(
        "--verdict-output-mode",
        default=DEFAULT_VERDICT_OUTPUT_MODE,
        choices=["strict", "soft", "dual"],
        help="Write strict/soft/dual verdict calibration outputs (default: %(default)s)",
    )
    parser.add_argument(
        "--max-calibration-chains",
        type=int,
        default=DEFAULT_MAX_CALIBRATION_CHAINS,
        help="Maximum chains per binary admitted to the verdict calibration queue (default: %(default)s)",
    )
    parser.add_argument(
        "--sample-suspicious-ratio-threshold",
        type=float,
        default=DEFAULT_SAMPLE_SUSPICIOUS_RATIO_THRESHOLD,
        help="Sample-level suspicious ratio threshold for queue widening (default: %(default)s)",
    )
    parser.add_argument(
        "--min-risk-score",
        type=float,
        default=DEFAULT_MIN_RISK_SCORE,
        help="Minimum deterministic risk score for soft widening candidates (default: %(default)s)",
    )
    parser.add_argument(
        "--review-needs-threshold",
        type=float,
        default=DEFAULT_REVIEW_NEEDS_THRESHOLD,
        help="Risk-score threshold for marking a chain as review-needed (default: %(default)s)",
    )
    parser.add_argument(
        "--allow-manual-llm-supervision",
        action="store_true",
        default=DEFAULT_ALLOW_MANUAL_LLM_SUPERVISION,
        help="Allow externally supplied LLM/BinAgent review decisions to adjust soft verdicts",
    )
    parser.add_argument(
        "--llm-promote-budget",
        type=int,
        default=DEFAULT_LLM_PROMOTE_BUDGET,
        help="Per-binary promotion budget for accepted external verdict suggestions (default: %(default)s)",
    )
    parser.add_argument(
        "--llm-demote-budget",
        type=int,
        default=DEFAULT_LLM_DEMOTE_BUDGET,
        help="Per-binary demotion budget for accepted external verdict suggestions (default: %(default)s)",
    )
    parser.add_argument(
        "--llm-soft-budget",
        type=int,
        default=DEFAULT_LLM_SOFT_BUDGET,
        help="Per-binary deterministic soft-widen budget for DROP -> SUSPICIOUS triage (default: %(default)s)",
    )
    parser.add_argument(
        "--verdict-review-json",
        default=None,
        help="Optional JSON file containing external LLM/BinAgent review decisions for stage-10 verdict calibration",
    )


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="sourceagent",
        description=f"{APP_NAME} v{APP_VERSION} — Semantic source/sink label recovery for monolithic firmware",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    subparsers = parser.add_subparsers(dest="command")

    # mine subcommand
    mine_parser = subparsers.add_parser("mine", help="Run source/sink mining pipeline")
    mine_parser.add_argument("binary", help="Path to firmware .bin or .elf")
    mine_parser.add_argument(
        "--stage", type=int, default=7,
        help="Run pipeline up to this stage (1-10, default: 7)",
    )
    mine_parser.add_argument("--model", "-m", default=None, help="LLM model for Stage 6 (enables LLM mode)")
    mine_parser.add_argument("--run-id", default=None, help="Custom run ID")
    mine_parser.add_argument(
        "--offline", action="store_true",
        help="Skip Ghidra MCP (stages 2+ that require MCP become no-ops)",
    )
    mine_parser.add_argument(
        "--analysis-wait-sec", type=int, default=60,
        help="Max seconds to wait for Ghidra analysis completion before proceeding (default: 60)",
    )
    mine_parser.add_argument(
        "--mcp-connect-timeout-sec", type=int, default=30,
        help="Max seconds to wait for MCP server connection (default: 30)",
    )

    _add_verdict_calibration_args(mine_parser)
    mine_parser.add_argument(
        "--output", "-o", default=None,
        help="Write JSON results to this file",
    )

    mine_parser.add_argument(
        "--export", default=None, metavar="DIR",
        help="Export facts bundle (labels.jsonl + index.json) to DIR",
    )

    # export subcommand
    export_parser = subparsers.add_parser("export", help="Export facts bundle from JSON results")
    export_parser.add_argument("input", help="Pipeline result JSON file (from mine --output)")
    export_parser.add_argument("output_dir", help="Directory to write facts bundle")
    export_parser.add_argument(
        "--verdicts", default="VERIFIED,PARTIAL",
        help="Comma-separated verdicts to include (default: VERIFIED,PARTIAL)",
    )

    # eval subcommand
    eval_parser = subparsers.add_parser("eval", help="Evaluate against ground truth")
    eval_parser.add_argument("binary", nargs="?", help="Specific binary to evaluate")
    eval_parser.add_argument(
        "--all", metavar="DIR",
        help="Batch evaluate binaries in DIR",
    )
    eval_parser.add_argument(
        "--manifest-json", default=None,
        help="Optional manifest JSON describing a mixed binary suite",
    )
    eval_parser.add_argument(
        "--formats", default="bin,elf",
        help="Comma-separated formats for --all (default: bin,elf)",
    )
    eval_parser.add_argument(
        "--only-unstripped-elf", action="store_true",
        help="Keep only ELF files whose stem does not contain 'stripped'",
    )
    eval_parser.add_argument(
        "--stage", type=int, default=7,
        help="Run pipeline up to this stage when evaluation needs a fresh run (1-10, default: 7)",
    )
    eval_parser.add_argument(
        "--online", action="store_true",
        help="Enable online mode (default eval is offline)",
    )
    eval_parser.add_argument(
        "--model", "-m", default=None,
        help="LLM model for Stage 6 (enables LLM proposer mode)",
    )
    eval_parser.add_argument(
        "--accept-verdicts", default="VERIFIED,PARTIAL",
        help="Comma-separated verdicts counted as positive (default: VERIFIED,PARTIAL)",
    )
    eval_parser.add_argument(
        "--partial-credit", type=float, default=0.5,
        help="Credit value for near-miss sink-family matches in weighted scoring (default: 0.5)",
    )
    eval_parser.add_argument(
        "--output-dir", default=None,
        help="Write detailed eval artifacts (raw pipeline JSON, scoring, FP stats) to this directory",
    )
    eval_parser.add_argument(
        "--gt-json", default=None,
        help="Optional ground-truth JSON file (list or map of GroundTruthEntry-like objects)",
    )
    eval_parser.add_argument(
        "--eval-scope", default="auto", choices=["auto", "all", "sinks", "sources"],
        help="Filter evaluation to sinks/sources/all. auto infers from GT labels (default: auto)",
    )
    eval_parser.add_argument(
        "--sample-timeout", type=int, default=240,
        help="Per-sample timeout in seconds for eval runs (0 disables timeout, default: 240)",
    )
    eval_parser.add_argument(
        "--analysis-wait-sec", type=int, default=60,
        help="Max seconds to wait for Ghidra analysis completion per sample (default: 60)",
    )
    eval_parser.add_argument(
        "--mcp-connect-timeout-sec", type=int, default=30,
        help="Max seconds to wait for MCP server connection per sample (default: 30)",
    )

    _add_verdict_calibration_args(eval_parser)

    # gt-sinks subcommand
    gt_sinks_parser = subparsers.add_parser(
        "gt-sinks",
        help="Generate normalized machine-readable GT sink list from microbench",
    )
    gt_sinks_parser.add_argument(
        "--microbench-dir",
        default="firmware/microbench",
        help="Microbench directory containing .map files (default: firmware/microbench)",
    )
    gt_sinks_parser.add_argument(
        "--output-json",
        default="firmware/ground_truth_bundle/normalized_gt_sinks.json",
        help="Output JSON path (default: firmware/ground_truth_bundle/normalized_gt_sinks.json)",
    )
    gt_sinks_parser.add_argument(
        "--output-csv",
        default="firmware/ground_truth_bundle/normalized_gt_sinks.csv",
        help="Output CSV path (default: firmware/ground_truth_bundle/normalized_gt_sinks.csv)",
    )

    # gt-sources subcommand
    gt_sources_parser = subparsers.add_parser(
        "gt-sources",
        help="Generate normalized machine-readable GT source list for microbench/CVE set",
    )
    gt_sources_parser.add_argument(
        "--output-json",
        default="firmware/ground_truth_bundle/normalized_gt_sources.json",
        help="Output JSON path (default: firmware/ground_truth_bundle/normalized_gt_sources.json)",
    )
    gt_sources_parser.add_argument(
        "--output-csv",
        default="firmware/ground_truth_bundle/normalized_gt_sources.csv",
        help="Output CSV path (default: firmware/ground_truth_bundle/normalized_gt_sources.csv)",
    )

    # gt-bundle subcommand
    gt_bundle_parser = subparsers.add_parser(
        "gt-bundle",
        help="Generate combined normalized GT bundle (sources + sinks)",
    )
    gt_bundle_parser.add_argument(
        "--microbench-dir",
        default="firmware/microbench",
        help="Microbench directory containing .map files (default: firmware/microbench)",
    )
    gt_bundle_parser.add_argument(
        "--output-json",
        default="firmware/ground_truth_bundle/normalized_gt_bundle.json",
        help="Output JSON path (default: firmware/ground_truth_bundle/normalized_gt_bundle.json)",
    )
    gt_bundle_parser.add_argument(
        "--output-csv",
        default="firmware/ground_truth_bundle/normalized_gt_bundle.csv",
        help="Output CSV path (default: firmware/ground_truth_bundle/normalized_gt_bundle.csv)",
    )

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s: %(message)s")

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    _quiet_asyncio_run(_dispatch(args))


async def _dispatch(args):
    """Dispatch to the appropriate subcommand handler."""
    if args.command == "mine":
        await _cmd_mine(args)
    elif args.command == "export":
        await _cmd_export(args)
    elif args.command == "eval":
        await _cmd_eval(args)
    elif args.command == "gt-sinks":
        await _cmd_gt_sinks(args)
    elif args.command == "gt-sources":
        await _cmd_gt_sources(args)
    elif args.command == "gt-bundle":
        await _cmd_gt_bundle(args)


# ── Pipeline Orchestrator ──────────────────────────────────────────────────


async def _cmd_mine(args):
    """Run the mining pipeline on a binary.

    Stages:
      1  M1  — Load binary, produce MemoryMap
      2  M2  — Build MemoryAccessIndex (Ghidra MCP)
      3  VS0 — Mine MMIO_READ sources
         VS2 — Mine ISR sources (ISR_MMIO_READ, ISR_FILLED_BUFFER)
         VS3 — Mine DMA_BACKED_BUFFER sources
      4  VS1 — Mine COPY_SINK sinks (Ghidra MCP)
      5  M5  — Pack evidence
      6  M6  — Propose labels (heuristic or LLM)
      7  M7  — Verify proposals
      8  M8  — Build channel graph + refined objects
      9  M9  — Extract sink roots + link chains + chain eval
      10 M10 — Build low-conf sink list + triage queue
    """
    from sourceagent.pipeline.models import PipelineResult

    binary_path = Path(args.binary).resolve()
    if not binary_path.exists():
        print(f"Error: binary not found: {binary_path}")
        sys.exit(1)

    run_id = args.run_id or f"run-{binary_path.stem}-{int(time.time())}"
    max_stage = args.stage
    if max_stage < 1 or max_stage > 10:
        print("Error: --stage must be in [1, 10]")
        sys.exit(1)
    offline = args.offline

    result = PipelineResult(binary_path=str(binary_path), run_id=run_id)
    setattr(result, "_max_stage", max_stage)

    print(f"[SourceAgent] Mining sources/sinks from: {binary_path}")
    print(f"[SourceAgent] Pipeline stages: 1-{max_stage}, run_id={run_id}")
    if offline:
        print("[SourceAgent] OFFLINE mode — Ghidra MCP disabled")

    # ── Stage 1: Load binary (M1) ────────────────────────────────────────

    memory_map = await _run_stage_1(binary_path, result)
    if memory_map is None:
        _print_result(result, args)
        return result

    result.memory_map = memory_map
    if max_stage < 2:
        _print_result(result, args)
        return result

    # ── Connect Ghidra MCP (needed for stages 2, 4) ──────────────────────

    mcp_manager = None
    ghidra_binary_name = ""

    if not offline:
        mcp_manager, ghidra_binary_name = await _connect_ghidra(
            binary_path,
            result,
            memory_map,
            analysis_wait_sec=int(getattr(args, "analysis_wait_sec", 60) or 60),
            mcp_connect_timeout_sec=int(getattr(args, "mcp_connect_timeout_sec", 30) or 30),
        )
        if mcp_manager is None:
            _print_result(result, args)
            return result

    # ── Build flash constant pointer table (for raw .bin) ──────────────
    flash_ptr_table = None
    if not offline and binary_path.suffix.lower() == ".bin" and memory_map.base_address is not None:
        from sourceagent.pipeline.flash_const_ptr import build_flash_const_ptr_table
        flash_ptr_table = build_flash_const_ptr_table(binary_path, memory_map.base_address)
        if flash_ptr_table:
            print(f"[FlashPtr] Found {len(flash_ptr_table)} flash->MMIO constant pointers")

    # ── Stage 2: Build MemoryAccessIndex (M2) ────────────────────────────

    mai = await _run_stage_2(
        memory_map, mcp_manager, ghidra_binary_name, offline, result,
        flash_ptr_table=flash_ptr_table,
    )

    if max_stage < 3:
        _print_result(result, args)
        return result

    # ── Stage 2.5: Inter-procedural constant propagation ─────────────────

    if mai is not None and mcp_manager is not None:
        mai = await _run_stage_2_5(mai, mcp_manager, ghidra_binary_name)

    # Keep MAI in-memory for downstream artifact builders.
    setattr(result, "_mai", mai)

    # ── Populate all_mmio_addrs from MAI ──────────────────────────────────
    if mai is not None:
        _populate_all_mmio_addrs(result, mai)

    # ── Stage 3: Source miners (VS0, VS2, VS3) ───────────────────────────

    sources = _run_stage_3(mai, memory_map, result)

    # ── Stage 4: Sink miners (VS1, VS4-VS5) ─────────────────────────────

    sinks = await _run_stage_4(memory_map, mcp_manager, ghidra_binary_name, offline, result, mai)

    result.source_candidates = sources
    result.sink_candidates = sinks
    print(f"[Mining] Total: {len(sources)} sources, {len(sinks)} sinks")

    if max_stage < 5:
        _print_result(result, args)
        return result

    # ── Stage 5: Evidence packing (M5) ───────────────────────────────────

    packs = _run_stage_5(sources, sinks, result)
    if packs is None:
        _print_result(result, args)
        return result

    if max_stage < 6:
        _print_result(result, args)
        return result

    # ── Stage 6: Label proposal (M6) ─────────────────────────────────────

    proposals = await _run_stage_6(packs, args, result)
    if proposals is None:
        _print_result(result, args)
        return result

    if max_stage < 7:
        _print_result(result, args)
        return result

    # ── Stage 7: Verification (M7) ───────────────────────────────────────

    await _run_stage_7(proposals, mcp_manager, ghidra_binary_name, result)

    # ── Stage 8-10: Chain artifacts / linking / triage ───────────────────
    _run_stage_8_10(result, max_stage=max_stage, args=args)

    # ── Cleanup ──────────────────────────────────────────────────────────

    if mcp_manager:
        try:
            await mcp_manager.disconnect_all()
        except Exception:
            pass

    _print_result(result, args)

    # Auto-export facts bundle if --export specified
    if getattr(args, "export", None) and result.verified_labels:
        _export_facts_bundle(result, args.export)

    return result


# ── Stage Implementations ──────────────────────────────────────────────────


async def _run_stage_1(binary_path, result):
    """Stage 1 (M1): Load binary → MemoryMap."""
    print("[Stage 1] Loading binary...")

    from sourceagent.agents.firmware_detect import detect_cortex_m_raw
    hint = detect_cortex_m_raw(str(binary_path))
    if hint:
        print(f"[Stage 1] Detected ARM Cortex-M: arch={hint['language']}, base={hint['base_address']}")
    else:
        print("[Stage 1] Warning: Could not detect ARM Cortex-M vector table")

    from sourceagent.pipeline.loader import load_binary
    try:
        memory_map = load_binary(binary_path)
    except Exception as e:
        print(f"[Stage 1] ERROR: {e}")
        result.stage_errors["M1"] = str(e)
        return None

    print(
        f"[Stage 1] MemoryMap: {len(memory_map.regions)} regions, "
        f"base=0x{memory_map.base_address:08x}, "
        f"{len(memory_map.isr_handler_addrs)} ISR handlers"
    )
    return memory_map


async def _connect_ghidra(
    binary_path,
    result,
    memory_map=None,
    analysis_wait_sec: int = 60,
    mcp_connect_timeout_sec: int = 30,
):
    """Connect to Ghidra MCP, import binary, wait for analysis.

    Returns (mcp_manager, ghidra_binary_name) on success,
    (None, "") on failure.
    """
    from sourceagent.mcp.manager import MCPManager

    # Project selection policy:
    # - default: shared project from mcp_servers.json
    # - optional override: SOURCEAGENT_GHIDRA_PROJECT_PATH
    # - optional mode: SOURCEAGENT_GHIDRA_PROJECT_MODE=isolated
    # - fallback: recently used healthy projects under /tmp/sourceagent_ghidra_projects
    old_project_env = os.environ.get("SOURCEAGENT_GHIDRA_PROJECT_PATH")
    project_mode = str(
        os.environ.get("SOURCEAGENT_GHIDRA_PROJECT_MODE", "shared") or "shared"
    ).strip().lower()
    candidate_overrides: List[Optional[str]] = []
    if old_project_env:
        candidate_overrides.append(old_project_env)
    elif project_mode == "isolated":
        project_root = Path("/tmp/sourceagent_ghidra_projects")
        isolated_project = project_root / f"{binary_path.stem}_{int(time.time())}"
        try:
            isolated_project.mkdir(parents=True, exist_ok=True)
            candidate_overrides.append(str(isolated_project))
        except Exception:
            pass
    else:
        # Primary: use configured shared project (no override).
        candidate_overrides.append(None)
        # Optional fallback: try recently used projects with local chroma DB.
        # Default OFF: stale/broken historical projects can cause long retry loops.
        use_fallback = str(
            os.environ.get("SOURCEAGENT_GHIDRA_ENABLE_FALLBACK_PROJECTS", "0")
        ).strip().lower() in {"1", "true", "yes", "y"}
        if use_fallback:
            candidate_overrides.extend(_discover_ghidra_project_overrides(limit=8))

    # De-duplicate while preserving order.
    seen: Set[str] = set()
    unique_overrides: List[Optional[str]] = []
    for item in candidate_overrides:
        key = "<default>" if item is None else str(item)
        if key in seen:
            continue
        seen.add(key)
        unique_overrides.append(item)

    try:
        last_error = ""
        for idx, override in enumerate(unique_overrides, start=1):
            if override:
                os.environ["SOURCEAGENT_GHIDRA_PROJECT_PATH"] = str(override)
                print(
                    "[Ghidra] Connecting to MCP server... "
                    f"(project override {idx}/{len(unique_overrides)})"
                )
            else:
                os.environ.pop("SOURCEAGENT_GHIDRA_PROJECT_PATH", None)
                print(
                    "[Ghidra] Connecting to MCP server... "
                    f"(default project {idx}/{len(unique_overrides)})"
                )

            mcp_manager = MCPManager()
            try:
                ghidra_server = await _connect_ghidra_server_only(
                    mcp_manager,
                    timeout_sec=max(1, int(mcp_connect_timeout_sec)),
                )
            except asyncio.TimeoutError:
                last_error = (
                    "MCP connect timeout after "
                    f"{max(1, int(mcp_connect_timeout_sec))}s"
                )
                try:
                    await mcp_manager.disconnect_all()
                except Exception:
                    pass
                continue
            except Exception as e:
                last_error = str(e)
                try:
                    await mcp_manager.disconnect_all()
                except Exception:
                    pass
                continue

            if not ghidra_server:
                last_error = (
                    "MCP connect timeout after "
                    f"{max(1, int(mcp_connect_timeout_sec))}s"
                )
                try:
                    await mcp_manager.disconnect_all()
                except Exception:
                    pass
                continue

            print(f"[Ghidra] Connected to server: {ghidra_server}")

            # Import binary
            ghidra_binary_name = await _import_and_analyze(
                mcp_manager, ghidra_server, binary_path,
                memory_map=memory_map,
                max_wait=float(analysis_wait_sec),
            )
            if not ghidra_binary_name:
                last_error = "Ghidra import failed"
                try:
                    await mcp_manager.disconnect_all()
                except Exception:
                    pass
                continue

            print(f"[Ghidra] Binary loaded: {ghidra_binary_name}")

            # Set up firmware memory context in Ghidra (ISR entry points, memory regions)
            # For .bin files: create memory regions + ISR entry points
            # For .elf files: only add ISR entry points (regions already set by ELF loader)
            if memory_map is not None and ghidra_server:
                has_isr = bool(memory_map.isr_handler_addrs)
                is_bin = binary_path.suffix.lower() == ".bin"
                if is_bin or has_isr:
                    await _setup_firmware_context(
                        mcp_manager, ghidra_server, ghidra_binary_name, memory_map,
                        skip_regions=(not is_bin),
                    )

            return mcp_manager, ghidra_binary_name

        if not last_error:
            last_error = (
                "MCP connect timeout after "
                f"{max(1, int(mcp_connect_timeout_sec))}s"
            )
        print(f"[Ghidra] ERROR connecting: {last_error}")
        result.stage_errors["MCP"] = last_error
        return None, ""
    finally:
        if old_project_env is None:
            os.environ.pop("SOURCEAGENT_GHIDRA_PROJECT_PATH", None)
        else:
            os.environ["SOURCEAGENT_GHIDRA_PROJECT_PATH"] = old_project_env


def _discover_ghidra_project_overrides(limit: int = 8) -> List[str]:
    """Discover likely-healthy Ghidra project paths for fallback connection."""
    root = Path("/tmp/sourceagent_ghidra_projects")
    if not root.exists():
        return []
    candidates: List[tuple[float, str]] = []
    try:
        for p in root.iterdir():
            if not p.is_dir():
                continue
            stem = p.name
            if not (p / f"{stem}.gpr").exists():
                continue
            if not (p / f"{stem}.rep").exists():
                continue
            if not (p / "chromadb" / "chroma.sqlite3").exists():
                continue
            try:
                mtime = p.stat().st_mtime
            except Exception:
                mtime = 0.0
            candidates.append((mtime, str(p)))
    except Exception:
        return []

    candidates.sort(key=lambda x: x[0], reverse=True)
    return [path for _, path in candidates[:max(1, int(limit))]]


async def _connect_ghidra_server_only(mcp_manager, timeout_sec: int = 30) -> Optional[str]:
    """Connect only ghidra-like MCP servers to avoid unrelated server stalls."""
    timeout_cap = str(max(1, int(timeout_sec)))
    old_timeout_cap = os.environ.get("SOURCEAGENT_MCP_CONNECT_TIMEOUT_SEC")
    os.environ["SOURCEAGENT_MCP_CONNECT_TIMEOUT_SEC"] = timeout_cap

    try:
        candidates: List[str] = []
        try:
            for item in mcp_manager.list_configured_servers():
                name = str(item.get("name", "") or "")
                command = str(item.get("command", "") or "")
                args = " ".join(item.get("args", []) or [])
                enabled = bool(item.get("enabled", True))
                if not enabled:
                    continue
                if (
                    "ghidra" in name.lower()
                    or "pyghidra-mcp" in command
                    or "pyghidra-mcp" in args
                ):
                    candidates.append(name)
        except Exception:
            candidates = []

        # Fallback to legacy connect_all path if config inspection fails.
        if not candidates:
            await asyncio.wait_for(
                mcp_manager.connect_all(),
                timeout=max(1, int(timeout_sec)),
            )
            return _find_ghidra_server(mcp_manager)

        attempts = 3
        for attempt in range(1, attempts + 1):
            for name in candidates:
                try:
                    server = await asyncio.wait_for(
                        mcp_manager.connect_server(name),
                        timeout=max(1, int(timeout_sec)),
                    )
                except Exception:
                    continue
                if server and getattr(server, "connected", False):
                    return name

            if attempt < attempts:
                try:
                    await mcp_manager.disconnect_all()
                except Exception:
                    pass
                await asyncio.sleep(2.0 * attempt)

        return None
    finally:
        if old_timeout_cap is None:
            os.environ.pop("SOURCEAGENT_MCP_CONNECT_TIMEOUT_SEC", None)
        else:
            os.environ["SOURCEAGENT_MCP_CONNECT_TIMEOUT_SEC"] = old_timeout_cap


def _find_ghidra_server(mcp_manager) -> Optional[str]:
    """Find the first connected Ghidra MCP server name."""
    for name, server in mcp_manager.servers.items():
        if not server.connected:
            continue
        low = name.lower()
        if "ghidra" in low:
            return name
        # Check tool names for ghidra-specific tools
        tool_names = {t.get("name", "") for t in server.tools}
        if "decompile_function" in tool_names and "import_binary" in tool_names:
            return name
    return None


async def _setup_firmware_context(
    mcp_manager, server_name, ghidra_binary_name, memory_map,
    skip_regions: bool = False,
):
    """Create memory blocks and seed ISR entry points in Ghidra.

    For raw .bin files: creates memory regions + ISR entry points.
    For .elf files: only adds ISR entry points (skip_regions=True).
    """
    # Build regions list from MemoryMap (exclude FLASH — already exists from import)
    regions = []
    if not skip_regions:
        for r in memory_map.regions:
            if r.kind == "flash":
                continue  # Ghidra already has the flash block from import
            regions.append({
                "name": r.name,
                "base": f"0x{r.base:08x}",
                "size": f"0x{r.size:x}",
                "perms": r.permissions,
            })

    # Build entry points from ISR handler addresses
    entry_points = [f"0x{addr:08x}" for addr in memory_map.isr_handler_addrs if addr != 0]

    if not regions and not entry_points:
        return

    args = {"binary_name": ghidra_binary_name}
    if regions:
        args["regions"] = regions
    if entry_points:
        args["entry_points"] = entry_points

    try:
        result = await mcp_manager.call_tool(server_name, "setup_firmware_context", args)
        data = _parse_mcp_content(result)
        if data:
            print(
                f"[Ghidra] Firmware context: "
                f"{len(data.get('memory_blocks_created', []))} blocks, "
                f"{data.get('entry_points_added', 0)} entry points, "
                f"{data.get('functions_created', 0)} functions created"
            )
            if data.get("errors"):
                for err in data["errors"]:
                    logger.warning("[Ghidra] setup_firmware_context: %s", err)
    except Exception as e:
        logger.warning("setup_firmware_context failed (non-fatal): %s", e)

    # Wait briefly for re-analysis to complete
    await asyncio.sleep(10)


async def _import_and_analyze(
    mcp_manager, server_name: str, binary_path: Path,
    max_wait: float = 60, poll_interval: float = 3,
    memory_map=None,
) -> Optional[str]:
    """Import a binary into Ghidra and wait for analysis to complete.

    Returns the Ghidra binary name (with hash suffix) or None on failure.
    For raw .bin files, pass memory_map to provide language and base address hints.
    """
    binary_stem = binary_path.stem

    # Check if already imported and analyzed
    existing = await _find_binary_in_project(
        mcp_manager, server_name, binary_stem, require_analyzed=True,
    )
    if existing:
        logger.info("Binary already analyzed in Ghidra project: %s", existing)
        return existing

    # Check if imported but still analyzing — skip re-import, just poll
    existing_unanalyzed = await _find_binary_in_project(
        mcp_manager, server_name, binary_stem, require_analyzed=False,
    )
    if not existing_unanalyzed:
        # Import fresh — for raw .bin files, provide language/base hints
        import_args: Dict[str, Any] = {"binary_path": str(binary_path)}
        if binary_path.suffix.lower() == ".bin" and memory_map is not None:
            if memory_map.arch:
                import_args["language"] = memory_map.arch
            if memory_map.base_address is not None:
                import_args["base_address"] = f"0x{memory_map.base_address:x}"
        try:
            await mcp_manager.call_tool(server_name, "import_binary", import_args)
        except Exception as e:
            logger.error("import_binary failed: %s", e)
            return None
    else:
        logger.info("Binary in Ghidra project, waiting for analysis: %s", existing_unanalyzed)

    # Poll for analysis completion
    start = time.time()
    while time.time() - start < max_wait:
        await asyncio.sleep(poll_interval)
        name = await _find_binary_in_project(
            mcp_manager, server_name, binary_stem, require_analyzed=True,
        )
        if name:
            return name
        logger.debug("Waiting for Ghidra analysis... (%.0fs)", time.time() - start)

    # Timeout — try to use the binary even if analysis isn't complete
    name = await _find_binary_in_project(mcp_manager, server_name, binary_stem)
    if name:
        logger.warning("Analysis not confirmed complete after %.0fs, proceeding anyway", max_wait)
        return name

    return None


async def _find_binary_in_project(
    mcp_manager, server_name: str, stem: str, require_analyzed: bool = False,
) -> Optional[str]:
    """Find a binary in the Ghidra project by stem name."""
    try:
        result = await mcp_manager.call_tool(
            server_name, "list_project_binaries", {},
        )
    except Exception:
        return None

    # Parse MCP content blocks
    data = _parse_mcp_content(result)
    if not data:
        return None

    programs = data.get("programs", [])
    # Exact stem match. Ghidra names can be:
    #   "foo.elf-abc123" → stem "foo"
    #   "foo-abc123"     → stem "foo" (strip hash suffix)
    # This prevents "t0_format_string" from matching "t0_format_string_stripped".
    for prog in programs:
        name = prog.get("name", "")
        clean_name = name.lstrip("/")
        # Extract stem: "foo.elf-abc123" → "foo", "foo-abc123" → "foo"
        if "." in clean_name:
            ghidra_stem = clean_name.split(".")[0]
        else:
            # No extension: strip trailing -hash (6+ hex chars)
            ghidra_stem = re.sub(r'-[0-9a-f]{6,}$', '', clean_name)
        if ghidra_stem == stem:
            if require_analyzed and not prog.get("analysis_complete", False):
                continue
            return clean_name

    return None


def _parse_mcp_content(content_blocks) -> Optional[dict]:
    """Parse JSON from MCP content blocks."""
    if not content_blocks:
        return None
    for block in content_blocks:
        if isinstance(block, dict) and block.get("type") == "text":
            try:
                return json.loads(block["text"])
            except (json.JSONDecodeError, KeyError):
                continue
    return None


def _populate_all_mmio_addrs(result, mai):
    """Populate result.all_mmio_addrs from MAI MMIO accesses.

    Builds {addr: "load"|"store"|"both"} from all resolved MMIO accesses.
    """
    addr_kinds: dict = {}
    for access in mai.mmio_accesses:
        if access.target_addr is None:
            continue
        addr = access.target_addr
        kind = access.kind  # "load" or "store"
        existing = addr_kinds.get(addr)
        if existing is None:
            addr_kinds[addr] = kind
        elif existing != kind:
            addr_kinds[addr] = "both"
    result.all_mmio_addrs = addr_kinds


async def _run_stage_2(memory_map, mcp_manager, ghidra_binary_name, offline, result,
                       flash_ptr_table=None):
    """Stage 2 (M2): Build MemoryAccessIndex via Ghidra MCP."""
    if offline or not mcp_manager:
        print("[Stage 2] Skipped (offline mode)")
        return None

    print("[Stage 2] Building MemoryAccessIndex...")
    from sourceagent.pipeline.memory_access_index import build_memory_access_index
    try:
        mai = await build_memory_access_index(
            memory_map, mcp_manager, ghidra_binary_name,
            flash_ptr_table=flash_ptr_table,
        )
        print(
            f"[Stage 2] MAI: {len(mai.accesses)} accesses, "
            f"{len(mai.mmio_accesses)} MMIO, "
            f"{len(mai.isr_functions)} ISR functions"
        )
        return mai
    except Exception as e:
        print(f"[Stage 2] ERROR: {e}")
        result.stage_errors["M2"] = str(e)
        return None


async def _run_stage_2_5(mai, mcp_manager, ghidra_binary_name):
    """Stage 2.5: Inter-procedural constant propagation for HAL struct indirection."""
    print("[Stage 2.5] Resolving ARG-provenance accesses via caller analysis...")
    from sourceagent.pipeline.interprocedural import resolve_interprocedural
    try:
        mai = await resolve_interprocedural(mai, mcp_manager, ghidra_binary_name)
        interp_count = sum(
            1 for a in mai.accesses if a.base_provenance == "INTERPROCEDURAL"
        )
        if interp_count > 0:
            print(
                f"[Stage 2.5] Resolved {interp_count} INTERPROCEDURAL accesses "
                f"(MAI: {len(mai.accesses)} total, {len(mai.mmio_accesses)} MMIO)"
            )
        else:
            print("[Stage 2.5] No additional accesses resolved")
    except Exception as e:
        print(f"[Stage 2.5] WARNING: {e}")
    return mai


def _run_stage_3(mai, memory_map, result):
    """Stage 3 (VS0, VS2, VS3): Source miners."""
    sources = []

    if mai is None:
        print("[Stage 3] Skipped (no MemoryAccessIndex)")
        return sources

    # VS0: MMIO_READ
    print("[Stage 3] Mining MMIO_READ sources (VS0)...")
    from sourceagent.pipeline.miners.mmio_read import mine_mmio_read_sources
    try:
        mmio = mine_mmio_read_sources(mai, memory_map)
        sources.extend(mmio)
        print(f"[Stage 3] VS0: {len(mmio)} MMIO_READ candidates")
    except Exception as e:
        print(f"[Stage 3] VS0 ERROR: {e}")
        result.stage_errors["VS0"] = str(e)

    # VS2: ISR context (ISR_MMIO_READ + ISR_FILLED_BUFFER)
    print("[Stage 3] Mining ISR sources (VS2)...")
    from sourceagent.pipeline.miners.isr_context import mine_isr_sources
    try:
        isr = mine_isr_sources(mai, memory_map)
        sources.extend(isr)
        print(f"[Stage 3] VS2: {len(isr)} ISR candidates")
    except Exception as e:
        print(f"[Stage 3] VS2 ERROR: {e}")
        result.stage_errors["VS2"] = str(e)

    # VS3: DMA_BACKED_BUFFER
    print("[Stage 3] Mining DMA sources (VS3)...")
    from sourceagent.pipeline.miners.dma_buffer import mine_dma_sources
    try:
        dma = mine_dma_sources(mai, memory_map)
        sources.extend(dma)
        print(f"[Stage 3] VS3: {len(dma)} DMA candidates")
    except Exception as e:
        print(f"[Stage 3] VS3 ERROR: {e}")
        result.stage_errors["VS3"] = str(e)

    return sources


async def _run_stage_4(memory_map, mcp_manager, ghidra_binary_name, offline, result, mai=None):
    """Stage 4 (VS1, VS4-VS5): Sink miners."""
    sinks = []

    if offline or not mcp_manager:
        print("[Stage 4] Skipped (offline mode)")
        return sinks

    # VS1: COPY_SINK
    print("[Stage 4] Mining COPY_SINK sinks (VS1)...")
    from sourceagent.pipeline.miners.copy_sink import mine_copy_sinks
    try:
        copy_sinks = await mine_copy_sinks(memory_map, mcp_manager, ghidra_binary_name, mai=mai)
        sinks.extend(copy_sinks)
        print(f"[Stage 4] VS1: {len(copy_sinks)} COPY_SINK candidates")
    except Exception as e:
        print(f"[Stage 4] VS1 ERROR: {e}")
        result.stage_errors["VS1"] = str(e)

    # VS4-VS5: MEMSET_SINK, STORE_SINK, LOOP_WRITE_SINK
    print("[Stage 4] Mining additional sinks (VS4-VS5)...")
    from sourceagent.pipeline.miners.additional_sinks import mine_additional_sinks
    try:
        additional = await mine_additional_sinks(
            memory_map, mcp_manager, ghidra_binary_name, mai=mai,
        )
        sinks.extend(additional)
        by_label = {}
        for s in additional:
            label = s.preliminary_label.value if hasattr(s.preliminary_label, 'value') else str(s.preliminary_label)
            by_label[label] = by_label.get(label, 0) + 1
        print(f"[Stage 4] VS4-VS5: {len(additional)} additional sinks {by_label}")
    except Exception as e:
        print(f"[Stage 4] VS4-VS5 ERROR: {e}")
        result.stage_errors["VS4"] = str(e)

    # VS6: FORMAT_STRING_SINK
    print("[Stage 4] Mining FORMAT_STRING_SINK sinks (VS6)...")
    from sourceagent.pipeline.miners.format_string_sink import mine_format_string_sinks
    try:
        fmt_sinks = await mine_format_string_sinks(
            memory_map, mcp_manager, ghidra_binary_name, mai=mai,
        )
        sinks.extend(fmt_sinks)
        print(f"[Stage 4] VS6: {len(fmt_sinks)} FORMAT_STRING_SINK candidates")
    except Exception as e:
        print(f"[Stage 4] VS6 ERROR: {e}")
        result.stage_errors["VS6"] = str(e)

    # VS7: FUNC_PTR_SINK
    print("[Stage 4] Mining FUNC_PTR_SINK sinks (VS7)...")
    from sourceagent.pipeline.miners.func_ptr_sink import mine_func_ptr_sinks
    try:
        fptr_sinks = await mine_func_ptr_sinks(
            memory_map, mcp_manager, ghidra_binary_name, mai=mai,
        )
        sinks.extend(fptr_sinks)
        print(f"[Stage 4] VS7: {len(fptr_sinks)} FUNC_PTR_SINK candidates")
    except Exception as e:
        print(f"[Stage 4] VS7 ERROR: {e}")
        result.stage_errors["VS7"] = str(e)

    return sinks


def _run_stage_5(sources, sinks, result):
    """Stage 5 (M5): Pack evidence."""
    print("[Stage 5] Packing evidence...")
    from sourceagent.pipeline.evidence_packer import pack_evidence
    try:
        packs = pack_evidence(sources, sinks)
        result.evidence_packs = packs
        print(f"[Stage 5] {len(packs)} evidence packs")
        return packs
    except Exception as e:
        print(f"[Stage 5] ERROR: {e}")
        result.stage_errors["M5"] = str(e)
        return None


async def _run_stage_6(packs, args, result):
    """Stage 6 (M6): Propose labels."""
    print("[Stage 6] Proposing labels...")
    from sourceagent.pipeline.proposer import propose_labels

    mode = "heuristic"
    llm = None
    model = args.model or ""
    if model:
        mode = "llm"
        try:
            import litellm
            llm = litellm.acompletion
        except ImportError:
            print("[Stage 6] Warning: litellm not installed, falling back to heuristic mode")
            mode = "heuristic"
            model = ""

    try:
        proposals = await propose_labels(packs, llm=llm, model=model, mode=mode)
        result.proposals = proposals
        print(f"[Stage 6] {len(proposals)} proposals (mode={mode})")
        return proposals
    except Exception as e:
        print(f"[Stage 6] ERROR: {e}")
        result.stage_errors["M6"] = str(e)
        return None


async def _run_stage_7(proposals, mcp_manager, ghidra_binary_name, result):
    """Stage 7 (M7): Verify proposals."""
    print("[Stage 7] Verifying proposals...")
    from sourceagent.pipeline.verifier import verify_proposals
    try:
        verified = await verify_proposals(proposals, mcp_manager, ghidra_binary_name)
        result.verified_labels = verified

        verdicts = {}
        for v in verified:
            key = v.verdict.value
            verdicts[key] = verdicts.get(key, 0) + 1
        print(f"[Stage 7] {len(verified)} verified — {verdicts}")
    except Exception as e:
        print(f"[Stage 7] ERROR: {e}")
        result.stage_errors["M7"] = str(e)


def _run_stage_8_10(result, *, max_stage: int, args=None):
    """Stage 8-10: build chain artifacts with staged contracts."""
    if max_stage < 8:
        return

    from sourceagent.pipeline.chain_artifacts import build_phase_a_artifacts

    print("[Stage 8] Building ChannelGraph + refined objects...")
    try:
        review_decisions = load_review_decisions(getattr(args, "verdict_review_json", None))
        artifacts = build_phase_a_artifacts(
            result,
            max_stage=max_stage,
            calibration_mode=str(getattr(args, "calibration_mode", DEFAULT_CALIBRATION_MODE) or DEFAULT_CALIBRATION_MODE),
            verdict_output_mode=str(getattr(args, "verdict_output_mode", DEFAULT_VERDICT_OUTPUT_MODE) or DEFAULT_VERDICT_OUTPUT_MODE),
            max_calibration_chains=int(getattr(args, "max_calibration_chains", DEFAULT_MAX_CALIBRATION_CHAINS) or DEFAULT_MAX_CALIBRATION_CHAINS),
            sample_suspicious_ratio_threshold=float(
                getattr(args, "sample_suspicious_ratio_threshold", DEFAULT_SAMPLE_SUSPICIOUS_RATIO_THRESHOLD)
                or DEFAULT_SAMPLE_SUSPICIOUS_RATIO_THRESHOLD
            ),
            min_risk_score=float(getattr(args, "min_risk_score", DEFAULT_MIN_RISK_SCORE) or DEFAULT_MIN_RISK_SCORE),
            review_needs_threshold=float(
                getattr(args, "review_needs_threshold", DEFAULT_REVIEW_NEEDS_THRESHOLD)
                or DEFAULT_REVIEW_NEEDS_THRESHOLD
            ),
            allow_manual_llm_supervision=bool(
                getattr(args, "allow_manual_llm_supervision", DEFAULT_ALLOW_MANUAL_LLM_SUPERVISION)
            ),
            llm_promote_budget=int(getattr(args, "llm_promote_budget", DEFAULT_LLM_PROMOTE_BUDGET) or DEFAULT_LLM_PROMOTE_BUDGET),
            llm_demote_budget=int(getattr(args, "llm_demote_budget", DEFAULT_LLM_DEMOTE_BUDGET) or DEFAULT_LLM_DEMOTE_BUDGET),
            llm_soft_budget=int(getattr(args, "llm_soft_budget", DEFAULT_LLM_SOFT_BUDGET) or DEFAULT_LLM_SOFT_BUDGET),
            review_decisions=review_decisions,
        )
    except Exception as e:
        print(f"[Stage 8] ERROR: {e}")
        result.stage_errors["M8"] = str(e)
        return

    # Cache staged artifacts so output serialization does not rebuild.
    setattr(result, "_phase_a_artifacts", artifacts)

    channel_graph = artifacts.get("channel_graph", {}) or {}
    refined = artifacts.get("refined_objects", {}) or {}
    obj_count = len(channel_graph.get("object_nodes", []) or [])
    edge_count = len(channel_graph.get("channel_edges", []) or [])
    ref_count = len(refined.get("objects", []) or [])
    print(f"[Stage 8] object_nodes={obj_count}, channel_edges={edge_count}, refined_objects={ref_count}")

    if max_stage >= 9:
        chains = (artifacts.get("chains", {}) or {}).get("chains", []) or []
        chain_eval = (artifacts.get("chain_eval", {}) or {}).get("stats", {}) or {}
        print(
            "[Stage 9] "
            f"sink_roots={len((artifacts.get('sink_roots', {}) or {}).get('sink_roots', []) or [])}, "
            f"chains={len(chains)}, confirmed={chain_eval.get('confirmed', 0)}, "
            f"suspicious={chain_eval.get('suspicious', 0)}"
        )

    if max_stage >= 10:
        low_conf = (artifacts.get("low_conf_sinks", {}) or {}).get("items", []) or []
        triage = (artifacts.get("triage_queue", {}) or {}).get("items", []) or []
        review_queue = (artifacts.get("verdict_calibration_queue", {}) or {}).get("items", []) or []
        soft_rows = (artifacts.get("verdict_soft_triage", {}) or {}).get("items", []) or []
        review_needed = sum(1 for row in soft_rows if row.get("needs_review"))
        print(
            f"[Stage 10] low_conf={len(low_conf)}, triage_topk={len(triage)}, "
            f"review_queue={len(review_queue)}, review_needed={review_needed}"
        )


# ── Output ─────────────────────────────────────────────────────────────────


def _print_result(result, args=None):
    """Print a summary of the pipeline result."""
    print()
    print("=" * 60)
    print(f"[SourceAgent] Pipeline complete — run_id={result.run_id}")
    print(f"  Binary:     {result.binary_path}")

    if result.memory_map:
        mm = result.memory_map
        print(f"  MemoryMap:  {len(mm.regions)} regions, base=0x{mm.base_address:08x}")

    print(f"  Sources:    {len(result.source_candidates)}")
    print(f"  Sinks:      {len(result.sink_candidates)}")
    print(f"  Packs:      {len(result.evidence_packs)}")
    print(f"  Proposals:  {len(result.proposals)}")

    if result.verified_labels:
        verdicts = {}
        for v in result.verified_labels:
            key = v.verdict.value
            verdicts[key] = verdicts.get(key, 0) + 1
        print(f"  Verified:   {len(result.verified_labels)} — {verdicts}")

        # Print verified labels
        for vl in result.verified_labels:
            status = vl.verdict.value
            label = vl.final_label or vl.proposal.label
            addr = f"0x{vl.proposal.address:08x}" if vl.proposal.address else "?"
            func = vl.proposal.function_name or "?"
            conf = f"{vl.proposal.confidence:.2f}"
            print(f"    [{status:8s}] {label:20s} @ {addr} in {func} (conf={conf})")

    if result.stage_errors:
        print(f"  Errors:     {result.stage_errors}")

    print("=" * 60)

    # Write JSON output if requested
    if args and getattr(args, "output", None):
        _write_json_output(result, args.output)


def _write_json_output(result, output_path: str):
    """Serialize PipelineResult to JSON file."""
    data = _pipeline_result_to_dict(result)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"[SourceAgent] Results written to: {out}")


def _pipeline_result_to_dict(result) -> Dict[str, Any]:
    """Convert PipelineResult dataclasses/enums to plain JSON-serializable dict."""
    from dataclasses import asdict

    data = asdict(result)
    artifacts = getattr(result, "_phase_a_artifacts", None)
    if artifacts is None:
        try:
            from sourceagent.pipeline.chain_artifacts import build_phase_a_artifacts

            artifacts = build_phase_a_artifacts(result)
        except Exception as e:
            logger.warning("phase-A artifact build failed (non-fatal): %s", e)
            artifacts = {
                "channel_graph": {},
                "refined_objects": {},
                "sink_roots": {},
                "chains": {},
                "chain_eval": {},
                "low_conf_sinks": {},
                "triage_queue": {},
                "verdict_feature_pack": {},
                "verdict_calibration_queue": {},
                "verdict_calibration_decisions": {},
                "verdict_audit_flags": {},
                "verdict_soft_triage": {},
                "status": "failed",
                "failure_code": "ARTIFACT_BUILD_ERROR",
                "failure_detail": str(e),
            }
    data["phase_a_artifacts"] = artifacts

    # Convert enum values to strings
    def _fix_enums(obj):
        if isinstance(obj, dict):
            return {k: _fix_enums(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_fix_enums(v) for v in obj]
        if hasattr(obj, "value"):
            return obj.value
        return obj

    return _fix_enums(data)


# ── Facts Bundle Export ────────────────────────────────────────────────────


def _export_facts_bundle(result, output_dir: str):
    """Export verified labels as a facts bundle."""
    from sourceagent.pipeline.facts_bundle import build_facts_bundle, write_facts_bundle

    bundle = build_facts_bundle(result)
    out = write_facts_bundle(bundle, output_dir)
    print(
        f"[SourceAgent] Facts bundle exported to {out}: "
        f"{bundle.label_count} labels ({bundle.source_count} sources, {bundle.sink_count} sinks)"
    )


async def _cmd_export(args):
    """Export a facts bundle from a saved pipeline result JSON file."""
    from sourceagent.pipeline.facts_bundle import (
        build_facts_bundle, write_facts_bundle, build_callsite_queue,
    )
    from sourceagent.pipeline.models import PipelineResult

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: input file not found: {input_path}")
        sys.exit(1)

    # Load pipeline result from JSON
    data = json.loads(input_path.read_text(encoding="utf-8"))
    result = _reconstruct_pipeline_result(data)

    verdicts = [v.strip() for v in args.verdicts.split(",")]
    print(f"[SourceAgent] Exporting facts bundle (verdicts: {verdicts})")

    bundle = build_facts_bundle(result, accepted_verdicts=verdicts)
    out = write_facts_bundle(bundle, args.output_dir)

    # Also export callsite queue
    queue = build_callsite_queue(bundle)
    queue_path = Path(args.output_dir) / "callsite_queue.json"
    queue_path.write_text(json.dumps(queue, indent=2, default=str), encoding="utf-8")

    print(
        f"[SourceAgent] Facts bundle exported to {out}: "
        f"{bundle.label_count} labels, {len(queue)} callsite tasks"
    )


def _reconstruct_pipeline_result(data: dict):
    """Reconstruct PipelineResult from a JSON dict (from --output).

    Rebuilds just enough structure for build_facts_bundle to work:
    the verified_labels list with proposals and obligations.
    """
    from sourceagent.pipeline.models import (
        LLMProposal, Obligation, ObligationStatus,
        PipelineResult, VerificationVerdict, VerifiedLabel,
    )

    verified_labels = []
    for vl_data in data.get("verified_labels", []):
        prop_data = vl_data.get("proposal", {})
        proposal = LLMProposal(
            pack_id=prop_data.get("pack_id", ""),
            label=prop_data.get("label", ""),
            address=prop_data.get("address", 0),
            function_name=prop_data.get("function_name", ""),
            claims=prop_data.get("claims", []),
            confidence=prop_data.get("confidence", 0.0),
            evidence_refs=prop_data.get("evidence_refs", []),
            notes=prop_data.get("notes", ""),
        )

        obligations = []
        for ob_data in vl_data.get("obligations", []):
            obligations.append(Obligation(
                obligation_id=ob_data.get("obligation_id", ""),
                kind=ob_data.get("kind", ""),
                description=ob_data.get("description", ""),
                required=ob_data.get("required", True),
                status=ObligationStatus(ob_data.get("status", "pending")),
                evidence=ob_data.get("evidence", ""),
            ))

        verdict_str = vl_data.get("verdict", "UNKNOWN")
        try:
            verdict = VerificationVerdict(verdict_str)
        except ValueError:
            verdict = VerificationVerdict.UNKNOWN

        verified_labels.append(VerifiedLabel(
            pack_id=vl_data.get("pack_id", ""),
            proposal=proposal,
            obligations=obligations,
            verdict=verdict,
            final_label=vl_data.get("final_label"),
        ))

    return PipelineResult(
        binary_path=data.get("binary_path", ""),
        run_id=data.get("run_id", ""),
        verified_labels=verified_labels,
        stage_errors=data.get("stage_errors", {}),
    )


# ── Eval Subcommand ────────────────────────────────────────────────────────


def _parse_eval_formats(formats_csv: str) -> List[str]:
    """Parse --formats CSV into normalized extensions (without dots)."""
    formats: List[str] = []
    for raw in (formats_csv or "").split(","):
        f = raw.strip().lower().lstrip(".")
        if not f:
            continue
        if f not in formats:
            formats.append(f)
    return formats or ["bin", "elf"]


def _is_unstripped_elf(path: Path) -> bool:
    return path.suffix.lower() == ".elf" and "stripped" not in path.stem.lower()


def _infer_dataset_from_path(path: Path) -> str:
    parts = {p.lower() for p in path.parts}
    if "microbench" in parts:
        return "microbench"
    if "p2im-unit_tests" in parts:
        return "p2im-unit_tests"
    if "p2im-real_firmware" in parts:
        return "p2im-real_firmware"
    if "p2im" in parts:
        return "p2im"
    if "usbs" in parts:
        return "uSBS"
    if "monolithic-firmware-collection" in parts:
        return "monolithic-firmware-collection"
    return "unknown"


def _load_eval_manifest(manifest_path: Path) -> List[Dict[str, Any]]:
    """Load eval suite manifest JSON.

    Accepted formats:
      - list[object]
      - {"samples": list[object]}
    Required sample key:
      - binary_path
    Optional keys:
      - dataset, sample_id, gt_stem, eval_scope, notes, output_stem
    """
    if not manifest_path.exists():
        raise FileNotFoundError(f"manifest not found: {manifest_path}")

    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        samples = raw.get("samples", [])
    elif isinstance(raw, list):
        samples = raw
    else:
        raise ValueError(f"unsupported manifest JSON type: {type(raw)}")

    if not isinstance(samples, list):
        raise ValueError("manifest 'samples' must be a list")

    out: List[Dict[str, Any]] = []
    for idx, item in enumerate(samples):
        if not isinstance(item, dict):
            continue
        raw_path = (item.get("binary_path") or "").strip()
        if not raw_path:
            continue
        p = Path(raw_path)
        if not p.is_absolute():
            p = (manifest_path.parent / p).resolve()
        out.append({
            "binary_path": p,
            "dataset": item.get("dataset", "") or _infer_dataset_from_path(p),
            "sample_id": item.get("sample_id", "") or p.stem,
            "gt_stem": item.get("gt_stem", "") or p.stem,
            "output_stem": item.get("output_stem", "") or item.get("sample_id", "") or p.stem,
            "eval_scope": item.get("eval_scope", "") or "",
            "notes": item.get("notes", "") or "",
            "_manifest_index": idx,
        })
    return out


def _collect_eval_items(args) -> List[Dict[str, Any]]:
    """Collect eval items from --manifest-json / --all / positional binary."""
    items: List[Dict[str, Any]] = []
    if getattr(args, "manifest_json", None):
        manifest_path = Path(args.manifest_json).resolve()
        items = _load_eval_manifest(manifest_path)
        return items

    if args.all:
        eval_dir = Path(args.all).resolve()
        if not eval_dir.exists():
            raise FileNotFoundError(f"directory not found: {eval_dir}")
        formats = _parse_eval_formats(args.formats)
        binaries_set = set()
        for fmt in formats:
            binaries_set.update(eval_dir.glob(f"*.{fmt}"))
        binaries = sorted(p.resolve() for p in binaries_set)
        for p in binaries:
            items.append({
                "binary_path": p,
                "dataset": _infer_dataset_from_path(p),
                "sample_id": p.stem,
                "gt_stem": p.stem,
                "output_stem": p.stem,
                "eval_scope": "",
                "notes": "",
            })
        return items

    if args.binary:
        p = Path(args.binary).resolve()
        items.append({
            "binary_path": p,
            "dataset": _infer_dataset_from_path(p),
            "sample_id": p.stem,
            "gt_stem": p.stem,
            "output_stem": p.stem,
            "eval_scope": "",
            "notes": "",
        })
        return items

    return []


def _label_kind(label: str) -> str:
    if label in _SOURCE_LABELS:
        return "source"
    if label in _SINK_LABELS:
        return "sink"
    return "other"


def _collect_detected_labels(
    pipeline_result,
    accepted_verdicts,
) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for idx, vl in enumerate(getattr(pipeline_result, "verified_labels", [])):
        if vl.verdict not in accepted_verdicts:
            continue
        label = str(vl.final_label or vl.proposal.label or "")
        records.append({
            "index": idx,
            "label": label,
            "kind": _label_kind(label),
            "address": int(vl.proposal.address or 0),
            "function_name": str(vl.proposal.function_name or ""),
            "verdict": vl.verdict.value,
            "pack_id": vl.pack_id,
        })
    return records


def _extract_chain_stats_from_result_dict(data: Dict[str, Any]) -> Dict[str, int]:
    """Extract chain_eval stats from serialized pipeline result dict."""
    stats = (
        (data.get("phase_a_artifacts", {}) or {})
        .get("chain_eval", {})
        .get("stats", {})
        or {}
    )
    soft_triage = (
        (data.get("phase_a_artifacts", {}) or {})
        .get("verdict_soft_triage", {})
        .get("stats", {})
        or {}
    )
    review_queue = (
        (data.get("phase_a_artifacts", {}) or {})
        .get("verdict_calibration_queue", {})
        .get("items", [])
        or []
    )
    return {
        "chain_count": int(stats.get("chain_count", 0) or 0),
        "chain_with_source": int(stats.get("with_source", 0) or 0),
        "chain_with_channel": int(stats.get("with_channel", 0) or 0),
        "chain_confirmed": int(stats.get("confirmed", 0) or 0),
        "chain_suspicious": int(stats.get("suspicious", 0) or 0),
        "chain_safe_or_low_risk": int(stats.get("safe_or_low_risk", 0) or 0),
        "chain_dropped": int(stats.get("dropped", 0) or 0),
        "verdict_review_queue": len(review_queue),
        "verdict_review_needed": int(soft_triage.get("needs_review", 0) or 0),
        "verdict_soft_suspicious": int(soft_triage.get("soft_suspicious", 0) or 0),
        "verdict_llm_reviewed": int(soft_triage.get("llm_reviewed", 0) or 0),
    }


def _write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


_SOURCE_LABELS = {
    "MMIO_READ", "ISR_MMIO_READ", "ISR_FILLED_BUFFER", "DMA_BACKED_BUFFER",
}
_SINK_LABELS = {
    "COPY_SINK", "MEMSET_SINK", "STORE_SINK", "LOOP_WRITE_SINK",
    "FORMAT_STRING_SINK", "FUNC_PTR_SINK",
    "LENGTH_TRUST_SINK", "UNBOUNDED_WALK_SINK", "PARSING_OVERFLOW_SINK",
}


def _infer_eval_scope_from_gt(gt_entries: List[Any]) -> str:
    """Infer eval scope from GT labels to avoid cross-task FP inflation."""
    labels = {
        str(getattr(e, "label", "") or "")
        for e in gt_entries
        if not str(getattr(e, "label", "") or "").startswith("_")
    }
    if not labels:
        return "all"
    all_source = all(lbl in _SOURCE_LABELS for lbl in labels)
    all_sink = all(lbl in _SINK_LABELS for lbl in labels)
    if all_source:
        return "sources"
    if all_sink:
        return "sinks"
    return "all"


def _filter_eval_results_by_scope(rows: List[Any], eval_scope: str) -> List[Any]:
    """Filter EvalResult rows according to eval scope for reporting."""
    if eval_scope == "sinks":
        return [r for r in rows if str(getattr(r, "label_class", "")) in _SINK_LABELS]
    if eval_scope == "sources":
        return [r for r in rows if str(getattr(r, "label_class", "")) in _SOURCE_LABELS]
    return rows


def _load_gt_registry_from_json(gt_json_path: Path) -> Dict[str, List[Any]]:
    """Load GT registry from JSON (list or dict form)."""
    from sourceagent.pipeline.models import GroundTruthEntry

    if not gt_json_path.exists():
        raise FileNotFoundError(f"GT JSON not found: {gt_json_path}")

    raw = json.loads(gt_json_path.read_text(encoding="utf-8"))
    registry: Dict[str, List[Any]] = {}

    def _to_entry(item: Dict[str, Any], fallback_stem: str = "") -> GroundTruthEntry:
        stem = item.get("binary_stem") or fallback_stem
        return GroundTruthEntry(
            binary_stem=stem,
            label=item.get("label", ""),
            address=item.get("address"),
            function_name=item.get("function_name", "") or "",
            notes=item.get("notes", "") or "",
            pipeline_label_hint=item.get("pipeline_label_hint", "") or "",
        )

    if isinstance(raw, dict):
        for stem, entries in raw.items():
            if not isinstance(entries, list):
                continue
            registry[stem] = [_to_entry(e, fallback_stem=stem) for e in entries if isinstance(e, dict)]
        return registry

    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            entry = _to_entry(item)
            if not entry.binary_stem:
                continue
            registry.setdefault(entry.binary_stem, []).append(entry)
        return registry

    raise ValueError(f"Unsupported GT JSON format: {type(raw)}")


def _binary_meta(binary_path: Path) -> Dict[str, Any]:
    suffix = binary_path.suffix.lower().lstrip(".")
    return {
        "path": str(binary_path),
        "stem": binary_path.stem,
        "suffix": suffix or "<none>",
        "is_stripped_name_hint": (
            "stripped" in binary_path.stem.lower() and suffix == "elf"
        ),
    }


def _stem_counts(items: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        binary_path = item.get("binary_path")
        if not isinstance(binary_path, Path):
            continue
        stem = binary_path.stem
        counts[stem] = counts.get(stem, 0) + 1
    return counts


def _make_eval_project_override(output_stem: str) -> str:
    root = Path("/tmp/sourceagent_ghidra_projects")
    root.mkdir(parents=True, exist_ok=True)
    ts = int(time.time() * 1000)
    suffix = uuid.uuid4().hex[:8]
    project = root / f"eval_{output_stem}_{ts}_{suffix}"
    project.mkdir(parents=True, exist_ok=True)
    return str(project)


def _needs_isolated_eval_project(
    binary_path: Path,
    output_stem: str,
    stem_counts: Dict[str, int],
) -> bool:
    stem = binary_path.stem
    if stem_counts.get(stem, 0) > 1:
        return True
    # Manifest-driven variants (e.g. uSBS) may share the same ELF stem while
    # representing different benchmark cases. If the desired output stem differs
    # from the binary stem, isolate the Ghidra project to avoid reusing a stale
    # import from an earlier run of a sibling sample.
    if output_stem and output_stem != stem:
        return True
    return False


def _format_counts(binary_meta: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in binary_meta:
        suffix = item.get("suffix", "<none>")
        counts[suffix] = counts.get(suffix, 0) + 1
    return dict(sorted(counts.items()))


def _write_scoring_policy_artifacts(output_dir: Path, policy: Dict[str, Any]):
    """Write scoring policy in JSON + Markdown."""
    policy_json = output_dir / "scoring_policy.json"
    policy_md = output_dir / "scoring_policy.md"
    policy_json.write_text(json.dumps(policy, indent=2), encoding="utf-8")

    md_lines = [
        "# Eval Scoring Policy",
        "",
        "## Matching Priority",
    ]
    for idx, step in enumerate(policy.get("matching_priority", []), start=1):
        md_lines.append(f"{idx}. {step}")

    md_lines.extend([
        "",
        "## Strict Scoring",
        f"- `TP = {policy.get('strict_scoring', {}).get('tp', '')}`",
        f"- `FN = {policy.get('strict_scoring', {}).get('fn', '')}`",
        f"- `FP = {policy.get('strict_scoring', {}).get('fp', '')}`",
        "",
        "## Weighted Partial Scoring",
        f"- `partial_credit = {policy.get('weighted_partial_scoring', {}).get('partial_credit', 0.5)}`",
        f"- `TP = {policy.get('weighted_partial_scoring', {}).get('tp', '')}`",
        f"- `FN = {policy.get('weighted_partial_scoring', {}).get('fn', '')}`",
        f"- `FP = {policy.get('weighted_partial_scoring', {}).get('fp', '')}`",
        "",
        "## Near-Miss Rule (`~1`)",
        f"- {policy.get('partial_rule_summary', '')}",
        "",
    ])
    policy_md.write_text("\n".join(md_lines), encoding="utf-8")


async def _cmd_eval(args):
    """Run evaluation against ground truth."""
    from sourceagent.pipeline.models import VerificationVerdict
    try:
        items = _collect_eval_items(args)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    if not items:
        print("Error: specify a binary, --all <dir>, or --manifest-json <file>")
        sys.exit(1)

    if args.only_unstripped_elf:
        before = len(items)
        items = [it for it in items if _is_unstripped_elf(it["binary_path"])]
        print(
            "[SourceAgent] Filter --only-unstripped-elf: "
            f"{len(items)}/{before} samples kept"
        )
        if not items:
            print("Error: no samples remain after --only-unstripped-elf filter")
            sys.exit(1)

    if args.manifest_json:
        print(
            f"[SourceAgent] Manifest eval: {len(items)} samples from "
            f"{Path(args.manifest_json).resolve()}"
        )
    elif args.all:
        print(
            f"[SourceAgent] Batch eval: {len(items)} binaries in "
            f"{Path(args.all).resolve()} (formats={','.join(_parse_eval_formats(args.formats))})"
        )
    else:
        print(f"[SourceAgent] Eval single binary: {items[0]['binary_path']}")

    from sourceagent.pipeline.eval_harness import (
        GROUND_TRUTH,
        aggregate_results,
        compare_labels_detailed,
        default_scoring_policy,
        eval_results_to_dict,
        print_eval_report,
        run_eval,
    )
    gt_registry = GROUND_TRUTH
    if args.gt_json:
        gt_path = Path(args.gt_json).resolve()
        try:
            gt_registry = _load_gt_registry_from_json(gt_path)
            print(
                f"[SourceAgent] Loaded external GT registry: {gt_path} "
                f"({len(gt_registry)} binary stems)"
            )
        except Exception as e:
            print(f"Error: failed to load --gt-json {gt_path}: {e}")
            sys.exit(1)

    offline = not args.online
    model = args.model or ""
    proposer_mode = "llm" if model else "heuristic"
    partial_credit = float(args.partial_credit)
    eval_scope = getattr(args, "eval_scope", "auto")
    sample_timeout = int(getattr(args, "sample_timeout", 240) or 0)

    accepted_verdicts: Set[VerificationVerdict] = set()
    accepted_verdict_names: List[str] = []
    for raw in (args.accept_verdicts or "").split(","):
        name = raw.strip().upper()
        if not name:
            continue
        try:
            verdict = VerificationVerdict(name)
            accepted_verdicts.add(verdict)
            accepted_verdict_names.append(verdict.value)
        except ValueError:
            print(f"[SourceAgent] Warning: unknown verdict '{name}', ignored")
    if not accepted_verdicts:
        accepted_verdicts = {VerificationVerdict.VERIFIED, VerificationVerdict.PARTIAL}
        accepted_verdict_names = ["VERIFIED", "PARTIAL"]

    output_dir = Path(args.output_dir).resolve() if args.output_dir else None
    if output_dir:
        (output_dir / "raw_results").mkdir(parents=True, exist_ok=True)
        (output_dir / "raw_views").mkdir(parents=True, exist_ok=True)
        (output_dir / "detailed").mkdir(parents=True, exist_ok=True)
        (output_dir / "summary").mkdir(parents=True, exist_ok=True)
        (output_dir / "tables").mkdir(parents=True, exist_ok=True)

    all_results = []
    detailed_rows = []
    sample_summaries = []
    binary_meta: List[Dict[str, Any]] = []
    per_file_rows: List[Dict[str, Any]] = []
    detection_by_label_total: Dict[str, int] = {}
    detection_by_label_gt: Dict[str, int] = {}
    detection_by_label_no_gt: Dict[str, int] = {}
    stem_counts = _stem_counts(items)

    for item in items:
        binary_path: Path = item["binary_path"]
        dataset = item.get("dataset", "") or _infer_dataset_from_path(binary_path)
        sample_id = item.get("sample_id", "") or binary_path.stem
        gt_stem = item.get("gt_stem", "") or binary_path.stem
        output_stem = item.get("output_stem", "") or sample_id or binary_path.stem
        item_eval_scope = item.get("eval_scope", "") or ""

        meta = _binary_meta(binary_path)
        meta["dataset"] = dataset
        meta["sample_id"] = sample_id
        meta["gt_stem"] = gt_stem
        binary_meta.append(meta)

        if not binary_path.exists():
            print(f"[SourceAgent] Warning: {binary_path} not found, skipping")
            sample_summaries.append({
                "binary": str(binary_path),
                "stem": binary_path.stem,
                "output_stem": output_stem,
                "dataset": dataset,
                "sample_id": sample_id,
                "status": "missing_binary",
            })
            per_file_rows.append({
                "dataset": dataset,
                "sample_id": sample_id,
                "binary_stem": binary_path.stem,
                "output_stem": output_stem,
                "binary_path": str(binary_path),
                "has_gt": False,
                "status": "missing_binary",
                "eval_scope": "",
                "strict_tp": "",
                "strict_fp": "",
                "strict_fn": "",
                "strict_precision": "",
                "strict_recall": "",
                "strict_f1": "",
                "detected_total": 0,
                "detected_source": 0,
                "detected_sink": 0,
                "detected_other": 0,
                "detected_labels": "",
                "chain_count": 0,
                "chain_with_source": 0,
                "chain_with_channel": 0,
                "chain_confirmed": 0,
                "chain_suspicious": 0,
                "chain_safe_or_low_risk": 0,
                "chain_dropped": 0,
                "verdict_review_queue": 0,
                "verdict_review_needed": 0,
                "verdict_soft_suspicious": 0,
                "verdict_llm_reviewed": 0,
            })
            continue

        stem = binary_path.stem
        gt = gt_registry.get(gt_stem, [])
        has_gt = bool(gt)
        if has_gt:
            print(
                f"[SourceAgent] Eval: {stem} [{output_stem}] ({dataset}) — "
                f"{len(gt)} ground truth entries (stem={gt_stem})"
            )
        else:
            print(f"[SourceAgent] Eval: {stem} [{output_stem}] ({dataset}) — no ground truth, mining-only mode")

        try:
            run_id = f"eval-{output_stem}-{int(time.time())}"
            raw_json_path = (
                output_dir / "raw_results" / f"{output_stem}.pipeline.json"
                if output_dir else None
            )
            needs_isolated_project = _needs_isolated_eval_project(
                binary_path,
                output_stem,
                stem_counts,
            )
            old_project_env = os.environ.get("SOURCEAGENT_GHIDRA_PROJECT_PATH")
            old_project_mode = os.environ.get("SOURCEAGENT_GHIDRA_PROJECT_MODE")
            if needs_isolated_project and not offline:
                project_override = _make_eval_project_override(output_stem)
                os.environ["SOURCEAGENT_GHIDRA_PROJECT_PATH"] = project_override
                print(
                    "[SourceAgent] Eval: "
                    f"{output_stem} uses isolated Ghidra project {project_override}"
                )
            try:
                run_eval_coro = run_eval(
                    str(binary_path),
                    gt if has_gt else [],
                    stage=args.stage,
                    offline=offline,
                    model=model,
                    analysis_wait_sec=int(getattr(args, "analysis_wait_sec", 60) or 60),
                    mcp_connect_timeout_sec=int(getattr(args, "mcp_connect_timeout_sec", 30) or 30),
                    accepted_verdicts=accepted_verdicts,
                    output_path=str(raw_json_path) if raw_json_path else None,
                    run_id=run_id,
                    return_pipeline_result=True,
                )
                if sample_timeout > 0:
                    results, pipeline_result = await asyncio.wait_for(
                        run_eval_coro, timeout=sample_timeout,
                    )
                else:
                    results, pipeline_result = await run_eval_coro
            finally:
                if old_project_env is None:
                    os.environ.pop("SOURCEAGENT_GHIDRA_PROJECT_PATH", None)
                else:
                    os.environ["SOURCEAGENT_GHIDRA_PROJECT_PATH"] = old_project_env
                if old_project_mode is None:
                    os.environ.pop("SOURCEAGENT_GHIDRA_PROJECT_MODE", None)
                else:
                    os.environ["SOURCEAGENT_GHIDRA_PROJECT_MODE"] = old_project_mode
            detected = _collect_detected_labels(pipeline_result, accepted_verdicts)
            detected_by_label: Dict[str, int] = {}
            detected_source = 0
            detected_sink = 0
            detected_other = 0
            for rec in detected:
                label = rec["label"]
                detected_by_label[label] = detected_by_label.get(label, 0) + 1
                detection_by_label_total[label] = detection_by_label_total.get(label, 0) + 1
                if has_gt:
                    detection_by_label_gt[label] = detection_by_label_gt.get(label, 0) + 1
                else:
                    detection_by_label_no_gt[label] = detection_by_label_no_gt.get(label, 0) + 1

                if rec["kind"] == "source":
                    detected_source += 1
                elif rec["kind"] == "sink":
                    detected_sink += 1
                else:
                    detected_other += 1

            if has_gt:
                sample_eval_scope = item_eval_scope or eval_scope
                if sample_eval_scope == "auto":
                    sample_eval_scope = _infer_eval_scope_from_gt(gt)
                report_rows = _filter_eval_results_by_scope(results, sample_eval_scope)
                print_eval_report(report_rows, stem)
                all_results.extend(report_rows)

                detailed = compare_labels_detailed(
                    pipeline_result,
                    gt,
                    accepted_verdicts=accepted_verdicts,
                    partial_credit=partial_credit,
                    eval_scope=sample_eval_scope,
                )
                detailed_rows.append(detailed)

                strict_tp = detailed["strict"]["tp"]
                strict_fp = detailed["strict"]["fp"]
                strict_fn = detailed["strict"]["fn"]
                weighted_tp = detailed["weighted"]["tp"]
                weighted_fp = detailed["weighted"]["fp"]
                weighted_fn = detailed["weighted"]["fn"]

                sample_summaries.append({
                    "binary": str(binary_path),
                    "stem": stem,
                    "output_stem": output_stem,
                    "dataset": dataset,
                    "sample_id": sample_id,
                    "gt_stem": gt_stem,
                    "status": "ok",
                    "run_id": pipeline_result.run_id,
                    "strict": {
                        "tp": strict_tp,
                        "fp": strict_fp,
                        "fn": strict_fn,
                        "precision": detailed["strict"]["precision"],
                        "recall": detailed["strict"]["recall"],
                        "f1": detailed["strict"]["f1"],
                    },
                    "weighted": {
                        "tp": weighted_tp,
                        "fp": weighted_fp,
                        "fn": weighted_fn,
                        "precision": detailed["weighted"]["precision"],
                        "recall": detailed["weighted"]["recall"],
                        "f1": detailed["weighted"]["f1"],
                        "partial_match_count": detailed["weighted"]["partial_match_count"],
                    },
                    "eval_scope": sample_eval_scope,
                    "detected": {
                        "total": len(detected),
                        "source": detected_source,
                        "sink": detected_sink,
                        "other": detected_other,
                        "by_label": dict(sorted(detected_by_label.items())),
                    },
                })
                per_file_rows.append({
                    "dataset": dataset,
                    "sample_id": sample_id,
                    "binary_stem": stem,
                    "output_stem": output_stem,
                    "binary_path": str(binary_path),
                    "has_gt": True,
                    "status": "ok",
                    "eval_scope": sample_eval_scope,
                    "strict_tp": strict_tp,
                    "strict_fp": strict_fp,
                    "strict_fn": strict_fn,
                    "strict_precision": detailed["strict"]["precision"],
                    "strict_recall": detailed["strict"]["recall"],
                    "strict_f1": detailed["strict"]["f1"],
                    "detected_total": len(detected),
                    "detected_source": detected_source,
                    "detected_sink": detected_sink,
                    "detected_other": detected_other,
                    "detected_labels": json.dumps(dict(sorted(detected_by_label.items())), ensure_ascii=True),
                    "chain_count": 0,
                    "chain_with_source": 0,
                    "chain_with_channel": 0,
                    "chain_confirmed": 0,
                    "chain_suspicious": 0,
                    "chain_safe_or_low_risk": 0,
                    "chain_dropped": 0,
                })
            else:
                print(
                    f"[SourceAgent] Detection-only summary: {stem} "
                    f"(labels={len(detected)}, sources={detected_source}, sinks={detected_sink})"
                )
                sample_summaries.append({
                    "binary": str(binary_path),
                    "stem": stem,
                    "output_stem": output_stem,
                    "dataset": dataset,
                    "sample_id": sample_id,
                    "gt_stem": gt_stem,
                    "status": "ok_no_ground_truth",
                    "run_id": pipeline_result.run_id,
                    "detected": {
                        "total": len(detected),
                        "source": detected_source,
                        "sink": detected_sink,
                        "other": detected_other,
                        "by_label": dict(sorted(detected_by_label.items())),
                    },
                })
                per_file_rows.append({
                    "dataset": dataset,
                    "sample_id": sample_id,
                    "binary_stem": stem,
                    "output_stem": output_stem,
                    "binary_path": str(binary_path),
                    "has_gt": False,
                    "status": "ok_no_ground_truth",
                    "eval_scope": "",
                    "strict_tp": "",
                    "strict_fp": "",
                    "strict_fn": "",
                    "strict_precision": "",
                    "strict_recall": "",
                    "strict_f1": "",
                    "detected_total": len(detected),
                    "detected_source": detected_source,
                    "detected_sink": detected_sink,
                    "detected_other": detected_other,
                    "detected_labels": json.dumps(dict(sorted(detected_by_label.items())), ensure_ascii=True),
                    "chain_count": 0,
                    "chain_with_source": 0,
                    "chain_with_channel": 0,
                    "chain_confirmed": 0,
                    "chain_suspicious": 0,
                    "chain_safe_or_low_risk": 0,
                    "chain_dropped": 0,
                })

            if output_dir:
                data = _pipeline_result_to_dict(pipeline_result)
                chain_stats = _extract_chain_stats_from_result_dict(data)
                if sample_summaries:
                    sample_summaries[-1]["chain"] = dict(chain_stats)
                if per_file_rows:
                    per_file_rows[-1].update(chain_stats)

                # Split views for optimization loop tooling.
                (output_dir / "raw_views" / f"{output_stem}.candidate.json").write_text(
                    json.dumps({
                        "binary_path": data.get("binary_path"),
                        "run_id": data.get("run_id"),
                        "source_candidates": data.get("source_candidates", []),
                        "sink_candidates": data.get("sink_candidates", []),
                    }, indent=2),
                    encoding="utf-8",
                )
                (output_dir / "raw_views" / f"{output_stem}.proposal.json").write_text(
                    json.dumps({
                        "binary_path": data.get("binary_path"),
                        "run_id": data.get("run_id"),
                        "proposals": data.get("proposals", []),
                    }, indent=2),
                    encoding="utf-8",
                )
                (output_dir / "raw_views" / f"{output_stem}.verified.json").write_text(
                    json.dumps({
                        "binary_path": data.get("binary_path"),
                        "run_id": data.get("run_id"),
                        "verified_labels": data.get("verified_labels", []),
                    }, indent=2),
                    encoding="utf-8",
                )
                (output_dir / "raw_views" / f"{output_stem}.phase_a_artifacts.json").write_text(
                    json.dumps({
                        "binary_path": data.get("binary_path"),
                        "run_id": data.get("run_id"),
                        "phase_a_artifacts": data.get("phase_a_artifacts", {}),
                    }, indent=2),
                    encoding="utf-8",
                )
                phase_a = data.get("phase_a_artifacts", {}) or {}
                for artifact_name in (
                    "channel_graph",
                    "refined_objects",
                    "sink_roots",
                    "chains",
                    "chain_eval",
                    "low_conf_sinks",
                    "triage_queue",
                    "verdict_feature_pack",
                    "verdict_calibration_queue",
                    "verdict_calibration_decisions",
                    "verdict_audit_flags",
                    "verdict_soft_triage",
                ):
                    (output_dir / "raw_views" / f"{output_stem}.{artifact_name}.json").write_text(
                        json.dumps(phase_a.get(artifact_name, {}), indent=2),
                        encoding="utf-8",
                    )

                (output_dir / "detailed" / f"{output_stem}.matching.json").write_text(
                    json.dumps({
                        "binary_meta": _binary_meta(binary_path),
                        "dataset": dataset,
                        "sample_id": sample_id,
                        "output_stem": output_stem,
                        "gt_stem": gt_stem,
                        "gt_entries": [
                            {
                                "binary_stem": gt_item.binary_stem,
                                "label": gt_item.label,
                                "address": gt_item.address,
                                "function_name": gt_item.function_name,
                                "notes": gt_item.notes,
                            }
                            for gt_item in gt
                        ],
                        "has_ground_truth": has_gt,
                        "detected_labels": detected,
                        "label_metrics": eval_results_to_dict(results),
                        "detailed_matching": (
                            detailed if has_gt else {
                                "binary_path": str(binary_path),
                                "binary_stem": stem,
                                "output_stem": output_stem,
                                "gt_count": 0,
                                "prediction_count": len(detected),
                                "matches": [],
                                "fp_predictions": detected,
                            }
                        ),
                    }, indent=2),
                    encoding="utf-8",
                )

        except asyncio.TimeoutError:
            print(
                f"[SourceAgent] Eval TIMEOUT for {stem} "
                f"(>{sample_timeout}s), continuing..."
            )
            sample_summaries.append({
                "binary": str(binary_path),
                "stem": stem,
                "output_stem": output_stem,
                "dataset": dataset,
                "sample_id": sample_id,
                "gt_stem": gt_stem,
                "status": "eval_timeout",
                "error": f"timeout>{sample_timeout}s",
            })
            per_file_rows.append({
                "dataset": dataset,
                "sample_id": sample_id,
                "binary_stem": stem,
                "output_stem": output_stem,
                "binary_path": str(binary_path),
                "has_gt": bool(gt),
                "status": "eval_timeout",
                "eval_scope": "",
                "strict_tp": "",
                "strict_fp": "",
                "strict_fn": "",
                "strict_precision": "",
                "strict_recall": "",
                "strict_f1": "",
                "detected_total": 0,
                "detected_source": 0,
                "detected_sink": 0,
                "detected_other": 0,
                "detected_labels": "",
                "chain_count": 0,
                "chain_with_source": 0,
                "chain_with_channel": 0,
                "chain_confirmed": 0,
                "chain_suspicious": 0,
                "chain_safe_or_low_risk": 0,
                "chain_dropped": 0,
                "verdict_review_queue": 0,
                "verdict_review_needed": 0,
                "verdict_soft_suspicious": 0,
                "verdict_llm_reviewed": 0,
            })
        except Exception as e:
            print(f"[SourceAgent] Eval ERROR for {stem}: {e}")
            sample_summaries.append({
                "binary": str(binary_path),
                "stem": stem,
                "output_stem": output_stem,
                "dataset": dataset,
                "sample_id": sample_id,
                "gt_stem": gt_stem,
                "status": "eval_error",
                "error": str(e),
            })
            per_file_rows.append({
                "dataset": dataset,
                "sample_id": sample_id,
                "binary_stem": stem,
                "output_stem": output_stem,
                "binary_path": str(binary_path),
                "has_gt": bool(gt),
                "status": "eval_error",
                "eval_scope": "",
                "strict_tp": "",
                "strict_fp": "",
                "strict_fn": "",
                "strict_precision": "",
                "strict_recall": "",
                "strict_f1": "",
                "detected_total": 0,
                "detected_source": 0,
                "detected_sink": 0,
                "detected_other": 0,
                "detected_labels": "",
                "chain_count": 0,
                "chain_with_source": 0,
                "chain_with_channel": 0,
                "chain_confirmed": 0,
                "chain_suspicious": 0,
                "chain_safe_or_low_risk": 0,
                "chain_dropped": 0,
                "verdict_review_queue": 0,
                "verdict_review_needed": 0,
                "verdict_soft_suspicious": 0,
                "verdict_llm_reviewed": 0,
            })

    if len(items) > 1:
        print("\n[SourceAgent] Aggregate results across all binaries:")
        if detailed_rows:
            strict_tp = sum(d["strict"]["tp"] for d in detailed_rows)
            strict_fp = sum(d["strict"]["fp"] for d in detailed_rows)
            strict_fn = sum(d["strict"]["fn"] for d in detailed_rows)
            denom_p = strict_tp + strict_fp
            denom_r = strict_tp + strict_fn
            strict_p = (strict_tp / denom_p) if denom_p > 0 else 0.0
            strict_r = (strict_tp / denom_r) if denom_r > 0 else 0.0
            strict_f1 = (
                2 * strict_p * strict_r / (strict_p + strict_r)
                if (strict_p + strict_r) > 0 else 0.0
            )
            print(
                "  TP={:.0f} FP={:.0f} FN={:.0f}".format(
                    strict_tp, strict_fp, strict_fn,
                ),
            )
            print(
                f"  Precision={strict_p:.2f} Recall={strict_r:.2f} F1={strict_f1:.2f}",
            )
            if all_results:
                agg = aggregate_results(all_results)
                print(
                    "  (legacy label-metrics micro-average: "
                    f"TP={agg.true_positives} FP={agg.false_positives} FN={agg.false_negatives})",
                )
        elif all_results:
            agg = aggregate_results(all_results)
            print(f"  TP={agg.true_positives} FP={agg.false_positives} FN={agg.false_negatives}")
            print(f"  Precision={agg.precision:.2f} Recall={agg.recall:.2f} F1={agg.f1:.2f}")

    if output_dir:
        scoring_policy = default_scoring_policy(partial_credit=partial_credit)
        _write_scoring_policy_artifacts(output_dir, scoring_policy)

        # Aggregate weighted metrics and FP breakdown.
        weighted_tp = sum(d["weighted"]["tp"] for d in detailed_rows)
        weighted_fp = sum(d["weighted"]["fp"] for d in detailed_rows)
        weighted_fn = sum(d["weighted"]["fn"] for d in detailed_rows)
        strict_tp = sum(d["strict"]["tp"] for d in detailed_rows)
        strict_fp = sum(d["strict"]["fp"] for d in detailed_rows)
        strict_fn = sum(d["strict"]["fn"] for d in detailed_rows)

        def _safe_div(a: float, b: float) -> float:
            return a / b if b > 0 else 0.0

        weighted_p = _safe_div(weighted_tp, weighted_tp + weighted_fp)
        weighted_r = _safe_div(weighted_tp, weighted_tp + weighted_fn)
        weighted_f1 = _safe_div(2 * weighted_p * weighted_r, weighted_p + weighted_r)

        strict_p = _safe_div(strict_tp, strict_tp + strict_fp)
        strict_r = _safe_div(strict_tp, strict_tp + strict_fn)
        strict_f1 = _safe_div(2 * strict_p * strict_r, strict_p + strict_r)

        fp_by_label: Dict[str, int] = {}
        for d in detailed_rows:
            for label, count in d.get("fp_by_label", {}).items():
                fp_by_label[label] = fp_by_label.get(label, 0) + int(count)
        fp_by_label = dict(sorted(fp_by_label.items()))

        label_summary = eval_results_to_dict(all_results)
        summary = {
            "strict_overall": {
                "tp": strict_tp,
                "fp": strict_fp,
                "fn": strict_fn,
                "precision": strict_p,
                "recall": strict_r,
                "f1": strict_f1,
            },
            "weighted_overall": {
                "tp": weighted_tp,
                "fp": weighted_fp,
                "fn": weighted_fn,
                "precision": weighted_p,
                "recall": weighted_r,
                "f1": weighted_f1,
                "partial_credit": partial_credit,
            },
            "fp_by_label": fp_by_label,
            "label_metrics": label_summary,
            "samples": sample_summaries,
        }
        (output_dir / "summary" / "eval_summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8",
        )

        # By-dataset table
        by_dataset: Dict[str, Dict[str, Any]] = {}
        for row in per_file_rows:
            ds = row["dataset"]
            acc = by_dataset.setdefault(ds, {
                "dataset": ds,
                "sample_count": 0,
                "gt_sample_count": 0,
                "no_gt_sample_count": 0,
                "ok_count": 0,
                "error_count": 0,
                "strict_tp": 0.0,
                "strict_fp": 0.0,
                "strict_fn": 0.0,
                "detected_total": 0,
                "detected_source": 0,
                "detected_sink": 0,
                "detected_other": 0,
                "chain_count": 0,
                "chain_with_source": 0,
                "chain_with_channel": 0,
                "chain_confirmed": 0,
                "chain_suspicious": 0,
                "chain_safe_or_low_risk": 0,
                "chain_dropped": 0,
                "verdict_review_queue": 0,
                "verdict_review_needed": 0,
                "verdict_soft_suspicious": 0,
                "verdict_llm_reviewed": 0,
            })
            acc["sample_count"] += 1
            status = str(row.get("status", ""))
            if status.startswith("ok"):
                acc["ok_count"] += 1
            if status == "eval_error":
                acc["error_count"] += 1
            has_gt = bool(row.get("has_gt"))
            if has_gt:
                acc["gt_sample_count"] += 1
                acc["strict_tp"] += float(row.get("strict_tp") or 0.0)
                acc["strict_fp"] += float(row.get("strict_fp") or 0.0)
                acc["strict_fn"] += float(row.get("strict_fn") or 0.0)
            else:
                acc["no_gt_sample_count"] += 1
            acc["detected_total"] += int(row.get("detected_total") or 0)
            acc["detected_source"] += int(row.get("detected_source") or 0)
            acc["detected_sink"] += int(row.get("detected_sink") or 0)
            acc["detected_other"] += int(row.get("detected_other") or 0)
            acc["chain_count"] += int(row.get("chain_count") or 0)
            acc["chain_with_source"] += int(row.get("chain_with_source") or 0)
            acc["chain_with_channel"] += int(row.get("chain_with_channel") or 0)
            acc["chain_confirmed"] += int(row.get("chain_confirmed") or 0)
            acc["chain_suspicious"] += int(row.get("chain_suspicious") or 0)
            acc["chain_safe_or_low_risk"] += int(row.get("chain_safe_or_low_risk") or 0)
            acc["chain_dropped"] += int(row.get("chain_dropped") or 0)
            acc["verdict_review_queue"] += int(row.get("verdict_review_queue") or 0)
            acc["verdict_review_needed"] += int(row.get("verdict_review_needed") or 0)
            acc["verdict_soft_suspicious"] += int(row.get("verdict_soft_suspicious") or 0)
            acc["verdict_llm_reviewed"] += int(row.get("verdict_llm_reviewed") or 0)

        by_dataset_rows = []
        for _, acc in sorted(by_dataset.items(), key=lambda x: x[0]):
            tp = float(acc["strict_tp"])
            fp = float(acc["strict_fp"])
            fn = float(acc["strict_fn"])
            p = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
            r = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
            f1 = (2 * p * r / (p + r)) if (p + r) > 0 else 0.0
            out = dict(acc)
            out["strict_precision"] = p
            out["strict_recall"] = r
            out["strict_f1"] = f1
            by_dataset_rows.append(out)

        # By-label table
        gt_label_agg: Dict[str, Dict[str, Any]] = {}
        for row in label_summary.get("rows", []):
            label = row.get("label_class", "")
            acc = gt_label_agg.setdefault(label, {
                "label": label,
                "kind": _label_kind(label),
                "gt_tp": 0.0,
                "gt_fp": 0.0,
                "gt_fn": 0.0,
            })
            acc["gt_tp"] += float(row.get("tp", 0) or 0)
            acc["gt_fp"] += float(row.get("fp", 0) or 0)
            acc["gt_fn"] += float(row.get("fn", 0) or 0)

        all_labels = (
            set(gt_label_agg.keys()) |
            set(detection_by_label_total.keys()) |
            set(detection_by_label_gt.keys()) |
            set(detection_by_label_no_gt.keys())
        )
        by_label_rows: List[Dict[str, Any]] = []
        for label in sorted(all_labels):
            gt_row = gt_label_agg.get(label, {})
            tp = float(gt_row.get("gt_tp", 0.0))
            fp = float(gt_row.get("gt_fp", 0.0))
            fn = float(gt_row.get("gt_fn", 0.0))
            p = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
            r = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
            f1 = (2 * p * r / (p + r)) if (p + r) > 0 else 0.0
            by_label_rows.append({
                "label": label,
                "kind": _label_kind(label),
                "gt_tp": tp,
                "gt_fp": fp,
                "gt_fn": fn,
                "gt_precision": p,
                "gt_recall": r,
                "gt_f1": f1,
                "detected_total": int(detection_by_label_total.get(label, 0)),
                "detected_in_gt_samples": int(detection_by_label_gt.get(label, 0)),
                "detected_in_no_gt_samples": int(detection_by_label_no_gt.get(label, 0)),
            })

        by_kind_rows: List[Dict[str, Any]] = []
        for kind in ("source", "sink", "other"):
            rows = [r for r in by_label_rows if str(r.get("kind", "")) == kind]
            tp = sum(float(r.get("gt_tp", 0.0) or 0.0) for r in rows)
            fp = sum(float(r.get("gt_fp", 0.0) or 0.0) for r in rows)
            fn = sum(float(r.get("gt_fn", 0.0) or 0.0) for r in rows)
            p = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
            r = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
            f1 = (2 * p * r / (p + r)) if (p + r) > 0 else 0.0
            by_kind_rows.append({
                "kind": kind,
                "gt_tp": tp,
                "gt_fp": fp,
                "gt_fn": fn,
                "gt_precision": p,
                "gt_recall": r,
                "gt_f1": f1,
                "detected_total": sum(int(rw.get("detected_total", 0) or 0) for rw in rows),
                "detected_in_gt_samples": sum(int(rw.get("detected_in_gt_samples", 0) or 0) for rw in rows),
                "detected_in_no_gt_samples": sum(int(rw.get("detected_in_no_gt_samples", 0) or 0) for rw in rows),
            })

        summary["by_dataset"] = by_dataset_rows
        summary["by_label_type"] = by_label_rows
        summary["by_kind"] = by_kind_rows
        summary["by_file"] = per_file_rows
        summary["chain_overall"] = {
            "chain_count": sum(int(r.get("chain_count") or 0) for r in per_file_rows),
            "chain_with_source": sum(int(r.get("chain_with_source") or 0) for r in per_file_rows),
            "chain_with_channel": sum(int(r.get("chain_with_channel") or 0) for r in per_file_rows),
            "chain_confirmed": sum(int(r.get("chain_confirmed") or 0) for r in per_file_rows),
            "chain_suspicious": sum(int(r.get("chain_suspicious") or 0) for r in per_file_rows),
            "chain_safe_or_low_risk": sum(int(r.get("chain_safe_or_low_risk") or 0) for r in per_file_rows),
            "chain_dropped": sum(int(r.get("chain_dropped") or 0) for r in per_file_rows),
            "verdict_review_queue": sum(int(r.get("verdict_review_queue") or 0) for r in per_file_rows),
            "verdict_review_needed": sum(int(r.get("verdict_review_needed") or 0) for r in per_file_rows),
            "verdict_soft_suspicious": sum(int(r.get("verdict_soft_suspicious") or 0) for r in per_file_rows),
            "verdict_llm_reviewed": sum(int(r.get("verdict_llm_reviewed") or 0) for r in per_file_rows),
        }
        (output_dir / "summary" / "eval_summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8",
        )

        _write_csv(
            output_dir / "tables" / "by_file.csv",
            per_file_rows,
            [
                "dataset", "sample_id", "binary_stem", "output_stem", "binary_path",
                "has_gt", "status", "eval_scope",
                "strict_tp", "strict_fp", "strict_fn",
                "strict_precision", "strict_recall", "strict_f1",
                "detected_total", "detected_source", "detected_sink", "detected_other",
                "detected_labels",
                "chain_count", "chain_with_source", "chain_with_channel",
                "chain_confirmed", "chain_suspicious", "chain_safe_or_low_risk", "chain_dropped",
                "verdict_review_queue", "verdict_review_needed", "verdict_soft_suspicious", "verdict_llm_reviewed",
            ],
        )
        _write_csv(
            output_dir / "tables" / "by_dataset.csv",
            by_dataset_rows,
            [
                "dataset", "sample_count", "gt_sample_count", "no_gt_sample_count",
                "ok_count", "error_count",
                "strict_tp", "strict_fp", "strict_fn",
                "strict_precision", "strict_recall", "strict_f1",
                "detected_total", "detected_source", "detected_sink", "detected_other",
                "chain_count", "chain_with_source", "chain_with_channel",
                "chain_confirmed", "chain_suspicious", "chain_safe_or_low_risk", "chain_dropped",
                "verdict_review_queue", "verdict_review_needed", "verdict_soft_suspicious", "verdict_llm_reviewed",
            ],
        )
        _write_csv(
            output_dir / "tables" / "by_label_type.csv",
            by_label_rows,
            [
                "label", "kind",
                "gt_tp", "gt_fp", "gt_fn",
                "gt_precision", "gt_recall", "gt_f1",
                "detected_total", "detected_in_gt_samples", "detected_in_no_gt_samples",
            ],
        )
        _write_csv(
            output_dir / "tables" / "by_kind.csv",
            by_kind_rows,
            [
                "kind",
                "gt_tp", "gt_fp", "gt_fn",
                "gt_precision", "gt_recall", "gt_f1",
                "detected_total", "detected_in_gt_samples", "detected_in_no_gt_samples",
            ],
        )

        md_lines = [
            "# Eval Suite Summary",
            "",
            "## Strict (GT-scored samples)",
            "",
            "| TP | FP | FN | Precision | Recall | F1 |",
            "|---:|---:|---:|---:|---:|---:|",
            (
                f"| {summary['strict_overall']['tp']:.0f} | "
                f"{summary['strict_overall']['fp']:.0f} | "
                f"{summary['strict_overall']['fn']:.0f} | "
                f"{summary['strict_overall']['precision']:.3f} | "
                f"{summary['strict_overall']['recall']:.3f} | "
                f"{summary['strict_overall']['f1']:.3f} |"
            ),
            "",
            "## Strict by Kind",
            "",
            "| Kind | TP | FP | FN | Precision | Recall | F1 |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for row in by_kind_rows:
            md_lines.append(
                f"| {row['kind']} | {row['gt_tp']:.0f} | {row['gt_fp']:.0f} | {row['gt_fn']:.0f} | "
                f"{row['gt_precision']:.3f} | {row['gt_recall']:.3f} | {row['gt_f1']:.3f} |"
            )

        md_lines.extend([
            "",
            "## Chain Overall",
            "",
            "| Chains | With Source | With Channel | Confirmed | Suspicious | Safe/Low-Risk | Dropped |",
            "|---:|---:|---:|---:|---:|---:|---:|",
            (
                f"| {summary['chain_overall']['chain_count']} | "
                f"{summary['chain_overall']['chain_with_source']} | "
                f"{summary['chain_overall']['chain_with_channel']} | "
                f"{summary['chain_overall']['chain_confirmed']} | "
                f"{summary['chain_overall']['chain_suspicious']} | "
                f"{summary['chain_overall']['chain_safe_or_low_risk']} | "
                f"{summary['chain_overall']['chain_dropped']} |"
            ),
            "",
            "## By Dataset",
            "",
            "| Dataset | Samples | GT | No-GT | TP | FP | FN | Detected Sources | Detected Sinks | Chains | Confirmed |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ])
        for row in by_dataset_rows:
            md_lines.append(
                f"| {row['dataset']} | {row['sample_count']} | {row['gt_sample_count']} | "
                f"{row['no_gt_sample_count']} | {row['strict_tp']:.0f} | "
                f"{row['strict_fp']:.0f} | {row['strict_fn']:.0f} | "
                f"{row['detected_source']} | {row['detected_sink']} | "
                f"{row['chain_count']} | {row['chain_confirmed']} |"
            )
        (output_dir / "summary" / "eval_summary.md").write_text(
            "\n".join(md_lines) + "\n",
            encoding="utf-8",
        )

        run_manifest = {
            "run_params": {
                "offline": offline,
                "online": bool(args.online),
                "stage": args.stage,
                "model": model or None,
                "proposer_mode": proposer_mode,
                "eval_scope_requested": eval_scope,
                "accepted_verdicts": accepted_verdict_names,
                "partial_credit": partial_credit,
                "formats": _parse_eval_formats(args.formats),
                "only_unstripped_elf": bool(args.only_unstripped_elf),
                "sample_timeout_sec": sample_timeout,
                "analysis_wait_sec": int(getattr(args, "analysis_wait_sec", 60) or 60),
                "mcp_connect_timeout_sec": int(getattr(args, "mcp_connect_timeout_sec", 30) or 30),
            },
            "binary_selection": {
                "single_binary": str(Path(args.binary).resolve()) if args.binary else None,
                "all_dir": str(Path(args.all).resolve()) if args.all else None,
                "manifest_json": (
                    str(Path(args.manifest_json).resolve()) if args.manifest_json else None
                ),
                "requested_count": len(items),
                "gt_json": str(Path(args.gt_json).resolve()) if args.gt_json else None,
            },
            "binary_meta": binary_meta,
            "format_counts": _format_counts(binary_meta),
            "mixed_formats": len({b["suffix"] for b in binary_meta}) > 1,
            "stripped_elf_count": sum(
                1 for b in binary_meta if b["suffix"] == "elf" and b["is_stripped_name_hint"]
            ),
            "sample_status": sample_summaries,
        }
        (output_dir / "run_manifest.json").write_text(
            json.dumps(run_manifest, indent=2), encoding="utf-8",
        )
        (output_dir / "detailed" / "all_samples_detailed.json").write_text(
            json.dumps(detailed_rows, indent=2), encoding="utf-8",
        )
        print(f"[SourceAgent] Eval artifacts written to: {output_dir}")


async def _cmd_gt_sinks(args):
    """Generate normalized GT sink list (machine-readable)."""
    from sourceagent.pipeline.gt_sink_catalog import write_normalized_sink_gt

    microbench_dir = Path(args.microbench_dir).resolve()
    output_json = Path(args.output_json).resolve()
    output_csv = Path(args.output_csv).resolve()

    if not microbench_dir.exists():
        print(f"Error: microbench dir not found: {microbench_dir}")
        sys.exit(1)

    summary = write_normalized_sink_gt(
        microbench_dir=microbench_dir,
        output_json=output_json,
        output_csv=output_csv,
    )
    print(
        "[SourceAgent] GT sink inventory generated: "
        f"{summary['entry_count']} entries across {summary['sample_count']} samples"
    )
    print(f"  JSON: {output_json}")
    print(f"  CSV:  {output_csv}")


async def _cmd_gt_sources(args):
    """Generate normalized GT source list (machine-readable)."""
    from sourceagent.pipeline.gt_source_catalog import write_normalized_source_gt

    output_json = Path(args.output_json).resolve()
    output_csv = Path(args.output_csv).resolve()
    summary = write_normalized_source_gt(
        output_json=output_json,
        output_csv=output_csv,
    )
    print(
        "[SourceAgent] GT source inventory generated: "
        f"{summary['entry_count']} entries across {summary['sample_count']} samples"
    )
    print(f"  JSON: {output_json}")
    print(f"  CSV:  {output_csv}")


async def _cmd_gt_bundle(args):
    """Generate combined normalized GT bundle (sources + sinks)."""
    from sourceagent.pipeline.gt_sink_catalog import build_normalized_sink_gt
    from sourceagent.pipeline.gt_source_catalog import build_normalized_source_gt

    microbench_dir = Path(args.microbench_dir).resolve()
    output_json = Path(args.output_json).resolve()
    output_csv = Path(args.output_csv).resolve()

    if not microbench_dir.exists():
        print(f"Error: microbench dir not found: {microbench_dir}")
        sys.exit(1)

    source_rows = build_normalized_source_gt()
    sink_rows = build_normalized_sink_gt(microbench_dir)

    rows: List[Dict[str, Any]] = []
    for row in source_rows:
        rows.append({**row, "gt_kind": "source"})
    for row in sink_rows:
        rows.append({**row, "gt_kind": "sink"})
    rows.sort(
        key=lambda x: (
            str(x.get("binary_stem", "")),
            str(x.get("gt_kind", "")),
            str(x.get("gt_source_id", x.get("gt_sink_id", ""))),
        )
    )

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    fieldnames = [
        "gt_kind",
        "binary_stem",
        "gt_source_id",
        "gt_sink_id",
        "label",
        "pipeline_label_hint",
        "function_name",
        "address",
        "address_hex",
        "address_status",
        "notes",
        "source_file",
        "map_file",
    ]
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    sample_count = len({str(r.get("binary_stem", "")) for r in rows})
    source_count = sum(1 for r in rows if r.get("gt_kind") == "source")
    sink_count = sum(1 for r in rows if r.get("gt_kind") == "sink")
    unresolved = sum(1 for r in rows if str(r.get("address_status", "")) != "resolved")
    print(
        "[SourceAgent] GT bundle generated: "
        f"{len(rows)} entries (source={source_count}, sink={sink_count}) "
        f"across {sample_count} samples, unresolved={unresolved}"
    )
    print(f"  JSON: {output_json}")
    print(f"  CSV:  {output_csv}")


# ── Async Runner ───────────────────────────────────────────────────────────


def _quiet_asyncio_run(coro):
    """Run async coroutine suppressing SSL teardown errors on shutdown."""
    loop = asyncio.new_event_loop()

    # Suppress spurious SSL/transport errors on shutdown
    original_handler = loop.get_exception_handler()

    def _quiet_handler(loop, context):
        exc = context.get("exception")
        if exc and isinstance(exc, (OSError, RuntimeError)):
            msg = str(exc)
            if "SSL" in msg or "transport" in msg.lower() or "Event loop is closed" in msg:
                return
        if original_handler:
            original_handler(loop, context)
        else:
            loop.default_exception_handler(context)

    loop.set_exception_handler(_quiet_handler)

    try:
        loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        loop.close()


if __name__ == "__main__":
    main()
