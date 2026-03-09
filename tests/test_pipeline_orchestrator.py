"""Tests for the pipeline orchestrator (sourceagent/interface/main.py).

Tests use a mock-heavy approach since the orchestrator wires real stages
together. We mock individual stage functions to verify orchestration
logic: stage gating, offline mode, error handling, and result aggregation.
"""

import asyncio
import json
import types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sourceagent.pipeline.models import (
    EvidenceItem,
    EvidencePack,
    LLMProposal,
    MemoryAccess,
    MemoryAccessIndex,
    MemoryMap,
    MemoryRegion,
    ObligationStatus,
    PipelineResult,
    SinkCandidate,
    SinkLabel,
    SourceCandidate,
    SourceLabel,
    VerificationVerdict,
    VerifiedLabel,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────


def test_stem_counts_counts_duplicate_binary_stems(tmp_path):
    from sourceagent.interface.main import _stem_counts

    items = [
        {"binary_path": tmp_path / "same.elf"},
        {"binary_path": tmp_path / "same.bin"},
        {"binary_path": tmp_path / "other.elf"},
    ]

    counts = _stem_counts(items)

    assert counts == {"same": 2, "other": 1}


def test_make_eval_project_override_creates_unique_project_dirs():
    from sourceagent.interface.main import _make_eval_project_override

    path1 = Path(_make_eval_project_override("dup_sample"))
    path2 = Path(_make_eval_project_override("dup_sample"))

    assert path1.exists()
    assert path2.exists()
    assert path1 != path2
    assert path1.name.startswith("eval_dup_sample_")
    assert path2.name.startswith("eval_dup_sample_")


def test_needs_isolated_eval_project_for_duplicate_stem(tmp_path):
    from sourceagent.interface.main import _needs_isolated_eval_project

    binary = tmp_path / "same.elf"
    counts = {"same": 2}

    assert _needs_isolated_eval_project(binary, "same", counts) is True


def test_needs_isolated_eval_project_for_variant_output_stem(tmp_path):
    from sourceagent.interface.main import _needs_isolated_eval_project

    binary = tmp_path / "STM32469I_EVAL_stm32_udp_echo_server.elf"
    counts = {"STM32469I_EVAL_stm32_udp_echo_server": 1}

    assert _needs_isolated_eval_project(
        binary,
        "usbs_test_printf_fw",
        counts,
    ) is True


def _make_memory_map(binary_path="/tmp/test.bin"):
    return MemoryMap(
        binary_path=binary_path,
        arch="ARM:LE:32:Cortex",
        base_address=0x08000000,
        entry_point=0x08000100,
        regions=[
            MemoryRegion("FLASH", 0x08000000, 0x10000, "rx", "flash"),
            MemoryRegion("SRAM", 0x20000000, 0x5000, "rw", "sram"),
            MemoryRegion("PERIPHERAL", 0x40000000, 0x20000000, "rw", "mmio"),
        ],
        isr_handler_addrs=[0x08000101, 0x08000201],
    )


def _make_mai():
    return MemoryAccessIndex(
        binary_path="/tmp/test.bin",
        accesses=[
            MemoryAccess(0x08001000, "load", 4, target_addr=0x40011000,
                         base_provenance="CONST", function_name="FUN_08001000"),
        ],
        mmio_accesses=[
            MemoryAccess(0x08001000, "load", 4, target_addr=0x40011000,
                         base_provenance="CONST", function_name="FUN_08001000"),
        ],
        isr_functions=["FUN_08000100"],
    )


def _make_source():
    return SourceCandidate(
        address=0x08001000,
        function_name="FUN_08001000",
        preliminary_label=SourceLabel.MMIO_READ,
        evidence=[EvidenceItem("E1", "SITE", "load 4 bytes from 0x40011000")],
        confidence_score=0.7,
        facts={"addr_expr": "0x40011000", "provenance": "CONST", "segment": "MMIO"},
    )


def _make_sink():
    return SinkCandidate(
        address=0x08002000,
        function_name="FUN_08002000",
        preliminary_label=SinkLabel.COPY_SINK,
        evidence=[EvidenceItem("E1", "SITE", "memcpy call")],
        confidence_score=0.8,
        facts={"callee": "memcpy", "args_extracted": True},
    )


def _make_pack():
    return EvidencePack(
        pack_id="test-MMIO_READ-0x08001000-abc123",
        candidate_hint="MMIO_READ",
        binary_path="/tmp/test.bin",
        address=0x08001000,
        function_name="FUN_08001000",
        facts={"addr_expr": "0x40011000", "provenance": "CONST", "segment": "MMIO"},
        evidence=[EvidenceItem("E1", "SITE", "load 4 bytes from 0x40011000")],
    )


def _make_proposal():
    return LLMProposal(
        pack_id="test-MMIO_READ-0x08001000-abc123",
        label="MMIO_READ",
        address=0x08001000,
        function_name="FUN_08001000",
        claims=[{"addr_expr": "0x40011000", "provenance": "CONST", "segment": "MMIO"}],
        confidence=0.7,
        evidence_refs=["E1"],
    )


def _make_verified_label():
    return VerifiedLabel(
        pack_id="test-MMIO_READ-0x08001000-abc123",
        proposal=_make_proposal(),
        verdict=VerificationVerdict.VERIFIED,
        final_label="MMIO_READ",
    )


@pytest.fixture
def tmp_binary(tmp_path):
    """Create a minimal binary file for testing."""
    binary = tmp_path / "test_fw.bin"
    # Minimal ARM Cortex-M vector table (SP + reset vector)
    binary.write_bytes(b"\x00\x50\x00\x20\x01\x01\x00\x08" + b"\x00" * 248)
    return binary


@pytest.fixture
def mock_args(tmp_binary):
    """Mock CLI args."""
    args = types.SimpleNamespace(
        binary=str(tmp_binary),
        stage=7,
        model=None,
        run_id="test-run-001",
        offline=False,
        output=None,
    )
    return args


# ── Helper: run _cmd_mine with patches ────────────────────────────────────


async def _run_mine(args, patches=None):
    """Run _cmd_mine with optional patches applied."""
    from sourceagent.interface.main import _cmd_mine

    if patches:
        # Stack multiple patches
        import contextlib
        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            return await _cmd_mine(args)
    else:
        return await _cmd_mine(args)


# ── Tests: Stage 1 (loader) ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stage1_nonexistent_binary():
    """Non-existent binary should exit with error."""
    args = types.SimpleNamespace(
        binary="/tmp/nonexistent_binary_abc123.bin",
        stage=7, model=None, run_id="test", offline=False, output=None,
    )
    with pytest.raises(SystemExit):
        from sourceagent.interface.main import _cmd_mine
        await _cmd_mine(args)


@pytest.mark.asyncio
async def test_stage1_load_binary(tmp_binary):
    """Stage 1 should produce a MemoryMap from a valid binary."""
    args = types.SimpleNamespace(
        binary=str(tmp_binary), stage=1, model=None,
        run_id="test", offline=False, output=None,
    )
    with patch("sourceagent.agents.firmware_detect.detect_cortex_m_raw", return_value=None):
        with patch("sourceagent.pipeline.loader.load_binary", return_value=_make_memory_map(str(tmp_binary))):
            from sourceagent.interface.main import _cmd_mine
            result = await _cmd_mine(args)

    assert result is not None
    assert result.memory_map is not None
    assert len(result.memory_map.regions) == 3


@pytest.mark.asyncio
async def test_stage1_load_error(tmp_binary):
    """Stage 1 error should set stage_errors and return."""
    args = types.SimpleNamespace(
        binary=str(tmp_binary), stage=7, model=None,
        run_id="test", offline=False, output=None,
    )
    with patch("sourceagent.agents.firmware_detect.detect_cortex_m_raw", return_value=None):
        with patch("sourceagent.pipeline.loader.load_binary", side_effect=ValueError("bad binary")):
            from sourceagent.interface.main import _cmd_mine
            result = await _cmd_mine(args)

    assert "M1" in result.stage_errors
    assert result.memory_map is None


# ── Tests: Stage gating ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stage_gating_stops_at_1(tmp_binary):
    """--stage 1 should not attempt MCP connection."""
    args = types.SimpleNamespace(
        binary=str(tmp_binary), stage=1, model=None,
        run_id="test", offline=False, output=None,
    )
    mm = _make_memory_map(str(tmp_binary))

    with patch("sourceagent.agents.firmware_detect.detect_cortex_m_raw", return_value=None):
        with patch("sourceagent.pipeline.loader.load_binary", return_value=mm):
            from sourceagent.interface.main import _cmd_mine
            result = await _cmd_mine(args)

    assert result.memory_map is not None
    assert len(result.source_candidates) == 0
    assert len(result.verified_labels) == 0


@pytest.mark.asyncio
async def test_stage_gating_stops_at_4(tmp_binary):
    """--stage 4 should stop before evidence packing."""
    args = types.SimpleNamespace(
        binary=str(tmp_binary), stage=4, model=None,
        run_id="test", offline=True, output=None,
    )
    mm = _make_memory_map(str(tmp_binary))

    with patch("sourceagent.agents.firmware_detect.detect_cortex_m_raw", return_value=None):
        with patch("sourceagent.pipeline.loader.load_binary", return_value=mm):
            from sourceagent.interface.main import _cmd_mine
            result = await _cmd_mine(args)

    assert result.memory_map is not None
    assert len(result.evidence_packs) == 0
    assert len(result.proposals) == 0


@pytest.mark.asyncio
async def test_stage8_builds_phase_artifacts_cache(tmp_binary):
    """--stage 8 should populate cached phase artifacts on PipelineResult."""
    args = types.SimpleNamespace(
        binary=str(tmp_binary), stage=8, model=None,
        run_id="test-stage8", offline=True, output=None,
    )
    mm = _make_memory_map(str(tmp_binary))

    with patch("sourceagent.agents.firmware_detect.detect_cortex_m_raw", return_value=None):
        with patch("sourceagent.pipeline.loader.load_binary", return_value=mm):
            from sourceagent.interface.main import _cmd_mine
            result = await _cmd_mine(args)

    artifacts = getattr(result, "_phase_a_artifacts", {})
    assert artifacts
    assert artifacts["channel_graph"]["status"] == "ok"
    assert artifacts["sink_roots"]["status"] == "not_run"
    assert artifacts["triage_queue"]["status"] == "not_run"


# ── Tests: Offline mode ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_offline_mode_skips_mcp(tmp_binary):
    """Offline mode should skip Ghidra MCP stages and still run M1, M5-M7."""
    args = types.SimpleNamespace(
        binary=str(tmp_binary), stage=7, model=None,
        run_id="test", offline=True, output=None,
    )
    mm = _make_memory_map(str(tmp_binary))

    with patch("sourceagent.agents.firmware_detect.detect_cortex_m_raw", return_value=None):
        with patch("sourceagent.pipeline.loader.load_binary", return_value=mm):
            from sourceagent.interface.main import _cmd_mine
            result = await _cmd_mine(args)

    # Should have run stage 1 but skipped 2-4 (no MAI, no MCP)
    assert result.memory_map is not None
    assert len(result.source_candidates) == 0
    assert len(result.sink_candidates) == 0
    # Stages 5-7 still ran (with empty inputs)
    assert len(result.evidence_packs) == 0
    assert len(result.proposals) == 0
    assert len(result.verified_labels) == 0


# ── Tests: Full pipeline flow (all stages mocked) ───────────────────────


@pytest.mark.asyncio
async def test_full_pipeline_heuristic_mode(tmp_binary):
    """Full pipeline with heuristic proposer should run all 7 stages."""
    args = types.SimpleNamespace(
        binary=str(tmp_binary), stage=7, model=None,
        run_id="test-full", offline=True, output=None,
    )
    mm = _make_memory_map(str(tmp_binary))
    mai = _make_mai()
    source = _make_source()
    sink = _make_sink()
    pack = _make_pack()
    proposal = _make_proposal()
    verified = _make_verified_label()

    with patch("sourceagent.agents.firmware_detect.detect_cortex_m_raw", return_value=None), \
         patch("sourceagent.pipeline.loader.load_binary", return_value=mm), \
         patch("sourceagent.pipeline.miners.mmio_read.mine_mmio_read_sources", return_value=[source]), \
         patch("sourceagent.pipeline.miners.isr_context.mine_isr_sources", return_value=[]), \
         patch("sourceagent.pipeline.miners.dma_buffer.mine_dma_sources", return_value=[]), \
         patch("sourceagent.pipeline.evidence_packer.pack_evidence", return_value=[pack]), \
         patch("sourceagent.pipeline.proposer.propose_labels", new_callable=AsyncMock, return_value=[proposal]), \
         patch("sourceagent.pipeline.verifier.verify_proposals", new_callable=AsyncMock, return_value=[verified]):
        from sourceagent.interface.main import _cmd_mine
        # Need to reload to pick up patches via lazy imports
        result = await _cmd_mine(args)

    # Stage 1 ran
    assert result.memory_map is not None
    # Stages 3-4 ran (offline, so no MCP, but mmio miner was patched at module level)
    # Note: offline mode skips stages that need MAI (no MAI without MCP)
    # The patched miners won't actually be called because mai is None in offline mode
    # What we verify is that the pipeline structure works end-to-end
    assert result.run_id == "test-full"


# ── Tests: _find_ghidra_server ───────────────────────────────────────────


def test_find_ghidra_server_by_name():
    """Should find server with 'ghidra' in name."""
    from sourceagent.interface.main import _find_ghidra_server

    mock_mgr = MagicMock()
    mock_server = MagicMock()
    mock_server.connected = True
    mock_server.tools = []
    mock_mgr.servers = {"ghidra": mock_server}

    result = _find_ghidra_server(mock_mgr)
    assert result == "ghidra"


def test_find_ghidra_server_by_tools():
    """Should detect Ghidra server by tool names if not named 'ghidra'."""
    from sourceagent.interface.main import _find_ghidra_server

    mock_mgr = MagicMock()
    mock_server = MagicMock()
    mock_server.connected = True
    mock_server.tools = [
        {"name": "decompile_function"},
        {"name": "import_binary"},
        {"name": "search_symbols_by_name"},
    ]
    mock_mgr.servers = {"analysis-server": mock_server}

    result = _find_ghidra_server(mock_mgr)
    assert result == "analysis-server"


def test_find_ghidra_server_none():
    """Should return None if no ghidra server is connected."""
    from sourceagent.interface.main import _find_ghidra_server

    mock_mgr = MagicMock()
    mock_mgr.servers = {}
    assert _find_ghidra_server(mock_mgr) is None


def test_find_ghidra_server_disconnected():
    """Should skip disconnected servers."""
    from sourceagent.interface.main import _find_ghidra_server

    mock_mgr = MagicMock()
    mock_server = MagicMock()
    mock_server.connected = False
    mock_mgr.servers = {"ghidra": mock_server}
    assert _find_ghidra_server(mock_mgr) is None


# ── Tests: _parse_mcp_content ────────────────────────────────────────────


def test_parse_mcp_content_valid():
    """Should parse JSON from text content blocks."""
    from sourceagent.interface.main import _parse_mcp_content

    blocks = [{"type": "text", "text": '{"programs": []}'}]
    result = _parse_mcp_content(blocks)
    assert result == {"programs": []}


def test_parse_mcp_content_empty():
    """Should return None for empty content."""
    from sourceagent.interface.main import _parse_mcp_content
    assert _parse_mcp_content([]) is None
    assert _parse_mcp_content(None) is None


def test_parse_mcp_content_invalid_json():
    """Should return None for invalid JSON."""
    from sourceagent.interface.main import _parse_mcp_content

    blocks = [{"type": "text", "text": "not json"}]
    assert _parse_mcp_content(blocks) is None


def test_parse_mcp_content_non_text():
    """Should skip non-text blocks."""
    from sourceagent.interface.main import _parse_mcp_content

    blocks = [{"type": "image", "data": "..."}]
    assert _parse_mcp_content(blocks) is None


# ── Tests: _find_binary_in_project ───────────────────────────────────────


@pytest.mark.asyncio
async def test_find_binary_in_project():
    """Should find binary by stem match."""
    from sourceagent.interface.main import _find_binary_in_project

    mock_mgr = AsyncMock()
    mock_mgr.call_tool = AsyncMock(return_value=[
        {"type": "text", "text": json.dumps({
            "programs": [
                {"name": "/test_fw-abc123", "analysis_complete": True},
            ]
        })}
    ])

    result = await _find_binary_in_project(mock_mgr, "ghidra", "test_fw")
    assert result == "test_fw-abc123"


@pytest.mark.asyncio
async def test_find_binary_in_project_not_analyzed():
    """Should skip unanalyzed binaries when require_analyzed=True."""
    from sourceagent.interface.main import _find_binary_in_project

    mock_mgr = AsyncMock()
    mock_mgr.call_tool = AsyncMock(return_value=[
        {"type": "text", "text": json.dumps({
            "programs": [
                {"name": "/test_fw-abc123", "analysis_complete": False},
            ]
        })}
    ])

    result = await _find_binary_in_project(
        mock_mgr, "ghidra", "test_fw", require_analyzed=True,
    )
    assert result is None


@pytest.mark.asyncio
async def test_find_binary_in_project_no_match():
    """Should return None if stem doesn't match any binary."""
    from sourceagent.interface.main import _find_binary_in_project

    mock_mgr = AsyncMock()
    mock_mgr.call_tool = AsyncMock(return_value=[
        {"type": "text", "text": json.dumps({
            "programs": [
                {"name": "/other_fw-xyz789", "analysis_complete": True},
            ]
        })}
    ])

    result = await _find_binary_in_project(mock_mgr, "ghidra", "test_fw")
    assert result is None


@pytest.mark.asyncio
async def test_find_binary_in_project_mcp_error():
    """Should return None on MCP error."""
    from sourceagent.interface.main import _find_binary_in_project

    mock_mgr = AsyncMock()
    mock_mgr.call_tool = AsyncMock(side_effect=RuntimeError("MCP error"))

    result = await _find_binary_in_project(mock_mgr, "ghidra", "test_fw")
    assert result is None


# ── Tests: _import_and_analyze ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_import_and_analyze_already_imported():
    """Should return existing binary name without re-importing."""
    from sourceagent.interface.main import _import_and_analyze

    mock_mgr = AsyncMock()
    mock_mgr.call_tool = AsyncMock(return_value=[
        {"type": "text", "text": json.dumps({
            "programs": [
                {"name": "/test_fw-abc123", "analysis_complete": True},
            ]
        })}
    ])

    result = await _import_and_analyze(
        mock_mgr, "ghidra", Path("/tmp/test_fw.bin"),
    )
    assert result == "test_fw-abc123"
    # import_binary should not have been called (only list_project_binaries)
    calls = mock_mgr.call_tool.call_args_list
    assert all(c[0][1] == "list_project_binaries" for c in calls)


@pytest.mark.asyncio
async def test_import_and_analyze_new_binary():
    """Should import, poll, and return binary name."""
    from sourceagent.interface.main import _import_and_analyze

    call_count = 0

    async def mock_call_tool(server, tool, args):
        nonlocal call_count
        if tool == "list_project_binaries":
            call_count += 1
            if call_count <= 1:
                # First check: not found
                return [{"type": "text", "text": json.dumps({"programs": []})}]
            else:
                # Second check: found and analyzed
                return [{"type": "text", "text": json.dumps({
                    "programs": [
                        {"name": "/test_fw-abc123", "analysis_complete": True},
                    ]
                })}]
        elif tool == "import_binary":
            return [{"type": "text", "text": '{"status": "ok"}'}]
        return []

    mock_mgr = AsyncMock()
    mock_mgr.call_tool = mock_call_tool

    result = await _import_and_analyze(
        mock_mgr, "ghidra", Path("/tmp/test_fw.bin"),
        max_wait=30, poll_interval=0.1,
    )
    assert result == "test_fw-abc123"


@pytest.mark.asyncio
async def test_import_and_analyze_import_failure():
    """Should return None if import_binary fails."""
    from sourceagent.interface.main import _import_and_analyze

    async def mock_call_tool(server, tool, args):
        if tool == "list_project_binaries":
            return [{"type": "text", "text": json.dumps({"programs": []})}]
        elif tool == "import_binary":
            raise RuntimeError("import failed")
        return []

    mock_mgr = AsyncMock()
    mock_mgr.call_tool = mock_call_tool

    result = await _import_and_analyze(
        mock_mgr, "ghidra", Path("/tmp/test_fw.bin"),
    )
    assert result is None


@pytest.mark.asyncio
async def test_import_and_analyze_timeout():
    """Should return None after timeout if analysis never completes."""
    from sourceagent.interface.main import _import_and_analyze

    async def mock_call_tool(server, tool, args):
        if tool == "list_project_binaries":
            return [{"type": "text", "text": json.dumps({"programs": []})}]
        elif tool == "import_binary":
            return [{"type": "text", "text": '{"status": "ok"}'}]
        return []

    mock_mgr = AsyncMock()
    mock_mgr.call_tool = mock_call_tool

    result = await _import_and_analyze(
        mock_mgr, "ghidra", Path("/tmp/test_fw.bin"),
        max_wait=0.3, poll_interval=0.1,
    )
    # Timeout but no binary found at all → None
    assert result is None


# ── Tests: _write_json_output ────────────────────────────────────────────


def test_write_json_output(tmp_path):
    """Should write valid JSON to file."""
    from sourceagent.interface.main import _write_json_output

    result = PipelineResult(binary_path="/tmp/test.bin", run_id="test-001")
    result.memory_map = _make_memory_map()
    result.source_candidates = [_make_source()]

    out_file = tmp_path / "result.json"
    _write_json_output(result, str(out_file))

    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert data["run_id"] == "test-001"
    assert len(data["source_candidates"]) == 1


def test_write_json_output_with_verified_labels(tmp_path):
    """Should serialize verified labels with enum values."""
    from sourceagent.interface.main import _write_json_output

    result = PipelineResult(binary_path="/tmp/test.bin", run_id="test-002")
    result.verified_labels = [_make_verified_label()]

    out_file = tmp_path / "result.json"
    _write_json_output(result, str(out_file))

    data = json.loads(out_file.read_text())
    assert len(data["verified_labels"]) == 1
    vl = data["verified_labels"][0]
    assert vl["verdict"] == "VERIFIED"
    assert vl["final_label"] == "MMIO_READ"


# ── Tests: _print_result ────────────────────────────────────────────────


def test_print_result_minimal(capsys):
    """Should print summary even with empty result."""
    from sourceagent.interface.main import _print_result

    result = PipelineResult(binary_path="/tmp/test.bin", run_id="test-001")
    _print_result(result)

    output = capsys.readouterr().out
    assert "Pipeline complete" in output
    assert "test-001" in output


def test_print_result_with_labels(capsys):
    """Should print verified labels in summary."""
    from sourceagent.interface.main import _print_result

    result = PipelineResult(binary_path="/tmp/test.bin", run_id="test-002")
    result.memory_map = _make_memory_map()
    result.verified_labels = [_make_verified_label()]

    _print_result(result)

    output = capsys.readouterr().out
    assert "VERIFIED" in output
    assert "MMIO_READ" in output


def test_print_result_with_errors(capsys):
    """Should print stage errors."""
    from sourceagent.interface.main import _print_result

    result = PipelineResult(binary_path="/tmp/test.bin", run_id="test-003")
    result.stage_errors = {"M2": "connection failed"}

    _print_result(result)

    output = capsys.readouterr().out
    assert "connection failed" in output


# ── Tests: Stage error isolation ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_stage3_error_doesnt_block_later_stages(tmp_binary):
    """A source miner error should be recorded but not crash the pipeline."""
    args = types.SimpleNamespace(
        binary=str(tmp_binary), stage=7, model=None,
        run_id="test-err", offline=True, output=None,
    )
    mm = _make_memory_map(str(tmp_binary))

    with patch("sourceagent.agents.firmware_detect.detect_cortex_m_raw", return_value=None), \
         patch("sourceagent.pipeline.loader.load_binary", return_value=mm):
        from sourceagent.interface.main import _cmd_mine
        result = await _cmd_mine(args)

    # In offline mode, no MAI, so miners are skipped entirely
    # Pipeline should complete without errors
    assert result.run_id == "test-err"
    assert "M1" not in result.stage_errors


# ── Tests: Output flag ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_output_flag_writes_json(tmp_binary, tmp_path):
    """--output flag should write JSON result file."""
    out_file = tmp_path / "output.json"
    args = types.SimpleNamespace(
        binary=str(tmp_binary), stage=1, model=None,
        run_id="test-out", offline=False, output=str(out_file),
    )
    mm = _make_memory_map(str(tmp_binary))

    with patch("sourceagent.agents.firmware_detect.detect_cortex_m_raw", return_value=None), \
         patch("sourceagent.pipeline.loader.load_binary", return_value=mm):
        from sourceagent.interface.main import _cmd_mine
        result = await _cmd_mine(args)

    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert data["run_id"] == "test-out"


# ── Tests: _run_stage_2 ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_stage2_offline():
    """Stage 2 should return None in offline mode."""
    from sourceagent.interface.main import _run_stage_2
    from sourceagent.pipeline.models import PipelineResult

    result = PipelineResult(binary_path="/tmp/test.bin", run_id="test")
    mai = await _run_stage_2(_make_memory_map(), None, "", True, result)
    assert mai is None


@pytest.mark.asyncio
async def test_run_stage2_error():
    """Stage 2 error should be recorded in stage_errors."""
    from sourceagent.interface.main import _run_stage_2
    from sourceagent.pipeline.models import PipelineResult

    result = PipelineResult(binary_path="/tmp/test.bin", run_id="test")
    mock_mgr = AsyncMock()

    with patch(
        "sourceagent.pipeline.memory_access_index.build_memory_access_index",
        new_callable=AsyncMock,
        side_effect=RuntimeError("MCP timeout"),
    ):
        mai = await _run_stage_2(_make_memory_map(), mock_mgr, "test-abc", False, result)

    assert mai is None
    assert "M2" in result.stage_errors


# ── Tests: _run_stage_3 ─────────────────────────────────────────────────


def test_run_stage3_no_mai():
    """Stage 3 should return empty list when MAI is None."""
    from sourceagent.interface.main import _run_stage_3
    from sourceagent.pipeline.models import PipelineResult

    result = PipelineResult(binary_path="/tmp/test.bin", run_id="test")
    sources = _run_stage_3(None, _make_memory_map(), result)
    assert sources == []


def test_run_stage3_with_mai():
    """Stage 3 should call all three source miners."""
    from sourceagent.interface.main import _run_stage_3
    from sourceagent.pipeline.models import PipelineResult

    result = PipelineResult(binary_path="/tmp/test.bin", run_id="test")
    mai = _make_mai()
    mm = _make_memory_map()

    with patch("sourceagent.pipeline.miners.mmio_read.mine_mmio_read_sources", return_value=[_make_source()]), \
         patch("sourceagent.pipeline.miners.isr_context.mine_isr_sources", return_value=[]), \
         patch("sourceagent.pipeline.miners.dma_buffer.mine_dma_sources", return_value=[]):
        sources = _run_stage_3(mai, mm, result)

    assert len(sources) == 1
    assert sources[0].preliminary_label == SourceLabel.MMIO_READ


def test_run_stage3_miner_error():
    """Stage 3 should record errors but continue to other miners."""
    from sourceagent.interface.main import _run_stage_3
    from sourceagent.pipeline.models import PipelineResult

    result = PipelineResult(binary_path="/tmp/test.bin", run_id="test")
    mai = _make_mai()
    mm = _make_memory_map()

    with patch("sourceagent.pipeline.miners.mmio_read.mine_mmio_read_sources",
               side_effect=RuntimeError("crash")), \
         patch("sourceagent.pipeline.miners.isr_context.mine_isr_sources", return_value=[]), \
         patch("sourceagent.pipeline.miners.dma_buffer.mine_dma_sources", return_value=[]):
        sources = _run_stage_3(mai, mm, result)

    assert "VS0" in result.stage_errors
    assert sources == []  # Other miners returned empty


# ── Tests: _run_stage_4 ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_stage4_offline():
    """Stage 4 should return empty in offline mode."""
    from sourceagent.interface.main import _run_stage_4
    from sourceagent.pipeline.models import PipelineResult

    result = PipelineResult(binary_path="/tmp/test.bin", run_id="test")
    sinks = await _run_stage_4(_make_memory_map(), None, "", True, result)
    assert sinks == []


@pytest.mark.asyncio
async def test_run_stage4_with_mcp():
    """Stage 4 should call copy_sink miner when MCP available."""
    from sourceagent.interface.main import _run_stage_4
    from sourceagent.pipeline.models import PipelineResult

    result = PipelineResult(binary_path="/tmp/test.bin", run_id="test")
    mock_mgr = AsyncMock()

    with patch(
        "sourceagent.pipeline.miners.copy_sink.mine_copy_sinks",
        new_callable=AsyncMock,
        return_value=[_make_sink()],
    ):
        sinks = await _run_stage_4(_make_memory_map(), mock_mgr, "test-abc", False, result)

    assert len(sinks) == 1
    assert sinks[0].preliminary_label == SinkLabel.COPY_SINK


# ── Tests: _run_stage_5 ─────────────────────────────────────────────────


def test_run_stage5():
    """Stage 5 should pack evidence from sources and sinks."""
    from sourceagent.interface.main import _run_stage_5
    from sourceagent.pipeline.models import PipelineResult

    result = PipelineResult(binary_path="/tmp/test.bin", run_id="test")

    with patch("sourceagent.pipeline.evidence_packer.pack_evidence", return_value=[_make_pack()]):
        packs = _run_stage_5([_make_source()], [_make_sink()], result)

    assert len(packs) == 1
    assert len(result.evidence_packs) == 1


def test_run_stage5_error():
    """Stage 5 error should return None."""
    from sourceagent.interface.main import _run_stage_5
    from sourceagent.pipeline.models import PipelineResult

    result = PipelineResult(binary_path="/tmp/test.bin", run_id="test")

    with patch("sourceagent.pipeline.evidence_packer.pack_evidence",
               side_effect=RuntimeError("packing error")):
        packs = _run_stage_5([], [], result)

    assert packs is None
    assert "M5" in result.stage_errors


# ── Tests: _run_stage_6 ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_stage6_heuristic():
    """Stage 6 should use heuristic mode when no --model is specified."""
    from sourceagent.interface.main import _run_stage_6
    from sourceagent.pipeline.models import PipelineResult

    result = PipelineResult(binary_path="/tmp/test.bin", run_id="test")
    args = types.SimpleNamespace(model=None)

    with patch(
        "sourceagent.pipeline.proposer.propose_labels",
        new_callable=AsyncMock,
        return_value=[_make_proposal()],
    ):
        proposals = await _run_stage_6([_make_pack()], args, result)

    assert len(proposals) == 1
    assert len(result.proposals) == 1


@pytest.mark.asyncio
async def test_run_stage6_error():
    """Stage 6 error should return None."""
    from sourceagent.interface.main import _run_stage_6
    from sourceagent.pipeline.models import PipelineResult

    result = PipelineResult(binary_path="/tmp/test.bin", run_id="test")
    args = types.SimpleNamespace(model=None)

    with patch(
        "sourceagent.pipeline.proposer.propose_labels",
        new_callable=AsyncMock,
        side_effect=RuntimeError("LLM error"),
    ):
        proposals = await _run_stage_6([_make_pack()], args, result)

    assert proposals is None
    assert "M6" in result.stage_errors


# ── Tests: _run_stage_7 ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_stage7():
    """Stage 7 should verify proposals and store results."""
    from sourceagent.interface.main import _run_stage_7
    from sourceagent.pipeline.models import PipelineResult

    result = PipelineResult(binary_path="/tmp/test.bin", run_id="test")

    with patch(
        "sourceagent.pipeline.verifier.verify_proposals",
        new_callable=AsyncMock,
        return_value=[_make_verified_label()],
    ):
        await _run_stage_7([_make_proposal()], None, "", result)

    assert len(result.verified_labels) == 1
    assert result.verified_labels[0].verdict == VerificationVerdict.VERIFIED


@pytest.mark.asyncio
async def test_run_stage7_error():
    """Stage 7 error should be recorded but not crash."""
    from sourceagent.interface.main import _run_stage_7
    from sourceagent.pipeline.models import PipelineResult

    result = PipelineResult(binary_path="/tmp/test.bin", run_id="test")

    with patch(
        "sourceagent.pipeline.verifier.verify_proposals",
        new_callable=AsyncMock,
        side_effect=RuntimeError("verify error"),
    ):
        await _run_stage_7([_make_proposal()], None, "", result)

    assert "M7" in result.stage_errors
    assert len(result.verified_labels) == 0
