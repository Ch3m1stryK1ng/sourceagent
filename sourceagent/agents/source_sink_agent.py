"""SourceSinkAgent — LLM agent for RQ1 source/sink label recovery.

Replaces GeneralAgent. Uses the same BaseAgent infrastructure (Plan -> Act -> Observe
loop) but with a system prompt focused on:
  - MMIO register identification in ARM Cortex-M firmware
  - Memory copy sink pattern recognition
  - ISR boundary detection
  - Conservative labeling bias

Two modes:
  - MINE: Full pipeline orchestration (loads binary, runs stages 1-7)
  - PROPOSE: Single-shot LLM label proposal from a provided EvidencePack
"""

import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

from .base_agent import BaseAgent

logger = logging.getLogger("sourceagent.source_sink_agent")


class AgentMode(str, Enum):
    """Operating mode for SourceSinkAgent."""
    MINE = "mine"
    PROPOSE = "propose"


@dataclass
class TaskContext:
    """Context for a source/sink mining task."""
    mode: AgentMode = AgentMode.MINE
    description: str = ""
    file_path: str = ""
    run_id: str = ""
    max_stage: int = 7  # Run pipeline up to this stage


SOURCE_LABELS_DOC = """## Source Labels (where attacker-controlled data enters)
- MMIO_READ: A direct memory-mapped I/O register read (LDR/LDRH/LDRB targeting 0x40000000-0x5FFFFFFF)
- ISR_MMIO_READ: An MMIO read that occurs inside an Interrupt Service Routine
- ISR_FILLED_BUFFER: A SRAM buffer whose contents are populated by an ISR (ring buffer pattern)
- DMA_BACKED_BUFFER: A SRAM buffer filled by a DMA engine transfer, not CPU-driven reads
"""

SINK_LABELS_DOC = """## Sink Labels (where data is consumed unsafely)
- COPY_SINK: A call to memcpy/memmove/__aeabi_memcpy where the length is runtime-derived
- MEMSET_SINK: A call to memset/bzero where the size is not a compile-time constant
- STORE_SINK: A direct STR/STRB/STRH instruction writing to a buffer with non-constant offset
- LOOP_WRITE_SINK: A bounded loop (for/while) writing sequential bytes to a buffer
"""

SYSTEM_PROMPT_TEMPLATE = """You are SourceAgent, an expert at semantic source/sink label recovery in stripped ARM Cortex-M firmware binaries.

## Task
{task_description}

## Binary Under Analysis
Path: {file_path}

{source_labels_doc}
{sink_labels_doc}

## Analysis Rules
1. ALWAYS use Ghidra MCP tools to gather evidence. Never fabricate addresses or decompilation.
2. For sources: verify target address is in peripheral range (0x40000000-0x5FFFFFFF) for MMIO labels.
3. For sinks: verify the callee matches a known copy/memset function signature.
4. Conservative bias: when evidence is ambiguous, prefer the label that implies higher security relevance.
5. ISR detection: check if function address matches a vector table entry (words 2-N at base_address).
6. Record evidence: instruction address, decompile snippet, backward slice.

## Output Protocol
When proposing a label, output structured JSON between markers:

BEGIN_LABEL_JSON
{{"label": "MMIO_READ", "address": "0x40004400", "function": "uart_poll", "evidence_refs": ["E1", "E2"], "confidence": 0.85, "rationale": "..."}}
END_LABEL_JSON
"""


class SourceSinkAgent(BaseAgent):
    """Agent for RQ1 source/sink label recovery from firmware binaries."""

    def __init__(
        self,
        llm,
        tools,
        runtime=None,
        context: Optional[TaskContext] = None,
        max_iterations: int = 90,
        **kwargs,
    ):
        super().__init__(
            llm=llm,
            tools=tools,
            runtime=runtime,
            max_iterations=max_iterations,
            **kwargs,
        )
        self.context = context or TaskContext()

    def get_system_prompt(self, mode: str = "agent") -> str:
        """Generate system prompt for source/sink label recovery."""
        return SYSTEM_PROMPT_TEMPLATE.format(
            task_description=self.context.description or
                "Mine source and sink labels from the target firmware binary.",
            file_path=self.context.file_path or "(not specified)",
            source_labels_doc=SOURCE_LABELS_DOC,
            sink_labels_doc=SINK_LABELS_DOC,
        )
