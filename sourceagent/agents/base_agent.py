"""Base agent class for PentestAgent."""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, AsyncIterator, List, Optional

from ..config.constants import AGENT_MAX_ITERATIONS
from .state import AgentState, AgentStateManager

logger = logging.getLogger("sourceagent.base_agent")

if TYPE_CHECKING:
    from ..llm import LLM
    from ..runtime import Runtime
    from ..tools import Tool


@dataclass
class ToolCall:
    """Represents a tool call from the LLM."""

    id: str
    name: str
    arguments: dict


@dataclass
class ToolResult:
    """Result from a tool execution."""

    tool_call_id: str
    tool_name: str
    result: Optional[str] = None
    error: Optional[str] = None
    success: bool = True


@dataclass
class AgentMessage:
    """A message in the agent conversation."""

    role: str  # "user", "assistant", "tool_result", "system"
    content: str
    tool_calls: Optional[List[ToolCall]] = None
    tool_results: Optional[List[ToolResult]] = None
    metadata: dict = field(default_factory=dict)
    usage: Optional[dict] = None  # Token usage from LLM response

    def to_llm_format(self) -> dict:
        """Convert to LLM message format."""
        import json

        msg = {"role": self.role, "content": self.content}

        if self.tool_calls:
            msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": (
                            json.dumps(tc.arguments)
                            if isinstance(tc.arguments, dict)
                            else tc.arguments
                        ),
                    },
                }
                for tc in self.tool_calls
            ]

        return msg


class BaseAgent(ABC):
    """Base class for all agents."""

    def __init__(
        self,
        llm: "LLM",
        tools: List["Tool"],
        runtime: "Runtime",
        max_iterations: int = AGENT_MAX_ITERATIONS,
    ):
        """
        Initialize the base agent.

        Args:
            llm: The LLM instance for generating responses
            tools: List of tools available to the agent
            runtime: The runtime environment for tool execution
            max_iterations: Maximum iterations before forcing stop (safety limit)
        """
        self.llm = llm
        self.runtime = runtime
        self.max_iterations = max_iterations
        self.state_manager = AgentStateManager()
        self.conversation_history: List[AgentMessage] = []
        self._llm_trace_path: Optional[Path] = None

        # Langfuse trace (set in agent_loop / solve)
        self._lf_trace = None
        self._llm_error_count = 0

        # Each agent gets its own plan instance
        from ..tools.finish import TaskPlan

        self._task_plan = TaskPlan()

        # Attach plan to runtime so finish tool can access it
        self.runtime.plan = self._task_plan

        # Use tools as-is (finish accesses plan via runtime)
        self.tools = list(tools)

    def set_llm_trace_path(self, path: Optional[str]) -> None:
        """Enable LLM request/response tracing to a JSONL file."""
        self._llm_trace_path = Path(path) if path else None

    def should_auto_plan(self) -> bool:
        """Whether to auto-generate a plan before tool usage."""
        return True

    @property
    def state(self) -> AgentState:
        """Get current agent state."""
        return self.state_manager.current_state

    @state.setter
    def state(self, value: AgentState):
        """Set agent state."""
        self.state_manager.transition_to(value)

    def cleanup_after_cancel(self) -> None:
        """
        Clean up agent state after a cancellation.

        Removes the cancelled request and any pending tool calls from
        conversation history to prevent stale responses from contaminating
        the next conversation.
        """
        # Remove incomplete messages from the end of conversation
        while self.conversation_history:
            last_msg = self.conversation_history[-1]
            # Remove assistant message with tool calls (incomplete tool execution)
            if last_msg.role == "assistant" and last_msg.tool_calls:
                self.conversation_history.pop()
            # Remove orphaned tool_result messages
            elif last_msg.role == "tool":
                self.conversation_history.pop()
            # Remove the user message that triggered the cancelled request
            elif last_msg.role == "user":
                self.conversation_history.pop()
                break  # Stop after removing the user message
            else:
                break

        # Reset state to idle
        self.state_manager.transition_to(AgentState.IDLE)

    @abstractmethod
    def get_system_prompt(self, mode: str = "agent") -> str:
        """Return the system prompt for this agent.

        Args:
            mode: 'agent' for autonomous mode, 'assist' for single-shot assist mode
        """
        pass

    async def preflight(self) -> None:
        """Optional preflight hook for agents."""
        return None
    
    def _truncate_text(self, text: str, limit: int = 4000) -> str:
        if text and len(text) > limit:
            return text[:limit] + "...[truncated]"
        return text

    def _append_llm_trace(self, payload: dict) -> None:
        """Append a trace event to the JSONL trace file."""
        if not self._llm_trace_path:
            return
        try:
            self._llm_trace_path.parent.mkdir(parents=True, exist_ok=True)
            with self._llm_trace_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except Exception:
            # Best-effort tracing; never fail the agent loop
            return

    def _truncate_tool_output(self, tool_name: str, content: str, limit: int = 12000) -> str:
        """Reduce large tool outputs before sending to the LLM."""
        if not content:
            return content

        # Attempt structured trimming for Ghidra MCP JSON outputs
        if "mcp_ghidra" in (tool_name or ""):
            try:
                data = json.loads(content)
                # Some tools wrap payload under "data"
                if isinstance(data, dict) and "data" in data:
                    data = data.get("data", data)
            except Exception:
                return self._truncate_text(content, limit)

            # disassemble_function: keep only dangerous calls and nearby windows
            if "disassembly" in data or "dangerous_calls" in data:
                disasm = data.get("disassembly", [])
                dangerous = data.get("dangerous_calls", [])
                if disasm and dangerous:
                    # Build index map
                    addr_to_idx = {line.get("address"): i for i, line in enumerate(disasm)}
                    windows = []
                    for call in dangerous:
                        idx = addr_to_idx.get(call.get("address"))
                        if idx is None:
                            continue
                        # Slightly larger context window for better LLM reasoning
                        start = max(0, idx - 20)
                        end = min(len(disasm), idx + 21)
                        windows.append(
                            {
                                "around": call.get("address"),
                                "function": call.get("function"),
                                "context": disasm[start:end],
                            }
                        )
                    data = {
                        "function_name": data.get("function_name"),
                        "start_address": data.get("start_address"),
                        "end_address": data.get("end_address"),
                        "dangerous_calls": dangerous,
                        "evidence_windows": windows[:10],
                    }
                else:
                    # If no dangerous calls, keep a small head/tail
                    data["disassembly"] = (disasm[:60] + disasm[-20:]) if disasm else []
                return json.dumps(data)[:limit]

            # decompile_function: keep pseudocode + line_map (truncate)
            if "pseudocode" in data or "line_map" in data:
                line_map = data.get("line_map", [])
                if isinstance(line_map, list):
                    line_map = line_map[:200]
                data = {
                    "function": data.get("function"),
                    "address": data.get("address"),
                    "pseudocode": (data.get("pseudocode") or "")[:8000],
                    "line_map": line_map,
                    "warnings": data.get("warnings", []),
                    "hexrays_available": data.get("hexrays_available", False),
                }
                return json.dumps(data)[:limit]

            # get_strings: keep only format strings and suspicious hints
            if "strings" in data and ("format_strings" in data or "paths" in data):
                data = {
                    "count": data.get("count"),
                    "format_strings": data.get("format_strings", [])[:50],
                    "paths": data.get("paths", [])[:50],
                    "strings": [
                        s for s in data.get("strings", [])
                        if any(k in (s.get("content", "")).lower() for k in ["mode", "usage", "uaf", "blob", "path", "line", "starts with"])
                    ][:50],
                }
                return json.dumps(data)[:limit]

            # get_functions / find_xrefs: trim lists
            if "functions" in data:
                data["functions"] = data.get("functions", [])[:120]
                return json.dumps(data)[:limit]
            if "xrefs_to" in data or "xrefs_from" in data:
                data["xrefs_to"] = data.get("xrefs_to", [])[:80]
                data["xrefs_from"] = data.get("xrefs_from", [])[:80]
                return json.dumps(data)[:limit]

            return json.dumps(data)[:limit]

        # Default truncation
        return self._truncate_text(content, limit)

    async def agent_loop(self, initial_message: str) -> AsyncIterator[AgentMessage]:
        """
        Main agent execution loop.

        Starts a new task session, resetting previous state and history.

        Simple control flow:
        - Tool calls: Execute tools, continue loop
        - Text response (no tools): Done
        - Max iterations reached: Force stop with warning

        Args:
            initial_message: The initial user message to process

        Yields:
            AgentMessage objects as the agent processes
        """
        # Always reset for a new agent loop task to ensure clean state
        self.reset()

        # Create Langfuse root trace (no-op when disabled)
        from ..observability import create_trace
        self._lf_trace = create_trace(
            name="agent_loop",
            metadata={"initial_message": initial_message[:200]},
        )

        self.state_manager.transition_to(AgentState.THINKING)
        self.conversation_history.append(
            AgentMessage(role="user", content=initial_message)
        )

        # Optional preflight (agent-specific)
        try:
            await self.preflight()
        except Exception:
            # Preflight failures should not abort the main loop
            pass

        async for msg in self._run_loop():
            yield msg

    async def continue_conversation(
        self, user_message: str
    ) -> AsyncIterator[AgentMessage]:
        """
        Continue the conversation with a new user message.

        Args:
            user_message: The new user message

        Yields:
            AgentMessage objects as the agent processes
        """
        self.conversation_history.append(
            AgentMessage(role="user", content=user_message)
        )
        self.state_manager.transition_to(AgentState.THINKING)

        async for msg in self._run_loop():
            yield msg

    async def _run_loop(self) -> AsyncIterator[AgentMessage]:
        """
        Core agent loop logic - shared by agent_loop and continue_conversation.

        Termination conditions:
        1. finish tool is called AND plan complete -> clean exit with summary
        2. max_iterations reached -> forced exit with warning
        3. error -> exit with error state

        Text responses WITHOUT tool calls are treated as "thinking out loud"
        and do NOT terminate the loop. This prevents premature stopping.

        The loop enforces plan completion before allowing finish.

        Yields:
            AgentMessage objects as the agent processes
        """
        # Clear any previous plan for new task — but only when the
        # subclass will auto-generate one.  GeneralAgent pre-populates
        # _task_plan before entering the loop; clearing it here would
        # make is_complete() return True on an empty list, exiting the
        # loop after the first tool call.
        if self.should_auto_plan():
            self._task_plan.clear()

        from ..observability import build_litellm_metadata, span_context

        iteration = 0

        while iteration < self.max_iterations:
            iteration += 1

            # Hook: let subclasses inject messages or override tools per-iteration
            iter_tools = self._on_iteration_start(iteration, self.max_iterations)

            # ITERATION 1: Force plan creation (loop-enforced, not prompt-based)
            if iteration == 1 and len(self._task_plan.steps) == 0 and self.should_auto_plan():
                plan_msg = await self._auto_generate_plan()
                if plan_msg:
                    yield plan_msg

            system_prompt = self.get_system_prompt()
            messages_payload = self._format_messages_for_llm()

            # Trace request (truncated for safety/readability)
            self._append_llm_trace(
                {
                    "ts": datetime.now().isoformat(),
                    "event": "llm_request",
                    "iteration": iteration,
                    "system_prompt": self._truncate_text(system_prompt, 6000),
                    "messages": [
                        {
                            "role": m.get("role"),
                            "content": self._truncate_text(str(m.get("content", "")), 6000),
                            "tool_calls": m.get("tool_calls"),
                        }
                        for m in messages_payload
                    ],
                    "tools": [t.name for t in self.tools if getattr(t, "enabled", True)],
                }
            )

            # Build Langfuse metadata for litellm correlation
            _iter_name = f"iteration_{iteration}"
            _lf_meta = build_litellm_metadata(
                trace_id=getattr(self._lf_trace, "id", ""),
                span_id="",  # filled below inside span
                generation_name=_iter_name,
            )

            response = await self.llm.generate(
                system_prompt=system_prompt,
                messages=messages_payload,
                tools=iter_tools if iter_tools is not None else self.tools,
                metadata=_lf_meta or None,
            )

            # Trace response
            self._append_llm_trace(
                {
                    "ts": datetime.now().isoformat(),
                    "event": "llm_response",
                    "iteration": iteration,
                    "model": response.model,
                    "finish_reason": response.finish_reason,
                    "content": self._truncate_text(response.content or "", 6000),
                    "tool_calls": response.tool_calls,
                    "usage": response.usage,
                }
            )

            # Case 0: LLM API error — don't burn an iteration, retry with backoff
            if response.finish_reason == "error":
                err_text = response.content or "LLM Error"
                _is_permanent = any(k in err_text.lower() for k in [
                    "badrequest", "bad_request", "invalid parameter",
                    "invalid_api_key", "authentication",
                    "status\": 401", "status: 401",
                ])
                _llm_err_count = getattr(self, "_llm_error_count", 0) + 1
                self._llm_error_count = _llm_err_count
                logger.warning(
                    f"[BASE_AGENT] LLM error #{_llm_err_count} at iteration {iteration}: "
                    f"{err_text[:120]}"
                )
                # Yield the error so the UI can display it
                yield AgentMessage(role="assistant", content=err_text)
                if _is_permanent or _llm_err_count >= 5:
                    reason = "permanent API error" if _is_permanent else f"{_llm_err_count} consecutive LLM API errors"
                    yield AgentMessage(
                        role="assistant",
                        content=f"[!] Stopping: {reason}.",
                        metadata={"max_iterations_reached": True},
                    )
                    return
                # Don't count this as an iteration — roll back and wait
                iteration -= 1
                await asyncio.sleep(min(10 * _llm_err_count, 60))
                continue
            else:
                self._llm_error_count = 0  # Reset on success

            # Case 1: Empty response - try recovery
            if not response.tool_calls and not response.content:
                # Track consecutive empty responses
                empty_count = getattr(self, "_empty_response_count", 0) + 1
                self._empty_response_count = empty_count
                logger.warning(f"[BASE_AGENT] Empty response #{empty_count} at iteration {iteration}")

                if empty_count >= 3:
                    # Multiple empty responses - generate summary from notes and exit
                    # Try to get findings from notes
                    summary_content = "Analysis completed. "
                    try:
                        from ..tools.notes import get_all_notes_sync
                        notes = get_all_notes_sync()
                        if notes:
                            vuln_notes = [f"- {k}: {v.get('content', v) if isinstance(v, dict) else v}"
                                         for k, v in notes.items()
                                         if isinstance(v, dict) and v.get('category') == 'vulnerability'
                                         or 'vuln' in str(k).lower()]
                            if vuln_notes:
                                summary_content += f"Found {len(vuln_notes)} potential vulnerabilities:\n" + "\n".join(vuln_notes[:5])
                            else:
                                summary_content += "No vulnerabilities recorded in notes."
                        else:
                            summary_content += "No findings recorded."
                    except Exception:
                        summary_content += "Unable to retrieve findings."

                    stuck_msg = AgentMessage(
                        role="assistant",
                        content=summary_content,
                        metadata={"empty_response": True, "auto_summary": True},
                    )
                    self.conversation_history.append(stuck_msg)
                    yield stuck_msg
                    self.state_manager.transition_to(AgentState.COMPLETE)
                    return

                # Recovery prompts - increasingly explicit
                if empty_count == 1:
                    recovery_prompt = (
                        "Continue with your analysis. What is the next step? "
                        "Use the available tools to gather more information or "
                        "use the notes tool to record any findings."
                    )
                else:
                    recovery_prompt = (
                        "IMPORTANT: You must respond. Either:\n"
                        "1. Call a tool to continue analysis (mcp_ghidra-local_*, terminal, notes)\n"
                        "2. Use notes(action='create', key='finding', value='...', category='vulnerability') to record findings\n"
                        "3. Provide a text summary of your analysis\n\n"
                        "What vulnerabilities have you found so far?"
                    )

                logger.info(f"[BASE_AGENT] Sending recovery prompt #{empty_count}")
                self.conversation_history.append(
                    AgentMessage(role="user", content=recovery_prompt)
                )
                continue
            else:
                # Reset empty count on valid response
                self._empty_response_count = 0

            # Case 2: Thinking / Intermediate Output (Content but no tools)
            if not response.tool_calls:
                thinking_msg = AgentMessage(
                    role="assistant",
                    content=response.content,
                    usage=response.usage,
                    metadata={"intermediate": True},
                )
                self.conversation_history.append(thinking_msg)
                yield thinking_msg
                continue

            # Case 3: Tool Execution
            # Build tool calls list
            tool_calls = [
                ToolCall(
                    id=tc.id if hasattr(tc, "id") else str(i),
                    name=(
                        tc.function.name
                        if hasattr(tc, "function")
                        else tc.get("name", "")
                    ),
                    arguments=self._parse_arguments(tc),
                )
                for i, tc in enumerate(response.tool_calls)
            ]

            # Execute tools
            self.state_manager.transition_to(AgentState.EXECUTING)

            # Yield thinking message if content exists (before execution)
            if response.content:
                thinking_msg = AgentMessage(
                    role="assistant",
                    content=response.content,
                    usage=response.usage,
                    metadata={"intermediate": True},
                )
                yield thinking_msg

            tool_results = await self._execute_tools(response.tool_calls)

            # Record in history
            assistant_msg = AgentMessage(
                role="assistant",
                content=response.content or "",
                tool_calls=tool_calls,
                usage=response.usage,
            )
            self.conversation_history.append(assistant_msg)

            tool_result_msg = AgentMessage(
                role="tool_result", content="", tool_results=tool_results
            )
            self.conversation_history.append(tool_result_msg)

            # Yield results for display update immediately
            display_msg = AgentMessage(
                role="assistant",
                content="",  # Suppress content here as it was already yielded as thinking
                tool_calls=tool_calls,
                tool_results=tool_results,
                usage=response.usage,
            )
            yield display_msg

            # Check for plan failure (Tactical Replanning)
            if (
                hasattr(self._task_plan, "has_failure")
                and self._task_plan.has_failure()
            ):
                # Find the failed step
                failed_step = None
                for s in self._task_plan.steps:
                    if s.status == "fail":
                        failed_step = s
                        break

                if failed_step:
                    replan_msg = await self._replan(failed_step)
                    if replan_msg:
                        self.conversation_history.append(replan_msg)
                        yield replan_msg

                        # Check if replan indicated impossibility
                        if replan_msg.metadata.get("replan_impossible"):
                            self.state_manager.transition_to(AgentState.COMPLETE)
                            return

                        continue

            # Check if plan is now complete
            if self._task_plan.is_complete():
                # All steps done - generate final summary
                summary_response = await self.llm.generate(
                    system_prompt="You are a helpful assistant. Provide a brief, clear summary of what was accomplished.",
                    messages=self._format_messages_for_llm(),
                    tools=self.tools,  # Must provide tools if history contains tool calls
                )

                completion_msg = AgentMessage(
                    role="assistant",
                    content=summary_response.content or "Task complete.",
                    usage=summary_response.usage,
                    metadata={"task_complete": True},
                )
                self.conversation_history.append(completion_msg)
                yield completion_msg
                self.state_manager.transition_to(AgentState.COMPLETE)
                return

            self.state_manager.transition_to(AgentState.THINKING)

        # Max iterations reached - force stop
        warning_msg = AgentMessage(
            role="assistant",
            content=f"[!] Reached maximum iterations ({self.max_iterations}). Stopping to prevent infinite loop. You can continue the conversation if needed.",
            metadata={"max_iterations_reached": True},
        )
        self.conversation_history.append(warning_msg)
        yield warning_msg
        self.state_manager.transition_to(AgentState.COMPLETE)

    def _format_messages_for_llm(self) -> List[dict]:
        """Format conversation history for LLM."""
        messages = []

        for msg in self.conversation_history:
            if msg.role == "tool_result" and msg.tool_results:
                # Format tool results as tool response messages
                for result in msg.tool_results:
                    messages.append(
                        {
                            "role": "tool",
                            "content": (
                                self._truncate_tool_output(result.tool_name, result.result)
                                if result.success
                                else f"Error: {result.error}"
                            ),
                            "tool_call_id": result.tool_call_id,
                        }
                    )
            else:
                messages.append(msg.to_llm_format())

        # Memory summarization/truncation can split assistant-tool_call/tool pairs.
        # OpenAI tool-call protocol requires each "tool" message to correspond to a
        # preceding assistant message with matching tool_call id.
        return self._sanitize_llm_messages(messages)

    def _sanitize_llm_messages(self, messages: List[dict]) -> List[dict]:
        """
        Drop orphan tool messages that do not have an in-scope assistant tool call.

        This prevents OpenAI 400 errors like:
        "messages with role 'tool' must be a response to a preceding message with 'tool_calls'".
        """
        sanitized: List[dict] = []
        open_tool_ids: set[str] = set()

        for m in messages:
            role = m.get("role")

            if role == "assistant":
                # A new assistant turn starts a fresh expected tool-call set.
                open_tool_ids = set()
                for tc in m.get("tool_calls") or []:
                    tc_id = tc.get("id")
                    if tc_id:
                        open_tool_ids.add(tc_id)
                sanitized.append(m)
                continue

            if role == "tool":
                tc_id = m.get("tool_call_id")
                if tc_id and tc_id in open_tool_ids:
                    sanitized.append(m)
                    open_tool_ids.discard(tc_id)
                else:
                    logger.debug(
                        "[BASE_AGENT] Dropping orphan tool message with tool_call_id=%s",
                        tc_id,
                    )
                continue

            sanitized.append(m)

        return sanitized

    def _parse_arguments(self, tool_call: Any) -> dict:
        """Parse tool call arguments."""
        import json

        if hasattr(tool_call, "function"):
            args = tool_call.function.arguments
        elif isinstance(tool_call, dict):
            args = tool_call.get("arguments", {})
        else:
            args = {}

        if isinstance(args, str):
            try:
                return json.loads(args)
            except json.JSONDecodeError:
                return {"raw": args}
        return args

    async def _execute_tools(self, tool_calls: List[Any]) -> List[ToolResult]:
        """
        Execute tool calls and return results.

        Args:
            tool_calls: List of tool calls from the LLM

        Returns:
            List of ToolResult objects
        """
        from ..observability import span_context

        results = []

        for i, call in enumerate(tool_calls):
            # Extract tool call id, name and arguments
            if hasattr(call, "id"):
                tool_call_id = call.id
            elif isinstance(call, dict) and "id" in call:
                tool_call_id = call["id"]
            else:
                tool_call_id = f"call_{i}"

            if hasattr(call, "function"):
                name = call.function.name
                arguments = self._parse_arguments(call)
            elif isinstance(call, dict):
                name = call.get("name", "")
                arguments = call.get("arguments", {})
            else:
                continue

            tool = self._find_tool(name)

            with span_context(
                self._lf_trace,
                f"tool_{name}",
                metadata={"arguments": {k: str(v)[:200] for k, v in (arguments or {}).items()}},
            ):
                if tool:
                    try:
                        result = await tool.execute(arguments, self.runtime)
                        results.append(
                            ToolResult(
                                tool_call_id=tool_call_id,
                                tool_name=name,
                                result=result,
                                success=True,
                            )
                        )
                    except Exception as e:
                        results.append(
                            ToolResult(
                                tool_call_id=tool_call_id,
                                tool_name=name,
                                error=str(e),
                                success=False,
                            )
                        )
                else:
                    results.append(
                        ToolResult(
                            tool_call_id=tool_call_id,
                            tool_name=name,
                            error=f"Tool '{name}' not found",
                            success=False,
                        )
                    )

        return results

    def _find_tool(self, name: str) -> Optional["Tool"]:
        """
        Find a tool by name.

        Args:
            name: The tool name to find

        Returns:
            The Tool if found, None otherwise
        """
        for tool in self.tools:
            if tool.name == name:
                return tool
        # Fallback: if tool not found, attempt to use a generic terminal tool
        # for commands. Some LLMs may emit semantic tool names (e.g. "network_scan")
        # instead of the actual registered tool name. Use the `terminal` tool
        # as a best-effort fallback when available.
        for tool in self.tools:
            if tool.name == "terminal":
                return tool
        return None

    def _on_iteration_start(self, iteration: int, max_iterations: int) -> Optional[list]:
        """Hook called at the start of each loop iteration.

        Subclasses can override to inject messages into conversation_history
        or return a tools list to override self.tools for this iteration.

        Returns:
            None to use self.tools, or a list of tools to override.
        """
        return None

    def _can_finish(self) -> tuple[bool, str]:
        """Check if the agent can finish based on plan completion."""
        if len(self._task_plan.steps) == 0:
            return True, "No plan exists"

        pending = self._task_plan.get_pending_steps()
        if pending:
            pending_desc = ", ".join(
                f"Step {s.id}: {s.description}" for s in pending[:3]
            )
            more = f" (+{len(pending) - 3} more)" if len(pending) > 3 else ""
            return False, f"Incomplete: {pending_desc}{more}"

        return True, "All steps complete"

    async def _auto_generate_plan(self) -> Optional[AgentMessage]:
        """
        Automatically generate a plan from the user's request (loop-enforced).

        This is called on iteration 1 to force plan creation before any tool execution.
        Uses function calling for reliable structured output.

        Returns:
            AgentMessage with plan display, or None if generation fails
        """
        from ..tools.finish import PlanStep
        from ..tools.registry import Tool, ToolSchema

        # Get the user's original request (last message)
        user_request = ""
        for msg in reversed(self.conversation_history):
            if msg.role == "user":
                user_request = msg.content
                break

        if not user_request:
            return None  # No request to plan

        # Create a temporary tool for plan generation (function calling)
        plan_generator_tool = Tool(
            name="create_plan",
            description="Create a step-by-step plan for the task. Call this with the steps needed.",
            schema=ToolSchema(
                properties={
                    "steps": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of actionable steps (one tool action each)",
                    },
                },
                required=["steps"],
            ),
            execute_fn=lambda args, runtime: None,  # Dummy - we parse args directly
            category="planning",
        )

        plan_prompt = f"""Break this request into minimal, actionable steps.

Request: {user_request}

Guidelines:
- Be concise (typically 2-4 steps)
- One tool action per step
- Don't include waiting/loading (handled automatically)
- Do NOT include a "finish", "complete", or "verify" step (handled automatically)

Call the create_plan tool with your steps."""

        try:
            response = await self.llm.generate(
                system_prompt="You are a task planning assistant. Always use the create_plan tool.",
                messages=[{"role": "user", "content": plan_prompt}],
                tools=[plan_generator_tool],
            )

            # Extract steps from tool call arguments
            steps = []
            if response.tool_calls:
                for tc in response.tool_calls:
                    args = self._parse_arguments(tc)
                    if args.get("steps"):
                        steps = args["steps"]
                        break

            # Fallback: if LLM didn't provide steps, create single-step plan
            if not steps:
                steps = [user_request]

            # Create the plan
            self._task_plan.original_request = user_request
            self._task_plan.steps = [
                PlanStep(id=i + 1, description=str(step).strip())
                for i, step in enumerate(steps)
            ]

            # Add a system message showing the generated plan
            plan_display = ["Plan:"]
            for step in self._task_plan.steps:
                plan_display.append(f"  {step.id}. {step.description}")

            plan_msg = AgentMessage(
                role="assistant",
                content="\n".join(plan_display),
                metadata={"auto_plan": True},
                usage=response.usage,
            )
            self.conversation_history.append(plan_msg)
            return plan_msg

        except Exception as e:
            # Plan generation failed - create fallback single-step plan
            self._task_plan.original_request = user_request
            self._task_plan.steps = [PlanStep(id=1, description=user_request)]

            error_msg = AgentMessage(
                role="assistant",
                content=f"Plan generation failed: {str(e)}\nUsing fallback: treating request as single step.",
                metadata={"auto_plan_failed": True},
            )
            self.conversation_history.append(error_msg)
            return error_msg
            return error_msg

    async def _replan(self, failed_step: Any) -> Optional[AgentMessage]:
        """
        Handle plan failure by generating a new plan (Tactical Replanning).
        """
        from ..tools.finish import PlanStep
        from ..tools.registry import Tool, ToolSchema

        # 1. Archive current plan (log it)
        old_plan_str = "\n".join(
            [f"{s.id}. {s.description} ({s.status})" for s in self._task_plan.steps]
        )

        # 2. Generate new plan
        # Create a temporary tool for plan generation
        plan_generator_tool = Tool(
            name="create_plan",
            description="Create a NEW step-by-step plan. Call this with the steps needed.",
            schema=ToolSchema(
                properties={
                    "feasible": {
                        "type": "boolean",
                        "description": "Can the task be completed with a new plan? Set false if impossible/out-of-scope.",
                    },
                    "steps": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of actionable steps (required if feasible=true).",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason for the new plan OR reason why it's impossible.",
                    },
                },
                required=["feasible", "reason"],
            ),
            execute_fn=lambda args, runtime: None,
            category="planning",
        )

        replan_prompt = f"""The previous plan failed at step {failed_step.id}.

Failed Step: {failed_step.description}
Reason: {failed_step.result}

Previous Plan:
{old_plan_str}

Original Request: {self._task_plan.original_request}

Task: Generate a NEW plan (v2) that addresses this failure.
- If the failure invalidates the entire approach, try a different tactical approach.
- If the task is IMPOSSIBLE or OUT OF SCOPE (e.g., requires installing software on a remote target, physical access, or permissions you don't have), set feasible=False.
- Do NOT propose steps that violate standard pentest constraints (no installing agents/services on targets unless exploited).

Call create_plan with the new steps OR feasible=False."""

        try:
            response = await self.llm.generate(
                system_prompt="You are a tactical planning assistant. The previous plan failed. Create a new one or declare it impossible.",
                messages=[{"role": "user", "content": replan_prompt}],
                tools=[plan_generator_tool],
            )

            # Extract steps
            steps = []
            feasible = True
            reason = ""

            if response.tool_calls:
                for tc in response.tool_calls:
                    args = self._parse_arguments(tc)
                    feasible = args.get("feasible", True)
                    reason = args.get("reason", "")
                    if feasible and args.get("steps"):
                        steps = args["steps"]
                    break

            if not feasible:
                return AgentMessage(
                    role="assistant",
                    content=f"Task determined to be infeasible after failure.\nReason: {reason}",
                    metadata={"replan_impossible": True},
                )

            if not steps:
                return None

            # Update plan
            self._task_plan.steps = [
                PlanStep(id=i + 1, description=str(step).strip())
                for i, step in enumerate(steps)
            ]

            # Return message
            plan_display = [f"Plan v2 (Replanned) - {reason}:"]
            for step in self._task_plan.steps:
                plan_display.append(f"  {step.id}. {step.description}")

            return AgentMessage(
                role="assistant",
                content="\n".join(plan_display),
                metadata={"replanned": True},
            )

        except Exception as e:
            return AgentMessage(
                role="assistant",
                content=f"Replanning failed: {str(e)}",
                metadata={"replan_failed": True},
            )

    def reset(self):
        """Reset the agent state for a new conversation."""
        self.state_manager.reset()
        self.conversation_history.clear()
        self._empty_response_count = 0

    async def assist(self, message: str) -> AsyncIterator[AgentMessage]:
        """
        Assist mode - single LLM call, single tool execution if needed.

        Simple flow: LLM responds, optionally calls one tool, returns result.
        No looping, no retries. User can follow up if needed.

        Note: 'finish' tool is excluded - assist mode doesn't need explicit
        termination since it's single-shot by design.

        Args:
            message: The user message to respond to

        Yields:
            AgentMessage objects
        """
        self.state_manager.transition_to(AgentState.THINKING)
        self.conversation_history.append(AgentMessage(role="user", content=message))

        # Filter out 'finish' tool - not needed for single-shot assist mode
        assist_tools = [t for t in self.tools if t.name != "finish"]

        # Single LLM call with tools available
        response = await self.llm.generate(
            system_prompt=self.get_system_prompt(mode="assist"),
            messages=self._format_messages_for_llm(),
            tools=assist_tools,
        )

        # If LLM wants to use tools, execute and return result
        if response.tool_calls:
            # Build tool calls list
            tool_calls = [
                ToolCall(
                    id=tc.id if hasattr(tc, "id") else str(i),
                    name=(
                        tc.function.name
                        if hasattr(tc, "function")
                        else tc.get("name", "")
                    ),
                    arguments=self._parse_arguments(tc),
                )
                for i, tc in enumerate(response.tool_calls)
            ]

            # Yield tool calls IMMEDIATELY (before execution) for UI display
            # Include any thinking/planning content from the LLM
            if response.content:
                thinking_msg = AgentMessage(
                    role="assistant",
                    content=response.content,
                    metadata={"intermediate": True},
                )
                yield thinking_msg

            # NOW execute the tools (this can take a while)
            self.state_manager.transition_to(AgentState.EXECUTING)
            tool_results = await self._execute_tools(response.tool_calls)

            # Store in history (minimal content to save tokens)
            assistant_msg = AgentMessage(
                role="assistant", content=response.content or "", tool_calls=tool_calls
            )
            self.conversation_history.append(assistant_msg)

            tool_result_msg = AgentMessage(
                role="tool_result", content="", tool_results=tool_results
            )
            self.conversation_history.append(tool_result_msg)

            # Yield tool results for display
            results_msg = AgentMessage(
                role="assistant",
                content="",
                tool_calls=tool_calls,
                tool_results=tool_results,
            )
            yield results_msg

            # Format tool results as final response
            result_text = self._format_tool_results(tool_results)
            final_msg = AgentMessage(role="assistant", content=result_text)
            self.conversation_history.append(final_msg)
            yield final_msg
        else:
            # Direct response, no tools needed
            assistant_msg = AgentMessage(
                role="assistant", content=response.content or ""
            )
            self.conversation_history.append(assistant_msg)
            yield assistant_msg

        self.state_manager.transition_to(AgentState.COMPLETE)

    def _format_tool_results(self, results: List[ToolResult]) -> str:
        """Format tool results as a simple response."""
        parts = []
        for r in results:
            if r.success:
                parts.append(r.result or "Done.")
            else:
                parts.append(f"Error: {r.error}")
        return "\n".join(parts)
