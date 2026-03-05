"""MCP transport implementations for PentestAgent."""

import asyncio
import json
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class MCPTransport(ABC):
    """Abstract base class for MCP transports."""

    @abstractmethod
    async def connect(self):
        """Establish the connection."""
        pass

    @abstractmethod
    async def send(self, message: dict, timeout: float = 15.0) -> dict:
        """Send a message and receive a response."""
        pass

    @abstractmethod
    async def disconnect(self):
        """Close the connection."""
        pass

    @property
    @abstractmethod
    def is_connected(self) -> bool:
        """Check if the transport is connected."""
        pass


class StdioTransport(MCPTransport):
    """MCP transport over stdio (for npx/uvx commands)."""

    def __init__(self, command: str, args: list[str], env: Dict[str, str]):
        """
        Initialize stdio transport.

        Args:
            command: The command to run (e.g., 'npx', 'uvx')
            args: Command arguments
            env: Additional environment variables
        """
        self.command = command
        self.args = args
        self.env = env
        self.process: Optional[asyncio.subprocess.Process] = None
        self._lock = asyncio.Lock()

    @property
    def is_connected(self) -> bool:
        """Check if the process is running."""
        return self.process is not None and self.process.returncode is None

    async def connect(self):
        """Start the MCP server process."""
        import shutil

        # Merge environment variables
        full_env = {**os.environ, **self.env}

        # On Windows, resolve commands like npx, uvx that may be .cmd/.ps1 wrappers
        if os.name == "nt":
            # Check for .cmd version first (more compatible)
            cmd_path = shutil.which(f"{self.command}.cmd")
            if cmd_path:
                resolved_command = cmd_path
            else:
                # Fall back to regular which
                resolved_command = shutil.which(self.command) or self.command
        else:
            resolved_command = self.command

        self.process = await asyncio.create_subprocess_exec(
            resolved_command,
            *self.args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=full_env,
            limit=1024 * 1024,  # 1MB buffer limit for large MCP responses
        )

    async def send(self, message: dict, timeout: float = 15.0) -> dict:
        """
        Send a JSON-RPC message and wait for response.

        Args:
            message: The JSON-RPC message to send
            timeout: Timeout in seconds for response (default 15s)

        Returns:
            The JSON-RPC response
        """
        if not self.process or not self.process.stdin or not self.process.stdout:
            raise RuntimeError("Transport not connected")

        async with self._lock:
            # Send JSON-RPC message with newline
            msg_bytes = (json.dumps(message) + "\n").encode()
            self.process.stdin.write(msg_bytes)
            await self.process.stdin.drain()

            # Notifications don't have responses
            if "id" not in message:
                return {}

            # Read response line
            try:
                response_line = await asyncio.wait_for(
                    self.process.stdout.readline(), timeout=timeout
                )

                if not response_line:
                    raise RuntimeError("Server closed connection")

                return json.loads(response_line.decode())

            except asyncio.TimeoutError as e:
                raise RuntimeError("Timeout waiting for MCP response") from e
            except json.JSONDecodeError as e:
                raise RuntimeError(f"Invalid JSON response: {e}") from e

    async def disconnect(self):
        """Terminate the MCP server process cleanly."""
        if not self.process:
            return

        proc = self.process
        self.process = None

        # Close all pipes first to prevent "unclosed transport" warnings
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if pipe:
                try:
                    pipe.close()
                except Exception:
                    pass

        # Wait for pipe transports to close
        if proc.stdin:
            try:
                await proc.stdin.wait_closed()
            except Exception:
                pass

        # Terminate the process
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            proc.kill()
            try:
                await proc.wait()
            except Exception:
                pass
        except Exception:
            pass


class SSETransport(MCPTransport):
    """MCP transport over Server-Sent Events (HTTP)."""

    def __init__(self, url: str):
        """
        Initialize SSE transport.

        Args:
            url: The HTTP endpoint URL
        """
        self.url = url
        self.session: Optional[Any] = None  # aiohttp.ClientSession
        self._connected = False
        self._post_url: Optional[str] = None
        self._sse_response: Optional[Any] = None
        self._sse_task: Optional[asyncio.Task] = None
        self._pending: dict[str, asyncio.Future] = {}
        self._pending_lock = asyncio.Lock()
        self._endpoint_ready: Optional[asyncio.Event] = None

    @property
    def is_connected(self) -> bool:
        """Check if the session is active."""
        return self._connected and self.session is not None

    async def connect(self):
        """Connect to the SSE endpoint."""
        try:
            import aiohttp

            self.session = aiohttp.ClientSession()

            # Open a persistent SSE connection so we can receive async
            # responses delivered over the event stream. Keep the response
            # object alive and run a background task to parse events.
            try:
                # Do not use a short timeout; keep the connection open.
                resp = await self.session.get(self.url, timeout=None)
                # Store response and start background reader
                self._sse_response = resp
                # event used to signal when endpoint announced
                self._endpoint_ready = asyncio.Event()
                self._sse_task = asyncio.create_task(self._sse_listener(resp))
                # Wait a short time for the endpoint to be discovered to avoid races
                try:
                    await asyncio.wait_for(self._endpoint_ready.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    # If endpoint not discovered, continue; send() will try discovery
                    pass
            except Exception:
                # If opening the SSE stream fails, still mark connected so
                # send() can attempt POST discovery and report meaningful errors.
                self._sse_response = None
                self._sse_task = None
                self._endpoint_ready = None

            self._connected = True
        except ImportError as e:
            raise RuntimeError(
                "aiohttp is required for SSE transport. Install with: pip install aiohttp"
            ) from e

    async def send(self, message: dict, timeout: float = 15.0) -> dict:
        """
        Send a message via HTTP POST.

        Args:
            message: The JSON-RPC message to send
            timeout: Timeout in seconds for response (default 15s)

        Returns:
            The JSON-RPC response
        """
        if not self.session:
            raise RuntimeError("Transport not connected")

        if not self.session:
            raise RuntimeError("Transport not connected")

        # Ensure we have a POST endpoint. If discovery hasn't completed yet,
        # try a quick synchronous discovery attempt before posting so we don't
        # accidentally POST to the SSE listen endpoint which returns 405.
        if not self._post_url:
            try:
                await self._discover_post_url(timeout=2.0)
            except Exception:
                pass

        post_target = self._post_url or self.url

        try:
            async with self.session.post(
                post_target, json=message, headers={"Content-Type": "application/json"}
            ) as response:
                status = response.status
                if status == 200:
                    return await response.json()
                if status == 202:
                    # Asynchronous response: wait for matching SSE event with the same id
                    if "id" not in message:
                        return {}
                    msg_id = str(message["id"])
                    fut = asyncio.get_running_loop().create_future()
                    async with self._pending_lock:
                        self._pending[msg_id] = fut
                    try:
                        result = await asyncio.wait_for(fut, timeout=timeout)
                        return result
                    finally:
                        async with self._pending_lock:
                            self._pending.pop(msg_id, None)
                # Other statuses are errors
                raise RuntimeError(f"HTTP error: {status}")

        except Exception as e:
            raise RuntimeError(f"SSE request failed: {e}") from e

    async def _discover_post_url(self, timeout: float = 2.0) -> None:
        """Attempt a short GET to the SSE endpoint to find the advertised POST URL.

        This is a fallback used when the background listener hasn't yet
        extracted the `endpoint` event. It reads a few lines with a short
        timeout and sets `self._post_url` if found.
        """
        if not self.session:
            return

        try:
            async with self.session.get(self.url, timeout=timeout) as resp:
                if resp.status != 200:
                    return
                # Read up to a few lines looking for `data:`
                for _ in range(20):
                    line = await resp.content.readline()
                    if not line:
                        break
                    try:
                        text = line.decode(errors="ignore").strip()
                    except Exception:
                        continue
                    if text.startswith("data:"):
                        endpoint = text.split("data:", 1)[1].strip()
                        from urllib.parse import urlparse

                        p = urlparse(self.url)
                        if endpoint.startswith("http"):
                            self._post_url = endpoint
                        elif endpoint.startswith("/"):
                            self._post_url = f"{p.scheme}://{p.netloc}{endpoint}"
                        else:
                            self._post_url = f"{p.scheme}://{p.netloc}/{endpoint.lstrip('/')}"
                        return
        except Exception:
            return

    async def disconnect(self):
        """Close the HTTP session."""
        # Cancel listener and close SSE response
        try:
            if self._sse_task:
                self._sse_task.cancel()
                try:
                    await self._sse_task
                except Exception:
                    pass
                self._sse_task = None
        except Exception:
            pass

        try:
            if self._sse_response:
                try:
                    await self._sse_response.release()
                except Exception:
                    pass
                self._sse_response = None
        except Exception:
            pass

        # Fail any pending requests
        async with self._pending_lock:
            for fut in list(self._pending.values()):
                if not fut.done():
                    fut.set_exception(RuntimeError("Transport disconnected"))
            self._pending.clear()

        if self.session:
            await self.session.close()
            self.session = None
        self._connected = False

    async def _sse_listener(self, resp: Any):
        """Background task that reads SSE events and resolves pending futures.

        The listener expects SSE-formatted events where `data:` lines may
        contain JSON payloads. If a JSON object contains an `id` field that
        matches a pending request, the corresponding future is completed with
        that JSON value.
        """
        try:
            # Read the stream line-by-line, accumulating event blocks
            event_lines: list[str] = []
            async for raw in resp.content:
                try:
                    line = raw.decode(errors="ignore").rstrip("\r\n")
                except Exception:
                    continue
                if line == "":
                    # End of event; process accumulated lines
                    event_name = None
                    data_lines: list[str] = []
                    for l in event_lines:
                        if l.startswith("event:"):
                            event_name = l.split(":", 1)[1].strip()
                        elif l.startswith("data:"):
                            data_lines.append(l.split(":", 1)[1].lstrip())

                    if data_lines:
                        data_text = "\n".join(data_lines)
                        # If this is an endpoint announcement, record POST URL
                        if event_name == "endpoint":
                            try:
                                from urllib.parse import urlparse

                                p = urlparse(self.url)
                                endpoint = data_text.strip()
                                if endpoint.startswith("http"):
                                    self._post_url = endpoint
                                elif endpoint.startswith("/"):
                                    self._post_url = f"{p.scheme}://{p.netloc}{endpoint}"
                                else:
                                    self._post_url = f"{p.scheme}://{p.netloc}/{endpoint.lstrip('/')}"
                            except Exception:
                                pass
                            # Notify connect() that endpoint is ready
                            try:
                                if self._endpoint_ready and not self._endpoint_ready.is_set():
                                    self._endpoint_ready.set()
                            except Exception:
                                pass
                        else:
                            # Try to parse as JSON and resolve pending futures
                            try:
                                obj = json.loads(data_text)
                                if isinstance(obj, dict) and "id" in obj:
                                    msg_id = str(obj.get("id"))
                                    async with self._pending_lock:
                                        fut = self._pending.get(msg_id)
                                    if fut and not fut.done():
                                        fut.set_result(obj)
                            except Exception:
                                pass

                    event_lines = []
                else:
                    event_lines.append(line)
        except asyncio.CancelledError:
            return
        except Exception:
            # On error, fail pending futures
            async with self._pending_lock:
                for fut in list(self._pending.values()):
                    if not fut.done():
                        fut.set_exception(RuntimeError("SSE listener error"))
                self._pending.clear()
        finally:
            # Ensure we mark disconnected state
            self._connected = False


class WebSocketTransport(MCPTransport):
    """MCP transport over WebSocket."""

    def __init__(self, url: str):
        """
        Initialize WebSocket transport.

        Args:
            url: The WebSocket endpoint URL
        """
        self.url = url
        self.ws: Optional[Any] = None
        self._connected = False

    @property
    def is_connected(self) -> bool:
        """Check if the WebSocket is connected."""
        return self._connected and self.ws is not None

    async def connect(self):
        """Connect to the WebSocket endpoint."""
        try:
            import aiohttp

            self._session = aiohttp.ClientSession()
            self.ws = await self._session.ws_connect(self.url)
            self._connected = True
        except ImportError as e:
            raise RuntimeError("aiohttp is required for WebSocket transport") from e

    async def send(self, message: dict) -> dict:
        """
        Send a message via WebSocket.

        Args:
            message: The JSON-RPC message to send

        Returns:
            The JSON-RPC response
        """
        if not self.ws:
            raise RuntimeError("Transport not connected")

        await self.ws.send_json(message)

        # Notifications don't have responses
        if "id" not in message:
            return {}

        response = await self.ws.receive_json()
        return response

    async def disconnect(self):
        """Close the WebSocket connection."""
        if self.ws:
            await self.ws.close()
            self.ws = None
        if hasattr(self, "_session") and self._session:
            await self._session.close()
            self._session = None
        self._connected = False
