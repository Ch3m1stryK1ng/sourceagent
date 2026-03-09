"""MCP server connection manager for PentestAgent.

Uses standard MCP configuration format:
{
    "mcpServers": {
        "server-name": {
            "command": "npx",
            "args": ["-y", "package-name"],
            "env": {"VAR": "value"}
        }
    }
}
"""

import asyncio
import json
import os
import atexit
import signal
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .tools import create_mcp_tool
from .transport import MCPTransport, StdioTransport


@dataclass
class MCPServerConfig:
    """Configuration for an MCP server."""

    name: str
    command: str
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    description: str = ""
    # Connection and handshake timeout (seconds)
    timeout: int = 15
    # Whether to auto-start this server when `connect_all()` is called.
    start_on_launch: bool = False


@dataclass
class MCPServer:
    """Represents a connected MCP server."""

    name: str
    config: MCPServerConfig
    transport: MCPTransport
    tools: List[dict] = field(default_factory=list)
    connected: bool = False
    # Lock for serializing all communication with this server
    # Prevents message ID collisions and transport interleaving
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def disconnect(self):
        """Disconnect from the server."""
        if self.connected:
            await self.transport.disconnect()
            self.connected = False


class MCPManager:
    """Manages MCP server connections and exposes tools to agents."""

    DEFAULT_CONFIG_PATHS = [
        Path.cwd() / "mcp_servers.json",
        Path.cwd() / "mcp.json",
        Path(__file__).parent / "mcp_servers.json",
        Path.home() / ".sourceagent" / "mcp_servers.json",
    ]

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or self._find_config()
        self.servers: Dict[str, MCPServer] = {}
        # Track adapters we auto-started so we can stop them later
        self._started_adapters: Dict[str, object] = {}
        self._message_id = 0
        # Ensure we attempt to clean up vendored servers on process exit
        try:
            atexit.register(self._atexit_cleanup)
        except Exception:
            pass

    def _find_config(self) -> Path:
        for path in self.DEFAULT_CONFIG_PATHS:
            if path.exists():
                return path
        return self.DEFAULT_CONFIG_PATHS[0]

    @staticmethod
    def _is_ghidra_server(name: str, config: MCPServerConfig) -> bool:
        lowered = (name or "").lower()
        return (
            "ghidra" in lowered
            or (config.command and "pyghidra-mcp" in str(config.command))
            or any("pyghidra-mcp" in str(a) for a in (config.args or []))
        )

    def _cleanup_ghidra_project_locks(self, config: MCPServerConfig) -> int:
        """Best-effort cleanup for stale pyghidra-mcp project lock files."""
        try:
            project_path = None
            args = config.args or []
            for i, a in enumerate(args):
                if a == "--project-path" and i + 1 < len(args):
                    project_path = args[i + 1]
                    break
            if not project_path:
                project_path = "pyghidra_mcp_projects/pyghidra_mcp"

            proj = Path(project_path)
            if not proj.is_absolute():
                proj = Path.cwd() / proj

            removed = 0
            for suffix in (".lock", ".lock~"):
                lock_file = proj / f"{proj.name}{suffix}"
                if lock_file.exists():
                    lock_file.unlink(missing_ok=True)
                    removed += 1
            return removed
        except Exception:
            return 0

    def _get_next_id(self) -> int:
        self._message_id += 1
        return self._message_id

    def _load_config(self) -> Dict[str, MCPServerConfig]:
        if not self.config_path.exists():
            return {}
        try:
            raw = json.loads(self.config_path.read_text(encoding="utf-8"))
            servers = {}
            mcp_servers = raw.get("mcpServers", {})
            for name, config in mcp_servers.items():
                if not config.get("command"):
                    continue
                servers[name] = MCPServerConfig(
                    name=name,
                    command=config["command"],
                    args=config.get("args", []),
                    env=config.get("env", {}),
                    enabled=config.get("enabled", True),
                    timeout=config.get("timeout", 15),
                    start_on_launch=config.get("start_on_launch", False),
                    description=config.get("description", ""),
                )
            # Allow override via environment variables for vendored MCP servers.
            # Per-adapter overrides supported:
            # - Hexstrike: LAUNCH_HEXTRIKE or LAUNCH_HEXSTRIKE
            # - Metasploit: LAUNCH_METASPLOIT_MCP
            # If set to a truthy value (1,true,y), force-enable auto-start for matching vendored server.
            # If set to a falsy value (0,false,n), force-disable auto-start for matching vendored server.
            def _apply_launch_override(env_names, match_fn):
                launch_env = None
                for e in env_names:
                    launch_env = os.environ.get(e)
                    if launch_env is not None:
                        break
                if launch_env is None:
                    return
                v = str(launch_env).strip().lower()
                enable = v in ("1", "true", "yes", "y")
                disable = v in ("0", "false", "no", "n")

                for name, cfg in servers.items():
                    try:
                        if not match_fn(name, cfg):
                            continue
                        if enable:
                            cfg.start_on_launch = True
                        elif disable:
                            cfg.start_on_launch = False
                    except Exception:
                        continue

            # Hexstrike override
            _apply_launch_override(["LAUNCH_HEXTRIKE", "LAUNCH_HEXSTRIKE"],
                                   lambda name, cfg: (
                                       (name or "").lower().find("hexstrike") != -1
                                       or (cfg.command and "third_party/hexstrike" in str(cfg.command))
                                       or any("third_party/hexstrike" in str(a) for a in (cfg.args or []))
                                   ))

            # Metasploit override
            _apply_launch_override(["LAUNCH_METASPLOIT_MCP"],
                                   lambda name, cfg: (
                                       (name or "").lower().find("metasploit") != -1
                                       or (cfg.command and "third_party/MetasploitMCP" in str(cfg.command))
                                       or any("third_party/MetasploitMCP" in str(a) for a in (cfg.args or []))
                                   ))

            # Ghidra override
            _apply_launch_override(["LAUNCH_GHIDRA"],
                                   lambda name, cfg: (
                                       (name or "").lower().find("ghidra") != -1
                                       or (cfg.command and "pyghidra-mcp" in str(cfg.command))
                                       or any("pyghidra-mcp" in str(a) for a in (cfg.args or []))
                                   ))

            return servers
        except json.JSONDecodeError as e:
            print(f"[MCP] Error loading config: {e}")
            return {}

    def _save_config(self, servers: Dict[str, MCPServerConfig]):
        config = {"mcpServers": {}}
        for name, server in servers.items():
            server_config = {"command": server.command, "args": server.args}
            if server.env:
                server_config["env"] = server.env
            if server.description:
                server_config["description"] = server.description
            if server.timeout != 15:
                server_config["timeout"] = server.timeout
            if not server.enabled:
                server_config["enabled"] = False
            config["mcpServers"][name] = server_config
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    def _atexit_cleanup(self):
        """Synchronous atexit cleanup that attempts to stop adapters and disconnect servers."""
        try:
            # Try to run async shutdown; if an event loop is already running this may fail,
            # but it's best-effort to avoid orphaned vendored servers.
            asyncio.run(self._stop_started_adapters_and_disconnect())
        except Exception:
            # Last-ditch: attempt to stop adapters synchronously.
            # If the adapter exposes a blocking `stop()` call, call it. Otherwise, try
            # to kill the underlying process by PID to avoid asyncio subprocess
            # destructors running after the loop is closed.
            for adapter in list(self._started_adapters.values()):
                try:
                    # Prefer adapter-provided synchronous stop hook
                    stop_sync = getattr(adapter, "stop_sync", None)
                    if stop_sync:
                        try:
                            stop_sync()
                            continue
                        except Exception:
                            pass

                    # Fallback: try blocking stop() if present
                    stop = getattr(adapter, "stop", None)
                    if stop and not asyncio.iscoroutinefunction(stop):
                        try:
                            stop()
                            continue
                        except Exception:
                            pass

                    # Final fallback: kill underlying PID if available
                    pid = None
                    proc = getattr(adapter, "_process", None)
                    if proc is not None:
                        pid = getattr(proc, "pid", None)
                    if pid:
                        try:
                            os.kill(pid, signal.SIGTERM)
                        except Exception:
                            try:
                                os.kill(pid, signal.SIGKILL)
                            except Exception:
                                pass
                except Exception:
                    pass

    async def _stop_started_adapters_and_disconnect(self) -> None:
        # Stop any adapters we started
        for name, adapter in list(self._started_adapters.items()):
            try:
                stop = getattr(adapter, "stop", None)
                if stop:
                    if asyncio.iscoroutinefunction(stop):
                        await stop()
                    else:
                        # run blocking stop in executor
                        loop = asyncio.get_running_loop()
                        await loop.run_in_executor(None, stop)
            except Exception:
                pass
        self._started_adapters.clear()

        # Disconnect any active MCP server connections
        try:
            await self.disconnect_all()
        except Exception:
            pass

    def add_server(
        self,
        name: str,
        command: str,
        args: List[str] = None,
        env: Dict[str, str] = None,
        description: str = "",
    ):
        servers = self._load_config()
        servers[name] = MCPServerConfig(
            name=name,
            command=command,
            args=args or [],
            env=env or {},
            description=description,
        )
        self._save_config(servers)
        print(f"[MCP] Added server: {name}")

    def remove_server(self, name: str) -> bool:
        servers = self._load_config()
        if name in servers:
            del servers[name]
            self._save_config(servers)
            return True
        return False

    def set_enabled(self, name: str, enabled: bool) -> bool:
        """Enable or disable a configured MCP server in the config file.

        Returns True if the server existed and was updated, False otherwise.
        """
        servers = self._load_config()
        if name not in servers:
            return False
        servers[name].enabled = bool(enabled)
        self._save_config(servers)
        return True

    def list_configured_servers(self) -> List[dict]:
        servers = self._load_config()
        return [
            {
                "name": n,
                "command": s.command,
                "args": s.args,
                "env": s.env,
                "enabled": s.enabled,
                "description": s.description,
                "connected": n in self.servers and self.servers[n].connected,
            }
            for n, s in servers.items()
        ]

    async def connect_all(self) -> List[Any]:
        servers_config = self._load_config()
        # Respect explicit LAUNCH_* env overrides for vendored MCP servers.
        # If set to a falsy value (0/false/no/n) we will skip connecting to matching vendored servers.
        launch_hex_env = os.environ.get("LAUNCH_HEXTRIKE") or os.environ.get("LAUNCH_HEXSTRIKE")
        launch_hex_disabled = False
        if launch_hex_env is not None:
            v = str(launch_hex_env).strip().lower()
            if v in ("0", "false", "no", "n"):
                launch_hex_disabled = True

        launch_msf_env = os.environ.get("LAUNCH_METASPLOIT_MCP")
        launch_msf_disabled = False
        if launch_msf_env is not None:
            v = str(launch_msf_env).strip().lower()
            if v in ("0", "false", "no", "n"):
                launch_msf_disabled = True

        launch_ghidra_env = os.environ.get("LAUNCH_GHIDRA")
        launch_ghidra_disabled = False
        if launch_ghidra_env is not None:
            v = str(launch_ghidra_env).strip().lower()
            if v in ("0", "false", "no", "n"):
                launch_ghidra_disabled = True

        all_tools = []
        for name, config in servers_config.items():
            if not config.enabled:
                continue
            # If the user explicitly disabled launching HexStrike, skip hexstrike entries entirely
            lowered = name.lower() if name else ""
            is_hex = (
                "hexstrike" in lowered
                or (config.command and "third_party/hexstrike" in str(config.command))
                or any("third_party/hexstrike" in str(a) for a in (config.args or []))
            )
            if launch_hex_disabled and is_hex:
                print(f"[MCP] Skipping auto-connection for {name} due to LAUNCH_HEXTRIKE={launch_hex_env}")
                continue
            # Skip metasploit if disabled
            is_msf = (
                "metasploit" in lowered
                or (config.command and "MetasploitMCP" in str(config.command))
                or any("MetasploitMCP" in str(a) for a in (config.args or []))
            )
            if launch_msf_disabled and is_msf:
                print(f"[MCP] Skipping auto-connection for {name} due to LAUNCH_METASPLOIT_MCP={launch_msf_env}")
                continue
            # Skip ghidra if disabled
            is_ghidra = (
                "ghidra" in lowered
                or (config.command and "pyghidra-mcp" in str(config.command))
            )
            if launch_ghidra_disabled and is_ghidra:
                print(f"[MCP] Skipping auto-connection for {name} due to LAUNCH_GHIDRA={launch_ghidra_env}")
                continue
            # Optionally auto-start vendored servers (e.g., HexStrike subtree or MetasploitMCP)
            if getattr(config, "start_on_launch", False):
                try:
                    args_joined = " ".join(config.args or [])
                    cmd_str = config.command or ""

                    # Hexstrike auto-start
                    if "third_party/hexstrike" in args_joined or (cmd_str and "third_party/hexstrike" in cmd_str):
                        if not launch_hex_disabled:
                            try:
                                from .hexstrike_adapter import HexstrikeAdapter

                                adapter = HexstrikeAdapter()
                                started = await adapter.start()
                                if started:
                                    try:
                                        self._started_adapters[name] = adapter
                                    except Exception:
                                        pass
                                    print(f"[MCP] Auto-started vendored server for {name}")
                            except Exception as e:
                                print(f"[MCP] Failed to auto-start vendored server {name}: {e}")
                        else:
                            print(f"[MCP] Skipping auto-start for {name} due to LAUNCH_HEXTRIKE override")

                    # Metasploit auto-start
                    if "third_party/MetasploitMCP" in args_joined or (cmd_str and "third_party/MetasploitMCP" in cmd_str) or (name and "metasploit" in name.lower()):
                        if not launch_msf_disabled:
                            try:
                                from .metasploit_adapter import MetasploitAdapter

                                adapter = MetasploitAdapter()
                                started = await adapter.start()
                                if started:
                                    try:
                                        self._started_adapters[name] = adapter
                                    except Exception:
                                        pass
                                    print(f"[MCP] Auto-started vendored server for {name}")
                            except Exception as e:
                                print(f"[MCP] Failed to auto-start vendored server {name}: {e}")
                        else:
                            print(f"[MCP] Skipping auto-start for {name} due to LAUNCH_METASPLOIT_MCP override")

                    # Ghidra: stdio transport is handled by StdioTransport directly, no adapter needed
                except Exception:
                    pass
            server = await self._connect_server(config)
            if not server and self._is_ghidra_server(name, config):
                removed = self._cleanup_ghidra_project_locks(config)
                if removed:
                    print(f"[MCP] Removed {removed} stale Ghidra lock file(s), retrying {name}...")
                    server = await self._connect_server(config)
            if server:
                self.servers[name] = server
                for tool_def in server.tools:
                    tool = create_mcp_tool(tool_def, server, self)
                    all_tools.append(tool)
                print(f"[MCP] Connected to {name} with {len(server.tools)} tools")
        return all_tools

    async def connect_server(self, name: str) -> Optional[MCPServer]:
        servers_config = self._load_config()
        if name not in servers_config:
            return None
        config = servers_config[name]
        # If this appears to be a vendored Metasploit MCP entry, attempt to auto-start
        # the vendored adapter so `sourceagent mcp test metasploit-local` works
        try:
            args_joined = " ".join(config.args or [])
            cmd_str = config.command or ""
            is_msf = (
                (name and "metasploit" in name.lower())
                or ("third_party/MetasploitMCP" in cmd_str)
                or ("third_party/MetasploitMCP" in args_joined)
            )
            if is_msf:
                launch_msf_env = os.environ.get("LAUNCH_METASPLOIT_MCP")
                launch_disabled = False
                if launch_msf_env is not None:
                    v = str(launch_msf_env).strip().lower()
                    if v in ("0", "false", "no", "n"):
                        launch_disabled = True
                if not launch_disabled:
                    try:
                        from .metasploit_adapter import MetasploitAdapter

                        adapter = MetasploitAdapter()
                        started = await adapter.start()
                        if started:
                            try:
                                self._started_adapters[name] = adapter
                            except Exception:
                                pass
                            print(f"[MCP] Auto-started vendored server for {name}")
                    except Exception:
                        pass
        except Exception:
            pass

        server = await self._connect_server(config)
        if not server and self._is_ghidra_server(name, config):
            removed = self._cleanup_ghidra_project_locks(config)
            if removed:
                print(f"[MCP] Removed {removed} stale Ghidra lock file(s), retrying {name}...")
                server = await self._connect_server(config)
        if server:
            self.servers[name] = server
        return server

    async def _connect_server(self, config: MCPServerConfig) -> Optional[MCPServer]:
        transport = None
        try:
            env = {**os.environ, **config.env}
            effective_args = list(config.args or [])
            # Optional runtime override for pyghidra-mcp project path to avoid
            # expensive startup on very large stale projects.
            ghidra_proj = os.environ.get("SOURCEAGENT_GHIDRA_PROJECT_PATH")
            if (
                ghidra_proj
                and self._is_ghidra_server(config.name, config)
                and "--project-path" not in effective_args
            ):
                effective_args.extend(["--project-path", ghidra_proj])
                print(f"[MCP] Ghidra project override: {ghidra_proj}")
            # Use per-server timeout (default 15s) for initialize/tools handshake.
            # Ghidra-backed servers can need longer cold-start time.
            connect_timeout = float(getattr(config, "timeout", 15) or 15)
            # Optional runtime cap so caller and transport timeouts stay aligned.
            # Prevents outer wait_for cancellation from leaving child processes alive.
            timeout_cap_raw = os.environ.get("SOURCEAGENT_MCP_CONNECT_TIMEOUT_SEC")
            if timeout_cap_raw:
                try:
                    timeout_cap = float(timeout_cap_raw)
                    if timeout_cap > 0:
                        connect_timeout = max(1.0, min(connect_timeout, timeout_cap))
                except Exception:
                    pass

            # Decide transport type:
            # - If args contain a http/sse transport or a --server http:// URL, use SSETransport
            # - Otherwise default to StdioTransport (spawn process and use stdio JSON-RPC)
            use_http = False
            http_url = None
            args_joined = " ".join(config.args or [])
            if "--transport http" in args_joined or "--transport sse" in args_joined:
                # Try to extract host/port from args
                try:
                    # naive parsing: look for --host <host> and --port <port>
                    host = None
                    port = None
                    for i, a in enumerate(config.args or []):
                        if a == "--host" and i + 1 < len(config.args):
                            host = config.args[i + 1]
                        if a == "--port" and i + 1 < len(config.args):
                            port = config.args[i + 1]
                    if host and port:
                        http_url = f"http://{host}:{port}/sse"
                except Exception:
                    http_url = None
                use_http = True
            # If args specify a --server URL, prefer that
            if not http_url:
                from urllib.parse import urlparse

                for i, a in enumerate(config.args or []):
                    if a == "--server" and i + 1 < len(config.args):
                        candidate = config.args[i + 1]
                        if isinstance(candidate, str) and candidate.startswith("http"):
                            # If the provided server URL doesn't include a path, default to the MCP SSE path
                            p = urlparse(candidate)
                            if p.path and p.path != "/":
                                http_url = candidate
                            else:
                                http_url = candidate.rstrip("/") + "/sse"
                            use_http = True
                            break

            if use_http and http_url:
                from .transport import SSETransport

                transport = SSETransport(url=http_url)
                await transport.connect()
            else:
                transport = StdioTransport(
                    command=config.command, args=effective_args, env=env
                )
                await transport.connect()

            await transport.send(
                {
                    "jsonrpc": "2.0",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "sourceagent", "version": "0.2.0"},
                    },
                    "id": self._get_next_id(),
                },
                timeout=connect_timeout,
            )
            await transport.send(
                {"jsonrpc": "2.0", "method": "notifications/initialized"}
            )

            tools_response = await transport.send(
                {"jsonrpc": "2.0", "method": "tools/list", "id": self._get_next_id()},
                timeout=connect_timeout,
            )
            tools = tools_response.get("result", {}).get("tools", [])

            return MCPServer(
                name=config.name,
                config=config,
                transport=transport,
                tools=tools,
                connected=True,
            )
        except asyncio.CancelledError:
            # Ensure child stdio process is terminated when caller timeout cancels.
            if transport:
                try:
                    await transport.disconnect()
                except Exception:
                    pass
            raise
        except Exception as e:
            detail = ""
            try:
                if isinstance(transport, StdioTransport) and transport.process:
                    proc = transport.process
                    rc = proc.returncode
                    if rc is None:
                        await asyncio.sleep(0.05)
                        rc = proc.returncode
                    stderr_tail = ""
                    if proc.stderr:
                        try:
                            err_bytes = await asyncio.wait_for(
                                proc.stderr.read(4096), timeout=0.2
                            )
                            if err_bytes:
                                stderr_tail = err_bytes.decode(errors="ignore").strip()
                        except Exception:
                            pass
                    if rc is not None or stderr_tail:
                        if stderr_tail:
                            one_line = " ".join(stderr_tail.split())
                            if len(one_line) > 240:
                                one_line = "..." + one_line[-240:]
                            detail = f" (rc={rc}, stderr={one_line})"
                        else:
                            detail = f" (rc={rc})"
            except Exception:
                detail = ""
            # Clean up transport on failure
            if transport:
                try:
                    await transport.disconnect()
                except Exception:
                    pass
            print(f"[MCP] Failed to connect to {config.name}: {e}{detail}")
            return None

    async def call_tool(self, server_name: str, tool_name: str, arguments: dict) -> Any:
        server = self.servers.get(server_name)
        if not server or not server.connected:
            raise ValueError(f"Server '{server_name}' not connected")

        # Serialize all communication with this server to prevent:
        # - Message ID collisions
        # - Transport write interleaving
        # - Response routing issues
        async with server._lock:
            # Use 5 minute timeout for tool calls (scans can take a while)
            response = await server.transport.send(
                {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": arguments},
                    "id": self._get_next_id(),
                },
                timeout=300.0,
            )
        if "error" in response:
            raise RuntimeError(f"MCP error: {response['error'].get('message')}")
        return response.get("result", {}).get("content", [])

    async def disconnect_server(self, name: str):
        server = self.servers.get(name)
        if server:
            await server.disconnect()
            del self.servers[name]
        # If we started an adapter for this server, stop it as well
        adapter = self._started_adapters.pop(name, None)
        if adapter:
            try:
                stop = getattr(adapter, "stop", None)
                if stop:
                    if asyncio.iscoroutinefunction(stop):
                        await stop()
                    else:
                        loop = asyncio.get_running_loop()
                        await loop.run_in_executor(None, stop)
            except Exception:
                pass

    async def disconnect_all(self):
        for server in list(self.servers.values()):
            await server.disconnect()
        self.servers.clear()

    async def reconnect_all(self) -> List[Any]:
        """Disconnect all servers and reconnect them.

        Useful after cancellation leaves servers in a bad state.
        """
        # Disconnect all
        await self.disconnect_all()

        # Reconnect all configured servers
        return await self.connect_all()

    def get_server(self, name: str) -> Optional[MCPServer]:
        return self.servers.get(name)

    def get_all_servers(self) -> List[MCPServer]:
        return list(self.servers.values())

    def is_connected(self, name: str) -> bool:
        server = self.servers.get(name)
        return server is not None and server.connected
