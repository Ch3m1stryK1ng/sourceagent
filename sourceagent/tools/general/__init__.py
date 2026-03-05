"""
General-purpose tools for the GeneralAgent.

These are primitive tools that can be composed by the LLM to solve
various tasks (binary analysis, CTF, vuln detection, etc.).
"""

import asyncio
import base64
import binascii
import collections
import os
import re
import shlex
import socket
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from ..registry import Tool, ToolSchema, register_tool_instance

if TYPE_CHECKING:
    from ...runtime import Runtime


# =============================================================================
# File System Tools
# =============================================================================

async def _read_file(arguments: dict, runtime: "Runtime") -> str:
    """Read contents of a file."""
    path = arguments.get("path", "")
    max_bytes = arguments.get("max_bytes", 10000)

    if not path:
        return "Error: path is required"

    try:
        file_path = Path(path)
        if not file_path.exists():
            return f"Error: File not found: {path}"

        # Check if binary
        with open(file_path, 'rb') as f:
            sample = f.read(1024)
            is_binary = b'\x00' in sample

        if is_binary:
            with open(file_path, 'rb') as f:
                data = f.read(max_bytes)
            lines = []
            for i in range(0, min(len(data), 512), 16):
                chunk = data[i:i+16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                lines.append(f"{i:08x}  {hex_part:<48}  {ascii_part}")
            return f"Binary file ({len(data)} bytes):\n" + '\n'.join(lines)
        else:
            content = file_path.read_text(errors='replace')[:max_bytes]
            return content
    except Exception as e:
        return f"Error: {e}"


async def _list_dir(arguments: dict, runtime: "Runtime") -> str:
    """List directory contents."""
    path = arguments.get("path", ".")

    try:
        dir_path = Path(path)
        if not dir_path.exists():
            return f"Error: Directory not found: {path}"
        if not dir_path.is_dir():
            return f"Error: Not a directory: {path}"

        entries = []
        for entry in sorted(dir_path.iterdir()):
            if entry.is_dir():
                entries.append(f"[DIR]  {entry.name}/")
            else:
                size = entry.stat().st_size
                entries.append(f"[FILE] {entry.name} ({size} bytes)")

        return '\n'.join(entries) if entries else "(empty directory)"
    except Exception as e:
        return f"Error: {e}"


async def _search_pattern(arguments: dict, runtime: "Runtime") -> str:
    """Search for regex pattern in files."""
    pattern = arguments.get("pattern", "")
    path = arguments.get("path", ".")
    max_results = arguments.get("max_results", 50)

    if not pattern:
        return "Error: pattern is required"

    try:
        result = subprocess.run(
            ["grep", "-r", "-n", "-E", pattern, path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        lines = result.stdout.split('\n')[:max_results]
        return '\n'.join(lines) if lines and lines[0] else "No matches found"
    except subprocess.TimeoutExpired:
        return "Error: Search timed out"
    except Exception as e:
        return f"Error: {e}"


async def _analyze_file(arguments: dict, runtime: "Runtime") -> str:
    """Provide a structural overview of a file for pattern recognition."""
    path = arguments.get("path", "")
    if not path:
        return "Error: path is required"

    file_path = Path(path)
    if not file_path.exists():
        return f"Error: File not found: {path}"

    parts = []

    # Basic info
    try:
        stat = file_path.stat()
        parts.append(f"File: {file_path.name}")
        parts.append(f"Size: {stat.st_size} bytes ({stat.st_size / 1024:.1f} KB)")
    except Exception as e:
        return f"Error: {e}"

    # File type via `file` command
    try:
        result = subprocess.run(["file", str(file_path)], capture_output=True, text=True, timeout=10)
        file_type = result.stdout.strip().split(":", 1)[-1].strip()
        parts.append(f"Type: {file_type}")
    except Exception:
        pass

    # Check if binary
    try:
        with open(file_path, 'rb') as f:
            sample = f.read(4096)
            is_binary = b'\x00' in sample
    except Exception:
        is_binary = True

    if is_binary:
        parts.append("Content: Binary file (use extract_strings or read_file for hex dump)")
        return "\n".join(parts)

    # Text file analysis
    try:
        content = file_path.read_text(errors='replace')
        lines = content.split('\n')
        parts.append(f"Lines: {len(lines)}")

        # First and last lines
        parts.append(f"\nFirst 5 lines:")
        for line in lines[:5]:
            parts.append(f"  {line[:200]}")
        if len(lines) > 10:
            parts.append(f"\nLast 5 lines:")
            for line in lines[-5:]:
                parts.append(f"  {line[:200]}")

        # Detect common structural patterns
        patterns_found = {}

        # Template/function definitions
        template_defs = re.findall(r'define\s+"([^"]+)"', content)
        if template_defs:
            patterns_found["Template definitions (define \"...\")"] = len(template_defs)

        func_defs = re.findall(r'\bdef\s+\w+|function\s+\w+|func\s+\w+', content)
        if func_defs:
            patterns_found["Function definitions"] = len(func_defs)

        class_defs = re.findall(r'\bclass\s+\w+', content)
        if class_defs:
            patterns_found["Class definitions"] = len(class_defs)

        # Include/call patterns
        includes = re.findall(r'include\s+"([^"]+)"', content)
        if includes:
            patterns_found["Include calls"] = len(includes)
            unique_includes = len(set(includes))
            patterns_found["Unique includes"] = unique_includes

        # Detect operations that suggest VM/interpreter
        vm_indicators = {
            "Arithmetic (add/sub/mul/mod)": len(re.findall(r'\b(add|sub|mul|mod)\b', content)),
            "Memory operations (set/index)": len(re.findall(r'\b(set|index)\s+\$', content)),
            "Conditionals (if ne/eq/lt/gt)": len(re.findall(r'\bif\s+(ne|eq|lt|gt)\b', content)),
            "Loop patterns (recursive include)": 0,
            "I/O patterns (printf/input/read)": len(re.findall(r'\b(printf|input|read|write|print)\b', content)),
        }

        # Count recursive includes (templates that include themselves = loops)
        if template_defs:
            for tname in set(template_defs):
                # Check if any include of this template appears in its own definition
                pattern = rf'define\s+"{re.escape(tname)}".*?end\s*-?\}}\}}'
                matches = re.findall(pattern, content, re.DOTALL)
                for m in matches:
                    if f'include "{tname}"' in m:
                        vm_indicators["Loop patterns (recursive include)"] += 1

        for label, count in vm_indicators.items():
            if count > 0:
                patterns_found[label] = count

        if patterns_found:
            parts.append("\n## Structural Patterns:")
            for label, count in sorted(patterns_found.items(), key=lambda x: -x[1]):
                parts.append(f"  {label}: {count}")

        # Top repeated tokens (helps identify obfuscation/VM patterns)
        words = re.findall(r'[a-zA-Z_]\w{3,}', content)
        word_freq = collections.Counter(words).most_common(20)
        if word_freq:
            parts.append("\n## Top 20 tokens:")
            for word, count in word_freq:
                parts.append(f"  {word}: {count}")

        # VM/interpreter detection heuristic
        vm_score = 0
        if (patterns_found.get("Template definitions (define \"...\")") or 0) > 50:
            vm_score += 2
        if patterns_found.get("Arithmetic (add/sub/mul/mod)", 0) > 100:
            vm_score += 2
        if patterns_found.get("Memory operations (set/index)", 0) > 50:
            vm_score += 2
        if patterns_found.get("Loop patterns (recursive include)", 0) > 10:
            vm_score += 2
        if patterns_found.get("I/O patterns (printf/input/read)", 0) > 5:
            vm_score += 1

        if vm_score >= 4:
            parts.append("\n## HINT: This file likely implements a virtual machine or interpreter.")
            parts.append("  Strategy: Write a solve_script to parse the file, extract the")
            parts.append("  encoded program, and emulate/analyze it to determine expected input.")

    except Exception as e:
        parts.append(f"Error reading content: {e}")

    return "\n".join(parts)


async def _extract_strings(arguments: dict, runtime: "Runtime") -> str:
    """Extract printable strings from a file."""
    path = arguments.get("path", "")
    min_length = arguments.get("min_length", 4)
    max_results = arguments.get("max_results", 200)

    if not path:
        return "Error: path is required"

    try:
        result = subprocess.run(
            ["strings", "-n", str(min_length), path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        lines = result.stdout.split('\n')[:max_results]
        return '\n'.join(lines) if lines else "No strings found"
    except Exception as e:
        return f"Error: {e}"


# =============================================================================
# Execution Tools
# =============================================================================

READ_ONLY_CMD_CACHE_LIMIT = 128
SHELL_CONTROL_TOKENS = ("&&", "||", ";", "|", ">", "<", "$(", "`")


def _normalize_readonly_command(command: str) -> str | None:
    """
    Produce a stable cache key for deterministic read-only commands.

    We intentionally cache only simple one-shot commands (no shell control tokens)
    to avoid masking side-effectful command behavior.
    """
    if not command:
        return None
    cmd = " ".join(command.strip().split())
    if not cmd:
        return None
    if any(tok in cmd for tok in SHELL_CONTROL_TOKENS):
        return None

    if cmd.startswith("file "):
        return f"file::{cmd[5:].strip()}"

    if cmd.startswith("readelf "):
        try:
            parts = shlex.split(cmd)
        except ValueError:
            return None
        if len(parts) < 3:
            return None
        path = parts[-1]
        option_tokens = []
        for token in parts[1:-1]:
            if not token.startswith("-"):
                continue
            if token.startswith("--"):
                option_tokens.append(token)
                continue
            # Normalize short-option bundles and ignore formatting-only -W.
            chars = "".join(ch for ch in token[1:] if ch != "W")
            if chars:
                option_tokens.append("-" + "".join(sorted(set(chars))))
        return f"readelf::{path}::{' '.join(sorted(option_tokens))}"

    m = re.match(r"checksec\s+--file=([^\s]+)$", cmd)
    if m:
        return f"checksec::{m.group(1)}"

    return None

async def _run_command(arguments: dict, runtime: "Runtime") -> str:
    """Execute a shell command."""
    command = arguments.get("command", "")
    timeout = arguments.get("timeout", 30)
    cwd = arguments.get("cwd")

    if not command:
        return "Error: command is required"

    # Safety check - block dangerous commands
    dangerous = ["rm -rf /", "mkfs", "dd if=/dev/zero", ":(){:|:&};:"]
    for d in dangerous:
        if d in command:
            return f"Error: Blocked dangerous command pattern: {d}"

    cache_key = _normalize_readonly_command(command)
    cache = getattr(runtime, "_run_command_cache", None) if runtime is not None else None
    if cache is None:
        cache = {}
        if runtime is not None:
            setattr(runtime, "_run_command_cache", cache)
    if cache_key and cache_key in cache:
        return cache[cache_key]

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        output = result.stdout + result.stderr
        rendered = output[:20000] if output else f"(exit code: {result.returncode})"
        if cache_key and not rendered.startswith("Error:"):
            cache[cache_key] = rendered
            # Keep memory bounded.
            if len(cache) > READ_ONLY_CMD_CACHE_LIMIT:
                oldest_key = next(iter(cache.keys()))
                cache.pop(oldest_key, None)
        return rendered
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"


async def _python_eval(arguments: dict, runtime: "Runtime") -> str:
    """Evaluate a Python expression (safe subset)."""
    code = arguments.get("code", "")

    if not code:
        return "Error: code is required"

    # Very restricted - only allow safe operations
    allowed_builtins = {
        'abs': abs, 'len': len, 'str': str, 'int': int, 'float': float,
        'hex': hex, 'bin': bin, 'ord': ord, 'chr': chr, 'list': list,
        'range': range, 'sum': sum, 'min': min, 'max': max, 'sorted': sorted,
        'bytes': bytes, 'bytearray': bytearray,
    }

    try:
        # Only allow single expressions
        result = eval(code, {"__builtins__": allowed_builtins}, {})
        return str(result)
    except Exception as e:
        return f"Error: {e}"


async def _solve_script(arguments: dict, runtime: "Runtime") -> str:
    """Write and execute a Python solver script."""
    code = arguments.get("code", "")
    timeout = arguments.get("timeout", 120)
    args = arguments.get("args", "")

    if not code:
        return "Error: code is required"

    # Write script to temp file
    script_path = Path(f"/tmp/solve_script_{os.getpid()}.py")
    try:
        script_path.write_text(code)
    except Exception as e:
        return f"Error writing script: {e}"

    # Execute
    cmd = f"python3 {script_path}"
    if args:
        cmd += f" {args}"

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return f"Script timed out after {timeout}s. Partial output may be lost."

        output = ""
        if stdout:
            output += stdout.decode(errors="replace")
        if stderr:
            output += "\n[STDERR]\n" + stderr.decode(errors="replace")

        if not output.strip():
            output = f"(exit code: {proc.returncode})"

        return output[:30000]
    except Exception as e:
        return f"Error executing script: {e}"
    finally:
        try:
            script_path.unlink(missing_ok=True)
        except Exception:
            pass


# =============================================================================
# Network Tools
# =============================================================================

async def _netcat_interact(arguments: dict, runtime: "Runtime") -> str:
    """Connect to a network service and interact."""
    host = arguments.get("host", "")
    port = arguments.get("port", 0)
    send_data = arguments.get("send", "")
    timeout = arguments.get("timeout", 10)

    if not host or not port:
        return "Error: host and port are required"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, int(port)))

        # Read initial banner
        output_parts = []
        try:
            while True:
                sock.settimeout(2.0)
                data = sock.recv(4096)
                if not data:
                    break
                output_parts.append(data.decode('utf-8', errors='replace'))
                if len(output_parts) > 50:
                    break
        except socket.timeout:
            pass

        # Send data if provided
        if send_data:
            # Process escape sequences
            send_data = send_data.encode().decode('unicode_escape')
            sock.sendall(send_data.encode())

            # Read response
            try:
                while True:
                    sock.settimeout(2.0)
                    data = sock.recv(4096)
                    if not data:
                        break
                    output_parts.append(data.decode('utf-8', errors='replace'))
                    if len(output_parts) > 100:
                        break
            except socket.timeout:
                pass

        sock.close()
        return "".join(output_parts)[:50000]

    except socket.error as e:
        return f"Error: {e}"


# =============================================================================
# Decoding Tools
# =============================================================================

async def _decode(arguments: dict, runtime: "Runtime") -> str:
    """Try to decode text using common encodings."""
    text = arguments.get("text", "")
    method = arguments.get("method", "auto")

    if not text:
        return "Error: text is required"

    results = []

    def try_base64(t):
        try:
            padded = t + "=" * (4 - len(t) % 4) if len(t) % 4 else t
            decoded = base64.b64decode(padded, validate=True)
            if all(32 <= b < 127 or b in (9, 10, 13) for b in decoded):
                return decoded.decode('utf-8')
        except:
            pass
        return None

    def try_base32(t):
        try:
            upper = t.upper()
            padded = upper + "=" * (8 - len(upper) % 8) if len(upper) % 8 else upper
            decoded = base64.b32decode(padded)
            if all(32 <= b < 127 or b in (9, 10, 13) for b in decoded):
                return decoded.decode('utf-8')
        except:
            pass
        return None

    def try_hex(t):
        try:
            decoded = binascii.unhexlify(t)
            if all(32 <= b < 127 or b in (9, 10, 13) for b in decoded):
                return decoded.decode('utf-8')
        except:
            pass
        return None

    def try_rot13(t):
        result = []
        for c in t:
            if 'a' <= c <= 'z':
                result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(c)
        return ''.join(result)

    def try_xor(t, key):
        try:
            decoded = bytes([b ^ key for b in t.encode()])
            if all(32 <= b < 127 or b in (9, 10, 13) for b in decoded):
                return decoded.decode('utf-8')
        except:
            pass
        return None

    methods_to_try = ["base64", "base32", "hex", "rot13"] if method == "auto" else [method]

    for m in methods_to_try:
        result = None
        if m == "base64":
            result = try_base64(text)
        elif m == "base32":
            result = try_base32(text)
        elif m == "hex":
            result = try_hex(text)
        elif m == "rot13":
            result = try_rot13(text)
        elif m == "xor":
            # Try common XOR keys
            for key in range(1, 256):
                result = try_xor(text, key)
                if result and len(result) > 3:
                    results.append(f"xor(key={key}): {result}")
                    break
            continue

        if result:
            results.append(f"{m}: {result}")

    return "\n".join(results) if results else "No valid decoding found"


# =============================================================================
# APK Tools
# =============================================================================

async def _apk_extract(arguments: dict, runtime: "Runtime") -> str:
    """Extract and analyze an APK file."""
    apk_path = arguments.get("apk_path", "")

    if not apk_path:
        return "Error: apk_path is required"

    if not os.path.isfile(apk_path):
        return f"Error: APK not found: {apk_path}"

    try:
        from ...apk import APKAnalyzer
        analyzer = APKAnalyzer(apk_path)
        result = analyzer.analyze()

        if result.error:
            return f"Error: {result.error}"

        summary = {
            "package": result.package_name,
            "version": result.version_name,
            "activities": len(result.activities),
            "services": len(result.services),
            "permissions": result.permissions[:10],
            "strings_found": len(result.strings),
            "suspicious_hits": len(result.suspicious_hits),
            "out_dir": str(result.out_dir),
        }

        import json
        return json.dumps(summary, indent=2)
    except ImportError:
        return "Error: APK analyzer not available"
    except Exception as e:
        return f"Error: {e}"


async def _apk_solve(arguments: dict, runtime: "Runtime") -> str:
    """Run deterministic APK CTF solver."""
    apk_path = arguments.get("apk_path", "")
    flag_regex = arguments.get("flag_regex", r"picoCTF\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}")

    if not apk_path:
        return "Error: apk_path is required"

    try:
        from ...apk import APKAnalyzer
        analyzer = APKAnalyzer(apk_path)
        analyzer.analyze()
        solver_result = analyzer.solve(flag_regex=flag_regex)

        if solver_result.success:
            flags = [f.flag for f in solver_result.flags]
            return f"FLAGS FOUND: {flags}"
        else:
            return f"No flags found. Reason: {solver_result.stop_reason}"
    except Exception as e:
        return f"Error: {e}"


# =============================================================================
# Register Tools
# =============================================================================

def register_general_tools():
    """Register all general-purpose tools."""

    tools = [
        Tool(
            name="read_file",
            description="Read contents of a file. Returns hex dump for binary files.",
            schema=ToolSchema(
                properties={
                    "path": {"type": "string", "description": "Path to the file"},
                    "max_bytes": {"type": "integer", "description": "Max bytes to read (default: 10000)"},
                },
                required=["path"],
            ),
            execute_fn=_read_file,
            category="filesystem",
        ),
        Tool(
            name="list_dir",
            description="List contents of a directory.",
            schema=ToolSchema(
                properties={
                    "path": {"type": "string", "description": "Directory path (default: current)"},
                },
                required=[],
            ),
            execute_fn=_list_dir,
            category="filesystem",
        ),
        Tool(
            name="search_pattern",
            description="Search for a regex pattern in files (grep).",
            schema=ToolSchema(
                properties={
                    "pattern": {"type": "string", "description": "Regex pattern to search"},
                    "path": {"type": "string", "description": "File or directory to search"},
                    "max_results": {"type": "integer", "description": "Max results (default: 50)"},
                },
                required=["pattern"],
            ),
            execute_fn=_search_pattern,
            category="filesystem",
        ),
        Tool(
            name="analyze_file",
            description=(
                "Structural overview of a file: size, line count, type, pattern counts "
                "(template/function definitions, arithmetic ops, memory ops, loops, I/O). "
                "Use BEFORE reading large files to understand structure and detect VMs/interpreters."
            ),
            schema=ToolSchema(
                properties={
                    "path": {"type": "string", "description": "Path to the file"},
                },
                required=["path"],
            ),
            execute_fn=_analyze_file,
            category="filesystem",
        ),
        Tool(
            name="extract_strings",
            description="Extract printable strings from a binary file.",
            schema=ToolSchema(
                properties={
                    "path": {"type": "string", "description": "Path to the file"},
                    "min_length": {"type": "integer", "description": "Minimum string length (default: 4)"},
                    "max_results": {"type": "integer", "description": "Max results (default: 200)"},
                },
                required=["path"],
            ),
            execute_fn=_extract_strings,
            category="filesystem",
        ),
        Tool(
            name="run_command",
            description="Execute a shell command. Use for: file, objdump, readelf, etc.",
            schema=ToolSchema(
                properties={
                    "command": {"type": "string", "description": "Command to execute"},
                    "timeout": {"type": "integer", "description": "Timeout in seconds (default: 30)"},
                    "cwd": {"type": "string", "description": "Working directory (optional)"},
                },
                required=["command"],
            ),
            execute_fn=_run_command,
            category="execution",
        ),
        Tool(
            name="python_eval",
            description="Evaluate a Python expression (safe subset: math, conversions).",
            schema=ToolSchema(
                properties={
                    "code": {"type": "string", "description": "Python expression to evaluate"},
                },
                required=["code"],
            ),
            execute_fn=_python_eval,
            category="execution",
        ),
        Tool(
            name="netcat",
            description="Connect to a network service and interact. Returns banner and response.",
            schema=ToolSchema(
                properties={
                    "host": {"type": "string", "description": "Hostname to connect to"},
                    "port": {"type": "integer", "description": "Port number"},
                    "send": {"type": "string", "description": "Data to send (use \\n for newlines)"},
                    "timeout": {"type": "integer", "description": "Timeout in seconds (default: 10)"},
                },
                required=["host", "port"],
            ),
            execute_fn=_netcat_interact,
            category="network",
        ),
        Tool(
            name="decode",
            description="Try to decode text using common encodings (base64, base32, hex, rot13, xor).",
            schema=ToolSchema(
                properties={
                    "text": {"type": "string", "description": "Text to decode"},
                    "method": {
                        "type": "string",
                        "description": "Method: auto, base64, base32, hex, rot13, xor",
                        "enum": ["auto", "base64", "base32", "hex", "rot13", "xor"],
                    },
                },
                required=["text"],
            ),
            execute_fn=_decode,
            category="crypto",
        ),
        Tool(
            name="apk_extract",
            description="Extract and analyze an Android APK file. Returns manifest, components, permissions.",
            schema=ToolSchema(
                properties={
                    "apk_path": {"type": "string", "description": "Path to APK file"},
                },
                required=["apk_path"],
            ),
            execute_fn=_apk_extract,
            category="reverse",
        ),
        Tool(
            name="apk_solve",
            description="Run deterministic APK CTF solver to find encoded flags.",
            schema=ToolSchema(
                properties={
                    "apk_path": {"type": "string", "description": "Path to APK file"},
                    "flag_regex": {"type": "string", "description": "Flag pattern regex"},
                },
                required=["apk_path"],
            ),
            execute_fn=_apk_solve,
            category="reverse",
        ),
        Tool(
            name="solve_script",
            description=(
                "Write and execute a Python solver script. Use this for challenges that need "
                "custom code: timing attacks, brute-force, crypto, socket pipelining, PRNG prediction, etc. "
                "The code parameter is a full Python program (imports allowed). Returns stdout+stderr."
            ),
            schema=ToolSchema(
                properties={
                    "code": {"type": "string", "description": "Full Python script source code"},
                    "timeout": {"type": "integer", "description": "Timeout in seconds (default: 120)"},
                    "args": {"type": "string", "description": "Command-line arguments (optional)"},
                },
                required=["code"],
            ),
            execute_fn=_solve_script,
            category="execution",
        ),
    ]

    for tool in tools:
        register_tool_instance(tool)

    return tools
