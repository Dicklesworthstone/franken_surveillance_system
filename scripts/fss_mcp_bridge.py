#!/usr/bin/env python3
"""Opt-in, read-only FSS CLI bridge. Python 3.11+, POSIX, standard library only.

This is a reference adapter, not the native production MCP service. Authority,
coverage, continuation and evidence semantics belong to the existing fss CLI.
The operator pins the executable, deployment root and audit principal; clients
cannot override them or select an arbitrary command. There is no network server.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import signal
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class BridgeError(Exception):
    """An intentionally non-secret, stable bridge error identity."""

    def __init__(self, identity: str):
        super().__init__(identity)
        self.identity = identity


class InvalidArguments(BridgeError):
    def __init__(self) -> None:
        super().__init__("ERR-MCP-ARGUMENTS-001")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(_: str) -> Any:
    raise ValueError("non-finite JSON number")


def parse_json(raw: bytes | str) -> Any:
    """Reject duplicate keys, non-JSON numbers and excessively nested values."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="strict")
    # Bound nesting BEFORE json.loads, including escaped quotes and brackets in text.
    depth = 0
    quoted = escaped = False
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 64:
                raise ValueError("JSON nesting limit")
        elif char in "]}":
            depth -= 1
    value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            item.encode("utf-8", errors="strict")  # Reject escaped lone surrogates.
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("JSON number overflow")
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return value


def _text(maximum: int = 1024, **extra: Any) -> dict[str, Any]:
    return {"type": "string", "minLength": 1, "maxLength": maximum, **extra}


def _integer(minimum: int, maximum: int) -> dict[str, Any]:
    return {"type": "integer", "minimum": minimum, "maximum": maximum}


# Keep these names aligned with architecture/operation_crosswalk.json. No effect,
# session-writing, export, hydration, raw-file or arbitrary-execution tools exist.
TOOL_SPECS: dict[str, dict[str, Any]] = {
    "session_orient": {
        "command": ("session", "orient"),
        "operation": "AOP-003",
        "description": "Read the committed situation and coverage. Affordances are listed, never executed.",
        "properties": {
            "view": _text(enum=["pulse", "brief", "epistemic_map"]),
            "budget_tokens": _integer(1, 1_000_000),
        },
        "required": [],
    },
    "session_follow": {
        "command": ("session", "follow"),
        "operation": "AOP-004",
        "description": "Read one exact delta page since an orient anchor. Pass opaque continuation tokens unchanged; this is not a subscription.",
        "properties": {
            "since": _text(16_384),
            "view": _text(enum=["pulse", "brief"]),
            "max_entries": _integer(1, 32),
            "continuation": _text(16_384),
        },
        "required": ["since"],
    },
    "query": {
        "command": ("query",),
        "operation": "AOP-005",
        "description": "Read an exact bounded committed event-record page. An empty result never proves physical absence.",
        "properties": {
            "event_id": _text(), "kind": _text(128), "state": _text(128),
            "zone": _text(),
            # Decimal strings preserve the full signed i128 range in JS clients.
            "from_ns": _text(40, pattern=r"^(0|-?[1-9][0-9]*)$"),
            "through_ns": _text(40, pattern=r"^(0|-?[1-9][0-9]*)$"),
            "max_entries": _integer(1, 32),
            "anchor": _text(16_384), "continuation": _text(16_384),
        },
        "required": [],
    },
    "explain": {
        "command": ("explain",),
        "operation": "AOP-011",
        "description": "Read one published event's evidence, knowledge states and contradictions. Does not publish or notify.",
        "properties": {"event_id": _text()},
        "required": ["event_id"],
    },
}


def tool_catalog() -> list[dict[str, Any]]:
    return [{
        "name": name,
        "description": f"{spec['operation']}: {spec['description']}",
        "inputSchema": {
            "type": "object", "properties": spec["properties"],
            "required": spec["required"], "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True, "destructiveHint": False,
            "idempotentHint": True, "openWorldHint": False,
        },
    } for name, spec in TOOL_SPECS.items()]


def validate_arguments(name: str, arguments: Any) -> dict[str, str | int]:
    if not isinstance(name, str) or name not in TOOL_SPECS or not isinstance(arguments, dict):
        raise InvalidArguments()
    spec = TOOL_SPECS[name]
    props = spec["properties"]
    if arguments.keys() - props.keys() or any(key not in arguments for key in spec["required"]):
        raise InvalidArguments()
    for key, value in arguments.items():
        schema = props[key]
        if schema["type"] == "integer":
            if type(value) is not int or not schema["minimum"] <= value <= schema["maximum"]:
                raise InvalidArguments()
        else:
            if not isinstance(value, str) or not 1 <= len(value) <= schema["maxLength"]:
                raise InvalidArguments()
            try:
                if len(value.encode("utf-8")) > schema["maxLength"]:
                    raise InvalidArguments()
            except UnicodeError as exc:
                raise InvalidArguments() from exc
            if any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise InvalidArguments()
            if "enum" in schema and value not in schema["enum"]:
                raise InvalidArguments()
            if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
                raise InvalidArguments()
        if key in ("from_ns", "through_ns") and not -(1 << 127) <= int(value) < (1 << 127):
            raise InvalidArguments()
    if "from_ns" in arguments and "through_ns" in arguments:
        if int(arguments["from_ns"]) > int(arguments["through_ns"]):
            raise InvalidArguments()
    return dict(arguments)


@dataclass(frozen=True)
class Config:
    executable: Path
    root: Path
    principal: str = "principal:local-mcp"
    timeout_seconds: float = 15.0
    output_bytes: int = 2 * 1024 * 1024
    stderr_bytes: int = 16 * 1024

    def __post_init__(self) -> None:
        try:
            if os.name != "posix" or not self.executable.is_absolute() or not self.root.is_absolute():
                raise ValueError
            executable = self.executable.resolve(strict=True)
            root = self.root.resolve(strict=True)
            if not executable.is_file() or not os.access(executable, os.X_OK) or not root.is_dir():
                raise ValueError
            if not isinstance(self.principal, str) or not re.fullmatch(r"[A-Za-z0-9:._/-]{1,256}", self.principal):
                raise ValueError
            if type(self.timeout_seconds) not in (int, float) or not math.isfinite(self.timeout_seconds):
                raise ValueError
            if not 0.05 <= self.timeout_seconds <= 60:
                raise ValueError
            if type(self.output_bytes) is not int or not 1024 <= self.output_bytes <= 16 * 1024 * 1024:
                raise ValueError
            if type(self.stderr_bytes) is not int or not 1024 <= self.stderr_bytes <= 64 * 1024:
                raise ValueError
        except (OSError, ValueError, TypeError, RuntimeError) as exc:
            raise BridgeError("ERR-MCP-CONFIGURATION-001") from exc
        object.__setattr__(self, "executable", executable)
        object.__setattr__(self, "root", root)


def command_argv(config: Config, name: str, arguments: Any) -> list[str]:
    arguments = validate_arguments(name, arguments)
    # Inline values remain one argument even when they begin with '--'. Never use
    # shlex, a shell, PATH lookup or client-specified executable/root/principal.
    argv = [str(config.executable), *TOOL_SPECS[name]["command"], "--json",
            f"--root={config.root}", f"--principal={config.principal}"]
    for key in TOOL_SPECS[name]["properties"]:
        if key in arguments:
            argv.append(f"--{key.replace('_', '-')}={arguments[key]}")
    return argv


async def _read_bounded(stream: asyncio.StreamReader, maximum: int) -> bytes:
    output = bytearray()
    while True:
        chunk = await stream.read(min(8192, maximum + 1 - len(output)))
        if not chunk:
            return bytes(output)
        output.extend(chunk)
        if len(output) > maximum:
            raise BridgeError("ERR-MCP-OUTPUT-LIMIT-001")


async def _stop_process(process: asyncio.subprocess.Process) -> None:
    # Every child gets a new POSIX session. Kill its group even when the leader
    # exited: otherwise an inherited pipe can keep a reader alive indefinitely.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    async def drain(stream: asyncio.StreamReader | None) -> None:
        if stream is not None:
            while await stream.read(8192):
                pass

    # Process.wait alone can deadlock when a paused pipe transport still holds
    # bytes. Readers have been cancelled/joined before we drain the killed group.
    try:
        await asyncio.wait_for(asyncio.gather(
            drain(process.stdout), drain(process.stderr), process.wait()), 1.0)
    except TimeoutError as exc:
        raise BridgeError("ERR-MCP-CLEANUP-001") from exc


async def run_cli(config: Config, name: str, arguments: Any) -> dict[str, Any]:
    """One read, no retry; bound stdout AND stderr while the process is running."""
    argv = command_argv(config, name, arguments)
    process: asyncio.subprocess.Process | None = None
    tasks: list[asyncio.Task[Any]] = []
    completed = False
    try:
        process = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            # An absolute executable does not need the operator's secret-bearing
            # environment or dynamic-loader overrides. No per-tool env overrides.
            env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"},
            limit=8192,
        )
        assert process.stdout is not None and process.stderr is not None
        tasks = [asyncio.create_task(_read_bounded(process.stdout, config.output_bytes)),
                 asyncio.create_task(_read_bounded(process.stderr, config.stderr_bytes)),
                 asyncio.create_task(process.wait())]
        try:
            raw, stderr, exit_code = await asyncio.wait_for(
                asyncio.gather(*tasks), timeout=config.timeout_seconds)
            completed = True
        except TimeoutError as exc:
            raise BridgeError("ERR-MCP-TIMEOUT-001") from exc
        try:
            envelope = parse_json(raw)
            if not isinstance(envelope, dict) or not envelope:
                raise ValueError("expected CLI object")
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise BridgeError("ERR-MCP-CLI-OUTPUT-001") from exc
        # Forward the entire original envelope. Do not promote incomplete coverage,
        # synthesize a silence certificate or substitute a newer continuation.
        return {
            "content": [{"type": "text", "text": raw.decode("utf-8").strip()}],
            "structuredContent": envelope,
            "isError": exit_code != 0,
            "_meta": {"fss/bridge": {
                "operationId": TOOL_SPECS[name]["operation"],
                "exitCode": exit_code, "stdoutSha256": hashlib.sha256(raw).hexdigest(),
                "stderrBytes": len(stderr), "stderrSha256": hashlib.sha256(stderr).hexdigest(),
            }},
        }
    except OSError as exc:
        raise BridgeError("ERR-MCP-EXECUTION-001") from exc
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if process is not None and not completed:
            await _stop_process(process)


# Explicitly supported dated profiles. Modern request context is NEVER inherited
# from a preceding request, even when both eras share the same stdio process.
MODERN_VERSION = "2026-07-28"
LEGACY_VERSIONS = ("2025-11-25", "2025-06-18")
PROTOCOL_VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
CLIENT_CAPABILITIES_KEY = "io.modelcontextprotocol/clientCapabilities"
CLIENT_INFO_KEY = "io.modelcontextprotocol/clientInfo"
SERVER_INFO_KEY = "io.modelcontextprotocol/serverInfo"
MAX_INPUT_BYTES = 64 * 1024
MAX_REQUESTS = 4096
SERVER_INFO = {"name": "fss-read-only-bridge", "version": "0.1.0"}


class RpcFault(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code, self.message, self.data = code, message, data


def _request_id(value: Any) -> bool:
    return (type(value) is int and -(2**53 - 1) <= value <= 2**53 - 1) or (
        isinstance(value, str) and 1 <= len(value) <= 256)


def _tool_failure(identity: str) -> dict[str, Any]:
    # Transport failures are not FSS authority receipts. In particular, no
    # synthetic AgentResponseEnvelope is supplied on timeout/corruption/cancel.
    return {"content": [{"type": "text", "text": identity}], "isError": True}


@dataclass
class _Job:
    task: asyncio.Task[None]
    cancelled: bool = False


class Server:
    """Bounded concurrent calls; notifications never spawn work or get replies."""

    def __init__(self, config: Config, *, max_inflight: int = 2, runner: Any = run_cli):
        if type(max_inflight) is not int or not 1 <= max_inflight <= 4:
            raise BridgeError("ERR-MCP-CONFIGURATION-001")
        self.config, self.max_inflight, self.runner = config, max_inflight, runner
        self.version: str | None = None
        self.ready = False
        self.jobs: dict[str | int, _Job] = {}
        self.tasks: set[asyncio.Task[None]] = set()
        self.seen: set[str | int] = set()
        self.request_count = 0
        self.stopping = asyncio.Event()
        self.output_lock = asyncio.Lock()
        self._send_bytes: Any = None

    def request_stop(self) -> None:
        self.stopping.set()

    async def _send(self, response: dict[str, Any], on_begin: Any = None) -> None:
        if self.stopping.is_set():
            return
        data = json.dumps(response, ensure_ascii=False, allow_nan=False,
                          separators=(",", ":")).encode("utf-8") + b"\n"
        if len(data) > 16 * 1024 * 1024:
            failed = _tool_failure("ERR-MCP-OUTPUT-LIMIT-001")
            if response.get("result", {}).get("resultType") == "complete":
                failed = self._result(failed, modern=True)
            data = json.dumps({"jsonrpc": "2.0", "id": response.get("id"), "result": failed},
                              separators=(",", ":")).encode() + b"\n"
        try:
            async with self.output_lock:
                if not self.stopping.is_set():
                    # One immutable frame now owns the output channel. A client
                    # may receive it before local drain completes. Release its ID
                    # at this boundary, not when the worker eventually retires.
                    if on_begin is not None:
                        on_begin()
                    await asyncio.wait_for(self._send_bytes(data), timeout=5.0)
        except (OSError, TimeoutError):
            self.request_stop()

    async def _error(self, identity: Any, code: int, message: str, data: Any = None) -> None:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        await self._send({"jsonrpc": "2.0", "id": identity, "error": error})

    @staticmethod
    def _result(result: dict[str, Any], modern: bool) -> dict[str, Any]:
        if not modern:
            return result
        # Only the MCP wrapper changes, NEVER the FSS structuredContent object.
        return {**result, "resultType": "complete",
                "_meta": {**result.get("_meta", {}), SERVER_INFO_KEY: SERVER_INFO}}

    @staticmethod
    def _modern(method: str, params: dict[str, Any]) -> bool:
        meta = params.get("_meta", {})
        if not isinstance(meta, dict):
            raise RpcFault(-32602, "Invalid request metadata")
        modern = method == "server/discover" or any(key in meta for key in (
            PROTOCOL_VERSION_KEY, CLIENT_CAPABILITIES_KEY, CLIENT_INFO_KEY))
        if not modern:
            return False
        version = meta.get(PROTOCOL_VERSION_KEY)
        if not isinstance(version, str) or not isinstance(meta.get(CLIENT_CAPABILITIES_KEY), dict):
            raise RpcFault(-32602, "Missing or invalid per-request protocol metadata")
        info = meta.get(CLIENT_INFO_KEY)
        if info is not None and (not isinstance(info, dict)
                or not isinstance(info.get("name"), str) or not isinstance(info.get("version"), str)):
            raise RpcFault(-32602, "Invalid per-request client identity")
        if version != MODERN_VERSION:
            raise RpcFault(-32022, "Unsupported protocol version", {
                "supported": [MODERN_VERSION], "requested": version})
        return True

    def _cancel(self, identity: Any) -> None:
        if not _request_id(identity):
            return
        job = self.jobs.get(identity)
        if job is not None and not job.cancelled:
            job.cancelled = True
            job.task.cancel()

    def _retire(self, identity: str | int, task: asyncio.Task[None]) -> None:
        self.tasks.discard(task)
        job = self.jobs.get(identity)
        if job is not None and job.task is task:
            self.jobs.pop(identity, None)

    async def _call(self, identity: str | int, name: str, arguments: Any, modern: bool) -> None:
        try:
            try:
                result = await self.runner(self.config, name, arguments)
            except BridgeError as exc:
                result = _tool_failure(exc.identity)
            except Exception:
                # Never leak an OS path, provider response, traceback or a client
                # argument through an unexpected implementation error.
                result = _tool_failure("ERR-MCP-INTERNAL-001")
            if not self.jobs[identity].cancelled:
                def begin_response() -> None:
                    job = self.jobs.get(identity)
                    if job is not None and job.task is asyncio.current_task():
                        self.jobs.pop(identity, None)

                await self._send({"jsonrpc": "2.0", "id": identity,
                                  "result": self._result(result, modern)}, begin_response)
        except asyncio.CancelledError:
            # A cancelled MCP request receives no further messages. run_cli's
            # finally block kills/reaps the child before this task is retired.
            pass
        finally:
            task = asyncio.current_task()
            if task is not None:
                self._retire(identity, task)

    async def _dispatch(self, identity: str | int, method: str, params: dict[str, Any], modern: bool) -> Any:
        if method == "server/discover":
            if params.keys() - {"_meta"}:
                raise RpcFault(-32602, "Invalid discovery parameters")
            return {"supportedVersions": [MODERN_VERSION, *LEGACY_VERSIONS],
                    "capabilities": {"tools": {}},
                    "instructions": "Read-only reference bridge. No effect tools or authentication. Deployment and audit principal are operator-pinned."}
        if method == "initialize":
            if modern:
                raise RpcFault(-32601, "Initialization is not a modern protocol method")
            if self.version is not None:
                raise RpcFault(-32600, "Already initialized")
            info = params.get("clientInfo")
            if (not isinstance(params.get("protocolVersion"), str)
                    or not isinstance(params.get("capabilities"), dict)
                    or not isinstance(info, dict)
                    or not isinstance(info.get("name"), str)
                    or not isinstance(info.get("version"), str)):
                raise RpcFault(-32602, "Invalid initialization parameters")
            offered = params["protocolVersion"]
            self.version = offered if offered in LEGACY_VERSIONS else LEGACY_VERSIONS[0]
            return {
                "protocolVersion": self.version, "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
                "instructions": "Read-only reference bridge. Root and audit principal are operator-pinned. An empty query is not absence evidence. No authentication or effect tools.",
            }
        if method == "ping":
            return {}
        if method not in ("tools/list", "tools/call"):
            raise RpcFault(-32601, "Method not found")
        if not modern and not self.ready:
            raise RpcFault(-32602, "Initialization or per-request protocol metadata required")
        if method == "tools/list":
            if params.keys() - {"_meta"}:
                # All four tools fit one page; no cursor is ever minted.
                raise RpcFault(-32602, "Unsupported tools cursor or parameter")
            return {"tools": tool_catalog()}
        if (params.keys() - {"name", "arguments", "_meta"}
                or not isinstance(params.get("name"), str)
                or params["name"] not in TOOL_SPECS
                or not isinstance(params.get("arguments", {}), dict)):
            raise RpcFault(-32602, "Unknown tool or malformed tool call")
        if len(self.tasks) >= self.max_inflight:
            return _tool_failure("ERR-MCP-BUSY-001")
        try:
            args = validate_arguments(params["name"], params.get("arguments", {}))
        except InvalidArguments as exc:
            return _tool_failure(exc.identity)
        task = asyncio.create_task(self._call(identity, params["name"], args, modern))
        self.jobs[identity] = _Job(task)
        self.tasks.add(task)
        # A coroutine cancelled before its first poll never enters its finally
        # block. The done callback is therefore required, not just defensive.
        task.add_done_callback(lambda done: self._retire(identity, done))
        return None  # Exactly this task owns the eventual response.

    async def handle(self, raw: bytes) -> None:
        try:
            request = parse_json(raw)
        except (ValueError, UnicodeError, RecursionError):
            await self._error(None, -32700, "Parse error")
            return
        if (not isinstance(request, dict) or request.get("jsonrpc") != "2.0"
                or not isinstance(request.get("method"), str)
                or request.keys() - {"jsonrpc", "id", "method", "params"}):
            await self._error(None, -32600, "Invalid request")
            return
        method = request["method"]
        params = request.get("params", {})
        if "id" not in request:
            # A malformed or unknown notification has no response and no effect.
            if not isinstance(params, dict):
                return
            if method == "notifications/initialized" and self.version is not None:
                self.ready = True
            elif method == "notifications/cancelled":
                self._cancel(params.get("requestId"))
            return
        identity = request["id"]
        if not _request_id(identity):
            await self._error(None, -32600, "Invalid request id")
            return
        if not isinstance(params, dict):
            await self._error(identity, -32602, "Invalid parameters")
            return
        try:
            modern = self._modern(method, params)
        except RpcFault as exc:
            await self._error(identity, exc.code, exc.message, exc.data)
            return
        if identity in self.jobs or (not modern and identity in self.seen):
            # Modern IDs may be reused AFTER a response, never while in flight.
            await self._error(None, -32600, "Duplicate request id; closing transport")
            self.request_stop()
            return
        if self.request_count >= MAX_REQUESTS:
            # Application-defined code outside JSON-RPC/MCP's reserved range.
            await self._error(identity, -32900, "Request budget exhausted; restart transport")
            self.request_stop()
            return
        self.request_count += 1
        if not modern:
            self.seen.add(identity)
        try:
            result = await self._dispatch(identity, method, params, modern)
        except RpcFault as exc:
            await self._error(identity, exc.code, exc.message, exc.data)
        else:
            if result is not None:
                await self._send({"jsonrpc": "2.0", "id": identity,
                                  "result": self._result(result, modern)})

    async def serve(self, reader: asyncio.StreamReader, send_bytes: Any) -> None:
        self._send_bytes = send_bytes

        async def read_loop() -> None:
            while not self.stopping.is_set():
                try:
                    raw = await reader.readline()
                except ValueError:
                    await self._error(None, -32600, "Message byte limit exceeded; closing transport")
                    return
                if not raw:
                    return
                if len(raw) > MAX_INPUT_BYTES or not raw.endswith(b"\n"):
                    await self._error(None, -32600, "Invalid framing or message byte limit")
                    return
                await self.handle(raw)

        reading = asyncio.create_task(read_loop())
        stopping = asyncio.create_task(self.stopping.wait())
        try:
            await asyncio.wait((reading, stopping), return_when=asyncio.FIRST_COMPLETED)
        finally:
            self.request_stop()
            reading.cancel()
            stopping.cancel()
            # Include workers whose reply has started but whose local drain has
            # not finished. Cancel at most once so child cleanup is not interrupted.
            tasks = list(self.tasks)
            for task in tasks:
                if task.cancelling() == 0:
                    task.cancel()
            await asyncio.gather(reading, stopping, *tasks, return_exceptions=True)


class _Output(asyncio.Protocol):
    """Write-pipe flow control without a blocking stdout write in the input loop."""

    def __init__(self) -> None:
        self.transport: Any = None
        self.paused = False
        self.closed = False
        self.waiter: asyncio.Future[None] | None = None

    def connection_made(self, transport: Any) -> None:
        self.transport = transport
        transport.set_write_buffer_limits(high=64 * 1024, low=16 * 1024)

    def pause_writing(self) -> None:
        self.paused = True

    def resume_writing(self) -> None:
        self.paused = False
        if self.waiter is not None and not self.waiter.done():
            self.waiter.set_result(None)

    def connection_lost(self, exc: Exception | None) -> None:
        self.closed = True
        self.resume_writing()

    async def send(self, data: bytes) -> None:
        if self.closed:
            raise BrokenPipeError
        self.transport.write(data)
        if self.paused:
            self.waiter = asyncio.get_running_loop().create_future()
            try:
                await self.waiter
            finally:
                self.waiter = None
        if self.closed:
            raise BrokenPipeError


async def _stdio(config: Config, max_inflight: int) -> None:
    import sys
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=MAX_INPUT_BYTES)
    input_transport, _ = await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer)
    output = _Output()
    output_transport, _ = await loop.connect_write_pipe(lambda: output, sys.stdout.buffer)
    server = Server(config, max_inflight=max_inflight)
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, server.request_stop)
    try:
        await server.serve(reader, output.send)
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(sig)
        input_transport.close()
        output_transport.close()


def main() -> int:
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fss-binary", required=True, type=Path, help="absolute path to an operator-trusted fss binary")
    parser.add_argument("--root", required=True, type=Path, help="absolute path to one authorized deployment")
    parser.add_argument("--principal", default="principal:local-mcp", help="fixed audit label; NOT authentication")
    parser.add_argument("--timeout-seconds", type=float, default=15.0)
    parser.add_argument("--output-bytes", type=int, default=2 * 1024 * 1024)
    parser.add_argument("--max-inflight", type=int, default=2)
    args = parser.parse_args()
    try:
        config = Config(args.fss_binary, args.root, args.principal, args.timeout_seconds, args.output_bytes)
        asyncio.run(_stdio(config, args.max_inflight))
        return 0
    except (BridgeError, OSError, ValueError, RuntimeError):
        print("ERR-MCP-STARTUP-001", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
