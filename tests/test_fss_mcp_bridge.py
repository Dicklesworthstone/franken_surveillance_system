"""Offline bridge tests: real subprocesses, no cameras, relay, deployment or network."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "fss_mcp_bridge.py"
spec = importlib.util.spec_from_file_location("fss_mcp_bridge", SCRIPT)
bridge = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = bridge
spec.loader.exec_module(bridge)


class ParsingTests(unittest.TestCase):
    def test_exact_registered_read_only_tools(self):
        self.assertEqual(list(bridge.TOOL_SPECS), ["session_orient", "session_follow", "query", "explain"])
        for tool in bridge.tool_catalog():
            self.assertTrue(tool["annotations"]["readOnlyHint"])
            self.assertFalse(tool["inputSchema"]["additionalProperties"])

    def test_strict_json(self):
        for raw in (b'{"a":1,"a":2}', b'NaN', b'Infinity', b'1e999',
                    b'"\\ud800"', b'"\xff"', b'{} {}', b'[' * 65 + b']' * 65):
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                bridge.parse_json(raw)

    def test_quoted_brackets_do_not_consume_depth(self):
        self.assertEqual(bridge.parse_json(json.dumps("[" * 100)), "[" * 100)
        self.assertEqual(bridge.parse_json('{"a": "quote: \\\""}'), {"a": 'quote: "'})

    def test_client_cannot_change_scope_or_invoke_effect(self):
        for name, args in (("commit", {}), ("session_open", {}), ("session_orient", {"root": "/tmp"}),
                           ("query", {"principal": "admin"}), ("explain", {"event_id": "e", "command": "rm"})):
            with self.subTest(name=name, args=args), self.assertRaises(bridge.InvalidArguments):
                bridge.validate_arguments(name, args)

    def test_required_and_shape(self):
        for name, args in (("explain", {}), ("session_follow", {}), ("query", []), ([], {}),
                           ("query", {"max_entries": True}), ("query", {"max_entries": 0}),
                           ("query", {"max_entries": 33}), ("query", {"max_entries": 1.5}),
                           ("explain", {"event_id": ""}), ("explain", {"event_id": "a\nb"}),
                           ("session_orient", {"view": "everything"}),
                           ("session_follow", {"since": "a", "view": "epistemic_map"})):
            with self.subTest(name=name, args=args), self.assertRaises(bridge.InvalidArguments):
                bridge.validate_arguments(name, args)

    def test_nanosecond_precision_and_bounds(self):
        good = {"from_ns": str(-(1 << 127)), "through_ns": str((1 << 127) - 1)}
        self.assertEqual(bridge.validate_arguments("query", good), good)
        for value in (1, "-0", "01", "+1", " 1", "1.0", "1e2", str(1 << 127), str(-(1 << 127) - 1)):
            with self.subTest(value=value), self.assertRaises(bridge.InvalidArguments):
                bridge.validate_arguments("query", {"from_ns": value})
        with self.assertRaises(bridge.InvalidArguments):
            bridge.validate_arguments("query", {"from_ns": "2", "through_ns": "1"})

    def test_utf8_budget_and_surrogates(self):
        for value in ("é" * 600, "\ud800", "x" * 1025, "x\0y", "x\x7fy"):
            with self.subTest(), self.assertRaises(bridge.InvalidArguments):
                bridge.validate_arguments("explain", {"event_id": value})


@unittest.skipUnless(os.name == "posix", "reference bridge is POSIX-only")
class RunnerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.executable = self.root / "fixture-fss"
        self.write_program('import json, sys\nprint(json.dumps({"argv":sys.argv[1:]}))\n')

    def write_program(self, program):
        self.executable.write_text(f"#!{sys.executable}\n" + program)
        self.executable.chmod(0o700)

    def config(self, **kwargs):
        return bridge.Config(self.executable, self.root, **kwargs)

    async def test_shell_metacharacters_are_data_and_scope_is_fixed(self):
        value = "--root=/elsewhere;$(touch /tmp/not-permitted)"
        result = await bridge.run_cli(self.config(), "explain", {"event_id": value})
        self.assertEqual(result["structuredContent"]["argv"], [
            "explain", "--json", f"--root={self.root}", "--principal=principal:local-mcp", f"--event-id={value}"])
        self.assertFalse(result["isError"])

    async def test_opaque_continuation_and_anchor_are_unchanged(self):
        result = await bridge.run_cli(self.config(), "session_follow", {
            "since": "fss:anchor:abc/==", "continuation": "cursor:ABC_-./=", "max_entries": 2})
        args = result["structuredContent"]["argv"]
        self.assertIn("--since=fss:anchor:abc/==", args)
        self.assertIn("--continuation=cursor:ABC_-./=", args)

    async def test_original_envelope_and_typed_error_are_preserved(self):
        raw = '{ "schema": "fss/1", "error": "ERR-AGENT-RESNAPSHOT-001", "coverage": "not_observable" }'
        self.write_program(f'import sys\nprint({raw!r})\nprint("secret-provider-string", file=sys.stderr)\nsys.exit(7)\n')
        result = await bridge.run_cli(self.config(), "query", {})
        self.assertTrue(result["isError"])
        self.assertEqual(result["content"][0]["text"], raw)
        self.assertEqual(result["structuredContent"], json.loads(raw))
        self.assertNotIn("secret-provider-string", json.dumps(result))
        self.assertEqual(result["_meta"]["fss/bridge"]["exitCode"], 7)

    async def test_environment_does_not_forward_secrets_or_loader_overrides(self):
        self.write_program('import os, json\nprint(json.dumps(dict(os.environ)))\n')
        from unittest.mock import patch
        with patch.dict(os.environ, {"SECRET_TEST_TOKEN": "private", "LD_PRELOAD": "/never"}):
            result = await bridge.run_cli(self.config(), "query", {})
        self.assertNotIn("SECRET_TEST_TOKEN", result["structuredContent"])
        self.assertNotIn("LD_PRELOAD", result["structuredContent"])

    async def test_malformed_output_is_not_forwarded(self):
        for raw in ('not JSON: secret', '[]', '{}', '{"a":1,"a":2}', '{"n":NaN}', '{"x":"\\ud800"}'):
            self.write_program(f'print({raw!r})\n')
            with self.subTest(raw=raw), self.assertRaisesRegex(bridge.BridgeError, "ERR-MCP-CLI-OUTPUT-001"):
                await bridge.run_cli(self.config(), "query", {})

    async def test_stdout_and_stderr_are_bounded_while_running(self):
        for stream in ("stdout", "stderr"):
            self.write_program(f'import sys\nwhile True: sys.{stream}.write("x" * 8192); sys.{stream}.flush()\n')
            with self.subTest(stream=stream), self.assertRaisesRegex(bridge.BridgeError, "ERR-MCP-OUTPUT-LIMIT-001"):
                await bridge.run_cli(self.config(output_bytes=1024, stderr_bytes=1024), "query", {})

    async def test_timeout(self):
        self.write_program('import time\ntime.sleep(30)\n')
        with self.assertRaisesRegex(bridge.BridgeError, "ERR-MCP-TIMEOUT-001"):
            await bridge.run_cli(self.config(timeout_seconds=0.05), "query", {})

    async def test_cancel_reaps_child(self):
        marker = self.root / "pid"
        self.write_program(f'import os, time\nopen({str(marker)!r}, "w").write(str(os.getpid()))\ntime.sleep(30)\n')
        task = asyncio.create_task(bridge.run_cli(self.config(), "query", {}))
        async with asyncio.timeout(5.0):
            while not marker.exists():
                if task.done():
                    await task  # Surface a startup failure rather than a false timeout.
                    self.fail("fixture exited before reporting its PID")
                await asyncio.sleep(0.01)
        pid = int(marker.read_text())
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_configuration_refuses_invalid_limits_and_relative_paths(self):
        for kwargs in ({"timeout_seconds": float("nan")}, {"timeout_seconds": 0},
                       {"output_bytes": True}, {"output_bytes": 100}, {"stderr_bytes": 100},
                       {"principal": "admin\nother"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(bridge.BridgeError):
                self.config(**kwargs)
        with self.assertRaises(bridge.BridgeError):
            bridge.Config(Path("relative"), self.root)



class ProtocolHarness(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = bridge.Config(Path(sys.executable).resolve(), self.root)
        self.reader = asyncio.StreamReader(limit=bridge.MAX_INPUT_BYTES)
        self.responses = asyncio.Queue()
        self.called = []
        self.release = asyncio.Event()

        async def runner(config, name, args):
            self.called.append((name, args))
            await self.release.wait()
            return {"content": [{"type": "text", "text": '{"ok":true}'}],
                    "structuredContent": {"ok": True}, "isError": False}

        async def send(raw):
            self.assertTrue(raw.endswith(b"\n"))
            self.assertEqual(raw.count(b"\n"), 1)
            await self.responses.put(json.loads(raw))

        self.server = bridge.Server(self.config, max_inflight=1, runner=runner)
        self.serving = asyncio.create_task(self.server.serve(self.reader, send))
        self.next_id = 1

    async def asyncTearDown(self):
        self.reader.feed_eof()
        await asyncio.wait_for(self.serving, 2)

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.reader.feed_data(json.dumps(msg).encode() + b"\n")

    def request(self, method, params=None, identity=None):
        if identity is None:
            identity = self.next_id
            self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": identity, "method": method}
        if params is not None:
            msg["params"] = params
        self.reader.feed_data(json.dumps(msg).encode() + b"\n")
        return identity

    async def response(self):
        return await asyncio.wait_for(self.responses.get(), 2)

    async def initialize(self, version="2025-11-25"):
        self.request("initialize", {"protocolVersion": version, "capabilities": {},
                                    "clientInfo": {"name": "test", "version": "1"}})
        result = await self.response()
        self.notify("notifications/initialized")
        return result


class ProtocolTests(ProtocolHarness):
    async def test_initialize_catalog_and_round_trip(self):
        init = await self.initialize()
        self.assertEqual(init["result"]["protocolVersion"], "2025-11-25")
        self.assertEqual(init["result"]["capabilities"], {"tools": {"listChanged": False}})
        self.request("tools/list")
        catalog = await self.response()
        self.assertEqual([t["name"] for t in catalog["result"]["tools"]], list(bridge.TOOL_SPECS))
        self.release.set()
        identity = self.request("tools/call", {"name": "explain", "arguments": {"event_id": "e:1"}})
        reply = await self.response()
        self.assertEqual(reply["id"], identity)
        self.assertEqual(reply["result"]["structuredContent"], {"ok": True})
        self.assertEqual(self.called, [("explain", {"event_id": "e:1"})])

    async def test_unsupported_legacy_version_negotiates_supported_version(self):
        self.assertEqual((await self.initialize("unknown"))["result"]["protocolVersion"], "2025-11-25")

    async def test_requires_initialized_notification(self):
        self.request("tools/list")
        self.assertEqual((await self.response())["error"]["code"], -32602)
        self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                    "clientInfo": {"name": "test", "version": "1"}})
        self.assertEqual((await self.response())["result"]["protocolVersion"], "2025-06-18")
        self.request("tools/list")
        self.assertEqual((await self.response())["error"]["code"], -32602)

    async def test_parse_error_and_recovery(self):
        self.reader.feed_data(b'{broken}\n')
        self.assertEqual((await self.response())["error"]["code"], -32700)
        self.request("ping")
        self.assertEqual((await self.response())["result"], {})

    async def test_notifications_never_execute_tools_or_get_replies(self):
        await self.initialize()
        self.notify("tools/call", {"name": "query", "arguments": {}})
        self.notify("unknown", {"data": "secret"})
        self.notify("notifications/cancelled", {"requestId": []})
        identity = self.request("ping")
        self.assertEqual((await self.response())["id"], identity)
        self.assertEqual(self.called, [])
        self.assertTrue(self.responses.empty())

    async def test_invalid_tools_and_scope_refused_before_execution(self):
        await self.initialize()
        for params, protocol in (({"name": "commit"}, True), ({"name": ["query"]}, True),
                                 ({"name": "query", "arguments": []}, True),
                                 ({"name": "query", "arguments": {"root": "/elsewhere"}}, False),
                                 ({"name": "explain", "arguments": {}}, False)):
            self.request("tools/call", params)
            reply = await self.response()
            if protocol:
                self.assertEqual(reply["error"]["code"], -32602)
            else:
                self.assertTrue(reply["result"]["isError"])
        self.assertEqual(self.called, [])

    async def test_cancelled_call_has_no_reply_and_ping_still_works(self):
        await self.initialize()
        identity = self.request("tools/call", {"name": "query"})
        for _ in range(100):
            if self.called:
                break
            await asyncio.sleep(0.001)
        self.assertTrue(self.called)
        self.notify("notifications/cancelled", {"requestId": identity})
        self.notify("notifications/cancelled", {"requestId": identity})
        ping = self.request("ping")
        self.assertEqual((await self.response())["id"], ping)
        self.release.set()
        await asyncio.sleep(0.01)
        self.assertEqual(self.server.jobs, {})
        self.assertTrue(self.responses.empty())

    async def test_concurrency_limit_does_not_queue_hidden_work(self):
        await self.initialize()
        self.request("tools/call", {"name": "query"})
        second = self.request("tools/call", {"name": "query"})
        reply = await self.response()
        self.assertEqual(reply["id"], second)
        self.assertEqual(reply["result"]["content"][0]["text"], "ERR-MCP-BUSY-001")
        self.assertLessEqual(len(self.called), 1)

    async def test_duplicate_id_closes_without_rebinding(self):
        await self.initialize()
        identity = self.request("tools/call", {"name": "query"})
        self.request("tools/call", {"name": "explain", "arguments": {"event_id": "other"}}, identity)
        reply = await self.response()
        self.assertIsNone(reply["id"])
        self.assertEqual(reply["error"]["code"], -32600)
        await asyncio.wait_for(self.serving, 2)
        self.assertTrue(all(name == "query" for name, _ in self.called))

    async def test_oversized_line_closes_and_never_executes_suffix(self):
        self.reader.feed_data(b"x" * (bridge.MAX_INPUT_BYTES + 1) + b"\n")
        self.request("ping")
        self.assertEqual((await self.response())["error"]["code"], -32600)
        await asyncio.wait_for(self.serving, 2)
        self.assertTrue(self.responses.empty())

    async def test_lists_have_no_silent_cursor_reset(self):
        await self.initialize()
        self.request("tools/list", {"cursor": "forged"})
        self.assertEqual((await self.response())["error"]["code"], -32602)

    async def test_boolean_null_and_compound_ids_are_invalid(self):
        for identity in (True, None, [], {}):
            self.reader.feed_data(json.dumps({"jsonrpc": "2.0", "id": identity, "method": "ping"}).encode() + b"\n")
            reply = await self.response()
            self.assertIsNone(reply["id"])
            self.assertEqual(reply["error"]["code"], -32600)

    async def test_eof_cancels_work(self):
        await self.initialize()
        self.request("tools/call", {"name": "query"})
        await asyncio.sleep(0.01)
        self.reader.feed_eof()
        await asyncio.wait_for(self.serving, 2)
        self.assertEqual(self.server.jobs, {})
        self.assertTrue(self.responses.empty())

    async def test_transport_error_is_not_an_authority_envelope(self):
        async def refusal(*args):
            raise bridge.BridgeError("ERR-MCP-TIMEOUT-001")
        self.server.runner = refusal
        await self.initialize()
        self.request("tools/call", {"name": "query"})
        result = (await self.response())["result"]
        self.assertTrue(result["isError"])
        self.assertNotIn("structuredContent", result)

    async def test_request_budget_is_bounded(self):
        self.server.request_count = bridge.MAX_REQUESTS
        self.request("ping", identity="over-budget")
        self.assertEqual((await self.response())["error"]["code"], -32900)
        await asyncio.wait_for(self.serving, 2)


class StdioTests(unittest.IsolatedAsyncioTestCase):
    async def test_executable_wire_protocol_and_eof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture-fss"
            fixture.write_text(f'#!{sys.executable}\nimport json, sys\nprint(json.dumps({{"argv":sys.argv[1:]}}))\n')
            fixture.chmod(0o700)
            process = await asyncio.create_subprocess_exec(
                sys.executable, str(SCRIPT), "--fss-binary", str(fixture), "--root", str(root),
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            async def send(message):
                process.stdin.write(json.dumps(message).encode() + b"\n")
                await process.stdin.drain()
            async def receive():
                return json.loads(await asyncio.wait_for(process.stdout.readline(), 3))
            try:
                await send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                    "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "wire-test", "version": "1"}}})
                self.assertEqual((await receive())["result"]["protocolVersion"], "2025-11-25")
                await send({"jsonrpc": "2.0", "method": "notifications/initialized"})
                await send({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                    "name": "session_orient", "arguments": {"view": "brief"}}})
                reply = await receive()
                self.assertEqual(reply["result"]["structuredContent"]["argv"][:3], ["session", "orient", "--json"])
                process.stdin.close()
                await asyncio.wait_for(process.wait(), 3)
                self.assertEqual(process.returncode, 0)
                self.assertEqual(await process.stderr.read(), b"")
                self.assertEqual(await process.stdout.read(), b"")
            finally:
                if process.returncode is None:
                    process.kill()
                    await process.wait()



class ModernProtocolTests(ProtocolHarness):
    """Per-request contexts stay independent of legacy initialization state."""

    def modern_params(self, **params):
        return {**params, "_meta": {
            bridge.PROTOCOL_VERSION_KEY: bridge.MODERN_VERSION,
            bridge.CLIENT_CAPABILITIES_KEY: {},
        }}

    async def test_modern_discovery_needs_no_initialization(self):
        self.request("server/discover", self.modern_params())
        result = (await self.response())["result"]
        self.assertEqual(result["resultType"], "complete")
        self.assertIn("2026-07-28", result["supportedVersions"])
        self.assertEqual(result["capabilities"], {"tools": {}})
        self.assertEqual(result["_meta"][bridge.SERVER_INFO_KEY], bridge.SERVER_INFO)
        self.assertIsNone(self.server.version)
        self.assertFalse(self.server.ready)

    async def test_modern_direct_tool_call_preserves_envelope(self):
        self.release.set()
        self.request("tools/call", self.modern_params(name="query", arguments={}))
        result = (await self.response())["result"]
        self.assertEqual(result["resultType"], "complete")
        self.assertEqual(result["structuredContent"], {"ok": True})
        self.assertNotIn("resultType", result["structuredContent"])

    async def test_modern_version_not_inherited_by_next_request(self):
        self.request("tools/list", self.modern_params())
        self.assertEqual((await self.response())["result"]["resultType"], "complete")
        self.request("tools/list")
        self.assertEqual((await self.response())["error"]["code"], -32602)
        self.request("tools/list", {"_meta": {bridge.CLIENT_CAPABILITIES_KEY: {}}})
        self.assertEqual((await self.response())["error"]["code"], -32602)

    async def test_modern_missing_capabilities_is_refused_before_io(self):
        self.request("tools/call", {"name": "query", "_meta": {bridge.PROTOCOL_VERSION_KEY: bridge.MODERN_VERSION}})
        self.assertEqual((await self.response())["error"]["code"], -32602)
        self.assertEqual(self.called, [])

    async def test_unsupported_modern_version_has_typed_negotiation_error(self):
        params = self.modern_params()
        params["_meta"][bridge.PROTOCOL_VERSION_KEY] = "2099-01-01"
        self.request("server/discover", params)
        error = (await self.response())["error"]
        self.assertEqual(error["code"], -32022)
        self.assertEqual(error["data"], {"requested": "2099-01-01", "supported": [bridge.MODERN_VERSION]})
        self.assertFalse(self.server.ready)

    async def test_both_eras_can_share_process_without_context_leak(self):
        await self.initialize()
        self.request("tools/list", self.modern_params())
        self.assertEqual((await self.response())["result"]["resultType"], "complete")
        self.request("tools/list")
        self.assertNotIn("resultType", (await self.response())["result"])

    async def test_modern_id_reuse_after_reply_is_allowed(self):
        for _ in range(3):
            self.request("ping", self.modern_params(), identity="reused-after-response")
            self.assertEqual((await self.response())["result"]["resultType"], "complete")
        self.assertFalse(self.server.stopping.is_set())

    async def test_modern_tool_error_keeps_complete_wrapper_without_fake_evidence(self):
        self.request("tools/call", self.modern_params(name="explain", arguments={}))
        result = (await self.response())["result"]
        self.assertEqual(result["resultType"], "complete")
        self.assertTrue(result["isError"])
        self.assertNotIn("structuredContent", result)
        self.assertEqual(self.called, [])

    async def test_modern_cancel_keeps_channel_usable(self):
        identity = self.request("tools/call", self.modern_params(name="query"))
        for _ in range(100):
            if self.called:
                break
            await asyncio.sleep(0.001)
        self.notify("notifications/cancelled", {"requestId": identity})
        ping = self.request("ping", self.modern_params())
        self.assertEqual((await self.response())["id"], ping)
        self.release.set()
        await asyncio.sleep(0.01)
        self.assertTrue(self.responses.empty())

    async def test_modern_malformed_metadata_is_not_accepted_as_legacy(self):
        await self.initialize()
        for meta in ([], {bridge.PROTOCOL_VERSION_KEY: bridge.MODERN_VERSION},
                     {bridge.PROTOCOL_VERSION_KEY: bridge.MODERN_VERSION, bridge.CLIENT_CAPABILITIES_KEY: [],},
                     {bridge.PROTOCOL_VERSION_KEY: bridge.MODERN_VERSION, bridge.CLIENT_CAPABILITIES_KEY: {}, bridge.CLIENT_INFO_KEY: "admin"}):
            self.request("tools/list", {"_meta": meta})
            self.assertEqual((await self.response())["error"]["code"], -32602)



class ShutdownTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_stdio_eof_and_sigterm_reap_running_cli(self):
        import signal
        for shutdown in ("eof", "sigterm"):
            with self.subTest(shutdown=shutdown), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                marker = root / "child-pid"
                fixture = root / "fixture-fss"
                fixture.write_text(f'#!{sys.executable}\nimport os, time\nopen({str(marker)!r}, "w").write(str(os.getpid()))\ntime.sleep(30)\n')
                fixture.chmod(0o700)
                process = await asyncio.create_subprocess_exec(
                    sys.executable, str(SCRIPT), "--fss-binary", str(fixture), "--root", str(root),
                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try:
                    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                        "name": "query", "_meta": {bridge.PROTOCOL_VERSION_KEY: bridge.MODERN_VERSION,
                                                   bridge.CLIENT_CAPABILITIES_KEY: {}}}}
                    process.stdin.write(json.dumps(request).encode() + b"\n")
                    await process.stdin.drain()
                    for _ in range(200):
                        if marker.exists():
                            break
                        await asyncio.sleep(0.01)
                    self.assertTrue(marker.exists())
                    pid = int(marker.read_text())
                    if shutdown == "eof":
                        process.stdin.close()
                    else:
                        process.send_signal(signal.SIGTERM)
                    await asyncio.wait_for(process.wait(), 3)
                    self.assertEqual(process.returncode, 0)
                    self.assertEqual(await process.stdout.read(), b"")
                    self.assertEqual(await process.stderr.read(), b"")
                    with self.assertRaises(ProcessLookupError):
                        os.kill(pid, 0)
                finally:
                    if process.returncode is None:
                        process.kill()
                        await process.wait()
                    if process.stdin is not None:
                        process.stdin.close()

    async def test_json_before_hung_exit_is_not_accepted_as_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture-fss"
            fixture.write_text(f'#!{sys.executable}\nimport os, time\nos.write(1, b\'{{"ok":true}}\\n\')\nos.close(1)\nos.close(2)\ntime.sleep(30)\n')
            fixture.chmod(0o700)
            config = bridge.Config(fixture, root, timeout_seconds=0.1)
            with self.assertRaisesRegex(bridge.BridgeError, "ERR-MCP-TIMEOUT-001"):
                await bridge.run_cli(config, "query", {})



class RetirementTests(ProtocolHarness):
    async def test_cancel_before_first_poll_releases_capacity(self):
        # Directly handle both frames without yielding to the newly created worker.
        self.server._send_bytes = lambda _: asyncio.sleep(0)
        params = {"name": "query", "_meta": {
            bridge.PROTOCOL_VERSION_KEY: bridge.MODERN_VERSION,
            bridge.CLIENT_CAPABILITIES_KEY: {}}}
        await self.server.handle(json.dumps({"jsonrpc": "2.0", "id": "early", "method": "tools/call", "params": params}).encode())
        self.server._cancel("early")
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self.assertEqual(self.server.jobs, {})
        self.assertEqual(self.server.tasks, set())
        self.assertEqual(self.called, [])

    async def test_reply_releases_id_before_local_drain(self):
        self.server.max_inflight = 2
        hold = asyncio.Event()
        first_reply = asyncio.Event()
        outputs = []

        async def send(raw):
            outputs.append(json.loads(raw))
            if len(outputs) == 1:
                first_reply.set()
                await hold.wait()

        self.server._send_bytes = send
        self.release.set()
        params = {"name": "query", "_meta": {
            bridge.PROTOCOL_VERSION_KEY: bridge.MODERN_VERSION,
            bridge.CLIENT_CAPABILITIES_KEY: {}}}
        raw = json.dumps({"jsonrpc": "2.0", "id": "reuse", "method": "tools/call", "params": params}).encode()
        # The first reply is visible to the client, but local write completion is
        # delayed. Reusing the now-completed modern ID must not rebind old cleanup.
        await self.server.handle(raw)
        await asyncio.wait_for(first_reply.wait(), 1)
        await self.server.handle(raw)
        hold.set()
        for _ in range(100):
            if len(outputs) == 2 and not self.server.tasks:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(len(outputs), 2)
        self.assertTrue(all("result" in result for result in outputs))
        self.assertEqual(self.server.jobs, {})
        self.assertEqual(self.server.tasks, set())
        self.assertFalse(self.server.stopping.is_set())

    async def test_shutdown_retires_unstarted_task(self):
        self.server._send_bytes = lambda _: asyncio.sleep(0)
        params = {"name": "query", "_meta": {
            bridge.PROTOCOL_VERSION_KEY: bridge.MODERN_VERSION,
            bridge.CLIENT_CAPABILITIES_KEY: {}}}
        await self.server.handle(json.dumps({"jsonrpc": "2.0", "id": "shutdown", "method": "tools/call", "params": params}).encode())
        self.server._cancel("shutdown")
        self.server.request_stop()
        await asyncio.wait_for(self.serving, 2)
        self.assertEqual(self.server.jobs, {})
        self.assertEqual(self.server.tasks, set())


if __name__ == "__main__":
    unittest.main()
