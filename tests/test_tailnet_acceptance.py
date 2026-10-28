#!/usr/bin/env python3
"""Unit-test the tailnet acceptance harness (deliverables/scripts/tailnet_acceptance.py).

Covers every contract row against mock servers on loopback (no device, no
network), per docs/exploit/TAILSCALE-ENDSTATE.md §2:

  mock RTSP server      -> rtsp-port, rtsp-handshake, rtsp-frame (real ffmpeg
                           decodes an embedded 64x64 H264 I-frame)
  mock ONVIF/HTTP       -> onvif-capabilities (GetCapabilities shape),
                           onvif-device-info (GetDeviceInformation + --expect-model
                           identity gate, negative: wrong model must FAIL),
                           http-control
  fake ssh shim         -> tailscaled-status (node+peers pass; rc!=0 and
                           single-peer outputs FAIL)
  resolution            -> tailnet-bind row behaviour with no tailscale interface

  python3 tests/test_tailnet_acceptance.py
"""
from __future__ import annotations

import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "deliverables" / "scripts" / "tailnet_acceptance.py"
spec = importlib.util.spec_from_file_location("tailnet_acceptance", SCRIPT)
ta = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ta)

FAILURES: list[str] = []


def check(cond: bool, what: str) -> None:
    print(("  PASS  " if cond else "  FAIL  ") + what)
    if not cond:
        FAILURES.append(what)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class MockStack:
    """RTSP + HTTP mock on free ports, plus the fake-ssh shim."""

    def __init__(self) -> None:
        self.rtsp_port = free_port()
        self.http_port = free_port()
        self.server = ta.MockServer(self.rtsp_port, self.http_port)
        self.server.start()
        assert self.server.ready.wait(timeout=3)
        # fake ssh shim: parameterized output via env
        self.ssh_shim = Path(tempfile.mkdtemp()) / "fake-ssh.sh"
        self.ssh_shim.write_text(
            "#!/bin/sh\n"
            'if [ -n "$FAKE_SSH_FAIL" ]; then echo "ssh: connection refused" >&2; exit 255; fi\n'
            'if [ -n "$FAKE_SSH_SOLO" ]; then echo "wyze-424\\tactive\\tdirect 1.2.3.4:41641"; exit 0; fi\n'
            'echo "wyze-424       active     direct 1.2.3.4:41641";\n'
            'echo "peer-node      active     relay \\"tailnet\\"";\n'
            "exit 0\n"
        )
        os.chmod(self.ssh_shim, 0o755)
        # fake sftp shim: real filesystem round-trip of the put/get/rm batch
        self.sftp_shim = self.ssh_shim.parent / "fake-sftp.sh"
        self.sftp_shim.write_text(
            "#!/bin/sh\n"
            "batch=$(cat)\n"
            'echo "$batch" | while IFS= read -r line; do\n'
            '  case "$line" in\n'
            '    put\\ *) set -- $line; cp "$2" "$3" ;;\n'
            '    get\\ *) set -- $line; cp "$2" "$3" ;;\n'
            '    rm\\ *) set -- $line; rm -f "$2" ;;\n'
            "  esac\n"
            "done\n"
            'if [ -n "$FAKE_SFTP_FAIL" ]; then echo "sftp: subystem failed" >&2; exit 1; fi\n'
            "exit 0\n"
        )
        os.chmod(self.sftp_shim, 0o755)

    def stop(self) -> None:
        self.server.stop_flag = True
        time.sleep(0.3)


def main() -> int:
    print("== tailnet_acceptance unit tests (mock servers on loopback)")
    stack = MockStack()
    try:
        time.sleep(0.1)

        # --- positive: every row passes against the mocks
        rows, all_pass = ta.run_contract(
            "127.0.0.1", stack.rtsp_port, stack.http_port, stack.http_port,
            timeout=5.0, require_tailnet_bind=False,
            expect_model="wyze_cam4", ssh_user="root",
            ssh_cmd=str(stack.ssh_shim), want_sftp=True,
            sftp_cmd=str(stack.sftp_shim),
        )
        by_row = {r["row"]: r for r in rows}
        check(all_pass, "all rows pass against mocks")
        check(len(rows) == 10, "exactly 10 contract rows, got %d" % len(rows))
        for row in ("rtsp-port", "rtsp-handshake", "rtsp-frame", "onvif-capabilities",
                    "onvif-device-info", "onvif-profile-s", "http-control",
                    "tailscaled-status", "dropbear-sftp", "tailnet-bind"):
            check(row in by_row and by_row[row]["pass"], "row %s PASS" % row)
        check("decoded" in by_row["rtsp-frame"]["detail"],
              "rtsp-frame detail reports a decoded frame")
        check("thingino" in by_row["onvif-device-info"]["detail"],
              "device-info detail carries Manufacturer=thingino")
        check("H264" in by_row["onvif-profile-s"]["detail"],
              "profile-s detail reports H264 encoder binding")
        check("round-trip" in by_row["dropbear-sftp"]["detail"],
              "sftp detail reports put+get round-trip")
        check("peer lines" in by_row["tailscaled-status"]["detail"],
              "tailscaled-status detail reports peers")

        # --- negative: wrong expected model must fail the identity gate
        rows, all_pass = ta.run_contract(
            "127.0.0.1", stack.rtsp_port, stack.http_port, stack.http_port,
            timeout=5.0, require_tailnet_bind=False,
            expect_model="tapo_c660", ssh_user=None,
        )
        di = next(r for r in rows if r["row"] == "onvif-device-info")
        check(not di["pass"] and "tapo_c660" in di["detail"],
              "onvif-device-info FAILS when Model misses --expect-model")
        ts = next(r for r in rows if r["row"] == "tailscaled-status")
        check(not ts["pass"] and "skipped" in ts["detail"],
              "tailscaled-status is an explicit skip without --ssh-user")
        sf = next(r for r in rows if r["row"] == "dropbear-sftp")
        check(not sf["pass"] and "skipped" in sf["detail"],
              "dropbear-sftp is an explicit skip without --ssh-user/--sftp")

        # --- sftp failure mode via the shim
        os.environ["FAKE_SFTP_FAIL"] = "1"
        ok, detail = ta.sftp_row("127.0.0.1", 22, "root", 5.0,
                                 sftp_cmd=str(stack.sftp_shim))
        check(not ok and "rc=1" in detail, "dropbear-sftp FAILS on shim rc!=0")
        del os.environ["FAKE_SFTP_FAIL"]

        # --- tailscaled-status failure modes via the shim
        env_backup = dict(os.environ)
        os.environ["FAKE_SSH_FAIL"] = "1"
        ok, detail = ta.tailscaled_status_row("127.0.0.1", 22, "root", 5.0,
                                              ssh_cmd=str(stack.ssh_shim))
        check(not ok and "rc=255" in detail, "tailscaled-status FAILS on ssh rc!=0")
        del os.environ["FAKE_SSH_FAIL"]
        os.environ["FAKE_SSH_SOLO"] = "1"
        ok, detail = ta.tailscaled_status_row("127.0.0.1", 22, "root", 5.0,
                                              ssh_cmd=str(stack.ssh_shim))
        check(not ok and "no peers" in detail,
              "tailscaled-status FAILS when status lists no peers")
        os.environ.clear()
        os.environ.update(env_backup)

        # --- tailnet-bind: no tailscale interface on this host -> row must be
        #     pass with 'tailscale addrs none' only when binding is not required
        ok, detail = ta.tailscale_addrs() is not None, ""
        rows, _ = ta.run_contract(
            "127.0.0.1", stack.rtsp_port, stack.http_port, stack.http_port,
            timeout=5.0, require_tailnet_bind=False, ssh_user=None,
        )
        bind = next(r for r in rows if r["row"] == "tailnet-bind")
        check("tailscale addrs" in bind["detail"], "tailnet-bind row reports resolution + addrs")

        # --- rtsp-frame against a CLOSED port must fail cleanly (no hang)
        closed = free_port()
        t0 = time.monotonic()
        ok, detail = ta.rtsp_frame_row("127.0.0.1", closed, 3.0)
        elapsed = time.monotonic() - t0
        check(not ok and elapsed < 15.0,
              "rtsp-frame fails bounded (%.1fs) on a closed port: %s" % (elapsed, detail[:60]))

        # --- malformed ONVIF answer must fail, not crash
        ok, detail = ta.onvif_device_info_row("127.0.0.1", closed, 2.0)
        check(not ok, "onvif-device-info fails cleanly on a closed port")
    finally:
        stack.stop()

    print("verdict: %s" % ("PASS" if not FAILURES else "FAIL %d" % len(FAILURES)))
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    sys.exit(main())
