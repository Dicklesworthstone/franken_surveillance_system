#!/usr/bin/env python3
"""Orchestration tests for deliverables/scripts/tapo_sweep_run.sh.

The runner's job is the part a person forgets under a 17 h walk: notice that the unit rebooted
(mmap_base re-randomises, so the walk is void) and start again from the top, without ever poking an
absent camera. The device is stubbed through ARP_CMD / PING_CMD / HARNESS.
"""
from __future__ import annotations

import os
import pathlib
import stat
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNNER = ROOT / "deliverables" / "scripts" / "tapo_sweep_run.sh"
MAC = "50:3d:d1:e3:e2:07"
HOST = "192.168.4.33"


class RunnerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.log = self.dir / "sweep.log"
        self.uptime = self.dir / "sweep.uptime"
        # One queue token per *presence check*: arp consumes the token and publishes it, ping reads
        # it back, so a check costs exactly one token.
        self.queue = self.dir / "queue"
        self.queue.write_text("")
        self.n = self.dir / "n"
        self.n.write_text("0")
        self.cur = self.dir / "cur"
        self.arp = self._script("arp", f"""#!/bin/bash
n=$(cat {self.n}); n=$((n + 1)); echo $n > {self.n}
tok=$(sed -n "${{n}}p" {self.queue})
echo "$tok" > {self.cur}
if [ "$tok" = up ]; then echo "? ({HOST}) at 50:3d:d1:e3:e2:7 on en0 ifscope [ethernet]"; fi
""")
        self.ping = self._script("ping", f"""#!/bin/bash
[ "$(cat {self.cur} 2>/dev/null)" = up ] && {{ echo "64 bytes: time=1.2 ms"; exit 0; }}
exit 1
""")
        # sudo resets the environment, so the harness reads its config from a file
        self.calls = self.dir / "calls"
        self.calls.write_text("0")
        self.shell_at = self.dir / "shell_at"
        self.shell_at.write_text("0")
        self.harness = self._script("harness.py", f"""#!/usr/bin/env python3
n = int(open("{self.calls}").read() or 0) + 1
open("{self.calls}", "w").write(str(n))
print("addr guess")
print("SHELL on 192.168.4.33:4444" if open("{self.shell_at}").read().strip() == str(n)
      else '{{"raw": ""}} no shell; DECODE-BUFFER zone likely')
""")

    def _script(self, name: str, body: str) -> pathlib.Path:
        p = self.dir / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
        return p

    def run_sweep(self, queue: str, **env: str) -> subprocess.CompletedProcess:
        self.queue.write_text(queue)
        e = dict(os.environ, ARP_CMD=str(self.arp), PING_CMD=str(self.ping),
                 HARNESS=str(self.harness), LOG=str(self.log),
                 UPTIME=str(self.uptime), SETTLE="0", GAP_S="25",
                 START="0xb7000000", END="0xb6fff000", STEP="0x400", **env)
        return subprocess.run(["bash", str(RUNNER)], env=e, capture_output=True, text=True,
                              timeout=120)

    def test_walks_down_and_exhausts(self) -> None:
        res = self.run_sweep("up\n" * 40)
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("range exhausted", res.stdout)
        self.assertEqual(self.calls.read_text(), "4")  # 0xb7000000..0xb6fff400, END exclusive

    def test_shell_stops_the_walk(self) -> None:
        self.shell_at.write_text("2")
        res = self.run_sweep("up\n" * 40)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("SHELL at", res.stdout)
        self.assertEqual(self.calls.read_text(), "2")

    def test_reboot_restarts_from_the_top(self) -> None:
        # up, up, then absent for the next probe, then back
        res = self.run_sweep("up\nup\ndown\ndown\n" + "up\n" * 40, MAX_WAIT="12")
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("REBOOT detected", res.stdout)
        # after the restart the first address is probed again
        self.assertIn("addr=0xb7000000", res.stdout)
        self.assertGreaterEqual(res.stdout.count("addr=0xb7000000"), 2)

    def test_absent_unit_is_never_poked(self) -> None:
        res = self.run_sweep("down\n" * 10, MAX_WAIT="0")
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertEqual(self.calls.read_text(), "0")
        self.assertIn("ABSENT", res.stdout)

    def test_second_sweeper_is_refused(self) -> None:
        self.queue.write_text("up\n" * 200)
        e = dict(os.environ, ARP_CMD=str(self.arp), PING_CMD=str(self.ping),
                 HARNESS=str(self.harness), LOG=str(self.log), UPTIME=str(self.uptime),
                 SETTLE="1", START="0xb7000000", END="0xb6f00000", STEP="0x400")
        first = subprocess.Popen(["bash", str(RUNNER)], env=e,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(50):
                if (self.dir / "calls").read_text() != "0":
                    break
                import time as _t
                _t.sleep(0.1)
            second = subprocess.run(["bash", str(RUNNER)], env=e, capture_output=True, text=True,
                                    timeout=30)
            self.assertEqual(second.returncode, 5, second.stdout + second.stderr)
            self.assertIn("another sweep is running", second.stderr)
        finally:
            first.terminate()
            first.wait(timeout=10)

    def test_uptime_pattern_is_recorded(self) -> None:
        self.run_sweep("up\nup\ndown\nup\n" + "up\n" * 40, MAX_WAIT="12")
        text = self.uptime.read_text()
        self.assertIn("present icmp=yes rtt=", text)
        self.assertIn("absent", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
