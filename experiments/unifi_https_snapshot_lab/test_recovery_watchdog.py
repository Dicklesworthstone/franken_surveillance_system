#!/usr/bin/env python3
"""Safety decisions for the temporary G4 recovery watchdog."""
import argparse
import hashlib
import http.client
import subprocess
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import recovery_watchdog as watchdog


class RecorderStateTests(unittest.TestCase):
    def test_journal_failure_is_unknown_and_never_requests_reboot(self):
        for failure in (subprocess.TimeoutExpired('journalctl', 30), OSError('unavailable')):
            with self.subTest(failure=type(failure).__name__), \
                 patch.object(watchdog.subprocess, 'run', side_effect=failure):
                self.assertEqual(watchdog.read_recorder_state(100), 'unknown')

    def test_last_relevant_startup_event_wins(self):
        offline = "Recorder startup failed: camera has not connected to the Scrypted controller emulator yet"
        started = "Continuous video recording started in protected staging"
        disk = "Recorder startup failed: insufficient storage"
        self.assertEqual(watchdog.recorder_state(""), "unknown")
        self.assertEqual(watchdog.recorder_state(offline), "unknown")
        self.assertEqual(watchdog.recorder_state(offline + "\n" + offline), "camera_offline")
        self.assertEqual(watchdog.recorder_state(offline + "\n" + started), "recording")
        self.assertEqual(watchdog.recorder_state(started + "\n" + offline), "unknown")
        self.assertEqual(watchdog.recorder_state(started + "\n" + offline + "\n" + offline), "camera_offline")
        self.assertEqual(watchdog.recorder_state(offline + "\n" + offline + "\n" + disk), "other_failure")

    def test_healthy_or_unknown_state_never_connects_to_camera(self):
        args = argparse.Namespace(since=100, camera="127.0.0.1")
        for state in ("recording", "unknown", "other_failure"):
            with self.subTest(state=state), patch.object(watchdog.time, "time", return_value=101), \
                 patch.object(watchdog, "read_recorder_state", return_value=state), \
                 patch.object(watchdog, "PinnedConnection") as connect:
                self.assertEqual(watchdog.recover(args), "recovery_abstained_recorder_state")
                connect.assert_not_called()

    def test_marker_cannot_be_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "marker"
            watchdog.create_marker(marker)
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                watchdog.create_marker(marker)

    def test_pin_is_checked_on_every_connect(self):
        pin = b"expected synthetic certificate"
        for actual, matches in ((pin, True), (b"wrong certificate", False)):
            fake_sock = SimpleNamespace(getpeercert=lambda **_: actual, close=lambda: None)
            with self.subTest(matches=matches), patch.object(
                http.client.HTTPSConnection, "connect", lambda connection: setattr(connection, "sock", fake_sock)
            ):
                connection = watchdog.PinnedConnection("127.0.0.1", pin)
                if matches:
                    connection.connect()
                    self.assertEqual(connection.pin, hashlib.sha256(pin).digest())
                else:
                    with self.assertRaises(RuntimeError):
                        connection.connect()

    def test_revalidates_before_marking_and_sends_at_most_one_reboot(self):
        class Response:
            status = 200
            def __init__(self, body=b"{}"):
                self.body = body
            def getheader(self, name, default=""):
                return "authId=synthetic" if name == "Set-Cookie" else default
            def read(self, _):
                return self.body

        class Connection:
            def __init__(self, controller):
                self.controller = controller
                self.requests = []
            def connect(self):
                self.requests.append("connect")
            def request(self, method, path, *args, **kwargs):
                self.requests.append(method + " " + path)
            def getresponse(self):
                if self.requests[-1] == "GET /api/1.1/settings":
                    return Response(('{"controller":{"addr":"' + self.controller + '"}}').encode())
                return Response()
            def close(self):
                pass

        args = argparse.Namespace(since=100, camera="127.0.0.1", controller="192.168.1.2",
                                  pin=Path("/pin"), credentials=Path("/credential"), marker=Path("/marker"))
        for controller, states, expected, reboot in (
            ("192.168.1.9", ["camera_offline"], "recovery_abstained_controller_changed", False),
            ("192.168.1.2", ["camera_offline", "recording"], "recovery_abstained_recorder_changed", False),
            ("192.168.1.2", ["camera_offline", "unknown"], "recovery_abstained_recorder_changed", False),
            ("192.168.1.2", ["camera_offline", "camera_offline"], "recovery_reboot_may_have_been_dispatched", True),
        ):
            fake = Connection(controller)
            with self.subTest(expected=expected), patch.object(watchdog.time, "time", return_value=101), \
                 patch.object(watchdog, "read_recorder_state", side_effect=states), \
                 patch.object(watchdog, "private_regular_file", side_effect=[b"synthetic pin", b'{"username":"fixture","password":"fixture"}']), \
                 patch.object(watchdog, "PinnedConnection", return_value=fake), \
                 patch.object(watchdog, "create_marker") as marker:
                self.assertEqual(watchdog.recover(args), expected)
                self.assertEqual(fake.requests.count("GET /api/1.1/reboot"), int(reboot))
                self.assertEqual(marker.call_count, int(reboot))


if __name__ == "__main__":
    unittest.main()
