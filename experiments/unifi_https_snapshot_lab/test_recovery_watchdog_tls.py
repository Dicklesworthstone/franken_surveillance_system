#!/usr/bin/env python3
"""Loopback TLS and durable-marker tests for the transitional watchdog.

The recorder-state source is controlled by the fixture; the HTTP transport,
certificate check, private files, and exclusive marker are real. No camera,
systemd unit, or existing credential is accessed.
"""

import argparse
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import recovery_watchdog as watchdog
from fixture import request


class Camera:
    def __init__(self, cert, key, controller, marker, drop_on_reboot):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(5)
        self.port = self.listener.getsockname()[1]
        self.controller = controller
        self.marker = marker
        self.drop_on_reboot = drop_on_reboot
        self.requests = []
        self.errors = []
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()

    def serve(self):
        try:
            raw, _ = self.listener.accept()
            with raw, self.context.wrap_socket(raw, server_side=True) as peer:
                peer.settimeout(5)
                while True:
                    try:
                        line, headers, body = request(peer)
                    except RuntimeError as error:
                        if str(error) == "invalid fixture request":
                            break  # Normal client close, including a rejected pin.
                        raise
                    self.requests.append(line)
                    if line == b"POST /api/1.1/login HTTP/1.1":
                        if json.loads(body) != {"username": "fixture", "password": "fixture"}:
                            raise ValueError("fixture login mismatch")
                        payload = b"{}"
                        cookie = b"Set-Cookie: authId=fixture; Path=/\r\n"
                    elif line == b"GET /api/1.1/settings HTTP/1.1":
                        if headers.get(b"cookie") != b"authId=fixture":
                            raise ValueError("fixture cookie mismatch")
                        payload = json.dumps({"controller": {"addr": self.controller}}).encode()
                        cookie = b""
                    elif line == b"GET /api/1.1/reboot HTTP/1.1":
                        if headers.get(b"cookie") != b"authId=fixture":
                            raise ValueError("fixture cookie mismatch")
                        if not self.marker.is_file() or self.marker.stat().st_mode & 0o777 != 0o600:
                            raise ValueError("reboot arrived before private marker")
                        if self.drop_on_reboot:
                            break
                        payload = b"{}"
                        cookie = b""
                    else:
                        raise ValueError("unexpected fixture request")
                    peer.sendall(b"HTTP/1.1 200 OK\r\n" + cookie + b"Content-Length: "
                                 + str(len(payload)).encode() + b"\r\n\r\n" + payload)
        except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
            # A rejected certificate may close the local connection abruptly.
            pass
        except Exception as error:
            self.errors.append(type(error).__name__)
        finally:
            self.listener.close()

    def finish(self):
        self.thread.join(timeout=8)
        if self.thread.is_alive() or self.errors:
            raise AssertionError("loopback camera did not finish cleanly")


class RecoveryTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="fss-recovery-tls-")
        cls.root = Path(cls.temp.name)
        cls.cert, cls.key, cls.der = (cls.root / name for name in ("cert.pem", "key.pem", "cert.der"))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-keyout", str(cls.key), "-out", str(cls.cert), "-days", "1", "-subj", "/CN=localhost"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "x509", "-in", str(cls.cert), "-outform", "der", "-out", str(cls.der)], check=True)
        os.chmod(cls.der, 0o600)
        cls.credential = cls.root / "credential.json"
        cls.credential.write_text('{"username":"fixture","password":"fixture"}')
        os.chmod(cls.credential, 0o600)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def exercise(self, name, controller, states, expected, *, wrong_pin=False, existing_marker=False, drop_on_reboot=False):
        marker = self.root / (name + ".marker")
        if existing_marker:
            watchdog.create_marker(marker)
        pin = self.der
        if wrong_pin:
            pin = self.root / "wrong.der"
            pin.write_bytes(b"synthetic wrong certificate")
            os.chmod(pin, 0o600)
        camera = Camera(str(self.cert), str(self.key), controller, marker, drop_on_reboot)
        original = watchdog.PinnedConnection

        class LocalPinned(original):
            def __init__(self, host, certificate):
                super().__init__(host, certificate)
                self.port = camera.port

        args = argparse.Namespace(since=int(time.time()) - 1, camera="127.0.0.1", controller="127.0.0.2",
                                  pin=pin, credentials=self.credential, marker=marker)
        try:
            with patch.object(watchdog, "read_recorder_state", side_effect=states), \
                 patch.object(watchdog, "PinnedConnection", LocalPinned):
                if expected is RuntimeError or expected is FileExistsError:
                    with self.assertRaises(expected):
                        watchdog.recover(args)
                else:
                    self.assertEqual(watchdog.recover(args), expected)
        finally:
            camera.finish()
        return marker, camera.requests

    def test_wrong_pin_refuses_before_login(self):
        marker, requests = self.exercise("pin", "127.0.0.2", ["camera_offline"], RuntimeError, wrong_pin=True)
        self.assertFalse(marker.exists())
        self.assertEqual(requests, [])

    def test_different_controller_abstains(self):
        marker, requests = self.exercise("controller", "127.0.0.3", ["camera_offline"], "recovery_abstained_controller_changed")
        self.assertFalse(marker.exists())
        self.assertEqual(len(requests), 2)

    def test_recorder_recovery_abstains(self):
        marker, requests = self.exercise("state", "127.0.0.2", ["camera_offline", "recording"], "recovery_abstained_recorder_changed")
        self.assertFalse(marker.exists())
        self.assertEqual(len(requests), 2)

    def test_one_reboot_requires_durable_marker(self):
        marker, requests = self.exercise("once", "127.0.0.2", ["camera_offline", "camera_offline"], "recovery_reboot_may_have_been_dispatched")
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        self.assertEqual(requests.count(b"GET /api/1.1/reboot HTTP/1.1"), 1)

    def test_existing_marker_prevents_reboot(self):
        marker, requests = self.exercise("existing", "127.0.0.2", ["camera_offline", "camera_offline"], FileExistsError, existing_marker=True)
        self.assertTrue(marker.exists())
        self.assertEqual(requests.count(b"GET /api/1.1/reboot HTTP/1.1"), 0)

    def test_dropped_reboot_response_keeps_the_one_shot_marker(self):
        marker, requests = self.exercise("drop", "127.0.0.2", ["camera_offline", "camera_offline"],
                                         "recovery_reboot_may_have_been_dispatched", drop_on_reboot=True)
        self.assertTrue(marker.exists())
        self.assertEqual(requests.count(b"GET /api/1.1/reboot HTTP/1.1"), 1)


if __name__ == "__main__":
    unittest.main()
