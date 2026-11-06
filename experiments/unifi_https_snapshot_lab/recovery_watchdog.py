#!/usr/bin/env python3
"""One-shot recovery for the temporary owner-authorized G4 laboratory trial.

This is a transitional host watchdog, not an FSS production camera owner.
It never retries a reboot: a private, durable marker is created before the
request. Unknown recorder errors and controller claims cause abstention.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import ssl
import stat
import subprocess
import time

MAX_BODY = 1024 * 1024
RECORDING = "Continuous video recording started in protected staging"
START_FAILED = "Recorder startup failed:"
CAMERA_OFFLINE = "has not connected to the Scrypted controller emulator yet"


def recorder_state(lines: str) -> str:
    """Classify the last relevant startup event, never its private contents."""
    state = "unknown"
    consecutive_offline = 0
    for line in lines.splitlines():
        if RECORDING in line:
            state = "recording"
            consecutive_offline = 0
        elif START_FAILED in line:
            if CAMERA_OFFLINE in line:
                consecutive_offline += 1
                state = "camera_offline" if consecutive_offline >= 2 else "unknown"
            else:
                state = "other_failure"
                consecutive_offline = 0
    return state


def read_recorder_state(since: int) -> str:
    try:
        result = subprocess.run(
            ["/usr/bin/journalctl", "-u", "unifi-g4-recorder.service", "--since",
             f"@{since}", "--no-pager", "-n", "100", "-o", "cat"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        # A slow or inaccessible journal is not evidence that a reboot is safe.
        return "unknown"
    return recorder_state(result.stdout.decode("utf-8", "replace"))


class PinnedConnection(http.client.HTTPSConnection):
    """Check the exact observed certificate before every connection is used."""

    def __init__(self, host: str, pin: bytes):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        super().__init__(host, 443, context=context, timeout=8)
        self.pin = hashlib.sha256(pin).digest()

    def connect(self) -> None:
        super().connect()
        if self.sock is None or hashlib.sha256(self.sock.getpeercert(binary_form=True)).digest() != self.pin:
            self.close()
            raise RuntimeError("camera pin mismatch")


def read_body(response: http.client.HTTPResponse) -> bytes:
    body = response.read(MAX_BODY + 1)
    if len(body) > MAX_BODY:
        raise RuntimeError("camera response too large")
    return body


def private_regular_file(path: Path) -> bytes:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
            or info.st_uid != os.geteuid() or info.st_size > 16384):
        raise RuntimeError("invalid private input")
    return path.read_bytes()


def create_marker(path: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        message = b"reboot may have been dispatched; do not retry automatically\n"
        if os.write(fd, message) != len(message):
            raise OSError("incomplete recovery marker")
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def recover(args: argparse.Namespace) -> str:
    now = int(time.time())
    if args.since > now or now - args.since > 3600:
        return "recovery_abstained_invalid_window"
    if read_recorder_state(args.since) != "camera_offline":
        return "recovery_abstained_recorder_state"

    pin = private_regular_file(args.pin)
    connection = PinnedConnection(args.camera, pin)
    connection.connect()  # Pin before reading credentials.
    try:
        credential = json.loads(private_regular_file(args.credentials))
        if not isinstance(credential, dict) or not all(isinstance(credential.get(k), str) for k in ("username", "password")):
            raise RuntimeError("invalid credential")
        body = json.dumps({"username": credential["username"], "password": credential["password"]})
        connection.request("POST", "/api/1.1/login", body, {"Content-Type": "application/json"})
        response = connection.getresponse()
        cookie = response.getheader("Set-Cookie", "").split(";", 1)[0]
        read_body(response)
        if response.status != 200 or not cookie.startswith("authId="):
            raise RuntimeError("camera login refused")

        connection.request("GET", "/api/1.1/settings", headers={"Cookie": cookie})
        response = connection.getresponse()
        settings = json.loads(read_body(response))
        if response.status != 200 or not isinstance(settings, dict):
            raise RuntimeError("camera settings unavailable")
        controller = settings.get("controller")
        if not isinstance(controller, dict) or controller.get("addr") != args.controller:
            return "recovery_abstained_controller_changed"
        if read_recorder_state(args.since) != "camera_offline":
            return "recovery_abstained_recorder_changed"

        # The marker is the durable one-shot boundary. A failure afterward is
        # indeterminate and must not cause an automatic replay.
        create_marker(args.marker)
        try:
            connection.request("GET", "/api/1.1/reboot", headers={"Cookie": cookie})
            response = connection.getresponse()
            read_body(response)
        except (OSError, http.client.HTTPException):
            pass  # The camera commonly drops its connection during reboot.
        return "recovery_reboot_may_have_been_dispatched"
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--camera", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--pin", type=Path, required=True)
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--marker", type=Path, required=True)
    parser.add_argument("--since", type=int, required=True)
    parser.add_argument("--owner-authorized", action="store_true", required=True)
    args = parser.parse_args()
    if not all(p.is_absolute() for p in (args.pin, args.credentials, args.marker)):
        parser.error("paths must be absolute")
    try:
        for text in (args.camera, args.controller):
            address = ipaddress.IPv4Address(text)
            if address.is_unspecified or address.is_multicast or not (address.is_private or address.is_link_local or address.is_loopback):
                raise ValueError("address outside local scope")
        parent = args.marker.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o077 or parent.st_uid != os.geteuid():
            raise ValueError("marker directory must be private")
        print(recover(args))
        return 0
    except Exception:
        # Never include exception text, camera responses, cookies or credentials.
        print("recovery_failed_or_indeterminate")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
