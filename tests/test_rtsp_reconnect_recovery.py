#!/usr/bin/env python3
"""Native process recovery after a real, owner-scoped loopback AVC reconnect.

Usage: python3 tests/test_rtsp_reconnect_recovery.py /path/to/fss-capture-rtsp
No third-party Python packages, network services, credentials, or media executables.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

REPOSITORY = Path(__file__).resolve().parents[1]
RECOVERY = "fss.rtsp_reconnect_recovery_cli.v1"
BINARY = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else None
OUTPUT_LIMIT = 2 * 1024 * 1024
SDP = (
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\n"
    "a=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n"
    "a=fmtp:96 packetization-mode=1;sprop-parameter-sets="
    "Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\na=control:trackID=0\r\n"
)


def run(arguments: list[str]) -> tuple[int, bytes, bytes]:
    if BINARY is None or not BINARY.is_file():
        raise RuntimeError("pass the built native fss-capture-rtsp executable")
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(
            [str(BINARY), *arguments], stdin=subprocess.DEVNULL,
            stdout=stdout, stderr=stderr,
        )
        deadline = time.monotonic() + 20
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline or any(
                    os.fstat(stream.fileno()).st_size > OUTPUT_LIMIT
                    for stream in (stdout, stderr)
                ):
                    raise RuntimeError("native recovery exceeded process/output bound")
                time.sleep(0.01)
            result = []
            for stream in (stdout, stderr):
                stream.seek(0)
                data = stream.read(OUTPUT_LIMIT + 1)
                if len(data) > OUTPUT_LIMIT:
                    raise RuntimeError("oversized native output")
                result.append(data)
            return process.returncode, result[0], result[1]
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)


def successful(arguments: list[str]) -> bytes:
    code, stdout, stderr = run(arguments)
    if code:
        raise AssertionError(f"native exit={code}; stdout={stdout!r}; stderr={stderr!r}")
    return stdout


def packets(pictures: int) -> list[bytes]:
    raw = (REPOSITORY / "crates/fss-packet/tests/fixtures/avc/baseline.264").read_bytes()
    starts = []
    at = 0
    while at + 3 <= len(raw):
        width = 4 if raw[at:at + 4] == b"\x00\x00\x00\x01" else (
            3 if raw[at:at + 3] == b"\x00\x00\x01" else 0
        )
        if width:
            starts.append((at, at + width))
            at += width
        else:
            at += 1
    output = []
    seen = 0
    for index, (_, begin) in enumerate(starts):
        if seen == pictures:
            break
        end = starts[index + 1][0] if index + 1 < len(starts) else len(raw)
        nal = raw[begin:end].rstrip(b"\x00")
        if not nal or nal[0] & 31 not in (1, 5, 6, 7, 8):
            continue
        is_picture = nal[0] & 31 in (1, 5)
        rtp = bytes([0x80, 96 | (128 if is_picture else 0)])
        rtp += (len(output) + 1).to_bytes(2, "big")
        rtp += (9000 + seen * 3600).to_bytes(4, "big") + (7).to_bytes(4, "big") + nal
        output.append(rtp)
        seen += int(is_picture)
    if seen != pictures:
        raise AssertionError("pinned AVC fixture lacks requested pictures")
    return output


def request(peer: socket.socket, deadline: float) -> tuple[str, int] | None:
    raw = bytearray()
    while len(raw) < 8192:
        if time.monotonic() >= deadline:
            raise TimeoutError("camera request lifetime exceeded")
        part = peer.recv(1)
        if not part:
            if raw:
                raise AssertionError("client closed mid-request")
            return None
        raw += part
        if raw.endswith(b"\r\n\r\n"):
            text = raw.decode("ascii")
            if "authorization:" in text.lower():
                raise AssertionError("unexpected authentication in public fixture")
            cseq = [line.split(":", 1)[1].strip() for line in text.split("\r\n")
                    if line.lower().startswith("cseq:")]
            if len(cseq) != 1:
                raise AssertionError("missing/ambiguous CSeq")
            return text.split()[0], int(cseq[0])
    raise AssertionError("oversized camera control request")


def response(peer: socket.socket, sequence: int, headers: str = "", body: str = "") -> None:
    peer.sendall((f"RTSP/1.0 200 OK\r\nCSeq: {sequence}\r\n"
                  f"Content-Length: {len(body)}\r\n{headers}\r\n{body}").encode("ascii"))


def camera(listener: socket.socket, errors: list[BaseException]) -> None:
    deadline = time.monotonic() + 25
    try:
        for pictures in (1, 2):
            with listener.accept()[0] as peer:
                peer.settimeout(5)
                for expected in ("DESCRIBE", "SETUP", "PLAY"):
                    item = request(peer, deadline)
                    if item is None or item[0] != expected:
                        raise AssertionError(f"expected {expected}, got {item}")
                    if expected == "DESCRIBE":
                        response(peer, item[1], "Content-Type: application/sdp\r\n", SDP)
                    elif expected == "SETUP":
                        response(peer, item[1], "Session: fixture;timeout=60\r\n"
                                 "Transport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n")
                    else:
                        response(peer, item[1], "Session: fixture\r\n")
                for packet in packets(pictures):
                    peer.sendall(b"$\x00" + len(packet).to_bytes(2, "big") + packet)
                if pictures == 1:
                    peer.shutdown(socket.SHUT_WR)
                for _ in range(16):
                    item = request(peer, deadline)
                    if item is None:
                        break
                    if item[0] not in ("OPTIONS", "GET_PARAMETER", "TEARDOWN"):
                        raise AssertionError(f"unexpected control {item}")
                    response(peer, item[1], "Session: fixture\r\n")
                else:
                    raise AssertionError("camera control allowance exhausted")
    except BaseException as error:
        errors.append(error)


def arguments(root: Path, port: int) -> list[str]:
    values = {
        "root": str(root / "capture"), "pins": str(root / "pins"),
        "peer": f"127.0.0.1:{port}", "authority": f"127.0.0.1:{port}",
        "presentation": "/live/", "control-root": "/live",
        "sensor-id": "sensor:recovery", "stream-id": "stream:recovery",
        "generation": "7", "ingress": "71", "ssrc": "7",
        "frame-duration-ticks": "3600", "stop-after-pictures": "2",
        "owner-authorized": "yes", "plaintext": "yes", "retain-originals": "yes",
        "max-attempts": "3", "retry-delay-ms": "5", "retry-max-delay-ms": "10",
        "timeout-ms": "5000", "drain-timeout-ms": "5000", "max-report-bytes": "131072",
    }
    for key in ("anchor", "receive-clock", "timing-evidence", "journal-id"):
        values[key] = "sha256:" + hashlib.sha256(key.encode()).hexdigest()
    return ["reconnect", *[part for key, value in values.items() for part in ("--" + key, value)]]


def inventory(root: Path) -> dict[str, str]:
    entries = sorted(root.rglob("*"))
    if len(entries) > 4096:
        raise AssertionError("fixture inventory exceeded its bound")
    result = {}
    for path in entries:
        if path.is_symlink():
            raise AssertionError("unexpected symlink in native fixture")
        if path.is_file():
            if path.stat().st_size > 4 * 1024 * 1024:
                raise AssertionError("fixture object exceeded its byte bound")
            result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


class RecoveryProcess(unittest.TestCase):
    def test_capture_then_offline_recovery_does_not_reconnect_or_duplicate_custody(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fss-recovery-cli-") as temporary:
            root = Path(temporary).resolve()
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(4)
                listener.settimeout(8)
                base = arguments(root, listener.getsockname()[1])
                capture_plan = json.loads(successful(base))
                errors: list[BaseException] = []
                server = threading.Thread(target=camera, args=(listener, errors))
                server.start()
                try:
                    captured = successful([*base, "--approve", capture_plan["approval"]])
                finally:
                    server.join(timeout=26)
                self.assertFalse(server.is_alive(), "bounded camera thread did not stop")
                self.assertEqual(errors, [])
                terminal = [json.loads(line)["detail"] for line in captured.splitlines()
                            if json.loads(line).get("kind") == "reconnect_terminal"]
                self.assertEqual(terminal[0]["durable_pictures_all_attempts"], 3)
                saved = inventory(root)
                recovery = [*base, "--recover", "yes", "--recovery-timeout-ms", "10000"]
                plan = json.loads(successful(recovery))
                self.assertEqual(plan["schema"], RECOVERY)
                self.assertNotEqual(plan["approval"], capture_plan["approval"])
                self.assertEqual(plan["attempts"][2]["observation"], "both_stores_unobserved")
                self.assertEqual(saved, inventory(root), "preview changed retained files")
                for wrong in (
                    [*recovery, "--approve", capture_plan["approval"]],
                    [*base, "--approve", plan["approval"]],
                ):
                    code, output, error = run(wrong)
                    self.assertNotEqual(code, 0)
                    self.assertEqual(output, b"")
                    self.assertIn(b"ERR-CAPTURE-RTSP-APPROVAL-001", error)
                approved = [*recovery, "--approve", plan["approval"]]
                for _ in range(2):
                    records = [json.loads(line) for line in successful(approved).splitlines()]
                    self.assertEqual([row["sequence"] for row in records], list(range(len(records))))
                    self.assertTrue(all(row["schema"] == RECOVERY for row in records))
                    self.assertEqual(records[-1]["kind"], "recovery_terminal")
                    result = records[-1]["detail"]
                    self.assertEqual(result["selected_work_restored"], 2)
                    self.assertEqual(result["unobserved_attempts"], 1)
                    for claim in ("capture_complete", "continuity_across_attempts",
                                  "absence_certifiable", "network_requested", "source_bytes_emitted"):
                        self.assertFalse(result[claim], claim)
                    for row in records:
                        if row["kind"] == "attempt_recovery" and row["detail"].get("work_custody") == "verified":
                            detail = row["detail"]
                            self.assertIn(detail["generation"], (7, 8))
                            receipt = detail["catalog"] or detail["window"]
                            self.assertTrue(receipt["slot"])
                            self.assertEqual(receipt["outcome"], "already_durable")
                    self.assertEqual(saved, inventory(root), "recovery duplicated or replaced custody")
                listener.settimeout(0.05)
                with self.assertRaises(socket.timeout):
                    listener.accept()

                # Damage an actual retained RTP object, not merely a work receipt. Metadata-only
                # preview still works, but all-source preflight must refuse the entire recovery.
                picture = next(packet for packet in packets(2) if packet[12] & 31 == 5)
                originals = [path for path in (root / "capture.attempt-0002/spool/objects").iterdir()
                             if picture in path.read_bytes()]
                self.assertTrue(originals, "native archive did not retain original RTP")
                data = bytearray(originals[0].read_bytes())
                data[-1] ^= 1
                originals[0].write_bytes(data)
                damaged = inventory(root)
                self.assertEqual(json.loads(successful(recovery))["approval"], plan["approval"])
                code, output, _ = run(approved)
                self.assertNotEqual(code, 0)
                self.assertNotIn(b'"kind":"source_preflight_complete"', output)
                self.assertNotIn(b'"kind":"attempt_recovery"', output)
                self.assertEqual(damaged, inventory(root), "failed preflight altered either archive")
                with self.assertRaises(socket.timeout):
                    listener.accept()


if __name__ == "__main__":
    unittest.main()
