#!/usr/bin/env python3
"""Laboratory-only real-binary/native-loopback contracts; no mocked FSS implementation.

The only network endpoint is a bounded loopback socket owned by this fixture. Production
capture, HTTP/MIME framing, custody, decode and cold checks execute in the Rust binaries.
"""
from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def dimensions(jpeg: bytes) -> tuple[int, int]:
    """Read the fixture's SOF dimensions, not a pixel decode or a Rust codec oracle."""
    assert jpeg[:2] == b"\xff\xd8"
    pos = 2
    while pos + 4 <= len(jpeg):
        assert jpeg[pos] == 0xFF
        while jpeg[pos] == 0xFF:
            pos += 1
        marker = jpeg[pos]
        pos += 1
        length = int.from_bytes(jpeg[pos:pos + 2], "big")
        assert length >= 2 and pos + length <= len(jpeg)
        if marker in (0xC0, 0xC1, 0xC2):
            return (int.from_bytes(jpeg[pos + 5:pos + 7], "big"),
                    int.from_bytes(jpeg[pos + 3:pos + 5], "big"))
        pos += length
    raise AssertionError("missing fixture SOF")


def multipart(jpeg: bytes, count: int, terminal: bool = True) -> bytes:
    part = (b"--fss\r\nContent-Type: image/jpeg\r\nContent-Length: "
            + str(len(jpeg)).encode() + b"\r\n\r\n" + jpeg + b"\r\n")
    return part * count + (b"--fss--\r\n" if terminal else b"")


def wire(jpeg: bytes, mode: str, count: int = 2, terminal: bool = True) -> bytes:
    body = multipart(jpeg, count, terminal)
    head = b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=fss\r\n"
    if mode == "length":
        return head + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    if mode == "chunked":
        chunks = [body[n:n + 37] for n in range(0, len(body), 37)]
        return (head + b"Transfer-Encoding: chunked\r\n\r\n"
                + b"".join(f"{len(c):x}\r\n".encode() + c + b"\r\n" for c in chunks)
                + b"0\r\n\r\n")
    assert mode == "close"
    return head + b"\r\n" + body


class Endpoint:
    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(2)
        self.listener.settimeout(10)
        self.requests: list[bytes] = []
        self.errors: list[BaseException] = []
        self.thread: threading.Thread | None = None

    @property
    def peer(self) -> str:
        return f"127.0.0.1:{self.listener.getsockname()[1]}"

    def no_connection(self) -> None:
        self.listener.settimeout(0.05)
        try:
            connection, _ = self.listener.accept()
        except socket.timeout:
            return
        else:
            connection.close()
            raise AssertionError("unexpected native TCP attempt")
        finally:
            self.listener.settimeout(10)

    def serve(self, response: bytes, stall: bool = False) -> None:
        def run() -> None:
            try:
                connection, _ = self.listener.accept()
                with connection:
                    connection.settimeout(10)
                    request = b""
                    while not request.endswith(b"\r\n\r\n"):
                        chunk = connection.recv(512)
                        assert chunk, "capture disconnected before GET"
                        request += chunk
                        assert len(request) <= 4096
                    self.requests.append(request)
                    assert request.startswith(b"GET /video HTTP/1.1\r\n")
                    assert b"Host: camera.invalid" in request
                    assert b"Authorization:" not in request
                    try:
                        if response:
                            connection.sendall(response)
                        if stall:
                            # The native client must stop under its own requested boundary.
                            assert connection.recv(1) == b""
                        else:
                            connection.shutdown(socket.SHUT_WR)
                    except (BrokenPipeError, ConnectionResetError):
                        pass  # A deliberate bounded/refused capture closes without more I/O.
            except BaseException as error:
                self.errors.append(error)
        self.thread = threading.Thread(target=run, name="owned-loopback-http")
        self.thread.start()

    def join(self) -> None:
        assert self.thread is not None
        self.thread.join(12)
        assert not self.thread.is_alive(), "bounded loopback server did not stop"
        if self.errors:
            raise self.errors[0]
        assert len(self.requests) == 1
        self.no_connection()

    def close(self) -> None:
        self.listener.close()


def command(args: list[str], *, success: bool | None = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, text=True, capture_output=True, timeout=25, check=False)
    assert len(result.stdout.encode()) <= 32 * 1024 * 1024
    if success is True:
        assert result.returncode == 0, (result.returncode, result.stderr, result.stdout[-4000:])
    elif success is False:
        assert result.returncode != 0, result.stdout
    return result


def parse_rows(result: subprocess.CompletedProcess[str]) -> list[dict]:
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert rows and rows[-1]["kind"] == "finish", result.stdout
    assert [row["sequence"] for row in rows] == list(range(len(rows)))
    assert all(row["format"] == "fss.http_capture_cli.v1" for row in rows)
    prepared = set()
    for row in rows:
        if row["kind"] == "wire_prepared":
            prepared.add(json.dumps(row["detail"]["pin"], sort_keys=True))
        elif row["kind"] == "wire_durable":
            assert json.dumps(row["detail"]["pin"], sort_keys=True) in prepared
    return rows


def main() -> None:
    capture, archive, event, jpeg_path = sys.argv[1:]
    jpeg = Path(jpeg_path).read_bytes()
    width, height = dimensions(jpeg)
    scenarios = 0
    with tempfile.TemporaryDirectory(prefix="fss-capture-cli-") as tmp:
        base = Path(tmp).resolve()
        def options(root: Path, endpoint: Endpoint, extra: list[str] | None = None) -> list[str]:
            return [capture, "http", "--root", str(root), "--peer", endpoint.peer,
                    "--host", "camera.invalid", "--target", "/video",
                    "--source", sha(str(root).encode()), "--generation", "1",
                    "--receive-clock", sha(b"fixture receive clock"),
                    "--retention-evidence", sha(b"fixture original header/media retention"),
                    "--owner-authorized", "yes", "--plaintext", "yes", "--retain-originals", "yes",
                    "--timeout-ms", "5000", "--read-bytes", "257"] + (extra or [])

        def preview(args: list[str], root: Path, endpoint: Endpoint) -> str:
            result = command(args)
            plan = json.loads(result.stdout)
            assert plan["kind"] == "plan" and plan["writes"] == plan["network"] == "none"
            assert plan["approval_digest"] == json.loads(command(args).stdout)["approval_digest"]
            assert not root.exists()
            endpoint.no_connection()
            return plan["approval_digest"]

        def run(root: Path, mode: str, *, extra: list[str] | None = None,
                response: bytes | None = None, stall: bool = False, success: bool = True) -> tuple[list[dict], list[str], Endpoint]:
            endpoint = Endpoint()
            args = options(root, endpoint, extra)
            approval = preview(args, root, endpoint)
            endpoint.serve(wire(jpeg, mode) if response is None else response, stall)
            result = command(args + ["--approve", approval], success=success)
            endpoint.join()
            return parse_rows(result), args + ["--approve", approval], endpoint

        def cold(root: Path, finish: dict, *, decode: str = "none", privacy: list[str] | None = None,
                 success: bool | None = True) -> dict:
            source = finish["source"]
            pin = finish["pin"]
            args = [archive, "check-http", "--root", str(root), "--source", source["source"],
                    "--generation", str(source["generation"]), "--receive-clock", source["receive_clock"],
                    "--retention-evidence", source["retention_evidence"], "--head", pin["head"],
                    "--reads", str(pin["reads"]), "--bytes", str(pin["bytes"]),
                    "--read-originals", "yes", "--decode", decode, "--read-bytes", "113"]
            if finish["completion"] is not None:
                args.extend(["--completion-root", finish["completion"]["root"]])
            args += privacy or []
            result = command(args, success=success)
            return json.loads(result.stdout) if result.stdout else {}

        # Stale approval, illegal routes and absent acknowledgements fail before root/TCP.
        endpoint = Endpoint()
        root = base / "rejected"
        args = options(root, endpoint)
        approved = preview(args, root, endpoint)
        command(args + ["--max-frames", "1", "--approve", approved], success=False)
        assert not root.exists()
        endpoint.no_connection()
        for key, value in [("--target", "/video?token=never-log-this"), ("--peer", "camera.invalid:80"), ("--plaintext", "no")]:
            changed = args[:]
            changed[changed.index(key) + 1] = value
            refused = command(changed, success=False)
            assert "never-log-this" not in refused.stdout + refused.stderr
            assert not root.exists()
            endpoint.no_connection()
        endpoint.close()
        scenarios += 1

        # Native fixed-length, chunked, and real close-delimited termination -> cold source checks.
        completed = []
        for mode in ("length", "chunked", "close"):
            root = base / mode
            rows, args, endpoint = run(root, mode, extra=["--max-frames", "2"])
            finish = rows[-1]["detail"]
            frames = [r["detail"] for r in rows if r["kind"] == "frame_verified"]
            assert finish["status"] == "native_complete" and finish["stream_complete"]
            assert finish["request_satisfied"] and finish["frames_taken"] == len(frames) == 2
            assert finish["completion"] and finish["decoded_frames"] == 0
            assert not finish["coverage_certified"] and not finish["event_published"]
            restored = cold(root, finish)
            assert restored["status"] == "complete" and restored["checked_frames"] == 2
            assert [r["encoded_digest"] for r in frames] == [r["encoded"] for r in restored["frames"]]
            assert [r["source_map_digest"] for r in frames] == [r["exposure"] for r in restored["frames"]]
            assert all(r["pixel_decode"]["state"] == "not_requested" for r in frames)
            # Same approved source namespace is a recovery task, never a second TCP session.
            refused = parse_rows(command(args, success=False))[-1]["detail"]
            assert refused["status"] == "start_refused" and not refused["tcp_attempted"]
            endpoint.no_connection()
            endpoint.close()
            completed.append((root, finish))
            scenarios += 1

        # Indefinite real-camera style response: explicit count stop does not synthesize EOF.
        rows, _, endpoint = run(base / "count", "close", extra=["--stop-after-frames", "1"],
                                response=wire(jpeg, "close", 3, False), stall=True)
        finish = rows[-1]["detail"]
        assert finish["status"] == "requested_count_reached" and finish["request_satisfied"]
        assert finish["frames_taken"] == 1 and not finish["stream_complete"] and finish["completion"] is None
        assert not any(r["kind"] == "completion_prepared" for r in rows)
        endpoint.close()
        scenarios += 1

        # A safety bound is NOT the deliberate count-stop success path.
        rows, _, endpoint = run(base / "limit", "length", extra=["--max-frames", "1"], success=False)
        finish = rows[-1]["detail"]
        assert finish["status"] == "refused" and not finish["request_satisfied"]
        assert finish["frames_taken"] == 1 and finish["completion"] is None and finish["pin"]["reads"] > 0
        endpoint.close()
        scenarios += 1

        # An idle socket reaches its owner deadline without an invented zero-byte read/EOF.
        endpoint = Endpoint()
        root = base / "deadline"
        args = options(root, endpoint)
        args[args.index("--timeout-ms") + 1] = "500"
        approval = preview(args, root, endpoint)
        endpoint.serve(b"", True)
        start = time.monotonic()
        rows = parse_rows(command(args + ["--approve", approval], success=False))
        endpoint.join()
        assert time.monotonic() - start < 20
        finish = rows[-1]["detail"]
        assert finish["status"] == "refused" and not finish["stream_complete"]
        assert not finish["peer_eof_observed"] and finish["completion"] is None
        endpoint.close()
        scenarios += 1

        # Malformed framing leaves original custody diagnostic, never an all-clear or reconnect.
        malformed = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx"
        rows, _, endpoint = run(base / "malformed", "length", response=malformed, success=False)
        finish = rows[-1]["detail"]
        assert finish["status"] == "refused" and finish["pin"]["reads"] > 0
        assert not finish["stream_complete"] and not finish["reconnect_attempted"]
        endpoint.close()
        scenarios += 1

        # Real retained privacy declaration -> live full JPEG decode -> masked cold replay.
        privacy_root = base / "privacy"
        site, sensor = "site:http-capture", "sensor:owned-camera"
        declare = [event, "privacy-mask", "declare", "--root", str(privacy_root), "--site", site,
                   "--sensor", sensor, "--resolution", f"{width}x{height}", "--rect", f"0,0,{width},{height}"]
        mask_preview = json.loads(command(declare).stdout)
        mask = json.loads(command(declare + ["--approve", mask_preview["approval_digest"]]).stdout)
        privacy = ["--privacy-root", str(privacy_root), "--site", site, "--sensor", sensor]
        extra = ["--decode", "grayscale"] + privacy
        root = base / "masked"
        rows, _, endpoint = run(root, "chunked", extra=extra)
        finish = rows[-1]["detail"]
        frames = [r["detail"]["pixel_decode"] for r in rows if r["kind"] == "frame_verified"]
        expected_luma = sha(bytes([16]) * width * height)
        assert finish["decoded_frames"] == 2
        assert all(f["luma_digest"] == expected_luma and f["policy_digest"] == mask["policy_digest"] for f in frames)
        assert all(f["privacy"] == "retained_policy_applied" and not f["pixels_emitted"] for f in frames)
        restored = cold(root, finish, decode="grayscale", privacy=privacy)
        assert all(f["luma"] == expected_luma for f in restored["frames"])
        endpoint.close()
        scenarios += 1

        # Native decode budget denial preserves originals without pretending the JPEG was checked.
        rows, _, endpoint = run(base / "decode-budget", "length", extra=extra + ["--max-decode-work", "0"], success=False)
        finish = rows[-1]["detail"]
        assert finish["decoded_frames"] == 0 and finish["pin"]["reads"] > 0
        assert finish["status"] == "refused" and finish["completion"] is None
        endpoint.close()
        scenarios += 1

        # A missing privacy authority cannot become a new empty/no-policy deployment.
        endpoint = Endpoint()
        root = base / "missing-privacy"
        args = options(root, endpoint, ["--decode", "grayscale", "--privacy-root", str(base / "missing-policy"),
                                        "--site", site, "--sensor", sensor])
        approval = preview(args, root, endpoint)
        command(args + ["--approve", approval], success=False)
        assert not root.exists() and not (base / "missing-policy").exists()
        endpoint.no_connection()
        endpoint.close()
        scenarios += 1

        # Corrupt stored bytes fail a cold verification; the checker must not repair them.
        root, finish = completed[0]
        objects = [p for p in (root / "spool" / "objects").rglob("*") if p.is_file()]
        assert objects
        victim = max(objects, key=lambda p: p.stat().st_size)
        changed = bytearray(victim.read_bytes())
        changed[-1] ^= 1
        victim.write_bytes(changed)
        cold(root, finish, success=False)
        assert victim.read_bytes() == changed
        scenarios += 1

    print(json.dumps({"scenario_count": scenarios, "native_binaries_executed": True,
                      "coverage_or_detection_quality_claim": False}, sort_keys=True))


if __name__ == "__main__":
    main()
