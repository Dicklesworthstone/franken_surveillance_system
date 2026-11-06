#!/usr/bin/env python3
"""Independent TLS camera fixture for the temporary handoff trial."""
import http.server
import json
import os
import pathlib
import secrets
import ssl
import subprocess
import sys
import tempfile
import threading


def run_case(binary, cert_der, cert_pem, key_pem, directory, current, expected, destination, mode):
    username, password, token = (secrets.token_hex(12) for _ in range(3))
    secret = pathlib.Path(directory) / (mode + "-credential.json")
    fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump({"username": username, "password": password}, output)
    if mode == "badpin":
        secret.unlink()
    journal = pathlib.Path(directory) / (mode + "-journal")
    state = {"controller": current, "requests": [], "post_readbacks": 0, "settings_reads": 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def send_body(self, body, cookie=False):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if cookie:
                self.send_header("Set-Cookie", "authId=" + token + "; Path=/; HttpOnly")
            self.end_headers()
            self.wfile.write(body)

        def authorized(self):
            return self.headers.get("Cookie") == "authId=" + token

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            if self.path != "/api/1.1/login" or n > 4096:
                self.send_error(400)
                return
            if json.loads(self.rfile.read(n)) != {"username": username, "password": password}:
                self.send_error(403)
                return
            state["requests"].append("login")
            self.send_body(b"{}", cookie=True)

        def do_GET(self):
            if not self.authorized():
                self.send_error(403)
                return
            if self.path == "/api/1.1/status":
                state["requests"].append("status")
                self.send_body(b'{"board":{},"fw":{},"controller":{}}')
            elif self.path == "/api/1.1/settings":
                state["requests"].append("settings")
                state["settings_reads"] += 1
                if mode == "observe-changed" and state["settings_reads"] == 2:
                    state["controller"] = "192.168.1.99"
                if "put" in state["requests"]:
                    state["post_readbacks"] += 1
                    if mode == "delayed" and state["post_readbacks"] > 1:
                        state["controller"] = destination
                    if mode == "reverted" and state["post_readbacks"] > 1:
                        state["controller"] = current
                self.send_body(json.dumps({"controller": {"addr": state["controller"]}}).encode())
            else:
                self.send_error(404)

        def do_PUT(self):
            chunked = mode == "chunked"
            if not self.authorized() or self.path != "/api/1.1/settings":
                self.send_error(400)
                return
            if chunked:
                if self.headers.get("Transfer-Encoding") != "chunked" or self.headers.get("Content-Length") is not None:
                    self.send_error(400)
                    return
                line = self.rfile.readline(16)
                try:
                    n = int(line.strip(), 16)
                except ValueError:
                    self.send_error(400)
                    return
                if not line.endswith(b"\r\n") or not 0 < n <= 4096:
                    self.send_error(400)
                    return
                payload = self.rfile.read(n)
                if self.rfile.read(7) != b"\r\n0\r\n\r\n":
                    self.send_error(400)
                    return
            else:
                if self.headers.get("Transfer-Encoding") is not None:
                    self.send_error(400)
                    return
                n = int(self.headers.get("Content-Length", "0"))
                if not 0 < n <= 4096:
                    self.send_error(400)
                    return
                payload = self.rfile.read(n)
            body = json.loads(payload)
            if body != {"controller": {"addr": destination}}:
                self.send_error(400)
                return
            state["requests"].append("put")
            if mode in ("readback-previous", "delayed"):
                state["controller"] = current
            elif mode == "readback-different":
                state["controller"] = "192.168.1.99"
            else:
                state["controller"] = destination
            self.send_body(b'{"success":true,"statusCode":200,"private":"synthetic-response-canary"}')

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    server.socket.settimeout(15)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_pem, key_pem)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server_errors = []

    def serve():
        try:
            server.handle_request()
        except (OSError, ssl.SSLError) as error:
            if mode != "badpin":
                server_errors.append(type(error).__name__)

    worker = threading.Thread(target=serve)
    worker.start()
    pin_case = "mismatch" if mode == "badpin" else "match"
    args = [binary, cert_der, "127.0.0.1", "tls13", pin_case, "sha256:" + "1" * 64,
            str(secret), str(server.server_port), expected, destination, str(journal), "--owner-authorized"]
    if mode == "chunked":
        args.append("--chunked")
    if mode.startswith("observe-"):
        args.append("--observe-only")
    try:
        run = subprocess.run(args, capture_output=True, text=True, timeout=25)
    finally:
        worker.join(timeout=15)
        server.server_close()
    if worker.is_alive():
        raise RuntimeError(mode + ": fixture server did not finish")
    if server_errors:
        raise RuntimeError(mode + ": fixture TLS error " + ",".join(server_errors))
    if any(value in run.stdout or value in run.stderr for value in (username, password, token, "synthetic-response-canary")):
        raise RuntimeError(mode + ": credential or cookie reached output")
    if mode.startswith("observe-"):
        expected_requests = ["login", "status", "settings", "settings"]
        if state["requests"] != expected_requests or journal.exists():
            raise RuntimeError(mode + ": observation performed an unexpected operation")
        if mode == "observe-changed":
            if not run.returncode or "controller claim changed" not in run.stderr:
                raise RuntimeError(mode + ": changing claim was not refused")
        else:
            claim = mode.removeprefix("observe-")
            if run.returncode or f"controller_claim={claim} effect=none" not in run.stdout:
                raise RuntimeError(mode + ": observation was not classified")
    elif mode in ("forward", "rollback", "chunked"):
        expected_requests = ["login", "status", "settings", "settings", "put", "settings", "settings", "settings"]
        if (run.returncode or state["requests"] != expected_requests or state["controller"] != destination
                or not journal.is_dir() or "controller_claim=requested" not in run.stdout
                or "handoff_response=Object { success: Some(true), status_code: Some(200) }" not in run.stdout):
            raise RuntimeError(mode + ": transition failed: " + run.stderr[-500:])
    elif mode in ("readback-previous", "readback-different", "delayed", "reverted"):
        expected_requests = ["login", "status", "settings", "settings", "put", "settings", "settings", "settings"]
        classes = {"readback-previous": ("Previous", "Previous", "Previous"),
                   "readback-different": ("Different", "Different", "Different"),
                   "delayed": ("Previous", "Requested", "Requested"),
                   "reverted": ("Requested", "Previous", "Previous")}[mode]
        if (not run.returncode or state["requests"] != expected_requests or not journal.is_dir()
                or any(f"handoff_readback[{index}]={value}" not in run.stdout for index, value in enumerate(classes))
                or "do not retry automatically" not in run.stderr):
            raise RuntimeError(mode + ": readback classification or effect fencing failed")
    elif mode == "badpin":
        if run.returncode or state["requests"] or journal.exists() or "mismatch=rejected" not in run.stdout:
            raise RuntimeError(mode + ": pin mismatch did not fail before credential access")
    elif mode == "already":
        if run.returncode or state["requests"] != ["login", "status", "settings"] or journal.exists() or "effect=none" not in run.stdout:
            raise RuntimeError(mode + ": idempotent observation failed")
    else:
        if not run.returncode or state["requests"] != ["login", "status", "settings"] or journal.exists():
            raise RuntimeError(mode + ": unexpected-controller refusal failed")


def main():
    if len(sys.argv) != 5:
        raise SystemExit("handoff_fixture.py BINARY CERT_DER CERT_PEM KEY_PEM")
    binary, cert_der, cert_pem, key_pem = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix="fss-unifi-handoff-fixture-") as directory:
        old, new, other = "192.168.1.10", "192.168.1.40", "192.168.1.50"
        run_case(binary, cert_der, cert_pem, key_pem, directory, old, old, new, "forward")
        run_case(binary, cert_der, cert_pem, key_pem, directory, old, old, new, "chunked")
        run_case(binary, cert_der, cert_pem, key_pem, directory, new, new, old, "rollback")
        run_case(binary, cert_der, cert_pem, key_pem, directory, old, new, old, "already")
        run_case(binary, cert_der, cert_pem, key_pem, directory, old, new, other, "stale")
        run_case(binary, cert_der, cert_pem, key_pem, directory, old, old, new, "badpin")
        run_case(binary, cert_der, cert_pem, key_pem, directory, old, old, new, "readback-previous")
        run_case(binary, cert_der, cert_pem, key_pem, directory, old, old, new, "readback-different")
        run_case(binary, cert_der, cert_pem, key_pem, directory, old, old, new, "delayed")
        run_case(binary, cert_der, cert_pem, key_pem, directory, old, old, new, "reverted")
        run_case(binary, cert_der, cert_pem, key_pem, directory, old, old, new, "observe-expected")
        run_case(binary, cert_der, cert_pem, key_pem, directory, new, old, new, "observe-destination")
        run_case(binary, cert_der, cert_pem, key_pem, directory, other, old, new, "observe-different")
        run_case(binary, cert_der, cert_pem, key_pem, directory, old, old, new, "observe-changed")
    print("handoff fixture: fourteen fixed-length, chunked, rollback, no-op, refusal, pin, temporal readback, and read-only observation checks passed")


if __name__ == "__main__":
    main()
