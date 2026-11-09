#!/opt/homebrew/bin/python3
"""Capsule HTTP server for the tunnel leg of the Wyze OTA: logs who fetched what.

Plain ``python -m http.server`` is unusable as an OTA witness because cloudflared
connects from 127.0.0.1, so the access log names no camera and drops the
User-Agent that actually distinguishes the camera from our probes.

This server keeps the same directory/port contract and adds one JSON line per
request to ``/tmp/ota/fwserve_access.jsonl``:

  ts, method, path, ua, probe, range, status, bytes_sent, complete, dur_ms

``probe`` is true when the UA carries ``fss-probe`` (every readiness/operator
check sends it). Any non-probe request for a capsule is evidence that a camera
reached us through the tunnel, which is the chain-completion trigger
``wyze_chain_watch.sh`` waits on. ``complete`` false on a 200 means the client
hung up mid-body — the interesting failure when an OTA downloader rejects TLS.

Read it, never tail it by hand: ``fwserve_access.jsonl`` is the machine truth.
"""
import json
import os
import sys
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = "/tmp/fwserve/wuv2/upgrade/HL_CAM4/firmware"
ACCESS = "/tmp/ota/fwserve_access.jsonl"
PROBE_MARK = "fss-probe"


class Handler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=ROOT, **kw)

    def log_message(self, fmt, *args):
        pass  # the JSONL is the log

    # -- byte accounting ---------------------------------------------------
    def copyfile(self, source, outputfile):
        sent = 0
        try:
            while True:
                buf = source.read(64 * 1024)
                if not buf:
                    return sent
                outputfile.write(buf)
                sent += len(buf)
        finally:
            self._sent = sent

    def _record(self, status):
        ua = self.headers.get("User-Agent", "")
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "method": self.command,
            "path": self.path,
            "ua": ua,
            "probe": PROBE_MARK in ua,
            "range": self.headers.get("Range", ""),
            "status": status,
            "bytes_sent": getattr(self, "_sent", 0),
            # a HEAD has no body; a GET that sent nothing or died early is partial
            "complete": self.command == "HEAD"
            or getattr(self, "_sent", 0) >= getattr(self, "_expect", 0),
            "dur_ms": int((time.time() - self._t0) * 1000) if hasattr(self, "_t0") else -1,
        }
        try:
            with open(ACCESS, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
        except OSError as e:  # logging must never kill the transfer
            print(f"access log: {e}", file=sys.stderr, flush=True)

    # -- request path ------------------------------------------------------
    def _setup(self):
        self._t0 = time.time()
        self._sent = 0
        self._status = 0

    def do_HEAD(self):
        self._setup()
        self.send_head()
        self._record(self._status)

    def do_GET(self):
        self._setup()
        f = self.send_head()
        if not f:
            self._record(self._status)
            return
        try:
            self.copyfile(f, self.wfile)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:  # never lose the record to an unexpected error
            print(f"get {self.path}: {e!r}", file=sys.stderr, flush=True)
        finally:
            f.close()
        self._record(self._status)

    def send_header(self, keyword, value):
        if keyword.lower() == "content-length":
            self._expect = int(value)
        super().send_header(keyword, value)

    def send_head(self):
        # status is captured by send_response(); nothing to add here
        return super().send_head()

    def send_response(self, code, message=None):
        self._status = code
        super().send_response(code, message)


def main():
    os.makedirs(os.path.dirname(ACCESS), exist_ok=True)
    srv = ThreadingHTTPServer(("127.0.0.1", 9443), Handler)
    srv.daemon_threads = True
    print(f"serving {ROOT} on 127.0.0.1:9443 -> {ACCESS}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
