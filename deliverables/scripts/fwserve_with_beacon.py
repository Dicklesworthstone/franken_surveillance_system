#!/opt/homebrew/bin/python3
"""http.server with beacon capture: logs /fss-ran and /fss-recon hits to /tmp/fss_beacons.log
Serves /tmp/fwserve on 192.168.4.160:8080 — replacement for the launchd plain http.server."""
import http.server, socketserver, os, socket, time, urllib.parse

ROOT = "/tmp/fwserve"
LOG = "/tmp/fss_beacons.log"

class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=ROOT, **kw)
    def do_GET(self):
        try:
            self._handle_get()
        except Exception:
            try:
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.end_headers()
            except Exception:
                pass

    def _handle_get(self):
        p = self.path.split("?")[0]
        if p.startswith("/fss-ran") or p.startswith("/fss-recon"):
            q = urllib.parse.parse_qs(self.path.split("?")[1] if "?" in self.path else "")
            uid = q.get("uid", ["?"])[0]; via = q.get("via", ["?"])[0]
            arch = q.get("arch", ["?"])[0]; mtd = q.get("mtd", ["?"])[0]
            with open(LOG, "a") as f:
                stage = (q.get("stage") or ["-"])[0]
                f.write(f'{time.strftime("%H:%M:%S")} BEACON {p} stage={stage} uid={uid} via={via} arch={arch} mtd={mtd} from={self.client_address[0]}\n')
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        return super().do_GET()
    def log_message(self, fmt, *args):
        pass  # quiet: beacon log is the signal

socketserver.TCPServer.allow_reuse_address = True
class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    address_family = socket.AF_INET

with Server(("0.0.0.0", 8080), H) as s:
    s.serve_forever()
