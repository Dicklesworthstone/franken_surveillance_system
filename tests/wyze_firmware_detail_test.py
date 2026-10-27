#!/usr/bin/env python3
"""Unit-test the get_firmware_detail responder against ota-path.md §23.4.

Runs the response builder and the live handler over plain HTTP (no TLS) with a
mock, asserting the §23.4 captured shape:

  {"code":"1","msg":"SUCCESS","data":{"version":…,"url":…,"filename":…},"traceId":…}

plus the md5 carriers assis's descriptor parser needs (§22.2/§23.4).

  python3 tests/wyze_firmware_detail_test.py            # shape assertions + live mock
  python3 tests/wyze_firmware_detail_test.py --serve    # keep the mock up for curl
"""
import argparse
import http.client
import importlib.util
import json
import os
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
SERVE = os.path.join(HERE, "..", "deliverables", "scripts", "wyze_forge_serve.py")

spec = importlib.util.spec_from_file_location("wyze_forge_serve", SERVE)
forge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(forge)

VERSION = "4.52.17.32"
URL = ("https://s3-us-west-2.amazonaws.com/wuv2/upgrade/HL_CAM4/firmware/"
       "4.52.17.32.tar")
MD5 = "c642a2ca9f80b03c7ee5e05795f5822b"

FAILURES = []


def check(name, cond, detail=""):
    tag = "ok " if cond else "FAIL"
    print(f"  [{tag}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def test_builder():
    print("builder shape vs §23.4:")
    obj = forge.firmware_detail_response(VERSION, URL, MD5, trace_id="t" * 32)
    check("code is string '1'", obj.get("code") == "1", repr(obj.get("code")))
    check("msg == SUCCESS", obj.get("msg") == "SUCCESS")
    data = obj.get("data") or {}
    check("data.version == target", data.get("version") == VERSION)
    check("data.url == capsule url", data.get("url") == URL)
    check("data.filename derived from url",
          data.get("filename") == "4.52.17.32.tar", repr(data.get("filename")))
    check("traceId present", isinstance(obj.get("traceId"), str) and obj["traceId"])
    fixed = forge.firmware_detail_response(VERSION, URL, MD5, trace_id="fixed")
    check("traceId honored when given", fixed["traceId"] == "fixed")
    for alias in ("firmware_md5", "firmwareMd5", "md5"):
        check(f"md5 carrier '{alias}'", data.get(alias) == MD5)
    # filename derivation ignores a presigned query string
    presigned = forge.firmware_detail_response(VERSION, URL + "?X-Amz-Signature=ab", MD5)
    check("filename strips query", presigned["data"]["filename"] == "4.52.17.32.tar")
    # url without a basename still yields a filename
    bare = forge.firmware_detail_response(VERSION, "https://host/", MD5)
    check("filename fallback", bare["data"]["filename"] == "firmware.tar",
          repr(bare["data"]["filename"]))
    # top-level key set exactly matches the captured envelope keys + carriers
    check("top-level keys", set(obj) == {"code", "msg", "data", "traceId"},
          str(sorted(obj)))
    return obj


def test_live_handler():
    print("live handler over plain HTTP (mock, no TLS):")
    body_bytes = {}

    # main() wires TLS + binds 443 and keeps the Handler class in its closure, so
    # re-create the exact class here: extract its source and exec with our args.
    src = open(SERVE).read()
    # extract the Handler class source from main() and exec it with our args namespace
    start = src.index("    class Handler(http.server.SimpleHTTPRequestHandler):")
    end = src.index("    handler = Handler")
    import textwrap
    cls_src = textwrap.dedent(src[start:end])
    ns = {
        "http": __import__("http"),
        "os": os, "json": json, "time": __import__("time"),
        "a": argparse.Namespace(dir="/tmp", firmware_detail=True,
                                target_version=VERSION, capsule_url=URL, capsule_md5=MD5),
        "passthrough": forge.passthrough,
        "firmware_detail_response": forge.firmware_detail_response,
    }
    exec(compile(cls_src, "<handler>", "exec"), ns)
    Handler = ns["Handler"]

    import http.server as _httpsrv

    class Server(_httpsrv.HTTPServer):
        allow_reuse_address = True

    srv = Server(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        # POST
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        payload = json.dumps({"version": VERSION})
        conn.request("POST", "/firmware/upgrade/get_firmware_detail", payload,
                     {"Content-Type": "application/json"})
        r = conn.getresponse()
        body = r.read()
        check("POST status 200", r.status == 200, str(r.status))
        check("POST content-type json", "json" in (r.getheader("Content-Type") or ""))
        obj = json.loads(body)
        check("POST code '1'", obj.get("code") == "1")
        check("POST version echoed", obj["data"]["version"] == VERSION)
        check("POST url is ours", obj["data"]["url"] == URL)
        check("POST md5 carriers", obj["data"]["md5"] == MD5)
        body_bytes["post"] = obj
        conn.close()
        # GET
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/firmware/upgrade/get_firmware_detail")
        r = conn.getresponse()
        body = r.read()
        check("GET status 200", r.status == 200, str(r.status))
        obj = json.loads(body)
        check("GET shape matches POST", obj["data"] == body_bytes["post"]["data"])
        conn.close()
    finally:
        srv.shutdown()
    return body_bytes


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--serve", action="store_true")
    ap.parse_args()
    test_builder()
    test_live_handler()
    if FAILURES:
        print(f"\n{len(FAILURES)} failure(s): {FAILURES}")
        return 1
    print("\nall §23.4 shape checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
