#!/usr/bin/env python3
"""Owner-account helpers for the Wyze lab: certs, broker presence, shadow push, actions.

Lab tooling (stdlib + the owner's `cryptography` venv is NOT needed; only ssl/socket/json).
Token comes from WYZE_TOKEN or ~/.config/fss-lab/wyze_auth.json (access_token).
Certificates are fetched to ~/.config/fss-lab/wyze_iot/<MAC>/ and never printed.

  wyze_cloud.py cert <MAC> <ENR>          # issue + download cert/key/rootCA
  wyze_cloud.py presence <THING> <MAC>    # is the camera on the broker? (survive>1s = absent)
  wyze_cloud.py push <THING> <MAC> <URL> <MD5>
  wyze_cloud.py action <THING> <MAC> restart|power_off|power_on

Only the pieces proven on 2026-10-22/23 are here. `run_action upgrade` is deliberately absent: the
modern upgrade endpoints use a dynamic signature (see docs/research/EV-pack-H-002.md §2.2.1).
"""
import json, os, socket, ssl, sys, time, urllib.request

API = "https://app.wyzecam.com"
HDR_APPID = "9319141212m2ik"
APPID_CERT = "wc4p_5b0e5bc2788d4ff68c7b98a5656148d0"
SV_RUN_ACTION = "011a6b42d80a4f32b4cc24bb721c9c96"
SV_CERT = "5b0e5bc2788d4ff68c7b98a5656148d0"
PHONE = "d39515e3-5b94-4b29-b63f-1b3456cc270a"
IOT = ("aws-iot.wyzecam.com", 8883)
IOT_SNI = "a24rq1e5m4mtei.iot.us-west-2.amazonaws.com"  # the wildcard cert needs the CNAME target
IOT_DIR = os.path.expanduser("~/.config/fss-lab/wyze_iot")


def token() -> str:
    t = os.environ.get("WYZE_TOKEN")
    if t:
        return t
    path = os.path.expanduser("~/.config/fss-lab/wyze_auth.json")
    with open(path) as fh:
        return json.load(fh)["access_token"]


def api(path: str, body: dict, appid: str = HDR_APPID) -> dict:
    body = dict(body, access_token=token(), app_name="wyze", app_ver="2.50.0", phone_id=PHONE,
                ts=int(time.time() * 1000))
    tok = token()
    req = urllib.request.Request(API + path, data=json.dumps(body).encode(),
                                 headers={"content-type": "application/json", "appid": appid,
                                          "authorization": tok,
                                          "user-agent": "wyze_ios/3.22.0"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


def cert(mac: str, enr: str) -> None:
    d = os.path.join(IOT_DIR, mac)
    os.makedirs(d, exist_ok=True)
    j = api("/device/system/get_iot_certificate", {
        "mac": mac, "product_model": "HL_CAM4", "product_type": "Camera",
        "hardware_ver": "0.0.0.0", "firmware_ver": "4.52.17.26", "enr": enr,
        "sc": "verify_method", "sv": SV_CERT}, appid=APPID_CERT)
    if j.get("code") != "1":
        sys.exit("cert refused: " + j.get("msg", "?"))
    for key, name in (("root_cert_url", "rootCA.crt"), ("client_cert_url", "cert.pem"),
                      ("client_private_key_url", "privkey.pem")):
        with urllib.request.urlopen(j["data"][key], timeout=30) as r, open(os.path.join(d, name), "wb") as fh:
            fh.write(r.read())
    print("cert ok:", j["data"]["thing_name"])


def _iot(thing: str, mac: str, connect_s: float = 12.0):
    d = os.path.join(IOT_DIR, mac)
    ctx = ssl.create_default_context(cafile=os.path.join(d, "rootCA.crt"))
    ctx.load_cert_chain(os.path.join(d, "cert.pem"), os.path.join(d, "privkey.pem"))
    s = ctx.wrap_socket(socket.create_connection(IOT, timeout=10), server_hostname=IOT_SNI)
    s.settimeout(connect_s)
    # client id must be the thing name; anything else is CONNACK-then-close
    s.sendall(_pkt(1, 0, _s("MQTT") + bytes([4, 0x02]) + b"\x00\x3c" + _s(thing)))
    if s.recv(4) != b"\x20\x02\x00\x00":
        sys.exit("connack refused")
    return s


def _s(x: str) -> bytes:
    b = x.encode()
    return len(b).to_bytes(2, "big") + b


def _pkt(t: int, flags: int, payload: bytes) -> bytes:
    n, out = len(payload), b""
    while True:
        b, n = n % 128, n // 128
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            break
    return bytes([(t << 4) | flags]) + out + payload


def presence(thing: str, mac: str) -> None:
    """A connect that outlives ~1 s means no camera client holds the id: the camera is absent."""
    s = _iot(thing, mac)
    end, alive = time.time() + 12, 0.0
    while time.time() < end:
        try:
            s.sendall(_pkt(12, 0, b"\xc0\x00"))
            if not s.recv(2):
                break
            alive = time.time()
        except (socket.timeout, ssl.SSLError):
            break
        except OSError:
            break
        time.sleep(1.2)
    print("present" if alive and time.time() - alive > 1.0 else "ABSENT (camera not on broker)")


def push(thing: str, mac: str, url: str, md5: str) -> None:
    """One delta, retried until the broker acks.

    The camera shares the client id and kicks us within milliseconds, so a single-shot publish
    often dies unacked. Retrying the same packet until a PUBACK lands is what makes this
    reliable; only then is the connection dropped (a held id starves the camera).
    """
    d = os.path.join(IOT_DIR, mac)
    ctx = ssl.create_default_context(cafile=os.path.join(d, "rootCA.crt"))
    ctx.load_cert_chain(os.path.join(d, "cert.pem"), os.path.join(d, "privkey.pem"))
    body = json.dumps({"state": {"desired": {"url": url, "md5": md5, "model": "HL_CAM4"}}}).encode()
    topic = _s(f"$aws/things/{thing}/shadow/name/wyze-service/update")
    for attempt in range(5):
        try:
            w = ctx.wrap_socket(socket.create_connection(IOT, timeout=10), server_hostname=IOT_SNI)
            w.settimeout(6)
            w.sendall(_pkt(1, 0, _s("MQTT") + bytes([4, 0x02]) + b"\x00\x3c" + _s(thing)))
            if w.recv(4) != b"\x20\x02\x00\x00":
                continue
            w.sendall(_pkt(3, 2, topic + body))  # QoS1, no packet id: the broker accepts this form
            if w.recv(4)[:1] == b"\x40":
                w.close()
                print(f"published (puback, attempt {attempt + 1})")
                print("now hang up and wait ~40 s; do not reconnect")
                return
        except (socket.timeout, OSError, ssl.SSLError):
            pass
        time.sleep(1.5)
    sys.exit("publish never acked after 5 attempts (camera likely absent)")


def action(thing: str, mac: str, key: str) -> None:
    j = api("/app/v2/auto/run_action", {
        "sc": "run_action", "sv": SV_RUN_ACTION, "provider_key": "WYZEC1", "action_key": key,
        "instance_id": thing.upper(), "custom_string": "", "action_params": {}})
    print(j.get("msg", j))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "cert" and len(sys.argv) == 4:
        cert(sys.argv[2].upper(), sys.argv[3])
    elif cmd == "presence" and len(sys.argv) == 4:
        presence(sys.argv[2], sys.argv[3].upper())
    elif cmd == "push" and len(sys.argv) == 6:
        push(sys.argv[2], sys.argv[3].upper(), sys.argv[4], sys.argv[5])
    elif cmd == "action" and len(sys.argv) == 5:
        action(sys.argv[2], sys.argv[3].upper(), sys.argv[4])
    else:
        sys.exit(__doc__)
