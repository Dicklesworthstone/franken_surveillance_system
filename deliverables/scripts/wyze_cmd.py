"""The one implementation of a Wyze cloud command body and of MQTT framing.

Two consumers need exactly these bytes: the transparent proxy (`wyze_mqtt_mitm.py`, which rewrites
and re-originates a cloud session) and the local shadow broker (`wyze_mqtt_broker.py`, which owns the
session). Keeping one builder is what makes an oracle run against the broker mean anything about the
proxy, and vice versa.

The body is the one iCamera's UDS receiver accepts: `{Action, Params{...}, Guid}` with `sub_mac`
top-level (the handler at iCamera:0x476e98 dereferences it after starting the worker), XXTEA under the
device ENR (ota-path.md §9.5). Shape sweeps (`OTA_SHAPES`, `OTA_EXTRA`, `OTA_PARAMS_EXTRA`) exist
because the exact cloud body was never captured; they are applied here so both paths sweep the same.
"""
import base64
import json
import struct

MODEL_DEFAULT = "HL_CAM4"
URL_DEFAULT = "https://s3-us-west-2.amazonaws.com/wuv2/upgrade/HL_CAM4/firmware/4.52.17.33.tar"


def enc_len(n):
    out = b""
    while True:
        d = n % 128
        n //= 128
        out += bytes([d | (0x80 if n else 0)])
        if not n:
            return out


def pkt(kind, body, flags=0):
    return bytes([(kind << 4) | flags]) + enc_len(len(body)) + body


def xxtea(data, key, decrypt=False):
    n = len(data) // 4
    if n < 2:
        return data
    v = list(struct.unpack("<%dI" % n, data[:n * 4]))
    k = list(struct.unpack("<4I", (key + b"\0" * 16)[:16]))
    delta = 0x9E3779B9
    rounds = 6 + 52 // n
    if decrypt:
        total = (rounds * delta) & 0xFFFFFFFF
        y = v[0]
        for _ in range(rounds):
            e = (total >> 2) & 3
            for p in range(n - 1, -1, -1):
                z = v[(p - 1) % n]
                mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))
                v[p] = (v[p] - mx) & 0xFFFFFFFF
                y = v[p]
            total = (total - delta) & 0xFFFFFFFF
    else:
        total = 0
        z = v[n - 1]
        for _ in range(rounds):
            total = (total + delta) & 0xFFFFFFFF
            e = (total >> 2) & 3
            for p in range(n):
                y = v[(p + 1) % n]
                mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))
                v[p] = (v[p] + mx) & 0xFFFFFFFF
                z = v[p]
    return struct.pack("<%dI" % n, *v)


def build_body(act, thing, i=0, model=MODEL_DEFAULT, url=URL_DEFAULT, md5="", proc_name=None):
    """The command body for one swept action. Unknown actions take the stop/start branch."""
    ver = url.rsplit("/", 1)[-1].split(".tar")[0]
    inner = {"model": model, "url": url, "firmware_ver": ver, "md5": md5, "sub_mac": thing.upper()}
    if act == "upgrade":
        return {"Action": "upgrade", "Params": inner, "sub_mac": thing.upper(), "Guid": "%016x" % (i + 1)}
    if act == "cmd":
        # iotclient logs "cmd:%d, len:%d, data:%s" and builds the UDS message itself
        return {"cmd": 1234, "sub_mac": thing.upper(), "data": inner}
    if act == "cmdstr":
        return {"cmd": 1234, "data": json.dumps(inner)}
    if act == "upgradeSub":
        return {"Action": act, "Guid": f"{thing}-{i}", "url": url, "md5": md5, "model": model,
                "sub_mac": thing.upper(), "Params": {"url": url}}
    if act.lower().startswith(("stop", "start", "kill", "restartprocess")):
        return {"Action": act, "Guid": f"{thing}-{i}",
                "Params": {"processname": proc_name or "wyzeedgeai_cam_v4_test_protocol"}}
    # no Ts: the captured body has none
    return {"Action": act, "Guid": f"{thing}-{i}", "Params": inner}


def apply_shapes(body, top_spec, par_spec):
    """Merge swept extra fields: top-level into the body, the other into Params."""
    for spec, dst in ((top_spec, body), (par_spec, body.get("Params") or {})):
        if spec:
            dst.update(json.loads(spec))
    return body


def encode_payload(text, enc="3", enr="", rawhex=""):
    """Encode the JSON body the way the cloud does. enc: 1/2/3/4 AES/XXTEA variants, 5 raw hex."""
    pl = text.encode()
    if not enc:
        return pl
    if enc == "5":
        return bytes.fromhex(rawhex)
    if enc in ("3", "4"):
        pl = xxtea(pl + b"\0" * (-len(pl) % 4), enr.encode())
        if enc == "4":
            pl = struct.pack("<III", 0, 1319, len(pl)) + pl
        return pl
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if enc == "2":
        k = enr.encode()[:16]
    else:
        k = base64.b64decode(enr)
        k = (k + b"\0" * 16)[:16]
    pl += b"\0" * (-len(pl) % 16)
    e = Cipher(algorithms.AES(k), modes.ECB()).encryptor()
    return e.update(pl) + e.finalize()
