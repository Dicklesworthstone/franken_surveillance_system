#!/usr/bin/env python3
"""EV-pack-H-003 — ready-to-run LAN OTA `0x1A` probe for the AOSU HomeBase H2E.

Speaks Tuya 3.5 on 6668 with the 18-byte `lpv35_fixed_head_t` header
(prefix | version:4|reserved:4 | reserved2 | seq | cmd | len, GCM AAD = header[4:18])
and fires ONE `FRM_LAN_OTA_START (0x1A)` frame whose descriptor is deliberately
unusable, so the reply says which gate the device actually enforces:

    retcode 1 + ASCII reason        -> body shape wrong (nothing written; try the other candidate)
    retcode 0, then OTA fault 45/49 -> shape right, digest rejected
    retcode 0, silence              -> accepted; re-run with a real image

`0x1A` only ANNOUNCES an image, so a wrong digest costs no flash write.

Usage:
    ./ev-pack-h-003-send-ota-start.py --key <32 hex>              # candidate B (default)
    ./ev-pack-h-003-send-ota-start.py --key <32 hex> --candidate A
    ./ev-pack-h-003-send-ota-start.py --key <32 hex> --dry        # hex only, no socket
    ./ev-pack-h-003-send-ota-start.py --selftest                  # no device, no key

Candidate B is the default: `TUYA_OTA_FIRMWARE_INFO_T { uint32_t len; uint32_t crc32;
uint8_t md5[16]; }` = 24 bytes (`tuya_cloud_types.h:1252-1256`). See the pack's
"LAN OTA" section for why both candidates exist and why neither carries an hmac.

Budget: `ALLOW_NO_KEY_NUM 3` frames per connection are tolerated keyed by the
local_key instead of the session key, and `CLIENT_LIMT 3` clients overall — the
negotiation here is single-shot and every later frame uses the session key.
"""

import argparse
import hashlib
import hmac
import json
import os
import socket
import struct
import sys
import zlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = bytes.fromhex("00006699")
SUFFIX = bytes.fromhex("00009966")
HEADER_LEN好心 = 18
HEADER_LEN = 18                      # 4 magic + 2 reserved + 4 seq + 4 cmd + 4 len
AAD = slice(4, HEADER_LEN)
CMD_NEG_START, CMD_NEG_RESP, CMD_NEG_FINISH = 0x03, 0x04, 0x05
CMD_OTA_START = 0x1A
ZERO_RC = b"\x00\x00\x00\x00"
FAKE_IMAGE = b"\x00" * 512


def seal(seq, cmd, raw, key, retcode=ZERO_RC):
    """One sealed 6699 frame. `raw` excludes the retcode, which is prepended."""
    iv = os.urandom(12)
    body = retcode + raw
    hdr = PREFIX + b"\x00\x00" + struct.pack(">III", seq, cmd, 12 + len(body) + 16)
    return hdr + iv + AESGCM(key).encrypt(iv, body, hdr[AAD]) + SUFFIX


def open_frame(data, key, with_retcode=True):
    """Verify + decrypt an inbound frame; returns (retcode|None, plaintext)."""
    if data[:4] != PREFIX or data[-4:] != SUFFIX:
        raise ValueError("not a 6699 frame")
    length = struct.unpack(">I", data[14:18])[0]
    iv, sealed = data[18:30], data[30:-4]      # sealed = ciphertext || tag(16)
    if len(sealed) != length - 12:          # declared length covers iv + ct + tag
        raise ValueError("length mismatch: declared %d, have %d" % (length, len(sealed) + 12))
    raw = AESGCM(key).decrypt(iv, sealed, data[AAD])
    return (raw[:4] if with_retcode else None), (raw[4:] if with_retcode else raw)


def candidate_b():
    """24-byte descriptor: correct len, correct crc32, deliberately wrong md5."""
    return struct.pack(">II", len(FAKE_IMAGE), zlib.crc32(FAKE_IMAGE) & 0xFFFFFFFF) + b"\xde\xad\xbe\xef" * 4


def candidate_a():
    """The cloud descriptor as JSON. `httpsUrl` is mandatory (unchecked ->valuestring)."""
    md5 = hashlib.md5(FAKE_IMAGE).hexdigest()
    return json.dumps({
        "type": 1,
        "size": str(len(FAKE_IMAGE)),
        "httpsUrl": "https://127.0.0.1:9/none",
        "hmac": "0" * 64,
        "md5": md5[:-1] + ("0" if md5[-1] != "0" else "1"),
    }).encode()


def recv_frame(sock):
    """Read exactly one frame, honouring the declared length."""
    def take(n):
        out = b""
        while len(out) < n:
            chunk = sock.recv(n - len(out))
            if not chunk:
                raise SystemExit("peer closed mid-frame")
            out += chunk
        return out

    head = take(HEADER_LEN)
    return head + take(struct.unpack(">I", head[14:18])[0] + 4)


def negotiate(sock, local_key):
    """Single-shot 0x03 -> 0x04 -> 0x05. Returns the session key."""
    client_nonce = os.urandom(16)
    sock.sendall(seal(1, CMD_NEG_START, client_nonce, local_key, retcode=b""))
    rc, payload = open_frame(recv_frame(sock), local_key)
    if rc != ZERO_RC:
        raise SystemExit("negotiation rejected: retcode %s" % rc.hex())
    if len(payload) < 48:
        raise SystemExit("short negotiation response (%d B, want 48)" % len(payload))
    device_nonce, proof = payload[:16], payload[16:48]
    if proof != hmac.new(local_key, client_nonce, hashlib.sha256).digest():
        raise SystemExit("DEVICE PROOF INVALID - wrong local_key")
    x = bytes(a ^ b for a, b in zip(client_nonce, device_nonce))
    session_key = AESGCM(local_key).encrypt(client_nonce[:12], x, None)[:16]
    sock.sendall(seal(2, CMD_NEG_FINISH,
                      hmac.new(local_key, device_nonce, hashlib.sha256).digest(),
                      local_key, retcode=b""))
    return session_key


def selftest():
    key = bytes(range(16))
    body = candidate_b()
    frame = seal(7, CMD_OTA_START, body, key)
    assert frame[:4] == PREFIX and frame[-4:] == SUFFIX
    assert frame[4:6] == b"\x00\x00", "reserved pair must be two zero bytes"
    assert struct.unpack(">I", frame[14:18])[0] == 12 + 4 + len(body) + 16
    assert struct.unpack(">I", frame[14:18])[0] == 12 + 4 + len(body) + 16
    rc, back = open_frame(frame, key)
    assert rc == ZERO_RC and back == body, "round-trip mismatch"
    assert len(body) == 24 and len(candidate_a()) > 24
    print("selftest ok: 18 B header, reserved pair, AAD [4:18], len=12+4+24+16, round-trip clean")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.4.37")
    ap.add_argument("--port", type=int, default=6668)
    ap.add_argument("--key", help="local_key, 32 hex chars")
    ap.add_argument("--candidate", choices=("A", "B"), default="B")
    ap.add_argument("--dry", action="store_true", help="print the frame, do not connect")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.key:
        ap.error("--key is required (or --selftest)")
    local_key = bytes.fromhex(args.key)
    if len(local_key) != 16:
        ap.error("--key must be 16 bytes / 32 hex chars")

    body = candidate_b() if args.candidate == "B" else candidate_a()
    print("# candidate %s: %d B body over a 512 B fake image, digest deliberately wrong"
          % (args.candidate, len(body)))

    if args.dry:
        # Body considers no session: sealed with a stand-in key/iv so the bytes are inspectable.
        print(seal(3, CMD_OTA_START, body, local_key).hex())
        return 0

    with socket.create_connection((args.host, args.port), args.timeout) as sock:
        sock.settimeout(args.timeout)
        try:
            session_key = negotiate(sock, local_key)
        except (TimeoutError, socket.timeout):
            raise SystemExit("no negotiation response: wrong local_key, or the 6668 "
                             "accept backlog is wedged - retry with backoff")
        print("# session established")
        sock.sendall(seal(3, CMD_OTA_START, body, session_key))
        try:
            frame = recv_frame(sock)
        except SystemExit:
            print("0x1A -> SILENCE (accepted, no reply: nothing to parse back)")
            return 0
        rc, payload = open_frame(frame, session_key)
        print("0x1A -> retcode %s" % rc.hex())
        if rc != ZERO_RC:
            print("  reason: %r" % payload.decode("utf-8", "replace"))
            print("  => body SHAPE wrong. Nothing was written; try --candidate %s"
                  % ("A" if args.candidate == "B" else "B"))
        else:
            print("  => shape accepted. Watch this session for an OTA fault:")
            print("     45 = download HMAC  49 = upgrade HMAC (digest-gated)")
            print("     no fault           = digest ignored (local_key alone is enough)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
