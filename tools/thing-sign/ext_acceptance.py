#!/usr/bin/env python3
"""tecrkcehc_ext parser-acceptance harness (fss-fkkpw).

Mirrors the exact evaluation order of libthing_security.so's blob parser (arm64,
MD5 465e5af0355b4a3ecfd305fc6df62926) so candidate blobs can be graded without a device:

  parser @ 0x1929c (called with the file loaded at x19+0x78, len at x19+0x80):
    1. scan bytes [1..len) for the FIRST '\\n' (0x0a) at 0x192e8; remember its index w21.
       No newline anywhere -> -1 (0x1936c/0x19370: w21 stays 0, cmp fails -> 0x1930c).
       NOTE 0x192e8: scan starts at ptr+1, i.e. a leading newline at index 0 is not seen.
    2. decimal field: scan BACKWARD from the newline (0x1933c ldrb [x23, x28], x28=w21
       decrementing at 0x19330), accumulate digits (c-0x30) with pow(10, k) at 0x19358,
       store into ctx+0x14 (0x19320/0x19360/0x19364). Non-digit chars are skipped, not
       fatal. The number is little-endian by position (units digit is the last char
       before the newline).
    3. w24 = index of newline + 1 (0x19300 add w24, w21, #1); base64 payload is
       [newline+1, len) via memmove at 0x193e8, NUL-terminated at 0x193ec.
       Length check at 0x19388: len - w21 - 2 must NOT be >= -0x10 (cmn #0x10 / b.hs
       fail) -> an empty or tiny remainder is accepted only when >= 0? (see below).
    4. consumer 0x18c68: base64-decode with mbedtls_base64_decode (0x18ce0) into a
       buffer of the payload length; on failure -> error. Success -> decoded bytes are
       copied into a std::string, then passed to helper 0x18dbc.
    5. helper 0x18dbc (0x18dbc-0x18f00): AES-128-ECB decrypt (0x10fb0 -> inline
       FIPS-197 tables: SBOX 0x756f, Rcon 0x7470, InvSBOX 0x766f, InvShiftRows idx
       0x7410; 9 main rounds = AES-128). Then the plaintext bytes are pushed into a
       std::string with EVERY NUL BYTE REPLACED BY '0' (0x18e9c movz w24,#0x3002;
       strh stores "\\x02""0"; append(sp+1, 1) = "0"). Result string returned.

So acceptance classes, in order of strictness:
  A. shape:  has a newline at index >= 1; prefix before it has >= 1 digit.
  B. base64: remainder must decode via mbedtls (strict alphabet/padding).
  C. cipher: decoded length must be a multiple of 16 (AES-ECB block) for the decrypt
     to run without trailing garbage (mbedtls cipher layer enforces this).
  D. length hint: the decimal field is stored at ctx+0x14; consumers compare it
     against the decoded/plaintext length (exact meaning per-callsite; harness
     records it so live runs can correlate).

The sweep mode generates placeholder payloads across the plausible content shapes
(documented in FLEET_LIBERATION_STATUS.md) and grades each; the live docker harness
(`docker run ... fss-jvm`) then confirms which shapes change checkStatus/cmd-1.

Usage:
  python3 ext_acceptance.py parse FILE...          # grade existing files
  python3 ext_acceptance.py sweep [--out DIR]      # generate + grade placeholders
  python3 ext_acceptance.py decrypt FILE KEYHEX    # AES-128-ECB decrypt a candidate
"""
import argparse
import base64
import os
import sys

SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16")
INV_SBOX = bytes(a for a in (
    # derived as the inverse permutation of SBOX (verified against the .so table at 0x766f)
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d))
RCON = bytes.fromhex("8d01020408102040801b366cd8ab4d9a")
# InvShiftRows column-major read index (0x7410), bytes 0..15
INV_SHIFT = list(range(0x00, 0x10))


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a = (a ^ 0x1B) & 0xFF
    return a


def _mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = _xtime(a)
    return p


def key_expansion_128(key):
    w = [list(key[i * 4:(i + 1) * 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[i // 4]
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum((w[4 * r + c] for c in range(4)), []) for r in range(11)]


def _shift_rows(s, inv=False):
    # state is column-major 4x4: s[r + 4c]
    o = list(s)
    for r in range(1, 4):
        row = [s[r + 4 * c] for c in range(4)]
        row = row[-r:] + row[:-r] if inv else row[r:] + row[:r]
        for c in range(4):
            o[r + 4 * c] = row[c]
    return o


def _mix_columns(s, inv=False):
    M = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
    MI = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))
    m = MI if inv else M
    o = [0] * 16
    for c in range(4):
        for r in range(4):
            o[r + 4 * c] = (_mul(m[r][0], s[0 + 4 * c]) ^ _mul(m[r][1], s[1 + 4 * c])
                            ^ _mul(m[r][2], s[2 + 4 * c]) ^ _mul(m[r][3], s[3 + 4 * c]))
    return o


def add_round_key(s, rk):
    return [a ^ b for a, b in zip(s, rk)]


def aes128_ecb_decrypt_block(block, round_keys):
    s = add_round_key(list(block), round_keys[10])
    for rnd in range(9, 0, -1):
        s = _shift_rows(s, inv=True)
        s = [INV_SBOX[b] for b in s]
        s = add_round_key(s, round_keys[rnd])
        s = _mix_columns(s, inv=True)
    s = _shift_rows(s, inv=True)
    s = [INV_SBOX[b] for b in s]
    return add_round_key(s, round_keys[0])


def parse(blob: bytes):
    """Exact-shape parser; returns dict with class flags and fields."""
    r = {"len": len(blob), "class": "reject", "newline_idx": None,
         "decimal": None, "b64_payload": None, "decoded_len": None,
         "decoded_ok": False, "block_aligned": False, "b64_err": None}
    # step 1: first newline scanning from index 1
    nl = None
    for i in range(1, len(blob)):
        if blob[i] == 0x0A:
            nl = i
            break
    r["newline_idx"] = nl
    if nl is None:
        r["b64_err"] = "no newline in [1..len)"
        return r
    # step 2: backward decimal accumulate (digits only, skipped non-digits)
    val, k = 0, 0
    for i in range(nl - 1, -1, -1):
        c = blob[i]
        if 0x30 <= c <= 0x39:
            val += (c - 0x30) * (10 ** k)
            k += 1
    r["decimal"] = val
    # step 3: payload after newline
    payload = blob[nl + 1:]
    r["b64_payload"] = payload
    # remainder length check mirrors 0x19380-0x1938c: (len - nl - 2) >= -16 fails
    rem = len(blob) - nl - 2
    if rem < -16:
        r["b64_err"] = "remainder too short (cmn #0x10 fail)"
        r["class"] = "shape"
        return r
    r["class"] = "shape"
    if not payload:
        r["b64_err"] = "empty payload"
        return r
    # step 4: strict base64 (mbedtls requires padding, rejects whitespace)
    try:
        dec = base64.b64decode(payload, validate=True)
        r["decoded_len"] = len(dec)
        r["decoded_ok"] = True
        r["class"] = "b64"
        r["block_aligned"] = len(dec) % 16 == 0 and len(dec) > 0
        if r["block_aligned"]:
            r["class"] = "cipher"
        r["_decoded"] = dec
    except Exception as e:
        r["b64_err"] = str(e)
    return r


def decrypt_candidate(blob: bytes, key16: bytes):
    """Full pipeline: parse -> base64 -> AES-128-ECB decrypt -> NUL->'0' string."""
    p = parse(blob)
    if not p["decoded_ok"] or not p["block_aligned"]:
        return None, p
    dec = p["_decoded"]
    rk = key_expansion_128(key16)
    out = b""
    for i in range(0, len(dec), 16):
        out += bytes(aes128_ecb_decrypt_block(dec[i:i + 16], rk))
    text = out.replace(b"\x00", b"0")
    return text, p


B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def mk_blob(decimal: int, payload: bytes, pad_nl: bool = False) -> bytes:
    body = base64.b64encode(payload).decode()
    if pad_nl:
        body += "\n"
    return f"{decimal}\n{body}".encode()


def sweep(outdir=None):
    """Placeholder shapes documented in FLEET_LIBERATION_STATUS.md §signer."""
    cases = []
    key = b"7178265647164836"  # the 16-char literal baked into the .so at 0x81e0
    rk = key_expansion_128(key)

    def enc16(n):
        out = b""
        for i in range(0, len(n), 16):
            s = add_round_key(list(n[i:i + 16]), rk[10])
            for r_ in range(9, 0, -1):
                s = _shift_rows(s, inv=True)
                s = [INV_SBOX[b] for b in s]
                s = add_round_key(s, rk[r_])
                s = _mix_columns(s, inv=True)
            s = _shift_rows(s, inv=True)
            s = [INV_SBOX[b] for b in s]
            out += bytes(add_round_key(s, rk[0]))
        return out

    plain_shapes = {
        "json-keys": b'{"appSecret":"x","key":"y"}',
        "hex-32": bytes.fromhex("00" * 32),
        "csv-keys": b"a=1;b=2;c=3",
        "zero-16": b"\x00" * 16,
        "fips197": bytes.fromhex("00102030021222320414243406162636"),
    }
    for name, plain in plain_shapes.items():
        ct = enc16(plain.ljust((len(plain) + 15) // 16 * 16, b"\x00"))
        cases.append((f"enc-{name}", mk_blob(len(plain), ct)))
        cases.append((f"enc-{name}-padnl", mk_blob(len(plain), ct, pad_nl=True)))
    # raw (not encrypted) shapes
    for name, plain in plain_shapes.items():
        cases.append((f"raw-{name}", mk_blob(len(plain), plain)))
    # existing placeholder grade
    here = os.path.dirname(os.path.abspath(__file__))
    cur = os.path.join(here, "assets", "tecrkcehc_ext")
    if os.path.exists(cur):
        cases.insert(0, ("current-placeholder", open(cur, "rb").read()))
    results = []
    for name, blob in cases:
        p = parse(blob)
        txt = None
        if p["decoded_ok"] and p["block_aligned"]:
            txt, _ = decrypt_candidate(blob, key)
        line = (f"{name:24s} class={p['class']:7s} decimal={p['decimal']} "
                f"dec_len={p['decoded_len']} "
                f"plain={(txt or b'')[:32]!r}")
        results.append(line)
        if outdir:
            os.makedirs(outdir, exist_ok=True)
            open(os.path.join(outdir, name), "wb").write(blob)
    print("\n".join(results))
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["parse", "sweep", "decrypt"])
    ap.add_argument("files", nargs="*")
    ap.add_argument("--out")
    ap.add_argument("--keyhex")
    a = ap.parse_args()
    if a.mode == "sweep":
        sweep(a.out)
    elif a.mode == "parse":
        for f in a.files:
            blob = open(f, "rb").read()
            p = parse(blob)
            p.pop("_decoded", None)
            print(f, p)
    elif a.mode == "decrypt":
        if not a.keyhex:
            sys.exit("decrypt needs --keyhex (16 bytes hex)")
        for f in a.files:
            blob = open(f, "rb").read()
            txt, p = decrypt_candidate(blob, bytes.fromhex(a.keyhex))
            print(f, "class=", p["class"], "plain=", (txt or b"")[:64])


if __name__ == "__main__":
    main()
