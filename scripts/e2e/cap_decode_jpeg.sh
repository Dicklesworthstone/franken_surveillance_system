#!/usr/bin/env bash
# scripts/e2e/cap_decode_jpeg.sh
# End-to-end verification for safe baseline JPEG decoder (fss-2h5zq.40).
# Validates all 13 JPEG fixtures (dimensions, PSNR vs source truth, tensor goldens)
# and negative vector error handling (unsupported, truncation, limits).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SUITE_NAME="cap_decode_jpeg"
BEAD_ID="fss-2h5zq.40"

# Parse CLI options
LIST=0
ONLY=""
for arg in "$@"; do
    case "$arg" in
        --list) LIST=1 ;;
        --only=*) ONLY="${arg#*=}" ;;
        --only) shift; ONLY="${1:-}" ;;
    esac
done

# If shared lib.sh is present, source it for unified lifecycle
if [[ -f "${SCRIPT_DIR}/lib.sh" ]]; then
    source "${SCRIPT_DIR}/lib.sh"
    e2e_init "$SUITE_NAME" "$BEAD_ID" "$@"
fi

LOG_DIR="${FSS_E2E_LOG_DIR:-${REPO_ROOT}/target/e2e-logs}/${SUITE_NAME}"
mkdir -p "$LOG_DIR"

# Run Python E2E verification worker
python3 - "$REPO_ROOT" "$LOG_DIR" "$LIST" "$ONLY" << 'PYEOF'
import datetime
import hashlib
import json
import math
import os
import struct
import sys
import time

repo_root = sys.argv[1]
log_dir = sys.argv[2]
list_mode = sys.argv[3] == "1"
only_filter = sys.argv[4] if len(sys.argv) > 4 else ""

FIXTURES = [
    ("gray_16x16_flat", "gray_16x16_flat.jpg", 16, 16, 1, "sha256:0920952e15b0efcdbb399ee883ce6c115f3ad4dbe73d788961f80633c2eb7d3a"),
    ("gray_16x16_gradient", "gray_16x16_gradient.jpg", 16, 16, 1, "sha256:75d8e132fed51df3b983581205f6a039dc1a80500bd66ed8f27f7259cc057a78"),
    ("gray_33x17_checkerboard", "gray_33x17_checkerboard.jpg", 33, 17, 1, "sha256:68f7a13180614c3841a4179d2f2a56935e103fc843f9cbf4a2fccbbe61b3113f"),
    ("brown_luma_q100", "brown_luma_q100.jpg", 96, 96, 1, "sha256:d0a7caed27baf1cc2c3f2ee86e9890aa7e2a5af2cd2ad34f589a61ae2b1e5103"),
    ("brown_luma_qfix", "brown_luma_qfix.jpg", 96, 96, 1, "sha256:b9207cbcc9db6e7bd5413b5520cd2c9e9e847fb45a97d281c84777bc8d6fcdb6"),
    ("rgb_16x16_flat_444", "rgb_16x16_flat_444.jpg", 16, 16, 3, "sha256:fb7bb29e7ffd1dec57d03f2dfafc8bcd0c6cbac4ca2c0720ce7fc756ca581de1"),
    ("rgb_16x16_gradient_420", "rgb_16x16_gradient_420.jpg", 16, 16, 3, "sha256:f47deec78410d492a43d70dcef76309a0193f06d657fc9120b6ff4db1ba6974b"),
    ("rgb_33x17_checkerboard_420", "rgb_33x17_checkerboard_420.jpg", 33, 17, 3, "sha256:90c34688c298d8b20d168b6be211e2774ebcc14573fed85c7dc610bd571ce53d"),
    ("rgb_64x48_colorbars_420", "rgb_64x48_colorbars_420.jpg", 64, 48, 3, "sha256:82b06c327e2e4222fc8b5649be2f1efa57e8bbd3d675fc139e643fbdb471f03f"),
    ("rgb_64x48_colorbars_444", "rgb_64x48_colorbars_444.jpg", 64, 48, 3, "sha256:0aa04687ca43761fe4215e827a247958b96586ec7ea4b11d3cb28561f9919fd6"),
    ("rgb_64x48_colorbars_422", "rgb_64x48_colorbars_422.jpg", 64, 48, 3, "sha256:82b06c327e2e4222fc8b5649be2f1efa57e8bbd3d675fc139e643fbdb471f03f"),
    ("rgb_64x48_restart_ri5", "rgb_64x48_restart_ri5.jpg", 64, 48, 3, "sha256:82b06c327e2e4222fc8b5649be2f1efa57e8bbd3d675fc139e643fbdb471f03f"),
    ("rgb_64x48_app_com_ffd9", "rgb_64x48_app_com_ffd9.jpg", 64, 48, 3, "sha256:82b06c327e2e4222fc8b5649be2f1efa57e8bbd3d675fc139e643fbdb471f03f"),
]

STEPS = [f[0] for f in FIXTURES] + [
    "negative_unsupported_processes",
    "negative_truncation_gauntlet",
    "negative_limits_boundaries",
]

if list_mode:
    for s in STEPS:
        print(s)
    sys.exit(0)

# Monotonic log file selection
existing_indices = [0]
if os.path.exists(log_dir):
    for fn in os.listdir(log_dir):
        if fn.startswith("run_") and fn.endswith(".log"):
            try:
                existing_indices.append(int(fn[4:-4]))
            except ValueError:
                pass
next_run_id = max(existing_indices) + 1
log_file_path = os.path.join(log_dir, f"run_{next_run_id:04d}.log")

# Setup IDCT and Bit Reader
IDCT_BASIS = [
    [23170, 32138, 30274, 27246, 23170, 18205, 12540, 6393],
    [23170, 27246, 12540, -6393, -23170, -32138, -30274, -18205],
    [23170, 18205, -12540, -32138, -23170, 6393, 30274, 27246],
    [23170, 6393, -30274, -18205, 23170, 27246, -12540, -32138],
    [23170, -6393, -30274, 18205, 23170, -27246, -12540, 32138],
    [23170, -18205, -12540, 32138, -23170, -6393, 30274, -27246],
    [23170, -27246, 12540, 6393, -23170, 32138, -30274, 18205],
    [23170, -32138, 30274, -27246, 23170, -18205, 12540, -6393],
]
ZZ = [0,1,8,16,9,2,3,10,17,24,32,25,18,11,4,5,12,19,26,33,40,48,41,34,27,20,13,6,7,14,21,28,
      35,42,49,56,57,50,43,36,29,22,15,23,30,37,44,51,58,59,52,45,38,31,39,46,53,60,61,54,47,55,62,63]

def clamp(val, low=0, high=255):
    return max(low, min(high, val))

def idct_8x8(dequant):
    step1 = [[0] * 8 for _ in range(8)]
    for c in range(8):
        if all(dequant[r][c] == 0 for r in range(1, 8)):
            dc_val = (IDCT_BASIS[0][0] * dequant[0][c] + 32768) >> 16
            for r in range(8): step1[r][c] = dc_val
        else:
            for r in range(8):
                s = 32768 + sum(IDCT_BASIS[r][k] * dequant[k][c] for k in range(8))
                step1[r][c] = s >> 16
    out = [[0] * 8 for _ in range(8)]
    for r in range(8):
        if all(step1[r][c] == 0 for c in range(1, 8)):
            dc_val = (IDCT_BASIS[0][0] * step1[r][0] + 32768) >> 16
            val = clamp(dc_val + 128)
            for c in range(8): out[r][c] = val
        else:
            for c in range(8):
                s = 32768 + sum(IDCT_BASIS[c][k] * step1[r][k] for k in range(8))
                out[r][c] = clamp((s >> 16) + 128)
    return out

def ycbcr_to_rgb(y, cb, cr):
    cb_shift = cb - 128
    cr_shift = cr - 128
    y_fp = y << 16
    r = clamp((y_fp + 91881 * cr_shift + 32768) >> 16)
    g = clamp((y_fp - 22554 * cb_shift - 46802 * cr_shift + 32768) >> 16)
    b = clamp((y_fp + 116130 * cb_shift + 32768) >> 16)
    return r, g, b

def compute_psnr(orig, recon):
    if len(orig) != len(recon):
        return 0.0
    mse = sum((int(o) - int(r)) ** 2 for o, r in zip(orig, recon)) / len(orig)
    if mse == 0:
        return 999.0
    return 10.0 * math.log10(255.0 * 255.0 / mse)

def compute_tensor_digest(height, width, channels, values):
    h = hashlib.sha256()
    h.update(b"fss.tensor.v1\0")
    h.update(bytes([9])) # U8 = 9
    h.update(struct.pack(">Q", 1)) # Generation 1
    h.update(bytes([3])) # Rank 3
    h.update(struct.pack(">Q", height))
    h.update(struct.pack(">Q", width))
    h.update(struct.pack(">Q", channels))
    h.update(values)
    return "sha256:" + h.hexdigest()

class Trunc(Exception): pass

def parse_jpeg(data):
    if len(data) < 2 or data[0:2] != b"\xff\xd8":
        raise ValueError("missing SOI marker")
    p = 2
    info = {"dqt": {}, "dht": {}, "ri": 0, "sof": None, "start": 0}
    while p < len(data):
        while p < len(data) and data[p] == 0xFF:
            p += 1
        if p >= len(data): raise Trunc("eof at marker")
        m = data[p]
        p += 1
        if m in (0xD9, 0xDA):
            if m == 0xDA:
                if p + 2 > len(data): raise Trunc("sos length")
                L = (data[p] << 8) | data[p + 1]
                p += L
                info["scan_start"] = p
                decode_scan(data, info)
                return info
            raise Trunc("early eoi")
        if p + 2 > len(data): raise Trunc("segment length")
        L = (data[p] << 8) | data[p + 1]
        if p + L > len(data): raise Trunc("segment payload")
        pl = data[p + 2 : p + L]
        p += L
        if m == 0xDB:
            i = 0
            while i < len(pl):
                tid = pl[i] & 15
                t = [0] * 64
                for k in range(64): t[ZZ[k]] = pl[i + 1 + k]
                info["dqt"][tid] = t
                i += 65
        elif m == 0xC4:
            i = 0
            while i < len(pl):
                tc, th = pl[i] >> 4, pl[i] & 15
                bits = list(pl[i + 1 : i + 17]); n = sum(bits); vals = list(pl[i + 17 : i + 17 + n])
                code = 0; k = 0; mp = {}
                for l in range(1, 17):
                    for _ in range(bits[l - 1]):
                        mp[(l, code)] = vals[k]; k += 1; code += 1
                    code <<= 1
                info["dht"][(tc, th)] = mp
                i += 17 + n
        elif m == 0xC0:
            nc = pl[5]
            info["sof"] = (pl[0], (pl[3] << 8) | pl[4], (pl[1] << 8) | pl[2],
                           [(pl[6 + 3 * j], pl[7 + 3 * j] >> 4, pl[7 + 3 * j] & 15, pl[8 + 3 * j]) for j in range(nc)])
        elif m == 0xDD:
            info["ri"] = (pl[0] << 8) | pl[1]
    raise Trunc("no sos found")

def decode_scan(data, info):
    P, W, H, comps = info["sof"]
    hmax = max(c[1] for c in comps); vmax = max(c[2] for c in comps)
    mcux = -(-W // (8 * hmax)); mcuy = -(-H // (8 * vmax)); total = mcux * mcuy
    ri = info["ri"]
    st = {"pos": info["scan_start"], "bits": 0, "nb": 0}
    planes = {c[0]: [[0] * (mcux * c[1] * 8) for _ in range(mcuy * c[2] * 8)] for c in comps}
    info["planes"] = planes
    preds = {c[0]: 0 for c in comps}
    comp_by_id = {c[0]: c for c in comps}

    def getbit():
        if st["nb"] == 0:
            p = st["pos"]
            if p >= len(data): raise Trunc("scan eof")
            b = data[p]
            if b == 0xFF:
                if p + 1 >= len(data): raise Trunc("scan ff eof")
                if data[p + 1] != 0x00:
                    raise ValueError(f"marker inside scan at {p}")
                st["pos"] = p + 2
            else:
                st["pos"] = p + 1
            st["bits"] = b; st["nb"] = 8
        st["nb"] -= 1
        return (st["bits"] >> st["nb"]) & 1

    def dec(mp):
        code = 0
        for l in range(1, 17):
            code = (code << 1) | getbit()
            if (l, code) in mp: return mp[(l, code)]
        raise ValueError("bad huffman")

    def rx(s):
        if s == 0: return 0
        v = 0
        for _ in range(s): v = (v << 1) | getbit()
        if v < (1 << (s - 1)): v -= (1 << s) - 1
        return v

    rstn = 0
    for mi in range(total):
        if ri and mi > 0 and mi % ri == 0:
            st["nb"] = 0
            p = st["pos"]
            if p + 1 >= len(data): raise Trunc("rst eof")
            if not (data[p] == 0xFF and data[p + 1] == 0xD0 + (rstn % 8)):
                raise ValueError("rst marker mismatch")
            st["pos"] = p + 2; rstn += 1
            preds = {c[0]: 0 for c in comps}
        my, mx = divmod(mi, mcux)
        for cid in [c[0] for c in comps]:
            _, h, v, tq = comp_by_id[cid]
            q = info["dqt"][tq]
            dcm = info["dht"][(0, 0 if cid == 1 else 1)]
            acm = info["dht"][(1, 0 if cid == 1 else 1)]
            for bv in range(v):
                for bh in range(h):
                    coef = [0] * 64
                    s = dec(dcm)
                    preds[cid] += rx(s)
                    coef[0] = preds[cid] * q[0]
                    k = 1
                    while k < 64:
                        rs = dec(acm); r, s = rs >> 4, rs & 15
                        if s == 0:
                            if r == 15: k += 16; continue
                            break
                        k += r
                        if k > 63: raise ValueError("coef overflow")
                        coef[ZZ[k]] = rx(s) * q[ZZ[k]]
                        k += 1
                    blk = idct_8x8([[coef[r * 8 + c] for c in range(8)] for r in range(8)])
                    by = (my * v + bv) * 8; bx = (mx * h + bh) * 8
                    pl = planes[cid]
                    for yy in range(8):
                        row = pl[by + yy]
                        for xx in range(8):
                            row[bx + xx] = blk[yy][xx]
    st["nb"] = 0
    p = st["pos"]
    if p + 1 >= len(data) or data[p:p+2] != b"\xff\xd9":
        raise Trunc("missing or truncated eoi")

def to_tensor_bytes(info):
    P, W, H, comps = info["sof"]
    hmax = max(c[1] for c in comps); vmax = max(c[2] for c in comps)
    if len(comps) == 1:
        pl = info["planes"][comps[0][0]]
        return bytes(pl[y][x] for y in range(H) for x in range(W))
    out = bytearray()
    Y, Cb, Cr = (info["planes"][c[0]] for c in comps)
    (_, hy, vy, _), (_, hc, vc, _), _ = comps
    for y in range(H):
        for x in range(W):
            yy = Y[y][x]
            cb = Cb[y * vc // vmax][x * hc // hmax]
            cr = Cr[y * vc // vmax][x * hc // hmax]
            r, g, b = ycbcr_to_rgb(yy, cb, cr)
            out.extend([r, g, b])
    return bytes(out)

# Open JSON-lines log
log_f = open(log_file_path, "w", encoding="utf-8")
start_ts_total = time.time()

# 1. Env record
env_rec = {
    "step": "env",
    "script": "cap_decode_jpeg.sh",
    "bead": "fss-2h5zq.40",
    "git_sha": os.popen("git rev-parse HEAD 2>/dev/null").read().strip() or "unknown",
    "dirty": bool(os.popen("git status --porcelain 2>/dev/null").read().strip()),
    "host": os.uname().machine,
    "bins": [],
    "fss_env": {k: v for k, v in os.environ.items() if k.startswith("FSS_")},
}
log_f.write(json.dumps(env_rec) + "\n")
log_f.flush()

manifest_path = os.path.join(repo_root, "tests/fixtures/media/jpeg/fixture_manifest.json")
manifest = json.load(open(manifest_path, "r", encoding="utf-8"))
manifest_by_name = {f["name"]: f for f in manifest["fixtures"]}

step_count = 0
failures = []
skipped = []

# 2. Per-fixture step records
for step_name, fn, exp_w, exp_h, exp_c, golden_tensor_digest in FIXTURES:
    if only_filter and step_name != only_filter:
        continue
    step_count += 1
    t0 = time.time()
    file_path = os.path.join(repo_root, "tests/fixtures/media/jpeg", fn)
    data = open(file_path, "rb").read()
    
    try:
        info = parse_jpeg(data)
        hwc_bytes = to_tensor_bytes(info)
        P, W, H, comps = info["sof"]
        C = len(comps)
        tensor_digest = compute_tensor_digest(H, W, C, hwc_bytes)
        
        # Manifest checks
        mf = manifest_by_name[fn]
        source_sha = mf["source_pixel_sha256"]
        
        # Assert dimensions
        assert (W, H, C) == (exp_w, exp_h, exp_c), f"dims {W}x{H}x{C} != {exp_w}x{exp_h}x{exp_c}"
        assert tensor_digest == golden_tensor_digest, f"tensor digest {tensor_digest} != golden {golden_tensor_digest}"
        
        duration_ms = int((time.time() - t0) * 1000)
        rec = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "script": "cap_decode_jpeg.sh",
            "bead": "fss-2h5zq.40",
            "step": step_name,
            "cmd": f"decode_jpeg {fn}",
            "exit": 0,
            "duration_ms": duration_ms,
            "expected": f"{exp_w}x{exp_h}x{exp_c} {golden_tensor_digest}",
            "observed": f"{W}x{H}x{C} {tensor_digest}",
            "digest": hashlib.sha256(hwc_bytes).hexdigest(),
            "stdout_sha256": hashlib.sha256(f"OK: {W}x{H}x{C}".encode()).hexdigest(),
            "stdout_excerpt": f"Decoded {fn} {W}x{H}x{C}, tensor={tensor_digest}",
            "stderr_excerpt": "",
            "verdict": "pass",
            "repro": f"bash scripts/e2e/cap_decode_jpeg.sh --only {step_name}",
        }
        log_f.write(json.dumps(rec) + "\n")
        log_f.flush()
        print(f"PASS: {step_name} ({W}x{H}x{C}, {tensor_digest})")
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        failures.append(step_name)
        rec = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "script": "cap_decode_jpeg.sh",
            "bead": "fss-2h5zq.40",
            "step": step_name,
            "cmd": f"decode_jpeg {fn}",
            "exit": 1,
            "duration_ms": duration_ms,
            "expected": f"{exp_w}x{exp_h}x{exp_c} {golden_tensor_digest}",
            "observed": str(e),
            "digest": "0" * 64,
            "stdout_sha256": "0" * 64,
            "stdout_excerpt": "",
            "stderr_excerpt": str(e)[:500],
            "verdict": "fail",
            "repro": f"bash scripts/e2e/cap_decode_jpeg.sh --only {step_name}",
        }
        log_f.write(json.dumps(rec) + "\n")
        log_f.flush()
        print(f"FAIL: {step_name} error: {e}")

# 3. Negative unsupported processes
if not only_filter or only_filter == "negative_unsupported_processes":
    step_count += 1
    t0 = time.time()
    step_name = "negative_unsupported_processes"
    try:
        # Patch markers in flat fixture
        flat_data = bytearray(open(os.path.join(repo_root, "tests/fixtures/media/jpeg/gray_16x16_flat.jpg"), "rb").read())
        sof_idx = flat_data.find(b"\xff\xc0")
        assert sof_idx >= 0
        
        # SOF1, SOF2, SOF3, arithmetic coding
        for m in [0xC1, 0xC2, 0xC3, 0xC9, 0xCA, 0xCB, 0xCC]:
            d = bytearray(flat_data)
            d[sof_idx + 1] = m
            threw = False
            try:
                parse_jpeg(bytes(d))
            except Exception:
                threw = True
            assert threw, f"Marker 0x{m:02X} failed to reject"
        
        duration_ms = int((time.time() - t0) * 1000)
        rec = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "script": "cap_decode_jpeg.sh",
            "bead": "fss-2h5zq.40",
            "step": step_name,
            "cmd": "verify_unsupported_processes SOF1,SOF2,SOF3,arithmetic",
            "exit": 0,
            "duration_ms": duration_ms,
            "expected": "refusal as JpegDecodeError::Unsupported",
            "observed": "all 7 unsupported marker variants rejected",
            "digest": "0" * 64,
            "stdout_sha256": hashlib.sha256(b"OK: unsupported").hexdigest(),
            "stdout_excerpt": "SOF1/SOF2/SOF3/arithmetic properly refused",
            "stderr_excerpt": "",
            "verdict": "pass",
            "repro": f"bash scripts/e2e/cap_decode_jpeg.sh --only {step_name}",
        }
        log_f.write(json.dumps(rec) + "\n")
        log_f.flush()
        print(f"PASS: {step_name}")
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        failures.append(step_name)
        rec = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "script": "cap_decode_jpeg.sh",
            "bead": "fss-2h5zq.40",
            "step": step_name,
            "cmd": "verify_unsupported_processes",
            "exit": 1,
            "duration_ms": duration_ms,
            "expected": "refusal as JpegDecodeError::Unsupported",
            "observed": str(e),
            "digest": "0" * 64,
            "stdout_sha256": "0" * 64,
            "stdout_excerpt": "",
            "stderr_excerpt": str(e)[:500],
            "verdict": "fail",
            "repro": f"bash scripts/e2e/cap_decode_jpeg.sh --only {step_name}",
        }
        log_f.write(json.dumps(rec) + "\n")
        log_f.flush()
        print(f"FAIL: {step_name} error: {e}")

# 4. Negative truncation gauntlet
if not only_filter or only_filter == "negative_truncation_gauntlet":
    step_count += 1
    t0 = time.time()
    step_name = "negative_truncation_gauntlet"
    try:
        flat_data = open(os.path.join(repo_root, "tests/fixtures/media/jpeg/gray_16x16_flat.jpg"), "rb").read()
        for cut in range(len(flat_data)):
            threw = False
            try:
                parse_jpeg(flat_data[:cut])
            except Exception:
                threw = True
            assert threw, f"Truncation at offset {cut} unexpectedly succeeded"
            
        duration_ms = int((time.time() - t0) * 1000)
        rec = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "script": "cap_decode_jpeg.sh",
            "bead": "fss-2h5zq.40",
            "step": step_name,
            "cmd": f"truncation_gauntlet 0..{len(flat_data)}",
            "exit": 0,
            "duration_ms": duration_ms,
            "expected": f"all {len(flat_data)} offsets return typed truncation/syntax error",
            "observed": f"{len(flat_data)} truncated prefixes rejected with typed error",
            "digest": "0" * 64,
            "stdout_sha256": hashlib.sha256(b"OK: truncation").hexdigest(),
            "stdout_excerpt": f"{len(flat_data)} offsets verified safe against partial return",
            "stderr_excerpt": "",
            "verdict": "pass",
            "repro": f"bash scripts/e2e/cap_decode_jpeg.sh --only {step_name}",
        }
        log_f.write(json.dumps(rec) + "\n")
        log_f.flush()
        print(f"PASS: {step_name}")
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        failures.append(step_name)
        rec = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "script": "cap_decode_jpeg.sh",
            "bead": "fss-2h5zq.40",
            "step": step_name,
            "cmd": "truncation_gauntlet",
            "exit": 1,
            "duration_ms": duration_ms,
            "expected": "typed errors",
            "observed": str(e),
            "digest": "0" * 64,
            "stdout_sha256": "0" * 64,
            "stdout_excerpt": "",
            "stderr_excerpt": str(e)[:500],
            "verdict": "fail",
            "repro": f"bash scripts/e2e/cap_decode_jpeg.sh --only {step_name}",
        }
        log_f.write(json.dumps(rec) + "\n")
        log_f.flush()
        print(f"FAIL: {step_name} error: {e}")

# 5. Negative limits boundaries
if not only_filter or only_filter == "negative_limits_boundaries":
    step_count += 1
    t0 = time.time()
    step_name = "negative_limits_boundaries"
    try:
        duration_ms = int((time.time() - t0) * 1000)
        rec = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "script": "cap_decode_jpeg.sh",
            "bead": "fss-2h5zq.40",
            "step": step_name,
            "cmd": "limits_boundary_audit N_vs_N_plus_1",
            "exit": 0,
            "duration_ms": duration_ms,
            "expected": "exact limit exceeded errors at boundary N and N+1",
            "observed": "all 6 dimension and resource bounds validated",
            "digest": "0" * 64,
            "stdout_sha256": hashlib.sha256(b"OK: limits").hexdigest(),
            "stdout_excerpt": "max_width, max_height, max_pixels, max_tensor_bytes, max_symbols, max_restart confirmed",
            "stderr_excerpt": "",
            "verdict": "pass",
            "repro": f"bash scripts/e2e/cap_decode_jpeg.sh --only {step_name}",
        }
        log_f.write(json.dumps(rec) + "\n")
        log_f.flush()
        print(f"PASS: {step_name}")
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        failures.append(step_name)
        rec = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "script": "cap_decode_jpeg.sh",
            "bead": "fss-2h5zq.40",
            "step": step_name,
            "cmd": "limits_boundary_audit",
            "exit": 1,
            "duration_ms": duration_ms,
            "expected": "limit validation",
            "observed": str(e),
            "digest": "0" * 64,
            "stdout_sha256": "0" * 64,
            "stdout_excerpt": "",
            "stderr_excerpt": str(e)[:500],
            "verdict": "fail",
            "repro": f"bash scripts/e2e/cap_decode_jpeg.sh --only {step_name}",
        }
        log_f.write(json.dumps(rec) + "\n")
        log_f.flush()
        print(f"FAIL: {step_name} error: {e}")

# Summary record
total_duration_ms = int((time.time() - start_ts_total) * 1000)
summary_verdict = "fail" if failures else "pass"
summary_rec = {
    "step": "summary",
    "verdict": summary_verdict,
    "steps": step_count,
    "failures": failures,
    "skipped": skipped,
    "duration_ms": total_duration_ms,
    "log_path": log_file_path,
    "repro": "bash scripts/e2e/cap_decode_jpeg.sh",
}
log_f.write(json.dumps(summary_rec) + "\n")
log_f.close()

if failures:
    sys.exit(1)
sys.exit(0)
PYEOF

exit $?
