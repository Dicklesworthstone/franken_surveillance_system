#!/usr/bin/env python3
"""FSS-118 (`fss-x4a.12.17`): Sealed lab-only FFmpeg/ffprobe media differential runner.

Compares first-party pure-Rust media tooling (`fss-probe` + scalar MJPEG/container fixtures)
against locally installed `ffprobe`/`ffmpeg` strictly as an offline, lab-only differential oracle.

Non-negotiable invariants (`INV-003`, `INV-040`, `INV-049`, `FSS-024`):
- Production Rust crates NEVER link or invoke FFmpeg/ffprobe; this script lives outside `crates/`.
- Oracle outputs are explicitly tainted `sealed_laboratory_oracle_only` and NEVER constitute
  source custody or production runtime authority.
- Missing `ffmpeg`, `ffprobe`, or `fss-probe` fails closed (exit 5 `unavailable_lab_oracle`);
  it NEVER degrades into a fake pass.
- Emits bounded, secret-free JSONL transitions (`differential.jsonl`) and a self-verifying
  canonical SHA-256 receipt (`ffmpeg-differential-receipt.json`) verifiable via `--verify-receipt`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent.parent
SCHEMA = "fss.lab_ffmpeg_differential_receipt.v1"
ORACLE_ROLE = "sealed_laboratory_oracle_only"
EXIT_OK = 0
EXIT_DIFF_FAIL = 1
EXIT_USAGE = 4
EXIT_UNAVAILABLE = 5

# Maximum per-pixel absolute delta allowed between pure-Rust scalar JPEG IDCT and FFmpeg's
# integer/SIMD IDCT on the reference 17x13 luma fixture (ISO/IEC 10918-2 permits +/-1..2 LSB).
JPEG_IDCT_MAX_ABS_DELTA = 2


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def compute_receipt_digest(receipt: dict[str, Any]) -> str:
    body = {k: v for k, v in receipt.items() if k != "receipt_digest"}
    return sha256_bytes(b"fss.lab_ffmpeg_differential_receipt.v1\0" + canonical_json_bytes(body))


def find_tool(explicit: str | None, name: str) -> str | None:
    if explicit:
        p = Path(explicit)
        return str(p) if p.is_file() and os.access(p, os.X_OK) else None
    found = shutil.which(name)
    if found:
        return found
    for fallback in (f"/opt/homebrew/bin/{name}", f"/usr/local/bin/{name}", f"/usr/bin/{name}"):
        if Path(fallback).is_file() and os.access(fallback, os.X_OK):
            return fallback
    return None


def find_fss_probe(explicit: str | None) -> str | None:
    if explicit:
        p = Path(explicit)
        return str(p) if p.is_file() and os.access(p, os.X_OK) else None
    target_base = Path(os.environ.get("CARGO_TARGET_DIR", str(REPO / "target")))
    candidates = [
        target_base / "debug" / "fss-probe",
        REPO / "target" / "debug" / "fss-probe",
        Path("/tmp/fss-mac-target/debug/fss-probe"),
    ]
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return str(c)
    for sub in sorted(target_base.glob("*/debug/fss-probe")):
        if sub.is_file() and os.access(sub, os.X_OK):
            return str(sub)
    return None


def tool_banner(binary: str) -> str:
    proc = subprocess.run(
        [binary, "-version"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    first = (proc.stdout or proc.stderr or "").splitlines()
    return first[0].strip() if first else "unknown"


def parse_fss_probe_kv(stdout: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for tok in stdout.strip().split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            out[k] = v
    return out


def normalize_container_family(fss_val: str) -> str:
    low = fss_val.lower()
    if low in ("isobmff", "iso-bmff", "mp4", "quicktime"):
        return "isobmff"
    if low in ("matroska", "mkv", "webm"):
        return "matroska"
    if low in ("jpeg", "mjpeg", "jfif"):
        return "jpeg"
    return low


def normalize_ffprobe_container(format_name: str) -> str:
    parts = {p.strip().lower() for p in format_name.split(",")}
    if parts & {"mp4", "mov", "3gp", "isom"}:
        return "isobmff"
    if parts & {"matroska", "webm"}:
        return "matroska"
    if parts & {"jpeg_pipe", "image2", "mjpeg"}:
        return "jpeg"
    return format_name.lower()


def normalize_codec(codec: str) -> str:
    low = codec.lower()
    if low in ("avc", "h264", "h.264", "avc1"):
        return "h264"
    if low in ("hevc", "h265", "h.265", "hvc1", "hev1"):
        return "hevc"
    if low in ("mjpeg", "jpeg"):
        return "mjpeg"
    return low


def run_fss_probe(binary: str, payload: bytes, args: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(
        [binary, *args],
        input=payload,
        capture_output=True,
        timeout=15,
        check=False,
    )
    return (
        proc.returncode,
        proc.stdout.decode("utf-8", errors="replace").strip(),
        proc.stderr.decode("utf-8", errors="replace").strip(),
    )


def run_ffprobe_json(ffprobe: str, path: Path) -> tuple[int, dict[str, Any] | None, str]:
    proc = subprocess.run(
        [
            ffprobe,
            "-v",
            "error",
            "-print_format",
            "json",
            "-show_format",
            "-show_streams",
            str(path),
        ],
        capture_output=True,
        timeout=15,
        check=False,
    )
    stderr = proc.stderr.decode("utf-8", errors="replace").strip()
    if proc.returncode != 0:
        return proc.returncode, None, stderr
    try:
        parsed = json.loads(proc.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        return 1, None, f"json decode error: {exc}"
    return 0, parsed, stderr


def run_parameter_case(
    case_id: str,
    rel_fixture: str,
    fss_probe: str,
    ffprobe: str,
) -> dict[str, Any]:
    path = REPO / rel_fixture
    raw = path.read_bytes()
    rc_fss, out_fss, err_fss = run_fss_probe(fss_probe, raw, ["--parameters"])
    rc_ff, data_ff, err_ff = run_ffprobe_json(ffprobe, path)

    divergences: list[str] = []
    fss_kv = parse_fss_probe_kv(out_fss)
    video_stream = None
    if data_ff is not None:
        for stream in data_ff.get("streams", []):
            if stream.get("codec_type") == "video":
                video_stream = stream
                break

    if rc_fss != 0:
        divergences.append(f"fss-probe exited {rc_fss}: {err_fss or out_fss}")
    if rc_ff != 0 or data_ff is None or video_stream is None:
        divergences.append(f"ffprobe exited {rc_ff}: {err_ff}")

    fss_summary: dict[str, Any] = {}
    ff_summary: dict[str, Any] = {}
    if not divergences and data_ff is not None and video_stream is not None:
        fss_container = normalize_container_family(fss_kv.get("container", ""))
        ff_container = normalize_ffprobe_container(str(data_ff.get("format", {}).get("format_name", "")))
        fss_codec = normalize_codec(fss_kv.get("codec", ""))
        ff_codec = normalize_codec(str(video_stream.get("codec_name", "")))
        fss_dw = int(fss_kv.get("display_width", "0"))
        fss_dh = int(fss_kv.get("display_height", "0"))
        ff_dw = int(video_stream.get("width", 0))
        ff_dh = int(video_stream.get("height", 0))
        fss_cw = int(fss_kv.get("coded_width", "0"))
        fss_ch = int(fss_kv.get("coded_height", "0"))
        ff_cw = int(video_stream.get("coded_width", ff_dw))
        ff_ch = int(video_stream.get("coded_height", ff_dh))

        fss_summary = {
            "container": fss_container,
            "codec": fss_codec,
            "display_width": fss_dw,
            "display_height": fss_dh,
            "coded_width": fss_cw,
            "coded_height": fss_ch,
        }
        ff_summary = {
            "container": ff_container,
            "codec": ff_codec,
            "display_width": ff_dw,
            "display_height": ff_dh,
            "coded_width": ff_cw,
            "coded_height": ff_ch,
        }
        if fss_container != ff_container:
            divergences.append(f"container mismatch: fss={fss_container} ffprobe={ff_container}")
        if fss_codec != ff_codec:
            divergences.append(f"codec mismatch: fss={fss_codec} ffprobe={ff_codec}")
        if (fss_dw, fss_dh) != (ff_dw, ff_dh):
            divergences.append(f"display dims mismatch: fss=({fss_dw},{fss_dh}) ffprobe=({ff_dw},{ff_dh})")
        if (fss_cw, fss_ch) != (ff_cw, ff_ch):
            divergences.append(f"coded dims mismatch: fss=({fss_cw},{fss_ch}) ffprobe=({ff_cw},{ff_ch})")

    return {
        "case_id": case_id,
        "kind": "positive_container_parameters",
        "fixture": rel_fixture,
        "fixture_digest": sha256_bytes(raw),
        "fixture_bytes": len(raw),
        "fss_exit": rc_fss,
        "ffprobe_exit": rc_ff,
        "fss_summary": fss_summary,
        "oracle_summary": ff_summary,
        "divergences": divergences,
        "status": "pass" if not divergences else "fail",
    }


def run_jpeg_pixel_case(
    case_id: str,
    rel_jpg: str,
    rel_gray: str | None,
    fss_probe: str,
    ffprobe: str,
    ffmpeg: str,
) -> dict[str, Any]:
    jpg_path = REPO / rel_jpg
    jpg_bytes = jpg_path.read_bytes()
    rc_fss, out_fss, _ = run_fss_probe(fss_probe, jpg_bytes, ["--bytes", "64"])
    rc_ff, data_ff, err_ff = run_ffprobe_json(ffprobe, jpg_path)

    divergences: list[str] = []
    if rc_fss != 0 or "jpeg" not in out_fss.lower():
        divergences.append(f"fss-probe failed jpeg signature: rc={rc_fss} out={out_fss!r}")

    video_stream = None
    if data_ff is not None:
        for stream in data_ff.get("streams", []):
            if stream.get("codec_type") == "video":
                video_stream = stream
                break
    if rc_ff != 0 or video_stream is None:
        divergences.append(f"ffprobe failed jpeg probe: rc={rc_ff} err={err_ff}")
    elif normalize_codec(str(video_stream.get("codec_name", ""))) != "mjpeg":
        divergences.append(f"unexpected ffprobe codec: {video_stream.get('codec_name')}")

    max_abs_delta: int | None = None
    pixel_count: int | None = None
    oracle_pixel_digest: str | None = None
    scalar_golden_digest: str | None = None
    if rel_gray is not None and not divergences:
        golden = (REPO / rel_gray).read_bytes()
        scalar_golden_digest = sha256_bytes(golden)
        proc = subprocess.run(
            [
                ffmpeg,
                "-v",
                "error",
                "-i",
                str(jpg_path),
                "-f",
                "rawvideo",
                "-pix_fmt",
                "gray",
                "-",
            ],
            capture_output=True,
            timeout=15,
            check=False,
        )
        if proc.returncode != 0:
            divergences.append(f"ffmpeg decode failed rc={proc.returncode}")
        else:
            decoded = proc.stdout
            oracle_pixel_digest = sha256_bytes(decoded)
            pixel_count = len(decoded)
            if len(decoded) != len(golden):
                divergences.append(
                    f"decoded byte length mismatch: ffmpeg={len(decoded)} scalar_golden={len(golden)}"
                )
            else:
                max_abs_delta = max(abs(a - b) for a, b in zip(decoded, golden))
                if max_abs_delta > JPEG_IDCT_MAX_ABS_DELTA:
                    divergences.append(
                        f"pixel delta {max_abs_delta} exceeds tolerance {JPEG_IDCT_MAX_ABS_DELTA}"
                    )

    return {
        "case_id": case_id,
        "kind": "positive_jpeg_probe_and_pixel_parity" if rel_gray else "positive_jpeg_probe",
        "fixture": rel_jpg,
        "fixture_digest": sha256_bytes(jpg_bytes),
        "fixture_bytes": len(jpg_bytes),
        "fss_exit": rc_fss,
        "ffprobe_exit": rc_ff,
        "pixel_count": pixel_count,
        "max_abs_delta": max_abs_delta,
        "tolerance_max_abs_delta": JPEG_IDCT_MAX_ABS_DELTA if rel_gray else None,
        "scalar_golden_digest": scalar_golden_digest,
        "oracle_pixel_digest": oracle_pixel_digest,
        "divergences": divergences,
        "status": "pass" if not divergences else "fail",
    }


def run_negative_case(
    case_id: str,
    payload: bytes,
    expected_fss_exit: int,
    fss_probe: str,
    ffprobe: str,
    scratch_dir: Path,
) -> dict[str, Any]:
    tmp_file = scratch_dir / f"{case_id}.bin"
    tmp_file.write_bytes(payload)
    rc_fss, out_fss, _ = run_fss_probe(fss_probe, payload, ["--bytes", str(min(len(payload), 64))])
    rc_ff, _, _ = run_ffprobe_json(ffprobe, tmp_file)

    divergences: list[str] = []
    if rc_fss != expected_fss_exit:
        divergences.append(f"fss-probe expected exit {expected_fss_exit}, got {rc_fss} ({out_fss!r})")
    if rc_ff == 0:
        divergences.append("ffprobe unexpectedly accepted hostile negative fixture (exit 0)")

    return {
        "case_id": case_id,
        "kind": "negative_hostile_input_refusal",
        "fixture": f"synthetic:{case_id}",
        "fixture_digest": sha256_bytes(payload),
        "fixture_bytes": len(payload),
        "expected_fss_exit": expected_fss_exit,
        "fss_exit": rc_fss,
        "ffprobe_exit": rc_ff,
        "divergences": divergences,
        "status": "pass" if not divergences else "fail",
    }


def run_bounded_limit_case(
    case_id: str,
    rel_fixture: str,
    fss_probe: str,
    ffprobe: str,
) -> dict[str, Any]:
    path = REPO / rel_fixture
    raw = path.read_bytes()
    rc_fss, out_fss, _ = run_fss_probe(fss_probe, raw, ["--parameters"])
    rc_ff, data_ff, _ = run_ffprobe_json(ffprobe, path)

    divergences: list[str] = []
    if rc_fss != 14:
        divergences.append(f"expected fss-probe bounded prefix limit exit 14, got {rc_fss} ({out_fss!r})")
    if rc_ff != 0 or data_ff is None:
        divergences.append(f"expected seeking ffprobe oracle to parse valid fixture, got exit {rc_ff}")

    return {
        "case_id": case_id,
        "kind": "bounded_prefix_limit_disclosed",
        "fixture": rel_fixture,
        "fixture_digest": sha256_bytes(raw),
        "fixture_bytes": len(raw),
        "expected_fss_exit": 14,
        "fss_exit": rc_fss,
        "ffprobe_exit": rc_ff,
        "divergences": divergences,
        "status": "pass" if not divergences else "fail",
    }


def verify_receipt(receipt_path: Path) -> tuple[bool, str]:
    if receipt_path.is_symlink():
        return False, "refused symlink receipt path"
    if not receipt_path.is_file():
        return False, f"receipt not found: {receipt_path}"
    try:
        doc = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"invalid JSON receipt: {exc}"
    if not isinstance(doc, dict):
        return False, "receipt root must be an object"
    if doc.get("schema") != SCHEMA:
        return False, f"unexpected schema: {doc.get('schema')!r}"
    if doc.get("oracle_role") != ORACLE_ROLE:
        return False, f"unexpected oracle_role: {doc.get('oracle_role')!r}"
    if doc.get("production_authority") is not False:
        return False, "production_authority must be strictly false"
    expected_digest = compute_receipt_digest(doc)
    if doc.get("receipt_digest") != expected_digest:
        return False, f"receipt_digest mismatch: got {doc.get('receipt_digest')!r}, expected {expected_digest!r}"
    cases = doc.get("cases")
    if not isinstance(cases, list) or not cases:
        return False, "receipt contains no cases"
    for c in cases:
        if not isinstance(c, dict) or c.get("status") != "pass" or c.get("divergences"):
            return False, f"non-passing case in receipt: {c.get('case_id') if isinstance(c, dict) else 'invalid'}"
    if doc.get("verdict") != "pass":
        return False, f"receipt verdict is not pass: {doc.get('verdict')!r}"
    return True, f"verified {len(cases)} sealed lab-oracle cases ({expected_digest})"


def read_pinned_toolchain() -> str:
    tc = REPO / "rust-toolchain.toml"
    if not tc.is_file():
        return "unknown"
    for line in tc.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("channel") and "=" in line:
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="FSS-118 sealed FFmpeg/ffprobe lab differential runner")
    parser.add_argument("--output-dir", type=Path, help="Directory for differential.jsonl and receipt")
    parser.add_argument("--verify-receipt", type=Path, help="Verify an existing differential receipt and exit")
    parser.add_argument("--fss-probe", type=str, default=None, help="Explicit path to fss-probe binary")
    parser.add_argument("--ffmpeg", type=str, default=None, help="Explicit path to ffmpeg binary")
    parser.add_argument("--ffprobe", type=str, default=None, help="Explicit path to ffprobe binary")
    parser.add_argument(
        "--simulate-missing-tool",
        action="store_true",
        help="Adversarial fault test: fail closed with exit 5 unavailable_lab_oracle",
    )
    args = parser.parse_args(argv)

    if args.verify_receipt is not None:
        ok, msg = verify_receipt(args.verify_receipt)
        print(f"RECEIPT_VERIFY status={'pass' if ok else 'fail'} detail={msg}")
        return EXIT_OK if ok else EXIT_DIFF_FAIL

    if args.output_dir is None:
        print("error: --output-dir is required unless --verify-receipt is given", file=sys.stderr)
        return EXIT_USAGE

    if args.simulate_missing_tool:
        print("error: unavailable_lab_oracle (simulated missing ffmpeg/ffprobe)", file=sys.stderr)
        return EXIT_UNAVAILABLE

    ffmpeg = find_tool(args.ffmpeg, "ffmpeg")
    ffprobe = find_tool(args.ffprobe, "ffprobe")
    fss_probe = find_fss_probe(args.fss_probe)
    missing = [
        name
        for name, path in (("ffmpeg", ffmpeg), ("ffprobe", ffprobe), ("fss-probe", fss_probe))
        if path is None
    ]
    if missing:
        print(
            f"error: unavailable_lab_oracle missing={','.join(missing)}; refusing to fabricate a pass",
            file=sys.stderr,
        )
        return EXIT_UNAVAILABLE

    assert ffmpeg is not None and ffprobe is not None and fss_probe is not None

    out_dir: Path = args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    started_ns = time.time_ns()

    cases: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="fss-118-neg-") as tmp:
        scratch = Path(tmp)
        cases.append(
            run_parameter_case(
                "mp4_avc_params",
                "crates/fss-container/tests/fixtures/fragmented_av.mp4",
                fss_probe,
                ffprobe,
            )
        )
        cases.append(
            run_parameter_case(
                "mp4_hevc_params",
                "crates/fss-container/tests/fixtures/hevc_fragmented_av.mp4",
                fss_probe,
                ffprobe,
            )
        )
        cases.append(
            run_parameter_case(
                "mkv_avc_params",
                "crates/fss-container/tests/fixtures/avc_av.mkv",
                fss_probe,
                ffprobe,
            )
        )
        cases.append(
            run_parameter_case(
                "mkv_hevc_params",
                "crates/fss-container/tests/fixtures/hevc_av.mkv",
                fss_probe,
                ffprobe,
            )
        )
        cases.append(
            run_parameter_case(
                "mp4_indexed_avc_params",
                "crates/fss-container/tests/fixtures/indexed_avc.mp4",
                fss_probe,
                ffprobe,
            )
        )
        cases.append(
            run_parameter_case(
                "qt_hevc_mov_params",
                "crates/fss-container/tests/fixtures/qt_hevc.mov",
                fss_probe,
                ffprobe,
            )
        )
        cases.append(
            run_bounded_limit_case(
                "bounded_prefix_limit_interleaved_mp4",
                "crates/fss-container/tests/fixtures/interleaved_av.mp4",
                fss_probe,
                ffprobe,
            )
        )
        cases.append(
            run_jpeg_pixel_case(
                "jpeg_gray_pixel_parity",
                "crates/fss-codec-mjpeg/tests/fixtures/gray.jpg",
                "crates/fss-codec-mjpeg/tests/fixtures/gray.gray",
                fss_probe,
                ffprobe,
                ffmpeg,
            )
        )
        cases.append(
            run_jpeg_pixel_case(
                "jpeg_y420_restart_probe",
                "crates/fss-codec-mjpeg/tests/fixtures/y420_restart.jpg",
                None,
                fss_probe,
                ffprobe,
                ffmpeg,
            )
        )
        cases.append(
            run_negative_case("neg_truncated_header", b"FLV", 10, fss_probe, ffprobe, scratch)
        )
        cases.append(
            run_negative_case(
                "neg_corrupt_garbage",
                bytes((i * 73 + 19) & 0xFF for i in range(64)),
                11,
                fss_probe,
                ffprobe,
                scratch,
            )
        )
        cases.append(
            run_negative_case(
                "neg_contradictory_header",
                b"\x00\x00\x01\x67ftypisom\x00\x00\x00\x00",
                12,
                fss_probe,
                ffprobe,
                scratch,
            )
        )

    finished_ns = time.time_ns()
    all_passed = all(c["status"] == "pass" for c in cases)

    jsonl_path = out_dir / "differential.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for idx, case in enumerate(cases, start=1):
            event = {
                "schema_version": 1,
                "requirement_id": "FSS-118",
                "bead_id": "fss-x4a.12.17",
                "step_index": idx,
                "case_id": case["case_id"],
                "kind": case["kind"],
                "oracle_role": ORACLE_ROLE,
                "fixture": case["fixture"],
                "fixture_digest": case["fixture_digest"],
                "status": case["status"],
                "divergences": case["divergences"],
            }
            fh.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")

    receipt: dict[str, Any] = {
        "schema": SCHEMA,
        "requirement_id": "FSS-118",
        "bead_id": "fss-x4a.12.17",
        "oracle_role": ORACLE_ROLE,
        "production_authority": False,
        "claim_scope": "local_lab_differential_parity_over_pinned_fixtures",
        "excluded_dimensions": [
            "production_runtime",
            "source_custody_authority",
            "hardware_decode_acceleration",
            "cross_platform_release_matrix",
        ],
        "host_target": f"{platform.system()}-{platform.machine()}",
        "pinned_toolchain": read_pinned_toolchain(),
        "oracle_versions": {
            "ffmpeg": tool_banner(ffmpeg),
            "ffprobe": tool_banner(ffprobe),
        },
        "started_ns": started_ns,
        "finished_ns": finished_ns,
        "cases_total": len(cases),
        "cases_passed": sum(1 for c in cases if c["status"] == "pass"),
        "verdict": "pass" if all_passed else "fail",
        "jsonl_log_digest": sha256_file(jsonl_path),
        "cases": cases,
    }
    receipt["receipt_digest"] = compute_receipt_digest(receipt)

    receipt_path = out_dir / "ffmpeg-differential-receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(
        f"CAPLOG fss_118_lab_differential verdict={receipt['verdict']} "
        f"cases_ok={receipt['cases_passed']}/{receipt['cases_total']} "
        f"receipt_digest={receipt['receipt_digest']}"
    )
    return EXIT_OK if all_passed else EXIT_DIFF_FAIL


if __name__ == "__main__":
    sys.exit(main())
