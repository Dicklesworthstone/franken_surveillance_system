#!/usr/bin/env python3
"""First-footage auto-acceptance gate after enrollment (fss-footage-acceptance-7kj8s).

Executes one bounded, authenticated media acquisition through the NATIVE pure-Rust
FSS pipeline (zero ffmpeg in the acceptance path):

  fss-capture-rtsp (plan -> exact --approve -> bounded RTSP/TCP capture, durable GOP windows)
    -> fss-import-rtsp (plan -> exact --approve -> source-preserving import + causal timing bounds)
    -> fss-event watch --sensor-health conservative-v1 (pure-Rust decode + anti-frozen/dark/flat
       screening + foreground motion track + CoverageWitness retention)
    -> fss session orient --json (SituationFrame + epistemic coverage & event check)

Preserves SEPARATE, ORTHOGONAL typed predicates (never collapsed into one score):
  1. admin_receipt   — pinned SSH host-key SHA-256 + uid=0 on new firmware (or RootProof JSON)
  2. fw_identity     — verified firmware identity + family compatibility row
                       (TP-Link Tapo C460/C660 battery models have NO stock RTSP and require
                       verified sensor/encoder/duty-cycle support, not an ONVIF checkbox)
  3. media_auth      — exact authenticated RTSP session + codec profile via fss-capture-rtsp
  4. source_receipt  — durable window custody, origin proofs, and explicit wire omissions
  5. continuity      — clean capture completion, timing uncertainty, gap honesty, CoverageWitness
  6. visible_event   — anti-stale/anti-frozen predicate via pure-Rust sensor-health screening,
                       unique per-frame luma digests, contrast span, and visible motion candidate

Scope separation:
  - Local acceptance is evaluated FIRST (`local_scope`).
  - Tailnet acceptance is tracked in a SEPARATE row (`tailnet_scope`) when `--tailnet-host` is set.

Exit codes:
  0  requested acceptance gate passed (`local_media_accepted`, or `full_post_flash_accepted` with --require-full)
  1  gate ran and at least one required predicate failed
  2  CLI/configuration/infrastructure error (missing native binaries, unreadable cred file, unknown family)
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent

# Explicit camera-family compatibility matrix.
# TP-Link C460/C660 are battery cameras WITHOUT stock RTSP: post-flash acceptance requires
# verified sensor/encoder/duty-cycle compatibility proof, never just an ONVIF checkbox.
CAMERA_FAMILIES: dict[str, dict[str, Any]] = {
    "wyze-hl_cam4": {
        "model_class": "Wyze Cam v4 (Ingenic T41NQ / OS04D10)",
        "power_profile": "wired",
        "stock_rtsp": True,
        "post_flash_target": "thingino",
        "requires_battery_compat_row": False,
        "notes": "Wired camera; stock SmolRTSP (1 conn/IP, in-band SPS/PPS) or Thingino prudynt RTSP+ONVIF.",
    },
    "tapo-c460": {
        "model_class": "TP-Link Tapo C460 (SigmaStar battery PIR)",
        "power_profile": "battery_pir",
        "stock_rtsp": False,
        "post_flash_target": "custom-sstar",
        "requires_battery_compat_row": True,
        "battery_required_checks": ["sensor_driver", "encoder_pipeline", "duty_cycle_budget"],
        "notes": (
            "Battery model WITHOUT stock RTSP; post-flash acceptance requires verified "
            "sensor driver, hardware encoder pipeline, and duty-cycle budget (not an ONVIF checkbox)."
        ),
    },
    "tapo-c660": {
        "model_class": "TP-Link Tapo C660 (SigmaStar battery PIR)",
        "power_profile": "battery_pir",
        "stock_rtsp": False,
        "post_flash_target": "custom-sstar",
        "requires_battery_compat_row": True,
        "battery_required_checks": ["sensor_driver", "encoder_pipeline", "duty_cycle_budget"],
        "notes": (
            "Battery model WITHOUT stock RTSP; post-flash acceptance requires verified "
            "sensor driver, hardware encoder pipeline, and duty-cycle budget (not an ONVIF checkbox)."
        ),
    },
    "unifi-g4-instant": {
        "model_class": "Ubiquiti UniFi UVC G4 Instant (SAV530q)",
        "power_profile": "wired",
        "stock_rtsp": False,
        "post_flash_target": "native-unifi-direct-or-protect-rtsps",
        "requires_battery_compat_row": False,
        "notes": "Wired camera; native UniFi discovery + RTSPS/HTTPS Direct (TLS gated on ADR-0014/VIT-016).",
    },
    "owlet": {
        "model_class": "Owlet Cam (Cubo/TUTK)",
        "power_profile": "wired",
        "stock_rtsp": False,
        "post_flash_target": "tbd",
        "requires_battery_compat_row": False,
        "notes": "Wired camera without stock RTSP.",
    },
    "yi": {
        "model_class": "Yi IPC (Zowee)",
        "power_profile": "wired",
        "stock_rtsp": False,
        "post_flash_target": "yi-hack-or-openipc",
        "requires_battery_compat_row": False,
        "notes": "Wired camera without stock RTSP.",
    },
    "aosu-tuya": {
        "model_class": "AOSU (Tuya HomeBase)",
        "power_profile": "battery_homebase",
        "stock_rtsp": False,
        "post_flash_target": "tbd",
        "requires_battery_compat_row": True,
        "battery_required_checks": ["sensor_driver", "encoder_pipeline", "duty_cycle_budget"],
        "notes": "Battery/HomeBase camera without stock RTSP; requires sensor/encoder/duty-cycle proof.",
    },
    "generic-rtsp": {
        "model_class": "Generic wired RTSP camera",
        "power_profile": "wired",
        "stock_rtsp": True,
        "post_flash_target": "native-rtsp",
        "requires_battery_compat_row": False,
        "notes": "Generic wired RTSP/ONVIF camera.",
    },
}


def sha256_str(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    payload = json.dumps(data, indent=2, sort_keys=False) + "\n"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def resolve_binaries(bin_dir: str | None) -> tuple[dict[str, Path] | None, str | None]:
    candidates: list[Path] = []
    if bin_dir:
        candidates.append(Path(bin_dir))
    if os.environ.get("FSS_BIN_DIR"):
        candidates.append(Path(os.environ["FSS_BIN_DIR"]))
    candidates.extend([
        REPO_ROOT / "target" / "rch-camera-bins",
        REPO_ROOT / "target" / "debug",
        Path(os.environ.get("CARGO_TARGET_DIR", "/data/cargo-targets")) / "debug",
    ])
    names = ("fss-capture-rtsp", "fss-import-rtsp", "fss-event", "fss")
    found: dict[str, Path] = {}
    for name in names:
        for directory in candidates:
            cand = directory / name
            if cand.is_file() and os.access(cand, os.X_OK):
                found[name] = cand
                break
        if name not in found:
            return None, f"missing required native FSS binary {name!r} (searched {[str(c) for c in candidates]})"
    return found, None


def _run_cmd(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def _run_cmd_safe(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    """Run subprocess without letting TimeoutExpired/OSError escape as a raw traceback."""
    try:
        return _run_cmd(cmd, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        suffix = f"command_timeout_after_{timeout}s"
        return subprocess.CompletedProcess(cmd, 124, out, f"{err}\n{suffix}".strip() if err else suffix)
    except OSError as exc:
        return subprocess.CompletedProcess(cmd, 127, "", f"command_exec_error:{exc}")


# ---------------------------------------------------------------------------
# Predicate 1: admin_receipt (pinned SSH host-key SHA-256 + uid=0, or RootProof JSON)
# ---------------------------------------------------------------------------

def evaluate_admin_receipt(
    *,
    admin_receipt_json: str | None,
    ssh_host: str | None,
    ssh_port: int,
    ssh_user: str,
    ssh_key: str | None,
    ssh_pinned_hostkey: str | None,
    timeout: float,
    ssh_cmd: str = "ssh",
    ssh_keyscan_cmd: str = "ssh-keyscan",
    ssh_keygen_cmd: str = "ssh-keygen",
) -> dict[str, Any]:
    if admin_receipt_json:
        p = Path(admin_receipt_json)
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {
                "status": "failed",
                "reason": f"unreadable_admin_receipt_json: {exc}",
                "source": str(p),
                "checks": {},
            }
        if not isinstance(doc, dict):
            return {
                "status": "failed",
                "reason": f"admin_receipt_json_not_object:{type(doc).__name__}",
                "source": str(p),
                "checks": {},
            }
        vector = str(doc.get("vector") or "")
        passed_flag = bool(doc.get("pass"))
        checks_list = doc.get("checks") if isinstance(doc.get("checks"), list) else []
        uid0_seen = any(
            bool(c.get("pass")) and "uid=0(" in str(c.get("got") or "")
            for c in checks_list
            if isinstance(c, dict)
        )
        observed_fp = doc.get("pinned_hostkey_sha256") or doc.get("ssh_hostkey_sha256")
        pin_ok = True
        if ssh_pinned_hostkey:
            pin_ok = isinstance(observed_fp, str) and observed_fp == ssh_pinned_hostkey
        allowed_vectors = ("dropbear22", "telnet9999", "telnet4444", "uart-console", "pinned-ssh")
        vector_ok = vector in allowed_vectors
        ok = passed_flag and uid0_seen and pin_ok and vector_ok
        reason = "verified_from_root_proof_artifact" if ok else (
            "ssh_hostkey_pin_mismatch" if not pin_ok else
            f"unsupported_admin_vector:{vector or 'missing'}" if (passed_flag and uid0_seen and not vector_ok) else
            "root_proof_missing_uid0_or_failed"
        )
        return {
            "status": "passed" if ok else "failed",
            "reason": reason,
            "source": str(p),
            "checks": {
                "vector": vector,
                "artifact_pass": passed_flag,
                "uid0_verified": uid0_seen,
                "pinned_hostkey_expected": ssh_pinned_hostkey,
                "pinned_hostkey_observed": observed_fp,
                "pinned_hostkey_matched": pin_ok if ssh_pinned_hostkey else None,
            },
        }

    if ssh_host:
        if not ssh_pinned_hostkey:
            return {
                "status": "failed",
                "reason": "ssh_host_requires_explicit_ssh_pinned_hostkey_sha256",
                "source": f"{ssh_user}@{ssh_host}:{ssh_port}",
                "checks": {"pinned_hostkey_expected": None},
            }
        try:
            scan = _run_cmd(
                [ssh_keyscan_cmd, "-T", str(max(1, int(timeout))), "-p", str(ssh_port), ssh_host],
                timeout=timeout + 5,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {
                "status": "failed",
                "reason": f"ssh_keyscan_error: {exc}",
                "source": f"{ssh_user}@{ssh_host}:{ssh_port}",
                "checks": {"pinned_hostkey_expected": ssh_pinned_hostkey},
            }
        key_lines = [ln for ln in (scan.stdout or "").splitlines() if ln.strip() and not ln.startswith("#")]
        if scan.returncode != 0 or not key_lines:
            return {
                "status": "failed",
                "reason": "ssh_keyscan_returned_no_host_keys",
                "source": f"{ssh_user}@{ssh_host}:{ssh_port}",
                "checks": {"pinned_hostkey_expected": ssh_pinned_hostkey},
            }
        with tempfile.TemporaryDirectory(prefix="fss-ssh-pin-") as tmpdir:
            matched_key_lines: list[str] = []
            observed_fps: list[str] = []
            for idx, kline in enumerate(key_lines):
                probe_kh = Path(tmpdir) / f"probe_{idx}.pub"
                probe_kh.write_text(kline + "\n", encoding="utf-8")
                try:
                    fp_proc = _run_cmd([ssh_keygen_cmd, "-lf", str(probe_kh), "-E", "sha256"], timeout=timeout + 5)
                except (OSError, subprocess.TimeoutExpired) as exc:
                    return {
                        "status": "failed",
                        "reason": f"ssh_keygen_fingerprint_error: {exc}",
                        "source": f"{ssh_user}@{ssh_host}:{ssh_port}",
                        "checks": {"pinned_hostkey_expected": ssh_pinned_hostkey},
                    }
                line_fps = re.findall(r"(SHA256:[A-Za-z0-9+/=]+)", fp_proc.stdout or "")
                observed_fps.extend(line_fps)
                if ssh_pinned_hostkey in line_fps:
                    matched_key_lines.append(kline)
            if not matched_key_lines:
                return {
                    "status": "failed",
                    "reason": "ssh_hostkey_pin_mismatch",
                    "source": f"{ssh_user}@{ssh_host}:{ssh_port}",
                    "checks": {
                        "pinned_hostkey_expected": ssh_pinned_hostkey,
                        "pinned_hostkey_observed": observed_fps,
                        "pinned_hostkey_matched": False,
                    },
                }
            # Write ONLY the exact pinned host-key line(s) into known_hosts so ssh cannot
            # silently negotiate an unpinned secondary key offered by the server.
            kh_path = Path(tmpdir) / "known_hosts"
            kh_path.write_text("\n".join(matched_key_lines) + "\n", encoding="utf-8")
            cmd = [
                ssh_cmd,
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={kh_path}",
                "-o", f"ConnectTimeout={max(1, int(timeout))}",
                "-p", str(ssh_port),
            ]
            if ssh_key:
                cmd.extend(["-i", ssh_key])
            cmd.extend([f"{ssh_user}@{ssh_host}", "id"])
            try:
                id_proc = _run_cmd(cmd, timeout=timeout + 8)
            except (OSError, subprocess.TimeoutExpired) as exc:
                return {
                    "status": "failed",
                    "reason": f"pinned_ssh_exec_error: {exc}",
                    "source": f"{ssh_user}@{ssh_host}:{ssh_port}",
                    "checks": {
                        "pinned_hostkey_expected": ssh_pinned_hostkey,
                        "pinned_hostkey_matched": True,
                    },
                }
            uid_out = (id_proc.stdout or "").strip()
            uid0_ok = id_proc.returncode == 0 and bool(re.search(r"\buid=0\(", uid_out))
            return {
                "status": "passed" if uid0_ok else "failed",
                "reason": "pinned_ssh_uid0_verified" if uid0_ok else f"pinned_ssh_uid0_failed_rc_{id_proc.returncode}",
                "source": f"{ssh_user}@{ssh_host}:{ssh_port}",
                "checks": {
                    "pinned_hostkey_expected": ssh_pinned_hostkey,
                    "pinned_hostkey_observed": observed_fps,
                    "pinned_hostkey_matched": True,
                    "ssh_rc": id_proc.returncode,
                    "uid_output": uid_out[:200],
                    "uid0_verified": uid0_ok,
                },
            }

    return {
        "status": "not_verified",
        "reason": "no_admin_receipt_or_pinned_ssh_supplied",
        "source": None,
        "checks": {},
    }


# ---------------------------------------------------------------------------
# Predicate 2: fw_identity + battery/family compatibility row
# ---------------------------------------------------------------------------

def _query_onvif_device_info(host: str, port: int, timeout: float, path: str = "/onvif/device_service") -> tuple[dict[str, str] | None, str]:
    envelope = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
        "<s:Body><tds:GetDeviceInformation/></s:Body></s:Envelope>"
    ).encode("utf-8")
    req = (
        f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        f"Content-Type: application/soap+xml; charset=utf-8\r\n"
        f"Content-Length: {len(envelope)}\r\nConnection: close\r\n\r\n"
    ).encode("utf-8") + envelope
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(req)
            buf = b""
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline and len(buf) < 65536:
                try:
                    chunk = sock.recv(4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                if b"</s:Envelope>" in buf:
                    break
    except OSError as exc:
        return None, f"onvif_connect_error: {exc}"
    text = buf.decode("utf-8", "replace")
    body_m = re.search(r"<tds:GetDeviceInformationResponse>(?P<body>.*?)</tds:GetDeviceInformationResponse>", text, re.S)
    if not body_m:
        return None, f"no_GetDeviceInformationResponse ({len(text)} bytes)"
    body = body_m.group("body")
    out: dict[str, str] = {}
    for field in ("Manufacturer", "Model", "FirmwareVersion", "SerialNumber", "HardwareId"):
        fm = re.search(rf"<tds:{field}>([^<]+)</tds:{field}>", body)
        if fm:
            out[field] = fm.group(1).strip()
    missing = [f for f in ("Manufacturer", "Model", "FirmwareVersion") if f not in out]
    if missing:
        return None, f"missing_onvif_fields: {missing}"
    return out, "ok"


def evaluate_fw_identity(
    *,
    family: str,
    onvif_host: str | None,
    onvif_port: int,
    fw_identity_json: str | None,
    compat_proof_json: str | None,
    expect_manufacturer: str | None,
    expect_model: str | None,
    expect_firmware: str | None,
    timeout: float,
) -> dict[str, Any]:
    fam_info = CAMERA_FAMILIES[family]
    compat_row: dict[str, Any] = {
        "family": family,
        "model_class": fam_info["model_class"],
        "power_profile": fam_info["power_profile"],
        "stock_rtsp": fam_info["stock_rtsp"],
        "post_flash_target": fam_info["post_flash_target"],
        "requires_battery_compat_row": fam_info["requires_battery_compat_row"],
        "battery_compat_checks": None,
        "battery_compat_satisfied": None,
        "notes": fam_info["notes"],
    }

    identity_data: dict[str, Any] | None = None
    source: str | None = None
    probe_error: str | None = None

    if fw_identity_json:
        p = Path(fw_identity_json)
        source = str(p)
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                probe_error = f"fw_identity_json_not_object:{type(raw).__name__}"
            else:
                identity_data = {
                    "Manufacturer": str(raw.get("manufacturer") or raw.get("Manufacturer") or ""),
                    "Model": str(raw.get("model") or raw.get("Model") or ""),
                    "FirmwareVersion": str(raw.get("firmware_version") or raw.get("FirmwareVersion") or ""),
                }
                if not all(identity_data.values()):
                    probe_error = "fw_identity_json_missing_manufacturer_model_or_firmware_version"
        except (OSError, json.JSONDecodeError) as exc:
            probe_error = f"unreadable_fw_identity_json: {exc}"
    elif onvif_host:
        source = f"onvif://{onvif_host}:{onvif_port}/onvif/device_service"
        identity_data, detail = _query_onvif_device_info(onvif_host, onvif_port, timeout)
        if identity_data is None:
            probe_error = detail

    # Battery model compatibility gate (C460/C660/AOSU): an ONVIF checkbox is NOT sufficient!
    battery_ok = True
    if fam_info["requires_battery_compat_row"]:
        req_keys = fam_info.get("battery_required_checks", ["sensor_driver", "encoder_pipeline", "duty_cycle_budget"])
        compat_doc: dict[str, Any] = {}
        if compat_proof_json:
            try:
                loaded_compat = json.loads(Path(compat_proof_json).read_text(encoding="utf-8"))
                if isinstance(loaded_compat, dict):
                    compat_doc = loaded_compat
                else:
                    compat_doc = {"_error": f"compat_proof_json_not_object:{type(loaded_compat).__name__}"}
            except (OSError, json.JSONDecodeError) as exc:
                compat_doc = {"_error": str(exc)}
        checks = {k: bool(compat_doc.get(k) is True) for k in req_keys}
        battery_ok = all(checks.values()) and ("_error" not in compat_doc)
        compat_row["battery_compat_checks"] = checks
        compat_row["battery_compat_satisfied"] = battery_ok
        if "_error" in compat_doc:
            compat_row["battery_compat_error"] = compat_doc["_error"]

    if probe_error:
        return {
            "status": "failed",
            "reason": probe_error,
            "source": source,
            "identity": identity_data,
            "compatibility_row": compat_row,
        }

    if fam_info["requires_battery_compat_row"] and not battery_ok:
        return {
            "status": "failed",
            "reason": "battery_model_no_stock_rtsp_requires_verified_sensor_encoder_duty_cycle_proof",
            "source": source,
            "identity": identity_data,
            "compatibility_row": compat_row,
        }

    if identity_data is None:
        return {
            "status": "not_verified",
            "reason": "no_fw_identity_probe_or_json_supplied",
            "source": None,
            "identity": None,
            "compatibility_row": compat_row,
        }

    mismatches: list[str] = []
    if expect_manufacturer and expect_manufacturer.lower() not in identity_data["Manufacturer"].lower():
        mismatches.append(f"manufacturer={identity_data['Manufacturer']!r} expected~={expect_manufacturer!r}")
    if expect_model and expect_model.lower() not in identity_data["Model"].lower():
        mismatches.append(f"model={identity_data['Model']!r} expected~={expect_model!r}")
    if expect_firmware and expect_firmware.lower() not in identity_data["FirmwareVersion"].lower():
        mismatches.append(f"firmware={identity_data['FirmwareVersion']!r} expected~={expect_firmware!r}")

    if mismatches:
        return {
            "status": "failed",
            "reason": "fw_identity_expectation_mismatch: " + "; ".join(mismatches),
            "source": source,
            "identity": identity_data,
            "compatibility_row": compat_row,
        }

    return {
        "status": "passed",
        "reason": "fw_identity_verified",
        "source": source,
        "identity": identity_data,
        "compatibility_row": compat_row,
    }


# ---------------------------------------------------------------------------
# Native pure-Rust media acquisition + import + watch + orient
# ---------------------------------------------------------------------------

def parse_capture_jsonl(path: Path) -> dict[str, Any]:
    started: dict[str, Any] | None = None
    terminal: dict[str, Any] | None = None
    windows: list[dict[str, Any]] = []
    protocols: list[str] = []
    requests: list[dict[str, Any]] = []
    catalog: dict[str, Any] | None = None

    if not path.is_file():
        return {
            "started": None,
            "terminal": None,
            "windows": [],
            "protocols": [],
            "requests": [],
            "catalog": None,
        }

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            kind = rec.get("kind")
            detail = rec.get("detail") if isinstance(rec.get("detail"), dict) else rec
            if kind == "started":
                started = detail
            elif kind == "terminal":
                terminal = detail
            elif kind == "window_durable":
                windows.append(detail)
            elif kind == "protocol":
                st = detail.get("state")
                if isinstance(st, str):
                    protocols.append(st)
            elif kind == "request_queued":
                requests.append(detail)
            elif kind == "catalog_published":
                catalog = detail

    return {
        "started": started,
        "terminal": terminal,
        "windows": windows,
        "protocols": protocols,
        "requests": requests,
        "catalog": catalog,
    }


def _find_free_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return int(s.getsockname()[1])


def run_native_footage_pipeline(
    *,
    bins: dict[str, Path],
    work_dir: Path,
    sensor_id: str,
    stream_id: str,
    site: str,
    codec: str,
    peer: str | None,
    authority: str | None,
    presentation: str,
    control_root: str | None,
    credential_file: str | None,
    auth_realm: str | None,
    require_auth: bool,
    pictures: int,
    frame_duration_ticks: int,
    source_duration_max_ticks: int | None,
    source_no_reorder: bool,
    ssrc: str,
    capture_timeout_ms: int,
    zone: str,
    pixel_threshold: int,
    min_region_pixels: int,
    min_frames: int,
    min_unique_luma_digests: int,
    min_contrast_span: int,
    max_repeated_frames: int,
    visible_event_mode: str,
    publish_event: bool,
    include_capture_time_hint: bool,
    from_archive: str | None,
    capture_jsonl_in: str | None,
    bridge_status_path: str | None,
    wyze_bridge_cam_ip: str | None,
) -> dict[str, Any]:
    """Run native pure-Rust capture -> import -> watch(--sensor-health) -> orient."""
    bridge_proc: subprocess.Popen[str] | None = None
    bridge_status: dict[str, Any] | None = None
    effective_peer = peer
    effective_authority = authority
    effective_cred_file = credential_file
    effective_realm = auth_realm

    try:
        # Optional Wyze single-session RTSP bridge (localhost ephemeral port + random SHA-256 Digest cred)
        if wyze_bridge_cam_ip:
            if not credential_file or not Path(credential_file).is_file():
                raise ValueError("--use-wyze-bridge requires a readable --credential-file for upstream Wyze creds")
            bport = _find_free_port("127.0.0.1")
            dn_cred = work_dir / "bridge_downstream.cred"
            dn_pass = secrets.token_hex(12)
            dn_cred.write_text(f"fssaccept\n{dn_pass}\n", encoding="utf-8")
            os.chmod(dn_cred, 0o600)
            b_status_file = work_dir / "bridge_status.json"
            b_log_file = work_dir / "bridge.log"
            bridge_script = HERE / "wyze_rtsp_bridge.py"
            with open(b_log_file, "w", encoding="utf-8") as blog:
                bridge_proc = subprocess.Popen(
                    [
                        sys.executable, str(bridge_script),
                        "--upstream-host", wyze_bridge_cam_ip,
                        "--upstream-port", "554",
                        "--upstream-path", presentation,
                        "--upstream-cred-file", credential_file,
                        "--listen-host", "127.0.0.1",
                        "--listen-port", str(bport),
                        "--listen-path", presentation,
                        "--downstream-cred-file", str(dn_cred),
                        "--downstream-realm", "fss-accept-bridge",
                        "--status-file", str(b_status_file),
                    ],
                    stdout=blog,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
            deadline = time.monotonic() + 20.0
            while time.monotonic() < deadline:
                if bridge_proc.poll() is not None:
                    break
                if b_status_file.is_file():
                    try:
                        st = json.loads(b_status_file.read_text(encoding="utf-8"))
                        if st.get("ready"):
                            bridge_status = st
                            break
                    except ValueError:
                        pass
                time.sleep(0.25)
            if bridge_status is None:
                log_tail = b_log_file.read_text(encoding="utf-8", errors="replace")[-500:]
                return _fail_media_bundle(
                    f"wyze_bridge_not_ready: {log_tail}",
                    bridge_status=None,
                )
            effective_peer = f"127.0.0.1:{bport}"
            effective_authority = effective_peer
            effective_cred_file = str(dn_cred)
            effective_realm = "fss-accept-bridge"
            bridge_status_path = str(b_status_file)

        # Deterministic anchors for this acceptance session (derived from sensor/stream; never secrets)
        anchor = sha256_str(f"fss-footage-accept-anchor-{sensor_id}-{stream_id}")
        receive_clock = sha256_str(f"fss-footage-accept-clock-{sensor_id}-{stream_id}")
        timing_evidence = sha256_str(f"fss-footage-accept-timing-{sensor_id}-{stream_id}")
        journal_id = sha256_str(f"fss-footage-accept-journal-{sensor_id}-{stream_id}")

        capture_rc = 0
        capture_stderr = ""
        capture_plan_approval: str | None = None
        t_before_capture_ns = time.time_ns()
        t_after_capture_ns = t_before_capture_ns

        if from_archive:
            archive_dir = Path(from_archive)
            capture_jsonl = Path(capture_jsonl_in) if capture_jsonl_in else (archive_dir.parent / "capture.jsonl")
            parsed_cap = parse_capture_jsonl(capture_jsonl)
            if parsed_cap["started"] and isinstance(parsed_cap["started"].get("source"), dict):
                src = parsed_cap["started"]["source"]
                anchor = str(src.get("anchor") or anchor)
                receive_clock = str(src.get("receive_clock") or receive_clock)
                sensor_id = str(src.get("sensor_id") or sensor_id)
                stream_id = str(src.get("stream_id") or stream_id)
            if parsed_cap["terminal"] and parsed_cap["terminal"].get("complete") is False:
                capture_rc = 1
        else:
            assert effective_peer is not None
            archive_dir = work_dir / "archive"
            pins_dir = work_dir / "pins"
            capture_jsonl = work_dir / "capture.jsonl"
            ctrl_root = control_root if control_root is not None else presentation
            cap_args = [
                str(bins["fss-capture-rtsp"]),
                "--root", str(archive_dir),
                "--pins", str(pins_dir),
                "--peer", effective_peer,
                "--authority", effective_authority or effective_peer,
                "--presentation", presentation,
                "--control-root", ctrl_root,
                "--sensor-id", sensor_id,
                "--stream-id", stream_id,
                "--generation", "1",
                "--ingress", "1",
                "--ssrc", ssrc,
                "--anchor", anchor,
                "--receive-clock", receive_clock,
                "--timing-evidence", timing_evidence,
                "--journal-id", journal_id,
                "--frame-duration-ticks", str(frame_duration_ticks),
                "--stop-after-pictures", str(pictures),
                "--owner-authorized", "yes",
                "--plaintext", "yes",
                "--retain-originals", "yes",
                "--timeout-ms", str(capture_timeout_ms),
                "--drain-timeout-ms", str(min(capture_timeout_ms, 15000)),
                "--response-timeout-ms", str(min(capture_timeout_ms, 15000)),
                "--max-storage-pause-ms", str(min(capture_timeout_ms, 30000)),
            ]
            if source_duration_max_ticks is not None:
                cap_args.extend(["--source-duration-max-ticks", str(source_duration_max_ticks)])
            if source_no_reorder:
                cap_args.extend(["--source-no-reorder", "yes"])
            if effective_cred_file:
                cap_args.extend(["--credential-file", effective_cred_file])
            if effective_realm:
                cap_args.extend(["--auth-realm", effective_realm])

            # Step 1: pure plan
            plan_proc = _run_cmd_safe(cap_args, timeout=30.0)
            if plan_proc.returncode != 0:
                return _fail_media_bundle(
                    f"capture_plan_failed_rc_{plan_proc.returncode}: {(plan_proc.stderr or plan_proc.stdout).strip()[:300]}",
                    bridge_status=bridge_status,
                )
            try:
                plan_doc = json.loads(plan_proc.stdout)
                capture_plan_approval = str(plan_doc["approval"])
            except (ValueError, KeyError) as exc:
                return _fail_media_bundle(f"capture_plan_parse_error: {exc}", bridge_status=bridge_status)

            # Step 2: approved bounded live capture
            t_before_capture_ns = time.time_ns()
            cap_proc = _run_cmd_safe(
                cap_args + ["--approve", capture_plan_approval],
                timeout=max(30.0, capture_timeout_ms / 1000.0 + 15.0),
            )
            t_after_capture_ns = time.time_ns()
            capture_rc = cap_proc.returncode
            capture_stderr = (cap_proc.stderr or "").strip()
            capture_jsonl.write_text(cap_proc.stdout or "", encoding="utf-8")
            parsed_cap = parse_capture_jsonl(capture_jsonl)

        if bridge_status_path and Path(bridge_status_path).is_file():
            try:
                bridge_status = json.loads(Path(bridge_status_path).read_text(encoding="utf-8"))
            except ValueError:
                pass

        started = parsed_cap["started"] or {}
        terminal = parsed_cap["terminal"] or {}
        windows = parsed_cap["windows"]
        protocols = parsed_cap["protocols"]

        # ---- Evaluate Predicate 3: media_auth ----
        auth_mode = str(terminal.get("authentication") or started.get("authentication") or "none")
        auth_challenges = int(terminal.get("authentication_challenges") or 0)
        digest_reqs = int(terminal.get("digest_requests_queued") or 0)
        rtsp_progressed = all(st in protocols for st in ("described", "ready", "playing"))
        auth_satisfied = (not require_auth) or (auth_mode != "none" and (auth_challenges >= 1 or digest_reqs >= 1))
        cap_error_id = terminal.get("error_id")
        codec_obs = str(terminal.get("codec") or started.get("codec") or "")
        codec_matched = codec_obs == codec if codec_obs else False
        media_auth_ok = bool(started) and rtsp_progressed and auth_satisfied and codec_matched and (
            cap_error_id is None or "AUTH" not in str(cap_error_id)
        )
        # If capture failed before playing (e.g., auth error 401), media_auth MUST fail!
        if capture_rc != 0 and not rtsp_progressed:
            media_auth_ok = False

        media_auth_reason = "authenticated_rtsp_session_verified" if media_auth_ok else (
            f"rtsp_auth_required_got_{auth_mode}" if not auth_satisfied else
            f"rtsp_protocol_incomplete:{protocols}" if not rtsp_progressed else
            f"codec_mismatch:got_{codec_obs}_want_{codec}" if not codec_matched else
            f"capture_failed:{cap_error_id or capture_stderr[:160]}"
        )
        media_auth_pred: dict[str, Any] = {
            "status": "passed" if media_auth_ok else "failed",
            "reason": media_auth_reason,
            "native_binary": str(bins["fss-capture-rtsp"]),
            "capture_approval": capture_plan_approval or started.get("approval_digest"),
            "session": {
                "codec": codec_obs or None,
                "time_scale": started.get("time_scale"),
                "frame_duration_ticks": started.get("frame_duration_ticks"),
                "authentication": auth_mode,
                "require_auth": require_auth,
                "authentication_challenges": auth_challenges,
                "digest_requests_queued": digest_reqs,
                "transport_encrypted": bool(terminal.get("transport_encrypted", False)),
                "server_identity_verified": bool(terminal.get("server_identity_verified", False)),
                "protocols_observed": protocols,
                "source_binding": terminal.get("source_binding"),
                "capture_error_id": cap_error_id,
            },
        }
        if bridge_status:
            media_auth_pred["bridge_telemetry"] = {
                "profile_level_id": bridge_status.get("profile_level_id"),
                "sps_len": bridge_status.get("sps_len"),
                "pps_len": bridge_status.get("pps_len"),
                "ssrc_hex": bridge_status.get("ssrc_hex"),
                "packets_received": bridge_status.get("packets_received", bridge_status.get("video_packets_received")),
                "audio_packets_discarded": bridge_status.get("audio_packets_discarded"),
            }

        # If no durable windows exist, source_receipt, continuity, and visible_event cannot pass.
        if not windows:
            return {
                "media_auth": media_auth_pred,
                "source_receipt": {
                    "status": "failed",
                    "reason": f"no_durable_windows_captured:{cap_error_id or capture_stderr[:160]}",
                    "durable_windows": 0,
                    "custody_state": (terminal.get("runtime") or {}).get("custody_state"),
                    "explicit_omissions": {
                        "raw_tcp_retention": terminal.get("raw_tcp_retention"),
                        "control_and_rtcp_retention": terminal.get("control_and_rtcp_retention"),
                    },
                },
                "continuity": {
                    "status": "failed",
                    "reason": f"capture_incomplete:{cap_error_id or terminal.get('stop_cause') or 'no_windows'}",
                    "capture_rc": capture_rc,
                    "complete": bool(terminal.get("complete", False)),
                    "stop_cause": terminal.get("stop_cause"),
                    "error_id": cap_error_id,
                    "peer_eof": terminal.get("peer_eof"),
                    "requested_pictures": terminal.get("requested_pictures"),
                    "collected_pictures": terminal.get("collected_pictures"),
                    "durable_pictures": terminal.get("durable_pictures"),
                    "capture_continuity_certified": bool(terminal.get("capture_continuity", False)),
                },
                "visible_event": {
                    "status": "failed",
                    "reason": "no_imported_frames_to_screen",
                    "frames_decoded": 0,
                },
            }

        # ---- Step 3: Native pure-Rust import via fss-import-rtsp ----
        dep_dir = work_dir / "deployment"
        imports: list[dict[str, Any]] = []
        import_errors: list[str] = []
        receive_ns = time.time_ns()
        time_scale = int(started.get("time_scale") or 90000)

        # Compute causal timing bounds strictly satisfying:
        #   capture_start_ns + window_duration_ns + capture_uncertainty_ns <= receive_ns
        # Never invent tighter certainty than the wall-clock capture envelope!
        total_capture_span_ns = max(0, t_after_capture_ns - t_before_capture_ns)
        base_uncertainty_ns = max(1_000_000_000, total_capture_span_ns)

        # Import windows in order up to a bounded cap (at least 4 windows, and enough to reach
        # min_frames for short-GOP / all-IDR streams, capped at 12 windows).
        selected_windows: list[dict[str, Any]] = []
        cum_pics = 0
        for w in windows:
            if len(selected_windows) >= 12:
                break
            selected_windows.append(w)
            cum_pics += int(w.get("pictures") or 0)
            if len(selected_windows) >= 4 and cum_pics >= min_frames:
                break
        for w in selected_windows:
            slot = str(w["slot"])
            wroot = str(w["root"])
            wpics = int(w.get("pictures") or 0)
            dec_start = int(w.get("decode_start") or 0)
            dec_end = int(w.get("decode_end") or 0)
            win_dur_ns = (
                int((dec_end - dec_start) * 1_000_000_000 // time_scale)
                if dec_end > dec_start and time_scale > 0
                else int(wpics * frame_duration_ticks * 1_000_000_000 // max(1, time_scale))
            )

            imp_args = [
                str(bins["fss-import-rtsp"]),
                "--archive", str(archive_dir),
                "--root", str(dep_dir),
                "--site", site,
                "--codec", codec,
                "--window-slot", slot,
                "--window-root", wroot,
                "--sensor-id", sensor_id,
                "--stream-id", stream_id,
                "--generation", "1",
                "--anchor", anchor,
                "--receive-clock", receive_clock,
                "--receive-time-ns", str(receive_ns),
                "--owner-authorized", "yes",
                "--read-originals", "yes",
                "--retain-originals", "yes",
            ]
            cap_start_used: int | None = None
            cap_unc_used: int | None = None
            if include_capture_time_hint:
                # Strictly causal operator-assumption bound anchored before receive_ns
                safety_margin_ns = 1_000_000_000
                cap_unc_used = base_uncertainty_ns
                cap_start_used = receive_ns - win_dur_ns - cap_unc_used - safety_margin_ns
                if not from_archive and cap_start_used > t_before_capture_ns:
                    cap_start_used = t_before_capture_ns
                imp_args.extend([
                    "--capture-start-ns", str(cap_start_used),
                    "--capture-uncertainty-ns", str(cap_unc_used),
                ])

            ip_proc = _run_cmd_safe(imp_args, timeout=30.0)
            if ip_proc.returncode != 0:
                import_errors.append(f"import_plan_failed({slot}): {(ip_proc.stderr or ip_proc.stdout).strip()[:200]}")
                continue
            try:
                iplan = json.loads(ip_proc.stdout)
                iapp = str(iplan["approval_digest"])
            except (ValueError, KeyError) as exc:
                import_errors.append(f"import_plan_parse({slot}): {exc}")
                continue

            ir_proc = _run_cmd_safe(imp_args + ["--approve", iapp], timeout=30.0)
            if ir_proc.returncode != 0:
                import_errors.append(f"import_run_failed({slot}): {(ir_proc.stderr or ir_proc.stdout).strip()[:200]}")
                continue
            try:
                idoc = json.loads(ir_proc.stdout)
            except ValueError as exc:
                import_errors.append(f"import_run_parse({slot}): {exc}")
                continue
            idoc["_capture_start_ns"] = cap_start_used
            idoc["_capture_uncertainty_ns"] = cap_unc_used
            idoc["_receive_time_ns"] = receive_ns
            imports.append(idoc)

        # ---- Evaluate Predicate 4: source_receipt ----
        runtime_info = terminal.get("runtime") if isinstance(terminal.get("runtime"), dict) else {}
        custody_state = runtime_info.get("custody_state")
        all_imports_verified = bool(imports) and not import_errors and all(
            imp.get("kind") == "imported"
            and imp.get("source_archive_retained_separately") is True
            and imp.get("destination_contains_original_recording") is True
            and bool(imp.get("origin_proof"))
            and bool(imp.get("import_identity"))
            and bool(imp.get("import_root"))
            for imp in imports
        )
        source_receipt_ok = (
            len(windows) >= 1
            and int(terminal.get("durable_source_object_bytes") or 0) > 0
            and custody_state == "verified"
            and all_imports_verified
        )
        source_receipt_pred = {
            "status": "passed" if source_receipt_ok else "failed",
            "reason": "source_custody_and_origin_proofs_verified" if source_receipt_ok else (
                f"import_errors:{import_errors}" if import_errors else
                f"custody_state={custody_state}"
            ),
            "native_binary": str(bins["fss-import-rtsp"]),
            "custody_state": custody_state,
            "durable_windows_count": len(windows),
            "durable_source_object_bytes": terminal.get("durable_source_object_bytes"),
            "snapshot_digest": terminal.get("snapshot_digest"),
            "rtp_retention": terminal.get("rtp_retention"),
            "explicit_omissions": {
                "raw_tcp_retention": terminal.get("raw_tcp_retention"),
                "control_and_rtcp_retention": terminal.get("control_and_rtcp_retention"),
            },
            "imports": [
                {
                    "window_slot": imp.get("window_slot"),
                    "window_root": imp.get("window_root"),
                    "import_identity": imp.get("import_identity"),
                    "import_root": imp.get("import_root"),
                    "origin_proof": imp.get("origin_proof"),
                    "manifest_digest": imp.get("manifest_digest"),
                    "frames": imp.get("frames"),
                    "codec": imp.get("codec"),
                    "capture_time_label": imp.get("capture_time_label"),
                    "source_archive_retained_separately": imp.get("source_archive_retained_separately"),
                    "destination_contains_original_recording": imp.get("destination_contains_original_recording"),
                }
                for imp in imports
            ],
            "import_errors": import_errors,
        }

        if not imports:
            return {
                "media_auth": media_auth_pred,
                "source_receipt": source_receipt_pred,
                "continuity": {
                    "status": "failed",
                    "reason": "no_imports_available_for_coverage_analysis",
                    "capture_rc": capture_rc,
                    "complete": bool(terminal.get("complete", False)),
                },
                "visible_event": {
                    "status": "failed",
                    "reason": "no_imports_available_for_visible_event_screening",
                    "frames_decoded": 0,
                },
            }

        # ---- Step 4: Native pure-Rust decode + sensor-health + watch + coverage retention ----
        # Analyze all imported windows and select the best window for visible-event evaluation
        # while enforcing health/continuity across ALL imported windows!
        watch_reports: list[dict[str, Any]] = []
        watch_errors: list[str] = []
        published_events: list[dict[str, Any]] = []

        for idx, imp in enumerate(imports):
            imp_id = str(imp["import_identity"])
            rep_path = work_dir / f"watch-{idx}.json"
            watch_base = [
                str(bins["fss-event"]),
                "watch",
                "--root", str(dep_dir),
                "--site", site,
                "--import-id", imp_id,
                "--interpretation", "ycbcr",
                "--pixel-threshold", str(pixel_threshold),
                "--min-region-pixels", str(min_region_pixels),
                "--zone", zone,
                "--sensor-health", "conservative-v1",
            ]
            w_proc = _run_cmd_safe(watch_base + ["--report-out", str(rep_path)], timeout=45.0)
            if w_proc.returncode != 0 or not rep_path.is_file():
                watch_errors.append(f"watch_failed({imp_id}): {(w_proc.stderr or w_proc.stdout).strip()[:240]}")
                continue
            wdoc = json.loads(rep_path.read_text(encoding="utf-8"))

            # Retain CoverageWitness
            cov_app = (wdoc.get("coverage") or {}).get("approval_digest")
            if isinstance(cov_app, str) and cov_app:
                ret_path = work_dir / f"watch-{idx}-retained.json"
                r_proc = _run_cmd_safe(
                    watch_base + ["--retain-coverage", cov_app, "--report-out", str(ret_path)],
                    timeout=45.0,
                )
                if r_proc.returncode == 0 and ret_path.is_file():
                    wdoc = json.loads(ret_path.read_text(encoding="utf-8"))

            # Optionally publish first visible motion event candidate
            if publish_event and wdoc.get("candidates"):
                cand0 = wdoc["candidates"][0]
                prop_digest = cand0.get("proposal_digest")
                if isinstance(prop_digest, str) and prop_digest:
                    pub_path = work_dir / f"watch-{idx}-published.json"
                    p_proc = _run_cmd_safe(
                        watch_base + ["--approve", prop_digest, "--report-out", str(pub_path)],
                        timeout=45.0,
                    )
                    if p_proc.returncode == 0 and pub_path.is_file():
                        pdoc = json.loads(pub_path.read_text(encoding="utf-8"))
                        wdoc = pdoc
                        if pdoc.get("published_count", 0) >= 1 and pdoc.get("candidates"):
                            published_events.append({
                                "import_identity": imp_id,
                                "event_id": pdoc["candidates"][0].get("event_id"),
                                "proposal_digest": prop_digest,
                                "provenance_root": pdoc["candidates"][0].get("provenance_root"),
                            })
            watch_reports.append(wdoc)

        # ---- Step 5: Native pure-Rust SituationFrame orientation via fss session orient ----
        orient_doc: dict[str, Any] | None = None
        orient_proc = _run_cmd_safe(
            [str(bins["fss"]), "session", "orient", "--root", str(dep_dir), "--json"],
            timeout=30.0,
        )
        if orient_proc.returncode == 0:
            try:
                orient_doc = json.loads(orient_proc.stdout)
            except ValueError:
                orient_doc = None

        # ---- Evaluate Predicate 5: continuity ----
        qproof = runtime_info.get("quiescence_proof") if isinstance(runtime_info.get("quiescence_proof"), dict) else {}
        capture_clean = (
            capture_rc == 0
            and terminal.get("complete") is True
            and terminal.get("stop_cause") == "owner_stopped"
            and terminal.get("error_id") is None
            and terminal.get("peer_eof") is False
            and terminal.get("input_end_observed") is False
            and int(terminal.get("connections_retried") or 0) == 0
            and int(terminal.get("collected_pictures") or 0) == int(terminal.get("requested_pictures") or -1)
            and int(terminal.get("durable_pictures") or 0) == int(terminal.get("requested_pictures") or -1)
            and runtime_info.get("quiescent") is True
            and int(qproof.get("indeterminate_obligations") or 0) == 0
        )
        all_source_gaps = [
            seg
            for wr in watch_reports
            for seg in ((wr.get("sensor_health") or {}).get("source_gap_segments") or [])
        ]
        all_restarts = [
            seg
            for wr in watch_reports
            for seg in ((wr.get("sensor_health") or {}).get("decoder_restart_segments") or [])
        ]
        coverage_statuses = [(wr.get("coverage") or {}).get("coverage_status") for wr in watch_reports]
        coverage_retained = bool(watch_reports) and all(
            st in ("retained", "already_retained") for st in coverage_statuses
        )
        witness_count_total = sum(int((wr.get("coverage") or {}).get("witness_count") or 0) for wr in watch_reports)
        absence_certified_any = any(bool((wr.get("coverage") or {}).get("absence_certified")) for wr in watch_reports)

        orient_payload = (orient_doc or {}).get("payload") or {}
        orient_frame = orient_payload.get("situationFrame") or {}
        orient_cells = orient_frame.get("knowledgeCells") if isinstance(orient_frame.get("knowledgeCells"), list) else []
        orient_cell_map = {
            str(c.get("cellId")): str(c.get("value") or "")
            for c in orient_cells
            if isinstance(c, dict) and c.get("cellId")
        }
        orient_anchor = (orient_doc or {}).get("outputAnchor") or orient_payload.get("anchor") or {}
        orient_ok = bool(orient_frame.get("frameId"))

        continuity_ok = (
            capture_clean
            and not watch_errors
            and len(all_source_gaps) == 0
            and coverage_retained
            and orient_ok
        )
        continuity_reason = "bounded_capture_complete_and_coverage_retained" if continuity_ok else (
            f"capture_not_clean:rc={capture_rc},complete={terminal.get('complete')},peer_eof={terminal.get('peer_eof')},err={cap_error_id}"
            if not capture_clean else
            f"watch_errors:{watch_errors}" if watch_errors else
            f"source_gaps_observed:{all_source_gaps}" if all_source_gaps else
            f"coverage_not_retained:{coverage_statuses}" if not coverage_retained else
            "situation_frame_orient_failed"
        )
        continuity_pred = {
            "status": "passed" if continuity_ok else "failed",
            "reason": continuity_reason,
            "capture_rc": capture_rc,
            "complete": bool(terminal.get("complete", False)),
            "stop_cause": terminal.get("stop_cause"),
            "error_id": cap_error_id,
            "peer_eof": terminal.get("peer_eof"),
            "connections_retried": terminal.get("connections_retried"),
            "requested_pictures": terminal.get("requested_pictures"),
            "collected_pictures": terminal.get("collected_pictures"),
            "durable_pictures": terminal.get("durable_pictures"),
            "runtime_quiescent": runtime_info.get("quiescent"),
            "indeterminate_obligations": qproof.get("indeterminate_obligations"),
            "capture_continuity_certified": bool(terminal.get("capture_continuity", False)),
            "timing_uncertainty": {
                "capture_time_label": imports[0].get("capture_time_label"),
                "capture_start_ns": imports[0].get("_capture_start_ns"),
                "capture_uncertainty_ns": imports[0].get("_capture_uncertainty_ns"),
                "receive_time_ns": imports[0].get("_receive_time_ns"),
            },
            "coverage": {
                "statuses": coverage_statuses,
                "witness_count_total": witness_count_total,
                "absence_certified": absence_certified_any,
                "source_gap_segments": all_source_gaps,
                "decoder_restart_segments": all_restarts,
            },
            "situation_frame": {
                "frame_id": orient_frame.get("frameId"),
                "capsule_sequence": orient_anchor.get("capsuleSequence") if isinstance(orient_anchor, dict) else None,
                "epistemic_state": (orient_doc or {}).get("epistemicState"),
                "completeness": (orient_doc or {}).get("completeness"),
                "coverage_status": (orient_frame.get("coverage") or {}).get("status"),
                "coverage_gaps": (orient_frame.get("coverage") or {}).get("gaps"),
                "ledger_head": orient_cell_map.get("claim:deployment:ledger-head"),
                "events_cell": orient_cell_map.get("claim:deployment:events"),
            },
        }

        # ---- Evaluate Predicate 6: visible_event (anti-stale / anti-frozen image) ----
        # Evaluate per-window qualification so a real H.264 encoder P-skip run in an earlier quiet
        # window does not mask a clean visible-event window, while a truly frozen/stale/flat camera
        # fails ZERO qualifying windows. Every window's health is still reported transparently.
        total_frames_decoded = sum(int(wr.get("frames_decoded") or 0) for wr in watch_reports)
        all_obs = [
            obs
            for wr in watch_reports
            for obs in ((wr.get("sensor_health") or {}).get("observations") or [])
        ]
        all_luma_digests = [str(o.get("luma_digest")) for o in all_obs if o.get("luma_digest")]
        unique_luma_digests = sorted(set(all_luma_digests))
        max_rep_global = max((int(o.get("repeated_frames") or 0) for o in all_obs), default=0)
        max_contrast_global = max((int(o.get("contrast_span") or 0) for o in all_obs), default=0)
        min_contrast_global = min((int(o.get("contrast_span") or 0) for o in all_obs), default=0)
        health_statuses = [(wr.get("sensor_health") or {}).get("status") for wr in watch_reports]
        affected_segments_total = sum(
            len((wr.get("sensor_health") or {}).get("affected_segments") or [])
            for wr in watch_reports
        )
        all_health_findings = sorted({
            str(f)
            for o in all_obs
            for f in (o.get("findings") or [])
        })
        confirmed_tracks_total = sum(int(wr.get("confirmed_tracks") or 0) for wr in watch_reports)
        candidate_count_total = sum(int(wr.get("candidate_count") or 0) for wr in watch_reports)

        window_evaluations: list[dict[str, Any]] = []
        for wr in watch_reports:
            sh = wr.get("sensor_health") or {}
            w_obs = sh.get("observations") or []
            w_frames = int(wr.get("frames_decoded") or 0)
            w_unique = len({str(o.get("luma_digest")) for o in w_obs if o.get("luma_digest")})
            w_max_rep = max((int(o.get("repeated_frames") or 0) for o in w_obs), default=0)
            w_max_contrast = max((int(o.get("contrast_span") or 0) for o in w_obs), default=0)
            w_findings = sorted({str(f) for o in w_obs for f in (o.get("findings") or [])})
            w_affected = len(sh.get("affected_segments") or [])
            w_status = sh.get("status")
            w_clear = (
                w_status == "clear_screen_not_health_evidence"
                and w_affected == 0
                and len(w_findings) == 0
            )
            w_non_frozen = w_unique >= min_unique_luma_digests and w_max_rep < max_repeated_frames
            w_non_flat = w_max_contrast >= min_contrast_span
            w_tracks = int(wr.get("confirmed_tracks") or 0)
            w_cands = int(wr.get("candidate_count") or 0)
            w_motion = w_tracks >= 1 and w_cands >= 1
            w_qualifies_live = w_clear and w_non_frozen and w_non_flat
            w_qualifies_strict = w_qualifies_live and w_motion
            window_evaluations.append({
                "import_identity": wr.get("import_identity"),
                "frames_decoded": w_frames,
                "sensor_health_status": w_status,
                "sensor_health_findings": w_findings,
                "affected_segments": w_affected,
                "unique_luma_digests": w_unique,
                "max_repeated_frames": w_max_rep,
                "max_contrast_span": w_max_contrast,
                "confirmed_tracks": w_tracks,
                "candidate_count": w_cands,
                "qualifies_live_variation": w_qualifies_live,
                "qualifies_strict_visible_event": w_qualifies_strict,
            })

        frames_ok = total_frames_decoded >= min_frames
        qualifying_live_windows = [w for w in window_evaluations if w["qualifies_live_variation"]]
        qualifying_strict_windows = [w for w in window_evaluations if w["qualifies_strict_visible_event"]]
        # Every qualifying window already proved sensor_health == clear_screen_not_health_evidence;
        # all_windows_health_clear separately reports the stricter all-window bar.
        health_screen_clear = bool(qualifying_live_windows)
        all_windows_health_clear = bool(watch_reports) and all(
            st == "clear_screen_not_health_evidence" for st in health_statuses
        ) and affected_segments_total == 0 and len(all_health_findings) == 0
        non_frozen_ok = bool(qualifying_live_windows) and len(unique_luma_digests) >= min_unique_luma_digests
        non_flat_ok = max_contrast_global >= min_contrast_span
        motion_candidate_ok = bool(qualifying_strict_windows)

        orient_events_text = orient_cell_map.get("claim:deployment:events") or ""
        orient_has_published = True
        if publish_event and qualifying_strict_windows:
            orient_has_published = bool(published_events) and any(
                str(pe.get("event_id") or "") in orient_events_text
                for pe in published_events
            )

        if visible_event_mode == "strict":
            visible_ok = (
                not watch_errors
                and frames_ok
                and bool(qualifying_strict_windows)
                and orient_has_published
            )
        else:
            # live-variation mode still strictly rejects frozen/stale/dark/flat frames,
            # while recording motion_candidate_ok transparently as a separate field.
            visible_ok = (
                not watch_errors
                and frames_ok
                and bool(qualifying_live_windows)
            )

        if visible_ok:
            visible_reason = (
                "visible_motion_event_and_non_frozen_frames_verified"
                if motion_candidate_ok
                else "non_frozen_live_luma_variation_verified_no_motion_candidate_required"
            )
        elif watch_errors:
            visible_reason = f"watch_errors:{watch_errors}"
        elif not frames_ok:
            visible_reason = f"insufficient_decoded_frames:{total_frames_decoded}<{min_frames}"
        elif not non_frozen_ok and len(unique_luma_digests) < min_unique_luma_digests:
            visible_reason = f"frozen_or_stale_image_detected:unique_luma_digests={len(unique_luma_digests)}<{min_unique_luma_digests},max_repeated_frames={max_rep_global}"
        elif not qualifying_live_windows and affected_segments_total > 0:
            visible_reason = f"sensor_health_degraded:statuses={health_statuses},findings={all_health_findings},affected={affected_segments_total}"
        elif not non_flat_ok:
            visible_reason = f"flat_or_low_contrast_image:max_contrast_span={max_contrast_global}<{min_contrast_span}"
        elif not motion_candidate_ok:
            visible_reason = "no_visible_motion_event_observed_only_background_variation"
        else:
            visible_reason = "published_event_not_reflected_in_situation_frame"

        sampled_luma = []
        if all_obs:
            sample_indices = sorted({0, len(all_obs) // 2, len(all_obs) - 1})
            for si in sample_indices:
                o = all_obs[si]
                sampled_luma.append({
                    "segment": o.get("segment"),
                    "luma_digest": o.get("luma_digest"),
                    "contrast_span": o.get("contrast_span"),
                    "repeated_frames": o.get("repeated_frames"),
                    "findings": o.get("findings"),
                })

        visible_event_pred = {
            "status": "passed" if visible_ok else "failed",
            "reason": visible_reason,
            "mode": visible_event_mode,
            "native_binary": str(bins["fss-event"]),
            "zone": zone,
            "dimensions": [watch_reports[0].get("width"), watch_reports[0].get("height")] if watch_reports else None,
            "media_format": watch_reports[0].get("media_format") if watch_reports else None,
            "checks": {
                "frames_decoded": total_frames_decoded,
                "min_frames_required": min_frames,
                "frames_ok": frames_ok,
                "windows_analyzed": len(window_evaluations),
                "qualifying_live_windows": len(qualifying_live_windows),
                "qualifying_strict_windows": len(qualifying_strict_windows),
                "sensor_health_statuses": health_statuses,
                "sensor_health_findings": all_health_findings,
                "sensor_health_affected_segments": affected_segments_total,
                "sensor_health_clear": health_screen_clear,
                "all_windows_health_clear": all_windows_health_clear,
                "unique_luma_digests": len(unique_luma_digests),
                "min_unique_luma_digests": min_unique_luma_digests,
                "max_repeated_frames": max_rep_global,
                "max_allowed_repeated_frames": max_repeated_frames,
                "non_frozen_ok": non_frozen_ok,
                "min_contrast_span_observed": min_contrast_global,
                "max_contrast_span_observed": max_contrast_global,
                "min_contrast_span_required": min_contrast_span,
                "non_flat_ok": non_flat_ok,
                "confirmed_tracks": confirmed_tracks_total,
                "candidate_count": candidate_count_total,
                "motion_candidate_ok": motion_candidate_ok,
                "orient_reflects_published_event": orient_has_published,
                "strict_visible_event_passed": bool(frames_ok and qualifying_strict_windows and orient_has_published),
            },
            "window_evaluations": window_evaluations,
            "sampled_frame_observations": sampled_luma,
            "published_events": published_events,
        }

        return {
            "media_auth": media_auth_pred,
            "source_receipt": source_receipt_pred,
            "continuity": continuity_pred,
            "visible_event": visible_event_pred,
        }
    finally:
        if bridge_proc is not None and bridge_proc.poll() is None:
            bridge_proc.terminate()
            try:
                bridge_proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                bridge_proc.kill()
                bridge_proc.wait(timeout=3.0)


def _fail_media_bundle(reason: str, bridge_status: dict[str, Any] | None) -> dict[str, Any]:
    pred = {"status": "failed", "reason": reason}
    if bridge_status is not None:
        pred["bridge_status"] = bridge_status
    return {
        "media_auth": pred,
        "source_receipt": {"status": "failed", "reason": f"upstream_failed:{reason}"},
        "continuity": {"status": "failed", "reason": f"upstream_failed:{reason}"},
        "visible_event": {"status": "failed", "reason": f"upstream_failed:{reason}"},
    }


def evaluate_tailnet_row(
    *,
    tailnet_host: str | None,
    rtsp_port: int,
    onvif_port: int,
    http_port: int,
    timeout: float,
    expect_model: str | None,
) -> dict[str, Any]:
    if not tailnet_host:
        return {
            "status": "not_run_local_first",
            "reason": "local_acceptance_evaluated_first_no_tailnet_host_supplied",
            "host": None,
            "rows": [],
        }
    sys.path.insert(0, str(HERE))
    try:
        import tailnet_acceptance  # type: ignore
    except ImportError as exc:
        return {
            "status": "failed",
            "reason": f"tailnet_acceptance_import_error: {exc}",
            "host": tailnet_host,
            "rows": [],
        }
    rows, _all_pass, infra_fail = tailnet_acceptance.run_contract(
        host=tailnet_host,
        rtsp_port=rtsp_port,
        onvif_port=onvif_port,
        http_port=http_port,
        timeout=timeout,
        require_tailnet_bind=True,
        expect_model=expect_model,
        want_frame=False,  # native FSS rust path owns frame decode; tailnet row checks tailnet control/transport
    )
    required_tailnet_rows = {
        "tailnet-bind",
        "rtsp-port",
        "rtsp-handshake",
        "onvif-capabilities",
        "onvif-device-info",
        "onvif-profile-s",
        "http-control",
    }
    evaluated = [r for r in rows if r.get("row") in required_tailnet_rows]
    tailnet_control_pass = (not infra_fail) and len(evaluated) == len(required_tailnet_rows) and all(
        bool(r.get("pass")) for r in evaluated
    )
    return {
        "status": "passed" if tailnet_control_pass else ("infra_failed" if infra_fail else "failed"),
        "reason": "tailnet_control_contract_passed" if tailnet_control_pass else "tailnet_control_contract_incomplete_or_failed",
        "host": tailnet_host,
        "all_pass": tailnet_control_pass,
        "infra_fail": infra_fail,
        "rows": rows,
    }


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="First-footage auto-acceptance after enrollment via native pure-Rust FSS binaries."
    )
    ap.add_argument("--camera-id", required=True, help="Logical sensor/camera id (e.g. wyze-39)")
    ap.add_argument(
        "--family",
        default="generic-rtsp",
        help=f"Camera family compatibility row ({', '.join(sorted(CAMERA_FAMILIES))})",
    )
    ap.add_argument("--site", default="home-lab", help="FSS site id")
    ap.add_argument("--stream-id", default="stream1", help="Logical stream id")
    ap.add_argument("--codec", default="avc", choices=("avc", "hevc", "mjpeg"))

    # Native RTSP source options (live, Wyze bridge, or archive replay)
    ap.add_argument("--peer", help="RTSP peer host:port (e.g. 127.0.0.1:18554)")
    ap.add_argument("--authority", help="RTSP URI authority (defaults to --peer)")
    ap.add_argument("--presentation", default="/stream1", help="RTSP presentation path")
    ap.add_argument("--control-root", default=None, help="RTSP control root (defaults to --presentation)")
    ap.add_argument("--credential-file", help="0600 credential file (user LF pass LF)")
    ap.add_argument("--auth-realm", default=None, help="Expected RTSP Digest realm")
    ap.add_argument("--allow-unauthenticated", action="store_true", help="Allow plaintext unauthenticated RTSP (not recommended)")
    ap.add_argument("--use-wyze-bridge", metavar="CAM_IP", help="Run wyze_rtsp_bridge.py against CAM_IP on an ephemeral localhost port")
    ap.add_argument("--bridge-status", help="Optional existing bridge_status.json path for SDP/audio telemetry")
    ap.add_argument("--from-archive", help="Evaluate an already-captured FSS RTSP archive directory")
    ap.add_argument("--capture-jsonl", help="Path to capture.jsonl paired with --from-archive")

    # Capture & watch tuning
    ap.add_argument("--pictures", type=int, default=40, help="Bounded picture count to capture")
    ap.add_argument("--frame-duration-ticks", type=int, default=4500, help="90kHz ticks per picture (4500=20fps, 3600=25fps)")
    ap.add_argument("--source-duration-max-ticks", type=int, default=18000, help="Max source frame duration ticks")
    ap.add_argument("--no-source-no-reorder", action="store_true", help="Do not pass --source-no-reorder yes")
    ap.add_argument("--ssrc", default="auto", help="Expected RTP SSRC or 'auto'")
    ap.add_argument("--capture-timeout-ms", type=int, default=25000)
    ap.add_argument("--zone", default="yard:0,0,640,360", help="Watch zone ID:X,Y,W,H")
    ap.add_argument("--pixel-threshold", type=int, default=24)
    ap.add_argument("--min-region-pixels", type=int, default=64)
    ap.add_argument("--min-frames", type=int, default=8, help="Minimum pure-Rust decoded frames")
    ap.add_argument("--min-unique-luma-digests", type=int, default=2, help="Minimum unique frame luma digests (anti-frozen)")
    ap.add_argument("--min-contrast-span", type=int, default=8, help="Minimum luma contrast span (anti-flat/blank)")
    ap.add_argument("--max-repeated-frames", type=int, default=8, help="Strict ceiling on consecutive identical luma frames")
    ap.add_argument(
        "--visible-event-mode",
        choices=("strict", "live-variation"),
        default="strict",
        help="'strict' requires confirmed foreground motion candidate + non-frozen/clear health; 'live-variation' requires non-frozen/clear health",
    )
    ap.add_argument("--publish-event", action="store_true", help="Approve and publish the first visible motion candidate into SituationFrame")
    ap.add_argument("--no-capture-time-hint", action="store_true", help="Leave capture_time unknown on import")

    # Separate post-flash admin_receipt & fw_identity predicates
    ap.add_argument("--admin-receipt-json", help="Path to existing RootProof JSON for admin_receipt")
    ap.add_argument("--ssh-host", help="Camera IP/host for pinned SSH uid=0 check")
    ap.add_argument("--ssh-port", type=int, default=22)
    ap.add_argument("--ssh-user", default="root")
    ap.add_argument("--ssh-key", default=None)
    ap.add_argument("--ssh-pinned-hostkey", help="Expected SSH server host-key fingerprint (SHA256:...)")
    ap.add_argument("--onvif-host", help="Camera IP/host for ONVIF GetDeviceInformation")
    ap.add_argument("--onvif-port", type=int, default=80)
    ap.add_argument("--fw-identity-json", help="Path to JSON with manufacturer/model/firmware_version")
    ap.add_argument("--compat-proof-json", help="Path to JSON proving battery camera sensor_driver/encoder_pipeline/duty_cycle_budget")
    ap.add_argument("--expect-fw-manufacturer", default=None)
    ap.add_argument("--expect-fw-model", default=None)
    ap.add_argument("--expect-fw-version", default=None)

    # Separate tailnet scope row
    ap.add_argument("--tailnet-host", default=None, help="Optional tailnet hostname/IP (evaluated separately from local acceptance)")
    ap.add_argument("--tailnet-rtsp-port", type=int, default=554)
    ap.add_argument("--tailnet-onvif-port", type=int, default=80)
    ap.add_argument("--tailnet-http-port", type=int, default=80)

    # Execution & output controls
    ap.add_argument("--bin-dir", default=None, help="Directory containing native FSS binaries")
    ap.add_argument("--timeout", type=float, default=5.0, help="Control-plane probe timeout (seconds)")
    ap.add_argument("--keep-artifacts", default=None, help="Preserve working directory at this path")
    ap.add_argument("--out", default=None, help="Atomically write JSON receipt to this file")
    ap.add_argument("--require-full", action="store_true", help="Exit 0 only if ALL 6 local predicates pass (including admin_receipt & fw_identity)")
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    a = ap.parse_args(argv)

    if a.family not in CAMERA_FAMILIES:
        err = {
            "schema": "fss.footage_acceptance.v1",
            "error": f"unknown camera family {a.family!r}; expected one of {sorted(CAMERA_FAMILIES)}",
        }
        print(json.dumps(err, indent=2), file=sys.stderr)
        return 2

    if a.min_unique_luma_digests < 2 or a.min_frames < 2 or a.min_contrast_span < 1 or a.max_repeated_frames < 2 or a.pictures < 1:
        err = {
            "schema": "fss.footage_acceptance.v1",
            "error": (
                "anti-frozen visible_event bounds cannot be weakened below minimums: "
                "min_unique_luma_digests>=2, min_frames>=2, min_contrast_span>=1, "
                "max_repeated_frames>=2, pictures>=1"
            ),
        }
        print(json.dumps(err, indent=2), file=sys.stderr)
        return 2

    sources = [
        flag
        for flag, val in (
            ("--peer", a.peer),
            ("--use-wyze-bridge", a.use_wyze_bridge),
            ("--from-archive", a.from_archive),
        )
        if val
    ]
    if len(sources) != 1:
        err = {
            "schema": "fss.footage_acceptance.v1",
            "error": (
                "must supply exactly one of --peer, --use-wyze-bridge, or --from-archive"
                if not sources
                else f"mutually exclusive source flags supplied: {', '.join(sources)}"
            ),
        }
        print(json.dumps(err, indent=2), file=sys.stderr)
        return 2

    bins, bin_err = resolve_binaries(a.bin_dir)
    if bins is None:
        err = {"schema": "fss.footage_acceptance.v1", "error": bin_err}
        print(json.dumps(err, indent=2), file=sys.stderr)
        return 2

    if a.credential_file and not Path(a.credential_file).is_file():
        err = {"schema": "fss.footage_acceptance.v1", "error": f"unreadable credential file: {a.credential_file}"}
        print(json.dumps(err, indent=2), file=sys.stderr)
        return 2

    admin_pred = evaluate_admin_receipt(
        admin_receipt_json=a.admin_receipt_json,
        ssh_host=a.ssh_host,
        ssh_port=a.ssh_port,
        ssh_user=a.ssh_user,
        ssh_key=a.ssh_key,
        ssh_pinned_hostkey=a.ssh_pinned_hostkey,
        timeout=a.timeout,
    )
    fw_pred = evaluate_fw_identity(
        family=a.family,
        onvif_host=a.onvif_host,
        onvif_port=a.onvif_port,
        fw_identity_json=a.fw_identity_json,
        compat_proof_json=a.compat_proof_json,
        expect_manufacturer=a.expect_fw_manufacturer,
        expect_model=a.expect_fw_model,
        expect_firmware=a.expect_fw_version,
        timeout=a.timeout,
    )

    tmp_ctx = None
    if a.keep_artifacts:
        work_dir = Path(a.keep_artifacts)
        work_dir.mkdir(parents=True, exist_ok=True)
    else:
        tmp_ctx = tempfile.TemporaryDirectory(prefix=f"fss-footage-accept-{a.camera_id}-")
        work_dir = Path(tmp_ctx.name)

    try:
        media_bundle = run_native_footage_pipeline(
            bins=bins,
            work_dir=work_dir,
            sensor_id=a.camera_id,
            stream_id=a.stream_id,
            site=a.site,
            codec=a.codec,
            peer=a.peer,
            authority=a.authority,
            presentation=a.presentation,
            control_root=a.control_root,
            credential_file=a.credential_file,
            auth_realm=a.auth_realm,
            require_auth=not a.allow_unauthenticated,
            pictures=a.pictures,
            frame_duration_ticks=a.frame_duration_ticks,
            source_duration_max_ticks=None if a.source_duration_max_ticks <= 0 else a.source_duration_max_ticks,
            source_no_reorder=not a.no_source_no_reorder,
            ssrc=a.ssrc,
            capture_timeout_ms=a.capture_timeout_ms,
            zone=a.zone,
            pixel_threshold=a.pixel_threshold,
            min_region_pixels=a.min_region_pixels,
            min_frames=a.min_frames,
            min_unique_luma_digests=a.min_unique_luma_digests,
            min_contrast_span=a.min_contrast_span,
            max_repeated_frames=a.max_repeated_frames,
            visible_event_mode=a.visible_event_mode,
            publish_event=a.publish_event,
            include_capture_time_hint=not a.no_capture_time_hint,
            from_archive=a.from_archive,
            capture_jsonl_in=a.capture_jsonl,
            bridge_status_path=a.bridge_status,
            wyze_bridge_cam_ip=a.use_wyze_bridge,
        )
    except ValueError as exc:
        err = {"schema": "fss.footage_acceptance.v1", "error": str(exc)}
        print(json.dumps(err, indent=2), file=sys.stderr)
        return 2
    finally:
        if tmp_ctx is not None:
            tmp_ctx.cleanup()

    tailnet_row = evaluate_tailnet_row(
        tailnet_host=a.tailnet_host,
        rtsp_port=a.tailnet_rtsp_port,
        onvif_port=a.tailnet_onvif_port,
        http_port=a.tailnet_http_port,
        timeout=a.timeout,
        expect_model=a.expect_fw_model,
    )

    predicates = {
        "admin_receipt": admin_pred,
        "fw_identity": fw_pred,
        "media_auth": media_bundle["media_auth"],
        "source_receipt": media_bundle["source_receipt"],
        "continuity": media_bundle["continuity"],
        "visible_event": media_bundle["visible_event"],
    }

    local_media_accepted = all(
        predicates[k]["status"] == "passed"
        for k in ("media_auth", "source_receipt", "continuity", "visible_event")
    )
    full_post_flash_accepted = all(
        predicates[k]["status"] == "passed"
        for k in ("admin_receipt", "fw_identity", "media_auth", "source_receipt", "continuity", "visible_event")
    )

    gate_passed = full_post_flash_accepted if a.require_full else local_media_accepted
    if a.tailnet_host and tailnet_row["status"] != "passed":
        # Tailnet row is tracked separately; local acceptance remains independently true/false!
        pass

    receipt = {
        "schema": "fss.footage_acceptance.v1",
        "recorded_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "camera_id": a.camera_id,
        "family": a.family,
        "site": a.site,
        "stream_id": a.stream_id,
        "native_rust_pipeline": True,
        "ffmpeg_used": False,
        "local_scope": {
            "local_media_accepted": local_media_accepted,
            "full_post_flash_accepted": full_post_flash_accepted,
            "require_full": a.require_full,
            "gate_passed": gate_passed,
            "predicate_statuses": {k: v["status"] for k, v in predicates.items()},
        },
        "tailnet_scope": tailnet_row,
        "predicates": predicates,
    }

    if a.out:
        atomic_write_json(Path(a.out), receipt)
    print(json.dumps(receipt, indent=2))
    return 0 if gate_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
