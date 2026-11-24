#!/usr/bin/env python3
"""owner_session_preflight.py — Single-command pre-flight check for fss-owner-session-yii4s.

Read-only, zero-mutation verifier that confirms EVERY agent-side prerequisite BEFORE the
operator spends physical/account time on owner-gated camera unlocks:
  1. Pure-Rust FSS binaries ready (`fss`, `fss-capture-rtsp`, `fss-import-rtsp`,
     `fss-event`, `fss-discover`).
  2. Reproducible Tuya signer image (`fss-jvm`, pinned `linux/arm64`) ready.
  3. Optional Mac Studio fleet gate (`--mac-host yi-ap` -> `fleet_status.py --gate --json`).
  4. Live TCP reachability across all registered owner cameras (`deliverables/fleet/registry.yaml`)
     + latest retained proofs (`deliverables/proofs/`).
  5. Owlet capture-point coverage precondition (`--owlet-capture-mode`):
     en1 on mac-studio is PROVEN blind to phone<->camera unicast (switched AP forwards
     unicast directly to target MAC), so `en1_only` FAILS CLOSED instead of letting the
     operator burn a live-view session on a blind capture.

Usage:
  owner_session_preflight.py [--mac-host yi-ap] [--owlet-capture-mode router_pcap|adb_phone|en1_only]
                             [--skip-network] [--json | --markdown] [--out PATH]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
PROOFS_DIR = REPO / "deliverables" / "proofs"

sys.path.insert(0, str(HERE))
import fleet_status as fs  # noqa: E402
import footage_acceptance as fa  # noqa: E402
import registry as reg_mod  # noqa: E402


CAMERA_PLAN: dict[str, dict[str, Any]] = {
    "wyze-39": {
        "probe_ports": [554, 22],
        "already_working_zero_touch": True,
        "zero_touch_status": "Live pure-Rust FSS ingestion verified (wyze-39-footage-acceptance-2026-11-23.json, strict visible-event pass, zero ffmpeg).",
        "operator_action": "OPTIONAL: power-cycle ONLY when ready to trigger armed Thingino OTA capsule (4.52.17.104.tar) for permanent root + native ONVIF/RTSP.",
        "fastest_non_exploit_path": "Already ingesting via wyze_rtsp_bridge.py -> fss-capture-rtsp -> fss-import-rtsp -> fss-event watch.",
        "why_zero_touch_blocked_evidence": "Stock iCamera OTA executor only runs after reboot when wedged; no root shell without OTA install (RootProof dropbear22/telnet9999=FAIL).",
        "predicted_receipt": "fwserve_access.jsonl complete:true + /tmp/fss_beacons.log stage=done + RootProof(dropbear22) PASS + footage_acceptance.py --require-full PASS.",
        "post_action_verify_cmd": "python3 deliverables/scripts/footage_acceptance.py --camera-id wyze-39 --family wyze-hl_cam4 --use-wyze-bridge 192.168.4.39 --credential-file <cred> --pictures 90 --publish-event",
    },
    "wyze-51": {
        "probe_ports": [554, 22],
        "already_working_zero_touch": True,
        "zero_touch_status": "Live pure-Rust FSS ingestion verified at 10fps night cadence (wyze-51-footage-acceptance-2026-11-23.json, 40/40 decoded, zero ffmpeg).",
        "operator_action": "OPTIONAL: power-cycle ONLY when ready to trigger armed Thingino OTA capsule (4.52.17.104.tar) for permanent root + native ONVIF/RTSP.",
        "fastest_non_exploit_path": "Already ingesting via wyze_rtsp_bridge.py -> fss-capture-rtsp -> fss-import-rtsp -> fss-event watch.",
        "why_zero_touch_blocked_evidence": "Same as wyze-39: stock RTSP works now; permanent Thingino flash waits on iCamera OTA trigger.",
        "predicted_receipt": "fwserve_access.jsonl complete:true + RootProof(dropbear22) PASS + footage_acceptance.py --require-full PASS.",
        "post_action_verify_cmd": "python3 deliverables/scripts/footage_acceptance.py --camera-id wyze-51 --family wyze-hl_cam4 --use-wyze-bridge 192.168.4.51 --credential-file <cred> --pictures 40 --frame-duration-ticks 9000 --source-duration-max-ticks 36000 --visible-event-mode live-variation",
    },
    "unifi-g4-instant": {
        "probe_ports": [80, 443, 554, 7447],
        "already_working_zero_touch": False,
        "zero_touch_status": "Native pure-Rust fss-discover --unifi-only verified (192.168.4.177, UVC G4 Instant, fw UVC.SAV530q.v4.70.37.67.M_9b6a37f.240320.0635).",
        "operator_action": "Enable RTSP in UniFi Protect console (port 7447) or standalone camera web UI on 192.168.4.177, then save 0600 private export JSON for fss-capture-rtsp from-unifi.",
        "fastest_non_exploit_path": "100% standards/official Protect export -> fss-capture-rtsp from-unifi --stream-transport operator-rtsp (zero exploit, zero firmware mod; see docs/UNIFI_PROTECT.md).",
        "why_zero_touch_blocked_evidence": "Ports 554/7441/7447 are closed on 192.168.4.177 and 192.168.4.1; DEP-TLS-001 (rustls) returned to ADR-0014 in VIT-026 so FSS stays plaintext-only until TLS is admitted.",
        "predicted_receipt": "0600 Protect JSON + fss-capture-rtsp from-unifi durable windows + footage_acceptance.py --family unifi-g4-instant PASS.",
        "post_action_verify_cmd": "fss-capture-rtsp from-unifi --unifi-file /path/to/g4-export.json --unifi-digest sha256:<HEX> --quality medium --stream-transport operator-rtsp --peer <CONSOLE_IP>:7447 ...",
    },
    "yi": {
        "probe_ports": [80, 554, 4444],
        "already_working_zero_touch": False,
        "zero_touch_status": "Reachable on LAN (192.168.4.20); UDP WS-Discovery + 32108/0x30 alive, TCP 80/554/4444 actively RST.",
        "operator_action": "FASTEST (30s, zero exploit): insert FAT32 microSD with pinned yi-hack release -> reboot -> RTSP+ONVIF+SSH. Alternative (3 min, no SD): one-time Yi app QR pairing to open ONVIF/RTSP.",
        "fastest_non_exploit_path": "FAT32 microSD yi-hack via vendor's own SD updater (Class D, 30s once) OR one-time Yi app QR pairing (Class B; see DEVICE_ADAPTER_MATRIX.md §3b).",
        "why_zero_touch_blocked_evidence": "Port 80/554/4444 RST across all source ports/subnets; ONVIF XAddrs is static until provisioned (EV-pack-H-006).",
        "predicted_receipt": "Port 554/80 OPEN + ONVIF GetDeviceInformation + footage_acceptance.py --family yi PASS.",
        "post_action_verify_cmd": "python3 deliverables/scripts/footage_acceptance.py --camera-id yi --family yi --peer 192.168.4.20:554 --onvif-host 192.168.4.20 ...",
    },
    "aosu": {
        "probe_ports": [443, 6668, 8888, 51028],
        "already_working_zero_touch": False,
        "zero_touch_status": "Live UDP 6667 0x23 discovery confirmed (MAC 60:d5:61:21:4d:36); offline Docker signer fss-jvm cleanly rebuilt & verified 10/10 (fss-tuya-signer-ci-po1ve CLOSED).",
        "operator_action": "Create 1 fresh Tuya IoT Platform account (iot.tuya.com) -> record new app_id + app_secret (or pair under Smart Life for official Tuya API local_key, LAB-AOSU-8).",
        "fastest_non_exploit_path": "Fresh Tuya IoT developer account -> local_key via official API (zero MITM) -> pure-Rust fss-capture-tuya (see docs/exploit/tuya-fresh-registration-runbook.md).",
        "why_zero_touch_blocked_evidence": "app_id 7hvgpakg784c3pj5qe3e returns ILLEGAL_CLIENT_ID even from fresh Contabo VPS IP (burned registration, NOT a signing bug; test_tuya_sign.py 10/10 PASS). Battery model has no stock RTSP.",
        "predicted_receipt": "aosu_tuya_api.py keyget returns 16-char local_key -> fss-capture-tuya durable EvidenceDeltaBatch.",
        "post_action_verify_cmd": "FSS_SIGN_APPID=<new_id> FSS_SIGN_SEED=<new_secret> python3 deliverables/scripts/aosu_tuya_api.py login",
    },
    "owlet": {
        "probe_ports": [80, 554],
        "already_working_zero_touch": False,
        "zero_touch_status": "1,139 live rounds + H3/H4/H5 closed-negative logged; vendor app also hits -20011 AV_ER_TIMEOUT.",
        "operator_action": "Power-cycle 192.168.4.163 to clear wedged camera DTLS gate, then open Owlet app live view while router/AP or adb-phone capture is armed (NEVER en1-only).",
        "fastest_non_exploit_path": "Physical power-cycle + router/phone-side capture of full 576B 0x2043 session registration (or UART serial console).",
        "why_zero_touch_blocked_evidence": "Camera refuses DTLS even for vendor's own app (-20011 AV_ER_TIMEOUT); fw 3.48.0 has zero remote reboot IOCtrl; en1 misses phone<->camera unicast (fss-owner-session-yii4s).",
        "predicted_receipt": "Non-truncated 576B 0x2043 registration + 0x2041 grant in router/phone pcap.",
        "post_action_verify_cmd": "python3 deliverables/scripts/owlet_replay_capture.py --pcap <router_or_phone.pcap>",
    },
    "tapo-c460": {
        "probe_ports": [443, 554, 2020, 4444],
        "already_working_zero_touch": False,
        "zero_touch_status": "Battery camera (no stock RTSP); LAN stack responds (554/2020/4444 RST), 443 sleeping between PIR wakes.",
        "operator_action": "HOLD FLASH FOR VIDEO: current OpenIPC nt98567/c460 rootfs has NO sc5336p sensor driver (boots blind). Only wake/UART-dump if pursuing kernel driver work.",
        "fastest_non_exploit_path": "Do not expect stock RTSP (battery model). footage_acceptance.py enforces verified sensor_driver + encoder_pipeline + duty_cycle_budget proof before accepting.",
        "why_zero_touch_blocked_evidence": "Battery model has no stock RTSP; current custom image lacks sc5336p kernel sensor module (HANDBACK.md §Known gap; docs/exploit/c460-openipc-flash.md).",
        "predicted_receipt": "If UART/shell obtained: full MTD backup + sensor_driver/encoder_pipeline/duty_cycle_budget compatibility JSON.",
        "post_action_verify_cmd": "python3 deliverables/scripts/footage_acceptance.py --camera-id tapo-c460 --family tapo-c460 --compat-proof-json <proof.json> ...",
    },
    "tapo-c660": {
        "probe_ports": [443, 554, 2020, 4444],
        "already_working_zero_touch": False,
        "zero_touch_status": "Battery camera (no stock RTSP); re-provisioned onto 192.168.5.76; ROP sweep + TFTP armed on mac-studio.",
        "operator_action": "HOLD FLASH FOR VIDEO: current nt98567 image has NO compiled sensor driver (boots blind). Walk-by PIR wake only useful for flash backup/driver research.",
        "fastest_non_exploit_path": "Battery model has no stock RTSP; requires verified sensor_driver + encoder_pipeline + duty_cycle_budget proof.",
        "why_zero_touch_blocked_evidence": "Built nt98567 rootfs has 0 matches for sensor_gc/sc/imx (HANDBACK.md §Known gap).",
        "predicted_receipt": "If shell obtained: full verified MTD backup via backup receivers + battery compatibility proof JSON.",
        "post_action_verify_cmd": "python3 deliverables/scripts/footage_acceptance.py --camera-id tapo-c660 --family tapo-c660 --compat-proof-json <proof.json> ...",
    },
}


def check_owlet_capture_precondition(mode: str) -> dict[str, Any]:
    """Enforce fss-owner-session-yii4s coverage precondition: en1 is blind to phone<->camera unicast."""
    if mode in ("router_pcap", "adb_phone", "tap_hub"):
        return {
            "status": "passed",
            "mode": mode,
            "reason": f"capture_point_sees_phone_camera_unicast ({mode})",
        }
    return {
        "status": "failed",
        "mode": mode,
        "reason": (
            "coverage_blind_to_phone_camera_unicast: mac-studio en1 only sees host<->camera "
            "unicast + broadcast because the AP forwards phone<->camera unicast directly to "
            "the target MAC. Arm router/AP tcpdump, adb phone tcpdump, or a tap/hub before "
            "asking the operator to open Owlet live view."
        ),
    }


def check_docker_tuya_signer(image: str = "fss-jvm") -> dict[str, Any]:
    if not shutil.which("docker"):
        return {"status": "failed", "reason": "docker_not_installed", "image": image}
    try:
        r = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "failed", "reason": f"docker_error:{exc}", "image": image}
    if r.returncode != 0:
        return {
            "status": "failed",
            "reason": f"image_not_built:{image}",
            "image": image,
            "repair": "docker build --no-cache --platform linux/arm64 -f tools/thing-sign/Dockerfile.jvm -t fss-jvm tools/thing-sign/",
        }
    try:
        parsed = json.loads(r.stdout)
        if not isinstance(parsed, list) or not parsed or not isinstance(parsed[0], dict):
            raise ValueError("unexpected_inspect_shape")
        info = parsed[0]
    except (ValueError, IndexError, TypeError) as exc:
        return {"status": "failed", "reason": f"docker_inspect_parse_error:{exc}", "image": image}
    arch = f"{info.get('Os')}/{info.get('Architecture')}"
    labels = (info.get("Config") or {}).get("Labels") or {}
    ok = arch == "linux/arm64" and labels.get("fss.platform_lock") == "linux/arm64"
    return {
        "status": "passed" if ok else "failed",
        "image": image,
        "id": str(info.get("Id") or "")[:19],
        "arch": arch,
        "platform_lock": labels.get("fss.platform_lock"),
        "reason": "pinned_arm64_signer_ready" if ok else "image_missing_platform_lock_labels_rebuild_required",
    }


def check_mac_fleet_gate(mac_host: str | None) -> dict[str, Any]:
    if not mac_host:
        return {"status": "skipped", "reason": "no_mac_host_supplied"}
    cmd = [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", mac_host,
        "cd /Users/jemanuel/projects/franken_surveillance_system && python3 deliverables/scripts/fleet_status.py --gate --json",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=40, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "failed", "host": mac_host, "reason": f"ssh_error:{exc}"}
    doc = None
    try:
        doc = json.loads(r.stdout)
    except ValueError:
        pass
    planes = doc.get("planes") if isinstance(doc, dict) else {}
    return {
        "status": "passed" if r.returncode == 0 else "failed",
        "host": mac_host,
        "rc": r.returncode,
        "plane_count": len(planes) if isinstance(planes, dict) else 0,
        "planes": planes,
        "reason": "all_fleet_planes_green" if r.returncode == 0 else f"fleet_gate_failed_rc_{r.returncode}",
    }


def _probe_single_tcp(ip: str, port: int, timeout: float) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            return "open"
        except ConnectionRefusedError:
            return "refused"
        except socket.timeout:
            return "timeout"
        except OSError as exc:
            return f"error:{type(exc).__name__}"


def probe_tcp_ports(ip: str | None, ports: list[int], timeout: float = 0.8) -> dict[str, str]:
    if not ip or not ports:
        return {}
    if len(ports) == 1:
        return {str(ports[0]): _probe_single_tcp(ip, ports[0], timeout)}
    out: dict[str, str] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(ports))) as ex:
        futs = {ex.submit(_probe_single_tcp, ip, p, timeout): p for p in ports}
        for fut, p in futs.items():
            out[str(p)] = fut.result()
    return {str(p): out[str(p)] for p in ports}


def _find_fss_discover(bins: dict[str, Path] | None, bin_dir: str | None) -> str | None:
    search_dirs: list[Path] = []
    if bin_dir:
        search_dirs.append(Path(bin_dir))
    if bins is not None:
        search_dirs.append(bins["fss"].parent)
    for env_key in ("FSS_BIN_DIR", "CARGO_TARGET_DIR"):
        v = os.environ.get(env_key)
        if v:
            p = Path(v)
            search_dirs.extend([p, p / "release", p / "debug"])
    search_dirs.extend([
        Path("/data/cargo-targets/debug"),
        Path("/data/cargo-targets/release"),
        REPO / "target" / "release",
        REPO / "target" / "debug",
    ])
    for d in search_dirs:
        cand = d / "fss-discover"
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return shutil.which("fss-discover")


def build_preflight_report(
    *,
    mac_host: str | None = None,
    owlet_capture_mode: str = "en1_only",
    skip_network: bool = False,
    bin_dir: str | None = None,
) -> dict[str, Any]:
    bins, bin_err = fa.resolve_binaries(bin_dir)
    rust_bins_check = (
        {"status": "passed", "binaries": {k: str(v) for k, v in bins.items()}}
        if bins is not None
        else {"status": "failed", "reason": bin_err}
    )
    rust_bins_check["fss_discover"] = _find_fss_discover(bins, bin_dir)

    tuya_check = check_docker_tuya_signer("fss-jvm")
    mac_check = check_mac_fleet_gate(mac_host)
    owlet_cov = check_owlet_capture_precondition(owlet_capture_mode)

    reg = reg_mod.load()
    reg_cams = reg.get("cameras") or []
    proofs = fs.latest_proofs(reg_cams)

    # Probe all camera TCP ports concurrently (bounded worker pool) so full-fleet
    # preflight completes in ~1s instead of ~20s sequentially.
    port_results_by_cam: dict[str, dict[str, str]] = {}
    if not skip_network:
        probe_tasks: list[tuple[str, str, int]] = []
        for c in reg_cams:
            cid = c["id"]
            ip = c.get("last_seen_ip")
            ports = CAMERA_PLAN.get(cid, {}).get("probe_ports", [80, 554])
            port_results_by_cam[cid] = {}
            if ip:
                for p in ports:
                    probe_tasks.append((cid, ip, p))
        if probe_tasks:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(probe_tasks))) as ex:
                futs = {
                    ex.submit(_probe_single_tcp, ip, p, 0.8): (cid, p)
                    for cid, ip, p in probe_tasks
                }
                for fut, (cid, p) in futs.items():
                    port_results_by_cam[cid][str(p)] = fut.result()

    cameras_out: list[dict[str, Any]] = []
    for c in reg_cams:
        cid = c["id"]
        plan = CAMERA_PLAN.get(cid, {})
        ip = c.get("last_seen_ip")
        ports = plan.get("probe_ports", [80, 554])
        raw_ports = port_results_by_cam.get(cid, {})
        port_res = {} if skip_network else {str(p): raw_ports[str(p)] for p in ports if str(p) in raw_ports}
        c_proofs = {
            k: {"pass": bool(ok), "timestamp": ts}
            for k, (ok, ts) in sorted((proofs.get(cid) or {}).items())
        }
        cameras_out.append({
            "id": cid,
            "family": c.get("family"),
            "model": c.get("model"),
            "mac": c.get("mac"),
            "ip": ip,
            "vector": c.get("vector"),
            "ports": port_res,
            "proofs": c_proofs,
            "already_working_zero_touch": bool(plan.get("already_working_zero_touch", False)),
            "zero_touch_status": plan.get("zero_touch_status", ""),
            "operator_action": plan.get("operator_action", ""),
            "fastest_non_exploit_path": plan.get("fastest_non_exploit_path", ""),
            "why_zero_touch_blocked_evidence": plan.get("why_zero_touch_blocked_evidence", ""),
            "predicted_receipt": plan.get("predicted_receipt", ""),
            "post_action_verify_cmd": plan.get("post_action_verify_cmd", ""),
        })

    infra_ready = (
        rust_bins_check["status"] == "passed"
        and tuya_check["status"] == "passed"
        and mac_check["status"] in ("passed", "skipped")
    )
    return {
        "schema": "fss.owner_session_preflight.v1",
        "recorded_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "registry_generation": reg.get("generation"),
        "checks": {
            "pure_rust_binaries": rust_bins_check,
            "tuya_signer_docker": tuya_check,
            "mac_fleet_gate": mac_check,
            "owlet_capture_precondition": owlet_cov,
        },
        "summary": {
            "agent_infra_ready": infra_ready,
            "owlet_capture_ready": owlet_cov["status"] == "passed",
            "cameras_total": len(cameras_out),
            "cameras_ingesting_pure_rust": sum(
                1 for c in cameras_out if c["proofs"].get("fss-footage", {}).get("pass")
            ),
            "cameras_operator_gated": sum(1 for c in cameras_out if not c["already_working_zero_touch"]),
        },
        "cameras": cameras_out,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# Prepared Owner Session Pre-Flight (`{report['recorded_at_utc']}`)",
        "",
        "## Agent-Side Prerequisites",
        "",
        f"- **Pure-Rust FSS binaries:** `{report['checks']['pure_rust_binaries']['status']}`",
        f"- **Tuya Docker signer (`fss-jvm`):** `{report['checks']['tuya_signer_docker']['status']}` ({report['checks']['tuya_signer_docker'].get('reason')})",
        f"- **Mac Studio fleet gate:** `{report['checks']['mac_fleet_gate']['status']}` ({report['checks']['mac_fleet_gate'].get('reason')})",
        f"- **Owlet capture precondition:** `{report['checks']['owlet_capture_precondition']['status']}` — {report['checks']['owlet_capture_precondition']['reason']}",
        "",
        "## Per-Camera Prepared Session Table",
        "",
        "| Camera | IP | Zero-Touch Pure-Rust? | Proofs | Smallest Operator Unlock | Fastest Non-Exploit Path |",
        "|---|---|---|---|---|---|",
    ]
    for c in report["cameras"]:
        p_str = ", ".join(f"{k}:{'PASS' if v['pass'] else 'FAIL'}" for k, v in c["proofs"].items()) or "none"
        zt = "YES" if c["already_working_zero_touch"] else "no"
        lines.append(
            f"| `{c['id']}` | `{c['ip']}` | {zt} | {p_str} | {c['operator_action']} | {c['fastest_non_exploit_path']} |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Pre-flight check for prepared owner camera session.")
    ap.add_argument("--mac-host", default=None, help="Optional SSH host for Mac Studio fleet gate (e.g. yi-ap)")
    ap.add_argument(
        "--owlet-capture-mode",
        choices=("en1_only", "router_pcap", "adb_phone", "tap_hub"),
        default="en1_only",
        help="Active Owlet capture vantage point (en1_only fails closed because AP hides phone<->camera unicast)",
    )
    ap.add_argument(
        "--require-owlet-capture",
        action="store_true",
        help="Fail closed (exit 1) unless owlet_capture_precondition passes (blocks blind en1_only runs)",
    )
    ap.add_argument("--skip-network", action="store_true", help="Skip live TCP probes across camera IPs")
    ap.add_argument("--bin-dir", default=None, help="Directory with native FSS binaries")
    ap.add_argument("--markdown", action="store_true", help="Print Markdown summary instead of JSON")
    ap.add_argument("--out", default=None, help="Write JSON report atomically to this path")
    a = ap.parse_args(argv)

    rep = build_preflight_report(
        mac_host=a.mac_host,
        owlet_capture_mode=a.owlet_capture_mode,
        skip_network=a.skip_network,
        bin_dir=a.bin_dir,
    )
    if a.out:
        fa.atomic_write_json(Path(a.out), rep)
    if a.markdown:
        print(render_markdown(rep))
    else:
        print(json.dumps(rep, indent=2))
    ok = rep["summary"]["agent_infra_ready"] and (
        rep["summary"]["owlet_capture_ready"] if a.require_owlet_capture else True
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
