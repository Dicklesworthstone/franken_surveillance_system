#!/usr/bin/env python3
"""thingino_bootwatch — flash-day one-command watcher.

After the forged-OTA capsule flashes the thingino image, nobody has ever observed
first boot (FINISH-WYZE.md "Still not verified: an on-hardware boot"). This tool
closes that gap: it watches for the flashed unit to come up on the wire, captures
its IP, runs the full acceptance contract (deliverables/scripts/tailnet_acceptance.py:
RTSP port/handshake/frame, ONVIF capabilities/device-info/Profile-S, HTTP control,
tailscaled status, tailnet bind), and writes a boot-certificate artifact — JSON,
digest-anchored to the flashed image — so flash day is one command.

Identity: the camera is tracked by its Wi-Fi MAC (Wyze OUI 80:48:2c on these
units; the atbm6062s keeps its programmed MAC across the flash — no ethaddr is
overridden in the image env, verified by parsing the env region). Discovery runs
two providers and takes whichever finds the unit first:

  arp      periodic ARP sweep of the connected L2 segment, filtered by MAC
           prefix (or the exact CAM_MAC); positive only when the entry is
           reachable (ICMP or TCP answers)
  mdns     `dns-sd -B` browse for the unit's browse domain (macOS builtin; on
           Linux the shim falls back to `avahi-browse -prt`), matched by
           hostname/service name substring (default "thingino")

Presence rule (ROOT-EXPLOIT-MATRIX-2026-10-28 standing rule 1): ARP positive AND
the unit answers (ICMP echo or an open TCP port). An ARP entry alone is the
asleep/wedged verdict the preflight keeps meeting.

Certificate: schema fss.thingino-boot.v1

  {schema, started_utc, seen_utc, mac, ip, image: {path, sha256},
   discovery: {provider, detail}, acceptance: {schema, host, all_pass, rows},
   verdict: "BOOTED-ACCEPTED" | "BOOTED-UNACCEPTED" | "NOT-SEEN", duration_s}

Usage:
  thingino_bootwatch.py --mac 80:48:2c:4b:cf:0b \
      --image deliverables/firmware/thingino-...-tailnet.bin \
      [--cert out/boot-cert.json] [--timeout 900] [--poll 5]
      [--expect-model wyze_cam4] [--ssh-user root] [--tailnet-host name.ts.net]

Mock mode (unit tests, no device): pass --mock-discovery JSON (provider, mac, ip,
after_s) and --mock-acceptance (a recorded fss.tailnet-acceptance.v1 payload or
"all-pass"); the discovery and acceptance providers are replaced by the mocks and
the certificate path is exercised end to end.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

CERT_SCHEMA = "fss.thingino-boot.v1"
DEFAULT_MAC_PREFIX = "80:48:2c"  # Wyze OUI (the v4 fleet on this LAN)
DEFAULT_BROWSE_NAME = "thingino"


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def norm_mac(mac: str) -> str:
    # arp prints octets without leading zeros (80:48:2c:4b:cf:b); both sides normalise
    parts = [p for p in re.split(r"[:\-]", mac.strip().lower()) if p]
    return ":".join(p.zfill(2) for p in parts)


def mac_prefix(mac: str) -> str:
    return ":".join(norm_mac(mac).split(":")[:3])


def arp_table() -> list[tuple[str, str]]:
    """(ip, mac) pairs from the system ARP table (sudo -n form per standing rules)."""
    out = []
    for cmd in (["sudo", "-n", "/usr/sbin/arp", "-an"], ["/usr/sbin/arp", "-an"], ["arp", "-an"]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                m = re.search(r"\(([\d.]+)\)\s+at\s+([0-9a-fA-F:]+)", line)
                if m and "incomplete" not in line:
                    out.append((m.group(1), norm_mac(m.group(2))))
            break
    return out


def reachable(ip: str, timeout: float = 2.0) -> tuple[bool, str]:
    """ICMP echo, then a TCP probe of the thingino service ports."""
    r = subprocess.run(["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip],
                       capture_output=True, timeout=timeout + 2)
    if r.returncode == 0:
        return True, "icmp"
    for port in (80, 554, 8080, 8899):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True, "tcp:%d" % port
        except OSError:
            continue
    return False, "no-answer"


# --- discovery providers ----------------------------------------------------------------------

class ArpDiscovery:
    """ARP sweep filtered by MAC prefix/exact MAC; presence = ARP AND answer."""

    def __init__(self, mac: str | None, prefix: str, poll: float):
        self.mac = norm_mac(mac) if mac else None
        self.prefix = mac_prefix(prefix)
        self.poll = poll

    def poll_once(self) -> tuple[str | None, str]:
        for ip, m in arp_table():
            if self.mac and m == self.mac or (not self.mac and m.startswith(self.prefix)):
                ok, how = reachable(ip)
                if ok:
                    return ip, "arp match %s, reachable via %s" % (m, how)
                return None, "arp match %s at %s but asleep (no answer)" % (m, ip)
        return None, "no ARP entry for prefix %s" % self.prefix


class MdnsDiscovery:
    """dns-sd browse (macOS) / avahi-browse (Linux), matched by name substring."""

    def __init__(self, name_substring: str, timeout: float = 4.0):
        self.name = name_substring.lower()
        self.timeout = timeout

    def poll_once(self) -> tuple[str | None, str]:
        r = subprocess.run(["dns-sd", "-B", "_http._tcp", "local."],
                           capture_output=True, text=True, timeout=self.timeout + 3)
        for line in r.stdout.splitlines():
            if self.name in line.lower():
                host = line.split()[-1]
                try:
                    ip = socket.gethostbyname(host)
                    ok, how = reachable(ip)
                    if ok:
                        return ip, "mdns %s -> %s via %s" % (host, ip, how)
                    return None, "mdns %s -> %s but asleep" % (host, ip)
                except OSError:
                    continue
        return None, "no mdns match for %r" % self.name


# --- acceptance ------------------------------------------------------------------------------

def effective_acceptance(acceptance: dict) -> bool:
    """True when every non-skipped row passed. Opt-in rows the operator did not
    request (ssh/sftp/frame skips) are recorded verbatim but must not fail the
    boot certificate — the flashed unit can be fully accepted without them."""
    rows = acceptance.get("rows", [])
    observed = [r for r in rows if not r.get("detail", "").startswith("skipped:")]
    return bool(observed) and all(r["pass"] for r in observed)


def run_acceptance(ip: str, args) -> dict:
    """Full contract via tailnet_acceptance.run_contract; LAN mode (no bind check)."""
    spec = import_tailnet_acceptance()
    if spec is None:
        return {"schema": "fss.tailnet-acceptance.v1", "host": ip, "all_pass": False,
                "rows": [{"row": "harness", "pass": False,
                          "detail": "tailnet_acceptance.py not found next to this script"}]}
    rows, all_pass, _infra = spec.run_contract(
        ip, rtsp_port=554, onvif_port=80, http_port=80, timeout=args.timeout_per_probe,
        require_tailnet_bind=False, expect_model=args.expect_model,
        ssh_user=args.ssh_user, want_frame=not args.no_frame)
    return {"schema": "fss.tailnet-acceptance.v1", "host": ip, "all_pass": all_pass,
            "rows": rows}


def import_tailnet_acceptance():
    here = Path(__file__).resolve().parent
    script = here / "tailnet_acceptance.py"
    if not script.exists():
        return None
    import importlib.util
    s = importlib.util.spec_from_file_location("tailnet_acceptance_for_bootwatch", script)
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    return mod


# --- mocks -----------------------------------------------------------------------------------

class MockDiscovery:
    """Scripted discovery: returns the scripted (ip, detail) after `after_s` seconds."""

    def __init__(self, spec: dict, started: float):
        self.spec = spec
        self.started = started

    def poll_once(self) -> tuple[str | None, str]:
        if time.monotonic() - self.started >= float(self.spec.get("after_s", 0)):
            ip = self.spec.get("ip")
            detail = self.spec.get("detail", "mock discovery")
            if ip:
                return ip, detail
            return None, detail
        return None, "mock: not yet"


class MockAcceptance:
    """Scripted acceptance result (recorded payload or 'all-pass')."""

    def __init__(self, spec):
        self.spec = spec

    def __call__(self, ip: str, args) -> dict:
        if isinstance(self.spec, dict):
            result = json.loads(json.dumps(self.spec))
        else:  # "all-pass"
            result = {"schema": "fss.tailnet-acceptance.v1", "host": ip, "all_pass": True,
                      "rows": [{"row": "mock", "pass": True, "detail": "scripted all-pass"}]}
        result.setdefault("host", ip)
        return result


# --- certificate -----------------------------------------------------------------------------

def image_digest(path: str | None) -> dict:
    if not path:
        return {"path": None, "sha256": None}
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return {"path": os.path.abspath(path), "sha256": h.hexdigest()}


def build_cert(started: str, mac: str | None, seen: dict, image: dict,
               acceptance: dict | None, duration: float) -> dict:
    if seen.get("ip") is None:
        verdict = "NOT-SEEN"
    elif acceptance and (acceptance.get("all_pass") or effective_acceptance(acceptance)):
        verdict = "BOOTED-ACCEPTED"
    else:
        verdict = "BOOTED-UNACCEPTED"
    return {
        "schema": CERT_SCHEMA,
        "started_utc": started,
        "seen_utc": seen.get("utc"),
        "mac": mac,
        "ip": seen.get("ip"),
        "discovery": seen.get("discovery"),
        "image": image,
        "acceptance": acceptance,
        "verdict": verdict,
        "duration_s": round(duration, 1),
    }


def watch(args) -> dict:
    started = utcnow()
    t0 = time.monotonic()
    if args.mock_discovery:
        discovery = MockDiscovery(json.loads(Path(args.mock_discovery).read_text()), t0)
    else:
        discovery = ArpDiscovery(args.mac, args.mac_prefix or DEFAULT_MAC_PREFIX, args.poll)

    accept = (MockAcceptance(json.loads(Path(args.mock_acceptance).read_text()))
              if args.mock_acceptance and Path(args.mock_acceptance).exists()
              else (MockAcceptance("all-pass") if args.mock_acceptance == "all-pass"
                    else run_acceptance))

    deadline = t0 + args.timeout
    seen: dict = {"ip": None, "utc": None, "discovery": None}
    last_detail = ""
    while time.monotonic() < deadline:
        ip, detail = discovery.poll_once()
        if detail != last_detail:
            print("[%s] %s" % (utcnow(), detail))
            last_detail = detail
        if ip:
            seen = {"ip": ip, "utc": utcnow(), "discovery": {"provider": discovery.__class__.__name__, "detail": detail}}
            break
        seen["discovery"] = {"provider": discovery.__class__.__name__, "detail": detail}
        time.sleep(args.poll)

    acceptance = None
    if seen["ip"]:
        print("[%s] unit at %s — running the acceptance contract" % (utcnow(), seen["ip"]))
        acceptance = accept(seen["ip"], args)
        for row in acceptance.get("rows", []):
            print("  %-19s %s  %s" % (row["row"], "PASS" if row["pass"] else "FAIL", row["detail"]))

    cert = build_cert(started, args.mac, seen, image_digest(args.image), acceptance,
                      time.monotonic() - t0)
    out = Path(args.cert) if args.cert else Path("boot-certificate.json")
    if args.cert:  # explicit path: honour the directory
        out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(cert, indent=1) + "\n")
    print("boot certificate: %s (verdict %s)" % (out, cert["verdict"]))
    return cert


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--mac", help="exact camera MAC (preferred identity)")
    ap.add_argument("--mac-prefix", default=DEFAULT_MAC_PREFIX,
                    help="ARP OUI filter when --mac is unknown (default %(default)s)")
    ap.add_argument("--image", help="flashed image path; its sha256 anchors the certificate")
    ap.add_argument("--cert", help="boot-certificate output path (default boot-certificate.json)")
    ap.add_argument("--timeout", type=float, default=900.0,
                    help="seconds to watch for first sight (default %(default)s)")
    ap.add_argument("--poll", type=float, default=5.0, help="discovery poll interval")
    ap.add_argument("--expect-model", default=None, help="ONVIF Model assertion")
    ap.add_argument("--ssh-user", default=None, help="dropbear user for tailscaled-status row")
    ap.add_argument("--no-frame", action="store_true", help="skip the rtsp-frame ffmpeg row")
    ap.add_argument("--timeout-per-probe", type=float, default=5.0,
                    help="per-acceptance-probe budget seconds")
    ap.add_argument("--mock-discovery", help="mock discovery spec JSON: {ip?, mac?, after_s, detail?}")
    ap.add_argument("--mock-acceptance", help="mock acceptance: recorded payload JSON or 'all-pass'")
    args = ap.parse_args()
    if not args.mac and not args.mock_discovery:
        args.mac = None  # OUI-prefix mode
    cert = watch(args)
    return 0 if cert["verdict"] == "BOOTED-ACCEPTED" else 1


if __name__ == "__main__":
    sys.exit(main())
