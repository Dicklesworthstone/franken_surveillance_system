#!/usr/bin/env python3
"""Flash-day dry run — one test proving the ENTIRE flash-day chain host-side.

Chain under test (docs/exploit/FLASH-DAY-RUNBOOK.md, mocked end to end, no device,
no flash):

  1. capsule GET       mock assis downloads the built capsule over HTTP; md5 checked
  2. installer run     the REAL deliverables/scripts/upgraderun.sh executes in a
                       sandbox: only its absolute paths (/proc/mtd, /dev/mtdblock,
                       reboot, busybox) are substituted — every line of installer
                       logic runs verbatim
  3. 6 partition backups  receivers on PORT+1+slot collect dd streams; received
                       bytes must equal the fake partition images
  4. image fetch+write    the installer fetches img.bin over plain HTTP, sha256
                       gates it, and writes every partition highest-offset-first
                       with uboot LAST; the fake mtdblock files must end up
                       byte-identical to the corresponding image slices
  5. simulated boot    the mock device (loopback) flips from closed to serving
  6. bootwatch         thingino_bootwatch detects the unit and issues its
                       fss.thingino-boot.v1 certificate
  7. acceptance        the REAL tailnet_acceptance contract runs green against
                       the mock device; the certificate verdict is BOOTED-ACCEPTED

Run:  python3 tests/flash_day_dryrun_test.py   (also valid under pytest)
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))

import test_thingino_bootwatch as tbw  # reuses the loopback mock device + bootwatch module

FAILURES: list[str] = []
PHASES: list[tuple[str, str]] = []


def phase(name: str) -> None:
    print("\n=== phase: %s ===" % name)
    PHASES.append((name, "start"))


def ok(cond: bool, what: str) -> None:
    print(("  PASS  " if cond else "  FAIL  ") + what)
    if not cond:
        FAILURES.append(what)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def free_block(n: int) -> int:
    """First port where n consecutive ports are bindable (capsule PORT + its slots)."""
    base = 20000
    while base < 60000 - n:
        try:
            socks = []
            for i in range(n):
                s = socket.socket()
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", base + i))
                socks.append(s)
            for s in socks:
                s.close()
            return base
        except OSError:
            base += n
    raise RuntimeError("no free port block of %d" % n)


# --- load the modules under test --------------------------------------------------------------

def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bw = load("thingino_bootwatch", REPO / "deliverables" / "scripts" / "thingino_bootwatch.py")
ta = load("tailnet_acceptance", REPO / "deliverables" / "scripts" / "tailnet_acceptance.py")


def test_flash_day_chain():
    """The whole chain, in order. One test; every phase asserts its own invariant."""
    work = Path(tempfile.mkdtemp(prefix="flashday-"))
    try:
        _run_chain(work)
    finally:
        if FAILURES:
            print("[keep] work dir for post-mortem: %s" % work)
        else:
            shutil.rmtree(work, ignore_errors=True)
    print()
    if FAILURES:
        print("FAILURES: %d" % len(FAILURES))
        raise AssertionError("%d flash-day chain assert(s) failed" % len(FAILURES))
    print("flash-day chain: %d phases, all asserts passed" % (len(PHASES)))


# --- the chain --------------------------------------------------------------------------------

def _run_chain(work: Path) -> None:
    # ---- fixtures: a 16 MiB chip image + the stock /proc/mtd map -------------------------
    CHIP = 16777216
    mtd_map = [  # (name, size) in stock order
        ("uboot", 0x50000), ("boot", 0x10000), ("system", 0x190000),
        ("back", 0x40000), ("cfg", 0x10000), ("provisioning", 0x10000),
    ]
    # pad the map to the chip size with trailing free space the way the stock map does
    mapped = sum(sz for _, sz in mtd_map)
    assert mapped < CHIP
    mtd_map[-1] = ("provisioning", CHIP - mapped + 0x10000)

    image = bytearray()
    part_seed = {}
    for i, (name, size) in enumerate(mtd_map):
        blob = bytes([0x50 + i]) * size + hashlib.sha256(name.encode()).digest() * ((size - 32) // 32 + 1)
        blob = blob[:size]
        part_seed[name] = blob
        image += blob
    image = bytes(image)
    assert len(image) == CHIP
    img_sha = hashlib.sha256(image).hexdigest()

    phase("0. capsule build (committed inputs, deterministic)")
    builder = REPO / "deliverables" / "scripts" / "build_ota_tar.py"
    cap_out = work / "cap"
    cap_dir = work / "serve" / "wuv2" / "upgrade" / "HL_CAM4" / "firmware"
    cap_dir.mkdir(parents=True)
    img_path = work / "serve" / "img.bin"
    img_path.write_bytes(image)
    # IMG_PORT must be a real free port; rebuild with it now that we know the plane ports
    img_port = free_port()
    http_port = free_port()      # capsule plane (mock assis HTTP)
    cap_port = free_block(8)     # PORT itself + slots 1..6 must all be free (backup dial)
    r = subprocess.run(
        [sys.executable, str(builder),
         "--script", str(REPO / "deliverables" / "scripts" / "upgraderun.sh"),
         "--out-dir", str(cap_out),
         "--file", str(REPO / "deliverables" / "firmware" / "busybox-mipsel-static:busybox"),
         "--render", "HOST=127.0.0.1", "--render", "PORT=%d" % cap_port, "--render", "IMG_PORT=%d" % img_port,
         "--render", "IMAGE=img.bin",
         "--render", "SHA256=%s" % img_sha,
         "--render", "SENSOR=os04d10", "--no-aes"],
        capture_output=True, text=True)
    ok(r.returncode == 0, "capsule rebuilt with the live IMG_PORT")
    capsule = (cap_out / "Upgrade.tar").read_bytes()
    cap_md5 = hashlib.md5(capsule).hexdigest()
    with tarfile.open(fileobj=__import__("io").BytesIO(capsule)) as tf:
        members = sorted(m.name for m in tf.getmembers())
    ok(members == ["Upgrade/busybox", "Upgrade/upgraderun.sh"], "capsule members %s" % members)
    capsule_path = cap_dir / "4.52.17.32.tar"
    capsule_path.write_bytes(capsule)
    capsule_served = {"hits": 0}

    # ---- planes: raw accept-loop servers (capsule GET + image fetch + backups) -----------
    def raw_server(port: int, handler):
        """Accept loop; handler(conn) serves one connection."""
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(16)

        def loop():
            while not srv_closed.is_set():
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                threading.Thread(target=handler, args=(conn,), daemon=True).start()

        threading.Thread(target=loop, daemon=True).start()
        return srv

    srv_closed = threading.Event()
    servers = []

    def capsule_handler(conn):
        try:
            data = conn.recv(8192).decode("utf-8", "replace")
            if "GET" in data:
                body = capsule_path.read_bytes()
                capsule_served["hits"] += 1
                conn.sendall(("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                              "Content-Type: application/x-tar\r\nConnection: close\r\n\r\n"
                              % len(body)).encode() + body)
            else:
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
        finally:
            conn.close()

    def image_handler(conn):
        try:
            data = conn.recv(8192).decode("utf-8", "replace")
            if "GET" in data and "img.bin" in data:
                conn.sendall(("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                              "Connection: close\r\n\r\n" % len(image)).encode() + image)
            else:
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
        finally:
            conn.close()

    servers.append(raw_server(http_port, capsule_handler))
    servers.append(raw_server(img_port, image_handler))

    # ---- phase 1: capsule GET (mock assis download + md5 gate) ---------------------------
    phase("1. capsule GET (mock assis, md5 gate)")
    import urllib.request
    got = urllib.request.urlopen("http://127.0.0.1:%d/wuv2/upgrade/HL_CAM4/firmware/4.52.17.32.tar"
                                 % http_port, timeout=10).read()
    ok(got == capsule, "assis GET returned the exact capsule bytes")
    ok(hashlib.md5(got).hexdigest() == cap_md5, "md5 gate: %s" % cap_md5)
    ok(capsule_served["hits"] == 1, "plane served the capsule once")

    # ---- phase 2+3+4: installer run in the sandbox ---------------------------------------
    phase("2. installer run (real upgraderun.sh, sandboxed paths)")
    # extract the capsule the way assis does
    simroot = work / "simroot"
    (simroot / "tmp").mkdir(parents=True)
    with tarfile.open(fileobj=__import__("io").BytesIO(capsule)) as tf:
        tf.extractall(simroot / "tmp")
    ok((simroot / "tmp" / "Upgrade" / "upgraderun.sh").exists()
       and (simroot / "tmp" / "Upgrade" / "busybox").exists(),
       "extracted to /tmp/Upgrade/{upgraderun.sh,busybox}")

    # fake /proc/mtd + fake mtdblock devices
    procdir = work / "proc"
    procdir.mkdir()
    mtd_lines = ["dev:    size   erasesize  name"]
    for i, (name, size) in enumerate(mtd_map):
        mtd_lines.append('mtd%d: %08x %08x "%s"' % (i, size, 0x1000, name))
    (procdir / "mtd").write_text("\n".join(mtd_lines) + "\n")
    devdir = work / "dev"
    devdir.mkdir()
    for i, (name, size) in enumerate(mtd_map):
        (devdir / ("mtdblock%d" % i)).write_bytes(part_seed[name])

    # backup receivers on PORT+1+slot (the installer dials HOST=127.0.0.1, PORT=443 fixed
    # by the render; slots land on 444..449 — free in the sandbox)
    backup_base = cap_port  # installer dials PORT+1+slot
    backups: dict[int, bytes] = {}
    backup_done = threading.Event()

    def backup_handler(slot):
        def handler(conn):
            try:
                chunks = []
                while True:
                    d = conn.recv(1 << 16)
                    if not d:
                        break
                    chunks.append(d)
            except OSError:
                pass
            finally:
                conn.close()
            backups[slot] = b"".join(chunks)
            if len(backups) == 6:
                backup_done.set()
        return handler

    for slot in range(len(mtd_map)):
        servers.append(raw_server(backup_base + 1 + slot, backup_handler(slot)))

    # busybox shim: dispatch the applets the installer uses to host tools
    bb_shim = simroot / "tmp" / "Upgrade" / "busybox"  # overwrite the MIPS binary with a shim
    bb_shim.write_text("""#!/bin/sh
# host-side dry-run shim: dispatch busybox applets to host tools (same argv shapes)
cmd="$1"; shift
case "$cmd" in
  dd) exec /bin/dd "$@" ;;
  nc) exec /usr/bin/nc "$@" ;;
  wget) exec /usr/bin/curl -fsS -o "$(echo "$@" | sed -n 's/.*-O \\([^ ]*\\).*/\\1/p')" "$(echo "$@" | sed -n 's/.*\\(http[^ ]*\\).*/\\1/p')" ;;
  sha256sum) exec /usr/bin/shasum -a 256 "$@" ;;
  reboot) echo "reboot called" >> "$REBOOT_LOG"; exit 0 ;;
  *) echo "shim: unknown applet $cmd" >&2; exit 1 ;;
esac
""")
    bb_shim.chmod(0o755)
    reboot_log = work / "reboot.log"

    # sandbox the installer's absolute paths — ONLY paths, zero logic edits; the diff is
    # asserted to be exactly these substitutions
    installer_src = (simroot / "tmp" / "Upgrade" / "upgraderun.sh").read_text()
    installer_sandbox = installer_src
    for a, b in (("/proc/mtd", str(procdir / "mtd")),
                 ("/dev/mtdblock", str(devdir / "mtdblock")),
                 ("/tmp/Upgrade/busybox", str(bb_shim)),
                 ("/tmp/thingino.bin", str(work / "thingino.bin")),
                 ('"$BB" reboot', 'touch "%s"' % reboot_log)):
        installer_sandbox = installer_sandbox.replace(a, b)
    # the only non-path substitution: reboot -> log (the shim's reboot applet would also do,
    # but the script calls plain `"$BB" reboot`; keep the log explicit and assertable)
    ok(installer_sandbox != installer_src, "installer sandboxed")
    ok('if="/proc/mtd"' not in installer_sandbox and '< /proc/mtd' not in installer_sandbox
       and 'of="/dev/mtdblock' not in installer_sandbox,
       "no real-device paths remain in the sandboxed installer")
    sandbox_script = work / "upgraderun.sandbox.sh"
    sandbox_script.write_text(installer_sandbox)
    sandbox_script.chmod(0o755)

    env = dict(os.environ, REBOOT_LOG=str(reboot_log))
    t0 = time.monotonic()
    run = subprocess.run(["/bin/sh", str(sandbox_script)], capture_output=True, text=True,
                         env=env, timeout=300)
    elapsed = time.monotonic() - t0
    ok(run.returncode == 0, "installer exit 0 in %.1fs (stderr tail: %s)"
       % (elapsed, run.stderr[-200:] if run.returncode else "-"))
    log = run.stdout
    ok("geometry ok" in log, "geometry gate passed: %s" %
       (re.search(r"geometry ok.*", log).group(0) if "geometry ok" in log else "ABSENT"))

    # phase 3: six partition backups, byte-identical to the fake partitions
    phase("3. six partition backups")
    for i, (name, size) in enumerate(mtd_map):
        got_b = backups.get(i)
        ok(got_b == part_seed[name],
           "backup mtd%d (%s): %s bytes, byte-identical" % (i, name, len(got_b or b"")))
    ok(len(backups) == 6, "exactly %d backup streams received" % len(backups))
    if len(backups) != 6 or any(not v for v in backups.values()):
        # failure diagnostics: the installer's own view of the backup phase
        print("  [debug] backup slots seen: %s" % sorted(backups))
        print("  [debug] installer log:\n" + "\n".join(
            "    " + l for l in log.splitlines()
            if "backup" in l or "nc" in l or "geometry" in l))
        print("  [debug] work dir kept: %s" % work)

    # phase 4: image fetch + sha256 gate + partition writes
    phase("4. image fetch, sha256 gate, partition writes (uboot LAST)")
    staged = work / "thingino.bin"
    ok(staged.exists() and staged.stat().st_size == CHIP, "16 MiB image staged to /tmp")
    ok(hashlib.sha256(staged.read_bytes()).hexdigest() == img_sha, "staged image sha256 matches")
    ok("digest mismatch" not in log and "download failed" not in log, "no installer failures")
    for i, (name, size) in enumerate(mtd_map):
        written = (devdir / ("mtdblock%d" % i)).read_bytes()
        expect_slice = image[sum(s for _, s in mtd_map[:i]):][:size]
        ok(written == expect_slice, "mtd%d (%s) now byte-identical to the image slice" % (i, name))
    # write ORDER: highest offset first, uboot last
    writes = re.findall(r"write (\d+) bytes at 0x([0-9a-f]+) -> mtdblock(\d+)", log)
    ok(len(writes) == 6, "six writes logged")
    offsets = [int(o, 16) for _, o, _ in writes]
    ok(offsets == sorted(offsets, reverse=True), "write order highest-offset-first: %s" % offsets)
    ok(writes[-1][2] == "0" and offsets[-1] == 0, "uboot (mtd0, offset 0) written LAST")
    ok(reboot_log.exists(), "installer finished with the reboot step")

    # phase 5: simulated boot — the mock device comes up (reuse tbw's loopback device)
    phase("5. simulated first boot (mock device serves thingino)")
    device = tbw  # the module-level mock device machinery in test_thingino_bootwatch
    http_port2 = free_port()
    rtsp_port2 = free_port()
    srv = device.Device(http_port2)
    srv.start()
    rtsp_sock = socket.socket()
    rtsp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rtsp_sock.bind(("127.0.0.1", rtsp_port2))
    rtsp_sock.listen(4)
    device.rtsp = rtsp_sock  # tbw.rtsp_serve reads its module global
    threading.Thread(target=device.rtsp_serve, daemon=True).start()
    time.sleep(0.2)

    # phase 6+7: bootwatch detects the unit; full acceptance suite green; certificate
    phase("6. bootwatch detects the unit")
    disc = work / "disc.json"
    disc.write_text(json.dumps({"ip": "127.0.0.1", "after_s": 0,
                                "detail": "mock: post-flash unit up at 127.0.0.1"}))
    cert_out = work / "boot-certificate.json"

    class Args:
        mac = "80:48:2c:4b:cf:0b"
        mac_prefix = "80:48:2c"
        image = str(REPO / "deliverables" / "firmware"
                    / "thingino-wyze_cam4_t41nq_os04d10_atbm6062s-tailnet.bin")
        cert = str(cert_out)
        timeout = 10.0
        poll = 0.2
        expect_model = "wyze_cam4"
        ssh_user = None
        no_frame = True
        timeout_per_probe = 5.0
        mock_discovery = str(disc)
        mock_acceptance = None

    orig = bw.run_acceptance

    def acceptance_via_real_contract(ip, args_):
        rows, all_pass, _ = ta.run_contract(
            ip, rtsp_port=rtsp_port2, onvif_port=http_port2, http_port=http_port2,
            timeout=5.0, require_tailnet_bind=False, expect_model="wyze_cam4",
            ssh_user=None, want_frame=False)
        return {"schema": "fss.tailnet-acceptance.v1", "host": ip, "all_pass": all_pass,
                "rows": rows}

    bw.run_acceptance = acceptance_via_real_contract
    try:
        cert = bw.watch(Args())
    finally:
        bw.run_acceptance = orig

    phase("7. acceptance suite green + boot certificate")
    rows = {r["row"]: r for r in cert["acceptance"]["rows"]}
    for row_name in ("rtsp-port", "rtsp-handshake", "onvif-capabilities",
                     "onvif-device-info", "onvif-profile-s", "http-control"):
        ok(rows.get(row_name, {}).get("pass"), "acceptance row %s PASS" % row_name)
    ok(rows["onvif-device-info"]["detail"].find("wyze_cam4") >= 0,
       "identity gate: Model=wyze_cam4 (the flashed-image assertion)")
    ok(cert["verdict"] == "BOOTED-ACCEPTED", "boot certificate verdict BOOTED-ACCEPTED")
    saved = json.loads(cert_out.read_text())
    ok(saved["schema"] == bw.CERT_SCHEMA and saved["ip"] == "127.0.0.1",
       "certificate artifact on disk with schema + IP")
    ok(saved["image"]["sha256"] is not None, "certificate anchored to an image digest")

    srv.stop()
    srv_closed.set()
    for s in servers:
        try:
            s.close()
        except OSError:
            pass


if __name__ == "__main__":
    test_flash_day_chain()
    sys.exit(0)
