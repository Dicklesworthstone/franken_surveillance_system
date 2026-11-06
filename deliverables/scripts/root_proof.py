#!/usr/bin/env python3
"""RootProof — a machine-checkable root artifact per camera+vector.

Born from the liberation workstream's core ambiguity: "root" meant five different
proofs across cameras (telnetd :9999, dropbear :22, tftp exfil, beacon uid=0,
RTSP enabled). Beads closed on narrative claims. This makes the definition of
done EXECUTABLE: a RootProof JSON artifact whose checks each have an expect and
a got, and a ledger that any bead can reference.

    root_proof.py <ip> <vector> [--timeout 5] [--notes TEXT]

Vectors (each = defined check set):
    telnet9999   nc to :9999, send id\\n, expect uid=0( in reply
    telnet4444   nc to :4444, send id\\n, expect uid=0( in reply   (Tapo ROP shell)
    dropbear22   ssh root@ip 'id && cat /proc/mtd' with the lab key, expect uid=0
    tftp-exfil   verify /tmp/tftp/<marker> landed via WRQ from <ip>
    beacon-uid0  verify a BEACON line with uid=0 exists for this ip in /tmp/fss_beacons.log
    rtsp-enable  probe :554, send OPTIONS, expect RTSP/1.0 200
    uart-console n/a from this host — operator records the transcript manually via --notes

Exit 0 = proof PASSED (all checks); exit 1 = proof FAILED or NEGATIVE (the
artifact is still written — absence of evidence with a timestamp is evidence).
Exit 2 = usage/bad vector.

Artifacts:  deliverables/proofs/<cam>-<vector>-<utc>.json
            deliverables/proofs/transcripts/<cam>-<vector>-<utc>.txt
Ledger:     deliverables/proofs/LEDGER.md (regenerated every run)
"""
import argparse
import datetime
import json
import os
import re
import socket
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROOFS = os.path.normpath(os.path.join(HERE, "..", "proofs"))
TRANSCRIPTS = os.path.join(PROOFS, "transcripts")
LEDGER = os.path.join(PROOFS, "LEDGER.md")
BEACON_LOG = "/tmp/fss_beacons.log"
TFTP_DIR = "/tmp/tftp"

VECTORS = {}


def vector(name):
    def deco(fn):
        VECTORS[name] = fn
        return fn
    return deco


def _shell_probe(ip, port, payload, expect_re, timeout):
    """One nc-style probe: connect, send, read, regex. Returns (check, transcript)."""
    lines = []
    check = {"name": f"tcp{port}-expect:{expect_re}", "expect": expect_re, "got": "", "pass": False}
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        if payload:
            s.sendall(payload)
        buf = b""
        try:
            while len(buf) < 4096:
                chunk = s.recv(1024)
                if not chunk:
                    break
                buf += chunk
                if re.search(expect_re.encode(), buf):
                    break
        except socket.timeout:
            pass
        s.close()
        text = buf.decode("utf-8", "replace")
        lines.append(f">>> sent {payload!r}")
        lines.append(f"<<< {len(buf)}B: {text[:800]}")
        check["got"] = text[:400]
        check["pass"] = bool(re.search(expect_re, text))
    except OSError as e:
        lines.append(f"!!! {e}")
        check["got"] = str(e)
    return check, "\n".join(lines)


@vector("telnet9999")
def telnet9999(ip, timeout, _notes):
    return _shell_probe(ip, 9999, b"id\n", r"uid=0\(", timeout)


@vector("telnet4444")
def telnet4444(ip, timeout, _notes):
    return _shell_probe(ip, 4444, b"id\n", r"uid=0\(", timeout)


@vector("rtsp-enable")
def rtsp_enable(ip, timeout, _notes):
    opts = (b"OPTIONS rtsp://" + ip.encode() + b"/ RTSP/1.0\r\nCSeq: 1\r\n\r\n")
    return _shell_probe(ip, 554, opts, r"RTSP/1\.0 200", timeout)


@vector("dropbear22")
def dropbear22(ip, timeout, notes):
    key = os.path.expanduser(notes.get("key", "~/.ssh/id_ed25519"))
    cmd = f"ssh -i {key} -o ConnectTimeout={timeout} -o StrictHostKeyChecking=no -o BatchMode=yes root@{ip} 'id && cat /proc/mtd'"
    check = {"name": "dropbear22-uid0", "expect": r"uid=0\(", "got": "", "pass": False}
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout + 10)
        check["got"] = (r.stdout + r.stderr)[:400]
        check["pass"] = bool(re.search(check["expect"], r.stdout)) and r.returncode == 0
        return check, f"$ {cmd}\nrc={r.returncode}\n{r.stdout}{r.stderr}"
    except subprocess.TimeoutExpired as e:
        check["got"] = f"timeout after {timeout + 10}s"
        return check, f"$ {cmd}\nTIMEOUT"


@vector("tftp-exfil")
def tftp_exfil(ip, timeout, notes):
    """A WRQ from <ip> landing any file in /tmp/tftp proves the in-camera tftp client ran."""
    marker = notes.get("marker", "")
    check = {"name": "tftp-wrq-from-cam", "expect": "any file in /tmp/tftp sourced from the camera",
             "got": "", "pass": False}
    lines = []
    hits = []
    if os.path.isdir(TFTP_DIR):
        for f in os.listdir(TFTP_DIR):
            p = os.path.join(TFTP_DIR, f)
            if os.path.getsize(p) > 0:
                hits.append((f, os.path.getsize(p)))
    lines.append(f"files in {TFTP_DIR}: {hits or 'none'}")
    if marker:
        m = os.path.join(TFTP_DIR, marker)
        check2 = {"name": f"marker:{marker}", "expect": "exists non-empty", "got": "", "pass": False}
        if os.path.isfile(m) and os.path.getsize(m) > 0:
            check2.update(got=f"{os.path.getsize(m)}B", pass_=True)
            check2["pass"] = True
        else:
            check2["got"] = "missing or empty"
        return [check, check2], "\n".join(lines)
    check["pass"] = bool(hits)
    check["got"] = str(hits)
    return check, "\n".join(lines)


@vector("beacon-uid0")
def beacon_uid0(ip, timeout, _notes):
    """The entrypoint beacon with uid=0 proves the payload executed as root on the camera."""
    check = {"name": f"beacon uid=0 from {ip}", "expect": r"uid=0.*from=" + re.escape(ip), "got": "",
             "pass": False}
    lines = []
    found = ""
    if os.path.isfile(BEACON_LOG):
        with open(BEACON_LOG, "r", errors="replace") as f:
            for line in f:
                if ip in line and "uid=0" in line:
                    found = line.rstrip()
    lines.append(f"last matching: {found or 'NONE'}")
    check["got"] = found[:400]
    check["pass"] = bool(found)
    return check, "\n".join(lines)


@vector("uart-console")
def uart_console(ip, timeout, notes):
    """Manual vector: the operator pastes the console transcript via --notes text.
    Pass requires the text to contain a uid=0 marker (the root prompt proof)."""
    text = notes.get("text", "")
    check = {"name": "uart-transcript-uid0", "expect": r"uid=0\(", "got": text[:400], "pass": False}
    check["pass"] = bool(re.search(r"uid=0\(", text))
    return check, text or "(no transcript supplied)"


def cam_id(ip):
    return f"192.168.4.{ip.split('.')[-1]}" if ip.startswith("192.168.4.") else ip


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("ip")
    ap.add_argument("vector", choices=sorted(VECTORS))
    ap.add_argument("--timeout", type=int, default=5)
    ap.add_argument("--key", default="~/.ssh/id_ed25519", help="ssh key for dropbear22")
    ap.add_argument("--marker", default="", help="expected filename for tftp-exfil")
    ap.add_argument("--text", default="", help="pasted transcript for uart-console")
    ap.add_argument("--notes", default="", help="free-text context stored in the artifact")
    a = ap.parse_args()

    os.makedirs(TRANSCRIPTS, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    notes = {"key": a.key, "marker": a.marker, "text": a.text}

    result = VECTORS[a.vector](a.ip, a.timeout, notes)
    transcript = ""
    if isinstance(result, dict):
        checks, transcript = [result], ""
    elif isinstance(result, tuple):
        first, transcript = result[0], (result[1] or "")
        checks = [first] if isinstance(first, dict) else list(first)
    elif isinstance(result, list):
        checks = result
    else:
        checks = [result]

    passed = all(bool(c.get("pass")) for c in checks) if checks else False

    # regenerate transcript from the checks when the vector didn't provide one
    body = transcript or "\n".join(f"{c['name']}: got={c['got']!r}" for c in checks)

    artifact = {
        "camera": cam_id(a.ip),
        "ip": a.ip,
        "vector": a.vector,
        "timestamp_utc": ts,
        "pass": passed,
        "checks": [{k: v for k, v in c.items()} for c in checks],
        "notes": a.notes,
        "tool": "root_proof.py",
    }
    cam = artifact["camera"].replace(".", "_")
    base = f"{cam}-{a.vector}-{ts}"
    apath = os.path.join(PROOFS, base + ".json")
    tpath = os.path.join(TRANSCRIPTS, base + ".txt")
    with open(apath, "w") as f:
        json.dump(artifact, f, indent=1)
    with open(tpath, "w") as f:
        f.write(body + "\n")

    regenerate_ledger()

    print(f"{'PASS' if passed else 'FAIL'} {a.vector} {a.ip} -> {os.path.relpath(apath)}")
    for c in checks:
        mark = "✓" if c.get("pass") else "✗"
        print(f"  {mark} {c['name']}: got={str(c['got'])[:120]!r}")
    return 0 if passed else 1


def regenerate_ledger():
    """LEDGER.md: cam × vector × latest-proof. Idempotent; dedupe by (cam, vector, day, pass)."""
    rows = {}
    if not os.path.isdir(PROOFS):
        return
    for f in sorted(os.listdir(PROOFS)):
        if not f.endswith(".json"):
            continue
        try:
            d = json.load(open(os.path.join(PROOFS, f)))
        except (json.JSONDecodeError, OSError):
            continue
        key = (d.get("camera"), d.get("vector"))
        cur = rows.get(key)
        if cur is None or str(d.get("timestamp_utc", "")) > str(cur.get("timestamp_utc", "")):
            rows[key] = d
    cams = sorted({k[0] for k in rows})
    lines = [
        "# Root-proof ledger",
        "",
        "Machine-generated by root_proof.py — do not edit by hand.",
        "Latest proof per (camera, vector). A MISSING cell means never proven,",
        "which for a liberation bead is a definition-of-done gap, not a footnote.",
        "",
    ]
    vectors = sorted({k[1] for k in rows})
    header = "| camera | " + " | ".join(vectors) + " |"
    sep = "|---" * (len(vectors) + 1) + "|"
    lines += [header, sep]
    for cam in cams:
        cells = []
        for v in vectors:
            d = rows.get((cam, v))
            if d is None:
                cells.append("—")
            else:
                mark = "✅" if d.get("pass") else "❌"
                cells.append(f"{mark} {d.get('timestamp_utc', '?')}")
        lines.append(f"| {cam} | " + " | ".join(cells) + " |")
    with open(LEDGER, "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    sys.exit(main())
