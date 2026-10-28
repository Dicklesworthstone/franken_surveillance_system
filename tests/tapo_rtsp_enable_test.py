#!/usr/bin/env python3
"""Offline contract test for the Tapo RTSP provisioning path (fss-9tdk4).

The request shapes are not guesses: they are the app's own serialization
(`model/AccountInfo.java` secondary constructor + `model/AccountEnable.java`,
EV-pack-H-014 §2), and both calls were proven live on .4.70 (EV-pack-H-012 §2,
error_code 0):

  setAccountEnabled  {"user_management":{"set_account_enabled":
                      {"secname":"third_account","enabled":"on"}}}
  changeThirdAccount {"user_management":{"change_third_account":
                      {"secname":"third_account","username":U,
                       "passwd":MD5_HEX_UPPER,"old_passwd":"",
                       "ciphertext":BASE64_RSA_PKCS1,"unique_key":0}}}

The ciphertext is checked by decrypting it with the private half, so the test
fails if the padding, the key selection, or the base64 form drifts. The RTSP
probe is checked against a mock server that verifies the Digest response
itself, and the closed-port case must report not-listening (config acceptance
is not a listener).

  python3 tests/tapo_rtsp_enable_test.py
"""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
POST = os.path.join(HERE, "..", "deliverables", "scripts", "tapo_post.py")

spec = importlib.util.spec_from_file_location("tapo_post", POST)
post = importlib.util.module_from_spec(spec)
spec.loader.exec_module(post)

FAILURES = []
PASSWORD = "Fss-Third-9x7"
USER = "fssuser"


def check(name, cond, detail=""):
    tag = "ok " if cond else "FAIL"
    print("  [%s] %s%s" % (tag, name, (" — %s" % detail) if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def keypair(tmp):
    priv = os.path.join(tmp, "priv.pem")
    pub = os.path.join(tmp, "pub.pem")
    subprocess.run(["openssl", "genrsa", "-out", priv, "2048"], check=True,
                   capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", priv, "-pubout", "-out", pub], check=True,
                   capture_output=True)
    return priv, open(pub).read()


class FakeDS:
    """Records inner DS requests; answers the three calls rtsp_enable makes."""

    def __init__(self, pub_pem, fail=None):
        self.pub_pem = pub_pem
        self.fail = fail or set()
        self.inner = []

    def login(self, host, tries=0):
        return {"stok": "s", "seq": 1, "lsk": "0" * 32, "ivb": "0" * 32}

    def req(self, host, sess, inner, timeout=8):
        self.inner.append(inner)
        method = inner["method"]
        if method in self.fail:
            return {"error_code": -1, "result": {}}
        if method == "getThirdAccount":
            return {"error_code": 0, "result": {"username": "", "enabled": "off"}}
        if method == "scanApList":
            return {"error_code": 0, "result": {"ap_list": [
                {"ssid": "Aardvark", "public_key": self.pub_pem}]}}
        return {"error_code": 0, "result": {}}


def install(fake):
    post.ds.login = fake.login
    post.ds.req = fake.req


def decrypt(priv, b64):
    p = subprocess.run(["openssl", "pkeyutl", "-decrypt", "-inkey", priv,
                        "-pkeyopt", "rsa_padding_mode:pkcs1"],
                       input=base64.b64decode(b64), capture_output=True)
    return p.stdout.decode()


def test_shapes(tmp):
    print("changeThirdAccount / setAccountEnabled vs the app's serialization:")
    priv, pub = keypair(tmp)
    fake = FakeDS(pub)
    install(fake)
    rc = post.rtsp_enable("192.0.2.1", USER, PASSWORD)
    check("both writes ack -> rc 0", rc == 0, "rc=%s" % rc)

    methods = [r["method"] for r in fake.inner]
    check("order: read, scan, enable, change, read",
          methods == ["getThirdAccount", "scanApList", "setAccountEnabled",
                      "changeThirdAccount", "getThirdAccount"], repr(methods))

    enable = fake.inner[2]["params"]["user_management"]["set_account_enabled"]
    check("setAccountEnabled secname", enable.get("secname") == "third_account", repr(enable))
    check("setAccountEnabled enabled=on", enable.get("enabled") == "on", repr(enable))

    change = fake.inner[3]["params"]["user_management"]["change_third_account"]
    check("changeThirdAccount secname", change.get("secname") == "third_account", repr(change))
    check("changeThirdAccount username", change.get("username") == USER, repr(change))
    check("passwd is MD5 hex UPPERCASE",
          change.get("passwd") == hashlib.md5(PASSWORD.encode()).hexdigest().upper(),
          repr(change.get("passwd")))
    check("old_passwd present and empty", change.get("old_passwd") == "", repr(change.get("old_passwd")))
    check("unique_key 0 (proven value)", change.get("unique_key") == 0, repr(change.get("unique_key")))
    check("ciphertext decrypts to the password",
          decrypt(priv, change.get("ciphertext", "")) == PASSWORD,
          repr(decrypt(priv, change.get("ciphertext", ""))[:40]))
    check("no public_key field (Gson omits nulls)", "public_key" not in change, repr(sorted(change)))


def test_failures(tmp):
    print("write failures are reported, not swallowed:")
    _, pub = keypair(tmp)
    for method in ("setAccountEnabled", "changeThirdAccount"):
        fake = FakeDS(pub, fail={method})
        install(fake)
        check("%s error -> rc 1" % method, post.rtsp_enable("192.0.2.1", USER, PASSWORD) == 1)

    fake = FakeDS("")
    install(fake)
    check("no public_key -> rc 1", post.rtsp_enable("192.0.2.1", USER, PASSWORD) == 1)


def test_find_public_key():
    print("public key is found wherever scanApList nests it:")
    pem = "-----BEGIN PUBLIC KEY-----\nX\n-----END PUBLIC KEY-----\n"
    check("nested dict/list", post.find_public_key({"a": [{"b": pem}]}) == pem)
    check("absent -> None", post.find_public_key({"a": 1}) is None)


class MockRTSP:
    """401 with a Digest challenge, then 200 only for a correct response."""

    def __init__(self):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.seen = []
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()

    def handle(self, c):
        data = b""
        while b"\r\n\r\n" not in data:
            d = c.recv(4096)
            if not d:
                break
            data += d
        req = data.decode("latin1")
        self.seen.append(req)
        if "Authorization: Digest" not in req:
            c.sendall(b'RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n'
                      b'WWW-Authenticate: Digest realm="TP-Link IP-Camera",'
                      b'algorithm="MD5",qop="auth",nonce="abc123"\r\n\r\n')
        else:
            ok = self.valid(req)
            c.sendall(b"RTSP/1.0 %s\r\nCSeq: 2\r\n\r\n"
                      % (b"200 OK" if ok else b"401 Unauthorized"))
        c.close()

    def valid(self, req):
        uri = re.search(r"uri=\"([^\"]*)\"", req).group(1)
        nonce = re.search(r"nonce=\"([^\"]*)\"", req).group(1)
        nc = re.search(r"nc=([0-9a-f]+)", req).group(1)
        cnonce = re.search(r"cnonce=\"([^\"]*)\"", req).group(1)
        qop = re.search(r"qop=([^,\s]+)", req).group(1)
        got = re.search(r"response=\"([0-9a-f]+)\"", req).group(1)
        h = lambda s: hashlib.md5(s.encode()).hexdigest()  # noqa: E731
        ha1 = h("%s:TP-Link IP-Camera:%s" % (USER, PASSWORD))
        ha2 = h("DESCRIBE:%s" % uri)
        return got == h("%s:%s:%s:%s:%s:%s" % (ha1, nonce, nc, cnonce, qop, ha2))

    def close(self):
        self.srv.close()


def test_probe():
    print("DESCRIBE: challenge, then a digest the server verifies:")
    m = MockRTSP()
    try:
        r = post.rtsp_probe("127.0.0.1", USER, PASSWORD, m.port)
        check("listener detected", r["listening"] is True, repr(r))
        check("challenge captured", "TP-Link IP-Camera" in (r["challenge"] or ""), repr(r.get("challenge")))
        check("authenticated 200", r["authenticated"] is True and r["status"] == 200, repr(r))
        check("two DESCRIBE requests, one connection each",
              len([s for s in m.seen if s.startswith("DESCRIBE")]) == 2, repr(m.seen))
    finally:
        m.close()

    print("realm is extractable without a credential:")
    m = MockRTSP()
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = post.rtsp_realm("127.0.0.1", m.port)
        check("realm printed", rc == 0 and buf.getvalue().strip() == "TP-Link IP-Camera",
              repr(buf.getvalue()))
    finally:
        m.close()

    print("wrong password is rejected:")
    m = MockRTSP()
    try:
        r = post.rtsp_probe("127.0.0.1", USER, "wrong", m.port)
        check("401 after bad digest", r["status"] == 401 and not r["authenticated"], repr(r))
    finally:
        m.close()

    print("closed port is not a listener:")
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead = s.getsockname()[1]
    s.close()
    r = post.rtsp_probe("127.0.0.1", USER, PASSWORD, dead, timeout=1)
    check("listening False", r["listening"] is False, repr(r))
    check("verify verdict is 1", post.rtsp_verify("127.0.0.1", USER, PASSWORD, dead, dead) == 1)


def test_onvif():
    print("ONVIF liveness is a 200 on GetSystemDateAndTime:")
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(2)
    port = srv.getsockname()[1]

    def serve():
        c, _ = srv.accept()
        c.recv(4096)
        c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
        c.close()
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    check("200 -> True", post.onvif_probe("127.0.0.1", port, timeout=2) is True)
    check("closed -> False", post.onvif_probe("127.0.0.1", port, timeout=1) is False)


def test_presence():
    print("presence needs ICMP AND a resolved ARP entry:")
    real = post.subprocess.run

    class R:
        def __init__(self, rc=0, out=""):
            self.returncode = rc
            self.stdout = out

    def install(icmp, arp_line):
        def fake(cmd, **kw):
            if cmd[0] == "ping":
                return R(0 if icmp else 1)
            return R(0, arp_line)
        post.subprocess.run = fake

    try:
        install(True, "? (192.0.2.1) at aa:bb on en0")
        check("both signals -> True", post.present("192.0.2.1") is True)
        install(False, "? (192.0.2.1) at aa:bb on en0")
        check("ARP only (asleep) -> False", post.present("192.0.2.1") is False)
        install(True, "? (192.0.2.1) at (incomplete) on en0")
        check("ICMP + incomplete -> False", post.present("192.0.2.1") is False)
        install(True, "? (192.0.2.9) at aa:bb on en0")
        check("ICMP + other host -> False", post.present("192.0.2.1") is False)
    finally:
        post.subprocess.run = real

    seq = iter([False, False, True])
    real_present = post.present
    post.present = lambda host: next(seq)
    try:
        check("wait returns on the first PRESENT", post.wait_present("192.0.2.1", 1, poll=0) is True)
    finally:
        post.present = real_present

    post.present = lambda host: False
    try:
        check("wait gives up at the deadline", post.wait_present("192.0.2.1", 0.001, poll=0) is False)
    finally:
        post.present = real_present

    print("the overflow guard's arp_present uses the same census form:")
    install(True, "? (192.0.2.1) at aa:bb on en0")
    try:
        check("both signals -> True", post.ds.arp_present("192.0.2.1") is True)
        install(False, "? (192.0.2.1) at aa:bb on en0")
        check("ARP only -> False", post.ds.arp_present("192.0.2.1") is False)
        install(True, "? (192.0.2.1) at (incomplete) on en0")
        check("incomplete -> False", post.ds.arp_present("192.0.2.1") is False)

        def broken(cmd, **kw):
            if cmd[0] == "ping":
                return R(1)
            return R(1, "")
        post.subprocess.run = broken
        check("unreadable ARP -> None", post.ds.arp_present("192.0.2.1") is None)
    finally:
        post.subprocess.run = real


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        test_shapes(tmp)
        test_failures(tmp)
    test_find_public_key()
    test_probe()
    test_onvif()
    test_presence()
    if FAILURES:
        print("\n%d failure(s): %s" % (len(FAILURES), FAILURES))
        return 1
    print("\nall RTSP provisioning contract checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
