#!/usr/bin/env python3
"""Conformance + loopback test for owlet_direct_connect.py (fss-kemuu).

Two independent checks:

  * byte-exact replication — building the frames with the captured session tag, random and
    credential blob must reproduce the app's own wire bytes, so the replay is the app's frame
    and not an approximation of it;
  * end-to-end through the real code path — a fake camera on loopback answers probe/nO/ACK, the
    second 0x0602, then asserts it received a ClientHello and a login sharing one tag with
    `AUTHPWD_admin` and the credential blob, and answers 0x2041; round_trip must report the grant.

  python3 tests/owlet_direct_connect_test.py
"""
import os
import socket
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "deliverables", "scripts"))

import owlet_direct_connect as dc        # noqa: E402
import owlet_grant_loop as gl            # noqa: E402

FAILURES = []

# one captured session pair (wire), from owlet_auth_java_hook_2026-11-03.log
TAG = bytes.fromhex("007d3c57439c3d36")
TAIL = bytes.fromhex("f72bcc41ac7c06bb3bb60cc5d434541af823aeca9450b4913d97a3b81430cc8e"
                    "3a2b7b7308042745")
RAND = bytes.fromhex("eefefdc9c02b1a956f612a050b21a08fa9019998e5878d84a187ad1426ab7ea9")
BLOB = bytes.fromhex("b373eb7669e67ce21436cd6c3be55f86f1e4a8ec5652eb1bab1327d09e47395a")
HELLO_W = bytes.fromhex(
    "3e6c8dcf40d010da3d2de82d70efcac8aaed94b2762f21c54db1280c45e4b809712e6d2c40d0a0ca"
    "2d6d280c40e4cad8d29fef8dd476b098cd70280cade45436b04635cbc50950802fd43816d86a43c3ae"
    "28ad8c80dc81c84702dabb214cc6308c2c112c409dacc9f187a1c6cc28c112c82e81ec80410dc9fdea"
    "8a0a7024c8da84e421208c1d90c031e0080d70e5c1daa4272d2c4000c1c83da1a106f028c1d225271d"
    "ac408151c921baab0f2025c0da45250dec40d001c3fd98e2043025c9daee2b8d8c4090f0fa2d92ca06"
    "80e4d5d0ae2f9d2c403031cb2d61180ce0e4cad86f2e8dec40d030cb2deda90d70e4cbda4e4e9da448"
    "51304a2dae280fa0e49b9a0eae8dc944c150aa2de9888cf0ec4b585e0e8d8842f1609a3d6c182c70e6"
    "ebe8416e63")
LOGIN_W = bytes.fromhex(
    "3e6c8dcf40d010da3d2fe82dc0efcad0aaed94b2760f21c54db1280c45e4b8096d2eac4c40c040cb"
    "2d6f280c40e4cad8eb6ac8c8102537df2d60280c44e5dada19a06bf83cb06d189b3ebeca4f8a7cea"
    "405b8847aaeaf3bbdea97eb22bba44c06e2e8d8c40d040fa347345f8efdd149d6e2e8d8c40d0424a"
    "dd6d380ca1f3da06ad5e46388593016f4f0bf7b08ba47b135d44945cf81308276ff9d726092fd0d1"
    "6564011a43426d79")


def check(name, cond, detail=""):
    print(f"  [{'ok ' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def test_byte_exact():
    print("byte-exact replication of the captured app frames:")
    hello, login, tag = dc.build_session_frames(b"admin", BLOB, tag=TAG, rand=RAND, tail=TAIL)
    check("session tag preserved in the ClientHello", hello[:0] == b"" and dc.HELLO_T[20:28] == TAG)
    check("ClientHello matches the app byte for byte", hello == HELLO_W,
          f"len {len(hello)} vs {len(HELLO_W)}")
    check("login matches the app byte for byte", login == LOGIN_W)
    check("both frames share the tag", dc.gl.inv_transcode(hello)[20:28]
          == dc.gl.inv_transcode(login)[20:28] == TAG)
    plain = dc.gl.inv_transcode(login)
    check("login identity is AUTHPWD_admin", plain[55:68] == b"AUTHPWD_admin")
    check("login carries the 32-byte blob", plain[69:101] == BLOB and plain[68] == 32)


class FakeCamera(threading.Thread):
    """Answers the search handshake, then verifies the client's auth frames."""

    daemon = True

    def __init__(self):
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.client = None
        self.seen = []
        self.frames = []
        self.error = None

    def send(self, plain):
        self.sock.sendto(dc.gl.transcode(plain), self.client)

    def run(self):
        try:
            while True:
                raw, addr = self.sock.recvfrom(4096)
                self.client = addr
                plain = dc.gl.inv_transcode(raw)
                typ = int.from_bytes(plain[8:10], "little")
                self.seen.append((len(raw), typ))
                if len(raw) == 88 and typ == 0x0601:      # probe
                    self.send(bytearray(b"\x00" * 200))    # nO
                    nO = bytearray(200)
                    nO[8:10] = b"\x02\x06"
                    self.send(nO)
                elif len(raw) == 88 and typ == 0x0602:     # ACK -> re-arm
                    again = bytearray(200)
                    again[8:10] = b"\x02\x06"
                    self.send(again)
                elif len(raw) in (52, 168, 291):
                    self.frames.append(raw)
                if len(raw) == 168:
                    grant = bytearray(88)
                    grant[0:2] = b"\x20\x41"
                    grant[8:10] = b"\x41\x20"
                    self.sock.sendto(dc.gl.xor_frame(bytes(grant)), addr)
                    return
        except Exception as exc:                            # noqa: BLE001
            self.error = exc


def test_loopback():
    print("loopback end to end through round_trip:")
    cam = FakeCamera()
    cam.start()
    created = []

    class Rec(socket.socket):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            created.append(self)

    saved = (gl.MY_IP, gl.l2_send, gl.l2_send_to, dc.socket.socket)
    gl.MY_IP = "127.0.0.1"
    dc.socket.socket = Rec
    # the client must send from ITS OWN socket, or the fake camera hears its own replies
    gl.l2_send = lambda payload, sport: created[-1].sendto(payload, ("127.0.0.1", cam.port))
    gl.l2_send_to = lambda payload, sport, addr: created[-1].sendto(payload, ("127.0.0.1", cam.port))
    cred = {"tutkid": "TDEWNKCZVSYLVLT7111A", "authKey": "qrTg9I00",
            "password": "461a089980584b82aa1bc24dc970dc2"}
    try:
        out, code = dc.round_trip(cred, 1, "ascii", 3.0, post_grant=0.1)
    finally:
        gl.MY_IP, gl.l2_send, gl.l2_send_to, dc.socket.socket = saved
        cam.join(timeout=3)
    check("no fake-camera error", cam.error is None, str(cam.error))
    check("round reports the grant", out.get("grant") is True, str(out.get("stage")))
    check("exit code 0", code == 0)
    lengths = [n for n, _ in cam.seen]
    # two probes (native sends the probe twice), the ACK, three beacons, then hello and login
    check("camera saw probes, ACK, beacons, hello, login",
          lengths[:8] == [88, 88, 88, 52, 52, 52, 291, 168], str(lengths))
    post = out.get("post") or []
    check("0x2041 recorded", any(r["type"] == "0x2041" for r in post), str(post))
    tags = {dc.gl.inv_transcode(f)[20:28] for f in cam.frames if len(f) in (168, 291)}
    check("hello and login carried one tag", len(tags) == 1, str(tags))
    btags = {dc.gl.inv_transcode(f)[37:45] for f in cam.frames if len(f) == 52}
    check("beacons carried the same tag", btags == tags, f"{btags} vs {tags}")


def test_blob_modes():
    print("credential blob modes:")
    pw = "461a089980584b82aa1bc24dc970dc2"
    check("ascii pads to 32", len(dc.credential_blob("ascii", pw)) == 32)
    check("ascii carries the password", dc.credential_blob("ascii", pw)[:31] == pw.encode())
    check("zero is 32 NULs", dc.credential_blob("zero", pw) == b"\x00" * 32)
    check("raw hex-decodes", dc.credential_blob("raw", pw)[:15] == bytes.fromhex(pw + "0")[:15])
    check("captured is the app's blob", dc.credential_blob("captured", pw) == BLOB)


def main() -> int:
    test_byte_exact()
    test_blob_modes()
    test_loopback()
    if FAILURES:
        print(f"\n{len(FAILURES)} failure(s): {FAILURES}")
        return 1
    print("\nall direct-connect checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
