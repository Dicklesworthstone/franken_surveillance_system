#!/usr/bin/env python3
"""Check synthetic Rust GATT call fixtures with the system GDBus parser.

Read GATT_ORACLE_<mode>_<length>=<hex> lines from stdin. This is an offline
interoperability check, not a Bluetooth connection, authorization, or camera
test. Never pass real camera traffic or credentials to this fixture.
"""

import sys

import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio  # noqa: E402


def main() -> int:
    seen = set()
    for line in sys.stdin:
        if not line.startswith("GATT_ORACLE_"):
            continue
        label, hex_bytes = line.strip().split("=", 1)
        _, _, mode, length_text = label.split("_")
        if mode not in ("request", "command") or length_text not in ("0", "3"):
            raise ValueError("unexpected fixture label")
        key = (mode, int(length_text))
        if key in seen:
            raise ValueError("duplicate fixture")
        seen.add(key)
        message = Gio.DBusMessage.new_from_blob(
            bytes.fromhex(hex_bytes), Gio.DBusCapabilityFlags.NONE
        )
        if message.get_message_type() != Gio.DBusMessageType.METHOD_CALL:
            raise ValueError("wrong message type")
        if message.get_flags() != Gio.DBusMessageFlags.NO_AUTO_START:
            raise ValueError("wrong message flags")
        if message.get_serial() != 9 or message.get_destination() != ":1.42":
            raise ValueError("wrong serial or destination")
        if message.get_path() != "/org/bluez/hci0/dev_01_23_45_67_89_AB/service001/char002":
            raise ValueError("wrong synthetic object path")
        if message.get_interface() != "org.bluez.GattCharacteristic1":
            raise ValueError("wrong interface")
        if message.get_member() != "WriteValue" or message.get_signature() != "aya{sv}":
            raise ValueError("wrong method or signature")
        payload, options = message.get_body().unpack()
        if bytes(payload) != bytes([0xA5] * key[1]) or options != {"type": mode}:
            raise ValueError("wrong synthetic body")
    expected = {(mode, length) for mode in ("request", "command") for length in (0, 3)}
    if seen != expected:
        raise ValueError("missing synthetic fixtures")
    print("GDBus accepted 4/4 synthetic GATT write fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
