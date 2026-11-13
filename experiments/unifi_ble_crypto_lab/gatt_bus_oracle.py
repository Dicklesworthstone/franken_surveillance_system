#!/usr/bin/env python3
"""Deliver fixed synthetic GATT frames through a private bus to a fake peer.

Requires Python GObject bindings and dbus-daemon on Linux. The service is a
test double on an abstract Unix socket; no system bus, Bluetooth adapter,
camera, network credentials, or real device traffic is used.
"""

import os
import secrets
import socket
import struct
import subprocess
import sys
import threading

import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib  # noqa: E402


PATH = "/org/bluez/hci0/dev_01_23_45_67_89_AB/service001/char002"
INTERFACE = "org.bluez.GattCharacteristic1"
XML = """<node><interface name="org.bluez.GattCharacteristic1">
<method name="WriteValue"><arg type="ay" direction="in"/>
<arg type="a{sv}" direction="in"/></method></interface></node>"""


def receive_exact(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise RuntimeError("private bus closed early")
        data.extend(chunk)
    return bytes(data)


def receive_reply(stream, serial):
    for _ in range(16):
        header = receive_exact(stream, 16)
        endian = "<" if header[0:1] == b"l" else ">" if header[0:1] == b"B" else None
        if endian is None:
            raise ValueError("invalid reply byte order")
        body_length, _, header_length = struct.unpack(endian + "III", header[4:16])
        size = ((header_length + 7) & ~7) + body_length
        if size > 8192:
            raise ValueError("unbounded reply")
        frame = header + receive_exact(stream, size)
        reply = Gio.DBusMessage.new_from_blob(frame, Gio.DBusCapabilityFlags.NONE)
        if reply.get_reply_serial() == serial:
            return reply
    raise RuntimeError("matching private-bus reply missing")


def main() -> int:
    fixtures = {}
    for line in sys.stdin:
        if line.startswith("GATT_ORACLE_"):
            label, value = line.strip().split("=", 1)
            _, _, mode, length = label.split("_")
            key = (mode, int(length))
            if key in fixtures:
                raise ValueError("duplicate fixture")
            fixtures[key] = bytes.fromhex(value)
    if set(fixtures) != {(m, n) for m in ("request", "command") for n in (0, 3)}:
        raise ValueError("incomplete fixture set")

    address = "unix:abstract=fss-gatt-oracle-" + secrets.token_hex(12)
    daemon = subprocess.Popen(
        ["dbus-daemon", "--session", "--nofork", "--address=" + address, "--print-address=1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    connections = []
    loop = None
    thread = None
    client = None
    try:
        assert daemon.stdout is not None
        bus_address = daemon.stdout.readline().strip()
        if not bus_address.startswith(address):
            raise RuntimeError("private bus did not start")
        flags = (
            Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT
            | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION
        )
        # The fixed fixture's unique owner has five bytes; keep clients alive
        # until a private service owner with the same encoded length is issued.
        service = None
        for _ in range(100):
            connection = Gio.DBusConnection.new_for_address_sync(bus_address, flags, None, None)
            connections.append(connection)
            if len(connection.get_unique_name().encode("ascii")) == len(b":1.42"):
                service = connection
                break
        if service is None:
            raise RuntimeError("could not acquire a same-length private owner")
        owner = service.get_unique_name().encode("ascii")
        info = Gio.DBusNodeInfo.new_for_xml(XML).interfaces[0]
        received = []

        def call(_connection, _sender, path, interface, member, parameters, invocation):
            if path != PATH or interface != INTERFACE or member != "WriteValue":
                invocation.return_dbus_error("org.example.Invalid", "unexpected method")
                return
            value, options = parameters.unpack()
            received.append((bytes(value), options))
            invocation.return_value(GLib.Variant("()", ()))

        registration = service.register_object(PATH, info, call, None, None)
        if not registration:
            raise RuntimeError("fake service registration failed")
        loop = GLib.MainLoop()
        thread = threading.Thread(target=loop.run, daemon=True)
        thread.start()
        # Authenticate a separate raw client, then send the Rust-generated
        # bytes themselves; GDBus is used only for Hello and reply decoding.
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect("\0" + address.split("=", 1)[1])
        uid_hex = str(os.getuid()).encode("ascii").hex().encode("ascii")
        client.sendall(b"\0AUTH EXTERNAL " + uid_hex + b"\r\n")
        auth = bytearray()
        while not auth.endswith(b"\r\n") and len(auth) < 128:
            auth.extend(receive_exact(client, 1))
        if not auth.startswith(b"OK "):
            raise RuntimeError("private-bus authentication failed")
        client.sendall(b"BEGIN\r\n")
        hello = Gio.DBusMessage.new_method_call(
            "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello"
        )
        hello.set_serial(1)
        client.sendall(hello.to_blob(Gio.DBusCapabilityFlags.NONE))
        if receive_reply(client, 1).get_message_type() != Gio.DBusMessageType.METHOD_RETURN:
            raise RuntimeError("private-bus Hello failed")
        expected = []
        for (mode, length), blob in sorted(fixtures.items()):
            if blob.count(b":1.42") != 1:
                raise ValueError("unexpected owner in fixture")
            routed = blob.replace(b":1.42", owner, 1)
            client.sendall(routed)
            reply = receive_reply(client, 9)
            if reply.get_message_type() != Gio.DBusMessageType.METHOD_RETURN:
                raise RuntimeError("fake service did not acknowledge the write")
            expected.append((bytes([0xA5] * length), {"type": mode}))
        if received != expected:
            raise ValueError("fake service observed different calls")
        print("Private D-Bus delivered 4/4 synthetic GATT writes to fake service")
        return 0
    finally:
        if loop is not None:
            loop.quit()
        if thread is not None:
            thread.join(timeout=5)
        if client is not None:
            client.close()
        for connection in connections:
            connection.close_sync(None)
        daemon.terminate()
        daemon.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
