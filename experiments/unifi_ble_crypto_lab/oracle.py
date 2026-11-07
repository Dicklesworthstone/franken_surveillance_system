#!/usr/bin/env python3
"""Independent, synthetic-only PyNaCl/MessagePack oracle; never use credentials."""
import hashlib
import struct

import msgpack
import nacl.bindings
import nacl.secret


def packet(key, sequence, protocol, data):
    plaintext = struct.pack(">HB", sequence, protocol) + data
    nonce = struct.pack(">H", sequence) + bytes(22)
    ciphertext = nacl.secret.SecretBox(key).encrypt(plaintext, nonce).ciphertext
    return struct.pack(">H", len(ciphertext) + 2) + ciphertext


def main():
    key = bytes(range(32))
    nonce = bytes(range(24))
    for size in (0, 43, 129):
        print(f"secretbox_{size}", nacl.secret.SecretBox(key).encrypt(bytes(range(size)), nonce).ciphertext.hex())
    for size in (0, 128, 129):
        print(f"blake2b_{size}", hashlib.blake2b(bytes(range(size)), digest_size=32).hexdigest())

    default_key = bytes.fromhex("a781f8a4a627373b70745738cdffdd1de9ae352517c374ca9afc215c39c62637")
    client_private, peer_private = bytes(range(32)), bytes(range(32, 64))
    client_public = nacl.bindings.crypto_scalarmult_base(client_private)
    peer_public = nacl.bindings.crypto_scalarmult_base(peer_private)
    shared = nacl.bindings.crypto_scalarmult(client_private, peer_public)
    derived = hashlib.blake2b(shared + client_public + peer_public, digest_size=32).digest()
    print("peer_public", peer_public.hex())
    print("derived", derived.hex())
    print("host_pub", packet(default_key, 0, 0, msgpack.packb(("DHPK", False, client_public))).hex())
    print("peer_pub", packet(default_key, 0, 0, msgpack.packb(("DHPK", True, peer_public))).hex())
    print("auth", packet(default_key, 1, 0, msgpack.packb(("AUTH", "DH"))).hex())
    print("api", packet(derived, 2, 3, b"synthetic").hex())
    print("api_response", packet(derived, 2, 3, b"response").hex())
    # Both directions use the same synthetic key and sequence-derived nonce.
    # Show the shared ciphertext prefix reveals the XOR of plaintext bytes.
    request = packet(derived, 2, 3, b"synthetic")[18:]
    response = packet(derived, 2, 3, b"response")[18:]
    request_plain = struct.pack(">HB", 2, 3) + b"synthetic"
    response_plain = struct.pack(">HB", 2, 3) + b"response"
    assert bytes(a ^ b for a, b in zip(request, response)) == bytes(
        a ^ b for a, b in zip(request_plain, response_plain)
    )
    print("synthetic_directional_nonce_reuse_xor", "confirmed")


if __name__ == "__main__":
    main()
