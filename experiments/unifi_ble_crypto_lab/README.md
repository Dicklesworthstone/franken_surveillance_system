# UniFi BLE cryptographic interoperability lab

This isolated, `forbid(unsafe_code)` experiment reproduces the packet cipher
and reference key mixing described by the third-party
[UniFi BLE client](https://github.com/zerotypic/unifi-ble-client). It reuses
the repository's existing `fss-tutk` X25519 and Poly1305 source and implements
XSalsa20 and BLAKE2b-256 for this offline lab. It has no BLE, device, network,
secret-store or provisioning access. **It is not an admitted cryptographic
provider, must not handle real credentials, and must not be used for camera
setup.** Interoperability does not establish constant-time execution, secure
erasure, independently reviewed crypto, safe entropy, device identity, or
compatibility with any physical device.

`oracle.py` generates only deterministic synthetic vectors with independent
PyNaCl/libsodium, MessagePack and Python `hashlib` implementations. The Rust
tests compare secretbox, DH mixing, BLAKE2b final block boundaries, and four
framed handshake/API messages with those outputs; they reject tampering, a
wrong key, nonce, sequence, protocol, low-order point, malformed frames, and
oversized input. Matching packet encodings are not a completed handshake: no
state machine, BLE connection, response correlation, write journal, or nonce
exhaustion owner exists here.

The reference initializes both direction counters at zero under the same
public default key and derives the nonce from the counter. The reference's
first host and device packets therefore reuse a key and nonce; the public
default also does not authenticate either peer. Camera identity and a safe
secret-provisioning boundary require separate evidence and design. Do not
interpret successful decryption or receipt of `AUTH` as device authentication.
The reference documentation describes a two-byte API-part size, while its
actual implementation uses a four-byte size; neither version has been
qualified against the owned G4.

On 2026-11-06, strict-remote RCH build job `30098575685845120` completed and
was acknowledged with source custody released. The matching Linux test binary
was then run independently on the same worker: **8 passed, 0 failed**,
including two tests inherited from the existing X25519 source. Binary SHA-256:
`c9498db5369ef8e2a1f38a08dd09eee6b5880e20dd5e4eb3d40fece89757b93e`.
The exact lab source SHA-256 was
`a127fb17cae5dde8a1b103d732597e8631eee4441d907197550c956598601fa5`;
the included `chacha.rs` and `x25519.rs` source hashes were respectively
`7fc3049402446f2341193e4d32a30690d64fccd85c58249ff75baabc0ec1d58a` and
`e3aa51673334996f42e3b8d1e64c06fd1e74f8c635b473898c11bb69107eaade`.
The isolated test workspace replicated these sources, with a reduced root
manifest for remote compilation. Seven dead-code warnings arose from including
the larger existing ChaCha module for its Poly1305 routine. This was not a
workspace qualification or a real-camera test.
