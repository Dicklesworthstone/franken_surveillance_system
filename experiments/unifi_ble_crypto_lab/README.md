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
oversized input. The experimental host-side handshake now advances through
those messages, keeps at most two early frames while a write is pending, fences
indeterminate writes, and checks the next received API sequence through
exhaustion. It retains an uncertain pending ciphertext for reconciliation.
It does not implement BLE I/O, outgoing API sequence ownership, response
correlation, a write journal, or camera identity. Matching this synthetic
handshake is not a physical device setup.

The reference initializes both direction counters at zero under the same
public default key and derives the nonce from the counter. The reference's
first host and device packets therefore reuse a key and nonce; the public
default also does not authenticate either peer. Camera identity and a safe
secret-provisioning boundary require separate evidence and design. Do not
interpret successful decryption or receipt of `AUTH` as device authentication.
The reference documentation describes a two-byte API-part size, while its
actual implementation uses a four-byte size; neither version has been
qualified against the owned G4.

An expanded source-matched fixture was built in strict-remote job
`30098575685845135`, with terminal acknowledgment and source custody released.
The executable SHA-256 was
`c8f2f7389f8df4f464476eaafae4aadf84bdf32de4b4f8d06fe92270b1a27cd9`;
it was run on the worker and passed **12/12** tests, including the synthetic
reference transcript, early notifications, replay, bounded queue, conflicting
write outcomes, and preservation of an indeterminate pending ciphertext. The
`handshake.rs` and current `lib.rs` source hashes were respectively
`aecb0e995f0ab6d9ed46c579e6a3b6d6cd2a666b9076a17b4dc5004f9530be2c` and
`e7e9926773028bdf4b1e9080da7d9c341ab2dec1cee7353a27a0b1081e9e9b81`.
These are synthetic checks with publicly known keys, not BLE or G4 evidence.
The subsequent revision added invalid-public-key and receive-sequence
exhaustion checks. Strict-remote job `30098575685845138` compiled that source,
with terminal acknowledgment and source custody released; the resulting
Linux binary SHA-256
`1d2d49a08ab62a3238da9909ed239c6fa41ed205e0a24949564615a44d058649`
was executed separately and passed **14/14** tests. Its `handshake.rs`
SHA-256 was `773d0704f441001273f50eaa053b2dcdc3bf67cb542c5ee10dd77fbaa0f2128b`;
the previously listed `lib.rs` hash remains unchanged. This still does not
establish BLE transport behavior, authenticated identity, or real-device use.

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
