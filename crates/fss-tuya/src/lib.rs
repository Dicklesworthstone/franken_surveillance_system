#![forbid(unsafe_code)]
//! Sans-IO Tuya LAN protocol core (55AA / 6699 framing, AES-128-ECB/GCM,
//! 3.4/3.5 session negotiation) for owner-authorized devices, plus the
//! deterministic homebase simulator of INTEROPERABILITY_LAB §5.
//!
//! This crate owns wire formats, cryptography, and the simulator state
//! machine only: it performs no I/O, opens no socket, and learns no
//! credential from anywhere except explicit owner-supplied values. Every
//! secret-bearing input is documented; nothing secret is ever logged or
//! persisted here. Simulator keys are test fixtures, never real device keys.
//!
//! Protocol provenance (LAB-AOSU-4, bead fss-x4a.21.3.4): framing and the
//! 3.4/3.5 session flow are mirrored against the public tinytuya
//! implementation (MIT) read as a laboratory oracle — production semantics
//! here are first-party safe Rust. Wire facts encoded:
//!   * 55AA frames: `prefix | seq | cmd | len` (16-byte header), then
//!     `retcode? | payload | crc32 | 0x0000AA55`; with an HMAC key (3.4) the
//!     CRC32 trailer is replaced by HMAC-SHA256(key, header|payload).
//!   * 6699 frames (3.5): `prefix | 0 | seq | cmd | len` (20-byte header),
//!     then `iv(12) | ciphertext | gcm-tag(16)` AES-128-GCM under the session
//!     or device key with AAD = header bytes `[4..20]`, then `0x00009966`.
//!   * 3.4/3.5 session negotiation: client nonce (cmd 3) → device nonce +
//!     HMAC-SHA256(local_key, client_nonce) (cmd 4) → client
//!     HMAC-SHA256(local_key, device_nonce) (cmd 5); session key is
//!     AES-128(local_key) over `local_nonce ^ remote_nonce` — ECB (3.4) or
//!     GCM with iv = `client_nonce[..12]` taking the first ciphertext block
//!     (3.5).
//!   * LAN broadcast beacons: cmd 0x13 (`UDP_NEW`, AES-128-ECB under the
//!     well-known udpkey — a public protocol constant) and cmd 0x23
//!     (`BOARDCAST_LPV34`, AES-128-ECB under the device local_key).

pub mod crypto;
pub mod sim;
pub mod wire;
