#![forbid(unsafe_code)]
//! Sans-IO TUTK/IOTC NEW-protocol (magic `0xCC51`) core for owner-authorized
//! Wyze-class cameras.
//!
//! This crate owns wire formats and cryptography only: it performs no I/O,
//! opens no socket, and learns no credential from anywhere except explicit
//! owner-supplied values. Every secret-bearing input is documented; nothing
//! secret is ever logged or persisted here.
//!
//! Protocol provenance (LAB-2026-10-07, bead fss-x4a.21.2): the wire formats
//! are live-proven against owner Wyze Cam v4 (HL_CAM4, firmware 4.52.17.26)
//! via the Python reference client in the interoperability lab, and corrected
//! against the independent go2rtc implementation. Known reference-doc errors
//! that this crate does NOT inherit:
//!   * the `0x1502` HMAC-SHA1 trailer covers only the 28-byte header, not the
//!     header plus DTLS payload;
//!   * the DTLS channel lives in the HIGH byte of the `[12:13]` field
//!     (`0x0010 | channel << 8`), Main channel = 0;
//!   * `[24-27]` is the constant `01 00 00 00`, not the channel;
//!   * CC51 AV frame headers are version `0x000C` with no `0x507E` magic;
//!   * the `0x0009` message-ACK flow is mandatory (24-byte layout);
//!   * post-discovery sessions move to the discovery response's source port;
//!   * `0x1202` is a post-discovery session keepalive, not a DTLS frame.

pub mod av;
pub mod chacha;
pub mod digest;
pub mod dtls;
pub mod wire;
pub mod x25519;
pub mod xxtea;

pub use wire::{
    auth_key, derive_psk, derive_psk_truncated, new_session_id, NewProto, ProtoError,
    CHANNEL_MAIN, CMD_DISCOVERY, CMD_DTLS, CMD_KEEPALIVE, MAGIC_NEWPROTO,
};
