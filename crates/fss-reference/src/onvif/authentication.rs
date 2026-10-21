#![forbid(unsafe_code)]
//! Explicit WS-Security UsernameToken PasswordDigest, OASIS profile 1.1.1 §3.1.
//! This legacy protocol proof is not password storage or transport security.
//! The caller owns credential leases, unpredictable nonces, and clock authority.

use std::fmt;

use fss_tutk::digest::Sha1;

use super::wire::{SoapRequest, WireError};
use crate::rtsp::authentication::DigestCredentials;

pub use super::wire::UtcDateTime;

const WSSE_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const WSU_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
const PASSWORD_DIGEST: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";
const BASE64_BINARY: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";

/// One fresh per-request SOAP authorization. Debug never contains the username,
/// nonce, timestamp, password proof, or lengths. It owns no plaintext password.
/// This value must never be persisted in an inventory, handoff, or diagnostic.
pub struct UsernameToken {
    header: Vec<u8>,
    created: UtcDateTime,
}

impl UsernameToken {
    /// Build a PasswordDigest from already validated borrowed credentials, one
    /// fresh unpredictable 128-bit nonce, and an explicitly owned UTC timestamp.
    /// This pure operation does not acquire or renew any credential authority.
    #[must_use]
    pub fn new(credentials: &DigestCredentials<'_>, nonce: [u8; 16], created: UtcDateTime) -> Self {
        let (username, password) = credentials.username_token_parts();
        let created_text = created.to_rfc3339();
        let mut hash = Sha1::new();
        // Hash raw nonce bytes and exactly the Created bytes emitted in XML.
        hash.update(&nonce);
        hash.update(created_text.as_bytes());
        hash.update(password.as_bytes());
        let mut digest = hash.finish();
        let proof = base64(&digest);
        digest.fill(0);
        let nonce = base64(&nonce);
        let username = escaped_username(username);
        let header = format!(
            "<s:Header><wsse:Security s:mustUnderstand=\"1\" xmlns:wsse=\"{WSSE_NS}\" xmlns:wsu=\"{WSU_NS}\"><wsse:UsernameToken><wsse:Username>{username}</wsse:Username><wsse:Password Type=\"{PASSWORD_DIGEST}\">{proof}</wsse:Password><wsse:Nonce EncodingType=\"{BASE64_BINARY}\">{nonce}</wsse:Nonce><wsu:Created>{created_text}</wsu:Created></wsse:UsernameToken></wsse:Security></s:Header>"
        ).into_bytes();
        Self { header, created }
    }

    pub(super) const fn created(&self) -> UtcDateTime {
        self.created
    }
}

impl fmt::Debug for UsernameToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UsernameToken([REDACTED])")
    }
}

impl Drop for UsernameToken {
    fn drop(&mut self) {
        // Best effort only; the allocator/compiler does not promise erasure.
        self.header.fill(0);
    }
}

impl SoapRequest {
    /// Add one typed PasswordDigest header, preserving the read-only action and
    /// escaped body. Repeated signing and signing the time bootstrap are refused.
    pub fn with_username_token(self, token: &UsernameToken) -> Result<Self, WireError> {
        self.with_security_header(&token.header)
    }
}

fn escaped_username(username: &str) -> String {
    let mut escaped = String::with_capacity(username.len());
    for byte in username.bytes() {
        match byte {
            b'&' => escaped.push_str("&amp;"),
            b'<' => escaped.push_str("&lt;"),
            b'>' => escaped.push_str("&gt;"),
            b'"' => escaped.push_str("&quot;"),
            b'\'' => escaped.push_str("&apos;"),
            _ => escaped.push(char::from(byte)),
        }
    }
    escaped
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for block in bytes.chunks(3) {
        let first = block[0];
        let second = block.get(1).copied().unwrap_or(0);
        let third = block.get(2).copied().unwrap_or(0);
        encoded.push(char::from(ALPHABET[usize::from(first >> 2)]));
        encoded.push(char::from(
            ALPHABET[usize::from((first & 3) << 4 | second >> 4)],
        ));
        encoded.push(if block.len() > 1 {
            char::from(ALPHABET[usize::from((second & 15) << 2 | third >> 6)])
        } else {
            '='
        });
        encoded.push(if block.len() > 2 {
            char::from(ALPHABET[usize::from(third & 63)])
        } else {
            '='
        });
    }
    encoded
}
