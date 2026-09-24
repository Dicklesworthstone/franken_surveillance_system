#![forbid(unsafe_code)]
//! Bounded Digest authentication for explicitly authorized RTSP credential owners.
//! No I/O, credential discovery, automatic downgrade, or source-authenticity claim.

mod md5;

use fss_core::ContentDigest;
use std::fmt::{self, Write as _};

/// Maximum accepted WWW-Authenticate value; never retained by the public RTSP parser.
pub const MAX_CHALLENGE_BYTES: usize = 2_048;
/// Maximum generated Authorization value (not the full request).
pub const MAX_AUTHORIZATION_BYTES: usize = 4_096;

/// Negotiated Digest algorithm. MD5 is solely a legacy wire-protocol primitive,
/// never an FSS content digest, password-storage hash, or integrity algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestAlgorithm {
    /// RFC 7616 SHA-256 with qop=auth.
    Sha256,
    /// RFC 7616 SHA-256-sess with qop=auth.
    Sha256Session,
    /// Explicitly enabled legacy MD5 interoperability.
    LegacyMd5,
    /// Explicitly enabled legacy MD5-sess interoperability.
    LegacyMd5Session,
}
impl DigestAlgorithm {
    fn label(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha256Session => "SHA-256-sess",
            Self::LegacyMd5 => "MD5",
            Self::LegacyMd5Session => "MD5-sess",
        }
    }
    fn session(self) -> bool {
        matches!(self, Self::Sha256Session | Self::LegacyMd5Session)
    }
    pub(super) fn legacy(self) -> bool {
        matches!(self, Self::LegacyMd5 | Self::LegacyMd5Session)
    }
    fn hash(self, bytes: &[u8]) -> Result<String, AuthenticationError> {
        if self.legacy() {
            hex(&md5::digest(bytes))
        } else {
            hex(&ContentDigest::try_sha256(bytes)
                .map_err(|_| AuthenticationError::Capacity)?
                .bytes())
        }
    }
}

/// Owner policy, never widened by a server challenge.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DigestPolicy {
    /// Permit MD5/MD5-sess, including the historical omitted algorithm spelling.
    /// Disabled by default. This does not claim resistance to offline guessing.
    pub allow_legacy_md5: bool,
    /// Permit RFC 2069 responses without qop, only together with legacy MD5.
    /// Disabled by default; qop omission never downgrades SHA-256.
    pub allow_legacy_no_qop: bool,
}

/// Payload-free refusal; no server text, nonce, URI, username, or password is echoed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationError {
    /// Unsupported scheme, algorithm, qop, charset, or directive.
    Unsupported,
    /// Malformed/duplicate fields or unsafe quoted/header input.
    Malformed,
    /// The challenge realm does not equal the credential owner's pinned realm.
    Realm,
    /// Input, allocation, or generated output exceeds a fixed budget.
    Capacity,
    /// Invalid bounded ASCII username/password supplied by the credential owner.
    Credentials,
    /// Counter exhausted, replayed nonce, or forbidden authentication downgrade.
    Replay,
    /// Authentication retries for the current command were exhausted.
    RetryLimit,
    /// Raw input is not one exact matching, complete 401 response.
    Response,
    /// No configured credential owner/challenge is available for this operation.
    State,
}
impl fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RTSP authentication refusal: {self:?}")
    }
}
impl std::error::Error for AuthenticationError {}

/// Borrowed credentials. No owned password is stored in a client session. The
/// caller remains responsible for secret storage, authorization and memory erasure.
/// Debug deliberately reveals neither the username nor the password, nor lengths.
pub struct DigestCredentials<'a> {
    username: &'a str,
    password: &'a str,
}
impl<'a> DigestCredentials<'a> {
    /// Validate the deliberately bounded ASCII interoperability subset. Colons
    /// in usernames and controls in either field are refused; passwords may contain ':'.
    pub fn new(username: &'a str, password: &'a str) -> Result<Self, AuthenticationError> {
        if username.is_empty()
            || username.len() > 256
            || password.len() > 1_024
            || username.contains(':')
            || !quoted_ascii(username)
            || !quoted_ascii(password)
        {
            return Err(AuthenticationError::Credentials);
        }
        Ok(Self { username, password })
    }
}
impl fmt::Debug for DigestCredentials<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DigestCredentials([REDACTED])")
    }
}

/// Challenge metadata is sensitive. This value is neither Clone nor printable;
/// the ordinary RTSP parser continues to expose only redacted authentication flags.
pub struct DigestChallenge {
    realm: String,
    nonce: String,
    opaque: Option<String>,
    algorithm: DigestAlgorithm,
    qop_auth: bool,
    stale: bool,
    userhash: bool,
}
impl fmt::Debug for DigestChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DigestChallenge")
            .field("algorithm", &self.algorithm)
            .field("qop_auth", &self.qop_auth)
            .field("stale", &self.stale)
            .finish_non_exhaustive()
    }
}
impl DigestChallenge {
    /// Parse exactly one Digest challenge, with duplicate fields rejected even
    /// when their spellings differ in case. Multiple challenges must be separated
    /// and selected by an authorized owner; there is no automatic weaker fallback.
    pub fn parse(
        value: &str,
        expected_realm: &str,
        policy: DigestPolicy,
    ) -> Result<Self, AuthenticationError> {
        if value.len() > MAX_CHALLENGE_BYTES || expected_realm.len() > 512 {
            return Err(AuthenticationError::Capacity);
        }
        if !quoted_ascii(expected_realm) {
            return Err(AuthenticationError::Realm);
        }
        if value.bytes().any(|b| b < 32 && b != b'\t' || b >= 127) {
            return Err(AuthenticationError::Malformed);
        }
        let (scheme, rest) = value
            .trim()
            .split_once([' ', '\t'])
            .ok_or(AuthenticationError::Malformed)?;
        if !scheme.eq_ignore_ascii_case("Digest") {
            return Err(AuthenticationError::Unsupported);
        }
        let fields = fields(rest)?;
        let take = |name: &str| {
            fields
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };
        let realm = take("realm").ok_or(AuthenticationError::Malformed)?;
        if realm != expected_realm {
            return Err(AuthenticationError::Realm);
        }
        let nonce = take("nonce").ok_or(AuthenticationError::Malformed)?;
        if nonce.is_empty() || nonce.len() > 512 {
            return Err(AuthenticationError::Malformed);
        }
        let algorithm = match take("algorithm")
            .unwrap_or("MD5")
            .to_ascii_lowercase()
            .as_str()
        {
            "sha-256" => DigestAlgorithm::Sha256,
            "sha-256-sess" => DigestAlgorithm::Sha256Session,
            "md5" => DigestAlgorithm::LegacyMd5,
            "md5-sess" => DigestAlgorithm::LegacyMd5Session,
            _ => return Err(AuthenticationError::Unsupported),
        };
        if algorithm.legacy() && !policy.allow_legacy_md5 {
            return Err(AuthenticationError::Unsupported);
        }
        let qop_auth = if let Some(qop) = take("qop") {
            let mut found = false;
            for item in qop.split(',').map(str::trim) {
                if item.is_empty() || !item.bytes().all(token) {
                    return Err(AuthenticationError::Malformed);
                }
                if item == "auth" {
                    found = true;
                }
            }
            if !found {
                return Err(AuthenticationError::Unsupported);
            }
            true
        } else {
            if !algorithm.legacy() || !policy.allow_legacy_no_qop {
                return Err(AuthenticationError::Unsupported);
            }
            false
        };
        let boolean = |name: &str| match take(name) {
            None | Some("false") => Ok(false),
            Some("true") => Ok(true),
            _ => Err(AuthenticationError::Malformed),
        };
        if take("charset").is_some_and(|s| !s.eq_ignore_ascii_case("UTF-8")) {
            return Err(AuthenticationError::Unsupported);
        }
        if take("opaque").is_some_and(|s| s.len() > 512) {
            return Err(AuthenticationError::Capacity);
        }
        Ok(Self {
            realm: realm.to_owned(),
            nonce: nonce.to_owned(),
            opaque: take("opaque").map(str::to_owned),
            algorithm,
            qop_auth,
            stale: boolean("stale")?,
            userhash: boolean("userhash")?,
        })
    }
    /// Negotiated algorithm, without exposing challenge text.
    pub fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }
    /// Whether the server asserted nonce staleness; not trusted on its own.
    pub fn stale(&self) -> bool {
        self.stale
    }
    pub(super) fn same_nonce(&self, other: &Self) -> bool {
        self.nonce == other.nonce
    }
    pub(super) fn no_weaker_than(&self, other: &Self) -> bool {
        (!self.algorithm.legacy() || other.algorithm.legacy())
            && (self.qop_auth || !other.qop_auth)
            && (self.userhash || !other.userhash)
    }

    /// Calculate one wire value. The URI MUST be the exact request-target, not
    /// a normalized path. This pure calculation grants no network authority.
    /// The RTSP session adapter additionally binds method/target, CSeq and deadline.
    /// Supply fresh unpredictable 128-bit cnonce bytes from the owner; no clock,
    /// process ID, deterministic RNG or ambient entropy source is substituted here.
    pub fn authorize(
        &self,
        method: &str,
        uri: &str,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        nonce_count: u32,
    ) -> Result<DigestAuthorization, AuthenticationError> {
        self.authorize_text(method, uri, credentials, &hex(&cnonce)?, nonce_count)
    }
    fn authorize_text(
        &self,
        method: &str,
        uri: &str,
        credentials: &DigestCredentials<'_>,
        cnonce: &str,
        nonce_count: u32,
    ) -> Result<DigestAuthorization, AuthenticationError> {
        if nonce_count == 0 {
            return Err(AuthenticationError::Replay);
        }
        if method.is_empty()
            || method.len() > 32
            || !method.bytes().all(|b| b.is_ascii_uppercase())
            || uri.is_empty()
            || uri.len() > 2_048
            || !uri.bytes().all(|b| (33..127).contains(&b))
            || cnonce.is_empty()
            || cnonce.len() > 128
            || !cnonce.bytes().all(token)
        {
            return Err(AuthenticationError::Malformed);
        }
        let response = self.response(method, uri, credentials, cnonce, nonce_count)?;
        let username = if self.userhash {
            self.algorithm
                .hash(format!("{}:{}", credentials.username, self.realm).as_bytes())?
        } else {
            credentials.username.to_owned()
        };
        // Include worst-case syntax overhead before allocation. Escaping cannot
        // cause an over-limit output to grow past the advertised allocation bound.
        let escaped = |s: &str| s.len() + s.bytes().filter(|b| matches!(b, b'"' | b'\\')).count();
        let bound = 256
            + escaped(&username)
            + escaped(&self.realm)
            + escaped(&self.nonce)
            + escaped(uri)
            + self.opaque.as_deref().map_or(0, escaped)
            + cnonce.len()
            + response.len();
        if bound > MAX_AUTHORIZATION_BYTES {
            return Err(AuthenticationError::Capacity);
        }
        let mut out = String::new();
        out.try_reserve_exact(MAX_AUTHORIZATION_BYTES)
            .map_err(|_| AuthenticationError::Capacity)?;
        out.push_str("Digest username=");
        quote(&mut out, &username);
        out.push_str(", realm=");
        quote(&mut out, &self.realm);
        out.push_str(", nonce=");
        quote(&mut out, &self.nonce);
        out.push_str(", uri=");
        quote(&mut out, uri);
        out.push_str(", response=");
        quote(&mut out, &response);
        write!(&mut out, ", algorithm={}", self.algorithm.label())
            .map_err(|_| AuthenticationError::Capacity)?;
        if self.qop_auth {
            write!(&mut out, ", qop=auth, nc={nonce_count:08x}, cnonce=")
                .map_err(|_| AuthenticationError::Capacity)?;
            quote(&mut out, cnonce);
        } else if self.algorithm.session() {
            out.push_str(", cnonce=");
            quote(&mut out, cnonce);
        }
        if let Some(opaque) = &self.opaque {
            out.push_str(", opaque=");
            quote(&mut out, opaque);
        }
        if self.userhash {
            out.push_str(", userhash=true");
        }
        if out.len() > MAX_AUTHORIZATION_BYTES {
            return Err(AuthenticationError::Capacity);
        }
        Ok(DigestAuthorization(out))
    }
    fn response(
        &self,
        method: &str,
        uri: &str,
        credentials: &DigestCredentials<'_>,
        cnonce: &str,
        nc: u32,
    ) -> Result<String, AuthenticationError> {
        // Transient secret-bearing A1 is not stored in client state or diagnostics.
        // Rust allocation/drop is not claimed as a guaranteed zeroization primitive.
        let mut a1 = Vec::new();
        a1.try_reserve_exact(
            credentials.username.len() + self.realm.len() + credentials.password.len() + 2,
        )
        .map_err(|_| AuthenticationError::Capacity)?;
        a1.extend_from_slice(credentials.username.as_bytes());
        a1.push(b':');
        a1.extend_from_slice(self.realm.as_bytes());
        a1.push(b':');
        a1.extend_from_slice(credentials.password.as_bytes());
        let hashed = self.algorithm.hash(&a1);
        a1.fill(0);
        let mut ha1 = hashed?;
        if self.algorithm.session() {
            ha1 = self
                .algorithm
                .hash(format!("{ha1}:{}:{cnonce}", self.nonce).as_bytes())?;
        }
        let ha2 = self.algorithm.hash(format!("{method}:{uri}").as_bytes())?;
        let response_input = if self.qop_auth {
            format!("{ha1}:{}:{nc:08x}:{cnonce}:auth:{ha2}", self.nonce)
        } else {
            format!("{ha1}:{}:{ha2}", self.nonce)
        };
        self.algorithm.hash(response_input.as_bytes())
    }
}

/// Secret-bearing wire value; Debug always redacts it. Not Clone, not a send receipt.
pub struct DigestAuthorization(String);
impl DigestAuthorization {
    /// Expose only to the authorized transport/request owner. Never log this value.
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for DigestAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DigestAuthorization([REDACTED])")
    }
}

fn quoted_ascii(s: &str) -> bool {
    s.bytes().all(|b| (32..127).contains(&b))
}
fn token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}
fn quote(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        if matches!(c, '"' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
}
fn hex(bytes: &[u8]) -> Result<String, AuthenticationError> {
    let mut out = String::new();
    out.try_reserve_exact(bytes.len() * 2)
        .map_err(|_| AuthenticationError::Capacity)?;
    for b in bytes {
        write!(&mut out, "{b:02x}").map_err(|_| AuthenticationError::Capacity)?;
    }
    Ok(out)
}
fn fields(input: &str) -> Result<Vec<(String, String)>, AuthenticationError> {
    let raw = input.as_bytes();
    let mut at = 0;
    let mut out = Vec::<(String, String)>::new();
    out.try_reserve_exact(16)
        .map_err(|_| AuthenticationError::Capacity)?;
    loop {
        while raw.get(at).is_some_and(|b| matches!(b, b' ' | b'\t')) {
            at += 1;
        }
        if at == raw.len() {
            if out.is_empty() {
                return Err(AuthenticationError::Malformed);
            }
            return Ok(out);
        }
        if out.len() == 16 {
            return Err(AuthenticationError::Capacity);
        }
        let begin = at;
        while raw.get(at).is_some_and(|b| token(*b)) {
            at += 1;
        }
        if begin == at {
            return Err(AuthenticationError::Malformed);
        }
        let name = input[begin..at].to_ascii_lowercase();
        if !matches!(
            name.as_str(),
            "realm"
                | "nonce"
                | "opaque"
                | "algorithm"
                | "qop"
                | "stale"
                | "charset"
                | "userhash"
                | "domain"
        ) {
            return Err(AuthenticationError::Unsupported);
        }
        if out.iter().any(|(n, _)| *n == name) {
            return Err(AuthenticationError::Malformed);
        }
        while raw.get(at).is_some_and(|b| matches!(b, b' ' | b'\t')) {
            at += 1;
        }
        if raw.get(at) != Some(&b'=') {
            return Err(AuthenticationError::Malformed);
        }
        at += 1;
        while raw.get(at).is_some_and(|b| matches!(b, b' ' | b'\t')) {
            at += 1;
        }
        let mut value = String::new();
        value
            .try_reserve_exact(raw.len().saturating_sub(at))
            .map_err(|_| AuthenticationError::Capacity)?;
        if raw.get(at) == Some(&b'"') {
            at += 1;
            loop {
                let byte = *raw.get(at).ok_or(AuthenticationError::Malformed)?;
                at += 1;
                if byte == b'"' {
                    break;
                }
                let byte = if byte == b'\\' {
                    let b = *raw.get(at).ok_or(AuthenticationError::Malformed)?;
                    at += 1;
                    b
                } else {
                    byte
                };
                if !(32..127).contains(&byte) {
                    return Err(AuthenticationError::Malformed);
                }
                value.push(char::from(byte));
            }
        } else {
            let begin = at;
            while raw.get(at).is_some_and(|b| token(*b)) {
                value.push(char::from(raw[at]));
                at += 1;
            }
            if begin == at {
                return Err(AuthenticationError::Malformed);
            }
        }
        out.push((name, value));
        while raw.get(at).is_some_and(|b| matches!(b, b' ' | b'\t')) {
            at += 1;
        }
        if at == raw.len() {
            return Ok(out);
        }
        if raw[at] != b',' {
            return Err(AuthenticationError::Malformed);
        }
        at += 1;
        if raw[at..].iter().all(|b| matches!(b, b' ' | b'\t')) {
            return Err(AuthenticationError::Malformed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc2617_md5_response_vector() -> Result<(), AuthenticationError> {
        let c = DigestChallenge::parse(
            "Digest realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth,auth-int\"",
            "testrealm@host.com",
            DigestPolicy {
                allow_legacy_md5: true,
                allow_legacy_no_qop: false,
            },
        )?;
        let credentials = DigestCredentials::new("Mufasa", "Circle Of Life")?;
        assert_eq!(
            c.response("GET", "/dir/index.html", &credentials, "0a4f113b", 1)?,
            "6629fae49393a05397450978507c4ef1"
        );
        Ok(())
    }
}
