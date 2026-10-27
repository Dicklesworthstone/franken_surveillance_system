#![forbid(unsafe_code)]
//! Bounded selection from the camera's authentication offers.
//! This module owns no credentials, I/O, retries, or authority.

use crate::rtsp::authentication::{
    AuthenticationError, DigestAlgorithm, DigestChallenge, DigestPolicy, MAX_CHALLENGE_BYTES,
};
use crate::rtsp::message::{AuthScheme, extract_auth_scheme};

const MAX_OFFERS: usize = 8;
const MAX_OFFER_BYTES: usize = 8_192;

/// Borrowed original challenge slices. Never expose them through Debug or reports.
pub(super) struct ChallengeOffers<'a> {
    values: [&'a str; MAX_OFFERS],
    len: usize,
    bytes: usize,
}

impl<'a> ChallengeOffers<'a> {
    pub(super) fn new() -> Self {
        Self {
            values: [""; MAX_OFFERS],
            len: 0,
            bytes: 0,
        }
    }

    /// Accept repeated fields or a combined challenge list. A comma within a
    /// quoted value, or before another name=value parameter, is not a boundary.
    pub(super) fn push_header(&mut self, value: &'a str) -> Result<(), AuthenticationError> {
        if value.len() > MAX_CHALLENGE_BYTES
            || value.len() > MAX_OFFER_BYTES.saturating_sub(self.bytes)
        {
            return Err(AuthenticationError::Capacity);
        }
        if value.bytes().any(|b| b < 32 && b != b'\t' || b >= 127) {
            return Err(AuthenticationError::Malformed);
        }
        self.bytes += value.len();
        let bytes = value.as_bytes();
        let mut start = 0;
        let mut quoted = false;
        let mut escaped = false;
        for (at, &byte) in bytes.iter().enumerate() {
            if escaped {
                escaped = false;
                continue;
            }
            if quoted {
                match byte {
                    b'\\' => escaped = true,
                    b'"' => quoted = false,
                    _ => {}
                }
                continue;
            }
            if byte == b'"' {
                quoted = true;
                continue;
            }
            if byte != b',' {
                continue;
            }
            let next = skip_space(bytes, at + 1);
            let mut end = next;
            while bytes.get(end).is_some_and(|b| token(*b)) {
                end += 1;
            }
            if end == next {
                return Err(AuthenticationError::Malformed);
            }
            let rest = skip_space(bytes, end);
            if bytes.get(rest) == Some(&b'=') {
                continue;
            }
            // The supported list subset requires a scheme followed by a value.
            // A bare trailing token is not silently discarded as another scheme:
            // that would hide malformed Digest parameters such as an unquoted qop list.
            if rest == end || rest == bytes.len() {
                return Err(AuthenticationError::Malformed);
            }
            self.push(&value[start..at])?;
            start = next;
        }
        if quoted || escaped {
            return Err(AuthenticationError::Malformed);
        }
        self.push(&value[start..])
    }

    fn push(&mut self, value: &'a str) -> Result<(), AuthenticationError> {
        let value = value.trim();
        if extract_auth_scheme(value).is_none() {
            return Err(AuthenticationError::Malformed);
        }
        if self.len == MAX_OFFERS {
            return Err(AuthenticationError::Capacity);
        }
        self.values[self.len] = value;
        self.len += 1;
        Ok(())
    }

    pub(super) fn contains_digest(&self) -> bool {
        self.values[..self.len]
            .iter()
            .any(|value| extract_auth_scheme(value) == Some(AuthScheme::Digest))
    }

    /// Select the strongest allowed Digest without changing the owner's policy.
    /// Malformed or wrong-realm Digest offers invalidate the response. Unsupported
    /// schemes/algorithms never receive credentials. The winner must preserve all
    /// security properties of every other supported offer; incomparable choices
    /// and equally preferred duplicate offers fail closed.
    pub(super) fn select(
        &self,
        realm: &str,
        policy: DigestPolicy,
    ) -> Result<DigestChallenge, AuthenticationError> {
        let mut candidates = Vec::new();
        candidates
            .try_reserve_exact(self.len)
            .map_err(|_| AuthenticationError::Capacity)?;
        for value in &self.values[..self.len] {
            if extract_auth_scheme(value) != Some(AuthScheme::Digest) {
                continue;
            }
            match DigestChallenge::parse(value, realm, policy) {
                Ok(challenge) => candidates.push(challenge),
                Err(AuthenticationError::Unsupported) => {}
                Err(error) => return Err(error),
            }
        }
        let mut best: Option<usize> = None;
        let mut ties = 0;
        for (index, candidate) in candidates.iter().enumerate() {
            if !candidates
                .iter()
                .all(|other| candidate.no_weaker_than(other))
            {
                continue;
            }
            if let Some(previous) = best {
                let previous = candidates.get(previous).ok_or(AuthenticationError::State)?;
                match preference(candidate.algorithm()).cmp(&preference(previous.algorithm())) {
                    std::cmp::Ordering::Greater => {
                        best = Some(index);
                        ties = 1;
                    }
                    std::cmp::Ordering::Equal => ties += 1,
                    std::cmp::Ordering::Less => {}
                }
            } else {
                best = Some(index);
                ties = 1;
            }
        }
        if ties > 1 {
            return Err(AuthenticationError::Malformed);
        }
        let best = best.ok_or(AuthenticationError::Unsupported)?;
        candidates
            .into_iter()
            .nth(best)
            .ok_or(AuthenticationError::State)
    }
}

fn skip_space(bytes: &[u8], mut at: usize) -> usize {
    while bytes.get(at).is_some_and(|b| matches!(b, b' ' | b'\t')) {
        at += 1;
    }
    at
}

fn token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_\x60|~".contains(&byte)
}

fn preference(algorithm: DigestAlgorithm) -> u8 {
    // SHA-256 dominates explicitly allowed MD5. The sess tie-break is stable,
    // not a claim that a session variant upgrades the hash's security strength.
    match algorithm {
        DigestAlgorithm::Sha256Session => 3,
        DigestAlgorithm::Sha256 => 2,
        DigestAlgorithm::LegacyMd5Session => 1,
        DigestAlgorithm::LegacyMd5 => 0,
    }
}
