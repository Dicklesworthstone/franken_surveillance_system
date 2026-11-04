#![forbid(unsafe_code)]
//! The shared sans-I/O RTSP URI syntax gate used by live negotiation and site planning.
//! Exact text is preserved; no DNS, URL rewriting, credential access or network I/O occurs.

use std::fmt;

const MAX_URI: usize = 2_048;

/// A private RTSP URI is malformed or outside the admitted scope syntax.
/// The refused URI is never retained in this error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UriScopeError;

impl fmt::Display for UriScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RTSP URI scope refused")
    }
}
impl std::error::Error for UriScopeError {}

/// Validate exact credential-free RTSP syntax, preserving the authority and path/query.
/// This syntax check grants no permission, authenticity, scope or transport protection.
/// Encoded controls, separators, traversal and double decoding are refused.
pub fn validated_uri_parts(uri: &str) -> Result<(&str, &str), UriScopeError> {
    if uri.len() > MAX_URI
        || !uri.is_ascii()
        || uri
            .bytes()
            .any(|b| b <= 32 || b >= 127 || b"\\#@".contains(&b))
    {
        return Err(UriScopeError);
    }
    let rest = uri.strip_prefix("rtsp://").ok_or(UriScopeError)?;
    let split = rest.find('/').ok_or(UriScopeError)?;
    let (authority, path) = rest.split_at(split);
    if authority.is_empty() || (authority.contains('%') || authority.contains('?')) {
        return Err(UriScopeError);
    }
    // Authority is matched exactly, not resolved. No DNS alias or alternate port broadening.
    if !authority
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
    {
        return Err(UriScopeError);
    }
    for segment in path.split('?').next().unwrap_or("").split('/') {
        if matches!(segment, "." | "..") {
            return Err(UriScopeError);
        }
    }
    let mut at = 0;
    let raw = path.as_bytes();
    while at < raw.len() {
        if raw[at] == b'%' {
            let hex = path.get(at + 1..at + 3).ok_or(UriScopeError)?;
            let decoded = u8::from_str_radix(hex, 16).map_err(|_| UriScopeError)?;
            if decoded <= 32 || b"./\\@#%".contains(&decoded) || decoded == 127 {
                return Err(UriScopeError);
            }
            at += 3;
        } else {
            at += 1;
        }
    }
    Ok((authority, path))
}
