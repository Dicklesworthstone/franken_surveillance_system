#![forbid(unsafe_code)]
//! Canary leak and taint scanner for proving zero secret exfiltration across logs,
//! artifacts, vault files, journals, and debug output.

use core::fmt;

use zeroize::Zeroizing;

use crate::error::SecretError;
use crate::secret::SecretBytes;

/// Minimum length in bytes for a registered leak canary to prevent trivial false positives.
pub const MIN_CANARY_LEN: usize = 4;

/// Encoding form under which a registered secret canary was detected.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LeakEncoding {
    /// Raw unencoded canary byte sequence.
    Raw,
    /// Lowercase hexadecimal encoding of the canary.
    HexLower,
    /// Uppercase hexadecimal encoding of the canary.
    HexUpper,
    /// Standard Base64 encoding (unpadded body match).
    Base64Std,
    /// URL-safe Base64 encoding (unpadded body match).
    Base64Url,
}

impl LeakEncoding {
    /// Returns the stable machine-readable encoding name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::HexLower => "hex_lower",
            Self::HexUpper => "hex_upper",
            Self::Base64Std => "base64_std",
            Self::Base64Url => "base64_url",
        }
    }
}

impl fmt::Display for LeakEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Non-secret finding describing a detected canary leak without echoing secret bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeakFinding {
    /// Logical surface inspected (e.g. `"vault.fssv"`, `"stderr"`, `"situation_capsule"`).
    pub surface_name: String,
    /// Operator-supplied non-secret label for the registered canary.
    pub canary_label: String,
    /// Encoding under which the canary appeared.
    pub encoding: LeakEncoding,
    /// Byte offset inside the scanned surface where the match began.
    pub byte_offset: usize,
    /// Length in bytes of the matched needle.
    pub match_len: usize,
}

impl fmt::Display for LeakFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "canary '{}' leaked in '{}' as {} at offset {} ({} bytes)",
            self.canary_label, self.surface_name, self.encoding, self.byte_offset, self.match_len
        )
    }
}

/// Error report emitted when [`CanaryLeakScanner::assert_clean`] detects one or more leaks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeakReport {
    /// All leak findings recorded for the inspected surface.
    pub findings: Vec<LeakFinding>,
}

impl fmt::Display for LeakReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "detected {} secret canary leak(s):", self.findings.len())?;
        for finding in &self.findings {
            write!(f, " [{finding}]")?;
        }
        Ok(())
    }
}

impl std::error::Error for LeakReport {}

struct RegisteredCanary {
    label: String,
    needles: Vec<(LeakEncoding, Zeroizing<Vec<u8>>)>,
}

/// Scans arbitrary byte surfaces for raw, hex, and base64 encodings of registered secret canaries.
///
/// Never formats or exposes registered canary values in `Debug`, `Display`, or [`LeakFinding`].
#[derive(Default)]
pub struct CanaryLeakScanner {
    canaries: Vec<RegisteredCanary>,
}

impl CanaryLeakScanner {
    /// Creates an empty leak scanner.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            canaries: Vec::new(),
        }
    }

    /// Registers a [`SecretBytes`] canary under a non-secret `label`.
    pub fn register_secret(
        &mut self,
        label: impl Into<String>,
        secret: &SecretBytes,
    ) -> Result<(), SecretError> {
        self.register_bytes(label, secret.as_slice())
    }

    /// Registers raw canary bytes under a non-secret `label`.
    pub fn register_bytes(
        &mut self,
        label: impl Into<String>,
        canary: &[u8],
    ) -> Result<(), SecretError> {
        let label = label.into();
        if label.is_empty() {
            return Err(SecretError::InvalidInput {
                detail: "canary label must not be empty".to_string(),
            });
        }
        if canary.len() < MIN_CANARY_LEN {
            return Err(SecretError::InvalidInput {
                detail: format!(
                    "canary '{}' length {} is below minimum of {MIN_CANARY_LEN} bytes",
                    label,
                    canary.len()
                ),
            });
        }

        let mut needles = Vec::with_capacity(5);
        needles.push((LeakEncoding::Raw, Zeroizing::new(canary.to_vec())));
        needles.push((LeakEncoding::HexLower, encode_hex(canary, false)));
        needles.push((LeakEncoding::HexUpper, encode_hex(canary, true)));

        let b64_std = encode_base64_unpadded(canary, false);
        let b64_url = encode_base64_unpadded(canary, true);
        let url_distinct = *b64_url != *b64_std;
        needles.push((LeakEncoding::Base64Std, b64_std));
        if url_distinct {
            needles.push((LeakEncoding::Base64Url, b64_url));
        }

        self.canaries.push(RegisteredCanary { label, needles });
        Ok(())
    }

    /// Returns the number of registered canaries.
    #[must_use]
    pub fn canary_count(&self) -> usize {
        self.canaries.len()
    }

    /// Scans `surface_bytes` for all registered canaries and returns all findings.
    #[must_use]
    pub fn scan(&self, surface_name: &str, surface_bytes: &[u8]) -> Vec<LeakFinding> {
        let mut findings = Vec::new();
        for canary in &self.canaries {
            for (encoding, needle) in &canary.needles {
                if let Some(offset) = find_subslice(surface_bytes, needle.as_slice()) {
                    findings.push(LeakFinding {
                        surface_name: surface_name.to_string(),
                        canary_label: canary.label.clone(),
                        encoding: *encoding,
                        byte_offset: offset,
                        match_len: needle.len(),
                    });
                }
            }
        }
        findings
    }

    /// Verifies that zero registered canaries appear in `surface_bytes`.
    pub fn assert_clean(&self, surface_name: &str, surface_bytes: &[u8]) -> Result<(), LeakReport> {
        let findings = self.scan(surface_name, surface_bytes);
        if findings.is_empty() {
            Ok(())
        } else {
            Err(LeakReport { findings })
        }
    }
}

impl fmt::Debug for CanaryLeakScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanaryLeakScanner")
            .field("canary_count", &self.canaries.len())
            .finish()
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn encode_hex(bytes: &[u8], uppercase: bool) -> Zeroizing<Vec<u8>> {
    let digits: &[u8; 16] = if uppercase {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len() * 2));
    for &byte in bytes {
        out.push(digits[usize::from(byte >> 4)]);
        out.push(digits[usize::from(byte & 0x0f)]);
    }
    out
}

fn encode_base64_unpadded(bytes: &[u8], url_safe: bool) -> Zeroizing<Vec<u8>> {
    let alphabet: &[u8; 64] = if url_safe {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len().div_ceil(3) * 4));
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        out.push(alphabet[usize::from(a >> 2)]);
        out.push(alphabet[usize::from(((a & 0x03) << 4) | (b >> 4))]);
        if chunk.len() > 1 {
            out.push(alphabet[usize::from(((b & 0x0f) << 2) | (c >> 6))]);
        }
        if chunk.len() > 2 {
            out.push(alphabet[usize::from(c & 0x3f)]);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_detects_raw_hex_and_base64_and_redacts_self() -> Result<(), SecretError> {
        let mut scanner = CanaryLeakScanner::new();
        let secret = SecretBytes::from_slice(b"CANARY-TOKEN-9988!")?;
        scanner.register_secret("rtsp-canary", &secret)?;
        assert_eq!(scanner.canary_count(), 1);
        assert!(!format!("{scanner:?}").contains("CANARY-TOKEN"));

        assert!(
            scanner
                .assert_clean("clean-log", b"normal log line")
                .is_ok()
        );

        let raw_findings = scanner.scan("raw-log", b"oops CANARY-TOKEN-9988! leaked");
        assert!(raw_findings.iter().any(|f| f.encoding == LeakEncoding::Raw));

        let hex_lower = b"prefix 43414e4152592d544f4b454e2d3939383821 suffix";
        let hex_findings = scanner.scan("hex-log", hex_lower);
        assert!(
            hex_findings
                .iter()
                .any(|f| f.encoding == LeakEncoding::HexLower)
        );

        // Base64("CANARY-TOKEN-9988!") = "Q0FOQVJZLV RPS0VOLTk5ODgh" without space
        let b64_findings = scanner.scan("b64-log", b"header Q0FOQVJZLV RPS0VOLTk5ODgh".as_slice());
        assert!(b64_findings.is_empty());
        let b64_real = scanner.scan("b64-log", b"header Q0FOQVJZLVRPS0VOLTk5ODgh trailer");
        assert!(
            b64_real
                .iter()
                .any(|f| f.encoding == LeakEncoding::Base64Std)
        );
        Ok(())
    }
}
