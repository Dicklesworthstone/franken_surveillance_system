#![forbid(unsafe_code)]
//! Redaction and bounding utilities for safe CLI error and diagnostic rendering.

const DEFAULT_BOUND_LEN: usize = 64;

/// Known prefixes that contain sensitive values and must have their values redacted.
const SENSITIVE_PREFIXES: [&str; 12] = [
    "--password=",
    "--secret=",
    "--token=",
    "--key=",
    "--api-key=",
    "--auth=",
    "-p=",
    "-k=",
    "-s=",
    "-t=",
    "bearer ",
    "authorization:",
];

const SENSITIVE_PREFIXES_BYTES: [&[u8]; 12] = [
    b"--password=",
    b"--secret=",
    b"--token=",
    b"--key=",
    b"--api-key=",
    b"--auth=",
    b"-p=",
    b"-k=",
    b"-s=",
    b"-t=",
    b"bearer ",
    b"authorization:",
];

/// Redacts sensitive values, escapes control characters, and truncates to a bounded length.
#[must_use]
pub fn redact_argument(input: &str) -> String {
    let sanitized = redact_sensitive_prefixes(input);
    sanitize_and_truncate(&sanitized, DEFAULT_BOUND_LEN)
}

/// Redacts the value portion of options matching sensitive prefix patterns.
fn redact_sensitive_prefixes(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    for prefix in SENSITIVE_PREFIXES {
        if lower.starts_with(prefix) {
            let actual_prefix = &input[..prefix.len()];
            return format!("{actual_prefix}[REDACTED]");
        }
    }
    input.to_owned()
}

/// Redacts the sensitive value portion of raw byte slices matching known sensitive prefixes.
#[must_use]
pub fn redact_sensitive_bytes(bytes: &[u8]) -> Vec<u8> {
    for &prefix in &SENSITIVE_PREFIXES_BYTES {
        if bytes.len() >= prefix.len() {
            let matches = bytes[..prefix.len()]
                .iter()
                .zip(prefix.iter())
                .all(|(&b, &p)| b.to_ascii_lowercase() == p);
            if matches {
                let mut out = bytes[..prefix.len()].to_vec();
                out.extend_from_slice(b"[REDACTED]");
                return out;
            }
        }
    }
    bytes.to_vec()
}

/// Checks whether a token is an allowed safe identifier (registered command name, option, scenario, or bounded numeric).
#[must_use]
pub fn is_safe_to_echo(token: &str) -> bool {
    const SAFE_IDENTIFIERS: &[&str] = &[
        "help",
        "version",
        "capabilities",
        "doctor",
        "status",
        "list",
        "matrix",
        "self-test",
        "run",
        "replay",
        "--help",
        "-h",
        "--version",
        "-V",
        "--json",
        "--scenario",
        "--repeat",
        "quiet",
        "raccoon",
        "intrusion",
        "sneaky",
        "lost-ack",
        "corrupt-source",
        "all",
        "success",
        "budget-fallback",
        "expired",
    ];

    if SAFE_IDENTIFIERS.contains(&token) {
        return true;
    }

    if !token.is_empty() && token.len() <= 10 && token.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }

    if let Some(val) = token.strip_prefix("--scenario=") {
        return is_safe_to_echo(val);
    }
    if let Some(val) = token.strip_prefix("--repeat=") {
        return is_safe_to_echo(val);
    }

    false
}

/// Redacts sensitive values or arbitrary unrecognized values to a bounded length+digest form.
#[must_use]
pub fn redact_value_or_digest(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    for prefix in SENSITIVE_PREFIXES {
        if lower.starts_with(prefix) {
            let actual_prefix = &input[..prefix.len()];
            return format!("{actual_prefix}[REDACTED]");
        }
    }

    if is_safe_to_echo(input) {
        return sanitize_and_truncate(input, DEFAULT_BOUND_LEN);
    }

    let digest = fss_core::sha256(input.as_bytes());
    let mut hex = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    format!("[redacted:{}bytes:sha256:{hex}]", input.len())
}

/// Escapes control characters and truncates strings exceeding `max_len`.
#[must_use]
pub fn sanitize_and_truncate(input: &str, max_len: usize) -> String {
    let mut out = String::new();
    let mut char_count = 0;
    let mut truncated = false;

    for ch in input.chars() {
        if char_count >= max_len {
            truncated = true;
            break;
        }
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
        char_count += 1;
    }

    if truncated {
        out.push_str("...[truncated]");
    }
    out
}

/// Renders a safe representation of arbitrary raw bytes, formatting non-ASCII as hex escapes.
/// Redacts sensitive prefixes before formatting.
#[must_use]
pub fn safe_os_repr(bytes: &[u8], max_len: usize) -> String {
    let redacted_bytes = redact_sensitive_bytes(bytes);
    let bytes = &redacted_bytes[..];

    let mut out = String::new();
    let mut byte_count = 0;
    let mut truncated = false;

    for &byte in bytes {
        if byte_count >= max_len {
            truncated = true;
            break;
        }
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7E => out.push(byte as char),
            b => {
                out.push_str(&format!("\\x{b:02x}"));
            }
        }
        byte_count += 1;
    }

    if truncated {
        out.push_str("...[truncated]");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_prefixes_are_redacted() {
        assert_eq!(
            redact_argument("--password=supersecret"),
            "--password=[REDACTED]"
        );
        assert_eq!(redact_argument("--TOKEN=xyz12345"), "--TOKEN=[REDACTED]");
        assert_eq!(redact_argument("--api-key=mykey"), "--api-key=[REDACTED]");
        assert_eq!(redact_argument("-p=secret"), "-p=[REDACTED]");
        assert_eq!(redact_argument("-k=secret"), "-k=[REDACTED]");
    }

    #[test]
    fn long_inputs_are_bounded() {
        let long_str = "a".repeat(200);
        let redacted = redact_argument(&long_str);
        assert!(redacted.len() < 100);
        assert!(redacted.ends_with("...[truncated]"));
    }

    #[test]
    fn control_characters_are_escaped() {
        assert_eq!(redact_argument("hello\nworld"), "hello\\nworld");
        assert_eq!(redact_argument("tab\there"), "tab\\there");
    }

    #[test]
    fn raw_bytes_representation_is_safe() {
        let bytes = [0xFF, 0xFE, b'a', b'b'];
        assert_eq!(safe_os_repr(&bytes, 10), "\\xff\\xfeab");
    }

    #[test]
    fn raw_bytes_sensitive_prefixes_are_redacted() {
        let bytes = b"--password=supersecret\xff";
        let repr = safe_os_repr(bytes, 64);
        assert!(!repr.contains("supersecret"));
        assert!(repr.contains("[REDACTED]"));
    }

    #[test]
    fn is_safe_to_echo_recognizes_commands_and_numerics() {
        assert!(is_safe_to_echo("status"));
        assert!(is_safe_to_echo("42"));
        assert!(is_safe_to_echo("--repeat"));
        assert!(!is_safe_to_echo("secret_token"));
    }

    #[test]
    fn redact_value_or_digest_hashes_unknown_tokens() {
        let redacted = redact_value_or_digest("my_unknown_secret");
        assert!(redacted.starts_with("[redacted:17bytes:sha256:"));
        assert_eq!(redact_value_or_digest("status"), "status");
    }
}
