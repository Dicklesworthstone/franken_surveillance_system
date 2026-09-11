#![forbid(unsafe_code)]
//! Redaction and bounding utilities for safe CLI error and diagnostic rendering.

const DEFAULT_BOUND_LEN: usize = 64;

/// Known prefixes that contain sensitive values and must have their values redacted.
const SENSITIVE_PREFIXES: [&str; 8] = [
    "--password=",
    "--secret=",
    "--token=",
    "--key=",
    "--api-key=",
    "--auth=",
    "bearer ",
    "authorization:",
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
#[must_use]
pub fn safe_os_repr(bytes: &[u8], max_len: usize) -> String {
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
}
