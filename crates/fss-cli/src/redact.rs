#![forbid(unsafe_code)]
//! Redaction and bounding utilities for safe CLI error and diagnostic rendering.

use crate::hydration_cmd::VALID_HYDRATION_SCENARIOS;
use crate::lab_cmd::VALID_SCENARIOS;

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

/// Known standalone sensitive flags whose following argument token carries a sensitive value.
pub const SENSITIVE_STANDALONE_FLAGS: [&str; 12] = [
    "--password",
    "-p",
    "--token",
    "-t",
    "--secret",
    "-s",
    "--key",
    "-k",
    "--api-key",
    "--auth",
    "--bearer",
    "--authorization",
];

/// Checks whether a flag is a known sensitive standalone flag.
#[must_use]
pub fn is_sensitive_standalone_flag(flag: &str) -> bool {
    SENSITIVE_STANDALONE_FLAGS
        .iter()
        .any(|&f| f.eq_ignore_ascii_case(flag))
}

/// Checks whether an option name is a registered public option whose value may be safely echoed.
#[must_use]
pub fn is_registered_public_option_with_value(opt_name: &str, val: &str) -> bool {
    if opt_name == "--scenario" {
        VALID_HYDRATION_SCENARIOS.contains(&val)
    } else if opt_name == "--repeat" {
        val.parse::<usize>().is_ok()
    } else {
        false
    }
}

/// Redacts sensitive values, escapes control characters, and truncates to a bounded length.
/// For any unknown option containing '=', redacts the value part unconditionally.
#[must_use]
pub fn redact_argument(input: &str) -> String {
    let sanitized = redact_sensitive_prefixes(input);
    if sanitized != input {
        return sanitize_and_truncate(&sanitized, DEFAULT_BOUND_LEN);
    }
    if (input.starts_with("--") || input.starts_with('-'))
        && let Some((opt_name, val)) = input.split_once('=')
        && !is_registered_public_option_with_value(opt_name, val)
    {
        let redacted_opt = format!("{opt_name}=[redacted]");
        return sanitize_and_truncate(&redacted_opt, DEFAULT_BOUND_LEN);
    }
    sanitize_and_truncate(&sanitized, DEFAULT_BOUND_LEN)
}

/// Redacts the value portion of options matching sensitive prefix patterns anywhere in the string.
fn redact_sensitive_prefixes(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let mut earliest: Option<(usize, usize)> = None;
    for prefix in SENSITIVE_PREFIXES {
        if let Some(pos) = lower.find(prefix) {
            match earliest {
                Some((best_pos, _)) if pos < best_pos => {
                    earliest = Some((pos, prefix.len()));
                }
                None => {
                    earliest = Some((pos, prefix.len()));
                }
                _ => {}
            }
        }
    }
    if let Some((pos, prefix_len)) = earliest {
        let actual_prefix = &input[..pos + prefix_len];
        return format!("{actual_prefix}[REDACTED]");
    }
    input.to_owned()
}

/// Redacts the sensitive value portion of raw byte slices matching known sensitive prefixes anywhere in the slice.
#[must_use]
pub fn redact_sensitive_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut earliest: Option<(usize, usize)> = None;
    for &prefix in &SENSITIVE_PREFIXES_BYTES {
        if bytes.len() >= prefix.len() {
            for (i, window) in bytes.windows(prefix.len()).enumerate() {
                let matches = window
                    .iter()
                    .zip(prefix.iter())
                    .all(|(&b, &p)| b.to_ascii_lowercase() == p);
                if matches {
                    match earliest {
                        Some((best_pos, _)) if i < best_pos => {
                            earliest = Some((i, prefix.len()));
                        }
                        None => {
                            earliest = Some((i, prefix.len()));
                        }
                        _ => {}
                    }
                    break;
                }
            }
        }
    }

    if let Some((pos, prefix_len)) = earliest {
        let mut out = bytes[..pos + prefix_len].to_vec();
        out.extend_from_slice(b"[REDACTED]");
        return out;
    }
    bytes.to_vec()
}

const FSS_COMMANDS: [&str; 5] = ["help", "version", "capabilities", "doctor", "status"];

const LAB_COMMANDS: [&str; 6] = ["help", "list", "matrix", "self-test", "run", "replay"];

const COMMON_FLAGS: [&str; 9] = [
    "--help",
    "-h",
    "--version",
    "-V",
    "--json",
    "--scenario",
    "--repeat",
    "--strict",
    "--timeout-ms",
];

/// Checks whether a token is an allowed safe identifier (registered command name, option, scenario).
/// Arbitrary numeric strings are NOT considered safe identifiers (F3).
/// Scenarios are derived from registered lists as the single source of truth (F5).
#[must_use]
pub fn is_safe_to_echo(token: &str) -> bool {
    if FSS_COMMANDS.contains(&token)
        || LAB_COMMANDS.contains(&token)
        || COMMON_FLAGS.contains(&token)
        || VALID_SCENARIOS.contains(&token)
        || VALID_HYDRATION_SCENARIOS.contains(&token)
    {
        return true;
    }

    if let Some(val) = token.strip_prefix("--scenario=") {
        return VALID_HYDRATION_SCENARIOS.contains(&val);
    }

    false
}

/// Redacts sensitive values or arbitrary unrecognized values to an opaque bounded length form.
/// Emits deterministic plain `[redacted]` with NO length or preimage-derived digest (F2).
#[must_use]
pub fn redact_value_or_digest(input: &str) -> String {
    let sanitized = redact_sensitive_prefixes(input);
    if sanitized != input {
        return sanitize_and_truncate(&sanitized, DEFAULT_BOUND_LEN);
    }

    if (input.starts_with("--") || input.starts_with('-'))
        && let Some((opt_name, val)) = input.split_once('=')
        && !is_registered_public_option_with_value(opt_name, val)
    {
        let redacted_opt = format!("{opt_name}=[redacted]");
        return sanitize_and_truncate(&redacted_opt, DEFAULT_BOUND_LEN);
    }

    if is_safe_to_echo(input) {
        return sanitize_and_truncate(input, DEFAULT_BOUND_LEN);
    }

    "[redacted]".to_owned()
}

/// Escapes control characters and truncates strings exceeding `max_len`.
#[must_use]
pub fn sanitize_and_truncate(input: &str, max_len: usize) -> String {
    let mut out = String::new();
    let mut truncated = false;

    for (char_count, ch) in input.chars().enumerate() {
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
    }

    if truncated {
        out.push_str("...[truncated]");
    }
    out
}

/// Renders a safe representation of arbitrary raw bytes, formatting non-ASCII as hex escapes.
/// Redacts sensitive prefixes anywhere in the byte slice before formatting.
#[must_use]
pub fn safe_os_repr(bytes: &[u8], max_len: usize) -> String {
    let redacted_bytes = redact_sensitive_bytes(bytes);
    let bytes = &redacted_bytes[..];

    let mut out = String::new();
    let mut truncated = false;

    for (byte_count, &byte) in bytes.iter().enumerate() {
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
    fn is_safe_to_echo_recognizes_commands_and_not_arbitrary_numerics() {
        assert!(is_safe_to_echo("status"));
        assert!(!is_safe_to_echo("42"));
        assert!(is_safe_to_echo("--repeat"));
        assert!(!is_safe_to_echo("secret_token"));
    }

    #[test]
    fn redact_value_or_digest_redacts_unknown_tokens_opaquely() {
        let redacted = redact_value_or_digest("my_unknown_secret");
        assert_eq!(redacted, "[redacted]");
        assert_eq!(redact_value_or_digest("status"), "status");
    }
}
