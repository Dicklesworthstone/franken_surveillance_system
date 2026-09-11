#![forbid(unsafe_code)]
//! OS-native argument tokenization and UTF-8 validation without panic.

use std::ffi::OsString;

use crate::error::CliError;
use crate::redact::{is_sensitive_standalone_flag, safe_os_repr};

/// Maximum allowed length in bytes for a single argument token.
pub const MAX_ARG_TOKEN_BYTES: usize = 4096;

/// A validated UTF-8 command-line argument token with its positional index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgToken {
    /// Zero-based index of this argument within the program arguments (excluding argv[0]).
    pub index: usize,
    /// UTF-8 string value of the argument.
    pub raw: String,
}

impl ArgToken {
    /// Creates a new argument token.
    #[must_use]
    pub const fn new(index: usize, raw: String) -> Self {
        Self { index, raw }
    }

    /// Returns a reference to the string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

/// Tokenizes an iterator of OS-native arguments into validated `ArgToken` records.
///
/// This function never panics on non-UTF-8 inputs. If any argument cannot be decoded
/// as valid UTF-8, it returns an explicit `CliError::InvalidUnicode`.
///
/// If any argument exceeds `MAX_ARG_TOKEN_BYTES`, it returns `CliError::MalformedValue`.
/// If an argument follows a sensitive standalone flag, its value is
/// automatically redacted to `[redacted]`.
pub fn tokenize_os_args<I>(args: I) -> Result<Vec<ArgToken>, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut tokens = Vec::new();
    let mut prev_was_sensitive = false;

    for (index, os_arg) in args.into_iter().enumerate() {
        let is_sensitive_value = prev_was_sensitive;
        prev_was_sensitive = false;

        match os_arg.to_str() {
            Some(valid_str) => {
                if valid_str.len() > MAX_ARG_TOKEN_BYTES {
                    return Err(CliError::MalformedValue {
                        option: "argv".to_owned(),
                        value: format!("[oversized:{}bytes]", valid_str.len()),
                        reason: format!("argument exceeds {MAX_ARG_TOKEN_BYTES} byte limit"),
                        command: None,
                        index,
                    });
                }
                if is_sensitive_value {
                    tokens.push(ArgToken::new(index, "[redacted]".to_owned()));
                } else {
                    if is_sensitive_standalone_flag(valid_str) {
                        prev_was_sensitive = true;
                    }
                    tokens.push(ArgToken::new(index, valid_str.to_owned()));
                }
            }
            None => {
                #[cfg(unix)]
                let (byte_length, redacted_repr) = {
                    use std::os::unix::ffi::OsStrExt;
                    let bytes = os_arg.as_bytes();
                    if is_sensitive_value {
                        (bytes.len(), "[redacted]".to_owned())
                    } else {
                        (bytes.len(), safe_os_repr(bytes, 32))
                    }
                };
                #[cfg(windows)]
                let (byte_length, redacted_repr) = {
                    use std::os::windows::ffi::OsStrExt;
                    let wide: Vec<u16> = os_arg.encode_wide().collect();
                    let byte_length = wide.len() * 2;
                    if is_sensitive_value {
                        (byte_length, "[redacted]".to_owned())
                    } else {
                        let mut repr = String::new();
                        for &unit in wide.iter().take(32) {
                            if (0x20..=0x7E).contains(&unit)
                                && unit != b'\\' as u16
                                && unit != b'"' as u16
                            {
                                repr.push(unit as u8 as char);
                            } else {
                                use std::fmt::Write;
                                let _ = write!(repr, "\\u{{{unit:04x}}}");
                            }
                        }
                        if wide.len() > 32 {
                            repr.push_str("...[truncated]");
                        }
                        (byte_length, redact_argument(&repr))
                    }
                };
                #[cfg(all(not(unix), not(windows)))]
                let (byte_length, redacted_repr) = {
                    let lossy = os_arg.to_string_lossy();
                    if is_sensitive_value {
                        (lossy.len(), "[redacted]".to_owned())
                    } else {
                        (lossy.len(), redact_argument(&lossy))
                    }
                };

                return Err(CliError::InvalidUnicode {
                    index,
                    byte_length,
                    redacted_repr,
                });
            }
        }
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_utf8_tokens_are_parsed() {
        let os_args = vec![OsString::from("status"), OsString::from("--json")];
        let result = tokenize_os_args(os_args);
        assert!(result.is_ok());
        if let Ok(tokens) = result {
            assert_eq!(tokens.len(), 2);
            assert_eq!(tokens[0].index, 0);
            assert_eq!(tokens[0].raw, "status");
            assert_eq!(tokens[1].index, 1);
            assert_eq!(tokens[1].raw, "--json");
        }
    }

    #[test]
    fn oversized_token_is_rejected() {
        let huge = "x".repeat(MAX_ARG_TOKEN_BYTES + 1);
        let os_args = vec![OsString::from(huge)];
        let result = tokenize_os_args(os_args);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err.error_id(), crate::error::ERR_CLI_MALFORMED_VALUE);
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_token_is_rejected_with_invalid_unicode_error() {
        use std::os::unix::ffi::OsStringExt;
        let invalid_bytes = vec![0x66, 0x6f, 0x6f, 0x80, 0x81];
        let os_args = vec![OsString::from_vec(invalid_bytes)];
        let result = tokenize_os_args(os_args);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err.error_id(), crate::error::ERR_CLI_INVALID_UNICODE);
            assert_eq!(err.argument_index(), Some(0));
        }
    }
}
