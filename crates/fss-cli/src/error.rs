#![forbid(unsafe_code)]
//! Stable error and exit identities for the FSS command-line interface.

use core::fmt;

use fss_core::RecoveryClass;

use crate::redact::{redact_argument, redact_value_or_digest};

/// Stable error identity for unknown commands.
pub const ERR_CLI_UNKNOWN_COMMAND: &str = "ERR-CLI-UNKNOWN-COMMAND-001";
/// Stable error identity for unknown options.
pub const ERR_CLI_UNKNOWN_OPTION: &str = "ERR-CLI-UNKNOWN-OPTION-001";
/// Stable error identity for missing required values or options.
pub const ERR_CLI_MISSING_VALUE: &str = "ERR-CLI-MISSING-VALUE-001";
/// Stable error identity for duplicate or mutually exclusive options.
pub const ERR_CLI_DUPLICATE_OPTION: &str = "ERR-CLI-DUPLICATE-OPTION-001";
/// Stable error identity for malformed option or argument values.
pub const ERR_CLI_MALFORMED_VALUE: &str = "ERR-CLI-MALFORMED-VALUE-001";
/// Stable error identity for invalid Unicode in operating system arguments.
pub const ERR_CLI_INVALID_UNICODE: &str = "ERR-CLI-INVALID-UNICODE-001";
/// Stable error identity for unexpected positional arguments.
pub const ERR_CLI_UNEXPECTED_POSITIONAL: &str = "ERR-CLI-UNEXPECTED-POSITIONAL-001";
/// Stable error identity for trailing arguments after grammar exhaustion.
pub const ERR_CLI_TRAILING_ARGUMENT: &str = "ERR-CLI-TRAILING-ARGUMENT-001";
/// Stable error identity for runtime execution failure.
pub const ERR_CLI_RUNTIME_FAILURE: &str = "ERR-CLI-RUNTIME-FAILURE-001";

/// Stable exit identity representing an exit code and a registered identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitIdentity {
    /// Process exit code.
    pub code: u8,
    /// Stable identifier string.
    pub identifier: &'static str,
}

impl ExitIdentity {
    /// Successful execution.
    pub const SUCCESS: Self = Self {
        code: 0,
        identifier: "EXIT-OK-000",
    };

    /// Runtime execution failure exit identity.
    pub const RUNTIME_FAILURE: Self = Self {
        code: 1,
        identifier: "EXIT-CLI-RUNTIME-FAILURE-001",
    };

    /// Unknown command exit identity.
    pub const UNKNOWN_COMMAND: Self = Self {
        code: 2,
        identifier: "EXIT-CLI-UNKNOWN-COMMAND-002",
    };

    /// Unknown option exit identity.
    pub const UNKNOWN_OPTION: Self = Self {
        code: 2,
        identifier: "EXIT-CLI-UNKNOWN-OPTION-002",
    };

    /// Missing value exit identity.
    pub const MISSING_VALUE: Self = Self {
        code: 2,
        identifier: "EXIT-CLI-MISSING-VALUE-002",
    };

    /// Duplicate option exit identity.
    pub const DUPLICATE_OPTION: Self = Self {
        code: 2,
        identifier: "EXIT-CLI-DUPLICATE-OPTION-002",
    };

    /// Malformed value exit identity.
    pub const MALFORMED_VALUE: Self = Self {
        code: 2,
        identifier: "EXIT-CLI-MALFORMED-VALUE-002",
    };

    /// Invalid Unicode exit identity.
    pub const INVALID_UNICODE: Self = Self {
        code: 2,
        identifier: "EXIT-CLI-INVALID-UNICODE-002",
    };

    /// Unexpected positional argument exit identity.
    pub const UNEXPECTED_POSITIONAL: Self = Self {
        code: 2,
        identifier: "EXIT-CLI-UNEXPECTED-POSITIONAL-002",
    };

    /// Trailing argument exit identity.
    pub const TRAILING_ARGUMENT: Self = Self {
        code: 2,
        identifier: "EXIT-CLI-TRAILING-ARGUMENT-002",
    };
}

/// Typed errors produced during CLI argument decoding and validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CliError {
    /// An unknown command was specified.
    UnknownCommand {
        /// The token presented as a command.
        command: String,
        /// Context or parent command if any.
        context: Option<String>,
        /// Index of the token in argv.
        index: usize,
    },
    /// An unknown option/flag was specified.
    UnknownOption {
        /// The unrecognized option flag.
        option: String,
        /// Command context under which the option was parsed.
        command: Option<String>,
        /// Index of the option in argv.
        index: usize,
    },
    /// A required option or argument value is missing.
    MissingValue {
        /// Name of the option or argument that required a value.
        option: String,
        /// Command context.
        command: Option<String>,
        /// Expected description.
        expected: String,
    },
    /// A duplicate or mutually exclusive option was encountered.
    DuplicateOption {
        /// The repeated option.
        option: String,
        /// Command context.
        command: Option<String>,
        /// Index of the second occurrence.
        index: usize,
    },
    /// A value could not be parsed into the expected type or domain.
    MalformedValue {
        /// Option or argument name.
        option: String,
        /// Value that failed parsing.
        value: String,
        /// Explanation of what was expected.
        reason: String,
        /// Command context.
        command: Option<String>,
        /// Index of the argument in argv.
        index: usize,
    },
    /// An argument was not valid UTF-8.
    InvalidUnicode {
        /// Index of the argument in argv.
        index: usize,
        /// Byte length of the invalid argument.
        byte_length: usize,
        /// Safe redacted representation.
        redacted_repr: String,
    },
    /// An unexpected positional argument was provided.
    UnexpectedPositional {
        /// Positional token.
        argument: String,
        /// Index of the token in argv.
        index: usize,
        /// Command context.
        command: Option<String>,
    },
    /// Trailing tokens were provided after the command's grammar was exhausted.
    TrailingArgument {
        /// The first trailing argument encountered.
        argument: String,
        /// Index of the trailing argument in argv.
        index: usize,
        /// Command context.
        command: Option<String>,
    },
}

impl CliError {
    /// Returns the stable machine-readable error identity.
    #[must_use]
    pub const fn error_id(&self) -> &'static str {
        match self {
            Self::UnknownCommand { .. } => ERR_CLI_UNKNOWN_COMMAND,
            Self::UnknownOption { .. } => ERR_CLI_UNKNOWN_OPTION,
            Self::MissingValue { .. } => ERR_CLI_MISSING_VALUE,
            Self::DuplicateOption { .. } => ERR_CLI_DUPLICATE_OPTION,
            Self::MalformedValue { .. } => ERR_CLI_MALFORMED_VALUE,
            Self::InvalidUnicode { .. } => ERR_CLI_INVALID_UNICODE,
            Self::UnexpectedPositional { .. } => ERR_CLI_UNEXPECTED_POSITIONAL,
            Self::TrailingArgument { .. } => ERR_CLI_TRAILING_ARGUMENT,
        }
    }

    /// Returns the stable exit identity for this error.
    #[must_use]
    pub const fn exit_identity(&self) -> ExitIdentity {
        match self {
            Self::UnknownCommand { .. } => ExitIdentity::UNKNOWN_COMMAND,
            Self::UnknownOption { .. } => ExitIdentity::UNKNOWN_OPTION,
            Self::MissingValue { .. } => ExitIdentity::MISSING_VALUE,
            Self::DuplicateOption { .. } => ExitIdentity::DUPLICATE_OPTION,
            Self::MalformedValue { .. } => ExitIdentity::MALFORMED_VALUE,
            Self::InvalidUnicode { .. } => ExitIdentity::INVALID_UNICODE,
            Self::UnexpectedPositional { .. } => ExitIdentity::UNEXPECTED_POSITIONAL,
            Self::TrailingArgument { .. } => ExitIdentity::TRAILING_ARGUMENT,
        }
    }

    /// Returns safe repair guidance explaining how to resolve the syntax error.
    #[must_use]
    pub fn repair_guidance(&self) -> String {
        match self {
            Self::UnknownCommand { command, .. } => {
                format!(
                    "command `{}` is not recognized; run with `help` or `--help` to view supported commands",
                    redact_value_or_digest(command)
                )
            }
            Self::UnknownOption {
                option, command, ..
            } => {
                let safe_opt = redact_argument(option);
                if let Some(cmd) = command {
                    format!(
                        "option `{safe_opt}` is not supported for command `{}`",
                        redact_value_or_digest(cmd)
                    )
                } else {
                    format!("option `{safe_opt}` is not recognized")
                }
            }
            Self::MissingValue {
                option, expected, ..
            } => {
                format!(
                    "provide a value for `{}`; expected {expected}",
                    redact_argument(option)
                )
            }
            Self::DuplicateOption { option, .. } => {
                format!(
                    "option `{}` was provided more than once; specify it at most once",
                    redact_argument(option)
                )
            }
            Self::MalformedValue {
                option,
                reason,
                command,
                ..
            } => {
                let safe_opt = redact_argument(option);
                if let Some(cmd) = command {
                    format!(
                        "provide a valid value for `{safe_opt}` for command `{}`: {reason}",
                        redact_value_or_digest(cmd)
                    )
                } else {
                    format!("provide a valid value for `{safe_opt}`: {reason}")
                }
            }
            Self::InvalidUnicode { index, .. } => {
                format!(
                    "argument at index {index} contains invalid UTF-8 bytes; encode input in UTF-8"
                )
            }
            Self::UnexpectedPositional {
                argument, command, ..
            } => {
                let safe_arg = redact_value_or_digest(argument);
                if let Some(cmd) = command {
                    format!(
                        "command `{}` does not accept positional argument `{safe_arg}`",
                        redact_value_or_digest(cmd)
                    )
                } else {
                    format!("unexpected positional argument `{safe_arg}`")
                }
            }
            Self::TrailingArgument {
                argument, command, ..
            } => {
                let safe_arg = redact_value_or_digest(argument);
                if let Some(cmd) = command {
                    format!(
                        "command `{}` grammar was fully satisfied; remove trailing argument `{safe_arg}`",
                        redact_value_or_digest(cmd)
                    )
                } else {
                    format!(
                        "command grammar was fully satisfied; remove trailing argument `{safe_arg}`"
                    )
                }
            }
        }
    }

    /// Returns the command name if known.
    #[must_use]
    pub fn command_name(&self) -> Option<&str> {
        match self {
            Self::UnknownCommand { .. } => None,
            Self::UnknownOption { command, .. }
            | Self::MissingValue { command, .. }
            | Self::DuplicateOption { command, .. }
            | Self::MalformedValue { command, .. }
            | Self::UnexpectedPositional { command, .. }
            | Self::TrailingArgument { command, .. } => command.as_deref(),
            Self::InvalidUnicode { .. } => None,
        }
    }

    /// Returns the argument index associated with the failure, if applicable.
    #[must_use]
    pub const fn argument_index(&self) -> Option<usize> {
        match self {
            Self::UnknownCommand { index, .. }
            | Self::UnknownOption { index, .. }
            | Self::DuplicateOption { index, .. }
            | Self::MalformedValue { index, .. }
            | Self::InvalidUnicode { index, .. }
            | Self::UnexpectedPositional { index, .. }
            | Self::TrailingArgument { index, .. } => Some(*index),
            Self::MissingValue { .. } => None,
        }
    }

    /// Returns whether any effect could have begun before parsing failed.
    /// By contract, argument parsing always fails before any effect or mutation.
    #[must_use]
    pub const fn effect_started(&self) -> bool {
        false
    }

    /// Returns whether safe retry without change is permitted.
    #[must_use]
    pub const fn safe_retry(&self) -> bool {
        false
    }

    /// Returns the recovery classification.
    #[must_use]
    pub const fn recovery_class(&self) -> RecoveryClass {
        RecoveryClass::NeverUnchanged
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommand { command, .. } => {
                write!(
                    f,
                    "unknown or incomplete command: {}",
                    redact_value_or_digest(command)
                )
            }
            Self::UnknownOption {
                option, command, ..
            } => {
                let safe_opt = redact_argument(option);
                if let Some(cmd) = command {
                    write!(
                        f,
                        "unknown option `{safe_opt}` for command `{}`",
                        redact_value_or_digest(cmd)
                    )
                } else {
                    write!(f, "unknown option `{safe_opt}`")
                }
            }
            Self::MissingValue {
                option, expected, ..
            } => {
                write!(
                    f,
                    "missing value for `{}`; expected {expected}",
                    redact_argument(option)
                )
            }
            Self::DuplicateOption { option, .. } => {
                write!(f, "duplicate option: `{}`", redact_argument(option))
            }
            Self::MalformedValue {
                option,
                value,
                reason,
                command,
                ..
            } => {
                let safe_opt = redact_argument(option);
                let safe_val = redact_value_or_digest(value);
                if let Some(cmd) = command {
                    write!(
                        f,
                        "malformed value `{safe_val}` for `{safe_opt}` for command `{}`: {reason}",
                        redact_value_or_digest(cmd)
                    )
                } else {
                    write!(f, "malformed value `{safe_val}` for `{safe_opt}`: {reason}")
                }
            }
            Self::InvalidUnicode {
                index,
                byte_length,
                redacted_repr,
            } => {
                write!(
                    f,
                    "argument at index {index} is not valid UTF-8 ({byte_length} bytes): {redacted_repr}"
                )
            }
            Self::UnexpectedPositional {
                argument, command, ..
            } => {
                let safe_arg = redact_value_or_digest(argument);
                if let Some(cmd) = command {
                    write!(
                        f,
                        "unexpected positional argument `{safe_arg}` for command `{}`",
                        redact_value_or_digest(cmd)
                    )
                } else {
                    write!(f, "unexpected positional argument `{safe_arg}`")
                }
            }
            Self::TrailingArgument {
                argument,
                index,
                command,
                ..
            } => {
                let safe_arg = redact_value_or_digest(argument);
                if let Some(cmd) = command {
                    write!(
                        f,
                        "unexpected trailing argument `{safe_arg}` at index {index} for command `{}`",
                        redact_value_or_digest(cmd)
                    )
                } else {
                    write!(
                        f,
                        "unexpected trailing argument `{safe_arg}` at index {index}"
                    )
                }
            }
        }
    }
}

impl std::error::Error for CliError {}
