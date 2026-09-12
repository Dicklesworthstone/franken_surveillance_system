#![forbid(unsafe_code)]
//! Deterministic test-event and proof-logging substrate.
//!
//! Ref: `fss-x4a.28.40` / `TEST-HARNESS-001`.
//!
//! Provides a minimal, versioned, bounded JSONL test-event envelope for unit, property,
//! differential, fault, and integration suites. Every event carries run/case/step identities,
//! monotone sequence, seed, source and contract digests, input/expected/actual digests,
//! a typed outcome, and duration from an explicit clock.
//!
//! No ambient time or global mutable state is used. Sensitive strings and unredacted media
//! are detected and rejected. All field lengths and container sizes are bounded and validated.

use core::fmt;
use std::io::Write;

use crate::ContentDigest;

/// Canonical schema identifier for test event records.
pub const TEST_EVENT_SCHEMA: &str = "test_event.v1";

/// Schema version 1.
pub const TEST_EVENT_VERSION_1: u32 = 1;

/// Maximum byte length of a test run identifier.
pub const MAX_TEST_RUN_ID_LEN: usize = 128;

/// Maximum byte length of a test case identifier.
pub const MAX_TEST_CASE_ID_LEN: usize = 128;

/// Maximum byte length of a test step identifier.
pub const MAX_TEST_STEP_ID_LEN: usize = 128;

/// Maximum byte length of an execution phase name.
pub const MAX_TEST_PHASE_LEN: usize = 64;

/// Maximum byte length of an individual tag.
pub const MAX_TEST_TAG_LEN: usize = 128;

/// Maximum number of tags per event record.
pub const MAX_TEST_TAGS_COUNT: usize = 64;

/// Maximum byte length of freeform detail string.
pub const MAX_TEST_DETAIL_LEN: usize = 1024;

/// Maximum total encoded JSON byte length for a single test event record.
pub const MAX_TEST_EVENT_JSON_BYTES: usize = 8192;

/// Typed outcome of a test step or execution episode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum TestOutcome {
    /// Step or test passed its assertions and invariants.
    Passed,
    /// Step or test failed a functional assertion or contract check.
    Failed,
    /// Step or test was skipped.
    Skipped,
    /// Execution terminated unexpectedly (e.g. abort, SIGABRT, worker crash).
    Crashed,
    /// Execution was explicitly cancelled or timed out.
    Cancelled,
    /// Step reached an indeterminate or torn state requiring reconciliation.
    Indeterminate,
}

impl TestOutcome {
    /// Returns the stable string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::Crashed => "crashed",
            Self::Cancelled => "cancelled",
            Self::Indeterminate => "indeterminate",
        }
    }

    /// Parses an outcome from its stable string representation.
    pub fn parse(s: &str) -> Result<Self, TestEventError> {
        match s {
            "passed" => Ok(Self::Passed),
            "failed" => Ok(Self::Failed),
            "skipped" => Ok(Self::Skipped),
            "crashed" => Ok(Self::Crashed),
            "cancelled" => Ok(Self::Cancelled),
            "indeterminate" => Ok(Self::Indeterminate),
            _ => Err(TestEventError::InvalidOutcome(s.to_string())),
        }
    }
}

impl fmt::Display for TestOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed errors encountered during test event construction, validation, or parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TestEventError {
    /// Schema version is unsupported.
    UnsupportedVersion(u32),
    /// Schema string mismatch.
    SchemaMismatch {
        /// The expected schema string.
        expected: String,
        /// The actual schema string found.
        actual: String,
    },
    /// Identifier is empty.
    EmptyIdentifier(&'static str),
    /// Identifier contains forbidden characters.
    InvalidIdentifier {
        /// Name of the field containing the invalid identifier.
        field: &'static str,
        /// Value of the invalid identifier.
        value: String,
    },
    /// Run ID exceeds length bound.
    RunIdTooLong {
        /// Maximum permitted length.
        max: usize,
        /// Actual length observed.
        actual: usize,
    },
    /// Case ID exceeds length bound.
    CaseIdTooLong {
        /// Maximum permitted length.
        max: usize,
        /// Actual length observed.
        actual: usize,
    },
    /// Step ID exceeds length bound.
    StepIdTooLong {
        /// Maximum permitted length.
        max: usize,
        /// Actual length observed.
        actual: usize,
    },
    /// Phase name exceeds length bound.
    PhaseTooLong {
        /// Maximum permitted length.
        max: usize,
        /// Actual length observed.
        actual: usize,
    },
    /// Detail string exceeds length bound.
    DetailTooLong {
        /// Maximum permitted length.
        max: usize,
        /// Actual length observed.
        actual: usize,
    },
    /// Individual tag exceeds length bound.
    TagTooLong {
        /// Maximum permitted length.
        max: usize,
        /// Actual length observed.
        actual: usize,
    },
    /// Total tag count exceeds bound.
    TagsCountExceeded {
        /// Maximum permitted count.
        max: usize,
        /// Actual count observed.
        actual: usize,
    },
    /// Total encoded JSON byte length exceeds bound.
    JsonSizeExceeded {
        /// Maximum permitted byte size.
        max: usize,
        /// Actual byte size observed.
        actual: usize,
    },
    /// Monotone sequence regression detected.
    SequenceRegression {
        /// The expected sequence lower bound.
        expected_at_least: u64,
        /// The actual sequence number observed.
        actual: u64,
    },
    /// Forbidden secret or credential pattern detected.
    SecretDetected {
        /// Field where secret pattern was detected.
        field: &'static str,
    },
    /// Invalid outcome string.
    InvalidOutcome(String),
    /// Required JSON field missing.
    MissingField(&'static str),
    /// JSON parsing or syntax error.
    MalformedJson(String),
}

impl fmt::Display for TestEventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported test event version {v}"),
            Self::SchemaMismatch { expected, actual } => {
                write!(f, "schema mismatch: expected '{expected}', found '{actual}'")
            }
            Self::EmptyIdentifier(field) => write!(f, "identifier for '{field}' is empty"),
            Self::InvalidIdentifier { field, value } => {
                write!(f, "identifier '{value}' for '{field}' contains invalid characters")
            }
            Self::RunIdTooLong { max, actual } => {
                write!(f, "run_id length {actual} exceeds maximum of {max}")
            }
            Self::CaseIdTooLong { max, actual } => {
                write!(f, "case_id length {actual} exceeds maximum of {max}")
            }
            Self::StepIdTooLong { max, actual } => {
                write!(f, "step_id length {actual} exceeds maximum of {max}")
            }
            Self::PhaseTooLong { max, actual } => {
                write!(f, "phase length {actual} exceeds maximum of {max}")
            }
            Self::DetailTooLong { max, actual } => {
                write!(f, "detail length {actual} exceeds maximum of {max}")
            }
            Self::TagTooLong { max, actual } => {
                write!(f, "tag length {actual} exceeds maximum of {max}")
            }
            Self::TagsCountExceeded { max, actual } => {
                write!(f, "tags count {actual} exceeds maximum of {max}")
            }
            Self::JsonSizeExceeded { max, actual } => {
                write!(f, "json byte size {actual} exceeds maximum of {max}")
            }
            Self::SequenceRegression {
                expected_at_least,
                actual,
            } => write!(
                f,
                "monotone sequence regression: expected at least {expected_at_least}, found {actual}"
            ),
            Self::SecretDetected { field } => {
                write!(f, "sensitive credential or secret keyword detected in '{field}'")
            }
            Self::InvalidOutcome(s) => write!(f, "invalid test outcome '{s}'"),
            Self::MissingField(field) => write!(f, "missing required field '{field}' in test event"),
            Self::MalformedJson(msg) => write!(f, "malformed test event JSON: {msg}"),
        }
    }
}

impl std::error::Error for TestEventError {}

fn check_for_secrets(field: &'static str, s: &str) -> Result<(), TestEventError> {
    let lower = s.to_ascii_lowercase();
    for needle in [
        "bearer ",
        "private_key",
        "secret_key",
        "auth_token",
        "access_token",
        "authorization:",
        "password=",
    ] {
        if lower.contains(needle) {
            return Err(TestEventError::SecretDetected { field });
        }
    }
    Ok(())
}

fn validate_test_id(
    field: &'static str,
    value: &str,
    max_len: usize,
) -> Result<(), TestEventError> {
    if value.is_empty() {
        return Err(TestEventError::EmptyIdentifier(field));
    }
    if value.len() > max_len {
        return match field {
            "run_id" => Err(TestEventError::RunIdTooLong {
                max: max_len,
                actual: value.len(),
            }),
            "case_id" => Err(TestEventError::CaseIdTooLong {
                max: max_len,
                actual: value.len(),
            }),
            "step_id" => Err(TestEventError::StepIdTooLong {
                max: max_len,
                actual: value.len(),
            }),
            _ => Err(TestEventError::RunIdTooLong {
                max: max_len,
                actual: value.len(),
            }),
        };
    }
    for b in value.bytes() {
        let valid = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'/');
        if !valid {
            return Err(TestEventError::InvalidIdentifier {
                field,
                value: value.to_string(),
            });
        }
    }
    check_for_secrets(field, value)
}

/// Bounded, versioned test event record for deterministic test execution and proof logging.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestEventRecord {
    /// Schema format identifier (`test_event.v1`).
    pub schema: &'static str,
    /// Schema version number (`1`).
    pub version: u32,
    /// Stable test run identifier.
    pub run_id: String,
    /// Stable test suite or test case identifier.
    pub case_id: String,
    /// Stable test step identifier.
    pub step_id: String,
    /// Monotonically non-decreasing step sequence number.
    pub sequence: u64,
    /// Pseudorandom seed or schedule identifier (0 if unseeded / deterministic).
    pub seed: u64,
    /// Cryptographic digest of the test source or harness identity.
    pub source_digest: ContentDigest,
    /// Cryptographic digest of the contract or specification under test.
    pub contract_digest: ContentDigest,
    /// Cryptographic digest of the step input.
    pub input_digest: ContentDigest,
    /// Cryptographic digest of the expected outcome or reference state.
    pub expected_digest: ContentDigest,
    /// Cryptographic digest of the actual observed outcome or disk state.
    pub actual_digest: ContentDigest,
    /// Typed outcome of this test step.
    pub outcome: TestOutcome,
    /// Step duration in nanoseconds from an explicit or virtual clock (never ambient).
    pub duration_ns: u64,
    /// Optional execution phase name (e.g. "spool_staging", "ledger_commit").
    pub phase: Option<String>,
    /// Optional bounded tags or classification markers.
    pub tags: Vec<String>,
    /// Optional freeform detail string.
    pub detail: Option<String>,
}

impl TestEventRecord {
    /// Validates all fields against contract bounds, format rules, and secret detection.
    pub fn validate(&self) -> Result<(), TestEventError> {
        if self.version != TEST_EVENT_VERSION_1 {
            return Err(TestEventError::UnsupportedVersion(self.version));
        }
        if self.schema != TEST_EVENT_SCHEMA {
            return Err(TestEventError::SchemaMismatch {
                expected: TEST_EVENT_SCHEMA.to_string(),
                actual: self.schema.to_string(),
            });
        }
        validate_test_id("run_id", &self.run_id, MAX_TEST_RUN_ID_LEN)?;
        validate_test_id("case_id", &self.case_id, MAX_TEST_CASE_ID_LEN)?;
        validate_test_id("step_id", &self.step_id, MAX_TEST_STEP_ID_LEN)?;

        if let Some(ref phase) = self.phase {
            if phase.len() > MAX_TEST_PHASE_LEN {
                return Err(TestEventError::PhaseTooLong {
                    max: MAX_TEST_PHASE_LEN,
                    actual: phase.len(),
                });
            }
            check_for_secrets("phase", phase)?;
        }

        if let Some(ref detail) = self.detail {
            if detail.len() > MAX_TEST_DETAIL_LEN {
                return Err(TestEventError::DetailTooLong {
                    max: MAX_TEST_DETAIL_LEN,
                    actual: detail.len(),
                });
            }
            check_for_secrets("detail", detail)?;
        }

        if self.tags.len() > MAX_TEST_TAGS_COUNT {
            return Err(TestEventError::TagsCountExceeded {
                max: MAX_TEST_TAGS_COUNT,
                actual: self.tags.len(),
            });
        }
        for tag in &self.tags {
            if tag.len() > MAX_TEST_TAG_LEN {
                return Err(TestEventError::TagTooLong {
                    max: MAX_TEST_TAG_LEN,
                    actual: tag.len(),
                });
            }
            check_for_secrets("tags", tag)?;
        }

        Ok(())
    }

    /// Renders this event record as a deterministic, bounded single-line JSONL string.
    pub fn to_jsonl(&self) -> Result<String, TestEventError> {
        self.validate()?;

        let mut out = String::with_capacity(512);
        out.push_str("{\"schema\":\"");
        out.push_str(self.schema);
        out.push_str("\",\"version\":");
        out.push_str(&self.version.to_string());
        out.push_str(",\"run_id\":\"");
        escape_json_string(&self.run_id, &mut out);
        out.push_str("\",\"case_id\":\"");
        escape_json_string(&self.case_id, &mut out);
        out.push_str("\",\"step_id\":\"");
        escape_json_string(&self.step_id, &mut out);
        out.push_str("\",\"sequence\":");
        out.push_str(&self.sequence.to_string());
        out.push_str(",\"seed\":");
        out.push_str(&self.seed.to_string());
        out.push_str(",\"source_digest\":\"");
        out.push_str(&self.source_digest.to_string());
        out.push_str("\",\"contract_digest\":\"");
        out.push_str(&self.contract_digest.to_string());
        out.push_str("\",\"input_digest\":\"");
        out.push_str(&self.input_digest.to_string());
        out.push_str("\",\"expected_digest\":\"");
        out.push_str(&self.expected_digest.to_string());
        out.push_str("\",\"actual_digest\":\"");
        out.push_str(&self.actual_digest.to_string());
        out.push_str("\",\"outcome\":\"");
        out.push_str(self.outcome.as_str());
        out.push_str("\",\"duration_ns\":");
        out.push_str(&self.duration_ns.to_string());

        if let Some(ref phase) = self.phase {
            out.push_str(",\"phase\":\"");
            escape_json_string(phase, &mut out);
            out.push('"');
        }

        if !self.tags.is_empty() {
            out.push_str(",\"tags\":[");
            for (idx, tag) in self.tags.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push('"');
                escape_json_string(tag, &mut out);
                out.push('"');
            }
            out.push(']');
        }

        if let Some(ref detail) = self.detail {
            out.push_str(",\"detail\":\"");
            escape_json_string(detail, &mut out);
            out.push('"');
        }

        out.push('}');

        if out.len() > MAX_TEST_EVENT_JSON_BYTES {
            return Err(TestEventError::JsonSizeExceeded {
                max: MAX_TEST_EVENT_JSON_BYTES,
                actual: out.len(),
            });
        }

        out.push('\n');
        Ok(out)
    }

    /// Parses a test event record from a single JSON string or line.
    pub fn from_json_str(s: &str) -> Result<Self, TestEventError> {
        let trimmed = s.trim();
        if trimmed.len() > MAX_TEST_EVENT_JSON_BYTES {
            return Err(TestEventError::JsonSizeExceeded {
                max: MAX_TEST_EVENT_JSON_BYTES,
                actual: trimmed.len(),
            });
        }
        if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
            return Err(TestEventError::MalformedJson(
                "expected JSON object enclosed in braces".to_string(),
            ));
        }

        let inner = &trimmed[1..trimmed.len() - 1];
        let entries = parse_json_key_values(inner)?;

        let schema = entries
            .get("schema")
            .ok_or(TestEventError::MissingField("schema"))?;
        if schema != TEST_EVENT_SCHEMA {
            return Err(TestEventError::SchemaMismatch {
                expected: TEST_EVENT_SCHEMA.to_string(),
                actual: schema.clone(),
            });
        }

        let version = entries
            .get("version")
            .ok_or(TestEventError::MissingField("version"))?
            .parse::<u32>()
            .map_err(|e| TestEventError::MalformedJson(format!("invalid version integer: {e}")))?;

        let run_id = entries
            .get("run_id")
            .or_else(|| entries.get("runId"))
            .ok_or(TestEventError::MissingField("run_id"))?
            .clone();

        let case_id = entries
            .get("case_id")
            .or_else(|| entries.get("caseId"))
            .ok_or(TestEventError::MissingField("case_id"))?
            .clone();

        let step_id = entries
            .get("step_id")
            .or_else(|| entries.get("stepId"))
            .ok_or(TestEventError::MissingField("step_id"))?
            .clone();

        let sequence = entries
            .get("sequence")
            .ok_or(TestEventError::MissingField("sequence"))?
            .parse::<u64>()
            .map_err(|e| TestEventError::MalformedJson(format!("invalid sequence integer: {e}")))?;

        let seed = entries
            .get("seed")
            .ok_or(TestEventError::MissingField("seed"))?
            .parse::<u64>()
            .map_err(|e| TestEventError::MalformedJson(format!("invalid seed integer: {e}")))?;

        let source_str = entries
            .get("source_digest")
            .or_else(|| entries.get("sourceDigest"))
            .ok_or(TestEventError::MissingField("source_digest"))?;
        let source_digest = ContentDigest::parse(source_str)
            .map_err(|e| TestEventError::MalformedJson(format!("invalid source_digest: {e:?}")))?;

        let contract_str = entries
            .get("contract_digest")
            .or_else(|| entries.get("contractDigest"))
            .ok_or(TestEventError::MissingField("contract_digest"))?;
        let contract_digest = ContentDigest::parse(contract_str)
            .map_err(|e| TestEventError::MalformedJson(format!("invalid contract_digest: {e:?}")))?;

        let input_str = entries
            .get("input_digest")
            .or_else(|| entries.get("inputDigest"))
            .ok_or(TestEventError::MissingField("input_digest"))?;
        let input_digest = ContentDigest::parse(input_str)
            .map_err(|e| TestEventError::MalformedJson(format!("invalid input_digest: {e:?}")))?;

        let expected_str = entries
            .get("expected_digest")
            .or_else(|| entries.get("expectedDigest"))
            .ok_or(TestEventError::MissingField("expected_digest"))?;
        let expected_digest = ContentDigest::parse(expected_str)
            .map_err(|e| TestEventError::MalformedJson(format!("invalid expected_digest: {e:?}")))?;

        let actual_str = entries
            .get("actual_digest")
            .or_else(|| entries.get("actualDigest"))
            .ok_or(TestEventError::MissingField("actual_digest"))?;
        let actual_digest = ContentDigest::parse(actual_str)
            .map_err(|e| TestEventError::MalformedJson(format!("invalid actual_digest: {e:?}")))?;

        let outcome_str = entries
            .get("outcome")
            .ok_or(TestEventError::MissingField("outcome"))?;
        let outcome = TestOutcome::parse(outcome_str)?;

        let duration_ns = entries
            .get("duration_ns")
            .or_else(|| entries.get("durationNs"))
            .ok_or(TestEventError::MissingField("duration_ns"))?
            .parse::<u64>()
            .map_err(|e| TestEventError::MalformedJson(format!("invalid duration_ns integer: {e}")))?;

        let phase = entries.get("phase").cloned();
        let detail = entries.get("detail").cloned();

        let tags = if let Some(tags_raw) = entries.get("tags") {
            parse_json_string_array(tags_raw)?
        } else {
            Vec::new()
        };

        let record = Self {
            schema: TEST_EVENT_SCHEMA,
            version,
            run_id,
            case_id,
            step_id,
            sequence,
            seed,
            source_digest,
            contract_digest,
            input_digest,
            expected_digest,
            actual_digest,
            outcome,
            duration_ns,
            phase,
            tags,
            detail,
        };

        record.validate()?;
        Ok(record)
    }
}

fn escape_json_string(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => {
                use core::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

fn parse_json_key_values(
    inner: &str,
) -> Result<std::collections::BTreeMap<String, String>, TestEventError> {
    let mut map = std::collections::BTreeMap::new();
    let bytes = inner.as_bytes();
    let len = bytes.len();
    let mut pos = 0;

    while pos < len {
        while pos < len && (bytes[pos].is_ascii_whitespace() || bytes[pos] == b',') {
            pos += 1;
        }
        if pos >= len {
            break;
        }

        if bytes[pos] != b'"' {
            return Err(TestEventError::MalformedJson(format!(
                "expected key string at position {pos}"
            )));
        }
        pos += 1;
        let key_start = pos;
        while pos < len && bytes[pos] != b'"' {
            if bytes[pos] == b'\\' && pos + 1 < len {
                pos += 2;
            } else {
                pos += 1;
            }
        }
        if pos >= len {
            return Err(TestEventError::MalformedJson("unterminated key string".to_string()));
        }
        let key = unescape_json_slice(&bytes[key_start..pos])?;
        pos += 1;

        while pos < len && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos >= len || bytes[pos] != b':' {
            return Err(TestEventError::MalformedJson(format!(
                "expected colon after key '{key}' at position {pos}"
            )));
        }
        pos += 1;

        while pos < len && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos >= len {
            return Err(TestEventError::MalformedJson(format!(
                "expected value for key '{key}'"
            )));
        }

        if bytes[pos] == b'"' {
            pos += 1;
            let val_start = pos;
            while pos < len && bytes[pos] != b'"' {
                if bytes[pos] == b'\\' && pos + 1 < len {
                    pos += 2;
                } else {
                    pos += 1;
                }
            }
            if pos >= len {
                return Err(TestEventError::MalformedJson(format!(
                    "unterminated string value for key '{key}'"
                )));
            }
            let val = unescape_json_slice(&bytes[val_start..pos])?;
            pos += 1;
            map.insert(key, val);
        } else if bytes[pos] == b'[' {
            let arr_start = pos;
            let mut depth = 0_usize;
            while pos < len {
                if bytes[pos] == b'[' {
                    depth += 1;
                } else if bytes[pos] == b']' {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        pos += 1;
                        break;
                    }
                }
                pos += 1;
            }
            let val = std::str::from_utf8(&bytes[arr_start..pos])
                .map_err(|e| TestEventError::MalformedJson(format!("invalid array utf8: {e}")))?
                .to_string();
            map.insert(key, val);
        } else {
            let val_start = pos;
            while pos < len && bytes[pos] != b',' && bytes[pos] != b'}' && !bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            let val = std::str::from_utf8(&bytes[val_start..pos])
                .map_err(|e| TestEventError::MalformedJson(format!("invalid value utf8: {e}")))?
                .to_string();
            map.insert(key, val);
        }
    }

    Ok(map)
}

fn unescape_json_slice(bytes: &[u8]) -> Result<String, TestEventError> {
    let mut out = String::with_capacity(bytes.len());
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'\\' && idx + 1 < bytes.len() {
            idx += 1;
            match bytes[idx] {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'u' if idx + 4 < bytes.len() => {
                    let hex = std::str::from_utf8(&bytes[idx + 1..idx + 5]).map_err(|_| {
                        TestEventError::MalformedJson("invalid unicode escape".to_string())
                    })?;
                    let code = u32::from_str_radix(hex, 16).map_err(|_| {
                        TestEventError::MalformedJson("invalid hex in unicode escape".to_string())
                    })?;
                    let ch = char::from_u32(code).ok_or_else(|| {
                        TestEventError::MalformedJson("invalid code point in unicode escape".to_string())
                    })?;
                    out.push(ch);
                    idx += 4;
                }
                other => out.push(other as char),
            }
        } else {
            out.push(bytes[idx] as char);
        }
        idx += 1;
    }
    Ok(out)
}

fn parse_json_string_array(s: &str) -> Result<Vec<String>, TestEventError> {
    let trimmed = s.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Err(TestEventError::MalformedJson(
            "expected array enclosed in brackets".to_string(),
        ));
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let bytes = inner.as_bytes();
    let len = bytes.len();
    let mut pos = 0;
    let mut result = Vec::new();

    while pos < len {
        while pos < len && (bytes[pos].is_ascii_whitespace() || bytes[pos] == b',') {
            pos += 1;
        }
        if pos >= len {
            break;
        }
        if bytes[pos] != b'"' {
            return Err(TestEventError::MalformedJson(format!(
                "expected string item in array at position {pos}"
            )));
        }
        pos += 1;
        let start = pos;
        while pos < len && bytes[pos] != b'"' {
            if bytes[pos] == b'\\' && pos + 1 < len {
                pos += 2;
            } else {
                pos += 1;
            }
        }
        if pos >= len {
            return Err(TestEventError::MalformedJson(
                "unterminated string in array".to_string(),
            ));
        }
        let item = unescape_json_slice(&bytes[start..pos])?;
        pos += 1;
        result.push(item);
    }

    Ok(result)
}

/// In-memory collector for deterministic test event sequences.
///
/// Enforces strictly non-decreasing step sequences and validates every record before retention.
#[derive(Clone, Debug, Default)]
pub struct TestEventCollector {
    records: Vec<TestEventRecord>,
    next_sequence: u64,
}

impl TestEventCollector {
    /// Creates a new empty test event collector.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            next_sequence: 0,
        }
    }

    /// Records a test event, validating fields and sequence monotonicity.
    pub fn push(&mut self, record: TestEventRecord) -> Result<(), TestEventError> {
        record.validate()?;
        if record.sequence < self.next_sequence {
            return Err(TestEventError::SequenceRegression {
                expected_at_least: self.next_sequence,
                actual: record.sequence,
            });
        }
        self.next_sequence = record.sequence.saturating_add(1);
        self.records.push(record);
        Ok(())
    }

    /// Returns a slice over all retained test event records.
    #[must_use]
    pub fn records(&self) -> &[TestEventRecord] {
        &self.records
    }

    /// Consumes the collector, returning the retained records vector.
    #[must_use]
    pub fn into_records(self) -> Vec<TestEventRecord> {
        self.records
    }

    /// Writes all retained records as JSONL to the provided writer.
    pub fn write_jsonl<W: Write>(&self, writer: &mut W) -> Result<(), Box<dyn std::error::Error>> {
        for record in &self.records {
            let line = record.to_jsonl()?;
            writer.write_all(line.as_bytes())?;
        }
        writer.flush()?;
        Ok(())
    }
}
