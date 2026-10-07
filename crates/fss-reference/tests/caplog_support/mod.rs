#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Truthful CAPLOG records for the fail-closed e2e harness (`scripts/e2e/lib.sh`).
//!
//! The harness reads every `CAPLOG {json}` marker from a test's stdout and stderr. A record
//! must be one well-formed JSON object with a unique step name, and a `pass` verdict whose
//! `expected` differs from its `observed` is a failure. A [`Record`] therefore carries the
//! values a check actually compared, named field by field, and derives its verdict from them:
//! it is `pass` exactly when every observed field equals its expected field. Every string is
//! JSON-escaped, so a record is never malformed whatever the observed text contains.

use std::fmt::Write as _;

/// A value rendered as JSON text inside a CAPLOG record.
pub trait CaplogValue {
    /// The value as one JSON text.
    fn caplog_json(&self) -> String;
}

/// JSON text that a caller already rendered (an object view such as a frame summary).
pub struct RawJson(pub String);

impl CaplogValue for RawJson {
    fn caplog_json(&self) -> String {
        self.0.clone()
    }
}

impl CaplogValue for bool {
    fn caplog_json(&self) -> String {
        self.to_string()
    }
}

macro_rules! integer_value {
    ($($ty:ty),*) => {$(
        impl CaplogValue for $ty {
            fn caplog_json(&self) -> String {
                self.to_string()
            }
        }
    )*};
}
integer_value!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, isize);

macro_rules! float_value {
    ($($ty:ty),*) => {$(
        impl CaplogValue for $ty {
            fn caplog_json(&self) -> String {
                // JSON has no NaN or infinity; a non-finite value is reported as its name.
                if self.is_finite() {
                    format!("{self:?}")
                } else {
                    json_string(&self.to_string())
                }
            }
        }
    )*};
}
float_value!(f32, f64);

impl CaplogValue for str {
    fn caplog_json(&self) -> String {
        json_string(self)
    }
}

impl CaplogValue for String {
    fn caplog_json(&self) -> String {
        json_string(self)
    }
}

impl<T: CaplogValue + ?Sized> CaplogValue for &T {
    fn caplog_json(&self) -> String {
        (**self).caplog_json()
    }
}

impl<T: CaplogValue> CaplogValue for Option<T> {
    fn caplog_json(&self) -> String {
        self.as_ref()
            .map_or_else(|| "null".to_string(), CaplogValue::caplog_json)
    }
}

impl<T: CaplogValue> CaplogValue for [T] {
    fn caplog_json(&self) -> String {
        let items: Vec<String> = self.iter().map(CaplogValue::caplog_json).collect();
        format!("[{}]", items.join(","))
    }
}

impl<T: CaplogValue, const N: usize> CaplogValue for [T; N] {
    fn caplog_json(&self) -> String {
        self.as_slice().caplog_json()
    }
}

impl<T: CaplogValue> CaplogValue for Vec<T> {
    fn caplog_json(&self) -> String {
        self.as_slice().caplog_json()
    }
}

impl<A: CaplogValue, B: CaplogValue> CaplogValue for (A, B) {
    fn caplog_json(&self) -> String {
        format!("[{},{}]", self.0.caplog_json(), self.1.caplog_json())
    }
}

/// `text` as one JSON string literal, every quote, backslash and control character escaped.
pub fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 || c == '\u{7f}' => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// One compared field: name, expected JSON, observed JSON, and whether they are equal.
type Field = (String, String, String, bool);

/// One CAPLOG step: the named fields a check compared, expected beside observed.
pub struct Record {
    step: String,
    fields: Vec<Field>,
}

impl Record {
    /// A record for `step`; the step name must be unique within its e2e script.
    pub fn new(step: &str) -> Self {
        Self {
            step: step.to_string(),
            fields: Vec::new(),
        }
    }

    /// Adds one compared field: the value the check required and the value it saw.
    pub fn check<E, O>(mut self, name: &str, expected: E, observed: O) -> Self
    where
        E: CaplogValue,
        O: CaplogValue,
    {
        let equal = expected.caplog_json() == observed.caplog_json();
        self.fields.push((
            name.to_string(),
            expected.caplog_json(),
            observed.caplog_json(),
            equal,
        ));
        self
    }

    /// Adds one compared field whose equality is the type's own `==`, exactly as the test's
    /// `assert_eq!` compares it (floats: `-0.0 == 0.0`, as the harness's JSON comparison also
    /// holds).
    pub fn check_eq<T>(mut self, name: &str, expected: T, observed: T) -> Self
    where
        T: CaplogValue + PartialEq,
    {
        self.fields.push((
            name.to_string(),
            expected.caplog_json(),
            observed.caplog_json(),
            expected == observed,
        ));
        self
    }

    /// True exactly when every observed field equals its expected field.
    pub fn passed(&self) -> bool {
        !self.fields.is_empty() && self.fields.iter().all(|field| field.3)
    }

    fn object(&self, pick: fn(&Field) -> &String) -> String {
        let members: Vec<String> = self
            .fields
            .iter()
            .map(|field| format!("{}:{}", json_string(&field.0), pick(field)))
            .collect();
        format!("{{{}}}", members.join(","))
    }

    /// The expected fields as one JSON object.
    pub fn expected_json(&self) -> String {
        self.object(|field| &field.1)
    }

    /// The observed fields as one JSON object.
    pub fn observed_json(&self) -> String {
        self.object(|field| &field.2)
    }

    /// Prints the record with a verdict derived from the compared fields; returns that verdict.
    pub fn emit(&self, duration_ms: u128) -> bool {
        let passed = self.passed();
        println!(
            "CAPLOG {{\"step\":{},\"verdict\":\"{}\",\"exit\":{},\"duration_ms\":{duration_ms},\
             \"expected\":{},\"observed\":{}}}",
            json_string(&self.step),
            if passed { "pass" } else { "fail" },
            i32::from(!passed),
            self.expected_json(),
            self.observed_json(),
        );
        passed
    }

    /// Prints the record and asserts that its derived verdict equals `checked`, the outcome of
    /// the test's own check, so a record can never report another outcome than the assertion
    /// beside it. Returns `checked`.
    pub fn emit_checked(&self, duration_ms: u128, checked: bool) -> bool {
        let passed = self.emit(duration_ms);
        assert_eq!(
            passed,
            checked,
            "CAPLOG record {} disagrees with its check: expected {} observed {}",
            self.step,
            self.expected_json(),
            self.observed_json()
        );
        checked
    }

    /// Prints an explicit skip (never a pass): the check could not run, for `reason`.
    pub fn emit_skip(&self, reason: &str, duration_ms: u128) {
        println!(
            "CAPLOG {{\"step\":{},\"verdict\":\"skip\",\"exit\":0,\"duration_ms\":{duration_ms},\
             \"reason\":{},\"expected\":{},\"observed\":{}}}",
            json_string(&self.step),
            json_string(reason),
            self.expected_json(),
            self.observed_json(),
        );
    }
}
