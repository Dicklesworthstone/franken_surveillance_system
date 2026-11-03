#![forbid(unsafe_code)]
//! Deterministic JSON primitives shared by bounded pure query adapters and agent reports.

use std::fmt::Write as _;

/// Escape a string according to RFC 8259, preserving the established CLI byte spelling.
#[must_use]
pub fn escape_json_str(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0C' => out.push_str("\\f"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            '\x7f' => out.push_str("\\u007f"),
            c if (c as u32) < 0x20 || (0x80..=0x9F).contains(&(c as u32)) => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// A JSON string literal.
#[must_use]
pub fn string(value: &str) -> String {
    format!("\"{}\"", escape_json_str(value))
}

/// A JSON array of string literals.
#[must_use]
pub fn strings<I, S>(values: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let items: Vec<String> = values.into_iter().map(|v| string(v.as_ref())).collect();
    array(&items)
}

/// A JSON array of already-rendered values.
#[must_use]
pub fn array(items: &[String]) -> String {
    format!("[{}]", items.join(","))
}

/// A JSON object from trusted field names and already-rendered values, in the given order.
#[must_use]
pub fn object(fields: &[(&str, String)]) -> String {
    let mut out = String::from("{");
    for (index, (key, value)) in fields.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(out, "\"{key}\":{value}");
    }
    out.push('}');
    out
}
