#![forbid(unsafe_code)]
//! Bounded, strict JSON reading for operator- and agent-authored intent files (`--case-file`,
//! `--intent`, ...). This is an input boundary, never a durable format: values are decoded into
//! typed requests and the original bytes are never retained as authority.
//!
//! Strictness: duplicate object keys, trailing bytes, non-UTF-8 input, unpaired surrogates, and
//! inputs past the depth, node, string, or byte bounds are refused. Numbers are kept as their
//! exact decimal text so integer fields keep full precision.

use std::collections::BTreeMap;

/// Largest accepted intent document.
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_NODES: usize = 65_536;
const MAX_STRING_BYTES: usize = 64 * 1024;

/// One decoded JSON value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// A number, as its exact source text.
    Number(String),
    /// A string.
    Text(String),
    /// An array.
    Array(Vec<Value>),
    /// An object with unique keys.
    Object(BTreeMap<String, Value>),
}

/// Why an intent document was refused (a position and a reason, never the document bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonError {
    /// Byte offset of the failure.
    pub at: usize,
    /// What was wrong.
    pub reason: &'static str,
}

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at byte {}", self.reason, self.at)
    }
}

impl std::error::Error for JsonError {}

impl Value {
    /// The object's fields, if this is an object.
    #[must_use]
    pub const fn object(&self) -> Option<&BTreeMap<String, Self>> {
        match self {
            Self::Object(fields) => Some(fields),
            _ => None,
        }
    }

    /// The array's items, if this is an array.
    #[must_use]
    pub fn array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The string, if this is a string.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            _ => None,
        }
    }

    /// The boolean, if this is a boolean.
    #[must_use]
    pub const fn boolean(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// An exact signed integer from a JSON integer or a canonical decimal string.
    #[must_use]
    pub fn integer(&self) -> Option<i128> {
        let text = match self {
            Self::Number(text) | Self::Text(text) => text.as_str(),
            _ => return None,
        };
        let digits = text.strip_prefix('-').unwrap_or(text);
        if digits.is_empty()
            || !digits.bytes().all(|byte| byte.is_ascii_digit())
            || (digits.len() > 1 && digits.starts_with('0'))
        {
            return None;
        }
        text.parse().ok()
    }
}

/// Decodes one complete JSON document.
pub fn parse(text: &str) -> Result<Value, JsonError> {
    if text.len() > MAX_INPUT_BYTES {
        return Err(JsonError {
            at: MAX_INPUT_BYTES,
            reason: "document exceeds the input bound",
        });
    }
    let mut parser = Parser {
        bytes: text.as_bytes(),
        text,
        at: 0,
        nodes: 0,
    };
    let value = parser.value(0)?;
    parser.whitespace();
    if parser.at != parser.bytes.len() {
        return parser.fail("trailing bytes after the document");
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    at: usize,
    nodes: usize,
}

impl Parser<'_> {
    fn fail<T>(&self, reason: &'static str) -> Result<T, JsonError> {
        Err(JsonError {
            at: self.at,
            reason,
        })
    }

    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.at)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.at += 1;
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, JsonError> {
        if self.text[self.at..].starts_with(word) {
            self.at += word.len();
            Ok(value)
        } else {
            self.fail("invalid literal")
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth > MAX_DEPTH {
            return self.fail("document nests too deeply");
        }
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return self.fail("document has too many values");
        }
        self.whitespace();
        match self.bytes.get(self.at) {
            None => self.fail("unexpected end of document"),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'"') => self.string().map(Value::Text),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => self.fail("unexpected character"),
        }
    }

    fn number(&mut self) -> Result<Value, JsonError> {
        let start = self.at;
        if self.bytes.get(self.at) == Some(&b'-') {
            self.at += 1;
        }
        let digits = |parser: &mut Self| {
            let begin = parser.at;
            while parser.bytes.get(parser.at).is_some_and(u8::is_ascii_digit) {
                parser.at += 1;
            }
            parser.at - begin
        };
        let integer_start = self.at;
        let integer = digits(self);
        if integer == 0 || (integer > 1 && self.bytes[integer_start] == b'0') {
            return self.fail("invalid number");
        }
        if self.bytes.get(self.at) == Some(&b'.') {
            self.at += 1;
            if digits(self) == 0 {
                return self.fail("invalid number fraction");
            }
        }
        if matches!(self.bytes.get(self.at), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.bytes.get(self.at), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if digits(self) == 0 {
                return self.fail("invalid number exponent");
            }
        }
        if self.at - start > 64 {
            return self.fail("number is too long");
        }
        Ok(Value::Number(self.text[start..self.at].to_owned()))
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let Some(chunk) = self.text.get(self.at..self.at + 4) else {
            return self.fail("truncated unicode escape");
        };
        let value =
            u32::from_str_radix(chunk, 16).or_else(|_| self.fail("invalid unicode escape"))?;
        self.at += 4;
        Ok(value)
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.at += 1;
        let mut out = String::new();
        loop {
            let Some(&byte) = self.bytes.get(self.at) else {
                return self.fail("unterminated string");
            };
            match byte {
                b'"' => {
                    self.at += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.at += 1;
                    let Some(&escape) = self.bytes.get(self.at) else {
                        return self.fail("unterminated escape");
                    };
                    self.at += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let first = self.hex4()?;
                            let scalar = if (0xD800..0xDC00).contains(&first) {
                                if self.text.get(self.at..self.at + 2) != Some("\\u") {
                                    return self.fail("unpaired surrogate");
                                }
                                self.at += 2;
                                let second = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&second) {
                                    return self.fail("unpaired surrogate");
                                }
                                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&first) {
                                return self.fail("unpaired surrogate");
                            } else {
                                first
                            };
                            let Some(character) = char::from_u32(scalar) else {
                                return self.fail("invalid unicode scalar");
                            };
                            out.push(character);
                        }
                        _ => return self.fail("invalid escape"),
                    }
                }
                0x00..=0x1f => return self.fail("control character in string"),
                _ => {
                    let Some(character) = self.text[self.at..].chars().next() else {
                        return self.fail("unterminated string");
                    };
                    out.push(character);
                    self.at += character.len_utf8();
                }
            }
            if out.len() > MAX_STRING_BYTES {
                return self.fail("string exceeds its bound");
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.at += 1;
        let mut items = Vec::new();
        self.whitespace();
        if self.bytes.get(self.at) == Some(&b']') {
            self.at += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.whitespace();
            match self.bytes.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Array(items));
                }
                _ => return self.fail("expected `,` or `]`"),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.at += 1;
        let mut fields = BTreeMap::new();
        self.whitespace();
        if self.bytes.get(self.at) == Some(&b'}') {
            self.at += 1;
            return Ok(Value::Object(fields));
        }
        loop {
            self.whitespace();
            if self.bytes.get(self.at) != Some(&b'"') {
                return self.fail("expected an object key");
            }
            let key = self.string()?;
            self.whitespace();
            if self.bytes.get(self.at) != Some(&b':') {
                return self.fail("expected `:`");
            }
            self.at += 1;
            let value = self.value(depth + 1)?;
            if fields.insert(key, value).is_some() {
                return self.fail("duplicate object key");
            }
            self.whitespace();
            match self.bytes.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(fields));
                }
                _ => return self.fail("expected `,` or `}`"),
            }
        }
    }
}

/// Reads an intent document from a regular file, or from stdin when `path` is `-`.
pub fn read_document(path: &str) -> Result<Value, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    if path == "-" {
        std::io::stdin()
            .take(MAX_INPUT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("stdin cannot be read: {error}"))?;
    } else {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("the file cannot be read: {error}"))?;
        if !metadata.file_type().is_file() {
            return Err("the path is not a regular file".to_owned());
        }
        std::fs::File::open(path)
            .and_then(|file| {
                file.take(MAX_INPUT_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)
            })
            .map_err(|error| format!("the file cannot be read: {error}"))?;
    }
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(format!("the document exceeds {MAX_INPUT_BYTES} bytes"));
    }
    let text = String::from_utf8(bytes).map_err(|_| "the document is not UTF-8".to_owned())?;
    parse(&text).map_err(|error| format!("the document is not valid JSON: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_nested_documents_exactly() -> Result<(), JsonError> {
        let value = parse(r#" {"a": [1, -20, "xé😀", true, null], "b": {"c": 0.5e3}} "#)?;
        let fields = value.object().ok_or(JsonError {
            at: 0,
            reason: "not object",
        })?;
        let items = fields["a"].array().ok_or(JsonError {
            at: 0,
            reason: "not array",
        })?;
        assert_eq!(items[0].integer(), Some(1));
        assert_eq!(items[1].integer(), Some(-20));
        assert_eq!(items[2].text(), Some("x\u{e9}\u{1f600}"));
        assert_eq!(items[3].boolean(), Some(true));
        assert_eq!(items[4], Value::Null);
        assert_eq!(fields["b"].object().map(|b| b["c"].integer()), Some(None));
        Ok(())
    }

    #[test]
    fn refuses_malformed_and_ambiguous_documents() {
        for bad in [
            r#"{"a":1,"a":2}"#,
            r#"{"a":1} x"#,
            r#"[01]"#,
            r#""\ud800""#,
            "\"a\u{1}\"",
            r#"{"a" 1}"#,
            "[1,]",
            "",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} must be refused");
        }
        let deep = "[".repeat(40) + &"]".repeat(40);
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn integers_keep_full_precision_and_reject_non_canonical_text() {
        let big = Value::Text("-170141183460469231731687303715884105728".to_owned());
        assert_eq!(big.integer(), Some(i128::MIN));
        assert_eq!(Value::Text("007".to_owned()).integer(), None);
        assert_eq!(Value::Number("1.5".to_owned()).integer(), None);
        assert_eq!(Value::Text("".to_owned()).integer(), None);
    }
}
