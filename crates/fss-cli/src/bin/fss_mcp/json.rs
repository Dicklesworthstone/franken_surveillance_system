#![forbid(unsafe_code)]
//! Bounded JSON decoding for the local MCP wire boundary, not a durable format.
//! Unknown values are validated, not interpreted. Duplicate decoded keys are rejected.

use std::collections::BTreeMap;

pub(super) const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_NODES: usize = 4096;
const MAX_STRING_BYTES: usize = 16 * 1024;

#[derive(Debug, PartialEq)]
pub(super) enum Value {
    Null,
    Boolean,
    Number(String),
    Text(String),
    Array,
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub(super) fn object(&self) -> Option<&BTreeMap<String, Self>> {
        match self { Self::Object(value) => Some(value), _ => None }
    }

    pub(super) fn text(&self) -> Option<&str> {
        match self { Self::Text(value) => Some(value), _ => None }
    }
}

pub(super) fn parse(text: &str) -> Result<Value, ()> {
    if text.len() > MAX_FRAME_BYTES { return Err(()); }
    let mut parser = Parser { text, at: 0, nodes: 0 };
    let value = parser.value(0)?;
    parser.whitespace();
    if parser.at != text.len() { return Err(()); }
    Ok(value)
}

struct Parser<'a> { text: &'a str, at: usize, nodes: usize }

impl Parser<'_> {
    fn peek(&self) -> Option<u8> { self.text.as_bytes().get(self.at).copied() }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) { self.at += 1; }
    }

    fn eat(&mut self, byte: u8) -> Result<(), ()> {
        if self.peek() != Some(byte) { return Err(()); }
        self.at += 1;
        Ok(())
    }

    fn value(&mut self, depth: usize) -> Result<Value, ()> {
        if depth > MAX_DEPTH || self.nodes >= MAX_NODES { return Err(()); }
        self.nodes += 1;
        self.whitespace();
        match self.peek() {
            Some(b'{') => {
                self.at += 1;
                self.whitespace();
                let mut members = BTreeMap::new();
                if self.peek() == Some(b'}') { self.at += 1; return Ok(Value::Object(members)); }
                loop {
                    self.whitespace();
                    let key = self.string()?;
                    self.whitespace();
                    self.eat(b':')?;
                    let value = self.value(depth + 1)?;
                    if members.insert(key, value).is_some() { return Err(()); }
                    self.whitespace();
                    if self.peek() == Some(b'}') { self.at += 1; break; }
                    self.eat(b',')?;
                }
                Ok(Value::Object(members))
            }
            Some(b'[') => {
                self.at += 1;
                self.whitespace();
                if self.peek() == Some(b']') { self.at += 1; return Ok(Value::Array); }
                loop {
                    self.value(depth + 1)?;
                    self.whitespace();
                    if self.peek() == Some(b']') { self.at += 1; break; }
                    self.eat(b',')?;
                }
                Ok(Value::Array)
            }
            Some(b'"') => self.string().map(Value::Text),
            Some(b't') => { self.literal("true")?; Ok(Value::Boolean) }
            Some(b'f') => { self.literal("false")?; Ok(Value::Boolean) }
            Some(b'n') => { self.literal("null")?; Ok(Value::Null) }
            Some(b'-' | b'0'..=b'9') => self.number().map(Value::Number),
            _ => Err(()),
        }
    }

    fn literal(&mut self, literal: &str) -> Result<(), ()> {
        if !self.text.get(self.at..).ok_or(())?.starts_with(literal) { return Err(()); }
        self.at += literal.len();
        Ok(())
    }

    fn digits(&mut self) -> Result<(), ()> {
        let start = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) { self.at += 1; }
        if self.at == start { Err(()) } else { Ok(()) }
    }

    fn number(&mut self) -> Result<String, ()> {
        let start = self.at;
        if self.peek() == Some(b'-') { self.at += 1; }
        match self.peek() {
            Some(b'0') => { self.at += 1; }
            Some(b'1'..=b'9') => self.digits()?,
            _ => return Err(()),
        }
        if self.peek() == Some(b'.') { self.at += 1; self.digits()?; }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) { self.at += 1; }
            self.digits()?;
        }
        Ok(self.text.get(start..self.at).ok_or(())?.to_owned())
    }

    fn hex4(&mut self) -> Result<u32, ()> {
        let mut result = 0;
        for _ in 0..4 {
            let digit = match self.peek().ok_or(())? {
                byte @ b'0'..=b'9' => byte - b'0',
                byte @ b'a'..=b'f' => byte - b'a' + 10,
                byte @ b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err(()),
            };
            result = result * 16 + u32::from(digit);
            self.at += 1;
        }
        Ok(result)
    }

    fn unicode(&mut self) -> Result<char, ()> {
        let first = self.hex4()?;
        let scalar = if (0xd800..=0xdbff).contains(&first) {
            self.eat(b'\\')?;
            self.eat(b'u')?;
            let second = self.hex4()?;
            if !(0xdc00..=0xdfff).contains(&second) { return Err(()); }
            0x10000 + ((first - 0xd800) << 10) + second - 0xdc00
        } else { first };
        char::from_u32(scalar).ok_or(())
    }

    fn string(&mut self) -> Result<String, ()> {
        self.eat(b'"')?;
        let mut result = String::new();
        loop {
            let ch = match self.peek().ok_or(())? {
                b'"' => { self.at += 1; return Ok(result); }
                0..=0x1f => return Err(()),
                b'\\' => {
                    self.at += 1;
                    let escaped = self.peek().ok_or(())?;
                    self.at += 1;
                    match escaped {
                        b'"' => '"', b'\\' => '\\', b'/' => '/', b'b' => '\u{8}',
                        b'f' => '\u{c}', b'n' => '\n', b'r' => '\r', b't' => '\t',
                        b'u' => self.unicode()?, _ => return Err(()),
                    }
                }
                _ => {
                    let ch = self.text.get(self.at..).ok_or(())?.chars().next().ok_or(())?;
                    self.at += ch.len_utf8();
                    ch
                }
            };
            if result.len() + ch.len_utf8() > MAX_STRING_BYTES { return Err(()); }
            result.push(ch);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_and_exact_number_spelling() {
        assert_eq!(parse(r#""\uD83D\uDE80 café""#), Ok(Value::Text("🚀 café".to_owned())));
        assert_eq!(parse("-1234567890123456789"), Ok(Value::Number("-1234567890123456789".to_owned())));
        assert!(parse(r#"{"a":[true,false,null,1.25e-3],"b":"\b\f\n\r\t\/\\\""}"#).is_ok());
    }

    #[test]
    fn rejects_ambiguous_or_malformed_json() {
        for text in [r#"{"a":1,"\u0061":2}"#, r#""\uD800""#, r#""\uDC00""#,
            r#""\uD800\u0041""#, "[1,]", "{\"a\":1,}", "01", "-01", "1.", "1e",
            "1e+", "+1", "NaN", "true false", "\"a\nb\"", "[", "{", ""] {
            assert!(parse(text).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn bounds_bytes_depth_nodes_and_decoded_strings() {
        assert!(parse(&" ".repeat(MAX_FRAME_BYTES + 1)).is_err());
        assert!(parse(&format!("{}0{}", "[".repeat(34), "]".repeat(34))).is_err());
        assert!(parse(&format!("[{}0]", "0,".repeat(MAX_NODES))).is_err());
        assert!(parse(&format!("\"{}\"", "x".repeat(MAX_STRING_BYTES + 1))).is_err());
        assert!(parse(&format!("\"{}\"", "x".repeat(MAX_STRING_BYTES))).is_ok());
    }
}
