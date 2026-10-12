#![forbid(unsafe_code)]
//! Test-only decoding of the server's single-text MCP result wrapper.
//! Only that outer string may exceed the native intent parser's 64 KiB string bound.
//! Escape-aligned pieces and all outer metadata still use the existing strict JSON parser.

use std::error::Error;

use fss_cli::json_input::{MAX_INPUT_BYTES, Value, parse};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_WIRE_BYTES: usize = 6 * MAX_TEXT_BYTES + MAX_INPUT_BYTES;
const CHUNK_BYTES: usize = 8 * 1024;

fn whitespace(bytes: &[u8], mut at: usize) -> usize {
    while bytes
        .get(at)
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t' | b'\r' | b'\n'))
    {
        at += 1;
    }
    at
}

fn quoted_end(bytes: &[u8], start: usize) -> Result<usize> {
    if bytes.get(start) != Some(&b'"') {
        return Err("MCP text value is not a JSON string".into());
    }
    let mut at = start + 1;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'"' => return Ok(at + 1),
            b'\\' => at += 2,
            0..=31 => return Err("unescaped control byte in MCP JSON string".into()),
            _ => at += 1,
        }
    }
    Err("unterminated MCP JSON string".into())
}

/// One complete scalar or escape, keeping a UTF-16 surrogate pair in one native parse.
fn next_piece(text: &str, at: usize) -> Result<usize> {
    let bytes = text.as_bytes();
    if bytes[at] != b'\\' {
        return Ok(at + text[at..].chars().next().ok_or("missing scalar")?.len_utf8());
    }
    match bytes.get(at + 1) {
        Some(b'u') => {
            let hex = text.get(at + 2..at + 6).ok_or("short Unicode escape")?;
            if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err("invalid Unicode escape".into());
            }
            let unit = u16::from_str_radix(hex, 16)?;
            if (0xd800..=0xdbff).contains(&unit) {
                let low = text.get(at + 6..at + 12).ok_or("missing low surrogate")?;
                if !low.starts_with("\\u") {
                    return Err("missing low surrogate escape".into());
                }
                // The existing native parser validates the second code unit and pairing.
                Ok(at + 12)
            } else {
                Ok(at + 6)
            }
        }
        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => Ok(at + 2),
        Some(_) => Err("invalid MCP JSON escape".into()),
        None => Err("incomplete MCP JSON escape".into()),
    }
}

fn decode_text(quoted: &str) -> Result<String> {
    let inside = quoted
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or("missing MCP string quotes")?;
    let mut decoded = String::new();
    let mut start = 0;
    let mut at = 0;
    while at < inside.len() {
        at = next_piece(inside, at)?;
        if at - start >= CHUNK_BYTES || at == inside.len() {
            let chunk = format!("\"{}\"", &inside[start..at]);
            let Value::Text(piece) = parse(&chunk)? else {
                return Err("native string decoder returned a non-string".into());
            };
            if piece.len() > MAX_TEXT_BYTES - decoded.len() {
                return Err("MCP semantic text exceeds the server's 4 MiB ceiling".into());
            }
            decoded.push_str(&piece);
            start = at;
        }
    }
    Ok(decoded)
}

/// Parse one response without changing production request limits or any response content.
/// Initialization/error messages and every field outside the single tool text retain native
/// parsing limits. Large tool text is restored only after the full outer structure is checked.
pub(super) fn parse_response(line: &str) -> Result<Value> {
    if line.len() > MAX_WIRE_BYTES {
        return Err("MCP response exceeds the bounded escaped wire ceiling".into());
    }
    let bytes = line.as_bytes();
    let mut at = 0;
    let mut text_span = None;
    while at < bytes.len() {
        if bytes[at] != b'"' {
            at += 1;
            continue;
        }
        let end = quoted_end(bytes, at)?;
        let colon = whitespace(bytes, end);
        if bytes.get(colon) == Some(&b':') && parse(&line[at..end])?.text() == Some("text") {
            let start = whitespace(bytes, colon + 1);
            let finish = quoted_end(bytes, start)?;
            if text_span.replace((start, finish)).is_some() {
                return Err("more than one MCP text field".into());
            }
            at = finish;
        } else {
            at = end;
        }
    }
    let Some((start, end)) = text_span else {
        return parse(line).map_err(Into::into);
    };
    let wrapper_len = line.len() - (end - start) + 2;
    if wrapper_len > MAX_INPUT_BYTES {
        return Err("MCP outer metadata exceeds the native document bound".into());
    }
    let mut wrapper = String::with_capacity(wrapper_len);
    wrapper.push_str(&line[..start]);
    wrapper.push_str("\"\"");
    wrapper.push_str(&line[end..]);
    let mut response = parse(&wrapper)?;
    let Value::Object(root) = &mut response else {
        return Err("MCP response is not an object".into());
    };
    if root.len() != 3
        || root.get("jsonrpc").and_then(Value::text) != Some("2.0")
        || !matches!(
            root.get("id"),
            Some(Value::Null | Value::Text(_) | Value::Number(_))
        )
    {
        return Err("unexpected MCP response metadata".into());
    }
    let Some(Value::Object(result)) = root.get_mut("result") else {
        return Err("MCP tool result is not an object".into());
    };
    if result.len() != 2 || !matches!(result.get("isError"), Some(Value::Bool(_))) {
        return Err("unexpected MCP result metadata".into());
    }
    let Some(Value::Array(content)) = result.get_mut("content") else {
        return Err("MCP content is not an array".into());
    };
    if content.len() != 1 {
        return Err("MCP result must contain exactly one text item".into());
    }
    let Value::Object(item) = &mut content[0] else {
        return Err("MCP content item is not an object".into());
    };
    if item.len() != 2
        || item.get("type").and_then(Value::text) != Some("text")
        || item.get("text").and_then(Value::text) != Some("")
    {
        return Err("unexpected MCP text item".into());
    }
    item.insert("text".to_owned(), Value::Text(decode_text(&line[start..end])?));
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrapper(id: &str, quoted: &str) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"result":{{"content":[{{"type":"text","text":{quoted}}}],"isError":false}}}}"#
        )
    }

    fn body(value: &Value) -> Result<&str> {
        value
            .object()
            .and_then(|root| root.get("result"))
            .and_then(Value::object)
            .and_then(|result| result.get("content"))
            .and_then(Value::array)
            .and_then(|content| content.first())
            .and_then(Value::object)
            .and_then(|item| item.get("text"))
            .and_then(Value::text)
            .ok_or_else(|| "missing result text".into())
    }

    #[test]
    fn large_outer_text_retains_the_full_native_document_and_exact_id() -> Result<()> {
        let rows = (0..128)
            .map(|_| format!("\"{}\"", "x".repeat(640)))
            .collect::<Vec<_>>()
            .join(",");
        let semantic = format!("{{\"rows\":[{rows}]}}");
        let frame = wrapper(
            "900719925474099312345678901",
            &format!("\"{}\"", fss_cli::escape_json_str(&semantic)),
        );
        assert!(
            parse(&frame).is_err(),
            "the production intent limit stays unchanged"
        );
        let decoded = parse_response(&frame)?;
        assert_eq!(body(&decoded)?, semantic);
        assert_eq!(parse(body(&decoded)?)?, parse(&semantic)?);
        assert_eq!(
            decoded.object().and_then(|root| root.get("id")),
            Some(&Value::Number("900719925474099312345678901".to_owned()))
        );
        Ok(())
    }

    #[test]
    fn chunk_boundaries_preserve_unicode_surrogates_and_literal_escapes() -> Result<()> {
        let quoted = format!(
            "\"{}\\uD83D\\uDE80\\n\\\"\\\\\\t\\u0000é\"",
            "a".repeat(CHUNK_BYTES - 3)
        );
        let value = parse_response(&wrapper(r#""id:\u0061""#, &quoted))?;
        assert_eq!(
            body(&value)?,
            format!("{}🚀\n\"\\\t\0é", "a".repeat(CHUNK_BYTES - 3))
        );
        assert_eq!(
            value
                .object()
                .and_then(|root| root.get("id"))
                .and_then(Value::text),
            Some("id:a")
        );
        Ok(())
    }

    #[test]
    fn malformed_strings_and_ambiguous_wrappers_are_never_masked() {
        for quoted in [
            r#""\q""#,
            r#""\é""#,
            r#""\🚀""#,
            r#""\uD800""#,
            r#""\uDC00""#,
            r#""\uD800\u0041""#,
            r#""\u12xz""#,
            "\"unescaped\nnewline\"",
        ] {
            assert!(parse_response(&wrapper("2", quoted)).is_err(), "{quoted}");
        }
        let valid = wrapper("2", r#""unchanged""#);
        for invalid in [
            format!("{valid} trailing"),
            valid.replace(r#""id":2"#, r#""id":2,"id":3"#),
            valid.replace(r#""type":"text""#, r#""type":"image""#),
            valid.replace(r#""text":"unchanged""#, r#""text":"unchanged","text":"other""#),
            valid.replace(r#""isError":false"#, r#""isError":false,"extra":null"#),
            valid.replace(r#""id":2"#, r#""id":{"text":"outside-content"}"#),
        ] {
            assert!(parse_response(&invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn semantic_and_non_content_string_limits_remain_enforced() -> Result<()> {
        let maximum = "x".repeat(MAX_TEXT_BYTES);
        assert_eq!(
            body(&parse_response(&wrapper("2", &format!("\"{maximum}\"")))?)?,
            maximum
        );
        assert!(parse_response(&wrapper("2", &format!("\"{maximum}x\""))).is_err());
        assert!(
            parse_response(&wrapper(&format!("\"{}\"", "i".repeat(65_537)), r#""small""#)).is_err()
        );
        let initialization =
            r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;
        assert_eq!(parse_response(initialization)?, parse(initialization)?);
        Ok(())
    }
}
