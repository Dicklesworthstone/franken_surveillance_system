#![forbid(unsafe_code)]
//! Narrow, bounded S3 multipart XML. Only a flat response root and scalar
//! children are admitted. DTDs, processing instructions, nesting and duplicate
//! fields cannot turn an ambiguous provider response into an acknowledgement.

use std::collections::BTreeMap;

use fss_core::ContentDigest;
use fss_object::multipart::PartReceipt;

use super::{S3Error, signing};

const NAMESPACE: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

pub(super) fn space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}
pub(super) fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
        && value.as_bytes()[0].is_ascii_alphabetic()
}
fn valid_char(value: char) -> bool {
    matches!(value, '\t' | '\n' | '\r')
        || value >= ' ' && value != '\u{fffe}' && value != '\u{ffff}'
}

pub(super) fn decode(value: &str) -> Result<String, S3Error> {
    if value.len() > 16 * 1024 || value.contains('<') || value.contains("]]>") {
        return Err(S3Error::Protocol);
    }
    let mut rest = value;
    let mut out = String::with_capacity(value.len());
    while let Some(index) = rest.find('&') {
        out.push_str(&rest[..index]);
        rest = &rest[index + 1..];
        let end = rest
            .find(';')
            .filter(|end| *end <= 12)
            .ok_or(S3Error::Protocol)?;
        let entity = &rest[..end];
        let c = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let (digits, radix) = if let Some(digits) = entity.strip_prefix("#x") {
                    (digits, 16)
                } else if let Some(digits) = entity.strip_prefix('#') {
                    (digits, 10)
                } else {
                    return Err(S3Error::Protocol);
                };
                if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
                    return Err(S3Error::Protocol);
                }
                char::from_u32(u32::from_str_radix(digits, radix).map_err(|_| S3Error::Protocol)?)
                    .filter(|c| valid_char(*c))
                    .ok_or(S3Error::Protocol)?
            }
        };
        out.push(c);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    if !out.chars().all(valid_char) {
        return Err(S3Error::Protocol);
    }
    Ok(out)
}

fn root(open: &str, expected: &str) -> Result<(), S3Error> {
    let end = open.find(space).unwrap_or(open.len());
    if &open[..end] != expected {
        return Err(S3Error::Protocol);
    }
    let attribute = open[end..].trim_matches(space);
    if attribute.is_empty() {
        return Ok(());
    }
    let attribute = attribute
        .strip_prefix("xmlns")
        .ok_or(S3Error::Protocol)?
        .trim_start_matches(space)
        .strip_prefix('=')
        .ok_or(S3Error::Protocol)?
        .trim_start_matches(space);
    let quote = attribute.chars().next().ok_or(S3Error::Protocol)?;
    if !matches!(quote, '\'' | '"')
        || !attribute.ends_with(quote)
        || attribute.len() < 2
        || &attribute[1..attribute.len() - 1] != NAMESPACE
    {
        return Err(S3Error::Protocol);
    }
    Ok(())
}

pub(super) fn body<'a>(bytes: &'a [u8], expected: &str) -> Result<&'a str, S3Error> {
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(S3Error::Protocol);
    }
    let mut text = std::str::from_utf8(bytes)
        .map_err(|_| S3Error::Protocol)?
        .trim_matches(space);
    if text.starts_with("<?xml") {
        let end = text
            .find("?>")
            .filter(|end| *end <= 128)
            .ok_or(S3Error::Protocol)?;
        let declaration = &text[..end + 2];
        if !matches!(
            declaration,
            "<?xml version=\"1.0\"?>"
                | "<?xml version='1.0'?>"
                | "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                | "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        ) {
            return Err(S3Error::Protocol);
        }
        text = text[end + 2..].trim_start_matches(space);
    }
    let text = text.strip_prefix('<').ok_or(S3Error::Protocol)?;
    let end = text.find('>').ok_or(S3Error::Protocol)?;
    root(&text[..end], expected)?;
    let text = &text[end + 1..];
    let closing = format!("</{expected}>");
    text.strip_suffix(&closing).ok_or(S3Error::Protocol)
}

pub(super) fn response(bytes: &[u8], expected: &str) -> Result<BTreeMap<String, String>, S3Error> {
    let mut text = body(bytes, expected)?;
    let mut fields = BTreeMap::new();
    loop {
        text = text.trim_start_matches(space);
        if text.is_empty() {
            return Ok(fields);
        }
        if fields.len() >= 32 {
            return Err(S3Error::Protocol);
        }
        let tail = text.strip_prefix('<').ok_or(S3Error::Protocol)?;
        let end = tail.find('>').ok_or(S3Error::Protocol)?;
        let field = &tail[..end];
        if !name(field) {
            return Err(S3Error::Protocol);
        }
        let tail = &tail[end + 1..];
        let closing = format!("</{field}>");
        let end = tail.find(&closing).ok_or(S3Error::Protocol)?;
        let value = decode(&tail[..end])?;
        if fields.insert(field.to_owned(), value).is_some() {
            return Err(S3Error::Protocol);
        }
        text = &tail[end + closing.len()..];
    }
}

pub(super) fn required<'a>(
    fields: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str, S3Error> {
    fields
        .get(name)
        .map(String::as_str)
        .ok_or(S3Error::Protocol)
}

pub(super) fn target(
    fields: &BTreeMap<String, String>,
    bucket: &str,
    key: &str,
) -> Result<(), S3Error> {
    if required(fields, "Bucket")? != bucket || required(fields, "Key")? != key {
        return Err(S3Error::Binding);
    }
    Ok(())
}

fn escape(value: &str, out: &mut Vec<u8>) -> Result<(), S3Error> {
    if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        return Err(S3Error::Protocol);
    }
    for c in value.chars() {
        match c {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '>' => out.extend_from_slice(b"&gt;"),
            '"' => out.extend_from_slice(b"&quot;"),
            '\'' => out.extend_from_slice(b"&apos;"),
            _ => {
                let mut bytes = [0; 4];
                out.extend_from_slice(c.encode_utf8(&mut bytes).as_bytes());
            }
        }
    }
    Ok(())
}

pub(super) fn completion_bound(parts: usize) -> Result<usize, S3Error> {
    if !(1..=10_000).contains(&parts) {
        return Err(S3Error::Limit);
    }
    // Worst-case opaque ETag escaping (6 bytes per input byte), fixed checksum,
    // part number and markup. Bound is checked before allocation.
    parts
        .checked_mul(6400)
        .and_then(|n| n.checked_add(256))
        .ok_or(S3Error::Limit)
}

pub(super) fn completion(parts: &[PartReceipt]) -> Result<Vec<u8>, S3Error> {
    let bound = completion_bound(parts.len())?;
    let mut out = Vec::with_capacity(bound);
    out.extend_from_slice(
        b"<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    for (index, part) in parts.iter().enumerate() {
        if part.index != index as u64 {
            return Err(S3Error::Binding);
        }
        out.extend_from_slice(b"<Part><PartNumber>");
        out.extend_from_slice((index + 1).to_string().as_bytes());
        out.extend_from_slice(b"</PartNumber><ETag>");
        escape(&part.etag.0, &mut out)?;
        out.extend_from_slice(b"</ETag><ChecksumSHA256>");
        out.extend_from_slice(signing::base64(&part.content_digest.bytes()).as_bytes());
        out.extend_from_slice(b"</ChecksumSHA256></Part>");
    }
    out.extend_from_slice(b"</CompleteMultipartUpload>");
    if out.len() > bound {
        return Err(S3Error::Limit);
    }
    Ok(out)
}

pub(super) fn composite_checksum<'a>(
    parts: impl ExactSizeIterator<Item = &'a PartReceipt>,
) -> String {
    let count = parts.len();
    let mut bytes = Vec::with_capacity(count * 32);
    for part in parts {
        bytes.extend_from_slice(&part.content_digest.bytes());
    }
    format!(
        "{}-{}",
        signing::base64(&ContentDigest::sha256(&bytes).bytes()),
        count
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use fss_object::multipart::ETag;

    #[test]
    fn success_is_exact_and_error_or_ambiguous_xml_refuses() {
        let good = br#" <?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>archive</Bucket><Key>a&amp;b</Key><UploadId>a+/=</UploadId></InitiateMultipartUploadResult> "#;
        let fields = response(good, "InitiateMultipartUploadResult").unwrap();
        target(&fields, "archive", "a&b").unwrap();
        assert_eq!(required(&fields, "UploadId").unwrap(), "a+/=");
        for bad in [
            "<Error><Code>InternalError</Code></Error>",
            "<CompleteMultipartUploadResult><ETag>x</ETag><ETag>y</ETag></CompleteMultipartUploadResult>",
            "<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///secret'>]><CompleteMultipartUploadResult/>",
            "<CompleteMultipartUploadResult><Key><Inner>x</Inner></Key></CompleteMultipartUploadResult>",
            "<CompleteMultipartUploadResult xmlns='urn:other'></CompleteMultipartUploadResult>",
            "<CompleteMultipartUploadResult></CompleteMultipartUploadResult><Error></Error>",
        ] {
            assert!(response(bad.as_bytes(), "CompleteMultipartUploadResult").is_err());
        }
    }

    #[test]
    fn completion_has_consecutive_parts_opaque_etags_and_composite_digest() {
        let parts = vec![PartReceipt {
            index: 0,
            content_digest: ContentDigest::sha256(b"abc"),
            etag: ETag("\"opaque&token\"".into()),
        }];
        let body = String::from_utf8(completion(&parts).unwrap()).unwrap();
        assert!(body.contains("<PartNumber>1</PartNumber>"));
        assert!(body.contains("<ETag>&quot;opaque&amp;token&quot;</ETag>"));
        assert!(body.contains(
            "<ChecksumSHA256>ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=</ChecksumSHA256>"
        ));
        assert!(composite_checksum(parts.iter()).ends_with("-1"));
        let mut invalid = parts;
        invalid[0].index = 1;
        assert!(completion(&invalid).is_err());
    }
}
