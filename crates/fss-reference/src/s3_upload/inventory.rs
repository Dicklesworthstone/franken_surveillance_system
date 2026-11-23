#![forbid(unsafe_code)]
//! Positive, bounded ListParts evidence for one previously dispatched part.
//!
//! An absent part is never evidence that its write failed. Only an untruncated
//! inventory containing every dispatched intention can restore active knowledge.

use std::collections::BTreeMap;

use fss_core::ContentDigest;
use fss_object::multipart::{ETag, PartReceipt, UploadId};

use super::{S3Error, signing, xml};

pub(super) const MAX_PARTS: usize = 1000;

struct ObservedPart {
    index: u64,
    size: u64,
    checksum: String,
    etag: String,
}

fn integer(value: &str) -> Result<u64, S3Error> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(S3Error::Protocol);
    }
    value.parse().map_err(|_| S3Error::Protocol)
}

fn part(bytes: &[u8]) -> Result<ObservedPart, S3Error> {
    let fields = xml::response(bytes, "Part")?;
    if fields.keys().any(|field| {
        !matches!(
            field.as_str(),
            "PartNumber" | "Size" | "ChecksumSHA256" | "ETag" | "LastModified"
        )
    }) {
        return Err(S3Error::Protocol);
    }
    let number = integer(xml::required(&fields, "PartNumber")?)?;
    if !(1..=10_000).contains(&number) {
        return Err(S3Error::Protocol);
    }
    let etag = xml::required(&fields, "ETag")?;
    if etag.is_empty() || etag.len() > 1024 || etag.chars().any(char::is_control) {
        return Err(S3Error::Protocol);
    }
    let checksum = xml::required(&fields, "ChecksumSHA256")?;
    if checksum.len() != 44 {
        return Err(S3Error::Protocol);
    }
    Ok(ObservedPart {
        index: number - 1,
        size: integer(xml::required(&fields, "Size")?)?,
        checksum: checksum.to_owned(),
        etag: etag.to_owned(),
    })
}

/// A strict response can be inconclusive. None never authorizes a retry or
/// establishes absence, abortion or completion of the upload.
pub(super) fn verify(
    bytes: &[u8],
    bucket: &str,
    key: &str,
    upload: &UploadId,
    intended: &BTreeMap<u64, (u64, ContentDigest)>,
    acknowledged: &BTreeMap<u64, PartReceipt>,
) -> Result<Option<Vec<PartReceipt>>, S3Error> {
    if intended.is_empty() || intended.len() > MAX_PARTS {
        return Err(S3Error::Limit);
    }
    let mut text = xml::body(bytes, "ListPartsResult")?;
    let mut fields = BTreeMap::new();
    let mut parts = Vec::new();
    loop {
        text = text.trim_start_matches(xml::space);
        if text.is_empty() {
            break;
        }
        let opening = text.strip_prefix('<').ok_or(S3Error::Protocol)?;
        let end = opening.find('>').ok_or(S3Error::Protocol)?;
        let field = &opening[..end];
        if !xml::name(field) {
            return Err(S3Error::Protocol);
        }
        let tail = &opening[end + 1..];
        let closing = format!("</{field}>");
        let value_end = tail.find(&closing).ok_or(S3Error::Protocol)?;
        let element_len = end + 2 + value_end + closing.len();
        let element = &text[..element_len];
        if field == "Part" {
            if parts.len() >= MAX_PARTS {
                return Err(S3Error::Limit);
            }
            let observed = part(element.as_bytes())?;
            if parts
                .last()
                .is_some_and(|previous: &ObservedPart| previous.index >= observed.index)
            {
                return Err(S3Error::Protocol);
            }
            parts.push(observed);
        } else {
            if fields.len() >= 16 || fields.contains_key(field) {
                return Err(S3Error::Protocol);
            }
            let value = match field {
                "Owner" | "Initiator" => {
                    let identity = xml::response(element.as_bytes(), field)?;
                    if identity
                        .keys()
                        .any(|name| !matches!(name.as_str(), "ID" | "DisplayName"))
                        || xml::required(&identity, "ID")?.is_empty()
                    {
                        return Err(S3Error::Protocol);
                    }
                    // Provider account labels are not authority or part proof.
                    String::new()
                }
                "Bucket" | "Key" | "UploadId" | "PartNumberMarker"
                | "NextPartNumberMarker" | "MaxParts" | "IsTruncated"
                | "ChecksumAlgorithm" | "ChecksumType" | "StorageClass" => {
                    xml::decode(&tail[..value_end])?
                }
                _ => return Err(S3Error::Protocol),
            };
            fields.insert(field.to_owned(), value);
        }
        text = &text[element_len..];
    }
    if xml::required(&fields, "Bucket")? != bucket
        || xml::required(&fields, "Key")? != key
        || xml::required(&fields, "UploadId")? != upload.0
        || xml::required(&fields, "ChecksumAlgorithm")? != "SHA256"
        || xml::required(&fields, "ChecksumType")? != "COMPOSITE"
    {
        return Ok(None);
    }
    let truncated = match xml::required(&fields, "IsTruncated")? {
        "false" => false,
        "true" => true,
        _ => return Err(S3Error::Protocol),
    };
    let marker = integer(xml::required(&fields, "PartNumberMarker")?)?;
    let max_parts = integer(xml::required(&fields, "MaxParts")?)?;
    let next_marker = fields
        .get("NextPartNumberMarker")
        .map(|value| integer(value))
        .transpose()?;
    let last_number = parts.last().map_or(0, |part| part.index + 1);
    if truncated
        || marker != 0
        || max_parts != MAX_PARTS as u64
        || next_marker.is_some_and(|marker| marker != 0 && marker != last_number)
        || parts.len() != intended.len()
    {
        return Ok(None);
    }
    let mut receipts = Vec::with_capacity(parts.len());
    for observed in parts {
        let Some(&(size, digest)) = intended.get(&observed.index) else {
            return Ok(None);
        };
        if size != observed.size || signing::base64(&digest.bytes()) != observed.checksum {
            return Ok(None);
        }
        let receipt = PartReceipt {
            index: observed.index,
            content_digest: digest,
            etag: ETag(observed.etag),
        };
        if acknowledged
            .get(&receipt.index)
            .is_some_and(|known| known != &receipt)
        {
            return Ok(None);
        }
        receipts.push(receipt);
    }
    // Retain this check independently of the adapter's restoration validation.
    // An alleged full inventory cannot erase any already acknowledged part.
    if acknowledged.values().any(|known| {
        receipts
            .binary_search_by_key(&known.index, |part| part.index)
            .ok()
            .and_then(|index| receipts.get(index))
            != Some(known)
    }) {
        return Ok(None);
    }
    Ok(Some(receipts))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn row(index: u64, bytes: &[u8], etag: &str) -> String {
        format!(
            "<Part><PartNumber>{}</PartNumber><Size>{}</Size><ChecksumSHA256>{}</ChecksumSHA256><ETag>{etag}</ETag></Part>",
            index + 1,
            bytes.len(),
            signing::base64(&ContentDigest::sha256(bytes).bytes()),
        )
    }

    fn response(rows: &str) -> String {
        format!(
            "<ListPartsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>archive</Bucket><Key>a&amp;b</Key><UploadId>owned/+upload=</UploadId><PartNumberMarker>0</PartNumberMarker><MaxParts>1000</MaxParts><IsTruncated>false</IsTruncated><ChecksumAlgorithm>SHA256</ChecksumAlgorithm><ChecksumType>COMPOSITE</ChecksumType><Owner><ID>owner</ID></Owner><Initiator><ID>initiator</ID><DisplayName>fixture</DisplayName></Initiator>{rows}</ListPartsResult>"
        )
    }

    fn intended() -> BTreeMap<u64, (u64, ContentDigest)> {
        [
            (0, (3, ContentDigest::sha256(b"abc"))),
            (1, (3, ContentDigest::sha256(b"def"))),
        ]
        .into_iter()
        .collect()
    }

    fn checked(bytes: &str) -> Result<Option<Vec<PartReceipt>>, S3Error> {
        let acknowledged = [(
            0,
            PartReceipt {
                index: 0,
                content_digest: ContentDigest::sha256(b"abc"),
                etag: ETag("\"known\"".into()),
            },
        )]
        .into_iter()
        .collect();
        verify(
            bytes.as_bytes(),
            "archive",
            "a&b",
            &UploadId("owned/+upload=".into()),
            &intended(),
            &acknowledged,
        )
    }

    #[test]
    fn positive_inventory_preserves_known_receipts_and_recovers_only_exact_dispatched_bytes() {
        let body =
            response(&(row(0, b"abc", "&quot;known&quot;") + &row(1, b"def", "pending")));
        let receipt = checked(&body).unwrap().unwrap();
        assert_eq!(receipt.len(), 2);
        assert_eq!(receipt[0].etag.0, "\"known\"");
        assert_eq!(receipt[1].content_digest, ContentDigest::sha256(b"def"));
        assert_eq!(receipt[1].etag.0, "pending");
    }

    #[test]
    fn incomplete_wrong_identity_or_changed_known_part_never_authorizes_resume() {
        let first = row(0, b"abc", "&quot;known&quot;");
        let body = response(&(first.clone() + &row(1, b"def", "pending")));
        for bad in [
            response(&first),
            response(""),
            response(&(first.clone() + &row(2, b"def", "pending"))),
            response(&(first.clone() + &row(1, b"xyz", "pending"))),
            response(&(row(0, b"abc", "changed") + &row(1, b"def", "pending"))),
            body.replace("<Size>3</Size>", "<Size>4</Size>"),
            body.replace("<Bucket>archive</Bucket>", "<Bucket>other</Bucket>"),
            body.replace("<Key>a&amp;b</Key>", "<Key>other</Key>"),
            body.replace("owned/+upload=", "another-upload"),
            body.replace("<IsTruncated>false", "<IsTruncated>true"),
            body.replace("<PartNumberMarker>0", "<PartNumberMarker>1"),
            body.replace("<MaxParts>1000", "<MaxParts>1"),
            body.replace("<ChecksumType>COMPOSITE", "<ChecksumType>FULL_OBJECT"),
            body.replace("<ChecksumAlgorithm>SHA256", "<ChecksumAlgorithm>SHA1"),
        ] {
            assert!(checked(&bad).unwrap().is_none(), "accepted {bad}");
        }
    }

    #[test]
    fn ambiguous_nested_duplicate_or_noncanonical_inventory_refuses() {
        let first = row(0, b"abc", "&quot;known&quot;");
        let second = row(1, b"def", "pending");
        let body = response(&(first.clone() + &second));
        for bad in [
            response(&(second + &first)),
            response(&(first.clone() + &first)),
            body.replace("<Size>3</Size>", "<Size>3</Size><Size>3</Size>"),
            body.replace("<Size>3</Size>", "<Size>03</Size>"),
            body.replace("<PartNumber>1", "<PartNumber>0"),
            body.replace("<PartNumber>1", "<PartNumber>10001"),
            body.replace("<ETag>pending", "<ETag><Inner>pending</Inner>"),
            body.replace("<Key>a&amp;b</Key>", &format!("<Key>a&amp;b{first}</Key>")),
            body.replace("<IsTruncated>false", "<IsTruncated>0"),
            body.replace(
                "<MaxParts>1000</MaxParts>",
                "<MaxParts>1000</MaxParts><MaxParts>1000</MaxParts>",
            ),
            body.replace(
                "<Owner><ID>owner</ID></Owner>",
                "<Owner><ID><Part>hidden</Part></ID></Owner>",
            ),
            body.clone() + "<Error></Error>",
            "<!DOCTYPE x>".to_owned() + &body,
        ] {
            assert!(checked(&bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn inventory_count_is_bounded_before_retaining_extra_parts() {
        let rows: String = (0..=MAX_PARTS as u64)
            .map(|index| row(index, b"abc", "token"))
            .collect();
        assert_eq!(checked(&response(&rows)), Err(S3Error::Limit));
    }
}
