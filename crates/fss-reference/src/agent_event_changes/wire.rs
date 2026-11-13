#![forbid(unsafe_code)]
//! A lossless comparison of native canonical event JSON values; no numeric parser is used.

use std::collections::BTreeMap;

use super::*;

// Every existing EventHypothesis JSON key is covered. A future native shape change refuses
// this projection until its policy is explicitly updated; it cannot silently omit a field.
const FIELDS: [&str; 14] = [
    "decisionPath",
    "eventId",
    "evidence",
    "kind",
    "modelReceipts",
    "probability",
    "revision",
    "schema",
    "state",
    "supersedes",
    "timeInterval",
    "trackIds",
    "uncertaintyReason",
    "zoneIds",
];

fn invalid() -> EventChangesError {
    failure(EventChangesErrorKind::InvalidRecord)
}

/// Split trusted, locally emitted canonical JSON at its top-level field boundaries. This is
/// not an external JSON decoder. Exact integer/float lexemes and complete nested values stay
/// untouched, including quoted brackets, commas, control escapes and non-ASCII prose.
fn fields(json: &str) -> Result<BTreeMap<&'static str, &str>, EventChangesError> {
    let bytes = json.as_bytes();
    if bytes.first() != Some(&b'{') || bytes.last() != Some(&b'}') {
        return Err(invalid());
    }
    let mut offset = 1;
    let mut result = BTreeMap::new();
    while offset < bytes.len() - 1 {
        if bytes.get(offset) != Some(&b'"') {
            return Err(invalid());
        }
        offset += 1;
        let name_start = offset;
        while bytes.get(offset).is_some_and(|byte| *byte != b'"') {
            offset += 1;
        }
        let key = json.get(name_start..offset).ok_or_else(invalid)?;
        let key = FIELDS
            .iter()
            .copied()
            .find(|field| *field == key)
            .ok_or_else(invalid)?;
        offset += 1;
        if bytes.get(offset) != Some(&b':') {
            return Err(invalid());
        }
        offset += 1;
        let start = offset;
        let mut nesting = 0usize;
        let mut quoted = false;
        let mut escaped = false;
        while offset < bytes.len() {
            let byte = bytes[offset];
            if quoted {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quoted = false;
                }
            } else {
                match byte {
                    b'"' => quoted = true,
                    b'[' | b'{' => nesting = nesting.checked_add(1).ok_or_else(invalid)?,
                    b']' | b'}' if nesting > 0 => nesting -= 1,
                    b',' | b'}' if nesting == 0 => break,
                    _ => {}
                }
            }
            offset += 1;
        }
        if quoted || escaped || nesting != 0 || start == offset || offset >= bytes.len() {
            return Err(invalid());
        }
        let value = json.get(start..offset).ok_or_else(invalid)?;
        if result.insert(key, value).is_some() {
            return Err(invalid());
        }
        match bytes[offset] {
            b',' => offset += 1,
            b'}' if offset == bytes.len() - 1 => break,
            _ => return Err(invalid()),
        }
    }
    if result.len() != FIELDS.len() || FIELDS.iter().any(|field| !result.contains_key(field)) {
        return Err(invalid());
    }
    Ok(result)
}

fn quote(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ch if ch < ' ' => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

pub(super) fn build(
    from: &EventHypothesis,
    to: &EventHypothesis,
    from_publication: (ContentDigest, u64),
    to_publication: (ContentDigest, u64),
    anchor_token: &str,
) -> Result<EventChangesReport, EventChangesError> {
    let before = from.to_canonical_json();
    let after = to.to_canonical_json();
    if before
        .len()
        .checked_add(after.len())
        .is_none_or(|bytes| bytes > MAX_EVENT_CHANGES_REPORT_BYTES)
    {
        return Err(failure(EventChangesErrorKind::BudgetExceeded));
    }
    let before_fields = fields(&before)?;
    let after_fields = fields(&after)?;
    let mut changes = Vec::new();
    for field in FIELDS {
        let old = before_fields.get(field).ok_or_else(invalid)?;
        let new = after_fields.get(field).ok_or_else(invalid)?;
        if old != new {
            changes.push(EventFieldChange {
                field,
                before: (*old).to_owned(),
                after: (*new).to_owned(),
            });
        }
    }
    let policy = ContentDigest::sha256(EVENT_CHANGES_POLICY.as_bytes());
    let mut encoder = CanonicalEncoder::new();
    encoder.text(EVENT_CHANGES_DIGEST_DOMAIN);
    encoder.u32(1);
    encoder.digest(policy);
    encoder.text(anchor_token);
    for (event, (root, sequence)) in [(from, from_publication), (to, to_publication)] {
        encoder.digest(root);
        encoder.u64(sequence);
        encoder.digest(event.revision_digest());
        event.encode_canonical(&mut encoder);
    }
    encoder.u64(changes.len() as u64);
    for change in &changes {
        encoder.text(change.field());
        encoder.text(change.before_json());
        encoder.text(change.after_json());
    }
    let digest = ContentDigest::sha256(&encoder.finish());
    let record = |event: &EventHypothesis, raw: &str, publication: (ContentDigest, u64)| {
        format!(
            "{{\"commitSequence\":\"{}\",\"publicationRoot\":\"{}\",\"revision\":{},\"revisionDigest\":\"{}\"}}",
            publication.1,
            publication.0,
            raw,
            event.revision_digest()
        )
    };
    let json = format!(
        "{{\"anchorToken\":{},\"changes\":[{}],\"comparisonDigest\":\"{}\",\"from\":{},\"policyDigest\":\"{}\",\"question\":\"what_changed\",\"schema\":\"{}\",\"to\":{}}}",
        quote(anchor_token),
        changes
            .iter()
            .map(EventFieldChange::to_json)
            .collect::<Vec<_>>()
            .join(","),
        digest,
        record(from, &before, from_publication),
        policy,
        EVENT_CHANGES_SCHEMA,
        record(to, &after, to_publication)
    );
    if json.len() > MAX_EVENT_CHANGES_REPORT_BYTES {
        return Err(failure(EventChangesErrorKind::BudgetExceeded));
    }
    Ok(EventChangesReport {
        from: from.clone(),
        to: to.clone(),
        from_root: from_publication.0,
        to_root: to_publication.0,
        from_sequence: from_publication.1,
        to_sequence: to_publication.1,
        changes,
        digest,
        json,
    })
}
