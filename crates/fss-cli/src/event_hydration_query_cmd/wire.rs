#![forbid(unsafe_code)]
//! Exact JSON interchange for existing hydration contracts. No request grants are decoded.

use std::collections::BTreeMap;

use fss_core::{
    BudgetVector, ContentDigest, ContinuationCursor, ContinuationCursorPublishParams,
    ContinuationScope, HydrationArtifact, HydrationReceipt, HydrationRequest, LedgerAnchor,
    SemanticHandle, SessionId, TimestampNs,
};

use crate::agent_json;
use crate::json_input::{Value, parse};
use crate::json_output::{object, string, strings};

pub(super) const MAX_CURSOR_BYTES: usize = 16 * 1024;

fn hydration_budget(value: &BudgetVector) -> String {
    // The native hydration schemas predate the ordinary envelope spelling and use a lowercase
    // j. Preserve both registered interchange spellings without changing the canonical vector.
    agent_json::budget(value).replace("\"energyMilliJoules\":", "\"energyMillijoules\":")
}

fn digest(value: ContentDigest) -> String {
    string(&value.to_text())
}

fn optional_digest(value: Option<ContentDigest>) -> String {
    value.map_or_else(|| "null".to_owned(), digest)
}

fn optional_cursor(value: Option<&ContinuationCursor>) -> String {
    value.map_or_else(|| "null".to_owned(), cursor)
}

fn exact_anchor(value: &LedgerAnchor) -> String {
    // The ordinary presentation places this epoch in its privacy projection. Hydration
    // interchange must carry it with the anchor to reproduce the native descriptor/cursor.
    let mut output = agent_json::evidence_anchor(value);
    output.pop();
    output.push_str(&format!(",\"privacyEpoch\":{}}}", value.privacy_epoch));
    output
}

pub(super) fn cursor(value: &ContinuationCursor) -> String {
    object(&[
        ("schema", string("fss.agent_continuation_cursor.v1")),
        ("cursorId", string(&value.cursor_id)),
        ("scope", string(value.scope.as_str())),
        ("streamId", string(&value.stream_id)),
        (
            "contractBasis",
            agent_json::contract_basis(&value.contract_basis),
        ),
        ("sessionId", string(value.session_id.as_str())),
        ("viewId", string(&value.view_id)),
        ("basisAnchor", exact_anchor(&value.basis_anchor)),
        ("resumeAnchor", exact_anchor(&value.resume_anchor)),
        ("selectionWitness", digest(value.selection_witness)),
        ("position", value.position.to_string()),
        ("highWaterMark", value.upper_bound.to_string()),
        ("sourceDigest", digest(value.source_digest)),
        (
            "previousCursorDigest",
            optional_digest(value.predecessor_digest),
        ),
        ("issuedAtNs", value.issued_at.0.to_string()),
        ("expiresAtNs", value.expires_at.0.to_string()),
        ("cursorDigest", digest(value.cursor_digest)),
    ])
}

fn field<'a>(fields: &'a BTreeMap<String, Value>, name: &str) -> Result<&'a Value, ()> {
    fields.get(name).ok_or(())
}

fn text<'a>(fields: &'a BTreeMap<String, Value>, name: &str) -> Result<&'a str, ()> {
    field(fields, name)?.text().ok_or(())
}

fn number<T>(fields: &BTreeMap<String, Value>, name: &str) -> Result<T, ()>
where
    T: std::str::FromStr + ToString,
{
    let Value::Number(value) = field(fields, name)? else {
        return Err(());
    };
    let parsed = value.parse::<T>().map_err(|_| ())?;
    if parsed.to_string() != *value {
        return Err(());
    }
    Ok(parsed)
}

fn read_digest(fields: &BTreeMap<String, Value>, name: &str) -> Result<ContentDigest, ()> {
    let value = text(fields, name)?;
    let digest = ContentDigest::parse(value).map_err(|_| ())?;
    if digest.to_text() != value {
        return Err(());
    }
    Ok(digest)
}

fn anchor(value: &Value) -> Result<LedgerAnchor, ()> {
    let fields = value.object().ok_or(())?;
    let anchor = LedgerAnchor {
        site_lineage: text(fields, "deploymentId")?.to_owned(),
        ledger_epoch: number(fields, "observationEpoch")?,
        commit_sequence: number(fields, "capsuleSequence")?,
        state_root: read_digest(fields, "authorityRoot")?,
        schema_epoch: number(fields, "schemaEpoch")?,
        policy_epoch: number(fields, "policyEpoch")?,
        adapter_registry_epoch: number(fields, "adapterEpoch")?,
        privacy_epoch: number(fields, "privacyEpoch")?,
    };
    // The exact registered deployment projection also binds null generations and explicit
    // not-applicable sentinels. Reject extra fields or caller-selected device scope.
    if parse(&exact_anchor(&anchor)).map_err(|_| ())? != *value {
        return Err(());
    }
    Ok(anchor)
}

/// Decode one complete native cursor, preserving exact integers and all proof fields.
pub(super) fn parse_cursor(input: &str) -> Result<ContinuationCursor, ()> {
    if input.is_empty() || input.len() > MAX_CURSOR_BYTES {
        return Err(());
    }
    let value = parse(input).map_err(|_| ())?;
    let fields = value.object().ok_or(())?;
    if text(fields, "schema")? != "fss.agent_continuation_cursor.v1"
        || text(fields, "scope")? != "evidence_hydration"
        || text(fields, "viewId")? != fss_core::hydration::HYDRATION_VIEW_ID
    {
        return Err(());
    }
    let basis = fss_core::reference_contract_basis();
    if *field(fields, "contractBasis")?
        != parse(&agent_json::contract_basis(&basis)).map_err(|_| ())?
    {
        return Err(());
    }
    let predecessor_digest = match field(fields, "previousCursorDigest")? {
        Value::Null => None,
        _ => Some(read_digest(fields, "previousCursorDigest")?),
    };
    let cursor = ContinuationCursor::publish(ContinuationCursorPublishParams {
        scope: ContinuationScope::EvidenceHydration,
        stream_id: text(fields, "streamId")?.to_owned(),
        contract_basis: basis,
        session_id: SessionId::parse(text(fields, "sessionId")?).map_err(|_| ())?,
        view_id: text(fields, "viewId")?.to_owned(),
        basis_anchor: anchor(field(fields, "basisAnchor")?)?,
        resume_anchor: anchor(field(fields, "resumeAnchor")?)?,
        source_digest: read_digest(fields, "sourceDigest")?,
        position: number(fields, "position")?,
        upper_bound: number(fields, "highWaterMark")?,
        selection_witness: read_digest(fields, "selectionWitness")?,
        predecessor_digest,
        issued_at: TimestampNs(number(fields, "issuedAtNs")?),
        expires_at: TimestampNs(number(fields, "expiresAtNs")?),
    })
    .map_err(|_| ())?;
    // Re-rendering enforces the full closed shape, exact identity/digest and integer spelling.
    // Runtime custody and durable issuance/consumption admission remain native responsibilities.
    if parse(&self::cursor(&cursor)).map_err(|_| ())? != value {
        return Err(());
    }
    Ok(cursor)
}

pub(super) fn descriptor(value: &SemanticHandle) -> String {
    let capabilities: Vec<_> = value
        .required_capabilities
        .iter()
        .map(|(level, set)| (level.as_str(), strings(set.iter())))
        .collect();
    let costs: Vec<_> = value
        .estimated_costs
        .iter()
        .map(|(level, cost)| (level.as_str(), hydration_budget(cost)))
        .collect();
    object(&[
        ("schema", string(SemanticHandle::SCHEMA)),
        ("handleId", string(&value.handle_id)),
        ("descriptorDigest", digest(value.descriptor_digest)),
        (
            "contractBasis",
            agent_json::contract_basis(&value.contract_basis),
        ),
        ("anchor", exact_anchor(&value.anchor)),
        ("subjectId", string(&value.subject_id)),
        ("subjectDigest", digest(value.subject_digest)),
        ("semanticType", string(&value.semantic_type)),
        ("sourceId", string(&value.source_id)),
        (
            "captureInterval",
            value.capture_interval.as_ref().map_or_else(
                || "null".to_owned(),
                |interval| {
                    object(&[
                        ("earliestNs", interval.earliest.0.to_string()),
                        ("latestNs", interval.latest.0.to_string()),
                    ])
                },
            ),
        ),
        (
            "spatialScope",
            agent_json::optional_string(value.spatial_scope.as_deref()),
        ),
        ("privacyClass", string(&value.privacy_class)),
        (
            "appliedTransform",
            agent_json::optional_string(value.applied_transform.as_deref()),
        ),
        ("availability", string(value.availability.as_str())),
        ("retentionUntilNs", value.retention_until.0.to_string()),
        (
            "levels",
            strings(value.levels.iter().map(|level| level.as_str())),
        ),
        ("requiredCapabilities", object(&capabilities)),
        ("estimatedCosts", object(&costs)),
        ("laboratoryAccess", string(value.laboratory_access.as_str())),
        (
            "debugCapability",
            agent_json::optional_string(value.debug_capability.as_deref()),
        ),
        (
            "derivativeHandles",
            strings(value.derivative_handles.iter()),
        ),
        ("publishedAtNs", value.published_at.0.to_string()),
    ])
}

pub(super) fn request(value: &HydrationRequest) -> String {
    object(&[
        ("schema", string("fss.semantic_hydration_request.v1")),
        ("requestId", string(&value.request_id)),
        ("requestDigest", digest(value.request_digest)),
        (
            "contractBasis",
            agent_json::contract_basis(&value.contract_basis),
        ),
        ("sessionId", string(value.session_id.as_str())),
        ("handleId", string(&value.handle_id)),
        (
            "expectedDescriptorDigest",
            digest(value.expected_descriptor_digest),
        ),
        (
            "expectedSubjectDigest",
            digest(value.expected_subject_digest),
        ),
        ("anchor", exact_anchor(&value.anchor)),
        ("requestedLevel", string(value.requested_level.as_str())),
        ("allowLowerLevel", value.allow_lower_level.to_string()),
        (
            "availableCapabilities",
            strings(value.available_capabilities.iter()),
        ),
        (
            "authorizedPrivacyClasses",
            strings(value.authorized_privacy_classes.iter()),
        ),
        ("budget", hydration_budget(&value.budget)),
        ("purpose", string(value.purpose.as_str())),
        ("continuation", optional_cursor(value.continuation.as_ref())),
        ("issuedAtNs", value.issued_at.0.to_string()),
    ])
}

pub(super) fn receipt(value: &HydrationReceipt) -> String {
    object(&[
        ("schema", string("fss.semantic_hydration_receipt.v1")),
        ("receiptId", string(&value.receipt_id)),
        ("receiptDigest", digest(value.receipt_digest)),
        ("requestDigest", digest(value.request_digest)),
        ("handleId", string(&value.handle_id)),
        ("descriptorDigest", digest(value.descriptor_digest)),
        ("subjectDigest", digest(value.subject_digest)),
        ("anchor", exact_anchor(&value.anchor)),
        ("requestedLevel", string(value.requested_level.as_str())),
        (
            "deliveredLevel",
            value
                .delivered_level
                .map_or_else(|| "null".to_owned(), |level| string(level.as_str())),
        ),
        ("availability", string(value.availability.as_str())),
        ("cost", hydration_budget(&value.cost)),
        ("completeness", string(value.completeness.as_str())),
        ("artifactDigest", optional_digest(value.artifact_digest)),
        ("proofRoots", agent_json::digests(value.proof_roots.iter())),
        ("continuation", optional_cursor(value.continuation.as_ref())),
        ("invalidators", strings(value.invalidators.iter())),
        ("issuedAtNs", value.issued_at.0.to_string()),
    ])
}

fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(ALPHABET[usize::from(first >> 2)]));
        output.push(char::from(
            ALPHABET[usize::from((first & 3) << 4 | second >> 4)],
        ));
        output.push(if chunk.len() > 1 {
            char::from(ALPHABET[usize::from((second & 15) << 2 | third >> 6)])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(ALPHABET[usize::from(third & 63)])
        } else {
            '='
        });
    }
    output
}

pub(super) fn artifact(value: &HydrationArtifact) -> String {
    object(&[
        ("schema", string("fss.semantic_hydration_artifact.v1")),
        ("level", string(value.level.as_str())),
        ("contentType", string(&value.content_type)),
        ("payloadBase64", string(&base64(&value.payload))),
        ("payloadDigest", digest(value.payload_digest)),
        ("proofRoots", agent_json::digests(value.proof_roots.iter())),
        ("completeness", string(value.completeness.as_str())),
        (
            "appliedTransform",
            agent_json::optional_string(value.applied_transform.as_deref()),
        ),
        ("artifactDigest", digest(value.artifact_digest)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_bytes_use_rfc4648_without_loss() {
        for (bytes, expected) in [
            (b"".as_slice(), ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foobar", "Zm9vYmFy"),
            (&[0, 255, 128], "AP+A"),
        ] {
            assert_eq!(base64(bytes), expected);
        }
    }

    #[test]
    fn exact_cursor_round_trip_preserves_large_integers_and_privacy_epoch()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut anchor = LedgerAnchor::genesis("site:hydration-wire");
        anchor.commit_sequence = 9_007_199_254_740_993;
        anchor.privacy_epoch = 17;
        let original = ContinuationCursor::publish(ContinuationCursorPublishParams {
            scope: ContinuationScope::EvidenceHydration,
            stream_id: "semantic-handle:wire".to_owned(),
            contract_basis: fss_core::reference_contract_basis(),
            session_id: SessionId::parse("session:hydration-wire")?,
            view_id: fss_core::hydration::HYDRATION_VIEW_ID.to_owned(),
            basis_anchor: anchor.clone(),
            resume_anchor: anchor,
            source_digest: ContentDigest::sha256(b"exact hydration descriptor"),
            position: 1,
            upper_bound: 2,
            selection_witness: ContentDigest::sha256(b"exact hydration ladder"),
            predecessor_digest: None,
            issued_at: TimestampNs(9_007_199_254_740_993),
            expires_at: TimestampNs(9_007_199_254_740_993_000),
        })?;
        let encoded = cursor(&original);
        assert_eq!(
            parse_cursor(&encoded).map_err(|()| "cursor refused")?,
            original
        );
        for changed in [
            encoded.replace("\"privacyEpoch\":17", "\"privacyEpoch\":18"),
            encoded.replace(",\"privacyEpoch\":17", ""),
            encoded.replace("\"position\":1", "\"position\":1e0"),
            encoded.replace("\"position\":1", "\"position\":\"1\""),
            encoded.replacen("{", "{\"grant\":\"CAP-READ-MEDIA-001\",", 1),
            encoded.replacen("\"position\":1", "\"position\":1,\"position\":1", 1),
            format!("{encoded} null"),
        ] {
            assert!(parse_cursor(&changed).is_err());
        }
        assert!(parse_cursor(&" ".repeat(MAX_CURSOR_BYTES + 1)).is_err());
        Ok(())
    }
}
