#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::fmt::Write as _;

use fss_core::{
    BudgetVector, CanonicalEncode, Completeness, ContentDigest, ContinuationCursor,
    ContinuationScope, ContractBasis, HYDRATION_VIEW_ID, HandleAvailability, HydrationArtifact,
    HydrationLevel, HydrationPurpose, HydrationReceipt, HydrationReceiptSpec, HydrationRequest,
    HydrationRequestSpec, HydrationResponse, LaboratoryAccess, LedgerAnchor, SemanticHandle,
    SemanticHandleSpec, SessionId, TimestampNs,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("fss-hydration-rehearsal: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let scenario = env::args().nth(1).unwrap_or_else(|| "all".to_owned());
    match scenario.as_str() {
        "success" => println!("{}", success_record()?),
        "expired" => println!("{}", expired_record()?),
        "all" => {
            println!("{}", success_record()?);
            println!("{}", expired_record()?);
        }
        _ => {
            return Err(format!(
                "unknown scenario {scenario:?}; expected success, expired, or all"
            )
            .into());
        }
    }
    Ok(())
}

fn success_record() -> Result<String, Box<dyn Error>> {
    let handle = handle(TimestampNs(10_000))?;
    let request = request(&handle, HydrationLevel::H1, TimestampNs(20))?;
    let artifact = HydrationArtifact::publish(
        HydrationLevel::H1,
        "application/fss+json",
        b"bounded semantic synopsis".to_vec(),
        [handle.subject_digest],
        Completeness::Complete,
        None,
    )?;
    let continuation = ContinuationCursor::publish(
        ContinuationScope::EvidenceHydration,
        handle.handle_id.clone(),
        handle.contract_basis.clone(),
        request.session_id.clone(),
        HYDRATION_VIEW_ID,
        handle.anchor.clone(),
        handle.anchor.clone(),
        handle.ladder_policy_digest(),
        2,
        3,
        artifact.artifact_digest,
        None,
        request.issued_at,
        TimestampNs(1_000),
    )?;
    let mut proof_roots = artifact.proof_roots.clone();
    proof_roots.insert(artifact.artifact_digest);
    let receipt = HydrationReceipt::publish(HydrationReceiptSpec {
        request_digest: request.request_digest,
        handle_id: handle.handle_id.clone(),
        descriptor_digest: handle.descriptor_digest,
        subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: request.requested_level,
        delivered_level: Some(HydrationLevel::H1),
        availability: HandleAvailability::Available,
        cost: handle
            .estimated_cost(HydrationLevel::H1)
            .ok_or("missing H1 cost")?,
        completeness: Completeness::Complete,
        artifact_digest: Some(artifact.artifact_digest),
        proof_roots,
        continuation: Some(continuation.clone()),
        invalidators: BTreeSet::from([
            format!("descriptor:{}", handle.descriptor_digest),
            "retention-expiry".to_owned(),
        ]),
        issued_at: request.issued_at,
    })?;
    let response = HydrationResponse {
        artifact: Some(artifact),
        receipt,
    };
    response.validate_for(&request, &handle)?;
    let cursor_digest = continuation.canonical_digest("fss.hydration_rehearsal_cursor.v1");
    Ok(record(
        "success",
        "ok",
        &handle,
        &request,
        &response.receipt,
        response
            .artifact
            .as_ref()
            .map(|value| value.artifact_digest),
        Some(cursor_digest),
    ))
}

fn expired_record() -> Result<String, Box<dyn Error>> {
    let handle = handle(TimestampNs(100))?;
    let request = request(&handle, HydrationLevel::H1, TimestampNs(101))?;
    let receipt = HydrationReceipt::publish(HydrationReceiptSpec {
        request_digest: request.request_digest,
        handle_id: handle.handle_id.clone(),
        descriptor_digest: handle.descriptor_digest,
        subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: request.requested_level,
        delivered_level: None,
        availability: HandleAvailability::Expired,
        cost: BudgetVector::default(),
        completeness: Completeness::Stale,
        artifact_digest: None,
        proof_roots: BTreeSet::from([handle.descriptor_digest]),
        continuation: None,
        invalidators: BTreeSet::from(["retention-expired".to_owned()]),
        issued_at: request.issued_at,
    })?;
    let response = HydrationResponse {
        artifact: None,
        receipt,
    };
    response.validate_for(&request, &handle)?;
    Ok(record(
        "expired",
        "typed_unavailable",
        &handle,
        &request,
        &response.receipt,
        None,
        None,
    ))
}

fn handle(retention_until: TimestampNs) -> Result<SemanticHandle, Box<dyn Error>> {
    let levels = BTreeSet::from([HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2]);
    let required_capabilities = BTreeMap::from([
        (
            HydrationLevel::H0,
            BTreeSet::from(["capability:hydrate:h0".to_owned()]),
        ),
        (
            HydrationLevel::H1,
            BTreeSet::from(["capability:hydrate:h1".to_owned()]),
        ),
        (
            HydrationLevel::H2,
            BTreeSet::from(["capability:hydrate:h2".to_owned()]),
        ),
    ]);
    let estimated_costs = BTreeMap::from([
        (
            HydrationLevel::H0,
            BudgetVector {
                latency_ms: 5,
                tokens: 32,
                bytes: 256,
                cpu_millis: 1,
                ..BudgetVector::default()
            },
        ),
        (
            HydrationLevel::H1,
            BudgetVector {
                latency_ms: 10,
                tokens: 128,
                bytes: 1_024,
                cpu_millis: 2,
                privacy_exposure: 0.1,
                ..BudgetVector::default()
            },
        ),
        (
            HydrationLevel::H2,
            BudgetVector {
                latency_ms: 20,
                tokens: 256,
                bytes: 4_096,
                cpu_millis: 4,
                privacy_exposure: 0.2,
                ..BudgetVector::default()
            },
        ),
    ]);
    Ok(SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: basis(),
        anchor: anchor(),
        subject_id: "evidence:hydration-rehearsal".to_owned(),
        subject_digest: ContentDigest::sha256(b"hydration rehearsal subject"),
        semantic_type: "evidence_bundle".to_owned(),
        source_id: "sensor:hydration-rehearsal".to_owned(),
        capture_interval: None,
        spatial_scope: Some("zone:rear".to_owned()),
        privacy_class: "private:property".to_owned(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        retention_until,
        levels,
        required_capabilities,
        estimated_costs,
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })?)
}

fn request(
    handle: &SemanticHandle,
    level: HydrationLevel,
    issued_at: TimestampNs,
) -> Result<HydrationRequest, Box<dyn Error>> {
    Ok(HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:hydration-rehearsal")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: level,
        allow_lower_level: false,
        available_capabilities: BTreeSet::from([
            "capability:hydrate:h0".to_owned(),
            "capability:hydrate:h1".to_owned(),
            "capability:hydrate:h2".to_owned(),
        ]),
        authorized_privacy_classes: BTreeSet::from(["private:property".to_owned()]),
        budget: handle.estimated_cost(level).ok_or("missing level cost")?,
        purpose: HydrationPurpose::IncidentAdjudication,
        continuation: None,
        issued_at,
    })?)
}

fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(
        b"schemas",
        b"operations",
        b"views",
        b"capabilities",
        b"errors",
        b"costs",
        "fss-hydration-rehearsal:1",
        None,
    )
}

fn anchor() -> LedgerAnchor {
    let mut anchor = LedgerAnchor::genesis("site:hydration-rehearsal");
    anchor.commit_sequence = 1;
    anchor
}

#[allow(clippy::too_many_arguments)]
fn record(
    scenario: &str,
    outcome: &str,
    handle: &SemanticHandle,
    request: &HydrationRequest,
    receipt: &HydrationReceipt,
    artifact_digest: Option<ContentDigest>,
    continuation_digest: Option<ContentDigest>,
) -> String {
    let mut output = String::new();
    write!(
        output,
        "{{\"schema\":\"fss.hydration_rehearsal.v1\",\"scenario\":\"{}\",\"outcome\":\"{}\",\"handleId\":\"{}\",\"descriptorDigest\":\"{}\",\"subjectDigest\":\"{}\",\"requestDigest\":\"{}\",\"receiptDigest\":\"{}\",\"availability\":\"{}\",\"requestedLevel\":\"{}\",\"deliveredLevel\":{},\"artifactDigest\":{},\"continuationDigest\":{},\"reproduction\":\"cargo run -q -p fss-cli --bin fss-hydration-rehearsal -- {}\"}}",
        json_escape(scenario),
        json_escape(outcome),
        json_escape(&handle.handle_id),
        handle.descriptor_digest,
        handle.subject_digest,
        request.request_digest,
        receipt.receipt_digest,
        receipt.availability.as_str(),
        receipt.requested_level.as_str(),
        optional_level(receipt.delivered_level),
        optional_digest(artifact_digest),
        optional_digest(continuation_digest),
        json_escape(scenario),
    )
    .expect("writing to String cannot fail");
    output
}

fn optional_level(level: Option<HydrationLevel>) -> String {
    level.map_or_else(
        || "null".to_owned(),
        |value| format!("\"{}\"", value.as_str()),
    )
}

fn optional_digest(digest: Option<ContentDigest>) -> String {
    digest.map_or_else(|| "null".to_owned(), |value| format!("\"{value}\""))
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                write!(escaped, "\\u{:04x}", u32::from(character))
                    .expect("writing to String cannot fail");
            }
            character => escaped.push(character),
        }
    }
    escaped
}
