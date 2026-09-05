#![forbid(unsafe_code)]
//! Deterministic process-level rehearsal of the reference hydration catalog.

use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::io::{self, Write};

use fss_core::{
    BudgetVector, Completeness, ContentDigest, ContractBasis, HandleAvailability, HydrationArtifact,
    HydrationError, HydrationLevel, HydrationPurpose, HydrationRequest, HydrationRequestSpec,
    HydrationResponse, LaboratoryAccess, LedgerAnchor, SemanticHandle, SemanticHandleSpec,
    SessionId, TimestampNs,
};
use fss_reference::ReferenceHydrationCatalog;

const SCENARIOS: [&str; 6] = [
    "success",
    "budget-fallback",
    "privacy-denied",
    "expired",
    "h4-denied",
    "h4-qualified",
];

fn main() {
    if let Err(error) = run() {
        eprintln!("fss-hydration-rehearsal: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let scenario = match args.next().as_deref() {
        None => "all".to_owned(),
        Some("--scenario") => args.next().ok_or("--scenario requires a value")?,
        Some(value) => value.to_owned(),
    };
    if args.next().is_some() {
        return Err("unexpected trailing arguments".into());
    }
    let selected: Vec<&str> = if scenario == "all" {
        SCENARIOS.to_vec()
    } else if SCENARIOS.contains(&scenario.as_str()) {
        vec![scenario.as_str()]
    } else {
        return Err("unknown scenario; expected success, budget-fallback, privacy-denied, expired, h4-denied, h4-qualified, or all".into());
    };
    let records = selected.into_iter().map(rehearse).collect::<Result<Vec<_>, _>>()?;
    let mut stdout = io::stdout().lock();
    for record in records {
        writeln!(stdout, "{record}")?;
    }
    Ok(())
}

fn rehearse(scenario: &str) -> Result<String, Box<dyn Error>> {
    let (catalog, handle) = fixture()?;
    let level = match scenario {
        "success" => HydrationLevel::H2,
        "budget-fallback" => HydrationLevel::H3,
        "h4-denied" | "h4-qualified" => HydrationLevel::H4,
        _ => HydrationLevel::H1,
    };
    let request = HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:hydration-rehearsal")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: level,
        allow_lower_level: scenario == "budget-fallback",
        available_capabilities: handle.required_capabilities.values().flatten().cloned().collect(),
        authorized_privacy_classes: if scenario == "privacy-denied" {
            BTreeSet::new()
        } else {
            BTreeSet::from([handle.privacy_class.clone()])
        },
        budget: cost(if scenario == "budget-fallback" { HydrationLevel::H1 } else { level }),
        purpose: if scenario == "h4-qualified" {
            HydrationPurpose::Qualification
        } else {
            HydrationPurpose::Routine
        },
        continuation: None,
        issued_at: TimestampNs(10),
    })?;
    let now = if scenario == "expired" { TimestampNs(100) } else { TimestampNs(20) };
    let result = catalog.hydrate(&request, now);
    let expected_error = match scenario {
        "privacy-denied" => Some(HydrationError::PrivacyDenied),
        "h4-denied" => Some(HydrationError::LaboratoryGrantRequired),
        _ => None,
    };
    match (result, expected_error) {
        (Err(error), Some(expected)) if error == expected => {
            Ok(denied_record(scenario, &handle, &request, &error))
        }
        (Err(error), _) => Err(error.into()),
        (Ok(_), Some(_)) => Err("expected disclosure refusal did not occur".into()),
        (Ok(response), None) => {
            response.validate_for(&request, &handle)?;
            let expected_level = match scenario {
                "expired" => None,
                "budget-fallback" => Some(HydrationLevel::H1),
                _ => Some(level),
            };
            if response.receipt.delivered_level != expected_level {
                return Err("unexpected delivered hydration level".into());
            }
            Ok(success_record(scenario, &handle, &request, &response))
        }
    }
}

fn fixture() -> Result<(ReferenceHydrationCatalog, SemanticHandle), HydrationError> {
    let levels = BTreeSet::from([
        HydrationLevel::H0,
        HydrationLevel::H1,
        HydrationLevel::H2,
        HydrationLevel::H3,
        HydrationLevel::H4,
    ]);
    let mut anchor = LedgerAnchor::genesis("site:hydration-rehearsal");
    anchor.commit_sequence = 1;
    let handle = SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: ContractBasis::from_registry_bytes(
            b"schemas", b"operations", b"views", b"capabilities", b"errors", b"costs",
            "fss-hydration-rehearsal:2", None,
        ),
        anchor,
        subject_id: "evidence:hydration-rehearsal".to_owned(),
        subject_digest: ContentDigest::sha256(b"synthetic redacted rehearsal subject"),
        semantic_type: "evidence_bundle".to_owned(),
        source_id: "sensor:hydration-rehearsal".to_owned(),
        capture_interval: None,
        spatial_scope: Some("zone:reference".to_owned()),
        privacy_class: "private:property".to_owned(),
        applied_transform: Some("redaction:reference:v1".to_owned()),
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(100),
        required_capabilities: levels.iter().map(|level| {
            (*level, BTreeSet::from([format!("capability:hydrate:h{}", level.ordinal())]))
        }).collect(),
        estimated_costs: levels.iter().map(|level| (*level, cost(*level))).collect(),
        levels,
        laboratory_access: LaboratoryAccess::QualificationOrDebugGrant,
        debug_capability: Some("capability:hydrate:debug".to_owned()),
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })?;
    let mut catalog = ReferenceHydrationCatalog::new();
    catalog.register_descriptor(handle.clone())?;
    for level in &handle.levels {
        let artifact = HydrationArtifact::publish(
            *level,
            "application/fss+json",
            format!("synthetic {} evidence", level.as_str()).into_bytes(),
            [handle.subject_digest],
            Completeness::Complete,
            handle.applied_transform.clone(),
        )?;
        catalog.register_artifact(&handle.handle_id, handle.descriptor_digest, artifact)?;
    }
    Ok((catalog, handle))
}

fn cost(level: HydrationLevel) -> BudgetVector {
    let scale = 1_u64 << level.ordinal();
    BudgetVector {
        latency_ms: 5 * scale,
        tokens: 32 * scale,
        bytes: 256 * scale,
        cpu_millis: scale,
        storage_operations: 1,
        privacy_exposure: f64::from(level.ordinal()) / 10.0,
        ..BudgetVector::default()
    }
}

fn success_record(
    scenario: &str,
    handle: &SemanticHandle,
    request: &HydrationRequest,
    response: &HydrationResponse,
) -> String {
    let receipt = &response.receipt;
    let outcome = if response.artifact.is_some() { "ok" } else { "typed_unavailable" };
    // All text values below come from the closed scenario set and fixed portable fixture IDs.
    format!(
        "{{\"schema\":\"fss.hydration_rehearsal.v1\",\"scenario\":\"{scenario}\",\"outcome\":\"{outcome}\",\"handleId\":\"{}\",\"descriptorDigest\":\"{}\",\"subjectDigest\":\"{}\",\"requestDigest\":\"{}\",\"receiptDigest\":\"{}\",\"availability\":\"{}\",\"requestedLevel\":\"{}\",\"deliveredLevel\":{},\"artifactDigest\":{},\"continuationDigest\":{},\"completeness\":\"{}\",\"serviceTimeNs\":{},\"reproduction\":\"cargo run -q -p fss-cli --bin fss-hydration-rehearsal -- --scenario {scenario}\"}}",
        handle.handle_id, handle.descriptor_digest, handle.subject_digest,
        request.request_digest, receipt.receipt_digest, receipt.availability.as_str(),
        request.requested_level.as_str(),
        receipt.delivered_level.map_or_else(|| "null".to_owned(), |value| format!("\"{}\"", value.as_str())),
        optional_digest(receipt.artifact_digest),
        optional_digest(receipt.continuation.as_ref().map(|cursor| cursor.cursor_digest)),
        completeness(receipt.completeness), receipt.issued_at.0,
    )
}

fn denied_record(
    scenario: &str,
    handle: &SemanticHandle,
    request: &HydrationRequest,
    error: &HydrationError,
) -> String {
    format!(
        "{{\"schema\":\"fss.hydration_rehearsal.v1\",\"scenario\":\"{scenario}\",\"outcome\":\"denied\",\"handleId\":\"{}\",\"descriptorDigest\":\"{}\",\"requestDigest\":\"{}\",\"requestedLevel\":\"{}\",\"error\":\"{}\",\"artifactDigest\":null,\"continuationDigest\":null}}",
        handle.handle_id, handle.descriptor_digest, request.request_digest,
        request.requested_level.as_str(), error.code(),
    )
}

fn optional_digest(digest: Option<ContentDigest>) -> String {
    digest.map_or_else(|| "null".to_owned(), |value| format!("\"{value}\""))
}

fn completeness(value: Completeness) -> &'static str {
    match value {
        Completeness::Complete => "complete",
        Completeness::Bounded => "bounded",
        Completeness::Partial => "partial",
        Completeness::Unknown => "unknown",
        Completeness::NotObservable => "not_observable",
        Completeness::Unauthorized => "unauthorized",
        Completeness::Stale => "stale",
    }
}
