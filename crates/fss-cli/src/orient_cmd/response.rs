#![forbid(unsafe_code)]
//! Validated `AgentResponseEnvelope` builders and per-operation privacy projections shared across
//! CLI agent commands.

use fss_core::{
    AgentResponseEnvelope, AgentView, Completeness, ContentDigest, ContractBasisError,
    ExecutionBoundary, KnowledgeState, LedgerAnchor, PrincipalId, ResponseOutcome,
    ResponseSafeRetry, ResponseTaskState,
};
use fss_reference::agent_orient::ORIENT_DATA_CLASSES;

use super::diagnostics::RenderError;
use crate::agent_json;

/// The privacy projection every orient/explain answer is served under, at the anchor's privacy
/// epoch.
pub(super) fn privacy_projection(anchor: &LedgerAnchor) -> agent_json::PrivacyProjection {
    agent_json::PrivacyProjection {
        purpose: "read-only agent read of a local reference deployment".to_owned(),
        policy_generation_id: format!("privacy-epoch:{}", anchor.privacy_epoch),
        visible_domains: ORIENT_DATA_CLASSES
            .iter()
            .map(|class| (*class).to_owned())
            .collect(),
        redacted_domains: vec!["media-payloads".to_owned()],
    }
}

/// Everything that differs between one response and another; the rest is fixed per command.
pub(crate) struct ResponseParts {
    pub(crate) operation: &'static str,
    pub(crate) request_digest: ContentDigest,
    pub(crate) principal: PrincipalId,
    pub(crate) session_id: Option<String>,
    pub(crate) mission_id: Option<String>,
    pub(crate) anchor: LedgerAnchor,
    pub(crate) view: AgentView,
    pub(crate) capability: &'static str,
    pub(crate) outcome: ResponseOutcome,
    pub(crate) error_id: Option<&'static str>,
    pub(crate) payload_schema: &'static str,
    pub(crate) payload_json: String,
    pub(crate) epistemic_state: KnowledgeState,
    pub(crate) completeness: Completeness,
    pub(crate) warnings: Vec<String>,
    pub(crate) contradictions: Vec<String>,
    pub(crate) degradation: Vec<String>,
    pub(crate) budgets_json: String,
    pub(crate) proof_pointers: Vec<String>,
    /// Affordance identities, in order.
    pub(crate) affordances: Vec<String>,
    /// Their registered `agent_affordance.v1` objects, in the same order.
    pub(crate) affordance_objects: Vec<String>,
    pub(crate) decision_fingerprint: ContentDigest,
    pub(crate) compression_receipt_id: Option<String>,
    pub(crate) continuation: Option<String>,
    pub(crate) recovery_class: &'static str,
    pub(crate) safe_retry: ResponseSafeRetry,
    pub(crate) boundary: ExecutionBoundary,
    pub(crate) created_at_ns: i128,
    /// Durable workspace revision the answer is bound to (agent-session commands only).
    pub(crate) workspace_revision: Option<u64>,
    /// Idempotency identity of a durable agent-plane write (agent-session commands only).
    pub(crate) idempotency_key: Option<String>,
}

pub(crate) fn build_response(parts: ResponseParts) -> Result<String, Box<dyn std::error::Error>> {
    build_response_with_resnapshot(parts, false)
}

pub(crate) fn build_response_with_resnapshot(
    parts: ResponseParts,
    resnapshot_required: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    build_response_for_basis(
        parts,
        resnapshot_required,
        fss_core::reference_contract_basis(),
    )
}

/// The additive retained-probe response profile never changes another operation's basis.
pub(crate) fn build_probe_response(
    parts: ResponseParts,
) -> Result<String, Box<dyn std::error::Error>> {
    if parts.operation != "investigate"
        || !matches!(parts.view, AgentView::Case | AgentView::Forensic)
        || parts.payload_schema != fss_core::AgentCognitiveEnvelopeV2::SCHEMA
    {
        return Err(RenderError("invalid admitted probe response profile").into());
    }
    build_response_for_basis(
        parts,
        false,
        fss_core::contract_basis::probe_contract_basis(),
    )
}

fn build_response_for_basis(
    parts: ResponseParts,
    resnapshot_required: bool,
    basis: fss_core::ContractBasis,
) -> Result<String, Box<dyn std::error::Error>> {
    let privacy = privacy_projection(&parts.anchor).envelope_json();
    build_response_for_basis_and_privacy(parts, resnapshot_required, basis, privacy)
}

/// The footage query additionally exposes verified import and capsule metadata. Keep this
/// explicit projection local to that target instead of broadening every agent read.
pub(crate) fn build_footage_response(
    parts: ResponseParts,
) -> Result<String, Box<dyn std::error::Error>> {
    if parts.operation != "query"
        || parts.view != AgentView::Case
        || parts.payload_schema != fss_core::AgentCognitiveEnvelope::SCHEMA
    {
        return Err(RenderError("invalid footage query response profile").into());
    }
    let mut projection = privacy_projection(&parts.anchor);
    projection.purpose = "read-only agent query of retained recorded-file metadata".to_owned();
    projection.visible_domains.extend([
        "retained-import-metadata".to_owned(),
        "sensor-capsule-metadata".to_owned(),
    ]);
    build_response_for_basis_and_privacy(
        parts,
        false,
        fss_core::reference_contract_basis(),
        projection.envelope_json(),
    )
}

/// Redacted vendor-metadata projection scoped to the exact ONVIF query target.
pub(crate) fn build_onvif_response(
    parts: ResponseParts,
) -> Result<String, Box<dyn std::error::Error>> {
    if parts.operation != "query"
        || parts.view != AgentView::Case
        || parts.payload_schema != fss_core::AgentCognitiveEnvelope::SCHEMA
    {
        return Err(RenderError("invalid ONVIF query response profile").into());
    }
    let mut projection = privacy_projection(&parts.anchor);
    projection.purpose =
        "read-only redacted query of exact retained ONVIF vendor metadata".to_owned();
    projection.visible_domains.extend([
        "onvif-source-publication-metadata".to_owned(),
        "onvif-vendor-analysis-redacted-semantics".to_owned(),
        "operator-declared-raw-coordinate-zone-policy".to_owned(),
    ]);
    build_response_for_basis_and_privacy(
        parts,
        false,
        fss_core::reference_contract_basis(),
        projection.envelope_json(),
    )
}

/// Sampled QSR metadata requires independent internal source-verification consent.
pub(crate) fn build_qsr_response(
    parts: ResponseParts,
) -> Result<String, Box<dyn std::error::Error>> {
    if parts.operation != "query"
        || parts.view != AgentView::Case
        || parts.payload_schema != fss_core::AgentCognitiveEnvelope::SCHEMA
        || parts.capability != fss_core::RuntimeGrant::AgentQuery.as_str()
    {
        return Err(RenderError("invalid QSR query response profile").into());
    }
    let mut projection = privacy_projection(&parts.anchor);
    projection.purpose =
        "read-only sampled QSR query with explicitly authorized source verification".to_owned();
    projection.visible_domains.extend([
        "retained-screened-package-zone-metadata".to_owned(),
        "sampled-qsr-count-presence-dwell-lane-metadata".to_owned(),
        "historical-screening-and-mask-boundaries".to_owned(),
    ]);
    build_response_for_basis_privacy_and_capabilities(
        parts,
        false,
        fss_core::reference_contract_basis(),
        projection.envelope_json(),
        vec![
            fss_core::RuntimeGrant::AgentQuery.as_str().to_owned(),
            fss_core::RuntimeGrant::ReadMedia.as_str().to_owned(),
        ],
    )
}

/// Matched detector track metadata requires independent source-verification consent.
pub(crate) fn build_tracks_response(
    parts: ResponseParts,
) -> Result<String, Box<dyn std::error::Error>> {
    if parts.operation != "query"
        || parts.view != AgentView::Case
        || parts.payload_schema != fss_core::AgentCognitiveEnvelope::SCHEMA
        || parts.capability != fss_core::RuntimeGrant::AgentQuery.as_str()
    {
        return Err(RenderError("invalid tracks query response profile").into());
    }
    let mut projection = privacy_projection(&parts.anchor);
    projection.purpose =
        "read-only retained detector tracks with explicitly authorized source verification"
            .to_owned();
    projection.visible_domains.extend([
        "retained-package-detection-metadata".to_owned(),
        "matched-track-observation-metadata".to_owned(),
        "model-recipe-and-source-continuity-metadata".to_owned(),
    ]);
    build_response_for_basis_privacy_and_capabilities(
        parts,
        false,
        fss_core::reference_contract_basis(),
        projection.envelope_json(),
        vec![
            fss_core::RuntimeGrant::AgentQuery.as_str().to_owned(),
            fss_core::RuntimeGrant::ReadMedia.as_str().to_owned(),
        ],
    )
}

/// Event metadata hydration discloses only H0/H1 under both live session grants.
/// Its existing session journal records charges and cursors; it has no media/effect grant.
pub(crate) fn build_event_hydration_response(
    parts: ResponseParts,
) -> Result<String, Box<dyn std::error::Error>> {
    use fss_reference::deployment_session::evidence_hydration::{
        EVIDENCE_HYDRATION_CAPABILITY, EVIDENCE_QUERY_CAPABILITY, EvidenceHydrationAnswer,
    };
    if parts.operation != "query"
        || !matches!(parts.view, AgentView::Case | AgentView::Forensic)
        || parts.payload_schema != EvidenceHydrationAnswer::SCHEMA
        || parts.capability != EVIDENCE_HYDRATION_CAPABILITY
    {
        return Err(RenderError("invalid event evidence hydration response profile").into());
    }
    let mut projection = privacy_projection(&parts.anchor);
    projection.purpose = "session-authorized retained event metadata hydration".to_owned();
    projection.visible_domains.extend([
        "retained-event-identity-and-semantic-synopsis".to_owned(),
        "event-evidence-provenance-and-disclosure-receipt".to_owned(),
    ]);
    // Required intent is not effective authority on refusal. A payload-free response must
    // not advertise the grants of a session whose principal or stored scope was rejected.
    let capabilities = if parts.payload_json == "null" {
        projection.purpose =
            "payload-free hydration refusal at a historical metadata observation".to_owned();
        projection.visible_domains.clear();
        projection
            .redacted_domains
            .push("all-requested-event-evidence".to_owned());
        Vec::new()
    } else {
        vec![
            EVIDENCE_QUERY_CAPABILITY.to_owned(),
            EVIDENCE_HYDRATION_CAPABILITY.to_owned(),
        ]
    };
    build_response_for_basis_privacy_and_capabilities(
        parts,
        false,
        fss_core::hydration_contract_basis(),
        projection.envelope_json(),
        capabilities,
    )
}

/// Retained report discovery discloses metadata under AgentQuery authority alone.
pub(crate) fn build_report_catalog_response(
    parts: ResponseParts,
) -> Result<String, Box<dyn std::error::Error>> {
    if parts.operation != "query"
        || parts.view != AgentView::Case
        || parts.payload_schema != fss_core::AgentCognitiveEnvelope::SCHEMA
        || parts.capability != fss_core::RuntimeGrant::AgentQuery.as_str()
    {
        return Err(RenderError("invalid report catalogue query response profile").into());
    }
    let mut projection = privacy_projection(&parts.anchor);
    projection.purpose =
        "read-only discovery of retained detector and zone-report metadata".to_owned();
    projection.visible_domains.extend([
        "retained-package-detection-metadata".to_owned(),
        "retained-package-zone-report-metadata".to_owned(),
        "report-publication-and-provenance-metadata".to_owned(),
    ]);
    build_response_for_basis_and_privacy(
        parts,
        false,
        fss_core::reference_contract_basis(),
        projection.envelope_json(),
    )
}

/// Retained source discovery discloses metadata under AgentQuery authority alone.
pub(crate) fn build_sources_response(
    parts: ResponseParts,
) -> Result<String, Box<dyn std::error::Error>> {
    if parts.operation != "query"
        || parts.view != AgentView::Case
        || parts.payload_schema != fss_core::AgentCognitiveEnvelope::SCHEMA
        || parts.capability != fss_core::RuntimeGrant::AgentQuery.as_str()
    {
        return Err(RenderError("invalid sources query response profile").into());
    }
    let mut projection = privacy_projection(&parts.anchor);
    projection.purpose =
        "read-only inventory of retained source metadata and historical continuity".to_owned();
    projection.visible_domains.extend([
        "retained-sensor-and-stream-capsule-metadata".to_owned(),
        "historical-source-continuity-and-health-metadata".to_owned(),
        "source-import-and-deletion-inventory".to_owned(),
    ]);
    build_response_for_basis_and_privacy(
        parts,
        false,
        fss_core::reference_contract_basis(),
        projection.envelope_json(),
    )
}

/// Retained localization discovery projects existing metadata under AgentQuery authority.
pub(crate) fn build_localizations_response(
    parts: ResponseParts,
) -> Result<String, Box<dyn std::error::Error>> {
    if parts.operation != "query"
        || parts.view != AgentView::Case
        || parts.payload_schema != fss_core::AgentCognitiveEnvelope::SCHEMA
        || parts.capability != fss_core::RuntimeGrant::AgentQuery.as_str()
    {
        return Err(RenderError("invalid localizations query response profile").into());
    }
    let mut projection = privacy_projection(&parts.anchor);
    projection.purpose =
        "read-only discovery of retained localization recipe and receipt metadata".to_owned();
    projection.visible_domains.extend([
        "retained-localization-recipe-and-receipt-metadata".to_owned(),
        "localization-publication-and-source-custody-metadata".to_owned(),
        "declared-twin-and-atlas-identity-pins".to_owned(),
    ]);
    build_response_for_basis_and_privacy(
        parts,
        false,
        fss_core::reference_contract_basis(),
        projection.envelope_json(),
    )
}

/// Explicit privacy projection for native archive metadata, scoped to AOP-005 only.
pub(crate) fn build_recording_response(
    parts: ResponseParts,
) -> Result<String, Box<dyn std::error::Error>> {
    if parts.operation != "query"
        || parts.view != AgentView::Case
        || parts.payload_schema != fss_core::AgentCognitiveEnvelope::SCHEMA
    {
        return Err(RenderError("invalid recording query response profile").into());
    }
    let mut projection = privacy_projection(&parts.anchor);
    projection.purpose = "read-only agent query of pinned native recording metadata".to_owned();
    projection.visible_domains.extend([
        "native-recording-catalog-metadata".to_owned(),
        "native-recording-window-metadata".to_owned(),
    ]);
    build_response_for_basis_and_privacy(
        parts,
        false,
        fss_core::reference_contract_basis(),
        projection.envelope_json(),
    )
}

/// UTC recording queries additionally disclose the explicitly pinned clock companion metadata.
/// This profile does not broaden the existing decode-clock recording response.
pub(crate) fn build_recording_utc_response(
    parts: ResponseParts,
) -> Result<String, Box<dyn std::error::Error>> {
    if parts.operation != "query"
        || parts.view != AgentView::Case
        || parts.payload_schema != fss_core::AgentCognitiveEnvelope::SCHEMA
    {
        return Err(RenderError("invalid UTC recording query response profile").into());
    }
    let mut projection = privacy_projection(&parts.anchor);
    projection.purpose =
        "read-only agent query of pinned native recording and clock metadata".to_owned();
    projection.visible_domains.extend([
        "native-recording-catalog-metadata".to_owned(),
        "native-recording-window-metadata".to_owned(),
        "native-recording-clock-metadata".to_owned(),
    ]);
    build_response_for_basis_and_privacy(
        parts,
        false,
        fss_core::reference_contract_basis(),
        projection.envelope_json(),
    )
}

/// Source-verified recorder assertions remain private metadata; original media stays redacted.
/// This profile is separate from catalog and retained node-clock metadata queries.
pub(crate) fn build_recording_replay_response(
    parts: ResponseParts,
) -> Result<String, Box<dyn std::error::Error>> {
    build_recording_replay_response_profile(parts, false)
}

/// Current import metadata is visible only in the explicit imported recorder query profile.
pub(crate) fn build_retained_recording_replay_response(
    parts: ResponseParts,
) -> Result<String, Box<dyn std::error::Error>> {
    build_recording_replay_response_profile(parts, true)
}

fn build_recording_replay_response_profile(
    parts: ResponseParts,
    retained: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    if parts.operation != "query"
        || parts.view != AgentView::Case
        || parts.payload_schema != fss_core::AgentCognitiveEnvelope::SCHEMA
        || parts.capability != fss_core::RuntimeGrant::AgentQuery.as_str()
    {
        return Err(RenderError("invalid recorder UTC query response profile").into());
    }
    let mut projection = privacy_projection(&parts.anchor);
    projection.purpose =
        "read-only recorder UTC query with explicitly authorized source verification".to_owned();
    projection.visible_domains.extend([
        "native-replay-receipt-metadata".to_owned(),
        "native-recording-window-metadata".to_owned(),
        "source-verified-recorder-time-assertions".to_owned(),
    ]);
    if retained {
        projection.visible_domains.extend([
            "retained-import-metadata".to_owned(),
            "retained-original-custody-metadata".to_owned(),
        ]);
    }
    build_response_for_basis_privacy_and_capabilities(
        parts,
        false,
        fss_core::reference_contract_basis(),
        projection.envelope_json(),
        vec![
            fss_core::RuntimeGrant::AgentQuery.as_str().to_owned(),
            fss_core::RuntimeGrant::ReadMedia.as_str().to_owned(),
        ],
    )
}

fn build_response_for_basis_and_privacy(
    parts: ResponseParts,
    resnapshot_required: bool,
    basis: fss_core::ContractBasis,
    privacy: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let capabilities = vec![parts.capability.to_owned()];
    build_response_for_basis_privacy_and_capabilities(
        parts,
        resnapshot_required,
        basis,
        privacy,
        capabilities,
    )
}

fn build_response_for_basis_privacy_and_capabilities(
    parts: ResponseParts,
    resnapshot_required: bool,
    basis: fss_core::ContractBasis,
    privacy: String,
    capabilities: Vec<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let payload_digest = ContentDigest::sha256(parts.payload_json.as_bytes());
    let short = parts.request_digest.to_text();
    let hex = short.split_once(':').map_or(short.as_str(), |(_, hex)| hex);
    let envelope = AgentResponseEnvelope::new(
        basis,
        parts.operation,
        format!("request:{}:{hex}", parts.operation),
        1,
        parts.principal.as_str(),
        parts.session_id,
        parts.mission_id,
        format!("trace:{}:{hex}", parts.operation),
        parts.anchor,
        None,
        parts.workspace_revision,
        parts.view,
        capabilities,
        privacy,
        parts.outcome,
        None,
        Some(ResponseTaskState::None),
        parts.error_id.map(ToOwned::to_owned),
        parts.payload_schema,
        parts.payload_json,
        payload_digest,
        parts.epistemic_state,
        parts.completeness,
        parts.warnings,
        parts.contradictions,
        parts.degradation,
        parts.budgets_json,
        parts.proof_pointers,
        parts.affordances,
        parts.decision_fingerprint,
        parts.compression_receipt_id,
        None,
        parts.continuation,
        parts.idempotency_key,
        parts.recovery_class,
        parts.safe_retry,
        resnapshot_required,
        parts.boundary,
        parts.created_at_ns,
    )?;
    envelope.validate().map_err(ContractBasisError::Contract)?;
    agent_json::response_envelope(&envelope, &parts.affordance_objects)
        .ok_or_else(|| RenderError("affordance objects do not match the envelope").into())
}
