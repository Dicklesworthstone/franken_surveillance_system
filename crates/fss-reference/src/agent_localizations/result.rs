#![forbid(unsafe_code)]
//! Exact native continuation and metadata projection without localization/adoption claims.

use super::*;
use crate::agent_follow::snapshot_anchor_token;
use crate::agent_orient::DeploymentSnapshot;
use crate::agent_orient::historical_health::{HistoricalHealthDeletion, HistoricalHealthMetadata};
use crate::retained_source::RetainedReadUsage;
use fss_core::{
    AgentQueryPlan, AgentView, ContinuationCursor, ContinuationEntry, ContinuationPage,
    ContinuationScope, ContinuationStream, ContinuationStreamPublishParams, EnvelopeCoverage,
    EnvelopeEpistemic, EnvelopeProposition, KnowledgeState, MissionId, QueryCompletenessRequested,
    QueryInterpretation, QueryReadReceipt, SessionId, TimestampNs, admit_query_read,
    reference_contract_basis,
};

/// One page after the complete bounded current localization index has been verified.
#[derive(Clone, Debug, PartialEq)]
pub struct DeploymentLocalizationsQuery {
    filter: LocalizationsQueryFilter,
    /// Complete unfiltered protected metadata, including historical health and deletion scope.
    pub snapshot: DeploymentSnapshot,
    /// Registered AOP-005 inactive-localization metadata plan.
    pub plan: AgentQueryPlan,
    /// Native metadata admission, without media or effect authority.
    pub admission: QueryReadReceipt,
    /// Exact current authority and effect-prefix token.
    pub anchor_token: String,
    /// Exact scope and consumed cursor identity.
    pub request_digest: ContentDigest,
    /// Complete native index and unfiltered protected diagnostic witness.
    pub selection_witness: ContentDigest,
    /// Exact admitted page and continuation fingerprint.
    pub decision_digest: ContentDigest,
    /// Deterministic ephemeral session; this read persists no session.
    pub session_id: SessionId,
    /// Deterministic localization-discovery mission.
    pub mission_id: MissionId,
    /// All currently retracted package slots, independently of filters/page size.
    pub retracted_localizations: usize,
    /// All current package metadata rows verified before predicates.
    pub scanned_localizations: usize,
    /// Matching package count independently of the returned page size.
    pub matched_localizations: usize,
    /// Native cursor consumed for this page.
    pub cursor: ContinuationCursor,
    /// Exact native page with optional continuation.
    pub page: ContinuationPage,
    /// Rows in canonical package-identity order.
    pub rows: Vec<LocalizationsQueryRow>,
    /// Aggregate metadata bytes and read attempts, including final verification.
    pub read_usage: RetainedReadUsage,
}

impl DeploymentLocalizationsQuery {
    /// Matching retained package rows remaining, never inferred poses or physical observations.
    pub fn remaining_localizations(&self) -> usize {
        self.matched_localizations - (self.cursor.position as usize + self.rows.len())
    }

    /// Exact custody/source metadata facts with replay and physical currency left separate.
    pub fn epistemic(&self) -> EnvelopeEpistemic {
        let mut propositions = vec![
            EnvelopeProposition {
                id: "claim:localizations:selection".to_owned(),
                statement: format!(
                    "Verified metadata for {} current retained inactive localization packages; {} match the exact identity predicates; this page returns {} from position {}; {} remain. {} package slots have current committed retractions and are excluded independently of filters. Metadata admission verifies native recipe/receipt source bindings, current privacy and exact root publication closure. It does not execute the localization or interpret its candidate/abstention outcome.",
                    self.scanned_localizations, self.matched_localizations, self.rows.len(),
                    self.cursor.position, self.remaining_localizations(), self.retracted_localizations,
                ),
                state: KnowledgeState::Known,
                provenance: "derived".to_owned(),
                evidence: vec![self.selection_witness.to_text()],
            },
            EnvelopeProposition {
                id: "claim:localizations:protected-context".to_owned(),
                statement: format!(
                    "The complete unfiltered protected deployment snapshot retains all historical health receipts ({} total), source liveness, coverage and deletion boundaries, including records unrelated to this page. Successful metadata admission and later clean diagnostics do not cancel those findings or establish current camera observability.",
                    self.snapshot.historical_health.len(),
                ),
                state: KnowledgeState::Known,
                provenance: "derived".to_owned(),
                evidence: vec![self.selection_witness.to_text()],
            },
            EnvelopeProposition {
                id: "claim:localizations:physical-currency".to_owned(),
                statement: "Receipt reproduction, source/archive/pixel payload availability, current camera pose, current calibration, adoption and physical coverage are not established. Archive hashes are original pins, not freshness or custody claims for authoring scenes or atlas photographs. Native localization may have returned candidates, insufficient matches or geometric failure; every such retained attempt has the same discovery scope. An empty metadata result certifies no physical absence. This read performs no activation and grants no ReadMedia capability.".to_owned(),
                state: KnowledgeState::Unknown,
                provenance: "derived".to_owned(),
                evidence: Vec::new(),
            },
        ];
        for row in &self.rows {
            propositions.push(EnvelopeProposition {
                id: format!("claim:localizations:{}", hex(row.row_digest())),
                statement: format!("Retained localization metadata: {}", row_json(row)),
                state: KnowledgeState::Known,
                provenance: "derived".to_owned(),
                evidence: vec![
                    row.metadata.package_identity.to_text(),
                    row.metadata.receipt_digest.to_text(),
                    row.metadata.publication_root.to_text(),
                    row.metadata.capsule_digest.to_text(),
                ],
            });
        }
        EnvelopeEpistemic {
            propositions,
            assumptions: vec![
                self.filter.description(),
                "The principal is an audit label, not authentication. This metadata read grants no media disclosure, calibration, activation or effect authority.".to_owned(),
                "Capture intervals and clocks remain the original capsule declarations. One retained exposure is not continuous coverage or current device health.".to_owned(),
                "Native cold replay remains separate work requiring the retained source, decoder, twin and descriptor archives with the complete original recipe. Metadata discovery does not claim those payloads are available.".to_owned(),
                "Historical health, liveness, coverage and deletion findings remain in the complete protected snapshot regardless of the selected sensor, stream, import, twin or page.".to_owned(),
                "Verification is a bounded sequence of observations with live admission, not an atomic filesystem snapshot or a read lease.".to_owned(),
            ],
            invalidators: vec![
                "Any authority/effect prefix, layout, source/privacy/publication metadata, protected diagnostic or deletion change requires a new query.".to_owned(),
                "Changing principal, sensor, stream, import, twin, page size or any read limit invalidates the continuation.".to_owned(),
            ],
        }
    }

    /// Complete bounded current metadata index, distinct from media or physical observability.
    pub fn coverage(&self) -> EnvelopeCoverage {
        let remaining = self.remaining_localizations();
        EnvelopeCoverage {
            authorized_domain: vec!["current committed native localization publication, recipe/receipt source metadata and complete protected deployment metadata".to_owned()],
            observed_domain: vec!["complete bounded inactive-localization metadata index, original source/archive pins and current metadata custody/privacy restrictions".to_owned()],
            not_observable_domain: vec![
                "source media, decoded pixels, twin/atlas archive payload availability, authoring scenes and reference photographs".to_owned(),
                "localization replay, candidate pose correctness, physical identity, presence, absence, current calibration, adoption and physical coverage".to_owned(),
                "retracted package metadata is not returned; current retraction counts and complete protected lifecycle metadata remain unfiltered".to_owned(),
            ],
            omitted_count: remaining as u64,
            omission_reasons: if remaining == 0 { Vec::new() } else {
                vec!["remaining matching inactive-localization rows are available through the exact continuation".to_owned()]
            },
            stop_reason: if remaining == 0 { "committed_index_exhausted" } else { "page_limit" }.to_owned(),
        }
    }
}

fn quote(value: &str) -> String {
    let mut encoded = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            '\t' => encoded.push_str("\\t"),
            character if character < ' ' => {
                encoded.push_str(&format!("\\u{:04x}", character as u32))
            }
            character => encoded.push(character),
        }
    }
    encoded.push('"');
    encoded
}

/// Exact native fields for the existing fss/1 proposition statement.
/// All u64/i128 values are decimal strings to preserve their complete precision in JSON.
pub fn row_json(row: &LocalizationsQueryRow) -> String {
    let m = &row.metadata;
    let a = &m.source_anchor;
    let anchor = format!(
        concat!(
            "{{\"site_lineage\":{},\"ledger_epoch\":{},\"commit_sequence\":{},",
            "\"adapter_registry_epoch\":{},\"schema_epoch\":{},\"policy_epoch\":{},",
            "\"privacy_epoch\":{},\"state_root\":{}}}"
        ),
        quote(&a.site_lineage),
        quote(&a.ledger_epoch.to_string()),
        quote(&a.commit_sequence.to_string()),
        quote(&a.adapter_registry_epoch.to_string()),
        quote(&a.schema_epoch.to_string()),
        quote(&a.policy_epoch.to_string()),
        quote(&a.privacy_epoch.to_string()),
        quote(&a.state_root.to_text()),
    );
    format!(
        concat!(
            "{{\"package_identity\":{},\"receipt_digest\":{},\"publication_root\":{},\"publication_slot\":{},",
            "\"import_identity\":{},\"import_root\":{},\"source_manifest\":{},\"source_anchor\":{},",
            "\"capsule_digest\":{},\"sensor_id\":{},\"stream_id\":{},\"declared_capture_ns\":[{},{}],",
            "\"segment_index\":{},\"range_start\":{},\"range_count\":{},\"codec\":{},",
            "\"mask_binding\":{},\"mask_policy\":{},\"twin_digest\":{},\"scene_digest\":{},",
            "\"atlas_package\":{},\"atlas_provenance\":{},\"descriptor_generation\":{},\"committed_sequence\":{},",
            "\"schema\":\"fss.recorded_twin_localization_package.v1\",",
            "\"receipt_schema\":\"fss.recorded_twin_localization_receipt.v1\",",
            "\"scope\":\"unactivated_camera_pose_candidates\",\"verification\":\"metadata_only\",",
            "\"replay\":\"not_performed\",\"candidate_outcome\":\"not_interpreted\",",
            "\"activation_performed\":false,\"adoption\":\"unknown\",\"current_calibration\":\"unknown\",",
            "\"physical_coverage\":\"unknown\",\"source_payload_availability\":\"unknown\",",
            "\"archive_payload_availability\":\"unknown\",\"privacy_status\":\"current_binding_matches_receipt\"}}"
        ),
        quote(&m.package_identity.to_text()),
        quote(&m.receipt_digest.to_text()),
        quote(&m.publication_root.to_text()),
        quote(m.publication_slot.as_str()),
        quote(&m.import_identity.to_text()),
        quote(&m.import_root.to_text()),
        quote(&m.source_manifest.to_text()),
        anchor,
        quote(&m.capsule_digest.to_text()),
        quote(m.sensor_id.as_str()),
        quote(m.stream_id.as_str()),
        quote(&m.capture.earliest.0.to_string()),
        quote(&m.capture.latest.0.to_string()),
        quote(&m.segment_index.to_string()),
        quote(&m.range_start.to_string()),
        quote(&m.range_count.to_string()),
        quote(m.codec),
        quote(&m.mask_binding.to_text()),
        m.mask_policy
            .map_or_else(|| "null".to_owned(), |value| quote(&value.to_text())),
        quote(&m.twin_digest.to_text()),
        quote(&m.scene_digest.to_text()),
        quote(&m.atlas_package.to_text()),
        quote(&m.atlas_provenance.to_text()),
        quote(&m.descriptor_generation.to_text()),
        quote(&m.committed_sequence.to_string()),
    )
}

fn encode_deletion(deletion: &HistoricalHealthDeletion, encoder: &mut CanonicalEncoder) {
    encoder.digest(deletion.unavailable_digest);
    encoder.digest(deletion.deletion_plan);
    encoder.bool(deletion.authority_in_prefix);
}

/// Bind all diagnostics, not just receipts related to selected sensor/stream rows.
/// Native immutable decoding owns their exact semantics; this is selection identity only.
fn encode_diagnostics(snapshot: &DeploymentSnapshot, encoder: &mut CanonicalEncoder) {
    encoder.u64(snapshot.deletions_committed as u64);
    encoder.u64(snapshot.historical_health.len() as u64);
    for diagnostic in &snapshot.historical_health {
        encoder.digest(diagnostic.receipt_digest);
        encoder.u64(diagnostic.committed_sequence);
        match &diagnostic.metadata {
            HistoricalHealthMetadata::Retained {
                provenance_root,
                deleted_dependencies,
                ..
            } => {
                encoder.u8(0);
                encoder.digest(*provenance_root);
                encoder.u64(deleted_dependencies.len() as u64);
                for deletion in deleted_dependencies {
                    encode_deletion(deletion, encoder);
                }
            }
            HistoricalHealthMetadata::Deleted(deletion) => {
                encoder.u8(1);
                encode_deletion(deletion, encoder);
            }
        }
    }
    encoder.u64(snapshot.sensor_liveness.len() as u64);
    for observation in &snapshot.sensor_liveness {
        encoder.digest(observation.root);
        observation.anchor.encode_canonical(encoder);
    }
    encoder.u64(snapshot.coverage.len() as u64);
    for coverage in &snapshot.coverage {
        encoder.digest(coverage.payload_digest);
        encoder.u64(coverage.committed_sequence);
    }
    encoder.u64(snapshot.source_coverage.len() as u64);
    for coverage in &snapshot.source_coverage {
        encoder.digest(coverage.payload_digest);
        encoder.u64(coverage.committed_sequence);
    }
    encoder.bool(snapshot.coverage_evidence_unattributed);
}

#[allow(clippy::result_large_err)]
pub(super) fn compile(
    snapshot: DeploymentSnapshot,
    request: &LocalizationsQueryRequest,
    limits: &LocalizationsQueryLimits,
    ordered: Vec<LocalizationsQueryRow>,
    retracted_localizations: usize,
) -> Result<DeploymentLocalizationsQuery, LocalizationsQueryError> {
    let anchor_token = snapshot_anchor_token(&snapshot);
    let selected: Vec<_> = ordered
        .iter()
        .filter(|row| request.filter.matches(row))
        .collect();
    let basis = reference_contract_basis();
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_localizations.scope.v1");
    basis.encode_canonical(&mut encoder);
    encoder.text(&anchor_token);
    request.principal.encode_canonical(&mut encoder);
    request.filter.encode_canonical(&mut encoder);
    encoder.u32(request.max_entries);
    for value in [
        limits.max_objects,
        limits.max_localizations,
        limits.read.max_read_bytes,
        limits.read.max_read_objects,
        limits.read.snapshot.max_layout_bytes,
        limits.read.snapshot.max_journal_bytes,
        limits.read.snapshot.max_object_bytes,
        limits.read.snapshot.max_events,
        limits.read.snapshot.max_revisions_per_event,
    ] {
        encoder.u64(value as u64);
    }
    let scope = ContentDigest::sha256(&encoder.finish());
    let suffix = hex(scope);
    let session_id = SessionId::parse(format!("session:localizations:{suffix}"))
        .map_err(|_| LocalizationsQueryError::Contract)?;
    let mission_id = MissionId::parse(format!("mission:localizations:{suffix}"))
        .map_err(|_| LocalizationsQueryError::Contract)?;
    let allowance = limits.allowance()?;
    let admission = admit_query_read(
        &basis,
        &snapshot.anchor,
        "query",
        request.max_entries,
        allowance,
    )
    .map_err(|_| LocalizationsQueryError::Contract)?;
    let interpretation_id = "interpretation:retained-localization-metadata";
    let interpretation = QueryInterpretation::new(
        interpretation_id,
        request.filter.description(),
        true,
        true,
        None,
    )
    .map_err(|_| LocalizationsQueryError::Contract)?;
    let targets = if selected.len() <= 128 {
        selected
            .iter()
            .map(|row| format!("localization:{}", hex(row.row_digest())))
            .collect()
    } else {
        vec![format!("localizations:{suffix}")]
    };
    let plan = AgentQueryPlan::compile(
        format!("query-plan:{suffix}"),
        mission_id.clone(),
        session_id.clone(),
        &basis,
        "AOP-005",
        scope,
        vec!["taint:structured-operator-input".to_owned()],
        snapshot.anchor.clone(),
        request.filter.description(),
        targets,
        vec![
            fss_publication::ROOT_REACHABILITY_FAMILY.to_owned(),
            crate::reference_deployment::FAMILY_SENSOR_CAPSULE.to_owned(),
            crate::reference_deployment::FAMILY_FILE_IMPORT.to_owned(),
            crate::reference_deployment::FAMILY_COVERAGE_WITNESS.to_owned(),
            crate::ingest::historical_health::FAMILY_HISTORICAL_HEALTH.to_owned(),
        ],
        vec![crate::agent_query::CAPABILITY_QUERY.to_owned()],
        vec!["metadata_only".to_owned()],
        QueryCompletenessRequested::Bounded,
        allowance,
        vec![interpretation],
        interpretation_id,
        allowance,
        AgentView::Case.id(),
        snapshot.latest_evidence_time.0,
    )
    .map_err(|_| LocalizationsQueryError::Contract)?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_localizations.selection.v1");
    encoder.digest(scope);
    encoder.digest(plan.plan_digest());
    encoder.u64(retracted_localizations as u64);
    encoder.u64(ordered.len() as u64);
    for row in &ordered {
        encoder.digest(row.row_digest());
    }
    encode_diagnostics(&snapshot, &mut encoder);
    let selection_witness = ContentDigest::sha256(&encoder.finish());
    let entries = selected
        .iter()
        .enumerate()
        .map(|(index, row)| {
            ContinuationEntry::new(index as u64, "localization_package", row.row_digest(), true)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(LocalizationsQueryError::Continuation)?;
    let issued_at = snapshot.latest_evidence_time;
    let expires_at = TimestampNs(
        issued_at
            .0
            .checked_add(crate::agent_query::QUERY_CURSOR_LIFETIME_NS)
            .ok_or(LocalizationsQueryError::InvalidRequest(
                "localization evidence clock cannot represent cursor expiry",
            ))?,
    );
    let stream = ContinuationStream::publish(ContinuationStreamPublishParams {
        stream_id: format!("localizations:{suffix}"),
        scope: ContinuationScope::Investigation,
        contract_basis: basis,
        session_id: session_id.clone(),
        view_id: AgentView::Case.id().to_owned(),
        anchor: snapshot.anchor.clone(),
        entries,
        page_size: request.max_entries,
        selection_witness,
        issued_at,
        expires_at,
    })
    .map_err(LocalizationsQueryError::Continuation)?;
    let cursor = match &request.continuation {
        None => stream.initial_cursor(),
        Some(token) => stream.cursor_for_token(token, issued_at),
    }
    .map_err(LocalizationsQueryError::Continuation)?;
    let page = stream
        .read_page(&cursor, issued_at)
        .map_err(LocalizationsQueryError::Continuation)?;
    page.verify()
        .map_err(LocalizationsQueryError::Continuation)?;
    let mut rows = Vec::with_capacity(page.entries.len());
    for entry in &page.entries {
        let row = usize::try_from(entry.sequence)
            .ok()
            .and_then(|index| selected.get(index))
            .filter(|row| row.row_digest() == entry.payload_digest)
            .ok_or(LocalizationsQueryError::Continuation(
                ContinuationError::OutOfRange,
            ))?;
        rows.push((**row).clone());
    }
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_localizations.request.v1");
    encoder.digest(scope);
    encoder.digest(cursor.cursor_digest);
    let request_digest = ContentDigest::sha256(&encoder.finish());
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_localizations.decision.v1");
    encoder.digest(request_digest);
    encoder.digest(selection_witness);
    encoder.digest(admission.receipt_digest());
    encoder.u64(rows.len() as u64);
    for row in &rows {
        encoder.digest(row.row_digest());
    }
    encoder.bool(page.next_cursor.is_some());
    if let Some(next) = &page.next_cursor {
        encoder.digest(next.cursor_digest);
    }
    let decision_digest = ContentDigest::sha256(&encoder.finish());
    Ok(DeploymentLocalizationsQuery {
        filter: request.filter.clone(),
        snapshot,
        plan,
        admission,
        anchor_token,
        request_digest,
        selection_witness,
        decision_digest,
        session_id,
        mission_id,
        retracted_localizations,
        scanned_localizations: ordered.len(),
        matched_localizations: selected.len(),
        cursor,
        page,
        rows,
        read_usage: RetainedReadUsage::default(),
    })
}
