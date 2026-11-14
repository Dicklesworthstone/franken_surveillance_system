#![forbid(unsafe_code)]
//! Native AOP-005 read plan, exact continuation and bounded epistemic projection.

use super::*;
use crate::agent_follow::snapshot_anchor_token;
use crate::agent_orient::DeploymentSnapshot;
use crate::retained_source::RetainedReadUsage;
use fss_core::{
    AgentQueryPlan, AgentView, ContinuationCursor, ContinuationEntry, ContinuationPage,
    ContinuationScope, ContinuationStream, ContinuationStreamPublishParams, EnvelopeCoverage,
    EnvelopeEpistemic, EnvelopeProposition, KnowledgeState, MissionId, QueryCompletenessRequested,
    QueryInterpretation, QueryReadReceipt, SessionId, TimestampNs, admit_query_read,
    reference_contract_basis,
};

/// One exact page of retained report handles after complete-index metadata verification.
#[derive(Clone, Debug, PartialEq)]
pub struct DeploymentReportCatalogQuery {
    filter: ReportCatalogFilter,
    /// Current verified deployment metadata; no writer or recovery owner was opened.
    pub snapshot: DeploymentSnapshot,
    /// Registered AOP-005 metadata discovery plan.
    pub plan: AgentQueryPlan,
    /// Native read admission receipt, carrying no effect or source-media authority.
    pub admission: QueryReadReceipt,
    /// Exact current authority and effect-prefix token.
    pub anchor_token: String,
    /// Exact scope and consumed cursor identity.
    pub request_digest: ContentDigest,
    /// Complete verified metadata index, including rows omitted by the predicates.
    pub selection_witness: ContentDigest,
    /// Exact admitted page and continuation fingerprint.
    pub decision_digest: ContentDigest,
    /// Deterministic ephemeral read session; no session state is persisted.
    pub session_id: SessionId,
    /// Deterministic metadata discovery mission.
    pub mission_id: MissionId,
    /// All supported retained reports verified before filtering.
    pub scanned_reports: usize,
    /// Total matching reports independently of the page size.
    pub matched_reports: usize,
    /// Native cursor consumed for this page.
    pub cursor: ContinuationCursor,
    /// Exact native page and optional continuation.
    pub page: ContinuationPage,
    /// Deterministic family/report-digest ordered metadata handles.
    pub rows: Vec<ReportCatalogRow>,
    /// Actual aggregate metadata payload bytes and reads, including final revalidation.
    pub read_usage: RetainedReadUsage,
}

impl DeploymentReportCatalogQuery {
    /// Matching stored declarations remaining after this page, never physical observations.
    pub fn remaining_reports(&self) -> usize {
        self.matched_reports - (self.cursor.position as usize + self.rows.len())
    }

    /// Metadata knowledge with explicit source, inference and eligibility residuals.
    pub fn epistemic(&self) -> EnvelopeEpistemic {
        let mut propositions = vec![
            EnvelopeProposition {
                id: "claim:report-catalog:selection".to_owned(),
                statement: format!(
                    "Verified {} current retained detection, zone and native RecordedInference model-run metadata declarations; {} match the requested family and declared interval; this page returns {} from position {}; {} remain. Metadata handles, canonical publications and retained metadata bytes are verified. Source availability remains unknown; source reconstruction, tensor payload verification and model execution are not performed.",
                    self.scanned_reports, self.matched_reports, self.rows.len(),
                    self.cursor.position, self.remaining_reports(),
                ),
                state: KnowledgeState::Known,
                provenance: "derived".to_owned(),
                evidence: vec![self.selection_witness.to_text()],
            },
            EnvelopeProposition {
                id: "claim:report-catalog:source-observability".to_owned(),
                statement: "This catalog reads retained metadata only. It does not verify original media, current source availability, model/input/output tensors, zone-report semantic reconstruction, QSR eligibility, physical identity, presence, absence or coverage. A discovered handle grants no ReadMedia capability; a later source-verified query can still refuse.".to_owned(),
                state: KnowledgeState::Unknown,
                provenance: "derived".to_owned(),
                evidence: Vec::new(),
            },
        ];
        for row in &self.rows {
            propositions.push(EnvelopeProposition {
                id: format!(
                    "claim:report-catalog:{}:{}",
                    row.family.as_str(),
                    hex(row.report_digest)
                ),
                statement: format!("Retained report metadata: {}", row_json(row)),
                state: KnowledgeState::Known,
                provenance: "derived".to_owned(),
                evidence: if row.model_run.is_some() {
                    vec![row.record_digest.to_text(), row.provenance_root.to_text()]
                } else {
                    vec![
                        row.report_digest.to_text(),
                        row.record_digest.to_text(),
                        row.provenance_root.to_text(),
                    ]
                },
            });
        }
        EnvelopeEpistemic {
            propositions,
            assumptions: vec![
                self.filter.description(),
                "The principal is an audit label, not authentication. This metadata read grants no source-media disclosure, inference or effect authority.".to_owned(),
                "A native v2 zone-report schema is a retained declaration; QSR eligibility still requires the separate native source-verified query.".to_owned(),
                "Model-run discovery covers native RecordedInference declarations only; executor_activity receipts and other model-invocation producers are not interpreted by this catalog.".to_owned(),
                "Verification is a bounded sequence of metadata observations with live admission, not an atomic filesystem snapshot or a read lease.".to_owned(),
            ],
            invalidators: vec![
                "Any current authority/effect prefix, layout, retained metadata, publication or deletion change requires a new query.".to_owned(),
                "Changing principal, family, interval, page size or read limits invalidates continuation tokens.".to_owned(),
            ],
        }
    }

    /// Complete bounded metadata index coverage, separate from source and physical coverage.
    pub fn coverage(&self) -> EnvelopeCoverage {
        let remaining = self.remaining_reports();
        EnvelopeCoverage {
            authorized_domain: vec!["current retained package_detection_record, package_zone_report and native object:model-run model_invocation_receipt metadata".to_owned()],
            observed_domain: vec!["exact supported native report declarations, publication manifests and retained metadata bytes; native model-run frame/import metadata linkage".to_owned()],
            not_observable_domain: vec![
                "other report families and model-invocation producers, source media, current source availability, model/input/output payloads, report semantic reconstruction and QSR eligibility".to_owned(),
                "physical identity, presence, absence, live coverage, trusted UTC and precise occurrence time".to_owned(),
            ],
            omitted_count: remaining as u64,
            omission_reasons: if remaining == 0 { Vec::new() } else {
                vec!["remaining matching report metadata is available through the exact continuation".to_owned()]
            },
            stop_reason: if remaining == 0 { "committed_index_exhausted" } else { "page_limit" }.to_owned(),
        }
    }
}

fn quote(value: &str) -> String {
    let mut encoded = String::new();
    encoded.push('"');
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

/// Exact native row fields inside the existing statement, without a second outer envelope.
/// Times and commit sequences are decimal strings so JSON consumers preserve all i128/u64 bits.
fn row_json(row: &ReportCatalogRow) -> String {
    let details = match &row.model_run {
        None => ",\"qsr_eligibility\":\"unknown\"".to_owned(),
        Some(run) => format!(
            concat!(
                ",\"model_run\":{{\"run_identity\":{},\"executor_profile_digest\":{},",
                "\"model_digest\":{},\"frame_root\":{},\"import_identity\":{},",
                "\"segment_index\":{},\"interpretation\":{}}},",
                "\"tensor_payload_verification\":\"not_performed\",\"model_execution\":\"not_performed\""
            ),
            quote(&run.run_identity.to_text()),
            quote(&run.executor_profile_digest.to_text()),
            quote(&run.model_digest.to_text()),
            quote(&run.frame_root.to_text()),
            quote(&run.import_identity.to_text()),
            quote(&run.segment_index.to_string()),
            quote(match run.interpretation {
                crate::ingest::recorded_decode::ComponentInterpretation::Grayscale => "gray",
                crate::ingest::recorded_decode::ComponentInterpretation::YCbCr => "ycbcr",
            }),
        ),
    };
    format!(
        concat!(
            "{{\"family\":{},\"report_digest\":{},\"record_digest\":{},",
            "\"provenance_root\":{},\"publication_slot\":{},\"schema\":{},",
            "\"declared_validity_ns\":[{},{}],\"retention_commit\":{},",
            "\"metadata_availability\":\"verified\",\"source_payload_availability\":\"unknown\",",
            "\"source_reconstruction\":\"not_performed\"{}}}"
        ),
        quote(row.family.as_str()),
        quote(&row.report_digest.to_text()),
        quote(&row.record_digest.to_text()),
        quote(&row.provenance_root.to_text()),
        quote(&row.publication_slot),
        quote(&row.schema),
        quote(&row.validity.earliest.0.to_string()),
        quote(&row.validity.latest.0.to_string()),
        quote(&row.committed_sequence.to_string()),
        details,
    )
}

pub(super) fn compile(
    snapshot: DeploymentSnapshot,
    request: &ReportCatalogRequest,
    limits: &ReportCatalogLimits,
    ordered: Vec<ReportCatalogRow>,
) -> Result<DeploymentReportCatalogQuery, ReportCatalogError> {
    let anchor_token = snapshot_anchor_token(&snapshot);
    let selected: Vec<_> = ordered
        .iter()
        .filter(|row| request.filter.matches(row))
        .collect();
    let basis = reference_contract_basis();
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_report_catalog.scope.v1");
    basis.encode_canonical(&mut encoder);
    encoder.text(&anchor_token);
    request.principal.encode_canonical(&mut encoder);
    request.filter.encode_canonical(&mut encoder);
    encoder.u32(request.max_entries);
    for value in [
        limits.max_reports,
        limits.max_objects,
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
    let session_id = SessionId::parse(format!("session:report-catalog:{suffix}"))
        .map_err(|_| ReportCatalogError::Contract)?;
    let mission_id = MissionId::parse(format!("mission:report-catalog:{suffix}"))
        .map_err(|_| ReportCatalogError::Contract)?;
    let allowance = limits.allowance()?;
    let admission = admit_query_read(
        &basis,
        &snapshot.anchor,
        "query",
        request.max_entries,
        allowance,
    )
    .map_err(|_| ReportCatalogError::Contract)?;
    let interpretation_id = "interpretation:retained-report-metadata";
    let interpretation = QueryInterpretation::new(
        interpretation_id,
        request.filter.description(),
        true,
        true,
        None,
    )
    .map_err(|_| ReportCatalogError::Contract)?;
    let targets = if selected.len() <= 128 {
        selected
            .iter()
            .map(|row| format!("report:{}:{}", row.family.as_str(), hex(row.report_digest)))
            .collect()
    } else {
        vec![format!("report-catalog:{suffix}")]
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
            PACKAGE_DETECTION_FAMILY.to_owned(),
            PACKAGE_ZONE_FAMILY.to_owned(),
            FAMILY_MODEL_INVOCATION_RECEIPT.to_owned(),
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
    .map_err(|_| ReportCatalogError::Contract)?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_report_catalog.selection.v1");
    encoder.digest(scope);
    encoder.digest(plan.plan_digest());
    encoder.u64(ordered.len() as u64);
    for row in &ordered {
        encoder.digest(row.row_digest());
    }
    let selection_witness = ContentDigest::sha256(&encoder.finish());
    let entries = selected
        .iter()
        .enumerate()
        .map(|(index, row)| {
            ContinuationEntry::new(index as u64, row.family.as_str(), row.row_digest(), true)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(ReportCatalogError::Continuation)?;
    let issued_at = snapshot.latest_evidence_time;
    let expires_at = TimestampNs(
        issued_at
            .0
            .checked_add(crate::agent_query::QUERY_CURSOR_LIFETIME_NS)
            .ok_or(ReportCatalogError::InvalidRequest(
                "report evidence clock cannot represent cursor expiry",
            ))?,
    );
    let stream = ContinuationStream::publish(ContinuationStreamPublishParams {
        stream_id: format!("report-catalog:{suffix}"),
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
    .map_err(ReportCatalogError::Continuation)?;
    let cursor = match &request.continuation {
        None => stream.initial_cursor(),
        Some(token) => stream.cursor_for_token(token, issued_at),
    }
    .map_err(ReportCatalogError::Continuation)?;
    let page = stream
        .read_page(&cursor, issued_at)
        .map_err(ReportCatalogError::Continuation)?;
    page.verify().map_err(ReportCatalogError::Continuation)?;
    let mut rows = Vec::with_capacity(page.entries.len());
    for entry in &page.entries {
        let row = usize::try_from(entry.sequence)
            .ok()
            .and_then(|index| selected.get(index))
            .filter(|row| row.row_digest() == entry.payload_digest)
            .ok_or(ReportCatalogError::Continuation(
                ContinuationError::OutOfRange,
            ))?;
        rows.push((**row).clone());
    }
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_report_catalog.request.v1");
    encoder.digest(scope);
    encoder.digest(cursor.cursor_digest);
    let request_digest = ContentDigest::sha256(&encoder.finish());
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_report_catalog.decision.v1");
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
    Ok(DeploymentReportCatalogQuery {
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
        scanned_reports: ordered.len(),
        matched_reports: selected.len(),
        cursor,
        page,
        rows,
        read_usage: RetainedReadUsage::default(),
    })
}
