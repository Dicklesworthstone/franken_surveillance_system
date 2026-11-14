#![forbid(unsafe_code)]
//! Exact source-inventory continuation and a bounded, explicitly historical projection.

use super::*;
use crate::agent_follow::snapshot_anchor_token;
use crate::agent_orient::DeploymentSnapshot;
use crate::agent_orient::historical_health::{
    HistoricalHealthDeletion, HistoricalHealthMetadata,
};
use crate::retained_source::RetainedReadUsage;
use fss_core::{
    AgentQueryPlan, AgentView, ContinuationCursor, ContinuationEntry, ContinuationPage,
    ContinuationScope, ContinuationStream, ContinuationStreamPublishParams, EnvelopeCoverage,
    EnvelopeEpistemic, EnvelopeProposition, KnowledgeState, MissionId, QueryCompletenessRequested,
    QueryInterpretation, QueryReadReceipt, SessionId, TimestampNs, admit_query_read,
    reference_contract_basis,
};

/// One page of source history after complete-index metadata verification.
#[derive(Clone, Debug, PartialEq)]
pub struct DeploymentSourcesQuery {
    filter: SourcesQueryFilter,
    /// Complete unfiltered protected metadata, including every retained historical health
    /// receipt and explicit deletion boundary. No writer or recovery owner was opened.
    pub snapshot: DeploymentSnapshot,
    /// Registered AOP-005 source-inventory plan.
    pub plan: AgentQueryPlan,
    /// Native metadata read admission, without media disclosure or effect authority.
    pub admission: QueryReadReceipt,
    /// Exact current authority and effect-prefix token.
    pub anchor_token: String,
    /// Exact scope and consumed cursor identity.
    pub request_digest: ContentDigest,
    /// Complete source index and unfiltered lifecycle/diagnostic metadata witness.
    pub selection_witness: ContentDigest,
    /// Exact admitted page and continuation fingerprint.
    pub decision_digest: ContentDigest,
    /// Deterministic ephemeral session; no read session is persisted.
    pub session_id: SessionId,
    /// Deterministic source-inventory mission.
    pub mission_id: MissionId,
    /// Whole-deployment accounting, unchanged by filters or page size.
    pub summary: SourcesQuerySummary,
    /// Sensor/stream rows verified before predicates.
    pub scanned_streams: usize,
    /// Matching rows independently of the page size.
    pub matched_streams: usize,
    /// Native cursor consumed for this page.
    pub cursor: ContinuationCursor,
    /// Native exact page with optional continuation.
    pub page: ContinuationPage,
    /// Sensor then stream identity ordered rows.
    pub rows: Vec<SourcesQueryRow>,
    /// Actual aggregate metadata bytes and read attempts, including final revalidation.
    pub read_usage: RetainedReadUsage,
}

impl DeploymentSourcesQuery {
    /// Matching historical stream rows remaining, never physical observations.
    pub fn remaining_streams(&self) -> usize {
        self.matched_streams - (self.cursor.position as usize + self.rows.len())
    }

    /// Historical metadata facts with current health and physical coverage kept unknown.
    pub fn epistemic(&self) -> EnvelopeEpistemic {
        let summary = &self.summary;
        let mut propositions = vec![
            EnvelopeProposition {
                id: "claim:sources:selection".to_owned(),
                statement: format!(
                    "Verified {} historical sensor/stream rows from {} sensors and {} retained capsule metadata objects; {} rows match the exact identity predicates; this page returns {} from position {}; {} remain. Counts and continuity use the native operational inventory rule. Capsule byte totals and capture ranges are retained declarations, not source-payload or physical coverage verification.",
                    self.scanned_streams, summary.sensors, summary.retained_capsules,
                    self.matched_streams, self.rows.len(), self.cursor.position,
                    self.remaining_streams(),
                ),
                state: KnowledgeState::Known,
                provenance: "derived".to_owned(),
                evidence: vec![self.selection_witness.to_text()],
            },
            EnvelopeProposition {
                id: "claim:sources:inventory-boundaries".to_owned(),
                statement: format!(
                    "Whole unfiltered inventory: {} historical capsule objects, {} retained capsules, {} deleted capsules, {} capsules excluded by incomplete imports, {} completed imports, {} deleted imports and {} incomplete imports. Every historical health receipt ({} total), recorded liveness observation and coverage record remains in the complete protected snapshot, including records unrelated to this page. No later clean diagnostic cancels an older finding.",
                    summary.capsule_objects, summary.retained_capsules,
                    summary.deleted_capsules, summary.incomplete_import_capsules,
                    summary.completed_imports, summary.deleted_imports,
                    summary.incomplete_imports.len(), self.snapshot.historical_health.len(),
                ),
                state: KnowledgeState::Known,
                provenance: "derived".to_owned(),
                evidence: vec![self.selection_witness.to_text()],
            },
            EnvelopeProposition {
                id: "claim:sources:current-observability".to_owned(),
                statement: "Current source health, network availability, source-payload availability, physical presence, absence and physical coverage remain unknown. This is retained historical metadata, not a live probe or device registry. Historical continuity and heuristic health receipts apply only to their original evidence and capture scope. Empty or gap-free inventory never certifies absence. This read grants no ReadMedia capability.".to_owned(),
                state: KnowledgeState::Unknown,
                provenance: "derived".to_owned(),
                evidence: Vec::new(),
            },
        ];
        for row in &self.rows {
            propositions.push(EnvelopeProposition {
                id: format!("claim:sources:{}", hex(row.row_digest())),
                statement: format!("Retained source metadata: {}", row_json(row)),
                state: KnowledgeState::Known,
                provenance: "derived".to_owned(),
                evidence: row.capsule_metadata.iter().map(|digest| digest.to_text()).collect(),
            });
        }
        EnvelopeEpistemic {
            propositions,
            assumptions: vec![
                self.filter.description(),
                "The principal is an audit label, not authentication. This metadata read grants no media disclosure, perception or effect authority.".to_owned(),
                "Estimated clocks remain file-source timing assumptions; mixed estimated/source clocks remain degraded even when historical delivery witnesses exist.".to_owned(),
                "The row's capsule metadata handles are the canonical first and last digests, not a full expansion. The selection witness binds every eligible capsule metadata digest, including capsules outside the returned page.".to_owned(),
                "Historical health stays per receipt with its native sensor, stream, import, privacy and capture bindings. No latest-per-sensor value or current health judgment is inferred.".to_owned(),
                "Verification is a bounded sequence of observations with live admission, not an atomic filesystem snapshot or a read lease.".to_owned(),
            ],
            invalidators: vec![
                "Any authority/effect prefix, layout, capsule metadata, protected diagnostic or deletion change requires a new query.".to_owned(),
                "Changing principal, sensor, stream, page size or any read limit invalidates the continuation.".to_owned(),
            ],
        }
    }

    /// Complete bounded inventory coverage, separately from physical/source observability.
    pub fn coverage(&self) -> EnvelopeCoverage {
        let remaining = self.remaining_streams();
        EnvelopeCoverage {
            authorized_domain: vec![
                "committed sensor-capsule metadata, native import lifecycle and complete protected deployment metadata".to_owned(),
            ],
            observed_domain: vec![
                "complete bounded eligible historical capsule index, sensor/stream counts, declared clocks and native historical continuity witnesses".to_owned(),
            ],
            not_observable_domain: vec![
                "source media, current source health, current network availability, device enrollment and media replay eligibility".to_owned(),
                "physical identity, presence, absence, physical coverage, trusted UTC and timing finer than capsule declarations".to_owned(),
                "capsules excluded by incomplete import or committed deletion authority remain separately accounted for in the unfiltered summary".to_owned(),
            ],
            omitted_count: remaining as u64,
            omission_reasons: if remaining == 0 {
                Vec::new()
            } else {
                vec!["remaining matching historical stream rows are available through the exact continuation".to_owned()]
            },
            stop_reason: if remaining == 0 {
                "committed_index_exhausted"
            } else {
                "page_limit"
            }.to_owned(),
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

/// Exact native row fields for the existing fss/1 proposition statement.
/// Source-byte totals and capture times are decimal strings, preserving u64/i128 precision.
pub fn row_json(row: &SourcesQueryRow) -> String {
    let stream = &row.stream;
    let clocks = stream.clock_bases.iter().map(|value| quote(value))
        .collect::<Vec<_>>().join(",");
    let handles = row.capsule_metadata.iter().map(|digest| quote(&digest.to_text()))
        .collect::<Vec<_>>().join(",");
    format!(
        concat!(
            "{{\"sensor_id\":{},\"stream_id\":{},\"capsules\":{},\"recorded_gaps\":{},",
            "\"declared_source_bytes\":{},\"clock_bases\":[{}],",
            "\"declared_capture_ns\":[{},{}],\"witnessed_continuous\":{},",
            "\"witnessed_degraded\":{},\"continuity\":{},\"continuity_reason\":{},",
            "\"capsule_metadata\":[{}],\"capsule_metadata_handles_complete\":{},",
            "\"continuity_scope\":\"retained_history_only\",",
            "\"capture_scope_semantics\":\"hull_of_declared_capsule_times_not_continuous_coverage\",",
            "\"current_health\":\"unknown\",\"physical_coverage\":\"unknown\",",
            "\"source_payload_availability\":\"unknown\"}}"
        ),
        quote(&stream.sensor_id),
        quote(&stream.stream_id),
        stream.capsules,
        stream.recorded_gaps,
        quote(&stream.declared_source_bytes.to_string()),
        clocks,
        quote(&stream.capture_earliest.0.to_string()),
        quote(&stream.capture_latest.0.to_string()),
        stream.witnessed_continuous,
        stream.witnessed_degraded,
        quote(stream.continuity.as_str()),
        quote(stream.continuity_reason.as_str()),
        handles,
        row.capsule_metadata.len() == stream.capsules,
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

pub(super) fn compile(
    snapshot: DeploymentSnapshot,
    request: &SourcesQueryRequest,
    limits: &SourcesQueryLimits,
    summary: SourcesQuerySummary,
    ordered: Vec<SourcesQueryRow>,
    capsule_index: &[ContentDigest],
) -> Result<DeploymentSourcesQuery, SourcesQueryError> {
    let anchor_token = snapshot_anchor_token(&snapshot);
    let selected: Vec<_> = ordered.iter().filter(|row| request.filter.matches(row)).collect();
    let basis = reference_contract_basis();
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_sources.scope.v1");
    basis.encode_canonical(&mut encoder);
    encoder.text(&anchor_token);
    request.principal.encode_canonical(&mut encoder);
    request.filter.encode_canonical(&mut encoder);
    encoder.u32(request.max_entries);
    for value in [
        limits.max_objects,
        limits.max_capsules,
        limits.max_streams,
        limits.max_metadata_bytes,
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
    let session_id = SessionId::parse(format!("session:sources:{suffix}"))
        .map_err(|_| SourcesQueryError::Contract)?;
    let mission_id = MissionId::parse(format!("mission:sources:{suffix}"))
        .map_err(|_| SourcesQueryError::Contract)?;
    let allowance = limits.allowance()?;
    let admission = admit_query_read(
        &basis, &snapshot.anchor, "query", request.max_entries, allowance,
    ).map_err(|_| SourcesQueryError::Contract)?;
    let interpretation_id = "interpretation:retained-source-inventory";
    let interpretation = QueryInterpretation::new(
        interpretation_id, request.filter.description(), true, true, None,
    ).map_err(|_| SourcesQueryError::Contract)?;
    let targets = if selected.len() <= 128 {
        selected.iter().map(|row| format!("source:{}", hex(row.row_digest()))).collect()
    } else {
        vec![format!("sources:{suffix}")]
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
    ).map_err(|_| SourcesQueryError::Contract)?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_sources.selection.v1");
    encoder.digest(scope);
    encoder.digest(plan.plan_digest());
    summary.encode_canonical(&mut encoder);
    encoder.u64(ordered.len() as u64);
    for row in &ordered {
        encoder.digest(row.row_digest());
    }
    encoder.u64(capsule_index.len() as u64);
    for digest in capsule_index {
        encoder.digest(*digest);
    }
    encode_diagnostics(&snapshot, &mut encoder);
    let selection_witness = ContentDigest::sha256(&encoder.finish());
    let entries = selected.iter().enumerate().map(|(index, row)| {
        ContinuationEntry::new(index as u64, "sensor_stream", row.row_digest(), true)
    }).collect::<Result<Vec<_>, _>>().map_err(SourcesQueryError::Continuation)?;
    let issued_at = snapshot.latest_evidence_time;
    let expires_at = TimestampNs(issued_at.0
        .checked_add(crate::agent_query::QUERY_CURSOR_LIFETIME_NS)
        .ok_or(SourcesQueryError::InvalidRequest(
            "source evidence clock cannot represent cursor expiry",
        ))?);
    let stream = ContinuationStream::publish(ContinuationStreamPublishParams {
        stream_id: format!("sources:{suffix}"),
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
    }).map_err(SourcesQueryError::Continuation)?;
    let cursor = match &request.continuation {
        None => stream.initial_cursor(),
        Some(token) => stream.cursor_for_token(token, issued_at),
    }.map_err(SourcesQueryError::Continuation)?;
    let page = stream.read_page(&cursor, issued_at).map_err(SourcesQueryError::Continuation)?;
    page.verify().map_err(SourcesQueryError::Continuation)?;
    let mut rows = Vec::with_capacity(page.entries.len());
    for entry in &page.entries {
        let row = usize::try_from(entry.sequence).ok()
            .and_then(|index| selected.get(index))
            .filter(|row| row.row_digest() == entry.payload_digest)
            .ok_or(SourcesQueryError::Continuation(ContinuationError::OutOfRange))?;
        rows.push((**row).clone());
    }
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_sources.request.v1");
    encoder.digest(scope);
    encoder.digest(cursor.cursor_digest);
    let request_digest = ContentDigest::sha256(&encoder.finish());
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_sources.decision.v1");
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
    Ok(DeploymentSourcesQuery {
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
        summary,
        scanned_streams: ordered.len(),
        matched_streams: selected.len(),
        cursor,
        page,
        rows,
        read_usage: RetainedReadUsage::default(),
    })
}
