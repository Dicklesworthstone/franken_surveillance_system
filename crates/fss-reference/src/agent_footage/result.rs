#![forbid(unsafe_code)]
//! Native query plan, exact continuation owner and epistemic projection.

use super::*;
use crate::agent_follow::snapshot_anchor_token;
use crate::agent_orient::DeploymentSnapshot;
use fss_core::{
    AgentQueryPlan, AgentView, BudgetQuantitiesSpec, BudgetVector, ContinuationCursor,
    ContinuationEntry, ContinuationPage, ContinuationScope, ContinuationStream,
    ContinuationStreamPublishParams, EnvelopeCoverage, EnvelopeEpistemic, EnvelopeProposition,
    KnowledgeState, MissionId, QueryCompletenessRequested, QueryInterpretation, QueryReadReceipt,
    SessionId, TimestampNs, admit_query_read, reference_contract_basis,
};

/// One exact verified page with the native read receipt and complete-index selection witness.
#[derive(Clone, Debug, PartialEq)]
pub struct DeploymentFootageQuery {
    filter: FootageQueryFilter,
    /// Full verified metadata snapshot at the query's committed head.
    pub snapshot: DeploymentSnapshot,
    /// Native AOP-005 compiled metadata query plan.
    pub plan: AgentQueryPlan,
    /// Read admission allowance; not a measured latency or identity-authentication receipt.
    pub admission: QueryReadReceipt,
    /// Exact authority and effect-prefix token.
    pub anchor_token: String,
    /// Canonical identity of this exact cursor request.
    pub request_digest: ContentDigest,
    /// Complete verified file-capsule index witness, including rows outside the filter.
    pub selection_witness: ContentDigest,
    /// Exact result-page fingerprint.
    pub decision_digest: ContentDigest,
    /// Deterministic reference query session (not a durable workspace).
    pub session_id: SessionId,
    /// Explicit metadata-query mission, carrying no effect authority.
    pub mission_id: MissionId,
    /// All verified capsule records before filtering.
    pub scanned_capsules: usize,
    /// Total matching records, independent of this page's length.
    pub matched_capsules: usize,
    /// Complete imports belonging to another adapter; outside this query's declared scope.
    pub other_adapter_imports: usize,
    /// Native cursor consumed by this page.
    pub cursor: ContinuationCursor,
    /// Exact page and continuation from the existing owner.
    pub page: ContinuationPage,
    /// Metadata in deterministic import-identity/segment order.
    pub rows: Vec<FootageQueryRow>,
    /// Actual metadata payload bytes, including initial/final snapshots and rereads.
    /// Filesystem framing and syscall overhead are not measured here.
    pub metadata_bytes_read: u64,
    /// File/object payload reads under the same non-replenishing allowance.
    pub metadata_objects_read: u64,
}
impl DeploymentFootageQuery {
    /// Matching records remaining after this page; never physical-world omissions.
    pub fn remaining_capsules(&self) -> usize {
        self.matched_capsules - (self.cursor.position as usize + self.rows.len())
    }
    /// Declared metadata knowledge with unconditional time, payload and absence residuals.
    pub fn epistemic(&self) -> EnvelopeEpistemic {
        let mut propositions=vec![EnvelopeProposition {
            id:"claim:footage:record-selection".to_owned(),
            statement:format!("Verified {} retained completed-file capsule metadata records; {} overlap the requested source-native filters; this page returns {} from position {}; {} remain. Other-adapter completed imports outside this scope: {}. Metadata availability is verified; source payload availability is unknown.",
                self.scanned_capsules,self.matched_capsules,self.rows.len(),self.cursor.position,self.remaining_capsules(),self.other_adapter_imports),
            state:KnowledgeState::Known,provenance:"derived".to_owned(),
            evidence:vec![self.selection_witness.to_text()],
        },EnvelopeProposition {
            id:"claim:footage:physical-observability".to_owned(),
            statement:"Physical presence, absence, live coverage, current source-payload availability, trusted UTC and capture-time precision are unknown. Zero matches or gap_before=false cannot establish physical absence or continuous recording. No source-media bytes were read.".to_owned(),
            state:KnowledgeState::Unknown,provenance:"derived".to_owned(),evidence:Vec::new(),
        }];
        for row in &self.rows {
            let c = &row.capsule;
            propositions.push(EnvelopeProposition {
                id:format!("claim:footage:{}:{}",hex(row.import_identity),row.segment_index),
                statement:format!("Retained capsule metadata: import_identity={}, import_root={}, manifest_digest={}, capsule_id={}, capsule_digest={}, sensor={}, stream={}, sequence={}, declared_capture_interval_ns=[{},{}], clock_basis={}, capture_time_label={}, time_uncertainty=unknown, receive_time_ns={}, segment_index={}, source_offset={}, source_len={}, segment_digest={}, input_digest={}, input_bytes={}, format={}, frame_count={}, gap_before={}, completion_commit={}, metadata_availability=verified, source_payload_availability=unknown. Source-native endpoints are not UTC and a broad interval is not a precise occurrence time.",
                    row.import_identity,row.import_root,row.manifest_digest,c.capsule_id.as_str(),row.capsule_digest,
                    c.sensor_id.as_str(),c.stream_id.as_str(),c.sequence,c.capture.earliest.0,c.capture.latest.0,
                    c.clock_basis.as_str(),row.capture_time_label,c.receive_time.0,row.segment_index,row.source_offset,
                    row.source_len,c.source_digest,row.input_digest,row.input_bytes,row.format,c.frame_count,c.gap_before,row.committed_sequence),
                state:KnowledgeState::Known,provenance:"derived".to_owned(),
                evidence:vec![row.import_root.to_text(),row.manifest_digest.to_text(),row.capsule_digest.to_text()],
            });
        }
        EnvelopeEpistemic { propositions, assumptions:vec![self.filter.description(),
            "The principal is an audit label, not authentication. This query grants no effect or raw-media authority.".to_owned(),
            "The global spool doctor was not run; the snapshot's conservative attention verdict is not a full health inspection.".to_owned()],
            invalidators:vec!["Any authority/effect head, layout, selected metadata, publication or deletion change requires a new query.".to_owned(),
                "Changing principal, filter, page size or read limits invalidates continuations.".to_owned()] }
    }
    /// Index completeness is separate from payload availability and physical observability.
    pub fn coverage(&self) -> EnvelopeCoverage {
        let remaining = self.remaining_capsules();
        EnvelopeCoverage {
            authorized_domain:vec!["local committed ADP-FILE-001 capsule metadata".to_owned()],
            observed_domain:vec!["verified metadata of complete, non-deleted file imports at the exact committed head".to_owned()],
            not_observable_domain:vec!["live streams, other adapters, incomplete or deleted imports".to_owned(),
                "source payload availability/content, trusted UTC, physical activity, continuous coverage and absence".to_owned()],
            omitted_count:remaining as u64,
            omission_reasons:if remaining==0 {Vec::new()} else {vec!["remaining matching metadata is available through the exact continuation".to_owned()]},
            stop_reason:if remaining==0 {"committed_index_exhausted"} else {"page_limit"}.to_owned(),
        }
    }
}
fn hex(d: ContentDigest) -> String {
    d.to_text()
        .split_once(':')
        .map_or_else(String::new, |(_, h)| h.to_owned())
}

pub(super) fn compile(
    snapshot: DeploymentSnapshot,
    request: &FootageQueryRequest,
    limits: &FootageQueryLimits,
    ordered: Vec<FootageQueryRow>,
    other_adapter_imports: usize,
) -> Result<DeploymentFootageQuery, FootageQueryError> {
    let anchor_token = snapshot_anchor_token(&snapshot);
    let selected: Vec<_> = ordered
        .iter()
        .filter(|r| request.filter.matches(&r.capsule))
        .collect();
    let basis = reference_contract_basis();
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_footage.scope.v1");
    basis.encode_canonical(&mut e);
    e.text(&anchor_token);
    request.principal.encode_canonical(&mut e);
    request.filter.encode_canonical(&mut e);
    e.u32(request.max_entries);
    for n in [
        limits.max_imports,
        limits.max_capsules,
        limits.max_objects,
        limits.max_metadata_bytes,
        limits.max_metadata_objects,
        limits.snapshot.max_layout_bytes,
        limits.snapshot.max_journal_bytes,
        limits.snapshot.max_object_bytes,
        limits.snapshot.max_events,
        limits.snapshot.max_revisions_per_event,
    ] {
        e.u64(n as u64);
    }
    let scope = ContentDigest::sha256(&e.finish());
    let suffix = hex(scope);
    let session_id = SessionId::parse(format!("session:footage:{suffix}"))?;
    let mission_id = MissionId::parse(format!("mission:footage:{suffix}"))?;
    let allowance = BudgetVector::from_quantities(BudgetQuantitiesSpec {
        latency_ms: 60_000,
        bytes: limits.max_metadata_bytes as u64,
        storage_operations: limits.max_metadata_objects as u64,
        ..BudgetQuantitiesSpec::ZERO
    });
    let admission = admit_query_read(
        &basis,
        &snapshot.anchor,
        "query",
        request.max_entries,
        allowance,
    )?;
    let interpretation = QueryInterpretation::new(
        "interpretation:retained-file-capsule-metadata",
        request.filter.description(),
        true,
        true,
        None,
    )?;
    let targets = if selected.len() <= 128 {
        selected
            .iter()
            .map(|r| r.capsule.capsule_id.as_str().to_owned())
            .collect()
    } else {
        vec![format!("footage-query:{suffix}")]
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
        vec!["sensor_capsule".to_owned()],
        vec![crate::agent_query::CAPABILITY_QUERY.to_owned()],
        vec!["metadata_only".to_owned()],
        QueryCompletenessRequested::Bounded,
        allowance,
        vec![interpretation],
        "interpretation:retained-file-capsule-metadata",
        allowance,
        AgentView::Case.id(),
        snapshot.latest_evidence_time.0,
    )?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_footage.selection.v1");
    e.digest(scope);
    e.digest(plan.plan_digest());
    e.u64(other_adapter_imports as u64);
    e.u64(ordered.len() as u64);
    for row in &ordered {
        e.digest(row.row_digest());
    }
    let selection_witness = ContentDigest::sha256(&e.finish());
    let entries = selected
        .iter()
        .enumerate()
        .map(|(i, r)| ContinuationEntry::new(i as u64, "sensor_capsule", r.row_digest(), true))
        .collect::<Result<Vec<_>, _>>()?;
    let issued_at = snapshot.latest_evidence_time;
    let expires_at = TimestampNs(
        issued_at
            .0
            .checked_add(crate::agent_query::QUERY_CURSOR_LIFETIME_NS)
            .ok_or(FootageQueryError::InvalidRequest(
                "footage evidence clock cannot represent cursor expiry",
            ))?,
    );
    let stream = ContinuationStream::publish(ContinuationStreamPublishParams {
        stream_id: format!("footage:{suffix}"),
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
    })?;
    let cursor = match &request.continuation {
        None => stream.initial_cursor()?,
        Some(token) => stream.cursor_for_token(token, issued_at)?,
    };
    let page = stream.read_page(&cursor, issued_at)?;
    page.verify()?;
    let mut rows = Vec::with_capacity(page.entries.len());
    for entry in &page.entries {
        let row = usize::try_from(entry.sequence)
            .ok()
            .and_then(|i| selected.get(i))
            .filter(|r| r.row_digest() == entry.payload_digest)
            .ok_or(ContinuationError::OutOfRange)?;
        rows.push((**row).clone());
    }
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_footage.request.v1");
    e.digest(scope);
    e.digest(cursor.cursor_digest);
    let request_digest = ContentDigest::sha256(&e.finish());
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_footage.decision.v1");
    e.digest(request_digest);
    e.digest(selection_witness);
    e.digest(admission.receipt_digest());
    e.u64(rows.len() as u64);
    for row in &rows {
        e.digest(row.row_digest());
    }
    e.bool(page.next_cursor.is_some());
    if let Some(next) = &page.next_cursor {
        e.digest(next.cursor_digest);
    }
    let decision_digest = ContentDigest::sha256(&e.finish());
    Ok(DeploymentFootageQuery {
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
        scanned_capsules: ordered.len(),
        matched_capsules: selected.len(),
        other_adapter_imports,
        cursor,
        page,
        rows,
        metadata_bytes_read: 0,
        metadata_objects_read: 0,
    })
}
