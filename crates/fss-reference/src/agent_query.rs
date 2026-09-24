#![forbid(unsafe_code)]
//! Bounded, read-only AOP-005 queries of the latest committed event revisions.
//!
//! A query searches records, not the physical world. Exhausting this index never proves
//! physical absence, even when a separate coverage witness exists. Time predicates compare
//! the closed intervals declared by the records; they do not repair clocks or infer UTC.
//! Callers first obtain a verified snapshot through `agent_orient::read_deployment`.
//!
//! Selection, the compiled `AgentQueryPlan`, and every continuation bind the principal,
//! filters, page size, complete event index, authority anchor, and effect-journal prefix.
//! A changed head requires a new query; no page silently rebases. Pagination uses the
//! existing bounded investigation-result stream, not a second cursor implementation.

use fss_core::{
    AgentQueryPlan, AgentView, BudgetQuantitiesSpec, BudgetVector, CanonicalEncode,
    CanonicalEncoder, ContentDigest, ContinuationCursor, ContinuationEntry, ContinuationError,
    ContinuationPage, ContinuationScope, ContinuationStream, ContinuationStreamPublishParams,
    ContractBasisError, ContractError, EnvelopeCoverage, EnvelopeEpistemic, EnvelopeProposition,
    EventHypothesis, EventId, EventKind, EventState, KnowledgeState, MissionId, PrincipalId,
    QueryCompletenessRequested, QueryInterpretation, QueryReadReceipt, SessionId, TimestampNs,
    admit_query_read, reference_contract_basis,
};

use crate::agent_follow::{AnchorToken, snapshot_anchor_token};
use crate::agent_orient::{DeploymentSnapshot, RetainedEvent};

/// The registered capability for this metadata-only reference read (not authentication).
pub const CAPABILITY_QUERY: &str = "CAP-AGENT-QUERY-001";
/// Hard bound on the complete index searched by one reference query.
pub const MAX_QUERY_EVENTS: usize = 128;
/// Hard bound on one page of event records.
pub const MAX_QUERY_ENTRIES: u32 = 32;
/// Default page size.
pub const DEFAULT_QUERY_ENTRIES: u32 = 16;
/// Cursor lifetime on the committed evidence clock, not the wall clock.
pub const QUERY_CURSOR_LIFETIME_NS: i128 = 3_600_000_000_000;

/// Exact conjunctive filters on the latest committed revision of each event.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EventQueryFilter {
    /// Exact event identity; no substring matching.
    pub event_id: Option<EventId>,
    /// Recorded hypothesis class, not a verified physical classification.
    pub kind: Option<EventKind>,
    /// Recorded lifecycle state, not an effect outcome.
    pub state: Option<EventState>,
    /// Exact, case-sensitive membership in the recorded zone list.
    pub zone: Option<String>,
    /// Inclusive lower bound; records whose latest endpoint is before it are excluded.
    pub from_ns: Option<i128>,
    /// Inclusive upper bound; records whose earliest endpoint is after it are excluded.
    pub through_ns: Option<i128>,
}

impl EventQueryFilter {
    /// Refuses inverted intervals and empty, oversized, or control-bearing zone names.
    pub fn validate(&self) -> Result<(), QueryError> {
        if self
            .from_ns
            .zip(self.through_ns)
            .is_some_and(|(a, b)| a > b)
        {
            return Err(QueryError::InvalidRequest("inverted query interval"));
        }
        if self.zone.as_ref().is_some_and(|zone| {
            zone.is_empty()
                || zone.len() > fss_core::MAX_ZONE_ID_LEN
                || zone.chars().any(char::is_control)
        }) {
            return Err(QueryError::InvalidRequest("invalid query zone"));
        }
        Ok(())
    }

    /// Tests declared record metadata only; endpoints are compared without arithmetic.
    #[must_use]
    pub fn matches(&self, event: &EventHypothesis) -> bool {
        self.event_id
            .as_ref()
            .is_none_or(|id| id == &event.event_id)
            && self.kind.is_none_or(|kind| kind == event.kind)
            && self.state.is_none_or(|state| state == event.state)
            && self
                .zone
                .as_ref()
                .is_none_or(|zone| event.zone_ids.contains(zone))
            && self
                .from_ns
                .is_none_or(|from| event.interval.latest.0 >= from)
            && self
                .through_ns
                .is_none_or(|through| event.interval.earliest.0 <= through)
    }

    /// Human-inspectable, literal interpretation of the typed filters.
    #[must_use]
    pub fn description(&self) -> String {
        format!(
            "Latest committed event records; all predicates are ANDed: event_id={:?}, \
             kind={:?}, state={:?}, exact_zone={:?}, declared_interval_from_ns={:?}, \
             declared_interval_through_ns={:?}. Missing predicates mean no restriction; \
             time matching is closed-interval overlap, not a clock conversion.",
            self.event_id.as_ref().map(EventId::as_str),
            self.kind.map(EventKind::as_str),
            self.state.map(EventState::as_str),
            self.zone,
            self.from_ns,
            self.through_ns,
        )
    }
}

impl CanonicalEncode for EventQueryFilter {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        for text in [
            self.event_id.as_ref().map(EventId::as_str),
            self.kind.map(EventKind::as_str),
            self.state.map(EventState::as_str),
            self.zone.as_deref(),
        ] {
            encoder.bool(text.is_some());
            if let Some(text) = text {
                encoder.text(text);
            }
        }
        for time in [self.from_ns, self.through_ns] {
            encoder.bool(time.is_some());
            if let Some(time) = time {
                encoder.i128(time);
            }
        }
    }
}

/// One bounded reference query. The principal is an OS-operator audit label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventQueryRequest {
    /// Exact predicates.
    pub filter: EventQueryFilter,
    /// Principal bound into the plan and every cursor.
    pub principal: PrincipalId,
    /// Number of event records per page, in 1..=MAX_QUERY_ENTRIES.
    pub max_entries: u32,
    /// Optional precondition: the exact token of the currently committed snapshot.
    pub expected_anchor: Option<AnchorToken>,
    /// Exact token returned by the preceding page; never an offset supplied by the caller.
    pub continuation: Option<String>,
}

impl EventQueryRequest {
    /// Validates limits before compilation or index allocation.
    pub fn validate(&self) -> Result<(), QueryError> {
        self.filter.validate()?;
        if !(1..=MAX_QUERY_ENTRIES).contains(&self.max_entries) {
            return Err(QueryError::InvalidRequest("query page size outside bounds"));
        }
        if self.continuation.as_ref().is_some_and(|token| {
            token.len() > 256
                || !token.starts_with("continuation:")
                || !token.bytes().all(|b| {
                    b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || matches!(b, b':' | b'+' | b'.' | b'_' | b'-')
                })
        }) {
            return Err(QueryError::InvalidRequest(
                "invalid query continuation spelling",
            ));
        }
        Ok(())
    }
}

/// Typed refusal; none of these outcomes permits a partial or invented result set.
#[derive(Debug)]
pub enum QueryError {
    /// Invalid scalar input, before index traversal.
    InvalidRequest(&'static str),
    /// The full index exceeds the reference bound; filtering is not a scan-limit escape.
    TooManyEvents,
    /// The caller's explicit head precondition is not the verified snapshot's token.
    AnchorChanged,
    /// A snapshot supplied to the pure compiler has invalid or duplicate event records.
    InvalidRecord,
    /// Native cursor or stream validation failed.
    Continuation(ContinuationError),
    /// Native plan or admission validation failed.
    Contract(ContractBasisError),
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(reason) => f.write_str(reason),
            Self::TooManyEvents => f.write_str("complete event index exceeds query bound"),
            Self::AnchorChanged => f.write_str("query anchor changed; start a new query"),
            Self::InvalidRecord => f.write_str("invalid or duplicate committed event record"),
            Self::Continuation(error) => write!(f, "query continuation refused: {error}"),
            Self::Contract(error) => write!(f, "query contract refused: {error}"),
        }
    }
}

impl std::error::Error for QueryError {}

impl From<ContinuationError> for QueryError {
    fn from(value: ContinuationError) -> Self {
        Self::Continuation(value)
    }
}

impl From<ContractError> for QueryError {
    fn from(value: ContractError) -> Self {
        Self::Contract(ContractBasisError::Contract(value))
    }
}

impl From<ContractBasisError> for QueryError {
    fn from(value: ContractBasisError) -> Self {
        Self::Contract(value)
    }
}

/// One selected latest revision, retaining its exact metadata and expansion roots.
#[derive(Clone, Debug, PartialEq)]
pub struct QueryEvent {
    /// The unmodified committed hypothesis; never promoted by querying it.
    pub event: EventHypothesis,
    /// Manifest root verified by the deployment reader.
    pub event_root: ContentDigest,
    /// Revision witness verified by the deployment reader.
    pub revision_digest: ContentDigest,
    /// Authority commit publishing this revision.
    pub committed_sequence: u64,
    /// Digest of the lineage's sensor-integrity assessment.
    pub tamper_digest: ContentDigest,
    /// Number of unretired sensor-integrity reports, including earlier revisions.
    pub open_tamper_reports: usize,
}

impl From<&RetainedEvent> for QueryEvent {
    fn from(value: &RetainedEvent) -> Self {
        Self {
            event: value.event.clone(),
            event_root: value.event_root,
            revision_digest: value.revision_digest,
            committed_sequence: value.committed_sequence,
            tamper_digest: value
                .tamper
                .canonical_digest("fss.agent_query.sensor_integrity.v1"),
            open_tamper_reports: value.tamper.open_tamper_reports.len(),
        }
    }
}

/// One exact page and its native query plan, bounded-read receipt, and proof witnesses.
#[derive(Clone, Debug, PartialEq)]
pub struct DeploymentQuery {
    filter: EventQueryFilter,
    /// Inspectable compiled plan; stable across pages of the same query.
    pub plan: AgentQueryPlan,
    /// Admission allowance, not a measurement of elapsed latency.
    pub admission: QueryReadReceipt,
    /// Full authority/effect-prefix token at which this query was evaluated.
    pub anchor_token: String,
    /// Identity of this exact page request.
    pub request_digest: ContentDigest,
    /// Witness over the plan and the complete ordered index, not just the returned page.
    pub selection_witness: ContentDigest,
    /// Decision fingerprint over this exact result page.
    pub decision_digest: ContentDigest,
    /// Explicit reference query session (not a durable workspace).
    pub session_id: SessionId,
    /// Explicit metadata-query mission (not an effect authorization).
    pub mission_id: MissionId,
    /// Complete index cardinality inspected before filtering.
    pub scanned_events: usize,
    /// Exact number of matching latest revisions in that index.
    pub matched_events: usize,
    /// Cursor used for this page.
    pub cursor: ContinuationCursor,
    /// Native exact page, including its next cursor when present.
    pub page: ContinuationPage,
    /// Unmodified latest event records in event-ID order.
    pub events: Vec<QueryEvent>,
}

impl DeploymentQuery {
    /// Number of matched records still available after this page (not physical omissions).
    #[must_use]
    pub fn remaining_events(&self) -> usize {
        self.matched_events - (self.cursor.position as usize + self.events.len())
    }

    /// Typed record-level propositions. The physical-absence residual is unconditional.
    #[must_use]
    pub fn epistemic(&self) -> EnvelopeEpistemic {
        let mut propositions = vec![
            EnvelopeProposition {
                id: "claim:query:record-selection".to_owned(),
                statement: format!(
                    "Inspected {} latest committed event records; {} match; this page \
                     returns {} record(s) from position {}; {} matching records remain. \
                     This count is about the committed index only.",
                    self.scanned_events,
                    self.matched_events,
                    self.events.len(),
                    self.cursor.position,
                    self.remaining_events(),
                ),
                state: KnowledgeState::Known,
                provenance: "derived".to_owned(),
                evidence: vec![self.selection_witness.to_text()],
            },
            EnvelopeProposition {
                id: "claim:query:physical-absence".to_owned(),
                statement: "Whether matching physical activity occurred is not established \
                    by this record query. Zero matching records is not certified absence."
                    .to_owned(),
                state: KnowledgeState::Unknown,
                provenance: "derived".to_owned(),
                evidence: Vec::new(),
            },
        ];
        for row in &self.events {
            let event = &row.event;
            let contradictions = event
                .evidence
                .iter()
                .filter(|edge| edge.counts_as_contradiction())
                .count();
            propositions.push(EnvelopeProposition {
                id: event.event_id.as_str().to_owned(),
                statement: format!(
                    "Committed hypothesis record: event_id={}, revision={}, kind={}, \
                     lifecycle={}, declared_interval_ns=[{},{}], zone_count={}, \
                     contradictory_edges={}, open_sensor_tamper_reports={}, commit={}. \
                     Known describes this record's contents, not the hypothesis's physical truth. \
                     Use explain on this event identity for its evidence and uncertainty.",
                    event.event_id.as_str(),
                    event.revision,
                    event.kind.as_str(),
                    event.state.as_str(),
                    event.interval.earliest.0,
                    event.interval.latest.0,
                    event.zone_ids.len(),
                    contradictions,
                    row.open_tamper_reports,
                    row.committed_sequence,
                ),
                state: KnowledgeState::Known,
                provenance: "derived".to_owned(),
                evidence: vec![
                    row.event_root.to_text(),
                    row.revision_digest.to_text(),
                    row.tamper_digest.to_text(),
                ],
            });
        }
        EnvelopeEpistemic {
            propositions,
            assumptions: vec![
                self.filter.description(),
                "This metadata read grants no effect authority, performs no source-media search, \
                 and does not authenticate its principal audit label."
                    .to_owned(),
            ],
            invalidators: vec![
                "Any authority or effect-journal advance requires a new query.".to_owned(),
                "A change of principal, filters, or page size invalidates the continuation."
                    .to_owned(),
            ],
        }
    }

    /// Declares index completeness separately from physical-world observability.
    #[must_use]
    pub fn coverage(&self) -> EnvelopeCoverage {
        let remaining = self.remaining_events();
        EnvelopeCoverage {
            authorized_domain: vec!["local committed event_revision metadata".to_owned()],
            observed_domain: vec!["latest committed revision of each retained event".to_owned()],
            not_observable_domain: vec![
                "physical activity outside or missing from the committed event index".to_owned(),
                "unpublished detections, source-media content, and physical absence".to_owned(),
            ],
            omitted_count: remaining as u64,
            omission_reasons: if remaining == 0 {
                Vec::new()
            } else {
                vec![
                    "remaining matched records are available through the exact continuation"
                        .to_owned(),
                ]
            },
            stop_reason: if remaining == 0 {
                "committed_index_exhausted"
            } else {
                "page_limit"
            }
            .to_owned(),
        }
    }
}

fn hex(digest: ContentDigest) -> String {
    let text = digest.to_text();
    text.split_once(':')
        .map_or(text.as_str(), |(_, hex)| hex)
        .to_owned()
}

fn find_cursor(
    stream: &ContinuationStream,
    token: &str,
    now: TimestampNs,
) -> Result<ContinuationCursor, ContinuationError> {
    let mut cursor = stream.initial_cursor()?;
    loop {
        if cursor.token() == token {
            return Ok(cursor);
        }
        match stream.read_page(&cursor, now)?.next_cursor {
            Some(next) => cursor = next,
            None => return Err(ContinuationError::WrongStream),
        }
    }
}

/// Compiles and executes one bounded metadata query over a verified snapshot.
///
/// Nothing is read or written here. The snapshot must come from the verified deployment
/// reader. Invalid records and duplicate event identities fail closed even when excluded
/// by the filter. The complete index is bounded before sorting or canonical encoding.
pub fn query_deployment(
    snapshot: &DeploymentSnapshot,
    request: &EventQueryRequest,
) -> Result<DeploymentQuery, QueryError> {
    request.validate()?;
    if snapshot.events.len() > MAX_QUERY_EVENTS {
        return Err(QueryError::TooManyEvents);
    }
    let anchor_token = snapshot_anchor_token(snapshot);
    if request
        .expected_anchor
        .as_ref()
        .is_some_and(|anchor| anchor.as_str() != anchor_token)
    {
        return Err(QueryError::AnchorChanged);
    }
    let mut ordered: Vec<&RetainedEvent> = snapshot.events.iter().collect();
    ordered.sort_by(|a, b| a.event.event_id.cmp(&b.event.event_id));
    for (index, row) in ordered.iter().enumerate() {
        row.event.verify().map_err(|_| QueryError::InvalidRecord)?;
        if index > 0 && ordered[index - 1].event.event_id == row.event.event_id {
            return Err(QueryError::InvalidRecord);
        }
    }
    let selected: Vec<&RetainedEvent> = ordered
        .iter()
        .copied()
        .filter(|row| request.filter.matches(&row.event))
        .collect();
    let basis = reference_contract_basis();
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_query.scope.v1");
    basis.encode_canonical(&mut encoder);
    encoder.text(&anchor_token);
    request.principal.encode_canonical(&mut encoder);
    request.filter.encode_canonical(&mut encoder);
    encoder.u32(request.max_entries);
    let scope = ContentDigest::sha256(&encoder.finish());
    let suffix = hex(scope);
    let session_id = SessionId::parse(format!("session:query:{suffix}"))
        .map_err(ContractBasisError::Contract)?;
    let mission_id = MissionId::parse(format!("mission:query:{suffix}"))
        .map_err(ContractBasisError::Contract)?;
    // The native admission contract requires a positive latency allowance. This is an
    // allowance only; callers must not report it as measured or enforced elapsed time.
    let allowance = BudgetVector::from_quantities(BudgetQuantitiesSpec {
        latency_ms: 60_000,
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
        "interpretation:committed-event-records",
        request.filter.description(),
        true,
        true,
        None,
    )
    .map_err(ContractBasisError::Contract)?;
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
        selected
            .iter()
            .map(|row| row.event.event_id.as_str().to_owned())
            .collect(),
        vec!["event_revision".to_owned()],
        vec![CAPABILITY_QUERY.to_owned()],
        vec!["metadata_only".to_owned()],
        QueryCompletenessRequested::Bounded,
        allowance,
        vec![interpretation],
        "interpretation:committed-event-records",
        allowance,
        AgentView::Case.id(),
        snapshot.latest_evidence_time.0,
    )?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_query.selection.v1");
    encoder.digest(scope);
    encoder.digest(plan.plan_digest());
    encoder.u64(ordered.len() as u64);
    for row in &ordered {
        row.event.encode_canonical(&mut encoder);
        encoder.digest(row.event_root);
        encoder.digest(row.revision_digest);
        encoder.u64(row.committed_sequence);
        row.tamper.encode_canonical(&mut encoder);
    }
    let selection_witness = ContentDigest::sha256(&encoder.finish());
    let entries = selected
        .iter()
        .enumerate()
        .map(|(index, row)| {
            ContinuationEntry::new(index as u64, "event_revision", row.revision_digest, true)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let issued_at = snapshot.latest_evidence_time;
    let expires_at = TimestampNs(issued_at.0.checked_add(QUERY_CURSOR_LIFETIME_NS).ok_or(
        QueryError::InvalidRequest("query evidence clock cannot represent cursor expiry"),
    )?);
    let stream = ContinuationStream::publish(ContinuationStreamPublishParams {
        stream_id: format!("query:{suffix}"),
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
        Some(token) => find_cursor(&stream, token, issued_at)?,
    };
    let page = stream.read_page(&cursor, issued_at)?;
    page.verify()?;
    let mut events = Vec::with_capacity(page.entries.len());
    for entry in &page.entries {
        let row = usize::try_from(entry.sequence)
            .ok()
            .and_then(|index| selected.get(index))
            .filter(|row| row.revision_digest == entry.payload_digest)
            .ok_or(ContinuationError::OutOfRange)?;
        events.push(QueryEvent::from(*row));
    }
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_query.request.v1");
    encoder.digest(scope);
    encoder.digest(cursor.cursor_digest);
    let request_digest = ContentDigest::sha256(&encoder.finish());
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_query.decision.v1");
    encoder.digest(request_digest);
    encoder.digest(selection_witness);
    encoder.digest(admission.receipt_digest());
    encoder.u64(events.len() as u64);
    for row in &events {
        encoder.digest(row.event_root);
        encoder.digest(row.revision_digest);
    }
    encoder.bool(page.next_cursor.is_some());
    if let Some(next) = &page.next_cursor {
        encoder.digest(next.cursor_digest);
    }
    let decision_digest = ContentDigest::sha256(&encoder.finish());
    Ok(DeploymentQuery {
        filter: request.filter.clone(),
        plan,
        admission,
        anchor_token,
        request_digest,
        selection_witness,
        decision_digest,
        session_id,
        mission_id,
        scanned_events: ordered.len(),
        matched_events: selected.len(),
        cursor,
        page,
        events,
    })
}

#[cfg(test)]
mod tests;
