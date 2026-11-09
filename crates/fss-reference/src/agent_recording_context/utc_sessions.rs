#![forbid(unsafe_code)]
//! AOP-005 conditional UTC candidates across explicitly pinned capture sessions.
//!
//! One deployment allowance brackets the entire native union, and one native archive
//! allowance spans every session, catalog, clock and final revalidation. The observations
//! are independently verified owners, not an atomic cross-owner snapshot. Each session's
//! original source scope and conditional clock evidence remain distinct; combining declared
//! UTC envelopes never establishes clock equivalence, camera exposure time or absence.

use std::collections::BTreeSet;
use std::path::Path;

use fss_core::{
    AgentQueryPlan, AgentView, BudgetQuantitiesSpec, BudgetVector, CanonicalEncode,
    CanonicalEncoder, ContentDigest, EnvelopeCoverage, EnvelopeEpistemic, EnvelopeProposition,
    KnowledgeState, MissionId, PrincipalId, QueryCompletenessRequested, QueryInterpretation,
    QueryReadReceipt, SessionId, admit_query_read, reference_contract_basis,
};
use fss_object::SpoolIo;

use crate::agent_follow::{AnchorToken, snapshot_anchor_token};
use crate::agent_orient::{
    DeploymentHistory, DeploymentReadError, DeploymentSnapshot, MetadataReadBudget, OrientLimits,
};
use crate::agent_recordings::utc_sessions::{
    RecordingUtcSessionsError, RecordingUtcSessionsLimits, RecordingUtcSessionsQuery,
    RecordingUtcSessionsRequest, query_recordings_utc_sessions,
};

/// Refusal of an incomplete session union, changed deployment or exhausted shared allowance.
#[derive(Debug)]
pub enum RecordingUtcSessionsContextError {
    /// Unsupported request or limits, rejected before archive I/O.
    InvalidRequest,
    /// Metadata-only deployment replay failed.
    Deployment(DeploymentReadError),
    /// Native session, catalog, clock, custody or shared-budget verification failed.
    Recording(RecordingUtcSessionsError),
    /// Expected/current deployment prefix or deletion state changed.
    AnchorChanged,
    /// The shared deployment metadata allowance was exhausted.
    OverBudget,
    /// Cooperative cancellation was requested before the next bounded phase.
    Cancelled,
    /// A verified query could not be admitted by the existing AOP-005 contract.
    Contract,
}

impl std::fmt::Display for RecordingUtcSessionsContextError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Self::InvalidRequest => "invalid UTC session-union request or allowance",
            Self::Deployment(_) => "deployment metadata verification failed",
            Self::Recording(_) => "native UTC session metadata verification refused",
            Self::AnchorChanged => "deployment authority, layout or deletion state changed",
            Self::OverBudget => "deployment metadata read allowance exhausted",
            Self::Cancelled => "UTC session-union query cancelled",
            Self::Contract => "UTC session-union query contract admission failed",
        })
    }
}
impl std::error::Error for RecordingUtcSessionsContextError {}

/// Exact session/catalog/clock union and independently verified deployment precondition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingUtcSessionsContextRequest {
    /// Explicit source scopes, catalog pins, retained clocks and half-open UTC interval.
    pub recording: RecordingUtcSessionsRequest,
    /// Audit label; this does not authenticate the caller or grant hydration authority.
    pub principal: PrincipalId,
    /// Optional exact deployment authority/effect-history token.
    pub expected_anchor: Option<AnchorToken>,
}

/// Separate, non-replenishing allowances for the two independently verified owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordingUtcSessionsContextLimits {
    /// Per-input deployment metadata limits.
    pub snapshot: OrientLimits,
    /// Total deployment metadata payload bytes across both history reads.
    pub deployment_bytes: usize,
    /// Total deployment file/object payload reads, including rereads.
    pub deployment_reads: usize,
    /// Shared native limits for the complete session union and its final verification pass.
    pub recording: RecordingUtcSessionsLimits,
}

impl Default for RecordingUtcSessionsContextLimits {
    fn default() -> Self {
        Self {
            snapshot: OrientLimits::default(),
            deployment_bytes: 256 * 1024 * 1024,
            deployment_reads: 65_536,
            recording: RecordingUtcSessionsLimits::default(),
        }
    }
}

impl RecordingUtcSessionsContextLimits {
    fn validate(&self) -> Result<(), RecordingUtcSessionsContextError> {
        let ceiling = Self::default();
        for (value, maximum) in [
            (self.deployment_bytes, ceiling.deployment_bytes),
            (self.deployment_reads, ceiling.deployment_reads),
            (
                self.snapshot.max_layout_bytes,
                ceiling.snapshot.max_layout_bytes,
            ),
            (
                self.snapshot.max_journal_bytes,
                ceiling.snapshot.max_journal_bytes,
            ),
            (
                self.snapshot.max_object_bytes,
                ceiling.snapshot.max_object_bytes,
            ),
            (self.snapshot.max_events, ceiling.snapshot.max_events),
            (
                self.snapshot.max_revisions_per_event,
                ceiling.snapshot.max_revisions_per_event,
            ),
        ] {
            if value == 0 || value > maximum {
                return Err(RecordingUtcSessionsContextError::InvalidRequest);
            }
        }
        Ok(())
    }

    /// Combined declared allowance. Native filesystem calls and deployment payload reads
    /// keep their distinct meanings in the result's individual counters.
    pub fn allowance(&self) -> Result<BudgetVector, RecordingUtcSessionsContextError> {
        Ok(BudgetVector::from_quantities(BudgetQuantitiesSpec {
            latency_ms: 60_000,
            bytes: (self.deployment_bytes as u64)
                .checked_add(self.recording.metadata.max_read_bytes)
                .ok_or(RecordingUtcSessionsContextError::InvalidRequest)?,
            storage_operations: (self.deployment_reads as u64)
                .checked_add(self.recording.metadata.max_io_calls)
                .ok_or(RecordingUtcSessionsContextError::InvalidRequest)?,
            ..BudgetQuantitiesSpec::ZERO
        }))
    }
}

/// Complete bounded session union together with protected current deployment context.
#[derive(Clone, Debug)]
pub struct DeploymentRecordingUtcSessionsQuery {
    /// Metadata-only snapshot bracketed by matching authority/effect-prefix reads.
    pub snapshot: DeploymentSnapshot,
    /// Exact current deployment prefix, distinct from every historical capture scope.
    pub anchor_token: String,
    /// Byte-free native union with separate session and clock provenance.
    pub native: RecordingUtcSessionsQuery,
    /// Existing AOP-005 query-plan receipt.
    pub plan: AgentQueryPlan,
    /// Existing read admission; no source-media or effect authority.
    pub admission: QueryReadReceipt,
    /// Request binds principal, deployment prefix, complete source pins and allowances.
    pub request_digest: ContentDigest,
    /// Decision binds the request, native union and admitted plan.
    pub decision_digest: ContentDigest,
    /// Deterministic query session label, not a durable workspace.
    pub session_id: SessionId,
    /// Deterministic metadata-query mission label.
    pub mission_id: MissionId,
    /// Both deployment history reads, separate from native archive counters.
    pub deployment_bytes_read: u64,
    /// Both deployment file/object payload reads.
    pub deployment_metadata_reads: u64,
}

impl DeploymentRecordingUtcSessionsQuery {
    /// Session/catalog positions supporting selected rows. Unselected metadata remains
    /// verified and decision-bound without expanding every catalog into the agent response.
    pub fn selected_catalog_indexes(&self) -> BTreeSet<(usize, usize)> {
        self.native
            .rows
            .iter()
            .flat_map(|row| {
                row.row
                    .locations
                    .iter()
                    .map(move |location| (row.session_index, location.catalog_index))
            })
            .collect()
    }

    /// Preserve each independent source/clock scope and conditional gap interpretation.
    pub fn epistemic(&self, request: &RecordingUtcSessionsRequest) -> EnvelopeEpistemic {
        let selected_catalogs = self.selected_catalog_indexes();
        let mut union_evidence = vec![self.native.decision_digest.to_text()];
        union_evidence.extend(
            self.native
                .sessions
                .iter()
                .map(|session| session.session_digest.to_text()),
        );
        let mut propositions = vec![EnvelopeProposition {
            id: "claim:recordings-utc-sessions:selection".to_owned(),
            statement: format!(
                "Verified one complete explicitly pinned capture-session union: sessions={}, indexed_memberships={}, unique_windows={}, returned_windows={}, requested_utc_ns=[{},{}), quoted_hydration_bytes={}. All input catalogs, clocks and window metadata were verified, including unselected inputs. Session order is canonical by session digest; row order within each session preserves native decode order. Complete selected window byte quotes are counted once. No media hydration is authorized.",
                self.native.sessions.len(), self.native.scanned_windows, self.native.unique_windows,
                self.native.rows.len(), request.interval.start, request.interval.end,
                self.native.quoted_hydration_bytes,
            ),
            state: KnowledgeState::Known,
            provenance: "derived".to_owned(),
            evidence: union_evidence.clone(),
        }, EnvelopeProposition {
            id: "claim:recordings-utc-sessions:physical-observability".to_owned(),
            statement: "Source-media availability, exact packet/admission correspondence, camera exposure time, trusted UTC, clock equivalence between sessions, live coverage, physical activity and physical absence remain unknown. No source-media bytes were read. Independent conditional UTC assertions are not synchronized-clock proof. Other source scopes and unpinned catalogs were not searched.".to_owned(),
            state: KnowledgeState::Unknown,
            provenance: "derived".to_owned(),
            evidence: Vec::new(),
        }];
        for (session_index, session) in self.native.sessions.iter().enumerate() {
            let source = &session.scope.recording;
            let session_evidence = vec![
                session.session_digest.to_text(),
                session.clock_root.to_text(),
                session.clock_metadata_digest.to_text(),
            ];
            propositions.push(EnvelopeProposition {
                id: format!("claim:recordings-utc-sessions:session:{session_index}"),
                statement: format!(
                    "Verified capture-session input: session_index={session_index}, session_digest={}, codec={}, sensor={}, stream={}, generation={}, source_anchor={}, receive_clock={}, decode_clock={}, time_scale={}, catalogs={}, indexed_memberships={}, unique_windows={}, clock_windows={}, quoted_hydration_bytes={}. This historical source scope remains separate from every other session and the current deployment prefix. Unselected catalog identities remain bound by the session digest and complete union decision.",
                    session.session_digest, session.codec.as_str(), source.sensor.as_str(), source.stream.as_str(),
                    source.generation, source.anchor, source.receive_clock, session.scope.decode_clock,
                    session.scope.time_scale, session.catalogs.len(), session.scanned_windows,
                    session.unique_windows, session.clock_windows, session.quoted_hydration_bytes,
                ),
                state: KnowledgeState::Known,
                provenance: "derived".to_owned(),
                evidence: session_evidence.clone(),
            });
            propositions.push(EnvelopeProposition {
                id: format!("claim:recordings-utc-sessions:session:{session_index}:clock"),
                statement: format!(
                    "Reconstructed this session's retained clock metadata under its original fixed policy: clock_slot={}, clock_root={}, clock_metadata={}, approval_digest={}, completed_read_brackets={}, utc_minus_local_wall_offset_ns=[{},{}], max_sample_bracket_ns={}, max_drift_ppb={}, max_age_ns={}. These are conditional node read/admission envelopes. The local NTP assertion is unauthenticated and packet-admission coordinates were not replayed from source. Its retained approval identity grants no present acquisition, hydration or disclosure authority.",
                    session.clock_slot.as_str(), session.clock_root, session.clock_metadata_digest,
                    session.clock_approval_digest, session.clock_brackets,
                    session.clock_offset.lower_ns, session.clock_offset.upper_ns,
                    session.clock_policy.max_sample_bracket_ns, session.clock_policy.max_drift_ppb,
                    session.clock_policy.max_age_ns,
                ),
                state: KnowledgeState::Known,
                provenance: "derived".to_owned(),
                evidence: session_evidence.clone(),
            });
            for &(input_index, catalog_index) in &selected_catalogs {
                if input_index != session_index {
                    continue;
                }
                let catalog = &session.catalogs[catalog_index];
                propositions.push(EnvelopeProposition {
                    id: format!("claim:recordings-utc-sessions:session:{session_index}:catalog:{catalog_index}"),
                    statement: format!(
                        "Verified catalog supporting selected metadata: session_index={session_index}, catalog_index={catalog_index}, slot={}, root={}, metadata={}, indexed_windows={}. Unselected catalogs were verified without expanding their rows into this response.",
                        catalog.pin.slot.as_str(), catalog.pin.root, catalog.metadata_digest, catalog.scanned_windows,
                    ),
                    state: KnowledgeState::Known,
                    provenance: "derived".to_owned(),
                    evidence: vec![session.session_digest.to_text(), catalog.pin.root.to_text(), catalog.metadata_digest.to_text()],
                });
            }
            for (gap_index, gap) in session.indexed_gaps.iter().enumerate() {
                propositions.push(EnvelopeProposition {
                    id: format!("claim:recordings-utc-sessions:session:{session_index}:indexed-gap:{gap_index}"),
                    statement: format!(
                        "No clock-annotated window among this session's explicitly pinned catalogs declares a node-observation envelope overlapping UTC nanoseconds [{},{}). Unknown-clock windows from this session may overlap the interval. Another session's observations do not establish continuity or physical coverage for this one.",
                        gap.start, gap.end,
                    ),
                    state: KnowledgeState::NotObservable,
                    provenance: "derived".to_owned(),
                    evidence: session_evidence.clone(),
                });
            }
        }
        for (index, selected) in self.native.rows.iter().enumerate() {
            let row = &selected.row;
            let session = &self.native.sessions[selected.session_index];
            let decode = row.entry.decode_interval();
            let memberships = row
                .locations
                .iter()
                .map(|location| {
                    format!(
                        "{}:{}:{}",
                        location.catalog_index, location.ordinal, location.catalog_root
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            let (time, state) = match row.utc_interval {
                Some(interval) => (format!(
                    "conditional_node_observation_utc_ns=[{},{}] (inclusive), clock_ordinal={}",
                    interval.earliest_ns, interval.latest_ns,
                    row.clock_ordinal.map_or_else(|| "unavailable".to_owned(), |ordinal| ordinal.to_string()),
                ), KnowledgeState::Known),
                None => ("clock_unavailable: temporal overlap cannot be determined; this window remains explicit regardless of the requested interval".to_owned(), KnowledgeState::NotObservable),
            };
            let mut evidence = vec![
                selected.session_digest.to_text(),
                session.clock_metadata_digest.to_text(),
                row.entry.root().to_text(),
            ];
            evidence.extend(row.locations.iter().map(|location| {
                session.catalogs[location.catalog_index]
                    .metadata_digest
                    .to_text()
            }));
            propositions.push(EnvelopeProposition {
                id: format!("claim:recordings-utc-sessions:window:{index}"),
                statement: format!(
                    "Published recording metadata: session_index={}, session_digest={}, slot={}, root={}, row_digest={}, catalog_index:ordinal:root=[{}], decode_interval=[{},{}), {}, hydration_bytes={}, samples={}, packets={}, nals={}, metadata_availability=verified, source_payload_availability=unknown. Clock annotations retain their session's separate provenance and do not establish synchronized exposure time.",
                    selected.session_index, selected.session_digest, row.entry.slot().as_str(), row.entry.root(),
                    selected.row_digest(), memberships, decode.start, decode.end, time, row.entry.byte_len(),
                    row.entry.samples(), row.entry.packets(), row.entry.nals(),
                ),
                state,
                provenance: "derived".to_owned(),
                evidence,
            });
        }
        for (index, gap) in self.native.indexed_gaps.iter().enumerate() {
            propositions.push(EnvelopeProposition {
                id: format!("claim:recordings-utc-sessions:indexed-gap:{index}"),
                statement: format!(
                    "No clock-annotated window in the complete pinned session union declares a conditional node-observation envelope overlapping UTC nanoseconds [{},{}). Windows with unavailable clocks may overlap this interval. This conditional metadata gap does not establish camera downtime, missing-footage cause, synchronized clock truth or physical absence.",
                    gap.start, gap.end,
                ),
                state: KnowledgeState::NotObservable,
                provenance: "derived".to_owned(),
                evidence: union_evidence.clone(),
            });
        }
        EnvelopeEpistemic {
            propositions,
            assumptions: vec![
                "The principal is an audit label, not authentication; this query grants no effect, source-media hydration or disclosure authority.".to_owned(),
                "Every session scope, catalog and clock pin is explicit caller input, not proof that a camera belongs to this deployment. Archive and deployment observations are separately verified, not an atomic cross-owner snapshot.".to_owned(),
                "Retained NTP and host-clock samples are supplied assertions. Internal consistency does not authenticate their source, synchronize independent capture sessions, establish uninterrupted clock continuity or renew any original clock lifetime.".to_owned(),
                "The deployment spool doctor was not run; metadata-only context retains its conservative attention verdict.".to_owned(),
            ],
            invalidators: vec!["Any authority/effect-prefix, publication, metadata, deletion state, session/catalog membership, source/clock scope, policy assumption or allowance change requires a new query.".to_owned()],
        }
    }

    /// Exhausting a pinned metadata union does not establish physical capture coverage.
    pub fn coverage(&self) -> EnvelopeCoverage {
        EnvelopeCoverage {
            authorized_domain: vec!["one bounded union of explicitly pinned AVC/HEVC capture sessions, catalogs and retained clocks for the same exact sensor and stream".to_owned()],
            observed_domain: vec!["every pinned catalog/window/clock metadata record, complete referenced deletion-marker closure and independently reconstructed conditional node-observation UTC envelopes".to_owned()],
            not_observable_domain: vec!["source packet replay, payload availability, trusted UTC, cross-session clock equivalence, camera exposure time, unpinned sessions/catalogs, continuous physical coverage, activity and absence".to_owned()],
            omitted_count: 0,
            omission_reasons: Vec::new(),
            stop_reason: "pinned_sessions_catalogs_and_clocks_exhausted".to_owned(),
        }
    }
}

/// Read a complete UTC session union while preserving current protected deployment context.
pub fn query_recordings_utc_sessions_in_deployment(
    io: &dyn SpoolIo,
    deployment_root: &Path,
    archive_root: &Path,
    request: &RecordingUtcSessionsContextRequest,
    limits: &RecordingUtcSessionsContextLimits,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<DeploymentRecordingUtcSessionsQuery, RecordingUtcSessionsContextError> {
    request
        .recording
        .request_digest(limits.recording)
        .map_err(RecordingUtcSessionsContextError::Recording)?;
    limits.validate()?;
    if !(1..=32).contains(&request.recording.max_windows) {
        return Err(RecordingUtcSessionsContextError::InvalidRequest);
    }
    let checkpoint = || {
        if cancelled() {
            Err(RecordingUtcSessionsContextError::Cancelled)
        } else {
            Ok(())
        }
    };
    checkpoint()?;
    let budget = MetadataReadBudget::new(limits.deployment_bytes, limits.deployment_reads);
    let history = DeploymentHistory::read_metadata(deployment_root, &limits.snapshot, &budget)
        .map_err(RecordingUtcSessionsContextError::Deployment)?;
    let snapshot = history
        .snapshot_at(history.head())
        .map_err(RecordingUtcSessionsContextError::Deployment)?;
    budget
        .ensure_valid()
        .map_err(|_| RecordingUtcSessionsContextError::OverBudget)?;
    let anchor_token = snapshot_anchor_token(&snapshot);
    if request
        .expected_anchor
        .as_ref()
        .is_some_and(|a| a.as_str() != anchor_token)
    {
        return Err(RecordingUtcSessionsContextError::AnchorChanged);
    }
    checkpoint()?;
    let native = query_recordings_utc_sessions(
        io,
        archive_root,
        &request.recording,
        limits.recording,
        cancelled,
    )
    .map_err(RecordingUtcSessionsContextError::Recording)?;
    checkpoint()?;
    let final_history =
        DeploymentHistory::read_metadata(deployment_root, &limits.snapshot, &budget)
            .map_err(RecordingUtcSessionsContextError::Deployment)?;
    let final_snapshot = final_history
        .snapshot_at(final_history.head())
        .map_err(RecordingUtcSessionsContextError::Deployment)?;
    budget
        .ensure_valid()
        .map_err(|_| RecordingUtcSessionsContextError::OverBudget)?;
    if snapshot_anchor_token(&final_snapshot) != anchor_token
        || final_history.metadata_layout_digest() != history.metadata_layout_digest()
        || final_snapshot.deletions != snapshot.deletions
        || native
            .reference_digests
            .iter()
            .any(|digest| snapshot.deletions.object(*digest).is_some())
    {
        return Err(RecordingUtcSessionsContextError::AnchorChanged);
    }
    checkpoint()?;
    let basis = reference_contract_basis();
    let allowance = limits.allowance()?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_recordings.utc_sessions_context_request.v1");
    basis.encode_canonical(&mut e);
    e.text(&anchor_token);
    request.principal.encode_canonical(&mut e);
    e.digest(native.request_digest);
    for value in [
        limits.deployment_bytes,
        limits.deployment_reads,
        limits.snapshot.max_layout_bytes,
        limits.snapshot.max_journal_bytes,
        limits.snapshot.max_object_bytes,
        limits.snapshot.max_events,
        limits.snapshot.max_revisions_per_event,
    ] {
        e.u64(value as u64);
    }
    let request_digest = ContentDigest::sha256(&e.finish());
    let suffix = request_digest.to_text();
    let suffix = suffix.strip_prefix("sha256:").unwrap_or(&suffix);
    let session_id = SessionId::parse(format!("session:recordings-utc-sessions:{suffix}"))
        .map_err(|_| RecordingUtcSessionsContextError::Contract)?;
    let mission_id = MissionId::parse(format!("mission:recordings-utc-sessions:{suffix}"))
        .map_err(|_| RecordingUtcSessionsContextError::Contract)?;
    let admission = admit_query_read(
        &basis,
        &snapshot.anchor,
        "query",
        request.recording.max_windows as u32,
        allowance,
    )
    .map_err(|_| RecordingUtcSessionsContextError::Contract)?;
    let description = "Complete explicitly pinned capture-session/catalog/clock union selected by independent conditional node-observation UTC envelopes; unknown-clock windows remain explicit and no clock equivalence, packet replay, trusted UTC, camera exposure time or physical absence is inferred";
    let interpretation_id = "interpretation:native-recording-utc-sessions-metadata";
    let interpretation = QueryInterpretation::new(interpretation_id, description, true, true, None)
        .map_err(|_| RecordingUtcSessionsContextError::Contract)?;
    let plan = AgentQueryPlan::compile(
        format!("query-plan:{suffix}"),
        mission_id.clone(),
        session_id.clone(),
        &basis,
        "AOP-005",
        request_digest,
        vec!["taint:structured-operator-input".to_owned()],
        snapshot.anchor.clone(),
        description,
        native
            .sessions
            .iter()
            .flat_map(|session| {
                [
                    session.session_digest.to_text(),
                    session.clock_root.to_text(),
                ]
            })
            .collect(),
        vec!["recording_window".to_owned()],
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
    .map_err(|_| RecordingUtcSessionsContextError::Contract)?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_recordings.utc_sessions_context_decision.v1");
    e.digest(request_digest);
    e.digest(native.decision_digest);
    e.digest(plan.plan_digest());
    let decision_digest = ContentDigest::sha256(&e.finish());
    let (deployment_bytes_read, deployment_metadata_reads) = budget.consumed();
    Ok(DeploymentRecordingUtcSessionsQuery {
        snapshot,
        anchor_token,
        native,
        plan,
        admission,
        request_digest,
        decision_digest,
        session_id,
        mission_id,
        deployment_bytes_read,
        deployment_metadata_reads,
    })
}
