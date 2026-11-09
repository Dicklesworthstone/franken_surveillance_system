#![forbid(unsafe_code)]
//! AOP-005 conditional UTC candidates across explicitly pinned catalog pages.
//!
//! The deployment and archive are distinct owners. The deployment prefix is read before and
//! after the native archive query; neither read claims an atomic cross-owner snapshot. One
//! non-replenishing deployment allowance and one non-replenishing archive allowance bound the
//! entire operation. No writer, recovery handle, directory discovery or source-media read is
//! admitted by the archive query.

use std::path::Path;

use fss_core::{
    AgentQueryPlan, AgentView, BudgetQuantitiesSpec, BudgetVector, CanonicalEncode,
    CanonicalEncoder, ContentDigest, EnvelopeCoverage, EnvelopeEpistemic, EnvelopeProposition,
    KnowledgeState, MissionId, PrincipalId, QueryCompletenessRequested, QueryInterpretation,
    QueryReadReceipt, SessionId, admit_query_read, reference_contract_basis,
};
use fss_object::SpoolIo;

use super::utc::RecordingUtcContextError;

use crate::agent_follow::{AnchorToken, snapshot_anchor_token};
use crate::agent_orient::{
    DeploymentHistory, DeploymentSnapshot, MetadataReadBudget, OrientLimits,
};
use crate::agent_recordings::utc_set::{
    RecordingUtcSetQuery, RecordingUtcSetQueryLimits, RecordingUtcSetQueryRequest,
    query_recordings_utc_set,
};

/// Caller-pinned native archive query and deployment authority precondition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingUtcSetContextRequest {
    /// Exact codec, source, catalog set, clock index and half-open Unix-nanosecond interval.
    pub recording: RecordingUtcSetQueryRequest,
    /// Audit label; this does not authenticate the caller or grant hydration authority.
    pub principal: PrincipalId,
    /// Optional exact deployment authority/effect-history token.
    pub expected_anchor: Option<AnchorToken>,
}

/// Separate, non-replenishing allowances for the two independently verified owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordingUtcSetContextLimits {
    /// Per-input deployment metadata limits.
    pub snapshot: OrientLimits,
    /// Total deployment metadata payload bytes across both history reads.
    pub deployment_bytes: usize,
    /// Total deployment file/object payload reads, including rereads.
    pub deployment_reads: usize,
    /// Native archive metadata and filesystem-call limits.
    pub recording: RecordingUtcSetQueryLimits,
}

impl Default for RecordingUtcSetContextLimits {
    fn default() -> Self {
        Self {
            snapshot: OrientLimits::default(),
            deployment_bytes: 256 * 1024 * 1024,
            deployment_reads: 65_536,
            recording: RecordingUtcSetQueryLimits::default(),
        }
    }
}

impl RecordingUtcSetContextLimits {
    fn validate(&self) -> Result<(), RecordingUtcContextError> {
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
                return Err(RecordingUtcContextError::InvalidRequest);
            }
        }
        Ok(())
    }

    /// Combined declared allowance. Archive filesystem calls and deployment payload reads
    /// retain their distinct meanings in the result's individual counters.
    pub fn allowance(&self) -> Result<BudgetVector, RecordingUtcContextError> {
        Ok(BudgetVector::from_quantities(BudgetQuantitiesSpec {
            latency_ms: 60_000,
            bytes: (self.deployment_bytes as u64)
                .checked_add(self.recording.metadata.max_read_bytes)
                .ok_or(RecordingUtcContextError::InvalidRequest)?,
            storage_operations: (self.deployment_reads as u64)
                .checked_add(self.recording.metadata.max_io_calls)
                .ok_or(RecordingUtcContextError::InvalidRequest)?,
            ..BudgetQuantitiesSpec::ZERO
        }))
    }
}

/// Complete bounded catalog-set selection together with current protected deployment context.
#[derive(Clone, Debug)]
pub struct DeploymentRecordingUtcSetQuery {
    /// Metadata-only snapshot, bracketed by matching authority/effect-prefix reads.
    pub snapshot: DeploymentSnapshot,
    /// Exact current deployment prefix; distinct from the catalog's source anchor.
    pub anchor_token: String,
    /// Native, byte-free catalog selection and its metered read usage.
    pub native: RecordingUtcSetQuery,
    /// Existing AOP-005 query-plan receipt.
    pub plan: AgentQueryPlan,
    /// Existing read admission; no source-media or effect authority.
    pub admission: QueryReadReceipt,
    /// Request identity binds principal, deployment prefix, source pins and allowances.
    pub request_digest: ContentDigest,
    /// Decision binds the request and native selection witness.
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

impl DeploymentRecordingUtcSetQuery {
    /// Preserve every catalog membership and unknown clock without claiming physical coverage.
    pub fn epistemic(&self, request: &RecordingUtcSetQueryRequest) -> EnvelopeEpistemic {
        let mut evidence = vec![self.native.clock_metadata_digest.to_text()];
        evidence.extend(
            self.native
                .catalogs
                .iter()
                .map(|catalog| catalog.metadata_digest.to_text()),
        );
        let mut propositions = vec![EnvelopeProposition {
            id: "claim:recordings-utc-set:catalog-selection".to_owned(),
            statement: format!(
                "Verified the complete explicit catalog set and clock-index metadata: catalogs={}, indexed_memberships={}, unique_windows={}, clock_windows={}, returned_windows={}, requested_utc_ns=[{},{}), quoted_hydration_bytes={}. Source sensor={}, stream={}, generation={}, source_anchor={}, receive_clock={}, decode_clock={}, time_scale={}. Complete unique windows are quoted once; no media hydration is authorized.",
                self.native.catalogs.len(), self.native.scanned_windows, self.native.unique_windows,
                self.native.clock_windows, self.native.rows.len(), request.interval.start,
                request.interval.end, self.native.quoted_hydration_bytes,
                request.scope.recording.sensor.as_str(), request.scope.recording.stream.as_str(),
                request.scope.recording.generation, request.scope.recording.anchor,
                request.scope.recording.receive_clock, request.scope.decode_clock, request.scope.time_scale,
            ),
            state: KnowledgeState::Known,
            provenance: "derived".to_owned(),
            evidence: evidence.clone(),
        }, EnvelopeProposition {
            id: "claim:recordings-utc-set:clock-conditions".to_owned(),
            statement: format!(
                "Reconstructed retained clock metadata under its original fixed policy: clock_root={}, clock_metadata={}, approval_digest={}, completed_read_brackets={}, utc_minus_local_wall_offset_ns=[{},{}], max_sample_bracket_ns={}, max_drift_ppb={}, max_age_ns={}. These are conditional node read/admission envelopes. The local NTP assertion is unauthenticated, packet-admission coordinates were not replayed from source, and camera exposure time is not established. The retained approval identity grants no present acquisition or disclosure authority.",
                self.native.clock_root, self.native.clock_metadata_digest,
                self.native.clock_approval_digest, self.native.clock_brackets,
                self.native.clock_offset.lower_ns, self.native.clock_offset.upper_ns,
                self.native.clock_policy.max_sample_bracket_ns,
                self.native.clock_policy.max_drift_ppb, self.native.clock_policy.max_age_ns,
            ),
            state: KnowledgeState::Known,
            provenance: "derived".to_owned(),
            evidence: vec![self.native.clock_root.to_text(), self.native.clock_metadata_digest.to_text()],
        }, EnvelopeProposition {
            id: "claim:recordings-utc-set:physical-observability".to_owned(),
            statement: "Source-media availability, exact packet/admission correspondence, camera exposure time, trusted UTC, live coverage, physical activity and physical absence remain unknown. No source-media bytes were read. A conditional envelope overlap is a candidate for later verification, not a confirmed event at that time. Catalogs outside the explicit set were not searched.".to_owned(),
            state: KnowledgeState::Unknown,
            provenance: "derived".to_owned(),
            evidence: Vec::new(),
        }];
        for (index, catalog) in self.native.catalogs.iter().enumerate() {
            propositions.push(EnvelopeProposition {
                id: format!("claim:recordings-utc-set:catalog:{index}"),
                statement: format!(
                    "Verified catalog metadata: catalog_index={index}, slot={}, root={}, metadata={}, indexed_windows={}.",
                    catalog.pin.slot.as_str(), catalog.pin.root, catalog.metadata_digest,
                    catalog.scanned_windows,
                ),
                state: KnowledgeState::Known,
                provenance: "derived".to_owned(),
                evidence: vec![catalog.pin.root.to_text(), catalog.metadata_digest.to_text()],
            });
        }
        for (index, row) in self.native.rows.iter().enumerate() {
            let decode = row.entry.decode_interval();
            let memberships = row
                .locations
                .iter()
                .map(|location| {
                    format!(
                        "{}:{}:{}",
                        location.catalog_index, location.ordinal, location.catalog_root,
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            let (time, state) = match row.utc_interval {
                Some(interval) => (format!(
                    "conditional_node_observation_utc_ns=[{},{}] (inclusive), clock_ordinal={}",
                    interval.earliest_ns, interval.latest_ns,
                    row.clock_ordinal.map(|ordinal| ordinal.to_string()).unwrap_or_else(|| "unavailable".to_owned()),
                ), KnowledgeState::Known),
                None => ("clock_unavailable: temporal overlap cannot be determined; this window is retained in the result regardless of the requested interval".to_owned(), KnowledgeState::NotObservable),
            };
            let mut row_evidence = vec![
                self.native.clock_metadata_digest.to_text(),
                row.entry.root().to_text(),
            ];
            row_evidence.extend(row.locations.iter().map(|location| {
                self.native.catalogs[location.catalog_index]
                    .metadata_digest
                    .to_text()
            }));
            propositions.push(EnvelopeProposition {
                id: format!("claim:recordings-utc-set:window:{index}"),
                statement: format!(
                    "Published recording metadata: slot={}, root={}, row_digest={}, catalog_index:ordinal:root=[{}], decode_interval=[{},{}), {}, hydration_bytes={}, samples={}, packets={}, nals={}, metadata_availability=verified, source_payload_availability=unknown. Clock annotations remain conditional retained metadata, not replayed packet observations.",
                    row.entry.slot().as_str(), row.entry.root(), row.row_digest(), memberships,
                    decode.start, decode.end, time, row.entry.byte_len(), row.entry.samples(),
                    row.entry.packets(), row.entry.nals(),
                ),
                state,
                provenance: "derived".to_owned(),
                evidence: row_evidence,
            });
        }
        for (index, gap) in self.native.indexed_gaps.iter().enumerate() {
            propositions.push(EnvelopeProposition {
                id: format!("claim:recordings-utc-set:indexed-gap:{index}"),
                statement: format!(
                    "No clock-annotated window in this explicit catalog set declares a node-observation envelope overlapping UTC nanoseconds [{},{}). Windows with unavailable clocks may overlap this interval. Capture coverage, missing-footage causes and physical absence are not established.",
                    gap.start, gap.end,
                ),
                state: KnowledgeState::NotObservable,
                provenance: "derived".to_owned(),
                evidence: evidence.clone(),
            });
        }
        EnvelopeEpistemic {
            propositions,
            assumptions: vec![
                "The principal is an audit label, not authentication; this query grants no effect or media hydration authority.".to_owned(),
                "Archive pins are explicit caller input, not proof that a camera belongs to this deployment. Archive and deployment observations are separately verified, not an atomic cross-owner snapshot.".to_owned(),
                "The retained NTP and host-clock samples are supplied assertions. Internal consistency does not authenticate their source, establish uninterrupted clock continuity or renew the original clock lifetime.".to_owned(),
                "The deployment spool doctor was not run; metadata-only context retains its conservative attention verdict.".to_owned(),
            ],
            invalidators: vec!["Any authority/effect-prefix, catalog membership, publication, metadata, deletion state, source/clock scope, policy assumption or allowance change requires a new query.".to_owned()],
        }
    }

    /// Exhausting the explicit metadata union does not establish physical or temporal coverage.
    pub fn coverage(&self) -> EnvelopeCoverage {
        EnvelopeCoverage {
            authorized_domain: vec!["one explicitly pinned native AVC/HEVC recording catalog set and its exact retained clock index".to_owned()],
            observed_domain: vec!["all selected catalog publication metadata, complete descriptor binding and internally reconstructed conditional node-observation time envelopes".to_owned()],
            not_observable_domain: vec!["source packet replay, payload availability, trusted UTC, camera exposure time, unselected catalogs, continuous physical coverage, activity and absence".to_owned()],
            omitted_count: 0,
            omission_reasons: Vec::new(),
            stop_reason: "pinned_clock_catalog_set_exhausted".to_owned(),
        }
    }
}

/// Read exact UTC candidate metadata without losing protected deployment or deletion context.
pub fn query_recordings_utc_set_in_deployment(
    io: &dyn SpoolIo,
    deployment_root: &Path,
    archive_root: &Path,
    request: &RecordingUtcSetContextRequest,
    limits: &RecordingUtcSetContextLimits,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<DeploymentRecordingUtcSetQuery, RecordingUtcContextError> {
    request
        .recording
        .request_digest(limits.recording)
        .map_err(RecordingUtcContextError::Recording)?;
    limits.validate()?;
    if !(1..=32).contains(&request.recording.max_windows) {
        return Err(RecordingUtcContextError::InvalidRequest);
    }
    let checkpoint = || {
        if cancelled() {
            Err(RecordingUtcContextError::Cancelled)
        } else {
            Ok(())
        }
    };
    checkpoint()?;
    let budget = MetadataReadBudget::new(limits.deployment_bytes, limits.deployment_reads);
    let history = DeploymentHistory::read_metadata(deployment_root, &limits.snapshot, &budget)
        .map_err(RecordingUtcContextError::Deployment)?;
    let snapshot = history
        .snapshot_at(history.head())
        .map_err(RecordingUtcContextError::Deployment)?;
    budget
        .ensure_valid()
        .map_err(|_| RecordingUtcContextError::OverBudget)?;
    let anchor_token = snapshot_anchor_token(&snapshot);
    if request
        .expected_anchor
        .as_ref()
        .is_some_and(|a| a.as_str() != anchor_token)
    {
        return Err(RecordingUtcContextError::AnchorChanged);
    }
    checkpoint()?;
    let native = query_recordings_utc_set(
        io,
        archive_root,
        &request.recording,
        limits.recording,
        cancelled,
    )
    .map_err(RecordingUtcContextError::Recording)?;
    checkpoint()?;
    let final_history =
        DeploymentHistory::read_metadata(deployment_root, &limits.snapshot, &budget)
            .map_err(RecordingUtcContextError::Deployment)?;
    let final_snapshot = final_history
        .snapshot_at(final_history.head())
        .map_err(RecordingUtcContextError::Deployment)?;
    budget
        .ensure_valid()
        .map_err(|_| RecordingUtcContextError::OverBudget)?;
    if snapshot_anchor_token(&final_snapshot) != anchor_token
        || final_history.metadata_layout_digest() != history.metadata_layout_digest()
        || final_snapshot.deletions != snapshot.deletions
        || native
            .reference_digests
            .iter()
            .any(|digest| snapshot.deletions.object(*digest).is_some())
    {
        return Err(RecordingUtcContextError::AnchorChanged);
    }
    checkpoint()?;
    let basis = reference_contract_basis();
    let allowance = limits.allowance()?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_recordings.utc_set_context_request.v1");
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
    let session_id = SessionId::parse(format!("session:recordings-utc-set:{suffix}"))
        .map_err(|_| RecordingUtcContextError::Contract)?;
    let mission_id = MissionId::parse(format!("mission:recordings-utc-set:{suffix}"))
        .map_err(|_| RecordingUtcContextError::Contract)?;
    let admission = admit_query_read(
        &basis,
        &snapshot.anchor,
        "query",
        request.recording.max_windows as u32,
        allowance,
    )
    .map_err(|_| RecordingUtcContextError::Contract)?;
    let description = "Exact published recording and clock metadata selected by conditional retained node-observation UTC envelopes; unknown-clock windows remain explicit, and no packet replay, trusted UTC, camera exposure time or physical absence is inferred";
    let interpretation_id = "interpretation:pinned-native-recording-utc-set-metadata";
    let interpretation = QueryInterpretation::new(interpretation_id, description, true, true, None)
        .map_err(|_| RecordingUtcContextError::Contract)?;
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
            .catalogs
            .iter()
            .map(|catalog| catalog.pin.root.to_text())
            .chain(std::iter::once(native.clock_root.to_text()))
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
    .map_err(|_| RecordingUtcContextError::Contract)?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.agent_recordings.utc_set_context_decision.v1");
    e.digest(request_digest);
    e.digest(native.decision_digest);
    e.digest(plan.plan_digest());
    let decision_digest = ContentDigest::sha256(&e.finish());
    let (deployment_bytes_read, deployment_metadata_reads) = budget.consumed();
    Ok(DeploymentRecordingUtcSetQuery {
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
