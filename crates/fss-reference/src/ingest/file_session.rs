#![forbid(unsafe_code)]
//! The acquisition lifecycle of one file import (`ADP-FILE-001`), driven through
//! [`fss_core::AcquisitionSession`] (fss-2h5zq.25).
//!
//! Every transition goes through the core session API, so the core transition table and every
//! witness `verify()` decide what is legal; this module never re-implements the state machine.
//!
//! # The honest file path
//!
//! `Requested → Authenticated → AdapterAccepted → Degraded → Cancelled`:
//!
//! * `Authenticated` carries a secret-free [`AuthReceipt`] with [`CredentialMethod::None`]: a local
//!   file has no credential. With no credential principal, the receipt binds the import identity.
//! * `AdapterAccepted` follows only once the request is admissible (capture-time assumptions are
//!   checked first); the adapter allocates no ring buffer.
//! * There is no `FirstFrameObserved`: the core [`fss_core::FirstFrameWitness`] requires a
//!   `Verified` decode and the importer splits and retains source bytes without decoding them.
//!   Claiming a verified decode would be fabricated, so the session degrades directly from
//!   `AdapterAccepted` (a registered transition). Model gap recorded as a finding (see the bead).
//! * `Degraded` names the lost dimensions — always `continuity_not_observable` (a file has no
//!   packet sequence and no live clock) and `first_frame_decode_not_attempted`, plus any omitted,
//!   truncated or gapped source bytes — and always invalidates the `absence` claim.
//! * A normally finished import ends `Cancelled` with a zero-task, zero-descriptor, drained
//!   [`QuiescenceReceipt`]. The core has no "end of source" kind, so the ending is labelled
//!   [`FileSessionEnding::EndOfFileSource`], never an operator cancel.
//! * Failures before any capsule batch commits end `Failed` with a [`FailureWitness`]; failures
//!   after the capsule batch committed, when the completion outcome is not known, end
//!   `Indeterminate` with an [`IndeterminateWitness`] naming the resume obligation; a cooperative
//!   cancellation ends `Cancelled` with [`FileSessionEnding::OperatorCancel`].
//!
//! # Retention
//!
//! A completed import retains its whole transition history in the same ledger batch that
//! completes it (`batch:file-import:<id>:manifest`): one `acquisition_transition` delta per
//! transition record, whose payload is the record's canonical bytes
//! (`fss.acquisition.transition_record.v1`) and whose witness is the justifying witness's canonical
//! bytes under its own registered `fss.acquisition.*` domain. Reopening reads those objects back,
//! decodes every witness and replays them through a fresh core session; the retained history is
//! accepted only if the replay reproduces it exactly. Failed, cancelled and indeterminate
//! histories are returned to the caller, never retained: a refused import writes nothing, and a
//! cancelled context admits no append.
//!
//! A file session never certifies absence: [`FileAcquisitionHistory::absence_claim`] is the core
//! [`AcquisitionSession::check_absence_claim_allowed`], which refuses every state but
//! `ContinuityVerified`, and a file session never reaches it.

use fss_core::identity::{
    AdapterCapabilities, CredentialMethod, DeviceCapabilities, DeviceClass, DeviceIdentity,
    MediaKind, SourceIdentity, SourceKind,
};
use fss_core::{
    AcquisitionError, AcquisitionRequest, AcquisitionSession, AcquisitionStateKind,
    AcquisitionTransitionRecord, AdapterAck, AuthReceipt, CanonicalDecode, CanonicalDecoder,
    CanonicalEncode, CanonicalEncoder, CaptureInterval, ClockBasis, ContentDigest, ContractError,
    DegradationEvidence, DeviceGeneration, DeviceId, DigestAlgorithm, EvidenceDelta,
    FailureWitness, FirmwareGeneration, IndeterminateWitness, ObjectId, Plane, QuiescenceReceipt,
    SCHEMA_TRANSITION_RECORD, SourceId, StreamGeneration, TimestampNs,
};

use crate::ingest::file_adapter::{FileIngestError, default_adapter_identity};
use crate::reference_deployment::{FAMILY_ACQUISITION_TRANSITION, ReferenceDeployment};

/// Object-id prefix of retained file acquisition transitions:
/// `object:acquisition-transition:<import hex>:<index, 4 digits>`.
pub const ACQUISITION_TRANSITION_OBJECT_PREFIX: &str = "object:acquisition-transition:";
/// Delta-id prefix of retained file acquisition transitions.
pub const ACQUISITION_TRANSITION_DELTA_PREFIX: &str = "delta:acquisition-transition:";
/// Lost dimension: a file has no packet sequence or live clock, so continuity is not observable.
pub const LOST_CONTINUITY_NOT_OBSERVABLE: &str = "continuity_not_observable";
/// Lost dimension: the importer retains source bytes without decoding them.
pub const LOST_FIRST_FRAME_DECODE_NOT_ATTEMPTED: &str = "first_frame_decode_not_attempted";
/// Lost dimension: unparsed source bytes were omitted from every segment.
pub const LOST_SOURCE_BYTES_OMITTED: &str = "source_bytes_omitted";
/// Lost dimension: a truncated frame (no end marker) was omitted.
pub const LOST_TRUNCATED_FRAME_OMITTED: &str = "truncated_frame_omitted";
/// Lost dimension: at least one segment follows a gap.
pub const LOST_SEGMENT_GAP: &str = "segment_gap_before";
/// Lost dimension: the file produced no segment at all.
pub const LOST_NO_SEGMENTS: &str = "no_segments";
/// The negative claim every file session invalidates.
pub const INVALIDATED_ABSENCE: &str = "absence";

const CANONICAL_PREFIX: &str = "fss.canonical.v1";
/// Ceiling on one retained acquisition object (records and witnesses are small).
const MAX_RETAINED_ACQUISITION_OBJECT_BYTES: usize = 64 * 1024;
const MAX_ERROR_MESSAGE_BYTES: usize = 512;

/// How a file acquisition session ended. The core has no "end of source" state kind, so the
/// ending of a `Cancelled` session is carried here, typed, rather than in a free-form note.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileSessionEnding {
    /// The whole file was read and the import completed; the session is `Cancelled` with a
    /// verified quiescence receipt. Never an operator cancel.
    EndOfFileSource,
    /// Cooperative cancellation at the named stage; the session is `Cancelled`.
    OperatorCancel {
        /// Pipeline stage where cancellation was observed.
        stage: String,
    },
    /// The import failed before any capsule batch committed; the session is `Failed`.
    Failed {
        /// Stable failure code carried by the [`FailureWitness`].
        error_code: String,
    },
    /// The capsule batch committed but completion did not; the session is `Indeterminate`
    /// until a resumed import completes it.
    Indeterminate {
        /// Stable failure code that left the completion outcome unknown.
        error_code: String,
    },
    /// The core refused the concluding transition; the session stays in its last legal state.
    Unresolved {
        /// The core refusal.
        detail: String,
    },
}

impl FileSessionEnding {
    /// Stable label of the ending.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EndOfFileSource => "end_of_file_source",
            Self::OperatorCancel { .. } => "operator_cancel",
            Self::Failed { .. } => "failed",
            Self::Indeterminate { .. } => "indeterminate",
            Self::Unresolved { .. } => "unresolved",
        }
    }
}

/// The acquisition lifecycle of one file import: the core session (state and transition
/// history) and its typed ending.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileAcquisitionHistory {
    session: AcquisitionSession,
    ending: FileSessionEnding,
    retained: bool,
}

impl FileAcquisitionHistory {
    /// The core acquisition session.
    #[must_use]
    pub const fn session(&self) -> &AcquisitionSession {
        &self.session
    }

    /// The core transition records, oldest first (the first is `requested → requested`).
    #[must_use]
    pub fn records(&self) -> &[AcquisitionTransitionRecord] {
        self.session.history()
    }

    /// The state kind each record entered, in order.
    #[must_use]
    pub fn kinds(&self) -> Vec<AcquisitionStateKind> {
        self.session.history().iter().map(|r| r.to).collect()
    }

    /// The current (for a concluded session, terminal) state kind.
    #[must_use]
    pub const fn terminal(&self) -> AcquisitionStateKind {
        self.session.state_kind()
    }

    /// The typed ending.
    #[must_use]
    pub const fn ending(&self) -> &FileSessionEnding {
        &self.ending
    }

    /// Whether this history is the one retained in the completing ledger batch.
    #[must_use]
    pub const fn retained(&self) -> bool {
        self.retained
    }

    /// The core absence-claim gate over this session. A file session never reaches
    /// `ContinuityVerified`, so this is always [`AcquisitionError::AbsenceClaimForbidden`].
    ///
    /// # Errors
    /// The core refusal.
    pub fn absence_claim(&self) -> Result<(), AcquisitionError> {
        self.session.check_absence_claim_allowed().map(|_| ())
    }

    /// Comma-separated state kinds, for line-oriented output.
    #[must_use]
    pub fn kinds_text(&self) -> String {
        self.kinds()
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// What a completed import retains of its acquisition lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcquisitionRetention {
    /// The verified, replayed history retained in the completing batch.
    Recorded(Box<FileAcquisitionHistory>),
    /// The completing batch carries no acquisition transitions: the import was completed before
    /// acquisition retention existed. Nothing is inferred about its lifecycle.
    NotRecorded,
}

impl AcquisitionRetention {
    /// The recorded history, if any.
    #[must_use]
    pub fn history(&self) -> Option<&FileAcquisitionHistory> {
        match self {
            Self::Recorded(history) => Some(history),
            Self::NotRecorded => None,
        }
    }

    /// Reopens the retained acquisition history of a completed import from its completing
    /// ledger batch, verifying every object digest and replaying every witness through a fresh
    /// core session.
    ///
    /// # Errors
    /// The import is not complete, a retained object is missing, oversized or mismatched, or the
    /// replay does not reproduce the retained records exactly.
    pub fn open(
        deployment: &ReferenceDeployment,
        import_identity: ContentDigest,
    ) -> Result<Self, FileIngestError> {
        if import_identity.algorithm() != DigestAlgorithm::Sha256 {
            return Err(ContractError::UnsupportedDigestAlgorithm.into());
        }
        let hex = hex(import_identity);
        let batch_id = format!("batch:file-import:{hex}:manifest");
        let batch = deployment
            .ledger()
            .batches()
            .iter()
            .find(|b| b.batch_id.as_str() == batch_id)
            .ok_or_else(|| invalid("completed import authority is absent"))?;
        let prefix = format!("{ACQUISITION_TRANSITION_OBJECT_PREFIX}{hex}:");
        let mut indexed: Vec<(usize, &EvidenceDelta)> = Vec::new();
        for delta in &batch.deltas {
            if delta.family != FAMILY_ACQUISITION_TRANSITION {
                continue;
            }
            let index = delta
                .object_id
                .as_str()
                .strip_prefix(&prefix)
                .and_then(|i| i.parse::<usize>().ok())
                .ok_or_else(|| invalid("acquisition transition of another import"))?;
            if delta.plane != Plane::Authority
                || delta.prior_generation.is_some()
                || delta.new_generation != 1
            {
                return Err(invalid("acquisition transition binding is not a creation"));
            }
            indexed.push((index, delta));
        }
        if indexed.is_empty() {
            return Ok(Self::NotRecorded);
        }
        if indexed.len() > fss_core::MAX_HISTORY_LEN {
            return Err(invalid("acquisition history exceeds the core bound"));
        }
        indexed.sort_by_key(|(index, _)| *index);
        let mut records = Vec::with_capacity(indexed.len());
        let mut witnesses = Vec::with_capacity(indexed.len());
        for (position, (index, delta)) in indexed.iter().enumerate() {
            if *index != position {
                return Err(invalid("acquisition transitions are not contiguous"));
            }
            let witness_digest = delta
                .witness_digest
                .ok_or_else(|| invalid("acquisition transition carries no witness"))?;
            if !batch.children.contains(&delta.payload_digest)
                || !batch.children.contains(&witness_digest)
            {
                return Err(invalid("acquisition objects are not batch children"));
            }
            let record_bytes = read_bounded(deployment, delta.payload_digest)?;
            let record: AcquisitionTransitionRecord = decode_domain(
                &record_bytes,
                SCHEMA_TRANSITION_RECORD,
                delta.payload_digest,
            )?;
            if record.witness_digest != witness_digest {
                return Err(ContractError::DigestMismatch.into());
            }
            let witness_bytes = read_bounded(deployment, witness_digest)?;
            witnesses.push(SessionWitness::decode(
                record.to,
                position == 0,
                &witness_bytes,
                witness_digest,
            )?);
            records.push(record);
        }
        let session = replay(&witnesses, &records)?;
        if session.request().source_identity.source_id.as_str() != format!("src:fi-{hex}") {
            return Err(invalid("acquisition request is bound to another import"));
        }
        if session.history() != records.as_slice() {
            return Err(invalid(
                "replayed acquisition history differs from the retained one",
            ));
        }
        if session.state_kind() != AcquisitionStateKind::Cancelled {
            return Err(invalid(
                "a completed import's acquisition does not end at end_of_file_source",
            ));
        }
        Ok(Self::Recorded(Box::new(FileAcquisitionHistory {
            session,
            ending: FileSessionEnding::EndOfFileSource,
            retained: true,
        })))
    }
}

/// Source facts the degradation evidence is derived from.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FileSourceFacts {
    pub(crate) segments: usize,
    pub(crate) omitted_spans: usize,
    pub(crate) truncated_frames: usize,
    pub(crate) gapped_segments: usize,
}

/// One justifying witness, with its registered canonical domain.
#[derive(Clone, Debug)]
enum SessionWitness {
    Request(Box<AcquisitionRequest>),
    Auth(AuthReceipt),
    Ack(AdapterAck),
    Degradation(DegradationEvidence),
    Failure(FailureWitness),
    Quiescence(QuiescenceReceipt),
    Indeterminate(IndeterminateWitness),
}

impl SessionWitness {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Self::Request(w) => domain_bytes(w.as_ref(), AcquisitionRequest::SCHEMA),
            Self::Auth(w) => domain_bytes(w, AuthReceipt::SCHEMA),
            Self::Ack(w) => domain_bytes(w, AdapterAck::SCHEMA),
            Self::Degradation(w) => domain_bytes(w, DegradationEvidence::SCHEMA),
            Self::Failure(w) => domain_bytes(w, FailureWitness::SCHEMA),
            Self::Quiescence(w) => domain_bytes(w, QuiescenceReceipt::SCHEMA),
            Self::Indeterminate(w) => domain_bytes(w, IndeterminateWitness::SCHEMA),
        }
    }

    fn decode(
        to: AcquisitionStateKind,
        first: bool,
        bytes: &[u8],
        expected: ContentDigest,
    ) -> Result<Self, FileIngestError> {
        Ok(match (first, to) {
            (true, AcquisitionStateKind::Requested) => Self::Request(Box::new(decode_domain(
                bytes,
                AcquisitionRequest::SCHEMA,
                expected,
            )?)),
            (false, AcquisitionStateKind::Authenticated) => {
                Self::Auth(decode_domain(bytes, AuthReceipt::SCHEMA, expected)?)
            }
            (false, AcquisitionStateKind::AdapterAccepted) => {
                Self::Ack(decode_domain(bytes, AdapterAck::SCHEMA, expected)?)
            }
            (false, AcquisitionStateKind::Degraded) => {
                Self::Degradation(decode_domain(bytes, DegradationEvidence::SCHEMA, expected)?)
            }
            (false, AcquisitionStateKind::Failed) => {
                Self::Failure(decode_domain(bytes, FailureWitness::SCHEMA, expected)?)
            }
            (false, AcquisitionStateKind::Cancelled) => {
                Self::Quiescence(decode_domain(bytes, QuiescenceReceipt::SCHEMA, expected)?)
            }
            (false, AcquisitionStateKind::Indeterminate) => Self::Indeterminate(decode_domain(
                bytes,
                IndeterminateWitness::SCHEMA,
                expected,
            )?),
            _ => return Err(invalid("unsupported retained file acquisition transition")),
        })
    }
}

/// Re-drives a fresh core session with the retained witnesses at the retained timestamps.
fn replay(
    witnesses: &[SessionWitness],
    records: &[AcquisitionTransitionRecord],
) -> Result<AcquisitionSession, FileIngestError> {
    let mut steps = witnesses.iter().zip(records);
    let Some((SessionWitness::Request(request), _)) = steps.next() else {
        return Err(invalid(
            "acquisition history does not start with its request",
        ));
    };
    let mut session = AcquisitionSession::new(request.as_ref().clone())?;
    for (witness, record) in steps {
        let at = record.timestamp_ns;
        match witness.clone() {
            SessionWitness::Request(_) => {
                return Err(invalid("acquisition request repeated mid-history"));
            }
            SessionWitness::Auth(w) => session.authenticate(w, at)?,
            SessionWitness::Ack(w) => session.accept(w, at)?,
            SessionWitness::Degradation(w) => session.degrade(w, at)?,
            SessionWitness::Failure(w) => session.fail(w, at)?,
            SessionWitness::Quiescence(w) => session.cancel(w, at)?,
            SessionWitness::Indeterminate(w) => session.mark_indeterminate(w, at)?,
        }
    }
    Ok(session)
}

/// Drives the core session for one import attempt, keeping each record's witness bytes.
#[derive(Clone, Debug)]
pub(crate) struct FileSessionDriver {
    session: AcquisitionSession,
    witnesses: Vec<SessionWitness>,
    at: TimestampNs,
    import_hex: String,
    capsules_committed: bool,
}

/// A proposed end-of-file closing: the `Cancelled` session plus everything that retains it.
#[derive(Clone, Debug)]
pub(crate) struct EndOfFileClosing {
    session: AcquisitionSession,
    /// `(record digest, record bytes, witness digest, witness bytes)` per transition.
    objects: Vec<(ContentDigest, Vec<u8>, ContentDigest, Vec<u8>)>,
}

impl EndOfFileClosing {
    /// Every object the closing stages (records and witnesses).
    pub(crate) fn object_bytes(&self) -> impl Iterator<Item = (ContentDigest, &[u8])> {
        self.objects
            .iter()
            .flat_map(|(rd, rb, wd, wb)| [(*rd, rb.as_slice()), (*wd, wb.as_slice())].into_iter())
    }

    /// One `acquisition_transition` creation delta per record, and the batch children.
    pub(crate) fn deltas(
        &self,
        import_hex: &str,
        validity: CaptureInterval,
    ) -> Result<(Vec<EvidenceDelta>, Vec<ContentDigest>), FileIngestError> {
        let mut deltas = Vec::with_capacity(self.objects.len());
        let mut children = Vec::with_capacity(self.objects.len() * 2);
        for (index, (record_digest, _, witness_digest, _)) in self.objects.iter().enumerate() {
            deltas.push(EvidenceDelta {
                delta_id: format!("{ACQUISITION_TRANSITION_DELTA_PREFIX}{import_hex}:{index:04}"),
                family: FAMILY_ACQUISITION_TRANSITION.to_owned(),
                object_id: ObjectId::parse(format!(
                    "{ACQUISITION_TRANSITION_OBJECT_PREFIX}{import_hex}:{index:04}"
                ))?,
                prior_generation: None,
                new_generation: 1,
                validity,
                plane: Plane::Authority,
                payload_digest: *record_digest,
                witness_digest: Some(*witness_digest),
                operation_id: None,
            });
            children.push(*record_digest);
            children.push(*witness_digest);
        }
        Ok((deltas, children))
    }
}

impl FileSessionDriver {
    /// `Requested → Authenticated` for one import attempt at the ingest arrival time.
    pub(crate) fn open(
        import_identity: ContentDigest,
        import_hex: &str,
        at: TimestampNs,
    ) -> Result<Self, FileIngestError> {
        let adapter_identity = default_adapter_identity()?;
        let source_id = SourceId::parse(format!("src:fi-{import_hex}"))?;
        let device_id = DeviceId::parse(format!("device:fi-{import_hex}"))?;
        let request = AcquisitionRequest {
            source_identity: SourceIdentity {
                source_id,
                device_id: device_id.clone(),
                adapter_id: adapter_identity.adapter_id.clone(),
                source_kind: SourceKind::ImportedArchive,
                media_kind: MediaKind::Video,
                channel: "file".to_owned(),
                nominal_clock_basis: ClockBasis::Estimated,
                stream_generation: StreamGeneration::parse("gen:stream:file-import-v1")?,
                failure_domain: "storage:local-recorded-file".to_owned(),
                is_live: false,
            },
            device_identity: DeviceIdentity {
                device_id,
                generation: DeviceGeneration::parse("gen:device:file-import-v1")?,
                manufacturer: "fss".to_owned(),
                model: "recorded-file-import".to_owned(),
                hardware_revision: "not_applicable".to_owned(),
                firmware_version: FirmwareGeneration::parse("gen:firmware:not-applicable")?,
                application_version: None,
                model_generation: None,
                device_class: DeviceClass::VirtualDevice,
                capabilities: DeviceCapabilities::NONE,
                failure_domain: "storage:local-recorded-file".to_owned(),
            },
            adapter_identity,
            // A bounded file import requests no live or device capability.
            requested_capabilities: AdapterCapabilities::NONE,
            requested_at_ns: at,
        };
        let session = AcquisitionSession::new(request.clone())?;
        let mut driver = Self {
            session,
            witnesses: vec![SessionWitness::Request(Box::new(request))],
            at,
            import_hex: import_hex.to_owned(),
            capsules_committed: false,
        };
        let request = driver.session.request().clone();
        let auth = AuthReceipt {
            adapter_id: request.adapter_identity.adapter_id.clone(),
            device_id: request.device_identity.device_id.clone(),
            method: CredentialMethod::None,
            principal_digest: import_identity,
            authorized_capabilities: request.requested_capabilities,
            authorized_at_ns: at,
            expires_at_ns: at,
        };
        driver.session.authenticate(auth.clone(), at)?;
        driver.witnesses.push(SessionWitness::Auth(auth));
        Ok(driver)
    }

    /// `Authenticated → AdapterAccepted` once the request is admissible.
    pub(crate) fn accept(&mut self) -> Result<(), FileIngestError> {
        let request = self.session.request();
        let ack = AdapterAck {
            adapter_id: request.adapter_identity.adapter_id.clone(),
            request_digest: request.request_digest(),
            ack_timestamp_ns: self.at,
            session_handle: format!("fi-{}", self.import_hex),
            allocated_buffer_frames: 0,
        };
        self.session.accept(ack.clone(), self.at)?;
        self.witnesses.push(SessionWitness::Ack(ack));
        Ok(())
    }

    /// `AdapterAccepted → Degraded`: the file has no observable continuity and was not decoded.
    pub(crate) fn degrade(&mut self, facts: FileSourceFacts) -> Result<(), FileIngestError> {
        let mut lost = vec![
            LOST_CONTINUITY_NOT_OBSERVABLE.to_owned(),
            LOST_FIRST_FRAME_DECODE_NOT_ATTEMPTED.to_owned(),
        ];
        if facts.omitted_spans > 0 {
            lost.push(LOST_SOURCE_BYTES_OMITTED.to_owned());
        }
        if facts.truncated_frames > 0 {
            lost.push(LOST_TRUNCATED_FRAME_OMITTED.to_owned());
        }
        if facts.gapped_segments > 0 {
            lost.push(LOST_SEGMENT_GAP.to_owned());
        }
        if facts.segments == 0 {
            lost.push(LOST_NO_SEGMENTS.to_owned());
        }
        let request = self.session.request();
        let evidence = DegradationEvidence {
            adapter_id: request.adapter_identity.adapter_id.clone(),
            device_id: request.device_identity.device_id.clone(),
            source_id: request.source_identity.source_id.clone(),
            degraded_at_ns: self.at,
            lost_dimensions: lost,
            invalidated_negative_claims: vec![INVALIDATED_ABSENCE.to_owned()],
            observed_packet_loss: 0,
            observed_jitter_ns: 0,
        };
        self.session.degrade(evidence.clone(), self.at)?;
        self.witnesses.push(SessionWitness::Degradation(evidence));
        Ok(())
    }

    /// Marks the capsule batch committed: later failures leave completion indeterminate.
    pub(crate) fn mark_capsules_committed(&mut self) {
        self.capsules_committed = true;
    }

    fn quiescence(&self) -> QuiescenceReceipt {
        let request = self.session.request();
        QuiescenceReceipt {
            adapter_id: request.adapter_identity.adapter_id.clone(),
            device_id: request.device_identity.device_id.clone(),
            source_id: request.source_identity.source_id.clone(),
            cancelled_at_ns: self.at,
            // The file was read into one bounded buffer and its handle closed; no task remains.
            active_tasks: 0,
            open_descriptors: 0,
            buffers_drained: true,
        }
    }

    /// Proposes the end-of-file closing on a copy of the session; the live session moves only
    /// when [`Self::commit_end_of_file`] is called after the completing batch commits.
    pub(crate) fn propose_end_of_file(&self) -> Result<EndOfFileClosing, FileIngestError> {
        let mut session = self.session.clone();
        let mut witnesses = self.witnesses.clone();
        let quiescence = self.quiescence();
        session.cancel(quiescence.clone(), self.at)?;
        witnesses.push(SessionWitness::Quiescence(quiescence));
        if witnesses.len() != session.history().len() {
            return Err(invalid("acquisition witnesses and records are misaligned"));
        }
        let mut objects = Vec::with_capacity(witnesses.len());
        for (witness, record) in witnesses.iter().zip(session.history()) {
            let record_bytes = domain_bytes(record, SCHEMA_TRANSITION_RECORD);
            let witness_bytes = witness.bytes();
            let witness_digest = ContentDigest::sha256(&witness_bytes);
            if witness_digest != record.witness_digest {
                return Err(ContractError::DigestMismatch.into());
            }
            objects.push((
                ContentDigest::sha256(&record_bytes),
                record_bytes,
                witness_digest,
                witness_bytes,
            ));
        }
        Ok(EndOfFileClosing { session, objects })
    }

    /// Adopts the committed end-of-file closing.
    pub(crate) fn commit_end_of_file(self, closing: EndOfFileClosing) -> FileAcquisitionHistory {
        FileAcquisitionHistory {
            session: closing.session,
            ending: FileSessionEnding::EndOfFileSource,
            retained: true,
        }
    }

    /// Concludes a failed attempt through the core: cooperative cancellation ends `Cancelled`,
    /// a failure after the capsule batch committed ends `Indeterminate`, any other failure ends
    /// `Failed`. Nothing is retained.
    pub(crate) fn conclude_error(mut self, error: &FileIngestError) -> FileAcquisitionHistory {
        let request = self.session.request().clone();
        let adapter_id = request.adapter_identity.adapter_id.clone();
        let device_id = request.device_identity.device_id.clone();
        let source_id = request.source_identity.source_id.clone();
        let code = error_code(error);
        let (outcome, ending) = if let Some(stage) = cancellation_stage(error) {
            let quiescence = self.quiescence();
            (
                self.session.cancel(quiescence, self.at),
                FileSessionEnding::OperatorCancel { stage },
            )
        } else if self.capsules_committed {
            let witness = IndeterminateWitness {
                adapter_id,
                device_id,
                source_id,
                indeterminate_at_ns: self.at,
                reason: bounded(&format!(
                    "capsule batch committed; import completion not committed ({code})"
                )),
                unresolved_obligations: vec![format!("resume_file_import:{}", self.import_hex)],
            };
            (
                self.session.mark_indeterminate(witness, self.at),
                FileSessionEnding::Indeterminate {
                    error_code: code.to_owned(),
                },
            )
        } else {
            let failure = FailureWitness {
                adapter_id,
                device_id,
                source_id,
                failed_at_ns: self.at,
                error_code: code.to_owned(),
                error_message: bounded(&error.to_string()),
                retryable: matches!(
                    error,
                    FileIngestError::Io(_) | FileIngestError::SpoolCapacityExceeded { .. }
                ),
            };
            (
                self.session.fail(failure, self.at),
                FileSessionEnding::Failed {
                    error_code: code.to_owned(),
                },
            )
        };
        let ending = match outcome {
            Ok(()) => ending,
            Err(refusal) => FileSessionEnding::Unresolved {
                detail: refusal.to_string(),
            },
        };
        FileAcquisitionHistory {
            session: self.session,
            ending,
            retained: false,
        }
    }
}

fn cancellation_stage(error: &FileIngestError) -> Option<String> {
    match error {
        FileIngestError::CancellationRequested { stage } => Some((*stage).to_owned()),
        FileIngestError::Reference(crate::error::ReferenceError::CancellationRequested {
            stage,
        }) => Some((*stage).to_owned()),
        _ => None,
    }
}

/// Stable, secret-free failure code of an import error.
fn error_code(error: &FileIngestError) -> &'static str {
    match error {
        FileIngestError::SymlinkNotAllowed { .. } => "symlink_not_allowed",
        FileIngestError::NotRegularFile { .. } => "not_regular_file",
        FileIngestError::EmptyFile { .. } => "empty_file",
        FileIngestError::FileTooLarge { .. } => "file_too_large",
        FileIngestError::SpoolCapacityExceeded { .. } => "spool_capacity_exceeded",
        FileIngestError::FormatConflict { .. } => "format_conflict",
        FileIngestError::UnknownFormat { .. } => "unknown_format",
        FileIngestError::AmbiguousAnnexBCodec { .. } => "ambiguous_annexb_codec",
        FileIngestError::UnsupportedFormat { .. } => "unsupported_format",
        FileIngestError::RtpBindingRequired {} => "rtp_binding_required",
        FileIngestError::RecordedRtp(_) => "recorded_rtp_import_refused",
        FileIngestError::CaptureHintAfterReceive { .. } => "capture_hint_after_receive",
        FileIngestError::CaptureHintLatestAfterReceive { .. } => {
            "capture_hint_latest_after_receive"
        }
        FileIngestError::InvalidCaptureHint { .. } => "invalid_capture_hint",
        FileIngestError::MissingReceiveTime {} => "missing_receive_time",
        FileIngestError::InvalidLimits { .. } => "invalid_limits",
        FileIngestError::ImportPlanConflict { .. } => "import_plan_conflict",
        FileIngestError::SegmentDigestMismatch { .. } => "segment_digest_mismatch",
        FileIngestError::CustodyUnavailable { .. } => "custody_unavailable",
        FileIngestError::SegmentIndexOutOfBounds { .. } => "segment_index_out_of_bounds",
        FileIngestError::CorruptSegment { .. } => "corrupt_segment",
        FileIngestError::EvidenceDeleted { .. } => "evidence_deleted",
        FileIngestError::CancellationRequested { .. } => "cancellation_requested",
        FileIngestError::Acquisition(_) => "acquisition_refused",
        FileIngestError::Io(_) => "io_error",
        FileIngestError::Reference(_) => "reference_error",
        FileIngestError::Contract(_) => "contract_error",
        FileIngestError::AnnexB(_) => "annexb_malformed",
        FileIngestError::Mjpeg(_) => "mjpeg_malformed",
        FileIngestError::LocalPublication(_) => "local_publication_error",
        FileIngestError::Spool(_) => "spool_error",
        FileIngestError::Object(_) => "object_error",
    }
}

fn bounded(text: &str) -> String {
    let mut end = text.len().min(MAX_ERROR_MESSAGE_BYTES);
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let out = text.get(..end).unwrap_or_default();
    if out.is_empty() {
        "unspecified".to_owned()
    } else {
        out.to_owned()
    }
}

fn domain_bytes<T: CanonicalEncode + ?Sized>(value: &T, domain: &str) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(CANONICAL_PREFIX);
    encoder.text(domain);
    value.encode_canonical(&mut encoder);
    encoder.finish()
}

fn decode_domain<T: CanonicalDecode>(
    bytes: &[u8],
    domain: &str,
    expected: ContentDigest,
) -> Result<T, FileIngestError> {
    if ContentDigest::sha256(bytes) != expected {
        return Err(ContractError::DigestMismatch.into());
    }
    let mut decoder = CanonicalDecoder::new(bytes);
    if decoder.text()? != CANONICAL_PREFIX || decoder.text()? != domain {
        return Err(invalid("unexpected acquisition object domain"));
    }
    let value = T::decode_canonical(&mut decoder)?;
    decoder.ensure_finished()?;
    Ok(value)
}

fn read_bounded(
    deployment: &ReferenceDeployment,
    digest: ContentDigest,
) -> Result<Vec<u8>, FileIngestError> {
    let bytes = deployment.publisher().spool().read(digest)?;
    if bytes.len() > MAX_RETAINED_ACQUISITION_OBJECT_BYTES {
        return Err(invalid("retained acquisition object exceeds its ceiling"));
    }
    Ok(bytes)
}

fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}

fn invalid(detail: &str) -> FileIngestError {
    FileIngestError::CorruptSegment {
        detail: format!("retained acquisition: {detail}"),
    }
}
