#![forbid(unsafe_code)]
//! Root-last publication through an explicitly supplied, already-open local owner.

use super::*;
use fss_object::SpoolError;
use fss_publication::{LocalPublicationError, LocalPublicationReceipt, LocalPublicationState,
    LocalRootPublisher, PublishCancellation, PublishCutPoint, SlotName};

type IoResult<T> = std::result::Result<T, RecordingIoError>;

/// Storage errors preserve the existing publisher's typed indeterminacy and repair
/// guidance. Debug/Display do not print its filesystem paths or recording bytes.
pub enum RecordingIoError {
    /// Byte/provenance/canonical validation failed.
    Content(RecordingError),
    /// The existing rooted publication owner refused or could not settle an I/O operation.
    Publication(LocalPublicationError),
    /// Verified source/object retrieval failed.
    Spool(SpoolError),
    /// The sealed bytes exceed the supplied reservation or owner object bounds.
    Budget,
    /// The caller's supplied admission deadline was reached.
    Deadline,
    /// Supplied monotonic time moved backwards.
    ClockReversed,
    /// Cancellation stopped this request; no existing root or prior commit is retracted.
    Cancelled,
    /// A cancelled/expired job cannot admit more I/O; use a newly authorized attempt.
    Stopped,
    /// A previous ambiguous effect requires reopening the existing owner for reconciliation.
    ReopenRequired,
    /// The selected slot does not currently prove a durable root.
    NotDurable,
    /// The selected slot names a different immutable root.
    RootConflict,
    /// A root or child has a durable tombstone; do not rehydrate it.
    Tombstoned,
}
impl std::fmt::Debug for RecordingIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Content(e) => f.debug_tuple("Content").field(e).finish(),
            Self::Publication(e) => f.debug_tuple("Publication").field(&e.code()).finish(),
            Self::Spool(_) => f.write_str("Spool"),
            Self::Budget => f.write_str("Budget"), Self::Deadline => f.write_str("Deadline"),
            Self::ClockReversed => f.write_str("ClockReversed"), Self::Cancelled => f.write_str("Cancelled"),
            Self::Stopped => f.write_str("Stopped"), Self::ReopenRequired => f.write_str("ReopenRequired"),
            Self::NotDurable => f.write_str("NotDurable"), Self::RootConflict => f.write_str("RootConflict"),
            Self::Tombstoned => f.write_str("Tombstoned"),
        }
    }
}
impl std::fmt::Display for RecordingIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "recording I/O refusal: {self:?}") }
}
impl std::error::Error for RecordingIoError {}

/// One bounded visible publication step. A staged child is never an archived root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordingProgress {
    /// One complete original/derived child was staged and verified by the spool.
    ChildStaged {
        /// Exact child's typed role.
        role: RecordingRole,
        /// Exact content-addressed child.
        digest: ContentDigest,
        /// Child payload size, not total filesystem overhead.
        bytes: usize,
        /// Number of children not yet staged by this attempt.
        remaining: usize,
    },
    /// Actual publisher receipt, including replay/indeterminacy distinctions and unclaimed rungs.
    Published(LocalPublicationReceipt),
    /// This job already returned its receipt; no new verification or I/O took place.
    Complete,
}

/// Request-owned bounded publication cursor. It cannot switch filesystem owners,
/// slots, bytes, or deadlines mid-attempt. Dropping it leaves existing staged
/// custody for explicit reconciliation; it never deletes source or publishes Drop.
pub struct RecordingPublication<'a> {
    plan: &'a PreparedRecording,
    publisher: &'a mut LocalRootPublisher,
    slot: SlotName,
    deadline_ns: u64,
    last_ns: Option<u64>,
    next_child: usize,
    stopped: bool,
    done: bool,
}
impl std::fmt::Debug for RecordingPublication<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingPublication").field("root", &self.plan.manifest.root())
            .field("next_child", &self.next_child).field("stopped", &self.stopped)
            .field("done", &self.done).finish_non_exhaustive()
    }
}
impl<'a> RecordingPublication<'a> {
    /// Admit exact bytes to an already-open, explicitly supplied rooted I/O owner.
    /// This is a reference composition, not a grant of network/export/crypto authority.
    /// The byte reservation includes all child payloads and the manifest; filesystem
    /// overhead/capacity remain governed by the underlying spool's own quotas.
    pub fn new(plan: &'a PreparedRecording, publisher: &'a mut LocalRootPublisher,
        slot: SlotName, reserved_bytes: usize, deadline_ns: u64) -> IoResult<Self>
    {
        if deadline_ns == 0 || plan.byte_len() > reserved_bytes || publisher.limits().max_children < 4
            || plan.children().iter().any(|(_, _, b)| b.len() > publisher.limits().spool.max_object_bytes)
            || plan.manifest.canonical_bytes().len() > publisher.limits().spool.max_object_bytes {
            return Err(RecordingIoError::Budget);
        }
        if publisher.is_poisoned() { return Err(RecordingIoError::ReopenRequired); }
        if publisher.root(&slot).is_some_and(|root| root.root != plan.manifest.root()) {
            return Err(RecordingIoError::RootConflict);
        }
        Ok(Self { plan, publisher, slot, deadline_ns, last_ns: None, next_child: 0, stopped: false, done: false })
    }

    /// Perform at most one child stage or the existing root-last commit. Cancellation
    /// is also passed through to the publisher's pre-commit cut points; it cannot
    /// retract a committed root. now_ns controls entry admission, not elapsed syscall
    /// time. The caller's cancellation probe must enforce live deadline/revocation
    /// checks at the publisher's cut points when driven by a real runtime.
    pub fn step(&mut self, now_ns: u64, cancel: &dyn PublishCancellation) -> IoResult<RecordingProgress> {
        if self.done { return Ok(RecordingProgress::Complete); }
        if self.stopped { return Err(RecordingIoError::Stopped); }
        if self.last_ns.is_some_and(|last| now_ns < last) { return Err(RecordingIoError::ClockReversed); }
        self.last_ns = Some(now_ns);
        if now_ns >= self.deadline_ns { self.stopped = true; return Err(RecordingIoError::Deadline); }
        if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
            self.stopped = true; return Err(RecordingIoError::Cancelled);
        }
        if self.publisher.is_poisoned() { return Err(RecordingIoError::ReopenRequired); }
        if self.publisher.root(&self.slot).is_some_and(|r| r.root != self.plan.manifest.root()) {
            return Err(RecordingIoError::RootConflict);
        }
        let already_durable = self.publisher.root(&self.slot)
            .is_some_and(|r| r.state == LocalPublicationState::Durable);
        if !already_durable && self.next_child < 4 {
            let (role, digest, bytes) = self.plan.children()[self.next_child];
            let observed = self.publisher.stage_object(bytes).map_err(RecordingIoError::Publication)?;
            if observed != digest { return Err(RecordingIoError::Content(RecordingError::Digest)); }
            self.next_child += 1;
            return Ok(RecordingProgress::ChildStaged { role, digest, bytes: bytes.len(), remaining: 4 - self.next_child });
        }
        // Existing roots are reverified by the publisher. A lost receipt never
        // causes remux, a different root, overwrite, or an invented terminal state.
        let receipt = match self.publisher.publish_cancellable(&self.slot, &self.plan.manifest, cancel) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.stopped = true;
                return Err(RecordingIoError::Publication(error));
            }
        };
        self.done = true;
        Ok(RecordingProgress::Published(receipt))
    }
}

/// Retrieve an exact durable slot/root through its existing bounded owner. Read
/// and rehash every child, then reconstruct source NALs and verify the canonical
/// maps before returning any media. No raw paths, directory listings or ambient
/// object discovery are used. A point-in-time read is not a retained future
/// retrievability guarantee. The owner separately authorizes source disclosure.
pub fn load_recording(publisher: &LocalRootPublisher, slot: &SlotName,
    expected_root: ContentDigest, scope: &RecordingScope, cancel: &dyn PublishCancellation)
    -> IoResult<PreparedRecording>
{
    load_window(publisher, slot, expected_root, scope, cancel, WindowFormat {
        kind: RECORDING_KIND, references: avc_references, verify: verify_recording,
    })
}

// Only codec-owned entrypoints inside recording may choose a format. There is
// no public verifier callback or mutable prepared-plan constructor bypass.
pub(super) struct WindowFormat {
    pub kind: &'static str,
    pub references: fn(&[u8]) -> Result<(RecordingScope, [ContentDigest; 3])>,
    pub verify: fn(&ObjectManifest, RecordingObjects<'_>, &RecordingScope) -> Result<RecordingSummary>,
}
fn avc_references(bytes: &[u8]) -> Result<(RecordingScope, [ContentDigest; 3])> {
    let index = wire::decode_index(bytes)?;
    Ok((index.scope, [index.source, index.initialization, index.media]))
}

// Shared storage admission/rehydration: every format still supplies its real
// complete semantic verifier before any bytes can leave as a prepared recording.
pub(super) fn load_window(publisher: &LocalRootPublisher, slot: &SlotName,
    expected_root: ContentDigest, scope: &RecordingScope, cancel: &dyn PublishCancellation,
    format: WindowFormat) -> IoResult<PreparedRecording>
{
    if publisher.is_poisoned() { return Err(RecordingIoError::ReopenRequired); }
    let root = publisher.root(slot).ok_or(RecordingIoError::NotDurable)?;
    if root.root != expected_root { return Err(RecordingIoError::RootConflict); }
    if root.state != LocalPublicationState::Durable { return Err(RecordingIoError::NotDurable); }
    // The spool caps allocation before reading. Refuse a more permissive owner
    // rather than claim this API imposed a smaller bound after a large allocation.
    if publisher.limits().spool.max_object_bytes > MAX_RECORDING_BYTES { return Err(RecordingIoError::Budget); }
    let mut total = 0_usize;
    let mut read = |digest| -> IoResult<Vec<u8>> {
        if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) { return Err(RecordingIoError::Cancelled); }
        if publisher.tombstones().any(|d| *d == digest) { return Err(RecordingIoError::Tombstoned); }
        let bytes = publisher.spool().read(digest).map_err(RecordingIoError::Spool)?;
        total = total.checked_add(bytes.len()).ok_or(RecordingIoError::Budget)?;
        if total > MAX_RECORDING_BYTES { return Err(RecordingIoError::Budget); }
        Ok(bytes)
    };
    let manifest_bytes = read(expected_root)?;
    let manifest = ObjectManifest::from_canonical_bytes(&manifest_bytes)
        .map_err(|_| RecordingIoError::Content(RecordingError::Malformed))?;
    if manifest.root() != expected_root || manifest.kind() != format.kind || manifest.children().len() != 4 {
        return Err(RecordingIoError::Content(RecordingError::Digest));
    }
    let index_digest = manifest.metadata_digest().ok_or(RecordingIoError::Content(RecordingError::Malformed))?;
    let index_bytes = read(index_digest)?;
    let (indexed_scope, [source_digest, initialization_digest, media_digest]) =
        (format.references)(&index_bytes).map_err(RecordingIoError::Content)?;
    if &indexed_scope != scope { return Err(RecordingIoError::Content(RecordingError::Scope)); }
    let expected = ObjectManifest::new(format.kind, [source_digest, initialization_digest, media_digest], Some(index_digest))
        .map_err(|_| RecordingIoError::Content(RecordingError::Digest))?;
    if expected != manifest { return Err(RecordingIoError::Content(RecordingError::Digest)); }
    let source = read(source_digest)?;
    let initialization = read(initialization_digest)?;
    let media = read(media_digest)?;
    let objects = RecordingObjects { source: &source, initialization: &initialization, media: &media, index: &index_bytes };
    let summary = (format.verify)(&manifest, objects, scope).map_err(RecordingIoError::Content)?;
    // A cancellation/revocation observed after bounded semantic replay still
    // prevents disclosure. It never retracts or deletes the durable source root.
    if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) { return Err(RecordingIoError::Cancelled); }
    Ok(PreparedRecording { manifest, source, initialization, media, index: index_bytes, summary })
}
