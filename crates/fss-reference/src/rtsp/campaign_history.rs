#![forbid(unsafe_code)]
//! Durable finite RTSP campaign observations through the existing root-last publisher.
//!
//! A start is retained before camera work and its native finish before any successor. A separate
//! terminal records the controller's final result. A selected prefix says nothing about later
//! attempts or the latest state: a start without a selected finish is an unknown outcome, not
//! proof of interruption, no footage, or no later activity. Native bindings are exact recorded
//! observations; verifying this metadata does not reverify an external recording/source archive.

mod plan;
mod read_io;
mod record;
mod storage;

use std::path::Path;

use fss_core::{CanonicalEncode, ContentDigest, ContractError, DigestAlgorithm};
use fss_geometry::{GeometryError, WorkBudget};
use fss_publication::{LocalRootPublisher, PublishCancellation, PublishCutPoint, SlotName};

use super::archive_pins::ArchivePinAnchor;
use crate::ReplayCx;

pub use plan::{
    CampaignAttempt, CampaignHistoryLimits, CampaignPlan, CampaignSourceBinding,
    MAX_CAMPAIGN_ATTEMPTS, MAX_CAMPAIGN_RECORDS,
};
use record::{CampaignRecord, Transition};
pub use storage::VerifiedCampaignHistory;

/// Current authority is rechecked before I/O, at publication cuts and before disclosure.
pub const STAGE_CAMPAIGN_HISTORY: &str = "rtsp_campaign_history:authority";
/// Cooperative boundary before each immutable root publication.
pub const STAGE_CAMPAIGN_APPEND: &str = "rtsp_campaign_history:append";
/// Cooperative boundary before disclosing a verified selected prefix.
pub const STAGE_CAMPAIGN_RELEASE: &str = "rtsp_campaign_history:release";
/// Maximum ordered native catalog bindings retained per attempt, independent of JSON output.
pub const MAX_CAMPAIGN_CATALOGS: usize = 1024;
type Result<T> = std::result::Result<T, CampaignHistoryError>;

/// Independently saved exact prefix. Possession does not grant read or acquisition authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CampaignPin {
    /// Original outer acquisition approval.
    pub approval: ContentDigest,
    /// Canonical frozen plan object digest.
    pub plan: ContentDigest,
    /// Exact last selected transition manifest root.
    pub root: ContentDigest,
    /// Number of selected transition records, including starts and any terminal.
    pub records: u32,
}
impl CampaignPin {
    /// Reject unsupported digest kinds, empty identities and impossible prefix lengths.
    pub fn validate(self) -> Result<()> {
        if !sha(self.approval)
            || !sha(self.plan)
            || !sha(self.root)
            || !(1..=MAX_CAMPAIGN_RECORDS).contains(&self.records)
        {
            return Err(CampaignHistoryError::Configuration);
        }
        Ok(())
    }
}

/// Metadata disclosure and retention remain separate capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CampaignOperation {
    /// Read this independently selected immutable metadata prefix.
    Read,
    /// Retain a boundary supplied by the current native capture/controller owner.
    Retain,
}

/// Explicit current principal, path, approval, capability, revocation and deadline policy.
/// A native adapter supplies typed observations directly; untrusted JSON is never a constructor.
pub trait CampaignAuthority: Send + Sync {
    /// Check the exact frozen plan at every access boundary; there is no default grant.
    fn permit(&self, operation: CampaignOperation, plan: &CampaignPlan) -> bool;
    /// Check read authority before loading the plan object, including the exact selected pin.
    fn permit_read(&self, _expected: CampaignPin, _root: &Path, _principal: &str) -> bool {
        false
    }
}

/// Original native classification. It is independent of human error text and controller output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CampaignRetryReason {
    /// The native connection owner could not establish the authorized source.
    ConnectionUnavailable,
    /// Input ended with fewer pictures than approved.
    SourceEnded,
    /// Explicit progress supervision observed a source stall.
    ProgressStalled,
    /// A sealed source-read interruption, only retryable under separate approval.
    ReadInterrupted,
    /// Native capture, archive publication and control ownership all settled successfully.
    SettledSuccess,
}

/// One exact catalog manifest identity observed by the native recording owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignCatalogBinding {
    /// Native immutable publisher slot, in native page order.
    pub slot: String,
    /// Native catalog manifest root, not a snapshot inventory digest.
    pub root: ContentDigest,
}

/// Exact native original-datagram prefix observation. It does not prove present retrievability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CampaignSourcePin {
    /// Native source scope digest.
    pub scope: ContentDigest,
    /// Native last datagram root, or exactly `scope` for an empty prefix.
    pub head: ContentDigest,
    /// Count of native source observations, not pictures or RTP sequence numbers.
    pub datagrams: u64,
    /// Sum of original payload lengths; retransmitted observations are counted separately.
    pub bytes: u64,
}

/// Exact identities retained from native typed owners. No custody is fabricated from strings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NativeBindings {
    /// Deterministic native snapshot inventory identity; this is NOT a published root/head.
    pub snapshot_digest: Option<ContentDigest>,
    /// Exact independent native pin-journal sequence and hash anchor.
    pub journal_anchor: Option<ArchivePinAnchor>,
    /// Exact observed catalog roots and slots in native page order.
    pub catalogs: Vec<CampaignCatalogBinding>,
    /// Exact typed native source prefix, when that owner was available.
    pub source_pin: Option<CampaignSourcePin>,
}

/// Native acquisition result captured before rendering terminal output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeAttemptObservation {
    /// The native owner returned completion, separate from controller/output success.
    pub complete: bool,
    /// Payload-free stable native failure identity; absent precisely on native completion.
    pub error_id: Option<String>,
    /// Native retry classification; no error-string inference is permitted.
    pub retry: Option<CampaignRetryReason>,
    /// Native durable picture count, not an assertion of continuous camera coverage.
    pub durable_pictures: u64,
    /// Native unresolved custody/publication/control work prevents every successor.
    pub recovery_required: bool,
    /// Native snapshot/catalog/pin/source observations, including available partial custody.
    pub bindings: NativeBindings,
}

/// One finished owner call. Missing native observation preserves unknown counts and custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignFinish {
    /// Direct native observation, or explicitly unavailable after a controller/driver failure.
    pub native: Option<NativeAttemptObservation>,
    /// Controller or output failure distinct from the native owner's own error identity.
    pub controller_error: Option<String>,
    /// Native settlement plus the independently approved picture rule passed.
    pub settled_success: bool,
    /// A successor was planned; this is NOT evidence that it actually started.
    pub next_attempt_planned: bool,
}

/// Separate controller terminal. The owner derives and verifies it from the retained finishes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignTerminal {
    /// Whether this campaign's frozen completion predicate passed.
    pub complete: bool,
    /// Payload-free stable failure identity, absent exactly on successful completion.
    pub error_id: Option<String>,
}

/// Historical failure retained by a verified continuation. It cannot authorize a retry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignPriorFailure {
    ordinal: u32,
    error_id: String,
}
impl CampaignPriorFailure {
    /// Original one-based attempt, never renumbered after restart.
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }
    /// Exact original native/controller failure identity.
    pub fn error_id(&self) -> &str {
        &self.error_id
    }
}

/// Bounded totals derived from the owner's verified finished prefix, not caller counters.
/// This is an observation; current authority and `start_attempt` still gate every successor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignContinuationSummary {
    completed_attempts: u32,
    remaining_attempts: u32,
    durable_pictures: u64,
    successful_attempts: u32,
    first_failure: Option<CampaignPriorFailure>,
}
impl CampaignContinuationSummary {
    /// Number of original attempts whose finishes are retained.
    pub const fn completed_attempts(&self) -> u32 {
        self.completed_attempts
    }
    /// Unused attempts in the original immutable schedule.
    pub const fn remaining_attempts(&self) -> u32 {
        self.remaining_attempts
    }
    /// Sum of the native durable-picture observations, without a continuity claim.
    pub const fn durable_pictures(&self) -> u64 {
        self.durable_pictures
    }
    /// Number of settled successful attempts, excluding every partial or failed capture.
    pub const fn successful_attempts(&self) -> u32 {
        self.successful_attempts
    }
    /// First exact original failure, even when later retained attempts succeeded.
    pub fn first_failure(&self) -> Option<&CampaignPriorFailure> {
        self.first_failure.as_ref()
    }
}

/// One selected start and optional selected native finish. Later activity remains unknown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignAttemptHistory {
    /// Exact predeclared attempt, never inferred from a directory listing.
    pub attempt: CampaignAttempt,
    /// Independently addressable start boundary.
    pub start: CampaignPin,
    /// `None` means `started_without_retained_finish` in this selected prefix.
    pub finish: Option<CampaignFinish>,
    /// Exact finish root when included in this selection.
    pub finish_pin: Option<CampaignPin>,
}

/// A refusal never permits acquisition, repair, an unrecorded successor, or a wider retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CampaignHistoryError {
    /// Invalid plan, identity, destination, pin or resource reservation.
    Configuration,
    /// A transition, parent, plan, expected pin or native binding disagrees.
    Mismatch,
    /// Noncanonical, unsupported, corrupt or incomplete metadata.
    Metadata,
    /// A previous campaign already used this approval namespace, including an empty attempt.
    Occupied,
    /// Missing, broken, visible-only or poisoned live publication.
    NotDurable,
    /// A required selected root, plan or metadata object has a tombstone.
    Tombstoned,
    /// Storage could not retain or verify the exact selected bytes.
    Storage,
    /// Independent allocation, total metadata, scan or shared work allowance was exceeded.
    Limit,
    /// Current authority, deadline, cancellation or scoped execution context refused.
    Denied,
    /// A failed append must be retried exactly before any different transition.
    Pending,
}
impl CampaignHistoryError {
    /// Stable payload-free failure identity, safe for machine output and retained diagnostics.
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::Configuration => "ERR-CAPTURE-RTSP-HISTORY-REQUEST-001",
            Self::Mismatch | Self::Metadata => "ERR-CAPTURE-RTSP-HISTORY-METADATA-001",
            Self::Occupied => "ERR-CAPTURE-RTSP-HISTORY-OCCUPIED-001",
            Self::NotDurable | Self::Storage => "ERR-CAPTURE-RTSP-HISTORY-STORAGE-001",
            Self::Tombstoned => "ERR-CAPTURE-RTSP-HISTORY-TOMBSTONED-001",
            Self::Limit => "ERR-CAPTURE-RTSP-HISTORY-LIMIT-001",
            Self::Denied => "ERR-CAPTURE-RTSP-HISTORY-AUTHORITY-001",
            Self::Pending => "ERR-CAPTURE-RTSP-HISTORY-PENDING-001",
        }
    }
}
impl std::fmt::Display for CampaignHistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.stable_id())
    }
}
impl std::error::Error for CampaignHistoryError {}
impl From<ContractError> for CampaignHistoryError {
    fn from(_: ContractError) -> Self {
        Self::Metadata
    }
}
impl From<GeometryError> for CampaignHistoryError {
    fn from(error: GeometryError) -> Self {
        if matches!(error, GeometryError::Cancelled) {
            Self::Denied
        } else {
            Self::Limit
        }
    }
}

pub(super) fn sha(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256 && digest.bytes() != [0; 32]
}
fn error_valid(value: &str) -> bool {
    value.starts_with("ERR-")
        && value.len() <= 128
        && value.len() > 4
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

pub(super) fn check(
    authority: &dyn CampaignAuthority,
    operation: CampaignOperation,
    plan: &CampaignPlan,
    root: &Path,
    cx: &ReplayCx,
) -> Result<()> {
    if cx.checkpoint(STAGE_CAMPAIGN_HISTORY).is_err()
        || !cx.io_authority().is_valid()
        || cx.io_authority().principal() != plan.principal
        || cx.root_dir() != root
        || Path::new(&plan.history_path) != root
        || !authority.permit(operation, plan)
    {
        return Err(CampaignHistoryError::Denied);
    }
    Ok(())
}

struct Access<'a> {
    authority: &'a dyn CampaignAuthority,
    operation: CampaignOperation,
    plan: &'a CampaignPlan,
    root: &'a Path,
    cx: &'a ReplayCx,
}
impl PublishCancellation for Access<'_> {
    fn cancel_requested(&self, _point: PublishCutPoint) -> bool {
        check(
            self.authority,
            self.operation,
            self.plan,
            self.root,
            self.cx,
        )
        .is_err()
    }
}

fn validate_finish(plan: &CampaignPlan, ordinal: u32, finish: &CampaignFinish) -> Result<()> {
    let attempt = plan
        .attempts
        .get(
            ordinal
                .checked_sub(1)
                .ok_or(CampaignHistoryError::Mismatch)? as usize,
        )
        .ok_or(CampaignHistoryError::Mismatch)?;
    if finish
        .controller_error
        .as_deref()
        .is_some_and(|error| !error_valid(error))
    {
        return Err(CampaignHistoryError::Metadata);
    }
    let Some(native) = &finish.native else {
        return if finish.controller_error.is_some()
            && !finish.settled_success
            && !finish.next_attempt_planned
        {
            Ok(())
        } else {
            Err(CampaignHistoryError::Mismatch)
        };
    };
    if native.complete != native.error_id.is_none()
        || native
            .error_id
            .as_deref()
            .is_some_and(|error| !error_valid(error))
        || (native.recovery_required && native.retry.is_some())
        || (native.retry == Some(CampaignRetryReason::SettledSuccess) && !native.complete)
        || (native.complete
            && native
                .retry
                .is_some_and(|reason| reason != CampaignRetryReason::SettledSuccess))
    {
        return Err(CampaignHistoryError::Mismatch);
    }
    let bindings = &native.bindings;
    if bindings.snapshot_digest.is_some_and(|digest| !sha(digest))
        || bindings
            .journal_anchor
            .is_some_and(|anchor| anchor.sequence == 0 || !sha(anchor.root))
        || bindings.catalogs.len() > MAX_CAMPAIGN_CATALOGS
    {
        return Err(CampaignHistoryError::Metadata);
    }
    let mut slots = std::collections::BTreeSet::new();
    let mut roots = std::collections::BTreeSet::new();
    for catalog in &bindings.catalogs {
        if SlotName::parse(&catalog.slot).is_err()
            || !sha(catalog.root)
            || !slots.insert(&catalog.slot)
            || !roots.insert(catalog.root)
        {
            return Err(CampaignHistoryError::Metadata);
        }
    }
    if let Some(pin) = bindings.source_pin {
        if !sha(pin.scope) || !sha(pin.head)
            || attempt.source.as_ref().is_none_or(|source| source.scope != pin.scope)
            || (pin.datagrams == 0 && (pin.head != pin.scope || pin.bytes != 0))
            // The native source owner retains malformed zero-byte datagrams too. A nonempty
            // observed prefix can therefore have zero payload bytes without being an empty pin.
            || (pin.datagrams != 0 && pin.head == pin.scope)
        {
            return Err(CampaignHistoryError::Mismatch);
        }
    }
    let picture_valid = native.durable_pictures != 0
        && if plan.duration_limited {
            native.durable_pictures <= attempt.picture_ceiling
        } else {
            native.durable_pictures == attempt.picture_ceiling
        };
    if native.complete
        && (!picture_valid || native.recovery_required)
        && finish.controller_error.is_none()
    {
        return Err(CampaignHistoryError::Mismatch);
    }
    let settled = native.complete
        && picture_valid
        && !native.recovery_required
        && native.retry == Some(CampaignRetryReason::SettledSuccess)
        && finish.controller_error.is_none();
    if finish.settled_success != settled
        || (settled && (bindings.snapshot_digest.is_none() || bindings.journal_anchor.is_none()))
    {
        return Err(CampaignHistoryError::Mismatch);
    }
    let retry = !native.complete
        && !native.recovery_required
        && match native.retry {
            Some(CampaignRetryReason::ConnectionUnavailable | CampaignRetryReason::SourceEnded) => {
                true
            }
            Some(CampaignRetryReason::ProgressStalled) => plan.progress_supervised,
            Some(CampaignRetryReason::ReadInterrupted) => {
                plan.retry_interrupted
                    && native.error_id.as_deref() == Some("ERR-CAPTURE-RTSP-SOURCE-001")
                    && native.durable_pictures > 0
                    && native.durable_pictures <= attempt.picture_ceiling
            }
            _ => false,
        };
    let next = finish.controller_error.is_none()
        && ordinal < plan.attempts.len() as u32
        && (retry || (plan.continue_after_success && settled));
    if finish.next_attempt_planned != next {
        return Err(CampaignHistoryError::Mismatch);
    }
    Ok(())
}

fn finish_error(finish: &CampaignFinish) -> Option<&str> {
    finish.controller_error.as_deref().or_else(|| {
        finish
            .native
            .as_ref()
            .and_then(|native| native.error_id.as_deref())
    })
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct HistoryState {
    attempts: Vec<CampaignAttemptHistory>,
    terminal: Option<CampaignTerminal>,
}
impl HistoryState {
    fn advance(
        &mut self,
        plan: &CampaignPlan,
        record: &CampaignRecord,
        pin: CampaignPin,
    ) -> Result<()> {
        if self.terminal.is_some() {
            return Err(CampaignHistoryError::Mismatch);
        }
        match &record.transition {
            Transition::Start(ordinal) => {
                if *ordinal != self.attempts.len() as u32 + 1
                    || self.attempts.last().is_some_and(|prior| {
                        prior
                            .finish
                            .as_ref()
                            .is_none_or(|finish| !finish.next_attempt_planned)
                    })
                {
                    return Err(CampaignHistoryError::Mismatch);
                }
                let attempt = plan
                    .attempts
                    .get(*ordinal as usize - 1)
                    .ok_or(CampaignHistoryError::Mismatch)?
                    .clone();
                self.attempts.push(CampaignAttemptHistory {
                    attempt,
                    start: pin,
                    finish: None,
                    finish_pin: None,
                });
            }
            Transition::Finish(ordinal, finish) => {
                validate_finish(plan, *ordinal, finish)?;
                let attempt = self
                    .attempts
                    .last_mut()
                    .ok_or(CampaignHistoryError::Mismatch)?;
                if attempt.attempt.ordinal != *ordinal || attempt.finish.is_some() {
                    return Err(CampaignHistoryError::Mismatch);
                }
                attempt.finish = Some(finish.clone());
                attempt.finish_pin = Some(pin);
            }
            Transition::Terminal(terminal) => {
                let last = self
                    .attempts
                    .last()
                    .and_then(|attempt| attempt.finish.as_ref())
                    .ok_or(CampaignHistoryError::Mismatch)?;
                if last.next_attempt_planned {
                    return Err(CampaignHistoryError::Mismatch);
                }
                let mut error = finish_error(last);
                if plan.continue_after_success {
                    if error.is_none() {
                        error = self
                            .attempts
                            .iter()
                            .filter_map(|attempt| attempt.finish.as_ref())
                            .find_map(finish_error);
                    }
                    if error.is_none()
                        && (self.attempts.len() != plan.attempts.len()
                            || self.attempts.iter().any(|attempt| {
                                attempt
                                    .finish
                                    .as_ref()
                                    .is_none_or(|finish| !finish.settled_success)
                            }))
                    {
                        return Err(CampaignHistoryError::Mismatch);
                    }
                }
                if terminal.complete != error.is_none() || terminal.error_id.as_deref() != error {
                    return Err(CampaignHistoryError::Mismatch);
                }
                self.terminal = Some(terminal.clone());
            }
        }
        Ok(())
    }
}

/// One finite history owner. A fresh process may adopt one exact verified finished prefix through
/// `CampaignWriter::resume_from_prefix`, but only when that retained finish explicitly planned
/// the next predeclared attempt. A start-only tail, terminal campaign, or non-continuing finish
/// remains non-resumable. A failed append retains its exact pending transition; every different
/// successor is blocked.
pub struct CampaignWriter {
    plan: CampaignPlan,
    limits: CampaignHistoryLimits,
    plan_digest: ContentDigest,
    state: HistoryState,
    tip: Option<CampaignPin>,
    last: Option<CampaignRecord>,
    pending: Option<CampaignRecord>,
    retained_bytes: u64,
}
impl CampaignWriter {
    /// Pure validation and reservation. First start additionally refuses an occupied namespace.
    pub fn new(plan: CampaignPlan, limits: CampaignHistoryLimits) -> Result<Self> {
        limits.validate()?;
        plan.validate()?;
        let plan_bytes = plan.canonical_bytes()?;
        if plan.attempts.len() as u32 * 2 + 1 > limits.maximum_records
            || plan_bytes.len() > limits.maximum_spool_object_bytes
            || plan_bytes.len() as u64 > limits.maximum_metadata_bytes
        {
            return Err(CampaignHistoryError::Limit);
        }
        Ok(Self {
            plan_digest: ContentDigest::sha256(&plan_bytes),
            plan,
            limits,
            state: HistoryState::default(),
            tip: None,
            last: None,
            pending: None,
            retained_bytes: plan_bytes.len() as u64,
        })
    }

    /// Adopt one exact durable finished prefix after a process restart.
    ///
    /// This is deliberately not a generic "resume latest" operation. `expected` must be an
    /// independently saved exact pin whose selected tail is a retained finish with
    /// `next_attempt_planned=true`. Start-only tails preserve an unknown native outcome and are
    /// refused; terminal campaigns and finishes that did not authorize a successor are refused.
    ///
    /// The caller supplies fresh current authority and a fresh work budget. Historical work,
    /// time and provider allowances are never reconstructed, refunded, or made spendable again.
    /// The frozen campaign plan and writer limits must match byte-for-byte, and the live publisher
    /// re-verifies the complete selected prefix before this writer can append the next start.
    pub fn resume_from_prefix(
        publisher: &LocalRootPublisher,
        plan: CampaignPlan,
        expected: CampaignPin,
        limits: CampaignHistoryLimits,
        authority: &dyn CampaignAuthority,
        cx: &ReplayCx,
        work: &mut WorkBudget<'_>,
    ) -> Result<Self> {
        let fresh = Self::new(plan.clone(), limits)?;
        if expected.approval != plan.approval || expected.plan != fresh.plan_digest {
            return Err(CampaignHistoryError::Mismatch);
        }
        let verified = storage::load_live(
            publisher,
            expected,
            limits,
            authority,
            cx,
            work,
            Some(&plan),
        )?;
        if verified.terminal().is_some() {
            return Err(CampaignHistoryError::Mismatch);
        }
        let tail = verified
            .attempts()
            .last()
            .ok_or(CampaignHistoryError::Mismatch)?;
        if tail.finish_pin != Some(expected)
            || tail
                .finish
                .as_ref()
                .is_none_or(|finish| !finish.next_attempt_planned)
            || tail.attempt.ordinal as usize >= plan.attempts.len()
        {
            return Err(CampaignHistoryError::Mismatch);
        }
        let root = publisher.root_dir().to_owned();
        let access = Access {
            authority,
            operation: CampaignOperation::Retain,
            plan: &plan,
            root: &root,
            cx,
        };
        storage::require_unoccupied_suffix(
            publisher,
            plan.approval,
            expected.records,
            limits,
            &access,
            work,
        )?;
        Ok(Self {
            plan_digest: fresh.plan_digest,
            plan,
            limits,
            state: verified.state.clone(),
            tip: Some(expected),
            last: None,
            pending: None,
            retained_bytes: verified.retained_metadata_bytes(),
        })
    }

    /// Derive continuation totals from this owner's exact finished prefix.
    ///
    /// `validate_finish` already proves every retry reason against the frozen plan. A missing
    /// native result, unresolved custody/control, controller failure, exhausted schedule,
    /// start-only tail, pending append, or terminal campaign cannot supply a continuation.
    /// Historical budget is not refunded, and a subsequent success cannot erase these failures.
    pub fn continuation_summary(&self) -> Result<CampaignContinuationSummary> {
        let completed = self.state.attempts.len();
        let tail = self
            .state
            .attempts
            .last()
            .ok_or(CampaignHistoryError::Mismatch)?;
        if self.pending.is_some()
            || self.state.terminal.is_some()
            || completed >= self.plan.attempts.len()
            || self.tip.is_none()
            || tail.finish_pin != self.tip
        {
            return Err(CampaignHistoryError::Mismatch);
        }
        let mut summary = CampaignContinuationSummary {
            completed_attempts: completed as u32,
            remaining_attempts: (self.plan.attempts.len() - completed) as u32,
            durable_pictures: 0,
            successful_attempts: 0,
            first_failure: None,
        };
        for attempt in &self.state.attempts {
            let finish = attempt
                .finish
                .as_ref()
                .ok_or(CampaignHistoryError::Mismatch)?;
            validate_finish(&self.plan, attempt.attempt.ordinal, finish)?;
            if !finish.next_attempt_planned {
                return Err(CampaignHistoryError::Mismatch);
            }
            let native = finish
                .native
                .as_ref()
                .ok_or(CampaignHistoryError::Mismatch)?;
            summary.durable_pictures = summary
                .durable_pictures
                .checked_add(native.durable_pictures)
                .ok_or(CampaignHistoryError::Limit)?;
            if finish.settled_success {
                summary.successful_attempts += 1;
            } else if summary.first_failure.is_none() {
                summary.first_failure = Some(CampaignPriorFailure {
                    ordinal: attempt.attempt.ordinal,
                    error_id: finish_error(finish)
                        .ok_or(CampaignHistoryError::Mismatch)?
                        .to_owned(),
                });
            }
        }
        Ok(summary)
    }
    /// Frozen exact owner-approved campaign scope.
    pub fn plan(&self) -> &CampaignPlan {
        &self.plan
    }
    /// Frozen independent metadata resource reservation.
    pub const fn limits(&self) -> CampaignHistoryLimits {
        self.limits
    }
    /// Last successfully retained root, never an implicit latest-head discovery.
    pub const fn tip(&self) -> Option<CampaignPin> {
        self.tip
    }

    /// Retain this start before submitting any camera operation for the attempt.
    pub fn start_attempt(
        &mut self,
        publisher: &mut LocalRootPublisher,
        ordinal: u32,
        authority: &dyn CampaignAuthority,
        cx: &ReplayCx,
        work: &mut WorkBudget<'_>,
    ) -> Result<CampaignPin> {
        self.append(publisher, Transition::Start(ordinal), authority, cx, work)
    }

    /// Retain the direct native result before releasing permission for a successor.
    pub fn finish_attempt(
        &mut self,
        publisher: &mut LocalRootPublisher,
        ordinal: u32,
        finish: CampaignFinish,
        authority: &dyn CampaignAuthority,
        cx: &ReplayCx,
        work: &mut WorkBudget<'_>,
    ) -> Result<CampaignPin> {
        self.append(
            publisher,
            Transition::Finish(ordinal, finish),
            authority,
            cx,
            work,
        )
    }

    /// Retain the distinct terminal only if it equals the result derived from all selected finishes.
    pub fn finish_campaign(
        &mut self,
        publisher: &mut LocalRootPublisher,
        terminal: CampaignTerminal,
        authority: &dyn CampaignAuthority,
        cx: &ReplayCx,
        work: &mut WorkBudget<'_>,
    ) -> Result<CampaignPin> {
        self.append(
            publisher,
            Transition::Terminal(terminal),
            authority,
            cx,
            work,
        )
    }

    fn append(
        &mut self,
        publisher: &mut LocalRootPublisher,
        transition: Transition,
        authority: &dyn CampaignAuthority,
        cx: &ReplayCx,
        work: &mut WorkBudget<'_>,
    ) -> Result<CampaignPin> {
        let root = publisher.root_dir().to_owned();
        check(authority, CampaignOperation::Retain, &self.plan, &root, cx)?;
        work.charge(4096)?;
        storage::publisher_bound(publisher.limits(), self.limits)?;
        if publisher.is_poisoned() {
            return Err(CampaignHistoryError::NotDurable);
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|record| record.transition != transition)
        {
            return Err(CampaignHistoryError::Pending);
        }
        // Successful exact replays reverify their retained graph under the SAME work account.
        if self.pending.is_none()
            && self
                .last
                .as_ref()
                .is_some_and(|record| record.transition == transition)
        {
            let pin = self.tip.ok_or(CampaignHistoryError::Mismatch)?;
            storage::load_live(
                publisher,
                pin,
                self.limits,
                authority,
                cx,
                work,
                Some(&self.plan),
            )?;
            return Ok(pin);
        }
        let access = Access {
            authority,
            operation: CampaignOperation::Retain,
            plan: &self.plan,
            root: &root,
            cx,
        };
        // An empty-namespace observation is not a reusable grant. Only this owner's exact
        // pending first append can survive another check; an invalid or early-refused request
        // leaves no authority to adopt a start subsequently written by a different owner.
        if self.tip.is_none() && self.pending.is_none() {
            storage::require_empty(publisher, self.plan.approval, self.limits, &access, work)?;
        }
        if let Some(prior) = self.tip
            && self.pending.is_none()
            && matches!(transition, Transition::Start(_))
        {
            // Another owner using this same live publisher may have advanced after our
            // continuation was admitted. Only our own exact pending append can reuse a slot.
            storage::require_unoccupied_suffix(
                publisher,
                self.plan.approval,
                prior.records,
                self.limits,
                &access,
                work,
            )?;
        }
        let record = CampaignRecord {
            approval: self.plan.approval,
            plan: self.plan_digest,
            limits: self.limits,
            sequence: self.tip.map_or(1, |pin| pin.records + 1),
            prior: self.tip,
            transition,
        };
        if record.sequence > self.limits.maximum_records {
            return Err(CampaignHistoryError::Limit);
        }
        let manifest = record.manifest()?;
        let pin = record.pin(manifest.root());
        let mut next = self.state.clone();
        next.advance(&self.plan, &record, pin)?;
        let extra = record.encode()?.len() as u64 + manifest.canonical_bytes().len() as u64;
        if self
            .retained_bytes
            .checked_add(extra)
            .is_none_or(|total| total > self.limits.maximum_metadata_bytes)
        {
            return Err(CampaignHistoryError::Limit);
        }
        if let Some(prior) = self.tip {
            let verified = storage::load_live(
                publisher,
                prior,
                self.limits,
                authority,
                cx,
                work,
                Some(&self.plan),
            )?;
            if verified.state != self.state || verified.plan != self.plan {
                return Err(CampaignHistoryError::Mismatch);
            }
        }
        self.pending = Some(record.clone());
        cx.checkpoint(STAGE_CAMPAIGN_APPEND)
            .map_err(|_| CampaignHistoryError::Denied)?;
        storage::publish(publisher, &self.plan, &record, self.limits, &access, work)?;
        // A completed durable publication must never be misreported as a late cancellation.
        self.state = next;
        self.tip = Some(pin);
        self.last = Some(record);
        self.pending = None;
        self.retained_bytes += extra;
        cx.checkpoint_post_commit(STAGE_CAMPAIGN_APPEND);
        Ok(pin)
    }
}
