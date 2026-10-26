#![forbid(unsafe_code)]
//! Lossless adjacent-prefix replay for `session.follow` (FSS-208).
//!
//! The ordinary follow compiler compares two endpoints. This adapter instead delivers exactly
//! one adjacent committed transition, including every page of its protected items, inside a
//! caller-pinned horizon. Later appends cannot silently change that horizon. A durable session
//! owner may retain the returned page identity and acknowledge it only after delivery; this
//! module performs no session writes and never acknowledges a page itself.
//!
//! The authority ledger and effect journal each retain an exact order, but retain no shared
//! total interleaving. If both advance in the requested interval, replay refuses before object
//! reads. Sorting timestamps, holding one journal at its latest state while replaying the other,
//! or claiming endpoint comparison captured every protected transition would invent history.
//! A frozen interval where one journal advances remains replayable after either journal later
//! appends: only the exact requested interval determines its order.
//!
//! Each invocation hydrates at most two existing bounded snapshots and emits one existing
//! `MeaningfulDelta` page. Classification, terminal-proof restrictions, possible-world
//! preservation, silence semantics, and legacy continuation identities remain the owner's.
//! Current deletion and custody failures still refuse historical hydration; this is not a
//! filesystem snapshot or a certificate of uninterrupted physical quiet.

use std::path::{Path, PathBuf};

use fss_core::{AgentView, CanonicalEncoder, ContentDigest};

use super::{
    AnchorToken, DeploymentFollow, FollowError, FollowRequest, MAX_FOLLOW_ENTRIES,
    follow_snapshots_for, resolve_anchor, snapshot_anchor_token,
};
use crate::agent_orient::{DeploymentHistory, HistoryPosition, OrientLimits, OrientSessionBinding};

/// Private delivery identity; existing follow and continuation domains are unchanged.
pub const REPLAY_PAGE_DOMAIN: &str = "fss.agent_follow_replay_page.v1";

/// The single journal whose exact order is traversed by this replay interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayAxis {
    /// The acknowledged position already equals the frozen horizon.
    CaughtUp,
    /// Exactly one authority-ledger commit is delivered.
    Ledger,
    /// Exactly one effect-journal record is delivered (or its explicit creation when empty).
    Effects,
}

impl ReplayAxis {
    /// Stable private adapter spelling; not a new public semantic operation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CaughtUp => "caught_up",
            Self::Ledger => "ledger",
            Self::Effects => "effects",
        }
    }
}

/// Immutable scope offered to caller-owned live I/O and cancellation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayBinding {
    objects_root: PathBuf,
    since: AnchorToken,
    horizon: AnchorToken,
    request: FollowRequest,
    read_limits: OrientLimits,
    session: Option<OrientSessionBinding>,
}

impl ReplayBinding {
    /// Actual object namespace in the already admitted deployment history; never inferred from
    /// a client-provided path or token. A root label itself grants no filesystem authority.
    #[must_use]
    pub fn objects_root(&self) -> &Path {
        &self.objects_root
    }

    /// Exact acknowledged position. Nothing in this call advances it durably.
    #[must_use]
    pub const fn since(&self) -> &AnchorToken {
        &self.since
    }

    /// Exact committed horizon, including both content-bound journal prefixes.
    #[must_use]
    pub const fn horizon(&self) -> &AnchorToken {
        &self.horizon
    }

    /// Principal, view, page size and exact input continuation admitted for this call.
    #[must_use]
    pub const fn request(&self) -> &FollowRequest {
        &self.request
    }

    /// Hard bounds on each of at most two snapshot reads. Callers can narrow, never enlarge,
    /// the existing native default profile.
    #[must_use]
    pub const fn read_limits(&self) -> OrientLimits {
        self.read_limits
    }

    /// Exact durable identity supplied by the authenticated session owner before compilation.
    /// Absence preserves the existing standalone read-only identity.
    #[must_use]
    pub fn session(&self) -> Option<&OrientSessionBinding> {
        self.session.as_ref()
    }
}

/// Work boundary requiring live admission. There are no spawned tasks, parks or effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayBoundary {
    /// Before reconstructing and hydrating the exact basis snapshot.
    BasisSnapshot,
    /// Before reconstructing and hydrating its adjacent successor.
    ResultSnapshot,
    /// Before bounded native composition/classification and page construction.
    Project,
    /// After all synchronous work, before releasing a private response to its owner.
    Deliver,
}

/// Caller-owned refusal. It never silently becomes an empty delta or an acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDenial {
    /// Principal, capability, privacy or exact I/O scope is no longer authorized.
    Unauthorized,
    /// Cancellation was requested; no new work or response delivery is admitted.
    Cancelled,
    /// The caller's unchanged deadline no longer admits new work.
    Deadline,
    /// An invocation budget cannot admit the next bounded step.
    Budget,
    /// Current trusted time or other admission authority is unavailable.
    Unavailable,
}

/// Equivalent explicit `Cx` boundary for this synchronous reference adapter. The owner must
/// authenticate and bind its existing context; no permissive production implementation exists.
pub trait ReplayControl {
    /// Admit this boundary under exactly the same immutable binding and live cancellation state.
    fn admit(
        &mut self,
        binding: &ReplayBinding,
        boundary: ReplayBoundary,
    ) -> Result<(), ReplayDenial>;
}

/// A verified adjacent transition and one exact page. The session owner retains this full
/// interval and page identity until an explicit acknowledgement succeeds.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplayStep {
    /// Existing native follow payload, including both complete publications and page receipts.
    pub follow: DeploymentFollow,
    /// Exact input position, retained even when this is a continuation page.
    pub since: AnchorToken,
    /// Exact adjacent successor. Advance to it only after every item page is acknowledged.
    pub result_anchor: AnchorToken,
    /// Frozen upper bound, unchanged by later appends.
    pub horizon: AnchorToken,
    /// Proven local journal order for this interval.
    pub axis: ReplayAxis,
    /// The adjacent result is the horizon. Pending item pages must still be delivered and ACKed.
    pub horizon_reached: bool,
}

impl ReplayStep {
    /// Exact delivery identity binding range, request, complete classified publications and
    /// native page. A different principal/view, horizon, item page, or recomputed historical
    /// situation cannot reuse an acknowledgement of this page.
    #[must_use]
    pub fn page_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(REPLAY_PAGE_DOMAIN);
        encoder.text(self.since.as_str());
        encoder.text(self.result_anchor.as_str());
        encoder.text(self.horizon.as_str());
        encoder.text(self.axis.as_str());
        encoder.bool(self.horizon_reached);
        encoder.digest(self.follow.basis.request_digest);
        encoder.digest(self.follow.result.request_digest);
        encoder.digest(self.follow.basis.publication.publication_digest);
        encoder.digest(self.follow.result.publication.publication_digest);
        encoder.digest(self.follow.delta.delta_digest());
        encoder.digest(self.follow.stream.source_digest);
        encoder.digest(self.follow.page.page_digest);
        ContentDigest::sha256(&encoder.finish())
    }
}

/// A refusal preserves the acknowledged cursor and never discards an intervening transition.
#[derive(Debug)]
pub enum ReplayError {
    /// Invalid view, page size, or widened/zero native read bounds.
    InvalidBounds,
    /// The requested horizon precedes the acknowledged position in either journal.
    ReversedRange,
    /// Both journals advanced without a retained cross-journal interleaving proof.
    AmbiguousOrder,
    /// Mission cases, plans, claims or findings need their own retained order. This limited
    /// deployment-history replay profile refuses populated facets instead of silently dropping
    /// protected mission state or mixing current facets into earlier deployment snapshots.
    UnsupportedSessionFacets,
    /// The underlying exact anchor, snapshot, classifier or native page refused the request.
    Follow(FollowError),
    /// The owner denied an explicitly bounded synchronous operation.
    Denied(ReplayDenial),
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBounds => f.write_str("follow replay bounds are not admitted"),
            Self::ReversedRange => f.write_str("follow replay would rewind a journal prefix"),
            Self::AmbiguousOrder => f.write_str(
                "both journals advanced without retained interleaving; explicit resnapshot is required",
            ),
            Self::UnsupportedSessionFacets => f.write_str(
                "mission facets require retained session-history replay; explicit session resnapshot is required",
            ),
            Self::Follow(error) => write!(f, "follow replay refused: {error}"),
            Self::Denied(reason) => write!(f, "follow replay owner refused {reason:?}"),
        }
    }
}

impl std::error::Error for ReplayError {}

fn admitted_bounds(history: &DeploymentHistory, request: &FollowRequest) -> bool {
    let limits = history.limits();
    let defaults = OrientLimits::default();
    matches!(request.view, AgentView::Pulse | AgentView::Brief)
        && (1..=MAX_FOLLOW_ENTRIES).contains(&request.max_entries)
        && request
            .continuation
            .as_ref()
            .is_none_or(|token| token.len() <= 256)
        && [
            (limits.max_layout_bytes, defaults.max_layout_bytes),
            (limits.max_journal_bytes, defaults.max_journal_bytes),
            (limits.max_object_bytes, defaults.max_object_bytes),
            (limits.max_events, defaults.max_events),
            (
                limits.max_revisions_per_event,
                defaults.max_revisions_per_event,
            ),
        ]
        .into_iter()
        .all(|(value, ceiling)| value > 0 && value <= ceiling)
}

fn next_position(
    history: &DeploymentHistory,
    since: HistoryPosition,
    horizon: HistoryPosition,
) -> Result<(ReplayAxis, HistoryPosition), ReplayError> {
    if horizon.commit_sequence < since.commit_sequence
        || horizon.effect_records < since.effect_records
    {
        return Err(ReplayError::ReversedRange);
    }
    let ledger = since.commit_sequence != horizon.commit_sequence;
    let effects = since.effect_records != horizon.effect_records;
    match (ledger, effects) {
        (true, true) => Err(ReplayError::AmbiguousOrder),
        (false, false) => Ok((ReplayAxis::CaughtUp, since)),
        (true, false) => {
            let commit_sequence = history
                .next_ledger_commit(since.commit_sequence, horizon.commit_sequence)
                .ok_or(ReplayError::ReversedRange)?;
            Ok((
                ReplayAxis::Ledger,
                HistoryPosition {
                    commit_sequence,
                    ..since
                },
            ))
        }
        (false, true) => {
            // Journal creation is explicit. An absent journal first becomes an empty present
            // journal, then each record advances separately; a record is never skipped.
            let count = since
                .effect_records
                .map_or(Some(0), |count| count.checked_add(1))
                .ok_or(ReplayError::ReversedRange)?;
            Ok((
                ReplayAxis::Effects,
                HistoryPosition {
                    effect_records: Some(count),
                    ..since
                },
            ))
        }
    }
}

/// Delivers one exact adjacent committed transition, or one continuation page of that transition.
///
/// The caller admits the initial bounded `DeploymentHistory::read` before invoking this adapter.
/// This function verifies both full tokens, the direction, and the provable single-journal
/// ordering before the first source-object I/O. It reads at most the two selected snapshots,
/// never loops across the backlog, and uses the existing native compiler without reclassification.
/// A continued page uses the same `since` and `horizon`; only after its final page has been
/// acknowledged may an owner supply `result_anchor` as the next `since`.
pub fn follow_replay_step<C: ReplayControl + ?Sized>(
    history: &DeploymentHistory,
    since: &AnchorToken,
    horizon: &AnchorToken,
    request: &FollowRequest,
    control: &mut C,
) -> Result<ReplayStep, ReplayError> {
    follow_replay_step_for(history, since, horizon, request, None, control)
}

/// Adjacent replay compiled for a real session/mission before native sealing and classification.
///
/// The session owner authenticates and pins the supplied identity and proves that unsupported
/// mission facets have not changed across this subscription's interval. Populated facets refuse
/// this limited profile: neither current case/plan/claim/finding snapshots nor empty substitutes
/// establish their intermediate history. The owner must also detect a facet that appeared and
/// resolved between calls, using its retained semantic revision history, and require resnapshot.
///
/// `None` is exactly [`follow_replay_step`]. Supplying a binding never adds a capability, refreshes
/// a lease, edits a workspace or post-hoc relabels a sealed `MeaningfulDelta`.
pub fn follow_replay_step_for<C: ReplayControl + ?Sized>(
    history: &DeploymentHistory,
    since: &AnchorToken,
    horizon: &AnchorToken,
    request: &FollowRequest,
    session: Option<&OrientSessionBinding>,
    control: &mut C,
) -> Result<ReplayStep, ReplayError> {
    if !admitted_bounds(history, request) {
        return Err(ReplayError::InvalidBounds);
    }
    if session.is_some_and(|binding| {
        !binding.cases.is_empty()
            || !binding.plans.is_empty()
            || !binding.claims.is_empty()
            || !binding.findings.is_empty()
            || binding
                .trauma_warnings
                .as_ref()
                .is_some_and(|warnings| !warnings.is_empty())
    }) {
        return Err(ReplayError::UnsupportedSessionFacets);
    }
    let basis_position = resolve_anchor(history, since)
        .map_err(|error| ReplayError::Follow(FollowError::Anchor(error)))?;
    let horizon_position = resolve_anchor(history, horizon)
        .map_err(|error| ReplayError::Follow(FollowError::Anchor(error)))?;
    let (axis, result_position) = next_position(history, basis_position, horizon_position)?;
    let binding = ReplayBinding {
        objects_root: history.replay_objects_root().to_path_buf(),
        since: since.clone(),
        horizon: horizon.clone(),
        request: request.clone(),
        read_limits: *history.limits(),
        session: session.cloned(),
    };
    control
        .admit(&binding, ReplayBoundary::BasisSnapshot)
        .map_err(ReplayError::Denied)?;
    let basis = history
        .snapshot_at(basis_position)
        .map_err(|error| ReplayError::Follow(FollowError::Read(error)))?;
    control
        .admit(&binding, ReplayBoundary::ResultSnapshot)
        .map_err(ReplayError::Denied)?;
    let result = history
        .snapshot_at(result_position)
        .map_err(|error| ReplayError::Follow(FollowError::Read(error)))?;
    let result_anchor =
        AnchorToken::parse(&snapshot_anchor_token(&result)).ok_or(ReplayError::InvalidBounds)?;
    control
        .admit(&binding, ReplayBoundary::Project)
        .map_err(ReplayError::Denied)?;
    let follow = follow_snapshots_for(history, &basis, &result, request, session)
        .map_err(ReplayError::Follow)?;
    control
        .admit(&binding, ReplayBoundary::Deliver)
        .map_err(ReplayError::Denied)?;
    Ok(ReplayStep {
        follow,
        since: since.clone(),
        result_anchor,
        horizon: horizon.clone(),
        axis,
        horizon_reached: result_position == horizon_position,
    })
}
