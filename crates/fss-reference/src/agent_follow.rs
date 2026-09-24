#![forbid(unsafe_code)]
//! Read-only `session.follow` (AOP-004) over an existing reference deployment root: the meaningful
//! decision-impact delta between the orientation at an earlier committed anchor and the
//! orientation at the head, delivered as exact pages of a bounded continuation stream.
//!
//! **Anchor tokens.** Every orientation carries a reusable [`AnchorToken`] naming the committed
//! [`HistoryPosition`] it was compiled at (see [`snapshot_anchor_token`]):
//!
//! ```text
//! anchor:<site>:<commit>:<effects>:<binding>
//! ```
//!
//! `<site>` is the first 16 hex digits of the SHA-256 of the site lineage, `<commit>` the ledger
//! commit sequence, `<effects>` `e<n>` for the first `n` committed effect-journal records or `none`
//! when no effect journal existed, and `<binding>` the 64-hex SHA-256 of a canonical encoding of
//! the site lineage, the complete authority anchor at that commit (state root and every epoch),
//! the ledger record root that chains the prefix, and the effect-journal presence, record count,
//! and record root. The token is therefore content-bound: it resolves only against a root whose
//! committed history reproduces every one of those roots ([`resolve_anchor`]). A token of another
//! site is [`AnchorRefusal::Foreign`], a position past the head is [`AnchorRefusal::Ahead`], and a
//! position whose recomputed binding differs (a tampered token, or a history that does not contain
//! it) is [`AnchorRefusal::Unknown`].
//!
//! **As-of reconstruction.** The basis situation is compiled by
//! [`DeploymentHistory::snapshot_at`], which reads only the ledger batches, effect records, and
//! spool objects inside the token's position, then projected by the same
//! [`orient_deployment`] every orientation uses; the result is the head snapshot. The two
//! publications are compared by [`classify_reference_meaningful_delta`], the deterministic
//! engine, unchanged: protected classes (contradiction, coverage loss, plan invalidation,
//! obligation, effect uncertainty, policy/authority, terminal transition) are reported exactly as
//! it classifies them, and silence is certified only when it certifies it. A persisting coverage
//! gap (no retained `CoverageWitness`) is itself protected coverage loss, so a follow over an
//! orientation that is `partial` never returns a silence certificate.
//!
//! **Pagination.** The delta's items are flattened into one immutable [`ContinuationStream`]
//! (scope `follow_stream`) in a fixed order that puts every protected item first: effect
//! uncertainty, obligation changes, invalidated assumptions, coverage changes, removed claims,
//! then changed cells. Each entry is content-bound to its item's canonical digest and flagged
//! critical when it evidences a protected class. A page carries the complete class set of the
//! delta and the items of one exact page; nothing is coalesced, omitted, or truncated, and the
//! next page is reached only through the exact cursor token the page returns
//! ([`follow_deployment`]). The stream binds the delta identity, the view, the page size, and the
//! head anchor, so a tampered token, a token of another stream, or a token issued before the head
//! advanced is refused ([`ContinuationError::WrongStream`]).
//!
//! Nothing here writes anything under the root.

use fss_core::{
    AgentView, CanonicalEncode, CanonicalEncoder, ContentDigest, ContinuationCursor,
    ContinuationEntry, ContinuationError, ContinuationPage, ContinuationScope, ContinuationStream,
    ContinuationStreamPublishParams, FollowWakeContract, KnowledgeCell, KnowledgeState,
    LedgerAnchor, MeaningfulDelta, PrincipalId, TimestampNs, admit_follow_read,
};

use crate::ReferenceError;
use crate::agent_orient::{
    DeploymentHistory, DeploymentOrientation, DeploymentReadError, DeploymentSnapshot,
    HistoryPosition, OrientError, OrientRequest, orient_deployment,
};
use crate::meaningful_delta::classify_reference_meaningful_delta;
use crate::situation::EFFECT_CLAIM_PREFIX;

/// Prefix of every anchor token.
pub const ANCHOR_TOKEN_PREFIX: &str = "anchor:";
/// Default number of delta items delivered per follow page.
pub const DEFAULT_FOLLOW_MAX_ENTRIES: u32 = 64;
/// Largest admitted follow page.
pub const MAX_FOLLOW_ENTRIES: u32 = 4096;
/// Lifetime of a follow cursor on the deployment's evidence clock (one hour). Cursors are issued at
/// the head's latest committed evidence time; because a stream also binds the head anchor, any
/// ledger or effect-journal advance already requires a rebase before this expiry.
pub const FOLLOW_CURSOR_LIFETIME_NS: i128 = 3_600_000_000_000;

const HEX: &[u8; 16] = b"0123456789abcdef";

fn digest_hex(value: ContentDigest) -> String {
    let text = value.to_text();
    text.split_once(':')
        .map_or(text.as_str(), |(_, hex)| hex)
        .to_owned()
}

/// First 16 hex digits of the SHA-256 of the site lineage.
fn site_label(site_lineage: &str) -> String {
    digest_hex(ContentDigest::sha256(site_lineage.as_bytes()))
        .chars()
        .take(16)
        .collect()
}

fn effects_label(effect_records: Option<u64>) -> String {
    effect_records.map_or_else(|| "none".to_owned(), |count| format!("e{count}"))
}

fn binding_digest(
    site_lineage: &str,
    position: HistoryPosition,
    anchor: &LedgerAnchor,
    ledger_root: ContentDigest,
    effect_root: ContentDigest,
) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_follow_anchor_token.v1");
    encoder.text(site_lineage);
    encoder.u64(position.commit_sequence);
    anchor.encode_canonical(&mut encoder);
    encoder.digest(ledger_root);
    match position.effect_records {
        Some(count) => {
            encoder.bool(true);
            encoder.u64(count);
            encoder.digest(effect_root);
        }
        None => encoder.bool(false),
    }
    ContentDigest::sha256(&encoder.finish())
}

fn render_token(
    site_lineage: &str,
    position: HistoryPosition,
    anchor: &LedgerAnchor,
    ledger_root: ContentDigest,
    effect_root: ContentDigest,
) -> String {
    format!(
        "{ANCHOR_TOKEN_PREFIX}{}:{}:{}:{}",
        site_label(site_lineage),
        position.commit_sequence,
        effects_label(position.effect_records),
        digest_hex(binding_digest(
            site_lineage,
            position,
            anchor,
            ledger_root,
            effect_root
        ))
    )
}

/// The reusable anchor token of the committed position `snapshot` was compiled at.
#[must_use]
pub fn snapshot_anchor_token(snapshot: &DeploymentSnapshot) -> String {
    render_token(
        &snapshot.site_lineage,
        snapshot.position,
        &snapshot.anchor,
        snapshot.ledger_root,
        snapshot.effect_journal_root,
    )
}

/// A syntactically valid anchor token (`anchor:<site>:<commit>:<effects>:<binding>`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorToken {
    text: String,
    site: String,
    position: HistoryPosition,
}

impl AnchorToken {
    /// Parses the canonical spelling of an anchor token; any other spelling (leading zeros,
    /// uppercase hex, missing or extra segments) is `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let rest = text.strip_prefix(ANCHOR_TOKEN_PREFIX)?;
        let mut parts = rest.split(':');
        let site = parts.next()?;
        let commit = parts.next()?;
        let effects = parts.next()?;
        let binding = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        let lower_hex = |value: &str, len: usize| {
            value.len() == len && value.bytes().all(|byte| HEX.contains(&byte))
        };
        if !lower_hex(site, 16) || !lower_hex(binding, 64) {
            return None;
        }
        let commit_sequence: u64 = commit.parse().ok()?;
        let effect_records = if effects == "none" {
            None
        } else {
            Some(effects.strip_prefix('e')?.parse::<u64>().ok()?)
        };
        // Only the canonical rendering of both numbers is accepted.
        if commit_sequence.to_string() != commit || effects_label(effect_records) != effects {
            return None;
        }
        Some(Self {
            text: text.to_owned(),
            site: site.to_owned(),
            position: HistoryPosition {
                commit_sequence,
                effect_records,
            },
        })
    }

    /// The token text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The committed position the token names.
    #[must_use]
    pub const fn position(&self) -> HistoryPosition {
        self.position
    }
}

/// Why an anchor token does not name a committed position of this deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorRefusal {
    /// The token names another deployment's site lineage.
    Foreign,
    /// The token names a position past this deployment's committed head.
    Ahead,
    /// The token's binding does not match this deployment's committed history at its position.
    Unknown,
}

impl AnchorRefusal {
    /// Stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Foreign => "follow_anchor_foreign",
            Self::Ahead => "follow_anchor_ahead",
            Self::Unknown => "follow_anchor_unknown",
        }
    }
}

/// Resolves `token` against `history` without reading anything beyond the history itself.
pub fn resolve_anchor(
    history: &DeploymentHistory,
    token: &AnchorToken,
) -> Result<HistoryPosition, AnchorRefusal> {
    if token.site != site_label(history.site_lineage()) {
        return Err(AnchorRefusal::Foreign);
    }
    let head = history.head();
    let position = token.position;
    if position.commit_sequence > head.commit_sequence {
        return Err(AnchorRefusal::Ahead);
    }
    match (position.effect_records, head.effect_records) {
        (Some(records), Some(head_records)) if records > head_records => {
            return Err(AnchorRefusal::Ahead);
        }
        // The token saw an effect journal this root no longer has.
        (Some(_), None) => return Err(AnchorRefusal::Unknown),
        _ => {}
    }
    let (anchor, ledger_root, effect_root) =
        history.roots_at(position).ok_or(AnchorRefusal::Unknown)?;
    if render_token(
        history.site_lineage(),
        position,
        &anchor,
        ledger_root,
        effect_root,
    ) != token.text
    {
        return Err(AnchorRefusal::Unknown);
    }
    Ok(position)
}

/// One item of a meaningful delta, in stream order.
#[derive(Clone, Debug, PartialEq)]
pub enum FollowItem {
    /// One `effectUncertaintyChanges` statement (protected).
    EffectUncertainty(String),
    /// One `obligationChanges` statement (protected).
    Obligation(String),
    /// One `invalidatedAssumptions` statement (protected).
    InvalidatedAssumption(String),
    /// One `coverageChanges` statement (protected).
    Coverage(String),
    /// One `removedClaimIds` entry (a typed removal; protected).
    RemovedClaim(String),
    /// One `changedCells` entry.
    ChangedCell(KnowledgeCell),
}

impl FollowItem {
    /// Stable stream-entry class.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::EffectUncertainty(_) => "effect_uncertainty_change",
            Self::Obligation(_) => "obligation_change",
            Self::InvalidatedAssumption(_) => "invalidated_assumption",
            Self::Coverage(_) => "coverage_change",
            Self::RemovedClaim(_) => "removed_claim",
            Self::ChangedCell(_) => "changed_cell",
        }
    }

    /// Whether the item evidences a protected (non-coalescible) class: every statement list and
    /// every removal does, and a changed cell does when it carries contradicting evidence, is
    /// conflicted, or states an effect.
    #[must_use]
    pub fn critical(&self) -> bool {
        match self {
            Self::ChangedCell(cell) => {
                !cell.contradictions().is_empty()
                    || cell.knowledge_state() == KnowledgeState::Conflicted
                    || cell.claim_id().starts_with(EFFECT_CLAIM_PREFIX)
            }
            Self::EffectUncertainty(_)
            | Self::Obligation(_)
            | Self::InvalidatedAssumption(_)
            | Self::Coverage(_)
            | Self::RemovedClaim(_) => true,
        }
    }

    /// Canonical content digest binding the stream entry to this exact item.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.agent_follow_item.v1");
        encoder.text(self.class());
        match self {
            Self::ChangedCell(cell) => encoder.digest(cell.cell_digest()),
            Self::EffectUncertainty(text)
            | Self::Obligation(text)
            | Self::InvalidatedAssumption(text)
            | Self::Coverage(text)
            | Self::RemovedClaim(text) => encoder.text(text),
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Every item of `delta`, protected lists first, each list in the engine's order.
#[must_use]
pub fn follow_items(delta: &MeaningfulDelta) -> Vec<FollowItem> {
    let mut items = Vec::new();
    items.extend(
        delta
            .effect_uncertainty_changes
            .iter()
            .cloned()
            .map(FollowItem::EffectUncertainty),
    );
    items.extend(
        delta
            .obligation_changes
            .iter()
            .cloned()
            .map(FollowItem::Obligation),
    );
    items.extend(
        delta
            .invalidated_assumptions
            .iter()
            .cloned()
            .map(FollowItem::InvalidatedAssumption),
    );
    items.extend(
        delta
            .coverage_changes
            .iter()
            .cloned()
            .map(FollowItem::Coverage),
    );
    items.extend(
        delta
            .removed_claim_ids
            .iter()
            .cloned()
            .map(FollowItem::RemovedClaim),
    );
    items.extend(
        delta
            .changed_cells
            .iter()
            .cloned()
            .map(FollowItem::ChangedCell),
    );
    items
}

/// One read-only follow request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FollowRequest {
    /// Registered view both situations are compiled in (`pulse` or `brief`).
    pub view: AgentView,
    /// Requesting principal (an audit label; no authority is minted).
    pub principal: PrincipalId,
    /// Items delivered per page (`1..=MAX_FOLLOW_ENTRIES`).
    pub max_entries: u32,
    /// Exact cursor token of the page to deliver; `None` delivers the first page.
    pub continuation: Option<String>,
}

/// One compiled follow answer: both situations, the complete delta, and one exact page of it.
#[derive(Clone, Debug, PartialEq)]
pub struct DeploymentFollow {
    /// Orientation compiled as of the `--since` anchor.
    pub basis: DeploymentOrientation,
    /// Orientation compiled at the committed head.
    pub result: DeploymentOrientation,
    /// The complete engine delta from basis to result.
    pub delta: MeaningfulDelta,
    /// Every item of the delta in stream order.
    pub items: Vec<FollowItem>,
    /// The immutable continuation stream over [`Self::items`].
    pub stream: ContinuationStream,
    /// The cursor this page was read from.
    pub cursor: ContinuationCursor,
    /// The exact page read.
    pub page: ContinuationPage,
    /// The items of [`Self::page`], in stream order.
    pub page_items: Vec<FollowItem>,
}

impl DeploymentFollow {
    /// Stream position of the page's first item.
    #[must_use]
    pub const fn page_start(&self) -> u64 {
        self.cursor.position
    }
}

/// Why a follow could not be answered.
#[derive(Debug)]
pub enum FollowError {
    /// The history could not produce a snapshot.
    Read(DeploymentReadError),
    /// The `--since` token does not name a committed position of this deployment.
    Anchor(AnchorRefusal),
    /// The continuation token is not a cursor of this exact stream, or the stream refused a read.
    Continuation(ContinuationError),
    /// An orientation could not be compiled.
    Orient(OrientError),
    /// The delta engine refused the comparison.
    Contract(ReferenceError),
}

impl From<ContinuationError> for FollowError {
    fn from(value: ContinuationError) -> Self {
        Self::Continuation(value)
    }
}

impl std::fmt::Display for FollowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(error) => write!(f, "{error}"),
            Self::Anchor(refusal) => f.write_str(refusal.code()),
            Self::Continuation(error) => write!(f, "{error}"),
            Self::Orient(error) => write!(f, "{error}"),
            Self::Contract(error) => write!(f, "meaningful delta refused: {error}"),
        }
    }
}

impl std::error::Error for FollowError {}

/// Finds the cursor of `stream` whose token is `token`, walking the stream's own cursors from the
/// initial one; a token no page of this stream issued is [`ContinuationError::WrongStream`].
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

/// Compiles one read-only follow of `history` since `since` for `request`.
///
/// The basis orientation is compiled from the snapshot at the token's committed position, the
/// result from the head snapshot, both in `request.view` for `request.principal`; the engine's
/// delta between their publications is flattened into a [`ContinuationStream`] and one exact page
/// is read, admitted through [`admit_follow_read`] under a wake contract bounded by
/// `request.max_entries` and the cursor's expiry.
pub fn follow_deployment(
    history: &DeploymentHistory,
    since: &AnchorToken,
    request: &FollowRequest,
) -> Result<DeploymentFollow, FollowError> {
    let position = resolve_anchor(history, since).map_err(FollowError::Anchor)?;
    let basis_snapshot = history.snapshot_at(position).map_err(FollowError::Read)?;
    let result_snapshot = history
        .snapshot_at(history.head())
        .map_err(FollowError::Read)?;
    let orient_request = OrientRequest {
        view: request.view,
        principal: request.principal.clone(),
        budget_tokens: None,
    };
    let basis = orient_deployment(&basis_snapshot, &orient_request, history.limits())
        .map_err(FollowError::Orient)?;
    let result = orient_deployment(&result_snapshot, &orient_request, history.limits())
        .map_err(FollowError::Orient)?;
    let delta = classify_reference_meaningful_delta(&basis.publication, &result.publication)
        .map_err(FollowError::Contract)?;

    let items = follow_items(&delta);
    let entries = items
        .iter()
        .enumerate()
        .map(|(sequence, item)| {
            ContinuationEntry::new(
                sequence as u64,
                item.class(),
                item.digest(),
                item.critical(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let capsule = result.capsule();
    let issued_at = capsule.created_at;
    let expires_at = TimestampNs(issued_at.0.saturating_add(FOLLOW_CURSOR_LIFETIME_NS));
    let stream = ContinuationStream::publish(ContinuationStreamPublishParams {
        stream_id: format!("follow:{}", delta.delta_id),
        scope: ContinuationScope::FollowStream,
        contract_basis: capsule.contract_basis.clone(),
        session_id: capsule.session_id.clone(),
        view_id: request.view.id().to_owned(),
        anchor: capsule.anchor.clone(),
        entries,
        page_size: request.max_entries,
        selection_witness: delta.selection_witness,
        issued_at,
        expires_at,
    })?;
    let cursor = match &request.continuation {
        None => stream.initial_cursor()?,
        Some(token) => find_cursor(&stream, token, issued_at)?,
    };
    let wake = FollowWakeContract::new(request.max_entries, expires_at, issued_at)?;
    let plan = admit_follow_read(&cursor, wake, issued_at)?;
    let page = stream.read_page(&cursor, issued_at)?;
    page.verify()?;
    if page.entries.len() as u64 != u64::from(plan.deliverable_entries)
        || plan.caught_up != page.next_cursor.is_none()
    {
        return Err(ContinuationError::OutOfRange.into());
    }
    let mut page_items = Vec::with_capacity(page.entries.len());
    for entry in &page.entries {
        let item = usize::try_from(entry.sequence)
            .ok()
            .and_then(|index| items.get(index))
            .filter(|item| item.digest() == entry.payload_digest)
            .ok_or(ContinuationError::OutOfRange)?;
        page_items.push(item.clone());
    }
    Ok(DeploymentFollow {
        basis,
        result,
        delta,
        items,
        stream,
        cursor,
        page,
        page_items,
    })
}

#[cfg(test)]
mod tests;
