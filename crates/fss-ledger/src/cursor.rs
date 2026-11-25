#![forbid(unsafe_code)]
//! Anchor-pinned, checksummed, bounded ledger replay cursor (`FSS-102`).
//!
//! [`LedgerReplayCursor`] provides deterministic paginated replay over the canonical
//! `EvidenceDeltaBatch` history for both [`LedgerOracle`] and [`DurableReferenceLedger`].
//! Every cursor pins its format version, exact `LedgerAnchor` (site lineage, ledger/schema/policy/
//! privacy/adapter epochs, commit sequence, and materialized `state_root`), and canonical
//! history-chain root (`fss.ledger_oracle_history.v1`), sealed under
//! `fss.ledger_replay_cursor.v1`.
//!
//! Replay carries zero write or effect authority. Cancellation, pending indeterminate appends,
//! lineage/epoch mismatches, forked anchors, out-of-range sequences, zero-progress byte budgets,
//! and corrupt wire bytes all fail closed with typed errors and safe recovery guidance.

use std::error::Error;
use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    EvidenceDeltaBatch, LedgerAnchor,
};

use crate::batch_codec::encode_batch;
use crate::durable::DurableReferenceLedger;
use crate::oracle::{
    LedgerOracle, MAX_ORACLE_TEXT_BYTES, genesis_history_root, successor_history_root,
};

/// Registered digest domain for [`LedgerReplayCursor`] commitments (`FSS-102`).
pub const LEDGER_REPLAY_CURSOR_DOMAIN: &str = "fss.ledger_replay_cursor.v1";
/// Binary wire header magic identifying a canonical ledger replay cursor.
pub const LEDGER_REPLAY_CURSOR_MAGIC: [u8; 8] = *b"FSSCUR01";
/// Supported binary wire format version for [`LedgerReplayCursor`].
pub const LEDGER_REPLAY_CURSOR_VERSION: u32 = 1;
/// Hard ceiling on batches returned by one bounded replay page.
pub const MAX_REPLAY_PAGE_BATCHES: usize = 1_024;
/// Hard ceiling on accounted canonical wire bytes per replay page (16 MiB).
pub const MAX_REPLAY_PAGE_BYTES: u64 = 16 * 1024 * 1024;
/// Hard ceiling on serialized binary wire length of one [`LedgerReplayCursor`] (8 KiB).
pub const MAX_REPLAY_CURSOR_BYTES: usize = 8_192;

/// Safe next action for a refused replay cursor operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayCursorGuidance {
    /// Request parameters violated hard bounds; repair the request before retrying.
    RepairRequest,
    /// Cooperative cancellation was observed before advancing; retry safely from the same cursor.
    RetryFromCursor,
    /// An indeterminate durable append is unresolved; reconcile it before resuming replay.
    ReconcilePendingAppend,
    /// Cursor belongs to a different lineage, epoch, or forked history; resnapshot from genesis.
    ResnapshotFromGenesis,
    /// Cursor sequence exceeds the local committed head; wait for replication or resnapshot.
    ResnapshotOrWaitForReplication,
    /// The next batch alone exceeds `max_bytes`; raise the page byte budget up to the ceiling.
    IncreaseByteBudget,
    /// Wire cursor bytes are corrupt or oversize; reject and re-issue from a verified anchor.
    RejectCorruptCursor,
    /// Wire cursor version is unsupported by this binary; upgrade or resnapshot.
    UpgradeOrResnapshot,
}

/// Typed failure emitted by [`LedgerReplayCursor`] codec, validation, or bounded paging.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayCursorError {
    /// Page budget fields are zero or exceed hard ceilings.
    InvalidBudget {
        /// Requested maximum batches per page.
        max_batches: usize,
        /// Requested maximum wire bytes per page.
        max_bytes: u64,
    },
    /// Cooperative cancellation observed before emitting any batches.
    Cancelled {
        /// Unchanged cursor commit sequence.
        cursor_sequence: u64,
    },
    /// Durable ledger has an unresolved indeterminate append that blocks replay reads.
    PendingReconciliation {
        /// Sequence of the indeterminate append.
        sequence: u64,
    },
    /// Cursor site lineage disagrees with the target ledger.
    LineageMismatch {
        /// Ledger site lineage.
        expected: String,
        /// Cursor site lineage.
        supplied: String,
    },
    /// Cursor ledger epoch disagrees with the target ledger.
    EpochMismatch {
        /// Ledger epoch.
        expected: u64,
        /// Cursor epoch.
        supplied: u64,
    },
    /// Cursor commit sequence is ahead of the ledger's committed head.
    CursorAheadOfHead {
        /// Cursor commit sequence.
        cursor_sequence: u64,
        /// Ledger head commit sequence.
        head_sequence: u64,
    },
    /// Cursor anchor or history root disagrees with the canonical commit at that sequence.
    DivergentAnchor {
        /// Commit sequence where divergence was detected.
        sequence: u64,
    },
    /// The very next canonical batch exceeds the caller's `max_bytes` budget.
    BatchExceedsByteBudget {
        /// Commit sequence of the oversized batch.
        sequence: u64,
        /// Encoded wire size of the next batch.
        batch_bytes: u64,
        /// Caller's configured page byte budget.
        budget_bytes: u64,
    },
    /// Wire cursor lacked [`LEDGER_REPLAY_CURSOR_MAGIC`].
    InvalidMagic,
    /// Wire cursor declared an unsupported format version.
    UnsupportedVersion {
        /// Observed format version.
        version: u32,
    },
    /// Wire cursor bytes were truncated, malformed, or contained trailing garbage.
    TruncatedOrMalformed(String),
    /// Wire cursor checksum did not match the recomputed domain-separated digest.
    ChecksumMismatch,
    /// Wire cursor length or field exceeded hard bounds.
    BoundsExceeded {
        /// Observed byte length.
        observed: usize,
        /// Hard maximum allowed bytes.
        maximum: usize,
    },
    /// Canonical encoding or internal history-root computation failed.
    Encoding(String),
}

impl ReplayCursorError {
    /// Registered stable error identity.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidBudget { .. } => "ERR-LEDGER-CURSOR-INVALID-BUDGET-001",
            Self::Cancelled { .. } => "ERR-LEDGER-CURSOR-CANCELLED-001",
            Self::PendingReconciliation { .. } => "ERR-LEDGER-CURSOR-PENDING-RECONCILE-001",
            Self::LineageMismatch { .. } => "ERR-LEDGER-CURSOR-LINEAGE-MISMATCH-001",
            Self::EpochMismatch { .. } => "ERR-LEDGER-CURSOR-EPOCH-MISMATCH-001",
            Self::CursorAheadOfHead { .. } => "ERR-LEDGER-CURSOR-AHEAD-OF-HEAD-001",
            Self::DivergentAnchor { .. } => "ERR-LEDGER-CURSOR-DIVERGENT-ANCHOR-001",
            Self::BatchExceedsByteBudget { .. } => "ERR-LEDGER-CURSOR-BYTE-BUDGET-001",
            Self::InvalidMagic => "ERR-LEDGER-CURSOR-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-LEDGER-CURSOR-UNSUPPORTED-VERSION-001",
            Self::TruncatedOrMalformed(_) => "ERR-LEDGER-CURSOR-MALFORMED-001",
            Self::ChecksumMismatch => "ERR-LEDGER-CURSOR-CHECKSUM-MISMATCH-001",
            Self::BoundsExceeded { .. } => "ERR-LEDGER-CURSOR-BOUNDS-001",
            Self::Encoding(_) => "ERR-LEDGER-CURSOR-ENCODING-001",
        }
    }

    /// Safe recovery guidance for this refusal.
    #[must_use]
    pub const fn guidance(&self) -> ReplayCursorGuidance {
        match self {
            Self::InvalidBudget { .. } => ReplayCursorGuidance::RepairRequest,
            Self::Cancelled { .. } => ReplayCursorGuidance::RetryFromCursor,
            Self::PendingReconciliation { .. } => ReplayCursorGuidance::ReconcilePendingAppend,
            Self::LineageMismatch { .. }
            | Self::EpochMismatch { .. }
            | Self::DivergentAnchor { .. } => ReplayCursorGuidance::ResnapshotFromGenesis,
            Self::CursorAheadOfHead { .. } => ReplayCursorGuidance::ResnapshotOrWaitForReplication,
            Self::BatchExceedsByteBudget { .. } => ReplayCursorGuidance::IncreaseByteBudget,
            Self::UnsupportedVersion { .. } => ReplayCursorGuidance::UpgradeOrResnapshot,
            Self::InvalidMagic
            | Self::TruncatedOrMalformed(_)
            | Self::ChecksumMismatch
            | Self::BoundsExceeded { .. }
            | Self::Encoding(_) => ReplayCursorGuidance::RejectCorruptCursor,
        }
    }
}

impl fmt::Display for ReplayCursorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.code())?;
        match self {
            Self::InvalidBudget {
                max_batches,
                max_bytes,
            } => write!(
                f,
                "invalid replay page budget (max_batches={max_batches}, max_bytes={max_bytes})"
            ),
            Self::Cancelled { cursor_sequence } => {
                write!(f, "replay cancelled at sequence {cursor_sequence}")
            }
            Self::PendingReconciliation { sequence } => write!(
                f,
                "durable ledger has pending indeterminate append at sequence {sequence}"
            ),
            Self::LineageMismatch { expected, supplied } => write!(
                f,
                "cursor site lineage '{supplied}' does not match ledger lineage '{expected}'"
            ),
            Self::EpochMismatch { expected, supplied } => write!(
                f,
                "cursor ledger epoch {supplied} does not match ledger epoch {expected}"
            ),
            Self::CursorAheadOfHead {
                cursor_sequence,
                head_sequence,
            } => write!(
                f,
                "cursor sequence {cursor_sequence} is ahead of committed head {head_sequence}"
            ),
            Self::DivergentAnchor { sequence } => write!(
                f,
                "cursor anchor or history root at sequence {sequence} diverges from canonical history"
            ),
            Self::BatchExceedsByteBudget {
                sequence,
                batch_bytes,
                budget_bytes,
            } => write!(
                f,
                "batch at sequence {sequence} requires {batch_bytes} bytes, exceeding page budget {budget_bytes}"
            ),
            Self::InvalidMagic => f.write_str("invalid replay cursor magic header"),
            Self::UnsupportedVersion { version } => {
                write!(
                    f,
                    "unsupported replay cursor version {version}; expected {LEDGER_REPLAY_CURSOR_VERSION}"
                )
            }
            Self::TruncatedOrMalformed(reason) => write!(f, "malformed replay cursor: {reason}"),
            Self::ChecksumMismatch => f.write_str("replay cursor checksum mismatch"),
            Self::BoundsExceeded { observed, maximum } => {
                write!(
                    f,
                    "replay cursor size {observed} bytes exceeds maximum {maximum}"
                )
            }
            Self::Encoding(reason) => write!(f, "replay cursor encoding error: {reason}"),
        }
    }
}

impl Error for ReplayCursorError {}

/// Validated bounded resource budget for one paginated ledger replay step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayPageBudget {
    max_batches: usize,
    max_bytes: u64,
}

impl ReplayPageBudget {
    /// Validates `max_batches` in `1..=MAX_REPLAY_PAGE_BATCHES` and
    /// `max_bytes` in `1..=MAX_REPLAY_PAGE_BYTES`.
    pub fn new(max_batches: usize, max_bytes: u64) -> Result<Self, ReplayCursorError> {
        if max_batches == 0
            || max_batches > MAX_REPLAY_PAGE_BATCHES
            || max_bytes == 0
            || max_bytes > MAX_REPLAY_PAGE_BYTES
        {
            return Err(ReplayCursorError::InvalidBudget {
                max_batches,
                max_bytes,
            });
        }
        Ok(Self {
            max_batches,
            max_bytes,
        })
    }

    /// Maximum batches per page.
    #[must_use]
    pub const fn max_batches(self) -> usize {
        self.max_batches
    }

    /// Maximum accounted canonical batch wire bytes per page.
    #[must_use]
    pub const fn max_bytes(self) -> u64 {
        self.max_bytes
    }
}

/// Anchor-pinned, checksummed continuation cursor over one canonical `EvidenceDeltaBatch` ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerReplayCursor {
    format_version: u32,
    last_anchor: LedgerAnchor,
    history_root: ContentDigest,
    cursor_digest: ContentDigest,
}

impl LedgerReplayCursor {
    /// Constructs a sealed cursor pinned to `last_anchor` and `history_root`.
    pub fn new(
        last_anchor: LedgerAnchor,
        history_root: ContentDigest,
    ) -> Result<Self, ReplayCursorError> {
        if last_anchor.site_lineage.is_empty()
            || last_anchor.site_lineage.len() > MAX_ORACLE_TEXT_BYTES
        {
            return Err(ReplayCursorError::BoundsExceeded {
                observed: last_anchor.site_lineage.len(),
                maximum: MAX_ORACLE_TEXT_BYTES,
            });
        }
        let format_version = LEDGER_REPLAY_CURSOR_VERSION;
        let cursor_digest = compute_cursor_digest(format_version, &last_anchor, history_root)?;
        Ok(Self {
            format_version,
            last_anchor,
            history_root,
            cursor_digest,
        })
    }

    /// Durable wire format version (`LEDGER_REPLAY_CURSOR_VERSION`).
    #[must_use]
    pub const fn format_version(&self) -> u32 {
        self.format_version
    }

    /// Exact last acknowledged canonical [`LedgerAnchor`].
    #[must_use]
    pub const fn last_anchor(&self) -> &LedgerAnchor {
        &self.last_anchor
    }

    /// Canonical history-chain root through `last_anchor.commit_sequence`.
    #[must_use]
    pub const fn history_root(&self) -> ContentDigest {
        self.history_root
    }

    /// Domain-separated SHA-256 commitment (`fss.ledger_replay_cursor.v1`).
    #[must_use]
    pub const fn cursor_digest(&self) -> ContentDigest {
        self.cursor_digest
    }

    /// Deployment site lineage pinned by this cursor.
    #[must_use]
    pub fn site_lineage(&self) -> &str {
        &self.last_anchor.site_lineage
    }

    /// Ledger epoch pinned by this cursor.
    #[must_use]
    pub const fn ledger_epoch(&self) -> u64 {
        self.last_anchor.ledger_epoch
    }

    /// Last acknowledged commit sequence (`0` at genesis).
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.last_anchor.commit_sequence
    }

    /// Encodes this cursor to deterministic, checksummed binary bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ReplayCursorError> {
        let mut enc = CanonicalEncoder::new();
        self.last_anchor.encode_canonical(&mut enc);
        enc.digest(self.history_root);
        enc.digest(self.cursor_digest);
        let body = enc
            .finish_checked()
            .map_err(|err| ReplayCursorError::Encoding(err.to_string()))?;
        let total = LEDGER_REPLAY_CURSOR_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_REPLAY_CURSOR_BYTES {
            return Err(ReplayCursorError::BoundsExceeded {
                observed: total,
                maximum: MAX_REPLAY_CURSOR_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&LEDGER_REPLAY_CURSOR_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and verifies a binary [`LedgerReplayCursor`], failing closed on any
    /// magic/version/checksum/truncation/trailing-byte/bound violation.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ReplayCursorError> {
        if bytes.len() > MAX_REPLAY_CURSOR_BYTES {
            return Err(ReplayCursorError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_REPLAY_CURSOR_BYTES,
            });
        }
        if bytes.len() < 12 {
            return Err(ReplayCursorError::InvalidMagic);
        }
        if bytes[..8] != LEDGER_REPLAY_CURSOR_MAGIC {
            return Err(ReplayCursorError::InvalidMagic);
        }
        let format_version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if format_version != LEDGER_REPLAY_CURSOR_VERSION {
            return Err(ReplayCursorError::UnsupportedVersion {
                version: format_version,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let last_anchor = LedgerAnchor::decode_canonical(&mut dec)
            .map_err(|err| ReplayCursorError::TruncatedOrMalformed(err.to_string()))?;
        if last_anchor.site_lineage.is_empty()
            || last_anchor.site_lineage.len() > MAX_ORACLE_TEXT_BYTES
        {
            return Err(ReplayCursorError::BoundsExceeded {
                observed: last_anchor.site_lineage.len(),
                maximum: MAX_ORACLE_TEXT_BYTES,
            });
        }
        let history_root = dec
            .digest()
            .map_err(|err| ReplayCursorError::TruncatedOrMalformed(err.to_string()))?;
        let stored_digest = dec
            .digest()
            .map_err(|err| ReplayCursorError::TruncatedOrMalformed(err.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            ReplayCursorError::TruncatedOrMalformed("trailing bytes after cursor".to_owned())
        })?;
        let computed = compute_cursor_digest(format_version, &last_anchor, history_root)?;
        if computed != stored_digest {
            return Err(ReplayCursorError::ChecksumMismatch);
        }
        Ok(Self {
            format_version,
            last_anchor,
            history_root,
            cursor_digest: stored_digest,
        })
    }
}

/// One bounded, deterministic page of canonical `EvidenceDeltaBatch` records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayPage {
    /// Ordered canonical batches strictly following `start_cursor`.
    pub batches: Vec<EvidenceDeltaBatch>,
    /// Verified cursor before this page was read.
    pub start_cursor: LedgerReplayCursor,
    /// Advanced cursor covering the final batch in `batches` (or `start_cursor` when empty).
    pub next_cursor: LedgerReplayCursor,
    /// Committed head anchor observed at replay time.
    pub head_anchor: LedgerAnchor,
    /// Canonical history-chain root through `head_anchor`.
    pub head_history_root: ContentDigest,
    /// Number of committed batches still remaining after `next_cursor`.
    pub remaining_batches: usize,
    /// Exact canonical wire bytes accounted across `batches`.
    pub bytes_accounted: u64,
    /// True when more batches remain beyond `next_cursor`.
    pub has_more: bool,
    /// True when `next_cursor` has reached `head_anchor` with zero remaining batches.
    pub complete: bool,
}

fn compute_cursor_digest(
    format_version: u32,
    last_anchor: &LedgerAnchor,
    history_root: ContentDigest,
) -> Result<ContentDigest, ReplayCursorError> {
    let mut enc = CanonicalEncoder::new();
    enc.text(LEDGER_REPLAY_CURSOR_DOMAIN);
    enc.u32(format_version);
    last_anchor.encode_canonical(&mut enc);
    enc.digest(history_root);
    let bytes = enc
        .finish_checked()
        .map_err(|err| ReplayCursorError::Encoding(err.to_string()))?;
    Ok(ContentDigest::sha256(&bytes))
}

fn validate_cursor_against(
    cursor: &LedgerReplayCursor,
    genesis: &LedgerAnchor,
    head_sequence: u64,
    expected_anchor: Option<&LedgerAnchor>,
    expected_history_root: Option<ContentDigest>,
) -> Result<(), ReplayCursorError> {
    if cursor.format_version != LEDGER_REPLAY_CURSOR_VERSION {
        return Err(ReplayCursorError::UnsupportedVersion {
            version: cursor.format_version,
        });
    }
    let recomputed = compute_cursor_digest(
        cursor.format_version,
        &cursor.last_anchor,
        cursor.history_root,
    )?;
    if recomputed != cursor.cursor_digest {
        return Err(ReplayCursorError::ChecksumMismatch);
    }
    if cursor.last_anchor.site_lineage != genesis.site_lineage {
        return Err(ReplayCursorError::LineageMismatch {
            expected: genesis.site_lineage.clone(),
            supplied: cursor.last_anchor.site_lineage.clone(),
        });
    }
    if cursor.last_anchor.ledger_epoch != genesis.ledger_epoch {
        return Err(ReplayCursorError::EpochMismatch {
            expected: genesis.ledger_epoch,
            supplied: cursor.last_anchor.ledger_epoch,
        });
    }
    if cursor.last_anchor.commit_sequence > head_sequence {
        return Err(ReplayCursorError::CursorAheadOfHead {
            cursor_sequence: cursor.last_anchor.commit_sequence,
            head_sequence,
        });
    }
    match (expected_anchor, expected_history_root) {
        (Some(anchor), Some(history_root))
            if anchor == &cursor.last_anchor && history_root == cursor.history_root =>
        {
            Ok(())
        }
        _ => Err(ReplayCursorError::DivergentAnchor {
            sequence: cursor.last_anchor.commit_sequence,
        }),
    }
}

impl LedgerOracle {
    /// Returns the genesis [`LedgerReplayCursor`] (`sequence == 0`) for this oracle.
    pub fn replay_cursor_genesis(&self) -> Result<LedgerReplayCursor, ReplayCursorError> {
        self.replay_cursor_at(0)
    }

    /// Returns a [`LedgerReplayCursor`] pinned to the committed anchor at `sequence`.
    pub fn replay_cursor_at(&self, sequence: u64) -> Result<LedgerReplayCursor, ReplayCursorError> {
        let head_sequence = self.head_sequence();
        if sequence > head_sequence {
            return Err(ReplayCursorError::CursorAheadOfHead {
                cursor_sequence: sequence,
                head_sequence,
            });
        }
        let anchor = self
            .anchor_at(sequence)
            .ok_or(ReplayCursorError::DivergentAnchor { sequence })?;
        let history_root = self
            .history_root_at(sequence)
            .ok_or(ReplayCursorError::DivergentAnchor { sequence })?;
        LedgerReplayCursor::new(anchor.clone(), history_root)
    }

    /// Reads one bounded canonical page of batches strictly following `cursor`.
    ///
    /// When `cancelled` is `true`, fails closed with [`ReplayCursorError::Cancelled`] before
    /// emitting any batch or advancing the cursor.
    pub fn replay_page(
        &self,
        cursor: &LedgerReplayCursor,
        budget: ReplayPageBudget,
        cancelled: bool,
    ) -> Result<ReplayPage, ReplayCursorError> {
        let head_sequence = self.head_sequence();
        let expected_anchor = self.anchor_at(cursor.sequence());
        let expected_history_root = self.history_root_at(cursor.sequence());
        validate_cursor_against(
            cursor,
            self.genesis_anchor(),
            head_sequence,
            expected_anchor,
            expected_history_root,
        )?;
        if cancelled {
            return Err(ReplayCursorError::Cancelled {
                cursor_sequence: cursor.sequence(),
            });
        }

        let start_idx = usize::try_from(cursor.sequence()).map_err(|_| {
            ReplayCursorError::CursorAheadOfHead {
                cursor_sequence: cursor.sequence(),
                head_sequence,
            }
        })?;
        let total_batches = self.batch_count();
        let mut batches = Vec::new();
        let mut bytes_accounted = 0u64;
        let mut next_anchor = cursor.last_anchor.clone();
        let mut next_history_root = cursor.history_root;

        let mut idx = start_idx;
        while idx < total_batches && batches.len() < budget.max_batches() {
            let Some((batch, hist_root)) = self.entry_at_index(idx) else {
                break;
            };
            let encoded_len = encode_batch(batch)
                .map_err(|err| ReplayCursorError::Encoding(err.to_string()))?
                .len() as u64;
            if bytes_accounted.saturating_add(encoded_len) > budget.max_bytes() {
                if batches.is_empty() {
                    return Err(ReplayCursorError::BatchExceedsByteBudget {
                        sequence: batch.new_anchor.commit_sequence,
                        batch_bytes: encoded_len,
                        budget_bytes: budget.max_bytes(),
                    });
                }
                break;
            }
            bytes_accounted = bytes_accounted.saturating_add(encoded_len);
            next_anchor = batch.new_anchor.clone();
            next_history_root = hist_root;
            batches.push(batch.clone());
            idx += 1;
        }

        let next_cursor = if batches.is_empty() {
            cursor.clone()
        } else {
            LedgerReplayCursor::new(next_anchor, next_history_root)?
        };
        let remaining_batches = total_batches.saturating_sub(idx);
        let has_more = remaining_batches > 0;
        let head_anchor = self.head_anchor().clone();
        let head_history_root = self.head_history_root();
        let complete = !has_more && next_cursor.last_anchor == head_anchor;

        Ok(ReplayPage {
            batches,
            start_cursor: cursor.clone(),
            next_cursor,
            head_anchor,
            head_history_root,
            remaining_batches,
            bytes_accounted,
            has_more,
            complete,
        })
    }
}

fn durable_history_roots(
    genesis: &LedgerAnchor,
    batches: &[EvidenceDeltaBatch],
) -> Result<Vec<ContentDigest>, ReplayCursorError> {
    let mut roots = Vec::with_capacity(batches.len().saturating_add(1));
    let mut current = genesis_history_root(genesis)
        .map_err(|err| ReplayCursorError::Encoding(err.to_string()))?;
    roots.push(current);
    for batch in batches {
        current = successor_history_root(
            current,
            batch.new_anchor.commit_sequence,
            batch.batch_digest,
            &batch.new_anchor,
        )
        .map_err(|err| ReplayCursorError::Encoding(err.to_string()))?;
        roots.push(current);
    }
    Ok(roots)
}

impl DurableReferenceLedger {
    /// Returns the genesis [`LedgerReplayCursor`] (`sequence == 0`) for this durable ledger.
    ///
    /// Refuses while an indeterminate append awaits reconciliation.
    pub fn replay_cursor_genesis(&self) -> Result<LedgerReplayCursor, ReplayCursorError> {
        self.replay_cursor_at(0)
    }

    /// Returns a [`LedgerReplayCursor`] pinned to the durable committed anchor at `sequence`.
    ///
    /// Refuses while an indeterminate append awaits reconciliation so uncommitted suffixes are
    /// never exposed.
    pub fn replay_cursor_at(&self, sequence: u64) -> Result<LedgerReplayCursor, ReplayCursorError> {
        if let Some(pending_seq) = self.pending_append_sequence() {
            return Err(ReplayCursorError::PendingReconciliation {
                sequence: pending_seq,
            });
        }
        let head = &self.current().anchor;
        let head_sequence = head.commit_sequence;
        if sequence > head_sequence {
            return Err(ReplayCursorError::CursorAheadOfHead {
                cursor_sequence: sequence,
                head_sequence,
            });
        }
        let genesis = LedgerAnchor::genesis(head.site_lineage.clone());
        let batches = self.batches();
        let roots = durable_history_roots(&genesis, batches)?;
        let anchor = if sequence == 0 {
            genesis
        } else {
            let idx = usize::try_from(sequence - 1)
                .map_err(|_| ReplayCursorError::DivergentAnchor { sequence })?;
            batches
                .get(idx)
                .ok_or(ReplayCursorError::DivergentAnchor { sequence })?
                .new_anchor
                .clone()
        };
        let root_idx = usize::try_from(sequence)
            .map_err(|_| ReplayCursorError::DivergentAnchor { sequence })?;
        let history_root = *roots
            .get(root_idx)
            .ok_or(ReplayCursorError::DivergentAnchor { sequence })?;
        LedgerReplayCursor::new(anchor, history_root)
    }

    /// Reads one bounded canonical page of durable committed batches strictly following `cursor`.
    ///
    /// Refuses while an indeterminate append awaits reconciliation, and produces cursors
    /// bit-identical to [`LedgerOracle::replay_page`] over the same committed history.
    pub fn replay_page(
        &self,
        cursor: &LedgerReplayCursor,
        budget: ReplayPageBudget,
        cancelled: bool,
    ) -> Result<ReplayPage, ReplayCursorError> {
        if let Some(pending_seq) = self.pending_append_sequence() {
            return Err(ReplayCursorError::PendingReconciliation {
                sequence: pending_seq,
            });
        }
        let head_anchor = self.current().anchor.clone();
        let head_sequence = head_anchor.commit_sequence;
        let genesis = LedgerAnchor::genesis(head_anchor.site_lineage.clone());
        let all_batches = self.batches();
        let roots = durable_history_roots(&genesis, all_batches)?;

        let expected_anchor: Option<&LedgerAnchor> = if cursor.sequence() == 0 {
            Some(&genesis)
        } else {
            usize::try_from(cursor.sequence() - 1)
                .ok()
                .and_then(|idx| all_batches.get(idx))
                .map(|batch| &batch.new_anchor)
        };
        let expected_history_root = usize::try_from(cursor.sequence())
            .ok()
            .and_then(|idx| roots.get(idx))
            .copied();

        validate_cursor_against(
            cursor,
            &genesis,
            head_sequence,
            expected_anchor,
            expected_history_root,
        )?;
        if cancelled {
            return Err(ReplayCursorError::Cancelled {
                cursor_sequence: cursor.sequence(),
            });
        }

        let start_idx = usize::try_from(cursor.sequence()).map_err(|_| {
            ReplayCursorError::CursorAheadOfHead {
                cursor_sequence: cursor.sequence(),
                head_sequence,
            }
        })?;
        let total_batches = all_batches.len();
        let mut batches = Vec::new();
        let mut bytes_accounted = 0u64;
        let mut next_anchor = cursor.last_anchor.clone();
        let mut next_history_root = cursor.history_root;

        let mut idx = start_idx;
        while idx < total_batches && batches.len() < budget.max_batches() {
            let batch = &all_batches[idx];
            let encoded_len = encode_batch(batch)
                .map_err(|err| ReplayCursorError::Encoding(err.to_string()))?
                .len() as u64;
            if bytes_accounted.saturating_add(encoded_len) > budget.max_bytes() {
                if batches.is_empty() {
                    return Err(ReplayCursorError::BatchExceedsByteBudget {
                        sequence: batch.new_anchor.commit_sequence,
                        batch_bytes: encoded_len,
                        budget_bytes: budget.max_bytes(),
                    });
                }
                break;
            }
            bytes_accounted = bytes_accounted.saturating_add(encoded_len);
            next_anchor = batch.new_anchor.clone();
            next_history_root = roots[idx + 1];
            batches.push(batch.clone());
            idx += 1;
        }

        let next_cursor = if batches.is_empty() {
            cursor.clone()
        } else {
            LedgerReplayCursor::new(next_anchor, next_history_root)?
        };
        let remaining_batches = total_batches.saturating_sub(idx);
        let has_more = remaining_batches > 0;
        let head_history_root = *roots
            .last()
            .ok_or_else(|| ReplayCursorError::Encoding("missing head history root".to_owned()))?;
        let complete = !has_more && next_cursor.last_anchor == head_anchor;

        Ok(ReplayPage {
            batches,
            start_cursor: cursor.clone(),
            next_cursor,
            head_anchor,
            head_history_root,
            remaining_batches,
            bytes_accounted,
            has_more,
            complete,
        })
    }
}
