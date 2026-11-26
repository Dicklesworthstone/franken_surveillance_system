#![forbid(unsafe_code)]
//! Derived high-water protocol for graph, search, model, and projection caches (`FSS-107`, `fss-x4a.9.14`).
//!
//! Binds every derived cache watermark to:
//! - an exact anchor-pinned [`LedgerReplayCursor`] (`FSS-102`),
//! - exact input/schema/policy/privacy/adapter/package/preprocess/numeric/kernel/memory/calibration
//!   and optional model weight generations ([`DerivedGenerationPin`]),
//! - the derived materialized state digest, and
//! - an explicit corruption flag.
//!
//! Evaluates whether a derived cache is `UpToDate`, eligible for sound bounded
//! `IncrementalCatchUp`, blocked on durable `PendingReconciliation`, `Cancelled`, or MUST execute
//! a full `RebuildRequired` from genesis (e.g. on ANY generation drift, lineage/epoch change,
//! forked anchor/history, ahead-of-head cursor, or corruption).

use std::error::Error;
use std::fmt;

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, ContractError, LedgerAnchor};

use crate::cursor::{LedgerReplayCursor, ReplayCursorError, ReplayPage, ReplayPageBudget};
use crate::durable::DurableReferenceLedger;
use crate::oracle::LedgerOracle;

/// Registered digest domain for [`DerivedHighWaterState`] commitments (`FSS-107`).
pub const DERIVED_HIGH_WATER_DOMAIN: &str = "fss.derived_high_water.v1";
/// Binary wire header magic for persisted derived high-water watermarks.
pub const HIGH_WATER_MAGIC: [u8; 8] = *b"FSSDHW01";
/// Supported durable format version for [`DerivedHighWaterState`].
pub const HIGH_WATER_VERSION: u32 = 1;
/// Hard ceiling on binary wire length of one [`DerivedHighWaterState`] (16 KiB).
pub const MAX_HIGH_WATER_WIRE_BYTES: usize = 16_384;
/// Hard ceiling on UTF-8 bytes in `cache_id`.
const MAX_CACHE_ID_BYTES: usize = 256;

/// Derived cache family governed by [`HighWaterProtocol`].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DerivedCacheKind {
    /// Registered typed graph projection cache (`G_phys`, `G_assoc`, etc.).
    Graph = 1,
    /// Lexical/semantic search index cache.
    Search = 2,
    /// Model inference / embedding / feature cache.
    Model = 3,
    /// MVCC operational projection cache (`fss-projection-store`).
    Projection = 4,
}

impl DerivedCacheKind {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Graph => "graph",
            Self::Search => "search",
            Self::Model => "model",
            Self::Projection => "projection",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::Graph),
            2 => Ok(Self::Search),
            3 => Ok(Self::Model),
            4 => Ok(Self::Projection),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Complete generation tuple pinning a derived cache against silent drift (`FSS-107`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedGenerationPin {
    /// Cache family.
    pub cache_kind: DerivedCacheKind,
    /// Stable bounded cache identifier.
    pub cache_id: String,
    /// Pinned ledger schema epoch.
    pub schema_epoch: u64,
    /// Pinned policy epoch.
    pub policy_epoch: u64,
    /// Pinned privacy epoch.
    pub privacy_epoch: u64,
    /// Pinned adapter registry epoch.
    pub adapter_registry_epoch: u64,
    /// Pinned model/index package generation.
    pub package_generation: u64,
    /// Pinned preprocess pipeline generation.
    pub preprocess_generation: u64,
    /// Pinned numeric/quantization generation.
    pub numeric_generation: u64,
    /// Pinned compute/SIMD kernel generation.
    pub kernel_generation: u64,
    /// Pinned memory/layout generation.
    pub memory_generation: u64,
    /// Pinned calibration generation.
    pub calibration_generation: u64,
    /// Optional immutable model weights/config digest.
    pub model_digest: Option<ContentDigest>,
}

impl DerivedGenerationPin {
    /// Validates bounded `cache_id` and non-zero generation invariants.
    pub fn validate(&self) -> Result<(), HighWaterError> {
        if self.cache_id.is_empty() || self.cache_id.len() > MAX_CACHE_ID_BYTES {
            return Err(HighWaterError::BoundsExceeded {
                observed: self.cache_id.len(),
                maximum: MAX_CACHE_ID_BYTES,
            });
        }
        if self.package_generation == 0
            || self.preprocess_generation == 0
            || self.numeric_generation == 0
            || self.kernel_generation == 0
            || self.memory_generation == 0
            || self.calibration_generation == 0
        {
            return Err(HighWaterError::InvalidGeneration(
                "derived cache generations must be >= 1".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the first drifted field reason when comparing `self` (persisted) against `expected`.
    #[must_use]
    pub fn diff_reason(&self, expected: &Self) -> Option<RebuildReason> {
        if self.cache_kind != expected.cache_kind || self.cache_id != expected.cache_id {
            return Some(RebuildReason::CacheIdentityChanged);
        }
        if self.schema_epoch != expected.schema_epoch
            || self.policy_epoch != expected.policy_epoch
            || self.privacy_epoch != expected.privacy_epoch
            || self.adapter_registry_epoch != expected.adapter_registry_epoch
        {
            return Some(RebuildReason::LedgerEpochChanged);
        }
        if self.package_generation != expected.package_generation
            || self.preprocess_generation != expected.preprocess_generation
            || self.numeric_generation != expected.numeric_generation
            || self.kernel_generation != expected.kernel_generation
            || self.memory_generation != expected.memory_generation
            || self.calibration_generation != expected.calibration_generation
            || self.model_digest != expected.model_digest
        {
            return Some(RebuildReason::DerivedGenerationDrift);
        }
        None
    }

    /// Computes a deterministic domain-separated SHA-256 digest of this validated generation pin.
    pub fn canonical_digest(&self) -> Result<ContentDigest, HighWaterError> {
        self.validate()?;
        let mut enc = CanonicalEncoder::new();
        enc.text(DERIVED_HIGH_WATER_DOMAIN);
        self.encode_canonical(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        enc.u8(self.cache_kind.tag());
        enc.text(&self.cache_id);
        enc.u64(self.schema_epoch);
        enc.u64(self.policy_epoch);
        enc.u64(self.privacy_epoch);
        enc.u64(self.adapter_registry_epoch);
        enc.u64(self.package_generation);
        enc.u64(self.preprocess_generation);
        enc.u64(self.numeric_generation);
        enc.u64(self.kernel_generation);
        enc.u64(self.memory_generation);
        enc.u64(self.calibration_generation);
        match self.model_digest {
            Some(d) => {
                enc.bool(true);
                enc.digest(d);
            }
            None => enc.bool(false),
        }
    }

    fn decode_canonical(dec: &mut CanonicalDecoder<'_>) -> Result<Self, HighWaterError> {
        let cache_kind = DerivedCacheKind::from_tag(
            dec.u8()
                .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?,
        )
        .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?;
        let cache_id = dec
            .text()
            .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?;
        if cache_id.is_empty() || cache_id.len() > MAX_CACHE_ID_BYTES {
            return Err(HighWaterError::BoundsExceeded {
                observed: cache_id.len(),
                maximum: MAX_CACHE_ID_BYTES,
            });
        }
        let pin = Self {
            cache_kind,
            cache_id: cache_id.to_owned(),
            schema_epoch: dec
                .u64()
                .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?,
            policy_epoch: dec
                .u64()
                .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?,
            privacy_epoch: dec
                .u64()
                .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?,
            adapter_registry_epoch: dec
                .u64()
                .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?,
            package_generation: dec
                .u64()
                .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?,
            preprocess_generation: dec
                .u64()
                .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?,
            numeric_generation: dec
                .u64()
                .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?,
            kernel_generation: dec
                .u64()
                .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?,
            memory_generation: dec
                .u64()
                .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?,
            calibration_generation: dec
                .u64()
                .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?,
            model_digest: if dec
                .bool()
                .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?
            {
                Some(
                    dec.digest()
                        .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?,
                )
            } else {
                None
            },
        };
        pin.validate()?;
        Ok(pin)
    }
}

/// Machine-readable reason why a derived cache MUST rebuild from genesis rather than catch up.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebuildReason {
    /// Cache was explicitly quarantined or marked corrupted.
    CacheCorrupted,
    /// Cache kind or identifier changed.
    CacheIdentityChanged,
    /// Ledger schema, policy, privacy, or adapter epoch changed.
    LedgerEpochChanged,
    /// Package, preprocess, numeric, kernel, memory, calibration, or model digest changed.
    DerivedGenerationDrift,
    /// Deployment site lineage or ledger epoch diverged.
    LineageOrEpochDiverged,
    /// Watermark cursor is ahead of the canonical ledger head.
    CursorAheadOfHead,
    /// Watermark anchor or history root forked from canonical history.
    HistoryForked,
}

/// Safe next action for a refused high-water operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HighWaterGuidance {
    /// Fix invalid generation tuple or request parameters.
    RepairConfiguration,
    /// Raise the replay page byte budget within protocol ceilings.
    IncreasePageByteBudget,
    /// Reconcile the pending indeterminate durable append first.
    ReconcilePendingAppend,
    /// Reject corrupt watermark bytes and trigger full rebuild from genesis.
    QuarantineAndRebuildFromGenesis,
    /// Upgrade reader or rebuild from genesis for unsupported watermark version.
    UpgradeOrRebuildFromGenesis,
}

/// Typed error returned by [`DerivedHighWaterState`] or [`HighWaterProtocol`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HighWaterError {
    /// Generation tuple violated non-zero invariants or differed on commit.
    InvalidGeneration(String),
    /// Advance attempted against a non-matching starting cursor or non-advancing page.
    CursorContinuityViolation {
        /// Current watermark commit sequence.
        expected_sequence: u64,
        /// Supplied page start commit sequence.
        supplied_sequence: u64,
    },
    /// Advance attempted on a corrupted/quarantined watermark.
    CorruptedWatermarkCannotAdvance,
    /// Next canonical batch exceeded the configured page byte budget.
    BatchExceedsByteBudget {
        /// Sequence of oversized batch.
        sequence: u64,
        /// Encoded batch byte length.
        batch_bytes: u64,
        /// Configured page byte budget.
        budget_bytes: u64,
    },
    /// Wire watermark lacked [`HIGH_WATER_MAGIC`].
    InvalidMagic,
    /// Wire watermark declared an unsupported version.
    UnsupportedVersion {
        /// Observed format version.
        version: u32,
    },
    /// Wire watermark was truncated, malformed, or had trailing bytes.
    MalformedWire(String),
    /// Wire watermark checksum failed verification.
    ChecksumMismatch,
    /// Wire length or text field exceeded hard bounds.
    BoundsExceeded {
        /// Observed length.
        observed: usize,
        /// Maximum permitted length.
        maximum: usize,
    },
    /// Underlying cursor or canonical encoding failure.
    Encoding(String),
}

impl HighWaterError {
    /// Registered stable error identity.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidGeneration(_) => "ERR-LEDGER-HIGHWATER-INVALID-GEN-001",
            Self::CursorContinuityViolation { .. } => "ERR-LEDGER-HIGHWATER-CONTINUITY-001",
            Self::CorruptedWatermarkCannotAdvance => "ERR-LEDGER-HIGHWATER-CORRUPTED-001",
            Self::BatchExceedsByteBudget { .. } => "ERR-LEDGER-HIGHWATER-BYTE-BUDGET-001",
            Self::InvalidMagic => "ERR-LEDGER-HIGHWATER-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-LEDGER-HIGHWATER-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-LEDGER-HIGHWATER-MALFORMED-WIRE-001",
            Self::ChecksumMismatch => "ERR-LEDGER-HIGHWATER-CHECKSUM-MISMATCH-001",
            Self::BoundsExceeded { .. } => "ERR-LEDGER-HIGHWATER-BOUNDS-001",
            Self::Encoding(_) => "ERR-LEDGER-HIGHWATER-ENCODING-001",
        }
    }

    /// Safe recovery guidance for this refusal.
    #[must_use]
    pub const fn guidance(&self) -> HighWaterGuidance {
        match self {
            Self::InvalidGeneration(_) | Self::CursorContinuityViolation { .. } => {
                HighWaterGuidance::RepairConfiguration
            }
            Self::BatchExceedsByteBudget { .. } => HighWaterGuidance::IncreasePageByteBudget,
            Self::UnsupportedVersion { .. } => HighWaterGuidance::UpgradeOrRebuildFromGenesis,
            Self::CorruptedWatermarkCannotAdvance
            | Self::InvalidMagic
            | Self::MalformedWire(_)
            | Self::ChecksumMismatch
            | Self::BoundsExceeded { .. }
            | Self::Encoding(_) => HighWaterGuidance::QuarantineAndRebuildFromGenesis,
        }
    }
}

impl fmt::Display for HighWaterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for HighWaterError {}

/// Anchor-pinned, checksummed high-water watermark for one derived cache (`FSS-107`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedHighWaterState {
    format_version: u32,
    generation: DerivedGenerationPin,
    cursor: LedgerReplayCursor,
    derived_state_digest: ContentDigest,
    corrupted: bool,
    watermark_digest: ContentDigest,
}

impl DerivedHighWaterState {
    /// Creates a new sealed watermark pinned to `generation`, `cursor`, and `derived_state_digest`.
    pub fn new(
        generation: DerivedGenerationPin,
        cursor: LedgerReplayCursor,
        derived_state_digest: ContentDigest,
    ) -> Result<Self, HighWaterError> {
        generation.validate()?;
        validate_generation_matches_anchor(&generation, cursor.last_anchor())?;
        let format_version = HIGH_WATER_VERSION;
        let corrupted = false;
        let watermark_digest = compute_watermark_digest(
            format_version,
            &generation,
            &cursor,
            derived_state_digest,
            corrupted,
        )?;
        Ok(Self {
            format_version,
            generation,
            cursor,
            derived_state_digest,
            corrupted,
            watermark_digest,
        })
    }

    /// Marks this watermark quarantined/corrupted so future evaluations mandate a clean rebuild.
    pub fn mark_corrupted(&self) -> Result<Self, HighWaterError> {
        let corrupted = true;
        let watermark_digest = compute_watermark_digest(
            self.format_version,
            &self.generation,
            &self.cursor,
            self.derived_state_digest,
            corrupted,
        )?;
        Ok(Self {
            format_version: self.format_version,
            generation: self.generation.clone(),
            cursor: self.cursor.clone(),
            derived_state_digest: self.derived_state_digest,
            corrupted,
            watermark_digest,
        })
    }

    /// Commits one verified incremental replay page, advancing the cursor atomically.
    pub fn commit_advance(
        &self,
        page: &ReplayPage,
        new_derived_state_digest: ContentDigest,
        expected_generation: &DerivedGenerationPin,
    ) -> Result<Self, HighWaterError> {
        if self.corrupted {
            return Err(HighWaterError::CorruptedWatermarkCannotAdvance);
        }
        expected_generation.validate()?;
        if let Some(reason) = self.generation.diff_reason(expected_generation) {
            return Err(HighWaterError::InvalidGeneration(format!(
                "cannot incrementally advance across generation drift ({reason:?})"
            )));
        }
        if page.start_cursor != self.cursor {
            return Err(HighWaterError::CursorContinuityViolation {
                expected_sequence: self.cursor.sequence(),
                supplied_sequence: page.start_cursor.sequence(),
            });
        }
        let expected_next_seq = page
            .start_cursor
            .sequence()
            .checked_add(page.batches.len() as u64);
        if expected_next_seq != Some(page.next_cursor.sequence())
            || (page.batches.is_empty() && page.next_cursor != page.start_cursor)
            || page.next_cursor.site_lineage() != self.cursor.site_lineage()
            || page.next_cursor.ledger_epoch() != self.cursor.ledger_epoch()
        {
            return Err(HighWaterError::CursorContinuityViolation {
                expected_sequence: expected_next_seq.unwrap_or(u64::MAX),
                supplied_sequence: page.next_cursor.sequence(),
            });
        }
        validate_generation_matches_anchor(expected_generation, page.next_cursor.last_anchor())?;
        Self::new(
            expected_generation.clone(),
            page.next_cursor.clone(),
            new_derived_state_digest,
        )
    }

    /// Durable wire format version.
    #[must_use]
    pub const fn format_version(&self) -> u32 {
        self.format_version
    }

    /// Exact pinned generation tuple.
    #[must_use]
    pub const fn generation(&self) -> &DerivedGenerationPin {
        &self.generation
    }

    /// Exact anchor-pinned ledger replay cursor.
    #[must_use]
    pub const fn cursor(&self) -> &LedgerReplayCursor {
        &self.cursor
    }

    /// Digest of the materialized derived cache state at `cursor`.
    #[must_use]
    pub const fn derived_state_digest(&self) -> ContentDigest {
        self.derived_state_digest
    }

    /// True if this cache was flagged corrupt/quarantined.
    #[must_use]
    pub const fn is_corrupted(&self) -> bool {
        self.corrupted
    }

    /// Domain-separated SHA-256 commitment (`fss.derived_high_water.v1`).
    #[must_use]
    pub const fn watermark_digest(&self) -> ContentDigest {
        self.watermark_digest
    }

    /// Encodes this watermark to bounded, checksummed binary bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, HighWaterError> {
        let cursor_bytes = self
            .cursor
            .to_canonical_bytes()
            .map_err(|err| HighWaterError::Encoding(err.to_string()))?;
        let mut enc = CanonicalEncoder::new();
        self.generation.encode_canonical(&mut enc);
        enc.bytes(&cursor_bytes);
        enc.digest(self.derived_state_digest);
        enc.bool(self.corrupted);
        enc.digest(self.watermark_digest);
        let body = enc
            .finish_checked()
            .map_err(|err| HighWaterError::Encoding(err.to_string()))?;
        let total = HIGH_WATER_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_HIGH_WATER_WIRE_BYTES {
            return Err(HighWaterError::BoundsExceeded {
                observed: total,
                maximum: MAX_HIGH_WATER_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&HIGH_WATER_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and verifies a binary [`DerivedHighWaterState`].
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, HighWaterError> {
        if bytes.len() > MAX_HIGH_WATER_WIRE_BYTES {
            return Err(HighWaterError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_HIGH_WATER_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != HIGH_WATER_MAGIC {
            return Err(HighWaterError::InvalidMagic);
        }
        let format_version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if format_version != HIGH_WATER_VERSION {
            return Err(HighWaterError::UnsupportedVersion {
                version: format_version,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let generation = DerivedGenerationPin::decode_canonical(&mut dec)?;
        let cursor_bytes = dec
            .bytes()
            .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?;
        let cursor = LedgerReplayCursor::from_canonical_bytes(cursor_bytes)
            .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?;
        validate_generation_matches_anchor(&generation, cursor.last_anchor())
            .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?;
        let derived_state_digest = dec
            .digest()
            .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?;
        let corrupted = dec
            .bool()
            .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?;
        let stored_digest = dec
            .digest()
            .map_err(|err| HighWaterError::MalformedWire(err.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            HighWaterError::MalformedWire("trailing bytes after high-water watermark".to_owned())
        })?;
        let computed = compute_watermark_digest(
            format_version,
            &generation,
            &cursor,
            derived_state_digest,
            corrupted,
        )?;
        if computed != stored_digest {
            return Err(HighWaterError::ChecksumMismatch);
        }
        Ok(Self {
            format_version,
            generation,
            cursor,
            derived_state_digest,
            corrupted,
            watermark_digest: stored_digest,
        })
    }
}

/// Non-collapsed decision emitted by [`HighWaterProtocol`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HighWaterPlan {
    /// Derived cache is already exact at the canonical head with matching generations.
    UpToDate {
        /// Current verified watermark cursor.
        cursor: LedgerReplayCursor,
        /// Current committed ledger head anchor.
        head_anchor: LedgerAnchor,
    },
    /// Derived cache can soundly catch up incrementally using `page`.
    IncrementalCatchUp {
        /// Bounded replay page strictly following the watermark cursor.
        page: Box<ReplayPage>,
        /// Remaining batches after this page.
        remaining_after_page: usize,
    },
    /// Incremental catch-up is unsound; derived cache MUST rebuild cleanly from `genesis_cursor`.
    RebuildRequired {
        /// Exact cause forbidding incremental catch-up.
        reason: RebuildReason,
        /// Verified genesis cursor for a clean rebuild.
        genesis_cursor: LedgerReplayCursor,
    },
    /// Durable ledger has an unresolved indeterminate append; derived cache MUST wait.
    BlockedPendingReconciliation {
        /// Sequence of the indeterminate append.
        pending_sequence: u64,
    },
    /// Cooperative cancellation was observed before advancing the cache.
    Cancelled {
        /// Unchanged watermark sequence.
        cursor_sequence: u64,
    },
}

/// Stateless deterministic evaluator for derived cache high-water transitions (`FSS-107`).
pub struct HighWaterProtocol;

impl HighWaterProtocol {
    /// Evaluates `watermark` against an in-memory [`LedgerOracle`].
    pub fn evaluate_oracle(
        oracle: &LedgerOracle,
        watermark: &DerivedHighWaterState,
        expected_generation: &DerivedGenerationPin,
        budget: ReplayPageBudget,
        cancelled: bool,
    ) -> Result<HighWaterPlan, HighWaterError> {
        expected_generation.validate()?;
        if cancelled {
            return Ok(HighWaterPlan::Cancelled {
                cursor_sequence: watermark.cursor.sequence(),
            });
        }
        if let Some(reason) =
            precheck_rebuild_reason(watermark, expected_generation, oracle.head_anchor())
        {
            let genesis_cursor = oracle
                .replay_cursor_genesis()
                .map_err(|err| HighWaterError::Encoding(err.to_string()))?;
            return Ok(HighWaterPlan::RebuildRequired {
                reason,
                genesis_cursor,
            });
        }
        match oracle.replay_page(&watermark.cursor, budget, cancelled) {
            Ok(page) => Ok(plan_from_page(page)),
            Err(ReplayCursorError::Cancelled { cursor_sequence }) => {
                Ok(HighWaterPlan::Cancelled { cursor_sequence })
            }
            Err(ReplayCursorError::BatchExceedsByteBudget {
                sequence,
                batch_bytes,
                budget_bytes,
            }) => Err(HighWaterError::BatchExceedsByteBudget {
                sequence,
                batch_bytes,
                budget_bytes,
            }),
            Err(err) => {
                let reason = rebuild_reason_from_cursor_error(&err)?;
                let genesis_cursor = oracle
                    .replay_cursor_genesis()
                    .map_err(|e| HighWaterError::Encoding(e.to_string()))?;
                Ok(HighWaterPlan::RebuildRequired {
                    reason,
                    genesis_cursor,
                })
            }
        }
    }

    /// Evaluates `watermark` against a [`DurableReferenceLedger`], respecting pending
    /// indeterminate-append isolation.
    pub fn evaluate_durable(
        durable: &DurableReferenceLedger,
        watermark: &DerivedHighWaterState,
        expected_generation: &DerivedGenerationPin,
        budget: ReplayPageBudget,
        cancelled: bool,
    ) -> Result<HighWaterPlan, HighWaterError> {
        expected_generation.validate()?;
        if cancelled {
            return Ok(HighWaterPlan::Cancelled {
                cursor_sequence: watermark.cursor.sequence(),
            });
        }
        if let Some(pending_sequence) = durable.pending_append_sequence() {
            return Ok(HighWaterPlan::BlockedPendingReconciliation { pending_sequence });
        }
        if let Some(reason) =
            precheck_rebuild_reason(watermark, expected_generation, &durable.current().anchor)
        {
            let genesis_cursor = durable
                .replay_cursor_genesis()
                .map_err(|err| HighWaterError::Encoding(err.to_string()))?;
            return Ok(HighWaterPlan::RebuildRequired {
                reason,
                genesis_cursor,
            });
        }
        match durable.replay_page(&watermark.cursor, budget, cancelled) {
            Ok(page) => Ok(plan_from_page(page)),
            Err(ReplayCursorError::PendingReconciliation { sequence }) => {
                Ok(HighWaterPlan::BlockedPendingReconciliation {
                    pending_sequence: sequence,
                })
            }
            Err(ReplayCursorError::Cancelled { cursor_sequence }) => {
                Ok(HighWaterPlan::Cancelled { cursor_sequence })
            }
            Err(ReplayCursorError::BatchExceedsByteBudget {
                sequence,
                batch_bytes,
                budget_bytes,
            }) => Err(HighWaterError::BatchExceedsByteBudget {
                sequence,
                batch_bytes,
                budget_bytes,
            }),
            Err(err) => {
                let reason = rebuild_reason_from_cursor_error(&err)?;
                let genesis_cursor = durable
                    .replay_cursor_genesis()
                    .map_err(|e| HighWaterError::Encoding(e.to_string()))?;
                Ok(HighWaterPlan::RebuildRequired {
                    reason,
                    genesis_cursor,
                })
            }
        }
    }
}

fn validate_generation_matches_anchor(
    generation: &DerivedGenerationPin,
    anchor: &LedgerAnchor,
) -> Result<(), HighWaterError> {
    if generation.schema_epoch != anchor.schema_epoch
        || generation.policy_epoch != anchor.policy_epoch
        || generation.privacy_epoch != anchor.privacy_epoch
        || generation.adapter_registry_epoch != anchor.adapter_registry_epoch
    {
        return Err(HighWaterError::InvalidGeneration(
            "generation pin ledger epochs disagree with cursor anchor epochs".to_owned(),
        ));
    }
    Ok(())
}

fn precheck_rebuild_reason(
    watermark: &DerivedHighWaterState,
    expected_generation: &DerivedGenerationPin,
    head_anchor: &LedgerAnchor,
) -> Option<RebuildReason> {
    if watermark.corrupted {
        return Some(RebuildReason::CacheCorrupted);
    }
    if let Some(reason) = watermark.generation.diff_reason(expected_generation) {
        return Some(reason);
    }
    if expected_generation.schema_epoch != head_anchor.schema_epoch
        || expected_generation.policy_epoch != head_anchor.policy_epoch
        || expected_generation.privacy_epoch != head_anchor.privacy_epoch
        || expected_generation.adapter_registry_epoch != head_anchor.adapter_registry_epoch
    {
        return Some(RebuildReason::LedgerEpochChanged);
    }
    None
}

fn plan_from_page(page: ReplayPage) -> HighWaterPlan {
    if page.batches.is_empty() && page.complete {
        HighWaterPlan::UpToDate {
            cursor: page.next_cursor,
            head_anchor: page.head_anchor,
        }
    } else {
        let remaining_after_page = page.remaining_batches;
        HighWaterPlan::IncrementalCatchUp {
            page: Box::new(page),
            remaining_after_page,
        }
    }
}

fn rebuild_reason_from_cursor_error(
    err: &ReplayCursorError,
) -> Result<RebuildReason, HighWaterError> {
    match err {
        ReplayCursorError::LineageMismatch { .. } | ReplayCursorError::EpochMismatch { .. } => {
            Ok(RebuildReason::LineageOrEpochDiverged)
        }
        ReplayCursorError::CursorAheadOfHead { .. } => Ok(RebuildReason::CursorAheadOfHead),
        ReplayCursorError::DivergentAnchor { .. } => Ok(RebuildReason::HistoryForked),
        other => Err(HighWaterError::Encoding(other.to_string())),
    }
}

fn compute_watermark_digest(
    format_version: u32,
    generation: &DerivedGenerationPin,
    cursor: &LedgerReplayCursor,
    derived_state_digest: ContentDigest,
    corrupted: bool,
) -> Result<ContentDigest, HighWaterError> {
    let mut enc = CanonicalEncoder::new();
    enc.text(DERIVED_HIGH_WATER_DOMAIN);
    enc.u32(format_version);
    generation.encode_canonical(&mut enc);
    enc.digest(cursor.cursor_digest());
    enc.digest(derived_state_digest);
    enc.bool(corrupted);
    let bytes = enc
        .finish_checked()
        .map_err(|err| HighWaterError::Encoding(err.to_string()))?;
    Ok(ContentDigest::sha256(&bytes))
}
