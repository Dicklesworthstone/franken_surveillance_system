#![forbid(unsafe_code)]
//! RaptorQ / systematic GF(256) post-repair canonical digest gate (`FSS-128`, `fss-x4a.13.12`).
//!
//! Implements the normative repair lifecycle in `docs/ATP_ARCHIVE_AND_REPLICATION.md` §6 and
//! `XFER-INV-006` (repair cannot invent authority):
//!
//! 1. **Immutable `RepairPlan`:** binds exact `target_object_digest`, `expected_byte_len`,
//!    `source_generation`, coding geometry (`symbol_size`, `source_symbol_count`,
//!    `repair_symbol_count`), `sealed_root_digest`, and `contract_basis_digest`.
//! 2. **Fenced `RepairLease` & `RepairAuthorityContext`:** enforces active capability/privacy,
//!    exact authority generation, unexpired monotonic lease fence, and explicitly refuses any
//!    authority escalation (`grants_effect_authority == true` fails closed per `XFER-INV-006`).
//! 3. **Deterministic pure-Rust systematic Cauchy GF(256) fountain/erasure engine:** encodes any
//!    payload into `k` source symbols and `r` repair symbols (`k + r <= 255`) so any `k` distinct
//!    valid symbols reconstruct the original payload without `unsafe` or foreign libraries.
//! 4. **Mandatory post-repair canonical digest gate (`PostRepairDigestGate`):** reconstructed bytes
//!    stage in `ReconstructionStaged` first, then undergo exact trailing-padding verification,
//!    byte-length verification, and domain-canonical SHA-256 verification against
//!    `target_object_digest`. Any mismatch, 1-bit flip, stale source generation, or insufficient
//!    symbol set moves to `RepairGateState::Quarantined` and NEVER publishes.
//! 5. **Durability-gated symbol refresh (`docs/ATP_ARCHIVE_AND_REPLICATION.md` §6 step 7):**
//!    refreshing repair symbols is authorized ONLY after `VerifiedCanonicalMatch`/`Published` AND
//!    source custody reaches at least [`CustodyLevel::Durable`].
//! 6. **Direct composition with `FSS-127` ([`crate::closure`]):** verified receipts project
//!    directly into [`InspectedObject::Present`] with `post_repair_verified: true`, while
//!    quarantined/staged/indeterminate states project without collapse into `Corrupt`,
//!    `StagedOnly`, or `Indeterminate`.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, TimestampNs,
};

use crate::closure::{ClosureEdge, CustodyLevel, InspectedObject};

/// Registered digest domain for immutable [`RepairPlan`] commitments (`FSS-128`).
pub const ATP_REPAIR_PLAN_DOMAIN: &str = "fss.atp_repair_plan.v1";
/// Registered digest domain for sealed [`PostRepairReceipt`] commitments (`FSS-128`).
pub const ATP_POST_REPAIR_RECEIPT_DOMAIN: &str = "fss.atp_post_repair_receipt.v1";
/// Domain tag for individual repair symbol content commitments.
pub const ATP_REPAIR_SYMBOL_DOMAIN: &str = "fss.atp_repair_symbol.v1";
/// Binary wire header magic for serialized post-repair receipts.
pub const REPAIR_RECEIPT_MAGIC: [u8; 8] = *b"FSSPRG01";
/// Supported durable format version for [`PostRepairReceipt`].
pub const REPAIR_RECEIPT_VERSION: u32 = 1;
/// Hard ceiling on bytes per coding symbol (64 KiB).
pub const MAX_SYMBOL_SIZE: usize = 64 * 1024;
/// Hard ceiling on total `k + r` symbols in one GF(256) Cauchy coding block.
pub const MAX_GF256_BLOCK_SYMBOLS: u32 = 255;
/// Hard ceiling on reconstructed payload bytes per bounded gate pass (16 MiB).
pub const MAX_RECONSTRUCTED_OBJECT_BYTES: usize = 16 * 1024 * 1024;
/// Hard ceiling on serialized receipt wire bytes (512 KiB).
pub const MAX_REPAIR_RECEIPT_WIRE_BYTES: usize = 512 * 1024;
/// Hard ceiling on candidate symbol envelopes admitted into one bounded repair gate pass.
pub const MAX_REPAIR_INPUT_ENVELOPES: usize = 4_096;
/// Hard ceiling on diagnostic label/reason bytes.
pub const MAX_REPAIR_LABEL_BYTES: usize = 256;

/// Non-collapsed repair gate lifecycle state (`docs/ATP_ARCHIVE_AND_REPLICATION.md` §6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairGateState {
    /// Immutable repair plan sealed; reconstruction has not begun.
    Planned = 1,
    /// Active fenced repair lease acquired; reconstruction not yet staged.
    LeaseAcquired = 2,
    /// Reconstructed candidate bytes staged only; NOT canonical-digest verified or publishable.
    ReconstructionStaged = 3,
    /// Reconstructed canonical SHA-256 and exact length matched `target_object_digest`.
    VerifiedCanonicalMatch = 4,
    /// Post-repair verification failed (digest mismatch, corrupt symbol, stale generation,
    /// or unrecoverable erasure); quarantined and barred from publication.
    Quarantined = 5,
    /// Verified repaired object published under root-last custody (grants no effect authority).
    Published = 6,
    /// Repair I/O or staging outcome remained ambiguous; never laundered into verified.
    Indeterminate = 7,
    /// Cooperative cancellation observed before verification or publication completed.
    Cancelled = 8,
}

impl RepairGateState {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::LeaseAcquired => "lease_acquired",
            Self::ReconstructionStaged => "reconstruction_staged",
            Self::VerifiedCanonicalMatch => "verified_canonical_match",
            Self::Quarantined => "quarantined",
            Self::Published => "published",
            Self::Indeterminate => "indeterminate",
            Self::Cancelled => "cancelled",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::Planned),
            2 => Ok(Self::LeaseAcquired),
            3 => Ok(Self::ReconstructionStaged),
            4 => Ok(Self::VerifiedCanonicalMatch),
            5 => Ok(Self::Quarantined),
            6 => Ok(Self::Published),
            7 => Ok(Self::Indeterminate),
            8 => Ok(Self::Cancelled),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Safe operator/agent recovery guidance for a refused or quarantined repair operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairGuidance {
    /// Fix invalid coding geometry, byte length, or label bounds.
    RepairPlanGeometry,
    /// Re-authorize revoked repair capability/privacy or refresh stale authority generation.
    ReauthorizeRepair,
    /// Never attach effect/retention/activation grants to a repair context (`XFER-INV-006`).
    StripEffectAuthorityFromRepair,
    /// Acquire a fresh fenced repair lease before staging or publishing.
    AcquireFreshRepairLease,
    /// Fetch fresh uncorrupted symbols for the exact source generation or restore from another replica.
    QuarantineAndFetchFreshReplica,
    /// Wait for source object durability (`CustodyLevel::Durable`) before refreshing repair symbols.
    AwaitSourceDurability,
    /// Reconcile ambiguous I/O or retry cleanly from the sealed immutable repair plan.
    ReconcileOrRetryFromPlan,
    /// Reject corrupt or unsupported receipt bytes and re-verify from durable custody.
    RejectCorruptReceipt,
}

/// Typed failure returned by [`RepairPlan`], [`PostRepairDigestGate`], or [`PostRepairReceipt`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepairGateError {
    /// Plan parameters, payload size, or labels violated protocol bounds.
    InvalidPlan(String),
    /// Capability or privacy authorization revoked.
    AuthorityRevoked(String),
    /// Caller attempted to smuggle effect/activation authority into repair (`XFER-INV-006`).
    AuthorityEscalationRefused,
    /// Active authority generation or contract basis drifted from the sealed plan.
    StaleAuthorityOrBasis {
        /// Machine-readable mismatch detail.
        detail: String,
    },
    /// Repair lease was inactive, expired, wrong plan/generation, or superseded by a higher fence.
    InvalidOrExpiredLease(String),
    /// Symbol belonged to a different target object, plan, or stale source generation.
    StaleOrMismatchedSymbol {
        /// Symbol ESI.
        esi: u32,
        /// Machine-readable mismatch reason.
        detail: String,
    },
    /// Publication attempted without a [`RepairGateState::VerifiedCanonicalMatch`] receipt.
    UnverifiedPublicationRefused {
        /// Observed gate state.
        state: RepairGateState,
    },
    /// Symbol refresh requested before source object achieved [`CustodyLevel::Durable`].
    SourceDurabilityInsufficient {
        /// Observed source custody milestone.
        observed: CustodyLevel,
        /// Required durability floor.
        required: CustodyLevel,
    },
    /// Cooperative cancellation observed before completion.
    Cancelled,
    /// Wire buffer exceeded hard protocol ceiling.
    BoundsExceeded {
        /// Observed bytes.
        observed: usize,
        /// Allowed ceiling.
        maximum: usize,
    },
    /// Binary receipt lacked [`REPAIR_RECEIPT_MAGIC`].
    InvalidMagic,
    /// Binary receipt declared an unsupported version.
    UnsupportedVersion {
        /// Observed version.
        version: u32,
    },
    /// Binary receipt was truncated, non-canonical, or structurally inconsistent.
    MalformedWire(String),
    /// Receipt canonical checksum failed verification.
    ChecksumMismatch,
    /// Canonical encoder failure.
    Encoding(String),
}

impl RepairGateError {
    /// Stable machine error identity.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidPlan(_) => "ERR-ATP-REPAIR-INVALID-PLAN-001",
            Self::AuthorityRevoked(_) => "ERR-ATP-REPAIR-AUTHORITY-REVOKED-001",
            Self::AuthorityEscalationRefused => "ERR-ATP-REPAIR-AUTHORITY-ESCALATION-001",
            Self::StaleAuthorityOrBasis { .. } => "ERR-ATP-REPAIR-STALE-BASIS-001",
            Self::InvalidOrExpiredLease(_) => "ERR-ATP-REPAIR-INVALID-LEASE-001",
            Self::StaleOrMismatchedSymbol { .. } => "ERR-ATP-REPAIR-STALE-SYMBOL-001",
            Self::UnverifiedPublicationRefused { .. } => "ERR-ATP-REPAIR-UNVERIFIED-PUBLISH-001",
            Self::SourceDurabilityInsufficient { .. } => "ERR-ATP-REPAIR-SOURCE-DURABILITY-001",
            Self::Cancelled => "ERR-ATP-REPAIR-CANCELLED-001",
            Self::BoundsExceeded { .. } => "ERR-ATP-REPAIR-BOUNDS-001",
            Self::InvalidMagic => "ERR-ATP-REPAIR-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-ATP-REPAIR-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-ATP-REPAIR-MALFORMED-WIRE-001",
            Self::ChecksumMismatch => "ERR-ATP-REPAIR-CHECKSUM-MISMATCH-001",
            Self::Encoding(_) => "ERR-ATP-REPAIR-ENCODING-001",
        }
    }

    /// Safe recovery guidance for this refusal.
    #[must_use]
    pub const fn guidance(&self) -> RepairGuidance {
        match self {
            Self::InvalidPlan(_) | Self::BoundsExceeded { .. } => {
                RepairGuidance::RepairPlanGeometry
            }
            Self::AuthorityRevoked(_) | Self::StaleAuthorityOrBasis { .. } => {
                RepairGuidance::ReauthorizeRepair
            }
            Self::AuthorityEscalationRefused => RepairGuidance::StripEffectAuthorityFromRepair,
            Self::InvalidOrExpiredLease(_) => RepairGuidance::AcquireFreshRepairLease,
            Self::StaleOrMismatchedSymbol { .. } | Self::UnverifiedPublicationRefused { .. } => {
                RepairGuidance::QuarantineAndFetchFreshReplica
            }
            Self::SourceDurabilityInsufficient { .. } => RepairGuidance::AwaitSourceDurability,
            Self::Cancelled => RepairGuidance::ReconcileOrRetryFromPlan,
            Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::MalformedWire(_)
            | Self::ChecksumMismatch
            | Self::Encoding(_) => RepairGuidance::RejectCorruptReceipt,
        }
    }
}

impl fmt::Display for RepairGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for RepairGateError {}

/// Explicit authority context for repair execution (`XFER-INV-006`: repair cannot invent authority).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairAuthorityContext {
    /// Exact pinned `ContractBasis` / authority anchor digest.
    pub contract_basis_digest: ContentDigest,
    /// Active authority generation.
    pub authority_generation: u64,
    /// Expected authority generation pinned in the repair plan.
    pub expected_authority_generation: u64,
    /// Active privacy epoch.
    pub privacy_epoch: u64,
    /// True while bounded object-repair capability remains active.
    pub repair_capability_active: bool,
    /// True while privacy projection authorization remains active.
    pub privacy_active: bool,
    /// MUST remain `false`: repair never carries or invents effect/activation/retention authority.
    pub grants_effect_authority: bool,
}

impl RepairAuthorityContext {
    /// Constructs a valid active repair-only authority context (`grants_effect_authority = false`).
    #[must_use]
    pub const fn active(
        contract_basis_digest: ContentDigest,
        authority_generation: u64,
        privacy_epoch: u64,
    ) -> Self {
        Self {
            contract_basis_digest,
            authority_generation,
            expected_authority_generation: authority_generation,
            privacy_epoch,
            repair_capability_active: true,
            privacy_active: true,
            grants_effect_authority: false,
        }
    }

    fn validate_against(&self, plan: &RepairPlan) -> Result<(), RepairGateError> {
        if self.grants_effect_authority {
            return Err(RepairGateError::AuthorityEscalationRefused);
        }
        if !self.repair_capability_active {
            return Err(RepairGateError::AuthorityRevoked(
                "repair capability revoked".to_owned(),
            ));
        }
        if !self.privacy_active {
            return Err(RepairGateError::AuthorityRevoked(
                "privacy authorization revoked".to_owned(),
            ));
        }
        if self.authority_generation != self.expected_authority_generation {
            return Err(RepairGateError::StaleAuthorityOrBasis {
                detail: format!(
                    "authority_generation ({}) != expected ({})",
                    self.authority_generation, self.expected_authority_generation
                ),
            });
        }
        if self.authority_generation != plan.expected_authority_generation {
            return Err(RepairGateError::StaleAuthorityOrBasis {
                detail: format!(
                    "authority_generation ({}) != plan expected ({})",
                    self.authority_generation, plan.expected_authority_generation
                ),
            });
        }
        if self.contract_basis_digest != plan.contract_basis_digest {
            return Err(RepairGateError::StaleAuthorityOrBasis {
                detail: "contract_basis_digest drifted from sealed repair plan".to_owned(),
            });
        }
        Ok(())
    }
}

/// Fenced repair lease binding one repair execution attempt to an exact plan and fence epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairLease {
    /// Stable lease identity.
    pub lease_id: String,
    /// Digest of the sealed [`RepairPlan`] this lease covers.
    pub plan_digest: ContentDigest,
    /// Monotonic lease fence (`>= 1`).
    pub fence: u64,
    /// Authority generation under which the lease was issued.
    pub authority_generation: u64,
    /// Expiry timestamp (strictly greater than current execution timestamp).
    pub expires_at: TimestampNs,
    /// False if the lease was explicitly released or revoked.
    pub active: bool,
}

impl RepairLease {
    fn validate(
        &self,
        plan: &RepairPlan,
        authority: &RepairAuthorityContext,
        min_fence: u64,
        now: TimestampNs,
    ) -> Result<(), RepairGateError> {
        validate_label(&self.lease_id, MAX_REPAIR_LABEL_BYTES, "lease_id")?;
        if !self.active {
            return Err(RepairGateError::InvalidOrExpiredLease(
                "repair lease is inactive or revoked".to_owned(),
            ));
        }
        if self.fence == 0 || self.fence < min_fence {
            return Err(RepairGateError::InvalidOrExpiredLease(format!(
                "repair lease fence {} below minimum required fence {min_fence}",
                self.fence
            )));
        }
        if self.plan_digest != plan.plan_digest {
            return Err(RepairGateError::InvalidOrExpiredLease(
                "repair lease plan_digest does not match sealed repair plan".to_owned(),
            ));
        }
        if self.authority_generation != authority.authority_generation {
            return Err(RepairGateError::InvalidOrExpiredLease(format!(
                "repair lease authority_generation ({}) != active ({})",
                self.authority_generation, authority.authority_generation
            )));
        }
        if now >= self.expires_at {
            return Err(RepairGateError::InvalidOrExpiredLease(
                "repair lease expired before reconstruction gate completed".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Immutable sealed repair plan targeting one exact object digest and source generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairPlan {
    /// Sealed archive/transfer root digest governing this object.
    pub sealed_root_digest: ContentDigest,
    /// Exact canonical SHA-256 digest of the target object payload to reconstruct.
    pub target_object_digest: ContentDigest,
    /// Exact canonical byte length of the target object payload.
    pub expected_byte_len: u64,
    /// Immutable source object generation (`>= 1`). Stale symbols fail closed.
    pub source_generation: u64,
    /// Exact `ContractBasis` / authority anchor digest pinned at planning time.
    pub contract_basis_digest: ContentDigest,
    /// Expected authority generation pinned at planning time.
    pub expected_authority_generation: u64,
    /// Fixed byte size per source and repair symbol (`1..=MAX_SYMBOL_SIZE`).
    pub symbol_size: u32,
    /// Count of systematic source symbols `k` (`>= 1`).
    pub source_symbol_count: u32,
    /// Count of GF(256) Cauchy repair symbols `r` (`>= 1`, `k + r <= 255`).
    pub repair_symbol_count: u32,
    /// Domain-separated SHA-256 commitment of this sealed plan (`fss.atp_repair_plan.v1`).
    pub plan_digest: ContentDigest,
}

impl RepairPlan {
    /// Seals a validated immutable [`RepairPlan`].
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        sealed_root_digest: ContentDigest,
        target_object_digest: ContentDigest,
        expected_byte_len: u64,
        source_generation: u64,
        contract_basis_digest: ContentDigest,
        expected_authority_generation: u64,
        symbol_size: u32,
        repair_symbol_count: u32,
    ) -> Result<Self, RepairGateError> {
        if source_generation == 0 {
            return Err(RepairGateError::InvalidPlan(
                "source_generation must be >= 1".to_owned(),
            ));
        }
        if expected_byte_len == 0 || expected_byte_len > MAX_RECONSTRUCTED_OBJECT_BYTES as u64 {
            return Err(RepairGateError::InvalidPlan(format!(
                "expected_byte_len {expected_byte_len} outside 1..={MAX_RECONSTRUCTED_OBJECT_BYTES}"
            )));
        }
        let sym_sz = symbol_size as usize;
        if sym_sz == 0 || sym_sz > MAX_SYMBOL_SIZE {
            return Err(RepairGateError::InvalidPlan(format!(
                "symbol_size {symbol_size} outside 1..={MAX_SYMBOL_SIZE}"
            )));
        }
        let k_u64 = expected_byte_len.div_ceil(u64::from(symbol_size));
        let source_symbol_count = u32::try_from(k_u64).map_err(|_| {
            RepairGateError::InvalidPlan("source_symbol_count overflows u32".to_owned())
        })?;
        if repair_symbol_count == 0 {
            return Err(RepairGateError::InvalidPlan(
                "repair_symbol_count must be >= 1".to_owned(),
            ));
        }
        let total = source_symbol_count
            .checked_add(repair_symbol_count)
            .ok_or_else(|| RepairGateError::InvalidPlan("total symbols overflow".to_owned()))?;
        if total > MAX_GF256_BLOCK_SYMBOLS {
            return Err(RepairGateError::InvalidPlan(format!(
                "total symbols k+r={total} exceeds GF(256) Cauchy block ceiling {MAX_GF256_BLOCK_SYMBOLS}"
            )));
        }

        let mut plan = Self {
            sealed_root_digest,
            target_object_digest,
            expected_byte_len,
            source_generation,
            contract_basis_digest,
            expected_authority_generation,
            symbol_size,
            source_symbol_count,
            repair_symbol_count,
            plan_digest: ContentDigest::sha256(b"unsealed-repair-plan"),
        };
        plan.plan_digest = plan.compute_digest()?;
        Ok(plan)
    }

    /// Recomputes the canonical plan digest (`fss.atp_repair_plan.v1`).
    pub fn compute_digest(&self) -> Result<ContentDigest, RepairGateError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(ATP_REPAIR_PLAN_DOMAIN);
        enc.digest(self.sealed_root_digest);
        enc.digest(self.target_object_digest);
        enc.u64(self.expected_byte_len);
        enc.u64(self.source_generation);
        enc.digest(self.contract_basis_digest);
        enc.u64(self.expected_authority_generation);
        enc.u32(self.symbol_size);
        enc.u32(self.source_symbol_count);
        enc.u32(self.repair_symbol_count);
        let bytes = enc
            .finish_checked()
            .map_err(|e| RepairGateError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn verify_self(&self) -> Result<(), RepairGateError> {
        if self.source_generation == 0
            || self.expected_byte_len == 0
            || self.expected_byte_len > MAX_RECONSTRUCTED_OBJECT_BYTES as u64
            || self.symbol_size == 0
            || (self.symbol_size as usize) > MAX_SYMBOL_SIZE
            || self.source_symbol_count == 0
            || self.repair_symbol_count == 0
            || self
                .source_symbol_count
                .saturating_add(self.repair_symbol_count)
                > MAX_GF256_BLOCK_SYMBOLS
            || self.expected_byte_len.div_ceil(u64::from(self.symbol_size))
                != u64::from(self.source_symbol_count)
        {
            return Err(RepairGateError::InvalidPlan(
                "repair plan geometry invariants violated".to_owned(),
            ));
        }
        if self.compute_digest()? != self.plan_digest {
            return Err(RepairGateError::ChecksumMismatch);
        }
        Ok(())
    }

    /// Encodes `canonical_bytes` into `k` systematic source symbols (`esi in 0..k`) followed by
    /// `r` deterministic GF(256) Cauchy repair symbols (`esi in k..k+r`).
    pub fn encode_symbols(
        &self,
        canonical_bytes: &[u8],
    ) -> Result<Vec<RepairSymbolEnvelope>, RepairGateError> {
        self.verify_self()?;
        if canonical_bytes.len() as u64 != self.expected_byte_len {
            return Err(RepairGateError::InvalidPlan(format!(
                "source payload length {} != expected_byte_len {}",
                canonical_bytes.len(),
                self.expected_byte_len
            )));
        }
        if ContentDigest::sha256(canonical_bytes) != self.target_object_digest {
            return Err(RepairGateError::InvalidPlan(
                "source payload digest does not match plan target_object_digest".to_owned(),
            ));
        }

        let sym_sz = self.symbol_size as usize;
        let k = self.source_symbol_count as usize;
        let r = self.repair_symbol_count as usize;

        let mut source_blocks: Vec<Vec<u8>> = Vec::with_capacity(k);
        for s in 0..k {
            let start = s * sym_sz;
            let end = (start + sym_sz).min(canonical_bytes.len());
            let mut block = vec![0_u8; sym_sz];
            block[..end - start].copy_from_slice(&canonical_bytes[start..end]);
            source_blocks.push(block);
        }

        let mut out = Vec::with_capacity(k + r);
        for (s, block) in source_blocks.iter().enumerate() {
            let esi = u32::try_from(s)
                .map_err(|_| RepairGateError::InvalidPlan("source ESI overflows u32".to_owned()))?;
            out.push(RepairSymbolEnvelope::seal(self, esi, block.clone())?);
        }
        for i in 0..r {
            let esi = u32::try_from(k + i)
                .map_err(|_| RepairGateError::InvalidPlan("repair ESI overflows u32".to_owned()))?;
            let mut parity = vec![0_u8; sym_sz];
            let x = esi as u8;
            for (j, src) in source_blocks.iter().enumerate() {
                let coeff = gf_inv(x ^ (j as u8));
                gf_mul_add_slice(&mut parity, src, coeff);
            }
            out.push(RepairSymbolEnvelope::seal(self, esi, parity)?);
        }
        Ok(out)
    }
}

/// Content-addressed immutable source or repair symbol pinned to one exact generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairSymbolEnvelope {
    /// Sealed plan digest.
    pub plan_digest: ContentDigest,
    /// Target object canonical SHA-256 digest.
    pub target_object_digest: ContentDigest,
    /// Exact source object generation (`>= 1`).
    pub source_generation: u64,
    /// Encoding Symbol Identifier (`0..k` systematic source, `k..k+r` Cauchy repair).
    pub esi: u32,
    /// Symbol payload bytes (exact length `plan.symbol_size`).
    pub payload: Vec<u8>,
    /// Domain-separated commitment over header fields and `payload`.
    pub symbol_digest: ContentDigest,
}

impl RepairSymbolEnvelope {
    /// Seals a symbol envelope pinned to `plan`.
    pub fn seal(plan: &RepairPlan, esi: u32, payload: Vec<u8>) -> Result<Self, RepairGateError> {
        let total = plan
            .source_symbol_count
            .saturating_add(plan.repair_symbol_count);
        if esi >= total || payload.len() != plan.symbol_size as usize {
            return Err(RepairGateError::StaleOrMismatchedSymbol {
                esi,
                detail: format!(
                    "symbol ESI {esi} (total {total}) or length {} != {}",
                    payload.len(),
                    plan.symbol_size
                ),
            });
        }
        let mut env = Self {
            plan_digest: plan.plan_digest,
            target_object_digest: plan.target_object_digest,
            source_generation: plan.source_generation,
            esi,
            payload,
            symbol_digest: ContentDigest::sha256(b"unsealed-symbol"),
        };
        env.symbol_digest = env.compute_digest()?;
        Ok(env)
    }

    /// Recomputes the canonical symbol commitment (`fss.atp_repair_symbol.v1`).
    pub fn compute_digest(&self) -> Result<ContentDigest, RepairGateError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(ATP_REPAIR_SYMBOL_DOMAIN);
        enc.digest(self.plan_digest);
        enc.digest(self.target_object_digest);
        enc.u64(self.source_generation);
        enc.u32(self.esi);
        enc.bytes(&self.payload);
        let bytes = enc
            .finish_checked()
            .map_err(|e| RepairGateError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// True if this symbol is a parity repair symbol (`esi >= k`).
    #[must_use]
    pub const fn is_repair_symbol(&self, source_symbol_count: u32) -> bool {
        self.esi >= source_symbol_count
    }
}

/// Result of running the post-repair canonical digest gate: receipt + verified bytes (only on match).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateExecutionResult {
    /// Sealed immutable receipt recording exact gate outcome, provenance, and non-collapsed state.
    pub receipt: PostRepairReceipt,
    /// Reconstructed canonical object bytes ONLY when `receipt.state == VerifiedCanonicalMatch`.
    /// Always `None` on `Quarantined`, `Indeterminate`, or `Cancelled`.
    pub verified_bytes: Option<Vec<u8>>,
}

/// Sealed post-repair canonical digest verification receipt (`fss.atp_post_repair_receipt.v1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostRepairReceipt {
    /// Wire format version (`REPAIR_RECEIPT_VERSION`).
    pub format_version: u32,
    /// Sealed repair plan digest.
    pub plan_digest: ContentDigest,
    /// Sealed archive/transfer root digest.
    pub sealed_root_digest: ContentDigest,
    /// Expected target canonical SHA-256 digest.
    pub target_object_digest: ContentDigest,
    /// Observed canonical SHA-256 digest of reconstructed bytes (if reconstruction produced bytes).
    pub observed_reconstructed_digest: Option<ContentDigest>,
    /// Expected canonical byte length.
    pub expected_byte_len: u64,
    /// Observed byte length of reconstructed candidate (0 if reconstruction did not finish).
    pub observed_byte_len: u64,
    /// Exact source object generation.
    pub source_generation: u64,
    /// Exact pinned `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Authority generation under which verification ran.
    pub authority_generation: u64,
    /// Active privacy epoch.
    pub privacy_epoch: u64,
    /// Monotonic lease fence that authorized this attempt.
    pub lease_fence: u64,
    /// Non-collapsed repair gate state.
    pub state: RepairGateState,
    /// Distinct systematic source symbols consumed (`esi < k`).
    pub source_symbols_used: u32,
    /// Distinct Cauchy repair symbols consumed (`esi >= k`).
    pub repair_symbols_used: u32,
    /// Duplicate symbol envelopes safely ignored.
    pub duplicate_symbols_ignored: u32,
    /// Symbol envelopes rejected for corruption/tampering before or during verification.
    pub corrupt_symbols_rejected: u32,
    /// Ordered canonical list of ESIs consumed in reconstruction.
    pub consumed_esis: Vec<u32>,
    /// Secret-free diagnostic detail explaining verification or quarantine.
    pub detail: String,
    /// Timestamp when this receipt was sealed.
    pub recorded_at: TimestampNs,
    /// Domain-separated SHA-256 commitment (`fss.atp_post_repair_receipt.v1`).
    pub receipt_digest: ContentDigest,
}

impl PostRepairReceipt {
    /// Transitions a [`RepairGateState::VerifiedCanonicalMatch`] receipt to
    /// [`RepairGateState::Published`] after revalidating live authority, lease fence, and self-digest.
    ///
    /// Publication still grants ZERO effect, retention, or activation authority (`XFER-INV-006`).
    pub fn mark_published(
        &self,
        plan: &RepairPlan,
        authority: &RepairAuthorityContext,
        lease: &RepairLease,
        min_fence: u64,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<Self, RepairGateError> {
        if cancelled {
            return Err(RepairGateError::Cancelled);
        }
        plan.verify_self()?;
        self.verify_self()?;
        authority.validate_against(plan)?;
        lease.validate(plan, authority, min_fence, now)?;
        self.verify_matches_plan_and_authority(plan, authority)?;
        if self.state != RepairGateState::VerifiedCanonicalMatch {
            return Err(RepairGateError::UnverifiedPublicationRefused { state: self.state });
        }
        if self.observed_reconstructed_digest != Some(self.target_object_digest)
            || self.observed_byte_len != self.expected_byte_len
        {
            return Err(RepairGateError::UnverifiedPublicationRefused {
                state: RepairGateState::Quarantined,
            });
        }
        let mut published = self.clone();
        published.state = RepairGateState::Published;
        published.lease_fence = lease.fence;
        published.recorded_at = now.max(self.recorded_at);
        published.detail = "verified_canonical_digest_published_root_last".to_owned();
        published.receipt_digest = published.compute_digest()?;
        Ok(published)
    }

    /// Evaluates `docs/ATP_ARCHIVE_AND_REPLICATION.md` §6 step 7: refreshing repair symbols is
    /// authorized ONLY after verified canonical reconstruction AND source object durability
    /// (`source_custody >= CustodyLevel::Durable`).
    pub fn authorize_symbol_refresh(
        &self,
        plan: &RepairPlan,
        authority: &RepairAuthorityContext,
        source_custody: CustodyLevel,
    ) -> Result<ContentDigest, RepairGateError> {
        plan.verify_self()?;
        self.verify_self()?;
        authority.validate_against(plan)?;
        self.verify_matches_plan_and_authority(plan, authority)?;
        if !matches!(
            self.state,
            RepairGateState::VerifiedCanonicalMatch | RepairGateState::Published
        ) {
            return Err(RepairGateError::UnverifiedPublicationRefused { state: self.state });
        }
        if source_custody < CustodyLevel::Durable {
            return Err(RepairGateError::SourceDurabilityInsufficient {
                observed: source_custody,
                required: CustodyLevel::Durable,
            });
        }
        Ok(self.receipt_digest)
    }

    fn verify_matches_plan_and_authority(
        &self,
        plan: &RepairPlan,
        authority: &RepairAuthorityContext,
    ) -> Result<(), RepairGateError> {
        if self.plan_digest != plan.plan_digest
            || self.sealed_root_digest != plan.sealed_root_digest
            || self.target_object_digest != plan.target_object_digest
            || self.expected_byte_len != plan.expected_byte_len
            || self.source_generation != plan.source_generation
            || self.contract_basis_digest != plan.contract_basis_digest
        {
            return Err(RepairGateError::InvalidPlan(
                "receipt does not match supplied sealed repair plan".to_owned(),
            ));
        }
        if self.authority_generation != authority.authority_generation
            || self.privacy_epoch != authority.privacy_epoch
        {
            return Err(RepairGateError::StaleAuthorityOrBasis {
                detail: format!(
                    "receipt authority/privacy ({}/{}) differs from active ({}/{})",
                    self.authority_generation,
                    self.privacy_epoch,
                    authority.authority_generation,
                    authority.privacy_epoch
                ),
            });
        }
        Ok(())
    }

    /// Projects this post-repair receipt directly into `FSS-127` [`InspectedObject`] without
    /// collapsing `Staged`, `Verified`, `Quarantined`, or `Indeterminate` states.
    pub fn to_inspected_object(
        &self,
        custody: CustodyLevel,
        edges: Vec<ClosureEdge>,
    ) -> Result<InspectedObject, RepairGateError> {
        self.verify_self()?;
        match self.state {
            RepairGateState::VerifiedCanonicalMatch | RepairGateState::Published => {
                if custody == CustodyLevel::Staged {
                    return Ok(InspectedObject::StagedOnly {
                        byte_len: self.observed_byte_len,
                    });
                }
                Ok(InspectedObject::Present {
                    custody,
                    byte_len: self.expected_byte_len,
                    post_repair_verified: true,
                    edges,
                })
            }
            RepairGateState::Quarantined => Ok(InspectedObject::Corrupt {
                reason: self.detail.clone(),
            }),
            RepairGateState::ReconstructionStaged => Ok(InspectedObject::StagedOnly {
                byte_len: self.observed_byte_len,
            }),
            RepairGateState::Indeterminate => Ok(InspectedObject::Indeterminate {
                reason: self.detail.clone(),
            }),
            RepairGateState::Planned
            | RepairGateState::LeaseAcquired
            | RepairGateState::Cancelled => Ok(InspectedObject::Missing),
        }
    }

    /// Recomputes the canonical SHA-256 digest (`fss.atp_post_repair_receipt.v1`).
    pub fn compute_digest(&self) -> Result<ContentDigest, RepairGateError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(ATP_POST_REPAIR_RECEIPT_DOMAIN);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| RepairGateError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn verify_self(&self) -> Result<(), RepairGateError> {
        if self.format_version != REPAIR_RECEIPT_VERSION {
            return Err(RepairGateError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        validate_label(&self.detail, MAX_REPAIR_LABEL_BYTES, "detail")?;
        if self.source_generation == 0 || self.lease_fence == 0 {
            return Err(RepairGateError::MalformedWire(
                "source_generation and lease_fence must be >= 1".to_owned(),
            ));
        }
        if self.expected_byte_len == 0
            || self.expected_byte_len > MAX_RECONSTRUCTED_OBJECT_BYTES as u64
            || self.observed_byte_len > self.expected_byte_len
            || self.observed_reconstructed_digest.is_some() != (self.observed_byte_len > 0)
        {
            return Err(RepairGateError::MalformedWire(
                "byte length and observed digest invariants violated".to_owned(),
            ));
        }
        let accounted_symbols =
            (self.source_symbols_used as usize).saturating_add(self.repair_symbols_used as usize);
        if accounted_symbols != self.consumed_esis.len() {
            return Err(RepairGateError::MalformedWire(
                "source_symbols_used + repair_symbols_used must equal consumed_esis.len()"
                    .to_owned(),
            ));
        }
        if matches!(
            self.state,
            RepairGateState::VerifiedCanonicalMatch | RepairGateState::Published
        ) && (self.observed_reconstructed_digest != Some(self.target_object_digest)
            || self.observed_byte_len != self.expected_byte_len
            || self.consumed_esis.is_empty())
        {
            return Err(RepairGateError::MalformedWire(
                "verified/published receipt must match target_object_digest, expected_byte_len, and non-empty ESIs"
                    .to_owned(),
            ));
        }
        for &esi in &self.consumed_esis {
            if esi >= MAX_GF256_BLOCK_SYMBOLS {
                return Err(RepairGateError::MalformedWire(format!(
                    "consumed ESI {esi} exceeds GF(256) ceiling {MAX_GF256_BLOCK_SYMBOLS}"
                )));
            }
        }
        for pair in self.consumed_esis.windows(2) {
            if pair[0] >= pair[1] {
                return Err(RepairGateError::MalformedWire(
                    "consumed_esis must be strictly ascending and unique".to_owned(),
                ));
            }
        }
        if self.compute_digest()? != self.receipt_digest {
            return Err(RepairGateError::ChecksumMismatch);
        }
        Ok(())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.digest(self.plan_digest);
        enc.digest(self.sealed_root_digest);
        enc.digest(self.target_object_digest);
        match self.observed_reconstructed_digest {
            Some(d) => {
                enc.u8(1);
                enc.digest(d);
            }
            None => enc.u8(0),
        }
        enc.u64(self.expected_byte_len);
        enc.u64(self.observed_byte_len);
        enc.u64(self.source_generation);
        enc.digest(self.contract_basis_digest);
        enc.u64(self.authority_generation);
        enc.u64(self.privacy_epoch);
        enc.u64(self.lease_fence);
        enc.u8(self.state.tag());
        enc.u32(self.source_symbols_used);
        enc.u32(self.repair_symbols_used);
        enc.u32(self.duplicate_symbols_ignored);
        enc.u32(self.corrupt_symbols_rejected);
        enc.u32(self.consumed_esis.len() as u32);
        for esi in &self.consumed_esis {
            enc.u32(*esi);
        }
        enc.text(&self.detail);
        self.recorded_at.encode_canonical(enc);
    }

    /// Encodes this receipt into bounded, checksummed binary bytes (`FSSPRG01` v1).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, RepairGateError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        enc.digest(self.receipt_digest);
        let body = enc
            .finish_checked()
            .map_err(|e| RepairGateError::Encoding(e.to_string()))?;
        let total = REPAIR_RECEIPT_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_REPAIR_RECEIPT_WIRE_BYTES {
            return Err(RepairGateError::BoundsExceeded {
                observed: total,
                maximum: MAX_REPAIR_RECEIPT_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&REPAIR_RECEIPT_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and verifies a binary [`PostRepairReceipt`] (`FSSPRG01` v1).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RepairGateError> {
        if bytes.len() > MAX_REPAIR_RECEIPT_WIRE_BYTES {
            return Err(RepairGateError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_REPAIR_RECEIPT_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != REPAIR_RECEIPT_MAGIC {
            return Err(RepairGateError::InvalidMagic);
        }
        let header_ver = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if header_ver != REPAIR_RECEIPT_VERSION {
            return Err(RepairGateError::UnsupportedVersion {
                version: header_ver,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let format_version = dec
            .u32()
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
        if format_version != header_ver {
            return Err(RepairGateError::UnsupportedVersion {
                version: format_version,
            });
        }
        let plan_digest = dec
            .digest()
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
        let sealed_root_digest = dec
            .digest()
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
        let target_object_digest = dec
            .digest()
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
        let observed_reconstructed_digest = match dec
            .u8()
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?
        {
            0 => None,
            1 => Some(
                dec.digest()
                    .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?,
            ),
            other => {
                return Err(RepairGateError::MalformedWire(format!(
                    "invalid observed digest tag {other}"
                )));
            }
        };
        let expected_byte_len = dec
            .u64()
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
        let observed_byte_len = dec
            .u64()
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
        let source_generation = dec
            .u64()
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
        let contract_basis_digest = dec
            .digest()
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
        let authority_generation = dec
            .u64()
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
        let privacy_epoch = dec
            .u64()
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
        let lease_fence = dec
            .u64()
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
        let state = RepairGateState::from_tag(
            dec.u8()
                .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?,
        )
        .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
        let source_symbols_used = dec
            .u32()
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
        let repair_symbols_used = dec
            .u32()
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
        let duplicate_symbols_ignored = dec
            .u32()
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
        let corrupt_symbols_rejected = dec
            .u32()
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
        let esi_count =
            dec.u32()
                .map_err(|e| RepairGateError::MalformedWire(e.to_string()))? as usize;
        if esi_count > MAX_GF256_BLOCK_SYMBOLS as usize
            || esi_count.saturating_mul(4) > dec.remaining()
        {
            return Err(RepairGateError::BoundsExceeded {
                observed: esi_count,
                maximum: MAX_GF256_BLOCK_SYMBOLS as usize,
            });
        }
        let mut consumed_esis = Vec::with_capacity(esi_count);
        for _ in 0..esi_count {
            let esi = dec
                .u32()
                .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
            consumed_esis.push(esi);
        }
        let detail = dec
            .text()
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?
            .to_owned();
        let recorded_at = TimestampNs::decode_canonical(&mut dec)
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
        let stored_digest = dec
            .digest()
            .map_err(|e| RepairGateError::MalformedWire(e.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            RepairGateError::MalformedWire("trailing bytes after post-repair receipt".to_owned())
        })?;

        let receipt = Self {
            format_version,
            plan_digest,
            sealed_root_digest,
            target_object_digest,
            observed_reconstructed_digest,
            expected_byte_len,
            observed_byte_len,
            source_generation,
            contract_basis_digest,
            authority_generation,
            privacy_epoch,
            lease_fence,
            state,
            source_symbols_used,
            repair_symbols_used,
            duplicate_symbols_ignored,
            corrupt_symbols_rejected,
            consumed_esis,
            detail,
            recorded_at,
            receipt_digest: stored_digest,
        };
        receipt.verify_self()?;
        Ok(receipt)
    }
}

/// Deterministic post-repair canonical digest gate (`FSS-128`).
pub struct PostRepairDigestGate;

impl PostRepairDigestGate {
    /// Reconstructs the target object from `symbols` using deterministic GF(256) Cauchy decoding
    /// and enforces the mandatory post-repair canonical SHA-256 + exact-length + zero-padding gate.
    ///
    /// - Refuses revoked authority, authority escalation (`XFER-INV-006`), stale basis/generation,
    ///   expired/stale lease fence, or cooperative cancellation before decoding.
    /// - Refuses stale-generation or wrong-plan/wrong-object symbols with [`RepairGateError::StaleOrMismatchedSymbol`].
    /// - Deduplicates identical symbol ESIs deterministically (lowest `k` ESIs in canonical ascending
    ///   order when more than `k` valid symbols arrive, ensuring permutation invariance!).
    /// - Rejects symbols whose `payload` does not match `symbol_digest` (accounting them in
    ///   `corrupt_symbols_rejected`); if fewer than `k` clean symbols remain, OR if forged symbols
    ///   with valid self-digests reconstruct bytes whose canonical SHA-256 or padding fails to match
    ///   `plan.target_object_digest`, seals a [`RepairGateState::Quarantined`] receipt with
    ///   `verified_bytes = None` (NEVER claiming verified or publishable).
    /// - If `staging_io_indeterminate` is `true`, seals [`RepairGateState::Indeterminate`] with
    ///   `verified_bytes = None` so ambiguous staging I/O is never laundered into success.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct_and_verify(
        plan: &RepairPlan,
        authority: &RepairAuthorityContext,
        lease: &RepairLease,
        min_fence: u64,
        symbols: &[RepairSymbolEnvelope],
        now: TimestampNs,
        staging_io_indeterminate: bool,
        cancelled: bool,
    ) -> Result<GateExecutionResult, RepairGateError> {
        if cancelled {
            return Err(RepairGateError::Cancelled);
        }
        if symbols.len() > MAX_REPAIR_INPUT_ENVELOPES {
            return Err(RepairGateError::BoundsExceeded {
                observed: symbols.len(),
                maximum: MAX_REPAIR_INPUT_ENVELOPES,
            });
        }
        plan.verify_self()?;
        authority.validate_against(plan)?;
        lease.validate(plan, authority, min_fence, now)?;

        let total_symbols = plan
            .source_symbol_count
            .saturating_add(plan.repair_symbol_count);
        let sym_sz = plan.symbol_size as usize;

        // Group well-formed, self-verified symbols by `(esi -> symbol_digest -> (payload, count))`
        // so duplicate and equivocating-ESI accounting is 100% invariant to input permutation.
        let mut grouped_by_esi: BTreeMap<u32, BTreeMap<ContentDigest, (Vec<u8>, u32)>> =
            BTreeMap::new();
        let mut duplicate_symbols_ignored = 0_u32;
        let mut corrupt_symbols_rejected = 0_u32;

        for env in symbols {
            // Hard boundary: stale generation / wrong plan / wrong target object fails closed immediately!
            if env.plan_digest != plan.plan_digest
                || env.target_object_digest != plan.target_object_digest
                || env.source_generation != plan.source_generation
            {
                return Err(RepairGateError::StaleOrMismatchedSymbol {
                    esi: env.esi,
                    detail: format!(
                        "symbol gen {} / plan / object differs from sealed plan gen {}",
                        env.source_generation, plan.source_generation
                    ),
                });
            }
            if env.esi >= total_symbols || env.payload.len() != sym_sz {
                corrupt_symbols_rejected = corrupt_symbols_rejected.saturating_add(1);
                continue;
            }
            if env.compute_digest()? != env.symbol_digest {
                corrupt_symbols_rejected = corrupt_symbols_rejected.saturating_add(1);
                continue;
            }
            grouped_by_esi
                .entry(env.esi)
                .or_default()
                .entry(env.symbol_digest)
                .and_modify(|(_, count)| *count = count.saturating_add(1))
                .or_insert_with(|| (env.payload.clone(), 1));
        }

        let mut valid_by_esi: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        for (esi, variants) in grouped_by_esi {
            if variants.len() == 1 {
                let Some((_, (payload, count))) = variants.into_iter().next() else {
                    continue;
                };
                duplicate_symbols_ignored =
                    duplicate_symbols_ignored.saturating_add(count.saturating_sub(1));
                valid_by_esi.insert(esi, payload);
            } else {
                // Equivocating ESI (distinct payloads claiming the same ESI): reject all copies!
                let total_for_esi: u32 = variants
                    .values()
                    .fold(0_u32, |acc, (_, count)| acc.saturating_add(*count));
                corrupt_symbols_rejected = corrupt_symbols_rejected.saturating_add(total_for_esi);
            }
        }

        if staging_io_indeterminate {
            let receipt = seal_receipt(
                plan,
                authority,
                lease.fence,
                RepairGateState::Indeterminate,
                None,
                0,
                0,
                0,
                duplicate_symbols_ignored,
                corrupt_symbols_rejected,
                Vec::new(),
                "staging_io_indeterminate_requires_reconciliation",
                now,
            )?;
            return Ok(GateExecutionResult {
                receipt,
                verified_bytes: None,
            });
        }

        let k = plan.source_symbol_count as usize;
        if valid_by_esi.len() < k {
            let receipt = seal_receipt(
                plan,
                authority,
                lease.fence,
                RepairGateState::Quarantined,
                None,
                0,
                0,
                0,
                duplicate_symbols_ignored,
                corrupt_symbols_rejected,
                Vec::new(),
                &format!(
                    "insufficient_valid_symbols:{}_of_{k}_required",
                    valid_by_esi.len()
                ),
                now,
            )?;
            return Ok(GateExecutionResult {
                receipt,
                verified_bytes: None,
            });
        }

        // Canonical deterministic selection: lowest `k` ESIs (prefers systematic source symbols first).
        let selected: Vec<(u32, Vec<u8>)> = valid_by_esi.into_iter().take(k).collect();
        let consumed_esis: Vec<u32> = selected.iter().map(|(esi, _)| *esi).collect();
        let source_symbols_used = consumed_esis
            .iter()
            .filter(|&&esi| esi < plan.source_symbol_count)
            .count() as u32;
        let repair_symbols_used = consumed_esis
            .iter()
            .filter(|&&esi| esi >= plan.source_symbol_count)
            .count() as u32;

        let Some(recovered_blocks) = gf256_cauchy_decode(k, sym_sz, &selected) else {
            let receipt = seal_receipt(
                plan,
                authority,
                lease.fence,
                RepairGateState::Quarantined,
                None,
                0,
                source_symbols_used,
                repair_symbols_used,
                duplicate_symbols_ignored,
                corrupt_symbols_rejected,
                consumed_esis,
                "gf256_decode_matrix_singular",
                now,
            )?;
            return Ok(GateExecutionResult {
                receipt,
                verified_bytes: None,
            });
        };

        let expected_len = plan.expected_byte_len as usize;
        let mut staged = Vec::with_capacity(k * sym_sz);
        for block in recovered_blocks {
            staged.extend_from_slice(&block);
        }
        let trailing_pad_nonzero = staged[expected_len..].iter().any(|&b| b != 0);
        staged.truncate(expected_len);

        let observed_digest = ContentDigest::sha256(&staged);
        let observed_len = staged.len() as u64;

        // Mandatory post-repair canonical digest gate: BOTH exact digest AND zero-padding must pass!
        if trailing_pad_nonzero || observed_digest != plan.target_object_digest {
            let reason = if trailing_pad_nonzero && observed_digest != plan.target_object_digest {
                "post_repair_digest_and_padding_mismatch_quarantined"
            } else if trailing_pad_nonzero {
                "post_repair_nonzero_padding_quarantined"
            } else {
                "post_repair_canonical_digest_mismatch_quarantined"
            };
            let receipt = seal_receipt(
                plan,
                authority,
                lease.fence,
                RepairGateState::Quarantined,
                Some(observed_digest),
                observed_len,
                source_symbols_used,
                repair_symbols_used,
                duplicate_symbols_ignored,
                corrupt_symbols_rejected,
                consumed_esis,
                reason,
                now,
            )?;
            return Ok(GateExecutionResult {
                receipt,
                verified_bytes: None,
            });
        }

        let receipt = seal_receipt(
            plan,
            authority,
            lease.fence,
            RepairGateState::VerifiedCanonicalMatch,
            Some(observed_digest),
            observed_len,
            source_symbols_used,
            repair_symbols_used,
            duplicate_symbols_ignored,
            corrupt_symbols_rejected,
            consumed_esis,
            "post_repair_canonical_digest_verified",
            now,
        )?;
        Ok(GateExecutionResult {
            receipt,
            verified_bytes: Some(staged),
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn seal_receipt(
    plan: &RepairPlan,
    authority: &RepairAuthorityContext,
    lease_fence: u64,
    state: RepairGateState,
    observed_reconstructed_digest: Option<ContentDigest>,
    observed_byte_len: u64,
    source_symbols_used: u32,
    repair_symbols_used: u32,
    duplicate_symbols_ignored: u32,
    corrupt_symbols_rejected: u32,
    consumed_esis: Vec<u32>,
    detail: &str,
    recorded_at: TimestampNs,
) -> Result<PostRepairReceipt, RepairGateError> {
    validate_label(detail, MAX_REPAIR_LABEL_BYTES, "detail")?;
    let mut receipt = PostRepairReceipt {
        format_version: REPAIR_RECEIPT_VERSION,
        plan_digest: plan.plan_digest,
        sealed_root_digest: plan.sealed_root_digest,
        target_object_digest: plan.target_object_digest,
        observed_reconstructed_digest,
        expected_byte_len: plan.expected_byte_len,
        observed_byte_len,
        source_generation: plan.source_generation,
        contract_basis_digest: plan.contract_basis_digest,
        authority_generation: authority.authority_generation,
        privacy_epoch: authority.privacy_epoch,
        lease_fence,
        state,
        source_symbols_used,
        repair_symbols_used,
        duplicate_symbols_ignored,
        corrupt_symbols_rejected,
        consumed_esis,
        detail: detail.to_owned(),
        recorded_at,
        receipt_digest: ContentDigest::sha256(b"unsealed-post-repair-receipt"),
    };
    receipt.receipt_digest = receipt.compute_digest()?;
    Ok(receipt)
}

/// Pure-Rust `GF(2^8)` multiplication modulo `0x11D` (`x^8 + x^4 + x^3 + x^2 + 1`).
#[must_use]
pub const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut acc = 0_u8;
    let mut bit = 0_u8;
    while bit < 8 {
        if (b & 1) != 0 {
            acc ^= a;
        }
        let hi = (a & 0x80) != 0;
        a <<= 1;
        if hi {
            a ^= 0x1D;
        }
        b >>= 1;
        bit += 1;
    }
    acc
}

/// Pure-Rust `GF(2^8)` multiplicative inverse via Fermat's Little Theorem (`a^254`), `0 -> 0`.
#[must_use]
pub const fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let mut acc = 1_u8;
    let mut base = gf_mul(a, a); // a^2
    let mut step = 0_u8;
    while step < 7 {
        acc = gf_mul(acc, base);
        base = gf_mul(base, base);
        step += 1;
    }
    acc
}

fn gf_mul_add_slice(dst: &mut [u8], src: &[u8], coeff: u8) {
    if coeff == 0 {
        return;
    }
    if coeff == 1 {
        for (d, &s) in dst.iter_mut().zip(src.iter()) {
            *d ^= s;
        }
        return;
    }
    for (d, &s) in dst.iter_mut().zip(src.iter()) {
        *d ^= gf_mul(coeff, s);
    }
}

fn gf_scale_slice(dst: &mut [u8], coeff: u8) {
    if coeff == 1 {
        return;
    }
    for d in dst.iter_mut() {
        *d = gf_mul(*d, coeff);
    }
}

/// Exact Gauss-Jordan elimination over `GF(2^8)` for a `k x k` submatrix of `[I_k; Cauchy_{r x k}]`.
fn gf256_cauchy_decode(
    k: usize,
    symbol_size: usize,
    selected: &[(u32, Vec<u8>)],
) -> Option<Vec<Vec<u8>>> {
    if selected.len() != k {
        return None;
    }
    let mut matrix = vec![vec![0_u8; k]; k];
    let mut rhs: Vec<Vec<u8>> = Vec::with_capacity(k);
    for (row, (esi, payload)) in selected.iter().enumerate() {
        if payload.len() != symbol_size {
            return None;
        }
        rhs.push(payload.clone());
        let esi_usize = *esi as usize;
        if esi_usize < k {
            matrix[row][esi_usize] = 1;
        } else {
            let x = *esi as u8;
            for (col, cell) in matrix[row].iter_mut().enumerate() {
                *cell = gf_inv(x ^ (col as u8));
            }
        }
    }

    for col in 0..k {
        let pivot = (col..k).find(|&r| matrix[r][col] != 0)?;
        if pivot != col {
            matrix.swap(col, pivot);
            rhs.swap(col, pivot);
        }
        let inv_pivot = gf_inv(matrix[col][col]);
        if inv_pivot == 0 {
            return None;
        }
        if inv_pivot != 1 {
            for cell in &mut matrix[col][col..k] {
                *cell = gf_mul(*cell, inv_pivot);
            }
            gf_scale_slice(&mut rhs[col], inv_pivot);
        }
        for row in 0..k {
            if row == col {
                continue;
            }
            let factor = matrix[row][col];
            if factor == 0 {
                continue;
            }
            for c in col..k {
                let pivot_val = matrix[col][c];
                if pivot_val != 0 {
                    matrix[row][c] ^= gf_mul(factor, pivot_val);
                }
            }
            let (src_row, dst_row) = if col < row {
                let (left, right) = rhs.split_at_mut(row);
                (&left[col], &mut right[0])
            } else {
                let (left, right) = rhs.split_at_mut(col);
                (&right[0], &mut left[row])
            };
            gf_mul_add_slice(dst_row, src_row, factor);
        }
    }
    Some(rhs)
}

fn validate_label(value: &str, max_len: usize, label: &str) -> Result<(), RepairGateError> {
    if value.is_empty() || value.len() > max_len {
        return Err(RepairGateError::InvalidPlan(format!(
            "{label} length {} outside 1..={max_len}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(RepairGateError::InvalidPlan(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}
