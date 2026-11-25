#![forbid(unsafe_code)]
//! Archive Decision Cards for path, repair, and object sizing (`FSS-134`, `fss-x4a.13.18`).
//!
//! Composes [`PathKind`] (`FSS-129`), GF(256) repair bounds (`FSS-128`), and explicit pricing
//! manifests (`docs/ATP_ARCHIVE_AND_REPLICATION.md` §3, §5, §6, §11) to produce auditable,
//! hard-clamp-filtered, Pareto-nondominated **Archive Decision Cards** with ZERO opaque scoring
//! and ZERO hidden effect authority:
//!
//! - **Hard clamps first:** unauthorized privacy, unverified integrity, disallowed residency,
//!   exceeded verification memory, exceeded GF(256) block symbol ceiling, or insufficient durability
//!   candidates are rejected transparently into `clamped_rejections` BEFORE frontier ranking.
//! - **Pareto nondominated frontier:** evaluates explicit multi-objective integer cost vectors
//!   `(total_cost_micros, latency_ms, overhead_bps, verification_memory_bytes)` — separating truly
//!   nondominated frontier options from dominated alternatives with exact dominating-option proofs.
//! - **Pricing provenance & invalidators:** binds exact `pricing_manifest_digest` and
//!   `pricing_manifest_date` (never hardcoded cloud price constants!) plus explicit invalidators
//!   and expected proof.
//! - **Zero effect authority:** a Decision Card is derived cognition/planning advice only; any
//!   attempt to mark `grants_effect_authority = true` fails closed (`XFER-INV-006`).
//! - **Bounded checksummed binary codec (`FSSADC01` v1):** sealed under
//!   `fss.atp_archive_decision_card.v1`.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, TimestampNs,
};

use crate::multipath::PathKind;
use crate::repair_gate::{MAX_GF256_BLOCK_SYMBOLS, MAX_SYMBOL_SIZE};

/// Registered digest domain for sealed [`ArchiveDecisionCard`] commitments (`FSS-134`).
pub const ATP_ARCHIVE_DECISION_CARD_DOMAIN: &str = "fss.atp_archive_decision_card.v1";
/// Binary wire header magic for serialized archive decision cards.
pub const ARCHIVE_CARD_MAGIC: [u8; 8] = *b"FSSADC01";
/// Supported durable format version for [`ArchiveDecisionCard`].
pub const ARCHIVE_CARD_VERSION: u32 = 1;
/// Hard ceiling on candidate options evaluated in one archive decision card.
pub const MAX_ARCHIVE_CARD_OPTIONS: usize = 64;
/// Hard ceiling on sensitivity invalidators attached to one card.
pub const MAX_CARD_INVALIDATORS: usize = 32;
/// Hard ceiling on label/note UTF-8 bytes.
pub const MAX_CARD_LABEL_BYTES: usize = 256;
/// Hard ceiling on serialized card wire bytes (512 KiB).
pub const MAX_ARCHIVE_CARD_WIRE_BYTES: usize = 512 * 1024;

/// Decision domain governed by one [`ArchiveDecisionCard`].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ArchiveDecisionKind {
    /// Multipath transfer path selection (latency vs egress vs failure-domain resilience).
    PathSelection = 1,
    /// RaptorQ / GF(256) repair symbol sizing (loss tolerance vs storage overhead vs decode memory).
    RepairOverheadSizing = 2,
    /// Chunk/object sizing (keyframe alignment vs Class-A PUT ops vs retrieval/verification memory).
    ObjectChunkSizing = 3,
}

impl ArchiveDecisionKind {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PathSelection => "path_selection",
            Self::RepairOverheadSizing => "repair_overhead_sizing",
            Self::ObjectChunkSizing => "object_chunk_sizing",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::PathSelection),
            2 => Ok(Self::RepairOverheadSizing),
            3 => Ok(Self::ObjectChunkSizing),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Safe operator/agent recovery guidance for a refused archive decision card.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveCardGuidance {
    /// Fix invalid pricing manifest, duplicate option IDs, or hard clamp bounds.
    RepairDecisionInputs,
    /// Re-authorize revoked capability/privacy or strip forbidden effect authority.
    ReauthorizePlanningContext,
    /// Supply at least one option satisfying hard privacy, residency, durability, and memory clamps.
    ProvidePolicyCompliantOption,
    /// Cooperative cancellation observed; retry when ready.
    RetryWhenReady,
    /// Reject corrupt or unsupported binary card bytes.
    RejectCorruptCard,
}

/// Typed error returned by [`ArchiveDecisionCardBuilder`] or [`ArchiveDecisionCard`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchiveCardError {
    /// Invalid pricing manifest, option geometry, or label bounds.
    InvalidInput(String),
    /// Capability/privacy revoked or effect authority illegally attached (`XFER-INV-006`).
    AuthorityRefused(String),
    /// Every candidate option failed hard durability, privacy, residency, or memory clamps.
    AllOptionsClamped {
        /// Number of rejected options.
        clamped_count: usize,
    },
    /// Cooperative cancellation observed before card emission.
    Cancelled,
    /// Option count or wire length exceeded hard ceilings.
    BoundsExceeded {
        /// Observed size/count.
        observed: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Binary card lacked [`ARCHIVE_CARD_MAGIC`].
    InvalidMagic,
    /// Binary card declared an unsupported version.
    UnsupportedVersion {
        /// Observed version.
        version: u32,
    },
    /// Binary card was truncated, non-canonical, or structurally inconsistent.
    MalformedWire(String),
    /// Card canonical checksum failed verification.
    ChecksumMismatch,
    /// Canonical encoder failure.
    Encoding(String),
}

impl ArchiveCardError {
    /// Stable canonical machine error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "ERR-ATP-DECISION-CARD-INVALID-INPUT-001",
            Self::AuthorityRefused(_) => "ERR-ATP-DECISION-CARD-AUTHORITY-001",
            Self::AllOptionsClamped { .. } => "ERR-ATP-DECISION-CARD-ALL-CLAMPED-001",
            Self::Cancelled => "ERR-ATP-DECISION-CARD-CANCELLED-001",
            Self::BoundsExceeded { .. } => "ERR-ATP-DECISION-CARD-BOUNDS-001",
            Self::InvalidMagic => "ERR-ATP-DECISION-CARD-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-ATP-DECISION-CARD-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-ATP-DECISION-CARD-MALFORMED-WIRE-001",
            Self::ChecksumMismatch => "ERR-ATP-DECISION-CARD-CHECKSUM-MISMATCH-001",
            Self::Encoding(_) => "ERR-ATP-DECISION-CARD-ENCODING-001",
        }
    }

    /// Safe recovery guidance.
    #[must_use]
    pub const fn guidance(&self) -> ArchiveCardGuidance {
        match self {
            Self::InvalidInput(_) | Self::BoundsExceeded { .. } => {
                ArchiveCardGuidance::RepairDecisionInputs
            }
            Self::AuthorityRefused(_) => ArchiveCardGuidance::ReauthorizePlanningContext,
            Self::AllOptionsClamped { .. } => ArchiveCardGuidance::ProvidePolicyCompliantOption,
            Self::Cancelled => ArchiveCardGuidance::RetryWhenReady,
            Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::MalformedWire(_)
            | Self::ChecksumMismatch
            | Self::Encoding(_) => ArchiveCardGuidance::RejectCorruptCard,
        }
    }
}

impl fmt::Display for ArchiveCardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for ArchiveCardError {}

/// Explicit input pricing manifest reference (`docs/ATP_ARCHIVE_AND_REPLICATION.md` §11: pricing is
/// an input manifest with date/source, NEVER hardcoded code constants).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PricingManifestRef {
    /// Content digest of the input pricing manifest.
    pub manifest_digest: ContentDigest,
    /// Effective ISO date string (e.g. `"2026-08-31"`).
    pub effective_date: String,
    /// Pricing source tuple (e.g. `"r2-and-b2-operator-manifest-v1"`).
    pub source_label: String,
}

/// Hard non-negotiable constraints evaluated BEFORE Pareto frontier ranking.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveHardClamps {
    /// Allowed data residency zones.
    pub allowed_residency_zones: BTreeSet<String>,
    /// Minimum required independent failure domains (`>= 1`).
    pub min_failure_domains: u32,
    /// Minimum required symbol-loss tolerance in basis points (`0..=10_000`).
    pub min_loss_tolerance_bps: u32,
    /// Maximum allowed verification memory footprint (bytes).
    pub max_verification_memory_bytes: u64,
    /// Maximum allowed total cost per workload window (micro-USD).
    pub max_total_cost_micros: u64,
    /// Require privacy authorization on every admitted option.
    pub require_privacy_authorized: bool,
    /// Require canonical integrity verification on every admitted option.
    pub require_integrity_verified: bool,
}

/// Planning authority context (`grants_effect_authority` MUST be `false` — Decision Cards never
/// execute transfers, repairs, or deletions!).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchivePlanningAuthority {
    /// Pinned `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Active authority generation.
    pub authority_generation: u64,
    /// Expected authority generation.
    pub expected_authority_generation: u64,
    /// Active privacy policy epoch.
    pub privacy_epoch: u64,
    /// True while read/planning capability remains active.
    pub capability_active: bool,
    /// True while privacy authorization remains active.
    pub privacy_active: bool,
    /// MUST remain `false`: a Decision Card recommendation never grants effect authority!
    pub grants_effect_authority: bool,
}

impl ArchivePlanningAuthority {
    /// Constructs an active planning-only authority context (`grants_effect_authority = false`).
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
            capability_active: true,
            privacy_active: true,
            grants_effect_authority: false,
        }
    }

    fn validate(&self) -> Result<(), ArchiveCardError> {
        if self.grants_effect_authority {
            return Err(ArchiveCardError::AuthorityRefused(
                "archive decision card cannot grant effect authority (XFER-INV-006)".to_owned(),
            ));
        }
        if !self.capability_active || !self.privacy_active {
            return Err(ArchiveCardError::AuthorityRefused(
                "archive planning capability or privacy authorization revoked".to_owned(),
            ));
        }
        if self.authority_generation != self.expected_authority_generation {
            return Err(ArchiveCardError::AuthorityRefused(format!(
                "stale authority generation {} != expected {}",
                self.authority_generation, self.expected_authority_generation
            )));
        }
        Ok(())
    }
}

/// Candidate option evaluated for path selection, repair overhead sizing, or object chunk sizing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveOptionSpec {
    /// Stable option identity (`1..=MAX_CARD_LABEL_BYTES`).
    pub option_id: String,
    /// Transport medium class (relevant to path selection / archive target).
    pub path_kind: PathKind,
    /// Residency zone label.
    pub residency_zone: String,
    /// Independent failure domains satisfied.
    pub failure_domains: u32,
    /// True iff privacy policy authorizes this option.
    pub privacy_authorized: bool,
    /// True iff canonical digest integrity verification is preserved.
    pub integrity_verified: bool,
    /// Chunk or object target size in bytes (`>= 1`).
    pub chunk_bytes: u64,
    /// Optional GF(256) repair symbol geometry `(symbol_size, source_k, repair_r)`.
    pub repair_geometry: Option<(u32, u32, u32)>,
    /// True when chunking preserves media keyframe/container boundaries (`§3`).
    pub keyframe_aligned: bool,
    /// Loss tolerance in basis points (`0..=10_000`, e.g. `2500` = tolerates 25% symbol loss).
    pub loss_tolerance_bps: u32,
    /// Exact decomposed cost vector (lower is strictly better on all 4 objectives!).
    /// Storage + Class-A/B ops + retrieval + egress total cost (micro-USD).
    pub total_cost_micros: u64,
    /// End-to-end p95 operation latency (milliseconds).
    pub latency_ms: u64,
    /// Storage / parity overhead in basis points (`0` = 0%, `2500` = 25% overhead).
    pub overhead_bps: u32,
    /// Peak RAM required for canonical verification/reconstruction (bytes).
    pub verification_memory_bytes: u64,
    /// Explicit expected proof description verifying this option after execution.
    pub expected_proof: String,
}

/// Audit record of one option rejected by hard clamps BEFORE Pareto frontier evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClampedOptionRejection {
    /// Rejected option identity.
    pub option_id: String,
    /// Machine-readable clamp violation reason.
    pub reason: String,
}

/// Record of one feasible option strictly dominated by at least one frontier option.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DominatedOptionRecord {
    /// Dominated option identity.
    pub option_id: String,
    /// Frontier option identity that strictly dominates it across the 4-objective cost vector.
    pub dominated_by: String,
}

/// Sealed, hard-clamp-filtered, Pareto-nondominated Archive Decision Card (`FSSADC01` v1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveDecisionCard {
    /// Wire format version (`ARCHIVE_CARD_VERSION`).
    pub format_version: u32,
    /// Stable card identity.
    pub card_id: String,
    /// Decision family (`PathSelection`, `RepairOverheadSizing`, `ObjectChunkSizing`).
    pub kind: ArchiveDecisionKind,
    /// Exact pinned `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Active authority generation.
    pub authority_generation: u64,
    /// Active privacy policy epoch.
    pub privacy_epoch: u64,
    /// Explicit pricing manifest reference (no hardcoded prices).
    pub pricing_manifest: PricingManifestRef,
    /// Options rejected by hard privacy, integrity, residency, durability, memory, or GF(256) clamps.
    pub clamped_rejections: Vec<ClampedOptionRejection>,
    /// Exact Pareto-nondominated frontier options in canonical ascending `(total_cost_micros, latency_ms, overhead_bps, verification_memory_bytes, option_id)` order.
    pub nondominated_frontier: Vec<ArchiveOptionSpec>,
    /// Feasible options strictly dominated by a frontier member (preserved transparently).
    pub dominated_options: Vec<DominatedOptionRecord>,
    /// Explicit conditions that invalidate this card and require recomputation.
    pub invalidators: Vec<String>,
    /// Timestamp when this card was sealed.
    pub generated_at: TimestampNs,
    /// Domain-separated SHA-256 commitment (`fss.atp_archive_decision_card.v1`).
    pub card_digest: ContentDigest,
}

impl ArchiveDecisionCard {
    /// Recomputes the domain-separated SHA-256 commitment (`fss.atp_archive_decision_card.v1`).
    pub fn compute_digest(&self) -> Result<ContentDigest, ArchiveCardError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(ATP_ARCHIVE_DECISION_CARD_DOMAIN);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| ArchiveCardError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn verify_self(&self) -> Result<(), ArchiveCardError> {
        if self.format_version != ARCHIVE_CARD_VERSION {
            return Err(ArchiveCardError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        validate_label(&self.card_id, MAX_CARD_LABEL_BYTES, "card_id")
            .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
        validate_label(
            &self.pricing_manifest.effective_date,
            MAX_CARD_LABEL_BYTES,
            "effective_date",
        )
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
        validate_label(
            &self.pricing_manifest.source_label,
            MAX_CARD_LABEL_BYTES,
            "source_label",
        )
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
        if self.nondominated_frontier.is_empty() {
            return Err(ArchiveCardError::MalformedWire(
                "nondominated_frontier must be non-empty".to_owned(),
            ));
        }
        // Verify frontier is genuinely mutually nondominated!
        for (i, a) in self.nondominated_frontier.iter().enumerate() {
            for (j, b) in self.nondominated_frontier.iter().enumerate() {
                if i != j && dominates(a, b) {
                    return Err(ArchiveCardError::MalformedWire(format!(
                        "frontier option '{}' strictly dominates '{}'",
                        a.option_id, b.option_id
                    )));
                }
            }
        }
        for pair in self.clamped_rejections.windows(2) {
            if pair[0].option_id >= pair[1].option_id {
                return Err(ArchiveCardError::MalformedWire(
                    "clamped_rejections must be strictly ordered by option_id".to_owned(),
                ));
            }
        }
        for pair in self.dominated_options.windows(2) {
            if pair[0].option_id >= pair[1].option_id {
                return Err(ArchiveCardError::MalformedWire(
                    "dominated_options must be strictly ordered by option_id".to_owned(),
                ));
            }
        }
        let frontier_ids: BTreeSet<&str> = self
            .nondominated_frontier
            .iter()
            .map(|o| o.option_id.as_str())
            .collect();
        if frontier_ids.len() != self.nondominated_frontier.len() {
            return Err(ArchiveCardError::MalformedWire(
                "duplicate option_id in nondominated_frontier".to_owned(),
            ));
        }
        let mut all_ids = frontier_ids.clone();
        for rej in &self.clamped_rejections {
            if !all_ids.insert(rej.option_id.as_str()) {
                return Err(ArchiveCardError::MalformedWire(format!(
                    "option_id '{}' overlaps across card partitions",
                    rej.option_id
                )));
            }
        }
        for dom in &self.dominated_options {
            if !all_ids.insert(dom.option_id.as_str()) {
                return Err(ArchiveCardError::MalformedWire(format!(
                    "option_id '{}' overlaps across card partitions",
                    dom.option_id
                )));
            }
            if !frontier_ids.contains(dom.dominated_by.as_str()) {
                return Err(ArchiveCardError::MalformedWire(format!(
                    "dominated_by '{}' is not present in nondominated_frontier",
                    dom.dominated_by
                )));
            }
        }
        if self.compute_digest()? != self.card_digest {
            return Err(ArchiveCardError::ChecksumMismatch);
        }
        Ok(())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.text(&self.card_id);
        enc.u8(self.kind.tag());
        enc.digest(self.contract_basis_digest);
        enc.u64(self.authority_generation);
        enc.u64(self.privacy_epoch);
        enc.digest(self.pricing_manifest.manifest_digest);
        enc.text(&self.pricing_manifest.effective_date);
        enc.text(&self.pricing_manifest.source_label);
        enc.u32(self.clamped_rejections.len() as u32);
        for rej in &self.clamped_rejections {
            enc.text(&rej.option_id);
            enc.text(&rej.reason);
        }
        enc.u32(self.nondominated_frontier.len() as u32);
        for opt in &self.nondominated_frontier {
            encode_option(opt, enc);
        }
        enc.u32(self.dominated_options.len() as u32);
        for dom in &self.dominated_options {
            enc.text(&dom.option_id);
            enc.text(&dom.dominated_by);
        }
        enc.u32(self.invalidators.len() as u32);
        for inv in &self.invalidators {
            enc.text(inv);
        }
        self.generated_at.encode_canonical(enc);
    }

    /// Encodes this card into bounded checksummed binary bytes (`FSSADC01` v1).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ArchiveCardError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        enc.digest(self.card_digest);
        let body = enc
            .finish_checked()
            .map_err(|e| ArchiveCardError::Encoding(e.to_string()))?;
        let total = ARCHIVE_CARD_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_ARCHIVE_CARD_WIRE_BYTES {
            return Err(ArchiveCardError::BoundsExceeded {
                observed: total,
                maximum: MAX_ARCHIVE_CARD_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&ARCHIVE_CARD_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and verifies a binary [`ArchiveDecisionCard`] (`FSSADC01` v1).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ArchiveCardError> {
        if bytes.len() > MAX_ARCHIVE_CARD_WIRE_BYTES {
            return Err(ArchiveCardError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_ARCHIVE_CARD_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != ARCHIVE_CARD_MAGIC {
            return Err(ArchiveCardError::InvalidMagic);
        }
        let header_ver = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if header_ver != ARCHIVE_CARD_VERSION {
            return Err(ArchiveCardError::UnsupportedVersion {
                version: header_ver,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let format_version = dec
            .u32()
            .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
        if format_version != header_ver {
            return Err(ArchiveCardError::UnsupportedVersion {
                version: format_version,
            });
        }
        let card_id = dec
            .text()
            .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?
            .to_owned();
        let kind = ArchiveDecisionKind::from_tag(
            dec.u8()
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?,
        )
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
        let contract_basis_digest = dec
            .digest()
            .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
        let authority_generation = dec
            .u64()
            .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
        let privacy_epoch = dec
            .u64()
            .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
        let pricing_manifest = PricingManifestRef {
            manifest_digest: dec
                .digest()
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?,
            effective_date: dec
                .text()
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?
                .to_owned(),
            source_label: dec
                .text()
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?
                .to_owned(),
        };

        let rej_count =
            dec.u32()
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))? as usize;
        if rej_count > MAX_ARCHIVE_CARD_OPTIONS || rej_count.saturating_mul(10) > dec.remaining() {
            return Err(ArchiveCardError::BoundsExceeded {
                observed: rej_count,
                maximum: MAX_ARCHIVE_CARD_OPTIONS,
            });
        }
        let mut clamped_rejections = Vec::with_capacity(rej_count);
        for _ in 0..rej_count {
            let option_id = dec
                .text()
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?
                .to_owned();
            let reason = dec
                .text()
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?
                .to_owned();
            validate_label(&option_id, MAX_CARD_LABEL_BYTES, "option_id")
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
            validate_label(&reason, MAX_CARD_LABEL_BYTES, "reason")
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
            clamped_rejections.push(ClampedOptionRejection { option_id, reason });
        }

        let front_count =
            dec.u32()
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))? as usize;
        if front_count > MAX_ARCHIVE_CARD_OPTIONS
            || front_count.saturating_mul(40) > dec.remaining()
        {
            return Err(ArchiveCardError::BoundsExceeded {
                observed: front_count,
                maximum: MAX_ARCHIVE_CARD_OPTIONS,
            });
        }
        let mut nondominated_frontier = Vec::with_capacity(front_count);
        for _ in 0..front_count {
            nondominated_frontier.push(decode_option(&mut dec)?);
        }

        let dom_count =
            dec.u32()
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))? as usize;
        if dom_count > MAX_ARCHIVE_CARD_OPTIONS || dom_count.saturating_mul(10) > dec.remaining() {
            return Err(ArchiveCardError::BoundsExceeded {
                observed: dom_count,
                maximum: MAX_ARCHIVE_CARD_OPTIONS,
            });
        }
        let mut dominated_options = Vec::with_capacity(dom_count);
        for _ in 0..dom_count {
            let option_id = dec
                .text()
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?
                .to_owned();
            let dominated_by = dec
                .text()
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?
                .to_owned();
            validate_label(&option_id, MAX_CARD_LABEL_BYTES, "option_id")
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
            validate_label(&dominated_by, MAX_CARD_LABEL_BYTES, "dominated_by")
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
            dominated_options.push(DominatedOptionRecord {
                option_id,
                dominated_by,
            });
        }

        let inv_count =
            dec.u32()
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))? as usize;
        if inv_count > MAX_CARD_INVALIDATORS || inv_count.saturating_mul(5) > dec.remaining() {
            return Err(ArchiveCardError::BoundsExceeded {
                observed: inv_count,
                maximum: MAX_CARD_INVALIDATORS,
            });
        }
        let mut invalidators = Vec::with_capacity(inv_count);
        for _ in 0..inv_count {
            let text = dec
                .text()
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?
                .to_owned();
            validate_label(&text, MAX_CARD_LABEL_BYTES, "invalidator")
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
            invalidators.push(text);
        }

        let generated_at = TimestampNs::decode_canonical(&mut dec)
            .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
        let stored_digest = dec
            .digest()
            .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            ArchiveCardError::MalformedWire("trailing bytes after archive decision card".to_owned())
        })?;

        let card = Self {
            format_version,
            card_id,
            kind,
            contract_basis_digest,
            authority_generation,
            privacy_epoch,
            pricing_manifest,
            clamped_rejections,
            nondominated_frontier,
            dominated_options,
            invalidators,
            generated_at,
            card_digest: stored_digest,
        };
        card.verify_self()?;
        Ok(card)
    }
}

/// Deterministic hard-clamp + Pareto-frontier builder for [`ArchiveDecisionCard`] (`FSS-134`).
pub struct ArchiveDecisionCardBuilder;

impl ArchiveDecisionCardBuilder {
    /// Evaluates `options` under `clamps` and builds a sealed Pareto-nondominated
    /// [`ArchiveDecisionCard`] independent of candidate submission order.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        card_id: &str,
        kind: ArchiveDecisionKind,
        authority: &ArchivePlanningAuthority,
        pricing_manifest: PricingManifestRef,
        clamps: &ArchiveHardClamps,
        options: Vec<ArchiveOptionSpec>,
        mut invalidators: Vec<String>,
        generated_at: TimestampNs,
        cancelled: bool,
    ) -> Result<ArchiveDecisionCard, ArchiveCardError> {
        if cancelled {
            return Err(ArchiveCardError::Cancelled);
        }
        authority.validate()?;
        validate_label(card_id, MAX_CARD_LABEL_BYTES, "card_id")?;
        validate_label(
            &pricing_manifest.effective_date,
            MAX_CARD_LABEL_BYTES,
            "effective_date",
        )?;
        validate_label(
            &pricing_manifest.source_label,
            MAX_CARD_LABEL_BYTES,
            "source_label",
        )?;
        if clamps.allowed_residency_zones.is_empty()
            || clamps.min_failure_domains == 0
            || clamps.max_verification_memory_bytes == 0
            || !clamps.require_privacy_authorized
            || !clamps.require_integrity_verified
        {
            return Err(ArchiveCardError::InvalidInput(
                "hard clamps must enforce residency, durability, memory, privacy, and integrity"
                    .to_owned(),
            ));
        }
        if options.is_empty() || options.len() > MAX_ARCHIVE_CARD_OPTIONS {
            return Err(ArchiveCardError::BoundsExceeded {
                observed: options.len(),
                maximum: MAX_ARCHIVE_CARD_OPTIONS,
            });
        }
        if invalidators.len() > MAX_CARD_INVALIDATORS {
            return Err(ArchiveCardError::BoundsExceeded {
                observed: invalidators.len(),
                maximum: MAX_CARD_INVALIDATORS,
            });
        }
        for inv in &invalidators {
            validate_label(inv, MAX_CARD_LABEL_BYTES, "invalidator")?;
        }
        invalidators.sort();
        invalidators.dedup();

        let mut seen_ids = BTreeSet::new();
        let mut clamped_rejections = Vec::new();
        let mut feasible = Vec::new();

        for opt in options {
            validate_label(&opt.option_id, MAX_CARD_LABEL_BYTES, "option_id")?;
            validate_label(&opt.residency_zone, MAX_CARD_LABEL_BYTES, "residency_zone")?;
            validate_label(&opt.expected_proof, MAX_CARD_LABEL_BYTES, "expected_proof")?;
            if opt.chunk_bytes == 0 || opt.loss_tolerance_bps > 10_000 {
                return Err(ArchiveCardError::InvalidInput(format!(
                    "option '{}' has invalid chunk_bytes or loss_tolerance_bps",
                    opt.option_id
                )));
            }
            if !seen_ids.insert(opt.option_id.clone()) {
                return Err(ArchiveCardError::InvalidInput(format!(
                    "duplicate option_id '{}'",
                    opt.option_id
                )));
            }
            if let Some(reason) = evaluate_hard_clamps(&opt, clamps) {
                clamped_rejections.push(ClampedOptionRejection {
                    option_id: opt.option_id,
                    reason,
                });
                continue;
            }
            feasible.push(opt);
        }

        clamped_rejections.sort_by(|a, b| a.option_id.cmp(&b.option_id));
        if feasible.is_empty() {
            return Err(ArchiveCardError::AllOptionsClamped {
                clamped_count: clamped_rejections.len(),
            });
        }

        // Canonical sort before Pareto decomposition so results are 100% submission-order invariant!
        feasible.sort_by(|a, b| {
            (
                a.total_cost_micros,
                a.latency_ms,
                a.overhead_bps,
                a.verification_memory_bytes,
                a.option_id.as_str(),
            )
                .cmp(&(
                    b.total_cost_micros,
                    b.latency_ms,
                    b.overhead_bps,
                    b.verification_memory_bytes,
                    b.option_id.as_str(),
                ))
        });

        let mut nondominated_frontier = Vec::new();
        let mut dominated_options = Vec::new();
        for candidate in &feasible {
            if let Some(dom) = feasible
                .iter()
                .find(|other| other.option_id != candidate.option_id && dominates(other, candidate))
            {
                dominated_options.push(DominatedOptionRecord {
                    option_id: candidate.option_id.clone(),
                    dominated_by: dom.option_id.clone(),
                });
            } else {
                nondominated_frontier.push(candidate.clone());
            }
        }
        dominated_options.sort_by(|a, b| a.option_id.cmp(&b.option_id));

        let mut card = ArchiveDecisionCard {
            format_version: ARCHIVE_CARD_VERSION,
            card_id: card_id.to_owned(),
            kind,
            contract_basis_digest: authority.contract_basis_digest,
            authority_generation: authority.authority_generation,
            privacy_epoch: authority.privacy_epoch,
            pricing_manifest,
            clamped_rejections,
            nondominated_frontier,
            dominated_options,
            invalidators,
            generated_at,
            card_digest: ContentDigest::sha256(b"unsealed-archive-decision-card"),
        };
        card.card_digest = card.compute_digest()?;
        Ok(card)
    }
}

fn evaluate_hard_clamps(opt: &ArchiveOptionSpec, clamps: &ArchiveHardClamps) -> Option<String> {
    if !opt.privacy_authorized {
        return Some("privacy_not_authorized".to_owned());
    }
    if !opt.integrity_verified {
        return Some("integrity_not_verified".to_owned());
    }
    if !clamps.allowed_residency_zones.contains(&opt.residency_zone) {
        return Some(format!("residency_zone_{}_disallowed", opt.residency_zone));
    }
    if opt.failure_domains < clamps.min_failure_domains {
        return Some(format!(
            "failure_domains_{}_below_{}",
            opt.failure_domains, clamps.min_failure_domains
        ));
    }
    if opt.loss_tolerance_bps < clamps.min_loss_tolerance_bps {
        return Some(format!(
            "loss_tolerance_bps_{}_below_{}",
            opt.loss_tolerance_bps, clamps.min_loss_tolerance_bps
        ));
    }
    if opt.verification_memory_bytes > clamps.max_verification_memory_bytes {
        return Some(format!(
            "verification_memory_{}_exceeds_{}",
            opt.verification_memory_bytes, clamps.max_verification_memory_bytes
        ));
    }
    if opt.total_cost_micros > clamps.max_total_cost_micros {
        return Some(format!(
            "total_cost_{}_exceeds_{}",
            opt.total_cost_micros, clamps.max_total_cost_micros
        ));
    }
    if let Some((sym_sz, k, r)) = opt.repair_geometry
        && (sym_sz == 0
            || (sym_sz as usize) > MAX_SYMBOL_SIZE
            || k == 0
            || r == 0
            || k.saturating_add(r) > MAX_GF256_BLOCK_SYMBOLS)
    {
        return Some("repair_geometry_exceeds_gf256_bounds".to_owned());
    }
    None
}

/// True iff option `a` is `<=` option `b` on ALL four cost/risk objectives and strictly `<` on at
/// least one objective (Pareto dominance).
fn dominates(a: &ArchiveOptionSpec, b: &ArchiveOptionSpec) -> bool {
    let le_all = a.total_cost_micros <= b.total_cost_micros
        && a.latency_ms <= b.latency_ms
        && a.overhead_bps <= b.overhead_bps
        && a.verification_memory_bytes <= b.verification_memory_bytes;
    let lt_any = a.total_cost_micros < b.total_cost_micros
        || a.latency_ms < b.latency_ms
        || a.overhead_bps < b.overhead_bps
        || a.verification_memory_bytes < b.verification_memory_bytes;
    le_all && lt_any
}

fn encode_option(opt: &ArchiveOptionSpec, enc: &mut CanonicalEncoder) {
    enc.text(&opt.option_id);
    enc.text(opt.path_kind.as_str());
    enc.text(&opt.residency_zone);
    enc.u32(opt.failure_domains);
    enc.bool(opt.privacy_authorized);
    enc.bool(opt.integrity_verified);
    enc.u64(opt.chunk_bytes);
    match opt.repair_geometry {
        Some((s, k, r)) => {
            enc.u8(1);
            enc.u32(s);
            enc.u32(k);
            enc.u32(r);
        }
        None => enc.u8(0),
    }
    enc.bool(opt.keyframe_aligned);
    enc.u32(opt.loss_tolerance_bps);
    enc.u64(opt.total_cost_micros);
    enc.u64(opt.latency_ms);
    enc.u32(opt.overhead_bps);
    enc.u64(opt.verification_memory_bytes);
    enc.text(&opt.expected_proof);
}

fn decode_option(dec: &mut CanonicalDecoder<'_>) -> Result<ArchiveOptionSpec, ArchiveCardError> {
    let option_id = dec
        .text()
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?
        .to_owned();
    validate_label(&option_id, MAX_CARD_LABEL_BYTES, "option_id")
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
    let path_kind = match dec
        .text()
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?
    {
        "local_disk" => PathKind::LocalDisk,
        "lan_peer" => PathKind::LanPeer,
        "cloud_provider" => PathKind::CloudProvider,
        "repair_source" => PathKind::RepairSource,
        other => {
            return Err(ArchiveCardError::MalformedWire(format!(
                "unknown path_kind '{other}'"
            )));
        }
    };
    let residency_zone = dec
        .text()
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?
        .to_owned();
    validate_label(&residency_zone, MAX_CARD_LABEL_BYTES, "residency_zone")
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
    let failure_domains = dec
        .u32()
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
    let privacy_authorized = dec
        .bool()
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
    let integrity_verified = dec
        .bool()
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
    let chunk_bytes = dec
        .u64()
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
    let repair_geometry = match dec
        .u8()
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?
    {
        0 => None,
        1 => Some((
            dec.u32()
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?,
            dec.u32()
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?,
            dec.u32()
                .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?,
        )),
        other => {
            return Err(ArchiveCardError::MalformedWire(format!(
                "invalid repair_geometry tag {other}"
            )));
        }
    };
    let keyframe_aligned = dec
        .bool()
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
    let loss_tolerance_bps = dec
        .u32()
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
    let total_cost_micros = dec
        .u64()
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
    let latency_ms = dec
        .u64()
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
    let overhead_bps = dec
        .u32()
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
    let verification_memory_bytes = dec
        .u64()
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
    let expected_proof = dec
        .text()
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?
        .to_owned();
    validate_label(&expected_proof, MAX_CARD_LABEL_BYTES, "expected_proof")
        .map_err(|e| ArchiveCardError::MalformedWire(e.to_string()))?;
    Ok(ArchiveOptionSpec {
        option_id,
        path_kind,
        residency_zone,
        failure_domains,
        privacy_authorized,
        integrity_verified,
        chunk_bytes,
        repair_geometry,
        keyframe_aligned,
        loss_tolerance_bps,
        total_cost_micros,
        latency_ms,
        overhead_bps,
        verification_memory_bytes,
        expected_proof,
    })
}

fn validate_label(value: &str, max_len: usize, label: &str) -> Result<(), ArchiveCardError> {
    if value.is_empty() || value.len() > max_len {
        return Err(ArchiveCardError::InvalidInput(format!(
            "{label} length {} outside 1..={max_len}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(ArchiveCardError::InvalidInput(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}
