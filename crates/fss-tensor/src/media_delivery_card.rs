#![forbid(unsafe_code)]
//! Deterministic Media Delivery, Live Surface, Archive Tier, and Backend Portability Decision Card
//! (`DOC-052`, bead `fss-x4a.5.52`).
//!
//! Enforces physical media-movement policy as auditable derived cognition:
//! - **Remux before transcode:** preserves source-coded bytes whenever codec/container/client
//!   compatible; transcode requires explicit justification (`ClientCodecIncompatibility`,
//!   `BandwidthCap`, `PrivacyRedaction`, or `ModelAnalysisInput`) and a sealed
//!   [`MediaDerivativeReceipt`] (`DOC-041`). Source custody is never overwritten.
//! - **Capability-projected live gateway:** compares `AuthorizedWebRtc`, `LlHlsCmafFmp4`,
//!   `SameHostFrameTransport`, and `JustifiedRtpRtspRelay` while hard-clamping out any gateway
//!   with vendor credentials, unmasked proxies (when privacy masking is required), expired auth,
//!   or unbounded bandwidth.
//! - **Six archive tiers with dated pricing:** plans `HotLocalSource`, `HotRemoteEvent`,
//!   `StandardHistorical`, `InfrequentAccess`, `MetadataAfterExpiry`, and `EvidenceHold` using
//!   dated storage, PUT/HEAD/GET/list, retrieval, egress, minimum-duration, object-lock, region,
//!   and durability quotes (never hardcoded cloud price constants).
//! - **Backend-neutral portability:** provider metadata/receipts are child placement records;
//!   migrating across backends publishes new placement/custody children without rewriting
//!   `semantic_event_digest` or `content_root_digest`.
//! - **Unavailable codec honesty:** unavailable codecs remain indexed and retained with an
//!   explicit decode limit rather than silent dropping or fabricated decode success.

use core::fmt;
use std::collections::BTreeSet;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, Generation, TimestampNs,
};

use crate::derivative_receipt::MediaDerivativeReceipt;

/// Registered digest domain for canonical media delivery decision cards
/// (`SCHEMA-DOMAIN-TENSOR-MEDIA-DELIVERY-CARD-001`).
pub const MEDIA_DELIVERY_DECISION_CARD_DOMAIN: &str = "fss.tensor.media_delivery_decision_card.v1";

/// Canonical binary format version for [`MediaDeliveryDecisionCard`].
pub const MEDIA_DELIVERY_CARD_FORMAT_VERSION: u32 = 1;

/// Maximum candidate options admitted in one decision card.
pub const MAX_DELIVERY_CANDIDATES: usize = 32;

/// Maximum backend placement child records carried on one decision card.
pub const MAX_PLACEMENT_RECORDS: usize = 16;

/// Maximum UTF-8 bytes in labels, provider IDs, dates, or rejection reasons.
pub const MAX_DELIVERY_LABEL_BYTES: usize = 128;

/// Physical media movement transformation mode (`DOC-052`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MediaMovementMode {
    /// Zero-reencode byte passthrough of source-coded stream.
    Passthrough,
    /// Lossless container repackaging preserving source-coded NAL/bitstream bytes.
    Remux,
    /// Decode + re-encode transformation (requires explicit justification & derivative receipt).
    Transcode,
}

impl MediaMovementMode {
    /// Stable canonical machine label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passthrough => "passthrough",
            Self::Remux => "remux",
            Self::Transcode => "transcode",
        }
    }
}

impl CanonicalEncode for MediaMovementMode {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::Passthrough => 1,
            Self::Remux => 2,
            Self::Transcode => 3,
        });
    }
}

impl CanonicalDecode for MediaMovementMode {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Passthrough),
            2 => Ok(Self::Remux),
            3 => Ok(Self::Transcode),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Authorized live media delivery surface taxonomy (`DOC-052`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LiveDeliverySurface {
    /// Owner-authorized interactive WebRTC session over privacy-masked proxy.
    AuthorizedWebRtc,
    /// Low-Latency HLS / CMAF fragmented MP4 delivery.
    LlHlsCmafFmp4,
    /// Zero-network same-host bounded frame transport.
    SameHostFrameTransport,
    /// Explicitly justified local RTP/RTSP relay.
    JustifiedRtpRtspRelay,
}

impl LiveDeliverySurface {
    /// Stable canonical machine label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizedWebRtc => "authorized_webrtc",
            Self::LlHlsCmafFmp4 => "ll_hls_cmaf_fmp4",
            Self::SameHostFrameTransport => "same_host_frame_transport",
            Self::JustifiedRtpRtspRelay => "justified_rtp_rtsp_relay",
        }
    }
}

impl CanonicalEncode for LiveDeliverySurface {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::AuthorizedWebRtc => 1,
            Self::LlHlsCmafFmp4 => 2,
            Self::SameHostFrameTransport => 3,
            Self::JustifiedRtpRtspRelay => 4,
        });
    }
}

impl CanonicalDecode for LiveDeliverySurface {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::AuthorizedWebRtc),
            2 => Ok(Self::LlHlsCmafFmp4),
            3 => Ok(Self::SameHostFrameTransport),
            4 => Ok(Self::JustifiedRtpRtspRelay),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Explicit justification required before any transcode option may pass hard clamps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranscodeJustification {
    /// No transcode justification (only valid for `Passthrough` / `Remux`).
    None,
    /// Target authorized client cannot decode the source codec natively.
    ClientCodecIncompatibility,
    /// Hard link bandwidth cap requires lower bitrate rendition.
    BandwidthCap,
    /// Mandatory privacy redaction/masking requires pixel-level re-encoding.
    PrivacyRedaction,
    /// Bounded model-analysis derivative input requires specific pixel/codec format.
    ModelAnalysisInput,
}

/// Codec decode support classification preserving source retention for unavailable codecs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecSupportStatus {
    /// Supported natively in first-party pure Rust.
    NativePureRust,
    /// Codec decode unavailable; source stays indexed and retained with explicit decode limit.
    UnavailableIndexedRetainedOnly,
}

/// Six archive placement tiers specified by `DOC-052`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ArchiveStorageTier {
    /// Hot local source custody spool.
    HotLocalSource,
    /// Hot remote event mirror for rapid incident retrieval.
    HotRemoteEvent,
    /// Standard historical durable object archive.
    StandardHistorical,
    /// Infrequent-access cold durable tier with minimum duration and retrieval fee.
    InfrequentAccess,
    /// Retained metadata and manifests after raw media expiry.
    MetadataAfterExpiry,
    /// Legal/evidence hold placement with object lock protection.
    EvidenceHold,
}

impl ArchiveStorageTier {
    /// Stable canonical machine label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HotLocalSource => "hot_local_source",
            Self::HotRemoteEvent => "hot_remote_event",
            Self::StandardHistorical => "standard_historical",
            Self::InfrequentAccess => "infrequent_access",
            Self::MetadataAfterExpiry => "metadata_after_expiry",
            Self::EvidenceHold => "evidence_hold",
        }
    }
}

impl CanonicalEncode for ArchiveStorageTier {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::HotLocalSource => 1,
            Self::HotRemoteEvent => 2,
            Self::StandardHistorical => 3,
            Self::InfrequentAccess => 4,
            Self::MetadataAfterExpiry => 5,
            Self::EvidenceHold => 6,
        });
    }
}

impl CanonicalDecode for ArchiveStorageTier {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::HotLocalSource),
            2 => Ok(Self::HotRemoteEvent),
            3 => Ok(Self::StandardHistorical),
            4 => Ok(Self::InfrequentAccess),
            5 => Ok(Self::MetadataAfterExpiry),
            6 => Ok(Self::EvidenceHold),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Security and bandwidth posture of a live delivery gateway candidate (`DOC-052`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveGatewaySpec {
    /// MUST be `false`: live gateway holds zero camera/vendor credentials!
    pub has_vendor_credentials: bool,
    /// Whether live stream is served as a capability-projected privacy-masked proxy.
    pub privacy_masked_proxy: bool,
    /// Digest of explicit capability authorization grant.
    pub auth_grant_digest: ContentDigest,
    /// Hard maximum outbound bandwidth in kbps (`> 0`).
    pub max_bandwidth_kbps: u32,
    /// Hard authorization expiration timestamp (`> evaluated_at_ns`).
    pub auth_expires_at_ns: TimestampNs,
}

/// Dated, provider-specific archive pricing quote (never hardcoded cloud price constants!).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TierPricingQuote {
    /// Target archive tier priced by this quote.
    pub tier: ArchiveStorageTier,
    /// ISO-8601 quote date (e.g. `2026-11-27`).
    pub pricing_date: String,
    /// Digest of the authoritative dated pricing manifest.
    pub pricing_manifest_digest: ContentDigest,
    /// Storage rate in micro-dollars per GiB-month.
    pub storage_micros_per_gib_month: u64,
    /// Class-A PUT cost in micro-dollars per 1,000 requests.
    pub put_micros_per_k: u64,
    /// HEAD cost in micro-dollars per 1,000 requests.
    pub head_micros_per_k: u64,
    /// Class-B GET cost in micro-dollars per 1,000 requests.
    pub get_micros_per_k: u64,
    /// LIST cost in micro-dollars per 1,000 requests.
    pub list_micros_per_k: u64,
    /// Retrieval fee in micro-dollars per GiB.
    pub retrieval_micros_per_gib: u64,
    /// Egress fee in micro-dollars per GiB.
    pub egress_micros_per_gib: u64,
    /// Minimum billable storage duration in days.
    pub min_duration_days: u32,
    /// Whether WORM / Object Lock is supported by this tier/backend.
    pub object_lock_supported: bool,
    /// Region identifier (e.g. `us-east-1`, `local-site-a`).
    pub region_code: String,
    /// Declared durability nines (e.g. `11` for 99.999999999%).
    pub durability_nines: u8,
}

impl TierPricingQuote {
    /// Estimates total monthly micro-dollar cost for `chunk_count` objects totaling `total_gib`
    /// plus `estimated_gets` reads and `egress_gib` egress, pricing PUT/HEAD/GET/LIST explicitly.
    #[must_use]
    pub fn estimate_total_cost_micros(
        &self,
        total_gib: u64,
        chunk_count: u64,
        estimated_gets: u64,
        egress_gib: u64,
    ) -> u64 {
        let storage = self.storage_micros_per_gib_month.saturating_mul(total_gib);
        let k_chunks = chunk_count.div_ceil(1_000);
        let k_gets = estimated_gets.div_ceil(1_000);
        let ops = self
            .put_micros_per_k
            .saturating_mul(k_chunks)
            .saturating_add(self.head_micros_per_k.saturating_mul(k_chunks))
            .saturating_add(self.list_micros_per_k)
            .saturating_add(self.get_micros_per_k.saturating_mul(k_gets));
        let movement = self
            .retrieval_micros_per_gib
            .saturating_mul(egress_gib)
            .saturating_add(self.egress_micros_per_gib.saturating_mul(egress_gib));
        storage.saturating_add(ops).saturating_add(movement)
    }
}

/// Child placement/custody record binding a backend provider without rewriting semantic identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendPlacementChild {
    /// Backend/provider identifier (e.g. `local-spool`, `s3-us-east-1`, `b2-eu-central`).
    pub provider_id: String,
    /// Placement tier at this provider.
    pub tier: ArchiveStorageTier,
    /// Region code.
    pub region_code: String,
    /// Digest of the provider-specific custody/location receipt child.
    pub placement_receipt_digest: ContentDigest,
    /// Optional previous provider when this record represents a backend-neutral migration.
    pub migrated_from_provider: Option<String>,
}

impl CanonicalEncode for BackendPlacementChild {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.provider_id);
        self.tier.encode_canonical(encoder);
        encoder.text(&self.region_code);
        encoder.digest(self.placement_receipt_digest);
        match &self.migrated_from_provider {
            Some(prev) => {
                encoder.u8(1);
                encoder.text(prev);
            }
            None => encoder.u8(0),
        }
    }
}

impl CanonicalDecode for BackendPlacementChild {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let provider_id = decoder.text()?.to_owned();
        let tier = ArchiveStorageTier::decode_canonical(decoder)?;
        let region_code = decoder.text()?.to_owned();
        let placement_receipt_digest = decoder.digest()?;
        let migrated_from_provider = match decoder.u8()? {
            0 => None,
            1 => {
                let prev = decoder.text()?.to_owned();
                if !is_clean_label(&prev) {
                    return Err(ContractError::InvalidIdentifier);
                }
                Some(prev)
            }
            _ => return Err(ContractError::InvalidIdentifier),
        };
        if !is_clean_label(&provider_id) || !is_clean_label(&region_code) {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self {
            provider_id,
            tier,
            region_code,
            placement_receipt_digest,
            migrated_from_provider,
        })
    }
}

/// Hard policy constraints governing one media delivery/tier evaluation pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaDeliveryConstraints {
    /// Clean decision card identifier.
    pub card_id: String,
    /// Pinned policy generation (`!= 0`).
    pub generation: Generation,
    /// Evaluation timestamp.
    pub evaluated_at_ns: TimestampNs,
    /// Immutable semantic event digest (NEVER rewritten across backend migrations!).
    pub semantic_event_digest: ContentDigest,
    /// Immutable source content root digest (NEVER rewritten across backend migrations!).
    pub content_root_digest: ContentDigest,
    /// Maximum acceptable end-to-end delivery latency in ms.
    pub max_latency_ms: u32,
    /// Maximum acceptable outbound bandwidth in kbps.
    pub max_bandwidth_kbps: u32,
    /// Maximum acceptable compute energy budget in millijoules.
    pub max_energy_mj: u64,
    /// Whether privacy masking is mandatory for outbound delivery.
    pub require_privacy_mask: bool,
    /// Whether legal/evidence object-lock protection is required on the target archive tier.
    pub require_object_lock: bool,
}

/// One candidate media movement + live surface + archive tier option to evaluate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaDeliveryCandidate {
    /// Unique stable option identifier.
    pub candidate_id: String,
    /// Movement mode (`Passthrough`, `Remux`, `Transcode`).
    pub mode: MediaMovementMode,
    /// Transcode justification (`None` for passthrough/remux).
    pub transcode_justification: TranscodeJustification,
    /// Codec decode support posture.
    pub codec_support: CodecSupportStatus,
    /// Live delivery surface.
    pub live_surface: LiveDeliverySurface,
    /// Live gateway posture & bounds.
    pub live_gateway: LiveGatewaySpec,
    /// Target archive tier pricing quote.
    pub tier_quote: TierPricingQuote,
    /// Backend placement child descriptor.
    pub placement: BackendPlacementChild,
    /// Estimated total cost in micro-dollars (storage + PUT/HEAD/GET/LIST + retrieval + egress).
    pub total_cost_micros: u64,
    /// Expected end-to-end latency in ms.
    pub latency_ms: u32,
    /// Expected bandwidth consumption in kbps.
    pub bandwidth_kbps: u32,
    /// Estimated CPU/GPU energy cost in millijoules.
    pub energy_millijoules: u64,
    /// Fidelity loss in basis points (`0` for passthrough/remux, `> 0` for lossy transcode).
    pub fidelity_loss_bps: u16,
    /// Sealed `MediaDerivativeReceipt` proving transform lineage (`DOC-041`).
    pub derivative_receipt: MediaDerivativeReceipt,
    /// MUST be `false`: source custody is never overwritten!
    pub overwrites_source: bool,
    /// MUST be `false`: decision cards never grant effect authority!
    pub grants_effect_authority: bool,
}

/// Hard-clamped candidate rejection recorded transparently on the decision card.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClampedDeliveryRejection {
    /// Candidate identifier.
    pub candidate_id: String,
    /// Machine-readable clamp violation reason.
    pub reason: String,
    /// Whether the underlying source remains indexed and retained despite decode/delivery clamp.
    pub source_indexed_and_retained: bool,
}

impl CanonicalEncode for ClampedDeliveryRejection {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.candidate_id);
        encoder.text(&self.reason);
        encoder.u8(u8::from(self.source_indexed_and_retained));
    }
}

impl CanonicalDecode for ClampedDeliveryRejection {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let candidate_id = decoder.text()?.to_owned();
        let reason = decoder.text()?.to_owned();
        let source_indexed_and_retained = match decoder.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ContractError::InvalidIdentifier),
        };
        if !is_clean_label(&candidate_id) || !is_clean_label(&reason) {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self {
            candidate_id,
            reason,
            source_indexed_and_retained,
        })
    }
}

/// One admitted option recorded in either the Pareto-nondominated frontier or dominated set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatedDeliveryOption {
    /// Candidate identifier.
    pub candidate_id: String,
    /// Movement mode.
    pub mode: MediaMovementMode,
    /// Live surface.
    pub live_surface: LiveDeliverySurface,
    /// Target archive tier.
    pub tier: ArchiveStorageTier,
    /// Dated pricing manifest digest.
    pub pricing_manifest_digest: ContentDigest,
    /// Sealed `MediaDerivativeReceipt` digest (`DOC-041`).
    pub derivative_receipt_digest: ContentDigest,
    /// Total estimated cost in micro-dollars.
    pub total_cost_micros: u64,
    /// Latency in ms.
    pub latency_ms: u32,
    /// Energy cost in millijoules.
    pub energy_millijoules: u64,
    /// Fidelity loss in basis points.
    pub fidelity_loss_bps: u16,
    /// When dominated (either Pareto or remux-before-transcode), names the dominating option ID.
    pub dominated_by: Option<String>,
}

impl CanonicalEncode for EvaluatedDeliveryOption {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.candidate_id);
        self.mode.encode_canonical(encoder);
        self.live_surface.encode_canonical(encoder);
        self.tier.encode_canonical(encoder);
        encoder.digest(self.pricing_manifest_digest);
        encoder.digest(self.derivative_receipt_digest);
        encoder.u64(self.total_cost_micros);
        encoder.u32(self.latency_ms);
        encoder.u64(self.energy_millijoules);
        encoder.u32(u32::from(self.fidelity_loss_bps));
        match &self.dominated_by {
            Some(dom) => {
                encoder.u8(1);
                encoder.text(dom);
            }
            None => encoder.u8(0),
        }
    }
}

impl CanonicalDecode for EvaluatedDeliveryOption {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let candidate_id = decoder.text()?.to_owned();
        let mode = MediaMovementMode::decode_canonical(decoder)?;
        let live_surface = LiveDeliverySurface::decode_canonical(decoder)?;
        let tier = ArchiveStorageTier::decode_canonical(decoder)?;
        let pricing_manifest_digest = decoder.digest()?;
        let derivative_receipt_digest = decoder.digest()?;
        let total_cost_micros = decoder.u64()?;
        let latency_ms = decoder.u32()?;
        let energy_millijoules = decoder.u64()?;
        let fidelity_loss_bps =
            u16::try_from(decoder.u32()?).map_err(|_| ContractError::InvalidIdentifier)?;
        let dominated_by = match decoder.u8()? {
            0 => None,
            1 => {
                let dom = decoder.text()?.to_owned();
                if !is_clean_label(&dom) || dom == candidate_id {
                    return Err(ContractError::InvalidIdentifier);
                }
                Some(dom)
            }
            _ => return Err(ContractError::InvalidIdentifier),
        };
        if !is_clean_label(&candidate_id) || fidelity_loss_bps > 10_000 {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self {
            candidate_id,
            mode,
            live_surface,
            tier,
            pricing_manifest_digest,
            derivative_receipt_digest,
            total_cost_micros,
            latency_ms,
            energy_millijoules,
            fidelity_loss_bps,
            dominated_by,
        })
    }
}

/// Typed fail-closed error for media delivery decision card evaluation and migration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MediaDeliveryCardError {
    /// Invalid card labels, zero generation, empty/oversized candidate list, or duplicate IDs.
    InvalidRequest(&'static str),
    /// Attached `MediaDerivativeReceipt` failed digest verification or claimed source custody.
    InvalidDerivativeReceipt(&'static str),
    /// Attempted backend migration tried to rewrite immutable semantic event or content identity.
    SemanticIdentityRewriteForbidden,
    /// Cooperative cancellation observed before completing evaluation.
    Cancelled,
}

impl fmt::Display for MediaDeliveryCardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(why) => write!(f, "invalid media delivery card request: {why}"),
            Self::InvalidDerivativeReceipt(why) => {
                write!(f, "invalid media derivative receipt: {why}")
            }
            Self::SemanticIdentityRewriteForbidden => {
                write!(
                    f,
                    "backend migration cannot rewrite semantic event/content identity"
                )
            }
            Self::Cancelled => write!(f, "media delivery decision card evaluation cancelled"),
        }
    }
}

impl std::error::Error for MediaDeliveryCardError {}

/// Canonical, tamper-evident Decision Card covering remux/transcode, live surface, archive tier,
/// and backend-neutral portability (`DOC-052`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaDeliveryDecisionCard {
    /// Format version (`MEDIA_DELIVERY_CARD_FORMAT_VERSION`).
    pub format_version: u32,
    /// Clean decision card identifier.
    pub card_id: String,
    /// Pinned policy generation (`!= 0`).
    pub generation: Generation,
    /// Evaluation timestamp.
    pub evaluated_at_ns: TimestampNs,
    /// Immutable semantic event identity (preserved across backend migrations).
    pub semantic_event_digest: ContentDigest,
    /// Immutable source content root digest (preserved across backend migrations).
    pub content_root_digest: ContentDigest,
    /// Pareto-nondominated surviving options (ordered deterministically by `candidate_id`).
    pub nondominated_frontier: Vec<EvaluatedDeliveryOption>,
    /// Admitted but dominated options with explicit dominating-option proofs.
    pub dominated_options: Vec<EvaluatedDeliveryOption>,
    /// Hard-clamped rejected options with explicit reasons.
    pub clamped_rejections: Vec<ClampedDeliveryRejection>,
    /// Backend-neutral child placement/custody records (provider metadata as children).
    pub placement_children: Vec<BackendPlacementChild>,
    /// Always `true`: backend placement/migration preserves immutable semantic identity.
    pub semantic_identity_preserved: bool,
    /// Always `false`: source custody is never overwritten.
    pub overwrites_source: bool,
    /// Always `false`: decision cards are derived cognition and never grant effect authority.
    pub grants_effect_authority: bool,
    /// Domain-separated SHA-256 commitment over all fields above.
    pub card_digest: ContentDigest,
}

impl MediaDeliveryDecisionCard {
    /// Recomputes the exact domain-separated SHA-256 digest over all canonical fields.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text(MEDIA_DELIVERY_DECISION_CARD_DOMAIN);
        enc.u32(self.format_version);
        enc.text(&self.card_id);
        enc.u64(self.generation.0);
        enc.i128(self.evaluated_at_ns.0);
        enc.digest(self.semantic_event_digest);
        enc.digest(self.content_root_digest);
        enc.u64(self.nondominated_frontier.len() as u64);
        for opt in &self.nondominated_frontier {
            opt.encode_canonical(&mut enc);
        }
        enc.u64(self.dominated_options.len() as u64);
        for opt in &self.dominated_options {
            opt.encode_canonical(&mut enc);
        }
        enc.u64(self.clamped_rejections.len() as u64);
        for rej in &self.clamped_rejections {
            rej.encode_canonical(&mut enc);
        }
        enc.u64(self.placement_children.len() as u64);
        for child in &self.placement_children {
            child.encode_canonical(&mut enc);
        }
        enc.u8(u8::from(self.semantic_identity_preserved));
        enc.u8(u8::from(self.overwrites_source));
        enc.u8(u8::from(self.grants_effect_authority));
        ContentDigest::sha256(&enc.finish())
    }

    /// Returns `true` iff `card_digest` matches [`Self::computed_digest`].
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.card_digest == self.computed_digest()
    }

    /// Publishes a backend-neutral migration by appending a new placement/custody child record
    /// WITHOUT rewriting `semantic_event_digest` or `content_root_digest` (`DOC-052`).
    pub fn append_backend_migration_child(
        &self,
        new_placement: BackendPlacementChild,
        expected_semantic_event_digest: ContentDigest,
        expected_content_root_digest: ContentDigest,
        migrated_at_ns: TimestampNs,
    ) -> Result<Self, MediaDeliveryCardError> {
        if expected_semantic_event_digest != self.semantic_event_digest
            || expected_content_root_digest != self.content_root_digest
        {
            return Err(MediaDeliveryCardError::SemanticIdentityRewriteForbidden);
        }
        if !is_clean_label(&new_placement.provider_id)
            || !is_clean_label(&new_placement.region_code)
            || new_placement
                .migrated_from_provider
                .as_deref()
                .is_none_or(|p| !is_clean_label(p) || p == new_placement.provider_id)
        {
            return Err(MediaDeliveryCardError::InvalidRequest(
                "invalid_migration_placement_child",
            ));
        }
        if self.placement_children.len() >= MAX_PLACEMENT_RECORDS {
            return Err(MediaDeliveryCardError::InvalidRequest(
                "placement_children_limit_exceeded",
            ));
        }
        let mut migrated = self.clone();
        migrated.evaluated_at_ns = migrated_at_ns;
        migrated.placement_children.push(new_placement);
        migrated.card_digest = migrated.computed_digest();
        Ok(migrated)
    }
}

impl CanonicalEncode for MediaDeliveryDecisionCard {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.format_version);
        encoder.text(&self.card_id);
        encoder.u64(self.generation.0);
        encoder.i128(self.evaluated_at_ns.0);
        encoder.digest(self.semantic_event_digest);
        encoder.digest(self.content_root_digest);
        encoder.u64(self.nondominated_frontier.len() as u64);
        for opt in &self.nondominated_frontier {
            opt.encode_canonical(encoder);
        }
        encoder.u64(self.dominated_options.len() as u64);
        for opt in &self.dominated_options {
            opt.encode_canonical(encoder);
        }
        encoder.u64(self.clamped_rejections.len() as u64);
        for rej in &self.clamped_rejections {
            rej.encode_canonical(encoder);
        }
        encoder.u64(self.placement_children.len() as u64);
        for child in &self.placement_children {
            child.encode_canonical(encoder);
        }
        encoder.u8(u8::from(self.semantic_identity_preserved));
        encoder.u8(u8::from(self.overwrites_source));
        encoder.u8(u8::from(self.grants_effect_authority));
        encoder.digest(self.card_digest);
    }
}

impl CanonicalDecode for MediaDeliveryDecisionCard {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let format_version = decoder.u32()?;
        if format_version != MEDIA_DELIVERY_CARD_FORMAT_VERSION {
            return Err(ContractError::InvalidIdentifier);
        }
        let card_id = decoder.text()?.to_owned();
        let generation = Generation(decoder.u64()?);
        let evaluated_at_ns = TimestampNs(decoder.i128()?);
        let semantic_event_digest = decoder.digest()?;
        let content_root_digest = decoder.digest()?;

        let f_len =
            usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidIdentifier)?;
        if f_len > MAX_DELIVERY_CANDIDATES || f_len > decoder.remaining() / 80 {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut nondominated_frontier = Vec::with_capacity(f_len);
        for _ in 0..f_len {
            let opt = EvaluatedDeliveryOption::decode_canonical(decoder)?;
            if opt.dominated_by.is_some() {
                return Err(ContractError::InvalidIdentifier);
            }
            nondominated_frontier.push(opt);
        }

        let d_len =
            usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidIdentifier)?;
        if d_len > MAX_DELIVERY_CANDIDATES || d_len > decoder.remaining() / 80 {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut dominated_options = Vec::with_capacity(d_len);
        for _ in 0..d_len {
            let opt = EvaluatedDeliveryOption::decode_canonical(decoder)?;
            if opt.dominated_by.is_none() {
                return Err(ContractError::InvalidIdentifier);
            }
            dominated_options.push(opt);
        }

        let r_len =
            usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidIdentifier)?;
        if r_len > MAX_DELIVERY_CANDIDATES || r_len > decoder.remaining() / 4 {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut clamped_rejections = Vec::with_capacity(r_len);
        for _ in 0..r_len {
            clamped_rejections.push(ClampedDeliveryRejection::decode_canonical(decoder)?);
        }

        let p_len =
            usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidIdentifier)?;
        if p_len > MAX_PLACEMENT_RECORDS || p_len > decoder.remaining() / 36 {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut placement_children = Vec::with_capacity(p_len);
        for _ in 0..p_len {
            placement_children.push(BackendPlacementChild::decode_canonical(decoder)?);
        }

        let semantic_identity_preserved = decode_bool(decoder)?;
        let overwrites_source = decode_bool(decoder)?;
        let grants_effect_authority = decode_bool(decoder)?;
        let card_digest = decoder.digest()?;

        let total_candidates = f_len + d_len + r_len;
        if !is_clean_label(&card_id)
            || generation.0 == 0
            || !(1..=MAX_DELIVERY_CANDIDATES).contains(&total_candidates)
            || !semantic_identity_preserved
            || overwrites_source
            || grants_effect_authority
        {
            return Err(ContractError::InvalidIdentifier);
        }

        let card = Self {
            format_version,
            card_id,
            generation,
            evaluated_at_ns,
            semantic_event_digest,
            content_root_digest,
            nondominated_frontier,
            dominated_options,
            clamped_rejections,
            placement_children,
            semantic_identity_preserved,
            overwrites_source,
            grants_effect_authority,
            card_digest,
        };
        if !card.verify_digest() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(card)
    }
}

fn decode_bool(decoder: &mut CanonicalDecoder<'_>) -> Result<bool, ContractError> {
    match decoder.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ContractError::InvalidIdentifier),
    }
}

fn is_clean_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_DELIVERY_LABEL_BYTES
        && !s
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
}

fn pareto_dominates(a: &EvaluatedDeliveryOption, b: &EvaluatedDeliveryOption) -> bool {
    let le = a.total_cost_micros <= b.total_cost_micros
        && a.latency_ms <= b.latency_ms
        && a.energy_millijoules <= b.energy_millijoules
        && a.fidelity_loss_bps <= b.fidelity_loss_bps;
    let lt = a.total_cost_micros < b.total_cost_micros
        || a.latency_ms < b.latency_ms
        || a.energy_millijoules < b.energy_millijoules
        || a.fidelity_loss_bps < b.fidelity_loss_bps;
    le && lt
}

/// Deterministically evaluates candidate media movement, live delivery, and archive tier options
/// against hard safety/privacy/custody/cost clamps and remux-before-transcode dominance (`DOC-052`).
pub fn evaluate_media_delivery_card(
    constraints: &MediaDeliveryConstraints,
    candidates: &[MediaDeliveryCandidate],
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<MediaDeliveryDecisionCard, MediaDeliveryCardError> {
    if !is_clean_label(&constraints.card_id)
        || constraints.generation.0 == 0
        || !(1..=MAX_DELIVERY_CANDIDATES).contains(&candidates.len())
    {
        return Err(MediaDeliveryCardError::InvalidRequest(
            "invalid_constraints_or_candidate_count",
        ));
    }
    if is_cancelled() {
        return Err(MediaDeliveryCardError::Cancelled);
    }

    let mut seen_ids = BTreeSet::new();
    let mut admitted: Vec<(
        EvaluatedDeliveryOption,
        TranscodeJustification,
        BackendPlacementChild,
    )> = Vec::new();
    let mut clamped_rejections = Vec::new();

    for cand in candidates {
        if is_cancelled() {
            return Err(MediaDeliveryCardError::Cancelled);
        }
        if !is_clean_label(&cand.candidate_id)
            || !seen_ids.insert(cand.candidate_id.clone())
            || !is_clean_label(&cand.tier_quote.pricing_date)
            || !is_clean_label(&cand.tier_quote.region_code)
            || !is_clean_label(&cand.placement.provider_id)
            || !is_clean_label(&cand.placement.region_code)
            || cand.fidelity_loss_bps > 10_000
        {
            return Err(MediaDeliveryCardError::InvalidRequest(
                "invalid_or_duplicate_candidate_metadata",
            ));
        }

        // Verify bound DOC-041 MediaDerivativeReceipt integrity & non-source custody!
        if !cand.derivative_receipt.verify_digest() || cand.derivative_receipt.is_source_custody {
            return Err(MediaDeliveryCardError::InvalidDerivativeReceipt(
                "corrupt_or_source_claiming_derivative_receipt",
            ));
        }

        // Hard safety/privacy/security/custody clamps BEFORE frontier evaluation.
        let clamp_reason: Option<(&str, bool)> = if cand.overwrites_source {
            Some(("source_overwrite_forbidden", true))
        } else if cand.grants_effect_authority {
            Some(("effect_authority_forbidden", true))
        } else if cand.live_gateway.has_vendor_credentials {
            Some(("live_gateway_vendor_credentials_forbidden", true))
        } else if constraints.require_privacy_mask && !cand.live_gateway.privacy_masked_proxy {
            Some(("unmasked_live_proxy_forbidden", true))
        } else if cand.live_gateway.max_bandwidth_kbps == 0
            || cand.live_gateway.auth_expires_at_ns.0 <= constraints.evaluated_at_ns.0
        {
            Some(("invalid_or_expired_live_gateway_bounds", true))
        } else if cand.codec_support == CodecSupportStatus::UnavailableIndexedRetainedOnly
            && cand.mode == MediaMovementMode::Transcode
        {
            // Unavailable codecs remain indexed & retained; decode/transcode refuses honestly!
            Some(("codec_decode_unavailable_source_indexed_retained", true))
        } else if cand.mode == MediaMovementMode::Transcode
            && cand.transcode_justification == TranscodeJustification::None
        {
            Some(("unjustified_transcode_remux_preferred", true))
        } else if constraints.require_object_lock && !cand.tier_quote.object_lock_supported {
            Some(("tier_missing_required_object_lock", true))
        } else if cand.latency_ms > constraints.max_latency_ms {
            Some(("latency_budget_exceeded", true))
        } else if cand.bandwidth_kbps > constraints.max_bandwidth_kbps
            || cand.bandwidth_kbps > cand.live_gateway.max_bandwidth_kbps
        {
            Some(("bandwidth_budget_exceeded", true))
        } else if cand.energy_millijoules > constraints.max_energy_mj {
            Some(("energy_budget_exceeded", true))
        } else {
            None
        };

        if let Some((reason, retained)) = clamp_reason {
            clamped_rejections.push(ClampedDeliveryRejection {
                candidate_id: cand.candidate_id.clone(),
                reason: reason.to_owned(),
                source_indexed_and_retained: retained,
            });
            continue;
        }

        admitted.push((
            EvaluatedDeliveryOption {
                candidate_id: cand.candidate_id.clone(),
                mode: cand.mode,
                live_surface: cand.live_surface,
                tier: cand.tier_quote.tier,
                pricing_manifest_digest: cand.tier_quote.pricing_manifest_digest,
                derivative_receipt_digest: cand.derivative_receipt.receipt_digest,
                total_cost_micros: cand.total_cost_micros,
                latency_ms: cand.latency_ms,
                energy_millijoules: cand.energy_millijoules,
                fidelity_loss_bps: cand.fidelity_loss_bps,
                dominated_by: None,
            },
            cand.transcode_justification,
            cand.placement.clone(),
        ));
    }

    admitted.sort_by(|a, b| a.0.candidate_id.cmp(&b.0.candidate_id));
    clamped_rejections.sort_by(|a, b| a.candidate_id.cmp(&b.candidate_id));

    // Identify lowest-cost Passthrough/Remux option for explicit remux-before-transcode dominance.
    let best_remux_id = admitted
        .iter()
        .filter(|(o, _, _)| {
            matches!(
                o.mode,
                MediaMovementMode::Passthrough | MediaMovementMode::Remux
            )
        })
        .min_by_key(|(o, _, _)| (o.total_cost_micros, o.latency_ms, o.candidate_id.clone()))
        .map(|(o, _, _)| o.candidate_id.clone());

    let mut nondominated_frontier = Vec::new();
    let mut dominated_options = Vec::new();
    let mut placement_children = Vec::new();
    let mut seen_placement_digests = BTreeSet::new();

    for (idx, (opt, just, placement)) in admitted.iter().enumerate() {
        // Explicit remux-before-transcode policy dominance when a compatible remux/passthrough
        // already satisfies all constraints and transcode is not demanded for privacy/analysis.
        let mut dominator: Option<String> = None;
        if opt.mode == MediaMovementMode::Transcode
            && !matches!(
                just,
                TranscodeJustification::PrivacyRedaction
                    | TranscodeJustification::ModelAnalysisInput
            )
            && let Some(ref remux_id) = best_remux_id
        {
            dominator = Some(remux_id.clone());
        }

        if dominator.is_none() {
            for (other_idx, (other, _, _)) in admitted.iter().enumerate() {
                if idx != other_idx && pareto_dominates(other, opt) {
                    dominator = Some(other.candidate_id.clone());
                    break;
                }
            }
        }

        if let Some(dom_id) = dominator {
            let mut dom_opt = opt.clone();
            dom_opt.dominated_by = Some(dom_id);
            dominated_options.push(dom_opt);
        } else {
            nondominated_frontier.push(opt.clone());
            if placement_children.len() < MAX_PLACEMENT_RECORDS
                && seen_placement_digests.insert(placement.placement_receipt_digest)
            {
                placement_children.push(placement.clone());
            }
        }
    }

    let mut card = MediaDeliveryDecisionCard {
        format_version: MEDIA_DELIVERY_CARD_FORMAT_VERSION,
        card_id: constraints.card_id.clone(),
        generation: constraints.generation,
        evaluated_at_ns: constraints.evaluated_at_ns,
        semantic_event_digest: constraints.semantic_event_digest,
        content_root_digest: constraints.content_root_digest,
        nondominated_frontier,
        dominated_options,
        clamped_rejections,
        placement_children,
        semantic_identity_preserved: true,
        overwrites_source: false,
        grants_effect_authority: false,
        card_digest: ContentDigest::sha256(b"pending"),
    };
    card.card_digest = card.computed_digest();
    Ok(card)
}
