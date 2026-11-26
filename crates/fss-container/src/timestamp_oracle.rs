#![forbid(unsafe_code)]
//! Deterministic decode and timestamp differential oracle (`FSS-060`, bead `fss-x4a.12.9`).
//!
//! Independently converts container track ticks into exact rational nanoseconds using checked
//! `i128` arithmetic, verifies monotonic decode order (DTS), validates B-frame reorder display
//! order (PTS), confirms explicit gap witnesses are never silently concealed, compares decoded
//! pixel digests bit-for-bit against a scalar reference stream, and seals a canonical
//! [`TimestampOracleReceipt`] carrying exact divergence reproducer details on any mismatch.
//!
//! Core invariants:
//! - Exact rational tick-to-nanosecond conversion (`ticks * 1_000_000_000 / timescale`) with
//!   explicit configured rounding tolerance (`max_rounding_error_ns`).
//! - Zero tolerance for silent frame drops, gap concealment, DTS regressions, reordered display
//!   inversions, or 1-bit pixel digest mismatches.
//! - Zero `unsafe`, zero `.expect()`, zero ambient I/O, bounded sample ceilings, and cooperative
//!   cancellation checkpoints.

use core::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, Generation,
};

/// Registered digest domain for canonical decode/timestamp differential oracle receipts
/// (`SCHEMA-DOMAIN-CONTAINER-TIMESTAMP-ORACLE-001`).
pub const DECODE_TIMESTAMP_ORACLE_RECEIPT_DOMAIN: &str =
    "fss.container.decode_timestamp_oracle_receipt.v1";

/// Canonical binary format version for [`TimestampOracleReceipt`].
pub const TIMESTAMP_ORACLE_FORMAT_VERSION: u32 = 1;

/// Maximum frames compared in a single differential oracle run.
pub const MAX_ORACLE_FRAMES: usize = 65_536;

/// Hard policy bounding a single differential oracle evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimestampOraclePolicy {
    /// Clean non-empty fixture/stream identifier.
    pub fixture_id: String,
    /// Positive container timescale in ticks per second (e.g., 90_000 for RTP/MP4, 1_000 for MKV).
    pub timescale_hz: u32,
    /// Explicit maximum allowed absolute nanosecond rounding delta (`0..=1_000_000`).
    pub max_rounding_error_ns: u64,
    /// Pinned oracle/decoder generation (`!= 0`).
    pub generation: Generation,
}

impl TimestampOraclePolicy {
    /// Fails closed on zero timescale, excessive tolerance, invalid ID, or zero generation.
    pub fn validate(&self) -> Result<(), TimestampOracleError> {
        if self.fixture_id.is_empty()
            || self.fixture_id.len() > 256
            || self
                .fixture_id
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(TimestampOracleError::InvalidPolicy);
        }
        if self.timescale_hz == 0
            || self.max_rounding_error_ns > 1_000_000
            || self.generation.0 == 0
        {
            return Err(TimestampOracleError::InvalidPolicy);
        }
        Ok(())
    }
}

/// Exact rational conversion of container ticks to nanoseconds using checked `i128` arithmetic
/// (truncation toward zero matches standard integer container timeline semantics).
pub fn ticks_to_ns_exact(ticks: i64, timescale_hz: u32) -> Result<i128, TimestampOracleError> {
    if timescale_hz == 0 {
        return Err(TimestampOracleError::InvalidPolicy);
    }
    let num = i128::from(ticks)
        .checked_mul(1_000_000_000)
        .ok_or(TimestampOracleError::ArithmeticOverflow)?;
    Ok(num / i128::from(timescale_hz))
}

/// One reference ground-truth decoded frame entry derived from exact container ticks and scalar decode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceDecodedFrame {
    /// Zero-based decode-order index.
    pub decode_index: u64,
    /// Container decode timestamp in track ticks.
    pub dts_ticks: i64,
    /// Container presentation timestamp in track ticks.
    pub pts_ticks: i64,
    /// Positive sample duration in track ticks.
    pub duration_ticks: u32,
    /// Whether this frame follows an explicit upstream gap witness.
    pub follows_gap: bool,
    /// Exact SHA-256 digest of the scalar-decoded canonical pixel plane bytes.
    pub pixel_digest: ContentDigest,
}

/// One candidate pipeline decoded frame observation to compare against [`ReferenceDecodedFrame`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateDecodedFrame {
    /// Zero-based decode-order index reported by candidate.
    pub decode_index: u64,
    /// Candidate decode timestamp in nanoseconds.
    pub dts_ns: i128,
    /// Candidate presentation timestamp in nanoseconds.
    pub pts_ns: i128,
    /// Candidate sample duration in nanoseconds.
    pub duration_ns: u64,
    /// Whether the candidate preserved the explicit gap marker (must never conceal a gap).
    pub gap_witnessed: bool,
    /// SHA-256 digest of the candidate's decoded pixel plane bytes.
    pub pixel_digest: ContentDigest,
}

/// Non-collapsed differential oracle verdict.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OracleVerdict {
    /// All frame counts, DTS/PTS conversions, display order, gap witnesses, and pixels matched.
    ExactParity,
    /// Candidate frame count disagreed with reference stream.
    FrameCountMismatch,
    /// Candidate decode timestamp regressed or drifted outside tolerance.
    DtsDivergence,
    /// Candidate presentation timestamp drifted or broke display order.
    PtsDivergence,
    /// Candidate duration drifted outside tolerance.
    DurationDivergence,
    /// Candidate silently concealed or fabricated an upstream gap witness.
    GapWitnessMismatch,
    /// Candidate decoded pixel plane digest diverged from scalar reference.
    PixelDigestMismatch,
}

impl OracleVerdict {
    /// Stable machine-readable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExactParity => "exact_parity",
            Self::FrameCountMismatch => "frame_count_mismatch",
            Self::DtsDivergence => "dts_divergence",
            Self::PtsDivergence => "pts_divergence",
            Self::DurationDivergence => "duration_divergence",
            Self::GapWitnessMismatch => "gap_witness_mismatch",
            Self::PixelDigestMismatch => "pixel_digest_mismatch",
        }
    }
}

impl CanonicalEncode for OracleVerdict {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::ExactParity => 1,
            Self::FrameCountMismatch => 2,
            Self::DtsDivergence => 3,
            Self::PtsDivergence => 4,
            Self::DurationDivergence => 5,
            Self::GapWitnessMismatch => 6,
            Self::PixelDigestMismatch => 7,
        });
    }
}

impl CanonicalDecode for OracleVerdict {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::ExactParity),
            2 => Ok(Self::FrameCountMismatch),
            3 => Ok(Self::DtsDivergence),
            4 => Ok(Self::PtsDivergence),
            5 => Ok(Self::DurationDivergence),
            6 => Ok(Self::GapWitnessMismatch),
            7 => Ok(Self::PixelDigestMismatch),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Minimized first-divergence witness retained on any non-`ExactParity` verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DivergenceReproducer {
    /// Decode index where the first divergence occurred.
    pub decode_index: u64,
    /// Exact reference value description.
    pub expected: String,
    /// Exact candidate value description.
    pub observed: String,
}

impl CanonicalEncode for DivergenceReproducer {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.decode_index);
        encoder.text(&self.expected);
        encoder.text(&self.observed);
    }
}

impl CanonicalDecode for DivergenceReproducer {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            decode_index: decoder.u64()?,
            expected: decoder.text()?.to_owned(),
            observed: decoder.text()?.to_owned(),
        })
    }
}

/// Typed operational error when inputs fail preflight or evaluation is cancelled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimestampOracleError {
    /// Policy bounds or timescale are invalid.
    InvalidPolicy,
    /// Reference stream itself is empty, oversized, or non-monotonic in DTS / decode index.
    InvalidReferenceStream(&'static str),
    /// Checked tick-to-nanosecond arithmetic overflowed.
    ArithmeticOverflow,
    /// Cooperative cancellation observed before sealing the receipt.
    Cancelled,
}

impl fmt::Display for TimestampOracleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => write!(f, "invalid timestamp differential oracle policy"),
            Self::InvalidReferenceStream(why) => write!(f, "invalid reference stream: {why}"),
            Self::ArithmeticOverflow => write!(f, "timestamp oracle arithmetic overflow"),
            Self::Cancelled => write!(f, "timestamp differential oracle cancelled"),
        }
    }
}

impl std::error::Error for TimestampOracleError {}

/// Canonical, content-addressed differential proof receipt produced by [`evaluate_decode_timestamp_oracle`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimestampOracleReceipt {
    /// Format version (`TIMESTAMP_ORACLE_FORMAT_VERSION`).
    pub format_version: u32,
    /// Evaluated fixture or stream identifier.
    pub fixture_id: String,
    /// Pinned oracle generation.
    pub generation: Generation,
    /// Track timescale in Hz.
    pub timescale_hz: u32,
    /// Configured maximum allowed absolute nanosecond rounding delta.
    pub max_rounding_error_ns: u64,
    /// Number of reference frames evaluated.
    pub reference_frame_count: u64,
    /// Number of candidate frames evaluated.
    pub candidate_frame_count: u64,
    /// Maximum observed absolute DTS delta in nanoseconds across compared frames.
    pub max_observed_dts_delta_ns: u64,
    /// Maximum observed absolute PTS delta in nanoseconds across compared frames.
    pub max_observed_pts_delta_ns: u64,
    /// Number of explicit gap witnesses verified.
    pub verified_gap_witnesses: u64,
    /// Non-collapsed differential verdict.
    pub verdict: OracleVerdict,
    /// Exact minimized first-divergence reproducer (`None` iff `ExactParity`).
    pub first_divergence: Option<DivergenceReproducer>,
    /// Digest binding the complete ordered reference stream (ticks + pixel digests).
    pub reference_stream_digest: ContentDigest,
    /// Digest binding the complete ordered candidate stream (timestamps + pixel digests).
    pub candidate_stream_digest: ContentDigest,
    /// Domain-separated SHA-256 digest over all fields above.
    pub receipt_digest: ContentDigest,
}

impl TimestampOracleReceipt {
    /// Recomputes the exact domain-separated SHA-256 digest over all canonical fields.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(DECODE_TIMESTAMP_ORACLE_RECEIPT_DOMAIN);
        encoder.u32(self.format_version);
        encoder.text(&self.fixture_id);
        encoder.u64(self.generation.0);
        encoder.u32(self.timescale_hz);
        encoder.u64(self.max_rounding_error_ns);
        encoder.u64(self.reference_frame_count);
        encoder.u64(self.candidate_frame_count);
        encoder.u64(self.max_observed_dts_delta_ns);
        encoder.u64(self.max_observed_pts_delta_ns);
        encoder.u64(self.verified_gap_witnesses);
        self.verdict.encode_canonical(&mut encoder);
        match &self.first_divergence {
            Some(div) => {
                encoder.u8(1);
                div.encode_canonical(&mut encoder);
            }
            None => encoder.u8(0),
        }
        encoder.digest(self.reference_stream_digest);
        encoder.digest(self.candidate_stream_digest);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Returns `true` iff `receipt_digest` matches [`Self::computed_digest`].
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.receipt_digest == self.computed_digest()
    }
}

impl CanonicalEncode for TimestampOracleReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.format_version);
        encoder.text(&self.fixture_id);
        encoder.u64(self.generation.0);
        encoder.u32(self.timescale_hz);
        encoder.u64(self.max_rounding_error_ns);
        encoder.u64(self.reference_frame_count);
        encoder.u64(self.candidate_frame_count);
        encoder.u64(self.max_observed_dts_delta_ns);
        encoder.u64(self.max_observed_pts_delta_ns);
        encoder.u64(self.verified_gap_witnesses);
        self.verdict.encode_canonical(encoder);
        match &self.first_divergence {
            Some(div) => {
                encoder.u8(1);
                div.encode_canonical(encoder);
            }
            None => encoder.u8(0),
        }
        encoder.digest(self.reference_stream_digest);
        encoder.digest(self.candidate_stream_digest);
        encoder.digest(self.receipt_digest);
    }
}

impl CanonicalDecode for TimestampOracleReceipt {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let format_version = decoder.u32()?;
        if format_version != TIMESTAMP_ORACLE_FORMAT_VERSION {
            return Err(ContractError::InvalidIdentifier);
        }
        let fixture_id = decoder.text()?.to_owned();
        if fixture_id.is_empty()
            || fixture_id.len() > 256
            || fixture_id
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(ContractError::InvalidIdentifier);
        }
        let generation = Generation(decoder.u64()?);
        let timescale_hz = decoder.u32()?;
        let max_rounding_error_ns = decoder.u64()?;
        let reference_frame_count = decoder.u64()?;
        let candidate_frame_count = decoder.u64()?;
        let max_observed_dts_delta_ns = decoder.u64()?;
        let max_observed_pts_delta_ns = decoder.u64()?;
        let verified_gap_witnesses = decoder.u64()?;
        let verdict = OracleVerdict::decode_canonical(decoder)?;
        let first_divergence = match decoder.u8()? {
            0 => None,
            1 => Some(DivergenceReproducer::decode_canonical(decoder)?),
            _ => return Err(ContractError::InvalidIdentifier),
        };
        let reference_stream_digest = decoder.digest()?;
        let candidate_stream_digest = decoder.digest()?;
        let receipt_digest = decoder.digest()?;

        if generation.0 == 0
            || timescale_hz == 0
            || reference_frame_count == 0
            || verified_gap_witnesses > reference_frame_count
            || (verdict == OracleVerdict::ExactParity
                && (first_divergence.is_some()
                    || reference_frame_count != candidate_frame_count
                    || max_observed_dts_delta_ns > max_rounding_error_ns
                    || max_observed_pts_delta_ns > max_rounding_error_ns))
            || (verdict != OracleVerdict::ExactParity && first_divergence.is_none())
        {
            return Err(ContractError::InvalidIdentifier);
        }

        let receipt = Self {
            format_version,
            fixture_id,
            generation,
            timescale_hz,
            max_rounding_error_ns,
            reference_frame_count,
            candidate_frame_count,
            max_observed_dts_delta_ns,
            max_observed_pts_delta_ns,
            verified_gap_witnesses,
            verdict,
            first_divergence,
            reference_stream_digest,
            candidate_stream_digest,
            receipt_digest,
        };
        if !receipt.verify_digest() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(receipt)
    }
}

fn digest_reference_stream(frames: &[ReferenceDecodedFrame]) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.u64(frames.len() as u64);
    for f in frames {
        enc.u64(f.decode_index);
        enc.i128(i128::from(f.dts_ticks));
        enc.i128(i128::from(f.pts_ticks));
        enc.u32(f.duration_ticks);
        enc.u8(u8::from(f.follows_gap));
        enc.digest(f.pixel_digest);
    }
    ContentDigest::sha256(&enc.finish())
}

fn digest_candidate_stream(frames: &[CandidateDecodedFrame]) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.u64(frames.len() as u64);
    for f in frames {
        enc.u64(f.decode_index);
        enc.i128(f.dts_ns);
        enc.i128(f.pts_ns);
        enc.u64(f.duration_ns);
        enc.u8(u8::from(f.gap_witnessed));
        enc.digest(f.pixel_digest);
    }
    ContentDigest::sha256(&enc.finish())
}

fn abs_delta_u64(a: i128, b: i128) -> u64 {
    let diff = a.abs_diff(b);
    u64::try_from(diff).unwrap_or(u64::MAX)
}

/// Runs the deterministic decode/timestamp differential oracle comparing `candidate` against
/// `reference` under `policy`, sealing a canonical [`TimestampOracleReceipt`].
pub fn evaluate_decode_timestamp_oracle(
    policy: &TimestampOraclePolicy,
    reference: &[ReferenceDecodedFrame],
    candidate: &[CandidateDecodedFrame],
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<TimestampOracleReceipt, TimestampOracleError> {
    policy.validate()?;
    if is_cancelled() {
        return Err(TimestampOracleError::Cancelled);
    }
    if reference.is_empty() || reference.len() > MAX_ORACLE_FRAMES {
        return Err(TimestampOracleError::InvalidReferenceStream(
            "empty_or_oversized",
        ));
    }
    if candidate.len() > MAX_ORACLE_FRAMES {
        return Err(TimestampOracleError::InvalidReferenceStream(
            "candidate_oversized",
        ));
    }

    // Validate monotonic reference stream decode indices and DTS before comparing.
    for (idx, frame) in reference.iter().enumerate() {
        if is_cancelled() {
            return Err(TimestampOracleError::Cancelled);
        }
        if frame.decode_index != idx as u64 {
            return Err(TimestampOracleError::InvalidReferenceStream(
                "non_contiguous_decode_index",
            ));
        }
        if frame.duration_ticks == 0 {
            return Err(TimestampOracleError::InvalidReferenceStream(
                "zero_duration_ticks",
            ));
        }
        if idx > 0 && frame.dts_ticks < reference[idx - 1].dts_ticks {
            return Err(TimestampOracleError::InvalidReferenceStream(
                "reference_dts_regression",
            ));
        }
    }

    let reference_stream_digest = digest_reference_stream(reference);
    let candidate_stream_digest = digest_candidate_stream(candidate);

    let mut verdict = OracleVerdict::ExactParity;
    let mut first_divergence: Option<DivergenceReproducer> = None;
    let mut max_dts_delta: u64 = 0;
    let mut max_pts_delta: u64 = 0;
    let mut verified_gaps: u64 = 0;

    let mut record_div = |v: OracleVerdict, idx: u64, expected: String, observed: String| {
        if first_divergence.is_none() {
            verdict = v;
            first_divergence = Some(DivergenceReproducer {
                decode_index: idx,
                expected,
                observed,
            });
        }
    };

    if reference.len() != candidate.len() {
        record_div(
            OracleVerdict::FrameCountMismatch,
            reference.len().min(candidate.len()) as u64,
            format!("frames={}", reference.len()),
            format!("frames={}", candidate.len()),
        );
    }

    let compare_len = reference.len().min(candidate.len());
    let mut prev_cand_dts: Option<i128> = None;
    let mut ref_display_order: Vec<(i128, u64)> = Vec::with_capacity(compare_len);
    let mut cand_display_order: Vec<(i128, u64)> = Vec::with_capacity(compare_len);

    for i in 0..compare_len {
        if is_cancelled() {
            return Err(TimestampOracleError::Cancelled);
        }
        let r = &reference[i];
        let c = &candidate[i];

        let expected_dts = ticks_to_ns_exact(r.dts_ticks, policy.timescale_hz)?;
        let expected_pts = ticks_to_ns_exact(r.pts_ticks, policy.timescale_hz)?;
        let expected_dur = ticks_to_ns_exact(i64::from(r.duration_ticks), policy.timescale_hz)?;

        let dts_delta = abs_delta_u64(expected_dts, c.dts_ns);
        let pts_delta = abs_delta_u64(expected_pts, c.pts_ns);
        let dur_delta = abs_delta_u64(expected_dur, i128::from(c.duration_ns));

        max_dts_delta = max_dts_delta.max(dts_delta);
        max_pts_delta = max_pts_delta.max(pts_delta);

        if let Some(prev_dts) = prev_cand_dts
            && c.dts_ns < prev_dts
        {
            record_div(
                OracleVerdict::DtsDivergence,
                r.decode_index,
                format!("monotonic_dts>={prev_dts}"),
                format!("regressed_dts={}", c.dts_ns),
            );
        }
        prev_cand_dts = Some(c.dts_ns);

        if c.decode_index != r.decode_index || dts_delta > policy.max_rounding_error_ns {
            record_div(
                OracleVerdict::DtsDivergence,
                r.decode_index,
                format!("idx={},dts_ns={expected_dts}", r.decode_index),
                format!("idx={},dts_ns={}", c.decode_index, c.dts_ns),
            );
        }
        if pts_delta > policy.max_rounding_error_ns {
            record_div(
                OracleVerdict::PtsDivergence,
                r.decode_index,
                format!("pts_ns={expected_pts}"),
                format!("pts_ns={}", c.pts_ns),
            );
        }
        if dur_delta > policy.max_rounding_error_ns {
            record_div(
                OracleVerdict::DurationDivergence,
                r.decode_index,
                format!("duration_ns={expected_dur}"),
                format!("duration_ns={}", c.duration_ns),
            );
        }
        if r.follows_gap != c.gap_witnessed {
            record_div(
                OracleVerdict::GapWitnessMismatch,
                r.decode_index,
                format!("follows_gap={}", r.follows_gap),
                format!("gap_witnessed={}", c.gap_witnessed),
            );
        } else if r.follows_gap {
            verified_gaps = verified_gaps.saturating_add(1);
        }
        if r.pixel_digest != c.pixel_digest {
            record_div(
                OracleVerdict::PixelDigestMismatch,
                r.decode_index,
                r.pixel_digest.to_text(),
                c.pixel_digest.to_text(),
            );
        }

        ref_display_order.push((expected_pts, r.decode_index));
        cand_display_order.push((c.pts_ns, c.decode_index));
    }

    // Verify B-frame display-order permutation parity (sorted by PTS, tie-broken by decode_index).
    ref_display_order.sort();
    cand_display_order.sort();
    for (r_item, c_item) in ref_display_order.iter().zip(cand_display_order.iter()) {
        if r_item.1 != c_item.1 {
            record_div(
                OracleVerdict::PtsDivergence,
                r_item.1,
                format!("display_order_frame={}", r_item.1),
                format!("display_order_frame={}", c_item.1),
            );
            break;
        }
    }

    if is_cancelled() {
        return Err(TimestampOracleError::Cancelled);
    }

    let mut receipt = TimestampOracleReceipt {
        format_version: TIMESTAMP_ORACLE_FORMAT_VERSION,
        fixture_id: policy.fixture_id.clone(),
        generation: policy.generation,
        timescale_hz: policy.timescale_hz,
        max_rounding_error_ns: policy.max_rounding_error_ns,
        reference_frame_count: reference.len() as u64,
        candidate_frame_count: candidate.len() as u64,
        max_observed_dts_delta_ns: max_dts_delta,
        max_observed_pts_delta_ns: max_pts_delta,
        verified_gap_witnesses: verified_gaps,
        verdict,
        first_divergence,
        reference_stream_digest,
        candidate_stream_digest,
        receipt_digest: ContentDigest::sha256(b"pending"),
    };
    receipt.receipt_digest = receipt.computed_digest();
    Ok(receipt)
}
