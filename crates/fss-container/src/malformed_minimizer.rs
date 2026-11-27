#![forbid(unsafe_code)]
//! Adversarial malformed compressed-stream corpus and deterministic delta-debugging minimizer
//! (`FSS-125`, bead `fss-x4a.12.24`, proof family `TEST-MEDIA-MALFORMED-001`).
//!
//! Treats every compressed container/codec byte stream as hostile (`INV-049`):
//! - [`default_adversarial_corpus`] provides a checked-in, deterministic hostile corpus across
//!   ISO-BMFF/MP4, Matroska/EBML, MJPEG/JPEG, H.264/AVC Annex-B, and H.265/HEVC Annex-B covering
//!   truncation, zero/max/overflow length fields, contradictory headers, recursive container size
//!   bombs, invalid RBSP/emulation prevention, and boundary-byte attacks.
//! - [`minimize_reproducer`] implements a bounded, deterministic, cooperatively cancellable
//!   3-stage delta debugger (ddmin chunk deletion -> single-byte deletion -> byte simplification
//!   toward `0x00`/`0x01`) that shrinks any failing input to a compact, reproducible counterexample
//!   sealed in a tamper-evident [`MinimizedReproducerReceipt`].

use core::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, Generation, TimestampNs,
};

/// Registered digest domain for canonical minimized reproducer receipts
/// (`SCHEMA-DOMAIN-CONTAINER-MINIMIZED-REPRODUCER-001`).
pub const MINIMIZED_REPRODUCER_RECEIPT_DOMAIN: &str =
    "fss.container.minimized_reproducer_receipt.v1";

/// Canonical binary format version for [`MinimizedReproducerReceipt`].
pub const MINIMIZED_REPRODUCER_FORMAT_VERSION: u32 = 1;

/// Hard upper bound on input bytes accepted by [`minimize_reproducer`] (1 MiB).
pub const MAX_MINIMIZER_INPUT_BYTES: usize = 1024 * 1024;

/// Hard upper bound on predicate evaluations per minimization run.
pub const MAX_MINIMIZER_EVALUATIONS: u32 = 100_000;

/// Maximum UTF-8 bytes in case IDs or failure-signature tags.
pub const MAX_CASE_LABEL_BYTES: usize = 128;

/// Closed taxonomy of compressed media stream formats targeted by `FSS-125`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StreamFormatKind {
    /// ISO-BMFF / MP4 / QuickTime container bytes.
    IsoBmff,
    /// Matroska / WebM EBML container bytes.
    Matroska,
    /// JPEG / MJPEG compressed frame bytes.
    Mjpeg,
    /// H.264 / AVC Annex-B NAL unit stream.
    AnnexBH264,
    /// H.265 / HEVC Annex-B NAL unit stream.
    AnnexBH265,
}

impl StreamFormatKind {
    /// Stable machine-readable format label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IsoBmff => "iso-bmff",
            Self::Matroska => "matroska",
            Self::Mjpeg => "mjpeg",
            Self::AnnexBH264 => "annex-b-h264",
            Self::AnnexBH265 => "annex-b-h265",
        }
    }
}

impl CanonicalEncode for StreamFormatKind {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::IsoBmff => 1,
            Self::Matroska => 2,
            Self::Mjpeg => 3,
            Self::AnnexBH264 => 4,
            Self::AnnexBH265 => 5,
        });
    }
}

impl CanonicalDecode for StreamFormatKind {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::IsoBmff),
            2 => Ok(Self::Matroska),
            3 => Ok(Self::Mjpeg),
            4 => Ok(Self::AnnexBH264),
            5 => Ok(Self::AnnexBH265),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// One deterministic hostile compressed-stream corpus vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdversarialStreamCase {
    /// Stable unique case identifier.
    pub case_id: String,
    /// Target compressed stream format.
    pub format: StreamFormatKind,
    /// Short hostility category (e.g., `box_size_zero_bomb`, `truncated_header`).
    pub attack_class: String,
    /// Exact hostile byte sequence.
    pub bytes: Vec<u8>,
}

/// Returns the deterministic built-in adversarial malformed compressed-stream corpus covering all
/// five FSS media formats and major parser/decoder attack classes.
#[must_use]
pub fn default_adversarial_corpus() -> Vec<AdversarialStreamCase> {
    vec![
        AdversarialStreamCase {
            case_id: "isobmff-truncated-ftyp".to_owned(),
            format: StreamFormatKind::IsoBmff,
            attack_class: "truncated_header".to_owned(),
            bytes: b"\x00\x00\x00\x18ftyp".to_vec(),
        },
        AdversarialStreamCase {
            case_id: "isobmff-box-size-overflow".to_owned(),
            format: StreamFormatKind::IsoBmff,
            attack_class: "length_field_overflow".to_owned(),
            bytes: b"\x00\x00\x00\x10ftypisom\x00\x00\x00\x00\xff\xff\xff\xffmoov\x00\x00\x00\x08trak"
                .to_vec(),
        },
        AdversarialStreamCase {
            case_id: "isobmff-contradictory-annexb-ftyp".to_owned(),
            format: StreamFormatKind::IsoBmff,
            attack_class: "contradictory_signature".to_owned(),
            bytes: b"\x00\x00\x01\x67ftypisom\x00\x00\x00\x00".to_vec(),
        },
        AdversarialStreamCase {
            case_id: "isobmff-nested-zero-size-bomb".to_owned(),
            format: StreamFormatKind::IsoBmff,
            attack_class: "zero_size_container_bomb".to_owned(),
            bytes: b"\x00\x00\x00\x10ftypisom\x00\x00\x00\x00\x00\x00\x00\x00moov\x00\x00\x00\x01trak\xff\xff\xff\xff\xff\xff\xff\xff"
                .to_vec(),
        },
        AdversarialStreamCase {
            case_id: "mkv-truncated-ebml-header".to_owned(),
            format: StreamFormatKind::Matroska,
            attack_class: "truncated_ebml".to_owned(),
            bytes: vec![0x1A, 0x45, 0xDF, 0xA3, 0x9F, 0x42, 0x86],
        },
        AdversarialStreamCase {
            case_id: "mkv-invalid-vint-zero".to_owned(),
            format: StreamFormatKind::Matroska,
            attack_class: "invalid_ebml_vint".to_owned(),
            bytes: vec![
                0x1A, 0x45, 0xDF, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0x80, 0x67, 0x00,
            ],
        },
        AdversarialStreamCase {
            case_id: "mjpeg-corrupt-sof0-zero-dims".to_owned(),
            format: StreamFormatKind::Mjpeg,
            attack_class: "zero_dimensions".to_owned(),
            bytes: vec![
                0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
                0x11, 0x00, 0xFF, 0xD9,
            ],
        },
        AdversarialStreamCase {
            case_id: "mjpeg-truncated-dht-length".to_owned(),
            format: StreamFormatKind::Mjpeg,
            attack_class: "length_field_underflow".to_owned(),
            bytes: vec![0xFF, 0xD8, 0xFF, 0xC4, 0xFF, 0xFF, 0x00, 0x01, 0xFF, 0xD9],
        },
        AdversarialStreamCase {
            case_id: "h264-truncated-sps-rbsp".to_owned(),
            format: StreamFormatKind::AnnexBH264,
            attack_class: "truncated_sps".to_owned(),
            bytes: vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00],
        },
        AdversarialStreamCase {
            case_id: "h264-forbidden-zero-bit-and-bad-epb".to_owned(),
            format: StreamFormatKind::AnnexBH264,
            attack_class: "forbidden_nal_header_and_epb".to_owned(),
            bytes: vec![
                0x00, 0x00, 0x00, 0x01, 0xE7, 0x64, 0x00, 0x1F, 0x00, 0x00, 0x03, 0xFF, 0xFF,
                0x80,
            ],
        },
        AdversarialStreamCase {
            case_id: "h265-truncated-vps-nal".to_owned(),
            format: StreamFormatKind::AnnexBH265,
            attack_class: "truncated_vps".to_owned(),
            bytes: vec![0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0C],
        },
        AdversarialStreamCase {
            case_id: "h265-corrupt-sps-boundary-bytes".to_owned(),
            format: StreamFormatKind::AnnexBH265,
            attack_class: "boundary_bytes".to_owned(),
            bytes: vec![
                0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0xFF, 0xFF, 0x7F, 0x80, 0x00, 0x00, 0x03,
                0x00, 0xFF,
            ],
        },
    ]
}

/// Hard resource and behavior bounds governing one deterministic minimization pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MinimizerPolicy {
    /// Maximum input length in bytes (`1..=MAX_MINIMIZER_INPUT_BYTES`).
    pub max_input_bytes: usize,
    /// Hard ceiling on predicate evaluations (`2..=MAX_MINIMIZER_EVALUATIONS`).
    pub max_evaluations: u32,
    /// Maximum ddmin + single-byte sweep passes (`1..=16`).
    pub max_passes: u8,
    /// Whether to run deterministic byte simplification (`b -> 0x00` / `0x01`) after shrinking.
    pub enable_byte_simplification: bool,
}

impl Default for MinimizerPolicy {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024,
            max_evaluations: 4_096,
            max_passes: 4,
            enable_byte_simplification: true,
        }
    }
}

impl MinimizerPolicy {
    /// Fails closed on zero or out-of-range limits.
    pub fn validate(self) -> Result<(), MinimizerError> {
        if !(1..=MAX_MINIMIZER_INPUT_BYTES).contains(&self.max_input_bytes)
            || !(2..=MAX_MINIMIZER_EVALUATIONS).contains(&self.max_evaluations)
            || !(1..=16).contains(&self.max_passes)
        {
            return Err(MinimizerError::InvalidPolicy);
        }
        Ok(())
    }
}

/// Typed fail-closed refusal for adversarial corpus minimization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MinimizerError {
    /// Policy bounds or labels are invalid.
    InvalidPolicy,
    /// Input is empty or exceeds `max_input_bytes`.
    InputOutOfBounds {
        /// Observed length.
        actual: usize,
        /// Configured ceiling.
        max: usize,
    },
    /// Initial candidate did NOT trigger the target failure predicate; nothing to minimize.
    InitialInputDidNotFail,
    /// Final minimized candidate failed re-verification (nondeterministic predicate detected!).
    NondeterministicPredicate,
    /// Cooperative cancellation observed before completing minimization.
    Cancelled,
}

impl fmt::Display for MinimizerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => write!(f, "invalid malformed-stream minimizer policy"),
            Self::InputOutOfBounds { actual, max } => {
                write!(f, "minimizer input length {actual} outside 1..={max}")
            }
            Self::InitialInputDidNotFail => {
                write!(f, "initial input did not reproduce target failure")
            }
            Self::NondeterministicPredicate => {
                write!(f, "minimizer predicate was nondeterministic on re-check")
            }
            Self::Cancelled => write!(f, "minimizer run cancelled"),
        }
    }
}

impl std::error::Error for MinimizerError {}

fn validate_label(val: &str) -> bool {
    !val.is_empty()
        && val.len() <= MAX_CASE_LABEL_BYTES
        && !val
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
}

/// Canonical, tamper-evident witness receipt binding an original failing compressed stream to its
/// deterministic minimized counterexample.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MinimizedReproducerReceipt {
    /// Format version (`MINIMIZED_REPRODUCER_FORMAT_VERSION`).
    pub format_version: u32,
    /// Stable case identifier.
    pub case_id: String,
    /// Target compressed stream format.
    pub format: StreamFormatKind,
    /// Pinned corpus/parser generation (`!= 0`).
    pub generation: Generation,
    /// Machine-readable failure signature preserved throughout minimization.
    pub failure_signature: String,
    /// Timestamp when minimization completed.
    pub minimized_at_ns: TimestampNs,
    /// Exact SHA-256 digest of the original failing input bytes.
    pub original_digest: ContentDigest,
    /// Original byte length (`>= 1`).
    pub original_len: u64,
    /// Exact SHA-256 digest of `minimized_bytes`.
    pub minimized_digest: ContentDigest,
    /// Minimized byte length (`<= original_len`).
    pub minimized_len: u64,
    /// Exact minimized reproducer bytes.
    pub minimized_bytes: Vec<u8>,
    /// Number of predicate evaluations executed (`<= max_evaluations`).
    pub predicate_evaluations: u32,
    /// Configured evaluation ceiling.
    pub max_evaluations: u32,
    /// Whether the evaluation budget was reached before reaching a 1-minimal fixed point.
    pub budget_exhausted: bool,
    /// Always `true`: final candidate was independently re-verified to reproduce the failure.
    pub reproduces_failure: bool,
    /// Domain-separated SHA-256 digest over all fields above.
    pub receipt_digest: ContentDigest,
}

impl MinimizedReproducerReceipt {
    /// Recomputes the exact domain-separated SHA-256 digest over all canonical fields.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(MINIMIZED_REPRODUCER_RECEIPT_DOMAIN);
        encoder.u32(self.format_version);
        encoder.text(&self.case_id);
        self.format.encode_canonical(&mut encoder);
        encoder.u64(self.generation.0);
        encoder.text(&self.failure_signature);
        encoder.i128(self.minimized_at_ns.0);
        encoder.digest(self.original_digest);
        encoder.u64(self.original_len);
        encoder.digest(self.minimized_digest);
        encoder.u64(self.minimized_len);
        encoder.bytes(&self.minimized_bytes);
        encoder.u32(self.predicate_evaluations);
        encoder.u32(self.max_evaluations);
        encoder.u8(u8::from(self.budget_exhausted));
        encoder.u8(u8::from(self.reproduces_failure));
        ContentDigest::sha256(&encoder.finish())
    }

    /// Returns `true` iff `receipt_digest` matches [`Self::computed_digest`].
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.receipt_digest == self.computed_digest()
    }
}

impl CanonicalEncode for MinimizedReproducerReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.format_version);
        encoder.text(&self.case_id);
        self.format.encode_canonical(encoder);
        encoder.u64(self.generation.0);
        encoder.text(&self.failure_signature);
        encoder.i128(self.minimized_at_ns.0);
        encoder.digest(self.original_digest);
        encoder.u64(self.original_len);
        encoder.digest(self.minimized_digest);
        encoder.u64(self.minimized_len);
        encoder.bytes(&self.minimized_bytes);
        encoder.u32(self.predicate_evaluations);
        encoder.u32(self.max_evaluations);
        encoder.u8(u8::from(self.budget_exhausted));
        encoder.u8(u8::from(self.reproduces_failure));
        encoder.digest(self.receipt_digest);
    }
}

fn decode_bool(decoder: &mut CanonicalDecoder<'_>) -> Result<bool, ContractError> {
    match decoder.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ContractError::InvalidIdentifier),
    }
}

impl CanonicalDecode for MinimizedReproducerReceipt {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let format_version = decoder.u32()?;
        if format_version != MINIMIZED_REPRODUCER_FORMAT_VERSION {
            return Err(ContractError::InvalidIdentifier);
        }
        let case_id = decoder.text()?.to_owned();
        let format = StreamFormatKind::decode_canonical(decoder)?;
        let generation = Generation(decoder.u64()?);
        let failure_signature = decoder.text()?.to_owned();
        let minimized_at_ns = TimestampNs(decoder.i128()?);
        let original_digest = decoder.digest()?;
        let original_len = decoder.u64()?;
        let minimized_digest = decoder.digest()?;
        let minimized_len = decoder.u64()?;
        let minimized_bytes = decoder.bytes()?.to_vec();
        let predicate_evaluations = decoder.u32()?;
        let max_evaluations = decoder.u32()?;
        let budget_exhausted = decode_bool(decoder)?;
        let reproduces_failure = decode_bool(decoder)?;
        let receipt_digest = decoder.digest()?;

        if !validate_label(&case_id)
            || !validate_label(&failure_signature)
            || generation.0 == 0
            || !(1..=MAX_MINIMIZER_INPUT_BYTES as u64).contains(&original_len)
            || minimized_len > original_len
            || minimized_bytes.len() as u64 != minimized_len
            || ContentDigest::sha256(&minimized_bytes) != minimized_digest
            || !(2..=MAX_MINIMIZER_EVALUATIONS).contains(&max_evaluations)
            || !(2..=max_evaluations).contains(&predicate_evaluations)
            || (budget_exhausted && predicate_evaluations != max_evaluations)
            || !reproduces_failure
        {
            return Err(ContractError::InvalidIdentifier);
        }

        let receipt = Self {
            format_version,
            case_id,
            format,
            generation,
            failure_signature,
            minimized_at_ns,
            original_digest,
            original_len,
            minimized_digest,
            minimized_len,
            minimized_bytes,
            predicate_evaluations,
            max_evaluations,
            budget_exhausted,
            reproduces_failure,
            receipt_digest,
        };
        if !receipt.verify_digest() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(receipt)
    }
}

/// Request metadata for one deterministic delta-debugging minimization run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MinimizeRequest<'a> {
    /// Stable case identifier.
    pub case_id: &'a str,
    /// Target stream format.
    pub format: StreamFormatKind,
    /// Pinned parser/corpus generation (`!= 0`).
    pub generation: Generation,
    /// Machine-readable target failure signature.
    pub failure_signature: &'a str,
    /// Observation timestamp.
    pub minimized_at_ns: TimestampNs,
    /// Original failing byte stream.
    pub original: &'a [u8],
}

/// Deterministically minimizes `req.original` while preserving `predicate(&candidate) == true`,
/// under hard evaluation/size budgets and cooperative cancellation, returning a sealed
/// [`MinimizedReproducerReceipt`].
pub fn minimize_reproducer(
    policy: MinimizerPolicy,
    req: MinimizeRequest<'_>,
    mut is_cancelled: impl FnMut() -> bool,
    mut predicate: impl FnMut(&[u8]) -> bool,
) -> Result<MinimizedReproducerReceipt, MinimizerError> {
    policy.validate()?;
    if !validate_label(req.case_id)
        || !validate_label(req.failure_signature)
        || req.generation.0 == 0
    {
        return Err(MinimizerError::InvalidPolicy);
    }
    if req.original.is_empty() || req.original.len() > policy.max_input_bytes {
        return Err(MinimizerError::InputOutOfBounds {
            actual: req.original.len(),
            max: policy.max_input_bytes,
        });
    }
    if is_cancelled() {
        return Err(MinimizerError::Cancelled);
    }

    // Reserve 1 evaluation at the end for mandatory independent reproducibility re-verification.
    let search_limit = policy.max_evaluations - 1;
    let mut evals: u32 = 1;
    if !predicate(req.original) {
        return Err(MinimizerError::InitialInputDidNotFail);
    }

    let mut best = req.original.to_vec();
    let mut budget_exhausted = false;

    let try_candidate = |cand: &[u8],
                         evals: &mut u32,
                         budget_exhausted: &mut bool,
                         is_cancelled: &mut dyn FnMut() -> bool,
                         predicate: &mut dyn FnMut(&[u8]) -> bool|
     -> Result<Option<bool>, MinimizerError> {
        if is_cancelled() {
            return Err(MinimizerError::Cancelled);
        }
        if *evals >= search_limit {
            *budget_exhausted = true;
            return Ok(None);
        }
        *evals = evals.saturating_add(1);
        Ok(Some(predicate(cand)))
    };

    for _pass in 0..policy.max_passes {
        let mut improved = false;

        // Stage 1: ddmin coarse chunk removal (granularity n = 2, 4, 8, ...).
        let mut granularity: usize = 2;
        while best.len() >= 2 && granularity <= best.len() {
            let chunk_size = best.len().div_ceil(granularity);
            let mut idx = 0;
            let mut removed_any = false;
            while idx < best.len() {
                let end = (idx + chunk_size).min(best.len());
                let mut candidate = Vec::with_capacity(best.len() - (end - idx));
                candidate.extend_from_slice(&best[..idx]);
                candidate.extend_from_slice(&best[end..]);
                match try_candidate(
                    &candidate,
                    &mut evals,
                    &mut budget_exhausted,
                    &mut is_cancelled,
                    &mut predicate,
                )? {
                    Some(true) => {
                        best = candidate;
                        improved = true;
                        removed_any = true;
                        granularity = granularity.saturating_sub(1).max(2);
                        break;
                    }
                    Some(false) => {
                        idx = end;
                    }
                    None => break,
                }
            }
            if budget_exhausted {
                break;
            }
            if !removed_any {
                if granularity >= best.len() {
                    break;
                }
                granularity = granularity.saturating_mul(2).min(best.len());
            }
        }
        if budget_exhausted {
            break;
        }

        // Stage 2: single-byte deletion sweep when Stage 1 did not already test every 1-byte
        // deletion (i.e. when `best.len() == 1` to test empty, or if granularity stopped early).
        let stage1_covered_singles = best.len() >= 2 && granularity >= best.len();
        if !stage1_covered_singles {
            let mut pos = best.len();
            while pos > 0 {
                pos -= 1;
                let mut candidate = Vec::with_capacity(best.len() - 1);
                candidate.extend_from_slice(&best[..pos]);
                candidate.extend_from_slice(&best[pos + 1..]);
                match try_candidate(
                    &candidate,
                    &mut evals,
                    &mut budget_exhausted,
                    &mut is_cancelled,
                    &mut predicate,
                )? {
                    Some(true) => {
                        best = candidate;
                        improved = true;
                    }
                    Some(false) => {}
                    None => break,
                }
            }
        }
        if budget_exhausted || !improved {
            break;
        }
    }

    // Stage 3: deterministic byte simplification toward canonical 0x00 / 0x01 values.
    if policy.enable_byte_simplification && !budget_exhausted {
        for pos in 0..best.len() {
            let orig_byte = best[pos];
            for replacement in [0x00_u8, 0x01_u8] {
                if orig_byte <= replacement {
                    continue;
                }
                best[pos] = replacement;
                match try_candidate(
                    &best,
                    &mut evals,
                    &mut budget_exhausted,
                    &mut is_cancelled,
                    &mut predicate,
                )? {
                    Some(true) => break,
                    Some(false) => {
                        best[pos] = orig_byte;
                    }
                    None => {
                        best[pos] = orig_byte;
                        break;
                    }
                }
            }
            if budget_exhausted {
                break;
            }
        }
    }

    if is_cancelled() {
        return Err(MinimizerError::Cancelled);
    }

    // Independent final reproducibility verification (uses reserved evaluation slot).
    evals = evals.saturating_add(1);
    if !predicate(&best) {
        return Err(MinimizerError::NondeterministicPredicate);
    }

    let original_digest = ContentDigest::sha256(req.original);
    let minimized_digest = ContentDigest::sha256(&best);
    let minimized_len = best.len() as u64;
    let mut receipt = MinimizedReproducerReceipt {
        format_version: MINIMIZED_REPRODUCER_FORMAT_VERSION,
        case_id: req.case_id.to_owned(),
        format: req.format,
        generation: req.generation,
        failure_signature: req.failure_signature.to_owned(),
        minimized_at_ns: req.minimized_at_ns,
        original_digest,
        original_len: req.original.len() as u64,
        minimized_digest,
        minimized_len,
        minimized_bytes: best,
        predicate_evaluations: evals,
        max_evaluations: policy.max_evaluations,
        budget_exhausted,
        reproduces_failure: true,
        receipt_digest: ContentDigest::sha256(b"pending"),
    };
    receipt.receipt_digest = receipt.computed_digest();
    Ok(receipt)
}
