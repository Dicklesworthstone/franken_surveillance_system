#![forbid(unsafe_code)]
//! Canonical digest-bound scrub verdicts, defect findings, and [`PackScrubReport`] receipts.

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm, TimestampNs};

use crate::error::PackError;
use crate::format::PackId;

use super::PACK_SCRUB_REPORT_DOMAIN;

/// Explicit integrity verdict reported by a doctor scrub pass (matching `DoctorScrubReceipt`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ScrubVerdict {
    /// Full corpus sweep completed with zero cryptographic or missing-pack defects.
    Clean,
    /// Zero corruption detected, but verification covered a bounded partial subset or hit budget clamp.
    Degraded,
    /// Cryptographic corruption or missing canonical packfile detected (`requires_obligation == true`).
    Failed,
}

impl ScrubVerdict {
    /// Returns the canonical lowercase string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
        }
    }

    /// Encodes as a canonical 1-byte tag.
    #[must_use]
    pub const fn to_tag(self) -> u8 {
        match self {
            Self::Clean => 1,
            Self::Degraded => 2,
            Self::Failed => 3,
        }
    }
}

/// Typed defect class observed during sealed packfile scrubbing.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ScrubFailureKind {
    /// Indexed sealed packfile is missing on disk.
    MissingPackFile,
    /// Sealed packfile `FSSF`..`FSSE` footer failed structural validation.
    CorruptFooter,
    /// Record `FSSP` magic, version, or framing bounds failed validation.
    InvalidRecordHeader,
    /// Record Castagnoli CRC32C checksum failed verification.
    CrcMismatch,
    /// Recomputed payload SHA-256 disagreed with record header or footer digest.
    ObjectDigestMismatch,
    /// Recomputed whole-pack SHA-256 disagreed with sealed footer digest.
    WholePackDigestMismatch,
    /// Unexpected filesystem I/O failure prevented verifying the packfile.
    IoError,
}

impl ScrubFailureKind {
    /// Encodes as a canonical 1-byte tag.
    #[must_use]
    pub const fn to_tag(self) -> u8 {
        match self {
            Self::MissingPackFile => 1,
            Self::CorruptFooter => 2,
            Self::InvalidRecordHeader => 3,
            Self::CrcMismatch => 4,
            Self::ObjectDigestMismatch => 5,
            Self::WholePackDigestMismatch => 6,
            Self::IoError => 7,
        }
    }
}

/// Exact forensic defect record emitted by [`crate::BackgroundScrubber`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScrubFinding {
    /// Sealed packfile where the defect was detected.
    pub pack_id: PackId,
    /// Exact content digest of the corrupt object when attributable to a specific record.
    pub digest: Option<ContentDigest>,
    /// Byte offset inside the packfile associated with the defect.
    pub offset: u64,
    /// Stable defect classification.
    pub kind: ScrubFailureKind,
    /// Non-secret diagnostic explanation.
    pub detail: String,
}

impl CanonicalEncode for ScrubFinding {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(u64::from(self.pack_id.epoch));
        encoder.u64(self.pack_id.seq);
        match self.digest {
            Some(d) => {
                encoder.bool(true);
                encoder.digest(d);
            }
            None => encoder.bool(false),
        }
        encoder.u64(self.offset);
        encoder.tag(self.kind.to_tag());
        encoder.text(&self.detail);
    }
}

/// Canonical digest-bound scrub receipt emitted by [`crate::BackgroundScrubber::scrub_pass`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackScrubReport {
    /// Caller-declared scrub completion timestamp (no ambient clock).
    pub scrubbed_at_ns: TimestampNs,
    /// Current sweep cycle ordinal (`1`-based).
    pub cycle_number: u64,
    /// True if this pass reached the end of the sealed pack corpus.
    pub cycle_completed: bool,
    /// Sealed packfiles fully verified during this pass.
    pub verified_packs: u64,
    /// Individual objects verified during this pass.
    pub verified_objects: u64,
    /// Framed object bytes verified during this pass.
    pub verified_bytes: u64,
    /// Total sealed packfiles present in the store when this pass ran.
    pub total_sealed_packs: u64,
    /// Verified corpus fraction in parts per million (`0..=1_000_000`).
    pub verified_fraction_ppm: u32,
    /// Sorted, deduplicated digests of every corrupt object detected during this pass.
    pub corrupt_digests: Vec<ContentDigest>,
    /// Sorted, deduplicated IDs of every missing sealed packfile detected during this pass.
    pub missing_packs: Vec<PackId>,
    /// Detailed forensic findings emitted during this pass.
    pub findings: Vec<ScrubFinding>,
    /// Explicit scrub verdict (`Clean`, `Degraded`, or `Failed`).
    pub verdict: ScrubVerdict,
    /// True whenever any corruption or missing packfile requires creating a repair obligation.
    pub requires_obligation: bool,
    /// Domain-separated SHA-256 digest under [`PACK_SCRUB_REPORT_DOMAIN`].
    pub report_digest: ContentDigest,
}

impl PackScrubReport {
    /// Recomputes and verifies [`Self::report_digest`], failing closed on tampering.
    pub fn verify_digest(&self) -> Result<(), PackError> {
        let expected = compute_scrub_report_digest(self)?;
        if expected != self.report_digest {
            return Err(PackError::DigestMismatch {
                expected: self.report_digest,
                actual: expected,
            });
        }
        Ok(())
    }
}

pub(crate) fn compute_scrub_report_digest(
    report: &PackScrubReport,
) -> Result<ContentDigest, PackError> {
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.canonical.v1");
    enc.text(PACK_SCRUB_REPORT_DOMAIN);
    report.scrubbed_at_ns.encode_canonical(&mut enc);
    enc.u64(report.cycle_number);
    enc.bool(report.cycle_completed);
    enc.u64(report.verified_packs);
    enc.u64(report.verified_objects);
    enc.u64(report.verified_bytes);
    enc.u64(report.total_sealed_packs);
    enc.u64(u64::from(report.verified_fraction_ppm));
    enc.u64(report.corrupt_digests.len() as u64);
    for d in &report.corrupt_digests {
        enc.digest(*d);
    }
    enc.u64(report.missing_packs.len() as u64);
    for p in &report.missing_packs {
        enc.u64(u64::from(p.epoch));
        enc.u64(p.seq);
    }
    enc.u64(report.findings.len() as u64);
    for finding in &report.findings {
        finding.encode_canonical(&mut enc);
    }
    enc.tag(report.verdict.to_tag());
    enc.bool(report.requires_obligation);
    let bytes = enc.finish_checked()?;
    Ok(ContentDigest::sha256(&bytes))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn finalize_report(
    scrubbed_at_ns: TimestampNs,
    cycle_number: u64,
    cycle_completed: bool,
    verified_packs: u64,
    verified_objects: u64,
    verified_bytes: u64,
    total_sealed_packs: u64,
    verified_fraction_ppm: u32,
    corrupt_digests: Vec<ContentDigest>,
    missing_packs: Vec<PackId>,
    findings: Vec<ScrubFinding>,
    verdict: ScrubVerdict,
) -> Result<PackScrubReport, PackError> {
    let requires_obligation = matches!(verdict, ScrubVerdict::Failed) || !findings.is_empty();
    let mut report = PackScrubReport {
        scrubbed_at_ns,
        cycle_number,
        cycle_completed,
        verified_packs,
        verified_objects,
        verified_bytes,
        total_sealed_packs,
        verified_fraction_ppm,
        corrupt_digests,
        missing_packs,
        findings,
        verdict,
        requires_obligation,
        report_digest: ContentDigest::new(DigestAlgorithm::Sha256, [0_u8; 32]),
    };
    report.report_digest = compute_scrub_report_digest(&report)?;
    Ok(report)
}
