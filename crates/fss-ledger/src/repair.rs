//! Audited doctor, sealed repair plan, and quarantine apply for foreign trailing bytes.
//!
//! Ref: fss-x4a.9.21 / LEDGER-REPAIR-001

use std::error::Error;
use std::fmt::{self, Write as _};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, DigestAlgorithm, sha256};

use crate::MAX_RECORD_PAYLOAD_BYTES;
use crate::error::JournalError;
use crate::format::{
    COMMIT_MAGIC, FORMAT_VERSION, HEADER_LEN, RECORD_MAGIC, TRAILER_LEN, read_u16, read_u32,
    read_u64, record_root,
};
use crate::recovery::recover_bytes;

const PLAN_SEAL_DOMAIN: &[u8] = b"FSS-LEDGER-SEALED-REPAIR-PLAN-V1\0";

/// Byte range and cryptographic digest of foreign trailing bytes in a journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForeignRange {
    /// Byte offset where foreign trailing bytes begin.
    pub offset: u64,
    /// Byte length of foreign trailing bytes.
    pub length: u64,
    /// SHA-256 digest of the foreign trailing byte range.
    pub digest: ContentDigest,
}

impl ForeignRange {
    /// Constructs a new foreign range descriptor.
    #[must_use]
    pub const fn new(offset: u64, length: u64, digest: ContentDigest) -> Self {
        Self {
            offset,
            length,
            digest,
        }
    }

    /// Byte offset where foreign trailing bytes begin.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Byte length of foreign trailing bytes.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// SHA-256 digest of the foreign trailing byte range.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
}

/// Diagnostic report produced by pure inspection of journal bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairDoctorReport {
    pub(crate) committed_len: u64,
    pub(crate) last_root: ContentDigest,
    pub(crate) records_count: usize,
    pub(crate) incomplete_tail: Option<u64>,
    pub(crate) foreign_range: Option<ForeignRange>,
}

impl RepairDoctorReport {
    /// Byte length through the last valid committed record's trailer.
    #[must_use]
    pub const fn committed_len(&self) -> u64 {
        self.committed_len
    }

    /// Root of the last committed record, or zero digest if no records are committed.
    #[must_use]
    pub const fn last_root(&self) -> ContentDigest {
        self.last_root
    }

    /// Number of valid committed records discovered.
    #[must_use]
    pub const fn records_count(&self) -> usize {
        self.records_count
    }

    /// First byte of a valid incomplete record tail from this writer, if present.
    #[must_use]
    pub const fn incomplete_tail(&self) -> Option<u64> {
        self.incomplete_tail
    }

    /// Foreign trailing byte range and digest, if detected.
    #[must_use]
    pub fn foreign_range(&self) -> Option<&ForeignRange> {
        self.foreign_range.as_ref()
    }

    /// Convenience: foreign offset if present.
    #[must_use]
    pub fn foreign_offset(&self) -> Option<u64> {
        self.foreign_range.as_ref().map(|r| r.offset)
    }

    /// Convenience: foreign length if present.
    #[must_use]
    pub fn foreign_length(&self) -> Option<u64> {
        self.foreign_range.as_ref().map(|r| r.length)
    }

    /// Convenience: foreign digest if present.
    #[must_use]
    pub fn foreign_digest(&self) -> Option<ContentDigest> {
        self.foreign_range.as_ref().map(|r| r.digest)
    }

    /// Returns true if foreign trailing bytes were detected requiring repair.
    #[must_use]
    pub const fn has_foreign_bytes(&self) -> bool {
        self.foreign_range.is_some()
    }

    /// Creates a sealed repair plan targeting a journal at `journal_path`.
    pub fn plan(&self, journal_path: impl AsRef<Path>) -> Result<SealedRepairPlan, RepairError> {
        SealedRepairPlan::create(journal_path, self)
    }

    /// Creates a sealed repair plan with an explicit cut offset.
    pub fn plan_with_cut(
        &self,
        journal_path: impl AsRef<Path>,
        cut_offset: u64,
    ) -> Result<SealedRepairPlan, RepairError> {
        SealedRepairPlan::create_with_cut(journal_path, self, cut_offset)
    }
}

/// Alias for [`RepairDoctorReport`].
pub type DoctorReport = RepairDoctorReport;

/// Alias for [`RepairDoctorReport`].
pub type JournalDoctorReport = RepairDoctorReport;

/// Pure function inspecting journal bytes and returning a typed doctor report.
///
/// Discovers the committed prefix length and any foreign trailing range and its SHA-256 digest.
pub fn doctor(bytes: &[u8]) -> Result<RepairDoctorReport, RepairError> {
    let mut offset = 0_usize;
    let mut expected_sequence = 1_u64;
    let mut previous_root = [0_u8; 32];
    let mut records_count = 0_usize;
    let mut committed_len = 0_usize;

    while offset < bytes.len() {
        let start = offset;
        let remaining = bytes.len() - offset;
        let check_len = remaining.min(8);

        // If magic doesn't match RECORD_MAGIC prefix, these are foreign bytes after committed_len
        if bytes[offset..offset + check_len] != RECORD_MAGIC[..check_len] {
            let foreign_len = (bytes.len() - committed_len) as u64;
            let foreign_digest =
                ContentDigest::new(DigestAlgorithm::Sha256, sha256(&bytes[committed_len..]));
            return Ok(RepairDoctorReport {
                committed_len: committed_len as u64,
                last_root: ContentDigest::new(DigestAlgorithm::Sha256, previous_root),
                records_count,
                incomplete_tail: None,
                foreign_range: Some(ForeignRange::new(
                    committed_len as u64,
                    foreign_len,
                    foreign_digest,
                )),
            });
        }

        // Check for valid torn write prefix from this writer (< HEADER_LEN)
        if remaining < HEADER_LEN {
            return Ok(RepairDoctorReport {
                committed_len: committed_len as u64,
                last_root: ContentDigest::new(DigestAlgorithm::Sha256, previous_root),
                records_count,
                incomplete_tail: Some(start as u64),
                foreign_range: None,
            });
        }

        let mut read_offset = offset + 8;
        let version = read_u16(bytes, &mut read_offset);
        if version != FORMAT_VERSION {
            let foreign_len = (bytes.len() - committed_len) as u64;
            let foreign_digest =
                ContentDigest::new(DigestAlgorithm::Sha256, sha256(&bytes[committed_len..]));
            return Ok(RepairDoctorReport {
                committed_len: committed_len as u64,
                last_root: ContentDigest::new(DigestAlgorithm::Sha256, previous_root),
                records_count,
                incomplete_tail: None,
                foreign_range: Some(ForeignRange::new(
                    committed_len as u64,
                    foreign_len,
                    foreign_digest,
                )),
            });
        }

        let sequence = read_u64(bytes, &mut read_offset);
        if sequence != expected_sequence {
            let foreign_len = (bytes.len() - committed_len) as u64;
            let foreign_digest =
                ContentDigest::new(DigestAlgorithm::Sha256, sha256(&bytes[committed_len..]));
            return Ok(RepairDoctorReport {
                committed_len: committed_len as u64,
                last_root: ContentDigest::new(DigestAlgorithm::Sha256, previous_root),
                records_count,
                incomplete_tail: None,
                foreign_range: Some(ForeignRange::new(
                    committed_len as u64,
                    foreign_len,
                    foreign_digest,
                )),
            });
        }

        let kind = read_u16(bytes, &mut read_offset);
        let payload_len = read_u32(bytes, &mut read_offset);
        let payload_len_usize = match usize::try_from(payload_len) {
            Ok(len) if len <= MAX_RECORD_PAYLOAD_BYTES => len,
            _ => {
                let foreign_len = (bytes.len() - committed_len) as u64;
                let foreign_digest =
                    ContentDigest::new(DigestAlgorithm::Sha256, sha256(&bytes[committed_len..]));
                return Ok(RepairDoctorReport {
                    committed_len: committed_len as u64,
                    last_root: ContentDigest::new(DigestAlgorithm::Sha256, previous_root),
                    records_count,
                    incomplete_tail: None,
                    foreign_range: Some(ForeignRange::new(
                        committed_len as u64,
                        foreign_len,
                        foreign_digest,
                    )),
                });
            }
        };

        let mut named_previous = [0_u8; 32];
        named_previous.copy_from_slice(&bytes[read_offset..read_offset + 32]);
        read_offset += 32;
        if named_previous != previous_root {
            let foreign_len = (bytes.len() - committed_len) as u64;
            let foreign_digest =
                ContentDigest::new(DigestAlgorithm::Sha256, sha256(&bytes[committed_len..]));
            return Ok(RepairDoctorReport {
                committed_len: committed_len as u64,
                last_root: ContentDigest::new(DigestAlgorithm::Sha256, previous_root),
                records_count,
                incomplete_tail: None,
                foreign_range: Some(ForeignRange::new(
                    committed_len as u64,
                    foreign_len,
                    foreign_digest,
                )),
            });
        }

        let mut named_payload_digest = [0_u8; 32];
        named_payload_digest.copy_from_slice(&bytes[read_offset..read_offset + 32]);
        read_offset += 32;

        if bytes.len() - read_offset < payload_len_usize.saturating_add(TRAILER_LEN) {
            return Ok(RepairDoctorReport {
                committed_len: committed_len as u64,
                last_root: ContentDigest::new(DigestAlgorithm::Sha256, previous_root),
                records_count,
                incomplete_tail: Some(start as u64),
                foreign_range: None,
            });
        }

        let payload = &bytes[read_offset..read_offset + payload_len_usize];
        read_offset += payload_len_usize;
        if sha256(payload) != named_payload_digest {
            let foreign_len = (bytes.len() - committed_len) as u64;
            let foreign_digest =
                ContentDigest::new(DigestAlgorithm::Sha256, sha256(&bytes[committed_len..]));
            return Ok(RepairDoctorReport {
                committed_len: committed_len as u64,
                last_root: ContentDigest::new(DigestAlgorithm::Sha256, previous_root),
                records_count,
                incomplete_tail: None,
                foreign_range: Some(ForeignRange::new(
                    committed_len as u64,
                    foreign_len,
                    foreign_digest,
                )),
            });
        }

        if bytes[read_offset..read_offset + 8] != COMMIT_MAGIC {
            let foreign_len = (bytes.len() - committed_len) as u64;
            let foreign_digest =
                ContentDigest::new(DigestAlgorithm::Sha256, sha256(&bytes[committed_len..]));
            return Ok(RepairDoctorReport {
                committed_len: committed_len as u64,
                last_root: ContentDigest::new(DigestAlgorithm::Sha256, previous_root),
                records_count,
                incomplete_tail: None,
                foreign_range: Some(ForeignRange::new(
                    committed_len as u64,
                    foreign_len,
                    foreign_digest,
                )),
            });
        }
        read_offset += 8;

        let mut committed_root = [0_u8; 32];
        committed_root.copy_from_slice(&bytes[read_offset..read_offset + 32]);
        read_offset += 32;

        let expected_root = record_root(
            sequence,
            kind,
            payload_len,
            previous_root,
            named_payload_digest,
        );
        if committed_root != expected_root {
            let foreign_len = (bytes.len() - committed_len) as u64;
            let foreign_digest =
                ContentDigest::new(DigestAlgorithm::Sha256, sha256(&bytes[committed_len..]));
            return Ok(RepairDoctorReport {
                committed_len: committed_len as u64,
                last_root: ContentDigest::new(DigestAlgorithm::Sha256, previous_root),
                records_count,
                incomplete_tail: None,
                foreign_range: Some(ForeignRange::new(
                    committed_len as u64,
                    foreign_len,
                    foreign_digest,
                )),
            });
        }

        offset = read_offset;
        committed_len = offset;
        previous_root = committed_root;
        records_count += 1;
        expected_sequence = match expected_sequence.checked_add(1) {
            Some(seq) => seq,
            None => return Err(RepairError::SequenceExhausted),
        };
    }

    Ok(RepairDoctorReport {
        committed_len: committed_len as u64,
        last_root: ContentDigest::new(DigestAlgorithm::Sha256, previous_root),
        records_count,
        incomplete_tail: None,
        foreign_range: None,
    })
}

/// Reads a journal file at `path` and produces a [`RepairDoctorReport`].
pub fn doctor_path(path: impl AsRef<Path>) -> Result<RepairDoctorReport, RepairError> {
    let bytes = fs::read(path.as_ref())?;
    doctor(&bytes)
}

fn compute_plan_seal(
    journal_path: &Path,
    committed_len: u64,
    last_root: ContentDigest,
    foreign_range: &ForeignRange,
    cut_offset: u64,
) -> ContentDigest {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PLAN_SEAL_DOMAIN);
    let path_str = journal_path.to_string_lossy();
    bytes.extend_from_slice(&(path_str.len() as u64).to_be_bytes());
    bytes.extend_from_slice(path_str.as_bytes());
    bytes.extend_from_slice(&committed_len.to_be_bytes());
    bytes.extend_from_slice(&last_root.bytes());
    bytes.extend_from_slice(&foreign_range.offset.to_be_bytes());
    bytes.extend_from_slice(&foreign_range.length.to_be_bytes());
    bytes.extend_from_slice(&foreign_range.digest.bytes());
    bytes.extend_from_slice(&cut_offset.to_be_bytes());
    ContentDigest::new(DigestAlgorithm::Sha256, sha256(&bytes))
}

/// Immutable, sealed plan binding journal identity, committed prefix, foreign range, and seal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedRepairPlan {
    pub(crate) journal_path: PathBuf,
    pub(crate) committed_len: u64,
    pub(crate) last_root: ContentDigest,
    pub(crate) foreign_range: ForeignRange,
    pub(crate) cut_offset: u64,
    pub(crate) seal: ContentDigest,
}

impl SealedRepairPlan {
    /// Creates a sealed repair plan with default cut at `committed_len`.
    pub fn create(
        journal_path: impl AsRef<Path>,
        report: &RepairDoctorReport,
    ) -> Result<Self, RepairError> {
        Self::create_with_cut(journal_path, report, report.committed_len)
    }

    /// Creates a sealed repair plan with an explicit cut offset.
    ///
    /// Refuses any cut offset before `report.committed_len()`.
    pub fn create_with_cut(
        journal_path: impl AsRef<Path>,
        report: &RepairDoctorReport,
        cut_offset: u64,
    ) -> Result<Self, RepairError> {
        let foreign_range = report
            .foreign_range()
            .cloned()
            .ok_or(RepairError::NoForeignBytes)?;

        if cut_offset < report.committed_len {
            return Err(RepairError::CutBeforeCommittedLen {
                cut: cut_offset,
                committed_len: report.committed_len,
            });
        }

        let journal_path = journal_path.as_ref().to_path_buf();
        let seal = compute_plan_seal(
            &journal_path,
            report.committed_len,
            report.last_root,
            &foreign_range,
            cut_offset,
        );

        Ok(Self {
            journal_path,
            committed_len: report.committed_len,
            last_root: report.last_root,
            foreign_range,
            cut_offset,
            seal,
        })
    }

    /// Verifies that the internal seal and invariants are intact.
    pub fn verify_seal(&self) -> Result<(), RepairError> {
        let expected = compute_plan_seal(
            &self.journal_path,
            self.committed_len,
            self.last_root,
            &self.foreign_range,
            self.cut_offset,
        );
        if self.seal != expected {
            return Err(RepairError::InvalidSeal {
                expected,
                actual: self.seal,
            });
        }
        if self.cut_offset < self.committed_len {
            return Err(RepairError::CutBeforeCommittedLen {
                cut: self.cut_offset,
                committed_len: self.committed_len,
            });
        }
        Ok(())
    }

    /// Bound path to the journal file.
    #[must_use]
    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    /// Bound committed prefix length.
    #[must_use]
    pub const fn committed_len(&self) -> u64 {
        self.committed_len
    }

    /// Bound committed root digest.
    #[must_use]
    pub const fn last_root(&self) -> ContentDigest {
        self.last_root
    }

    /// Bound foreign range descriptor.
    #[must_use]
    pub const fn foreign_range(&self) -> &ForeignRange {
        &self.foreign_range
    }

    /// Bound foreign offset.
    #[must_use]
    pub const fn foreign_offset(&self) -> u64 {
        self.foreign_range.offset
    }

    /// Bound foreign byte length.
    #[must_use]
    pub const fn foreign_length(&self) -> u64 {
        self.foreign_range.length
    }

    /// Bound foreign byte digest.
    #[must_use]
    pub const fn foreign_digest(&self) -> ContentDigest {
        self.foreign_range.digest
    }

    /// Planned cut offset (where file will be truncated).
    #[must_use]
    pub const fn cut_offset(&self) -> u64 {
        self.cut_offset
    }

    /// Cryptographic seal over the plan parameters.
    #[must_use]
    pub const fn seal(&self) -> ContentDigest {
        self.seal
    }

    /// Executes this sealed repair plan.
    pub fn apply(&self) -> Result<RepairReceipt, RepairError> {
        apply(self)
    }

    /// Overrides the seal for negative testing.
    #[doc(hidden)]
    #[must_use]
    pub const fn with_seal_for_test(mut self, seal: ContentDigest) -> Self {
        self.seal = seal;
        self
    }
}

/// Alias for [`SealedRepairPlan`].
pub type RepairPlan = SealedRepairPlan;

/// Creates a sealed repair plan binding journal identity, committed prefix, and foreign range.
pub fn plan(
    journal_path: impl AsRef<Path>,
    report: &RepairDoctorReport,
) -> Result<SealedRepairPlan, RepairError> {
    SealedRepairPlan::create(journal_path, report)
}

/// Creates a sealed repair plan with an explicit cut offset.
pub fn plan_with_cut(
    journal_path: impl AsRef<Path>,
    report: &RepairDoctorReport,
    cut_offset: u64,
) -> Result<SealedRepairPlan, RepairError> {
    SealedRepairPlan::create_with_cut(journal_path, report, cut_offset)
}

/// Computes the deterministic quarantine sidecar path for a journal and content digest.
#[must_use]
pub fn quarantine_path_for(journal_path: &Path, digest: ContentDigest) -> PathBuf {
    let parent = journal_path.parent().unwrap_or_else(|| Path::new("."));
    let mut hex = String::with_capacity(64);
    for byte in digest.bytes() {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    if parent.as_os_str().is_empty() {
        PathBuf::from(format!("{hex}.quarantine"))
    } else {
        parent.join(format!("{hex}.quarantine"))
    }
}

/// Typed receipt emitted upon applying a verified repair plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairReceipt {
    pub(crate) journal_path: PathBuf,
    pub(crate) committed_len: u64,
    pub(crate) last_root: ContentDigest,
    pub(crate) quarantined_offset: u64,
    pub(crate) quarantined_length: u64,
    pub(crate) quarantined_digest: ContentDigest,
    pub(crate) quarantine_path: PathBuf,
    pub(crate) truncated_to: u64,
    pub(crate) plan_seal: ContentDigest,
}

impl RepairReceipt {
    /// Path of the journal file that was repaired.
    #[must_use]
    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    /// Re-verified byte length of the committed journal prefix.
    #[must_use]
    pub const fn committed_len(&self) -> u64 {
        self.committed_len
    }

    /// Re-verified root of the committed journal prefix.
    #[must_use]
    pub const fn last_root(&self) -> ContentDigest {
        self.last_root
    }

    /// Byte offset where the quarantined foreign bytes began.
    #[must_use]
    pub const fn quarantined_offset(&self) -> u64 {
        self.quarantined_offset
    }

    /// Number of foreign bytes quarantined.
    #[must_use]
    pub const fn quarantined_length(&self) -> u64 {
        self.quarantined_length
    }

    /// SHA-256 digest of the quarantined foreign bytes for object-store import.
    #[must_use]
    pub const fn quarantined_digest(&self) -> ContentDigest {
        self.quarantined_digest
    }

    /// Path to the durable sidecar file retaining the quarantined foreign bytes.
    #[must_use]
    pub fn quarantine_path(&self) -> &Path {
        &self.quarantine_path
    }

    /// Byte length to which the journal was truncated.
    #[must_use]
    pub const fn truncated_to(&self) -> u64 {
        self.truncated_to
    }

    /// Cryptographic seal of the repair plan that was executed.
    #[must_use]
    pub const fn plan_seal(&self) -> ContentDigest {
        self.plan_seal
    }

    /// Alias for `quarantined_digest`.
    #[must_use]
    pub const fn foreign_digest(&self) -> ContentDigest {
        self.quarantined_digest
    }

    /// Alias for `quarantined_length`.
    #[must_use]
    pub const fn foreign_length(&self) -> u64 {
        self.quarantined_length
    }

    /// Alias for `quarantined_offset`.
    #[must_use]
    pub const fn foreign_offset(&self) -> u64 {
        self.quarantined_offset
    }
}

/// Applies a sealed repair plan: re-reads the file, re-verifies prefix and foreign digest,
/// quarantines foreign bytes to a sidecar file named by digest next to the journal, truncates,
/// and emits a typed receipt.
pub fn apply(plan: &SealedRepairPlan) -> Result<RepairReceipt, RepairError> {
    // 1. Verify seal and cut invariant
    plan.verify_seal()?;

    // 2. Open file for read + write
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&plan.journal_path)?;

    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;

    // 3. Re-verify committed prefix
    if (bytes.len() as u64) < plan.committed_len {
        return Err(RepairError::FileShorterThanCommittedLen {
            file_len: bytes.len() as u64,
            committed_len: plan.committed_len,
        });
    }

    let prefix_len =
        usize::try_from(plan.committed_len).map_err(|_| RepairError::LengthOverflow)?;
    let prefix = &bytes[..prefix_len];
    let prefix_report = recover_bytes(prefix)?;
    if prefix_report.committed_len() != plan.committed_len
        || prefix_report.last_root() != plan.last_root
        || prefix_report.incomplete_tail().is_some()
    {
        return Err(RepairError::CommittedPrefixMismatch {
            expected_len: plan.committed_len,
            expected_root: plan.last_root,
            actual_len: prefix_report.committed_len(),
            actual_root: prefix_report.last_root(),
        });
    }

    // 4. Re-verify foreign range and digest
    let foreign_start =
        usize::try_from(plan.foreign_range.offset).map_err(|_| RepairError::LengthOverflow)?;
    let foreign_len =
        usize::try_from(plan.foreign_range.length).map_err(|_| RepairError::LengthOverflow)?;
    let expected_end = foreign_start
        .checked_add(foreign_len)
        .ok_or(RepairError::LengthOverflow)?;

    if bytes.len() != expected_end {
        return Err(RepairError::FileLengthMismatch {
            expected: expected_end as u64,
            actual: bytes.len() as u64,
        });
    }

    let actual_foreign = &bytes[foreign_start..expected_end];
    let actual_digest = ContentDigest::new(DigestAlgorithm::Sha256, sha256(actual_foreign));

    if actual_digest != plan.foreign_range.digest {
        return Err(RepairError::PlanDigestMismatch {
            expected: plan.foreign_range.digest,
            actual: actual_digest,
        });
    }

    // 5. Quarantine foreign bytes to sidecar file named by digest next to the journal
    let quarantine_path = quarantine_path_for(&plan.journal_path, actual_digest);
    let tmp_quarantine_path = quarantine_path.with_extension("tmp");
    {
        let mut qfile = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_quarantine_path)?;
        qfile.write_all(actual_foreign)?;
        qfile.sync_all()?;
    }
    fs::rename(&tmp_quarantine_path, &quarantine_path)?;

    // 6. Truncate journal file
    file.set_len(plan.cut_offset)?;
    file.sync_all()?;

    // 7. Emit typed receipt
    Ok(RepairReceipt {
        journal_path: plan.journal_path.clone(),
        committed_len: plan.committed_len,
        last_root: plan.last_root,
        quarantined_offset: plan.foreign_range.offset,
        quarantined_length: plan.foreign_range.length,
        quarantined_digest: actual_digest,
        quarantine_path,
        truncated_to: plan.cut_offset,
        plan_seal: plan.seal,
    })
}

/// Errors occurring during doctor inspection, repair planning, or repair application.
#[derive(Debug)]
pub enum RepairError {
    /// Filesystem I/O error.
    Io(io::Error),
    /// Underlying journal error while recovering committed prefix.
    Journal(JournalError),
    /// No foreign trailing bytes were detected; nothing to repair.
    NoForeignBytes,
    /// Cut offset was before committed length; cutting into committed history is refused.
    CutBeforeCommittedLen {
        /// Attempted cut offset.
        cut: u64,
        /// Minimum safe committed length.
        committed_len: u64,
    },
    /// Sealed repair plan cryptographic seal is invalid or was tampered with.
    InvalidSeal {
        /// Expected seal digest.
        expected: ContentDigest,
        /// Actual seal digest found on plan.
        actual: ContentDigest,
    },
    /// Actual file length does not match expected foreign range.
    FileLengthMismatch {
        /// Expected total length (foreign offset + length).
        expected: u64,
        /// Actual file length observed.
        actual: u64,
    },
    /// File is shorter than the committed prefix.
    FileShorterThanCommittedLen {
        /// Actual file length observed.
        file_len: u64,
        /// Expected committed prefix length.
        committed_len: u64,
    },
    /// Committed prefix on disk does not match the plan's committed length or root.
    CommittedPrefixMismatch {
        /// Expected committed length in plan.
        expected_len: u64,
        /// Expected root in plan.
        expected_root: ContentDigest,
        /// Actual recovered committed length.
        actual_len: u64,
        /// Actual recovered root.
        actual_root: ContentDigest,
    },
    /// Actual foreign bytes digest at apply time does not match the plan's digest.
    PlanDigestMismatch {
        /// Expected foreign digest in plan.
        expected: ContentDigest,
        /// Actual foreign digest computed from file bytes.
        actual: ContentDigest,
    },
    /// Sequence space exhausted during inspection.
    SequenceExhausted,
    /// Length calculation overflowed 64 bits.
    LengthOverflow,
}

impl fmt::Display for RepairError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "repair I/O error: {error}"),
            Self::Journal(error) => write!(formatter, "repair journal error: {error}"),
            Self::NoForeignBytes => formatter.write_str("no foreign trailing bytes to repair"),
            Self::CutBeforeCommittedLen { cut, committed_len } => write!(
                formatter,
                "repair plan cut offset {cut} precedes committed length {committed_len}"
            ),
            Self::InvalidSeal { expected, actual } => write!(
                formatter,
                "repair plan seal mismatch: expected {expected}, got {actual}"
            ),
            Self::FileLengthMismatch { expected, actual } => write!(
                formatter,
                "repair file length mismatch: expected {expected}, got {actual}"
            ),
            Self::FileShorterThanCommittedLen {
                file_len,
                committed_len,
            } => write!(
                formatter,
                "file length {file_len} is shorter than committed prefix {committed_len}"
            ),
            Self::CommittedPrefixMismatch {
                expected_len,
                expected_root,
                actual_len,
                actual_root,
            } => write!(
                formatter,
                "committed prefix mismatch: expected ({expected_len}, {expected_root}), got ({actual_len}, {actual_root})"
            ),
            Self::PlanDigestMismatch { expected, actual } => write!(
                formatter,
                "foreign trailing bytes digest mismatch at apply: expected {expected}, got {actual}"
            ),
            Self::SequenceExhausted => formatter.write_str("journal sequence space exhausted"),
            Self::LengthOverflow => {
                formatter.write_str("repair length overflowed addressable bounds")
            }
        }
    }
}

impl Error for RepairError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Journal(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for RepairError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<JournalError> for RepairError {
    fn from(value: JournalError) -> Self {
        Self::Journal(value)
    }
}
