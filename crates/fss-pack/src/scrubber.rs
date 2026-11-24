#![forbid(unsafe_code)]
//! Rate-limited incremental background doctor scrubber for sealed packfiles
//! (`COMPREHENSIVE_PLAN §13.9`).
//!
//! Verifies bounded byte, object, and pack budgets per pass across immutable sealed packfiles
//! (checking `FSSF`..`FSSE` footer framing, `FSSP` record magic/headers, Castagnoli CRC32C,
//! per-object SHA-256 content digests, and whole-pack footer SHA-256) while maintaining a
//! deterministic cursor across passes and emitting canonical digest-bound [`PackScrubReport`]s
//! aligned with `DoctorScrubReceipt` semantics.

mod report;

use std::collections::BTreeSet;
use std::fs::File;

use fss_core::{ContentDigest, RegionTree, TimestampNs};
use fss_runtime::authority::AuthorityCx;

use crate::error::PackError;
use crate::format::{
    PACK_RECORD_HEADER_LEN, PACK_RECORD_OVERHEAD_LEN, PackId, decode_record_header,
    read_exact_at_bounded, verify_record_slice,
};
use crate::packfile::{read_sealed_footer_from_file, verify_sealed_pack};
use crate::store::PackStore;

use report::finalize_report;
pub use report::{PackScrubReport, ScrubFailureKind, ScrubFinding, ScrubVerdict};

/// Canonical digest domain for [`PackScrubReport::report_digest`].
pub const PACK_SCRUB_REPORT_DOMAIN: &str = "fss.pack.scrub_report.v1";
/// Maximum verified fraction in parts per million (`100% = 1_000_000`).
pub const MAX_VERIFIED_FRACTION_PPM: u32 = 1_000_000;

/// Per-pass resource ceilings bounding I/O and CPU consumption during incremental scrubbing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScrubBudget {
    /// Maximum framed object bytes to read and hash during one scrub pass.
    pub max_bytes: u64,
    /// Maximum sealed packfiles to inspect during one scrub pass.
    pub max_packs: usize,
    /// Maximum individual objects to verify during one scrub pass.
    pub max_objects: u64,
}

impl Default for ScrubBudget {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            max_packs: 8,
            max_objects: 4_096,
        }
    }
}

impl ScrubBudget {
    /// Validates that every budget dimension permits bounded forward progress.
    pub fn validate(self) -> Result<Self, PackError> {
        if self.max_bytes == 0 || self.max_packs == 0 || self.max_objects == 0 {
            return Err(PackError::InvalidConfig {
                detail: "ScrubBudget max_bytes, max_packs, and max_objects must all be >= 1"
                    .to_owned(),
            });
        }
        Ok(self)
    }
}

/// Deterministic resume position maintained across incremental scrub passes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScrubCursor {
    /// Next sealed packfile to inspect, or `None` when positioned at the start of a new sweep.
    pub next_pack_id: Option<PackId>,
    /// Next footer entry index within `next_pack_id`.
    pub next_entry_index: usize,
    /// Completed full-corpus sweep counter.
    pub completed_cycles: u64,
    /// Sealed packs fully verified so far in the active sweep cycle.
    pub cycle_verified_packs: u64,
    /// Objects verified so far in the active sweep cycle.
    pub cycle_verified_objects: u64,
    /// Bytes verified so far in the active sweep cycle.
    pub cycle_verified_bytes: u64,
}

/// Deterministic, rate-limited incremental background doctor scrubber over sealed packfiles.
#[derive(Clone, Debug, Default)]
pub struct BackgroundScrubber {
    cursor: ScrubCursor,
}

impl BackgroundScrubber {
    /// Creates a new [`BackgroundScrubber`] positioned at the beginning of cycle 1.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current deterministic scrub cursor.
    #[must_use]
    pub const fn cursor(&self) -> ScrubCursor {
        self.cursor
    }

    /// Resets the cursor back to the first sealed packfile without changing `completed_cycles`.
    pub fn reset_cycle(&mut self) {
        self.cursor.next_pack_id = None;
        self.cursor.next_entry_index = 0;
        self.cursor.cycle_verified_packs = 0;
        self.cursor.cycle_verified_objects = 0;
        self.cursor.cycle_verified_bytes = 0;
    }

    /// Executes one bounded scrub pass after checking caller [`AuthorityCx`] cancellation.
    pub fn scrub_pass_with_authority(
        &mut self,
        store: &PackStore,
        cx: &AuthorityCx,
        tree: &RegionTree,
        budget: ScrubBudget,
        now_ns: TimestampNs,
    ) -> Result<PackScrubReport, PackError> {
        if cx.is_cancel_requested(tree)? {
            return Err(PackError::Cancelled);
        }
        self.scrub_pass(store, budget, now_ns)
    }

    /// Executes one rate-limited incremental scrub pass across sealed packfiles under `budget`.
    pub fn scrub_pass(
        &mut self,
        store: &PackStore,
        budget: ScrubBudget,
        now_ns: TimestampNs,
    ) -> Result<PackScrubReport, PackError> {
        let budget = budget.validate()?;
        let _epoch_guard = store.pin_reader_epoch()?;

        let sealed_packs = store.sealed_pack_ids()?;
        let total_sealed_packs = sealed_packs.len() as u64;
        let cycle_number = self.cursor.completed_cycles.saturating_add(1);

        if sealed_packs.is_empty() {
            self.reset_cycle();
            return finalize_report(
                now_ns,
                cycle_number,
                false,
                0,
                0,
                0,
                0,
                0,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                ScrubVerdict::Degraded,
            );
        }

        let start_pos = match self.cursor.next_pack_id {
            Some(target) => match sealed_packs.binary_search(&target) {
                Ok(pos) => pos,
                Err(insert_pos) => {
                    self.cursor.next_entry_index = 0;
                    if insert_pos >= sealed_packs.len() {
                        0
                    } else {
                        insert_pos
                    }
                }
            },
            None => {
                self.cursor.next_entry_index = 0;
                0
            }
        };

        let mut pass_packs_touched = 0_usize;
        let mut pass_verified_packs = 0_u64;
        let mut pass_verified_objects = 0_u64;
        let mut pass_verified_bytes = 0_u64;
        let mut findings: Vec<ScrubFinding> = Vec::new();
        let mut corrupt_set: BTreeSet<ContentDigest> = BTreeSet::new();
        let mut missing_set: BTreeSet<PackId> = BTreeSet::new();
        let mut paused_mid_cycle = false;
        let mut budget_clamped = false;

        let packs_dir = store.packs_dir();
        let mut idx = start_pos;
        while idx < sealed_packs.len() {
            if pass_packs_touched >= budget.max_packs || pass_verified_objects >= budget.max_objects
            {
                self.cursor.next_pack_id = Some(sealed_packs[idx]);
                paused_mid_cycle = true;
                break;
            }

            let pack_id = sealed_packs[idx];
            let pack_path = packs_dir.join(pack_id.file_name());
            pass_packs_touched += 1;

            let file = match File::open(&pack_path) {
                Ok(f) => f,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    missing_set.insert(pack_id);
                    findings.push(ScrubFinding {
                        pack_id,
                        digest: None,
                        offset: 0,
                        kind: ScrubFailureKind::MissingPackFile,
                        detail: format!("sealed packfile {} missing on disk", pack_id.file_name()),
                    });
                    self.cursor.next_entry_index = 0;
                    idx += 1;
                    continue;
                }
                Err(err) => {
                    findings.push(ScrubFinding {
                        pack_id,
                        digest: None,
                        offset: 0,
                        kind: ScrubFailureKind::IoError,
                        detail: format!("failed to open sealed pack {pack_id}: {err}"),
                    });
                    self.cursor.next_entry_index = 0;
                    idx += 1;
                    continue;
                }
            };

            let file_len = match file.metadata() {
                Ok(m) => m.len(),
                Err(err) => {
                    findings.push(ScrubFinding {
                        pack_id,
                        digest: None,
                        offset: 0,
                        kind: ScrubFailureKind::IoError,
                        detail: format!("failed to stat sealed pack {pack_id}: {err}"),
                    });
                    self.cursor.next_entry_index = 0;
                    idx += 1;
                    continue;
                }
            };

            let footer = match read_sealed_footer_from_file(&file, pack_id, file_len) {
                Ok(f) => f,
                Err(err) => {
                    findings.push(ScrubFinding {
                        pack_id,
                        digest: None,
                        offset: 0,
                        kind: ScrubFailureKind::CorruptFooter,
                        detail: err.to_string(),
                    });
                    self.cursor.next_entry_index = 0;
                    idx += 1;
                    continue;
                }
            };

            let mut entry_idx = self.cursor.next_entry_index.min(footer.entries.len());
            let mut pack_paused = false;
            let mut pack_had_defect = false;

            while entry_idx < footer.entries.len() {
                let entry = footer.entries[entry_idx];
                let rec_len_u64 = entry
                    .len
                    .checked_add(PACK_RECORD_OVERHEAD_LEN as u64)
                    .ok_or(PackError::ArithmeticOverflow)?;
                if pass_verified_objects >= budget.max_objects {
                    pack_paused = true;
                    break;
                }
                if pass_verified_bytes.saturating_add(rec_len_u64) > budget.max_bytes {
                    if pass_verified_objects == 0 && rec_len_u64 > budget.max_bytes {
                        budget_clamped = true;
                    }
                    pack_paused = true;
                    break;
                }

                let rec_len =
                    usize::try_from(rec_len_u64).map_err(|_| PackError::ArithmeticOverflow)?;
                let mut buf = vec![0_u8; rec_len];
                let expected_digest = entry.digest();

                if let Err(err) = read_exact_at_bounded(&file, entry.offset, &mut buf) {
                    pack_had_defect = true;
                    corrupt_set.insert(expected_digest);
                    findings.push(ScrubFinding {
                        pack_id,
                        digest: Some(expected_digest),
                        offset: entry.offset,
                        kind: ScrubFailureKind::IoError,
                        detail: err.to_string(),
                    });
                } else if let Err(err) = decode_record_header(
                    pack_id,
                    entry.offset,
                    buf[..PACK_RECORD_HEADER_LEN]
                        .try_into()
                        .map_err(|_| PackError::ArithmeticOverflow)?,
                ) {
                    pack_had_defect = true;
                    corrupt_set.insert(expected_digest);
                    findings.push(ScrubFinding {
                        pack_id,
                        digest: Some(expected_digest),
                        offset: entry.offset,
                        kind: ScrubFailureKind::InvalidRecordHeader,
                        detail: err.to_string(),
                    });
                } else if let Err(err) =
                    verify_record_slice(pack_id, entry.offset, &buf, Some(expected_digest))
                {
                    pack_had_defect = true;
                    corrupt_set.insert(expected_digest);
                    let kind = match err {
                        PackError::CrcMismatch { .. } => ScrubFailureKind::CrcMismatch,
                        PackError::DigestMismatch { .. } => ScrubFailureKind::ObjectDigestMismatch,
                        _ => ScrubFailureKind::InvalidRecordHeader,
                    };
                    findings.push(ScrubFinding {
                        pack_id,
                        digest: Some(expected_digest),
                        offset: entry.offset,
                        kind,
                        detail: err.to_string(),
                    });
                } else {
                    pass_verified_objects = pass_verified_objects.saturating_add(1);
                    pass_verified_bytes = pass_verified_bytes.saturating_add(rec_len_u64);
                    self.cursor.cycle_verified_objects =
                        self.cursor.cycle_verified_objects.saturating_add(1);
                    self.cursor.cycle_verified_bytes =
                        self.cursor.cycle_verified_bytes.saturating_add(rec_len_u64);
                }

                entry_idx += 1;
            }

            if pack_paused {
                self.cursor.next_pack_id = Some(pack_id);
                self.cursor.next_entry_index = entry_idx;
                paused_mid_cycle = true;
                break;
            }

            // All objects in this pack scanned: also verify whole-pack footer SHA-256.
            if let Err(err) = verify_sealed_pack(packs_dir, pack_id) {
                pack_had_defect = true;
                let kind = match err {
                    PackError::DigestMismatch { .. } => ScrubFailureKind::WholePackDigestMismatch,
                    _ => ScrubFailureKind::CorruptFooter,
                };
                findings.push(ScrubFinding {
                    pack_id,
                    digest: None,
                    offset: footer.footer_offset,
                    kind,
                    detail: err.to_string(),
                });
            }

            if !pack_had_defect {
                pass_verified_packs = pass_verified_packs.saturating_add(1);
                self.cursor.cycle_verified_packs =
                    self.cursor.cycle_verified_packs.saturating_add(1);
            }

            self.cursor.next_entry_index = 0;
            idx += 1;
        }

        let cycle_completed = !paused_mid_cycle && idx >= sealed_packs.len();
        let verified_fraction_ppm = if total_sealed_packs == 0 {
            0
        } else {
            let raw = (u128::from(self.cursor.cycle_verified_packs) * 1_000_000)
                / u128::from(total_sealed_packs);
            u32::try_from(raw.min(u128::from(MAX_VERIFIED_FRACTION_PPM)))
                .unwrap_or(MAX_VERIFIED_FRACTION_PPM)
        };

        if cycle_completed {
            self.cursor.completed_cycles = self.cursor.completed_cycles.saturating_add(1);
            self.reset_cycle();
        }

        let verdict = if !findings.is_empty() {
            ScrubVerdict::Failed
        } else if cycle_completed
            && !budget_clamped
            && verified_fraction_ppm == MAX_VERIFIED_FRACTION_PPM
        {
            ScrubVerdict::Clean
        } else {
            ScrubVerdict::Degraded
        };

        finalize_report(
            now_ns,
            cycle_number,
            cycle_completed,
            pass_verified_packs,
            pass_verified_objects,
            pass_verified_bytes,
            total_sealed_packs,
            verified_fraction_ppm,
            corrupt_set.into_iter().collect(),
            missing_set.into_iter().collect(),
            findings,
            verdict,
        )
    }
}
