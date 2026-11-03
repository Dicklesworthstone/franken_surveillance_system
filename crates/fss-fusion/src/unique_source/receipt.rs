#![forbid(unsafe_code)]
//! Bounded immutable receipts for the explicit source-once profile.

use std::collections::BTreeMap;

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::{EProcessStepInput, EProcessStepOutcome};

use super::{SeenSource, UNIQUE_SOURCE_INVENTORY_DOMAIN, UNIQUE_SOURCE_STEP_DOMAIN};

/// How one original evidence alias was handled by this accepted transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceDisposition {
    /// First numeric admission of this canonical declared source.
    Admitted,
    /// Already consumed earlier or through another alias in this exact step; contributes zero.
    AlreadyAdmitted,
    /// Not an observed calibrated row; remains explicit and neutral without consuming capacity.
    NonNumeric,
}

/// Immutable accounting for every original evidence ID, including aliases removed from fusion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceAdmission {
    evidence_id: String,
    source_digest: Option<ContentDigest>,
    item_digest: ContentDigest,
    disposition: SourceDisposition,
    first_admitted_step: Option<u64>,
}

impl SourceAdmission {
    pub(super) fn new(
        evidence_id: String,
        source_digest: Option<ContentDigest>,
        item_digest: ContentDigest,
        disposition: SourceDisposition,
        first_admitted_step: Option<u64>,
    ) -> Self {
        Self {
            evidence_id,
            source_digest,
            item_digest,
            disposition,
            first_admitted_step,
        }
    }

    /// Exact original evidence alias; not a second source identity.
    #[must_use]
    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    /// Optional canonical declared source. Nonnumeric rows may explicitly have no source key.
    /// A laboratory marker never creates another identity.
    #[must_use]
    pub const fn source_digest(&self) -> Option<ContentDigest> {
        self.source_digest
    }

    /// Complete per-item source semantics excluding its alias, including event kind.
    #[must_use]
    pub const fn item_digest(&self) -> ContentDigest {
        self.item_digest
    }

    /// Whether this row added a numeric source, replayed one, or remained nonnumeric.
    #[must_use]
    pub const fn disposition(&self) -> SourceDisposition {
        self.disposition
    }

    /// Original numerical step index of admission; absent only for nonnumeric evidence.
    #[must_use]
    pub const fn first_admitted_step(&self) -> Option<u64> {
        self.first_admitted_step
    }
}

/// Immutable source-once transition, retaining the original numerical/transcript owner unchanged.
///
/// Replay the same ordered original queries, bindings and resets to verify identity. This
/// receipt binds declared keys and processing; it proves neither custody nor independent errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniqueSourceStepOutcome {
    previous: Option<ContentDigest>,
    submitted_query_digest: Option<ContentDigest>,
    source_limit: usize,
    sources_seen: usize,
    inventory_digest: ContentDigest,
    admissions: Vec<SourceAdmission>,
    step: EProcessStepOutcome,
    digest: ContentDigest,
}

pub(super) fn inventory_digest(
    source_limit: usize,
    seen: &BTreeMap<ContentDigest, SeenSource>,
) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(UNIQUE_SOURCE_INVENTORY_DOMAIN);
    encoder.u32(source_limit as u32);
    encoder.u32(seen.len() as u32);
    let mut digest = ContentDigest::sha256(&encoder.finish());
    for (source, entry) in seen {
        let mut encoder = CanonicalEncoder::new();
        encoder.digest(digest);
        encoder.digest(*source);
        encoder.digest(entry.item_digest);
        encoder.u64(entry.first_step);
        digest = ContentDigest::sha256(&encoder.finish());
    }
    digest
}

impl UniqueSourceStepOutcome {
    pub(super) fn seal(
        previous: Option<ContentDigest>,
        submitted_query_digest: Option<ContentDigest>,
        source_limit: usize,
        seen: &BTreeMap<ContentDigest, SeenSource>,
        admissions: Vec<SourceAdmission>,
        step: EProcessStepOutcome,
    ) -> Self {
        let inventory_digest = inventory_digest(source_limit, seen);
        let mut encoder = CanonicalEncoder::new();
        encoder.text(UNIQUE_SOURCE_STEP_DOMAIN);
        match previous {
            Some(previous) => {
                encoder.bool(true);
                encoder.digest(previous);
            }
            None => encoder.bool(false),
        }
        encoder.u32(source_limit as u32);
        encoder.u32(seen.len() as u32);
        encoder.digest(inventory_digest);
        match submitted_query_digest {
            Some(query) => {
                encoder.bool(true);
                encoder.digest(query);
            }
            None => encoder.bool(false),
        }
        encoder.u64(admissions.len() as u64);
        // At most MAX_EVIDENCE rows, with only fixed-size fields in the receipt encoder.
        for admission in &admissions {
            encoder.digest(ContentDigest::sha256(admission.evidence_id.as_bytes()));
            match admission.source_digest {
                Some(source) => {
                    encoder.bool(true);
                    encoder.digest(source);
                }
                None => encoder.bool(false),
            }
            encoder.digest(admission.item_digest);
            encoder.tag(match admission.disposition {
                SourceDisposition::Admitted => 0,
                SourceDisposition::AlreadyAdmitted => 1,
                SourceDisposition::NonNumeric => 2,
            });
            match admission.first_admitted_step {
                Some(index) => {
                    encoder.bool(true);
                    encoder.u64(index);
                }
                None => encoder.bool(false),
            }
        }
        // Independently bounded inner state binds hypothesis/configuration and all numbers;
        // the inner transcript also binds the effective query/decision or exact reset reason.
        encoder.digest(step.transcript.digest());
        let digest = ContentDigest::sha256(&encoder.finish());
        Self {
            previous,
            submitted_query_digest,
            source_limit,
            sources_seen: seen.len(),
            inventory_digest,
            admissions,
            step,
            digest,
        }
    }

    /// Previous accepted profile receipt, including numerical resets.
    #[must_use]
    pub const fn previous(&self) -> Option<ContentDigest> {
        self.previous
    }

    /// Original complete validated query before replay filtering; absent for resets.
    #[must_use]
    pub const fn submitted_query_digest(&self) -> Option<ContentDigest> {
        self.submitted_query_digest
    }

    /// Exact effective query actually fused after accounting for all declared-source replays.
    #[must_use]
    pub const fn effective_query_digest(&self) -> Option<ContentDigest> {
        match self.step.transcript.input() {
            EProcessStepInput::Observation { query_digest, .. } => Some(query_digest),
            EProcessStepInput::RegimeReset { .. } => None,
        }
    }

    /// Nonrefillable source allowance selected when this process was created.
    #[must_use]
    pub const fn source_limit(&self) -> usize {
        self.source_limit
    }

    /// Complete number of consumed numeric sources, including past regimes.
    #[must_use]
    pub const fn sources_seen(&self) -> usize {
        self.sources_seen
    }

    /// Canonical complete lifetime source inventory after this transition.
    #[must_use]
    pub const fn inventory_digest(&self) -> ContentDigest {
        self.inventory_digest
    }

    /// Complete original evidence inventory in canonical alias order, including all replays.
    #[must_use]
    pub fn admissions(&self) -> &[SourceAdmission] {
        &self.admissions
    }

    /// Existing numerical result and independently bounded fusion transcript.
    #[must_use]
    pub const fn step(&self) -> &EProcessStepOutcome {
        &self.step
    }

    /// Profile identity over original input, accounting, lifetime inventory and inner transition.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
}
