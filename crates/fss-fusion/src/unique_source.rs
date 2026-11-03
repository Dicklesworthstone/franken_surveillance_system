#![forbid(unsafe_code)]
//! Explicit bounded source-once accumulation alongside the historical window accumulator.
//!
//! Source keys are caller declarations. This profile prevents a declared source from adding a
//! second signed likelihood increment, including through a new observation alias or after a
//! numerical reset. It does not establish physical source identity, custody, temporal independence
//! or a test-supermartingale assumption. A caller that supplies a new key has declared a new source.

use std::collections::BTreeMap;
use std::fmt;

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::{
    Calibration, EProcessConfig, EvidenceItem, FusionError, FusionOutcome, FusionQuery,
    Observability, RegimeResetReason, SequentialEProcess,
};

mod receipt;
pub use receipt::{SourceAdmission, SourceDisposition, UniqueSourceStepOutcome};

pub mod checkpoint;
pub use checkpoint::{
    MAX_UNIQUE_SOURCE_CHECKPOINT_BYTES, UNIQUE_SOURCE_CHECKPOINT_MAGIC,
    UNIQUE_SOURCE_CHECKPOINT_VERSION, UniqueSourceCheckpoint, UniqueSourceCheckpointError,
};

/// Explicit profile receipt domain; historical e-process domains remain unchanged.
pub const UNIQUE_SOURCE_STEP_DOMAIN: &str = "fss.fusion.unique_source_step.v1";
/// Complete per-item source semantics excluding only its observation alias, plus event kind.
pub const UNIQUE_SOURCE_ITEM_DOMAIN: &str = "fss.fusion.unique_source_item.v1";
/// Complete bounded lifetime inventory of admitted canonical source keys.
pub const UNIQUE_SOURCE_INVENTORY_DOMAIN: &str = "fss.fusion.unique_source_inventory.v1";
/// JSON interchange schema, distinct from the canonical digest domain.
pub const UNIQUE_SOURCE_STEP_SCHEMA: &str = "fss.fusion_unique_source_step.v1";
/// Hard ceiling on remembered lifetime numeric sources; callers may select a smaller limit.
pub const MAX_UNIQUE_SOURCES: usize = 4_096;

/// Typed refusal from the explicit source-once profile. Every refusal leaves all state unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UniqueSourceError {
    /// Invalid hypothesis, query or numerical configuration from the original fusion owner.
    Fusion(FusionError),
    /// The bindings do not name exactly every original evidence ID once.
    InvalidBindings,
    /// One declared source changed its immutable semantics, including within one submitted step.
    ConflictingSource {
        /// Canonical algorithm and digest bytes; a noncanonical laboratory marker is not a key.
        source: ContentDigest,
    },
    /// Admitting the complete step would exceed the nonrefillable lifetime source allowance.
    SourceCapacity {
        /// Configured lifetime limit.
        limit: usize,
        /// Sources already admitted, including earlier regimes.
        existing: usize,
        /// New distinct numeric sources in the submitted step.
        additional: usize,
    },
}

impl UniqueSourceError {
    /// Registered stable refusal identity.
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::Fusion(error) => error.stable_id(),
            Self::InvalidBindings => "ERR-FUSION-SOURCE-BINDING-INVALID-001",
            Self::ConflictingSource { .. } => "ERR-FUSION-SOURCE-CONFLICT-001",
            Self::SourceCapacity { .. } => "ERR-FUSION-SOURCE-CAPACITY-001",
        }
    }
}

impl fmt::Display for UniqueSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fusion(error) => error.fmt(f),
            Self::InvalidBindings => {
                f.write_str("source bindings must match every evidence ID exactly")
            }
            Self::ConflictingSource { source } => {
                write!(
                    f,
                    "declared source {source} has conflicting immutable semantics"
                )
            }
            Self::SourceCapacity {
                limit,
                existing,
                additional,
            } => write!(
                f,
                "source allowance {limit} cannot admit {additional} new sources after {existing}"
            ),
        }
    }
}

impl std::error::Error for UniqueSourceError {}

impl From<FusionError> for UniqueSourceError {
    fn from(value: FusionError) -> Self {
        Self::Fusion(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SeenSource {
    item_digest: ContentDigest,
    first_step: u64,
}

fn canonical_source(source: ContentDigest) -> ContentDigest {
    // ContentDigest's laboratory marker is not encoded in canonical bytes or text. It must
    // never create an extra source slot. Provenance admission belongs to the caller's owner.
    ContentDigest::new(source.algorithm(), source.bytes())
}

fn item_digest(query: &FusionQuery, item: &EvidenceItem) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(UNIQUE_SOURCE_ITEM_DOMAIN);
    encoder.text(&query.kind);
    encoder.text(&item.sensor);
    encoder.u64(item.failure_domains.len() as u64);
    for domain in &item.failure_domains {
        encoder.text(domain);
    }
    match &item.calibration {
        Calibration::Calibrated { generation, llr } => {
            encoder.tag(0);
            encoder.text(generation);
            llr.encode(&mut encoder);
        }
        Calibration::Uncalibrated { reason } => {
            encoder.tag(1);
            encoder.text(reason);
        }
    }
    match &item.observability {
        Observability::Observed => encoder.tag(0),
        Observability::NotObservable { reason } => {
            encoder.tag(1);
            encoder.text(reason);
        }
        Observability::Redacted => encoder.tag(2),
        Observability::Stale => encoder.tag(3),
    }
    // Query-level coverage may change because of another camera; both submitted/effective query
    // receipts bind it, while this source's own observability remains an immutable item field.
    // Complete original query validation has already bounded every text and domain inventory.
    ContentDigest::sha256(&encoder.finish())
}

/// A bounded source-once profile around the unchanged numerical sequential accumulator.
///
/// The complete original query and one binding per evidence ID are validated before filtering.
/// Every calibrated, observed source is consumed once, whether its interval supports, refutes or
/// is zero. Identical source aliases/retries remain explicit in receipts but add no likelihood.
/// The same consumed source with changed semantics refuses the whole step. First nonnumeric
/// sightings reserve no lifetime slot; they may later become an actual calibrated observation.
/// Numeric resets retain the lifetime inventory and never refund capacity or permit source reuse.
#[derive(Clone, Debug)]
pub struct UniqueSourceEProcess {
    inner: SequentialEProcess,
    source_limit: usize,
    seen: BTreeMap<ContentDigest, SeenSource>,
    last_receipt: Option<ContentDigest>,
}

impl UniqueSourceEProcess {
    /// Creates an explicitly selected source-once process with a lifetime source allowance.
    ///
    /// # Errors
    ///
    /// Refuses invalid original numerical configuration/hypothesis or a limit outside
    /// `1..=MAX_UNIQUE_SOURCES`. No new profile is selected by historical constructors.
    pub fn new(
        hypothesis_id: impl Into<String>,
        config: EProcessConfig,
        source_limit: usize,
    ) -> Result<Self, UniqueSourceError> {
        if !(1..=MAX_UNIQUE_SOURCES).contains(&source_limit) {
            return Err(FusionError::InvalidPolicy(format!(
                "unique source limit must be in 1..={MAX_UNIQUE_SOURCES}"
            ))
            .into());
        }
        Ok(Self {
            inner: SequentialEProcess::new(hypothesis_id, config)?,
            source_limit,
            seen: BTreeMap::new(),
            last_receipt: None,
        })
    }

    /// Read-only numerical state; there is no mutable path around source admission.
    #[must_use]
    pub const fn accumulator(&self) -> &SequentialEProcess {
        &self.inner
    }

    /// Nonrefillable lifetime numeric source allowance.
    #[must_use]
    pub const fn source_limit(&self) -> usize {
        self.source_limit
    }

    /// Consumed distinct numeric sources across all regimes.
    #[must_use]
    pub fn sources_seen(&self) -> usize {
        self.seen.len()
    }

    /// Complete immutable lifetime inventory in canonical source-key order.
    ///
    /// Each row contains the declared source digest, its immutable semantic item digest, and
    /// the step of its first numeric admission. Callers can bind additional source-owner facts
    /// to exactly these keys when retaining a checkpoint. These are caller-declared identities,
    /// not source custody or independence certificates.
    pub fn admitted_sources(
        &self,
    ) -> impl ExactSizeIterator<Item = (ContentDigest, ContentDigest, u64)> + '_ {
        self.seen
            .iter()
            .map(|(source, entry)| (*source, entry.item_digest, entry.first_step))
    }

    /// Complete lifetime inventory commitment, including an empty inventory before any step.
    #[must_use]
    pub fn inventory_digest(&self) -> ContentDigest {
        receipt::inventory_digest(self.source_limit, &self.seen)
    }

    /// Last accepted profile receipt; refusals never advance it.
    #[must_use]
    pub const fn transcript_head(&self) -> Option<ContentDigest> {
        self.last_receipt
    }

    /// Evaluates one complete query using only newly admitted numeric sources.
    ///
    /// `bindings` maps each original evidence ID to an optional stable declared source digest.
    /// `None` is admitted only for nonnumeric rows such as missing-source health diagnostics.
    /// No digest is invented for those rows. Canonical
    /// source equality uses algorithm plus bytes, not the nonencoded laboratory marker. The
    /// returned fusion decision is for the effective incremental query; accumulated statistics
    /// are in the returned step. Replayed-only queries advance an explicit zero-delta receipt.
    ///
    /// # Errors
    ///
    /// Invalid original queries/bindings, conflicting source semantics, exhausted lifetime
    /// capacity or original numerical refusals leave the accumulator, inventory and both
    /// transcript chains unchanged. No valid prefix of a refused step is consumed.
    pub fn observe_step(
        &mut self,
        query: &FusionQuery,
        bindings: &BTreeMap<String, Option<ContentDigest>>,
    ) -> Result<(FusionOutcome, UniqueSourceStepOutcome), UniqueSourceError> {
        if query.hypothesis != self.inner.hypothesis_id() {
            return Err(FusionError::InvalidInput(
                "source-once observation belongs to a different hypothesis".to_owned(),
            )
            .into());
        }
        query.validate()?;
        if bindings.len() != query.evidence.len()
            || query
                .evidence
                .iter()
                .any(|item| !bindings.contains_key(&item.id))
            || query.evidence.iter().any(|item| {
                matches!(item.observability, Observability::Observed)
                    && matches!(item.calibration, Calibration::Calibrated { .. })
                    && bindings.get(&item.id).is_none_or(Option::is_none)
            })
        {
            return Err(UniqueSourceError::InvalidBindings);
        }

        let next_step = self.inner.step_index().saturating_add(1);
        let mut ordered: Vec<_> = query.evidence.iter().collect();
        ordered.sort_by(|a, b| a.id.cmp(&b.id));
        let mut effective = query.clone();
        effective.evidence.clear();
        let mut in_step = BTreeMap::new();
        let mut additions = BTreeMap::new();
        let mut admissions = Vec::with_capacity(ordered.len());
        for item in ordered {
            let source = (*bindings
                .get(&item.id)
                .ok_or(UniqueSourceError::InvalidBindings)?)
            .map(canonical_source);
            let fingerprint = item_digest(query, item);
            if let Some(source) = source {
                if self
                    .seen
                    .get(&source)
                    .is_some_and(|seen| seen.item_digest != fingerprint)
                    || in_step
                        .get(&source)
                        .is_some_and(|seen| *seen != fingerprint)
                {
                    return Err(UniqueSourceError::ConflictingSource { source });
                }
                in_step.insert(source, fingerprint);
            }
            let numeric = matches!(item.observability, Observability::Observed)
                && matches!(item.calibration, Calibration::Calibrated { .. });
            let (disposition, first_step) = if numeric {
                let source = source.ok_or(UniqueSourceError::InvalidBindings)?;
                if let Some(seen) = self.seen.get(&source).or_else(|| additions.get(&source)) {
                    (SourceDisposition::AlreadyAdmitted, Some(seen.first_step))
                } else {
                    additions.insert(
                        source,
                        SeenSource {
                            item_digest: fingerprint,
                            first_step: next_step,
                        },
                    );
                    effective.evidence.push(item.clone());
                    (SourceDisposition::Admitted, Some(next_step))
                }
            } else {
                // Preserve missing/redacted/stale/uncalibrated rows in the effective query so
                // replay filtering never manufactures complete observation or absence evidence.
                effective.evidence.push(item.clone());
                (SourceDisposition::NonNumeric, None)
            };
            admissions.push(SourceAdmission::new(
                item.id.clone(),
                source,
                fingerprint,
                disposition,
                first_step,
            ));
        }
        if self.seen.len() + additions.len() > self.source_limit {
            return Err(UniqueSourceError::SourceCapacity {
                limit: self.source_limit,
                existing: self.seen.len(),
                additional: additions.len(),
            });
        }

        let submitted_query = query.digest();
        let (fusion, step) = self.inner.observe_step(&effective)?;
        self.seen.extend(additions);
        let outcome = self.seal(Some(submitted_query), admissions, step);
        Ok((fusion, outcome))
    }

    /// Clears active numerical state while retaining all consumed source identities and capacity.
    pub fn reset_regime(&mut self, reason: RegimeResetReason) -> UniqueSourceStepOutcome {
        let step = self.inner.reset_regime(reason);
        self.seal(None, Vec::new(), step)
    }

    fn seal(
        &mut self,
        submitted_query: Option<ContentDigest>,
        admissions: Vec<SourceAdmission>,
        step: crate::EProcessStepOutcome,
    ) -> UniqueSourceStepOutcome {
        let outcome = UniqueSourceStepOutcome::seal(
            self.last_receipt,
            submitted_query,
            self.source_limit,
            &self.seen,
            admissions,
            step,
        );
        self.last_receipt = Some(outcome.digest());
        outcome
    }
}

#[cfg(test)]
mod tests;
