#![forbid(unsafe_code)]
//! Owner-requested retention selection over completed file imports.
//!
//! Every cleanup remains an exact one-shot request, optionally using a durable policy revision.
//! A policy supplies settings, never a clock service or standing deletion authority. Only an
//! entire recording whose latest possible capture plus the requested retention duration is
//! no later than the earliest owner-attested current time is eligible. Unknown capture time,
//! source gaps and substantive omissions retain the recording. Holds are not expired here.
//! A held or otherwise blocked expired recording stays explicit while independent expired
//! closures remain selectable. Each proposed union is checked, since combining individually
//! safe imports can make shared evidence deletable. The selection and its exclusion witnesses
//! travel inside the deletion scope; commit re-reads them before the tombstone-first protocol.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContentDigest, ContractError, DigestAlgorithm, Plane, SensorCapsule, SensorId, TimestampNs,
};

use super::{CommitReceipt, DeletionError, DeletionIndex, DeletionPlan, DeletionScope, Finding};
use crate::ingest::{RetainedFileImport, RetainedReadLimits};
use crate::reference_deployment::FAMILY_SENSOR_CAPSULE;
use crate::{ReferenceDeployment, ReplayCx};

mod budget;
pub use budget::RetentionByteAccounting;
/// Durable owner-approved policies; adoption never authorizes automatic deletion.
pub mod policy;

/// Stable selection encoding embedded in retention deletion plans.
pub const RETENTION_SELECTION_DOMAIN: &str = "fss.retention_selection.v1";
/// Selection with explicit closure-blocked exclusions. Legacy v1 bytes stay unchanged.
pub const RETENTION_BLOCKER_SELECTION_DOMAIN: &str = "fss.retention_selection.v2";
/// Age-constrained, oldest-first byte-budget selection. V1 and V2 bytes stay unchanged.
pub const RETENTION_BYTE_SELECTION_DOMAIN: &str = "fss.retention_selection.v3";
/// Exact retained policy pin wrapping an unchanged v1, v2 or v3 selection.
pub const RETENTION_POLICY_SELECTION_DOMAIN: &str = "fss.retention_selection.v4";
/// Maximum import identities inspected in one request, including unfinished imports.
pub const MAX_RETENTION_IMPORTS: usize = 256;
/// Maximum capsule records read across the complete inventory, not per import.
pub const MAX_RETENTION_CAPSULES: u64 = 16_384;
/// Maximum ledger deltas inspected across the request.
pub const MAX_RETENTION_LEDGER_ENTRIES: u64 = 1_000_000;
/// Maximum aggregate metadata bytes; source media is never read by the selector.
pub const MAX_RETENTION_METADATA_BYTES: u64 = 64 * 1024 * 1024;
/// Aggregate blocker findings retained across all excluded candidates; overflow refuses.
pub const MAX_RETENTION_BLOCKERS: usize = 4096;
/// Maximum bytes in one blocker field. Diagnostics never include source media.
const MAX_BLOCKER_TEXT_BYTES: usize = 4096;
/// Cancellation point before each inventory or metadata read.
pub const STAGE_RETENTION_READ: &str = "retention:read";
/// Cancellation point before each prospective union-closure evaluation.
pub const STAGE_RETENTION_COHORT: &str = "retention:cohort";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum SelectionVersion {
    Age,
    Blockers,
    ByteBudget,
}

/// Explicit owner choice, including conservative current-time bounds. No host clock is read.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RetentionRequest {
    sensor: SensorId,
    retain_for_ns: u64,
    now_earliest_ns: i128,
    now_latest_ns: i128,
    source_byte_budget: Option<u64>,
    policy: Option<ContentDigest>,
}

impl RetentionRequest {
    /// Validate the request before accessing a deployment.
    pub fn new(
        sensor: SensorId,
        retain_for_ns: u64,
        attested_now: CaptureInterval,
    ) -> Result<Self, DeletionError> {
        CaptureInterval::new(attested_now.earliest, attested_now.latest)?;
        if retain_for_ns == 0 {
            return Err(ContractError::InvalidIdentifier.into());
        }
        Ok(Self {
            sensor,
            retain_for_ns,
            now_earliest_ns: attested_now.earliest.0,
            now_latest_ns: attested_now.latest.0,
            source_byte_budget: None,
            policy: None,
        })
    }

    /// Exact sensor, not an alias inferred from a path.
    #[must_use]
    pub fn sensor(&self) -> &SensorId {
        &self.sensor
    }

    /// Requested minimum age of every selected recording, in nanoseconds.
    #[must_use]
    pub const fn retain_for_ns(&self) -> u64 {
        self.retain_for_ns
    }

    /// Add an explicit target for distinct completed input-file bytes of this sensor.
    ///
    /// The minimum age and every existing custody/hold/effect constraint still apply.
    /// Zero is permitted; an unattainable target produces an explicit remaining deficit.
    /// This is not a physical disk-space budget or a standing retention policy.
    #[must_use]
    pub fn with_source_byte_budget(mut self, max_retained_source_bytes: u64) -> Self {
        self.source_byte_budget = Some(max_retained_source_bytes);
        self
    }

    /// Explicit logical source-byte target, absent for the unchanged age-only selection.
    #[must_use]
    pub const fn source_byte_budget(&self) -> Option<u64> {
        self.source_byte_budget
    }

    /// Exact adopted policy whose settings supplied this request. It grants no deletion.
    #[must_use]
    pub const fn policy_digest(&self) -> Option<ContentDigest> {
        self.policy
    }

    /// Owner assertion of current time, not calibrated or independently observed time.
    #[must_use]
    pub fn attested_now(&self) -> CaptureInterval {
        CaptureInterval {
            earliest: TimestampNs(self.now_earliest_ns),
            latest: TimestampNs(self.now_latest_ns),
        }
    }

    fn encode(&self, e: &mut CanonicalEncoder) {
        self.sensor.encode_canonical(e);
        e.u64(self.retain_for_ns);
        TimestampNs(self.now_earliest_ns).encode_canonical(e);
        TimestampNs(self.now_latest_ns).encode_canonical(e);
    }

    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, DeletionError> {
        let sensor = SensorId::decode_canonical(d)?;
        let duration = d.u64()?;
        let earliest = TimestampNs::decode_canonical(d)?;
        let latest = TimestampNs::decode_canonical(d)?;
        Self::new(sensor, duration, CaptureInterval::new(earliest, latest)?)
    }

    fn classify(&self, end: CaptureEnd) -> RetentionDisposition {
        let duration = i128::from(self.retain_for_ns);
        let Some(latest_deadline) = end.latest_ns.checked_add(duration) else {
            return RetentionDisposition::DeadlineOverflow;
        };
        let Some(earliest_deadline) = end.earliest_ns.checked_add(duration) else {
            return RetentionDisposition::DeadlineOverflow;
        };
        if self.now_earliest_ns >= latest_deadline {
            RetentionDisposition::Eligible
        } else if self.now_latest_ns < earliest_deadline {
            RetentionDisposition::NotDue
        } else {
            RetentionDisposition::AgeUncertain
        }
    }
}

/// Why a complete recording is selected or retained. None of these states releases a hold.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RetentionDisposition {
    /// The entire recording is certainly old enough under both owner time assertions.
    Eligible,
    /// Even the latest asserted current time precedes the earliest possible deadline.
    NotDue,
    /// Current-time and capture uncertainty do not establish that the deadline elapsed.
    AgeUncertain,
    /// The import does not establish capture time.
    CaptureTimeUnknown,
    /// A source gap invalidates frame-index capture hints.
    SourceGap,
    /// Omitted source material prevents a whole-recording age assertion.
    SourceOmission,
    /// Timestamp arithmetic cannot represent the retention deadline; retain, never wrap.
    DeadlineOverflow,
    /// Old enough, but adding this import to the preceding selected cohort is blocked.
    /// Exact reasons and the prospective plan digest remain on the candidate.
    ClosureBlocked,
    /// Old enough, but the logical byte target was already reached before this candidate.
    /// Its closure was not evaluated and no hold is released.
    BudgetRetained,
}

impl RetentionDisposition {
    /// Stable machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::NotDue => "not_due",
            Self::AgeUncertain => "age_uncertain",
            Self::CaptureTimeUnknown => "capture_time_unknown",
            Self::SourceGap => "source_gap",
            Self::SourceOmission => "source_omission",
            Self::DeadlineOverflow => "deadline_overflow",
            Self::ClosureBlocked => "closure_blocked",
            Self::BudgetRetained => "budget_retained",
        }
    }

    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, DeletionError> {
        match d.text()? {
            "eligible" => Ok(Self::Eligible),
            "not_due" => Ok(Self::NotDue),
            "age_uncertain" => Ok(Self::AgeUncertain),
            "capture_time_unknown" => Ok(Self::CaptureTimeUnknown),
            "source_gap" => Ok(Self::SourceGap),
            "source_omission" => Ok(Self::SourceOmission),
            "deadline_overflow" => Ok(Self::DeadlineOverflow),
            "closure_blocked" => Ok(Self::ClosureBlocked),
            "budget_retained" => Ok(Self::BudgetRetained),
            _ => Err(DeletionError::RecordMismatch),
        }
    }
}

/// Bounds on the last capture: maxima of all capsule lower and upper bounds respectively.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CaptureEnd {
    /// Earliest possible last capture, in the import's operator-declared clock coordinates.
    pub earliest_ns: i128,
    /// Latest possible last capture; this endpoint controls deletion eligibility.
    pub latest_ns: i128,
}

/// Immutable source binding and selection decision for one recording of the requested sensor.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RetentionCandidate {
    import_identity: ContentDigest,
    manifest_digest: ContentDigest,
    timing_digest: ContentDigest,
    end: Option<CaptureEnd>,
    disposition: RetentionDisposition,
    blockers: Vec<Finding>,
    closure_witness: Option<ContentDigest>,
    source: Option<budget::RetentionSource>,
}

impl RetentionCandidate {
    /// Exact completed import.
    #[must_use]
    pub const fn import_identity(&self) -> ContentDigest {
        self.import_identity
    }
    /// Manifest that supplied time classification, gaps and omissions.
    #[must_use]
    pub const fn manifest_digest(&self) -> ContentDigest {
        self.manifest_digest
    }
    /// Binding over all source capsule metadata digests in manifest segment order.
    #[must_use]
    pub const fn timing_digest(&self) -> ContentDigest {
        self.timing_digest
    }
    /// Last-capture bounds, absent when source timing is not admissible.
    #[must_use]
    pub const fn capture_end(&self) -> Option<CaptureEnd> {
        self.end
    }
    /// Selection decision; eligible is not equivalent to deletion-authorized.
    #[must_use]
    pub const fn disposition(&self) -> RetentionDisposition {
        self.disposition
    }
    /// Exact blockers for the attempted addition, in canonical order. These do not release
    /// a hold, adjudicate an effect, or claim that every alternative cohort was searched.
    #[must_use]
    pub fn blockers(&self) -> &[Finding] {
        &self.blockers
    }
    /// Digest of the read-only trial deletion plan, with this import and the preceding
    /// accepted candidates. This is a recomputable witness, not a publication or approval.
    #[must_use]
    pub const fn closure_witness(&self) -> Option<ContentDigest> {
        self.closure_witness
    }

    /// Complete input-file identity from verified import metadata, present for v3 selections.
    /// Equal digests count once even when several imports of this sensor retain that input.
    #[must_use]
    pub fn source_digest(&self) -> Option<ContentDigest> {
        self.source.as_ref().map(|source| source.digest)
    }

    /// Declared complete input-file length; not physical bytes reclaimable from the spool.
    #[must_use]
    pub fn source_bytes(&self) -> Option<u64> {
        self.source.as_ref().map(|source| source.bytes)
    }
}

/// Complete, bounded selection. Fields are private; fresh deletion always recomputes it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RetentionSelection {
    request: RetentionRequest,
    candidates: Vec<RetentionCandidate>,
    version: SelectionVersion,
    byte_accounting: Option<RetentionByteAccounting>,
}

impl RetentionSelection {
    /// Exact owner request.
    #[must_use]
    pub fn request(&self) -> &RetentionRequest {
        &self.request
    }
    /// Every complete recording of the named sensor, including retained exclusions.
    #[must_use]
    pub fn candidates(&self) -> &[RetentionCandidate] {
        &self.candidates
    }
    /// Recomputable logical accounting for the hypothetical selected cohort, never an
    /// executed deletion or a promise of physical disk space. A blocked final plan cannot
    /// realize this projection. Incomplete imports and other sensors are outside its scope.
    #[must_use]
    pub fn byte_accounting(&self) -> Option<&RetentionByteAccounting> {
        self.byte_accounting.as_ref()
    }
    /// Exact canonical format. V2 is used only when at least one closure is excluded.
    #[must_use]
    pub const fn domain(&self) -> &'static str {
        if self.request.policy.is_some() {
            return RETENTION_POLICY_SELECTION_DOMAIN;
        }
        self.inner_domain()
    }

    const fn inner_domain(&self) -> &'static str {
        match self.version {
            SelectionVersion::Age => RETENTION_SELECTION_DOMAIN,
            SelectionVersion::Blockers => RETENTION_BLOCKER_SELECTION_DOMAIN,
            SelectionVersion::ByteBudget => RETENTION_BYTE_SELECTION_DOMAIN,
        }
    }
    /// Selected members, in strictly ascending import identity order.
    #[must_use]
    pub fn imports(&self) -> Vec<ContentDigest> {
        self.candidates
            .iter()
            .filter(|c| c.disposition == RetentionDisposition::Eligible)
            .map(|c| c.import_identity)
            .collect()
    }
    /// Content identity of the request, selected members, exclusions and timing bindings.
    pub fn digest(&self) -> Result<ContentDigest, DeletionError> {
        let mut e = CanonicalEncoder::new();
        self.encode(&mut e);
        Ok(ContentDigest::sha256(&e.finish_checked()?))
    }
    pub(super) fn encode(&self, e: &mut CanonicalEncoder) {
        if let Some(policy) = self.request.policy {
            e.text(RETENTION_POLICY_SELECTION_DOMAIN);
            e.digest(policy);
        }
        self.encode_inner(e);
    }

    fn encode_inner(&self, e: &mut CanonicalEncoder) {
        e.text(self.inner_domain());
        self.request.encode(e);
        if self.version == SelectionVersion::ByteBudget {
            e.bool(self.request.source_byte_budget.is_some());
            if let Some(maximum) = self.request.source_byte_budget {
                e.u64(maximum);
            }
        }
        e.u64(self.candidates.len() as u64);
        for c in &self.candidates {
            e.digest(c.import_identity);
            e.digest(c.manifest_digest);
            e.digest(c.timing_digest);
            e.bool(c.end.is_some());
            if let Some(end) = c.end {
                TimestampNs(end.earliest_ns).encode_canonical(e);
                TimestampNs(end.latest_ns).encode_canonical(e);
            }
            e.text(c.disposition.as_str());
            if self.version == SelectionVersion::ByteBudget {
                e.bool(c.source.is_some());
                if let Some(source) = &c.source {
                    e.digest(source.digest);
                    e.u64(source.bytes);
                }
            }
            if self.version != SelectionVersion::Age {
                e.bool(c.closure_witness.is_some());
                if let Some(witness) = c.closure_witness {
                    e.digest(witness);
                }
                e.u64(c.blockers.len() as u64);
                for finding in &c.blockers {
                    e.text(&finding.kind);
                    e.text(&finding.subject);
                    e.text(&finding.detail);
                }
            }
        }
        if self.version == SelectionVersion::ByteBudget {
            e.bool(self.byte_accounting.is_some());
            if let Some(accounting) = &self.byte_accounting {
                accounting.encode(e);
            }
        }
    }
    pub(super) fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, DeletionError> {
        let mut domain = d.text()?;
        let policy = if domain == RETENTION_POLICY_SELECTION_DOMAIN {
            if d.remaining() > super::MAX_DELETION_RECORD_BYTES {
                return Err(DeletionError::Bound {
                    limit: "retention_policy_selection_bytes",
                });
            }
            let policy = read_digest(d)?;
            domain = d.text()?;
            Some(policy)
        } else {
            None
        };
        // The wrapper is deliberately one level deep. The original inner encoding is
        // consumed directly, without a recursive parser or changed legacy bytes.
        let version = match domain {
            RETENTION_SELECTION_DOMAIN => SelectionVersion::Age,
            RETENTION_BLOCKER_SELECTION_DOMAIN => SelectionVersion::Blockers,
            RETENTION_BYTE_SELECTION_DOMAIN => SelectionVersion::ByteBudget,
            _ => return Err(DeletionError::RecordMismatch),
        };
        let mut request = RetentionRequest::decode(d)?;
        request.policy = policy;
        if version == SelectionVersion::ByteBudget {
            if !d.bool()? {
                return Err(DeletionError::RecordMismatch);
            }
            request.source_byte_budget = Some(d.u64()?);
        }
        let n = usize::try_from(d.u64()?).map_err(|_| DeletionError::RecordMismatch)?;
        if n > MAX_RETENTION_IMPORTS || n > d.remaining() / 108 {
            return Err(DeletionError::Bound {
                limit: "retention_selection_entries",
            });
        }
        let mut candidates = Vec::with_capacity(n);
        let mut total_blockers = 0;
        for _ in 0..n {
            let import_identity = read_digest(d)?;
            let manifest_digest = read_digest(d)?;
            let timing_digest = read_digest(d)?;
            let end = if d.bool()? {
                let earliest_ns = TimestampNs::decode_canonical(d)?.0;
                let latest_ns = TimestampNs::decode_canonical(d)?.0;
                if earliest_ns > latest_ns {
                    return Err(DeletionError::RecordMismatch);
                }
                Some(CaptureEnd {
                    earliest_ns,
                    latest_ns,
                })
            } else {
                None
            };
            let disposition = RetentionDisposition::decode(d)?;
            let source = if version == SelectionVersion::ByteBudget {
                if !d.bool()? {
                    return Err(DeletionError::RecordMismatch);
                }
                let source = budget::RetentionSource {
                    digest: read_digest(d)?,
                    bytes: d.u64()?,
                };
                if source.bytes == 0 {
                    return Err(DeletionError::RecordMismatch);
                }
                Some(source)
            } else {
                None
            };
            let mut blockers = Vec::new();
            let mut closure_witness = None;
            if version != SelectionVersion::Age {
                if d.bool()? {
                    closure_witness = Some(read_digest(d)?);
                }
                let count = usize::try_from(d.u64()?).map_err(|_| DeletionError::RecordMismatch)?;
                if count > MAX_RETENTION_BLOCKERS - total_blockers || count > d.remaining() / 24 {
                    return Err(DeletionError::Bound {
                        limit: "retention_blockers",
                    });
                }
                total_blockers += count;
                for _ in 0..count {
                    let mut text = || -> Result<String, DeletionError> {
                        let text = d.text()?;
                        if text.is_empty() || text.len() > MAX_BLOCKER_TEXT_BYTES {
                            return Err(DeletionError::RecordMismatch);
                        }
                        Ok(text.to_owned())
                    };
                    blockers.push(Finding {
                        kind: text()?,
                        subject: text()?,
                        detail: text()?,
                    });
                }
                if blockers.windows(2).any(|w| w[0] >= w[1]) {
                    return Err(ContractError::NonCanonicalOrdering.into());
                }
            }
            let blocked = disposition == RetentionDisposition::ClosureBlocked;
            if blocked != (closure_witness.is_some() && !blockers.is_empty())
                || !blocked && (closure_witness.is_some() || !blockers.is_empty())
            {
                return Err(DeletionError::RecordMismatch);
            }
            match (end, disposition) {
                (Some(end), state) if request.classify(end) == state => {}
                (Some(end), RetentionDisposition::ClosureBlocked)
                    if version != SelectionVersion::Age
                        && request.classify(end) == RetentionDisposition::Eligible => {}
                (Some(end), RetentionDisposition::BudgetRetained)
                    if version == SelectionVersion::ByteBudget
                        && request.classify(end) == RetentionDisposition::Eligible => {}
                (
                    None,
                    RetentionDisposition::CaptureTimeUnknown
                    | RetentionDisposition::SourceGap
                    | RetentionDisposition::SourceOmission,
                ) => {}
                _ => return Err(DeletionError::RecordMismatch),
            }
            candidates.push(RetentionCandidate {
                import_identity,
                manifest_digest,
                timing_digest,
                end,
                disposition,
                blockers,
                closure_witness,
                source,
            });
        }
        if candidates
            .windows(2)
            .any(|w| w[0].import_identity >= w[1].import_identity)
        {
            return Err(ContractError::NonCanonicalOrdering.into());
        }
        if version == SelectionVersion::Blockers && total_blockers == 0 {
            return Err(DeletionError::RecordMismatch);
        }
        let byte_accounting = if version == SelectionVersion::ByteBudget {
            if !d.bool()? {
                return Err(DeletionError::RecordMismatch);
            }
            Some(RetentionByteAccounting::decode(d)?)
        } else {
            None
        };
        let selection = Self {
            request,
            candidates,
            version,
            byte_accounting,
        };
        if version == SelectionVersion::ByteBudget {
            budget::verify_selection(&selection)?;
        }
        Ok(selection)
    }
}

fn read_digest(d: &mut CanonicalDecoder<'_>) -> Result<ContentDigest, DeletionError> {
    let digest = d.digest()?;
    if digest.algorithm() != DigestAlgorithm::Sha256 {
        return Err(ContractError::UnsupportedDigestAlgorithm.into());
    }
    Ok(digest)
}

/// Actual selector and shared dependency-scan work, including all-blocked selections.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionAssessment {
    /// Immutable selection, including each same-sensor exclusion.
    pub selection: RetentionSelection,
    /// Ledger deltas inspected while indexing and reading capsule bindings.
    pub ledger_entries: u64,
    /// Capsule metadata records read across all complete imports.
    pub capsules: u64,
    /// Aggregate canonical manifest and capsule metadata bytes.
    pub metadata_bytes: u64,
    /// Complete imports outside the named sensor; no content from those sensors is returned.
    pub outside_sensor: usize,
    /// Incomplete imports were not age-classified and are never selected.
    pub incomplete_imports: usize,
    /// Objects scanned once for the reusable dependency universe; zero with no age-eligible input.
    pub closure_scanned_objects: u64,
    /// Bytes in that one dependency scan, separate from the metadata selector's allowance.
    pub closure_scanned_bytes: u64,
    /// Prospective cohort plans evaluated, including the fast path and final exact selection.
    pub closure_evaluations: usize,
    /// Distinct held import closures evaluated once and reused across prospective cohorts.
    pub held_closures: usize,
}

#[derive(Default)]
struct Usage {
    entries: u64,
    capsules: u64,
    bytes: u64,
}

fn charge(
    used: &mut u64,
    amount: u64,
    maximum: u64,
    limit: &'static str,
) -> Result<(), DeletionError> {
    *used = used
        .checked_add(amount)
        .ok_or(DeletionError::Bound { limit })?;
    if *used > maximum {
        return Err(DeletionError::Bound { limit });
    }
    Ok(())
}

fn checkpoint(cx: &ReplayCx) -> Result<(), DeletionError> {
    cx.checkpoint(STAGE_RETENTION_READ)
        .map_err(|_| DeletionError::Cancelled {
            stage: STAGE_RETENTION_READ,
        })
}

fn import_identity(batch: &str) -> Result<Option<(ContentDigest, &str)>, DeletionError> {
    let Some(rest) = batch.strip_prefix("batch:file-import:") else {
        return Ok(None);
    };
    let (hex, phase) = rest.split_once(':').ok_or(DeletionError::RecordMismatch)?;
    let digest = ContentDigest::parse(format!("sha256:{hex}"))?;
    if hex.len() != 64 || digest.to_text() != format!("sha256:{hex}") || phase.is_empty() {
        return Err(DeletionError::RecordMismatch);
    }
    Ok(Some((digest, phase)))
}

/// Inspect completed file imports without decoding pixels, reading a host clock, or writing.
/// The caller authorizes the deployment as for `plan_scope_deletion`. The explicit replay
/// context must own this root. Bad custody, cancellation or a bound refuses the whole selection.
fn assess_age_retention(
    deployment: &ReferenceDeployment,
    request: &RetentionRequest,
    cx: &ReplayCx,
) -> Result<RetentionAssessment, DeletionError> {
    checkpoint(cx)?;
    if cx.root_dir() != deployment.root() {
        return Err(DeletionError::RecordMismatch);
    }
    if request.policy.is_some() {
        policy::validate_current_request(deployment, request, cx)?;
    }
    let deletions = DeletionIndex::read(deployment)?;
    let mut usage = Usage::default();
    let mut inventory: BTreeMap<ContentDigest, Vec<usize>> = BTreeMap::new();
    let mut complete = BTreeSet::new();
    for (position, batch) in deployment.ledger().batches().iter().enumerate() {
        checkpoint(cx)?;
        charge(
            &mut usage.entries,
            1 + batch.deltas.len() as u64,
            MAX_RETENTION_LEDGER_ENTRIES,
            "retention_ledger_entries",
        )?;
        if let Some((identity, phase)) = import_identity(batch.batch_id.as_str())? {
            if deletions.import(identity).is_some() {
                continue;
            }
            if !inventory.contains_key(&identity) && inventory.len() == MAX_RETENTION_IMPORTS {
                return Err(DeletionError::Bound {
                    limit: "retention_imports",
                });
            }
            inventory.entry(identity).or_default().push(position);
            if phase == "manifest" {
                complete.insert(identity);
            }
        }
    }
    let incomplete_imports = inventory.len() - complete.len();
    let mut candidates = Vec::new();
    let mut outside_sensor = 0;
    for identity in complete {
        checkpoint(cx)?;
        let retained =
            RetainedFileImport::open(deployment, identity, RetainedReadLimits::default(), cx)
                .map_err(|_| DeletionError::RecordMismatch)?;
        let manifest = retained.manifest();
        charge(
            &mut usage.bytes,
            manifest.canonical_bytes().len() as u64,
            MAX_RETENTION_METADATA_BYTES,
            "retention_metadata_bytes",
        )?;
        if manifest.segment_spans.is_empty() {
            return Err(DeletionError::RecordMismatch);
        }
        let expected: BTreeMap<_, _> = manifest
            .segment_spans
            .iter()
            .enumerate()
            .map(|(position, span)| (span.capsule_id.clone(), position))
            .collect();
        let mut capsules = BTreeMap::new();
        let batches = inventory
            .get(&identity)
            .ok_or(DeletionError::RecordMismatch)?;
        for &position in batches {
            let batch = &deployment.ledger().batches()[position];
            for delta in &batch.deltas {
                charge(
                    &mut usage.entries,
                    1,
                    MAX_RETENTION_LEDGER_ENTRIES,
                    "retention_ledger_entries",
                )?;
                if delta.family != FAMILY_SENSOR_CAPSULE {
                    continue;
                }
                checkpoint(cx)?;
                charge(
                    &mut usage.capsules,
                    1,
                    MAX_RETENTION_CAPSULES,
                    "retention_capsules",
                )?;
                let bytes = deployment.publisher().spool().read(delta.payload_digest)?;
                charge(
                    &mut usage.bytes,
                    bytes.len() as u64,
                    MAX_RETENTION_METADATA_BYTES,
                    "retention_metadata_bytes",
                )?;
                if bytes.len() > 16_384 || ContentDigest::sha256(&bytes) != delta.payload_digest {
                    return Err(DeletionError::RecordMismatch);
                }
                let capsule = SensorCapsule::from_canonical_bytes(&bytes)?;
                let segment = *expected
                    .get(&capsule.capsule_id)
                    .ok_or(DeletionError::RecordMismatch)?;
                let span = &manifest.segment_spans[segment];
                let current = deployment
                    .ledger()
                    .current()
                    .objects
                    .get(&delta.object_id)
                    .ok_or(DeletionError::RecordMismatch)?;
                if delta.plane != Plane::Authority
                    || !batch.children.contains(&delta.payload_digest)
                    || current.family != FAMILY_SENSOR_CAPSULE
                    || current.payload_digest != delta.payload_digest
                    || current.generation != delta.new_generation
                    || capsule.source_digest != span.segment_sha256
                    || capsule.source_bytes != span.len
                    || capsule.gap_before != span.gap_before
                    || capsules
                        .insert(segment, (delta.payload_digest, capsule))
                        .is_some()
                {
                    return Err(DeletionError::RecordMismatch);
                }
            }
        }
        if capsules.len() != expected.len() {
            return Err(DeletionError::RecordMismatch);
        }
        let sensors: BTreeSet<_> = capsules
            .values()
            .map(|(_, c)| c.sensor_id.clone())
            .collect();
        if sensors.len() != 1 {
            return Err(DeletionError::RecordMismatch);
        }
        if !sensors.contains(request.sensor()) {
            outside_sensor += 1;
            continue;
        }
        let mut timing = CanonicalEncoder::new();
        timing.text("fss.retention_capsule_timing.v1");
        timing.digest(identity);
        timing.digest(retained.manifest_digest());
        timing.u64(capsules.len() as u64);
        let mut end = CaptureEnd {
            earliest_ns: i128::MIN,
            latest_ns: i128::MIN,
        };
        let mut gap = false;
        for (digest, capsule) in capsules.values() {
            timing.digest(*digest);
            end.earliest_ns = end.earliest_ns.max(capsule.capture.earliest.0);
            end.latest_ns = end.latest_ns.max(capsule.capture.latest.0);
            gap |= capsule.gap_before;
        }
        let exclusion = if manifest.capture_time_label != "operator_assumption" {
            Some(RetentionDisposition::CaptureTimeUnknown)
        } else if gap {
            Some(RetentionDisposition::SourceGap)
        } else if manifest
            .omission_spans
            .iter()
            .any(|o| o.reason != "annexb_padding" && !o.is_container_structure())
        {
            Some(RetentionDisposition::SourceOmission)
        } else {
            None
        };
        candidates.push(RetentionCandidate {
            import_identity: identity,
            manifest_digest: retained.manifest_digest(),
            timing_digest: ContentDigest::sha256(&timing.finish_checked()?),
            end: if exclusion.is_some() { None } else { Some(end) },
            disposition: exclusion.unwrap_or_else(|| request.classify(end)),
            blockers: Vec::new(),
            closure_witness: None,
            source: request.source_byte_budget.map(|_| budget::RetentionSource {
                digest: manifest.input_sha256,
                bytes: manifest.input_bytes,
            }),
        });
    }
    checkpoint(cx)?;
    Ok(RetentionAssessment {
        selection: RetentionSelection {
            request: request.clone(),
            candidates,
            version: if request.source_byte_budget.is_some() {
                SelectionVersion::ByteBudget
            } else {
                SelectionVersion::Age
            },
            byte_accounting: None,
        },
        ledger_entries: usage.entries,
        capsules: usage.capsules,
        metadata_bytes: usage.bytes,
        outside_sensor,
        incomplete_imports,
        closure_scanned_objects: 0,
        closure_scanned_bytes: 0,
        closure_evaluations: 0,
        held_closures: 0,
    })
}

/// Assessment plus one union-closure plan. No safely selectable imports means no deletion plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionPlan {
    /// Selection and exclusions from verified retained metadata.
    pub assessment: RetentionAssessment,
    /// One exact plan for the selected cohort, or no selectable recording. Final aggregate
    /// publication bounds can still block a plan; no blocker is ignored at commit.
    pub deletion: Option<DeletionPlan>,
}

/// Assess conservative age and closure safety without writing any custody or authority.
pub fn assess_retention(
    deployment: &ReferenceDeployment,
    request: &RetentionRequest,
    cx: &ReplayCx,
) -> Result<RetentionAssessment, DeletionError> {
    Ok(plan_retention(deployment, request, cx)?.assessment)
}

fn cohort_checkpoint(cx: &ReplayCx) -> Result<(), DeletionError> {
    cx.checkpoint(STAGE_RETENTION_COHORT)
        .map_err(|_| DeletionError::Cancelled {
            stage: STAGE_RETENTION_COHORT,
        })
}

/// Prepare one union deletion using one reusable dependency scan and held-closure projection.
///
/// If the whole age-eligible cohort is safe, its legacy v1 selection stays byte-identical.
/// Otherwise candidates are considered in import-identity order. A candidate is selected only
/// when its union with the preceding selected candidates is unblocked; rejected additions retain
/// the complete blocker list and trial-plan digest. This deliberately favors deterministic safe
/// progress over searching every possible cohort. Every selected union is checked, not merely
/// its individual imports: combining imports can expose previously shared evidence to deletion.
/// With an explicit byte target, only certainly old-enough recordings are considered, ordered
/// by latest possible capture end then import identity. Selection stops once distinct completed
/// same-sensor input bytes meet the target; holds and unknown or young recordings can leave an
/// explicit deficit. This logical projection does not promise physical space or execution.
pub fn plan_retention(
    deployment: &ReferenceDeployment,
    request: &RetentionRequest,
    cx: &ReplayCx,
) -> Result<RetentionPlan, DeletionError> {
    let mut assessment = assess_age_retention(deployment, request, cx)?;
    if request.source_byte_budget.is_some() {
        return budget::plan(deployment, assessment, cx);
    }
    if assessment.selection.imports().is_empty() {
        return Ok(RetentionPlan {
            assessment,
            deletion: None,
        });
    }
    cohort_checkpoint(cx)?;
    let index = DeletionIndex::read(deployment)?;
    let holds = super::holds::HoldIndex::read(deployment, cx)?;
    let universe = super::walk::Universe::scan(deployment, &index, cx)?;
    let protection = holds.protection(&universe, deployment, cx)?;
    assessment.held_closures = protection.len();
    let mut evaluate = |selection: &RetentionSelection| -> Result<DeletionPlan, DeletionError> {
        cohort_checkpoint(cx)?;
        assessment.closure_evaluations += 1;
        let plan = universe.plan(deployment, &DeletionScope::Retention(selection.clone()))?;
        assessment.closure_scanned_objects = plan.scanned_objects;
        assessment.closure_scanned_bytes = plan.scanned_bytes;
        let plan = protection.protect(plan, cx)?;
        super::commit::admit_plan(deployment, plan, cx)
    };
    let whole = evaluate(&assessment.selection)?;
    if whole.blockers.is_empty() {
        return Ok(RetentionPlan {
            assessment,
            deletion: Some(whole),
        });
    }

    let age_selection = assessment.selection.clone();
    let mut selection = age_selection.clone();
    selection.version = SelectionVersion::Blockers;
    let mut selected = BTreeSet::new();
    let mut total_blockers = 0;
    for candidate in &mut selection.candidates {
        if candidate.disposition != RetentionDisposition::Eligible {
            continue;
        }
        // This internal trial is not a publishable selector: the public planner always
        // recomputes the complete inventory. Its exact bytes serve only as a refusal witness.
        let proposed = RetentionSelection {
            request: request.clone(),
            version: SelectionVersion::Age,
            candidates: age_selection
                .candidates
                .iter()
                .filter(|c| {
                    selected.contains(&c.import_identity)
                        || c.import_identity == candidate.import_identity
                })
                .cloned()
                .collect(),
            byte_accounting: None,
        };
        let plan = evaluate(&proposed)?;
        if plan.blockers.is_empty() {
            selected.insert(candidate.import_identity);
        } else {
            if plan.blockers.len() > MAX_RETENTION_BLOCKERS - total_blockers {
                return Err(DeletionError::Bound {
                    limit: "retention_blockers",
                });
            }
            total_blockers += plan.blockers.len();
            if plan.blockers.iter().any(|f| {
                [&f.kind, &f.subject, &f.detail]
                    .iter()
                    .any(|text| text.is_empty() || text.len() > MAX_BLOCKER_TEXT_BYTES)
            }) {
                return Err(DeletionError::Bound {
                    limit: "retention_blocker_text",
                });
            }
            candidate.disposition = RetentionDisposition::ClosureBlocked;
            candidate.closure_witness = Some(plan.digest()?);
            candidate.blockers = plan.blockers;
        }
    }
    if total_blockers == 0 {
        // The smaller trial selectors may fit an aggregate publication bound that the
        // complete inventory does not. No exclusion was proved: retain the original v1
        // blocked plan rather than minting a noncanonical empty-v2 selection or pretending
        // that the full request became executable.
        return Ok(RetentionPlan {
            assessment,
            deletion: Some(whole),
        });
    }
    // The final plan binds the complete selection and every exclusion, not the smaller
    // internal trial. It passes the same hold and aggregate authority-admission gates.
    let deletion = if selected.is_empty() {
        None
    } else {
        Some(evaluate(&selection)?)
    };
    cohort_checkpoint(cx)?;
    assessment.selection = selection;
    Ok(RetentionPlan {
        assessment,
        deletion,
    })
}

/// Revalidate legacy age metadata, or return the already revalidated v2/v3 union plan without
/// rescanning all source bytes. A decoded selection never grants authority on its own.
pub(super) fn revalidate_plan(
    deployment: &ReferenceDeployment,
    selection: &RetentionSelection,
    cx: &ReplayCx,
) -> Result<Option<DeletionPlan>, DeletionError> {
    match selection.version {
        SelectionVersion::Age => {
            if assess_age_retention(deployment, selection.request(), cx)?.selection != *selection {
                return Err(DeletionError::RecordMismatch);
            }
            Ok(None)
        }
        SelectionVersion::Blockers | SelectionVersion::ByteBudget => {
            let current = plan_retention(deployment, selection.request(), cx)?;
            if current.assessment.selection != *selection {
                return Err(DeletionError::RecordMismatch);
            }
            current.deletion.map(Some).ok_or_else(|| {
                DeletionError::ScopeEmpty(DeletionScope::Retention(selection.clone()).text())
            })
        }
    }
}

/// Execute exactly the approved cohort, or resume its retained plan after an interruption.
/// A new request, changed time assertion, later import, hold, or effect invalidates a fresh plan.
/// Once tombstones are durable, source bytes are not needed to resume the same deletion.
pub fn commit_retention(
    deployment: &mut ReferenceDeployment,
    request: &RetentionRequest,
    plan_digest: ContentDigest,
    approval: ContentDigest,
    principal: &str,
    cx: &ReplayCx,
) -> Result<CommitReceipt, DeletionError> {
    checkpoint(cx)?;
    super::commit::commit_retention(deployment, request, plan_digest, approval, principal, cx)
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn request(first: i128, last: i128) -> Result<RetentionRequest, DeletionError> {
        RetentionRequest::new(
            SensorId::parse("sensor:a")?,
            10,
            CaptureInterval::new(TimestampNs(first), TimestampNs(last))?,
        )
    }
    #[test]
    fn last_possible_capture_and_earliest_now_control_eligibility() -> TestResult {
        let end = CaptureEnd {
            earliest_ns: 80,
            latest_ns: 90,
        };
        assert_eq!(
            request(100, 110)?.classify(end),
            RetentionDisposition::Eligible
        );
        assert_eq!(
            request(99, 110)?.classify(end),
            RetentionDisposition::AgeUncertain
        );
        assert_eq!(request(70, 89)?.classify(end), RetentionDisposition::NotDue);
        assert_eq!(
            request(90, 99)?.classify(end),
            RetentionDisposition::AgeUncertain
        );
        Ok(())
    }
    #[test]
    fn signed_extremes_never_wrap_into_eligibility() -> TestResult {
        let end = CaptureEnd {
            earliest_ns: i128::MAX - 1,
            latest_ns: i128::MAX,
        };
        assert_eq!(
            request(i128::MAX, i128::MAX)?.classify(end),
            RetentionDisposition::DeadlineOverflow
        );
        let end = CaptureEnd {
            earliest_ns: i128::MIN,
            latest_ns: i128::MIN,
        };
        assert_eq!(
            request(i128::MIN + 10, i128::MIN + 10)?.classify(end),
            RetentionDisposition::Eligible
        );
        assert_eq!(
            request(i128::MIN + 9, i128::MIN + 9)?.classify(end),
            RetentionDisposition::NotDue
        );
        Ok(())
    }
    #[test]
    fn inverted_now_and_zero_duration_are_refused() -> TestResult {
        let sensor = SensorId::parse("sensor:a")?;
        assert!(
            RetentionRequest::new(
                sensor.clone(),
                0,
                CaptureInterval::new(TimestampNs(0), TimestampNs(0))?
            )
            .is_err()
        );
        assert!(
            RetentionRequest::new(
                sensor,
                1,
                CaptureInterval {
                    earliest: TimestampNs(2),
                    latest: TimestampNs(1),
                }
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn canonical_selection_binds_request_and_rejects_forged_eligibility() -> TestResult {
        let mut selection = RetentionSelection {
            request: request(100, 110)?,
            version: SelectionVersion::Age,
            candidates: vec![RetentionCandidate {
                import_identity: ContentDigest::sha256(b"import"),
                manifest_digest: ContentDigest::sha256(b"manifest"),
                timing_digest: ContentDigest::sha256(b"timing"),
                end: Some(CaptureEnd {
                    earliest_ns: 80,
                    latest_ns: 90,
                }),
                disposition: RetentionDisposition::Eligible,
                blockers: Vec::new(),
                closure_witness: None,
                source: None,
            }],
            byte_accounting: None,
        };
        let mut e = CanonicalEncoder::new();
        selection.encode(&mut e);
        let bytes = e.finish_checked()?;
        let mut d = CanonicalDecoder::new(&bytes);
        assert_eq!(RetentionSelection::decode(&mut d)?, selection);
        d.ensure_finished()?;
        let original = selection.digest()?;
        // Frozen legacy bytes: no witness or blocker-count suffix is added to v1.
        assert_eq!(bytes.len(), 246);
        assert_eq!(
            original.to_text(),
            "sha256:2b224eae38f5c61ee817923971d45e4972b05936fa486728db0253f9855b75e0"
        );
        selection.request = request(101, 110)?;
        assert_ne!(selection.digest()?, original);
        selection.request = request(0, 1)?;
        let mut e = CanonicalEncoder::new();
        selection.encode(&mut e);
        assert!(
            RetentionSelection::decode(&mut CanonicalDecoder::new(&e.finish_checked()?)).is_err()
        );
        Ok(())
    }
    #[test]
    fn exclusions_never_become_members_and_order_is_strict() -> TestResult {
        let c = RetentionCandidate {
            import_identity: ContentDigest::sha256(b"import"),
            manifest_digest: ContentDigest::sha256(b"manifest"),
            timing_digest: ContentDigest::sha256(b"timing"),
            end: None,
            disposition: RetentionDisposition::CaptureTimeUnknown,
            blockers: Vec::new(),
            closure_witness: None,
            source: None,
        };
        let selection = RetentionSelection {
            request: request(100, 100)?,
            version: SelectionVersion::Age,
            candidates: vec![c.clone()],
            byte_accounting: None,
        };
        assert!(selection.imports().is_empty());
        let mut duplicate = selection;
        duplicate.candidates.push(c);
        let mut e = CanonicalEncoder::new();
        duplicate.encode(&mut e);
        assert!(
            RetentionSelection::decode(&mut CanonicalDecoder::new(&e.finish_checked()?)).is_err()
        );
        Ok(())
    }
    fn blocked_selection() -> Result<RetentionSelection, DeletionError> {
        Ok(RetentionSelection {
            request: request(100, 110)?,
            version: SelectionVersion::Blockers,
            candidates: vec![RetentionCandidate {
                import_identity: ContentDigest::sha256(b"held import"),
                manifest_digest: ContentDigest::sha256(b"manifest"),
                timing_digest: ContentDigest::sha256(b"timing"),
                end: Some(CaptureEnd {
                    earliest_ns: 80,
                    latest_ns: 90,
                }),
                disposition: RetentionDisposition::ClosureBlocked,
                blockers: vec![Finding {
                    kind: "evidence_hold".to_owned(),
                    subject: "incident".to_owned(),
                    detail: "Exact retained hold record requires explicit release".to_owned(),
                }],
                closure_witness: Some(ContentDigest::sha256(b"trial plan")),
                source: None,
            }],
            byte_accounting: None,
        })
    }

    fn decoded(selection: &RetentionSelection) -> Result<RetentionSelection, DeletionError> {
        let mut e = CanonicalEncoder::new();
        selection.encode(&mut e);
        let bytes = e.finish_checked()?;
        let mut d = CanonicalDecoder::new(&bytes);
        let decoded = RetentionSelection::decode(&mut d)?;
        d.ensure_finished()?;
        Ok(decoded)
    }

    #[test]
    fn v2_exclusions_bind_the_exact_reasons_and_trial_closure_without_becoming_members()
    -> TestResult {
        let selection = blocked_selection()?;
        assert_eq!(decoded(&selection)?, selection);
        assert_eq!(selection.domain(), RETENTION_BLOCKER_SELECTION_DOMAIN);
        assert!(selection.imports().is_empty());
        let digest = selection.digest()?;
        let mut changed = selection.clone();
        changed.candidates[0].blockers[0].subject = "another-hold".to_owned();
        assert_ne!(changed.digest()?, digest);
        changed = selection.clone();
        changed.candidates[0].closure_witness = Some(ContentDigest::sha256(b"different closure"));
        assert_ne!(changed.digest()?, digest);
        changed = selection.clone();
        changed.version = SelectionVersion::Age;
        assert!(decoded(&changed).is_err());
        Ok(())
    }

    #[test]
    fn malformed_v2_never_drops_a_blocker_or_upgrades_nonexpired_recordings() -> TestResult {
        let good = blocked_selection()?;
        for mutation in 0..7 {
            let mut bad = good.clone();
            let candidate = &mut bad.candidates[0];
            match mutation {
                0 => candidate.blockers.clear(),
                1 => candidate.closure_witness = None,
                2 => candidate.disposition = RetentionDisposition::Eligible,
                3 => candidate.end = None,
                4 => {
                    candidate.end = Some(CaptureEnd {
                        earliest_ns: 1000,
                        latest_ns: 2000,
                    })
                }
                5 => candidate.blockers.push(candidate.blockers[0].clone()),
                _ => candidate.blockers[0].detail = "x".repeat(MAX_BLOCKER_TEXT_BYTES + 1),
            }
            assert!(decoded(&bad).is_err(), "mutation {mutation}");
        }
        let mut empty = good.clone();
        empty.candidates[0].disposition = RetentionDisposition::Eligible;
        empty.candidates[0].blockers.clear();
        empty.candidates[0].closure_witness = None;
        assert!(decoded(&empty).is_err());
        let mut over = good;
        over.candidates[0].blockers =
            vec![over.candidates[0].blockers[0].clone(); MAX_RETENTION_BLOCKERS + 1];
        assert!(matches!(
            decoded(&over),
            Err(DeletionError::Bound {
                limit: "retention_blockers"
            })
        ));
        Ok(())
    }

    #[test]
    fn budgets_refuse_instead_of_truncating_and_identity_parser_is_exact() -> TestResult {
        let mut used = 9;
        charge(&mut used, 1, 10, "test")?;
        assert!(charge(&mut used, 1, 10, "test").is_err());
        let digest = ContentDigest::sha256(b"import");
        let text = format!("batch:file-import:{}:manifest", &digest.to_text()[7..]);
        assert_eq!(import_identity(&text)?, Some((digest, "manifest")));
        assert!(import_identity("batch:file-import:bad:manifest").is_err());
        assert_eq!(import_identity("batch:other:manifest")?, None);
        Ok(())
    }

    #[test]
    fn policy_wrapper_preserves_each_legacy_inner_encoding_and_binds_the_revision() -> TestResult {
        let age = RetentionSelection {
            request: request(100, 110)?,
            version: SelectionVersion::Age,
            candidates: Vec::new(),
            byte_accounting: None,
        };
        let budget = RetentionSelection {
            request: request(100, 110)?.with_source_byte_budget(0),
            version: SelectionVersion::ByteBudget,
            candidates: Vec::new(),
            byte_accounting: Some(RetentionByteAccounting {
                max_retained_source_bytes: 0,
                before_source_bytes: 0,
                selected_source_bytes: 0,
                projected_remaining_source_bytes: 0,
                unmet_source_bytes: 0,
            }),
        };
        for inner in [age, blocked_selection()?, budget] {
            let mut original = CanonicalEncoder::new();
            inner.encode(&mut original);
            let original = original.finish_checked()?;
            let mut wrapped = inner.clone();
            wrapped.request.policy = Some(ContentDigest::sha256(b"policy:first"));
            assert_eq!(wrapped.domain(), RETENTION_POLICY_SELECTION_DOMAIN);
            assert_eq!(decoded(&wrapped)?, wrapped);
            let mut e = CanonicalEncoder::new();
            wrapped.encode(&mut e);
            let bytes = e.finish_checked()?;
            let mut d = CanonicalDecoder::new(&bytes);
            assert_eq!(d.text()?, RETENTION_POLICY_SELECTION_DOMAIN);
            assert_eq!(d.digest()?, wrapped.request.policy.ok_or("policy pin")?);
            assert_eq!(&bytes[bytes.len() - d.remaining()..], original);
            assert_ne!(wrapped.digest()?, inner.digest()?);
            let before = wrapped.digest()?;
            wrapped.request.policy = Some(ContentDigest::sha256(b"policy:second"));
            assert_ne!(wrapped.digest()?, before);
        }
        Ok(())
    }

    #[test]
    fn policy_wrapper_rejects_nesting_unknown_inner_formats_and_oversized_input() -> TestResult {
        for inner in [
            RETENTION_POLICY_SELECTION_DOMAIN,
            "fss.retention_selection.v99",
        ] {
            let mut e = CanonicalEncoder::new();
            e.text(RETENTION_POLICY_SELECTION_DOMAIN);
            e.digest(ContentDigest::sha256(b"policy"));
            e.text(inner);
            // No inner fields are supplied. Rejection happens at the domain dispatch;
            // nested wrappers never enter a recursive decode or consume another pin.
            assert!(matches!(
                RetentionSelection::decode(&mut CanonicalDecoder::new(&e.finish())),
                Err(DeletionError::RecordMismatch)
            ));
        }
        let mut e = CanonicalEncoder::new();
        e.text(RETENTION_POLICY_SELECTION_DOMAIN);
        let mut oversized = e.finish();
        oversized.resize(
            oversized.len() + super::super::MAX_DELETION_RECORD_BYTES + 1,
            0,
        );
        assert!(matches!(
            RetentionSelection::decode(&mut CanonicalDecoder::new(&oversized)),
            Err(DeletionError::Bound {
                limit: "retention_policy_selection_bytes"
            })
        ));
        Ok(())
    }
}
