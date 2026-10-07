#![forbid(unsafe_code)]
//! Owner-requested retention selection over completed file imports.
//!
//! This is a one-shot cleanup request, not a standing policy or a clock service. Only an
//! entire recording whose latest possible capture plus the requested retention duration is
//! no later than the earliest owner-attested current time is eligible. Unknown capture time,
//! source gaps and substantive omissions retain the recording. Holds are not expired here.
//! The selection, including exclusions and source-metadata bindings, travels inside the
//! deletion scope; a commit re-reads it before using the existing tombstone-first protocol.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContentDigest, ContractError, DigestAlgorithm, Plane, SensorCapsule, SensorId, TimestampNs,
};

use super::{CommitReceipt, DeletionError, DeletionIndex, DeletionPlan, DeletionScope};
use crate::ingest::{RetainedFileImport, RetainedReadLimits};
use crate::reference_deployment::FAMILY_SENSOR_CAPSULE;
use crate::{ReferenceDeployment, ReplayCx};

/// Stable selection encoding embedded in retention deletion plans.
pub const RETENTION_SELECTION_DOMAIN: &str = "fss.retention_selection.v1";
/// Maximum import identities inspected in one request, including unfinished imports.
pub const MAX_RETENTION_IMPORTS: usize = 256;
/// Maximum capsule records read across the complete inventory, not per import.
pub const MAX_RETENTION_CAPSULES: u64 = 16_384;
/// Maximum ledger deltas inspected across the request.
pub const MAX_RETENTION_LEDGER_ENTRIES: u64 = 1_000_000;
/// Maximum aggregate metadata bytes; source media is never read by the selector.
pub const MAX_RETENTION_METADATA_BYTES: u64 = 64 * 1024 * 1024;
/// Cancellation point before each inventory or metadata read.
pub const STAGE_RETENTION_READ: &str = "retention:read";

/// Explicit owner choice, including conservative current-time bounds. No host clock is read.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RetentionRequest {
    sensor: SensorId,
    retain_for_ns: u64,
    now_earliest_ns: i128,
    now_latest_ns: i128,
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
}

/// Complete, bounded selection. Fields are private; fresh deletion always recomputes it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RetentionSelection {
    request: RetentionRequest,
    candidates: Vec<RetentionCandidate>,
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
        e.text(RETENTION_SELECTION_DOMAIN);
        self.request.encode(e);
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
        }
    }
    pub(super) fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, DeletionError> {
        if d.text()? != RETENTION_SELECTION_DOMAIN {
            return Err(DeletionError::RecordMismatch);
        }
        let request = RetentionRequest::decode(d)?;
        let n = usize::try_from(d.u64()?).map_err(|_| DeletionError::RecordMismatch)?;
        if n > MAX_RETENTION_IMPORTS || n > d.remaining() / 108 {
            return Err(DeletionError::Bound {
                limit: "retention_selection_entries",
            });
        }
        let mut candidates = Vec::with_capacity(n);
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
            match (end, disposition) {
                (Some(end), state) if request.classify(end) == state => {}
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
            });
        }
        if candidates
            .windows(2)
            .any(|w| w[0].import_identity >= w[1].import_identity)
        {
            return Err(ContractError::NonCanonicalOrdering.into());
        }
        Ok(Self {
            request,
            candidates,
        })
    }
}

fn read_digest(d: &mut CanonicalDecoder<'_>) -> Result<ContentDigest, DeletionError> {
    let digest = d.digest()?;
    if digest.algorithm() != DigestAlgorithm::Sha256 {
        return Err(ContractError::UnsupportedDigestAlgorithm.into());
    }
    Ok(digest)
}

/// Actual selector work; graph-closure work is separately reported by the deletion plan.
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
pub fn assess_retention(
    deployment: &ReferenceDeployment,
    request: &RetentionRequest,
    cx: &ReplayCx,
) -> Result<RetentionAssessment, DeletionError> {
    checkpoint(cx)?;
    if cx.root_dir() != deployment.root() {
        return Err(DeletionError::RecordMismatch);
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
        });
    }
    checkpoint(cx)?;
    Ok(RetentionAssessment {
        selection: RetentionSelection {
            request: request.clone(),
            candidates,
        },
        ledger_entries: usage.entries,
        capsules: usage.capsules,
        metadata_bytes: usage.bytes,
        outside_sensor,
        incomplete_imports,
    })
}

/// Assessment plus one union-closure plan. No eligible imports means no deletion plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionPlan {
    /// Selection and exclusions from verified retained metadata.
    pub assessment: RetentionAssessment,
    /// One exact plan, including all existing hold and effect blockers, or nothing to delete.
    pub deletion: Option<DeletionPlan>,
}

/// Prepare one union deletion. Shared derivatives are classified once for the whole cohort.
pub fn plan_retention(
    deployment: &ReferenceDeployment,
    request: &RetentionRequest,
    cx: &ReplayCx,
) -> Result<RetentionPlan, DeletionError> {
    let assessment = assess_retention(deployment, request, cx)?;
    let deletion = if assessment.selection.imports().is_empty() {
        None
    } else {
        Some(super::plan_scope_deletion(
            deployment,
            &DeletionScope::Retention(assessment.selection.clone()),
            cx,
        )?)
    };
    Ok(RetentionPlan {
        assessment,
        deletion,
    })
}

pub(super) fn revalidate_selection(
    deployment: &ReferenceDeployment,
    selection: &RetentionSelection,
    cx: &ReplayCx,
) -> Result<(), DeletionError> {
    if assess_retention(deployment, selection.request(), cx)?.selection != *selection {
        return Err(DeletionError::RecordMismatch);
    }
    Ok(())
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
    let index = DeletionIndex::read(deployment)?;
    if let Some(entry) = index.plan(plan_digest) {
        if !matches!(&entry.plan.scope, DeletionScope::Retention(s) if s.request() == request) {
            return Err(DeletionError::StalePlan(plan_digest));
        }
        return super::commit_deletion(deployment, plan_digest, approval, principal, cx);
    }
    let assessment = assess_retention(deployment, request, cx)?;
    let scope = DeletionScope::Retention(assessment.selection);
    super::commit::commit_scope(deployment, &scope, plan_digest, approval, principal, cx)
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
            candidates: vec![RetentionCandidate {
                import_identity: ContentDigest::sha256(b"import"),
                manifest_digest: ContentDigest::sha256(b"manifest"),
                timing_digest: ContentDigest::sha256(b"timing"),
                end: Some(CaptureEnd {
                    earliest_ns: 80,
                    latest_ns: 90,
                }),
                disposition: RetentionDisposition::Eligible,
            }],
        };
        let mut e = CanonicalEncoder::new();
        selection.encode(&mut e);
        let bytes = e.finish_checked()?;
        let mut d = CanonicalDecoder::new(&bytes);
        assert_eq!(RetentionSelection::decode(&mut d)?, selection);
        d.ensure_finished()?;
        let original = selection.digest()?;
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
        };
        let selection = RetentionSelection {
            request: request(100, 100)?,
            candidates: vec![c.clone()],
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
}
