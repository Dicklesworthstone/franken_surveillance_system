#![forbid(unsafe_code)]
//! Logical source-byte accounting and age-constrained oldest-first cohort selection.
//!
//! A complete input-file identity counts once per sensor, regardless of repeated imports.
//! Only removing its last import from that sensor's complete inventory removes its logical
//! bytes. Shared storage, derivatives, other sensors and unfinished imports do not change
//! this accounting into a physical-space claim. The dependency walker remains authoritative
//! over actual deletion and every prospective union passes the same holds and effect gates.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm};

use super::{
    DeletionError, DeletionIndex, DeletionPlan, DeletionScope, MAX_BLOCKER_TEXT_BYTES,
    MAX_RETENTION_BLOCKERS, ReferenceDeployment, ReplayCx, RetentionAssessment, RetentionCandidate,
    RetentionDisposition, RetentionPlan, RetentionSelection, SelectionVersion, cohort_checkpoint,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct RetentionSource {
    pub(super) digest: ContentDigest,
    pub(super) bytes: u64,
}

/// Exact logical projection for distinct completed input files of the requested sensor.
///
/// These values bind the selected cohort, not a completed operation or physical disk usage.
/// The final deletion plan can still be blocked; only its successful commit realizes the
/// projected logical remainder. Unfinished imports and other sensors are outside this scope.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RetentionByteAccounting {
    /// Explicit owner target. Zero is valid and still cannot override the minimum age.
    pub max_retained_source_bytes: u64,
    /// Distinct full input-file bytes before the proposed deletion, including exclusions.
    pub before_source_bytes: u64,
    /// Logical bytes whose last same-sensor import belongs to the selected cohort.
    pub selected_source_bytes: u64,
    /// Distinct full input-file bytes still represented after the proposed deletion.
    pub projected_remaining_source_bytes: u64,
    /// Positive excess over the target, or zero when the projected remainder meets it.
    pub unmet_source_bytes: u64,
}

impl RetentionByteAccounting {
    pub(super) fn encode(&self, e: &mut CanonicalEncoder) {
        e.u64(self.max_retained_source_bytes);
        e.u64(self.before_source_bytes);
        e.u64(self.selected_source_bytes);
        e.u64(self.projected_remaining_source_bytes);
        e.u64(self.unmet_source_bytes);
    }

    pub(super) fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, DeletionError> {
        Ok(Self {
            max_retained_source_bytes: d.u64()?,
            before_source_bytes: d.u64()?,
            selected_source_bytes: d.u64()?,
            projected_remaining_source_bytes: d.u64()?,
            unmet_source_bytes: d.u64()?,
        })
    }
}

/// Length and retained import count for each distinct input-file identity.
type Sources = BTreeMap<ContentDigest, (u64, usize)>;

fn sources(candidates: &[RetentionCandidate]) -> Result<Sources, DeletionError> {
    let mut sources = Sources::new();
    for candidate in candidates {
        let source = candidate.source.ok_or(DeletionError::RecordMismatch)?;
        if source.bytes == 0 || source.digest.algorithm() != DigestAlgorithm::Sha256 {
            return Err(DeletionError::RecordMismatch);
        }
        let (bytes, count) = sources.entry(source.digest).or_insert((source.bytes, 0));
        if *bytes != source.bytes {
            return Err(DeletionError::RecordMismatch);
        }
        *count = count.checked_add(1).ok_or(DeletionError::Bound {
            limit: "retention_source_references",
        })?;
    }
    Ok(sources)
}

fn source_bytes(sources: &Sources) -> Result<u64, DeletionError> {
    sources.values().try_fold(0_u64, |total, &(bytes, _)| {
        total.checked_add(bytes).ok_or(DeletionError::Bound {
            limit: "retention_source_bytes",
        })
    })
}

/// Return the bytes released only if this was the last same-sensor import of the source.
fn remove_source(
    sources: &mut Sources,
    candidate: &RetentionCandidate,
) -> Result<u64, DeletionError> {
    let source = candidate.source.ok_or(DeletionError::RecordMismatch)?;
    let (bytes, count) = sources
        .get_mut(&source.digest)
        .ok_or(DeletionError::RecordMismatch)?;
    if *bytes != source.bytes || *count == 0 {
        return Err(DeletionError::RecordMismatch);
    }
    *count -= 1;
    if *count == 0 {
        sources.remove(&source.digest);
        Ok(source.bytes)
    } else {
        Ok(0)
    }
}

fn accounting(selection: &RetentionSelection) -> Result<RetentionByteAccounting, DeletionError> {
    let maximum = selection
        .request
        .source_byte_budget
        .ok_or(DeletionError::RecordMismatch)?;
    let mut retained = sources(&selection.candidates)?;
    let before = source_bytes(&retained)?;
    for candidate in &selection.candidates {
        if candidate.disposition == RetentionDisposition::Eligible {
            remove_source(&mut retained, candidate)?;
        }
    }
    let remaining = source_bytes(&retained)?;
    Ok(RetentionByteAccounting {
        max_retained_source_bytes: maximum,
        before_source_bytes: before,
        selected_source_bytes: before
            .checked_sub(remaining)
            .ok_or(DeletionError::RecordMismatch)?,
        projected_remaining_source_bytes: remaining,
        // Saturation is intentional only for this nonnegative deficit. All inventory sums
        // and selected/remainder differences above are checked and can never wrap or clamp.
        unmet_source_bytes: remaining.saturating_sub(maximum),
    })
}

/// The latest possible capture controls both the age floor and oldest-first order.
/// Canonical candidate storage itself remains in strictly ascending import-identity order.
fn age_order(selection: &RetentionSelection) -> Vec<usize> {
    let mut order: Vec<_> = selection
        .candidates
        .iter()
        .enumerate()
        .filter_map(|(i, candidate)| {
            candidate
                .end
                .filter(|&end| selection.request.classify(end) == RetentionDisposition::Eligible)
                .map(|end| (end.latest_ns, candidate.import_identity, i))
        })
        .collect();
    order.sort_unstable();
    order.into_iter().map(|(_, _, i)| i).collect()
}

/// Reject forged sums, digest/length aliases and policies that skip older unblocked imports
/// or continue evicting after reaching the target. Closure witnesses are revalidated against
/// the deployment before any new authority is granted.
pub(super) fn verify_selection(selection: &RetentionSelection) -> Result<(), DeletionError> {
    let expected = accounting(selection)?;
    if selection.version != SelectionVersion::ByteBudget
        || selection.byte_accounting.as_ref() != Some(&expected)
    {
        return Err(DeletionError::RecordMismatch);
    }
    let mut retained = sources(&selection.candidates)?;
    let mut remaining = expected.before_source_bytes;
    for i in age_order(selection) {
        let candidate = &selection.candidates[i];
        if remaining <= expected.max_retained_source_bytes {
            if candidate.disposition != RetentionDisposition::BudgetRetained {
                return Err(DeletionError::RecordMismatch);
            }
        } else {
            match candidate.disposition {
                RetentionDisposition::Eligible => {
                    remaining = remaining
                        .checked_sub(remove_source(&mut retained, candidate)?)
                        .ok_or(DeletionError::RecordMismatch)?;
                }
                RetentionDisposition::ClosureBlocked => {}
                _ => return Err(DeletionError::RecordMismatch),
            }
        }
    }
    if remaining != expected.projected_remaining_source_bytes {
        return Err(DeletionError::RecordMismatch);
    }
    Ok(())
}

/// Build the same internal age-domain closure trial used by age-only partial cleanup. It
/// carries no byte-budget assertion and cannot stand in for the complete final v3 selection.
fn trial_selection(
    selection: &RetentionSelection,
    selected: &BTreeSet<ContentDigest>,
    next: usize,
) -> RetentionSelection {
    let identity = selection.candidates[next].import_identity;
    let mut request = selection.request.clone();
    request.source_byte_budget = None;
    RetentionSelection {
        request,
        candidates: selection
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.import_identity == identity
                    || selected.contains(&candidate.import_identity)
            })
            .map(|candidate| {
                let mut candidate = candidate.clone();
                candidate.disposition = RetentionDisposition::Eligible;
                candidate.source = None;
                candidate
            })
            .collect(),
        version: SelectionVersion::Age,
        byte_accounting: None,
    }
}

pub(super) fn plan(
    deployment: &ReferenceDeployment,
    mut assessment: RetentionAssessment,
    cx: &ReplayCx,
) -> Result<RetentionPlan, DeletionError> {
    let mut selection = assessment.selection.clone();
    let maximum = selection
        .request
        .source_byte_budget
        .ok_or(DeletionError::RecordMismatch)?;
    let order = age_order(&selection);
    let mut retained = sources(&selection.candidates)?;
    let mut remaining = source_bytes(&retained)?;
    for &i in &order {
        selection.candidates[i].disposition = RetentionDisposition::BudgetRetained;
    }
    if remaining <= maximum || order.is_empty() {
        selection.byte_accounting = Some(accounting(&selection)?);
        verify_selection(&selection)?;
        assessment.selection = selection;
        return Ok(RetentionPlan {
            assessment,
            deletion: None,
        });
    }

    cohort_checkpoint(cx)?;
    let index = DeletionIndex::read(deployment)?;
    let holds = super::super::holds::HoldIndex::read(deployment, cx)?;
    let universe = super::super::walk::Universe::scan(deployment, &index, cx)?;
    let protection = holds.protection(&universe, deployment, cx)?;
    assessment.held_closures = protection.len();
    let mut evaluate = |selection: &RetentionSelection| -> Result<DeletionPlan, DeletionError> {
        cohort_checkpoint(cx)?;
        assessment.closure_evaluations += 1;
        let plan = universe.plan(deployment, &DeletionScope::Retention(selection.clone()))?;
        assessment.closure_scanned_objects = plan.scanned_objects;
        assessment.closure_scanned_bytes = plan.scanned_bytes;
        super::super::commit::admit_plan(deployment, protection.protect(plan, cx)?, cx)
    };
    let mut selected = BTreeSet::new();
    let mut total_blockers = 0;
    for i in order {
        if remaining <= maximum {
            break;
        }
        let proposed = trial_selection(&selection, &selected, i);
        let trial = evaluate(&proposed)?;
        let candidate = &mut selection.candidates[i];
        if trial.blockers.is_empty() {
            candidate.disposition = RetentionDisposition::Eligible;
            selected.insert(candidate.import_identity);
            remaining = remaining
                .checked_sub(remove_source(&mut retained, candidate)?)
                .ok_or(DeletionError::RecordMismatch)?;
        } else {
            if trial.blockers.len() > MAX_RETENTION_BLOCKERS - total_blockers {
                return Err(DeletionError::Bound {
                    limit: "retention_blockers",
                });
            }
            total_blockers += trial.blockers.len();
            if trial.blockers.iter().any(|f| {
                [&f.kind, &f.subject, &f.detail]
                    .iter()
                    .any(|text| text.is_empty() || text.len() > MAX_BLOCKER_TEXT_BYTES)
            }) {
                return Err(DeletionError::Bound {
                    limit: "retention_blocker_text",
                });
            }
            candidate.disposition = RetentionDisposition::ClosureBlocked;
            candidate.closure_witness = Some(trial.digest()?);
            candidate.blockers = trial.blockers;
        }
    }
    selection.byte_accounting = Some(accounting(&selection)?);
    verify_selection(&selection)?;
    // Exact full v3 bytes, all exclusions, holds and aggregate publication bounds are bound
    // by this final evaluation. Its blockers remain authoritative over the projection.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deletion::retention::{
        CaptureEnd, RETENTION_BYTE_SELECTION_DOMAIN, RetentionRequest,
    };
    use fss_core::{CaptureInterval, SensorId, TimestampNs};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn candidate(
        label: &[u8],
        source: &[u8],
        bytes: u64,
        end: i128,
        disposition: RetentionDisposition,
    ) -> RetentionCandidate {
        RetentionCandidate {
            import_identity: ContentDigest::sha256(label),
            manifest_digest: ContentDigest::sha256(b"manifest"),
            timing_digest: ContentDigest::sha256(b"timing"),
            end: Some(CaptureEnd {
                earliest_ns: end,
                latest_ns: end,
            }),
            disposition,
            blockers: Vec::new(),
            closure_witness: None,
            source: Some(RetentionSource {
                digest: ContentDigest::sha256(source),
                bytes,
            }),
        }
    }

    fn selection() -> Result<RetentionSelection, DeletionError> {
        let mut selection = RetentionSelection {
            request: RetentionRequest::new(
                SensorId::parse("sensor:budget")?,
                10,
                CaptureInterval::new(TimestampNs(100), TimestampNs(100))?,
            )?
            .with_source_byte_budget(60),
            candidates: vec![
                candidate(
                    b"first",
                    b"shared-source",
                    40,
                    0,
                    RetentionDisposition::Eligible,
                ),
                candidate(
                    b"second",
                    b"shared-source",
                    40,
                    10,
                    RetentionDisposition::Eligible,
                ),
                candidate(
                    b"third",
                    b"distinct-source",
                    60,
                    20,
                    RetentionDisposition::BudgetRetained,
                ),
            ],
            version: SelectionVersion::ByteBudget,
            byte_accounting: None,
        };
        selection
            .candidates
            .sort_by_key(|candidate| candidate.import_identity);
        selection.byte_accounting = Some(accounting(&selection)?);
        Ok(selection)
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
    fn v3_binds_distinct_source_accounting_and_exact_request() -> TestResult {
        let selection = selection()?;
        assert_eq!(decoded(&selection)?, selection);
        assert_eq!(selection.domain(), RETENTION_BYTE_SELECTION_DOMAIN);
        assert_eq!(
            selection.byte_accounting(),
            Some(&RetentionByteAccounting {
                max_retained_source_bytes: 60,
                before_source_bytes: 100,
                selected_source_bytes: 40,
                projected_remaining_source_bytes: 60,
                unmet_source_bytes: 0,
            })
        );
        let digest = selection.digest()?;
        let mut changed = selection.clone();
        changed.request.source_byte_budget = Some(61);
        changed.byte_accounting = Some(accounting(&changed)?);
        assert_eq!(decoded(&changed)?, changed);
        assert_ne!(changed.digest()?, digest);
        assert_eq!(changed.imports(), selection.imports());
        Ok(())
    }

    #[test]
    fn v3_rejects_forged_sums_missing_sources_and_digest_length_aliases() -> TestResult {
        let good = selection()?;
        for mutation in 0..10 {
            let mut bad = good.clone();
            let bytes = bad.byte_accounting.as_mut().ok_or("missing accounting")?;
            match mutation {
                0 => bytes.max_retained_source_bytes += 1,
                1 => bytes.before_source_bytes += 1,
                2 => bytes.selected_source_bytes += 1,
                3 => bytes.projected_remaining_source_bytes += 1,
                4 => bytes.unmet_source_bytes += 1,
                5 => bad.byte_accounting = None,
                6 => bad.request.source_byte_budget = None,
                7 => bad.candidates[0].source = None,
                8 => bad.candidates[0].source.as_mut().ok_or("source")?.bytes = 0,
                _ => {
                    let duplicate = bad
                        .candidates
                        .iter_mut()
                        .find(|c| {
                            c.source_digest() == Some(ContentDigest::sha256(b"shared-source"))
                        })
                        .ok_or("duplicate source")?;
                    duplicate.source.as_mut().ok_or("source")?.bytes += 1;
                }
            }
            assert!(decoded(&bad).is_err(), "mutation {mutation}");
        }
        let mut overflow = good;
        for candidate in &mut overflow.candidates {
            if candidate.source_digest() == Some(ContentDigest::sha256(b"shared-source")) {
                candidate.source.as_mut().ok_or("source")?.bytes = u64::MAX;
            }
        }
        assert!(matches!(
            decoded(&overflow),
            Err(DeletionError::Bound {
                limit: "retention_source_bytes",
            })
        ));
        Ok(())
    }

    #[test]
    fn v3_rejects_skipping_older_recordings_or_selecting_after_target_is_met() -> TestResult {
        let good = selection()?;
        for mutation in 0..3 {
            let mut bad = good.clone();
            let oldest = bad
                .candidates
                .iter()
                .position(|candidate| candidate.import_identity == ContentDigest::sha256(b"first"))
                .ok_or("oldest")?;
            let newest = bad
                .candidates
                .iter()
                .position(|candidate| candidate.import_identity == ContentDigest::sha256(b"third"))
                .ok_or("newest")?;
            match mutation {
                0 => bad.candidates[oldest].disposition = RetentionDisposition::BudgetRetained,
                1 => bad.candidates[newest].disposition = RetentionDisposition::Eligible,
                _ => {
                    // Make the retained candidate older than the selected ones, preserving
                    // otherwise valid age classifications and recomputed accounting.
                    bad.candidates[newest].end = Some(CaptureEnd {
                        earliest_ns: -1,
                        latest_ns: -1,
                    });
                }
            }
            bad.byte_accounting = Some(accounting(&bad)?);
            assert!(decoded(&bad).is_err(), "mutation {mutation}");
        }
        Ok(())
    }

    #[test]
    fn equal_capture_ends_use_import_identity_and_zero_target_keeps_unknown_sources() -> TestResult
    {
        let mut selection = selection()?;
        selection.request.source_byte_budget = Some(0);
        for candidate in &mut selection.candidates {
            candidate.end = None;
            candidate.disposition = RetentionDisposition::CaptureTimeUnknown;
        }
        selection.byte_accounting = Some(accounting(&selection)?);
        assert_eq!(decoded(&selection)?, selection);
        assert_eq!(
            selection
                .byte_accounting()
                .ok_or("accounting")?
                .unmet_source_bytes,
            100
        );
        for candidate in &mut selection.candidates {
            candidate.end = Some(CaptureEnd {
                earliest_ns: 0,
                latest_ns: 0,
            });
            candidate.disposition = RetentionDisposition::Eligible;
        }
        assert_eq!(age_order(&selection), vec![0, 1, 2]);
        selection.byte_accounting = Some(accounting(&selection)?);
        assert_eq!(decoded(&selection)?, selection);
        assert_eq!(
            selection
                .byte_accounting()
                .ok_or("accounting")?
                .projected_remaining_source_bytes,
            0
        );
        Ok(())
    }
}
