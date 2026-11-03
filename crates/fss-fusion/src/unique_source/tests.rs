#![forbid(unsafe_code)]
//! Behavioral contracts for bounded declared-source replay prevention.

use super::*;
use crate::{Coverage, FusionPolicy, LlrInterval, Severity};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn item(id: &str, sensor: &str) -> Result<EvidenceItem, FusionError> {
    Ok(EvidenceItem {
        id: id.to_owned(),
        sensor: sensor.to_owned(),
        failure_domains: [format!("sensor:{sensor}")].into_iter().collect(),
        calibration: Calibration::Calibrated {
            generation: "cal:v1".to_owned(),
            llr: LlrInterval::new(700, 900)?,
        },
        observability: Observability::Observed,
    })
}

fn query(evidence: Vec<EvidenceItem>) -> Result<FusionQuery, FusionError> {
    Ok(FusionQuery {
        hypothesis: "hyp:door".to_owned(),
        kind: "zone_entry".to_owned(),
        prior: LlrInterval::point(0)?,
        evidence,
        coverage: Coverage::Complete,
        opportunities: Vec::new(),
        probes: Vec::new(),
        severity: Severity {
            expected_harm: 10_000,
            false_alert_cost: 500,
            delay_cost_per_second: 100,
            reversible: false,
        },
        policy: FusionPolicy {
            generation: "policy:v1".to_owned(),
            alert_threshold: 1_800,
            retain_threshold: 0,
            reject_threshold: -1_000,
            min_independent_support: 2,
            urgent_single_domain_threshold: None,
            max_wait_ns: 0,
            look_penalty_per_doubling: 0,
            operator_confirmation_available: false,
        },
        looks: 1,
        now_ns: 1_000_000_000,
    })
}

fn bindings(rows: &[(&str, Option<&str>)]) -> BTreeMap<String, Option<ContentDigest>> {
    rows.iter()
        .map(|(id, source)| {
            (
                (*id).to_owned(),
                source.map(|source| ContentDigest::sha256(source.as_bytes())),
            )
        })
        .collect()
}

fn process(limit: usize) -> Result<UniqueSourceEProcess, UniqueSourceError> {
    UniqueSourceEProcess::new("hyp:door", EProcessConfig::default(), limit)
}

#[test]
fn replayed_sources_cannot_cross_an_alert_threshold_under_new_aliases() -> TestResult {
    let first = query(vec![item("east:0", "east")?, item("west:0", "west")?])?;
    let initial = bindings(&[
        ("east:0", Some("frame:east")),
        ("west:0", Some("frame:west")),
    ]);
    let mut unique = process(2)?;
    let mut legacy = SequentialEProcess::new("hyp:door", EProcessConfig::default())?;
    let (_, admitted) = unique.observe_step(&first, &initial)?;
    let (_, legacy_first) = legacy.observe_step(&first)?;
    assert_eq!(admitted.step(), &legacy_first);
    assert_eq!(
        admitted.step().accumulated_llr,
        LlrInterval::new(1_400, 1_800)?
    );
    assert!(!admitted.step().crossed_alert_threshold);

    let mut repeated = query(vec![item("east:999", "east")?, item("west:999", "west")?])?;
    repeated.looks = 2;
    repeated.now_ns += 1;
    let (_, replay) = unique.observe_step(
        &repeated,
        &bindings(&[
            ("east:999", Some("frame:east")),
            ("west:999", Some("frame:west")),
        ]),
    )?;
    let (_, legacy_replay) = legacy.observe_step(&repeated)?;
    assert!(
        legacy_replay.crossed_alert_threshold,
        "historical window behavior is unchanged"
    );
    assert!(!replay.step().crossed_alert_threshold);
    assert_eq!(replay.step().step_delta_llr, LlrInterval::point(0)?);
    assert_eq!(
        replay.step().accumulated_llr,
        admitted.step().accumulated_llr
    );
    assert_eq!(unique.sources_seen(), 2);
    assert_eq!(replay.inventory_digest(), admitted.inventory_digest());
    assert_eq!(replay.previous(), Some(admitted.digest()));
    assert_eq!(replay.submitted_query_digest(), Some(repeated.digest()));
    assert_ne!(
        replay.submitted_query_digest(),
        replay.effective_query_digest()
    );
    assert!(
        replay
            .admissions()
            .iter()
            .all(|row| row.disposition() == SourceDisposition::AlreadyAdmitted)
    );
    Ok(())
}

#[test]
fn mixed_steps_add_only_new_sources_and_do_not_drop_neutral_rows() -> TestResult {
    let mut unique = process(3)?;
    unique.observe_step(
        &query(vec![item("east:0", "east")?])?,
        &bindings(&[("east:0", Some("east"))]),
    )?;
    let mut neutral = item("south:missing", "south")?;
    neutral.observability = Observability::NotObservable {
        reason: "occluded".to_owned(),
    };
    let mut mixed = query(vec![
        item("east:1", "east")?,
        item("west:1", "west")?,
        neutral,
    ])?;
    mixed.coverage = Coverage::Gap {
        reason: "south occluded".to_owned(),
    };
    let (fusion, step) = unique.observe_step(
        &mixed,
        &bindings(&[
            ("east:1", Some("east")),
            ("west:1", Some("west")),
            ("south:missing", None),
        ]),
    )?;
    assert_eq!(step.step().step_delta_llr, LlrInterval::new(700, 900)?);
    assert_eq!(step.step().accumulated_llr, LlrInterval::new(1_400, 1_800)?);
    assert_eq!(step.sources_seen(), 2);
    let mut effective = mixed.clone();
    effective.evidence.retain(|item| item.id != "east:1");
    assert_eq!(fusion, crate::fuse(&effective)?);
    assert_eq!(step.effective_query_digest(), Some(effective.digest()));
    let diagnostic = step
        .admissions()
        .iter()
        .find(|row| row.evidence_id() == "south:missing")
        .ok_or("diagnostic row")?;
    assert_eq!(diagnostic.disposition(), SourceDisposition::NonNumeric);
    assert_eq!(diagnostic.source_digest(), None);
    assert_eq!(diagnostic.first_admitted_step(), None);
    Ok(())
}

#[test]
fn same_step_aliases_and_input_permutation_admit_one_canonical_source() -> TestResult {
    let first = query(vec![item("alias:z", "east")?, item("alias:a", "east")?])?;
    let mapping = bindings(&[
        ("alias:z", Some("same-frame")),
        ("alias:a", Some("same-frame")),
    ]);
    let mut reordered = first.clone();
    reordered.evidence.reverse();
    let mut a = process(1)?;
    let mut b = process(1)?;
    let observed = a.observe_step(&first, &mapping)?;
    assert_eq!(observed, b.observe_step(&reordered, &mapping)?);
    assert_eq!(
        observed.1.step().step_delta_llr,
        LlrInterval::new(700, 900)?
    );
    assert_eq!(observed.1.sources_seen(), 1);
    assert_eq!(observed.1.admissions()[0].evidence_id(), "alias:a");
    assert_eq!(
        observed.1.admissions()[0].disposition(),
        SourceDisposition::Admitted
    );
    assert_eq!(
        observed.1.admissions()[1].disposition(),
        SourceDisposition::AlreadyAdmitted
    );
    assert_eq!(observed.1.admissions()[1].first_admitted_step(), Some(1));
    Ok(())
}

#[test]
fn refuting_and_zero_likelihood_sources_are_consumed_once_too() -> TestResult {
    let mut unique = process(3)?;
    unique.observe_step(
        &query(vec![item("positive", "east")?])?,
        &bindings(&[("positive", Some("positive"))]),
    )?;
    let mut negative = item("negative", "west")?;
    negative.calibration = Calibration::Calibrated {
        generation: "cal:v1".to_owned(),
        llr: LlrInterval::new(-300, -100)?,
    };
    let negative = query(vec![negative])?;
    let (_, admitted) =
        unique.observe_step(&negative, &bindings(&[("negative", Some("negative"))]))?;
    let (_, replay) =
        unique.observe_step(&negative, &bindings(&[("negative", Some("negative"))]))?;
    assert_eq!(
        admitted.step().step_delta_llr,
        LlrInterval::new(-300, -100)?
    );
    assert_eq!(replay.step().step_delta_llr, LlrInterval::point(0)?);
    assert_eq!(
        admitted.step().accumulated_llr,
        replay.step().accumulated_llr
    );
    let mut zero = item("zero", "north")?;
    zero.calibration = Calibration::Calibrated {
        generation: "cal:v1".to_owned(),
        llr: LlrInterval::point(0)?,
    };
    let (_, zero) =
        unique.observe_step(&query(vec![zero])?, &bindings(&[("zero", Some("zero"))]))?;
    assert_eq!(zero.sources_seen(), 3);
    assert_eq!(
        zero.admissions()[0].disposition(),
        SourceDisposition::Admitted
    );
    Ok(())
}

#[test]
fn conflicting_consumed_source_semantics_refuse_every_field_transactionally() -> TestResult {
    let original = query(vec![item("source", "east")?])?;
    let mapping = bindings(&[("source", Some("frame"))]);
    let mut baseline = process(4)?;
    baseline.observe_step(&original, &mapping)?;
    let mut mutations = Vec::new();
    let mut changed = original.clone();
    changed.evidence[0].sensor = "different".to_owned();
    mutations.push(changed);
    let mut changed = original.clone();
    changed.evidence[0]
        .failure_domains
        .insert("model:new".to_owned());
    mutations.push(changed);
    let mut changed = original.clone();
    changed.evidence[0].calibration = Calibration::Calibrated {
        generation: "cal:v2".to_owned(),
        llr: LlrInterval::new(700, 900)?,
    };
    mutations.push(changed);
    let mut changed = original.clone();
    changed.evidence[0].calibration = Calibration::Calibrated {
        generation: "cal:v1".to_owned(),
        llr: LlrInterval::new(701, 900)?,
    };
    mutations.push(changed);
    let mut changed = original.clone();
    changed.evidence[0].calibration = Calibration::Uncalibrated {
        reason: "expired".to_owned(),
    };
    mutations.push(changed);
    let mut changed = original.clone();
    changed.evidence[0].observability = Observability::Redacted;
    mutations.push(changed);
    let mut changed = original.clone();
    changed.evidence[0].observability = Observability::Stale;
    mutations.push(changed);
    let mut changed = original.clone();
    changed.evidence[0].observability = Observability::NotObservable {
        reason: "occluded".to_owned(),
    };
    mutations.push(changed);
    let mut changed = original.clone();
    changed.kind = "other-event".to_owned();
    mutations.push(changed);
    let next = query(vec![item("next", "west")?])?;
    let next_bindings = bindings(&[("next", Some("new-frame"))]);
    for changed in mutations {
        let mut actual = baseline.clone();
        let mut untouched = baseline.clone();
        assert!(matches!(
            actual.observe_step(&changed, &mapping),
            Err(UniqueSourceError::ConflictingSource { .. })
        ));
        assert_eq!(actual.sources_seen(), 1);
        assert_eq!(actual.transcript_head(), untouched.transcript_head());
        assert_eq!(
            actual.observe_step(&next, &next_bindings)?,
            untouched.observe_step(&next, &next_bindings)?
        );
    }
    Ok(())
}

#[test]
fn conflicting_aliases_in_one_query_never_commit_a_valid_prefix() -> TestResult {
    let a = item("a", "east")?;
    let b = item("b", "west")?;
    let invalid = query(vec![a.clone(), b])?;
    let mut unique = process(1)?;
    assert!(matches!(
        unique.observe_step(
            &invalid,
            &bindings(&[("a", Some("same")), ("b", Some("same"))])
        ),
        Err(UniqueSourceError::ConflictingSource { .. })
    ));
    assert_eq!(unique.sources_seen(), 0);
    assert_eq!(unique.transcript_head(), None);
    let valid = query(vec![a])?;
    assert_eq!(
        unique.observe_step(&valid, &bindings(&[("a", Some("same"))]))?,
        process(1)?.observe_step(&valid, &bindings(&[("a", Some("same"))]))?
    );
    Ok(())
}

#[test]
fn complete_original_validation_and_binding_inventory_precede_filtering() -> TestResult {
    let original = query(vec![item("source", "east")?])?;
    let original_bindings = bindings(&[("source", Some("source"))]);
    let mut baseline = process(2)?;
    baseline.observe_step(&original, &original_bindings)?;
    for invalid in [
        BTreeMap::new(),
        bindings(&[("source", None)]),
        bindings(&[("wrong", Some("source"))]),
        bindings(&[("source", Some("source")), ("extra", None)]),
    ] {
        let mut actual = baseline.clone();
        assert!(matches!(
            actual.observe_step(&original, &invalid),
            Err(UniqueSourceError::InvalidBindings)
        ));
        assert_eq!(actual.transcript_head(), baseline.transcript_head());
    }
    let mut duplicate = original.clone();
    duplicate.evidence.push(duplicate.evidence[0].clone());
    assert!(matches!(
        baseline.observe_step(&duplicate, &original_bindings),
        Err(UniqueSourceError::Fusion(FusionError::InvalidInput(_)))
    ));
    let mut malformed = original.clone();
    malformed.evidence[0].sensor.clear();
    assert!(matches!(
        baseline.observe_step(&malformed, &original_bindings),
        Err(UniqueSourceError::Fusion(FusionError::InvalidInput(_)))
    ));
    let mut foreign = original.clone();
    foreign.hypothesis = "hyp:foreign".to_owned();
    assert!(matches!(
        baseline.observe_step(&foreign, &original_bindings),
        Err(UniqueSourceError::Fusion(FusionError::InvalidInput(_)))
    ));
    assert_eq!(baseline.sources_seen(), 1);
    assert_eq!(baseline.accumulator().step_index(), 1);
    Ok(())
}

#[test]
fn neutral_first_sighting_does_not_burn_source_identity_or_capacity() -> TestResult {
    let observed = query(vec![item("same", "east")?])?;
    let mut neutral = observed.clone();
    neutral.evidence[0].calibration = Calibration::Uncalibrated {
        reason: "not yet calibrated".to_owned(),
    };
    let mut unique = process(1)?;
    let mapping = bindings(&[("same", Some("frame"))]);
    let (_, first) = unique.observe_step(&neutral, &mapping)?;
    assert_eq!(first.sources_seen(), 0);
    assert_eq!(
        first.admissions()[0].disposition(),
        SourceDisposition::NonNumeric
    );
    assert_eq!(first.step().step_delta_llr, LlrInterval::point(0)?);
    let (_, actual) = unique.observe_step(&observed, &mapping)?;
    assert_eq!(actual.sources_seen(), 1);
    assert_eq!(actual.admissions()[0].first_admitted_step(), Some(2));
    assert_eq!(actual.step().step_delta_llr, LlrInterval::new(700, 900)?);
    Ok(())
}

#[test]
fn bounded_capacity_refuses_complete_step_without_eviction_and_survives_resets() -> TestResult {
    assert!(process(0).is_err());
    assert!(process(MAX_UNIQUE_SOURCES + 1).is_err());
    let first = query(vec![item("a", "east")?])?;
    let first_bindings = bindings(&[("a", Some("a"))]);
    let mut unique = process(1)?;
    let (_, admitted) = unique.observe_step(&first, &first_bindings)?;
    let mut untouched = unique.clone();
    let mixed = query(vec![item("a", "east")?, item("b", "west")?])?;
    assert!(matches!(
        unique.observe_step(&mixed, &bindings(&[("a", Some("a")), ("b", Some("b"))])),
        Err(UniqueSourceError::SourceCapacity {
            limit: 1,
            existing: 1,
            additional: 1
        })
    ));
    assert_eq!(
        unique.observe_step(&first, &first_bindings)?,
        untouched.observe_step(&first, &first_bindings)?
    );
    let before = unique.transcript_head();
    let reset = unique.reset_regime(RegimeResetReason::OperatorReset {
        reason: "new numeric regime".to_owned(),
    });
    assert_eq!(reset.previous(), before);
    assert_eq!(reset.submitted_query_digest(), None);
    assert_eq!(reset.effective_query_digest(), None);
    assert!(reset.admissions().is_empty());
    assert_eq!(reset.sources_seen(), 1);
    assert_eq!(reset.inventory_digest(), admitted.inventory_digest());
    let (_, replay) = unique.observe_step(&first, &first_bindings)?;
    assert_eq!(replay.step().accumulated_llr, LlrInterval::point(0)?);
    assert_eq!(replay.step().independent_supporting_clusters, 0);
    assert_eq!(replay.previous(), Some(reset.digest()));
    assert!(matches!(
        unique.observe_step(&mixed, &bindings(&[("a", Some("a")), ("b", Some("b"))])),
        Err(UniqueSourceError::SourceCapacity { .. })
    ));
    Ok(())
}

#[test]
fn canonical_source_algorithm_and_bytes_ignore_nonencoded_laboratory_aliases() -> TestResult {
    let original = query(vec![item("a", "east")?])?;
    let key = ContentDigest::sha256(b"same");
    let plain = [("a".to_owned(), Some(key))].into_iter().collect();
    let marked = [("a".to_owned(), Some(key.with_laboratory(true)))]
        .into_iter()
        .collect();
    let mut unique = process(1)?;
    let (_, first) = unique.observe_step(&original, &plain)?;
    let (_, same_first) = process(1)?.observe_step(&original, &marked)?;
    assert_eq!(first, same_first);
    let (_, replay) = unique.observe_step(&original, &marked)?;
    assert_eq!(replay.sources_seen(), 1);
    assert_eq!(replay.admissions()[0].source_digest(), Some(key));
    assert_eq!(
        replay.admissions()[0].disposition(),
        SourceDisposition::AlreadyAdmitted
    );
    let other_algorithm = ContentDigest::new(fss_core::DigestAlgorithm::Blake3, key.bytes());
    assert!(matches!(
        unique.observe_step(
            &original,
            &[("a".to_owned(), Some(other_algorithm))]
                .into_iter()
                .collect()
        ),
        Err(UniqueSourceError::SourceCapacity { .. })
    ));
    Ok(())
}

#[test]
fn profile_capacity_source_bindings_and_replay_dispositions_are_digest_bound() -> TestResult {
    let original = query(vec![item("a", "east")?])?;
    let map_a = bindings(&[("a", Some("frame:a"))]);
    let map_b = bindings(&[("a", Some("frame:b"))]);
    let mut one = process(1)?;
    let (_, first) = one.observe_step(&original, &map_a)?;
    let (_, capacity_changed) = process(2)?.observe_step(&original, &map_a)?;
    let (_, source_changed) = process(1)?.observe_step(&original, &map_b)?;
    assert_eq!(first.step(), capacity_changed.step());
    assert_eq!(first.step(), source_changed.step());
    assert_ne!(first.digest(), capacity_changed.digest());
    assert_ne!(first.digest(), source_changed.digest());
    assert_ne!(first.inventory_digest(), source_changed.inventory_digest());
    let (_, replay) = one.observe_step(&original, &map_a)?;
    assert_ne!(first.digest(), replay.digest());
    assert_eq!(
        first.submitted_query_digest(),
        replay.submitted_query_digest()
    );
    assert_ne!(
        first.effective_query_digest(),
        replay.effective_query_digest()
    );
    Ok(())
}

#[test]
fn empty_inventory_binds_capacity_before_any_observation_and_through_reset() -> TestResult {
    let mut first = process(1)?;
    let initial = first.inventory_digest();
    assert_eq!(initial, process(1)?.inventory_digest());
    assert_ne!(initial, process(2)?.inventory_digest());
    let reset = first.reset_regime(RegimeResetReason::OperatorReset {
        reason: "empty reset".to_owned(),
    });
    assert_eq!(initial, reset.inventory_digest());
    assert_eq!(initial, first.inventory_digest());
    let observed = query(vec![item("a", "east")?])?;
    let (_, next) = first.observe_step(&observed, &bindings(&[("a", Some("frame"))]))?;
    assert_ne!(initial, next.inventory_digest());
    assert_eq!(next.inventory_digest(), first.inventory_digest());
    Ok(())
}
