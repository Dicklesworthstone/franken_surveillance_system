use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SECOND: i128 = 1_000_000_000;
const TENTH: i128 = 100_000_000;
const UNCERTAINTY: i128 = 1_000_000;

fn frame(segment: usize) -> Result<CoverageFrame, ContractError> {
    let center = SECOND + segment as i128 * TENTH;
    Ok(CoverageFrame {
        segment,
        capture: CaptureInterval::new(
            TimestampNs(center - UNCERTAINTY),
            TimestampNs(center + UNCERTAINTY),
        )?,
    })
}

fn frames(segments: impl IntoIterator<Item = usize>) -> Result<Vec<CoverageFrame>, ContractError> {
    segments.into_iter().map(frame).collect()
}

fn zone(entries: Vec<CoverageEntry>, inside_frame: bool) -> CoverageZoneInput {
    CoverageZoneInput {
        zone_id: "door".to_owned(),
        geometry: "64,0,32,32".to_owned(),
        inside_frame,
        pipeline_generation: ContentDigest::sha256(b"generation"),
        entries,
    }
}

fn input<'a>(
    frames: &'a [CoverageFrame],
    gaps: &'a [bool],
    label: &'a str,
    zones: Vec<CoverageZoneInput>,
) -> CoverageInput<'a> {
    CoverageInput {
        source: CoverageSource::Watch,
        import_identity: ContentDigest::sha256(b"import"),
        import_root: ContentDigest::sha256(b"root"),
        sensor_id: "sensor:test",
        analysis_digest: ContentDigest::sha256(b"analysis"),
        basis: LedgerAnchor::genesis("site:test"),
        capture_time_label: label,
        segment_gaps: gaps,
        first_segment: frames.first().map_or(0, |f| f.segment),
        last_segment: frames.last().map_or(0, |f| f.segment),
        frames,
        confirmation_hits: 3,
        zones,
    }
}

fn reasons(zone: &ZoneCoverage) -> Vec<(&'static str, u64, u64)> {
    zone.uncovered
        .iter()
        .map(|gap| (gap.reason.as_str(), gap.first_segment, gap.last_segment))
        .collect()
}

#[test]
fn quiet_run_excludes_warmup_and_latency_and_certifies_the_rest() -> TestResult {
    let frames = frames(0..14)?;
    let gaps = vec![false; 14];
    let record = build_coverage(&input(
        &frames,
        &gaps,
        OPERATOR_TIME_LABEL,
        vec![zone(Vec::new(), true)],
    ))?;
    let door = &record.zones[0];
    assert_eq!(door.scope, "zone:door");
    assert_eq!(door.witnesses.len(), 1);
    let witness = &door.witnesses[0];
    assert_eq!(
        (witness.first_segment, witness.last_segment, witness.frames),
        (4, 11, 8)
    );
    // Certain bounds: latest capture of frame 4 to earliest capture of frame 11.
    assert_eq!(witness.covered.earliest.0, SECOND + 4 * TENTH + UNCERTAINTY);
    assert_eq!(witness.covered.latest.0, SECOND + 11 * TENTH - UNCERTAINTY);
    assert!(witness.witness.certifies_absence());
    assert_eq!(
        witness.witness.authorized_generation,
        COVERAGE_PRODUCER_GENERATION
    );
    assert_eq!(
        reasons(door),
        vec![
            ("background_warmup", 0, BACKGROUND_WARMUP_FRAMES as u64 - 1),
            ("confirmation_latency", 12, 13)
        ]
    );
    // Round trip through the exact retained bytes.
    let bytes = record.to_bytes();
    let decoded = CoverageRecord::from_bytes(&bytes, ContentDigest::sha256(&bytes))?;
    assert_eq!(decoded, record);
    assert_eq!(decoded.digest(), record.digest());
    Ok(())
}

#[test]
fn unknown_capture_time_and_zone_outside_frame_yield_no_witness() -> TestResult {
    let frames = frames(0..14)?;
    let gaps = vec![false; 14];
    let unknown = build_coverage(&input(
        &frames,
        &gaps,
        "unknown",
        vec![zone(Vec::new(), true)],
    ))?;
    assert!(unknown.zones[0].witnesses.is_empty());
    assert_eq!(
        reasons(&unknown.zones[0]),
        vec![("capture_time_unknown", 0, 13)]
    );
    let outside = build_coverage(&input(
        &frames,
        &gaps,
        OPERATOR_TIME_LABEL,
        vec![zone(Vec::new(), false)],
    ))?;
    assert!(outside.zones[0].witnesses.is_empty());
    assert_eq!(
        reasons(&outside.zones[0]),
        vec![("zone_outside_frame", 0, 13)]
    );
    Ok(())
}

#[test]
fn a_source_gap_makes_later_capture_time_unreliable() -> TestResult {
    let frames = frames(0..16)?;
    let mut gaps = vec![false; 16];
    gaps[8] = true;
    let record = build_coverage(&input(
        &frames,
        &gaps,
        OPERATOR_TIME_LABEL,
        vec![zone(Vec::new(), true)],
    ))?;
    let door = &record.zones[0];
    assert_eq!(door.witnesses.len(), 1);
    assert_eq!(
        (
            door.witnesses[0].first_segment,
            door.witnesses[0].last_segment
        ),
        (4, 7)
    );
    assert_eq!(
        reasons(door),
        vec![
            ("background_warmup", 0, 3),
            ("capture_time_unreliable_after_gap", 8, 15)
        ]
    );
    Ok(())
}

#[test]
fn entries_and_missing_segments_split_witnesses_explicitly() -> TestResult {
    let mut decoded = frames(0..8)?;
    decoded.extend(frames(9..16)?);
    let gaps = vec![false; 16];
    let entry = CoverageEntry {
        segment: 12,
        candidate: ContentDigest::sha256(b"candidate"),
        event_id: Some("event:watch:x".to_owned()),
    };
    let mut request = input(
        &decoded,
        &gaps,
        OPERATOR_TIME_LABEL,
        vec![zone(vec![entry], true)],
    );
    request.first_segment = 0;
    request.last_segment = 15;
    let record = build_coverage(&request)?;
    let door = &record.zones[0];
    let spans: Vec<(u64, u64)> = door
        .witnesses
        .iter()
        .map(|w| (w.first_segment, w.last_segment))
        .collect();
    assert_eq!(spans, vec![(4, 7), (9, 11)]);
    assert_eq!(
        reasons(door),
        vec![
            ("background_warmup", 0, 3),
            ("segment_not_decoded", 8, 8),
            ("zone_entry", 12, 12),
            ("interval_too_short", 13, 13),
            ("confirmation_latency", 14, 15)
        ]
    );
    Ok(())
}

#[test]
fn tampered_or_inconsistent_records_are_refused() -> TestResult {
    let frames = frames(0..14)?;
    let gaps = vec![false; 14];
    let record = build_coverage(&input(
        &frames,
        &gaps,
        OPERATOR_TIME_LABEL,
        vec![zone(Vec::new(), true)],
    ))?;
    let bytes = record.to_bytes();
    assert!(CoverageRecord::from_bytes(&bytes, ContentDigest::sha256(b"other")).is_err());
    let mut widened = record.clone();
    widened.zones[0].witnesses[0].covered.earliest = TimestampNs(0);
    assert!(widened.validate().is_err());
    let mut relabeled = record.clone();
    relabeled.capture_time_label = "unknown".to_owned();
    assert!(relabeled.validate().is_err());
    let mut regenerated = record;
    regenerated.zones[0].pipeline_generation = ContentDigest::sha256(b"other generation");
    assert!(regenerated.validate().is_err());
    Ok(())
}

#[test]
fn identity_ignores_the_anchor_but_the_approval_binds_it() -> TestResult {
    let frames = frames(0..14)?;
    let gaps = vec![false; 14];
    let first = build_coverage(&input(
        &frames,
        &gaps,
        OPERATOR_TIME_LABEL,
        vec![zone(Vec::new(), true)],
    ))?;
    let mut later = input(
        &frames,
        &gaps,
        OPERATOR_TIME_LABEL,
        vec![zone(Vec::new(), true)],
    );
    later.basis.commit_sequence += 1;
    let second = build_coverage(&later)?;
    assert_eq!(first.identity(), second.identity());
    assert_ne!(approval_digest(&[&first]), approval_digest(&[&second]));
    Ok(())
}

// Pose provenance (record version 4, fss-x8j0v follow-up).

fn posed_visibility() -> ZoneVisibility {
    ZoneVisibility {
        camera_model: CameraModel::CalibratedPose,
        grid: 8,
        threshold_ppm: 1_000_000,
        samples: 64,
        visible: 64,
        outside_frustum: 0,
        occluded: 0,
        privacy_masked: 0,
        occlusion: super::super::ground_visibility::Occlusion::MeshChecked(ContentDigest::sha256(
            b"mesh",
        )),
    }
}

fn posed_record(
    visibility: ZoneVisibility,
    provenance: Option<PoseProvenance>,
) -> Result<CoverageRecord, ContractError> {
    let frames = frames(0..14)?;
    let gaps = vec![false; 14];
    let mut input = input(
        &frames,
        &gaps,
        OPERATOR_TIME_LABEL,
        vec![zone(Vec::new(), true)],
    );
    input.source = CoverageSource::Corroborate;
    build_coverage_with(
        &input,
        &CoverageExtras {
            visibility: vec![Some(visibility)],
            pose_provenance: provenance,
            ..CoverageExtras::default()
        },
    )
}

fn calibrated(currency: GenerationCurrency) -> PoseProvenance {
    PoseProvenance::SiteCalibration {
        calibration_digest: ContentDigest::sha256(b"calibration"),
        camera_handle: 21,
        intrinsics_generation: 1,
        extrinsics_generation: 1,
        currency,
    }
}

#[test]
fn pose_provenance_is_version_four_round_trips_and_leaves_unbound_records_unchanged() -> TestResult
{
    let unbound = posed_record(posed_visibility(), None)?;
    let owner = posed_record(posed_visibility(), Some(PoseProvenance::OwnerPoseArgument))?;
    let asserted = posed_record(
        posed_visibility(),
        Some(calibrated(GenerationCurrency::OwnerAsserted)),
    )?;
    let unasserted = posed_record(
        posed_visibility(),
        Some(calibrated(GenerationCurrency::Unasserted)),
    )?;
    // Without a provenance the record is exactly the version-2 record it always was.
    let unbound_bytes = unbound.to_bytes();
    let mut version = CanonicalDecoder::new(&unbound_bytes);
    assert_eq!(version.bytes()?, RECORD_MAGIC);
    assert_eq!(version.u32()?, RECORD_VERSION_VISIBILITY);
    let mut stripped = owner.clone();
    stripped.pose_provenance = None;
    assert_eq!(stripped.to_bytes(), unbound.to_bytes());
    let mut digests = std::collections::BTreeSet::new();
    for record in [&owner, &asserted, &unasserted] {
        let bytes = record.to_bytes();
        let mut header = CanonicalDecoder::new(&bytes);
        assert_eq!(header.bytes()?, RECORD_MAGIC);
        assert_eq!(header.u32()?, RECORD_VERSION_POSE_PROVENANCE);
        let decoded = CoverageRecord::from_bytes(&bytes, ContentDigest::sha256(&bytes))?;
        assert_eq!(&decoded, record);
        // Deterministic: rebuilt from the same inputs, the same bytes.
        assert_eq!(
            posed_record(posed_visibility(), record.pose_provenance)?.to_bytes(),
            bytes
        );
        assert!(digests.insert(record.digest()));
    }
    assert!(digests.insert(unbound.digest()));
    // The provenance digest is domain-separated and distinguishes every source and currency.
    let provenance: std::collections::BTreeSet<_> = [
        PoseProvenance::OwnerPoseArgument.digest(),
        calibrated(GenerationCurrency::OwnerAsserted).digest(),
        calibrated(GenerationCurrency::Unasserted).digest(),
    ]
    .into_iter()
    .collect();
    assert_eq!(provenance.len(), 3);
    Ok(())
}

#[test]
fn pose_provenance_requires_a_calibrated_pose_on_a_corroborate_record() -> TestResult {
    let mut homography = posed_visibility();
    homography.camera_model = CameraModel::OwnerHomography;
    homography.occlusion = super::super::ground_visibility::Occlusion::Unknown(
        super::super::ground_visibility::OcclusionUnknownReason::NoCameraPose,
    );
    assert!(posed_record(homography.clone(), None).is_ok());
    assert!(posed_record(homography, Some(PoseProvenance::OwnerPoseArgument)).is_err());
    let zero = PoseProvenance::SiteCalibration {
        calibration_digest: ContentDigest::sha256(b"calibration"),
        camera_handle: 21,
        intrinsics_generation: 0,
        extrinsics_generation: 1,
        currency: GenerationCurrency::Unasserted,
    };
    assert!(posed_record(posed_visibility(), Some(zero)).is_err());
    let mut watch = posed_record(posed_visibility(), Some(PoseProvenance::OwnerPoseArgument))?;
    watch.source = CoverageSource::Watch;
    assert!(watch.validate().is_err());
    // A version-4 record whose provenance was edited is refused under its original digest.
    let record = posed_record(
        posed_visibility(),
        Some(calibrated(GenerationCurrency::Unasserted)),
    )?;
    let digest = record.digest();
    let mut edited = record;
    edited.pose_provenance = Some(calibrated(GenerationCurrency::OwnerAsserted));
    assert!(CoverageRecord::from_bytes(&edited.to_bytes(), digest).is_err());
    Ok(())
}

// Adoption currency (fss-x8j0v follow-up: retained calibration authority).

/// The version-4 provenance bytes as they were before `adopted_current` existed.
fn legacy_provenance_bytes(currency: &str) -> Vec<u8> {
    let mut e = CanonicalEncoder::new();
    e.text(POSE_PROVENANCE_DOMAIN);
    e.text("site_calibration");
    e.digest(ContentDigest::sha256(b"calibration"));
    e.u64(21);
    e.u64(1);
    e.u64(1);
    e.text(currency);
    e.finish()
}

#[test]
fn adopted_current_is_a_distinct_round_tripping_currency_and_earlier_bytes_are_unchanged()
-> TestResult {
    // The two earlier currencies keep their exact provenance bytes.
    for (currency, spelling) in [
        (
            GenerationCurrency::OwnerAsserted,
            "owner_asserted_not_observed",
        ),
        (GenerationCurrency::Unasserted, "unasserted_unknown"),
    ] {
        assert_eq!(
            calibrated(currency).digest(),
            ContentDigest::sha256(&legacy_provenance_bytes(spelling))
        );
    }
    let receipt = ContentDigest::sha256(b"adoption receipt");
    let adopted = calibrated(GenerationCurrency::AdoptedCurrent { receipt });
    let mut expected = legacy_provenance_bytes("adopted_current");
    let mut tail = CanonicalEncoder::new();
    tail.digest(receipt);
    expected.extend_from_slice(&tail.finish());
    assert_eq!(adopted.digest(), ContentDigest::sha256(&expected));
    assert_eq!(
        GenerationCurrency::AdoptedCurrent { receipt }.as_str(),
        "adopted_current"
    );
    assert_eq!(
        GenerationCurrency::AdoptedCurrent { receipt }.adoption_receipt(),
        Some(receipt)
    );
    // Distinct from the other currencies and from another receipt.
    let other = calibrated(GenerationCurrency::AdoptedCurrent {
        receipt: ContentDigest::sha256(b"another receipt"),
    });
    let digests: std::collections::BTreeSet<_> = [
        adopted.digest(),
        other.digest(),
        calibrated(GenerationCurrency::OwnerAsserted).digest(),
        calibrated(GenerationCurrency::Unasserted).digest(),
    ]
    .into_iter()
    .collect();
    assert_eq!(digests.len(), 4);
    // A version-4 record carrying it round-trips deterministically, and its summary names the
    // receipt and the non-claim.
    let record = posed_record(posed_visibility(), Some(adopted))?;
    let bytes = record.to_bytes();
    assert_eq!(
        posed_record(posed_visibility(), Some(adopted))?.to_bytes(),
        bytes
    );
    let decoded = CoverageRecord::from_bytes(&bytes, ContentDigest::sha256(&bytes))?;
    assert_eq!(decoded.pose_provenance, Some(adopted));
    let summary = adopted.summary();
    assert!(
        summary.contains(
            "generation currency adopted_current (retained owner adoption, not observed)"
        )
    );
    // Editing the currency of a retained record is refused under its original digest.
    let digest = record.digest();
    let mut edited = record;
    edited.pose_provenance = Some(calibrated(GenerationCurrency::OwnerAsserted));
    assert!(CoverageRecord::from_bytes(&edited.to_bytes(), digest).is_err());
    // An unknown or truncated currency is refused.
    assert!(GenerationCurrency::decode(&mut CanonicalDecoder::new(&[])).is_err());
    let mut e = CanonicalEncoder::new();
    e.text("observed_current");
    let bytes = e.finish();
    assert!(GenerationCurrency::decode(&mut CanonicalDecoder::new(&bytes)).is_err());
    let mut e = CanonicalEncoder::new();
    e.text("adopted_current");
    let bytes = e.finish();
    assert!(GenerationCurrency::decode(&mut CanonicalDecoder::new(&bytes)).is_err());
    Ok(())
}

// Pose uncertainty (record version 5, fss-x8j0v covariance propagation).

fn pose_covariance() -> Result<PoseCovariance, Box<dyn std::error::Error>> {
    let mut matrix = [[0.0_f64; 6]; 6];
    for (index, row) in matrix.iter_mut().enumerate() {
        row[index] = if index < 3 { 1e-8 } else { 1e-4 };
    }
    Ok(PoseCovariance::new(matrix)?)
}

fn robustness(observable: u32, outside_frustum: u32) -> PoseRobustness {
    PoseRobustness {
        nominal: PoseRobustnessClass::Observable,
        perturbations: 12,
        observable,
        occluded: 0,
        outside_frustum,
        privacy_masked: 0,
    }
}

fn uncertain_record(
    provenance: PoseProvenance,
    uncertainty: PoseUncertainty,
    robustness: Option<PoseRobustness>,
) -> Result<CoverageRecord, ContractError> {
    let frames = frames(0..14)?;
    let gaps = vec![false; 14];
    let mut input = input(
        &frames,
        &gaps,
        OPERATOR_TIME_LABEL,
        vec![zone(Vec::new(), true)],
    );
    input.source = CoverageSource::Corroborate;
    build_coverage_with(
        &input,
        &CoverageExtras {
            visibility: vec![Some(posed_visibility())],
            pose_provenance: Some(provenance),
            pose_uncertainty: Some(uncertainty),
            pose_robustness: vec![robustness],
            ..CoverageExtras::default()
        },
    )
}

#[test]
fn a_pose_sensitive_zone_carries_no_witness_and_a_robust_zone_says_so_in_its_predicate()
-> TestResult {
    let calibration = calibrated(GenerationCurrency::Unasserted);
    let sigma = PoseUncertainty::SigmaPoints {
        covariance: pose_covariance()?,
    };
    let robust = uncertain_record(calibration, sigma, Some(robustness(12, 0)))?;
    let sensitive = uncertain_record(calibration, sigma, Some(robustness(10, 2)))?;
    // Robust: the same witness window as the version-4 record, predicate extended.
    let unbound = posed_record(posed_visibility(), Some(calibration))?;
    let door = &robust.zones[0];
    assert_eq!(door.witnesses.len(), unbound.zones[0].witnesses.len());
    assert_eq!(door.uncovered, unbound.zones[0].uncovered);
    for witness in &door.witnesses {
        assert!(
            witness.witness.negative_predicate.ends_with(
                "; pose robust: 12 of 12 sigma-point perturbations of the calibration pose \
                 covariance keep the nominal class (local linear approximation, not a guarantee)"
            ),
            "{}",
            witness.witness.negative_predicate
        );
    }
    // Pose-sensitive: observable under the nominal pose, yet no witness and no absence.
    let door = &sensitive.zones[0];
    assert!(door.witnesses.is_empty());
    assert_eq!(sensitive.witnesses().count(), 0);
    // pose_sensitive precedes warm-up and confirmation latency: every frame carries it.
    assert_eq!(reasons(door), vec![("pose_sensitive", 0, 13)]);
    // A witness smuggled onto the sensitive zone is refused.
    let mut forged = sensitive.clone();
    forged.zones[0].witnesses = robust.zones[0].witnesses.clone();
    assert_eq!(forged.validate(), Err(ContractError::CoverageUncertified));
    Ok(())
}

#[test]
fn pose_uncertainty_is_version_five_round_trips_and_is_deterministic() -> TestResult {
    let calibration = calibrated(GenerationCurrency::OwnerAsserted);
    let sigma = PoseUncertainty::SigmaPoints {
        covariance: pose_covariance()?,
    };
    let records = [
        uncertain_record(
            PoseProvenance::OwnerPoseArgument,
            PoseUncertainty::NotProvided,
            None,
        )?,
        uncertain_record(calibration, PoseUncertainty::NotProvided, None)?,
        uncertain_record(calibration, sigma, Some(robustness(12, 0)))?,
        uncertain_record(calibration, sigma, Some(robustness(10, 2)))?,
    ];
    let mut digests = std::collections::BTreeSet::new();
    for record in &records {
        let bytes = record.to_bytes();
        let mut header = CanonicalDecoder::new(&bytes);
        assert_eq!(header.bytes()?, RECORD_MAGIC);
        assert_eq!(header.u32()?, RECORD_VERSION_POSE_UNCERTAINTY);
        assert_eq!(
            &CoverageRecord::from_bytes(&bytes, ContentDigest::sha256(&bytes))?,
            record
        );
        // Deterministic: rebuilt from the same inputs, bit-identical bytes.
        let again = uncertain_record(
            record.pose_provenance.ok_or("provenance")?,
            record.pose_uncertainty.ok_or("uncertainty")?,
            record.zones[0].pose_robustness,
        )?;
        assert_eq!(again.to_bytes(), bytes);
        assert!(digests.insert(record.digest()));
    }
    // `--pose` is explicitly uncertainty_not_provided, never robust, and its witnesses say so.
    let owner = &records[0];
    assert_eq!(
        owner.pose_uncertainty.map(|value| value.as_str()),
        Some("uncertainty_not_provided")
    );
    assert!(owner.zones[0].pose_robustness.is_none());
    assert!(!owner.zones[0].witnesses.is_empty());
    for witness in &owner.zones[0].witnesses {
        assert!(
            witness.witness.negative_predicate.contains(
                "; pose uncertainty_not_provided: the visibility rests on the nominal pose"
            ),
            "{}",
            witness.witness.negative_predicate
        );
    }
    // Without a bound uncertainty the same record stays version 4.
    let version_four = posed_record(posed_visibility(), Some(calibration))?;
    let version_four_bytes = version_four.to_bytes();
    let mut header = CanonicalDecoder::new(&version_four_bytes);
    header.bytes()?;
    assert_eq!(header.u32()?, RECORD_VERSION_POSE_PROVENANCE);
    // The uncertainty digest is domain-separated and distinguishes the statuses.
    assert_ne!(PoseUncertainty::NotProvided.digest(), sigma.digest());
    let wider = PoseUncertainty::SigmaPoints {
        covariance: pose_covariance()?.scaled(4.0).map_err(|e| e.to_string())?,
    };
    assert_ne!(wider.digest(), sigma.digest());
    Ok(())
}

#[test]
fn pose_uncertainty_is_refused_where_it_cannot_hold() -> TestResult {
    let calibration = calibrated(GenerationCurrency::Unasserted);
    let sigma = PoseUncertainty::SigmaPoints {
        covariance: pose_covariance()?,
    };
    // An owner `--pose` has no covariance: sigma points under it are refused.
    assert!(
        uncertain_record(
            PoseProvenance::OwnerPoseArgument,
            sigma,
            Some(robustness(12, 0))
        )
        .is_err()
    );
    // Sigma points need a robustness block on every zone; not-provided allows none.
    assert!(uncertain_record(calibration, sigma, None).is_err());
    assert!(
        uncertain_record(
            calibration,
            PoseUncertainty::NotProvided,
            Some(robustness(12, 0))
        )
        .is_err()
    );
    // A robustness whose nominal class is not the zone's, or whose counts do not add up.
    let mut wrong_class = robustness(12, 0);
    wrong_class.nominal = PoseRobustnessClass::Occluded;
    assert!(uncertain_record(calibration, sigma, Some(wrong_class)).is_err());
    assert!(uncertain_record(calibration, sigma, Some(robustness(11, 0))).is_err());
    // An uncertainty without a provenance is refused.
    let mut orphan = uncertain_record(calibration, PoseUncertainty::NotProvided, None)?;
    orphan.pose_provenance = None;
    assert!(orphan.validate().is_err());
    // An edited robustness or covariance is refused under the original digest.
    let record = uncertain_record(calibration, sigma, Some(robustness(12, 0)))?;
    let digest = record.digest();
    let mut edited = record.clone();
    edited.pose_uncertainty = Some(PoseUncertainty::SigmaPoints {
        covariance: pose_covariance()?.scaled(2.0).map_err(|e| e.to_string())?,
    });
    assert!(CoverageRecord::from_bytes(&edited.to_bytes(), digest).is_err());
    // A version-5 record relabelled version 4 no longer decodes.
    // (Length-prefixed magic `FSSCOV01`: bytes 0..16; version: bytes 16..20.)
    let mut relabelled = record.to_bytes();
    relabelled[16..20].copy_from_slice(&RECORD_VERSION_POSE_PROVENANCE.to_be_bytes());
    assert!(CoverageRecord::from_bytes(&relabelled, ContentDigest::sha256(&relabelled)).is_err());
    Ok(())
}
