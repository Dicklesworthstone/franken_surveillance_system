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
