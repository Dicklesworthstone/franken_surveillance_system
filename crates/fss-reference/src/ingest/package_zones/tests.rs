#![forbid(unsafe_code)]
//! Conservative geometry/temporal refusal cuts; source custody is tested through native owners.
use super::*;
use fss_core::TimestampNs;

fn config() -> PackageZoneConfig {
    PackageZoneConfig {
        maximum_sample_gap_ns: 12,
        dwell: Some(PackageZoneDwell {
            minimum_duration_ns: 18,
            minimum_observations: 3,
        }),
        zones: vec![PackageZone {
            id: "yard".into(),
            x: 10,
            y: 10,
            width: 20,
            height: 20,
            margin: 1,
        }],
    }
}
fn sequence(relations: &[PackageZoneRelation]) -> (Vec<PackageZoneCell>, Vec<PackageZoneFrame>) {
    let id = ContentDigest::sha256(b"one sealed source track");
    let frames = relations
        .iter()
        .enumerate()
        .map(|(i, _)| PackageZoneFrame {
            segment: i as u64,
            capsule_digest: ContentDigest::sha256(&(i as u64).to_be_bytes()),
            capture: CaptureInterval {
                earliest: TimestampNs(i as i128 * 10),
                latest: TimestampNs(i as i128 * 10 + 2),
            },
            dimensions: [64, 48],
            time_reliable: true,
            source_boundary: false,
        })
        .collect();
    let cells = relations
        .iter()
        .enumerate()
        .map(|(i, r)| PackageZoneCell {
            track: id,
            zone: 0,
            frame: i,
            relation: *r,
            sample_confirmed: true,
            detection_row: Some(7),
            bounds: Some([12 * 256, 12 * 256, 20 * 256, 20 * 256]),
            clipped: false,
        })
        .collect();
    (cells, frames)
}
#[test]
fn expanded_whole_boxes_not_centers_define_strict_membership() {
    use PackageZoneRelation::*;
    let zone = &config().zones[0];
    assert_eq!(
        compute::relation(zone, [12 * 256, 12 * 256, 20 * 256, 20 * 256], false),
        Inside
    );
    assert_eq!(
        compute::relation(zone, [11 * 256, 12 * 256, 20 * 256, 20 * 256], false),
        Boundary
    );
    assert_eq!(
        compute::relation(zone, [0, 12 * 256, 8 * 256, 20 * 256], false),
        Outside
    );
    assert_eq!(
        compute::relation(zone, [0, 12 * 256, 9 * 256, 20 * 256], false),
        Boundary
    );
    assert_eq!(
        compute::relation(zone, [12 * 256, 12 * 256, 20 * 256, 20 * 256], true),
        Partial
    );
}
#[test]
fn entries_and_maximal_dwell_use_only_confirmed_actual_consecutive_samples() -> Result<()> {
    use PackageZoneRelation::*;
    let (mut cells, frames) = sequence(&[Outside, Outside, Inside, Inside, Inside]);
    cells[0].sample_confirmed = false;
    let mut events = Vec::new();
    compute::timeline(&cells, &frames, &config(), &mut events)?;
    let entry = events
        .iter()
        .find(|e| e.kind == PackageZoneEventKind::EnteredBetweenObservations)
        .ok_or(PackageZoneError::Mismatch)?;
    assert_eq!((entry.from_frame, entry.at_frame), (Some(1), 2));
    let dwell = events
        .iter()
        .find(|e| e.kind == PackageZoneEventKind::SampledDwell)
        .ok_or(PackageZoneError::Mismatch)?;
    assert_eq!(
        (dwell.from_frame, dwell.at_frame, dwell.through_frame),
        (Some(2), 4, 4)
    );
    assert_eq!(
        (dwell.minimum_duration_ns, dwell.maximum_duration_ns),
        (Some(18), Some(22))
    );
    assert_eq!(dwell.observations, 3);
    Ok(())
}
#[test]
fn unavailable_tentative_boundary_clock_and_gap_samples_cannot_bridge_dwell_or_imply_exit()
-> Result<()> {
    use PackageZoneRelation::*;
    for cut in 0..8 {
        let (mut cells, mut frames) = sequence(&[Inside, Inside, Inside, Inside, Inside]);
        match cut {
            0 => cells[2].relation = Unobserved,
            1 => cells[2].relation = Partial,
            2 => cells[2].relation = Boundary,
            3 => cells[2].relation = Masked,
            4 => cells[2].sample_confirmed = false,
            5 => frames[2].time_reliable = false,
            6 => {
                frames[2].source_boundary = true;
                frames[3].source_boundary = true;
            }
            _ => {
                frames[2].capture.latest = TimestampNs(100);
                frames[3].source_boundary = true;
            }
        }
        let mut events = Vec::new();
        compute::timeline(&cells, &frames, &config(), &mut events)?;
        assert!(
            !events
                .iter()
                .any(|e| e.kind == PackageZoneEventKind::SampledDwell),
            "cut {cut}"
        );
        assert!(
            !events
                .iter()
                .any(|e| e.kind == PackageZoneEventKind::LeftBetweenObservations),
            "cut {cut}"
        );
        if cut != 2 {
            assert!(
                events
                    .iter()
                    .any(|e| e.kind == PackageZoneEventKind::ObservationInterrupted),
                "cut {cut}"
            );
        }
    }
    let (cells, mut frames) = sequence(&[Inside, Inside, Inside]);
    frames[1].capture.earliest = TimestampNs(-1);
    assert!(compute::timeline(&cells, &frames, &config(), &mut Vec::new()).is_err());
    Ok(())
}
#[test]
fn complete_boundary_measurements_preserve_side_endpoints_but_do_not_count_as_dwell() -> Result<()>
{
    use PackageZoneRelation::*;
    let (cells, frames) = sequence(&[Outside, Boundary, Inside, Boundary, Outside]);
    let mut events = Vec::new();
    compute::timeline(&cells, &frames, &config(), &mut events)?;
    assert!(events.iter().any(
        |e| e.kind == PackageZoneEventKind::EnteredBetweenObservations
            && e.from_frame == Some(0)
            && e.at_frame == 2
    ));
    assert!(
        events
            .iter()
            .any(|e| e.kind == PackageZoneEventKind::LeftBetweenObservations
                && e.from_frame == Some(2)
                && e.at_frame == 4)
    );
    assert!(
        !events
            .iter()
            .any(|e| e.kind == PackageZoneEventKind::SampledDwell)
    );
    Ok(())
}
#[test]
fn aggregate_product_and_canonical_configuration_are_bounded() -> Result<()> {
    assert_eq!(compute::admit(128, 64, 1)?, 8192);
    assert!(compute::admit(129, 64, 1).is_err());
    assert!(compute::admit(usize::MAX, 64, 16).is_err());
    assert!(compute::admit(1, 65, 1).is_err());
    let normalized = config().normalized([64, 48])?;
    assert!(!wire::config_bytes(&normalized).is_empty());
    let mut duplicate = config();
    duplicate.zones.push(duplicate.zones[0].clone());
    assert!(duplicate.normalized([64, 48]).is_err());
    Ok(())
}
