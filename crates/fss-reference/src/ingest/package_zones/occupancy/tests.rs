#![forbid(unsafe_code)]
//! Exact reducer regressions; retained/native owner tests live in package_zones_contract.

use super::*;

fn metadata<'a>(
    zones: &'a [super::super::PackageZone],
    frames: &'a [super::super::PackageZoneFrame],
) -> json::Source<'a> {
    json::Source {
        site: "site:occupancy-fixture",
        sensor: "sensor:occupancy-fixture",
        zone_report: track(10),
        zone_root: track(11),
        analysis: track(12),
        detection: track(13),
        import_identity: track(14),
        import_root: track(15),
        package: track(16),
        model_id: "MOD-OCCUPANCY-FIXTURE-001",
        generation: "model:fixture:g7",
        model: track(17),
        contract: track(18),
        label: "fixture \"label\"\\with\ncontrols",
        class_index: 0,
        capture_time_label: "unknown",
        clock: fss_core::ClockBasis::Estimated,
        privacy: track(19),
        screened: false,
        confirmation_hits: 2,
        maximum_missed_frames: 1,
        minimum_iou_ppm: 100_000,
        zones,
        frames,
    }
}

fn track(n: u8) -> ContentDigest {
    ContentDigest::sha256(&[n])
}
fn cell(
    track: ContentDigest,
    frame: usize,
    zone: usize,
    relation: PackageZoneRelation,
) -> PackageZoneCell {
    let observed = relation != PackageZoneRelation::Unobserved;
    PackageZoneCell {
        track,
        frame,
        zone,
        relation,
        sample_confirmed: observed,
        detection_row: observed.then_some(7),
        bounds: observed.then_some([256, 256, 512, 512]),
        clipped: relation == PackageZoneRelation::Partial,
    }
}

#[test]
fn complete_grid_keeps_empty_frames_zones_and_zero_without_an_absence_state() -> Result<()> {
    let rows = project(
        3,
        &[false, false],
        &[],
        &[],
        &[OccupancyHealth::Unassessed; 3],
        || Ok(()),
    )?;
    assert_eq!(rows.len(), 6);
    for (index, row) in rows.iter().enumerate() {
        assert_eq!((row.frame, row.zone), (index / 2, index % 2));
        assert_eq!(row.observed_count, Some(0));
        assert_eq!(row.state, OccupancyState::NoPositiveObservation);
        assert!(row.supporting_tracks.is_empty());
    }
    Ok(())
}

#[test]
fn only_actual_confirmed_inside_assignments_count_without_interpolation() -> Result<()> {
    use PackageZoneRelation::*;
    let id = track(1);
    let mut cells = vec![
        cell(id, 0, 0, Inside),
        cell(id, 1, 0, Inside),
        cell(id, 2, 0, Unobserved),
        cell(id, 3, 0, Inside),
    ];
    cells[0].sample_confirmed = false;
    let rows = project(
        4,
        &[false],
        &[id],
        &cells,
        &[OccupancyHealth::Unassessed; 4],
        || Ok(()),
    )?;
    assert_eq!(
        rows.iter().map(|r| r.observed_count).collect::<Vec<_>>(),
        vec![Some(0), Some(1), Some(0), Some(1)]
    );
    assert_eq!(rows[0].excluded.tentative, 1);
    assert_eq!(rows[2].excluded.unobserved, 1);
    assert_eq!(rows[1].supporting_tracks, vec![id]);
    assert_eq!(rows[3].supporting_tracks, vec![id]);
    Ok(())
}

#[test]
fn boundary_partial_outside_and_tentative_samples_keep_distinct_reasons() -> Result<()> {
    use PackageZoneRelation::*;
    let ids = [track(1), track(2), track(3), track(4)];
    let mut cells = ids
        .iter()
        .zip([Boundary, Partial, Outside, Inside])
        .enumerate()
        .map(|(i, (id, r))| {
            let mut c = cell(*id, 0, 0, r);
            c.detection_row = Some(i as u64);
            c
        })
        .collect::<Vec<_>>();
    cells[3].sample_confirmed = false;
    let rows = project(
        1,
        &[false],
        &ids,
        &cells,
        &[OccupancyHealth::ScreenedWithoutFindings],
        || Ok(()),
    )?;
    assert_eq!(rows[0].observed_count, Some(0));
    assert_eq!(rows[0].confirmed_outside, 1);
    assert_eq!(rows[0].excluded.boundary, 1);
    assert_eq!(rows[0].excluded.partial, 1);
    assert_eq!(rows[0].excluded.tentative, 1);
    Ok(())
}

#[test]
fn privacy_suppresses_counts_even_without_tracks_and_never_becomes_zero() -> Result<()> {
    let rows = project(1, &[true], &[], &[], &[OccupancyHealth::Unassessed], || {
        Ok(())
    })?;
    assert_eq!(rows[0].observed_count, None);
    assert_eq!(rows[0].state, OccupancyState::Masked);
    let id = track(1);
    let rows = project(
        1,
        &[true],
        &[id],
        &[cell(id, 0, 0, PackageZoneRelation::Masked)],
        &[OccupancyHealth::Unassessed],
        || Ok(()),
    )?;
    assert_eq!(rows[0].excluded.masked, 1);
    assert!(rows[0].supporting_tracks.is_empty());
    assert!(matches!(
        project(
            1,
            &[true],
            &[id],
            &[cell(id, 0, 0, PackageZoneRelation::Inside)],
            &[OccupancyHealth::Unassessed],
            || Ok(())
        ),
        Err(PackageZoneError::Mismatch)
    ));
    Ok(())
}

#[test]
fn exact_historical_health_policy_withholds_unknown_incomplete_and_finding_counts() -> Result<()> {
    let health = [
        OccupancyHealth::Unassessed,
        OccupancyHealth::ScreenedWithoutFindings,
        OccupancyHealth::NoMatchingDiagnostic,
        OccupancyHealth::ScreeningIncomplete,
        OccupancyHealth::Findings,
    ];
    let id = track(1);
    let cells = (0..health.len())
        .map(|i| cell(id, i, 0, PackageZoneRelation::Inside))
        .collect::<Vec<_>>();
    let rows = project(5, &[false], &[id], &cells, &health, || Ok(()))?;
    assert_eq!(rows[0].health, OccupancyHealth::Unassessed);
    assert_eq!(rows[0].observed_count, Some(1));
    assert_eq!(rows[1].observed_count, Some(1));
    for row in &rows[2..] {
        assert_eq!(row.state, OccupancyState::HealthExcluded);
        assert_eq!(row.observed_count, None);
        assert_eq!(row.excluded.health, 1);
        assert!(row.supporting_tracks.is_empty());
    }
    let empty = project(
        1,
        &[false],
        &[],
        &[],
        &[OccupancyHealth::NoMatchingDiagnostic],
        || Ok(()),
    )?;
    assert_eq!(empty[0].observed_count, None);
    Ok(())
}

#[test]
fn overlapping_zones_keep_the_same_support_without_cross_zone_deduplication() -> Result<()> {
    let id = track(1);
    let cells = [
        cell(id, 0, 0, PackageZoneRelation::Inside),
        cell(id, 0, 1, PackageZoneRelation::Inside),
    ];
    let rows = project(
        1,
        &[false, false],
        &[id],
        &cells,
        &[OccupancyHealth::Unassessed],
        || Ok(()),
    )?;
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|r| r.observed_count == Some(1) && r.supporting_tracks == [id])
    );
    Ok(())
}

#[test]
fn complete_inventory_refuses_missing_duplicate_foreign_and_out_of_range_cells() {
    let id = track(1);
    let good = cell(id, 0, 0, PackageZoneRelation::Inside);
    let bad = |cells: &[PackageZoneCell]| {
        project(
            2,
            &[false],
            &[id],
            cells,
            &[OccupancyHealth::Unassessed; 2],
            || Ok(()),
        )
    };
    assert!(matches!(
        bad(std::slice::from_ref(&good)),
        Err(PackageZoneError::Mismatch)
    ));
    assert!(matches!(
        bad(&[good.clone(), good.clone()]),
        Err(PackageZoneError::Mismatch)
    ));
    for mut c in [
        cell(track(2), 1, 0, PackageZoneRelation::Inside),
        cell(id, 2, 0, PackageZoneRelation::Inside),
        cell(id, 1, 1, PackageZoneRelation::Inside),
    ] {
        assert!(matches!(
            bad(&[good.clone(), c.clone()]),
            Err(PackageZoneError::Mismatch)
        ));
        c.detection_row = None;
        assert!(bad(&[good.clone(), c]).is_err());
    }
    assert!(matches!(
        project(
            1,
            &[false],
            &[id, id],
            &[good.clone(), good],
            &[OccupancyHealth::Unassessed],
            || Ok(())
        ),
        Err(PackageZoneError::Mismatch)
    ));
}

#[test]
fn duplicate_assignment_rows_cannot_inflate_a_count() {
    let ids = [track(1), track(2)];
    let cells = ids.map(|id| cell(id, 0, 0, PackageZoneRelation::Inside));
    assert!(matches!(
        project(
            1,
            &[false],
            &ids,
            &cells,
            &[OccupancyHealth::Unassessed],
            || Ok(())
        ),
        Err(PackageZoneError::Mismatch)
    ));
}

#[test]
fn inconsistent_missing_or_clipped_cells_refuse_complete_projection() {
    let id = track(1);
    for c in [
        PackageZoneCell {
            detection_row: Some(7),
            ..cell(id, 0, 0, PackageZoneRelation::Unobserved)
        },
        PackageZoneCell {
            sample_confirmed: true,
            ..cell(id, 0, 0, PackageZoneRelation::Unobserved)
        },
        PackageZoneCell {
            clipped: true,
            ..cell(id, 0, 0, PackageZoneRelation::Inside)
        },
        PackageZoneCell {
            clipped: false,
            ..cell(id, 0, 0, PackageZoneRelation::Partial)
        },
    ] {
        assert!(matches!(
            project(
                1,
                &[false],
                &[id],
                &[c],
                &[OccupancyHealth::Unassessed],
                || Ok(())
            ),
            Err(PackageZoneError::Mismatch)
        ));
    }
}

#[test]
fn support_order_and_digest_are_canonical_but_every_source_and_count_is_bound() -> Result<()> {
    let ids = [track(1), track(2)];
    let mut cells = [
        cell(ids[0], 0, 0, PackageZoneRelation::Inside),
        cell(ids[1], 0, 0, PackageZoneRelation::Inside),
    ];
    cells[1].detection_row = Some(8);
    let first = project(
        1,
        &[false],
        &ids,
        &cells,
        &[OccupancyHealth::Unassessed],
        || Ok(()),
    )?;
    cells.reverse();
    let second = project(
        1,
        &[false],
        &[ids[1], ids[0]],
        &cells,
        &[OccupancyHealth::Unassessed],
        || Ok(()),
    )?;
    assert_eq!(first, second);
    let d = identity(track(9), track(10), &first)?;
    assert_eq!(d, identity(track(9), track(10), &second)?);
    assert_ne!(d, identity(track(8), track(10), &first)?);
    assert_ne!(d, identity(track(9), track(11), &first)?);
    let mut changed = first;
    changed[0].excluded.tentative = 1;
    assert_ne!(d, identity(track(9), track(10), &changed)?);
    Ok(())
}

#[test]
fn whole_product_bounds_and_cancellation_refuse_without_partial_success() {
    let id = track(1);
    for (frames, zones) in [
        (0, vec![false]),
        (65, vec![false]),
        (1, vec![]),
        (1, vec![false; 17]),
    ] {
        assert!(matches!(
            project(frames, &zones, &[], &[], &[], || panic!(
                "bounds must precede work"
            )),
            Err(PackageZoneError::Limit)
        ));
    }
    assert!(matches!(
        project(
            64,
            &[false; 16],
            &[id; 9],
            &[],
            &[OccupancyHealth::Unassessed; 64],
            || panic!("product before work")
        ),
        Err(PackageZoneError::Limit)
    ));
    assert!(matches!(
        project(
            1,
            &[false],
            &[id],
            &[cell(id, 0, 0, PackageZoneRelation::Inside)],
            &[OccupancyHealth::Unassessed],
            || Err(PackageZoneError::Cancelled)
        ),
        Err(PackageZoneError::Cancelled)
    ));
    assert!(matches!(
        project(
            1,
            &[false],
            &[],
            &[],
            &[OccupancyHealth::Unassessed],
            || Err(PackageZoneError::Cancelled)
        ),
        Err(PackageZoneError::Cancelled)
    ));
}

#[test]
fn actual_json_projection_preserves_bindings_exact_times_nulls_and_escaping() -> Result<()> {
    use super::super::{PackageZone, PackageZoneFrame};
    use fss_core::{CaptureInterval, TimestampNs};
    let zones = [PackageZone {
        id: "register".into(),
        x: 0,
        y: 0,
        width: 32,
        height: 16,
        margin: 1,
    }];
    let frames = [PackageZoneFrame {
        segment: 31,
        capsule_digest: track(20),
        capture: CaptureInterval {
            earliest: TimestampNs(i128::MIN + 1),
            latest: TimestampNs(i128::MAX - 1),
        },
        dimensions: [32, 16],
        time_reliable: false,
        source_boundary: true,
    }];
    let source = metadata(&zones, &frames);
    let rows = project(1, &[true], &[], &[], &[OccupancyHealth::Unassessed], || {
        Ok(())
    })?;
    let report_digest = identity(source.zone_report, source.zone_root, &rows)?;
    let rendered = json::render(&source, report_digest, &rows)?;
    let parsed = fss_core::json_input::parse(&rendered)
        .map_err(|e| PackageZoneError::Source(Box::new(e)))?;
    let fields = parsed.object().ok_or(PackageZoneError::Mismatch)?;
    assert_eq!(
        fields["schema"].text(),
        Some(PACKAGE_OCCUPANCY_REPORT_DOMAIN)
    );
    assert_eq!(
        fields["source"]
            .object()
            .ok_or(PackageZoneError::Mismatch)?["label"]
            .text(),
        Some(source.label)
    );
    assert_eq!(
        fields["coverage_witness"],
        fss_core::json_input::Value::Null
    );
    assert!(rendered.contains(&format!("\"earliest_ns\":\"{}\"", i128::MIN + 1)));
    assert!(rendered.contains(&format!("\"latest_ns\":\"{}\"", i128::MAX - 1)));
    assert!(rendered.contains("\"time_reliable\":false,\"source_boundary\":true"));
    let semantics = fields["semantics"]
        .object()
        .ok_or(PackageZoneError::Mismatch)?;
    assert_eq!(semantics["absence_certified"].boolean(), Some(false));
    assert_eq!(
        semantics["continuous_occupancy_established"].boolean(),
        Some(false)
    );
    assert!(rendered.contains("\"observed_count\":null"));
    Ok(())
}

#[test]
fn full_maximum_empty_grid_renders_without_omission_or_invented_coverage() -> Result<()> {
    use super::super::{PackageZone, PackageZoneFrame};
    use fss_core::{CaptureInterval, TimestampNs};
    let zones = (0..16)
        .map(|i| PackageZone {
            id: format!("zone-{i:02}"),
            x: 0,
            y: 0,
            width: 32,
            height: 16,
            margin: 0,
        })
        .collect::<Vec<_>>();
    let frames = (0..64)
        .map(|i| PackageZoneFrame {
            segment: i,
            capsule_digest: track(i as u8),
            capture: CaptureInterval {
                earliest: TimestampNs(i128::from(i)),
                latest: TimestampNs(i128::from(i)),
            },
            dimensions: [32, 16],
            time_reliable: true,
            source_boundary: false,
        })
        .collect::<Vec<_>>();
    let source = metadata(&zones, &frames);
    let rows = project(
        64,
        &[false; 16],
        &[],
        &[],
        &[OccupancyHealth::Unassessed; 64],
        || Ok(()),
    )?;
    let rendered = json::render(
        &source,
        identity(source.zone_report, source.zone_root, &rows)?,
        &rows,
    )?;
    let parsed = fss_core::json_input::parse(&rendered)
        .map_err(|e| PackageZoneError::Source(Box::new(e)))?;
    assert_eq!(
        parsed.object().ok_or(PackageZoneError::Mismatch)?["samples"]
            .array()
            .ok_or(PackageZoneError::Mismatch)?
            .len(),
        1024
    );
    assert!(rendered.len() < MAX_PACKAGE_OCCUPANCY_JSON_BYTES);
    Ok(())
}
