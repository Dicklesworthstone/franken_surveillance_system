#![forbid(unsafe_code)]
//! Execute the actual production XML parser, tracklet projector, exact geometry, zone reducer
//! and CLI JSON writer. Caller-owned fixture pins do not simulate a retained custody owner.

extern crate self as fss_cli;
extern crate self as fss_reference;

/// Actual JSON escaping primitives.
#[path = "../../fss-cli/src/json_output.rs"]
pub mod json_output;
/// Actual source-linked tracklet implementation.
#[path = "../../fss-reference/src/onvif/metadata/tracks/contract.rs"]
pub mod tracks_contract;
/// Actual production wire parser.
#[path = "../../fss-reference/src/onvif/wire.rs"]
pub mod wire;
/// Actual finite vendor-zone implementation, including its exact arithmetic module.
#[path = "../../fss-reference/src/onvif/metadata/zones/contract.rs"]
pub mod zones_contract;

/// Real implementation namespaces used by the included production modules.
pub mod onvif {
    pub use crate::wire;
    /// Original metadata namespace.
    pub mod metadata {
        /// Original tracklet namespace.
        pub mod tracks {
            pub use crate::tracks_contract as contract;
        }
        /// Original zone namespace.
        pub mod zones {
            pub use crate::zones_contract as contract;
        }
    }
}
#[path = "../../fss-cli/src/bin/fss-onvif-metadata/analysis/zones_json.rs"]
mod zones_json;

use std::cell::Cell;
use std::fmt;

use fss_core::json_input::{Value, parse};
use fss_core::{ContentDigest, Plane, ProvenanceClass};
use tracks_contract::{TrackFrameInput, TrackLimits, TrackletReport, project_tracklets};
use zones_contract::geometry::{self, GeometryError};
use zones_contract::{
    MAX_ZONE_POLICY_BYTES, VendorZone, ZoneError, ZoneLimits, ZonePolicy, ZoneRelation, ZoneReport,
    ZoneTransitionKind, ZoneUnavailable, project_zones,
};

type Checked<T> = Result<T, Box<dyn std::error::Error>>;
type Test = Checked<()>;

struct Fixture {
    parsed: wire::EventDocument,
    digest: ContentDigest,
}
fn digest(value: &str) -> ContentDigest {
    ContentDigest::sha256(value.as_bytes())
}
fn fixture(frames: &str) -> Checked<Fixture> {
    let xml = format!(
        r#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema" xmlns:v="urn:vendor"><t:VideoAnalytics>{frames}</t:VideoAnalytics></t:MetadataStream>"#
    );
    Ok(Fixture {
        parsed: wire::parse_metadata_document(xml.as_bytes())?,
        digest: ContentDigest::sha256(xml.as_bytes()),
    })
}
fn object(id: &str, bounds: [&str; 4]) -> String {
    format!(
        r#"<t:Object ObjectId="{id}"><t:Appearance><t:Shape><t:BoundingBox left="{}" right="{}" top="{}" bottom="{}"/><t:CenterOfGravity x="0.5" y="0.5"/></t:Shape></t:Appearance></t:Object>"#,
        bounds[0], bounds[1], bounds[2], bounds[3]
    )
}
fn frame(second: u8, objects: &str) -> String {
    format!(
        r#"<t:Frame UtcTime="2026-11-09T00:00:{second:02}Z" Source="private_module_canary">{objects}</t:Frame>"#
    )
}
fn inputs(fixture: &Fixture) -> Vec<TrackFrameInput<'_>> {
    fixture
        .parsed
        .analytics_frames
        .iter()
        .enumerate()
        .map(|(index, frame)| TrackFrameInput {
            scope: digest("fixture exact source generation"),
            source_identity: digest("fixture owner identity"),
            source_root: digest("fixture owner root"),
            source_digest: fixture.digest,
            frame_digest: digest(&format!("{}:frame:{index}", fixture.digest)),
            document_index: 0,
            frame_index: index,
            frame,
            boundary_before: false,
            uninterpreted_source: false,
        })
        .collect()
}
fn track(frames: &[TrackFrameInput<'_>]) -> Checked<TrackletReport> {
    Ok(project_tracklets(frames, TrackLimits::default(), || true)?)
}
fn policy_at(tracks: &TrackletReport, occurrence: usize) -> Checked<ZonePolicy> {
    let occurrence = tracks
        .occurrences
        .get(occurrence)
        .ok_or("missing fixture occurrence")?;
    let frame = tracks
        .frames
        .get(occurrence.frame_ordinal)
        .ok_or("missing fixture frame")?;
    Ok(ZonePolicy {
        zones: vec![VendorZone {
            id: "private_zone_annotation".into(),
            scope: frame.reference.scope,
            module_digest: frame.module_digest.ok_or("missing fixture module")?,
            frame_transform_digest: frame.transformation_digest,
            object_transform_digest: occurrence.transformation_digest,
            min: [0, 0],
            max: [1_000_000, 1_000_000],
            margin: 0,
        }],
    })
}
fn project(
    frames: &[TrackFrameInput<'_>],
    tracks: &TrackletReport,
    policy: &ZonePolicy,
) -> Checked<ZoneReport> {
    Ok(project_zones(
        frames,
        tracks,
        policy,
        ZoneLimits::default(),
        || true,
    )?)
}
fn policy_json(policy: &ZonePolicy) -> String {
    let rows = policy.zones.iter().map(|z| format!(
        r#"{{"id":{},"scope":"{}","module_digest":"{}","frame_transform_digest":"{}","object_transform_digest":"{}","min":[{},{}],"max":[{},{}],"margin":{}}}"#,
        json_output::string(&z.id), z.scope, z.module_digest, z.frame_transform_digest, z.object_transform_digest,
        z.min[0], z.min[1], z.max[0], z.max[1], z.margin)).collect::<Vec<_>>().join(",");
    format!(
        r#"{{"schema":"fss.onvif_vendor_zone_policy.v1","coordinates":"raw_vendor_object_millionths","zones":[{rows}]}}"#
    )
}
fn field<'a>(value: &'a Value, key: &str) -> Checked<&'a Value> {
    value
        .object()
        .and_then(|o| o.get(key))
        .ok_or_else(|| format!("missing {key}").into())
}
fn rows<'a>(value: &'a Value, key: &str) -> Checked<&'a [Value]> {
    field(value, key)?
        .array()
        .ok_or_else(|| format!("expected array {key}").into())
}

#[test]
fn exact_decimal_grid_never_rounds_a_nonzero_tail_or_tiny_exponent_to_zero() -> Test {
    for (text, expected) in [
        ("0", [0, 0]),
        (
            "-0e-99999999999999999999999999999999999999999999999999",
            [0, 0],
        ),
        (".1", [100_000, 100_000]),
        ("+1.234567", [1_234_567, 1_234_567]),
        ("001.234567", [1_234_567, 1_234_567]),
        (".0000001", [0, 1]),
        ("-.0000001", [-1, 0]),
        ("1e-9999", [0, 1]),
        ("-1E-9999", [-1, 0]),
        ("1e9", [1_000_000_000_000_000, 1_000_000_000_000_000]),
        ("-1E9", [-1_000_000_000_000_000, -1_000_000_000_000_000]),
        (
            "1.234567000000000000000000000000000000000000000000000001",
            [1_234_567, 1_234_568],
        ),
        (
            "-1.23456700000000000000000000000000000000000000000000001",
            [-1_234_568, -1_234_567],
        ),
    ] {
        let result =
            geometry::decimal_millionths(text).map_err(|_| "valid exact decimal refused")?;
        assert_eq!([result.lower, result.upper], expected, "{text}");
    }
    for bad in [
        "",
        "+",
        "NaN",
        "1e",
        "1..0",
        " 1",
        "1e+-2",
        "1e9999",
        "1.000000000000000000000001e9",
    ] {
        assert!(geometry::decimal_millionths(bad).is_err(), "{bad}");
    }
    assert_eq!(
        geometry::decimal_millionths(&"1".repeat(65)),
        Err(GeometryError::Range)
    );
    Ok(())
}

#[test]
fn full_vendor_boxes_produce_complete_inside_outside_boundary_counts() -> Test {
    let f = fixture(&frame(
        0,
        &(object("1", [".2", ".4", ".2", ".4"])
            + &object("2", ["2", "3", ".2", ".4"])
            + &object("3", [".8", "1.2", ".2", ".4"])),
    ))?;
    let frames = inputs(&f);
    let tracks = track(&frames)?;
    let policy = policy_at(&tracks, 0)?;
    let result = project(&frames, &tracks, &policy)?;
    assert_eq!(
        result.cells.iter().map(|c| c.relation).collect::<Vec<_>>(),
        [
            ZoneRelation::Inside,
            ZoneRelation::Outside,
            ZoneRelation::Boundary
        ]
    );
    let sample = &result.frame_samples[0];
    assert_eq!(
        (
            sample.inside,
            sample.outside,
            sample.boundary,
            sample.unavailable
        ),
        (1, 1, 1, 0)
    );
    assert_eq!(result.transitions.len(), 1);
    assert_eq!(
        result.transitions[0].kind,
        ZoneTransitionKind::ObservedInside
    );
    assert_eq!(result.plane(), Plane::Cognition);
    assert_eq!(result.provenance(), ProvenanceClass::Derived);
    assert_eq!(result.source_provenance(), ProvenanceClass::VendorClaimed);
    assert_eq!(project(&frames, &tracks, &policy)?, result);
    Ok(())
}

#[test]
fn sub_grid_decimal_tail_cannot_turn_a_boundary_claim_into_inside() -> Test {
    let f = fixture(&frame(
        0,
        &object("1", ["-1e-300", "0.000001", "0", "0.000001"]),
    ))?;
    let number = &f.parsed.analytics_frames[0].objects[0]
        .appearance
        .as_ref()
        .ok_or("appearance")?
        .shape
        .as_ref()
        .ok_or("shape")?
        .bounding_box
        .left;
    assert!(number.as_f64() < 0.0);
    assert_eq!((number.as_f64() * 1_000_000.0).round(), 0.0);
    let frames = inputs(&f);
    let tracks = track(&frames)?;
    let mut policy = policy_at(&tracks, 0)?;
    policy.zones[0].min = [-1, -1];
    policy.zones[0].max = [2, 2];
    assert_eq!(
        project(&frames, &tracks, &policy)?.cells[0].relation,
        ZoneRelation::Boundary
    );
    Ok(())
}

#[test]
fn zero_original_frames_returns_a_complete_empty_projection() -> Test {
    let fixture = fixture(&frame(0, &object("1", [".2", ".4", ".2", ".4"])))?;
    let seeded = inputs(&fixture);
    let policy = policy_at(&track(&seeded)?, 0)?;
    let empty_tracks = track(&[])?;
    let report = project(&[], &empty_tracks, &policy)?;
    assert!(report.cells.is_empty());
    assert!(report.frame_samples.is_empty());
    assert!(report.transitions.is_empty());
    assert_eq!(report.tracklet_report_digest, empty_tracks.report_digest);
    assert!(report.encoded_bytes > 0);
    assert!(report.work_units > 0);
    Ok(())
}

#[test]
fn multiple_zones_keep_the_full_ordered_matrix_and_empty_frame_samples() -> Test {
    let f = fixture(
        &(frame(
            0,
            &(object("1", [".2", ".4", ".2", ".4"]) + &object("2", ["2.2", "2.4", ".2", ".4"])),
        ) + &frame(1, "")),
    )?;
    let frames = inputs(&f);
    let tracks = track(&frames)?;
    let mut policy = policy_at(&tracks, 0)?;
    let mut second = policy.zones[0].clone();
    second.id = "second_zone".into();
    second.min = [2_000_000, 0];
    second.max = [3_000_000, 1_000_000];
    policy.zones.push(second);
    let result = project(&frames, &tracks, &policy)?;
    assert_eq!(
        result
            .cells
            .iter()
            .map(|row| (row.occurrence_index, row.zone_index, row.relation))
            .collect::<Vec<_>>(),
        [
            (0, 0, ZoneRelation::Inside),
            (0, 1, ZoneRelation::Outside),
            (1, 0, ZoneRelation::Outside),
            (1, 1, ZoneRelation::Inside),
        ]
    );
    assert_eq!(
        result
            .frame_samples
            .iter()
            .map(|row| (
                row.frame_ordinal,
                row.zone_index,
                row.inside,
                row.outside,
                row.boundary,
                row.unavailable
            ))
            .collect::<Vec<_>>(),
        [
            (0, 0, 1, 1, 0, 0),
            (0, 1, 1, 1, 0, 0),
            (1, 0, 0, 0, 0, 0),
            (1, 1, 0, 0, 0, 0),
        ]
    );
    assert_eq!(result.transitions.len(), 2);
    assert!(
        result
            .transitions
            .iter()
            .all(|row| row.kind == ZoneTransitionKind::ObservedInside)
    );
    for limits in [
        ZoneLimits {
            max_cells: 3,
            ..ZoneLimits::default()
        },
        ZoneLimits {
            max_frame_samples: 3,
            ..ZoneLimits::default()
        },
    ] {
        assert_eq!(
            project_zones(&frames, &tracks, &policy, limits, || true),
            Err(ZoneError::Limit)
        );
    }
    let mut reordered = policy.clone();
    reordered.zones.reverse();
    assert_ne!(
        project(&frames, &tracks, &reordered)?.report_digest,
        result.report_digest
    );
    Ok(())
}

#[test]
fn out_of_range_claim_is_refused_at_original_wire_boundary_without_clamping() -> Test {
    let lexical = "1000000000.000000000000001";
    assert_eq!(lexical.parse::<f64>()?, 1_000_000_000.0);
    assert_eq!(
        geometry::decimal_millionths(lexical),
        Err(GeometryError::Range)
    );
    // The frozen source parser rejects this exact decimal before a retained frame exists.
    // A rounded approximation must not be substituted to manufacture an admitted claim.
    let xml = format!(
        r#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:VideoAnalytics>{}</t:VideoAnalytics></t:MetadataStream>"#,
        frame(0, &object("1", [".1", lexical, ".2", ".4"]))
    );
    assert!(matches!(
        wire::parse_metadata_document(xml.as_bytes()),
        Err(wire::WireError::InvalidField)
    ));
    Ok(())
}

#[test]
fn complete_box_margin_touching_and_reversed_numeric_endpoints_are_conservative() -> Test {
    let f = fixture(&frame(0, &object("1", [".4", ".2", ".4", ".2"])))?;
    let frames = inputs(&f);
    let tracks = track(&frames)?;
    let mut policy = policy_at(&tracks, 0)?;
    assert_eq!(
        project(&frames, &tracks, &policy)?.cells[0].relation,
        ZoneRelation::Inside
    );
    policy.zones[0].margin = 200_000;
    assert_eq!(
        project(&frames, &tracks, &policy)?.cells[0].relation,
        ZoneRelation::Boundary
    );
    assert_eq!(
        geometry::classify_rectangle([1, 1], [2, 2], [0, 0], [3, 3], u64::MAX),
        Err(GeometryError::Invalid)
    );
    Ok(())
}

#[test]
fn changed_scope_module_and_transform_declarations_never_become_outside() -> Test {
    let f = fixture(&frame(0, &object("1", ["2", "3", ".2", ".4"])))?;
    let frames = inputs(&f);
    let tracks = track(&frames)?;
    let policy = policy_at(&tracks, 0)?;
    for (slot, expected) in [
        ZoneUnavailable::ScopeMismatch,
        ZoneUnavailable::ModuleMismatch,
        ZoneUnavailable::FrameTransformMismatch,
        ZoneUnavailable::ObjectTransformMismatch,
    ]
    .into_iter()
    .enumerate()
    {
        let mut policy = policy.clone();
        let zone = &mut policy.zones[0];
        match slot {
            0 => zone.scope = digest("changed"),
            1 => zone.module_digest = digest("changed"),
            2 => zone.frame_transform_digest = digest("changed"),
            _ => zone.object_transform_digest = digest("changed"),
        }
        let result = project(&frames, &tracks, &policy)?;
        assert_eq!(result.cells[0].relation, ZoneRelation::Unavailable);
        assert_eq!(result.cells[0].reason, Some(expected));
        assert_eq!(result.frame_samples[0].outside, 0);
    }
    Ok(())
}

#[test]
fn declared_raw_coordinates_do_not_apply_even_known_reflected_transforms() -> Test {
    let transform = r#"<t:Transformation><t:Translate x="100" y="200"/><t:Scale x="-1" y="2"/></t:Transformation>"#;
    let object = object("1", [".2", ".4", ".2", ".4"])
        .replace("<t:Appearance>", &format!("<t:Appearance>{transform}"));
    let f = fixture(&frame(0, &(transform.to_owned() + &object)))?;
    let frames = inputs(&f);
    let tracks = track(&frames)?;
    let policy = policy_at(&tracks, 0)?;
    assert_eq!(
        project(&frames, &tracks, &policy)?.cells[0].relation,
        ZoneRelation::Inside
    );
    Ok(())
}

#[test]
fn missing_and_opaque_geometry_remains_in_the_full_unknown_inventory() -> Test {
    let healthy = object("1", [".2", ".4", ".2", ".4"]);
    let absent = r#"<t:Object ObjectId="2"/>"#;
    let shapeless = r#"<t:Object ObjectId="3"><t:Appearance/></t:Object>"#;
    let opaque =
        object("4", [".2", ".4", ".2", ".4"]).replace("</t:Shape>", "<v:Polygon/></t:Shape>");
    let f = fixture(&frame(0, &(healthy + absent + shapeless + &opaque)))?;
    let frames = inputs(&f);
    let tracks = track(&frames)?;
    let policy = policy_at(&tracks, 0)?;
    let result = project(&frames, &tracks, &policy)?;
    assert_eq!(
        result.cells.iter().map(|c| c.reason).collect::<Vec<_>>(),
        [
            None,
            Some(ZoneUnavailable::MissingAppearance),
            Some(ZoneUnavailable::MissingShape),
            Some(ZoneUnavailable::UnsupportedShape)
        ]
    );
    assert_eq!(result.frame_samples[0].inside, 1);
    assert_eq!(result.frame_samples[0].unavailable, 3);
    Ok(())
}

#[test]
fn opaque_frame_or_outer_source_blocks_every_claim_including_empty_samples() -> Test {
    let f =
        fixture(&(frame(0, &object("1", [".2", ".4", ".2", ".4"])) + &frame(1, "<v:Opaque/>")))?;
    let mut frames = inputs(&f);
    frames[0].uninterpreted_source = true;
    let tracks = track(&frames)?;
    let policy = policy_at(&tracks, 0)?;
    let result = project(&frames, &tracks, &policy)?;
    assert_eq!(
        result.cells[0].reason,
        Some(ZoneUnavailable::UninterpretedSource)
    );
    assert_eq!(
        result.frame_samples[1].basis_unavailable,
        Some(ZoneUnavailable::UnsupportedFrameContent)
    );
    assert_eq!(
        result.frame_samples[1].inside
            + result.frame_samples[1].outside
            + result.frame_samples[1].boundary
            + result.frame_samples[1].unavailable,
        0
    );
    Ok(())
}

#[test]
fn empty_wrong_module_and_empty_matching_module_are_distinguishable() -> Test {
    let wrong = frame(1, "").replace("private_module_canary", "another_module");
    let f = fixture(&(frame(0, &object("1", [".2", ".4", ".2", ".4"])) + &wrong + &frame(2, "")))?;
    let frames = inputs(&f);
    let tracks = track(&frames)?;
    let policy = policy_at(&tracks, 0)?;
    let result = project(&frames, &tracks, &policy)?;
    assert_eq!(result.frame_samples.len(), 3);
    assert_eq!(
        result.frame_samples[1].basis_unavailable,
        Some(ZoneUnavailable::ModuleMismatch)
    );
    assert_eq!(result.frame_samples[2].basis_unavailable, None);
    assert_eq!(result.cells.len(), 1);
    Ok(())
}

#[test]
fn side_transitions_preserve_endpoint_handles_and_do_not_interpolate_boundary_samples() -> Test {
    let f = fixture(
        &(frame(0, &object("1", ["2", "3", ".2", ".4"]))
            + &frame(1, &object("1", [".8", "1.2", ".2", ".4"]))
            + &frame(2, &object("1", [".2", ".4", ".2", ".4"]))
            + &frame(3, &object("1", ["2", "3", ".2", ".4"]))),
    )?;
    let frames = inputs(&f);
    let tracks = track(&frames)?;
    let policy = policy_at(&tracks, 0)?;
    let result = project(&frames, &tracks, &policy)?;
    assert_eq!(result.transitions.len(), 2);
    assert_eq!(
        (
            result.transitions[0].kind,
            result.transitions[0].previous_occurrence,
            result.transitions[0].occurrence
        ),
        (ZoneTransitionKind::EnteredBetweenObservations, Some(0), 2)
    );
    assert_eq!(
        (
            result.transitions[1].kind,
            result.transitions[1].previous_occurrence,
            result.transitions[1].occurrence
        ),
        (ZoneTransitionKind::LeftBetweenObservations, Some(2), 3)
    );
    Ok(())
}

#[test]
fn missing_shape_interrupts_the_side_without_destroying_the_vendor_tracklet() -> Test {
    let f = fixture(
        &(frame(0, &object("1", [".2", ".4", ".2", ".4"]))
            + &frame(1, r#"<t:Object ObjectId="1"><t:Appearance/></t:Object>"#)
            + &frame(2, &object("1", [".2", ".4", ".2", ".4"]))),
    )?;
    let frames = inputs(&f);
    let tracks = track(&frames)?;
    let policy = policy_at(&tracks, 0)?;
    assert_eq!(tracks.tracklets.len(), 1);
    let result = project(&frames, &tracks, &policy)?;
    assert_eq!(
        result
            .transitions
            .iter()
            .map(|t| t.kind)
            .collect::<Vec<_>>(),
        [
            ZoneTransitionKind::ObservedInside,
            ZoneTransitionKind::ObservationInterrupted,
            ZoneTransitionKind::ObservedInside
        ]
    );
    assert_eq!(result.transitions[1].previous_occurrence, Some(0));
    assert_eq!(result.transitions[2].previous_occurrence, None);
    Ok(())
}

#[test]
fn empty_frames_source_barriers_and_vendor_clock_breaks_never_stitch_a_crossing() -> Test {
    for middle in [
        frame(1, ""),
        frame(1, "").replace(" Source=\"private_module_canary\"", ""),
    ] {
        let f = fixture(
            &(frame(0, &object("1", ["2", "3", ".2", ".4"]))
                + &middle
                + &frame(2, &object("1", [".2", ".4", ".2", ".4"]))),
        )?;
        let frames = inputs(&f);
        let tracks = track(&frames)?;
        let policy = policy_at(&tracks, 0)?;
        let result = project(&frames, &tracks, &policy)?;
        assert_eq!(result.transitions.len(), 1);
        assert_eq!(
            result.transitions[0].kind,
            ZoneTransitionKind::ObservedInside
        );
    }
    for (second, boundary) in [(0, false), (9, false), (1, true)] {
        let f = fixture(
            &(frame(0, &object("1", ["2", "3", ".2", ".4"]))
                + &frame(second, &object("1", [".2", ".4", ".2", ".4"]))),
        )?;
        let mut frames = inputs(&f);
        frames[1].boundary_before = boundary;
        let tracks = track(&frames)?;
        let policy = policy_at(&tracks, 0)?;
        let result = project(&frames, &tracks, &policy)?;
        assert_eq!(result.transitions.len(), 1);
        assert_eq!(
            result.transitions[0].kind,
            ZoneTransitionKind::ObservedInside
        );
    }
    Ok(())
}

#[test]
fn altered_source_pair_or_track_membership_refuses_before_zone_results() -> Test {
    let f = fixture(
        &(frame(0, &object("1", ["2", "3", ".2", ".4"]))
            + &frame(1, &object("1", [".2", ".4", ".2", ".4"]))),
    )?;
    let mut frames = inputs(&f);
    let tracks = track(&frames)?;
    let policy = policy_at(&tracks, 0)?;
    let mut forged = tracks.clone();
    forged.tracklets[0].occurrence_indices.reverse();
    assert_eq!(
        project_zones(&frames, &forged, &policy, ZoneLimits::default(), || true),
        Err(ZoneError::InvalidInput)
    );
    frames[0].source_root = digest("another root");
    assert_eq!(
        project_zones(&frames, &tracks, &policy, ZoneLimits::default(), || true),
        Err(ZoneError::InvalidInput)
    );
    Ok(())
}

#[test]
fn policy_parser_is_closed_exact_and_binds_all_coordinate_domain_fields() -> Test {
    let f = fixture(&frame(0, &object("1", [".2", ".4", ".2", ".4"])))?;
    let frames = inputs(&f);
    let tracks = track(&frames)?;
    let policy = policy_at(&tracks, 0)?;
    let text = policy_json(&policy);
    assert_eq!(ZonePolicy::parse_json(&text)?, policy);
    assert_eq!(
        ZonePolicy::parse_json(&format!(" \n{text}\n "))?.digest()?,
        policy.digest()?
    );
    for bad in [
        text.replace("raw_vendor_object_millionths", "pixels"),
        text.replace("\"min\":[0,0]", "\"min\":[0.1,0]"),
        text.replace("\"min\":[0,0]", "\"min\":[\"0\",0]"),
        text.replace("\"margin\":0", "\"margin\":-1"),
        text.replace("\"zones\":[", "\"unknown\":true,\"zones\":["),
        text.replace("\"margin\":0", "\"unknown\":0,\"margin\":0"),
        text.replace("\"min\":[0,0]", "\"min\":[1000000,0]"),
        text.replace("\"margin\":0", "\"margin\":0,\"margin\":0"),
        " ".repeat(MAX_ZONE_POLICY_BYTES + 1),
    ] {
        assert!(ZonePolicy::parse_json(&bad).is_err());
    }
    let mut duplicate = policy.clone();
    duplicate.zones.push(duplicate.zones[0].clone());
    assert_eq!(duplicate.validate(), Err(ZoneError::InvalidPolicy));
    let mut changed = policy.clone();
    changed.zones[0].margin = 1;
    assert_ne!(changed.digest()?, policy.digest()?);
    Ok(())
}

#[test]
fn every_aggregate_bound_refuses_whole_output_and_exact_work_and_bytes_are_admitted() -> Test {
    let f = fixture(
        &(frame(0, &object("1", [".2", ".4", ".2", ".4"]))
            + &frame(1, &object("1", ["2", "3", ".2", ".4"]))),
    )?;
    let frames = inputs(&f);
    let tracks = track(&frames)?;
    let policy = policy_at(&tracks, 0)?;
    let result = project(&frames, &tracks, &policy)?;
    let limits = ZoneLimits {
        max_work_units: result.work_units,
        max_output_bytes: result.encoded_bytes,
        ..ZoneLimits::default()
    };
    let exact = project_zones(&frames, &tracks, &policy, limits, || true)?;
    assert_eq!(exact.work_units, result.work_units);
    assert_eq!(exact.encoded_bytes, result.encoded_bytes);
    for (limits, expected) in [
        (
            ZoneLimits {
                max_work_units: result.work_units - 1,
                ..limits
            },
            ZoneError::BudgetExceeded,
        ),
        (
            ZoneLimits {
                max_output_bytes: result.encoded_bytes - 1,
                ..limits
            },
            ZoneError::Limit,
        ),
        (
            ZoneLimits {
                max_cells: 1,
                ..limits
            },
            ZoneError::Limit,
        ),
        (
            ZoneLimits {
                max_frame_samples: 1,
                ..limits
            },
            ZoneError::Limit,
        ),
        (
            ZoneLimits {
                max_transitions: 1,
                ..limits
            },
            ZoneError::Limit,
        ),
    ] {
        assert_eq!(
            project_zones(&frames, &tracks, &policy, limits, || true),
            Err(expected)
        );
    }
    assert_eq!(track(&frames)?, tracks);
    Ok(())
}

#[test]
fn cancellation_at_initial_or_final_admission_returns_no_successful_prefix() -> Test {
    let f = fixture(&frame(0, &object("1", [".2", ".4", ".2", ".4"])))?;
    let frames = inputs(&f);
    let tracks = track(&frames)?;
    let policy = policy_at(&tracks, 0)?;
    let calls = Cell::new(0_usize);
    project_zones(&frames, &tracks, &policy, ZoneLimits::default(), || {
        calls.set(calls.get() + 1);
        true
    })?;
    let complete_calls = calls.get();
    for stop in [1, 2, complete_calls / 2, complete_calls] {
        calls.set(0);
        assert_eq!(
            project_zones(&frames, &tracks, &policy, ZoneLimits::default(), || {
                calls.set(calls.get() + 1);
                calls.get() < stop
            }),
            Err(ZoneError::Cancelled)
        );
        assert_eq!(calls.get(), stop);
    }
    Ok(())
}

#[test]
fn genuine_json_writer_preserves_complete_references_and_withholds_vendor_values() -> Test {
    let f = fixture(
        &(frame(
            0,
            &object("+987654321098765432109876543210", [".2", ".4", ".2", ".4"]),
        ) + &frame(
            1,
            &object("987654321098765432109876543210", ["2", "3", ".2", ".4"]),
        ) + &frame(2, "")),
    )?;
    let frames = inputs(&f);
    let tracks = track(&frames)?;
    let policy = policy_at(&tracks, 0)?;
    let result = project(&frames, &tracks, &policy)?;
    let mut json = String::new();
    zones_json::write_json(&mut json, &result)?;
    let value = parse(&json)?;
    assert_eq!(
        field(&value, "schema")?.text(),
        Some("fss.onvif_vendor_zone_projection.v1")
    );
    assert_eq!(
        field(&value, "source_provenance")?.text(),
        Some("vendor_claimed")
    );
    assert_eq!(field(&value, "absence_certified")?, &Value::Bool(false));
    assert_eq!(rows(&value, "cells")?.len(), 2);
    assert_eq!(rows(&value, "frame_samples")?.len(), 3);
    assert_eq!(rows(&value, "transitions")?.len(), 2);
    assert_eq!(
        field(&rows(&value, "transitions")?[1], "previous_occurrence")?.integer(),
        Some(0)
    );
    assert_eq!(
        field(&rows(&value, "transitions")?[1], "occurrence")?.integer(),
        Some(1)
    );
    assert_eq!(
        field(&value, "report_digest")?.text(),
        Some(result.report_digest.to_text().as_str())
    );
    for private in [
        "private_module_canary",
        "987654321098765432109876543210",
        "2026-11-09",
    ] {
        assert!(!json.contains(private));
    }
    let debug = format!(
        "{result:?} {:?} {:?}",
        result.policy, result.policy.zones[0]
    );
    assert!(!debug.contains("private_zone_annotation"));
    assert!(!debug.contains("private_module_canary"));
    struct Bounded {
        remaining: usize,
    }
    impl fmt::Write for Bounded {
        fn write_str(&mut self, value: &str) -> fmt::Result {
            if value.len() > self.remaining {
                return Err(fmt::Error);
            }
            self.remaining -= value.len();
            Ok(())
        }
    }
    for length in [0, 1, json.len() / 2, json.len() - 1] {
        assert!(zones_json::write_json(&mut Bounded { remaining: length }, &result).is_err());
    }
    assert!(
        zones_json::write_json(
            &mut Bounded {
                remaining: json.len()
            },
            &result
        )
        .is_ok()
    );
    Ok(())
}
