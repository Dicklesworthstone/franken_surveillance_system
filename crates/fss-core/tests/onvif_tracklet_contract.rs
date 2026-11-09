#![forbid(unsafe_code)]
//! Execute the actual native ONVIF wire parser and tracklet projector against the
//! actual core contracts, without a replacement runtime, parser or authority facade.

#[path = "../../fss-reference/src/onvif/wire.rs"]
pub mod wire;
/// The production namespace, exposing the actual wire implementation to its consumer.
pub mod onvif {
    pub use crate::wire;
}
#[path = "../../fss-reference/src/onvif/metadata/tracks/contract.rs"]
mod tracks;

use fss_core::{ContentDigest, Plane, ProvenanceClass};
use tracks::{
    TrackBreakReason as Reason, TrackError, TrackFrameInput, TrackLimits, TrackletReport,
    project_tracklets,
};
use wire::{AnalyticsFrame, EventDocument, parse_metadata_document};

type Test = Result<(), Box<dyn std::error::Error>>;

fn digest(value: &str) -> ContentDigest {
    ContentDigest::sha256(value.as_bytes())
}
fn object(id: &str) -> String {
    format!(r#"<t:Object ObjectId="{id}"/>"#)
}
fn frame(time: &str, module: Option<&str>, objects: &str) -> String {
    let source = module
        .map(|name| format!(r#" Source="{name}""#))
        .unwrap_or_default();
    format!(r#"<t:Frame UtcTime="{time}"{source}>{objects}</t:Frame>"#)
}
fn at(second: u8, module: &str, objects: &str) -> String {
    frame(
        &format!("2026-11-09T01:00:{second:02}Z"),
        Some(module),
        objects,
    )
}
fn document(frames: &str) -> Result<EventDocument, wire::WireError> {
    parse_metadata_document(format!(
        r#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema" xmlns:v="urn:vendor"><t:VideoAnalytics>{frames}</t:VideoAnalytics></t:MetadataStream>"#,
    ).as_bytes())
}
fn inputs(frames: &[AnalyticsFrame]) -> Vec<TrackFrameInput<'_>> {
    frames
        .iter()
        .enumerate()
        .map(|(index, frame)| TrackFrameInput {
            scope: digest("sensor/device/profile/parser/transport-generation"),
            source_identity: digest("retained-source"),
            source_root: digest("retained-root"),
            source_digest: digest("original-xml"),
            frame_digest: digest(&format!("original-frame-{index}")),
            document_index: 0,
            frame_index: index,
            frame,
            boundary_before: false,
            uninterpreted_source: false,
        })
        .collect()
}
fn project(document: &EventDocument) -> Result<TrackletReport, TrackError> {
    project_tracklets(
        &inputs(&document.analytics_frames),
        TrackLimits::default(),
        || true,
    )
}
fn has_end(report: &TrackletReport, index: usize, reason: Reason) -> bool {
    report.tracklets[index].end_reasons.contains(&reason)
}

#[test]
fn exact_occurrences_form_one_vendor_run_without_physical_authority() -> Test {
    let doc = document(
        &(at(0, "motion", &object("+001"))
            + &at(1, "motion", &object("1"))
            + &at(2, "motion", &object("01"))),
    )?;
    let report = project(&doc)?;
    assert_eq!(report.frames.len(), 3);
    assert_eq!(report.occurrences.len(), 3);
    assert_eq!(report.tracklets.len(), 1);
    assert_eq!(report.tracklets[0].occurrence_indices, [0, 1, 2]);
    assert_eq!(
        report
            .occurrences
            .iter()
            .map(|v| v.vendor_object_id.as_str())
            .collect::<Vec<_>>(),
        ["+001", "1", "01"]
    );
    assert!(has_end(&report, 0, Reason::EndOfInput));
    assert_eq!(report.plane(), Plane::Cognition);
    assert_eq!(report.provenance(), ProvenanceClass::Derived);
    assert_eq!(report.source_provenance(), ProvenanceClass::VendorClaimed);
    for (index, occurrence) in report.occurrences.iter().enumerate() {
        assert_eq!(occurrence.frame_ordinal, index);
        assert_eq!(occurrence.object_index, 0);
        assert_eq!(report.frames[index].reference.frame_index, index);
        assert_eq!(
            report.frames[index].reference.source_digest,
            digest("original-xml")
        );
    }
    assert_ne!(
        report.occurrences[0].identity,
        report.occurrences[1].identity
    );
    assert_eq!(report, project(&doc)?);
    Ok(())
}

#[test]
fn empty_frame_terminates_claimed_run_but_is_not_absence() -> Test {
    let doc = document(&(at(0, "m", &object("7")) + &at(1, "m", "") + &at(2, "m", &object("7"))))?;
    let report = project(&doc)?;
    assert_eq!(report.frames.len(), 3);
    assert_eq!(report.frames[1].occurrence_count, 0);
    assert_eq!(report.tracklets.len(), 2);
    assert!(has_end(&report, 0, Reason::MissingOccurrence));
    assert_ne!(report.tracklets[0].identity, report.tracklets[1].identity);
    assert_eq!(
        report.tracklets[0].vendor_key_digest,
        report.tracklets[1].vendor_key_digest
    );
    Ok(())
}

#[test]
fn missing_one_object_splits_only_that_object() -> Test {
    let doc = document(
        &(at(0, "m", &(object("1") + &object("2")))
            + &at(1, "m", &object("2"))
            + &at(2, "m", &(object("1") + &object("2")))),
    )?;
    let report = project(&doc)?;
    assert_eq!(report.tracklets.len(), 3);
    assert_eq!(report.tracklets[1].occurrence_indices, [1, 2, 4]);
    assert!(has_end(&report, 0, Reason::MissingOccurrence));
    Ok(())
}

#[test]
fn module_clocks_and_object_namespaces_are_independent() -> Test {
    let doc = document(
        &(at(40, "a", &object("1"))
            + &at(0, "b", &object("1"))
            + &at(41, "a", &object("1"))
            + &at(1, "b", &object("1"))),
    )?;
    let report = project(&doc)?;
    assert_eq!(report.tracklets.len(), 2);
    assert_eq!(report.tracklets[0].occurrence_indices, [0, 2]);
    assert_eq!(report.tracklets[1].occurrence_indices, [1, 3]);
    assert_ne!(
        report.tracklets[0].vendor_key_digest,
        report.tracklets[1].vendor_key_digest
    );
    Ok(())
}

#[test]
fn missing_or_empty_module_breaks_every_active_module_and_isolates_occurrences() -> Test {
    for module in [None, Some("")] {
        let doc = document(
            &(at(0, "a", &object("1"))
                + &at(0, "b", &object("1"))
                + &frame("2026-11-09T01:00:01Z", module, &object("1"))
                + &at(2, "a", &object("1"))
                + &at(2, "b", &object("1"))),
        )?;
        let report = project(&doc)?;
        assert_eq!(report.tracklets.len(), 5);
        for index in 0..3 {
            assert!(has_end(&report, index, Reason::MissingModule));
        }
        assert_eq!(report.frames[2].module_digest, None);
    }
    Ok(())
}

#[test]
fn explicit_source_gap_breaks_interleaved_modules() -> Test {
    let doc = document(
        &(at(0, "a", &object("1"))
            + &at(0, "b", &object("1"))
            + &at(1, "a", &object("1"))
            + &at(1, "b", &object("1"))),
    )?;
    let mut frames = inputs(&doc.analytics_frames);
    frames[2].boundary_before = true;
    let report = project_tracklets(&frames, TrackLimits::default(), || true)?;
    assert_eq!(report.tracklets.len(), 4);
    assert!(has_end(&report, 0, Reason::SourceBoundary));
    assert!(has_end(&report, 1, Reason::SourceBoundary));
    Ok(())
}

#[test]
fn generation_changes_and_independent_sources_never_join() -> Test {
    let doc = document(&(at(0, "m", &object("1")) + &at(1, "m", &object("1"))))?;
    let mut frames = inputs(&doc.analytics_frames);
    frames[1].scope = digest("new-device-generation");
    let report = project_tracklets(&frames, TrackLimits::default(), || true)?;
    assert_eq!(report.tracklets.len(), 2);
    assert!(has_end(&report, 0, Reason::GenerationChanged));
    let mut frames = inputs(&doc.analytics_frames);
    frames[1].source_identity = digest("independent-source");
    frames[1].frame_index = 0;
    let report = project_tracklets(&frames, TrackLimits::default(), || true)?;
    assert_eq!(report.tracklets.len(), 2);
    assert!(has_end(&report, 0, Reason::SourceBoundary));
    Ok(())
}

#[test]
fn skipped_or_backward_frame_and_document_locators_split_without_an_explicit_flag() -> Test {
    let doc = document(&(at(0, "m", &object("1")) + &at(1, "m", &object("1"))))?;
    for (first_doc, first_frame, next_doc, next_frame) in [
        (0, 0, 0, 2),
        (0, 2, 0, 1),
        (0, 0, 2, 0),
        (2, 0, 1, 0),
        (0, 0, 1, 1),
    ] {
        let mut frames = inputs(&doc.analytics_frames);
        frames[0].document_index = first_doc;
        frames[0].frame_index = first_frame;
        frames[1].document_index = next_doc;
        frames[1].frame_index = next_frame;
        let report = project_tracklets(&frames, TrackLimits::default(), || true)?;
        assert_eq!(report.tracklets.len(), 2);
        assert!(has_end(&report, 0, Reason::SourceBoundary));
    }
    let mut frames = inputs(&doc.analytics_frames);
    frames[1].document_index = 1;
    frames[1].frame_index = 0;
    frames[1].source_digest = digest("second-original-xml");
    assert_eq!(
        project_tracklets(&frames, TrackLimits::default(), || true)?
            .tracklets
            .len(),
        1
    );
    Ok(())
}

#[test]
fn repeated_equivalent_or_reversed_vendor_times_split() -> Test {
    for second in ["2026-11-09T01:00:00.100000000Z", "2026-11-09T00:59:59Z"] {
        let doc = document(
            &(frame("2026-11-09T01:00:00.1Z", Some("m"), &object("1"))
                + &frame(second, Some("m"), &object("1"))),
        )?;
        let report = project(&doc)?;
        assert_eq!(report.tracklets.len(), 2);
        assert!(has_end(&report, 0, Reason::VendorTimeNotIncreasing));
    }
    Ok(())
}

#[test]
fn vendor_gap_policy_is_inclusive_and_nanosecond_exact() -> Test {
    let mut limits = TrackLimits::default();
    limits.max_vendor_gap_ns = 1;
    let doc = document(
        &(frame("9999-12-31T23:59:59.999999997Z", Some("m"), &object("1"))
            + &frame("9999-12-31T23:59:59.999999998Z", Some("m"), &object("1"))
            + &frame("9999-12-31T23:59:59.999999999Z", Some("m"), &object("1"))),
    )?;
    assert_eq!(
        project_tracklets(&inputs(&doc.analytics_frames), limits, || true)?
            .tracklets
            .len(),
        1
    );
    let doc = document(
        &(at(0, "m", &object("1")) + &at(5, "m", &object("1")) + &at(11, "m", &object("1"))),
    )?;
    let report = project(&doc)?;
    assert_eq!(report.tracklets.len(), 2);
    assert_eq!(report.tracklets[0].occurrence_indices, [0, 1]);
    assert!(has_end(&report, 0, Reason::VendorTimeGap));
    Ok(())
}

#[test]
fn frame_coordinate_changes_split_every_object_of_that_module() -> Test {
    let transform = r#"<t:Transformation><t:Scale x="1" y="-1"/></t:Transformation>"#;
    let doc = document(
        &(at(0, "m", &(object("1") + &object("2")))
            + &at(
                1,
                "m",
                &(transform.to_owned() + &object("1") + &object("2")),
            )),
    )?;
    let report = project(&doc)?;
    assert_eq!(report.tracklets.len(), 4);
    assert!(has_end(&report, 0, Reason::FrameTransformChanged));
    assert!(has_end(&report, 1, Reason::FrameTransformChanged));
    Ok(())
}

#[test]
fn object_coordinate_changes_split_only_that_object() -> Test {
    let transformed = r#"<t:Object ObjectId="1"><t:Appearance><t:Transformation><t:Scale x="1" y="-1"/></t:Transformation></t:Appearance></t:Object>"#;
    let doc = document(
        &(at(0, "m", &(object("1") + &object("2")))
            + &at(1, "m", &(transformed.to_owned() + &object("2")))),
    )?;
    let report = project(&doc)?;
    assert_eq!(report.tracklets.len(), 3);
    assert!(has_end(&report, 0, Reason::ObjectTransformChanged));
    assert_eq!(report.tracklets[1].occurrence_indices, [1, 3]);
    Ok(())
}

#[test]
fn object_tree_and_sensitive_opaque_appearance_isolate_a_frame() -> Test {
    for opaque in [
        r#"<t:ObjectTree><t:Rename from="1" to="2"/></t:ObjectTree>"#,
        r#"<t:Object ObjectId="2"><t:Appearance><v:Face>private-face</v:Face></t:Appearance></t:Object>"#,
    ] {
        let doc = document(
            &(at(0, "m", &object("1"))
                + &at(1, "m", &(object("1") + opaque))
                + &at(2, "m", &object("1"))),
        )?;
        let report = project(&doc)?;
        assert!(
            report.frames[1]
                .barriers
                .contains(&Reason::UninterpretedContent)
        );
        assert!(has_end(&report, 0, Reason::UninterpretedContent));
        assert!(has_end(&report, 1, Reason::UninterpretedContent));
        assert!(
            report
                .tracklets
                .iter()
                .all(|t| t.occurrence_indices.len() == 1)
        );
        assert!(!format!("{report:?}").contains("private-face"));
    }
    Ok(())
}

#[test]
fn opaque_outer_source_breaks_all_modules_not_only_the_current_frame() -> Test {
    let doc = document(
        &(at(0, "a", &object("1"))
            + &at(0, "b", &object("1"))
            + &at(1, "a", &object("1"))
            + &at(1, "b", &object("1"))),
    )?;
    let mut frames = inputs(&doc.analytics_frames);
    frames[2].uninterpreted_source = true;
    let report = project_tracklets(&frames, TrackLimits::default(), || true)?;
    assert_eq!(report.tracklets.len(), 4);
    for index in 0..3 {
        assert!(has_end(&report, index, Reason::UninterpretedContent));
    }
    Ok(())
}

#[test]
fn duplicate_or_rebound_source_and_occurrence_pins_refuse() -> Test {
    let doc = document(&(at(0, "m", &object("1")) + &at(1, "m", &object("1"))))?;
    let mut frames = inputs(&doc.analytics_frames);
    frames[1].frame_index = 0;
    assert_eq!(
        project_tracklets(&frames, TrackLimits::default(), || true),
        Err(TrackError::DuplicateFrame)
    );
    let mut frames = inputs(&doc.analytics_frames);
    frames[1].source_root = digest("rebound-root");
    assert_eq!(
        project_tracklets(&frames, TrackLimits::default(), || true),
        Err(TrackError::InvalidInput)
    );
    let mut frames = inputs(&doc.analytics_frames);
    frames[1].source_digest = digest("different-xml-for-same-document");
    assert_eq!(
        project_tracklets(&frames, TrackLimits::default(), || true),
        Err(TrackError::InvalidInput)
    );
    let mut forged = doc.clone();
    let mut alias = forged.analytics_frames[0].objects[0].clone();
    alias.object_id = "+001".to_owned();
    forged.analytics_frames[0].objects.push(alias);
    assert_eq!(project(&forged), Err(TrackError::DuplicateObject));
    Ok(())
}

#[test]
fn frame_object_tracklet_work_and_output_limits_are_atomic() -> Test {
    let doc = document(
        &(at(0, "m", &(object("1") + &object("2"))) + &at(1, "m", &(object("1") + &object("2")))),
    )?;
    let frames = inputs(&doc.analytics_frames);
    for (limits, error) in [
        (
            TrackLimits {
                max_frames: 1,
                ..TrackLimits::default()
            },
            TrackError::Limit,
        ),
        (
            TrackLimits {
                max_objects: 3,
                ..TrackLimits::default()
            },
            TrackError::Limit,
        ),
        (
            TrackLimits {
                max_tracklets: 1,
                ..TrackLimits::default()
            },
            TrackError::Limit,
        ),
        (
            TrackLimits {
                max_work_units: 1,
                ..TrackLimits::default()
            },
            TrackError::BudgetExceeded,
        ),
        (
            TrackLimits {
                max_output_bytes: 1,
                ..TrackLimits::default()
            },
            TrackError::Limit,
        ),
    ] {
        assert_eq!(project_tracklets(&frames, limits, || true), Err(error));
    }
    let baseline = project(&doc)?;
    let tight = TrackLimits {
        max_output_bytes: baseline.encoded_bytes,
        ..TrackLimits::default()
    };
    let exact = project_tracklets(&frames, tight, || true)?;
    assert_eq!(exact.encoded_bytes, baseline.encoded_bytes);
    let one_short = TrackLimits {
        max_output_bytes: baseline.encoded_bytes - 1,
        ..TrackLimits::default()
    };
    assert_eq!(
        project_tracklets(&frames, one_short, || true),
        Err(TrackError::Limit)
    );
    let enough = TrackLimits {
        max_work_units: baseline.work_units,
        ..TrackLimits::default()
    };
    assert!(project_tracklets(&frames, enough, || true).is_ok());
    let not_enough = TrackLimits {
        max_work_units: baseline.work_units - 1,
        ..TrackLimits::default()
    };
    assert_eq!(
        project_tracklets(&frames, not_enough, || true),
        Err(TrackError::BudgetExceeded)
    );
    Ok(())
}

#[test]
fn every_admission_cut_refuses_the_complete_projection() -> Test {
    let doc = document(
        &(at(0, "m", &(object("1") + &object("2")))
            + &at(1, "m", &(object("1") + &object("2")))
            + &at(2, "m", "")),
    )?;
    let frames = inputs(&doc.analytics_frames);
    let mut checkpoints = 0;
    let baseline = project_tracklets(&frames, TrackLimits::default(), || {
        checkpoints += 1;
        true
    })?;
    for stop in 0..checkpoints {
        let mut current = 0;
        let refused = project_tracklets(&frames, TrackLimits::default(), || {
            let allowed = current != stop;
            current += 1;
            allowed
        });
        assert_eq!(refused, Err(TrackError::Cancelled), "cut {stop}");
        assert_eq!(current, stop + 1, "refusal must be sticky");
    }
    assert_eq!(baseline, project(&doc)?);
    Ok(())
}

#[test]
fn input_and_report_identities_bind_owner_pins_policy_and_typed_boundaries() -> Test {
    let doc = document(&(at(0, "m", &object("1")) + &at(1, "m", &object("1"))))?;
    let original = inputs(&doc.analytics_frames);
    let baseline = project(&doc)?;
    for field in 0..4 {
        let mut frames = original.clone();
        match field {
            0 => frames[1].frame_digest = digest("different-source-frame"),
            1 => frames[1].scope = digest("different-scope"),
            2 => frames[1].boundary_before = true,
            _ => frames[1].uninterpreted_source = true,
        }
        let changed = project_tracklets(&frames, TrackLimits::default(), || true)?;
        assert_ne!(baseline.input_digest, changed.input_digest);
        assert_ne!(baseline.report_digest, changed.report_digest);
    }
    let changed = project_tracklets(
        &original,
        TrackLimits {
            max_vendor_gap_ns: 2_000_000_000,
            ..TrackLimits::default()
        },
        || true,
    )?;
    assert_ne!(baseline.policy_digest, changed.policy_digest);
    assert_ne!(baseline.report_digest, changed.report_digest);
    Ok(())
}

#[test]
fn debug_withholds_all_private_vendor_strings() -> Test {
    let doc = document(
        &(at(0, "private-module-canary", &object("123456789123456789"))
            + &at(1, "private-module-canary", &object("123456789123456789"))),
    )?;
    let frames = inputs(&doc.analytics_frames);
    let report = project(&doc)?;
    let output = format!(
        "{report:?}{:?}{:?}{frames:?}",
        report.frames, report.occurrences
    );
    for value in [
        "private-module-canary",
        "123456789123456789",
        "2026-11-09T01:00",
    ] {
        assert!(!output.contains(value));
    }
    assert_eq!(
        report.occurrences[0].module_source.as_deref(),
        Some("private-module-canary")
    );
    Ok(())
}

#[test]
fn empty_input_and_empty_frame_preserve_zero_observations() -> Test {
    let empty = project_tracklets(&[], TrackLimits::default(), || true)?;
    assert!(empty.frames.is_empty());
    assert!(empty.occurrences.is_empty());
    assert!(empty.tracklets.is_empty());
    let doc = document(&at(0, "m", ""))?;
    let frame = project(&doc)?;
    assert_eq!(frame.frames.len(), 1);
    assert!(frame.tracklets.is_empty());
    assert_ne!(empty.report_digest, frame.report_digest);
    Ok(())
}

#[test]
fn actual_wire_timestamp_conversion_preserves_fraction_calendar_and_range() -> Test {
    use wire::parse_metadata_utc_nanoseconds as utc;
    assert_eq!(utc("1970-01-01T00:00:00Z")?, 0);
    assert_eq!(utc("1970-01-01T00:00:00.1Z")?, 100_000_000);
    assert_eq!(
        utc("1970-01-01T00:00:00.1Z")?,
        utc("1970-01-01T00:00:00.100000000Z")?
    );
    assert_eq!(utc("1970-01-01T00:00:00.000000001Z")?, 1);
    assert_eq!(
        utc("9999-12-31T23:59:59.999999999Z")?,
        253_402_300_799_999_999_999
    );
    assert_eq!(
        utc("2000-03-01T00:00:00Z")? - utc("2000-02-29T00:00:00Z")?,
        86_400_000_000_000
    );
    assert_eq!(
        utc("2100-03-01T00:00:00Z")? - utc("2100-02-28T00:00:00Z")?,
        86_400_000_000_000
    );
    for value in [
        "1969-12-31T23:59:59Z",
        "2026-02-29T00:00:00Z",
        "2100-02-29T00:00:00Z",
        "2026-11-09T01:00:60Z",
        "2026-11-09T24:00:00Z",
        "2026-11-09T01:00:00.0000000001Z",
        "2026-11-09T01:00:00.Z",
        "2026-11-09T01:00:00+00:00",
        "２０２６-11-09T01:00:00Z",
    ] {
        assert!(utc(value).is_err(), "{value}");
    }
    Ok(())
}

#[test]
fn shared_integer_key_preserves_the_wire_alias_contract() -> Test {
    for (value, expected) in [
        ("+001", "1"),
        ("01", "1"),
        ("-001", "-1"),
        ("-000", "0"),
        ("+0", "0"),
    ] {
        assert_eq!(wire::analytics_object_key(value)?, expected);
    }
    for value in ["", "+", "1.0", " 1", "1e1", "١", "--1"] {
        assert!(wire::analytics_object_key(value).is_err());
    }
    assert!(document(&at(0, "m", &(object("+001") + &object("1")))).is_err());
    Ok(())
}
