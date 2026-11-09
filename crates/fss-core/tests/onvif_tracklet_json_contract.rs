#![forbid(unsafe_code)]
//! Execute the actual production parser, projector, JSON primitives and projection renderer.
//! No retained owner, source custody, runtime or complete CLI execution is simulated here.

extern crate self as fss_cli;
extern crate self as fss_reference;

#[path = "../../fss-reference/src/onvif/metadata/tracks/contract.rs"]
pub mod contract;
#[path = "../../fss-cli/src/json_output.rs"]
pub mod json_output;
#[path = "../../fss-reference/src/onvif/wire.rs"]
pub mod wire;

/// Production namespaces containing the actual included implementation modules.
pub mod onvif {
    pub use crate::wire;
    /// Native metadata namespace; this test exposes only the real pure contract.
    pub mod metadata {
        /// Vendor tracklet namespace.
        pub mod tracks {
            pub use crate::contract;
        }
    }
}

#[path = "../../fss-cli/src/bin/fss-onvif-metadata/tracks/report/projection.rs"]
mod projection;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write};

use contract::{TrackFrameInput, TrackLimits, TrackletReport, project_tracklets};
use fss_core::ContentDigest;
use fss_core::json_input::{self, Value};
use wire::{AnalyticsFrame, EventDocument, parse_metadata_document};

type Checked<T> = Result<T, Box<dyn std::error::Error>>;
type Test = Checked<()>;

fn digest(value: &str) -> ContentDigest {
    ContentDigest::sha256(value.as_bytes())
}
fn document(frames: &str) -> Result<EventDocument, wire::WireError> {
    parse_metadata_document(format!(
        r#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema"><t:VideoAnalytics>{frames}</t:VideoAnalytics></t:MetadataStream>"#
    ).as_bytes())
}
fn frame_input(
    frame: &AnalyticsFrame,
    document_index: usize,
    frame_index: usize,
) -> TrackFrameInput<'_> {
    TrackFrameInput {
        scope: digest("exact-sensor-device-profile-parser-transport-generation"),
        source_identity: digest("retained-source-identity"),
        source_root: digest("retained-source-root"),
        source_digest: digest(&format!("original-xml-{document_index}")),
        frame_digest: digest(&format!("original-frame-{document_index}-{frame_index}")),
        document_index,
        frame_index,
        frame,
        boundary_before: false,
        uninterpreted_source: false,
    }
}
fn project(doc: &EventDocument) -> Result<TrackletReport, contract::TrackError> {
    let inputs: Vec<_> = doc
        .analytics_frames
        .iter()
        .enumerate()
        .map(|(index, frame)| frame_input(frame, 0, index))
        .collect();
    project_tracklets(&inputs, TrackLimits::default(), || true)
}
fn fixture() -> Result<EventDocument, wire::WireError> {
    document(concat!(
        "<t:Frame UtcTime=\"9999-12-31T23:59:59.1Z\" Source=\"private-zone &quot;quoted&quot; \\ 路線&#x2028;\"><t:Object ObjectId=\"+0042\"><t:Appearance><t:Class><t:Type>private-class-canary</t:Type></t:Class></t:Appearance></t:Object></t:Frame>",
        "<t:Frame UtcTime=\"9999-12-31T23:59:59.100000001Z\" Source=\"private-zone &quot;quoted&quot; \\ 路線&#x2028;\"><t:Object ObjectId=\"42\"><t:Appearance><t:Class><t:Type>private-class-canary</t:Type></t:Class></t:Appearance></t:Object></t:Frame>"
    ))
}
fn render(report: &TrackletReport, include_values: bool) -> Result<String, fmt::Error> {
    let mut out = String::from("{");
    projection::write_projection(&mut out, report, include_values)?;
    out.write_char('}')?;
    Ok(out)
}
fn object(value: &Value) -> Checked<&BTreeMap<String, Value>> {
    value.object().ok_or_else(|| "expected JSON object".into())
}
fn rows<'a>(value: &'a Value, field: &str) -> Checked<&'a [Value]> {
    object(value)?[field]
        .array()
        .ok_or_else(|| "expected JSON rows".into())
}
fn integer(value: &Value, field: &str) -> Checked<i128> {
    object(value)?[field]
        .integer()
        .ok_or_else(|| "expected exact integer".into())
}
fn text<'a>(value: &'a Value, field: &str) -> Checked<&'a str> {
    object(value)?[field]
        .text()
        .ok_or_else(|| "expected JSON text".into())
}
fn assert_exact_keys(value: &Value, expected: &[&str]) -> Test {
    assert_eq!(
        object(value)?
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        expected.iter().copied().collect()
    );
    Ok(())
}

#[test]
fn hidden_projection_is_valid_json_and_withholds_every_raw_value() -> Test {
    let report = project(&fixture()?)?;
    let hidden = render(&report, false)?;
    let parsed = json_input::parse(&hidden)?;
    assert_exact_keys(&parsed, &["frames", "occurrences", "tracklets"])?;
    for key in ["frames", "occurrences"] {
        for row in rows(&parsed, key)? {
            assert_eq!(object(row)?["values"], Value::Null);
        }
    }
    for canary in [
        "private-zone",
        "private-class-canary",
        "9999-12-31T23:59:59",
        "\"+0042\"",
        "路線",
    ] {
        assert!(
            !hidden.contains(canary),
            "private value reached undisclosed JSON"
        );
    }
    assert_eq!(rows(&parsed, "frames")?.len(), 2);
    assert_eq!(rows(&parsed, "occurrences")?.len(), 2);
    assert_eq!(rows(&parsed, "tracklets")?.len(), 1);
    Ok(())
}

#[test]
fn disclosure_round_trips_original_spelling_unicode_and_exact_nanoseconds() -> Test {
    let doc = fixture()?;
    let report = project(&doc)?;
    let rendered = render(&report, true)?;
    let parsed = json_input::parse(&rendered)?;
    let frames = rows(&parsed, "frames")?;
    let objects = rows(&parsed, "occurrences")?;
    for (index, frame) in frames.iter().enumerate() {
        let values = &object(frame)?["values"];
        assert_eq!(
            text(values, "module_source")?,
            doc.analytics_frames[index]
                .source
                .as_deref()
                .ok_or("expected named module")?
        );
        assert_eq!(
            text(values, "vendor_utc_time")?,
            doc.analytics_frames[index].utc_time
        );
        assert!(matches!(object(values)?["vendor_time_ns"], Value::Text(_)));
        assert_eq!(
            integer(values, "vendor_time_ns")?,
            report.frames[index].vendor_time_ns
        );
    }
    assert_eq!(
        integer(&object(&frames[1])?["values"], "vendor_time_ns")?
            - integer(&object(&frames[0])?["values"], "vendor_time_ns")?,
        1
    );
    assert_eq!(
        text(&object(&objects[0])?["values"], "vendor_object_id")?,
        "+0042"
    );
    assert_eq!(
        text(&object(&objects[1])?["values"], "vendor_object_id")?,
        "42"
    );
    assert!(rendered.contains("\\\"quoted\\\""));
    assert!(rendered.contains("\\u2028"));
    assert!(!rendered.contains("private-class-canary"));
    Ok(())
}

#[test]
fn renderer_preserves_all_source_handles_and_cross_array_references() -> Test {
    let report = project(&fixture()?)?;
    let parsed = json_input::parse(&render(&report, false)?)?;
    let frames = rows(&parsed, "frames")?;
    let objects = rows(&parsed, "occurrences")?;
    let tracks = rows(&parsed, "tracklets")?;
    for (index, frame) in frames.iter().enumerate() {
        let original = &report.frames[index];
        let reference = &original.reference;
        assert_eq!(integer(frame, "ordinal")?, index as i128);
        assert_eq!(
            integer(frame, "document_index")?,
            reference.document_index as i128
        );
        assert_eq!(
            integer(frame, "frame_index")?,
            reference.frame_index as i128
        );
        for (field, value) in [
            ("scope", reference.scope),
            ("source_identity", reference.source_identity),
            ("source_root", reference.source_root),
            ("source_digest", reference.source_digest),
            ("frame_digest", reference.frame_digest),
            ("transformation_digest", original.transformation_digest),
        ] {
            assert_eq!(text(frame, field)?, value.to_text());
        }
        assert_eq!(
            integer(frame, "occurrence_start")?,
            original.occurrence_start as i128
        );
        assert_eq!(
            integer(frame, "occurrence_count")?,
            original.occurrence_count as i128
        );
    }
    for (index, occurrence) in objects.iter().enumerate() {
        let original = &report.occurrences[index];
        assert_eq!(text(occurrence, "identity")?, original.identity.to_text());
        assert_eq!(
            text(occurrence, "tracklet_identity")?,
            original.tracklet_identity.to_text()
        );
        assert_eq!(
            integer(occurrence, "frame_ordinal")?,
            original.frame_ordinal as i128
        );
        assert_eq!(
            integer(occurrence, "object_index")?,
            original.object_index as i128
        );
        assert_eq!(
            text(occurrence, "transformation_digest")?,
            original.transformation_digest.to_text()
        );
    }
    for (index, track) in tracks.iter().enumerate() {
        let original = &report.tracklets[index];
        assert_eq!(text(track, "identity")?, original.identity.to_text());
        assert_eq!(text(track, "scope")?, original.scope.to_text());
        assert_eq!(
            text(track, "vendor_key_digest")?,
            original.vendor_key_digest.to_text()
        );
        let indices = rows(track, "occurrence_indices")?;
        assert_eq!(
            indices
                .iter()
                .map(|value| value
                    .integer()
                    .map(|number| number as usize)
                    .ok_or("expected occurrence index"))
                .collect::<Result<Vec<_>, _>>()?,
            original.occurrence_indices
        );
        for occurrence in indices {
            let occurrence =
                &objects[occurrence.integer().ok_or("expected occurrence index")? as usize];
            assert_eq!(
                text(occurrence, "tracklet_identity")?,
                text(track, "identity")?
            );
        }
    }
    Ok(())
}

#[test]
fn production_schema_closed_row_shapes_match_the_actual_renderer() -> Test {
    let schema = json_input::parse(include_str!(
        "../../../schemas/onvif_vendor_tracklets_report.v1.json"
    ))?;
    let definitions = object(&schema)?["$defs"]
        .object()
        .ok_or("expected schema definitions")?;
    let report = project(&fixture()?)?;
    for disclosed in [false, true] {
        let parsed = json_input::parse(&render(&report, disclosed)?)?;
        for (field, definition) in [
            ("frames", "frame"),
            ("occurrences", "occurrence"),
            ("tracklets", "tracklet"),
        ] {
            let definition = object(&definitions[definition])?;
            assert_eq!(definition["additionalProperties"], Value::Bool(false));
            let keys: Vec<_> = definition["required"]
                .array()
                .ok_or("expected required keys")?
                .iter()
                .map(|value| value.text().ok_or("expected required key"))
                .collect::<Result<_, _>>()?;
            for row in rows(&parsed, field)? {
                assert_exact_keys(row, &keys)?;
                if disclosed && field != "tracklets" {
                    let values_definition = if field == "frames" {
                        "frame_values"
                    } else {
                        "occurrence_values"
                    };
                    let values_keys: Vec<_> = object(&definitions[values_definition])?["required"]
                        .array()
                        .ok_or("expected required value keys")?
                        .iter()
                        .map(|value| value.text().ok_or("expected value key"))
                        .collect::<Result<_, _>>()?;
                    assert_exact_keys(&object(row)?["values"], &values_keys)?;
                }
            }
        }
    }
    Ok(())
}

#[test]
fn absent_module_is_json_null_and_empty_inputs_are_explicit_arrays() -> Test {
    let doc =
        document("<t:Frame UtcTime=\"2026-11-09T01:00:00Z\"><t:Object ObjectId=\"1\"/></t:Frame>")?;
    let parsed = json_input::parse(&render(&project(&doc)?, true)?)?;
    for field in ["frames", "occurrences"] {
        assert_eq!(
            object(&object(&rows(&parsed, field)?[0])?["values"])?["module_source"],
            Value::Null
        );
    }
    assert_eq!(
        object(&rows(&parsed, "frames")?[0])?["module_digest"],
        Value::Null
    );
    let empty = project_tracklets(&[], TrackLimits::default(), || true)?;
    assert_eq!(
        render(&empty, false)?,
        r#"{"frames":[],"occurrences":[],"tracklets":[]}"#
    );
    Ok(())
}

#[test]
fn rendering_is_deterministic_and_disclosure_does_not_mutate_the_projection() -> Test {
    let report = project(&fixture()?)?;
    let before = report.clone();
    let hidden = render(&report, false)?;
    let disclosed = render(&report, true)?;
    assert_eq!(hidden, render(&report, false)?);
    assert_eq!(disclosed, render(&report, true)?);
    assert_ne!(hidden, disclosed);
    assert_eq!(before, report);
    Ok(())
}

struct BoundedSink {
    text: String,
    maximum: usize,
    refused: bool,
}
impl Write for BoundedSink {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        assert!(!self.refused, "renderer continued after output refusal");
        if self
            .text
            .len()
            .checked_add(value.len())
            .is_none_or(|length| length > self.maximum)
        {
            self.refused = true;
            return Err(fmt::Error);
        }
        self.text.push_str(value);
        Ok(())
    }
}

#[test]
fn actual_projection_writer_propagates_capacity_refusal_without_retrying() -> Test {
    let report = project(&fixture()?)?;
    let mut complete = String::new();
    projection::write_projection(&mut complete, &report, true)?;
    for maximum in [
        0,
        1,
        80,
        complete.len() / 2,
        complete.len() - 1,
        complete.len(),
    ] {
        let mut out = BoundedSink {
            text: String::new(),
            maximum,
            refused: false,
        };
        let result = projection::write_projection(&mut out, &report, true);
        assert_eq!(result.is_ok(), maximum == complete.len());
        assert!(out.text.len() <= maximum);
        if result.is_ok() {
            assert_eq!(out.text, complete);
        }
    }
    Ok(())
}

#[test]
fn full_aggregate_frame_and_occurrence_limits_render_without_dropping_rows() -> Test {
    let mut documents = Vec::new();
    for document_index in 0..8 {
        let mut frames = String::new();
        for frame_index in 0..128 {
            let second = document_index * 128 + frame_index;
            write!(
                frames,
                "<t:Frame UtcTime=\"2026-11-09T01:{:02}:{:02}Z\" Source=\"module\"><t:Object ObjectId=\"1\"/><t:Object ObjectId=\"2\"/><t:Object ObjectId=\"3\"/><t:Object ObjectId=\"4\"/></t:Frame>",
                second / 60,
                second % 60
            )?;
        }
        documents.push(document(&frames)?);
    }
    let inputs: Vec<_> = documents
        .iter()
        .enumerate()
        .flat_map(|(document_index, document)| {
            document
                .analytics_frames
                .iter()
                .enumerate()
                .map(move |(frame_index, frame)| frame_input(frame, document_index, frame_index))
        })
        .collect();
    let limits = TrackLimits {
        max_work_units: contract::MAX_TRACK_WORK_UNITS,
        ..TrackLimits::default()
    };
    let report = project_tracklets(&inputs, limits, || true)?;
    let rendered = render(&report, true)?;
    let parsed = json_input::parse_reconstruction_atlas_report(&rendered)?;
    assert_eq!(rows(&parsed, "frames")?.len(), contract::MAX_TRACK_FRAMES);
    assert_eq!(
        rows(&parsed, "occurrences")?.len(),
        contract::MAX_TRACK_OBJECTS
    );
    assert_eq!(rows(&parsed, "tracklets")?.len(), 4);
    for track in rows(&parsed, "tracklets")? {
        assert_eq!(
            rows(track, "occurrence_indices")?.len(),
            contract::MAX_TRACK_FRAMES
        );
    }
    Ok(())
}
