#![forbid(unsafe_code)]
//! Bounded vendor scene descriptions and frozen v1 event-parser compatibility.

#[path = "../src/onvif/wire.rs"]
mod wire;

use wire::{
    AnalyticsClassFormat, EventDocument, MAX_ANALYTICS_CLASSES, MAX_ANALYTICS_FRAMES,
    MAX_ANALYTICS_NUMBER_BYTES, MAX_ANALYTICS_OBJECTS, MAX_ANALYTICS_OBJECTS_PER_FRAME, WireError,
    parse_event_document, parse_metadata_document,
};

type Test = Result<(), Box<dyn std::error::Error>>;
const NS: &str = r#"xmlns:t="http://www.onvif.org/ver10/schema" xmlns:v="urn:vendor""#;
const TIME: &str = "2026-10-27T12:34:56.123456789Z";

fn document(sections: &str) -> Vec<u8> {
    format!("<t:MetadataStream {NS}>{sections}</t:MetadataStream>").into_bytes()
}

fn analytics(frames: &str) -> Vec<u8> {
    document(&format!("<t:VideoAnalytics>{frames}</t:VideoAnalytics>"))
}

fn frame(content: &str) -> String {
    format!(r#"<t:Frame UtcTime="{TIME}">{content}</t:Frame>"#)
}

fn object(id: &str, appearance: &str) -> String {
    format!(r#"<t:Object ObjectId="{id}"><t:Appearance>{appearance}</t:Appearance></t:Object>"#)
}

fn shape(left: &str) -> String {
    format!(
        r#"<t:Shape><t:BoundingBox left="{left}" top="80.0" right="100.0" bottom="30.0"/><t:CenterOfGravity x="60.0" y="50.0"/></t:Shape>"#
    )
}

fn project(content: &str) -> Result<EventDocument, WireError> {
    parse_metadata_document(&analytics(&frame(content)))
}

fn replace(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    String::from_utf8_lossy(bytes)
        .replace(from, to)
        .into_bytes()
}

#[test]
fn projects_source_bound_shape_transforms_and_both_class_syntaxes() -> Test {
    let content = format!(
        r#"<t:Transformation><t:Translate x="-1" y="-1.0"/><t:Scale x="0.003125" y="4.16667e-3"/></t:Transformation>{}"#,
        object(
            "+0012",
            &format!(
                r#"<t:Transformation><t:Scale x="1" y="-1"/></t:Transformation>{}<t:Class><t:ClassCandidate><t:Type>Human</t:Type><t:Likelihood>0.8</t:Likelihood></t:ClassCandidate><t:Type Likelihood="0.75">Person</t:Type><t:Type>Unclassified</t:Type></t:Class>"#,
                shape("20.0")
            )
        )
    );
    let source = replace(
        &analytics(&frame(&content)),
        "<t:Frame UtcTime=",
        "<t:Frame Source=\"motion&amp;person\" UtcTime=",
    );
    let result = parse_metadata_document(&source)?;
    assert_eq!(result.analytics_frames.len(), 1);
    assert!(result.notifications.is_empty());
    assert!(!result.has_unsupported_content());
    let value = &result.analytics_frames[0];
    assert_eq!(value.utc_time, TIME);
    assert_eq!(value.source.as_deref(), Some("motion&person"));
    let transform = value
        .transformation
        .as_ref()
        .ok_or("frame transformation")?;
    assert_eq!(
        transform.translate.as_ref().ok_or("translate")?.x.as_str(),
        "-1"
    );
    assert_eq!(
        transform.scale.as_ref().ok_or("scale")?.y.as_str(),
        "4.16667e-3"
    );
    assert_eq!(value.objects[0].object_id, "+0012");
    let appearance = value.objects[0].appearance.as_ref().ok_or("appearance")?;
    let local = appearance
        .transformation
        .as_ref()
        .ok_or("object transformation")?;
    assert!(local.translate.is_none());
    assert_eq!(local.scale.as_ref().ok_or("object scale")?.y.as_f64(), -1.0);
    let bounds = appearance.shape.as_ref().ok_or("shape")?;
    assert_eq!(bounds.bounding_box.left.as_f64(), 20.0);
    assert_eq!(bounds.center_of_gravity.y.as_f64(), 50.0);
    let classes = &appearance.class.as_ref().ok_or("class")?.candidates;
    assert_eq!(classes.len(), 3);
    assert_eq!(classes[0].format, AnalyticsClassFormat::LegacyCandidate);
    assert_eq!(classes[1].format, AnalyticsClassFormat::Type);
    assert_eq!(classes[0].label, "Human");
    assert_eq!(
        classes[0].likelihood.as_ref().ok_or("likelihood")?.as_str(),
        "0.8"
    );
    assert!(classes[2].likelihood.is_none());
    // Hierarchical classes may total more than one; they are not renormalized.
    assert_eq!(
        classes[1].likelihood.as_ref().ok_or("likelihood")?.as_str(),
        "0.75"
    );
    Ok(())
}

#[test]
fn vendor_labels_preserve_string_whitespace_and_enforce_byte_bounds() -> Test {
    let value = project(&object(
        "1",
        "<t:Class><t:Type>  Human  </t:Type><t:ClassCandidate><t:Type>  Human  </t:Type><t:Likelihood> 0.8 </t:Likelihood></t:ClassCandidate></t:Class>",
    ))?;
    let classes = &value.analytics_frames[0].objects[0]
        .appearance
        .as_ref()
        .ok_or("appearance")?
        .class
        .as_ref()
        .ok_or("class")?
        .candidates;
    assert_eq!(classes[0].label, "  Human  ");
    assert_eq!(classes[1].label, "  Human  ");
    assert_eq!(
        classes[1].likelihood.as_ref().ok_or("likelihood")?.as_str(),
        "0.8"
    );
    for valid in ["x".repeat(256), "é".repeat(128)] {
        project(&object(
            "1",
            &format!("<t:Class><t:Type>{valid}</t:Type></t:Class>"),
        ))?;
        parse_metadata_document(&analytics(&format!(
            r#"<t:Frame UtcTime="{TIME}" Source="{valid}"/>"#
        )))?;
    }
    for invalid in [
        String::new(),
        "x".repeat(257),
        "é".repeat(129),
        "Human&#x9;".to_owned(),
    ] {
        assert!(
            project(&object(
                "1",
                &format!("<t:Class><t:Type>{invalid}</t:Type></t:Class>")
            ))
            .is_err()
        );
    }
    for invalid in ["x".repeat(257), "é".repeat(129), "camera&#xA;".to_owned()] {
        assert!(
            parse_metadata_document(&analytics(&format!(
                r#"<t:Frame UtcTime="{TIME}" Source="{invalid}"/>"#
            )))
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn namespace_prefix_changes_preserve_projection_but_spoofing_does_not_create_claims() -> Test {
    let bytes = analytics(&frame(&object("1", &shape("20"))));
    let alternate = replace(
        &replace(&bytes, "t:", "schema:"),
        "xmlns:t=",
        "xmlns:schema=",
    );
    assert_eq!(
        parse_metadata_document(&bytes)?,
        parse_metadata_document(&alternate)?
    );
    for (from, to) in [
        ("t:VideoAnalytics", "v:VideoAnalytics"),
        ("t:Frame", "v:Frame"),
    ] {
        let spoofed = parse_metadata_document(&replace(&bytes, from, to))?;
        assert!(spoofed.analytics_frames.is_empty());
        assert!(spoofed.has_unsupported_content());
    }
    let spoofed = parse_metadata_document(&replace(&bytes, "t:Object", "v:Object"))?;
    assert!(spoofed.analytics_frames[0].objects.is_empty());
    assert!(spoofed.has_unsupported_content());
    assert!(parse_metadata_document(&replace(&bytes, " left=", " v:left=")).is_err());
    assert!(parse_metadata_document(&replace(&bytes, "t:BoundingBox", "v:BoundingBox")).is_err());
    Ok(())
}

#[test]
fn v1_analytics_opacity_is_frozen_even_when_v2_refuses_its_semantics() -> Test {
    for content in [
        r#"<t:Frame UtcTime="invalid"><t:Object ObjectId="not-an-integer"/></t:Frame>"#,
        r#"<t:Frame UtcTime="2026-10-27T00:00:00Z"><t:Object ObjectId="1"><t:Appearance><t:Shape><t:BoundingBox left="NaN"/></t:Shape></t:Appearance></t:Object></t:Frame>"#,
        r#"<t:Frame>not whitespace</t:Frame>"#,
    ] {
        let bytes = analytics(content);
        let old = parse_event_document(&bytes)?;
        assert!(old.analytics_frames.is_empty());
        assert_eq!(old.unsupported_sections, 1);
        assert!(old.has_unsupported_content());
        assert!(parse_metadata_document(&bytes).is_err());
    }
    let bytes = analytics(&frame(""));
    assert_eq!(parse_event_document(&bytes)?.unsupported_sections, 1);
    assert_eq!(parse_metadata_document(&bytes)?.unsupported_sections, 0);
    Ok(())
}

#[test]
fn mixed_event_and_analytics_documents_keep_original_claims_and_occurrences() -> Test {
    let event = r#"<t:Event xmlns:n="http://docs.oasis-open.org/wsn/b-2" xmlns:topic="http://www.onvif.org/ver10/topics"><n:NotificationMessage><n:Topic Dialect="http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet">topic:RuleEngine/Motion</n:Topic><n:Message><t:Message UtcTime="2026-10-27T00:00:00Z"><t:Data><t:SimpleItem Name="State" Value="false"/></t:Data></t:Message></n:Message></n:NotificationMessage></t:Event>"#;
    let one = frame(&object("1", &shape("0")));
    let two = one.replace(TIME, "2026-10-26T23:00:00Z");
    let bytes = document(&format!(
        "<t:VideoAnalytics>{one}</t:VideoAnalytics>{event}<t:VideoAnalytics>{two}{one}</t:VideoAnalytics>"
    ));
    let old = parse_event_document(&bytes)?;
    let new = parse_metadata_document(&bytes)?;
    assert_eq!(old.notifications, new.notifications);
    assert_eq!(old.unsupported_sections, 2);
    assert_eq!(new.unsupported_sections, 0);
    assert_eq!(new.analytics_frames.len(), 3);
    assert_eq!(new.analytics_frames[0], new.analytics_frames[2]);
    assert_eq!(new.analytics_frames[1].utc_time, "2026-10-26T23:00:00Z");
    assert_eq!(new.analytics_frames[1].objects[0].object_id, "1");
    Ok(())
}

#[test]
fn pull_messages_v2_keeps_v1_event_projection() -> Test {
    let bytes = br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:e="http://www.onvif.org/ver10/events/wsdl"><s:Body><e:PullMessagesResponse><e:CurrentTime>2026-10-27T00:00:00Z</e:CurrentTime><e:TerminationTime>2026-10-27T00:01:00Z</e:TerminationTime></e:PullMessagesResponse></s:Body></s:Envelope>"#;
    assert_eq!(
        parse_event_document(bytes)?,
        parse_metadata_document(bytes)?
    );
    Ok(())
}

#[test]
fn missing_empty_and_zero_valued_fields_remain_distinct() -> Test {
    let values = project(
        r#"<t:Object ObjectId="0"/><t:Object ObjectId="1"><t:Appearance/></t:Object><t:Object ObjectId="2"><t:Appearance><t:Transformation/><t:Class/></t:Appearance></t:Object>"#,
    )?;
    let value = &values.analytics_frames[0];
    assert!(value.source.is_none());
    assert!(value.transformation.is_none());
    assert!(value.objects[0].appearance.is_none());
    let empty = value.objects[1]
        .appearance
        .as_ref()
        .ok_or("empty appearance")?;
    assert!(empty.transformation.is_none());
    assert!(empty.shape.is_none());
    assert!(empty.class.is_none());
    let present = value.objects[2]
        .appearance
        .as_ref()
        .ok_or("present appearance")?;
    assert!(
        present
            .transformation
            .as_ref()
            .ok_or("present transformation")?
            .scale
            .is_none()
    );
    assert!(
        present
            .class
            .as_ref()
            .ok_or("present class")?
            .candidates
            .is_empty()
    );
    let source_empty = parse_metadata_document(&replace(
        &analytics(&frame("")),
        "<t:Frame UtcTime=",
        "<t:Frame Source=\"\" UtcTime=",
    ))?;
    assert_eq!(source_empty.analytics_frames[0].source.as_deref(), Some(""));
    let empty_frame = project("")?;
    assert!(empty_frame.analytics_frames[0].objects.is_empty());
    assert!(!empty_frame.has_unsupported_content());
    Ok(())
}

#[test]
fn duplicate_object_ids_are_refused_only_within_the_same_frame() -> Test {
    for ids in [("1", "1"), ("001", "+1"), ("-0", "+000"), ("-0012", "-12")] {
        assert_eq!(
            project(&format!("{}{}", object(ids.0, ""), object(ids.1, ""))),
            Err(WireError::DuplicateField)
        );
    }
    let frames = format!("{}{}", frame(&object("1", "")), frame(&object("+001", "")));
    assert_eq!(
        parse_metadata_document(&analytics(&frames))?
            .analytics_frames
            .len(),
        2
    );
    let signed = project(&format!("{}{}", object("1", ""), object("-1", "")))?;
    assert_eq!(signed.analytics_frames[0].objects.len(), 2);
    Ok(())
}

#[test]
fn duplicate_structural_fields_cannot_hide_conflicting_geometry() -> Test {
    let valid = analytics(&frame(&object("1", &format!("{}<t:Class/>", shape("0")))));
    for (from, to) in [
        ("<t:Appearance>", "<t:Appearance/><t:Appearance>"),
        ("<t:Shape>", "<t:Shape/><t:Shape>"),
        ("<t:Class/>", "<t:Class/><t:Class/>"),
        (
            "<t:CenterOfGravity x=\"60.0\" y=\"50.0\"/>",
            "<t:CenterOfGravity x=\"60.0\" y=\"50.0\"/><t:CenterOfGravity x=\"1\" y=\"1\"/>",
        ),
        (
            "<t:BoundingBox ",
            "<t:BoundingBox left=\"0\" right=\"1\" top=\"1\" bottom=\"0\"/><t:BoundingBox ",
        ),
    ] {
        assert_eq!(
            parse_metadata_document(&replace(&valid, from, to)),
            Err(WireError::DuplicateField)
        );
    }
    for transform in [
        "<t:Transformation/><t:Transformation/>",
        r#"<t:Transformation><t:Translate x="1" y="2"/><t:Translate x="1" y="2"/></t:Transformation>"#,
        r#"<t:Transformation><t:Scale x="1" y="2"/><t:Scale x="1" y="2"/></t:Transformation>"#,
    ] {
        assert_eq!(project(transform), Err(WireError::DuplicateField));
        assert_eq!(
            project(&object("1", transform)),
            Err(WireError::DuplicateField)
        );
    }
    for duplicate in [
        "<t:Type>Human</t:Type><t:Type>Animal</t:Type><t:Likelihood>0.5</t:Likelihood>",
        "<t:Type>Human</t:Type><t:Likelihood>0.5</t:Likelihood><t:Likelihood>0.8</t:Likelihood>",
    ] {
        assert_eq!(
            project(&object(
                "1",
                &format!("<t:Class><t:ClassCandidate>{duplicate}</t:ClassCandidate></t:Class>")
            )),
            Err(WireError::DuplicateField)
        );
    }
    Ok(())
}

#[test]
fn object_id_and_shape_mandatory_fields_fail_closed() -> Test {
    for id in ["", "+", "-", "1.0", "1e2", "one", " 1", "1 ", "١"] {
        assert!(project(&object(id, "")).is_err());
    }
    assert!(project(&object(&"9".repeat(65), "")).is_err());
    assert!(project("<t:Object/>").is_err());
    assert!(project(r#"<t:Object UUID="private-identity"/>"#).is_err());
    assert!(project(&object("1", "<t:Shape/>")).is_err());
    let valid = analytics(&frame(&object("1", &shape("0"))));
    for (from, to) in [
        (r#"<t:CenterOfGravity x="60.0" y="50.0"/>"#, ""),
        (r#" top="80.0""#, ""),
        (r#" x="60.0""#, ""),
    ] {
        assert!(parse_metadata_document(&replace(&valid, from, to)).is_err());
    }
    Ok(())
}

#[test]
fn numeric_lexical_grammar_and_finite_bounds_are_enforced_before_projection() -> Test {
    for value in [
        "NaN",
        "nan",
        "INF",
        "-INF",
        "Infinity",
        "1e309",
        "-1e309",
        "1e-999",
        "1_000",
        "0x1",
        "1,2",
        "",
        ".",
        "+",
        "-",
        "1e",
        "1e+",
        "1.2.3",
        "1 e2",
        " 1",
        "1 ",
        "1\t",
        "++1",
        "١",
        "1000000001",
        "-1000000001",
        "1000000000.000000000000000001",
        "1e4097",
    ] {
        assert!(
            project(&object("1", &shape(value))).is_err(),
            "accepted invalid numeric input {value:?}"
        );
    }
    assert!(
        project(&object(
            "1",
            &shape(&"0".repeat(MAX_ANALYTICS_NUMBER_BYTES + 1))
        ))
        .is_err()
    );
    for value in [
        "+1",
        "1.",
        ".5",
        "1.e+2",
        "-0",
        "0.0e20",
        "1e-300",
        "1e9",
        "-1000000000",
    ] {
        let result = project(&object("1", &shape(value)))?;
        let number = &result.analytics_frames[0].objects[0]
            .appearance
            .as_ref()
            .ok_or("appearance")?
            .shape
            .as_ref()
            .ok_or("shape")?
            .bounding_box
            .left;
        assert_eq!(number.as_str(), value);
        assert!(number.as_f64().is_finite());
    }
    Ok(())
}

#[test]
fn likelihood_range_is_exact_even_when_binary_float_would_round_into_range() -> Test {
    for value in [
        "-0.1",
        "1.01",
        "NaN",
        "INF",
        "1.000000000000000000000001",
        "-1e-999",
    ] {
        for classes in [
            format!(r#"<t:Type Likelihood="{value}">Human</t:Type>"#),
            format!(
                "<t:ClassCandidate><t:Type>Human</t:Type><t:Likelihood>{value}</t:Likelihood></t:ClassCandidate>"
            ),
        ] {
            assert!(project(&object("1", &format!("<t:Class>{classes}</t:Class>"))).is_err());
        }
    }
    let result = project(&object(
        "1",
        r#"<t:Class><t:Type Likelihood="-0">Human</t:Type><t:Type Likelihood="1.000">Human</t:Type><t:Type>Human</t:Type></t:Class>"#,
    ))?;
    let classes = &result.analytics_frames[0].objects[0]
        .appearance
        .as_ref()
        .ok_or("appearance")?
        .class
        .as_ref()
        .ok_or("class")?
        .candidates;
    assert_eq!(
        classes.len(),
        3,
        "repeated classes preserve vendor alternatives"
    );
    assert!(
        classes[0]
            .likelihood
            .as_ref()
            .ok_or("likelihood")?
            .as_f64()
            .is_sign_negative()
    );
    assert_eq!(
        classes[1].likelihood.as_ref().ok_or("likelihood")?.as_str(),
        "1.000"
    );
    assert!(classes[2].likelihood.is_none());
    assert!(
        project(&object(
            "1",
            "<t:Class><t:ClassCandidate><t:Type>Human</t:Type></t:ClassCandidate></t:Class>"
        ))
        .is_err()
    );
    Ok(())
}

#[test]
fn source_coordinates_and_numeric_spelling_are_never_silently_rewritten() -> Test {
    let normal = project(&object("1", &shape("0")))?;
    let negative_zero = project(&object("1", &shape("-0")))?;
    assert_ne!(normal, negative_zero);
    let flipped = parse_metadata_document(&replace(
        &analytics(&frame(&object("1", &shape("0")))),
        "top=\"80.0\" right=\"100.0\" bottom=\"30.0\"",
        "top=\"30.0\" right=\"100.0\" bottom=\"80.0\"",
    ))?;
    let shape = flipped.analytics_frames[0].objects[0]
        .appearance
        .as_ref()
        .ok_or("appearance")?
        .shape
        .as_ref()
        .ok_or("shape")?;
    assert_eq!(shape.bounding_box.top.as_str(), "30.0");
    assert_eq!(shape.bounding_box.bottom.as_str(), "80.0");
    Ok(())
}

#[test]
fn frame_time_subset_is_strict_and_never_replaced_by_receive_time() -> Test {
    for time in [
        "",
        "2026-02-29T00:00:00Z",
        "2026-10-27T00:00:00",
        "2026-10-27T00:00:00+02:00",
        "2026-10-27T00:00:00.1234567890Z",
        "2026-10-27T24:00:00Z",
    ] {
        assert!(parse_metadata_document(&replace(&analytics(&frame("")), TIME, time)).is_err());
    }
    assert!(
        parse_metadata_document(&document("<t:VideoAnalytics><t:Frame/></t:VideoAnalytics>"))
            .is_err()
    );
    Ok(())
}

#[test]
fn frame_and_object_count_bounds_apply_across_multiple_sections() -> Test {
    let frames = frame("").repeat(MAX_ANALYTICS_FRAMES);
    assert_eq!(
        parse_metadata_document(&analytics(&frames))?
            .analytics_frames
            .len(),
        MAX_ANALYTICS_FRAMES
    );
    let excess = document(&format!(
        "<t:VideoAnalytics>{frames}</t:VideoAnalytics><t:VideoAnalytics>{}</t:VideoAnalytics>",
        frame("")
    ));
    assert_eq!(
        parse_metadata_document(&excess),
        Err(WireError::AnalyticsLimitExceeded)
    );
    let objects = (0..MAX_ANALYTICS_OBJECTS_PER_FRAME)
        .map(|i| format!(r#"<t:Object ObjectId="{i}"/>"#))
        .collect::<String>();
    assert_eq!(
        project(&objects)?.analytics_frames[0].objects.len(),
        MAX_ANALYTICS_OBJECTS_PER_FRAME
    );
    assert_eq!(
        project(&format!("{objects}<t:Object ObjectId=\"999\"/>")),
        Err(WireError::AnalyticsLimitExceeded)
    );
    let at_limit = frame(&objects).repeat(MAX_ANALYTICS_OBJECTS / MAX_ANALYTICS_OBJECTS_PER_FRAME);
    assert!(parse_metadata_document(&analytics(&at_limit)).is_ok());
    assert_eq!(
        parse_metadata_document(&analytics(&format!(
            "{at_limit}{}",
            frame("<t:Object ObjectId=\"1\"/>")
        ))),
        Err(WireError::AnalyticsLimitExceeded)
    );
    Ok(())
}

#[test]
fn class_candidate_limits_include_mixed_formats() -> Test {
    let candidates = r#"<t:Type Likelihood="0.5">Human</t:Type>"#.repeat(MAX_ANALYTICS_CLASSES - 1);
    let legacy = "<t:ClassCandidate><t:Type>Human</t:Type><t:Likelihood>0.5</t:Likelihood></t:ClassCandidate>";
    assert!(
        project(&object(
            "1",
            &format!("<t:Class>{candidates}{legacy}</t:Class>")
        ))
        .is_ok()
    );
    assert_eq!(
        project(&object(
            "1",
            &format!("<t:Class>{candidates}{legacy}<t:Type>Human</t:Type></t:Class>")
        )),
        Err(WireError::AnalyticsLimitExceeded)
    );
    Ok(())
}

#[test]
fn nested_unsupported_fields_propagate_to_the_document_completeness_predicate() -> Test {
    let complete = analytics(&frame(&format!(
        "<t:Transformation><t:Translate x=\"0\" y=\"0\"/></t:Transformation>{}",
        object(
            "1",
            &format!(
                "{}<t:Class><t:Type Likelihood=\"0.5\">Human</t:Type><t:ClassCandidate><t:Type>Other</t:Type><t:Likelihood>0.1</t:Likelihood></t:ClassCandidate></t:Class>",
                shape("0")
            )
        )
    )));
    assert!(!parse_metadata_document(&complete)?.has_unsupported_content());
    for (from, to) in [
        ("<t:MetadataStream ", "<t:MetadataStream v:extra=\"x\" "),
        ("<t:VideoAnalytics>", "<t:VideoAnalytics v:extra=\"x\">"),
        ("<t:Frame ", "<t:Frame v:extra=\"x\" "),
        ("<t:Object ", "<t:Object UUID=\"private\" "),
        ("<t:Appearance>", "<t:Appearance v:extra=\"x\">"),
        ("<t:Shape>", "<t:Shape v:extra=\"x\">"),
        ("<t:BoundingBox ", "<t:BoundingBox v:extra=\"x\" "),
        ("<t:CenterOfGravity ", "<t:CenterOfGravity v:extra=\"x\" "),
        ("<t:Transformation>", "<t:Transformation v:extra=\"x\">"),
        ("<t:Translate ", "<t:Translate v:extra=\"x\" "),
        ("<t:Class>", "<t:Class v:extra=\"x\">"),
        ("<t:Type Likelihood=", "<t:Type v:extra=\"x\" Likelihood="),
        ("<t:ClassCandidate>", "<t:ClassCandidate v:extra=\"x\">"),
        ("<t:Type>Other", "<t:Type v:extra=\"x\">Other"),
        ("<t:Likelihood>", "<t:Likelihood v:extra=\"x\">"),
        ("</t:MetadataStream>", "<v:Unknown/></t:MetadataStream>"),
        ("</t:VideoAnalytics>", "<v:Unknown/></t:VideoAnalytics>"),
        ("</t:Frame>", "<t:ObjectTree/></t:Frame>"),
        (
            "</t:Object>",
            "<t:Behaviour><t:Idle/></t:Behaviour></t:Object>",
        ),
        ("</t:Shape>", "<t:Polygon/></t:Shape>"),
        ("</t:Transformation>", "<t:Extension/></t:Transformation>"),
        ("</t:Class>", "<t:Extension/></t:Class>"),
        ("</t:ClassCandidate>", "<v:Unknown/></t:ClassCandidate>"),
    ] {
        let result = parse_metadata_document(&replace(&complete, from, to))?;
        assert!(
            result.has_unsupported_content(),
            "unaccounted opaque extension at {from}"
        );
    }
    Ok(())
}

#[test]
fn biometric_identity_images_and_external_uris_remain_opaque() -> Test {
    let opaque = r#"<t:LicensePlateInfo><t:PlateNumber>PRIVATE-PLATE</t:PlateNumber></t:LicensePlateInfo><t:HumanFace><v:Identity>PRIVATE-PERSON</v:Identity></t:HumanFace><t:HumanBody><v:Embedding>PRIVATE-EMBEDDING</v:Embedding></t:HumanBody><t:ImageRef>https://private.invalid/image</t:ImageRef><t:Image>PRIVATE-IMAGE</t:Image>"#;
    let result = project(&object("1", opaque))?;
    let appearance = result.analytics_frames[0].objects[0]
        .appearance
        .as_ref()
        .ok_or("appearance")?;
    assert_eq!(appearance.unsupported_extensions, 5);
    assert!(appearance.class.is_none());
    assert!(appearance.shape.is_none());
    assert!(result.has_unsupported_content());
    assert!(!format!("{result:?} {appearance:?}").contains("PRIVATE"));
    Ok(())
}

#[test]
fn debug_output_withholds_vendor_strings_identifiers_and_geometry() -> Test {
    let result = project(&object(
        "198765432",
        &format!(
            "{}<t:Class><t:Type Likelihood=\"0.812345\">PRIVATE-CLASS</t:Type></t:Class><t:Transformation><t:Scale x=\"7.65432\" y=\"1\"/></t:Transformation>",
            shape("12.34567")
        ),
    ))?;
    let value = &result.analytics_frames[0];
    let object = &value.objects[0];
    let appearance = object.appearance.as_ref().ok_or("appearance")?;
    let shape = appearance.shape.as_ref().ok_or("shape")?;
    let classes = appearance.class.as_ref().ok_or("class")?;
    let candidate = &classes.candidates[0];
    let text = format!(
        "{result:?} {value:?} {object:?} {appearance:?} {shape:?} {:?} {:?} {:?} {:?} {classes:?} {candidate:?} {:?}",
        shape.bounding_box,
        shape.bounding_box.left,
        shape.center_of_gravity,
        appearance.transformation,
        candidate.likelihood
    );
    for private in [
        "198765432",
        "PRIVATE-CLASS",
        "12.34567",
        "0.812345",
        "7.65432",
        TIME,
    ] {
        assert!(!text.contains(private));
    }
    Ok(())
}

#[test]
fn hostile_xml_mixed_text_and_nested_numeric_elements_refuse() -> Test {
    let bytes = analytics(&frame(&object(
        "1",
        &format!(
            "{}<t:Class><t:ClassCandidate><t:Type>Human</t:Type><t:Likelihood>0.5</t:Likelihood></t:ClassCandidate></t:Class>",
            shape("0")
        ),
    )));
    for (from, to) in [
        ("<t:VideoAnalytics>", "<t:VideoAnalytics>unprojected text"),
        ("<t:Appearance>", "<t:Appearance>unprojected text"),
        ("<t:Shape>", "<t:Shape>unprojected text"),
        ("<t:ClassCandidate>", "<t:ClassCandidate>unprojected text"),
        (
            r#"<t:CenterOfGravity x="60.0" y="50.0"/>"#,
            r#"<t:CenterOfGravity x="60.0" y="50.0"><v:Nested/></t:CenterOfGravity>"#,
        ),
    ] {
        assert!(parse_metadata_document(&replace(&bytes, from, to)).is_err());
    }
    for prefix in ["<!DOCTYPE x>", "<!ENTITY x 'secret'>", "<?vendor execute?>"] {
        let attack = [prefix.as_bytes(), bytes.as_slice()].concat();
        assert!(parse_metadata_document(&attack).is_err());
    }
    assert!(
        parse_metadata_document(&replace(&bytes, "t:MetadataStream", "v:MetadataStream")).is_err()
    );
    Ok(())
}
