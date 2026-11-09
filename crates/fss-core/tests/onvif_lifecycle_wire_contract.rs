#![forbid(unsafe_code)]
//! Execute the actual production lifecycle/XML parser without a replacement parser,
//! runtime, source owner, or protocol facade.

#[path = "../../fss-reference/src/onvif/wire.rs"]
pub mod wire;

use wire::{
    LifecycleDocument, LifecycleOperationKind as Kind, LifecycleParseLimits as Limits,
    LifecycleWireError as Error, WireError, analytics_object_key, lifecycle_parse_work_bound,
    parse_event_document, parse_metadata_document, parse_metadata_lifecycle_document,
};

type Test = Result<(), Box<dyn std::error::Error>>;

fn source(content: &str) -> String {
    format!(
        r#"<t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema" xmlns:v="urn:vendor">{content}</t:MetadataStream>"#
    )
}
fn frame(content: &str) -> String {
    format!(
        r#"<t:Frame UtcTime="2026-11-09T12:01:02.123456789Z" Source="motion private">{content}</t:Frame>"#
    )
}
fn frames(content: &str) -> String {
    source(&format!("<t:VideoAnalytics>{content}</t:VideoAnalytics>"))
}
fn tree(content: &str) -> String {
    frames(&frame(&format!("<t:ObjectTree>{content}</t:ObjectTree>")))
}
fn parse(xml: &str) -> Result<LifecycleDocument, Error> {
    parse_metadata_lifecycle_document(xml.as_bytes(), Limits::default(), || true)
}
fn rename(from: &str, to: &str) -> String {
    format!(r#"<t:Rename><t:from ObjectId="{from}"/><t:to ObjectId="{to}"/></t:Rename>"#)
}

#[test]
fn normative_lowercase_operations_preserve_lexemes_and_source_order() -> Test {
    let xml = tree(&format!(
        r#"{}<t:Split><t:from ObjectId="2"/><t:to ObjectId="2"/><t:to ObjectId="003"/></t:Split><t:Merge><t:from ObjectId="2"/><t:from ObjectId="003"/><t:to ObjectId="2"/></t:Merge><t:Delete ObjectId="-0007"/>"#,
        rename("+001", "2"),
    ));
    let result = parse(&xml)?;
    assert_eq!(result.frames.len(), 1);
    assert_eq!(result.operation_count, 4);
    assert_eq!(result.reference_count, 9);
    assert!(!result.has_unsupported_content());
    let frame = &result.frames[0];
    assert_eq!(frame.object_tree_child_index, Some(0));
    assert_eq!(frame.utc_time, "2026-11-09T12:01:02.123456789Z");
    assert_eq!(frame.source.as_deref(), Some("motion private"));
    assert_eq!(
        frame
            .operations
            .iter()
            .map(|op| op.kind)
            .collect::<Vec<_>>(),
        [Kind::Rename, Kind::Split, Kind::Merge, Kind::Delete]
    );
    for (index, operation) in frame.operations.iter().enumerate() {
        assert_eq!(operation.operation_index, index);
        assert_eq!(operation.tree_child_index, index);
    }
    assert_eq!(
        frame.operations[0].from[0].object_id.as_deref(),
        Some("+001")
    );
    assert_eq!(frame.operations[1].to[1].object_id.as_deref(), Some("003"));
    assert_eq!(
        frame.operations[3].from[0].object_id.as_deref(),
        Some("-0007")
    );
    assert!(frame.operations[3].to.is_empty());
    assert_eq!(analytics_object_key("+001")?, analytics_object_key("1")?);
    assert_eq!(Kind::Delete.as_str(), "delete");
    assert_eq!(parse(&xml)?, result);
    Ok(())
}

#[test]
fn endpoint_aliases_and_repeated_claims_are_not_coalesced() -> Test {
    let xml = tree(
        r#"<t:Merge><t:from ObjectId="+001"/><t:from ObjectId="1"/><t:to ObjectId="001"/></t:Merge><t:Delete ObjectId="1"/><t:Delete ObjectId="1"/>"#,
    );
    let result = parse(&xml)?;
    assert_eq!(result.operation_count, 3);
    assert_eq!(result.reference_count, 5);
    assert_eq!(result.frames[0].operations[0].from.len(), 2);
    assert_eq!(result.frames[0].operations[1].tree_child_index, 1);
    assert_eq!(result.frames[0].operations[2].tree_child_index, 2);
    Ok(())
}

#[test]
fn uppercase_example_endpoints_and_wrong_namespaces_do_not_masquerade() {
    for operation in [
        r#"<t:Rename><t:From ObjectId="1"/><t:To ObjectId="2"/></t:Rename>"#,
        r#"<t:Rename><v:from ObjectId="1"/><t:to ObjectId="2"/></t:Rename>"#,
        r#"<t:Rename><t:from ObjectId="1"/><to ObjectId="2"/></t:Rename>"#,
    ] {
        assert_eq!(
            parse(&tree(operation)),
            Err(Error::Wire(WireError::InvalidField))
        );
    }
}

#[test]
fn normative_endpoint_cardinalities_and_order_are_enforced() {
    for operation in [
        r#"<t:Rename><t:from ObjectId="1"/></t:Rename>"#,
        r#"<t:Rename><t:from ObjectId="1"/><t:from ObjectId="2"/><t:to ObjectId="3"/></t:Rename>"#,
        r#"<t:Rename><t:from ObjectId="1"/><t:to ObjectId="2"/><t:to ObjectId="3"/></t:Rename>"#,
        r#"<t:Merge><t:from ObjectId="1"/><t:to ObjectId="2"/></t:Merge>"#,
        r#"<t:Merge><t:from ObjectId="1"/><t:from ObjectId="2"/><t:to ObjectId="3"/><t:to ObjectId="4"/></t:Merge>"#,
        r#"<t:Split><t:from ObjectId="1"/><t:to ObjectId="2"/></t:Split>"#,
        r#"<t:Split><t:from ObjectId="1"/><t:from ObjectId="2"/><t:to ObjectId="3"/><t:to ObjectId="4"/></t:Split>"#,
        r#"<t:Rename><t:to ObjectId="2"/><t:from ObjectId="1"/></t:Rename>"#,
    ] {
        assert_eq!(
            parse(&tree(operation)),
            Err(Error::Wire(WireError::InvalidField))
        );
    }
}

#[test]
fn valid_schema_missing_integer_and_uuid_references_remain_opaque() -> Test {
    let result = parse(&tree(
        r#"<t:Rename><t:from UUID="private-uuid"/><t:to/></t:Rename><t:Delete ObjectId="7" UUID="other-private-uuid"/>"#,
    ))?;
    let operations = &result.frames[0].operations;
    assert_eq!(operations[0].from[0].object_id, None);
    assert_eq!(operations[0].from[0].uuid.as_deref(), Some("private-uuid"));
    assert_eq!(operations[0].to[0].object_id, None);
    assert_eq!(operations[0].to[0].uuid, None);
    assert!(!operations[0].from[0].is_supported());
    assert!(!operations[0].to[0].is_supported());
    assert!(!operations[1].from[0].is_supported());
    assert!(result.has_unsupported_content());
    Ok(())
}

#[test]
fn unsupported_reference_attributes_and_descendants_are_visible() -> Test {
    let result = parse(&tree(
        r#"<t:Rename v:mode="private"><t:from ObjectId="1" v:uncertain="yes"/><t:to ObjectId="2"><v:Detail/></t:to><v:Relationship/></t:Rename><t:Delete ObjectId="3"><v:Detail/></t:Delete>"#,
    ))?;
    let operation = &result.frames[0].operations[0];
    assert_eq!(operation.unsupported_extensions, 2);
    assert_eq!(operation.from[0].unsupported_extensions, 1);
    assert_eq!(operation.to[0].unsupported_extensions, 1);
    assert!(operation.has_unsupported_content());
    assert_eq!(
        result.frames[0].operations[1].from[0].unsupported_extensions,
        1
    );
    assert!(result.has_unsupported_content());
    Ok(())
}

#[test]
fn all_original_locators_survive_unknown_and_nonanalytics_siblings() -> Test {
    let xml = source(&format!(
        r#"<t:Event/><t:VideoAnalytics><v:Frame/><t:Frame UtcTime="2026-11-09T12:00:00Z"><t:Transformation/><t:Object ObjectId="7"/><v:Other/><t:ObjectTree><v:Lifecycle/>{}<v:Lifecycle/><t:Delete ObjectId="8"/></t:ObjectTree><t:Object ObjectId="8"/></t:Frame></t:VideoAnalytics><v:Section/><t:VideoAnalytics>{}</t:VideoAnalytics>"#,
        rename("7", "8"),
        frame(""),
    ));
    let result = parse(&xml)?;
    assert_eq!(result.unsupported_sections, 3);
    assert_eq!(result.frames.len(), 2);
    assert_eq!(
        (
            result.frames[0].frame_index,
            result.frames[0].section_index,
            result.frames[0].section_child_index
        ),
        (0, 1, 1)
    );
    assert_eq!(
        (
            result.frames[1].frame_index,
            result.frames[1].section_index,
            result.frames[1].section_child_index
        ),
        (1, 3, 0)
    );
    assert_eq!(result.frames[0].objects[0].object_index, 0);
    assert_eq!(result.frames[0].objects[0].frame_child_index, 1);
    assert_eq!(result.frames[0].objects[1].object_index, 1);
    assert_eq!(result.frames[0].objects[1].frame_child_index, 4);
    assert_eq!(result.frames[0].object_tree_child_index, Some(3));
    assert_eq!(result.frames[0].operations[0].tree_child_index, 1);
    assert_eq!(result.frames[0].operations[1].tree_child_index, 3);
    assert_eq!(result.frames[0].unsupported_extensions, 3);
    assert!(result.has_unsupported_content());
    Ok(())
}

#[test]
fn idle_removed_and_delete_are_distinct_original_claims() -> Test {
    let result = parse(&frames(&frame(
        r#"<t:Object ObjectId="1"><t:Behaviour><t:Idle/></t:Behaviour></t:Object><t:Object ObjectId="2"><t:Behaviour><t:Removed/></t:Behaviour></t:Object><t:Object ObjectId="3"><t:Behaviour><t:Removed/><t:Idle/></t:Behaviour></t:Object><t:ObjectTree><t:Delete ObjectId="4"/></t:ObjectTree>"#,
    )))?;
    let objects = &result.frames[0].objects;
    let idle = objects[0].behaviour.ok_or("missing idle")?;
    let removed = objects[1].behaviour.ok_or("missing removed")?;
    let both = objects[2].behaviour.ok_or("missing combined behaviour")?;
    assert!(idle.idle && !idle.removed);
    assert!(!removed.idle && removed.removed);
    assert!(both.idle && both.removed);
    assert_eq!(result.operation_count, 1);
    assert_eq!(result.frames[0].operations[0].kind, Kind::Delete);
    assert!(!result.has_unsupported_content());
    Ok(())
}

#[test]
fn missing_empty_and_opaque_behaviour_are_not_flattened() -> Test {
    let result = parse(&frames(&frame(
        r#"<t:Object ObjectId="1"/><t:Object ObjectId="2"><t:Behaviour/></t:Object><t:Object ObjectId="3"><t:Behaviour v:mode="opaque"><t:Idle v:flag="opaque"><v:Detail/></t:Idle><t:Speed>12</t:Speed></t:Behaviour></t:Object><t:ObjectTree/>"#,
    )))?;
    assert!(result.frames[0].objects[0].behaviour.is_none());
    let empty = result.frames[0].objects[1]
        .behaviour
        .ok_or("missing empty behaviour")?;
    assert!(!empty.idle && !empty.removed && empty.unsupported_extensions == 0);
    let opaque = result.frames[0].objects[2]
        .behaviour
        .ok_or("missing opaque behaviour")?;
    assert!(opaque.idle && !opaque.removed);
    assert_eq!(opaque.unsupported_extensions, 4);
    assert_eq!(result.frames[0].object_tree_child_index, Some(3));
    assert!(result.frames[0].operations.is_empty());
    assert!(result.has_unsupported_content());
    Ok(())
}

#[test]
fn duplicate_known_containers_and_flags_refuse_the_whole_parse() {
    for content in [
        r#"<t:ObjectTree/><t:ObjectTree/>"#,
        r#"<t:Transformation/><t:Transformation/>"#,
        r#"<t:Object ObjectId="1"><t:Behaviour/><t:Behaviour/></t:Object>"#,
        r#"<t:Object ObjectId="1"><t:Appearance/><t:Appearance/></t:Object>"#,
        r#"<t:Object ObjectId="1"><t:Behaviour><t:Idle/><t:Idle/></t:Behaviour></t:Object>"#,
        r#"<t:Object ObjectId="1"><t:Behaviour><t:Removed/><t:Removed/></t:Behaviour></t:Object>"#,
    ] {
        assert_eq!(
            parse(&frames(&frame(content))),
            Err(Error::Wire(WireError::DuplicateField))
        );
    }
}

#[test]
fn overlay_does_not_upgrade_frozen_v1_or_v2_interpretations() -> Test {
    let xml = frames(&frame(
        r#"<t:Object ObjectId="+001"><t:Behaviour><t:Idle/></t:Behaviour></t:Object><t:ObjectTree><t:Rename><t:from ObjectId="+001"/><t:to ObjectId="2"/></t:Rename></t:ObjectTree>"#,
    ));
    let old_v1 = parse_event_document(xml.as_bytes())?;
    let old_v2 = parse_metadata_document(xml.as_bytes())?;
    assert!(old_v1.analytics_frames.is_empty());
    assert_eq!(old_v1.unsupported_sections, 1);
    assert_eq!(old_v2.analytics_frames.len(), 1);
    assert_eq!(old_v2.analytics_frames[0].unsupported_extensions, 1);
    assert_eq!(
        old_v2.analytics_frames[0].objects[0].unsupported_extensions,
        1
    );
    assert!(old_v2.has_unsupported_content());
    let lifecycle = parse(&xml)?;
    assert!(!lifecycle.has_unsupported_content());
    assert_eq!(
        lifecycle.frames[0].objects[0]
            .reference
            .object_id
            .as_deref(),
        Some("+001")
    );
    assert_eq!(parse_event_document(xml.as_bytes())?, old_v1);
    assert_eq!(parse_metadata_document(xml.as_bytes())?, old_v2);
    Ok(())
}

#[test]
fn appearance_and_transform_remain_the_separate_analytics_owners_job() -> Test {
    let xml = frames(&frame(
        r#"<t:Transformation><t:Translate x="0" y="0"/><t:Scale x="1" y="1"/><v:Calibration/></t:Transformation><t:Object ObjectId="1"><t:Appearance><v:PrivateAppearance/></t:Appearance><t:Behaviour><t:Idle/></t:Behaviour></t:Object>"#,
    ));
    assert!(!parse(&xml)?.has_unsupported_content());
    assert!(parse_metadata_document(xml.as_bytes())?.has_unsupported_content());
    Ok(())
}

#[test]
fn all_debug_paths_redact_original_private_values() -> Test {
    let xml = frames(&frame(
        r#"<t:Object ObjectId="987654321012345"><t:Behaviour><t:Idle/></t:Behaviour></t:Object><t:ObjectTree><t:Rename><t:from ObjectId="987654321012345" UUID="uuid-do-not-log"/><t:to ObjectId="876543210123456"/></t:Rename></t:ObjectTree>"#,
    ));
    let result = parse(&xml)?;
    let frame = &result.frames[0];
    for rendered in [
        format!("{result:?}"),
        format!("{frame:?}"),
        format!("{:?}", frame.objects[0]),
        format!("{:?}", frame.operations[0]),
        format!("{:?}", frame.operations[0].from[0]),
    ] {
        for private in [
            "motion private",
            "2026-11-09",
            "987654321012345",
            "876543210123456",
            "uuid-do-not-log",
        ] {
            assert!(!rendered.contains(private));
        }
    }
    Ok(())
}

#[test]
fn decoded_xml_lexemes_preserve_unicode_entities_and_numeric_spelling() -> Test {
    let xml = source(
        r#"<t:VideoAnalytics><t:Frame UtcTime="2026-11-09T12:00:00.000000001Z" Source="módulo &amp; &quot;入口&quot;"><t:ObjectTree><t:Rename><t:from ObjectId="&#43;0007"/><t:to ObjectId="-0000"/></t:Rename></t:ObjectTree></t:Frame></t:VideoAnalytics>"#,
    );
    let result = parse(&xml)?;
    assert_eq!(
        result.frames[0].source.as_deref(),
        Some("módulo & \"入口\"")
    );
    assert_eq!(
        result.frames[0].operations[0].from[0].object_id.as_deref(),
        Some("+0007")
    );
    assert_eq!(
        result.frames[0].operations[0].to[0].object_id.as_deref(),
        Some("-0000")
    );
    Ok(())
}

#[test]
fn missing_and_empty_module_names_remain_distinct() -> Test {
    let xml = frames(
        r#"<t:Frame UtcTime="2026-11-09T12:00:00Z"/><t:Frame UtcTime="2026-11-09T12:00:01Z" Source=""/>"#,
    );
    let result = parse(&xml)?;
    assert_eq!(result.frames[0].source, None);
    assert_eq!(result.frames[1].source.as_deref(), Some(""));
    Ok(())
}

#[test]
fn malformed_known_scalar_and_text_content_are_rejected() {
    for operation in [
        r#"<t:Delete ObjectId="1.0"/>"#,
        r#"<t:Delete ObjectId=" 1"/>"#,
        r#"<t:Delete ObjectId="+"/>"#,
        r#"<t:Delete ObjectId="1">not empty</t:Delete>"#,
        r#"<t:Rename><t:from ObjectId="1">text</t:from><t:to ObjectId="2"/></t:Rename>"#,
    ] {
        assert_eq!(
            parse(&tree(operation)),
            Err(Error::Wire(WireError::InvalidField))
        );
    }
    assert_eq!(
        parse(&frames(r#"<t:Frame Source="m"/>"#)),
        Err(Error::Wire(WireError::MissingField))
    );
    assert_eq!(
        parse(&frames(r#"<t:Frame UtcTime="2026-11-09T12:00:00+00:00"/>"#)),
        Err(Error::Wire(WireError::InvalidField))
    );
}

#[test]
fn lexical_size_bounds_are_checked_before_cloning_values() -> Test {
    assert!(
        parse(&tree(&format!(
            r#"<t:Delete ObjectId="{}"/>"#,
            "9".repeat(64)
        )))
        .is_ok()
    );
    assert_eq!(
        parse(&tree(&format!(
            r#"<t:Delete ObjectId="{}"/>"#,
            "9".repeat(65)
        ))),
        Err(Error::Wire(WireError::InvalidField))
    );
    let accepted = parse(&tree(&format!(r#"<t:Delete UUID="{}"/>"#, "u".repeat(256))))?;
    assert!(accepted.has_unsupported_content());
    assert_eq!(
        parse(&tree(&format!(r#"<t:Delete UUID="{}"/>"#, "u".repeat(257)))),
        Err(Error::Wire(WireError::InvalidField))
    );
    let too_long_module = frames(&format!(
        r#"<t:Frame UtcTime="2026-11-09T12:00:00Z" Source="{}"/>"#,
        "m".repeat(257)
    ));
    assert_eq!(
        parse(&too_long_module),
        Err(Error::Wire(WireError::InvalidField))
    );
    Ok(())
}

#[test]
fn aggregate_shape_caps_refuse_before_returning_a_partial_document() {
    let fixtures = [
        (
            frames(&(frame("") + &frame(""))),
            Limits {
                max_frames: 1,
                ..Limits::default()
            },
        ),
        (
            frames(&frame(
                r#"<t:Object ObjectId="1"/><t:Object ObjectId="2"/>"#,
            )),
            Limits {
                max_objects: 1,
                ..Limits::default()
            },
        ),
        (
            tree(r#"<t:Delete ObjectId="1"/><t:Delete ObjectId="2"/>"#),
            Limits {
                max_operations: 1,
                ..Limits::default()
            },
        ),
        (
            tree(&rename("1", "2")),
            Limits {
                max_references: 1,
                ..Limits::default()
            },
        ),
    ];
    for (xml, limits) in fixtures {
        assert_eq!(
            parse_metadata_lifecycle_document(xml.as_bytes(), limits, || true),
            Err(Error::Limit)
        );
    }
}

#[test]
fn hard_frame_and_object_bounds_remain_shared_with_existing_wire() -> Test {
    let frames_at_limit = frames(&frame("").repeat(wire::MAX_ANALYTICS_FRAMES));
    assert_eq!(
        parse(&frames_at_limit)?.frames.len(),
        wire::MAX_ANALYTICS_FRAMES
    );
    assert_eq!(
        parse(&frames(&frame("").repeat(wire::MAX_ANALYTICS_FRAMES + 1))),
        Err(Error::Limit)
    );
    let object = r#"<t:Object ObjectId="1"/>"#;
    assert_eq!(
        parse(&frames(&frame(
            &object.repeat(wire::MAX_ANALYTICS_OBJECTS_PER_FRAME + 1)
        ))),
        Err(Error::Limit)
    );
    Ok(())
}

#[test]
fn complete_operation_and_reference_bounds_are_executable() -> Test {
    let operation = r#"<t:Delete ObjectId="1"/>"#;
    assert_eq!(
        parse(&tree(&operation.repeat(wire::MAX_LIFECYCLE_OPERATIONS)))?.operation_count,
        wire::MAX_LIFECYCLE_OPERATIONS
    );
    assert_eq!(
        parse(&tree(&operation.repeat(wire::MAX_LIFECYCLE_OPERATIONS + 1))),
        Err(Error::Limit)
    );
    let many_refs = |count| {
        tree(&format!(
            r#"<t:Merge>{}<t:to ObjectId="2"/></t:Merge>"#,
            r#"<t:from ObjectId="1"/>"#.repeat(count),
        ))
    };
    assert_eq!(
        parse(&many_refs(wire::MAX_LIFECYCLE_REFERENCES - 1))?.reference_count,
        wire::MAX_LIFECYCLE_REFERENCES
    );
    assert_eq!(
        parse(&many_refs(wire::MAX_LIFECYCLE_REFERENCES)),
        Err(Error::Limit)
    );
    Ok(())
}

#[test]
fn work_quote_is_preflighted_and_consumed_exactly_once() -> Test {
    let xml = tree(&rename("1", "2"));
    let quote = lifecycle_parse_work_bound(xml.len()).ok_or("missing quote")?;
    let mut calls = 0;
    assert_eq!(
        parse_metadata_lifecycle_document(
            xml.as_bytes(),
            Limits {
                max_work_units: quote - 1,
                ..Limits::default()
            },
            || {
                calls += 1;
                true
            }
        ),
        Err(Error::Limit)
    );
    assert_eq!(calls, 0);
    let result = parse_metadata_lifecycle_document(
        xml.as_bytes(),
        Limits {
            max_work_units: quote,
            ..Limits::default()
        },
        || true,
    )?;
    assert_eq!(result.work_units, quote);
    assert!(quote < Limits::default().max_work_units);
    let maximum =
        lifecycle_parse_work_bound(wire::MAX_SOAP_BYTES).ok_or("missing maximum quote")?;
    assert!(maximum <= wire::MAX_LIFECYCLE_PARSE_WORK_UNITS);
    assert!(lifecycle_parse_work_bound(wire::MAX_SOAP_BYTES + 1).is_none());
    assert!(lifecycle_parse_work_bound(usize::MAX).is_none());
    Ok(())
}

#[test]
fn every_cooperative_cut_including_finalization_returns_no_success() -> Test {
    let xml = frames(&frame(
        r#"<t:Object ObjectId="1"><t:Behaviour><t:Idle/></t:Behaviour></t:Object><t:ObjectTree><t:Rename><t:from ObjectId="1"/><t:to ObjectId="2"/></t:Rename></t:ObjectTree>"#,
    ));
    let mut checkpoints = 0;
    parse_metadata_lifecycle_document(xml.as_bytes(), Limits::default(), || {
        checkpoints += 1;
        true
    })?;
    assert!(checkpoints > 10);
    for refused_at in 1..=checkpoints {
        let mut calls = 0;
        let result = parse_metadata_lifecycle_document(xml.as_bytes(), Limits::default(), || {
            calls += 1;
            calls != refused_at
        });
        assert_eq!(result, Err(Error::Cancelled));
        assert_eq!(calls, refused_at);
    }
    Ok(())
}

#[test]
fn original_xml_safety_byte_and_format_bounds_are_not_bypassed() {
    let too_large = vec![b'x'; wire::MAX_SOAP_BYTES + 1];
    assert_eq!(
        parse_metadata_lifecycle_document(&too_large, Limits::default(), || true),
        Err(Error::Wire(WireError::InputTooLarge))
    );
    assert!(matches!(
        parse(
            r#"<!DOCTYPE t:MetadataStream [<!ENTITY x SYSTEM "file:///private">]><t:MetadataStream xmlns:t="http://www.onvif.org/ver10/schema">&x;</t:MetadataStream>"#
        ),
        Err(Error::Wire(WireError::UnsupportedXml))
    ));
    assert!(matches!(
        parse(r#"<x:MetadataStream/>"#),
        Err(Error::Wire(WireError::MalformedXml))
    ));
    assert_eq!(
        parse(
            r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>"#
        ),
        Err(Error::Wire(WireError::UnexpectedResponse))
    );
    assert_eq!(
        parse(&source("not element-only")),
        Err(Error::Wire(WireError::InvalidField))
    );
}

#[test]
fn empty_and_uninterpreted_documents_do_not_assert_absence() -> Test {
    let empty = parse(&source(""))?;
    assert!(empty.frames.is_empty());
    assert_eq!(empty.operation_count, 0);
    assert_eq!(empty.reference_count, 0);
    assert!(empty.work_units > 0);
    let opaque = parse(&source(
        "<v:VideoAnalytics/><t:Event/><t:VideoAnalytics><v:Frame/></t:VideoAnalytics>",
    ))?;
    assert!(opaque.frames.is_empty());
    assert_eq!(opaque.unsupported_sections, 3);
    assert!(opaque.has_unsupported_content());
    Ok(())
}
