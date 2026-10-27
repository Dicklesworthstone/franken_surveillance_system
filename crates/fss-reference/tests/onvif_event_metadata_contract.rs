#![forbid(unsafe_code)]
#![allow(clippy::panic)]
//! FSS-046: hostile, bounded vendor-event metadata remains cognition only.

#[path = "../src/onvif/wire.rs"]
mod wire;

use wire::{
    EventDocumentFormat, MAX_EVENT_ITEMS, MAX_EVENT_NOTIFICATIONS, MAX_EVENT_VALUE_BYTES,
    PropertyOperation, WireError, parse_event_document,
};

const NS: &str = r#"xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:n="http://docs.oasis-open.org/wsn/b-2" xmlns:topic="http://www.onvif.org/ver10/topics""#;

fn notification(message: &str) -> String {
    format!(
        r#"<n:NotificationMessage><n:Topic Dialect="http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet">topic:RuleEngine/CellMotionDetector/Motion</n:Topic><n:Message>{message}</n:Message></n:NotificationMessage>"#
    )
}

fn message(groups: &str) -> String {
    format!(
        r#"<tt:Message UtcTime="2026-10-27T12:34:56.123456789Z" PropertyOperation="Changed">{groups}</tt:Message>"#
    )
}

fn metadata(notifications: &str) -> Vec<u8> {
    format!(r#"<tt:MetadataStream {NS}><tt:Event>{notifications}</tt:Event></tt:MetadataStream>"#)
        .into_bytes()
}

fn pull(notifications: &str) -> Vec<u8> {
    format!(
        r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:e="http://www.onvif.org/ver10/events/wsdl" {NS}><s:Body><e:PullMessagesResponse><e:CurrentTime>2026-10-27T12:35:00Z</e:CurrentTime><e:TerminationTime>2026-10-27T12:40:00Z</e:TerminationTime>{notifications}</e:PullMessagesResponse></s:Body></s:Envelope>"#
    ).into_bytes()
}

fn parse(bytes: &[u8]) -> wire::EventDocument {
    match parse_event_document(bytes) {
        Ok(value) => value,
        Err(error) => panic!("valid synthetic metadata refused: {error:?}"),
    }
}

fn replace(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    String::from_utf8_lossy(bytes)
        .replace(from, to)
        .into_bytes()
}

#[test]
fn pull_messages_preserves_vendor_property_state_tokens_and_exact_values() {
    let groups = r#"<tt:Source><tt:SimpleItem Name="VideoSourceConfigurationToken" Value="camera&amp;1"/></tt:Source><tt:Key><tt:SimpleItem Name="ObjectId" Value="003"/></tt:Key><tt:Data><tt:SimpleItem Name="IsMotion" Value="false"/><tt:SimpleItem Name="Label" Value="do not execute &lt;commands&gt;"/></tt:Data>"#;
    let result = parse(&pull(&notification(&message(groups))));
    assert_eq!(result.format, EventDocumentFormat::PullMessages);
    assert_eq!(result.current_time.as_deref(), Some("2026-10-27T12:35:00Z"));
    assert_eq!(
        result.termination_time.as_deref(),
        Some("2026-10-27T12:40:00Z")
    );
    assert_eq!(result.notifications.len(), 1);
    assert!(!result.has_unsupported_content());
    let event = &result.notifications[0];
    assert_eq!(event.utc_time, "2026-10-27T12:34:56.123456789Z");
    assert_eq!(event.property_operation, Some(PropertyOperation::Changed));
    assert_eq!(event.topic.namespace, "http://www.onvif.org/ver10/topics");
    assert_eq!(
        event.topic.path,
        ["RuleEngine", "CellMotionDetector", "Motion"]
    );
    let Some(source) = &event.source else {
        panic!("missing source")
    };
    assert_eq!(source.simple_items[0].value, "camera&1");
    let Some(key) = &event.key else {
        panic!("missing key")
    };
    assert_eq!(key.simple_items[0].value, "003");
    let Some(data) = &event.data else {
        panic!("missing data")
    };
    assert_eq!(data.simple_items[0].value, "false");
    assert_eq!(data.simple_items[1].value, "do not execute <commands>");
}

#[test]
fn equivalent_namespace_prefixes_and_both_containers_preserve_notification_semantics() {
    let event = notification(&message("<tt:Data/>"));
    let stream = metadata(&event);
    let alternate = replace(
        &replace(&stream, "tt:", "schema:"),
        "xmlns:tt=",
        "xmlns:schema=",
    );
    assert_eq!(parse(&stream), parse(&alternate));
    assert_eq!(
        parse(&stream).notifications,
        parse(&pull(&event)).notifications
    );
    let concrete = replace(
        &stream,
        "http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet",
        "http://docs.oasis-open.org/wsn/t-1/TopicExpression/Concrete",
    );
    assert_eq!(parse(&stream).notifications, parse(&concrete).notifications);
}

#[test]
fn pure_events_missing_groups_and_present_empty_groups_are_distinct() {
    let bytes = metadata(&notification(
        r#"<tt:Message UtcTime="2024-02-29T00:00:00Z"><tt:Data/></tt:Message>"#,
    ));
    let result = parse(&bytes);
    assert!(result.current_time.is_none());
    assert!(result.termination_time.is_none());
    let event = &result.notifications[0];
    assert!(event.property_operation.is_none());
    assert!(event.source.is_none());
    assert!(event.key.is_none());
    assert!(event.data.is_some());
}

#[test]
fn initialized_changed_deleted_are_preserved_and_unknown_operations_refused() {
    let bytes = metadata(&notification(&message("")));
    for (name, operation) in [
        ("Initialized", PropertyOperation::Initialized),
        ("Changed", PropertyOperation::Changed),
        ("Deleted", PropertyOperation::Deleted),
    ] {
        assert_eq!(
            parse(&replace(&bytes, "Changed", name)).notifications[0].property_operation,
            Some(operation)
        );
    }
    assert_eq!(
        parse_event_document(&replace(&bytes, "Changed", "Granted")),
        Err(WireError::InvalidField)
    );
}

#[test]
fn duplicate_and_out_of_order_notifications_are_not_silently_coalesced() {
    let first = notification(&message(""));
    let older = first.replace("2026-10-27", "2026-10-26");
    let result = parse(&metadata(&format!("{first}{older}{first}")));
    assert_eq!(result.notifications.len(), 3);
    assert_eq!(result.notifications[0], result.notifications[2]);
    assert_eq!(
        result.notifications[1].utc_time,
        "2026-10-26T12:34:56.123456789Z"
    );
}

#[test]
fn complex_items_and_unknown_sections_are_explicitly_retained_only() {
    let event = notification(&message(
        r#"<tt:Data><tt:ElementItem Name="Region"><tt:Polygon><tt:Point x="1" y="2"/></tt:Polygon></tt:ElementItem><tt:Extension><tt:Future/></tt:Extension></tt:Data><tt:Extension><tt:Future/></tt:Extension>"#,
    ));
    let mut bytes = String::from_utf8_lossy(&metadata(&event)).into_owned();
    bytes = bytes.replace(
        "<tt:Event>",
        "<tt:VideoAnalytics><tt:Frame/></tt:VideoAnalytics><tt:Event>",
    );
    let result = parse(bytes.as_bytes());
    assert!(result.has_unsupported_content());
    assert_eq!(result.unsupported_sections, 1);
    assert_eq!(result.notifications[0].unsupported_extensions, 1);
    let Some(data) = &result.notifications[0].data else {
        panic!("missing data")
    };
    assert_eq!(data.element_items, ["Region"]);
    assert!(data.simple_items.is_empty());
    assert_eq!(data.unsupported_extensions, 1);
}

#[test]
fn empty_batches_are_just_empty_metadata_without_coverage_or_absence_claims() {
    let stream = parse(&metadata(""));
    let pull = parse(&pull(""));
    assert!(stream.notifications.is_empty());
    assert!(pull.notifications.is_empty());
    assert_ne!(stream.format, pull.format);
    let unknown = replace(
        &metadata(""),
        "<tt:Event>",
        "<tt:Event><vendor:NotificationMessage xmlns:vendor=\"urn:vendor\"/>",
    );
    let result = parse(&unknown);
    assert!(result.notifications.is_empty());
    assert_eq!(result.unsupported_sections, 1);
    assert!(result.has_unsupported_content());
}

#[test]
fn wrong_namespaces_cannot_supply_required_event_fields() {
    let bytes = metadata(&notification(&message("")));
    for (from, to) in [
        ("http://docs.oasis-open.org/wsn/b-2", "urn:impostor"),
        ("<tt:Message ", "<tt:Message xmlns:tt=\"urn:impostor\" "),
    ] {
        let result = parse_event_document(&replace(&bytes, from, to));
        if from.contains("wsn") {
            let Ok(result) = result else {
                panic!("expected retained-only section")
            };
            assert!(result.notifications.is_empty());
            assert!(result.has_unsupported_content());
        } else {
            assert!(result.is_err());
        }
    }
    assert!(
        parse_event_document(&replace(
            &pull(""),
            "http://www.onvif.org/ver10/events/wsdl",
            "urn:impostor"
        ))
        .is_err()
    );
}

#[test]
fn duplicate_groups_items_topics_messages_and_times_fail_closed() {
    let base = metadata(&notification(&message("<tt:Data/>")));
    assert_eq!(
        parse_event_document(&replace(&base, "<tt:Data/>", "<tt:Data/><tt:Data/>")),
        Err(WireError::DuplicateField)
    );
    for items in [
        r#"<tt:SimpleItem Name="State" Value="1"/><tt:SimpleItem Name="State" Value="0"/>"#,
        r#"<tt:SimpleItem Name="State" Value="1"/><tt:ElementItem Name="State"><tt:Value/></tt:ElementItem>"#,
    ] {
        assert_eq!(
            parse_event_document(&replace(
                &base,
                "<tt:Data/>",
                &format!("<tt:Data>{items}</tt:Data>")
            )),
            Err(WireError::DuplicateField)
        );
    }
    assert!(
        parse_event_document(&replace(
            &base,
            "</n:Message>",
            "<tt:Message UtcTime=\"2026-10-27T12:00:00Z\"/></n:Message>"
        ))
        .is_err()
    );
    let time = "<e:CurrentTime>2026-10-27T12:35:00Z</e:CurrentTime>";
    assert_eq!(
        parse_event_document(&replace(&pull(""), time, &format!("{time}{time}"))),
        Err(WireError::DuplicateField)
    );
}

#[test]
fn malformed_or_missing_values_never_turn_into_empty_or_false_data() {
    let base = metadata(&notification(&message("<tt:Data/>")));
    for item in [
        r#"<tt:SimpleItem Name="State"/>"#,
        r#"<tt:SimpleItem Value="true"/>"#,
        r#"<tt:SimpleItem Name="" Value="true"/>"#,
        r#"<tt:SimpleItem Name="State" Value="true"><tt:Injected/></tt:SimpleItem>"#,
        r#"<tt:ElementItem Name="State"/>"#,
        r#"<tt:ElementItem Name="State"><tt:A/><tt:B/></tt:ElementItem>"#,
    ] {
        assert!(
            parse_event_document(&replace(
                &base,
                "<tt:Data/>",
                &format!("<tt:Data>{item}</tt:Data>")
            ))
            .is_err(),
            "{item}"
        );
    }
    let empty = parse(&replace(
        &base,
        "<tt:Data/>",
        r#"<tt:Data><tt:SimpleItem Name="Value" Value=""/></tt:Data>"#,
    ));
    let Some(data) = &empty.notifications[0].data else {
        panic!("missing data")
    };
    assert_eq!(data.simple_items[0].value, "");
}

#[test]
fn timestamps_require_real_calendar_dates_explicit_utc_and_bounded_precision() {
    let bytes = metadata(&notification(&message("")));
    for time in [
        "2023-02-29T12:00:00Z",
        "2026-13-01T12:00:00Z",
        "2026-04-31T12:00:00Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T12:60:00Z",
        "2026-01-01T12:00:60Z",
        "2026-01-01T12:00:00",
        "2026-01-01T12:00:00+01:00",
        "1969-01-01T00:00:00Z",
        "2026-01-01T12:00:00.Z",
        "2026-01-01T12:00:00.1234567890Z",
        "2026-01-01T12:00:00.aZ",
    ] {
        assert_eq!(
            parse_event_document(&replace(&bytes, "2026-10-27T12:34:56.123456789Z", time)),
            Err(WireError::InvalidField),
            "{time}"
        );
    }
    for time in [
        "1970-01-01T00:00:00Z",
        "2000-02-29T12:00:00.0Z",
        "9999-12-31T23:59:59.999999999Z",
    ] {
        assert!(
            parse_event_document(&replace(&bytes, "2026-10-27T12:34:56.123456789Z", time)).is_ok()
        );
    }
}

#[test]
fn topics_are_namespace_resolved_concrete_names_not_selector_expressions() {
    let bytes = metadata(&notification(&message("")));
    for topic in [
        "topic:RuleEngine/*",
        "topic:RuleEngine//Motion",
        "topic:RuleEngine|topic:Other",
        "unbound:RuleEngine/Motion",
        "topic:RuleEngine/",
        "/topic:RuleEngine",
        "topic:RuleEngine/tt:Motion",
    ] {
        assert!(
            parse_event_document(&replace(
                &bytes,
                "topic:RuleEngine/CellMotionDetector/Motion",
                topic
            ))
            .is_err(),
            "{topic}"
        );
    }
    assert!(
        parse_event_document(&replace(
            &bytes,
            "topicExpression/ConcreteSet",
            "topicExpression/XPath"
        ))
        .is_err()
    );
}

#[test]
fn notification_item_and_value_limits_refuse_whole_document_without_truncation() {
    let event = notification(&message(""));
    assert_eq!(
        parse(&metadata(&event.repeat(MAX_EVENT_NOTIFICATIONS)))
            .notifications
            .len(),
        MAX_EVENT_NOTIFICATIONS
    );
    assert_eq!(
        parse_event_document(&metadata(&event.repeat(MAX_EVENT_NOTIFICATIONS + 1))),
        Err(WireError::EventLimitExceeded)
    );
    let items = (0..MAX_EVENT_ITEMS)
        .map(|i| format!(r#"<tt:SimpleItem Name="k{i}" Value="v"/>"#))
        .collect::<String>();
    assert!(
        parse_event_document(&metadata(&notification(&message(&format!(
            "<tt:Data>{items}</tt:Data>"
        )))))
        .is_ok()
    );
    let excess = format!(r#"<tt:Data>{items}<tt:SimpleItem Name="excess" Value="v"/></tt:Data>"#);
    assert_eq!(
        parse_event_document(&metadata(&notification(&message(&excess)))),
        Err(WireError::ItemLimitExceeded)
    );
    for (count, valid) in [
        (MAX_EVENT_VALUE_BYTES, true),
        (MAX_EVENT_VALUE_BYTES + 1, false),
    ] {
        let items = format!(
            r#"<tt:Data><tt:SimpleItem Name="Value" Value="{}"/></tt:Data>"#,
            "a".repeat(count)
        );
        assert_eq!(
            parse_event_document(&metadata(&notification(&message(&items)))).is_ok(),
            valid
        );
    }
}

#[test]
fn xml_entities_dtds_trailing_bodies_and_mixed_content_are_rejected() {
    let bytes = metadata(&notification(&message("")));
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        parse_event_document(
            format!("<!DOCTYPE tt:MetadataStream [<!ENTITY x SYSTEM 'file:///secret'>]>{text}")
                .as_bytes()
        )
        .is_err()
    );
    assert!(parse_event_document(format!("{text}<extra/>").as_bytes()).is_err());
    assert!(
        parse_event_document(&replace(&bytes, "<tt:Event>", "<tt:Event>unparsed text")).is_err()
    );
    assert!(
        parse_event_document(&replace(
            &bytes,
            "</tt:Message>",
            "unparsed text</tt:Message>"
        ))
        .is_err()
    );
}

#[test]
fn debug_and_errors_never_echo_vendor_metadata_or_clock_values() {
    let bytes = metadata(&notification(&message(
        r#"<tt:Source><tt:SimpleItem Name="private-name" Value="private-token"/></tt:Source><tt:Data><tt:ElementItem Name="private-region"><tt:Secret/></tt:ElementItem></tt:Data>"#,
    )));
    let result = parse(&bytes);
    let event = &result.notifications[0];
    let debug = format!(
        "{result:?} {event:?} {:?} {:?} {:?}",
        event.topic, event.source, event.data
    );
    for sensitive in [
        "private-name",
        "private-token",
        "private-region",
        "2026-10-27",
        "RuleEngine",
        "onvif.org",
    ] {
        assert!(!debug.contains(sensitive), "{debug}");
    }
}

#[test]
fn unknown_attributes_remain_explicit_instead_of_disappearing() {
    let bytes = metadata(&notification(&message(
        r#"<tt:Data><tt:SimpleItem Name="State" Value="true" vendor="uninterpreted"/></tt:Data>"#,
    )));
    let result = parse(&bytes);
    assert!(result.has_unsupported_content());
    let Some(data) = &result.notifications[0].data else {
        panic!("missing data")
    };
    assert_eq!(data.unsupported_extensions, 1);
    let bytes = replace(
        &bytes,
        "PropertyOperation=",
        r#"vendor-attribute="value" PropertyOperation="#,
    );
    assert_eq!(parse(&bytes).notifications[0].unsupported_extensions, 1);
}

#[test]
fn pull_response_clock_attributes_and_optional_soap_headers_are_explicit() {
    let bytes = pull("");
    for (from, to) in [
        (
            "<e:CurrentTime>",
            r#"<e:CurrentTime xmlns:v="urn:vendor" v:ClockStatus="Unsynchronized">"#,
        ),
        (
            "<e:TerminationTime>",
            r#"<e:TerminationTime vendor="unknown">"#,
        ),
        ("<s:Body>", r#"<s:Body vendor="unknown">"#),
        ("<s:Envelope ", r#"<s:Envelope vendor="unknown" "#),
        (
            "<s:Body>",
            r#"<s:Header><v:ClockStatus xmlns:v="urn:vendor">Unsynchronized</v:ClockStatus></s:Header><s:Body>"#,
        ),
    ] {
        let result = parse(&replace(&bytes, from, to));
        assert!(result.has_unsupported_content(), "{to}");
        assert_eq!(result.unsupported_sections, 1);
    }
}
