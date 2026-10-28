#![forbid(unsafe_code)]
//! Exact-source contracts: this suite also runs directly with rustc --test.

#[path = "../src/onvif/wire.rs"]
mod wire;

use wire::{
    EventDocumentFormat, MAX_PULL_POINT_LIFETIME_SECONDS, MAX_PULL_TIMEOUT_SECONDS, OnvifOperation,
    WireError, create_pull_point_request, parse_event_document, parse_pull_messages_response,
    parse_pull_point_subscription, parse_renew_response, parse_unsubscribe_response,
    pull_messages_request, renew_pull_point_request, unsubscribe_pull_point_request,
};

const SOAP: &str = "http://www.w3.org/2003/05/soap-envelope";
const EVENTS: &str = "http://www.onvif.org/ver10/events/wsdl";
const WSA: &str = "http://www.w3.org/2005/08/addressing";
const WSN: &str = "http://docs.oasis-open.org/wsn/b-2";
const CREATE_ACTION: &str =
    "http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionResponse";
const PULL_ACTION: &str =
    "http://www.onvif.org/ver10/events/wsdl/PullPointSubscription/PullMessagesResponse";
const ENDPOINT: &str = "http://192.0.2.4/onvif/subscription?Idx=7&Mode=pull";

fn envelope(body: &str, header: &str) -> Vec<u8> {
    format!(
        "<s:Envelope xmlns:s=\"{SOAP}\" xmlns:e=\"{EVENTS}\" xmlns:w=\"{WSA}\" xmlns:n=\"{WSN}\" xmlns:v=\"urn:vendor:route\"><s:Header>{header}</s:Header><s:Body>{body}</s:Body></s:Envelope>"
    ).into_bytes()
}

fn created_with_times(parameters: &str, current: &str, termination: &str) -> Vec<u8> {
    envelope(
        &format!(
            "<e:CreatePullPointSubscriptionResponse><e:SubscriptionReference><w:Address>http://192.0.2.4/onvif/subscription?Idx=7&amp;Mode=pull</w:Address>{parameters}</e:SubscriptionReference><n:CurrentTime>{current}</n:CurrentTime><n:TerminationTime>{termination}</n:TerminationTime></e:CreatePullPointSubscriptionResponse>"
        ),
        &format!("<w:Action s:mustUnderstand=\"1\">{CREATE_ACTION}</w:Action>"),
    )
}

fn created(parameters: &str) -> Vec<u8> {
    created_with_times(parameters, "2026-10-27T23:00:00Z", "2026-10-27T23:02:00Z")
}

fn pull(header: &str) -> Vec<u8> {
    envelope(
        "<e:PullMessagesResponse><e:CurrentTime>2026-10-27T23:00:01Z</e:CurrentTime><e:TerminationTime>2026-10-27T23:02:00Z</e:TerminationTime></e:PullMessagesResponse>",
        header,
    )
}

#[test]
fn create_request_has_finite_lease_and_explicit_addressing() {
    let request = create_pull_point_request(ENDPOINT, 120).unwrap();
    assert_eq!(
        request.action(),
        OnvifOperation::CreatePullPointSubscription.action()
    );
    assert!(request.is_event_subscription());
    let body = std::str::from_utf8(request.body()).unwrap();
    assert!(body.contains("<tev:InitialTerminationTime>PT120S</tev:InitialTerminationTime>"));
    assert!(body.contains("Idx=7&amp;Mode=pull"));
    assert!(body.contains("<wsa:Action s:mustUnderstand=\"1\">"));
    assert!(body.contains("<wsa:To s:mustUnderstand=\"1\">"));
    assert!(!body.contains("ConsumerReference"));
    assert!(!body.contains("<tev:Filter"));
    assert!(!format!("{request:?}").contains("Idx=7"));
    assert!(!wire::get_profiles_request().is_event_subscription());
}

#[test]
fn create_and_pull_bounds_are_enforced_before_io() {
    for lifetime in [0, MAX_PULL_POINT_LIFETIME_SECONDS + 1, u32::MAX] {
        assert_eq!(
            create_pull_point_request(ENDPOINT, lifetime).unwrap_err(),
            WireError::InvalidField
        );
    }
    assert!(create_pull_point_request(ENDPOINT, MAX_PULL_POINT_LIFETIME_SECONDS).is_ok());
    for endpoint in [
        "",
        "ftp://camera/endpoint",
        "http://camera/\r\nHeader:value",
        "http://camera/a#b",
    ] {
        assert_eq!(
            create_pull_point_request(endpoint, 60).unwrap_err(),
            WireError::InvalidField
        );
    }
    let subscription = parse_pull_point_subscription(&created("")).unwrap();
    for timeout in [0, MAX_PULL_TIMEOUT_SECONDS + 1, u32::MAX] {
        assert_eq!(
            pull_messages_request(&subscription, timeout, 1).unwrap_err(),
            WireError::InvalidField
        );
    }
    for count in [0, 129, u16::MAX] {
        assert_eq!(
            pull_messages_request(&subscription, 1, count).unwrap_err(),
            WireError::InvalidField
        );
    }
    assert!(pull_messages_request(&subscription, MAX_PULL_TIMEOUT_SECONDS, 128).is_ok());
}

#[test]
fn subscription_parses_correct_create_time_namespace_and_query() {
    let subscription = parse_pull_point_subscription(&created("")).unwrap();
    assert_eq!(subscription.endpoint(), ENDPOINT);
    assert_eq!(subscription.current_time(), "2026-10-27T23:00:00Z");
    assert_eq!(subscription.termination_time(), "2026-10-27T23:02:00Z");
    assert_eq!(subscription.lease_seconds(), 120);
    assert_eq!(subscription.reference_parameter_count(), 0);
    assert!(!format!("{subscription:?}").contains("192.0.2.4"));
    let wrong = String::from_utf8(created(""))
        .unwrap()
        .replace("n:CurrentTime", "e:CurrentTime");
    assert!(parse_pull_point_subscription(wrong.as_bytes()).is_err());
}

#[test]
fn scalar_reference_parameters_preserve_qnames_and_cannot_inject_headers() {
    let source = created(
        "<w:ReferenceParameters xmlns:local=\"urn:vendor:qname\"><v:Token>local:Specific&amp;Value</v:Token><v:Id>7</v:Id></w:ReferenceParameters>",
    );
    let subscription = parse_pull_point_subscription(&source).unwrap();
    assert_eq!(subscription.reference_parameter_count(), 2);
    for request in [
        pull_messages_request(&subscription, 5, 16).unwrap(),
        renew_pull_point_request(&subscription, 180).unwrap(),
        unsubscribe_pull_point_request(&subscription).unwrap(),
    ] {
        let body = std::str::from_utf8(request.body()).unwrap();
        assert_eq!(body.matches("IsReferenceParameter=\"true\"").count(), 2);
        assert!(body.contains("xmlns:local=\"urn:vendor:qname\""));
        assert!(body.contains("local:Specific&amp;Value"));
        assert!(body.contains("xmlns:fssref=\"urn:vendor:route\""));
        assert!(request.is_event_subscription());
        assert_eq!(body.matches("<s:Header>").count(), 1);
    }
}

#[test]
fn scalar_reference_parameter_prefix_shadowing_is_preserved() {
    let source = created(
        "<w:ReferenceParameters xmlns:fssref=\"urn:original\" xmlns:fssaddr=\"urn:other\"><v:Token xmlns:v=\"urn:shadowed\">fssref:Name</v:Token></w:ReferenceParameters>",
    );
    let subscription = parse_pull_point_subscription(&source).unwrap();
    let request = pull_messages_request(&subscription, 1, 1).unwrap();
    let body = std::str::from_utf8(request.body()).unwrap();
    assert!(body.contains("<fssref_:Token"));
    assert!(body.contains("xmlns:fssref_=\"urn:shadowed\""));
    assert!(body.contains("xmlns:fssref=\"urn:original\""));
    assert!(body.contains("fssaddr_:IsReferenceParameter=\"true\""));
    assert!(body.contains(">fssref:Name</"));
}

#[test]
fn reference_parameter_values_are_escaped_without_interpretation() {
    let source = created(
        "<w:ReferenceParameters><v:Token>&lt;s:Header&gt;&quot;&apos;&amp;</v:Token></w:ReferenceParameters>",
    );
    let subscription = parse_pull_point_subscription(&source).unwrap();
    let request = pull_messages_request(&subscription, 1, 1).unwrap();
    let body = std::str::from_utf8(request.body()).unwrap();
    assert!(body.contains("&lt;s:Header&gt;&quot;&apos;&amp;"));
    assert_eq!(body.matches("<s:Header>").count(), 1);
}

#[test]
fn complex_attributed_control_and_duplicate_parameters_are_refused() {
    for parameter in [
        "<v:Token><v:Nested>7</v:Nested></v:Token>",
        "<v:Token mode=\"route\">7</v:Token>",
        "<w:To>http://unapproved.example/</w:To>",
        "<s:Header/>",
        "<Token>7</Token>",
        "<v:Token>7</v:Token><v:Token>8</v:Token>",
        "<v:Token w:IsReferenceParameter=\"false\">7</v:Token>",
    ] {
        let source = created(&format!(
            "<w:ReferenceParameters>{parameter}</w:ReferenceParameters>"
        ));
        assert!(
            parse_pull_point_subscription(&source).is_err(),
            "{parameter}"
        );
    }
    let allowed = created(
        "<w:ReferenceParameters><v:Token w:IsReferenceParameter=\"1\">7</v:Token></w:ReferenceParameters>",
    );
    assert!(parse_pull_point_subscription(&allowed).is_ok());
}

#[test]
fn reference_parameter_count_and_bytes_are_bounded() {
    let parameters = (0..9)
        .map(|i| format!("<v:P{i}>7</v:P{i}>"))
        .collect::<String>();
    assert_eq!(
        parse_pull_point_subscription(&created(&format!(
            "<w:ReferenceParameters>{parameters}</w:ReferenceParameters>"
        )))
        .unwrap_err(),
        WireError::ItemLimitExceeded,
    );
    let oversized = format!(
        "<w:ReferenceParameters><v:Token>{}</v:Token></w:ReferenceParameters>",
        "x".repeat(1025)
    );
    assert_eq!(
        parse_pull_point_subscription(&created(&oversized)).unwrap_err(),
        WireError::InvalidField
    );
}

#[test]
fn reference_and_response_extensions_cannot_be_silently_dropped() {
    let base = String::from_utf8(created("")).unwrap();
    for replacement in [
        "<w:Metadata>unknown</w:Metadata></e:SubscriptionReference>",
        "<w:ReferenceProperties><v:Token>7</v:Token></w:ReferenceProperties></e:SubscriptionReference>",
        "<w:ReferenceParameters/><w:ReferenceParameters/></e:SubscriptionReference>",
    ] {
        let changed = base.replace("</e:SubscriptionReference>", replacement);
        assert!(parse_pull_point_subscription(changed.as_bytes()).is_err());
    }
    let changed = base.replace(
        "</e:CreatePullPointSubscriptionResponse>",
        "<v:Critical>unknown</v:Critical></e:CreatePullPointSubscriptionResponse>",
    );
    assert_eq!(
        parse_pull_point_subscription(changed.as_bytes()).unwrap_err(),
        WireError::UnsupportedEventContent
    );
}

#[test]
fn lease_arithmetic_handles_fractional_utc_and_calendar_boundaries() {
    for (current, end, seconds) in [
        ("2026-10-27T23:00:00.9Z", "2026-10-27T23:01:00.1Z", 59),
        (
            "2024-02-28T23:59:59.999999999Z",
            "2024-03-01T00:00:00Z",
            86400,
        ),
        ("1999-12-31T23:59:59Z", "2000-01-01T00:00:01Z", 2),
        ("2100-02-28T23:59:59Z", "2100-03-01T00:00:01Z", 2),
        ("9999-12-31T23:58:59Z", "9999-12-31T23:59:59Z", 60),
    ] {
        let subscription =
            parse_pull_point_subscription(&created_with_times("", current, end)).unwrap();
        assert_eq!(subscription.lease_seconds(), seconds);
        assert_eq!(subscription.current_time(), current);
        assert_eq!(subscription.termination_time(), end);
    }
}

#[test]
fn expired_zero_subsecond_invalid_and_unbounded_leases_are_refused() {
    for (current, end) in [
        ("2026-10-27T23:00:00Z", "2026-10-27T23:00:00Z"),
        ("2026-10-27T23:00:01Z", "2026-10-27T23:00:00Z"),
        ("2026-10-27T23:00:00.1Z", "2026-10-27T23:00:00.9Z"),
        ("2026-02-29T00:00:00Z", "2026-03-01T00:02:00Z"),
        ("2026-10-27T23:00:00+00:00", "2026-10-27T23:02:00Z"),
        ("1970-01-01T00:00:00Z", "9999-12-31T23:59:59Z"),
    ] {
        assert_eq!(
            parse_pull_point_subscription(&created_with_times("", current, end)).unwrap_err(),
            WireError::InvalidField,
        );
    }
}

#[test]
fn response_action_must_match_and_unknown_required_headers_refuse() {
    let base = String::from_utf8(created("")).unwrap();
    assert_eq!(
        parse_pull_point_subscription(base.replace(CREATE_ACTION, PULL_ACTION).as_bytes())
            .unwrap_err(),
        WireError::UnexpectedResponse,
    );
    let duplicate = base.replace(
        "</s:Header>",
        &format!("<w:Action>{CREATE_ACTION}</w:Action></s:Header>"),
    );
    assert_eq!(
        parse_pull_point_subscription(duplicate.as_bytes()).unwrap_err(),
        WireError::DuplicateField
    );
    let required = base.replace(
        "</s:Header>",
        "<v:Required s:mustUnderstand=\"1\"/></s:Header>",
    );
    assert_eq!(
        parse_pull_point_subscription(required.as_bytes()).unwrap_err(),
        WireError::UnsupportedHeader
    );
    let role = base.replace(
        "s:mustUnderstand=\"1\"",
        "s:mustUnderstand=\"1\" s:role=\"urn:someone-else\"",
    );
    assert_eq!(
        parse_pull_point_subscription(role.as_bytes()).unwrap_err(),
        WireError::UnsupportedHeader
    );
}

#[test]
fn addressed_pull_parser_does_not_change_import_v1_acceptance() {
    let required = pull(&format!(
        "<w:Action s:mustUnderstand=\"true\">{PULL_ACTION}</w:Action>"
    ));
    assert_eq!(
        parse_event_document(&required).unwrap_err(),
        WireError::UnsupportedHeader
    );
    let parsed = parse_pull_messages_response(&required).unwrap();
    assert_eq!(parsed.format, EventDocumentFormat::PullMessages);
    assert_eq!(parsed.notifications.len(), 0);
    assert!(parsed.has_unsupported_content());
    let wrong = pull(&format!("<w:Action>{CREATE_ACTION}</w:Action>"));
    assert!(parse_event_document(&wrong).is_ok());
    assert_eq!(
        parse_pull_messages_response(&wrong).unwrap_err(),
        WireError::UnexpectedResponse
    );
    let compatible = pull(&format!("<w:Action>{PULL_ACTION}</w:Action>"));
    assert_eq!(
        parse_event_document(&compatible).unwrap(),
        parse_pull_messages_response(&compatible).unwrap()
    );
    let metadata = b"<tt:MetadataStream xmlns:tt=\"http://www.onvif.org/ver10/schema\"/>";
    assert_eq!(
        parse_pull_messages_response(metadata).unwrap_err(),
        WireError::UnexpectedResponse
    );
}

#[test]
fn anonymous_to_is_understood_but_other_destinations_are_refused() {
    let good =
        pull("<w:To s:mustUnderstand=\"1\">http://www.w3.org/2005/08/addressing/anonymous</w:To>");
    assert!(parse_pull_messages_response(&good).is_ok());
    let wrong = pull("<w:To>http://unapproved.example/</w:To>");
    assert_eq!(
        parse_pull_messages_response(&wrong).unwrap_err(),
        WireError::UnsupportedHeader
    );
    let duplicate = pull(
        "<w:To>http://www.w3.org/2005/08/addressing/anonymous</w:To><w:To>http://www.w3.org/2005/08/addressing/anonymous</w:To>",
    );
    assert_eq!(
        parse_pull_messages_response(&duplicate).unwrap_err(),
        WireError::DuplicateField
    );
}

#[test]
fn renew_and_unsubscribe_bind_standard_actions_and_exact_response() {
    let subscription = parse_pull_point_subscription(&created("")).unwrap();
    let renew = renew_pull_point_request(&subscription, 90).unwrap();
    assert_eq!(
        renew.action(),
        "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/RenewRequest"
    );
    assert!(
        std::str::from_utf8(renew.body())
            .unwrap()
            .contains("<wsnt:TerminationTime>PT90S</wsnt:TerminationTime>")
    );
    let renewed = envelope(
        "<n:RenewResponse><n:TerminationTime>2026-10-27T23:04:00Z</n:TerminationTime><n:CurrentTime>2026-10-27T23:02:00Z</n:CurrentTime></n:RenewResponse>",
        "",
    );
    assert_eq!(parse_renew_response(&renewed).unwrap().lease_seconds(), 120);
    assert_eq!(parse_renew_response(&envelope("<n:RenewResponse><n:TerminationTime>2026-10-27T23:04:00Z</n:TerminationTime></n:RenewResponse>", "")).unwrap_err(), WireError::MissingField);
    let unsubscribe = unsubscribe_pull_point_request(&subscription).unwrap();
    assert_eq!(
        unsubscribe.action(),
        "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/UnsubscribeRequest"
    );
    assert!(parse_unsubscribe_response(&envelope("<n:UnsubscribeResponse/>", "")).is_ok());
    assert_eq!(
        parse_unsubscribe_response(&envelope(
            "<n:UnsubscribeResponse><v:Pending/></n:UnsubscribeResponse>",
            ""
        ))
        .unwrap_err(),
        WireError::UnsupportedEventContent
    );
    assert!(parse_unsubscribe_response(&envelope("<n:RenewResponse/>", "")).is_err());
}

#[test]
fn username_token_merges_into_single_addressing_header() {
    let unsigned = create_pull_point_request(ENDPOINT, 120).unwrap();
    let signed = unsigned.with_security_header(
        b"<s:Header><wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><wsse:UsernameToken>opaque-proof</wsse:UsernameToken></wsse:Security></s:Header>",
    ).unwrap();
    let body = std::str::from_utf8(signed.body()).unwrap();
    assert_eq!(body.matches("<s:Header>").count(), 1);
    assert_eq!(body.matches("</s:Header>").count(), 1);
    assert_eq!(body.matches("<wsse:Security ").count(), 1);
    assert!(body.find("<wsse:Security ").unwrap() < body.find("</s:Header>").unwrap());
    assert!(body.contains("<wsa:Action "));
    assert!(signed.has_username_token());
    assert!(signed.is_event_subscription());
    assert_eq!(
        signed.with_security_header(b"<s:Header/>").unwrap_err(),
        WireError::UnsupportedHeader
    );
    let ordinary = wire::get_profiles_request()
        .with_security_header(b"<s:Header><v:Security xmlns:v=\"urn:test\"/></s:Header>")
        .unwrap();
    assert_eq!(
        std::str::from_utf8(ordinary.body())
            .unwrap()
            .matches("<s:Header>")
            .count(),
        1
    );
}

#[test]
fn malformed_xml_faults_and_wrong_envelopes_never_create_subscriptions() {
    for bytes in [
        b"<!DOCTYPE evil [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><x/>".as_slice(),
        b"<x/>".as_slice(),
        b"<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'/>".as_slice(),
        b"<x>\xff</x>".as_slice(),
    ] {
        assert!(parse_pull_point_subscription(bytes).is_err());
    }
    let fault = envelope(
        "<s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code><s:Reason><s:Text xml:lang=\"en\">secret</s:Text></s:Reason></s:Fault>",
        "",
    );
    assert!(matches!(
        parse_pull_point_subscription(&fault),
        Err(WireError::SoapFault(_))
    ));
    assert!(!format!("{:?}", parse_pull_point_subscription(&fault)).contains("secret"));
}

#[test]
fn request_message_ids_are_explicit_immutable_and_redacted() {
    let id = "urn:fss:onvif:1234567890abcdef1234567890abcdef";
    let unsigned = create_pull_point_request(ENDPOINT, 120).unwrap();
    assert_eq!(unsigned.message_id(), None);
    let request = unsigned.with_message_id(id).unwrap();
    assert_eq!(request.message_id(), Some(id));
    assert!(!format!("{request:?}").contains(id));
    let body = std::str::from_utf8(request.body()).unwrap();
    assert_eq!(body.matches("<wsa:MessageID>").count(), 1);
    assert!(body.contains("<wsa:ReplyTo><wsa:Address>http://www.w3.org/2005/08/addressing/anonymous</wsa:Address></wsa:ReplyTo>"));
    assert_eq!(
        request.with_message_id(id).unwrap_err(),
        WireError::UnsupportedHeader
    );
    assert_eq!(
        wire::get_profiles_request()
            .with_message_id(id)
            .unwrap_err(),
        WireError::UnsupportedHeader
    );
    for invalid in [
        "",
        "urn:",
        "https://id.example/x",
        "urn:test:bad value",
        "urn:test:<injection>",
    ] {
        assert_eq!(
            create_pull_point_request(ENDPOINT, 60)
                .unwrap()
                .with_message_id(invalid)
                .unwrap_err(),
            WireError::InvalidField
        );
    }
}

#[test]
fn response_relationship_rejects_mismatch_duplicate_and_nonreply() {
    let id = "urn:fss:onvif:1234567890abcdef1234567890abcdef";
    let good = pull(&format!(
        "<w:RelatesTo s:mustUnderstand=\"1\">{id}</w:RelatesTo>"
    ));
    assert!(wire::validate_relates_to(&good, id).is_ok());
    assert!(parse_pull_messages_response(&good).is_ok());
    assert_eq!(
        wire::validate_relates_to(&good, "urn:fss:onvif:different").unwrap_err(),
        WireError::UnexpectedResponse
    );
    assert!(wire::validate_relates_to(&pull(""), id).is_ok());
    let duplicate = pull(&format!(
        "<w:RelatesTo>{id}</w:RelatesTo><w:RelatesTo>{id}</w:RelatesTo>"
    ));
    assert_eq!(
        wire::validate_relates_to(&duplicate, id).unwrap_err(),
        WireError::DuplicateField
    );
    assert_eq!(
        parse_pull_messages_response(&duplicate).unwrap_err(),
        WireError::DuplicateField
    );
    let other = pull(&format!(
        "<w:RelatesTo RelationshipType=\"urn:other\">{id}</w:RelatesTo>"
    ));
    assert_eq!(
        wire::validate_relates_to(&other, id).unwrap_err(),
        WireError::UnsupportedHeader
    );
    let explicit = pull(&format!(
        "<w:RelatesTo RelationshipType=\"http://www.w3.org/2005/08/addressing/reply\">{id}</w:RelatesTo>"
    ));
    assert!(wire::validate_relates_to(&explicit, id).is_ok());
}

#[test]
fn inherited_xml_context_cannot_change_replayed_reference_parameter_meaning() {
    let source = String::from_utf8(created(
        "<w:ReferenceParameters><v:Token>relative-token</v:Token></w:ReferenceParameters>",
    ))
    .unwrap();
    for attribute in [
        "xml:base=\"http://192.0.2.4/onvif/alternate/\"",
        "xml:lang=\"en\"",
        "xml:space=\"preserve\"",
    ] {
        for ancestor in ["<s:Envelope ", "<s:Body>"] {
            let replacement = if ancestor.ends_with('>') {
                format!("<s:Body {attribute}>")
            } else {
                format!("<s:Envelope {attribute} ")
            };
            let changed = source.replacen(ancestor, &replacement, 1);
            assert_eq!(
                parse_pull_point_subscription(changed.as_bytes()).unwrap_err(),
                WireError::UnsupportedEventContent,
            );
        }
    }
}
