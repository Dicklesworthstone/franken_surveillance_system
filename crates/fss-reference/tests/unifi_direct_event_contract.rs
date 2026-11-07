#![forbid(unsafe_code)]
//! Synthetic event classification and bounded, non-authoritative interpretation.

use fss_reference::unifi_direct::{
    Controller, Identity, Observation,
    events::{self, Edge, Kind},
};

#[test]
fn smart_event_is_a_camera_claim_with_explicit_reply_requirement()
-> Result<(), Box<dyn std::error::Error>> {
    let source=br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventSmartDetect","messageId":21,"responseExpected":true,"payload":{"edgeType":"enter","descriptors":[{"objectType":"person","trackerID":42,"confidenceLevel":80,"coord":[0,1,500,1000],"stationary":"false"}]}}"#;
    let mut controller = Controller::new(
        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
        1,
    )?;
    assert_eq!(
        controller.observe_event_claims(source)?,
        Observation::CameraEvent {
            kind: Kind::SmartDetect,
            message_id: 21,
            response_expected: true
        }
    );
    let parsed = events::interpret_source(source)?;
    assert_eq!(parsed.edge, Edge::Enter);
    let descriptor = &parsed.descriptors.ok_or("missing descriptors")?[0];
    assert_eq!(descriptor.object_type.as_deref(), Some("person"));
    assert_eq!(descriptor.tracker_id.as_deref(), Some("42"));
    assert_eq!(descriptor.confidence, Some(80.0));
    assert_eq!(descriptor.coordinates, Some([0.0, 1.0, 500.0, 1000.0]));
    assert_eq!(descriptor.stationary, Some(false));
    assert!(!format!("{descriptor:?}").contains("person"));
    Ok(())
}

#[test]
fn malformed_and_oversized_event_claims_are_refused() {
    assert_eq!(
        events::interpret_source(br#"{"payload":{"eventType":42}}"#),
        Err(events::Error::Invalid)
    );
    assert_eq!(
        events::interpret_source(br#"{"payload":{"descriptors":[{"coord":[0,0,1001,1]}]}}"#),
        Err(events::Error::Invalid)
    );
    let many = format!(
        "{{\"payload\":{{\"descriptors\":[{}]}}}}",
        vec!["{}"; 65].join(",")
    );
    assert_eq!(
        events::interpret_source(many.as_bytes()),
        Err(events::Error::Limit)
    );
}

#[test]
fn absent_empty_and_unknown_event_fields_are_distinct() -> Result<(), events::Error> {
    let missing = events::interpret_source(br#"{"payload":{}}"#)?;
    assert_eq!((missing.edge, missing.descriptors), (Edge::Missing, None));
    let empty = events::interpret_source(br#"{"payload":{"edgeType":"future","descriptors":[]}}"#)?;
    assert_eq!((empty.edge, empty.descriptors), (Edge::Other, Some(vec![])));
    assert_eq!(
        events::interpret_source(br#"{"payload":{"eventType":"pulse"}}"#)?.edge,
        Edge::Pulse
    );
    Ok(())
}
