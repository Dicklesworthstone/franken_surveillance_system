#![forbid(unsafe_code)]
//! Camera-local request sequencing, bounded inputs and refusal contracts.
use asupersync::http::h1::Response;
use fss_core::ContentDigest;
use fss_reference::unifi_direct::camera_api::{
    ControllerAddress, ControllerPort, Error, Phase, Session, StatusShape, VideoDestinationShape,
    WriteOutcome,
};
use std::{error::Error as StdError, net::Ipv4Addr};

type Test = Result<(), Box<dyn StdError>>;
const CREDENTIAL: &[u8] = br#"{"username":"test-user-canary","password":"test-password-canary"}"#;

fn login(s: &mut Session) -> Test {
    let request = s.prepare_login(CREDENTIAL)?;
    assert!(!format!("{request:?} {s:?}").contains("test-password-canary"));
    s.finish_write(request, WriteOutcome::Written)?;
    s.accept_login(
        Response::new(200, "OK", Vec::new())
            .with_header("Set-Cookie", "authId=test-cookie-canary; Path=/"),
    )?;
    Ok(())
}
fn status(s: &mut Session) -> Test {
    let request = s.prepare_status()?;
    assert!(!format!("{request:?} {s:?}").contains("test-cookie-canary"));
    s.finish_write(request, WriteOutcome::Written)?;
    assert_eq!(
        s.accept_status(Response::new(
            200,
            "OK",
            br#"{"board":{},"fw":{},"controller":{}}"#.to_vec()
        ))?,
        StatusShape {
            board: true,
            firmware: true,
            controller: true,
            controller_port: ControllerPort::Missing,
        }
    );
    Ok(())
}

#[test]
fn status_preserves_controller_port_claim_and_uncertainty() -> Test {
    let cases: &[(&[u8], ControllerPort)] = &[
        (
            br#"{"controller":{"port":7442}}"#,
            ControllerPort::Reported(7442),
        ),
        (
            br#"{"controller":{"port":65535}}"#,
            ControllerPort::Reported(65535),
        ),
        (br#"{"controller":{}}"#, ControllerPort::Missing),
        (br#"{}"#, ControllerPort::Missing),
        (br#"{"controller":{"port":null}}"#, ControllerPort::Unset),
        (br#"{"controller":{"port":0}}"#, ControllerPort::Unsupported),
        (
            br#"{"controller":{"port":65536}}"#,
            ControllerPort::Unsupported,
        ),
        (
            br#"{"controller":{"port":-1}}"#,
            ControllerPort::Unsupported,
        ),
        (
            br#"{"controller":{"port":"7442"}}"#,
            ControllerPort::Unsupported,
        ),
        (
            br#"{"controller":{"port":1.5}}"#,
            ControllerPort::Unsupported,
        ),
        (br#"{"controller":true}"#, ControllerPort::Unsupported),
    ];
    for (body, expected) in cases {
        let mut session = Session::new(Ipv4Addr::LOCALHOST, 1)?;
        login(&mut session)?;
        let request = session.prepare_status()?;
        session.finish_write(request, WriteOutcome::Written)?;
        let observed = session.accept_status(Response::new(200, "OK", body.to_vec()))?;
        assert_eq!(&observed.controller_port, expected);
    }
    Ok(())
}

#[test]
fn login_status_and_repeated_snapshot_sequence() -> Test {
    let mut s = Session::new(Ipv4Addr::LOCALHOST, 1)?;
    assert_eq!(s.phase(), Phase::Login);
    assert!(s.prepare_status().is_err());
    login(&mut s)?;
    status(&mut s)?;
    let frame = [0xff, 0xd8, 0xff, 0xd9];
    for _ in 0..2 {
        let request = s.prepare_snapshot()?;
        assert!(request.bytes().starts_with(b"GET /snap.jpeg HTTP/1.1\r\n"));
        s.finish_write(request, WriteOutcome::Written)?;
        let result = s.accept_snapshot(Response::new(200, "OK", frame.to_vec()))?;
        assert_eq!(result.bytes(), frame);
        assert_eq!(result.digest(), ContentDigest::sha256(&frame));
        assert_eq!(s.phase(), Phase::Snapshot);
    }
    Ok(())
}

#[test]
fn partial_write_fences_and_unwritten_request_can_be_prepared_again() -> Test {
    let mut s = Session::new(Ipv4Addr::LOCALHOST, 1)?;
    let request = s.prepare_login(CREDENTIAL)?;
    s.finish_write(request, WriteOutcome::NotWritten)?;
    assert_eq!(s.phase(), Phase::Login);
    let request = s.prepare_login(CREDENTIAL)?;
    s.finish_write(request, WriteOutcome::Indeterminate)?;
    assert_eq!(s.phase(), Phase::Fenced);
    assert!(s.prepare_login(CREDENTIAL).is_err());
    Ok(())
}

#[test]
fn wrong_session_request_and_invalid_credential_never_advance_state() -> Test {
    let mut a = Session::new(Ipv4Addr::LOCALHOST, 1)?;
    let mut b = Session::new(Ipv4Addr::LOCALHOST, 1)?;
    assert!(
        a.prepare_login(br#"{"username":"x","password":"y","extra":"z"}"#)
            .is_err()
    );
    assert!(
        a.prepare_login(br#"{"username":"x","password":"y","password":"z"}"#)
            .is_err()
    );
    let a_request = a.prepare_login(CREDENTIAL)?;
    let b_request = b.prepare_login(CREDENTIAL)?;
    assert_eq!(
        a.finish_write(b_request, WriteOutcome::Written),
        Err(Error::RequestMismatch)
    );
    assert_eq!(a.phase(), Phase::RequestPrepared);
    a.finish_write(a_request, WriteOutcome::NotWritten)?;
    assert_eq!(a.phase(), Phase::Login);
    assert_eq!(b.phase(), Phase::RequestPrepared);
    Ok(())
}

#[test]
fn invalid_cookies_status_and_images_fence_without_retry() -> Test {
    for response in [
        Response::new(401, "no", Vec::new()),
        Response::new(200, "ok", Vec::new()).with_header("Set-Cookie", "authId=a\r\nX: injected"),
        Response::new(200, "ok", Vec::new())
            .with_header("Set-Cookie", "authId=a")
            .with_header("Set-Cookie", "authId=b"),
    ] {
        let mut s = Session::new(Ipv4Addr::LOCALHOST, 1)?;
        let request = s.prepare_login(CREDENTIAL)?;
        s.finish_write(request, WriteOutcome::Written)?;
        assert!(s.accept_login(response).is_err());
        assert_eq!(s.phase(), Phase::Fenced);
    }
    let mut s = Session::new(Ipv4Addr::LOCALHOST, 1)?;
    login(&mut s)?;
    let request = s.prepare_status()?;
    s.finish_write(request, WriteOutcome::Written)?;
    assert!(
        s.accept_status(Response::new(200, "ok", br#"{"fw":{},"fw":{}}"#.to_vec()))
            .is_err()
    );
    assert_eq!(s.phase(), Phase::Fenced);
    let mut s = Session::new(Ipv4Addr::LOCALHOST, 1)?;
    login(&mut s)?;
    status(&mut s)?;
    let request = s.prepare_snapshot()?;
    s.finish_write(request, WriteOutcome::Written)?;
    assert!(
        s.accept_snapshot(Response::new(200, "ok", b"not a jpeg".to_vec()))
            .is_err()
    );
    assert_eq!(s.phase(), Phase::Fenced);
    Ok(())
}

#[test]
fn settings_preserve_known_unset_and_unknown_controller_claims() -> Test {
    let mut s = Session::new(Ipv4Addr::LOCALHOST, 1)?;
    login(&mut s)?;
    status(&mut s)?;
    let cases: [(&[u8], ControllerAddress, bool); 5] = [
        (
            br#"{"controller":{"addr":"192.168.1.12"},"password":"private-settings-canary"}"#,
            ControllerAddress::Reported(Ipv4Addr::new(192, 168, 1, 12)),
            true,
        ),
        (
            br#"{"controller":{"addr":null}}"#,
            ControllerAddress::Unset,
            true,
        ),
        (br#"{"controller":{}}"#, ControllerAddress::Missing, false),
        (
            br#"{"controller":{"addr":"other.example"}}"#,
            ControllerAddress::Unsupported,
            false,
        ),
        (
            br#"{"controller":{"addr":123}}"#,
            ControllerAddress::Unsupported,
            false,
        ),
    ];
    let mut prior = None;
    for (body, expected, bound) in cases {
        let request = s.prepare_settings()?;
        assert!(
            request
                .bytes()
                .starts_with(b"GET /api/1.1/settings HTTP/1.1\r\n")
        );
        s.finish_write(request, WriteOutcome::Written)?;
        let result = s.accept_settings(Response::new(200, "OK", body.to_vec()))?;
        assert_eq!(result.controller, expected);
        assert_eq!(result.binding.is_some(), bound);
        assert!(!format!("{result:?}").contains("192.168.1.12"));
        assert!(!format!("{result:?}").contains("private-settings-canary"));
        if prior.is_none() {
            prior = result.binding;
        } else if bound {
            assert_ne!(prior, result.binding);
        }
        assert_eq!(s.phase(), Phase::Snapshot);
    }
    let request = s.prepare_settings()?;
    s.finish_write(request, WriteOutcome::Written)?;
    assert!(
        s.accept_settings(Response::new(
            200,
            "OK",
            br#"{"controller":{},"controller":{}}"#.to_vec()
        ))
        .is_err()
    );
    assert_eq!(s.phase(), Phase::Fenced);
    Ok(())
}

#[test]
fn settings_report_video_destination_shapes_without_exposing_destinations() -> Test {
    use VideoDestinationShape::{DiscardOnly, Empty, NotReported, Other, TcpOnly};
    let mut session = Session::new(Ipv4Addr::LOCALHOST, 1)?;
    login(&mut session)?;
    status(&mut session)?;
    let cases: [(&[u8], [VideoDestinationShape; 3]); 5] = [
        (br#"{}"#, [NotReported, NotReported, NotReported]),
        (br#"{"av":{"video":{"video1":{"avSerializer":{"destinations":null}},"video2":{"avSerializer":{"destinations":["tcp://private-host:99"]}},"video3":{"avSerializer":{"destinations":[]}}}}}"#, [NotReported, TcpOnly, Empty]),
        (br#"{"av":{"video":{"video1":{"avSerializer":{"destinations":["file:///dev/null"]}},"video2":{"avSerializer":{"destinations":["tcp://a","file:///dev/null"]}},"video3":{"avSerializer":{"destinations":[null]}}}}}"#, [DiscardOnly, Other, Other]),
        (br#"{"av":{"video":{"video1":4,"video2":{"avSerializer":{"destinations":"tcp://a"}},"video3":null}}}"#, [Other, Other, NotReported]),
        (br#"{"av":{"video":{"video1":{"avSerializer":{"destinations":["tcp://a","tcp://a","tcp://a","tcp://a","tcp://a","tcp://a","tcp://a","tcp://a","tcp://a","tcp://a","tcp://a","tcp://a","tcp://a","tcp://a","tcp://a","tcp://a","tcp://a"]}}}}}"#, [Other, NotReported, NotReported]),
    ];
    for (body, expected) in cases {
        let request = session.prepare_settings()?;
        session.finish_write(request, WriteOutcome::Written)?;
        let observed = session.accept_settings(Response::new(200, "OK", body.to_vec()))?;
        assert_eq!(observed.video_destinations, expected);
        assert!(!format!("{observed:?}").contains("private-host"));
    }
    Ok(())
}

#[test]
fn serializer_capture_requires_disclosure_and_preserves_null_and_absence() -> Test {
    use fss_core::json_input::Value;
    use std::cell::Cell;
    let mut session = Session::new(Ipv4Addr::LOCALHOST, 3)?;
    login(&mut session)?;
    status(&mut session)?;
    let request = session.prepare_settings()?;
    session.finish_write(request, WriteOutcome::Written)?;
    let (shape, serializers) = session.accept_settings_with_serializers(Response::new(
        200,
        "OK",
        br#"{"password":"outside-canary","av":{"video":{"video1":{"avSerializer":{"destinations":null}},"video2":{"avSerializer":{"destinations":["tcp://private-destination:1234"],"parameters":{"withOpus":false}}},"video3":{"avSerializer":null}}}}"#.to_vec(),
    ))?;
    assert_eq!(
        shape.video_destinations,
        [
            VideoDestinationShape::NotReported,
            VideoDestinationShape::TcpOnly,
            VideoDestinationShape::NotReported
        ]
    );
    assert!(!format!("{serializers:?}").contains("private-destination"));
    let called = Cell::new(false);
    assert_eq!(
        serializers.visit(|_, _| false, |_| called.set(true)),
        Err(Error::DisclosureDenied)
    );
    assert!(!called.get());
    let recognized = serializers.visit(
        |peer, generation| peer == Ipv4Addr::LOCALHOST && generation == 3,
        |tracks| {
            let first = tracks[0].and_then(Value::object).and_then(|v| v.get("destinations"));
            let second = tracks[1].and_then(Value::object).and_then(|v| v.get("destinations")).and_then(Value::array);
            matches!(first, Some(Value::Null))
                && matches!(second, Some([Value::Text(destination)]) if destination == "tcp://private-destination:1234")
                && matches!(tracks[2], Some(Value::Null))
        },
    )?;
    assert!(recognized);
    assert_eq!(session.phase(), Phase::Snapshot);
    let request = session.prepare_settings()?;
    session.finish_write(request, WriteOutcome::Written)?;
    let (_, absent) = session.accept_settings_with_serializers(Response::new(
        200,
        "OK",
        br#"{"av":{"video":{"video3":{}}}}"#.to_vec(),
    ))?;
    assert!(absent.visit(|_, _| true, |tracks| tracks.iter().all(Option::is_none))?);
    Ok(())
}

#[test]
fn serializer_binding_changes_with_values_peer_and_generation() -> Test {
    fn binding(
        peer: Ipv4Addr,
        generation: u64,
        body: &[u8],
    ) -> Result<ContentDigest, Box<dyn StdError>> {
        let mut session = Session::new(peer, generation)?;
        login(&mut session)?;
        status(&mut session)?;
        let request = session.prepare_settings()?;
        session.finish_write(request, WriteOutcome::Written)?;
        let (_, values) =
            session.accept_settings_with_serializers(Response::new(200, "OK", body.to_vec()))?;
        assert_eq!(values.binding(|_, _| false), Err(Error::DisclosureDenied));
        Ok(values.binding(|p, g| p == peer && g == generation)?)
    }
    let first = br#"{"av":{"video":{"video2":{"avSerializer":{"type":"extendedFlv","parameters":{"withOpus":false,"streamName":"private-test"},"destinations":["tcp://private-target"]}}}}}"#;
    let reordered = br#"{"av":{"video":{"video2":{"avSerializer":{"destinations":["tcp://private-target"],"parameters":{"streamName":"private-test","withOpus":false},"type":"extendedFlv"}}}}}"#;
    let changed = br#"{"av":{"video":{"video2":{"avSerializer":{"type":"extendedFlv","parameters":{"withOpus":false,"streamName":"changed-test"},"destinations":["tcp://private-target"]}}}}}"#;
    let null = br#"{"av":{"video":{"video2":{"avSerializer":null}}}}"#;
    let absent = br#"{"av":{"video":{"video2":{}}}}"#;
    let original = binding(Ipv4Addr::LOCALHOST, 1, first)?;
    assert_eq!(original, binding(Ipv4Addr::LOCALHOST, 1, reordered)?);
    assert_ne!(original, binding(Ipv4Addr::LOCALHOST, 1, changed)?);
    assert_ne!(original, binding(Ipv4Addr::new(127, 0, 0, 2), 1, first)?);
    assert_ne!(original, binding(Ipv4Addr::LOCALHOST, 2, first)?);
    assert_ne!(
        binding(Ipv4Addr::LOCALHOST, 1, null)?,
        binding(Ipv4Addr::LOCALHOST, 1, absent)?
    );
    Ok(())
}

#[test]
fn settings_binding_changes_with_peer_and_generation() -> Test {
    fn observe(peer: Ipv4Addr, generation: u64) -> Result<ContentDigest, Box<dyn StdError>> {
        let mut s = Session::new(peer, generation)?;
        login(&mut s)?;
        status(&mut s)?;
        let request = s.prepare_settings()?;
        s.finish_write(request, WriteOutcome::Written)?;
        s.accept_settings(Response::new(
            200,
            "OK",
            br#"{"controller":{"addr":"192.168.1.12"}}"#.to_vec(),
        ))?
        .binding
        .ok_or_else(|| "missing settings binding".into())
    }
    let base = observe(Ipv4Addr::LOCALHOST, 1)?;
    assert_ne!(base, observe(Ipv4Addr::LOCALHOST, 2)?);
    assert_ne!(base, observe(Ipv4Addr::new(127, 0, 0, 2), 1)?);
    Ok(())
}
