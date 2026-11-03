#![forbid(unsafe_code)]

use super::*;

fn camera(package: Option<bool>) -> Result<ProtectCamera, ProtectError> {
    let capability = package.map_or_else(String::new, |value| {
        format!(",\"hasPackageCamera\":{value}")
    });
    ProtectCamera::parse(
        format!(r#"{{"id":"synthetic-camera","state":"CONNECTED"{capability}}}"#).as_bytes(),
    )
}

fn source(camera: &str, streams: &str, rtsp: Option<&str>) -> Result<ProtectSource, ProtectError> {
    let override_field = rtsp.map_or_else(String::new, |value| format!(",\"rtsp\":{value}"));
    ProtectSource::parse(
        format!(r#"{{"camera":{camera},"streams":{streams}{override_field}}}"#).as_bytes(),
    )
}

#[test]
fn catalog_preserves_unknown_families_and_offline_cameras() -> Result<(), ProtectError> {
    let catalog = ProtectCatalog::parse(br#"[
        {"id":"g3","name":"Garage","type":"UVC G3 Flex","state":"CONNECTED","hasPackageCamera":false},
        {"id":"g4","name":"Entry","type":"UVC G4 Doorbell Pro","state":"DISCONNECTED","hasPackageCamera":true},
        {"id":"g5","type":"G5 PTZ","state":"CONNECTING"},
        {"id":"g6","type":"G6 Entry","hasPackageCamera":true,"featureFlags":{"newVendorFeature":true}},
        {"id":"ai","type":"AI 360","state":"CONNECTED","videoMode":"highFps"},
        {"id":"future","type":"Unreleased model","state":"FUTURE_STATE","futureField":{"opaque":[1,2,3]}},
        {"id":"unnamed","name":"","type":null,"state":null,"hasPackageCamera":null}
    ]"#)?;
    assert_eq!(catalog.cameras().len(), 7);
    let future = catalog
        .camera("future")
        .ok_or(ProtectError::MissingField("fixture"))?;
    assert_eq!(future.model(), Some("Unreleased model"));
    assert_eq!(future.connection_state(), CameraConnection::Unknown);
    assert!(future.vendor_fields().contains_key("futureField"));
    assert_eq!(
        catalog.cameras()[1].connection_state(),
        CameraConnection::Disconnected
    );
    assert_eq!(
        catalog.cameras()[2].connection_state(),
        CameraConnection::Connecting
    );
    assert_eq!(catalog.cameras()[3].has_package_camera(), Some(true));
    assert_eq!(catalog.cameras()[6].has_package_camera(), None);
    assert_eq!(catalog.cameras()[6].name(), Some(""));
    assert!(catalog.camera("Entry").is_none());
    assert_eq!(
        catalog.cameras()[4]
            .vendor_fields()
            .get("videoMode")
            .and_then(Value::text),
        Some("highFps")
    );
    Ok(())
}

#[test]
fn main_qualities_share_one_view_but_package_is_separate() -> Result<(), ProtectError> {
    let camera = camera(Some(true))?;
    let high = camera.view_identity(ProtectQuality::High)?;
    let low = camera.view_identity(ProtectQuality::Low)?;
    let package = camera.view_identity(ProtectQuality::Package)?;
    assert_eq!(high, low);
    assert_ne!(high, package);
    assert_eq!(high.camera_id(), package.camera_id());
    assert_eq!(high.view(), ProtectView::Main);
    assert_eq!(package.view(), ProtectView::Package);
    Ok(())
}

#[test]
fn exact_quality_keeps_disabled_and_missing_distinct() -> Result<(), ProtectError> {
    let streams = ProtectStreams::parse(
        br#"{
        "high":"rtsps://192.0.2.8:7441/synthetic-high?enableSrtp",
        "medium":null,
        "futureQuality":{"video":"opaque"}
    }"#,
    )?;
    let camera = camera(Some(false))?;
    assert!(
        streams
            .select(&camera, ProtectQuality::High)?
            .requires_secure_transport()
    );
    assert_eq!(
        streams.select(&camera, ProtectQuality::Medium),
        Err(ProtectError::DisabledStream(ProtectQuality::Medium))
    );
    assert_eq!(
        streams.select(&camera, ProtectQuality::Low),
        Err(ProtectError::MissingStream(ProtectQuality::Low))
    );
    assert!(streams.extensions().contains_key("futureQuality"));
    assert_eq!(
        streams.availability(ProtectQuality::Medium),
        &StreamAvailability::Disabled
    );
    assert_eq!(
        streams.availability(ProtectQuality::Low),
        &StreamAvailability::Missing
    );
    Ok(())
}

#[test]
fn package_url_never_substitutes_for_missing_capability() -> Result<(), ProtectError> {
    let streams =
        ProtectStreams::parse(br#"{"package":"rtsp://192.0.2.8:7447/synthetic-package"}"#)?;
    for capability in [None, Some(false)] {
        assert_eq!(
            streams.select(&camera(capability)?, ProtectQuality::Package),
            Err(ProtectError::PackageUnavailable)
        );
    }
    assert!(
        streams
            .select(&camera(Some(true))?, ProtectQuality::Package)
            .is_ok()
    );
    assert!(
        streams
            .select(&camera(Some(true))?, ProtectQuality::High)
            .is_err()
    );
    Ok(())
}

#[test]
fn secure_publication_is_never_implicitly_rewritten() -> Result<(), ProtectError> {
    let input = source(
        r#"{"id":"doorbell","type":"G6 Entry","state":"DISCONNECTED","hasPackageCamera":true}"#,
        r#"{"high":"rtsps://192.0.2.8:7441/synthetic-secret?enableSrtp","package":null}"#,
        Some(r#"{"high":"rtsp://192.0.2.8:7447/explicit-other-secret?source=original"}"#),
    )?;
    let published = input.select(ProtectQuality::High, TransportChoice::Published)?;
    assert_eq!(
        published.endpoint().require_plaintext_rtsp(),
        Err(ProtectError::SecureTransportRequired)
    );
    assert_eq!(
        published.endpoint().request_uri(),
        "rtsps://192.0.2.8:7441/synthetic-secret?enableSrtp"
    );
    let explicit = input.select(ProtectQuality::High, TransportChoice::OperatorRtsp)?;
    assert_eq!(
        explicit.endpoint().require_plaintext_rtsp()?,
        "rtsp://192.0.2.8:7447/explicit-other-secret?source=original"
    );
    assert_eq!(
        explicit.camera().connection_state(),
        CameraConnection::Disconnected
    );
    assert_eq!(explicit.identity(), published.identity());
    assert_eq!(explicit.quality(), ProtectQuality::High);
    assert_eq!(explicit.view(), ProtectView::Main);
    assert!(matches!(
        input.select(ProtectQuality::Package, TransportChoice::Published),
        Err(ProtectError::DisabledStream(ProtectQuality::Package))
    ));
    assert!(matches!(
        input.select(ProtectQuality::Low, TransportChoice::OperatorRtsp),
        Err(ProtectError::MissingStream(ProtectQuality::Low))
    ));
    Ok(())
}

#[test]
fn operator_override_is_explicit_and_fixed_shape() -> Result<(), ProtectError> {
    let camera = r#"{"id":"camera"}"#;
    let streams = r#"{"high":"rtsps://192.0.2.8:7441/secret"}"#;
    let absent = source(camera, streams, None)?;
    assert!(matches!(
        absent.select(ProtectQuality::High, TransportChoice::OperatorRtsp),
        Err(ProtectError::MissingOperatorRtsp)
    ));
    assert_eq!(
        source(camera, streams, Some(streams)),
        Err(ProtectError::NonRtspOverride)
    );
    assert_eq!(
        source(
            camera,
            streams,
            Some(r#"{"hig":"rtsp://192.0.2.8:7447/secret"}"#)
        ),
        Err(ProtectError::UnknownSourceField)
    );
    assert_eq!(
        ProtectSource::parse(br#"{"camera":{"id":"camera"},"streams":{},"allowDowngrade":true}"#),
        Err(ProtectError::UnknownSourceField)
    );
    assert!(source(camera, streams, Some("null")).is_err());
    Ok(())
}

#[test]
fn endpoints_preserve_exact_authority_path_query_and_transport() -> Result<(), ProtectError> {
    for (uri, host, authority, port, secure, resource) in [
        (
            "rtsp://192.0.2.8:7447/synthetic%2Ftoken?x=a%20b&empty=",
            "192.0.2.8",
            "192.0.2.8:7447",
            Some(7447),
            false,
            "/synthetic%2Ftoken?x=a%20b&empty=",
        ),
        (
            "rtsps://[2001:db8::1]:7441/synthetic?enableSrtp",
            "2001:db8::1",
            "[2001:db8::1]:7441",
            Some(7441),
            true,
            "/synthetic?enableSrtp",
        ),
        (
            "rtsp://NVR.Example./camera/channel_0",
            "NVR.Example.",
            "NVR.Example.",
            None,
            false,
            "/camera/channel_0",
        ),
        ("rtsps://[::1]", "::1", "[::1]", None, true, ""),
        (
            "RTSP://camera.local:554/?x=A+Z%2b%2B",
            "camera.local",
            "camera.local:554",
            Some(554),
            false,
            "/?x=A+Z%2b%2B",
        ),
    ] {
        let endpoint = StreamEndpoint::parse(uri)?;
        assert_eq!(endpoint.request_uri(), uri);
        assert_eq!(endpoint.host(), host);
        assert_eq!(endpoint.authority(), authority);
        assert_eq!(endpoint.port(), port);
        assert_eq!(endpoint.requires_secure_transport(), secure);
        assert_eq!(endpoint.resource(), resource);
    }
    Ok(())
}

#[test]
fn malformed_and_credential_bearing_endpoints_are_refused_without_echo() {
    for uri in [
        "",
        "http://192.0.2.8/secret",
        "rtsp:/192.0.2.8/secret",
        "rtsp:///secret",
        "rtsp://camera.local:0/secret",
        "rtsp://camera.local:65536/secret",
        "rtsp://camera.local:-1/secret",
        "rtsp://camera.local:/secret",
        "rtsp://user:secret@192.0.2.8:7447/secret",
        "rtsp://192.0.2.8@evil.example/secret",
        "rtsp://camera%40evil/secret",
        "rtsp://[::1]evil/secret",
        "rtsp://[::1]:554:1/secret",
        "rtsp://[fe80::1%25eth0]/secret",
        "rtsp://[not-ipv6]/secret",
        "rtsp://2001:db8::1/secret",
        "rtsp://-camera.local/secret",
        "rtsp://camera..local/secret",
        "rtsp://camera_.local/secret",
        "rtsp://2130706433/secret",
        "rtsp://127.1/secret",
        "rtsp://0127.0.0.1/secret",
        "rtsp://0x7f.1/secret",
        "rtsp://0x7f000001/secret",
        "rtsp://256.0.0.1/secret",
        "rtsp://camera.local/secret#fragment",
        "rtsp://camera.local/secret\\path",
        "rtsp://camera.local/secret\r\nHeader:value",
        "rtsp://camera.local/secret path",
        "rtsp://camera.local/secret%",
        "rtsp://camera.local/secret%ZZ",
        "rtsp://camera.local/secret%0D",
        "rtsp://camera.local/secret%0a",
        "rtsp://camera.local/secret%00",
        "rtsp://camera.local/secret%7f",
        "rtsp://camera.local/secret\"",
        "rtsp://camera.local/<secret>",
        "rtsp://camera.local/café-secret",
    ] {
        let result = StreamEndpoint::parse(uri);
        assert!(result.is_err(), "malformed fixture was accepted");
        let diagnostic = format!("{result:?}");
        assert!(!diagnostic.contains("secret"));
        assert!(!diagnostic.contains("evil"));
    }
    assert_eq!(
        StreamEndpoint::parse("rtsp://a:b@camera.local/"),
        Err(ProtectError::UserInfoForbidden)
    );
}

#[test]
fn no_debug_path_reveals_url_tokens_or_private_vendor_fields() -> Result<(), ProtectError> {
    let marker = "sensitive-canary-never-log";
    let camera_json = format!(
        r#"{{"id":"{marker}","name":"{marker}","type":"{marker}","futureField":"{marker}","hasPackageCamera":true}}"#
    );
    let streams_json = format!(
        r#"{{"high":"rtsps://192.0.2.8:7441/{marker}?enableSrtp","futureField":"{marker}"}}"#
    );
    let source = source(&camera_json, &streams_json, None)?;
    let selected = source.select(ProtectQuality::High, TransportChoice::Published)?;
    let diagnostics = [
        format!("{source:?}"),
        format!("{:?}", source.camera()),
        format!("{:?}", source.streams()),
        format!("{selected:?}"),
        format!("{:?}", selected.endpoint()),
        format!("{:?}", selected.identity()),
        format!("{:?}", source.streams().availability(ProtectQuality::High)),
    ];
    for diagnostic in diagnostics {
        assert!(!diagnostic.contains(marker));
    }
    assert_eq!(
        selected
            .camera()
            .vendor_fields()
            .get("futureField")
            .and_then(Value::text),
        Some(marker)
    );
    Ok(())
}

#[test]
fn duplicate_invalid_and_oversized_documents_fail_closed() {
    for document in [
        r#"{"id":"a","id":"b"}"#,
        r#"{"id":"a"} trailing"#,
        r#"{"id":"\ud800"}"#,
        r#"{"id":0}"#,
        r#"{"id":""}"#,
        r#"{"id":"a","hasPackageCamera":"true"}"#,
        r#"{"id":"a","state":12}"#,
        r#"{"id":"a","name":"bad\nname"}"#,
    ] {
        assert!(ProtectCamera::parse(document.as_bytes()).is_err());
    }
    assert_eq!(
        ProtectCatalog::parse(br#"[{"id":"same"},{"id":"same"}]"#),
        Err(ProtectError::DuplicateCamera)
    );
    assert_eq!(
        ProtectCatalog::parse(br#"{}"#),
        Err(ProtectError::InvalidShape)
    );
    assert_eq!(
        ProtectCamera::parse(&[0xff]),
        Err(ProtectError::InvalidUtf8)
    );
    assert_eq!(
        ProtectCatalog::parse(&vec![b' '; MAX_PROTECT_DOCUMENT_BYTES + 1]),
        Err(ProtectError::InputLimit)
    );
    let too_many = (0..=MAX_PROTECT_CAMERAS)
        .map(|index| format!(r#"{{"id":"{index}"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        ProtectCatalog::parse(format!("[{too_many}]").as_bytes()),
        Err(ProtectError::CameraLimit)
    );
    assert!(
        ProtectCamera::parse(format!(r#"{{"id":"{}"}}"#, "x".repeat(MAX_ID_BYTES + 1)).as_bytes())
            .is_err()
    );
    assert!(matches!(
        ProtectStreams::parse(br#"{"high":false}"#),
        Err(ProtectError::InvalidField("high"))
    ));
    assert!(ProtectStreams::parse(br#"{"high":""}"#).is_err());
    assert!(ProtectStreams::parse(br#"{"high":null,"high":null}"#).is_err());
    assert!(
        ProtectStreams::parse(
            format!(r#"{{"unknown":{}}}"#, "[".repeat(40) + &"]".repeat(40)).as_bytes()
        )
        .is_err()
    );
    assert_eq!(
        StreamEndpoint::parse(&format!(
            "rtsp://camera.local/{}",
            "x".repeat(MAX_STREAM_URI_BYTES)
        )),
        Err(ProtectError::UriLimit)
    );
}

#[test]
fn deterministic_mutations_never_panic_or_echo_input() -> Result<(), ProtectError> {
    let seed = br#"{"camera":{"id":"synthetic-camera","hasPackageCamera":true},"streams":{"high":"rtsps://192.0.2.8:7441/canary-stream-token?enableSrtp","package":null}}"#;
    let source = ProtectSource::parse(seed)?;
    assert_eq!(source.camera().id(), "synthetic-camera");
    for index in 0..seed.len() {
        for byte in [0, b'\n', b'"', b'\\', b'{', b']', 0xff] {
            let mut mutated = seed.to_vec();
            mutated[index] = byte;
            let result = ProtectSource::parse(&mutated);
            let diagnostic = format!("{result:?}");
            assert!(!diagnostic.contains("canary-stream-token"));
            if let Err(error) = result {
                assert!(!error.to_string().contains("canary-stream-token"));
            }
        }
    }
    Ok(())
}
