#![forbid(unsafe_code)]
//! Selected UniFi routes retain the complete manifest identity without synthetic rebinding.

use fss_reference::ingest::rtpdump::{RtpDumpKind, RtpDumpLimits, RtpDumpReader};
use fss_reference::rtsp::decode_base64;
use fss_reference::site::probe_observation::{
    NegotiatedProbe, ObservationError, RtspProbeObserver,
};
use fss_reference::site::probe_route::ProbeRoute;
use fss_reference::site::{ProbeCodec, SiteError, SiteManifest, SourceKind};
use fss_reference::unifi::{ProtectQuality, ProtectSource, TransportChoice};

type Test = Result<(), Box<dyn std::error::Error>>;
const MANIFEST: &str = include_str!("../../../fixtures/site/manifest.v1.json");
const PRESENTATION: &str = "/PRIVATE_PROTECT_PATH/?quality=high&variant=%41%2b&order=2";

fn manifest() -> Result<SiteManifest, SiteError> {
    let mut manifest = SiteManifest::parse(MANIFEST)?;
    let source = &mut manifest.sources[0];
    source.kind = SourceKind::UnifiProtect;
    source.presentation = None;
    source.control_root = None;
    source.unifi_camera_id = Some("camera:front".into());
    manifest.validate()?;
    Ok(manifest)
}

fn export(camera: &str, uri: &str) -> Result<ProtectSource, Box<dyn std::error::Error>> {
    Ok(ProtectSource::parse(
        format!(r#"{{"camera":{{"id":"{camera}","type":"unknown-future-model"}},"streams":{{"high":"{uri}"}}}}"#)
            .as_bytes(),
    )?)
}

#[test]
fn selected_route_preserves_private_uri_bytes_and_complete_manifest_identity() -> Test {
    let manifest = manifest()?;
    let original = manifest.clone();
    let export = export(
        "camera:front",
        &format!("rtsp://camera-10.example:554{PRESENTATION}"),
    )?;
    let selected = export.select(ProtectQuality::High, TransportChoice::Published)?;
    let route = ProbeRoute::from_unifi(&manifest, 0, &selected)?;
    assert_eq!(route.presentation(), PRESENTATION);
    assert_eq!(route.control_root(), "/PRIVATE_PROTECT_PATH/");
    assert_eq!(route.manifest_digest(), original.digest()?);
    assert_eq!(manifest, original);
    route.clone().validate_for(&manifest, 0)?;
    for private in [
        "camera:front",
        "camera-10.example",
        "PRIVATE_PROTECT_PATH",
        "%41%2b",
    ] {
        assert!(!format!("{route:?}").contains(private));
    }
    Ok(())
}

#[test]
fn route_cannot_be_reused_after_manifest_change_or_for_another_source() -> Test {
    let manifest = manifest()?;
    let export = export("camera:front", "rtsp://camera-10.example:554/private")?;
    let selected = export.select(ProtectQuality::High, TransportChoice::Published)?;
    let route = ProbeRoute::from_unifi(&manifest, 0, &selected)?;
    assert_eq!(
        route.validate_for(&manifest, 1),
        Err(SiteError::SourceMismatch)
    );
    for change in 0..5 {
        let mut changed = manifest.clone();
        match change {
            0 => changed.generation += 1,
            1 => changed.sources.swap(0, 1),
            2 => changed.sources.truncate(1),
            3 => changed.sources[1].retention_class = "changed".into(),
            _ => {
                changed.sources[0].kind = SourceKind::Rtsp;
                changed.sources[0].unifi_camera_id = None;
                changed.sources[0].presentation = Some(route.presentation().into());
                changed.sources[0].control_root = Some(route.control_root().into());
            }
        }
        assert_eq!(
            route.validate_for(&changed, 0),
            Err(SiteError::StaleManifest)
        );
    }
    Ok(())
}

#[test]
fn direct_constructor_never_infers_a_route_for_unifi_or_onvif() -> Test {
    let direct = SiteManifest::parse(MANIFEST)?;
    for index in 0..direct.sources.len() {
        let route = ProbeRoute::direct(&direct, index)?;
        assert_eq!(route.presentation(), "/live/main");
        assert_eq!(route.control_root(), "/live");
        route.validate_for(&direct, index)?;
    }
    let mut manifest = manifest()?;
    assert!(ProbeRoute::direct(&manifest, 0).is_err());
    manifest.sources[0].kind = SourceKind::Onvif;
    manifest.sources[0].unifi_camera_id = None;
    manifest.sources[0].onvif_service_path = Some("/onvif/device_service".into());
    assert!(ProbeRoute::direct(&manifest, 0).is_err());
    Ok(())
}

#[test]
fn unifi_selection_refuses_other_cameras_secure_transport_and_route_drift() -> Test {
    let manifest = manifest()?;
    for (camera, uri) in [
        ("other-camera", "rtsp://camera-10.example:554/private"),
        ("camera:front", "rtsps://camera-10.example:554/private"),
        ("camera:front", "rtsp://other.example:554/private"),
        ("camera:front", "rtsp://camera-10.example:7447/private"),
        ("camera:front", "rtsp://192.0.2.11:554/private"),
        (
            "camera:front",
            "rtsp://camera-10.example:554/private?token=PRIVATE",
        ),
    ] {
        let export = export(camera, uri)?;
        let selected = export.select(ProtectQuality::High, TransportChoice::Published)?;
        let error = ProbeRoute::from_unifi(&manifest, 0, &selected)
            .expect_err("foreign or unsupported selection must be refused");
        assert!(!format!("{error:?} {error}").contains("PRIVATE"));
    }
    let export = export("camera:front", "rtsp://camera-10.example:554/private")?;
    let selected = export.select(ProtectQuality::High, TransportChoice::Published)?;
    for owner_authorized in [true, false] {
        let mut changed = manifest.clone();
        changed.sources[0].owner_authorized = owner_authorized;
        changed.sources[0].plaintext = !owner_authorized;
        assert!(ProbeRoute::from_unifi(&changed, 0, &selected).is_err());
    }
    assert!(ProbeRoute::from_unifi(&SiteManifest::parse(MANIFEST)?, 0, &selected).is_err());
    Ok(())
}

#[test]
fn unifi_default_port_is_explicitly_checked_without_dns_or_port_rewriting() -> Test {
    let mut manifest = manifest()?;
    manifest.sources[0].authority = "console.example".into();
    manifest.sources[0].peer = "192.0.2.10:7447".parse()?;
    let export = export("camera:front", "rtsp://console.example/private")?;
    let selected = export.select(ProtectQuality::High, TransportChoice::Published)?;
    assert_eq!(
        ProbeRoute::from_unifi(&manifest, 0, &selected),
        Err(SiteError::SourceMismatch)
    );
    manifest.sources[0].peer.set_port(554);
    ProbeRoute::from_unifi(&manifest, 0, &selected)?.validate_for(&manifest, 0)?;
    Ok(())
}

#[test]
fn native_unifi_observation_receipts_retain_original_manifest_and_selected_path() -> Test {
    let manifest = manifest()?;
    let export = export(
        "camera:front",
        &format!("rtsp://camera-10.example:554{PRESENTATION}"),
    )?;
    let selected = export.select(ProtectQuality::High, TransportChoice::Published)?;
    let route = ProbeRoute::from_unifi(&manifest, 0, &selected)?;
    for (codec, description, dump, parameters, payload) in [
        (
            ProbeCodec::Avc,
            include_bytes!("../../../fixtures/site_probe/avc.describe.rtsp").as_slice(),
            include_bytes!("../../../fixtures/site_probe/avc.rtpdump").as_slice(),
            vec!["Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=", "aM4PLIA="],
            96,
        ),
        (
            ProbeCodec::Hevc,
            include_bytes!("../../../fixtures/site_probe/hevc.describe.rtsp").as_slice(),
            include_bytes!("../../../fixtures/site_probe/hevc.rtpdump").as_slice(),
            vec![
                "QAEMAf//AWAAAAMAkAAAAwAAAwAekoCQ",
                "QgEBAWAAAAMAkAAAAwAAAwAeoCCBBZZKuTC8BaAgAAADACAAAAMBQQ==",
                "RAHBcaGkgA==",
            ],
            98,
        ),
    ] {
        let (_, sdp) = std::str::from_utf8(description)?
            .split_once("\r\n\r\n")
            .ok_or("missing fixture SDP")?;
        let parameters = parameters
            .iter()
            .map(|value| decode_base64(value))
            .collect::<Result<Vec<_>, _>>()?;
        let parameters = parameters.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let mut observer = RtspProbeObserver::new_with_route(
            &manifest,
            0,
            route.clone(),
            NegotiatedProbe {
                sdp: sdp.as_bytes(),
                media_index: 0,
                rtp_channel: 0,
                codec,
                payload_type: payload,
                parameter_sets: &parameters,
                server_identity: "fixture",
            },
        )?;
        let mut reader = RtpDumpReader::new(dump, RtpDumpLimits::default())?;
        while let Some(record) = reader.next_record()? {
            if record.kind() == RtpDumpKind::Rtp {
                observer.observe_rtp(0, record.packet())?;
            }
        }
        let receipt = observer.finish()?;
        assert_eq!(receipt.manifest_digest, manifest.digest()?);
        assert_eq!(receipt.presentation, PRESENTATION);
        assert_eq!(receipt.control_root, "/PRIVATE_PROTECT_PATH/");
        assert_eq!(receipt.frame_duration_ticks, 3600);
        assert_eq!(receipt.codec, codec);
        receipt.validate_for(&manifest)?;
        assert!(!format!("{receipt:?}").contains("PRIVATE_PROTECT_PATH"));
    }
    Ok(())
}

#[test]
fn unifi_observer_never_admits_an_unimplemented_jpeg_route() -> Test {
    let manifest = manifest()?;
    let export = export("camera:front", "rtsp://camera-10.example:554/private")?;
    let selected = export.select(ProtectQuality::High, TransportChoice::Published)?;
    let route = ProbeRoute::from_unifi(&manifest, 0, &selected)?;
    let (_, sdp) = std::str::from_utf8(include_bytes!(
        "../../../fixtures/site_probe/jpeg.describe.rtsp"
    ))?
    .split_once("\r\n\r\n")
    .ok_or("missing fixture SDP")?;
    let result = RtspProbeObserver::new_with_route(
        &manifest,
        0,
        route,
        NegotiatedProbe {
            sdp: sdp.as_bytes(),
            media_index: 0,
            rtp_channel: 0,
            codec: ProbeCodec::Jpeg,
            payload_type: 26,
            parameter_sets: &[],
            server_identity: "fixture",
        },
    );
    assert!(matches!(result, Err(ObservationError::Negotiation)));
    Ok(())
}
