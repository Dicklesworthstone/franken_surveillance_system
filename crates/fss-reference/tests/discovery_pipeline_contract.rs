#![forbid(unsafe_code)]
//! Real discovery composition without socket I/O: scope, attribution, DNS chains,
//! candidate dispatch, and conservative liveness across replay.

use fss_reference::discovery::census::{CensusConfig, CensusPlan, CensusReport, HostObs};
use fss_reference::discovery::watchdog::{DeviceClass, DeviceWatchdog, WatchState};
use fss_reference::discovery::{
    AdapterPath, AuthIngredient, Brand, CameraService, Confidence, DiscoverySighting, MdnsAnswer,
    MdnsObservation, Readiness, Signal, SsdpResponse, WsdMatch, assemble_discovery,
};
use std::error::Error;
use std::net::Ipv4Addr;
use std::time::Duration;

type Test = Result<(), Box<dyn Error>>;

fn ip(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 168, 4, last)
}

fn scope() -> Result<CensusPlan, fss_reference::discovery::CensusError> {
    CensusConfig {
        subnets: vec!["192.168.4.0/24".into()],
        workers: 2,
        tcp_timeout: Duration::from_millis(100),
    }
    .plan()
}

fn census(scope: &CensusPlan) -> CensusReport {
    CensusReport {
        hosts: Vec::new(),
        responders: Vec::new(),
        ping_targets: scope.ping_targets.len(),
    }
}

fn host(endpoint: Ipv4Addr) -> HostObs {
    HostObs {
        ip: endpoint,
        mac: "00:11:22:33:44:55".into(),
        oui_vendor: None,
        open_ports: Vec::new(),
        rtt_ms: None,
    }
}

fn onvif(endpoint: Ipv4Addr) -> WsdMatch {
    WsdMatch {
        ip: endpoint.to_string(),
        xaddrs: vec!["http://203.0.113.9/onvif/device_service".into()],
        scopes: Vec::new(),
        types: vec!["dn:NetworkVideoTransmitter".into()],
    }
}

fn mdns(responder: Ipv4Addr, target: Ipv4Addr, instance: &str) -> MdnsObservation {
    MdnsObservation {
        responder,
        answers: vec![
            MdnsAnswer {
                name: "_rtsp._tcp.local".into(),
                rr_type: 12,
                ttl: 120,
                rdata: instance.into(),
                srv_port: None,
            },
            MdnsAnswer {
                name: instance.into(),
                rr_type: 33,
                ttl: 120,
                rdata: "camera.local".into(),
                srv_port: Some(8554),
            },
            MdnsAnswer {
                name: "camera.local".into(),
                rr_type: 1,
                ttl: 120,
                rdata: target.to_string(),
                srv_port: None,
            },
        ],
    }
}

fn synthetic_beacon_bytes() -> Result<Vec<u8>, std::num::ParseIntError> {
    // The existing synthetic UDP_NEW wire fixture, decoded through the public
    // parser so this integration needs no library-only test helpers.
    const BEACON: &str = "000055aa00000007000000130000008c000000005b3b7a768d0e6bf789aeab5c1a83bf58b63a8bbc407f26e69fdbf292ed63137ab39989adf9de967f221c02e70e61265276c579b7a6cbaacb51177501340e10e646c2c35a7641bb15db3b7e1ffd87c1c165d95f416c4c516c727de9b49de29826f8d3effa80902d7174ca5c70d1b019f6794d229cecfdc3bd5b0ce19b15c425daa3e5f6980000aa55";
    (0..BEACON.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&BEACON[i..i + 2], 16))
        .collect()
}

#[test]
fn onvif_without_arp_becomes_an_owner_gated_standards_candidate() -> Test {
    let scope = scope()?;
    let report = assemble_discovery(&scope, census(&scope), &[], &[], &[], &[onvif(ip(44))])?;
    assert_eq!(report.candidates.len(), 1);
    let candidate = &report.candidates[0];
    assert_eq!(candidate.host.ip, ip(44));
    assert!(candidate.host.mac.is_empty());
    assert_eq!(candidate.brand.brand, Brand::Standards);
    assert_eq!(candidate.brand.confidence, Confidence::Likely);
    assert_eq!(candidate.dispatch.adapter, AdapterPath::Standards);
    assert_eq!(candidate.dispatch.readiness, Readiness::NeedsIngredient);
    assert_eq!(
        candidate.dispatch.missing,
        Some(AuthIngredient::StandardsEndpointCredentials)
    );
    assert_eq!(report.fresh_candidate_ips(), [ip(44)].into());
    assert_eq!(
        report.current_responses[0].kind,
        DiscoverySighting::WsdResponse
    );
    assert_eq!(report.advertised_services[0].service, CameraService::Onvif);
    // The remote XAddr neither becomes a target nor receives a liveness claim.
    assert_eq!(report.advertised_services[0].candidate, ip(44));
    Ok(())
}

#[test]
fn mdns_srv_address_chain_preserves_sender_and_advertised_port() -> Test {
    let scope = scope()?;
    let observation = mdns(ip(44), ip(44), "Front._rtsp._tcp.local");
    let report = assemble_discovery(&scope, census(&scope), &[], &[observation], &[], &[])?;
    assert_eq!(report.candidates[0].brand.brand, Brand::Standards);
    assert_eq!(report.fresh_candidate_ips(), [ip(44)].into());
    assert_eq!(report.advertised_services.len(), 1);
    let hint = report.advertised_services[0];
    assert_eq!(
        (hint.candidate, hint.responder, hint.port),
        (ip(44), ip(44), Some(8554))
    );
    Ok(())
}

#[test]
fn sleep_proxy_does_not_turn_an_advertised_camera_into_a_live_endpoint() -> Test {
    let scope = scope()?;
    let report = assemble_discovery(
        &scope,
        census(&scope),
        &[],
        &[mdns(ip(2), ip(44), "Front._rtsp._tcp.local")],
        &[],
        &[],
    )?;
    assert_eq!(report.fresh_candidate_ips(), [ip(2)].into());
    let camera = report
        .candidates
        .iter()
        .find(|c| c.host.ip == ip(44))
        .ok_or("camera missing")?;
    assert_eq!(camera.brand.brand, Brand::Standards);
    let mut watchdog = DeviceWatchdog::new();
    for candidate in &report.candidates {
        let id = candidate.host.ip.to_string();
        watchdog.register(&id, DeviceClass::Onvif, Some((10, 20)));
        if report.fresh_candidate_ips().contains(&candidate.host.ip) {
            watchdog.observe(&id, 100);
        }
    }
    watchdog.evaluate(100);
    assert_eq!(
        watchdog.state_of(&ip(2).to_string()),
        Some(&WatchState::Observable)
    );
    assert!(matches!(
        watchdog.state_of(&ip(44).to_string()),
        Some(WatchState::NotObservable { .. })
    ));
    Ok(())
}

#[test]
fn split_dns_replies_join_only_within_the_same_responder() -> Test {
    let scope = scope()?;
    let mut first = mdns(ip(44), ip(44), "Front._rtsp._tcp.local");
    let second = MdnsObservation {
        responder: ip(44),
        answers: first.answers.split_off(2),
    };
    let joined = assemble_discovery(
        &scope,
        census(&scope),
        &[],
        &[first.clone(), second.clone()],
        &[],
        &[],
    )?;
    assert_eq!(joined.advertised_services.len(), 1);
    let foreign = MdnsObservation {
        responder: ip(45),
        ..second
    };
    let unjoined = assemble_discovery(&scope, census(&scope), &[], &[first, foreign], &[], &[])?;
    assert!(unjoined.advertised_services.is_empty());
    assert!(
        unjoined
            .candidates
            .iter()
            .all(|c| c.brand.brand == Brand::Unknown)
    );
    Ok(())
}

#[test]
fn goodbye_suppresses_the_exact_service_in_any_packet_order() -> Test {
    let scope = scope()?;
    let live = mdns(ip(44), ip(44), "Front._rtsp._tcp.local");
    for index in [0, 1, 2] {
        let mut withdrawn = live.answers[index].clone();
        withdrawn.ttl = 0;
        let goodbye = MdnsObservation {
            responder: ip(44),
            answers: vec![withdrawn],
        };
        let first = assemble_discovery(
            &scope,
            census(&scope),
            &[],
            &[live.clone(), goodbye.clone()],
            &[],
            &[],
        )?;
        let second = assemble_discovery(
            &scope,
            census(&scope),
            &[],
            &[goodbye, live.clone()],
            &[],
            &[],
        )?;
        assert_eq!(first, second);
        assert!(first.advertised_services.is_empty());
        assert_eq!(first.fresh_candidate_ips(), [ip(44)].into());
    }
    Ok(())
}

#[test]
fn escaped_dns_label_cannot_impersonate_a_camera_service_boundary() -> Test {
    let scope = scope()?;
    for name in [
        r"Fake\._rtsp._tcp.local",
        "Front._http._tcp.local",
        "Front._rtsp._udp.local",
    ] {
        let report = assemble_discovery(
            &scope,
            census(&scope),
            &[],
            &[mdns(ip(44), ip(44), name)],
            &[],
            &[],
        )?;
        assert!(report.advertised_services.is_empty(), "{name}");
        assert_eq!(report.candidates[0].brand.brand, Brand::Unknown);
    }
    let valid = assemble_discovery(
        &scope,
        census(&scope),
        &[],
        &[mdns(ip(44), ip(44), r"Front\.door._rtsp._tcp.local")],
        &[],
        &[],
    )?;
    assert_eq!(valid.advertised_services.len(), 1);
    Ok(())
}

#[test]
fn unresolved_or_zero_port_service_never_becomes_an_onboarding_path() -> Test {
    let scope = scope()?;
    for zero_port in [false, true] {
        let mut observation = mdns(ip(44), ip(44), "Front._rtsp._tcp.local");
        if zero_port {
            observation.answers[1].srv_port = Some(0);
        } else {
            observation.answers.pop();
        }
        let report = assemble_discovery(&scope, census(&scope), &[], &[observation], &[], &[])?;
        assert!(report.onboarding_candidates().is_empty());
        assert_eq!(report.fresh_candidate_ips(), [ip(44)].into());
    }
    Ok(())
}

#[test]
fn out_of_scope_sources_and_advertised_addresses_cannot_expand_authority() -> Test {
    let scope = CensusConfig {
        subnets: vec!["192.168.4.0/30".into()],
        workers: 2,
        tcp_timeout: Duration::from_millis(100),
    }
    .plan()?;
    let mut cached = census(&scope);
    cached.hosts = vec![host(ip(44))];
    cached.responders = vec![ip(44)];
    let ssdp = SsdpResponse {
        ip: ip(44).to_string(),
        server: "camera".into(),
        st: String::new(),
        location: "http://192.168.4.1/description".into(),
        usn: String::new(),
    };
    let report = assemble_discovery(
        &scope,
        cached,
        &[],
        &[
            mdns(ip(44), ip(1), "Outside._rtsp._tcp.local"),
            mdns(ip(2), ip(44), "Remote._rtsp._tcp.local"),
        ],
        &[ssdp],
        &[onvif(ip(44))],
    )?;
    assert_eq!(
        report
            .candidates
            .iter()
            .map(|c| c.host.ip)
            .collect::<Vec<_>>(),
        vec![ip(2)]
    );
    assert!(report.advertised_services.is_empty());
    assert_eq!(report.fresh_candidate_ips(), [ip(2)].into());
    assert_eq!((report.ssdp_responders, report.wsd_matches), (0, 0));
    Ok(())
}

#[test]
fn duplicate_and_reordered_advertisements_do_not_inflate_confidence() -> Test {
    let scope = scope()?;
    let a = mdns(ip(44), ip(44), "Front._rtsp._tcp.local");
    let mut b = mdns(ip(45), ip(45), "Side._rtsp._tcp.local");
    b.answers.reverse();
    let first = assemble_discovery(
        &scope,
        census(&scope),
        &[],
        &[a.clone(), b.clone()],
        &[],
        &[onvif(ip(44))],
    )?;
    let second = assemble_discovery(
        &scope,
        census(&scope),
        &[],
        &[b, a.clone(), a],
        &[],
        &[onvif(ip(44)), onvif(ip(44))],
    )?;
    assert_eq!(first, second);
    assert!(
        first
            .candidates
            .iter()
            .all(|c| c.brand.confidence == Confidence::Likely)
    );
    Ok(())
}

#[test]
fn local_mac_disables_oui_inference_without_discarding_protocol_evidence() -> Test {
    let scope = scope()?;
    let mut cached = census(&scope);
    let mut h = host(ip(44));
    h.mac = "da:91:aa:bb:cc:dd".into();
    h.oui_vendor = Some("Wyze Labs Inc".into());
    cached.hosts.push(h);
    let report = assemble_discovery(&scope, cached, &[], &[], &[], &[onvif(ip(44))])?;
    assert_eq!(report.candidates[0].brand.brand, Brand::Standards);
    assert!(
        report.candidates[0]
            .brand
            .signals
            .contains(&Signal::LocallyAdministeredMac)
    );
    assert!(
        !report.candidates[0]
            .brand
            .signals
            .iter()
            .any(|s| matches!(s, Signal::OuiVendor(_)))
    );
    Ok(())
}

#[test]
fn cached_inventory_cannot_refresh_current_observation() -> Test {
    let scope = scope()?;
    let mut cached = census(&scope);
    cached.hosts.push(host(ip(44)));
    let report = assemble_discovery(&scope, cached, &[], &[], &[], &[])?;
    assert_eq!(report.candidates.len(), 1);
    assert!(report.fresh_candidate_ips().is_empty());
    assert!(report.current_responses.is_empty());
    let mut live = census(&scope);
    live.responders.push(ip(44));
    let report = assemble_discovery(&scope, live, &[], &[], &[], &[])?;
    assert_eq!(report.fresh_candidate_ips(), [ip(44)].into());
    assert_eq!(
        report.current_responses[0].kind,
        DiscoverySighting::CensusResponse
    );
    Ok(())
}

#[test]
fn dns_service_address_cross_product_refuses_before_unbounded_report_growth() -> Test {
    let scope = scope()?;
    let mut answers = Vec::new();
    for n in 0..33 {
        answers.push(MdnsAnswer {
            name: format!("Camera{n}._rtsp._tcp.local"),
            rr_type: 33,
            ttl: 120,
            rdata: "multi.local".into(),
            srv_port: Some(10_000 + n),
        });
    }
    for n in 1..=32 {
        answers.push(MdnsAnswer {
            name: "multi.local".into(),
            rr_type: 1,
            ttl: 120,
            rdata: ip(n).to_string(),
            srv_port: None,
        });
    }
    let result = assemble_discovery(
        &scope,
        census(&scope),
        &[],
        &[MdnsObservation {
            responder: ip(2),
            answers,
        }],
        &[],
        &[],
    );
    assert_eq!(
        result,
        Err(fss_reference::discovery::DiscoveryError::ObservationLimit)
    );
    Ok(())
}

#[test]
fn a_received_beacon_remains_actionable_without_a_cached_hardware_identity() -> Test {
    use fss_reference::discovery::tuya_beacon::decode_beacon;
    let bytes = synthetic_beacon_bytes()?;
    let scope = scope()?;
    let beacon = decode_beacon("192.168.4.44:6667", &bytes)?;
    let report = assemble_discovery(&scope, census(&scope), &[beacon], &[], &[], &[])?;
    assert_eq!(report.candidates[0].brand.brand, Brand::Tuya);
    assert_eq!(
        report.candidates[0].dispatch.missing,
        Some(AuthIngredient::AosuLocalKey)
    );
    assert_eq!(report.fresh_candidate_ips(), [ip(44)].into());
    assert!(report.candidates[0].host.mac.is_empty());
    Ok(())
}

#[test]
fn invalid_probe_windows_and_precancellation_do_not_open_probe_io() -> Test {
    use fss_reference::discovery::{DiscoverConfig, DiscoveryError, discover};
    use std::sync::atomic::AtomicBool;
    let mut cfg = DiscoverConfig::for_subnets(vec!["192.168.4.44/32".into()], ip(2));
    cfg.standards_seconds = u64::MAX;
    assert_eq!(
        discover(&cfg, &AtomicBool::new(false)),
        Err(DiscoveryError::InvalidProbeConfig)
    );
    cfg.standards_seconds = 1;
    let cancelled = discover(&cfg, &AtomicBool::new(true))?;
    assert_eq!(cancelled.ping_targets, 1);
    assert!(cancelled.candidates.is_empty());
    assert!(cancelled.current_responses.is_empty());
    Ok(())
}

#[test]
fn corrupt_beacon_cannot_create_a_candidate_or_refresh_health() -> Test {
    use fss_reference::discovery::tuya_beacon::decode_beacon;
    let scope = scope()?;
    let mut bytes = synthetic_beacon_bytes()?;
    let crc_offset = bytes.len() - 8;
    bytes[crc_offset] ^= 1;
    let beacon = decode_beacon("192.168.4.44:6667", &bytes)?;
    assert!(!beacon.crc_good);
    let direct = fss_reference::discovery::classify_host(&host(ip(44)), &[&beacon], None);
    assert_eq!(direct.brand, Brand::Unknown);
    let report = assemble_discovery(&scope, census(&scope), &[beacon], &[], &[], &[])?;
    assert!(report.candidates.is_empty());
    assert!(report.current_responses.is_empty());
    assert!(report.beacons.is_empty());
    Ok(())
}

#[test]
fn authenticated_6699_beacon_is_discoverable_without_confusing_gcm_with_crc() -> Test {
    use fss_reference::discovery::tuya_beacon::decode_beacon;
    use fss_tuya::wire::{UDP_BROADCAST_KEY, cmd, pack_6699};
    let scope = scope()?;
    // The public broadcast key verifies protocol integrity, not owner identity.
    // An address claimed inside the payload never replaces the actual sender.
    let frame = pack_6699(
        1,
        cmd::UDP_NEW,
        None,
        br#"{"ip":"203.0.113.9","gwId":"synthetic6699","version":"3.5"}"#,
        &UDP_BROADCAST_KEY,
        *b"0123456789ab",
    )?;
    let beacon = decode_beacon("192.168.4.44:6667", &frame)?;
    assert!(!beacon.crc_good);
    assert!(beacon.gcm_good);
    assert!(beacon.integrity_verified());
    let report = assemble_discovery(&scope, census(&scope), &[beacon], &[], &[], &[])?;
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].host.ip, ip(44));
    assert_eq!(report.candidates[0].brand.brand, Brand::Tuya);
    assert_eq!(
        report.candidates[0].dispatch.readiness,
        Readiness::NeedsIngredient
    );
    assert_eq!(report.fresh_candidate_ips(), [ip(44)].into());
    assert_eq!(
        report.current_responses[0].kind,
        DiscoverySighting::TuyaBeacon
    );

    // Corrupt ciphertext, authentication tag, and suffix remain diagnostic
    // observations, never actionable candidates or retained fresh responses.
    for offset in [32, frame.len() - 5, frame.len() - 1] {
        let mut tampered = frame.clone();
        tampered[offset] ^= 1;
        let bad = decode_beacon("192.168.4.44:6667", &tampered)?;
        assert!(!bad.integrity_verified());
        assert!(bad.payload_json.is_none());
        assert_eq!(
            fss_reference::discovery::classify_host(&host(ip(44)), &[&bad], None).brand,
            Brand::Unknown
        );
        let report = assemble_discovery(&scope, census(&scope), &[bad], &[], &[], &[])?;
        assert!(report.candidates.is_empty());
        assert!(report.current_responses.is_empty());
        assert!(report.beacons.is_empty());
    }
    Ok(())
}
